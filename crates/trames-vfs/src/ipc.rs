// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded AF_UNIX pairs, shared by dup/fork and confined to the guest runtime.
use super::*;

#[derive(Clone, Default)]
pub struct LocalRights(Vec<Rc<RefCell<OpenDescription>>>);
impl LocalRights {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
struct Packet {
    data: Vec<u8>,
    rights: LocalRights,
}
struct Channel {
    queues: [VecDeque<Packet>; 2],
    ends: [Weak<LocalSocket>; 2],
}
pub struct LocalSocket {
    channel: Rc<RefCell<Channel>>,
    side: usize,
    kind: u32,
    read_closed: Cell<bool>,
    write_closed: Cell<bool>,
}
pub struct LocalReceived {
    pub data: Vec<u8>,
    pub length: usize,
    pub truncated: bool,
    pub rights: LocalRights,
}
impl LocalSocket {
    pub fn kind(&self) -> u32 {
        self.kind
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if how > 2 {
            return Err(Errno(22));
        }
        if how != 1 {
            self.read_closed.set(true);
            self.channel.borrow_mut().queues[self.side].clear();
        }
        if how != 0 {
            self.write_closed.set(true);
        }
        Ok(())
    }
    pub fn send(&self, bytes: &[u8], flags: u32) -> Result<usize> {
        self.send_rights(bytes, flags, LocalRights::default())
    }
    pub fn send_rights(&self, bytes: &[u8], flags: u32, rights: LocalRights) -> Result<usize> {
        if flags & !(0x40 | 0x4000) != 0 {
            return Err(Errno(95));
        }
        if self.write_closed.get() {
            return Err(Errno(32));
        }
        let mut channel = self.channel.borrow_mut();
        let peer = channel.ends[1 - self.side]
            .upgrade()
            .ok_or(Errno(if self.kind == 2 { 111 } else { 32 }))?;
        if peer.read_closed.get() {
            return Err(Errno(32));
        }
        if self.kind == 1 && bytes.is_empty() {
            return Ok(0);
        }
        let queue = &mut channel.queues[1 - self.side];
        let used: usize = queue.iter().map(|p| p.data.len()).sum();
        if self.kind != 1 && bytes.len() > PIPE_CAPACITY {
            return Err(Errno(90));
        }
        let room = PIPE_CAPACITY - used;
        if (self.kind != 1 && (room < bytes.len() || queue.len() >= 128))
            || (self.kind == 1 && room == 0 && !bytes.is_empty())
        {
            return Err(Errno(11));
        }
        let count = room.min(bytes.len());
        let merge = self.kind == 1
            && rights.is_empty()
            && queue.back().is_some_and(|p| p.rights.is_empty());
        if !merge && queue.len() >= 128 {
            return Err(Errno(11));
        }
        if merge && count != 0 {
            queue
                .back_mut()
                .expect("stream queue")
                .data
                .extend_from_slice(&bytes[..count]);
        } else if count != 0 || self.kind != 1 {
            queue.push_back(Packet {
                data: bytes[..count].to_vec(),
                rights,
            });
        }
        Ok(count)
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<LocalReceived> {
        if flags & !(2 | 0x20 | 0x40 | 0x100 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if self.kind == 1 && flags & 0x100 != 0 && flags & 0x40 == 0 && count > PIPE_CAPACITY {
            // Larger blocking records need a scheduler continuation that
            // consumes partial data; never wait forever on a bounded queue.
            return Err(Errno(95));
        }
        let mut channel = self.channel.borrow_mut();
        let eof = self.read_closed.get()
            || channel.ends[1 - self.side]
                .upgrade()
                .is_none_or(|s| s.write_closed.get());
        let queue = &mut channel.queues[self.side];
        if self.read_closed.get()
            || (self.kind == 1 && count == 0)
            || (eof && queue.is_empty() && self.kind != 2)
        {
            return Ok(LocalReceived {
                data: Vec::new(),
                length: 0,
                truncated: false,
                rights: LocalRights::default(),
            });
        }
        if queue.is_empty() {
            return Err(Errno(11));
        }
        if self.kind != 1 {
            let packet = queue.front().expect("packet");
            let length = packet.data.len();
            let data = packet.data[..count.min(length)].to_vec();
            let rights = packet.rights.clone();
            if flags & 2 == 0 {
                queue.pop_front();
            }
            return Ok(LocalReceived {
                data,
                length,
                truncated: count < length,
                rights,
            });
        }
        let mut data = Vec::new();
        let mut rights = LocalRights::default();
        for packet in queue.iter() {
            let n = (count - data.len()).min(packet.data.len());
            data.extend_from_slice(&packet.data[..n]);
            if !packet.rights.is_empty() {
                rights = packet.rights.clone();
                break;
            }
            if data.len() == count {
                break;
            }
        }
        if flags & 2 == 0 {
            // MSG_WAITALL waits for the requested stream bytes unless EOF or
            // nonblocking mode permits a short read. Do not consume a prefix
            // before a blocked syscall is retried by the guest scheduler.
            if flags & 0x100 != 0
                && flags & 0x40 == 0
                && !eof
                && data.len() < count
                && rights.is_empty()
            {
                return Err(Errno(11));
            }
            let mut remaining = data.len();
            while remaining != 0 {
                let packet = queue.front_mut().expect("stream bytes");
                let n = remaining.min(packet.data.len());
                packet.data.drain(..n);
                packet.rights = LocalRights::default();
                remaining -= n;
                if packet.data.is_empty() {
                    queue.pop_front();
                }
            }
        }
        let length = data.len();
        Ok(LocalReceived {
            data,
            length,
            truncated: false,
            rights,
        })
    }
    pub fn poll(&self, events: u16) -> u16 {
        let channel = self.channel.borrow();
        let peer = channel.ends[1 - self.side].upgrade();
        let eof = self.read_closed.get() || peer.as_ref().is_none_or(|s| s.write_closed.get());
        let queue = &channel.queues[self.side];
        let send_queue = &channel.queues[1 - self.side];
        let room = PIPE_CAPACITY - send_queue.iter().map(|p| p.data.len()).sum::<usize>();
        (if !queue.is_empty() || (eof && self.kind != 2) {
            events & 1
        } else {
            0
        }) | (if room != 0
            && (send_queue.len() < 128
                || self.kind == 1 && send_queue.back().is_some_and(|p| p.rights.is_empty()))
        {
            events & 4
        } else {
            0
        }) | (if eof && self.kind != 2 {
            events & 0x2000
        } else {
            0
        }) | (if peer.is_none() || (eof && self.write_closed.get()) {
            16
        } else {
            0
        })
    }
}
impl Drop for LocalSocket {
    fn drop(&mut self) {
        // Rights queued for a closed receiver must release their open files.
        self.channel.borrow_mut().queues[self.side].clear();
    }
}
impl Vfs {
    pub fn send_rights(&self, fds: &[u32]) -> Result<LocalRights> {
        if fds.len() > 253 {
            return Err(Errno(22));
        }
        let mut rights = Vec::new();
        for fd in fds {
            let open = &self.descriptor(*fd)?.open;
            // UNIX-socket transfer needs an in-flight graph garbage collector.
            // Reject it explicitly until cycles can be reclaimed correctly.
            if open.borrow().local.is_some() {
                return Err(Errno(95));
            }
            rights.push(open.clone());
        }
        Ok(LocalRights(rights))
    }
    pub fn receive_rights(
        &mut self,
        rights: LocalRights,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u32>, bool) {
        let free: Vec<_> = (0..MAX_FDS)
            .filter(|fd| !self.fds.contains_key(fd))
            .take(capacity.min(rights.0.len()))
            .collect();
        let truncated = free.len() < rights.0.len();
        for (&fd, open) in free.iter().zip(rights.0) {
            self.fds.insert(fd, Descriptor { open, cloexec });
        }
        (free, truncated)
    }
    pub fn local_socket(&self, fd: u32) -> Result<Option<Rc<LocalSocket>>> {
        Ok(self.descriptor(fd)?.open.borrow().local.clone())
    }
    pub fn socketpair(&mut self, family: u32, kind: u32, protocol: u32) -> Result<[u32; 2]> {
        if family != 1 {
            return Err(Errno(97));
        }
        if kind & !(0xf | O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        if !matches!(kind & 0xf, 1 | 2 | 5) {
            return Err(Errno(94));
        }
        if protocol != 0 {
            return Err(Errno(93));
        }
        let free: Vec<_> = (0..MAX_FDS)
            .filter(|n| !self.fds.contains_key(n))
            .take(2)
            .collect();
        if free.len() != 2 {
            return Err(Errno(24));
        }
        let channel = Rc::new(RefCell::new(Channel {
            queues: [VecDeque::new(), VecDeque::new()],
            ends: [Weak::new(), Weak::new()],
        }));
        let ends: Vec<_> = (0..2)
            .map(|side| {
                Rc::new(LocalSocket {
                    channel: channel.clone(),
                    side,
                    kind: kind & 0xf,
                    read_closed: Cell::new(false),
                    write_closed: Cell::new(false),
                })
            })
            .collect();
        channel.borrow_mut().ends = [Rc::downgrade(&ends[0]), Rc::downgrade(&ends[1])];
        for (&fd, local) in free.iter().zip(ends) {
            self.fds.insert(
                fd,
                Descriptor {
                    open: Rc::new(RefCell::new(OpenDescription {
                        id: self.open_id(),
                        owner: (self.credentials.fsuid, self.credentials.fsgid),
                        kind: FdKind::Socket,
                        flags: 2 | (kind & O_NONBLOCK),
                        position: 0,
                        node: None,
                        pipe: None,
                        socket: None,
                        bridge: None,
                        kernel_log: None,
                        anonymous: None,
                        local: Some(local),
                        pty: None,
                        namespace: None,
                        mount: None,
                    })),
                    cloexec: kind & O_CLOEXEC != 0,
                },
            );
        }
        Ok([free[0], free[1]])
    }
}

#[cfg(test)]
mod waitall_tests {
    use super::*;
    #[test]
    fn fragmented_waitall_preserves_prefix_and_nonblocking_and_eof_return_short_reads() {
        let mut v = Vfs::default();
        let [a, b] = v.socketpair(1, 1, 0).unwrap();
        let receiver = v.local_socket(a).unwrap().unwrap();
        v.write(b, b"abc").unwrap();
        assert!(matches!(receiver.recv(8, 0x100), Err(Errno(11))));
        assert_eq!(receiver.recv(8, 2).unwrap().data, b"abc");
        v.write(b, b"defgh").unwrap();
        assert_eq!(receiver.recv(8, 0x100).unwrap().data, b"abcdefgh");
        v.write(b, b"xy").unwrap();
        assert_eq!(receiver.recv(8, 0x100 | 0x40).unwrap().data, b"xy");
        v.write(b, b"end").unwrap();
        v.close(b).unwrap();
        assert_eq!(receiver.recv(8, 0x100).unwrap().data, b"end");
        assert!(receiver.recv(8, 0x100).unwrap().data.is_empty());
        assert!(matches!(
            receiver.recv(PIPE_CAPACITY + 1, 0x100),
            Err(Errno(95))
        ));
    }
}
