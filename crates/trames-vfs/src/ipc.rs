// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded AF_UNIX pairs, shared by dup/fork and confined to the guest runtime.
use super::*;

struct Channel {
    queues: [VecDeque<Vec<u8>>; 2],
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
        let queue = &mut channel.queues[1 - self.side];
        let used: usize = queue.iter().map(Vec::len).sum();
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
        if self.kind == 1 && count != 0 && !queue.is_empty() {
            queue
                .back_mut()
                .expect("stream queue")
                .extend_from_slice(&bytes[..count]);
        } else if count != 0 || self.kind != 1 {
            queue.push_back(bytes[..count].to_vec());
        }
        Ok(count)
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<LocalReceived> {
        if flags & !(2 | 0x20 | 0x40 | 0x40000000) != 0 {
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
            });
        }
        if queue.is_empty() {
            return Err(Errno(11));
        }
        if self.kind != 1 {
            let packet = queue.front().expect("packet");
            let length = packet.len();
            let data = packet[..count.min(length)].to_vec();
            if flags & 2 == 0 {
                queue.pop_front();
            }
            return Ok(LocalReceived {
                data,
                length,
                truncated: count < length,
            });
        }
        let mut data = Vec::new();
        for packet in queue.iter() {
            let n = (count - data.len()).min(packet.len());
            data.extend_from_slice(&packet[..n]);
            if data.len() == count {
                break;
            }
        }
        if flags & 2 == 0 {
            let mut remaining = data.len();
            while remaining != 0 {
                let packet = queue.front_mut().expect("stream bytes");
                let n = remaining.min(packet.len());
                packet.drain(..n);
                remaining -= n;
                if packet.is_empty() {
                    queue.pop_front();
                }
            }
        }
        let length = data.len();
        Ok(LocalReceived {
            data,
            length,
            truncated: false,
        })
    }
    pub fn poll(&self, events: u16) -> u16 {
        let channel = self.channel.borrow();
        let peer = channel.ends[1 - self.side].upgrade();
        let eof = self.read_closed.get() || peer.as_ref().is_none_or(|s| s.write_closed.get());
        let queue = &channel.queues[self.side];
        let send_queue = &channel.queues[1 - self.side];
        let room = PIPE_CAPACITY - send_queue.iter().map(Vec::len).sum::<usize>();
        (if !queue.is_empty() || (eof && self.kind != 2) {
            events & 1
        } else {
            0
        }) | (if room != 0 && (self.kind == 1 || send_queue.len() < 128) {
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
impl Vfs {
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
                        anonymous: None,
                        local: Some(local),
                    })),
                    cloexec: kind & O_CLOEXEC != 0,
                },
            );
        }
        Ok([free[0], free[1]])
    }
}
