// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded guest AF_UNIX endpoints. No guest pathname reaches host sockets.
use super::*;
mod native;
pub(crate) use native::Services as NativeServices;

#[derive(Clone, Default)]
pub struct LocalRights(pub(super) Vec<Rc<RefCell<OpenDescription>>>);
thread_local! {
    // Releasing a queued socket may release another queue. Drain ownership
    // iteratively so an acyclic FD chain cannot exhaust the host thread stack.
    static RIGHTS_DROP: RefCell<Option<Vec<Rc<RefCell<OpenDescription>>>>> = const { RefCell::new(None) };
}
impl Drop for LocalRights {
    fn drop(&mut self) {
        if self.0.is_empty() {
            return;
        }
        RIGHTS_DROP.with(|pending| {
            let mut queue = pending.borrow_mut();
            if let Some(queue) = queue.as_mut() {
                queue.append(&mut self.0);
                return;
            }
            *queue = Some(std::mem::take(&mut self.0));
            drop(queue);
            loop {
                let next = pending.borrow_mut().as_mut().expect("rights drain").pop();
                if let Some(open) = next {
                    // Release the worklist borrow before nested socket drops.
                    drop(open);
                } else {
                    *pending.borrow_mut() = None;
                    break;
                }
            }
        });
    }
}
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
    epochs: [[u64; 2]; 2],
}
pub struct LocalSocket {
    namespace: Rc<RefCell<LocalNamespace>>,
    network: Rc<linux_namespace::RootNetwork>,
    channel: RefCell<Rc<RefCell<Channel>>>,
    side: Cell<usize>,
    connected: Cell<bool>,
    name: RefCell<Vec<u8>>,
    peer_name: RefCell<Vec<u8>>,
    credentials: Cell<[u32; 3]>,
    peer_credentials: Cell<[u32; 3]>,
    listener: RefCell<Option<Listener>>,
    listen_epoch: Cell<u64>,
    kind: u32,
    reuse: Cell<[u32; 2]>,
    read_closed: Cell<bool>,
    write_closed: Cell<bool>,
}
struct Listener {
    backlog: usize,
    pending: VecDeque<Rc<LocalSocket>>,
}
#[derive(Default)]
pub(super) struct LocalNamespace {
    abstract_names: BTreeMap<Vec<u8>, Weak<LocalSocket>>,
    sockets: Vec<Weak<LocalSocket>>,
}
pub struct LocalReceived {
    pub data: Vec<u8>,
    pub length: usize,
    pub truncated: bool,
    pub rights: LocalRights,
}
impl LocalSocket {
    pub fn readable_bytes(&self) -> Result<usize> {
        if self.listening() {
            return Err(Errno(22));
        }
        let binding = self.channel.borrow();
        let channel = binding.borrow();
        let queue = &channel.queues[self.side.get()];
        // Linux AF_UNIX reports one datagram, but all queued bytes for stream
        // and seqpacket. Do not recv/peek here: rights and zero-length packets
        // must remain queued, including after shutdown(SHUT_RD).
        Ok(if self.kind == 2 {
            queue.front().map_or(0, |packet| packet.data.len())
        } else {
            queue.iter().map(|packet| packet.data.len()).sum()
        })
    }
    fn new(
        kind: u32,
        credentials: [u32; 3],
        network: Rc<linux_namespace::RootNetwork>,
    ) -> Rc<Self> {
        Rc::new(Self {
            namespace: network.local.clone(),
            network,
            channel: RefCell::new(Rc::new(RefCell::new(Channel {
                queues: [VecDeque::new(), VecDeque::new()],
                ends: [Weak::new(), Weak::new()],
                epochs: [[0; 2]; 2],
            }))),
            side: Cell::new(0),
            connected: Cell::new(false),
            name: RefCell::new(vec![1, 0]),
            peer_name: RefCell::new(vec![1, 0]),
            credentials: Cell::new(credentials),
            peer_credentials: Cell::new([0, u32::MAX, u32::MAX]),
            listener: RefCell::new(None),
            listen_epoch: Cell::new(0),
            kind,
            reuse: Cell::new([0; 2]),
            read_closed: Cell::new(false),
            write_closed: Cell::new(false),
        })
    }
    fn pair(a: &Rc<Self>, b: &Rc<Self>) {
        let channel = Rc::new(RefCell::new(Channel {
            queues: [VecDeque::new(), VecDeque::new()],
            ends: [Rc::downgrade(a), Rc::downgrade(b)],
            epochs: [[0; 2]; 2],
        }));
        for (side, (end, peer)) in [(a, b), (b, a)].into_iter().enumerate() {
            *end.channel.borrow_mut() = channel.clone();
            end.side.set(side);
            end.connected.set(true);
            *end.peer_name.borrow_mut() = peer.name.borrow().clone();
            end.peer_credentials.set(peer.credentials.get());
        }
    }
    pub fn name(&self, peer: bool) -> Result<Vec<u8>> {
        if peer && !self.connected.get() {
            return Err(Errno(107));
        }
        Ok(if peer {
            self.peer_name.borrow().clone()
        } else {
            self.name.borrow().clone()
        })
    }
    pub fn peer_credentials(&self) -> [u32; 3] {
        self.peer_credentials.get()
    }
    pub fn accept_address_size(&self) -> Result<usize> {
        Ok(self
            .listener
            .borrow()
            .as_ref()
            .ok_or(Errno(22))?
            .pending
            .front()
            .ok_or(Errno(11))?
            .peer_name
            .borrow()
            .len())
    }
    pub fn listening(&self) -> bool {
        self.listener.borrow().is_some()
    }
    pub fn listen(&self, backlog: u32) -> Result<()> {
        if self.kind == 2 {
            return Err(Errno(95));
        }
        if self.connected.get() || self.name.borrow().len() == 2 {
            return Err(Errno(22));
        }
        let mut listener = self.listener.borrow_mut();
        let backlog = backlog.min(128) as usize;
        if let Some(l) = listener.as_mut() {
            l.backlog = backlog;
        } else {
            *listener = Some(Listener {
                backlog,
                pending: VecDeque::new(),
            });
        }
        Ok(())
    }
    pub(super) fn poll_epoch(&self) -> [u64; 2] {
        if self.listening() {
            return [self.listen_epoch.get(), 0];
        }
        self.channel.borrow().borrow().epochs[self.side.get()]
    }

    pub fn set_reuse(&self, option: u32, value: u32) -> Result<()> {
        let i = match option {
            2 => 0,
            15 => 1,
            _ => return Err(Errno(92)),
        };
        let mut reuse = self.reuse.get();
        reuse[i] = u32::from(value != 0);
        self.reuse.set(reuse);
        Ok(())
    }
    pub fn reuse(&self, option: u32) -> u32 {
        self.reuse.get()[usize::from(option == 15)]
    }
    pub fn kind(&self) -> u32 {
        self.kind
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if how > 2 {
            return Err(Errno(22));
        }
        if how != 1 {
            self.read_closed.set(true);
        }
        if how != 0 {
            self.write_closed.set(true);
        }
        let binding = self.channel.borrow();
        let mut channel = binding.borrow_mut();
        for epoch in &mut channel.epochs {
            for counter in epoch {
                *counter = counter.wrapping_add(1);
            }
        }
        Ok(())
    }
    pub fn send(&self, bytes: &[u8], flags: u32) -> Result<usize> {
        self.send_rights(bytes, flags, LocalRights::default())
    }
    pub fn send_rights(&self, bytes: &[u8], flags: u32, rights: LocalRights) -> Result<usize> {
        // Linux ignores the receive-only MSG_CMSG_CLOEXEC on sendmsg/sendto.
        // Firefox's Wayland proxy reuses this flag for both directions.
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if !self.connected.get() {
            return Err(Errno(if self.kind == 2 { 89 } else { 107 }));
        }
        if self.write_closed.get() {
            return Err(Errno(32));
        }
        let binding = self.channel.borrow();
        let peer = binding.borrow().ends[1 - self.side.get()]
            .upgrade()
            .ok_or(Errno(if self.kind == 2 { 111 } else { 32 }))?;
        if peer.read_closed.get() {
            return Err(Errno(32));
        }
        // Queued rights own their open descriptions. Permit Unix FD handoff
        // between independent channels, but reject a new owning cycle before
        // enqueue (Linux has a collector for cyclic SCM_RIGHTS; we do not).
        // Ordinary messages/rights without local sockets avoid this traversal.
        let mut pending: Vec<_> = rights
            .0
            .iter()
            .filter_map(|open| open.borrow().local.clone())
            .collect();
        let mut visited = std::collections::BTreeSet::new();
        while let Some(socket) = pending.pop() {
            if Rc::ptr_eq(&socket, &peer) {
                return Err(Errno(95));
            }
            if !visited.insert(Rc::as_ptr(&socket) as usize) {
                continue;
            }
            let channel = socket.channel.borrow();
            for packet in &channel.borrow().queues[socket.side.get()] {
                for open in &packet.rights.0 {
                    if let Some(socket) = &open.borrow().local {
                        pending.push(socket.clone());
                    }
                }
            }
        }
        let mut channel = binding.borrow_mut();
        if self.kind == 1 && bytes.is_empty() {
            return Ok(0);
        }
        let queue = &mut channel.queues[1 - self.side.get()];
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
        channel.epochs[1 - self.side.get()][0] =
            channel.epochs[1 - self.side.get()][0].wrapping_add(1);
        Ok(count)
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<LocalReceived> {
        // MSG_NOSIGNAL is accepted but has no effect on Linux receives.
        if flags & !(2 | 0x20 | 0x40 | 0x100 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if self.kind == 1 && flags & 0x100 != 0 && flags & 0x40 == 0 && count > PIPE_CAPACITY {
            // Larger blocking records need a scheduler continuation that
            // consumes partial data; never wait forever on a bounded queue.
            return Err(Errno(95));
        }
        if !self.connected.get() {
            return Err(Errno(if self.kind == 2 { 11 } else { 22 }));
        }
        let binding = self.channel.borrow();
        let mut channel = binding.borrow_mut();
        let eof = self.read_closed.get()
            || channel.ends[1 - self.side.get()]
                .upgrade()
                .is_none_or(|s| s.write_closed.get());
        let queue = &mut channel.queues[self.side.get()];
        if (self.kind == 1 && count == 0) || (eof && queue.is_empty() && self.kind != 2) {
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
                channel.epochs[1 - self.side.get()][1] =
                    channel.epochs[1 - self.side.get()][1].wrapping_add(1);
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
        if flags & 2 == 0 && !data.is_empty() {
            channel.epochs[1 - self.side.get()][1] =
                channel.epochs[1 - self.side.get()][1].wrapping_add(1);
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
        if let Some(listener) = self.listener.borrow().as_ref() {
            return if listener.pending.is_empty() {
                0
            } else {
                events & 1
            };
        }
        if !self.connected.get() {
            return (events & 4) | if self.kind == 2 { 0 } else { 16 };
        }
        let binding = self.channel.borrow();
        let channel = binding.borrow();
        let peer = channel.ends[1 - self.side.get()].upgrade();
        let eof = self.read_closed.get() || peer.as_ref().is_none_or(|s| s.write_closed.get());
        let queue = &channel.queues[self.side.get()];
        let send_queue = &channel.queues[1 - self.side.get()];
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
        let binding = self.channel.borrow();
        let mut channel = binding.borrow_mut();
        let queued = std::mem::take(&mut channel.queues[self.side.get()]);
        for counter in &mut channel.epochs[1 - self.side.get()] {
            *counter = counter.wrapping_add(1);
        }
        drop(channel);
        // A queued FD can refer to the opposite endpoint of this channel.
        drop(queued);
    }
}
impl Vfs {
    fn new_local(&self, kind: u32) -> Result<Rc<LocalSocket>> {
        self.new_local_in(kind, &self.root_network)
    }
    fn new_local_in(
        &self,
        kind: u32,
        network: &Rc<linux_namespace::RootNetwork>,
    ) -> Result<Rc<LocalSocket>> {
        let mut ns = network.local.borrow_mut();
        ns.sockets.retain(|s| s.strong_count() != 0);
        ns.abstract_names.retain(|_, s| s.strong_count() != 0);
        if ns.sockets.len() >= 1024 {
            return Err(Errno(23));
        }
        let socket = LocalSocket::new(
            kind,
            [
                self.lock_owner,
                self.credentials.euid,
                self.credentials.egid,
            ],
            network.clone(),
        );
        ns.sockets.push(Rc::downgrade(&socket));
        Ok(socket)
    }
    fn local_descriptor(&mut self, fd: u32, local: Rc<LocalSocket>, flags: u32) {
        self.fds.insert(
            fd,
            Descriptor {
                open: Rc::new(RefCell::new(OpenDescription {
                    read_node: None,
                    id: self.open_id(),
                    owner: (self.credentials.fsuid, self.credentials.fsgid),
                    kind: FdKind::Socket,
                    flags: 2 | (flags & O_NONBLOCK),
                    position: 0,
                    node: None,
                    pipe: None,
                    socket: None,
                    bridge: None,
                    kernel_log: None,
                    anonymous: None,
                    notification: None,
                    local: Some(local),
                    pty: None,
                    namespace: None,
                    network_control: None,
                    oom: None,
                    mount: None,
                })),
                cloexec: flags & O_CLOEXEC != 0,
            },
        );
    }
    pub fn local_create(&mut self, kind: u32, protocol: u32) -> Result<u32> {
        if kind & !(0xf | O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        if !matches!(kind & 0xf, 1 | 2 | 5) {
            return Err(Errno(94));
        }
        if protocol != 0 {
            return Err(Errno(93));
        }
        let fd = self.available(0)?;
        let local = self.new_local(kind & 0xf)?;
        self.local_descriptor(fd, local, kind);
        Ok(fd)
    }
    fn local_address(bytes: &[u8]) -> Result<(Vec<u8>, bool)> {
        if !(3..=110).contains(&bytes.len()) || bytes[..2] != [1, 0] {
            return Err(Errno(22));
        }
        if bytes[2] == 0 {
            return Ok((bytes.to_vec(), true));
        }
        let end = bytes[2..]
            .iter()
            .position(|&c| c == 0)
            .map_or(bytes.len(), |i| i + 2);
        let mut name = bytes[..end].to_vec();
        name.push(0);
        Ok((name, false))
    }
    pub fn local_listen(&self, socket: &LocalSocket, backlog: u32) -> Result<()> {
        let first = !socket.listening();
        socket.listen(backlog)?;
        if first {
            // lock_owner is the coordinator's global TGID, unlike the calling TID.
            socket.credentials.set([
                self.lock_owner,
                self.credentials.euid,
                self.credentials.egid,
            ]);
        }
        Ok(())
    }
    pub fn local_bind(&mut self, socket: &Rc<LocalSocket>, bytes: &[u8]) -> Result<()> {
        let (name, abstract_) = Self::local_address(bytes)?;
        if socket.name.borrow().len() != 2 {
            return Err(Errno(22));
        }
        if abstract_ {
            let mut ns = socket.namespace.borrow_mut();
            if ns
                .abstract_names
                .get(&name)
                .and_then(Weak::upgrade)
                .is_some()
            {
                return Err(Errno(98));
            }
            ns.abstract_names
                .insert(name.clone(), Rc::downgrade(socket));
        } else {
            let p = self.resolve_final(-100, &name[2..name.len() - 1], false)?;
            match self.node(&p) {
                Ok(_) => return Err(Errno(98)),
                Err(Errno(2)) => {}
                Err(e) => return Err(e),
            }
            self.check_parent_write(&p)?;
            self.insert(
                p,
                Content::Socket(Rc::downgrade(socket)),
                0o140000 | (0o777 & !self.umask),
            )?;
        }
        *socket.name.borrow_mut() = name;
        Ok(())
    }
    pub fn local_connect(&self, socket: &Rc<LocalSocket>, bytes: &[u8]) -> Result<()> {
        let (name, abstract_) = Self::local_address(bytes)?;
        if socket.connected.get() {
            return Err(Errno(106));
        }
        if socket.listening() {
            return Err(Errno(22));
        }
        // Unconnected datagrams need per-message destinations and credentials.
        if socket.kind == 2 {
            return Err(Errno(95));
        }
        let peer = if abstract_ {
            socket
                .namespace
                .borrow()
                .abstract_names
                .get(&name)
                .and_then(Weak::upgrade)
                .ok_or(Errno(111))?
        } else {
            let p = self.resolve_final(-100, &name[2..name.len() - 1], true)?;
            let node = self.node(&p)?;
            let n = node.borrow();
            if !self.allowed(&n, 2) {
                return Err(Errno(13));
            }
            let Content::Socket(peer) = &n.content else {
                return Err(Errno(111));
            };
            peer.upgrade().ok_or(Errno(111))?
        };
        if peer.kind != socket.kind {
            return Err(Errno(91));
        }
        let mut listener = peer.listener.borrow_mut();
        let l = listener.as_mut().ok_or(Errno(111))?;
        if l.pending.len() > l.backlog {
            return Err(Errno(11));
        }
        let accepted = self.new_local_in(socket.kind, &peer.network)?;
        accepted.credentials.set(peer.credentials.get());
        socket.credentials.set([
            self.lock_owner,
            self.credentials.euid,
            self.credentials.egid,
        ]);
        *accepted.name.borrow_mut() = peer.name.borrow().clone();
        LocalSocket::pair(socket, &accepted);
        l.pending.push_back(accepted);
        peer.listen_epoch
            .set(peer.listen_epoch.get().wrapping_add(1));
        Ok(())
    }
    pub fn local_accept(&mut self, socket: &LocalSocket, flags: u32) -> Result<(u32, Vec<u8>)> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        let fd = self.available(0)?;
        let accepted = socket
            .listener
            .borrow_mut()
            .as_mut()
            .ok_or(Errno(22))?
            .pending
            .pop_front()
            .ok_or(Errno(11))?;
        let name = accepted.peer_name.borrow().clone();
        self.local_descriptor(fd, accepted, flags);
        Ok((fd, name))
    }

    pub fn send_rights(&self, fds: &[u32]) -> Result<LocalRights> {
        if fds.len() > 253 {
            return Err(Errno(22));
        }
        let mut rights = Vec::new();
        for fd in fds {
            let open = &self.descriptor(*fd)?.open;
            rights.push(open.clone());
        }
        Ok(LocalRights(rights))
    }
    pub fn receive_rights(
        &mut self,
        mut rights: LocalRights,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u32>, bool) {
        let free: Vec<_> = (0..MAX_FDS)
            .filter(|fd| !self.fds.contains_key(fd))
            .take(capacity.min(rights.0.len()))
            .collect();
        let truncated = free.len() < rights.0.len();
        for (&fd, open) in free.iter().zip(rights.0.drain(..free.len())) {
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
        let a = self.new_local(kind & 0xf)?;
        let b = self.new_local(kind & 0xf)?;
        LocalSocket::pair(&a, &b);
        self.local_descriptor(free[0], a, kind);
        self.local_descriptor(free[1], b, kind);
        Ok([free[0], free[1]])
    }
}

#[cfg(test)]
mod waitall_tests {
    use super::*;
    #[test]
    fn sender_self_rights_and_deep_queue_chains_release_without_recursive_borrows() {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut v = Vfs::default();
                let [a, b] = v.socketpair(1, 1, 0).unwrap();
                let weak_a = Rc::downgrade(&v.local_socket(a).unwrap().unwrap());
                v.local_socket(a)
                    .unwrap()
                    .unwrap()
                    .send_rights(b"self", 0, v.send_rights(&[a]).unwrap())
                    .unwrap();
                v.close(a).unwrap();
                assert!(weak_a.upgrade().is_some());
                v.close(b).unwrap();
                assert!(weak_a.upgrade().is_none());
                let [mut sender, root] = v.socketpair(1, 1, 0).unwrap();
                let mut weak = Vec::new();
                for _ in 0..600 {
                    let [next, receiver] = v.socketpair(1, 1, 0).unwrap();
                    weak.push(Rc::downgrade(&v.local_socket(receiver).unwrap().unwrap()));
                    v.local_socket(sender)
                        .unwrap()
                        .unwrap()
                        .send_rights(b"fd", 0, v.send_rights(&[receiver]).unwrap())
                        .unwrap();
                    v.close(receiver).unwrap();
                    v.close(sender).unwrap();
                    sender = next;
                }
                v.close(sender).unwrap();
                let rights = v.send_rights(&[root]).unwrap();
                v.close(root).unwrap();
                // Truncated ancillary reception must use the same bounded
                // destruction path as an unread queue closing.
                let (fds, truncated) = v.receive_rights(rights, 0, false);
                assert!(fds.is_empty() && truncated);
                assert!(weak.iter().all(|socket| socket.upgrade().is_none()));
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn unix_rights_handoff_preserves_lifetime_and_rejects_direct_and_indirect_cycles() {
        let mut v = Vfs::default();
        let [a, b] = v.socketpair(1, 1, 0).unwrap();
        let [c, d] = v.socketpair(1, 1, 0).unwrap();
        let tx = v.local_socket(a).unwrap().unwrap();
        let rx = v.local_socket(b).unwrap().unwrap();
        let c_socket = v.local_socket(c).unwrap().unwrap();
        let weak = Rc::downgrade(&c_socket);
        assert_eq!(
            tx.send_rights(b"cycle", 0, v.send_rights(&[b]).unwrap()),
            Err(Errno(95))
        );
        tx.send_rights(b"fd", 0, v.send_rights(&[c]).unwrap())
            .unwrap();
        assert_eq!(
            v.local_socket(d).unwrap().unwrap().send_rights(
                b"cycle",
                0,
                v.send_rights(&[b]).unwrap()
            ),
            Err(Errno(95))
        );
        assert_eq!(v.readable_bytes(d), Ok(Some(0)));
        v.close(c).unwrap();
        drop(c_socket);
        assert!(weak.upgrade().is_some());
        let packet = rx.recv(2, 0).unwrap();
        assert_eq!(packet.data, b"fd");
        let (fds, truncated) = v.receive_rights(packet.rights, 1, true);
        assert!(!truncated);
        assert_ne!(v.flags(fds[0]).unwrap() & O_CLOEXEC, 0);
        v.write(d, b"still open").unwrap();
        assert_eq!(v.read(fds[0], 32).unwrap(), b"still open");
        v.close(fds[0]).unwrap();
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn fionread_keeps_packet_boundaries_rights_and_shutdown_queues() {
        for kind in [1, 2, 5] {
            let mut v = Vfs::default();
            let [a, b] = v.socketpair(1, kind | O_NONBLOCK, 0).unwrap();
            let receiver = v.local_socket(a).unwrap().unwrap();
            let sender = v.local_socket(b).unwrap().unwrap();
            let [reader, writer] = v.pipe(0).unwrap();
            sender
                .send_rights(b"abc", 0x40000040, v.send_rights(&[writer]).unwrap())
                .unwrap();
            sender.send(b"defgh", 0).unwrap();
            assert_eq!(v.readable_bytes(a), Ok(Some(if kind == 2 { 3 } else { 8 })));
            receiver.shutdown(0).unwrap();
            assert_eq!(v.readable_bytes(a), Ok(Some(if kind == 2 { 3 } else { 8 })));
            // Linux shutdown(SHUT_RD) keeps already queued data/rights readable.
            let packet = receiver.recv(32, 0).unwrap();
            assert_eq!(packet.data, b"abc");
            assert_eq!(packet.rights.0.len(), 1);
            v.close(writer).unwrap();
            assert_eq!(v.read(reader, 1), Err(Errno(11)));
            drop(packet);
            assert_eq!(v.read(reader, 1), Ok(Vec::new()));
            assert_eq!(v.readable_bytes(a), Ok(Some(5)));
            assert_eq!(receiver.recv(32, 0).unwrap().data, b"defgh");
            assert_eq!(v.readable_bytes(a), Ok(Some(0)));
            assert_eq!(sender.send(b"late", 0), Err(Errno(32)));
        }
        let mut v = Vfs::default();
        let [a, b] = v.socketpair(1, 2, 0).unwrap();
        v.write(b, b"").unwrap();
        v.write(b, b"next").unwrap();
        assert_eq!(v.readable_bytes(a), Ok(Some(0)));
        assert!(v
            .local_socket(a)
            .unwrap()
            .unwrap()
            .recv(32, 0)
            .unwrap()
            .data
            .is_empty());
        assert_eq!(v.readable_bytes(a), Ok(Some(4)));
        assert_eq!(v.read(a, 32).unwrap(), b"next");
        assert_eq!(v.readable_bytes(a), Ok(Some(0)));
        let fd = v.local_create(1, 0).unwrap();
        let listener = v.local_socket(fd).unwrap().unwrap();
        assert_eq!(v.readable_bytes(fd), Ok(Some(0)));
        v.local_bind(&listener, b"\x01\x00\x00fionread-listener")
            .unwrap();
        v.local_listen(&listener, 1).unwrap();
        assert_eq!(v.readable_bytes(fd), Err(Errno(22)));
    }
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

#[cfg(test)]
mod named_tests {
    use super::*;
    fn address(path: &[u8]) -> Vec<u8> {
        [b"\x01\x00".as_slice(), path, b"\0"].concat()
    }
    #[test]
    fn socket_lookup_follows_inode_links_and_permission_checks() {
        let mut v = Vfs::default();
        v.mkdir_at(-100, b"/tmp", 0o777).unwrap();
        let fd = v.socket(1, 1, 0).unwrap();
        let s = v.local_socket(fd).unwrap().unwrap();
        v.local_bind(&s, &address(b"/tmp/a")).unwrap();
        s.listen(1).unwrap();
        v.link_at(-100, b"/tmp/a", -100, b"/tmp/b").unwrap();
        v.unlink_at(-100, b"/tmp/a", false).unwrap();
        let client = v.socket(1, 1, 0).unwrap();
        let c = v.local_socket(client).unwrap().unwrap();
        v.chmod_at(-100, b"/tmp/b", 0).unwrap();
        let mut child = v.clone();
        child.credentials = Credentials::user(1000, 1000);
        assert_eq!(child.local_connect(&c, &address(b"/tmp/b")), Err(Errno(13)));
        v.chmod_at(-100, b"/tmp/b", 0o666).unwrap();
        child.local_connect(&c, &address(b"/tmp/b")).unwrap();
        let (accepted, _) = v.local_accept(&s, 0).unwrap();
        assert_eq!(
            v.local_socket(accepted)
                .unwrap()
                .unwrap()
                .peer_credentials()[1..],
            [1000, 1000]
        );
        v.write(client, b"shared inode").unwrap();
        assert_eq!(v.read(accepted, 32).unwrap(), b"shared inode");
    }
    #[test]
    fn accept_fd_exhaustion_retains_pending_connection() {
        let mut v = Vfs::default();
        let listener = v.socket(1, 1, 0).unwrap();
        let s = v.local_socket(listener).unwrap().unwrap();
        v.local_bind(&s, b"\x01\x00\0quota").unwrap();
        s.listen(0).unwrap();
        let client = v.socket(1, 1, 0).unwrap();
        let c = v.local_socket(client).unwrap().unwrap();
        v.local_connect(&c, b"\x01\x00\0quota").unwrap();
        let mut copies = Vec::new();
        while let Ok(fd) = v.dup(client, 0, false) {
            copies.push(fd);
        }
        assert_eq!(v.local_accept(&s, 0), Err(Errno(24)));
        v.close(copies.pop().unwrap()).unwrap();
        let (fd, _) = v.local_accept(&s, O_CLOEXEC).unwrap();
        v.write(client, b"queued").unwrap();
        assert_eq!(v.read(fd, 16).unwrap(), b"queued");
    }
}
