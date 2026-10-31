// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded guest AF_UNIX endpoints. No guest pathname reaches host sockets.
use super::*;
mod binding;
pub(crate) use binding::{PathBinding, PathBindings};
pub(super) mod channel;
mod datagram;
mod native;
pub(crate) use native::Services as NativeServices;
pub use native::WaylandAuth;

#[derive(Clone, Default)]
pub struct LocalRights(pub(super) Vec<OpenHandle>);
thread_local! {
    // Releasing a queued socket may release another queue. Drain ownership
    // iteratively so an acyclic FD chain cannot exhaust the host thread stack.
    static RIGHTS_DROP: RefCell<Option<Vec<OpenHandle>>> = const { RefCell::new(None) };
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
struct Channel {
    resource: Arc<channel::Resource>,
    ends: [Weak<LocalSocket>; 2],
    rights: RefCell<BTreeMap<u64, Ancillary>>,
    next_right: Cell<u64>,
}
#[derive(Clone)]
struct Ancillary {
    rights: LocalRights,
    credentials: Option<[u32; 3]>,
    source: Vec<u8>,
}
pub struct LocalSocket {
    namespace: Rc<RefCell<LocalNamespace>>,
    network: Rc<linux_namespace::RootNetwork>,
    pathname_binding: OnceCell<binding::OwnedBinding>,
    channel: RefCell<Rc<Channel>>,
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
    passcred: Cell<bool>,
    datagram_peer: RefCell<Weak<LocalSocket>>,
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
    pub credentials: Option<[u32; 3]>,
    pub source: Vec<u8>,
}
impl LocalSocket {
    pub fn readable_bytes(&self) -> Result<usize> {
        if self.listening() {
            return Err(Errno(22));
        }
        let binding = self.channel.borrow();
        // Linux AF_UNIX reports one datagram, but all queued bytes for stream
        // and seqpacket. Do not recv/peek here: rights and zero-length packets
        // must remain queued, including after shutdown(SHUT_RD).
        Ok(binding.resource.readable_bytes(self.side.get()))
    }
    fn new(
        kind: u32,
        credentials: [u32; 3],
        network: Rc<linux_namespace::RootNetwork>,
    ) -> Rc<Self> {
        Rc::new(Self {
            namespace: network.local.clone(),
            network,
            pathname_binding: OnceCell::new(),
            channel: RefCell::new(Rc::new(Channel {
                resource: channel::Resource::new(kind, kind == 2),
                ends: [Weak::new(), Weak::new()],
                rights: RefCell::default(),
                next_right: Cell::new(0),
            })),
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
            passcred: Cell::new(false),
            datagram_peer: RefCell::new(Weak::new()),
        })
    }
    fn pair(a: &Rc<Self>, b: &Rc<Self>) {
        let channel = Rc::new(Channel {
            resource: channel::Resource::new(a.kind, true),
            ends: [Rc::downgrade(a), Rc::downgrade(b)],
            rights: RefCell::default(),
            next_right: Cell::new(0),
        });
        for (side, (end, peer)) in [(a, b), (b, a)].into_iter().enumerate() {
            *end.channel.borrow_mut() = channel.clone();
            end.side.set(side);
            end.connected.set(true);
            *end.peer_name.borrow_mut() = peer.name.borrow().clone();
            end.peer_credentials.set(peer.credentials.get());
            channel.resource.set_passcred(side, end.passcred.get());
        }
        // Connect changes direct-resource eligibility without changing the FD
        // table; another forked table may already have cached this description.
        FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
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
        self.channel.borrow().resource.poll(self.side.get(), 0).1
    }

    pub fn set_reuse(&self, option: u32, value: u32) -> Result<()> {
        if option == 16 {
            self.passcred.set(value != 0);
            self.channel
                .borrow()
                .resource
                .set_passcred(self.side.get(), value != 0);
            return Ok(());
        }
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
        if option == 16 {
            return u32::from(self.passcred.get());
        }
        self.reuse.get()[usize::from(option == 15)]
    }
    pub fn kind(&self) -> u32 {
        self.kind
    }
    pub(super) fn direct(&self) -> Option<(Arc<channel::Resource>, usize)> {
        (self.kind == 1 && self.connected.get() && !self.listening())
            .then(|| (self.channel.borrow().resource.clone(), self.side.get()))
    }
    pub(super) fn direct_message(&self) -> Option<(Arc<channel::Resource>, usize)> {
        (matches!(self.kind, 2 | 5)
            && self.connected.get()
            && !self.listening()
            && self.channel.borrow().ends[0].strong_count() != 0)
            .then(|| (self.channel.borrow().resource.clone(), self.side.get()))
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        self.channel
            .borrow()
            .resource
            .shutdown(self.side.get(), how)
    }
    pub fn send(&self, bytes: &[u8], flags: u32) -> Result<usize> {
        self.send_rights(bytes, flags, LocalRights::default())
    }
    pub fn send_rights(&self, bytes: &[u8], flags: u32, rights: LocalRights) -> Result<usize> {
        self.send_rights_credentials(bytes, flags, rights, self.credentials.get())
    }
    fn send_rights_credentials(
        &self,
        bytes: &[u8],
        flags: u32,
        rights: LocalRights,
        credentials: [u32; 3],
    ) -> Result<usize> {
        // Preserve the original flags/connection/state checks before rights
        // graph traversal. Pure bytes need no owner rights-map operation.
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if !self.connected.get() {
            return Err(Errno(if self.kind == 2 { 89 } else { 107 }));
        }
        let binding = self.channel.borrow();
        if rights.is_empty() {
            return binding.resource.send_credentials(
                self.side.get(),
                bytes,
                flags,
                None,
                Some(credentials),
            );
        }
        binding.resource.send_check(self.side.get(), flags)?;
        let peer = binding.ends[1 - self.side.get()]
            .upgrade()
            .ok_or(Errno(if self.kind == 2 { 111 } else { 32 }))?;
        // Keep the existing no-owning-cycle rule. The shared queues only carry
        // IDs; their Rc rights ledger is touched/dropped on this owner thread.
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
            let ids = channel.resource.right_ids(socket.side.get());
            let ledger = channel.rights.borrow();
            for id in ids {
                for open in &ledger.get(&id).expect("queued rights").rights.0 {
                    if let Some(socket) = &open.borrow().local {
                        pending.push(socket.clone());
                    }
                }
            }
        }
        if self.kind == 1 && bytes.is_empty() {
            return Ok(0);
        }
        let id = binding.next_right.get();
        binding.next_right.set(id.checked_add(1).ok_or(Errno(75))?);
        binding.rights.borrow_mut().insert(
            id,
            Ancillary {
                rights,
                credentials: None,
                source: vec![1, 0],
            },
        );
        let result = binding.resource.send_credentials(
            self.side.get(),
            bytes,
            flags,
            Some(id),
            Some(credentials),
        );
        if result.is_err() {
            let unused = binding.rights.borrow_mut().remove(&id);
            drop(unused); // Never destroy rights while borrowing their ledger.
        }
        result
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<LocalReceived> {
        if flags & !(2 | 0x20 | 0x40 | 0x100 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if self.kind == 1 && flags & 0x100 != 0 && flags & 0x40 == 0 && count > PIPE_CAPACITY {
            return Err(Errno(95));
        }
        if !self.connected.get() && self.kind != 2 {
            return Err(Errno(if self.kind == 2 { 11 } else { 22 }));
        }
        let binding = self.channel.borrow();
        let received = binding
            .resource
            .recv(self.side.get(), count, flags, true)
            .expect("owner may receive rights")?;
        let ancillary = if let Some(id) = received.rights {
            if flags & 2 != 0 {
                binding
                    .rights
                    .borrow()
                    .get(&id)
                    .expect("peek rights")
                    .clone()
            } else {
                binding
                    .rights
                    .borrow_mut()
                    .remove(&id)
                    .expect("received rights")
            }
        } else {
            Ancillary {
                rights: LocalRights::default(),
                credentials: None,
                source: vec![1, 0],
            }
        };
        Ok(LocalReceived {
            data: received.data,
            length: received.length,
            truncated: received.truncated,
            rights: ancillary.rights,
            credentials: if self.passcred.get() {
                received
                    .credentials
                    .or(ancillary.credentials)
                    .or(Some([0, 65534, 65534]))
            } else {
                None
            },
            source: ancillary.source,
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
        if !self.connected.get() && self.kind != 2 {
            return (events & 4) | if self.kind == 2 { 0 } else { 16 };
        }
        self.channel
            .borrow()
            .resource
            .poll(self.side.get(), events)
            .0
    }
}
impl Drop for LocalSocket {
    fn drop(&mut self) {
        // Invalidate the path before resource notifications or nested rights
        // destruction can observe it. Inodes never own the socket lifetime.
        drop(self.pathname_binding.take());
        let binding = self.channel.borrow();
        let ids = binding.resource.close(self.side.get());
        let rights: Vec<_> = {
            let mut ledger = binding.rights.borrow_mut();
            ids.into_iter()
                .filter_map(|id| ledger.remove(&id))
                .collect()
        };
        // Nested endpoint destruction must happen with neither byte lock nor
        // rights-map borrow held; LocalRights retains its bounded-stack drain.
        drop(rights);
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
                open: OpenHandle::new(OpenDescription {
                    shared: Arc::new(SharedOpenDescription {
                        _disk_file: None,
                        #[cfg(all(feature = "hostfs", unix))]
                        host_file: None,
                        native_image: None,
                        mount_resource: std::sync::OnceLock::new(),
                        control: None,
                        read_node: None,
                        id: self.open_id(),
                        owner: (self.credentials.fsuid, self.credentials.fsgid),
                        kind: FdKind::Socket,
                        flags: (2 | (flags & O_NONBLOCK)).into(),
                        file_position: Arc::default(),
                        flock: std::sync::OnceLock::new(),
                        ofd_records: Default::default(),
                        node: None,
                        pipe: None,
                        bridge: None,
                        kernel_log: None,
                        notification: None,
                    }),
                    position: 0,
                    socket: None,
                    anonymous: None,
                    local: Some(local),
                    pty: None,
                    namespace: None,
                    network_control: None,
                    oom: None,
                    mount: None,
                }),
                cloexec: (flags & O_CLOEXEC != 0).into(),
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
            let binding = self.path_bindings.bind(socket);
            self.insert(
                p,
                Content::Socket(binding.path()),
                0o140000 | (0o777 & !self.umask()),
            )?;
            // A failed insert drops the unpublished binding and its route.
            let _ = socket.pathname_binding.set(binding);
        }
        *socket.name.borrow_mut() = name;
        Ok(())
    }
    fn local_destination(&self, socket: &LocalSocket, bytes: &[u8]) -> Result<Rc<LocalSocket>> {
        let (name, abstract_) = Self::local_address(bytes)?;
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
            self.path_bindings.resolve(peer).ok_or(Errno(111))?
        };
        if peer.kind != socket.kind {
            return Err(Errno(91));
        }
        Ok(peer)
    }
    pub fn local_connect(&self, socket: &Rc<LocalSocket>, bytes: &[u8]) -> Result<()> {
        if socket.connected.get() {
            return Err(Errno(106));
        }
        if socket.listening() {
            return Err(Errno(22));
        }
        let peer = self.local_destination(socket, bytes)?;
        if socket.kind == 2 {
            *socket.datagram_peer.borrow_mut() = Rc::downgrade(&peer);
            *socket.peer_name.borrow_mut() = peer.name.borrow().clone();
            socket.connected.set(true);
            return Ok(());
        }
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
        accepted.set_reuse(16, peer.reuse(16))?;
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
            self.fds.insert(
                fd,
                Descriptor {
                    open,
                    cloexec: cloexec.into(),
                },
            );
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
