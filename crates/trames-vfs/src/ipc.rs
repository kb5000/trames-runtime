// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded guest AF_UNIX endpoints. No guest pathname reaches host sockets.
use super::*;
mod binding;
pub(crate) use binding::{PathBinding, PathBindings};
pub(super) mod channel;
mod control;
mod datagram;
pub use control::LocalConnection;
pub use datagram::LocalDatagram;
mod native;
pub(super) mod ownership;
#[cfg(test)]
mod shared_graph_tests;
mod shared_rights;
pub(crate) use native::Services as NativeServices;
pub use native::{WaylandAuth, WaylandGrant};
pub use shared_rights::SharedRights;

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
    next_right: AtomicU64,
}
impl Channel {
    fn ends(&self) -> &[std::sync::Weak<LocalResource>; 2] {
        &self.resource.ends
    }
}
struct Binding {
    channel: Arc<Channel>,
    side: usize,
}
/// One authoritative connection publication. Connected I/O never locks the
/// mutable control graph; the unconnected initial resource is released once.
struct LocalChannel {
    initial: std::sync::Mutex<Option<Arc<Channel>>>,
    paired: std::sync::OnceLock<Binding>,
}
enum ChannelRead<'a> {
    Connected(&'a Arc<Channel>),
    Initial(Arc<Channel>),
}
impl std::ops::Deref for ChannelRead<'_> {
    type Target = Arc<Channel>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Connected(channel) => channel,
            Self::Initial(channel) => channel,
        }
    }
}
impl LocalChannel {
    fn new(kind: u32) -> Self {
        Self {
            initial: std::sync::Mutex::new(Some(Arc::new(Channel {
                resource: channel::Resource::new(kind, false),
                next_right: AtomicU64::new(0),
            }))),
            paired: Default::default(),
        }
    }
    fn borrow(&self) -> ChannelRead<'_> {
        if let Some(binding) = self.paired.get() {
            return ChannelRead::Connected(&binding.channel);
        }
        let initial = self.initial.lock().unwrap();
        // Connection publication can complete between the first test and lock.
        match initial.as_ref() {
            Some(channel) => ChannelRead::Initial(channel.clone()),
            None => {
                ChannelRead::Connected(&self.paired.get().expect("connection publication").channel)
            }
        }
    }
    fn install(&self, channel: Arc<Channel>, side: usize) {
        assert!(
            self.paired.set(Binding { channel, side }).is_ok(),
            "Unix connection installed once"
        );
        let unused = self.initial.lock().unwrap().take();
        drop(unused);
    }
    fn side(&self) -> usize {
        self.paired.get().map_or(0, |binding| binding.side)
    }
}
struct OwnerEntry {
    channel: std::sync::Weak<Channel>,
    side: usize,
    data: Ancillary,
}
#[derive(Default)]
pub(super) struct OwnerLedger {
    entries: RefCell<BTreeMap<(usize, u64), OwnerEntry>>,
    pub(super) uring: RefCell<BTreeMap<u64, (std::sync::Weak<()>, RetainedFd)>>,
}
impl OwnerLedger {
    fn reap(&self) {
        self.reap_uring();
        loop {
            let removed: Vec<_> = {
                let mut entries = self.entries.borrow_mut();
                let closed: Vec<_> = entries
                    .iter()
                    .filter_map(|(key, entry)| {
                        entry
                            .channel
                            .upgrade()
                            .is_none_or(|channel| !channel.resource.alive(entry.side))
                            .then_some(*key)
                    })
                    .collect();
                closed
                    .into_iter()
                    .filter_map(|key| entries.remove(&key))
                    .collect()
            };
            if removed.is_empty() {
                break;
            }
            // A released owner FD may close another channel. Drop outside the
            // ledger borrow, then drain only newly closed resources.
            drop(removed);
        }
    }
    pub(super) fn reap_uring(&self) {
        // Owner projections never cross threads. A worker drops only its Arc
        // token; original Rc descriptions retire at the next owner boundary.
        let removed: Vec<_> = {
            let mut entries = self.uring.borrow_mut();
            let dead: Vec<_> = entries
                .iter()
                .filter_map(|(id, (live, _))| (live.strong_count() == 0).then_some(*id))
                .collect();
            dead.into_iter()
                .filter_map(|id| entries.remove(&id))
                .collect()
        };
        drop(removed);
    }
    fn needs_reap(&self) -> bool {
        if self
            .uring
            .borrow()
            .values()
            .any(|(live, _)| live.strong_count() == 0)
        {
            return true;
        }
        self.entries.borrow().values().any(|entry| {
            entry
                .channel
                .upgrade()
                .is_none_or(|channel| !channel.resource.alive(entry.side))
        })
    }
    fn insert(&self, channel: &Arc<Channel>, side: usize, id: u64, data: Ancillary) {
        self.entries.borrow_mut().insert(
            (Arc::as_ptr(channel) as usize, id),
            OwnerEntry {
                channel: Arc::downgrade(channel),
                side,
                data,
            },
        );
    }
    fn get(&self, channel: &Arc<Channel>, id: u64) -> Ancillary {
        self.entries
            .borrow()
            .get(&(Arc::as_ptr(channel) as usize, id))
            .expect("queued rights")
            .data
            .clone()
    }
    fn remove(&self, channel: &Arc<Channel>, id: u64) -> Option<Ancillary> {
        self.entries
            .borrow_mut()
            .remove(&(Arc::as_ptr(channel) as usize, id))
            .map(|entry| entry.data)
    }
}
/// Owner-only ancillary access to the same actual shared socket resource.
/// No mutable connection or address state is stored in this projection.
pub struct LocalSocket {
    core: Arc<LocalResource>,
    // Fields drop in declaration order: release the core before reaping its
    // legacy owner rights on this owner-only view's thread.
    owner: OwnerView,
    _ownership: Option<Arc<ownership::Ownership>>,
}
#[derive(Clone, Default)]
pub(super) struct OwnerView(Rc<OwnerLedger>);
impl std::ops::Deref for OwnerView {
    type Target = OwnerLedger;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for OwnerView {
    fn drop(&mut self) {
        self.0.reap();
    }
}
impl std::ops::Deref for LocalSocket {
    type Target = LocalResource;
    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

#[derive(Clone)]
struct Ancillary {
    rights: LocalRights,
}
pub struct LocalResource {
    ownership: std::sync::Weak<ownership::Ownership>,
    namespace: Arc<SharedCell<LocalNamespace>>,
    network: Arc<linux_namespace::RootNetwork>,
    pathname_binding: std::sync::OnceLock<binding::OwnedBinding>,
    channel: LocalChannel,
    transition: std::sync::Mutex<()>,
    datagram_connected: std::sync::atomic::AtomicBool,
    name: SharedCell<Vec<u8>>,
    peer_name: SharedCell<Vec<u8>>,
    credentials: SharedCell<[u32; 3]>,
    peer_credentials: SharedCell<[u32; 3]>,
    listener: SharedCell<Option<Listener>>,
    listen_epoch: AtomicU64,
    kind: u32,
    reuse: [std::sync::atomic::AtomicU32; 2],
    passcred: std::sync::atomic::AtomicBool,
    timestamp: std::sync::atomic::AtomicU32,
    datagram_peer: SharedCell<std::sync::Weak<LocalResource>>,
}
/// One accepted complete Unix OFD, independent of later close/numeric reuse.
#[derive(Clone)]
pub struct LocalOperation(Arc<SharedOpenDescription>);
impl LocalOperation {
    pub(super) fn from_shared(file: SharedFd) -> Result<Self> {
        file.open.local.as_ref().ok_or(Errno(88))?;
        Ok(Self(file.open))
    }
}
impl std::ops::Deref for LocalOperation {
    type Target = LocalResource;
    fn deref(&self) -> &Self::Target {
        self.0.local.as_deref().expect("Unix OFD")
    }
}
impl DescriptorFactory {
    pub fn local_operation(&self, fd: u32) -> Option<Result<LocalOperation>> {
        Some(self.files.lookup(fd)?.and_then(LocalOperation::from_shared))
    }
    pub fn local_listen(&self, socket: &LocalResource, backlog: u32) -> Result<()> {
        let identity = self.local_sender_credentials();
        let credentials = self.local_credentials();
        socket.listen_as(
            backlog,
            Some([identity[0], credentials.euid, credentials.egid]),
        )
    }
}
struct Listener {
    backlog: usize,
    pending: VecDeque<Arc<LocalResource>>,
}
#[derive(Default)]
pub(super) struct LocalNamespace {
    abstract_names: BTreeMap<Vec<u8>, std::sync::Weak<LocalResource>>,
    sockets: Vec<std::sync::Weak<LocalResource>>,
}
pub struct LocalReceived<R = LocalRights> {
    pub data: Vec<u8>,
    pub length: usize,
    pub truncated: bool,
    pub rights: R,
    pub credentials: Option<[u32; 3]>,
    pub source: Vec<u8>,
    /// Linux cmsg type and (seconds, fractional units) at queue admission.
    pub timestamp: Option<(u32, [u64; 2])>,
}
impl LocalResource {
    fn connected(&self) -> bool {
        self.channel.paired.get().is_some() || self.datagram_connected.load(Ordering::Acquire)
    }
    fn side(&self) -> usize {
        self.channel.side()
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.channel.borrow().resource.readiness.subscribe(signal)
    }
    fn notify(&self) {
        self.channel.borrow().resource.readiness.notify_locked();
    }
    pub fn readable_bytes(&self) -> Result<usize> {
        if self.listening() {
            return Err(Errno(22));
        }
        let binding = self.channel.borrow();
        // Linux AF_UNIX reports one datagram, but all queued bytes for stream
        // and seqpacket. Do not recv/peek here: rights and zero-length packets
        // must remain queued, including after shutdown(SHUT_RD).
        Ok(binding.resource.readable_bytes(self.side()))
    }
    pub(super) fn allocate(
        kind: u32,
        credentials: [u32; 3],
        network: Arc<linux_namespace::RootNetwork>,
        ownership: std::sync::Weak<ownership::Ownership>,
    ) -> Result<Arc<Self>> {
        let mut ns = network.local.borrow_mut();
        ns.sockets.retain(|socket| socket.strong_count() != 0);
        ns.abstract_names
            .retain(|_, socket| socket.strong_count() != 0);
        if ns.sockets.len() >= 1024 {
            return Err(Errno(23));
        }
        let core = Self::new(kind, credentials, network.clone(), ownership);
        ns.sockets.push(Arc::downgrade(&core));
        Ok(core)
    }
    fn new(
        kind: u32,
        credentials: [u32; 3],
        network: Arc<linux_namespace::RootNetwork>,
        ownership: std::sync::Weak<ownership::Ownership>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ownership,
            namespace: network.local.clone(),
            network,
            pathname_binding: std::sync::OnceLock::new(),
            channel: LocalChannel::new(kind),
            transition: std::sync::Mutex::new(()),
            datagram_connected: std::sync::atomic::AtomicBool::new(false),
            name: SharedCell::new(vec![1, 0]),
            peer_name: SharedCell::new(vec![1, 0]),
            credentials: SharedCell::new(credentials),
            peer_credentials: SharedCell::new([0, u32::MAX, u32::MAX]),
            listener: SharedCell::new(None),
            listen_epoch: AtomicU64::new(0),
            kind,
            reuse: Default::default(),
            passcred: std::sync::atomic::AtomicBool::new(false),
            timestamp: std::sync::atomic::AtomicU32::new(0),
            datagram_peer: SharedCell::new(std::sync::Weak::new()),
        })
    }
    pub(super) fn pair(a: &Arc<Self>, b: &Arc<Self>) {
        let mut resource = channel::Resource::with_readiness(
            a.kind,
            true,
            a.channel.borrow().resource.readiness.clone(),
        );
        Arc::get_mut(&mut resource)
            .expect("pair before resource publication")
            .ends = [Arc::downgrade(a), Arc::downgrade(b)];
        let channel = Arc::new(Channel {
            resource,
            next_right: AtomicU64::new(0),
        });
        for (side, (end, peer)) in [(a, b), (b, a)].into_iter().enumerate() {
            *end.peer_name.borrow_mut() = peer.name.borrow().clone();
            end.peer_credentials.set(peer.credentials.get());
            channel
                .resource
                .inherit_options(side, &end.channel.borrow().resource, end.side());
        }
        // The accepted endpoint is unpublished. Publish the client last, after
        // both names, credentials and option sets are complete.
        b.channel.install(channel.clone(), 1);
        a.channel.install(channel, 0);
    }
    pub fn name(&self, peer: bool) -> Result<Vec<u8>> {
        if peer && !self.connected() {
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
        self.listen_as(backlog, None)
    }
    fn listen_as(&self, backlog: u32, identity: Option<[u32; 3]>) -> Result<()> {
        let transition = self.transition.lock().unwrap();
        if self.kind == 2 {
            return Err(Errno(95));
        }
        if self.connected() || self.name.borrow().len() == 2 {
            return Err(Errno(22));
        }
        let mut listener = self.listener.borrow_mut();
        let backlog = backlog.min(128) as usize;
        if let Some(l) = listener.as_mut() {
            l.backlog = backlog;
        } else {
            if let Some(identity) = identity {
                self.credentials.set(identity);
            }
            *listener = Some(Listener {
                backlog,
                pending: VecDeque::new(),
            });
        }
        drop(listener);
        drop(transition);
        self.notify();
        Ok(())
    }
    pub(super) fn poll_epoch(&self) -> [u64; 2] {
        if self.listening() {
            return [self.listen_epoch.load(Ordering::Relaxed), 0];
        }
        self.channel.borrow().resource.poll(self.side(), 0).1
    }

    pub fn set_reuse(&self, option: u32, value: u32) -> Result<()> {
        let transition = self.transition.lock().unwrap();
        if matches!(option, 29 | 35 | 63 | 64) {
            self.timestamp
                .store(if value == 0 { 0 } else { option }, Ordering::Relaxed);
            self.channel
                .borrow()
                .resource
                .set_timestamp(self.side(), if value == 0 { 0 } else { option });
            return Ok(());
        }
        if matches!(option, 7 | 8 | 32 | 33) {
            let binding = self.channel.borrow();
            binding
                .resource
                .set_buffer_unnotified(self.side(), matches!(option, 8 | 33), value);
            drop(transition);
            binding.resource.readiness.notify_locked();
            return Ok(());
        }
        if option == 16 {
            self.passcred.store(value != 0, Ordering::Relaxed);
            self.channel
                .borrow()
                .resource
                .set_passcred(self.side(), value != 0);
            return Ok(());
        }
        let i = match option {
            2 => 0,
            15 => 1,
            _ => return Err(Errno(92)),
        };
        self.reuse[i].store(u32::from(value != 0), Ordering::Relaxed);
        Ok(())
    }
    pub fn reuse(&self, option: u32) -> u32 {
        if matches!(option, 29 | 35 | 63 | 64) {
            return u32::from(self.timestamp.load(Ordering::Relaxed) == option);
        }
        if option == 16 {
            return u32::from(self.passcred.load(Ordering::Relaxed));
        }
        self.reuse[usize::from(option == 15)].load(Ordering::Relaxed)
    }
    pub fn buffer_size(&self, receive: bool) -> usize {
        self.channel
            .borrow()
            .resource
            .buffer_size(self.side(), receive)
    }
    pub fn kind(&self) -> u32 {
        self.kind
    }
    pub(super) fn direct(&self) -> Option<(Arc<channel::Resource>, usize)> {
        let binding = self.channel.paired.get()?;
        (self.kind == 1).then(|| (binding.channel.resource.clone(), binding.side))
    }
    pub(super) fn direct_message(&self) -> Option<(Arc<channel::Resource>, usize)> {
        let binding = self.channel.paired.get()?;
        matches!(self.kind, 2 | 5).then(|| (binding.channel.resource.clone(), binding.side))
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        self.channel.borrow().resource.shutdown(self.side(), how)
    }
    pub fn send(&self, bytes: &[u8], flags: u32) -> Result<usize> {
        if self.addressed_datagram() {
            return self.send_connected_datagram(bytes, flags, Some(self.credentials.get()));
        }
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if !self.connected() {
            return Err(Errno(if self.kind == 2 { 89 } else { 107 }));
        }
        self.channel.borrow().resource.send_credentials(
            self.side(),
            bytes,
            flags,
            None,
            Some(self.credentials.get()),
        )
    }
}
impl LocalSocket {
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
        if self.addressed_datagram() {
            return self.send_connected_rights(bytes, flags, rights, credentials);
        }
        // Preserve the original flags/connection/state checks before rights
        // graph traversal. Pure bytes need no owner rights-map operation.
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if !self.connected() {
            return Err(Errno(if self.kind == 2 { 89 } else { 107 }));
        }
        let binding = self.channel.borrow();
        if rights.is_empty() {
            return binding.resource.send_credentials(
                self.side(),
                bytes,
                flags,
                None,
                Some(credentials),
            );
        }
        // Portable sets exclude Unix owning graphs. Their actual resources
        // travel with the packet without an owner-only ledger.
        if let Some(shared) = rights.shared() {
            return binding.resource.send_shared(
                self.side(),
                bytes,
                flags,
                shared,
                Some(credentials),
            );
        }
        binding.resource.send_check(self.side(), flags)?;
        let peer = binding.ends()[1 - self.side()]
            .upgrade()
            .ok_or(Errno(if self.kind == 2 { 111 } else { 32 }))?;
        let graph = ownership::Ownership::legacy(&peer, &rights)?;
        if self.kind == 1 && bytes.is_empty() {
            return Ok(0);
        }
        let id = binding
            .next_right
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Errno(75))?;
        self.owner
            .insert(&binding, 1 - self.side(), id, Ancillary { rights });
        let result = binding.resource.send_ancillary(
            self.side(),
            bytes,
            flags,
            Some(shared_rights::QueuedRights::legacy(id, graph)),
            Some(credentials),
            Vec::new(),
        );
        if result.is_err() {
            let unused = self.owner.remove(&binding, id);
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
        if !self.connected() && self.kind != 2 {
            return Err(Errno(if self.kind == 2 { 11 } else { 22 }));
        }
        let binding = self.channel.borrow();
        let received = binding
            .resource
            .recv(self.side(), count, flags, true)
            .expect("owner may receive rights")?;
        let ancillary = if let Some(rights) = received.rights {
            if let Some(id) = rights.owner() {
                if flags & 2 != 0 {
                    self.owner.get(&binding, id)
                } else {
                    self.owner.remove(&binding, id).expect("received rights")
                }
            } else {
                Ancillary {
                    rights: rights.into_shared().expect("shared rights").local(),
                }
            }
        } else {
            Ancillary {
                rights: LocalRights::default(),
            }
        };
        Ok(LocalReceived {
            data: received.data,
            length: received.length,
            truncated: received.truncated,
            rights: ancillary.rights,
            credentials: if self.passcred.load(Ordering::Relaxed) {
                received.credentials.or(Some([0, 65534, 65534]))
            } else {
                None
            },
            source: if received.source.is_empty() {
                vec![1, 0]
            } else {
                received.source
            },
            timestamp: (self.timestamp.load(Ordering::Relaxed) != 0)
                .then_some(received.timestamp)
                .flatten()
                .map(|mut stamp| {
                    if matches!(self.timestamp.load(Ordering::Relaxed), 29 | 63) {
                        stamp[1] /= 1000;
                    }
                    (self.timestamp.load(Ordering::Relaxed), stamp)
                }),
        })
    }
}
impl LocalResource {
    pub fn poll(&self, events: u16) -> u16 {
        if let Some(listener) = self.listener.borrow().as_ref() {
            return if listener.pending.is_empty() {
                0
            } else {
                events & 1
            };
        }
        if !self.connected() && self.kind != 2 {
            return (events & 4) | if self.kind == 2 { 0 } else { 16 };
        }
        self.channel.borrow().resource.poll(self.side(), events).0
    }
}
impl Drop for LocalResource {
    fn drop(&mut self) {
        drop(self.pathname_binding.take());
        self.channel.borrow().resource.close(self.side());
    }
}
impl LocalSocket {
    pub(super) fn view(core: Arc<LocalResource>, owner: OwnerView) -> Rc<Self> {
        let ownership = core.ownership.upgrade();
        Rc::new(Self {
            core,
            owner,
            _ownership: ownership,
        })
    }
}

impl Vfs {
    pub fn local_view(&self, core: Arc<LocalResource>) -> Rc<LocalSocket> {
        LocalSocket::view(core, self.local_rights.clone())
    }
    pub fn reap_local_rights(&self) {
        self.local_rights.reap();
    }
    pub fn local_rights_need_owner(&self) -> bool {
        self.local_rights.needs_reap()
    }
    fn new_local(&self, kind: u32) -> Result<Rc<LocalSocket>> {
        self.new_local_in(kind, &self.root_network)
    }
    fn new_local_in(
        &self,
        kind: u32,
        network: &Arc<linux_namespace::RootNetwork>,
    ) -> Result<Rc<LocalSocket>> {
        let core = LocalResource::allocate(
            kind,
            [
                self.lock_owner,
                self.credentials.euid,
                self.credentials.egid,
            ],
            network.clone(),
            Arc::downgrade(&self.shared_files().0.local_ownership),
        )?;
        Ok(LocalSocket::view(core, self.local_rights.clone()))
    }

    pub(super) fn local_description(
        id: u64,
        owner: (u32, u32),
        local: Arc<LocalResource>,
        flags: u32,
    ) -> Descriptor {
        Descriptor {
            open: OpenHandle::new(OpenDescription {
                shared: Arc::new(SharedOpenDescription {
                    oom: None,
                    network_control: None,
                    mount_file: None,
                    runtime_file: None,
                    socket: None,
                    _disk_file: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_file: None,
                    native_image: None,
                    mount_resource: std::sync::OnceLock::new(),
                    mount_use: Default::default(),
                    directory_mount: Default::default(),
                    namespace_resource: None,
                    file_authority: Default::default(),
                    tcp_publication: Default::default(),
                    socket_control: None,
                    control: None,
                    read_node: None,
                    id,
                    owner,
                    kind: FdKind::Socket,
                    flags: (2 | (flags & O_NONBLOCK)).into(),
                    file_position: Arc::default(),
                    flock: std::sync::OnceLock::new(),
                    ofd_records: Default::default(),
                    node: None,
                    pipe: None,
                    pty: None,
                    local: Some(local),
                    bridge: None,
                    kernel_log: None,
                    notification: None,
                }),
                anonymous: None,
                namespace: None,
                mount: None,
            }),
            cloexec: (flags & O_CLOEXEC != 0).into(),
        }
    }
    pub fn local_create(&mut self, kind: u32, protocol: u32) -> Result<u32> {
        self.descriptor_factory().local_create(kind, protocol)
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
        socket.listen_as(
            backlog,
            Some([
                self.lock_owner,
                self.credentials.euid,
                self.credentials.egid,
            ]),
        )
    }
    pub fn local_bind(&mut self, socket: &Rc<LocalSocket>, bytes: &[u8]) -> Result<()> {
        self.local_bind_core(&socket.core, bytes)
    }
    pub fn local_connect(&self, socket: &Rc<LocalSocket>, bytes: &[u8]) -> Result<()> {
        self.local_connection_core(
            &socket.core,
            bytes,
            [
                self.lock_owner,
                self.credentials.euid,
                self.credentials.egid,
            ],
        )?
        .attempt()
    }
    pub fn local_accept(&mut self, socket: &LocalSocket, flags: u32) -> Result<(u32, Vec<u8>)> {
        self.descriptor_factory().accept_local_output(
            socket,
            flags,
            &mut (),
            |_, _| Ok(()),
            |_, _, _| Ok(()),
        )
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
        let free = self.fds.available_fds(capacity.min(rights.0.len()));
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
        drop(rights);
        self.reap_local_rights();
        (free, truncated)
    }
    pub fn local_socket(&self, fd: u32) -> Result<Option<Rc<LocalSocket>>> {
        Ok(self
            .descriptor(fd)?
            .open
            .borrow()
            .local
            .clone()
            .map(|core| LocalSocket::view(core, self.local_rights.clone())))
    }
    pub fn socketpair(&mut self, family: u32, kind: u32, protocol: u32) -> Result<[u32; 2]> {
        self.descriptor_factory()
            .local_pair_with_output(family, kind, protocol, |_| Ok(()))
    }
}

#[cfg(test)]
mod waitall_tests {
    use super::*;
    #[test]
    fn rights_and_worker_masks_cross_the_old_256_descriptor_boundary() {
        let mut v = Vfs::default();
        let mut originals = Vec::new();
        for n in 0..300 {
            originals.push(v.eventfd(n + 1, 0).unwrap());
        }
        let initial = v.stream_descriptors();
        let [reader, writer] = v.pipe(0).unwrap();
        assert!(reader >= 300);
        let before = v.stream_descriptors();
        assert_ne!(before[reader as usize / 64] & (1 << (reader % 64)), 0);
        assert_eq!(before[(MAX_FDS as usize - 1) / 64], 0);
        assert!(
            before.0.len() <= 6,
            "mask must follow actual FD numbers, not the ceiling"
        );
        let rights = v.send_rights(&originals[..3]).unwrap();
        let (received, truncated) = v.receive_rights(rights, 204, true);
        assert!(!truncated);
        assert_eq!(received.len(), 3);
        for (n, fd) in received.into_iter().enumerate() {
            assert_eq!(v.read(fd, 8).unwrap(), (n as u64 + 1).to_le_bytes());
            assert_ne!(v.flags(fd).unwrap() & O_CLOEXEC, 0);
        }
        v.close(reader).unwrap();
        v.close(writer).unwrap();
        assert_eq!(v.stream_descriptors(), initial);
        assert_ne!(
            before[reader as usize / 64] & (1 << (reader % 64)),
            0,
            "old epoch keeps immutable classification"
        );
    }
    #[test]
    fn sender_self_rights_and_deep_queue_chains_release_without_recursive_borrows() {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut v = Vfs::default();
                let [a, b] = v.socketpair(1, 1, 0).unwrap();
                let weak_a = Arc::downgrade(&v.local_socket(a).unwrap().unwrap().core);
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
                    weak.push(Arc::downgrade(
                        &v.local_socket(receiver).unwrap().unwrap().core,
                    ));
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
        let weak = Arc::downgrade(&c_socket.core);
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
        // Exercise real exhaustion without filling the normal million-FD space.
        v.fds.set_test_capacity(32);
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
