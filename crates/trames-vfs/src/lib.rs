// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared virtual namespace; host IO is confined to an explicitly selected store.
mod bpf;
pub mod capabilities;
mod cgroup;
mod fs_context;
mod fs_data;
use fs_context::FsContext;
pub use fs_context::Umask;
use fs_data::{FsBorrow, FsHandle};
mod credentials;
mod fd_status;
use fd_status::{CloseOnExec, DescriptorFlags, StatusFlags};
mod pipe;
pub use pipe::PipeEndpoint;
use pipe::{Pipe, PipeEnd};
mod fd_table;
mod open_handle;
use open_handle::{OpenHandle, OpenWeak};
mod shared_cell;
use shared_cell::SharedCell;
mod flock;
use fd_table::{Descriptor, DescriptorTable};
pub use fd_table::{SharedFd, SharedFiles};
pub use flock::FlockRequest;
mod directory;
mod disk_io;
pub use disk_io::{DiskRead, DiskReadCache, DiskReadJob};
mod direct_io;
mod file_data;
mod file_io;
use direct_io::PipeResource;
pub use file_io::{DirectFile, DirectFiles, FileEpoch};
mod readiness;
mod timer_io;
pub use direct_io::{DirectFd, DirectFds, DirectPoll};
pub use readiness::{IoSignal, IoSubscription, IoWake};
pub use timer_io::TimerFd;
pub use trames_shared::{HostEvents, HostFd, HostSubscription, Readiness};
mod events;
mod uring;
pub use uring::{
    RetainedFd, Uring, UringBufferGroup, UringBufferSource, UringProvidedBuffer, UringRequest,
    UringSqe, UringState, URING_CQES, URING_MAX_ENTRIES, URING_OPS, URING_SQ_ARRAY,
};
mod executable;
pub use executable::ExecutableFile;
mod inotify;
pub use inotify::{FileClose, InotifyInstance};
mod ipc;
mod kernel_log;
pub use kernel_log::KernelLogAccess;
mod locks;
mod mapped;
mod memfd;
mod mounts;
use mounts::{Mount, PathArg};
pub use mounts::{MountNamespace, ResolvedPath, CLONE_NEWNS};
mod syscall_names;
pub use ipc::{LocalReceived, LocalRights, LocalSocket, WaylandAuth};
pub use locks::{RecordLock, RecordLockContext};
mod linux_namespace;
mod pid_namespace;
pub use pid_namespace::{PidNamespace, CLONE_NEWPID};
mod namespace;
mod xattr;
pub use linux_namespace::{
    NamespaceSnapshot, UtsAccess, UtsNamespace, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET,
    CLONE_NEWUTS,
};
mod network;
mod network_io;
pub use network_io::{DirectNetwork, DirectTcpFd, NetworkEpoch};
mod oom;
mod overlay;
mod pseudo;
pub use oom::OomTask;
mod pty;
pub mod terminal;
pub use pty::{Pty, PtyEnd, PtyIo, PtySlaveEndpoint, TerminalAccess};
mod storage;
#[cfg(test)]
mod storage_tests;
pub use credentials::Credentials;
pub use pseudo::{FdInfo, ProcessInfo, RuntimeInfo};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::{BTreeMap, VecDeque},
    fmt,
    rc::{Rc, Weak},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
// Resource lifetime changes invalidate cached epoll/direct capabilities.
// Mutable OFD status is shared separately and needs no cache invalidation.
static FD_FLAGS_REVISION: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Default)]
pub struct FdFlags(Arc<[Option<DescriptorFlags>]>, Option<SharedFiles>);
pub enum EpochIo {
    Stream,
    File,
}
pub fn query_fd_flags(flags: u32, command: u64) -> Result<u64> {
    match command {
        1 => Ok(u64::from(flags & O_CLOEXEC != 0)),
        3 => Ok((flags & !(O_CLOEXEC | 0x40 | 0x80 | 0x100 | 0x200)) as u64),
        _ => Err(Errno(22)),
    }
}
pub use storage::{DiskOptions, StorageCapacity, StorageLimits, VolumeSpace, DEFAULT_DISK_BYTES};
pub use trames_net::{NetworkMode, Socket as NetSocket};
pub fn kernel_log_capacity() -> usize {
    kernel_log::LOG_CAPACITY
}
pub const MAX_PATH: usize = 4096;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NODES: usize = 1024;
pub const MAX_FDS: u32 = 256;
pub type FdMask = [u64; (MAX_FDS as usize).div_ceil(64)];
/// Scheduler task budget, also reported by procfs and RLIMIT_NPROC.
pub const MAX_TASKS: usize = 256;
pub const PIPE_CAPACITY: usize = 65536;
pub const AT_FDCWD: i32 = -100;
pub const O_DIRECTORY: u32 = 0x4000;
pub const O_NOFOLLOW: u32 = 0x8000;
pub const O_LARGEFILE: u32 = 0x20000;
pub const O_CLOEXEC: u32 = 0x80000;
pub const O_NONBLOCK: u32 = 0x800;
pub const O_PATH: u32 = 0x200000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(pub u32);
impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "virtual filesystem errno {}", self.0)
    }
}
impl std::error::Error for Errno {}
type Result<T> = std::result::Result<T, Errno>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdKind {
    Stdin,
    Stdout,
    Stderr,
    Node(Vec<u8>),
    PipeRead,
    PipeWrite,
    Terminal,
    Socket,
    Anonymous,
}
struct OpenDescription {
    shared: Arc<SharedOpenDescription>,
    position: u64,
    socket: Option<Rc<NetSocket>>,
    anonymous: Option<events::Anonymous>,
    local: Option<Rc<LocalSocket>>,
    pty: Option<Rc<PtyEnd>>,
    namespace: Option<linux_namespace::NamespaceHandle>,
    oom: Option<std::sync::Weak<OomTask>>,
    network_control: Option<network::Control>,
    mount: Option<Rc<Mount>>,
}
// The actual file, pipe and lock/notification lifetimes share one allocation.
// Endpoint/namespace control projections above still retain owner ownership.
struct SharedOpenDescription {
    id: u64,
    owner: (u32, u32),
    kind: FdKind,
    flags: StatusFlags,
    file_position: Arc<std::sync::Mutex<file_data::FilePosition>>,
    flock: std::sync::OnceLock<Arc<flock::Owner>>,
    node: Option<NodeRef>,
    // Overlay read descriptions retain the real lower file selected at open.
    read_node: Option<NodeRef>,
    pipe: Option<Arc<PipeEnd>>,
    bridge: Option<std::sync::Arc<trames_bridge::Connection>>,
    kernel_log: Option<Arc<kernel_log::Kmsg>>,
    notification: Option<Arc<FileClose>>,
}
impl std::ops::Deref for OpenDescription {
    type Target = SharedOpenDescription;
    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}
impl Drop for OpenDescription {
    fn drop(&mut self) {
        // Epoll snapshots in another forked FD table may retain this resource
        // without retaining the open description. Last-close must invalidate
        // those tables too, so their next snapshot removes the dead watch.
        if self.local.is_some()
            || matches!(
                self.anonymous,
                Some(
                    events::Anonymous::Event(_)
                        | events::Anonymous::Timer(_)
                        | events::Anonymous::Inotify(_)
                )
            )
        {
            FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Drop for SharedOpenDescription {
    fn drop(&mut self) {
        if self.pipe.is_some() || self.kernel_log.is_some() {
            FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
        }
        drop(self.notification.take());
    }
}
impl OpenDescription {
    fn current_position(&self) -> u64 {
        if let Some(log) = &self.kernel_log {
            return log.position();
        }
        if self.data_node().is_some_and(|n| {
            let n = n.borrow();
            !n.volatile && matches!(n.content, Content::File(_))
        }) {
            self.file_position.lock().unwrap().value
        } else {
            self.position
        }
    }
    fn data_node(&self) -> Option<NodeRef> {
        self.read_node.clone().or_else(|| self.node.clone())
    }
    fn metadata_node(&self) -> Option<NodeRef> {
        self.node
            .clone()
            .or_else(|| self.pipe.as_ref()?.metadata.clone())
    }
}
enum Content {
    Directory,
    File(storage::FileData),
    Symlink(Vec<u8>),
    Null,
    Terminal,
    Device(pseudo::Device),
    Fifo(Pipe),
    Socket(ipc::PathBinding),
}
type NodeRef = Arc<Inode>;
struct Inode {
    identity: u64,
    state: SharedCell<Node>,
    length: std::sync::OnceLock<trames_shared::LogicalSize>,
}
impl Inode {
    fn new(mut node: Node) -> Self {
        node.identity = trames_memory::new_backing_identity();
        Self {
            identity: node.identity,
            state: SharedCell::new(node),
            length: std::sync::OnceLock::new(),
        }
    }
    fn borrow(&self) -> std::sync::RwLockReadGuard<'_, Node> {
        self.state.borrow()
    }
    fn borrow_mut(&self) -> InodeWrite<'_> {
        InodeWrite {
            owner_cell: self,
            state_guard: self.state.borrow_mut(),
        }
    }
    fn length_for(&self, node: &Node) -> trames_shared::LogicalSize {
        self.length
            .get_or_init(|| {
                let size = trames_shared::LogicalSize::new(0);
                if let Content::File(data) = &node.content {
                    size.follow(&data.logical_size())
                        .expect("acyclic lower inode sizes");
                }
                size.on_change(trames_memory::backing_changed);
                size
            })
            .clone()
    }
    fn logical_size(&self) -> trames_shared::LogicalSize {
        if let Some(size) = self.length.get() {
            return size.clone();
        }
        self.length_for(&self.borrow())
    }
}
struct InodeWrite<'a> {
    owner_cell: &'a Inode,
    state_guard: std::sync::RwLockWriteGuard<'a, Node>,
}
impl std::ops::Deref for InodeWrite<'_> {
    type Target = Node;
    fn deref(&self) -> &Node {
        &self.state_guard
    }
}
impl std::ops::DerefMut for InodeWrite<'_> {
    fn deref_mut(&mut self) -> &mut Node {
        &mut self.state_guard
    }
}
impl Drop for InodeWrite<'_> {
    fn drop(&mut self) {
        if let Some(size) = self.owner_cell.length.get() {
            if let Content::File(data) = &self.state_guard.content {
                size.follow(&data.logical_size())
                    .expect("acyclic lower inode sizes");
            } else {
                size.store(0, Ordering::Relaxed);
            }
        }
    }
}
struct Node {
    identity: u64,
    record_locks: std::sync::OnceLock<Arc<locks::Records>>,
    whole_locks: std::sync::OnceLock<Arc<flock::Whole>>,
    notifications: inotify::Marks,
    // A validated name hint, not an authorization or lifetime cache. It follows
    // the inode and is not serialized; rename/unlink/bind-root changes miss.
    path_hint: SharedCell<Option<Vec<u8>>>,
    device: u64,
    content: Content,
    mode: u32,
    uid: u32,
    gid: u32,
    volatile: bool,
    inode: u64,
    links: u32,
    times: [storage::Timestamp; 3],
    seals: Option<u32>,
    xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}
impl Node {
    fn file_metadata(&self) -> file_data::FileMeta {
        if let Content::File(storage::FileData::Plain(data)) = &self.content {
            if let Some(meta) = data.metadata() {
                return meta;
            }
        }
        file_data::FileMeta {
            mode: self.mode,
            times: self.times,
        }
    }
    fn path_in(&self, paths: &BTreeMap<Vec<u8>, NodeRef>, root: &[u8]) -> Option<Vec<u8>> {
        let matches = |node: &NodeRef| node.identity == self.identity;
        if let Some(path) = self.path_hint.borrow().as_ref() {
            if mounts::below(path, root) && paths.get(path).is_some_and(matches) {
                return Some(path.clone());
            }
        }
        let path = paths
            .iter()
            .find(|(path, node)| mounts::below(path, root) && matches(node))
            .map(|(path, _)| path.clone());
        *self.path_hint.borrow_mut() = path.clone();
        path
    }
}
type ResolvedInode = (NodeRef, Vec<u8>, Option<Rc<Mount>>);
type ResolvedEntry = (ResolvedPath, Option<ResolvedInode>);
struct Filesystem {
    shared_budget: trames_shared::SharedBudget,
    paths: BTreeMap<Vec<u8>, NodeRef>,
    inodes: Vec<std::sync::Weak<Inode>>,
    next_inode: u64,
    limits: StorageLimits,
    disk: Option<Arc<storage::DiskStore>>,
    volume: Option<(VolumeSpace, u64)>,
}
pub struct Vfs {
    network: trames_net::Network,
    native_services: Rc<RefCell<Option<Rc<RefCell<ipc::NativeServices>>>>>,
    fs: FsHandle,
    fds: DescriptorTable,
    context: FsContext,
    uts: UtsNamespace,
    root_network: Rc<linux_namespace::RootNetwork>,
    path_bindings: ipc::PathBindings,
    ipc_namespace: Rc<linux_namespace::IpcNamespace>,
    cgroup_namespace: Rc<linux_namespace::CgroupNamespace>,
    pid_ns: PidNamespace,
    pid_children: PidNamespace,
    mounts: Option<MountNamespace>,
    mount_registry: Rc<RefCell<Vec<Weak<Mount>>>>,
    detached_mounts: Rc<RefCell<Vec<Vec<Rc<Mount>>>>>,
    pub credentials: Credentials,
    pseudo: Rc<RefCell<pseudo::PseudoFs>>,
    kernel_log: Arc<kernel_log::KernelLog>,
    cgroups: Rc<RefCell<cgroup::Cgroups>>,
    dumpable: Rc<Cell<bool>>,
    pid: u32,
    lock_owner: u32,
    record_locks: Arc<locks::Registry>,
    file_size_limit: u64,
    file_size_signal: Cell<bool>,
    next_open: Rc<Cell<u64>>,
    proc_accessed: Cell<bool>,
    ptys: Rc<RefCell<BTreeMap<u32, Weak<Pty>>>>,
    embedding_terminal: Rc<Cell<bool>>,
    pub controlling_terminal: Option<u32>,
    controlling_pair: Option<Rc<Pty>>,
    bridge: Option<trames_bridge::Broker>,
}
impl Clone for Vfs {
    fn clone(&self) -> Self {
        self.clone_with_files(false)
    }
}
impl Vfs {
    pub fn shared_files(&self) -> SharedFiles {
        self.fds.worker_membership()
    }
    /// Clone task context while choosing the Linux FD ownership domain.
    /// CLONE_FILES never allocates a temporary private FD map or flag cells.
    pub fn clone_with_files(&self, shared: bool) -> Self {
        self.clone_with_resources(shared, false)
    }
    pub fn clone_with_resources(&self, shared_files: bool, shared_fs: bool) -> Self {
        Self {
            network: self.network.clone(),
            native_services: self.native_services.clone(),
            fs: self.fs.clone(),
            fds: if shared_files {
                self.fds.shared()
            } else {
                self.fds.clone()
            },
            context: if shared_fs {
                self.context.shared()
            } else {
                self.context.clone()
            },
            uts: self.uts.clone(),
            root_network: self.root_network.clone(),
            path_bindings: self.path_bindings.clone(),
            ipc_namespace: self.ipc_namespace.clone(),
            cgroup_namespace: self.cgroup_namespace.clone(),
            pid_ns: self.pid_ns.clone(),
            pid_children: self.pid_children.clone(),
            mounts: self.mounts.clone(),
            mount_registry: self.mount_registry.clone(),
            detached_mounts: self.detached_mounts.clone(),
            credentials: self.credentials.clone(),
            pseudo: self.pseudo.clone(),
            kernel_log: self.kernel_log.clone(),
            cgroups: self.cgroups.clone(),
            dumpable: self.dumpable.clone(),
            pid: self.pid,
            lock_owner: self.lock_owner,
            record_locks: self.record_locks.clone(),
            file_size_limit: self.file_size_limit,
            file_size_signal: self.file_size_signal.clone(),
            next_open: self.next_open.clone(),
            proc_accessed: self.proc_accessed.clone(),
            ptys: self.ptys.clone(),
            embedding_terminal: self.embedding_terminal.clone(),
            controlling_terminal: self.controlling_terminal,
            controlling_pair: self.controlling_pair.clone(),
            bridge: self.bridge.clone(),
        }
    }
}

impl Default for Vfs {
    fn default() -> Self {
        let pid_ns = PidNamespace::default();
        let root_network = Rc::new(linux_namespace::RootNetwork::default());
        let network = root_network.network.borrow().clone();
        let mut v = Self {
            network,
            native_services: Rc::default(),
            fs: FsHandle::new(Filesystem {
                shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
                paths: BTreeMap::new(),
                inodes: Vec::new(),
                next_inode: 1,
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            }),
            fds: DescriptorTable::default(),
            context: FsContext::default(),
            uts: UtsNamespace::default(),
            root_network,
            path_bindings: ipc::PathBindings::default(),
            ipc_namespace: Rc::default(),
            cgroup_namespace: Rc::default(),
            pid_ns: pid_ns.clone(),
            pid_children: pid_ns,
            mounts: None,
            mount_registry: Rc::default(),
            detached_mounts: Rc::default(),
            credentials: Credentials::default(),
            pseudo: Rc::new(RefCell::new(pseudo::PseudoFs::default())),
            kernel_log: Arc::default(),
            cgroups: Rc::default(),
            dumpable: Rc::new(Cell::new(true)),
            pid: 1,
            ptys: Rc::default(),
            embedding_terminal: Rc::default(),
            controlling_terminal: None,
            controlling_pair: None,
            lock_owner: 1,
            record_locks: Arc::default(),
            file_size_limit: u64::MAX,
            file_size_signal: Cell::new(false),
            next_open: Rc::new(Cell::new(1)),
            proc_accessed: Cell::new(false),
            bridge: None,
        };
        v.insert(b"/".to_vec(), Content::Directory, 0o40755)
            .expect("root");
        v.context.paths.borrow_mut().cwd_node = Some(v.node(b"/").expect("root inode"));
        v.insert(b"/dev".to_vec(), Content::Directory, 0o40755)
            .expect("dev");
        v.insert(b"/dev/null".to_vec(), Content::Null, 0o20666)
            .expect("null");
        for (fd, kind, flags) in [
            (0, FdKind::Stdin, 0),
            (1, FdKind::Stdout, 1),
            (2, FdKind::Stderr, 1),
        ] {
            v.fds.insert(
                fd,
                Descriptor {
                    open: OpenHandle::new(OpenDescription {
                        shared: Arc::new(SharedOpenDescription {
                            read_node: None,
                            id: v.open_id(),
                            owner: (v.credentials.fsuid, v.credentials.fsgid),
                            kind,
                            flags: flags.into(),
                            file_position: Arc::default(),
                            flock: std::sync::OnceLock::new(),
                            node: None,
                            pipe: None,
                            bridge: None,
                            kernel_log: None,
                            notification: None,
                        }),
                        position: 0,
                        socket: None,
                        anonymous: None,
                        local: None,
                        pty: None,
                        namespace: None,
                        network_control: None,
                        oom: None,
                        mount: None,
                    }),
                    cloexec: (false).into(),
                },
            );
        }
        v.initialize_mounts().expect("initial mount namespace");
        v
    }
}
impl Vfs {
    pub fn attach_bridge(&mut self, broker: trames_bridge::Broker) {
        self.bridge = Some(broker);
    }
    pub fn bridge_fd(&self, fd: u32) -> bool {
        self.descriptor(fd)
            .is_ok_and(|d| d.open.borrow().bridge.is_some())
    }
    pub fn has_bridge_descriptors(&self) -> bool {
        self.fds
            .entries()
            .values()
            .any(|d| d.open.borrow().bridge.is_some())
    }
    fn open_id(&self) -> u64 {
        let id = self.next_open.get();
        self.next_open.set(id.wrapping_add(1));
        (1u64 << 62) | id
    }
    /// CLONE_FILES joins the same membership object; later edits need no propagation.
    pub fn share_descriptors_from(&mut self, other: &Self) {
        self.fds = other.fds.shared();
    }
    pub fn shares_descriptors_with(&self, other: &Self) -> bool {
        self.fds.shares_with(&other.fds)
    }
    /// Detach table metadata, retaining the same open descriptions. Structural
    /// clone/unshare/exec still execute at a joined lifecycle boundary.
    pub fn unshare_descriptors(&mut self) {
        self.fds = self.fds.clone();
    }
    /// Immutable descriptor kinds for one CPU epoch. Cached per shared table
    /// version, so dispatch does not scan all descriptors on every syscall.
    pub fn stream_descriptors(&self) -> FdMask {
        self.descriptor_io_masks().0
    }
    /// Live admitted membership/status/CLOEXEC. Excluded owner controls keep
    /// their frozen epoch capabilities; those structural edits still join.
    pub fn fd_flags_snapshot(&self) -> FdFlags {
        self.descriptor_snapshots().0
    }
    fn descriptor_snapshots(&self) -> (FdFlags, DirectFds) {
        let identity = self.fds.identity();
        let revision = FD_FLAGS_REVISION.load(Ordering::Relaxed);
        let metadata = self.fds.metadata();
        let mut cached = metadata.flags.borrow_mut();
        if let Some((old, snapshot)) = &*cached {
            if *old == revision {
                if let Some((direct_revision, direct)) = &*identity.direct.borrow() {
                    if *direct_revision == revision {
                        return (snapshot.clone(), direct.clone());
                    }
                }
            }
        }
        let descriptors = self.fds.entries();
        let mut entries = vec![
            None;
            descriptors
                .last_key_value()
                .map_or(0, |(&fd, _)| fd as usize + 1)
        ];
        let mut direct = vec![None; entries.len()];
        for (&fd, d) in descriptors.iter() {
            let open = d.open.borrow();
            entries[fd as usize] = Some(DescriptorFlags {
                status: open.flags.clone(),
                cloexec: d.cloexec.clone(),
            });
            direct[fd as usize] = DirectFd::snapshot(&open);
        }
        let snapshot = FdFlags(entries.into(), Some(self.shared_files()));
        *cached = Some((revision, snapshot.clone()));
        let direct = DirectFds(direct.into());
        *identity.direct.borrow_mut() = Some((revision, direct.clone()));
        (snapshot, direct)
    }
    fn ordinary_stream(o: &OpenDescription) -> bool {
        matches!(
            o.kind,
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::PipeRead | FdKind::PipeWrite
        ) || o.bridge.is_none() && o.local.as_ref().is_some_and(|socket| socket.kind() == 1)
    }
    /// Ready byte I/O only; recvmsg/SCM_RIGHTS, native bridge and PTY job control
    /// stay on their joined paths. Local sockets never reference worker Memory.
    pub fn epoch_stream_io(&self, fd: u32) -> bool {
        self.descriptor(fd)
            .is_ok_and(|d| Self::ordinary_stream(&d.open.borrow()))
    }
    fn descriptor_io_masks(&self) -> (FdMask, FdMask) {
        *self.fds.identity().io.get_or_init(|| {
            let mut streams = [0; (MAX_FDS as usize).div_ceil(64)];
            let mut files = streams;
            for (&fd, d) in self.fds.entries().iter() {
                let o = d.open.borrow();
                if Self::ordinary_stream(&o) {
                    streams[fd as usize / 64] |= 1 << (fd % 64);
                } else if Self::ordinary_file(&o, false).is_some() {
                    files[fd as usize / 64] |= 1 << (fd % 64);
                }
            }
            (streams, files)
        })
    }
    /// Candidate regular files, not a cached authorization or mapping decision.
    /// Recheck epoch_file_io before effects: mmap need not edit the FD table.
    pub fn file_descriptors(&self) -> FdMask {
        self.descriptor_io_masks().1
    }
    fn ordinary_file(o: &OpenDescription, write: bool) -> Option<NodeRef> {
        if !matches!(o.kind, FdKind::Node(_))
            || o.bridge.is_some()
            || o.kernel_log.is_some()
            || o.oom.is_some()
            || o.network_control.is_some()
            || o.mount.as_ref().is_some_and(|m| {
                matches!(
                    m.kind,
                    mounts::Kind::Proc | mounts::Kind::Sysfs | mounts::Kind::Cgroup
                )
            })
        {
            return None;
        }
        let node = if write { o.node.clone() } else { o.data_node() }?;
        let regular = {
            let n = node.borrow();
            !n.volatile && matches!(&n.content, Content::File(data) if data.shared_file().is_none())
        };
        regular.then_some(node)
    }
    /// Coordinator-only check against the retained inode, never a path lookup.
    /// Reads exclude shared writers in every VM; writes exclude all live maps.
    /// Writable shared snapshots must be committed before VFS can observe them.
    pub fn epoch_file_io(&self, fd: u32, write: bool) -> bool {
        matches!(self.epoch_io(fd, write), Some(EpochIo::File))
    }
    /// One retained-description lookup for service admission; no path cloning
    /// or second stream/file table walk in the coordinator's common I/O path.
    pub fn epoch_io(&self, fd: u32, write: bool) -> Option<EpochIo> {
        let o_descriptor = self.descriptor(fd).ok()?;
        let o = o_descriptor.open.borrow();
        if Self::ordinary_stream(&o) {
            return Some(EpochIo::Stream);
        }
        let node = Self::ordinary_file(&o, write)?;
        let ready =
            matches!(&node.borrow().content, Content::File(data) if data.epoch_io_safe(write));
        ready.then_some(EpochIo::File)
    }

    pub fn import_executable(&mut self, path: &[u8], bytes: Vec<u8>) -> Result<()> {
        self.import_reader(path, &mut bytes.as_slice(), true)
            .map(|_| ())
    }
    fn check_parent_write(&self, path: &ResolvedPath) -> Result<()> {
        path.writable()?;
        if Self::cgroup_mount(path)
            || path
                .mount
                .as_ref()
                .is_some_and(|m| m.devpts.is_some() || m.kind == mounts::Kind::Mqueue)
        {
            return Err(Errno(1));
        }
        if self.pseudo_readonly(&path.key) && self.uses_pseudo(path) {
            return Err(Errno(30));
        }
        if !self.allowed(&self.node(&path.parent())?.borrow(), 3) {
            return Err(Errno(13));
        }
        Ok(())
    }
    pub fn poll(&self, fd: u32, events: u16) -> u16 {
        self.poll_signals(fd, events, 0)
    }
    /// Non-consuming FIONREAD query for guest queues, including native Wayland
    /// connections (whose incoming bytes use the same local socket channel).
    pub fn readable_bytes(&self, fd: u32) -> Result<Option<usize>> {
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
        if let Some(socket) = &open.local {
            return socket.readable_bytes().map(Some);
        }
        if let Some(end) = &open.pipe {
            return Ok(Some(end.data.lock().unwrap().bytes.len()));
        }
        Ok(match &open.anonymous {
            Some(events::Anonymous::Inotify(i)) => Some(i.queue.available()),
            _ => None,
        })
    }
    pub fn poll_signals(&self, fd: u32, events: u16, pending: u64) -> u16 {
        let Ok(d) = self.descriptor(fd) else {
            return 32;
        };
        let open = d.open.borrow();
        Self::poll_open(&open, events, pending)
    }
    fn poll_open(o: &OpenDescription, events: u16, pending: u64) -> u16 {
        if let Some(end) = &o.pty {
            return end.pair.poll(end.master, events);
        }
        if let Some(log) = &o.kernel_log {
            return log.poll(events).0;
        }
        if matches!(o.kind, FdKind::Stdout | FdKind::Stderr) {
            return events & 4;
        }
        if let Some(local) = &o.local {
            return local.poll(events);
        }
        if let Some(anonymous) = &o.anonymous {
            return anonymous.poll(events, pending);
        }
        if let Some(bridge) = &o.bridge {
            return bridge.poll(events);
        }
        if let Some(socket) = &o.socket {
            return socket.poll(events).unwrap_or(8);
        }
        let mut ready = events & 5;
        if let Some(end) = &o.pipe {
            let p = end.data.lock().unwrap();
            ready = 0;
            if end.read {
                if !p.bytes.is_empty() {
                    ready |= events & 1;
                }
                if p.writers == 0 && p.write_epoch != end.initial_write_epoch {
                    ready |= 16;
                }
            }
            if end.write {
                if p.readers == 0 {
                    ready |= 8;
                } else if PIPE_CAPACITY - p.bytes.len() >= 4096 {
                    ready |= events & 4;
                }
            }
        }
        ready
    }
    pub fn enable_terminal(&mut self) -> Result<()> {
        self.embedding_terminal.set(true);
        self.controlling_terminal = Some(0);
        if self.node(b"/dev/tty").is_err() {
            self.insert(b"/dev/tty".to_vec(), Content::Terminal, 0o20666)?;
        }
        for fd in 0..=2 {
            self.fds.insert(
                fd,
                Descriptor {
                    open: OpenHandle::new(OpenDescription {
                        shared: Arc::new(SharedOpenDescription {
                            read_node: None,
                            id: self.open_id(),
                            owner: (self.credentials.fsuid, self.credentials.fsgid),
                            kind: FdKind::Terminal,
                            flags: (2).into(),
                            file_position: Arc::default(),
                            flock: std::sync::OnceLock::new(),
                            node: None,
                            pipe: None,
                            bridge: None,
                            kernel_log: None,
                            notification: None,
                        }),
                        position: 0,
                        socket: None,
                        anonymous: None,
                        local: None,
                        pty: None,
                        namespace: None,
                        network_control: None,
                        oom: None,
                        mount: None,
                    }),
                    cloexec: (false).into(),
                },
            );
        }
        Ok(())
    }
    fn insert(
        &mut self,
        path: impl Into<ResolvedPath>,
        content: Content,
        mut mode: u32,
    ) -> Result<()> {
        let path = path.into();
        let filesystem = path.filesystem(self);
        let parent = if path == b"/" {
            None
        } else {
            path.iter().rposition(|b| *b == b'/').and_then(|i| {
                self.node(&ResolvedPath {
                    key: path[..i.max(1)].to_vec(),
                    mount: path.mount.clone(),
                })
                .ok()
            })
        };
        let inherited = parent.as_ref().and_then(|p| {
            let p = p.borrow();
            (p.mode & 0o2000 != 0).then_some(p.gid)
        });
        if inherited.is_some() && matches!(content, Content::Directory) {
            mode |= 0o2000;
        }
        let mut fs = filesystem.borrow_mut();
        fs.inodes.retain(|n| n.strong_count() != 0);
        if fs.inodes.len() >= fs.limits.nodes || fs.paths.len() >= fs.limits.nodes {
            return Err(Errno(28));
        }
        let old_next = fs.next_inode;
        let inode = if let Content::File(data) = &content {
            match data.inode() {
                Some(inode) => inode,
                None => match &fs.overlay {
                    Some(overlay) => overlay.allocate_inode()?,
                    None => fs.next_inode,
                },
            }
        } else if let Some(overlay) = &fs.overlay {
            overlay.allocate_inode()?
        } else {
            fs.next_inode
        };
        if inode == fs.next_inode {
            fs.next_inode = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
        }
        if let Content::File(data) = &content {
            data.sync(false)?;
        }
        let node = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            device: path
                .mount
                .as_ref()
                .map_or(0xfd01, |m| m.root.borrow().device),
            content,
            mode,
            uid: self.credentials.fsuid,
            gid: inherited.unwrap_or(self.credentials.fsgid),
            volatile: false,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        fs.inodes.push(Arc::downgrade(&node));
        fs.paths.insert(path.key.clone(), node.clone());
        if let Err(e) = fs.checkpoint() {
            fs.paths.remove(&path.key);
            fs.inodes.pop();
            fs.next_inode = old_next;
            return Err(e);
        }
        if let Content::File(data) = &mut node.borrow_mut().content {
            data.orphan(false);
        }
        drop(fs);
        self.notification_link(&path, &node, true);
        self.notification_entry(
            &path,
            inotify::CREATE,
            0,
            matches!(node.borrow().content, Content::Directory),
        );
        Ok(())
    }
    fn node<P: PathArg + ?Sized>(&self, path: &P) -> Result<NodeRef> {
        let key = path.key();
        if path
            .mount()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup && m.root.borrow().links == 0)
        {
            return Err(Errno(19));
        }
        if self.uses_pseudo(path) {
            if key == b"/proc" || key.starts_with(b"/proc/") {
                self.proc_accessed.set(true);
            }
            if let Some(node) = self.pseudo_node(path)? {
                return Ok(node);
            }
        }
        path.mount()
            .map_or(&self.fs, |m| &m.fs)
            .borrow()
            .paths
            .get(key)
            .cloned()
            .ok_or(Errno(2))
    }
    fn descriptor(&self, fd: u32) -> Result<Descriptor> {
        self.fds.lookup(fd)
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.fs
            .borrow()
            .inodes
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|n| {
                let node = n.borrow();
                match &node.content {
                    Content::File(b) if node.seals.is_none() => b.len(),
                    _ => 0,
                }
            })
            .sum()
    }
    pub fn cwd(&self) -> Result<Vec<u8>> {
        {
            let paths = self.context.paths.borrow();
            self.path_visible(
                &self.location(paths.cwd_node.as_ref().ok_or(Errno(2))?, &paths.cwd_mount)?,
            )
        }
    }
    fn path_of(&self, node: &NodeRef) -> Result<Vec<u8>> {
        if let Some(path) = self.pseudo.borrow().path_of(node) {
            return Ok(path);
        }
        node.borrow()
            .path_in(&self.fs.borrow().paths, b"/")
            .ok_or(Errno(2))
    }
    pub fn fd_kind(&self, fd: u32) -> Result<FdKind> {
        Ok(self.descriptor(fd)?.open.borrow().kind.clone())
    }
    fn is_directory<P: PathArg + ?Sized>(&self, path: &P) -> bool {
        self.node(path)
            .is_ok_and(|n| matches!(n.borrow().content, Content::Directory))
    }
    fn base(&self, dirfd: i32) -> Result<ResolvedPath> {
        if dirfd == AT_FDCWD {
            let paths = self.context.paths.borrow();
            return self.location(paths.cwd_node.as_ref().ok_or(Errno(2))?, &paths.cwd_mount);
        }
        let o_descriptor = self.descriptor(dirfd as u32)?;
        let o = o_descriptor.open.borrow();
        let n = o.node.as_ref().ok_or(Errno(20))?;
        if !matches!(n.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        self.location(n, &o.mount)
    }
    pub fn resolve(&self, dirfd: i32, path: &[u8]) -> Result<ResolvedPath> {
        self.resolve_final(dirfd, path, true)
    }
    fn check_resolve_mount(from: &ResolvedPath, to: &ResolvedPath, policy: u64) -> Result<()> {
        if policy & 1 != 0 && from.mount.as_ref().map(|m| m.id) != to.mount.as_ref().map(|m| m.id) {
            return Err(Errno(18));
        }
        Ok(())
    }
    fn is_proc_magic_link(&self, at: &ResolvedPath) -> bool {
        if !self.uses_pseudo(at) {
            return false;
        }
        let Some(rest) = at.strip_prefix(b"/proc/") else {
            return false;
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let tail = match parts.as_slice() {
            [_, b"task", _, tail @ ..] => tail,
            [_, tail @ ..] => tail,
            _ => return false,
        };
        matches!(tail, [b"cwd" | b"root" | b"exe"] | [b"fd" | b"ns", _])
            && self
                .node(at)
                .is_ok_and(|n| matches!(n.borrow().content, Content::Symlink(_)))
    }
    /// Observe the actual traversal, including cwd/dirfd, symlinks and failed
    /// lookups of newly created process directories. A textual prefix check
    /// would miss aliases such as /dev/fd and links into another process's proc.
    pub fn accesses_proc(&self, dirfd: i32, path: &[u8]) -> bool {
        self.proc_accessed.set(false);
        let _ = self.resolve(dirfd, path);
        self.proc_accessed.replace(false)
    }
    pub fn resolve_final(
        &self,
        dirfd: i32,
        path: &[u8],
        follow_final: bool,
    ) -> Result<ResolvedPath> {
        self.resolve_entry(dirfd, path, follow_final, false)
            .map(|entry| entry.0)
    }
    fn metadata_target(
        &self,
        dirfd: i32,
        path: &[u8],
        follow: bool,
    ) -> Result<(ResolvedPath, NodeRef)> {
        let (path, magic) = self.resolve_entry(dirfd, path, follow, true)?;
        if let Some((node, label, mount)) = magic {
            Ok((ResolvedPath { key: label, mount }, node))
        } else {
            let node = self.node(&path)?;
            Ok((path, node))
        }
    }
    fn resolve_entry(
        &self,
        dirfd: i32,
        path: &[u8],
        follow_final: bool,
        retain_magic: bool,
    ) -> Result<ResolvedEntry> {
        self.resolve_entry_policy(dirfd, path, follow_final, retain_magic, 0)
    }
    fn resolve_entry_policy(
        &self,
        dirfd: i32,
        path: &[u8],
        follow_final: bool,
        retain_magic: bool,
        policy: u64,
    ) -> Result<ResolvedEntry> {
        if path.is_empty() {
            return Err(Errno(2));
        }
        if path.len() >= MAX_PATH || path.contains(&0) {
            return Err(Errno(36));
        }
        let scoped = policy & (8 | 16) != 0;
        let boundary = if scoped {
            Some(self.base(dirfd)?)
        } else {
            None
        };
        if policy & 8 != 0 && path[0] == b'/' {
            return Err(Errno(18));
        }
        let root = if policy & 16 != 0 {
            boundary.clone().unwrap()
        } else {
            self.root_location()?
        };
        let mut current = if path[0] == b'/' {
            self.follow_mounts(root.clone())?
        } else {
            self.base(dirfd)?
        };
        if path[0] == b'/' {
            Self::check_resolve_mount(&root, &current, policy)?;
        }
        let mut parts: VecDeque<Vec<u8>> = path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .map(|p| p.to_vec())
            .collect();
        let trailing = path.last() == Some(&b'/');
        let mut links = 0;
        while let Some(part) = parts.pop_front() {
            let node = self.node(&current)?;
            let n = node.borrow();
            if !matches!(n.content, Content::Directory) {
                return Err(Errno(20));
            }
            if !self.allowed(&n, 1) {
                return Err(Errno(13));
            }
            drop(n);
            if part == b"." {
                continue;
            }
            if part == b".." {
                if boundary.as_ref() == Some(&current) {
                    if policy & 8 != 0 {
                        return Err(Errno(18));
                    }
                    continue;
                }
                let parent = self.parent_location(&current)?;
                Self::check_resolve_mount(&current, &parent, policy)?;
                current = parent;
                continue;
            }
            if part.len() > 255 {
                return Err(Errno(36));
            }
            let parent = current.clone();
            if current != b"/" {
                current.push(b'/');
            }
            current.extend_from_slice(&part);
            if current.len() >= MAX_PATH {
                return Err(Errno(36));
            }
            current = self.follow_mounts(current)?;
            Self::check_resolve_mount(&parent, &current, policy)?;
            if !parts.is_empty() || follow_final || trailing {
                if policy & (2 | 4 | 8 | 16) != 0 && self.is_proc_magic_link(&current) {
                    return Err(Errno(40));
                }
                // An nsfs magic link names a kernel object, not a pathname such
                // as "uts:[123]". Leave the canonical endpoint for open/stat.
                if parts.is_empty()
                    && !trailing
                    && self.uses_pseudo(&current)
                    && self.namespace_for_path(&current)?.is_some()
                {
                    if policy & 1 != 0 {
                        return Err(Errno(18));
                    }
                    return Ok((current, None));
                }
                if self.uses_pseudo(&current) && (retain_magic || !parts.is_empty()) {
                    if let Some((node, label, mount)) = self.proc_magic_node_normalized(&current)? {
                        Self::check_resolve_mount(
                            &current,
                            &ResolvedPath {
                                key: label.clone(),
                                mount: mount.clone(),
                            },
                            policy,
                        )?;
                        if parts.is_empty() && !trailing {
                            return Ok((current, Some((node, label, mount))));
                        }
                        if !matches!(node.borrow().content, Content::Directory) {
                            return Err(Errno(20));
                        }
                        current = self.location(&node, &mount)?;
                        continue;
                    }
                }
                let node = match self.node(&current) {
                    Ok(node) => Some(node),
                    Err(Errno(2)) => None,
                    Err(e) => return Err(e),
                };
                if let Some(node) = node {
                    if let Content::Symlink(target) = &node.borrow().content {
                        if policy & 4 != 0 {
                            return Err(Errno(40));
                        }
                        if policy & 8 != 0 && target.starts_with(b"/") {
                            return Err(Errno(18));
                        }
                        if target.starts_with(b"/") {
                            Self::check_resolve_mount(&current, &root, policy)?;
                        }
                        self.check_proc_inspection(&current, true)?;
                        links += 1;
                        if links > 40 {
                            return Err(Errno(40));
                        }
                        current = if target.starts_with(b"/") {
                            root.clone()
                        } else {
                            parent
                        };
                        let mut expanded: VecDeque<_> = target
                            .split(|&b| b == b'/')
                            .filter(|p| !p.is_empty())
                            .map(|p| p.to_vec())
                            .collect();
                        if target.ends_with(b"/") {
                            expanded.push_back(b".".to_vec());
                        }
                        expanded.append(&mut parts);
                        if expanded.iter().map(|p| p.len() + 1).sum::<usize>() >= MAX_PATH {
                            return Err(Errno(36));
                        }
                        parts = expanded;
                    }
                }
            }
        }
        if trailing {
            let node = self.node(&current)?;
            if !matches!(node.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
        }
        Ok((current, None))
    }
    pub fn symlink_at(&mut self, target: &[u8], dirfd: i32, path: &[u8]) -> Result<()> {
        if target.is_empty() {
            return Err(Errno(2));
        }
        if target.len() >= MAX_PATH || target.contains(&0) {
            return Err(Errno(36));
        }
        let dest = self.resolve_final(dirfd, path, false)?;
        if self.node(&dest).is_ok() {
            return Err(Errno(17));
        }
        self.check_parent_write(&dest)?;
        self.insert(dest, Content::Symlink(target.to_vec()), 0o120777)
    }
    pub fn readlink_at(&self, dirfd: i32, path: &[u8]) -> Result<Vec<u8>> {
        // readlinkat has implicit AT_EMPTY_PATH support for an O_PATH handle
        // opened with O_NOFOLLOW. Keep the inode alive even after unlink, and
        // refresh dynamic proc magic links before reading their current target.
        if path.is_empty() {
            if dirfd == AT_FDCWD {
                return Err(Errno(2));
            }
            let description = self.descriptor(dirfd as u32)?.open.clone();
            if let FdKind::Node(path) = &description.borrow().kind {
                self.check_proc_inspection(
                    &ResolvedPath {
                        key: path.clone(),
                        mount: description.borrow().mount.clone(),
                    },
                    true,
                )?;
            }
            self.refresh_pseudo_fd(dirfd as u32)?;
            let open = description.borrow();
            let node = open.node.as_ref().ok_or(Errno(2))?.borrow();
            return match &node.content {
                Content::Symlink(target) => Ok(target.clone()),
                _ => Err(Errno(2)),
            };
        }
        let dest = self.resolve_final(dirfd, path, false)?;
        self.check_proc_inspection(&dest, true)?;
        let node = self.node(&dest)?;
        let n = node.borrow();
        match &n.content {
            Content::Symlink(target) => Ok(target.clone()),
            _ => Err(Errno(22)),
        }
    }
    pub fn import_file(&mut self, path: &[u8], bytes: Vec<u8>) -> Result<()> {
        self.import_reader(path, &mut bytes.as_slice(), false)
            .map(|_| ())
    }
    fn import_data(
        &mut self,
        path: &[u8],
        data: storage::FileData,
        executable: bool,
    ) -> Result<()> {
        let (current, parents) = self.import_plan(path)?;
        self.check_growth(0, data.len())?;
        for parent in parents {
            self.insert(parent, Content::Directory, 0o40755)?;
        }
        self.insert(
            current,
            Content::File(data),
            if executable { 0o100755 } else { 0o100644 },
        )
    }
    fn import_plan(&self, path: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
        if !path.starts_with(b"/")
            || path.contains(&0)
            || path.len() >= MAX_PATH
            || path.ends_with(b"/")
        {
            return Err(Errno(22));
        }
        let parts: Vec<_> = path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .collect();
        if parts
            .iter()
            .any(|p| *p == b"." || *p == b".." || p.len() > 255)
        {
            return Err(Errno(22));
        }
        let mut current = Vec::new();
        let mut parents = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            current.push(b'/');
            current.extend_from_slice(part);
            if i + 1 == parts.len() {
                if self.node(&current).is_ok() {
                    return Err(Errno(17));
                }
            } else if self.node(&current).is_err() {
                parents.push(current.clone());
            } else if !self.is_directory(&current) {
                return Err(Errno(20));
            }
        }
        let live = self
            .fs
            .borrow()
            .inodes
            .iter()
            .filter(|n| n.strong_count() != 0)
            .count();
        if live
            .checked_add(parents.len() + 1)
            .is_none_or(|n| n > self.fs.borrow().limits.nodes)
            || self
                .fs
                .borrow()
                .paths
                .len()
                .saturating_add(parents.len() + 1)
                > self.fs.borrow().limits.nodes
        {
            return Err(Errno(28));
        }
        Ok((current, parents))
    }
    /// Explicit embedding API: install an executable/hard link, without duplicating file data.
    pub fn import_alias(&mut self, existing: &[u8], alias: &[u8], executable: bool) -> Result<()> {
        let source = self.resolve_final(AT_FDCWD, existing, false)?;
        let dest = self.resolve_final(AT_FDCWD, alias, false)?;
        self.link_resolved(&source, &dest, executable)
    }
    fn link_resolved(
        &mut self,
        source: &ResolvedPath,
        dest: &ResolvedPath,
        executable: bool,
    ) -> Result<()> {
        if source.mount.as_ref().map(|m| m.id) != dest.mount.as_ref().map(|m| m.id) {
            return Err(Errno(18));
        }
        let filesystem = dest.filesystem(self);
        let source = self.node(source)?;
        if self.node(dest).is_ok() {
            return Err(Errno(17));
        }
        // Synthesized endpoints have a separate inode allocation/lifetime and
        // cannot be inserted into the persistent filesystem's inode table.
        if source.borrow().volatile
            || !matches!(
                source.borrow().content,
                Content::File(_)
                    | Content::Null
                    | Content::Terminal
                    | Content::Device(_)
                    | Content::Fifo(_)
                    | Content::Socket(_)
            )
        {
            return Err(Errno(1));
        }
        if filesystem.borrow().paths.len() >= filesystem.borrow().limits.nodes {
            return Err(Errno(28));
        }
        let old_mode = source.borrow().mode;
        {
            let mut n = source.borrow_mut();
            n.links += 1;
            if executable {
                n.mode |= 0o111;
            }
        }
        let mut fs = filesystem.borrow_mut();
        fs.paths.insert(dest.key.clone(), source.clone());
        if let Err(e) = fs.checkpoint() {
            fs.paths.remove(&dest.key);
            let mut n = source.borrow_mut();
            n.links -= 1;
            n.mode = old_mode;
            return Err(e);
        }
        drop(fs);
        self.notification_link(dest, &source, true);
        self.notification_entry(dest, inotify::CREATE, 0, false);
        inotify::notify(&source, inotify::ATTRIB, None);
        Ok(())
    }
    pub fn executable(&self, path: &[u8]) -> Result<Vec<u8>> {
        self.executable_file_at(AT_FDCWD, path, 0)?.bytes()
    }
    pub fn mkdir_at(&mut self, dirfd: i32, path: &[u8], mode: u32) -> Result<()> {
        if path.len() >= MAX_PATH {
            return Err(Errno(36));
        }
        // mkdir creates the last dentry even when its spelling ends in '/'.
        // It must not follow an existing final symlink to create its target.
        let mut path = path;
        while path.len() > 1 && path.last() == Some(&b'/') {
            path = &path[..path.len() - 1];
        }
        let p = self.resolve_final(dirfd, path, false)?;
        if self.node(&p).is_ok() {
            return Err(Errno(17));
        }
        if Self::cgroup_mount(&p) {
            return self.cgroup_mkdir(&p, mode);
        }
        self.check_parent_write(&p)?;
        self.insert(
            p,
            Content::Directory,
            0o40000 | (mode & 0o7777 & !self.umask()),
        )
    }
    pub fn mknod_at(&mut self, dirfd: i32, path: &[u8], mode: u32, device: u64) -> Result<()> {
        let type_ = mode & 0o170000;
        if !matches!(type_, 0 | 0o100000 | 0o10000 | 0o20000 | 0o60000) {
            return Err(Errno(if type_ == 0o140000 { 95 } else { 22 }));
        }
        let p = self.resolve_final(dirfd, path, false)?;
        match self.node(&p) {
            Ok(_) => return Err(Errno(17)),
            Err(Errno(2)) => {}
            Err(e) => return Err(e),
        }
        self.check_parent_write(&p)?;
        let content = match type_ {
            0o20000 | 0o60000 => {
                if !self.credentials.has_cap(capabilities::MKNOD) {
                    return Err(Errno(1));
                }
                self.cgroup_device(type_, device as u32 as u64, 1)?;
                // Linux's syscall ABI accepts an unsigned 32-bit new_encode_dev.
                pseudo::Device::node(device as u32, type_ == 0o60000)
            }
            0o10000 => Content::Fifo(Pipe::new(self.open_id())),
            _ => Content::File(self.empty_data_at(&p)?),
        };
        let type_ = if type_ == 0 { 0o100000 } else { type_ };
        self.insert(p, content, type_ | (mode & 0o7777 & !self.umask()))
    }
    pub fn unlink_at(&mut self, dirfd: i32, path: &[u8], directory: bool) -> Result<()> {
        let p = self.resolve_final(dirfd, path, false)?;
        if self.is_mount_root(&p) {
            return Err(Errno(16));
        }
        let node = self.node(&p)?;
        self.check_remove(&p)?;
        let is_dir = matches!(node.borrow().content, Content::Directory);
        if directory != is_dir {
            return Err(Errno(if is_dir { 21 } else { 20 }));
        }
        if Self::cgroup_mount(&p) {
            return if directory {
                self.cgroup_rmdir(&p)
            } else {
                Err(Errno(1))
            };
        }
        self.check_parent_write(&p)?;
        let filesystem = p.filesystem(self);
        if is_dir {
            let mut prefix = p.clone();
            prefix.push(b'/');
            if filesystem
                .borrow()
                .paths
                .keys()
                .any(|n| n.starts_with(&prefix))
            {
                return Err(Errno(39));
            }
        }
        node.borrow_mut().links -= 1;
        let mut fs = filesystem.borrow_mut();
        fs.paths.remove(&p.key);
        if let Err(e) = fs.checkpoint() {
            node.borrow_mut().links += 1;
            fs.paths.insert(p.key.clone(), node.clone());
            return Err(e);
        }
        drop(fs);
        self.notification_entry(&p, inotify::DELETE, 0, is_dir);
        self.notification_link(&p, &node, false);
        inotify::notify(&node, inotify::ATTRIB, None);
        let mut n = node.borrow_mut();
        if n.links == 0 {
            if is_dir {
                n.notifications.destroy(true);
            }
            if let Content::File(data) = &mut n.content {
                data.orphan(true);
            }
        }
        Ok(())
    }
    fn available(&self, min: u32) -> Result<u32> {
        (min..MAX_FDS)
            .find(|n| !self.fds.contains_key(n))
            .ok_or(Errno(24))
    }
    pub fn open_at(&mut self, dirfd: i32, path: &[u8], flags: u32, mode: u32) -> Result<u32> {
        self.open_at_resolve(dirfd, path, flags, mode, 0)
    }
    pub fn open_at_resolve(
        &mut self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
        mode: u32,
        policy: u64,
    ) -> Result<u32> {
        if policy & !63 != 0 || policy & 24 == 24 {
            return Err(Errno(22));
        }
        // No host-I/O-free lookup guarantee exists for the disk-backed namespace.
        if policy & 32 != 0 {
            return Err(Errno(11));
        }
        const ALLOWED: u32 = 3
            | 0x40
            | 0x80
            | 0x100
            | 0x200
            | 0x400
            | 0x800
            | O_DIRECTORY
            | O_NOFOLLOW
            | O_LARGEFILE
            | O_CLOEXEC
            | O_PATH
            | 0x101000;
        let flags = if flags & O_PATH != 0 {
            flags & (O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        } else {
            flags
        };
        if flags & !ALLOWED != 0 || flags & 3 == 3 || (flags & 0x200 != 0 && flags & 3 == 0) {
            return Err(Errno(22));
        }
        if flags & 0x40 != 0 && path.last() == Some(&b'/') {
            if path.len() >= MAX_PATH {
                return Err(Errno(36));
            }
            let mut plain = path;
            while plain.len() > 1 && plain.last() == Some(&b'/') {
                plain = &plain[..plain.len() - 1];
            }
            self.resolve_entry_policy(dirfd, plain, true, false, policy)?;
            return Err(Errno(21));
        }
        if policy == 0 {
            if let Some(fd) = self.open_proc_fd(dirfd, path, flags)? {
                return Ok(fd);
            }
        }
        let fd = self.available(0)?;
        let (p, _) = self.resolve_entry_policy(
            dirfd,
            path,
            flags & O_NOFOLLOW == 0 && flags & 0xc0 != 0xc0,
            policy != 0,
            policy,
        )?;
        // Only NO_XDEV alone can follow a final magic link. Validate the entire
        // traversal first; syscall execution serializes namespace mutations.
        if policy == 1 {
            if let Some(fd) = self.open_proc_fd(dirfd, path, flags)? {
                return Ok(fd);
            }
        }
        if flags & O_PATH == 0 {
            self.check_proc_inspection(&p, false)?;
        }
        if flags & O_PATH == 0 && (flags & 3 != 0 || flags & 0x200 != 0) {
            p.writable()?;
        }
        let oom = self.oom_for_path(&p);
        let network_control = self.network_control(&p);
        if oom.is_none()
            && network_control.is_none()
            && self.uses_pseudo(&p)
            && self.pseudo_readonly(&p)
            && (flags & 3 != 0 || flags & 0x240 != 0)
        {
            return Err(Errno(30));
        }
        let existed = match self.node(&p) {
            Ok(_) => true,
            Err(Errno(2)) => false,
            Err(e) => return Err(e),
        };
        if existed && flags & 0xc0 == 0xc0 {
            return Err(Errno(17));
        }
        if !existed {
            if flags & O_DIRECTORY != 0 || flags & 0x40 == 0 {
                return Err(Errno(2));
            }
            self.check_parent_write(&p)?;
            self.insert(
                p.clone(),
                Content::File(self.empty_data_at(&p)?),
                0o100000 | (mode & 0o7777 & !self.umask()),
            )?;
        }
        let node = self.node(&p)?;
        {
            let n = node.borrow();
            self.check_device_open(&n, flags)?;
            if matches!(n.content, Content::Socket(_)) && flags & O_PATH == 0 {
                return Err(Errno(6));
            }
            if matches!(n.content, Content::Symlink(_)) && flags & O_PATH == 0 {
                return Err(Errno(40));
            }
            if matches!(n.content, Content::Directory) && flags & 3 != 0 {
                return Err(Errno(21));
            }
            if flags & O_DIRECTORY != 0 && !matches!(n.content, Content::Directory) {
                return Err(Errno(20));
            }
            if existed
                && flags & O_PATH == 0
                && !(network_control.is_some()
                    && (self.credentials.euid == 0
                        || self.credentials.has_cap(capabilities::NET_ADMIN)))
                && ((flags & 3 != 1 && !self.allowed(&n, 4))
                    || (flags & 3 != 0 && !self.allowed(&n, 2)))
            {
                return Err(Errno(13));
            }
            if flags & O_PATH == 0
                && p.mount
                    .as_ref()
                    .is_some_and(|m| m.flags.get() & mounts::MS_NODEV != 0)
                && matches!(
                    n.content,
                    Content::Device(_) | Content::Null | Content::Terminal
                )
            {
                return Err(Errno(13));
            }
        }
        if flags & O_PATH == 0 && flags & 3 != 0 {
            self.overlay_prepare(&p, &node, flags & 0x200 != 0)?;
        }
        {
            let mut n = node.borrow_mut();
            if flags & 0x200 != 0
                && !Self::cgroup_mount(&p)
                && oom.is_none()
                && network_control.is_none()
            {
                if let Content::File(b) = &mut n.content {
                    b.truncate(0)?;
                    n.times[1] = storage::Timestamp::now();
                    n.times[2] = n.times[1];
                }
            }
        }
        if flags & 0x200 != 0 {
            self.checkpoint()?;
            if matches!(node.borrow().content, Content::File(_)) {
                inotify::notify(&node, inotify::MODIFY, None);
            }
        }
        if flags & O_PATH == 0
            && matches!(
                node.borrow().content,
                Content::Device(pseudo::Device::Unregistered(_))
            )
        {
            return Err(Errno(6));
        }
        let bridge = if flags & O_PATH == 0
            && matches!(
                node.borrow().content,
                Content::Device(pseudo::Device::Bridge)
            ) {
            Some(
                self.bridge
                    .as_ref()
                    .ok_or(Errno(19))?
                    .connect()
                    .map_err(Errno)?,
            )
        } else {
            None
        };
        let kernel_log = (flags & O_PATH == 0
            && matches!(node.borrow().content, Content::Device(pseudo::Device::Kmsg)))
        .then(|| kernel_log::Kmsg::new(self.kernel_log.clone()));
        let pty = if flags & O_PATH != 0 {
            None
        } else {
            match node.borrow().content {
                Content::Device(pseudo::Device::Ptmx) => Some(self.allocate_pty(&p)?),
                Content::Device(pseudo::Device::Pts(id, _)) if id != 0 => {
                    let pair = self.pty_by_id(id).ok_or(Errno(5))?;
                    if pair.locked.get()
                        || !pair.master_alive.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        return Err(Errno(5));
                    }
                    Some(PtyEnd::new(pair, false))
                }
                Content::Terminal => match self.controlling_terminal {
                    None => return Err(Errno(6)),
                    Some(0) => None,
                    Some(id) => {
                        let pair = self.pty_by_id(id).ok_or(Errno(6))?;
                        if !pair.master_alive.load(std::sync::atomic::Ordering::Relaxed) {
                            return Err(Errno(6));
                        }
                        Some(PtyEnd::new(pair, false))
                    }
                },
                _ => None,
            }
        };
        let pipe = if let Content::Fifo(pipe) = &node.borrow().content {
            PipeEnd::open(pipe, flags)?
        } else {
            None
        };
        let notification = self.notification_open(&p, &node, flags);
        let read_node = if flags & O_PATH == 0 && flags & 3 == 0 {
            match &node.borrow().content {
                Content::File(storage::FileData::Lower(source)) => Some(source.clone()),
                _ => None,
            }
        } else {
            None
        };
        self.fds.insert(
            fd,
            Descriptor {
                open: OpenHandle::new(OpenDescription {
                    shared: Arc::new(SharedOpenDescription {
                        read_node,
                        id: self.open_id(),
                        owner: (self.credentials.fsuid, self.credentials.fsgid),
                        kind: if flags & O_PATH == 0
                            && (pty.is_some()
                                || matches!(
                                    node.borrow().content,
                                    Content::Terminal | Content::Device(pseudo::Device::Pts(_, _))
                                ))
                        {
                            FdKind::Terminal
                        } else {
                            FdKind::Node(p.key.clone())
                        },
                        flags: (flags & !O_CLOEXEC).into(),
                        file_position: Arc::new(std::sync::Mutex::new(file_data::FilePosition {
                            value: 0,
                            pending: 0,
                        })),
                        flock: std::sync::OnceLock::new(),
                        node: Some(node),
                        pipe,
                        bridge,
                        kernel_log,
                        notification,
                    }),
                    position: 0,
                    mount: p.mount,
                    socket: None,
                    anonymous: None,
                    local: None,
                    pty,
                    namespace: None,
                    network_control,
                    oom,
                }),
                cloexec: (flags & O_CLOEXEC != 0).into(),
            },
        );
        Ok(fd)
    }
    pub fn close(&mut self, fd: u32) -> Result<()> {
        if let Some(result) = self.fds.membership().close(fd, self.lock_owner) {
            return result;
        }
        let descriptor = self.fds.close(fd)?;
        self.release_record_locks(&descriptor);
        Ok(())
    }
    pub fn fifo_open_ready(&self, fd: u32) -> Result<bool> {
        let d = self.fds.get(&fd).ok_or(Errno(9))?;
        let o = d.open.borrow();
        let Some(end) = &o.pipe else { return Ok(true) };
        Ok(end.open_ready())
    }
    pub fn cancel_fifo_open(&mut self, fd: u32) {
        self.fds.remove(&fd);
    }
    pub fn close_range(&mut self, first: u32, last: u32, flags: u32) -> Result<()> {
        if first > last || flags & !6 != 0 {
            return Err(Errno(22));
        }
        // The scheduler detaches CLONE_FILES views before UNSHARE reaches here.
        if flags & 4 != 0 {
            return fd_status::mark_cloexec_range(
                first,
                last,
                self.fds.entries().iter().map(|(&fd, d)| (fd, d.cloexec)),
            );
        }
        let fds: Vec<_> = self
            .fds
            .entries()
            .range(first..=last)
            .map(|(&fd, _)| fd)
            .collect();
        for fd in fds {
            self.close(fd)?;
        }
        Ok(())
    }
    pub fn close_all(&mut self) {
        let descriptors = self.fds.drain();
        for d in descriptors.values() {
            self.release_record_locks(d);
        }
    }
    /// Detach a task's view while another task retains the shared file table.
    /// No descriptor has actually closed, so POSIX process locks stay held.
    pub fn detach_file_table(&mut self) {
        self.fds = DescriptorTable::default();
    }
    /// exit/exec drops this task's table reference. Only the final reference
    /// closes entries; no process-table scan or separate files_id is needed.
    pub fn release_descriptors(&mut self) {
        if self.fds.last_owner() {
            self.close_all();
        } else {
            self.detach_file_table();
        }
    }
    pub fn close_exec(&mut self) {
        let closed: Vec<_> = self
            .fds
            .entries()
            .iter()
            .filter_map(|(&fd, d)| d.cloexec.get().then_some(fd))
            .collect();
        for fd in closed {
            let _ = self.close(fd);
        }
    }
    pub fn dup(&mut self, old: u32, min: u32, cloexec: bool) -> Result<u32> {
        if let Some(result) = self.fds.membership().duplicate(old, min, cloexec) {
            return result;
        }
        self.fds.duplicate(old, min, cloexec)
    }
    pub fn dup3(&mut self, old: u32, new: u32, flags: u32) -> Result<u32> {
        if let Some(result) = self
            .fds
            .membership()
            .duplicate_to(old, new, flags, self.lock_owner)
        {
            return result;
        }
        if let Some(replaced) = self.fds.duplicate_to(old, new, flags)? {
            self.release_record_locks(&replaced);
        }
        Ok(new)
    }
    pub fn flags(&self, fd: u32) -> Result<u32> {
        let d = self.descriptor(fd)?;
        let open = d.open.borrow();
        Ok(open.flags.get() | if d.cloexec.get() { O_CLOEXEC } else { 0 })
    }
    pub fn set_cloexec(&mut self, fd: u32, enabled: bool) -> Result<()> {
        self.descriptor(fd)?.cloexec.set(enabled);
        Ok(())
    }
    pub fn set_status_flags(&mut self, fd: u32, flags: u32) -> Result<()> {
        self.descriptor(fd)?.open.borrow().flags.set(flags)
    }
    pub fn set_nonblocking(&self, fd: u32, enabled: bool) -> Result<()> {
        self.descriptor(fd)?
            .open
            .borrow()
            .flags
            .nonblocking(enabled)
    }
    pub fn pipe(&mut self, flags: u32) -> Result<[u32; 2]> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno(22));
        }
        let free: Vec<_> = (0..MAX_FDS)
            .filter(|n| !self.fds.contains_key(n))
            .take(2)
            .collect();
        if free.len() != 2 {
            return Err(Errno(24));
        }
        let p = Pipe::new(self.open_id());
        let inode = p.inode;
        let metadata = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            device: 6,
            content: Content::Null,
            mode: 0o10600,
            uid: self.credentials.fsuid,
            gid: self.credentials.fsgid,
            volatile: false,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        let read = PipeEnd::new(p.clone(), true, false, Some(metadata.clone()));
        let write = PipeEnd::new(p, false, true, Some(metadata));
        for (fd, end, kind, access) in [
            (free[0], read, FdKind::PipeRead, 0),
            (free[1], write, FdKind::PipeWrite, 1),
        ] {
            self.fds.insert(
                fd,
                Descriptor {
                    open: OpenHandle::new(OpenDescription {
                        shared: Arc::new(SharedOpenDescription {
                            read_node: None,
                            id: self.open_id(),
                            owner: (self.credentials.fsuid, self.credentials.fsgid),
                            kind,
                            flags: ((flags & O_NONBLOCK) | access).into(),
                            file_position: Arc::default(),
                            flock: std::sync::OnceLock::new(),
                            node: None,
                            pipe: Some(end),
                            bridge: None,
                            kernel_log: None,
                            notification: None,
                        }),
                        position: 0,
                        socket: None,
                        anonymous: None,
                        local: None,
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
        Ok([free[0], free[1]])
    }
    /// Bounded splice through a pipe. Commit pipe consumption only after the
    /// destination accepts bytes; EAGAIN must never lose buffered stream data.
    pub fn splice(
        &mut self,
        input: u32,
        output: u32,
        count: usize,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<usize> {
        let source = self.descriptor(input)?.open.clone();
        let dest = self.descriptor(output)?.open.clone();
        if OpenHandle::ptr_eq(&source, &dest) {
            return Err(Errno(22));
        }
        let source_pipe = {
            let o = source.borrow();
            if o.flags.get() & O_PATH != 0 || o.flags.get() & 3 == 1 {
                return Err(Errno(9));
            }
            o.pipe.as_ref().map(|p| (p.pipe.clone(), p.read))
        };
        let dest_pipe = {
            let o = dest.borrow();
            if o.flags.get() & O_PATH != 0 || o.flags.get() & 3 == 0 {
                return Err(Errno(9));
            }
            if o.flags.get() & 0x400 != 0 {
                return Err(Errno(22));
            }
            o.pipe.as_ref().map(|p| (p.pipe.clone(), p.write))
        };
        for open in [&source, &dest] {
            let o = open.borrow();
            if o.socket
                .as_ref()
                .is_some_and(|s| s.info().is_some_and(|i| i.kind != 1))
                || o.local.as_ref().is_some_and(|s| s.kind() != 1)
            {
                return Err(Errno(22));
            }
        }
        if source_pipe.is_none() && dest_pipe.is_none() {
            return Err(Errno(22));
        }
        if source_pipe.is_some() && from.is_some() || dest_pipe.is_some() && to.is_some() {
            return Err(Errno(29));
        }
        if let (Some((a, _)), Some((b, _))) = (&source_pipe, &dest_pipe) {
            if Arc::ptr_eq(&a.data, &b.data) {
                return Err(Errno(22));
            }
        }
        if source_pipe.as_ref().is_some_and(|(_, read)| !*read)
            || dest_pipe.as_ref().is_some_and(|(_, write)| !*write)
        {
            return Err(Errno(9));
        }
        if count == 0 {
            return Ok(0);
        }
        if let Some((pipe, _)) = source_pipe {
            let bytes = {
                let p = pipe.data.lock().unwrap();
                if p.bytes.is_empty() && p.writers != 0 {
                    return Err(Errno(11));
                }
                p.bytes
                    .iter()
                    .take(count.min(PIPE_CAPACITY))
                    .copied()
                    .collect::<Vec<_>>()
            };
            if bytes.is_empty() {
                return Ok(0);
            }
            let n = if let Some((target, _)) = &dest_pipe {
                let mut p = target.data.lock().unwrap();
                if p.readers == 0 {
                    return Err(Errno(32));
                }
                let n = bytes.len().min(PIPE_CAPACITY - p.bytes.len());
                if n == 0 {
                    return Err(Errno(11));
                }
                p.bytes.extend(&bytes[..n]);
                p.io_epoch[0] = p.io_epoch[0].wrapping_add(1);
                n
            } else if let Some(offset) = to {
                self.pwrite(output, &bytes, offset)?
            } else {
                self.write(output, &bytes)?
            };
            let mut p = pipe.data.lock().unwrap();
            p.bytes.drain(..n);
            if n != 0 {
                p.io_epoch[1] = p.io_epoch[1].wrapping_add(1);
            }
            return Ok(n);
        }
        let (pipe, _) = dest_pipe.unwrap();
        let room = {
            let p = pipe.data.lock().unwrap();
            if p.readers == 0 {
                return Err(Errno(32));
            }
            PIPE_CAPACITY - p.bytes.len()
        };
        if room == 0 {
            return Err(Errno(11));
        }
        let bytes = if let Some(offset) = from {
            self.pread(input, count.min(room), offset)?
        } else {
            self.read(input, count.min(room))?
        };
        let mut p = pipe.data.lock().unwrap();
        p.bytes.extend(&bytes);
        if !bytes.is_empty() {
            p.io_epoch[0] = p.io_epoch[0].wrapping_add(1);
        }
        Ok(bytes.len())
    }
    pub fn read(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        self.refresh_pseudo_fd(fd)?;
        let o_descriptor = self.descriptor(fd)?;
        let mut o = o_descriptor.open.borrow_mut();
        if o.flags.get() & O_PATH != 0 || o.flags.get() & 3 == 1 {
            return Err(Errno(9));
        }
        if let Some(control) = &o.network_control {
            let data = control.read(o.position, count);
            o.position += data.len() as u64;
            return Ok(data);
        }
        if let Some(data) = Self::oom_read(&o, o.position, count)? {
            o.position += data.len() as u64;
            return Ok(data);
        }
        if let Some(data) = self.cgroup_read(&o, o.position, count)? {
            o.position += data.len() as u64;
            return Ok(data);
        }
        if let Some(log) = &o.kernel_log {
            return log.read(count);
        }
        if let Some(local) = &o.local {
            return local.recv(count, 0).map(|r| r.data);
        }
        if o.namespace.is_some() {
            return Err(Errno(22));
        }
        if let Some(anonymous) = &mut o.anonymous {
            return anonymous.read(count);
        }
        if let Some(bridge) = &o.bridge {
            return bridge.read(count).map_err(Errno);
        }
        if let Some(socket) = &o.socket {
            return socket
                .recv(count, 0)
                .map(|r| r.data)
                .map_err(|e| Errno(e.0));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        if let Some(end) = &o.pipe {
            if !end.read {
                return Err(Errno(9));
            }
            return end.data.lock().unwrap().read(count);
        }
        let node = o.data_node().ok_or(Errno(9))?;
        let n = node.borrow();
        let result = match &n.content {
            Content::File(b) => {
                if n.volatile {
                    let out = b.read_at(o.position, count)?;
                    o.position += out.len() as u64;
                    Ok(out)
                } else {
                    let mut position = o.file_position.lock().unwrap();
                    let out = b.read_at(position.value, count)?;
                    position.value += out.len() as u64;
                    Ok(out)
                }
            }
            Content::Null => Ok(Vec::new()),
            Content::Device(device) => device.read(count),
            Content::Directory => Err(Errno(21)),
            Content::Socket(_) => Err(Errno(6)),
            Content::Symlink(_) => Err(Errno(40)),
            Content::Terminal => Err(Errno(11)),
            Content::Fifo(_) => Err(Errno(29)),
        };
        drop(n);
        Self::complete_file_read(&o, &node, &result, true);
        result
    }
    pub fn write(&mut self, fd: u32, bytes: &[u8]) -> Result<usize> {
        let o_descriptor = self.descriptor(fd)?;
        let mut o = o_descriptor.open.borrow_mut();
        if o.flags.get() & 3 == 0 {
            return Err(Errno(9));
        }
        if let Some(log) = &o.kernel_log {
            return log.write(bytes);
        }
        if let Some(local) = &o.local {
            return local.send(bytes, 0);
        }
        if o.namespace.is_some() {
            return Err(Errno(22));
        }
        if let Some(anonymous) = &mut o.anonymous {
            return anonymous.write(bytes);
        }
        if let Some(bridge) = &o.bridge {
            return bridge.write(bytes).map_err(Errno);
        }
        if let Some(socket) = &o.socket {
            let socket = socket.clone();
            drop(o);
            return self.socket_send_bytes(&socket, bytes, 0, None);
        }
        if let Some(end) = &o.pipe {
            if !end.write {
                return Err(Errno(9));
            }
            return end.data.lock().unwrap().write(bytes);
        }
        drop(o);
        self.file_write(fd, bytes, None)
    }
    /// Per-task RLIMIT_FSIZE; disk quota remains a separate ENOSPC constraint.
    pub fn set_file_size_limit(&mut self, limit: u64) {
        self.file_size_limit = limit;
        self.file_size_signal.set(false);
    }
    pub fn take_file_size_signal(&self) -> bool {
        self.file_size_signal.replace(false)
    }
    fn file_write(&mut self, fd: u32, bytes: &[u8], offset: Option<u64>) -> Result<usize> {
        self.fd_writable(fd)?;
        let available = self.fd_available_bytes(fd)?;
        let memfd_available = self.memfd_available();
        let o_descriptor = self.descriptor(fd)?;
        let mut o = o_descriptor.open.borrow_mut();
        if o.flags.get() & 3 == 0 {
            return Err(Errno(9));
        }
        if let Some(control) = &o.network_control {
            let count = control.write(
                bytes,
                offset.unwrap_or(o.position),
                self.credentials.euid == 0 || self.credentials.has_cap(capabilities::NET_ADMIN),
            )?;
            if offset.is_none() {
                o.position += count as u64;
            }
            return Ok(count);
        }
        if let Some(count) = self.oom_write(&o, bytes)? {
            // proc oom_score_adj_write ignores and does not advance f_pos.
            return Ok(count);
        }
        if let Some(count) = self.cgroup_write(&o, bytes)? {
            if offset.is_none() {
                o.position = o.position.saturating_add(count as u64);
            }
            return Ok(count);
        }
        let node = o.node.clone().ok_or(Errno(29))?;
        self.pseudo_immutable(&node)?;
        let mut n = node.borrow_mut();
        let seals = n.seals;
        let count = bytes.len().min(storage::MAX_TRANSFER);
        let bytes = &bytes[..count];
        let result = match &mut n.content {
            Content::Null => Ok(bytes.len()),
            Content::Device(device) => device.write(bytes),
            Content::Fifo(_) => Err(Errno(29)),
            Content::Directory => Err(Errno(21)),
            Content::Socket(_) => Err(Errno(6)),
            Content::Symlink(_) => Err(Errno(40)),
            Content::Terminal => Err(Errno(11)),
            Content::File(b) => {
                if bytes.is_empty() {
                    return Ok(0);
                }
                let mut file_position = o.file_position.lock().unwrap();
                let position = if o.flags.get() & 0x400 != 0 {
                    b.len()
                } else {
                    offset.unwrap_or(file_position.value)
                };
                if position >= self.file_size_limit {
                    self.file_size_signal.set(true);
                    return Err(Errno(27));
                }
                let bytes = &bytes[..bytes
                    .len()
                    .min(usize::try_from(self.file_size_limit - position).unwrap_or(usize::MAX))];
                let end = position
                    .checked_add(bytes.len() as u64)
                    .filter(|&n| n <= i64::MAX as u64)
                    .ok_or(Errno(27))?;
                if seals.is_some_and(|s| s & 8 != 0 || s & 4 != 0 && end > b.len()) {
                    return Err(Errno(1));
                }
                let available = if seals.is_some() {
                    memfd_available
                } else {
                    available
                };
                if b.growth_charge(end) > available {
                    return Err(Errno(28));
                }
                let written = b.write_at(position, bytes)?;
                if offset.is_none() {
                    file_position.value = position + written as u64;
                }
                Ok(written)
            }
        };
        if result.is_ok_and(|n| n != 0) {
            let clear_setid = !self.credentials.has_cap(capabilities::FSETID);
            let shared = if let Content::File(storage::FileData::Plain(data)) = &n.content {
                data.modified(clear_setid)
            } else {
                None
            };
            if let Some(meta) = shared {
                n.mode = meta.mode;
                n.times = meta.times;
            } else {
                if clear_setid && matches!(n.content, Content::File(_)) {
                    n.mode &= !0o4000;
                    if n.mode & 0o10 != 0 {
                        n.mode &= !0o2000;
                    }
                }
                n.times[1] = storage::Timestamp::now();
                n.times[2] = n.times[1];
            }
        }
        let synchronous = o.flags.get() & 0x1000 != 0;
        drop(n);
        if result.is_ok_and(|n| n != 0)
            && !(node.borrow().seals.is_some() && o.notification.is_none())
        {
            inotify::notify(
                &node,
                inotify::MODIFY,
                o.notification.as_ref().and_then(|c| c.link.as_ref()),
            );
        }
        drop(o);
        if result.is_ok() && synchronous {
            self.sync_fd(fd, false)?;
        }
        result
    }
    pub fn pread(&self, fd: u32, count: usize, offset: u64) -> Result<Vec<u8>> {
        self.refresh_pseudo_fd(fd)?;
        if offset > i64::MAX as u64 {
            return Err(Errno(22));
        }
        let o_descriptor = self.descriptor(fd)?;
        let o = o_descriptor.open.borrow();
        if o.bridge.is_some() || o.kernel_log.is_some() {
            return Err(Errno(29));
        }
        if o.flags.get() & O_PATH != 0 || o.flags.get() & 3 == 1 {
            return Err(Errno(9));
        }
        if let Some(control) = &o.network_control {
            return Ok(control.read(offset, count));
        }
        if let Some(data) = Self::oom_read(&o, offset, count)? {
            return Ok(data);
        }
        if let Some(data) = self.cgroup_read(&o, offset, count)? {
            return Ok(data);
        }
        let node = o.data_node().ok_or(Errno(29))?;
        let n = node.borrow();
        let result = match &n.content {
            Content::File(b) => b.read_at(offset, count),
            Content::Null => Ok(Vec::new()),
            Content::Device(device) => device.read(count),
            Content::Directory => Err(Errno(21)),
            Content::Socket(_) => Err(Errno(6)),
            Content::Symlink(_) => Err(Errno(40)),
            Content::Terminal | Content::Fifo(_) => Err(Errno(29)),
        };
        drop(n);
        Self::complete_file_read(&o, &node, &result, count != 0);
        result
    }
    pub fn pwrite(&mut self, fd: u32, bytes: &[u8], offset: u64) -> Result<usize> {
        if self.bridge_fd(fd) || self.descriptor(fd)?.open.borrow().kernel_log.is_some() {
            return Err(Errno(29));
        }
        if offset > i64::MAX as u64 {
            return Err(Errno(22));
        }
        self.file_write(fd, bytes, Some(offset))
    }
    pub fn truncate_fd(&mut self, fd: u32, length: u64) -> Result<()> {
        if self.flags(fd)? & O_PATH != 0 {
            return Err(Errno(9));
        }
        self.fd_writable(fd)?;
        let available = self.fd_available_bytes(fd)?;
        let memfd_available = self.memfd_available();
        let o_descriptor = self.descriptor(fd)?;
        let o = o_descriptor.open.borrow();
        if o.flags.get() & 3 == 0 {
            return Err(Errno(22));
        }
        let node = o.node.clone().ok_or(Errno(22))?;
        self.pseudo_immutable(&node)?;
        let mut n = node.borrow_mut();
        let seals = n.seals;
        let Content::File(b) = &mut n.content else {
            return Err(Errno(22));
        };
        if length > i64::MAX as u64 {
            return Err(Errno(22));
        }
        if seals.is_some_and(|s| s & 2 != 0 && length < b.len() || s & 4 != 0 && length > b.len()) {
            return Err(Errno(1));
        }
        if length > b.len() && length > self.file_size_limit {
            self.file_size_signal.set(true);
            return Err(Errno(27));
        }
        let available = if seals.is_some() {
            memfd_available
        } else {
            available
        };
        if b.growth_charge(length) > available {
            return Err(Errno(28));
        }
        b.truncate(length)?;
        if !self.credentials.has_cap(capabilities::FSETID) {
            n.mode &= !0o4000;
            if n.mode & 0o10 != 0 {
                n.mode &= !0o2000;
            }
        }
        n.times[1] = storage::Timestamp::now();
        n.times[2] = n.times[1];
        drop(n);
        self.checkpoint()?;
        inotify::notify(
            &node,
            inotify::MODIFY,
            o.notification.as_ref().and_then(|c| c.link.as_ref()),
        );
        Ok(())
    }
    pub fn truncate_at(&mut self, path: &[u8], length: u64) -> Result<()> {
        let fd = self.open_at(AT_FDCWD, path, 1, 0)?;
        let result = self.truncate_fd(fd, length);
        self.close(fd)?;
        result
    }
    pub fn seek(&mut self, fd: u32, offset: i64, whence: u32) -> Result<u64> {
        let o_descriptor = self.descriptor(fd)?;
        let mut o = o_descriptor.open.borrow_mut();
        if o.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        if matches!(o.anonymous, Some(events::Anonymous::Signal { .. })) {
            return Ok(o.position);
        }
        if o.kind == FdKind::Terminal {
            return Err(Errno(29));
        }
        if o.bridge.is_some() {
            return Err(Errno(29));
        }
        let node = o.data_node().ok_or(Errno(29))?;
        let n = node.borrow();
        if let Some(log) = &o.kernel_log {
            return log.seek(offset, whence);
        }
        let length = if o.oom.is_some() {
            0
        } else {
            match &n.content {
                Content::File(b) => b.len(),
                Content::Directory => 0,
                Content::Socket(_) => return Err(Errno(6)),
                Content::Symlink(_) => return Err(Errno(40)),
                Content::Null => return Ok(0),
                Content::Device(_) => return Ok(0),
                Content::Terminal | Content::Fifo(_) => return Err(Errno(29)),
            }
        };
        let mut file_position = o.file_position.lock().unwrap();
        let regular = matches!(n.content, Content::File(_)) && !n.volatile;
        let base = match whence {
            0 => 0,
            1 => {
                if regular {
                    file_position.value as i64
                } else {
                    o.position as i64
                }
            }
            2 => length as i64,
            _ => return Err(Errno(22)),
        };
        let new = base
            .checked_add(offset)
            .filter(|&n| n >= 0)
            .ok_or(Errno(22))?;
        if regular {
            file_position.value = new as u64;
        }
        drop(file_position);
        if !regular {
            o.position = new as u64;
        }
        Ok(new as u64)
    }
    fn stat_node(&self, node: &Node, mount: Option<&Rc<Mount>>) -> Result<[u8; 128]> {
        let mut out = self.stat_node_fields(node, mount)?;
        let blocks = match &node.content {
            Content::File(data) if !node.volatile => data.blocks()?,
            _ => 0,
        };
        out[64..72].copy_from_slice(&blocks.to_le_bytes());
        Ok(out)
    }
    // Freeze only virtual fields when publishing worker capabilities. Actual
    // stat calls obtain live allocation/blocks; cohort setup must not stat every
    // host disk object even when no task will query it.
    fn stat_node_fields(&self, node: &Node, mount: Option<&Rc<Mount>>) -> Result<[u8; 128]> {
        let mut out = [0; 128];
        let device = mount
            .filter(|m| m.kind == mounts::Kind::Overlay)
            .map_or(node.device, |m| m.device());
        out[..8].copy_from_slice(&device.to_le_bytes());
        out[8..16].copy_from_slice(&node.inode.to_le_bytes());
        let metadata = node.file_metadata();
        out[16..20].copy_from_slice(&metadata.mode.to_le_bytes());
        let mut links = node.links;
        if links != 0 && matches!(node.content, Content::Directory) {
            // Persistent links count path owners; stat counts . and children's .. too.
            let fs = mount.map_or(&self.fs, |m| &m.fs).borrow();
            let path = node.path_in(&fs.paths, b"/").or_else(|| {
                self.pseudo
                    .borrow()
                    .nodes
                    .iter()
                    .find(|(_, n)| n.identity == node.identity)
                    .map(|((_, p), _)| p.clone())
            });
            if let Some(path) = path {
                let mut prefix = path.clone();
                if prefix != b"/" {
                    prefix.push(b'/');
                }
                let mut directories = std::collections::BTreeSet::new();
                for (name, n) in directory::children(&fs.paths, &path) {
                    if matches!(n.borrow().content, Content::Directory) {
                        directories.insert(name.to_vec());
                    }
                }
                let at = ResolvedPath {
                    key: path.clone(),
                    mount: mount.cloned(),
                };
                for name in self.mounted_pseudo_children(&at)? {
                    let mut child = prefix.clone();
                    child.extend_from_slice(&name);
                    if self
                        .node(&child)
                        .is_ok_and(|n| matches!(n.borrow().content, Content::Directory))
                    {
                        directories.insert(name);
                    }
                }
                links = 2 + directories.len() as u32;
            }
        }
        out[20..24].copy_from_slice(&links.to_le_bytes());
        out[24..28].copy_from_slice(&node.uid.to_le_bytes());
        out[28..32].copy_from_slice(&node.gid.to_le_bytes());
        let rdev = if !matches!(node.mode & 0o170000, 0o20000 | 0o60000) {
            0
        } else {
            match node.content {
                Content::Null => 0x103u64,
                Content::Terminal => 0x500,
                Content::Device(device) => device.rdev(),
                _ => 0,
            }
        };
        out[32..40].copy_from_slice(&rdev.to_le_bytes());
        let size = match &node.content {
            Content::File(b) if !node.volatile => b.len(),
            Content::Symlink(target) => target.len() as u64,
            _ => 0,
        };
        out[48..56].copy_from_slice(&size.to_le_bytes());
        out[56..60].copy_from_slice(&4096u32.to_le_bytes());
        for (offset, t) in [72, 88, 104].into_iter().zip(metadata.times) {
            out[offset..offset + 8].copy_from_slice(&t.seconds.to_le_bytes());
            out[offset + 8..offset + 16].copy_from_slice(&(t.nanos as u64).to_le_bytes());
        }
        Ok(out)
    }
    pub fn stat_at(&self, dirfd: i32, path: &[u8]) -> Result<[u8; 128]> {
        self.stat_at_flags(dirfd, path, false)
    }
    pub fn stat_at_flags(&self, dirfd: i32, path: &[u8], nofollow: bool) -> Result<[u8; 128]> {
        if !nofollow {
            if let Some(open) = self.proc_fd_description(dirfd, path)? {
                return self.stat_open(&open.borrow());
            }
        }
        let p = self.resolve_final(dirfd, path, !nofollow)?;
        let n = self.node(&p)?;
        let out = self.stat_node(&n.borrow(), p.mount.as_ref());
        out
    }
    pub fn stat_fd(&self, fd: u32) -> Result<[u8; 128]> {
        let d = self.descriptor(fd)?;
        let open = d.open.borrow();
        self.stat_open(&open)
    }
    fn stat_open(&self, o: &OpenDescription) -> Result<[u8; 128]> {
        if let Some(n) = o.metadata_node() {
            let mut stat = self.stat_node(&n.borrow(), o.mount.as_ref())?;
            if let Some(source) = &o.read_node {
                if let Content::File(data) = &source.borrow().content {
                    stat[48..56].copy_from_slice(&data.len().to_le_bytes());
                    stat[64..72].copy_from_slice(&data.blocks()?.to_le_bytes());
                }
            }
            return Ok(stat);
        }
        if matches!(o.kind, FdKind::Terminal) {
            if let Ok(n) = self.node(b"/dev/pts/0") {
                return self.stat_node(&n.borrow(), o.mount.as_ref());
            }
        }
        self.stat_node(
            &Node {
                identity: 0,
                record_locks: std::sync::OnceLock::new(),
                whole_locks: std::sync::OnceLock::new(),
                notifications: inotify::Marks::default(),
                path_hint: SharedCell::default(),
                device: if o.namespace.is_some() {
                    17
                } else if o.anonymous.is_some() {
                    16
                } else if o.socket.is_some() || o.local.is_some() {
                    5
                } else if o.pipe.is_some() {
                    6
                } else {
                    1
                },
                content: Content::Null,
                mode: if o.namespace.is_some() {
                    0o100444
                } else if o.anonymous.is_some() {
                    0o600
                } else if o.socket.is_some() || o.local.is_some() {
                    0o140600
                } else if o.pipe.is_some()
                    || matches!(o.kind, FdKind::Stdin | FdKind::Stdout | FdKind::Stderr)
                {
                    0o10600
                } else {
                    0o20666
                },
                inode: o.namespace.as_ref().map_or_else(
                    || o.pipe.as_ref().map_or(o.id, |p| p.pipe.inode),
                    linux_namespace::NamespaceHandle::id,
                ),
                links: 1,
                uid: o.owner.0,
                gid: o.owner.1,
                volatile: false,
                times: [storage::Timestamp::default(); 3],
                xattrs: BTreeMap::new(),
                seals: None,
            },
            None,
        )
    }
    pub fn chdir_fd(&mut self, fd: u32) -> Result<()> {
        let node = self
            .descriptor(fd)?
            .open
            .borrow()
            .node
            .clone()
            .ok_or(Errno(20))?;
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        if !self.allowed(&node.borrow(), 1) {
            return Err(Errno(13));
        }
        let mount = self.descriptor(fd)?.open.borrow().mount.clone();
        let mut paths = self.context.paths.borrow_mut();
        paths.cwd_mount = mount;
        paths.cwd_node = Some(node);
        Ok(())
    }
    pub fn chdir(&mut self, path: &[u8]) -> Result<()> {
        let p = self.resolve(AT_FDCWD, path)?;
        let n = self.node(&p)?;
        if !matches!(n.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        if !self.allowed(&n.borrow(), 1) {
            return Err(Errno(13));
        }
        let mut paths = self.context.paths.borrow_mut();
        paths.cwd_mount = p.mount;
        paths.cwd_node = Some(n);
        Ok(())
    }
    pub fn getdents(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        let d = self.descriptor(fd)?;
        let mut o = d.open.borrow_mut();
        let node = o.node.as_ref().ok_or(Errno(20))?;
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let p = self.location(node, &o.mount)?;
        let filesystem = p.filesystem(self);
        let fs = filesystem.borrow();
        let inode = node.borrow().inode;
        let parent = self.node(&self.parent_location(&p)?)?.borrow().inode;
        let mut children = BTreeMap::new();
        let mut prefix = p.clone();
        if prefix != b"/" {
            prefix.push(b'/');
        }
        for (name, node) in directory::children(&fs.paths, &p.key) {
            let n = node.borrow();
            children.insert(name.to_vec(), (n.inode, ((n.mode & 0o170000) >> 12) as u8));
        }
        drop(fs);
        for name in self.mounted_pseudo_children(&p)? {
            let mut child = prefix.clone();
            child.extend_from_slice(&name);
            let n = self.node(&child)?;
            let n = n.borrow();
            let kind = ((n.mode & 0o170000) >> 12) as u8;
            children.insert(name, (n.inode, kind));
        }
        let mut entries = vec![(b".".to_vec(), inode, 4u8), (b"..".to_vec(), parent, 4)];
        entries.extend(
            children
                .into_iter()
                .map(|(name, (inode, kind))| (name, inode, kind)),
        );
        let mut out = Vec::new();
        while let Some((name, ino, kind)) = entries.get(o.position as usize) {
            let size = (19 + name.len() + 1 + 7) & !7;
            if out.len() + size > count {
                if out.is_empty() {
                    return Err(Errno(22));
                }
                break;
            }
            let start = out.len();
            out.resize(start + size, 0);
            out[start..start + 8].copy_from_slice(&ino.to_le_bytes());
            out[start + 8..start + 16].copy_from_slice(&(o.position + 1).to_le_bytes());
            out[start + 16..start + 18].copy_from_slice(&(size as u16).to_le_bytes());
            out[start + 18] = *kind;
            out[start + 19..start + 19 + name.len()].copy_from_slice(name);
            o.position += 1;
        }
        Ok(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reverse_path_hint_validates_rename_unlink_and_replacement_inode() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/tree", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/tree/dir", 0o755).unwrap();
        v.chdir(b"/tree/dir").unwrap();
        assert_eq!(v.cwd().unwrap(), b"/tree/dir");
        v.rename_at(AT_FDCWD, b"/tree", AT_FDCWD, b"/moved", 0)
            .unwrap();
        assert_eq!(v.cwd().unwrap(), b"/moved/dir");
        v.import_file(b"/moved/file", b"old".to_vec()).unwrap();
        v.link_at(AT_FDCWD, b"/moved/file", AT_FDCWD, b"/alias")
            .unwrap();
        let node = v
            .node(&v.resolve(AT_FDCWD, b"/moved/file").unwrap())
            .unwrap();
        assert!(node
            .borrow()
            .path_in(&v.fs.borrow().paths, b"/moved")
            .is_some());
        v.unlink_at(AT_FDCWD, b"/moved/file", false).unwrap();
        v.import_file(b"/moved/file", b"replacement".to_vec())
            .unwrap();
        assert_eq!(
            node.borrow().path_in(&v.fs.borrow().paths, b"/"),
            Some(b"/alias".to_vec())
        );
        v.unlink_at(AT_FDCWD, b"/alias", false).unwrap();
        assert_eq!(node.borrow().path_in(&v.fs.borrow().paths, b"/"), None);
    }
    #[test]
    fn reverse_path_hint_cannot_escape_a_bind_root_through_a_hardlink() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/inside", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/view", 0o755).unwrap();
        v.import_file(b"/outside", b"same inode".to_vec()).unwrap();
        v.link_at(AT_FDCWD, b"/outside", AT_FDCWD, b"/inside/file")
            .unwrap();
        let node = v.node(&v.resolve(AT_FDCWD, b"/outside").unwrap()).unwrap();
        // Prime a valid path from outside the later bind mount root.
        assert_eq!(
            node.borrow().path_in(&v.fs.borrow().paths, b"/outside"),
            Some(b"/outside".to_vec())
        );
        v.mount(Some(b"/inside"), b"/view", None, 4096, None)
            .unwrap();
        let mount = v.resolve(AT_FDCWD, b"/view").unwrap().mount.unwrap();
        assert_eq!(mount.key_of(&node), Some(b"/inside/file".to_vec()));
        v.unlink_at(AT_FDCWD, b"/inside/file", false).unwrap();
        assert_eq!(mount.key_of(&node), None);
        assert!(v.stat_at(AT_FDCWD, b"/outside").is_ok());
    }
    #[test]
    fn paths_cannot_escape_root_or_traverse_regular_files() {
        let mut v = Vfs::default();
        v.import_file(b"/data/file", b"data".to_vec()).unwrap();
        assert_eq!(
            v.resolve(AT_FDCWD, b"/../../data/./file").unwrap(),
            b"/data/file"
        );
        assert_eq!(v.resolve(AT_FDCWD, b"/data/file/../file"), Err(Errno(20)));
        assert_eq!(v.resolve(9, b"relative"), Err(Errno(9)));
        assert_eq!(v.resolve(9, b"/data/file").unwrap(), b"/data/file");
    }
    #[test]
    fn open_read_seek_write_and_fd_reuse() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"abc".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        assert_eq!(fd, 3);
        assert_eq!(v.read(fd, 2).unwrap(), b"ab");
        v.seek(fd, -1, 1).unwrap();
        v.write(fd, b"Z").unwrap();
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 9).unwrap(), b"aZc");
        v.close(0).unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/file", 0, 0).unwrap(), 0);
        assert_eq!(
            v.open_at(AT_FDCWD, b"/file", O_DIRECTORY, 0),
            Err(Errno(20))
        );
    }
    #[test]
    fn directory_entries_are_aligned_and_continue_after_small_buffers() {
        let mut v = Vfs::default();
        v.import_file(b"/a/z", vec![1]).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/a", O_DIRECTORY, 0).unwrap();
        assert_eq!(v.getdents(fd, 1), Err(Errno(22)));
        let first = v.getdents(fd, 24).unwrap();
        assert_eq!(first.len(), 24);
        assert_eq!(first[19], b'.');
        let rest = v.getdents(fd, 4096).unwrap();
        assert_eq!(rest.len(), 48);
        assert_eq!(rest[43], b'z');
        assert!(v.getdents(fd, 4096).unwrap().is_empty());
    }
    #[test]
    fn append_null_and_storage_limit() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/new", 0x441, 0o644).unwrap();
        v.write(fd, b"a").unwrap();
        v.seek(fd, 0, 0).unwrap();
        v.write(fd, b"b").unwrap();
        let read = v.open_at(AT_FDCWD, b"/new", 0, 0).unwrap();
        assert_eq!(v.read(read, 9).unwrap(), b"ab");
        v.seek(fd, MAX_FILE_BYTES as i64, 0).unwrap(); // append resets position, so test a separate descriptor.
        let plain = v.open_at(AT_FDCWD, b"/new", 1, 0).unwrap();
        v.seek(plain, MAX_FILE_BYTES as i64, 0).unwrap();
        assert_eq!(v.write(plain, b"x"), Err(Errno(28)));
        assert_eq!(v.allocated_bytes(), 2);
        let null = v.open_at(AT_FDCWD, b"/dev/null", 2, 0).unwrap();
        assert_eq!(v.write(null, b"abc").unwrap(), 3);
        assert!(v.read(null, 99).unwrap().is_empty());
    }

    #[test]
    fn imports_do_not_leave_partial_directories_at_the_node_limit() {
        let mut v = Vfs::default();
        for index in 0..MAX_NODES - 3 {
            v.import_file(format!("/f{index}").as_bytes(), Vec::new())
                .unwrap();
        }
        assert_eq!(
            v.import_file(b"/new/parent/file", Vec::new()),
            Err(Errno(28))
        );
        assert_eq!(v.stat_at(AT_FDCWD, b"/new"), Err(Errno(2)));
    }

    #[test]
    fn directory_search_permissions_and_zero_length_writes() {
        let mut v = Vfs::default();
        v.chown_at(AT_FDCWD, b"/", 1000, 1000, false).unwrap();
        v.credentials = Credentials::user(1000, 1000);
        v.mkdir_at(AT_FDCWD, b"/hidden", 0o400).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/hidden/file", 0x41, 0o600),
            Err(Errno(13))
        );
        let fd = v.open_at(AT_FDCWD, b"/empty", 0x41, 0).unwrap();
        v.seek(fd, 1_000_000, 0).unwrap();
        assert_eq!(v.write(fd, b"").unwrap(), 0);
        assert_eq!(v.allocated_bytes(), 0);
    }
}

#[cfg(test)]
mod process_tests {
    use super::*;
    #[test]
    fn fd_authority_keeps_live_shared_status_and_independent_cloexec_changes() {
        let mut parent = Vfs::default();
        parent.import_file(b"/file", Vec::new()).unwrap();
        let fd = parent
            .open_at(AT_FDCWD, b"/file", 2 | O_CLOEXEC, 0)
            .unwrap();
        let mut child = parent.clone();
        let old = parent.fd_flags_snapshot();
        assert_eq!(query_fd_flags(old.get(fd).unwrap(), 1), Ok(1));
        child.set_status_flags(fd, 2 | O_NONBLOCK).unwrap();
        assert_eq!(
            query_fd_flags(parent.fd_flags_snapshot().get(fd).unwrap(), 3),
            Ok((2 | O_NONBLOCK) as u64)
        );
        assert_eq!(
            query_fd_flags(old.get(fd).unwrap(), 3),
            Ok((2 | O_NONBLOCK) as u64)
        );
        child.set_cloexec(fd, false).unwrap();
        assert_eq!(
            query_fd_flags(child.fd_flags_snapshot().get(fd).unwrap(), 1),
            Ok(0)
        );
        assert_eq!(
            query_fd_flags(parent.fd_flags_snapshot().get(fd).unwrap(), 1),
            Ok(1)
        );
        let duplicate = parent.dup(fd, 20, false).unwrap();
        assert_eq!(child.fd_flags_snapshot().get(duplicate), Err(Errno(9)));
        child.share_descriptors_from(&parent);
        assert_eq!(
            child.fd_flags_snapshot().get(duplicate),
            parent.fd_flags_snapshot().get(duplicate)
        );
        parent.close_exec();
        assert_eq!(parent.fd_flags_snapshot().get(fd), Err(Errno(9)));
        assert!(parent.fd_flags_snapshot().get(duplicate).is_ok());
        assert_eq!(parent.fd_flags_snapshot().get(u32::MAX), Err(Errno(9)));
    }
    #[test]
    fn stream_admission_follows_shared_fd_edits_and_independent_forks() {
        let mut parent = Vfs::default();
        let original = parent.stream_descriptors();
        let mut peer = parent.clone();
        let [read, write] = parent.pipe(0).unwrap();
        let streams = parent.stream_descriptors();
        assert_ne!(streams, original);
        assert_eq!(peer.stream_descriptors(), original);
        peer.share_descriptors_from(&parent);
        assert_eq!(peer.stream_descriptors(), streams);
        let duplicate = parent.dup(write, 20, true).unwrap();
        assert_ne!(parent.stream_descriptors(), streams);
        parent.close_exec();
        assert_eq!(parent.stream_descriptors(), streams);
        assert_eq!(parent.fd_kind(duplicate), Err(Errno(9)));
        parent.close(read).unwrap();
        assert_ne!(parent.stream_descriptors(), streams);
        assert_eq!(peer.stream_descriptors(), parent.stream_descriptors());
        parent.detach_file_table();
        assert!(parent.stream_descriptors().iter().all(|word| *word == 0));
    }
    #[test]
    fn shared_file_table_observes_edits_after_repeated_unchanged_syncs() {
        let mut parent = Vfs::default();
        parent.import_file(b"/file", b"abcd".to_vec()).unwrap();
        let fd = parent.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let mut peer = parent.clone();
        for _ in 0..8 {
            peer.share_descriptors_from(&parent);
        }
        assert_eq!(peer.read(fd, 1).unwrap(), b"a");
        assert_eq!(parent.read(fd, 1).unwrap(), b"b");
        parent.set_status_flags(fd, 2 | O_NONBLOCK).unwrap();
        assert_ne!(peer.flags(fd).unwrap() & O_NONBLOCK, 0);
        let copy = parent.dup(fd, 20, true).unwrap();
        parent.close(fd).unwrap();
        peer.share_descriptors_from(&parent);
        assert_eq!(peer.fd_kind(fd), Err(Errno(9)));
        assert_eq!(peer.read(copy, 1).unwrap(), b"c");
        peer.set_cloexec(copy, false).unwrap();
        parent.share_descriptors_from(&peer);
        parent.close_exec();
        assert_eq!(parent.read(copy, 1).unwrap(), b"d");
        peer.close_all();
        parent.share_descriptors_from(&peer);
        assert_eq!(parent.fd_kind(copy), Err(Errno(9)));
    }
    #[test]
    fn independent_fork_edits_cannot_share_a_file_table_version() {
        let mut parent = Vfs::default();
        parent.import_file(b"/file", vec![]).unwrap();
        let fd = parent.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let mut left = parent.clone();
        let mut right = parent.clone();
        left.set_cloexec(fd, true).unwrap();
        let copy = right.dup(fd, 20, false).unwrap();
        // Equally many edits on independent forks must not look unchanged.
        right.share_descriptors_from(&left);
        assert_eq!(right.fd_kind(copy), Err(Errno(9)));
        assert_ne!(right.flags(fd).unwrap() & O_CLOEXEC, 0);
        assert_eq!(parent.flags(fd).unwrap() & O_CLOEXEC, 0);
        right.detach_file_table();
        left.share_descriptors_from(&right);
        assert_eq!(left.fd_kind(fd), Err(Errno(9)));
        assert!(parent.fd_kind(fd).is_ok());
    }
    #[test]
    fn fork_shares_storage_and_open_position_but_not_descriptor_table() {
        let mut parent = Vfs::default();
        parent.import_file(b"/file", b"abcd".to_vec()).unwrap();
        let fd = parent.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let mut child = parent.clone();
        assert_eq!(child.read(fd, 1).unwrap(), b"a");
        assert_eq!(parent.read(fd, 1).unwrap(), b"b");
        child.close(fd).unwrap();
        assert_eq!(parent.read(fd, 1).unwrap(), b"c");
        child.open_at(AT_FDCWD, b"/child", 0x41, 0o600).unwrap();
        assert!(parent.stat_at(AT_FDCWD, b"/child").is_ok());
        child.chdir(b"/dev").unwrap();
        assert_eq!(parent.cwd().unwrap(), b"/");
    }
    #[test]
    fn dup_and_fork_share_status_flags_but_cloexec_is_per_descriptor() {
        let mut parent = Vfs::default();
        parent.import_file(b"/file", vec![]).unwrap();
        let fd = parent.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let duplicate = parent.dup(fd, 10, true).unwrap();
        let mut child = parent.clone();
        child.set_status_flags(fd, 2 | 0x400).unwrap();
        assert_ne!(parent.flags(duplicate).unwrap() & 0x400, 0);
        child.set_cloexec(fd, true).unwrap();
        assert_eq!(parent.flags(fd).unwrap() & O_CLOEXEC, 0);
        child.close_exec();
        assert_eq!(child.fd_kind(fd), Err(Errno(9)));
        assert!(parent.fd_kind(fd).is_ok());
        assert_eq!(child.fd_kind(duplicate), Err(Errno(9)));
    }
    #[test]
    fn pipe_eof_waits_for_last_shared_writer_and_broken_pipe_for_last_reader() {
        let mut parent = Vfs::default();
        let [r, w] = parent.pipe(0).unwrap();
        let mut child = parent.clone();
        parent.close(w).unwrap();
        assert_eq!(parent.read(r, 1), Err(Errno(11)));
        child.write(w, b"x").unwrap();
        child.close(w).unwrap();
        assert_eq!(parent.read(r, 1).unwrap(), b"x");
        assert!(parent.read(r, 1).unwrap().is_empty());
        let [r, w] = parent.pipe(0).unwrap();
        let mut child = parent.clone();
        parent.close(r).unwrap();
        assert_eq!(parent.write(w, b"x").unwrap(), 1);
        child.close(r).unwrap();
        assert_eq!(parent.write(w, b"x"), Err(Errno(32)));
    }
    #[test]
    fn pipe_small_writes_are_atomic_under_backpressure() {
        let mut v = Vfs::default();
        let [r, w] = v.pipe(O_NONBLOCK).unwrap();
        assert_eq!(v.write(w, &vec![7; PIPE_CAPACITY]).unwrap(), PIPE_CAPACITY);
        assert_eq!(v.poll(r, 1), 1);
        assert_eq!(v.poll(w, 4), 0);
        assert_eq!(v.read(r, 1).unwrap(), vec![7]);
        assert_eq!(v.write(w, b"ab"), Err(Errno(11)));
        assert_eq!(
            v.read(r, PIPE_CAPACITY).unwrap(),
            vec![7; PIPE_CAPACITY - 1]
        );
        v.close(w).unwrap();
        assert_eq!(v.poll(r, 1), 16); // Linux reports HUP, with no data readiness.
    }
    #[test]
    fn unlink_keeps_open_file_and_quota_until_last_close() {
        let mut v = Vfs::default();
        v.import_file(b"/file", b"abc".to_vec()).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/file", 0, 0).unwrap();
        v.unlink_at(AT_FDCWD, b"/file", false).unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/file"), Err(Errno(2)));
        assert_eq!(v.allocated_bytes(), 3);
        assert_eq!(v.read(fd, 3).unwrap(), b"abc");
        v.close(fd).unwrap();
        assert_eq!(v.allocated_bytes(), 0);
    }
    #[test]
    fn failed_dup3_does_not_close_the_target() {
        let mut v = Vfs::default();
        let old = v.fd_kind(1).unwrap();
        assert_eq!(v.dup3(200, 1, 0), Err(Errno(9)));
        assert_eq!(v.fd_kind(1).unwrap(), old);
        assert_eq!(v.dup3(1, 1, 0), Err(Errno(22)));
    }
}

#[cfg(test)]
mod permission_tests {
    use super::*;
    #[test]
    fn retained_inode_state_is_send_and_sync_without_manual_trait_overrides() {
        fn shared<T: Send + Sync>() {}
        shared::<Inode>();
        shared::<mapped::MappedData>();
        shared::<SharedOpenDescription>();
    }
    #[test]
    fn inode_metadata_and_last_lease_survive_owner_drop_on_another_worker() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/shared-inode", 0x42, 0o600).unwrap();
        let inode = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        let weak = Arc::downgrade(&inode);
        {
            let mut node = inode.borrow_mut();
            node.uid = 0;
            node.gid = !0;
        }
        drop(v);
        std::thread::scope(|scope| {
            let writer = inode.clone();
            scope.spawn(move || {
                for uid in 1..=2000 {
                    let mut node = writer.borrow_mut();
                    node.uid = uid;
                    node.gid = !uid;
                }
            });
            for _ in 0..2000 {
                let node = inode.borrow();
                assert_eq!(node.gid, !node.uid);
            }
        });
        std::thread::spawn(move || drop(inode)).join().unwrap();
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn directory_mutations_require_parent_write_and_import_uses_canonical_path() {
        let mut v = Vfs::default();
        v.chown_at(AT_FDCWD, b"/", 1000, 1000, false).unwrap();
        v.credentials = Credentials::user(1000, 1000);
        v.mkdir_at(AT_FDCWD, b"/readonly", 0o555).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/readonly/new", 0x41, 0o600),
            Err(Errno(13))
        );
        assert_eq!(
            v.mkdir_at(AT_FDCWD, b"/readonly/sub", 0o755),
            Err(Errno(13))
        );
        v.import_executable(b"/readonly//program", vec![1]).unwrap();
        assert_eq!(v.executable(b"/readonly/program").unwrap(), vec![1]);
        assert_eq!(
            v.unlink_at(AT_FDCWD, b"/readonly/program", false),
            Err(Errno(13))
        );
    }
}
