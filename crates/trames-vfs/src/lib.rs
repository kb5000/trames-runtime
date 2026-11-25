// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared virtual namespace; host IO is confined to an explicitly selected store.
#![recursion_limit = "512"]
pub mod binder;
mod bpf;
mod task_name;
pub use task_name::TaskName;
mod console;
#[cfg(unix)]
pub use console::NativeConsole;
pub use console::{CapturedBytes, CapturedConsole, ConsoleCallbacks, ConsoleIo, ConsoleStream};
pub mod capabilities;
mod cgroup;
pub use cgroup::{CgroupBirth, CgroupDestination, CgroupTask, CpuShare};
mod fs_context;
mod path_position;
mod path_queries;
pub mod poll_mask;
pub mod posix_mq;
mod sysv_ipc;
pub mod sysv_message;
pub mod sysv_semaphore;
pub mod sysv_shm;
pub use path_queries::PathQueries;
mod fs_data;
#[cfg(all(feature = "hostfs", unix))]
mod hostfs;
mod tmpfs;
use fs_context::FsContext;
pub use fs_context::{FsOwner, Umask};
use fs_data::{FsBorrow, FsHandle};
mod async_io;
mod user_namespace;
pub use user_namespace::{UserNamespace, CLONE_NEWUSER};
mod keyrings;
pub mod landlock;
pub use keyrings::{KeyOperation, KeyRegistry, KeyResult, SessionKeys};
mod credentials;
mod fd_status;
pub use async_io::{AsyncOwner, AsyncOwners, TaskSignal};
pub use fd_status::DescriptorControl;
use fd_status::{CloseOnExec, DescriptorFlags, StatusFlags};
mod pipe;
mod stream_transfer;
pub use fd_table::FifoOpen;
pub use pipe::PipeEndpoint;
use pipe::{Pipe, PipeEnd};
pub use stream_transfer::{StreamTransfer, TransferWait};
mod descriptor_factory;
mod pidfd;
pub use pidfd::{PendingPidFd, PidFd, PIDFD_THREAD};
mod fd_allocator;
mod fd_table;
pub mod perf;
mod resource_limits;
pub use descriptor_factory::DescriptorFactory;
pub use resource_limits::{
    DescriptorCeiling, DescriptorLimit, FileSizeLimit, FixedLimits, MemoryResourceLimits,
    MutableLimits, TaskLimit,
};
mod open_handle;
pub use open_handle::OfdIdentity;
use open_handle::{OpenHandle, OpenMount, OpenWeak};
mod shared_cell;
mod simple_device;
use shared_cell::SharedCell;
mod flock;
pub mod fuse;
use fd_table::{Descriptor, DescriptorTable};
pub use fd_table::{FileTableOwner, FileTableRetirement};
pub use fd_table::{SharedFd, SharedFiles};
pub use flock::FlockRequest;
mod directory;
mod disk_io;
pub use disk_io::{DiskRead, DiskReadCache, DiskReadJob, DiskSync, DiskSyncJob};
mod direct_io;
mod native_images;
pub use direct_io::{NativeEvent, NativeEvents};
mod file_accounting;
mod file_data;
mod file_work;
mod output_resources;
pub use output_resources::FileResources;
mod namespace_work;
pub use file_work::{
    FileCommand, FileCopy, FileOutcome, FileReply, FileTarget, FileValue, FileWork,
};
mod read_reply;
pub use namespace_work::{NamespaceAttempt, NamespaceCall};
pub use read_reply::{ReadPosition, ReadReply};
mod file_io;
use direct_io::PipeResource;
pub use file_io::{DirectFile, DirectFiles, FileAccess, FileEpoch, PreparedFile};
mod readiness;
mod timer_io;
pub use direct_io::{DirectFd, DirectFds, DirectPoll};
pub use readiness::{IoSignal, IoSubscription, IoWake};
pub use timer_io::BootTimer;
mod signal_reader;
#[cfg(test)]
mod uring_context_tests;
pub use signal_reader::SignalReader;
pub use timer_io::TimerFd;
pub use trames_shared::{HostEvents, HostFd, HostSubscription, Readiness, ReadinessDriver};
mod epoll;
mod epoll_graph;
mod events;
pub mod sync_file;
mod uring;
pub use uring::{
    RetainedFd, Uring, UringBufferGroup, UringBufferSource, UringExecutionLease, UringFile,
    UringFileView, UringObject, UringProvidedBuffer, UringRequest, UringResource, UringRetirement,
    UringRunning, UringSelection, UringSource, UringSqe, UringState, URING_CQES, URING_MAX_ENTRIES,
    URING_OPS, URING_SQ_ARRAY,
};
mod executable;
pub use executable::{script_interpreter, ScriptInterpreter};
pub use executable::{ExecutableFile, ExecutingFile};
mod inotify;
pub use inotify::{FileClose, InotifyInstance};
mod ipc;
mod kernel_log;
pub use kernel_log::KernelLogAccess;
mod locks;
mod mapped;
pub use mapped::MappingFile;
mod memfd;
pub use memfd::MemfdParameters;
mod mounts;
pub use mounts::fd::{MountAttributes, MountFdCall};
pub use mounts::query::{MountQuery, MountQueryKind, UNIQUE_MOUNT_ID_BASE};
use mounts::{Mount, PathArg};
pub use mounts::{MountNamespace, ResolvedPath, CLONE_NEWNS};
mod syscall_names;
pub use ipc::{
    LocalConnection, LocalDatagram, LocalOperation, LocalReceived, LocalResource, LocalRights,
    LocalSocket, SharedRights, WaylandAuth, WaylandGrant,
};
pub use locks::{
    ProcessRecordLocks, RecordFile, RecordLock, RecordLockContext, RecordLockRequest, RecordWait,
    OFD_LOCK_OWNER,
};
mod host_files;
mod linux_namespace;
mod task_namespace;
pub use host_files::{HostEdit, HostExport};
pub use task_namespace::{
    TaskNamespaceAttempt, TaskNamespaceOwnerAttempt, TaskNamespaceResources, TaskNamespaceWork,
    TaskNamespaces,
};
mod pid_namespace;
pub use pid_namespace::{PidNamespace, PidReference, CLONE_NEWPID};
mod acl;
mod file_caps;
mod namespace;
mod xattr;
pub use linux_namespace::{
    NamespaceSnapshot, UtsAccess, UtsNamespace, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET,
    CLONE_NEWUTS,
};
mod network;
mod network_io;
mod sysctl;
pub use network_io::{DirectNetwork, DirectTcpFd, NetworkEpoch};
mod oom;
mod overlay;
mod proc_file;
mod proc_image;
mod proc_inet;
pub use proc_image::ProcImage;
mod cpu_topology;
mod proc_source;
mod proc_time;
mod pseudo;
pub use oom::OomTask;
pub use proc_source::{
    proc_task_id, ProcCounters, ProcDirectory, ProcQuery, ProcResources, ProcSource, ProcTask,
    ProcessView, SeccompView,
};
mod pty;
pub mod terminal;
pub use pty::{
    ControllingTerminal, Pty, PtyEnd, PtyIo, PtySlaveEndpoint, TerminalAccess, TerminalIo,
    TerminalSignals, TerminalTask,
};
mod storage;
#[cfg(test)]
mod storage_tests;
pub use credentials::{CredentialState, Credentials, Dumpable, ExecCredentials};
mod file_actor;
pub use file_actor::FileActorScope;
pub use linux_namespace::{NamespaceProjection, PidfdNamespaces, SharedNamespaceSnapshot};
pub use pseudo::{FdInfo, ProcessInfo, RuntimeInfo};
use std::{
    cell::{Cell, OnceCell, RefCell},
    collections::{BTreeMap, VecDeque},
    fmt,
    rc::Rc,
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
const OPEN_ONLY_FLAGS: u32 = O_CREAT | 0x80 | 0x100 | O_TRUNC; // O_EXCL and O_NOCTTY
pub fn query_fd_flags(flags: u32, command: u64) -> Result<u64> {
    match command {
        1 => Ok(u64::from(flags & O_CLOEXEC != 0)),
        3 => Ok((flags & !(O_CLOEXEC | OPEN_ONLY_FLAGS)) as u64),
        _ => Err(Errno(22)),
    }
}
pub use network::{SocketControlOperation, SocketOperation, TunOperation};
pub use storage::{DiskOptions, StorageCapacity, StorageLimits, VolumeSpace, DEFAULT_DISK_BYTES};
pub use trames_net::{NetworkMode, Socket as NetSocket};
pub fn kernel_log_capacity() -> usize {
    kernel_log::LOG_CAPACITY
}
pub const MAX_PATH: usize = 4096;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NODES: usize = 1024;
/// Linux's default nr_open ceiling. Tables allocate only occupied slots.
pub const DEFAULT_MAX_FDS: u32 = 1 << 20;
/// Linux nr_open_max, rounded for a 64-bit fd bitmap. Tables remain sparse.
pub const MAX_FDS: u32 = (i32::MAX as u32) & !7;
/// Cold descriptor classification, shared by epochs and sized to live numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FdMask(Arc<[u64]>);
impl FdMask {
    pub fn iter(&self) -> std::slice::Iter<'_, u64> {
        self.0.iter()
    }
}
impl std::ops::Index<usize> for FdMask {
    type Output = u64;
    fn index(&self, word: usize) -> &u64 {
        self.0.get(word).unwrap_or(&0)
    }
}
/// Default environment task admission ceiling. This is a counter, not a
/// preallocated table, thread pool, PID range or memory reservation. A browser
/// can exceed 256 live threads during ordinary multi-process page loading.
pub const MAX_TASKS: usize = 65_536;
pub const PIPE_CAPACITY: usize = 65536;
pub const AT_FDCWD: i32 = -100;
const O_CREAT: u32 = 0x40;
const O_TRUNC: u32 = 0x200;
pub const O_DIRECTORY: u32 = 0x4000;
pub const O_NOFOLLOW: u32 = 0x8000;
pub const O_DIRECT: u32 = 0x10000;
pub const O_LARGEFILE: u32 = 0x20000;
pub const UTIME_NOW: i64 = 1_073_741_823;
pub const UTIME_OMIT: i64 = 1_073_741_822;
pub const O_NOATIME: u32 = 0x40000;
pub const O_CLOEXEC: u32 = 0x80000;
pub const O_NONBLOCK: u32 = 0x800;
pub const O_PATH: u32 = 0x200000;

/// The guest OFD access mode determines data access after open. Mode 3
/// checks both permissions at open but grants neither read nor write.
pub const fn fd_can_read(flags: u32) -> bool {
    flags & (O_PATH | 1) == 0
}

pub const fn fd_can_write(flags: u32) -> bool {
    matches!(flags & (O_PATH | 3), 1 | 2)
}
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
    anonymous: Option<events::Anonymous>,
    namespace: Option<linux_namespace::NamespaceHandle>,
    mount: Option<OpenMount>,
}
// The actual file, pipe and lock/notification lifetimes share one allocation.
// Legacy ancillary, task and mount control projections retain owner ownership.
struct SharedOpenDescription {
    _write_access: Option<executable::WriteAccess>,
    console: std::sync::OnceLock<console::ConsoleEndpoint>,
    oom: Option<std::sync::Weak<OomTask>>,
    sysctl_control: Option<sysctl::Control>,
    mount_file: Option<Arc<mounts::watch::MountFile>>,
    runtime_file: Option<Arc<proc_file::ProcFile>>,
    socket: Option<Arc<NetSocket>>,
    _disk_file: Option<Arc<std::fs::File>>,
    #[cfg(all(feature = "hostfs", unix))]
    host_file: Option<Arc<hostfs::OpenFile>>,
    native_image: Option<Arc<native_images::ImageFile>>,
    mount_resource: std::sync::OnceLock<Arc<mounts::MountData>>,
    mount_use: std::sync::OnceLock<mounts::MountUse>,
    directory_mount: std::sync::OnceLock<mounts::DirectoryPin>,
    namespace_resource: Option<linux_namespace::SharedNamespace>,
    link_credentials: Option<(u64, UserNamespace)>,
    landlock_denied: u64,
    file_authority: std::sync::OnceLock<file_io::PublishedFile>,
    tcp_publication: std::sync::Mutex<Option<DirectTcpFd>>,
    socket_control: Option<network_io::SocketControl>,
    control: Option<events::SharedControl>,
    id: u64,
    owner: (u32, u32),
    kind: FdKind,
    flags: StatusFlags,
    file_position: Arc<file_data::FilePosition>,
    flock: std::sync::OnceLock<Arc<flock::Owner>>,
    ofd_records: std::sync::OnceLock<locks::OfdOwner>,
    node: Option<NodeRef>,
    // Overlay read descriptions retain the real lower file selected at open.
    read_node: Option<NodeRef>,
    pipe: Option<Arc<PipeEnd>>,
    pty: Option<Arc<PtyEnd>>,
    local: Option<Arc<ipc::LocalResource>>,
    bridge: Option<std::sync::Arc<trames_bridge::Connection>>,
    kernel_log: Option<Arc<kernel_log::Kmsg>>,
    notification: Option<Arc<FileClose>>,
}
impl SharedOpenDescription {
    fn is_regular_file(&self) -> bool {
        self.node.as_ref().is_some_and(|node| node.regular_file)
    }
    fn notify_file_io(&self, node: &NodeRef, mask: u32) {
        if let Some(lease) = &self.notification {
            lease.path_event(mask);
        } else {
            inotify::notify(node, mask, None);
        }
    }
    fn notify_read(&self, bytes: &[u8]) {
        if !bytes.is_empty() {
            if let Some(lease) = &self.notification {
                lease.path_event(inotify::ACCESS);
            }
        }
    }
    fn metadata_node(&self) -> Option<NodeRef> {
        self.node
            .clone()
            .or_else(|| self.pipe.as_ref()?.metadata.clone())
            .or_else(|| {
                self.pty
                    .as_ref()
                    .filter(|end| !end.master)
                    .map(|end| end.pair.slave.clone())
            })
    }
    fn proc_watch(&self) -> Option<&Arc<readiness::ProcWatch>> {
        if let Some(file) = &self.mount_file {
            return Some(&file.watch);
        }
        match &self.sysctl_control {
            Some(sysctl::Control::UtsName(_, watch)) if self.flags.get() & O_PATH == 0 => {
                Some(watch)
            }
            _ => None,
        }
    }
    fn proc_control(&self) -> bool {
        self.oom.is_some()
            || self.sysctl_control.is_some()
            || self.mount_file.is_some()
            || self.runtime_file.is_some()
    }
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
        if self.control.is_none()
            && matches!(
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
        if self.pipe.is_some()
            || self.pty.is_some()
            || self.local.is_some()
            || self.kernel_log.is_some()
            || self.control.is_some()
            || self.native_image.is_some()
        {
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
        self.file_position.snapshot()
    }
    fn data_node(&self) -> Option<NodeRef> {
        self.read_node.clone().or_else(|| self.node.clone())
    }
}
enum Content {
    MessageQueue(Arc<posix_mq::Queue>),
    Directory,
    File(storage::FileData),
    // Bytes are owned by the daemon; this inode is never a local FileData.
    Fuse,
    Symlink(Vec<u8>),
    Null,
    Terminal,
    Device(pseudo::Device),
    Fifo(Pipe),
    Socket(ipc::PathBinding),
}
type NodeRef = Arc<Inode>;
struct Inode {
    text_users: std::sync::atomic::AtomicIsize,
    proc_node: std::sync::OnceLock<proc_source::ProcNode>,
    removed_directory_parent: std::sync::OnceLock<NodeRef>,
    fuse_abort: std::sync::OnceLock<fuse::Abort>,
    fuse_directory: std::sync::OnceLock<Arc<fuse::Directory>>,
    fuse_leaf: std::sync::OnceLock<Arc<fuse::Leaf>>,
    seq_file: bool,
    regular_file: bool,
    directory: bool,
    active_file_work: std::sync::atomic::AtomicUsize,
    layout: std::sync::OnceLock<Arc<trames_memory::layout::Layout>>,
    metadata: std::sync::Mutex<()>,
    // Immutable device behavior belongs to inode identity, not its pathname.
    simple_device: Option<simple_device::Kind>,
    #[cfg(all(feature = "hostfs", unix))]
    mount_target: std::sync::atomic::AtomicBool,
    #[cfg(all(feature = "hostfs", unix))]
    host: std::sync::OnceLock<Arc<hostfs::HostFile>>,
    identity: u64,
    state: SharedCell<Node>,
    length: std::sync::OnceLock<trames_shared::LogicalSize>,
    quota: std::sync::OnceLock<Arc<file_accounting::FileQuota>>,
    symlink_page: std::sync::OnceLock<Arc<file_accounting::FileCharge>>,
}
impl Inode {
    fn new(mut node: Node) -> Self {
        if node.seals.is_none() {
            if let Content::File(data) = &node.content {
                data.register_storage();
            }
        }
        if let Content::File(data) = &node.content {
            data.activate_metadata(node.mode, node.times);
        }
        node.identity = trames_memory::new_backing_identity();
        Self {
            text_users: Default::default(),
            seq_file: false,
            regular_file: !node.volatile && matches!(node.content, Content::File(_)),
            directory: matches!(node.content, Content::Directory),
            proc_node: Default::default(),
            removed_directory_parent: Default::default(),
            fuse_abort: Default::default(),
            fuse_directory: Default::default(),
            fuse_leaf: Default::default(),
            active_file_work: std::sync::atomic::AtomicUsize::new(0),
            layout: Default::default(),
            metadata: std::sync::Mutex::new(()),
            simple_device: simple_device::Kind::content(&node.content),
            #[cfg(all(feature = "hostfs", unix))]
            mount_target: std::sync::atomic::AtomicBool::new(false),
            #[cfg(all(feature = "hostfs", unix))]
            host: std::sync::OnceLock::new(),
            identity: node.identity,
            state: SharedCell::new(node),
            length: std::sync::OnceLock::new(),
            quota: std::sync::OnceLock::new(),
            symlink_page: Default::default(),
        }
    }
    fn bind_quota(&self, quota: &Arc<file_accounting::FileQuota>) -> Result<()> {
        let quota = self.quota.get_or_init(|| quota.clone());
        let node = self.borrow();
        if node.seals.is_none() && !node.volatile {
            if let Content::File(data) = &node.content {
                data.bind_quota(quota)?;
            }
        }
        Ok(())
    }
    fn borrow(&self) -> std::sync::RwLockReadGuard<'_, Node> {
        self.state.borrow()
    }
    fn try_borrow(&self) -> Option<std::sync::RwLockReadGuard<'_, Node>> {
        self.state.try_borrow()
    }
    fn borrow_mut(&self) -> InodeWrite<'_> {
        let mut state_guard = self.state.borrow_mut();
        let canonical = state_guard.file_metadata();
        state_guard.mode = canonical.mode;
        state_guard.times = canonical.times;
        let before = file_data::FileMeta {
            mode: state_guard.mode,
            times: state_guard.times,
        };
        InodeWrite {
            owner_cell: self,
            state_guard,
            before,
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
    before: file_data::FileMeta,
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
        if let Content::File(data) = &self.state_guard.content {
            let after = file_data::FileMeta {
                mode: self.state_guard.mode,
                times: self.state_guard.times,
            };
            data.activate_metadata(after.mode, after.times);
            data.patch_metadata(self.before, after);
        }
        if self.state_guard.seals.is_none() {
            if let Content::File(data) = &self.state_guard.content {
                data.register_storage();
                if !self.state_guard.volatile {
                    if let Some(quota) = self.owner_cell.quota.get() {
                        // Already-published storage either retains its original charge or
                        // was admitted by filesystem_empty_data before replacement.
                        data.bind_quota(quota).expect("admitted inode storage");
                    }
                }
            }
        }
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
#[cfg(test)]
thread_local! {static PATH_SEARCHES: Cell<usize> = const { Cell::new(0) };}
impl Node {
    fn stat_device(&self, mount: Option<&OpenMount>) -> u64 {
        mount
            .filter(|m| m.kind == mounts::Kind::Overlay)
            .map_or(self.device, |m| m.device())
    }
    fn file_metadata(&self) -> file_data::FileMeta {
        if let Content::File(data) = &self.content {
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
        // Unnamed/open-unlinked objects have no namespace entry. Their inode
        // lifetime is independent of the directory tree, including memfd IPC.
        if self.links == 0 {
            return None;
        }
        let matches = |node: &NodeRef| node.identity == self.identity;
        if let Some(path) = self.path_hint.borrow().as_ref() {
            if mounts::below(path, root) && paths.get(path).is_some_and(matches) {
                return Some(path.clone());
            }
        }
        #[cfg(test)]
        PATH_SEARCHES.with(|count| count.set(count.get() + 1));
        let path = paths
            .iter()
            .find(|(path, node)| mounts::below(path, root) && matches(node))
            .map(|(path, _)| path.clone());
        *self.path_hint.borrow_mut() = path.clone();
        path
    }
}
#[derive(Clone)]
struct ResolvedInode {
    node: NodeRef,
    label: Vec<u8>,
    mount: Option<Arc<Mount>>,
    // Acceptance retains the original resource until its operation finishes.
    // Neither the inode cache nor a long-lived query view owns these leases.
    file: Option<Arc<SharedOpenDescription>>,
    #[cfg(all(feature = "hostfs", unix))]
    host_file: Option<Arc<hostfs::OpenFile>>,
    _image: Option<Arc<ExecutableFile>>,
    _directory: Option<Arc<mounts::MountUse>>,
}
#[derive(Clone)]
struct MetadataTarget {
    path: ResolvedPath,
    node: NodeRef,
    _magic: Option<ResolvedInode>,
}
/// Mount information belonging to the same resolved path or open description as stat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatMount {
    pub id: u64,
    pub is_root: bool,
    mounted: bool,
}
impl StatMount {
    fn mounted(id: u64, is_root: bool) -> Self {
        Self {
            id,
            is_root,
            mounted: true,
        }
    }
    pub fn unique_id(self) -> Option<u64> {
        self.mounted.then_some(UNIQUE_MOUNT_ID_BASE + self.id)
    }
    fn for_open(open: &OpenDescription) -> Self {
        Self {
            id: Vfs::open_mount_id(open),
            mounted: open.mount.is_some(),
            is_root: open.mount.as_ref().is_some_and(|m| {
                open.node.as_ref().is_some_and(|n| Arc::ptr_eq(n, &m.root))
                    || m.kind == mounts::Kind::Nsfs && open.namespace_resource.is_some()
            }),
        }
    }
}

#[derive(Clone)]
enum ResolvedTarget {
    Inode(ResolvedInode),
    Descriptor(OpenHandle),
}
type ResolvedEntry = (ResolvedPath, Option<ResolvedTarget>);
#[derive(Clone, Copy)]
enum ResolveOperation<'a> {
    Fuse(fuse::PathOperation),
    ResumeFuse(fuse::PathOperation, bool),
    CaptureFuse(&'a RefCell<Option<fuse::PathPlan>>),
}
// One pathname walk, retained unchanged across a daemon wait. Ordinary paths
// construct this on the stack; credentials are captured only on suspension.
struct PathWalk {
    root: ResolvedPath,
    current: ResolvedPath,
    boundary: Option<ResolvedPath>,
    parts: VecDeque<Vec<u8>>,
    trailing: bool,
    follow_final: bool,
    retain_magic: bool,
    policy: u64,
    stop_magic: bool,
    sequence: Option<u64>,
    climbed: bool,
    links: usize,
    credentials: Option<Box<Credentials>>,
    follow_start: bool,
}
struct Filesystem {
    shared_budget: trames_shared::SharedBudget,
    paths: BTreeMap<Vec<u8>, NodeRef>,
    inodes: Vec<std::sync::Weak<Inode>>,
    next_inode: u64,
    limits: StorageLimits,
    disk: Option<Arc<storage::DiskStore>>,
    volume: Option<(VolumeSpace, u64)>,
}
impl Filesystem {
    fn admit_inode(&mut self) -> Result<()> {
        // Dead weak registrations cannot exhaust the live inode quota. Collect
        // only at the allocation boundary, never scan the whole image per memfd.
        if self.inodes.len() >= self.limits.nodes {
            self.inodes.retain(|node| node.strong_count() != 0);
        }
        if self.inodes.len() >= self.limits.nodes {
            return Err(Errno(28));
        }
        Ok(())
    }
}
/// Process snapshot fields actually consumed by a proc lookup. Unknown paths
/// stay conservative; independent kernel endpoints never enumerate tasks/RSS.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcRefresh(u16);
#[allow(non_upper_case_globals)]
impl ProcRefresh {
    pub const Independent: Self = Self(0);
    pub const Metadata: Self = Self(1);
    pub const Mappings: Self = Self(1 | 1 << 1);
    pub const Environment: Self = Self(1 | 1 << 2);
    pub const Auxiliary: Self = Self(1 | 1 << 3);
    pub const Arguments: Self = Self(1 | 1 << 4);
    pub const Descriptors: Self = Self(1 | 1 << 5);
    pub const Residency: Self = Self(1 | 1 << 6);
    /// Global host/quota accounting, distinct from an original task's RSS.
    pub const HostMemory: Self = Self(1 | 1 << 6 | 1 << 11);
    pub const Paths: Self = Self(1 | 1 << 7);
    pub const Namespaces: Self = Self(1 | 1 << 8);
    pub const Directories: Self = Self(1 | 1 << 10);
    const Content: Self = Self(1 << 9);
    pub const TerminalStat: Self = Self(1 | 1 << 6 | 1 << 12);
    pub const Full: Self = Self((1 << 13) - 1);

    fn includes(self, fields: Self) -> bool {
        self.0 & fields.0 == fields.0
    }
    pub fn for_path(path: &[u8]) -> Self {
        if [b"/cwd".as_slice(), b"/root"]
            .iter()
            .any(|tail| path.ends_with(tail))
        {
            return Self::Directories;
        }
        if path.ends_with(b"/exe") {
            return Self::Paths;
        }
        if path.split(|&c| c == b'/').any(|part| part == b"ns")
            || path.ends_with(b"/mounts")
            || path.ends_with(b"/mountinfo")
        {
            return Self::Namespaces;
        }
        if path == b"/proc/sys/fs/file-nr" {
            return Self::Descriptors;
        }
        if path == b"/proc/sys"
            || path.starts_with(b"/proc/sys/")
            || matches!(
                path,
                b"/proc/cpuinfo"
                    | b"/proc/cmdline"
                    | b"/proc/bootconfig"
                    | b"/proc/version"
                    | b"/proc/swaps"
                    | b"/proc/partitions"
                    | b"/proc/devices"
                    | b"/proc/diskstats"
                    | b"/proc/filesystems"
            )
        {
            return Self::Independent;
        }
        if path
            .split(|&c| c == b'/')
            .any(|part| matches!(part, b"fd" | b"fdinfo"))
        {
            return Self::Descriptors;
        }
        if path.split(|&c| c == b'/').any(|part| part == b"net") {
            // Network tables consult the target's original namespace directly.
            return Self::Metadata;
        }
        if path.ends_with(b"/cmdline") {
            return Self::Arguments;
        }
        if path.ends_with(b"/maps") {
            return Self::Mappings;
        }
        if path.ends_with(b"/environ") {
            return Self::Environment;
        }
        if path.ends_with(b"/auxv") {
            return Self::Auxiliary;
        }
        if matches!(path, b"/proc/stat" | b"/proc/uptime" | b"/proc/loadavg")
            || [b"/comm".as_slice(), b"/limits", b"/mounts", b"/mountinfo"]
                .iter()
                .any(|tail| path.ends_with(tail))
        {
            return Self::Metadata;
        }
        if path == b"/proc/meminfo" || path.ends_with(b"/oom_score") {
            return Self::HostMemory;
        }
        if path.ends_with(b"/stat") {
            return Self::TerminalStat;
        }
        if [
            b"/statm".as_slice(),
            b"/status",
            b"/smaps",
            b"/smaps_rollup",
        ]
        .iter()
        .any(|tail| path.ends_with(tail))
        {
            return Self::Residency;
        }
        // Directory traversal publishes identities first. The caller re-probes
        // a newly visible path before selecting its live data payload.
        Self::Metadata
    }
    /// A syscall can traverse a proc FD link into a different live payload.
    /// Keep exactly the union of dependencies. A descriptor-link traversal into
    /// maps/status must not also read unrelated argv/environment/auxiliary data.
    pub fn merge(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    pub fn arguments(self) -> bool {
        self.includes(Self::Arguments)
    }
    pub fn mappings(self) -> bool {
        self.includes(Self::Mappings)
    }
    pub fn environment(self) -> bool {
        self.includes(Self::Environment)
    }
    pub fn auxiliary(self) -> bool {
        self.includes(Self::Auxiliary)
    }
    pub fn descriptors(self) -> bool {
        self.includes(Self::Descriptors)
    }
    pub fn residency(self) -> bool {
        self.includes(Self::Residency)
    }
    pub fn terminal_stat(self) -> bool {
        self.includes(Self::TerminalStat)
    }
    pub fn host_memory(self) -> bool {
        self.includes(Self::HostMemory)
    }
    pub fn paths(self) -> bool {
        self.includes(Self::Paths)
    }
    pub fn namespaces(self) -> bool {
        self.includes(Self::Namespaces)
    }
    pub fn directories(self) -> bool {
        self.includes(Self::Directories)
    }
    pub fn content(self) -> bool {
        self.includes(Self::Content)
    }
    pub fn with_content(self) -> Self {
        self.merge(Self::Content)
    }
    pub fn lookup(self) -> Self {
        Self(self.0 & (1 | 1 << 5 | 1 << 7 | 1 << 8 | 1 << 10))
    }
}

pub struct Vfs {
    signal_reader: RefCell<Option<Arc<dyn SignalReader>>>,
    task_namespace_publication: OnceCell<Arc<task_namespace::Publication>>,
    query: Option<path_queries::Authority>,
    network: trames_net::Network,
    native_services: Arc<SharedCell<Option<Arc<ipc::NativeServices>>>>,
    fs: FsHandle,
    fds: DescriptorTable,
    context: FsContext,
    uts: UtsNamespace,
    root_network: Arc<linux_namespace::RootNetwork>,
    path_bindings: ipc::PathBindings,
    ipc_namespace: Arc<linux_namespace::IpcNamespace>,
    pub sem_undo: sysv_semaphore::UndoMember,
    cgroup_namespace: Arc<linux_namespace::CgroupNamespace>,
    pid_ns: PidNamespace,
    pid_identity: Option<PidReference>,
    pid_children: PidNamespace,
    mounts: Option<MountNamespace>,
    mount_registry: mounts::Registry,
    mount_resources: Arc<SharedCell<Vec<std::sync::Weak<mounts::MountIdentity>>>>,
    detached_mounts: Arc<SharedCell<Vec<Vec<Arc<Mount>>>>>,
    pub credentials: Credentials,
    namei_policy: Arc<sysctl::NameiPolicy>,
    task_limit: TaskLimit,
    pseudo: Arc<SharedCell<pseudo::PseudoFs>>,
    kernel_log: Arc<kernel_log::KernelLog>,
    binder: Arc<binder::Contexts>,
    cgroups: Arc<SharedCell<cgroup::Cgroups>>,
    dumpable: Dumpable,
    pid: u32,
    lock_owner: u32,
    record_locks: Arc<locks::Registry>,
    file_size_limit: FileSizeLimit,
    memory_resource_limits: MemoryResourceLimits,
    file_size_signal: Cell<bool>,
    next_open: Arc<descriptor_factory::OpenIds>,
    proc_accessed: Cell<bool>,
    proc_refresh: Cell<ProcRefresh>,
    source_observed: Cell<Option<proc_source::Observation>>,
    ptys: Arc<std::sync::Mutex<BTreeMap<u32, std::sync::Weak<Pty>>>>,
    embedding_terminal: Arc<std::sync::OnceLock<Arc<Pty>>>,
    controlling: std::sync::OnceLock<Arc<pty::ControllingTerminal>>,
    terminal_task: std::sync::OnceLock<Arc<dyn pty::TerminalTask>>,
    bridge: Option<trames_bridge::Broker>,
}
impl Clone for Vfs {
    fn clone(&self) -> Self {
        self.clone_with_files(false)
    }
}
impl Vfs {
    /// Environment-owned host controls retain the original namespace/network,
    /// without holding guest task custody or extending any guest OFD lifetime.
    pub fn host_control_view(&self) -> Self {
        let mut view = self.clone();
        view.fds = DescriptorTable::default();
        view.controlling = Default::default();
        view.embedding_terminal = Default::default();
        view.pid_identity = None;
        view
    }
    pub fn task_signal(&self) -> Option<Arc<dyn TaskSignal>> {
        self.signal_reader.borrow().as_ref()?.task_signal()
    }
    pub fn bind_signal_reader(&self, reader: Arc<dyn SignalReader>) {
        let mut current = self.signal_reader.borrow_mut();
        if current.as_ref().is_none_or(|r| !Arc::ptr_eq(r, &reader)) {
            *current = Some(reader);
        }
    }
    pub fn descriptor_limit(&self) -> u32 {
        self.fds.limit()
    }
    pub fn set_descriptor_limit(&self, limit: u32) {
        self.fds.set_limit(limit.min(MAX_FDS));
    }
    pub fn share_descriptor_limit(&mut self, other: &Self) {
        self.fds.share_limit(&other.fds);
    }
    pub fn shared_files(&self) -> SharedFiles {
        self.query
            .as_ref()
            .map_or_else(|| self.fds.worker_membership(), |q| q.files.clone())
    }
    /// Clone task context while choosing the Linux FD ownership domain.
    /// CLONE_FILES never allocates a temporary private FD map or flag cells.
    pub fn clone_with_files(&self, shared: bool) -> Self {
        self.clone_with_resources(shared, false)
    }
    pub fn clone_with_resources(&self, shared_files: bool, shared_fs: bool) -> Self {
        Self {
            signal_reader: RefCell::new(self.signal_reader.borrow().clone()),
            task_namespace_publication: OnceCell::new(),
            query: self.query.clone(),
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
            sem_undo: self.sem_undo.clone(),
            cgroup_namespace: self.cgroup_namespace.clone(),
            pid_ns: self.pid_ns.clone(),
            pid_identity: self.pid_identity.clone(),
            pid_children: self.pid_children.clone(),
            mounts: self.mounts.clone(),
            mount_registry: self.mount_registry.clone(),
            mount_resources: self.mount_resources.clone(),
            detached_mounts: self.detached_mounts.clone(),
            credentials: self.credentials.clone(),
            namei_policy: self.namei_policy.clone(),
            task_limit: self.task_limit.clone(),
            pseudo: self.pseudo.clone(),
            kernel_log: self.kernel_log.clone(),
            binder: self.binder.clone(),
            cgroups: self.cgroups.clone(),
            dumpable: self.dumpable.clone(),
            pid: self.pid,
            lock_owner: self.lock_owner,
            record_locks: self.record_locks.clone(),
            file_size_limit: self.file_size_limit.fork(),
            memory_resource_limits: self.memory_resource_limits.fork(),
            file_size_signal: self.file_size_signal.clone(),
            next_open: self.next_open.clone(),
            proc_accessed: self.proc_accessed.clone(),
            proc_refresh: self.proc_refresh.clone(),
            source_observed: Cell::new(None),
            ptys: self.ptys.clone(),
            embedding_terminal: self.embedding_terminal.clone(),
            controlling: self.controlling.get().map_or_else(Default::default, |s| {
                std::sync::OnceLock::from(Arc::new(s.fork()))
            }),
            terminal_task: Default::default(),
            bridge: self.bridge.clone(),
        }
    }
}

impl Vfs {
    fn empty(fs: FsHandle) -> Self {
        let pid_ns = PidNamespace::default();
        let root_network = Arc::new(linux_namespace::RootNetwork::default());
        let network = root_network.network.borrow().clone();
        let mount_registry = mounts::Registry::default();
        let mut context = FsContext::default();
        context.paths.registry = mount_registry.clone();
        Self {
            signal_reader: RefCell::new(None),
            task_namespace_publication: OnceCell::new(),
            query: None,
            network,
            native_services: Arc::default(),
            fs,
            fds: DescriptorTable::default(),
            context,
            uts: UtsNamespace::default(),
            root_network,
            path_bindings: ipc::PathBindings::default(),
            ipc_namespace: Arc::default(),
            sem_undo: Default::default(),
            cgroup_namespace: Arc::default(),
            pid_ns: pid_ns.clone(),
            pid_identity: None,
            pid_children: pid_ns,
            mounts: None,
            mount_registry,
            mount_resources: Arc::default(),
            detached_mounts: Arc::default(),
            credentials: Credentials::default(),
            namei_policy: Arc::default(),
            task_limit: TaskLimit::default(),
            pseudo: Arc::new(SharedCell::new(pseudo::PseudoFs::default())),
            kernel_log: Arc::default(),
            binder: Arc::default(),
            cgroups: Arc::default(),
            dumpable: Dumpable::default(),
            pid: 1,
            ptys: Arc::default(),
            embedding_terminal: Arc::default(),
            controlling: Default::default(),
            terminal_task: Default::default(),
            lock_owner: 1,
            record_locks: Arc::default(),
            file_size_limit: FileSizeLimit::default(),
            memory_resource_limits: MemoryResourceLimits::default(),
            file_size_signal: Cell::new(false),
            next_open: Arc::new(descriptor_factory::OpenIds::default()),
            proc_accessed: Cell::new(false),
            proc_refresh: Cell::new(ProcRefresh::Independent),
            source_observed: Cell::new(None),
            bridge: None,
        }
    }
}

impl Default for Vfs {
    fn default() -> Self {
        let mut v = Self::empty(FsHandle::new(Filesystem {
            shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
            paths: BTreeMap::new(),
            inodes: Vec::new(),
            next_inode: 1,
            limits: StorageLimits::memory(),
            disk: None,
            volume: None,
        }));
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
                            _write_access: None,
                            console: Default::default(),
                            oom: None,
                            sysctl_control: None,
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
                            landlock_denied: 0,
                            link_credentials: None,
                            file_authority: Default::default(),
                            tcp_publication: Default::default(),
                            socket_control: None,
                            control: None,
                            read_node: None,
                            id: v.open_id(),
                            owner: (v.credentials.fsuid, v.credentials.fsgid),
                            kind,
                            flags: flags.into(),
                            file_position: Arc::default(),
                            flock: std::sync::OnceLock::new(),
                            ofd_records: Default::default(),
                            node: None,
                            pipe: None,
                            pty: None,
                            local: None,
                            bridge: None,
                            kernel_log: None,
                            notification: None,
                        }),
                        anonymous: None,
                        namespace: None,
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
        descriptor_factory::next_id(&self.next_open)
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
        // FD membership changes, but this process keeps the same live rlimit.
        let limit = self.descriptor_limit_handle();
        self.fds = self.fds.clone();
        self.fds.bind_limit(limit.0);
    }
    /// Immutable descriptor kinds for one CPU epoch. Cached per shared table
    /// version, so dispatch does not scan all descriptors on every syscall.
    pub fn stream_descriptors(&self) -> FdMask {
        self.descriptor_io_masks().0
    }
    /// Actual membership only; consumers must not scan the numeric ceiling.
    pub fn descriptor_numbers(&self) -> Vec<u32> {
        self.fds
            .entries()
            .iter()
            .filter_map(|(&fd, _)| (fd < MAX_FDS).then_some(fd))
            .collect()
    }
    /// Live admitted membership/status/CLOEXEC. Excluded owner controls keep
    /// their frozen epoch capabilities; those structural edits still join.
    pub fn fd_flags_snapshot(&self) -> FdFlags {
        self.descriptor_snapshots().0
    }
    fn descriptor_snapshots(&self) -> (FdFlags, DirectFds) {
        let revision = FD_FLAGS_REVISION.load(Ordering::Relaxed);
        let mut cache = self.fds.cache();
        let cached = &cache.flags;
        if let Some((old, snapshot)) = cached {
            if *old == revision {
                if let Some((direct_revision, direct)) = &cache.direct {
                    if *direct_revision == revision {
                        return (
                            snapshot.clone(),
                            DirectFds(direct.clone(), Some(self.shared_files()), None, None),
                        );
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
            if matches!(d.open, open_handle::OpenView::Owner(_)) {
                entries[fd as usize] = Some(DescriptorFlags {
                    status: open.flags.clone(),
                    cloexec: d.cloexec.clone(),
                });
                direct[fd as usize] = DirectFd::snapshot(&open);
            }
        }
        let snapshot = FdFlags(entries.into(), Some(self.shared_files()));
        cache.flags = Some((revision, snapshot.clone()));
        let direct = DirectFds(direct.into(), Some(self.shared_files()), None, None);
        cache.direct = Some((revision, direct.0.clone()));
        (snapshot, direct)
    }
    fn ordinary_stream(o: &OpenDescription) -> bool {
        matches!(
            o.kind,
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr | FdKind::PipeRead | FdKind::PipeWrite
        ) || o.bridge.is_some()
            || o.local.as_ref().is_some_and(|socket| socket.kind() == 1)
    }
    /// Ready byte I/O shares original OFDs with message and terminal operations.
    /// Local sockets never reference worker Memory.
    pub fn epoch_stream_io(&self, fd: u32) -> bool {
        self.descriptor(fd)
            .is_ok_and(|d| Self::ordinary_stream(&d.open.borrow()))
    }
    fn descriptor_io_masks(&self) -> (FdMask, FdMask) {
        self.fds
            .cache()
            .io
            .get_or_init(|| {
                let descriptors = self.fds.entries();
                let words = descriptors
                    .last_key_value()
                    .map_or(0, |(&fd, _)| (fd as usize + 1).div_ceil(64));
                let mut streams = vec![0; words];
                let mut files = vec![0; words];
                for (&fd, d) in descriptors.iter() {
                    let o = d.open.borrow();
                    if Self::ordinary_stream(&o) {
                        streams[fd as usize / 64] |= 1 << (fd % 64);
                    } else if Self::ordinary_file(&o, false).is_some() {
                        files[fd as usize / 64] |= 1 << (fd % 64);
                    }
                }
                while streams.last() == Some(&0) {
                    streams.pop();
                }
                while files.last() == Some(&0) {
                    files.pop();
                }
                (FdMask(streams.into()), FdMask(files.into()))
            })
            .clone()
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
            || o.sysctl_control.is_some()
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
        let regular = node.regular_file;
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
    fn check_parent_write(&self, path: &ResolvedPath) -> Result<NodeRef> {
        if self.proc_directory_tree(path) {
            self.node(path)?;
        }
        path.writable()?;
        if Self::cgroup_mount(path)
            || path.mount.as_ref().is_some_and(|m| {
                m.devpts.is_some()
                    || matches!(m.kind, mounts::Kind::Mqueue | mounts::Kind::FuseControl)
            })
        {
            return Err(Errno(1));
        }
        if self.pseudo_readonly(&path.key) && self.uses_pseudo(path) {
            let parent = path.parent();
            if self.proc_task_directory(&parent) && self.node(path).is_ok() {
                return Err(Errno(1));
            }
            if self.proc_directory_tree(path) && !self.allowed(&self.node(&parent)?.borrow(), 3) {
                return Err(Errno(13));
            }
            return Err(Errno(30));
        }
        let parent = self.node(&path.parent())?;
        if !self.allowed(&parent.borrow(), 3) {
            return Err(Errno(13));
        }
        Ok(parent)
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
        if let Some(socket) = open.socket.clone() {
            drop(open);
            return socket.readable_bytes().map_err(|e| Errno(e.0));
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
        Self::poll_open(&open, events, pending, self.signal_reader.borrow().as_ref())
    }
    fn poll_open(
        o: &OpenDescription,
        events: u16,
        pending: u64,
        reader: Option<&Arc<dyn SignalReader>>,
    ) -> u16 {
        if let Some(events::SharedControl::Perf(event)) = &o.control {
            return event.poll(events).0;
        }
        if let Some(events::SharedControl::MessageQueue(q)) = &o.control {
            return q.poll(events).0;
        }
        if let Some(events::SharedControl::Fuse(file)) = &o.control {
            return file.poll(events).0;
        }
        if let Some(events::SharedControl::Tun(file, _)) = &o.control {
            return if o.flags.get() & O_PATH != 0 {
                32
            } else {
                file.poll(events).0
            };
        }
        if let Some(events::SharedControl::Binder(process)) = &o.control {
            return if o.flags.get() & O_PATH != 0 {
                32
            } else {
                process
                    .poll_for(
                        reader
                            .and_then(|r| r.global_tid())
                            .unwrap_or(process.owner()),
                        events,
                    )
                    .0
            };
        }
        if let Some(events::SharedControl::Pid(pid)) = &o.control {
            return pid.poll(events).0;
        }
        if let Some(events::SharedControl::Sync(file)) = &o.control {
            return file.poll(events).0;
        }
        if let Some(watch) = o.proc_watch() {
            return watch.poll(events).0;
        }
        if let Some(end) = &o.pty {
            return end.pair.poll(end.master, events);
        }
        if let Some(log) = &o.kernel_log {
            return log.poll(events).0;
        }
        if let Some(events::SharedControl::Cgroup(file)) = &o.control {
            return if o.flags.get() & O_PATH != 0 {
                32
            } else {
                file.poll(events).0
            };
        }
        if matches!(o.kind, FdKind::Stdout | FdKind::Stderr) {
            return events & 4;
        }
        if let Some(local) = &o.local {
            return local.poll(events);
        }
        if let Some(anonymous) = &o.anonymous {
            return anonymous.poll(events, pending, reader);
        }
        if let Some(bridge) = &o.bridge {
            return bridge.poll(events);
        }
        if let Some(socket) = &o.socket {
            return socket.poll(events).unwrap_or(8);
        }
        if let Some(end) = &o.pipe {
            return end.data.lock().unwrap().poll(
                end.read,
                end.write,
                end.initial_write_epoch,
                events,
            );
        }
        events & (poll_mask::READ_NORMAL | poll_mask::WRITE_NORMAL)
    }
    pub fn enable_terminal(&mut self) -> Result<()> {
        let pair = if let Some(pair) = self.embedding_terminal.get() {
            pair.clone()
        } else {
            let cached = self.pseudo.borrow().prepare(
                0,
                b"/dev/pts/0",
                Content::Device(pseudo::Device::Pts(0, 0)),
                0o20620,
            )?;
            let slave = cached.finish();
            {
                let mut node = slave.borrow_mut();
                node.uid = self.credentials.fsuid;
                node.gid = 5;
            }
            let pair = Pty::embedding(slave);
            self.embedding_terminal.get_or_init(|| pair).clone()
        };
        self.ptys.lock().unwrap().insert(0, Arc::downgrade(&pair));
        self.set_controlling_terminal(Some(0))
            .expect("embedding terminal");
        if self.node(b"/dev/tty").is_err() {
            self.insert(b"/dev/tty".to_vec(), Content::Terminal, 0o20666)?;
        }
        for fd in 0..=2 {
            self.fds.insert(
                fd,
                Descriptor {
                    open: OpenHandle::new(OpenDescription {
                        shared: Arc::new(SharedOpenDescription {
                            _write_access: None,
                            console: Default::default(),
                            oom: None,
                            sysctl_control: None,
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
                            landlock_denied: 0,
                            link_credentials: None,
                            file_authority: Default::default(),
                            tcp_publication: Default::default(),
                            socket_control: None,
                            control: None,
                            read_node: None,
                            id: self.open_id(),
                            owner: (self.credentials.fsuid, self.credentials.fsgid),
                            kind: FdKind::Terminal,
                            flags: (2).into(),
                            file_position: Arc::default(),
                            flock: std::sync::OnceLock::new(),
                            ofd_records: Default::default(),
                            node: None,
                            pipe: None,
                            pty: Some(pty::PtyEnd::new(pair.clone(), false)),
                            local: None,
                            bridge: None,
                            kernel_log: None,
                            notification: None,
                        }),
                        anonymous: None,
                        namespace: None,
                        mount: None,
                    }),
                    cloexec: (false).into(),
                },
            );
        }
        Ok(())
    }
    fn insert(&mut self, path: impl Into<ResolvedPath>, content: Content, mode: u32) -> Result<()> {
        self.insert_entry(path.into(), content, mode, false)
    }
    fn insert_entry(
        &mut self,
        path: ResolvedPath,
        content: Content,
        mut mode: u32,
        exclusive: bool,
    ) -> Result<()> {
        let filesystem = path.filesystem(self);
        let _namespace = filesystem.namespace.lock().unwrap();
        let path = self.rebase_indexed(path)?;
        if exclusive {
            self.landlock_check_parent(&path, None, landlock::make(mode))?;
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            let host_mode = if exclusive && !matches!(content, Content::Symlink(_)) {
                mode & !self.umask()
            } else {
                mode
            };
            let node = host.create(&filesystem, &path, &content, host_mode)?;
            self.notification_link(&path, &node, true);
            self.notification_entry(
                &path,
                inotify::CREATE,
                0,
                matches!(content, Content::Directory),
            );
            return Ok(());
        }
        let parent = if path == b"/" {
            None
        } else {
            let i = path.iter().rposition(|b| *b == b'/').ok_or(Errno(2))?;
            let parent = self.node(&ResolvedPath {
                directory_inode: None,
                indexed_position: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_position: None,
                retained_directory: None,
                proc_binding: None,
                key: path[..i.max(1)].to_vec(),
                mount: path.mount.clone(),
            })?;
            if !matches!(parent.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            Some(parent)
        };
        let xattrs = acl::inherit(
            parent.as_ref().map(|p| p.borrow()).as_deref(),
            &content,
            &mut mode,
            self.umask(),
            exclusive,
        );
        let inherited = parent.as_ref().and_then(|p| {
            let p = p.borrow();
            (p.mode & 0o2000 != 0).then_some(p.gid)
        });
        if inherited.is_some() && matches!(content, Content::Directory) {
            mode |= 0o2000;
        }
        let parent_times = directory::EntryTimes::lock(parent.as_deref(), None);
        let mut fs = filesystem.borrow_mut();
        if exclusive && fs.paths.contains_key(&path.key) {
            return Err(Errno(17));
        }
        fs.admit_inode()?;
        if fs.paths.len() >= fs.limits.nodes {
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
        let now = storage::Timestamp::now();
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
            times: [now; 3],
            xattrs,
            seals: None,
        }));
        fs.track_inode(&node)?;
        fs.paths.insert(path.key.clone(), node.clone());
        if let Err(e) = parent_times.commit(now, || fs.checkpoint()) {
            fs.paths.remove(&path.key);
            fs.inodes.pop();
            fs.next_inode = old_next;
            return Err(e);
        }
        if let Content::File(data) = &mut node.borrow_mut().content {
            data.orphan(false);
        }
        drop(fs);
        drop(parent_times);
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
        if let Some(query) = &self.query {
            // Every implemented mount uses original shared inode/topology
            // resources. Admission follows the actual node/provider, not a
            // filesystem-name whitelist (which used to exclude mqueue roots).
            query.pin_mount(path.mount());
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(position) = path.host_position() {
            let fs = path
                .mount()
                .map_or_else(|| self.fs.clone(), |mount| mount.fs.clone());
            return Ok(position
                .pin(fs.host.as_ref().ok_or(Errno(5))?, &fs, key)?
                .node
                .clone());
        }
        if let Some(position) = path.indexed_position() {
            return position.node(path.mount().map_or(&self.fs, |mount| &mount.fs));
        }
        if let Some(directory) = path.retained_directory().or_else(|| path.directory_inode()) {
            if let Some(fs) = path.mount().and_then(|mount| mount.fs.fuse.as_ref()) {
                fs.check(&self.credentials)?;
            }
            return Ok(directory.clone());
        }
        if path
            .mount()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup && m.root.borrow().links == 0)
        {
            return Err(Errno(19));
        }
        if let Some((mount, fs)) = path
            .mount()
            .and_then(|mount| mount.fs.fuse.as_ref().map(|fs| (mount, fs)))
        {
            fs.check(&self.credentials)?;
            return if path.key() == mount.root_path() {
                Ok(mount.root.clone())
            } else {
                Err(Errno(95))
            };
        }
        if self.uses_pseudo(path) {
            if key == b"/proc" || key.starts_with(b"/proc/") {
                self.proc_accessed.set(true);
                let demand = ProcRefresh::for_path(key);
                let previous = self.proc_refresh.get();
                self.proc_refresh.set(if previous.descriptors() {
                    previous.merge(demand)
                } else {
                    demand
                });
            }
            if let Some(node) = self.pseudo_node(path)? {
                return Ok(node);
            }
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(mount) = path.mount() {
            if let Some(host) = &mount.fs.host {
                return host.lookup(&mount.fs, key);
            }
        }
        let filesystem = path.mount().map_or(&self.fs, |m| &m.fs);
        let fs = filesystem.borrow();
        if let Some(node) = fs.paths.get(key) {
            return Ok(node.clone());
        }
        let overlay = fs.overlay.clone();
        drop(fs);
        overlay.ok_or(Errno(2))?.lookup_new(filesystem, key)
    }
    fn descriptor(&self, fd: u32) -> Result<Descriptor> {
        if let Some(query) = &self.query {
            return query.descriptor(fd);
        }
        self.fds.lookup(fd)
    }
    fn rebase_indexed(&self, mut path: ResolvedPath) -> Result<ResolvedPath> {
        if let Some(position) = &path.indexed_position {
            path.key = position.key(&path.filesystem(self))?;
        }
        Ok(path)
    }
    pub fn allocated_bytes(&self) -> u64 {
        Self::filesystem_used_bytes(&self.fs.borrow())
    }
    pub fn cwd(&self) -> Result<Vec<u8>> {
        self.cwd_name::<false>(&self.context.paths.borrow())
    }
    fn cwd_name<const GETCWD: bool>(&self, paths: &fs_context::Paths) -> Result<Vec<u8>> {
        let location = self.location(paths.cwd_node.as_ref().ok_or(Errno(2))?, &paths.cwd_mount)?;
        self.render_path::<GETCWD>(&location, &self.root_location_in(paths)?)
    }
    fn path_of(&self, node: &NodeRef) -> Result<Vec<u8>> {
        if let Some(path) = self.pseudo.borrow().path_of(node) {
            return Ok(path);
        }
        let fs = self.fs.borrow();
        let result = node.borrow().path_in(&fs.paths, b"/").ok_or(Errno(2));
        result
    }
    pub fn regular_file_fd(&self, fd: u32) -> Result<bool> {
        Ok(self.descriptor(fd)?.open.borrow().is_regular_file())
    }
    pub fn fd_kind(&self, fd: u32) -> Result<FdKind> {
        Ok(self.descriptor(fd)?.open.borrow().kind.clone())
    }
    /// Internal OFD identity for retained owner-side wait validation.
    pub fn open_description_identity(&self, fd: u32) -> Result<OfdIdentity> {
        Ok(OfdIdentity::new(&self.descriptor(fd)?.open.borrow().shared))
    }
    pub fn matches_open_description(&self, fd: u32, identity: &OfdIdentity) -> bool {
        self.descriptor(fd)
            .is_ok_and(|d| identity.matches(&d.open.borrow().shared))
    }
    fn is_directory<P: PathArg + ?Sized>(&self, path: &P) -> bool {
        self.node(path)
            .is_ok_and(|n| matches!(n.borrow().content, Content::Directory))
    }
    fn base(&self, dirfd: i32) -> Result<ResolvedPath> {
        self.path_base(dirfd, None)
    }
    fn path_base(&self, dirfd: i32, accepted: Option<&Descriptor>) -> Result<ResolvedPath> {
        let path = if dirfd == AT_FDCWD {
            let paths = self.context.paths.borrow();
            self.location(paths.cwd_node.as_ref().ok_or(Errno(2))?, &paths.cwd_mount)?
        } else {
            let o_descriptor = accepted
                .cloned()
                .map_or_else(|| self.descriptor(dirfd as u32), Ok)?;
            let o = o_descriptor.open.borrow();
            let n = o.node.as_ref().ok_or(Errno(20))?;
            if !matches!(n.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            self.location(n, &self.mount_for_path(o.mount.as_ref()))?
        };
        if path
            .proc_binding
            .as_ref()
            .and_then(|p| p.at(&path, self.proc_namespace(&path).id()))
            .is_some_and(|p| !p.target.present())
        {
            return Err(Errno(3));
        }
        Ok(path)
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
        self.proc_observation(dirfd, path).is_some()
    }
    /// The last actual proc traversal identifies the data dependency even when
    /// lookup fails (e.g. missing /proc/sys keys). Missing process directories
    /// first refresh identities; the caller re-probes the final data dependency
    /// after publishing newly-created tasks.
    pub fn proc_observation(&self, dirfd: i32, path: &[u8]) -> Option<ProcRefresh> {
        self.observe_proc(|vfs| vfs.resolve(dirfd, path)).1
    }
    /// Observe the actual operation when its result can be prepared before a
    /// possible proc refresh. Ordinary paths then need no discovery-only walk.
    /// A caller that refreshes proc must repeat the query before publishing it.
    pub fn observe_proc<T>(&self, operation: impl FnOnce(&Self) -> T) -> (T, Option<ProcRefresh>) {
        self.proc_accessed.set(false);
        self.proc_refresh.set(ProcRefresh::Independent);
        let result = operation(self);
        let demand = self
            .proc_accessed
            .replace(false)
            .then(|| self.proc_refresh.get());
        (result, demand)
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
    fn metadata_target(&self, dirfd: i32, path: &[u8], follow: bool) -> Result<MetadataTarget> {
        // Metadata calls have one pathname operand. Retain it only after an
        // actual suspension, rather than allocating an operand map on every
        // ordinary chmod/chown/utimens call.
        let accepted = self
            .query
            .as_ref()
            .filter(|q| q.metadata_call)
            .and_then(|q| q.metadata_entry.borrow_mut().take());
        let entry = if let Some(entry) = accepted {
            *entry
        } else {
            // Initial namespace admission already selected the native executor.
            // Per-component scheduling advice belongs to a resumed cold walk.
            let operation = self
                .query
                .as_ref()
                .filter(|q| q.metadata_call)
                .map(|_| ResolveOperation::Fuse(fuse::PathOperation::ResolveEntry));
            self.resolve_entry_operation(dirfd, path, follow, true, 0, false, operation, None)?
        };
        self.metadata_target_resolved(entry)
    }
    fn metadata_target_resolved(&self, (path, magic): ResolvedEntry) -> Result<MetadataTarget> {
        let magic = match magic {
            Some(ResolvedTarget::Inode(file)) => Some(file),
            Some(ResolvedTarget::Descriptor(open)) => Some(self.proc_open_node(&open, &path)?),
            None => None,
        };
        if let Some(file) = &magic {
            Ok(MetadataTarget {
                path: ResolvedPath {
                    directory_inode: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                    proc_binding: None,
                    key: file.label.clone(),
                    mount: file.mount.clone(),
                },
                node: file.node.clone(),
                _magic: magic,
            })
        } else {
            let node = self.node(&path)?;
            Ok(MetadataTarget {
                path,
                node,
                _magic: None,
            })
        }
    }
    fn resolve_entry(
        &self,
        dirfd: i32,
        path: &[u8],
        follow_final: bool,
        retain_magic: bool,
    ) -> Result<ResolvedEntry> {
        self.resolve_entry_policy(dirfd, path, follow_final, retain_magic, 0, false)
    }
    fn resolve_entry_policy(
        &self,
        dirfd: i32,
        path: &[u8],
        follow_final: bool,
        retain_magic: bool,
        policy: u64,
        stop_magic: bool,
    ) -> Result<ResolvedEntry> {
        self.resolve_entry_operation(
            dirfd,
            path,
            follow_final,
            retain_magic,
            policy,
            stop_magic,
            None,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn resolve_entry_operation(
        &self,
        dirfd: i32,
        path: &[u8],
        follow_final: bool,
        retain_magic: bool,
        policy: u64,
        stop_magic: bool,
        operation: Option<ResolveOperation<'_>>,
        accepted: Option<&Descriptor>,
    ) -> Result<ResolvedEntry> {
        // A topology call can resolve multiple operands. Once accepted, each
        // operand remains an object capability while a later operand waits.
        let paths = if operation.is_none() {
            self.query
                .as_ref()
                .and_then(|query| query.topology_paths.clone())
        } else {
            None
        };
        let key = paths.as_ref().map(|paths| {
            let mut paths = paths.borrow_mut();
            let operand = paths.cursor;
            paths.cursor += 1;
            namespace_work::PathKey::new(
                operand,
                dirfd,
                path,
                follow_final,
                retain_magic,
                policy,
                stop_magic,
            )
        });
        if let Some(paths) = &paths {
            if let Some(entry) = paths.borrow().accepted.get(key.as_ref().unwrap()) {
                return Ok(entry.clone());
            }
        }
        let operation = operation.or_else(|| {
            paths.as_ref().map(|paths| {
                ResolveOperation::ResumeFuse(
                    fuse::PathOperation::ResolveEntry,
                    paths.borrow().native,
                )
            })
        });
        let walk = self.start_path_walk(
            dirfd,
            path,
            follow_final,
            retain_magic,
            policy,
            stop_magic,
            accepted,
        );
        let result = walk
            .and_then(|walk| self.resolve_walk(walk, operation))
            .and_then(|entry| {
                if paths.is_some() {
                    self.pin_topology_entry(entry)
                } else {
                    Ok(entry)
                }
            });
        if let Some(paths) = paths {
            if let Ok(entry) = &result {
                paths
                    .borrow_mut()
                    .accepted
                    .insert(key.unwrap(), entry.clone());
            } else {
                paths.borrow_mut().pending = key;
            }
        }
        result
    }
    fn pin_topology_entry(&self, mut entry: ResolvedEntry) -> Result<ResolvedEntry> {
        if entry.1.is_none() {
            let node = self.node(&entry.0)?;
            #[cfg(all(feature = "hostfs", unix))]
            let native = entry.0.filesystem(self).host.is_some();
            #[cfg(not(all(feature = "hostfs", unix)))]
            let native = false;
            // A named host walk already retains its accepted native position.
            // Its projected cache need not exist in the mount's owner index.
            // Reconstructing that path loses the operand with ENOENT.
            if node.fuse_leaf.get().is_none() && !native {
                entry.0 = self.location(&node, &entry.0.mount)?;
            }
            // This is an accepted mount operand, which may also name an
            // ordinary file. Keep its inode even when a second operand waits.
            entry.0.directory_inode = Some(node);
        }
        Ok(entry)
    }
    #[allow(clippy::too_many_arguments)]
    fn start_path_walk(
        &self,
        dirfd: i32,
        path: &[u8],
        follow_final: bool,
        retain_magic: bool,
        policy: u64,
        stop_magic: bool,
        accepted: Option<&Descriptor>,
    ) -> Result<PathWalk> {
        self.begin_proc_query();
        if path.is_empty() {
            return Err(Errno(2));
        }
        if path.len() >= MAX_PATH || path.contains(&0) {
            return Err(Errno(36));
        }
        let scoped = policy & (8 | 16) != 0;
        let sequence = scoped.then(|| self.path_sequence());
        let climbed = false;
        let base = if scoped || path[0] != b'/' {
            Some(self.path_base(dirfd, accepted)?)
        } else {
            None
        };
        let boundary = scoped.then(|| base.as_ref().unwrap().clone());
        if policy & 8 != 0 && path[0] == b'/' {
            return Err(Errno(18));
        }
        let root = if policy & 16 != 0 {
            boundary.clone().unwrap()
        } else {
            self.root_location()?
        };
        let current = if path[0] == b'/' {
            root.clone()
        } else {
            base.unwrap()
        };
        let parts: VecDeque<Vec<u8>> = path
            .split(|&b| b == b'/')
            .filter(|p| !p.is_empty())
            .map(|p| p.to_vec())
            .collect();
        let trailing = path.last() == Some(&b'/');
        let links = 0;
        Ok(PathWalk {
            root,
            current,
            boundary,
            parts,
            trailing,
            follow_final,
            retain_magic,
            policy,
            stop_magic,
            sequence,
            climbed,
            links,
            credentials: None,
            follow_start: path[0] == b'/',
        })
    }
    fn directory_resolved(&self, (path, target): ResolvedEntry) -> Result<(ResolvedPath, NodeRef)> {
        let (path, node) = match target {
            Some(ResolvedTarget::Inode(file)) => {
                if path.host_position_present() || path.indexed_position.is_some() {
                    if !matches!(file.node.borrow().content, Content::Directory) {
                        return Err(Errno(20));
                    }
                    return Ok((path, file.node));
                }
                (self.location(&file.node, &file.mount)?, file.node)
            }
            Some(ResolvedTarget::Descriptor(open)) => {
                let file = self.proc_open_node(&open, &path)?;
                (self.location(&file.node, &file.mount)?, file.node)
            }
            None => {
                let node = self.node(&path)?;
                (path, node)
            }
        };
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        Ok((path, node))
    }
    fn path_native_work(&self, path: &ResolvedPath) -> bool {
        let fs = path.filesystem(self);
        #[cfg(all(feature = "hostfs", unix))]
        if fs.host.is_some() {
            return true;
        }
        fs.borrow().disk.is_some() || fs.has_overlay()
    }
    fn entry_native_work(&self, (path, target): &ResolvedEntry) -> bool {
        let fs = match target {
            Some(ResolvedTarget::Descriptor(open)) => {
                let open = open.borrow();
                #[cfg(all(feature = "hostfs", unix))]
                if open.host_file.is_some() {
                    return true;
                }
                let Some(mount) = &open.mount else {
                    return false;
                };
                mount.fs.clone()
            }
            Some(ResolvedTarget::Inode(file)) => {
                let Some(mount) = &file.mount else {
                    return false;
                };
                mount.fs.clone()
            }
            None => path.filesystem(self),
        };
        #[cfg(all(feature = "hostfs", unix))]
        if fs.host.is_some() {
            return true;
        }
        fs.borrow().disk.is_some() || fs.has_overlay()
    }
    fn resolve_walk(
        &self,
        walk: PathWalk,
        operation: Option<ResolveOperation<'_>>,
    ) -> Result<ResolvedEntry> {
        self.resolve_walk_permission(walk, operation, false)
    }
    fn resolve_walk_permission(
        &self,
        walk: PathWalk,
        operation: Option<ResolveOperation<'_>>,
        mut permission_checked: bool,
    ) -> Result<ResolvedEntry> {
        let PathWalk {
            root,
            mut current,
            boundary,
            mut parts,
            trailing,
            follow_final,
            retain_magic,
            policy,
            stop_magic,
            sequence,
            mut climbed,
            mut links,
            credentials: _,
            follow_start,
        } = walk;
        if follow_start {
            current = self.follow_mounts(current)?;
            Self::check_resolve_mount(&root, &current, policy)?;
        }
        loop {
            if let Some(ResolveOperation::ResumeFuse(operation, native)) = operation {
                if current.indexed_position.is_none() && !current.host_position_present() {
                    if let Some(node) = &current.directory_inode {
                        if !node.borrow().volatile
                            && current.mount.as_ref().is_none_or(|m| m.fs.fuse.is_none())
                        {
                            current.indexed_position =
                                Some(path_position::Position::inode(node.clone()));
                        }
                    }
                }
                // Scheduling advice has no lookup or filesystem effect. Stop
                // before an ordinary native path stage, retaining the original
                // current directory and unconsumed components for its executor.
                #[cfg(all(feature = "hostfs", unix))]
                let anchored = current.host_position.is_some()
                    || current.indexed_position.is_some() && self.path_native_work(&current);
                #[cfg(not(all(feature = "hostfs", unix)))]
                let anchored =
                    current.indexed_position.is_some() && self.path_native_work(&current);
                let next = if let Some(part) = parts
                    .front()
                    .filter(|p| !anchored && p.as_slice() != b"." && p.as_slice() != b"..")
                {
                    let mut next = current.clone();
                    if next != b"/" {
                        next.push(b'/');
                    }
                    next.extend_from_slice(part);
                    if let Some(position) = &current.indexed_position {
                        next.indexed_position = Some(position.child(part)?);
                    }
                    Some(self.follow_mounts(next)?)
                } else {
                    None
                };
                let owner = self.path_owner_work(&current)
                    || next.as_ref().is_some_and(|next| self.path_owner_work(next));
                let host = !native
                    && (self.path_native_work(&current)
                        || next
                            .as_ref()
                            .is_some_and(|next| self.path_native_work(next)));
                if owner || host {
                    let query = self.query.as_ref().unwrap();
                    let continuation = Some(Box::new((
                        PathWalk {
                            root,
                            current,
                            boundary,
                            parts,
                            trailing,
                            follow_final,
                            retain_magic,
                            policy,
                            stop_magic,
                            sequence,
                            climbed,
                            links,
                            credentials: Some(Box::new(self.credentials.clone())),
                            follow_start: false,
                        },
                        operation,
                    )));
                    if owner {
                        query.prepared.borrow_mut().owner_continuation = continuation;
                    } else {
                        query.prepared.borrow_mut().continuation = continuation;
                    }
                    return query.defer();
                }
            }
            let Some(part) = parts.pop_front() else { break };
            let parent_node = self.node(&current)?;
            #[cfg(all(feature = "hostfs", unix))]
            if let Some(position) = &current.host_position {
                let fs = current.filesystem(self);
                position
                    .pin(fs.host.as_ref().ok_or(Errno(5))?, &fs, &current.key)?
                    .file
                    .refresh_permissions(&parent_node)?;
            }
            let n = parent_node.borrow();
            if !matches!(n.content, Content::Directory) {
                return Err(Errno(20));
            }
            if !permission_checked {
                if let Some((mount, fs)) = current
                    .mount
                    .as_ref()
                    .and_then(|m| m.fs.fuse.as_ref().map(|fs| (m, fs)))
                    .filter(|(_, fs)| fs.local_permissions() || !fs.connection.initialized())
                {
                    let resume = match operation {
                        Some(ResolveOperation::Fuse(op)) => Some((op, false)),
                        Some(ResolveOperation::ResumeFuse(op, native)) => Some((op, native)),
                        _ => None,
                    };
                    if let Some((op, native)) = resume {
                        if fs.permission_refresh(&parent_node, &self.credentials, 1) {
                            drop(n);
                            parts.push_front(part);
                            let mut pending = fuse::Metadata::search_permission(
                                self,
                                &mount.shared,
                                fs,
                                parent_node.clone(),
                                PathWalk {
                                    root,
                                    current: current.clone(),
                                    boundary,
                                    parts,
                                    trailing,
                                    follow_final,
                                    retain_magic,
                                    policy,
                                    stop_magic,
                                    sequence,
                                    climbed,
                                    links,
                                    credentials: Some(Box::new(self.credentials.clone())),
                                    follow_start: false,
                                },
                                op,
                                native,
                            )?;
                            if let fuse::PathOperation::Open(flags) = op {
                                // Reserve/publication state must exist before
                                // an early parent-permission daemon wait.
                                pending.prepare_open(
                                    self.open_id(),
                                    mount.shared.clone(),
                                    current.key.clone(),
                                    flags,
                                    0,
                                    self.credentials.open_identity(),
                                );
                            }
                            let query = self.query.as_ref().ok_or(Errno(95))?;
                            query.prepared.borrow_mut().fuse = Some(Box::new(pending));
                            return query.defer();
                        }
                    }
                }
            }
            permission_checked = false;
            if !self.allowed(&n, 1)
                && !current.mount.as_ref().is_some_and(|m| m.fs.fuse.is_some())
                && !self.proc_fd_search_allowed(&current)
            {
                return Err(Errno(13));
            }
            let parent_owner = n.uid;
            let parent_mode = n.mode;
            drop(n);
            if part == b"." {
                continue;
            }
            if part == b".." {
                if let Some(seq) = sequence {
                    climbed = true;
                    if seq as u32 != 0 || self.path_sequence() != seq {
                        return Err(Errno(11));
                    }
                }
                if boundary.as_ref() == Some(&current) {
                    if policy & 8 != 0 {
                        return Err(Errno(18));
                    }
                    continue;
                }
                let parent = self.parent_location_in(&current, &root)?;
                Self::check_resolve_mount(&current, &parent, policy)?;
                current = parent;
                continue;
            }
            if current.retained_directory.is_some() {
                return Err(Errno(2));
            }
            if part.len() > 255 {
                return Err(Errno(if self.proc_directory_tree(&current) {
                    2
                } else {
                    36
                }));
            }
            let parent = current.clone();
            if current != b"/" {
                current.push(b'/');
            }
            current.extend_from_slice(&part);
            if let Some(position) = &parent.indexed_position {
                current.indexed_position = Some(position.child(&part)?);
            }
            #[cfg(all(feature = "hostfs", unix))]
            if let Some(position) = &parent.host_position {
                current.host_position = Some(position.child(&part)?);
            }
            if current.len() >= MAX_PATH {
                return Err(Errno(36));
            }
            current = self.follow_mounts(current)?;
            self.bind_proc_path(&mut current)?;
            Self::check_resolve_mount(&parent, &current, policy)?;
            if let Some(operation) = operation {
                if let Some((m, fs)) = current
                    .mount
                    .as_ref()
                    .and_then(|m| m.fs.fuse.as_ref().map(|fs| (m, fs)))
                {
                    // One daemon-owned component suspends the same VFS walk.
                    // A bind mount's root may be a non-root FUSE directory.
                    if current.key != m.root_path() {
                        let operation = match operation {
                            ResolveOperation::CaptureFuse(captured) => {
                                let mut names = parts;
                                names.push_front(part);
                                let plan = fuse::PathPlan::root(m, fs, names, trailing)
                                    .at_directory(parent_node.clone());
                                *captured.borrow_mut() = Some(plan.with_walk(PathWalk {
                                    root,
                                    current: parent,
                                    boundary,
                                    parts: VecDeque::new(),
                                    trailing: true,
                                    follow_final: true,
                                    retain_magic: true,
                                    policy,
                                    stop_magic: false,
                                    sequence,
                                    climbed,
                                    links,
                                    credentials: Some(Box::new(self.credentials.clone())),
                                    follow_start: false,
                                }));
                                return Ok((current, None));
                            }
                            ResolveOperation::Fuse(operation)
                            | ResolveOperation::ResumeFuse(operation, _) => operation,
                        };
                        let query = self.query.as_ref().ok_or(Errno(95))?;
                        let open = if let fuse::PathOperation::Open(flags) = operation {
                            let mut path = current.key.clone();
                            for part in &parts {
                                path.push(b'/');
                                path.extend_from_slice(part);
                            }
                            let denied = if flags & O_PATH == 0
                                && self.credentials.landlock.fs_mask() != 0
                            {
                                let root = ResolvedPath {
                                    key: m.root_path(),
                                    mount: Some(m.clone()),
                                    directory_inode: None,
                                    indexed_position: None,
                                    #[cfg(all(feature = "hostfs", unix))]
                                    host_position: None,
                                    retained_directory: None,
                                    proc_binding: None,
                                };
                                // Daemon-backed leaf rules are unavailable until FUSE
                                // publishes stable identities to the guest inode table.
                                self.landlock_denied(
                                    &root,
                                    None,
                                    landlock::READ_FILE
                                        | landlock::WRITE_FILE
                                        | landlock::READ_DIR
                                        | landlock::TRUNCATE
                                        | landlock::MAKE_REG,
                                )?
                            } else {
                                0
                            };
                            Some((path, flags, denied))
                        } else {
                            None
                        };
                        let selected_mount = m.clone();
                        let selected_fs = fs.clone();
                        let mut pending = fuse::Metadata::lookup(
                            self,
                            &selected_mount,
                            &selected_fs,
                            parent_node.clone(),
                            part,
                            PathWalk {
                                root,
                                current,
                                boundary,
                                parts,
                                trailing,
                                follow_final,
                                retain_magic,
                                policy,
                                stop_magic,
                                sequence,
                                climbed,
                                links,
                                credentials: Some(Box::new(self.credentials.clone())),
                                follow_start: false,
                            },
                            parent,
                            operation,
                        )?;
                        if let Some((path, flags, denied)) = open {
                            pending.prepare_open(
                                self.open_id(),
                                selected_mount.shared.clone(),
                                path,
                                flags,
                                denied,
                                self.credentials.open_identity(),
                            );
                        }
                        query.prepared.borrow_mut().fuse = Some(Box::new(pending));
                        return query.defer();
                    }
                }
            }
            if !parts.is_empty() || follow_final || trailing {
                if current
                    .mount
                    .as_ref()
                    .is_some_and(|m| m.flags.get() & mounts::MS_NOSYMFOLLOW != 0)
                    && self.is_proc_magic_link(&current)
                {
                    return Err(Errno(40));
                }
                if policy & (2 | 4 | 8 | 16) != 0 && self.is_proc_magic_link(&current) {
                    // Explicit NO_MAGICLINKS/NO_SYMLINKS takes precedence;
                    // scoped lookups reject the object jump with EXDEV.
                    return Err(Errno(if policy & (2 | 4) != 0 { 40 } else { 18 }));
                }
                // An nsfs magic link names an original kernel object, not its
                // display label. Accept that object once for open/metadata.
                if parts.is_empty()
                    && !trailing
                    && (self.uses_pseudo(&current)
                        || current
                            .mount
                            .as_ref()
                            .is_some_and(|m| m.namespace.is_some()))
                {
                    if let Some(namespace) = self.namespace_for_path(&current)? {
                        if policy & 1 != 0 {
                            return Err(Errno(18));
                        }
                        let target = retain_magic.then(|| {
                            ResolvedTarget::Descriptor(self.namespace_description(
                                namespace,
                                current.mount.clone().map(OpenMount::Owner),
                            ))
                        });
                        return Ok((current, target));
                    }
                }
                if stop_magic && parts.is_empty() && !trailing && self.uses_pseudo(&current) {
                    if let Some(open) = self.proc_fd_description_normalized(&current)? {
                        Self::check_resolve_mount(
                            &current,
                            &ResolvedPath {
                                key: Vec::new(),
                                directory_inode: None,
                                indexed_position: None,
                                #[cfg(all(feature = "hostfs", unix))]
                                host_position: None,
                                retained_directory: None,
                                proc_binding: None,
                                mount: self.mount_for_path(open.borrow().mount.as_ref()),
                            },
                            policy,
                        )?;
                        return Ok((current, Some(ResolvedTarget::Descriptor(open))));
                    }
                    if let Some(file) = self.proc_exe_node_normalized(&current)? {
                        Self::check_resolve_mount(
                            &current,
                            &ResolvedPath {
                                key: file.label.clone(),
                                directory_inode: None,
                                indexed_position: None,
                                #[cfg(all(feature = "hostfs", unix))]
                                host_position: None,
                                retained_directory: None,
                                proc_binding: None,
                                mount: file.mount.clone(),
                            },
                            policy,
                        )?;
                        return Ok((current, Some(ResolvedTarget::Inode(file))));
                    }
                }
                let directory = if self.uses_pseudo(&current) && !retain_magic && parts.is_empty() {
                    self.proc_directory_node_normalized(&current)?
                } else {
                    None
                };
                if self.uses_pseudo(&current)
                    && (retain_magic || !parts.is_empty() || directory.is_some())
                {
                    let magic = match directory {
                        Some(directory) => Some(directory),
                        None => self.proc_magic_node_normalized(&current)?,
                    };
                    if let Some(file) = magic {
                        Self::check_resolve_mount(
                            &current,
                            &ResolvedPath {
                                directory_inode: None,
                                indexed_position: None,
                                #[cfg(all(feature = "hostfs", unix))]
                                host_position: None,
                                retained_directory: None,
                                proc_binding: None,
                                key: file.label.clone(),
                                mount: file.mount.clone(),
                            },
                            policy,
                        )?;
                        if parts.is_empty() && !trailing && retain_magic {
                            return Ok((current, Some(ResolvedTarget::Inode(file))));
                        }
                        if !matches!(file.node.borrow().content, Content::Directory) {
                            return Err(Errno(20));
                        }
                        #[cfg(all(feature = "hostfs", unix))]
                        if file
                            .mount
                            .as_ref()
                            .is_some_and(|mount| mount.fs.host.is_some())
                        {
                            current = ResolvedPath {
                                key: file.node.host.get().ok_or(Errno(2))?.key_hint(),
                                mount: file.mount.clone(),
                                host_position: Some(hostfs::Position::magic(file)),
                                directory_inode: None,
                                indexed_position: None,
                                retained_directory: None,
                                proc_binding: None,
                            };
                            continue;
                        }
                        current = self.location(&file.node, &file.mount)?;
                        if !file.node.borrow().volatile
                            && file.mount.as_ref().is_none_or(|m| m.fs.fuse.is_none())
                        {
                            current.indexed_position = Some(path_position::Position::magic(file));
                        }
                        continue;
                    }
                }
                let node = match self.node(&current) {
                    Ok(node) => Some(node),
                    Err(Errno(2)) => None,
                    Err(e) => return Err(e),
                };
                if let Some(node) = node {
                    let n = node.borrow();
                    if n.mode & 0o170000 == 0o120000 && node.fuse_leaf.get().is_some() {
                        if parts.is_empty()
                            && parent_mode & 0o1002 == 0o1002
                            && n.uid != self.credentials.fsuid
                            && n.uid != parent_owner
                            && self.namei_policy.get(sysctl::Protection::Symlinks) != 0
                        {
                            return Err(Errno(13));
                        }
                        if policy & 4 != 0
                            || links >= 40
                            || current
                                .mount
                                .as_ref()
                                .is_some_and(|m| m.flags.get() & mounts::MS_NOSYMFOLLOW != 0)
                        {
                            return Err(Errno(40));
                        }
                        drop(n);
                        // A daemon wait may outlive rename/replacement of the
                        // mountpoint's parent. Retain that accepted directory,
                        // then let the existing walker anchor its relative work.
                        let mut parent = parent;
                        parent.directory_inode = Some(parent_node.clone());
                        let mount = current.mount.as_ref().ok_or(Errno(5))?.clone();
                        let fs = mount.fs.fuse.as_ref().ok_or(Errno(5))?;
                        let walk = PathWalk {
                            root,
                            current,
                            boundary,
                            parts,
                            trailing,
                            follow_final,
                            retain_magic,
                            policy,
                            stop_magic,
                            sequence,
                            climbed,
                            links,
                            credentials: Some(Box::new(self.credentials.clone())),
                            follow_start: false,
                        };
                        if let Some(ResolveOperation::CaptureFuse(captured)) = operation {
                            let mut walk = walk;
                            let names = std::mem::take(&mut walk.parts);
                            let accepted = walk.current.clone();
                            *captured.borrow_mut() = Some(
                                fuse::PathPlan::root(&mount, fs, names, trailing)
                                    .with_walk(walk)
                                    .at_link(node, parent),
                            );
                            return Ok((accepted, None));
                        }
                        let operation = match operation {
                            Some(
                                ResolveOperation::Fuse(op) | ResolveOperation::ResumeFuse(op, _),
                            ) => op,
                            _ => return Err(Errno(95)),
                        };
                        let mut pending =
                            fuse::Metadata::follow_inode(self, node, walk, parent, operation)?;
                        if let fuse::PathOperation::Open(flags) = operation {
                            // The final target supplies its own access policy.
                            // This plan only carries the original FD reservation.
                            pending.prepare_open(
                                self.open_id(),
                                mount.shared.clone(),
                                mount.root_path(),
                                flags,
                                0,
                                self.credentials.open_identity(),
                            );
                        }
                        let query = self.query.as_ref().ok_or(Errno(95))?;
                        query.prepared.borrow_mut().fuse = Some(Box::new(pending));
                        return query.defer();
                    }
                    if let Content::Symlink(target) = &n.content {
                        if parts.is_empty()
                            && parent_mode & 0o1002 == 0o1002
                            && n.uid != self.credentials.fsuid
                            && n.uid != parent_owner
                            && self.namei_policy.get(sysctl::Protection::Symlinks) != 0
                        {
                            return Err(Errno(13));
                        }
                        let caller_target = self.proc_caller_link(&current)?;
                        let target = caller_target.as_deref().unwrap_or(target);
                        if policy & 4 != 0
                            || current
                                .mount
                                .as_ref()
                                .is_some_and(|m| m.flags.get() & mounts::MS_NOSYMFOLLOW != 0)
                        {
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
                        let absolute = target.starts_with(b"/");
                        let mut expanded: VecDeque<_> = target
                            .split(|&b| b == b'/')
                            .filter(|p| !p.is_empty())
                            .map(|p| p.to_vec())
                            .collect();
                        if target.ends_with(b"/") {
                            expanded.push_back(b".".to_vec());
                        }
                        let mount = current.mount.as_deref().map(|m| &**m);
                        mounts::link_accessed(&node, n, mount);
                        current = if absolute { root.clone() } else { parent };
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
        if climbed && sequence != Some(self.path_sequence()) {
            return Err(Errno(11));
        }
        if matches!(
            operation,
            Some(
                ResolveOperation::Fuse(fuse::PathOperation::ResolveDirectory)
                    | ResolveOperation::ResumeFuse(fuse::PathOperation::ResolveDirectory, _)
            )
        ) {
            let node = self.node(&current)?;
            if !matches!(node.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            let directory = current
                .mount
                .as_ref()
                .map(|mount| Arc::new(mounts::MountUse::new(mount.identity.clone())));
            let target = ResolvedTarget::Inode(ResolvedInode {
                node,
                label: current.key.clone(),
                mount: current.mount.clone(),
                file: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_file: None,
                _image: None,
                _directory: directory,
            });
            return Ok((current, Some(target)));
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
        let (dest, fuse) = self.capture_fuse_path(dirfd, path, false)?;
        if let Some(plan) = fuse {
            return self.defer_fuse_namespace(
                plan,
                fuse::NamespaceAction::Symlink(target.to_vec()),
                None,
                landlock::MAKE_SYM,
            );
        }
        self.symlink_resolved(dest, target, path.ends_with(b"/"))
    }
    fn symlink_resolved(
        &mut self,
        dest: ResolvedPath,
        target: &[u8],
        trailing: bool,
    ) -> Result<()> {
        match self.node(&dest) {
            Ok(_) => return Err(Errno(17)),
            Err(Errno(2)) if !trailing => {}
            Err(error) => return Err(error),
        }
        self.check_parent_write(&dest)?;
        self.insert_entry(dest, Content::Symlink(target.to_vec()), 0o120777, true)
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
            crate::output_resources::OutputScope::retain(|| {
                let open = description.borrow();
                (
                    open.node.clone(),
                    open.mount.clone(),
                    open.mount
                        .as_ref()
                        .map(|mount| mounts::MountUse::new(mount.identity.clone())),
                )
            });
            if let Some(path) = self.proc_description_path(&description.borrow()) {
                self.begin_proc_query();
                self.refresh_proc_source(&path)?;
                self.check_proc_inspection(&path, true)?;
                if let Some(target) = self.proc_directory_readlink(&path)? {
                    return Ok(target);
                }
                if let Some(target) = self.proc_caller_link(&path)? {
                    return Ok(target);
                }
            }
            self.refresh_pseudo_fd(dirfd as u32)?;
            let open = description.borrow();
            let node = open
                .node
                .clone()
                .or_else(|| match &open.control {
                    Some(events::SharedControl::FuseFile(file)) => file.inode(),
                    _ => None,
                })
                .ok_or(Errno(2))?;
            return self.symlink_text(&node, open.mount.as_deref(), Errno(2));
        }
        let (dest, _) = self.resolve_entry_operation(
            dirfd,
            path,
            false,
            false,
            0,
            false,
            Some(ResolveOperation::Fuse(fuse::PathOperation::Readlink)),
            None,
        )?;
        self.readlink_resolved(&dest)
    }
    fn readlink_resolved(&self, dest: &ResolvedPath) -> Result<Vec<u8>> {
        crate::output_resources::OutputScope::path(dest);
        self.check_proc_inspection(dest, true)?;
        if let Some(target) = self.proc_directory_readlink(dest)? {
            return Ok(target);
        }
        if let Some(target) = self.proc_caller_link(dest)? {
            return Ok(target);
        }
        let node = self.node(dest)?;
        crate::output_resources::OutputScope::retain(|| node.clone());
        self.symlink_text(&node, dest.mount.as_deref().map(|m| &**m), Errno(22))
    }
    fn symlink_text(
        &self,
        node: &NodeRef,
        mount: Option<&mounts::MountData>,
        invalid: Errno,
    ) -> Result<Vec<u8>> {
        if node.borrow().mode & 0o170000 == 0o120000 && node.fuse_leaf.get().is_some() {
            let mount = mount.ok_or(Errno(5))?;
            let fs = mount.fs.fuse.as_ref().ok_or(Errno(5))?;
            let query = self.query.as_ref().ok_or(Errno(95))?;
            let pending = fuse::Metadata::readlink_inode(self, mount, fs, node.clone())?;
            query.prepared.borrow_mut().fuse = Some(Box::new(pending));
            return query.defer();
        }
        let n = node.borrow();
        let Content::Symlink(target) = &n.content else {
            return Err(invalid);
        };
        let text = target.clone();
        mounts::link_accessed(node, n, mount);
        Ok(text)
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
        // Staged bytes already own their original quota reservation.
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
        let fs = self.fs.borrow();
        let live = fs.inodes.iter().filter(|n| n.strong_count() != 0).count();
        if live
            .checked_add(parents.len() + 1)
            .is_none_or(|n| n > fs.limits.nodes)
            || fs.paths.len().saturating_add(parents.len() + 1) > fs.limits.nodes
        {
            return Err(Errno(28));
        }
        Ok((current, parents))
    }
    /// Explicit embedding API: install an executable/hard link, without duplicating file data.
    pub fn import_alias(&mut self, existing: &[u8], alias: &[u8], executable: bool) -> Result<()> {
        let source = self.resolve_final(AT_FDCWD, existing, false)?;
        let dest = self.resolve_final(AT_FDCWD, alias, false)?;
        self.link_resolved(&source, &dest, None, Some(executable))
    }
    fn link_resolved(
        &mut self,
        source: &ResolvedPath,
        dest: &ResolvedPath,
        retained: Option<&NodeRef>,
        import_executable: Option<bool>,
    ) -> Result<()> {
        if source.mount.as_ref().map(|m| m.id) != dest.mount.as_ref().map(|m| m.id) {
            return Err(Errno(18));
        }
        let filesystem = dest.filesystem(self);
        let _namespace = filesystem.namespace.lock().unwrap();
        let source = self.rebase_indexed(source.clone())?;
        let dest = self.rebase_indexed(dest.clone())?;
        let source = &source;
        let dest = &dest;
        let source_path = source;
        #[cfg(all(feature = "hostfs", unix))]
        let host_source = source.clone();
        let source = self.node(source)?;
        if retained.is_some_and(|node| !Arc::ptr_eq(node, &source)) {
            return Err(Errno(2));
        }
        if self.node(dest).is_ok() {
            return Err(Errno(17));
        }
        if import_executable.is_none() {
            dest.writable()?;
            self.check_link_source(&source.borrow())?;
            self.check_parent_write(dest)?;
            if self.credentials.landlock.fs_mask() != 0 {
                let mode = source.borrow().mode;
                self.landlock_check_parent(dest, None, landlock::make(mode))?;
                self.landlock_reparent(&source_path.parent(), &dest.parent(), &source)?;
            }
        }
        let executable = import_executable == Some(true);
        // Synthesized endpoints have a separate inode allocation/lifetime and
        // cannot be inserted into the persistent filesystem's inode table.
        {
            let n = source.borrow();
            if n.volatile
                || !matches!(
                    n.content,
                    Content::File(_)
                        | Content::Symlink(_)
                        | Content::Null
                        | Content::Terminal
                        | Content::Device(_)
                        | Content::Fifo(_)
                        | Content::Socket(_)
                )
            {
                return Err(Errno(1));
            }
            if import_executable.is_none() && n.links == 0 {
                return Err(Errno(2));
            }
        }
        {
            let fs = filesystem.borrow();
            if fs.paths.len() >= fs.limits.nodes {
                return Err(Errno(28));
            }
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            host.link(&filesystem, &host_source, dest)?;
        }
        let parent = filesystem.borrow().paths.get(&dest.parent().key).cloned();
        let parent_times = directory::EntryTimes::lock(parent.as_deref(), None);
        let now = storage::Timestamp::now();
        let source_metadata = source.metadata.lock().unwrap();
        let (old_mode, old_ctime) = {
            let mut n = source.borrow_mut();
            let old = (n.mode, n.times[2]);
            n.links += 1;
            n.times[2] = now;
            if executable {
                n.mode |= 0o111;
            }
            old
        };
        let mut fs = filesystem.borrow_mut();
        fs.paths.insert(dest.key.clone(), source.clone());
        if let Err(e) = parent_times.commit(now, || fs.checkpoint()) {
            fs.paths.remove(&dest.key);
            let mut n = source.borrow_mut();
            n.links -= 1;
            if executable {
                n.mode = old_mode;
            }
            if n.times[2] == now {
                n.times[2] = old_ctime;
            }
            return Err(e);
        }
        drop(fs);
        drop(source_metadata);
        drop(parent_times);
        self.notification_link(dest, &source, true);
        source
            .borrow()
            .notifications
            .send(inotify::ATTRIB, 0, b"", false);
        self.notification_entry(dest, inotify::CREATE, 0, false);
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
        let (p, fuse) = self.capture_fuse_path(dirfd, path, false)?;
        if let Some(plan) = fuse {
            return self.defer_fuse_namespace(
                plan,
                fuse::NamespaceAction::Mkdir { mode },
                None,
                landlock::MAKE_DIR,
            );
        }
        self.mkdir_resolved(p, mode)
    }
    fn mkdir_resolved(&mut self, p: ResolvedPath, mode: u32) -> Result<()> {
        if self.node(&p).is_ok() {
            return Err(Errno(17));
        }
        if Self::cgroup_mount(&p) {
            self.landlock_check_parent(&p, None, landlock::MAKE_DIR)?;
            return self.cgroup_mkdir(&p, mode);
        }
        self.check_parent_write(&p)?;
        self.insert_entry(p, Content::Directory, 0o40000 | (mode & 0o7777), true)
    }
    pub fn mknod_at(&mut self, dirfd: i32, path: &[u8], mode: u32, device: u64) -> Result<()> {
        let type_ = mode & 0o170000;
        if type_ == 0o040000 {
            return Err(Errno(1));
        }
        if !matches!(type_, 0 | 0o100000 | 0o10000 | 0o20000 | 0o60000 | 0o140000) {
            return Err(Errno(22));
        }
        let (p, fuse) = self.capture_fuse_path(dirfd, path, false)?;
        if let Some(plan) = fuse {
            if matches!(type_, 0o20000 | 0o60000) {
                if !self.credentials.has_cap(capabilities::MKNOD) {
                    return Err(Errno(1));
                }
                self.cgroup_device(type_, device as u32 as u64, 1)?;
            }
            let mode = (if type_ == 0 { 0o100000 } else { type_ }) | (mode & 0o7777);
            return self.defer_fuse_namespace(
                plan,
                fuse::NamespaceAction::Mknod {
                    mode,
                    device: device as u32,
                },
                None,
                landlock::make(mode),
            );
        }
        self.mknod_resolved(p, mode, device, path.ends_with(b"/"))
    }
    fn mknod_resolved(
        &mut self,
        p: ResolvedPath,
        mode: u32,
        device: u64,
        trailing: bool,
    ) -> Result<()> {
        let type_ = mode & 0o170000;
        match self.node(&p) {
            Ok(_) => return Err(Errno(17)),
            Err(Errno(2)) if trailing => return Err(Errno(2)),
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
            0o140000 => Content::Socket(ipc::PathBinding::default()),
            0o10000 => Content::Fifo(Pipe::new(self.open_id())),
            _ => Content::File(self.empty_data_at(&p)?),
        };
        let type_ = if type_ == 0 { 0o100000 } else { type_ };
        self.insert_entry(p, content, type_ | (mode & 0o7777), true)
    }
    pub fn unlink_at(&mut self, dirfd: i32, path: &[u8], directory: bool) -> Result<()> {
        let (p, fuse) = self.capture_fuse_path(dirfd, path, false)?;
        if directory {
            match path.rsplit(|&b| b == b'/').find(|part| !part.is_empty()) {
                Some(b".") => return Err(Errno(22)),
                Some(b"..") => return Err(Errno(39)),
                _ => {}
            }
        }
        if let Some(plan) = fuse {
            return self.defer_fuse_namespace(
                plan,
                fuse::NamespaceAction::Unlink { directory },
                None,
                if directory {
                    landlock::REMOVE_DIR
                } else {
                    landlock::REMOVE_FILE
                },
            );
        }
        self.unlink_resolved(p, directory, path.ends_with(b"/"))
    }
    fn unlink_resolved(&mut self, p: ResolvedPath, directory: bool, trailing: bool) -> Result<()> {
        let filesystem = p.filesystem(self);
        let _namespace = filesystem.namespace.lock().unwrap();
        let p = self.rebase_indexed(p)?;
        if self.is_mount_root(&p) {
            return Err(Errno(16));
        }
        let node = self.node(&p)?;
        if trailing && !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let parent = self.check_remove(&p)?;
        let (is_dir, is_queue) = match node.borrow().content {
            Content::Directory => (true, false),
            Content::MessageQueue(_) => (false, true),
            _ => (false, false),
        };
        if directory != is_dir {
            return Err(Errno(if is_dir { 21 } else { 20 }));
        }
        if !is_queue {
            self.landlock_check_parent(
                &p,
                Some(&parent),
                if is_dir {
                    landlock::REMOVE_DIR
                } else {
                    landlock::REMOVE_FILE
                },
            )?;
        }
        if Self::cgroup_mount(&p) {
            return if directory {
                self.cgroup_rmdir(&p)
            } else {
                Err(Errno(1))
            };
        }
        if is_queue {
            p.writable()?;
            if !self.allowed(&self.node(&p.parent())?.borrow(), 3) {
                return Err(Errno(13));
            }
        } else {
            self.check_parent_write(&p)?;
        }
        let filesystem = p.filesystem(self);
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            host.unlink(&filesystem, &p, directory)?;
            let mut fs = filesystem.borrow_mut();
            fs.paths.remove(&p.key);
            if is_dir {
                let _ = node.removed_directory_parent.set(parent.clone());
                let mut prefix = p.key.clone();
                prefix.push(b'/');
                let stale: Vec<_> = fs
                    .paths
                    .range(prefix.clone()..)
                    .take_while(|(key, _)| key.starts_with(&prefix))
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in stale {
                    fs.paths.remove(&key);
                }
            }
            drop(fs);
            let links = if is_dir {
                0
            } else {
                node.borrow().links.saturating_sub(1)
            };
            node.borrow_mut().links = links;
            self.notification_entry(&p, inotify::DELETE, 0, is_dir);
            self.notification_link(&p, &node, false);
            return Ok(());
        }
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
        let parent_times = directory::EntryTimes::lock(Some(&parent), None);
        let now = storage::Timestamp::now();
        let node_metadata = node.metadata.lock().unwrap();
        let old_ctime = {
            let mut n = node.borrow_mut();
            n.links -= 1;
            std::mem::replace(&mut n.times[2], now)
        };
        let mut fs = filesystem.borrow_mut();
        fs.paths.remove(&p.key);
        if let Err(e) = parent_times.commit(now, || fs.checkpoint()) {
            let mut n = node.borrow_mut();
            n.links += 1;
            if n.times[2] == now {
                n.times[2] = old_ctime;
            }
            drop(n);
            fs.paths.insert(p.key.clone(), node.clone());
            return Err(e);
        }
        if is_dir {
            let _ = node.removed_directory_parent.set(parent.clone());
        }
        drop(fs);
        drop(node_metadata);
        drop(parent_times);
        self.notification_link(&p, &node, false);
        if !is_dir {
            let mut n = node.borrow_mut();
            n.notifications.send(inotify::ATTRIB, 0, b"", false);
            if n.links == 0 {
                if let Content::File(data) = &mut n.content {
                    data.orphan(true);
                }
            }
        }
        // Release the namespace operation's own reference before the parent
        // event. An open descriptor may still defer DELETE_SELF until close.
        drop(node);
        self.notification_entry(&p, inotify::DELETE, 0, is_dir);
        Ok(())
    }
    fn available(&self, min: u32) -> Result<u32> {
        self.fds.available(min).ok_or(Errno(24))
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
        self.open_at_resolve_published::<false>(dirfd, path, flags, mode, policy, None)
    }
    fn open_at_resolve_published<const PATH_TRUNCATE: bool>(
        &mut self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
        mode: u32,
        policy: u64,
        publication: Option<&DirectFiles>,
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
            | O_DIRECT
            | O_DIRECTORY
            | O_NOFOLLOW
            | O_LARGEFILE
            | O_NOATIME
            | O_CLOEXEC
            | O_PATH
            | 0x101000;
        let flags = if flags & O_PATH != 0 {
            flags & (O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        } else {
            flags
        };
        if flags & !ALLOWED != 0 || flags & (O_CREAT | O_DIRECTORY) == (O_CREAT | O_DIRECTORY) {
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
            self.resolve_entry_policy(dirfd, plain, true, false, policy, false)?;
            return Err(Errno(21));
        }
        let membership = self
            .query
            .as_ref()
            .map_or_else(|| self.shared_files(), |q| q.files.clone());
        let reservation = membership.reserve()?;
        let resolved = self.resolve_entry_operation(
            dirfd,
            path,
            flags & O_NOFOLLOW == 0 && flags & 0xc0 != 0xc0,
            true,
            policy,
            true,
            (!PATH_TRUNCATE).then_some(ResolveOperation::Fuse(fuse::PathOperation::Open(flags))),
            None,
        );
        let entry = match resolved {
            Ok(entry) => entry,
            Err(e) => {
                if let Some(q) = &self.query {
                    if let Some(work) = q.prepared.borrow_mut().fuse.as_mut() {
                        work.reserve_open(
                            reservation,
                            mode,
                            self.umask_capability(),
                            publication.cloned(),
                        );
                    }
                }
                return Err(e);
            }
        };
        self.open_resolved::<PATH_TRUNCATE>(entry, flags, mode, publication, reservation)
    }
    fn open_resolved<const PATH_TRUNCATE: bool>(
        &mut self,
        entry: ResolvedEntry,
        flags: u32,
        mode: u32,
        publication: Option<&DirectFiles>,
        reservation: fd_table::ReservedFd,
    ) -> Result<u32> {
        let (mut p, target) = entry;
        let magic = match target {
            Some(ResolvedTarget::Inode(file)) => Some(file),
            Some(ResolvedTarget::Descriptor(open)) => {
                let original = open.borrow();
                if let Some(events::SharedControl::FuseFile(file)) = &original.control {
                    if original.node.is_none() {
                        let file = file.clone();
                        let path = if let FdKind::Node(path) = &original.kind {
                            path.clone()
                        } else {
                            Vec::new()
                        };
                        drop(original);
                        return self.reopen_fuse_file(
                            file,
                            path,
                            flags,
                            mode,
                            publication,
                            reservation,
                        );
                    }
                }
                if original.node.is_none() || original.namespace_resource.is_some() {
                    drop(original);
                    return self.reopen_proc_description(open, flags, publication, reservation);
                }
                drop(original);
                Some(self.proc_open_node(&open, &p)?)
            }
            None => None,
        };
        let forced_node = if let Some(file) = &magic {
            // Reopen the original inode through the ordinary open algorithm.
            // The accepted resource stays alive until this fresh OFD is ready.
            p = self
                .location(&file.node, &file.mount)
                .unwrap_or(ResolvedPath {
                    key: file.label.clone(),
                    directory_inode: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                    proc_binding: file
                        .node
                        .proc_node
                        .get()
                        .and_then(|proc| proc.binding.clone()),
                    mount: file.mount.clone(),
                });
            Some(file.node.clone())
        } else {
            None
        };
        if flags & O_PATH == 0 {
            self.check_proc_inspection(&p, false)?;
        }
        let original = magic.as_ref().and_then(|m| m.file.as_ref());
        let oom = original
            .and_then(|o| o.oom.clone())
            .or_else(|| self.oom_for_path(&p));
        let network_control = original
            .and_then(|o| o.sysctl_control.as_ref())
            .map(|control| control.reopen(&self.credentials))
            .or_else(|| self.sysctl_control(&p));
        let mount_file = (flags & O_PATH == 0)
            .then(|| self.proc_mount_file(&p))
            .flatten();
        let proc_mem = proc_file::memory_path(&p) && self.uses_pseudo(&p);
        let check_write = |node: Option<&NodeRef>| -> Result<()> {
            if flags & O_PATH == 0 && (flags & 3 != 0 || flags & 0x200 != 0) {
                if let Some(mount) = &p.mount {
                    mount.writable_data(node)?;
                }
                if let Some(
                    control @ (sysctl::Control::UserNamespaces(..)
                    | sysctl::Control::UtsName(..)
                    | sysctl::Control::Namei(..)
                    | sysctl::Control::OverflowId(..)),
                ) = &network_control
                {
                    if !control.authorized(&self.credentials, self.lock_owner) {
                        return Err(Errno(13));
                    }
                }
            }
            if oom.is_none()
                && network_control.is_none()
                && self.uses_pseudo(&p)
                && self.pseudo_readonly(&p)
                && !proc_mem
                && !node.is_some_and(|n| n.seq_file)
                && (flags & 3 != 0
                    || flags & O_TRUNC != 0
                    || flags & O_CREAT != 0 && !self.proc_directory_tree(&p))
            {
                return Err(Errno(30));
            }
            Ok(())
        };
        if let Some((mount, fs)) = p
            .mount
            .as_ref()
            .filter(|_| flags & O_PATH == 0)
            .and_then(|m| m.fs.fuse.as_ref().map(|fs| (m, fs)))
        {
            if PATH_TRUNCATE {
                return Err(Errno(21));
            }
            let query = self.query.as_ref().ok_or(Errno(95))?;
            let inode = self.node(&p)?;
            let denied = if flags & O_PATH == 0 {
                self.landlock_denied(
                    &p,
                    Some(&inode),
                    landlock::READ_DIR
                        | landlock::READ_FILE
                        | landlock::WRITE_FILE
                        | landlock::TRUNCATE,
                )?
            } else {
                0
            };
            let sticky_parent = if flags & O_CREAT != 0 && !inode.directory && magic.is_none() {
                let parent = self.parent_location(&p)?;
                if parent
                    .filesystem(self)
                    .fuse
                    .as_ref()
                    .is_none_or(|fs| fs.local_permissions())
                {
                    Some(self.node(&parent)?)
                } else {
                    None
                }
            } else {
                None
            };
            let mut pending = fuse::Metadata::open_inode(self, mount, fs, flags, inode)?;
            pending.prepare_open(
                self.open_id(),
                mount.shared.clone(),
                p.key.clone(),
                flags,
                denied,
                self.credentials.open_identity(),
            );
            if let Some(parent) = sticky_parent {
                pending.retain_open_parent(parent);
            }
            pending.reserve_open(
                reservation,
                mode,
                self.umask_capability(),
                publication.cloned(),
            );
            query.prepared.borrow_mut().fuse = Some(Box::new(pending));
            return query.defer();
        }
        let mut runtime_file = None;
        let mut existed = match forced_node.clone().map_or_else(|| self.node(&p), Ok) {
            Ok(node) => {
                if flags & 0xc0 == 0xc0 {
                    return Err(Errno(17));
                }
                if flags & (3 | O_CREAT | O_TRUNC) != 0
                    && matches!(node.borrow().content, Content::Directory)
                {
                    return Err(Errno(21));
                }
                check_write(Some(&node))?;
                let proc_regular = {
                    let n = node.borrow();
                    n.volatile && matches!(n.content, Content::File(_))
                };
                if flags & O_PATH == 0
                    && (flags & 3 == 0 || node.seq_file || proc_mem)
                    && oom.is_none()
                    && network_control.is_none()
                    && mount_file.is_none()
                    && proc_regular
                {
                    runtime_file = self.proc_runtime_file(&p);
                    if proc_mem {
                        let file = runtime_file.as_ref().ok_or(Errno(3))?;
                        file.check_memory_open(&self.credentials, self.lock_owner)?;
                    }
                }
                if let Some(query) = &self.query {
                    let n = node.borrow();
                    // O_NOFOLLOW errors need no owner-only file capability.
                    // Decide before classifying whether a data open is shared.
                    if flags & O_PATH == 0 && matches!(n.content, Content::Symlink(_)) {
                        return Err(Errno(if flags & O_DIRECTORY != 0 { 20 } else { 40 }));
                    }
                    let pty = (self.terminal_task.get().is_some()
                        || p.mount
                            .as_ref()
                            .is_some_and(|m| m.devpts.is_some() && m.shared_resources().is_some()))
                        && flags & O_PATH == 0
                        && match n.content {
                            Content::Device(pseudo::Device::Ptmx) => true,
                            Content::Device(pseudo::Device::Pts(_, _)) => {
                                flags & 0x100 != 0 || self.terminal_task.get().is_some()
                            }
                            _ => false,
                        };
                    let controlling_tty = matches!(n.content, Content::Terminal)
                        && self.terminal_task.get().is_some();
                    if !query.original
                        && !pty
                        && !controlling_tty
                        && !matches!(n.content, Content::Fifo(_) | Content::MessageQueue(_))
                        && node.simple_device.is_none()
                        && !matches!(n.content, Content::Device(device) if device.source_open())
                        && !(matches!(n.content, Content::Directory)
                            && matches!(p.as_ref(), b"/dev/dri" | b"/dev/block"))
                        && oom.is_none()
                        && network_control.is_none()
                        && mount_file.is_none()
                        && runtime_file.is_none()
                        && !(Self::cgroup_mount(&p)
                            && matches!(n.content, Content::Directory | Content::File(_)))
                        && !(node.proc_node.get().is_some()
                            && (flags & O_PATH != 0 || matches!(n.content, Content::Directory)))
                        && (n.volatile
                            || n.seals.is_some() && magic.as_ref().is_none_or(|m| m.file.is_none())
                            || !matches!(n.content, Content::File(_) | Content::Directory))
                    {
                        return query.defer();
                    }
                }
                true
            }
            Err(Errno(2)) => false,
            Err(e) => return Err(e),
        };
        #[cfg(all(feature = "hostfs", unix))]
        let mut created_host_file = None;
        if !existed {
            if flags & O_CREAT == 0 || flags & O_DIRECTORY != 0 || self.proc_directory_tree(&p) {
                return Err(Errno(2));
            }
            check_write(None)?;
            self.check_parent_write(&p)?;
            #[cfg(all(feature = "hostfs", unix))]
            let native_created = if let Some(host) = &p.filesystem(self).host {
                let filesystem = p.filesystem(self);
                let _namespace = filesystem.namespace.lock().unwrap();
                self.landlock_check_parent(&p, None, landlock::MAKE_REG)?;
                match host.create_open(&filesystem, &p, flags, mode & !self.umask()) {
                    Ok((node, lease)) => {
                        self.notification_link(&p, &node, true);
                        self.notification_entry(&p, inotify::CREATE, 0, false);
                        created_host_file = Some(lease);
                    }
                    Err(Errno(17)) if flags & 0x80 == 0 => existed = true,
                    Err(e) => return Err(e),
                }
                true
            } else {
                false
            };
            #[cfg(not(all(feature = "hostfs", unix)))]
            let native_created = false;
            if !native_created {
                match self.insert_entry(
                    p.clone(),
                    Content::File(self.empty_data_at(&p)?),
                    0o100000 | (mode & 0o7777),
                    true,
                ) {
                    Err(Errno(17)) if flags & 0x80 == 0 => existed = true,
                    result => result?,
                }
            }
        }
        let node = forced_node.map_or_else(|| self.node(&p), Ok)?;
        let landlock_denied = if self.credentials.landlock.fs_mask() == 0 {
            0
        } else {
            let retained = magic
                .as_ref()
                .and_then(|file| self.landlock_retained_path(file));
            let path = if magic.is_some() {
                retained.as_ref()
            } else {
                Some(&p)
            };
            self.landlock_open::<PATH_TRUNCATE>(path, &node, flags)?
        };
        if existed && flags & O_CREAT != 0 {
            self.check_sticky_create(&p, &node)?;
        }
        {
            let n = node.borrow();
            self.check_device_open(&n, flags)?;
            if flags & O_NOATIME != 0
                && self.credentials.fsuid != n.uid
                && !self
                    .credentials
                    .inode_cap(capabilities::FOWNER, n.uid, n.gid)
            {
                return Err(Errno(1));
            }
            if matches!(n.content, Content::Symlink(_)) && flags & O_PATH == 0 {
                return Err(Errno(if flags & O_DIRECTORY != 0 { 20 } else { 40 }));
            }
            if matches!(n.content, Content::Directory) && flags & (3 | O_CREAT | O_TRUNC) != 0 {
                return Err(Errno(21));
            }
            if matches!(n.content, Content::Directory)
                && flags & O_DIRECT != 0
                && flags & O_PATH == 0
            {
                return Err(Errno(22));
            }
            if flags & O_DIRECTORY != 0 && !matches!(n.content, Content::Directory) {
                return Err(Errno(20));
            }
            if existed
                && flags & O_PATH == 0
                && !network_control
                    .as_ref()
                    .is_some_and(|control| control.authorized(&self.credentials, self.lock_owner))
                && ((flags & 3 != 1 && !self.allowed(&n, 4))
                    || ((flags & 3 != 0 || flags & 0x200 != 0) && !self.allowed(&n, 2)))
            {
                return Err(Errno(13));
            }
            if matches!(n.content, Content::Socket(_)) && flags & O_PATH == 0 {
                return Err(Errno(6));
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
        let mut write_access = if node.regular_file && (fd_can_write(flags) || flags & O_TRUNC != 0)
        {
            Some(executable::WriteAccess::acquire(&node)?)
        } else {
            None
        };
        if fd_can_write(flags) || flags & O_TRUNC != 0 {
            self.overlay_prepare(&p, &node, flags & 0x200 != 0)?;
        }
        let disk_file = if flags & O_PATH == 0 {
            match &node.borrow().content {
                Content::File(data) => {
                    data.private_lease(fd_can_write(flags) || flags & O_TRUNC != 0)?
                }
                _ => None,
            }
        } else {
            None
        };
        #[cfg(all(feature = "hostfs", unix))]
        let host_file = match created_host_file {
            Some(file) => Some(file),
            None => p
                .filesystem(self)
                .host
                .as_ref()
                .map(|host| host.lease_path(&p.filesystem(self), &p, &node, flags))
                .transpose()?
                .flatten(),
        };
        let truncate = existed
            && flags & 0x200 != 0
            && !node.seq_file
            && !proc_mem
            && !Self::cgroup_mount(&p)
            && oom.is_none()
            && network_control.is_none();
        if self.query.is_none() {
            if truncate {
                let mut n = node.borrow_mut();
                if let Content::File(b) = &mut n.content {
                    b.truncate(0)?;
                    n.times[1] = storage::Timestamp::now();
                    n.times[2] = n.times[1];
                }
            }
            if truncate {
                self.checkpoint()?;
                if matches!(node.borrow().content, Content::File(_)) {
                    inotify::notify(&node, inotify::MODIFY, None);
                }
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
        let bridge = if flags & O_PATH == 0 {
            if let Content::Device(pseudo::Device::Bridge(channel)) = node.borrow().content {
                Some(
                    self.bridge
                        .as_ref()
                        .ok_or(Errno(19))?
                        .connect_channel(channel)
                        .map_err(Errno)?,
                )
            } else {
                None
            }
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
                Content::Device(pseudo::Device::Pts(id, _)) => {
                    let pair = self.pty_by_id(id).ok_or(Errno(5))?;
                    if pair.locked.load(std::sync::atomic::Ordering::Relaxed)
                        || !pair.master_alive.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        return Err(Errno(5));
                    }
                    Some(PtyEnd::new(pair, false))
                }
                Content::Terminal => match self.controlling_terminal() {
                    None => return Err(Errno(6)),
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
        let flags = if flags & O_PATH == 0 {
            flags | 0x20000
        } else {
            flags
        }; // ARM64 openat forces O_LARGEFILE except for O_PATH.
        let notification = if flags & O_PATH != 0 {
            None
        } else {
            let link = match original {
                Some(open) => open
                    .notification
                    .as_ref()
                    .and_then(|lease| lease.link.clone()),
                None => self.event_link(&p, &node),
            };
            Some(FileClose::open::<PATH_TRUNCATE>(&node, flags, link))
        };
        let read_node = if flags & O_PATH == 0 && flags & 3 == 0 {
            match &node.borrow().content {
                Content::File(storage::FileData::Lower(source)) => Some(source.clone()),
                _ => None,
            }
        } else {
            None
        };
        let binder_control = if flags & O_PATH == 0 {
            match node.borrow().content {
                Content::MessageQueue(ref q) => {
                    Some(events::SharedControl::MessageQueue(q.clone()))
                }
                Content::Device(pseudo::Device::Fuse) => Some(events::SharedControl::Fuse(
                    fuse::Device::new(self.credentials.user_namespace.clone()),
                )),
                Content::Device(pseudo::Device::Tun) => Some(events::SharedControl::Tun(
                    self.network.open_tun(),
                    self.root_network.user_namespace.clone(),
                )),
                Content::Device(pseudo::Device::Binder(device)) => {
                    Some(events::SharedControl::Binder(self.binder.open(
                        device as usize,
                        self.lock_owner,
                        self.credentials.euid,
                    )))
                }
                Content::Device(pseudo::Device::SwSync) => {
                    Some(events::SharedControl::Sync(sync_file::File::timeline(
                        self.pseudo
                            .borrow()
                            .runtime
                            .monotonic_origin
                            .unwrap_or_else(std::time::Instant::now),
                    )))
                }
                _ => None,
            }
        } else {
            None
        };
        let cgroup_control = self
            .cgroup_file(&p, &node)?
            .map(events::SharedControl::Cgroup);
        let automatic_terminal = pty
            .as_ref()
            .filter(|end| !end.master && flags & 0x100 == 0)
            .cloned();
        let descriptor = Descriptor {
            open: OpenHandle::new(OpenDescription {
                shared: Arc::new(SharedOpenDescription {
                    _write_access: if fd_can_write(flags) {
                        write_access.take()
                    } else {
                        None
                    },
                    console: Default::default(),
                    oom,
                    sysctl_control: network_control,
                    mount_file,
                    runtime_file,
                    socket: None,
                    _disk_file: disk_file,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_file,
                    native_image: None,
                    mount_resource: std::sync::OnceLock::new(),
                    mount_use: Default::default(),
                    directory_mount: Default::default(),
                    namespace_resource: None,
                    landlock_denied,
                    link_credentials: Some(self.credentials.open_identity()),
                    file_authority: Default::default(),
                    tcp_publication: Default::default(),
                    socket_control: None,
                    control: binder_control.or(cgroup_control),
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
                    flags: (flags & !(O_CLOEXEC | OPEN_ONLY_FLAGS)).into(),
                    file_position: Arc::default(),
                    flock: std::sync::OnceLock::new(),
                    ofd_records: Default::default(),
                    node: Some(node),
                    pipe,
                    pty,
                    local: None,
                    bridge,
                    kernel_log,
                    notification,
                }),
                mount: p.mount.map(OpenMount::Owner),
                anonymous: None,
                namespace: None,
            }),
            cloexec: (flags & O_CLOEXEC != 0).into(),
        };
        if let Some(query) = &self.query {
            if truncate || PATH_TRUNCATE {
                let OpenHandle::Shared(shared) = &descriptor.open else {
                    return query.defer();
                };
                let file = SharedFd::new(shared.clone());
                let target = if PATH_TRUNCATE {
                    Some(file.filesystem_target())
                } else {
                    file.file_target()
                };
                if let Some(target) = target {
                    query.prepared.borrow_mut().open = Some(file_work::PreparedOpen {
                        _truncate_access: write_access,
                        reservation,
                        target,
                        cloexec: descriptor.cloexec,
                        publication: publication.cloned(),
                    });
                    return query.defer();
                }
            }
        }
        if let Some(files) = publication {
            files.publish_open(self, &descriptor.open.borrow());
        }
        let number = reservation.publish(descriptor, self.query.is_none().then_some(&self.fds))?;
        if let (Some(end), Some(task)) = (automatic_terminal, self.terminal_task()) {
            end.pair.bind_signal_route(task.clone());
            let _ = task.acquire(&end.pair, false, fd_can_read(flags), true);
        }
        Ok(number)
    }
    pub fn close(&mut self, fd: u32) -> Result<()> {
        if let Some(result) = self.fds.membership().close(fd, self.lock_owner) {
            if !self.detached_mounts.borrow().is_empty() {
                self.reap_detached_mounts();
            }

            return result;
        }
        let descriptor = self.fds.close(fd)?;
        self.release_record_locks(&descriptor);
        drop(descriptor);

        self.reap_detached_mounts();
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
        self.reap_detached_mounts();
    }
    pub fn close_range(&mut self, first: u32, last: u32, flags: u32) -> Result<()> {
        // Task namespace transactions detach Files before UNSHARE reaches here.
        self.shared_files()
            .close_range(first, last, flags, self.lock_owner)?;

        self.reap_detached_mounts();
        Ok(())
    }
    pub fn close_all(&mut self) {
        let descriptors = self.fds.drain();
        for d in descriptors.values() {
            self.release_record_locks(d);
        }
        drop(descriptors);

        self.reap_detached_mounts();
    }
    /// Detach a task's view while another task retains the shared file table.
    /// No descriptor has actually closed, so POSIX process locks stay held.
    pub fn detach_file_table(&mut self) {
        let mut empty = DescriptorTable::default();
        empty.share_limit(&self.fds);
        self.fds = empty;
    }
    /// exit/exec drops this task's table reference. Only the final reference
    /// closes entries; no process-table scan or separate files_id is needed.
    pub fn release_descriptors(&mut self) {
        self.fds.retire(self.lock_owner);
        self.collect_retired_descriptors();
    }
    /// Collect owner-local projections after the original FileTableOwner has
    /// retired. Source exits must not re-run descriptor or process-lock release.
    pub fn collect_retired_descriptors(&mut self) {
        self.detach_file_table();

        self.reap_detached_mounts();
    }
    pub fn file_table_owner(&self) -> FileTableOwner {
        self.fds.task_owner()
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
            if !self.detached_mounts.borrow().is_empty() {
                self.reap_detached_mounts();
            }
            return result;
        }
        if let Some(replaced) = self.fds.duplicate_to(old, new, flags)? {
            self.release_record_locks(&replaced);
        }
        self.reap_detached_mounts();
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
        self.check_status_flags(fd, flags)?;
        self.descriptor(fd)?.open.borrow().flags.set(flags)
    }
    pub fn check_status_flags(&self, fd: u32, flags: u32) -> Result<()> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        fd_status::check_status(&open, &self.credentials, flags)
    }
    pub fn set_nonblocking(&self, fd: u32, enabled: bool) -> Result<()> {
        self.descriptor(fd)?
            .open
            .borrow()
            .flags
            .nonblocking(enabled)
    }
    pub fn pipe(&mut self, flags: u32) -> Result<[u32; 2]> {
        self.descriptor_factory().pipe(flags)
    }
    /// Bounded splice through a pipe. Commit pipe consumption only after the
    /// destination accepts bytes; EAGAIN must never lose buffered stream data.
    /// Existing splice descriptor/type prelude, without byte or offset effects.
    pub fn check_splice(
        &self,
        input: u32,
        output: u32,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<()> {
        let source = self.descriptor(input)?.open.clone();
        let dest = self.descriptor(output)?.open.clone();
        Self::splice_pipes(&source, &dest, from, to).map(|_| ())
    }
    #[allow(clippy::type_complexity)] // Original read/write pipe-end capabilities.
    fn splice_pipes(
        source: &OpenHandle,
        dest: &OpenHandle,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<(Option<(Pipe, bool)>, Option<(Pipe, bool)>)> {
        if OpenHandle::ptr_eq(source, dest) {
            return Err(Errno(22));
        }
        let source_pipe = {
            let o = source.borrow();
            if !fd_can_read(o.flags.get()) {
                return Err(Errno(9));
            }
            o.pipe.as_ref().map(|p| (p.pipe.clone(), p.read))
        };
        let dest_pipe = {
            let o = dest.borrow();
            if !fd_can_write(o.flags.get()) {
                return Err(Errno(9));
            }
            if o.flags.get() & 0x400 != 0 {
                return Err(Errno(22));
            }
            o.pipe.as_ref().map(|p| (p.pipe.clone(), p.write))
        };
        for (open, write) in [(source, false), (dest, true)] {
            let o = open.borrow();
            if o.socket.as_ref().is_some_and(|s| {
                s.info().is_some_and(|i| i.kind != 1)
                    && !(write && source_pipe.is_some() && s.is_inet_message())
            }) || o.local.as_ref().is_some_and(|s| s.kind() != 1)
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
        Ok((source_pipe, dest_pipe))
    }
    pub fn tee(&mut self, input: u32, output: u32, count: u64, flags: u32) -> Result<u64> {
        if let Some(result) = StreamTransfer::tee_empty(count, flags) {
            return result;
        }
        let files = self.shared_files();
        let input = files.query_lookup(input).ok_or(Errno(9))??;
        let output = files.query_lookup(output).ok_or(Errno(9))??;
        match StreamTransfer::tee(input, output, count, flags)?.execute(self)? {
            FileValue::Transfer { count, .. } => Ok(count),
            _ => unreachable!("pipe transfer"),
        }
    }
    pub fn splice(
        &mut self,
        input: u32,
        output: u32,
        count: usize,
        from: Option<u64>,
        to: Option<u64>,
    ) -> Result<usize> {
        let files = self.shared_files();
        if let (Some(Ok(source)), Some(Ok(dest))) = (files.lookup(input), files.lookup(output)) {
            if StreamTransfer::admitted(&source, &dest) {
                let mut transfer =
                    StreamTransfer::new(source, dest, Ok(from), Ok(to), count as u64, true, 0);
                return match transfer.execute(self)? {
                    FileValue::Transfer { count, .. } => Ok(count as usize),
                    _ => unreachable!(),
                };
            }
        }
        let source = self.descriptor(input)?.open.clone();
        let dest = self.descriptor(output)?.open.clone();
        let (source_pipe, dest_pipe) = Self::splice_pipes(&source, &dest, from, to)?;
        if count == 0 {
            return Ok(0);
        }
        if let Some((pipe, _)) = source_pipe {
            let (read, bytes) =
                stream_transfer::ReadLease::take(pipe.data.clone(), count.min(PIPE_CAPACITY))?;
            if bytes.is_empty() {
                return Ok(0);
            }
            let n = if let Some((target, _)) = &dest_pipe {
                let mut write =
                    stream_transfer::WriteLease::take(target.data.clone(), bytes.len(), false)?;
                let n = write.count;
                write.commit(&bytes[..n])?
            } else if let Some(offset) = to {
                self.pwrite(output, &bytes, offset)?
            } else {
                self.write(output, &bytes)?
            };
            read.commit(n);
            return Ok(n);
        }
        let (pipe, _) = dest_pipe.unwrap();
        let mut write = stream_transfer::WriteLease::take(
            pipe.data.clone(),
            count,
            source.borrow().is_regular_file(),
        )?;
        let bytes = if let Some(offset) = from {
            self.pread(input, write.count, offset)?
        } else {
            self.read(input, write.count)?
        };
        write.commit(&bytes)
    }
    pub fn tun_file(&self, fd: u32) -> Result<Option<TunOperation>> {
        let d = self.descriptor(fd)?;
        let o = d.open.borrow();
        if o.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        Ok(match &o.control {
            Some(events::SharedControl::Tun(file, namespace)) => Some(TunOperation {
                file: file.clone(),
                namespace: namespace.clone(),
            }),
            _ => None,
        })
    }
    pub fn read(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        self.refresh_pseudo_fd(fd)?;
        let descriptor = self.descriptor(fd)?;
        self.read_description(&descriptor, count)
    }
    fn read_description(&mut self, descriptor: &Descriptor, count: usize) -> Result<Vec<u8>> {
        let mut o = descriptor.open.borrow_mut();
        if let Some(kind) = o.node.as_ref().and_then(|n| n.simple_device) {
            return o.simple_read(kind, count);
        }
        if !fd_can_read(o.flags.get()) {
            return Err(Errno(9));
        }
        if let Some(events::SharedControl::MessageQueue(q)) = &o.control {
            return Ok(q.read(&o.file_position, count));
        }
        if let Some(events::SharedControl::Fuse(file)) = &o.control {
            let file = file.clone();
            drop(o);
            return file.connection()?.read(count);
        }
        if let Some(events::SharedControl::Tun(file, _)) = &o.control {
            let file = file.clone();
            drop(o);
            return file.read(count).map_err(|e| Errno(e.0));
        }
        if let Some(file) = &o.mount_file {
            let mut position = o.file_position.lock().unwrap();
            if position.pending != 0 {
                return Err(Errno(11));
            }
            let bytes = file.read(position.value, count, &self.cgroup_namespace.path);
            position.value += bytes.len() as u64;
            drop(position);
            o.notify_read(&bytes);
            return Ok(bytes);
        }
        if let Some(file) = &o.runtime_file {
            let mut position = o.file_position.lock().unwrap();
            if position.pending != 0 {
                return Err(Errno(11));
            }
            let bytes = file.read(position.value, count, self)?;
            position.value += bytes.len() as u64;
            drop(position);
            o.notify_read(&bytes);
            return Ok(bytes);
        }
        if let Some(control) = &o.sysctl_control {
            let mut position = o.file_position.lock().unwrap();
            if position.pending != 0 {
                return Err(Errno(11));
            }
            let data = control.read(position.value, count, self)?;
            position.value += data.len() as u64;
            drop(position);
            o.notify_read(&data);
            return Ok(data);
        }
        if o.oom.is_some() {
            let mut position = o.file_position.lock().unwrap();
            if position.pending != 0 {
                return Err(Errno(11));
            }
            if let Some(data) = Self::oom_read(&o, position.value, count)? {
                position.value += data.len() as u64;
                drop(position);
                o.notify_read(&data);
                return Ok(data);
            }
        }
        if let Some(events::SharedControl::Cgroup(file)) = &o.control {
            let mut position = o.file_position.lock().unwrap();
            if position.pending != 0 {
                return Err(Errno(11));
            }
            let data = file
                .cgroup_read(&self.cgroup_access(), position.value, count)?
                .ok_or(Errno(19))?;
            position.value += data.len() as u64;
            drop(position);
            o.notify_read(&data);
            return Ok(data);
        }
        if let Some(log) = &o.kernel_log {
            return log.read(count);
        }
        if let Some(local) = &o.local {
            return self
                .local_view(local.clone())
                .recv(count, 0)
                .map(|r| r.data);
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
                .recv(
                    count,
                    if o.flags.get() & O_NONBLOCK != 0 {
                        0x40
                    } else {
                        0
                    },
                )
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
            Content::Fuse => Err(Errno(95)),
            Content::MessageQueue(q) => Ok(q.read(&o.file_position, count)),
            Content::File(b) => {
                let mut position = o.file_position.lock().unwrap();
                if position.pending != 0 {
                    return Err(Errno(11));
                }
                Self::check_io_range(position.value, count as u64)?;
                let out = b.read_at(position.value, count)?;
                position.value += out.len() as u64;
                Ok(out)
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
        let descriptor = self.descriptor(fd)?;
        self.write_description(&descriptor, bytes)
    }
    fn write_description(&mut self, descriptor: &Descriptor, bytes: &[u8]) -> Result<usize> {
        let mut o = descriptor.open.borrow_mut();
        if let Some(kind) = o.node.as_ref().and_then(|n| n.simple_device) {
            return o.simple_write(kind, bytes);
        }
        if !fd_can_write(o.flags.get()) {
            return Err(Errno(9));
        }
        if let Some(events::SharedControl::MessageQueue(_)) = &o.control {
            return Err(Errno(22));
        }
        if let Some(events::SharedControl::Fuse(file)) = &o.control {
            let file = file.clone();
            drop(o);
            return file.connection()?.write(bytes);
        }
        if let Some(events::SharedControl::Tun(file, _)) = &o.control {
            let file = file.clone();
            drop(o);
            return file.write(bytes).map_err(|e| Errno(e.0));
        }
        if let Some(log) = &o.kernel_log {
            return log.write(bytes);
        }
        if let Some(local) = &o.local {
            return self.local_send_to(
                &self.local_view(local.clone()),
                bytes,
                0,
                None,
                LocalRights::default(),
            );
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
        if o.socket.is_some() {
            let socket = SocketOperation(o.shared.clone());
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
        self.file_write_description(descriptor, bytes, None)
    }
    /// Per-task RLIMIT_FSIZE; disk quota remains a separate ENOSPC constraint.
    pub fn file_size_limit_handle(&self) -> FileSizeLimit {
        self.file_size_limit.clone()
    }
    pub fn memory_resource_limits(&self) -> &MemoryResourceLimits {
        &self.memory_resource_limits
    }
    pub fn bind_memory_resource_limits(&mut self, limits: MemoryResourceLimits) {
        self.memory_resource_limits = limits;
    }
    pub fn descriptor_ceiling(&self) -> DescriptorCeiling {
        self.pseudo.borrow().nr_open.clone()
    }
    pub fn descriptor_limit_handle(&self) -> DescriptorLimit {
        self.shared_files().limit_handle()
    }
    pub fn bind_resource_limits(&mut self, file_size: FileSizeLimit, nofile: DescriptorLimit) {
        self.file_size_limit = file_size;
        self.fds.bind_limit(nofile.0);
    }
    pub fn set_file_size_limit(&mut self, limit: u64) {
        self.file_size_limit.set(limit);
        self.file_size_signal.set(false);
    }
    pub fn take_file_size_signal(&self) -> bool {
        self.file_size_signal.replace(false)
    }
    fn file_write(&mut self, fd: u32, bytes: &[u8], offset: Option<u64>) -> Result<usize> {
        let descriptor = self.descriptor(fd)?;
        self.file_write_description(&descriptor, bytes, offset)
    }
    fn file_write_description(
        &mut self,
        descriptor: &Descriptor,
        bytes: &[u8],
        offset: Option<u64>,
    ) -> Result<usize> {
        self.file_write_description_inner::<false>(descriptor, bytes, offset, None, (0, 0), &mut 0)
    }
    fn file_write_sync_description(
        &mut self,
        descriptor: &Descriptor,
        bytes: &[u8],
        offset: Option<u64>,
        data_only: bool,
    ) -> Result<usize> {
        let ordinary = descriptor
            .open
            .borrow()
            .node
            .as_ref()
            .is_some_and(|node| matches!(node.borrow().content, Content::File(_)));
        if ordinary {
            self.file_write_description_inner::<false>(
                descriptor,
                bytes,
                offset,
                Some(data_only),
                (0, 0),
                &mut 0,
            )
        } else {
            let count = self.file_write_description(descriptor, bytes, offset)?;
            self.sync_description(descriptor, data_only)?;
            Ok(count)
        }
    }

    fn file_write_description_inner<const COPY_TAIL: bool>(
        &mut self,
        descriptor: &Descriptor,
        bytes: &[u8],
        offset: Option<u64>,
        sync: Option<bool>,
        tail: (u64, usize),
        offered: &mut usize,
    ) -> Result<usize> {
        let file_size_limit = self.file_size_limit.get();
        let o = descriptor.open.borrow();
        let synchronous = fd_status::write_sync(o.flags.get(), sync);
        if offset.is_some() && o.pipe.is_some() {
            return Err(Errno(29));
        }
        let readonly = o.mount.as_ref().is_some_and(|mount| mount.readonly());
        if readonly && !mounts::special_file(o.node.as_ref()) {
            return Err(Errno(30));
        }
        let available = self.description_available_bytes(&o);
        let memfd_available = self.memfd_available();
        if !fd_can_write(o.flags.get()) {
            return Err(Errno(9));
        }
        if let Some(control) = &o.sysctl_control {
            let count = if let Some(mut explicit) = offset {
                control.write(bytes, &mut explicit, self)?
            } else {
                let mut position = o.file_position.lock().unwrap();
                if position.pending != 0 {
                    return Err(Errno(11));
                }
                if matches!(control, sysctl::Control::Comm { .. }) {
                    control.write(bytes, &mut 0, self)?
                } else {
                    control.write(bytes, &mut position.value, self)?
                }
            };
            // Wake callbacks may inspect this same open description.
            if let sysctl::Control::UtsName(domain, _) = control {
                self.uts.notify_name(*domain);
            }
            return Ok(count);
        }
        if o.runtime_file.as_ref().is_some_and(|file| file.is_memory()) {
            // Mutable guest memory is available on its own executing worker.
            return Err(Errno(95));
        }
        if o.oom.is_some() {
            let position = offset.is_none().then(|| o.file_position.lock().unwrap());
            if position
                .as_ref()
                .is_some_and(|position| position.pending != 0)
            {
                return Err(Errno(11));
            }
            if let Some(count) = self.oom_write(&o, bytes)? {
                // proc oom_score_adj_write ignores and does not advance f_pos.
                return Ok(count);
            }
        }
        if let Some(events::SharedControl::Cgroup(file)) = &o.control {
            if offset.is_some() {
                return file
                    .cgroup_write(&self.cgroup_access(), bytes)?
                    .ok_or(Errno(19));
            }
            let mut position = o.file_position.lock().unwrap();
            if position.pending != 0 {
                return Err(Errno(11));
            }
            let count = file
                .cgroup_write(&self.cgroup_access(), bytes)?
                .ok_or(Errno(19))?;
            position.value = position.value.saturating_add(count as u64);
            return Ok(count);
        }
        let node = o.node.clone().ok_or(Errno(29))?;
        self.pseudo_immutable(&node).map_err(|e| {
            // proc_reg_write returns EIO when the entry has no write operation.
            if node.seq_file {
                Errno(5)
            } else {
                e
            }
        })?;
        {
            let n = node.borrow();
            if !COPY_TAIL && n.seals.is_none() {
                if let Content::File(storage::FileData::Plain(data)) = &n.content {
                    let bytes = &bytes[..bytes.len().min(storage::MAX_TRANSFER)];
                    if bytes.is_empty() {
                        return Ok(0);
                    }
                    let mut position = o.file_position.lock().unwrap();
                    if offset.is_none() && position.pending != 0 {
                        return Err(Errno(11));
                    }
                    let at = offset.unwrap_or(position.value);
                    Self::check_io_range(at, bytes.len() as u64)?;
                    let append = o.flags.get() & 0x400 != 0;
                    let result = data.write_limited(at, bytes, append, file_size_limit, || {
                        self.file_size_signal.set(true)
                    });
                    let mut deferred_position = None;
                    if let Ok((_, end)) = result {
                        if offset.is_none() {
                            if synchronous.is_some() {
                                deferred_position =
                                    Some(o.file_position.defer_write(&mut position, end));
                            } else {
                                position.value = end;
                            }
                        }
                    }
                    drop(position);
                    if result.as_ref().is_ok_and(|(n, _)| *n != 0) {
                        data.modified(!self.credentials.has_cap(capabilities::FSETID));
                    }
                    drop(n);
                    if result.as_ref().is_ok_and(|(n, _)| *n != 0) {
                        o.notify_file_io(&node, inotify::MODIFY);
                    }
                    drop(o);
                    if result.is_ok() {
                        if let Some(data_only) = synchronous {
                            self.sync_description(descriptor, data_only)?;
                        }
                        if let Some(position) = deferred_position {
                            position.complete();
                        }
                    }
                    return result.map(|(n, _)| n);
                }
            }
        }
        let mut n = node.borrow_mut();
        let seals = n.seals;
        let count = bytes.len().min(storage::MAX_TRANSFER);
        let bytes = &bytes[..count];
        let mut deferred_position = None;
        let result = match &mut n.content {
            Content::Fuse => Err(Errno(95)),
            Content::MessageQueue(_) => Err(Errno(22)),
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
                if offset.is_none() && file_position.pending != 0 {
                    return Err(Errno(11));
                }
                Self::check_io_range(offset.unwrap_or(file_position.value), bytes.len() as u64)?;
                let position = if o.flags.get() & 0x400 != 0 {
                    b.len()
                } else {
                    offset.unwrap_or(file_position.value)
                };
                // A forward copy whose output starts at EOF consumes its own writes.
                // Under this inode and OFD lock each following byte in the chunk
                // repeats the original tail. Ordinary writes take the borrowed path.
                let expanded;
                let bytes = if COPY_TAIL
                    && position == b.len()
                    && tail.0.checked_add(bytes.len() as u64) == Some(position)
                    && tail.1 > bytes.len()
                    && !bytes.is_empty()
                {
                    expanded = file_work::repeat_tail(bytes, tail.1);
                    *offered = expanded.len();
                    &expanded[..]
                } else {
                    bytes
                };
                let plain = seals.is_none() && matches!(b, storage::FileData::Plain(_));
                let bytes = if plain {
                    bytes
                } else {
                    if position >= file_size_limit {
                        self.file_size_signal.set(true);
                        return Err(Errno(27));
                    }
                    let bytes = &bytes[..bytes
                        .len()
                        .min(usize::try_from(file_size_limit - position).unwrap_or(usize::MAX))];
                    let end = position
                        .checked_add(bytes.len() as u64)
                        .filter(|&n| n <= i64::MAX as u64)
                        .ok_or(Errno(27))?;
                    if seals.is_some_and(|s| s & 0x18 != 0 || s & 4 != 0 && end > b.len()) {
                        return Err(Errno(1));
                    }
                    let available = if seals.is_some() {
                        memfd_available
                    } else {
                        available
                    };
                    if let Some(query) = &self.query {
                        if !query.file_layout_exclusive && end > b.len() && b.layout_change(end) {
                            return query.defer();
                        }
                    }
                    if b.growth_charge(end) > available {
                        return Err(Errno(28));
                    }
                    bytes
                };
                let (written, end) = b.write_transfer(
                    position,
                    bytes,
                    o.flags.get() & 0x400 != 0,
                    file_size_limit,
                    || self.file_size_signal.set(true),
                )?;
                if offset.is_none() {
                    if synchronous.is_some() {
                        deferred_position =
                            Some(o.file_position.defer_write(&mut file_position, end));
                    } else {
                        file_position.value = end;
                    }
                }
                Ok(written)
            }
        };
        if !readonly && result.is_ok_and(|n| n != 0) {
            let clear_setid = !self.credentials.has_cap(capabilities::FSETID);
            let shared = if let Content::File(storage::FileData::Plain(data)) = &n.content {
                data.modified(clear_setid)
            } else {
                None
            };
            if shared.is_none() {
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
        drop(n);
        if result.is_ok_and(|n| n != 0)
            && !(node.borrow().seals.is_some() && o.notification.is_none())
        {
            o.notify_file_io(&node, inotify::MODIFY);
        }
        drop(o);
        if result.is_ok() {
            if let Some(data_only) = synchronous {
                self.sync_description(descriptor, data_only)?;
            }
            if let Some(position) = deferred_position {
                position.complete();
            }
        }
        result
    }
    pub fn pread(&self, fd: u32, count: usize, offset: u64) -> Result<Vec<u8>> {
        self.refresh_pseudo_fd(fd)?;
        if offset > i64::MAX as u64
            && !self
                .descriptor(fd)?
                .open
                .borrow()
                .runtime_file
                .as_ref()
                .is_some_and(|f| f.is_memory())
        {
            return Err(Errno(22));
        }
        let descriptor = self.descriptor(fd)?;
        self.pread_description(&descriptor, count, offset)
    }
    fn pread_description(
        &self,
        descriptor: &Descriptor,
        count: usize,
        offset: u64,
    ) -> Result<Vec<u8>> {
        let o = descriptor.open.borrow();
        if o.bridge.is_some() || o.kernel_log.is_some() || o.pipe.is_some() {
            return Err(Errno(29));
        }
        if let Some(kind) = o.node.as_ref().and_then(|n| n.simple_device) {
            return o.simple_read(kind, count);
        }
        if !fd_can_read(o.flags.get()) {
            return Err(Errno(9));
        }
        if let Some(file) = &o.mount_file {
            let data = file.read(offset, count, &self.cgroup_namespace.path);
            o.notify_read(&data);
            return Ok(data);
        }
        if let Some(file) = &o.runtime_file {
            return file
                .read(offset, count, self)
                .inspect(|data| o.notify_read(data));
        }
        if let Some(control) = &o.sysctl_control {
            return control
                .read(offset, count, self)
                .inspect(|data| o.notify_read(data));
        }
        if let Some(data) = Self::oom_read(&o, offset, count)? {
            o.notify_read(&data);
            return Ok(data);
        }
        if let Some(data) = self.cgroup_read(&o, offset, count)? {
            o.notify_read(&data);
            return Ok(data);
        }
        let node = o.data_node().ok_or(Errno(29))?;
        let n = node.borrow();
        if node.regular_file {
            Self::check_io_range(offset, count as u64)?;
        }
        let result = match &n.content {
            Content::Fuse => Err(Errno(95)),
            Content::MessageQueue(q) => Ok(q.status(offset, count)),
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
        if self.bridge_fd(fd) || {
            let d = self.descriptor(fd)?;
            let o = d.open.borrow();
            o.kernel_log.is_some()
                || o.pipe.is_some()
                || matches!(o.control, Some(events::SharedControl::Inotify(_)))
        } {
            return Err(Errno(29));
        }
        if offset > i64::MAX as u64
            && !self
                .descriptor(fd)?
                .open
                .borrow()
                .runtime_file
                .as_ref()
                .is_some_and(|f| f.is_memory())
        {
            return Err(Errno(22));
        }
        let descriptor = self.descriptor(fd)?;
        let o = descriptor.open.borrow();
        if let Some(kind) = o.node.as_ref().and_then(|n| n.simple_device) {
            return o.simple_write(kind, bytes);
        }
        drop(o);
        self.file_write(fd, bytes, Some(offset))
    }
    pub fn truncate_fd(&mut self, fd: u32, length: u64) -> Result<()> {
        self.resize_fd(fd, memfd::FileResize::Truncate(length))
    }
    pub fn truncate_at(&mut self, path: &[u8], length: u64) -> Result<()> {
        let fd = self.open_at_resolve_published::<true>(AT_FDCWD, path, 1, 0, 0, None)?;
        let result = self.truncate_fd(fd, length);
        self.close(fd)?;
        result
    }
    pub fn seek(&mut self, fd: u32, offset: i64, whence: u32) -> Result<u64> {
        let o_descriptor = self.descriptor(fd)?;
        Self::seek_description(&o_descriptor, offset, whence)
    }
    fn seek_description(o_descriptor: &Descriptor, offset: i64, whence: u32) -> Result<u64> {
        let o = o_descriptor.open.borrow();
        if o.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        if let Some(image) = &o.native_image {
            return match (offset, whence) {
                (0, 0) => Ok(0),
                (0, 2) => Ok(image.info().size),
                _ => Err(Errno(22)),
            };
        }
        if matches!(o.anonymous, Some(events::Anonymous::Signal(_))) {
            return Ok(o.file_position.lock().unwrap().value);
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
        if whence == 2
            && (o.runtime_file.as_ref().is_some_and(|file| file.is_memory())
                || node.seq_file
                || !n.volatile && matches!(n.content, Content::Directory))
        {
            return Err(Errno(22));
        }
        if matches!(whence, 3 | 4) && !node.regular_file {
            return Err(Errno(22));
        }
        let length = if o.oom.is_some() {
            0
        } else {
            match &n.content {
                Content::File(b) => b.len(),
                Content::MessageQueue(_) => 80,
                Content::Directory => 0,
                Content::Fuse => return Err(Errno(95)),
                Content::Socket(_) => return Err(Errno(6)),
                Content::Symlink(_) => return Err(Errno(40)),
                Content::Null => return Ok(0),
                Content::Device(_) => return Ok(0),
                Content::Terminal | Content::Fifo(_) => return Err(Errno(29)),
            }
        };
        drop(n);
        let mut file_position = o.file_position.lock().unwrap();
        if file_position.pending != 0 {
            return Err(Errno(11));
        }
        if o.runtime_file.as_ref().is_some_and(|f| f.is_memory()) {
            let value = match whence {
                0 => offset as u64,
                1 => file_position.value.wrapping_add(offset as u64),
                _ => return Err(Errno(22)),
            };
            file_position.value = value;
            return Ok(value);
        }
        let new = file_io::seek_offset(file_position.value, length, offset, whence)?;
        file_position.value = new;
        Ok(new)
    }
    fn stat_node(&self, node: &Node, mount: Option<&OpenMount>) -> Result<[u8; 128]> {
        let mut out = Self::stat_node_fields(node, node.stat_device(mount));
        let blocks = match &node.content {
            Content::File(data) if !node.volatile => data.blocks()?,
            _ => 0,
        };
        out[64..72].copy_from_slice(&blocks.to_le_bytes());
        Ok(out)
    }
    fn stat_node_fields(node: &Node, device: u64) -> [u8; 128] {
        let mut out = [0; 128];
        out[..8].copy_from_slice(&device.to_le_bytes());
        out[8..16].copy_from_slice(&node.inode.to_le_bytes());
        let metadata = node.file_metadata();
        out[16..20].copy_from_slice(&metadata.mode.to_le_bytes());
        out[20..24].copy_from_slice(&node.links.to_le_bytes());
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
            Content::MessageQueue(_) => 80,
            Content::File(b) if !node.volatile => b.len(),
            Content::Symlink(_) if node.volatile && node.device == 2 => 0,
            Content::Symlink(target) => target.len() as u64,
            _ => 0,
        };
        out[48..56].copy_from_slice(&size.to_le_bytes());
        out[56..60].copy_from_slice(&4096u32.to_le_bytes());
        for (offset, t) in [72, 88, 104].into_iter().zip(metadata.times) {
            out[offset..offset + 8].copy_from_slice(&t.seconds.to_le_bytes());
            out[offset + 8..offset + 16].copy_from_slice(&(t.nanos as u64).to_le_bytes());
        }
        out
    }
    fn stat_inode(&self, inode: &NodeRef, mount: Option<&OpenMount>) -> Result<[u8; 128]> {
        if let Some((m, fs)) = mount.and_then(|m| m.fs.fuse.as_ref().map(|fs| (m, fs))) {
            let query = self.query.as_ref().ok_or(Errno(95))?;
            let pending = fuse::Metadata::stat_inode(self, m, fs, inode.clone())?;
            query.prepared.borrow_mut().fuse = Some(Box::new(pending));
            return query.defer();
        }
        let (mut out, directory) = {
            let node = inode.borrow();
            (
                self.stat_node(&node, mount)?,
                node.links != 0 && matches!(node.content, Content::Directory),
            )
        };
        if directory {
            if let Some(proc) = inode
                .proc_node
                .get()
                .filter(|proc| proc.path.ends_with(b"/task"))
            {
                let at = ResolvedPath {
                    directory_inode: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                    proc_binding: proc.binding.clone(),
                    key: proc.path.clone(),
                    mount: self.mount_for_path(mount),
                };
                if let Some(group) = self.proc_thread_directory(&at) {
                    let ns = self.proc_namespace(&at);
                    let count = group
                        .target
                        .threads()
                        .iter()
                        .filter(|task| ns.local(task.pid()) != 0)
                        .count();
                    out[20..24].copy_from_slice(&(2 + count as u32).to_le_bytes());
                    return Ok(out);
                }
            }
            // Namespace/checkpoint writers use filesystem -> inode. In
            // particular, never carry the above scalar inode guard into here.
            let (path, mut directories) = {
                let fs = mount.map_or(&self.fs, |m| &m.fs).borrow();
                let path = inode.borrow().path_in(&fs.paths, b"/").or_else(|| {
                    self.pseudo
                        .borrow()
                        .nodes
                        .borrow()
                        .entries
                        .iter()
                        .find(|(_, n)| n.identity == inode.identity)
                        .map(|((_, p), _)| p.clone())
                });
                let mut directories = std::collections::BTreeSet::new();
                if let Some(path) = &path {
                    for (name, n) in directory::children(&fs.paths, path) {
                        if matches!(n.borrow().content, Content::Directory) {
                            directories.insert(name.to_vec());
                        }
                    }
                }
                (path, directories)
            };
            if let Some(path) = path {
                let mut prefix = path.clone();
                if prefix != b"/" {
                    prefix.push(b'/');
                }
                let at = ResolvedPath {
                    directory_inode: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                    proc_binding: None,
                    key: path,
                    mount: self.mount_for_path(mount),
                };
                // These lookups can re-enter the filesystem. No namespace or
                // inode guard remains, even if a writer is already queued.
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
                out[20..24].copy_from_slice(&(2 + directories.len() as u32).to_le_bytes());
            }
        }
        Ok(out)
    }
    pub fn stat_at(&self, dirfd: i32, path: &[u8]) -> Result<[u8; 128]> {
        self.stat_at_flags(dirfd, path, false)
    }
    pub fn stat_at_flags(&self, dirfd: i32, path: &[u8], nofollow: bool) -> Result<[u8; 128]> {
        self.stat_at_with_mount(dirfd, path, nofollow)
            .map(|(stat, _)| stat)
    }
    /// One pathname resolution retains both metadata and its mount identity.
    pub fn stat_at_with_mount(
        &self,
        dirfd: i32,
        path: &[u8],
        nofollow: bool,
    ) -> Result<([u8; 128], u64)> {
        self.statx_at(dirfd, path, nofollow)
            .map(|(stat, mount)| (stat, mount.id))
    }
    pub fn statx_at(
        &self,
        dirfd: i32,
        path: &[u8],
        nofollow: bool,
    ) -> Result<([u8; 128], StatMount)> {
        self.stat_at_raw(dirfd, path, nofollow)
            .map(|(stat, mount)| (self.credentials.user_namespace.stat(stat), mount))
    }
    fn stat_at_raw(
        &self,
        dirfd: i32,
        path: &[u8],
        nofollow: bool,
    ) -> Result<([u8; 128], StatMount)> {
        let (p, magic) = self.resolve_entry_operation(
            dirfd,
            path,
            !nofollow,
            !nofollow,
            0,
            !nofollow,
            Some(ResolveOperation::Fuse(fuse::PathOperation::Stat)),
            None,
        )?;
        self.stat_resolved((p, magic))
    }
    fn stat_resolved(&self, (p, magic): ResolvedEntry) -> Result<([u8; 128], StatMount)> {
        match magic {
            Some(ResolvedTarget::Descriptor(open)) => {
                let open = open.borrow();
                return self
                    .stat_open(&open)
                    .map(|stat| (stat, StatMount::for_open(&open)));
            }
            Some(ResolvedTarget::Inode(file)) => {
                let mount = StatMount {
                    id: file.mount.as_ref().map_or(1, |m| m.id),
                    mounted: file.mount.is_some(),
                    is_root: file
                        .mount
                        .as_ref()
                        .is_some_and(|m| Arc::ptr_eq(&file.node, &m.root)),
                };
                return self
                    .stat_inode(
                        &file.node,
                        file.mount.clone().map(OpenMount::Owner).as_ref(),
                    )
                    .map(|stat| (stat, mount));
            }
            None => {}
        }
        let id = p.mount.as_ref().map_or(1, |m| m.id);
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &p.filesystem(self).host {
            if let Some(position) = &p.host_position {
                let stat = position
                    .pin(host, &p.filesystem(self), &p.key)?
                    .file
                    .stat()?;
                let is_root = position.known_node().is_some_and(|node| {
                    p.mount
                        .as_ref()
                        .is_some_and(|mount| Arc::ptr_eq(node, &mount.root))
                });
                return Ok((stat, StatMount::mounted(id, is_root)));
            }
            let stat = host.stat_at(&p.key)?;
            let is_root = p
                .mount
                .as_ref()
                .and_then(|m| m.root.host.get())
                .is_some_and(|root| root.matches_stat(&stat));
            return Ok((
                stat,
                StatMount {
                    id,
                    is_root,
                    mounted: p.mount.is_some(),
                },
            ));
        }
        let n = self.node(&p)?;
        let is_root = p
            .mount
            .as_ref()
            .map_or_else(|| p.key == b"/", |m| Arc::ptr_eq(&n, &m.root));
        let mount = p.mount.map(OpenMount::Owner);
        let out = self.stat_inode(&n, mount.as_ref());
        out.map(|stat| {
            (
                stat,
                StatMount {
                    id,
                    is_root,
                    mounted: mount.is_some(),
                },
            )
        })
    }
    pub fn stat_fd(&self, fd: u32) -> Result<[u8; 128]> {
        self.stat_fd_with_mount(fd).map(|(stat, _)| stat)
    }
    /// One membership lookup accepts the original OFD for the entire query.
    pub fn stat_fd_with_mount(&self, fd: u32) -> Result<([u8; 128], u64)> {
        self.statx_fd(fd).map(|(stat, mount)| (stat, mount.id))
    }
    pub fn statx_fd(&self, fd: u32) -> Result<([u8; 128], StatMount)> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        self.statx_open::<false>(&open)
    }
    pub fn statx_fd_cached(&self, fd: u32) -> Result<([u8; 128], StatMount)> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        self.statx_open::<true>(&open)
    }
    fn statx_open<const CACHED: bool>(
        &self,
        open: &OpenDescription,
    ) -> Result<([u8; 128], StatMount)> {
        if CACHED {
            if let Some(events::SharedControl::FuseFile(file)) = &open.control {
                return file.cached_stat(self);
            }
            if let Some((mount, fs)) = open
                .mount
                .as_ref()
                .and_then(|mount| mount.fs.fuse.as_ref().map(|fs| (mount, fs)))
            {
                if let Some(node) = open.node.as_ref() {
                    return fuse::Metadata::cached_inode(self, mount, fs, node);
                }
            }
        }
        self.stat_open(open).map(|stat| {
            (
                self.credentials.user_namespace.stat(stat),
                StatMount::for_open(open),
            )
        })
    }
    fn namespace_stat(id: u64) -> [u8; 128] {
        let mut stat = [0; 128];
        stat[..8].copy_from_slice(&17u64.to_le_bytes());
        stat[8..16].copy_from_slice(&id.to_le_bytes());
        stat[16..20].copy_from_slice(&0o100444u32.to_le_bytes());
        stat[20..24].copy_from_slice(&1u32.to_le_bytes());
        stat[56..60].copy_from_slice(&4096u32.to_le_bytes());
        stat
    }
    /// Cache operations need the open mode and file type from the same OFD.
    fn cache_file_type(&self, open: &OpenDescription, reading: bool) -> Result<u32> {
        let flags = open.flags.get();
        if flags & O_PATH != 0 || reading && flags & 1 != 0 {
            return Err(Errno(9));
        }
        if let Some(node) = open.metadata_node() {
            return Ok(node.borrow().mode & 0o170000);
        }
        let stat = self.stat_open(open)?;
        Ok(u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000)
    }
    pub fn cache_fd_type(&self, fd: u32, reading: bool) -> Result<u32> {
        self.cache_file_type(&self.descriptor(fd)?.open.borrow(), reading)
    }
    fn stat_open(&self, o: &OpenDescription) -> Result<[u8; 128]> {
        if let Some(events::SharedControl::FuseFile(file)) = &o.control {
            let q = self.query.as_ref().ok_or(Errno(95))?;
            q.prepared.borrow_mut().fuse = Some(Box::new(file.stat(self)?));
            return q.defer();
        }
        if let Some(namespace) = &o.namespace_resource {
            return Ok(Self::namespace_stat(namespace.id()));
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(file) = &o.host_file {
            return file.stat();
        }
        if let Some(image) = &o.native_image {
            let mut stat = [0; 128];
            let info = image.info();
            stat[..8].copy_from_slice(&16u64.to_le_bytes());
            stat[8..16].copy_from_slice(&o.id.to_le_bytes());
            stat[16..20].copy_from_slice(&0o100600u32.to_le_bytes());
            stat[20..24].copy_from_slice(&1u32.to_le_bytes());
            stat[24..28].copy_from_slice(&o.owner.0.to_le_bytes());
            stat[28..32].copy_from_slice(&o.owner.1.to_le_bytes());
            stat[48..56].copy_from_slice(&info.size.to_le_bytes());
            stat[56..60].copy_from_slice(&4096u32.to_le_bytes());
            stat[64..72].copy_from_slice(&info.size.div_ceil(512).to_le_bytes());
            return Ok(stat);
        }
        if let Some(n) = o.metadata_node() {
            let mut stat = self.stat_inode(&n, o.mount.as_ref())?;
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
                return self.stat_inode(&n, o.mount.as_ref());
            }
        }
        let owner = o
            .socket
            .as_ref()
            .map_or([o.owner.0, o.owner.1], |s| s.inode_owner());
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
                } else if let Some(local) = &o.local {
                    0o140000 | local.inode_permissions.load(Ordering::Relaxed)
                } else if o.socket.is_some() {
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
                uid: owner[0],
                gid: owner[1],
                volatile: false,
                times: [storage::Timestamp::default(); 3],
                xattrs: BTreeMap::new(),
                seals: None,
            },
            None,
        )
    }
    pub fn chdir_fd(&mut self, fd: u32) -> Result<()> {
        let open = self.descriptor(fd)?.open;
        self.chdir_resolved((
            ResolvedPath {
                key: Vec::new(),
                mount: None,
                directory_inode: None,
                indexed_position: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_position: None,
                retained_directory: None,
                proc_binding: None,
            },
            Some(ResolvedTarget::Descriptor(open)),
        ))
    }
    pub fn chdir(&mut self, path: &[u8]) -> Result<()> {
        let entry = self.resolve_entry_operation(
            AT_FDCWD,
            path,
            true,
            true,
            0,
            true,
            Some(ResolveOperation::Fuse(fuse::PathOperation::Chdir)),
            None,
        )?;
        self.chdir_resolved(entry)
    }
    fn chdir_resolved(&mut self, entry: ResolvedEntry) -> Result<()> {
        self.change_directory_resolved(entry, false)
    }
    fn change_directory_resolved(&mut self, entry: ResolvedEntry, root: bool) -> Result<()> {
        #[cfg(all(feature = "hostfs", unix))]
        let retained_host = match &entry.1 {
            Some(ResolvedTarget::Descriptor(open)) => open.borrow().host_file.clone(),
            Some(ResolvedTarget::Inode(file)) => file.host_file.clone(),
            None => entry.0.host_position.as_ref().and_then(|p| p.known_file()),
        };
        // Keep the accepted target alive until publication. Its display name
        // is not another pathname to resolve after the execution-slot handoff.
        let (p, n) = match &entry.1 {
            Some(ResolvedTarget::Descriptor(open)) => {
                let open = open.borrow();
                let node = open.node.clone().ok_or(Errno(20))?;
                let path = ResolvedPath {
                    key: entry.0.key.clone(),
                    mount: self.mount_for_path(open.mount.as_ref()),
                    directory_inode: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                    proc_binding: None,
                };
                (path, node)
            }
            Some(ResolvedTarget::Inode(file)) => {
                let path = ResolvedPath {
                    key: file.label.clone(),
                    mount: file.mount.clone(),
                    directory_inode: None,
                    indexed_position: None,
                    #[cfg(all(feature = "hostfs", unix))]
                    host_position: None,
                    retained_directory: None,
                    proc_binding: None,
                };
                (path, file.node.clone())
            }
            None => (entry.0.clone(), self.node(&entry.0)?),
        };
        if !matches!(n.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        if let Some((mount, fs)) = p
            .mount
            .as_ref()
            .and_then(|mount| mount.fs.fuse.as_ref().map(|fs| (mount, fs)))
        {
            let query = self.query.as_ref().ok_or(Errno(95))?;
            query.prepared.borrow_mut().fuse = Some(Box::new(fuse::Metadata::change_directory(
                self, mount, fs, n, root,
            )?));
            return query.defer();
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(file) = &retained_host {
            file.refresh_permissions(&n)?;
        }
        if !self.allowed(&n.borrow(), 1) {
            return Err(Errno(13));
        }
        #[cfg(all(feature = "hostfs", unix))]
        let host_cwd = if retained_host.is_some() {
            retained_host
        } else {
            p.filesystem(self)
                .host
                .as_ref()
                .map(|host| host.lease_path(&p.filesystem(self), &p, &n, 0))
                .transpose()?
                .flatten()
        };
        let mut paths = self.context.paths.borrow_mut();
        #[cfg(all(feature = "hostfs", unix))]
        {
            if root {
                paths.host_root = host_cwd;
            } else {
                paths.host_cwd = host_cwd;
            }
        }
        if root {
            paths.root_mount = p.mount;
            paths.root_node = Some(n);
        } else {
            paths.cwd_mount = p.mount;
            paths.cwd_node = Some(n);
        }
        Ok(())
    }
    pub fn getdents(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        self.getdents_to(fd, count, |_, _| Ok(()))
    }
    pub fn getdents_to(
        &self,
        fd: u32,
        count: usize,
        mut copy: impl FnMut(usize, &[u8]) -> Result<()>,
    ) -> Result<Vec<u8>> {
        let d = self.descriptor(fd)?;
        self.getdents_description(&d, count, &mut copy)
    }
    fn getdents_description(
        &self,
        d: &Descriptor,
        count: usize,
        copy: &mut directory::CopyDirents<'_>,
    ) -> Result<Vec<u8>> {
        let o = d.open.borrow();
        if count > i32::MAX as usize {
            return Err(Errno(22));
        }
        let result = self.read_directory_entries(&o, count, copy);
        if result.is_ok() {
            if o.flags.get() & O_NOATIME == 0 {
                if let Some(node) = &o.node {
                    mounts::accessed(&mut node.borrow_mut(), o.mount.as_deref());
                }
            }
            if let Some(lease) = &o.notification {
                lease.path_event(inotify::ACCESS);
            }
        }
        result
    }
    fn read_directory_entries(
        &self,
        o: &OpenDescription,
        count: usize,
        copy: &mut directory::CopyDirents<'_>,
    ) -> Result<Vec<u8>> {
        if o.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        let node = o.node.as_ref().ok_or(Errno(20))?;
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let p = self.location(node, &self.mount_for_path(o.mount.as_ref()))?;
        if p.proc_binding
            .as_ref()
            .and_then(|scope| scope.at(&p, self.proc_namespace(&p).id()))
            .is_some_and(|scope| !scope.target.present())
        {
            if self.proc_thread_directory(&p).is_some() {
                return Err(Errno(2));
            }
            return Ok(Vec::new());
        }
        let filesystem = p.filesystem(self);
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            let children = host.children(&filesystem, &p)?;
            let inode = node.borrow().inode;
            let parent = self.node(&self.parent_location(&p)?)?.borrow().inode;
            return directory::encode(
                &o.file_position,
                count,
                (inode, parent),
                children,
                false,
                copy,
            );
        }
        let inode = node.borrow().inode;
        let parent = self.node(&self.parent_location(&p)?)?.borrow().inode;
        let mut children = directory::metadata(&filesystem, &p.key);
        let mut prefix = p.clone();
        if prefix != b"/" {
            prefix.push(b'/');
        }
        let mut add = |name: Vec<u8>, child: ResolvedPath| -> Result<()> {
            let node = match self.node(&child) {
                Err(Errno(2)) if p.starts_with(b"/proc/") || p.as_ref() == b"/proc" => {
                    return Ok(())
                }
                result => result?,
            };
            let n = node.borrow();
            children.insert(name, (n.inode, ((n.mode & 0o170000) >> 12) as u8));
            Ok(())
        };
        if let Some(group) = self.proc_thread_directory(&p) {
            let ns = self.proc_namespace(&p);
            // Resolve the original group once. A concurrent exit can invalidate
            // an entry before its metadata lookup, without hiding its siblings.
            for peer in group.target.threads() {
                let tid = ns.local(peer.pid());
                if tid == 0 {
                    continue;
                }
                let name = tid.to_string().into_bytes();
                let mut child = prefix.clone();
                child.extend_from_slice(&name);
                child.proc_binding = Some(group.member(&child, peer));
                add(name, child)?;
            }
        } else {
            for name in self.mounted_pseudo_children(&p)? {
                let mut child = prefix.clone();
                child.extend_from_slice(&name);
                add(name, child)?;
            }
        }
        let numbered = directory::proc_fds(&p.key) && self.uses_pseudo(&p);
        directory::encode(
            &o.file_position,
            count,
            (inode, parent),
            children,
            numbered,
            copy,
        )
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
            Ok((2 | O_NONBLOCK | O_LARGEFILE) as u64)
        );
        assert_eq!(
            query_fd_flags(old.get(fd).unwrap(), 3),
            Ok((2 | O_NONBLOCK | O_LARGEFILE) as u64)
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

#[cfg(test)]
mod shared_control_tests;

#[cfg(test)]
mod file_work_tests;

#[cfg(test)]
mod task_transfer;
