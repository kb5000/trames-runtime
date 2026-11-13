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
pub use cgroup::{CgroupBirth, CgroupTask};
mod fs_context;
mod path_queries;
pub use path_queries::PathQueries;
mod fs_data;
#[cfg(all(feature = "hostfs", unix))]
mod hostfs;
use fs_context::FsContext;
pub use fs_context::{FsOwner, Umask};
use fs_data::{FsBorrow, FsHandle};
mod async_io;
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
mod fd_allocator;
mod fd_table;
mod resource_limits;
pub use descriptor_factory::DescriptorFactory;
pub use resource_limits::{DescriptorLimit, FileSizeLimit};
mod open_handle;
pub use open_handle::OfdIdentity;
use open_handle::{OpenHandle, OpenMount, OpenWeak};
mod shared_cell;
mod simple_device;
use shared_cell::SharedCell;
mod flock;
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
mod namespace_work;
pub use file_work::{
    FileCommand, FileCopy, FileOutcome, FileReply, FileTarget, FileValue, FileWork,
};
pub use namespace_work::{NamespaceAttempt, NamespaceCall};
mod file_io;
use direct_io::PipeResource;
pub use file_io::{DirectFile, DirectFiles, FileAccess, FileEpoch, PreparedFile};
mod readiness;
mod timer_io;
pub use direct_io::{DirectFd, DirectFds, DirectPoll};
pub use readiness::{IoSignal, IoSubscription, IoWake};
mod signal_reader;
#[cfg(test)]
mod uring_context_tests;
pub use signal_reader::SignalReader;
pub use timer_io::TimerFd;
pub use trames_shared::{HostEvents, HostFd, HostSubscription, Readiness, ReadinessDriver};
mod epoll;
mod epoll_graph;
mod events;
mod uring;
pub use uring::{
    RetainedFd, Uring, UringBufferGroup, UringBufferSource, UringExecutionLease, UringFile,
    UringFileView, UringObject, UringProvidedBuffer, UringRequest, UringResource, UringRetirement,
    UringRunning, UringSelection, UringSource, UringSqe, UringState, URING_CQES, URING_MAX_ENTRIES,
    URING_OPS, URING_SQ_ARRAY,
};
mod executable;
pub use executable::ExecutableFile;
pub use executable::{script_interpreter, ScriptInterpreter};
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
mod proc_file;
mod proc_image;
pub use proc_image::ProcImage;
mod proc_source;
mod proc_time;
mod pseudo;
pub use oom::OomTask;
pub use proc_source::{
    ProcCounters, ProcDirectory, ProcQuery, ProcResources, ProcSource, ProcTask, ProcessView,
    SeccompView,
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
pub use linux_namespace::{NamespaceProjection, SharedNamespaceSnapshot};
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
pub fn query_fd_flags(flags: u32, command: u64) -> Result<u64> {
    match command {
        1 => Ok(u64::from(flags & O_CLOEXEC != 0)),
        3 => Ok((flags & !(O_CLOEXEC | 0x40 | 0x80 | 0x100 | 0x200)) as u64),
        _ => Err(Errno(22)),
    }
}
pub use network::{SocketControlOperation, SocketOperation};
pub use storage::{DiskOptions, StorageCapacity, StorageLimits, VolumeSpace, DEFAULT_DISK_BYTES};
pub use trames_net::{NetworkMode, Socket as NetSocket};
pub fn kernel_log_capacity() -> usize {
    kernel_log::LOG_CAPACITY
}
pub const MAX_PATH: usize = 4096;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NODES: usize = 1024;
/// Linux's default nr_open ceiling. Tables allocate only occupied slots.
pub const MAX_FDS: u32 = 1 << 20;
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
/// Scheduler task budget, also reported by procfs and RLIMIT_NPROC.
pub const MAX_TASKS: usize = 256;
pub const PIPE_CAPACITY: usize = 65536;
pub const AT_FDCWD: i32 = -100;
pub const O_DIRECTORY: u32 = 0x4000;
pub const O_NOFOLLOW: u32 = 0x8000;
pub const O_LARGEFILE: u32 = 0x20000;
pub const O_NOATIME: u32 = 0x40000;
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
    anonymous: Option<events::Anonymous>,
    namespace: Option<linux_namespace::NamespaceHandle>,
    mount: Option<OpenMount>,
}
// The actual file, pipe and lock/notification lifetimes share one allocation.
// Legacy ancillary, task and mount control projections retain owner ownership.
struct SharedOpenDescription {
    console: std::sync::OnceLock<console::ConsoleEndpoint>,
    oom: Option<std::sync::Weak<OomTask>>,
    network_control: Option<network::Control>,
    mount_file: Option<Arc<mounts::watch::MountFile>>,
    runtime_file: Option<Arc<proc_file::ProcFile>>,
    socket: Option<Arc<NetSocket>>,
    _disk_file: Option<Arc<std::fs::File>>,
    #[cfg(all(feature = "hostfs", unix))]
    host_file: Option<Arc<hostfs::OpenFile>>,
    native_image: Option<Arc<dyn trames_graphics::Image>>,
    mount_resource: std::sync::OnceLock<Arc<mounts::MountData>>,
    mount_use: std::sync::OnceLock<mounts::MountUse>,
    directory_mount: std::sync::OnceLock<mounts::DirectoryPin>,
    namespace_resource: Option<linux_namespace::SharedNamespace>,
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
    fn proc_control(&self) -> bool {
        self.oom.is_some()
            || self.network_control.is_some()
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
    proc_node: std::sync::OnceLock<proc_source::ProcNode>,
    regular_file: bool,
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
            regular_file: !node.volatile && matches!(node.content, Content::File(_)),
            proc_node: Default::default(),
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
struct ResolvedInode {
    node: NodeRef,
    label: Vec<u8>,
    mount: Option<Arc<Mount>>,
    // Acceptance retains the original resource until its operation finishes.
    // Neither the inode cache nor a long-lived query view owns these leases.
    file: Option<Arc<SharedOpenDescription>>,
    _image: Option<Arc<ExecutableFile>>,
    _directory: Option<mounts::MountUse>,
}
struct MetadataTarget {
    path: ResolvedPath,
    node: NodeRef,
    _magic: Option<ResolvedInode>,
}
enum ResolvedTarget {
    Inode(ResolvedInode),
    Descriptor(OpenHandle),
}
type ResolvedEntry = (ResolvedPath, Option<ResolvedTarget>);
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
    pub const Full: Self = Self((1 << 12) - 1);

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
            .any(|part| matches!(part, b"fd" | b"fdinfo" | b"net"))
        {
            return Self::Descriptors;
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
        if path == b"/proc/meminfo" {
            return Self::HostMemory;
        }
        if [
            b"/stat".as_slice(),
            b"/statm",
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
    cgroup_namespace: Arc<linux_namespace::CgroupNamespace>,
    pid_ns: PidNamespace,
    pid_identity: Option<PidReference>,
    pid_children: PidNamespace,
    mounts: Option<MountNamespace>,
    mount_registry: mounts::Registry,
    mount_resources: Arc<SharedCell<Vec<std::sync::Weak<mounts::MountIdentity>>>>,
    detached_mounts: Arc<SharedCell<Vec<Vec<Arc<Mount>>>>>,
    pub credentials: Credentials,
    pseudo: Arc<SharedCell<pseudo::PseudoFs>>,
    kernel_log: Arc<kernel_log::KernelLog>,
    binder: Arc<binder::Contexts>,
    cgroups: Arc<SharedCell<cgroup::Cgroups>>,
    dumpable: Dumpable,
    pid: u32,
    lock_owner: u32,
    record_locks: Arc<locks::Registry>,
    file_size_limit: FileSizeLimit,
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
            cgroup_namespace: self.cgroup_namespace.clone(),
            pid_ns: self.pid_ns.clone(),
            pid_identity: self.pid_identity.clone(),
            pid_children: self.pid_children.clone(),
            mounts: self.mounts.clone(),
            mount_registry: self.mount_registry.clone(),
            mount_resources: self.mount_resources.clone(),
            detached_mounts: self.detached_mounts.clone(),
            credentials: self.credentials.clone(),
            pseudo: self.pseudo.clone(),
            kernel_log: self.kernel_log.clone(),
            binder: self.binder.clone(),
            cgroups: self.cgroups.clone(),
            dumpable: self.dumpable.clone(),
            pid: self.pid,
            lock_owner: self.lock_owner,
            record_locks: self.record_locks.clone(),
            file_size_limit: self.file_size_limit.fork(),
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
            cgroup_namespace: Arc::default(),
            pid_ns: pid_ns.clone(),
            pid_identity: None,
            pid_children: pid_ns,
            mounts: None,
            mount_registry,
            mount_resources: Arc::default(),
            detached_mounts: Arc::default(),
            credentials: Credentials::default(),
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
                            console: Default::default(),
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
        Self::poll_open(&open, events, pending, self.signal_reader.borrow().as_ref())
    }
    fn peek_poll_open(
        o: &OpenDescription,
        events: u16,
        pending: u64,
        reader: Option<&Arc<dyn SignalReader>>,
    ) -> u16 {
        o.mount_file.as_ref().map_or_else(
            || Self::poll_open(o, events, pending, reader),
            |file| file.watch.peek(events).0,
        )
    }
    fn poll_open(
        o: &OpenDescription,
        events: u16,
        pending: u64,
        reader: Option<&Arc<dyn SignalReader>>,
    ) -> u16 {
        if let Some(events::SharedControl::Binder(process)) = &o.control {
            return if o.flags.get() & O_PATH != 0 {
                32
            } else {
                process.poll(events).0
            };
        }
        if let Some(file) = &o.mount_file {
            return file.watch.poll(events).0;
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
        let mut ready = events & 5;
        if let Some(end) = &o.pipe {
            let p = end.data.lock().unwrap();
            ready = 0;
            if end.read {
                if p.readable() {
                    ready |= events & 1;
                }
                if p.writers == 0 && p.write_epoch != end.initial_write_epoch {
                    ready |= 16;
                }
            }
            if end.write {
                if p.readers == 0 {
                    ready |= 8;
                } else if p.write_room() >= 4096 {
                    ready |= events & 4;
                }
            }
        }
        ready
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
                            console: Default::default(),
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
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            let node = host.create(&filesystem, &path.key, &content, mode)?;
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
                proc_binding: None,
                key: path[..i.max(1)].to_vec(),
                mount: path.mount.clone(),
            })?;
            if !matches!(parent.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            Some(parent)
        };
        let inherited = parent.as_ref().and_then(|p| {
            let p = p.borrow();
            (p.mode & 0o2000 != 0).then_some(p.gid)
        });
        if inherited.is_some() && matches!(content, Content::Directory) {
            mode |= 0o2000;
        }
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
        fs.track_inode(&node)?;
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
        if let Some(query) = &self.query {
            // Every implemented mount uses original shared inode/topology
            // resources. Admission follows the actual node/provider, not a
            // filesystem-name whitelist (which used to exclude mqueue roots).
            query.pin_mount(path.mount());
        }
        if path
            .mount()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup && m.root.borrow().links == 0)
        {
            return Err(Errno(19));
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
        path.mount()
            .map_or(&self.fs, |m| &m.fs)
            .borrow()
            .paths
            .get(key)
            .cloned()
            .ok_or(Errno(2))
    }
    fn descriptor(&self, fd: u32) -> Result<Descriptor> {
        if let Some(query) = &self.query {
            return query.descriptor(fd);
        }
        self.fds.lookup(fd)
    }
    pub fn allocated_bytes(&self) -> u64 {
        Self::filesystem_used_bytes(&self.fs.borrow())
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
        let fs = self.fs.borrow();
        let result = node.borrow().path_in(&fs.paths, b"/").ok_or(Errno(2));
        result
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
        let path = if dirfd == AT_FDCWD {
            let paths = self.context.paths.borrow();
            self.location(paths.cwd_node.as_ref().ok_or(Errno(2))?, &paths.cwd_mount)?
        } else {
            let o_descriptor = self.descriptor(dirfd as u32)?;
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
        let (path, magic) = self.resolve_entry(dirfd, path, follow, true)?;
        let magic = match magic {
            Some(ResolvedTarget::Inode(file)) => Some(file),
            Some(ResolvedTarget::Descriptor(open)) => Some(self.proc_open_node(&open, &path)?),
            None => None,
        };
        if let Some(file) = &magic {
            Ok(MetadataTarget {
                path: ResolvedPath {
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
        self.begin_proc_query();
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
            self.bind_proc_path(&mut current)?;
            Self::check_resolve_mount(&parent, &current, policy)?;
            if !parts.is_empty() || follow_final || trailing {
                if policy & (2 | 4 | 8 | 16) != 0 && self.is_proc_magic_link(&current) {
                    return Err(Errno(40));
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
                        current = self.location(&file.node, &file.mount)?;
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
                        let caller_target = self.proc_caller_link(&current)?;
                        let target = caller_target.as_deref().unwrap_or(target);
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
            let node = open.node.as_ref().ok_or(Errno(2))?.borrow();
            return match &node.content {
                Content::Symlink(target) => Ok(target.clone()),
                _ => Err(Errno(2)),
            };
        }
        let dest = self.resolve_final(dirfd, path, false)?;
        self.check_proc_inspection(&dest, true)?;
        if let Some(target) = self.proc_directory_readlink(&dest)? {
            return Ok(target);
        }
        if let Some(target) = self.proc_caller_link(&dest)? {
            return Ok(target);
        }
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
        let _namespace = filesystem.namespace.lock().unwrap();
        #[cfg(all(feature = "hostfs", unix))]
        let host_source = source.key.clone();
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
        {
            let fs = filesystem.borrow();
            if fs.paths.len() >= fs.limits.nodes {
                return Err(Errno(28));
            }
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            host.link(&host_source, &dest.key)?;
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
        self.insert_entry(
            p,
            Content::Directory,
            0o40000 | (mode & 0o7777 & !self.umask()),
            true,
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
        self.insert_entry(p, content, type_ | (mode & 0o7777 & !self.umask()), true)
    }
    pub fn unlink_at(&mut self, dirfd: i32, path: &[u8], directory: bool) -> Result<()> {
        let p = self.resolve_final(dirfd, path, false)?;
        let filesystem = p.filesystem(self);
        let _namespace = filesystem.namespace.lock().unwrap();
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
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            host.unlink(&p.key, directory)?;
            let mut fs = filesystem.borrow_mut();
            fs.paths.remove(&p.key);
            if is_dir {
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
        self.open_at_resolve_published(dirfd, path, flags, mode, policy, None)
    }
    fn open_at_resolve_published(
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
            self.resolve_entry_policy(dirfd, plain, true, false, policy, false)?;
            return Err(Errno(21));
        }
        let membership = self
            .query
            .as_ref()
            .map_or_else(|| self.shared_files(), |q| q.files.clone());
        let reservation = membership.reserve()?;
        let (mut p, target) = self.resolve_entry_policy(
            dirfd,
            path,
            flags & O_NOFOLLOW == 0 && flags & 0xc0 != 0xc0,
            true,
            policy,
            true,
        )?;
        let magic = match target {
            Some(ResolvedTarget::Inode(file)) => Some(file),
            Some(ResolvedTarget::Descriptor(open)) => {
                let original = open.borrow();
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
            .and_then(|o| o.network_control.clone())
            .or_else(|| self.network_control(&p));
        let mount_file = (flags & O_PATH == 0)
            .then(|| self.proc_mount_file(&p))
            .flatten();
        let check_write = || -> Result<()> {
            if flags & O_PATH == 0 && (flags & 3 != 0 || flags & 0x200 != 0) {
                p.writable()?;
            }
            if oom.is_none()
                && network_control.is_none()
                && self.uses_pseudo(&p)
                && self.pseudo_readonly(&p)
                && (flags & 3 != 0 || flags & 0x240 != 0)
            {
                return Err(Errno(30));
            }
            Ok(())
        };
        let mut runtime_file = None;
        let mut existed = match forced_node.clone().map_or_else(|| self.node(&p), Ok) {
            Ok(node) => {
                if flags & 0xc0 == 0xc0 {
                    return Err(Errno(17));
                }
                check_write()?;
                let proc_regular = {
                    let n = node.borrow();
                    n.volatile && matches!(n.content, Content::File(_))
                };
                if flags & (O_PATH | 3) == 0
                    && oom.is_none()
                    && network_control.is_none()
                    && mount_file.is_none()
                    && proc_regular
                {
                    runtime_file = self.proc_runtime_file(&p);
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
                        && !matches!(n.content, Content::Fifo(_))
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
        if !existed {
            check_write()?;
        }
        #[cfg(all(feature = "hostfs", unix))]
        let mut created_host_file = None;
        if !existed {
            if flags & O_DIRECTORY != 0 || flags & 0x40 == 0 {
                return Err(Errno(2));
            }
            self.check_parent_write(&p)?;
            #[cfg(all(feature = "hostfs", unix))]
            let native_created = if let Some(host) = &p.filesystem(self).host {
                match host.create_open(&p.filesystem(self), &p.key, flags, mode & !self.umask()) {
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
                    0o100000 | (mode & 0o7777 & !self.umask()),
                    true,
                ) {
                    Err(Errno(17)) if flags & 0x80 == 0 => existed = true,
                    result => result?,
                }
            }
        }
        let node = forced_node.map_or_else(|| self.node(&p), Ok)?;
        {
            let n = node.borrow();
            self.check_device_open(&n, flags)?;
            if flags & O_NOATIME != 0
                && self.credentials.fsuid != n.uid
                && !self.credentials.has_cap(capabilities::FOWNER)
            {
                return Err(Errno(1));
            }
            if matches!(n.content, Content::Socket(_)) && flags & O_PATH == 0 {
                return Err(Errno(6));
            }
            if matches!(n.content, Content::Symlink(_)) && flags & O_PATH == 0 {
                return Err(Errno(if flags & O_DIRECTORY != 0 { 20 } else { 40 }));
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
        let disk_file = if flags & O_PATH == 0 {
            match &node.borrow().content {
                Content::File(data) => data.private_lease(flags & 3 != 0)?,
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
                .map(|host| host.lease(&node, flags))
                .transpose()?
                .flatten(),
        };
        let truncate = flags & 0x200 != 0
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
            if flags & 0x200 != 0 {
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
        let notification = if let Some(original) = original {
            inotify::FileClose::reopen(&node, flags, original.notification.as_ref())
        } else {
            self.notification_open(&p, &node, flags)
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
                Content::Device(pseudo::Device::Binder(device)) => {
                    Some(events::SharedControl::Binder(self.binder.open(
                        device as usize,
                        self.lock_owner,
                        self.credentials.euid,
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
                    console: Default::default(),
                    oom,
                    network_control,
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
                    flags: (flags & !O_CLOEXEC).into(),
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
            if truncate || query.capture_open {
                let OpenHandle::Shared(shared) = &descriptor.open else {
                    return query.defer();
                };
                let file = SharedFd::new(shared.clone());
                let target = if query.capture_open {
                    Some(file.filesystem_target())
                } else {
                    file.file_target()
                };
                if let Some(target) = target {
                    *query.open_work.borrow_mut() = Some(file_work::PreparedOpen {
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
            let _ = task.acquire(&end.pair, false, flags & 3 != 1, true);
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
        for open in [source, dest] {
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
        Ok((source_pipe, dest_pipe))
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
                    stream_transfer::WriteLease::take(target.data.clone(), bytes.len())?;
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
        let mut write = stream_transfer::WriteLease::take(pipe.data.clone(), count)?;
        let bytes = if let Some(offset) = from {
            self.pread(input, write.count, offset)?
        } else {
            self.read(input, write.count)?
        };
        write.commit(&bytes)
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
        if o.flags.get() & O_PATH != 0 || o.flags.get() & 3 == 1 {
            return Err(Errno(9));
        }
        if let Some(file) = &o.mount_file {
            let mut position = o.file_position.lock().unwrap();
            let bytes = file.read(position.value, count);
            position.value += bytes.len() as u64;
            return Ok(bytes);
        }
        if let Some(file) = &o.runtime_file {
            let mut position = o.file_position.lock().unwrap();
            let bytes = file.read(position.value, count)?;
            position.value += bytes.len() as u64;
            return Ok(bytes);
        }
        if let Some(control) = &o.network_control {
            let mut position = o.file_position.lock().unwrap();
            let data = control.read(position.value, count);
            position.value += data.len() as u64;
            return Ok(data);
        }
        if o.oom.is_some() {
            let mut position = o.file_position.lock().unwrap();
            if let Some(data) = Self::oom_read(&o, position.value, count)? {
                position.value += data.len() as u64;
                return Ok(data);
            }
        }
        if let Some(events::SharedControl::Cgroup(file)) = &o.control {
            let mut position = o.file_position.lock().unwrap();
            let data = file
                .cgroup_read(&self.cgroup_access(), position.value, count)?
                .ok_or(Errno(19))?;
            position.value += data.len() as u64;
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
                let mut position = o.file_position.lock().unwrap();
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
            return o.simple_write::<false>(kind, bytes);
        }
        if o.flags.get() & 3 == 0 {
            return Err(Errno(9));
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
        self.file_write_description(descriptor, bytes, None)
    }
    /// Per-task RLIMIT_FSIZE; disk quota remains a separate ENOSPC constraint.
    pub fn file_size_limit_handle(&self) -> FileSizeLimit {
        self.file_size_limit.clone()
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
        let file_size_limit = self.file_size_limit.get();
        let o = descriptor.open.borrow();
        if let Some(mount) = &o.mount {
            mount.writable()?;
        }
        let available = self.description_available_bytes(&o);
        let memfd_available = self.memfd_available();
        if o.flags.get() & 3 == 0 {
            return Err(Errno(9));
        }
        if let Some(control) = &o.network_control {
            let mut position = o.file_position.lock().unwrap();
            let count = control.write(
                bytes,
                offset.unwrap_or(position.value),
                self.credentials.euid == 0 || self.credentials.has_cap(capabilities::NET_ADMIN),
            )?;
            if offset.is_none() {
                position.value += count as u64;
            }
            return Ok(count);
        }
        if let Some(count) = self.oom_write(&o, bytes)? {
            // proc oom_score_adj_write ignores and does not advance f_pos.
            return Ok(count);
        }
        if let Some(events::SharedControl::Cgroup(file)) = &o.control {
            if offset.is_some() {
                return file
                    .cgroup_write(&self.cgroup_access(), bytes)?
                    .ok_or(Errno(19));
            }
            let mut position = o.file_position.lock().unwrap();
            let count = file
                .cgroup_write(&self.cgroup_access(), bytes)?
                .ok_or(Errno(19))?;
            position.value = position.value.saturating_add(count as u64);
            return Ok(count);
        }
        let node = o.node.clone().ok_or(Errno(29))?;
        self.pseudo_immutable(&node)?;
        {
            let n = node.borrow();
            if n.seals.is_none() {
                if let Content::File(storage::FileData::Plain(data)) = &n.content {
                    let bytes = &bytes[..bytes.len().min(storage::MAX_TRANSFER)];
                    if bytes.is_empty() {
                        return Ok(0);
                    }
                    let mut position = o.file_position.lock().unwrap();
                    let at = offset.unwrap_or(position.value);
                    let append = o.flags.get() & 0x400 != 0;
                    let result = data.write_limited(at, bytes, append, file_size_limit, || {
                        self.file_size_signal.set(true)
                    });
                    if let Ok((_, end)) = result {
                        if offset.is_none() {
                            position.value = end;
                        }
                    }
                    drop(position);
                    if result.as_ref().is_ok_and(|(n, _)| *n != 0) {
                        data.modified(!self.credentials.has_cap(capabilities::FSETID));
                    }
                    let synchronous = o.flags.get() & 0x1000 != 0;
                    drop(n);
                    if result.as_ref().is_ok_and(|(n, _)| *n != 0) {
                        inotify::notify(
                            &node,
                            inotify::MODIFY,
                            o.notification.as_ref().and_then(|c| c.link.as_ref()),
                        );
                    }
                    drop(o);
                    if result.is_ok() && synchronous {
                        self.sync_description(descriptor, false)?;
                    }
                    return result.map(|(n, _)| n);
                }
            }
        }
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
                    file_position.value = end;
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
            self.sync_description(descriptor, false)?;
        }
        result
    }
    pub fn pread(&self, fd: u32, count: usize, offset: u64) -> Result<Vec<u8>> {
        self.refresh_pseudo_fd(fd)?;
        if offset > i64::MAX as u64 {
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
        if o.bridge.is_some() || o.kernel_log.is_some() {
            return Err(Errno(29));
        }
        if let Some(kind) = o.node.as_ref().and_then(|n| n.simple_device) {
            return o.simple_read(kind, count);
        }
        if o.flags.get() & O_PATH != 0 || o.flags.get() & 3 == 1 {
            return Err(Errno(9));
        }
        if let Some(file) = &o.mount_file {
            return Ok(file.read(offset, count));
        }
        if let Some(file) = &o.runtime_file {
            return file.read(offset, count);
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
        let descriptor = self.descriptor(fd)?;
        let o = descriptor.open.borrow();
        if let Some(kind) = o.node.as_ref().and_then(|n| n.simple_device) {
            return o.simple_write::<true>(kind, bytes);
        }
        drop(o);
        self.file_write(fd, bytes, Some(offset))
    }
    pub fn truncate_fd(&mut self, fd: u32, length: u64) -> Result<()> {
        self.resize_fd(fd, memfd::FileResize::Truncate(length))
    }
    pub fn truncate_at(&mut self, path: &[u8], length: u64) -> Result<()> {
        let fd = self.open_at(AT_FDCWD, path, 1, 0)?;
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
        drop(n);
        let mut file_position = o.file_position.lock().unwrap();
        let base = match whence {
            0 => 0,
            1 => file_position.value as i64,
            2 => length as i64,
            _ => return Err(Errno(22)),
        };
        let new = base
            .checked_add(offset)
            .filter(|&n| n >= 0)
            .ok_or(Errno(22))?;
        file_position.value = new as u64;
        Ok(new as u64)
    }
    fn stat_node(&self, node: &Node, mount: Option<&OpenMount>) -> Result<[u8; 128]> {
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
    fn stat_node_fields(&self, node: &Node, mount: Option<&OpenMount>) -> Result<[u8; 128]> {
        let mut out = [0; 128];
        let device = mount
            .filter(|m| m.kind == mounts::Kind::Overlay)
            .map_or(node.device, |m| m.device());
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
        Ok(out)
    }
    fn stat_inode(&self, inode: &NodeRef, mount: Option<&OpenMount>) -> Result<[u8; 128]> {
        let (mut out, directory) = {
            let node = inode.borrow();
            (
                self.stat_node(&node, mount)?,
                node.links != 0 && matches!(node.content, Content::Directory),
            )
        };
        if directory {
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
        let (p, magic) =
            self.resolve_entry_policy(dirfd, path, !nofollow, !nofollow, 0, !nofollow)?;
        match magic {
            Some(ResolvedTarget::Descriptor(open)) => {
                let open = open.borrow();
                return self
                    .stat_open(&open)
                    .map(|stat| (stat, Self::open_mount_id(&open)));
            }
            Some(ResolvedTarget::Inode(file)) => {
                let id = file.mount.as_ref().map_or(1, |m| m.id);
                return self
                    .stat_inode(
                        &file.node,
                        file.mount.clone().map(OpenMount::Owner).as_ref(),
                    )
                    .map(|stat| (stat, id));
            }
            None => {}
        }
        let id = p.mount.as_ref().map_or(1, |m| m.id);
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &p.filesystem(self).host {
            return host.stat_at(&p.key).map(|stat| (stat, id));
        }
        let n = self.node(&p)?;
        let mount = p.mount.map(OpenMount::Owner);
        let out = self.stat_inode(&n, mount.as_ref());
        out.map(|stat| (stat, id))
    }
    pub fn stat_fd(&self, fd: u32) -> Result<[u8; 128]> {
        self.stat_fd_with_mount(fd).map(|(stat, _)| stat)
    }
    /// One membership lookup accepts the original OFD for the entire query.
    pub fn stat_fd_with_mount(&self, fd: u32) -> Result<([u8; 128], u64)> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        self.stat_open(&open)
            .map(|stat| (stat, Self::open_mount_id(&open)))
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
    fn stat_open(&self, o: &OpenDescription) -> Result<[u8; 128]> {
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
        let mount = self.mount_for_path(self.descriptor(fd)?.open.borrow().mount.as_ref());
        let mut paths = self.context.paths.borrow_mut();
        #[cfg(all(feature = "hostfs", unix))]
        {
            paths.host_cwd = self.descriptor(fd)?.open.borrow().host_file.clone();
        }
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
        #[cfg(all(feature = "hostfs", unix))]
        let host_cwd = p
            .filesystem(self)
            .host
            .as_ref()
            .map(|host| host.lease(&n, 0))
            .transpose()?
            .flatten();
        let mut paths = self.context.paths.borrow_mut();
        #[cfg(all(feature = "hostfs", unix))]
        {
            paths.host_cwd = host_cwd;
        }
        paths.cwd_mount = p.mount;
        paths.cwd_node = Some(n);
        Ok(())
    }
    pub fn getdents(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        let d = self.descriptor(fd)?;
        self.getdents_description(&d, count)
    }
    fn getdents_description(&self, d: &Descriptor, count: usize) -> Result<Vec<u8>> {
        let o = d.open.borrow();
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
            return Ok(Vec::new());
        }
        let filesystem = p.filesystem(self);
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &filesystem.host {
            let children = host.children(&p.key)?;
            let inode = node.borrow().inode;
            let parent = self.node(&self.parent_location(&p)?)?.borrow().inode;
            return Self::encode_host_directory(&o, count, children, inode, parent);
        }
        let inode = node.borrow().inode;
        let parent = self.node(&self.parent_location(&p)?)?.borrow().inode;
        let mut children = directory::metadata(&filesystem, &p.key);
        let mut prefix = p.clone();
        if prefix != b"/" {
            prefix.push(b'/');
        }
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
        directory::encode(&o.file_position, count, &entries)
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

#[cfg(test)]
mod shared_control_tests;

#[cfg(test)]
mod file_work_tests;

#[cfg(test)]
mod task_transfer;
