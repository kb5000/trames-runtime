// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared virtual namespace; host IO is confined to an explicitly selected store.
mod bpf;
pub mod capabilities;
mod cgroup;
mod credentials;
mod events;
mod executable;
pub use executable::ExecutableFile;
mod inotify;
mod ipc;
mod kernel_log;
mod locks;
mod mapped;
mod memfd;
mod mounts;
use mounts::{Mount, PathArg};
pub use mounts::{MountNamespace, ResolvedPath, CLONE_NEWNS};
mod syscall_names;
pub use ipc::{LocalReceived, LocalRights, LocalSocket};
pub use locks::RecordLock;
mod linux_namespace;
mod pid_namespace;
pub use pid_namespace::{PidNamespace, CLONE_NEWPID};
mod namespace;
mod xattr;
pub use linux_namespace::{
    NamespaceSnapshot, UtsNamespace, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWUTS,
};
mod network;
mod oom;
mod pseudo;
pub use oom::OomTask;
mod pty;
pub mod terminal;
pub use pty::{Pty, PtyEnd};
mod storage;
#[cfg(test)]
mod storage_tests;
pub use credentials::Credentials;
pub use pseudo::{FdInfo, ProcessInfo, RuntimeInfo};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    fmt,
    rc::{Rc, Weak},
};
pub use storage::{DiskOptions, StorageCapacity, StorageLimits, VolumeSpace, DEFAULT_DISK_BYTES};
pub use trames_net::{NetworkMode, Socket as NetSocket};
pub fn kernel_log_capacity() -> usize {
    kernel_log::LOG_CAPACITY
}
pub const MAX_PATH: usize = 4096;
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_NODES: usize = 1024;
pub const MAX_FDS: u32 = 256;
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
struct Pipe {
    inode: u64,
    metadata: Option<Rc<RefCell<Node>>>,
    bytes: VecDeque<u8>,
    readers: u32,
    writers: u32,
    read_epoch: u64,
    write_epoch: u64,
    io_epoch: [u64; 2],
}
struct PipeEnd {
    pipe: Rc<RefCell<Pipe>>,
    read: bool,
    write: bool,
    waiting: Cell<Option<u64>>,
    initial_write_epoch: u64,
}
impl Pipe {
    fn new(inode: u64) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            inode,
            metadata: None,
            bytes: VecDeque::new(),
            readers: 0,
            writers: 0,
            read_epoch: 0,
            write_epoch: 0,
            io_epoch: [0; 2],
        }))
    }
}
impl PipeEnd {
    fn open(pipe: &Rc<RefCell<Pipe>>, flags: u32) -> Result<Option<Rc<Self>>> {
        if flags & O_PATH != 0 {
            return Ok(None);
        }
        let read = flags & 3 != 1;
        let write = flags & 3 != 0;
        if write && !read && flags & O_NONBLOCK != 0 && pipe.borrow().readers == 0 {
            return Err(Errno(6));
        }
        Ok(Some(Self::new(
            pipe.clone(),
            read,
            write,
            flags & O_NONBLOCK == 0,
        )))
    }
    fn new(pipe: Rc<RefCell<Pipe>>, read: bool, write: bool, block: bool) -> Rc<Self> {
        let mut p = pipe.borrow_mut();
        let initial_write_epoch = p.write_epoch.wrapping_sub(u64::from(p.writers != 0));
        let waiting = if block && read && !write && p.writers == 0 {
            Some(p.write_epoch)
        } else if block && write && !read && p.readers == 0 {
            Some(p.read_epoch)
        } else {
            None
        };
        if read {
            p.readers += 1;
            p.read_epoch = p.read_epoch.wrapping_add(1);
            p.io_epoch[1] = p.io_epoch[1].wrapping_add(1);
        }
        if write {
            p.writers += 1;
            p.write_epoch = p.write_epoch.wrapping_add(1);
            p.io_epoch[0] = p.io_epoch[0].wrapping_add(1);
        }
        drop(p);
        Rc::new(Self {
            pipe,
            read,
            write,
            waiting: Cell::new(waiting),
            initial_write_epoch,
        })
    }
}
impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut p = self.pipe.borrow_mut();
        p.readers -= u32::from(self.read);
        p.writers -= u32::from(self.write);
        if self.read {
            p.io_epoch[1] = p.io_epoch[1].wrapping_add(1);
        }
        if self.write {
            p.io_epoch[0] = p.io_epoch[0].wrapping_add(1);
        }
        if p.readers == 0 && p.writers == 0 {
            p.bytes.clear();
        }
    }
}
struct OpenDescription {
    id: u64,
    owner: (u32, u32),
    kind: FdKind,
    flags: u32,
    position: u64,
    node: Option<Rc<RefCell<Node>>>,
    pipe: Option<Rc<PipeEnd>>,
    socket: Option<Rc<NetSocket>>,
    bridge: Option<std::sync::Arc<trames_bridge::Connection>>,
    kernel_log: Option<Rc<RefCell<kernel_log::KernelLog>>>,
    anonymous: Option<events::Anonymous>,
    notification: Option<inotify::Close>,
    local: Option<Rc<LocalSocket>>,
    pty: Option<Rc<PtyEnd>>,
    namespace: Option<linux_namespace::NamespaceHandle>,
    oom: Option<Weak<OomTask>>,
    network_control: Option<network::Control>,
    mount: Option<Rc<Mount>>,
}
impl Drop for OpenDescription {
    fn drop(&mut self) {
        drop(self.notification.take());
    }
}
impl OpenDescription {
    fn metadata_node(&self) -> Option<Rc<RefCell<Node>>> {
        self.node
            .clone()
            .or_else(|| self.pipe.as_ref()?.pipe.borrow().metadata.clone())
    }
}
#[derive(Clone)]
struct Descriptor {
    open: Rc<RefCell<OpenDescription>>,
    cloexec: bool,
}
enum Content {
    Directory,
    File(storage::FileData),
    Symlink(Vec<u8>),
    Null,
    Terminal,
    Device(pseudo::Device),
    Fifo(Rc<RefCell<Pipe>>),
    Socket(Weak<LocalSocket>),
}
struct Node {
    notifications: inotify::Marks,
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
type ResolvedInode = (Rc<RefCell<Node>>, Vec<u8>, Option<Rc<Mount>>);
type ResolvedEntry = (ResolvedPath, Option<ResolvedInode>);
type FlockOwners = Vec<(Weak<RefCell<OpenDescription>>, u32)>;
struct Filesystem {
    shared_budget: trames_shared::SharedBudget,
    paths: BTreeMap<Vec<u8>, Rc<RefCell<Node>>>,
    inodes: Vec<Weak<RefCell<Node>>>,
    next_inode: u64,
    flock: BTreeMap<u64, FlockOwners>,
    record_locks: BTreeMap<u64, Vec<RecordLock>>,
    limits: StorageLimits,
    disk: Option<Rc<storage::DiskStore>>,
    volume: Option<(VolumeSpace, u64)>,
}
#[derive(Clone)]
pub struct Vfs {
    network: trames_net::Network,
    native_services: Rc<RefCell<Option<Rc<RefCell<ipc::NativeServices>>>>>,
    fs: Rc<RefCell<Filesystem>>,
    fds: BTreeMap<u32, Descriptor>,
    cwd_node: Option<Rc<RefCell<Node>>>,
    root_node: Option<Rc<RefCell<Node>>>,
    uts: UtsNamespace,
    root_network: Rc<linux_namespace::RootNetwork>,
    ipc_namespace: Rc<linux_namespace::IpcNamespace>,
    cgroup_namespace: Rc<linux_namespace::CgroupNamespace>,
    pid_ns: PidNamespace,
    pid_children: PidNamespace,
    mounts: Option<MountNamespace>,
    mount_registry: Rc<RefCell<Vec<Weak<Mount>>>>,
    detached_mounts: Rc<RefCell<Vec<Vec<Rc<Mount>>>>>,
    cwd_mount: Option<Rc<Mount>>,
    root_mount: Option<Rc<Mount>>,
    pub umask: u32,
    pub credentials: Credentials,
    pseudo: Rc<RefCell<pseudo::PseudoFs>>,
    kernel_log: Rc<RefCell<kernel_log::KernelLog>>,
    cgroups: Rc<RefCell<cgroup::Cgroups>>,
    dumpable: Rc<Cell<bool>>,
    pid: u32,
    lock_owner: u32,
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
impl Default for Vfs {
    fn default() -> Self {
        let pid_ns = PidNamespace::default();
        let root_network = Rc::new(linux_namespace::RootNetwork::default());
        let network = root_network.network.borrow().clone();
        let mut v = Self {
            network,
            native_services: Rc::default(),
            fs: Rc::new(RefCell::new(Filesystem {
                shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
                paths: BTreeMap::new(),
                inodes: Vec::new(),
                next_inode: 1,
                flock: BTreeMap::new(),
                record_locks: BTreeMap::new(),
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            })),
            fds: BTreeMap::new(),
            cwd_node: None,
            root_node: None,
            uts: UtsNamespace::default(),
            root_network,
            ipc_namespace: Rc::default(),
            cgroup_namespace: Rc::default(),
            pid_ns: pid_ns.clone(),
            pid_children: pid_ns,
            mounts: None,
            mount_registry: Rc::default(),
            detached_mounts: Rc::default(),
            cwd_mount: None,
            root_mount: None,
            umask: 0o022,
            credentials: Credentials::default(),
            pseudo: Rc::new(RefCell::new(pseudo::PseudoFs::default())),
            kernel_log: Rc::new(RefCell::new(kernel_log::KernelLog::default())),
            cgroups: Rc::default(),
            dumpable: Rc::new(Cell::new(true)),
            pid: 1,
            ptys: Rc::default(),
            embedding_terminal: Rc::default(),
            controlling_terminal: None,
            controlling_pair: None,
            lock_owner: 1,
            file_size_limit: u64::MAX,
            file_size_signal: Cell::new(false),
            next_open: Rc::new(Cell::new(1)),
            proc_accessed: Cell::new(false),
            bridge: None,
        };
        v.insert(b"/".to_vec(), Content::Directory, 0o40755)
            .expect("root");
        v.cwd_node = Some(v.node(b"/").expect("root inode"));
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
                    open: Rc::new(RefCell::new(OpenDescription {
                        id: v.open_id(),
                        owner: (v.credentials.fsuid, v.credentials.fsgid),
                        kind,
                        flags,
                        position: 0,
                        node: None,
                        pipe: None,
                        socket: None,
                        bridge: None,
                        kernel_log: None,
                        anonymous: None,
                        notification: None,
                        local: None,
                        pty: None,
                        namespace: None,
                        network_control: None,
                        oom: None,
                        mount: None,
                    })),
                    cloexec: false,
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
        self.fds.values().any(|d| d.open.borrow().bridge.is_some())
    }
    fn open_id(&self) -> u64 {
        let id = self.next_open.get();
        self.next_open.set(id.wrapping_add(1));
        (1u64 << 62) | id
    }
    /// Cooperatively shared clone resources are synchronized at syscall boundaries.
    pub fn share_descriptors_from(&mut self, other: &Self) {
        self.fds.clone_from(&other.fds);
    }
    pub fn share_context_from(&mut self, other: &Self) {
        self.cwd_node.clone_from(&other.cwd_node);
        self.root_node.clone_from(&other.root_node);
        self.cwd_mount.clone_from(&other.cwd_mount);
        self.root_mount.clone_from(&other.root_mount);
        self.umask = other.umask;
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
    pub fn poll_signals(&self, fd: u32, events: u16, pending: u64) -> u16 {
        let Ok(d) = self.descriptor(fd) else {
            return 32;
        };
        Self::poll_open(&d.open.borrow(), events, pending)
    }
    fn poll_open(o: &OpenDescription, events: u16, pending: u64) -> u16 {
        if let Some(end) = &o.pty {
            return end.pair.poll(end.master, events);
        }
        if let Some(log) = &o.kernel_log {
            return log.borrow().poll(o.position, events);
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
            let p = end.pipe.borrow();
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
                    open: Rc::new(RefCell::new(OpenDescription {
                        id: self.open_id(),
                        owner: (self.credentials.fsuid, self.credentials.fsgid),
                        kind: FdKind::Terminal,
                        flags: 2,
                        position: 0,
                        node: None,
                        pipe: None,
                        socket: None,
                        bridge: None,
                        kernel_log: None,
                        anonymous: None,
                        notification: None,
                        local: None,
                        pty: None,
                        namespace: None,
                        network_control: None,
                        oom: None,
                        mount: None,
                    })),
                    cloexec: false,
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
            data.inode().unwrap_or(fs.next_inode)
        } else {
            fs.next_inode
        };
        if inode == fs.next_inode {
            fs.next_inode = fs.next_inode.checked_add(1).ok_or(Errno(28))?;
        }
        if let Content::File(data) = &content {
            data.sync(false)?;
        }
        let node = Rc::new(RefCell::new(Node {
            notifications: inotify::Marks::default(),
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
        fs.inodes.push(Rc::downgrade(&node));
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
    fn node<P: PathArg + ?Sized>(&self, path: &P) -> Result<Rc<RefCell<Node>>> {
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
    fn descriptor(&self, fd: u32) -> Result<&Descriptor> {
        let d = self.fds.get(&fd).ok_or(Errno(9))?;
        if d.open
            .borrow()
            .pipe
            .as_ref()
            .is_some_and(|p| p.waiting.get().is_some())
        {
            return Err(Errno(9));
        }
        Ok(d)
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.fs
            .borrow()
            .inodes
            .iter()
            .filter_map(Weak::upgrade)
            .map(|n| match &n.borrow().content {
                Content::File(b) if n.borrow().seals.is_none() => b.len(),
                _ => 0,
            })
            .sum()
    }
    pub fn cwd(&self) -> Result<Vec<u8>> {
        self.path_visible(&self.location(self.cwd_node.as_ref().ok_or(Errno(2))?, &self.cwd_mount)?)
    }
    fn path_of(&self, node: &Rc<RefCell<Node>>) -> Result<Vec<u8>> {
        if let Some(path) = self.pseudo.borrow().path_of(node) {
            return Ok(path);
        }
        self.fs
            .borrow()
            .paths
            .iter()
            .find(|(_, n)| Rc::ptr_eq(n, node))
            .map(|(p, _)| p.clone())
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
            return self.location(self.cwd_node.as_ref().ok_or(Errno(2))?, &self.cwd_mount);
        }
        let o = self.descriptor(dirfd as u32)?.open.borrow();
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
    ) -> Result<(ResolvedPath, Rc<RefCell<Node>>)> {
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
            0o40000 | (mode & 0o7777 & !self.umask),
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
        self.insert(p, content, type_ | (mode & 0o7777 & !self.umask))
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
                0o100000 | (mode & 0o7777 & !self.umask),
            )?;
        }
        let node = self.node(&p)?;
        {
            let mut n = node.borrow_mut();
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
        .then(|| self.kernel_log.clone());
        let position = kernel_log.as_ref().map_or(0, |log| log.borrow().oldest());
        let pty = if flags & O_PATH != 0 {
            None
        } else {
            match node.borrow().content {
                Content::Device(pseudo::Device::Ptmx) => Some(self.allocate_pty(&p)?),
                Content::Device(pseudo::Device::Pts(id, _)) if id != 0 => {
                    let pair = self.pty_by_id(id).ok_or(Errno(5))?;
                    if pair.locked.get() || !pair.master_alive.get() {
                        return Err(Errno(5));
                    }
                    Some(PtyEnd::new(pair, false))
                }
                Content::Terminal => match self.controlling_terminal {
                    None => return Err(Errno(6)),
                    Some(0) => None,
                    Some(id) => {
                        let pair = self.pty_by_id(id).ok_or(Errno(6))?;
                        if !pair.master_alive.get() {
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
        self.fds.insert(
            fd,
            Descriptor {
                open: Rc::new(RefCell::new(OpenDescription {
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
                    flags: flags & !O_CLOEXEC,
                    position,
                    node: Some(node),
                    mount: p.mount,
                    pipe,
                    socket: None,
                    bridge,
                    kernel_log,
                    anonymous: None,
                    notification,
                    local: None,
                    pty,
                    namespace: None,
                    network_control,
                    oom,
                })),
                cloexec: flags & O_CLOEXEC != 0,
            },
        );
        Ok(fd)
    }
    pub fn close(&mut self, fd: u32) -> Result<()> {
        self.descriptor(fd)?;
        let descriptor = self.fds.remove(&fd).ok_or(Errno(9))?;
        self.release_record_locks(&descriptor);
        Ok(())
    }
    pub fn fifo_open_ready(&self, fd: u32) -> Result<bool> {
        let d = self.fds.get(&fd).ok_or(Errno(9))?;
        let o = d.open.borrow();
        let Some(end) = &o.pipe else { return Ok(true) };
        let Some(epoch) = end.waiting.get() else {
            return Ok(true);
        };
        let p = end.pipe.borrow();
        let ready = if end.read {
            p.writers != 0 || p.write_epoch != epoch
        } else {
            p.readers != 0 || p.read_epoch != epoch
        };
        if ready {
            end.waiting.set(None);
        }
        Ok(ready)
    }
    pub fn cancel_fifo_open(&mut self, fd: u32) {
        self.fds.remove(&fd);
    }
    pub fn close_range(&mut self, first: u32, last: u32, flags: u32) -> Result<()> {
        if first > last || flags & !6 != 0 {
            return Err(Errno(22));
        }
        // The scheduler detaches CLONE_FILES views before UNSHARE reaches here.
        let fds: Vec<_> = self.fds.range(first..=last).map(|(&fd, _)| fd).collect();
        for fd in fds {
            if flags & 4 != 0 {
                self.set_cloexec(fd, true)?;
            } else {
                self.close(fd)?;
            }
        }
        Ok(())
    }
    pub fn close_all(&mut self) {
        let descriptors = std::mem::take(&mut self.fds);
        for d in descriptors.values() {
            self.release_record_locks(d);
        }
    }
    /// Detach a task's view while another task retains the shared file table.
    /// No descriptor has actually closed, so POSIX process locks stay held.
    pub fn detach_file_table(&mut self) {
        self.fds.clear();
    }
    pub fn close_exec(&mut self) {
        let closed: Vec<_> = self
            .fds
            .iter()
            .filter_map(|(&fd, d)| d.cloexec.then_some(fd))
            .collect();
        for fd in closed {
            let _ = self.close(fd);
        }
    }
    pub fn dup(&mut self, old: u32, min: u32, cloexec: bool) -> Result<u32> {
        let mut d = self.descriptor(old)?.clone();
        if min >= MAX_FDS {
            return Err(Errno(22));
        }
        let fd = self.available(min)?;
        d.cloexec = cloexec;
        self.fds.insert(fd, d);
        Ok(fd)
    }
    pub fn dup3(&mut self, old: u32, new: u32, flags: u32) -> Result<u32> {
        if old == new || flags & !O_CLOEXEC != 0 {
            return Err(Errno(22));
        }
        if new >= MAX_FDS {
            return Err(Errno(9));
        }
        let mut d = self.descriptor(old)?.clone();
        d.cloexec = flags & O_CLOEXEC != 0;
        if self.fds.contains_key(&new) {
            self.close(new)?;
        }
        self.fds.insert(new, d);
        Ok(new)
    }
    pub fn flags(&self, fd: u32) -> Result<u32> {
        let d = self.descriptor(fd)?;
        Ok(d.open.borrow().flags | if d.cloexec { O_CLOEXEC } else { 0 })
    }
    pub fn set_cloexec(&mut self, fd: u32, enabled: bool) -> Result<()> {
        self.fds.get_mut(&fd).ok_or(Errno(9))?.cloexec = enabled;
        Ok(())
    }
    pub fn set_status_flags(&mut self, fd: u32, flags: u32) -> Result<()> {
        let d = self.descriptor(fd)?;
        let mut o = d.open.borrow_mut();
        // Embedding input is polled and output can report WouldBlock. Keep
        // O_NONBLOCK on these open descriptions just like guest pipes; the
        // scheduler already retries EAGAIN only for blocking descriptors.
        const CHANGEABLE: u32 = 0x400 | O_NONBLOCK;
        if flags & !(CHANGEABLE | 3 | O_DIRECTORY | O_NOFOLLOW | O_LARGEFILE | 0x101000) != 0 {
            return Err(Errno(22));
        }
        o.flags = (o.flags & !CHANGEABLE) | (flags & CHANGEABLE);
        Ok(())
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
        let inode = p.borrow().inode;
        p.borrow_mut().metadata = Some(Rc::new(RefCell::new(Node {
            notifications: inotify::Marks::default(),
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
        })));
        let read = PipeEnd::new(p.clone(), true, false, false);
        let write = PipeEnd::new(p, false, true, false);
        for (fd, end, kind, access) in [
            (free[0], read, FdKind::PipeRead, 0),
            (free[1], write, FdKind::PipeWrite, 1),
        ] {
            self.fds.insert(
                fd,
                Descriptor {
                    open: Rc::new(RefCell::new(OpenDescription {
                        id: self.open_id(),
                        owner: (self.credentials.fsuid, self.credentials.fsgid),
                        kind,
                        flags: (flags & O_NONBLOCK) | access,
                        position: 0,
                        node: None,
                        pipe: Some(end),
                        socket: None,
                        bridge: None,
                        kernel_log: None,
                        anonymous: None,
                        notification: None,
                        local: None,
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
        Ok([free[0], free[1]])
    }
    pub fn read(&mut self, fd: u32, count: usize) -> Result<Vec<u8>> {
        self.refresh_pseudo_fd(fd)?;
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        if o.flags & O_PATH != 0 || o.flags & 3 == 1 {
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
        if let Some(log) = o.kernel_log.clone() {
            return log.borrow().kmsg_read(&mut o.position, count);
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
            let mut p = end.pipe.borrow_mut();
            if p.bytes.is_empty() && p.writers != 0 {
                return Err(Errno(11));
            }
            let n = count.min(p.bytes.len());
            if n != 0 {
                p.io_epoch[1] = p.io_epoch[1].wrapping_add(1);
            }
            return Ok(p.bytes.drain(..n).collect());
        }
        let node = o.node.clone().ok_or(Errno(9))?;
        let mut n = node.borrow_mut();
        let result = match &n.content {
            Content::File(b) => {
                let out = b.read_at(o.position, count)?;
                o.position += out.len() as u64;
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
        if result.is_ok() {
            mounts::accessed(&mut n, o.mount.as_ref());
        }
        drop(n);
        if result.as_ref().is_ok_and(|b| !b.is_empty())
            && !(node.borrow().seals.is_some() && o.notification.is_none())
        {
            inotify::notify(
                &node,
                inotify::ACCESS,
                o.notification.as_ref().and_then(|c| c.link.as_ref()),
            );
        }
        result
    }
    pub fn write(&mut self, fd: u32, bytes: &[u8]) -> Result<usize> {
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        if o.flags & 3 == 0 {
            return Err(Errno(9));
        }
        if let Some(log) = &o.kernel_log {
            if bytes.len() > 1024 {
                return Err(Errno(22));
            }
            if !bytes.is_empty() {
                log.borrow_mut().append(14, &String::from_utf8_lossy(bytes));
            }
            return Ok(bytes.len());
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
            return socket
                .send_bytes_authorized(
                    bytes,
                    0,
                    None,
                    self.credentials.has_cap(capabilities::NET_ADMIN),
                )
                .map_err(|e| Errno(e.0));
        }
        if let Some(end) = &o.pipe {
            if !end.write {
                return Err(Errno(9));
            }
            let mut p = end.pipe.borrow_mut();
            if p.readers == 0 {
                return Err(Errno(32));
            }
            if bytes.is_empty() {
                return Ok(0);
            }
            let room = PIPE_CAPACITY - p.bytes.len();
            if room == 0 || (bytes.len() <= 4096 && room < bytes.len()) {
                return Err(Errno(11));
            }
            let n = room.min(bytes.len());
            p.bytes.extend(&bytes[..n]);
            p.io_epoch[0] = p.io_epoch[0].wrapping_add(1);
            return Ok(n);
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
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        if o.flags & 3 == 0 {
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
                let position = if o.flags & 0x400 != 0 {
                    b.len()
                } else {
                    offset.unwrap_or(o.position)
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
                    o.position = position + written as u64;
                }
                Ok(written)
            }
        };
        if result.is_ok_and(|n| n != 0) {
            if !self.credentials.has_cap(capabilities::FSETID)
                && matches!(n.content, Content::File(_))
            {
                n.mode &= !0o4000;
                if n.mode & 0o10 != 0 {
                    n.mode &= !0o2000;
                }
            }
            n.times[1] = storage::Timestamp::now();
            n.times[2] = n.times[1];
        }
        let synchronous = o.flags & 0x1000 != 0;
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
        let o = self.descriptor(fd)?.open.borrow();
        if o.bridge.is_some() || o.kernel_log.is_some() {
            return Err(Errno(29));
        }
        if o.flags & O_PATH != 0 || o.flags & 3 == 1 {
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
        let node = o.node.as_ref().ok_or(Errno(29))?;
        let mut n = node.borrow_mut();
        let result = match &n.content {
            Content::File(b) => b.read_at(offset, count),
            Content::Null => Ok(Vec::new()),
            Content::Device(device) => device.read(count),
            Content::Directory => Err(Errno(21)),
            Content::Socket(_) => Err(Errno(6)),
            Content::Symlink(_) => Err(Errno(40)),
            Content::Terminal | Content::Fifo(_) => Err(Errno(29)),
        };
        if count != 0 && result.is_ok() {
            mounts::accessed(&mut n, o.mount.as_ref());
        }
        drop(n);
        if result.as_ref().is_ok_and(|b| !b.is_empty())
            && !(node.borrow().seals.is_some() && o.notification.is_none())
        {
            inotify::notify(
                node,
                inotify::ACCESS,
                o.notification.as_ref().and_then(|c| c.link.as_ref()),
            );
        }
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
        let o = self.descriptor(fd)?.open.borrow();
        if o.flags & 3 == 0 {
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
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        if o.flags & O_PATH != 0 {
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
        let node = o.node.clone().ok_or(Errno(29))?;
        let n = node.borrow();
        if let Some(log) = &o.kernel_log {
            let position = log.borrow().seek(offset, whence)?;
            o.position = position;
            return Ok(0);
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
        let base = match whence {
            0 => 0,
            1 => o.position as i64,
            2 => length as i64,
            _ => return Err(Errno(22)),
        };
        let new = base
            .checked_add(offset)
            .filter(|&n| n >= 0)
            .ok_or(Errno(22))?;
        o.position = new as u64;
        Ok(new as u64)
    }
    fn stat_node(&self, node: &Node, mount: Option<&Rc<Mount>>) -> Result<[u8; 128]> {
        let mut out = [0; 128];
        out[..8].copy_from_slice(&node.device.to_le_bytes());
        out[8..16].copy_from_slice(&node.inode.to_le_bytes());
        out[16..20].copy_from_slice(&node.mode.to_le_bytes());
        let mut links = node.links;
        if links != 0 && matches!(node.content, Content::Directory) {
            // Persistent links count path owners; stat counts . and children's .. too.
            let fs = mount.map_or(&self.fs, |m| &m.fs).borrow();
            let path = fs
                .paths
                .iter()
                .find(|(_, n)| n.borrow().inode == node.inode)
                .map(|(p, _)| p.clone())
                .or_else(|| {
                    self.pseudo
                        .borrow()
                        .nodes
                        .iter()
                        .find(|(_, n)| n.borrow().inode == node.inode)
                        .map(|((_, p), _)| p.clone())
                });
            if let Some(path) = path {
                let mut prefix = path.clone();
                if prefix != b"/" {
                    prefix.push(b'/');
                }
                let mut directories = std::collections::BTreeSet::new();
                for (p, n) in fs.paths.range(prefix.clone()..) {
                    if !p.starts_with(&prefix) {
                        break;
                    }
                    let name = &p[prefix.len()..];
                    if !name.is_empty()
                        && !name.contains(&b'/')
                        && matches!(n.borrow().content, Content::Directory)
                    {
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
        let blocks = if let Content::File(data) = &node.content {
            if node.volatile {
                0
            } else {
                data.blocks()?
            }
        } else {
            0
        };
        out[64..72].copy_from_slice(&blocks.to_le_bytes());
        for (offset, t) in [72, 88, 104].into_iter().zip(node.times) {
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
        self.stat_open(&d.open.borrow())
    }
    fn stat_open(&self, o: &OpenDescription) -> Result<[u8; 128]> {
        if let Some(n) = o.metadata_node() {
            return self.stat_node(&n.borrow(), o.mount.as_ref());
        }
        if matches!(o.kind, FdKind::Terminal) {
            if let Ok(n) = self.node(b"/dev/pts/0") {
                return self.stat_node(&n.borrow(), o.mount.as_ref());
            }
        }
        self.stat_node(
            &Node {
                notifications: inotify::Marks::default(),
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
                    || o.pipe.as_ref().map_or(o.id, |p| p.pipe.borrow().inode),
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
        self.cwd_mount = mount;
        self.cwd_node = Some(node);
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
        self.cwd_mount = p.mount;
        self.cwd_node = Some(n);
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
        for (path, node) in fs.paths.range(prefix.key.clone()..) {
            if !path.starts_with(&prefix) {
                break;
            }
            let name = &path[prefix.len()..];
            if name.is_empty() || name.contains(&b'/') {
                continue;
            }
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
