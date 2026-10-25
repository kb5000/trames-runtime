// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux namespace identities are owned objects, never host namespace handles.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const MAX_NAMESPACES: usize = 128;
static NEXT_INODE: AtomicU64 = AtomicU64::new(0xf000_0000);

/// A network identity owns both its IP stack and abstract Unix address space.
/// Existing socket FDs retain their creating stack after unshare/setns.
pub(super) struct RootNetwork {
    inode: u64,
    pub network: RefCell<trames_net::Network>,
    pub local: Rc<RefCell<ipc::LocalNamespace>>,
    live: Rc<Cell<usize>>,
}
impl Default for RootNetwork {
    fn default() -> Self {
        Self {
            inode: NEXT_INODE.fetch_add(1, Ordering::Relaxed),
            network: RefCell::default(),
            local: Rc::default(),
            live: Rc::new(Cell::new(1)),
        }
    }
}
impl Drop for RootNetwork {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}
pub(super) struct IpcNamespace {
    inode: u64,
    pub mqueue: RefCell<Option<FsHandle>>,
    live: Rc<Cell<usize>>,
}
impl Default for IpcNamespace {
    fn default() -> Self {
        Self {
            inode: NEXT_INODE.fetch_add(1, Ordering::Relaxed),
            mqueue: RefCell::default(),
            live: Rc::new(Cell::new(1)),
        }
    }
}
impl Drop for IpcNamespace {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}
pub(super) struct CgroupNamespace {
    inode: u64,
    pub root: Option<NodeRef>,
    pub path: Vec<u8>,
    live: Rc<Cell<usize>>,
}
impl Default for CgroupNamespace {
    fn default() -> Self {
        Self {
            inode: NEXT_INODE.fetch_add(1, Ordering::Relaxed),
            root: None,
            path: b"/".to_vec(),
            live: Rc::new(Cell::new(1)),
        }
    }
}
impl Drop for CgroupNamespace {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}

struct Uts {
    inode: u64,
    names: std::sync::Mutex<[Vec<u8>; 2]>,
    live: Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for Uts {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}
#[derive(Clone)]
pub struct UtsNamespace(Arc<Uts>);
impl Default for UtsNamespace {
    fn default() -> Self {
        Self::new([b"trames".to_vec(), b"(none)".to_vec()], Arc::default())
            .expect("initial UTS namespace")
    }
}
impl UtsNamespace {
    fn new(names: [Vec<u8>; 2], live: Arc<std::sync::atomic::AtomicUsize>) -> Result<Self> {
        live.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < MAX_NAMESPACES).then_some(n + 1)
        })
        .map_err(|_| Errno(28))?;
        let inode = NEXT_INODE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| {
                live.fetch_sub(1, Ordering::Relaxed);
                Errno(28)
            })?;
        Ok(Self(Arc::new(Uts {
            inode,
            names: std::sync::Mutex::new(names),
            live,
        })))
    }
    pub fn id(&self) -> u64 {
        self.0.inode
    }
    pub fn name(&self, domain: bool) -> Vec<u8> {
        self.0.names.lock().unwrap()[usize::from(domain)].clone()
    }
    fn copy(&self) -> Result<Self> {
        Self::new(self.0.names.lock().unwrap().clone(), self.0.live.clone())
    }
    pub(super) fn label(&self) -> Vec<u8> {
        format!("uts:[{}]", self.id()).into_bytes()
    }
}
/// The UTS object is live and shared; only mutation authority is frozen for
/// a worker epoch. Credentials/unshare/setns still commit at the task boundary.
#[derive(Clone)]
pub struct UtsAccess {
    namespace: UtsNamespace,
    authorized: bool,
}
impl UtsAccess {
    pub fn names(&self) -> [Vec<u8>; 2] {
        self.namespace.0.names.lock().unwrap().clone()
    }
    pub fn set(&self, domain: bool, name: &[u8]) -> Result<()> {
        if !self.authorized {
            return Err(Errno(1));
        }
        if name.len() > 64 {
            return Err(Errno(22));
        }
        self.namespace.0.names.lock().unwrap()[usize::from(domain)] = name.to_vec();
        Ok(())
    }
}

#[derive(Clone)]
pub(super) enum NamespaceHandle {
    Uts(UtsNamespace),
    Mount(MountNamespace),
    Pid(PidNamespace),
    Net(Rc<RootNetwork>),
    Ipc(Rc<IpcNamespace>),
    Cgroup(Rc<CgroupNamespace>),
}
impl NamespaceHandle {
    pub fn id(&self) -> u64 {
        match self {
            Self::Uts(n) => n.id(),
            Self::Mount(n) => n.id(),
            Self::Pid(n) => n.id(),
            Self::Net(n) => n.inode,
            Self::Ipc(n) => n.inode,
            Self::Cgroup(n) => n.inode,
        }
    }
    pub fn kind(&self) -> u64 {
        match self {
            Self::Uts(_) => CLONE_NEWUTS,
            Self::Mount(_) => CLONE_NEWNS,
            Self::Pid(_) => CLONE_NEWPID,
            Self::Net(_) => CLONE_NEWNET,
            Self::Ipc(_) => CLONE_NEWIPC,
            Self::Cgroup(_) => CLONE_NEWCGROUP,
        }
    }
    pub fn label(&self) -> Vec<u8> {
        match self {
            Self::Uts(n) => n.label(),
            Self::Mount(n) => format!("mnt:[{}]", n.id()).into_bytes(),
            Self::Pid(n) => n.label(),
            Self::Net(n) => format!("net:[{}]", n.inode).into_bytes(),
            Self::Ipc(n) => format!("ipc:[{}]", n.inode).into_bytes(),
            Self::Cgroup(n) => format!("cgroup:[{}]", n.inode).into_bytes(),
        }
    }
}

#[derive(Clone, Default)]
pub struct NamespaceSnapshot {
    uts: std::sync::Weak<Uts>,
    pub(super) net: Weak<RootNetwork>,
    ipc: Weak<IpcNamespace>,
    cgroup: Weak<CgroupNamespace>,
    pub(super) pid: std::sync::Weak<pid_namespace::PidSpace>,
    pub(super) pid_children: std::sync::Weak<pid_namespace::PidSpace>,
    pub(super) mount: Weak<RefCell<mounts::Table>>,
    pub(super) root: Option<(Weak<Mount>, std::sync::Weak<Inode>)>,
}

impl Vfs {
    pub fn namespace_snapshot(&self) -> NamespaceSnapshot {
        let paths = self.context.paths.borrow();
        NamespaceSnapshot {
            uts: Arc::downgrade(&self.uts.0),
            net: Rc::downgrade(&self.root_network),
            ipc: Rc::downgrade(&self.ipc_namespace),
            cgroup: Rc::downgrade(&self.cgroup_namespace),
            pid: Arc::downgrade(&self.pid_ns.0),
            pid_children: Arc::downgrade(&self.pid_children.0),
            mount: self
                .mounts
                .as_ref()
                .map_or_else(Weak::new, |n| Rc::downgrade(&n.0)),
            root: paths.root_mount.as_ref().map(|m| {
                (
                    Rc::downgrade(m),
                    Arc::downgrade(paths.root_node.as_ref().unwrap_or(&m.root)),
                )
            }),
        }
    }
    pub fn unshare_net(&mut self) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let live = self.root_network.live.clone();
        if live.get() >= MAX_NAMESPACES {
            return Err(Errno(28));
        }
        let network = self.network.isolated().map_err(|e| Errno(e.0))?;
        let inode = NEXT_INODE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        live.set(live.get() + 1);
        self.root_network = Rc::new(RootNetwork {
            inode,
            network: RefCell::new(network.clone()),
            local: Rc::default(),
            live,
        });
        self.network = network;
        Ok(())
    }
    pub fn unshare_ipc(&mut self) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let live = self.ipc_namespace.live.clone();
        if live.get() >= MAX_NAMESPACES {
            return Err(Errno(28));
        }
        let inode = NEXT_INODE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        live.set(live.get() + 1);
        self.ipc_namespace = Rc::new(IpcNamespace {
            inode,
            mqueue: RefCell::default(),
            live,
        });
        Ok(())
    }
    pub fn unshare_cgroup(&mut self) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let live = self.cgroup_namespace.live.clone();
        if live.get() >= MAX_NAMESPACES {
            return Err(Errno(28));
        }
        let path = self.cgroup_path(self.pid);
        let root = self
            .cgroups
            .borrow()
            .fs
            .borrow()
            .paths
            .get(&path)
            .cloned()
            .ok_or(Errno(2))?;
        let inode = NEXT_INODE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        live.set(live.get() + 1);
        self.cgroup_namespace = Rc::new(CgroupNamespace {
            inode,
            root: Some(root),
            path,
            live,
        });
        Ok(())
    }
    pub(super) fn cgroup_view_path(&self, path: &[u8]) -> Vec<u8> {
        let components = |p: &[u8]| {
            p.split(|b| *b == b'/')
                .filter(|p| !p.is_empty())
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
        };
        let root = components(&self.cgroup_namespace.path);
        let target = components(path);
        let common = root.iter().zip(&target).take_while(|(a, b)| a == b).count();
        let mut parts = vec![b"..".to_vec(); root.len() - common];
        parts.extend_from_slice(&target[common..]);
        let mut out = b"/".to_vec();
        out.extend(parts.join(&b'/'));
        out
    }
    pub fn unshare_uts(&mut self) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        self.uts = self.uts.copy()?;
        Ok(())
    }
    pub fn set_uts_name(&mut self, domain: bool, name: &[u8]) -> Result<()> {
        self.uts_capability().set(domain, name)
    }
    pub fn uts_capability(&self) -> UtsAccess {
        UtsAccess {
            namespace: self.uts.clone(),
            authorized: self.credentials.has_cap(capabilities::SYS_ADMIN),
        }
    }
    pub fn uts_name(&self, domain: bool) -> Vec<u8> {
        self.uts.name(domain)
    }
    pub fn setns(&mut self, fd: u32, kind: u64) -> Result<()> {
        let ns = self
            .descriptor(fd)?
            .open
            .borrow()
            .namespace
            .clone()
            .ok_or(Errno(22))?;
        if kind != 0 && kind != ns.kind() {
            return Err(Errno(22));
        }
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        match ns {
            NamespaceHandle::Net(ns) => {
                self.network = ns.network.borrow().clone();
                self.root_network = ns;
            }
            NamespaceHandle::Ipc(ns) => self.ipc_namespace = ns,
            NamespaceHandle::Cgroup(ns) => self.cgroup_namespace = ns,
            NamespaceHandle::Uts(ns) => self.uts = ns,
            NamespaceHandle::Pid(ns) => {
                if !self.pid_ns.contains(&ns) {
                    return Err(Errno(22));
                }
                self.pid_children = ns;
            }
            NamespaceHandle::Mount(ns) => {
                let root = ns.0.borrow().root.clone();
                self.mounts = Some(ns);
                let mut paths = self.context.paths.borrow_mut();
                paths.root_node = Some(root.root.clone());
                paths.cwd_node = Some(root.root.clone());
                paths.root_mount = Some(root.clone());
                paths.cwd_mount = Some(root);
            }
        }
        Ok(())
    }
    pub fn namespace_type(&self, fd: u32) -> Result<Option<u64>> {
        Ok(self
            .descriptor(fd)?
            .open
            .borrow()
            .namespace
            .as_ref()
            .map(NamespaceHandle::kind))
    }
    pub(super) fn namespace_for_path(
        &self,
        path: &ResolvedPath,
    ) -> Result<Option<NamespaceHandle>> {
        if let Some(ns) = path.mount.as_ref().and_then(|m| m.namespace.clone()) {
            return Ok(Some(ns));
        }
        let Some(rest) = path.strip_prefix(b"/proc/") else {
            return Ok(None);
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let (group, pid, kind) = match parts.as_slice() {
            [pid, b"ns", kind @ (b"uts" | b"mnt" | b"pid" | b"pid_for_children" | b"net" | b"ipc"
            | b"cgroup")] => (None, *pid, *kind),
            [group, b"task", pid, b"ns", kind @ (b"uts" | b"mnt" | b"pid" | b"pid_for_children" | b"net" | b"ipc"
            | b"cgroup")] => (Some(*group), *pid, *kind),
            _ => return Ok(None),
        };
        let parse = |p: &[u8]| {
            std::str::from_utf8(p)
                .ok()
                .and_then(|p| p.parse::<u32>().ok())
        };
        let pseudo = self.pseudo.borrow();
        if !pseudo.enabled {
            return Ok(None);
        }
        let runtime = self.proc_runtime(path, &pseudo.runtime);
        let process = runtime
            .processes
            .iter()
            .find(|p| Some(p.pid) == parse(pid) && group.is_none_or(|g| Some(p.tgid) == parse(g)))
            .ok_or(Errno(2))?;
        if !self.may_inspect(path, &runtime, process) {
            return Err(Errno(13));
        }
        Ok(Some(match kind {
            b"net" => NamespaceHandle::Net(process.namespaces.net.upgrade().ok_or(Errno(2))?),
            b"ipc" => NamespaceHandle::Ipc(process.namespaces.ipc.upgrade().ok_or(Errno(2))?),
            b"cgroup" => {
                NamespaceHandle::Cgroup(process.namespaces.cgroup.upgrade().ok_or(Errno(2))?)
            }
            b"uts" => NamespaceHandle::Uts(UtsNamespace(
                process.namespaces.uts.upgrade().ok_or(Errno(2))?,
            )),
            b"pid" | b"pid_for_children" => NamespaceHandle::Pid(PidNamespace(
                if kind == b"pid" {
                    &process.namespaces.pid
                } else {
                    &process.namespaces.pid_children
                }
                .upgrade()
                .ok_or(Errno(2))?,
            )),
            _ => NamespaceHandle::Mount(MountNamespace(
                process.namespaces.mount.upgrade().ok_or(Errno(2))?,
            )),
        }))
    }
    pub(super) fn namespace_description(&self, ns: NamespaceHandle) -> OpenHandle {
        OpenHandle::new(OpenDescription {
            shared: Arc::new(SharedOpenDescription {
                mount_resource: std::sync::OnceLock::new(),
                read_node: None,
                id: ns.id(),
                owner: (0, 0),
                kind: FdKind::Anonymous,
                flags: (0).into(),
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
            namespace: Some(ns),
            network_control: None,
            oom: None,
            mount: None,
        })
    }
    /// Linux chroot changes only fs.root. Existing cwd/dirfds remain capabilities.
    pub fn chroot(&mut self, path: &[u8]) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_CHROOT) {
            return Err(Errno(1));
        }
        let path = self.resolve(AT_FDCWD, path)?;
        let node = self.node(&path)?;
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        if !self.allowed(&node.borrow(), 1) {
            return Err(Errno(13));
        }
        let mut paths = self.context.paths.borrow_mut();
        paths.root_mount = path.mount;
        paths.root_node = Some(node);
        Ok(())
    }
}

pub(super) fn snapshot_label(snapshot: &NamespaceSnapshot, kind: &[u8]) -> Option<Vec<u8>> {
    match kind {
        b"net" => snapshot
            .net
            .upgrade()
            .map(|ns| NamespaceHandle::Net(ns).label()),
        b"ipc" => snapshot
            .ipc
            .upgrade()
            .map(|ns| NamespaceHandle::Ipc(ns).label()),
        b"cgroup" => snapshot
            .cgroup
            .upgrade()
            .map(|ns| NamespaceHandle::Cgroup(ns).label()),
        b"uts" => snapshot.uts.upgrade().map(|ns| UtsNamespace(ns).label()),
        b"pid" => snapshot.pid.upgrade().map(|ns| PidNamespace(ns).label()),
        b"pid_for_children" => snapshot
            .pid_children
            .upgrade()
            .filter(|ns| {
                PidNamespace(ns.clone()).init() != 1 || !PidNamespace(ns.clone()).is_nested()
            })
            .map(|ns| PidNamespace(ns).label()),
        b"mnt" => snapshot
            .mount
            .upgrade()
            .map(|ns| NamespaceHandle::Mount(MountNamespace(ns)).label()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn snapshot(v: &mut Vfs) {
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    namespaces: v.namespace_snapshot(),
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
    }
    #[test]
    fn root_network_handle_binds_pins_and_reenters_without_creating_isolation() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        assert!(v.accesses_proc(AT_FDCWD, b"/proc/self/ns/net"));
        let fd = v.open_at(AT_FDCWD, b"/proc/self/ns/net", 0, 0).unwrap();
        let before = v.stat_fd(fd).unwrap();
        assert_eq!(v.namespace_type(fd), Ok(Some(CLONE_NEWNET)));
        v.import_file(b"/network", vec![]).unwrap();
        v.mount(Some(b"/proc/self/ns/net"), b"/network", None, 4096, None)
            .unwrap();
        let bound = v.open_at(AT_FDCWD, b"/network", 0, 0).unwrap();
        assert_eq!(v.stat_fd(bound).unwrap(), before);
        assert_eq!(v.stat_at(AT_FDCWD, b"/network").unwrap(), before);
        assert_eq!(
            u64::from_le_bytes(v.statfs_at(b"/network").unwrap()[..8].try_into().unwrap()),
            0x6e736673
        );
        assert_eq!(v.read(bound, 1), Err(Errno(22)));
        assert_eq!(v.setns(bound, CLONE_NEWUTS), Err(Errno(22)));
        v.unshare_mounts().unwrap();
        v.umount(b"/network", 2).unwrap();
        v.close(fd).unwrap();
        v.setns(bound, CLONE_NEWNET).unwrap();
        assert_eq!(v.namespace_type(bound), Ok(Some(CLONE_NEWNET)));
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(v.setns(bound, CLONE_NEWNET), Err(Errno(1)));
    }
    #[test]
    fn isolated_network_has_private_ports_abstract_names_and_retains_old_fds() {
        let mut root = Vfs::default();
        root.configure_network(NetworkMode::Loopback).unwrap();
        snapshot(&mut root);
        let nsfd = root.open_at(AT_FDCWD, b"/proc/self/ns/net", 0, 0).unwrap();
        let server = root.socket(2, 1, 0).unwrap();
        let server = root.socket_fd(server).unwrap();
        server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        server.listen(2).unwrap();
        let address = server.local_addr().unwrap();
        let old = root.socket(2, 1, 0).unwrap();
        let name = b"\x01\0\0isolated";
        let abstract_fd = root.socket(1, 1, 0).unwrap();
        let abstract_socket = root.local_socket(abstract_fd).unwrap().unwrap();
        root.local_bind(&abstract_socket, name).unwrap();
        abstract_socket.listen(2).unwrap();
        let old_abstract = root.socket(1, 1, 0).unwrap();
        let mut child = root.clone();
        child.unshare_net().unwrap();
        assert!(!child.loopback_up());
        assert!(child.network_info().is_none());
        assert_ne!(root.network.namespace_id(), child.network.namespace_id());
        let fd = child.socket(2, 1, 0).unwrap();
        let private = child.socket_fd(fd).unwrap();
        assert_eq!(private.bind(address), Err(trames_net::NetError(99)));
        child.set_loopback_up(true).unwrap();
        private.bind(address).unwrap();
        private.listen(2).unwrap();
        let client = child.socket(2, 1, 0).unwrap();
        let client = child.socket_fd(client).unwrap();
        assert_eq!(client.connect(address), Err(trames_net::NetError(115)));
        let end = std::time::Instant::now() + Duration::from_secs(2);
        let accepted = loop {
            if let Ok((s, _)) = private.accept() {
                break s;
            }
            assert!(std::time::Instant::now() < end);
            trames_net::wait(&[(private.clone(), 1)], Duration::from_millis(1)).unwrap();
        };
        assert_eq!(server.poll(1), Ok(0));
        client.send(b"private", 0, None).unwrap();
        let received = loop {
            if let Ok(r) = accepted.recv(7, 0) {
                break r.data;
            }
            assert!(std::time::Instant::now() < end);
            trames_net::wait(&[(accepted.clone(), 1)], Duration::from_millis(1)).unwrap();
        };
        assert_eq!(received, b"private");
        assert_eq!(
            client.info().unwrap().namespace_id,
            child.network.namespace_id()
        );
        assert_eq!(
            child.socket_fd(old).unwrap().info().unwrap().namespace_id,
            root.network.namespace_id()
        );
        let local = child.socket(1, 1, 0).unwrap();
        let local = child.local_socket(local).unwrap().unwrap();
        assert_eq!(child.local_connect(&local, name), Err(Errno(111)));
        child.local_bind(&local, name).unwrap();
        local.listen(1).unwrap();
        let inherited = child.local_socket(old_abstract).unwrap().unwrap();
        child.local_connect(&inherited, name).unwrap();
        assert!(abstract_socket.poll(1) & 1 != 0);
        assert_eq!(local.poll(1) & 1, 0);
        child.setns(nsfd, CLONE_NEWNET).unwrap();
        assert_eq!(child.network.namespace_id(), root.network.namespace_id());
        assert_eq!(private.local_addr(), Ok(address));
        child.credentials = Credentials::user(1000, 1000);
        let previous = child.network.namespace_id();
        assert_eq!(child.unshare_net(), Err(Errno(1)));
        assert_eq!(child.network.namespace_id(), previous);
    }
    #[test]
    fn ipc_namespace_mqueue_identity_and_pinned_mounts_are_independent() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let original = v.open_at(AT_FDCWD, b"/proc/self/ns/ipc", 0, 0).unwrap();
        v.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/c", 0o755).unwrap();
        v.mount(None, b"/a", Some(b"mqueue"), 0, None).unwrap();
        let a = v.open_at(AT_FDCWD, b"/a", 0, 0).unwrap();
        v.unshare_ipc().unwrap();
        snapshot(&mut v);
        let own = v.open_at(AT_FDCWD, b"/proc/self/ns/ipc", 0, 0).unwrap();
        assert_ne!(
            v.stat_fd(original).unwrap()[8..16],
            v.stat_fd(own).unwrap()[8..16]
        );
        assert_eq!(v.namespace_type(own), Ok(Some(CLONE_NEWIPC)));
        v.mount(None, b"/b", Some(b"mqueue"), 0, None).unwrap();
        let b = v.open_at(AT_FDCWD, b"/b", 0, 0).unwrap();
        assert_ne!(v.stat_fd(a).unwrap()[0..8], v.stat_fd(b).unwrap()[0..8]);
        v.setns(original, 0).unwrap();
        v.mount(None, b"/c", Some(b"mqueue"), 0, None).unwrap();
        let c = v.open_at(AT_FDCWD, b"/c", 0, 0).unwrap();
        assert_eq!(v.stat_fd(a).unwrap()[0..8], v.stat_fd(c).unwrap()[0..8]);
    }
    #[test]
    fn network_sysctls_pin_their_namespace_and_change_actual_ping_policy() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        snapshot(&mut v);
        let root = v.open_at(AT_FDCWD, b"/proc/self/ns/net", 0, 0).unwrap();
        let original = v
            .open_at(AT_FDCWD, b"/proc/sys/net/ipv4/ping_group_range", 2, 0)
            .unwrap();
        v.unshare_net().unwrap();
        assert_eq!(v.socket(2, 2, 1), Err(Errno(13)));
        let own = v
            .open_at(AT_FDCWD, b"/proc/sys/net/ipv4/ping_group_range", 2, 0)
            .unwrap();
        assert_eq!(v.read(own, 100).unwrap(), b"1\t0\n");
        v.seek(own, 0, 0).unwrap();
        v.write(own, b"0 2147483647\n").unwrap();
        let ping = v.socket(2, 2, 1).unwrap();
        v.close(ping).unwrap();
        v.write(original, b"1000 2000\n").unwrap();
        assert_eq!(v.network.ping_range(), [0, 2147483647]);
        let port = v
            .open_at(
                AT_FDCWD,
                b"/proc/sys/net/ipv4/ip_unprivileged_port_start",
                2,
                0,
            )
            .unwrap();
        assert_eq!(v.write(port, b"65536\n"), Err(Errno(22)));
        v.write(port, b"0\n").unwrap();
        assert_eq!(v.network.unprivileged_port(), 0);
        v.setns(root, CLONE_NEWNET).unwrap();
        assert_eq!(v.network.ping_range(), [1000, 2000]);
        assert_eq!(v.network.unprivileged_port(), 1024);
        v.credentials.caps.effective &= !(1 << capabilities::NET_ADMIN);
        v.seek(own, 0, 0).unwrap();
        assert_eq!(v.write(own, b"0 0"), Ok(3));
        v.credentials = Credentials::user(1000, 1000);
        v.seek(own, 0, 0).unwrap();
        assert_eq!(v.write(own, b"0 0"), Err(Errno(13)));
    }
    #[test]
    fn private_cgroup_namespace_rebases_proc_and_new_mount_without_moving_tasks() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/outer", 0o755)
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/outer/inner", 0o755)
            .unwrap();
        let membership = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/outer/cgroup.procs", 1, 0)
            .unwrap();
        v.write(membership, b"1").unwrap();
        v.close(membership).unwrap();
        let root = v.open_at(AT_FDCWD, b"/proc/self/ns/cgroup", 0, 0).unwrap();
        v.unshare_cgroup().unwrap();
        assert_eq!(v.cgroup_path(1), b"/outer");
        assert_eq!(v.cgroup_view_path(b"/outer"), b"/");
        assert_eq!(v.cgroup_view_path(b"/outer/inner"), b"/inner");
        assert_eq!(v.cgroup_view_path(b"/"), b"/..");
        v.mkdir_at(AT_FDCWD, b"/private-cgroup", 0o755).unwrap();
        v.mount(None, b"/private-cgroup", Some(b"cgroup2"), 0, None)
            .unwrap();
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/private-cgroup").unwrap()[..16],
            &v.stat_at(AT_FDCWD, b"/sys/fs/cgroup/outer").unwrap()[..16]
        );
        assert!(v.stat_at(AT_FDCWD, b"/private-cgroup/inner").is_ok());
        assert!(v.stat_at(AT_FDCWD, b"/private-cgroup/outer").is_err());
        v.setns(root, CLONE_NEWCGROUP).unwrap();
        assert_eq!(v.cgroup_view_path(b"/outer"), b"/outer");
    }
    #[test]
    fn worker_uts_names_and_last_namespace_reference_share_real_state() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<UtsNamespace>();
        send_sync::<UtsAccess>();
        let mut v = Vfs::default();
        let root = v.uts_capability();
        let old = v.namespace_snapshot().uts;
        let quota = v.uts.0.live.clone();
        v.unshare_uts().unwrap();
        let isolated = v.uts_capability();
        std::thread::scope(|scope| {
            scope.spawn(|| root.set(false, b"original-worker").unwrap());
            scope.spawn(|| isolated.set(false, b"private-worker").unwrap());
        });
        assert_eq!(v.uts_name(false), b"private-worker");
        assert_eq!(root.names()[0], b"original-worker");
        assert_eq!(quota.load(Ordering::Relaxed), 2);
        v.credentials = Credentials::user(1000, 1000);
        let denied = v.uts_capability();
        std::thread::spawn(move || {
            assert_eq!(denied.set(false, b"denied"), Err(Errno(1)));
            drop(root);
        })
        .join()
        .unwrap();
        assert!(old.upgrade().is_none());
        assert_eq!(quota.load(Ordering::Relaxed), 1);
        drop(v);
        std::thread::spawn(move || drop(isolated)).join().unwrap();
        assert_eq!(quota.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn concurrent_namespace_reservations_do_not_exceed_quota() {
        let ns = UtsNamespace::default();
        let mut retained = Vec::new();
        for _ in 1..MAX_NAMESPACES - 1 {
            retained.push(ns.copy().unwrap());
        }
        let gate = Arc::new(std::sync::Barrier::new(8));
        let results = std::thread::scope(|scope| {
            let mut threads = Vec::new();
            for _ in 0..8 {
                let ns = ns.clone();
                let gate = gate.clone();
                threads.push(scope.spawn(move || {
                    gate.wait();
                    ns.copy()
                }));
            }
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert!(results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| *e == Errno(28)));
        assert_eq!(ns.0.live.load(Ordering::Relaxed), MAX_NAMESPACES);
        std::thread::spawn(move || drop(results)).join().unwrap();
        assert!(ns.copy().is_ok());
    }
    #[test]
    fn namespace_fd_pins_identity_across_unshare_and_setns() {
        let mut v = Vfs::default();
        snapshot(&mut v);
        let original = v.uts.id();
        let fd = v
            .open_at(AT_FDCWD, b"/proc/self/ns/uts", O_CLOEXEC, 0)
            .unwrap();
        let before = v.stat_fd(fd).unwrap();
        assert_eq!(
            v.fd_snapshot()
                .into_iter()
                .find(|f| f.fd == fd)
                .unwrap()
                .inode,
            original
        );
        v.symlink_at(b"/proc/self/ns/uts", AT_FDCWD, b"/uts")
            .unwrap();
        let alias = v.open_at(AT_FDCWD, b"/uts", O_PATH, 0).unwrap();
        assert_eq!(v.stat_fd(alias).unwrap(), before);
        assert_eq!(v.namespace_type(alias), Ok(Some(CLONE_NEWUTS)));
        v.close(alias).unwrap();
        assert_eq!(
            u64::from_le_bytes(before[8..16].try_into().unwrap()),
            original
        );
        assert_eq!(v.read(fd, 16), Err(Errno(22)));
        let epoll = v.epoll_create(0).unwrap();
        assert_eq!(v.epoll_ctl(epoll, 1, fd, 1, 0), Err(Errno(1)));
        v.close(epoll).unwrap();
        v.unshare_uts().unwrap();
        v.set_uts_name(false, b"child").unwrap();
        assert_ne!(v.uts.id(), original);
        snapshot(&mut v);
        assert_ne!(
            v.readlink_at(AT_FDCWD, b"/proc/self/ns/uts").unwrap(),
            format!("uts:[{original}]").as_bytes()
        );
        assert_eq!(v.setns(fd, 0x20000), Err(Errno(22)));
        v.setns(fd, 0).unwrap();
        assert_eq!(v.uts.id(), original);
        assert_eq!(v.uts_name(false), b"trames");
        assert_eq!(v.stat_fd(fd).unwrap(), before);
        assert_eq!(
            u64::from_le_bytes(v.statfs_fd(fd).unwrap()[..8].try_into().unwrap()),
            0x6e736673
        );
        v.close(fd).unwrap();
    }
    #[test]
    fn namespace_quota_is_released_with_last_object_reference() {
        let mut v = Vfs::default();
        let mut retained = Vec::new();
        for _ in 1..MAX_NAMESPACES {
            retained.push(v.uts.clone());
            v.unshare_uts().unwrap();
        }
        let before = v.uts.id();
        assert_eq!(v.unshare_uts(), Err(Errno(28)));
        assert_eq!(v.uts.id(), before);
        retained.clear();
        v.unshare_uts().unwrap();
        assert_ne!(v.uts.id(), before);
    }
    #[test]
    fn clone_shares_names_until_unshare_and_checks_privilege() {
        let mut parent = Vfs::default();
        let mut child = parent.clone();
        child.set_uts_name(false, b"shared").unwrap();
        assert_eq!(parent.uts_name(false), b"shared");
        child.unshare_uts().unwrap();
        child.set_uts_name(false, b"isolated").unwrap();
        assert_eq!(parent.uts_name(false), b"shared");
        parent.credentials = Credentials::user(1000, 1000);
        assert_eq!(parent.unshare_uts(), Err(Errno(1)));
        assert_eq!(parent.set_uts_name(false, b"denied"), Err(Errno(1)));
    }
    #[test]
    fn chroot_clamps_dotdot_and_absolute_links_but_preserves_open_dirfds() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/jail", 0o755).unwrap();
        v.mkdir_at(AT_FDCWD, b"/jail/sub", 0o755).unwrap();
        v.import_file(b"/jail/inside", b"yes".to_vec()).unwrap();
        v.import_file(b"/outside", b"outside".to_vec()).unwrap();
        v.symlink_at(b"/inside", AT_FDCWD, b"/jail/link").unwrap();
        let rootfd = v.open_at(AT_FDCWD, b"/", O_PATH | O_DIRECTORY, 0).unwrap();
        let parent = v.clone();
        v.chroot(b"/jail").unwrap();
        assert_eq!(v.cwd(), Err(Errno(2))); // chroot does not chdir
        v.chdir(b"/").unwrap();
        assert_eq!(v.cwd().unwrap(), b"/");
        assert_eq!(
            v.resolve(AT_FDCWD, b"/../../inside").unwrap(),
            b"/jail/inside"
        );
        let fd = v.open_at(AT_FDCWD, b"/link", 0, 0).unwrap();
        assert_eq!(v.read(fd, 8).unwrap(), b"yes");
        assert_eq!(v.open_at(AT_FDCWD, b"/outside", 0, 0), Err(Errno(2)));
        assert!(v.open_at(rootfd as i32, b"outside", 0, 0).is_ok());
        assert!(parent.stat_at(AT_FDCWD, b"/outside").is_ok());
        v.chdir(b"sub").unwrap();
        assert_eq!(v.cwd().unwrap(), b"/sub");
        v.credentials = Credentials::user(1000, 1000);
        assert_eq!(v.chroot(b"/"), Err(Errno(1)));
    }
}
