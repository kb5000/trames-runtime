// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux namespace identities are owned objects, never host namespace handles.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

pub const CLONE_NEWUTS: u64 = 0x0400_0000;
const MAX_NAMESPACES: usize = 128;
static NEXT_INODE: AtomicU64 = AtomicU64::new(0xf000_0000);

struct Uts {
    inode: u64,
    names: RefCell<[Vec<u8>; 2]>,
    live: Rc<Cell<usize>>,
}
impl Drop for Uts {
    fn drop(&mut self) {
        self.live.set(self.live.get() - 1);
    }
}
#[derive(Clone)]
pub struct UtsNamespace(Rc<Uts>);
impl Default for UtsNamespace {
    fn default() -> Self {
        Self::new([b"trames".to_vec(), b"(none)".to_vec()], Rc::default())
            .expect("initial UTS namespace")
    }
}
impl UtsNamespace {
    fn new(names: [Vec<u8>; 2], live: Rc<Cell<usize>>) -> Result<Self> {
        if live.get() >= MAX_NAMESPACES {
            return Err(Errno(28));
        }
        let inode = NEXT_INODE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        live.set(live.get() + 1);
        Ok(Self(Rc::new(Uts {
            inode,
            names: RefCell::new(names),
            live,
        })))
    }
    pub fn id(&self) -> u64 {
        self.0.inode
    }
    pub fn name(&self, domain: bool) -> Vec<u8> {
        self.0.names.borrow()[usize::from(domain)].clone()
    }
    fn copy(&self) -> Result<Self> {
        Self::new(self.0.names.borrow().clone(), self.0.live.clone())
    }
    pub(super) fn label(&self) -> Vec<u8> {
        format!("uts:[{}]", self.id()).into_bytes()
    }
}

#[derive(Clone)]
pub(super) enum NamespaceHandle {
    Uts(UtsNamespace),
    Mount(MountNamespace),
}
impl NamespaceHandle {
    pub fn id(&self) -> u64 {
        match self {
            Self::Uts(n) => n.id(),
            Self::Mount(n) => n.id(),
        }
    }
    pub fn kind(&self) -> u64 {
        match self {
            Self::Uts(_) => CLONE_NEWUTS,
            Self::Mount(_) => CLONE_NEWNS,
        }
    }
    pub fn label(&self) -> Vec<u8> {
        match self {
            Self::Uts(n) => n.label(),
            Self::Mount(n) => format!("mnt:[{}]", n.id()).into_bytes(),
        }
    }
}

#[derive(Clone, Default)]
pub struct NamespaceSnapshot {
    uts: Weak<Uts>,
    pub(super) mount: Weak<RefCell<mounts::Table>>,
    pub(super) root: Option<(Weak<Mount>, Weak<RefCell<Node>>)>,
}

impl Vfs {
    pub fn namespace_snapshot(&self) -> NamespaceSnapshot {
        NamespaceSnapshot {
            uts: Rc::downgrade(&self.uts.0),
            mount: self
                .mounts
                .as_ref()
                .map_or_else(Weak::new, |n| Rc::downgrade(&n.0)),
            root: self.root_mount.as_ref().map(|m| {
                (
                    Rc::downgrade(m),
                    Rc::downgrade(self.root_node.as_ref().unwrap_or(&m.root)),
                )
            }),
        }
    }
    pub fn unshare_uts(&mut self) -> Result<()> {
        if self.credentials.euid != 0 {
            return Err(Errno(1));
        }
        self.uts = self.uts.copy()?;
        Ok(())
    }
    pub fn set_uts_name(&mut self, domain: bool, name: &[u8]) -> Result<()> {
        if self.credentials.euid != 0 {
            return Err(Errno(1));
        }
        if name.len() > 64 {
            return Err(Errno(22));
        }
        self.uts.0.names.borrow_mut()[usize::from(domain)] = name.to_vec();
        Ok(())
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
        if self.credentials.euid != 0 {
            return Err(Errno(1));
        }
        match ns {
            NamespaceHandle::Uts(ns) => self.uts = ns,
            NamespaceHandle::Mount(ns) => {
                let root = ns.0.borrow().root.clone();
                self.mounts = Some(ns);
                self.root_node = Some(root.root.clone());
                self.cwd_node = Some(root.root.clone());
                self.root_mount = Some(root.clone());
                self.cwd_mount = Some(root);
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
    pub(super) fn namespace_for_path(&self, path: &[u8]) -> Result<Option<NamespaceHandle>> {
        let Some(rest) = path.strip_prefix(b"/proc/") else {
            return Ok(None);
        };
        let parts: Vec<_> = rest.split(|b| *b == b'/').collect();
        let (group, pid, kind) = match parts.as_slice() {
            [pid, b"ns", kind @ (b"uts" | b"mnt")] => (None, *pid, *kind),
            [group, b"task", pid, b"ns", kind @ (b"uts" | b"mnt")] => (Some(*group), *pid, *kind),
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
        let process = pseudo
            .runtime
            .processes
            .iter()
            .find(|p| Some(p.pid) == parse(pid) && group.is_none_or(|g| Some(p.tgid) == parse(g)))
            .ok_or(Errno(2))?;
        if self.credentials.fsuid != 0 && self.credentials.fsuid != process.credentials.euid {
            return Err(Errno(13));
        }
        Ok(Some(match kind {
            b"uts" => NamespaceHandle::Uts(UtsNamespace(
                process.namespaces.uts.upgrade().ok_or(Errno(2))?,
            )),
            _ => NamespaceHandle::Mount(MountNamespace(
                process.namespaces.mount.upgrade().ok_or(Errno(2))?,
            )),
        }))
    }
    pub(super) fn namespace_description(
        &self,
        ns: NamespaceHandle,
    ) -> Rc<RefCell<OpenDescription>> {
        Rc::new(RefCell::new(OpenDescription {
            id: ns.id(),
            owner: (0, 0),
            kind: FdKind::Anonymous,
            flags: 0,
            position: 0,
            node: None,
            pipe: None,
            socket: None,
            bridge: None,
            kernel_log: None,
            anonymous: None,
            local: None,
            pty: None,
            namespace: Some(ns),
            mount: None,
        }))
    }
    /// Linux chroot changes only fs.root. Existing cwd/dirfds remain capabilities.
    pub fn chroot(&mut self, path: &[u8]) -> Result<()> {
        if self.credentials.euid != 0 {
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
        self.root_mount = path.mount;
        self.root_node = Some(node);
        Ok(())
    }
}

pub(super) fn snapshot_label(snapshot: &NamespaceSnapshot, kind: &[u8]) -> Option<Vec<u8>> {
    match kind {
        b"uts" => snapshot.uts.upgrade().map(|ns| UtsNamespace(ns).label()),
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
