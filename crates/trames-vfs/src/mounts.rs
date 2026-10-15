// SPDX-License-Identifier: GPL-3.0-or-later
//! Mount identity is separate from storage inode identity. All objects are
//! scheduler-owned; this adds no CPU-memory or host worker synchronization.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub(super) const MS_RDONLY: u64 = 1;
pub(super) const MS_NOSUID: u64 = 2;
pub(super) const MS_NODEV: u64 = 4;
pub(super) const MS_NOEXEC: u64 = 8;
pub(super) const MS_RELATIME: u64 = 1 << 21;
const MAX_MOUNTS: usize = 128;
static NEXT_MOUNT: AtomicU64 = AtomicU64::new(16);
static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(0xe000_0000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Root,
    Tmpfs,
    Proc,
    Sysfs,
    Devpts,
    Cgroup,
}
#[derive(Clone)]
pub(super) struct Attachment {
    pub parent: Rc<Mount>,
    pub node: Rc<RefCell<Node>>,
    pub fallback: Vec<u8>,
}
impl Attachment {
    fn key(&self) -> Vec<u8> {
        if self.node.borrow().volatile
            || self
                .parent
                .fs
                .borrow()
                .paths
                .get(&self.fallback)
                .is_some_and(|n| Rc::ptr_eq(n, &self.node))
        {
            return self.fallback.clone();
        }
        self.parent
            .key_of(&self.node)
            .unwrap_or_else(|| self.fallback.clone())
    }
}
pub(super) struct Mount {
    pub id: u64,
    pub fs: Rc<RefCell<Filesystem>>,
    pub root: Rc<RefCell<Node>>,
    pub root_key: Vec<u8>,
    pub kind: Kind,
    pub pid_namespace: Option<PidNamespace>,
    pub flags: Cell<u64>,
    pub writers: Cell<usize>,
    pub parent: RefCell<Option<Attachment>>,
}
impl Mount {
    pub fn readonly(&self) -> bool {
        self.flags.get() & MS_RDONLY != 0
    }
    pub fn writable(&self) -> Result<()> {
        if self.readonly() {
            Err(Errno(30))
        } else {
            Ok(())
        }
    }
    pub fn key_of(&self, node: &Rc<RefCell<Node>>) -> Option<Vec<u8>> {
        if Rc::ptr_eq(node, &self.root) {
            return Some(self.root_path());
        }
        let root = self.root_path();
        self.fs
            .borrow()
            .paths
            .iter()
            .find(|(p, n)| below(p, &root) && Rc::ptr_eq(n, node))
            .map(|(p, _)| p.clone())
    }
    fn root_path(&self) -> Vec<u8> {
        let fs = self.fs.borrow();
        if fs
            .paths
            .get(&self.root_key)
            .is_some_and(|n| Rc::ptr_eq(n, &self.root))
        {
            return self.root_key.clone();
        }
        fs.paths
            .iter()
            .find(|(_, n)| Rc::ptr_eq(n, &self.root))
            .map_or_else(|| self.root_key.clone(), |(p, _)| p.clone())
    }
}
pub(super) struct Table {
    pub id: u64,
    pub root: Rc<Mount>,
    pub mounts: Vec<Rc<Mount>>,
}
#[derive(Clone)]
pub struct MountNamespace(pub(super) Rc<RefCell<Table>>);
impl MountNamespace {
    pub fn id(&self) -> u64 {
        self.0.borrow().id
    }
}

/// A resolved storage key together with the exact mount used to reach it.
/// Plain byte paths are reserved for the embedding/storage implementation.
#[derive(Clone)]
pub struct ResolvedPath {
    pub(super) key: Vec<u8>,
    pub(super) mount: Option<Rc<Mount>>,
}
impl std::fmt::Debug for ResolvedPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedPath")
            .field("key", &self.key)
            .field("mount", &self.mount.as_ref().map(|m| m.id))
            .finish()
    }
}
impl std::ops::Deref for ResolvedPath {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.key
    }
}
impl std::ops::DerefMut for ResolvedPath {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.key
    }
}
impl AsRef<[u8]> for ResolvedPath {
    fn as_ref(&self) -> &[u8] {
        &self.key
    }
}
impl PartialEq for ResolvedPath {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
            && self.mount.as_ref().map(|m| m.id) == other.mount.as_ref().map(|m| m.id)
    }
}
impl<const N: usize> PartialEq<&[u8; N]> for ResolvedPath {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.key == *other
    }
}
impl From<Vec<u8>> for ResolvedPath {
    fn from(key: Vec<u8>) -> Self {
        Self { key, mount: None }
    }
}
impl ResolvedPath {
    pub fn into_bytes(self) -> Vec<u8> {
        self.key
    }
    pub(super) fn filesystem(&self, vfs: &Vfs) -> Rc<RefCell<Filesystem>> {
        self.mount
            .as_ref()
            .map_or_else(|| vfs.fs.clone(), |m| m.fs.clone())
    }
    pub(super) fn writable(&self) -> Result<()> {
        self.mount.as_ref().map_or(Ok(()), |m| m.writable())
    }
    pub(super) fn parent(&self) -> Self {
        let mut p = self.clone();
        p.key
            .truncate(p.key.iter().rposition(|b| *b == b'/').unwrap_or(0).max(1));
        p
    }
}
pub(super) trait PathArg {
    fn key(&self) -> &[u8];
    fn mount(&self) -> Option<&Rc<Mount>> {
        None
    }
}
impl PathArg for [u8] {
    fn key(&self) -> &[u8] {
        self
    }
}
impl<const N: usize> PathArg for [u8; N] {
    fn key(&self) -> &[u8] {
        self
    }
}
impl PathArg for Vec<u8> {
    fn key(&self) -> &[u8] {
        self
    }
}
impl PathArg for ResolvedPath {
    fn key(&self) -> &[u8] {
        &self.key
    }
    fn mount(&self) -> Option<&Rc<Mount>> {
        self.mount.as_ref()
    }
}

impl Vfs {
    pub(super) fn initialize_mounts(&mut self) -> Result<()> {
        let root = self
            .fs
            .borrow()
            .paths
            .get(b"/".as_slice())
            .cloned()
            .ok_or(Errno(2))?;
        let root = Rc::new(Mount {
            id: 1,
            fs: self.fs.clone(),
            root,
            root_key: b"/".to_vec(),
            kind: Kind::Root,
            pid_namespace: None,
            flags: Cell::new(MS_RELATIME),
            writers: Cell::new(0),
            parent: RefCell::new(None),
        });
        let mut mounts = vec![root.clone()];
        let enabled = self.pseudo.borrow().enabled;
        self.pseudo.borrow_mut().enabled = true;
        for (id, path, kind, flags) in [
            (2, b"/proc".as_slice(), Kind::Proc, 15),
            (3, b"/sys".as_slice(), Kind::Sysfs, 15),
            (4, b"/dev/pts".as_slice(), Kind::Devpts, 10),
        ] {
            let node = self.pseudo_node(path)?.ok_or(Errno(2))?;
            mounts.push(Rc::new(Mount {
                id,
                fs: self.fs.clone(),
                root: node.clone(),
                root_key: path.to_vec(),
                kind,
                pid_namespace: (kind == Kind::Proc).then(|| self.pid_ns.clone()),
                flags: Cell::new(flags),
                writers: Cell::new(0),
                parent: RefCell::new(Some(Attachment {
                    parent: root.clone(),
                    node,
                    fallback: path.to_vec(),
                })),
            }));
        }
        let point = self.pseudo_node(b"/sys/fs/cgroup")?.ok_or(Errno(2))?;
        let fs = self.cgroups.borrow().fs.clone();
        let cgroup_root = fs.borrow().paths[b"/".as_slice()].clone();
        mounts.push(Rc::new(Mount {
            id: 5,
            fs,
            root: cgroup_root,
            root_key: b"/".to_vec(),
            kind: Kind::Cgroup,
            pid_namespace: None,
            flags: Cell::new(14),
            writers: Cell::new(0),
            parent: RefCell::new(Some(Attachment {
                parent: mounts[2].clone(),
                node: point,
                fallback: b"/sys/fs/cgroup".to_vec(),
            })),
        }));
        self.pseudo.borrow_mut().enabled = enabled;
        self.cwd_mount = Some(root.clone());
        self.root_mount = Some(root.clone());
        self.register_mounts(&mounts)?;
        self.mounts = Some(MountNamespace(Rc::new(RefCell::new(Table {
            id: NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed),
            root,
            mounts,
        }))));
        Ok(())
    }
    pub(super) fn location(
        &self,
        node: &Rc<RefCell<Node>>,
        mount: &Option<Rc<Mount>>,
    ) -> Result<ResolvedPath> {
        let key = match mount {
            Some(m) => m
                .key_of(node)
                .or_else(|| self.pseudo.borrow().path_of(node))
                .ok_or(Errno(2))?,
            None => self.path_of(node)?,
        };
        Ok(ResolvedPath {
            key,
            mount: mount.clone(),
        })
    }
    pub(super) fn root_location(&self) -> Result<ResolvedPath> {
        if let Some(n) = &self.root_node {
            self.location(n, &self.root_mount)
        } else {
            let root = self
                .mounts
                .as_ref()
                .ok_or(Errno(2))?
                .0
                .borrow()
                .root
                .clone();
            Ok(ResolvedPath {
                key: root.root_path(),
                mount: Some(root),
            })
        }
    }
    pub(super) fn follow_mounts(&self, mut path: ResolvedPath) -> Result<ResolvedPath> {
        for _ in 0..MAX_MOUNTS {
            let Some(current) = &path.mount else {
                return Ok(path);
            };
            let next =
                self.mount_registry
                    .borrow()
                    .iter()
                    .rev()
                    .filter_map(Weak::upgrade)
                    .find(|m| {
                        (self.pseudo.borrow().enabled
                            || !matches!(
                                m.kind,
                                Kind::Proc | Kind::Sysfs | Kind::Devpts | Kind::Cgroup
                            ))
                            && m.parent.borrow().as_ref().is_some_and(|a| {
                                Rc::ptr_eq(&a.parent, current) && a.key() == path.key
                            })
                    });
            let Some(next) = next else {
                return Ok(path);
            };
            path = ResolvedPath {
                key: next.root_path(),
                mount: Some(next),
            };
        }
        Err(Errno(40))
    }
    pub(super) fn parent_location(&self, path: &ResolvedPath) -> Result<ResolvedPath> {
        if *path == self.root_location()? {
            return Ok(path.clone());
        }
        let mut at = path.clone();
        for _ in 0..MAX_MOUNTS {
            let Some(m) = &at.mount else {
                return Ok(at.parent());
            };
            if at.key != m.root_path() {
                return Ok(at.parent());
            }
            let attachment = m.parent.borrow().clone();
            let Some(a) = attachment else {
                return Ok(at);
            };
            at = ResolvedPath {
                key: a.key(),
                mount: Some(a.parent),
            };
            if at == self.root_location()? {
                return Ok(at);
            }
        }
        Err(Errno(40))
    }
    pub(super) fn path_visible(&self, path: &ResolvedPath) -> Result<Vec<u8>> {
        let root = self.root_location()?;
        let mut at = path.clone();
        let mut suffix = Vec::new();
        for _ in 0..=MAX_MOUNTS {
            if at.mount.as_ref().map(|m| m.id) == root.mount.as_ref().map(|m| m.id)
                && below(&at.key, &root.key)
            {
                let cut = if root.key == b"/" { 0 } else { root.key.len() };
                let mut out = at.key[cut..].to_vec();
                out.extend(suffix);
                return Ok(if out.is_empty() { b"/".to_vec() } else { out });
            }
            let m = at.mount.as_ref().ok_or(Errno(2))?;
            let prefix = m.root_path();
            if !at.key.starts_with(&prefix) {
                return Err(Errno(2));
            }
            let cut = if at.key == prefix {
                prefix.len()
            } else if prefix == b"/" {
                0
            } else {
                prefix.len()
            };
            let mut tail = at.key[cut..].to_vec();
            tail.extend(suffix);
            suffix = tail;
            let a = m.parent.borrow().clone().ok_or(Errno(2))?;
            at = ResolvedPath {
                key: a.key(),
                mount: Some(a.parent),
            };
        }
        Err(Errno(40))
    }
    pub fn unshare_mounts(&mut self) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let old = self.mounts.as_ref().ok_or(Errno(22))?.0.borrow();
        let mut copies = BTreeMap::new();
        for m in &old.mounts {
            copies.insert(
                m.id,
                Rc::new(Mount {
                    id: new_mount_id()?,
                    fs: m.fs.clone(),
                    root: m.root.clone(),
                    root_key: m.root_key.clone(),
                    kind: m.kind,
                    pid_namespace: m.pid_namespace.clone(),
                    flags: Cell::new(m.flags.get()),
                    writers: Cell::new(0),
                    parent: RefCell::new(None),
                }),
            );
        }
        for m in &old.mounts {
            if let Some(a) = m.parent.borrow().as_ref() {
                *copies[&m.id].parent.borrow_mut() = Some(Attachment {
                    parent: copies[&a.parent.id].clone(),
                    node: a.node.clone(),
                    fallback: a.fallback.clone(),
                });
            }
        }
        let remap = |mount: &mut Option<Rc<Mount>>| {
            if let Some(new) = mount.as_ref().and_then(|m| copies.get(&m.id)) {
                *mount = Some(new.clone());
            }
        };
        let root = copies[&old.root.id].clone();
        let mounts: Vec<_> = old.mounts.iter().map(|m| copies[&m.id].clone()).collect();
        drop(old);
        self.register_mounts(&mounts)?;
        remap(&mut self.cwd_mount);
        remap(&mut self.root_mount);
        self.mounts = Some(MountNamespace(Rc::new(RefCell::new(Table {
            id: NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed),
            root,
            mounts,
        }))));
        Ok(())
    }
}

impl Vfs {
    pub(super) fn uses_pseudo<P: PathArg + ?Sized>(&self, path: &P) -> bool {
        match path.mount().map(|m| m.kind) {
            Some(Kind::Tmpfs | Kind::Cgroup) => false,
            Some(Kind::Root) => {
                let p = path.key();
                !p.starts_with(b"/proc/")
                    && !p.starts_with(b"/sys/")
                    && !p.starts_with(b"/dev/pts/")
            }
            _ => true,
        }
    }
    pub(super) fn is_mount_root(&self, path: &ResolvedPath) -> bool {
        path.mount
            .as_ref()
            .is_some_and(|m| path.key == m.root_path())
    }
    pub(super) fn empty_data_at(&self, path: &ResolvedPath) -> Result<storage::FileData> {
        Self::filesystem_empty_data(&mut path.filesystem(self).borrow_mut())
    }
    pub(super) fn fd_writable(&self, fd: u32) -> Result<()> {
        self.descriptor(fd)?
            .open
            .borrow()
            .mount
            .as_ref()
            .map_or(Ok(()), |m| m.writable())
    }
    pub(super) fn fd_available_bytes(&self, fd: u32) -> Result<u64> {
        let open = self.descriptor(fd)?.open.borrow();
        let bytes =
            Self::filesystem_capacity(&open.mount.as_ref().map_or(&self.fs, |m| &m.fs).borrow())
                .available_bytes;
        Ok(bytes)
    }
    pub fn mapping_executable(&self, fd: u32) -> Result<bool> {
        Ok(self
            .descriptor(fd)?
            .open
            .borrow()
            .mount
            .as_ref()
            .is_none_or(|m| m.flags.get() & MS_NOEXEC == 0))
    }
}

impl Vfs {
    /// Mounts belong entirely to the guest. No host mount or pathname is used.
    pub fn mount(
        &mut self,
        source: Option<&[u8]>,
        target: &[u8],
        kind: Option<&[u8]>,
        flags: u64,
        data: Option<&[u8]>,
    ) -> Result<()> {
        const BIND: u64 = 4096;
        const REC: u64 = 16384;
        const REMOUNT: u64 = 32;
        const PRIVATE: u64 = 1 << 18;
        const ATTRS: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME;
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let flags = if flags & 0xffff0000 == 0xc0ed0000 {
            flags & 0xffff
        } else {
            flags
        };
        let flags = flags & !0x8000; // MS_SILENT only suppresses kernel mount diagnostics.
        let target = self.resolve(AT_FDCWD, target)?;
        let target_node = self.node(&target)?;
        let parent = target.mount.as_ref().ok_or(Errno(22))?.clone();
        if self
            .mounts
            .as_ref()
            .is_none_or(|ns| !ns.0.borrow().mounts.iter().any(|m| Rc::ptr_eq(m, &parent)))
        {
            return Err(Errno(22));
        }
        if flags & PRIVATE != 0 {
            if flags & !(PRIVATE | REC) != 0 {
                return Err(Errno(22));
            }
            // All current mounts are private; shared/slave propagation is not
            // accepted until actual cross-namespace propagation exists.
            return Ok(());
        }
        if flags & REMOUNT != 0 {
            if flags & !(REMOUNT | BIND | ATTRS) != 0 {
                return Err(Errno(95));
            }
            if !self.is_mount_root(&target) {
                return Err(Errno(22));
            }
            if matches!(parent.kind, Kind::Proc | Kind::Sysfs) && flags & MS_RDONLY == 0 {
                return Err(Errno(30));
            }
            if flags & MS_RDONLY != 0 && parent.writers.get() != 0 {
                return Err(Errno(16));
            }
            parent.flags.set(flags & ATTRS);
            return Ok(());
        }
        if flags & !(ATTRS | BIND | REC) != 0 {
            return Err(Errno(95));
        }
        if flags & REC != 0 && flags & BIND == 0 {
            return Err(Errno(22));
        }
        let ns = self.mounts.as_ref().ok_or(Errno(22))?;
        let mut additions = Vec::new();
        let (fs, root, root_key, mount_kind, attrs) = if flags & BIND != 0 {
            let source = self.resolve(AT_FDCWD, source.ok_or(Errno(22))?)?;
            let node = self.node(&source)?;
            if matches!(node.borrow().content, Content::Directory)
                != matches!(target_node.borrow().content, Content::Directory)
            {
                return Err(Errno(20));
            }
            let m = source.mount.as_ref().ok_or(Errno(22))?;
            if flags & REC != 0 {
                for child in &ns.0.borrow().mounts {
                    if Rc::ptr_eq(child, m) {
                        continue;
                    }
                    let mut at = child.clone();
                    for _ in 0..MAX_MOUNTS {
                        let Some(a) = at.parent.borrow().clone() else {
                            break;
                        };
                        if Rc::ptr_eq(&a.parent, m) {
                            let key = a.key();
                            if below(&key, &source.key) {
                                additions.push(child.clone());
                            }
                            break;
                        }
                        at = a.parent;
                    }
                }
            }
            (m.fs.clone(), node, source.key, m.kind, m.flags.get())
        } else {
            if !matches!(target_node.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            match kind.ok_or(Errno(22))? {
                b"tmpfs" => {
                    let (limit, nodes, mode) = tmpfs_options(data.unwrap_or_default())?;
                    let id = new_mount_id()?;
                    let inode = id << 32;
                    let root = Rc::new(RefCell::new(Node {
                        device: id,
                        content: Content::Directory,
                        mode: 0o40000 | mode,
                        uid: self.credentials.fsuid,
                        gid: self.credentials.fsgid,
                        volatile: false,
                        inode,
                        links: 1,
                        times: [storage::Timestamp::now(); 3],
                        seals: None,
                    }));
                    let fs = Rc::new(RefCell::new(Filesystem {
                        paths: BTreeMap::from([(b"/".to_vec(), root.clone())]),
                        inodes: vec![Rc::downgrade(&root)],
                        next_inode: inode + 1,
                        flock: BTreeMap::new(),
                        record_locks: BTreeMap::new(),
                        limits: StorageLimits {
                            file_bytes: limit,
                            nodes,
                        },
                        disk: None,
                        volume: None,
                    }));
                    (fs, root, b"/".to_vec(), Kind::Tmpfs, flags & ATTRS)
                }
                b"cgroup2" => {
                    if data.is_some_and(|d| !d.is_empty()) {
                        return Err(Errno(95));
                    }
                    let fs = self.cgroups.borrow().fs.clone();
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    (fs, root, b"/".to_vec(), Kind::Cgroup, flags & ATTRS)
                }
                b"proc" | b"sysfs" | b"devpts" => {
                    if data.is_some_and(|d| !d.is_empty()) {
                        return Err(Errno(95));
                    }
                    let (key, k) = match kind.unwrap() {
                        b"proc" => (b"/proc".as_slice(), Kind::Proc),
                        b"sysfs" => (b"/sys".as_slice(), Kind::Sysfs),
                        _ => (b"/dev/pts".as_slice(), Kind::Devpts),
                    };
                    let node = self.pseudo_node(key)?.ok_or(Errno(19))?;
                    (
                        self.fs.clone(),
                        node,
                        key.to_vec(),
                        k,
                        (flags & ATTRS) | if k == Kind::Devpts { 0 } else { MS_RDONLY },
                    )
                }
                _ => return Err(Errno(19)),
            }
        };
        if ns.0.borrow().mounts.len() + additions.len() + 1 > MAX_MOUNTS {
            return Err(Errno(28));
        }
        let proc_ns = if flags & 4096 != 0 {
            self.resolve(AT_FDCWD, source.ok_or(Errno(22))?)?
                .mount
                .and_then(|m| m.pid_namespace.clone())
        } else {
            (mount_kind == Kind::Proc).then(|| self.pid_ns.clone())
        };
        let root = Rc::new(Mount {
            id: new_mount_id()?,
            fs,
            root,
            root_key,
            kind: mount_kind,
            pid_namespace: proc_ns,
            flags: Cell::new(attrs),
            writers: Cell::new(0),
            parent: RefCell::new(Some(Attachment {
                parent,
                node: target_node,
                fallback: target.key,
            })),
        });
        let mut copies = BTreeMap::new();
        if !additions.is_empty() {
            let source = self.resolve(AT_FDCWD, source.ok_or(Errno(22))?)?;
            copies.insert(source.mount.as_ref().ok_or(Errno(22))?.id, root.clone());
            for m in &additions {
                copies.insert(m.id, copy_mount(m)?);
            }
            for m in &additions {
                let a = m.parent.borrow().clone().ok_or(Errno(22))?;
                *copies[&m.id].parent.borrow_mut() = Some(Attachment {
                    parent: copies.get(&a.parent.id).ok_or(Errno(22))?.clone(),
                    node: a.node,
                    fallback: a.fallback,
                });
            }
        }
        let mut added = vec![root];
        added.extend(additions.iter().map(|m| copies[&m.id].clone()));
        self.register_mounts(&added)?;
        let mut table = ns.0.borrow_mut();
        table.mounts.extend(added);
        Ok(())
    }
    pub fn umount(&mut self, target: &[u8], flags: u64) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        if flags & !(2 | 8) != 0 {
            return Err(Errno(22));
        }
        let target = self.resolve_final(AT_FDCWD, target, flags & 8 == 0)?;
        let mount = target.mount.as_ref().ok_or(Errno(22))?;
        if !self.is_mount_root(&target) {
            return Err(Errno(22));
        }
        let mut table = self.mounts.as_ref().ok_or(Errno(22))?.0.borrow_mut();
        if Rc::ptr_eq(mount, &table.root) {
            return Err(Errno(16));
        }
        if !table.mounts.iter().any(|m| Rc::ptr_eq(m, mount)) {
            return Err(Errno(22));
        }
        let mut ids = vec![mount.id];
        loop {
            let before = ids.len();
            for m in &table.mounts {
                if !ids.contains(&m.id)
                    && m.parent
                        .borrow()
                        .as_ref()
                        .is_some_and(|a| ids.contains(&a.parent.id))
                {
                    ids.push(m.id);
                }
            }
            if ids.len() == before {
                break;
            }
        }
        if flags & 2 == 0 && (ids.len() > 1 || Rc::strong_count(mount) > 2) {
            return Err(Errno(16));
        }
        let detached: Vec<_> = table
            .mounts
            .iter()
            .filter(|m| ids.contains(&m.id))
            .cloned()
            .collect();
        table.mounts.retain(|m| !ids.contains(&m.id));
        if flags & 2 != 0 {
            self.detached_mounts.borrow_mut().push(detached);
        }
        *mount.parent.borrow_mut() = None;
        Ok(())
    }
    pub fn pivot_root(&mut self, new_root: &[u8], put_old: &[u8]) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let new = self.resolve(AT_FDCWD, new_root)?;
        let old = self.resolve(AT_FDCWD, put_old)?;
        let new_mount = new.mount.as_ref().ok_or(Errno(22))?.clone();
        let old_mount = old.mount.as_ref().ok_or(Errno(22))?.clone();
        let old_node = self.node(&old)?;
        if !matches!(new_mount.root.borrow().content, Content::Directory)
            || !matches!(old_node.borrow().content, Content::Directory)
        {
            return Err(Errno(20));
        }
        let ns = self.mounts.as_ref().ok_or(Errno(22))?;
        let current_root = self.root_location()?;
        if !self.is_mount_root(&new)
            || !Rc::ptr_eq(&new_mount, &old_mount)
            || old.key == new.key
            || !below(&old.key, &new.key)
            || !self.is_mount_root(&current_root)
        {
            return Err(Errno(22));
        }
        let mut table = ns.0.borrow_mut();
        if Rc::ptr_eq(&new_mount, &table.root)
            || current_root
                .mount
                .as_ref()
                .is_none_or(|m| !Rc::ptr_eq(m, &table.root))
        {
            return Err(Errno(16));
        }
        let previous = table.root.clone();
        *new_mount.parent.borrow_mut() = None;
        *previous.parent.borrow_mut() = Some(Attachment {
            parent: new_mount.clone(),
            node: old_node,
            fallback: old.key,
        });
        table.root = new_mount.clone();
        drop(table);
        self.rebase_pivot_context(&previous, &new_mount);
        Ok(())
    }
    fn rebase_pivot_context(&mut self, previous: &Rc<Mount>, new: &Rc<Mount>) {
        if self
            .cwd_mount
            .as_ref()
            .is_some_and(|m| Rc::ptr_eq(m, previous))
            && self
                .cwd_node
                .as_ref()
                .is_some_and(|n| Rc::ptr_eq(n, &previous.root))
        {
            self.cwd_mount = Some(new.clone());
            self.cwd_node = Some(new.root.clone());
        }
        if self.root_node.is_none()
            || self
                .root_mount
                .as_ref()
                .is_some_and(|m| Rc::ptr_eq(m, previous))
                && self
                    .root_node
                    .as_ref()
                    .is_some_and(|n| Rc::ptr_eq(n, &previous.root))
        {
            self.root_mount = Some(new.clone());
            self.root_node = Some(new.root.clone());
        }
    }
    pub fn sync_pivot_from(&mut self, before: &Vfs, after: &Vfs) {
        if let (Some(ours), Some(theirs), Some(previous)) =
            (&self.mounts, &after.mounts, &before.root_mount)
        {
            if Rc::ptr_eq(&ours.0, &theirs.0) {
                let new = theirs.0.borrow().root.clone();
                self.rebase_pivot_context(previous, &new);
            }
        }
    }
    pub fn mount_id_at(&self, dirfd: i32, path: &[u8], nofollow: bool) -> Result<u64> {
        if !nofollow {
            if let Some(o) = self.proc_fd_description(dirfd, path)? {
                return Ok(o.borrow().mount.as_ref().map_or(17, |m| m.id));
            }
        }
        Ok(self
            .resolve_final(dirfd, path, !nofollow)?
            .mount
            .as_ref()
            .map_or(1, |m| m.id))
    }
    pub fn mount_id_fd(&self, fd: u32) -> Result<u64> {
        let o = self.descriptor(fd)?.open.borrow();
        Ok(o.mount.as_ref().map_or(
            if o.namespace.is_some() {
                17
            } else if matches!(o.kind, FdKind::Terminal) {
                4
            } else {
                1
            },
            |m| m.id,
        ))
    }
    pub(super) fn mounted_pseudo_children(&self, path: &ResolvedPath) -> Result<Vec<Vec<u8>>> {
        if !self.uses_pseudo(path)
            || path.mount.as_ref().is_some_and(|m| m.kind == Kind::Root)
                && matches!(path.key.as_slice(), b"/proc" | b"/sys" | b"/dev/pts")
        {
            return Ok(Vec::new());
        }
        self.pseudo_children(path)
    }
}
fn new_mount_id() -> Result<u64> {
    NEXT_MOUNT
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_add(1).filter(|n| *n < 0x1000_0000)
        })
        .map_err(|_| Errno(28))
}
fn copy_mount(m: &Mount) -> Result<Rc<Mount>> {
    Ok(Rc::new(Mount {
        id: new_mount_id()?,
        fs: m.fs.clone(),
        root: m.root.clone(),
        root_key: m.root_key.clone(),
        kind: m.kind,
        pid_namespace: m.pid_namespace.clone(),
        flags: Cell::new(m.flags.get()),
        writers: Cell::new(0),
        parent: RefCell::new(None),
    }))
}
fn below(path: &[u8], root: &[u8]) -> bool {
    path == root || path.starts_with(root) && (root == b"/" || path.get(root.len()) == Some(&b'/'))
}
fn tmpfs_options(data: &[u8]) -> Result<(u64, usize, u32)> {
    let mut size = MAX_FILE_BYTES as u64;
    let mut nodes = MAX_NODES;
    let mut mode = 0o1777;
    for item in data.split(|b| *b == b',').filter(|v| !v.is_empty()) {
        let at = item.iter().position(|b| *b == b'=').ok_or(Errno(22))?;
        let (key, value) = (&item[..at], &item[at + 1..]);
        let value = std::str::from_utf8(value).map_err(|_| Errno(22))?;
        match key {
            b"mode" => {
                mode = u32::from_str_radix(value, 8).map_err(|_| Errno(22))?;
                if mode & !0o7777 != 0 {
                    return Err(Errno(22));
                }
            }
            b"size" => {
                let (number, scale) = match value.as_bytes().last() {
                    Some(b'k' | b'K') => (&value[..value.len() - 1], 1024),
                    Some(b'm' | b'M') => (&value[..value.len() - 1], 1024 * 1024),
                    Some(b'g' | b'G') => (&value[..value.len() - 1], 1024 * 1024 * 1024),
                    _ => (value, 1),
                };
                size = number
                    .parse::<u64>()
                    .map_err(|_| Errno(22))?
                    .checked_mul(scale)
                    .ok_or(Errno(22))?;
                if size == 0 || size > MAX_FILE_BYTES as u64 {
                    return Err(Errno(28));
                }
            }
            b"nr_inodes" => {
                nodes = value.parse().map_err(|_| Errno(22))?;
                if nodes == 0 || nodes > MAX_NODES {
                    return Err(Errno(28));
                }
            }
            _ => return Err(Errno(95)),
        }
    }
    Ok((size, nodes, mode))
}

fn escape_mount_field(bytes: &[u8]) -> String {
    let mut result = String::new();
    for &b in bytes {
        match b {
            b' ' => result.push_str("\\040"),
            b'\t' => result.push_str("\\011"),
            b'\n' => result.push_str("\\012"),
            b'\\' => result.push_str("\\134"),
            0x21..=0x5b | 0x5d..=0x7e => result.push(b as char),
            _ => result.push_str(&format!("\\{b:03o}")),
        }
    }
    result
}
impl Mount {
    fn fs_name(&self) -> &'static str {
        match self.kind {
            Kind::Root => "rootfs",
            Kind::Tmpfs => "tmpfs",
            Kind::Proc => "proc",
            Kind::Sysfs => "sysfs",
            Kind::Devpts => "devpts",
            Kind::Cgroup => "cgroup2",
        }
    }
    fn options(&self) -> String {
        let mut out = if self.readonly() { "ro" } else { "rw" }.to_owned();
        for (bit, label) in [
            (MS_NOSUID, ",nosuid"),
            (MS_NODEV, ",nodev"),
            (MS_NOEXEC, ",noexec"),
        ] {
            if self.flags.get() & bit != 0 {
                out.push_str(label);
            }
        }
        if self.flags.get() & MS_RELATIME != 0 {
            out.push_str(",relatime");
        }
        out
    }
}
pub(super) fn table_text(snapshot: &NamespaceSnapshot, info: bool) -> Vec<u8> {
    let Some(table) = snapshot.mount.upgrade() else {
        return Vec::new();
    };
    let table = table.borrow();
    let mut text = String::new();
    for m in &table.mounts {
        let Some(mut target) = mount_absolute(m, &m.root_path(), &table.root) else {
            continue;
        };
        let view_root = snapshot
            .root
            .as_ref()
            .and_then(|(m, n)| Some((m.upgrade()?, n.upgrade()?)));
        let mut filesystem_root = m.root_path();
        if let Some((root_mount, root_node)) = view_root {
            let Some(root_key) = root_mount.key_of(&root_node) else {
                continue;
            };
            let Some(root_path) = mount_absolute(&root_mount, &root_key, &table.root) else {
                continue;
            };
            if Rc::ptr_eq(m, &root_mount) {
                target = b"/".to_vec();
                filesystem_root = root_key;
            } else {
                if !below(&target, &root_path) {
                    continue;
                }
                if root_path != b"/" {
                    target = target[root_path.len()..].to_vec();
                }
            }
        }
        if target.is_empty() {
            target.push(b'/');
        }
        let source = if m.kind == Kind::Root {
            "/dev/vda1"
        } else {
            m.fs_name()
        };
        let flags = m.options();
        if info {
            let root = match m.kind {
                Kind::Proc | Kind::Sysfs | Kind::Devpts => m
                    .root_path()
                    .strip_prefix(m.root_key.as_slice())
                    .unwrap_or(b"/")
                    .to_vec(),
                _ => filesystem_root,
            };
            let root = if root.is_empty() { b"/".to_vec() } else { root };
            let dev = m.root.borrow().device;
            let parent = m.parent.borrow().as_ref().map_or(m.id, |a| a.parent.id);
            text.push_str(&format!(
                "{} {} {}:{} {} {} {} - {} {} {}\n",
                m.id,
                parent,
                (dev >> 8) & 0xfff,
                dev & 0xff,
                escape_mount_field(&root),
                escape_mount_field(&target),
                flags,
                m.fs_name(),
                source,
                if m.readonly() { "ro" } else { "rw" }
            ));
        } else {
            text.push_str(&format!(
                "{} {} {} {} 0 0\n",
                source,
                escape_mount_field(&target),
                m.fs_name(),
                flags
            ));
        }
    }
    text.into_bytes()
}
impl Vfs {
    pub(super) fn mount_statfs(&self, mount: Option<&Rc<Mount>>) -> [u8; 120] {
        let Some(m) = mount else {
            return self.storage_stat();
        };
        let mut out = [0; 120];
        let magic = match m.kind {
            Kind::Root => 0x5452414d4553u64,
            Kind::Tmpfs => 0x01021994,
            Kind::Proc => 0x9fa0,
            Kind::Sysfs => 0x62656572,
            Kind::Devpts => 0x1cd1,
            Kind::Cgroup => 0x63677270,
        };
        let capacity = Self::filesystem_capacity(&m.fs.borrow());
        if matches!(m.kind, Kind::Root | Kind::Tmpfs) {
            for (offset, value) in [
                (16, capacity.budget_bytes / 4096),
                (24, capacity.available_bytes / 4096),
                (32, capacity.available_bytes / 4096),
                (40, capacity.node_limit as u64),
                (
                    48,
                    capacity.node_limit.saturating_sub(capacity.nodes_used) as u64,
                ),
            ] {
                out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        for (offset, value) in [
            (0, magic),
            (8, 4096),
            (56, m.root.borrow().device),
            (64, 255),
            (72, 4096),
            (
                80,
                (m.flags.get() & 15)
                    | if m.flags.get() & MS_RELATIME != 0 {
                        4096
                    } else {
                        0
                    },
            ),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setup() -> Vfs {
        let mut v = Vfs::default();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        for d in [b"/src".as_slice(), b"/dst", b"/new", b"/other"] {
            v.mkdir_at(AT_FDCWD, d, 0o755).unwrap();
        }
        v.import_file(b"/src/file", b"shared".to_vec()).unwrap();
        v
    }
    fn bind(v: &mut Vfs, source: &[u8], target: &[u8]) {
        v.mount(Some(source), target, None, 4096, None).unwrap();
    }
    fn read(v: &mut Vfs, p: &[u8]) -> Vec<u8> {
        let fd = v.open_at(AT_FDCWD, p, 0, 0).unwrap();
        let b = v.read(fd, 65536).unwrap();
        v.close(fd).unwrap();
        b
    }
    #[test]
    fn bind_identity_readonly_and_inode_updates() {
        let mut v = setup();
        bind(&mut v, b"/src", b"/dst");
        assert_eq!(read(&mut v, b"/dst/file"), b"shared");
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/src/file").unwrap()[..16],
            &v.stat_at(AT_FDCWD, b"/dst/file").unwrap()[..16]
        );
        assert_ne!(
            v.mount_id_at(AT_FDCWD, b"/src/file", false),
            v.mount_id_at(AT_FDCWD, b"/dst/file", false)
        );
        v.chdir(b"/dst").unwrap();
        assert_eq!(v.cwd().unwrap(), b"/dst");
        v.chdir(b"..").unwrap();
        assert_eq!(v.cwd().unwrap(), b"/");
        v.mount(None, b"/dst", None, 4096 | 32 | 1, None).unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/dst/file", 2, 0), Err(Errno(30)));
        assert_eq!(v.chmod_at(AT_FDCWD, b"/dst/file", 0o600), Err(Errno(30)));
        let fd = v.open_at(AT_FDCWD, b"/src/file", 2, 0).unwrap();
        v.write(fd, b"native").unwrap();
        v.close(fd).unwrap();
        assert_eq!(read(&mut v, b"/dst/file"), b"native");
        assert_eq!(
            v.rename_at(AT_FDCWD, b"/dst/file", AT_FDCWD, b"/src/a", 0),
            Err(Errno(18))
        );
        assert_eq!(v.unlink_at(AT_FDCWD, b"/dst", true), Err(Errno(16)));
        v.umount(b"/dst", 0).unwrap();
        assert!(v.stat_at(AT_FDCWD, b"/dst/file").is_err());
    }
    #[test]
    fn tmpfs_quota_hardlinks_rename_and_lazy_unmount_keep_fd() {
        let mut v = setup();
        let before = v.capacity();
        v.mount(
            None,
            b"/dst",
            Some(b"tmpfs"),
            0,
            Some(b"size=4k,nr_inodes=8,mode=0700"),
        )
        .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/dst/a", 0x42, 0o600).unwrap();
        v.write(fd, &[42; 4096]).unwrap();
        assert_eq!(v.write(fd, &[0]), Err(Errno(28)));
        v.link_at(AT_FDCWD, b"/dst/a", AT_FDCWD, b"/dst/b").unwrap();
        v.rename_at(AT_FDCWD, b"/dst/a", AT_FDCWD, b"/dst/c", 0)
            .unwrap();
        assert_eq!(v.capacity().used_bytes, before.used_bytes);
        assert_eq!(v.umount(b"/dst", 0), Err(Errno(16)));
        v.umount(b"/dst", 2).unwrap();
        assert!(v.stat_at(AT_FDCWD, b"/dst/b").is_err());
        assert_eq!(v.pread(fd, 1, 0).unwrap(), [42]);
        assert_eq!(&v.statfs_fd(fd).unwrap()[..8], &0x01021994u64.to_le_bytes());
        v.close(fd).unwrap();
    }
    #[test]
    fn unshare_mount_table_and_namespace_fd_lifetime() {
        let mut parent = setup();
        let nsfd = parent
            .open_at(AT_FDCWD, b"/proc/self/ns/mnt", 0, 0)
            .unwrap();
        assert_eq!(parent.namespace_type(nsfd).unwrap(), Some(CLONE_NEWNS));
        let mut child = parent.clone();
        child.unshare_mounts().unwrap();
        bind(&mut child, b"/src", b"/dst");
        assert!(parent.stat_at(AT_FDCWD, b"/dst/file").is_err());
        assert_eq!(read(&mut child, b"/dst/file"), b"shared");
        child.setns(nsfd, CLONE_NEWNS).unwrap();
        assert!(child.stat_at(AT_FDCWD, b"/dst/file").is_err());
        bind(&mut parent, b"/src", b"/dst");
        assert_eq!(read(&mut child, b"/dst/file"), b"shared");
    }
    #[test]
    fn recursive_bind_preserves_nested_tmpfs_and_pivot_root() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/src/sub", 0o755).unwrap();
        v.mount(None, b"/src/sub", Some(b"tmpfs"), 0, None).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/src/sub/inner", 0x42, 0o600).unwrap();
        v.write(fd, b"nested").unwrap();
        v.close(fd).unwrap();
        v.mount(Some(b"/src"), b"/dst", None, 4096 | 16384, None)
            .unwrap();
        assert_eq!(read(&mut v, b"/dst/sub/inner"), b"nested");
        bind(&mut v, b"/src", b"/new");
        v.mkdir_at(AT_FDCWD, b"/new/old", 0o755).unwrap();
        v.pivot_root(b"/new", b"/new/old").unwrap();
        assert_eq!(v.cwd().unwrap(), b"/");
        assert_eq!(read(&mut v, b"/file"), b"shared");
        assert_eq!(read(&mut v, b"/old/dst/sub/inner"), b"nested");
        v.umount(b"/old", 2).unwrap();
        assert!(v.stat_at(AT_FDCWD, b"/old/dst").is_err());
        assert_eq!(read(&mut v, b"/file"), b"shared");
    }
    #[test]
    fn shared_mapping_pins_mount_and_blocks_readonly_remount() {
        let mut v = setup();
        bind(&mut v, b"/src", b"/dst");
        let fd = v.open_at(AT_FDCWD, b"/dst/file", 2, 0).unwrap();
        let pages = v.mapping_pages(fd, 0, 4096, true, true).unwrap();
        v.close(fd).unwrap();
        assert_eq!(v.umount(b"/dst", 0), Err(Errno(16)));
        assert_eq!(
            v.mount(None, b"/dst", None, 4096 | 32 | 1, None),
            Err(Errno(16))
        );
        drop(pages);
        v.umount(b"/dst", 0).unwrap();
    }
}

impl Vfs {
    fn register_mounts(&self, mounts: &[Rc<Mount>]) -> Result<()> {
        self.reap_detached_mounts();
        let mut registry = self.mount_registry.borrow_mut();
        registry.retain(|m| m.strong_count() != 0);
        if registry.len() + mounts.len() > MAX_MOUNTS {
            return Err(Errno(28));
        }
        registry.extend(mounts.iter().map(Rc::downgrade));
        Ok(())
    }
    fn reap_detached_mounts(&self) {
        // The retained tree owns one reference per mount. Attachment edges
        // own their parents; anything else is an fd/cwd/root/exec/mapping pin.
        self.detached_mounts.borrow_mut().retain(|tree| {
            tree.iter().any(|m| {
                let internal = 1 + tree
                    .iter()
                    .filter(|child| {
                        child
                            .parent
                            .borrow()
                            .as_ref()
                            .is_some_and(|a| Rc::ptr_eq(&a.parent, m))
                    })
                    .count();
                Rc::strong_count(m) > internal
            })
        });
    }
}

fn mount_absolute(mount: &Rc<Mount>, key: &[u8], root: &Rc<Mount>) -> Option<Vec<u8>> {
    let mut at = mount.clone();
    let mut key = key.to_vec();
    let mut suffix = Vec::new();
    for _ in 0..MAX_MOUNTS {
        let base = at.root_path();
        if !below(&key, &base) {
            return None;
        }
        let cut = if key == base {
            base.len()
        } else if base == b"/" {
            0
        } else {
            base.len()
        };
        let mut tail = key[cut..].to_vec();
        tail.extend(suffix);
        suffix = tail;
        if Rc::ptr_eq(&at, root) {
            return Some(if suffix.is_empty() {
                b"/".to_vec()
            } else {
                suffix
            });
        }
        let attachment = at.parent.borrow().clone()?;
        key = attachment.key();
        at = attachment.parent;
    }
    None
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    fn vfs() -> Vfs {
        let mut v = Vfs::default();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        for d in [b"/a".as_slice(), b"/a/sub", b"/b"] {
            v.mkdir_at(-100, d, 0o755).unwrap();
        }
        v
    }
    #[test]
    fn detached_subtree_remains_traversable_and_releases_its_quota() {
        let mut v = vfs();
        v.mount(None, b"/a/sub", Some(b"tmpfs"), 0, None).unwrap();
        let fd = v.open_at(-100, b"/a/sub/data", 0x42, 0o600).unwrap();
        v.write(fd, b"live").unwrap();
        v.close(fd).unwrap();
        v.mount(Some(b"/a"), b"/b", None, 4096 | 16384, None)
            .unwrap();
        let dir = v.open_at(-100, b"/b", O_DIRECTORY, 0).unwrap();
        v.umount(b"/b", 2).unwrap();
        let fd = v.open_at(dir as i32, b"sub/data", 0, 0).unwrap();
        assert_eq!(v.read(fd, 4).unwrap(), b"live");
        v.close(fd).unwrap();
        v.close(dir).unwrap();
        v.reap_detached_mounts();
        assert!(v.detached_mounts.borrow().is_empty());
    }
    #[test]
    fn namespace_limit_failure_is_atomic_and_recoverable() {
        let mut v = vfs();
        let mut keep = Vec::new();
        loop {
            let id = v.mounts.as_ref().unwrap().id();
            let cwd = v.cwd().unwrap();
            let before = v.clone();
            match v.unshare_mounts() {
                Ok(()) => keep.push(before),
                Err(e) => {
                    assert_eq!(e, Errno(28));
                    assert_eq!(v.mounts.as_ref().unwrap().id(), id);
                    assert_eq!(v.cwd().unwrap(), cwd);
                    break;
                }
            }
        }
        drop(keep);
        v.unshare_mounts().unwrap();
    }
    #[test]
    fn tmpfs_directory_links_and_hardlink_outside_bind_do_not_confuse_paths() {
        let mut v = vfs();
        v.import_file(b"/a/z", b"data".to_vec()).unwrap();
        v.link_at(-100, b"/a/z", -100, b"/outside").unwrap();
        v.mount(Some(b"/a"), b"/b", None, 4096, None).unwrap();
        let fd = v.open_at(-100, b"/b/z", 0, 0).unwrap();
        assert_eq!(
            v.fd_snapshot().iter().find(|f| f.fd == fd).unwrap().target,
            b"/b/z"
        );
        v.mount(None, b"/a/sub", Some(b"tmpfs"), 0, None).unwrap();
        v.mkdir_at(-100, b"/a/sub/child", 0o755).unwrap();
        assert_eq!(
            &v.stat_at(-100, b"/a/sub").unwrap()[20..24],
            &3u32.to_le_bytes()
        );
    }
    #[test]
    fn noexec_mapping_rejects_later_mprotect_without_changing_other_pages() {
        let mut v = vfs();
        v.import_file(b"/a/data", vec![0; 4096]).unwrap();
        v.mount(Some(b"/a"), b"/b", None, 4096, None).unwrap();
        v.mount(None, b"/b", None, 4096 | 32 | MS_NOEXEC, None)
            .unwrap();
        let fd = v.open_at(-100, b"/b/data", 0, 0).unwrap();
        let mut memory = trames_memory::Memory::default();
        memory
            .map_backed(
                0x1000,
                v.mapping_pages(fd, 0, 4096, false, false).unwrap(),
                false,
                trames_memory::Permissions::R,
                false,
            )
            .unwrap();
        assert!(memory
            .protect(0x1000, 4096, trames_memory::Permissions::RX)
            .is_err());
    }
    #[test]
    fn retained_directory_exec_is_valid_outside_the_new_root() {
        let mut v = vfs();
        v.import_executable(b"/a/program", b"payload".to_vec())
            .unwrap();
        let dir = v.open_at(-100, b"/a", O_PATH | O_DIRECTORY, 0).unwrap();
        v.unshare_mounts().unwrap();
        v.chroot(b"/b").unwrap();
        v.chdir(b"/").unwrap();
        let file = v.executable_file_at(dir as i32, b"program", 0).unwrap();
        assert_eq!(file.bytes().unwrap(), b"payload");
        assert!(!v.executable_display(&file).ends_with(b" (deleted)"));
    }
    #[test]
    fn mountinfo_is_relative_to_chroot_and_escapes_field_bytes() {
        let mut v = vfs();
        v.mkdir_at(-100, b"/a/space here", 0o755).unwrap();
        v.mount(None, b"/a/space here", Some(b"tmpfs"), 0, None)
            .unwrap();
        v.chroot(b"/a").unwrap();
        v.chdir(b"/").unwrap();
        let text = String::from_utf8(table_text(&v.namespace_snapshot(), true)).unwrap();
        assert!(text.contains(" /a / "));
        assert!(text.contains(" /space\\040here "));
        assert!(!text.contains(" /proc "));
    }
}

pub(super) fn accessed(node: &mut Node, mount: Option<&Rc<Mount>>) {
    if node.volatile || mount.is_some_and(|m| m.readonly()) {
        return;
    }
    let now = storage::Timestamp::now();
    let atime = node.times[0];
    if mount.is_some_and(|m| m.flags.get() & MS_RELATIME != 0)
        && node.times[1..]
            .iter()
            .all(|t| (t.seconds, t.nanos) < (atime.seconds, atime.nanos))
        && now.seconds.saturating_sub(atime.seconds) < 86400
    {
        return;
    }
    node.times[0] = now;
}
