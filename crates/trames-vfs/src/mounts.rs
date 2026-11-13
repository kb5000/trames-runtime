// SPDX-License-Identifier: GPL-3.0-or-later
//! Mount identity and metadata are separate from owner namespace controls.
use super::*;
pub(super) mod admin;
mod propagation;
mod registry;
pub(super) use registry::Registry;
#[cfg(test)]
mod propagation_tests;
pub(super) mod watch;
#[cfg(test)]
mod worker_tests;
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
    Nsfs,
    Mqueue,
    Overlay,
    #[cfg(all(feature = "hostfs", unix))]
    Host,
}
#[derive(Clone)]
pub(super) struct Attachment {
    pub parent: Arc<Mount>,
    pub node: NodeRef,
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
                .is_some_and(|n| Arc::ptr_eq(n, &self.node))
        {
            return self.fallback.clone();
        }
        self.parent
            .key_of(&self.node)
            .unwrap_or_else(|| self.fallback.clone())
    }
}
pub(super) struct MountInit {
    pub id: u64,
    pub fs: FsHandle,
    pub root: NodeRef,
    pub root_key: Vec<u8>,
    pub kind: Kind,
    pub namespace: Option<linux_namespace::NamespaceHandle>,
    pub pid_namespace: Option<PidNamespace>,
    pub devpts: Option<Arc<pty::Devpts>>,
    pub flags: Cell<u64>,
    pub writers: Arc<mapped::Writers>,
    pub parent: RefCell<Option<Attachment>>,
}
// Resource identity is independent of parent topology. Overlay layers must
// retain this identity rather than the old root's parent chain after pivot.
pub(super) struct MountIdentity {
    users: std::sync::atomic::AtomicUsize,
    #[cfg(all(feature = "hostfs", unix))]
    has_children: std::sync::atomic::AtomicBool,
    pub id: u64,
    // Immutable mount identity; stat must not acquire the filesystem or root
    // inode lock while it already holds another inode guard.
    pub device: u64,
    pub fs: FsHandle,
    pub root: NodeRef,
    pub root_key: Vec<u8>,
    pub kind: Kind,
    pub pid_namespace: Option<PidNamespace>,
    pub devpts: Option<Arc<pty::Devpts>>,
    pub flags: MountFlags,
    propagation: propagation::Metadata,
    pub writers: Arc<mapped::Writers>,
}
pub(super) struct MountData {
    directory_users: std::sync::atomic::AtomicUsize,
    pub identity: Arc<MountIdentity>,
    parent: Arc<SharedCell<Option<SharedAttachment>>>,
    // Complete original namespace authority; metadata projections normalize
    // this handle before a namespace descriptor is opened.
    namespace: Option<linux_namespace::NamespaceHandle>,
}
// One lease per actual shared directory OFD, independent of FD aliases.
// This retains detached traversal topology only while directory users need it.
pub(super) struct DirectoryPin(Arc<MountData>);
impl DirectoryPin {
    pub(super) fn new(mount: Arc<MountData>) -> Self {
        mount.directory_users.fetch_add(1, Ordering::Relaxed);
        Self(mount)
    }
}
/// A real file/fs/image use, independent of metadata allocation references.
/// One lease belongs to the actual OFD or fs_struct, not each query projection
/// or accepted alias. Plain resource Arcs keep bytes/metadata alive only.
pub(super) struct MountUse {
    mount: Arc<MountIdentity>,
    _layers: Option<Arc<overlay::LayerUses>>,
}
impl MountUse {
    pub(super) fn is_for(&self, mount: &Arc<MountIdentity>) -> bool {
        Arc::ptr_eq(&self.mount, mount)
    }
    pub(super) fn new(mount: Arc<MountIdentity>) -> Self {
        let layers = mount.fs.layer_uses();
        mount.users.fetch_add(1, Ordering::Relaxed);
        Self {
            mount,
            _layers: layers,
        }
    }
}
impl MountIdentity {
    pub(super) fn in_use(&self) -> bool {
        self.users.load(Ordering::Relaxed) != 0
    }
}
impl Drop for MountUse {
    fn drop(&mut self) {
        self.mount.users.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Drop for DirectoryPin {
    fn drop(&mut self) {
        self.0.directory_users.fetch_sub(1, Ordering::Relaxed);
    }
}
impl std::ops::Deref for MountData {
    type Target = MountIdentity;
    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}
struct SharedAttachment {
    _parent: Arc<MountData>,
    _node: NodeRef,
    _fallback: Vec<u8>,
}
pub(super) struct MountFlags(AtomicU64);
impl MountFlags {
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    pub fn set(&self, flags: u64) {
        self.0.store(flags, Ordering::Relaxed);
    }
}
pub(super) struct MountParent {
    owner: SharedCell<Option<Attachment>>,
    shared: Arc<SharedCell<Option<SharedAttachment>>>,
}
pub(super) struct ParentWrite<'a> {
    owner: std::sync::RwLockWriteGuard<'a, Option<Attachment>>,
    shared: &'a SharedCell<Option<SharedAttachment>>,
}
impl MountParent {
    pub fn borrow(&self) -> std::sync::RwLockReadGuard<'_, Option<Attachment>> {
        self.owner.borrow()
    }
    pub fn borrow_mut(&self) -> ParentWrite<'_> {
        ParentWrite {
            owner: self.owner.borrow_mut(),
            shared: &self.shared,
        }
    }
}
impl std::ops::Deref for ParentWrite<'_> {
    type Target = Option<Attachment>;
    fn deref(&self) -> &Self::Target {
        &self.owner
    }
}
impl std::ops::DerefMut for ParentWrite<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.owner
    }
}
impl SharedAttachment {
    fn from_owner(a: &Attachment) -> Self {
        Self {
            _parent: a.parent.shared.clone(),
            _node: a.node.clone(),
            _fallback: a.fallback.clone(),
        }
    }
}
impl Drop for ParentWrite<'_> {
    fn drop(&mut self) {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(attachment) = &*self.owner {
            attachment.node.mount_target.store(true, Ordering::Relaxed);
            attachment
                .parent
                .has_children
                .store(true, Ordering::Relaxed);
        }
        let parent = self.owner.as_ref().map(SharedAttachment::from_owner);
        let old = std::mem::replace(&mut *self.shared.borrow_mut(), parent);
        drop(old);
    }
}
pub(super) struct Mount {
    // An installed/detached owner topology uses its overlay layers. Read-only
    // Rc projections leave this empty; retaining their FsHandle is observation.
    _layers: Option<Arc<overlay::LayerUses>>,
    pub shared: Arc<MountData>,
    pub namespace: Option<linux_namespace::NamespaceHandle>,
    pub parent: MountParent,
}
impl std::ops::Deref for Mount {
    type Target = MountData;
    fn deref(&self) -> &Self::Target {
        &self.shared
    }
}
impl Mount {
    pub(super) fn shared_resources(&self) -> Option<Arc<MountData>> {
        Some(self.shared.clone())
    }
    pub(super) fn new(init: MountInit) -> Self {
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(attachment) = init.parent.borrow().as_ref() {
            attachment.node.mount_target.store(true, Ordering::Relaxed);
            attachment
                .parent
                .has_children
                .store(true, Ordering::Relaxed);
        }
        let parent = Arc::new(SharedCell::new(
            init.parent
                .borrow()
                .as_ref()
                .map(SharedAttachment::from_owner),
        ));
        let namespace = init.namespace.clone();
        let identity = Arc::new(MountIdentity {
            users: Default::default(),
            #[cfg(all(feature = "hostfs", unix))]
            has_children: std::sync::atomic::AtomicBool::new(false),
            id: init.id,
            device: init
                .fs
                .overlay_device()
                .unwrap_or_else(|| init.root.borrow().device),
            fs: init.fs,
            root: init.root,
            root_key: init.root_key,
            kind: init.kind,
            pid_namespace: init.pid_namespace,
            devpts: init.devpts,
            flags: MountFlags(AtomicU64::new(init.flags.get())),
            propagation: Default::default(),
            writers: init.writers,
        });
        let shared = Arc::new(MountData {
            directory_users: Default::default(),
            identity,
            parent: parent.clone(),
            namespace,
        });
        let parent = shared.parent.clone();
        let layers = shared.fs.layer_uses();
        Self {
            _layers: layers,
            shared,
            namespace: init.namespace,
            parent: MountParent {
                owner: SharedCell::new(init.parent.into_inner()),
                shared: parent,
            },
        }
    }
    // Overlay sources are validated Root/Tmpfs directory capabilities. Their
    // byte/storage identity is independent of the current namespace ancestry.
    pub(super) fn layer_projection(identity: Arc<MountIdentity>) -> Arc<Self> {
        let parent = Arc::new(SharedCell::new(None));
        Arc::new(Self {
            _layers: None,
            shared: Arc::new(MountData {
                directory_users: Default::default(),
                identity,
                parent: parent.clone(),
                namespace: None,
            }),
            namespace: None,
            parent: MountParent {
                owner: SharedCell::new(None),
                shared: parent,
            },
        })
    }
    /// A private Rc topology over shared resources. No owner Rc is retained.
    pub(super) fn query_projection(
        shared: Arc<MountData>,
        cache: &mut BTreeMap<usize, Arc<Self>>,
    ) -> Arc<Self> {
        let key = Arc::as_ptr(&shared) as usize;
        if let Some(mount) = cache.get(&key) {
            return mount.clone();
        }
        let parent = shared.parent.borrow().as_ref().map(|a| Attachment {
            parent: Self::query_projection(a._parent.clone(), cache),
            node: a._node.clone(),
            fallback: a._fallback.clone(),
        });
        let mount = Arc::new(Self {
            _layers: None,
            parent: MountParent {
                owner: SharedCell::new(parent),
                shared: shared.parent.clone(),
            },
            namespace: shared.namespace.clone(),
            shared,
        });
        cache.insert(key, mount.clone());
        mount
    }
    pub(super) fn resource_projection(shared: Arc<MountData>) -> Arc<Self> {
        let parent = shared.parent.borrow().as_ref().map(|a| Attachment {
            parent: Self::resource_projection(a._parent.clone()),
            node: a._node.clone(),
            fallback: a._fallback.clone(),
        });
        Arc::new(Self {
            _layers: None,
            parent: MountParent {
                owner: SharedCell::new(parent),
                shared: shared.parent.clone(),
            },
            namespace: shared.namespace.clone(),
            shared,
        })
    }
}
impl MountData {
    pub(super) fn device(&self) -> u64 {
        self.identity.device
    }
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
    pub fn key_of(&self, node: &NodeRef) -> Option<Vec<u8>> {
        if Arc::ptr_eq(node, &self.root) {
            return Some(self.root_path());
        }
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &self.fs.host {
            return host.key_of(&self.fs, node).ok();
        }
        let root = self.root_path();
        let fs = self.fs.borrow();
        let result = node.borrow().path_in(&fs.paths, &root);
        result
    }
    fn root_path(&self) -> Vec<u8> {
        // Proc/sysfs inodes live in PseudoFs, never in the backing disk's path
        // map. Their immutable mount keys cannot be found by scanning that map.
        if matches!(self.kind, Kind::Proc | Kind::Sysfs) && self.root.borrow().volatile {
            return self.root_key.clone();
        }
        let fs = self.fs.borrow();
        if fs
            .paths
            .get(&self.root_key)
            .is_some_and(|n| Arc::ptr_eq(n, &self.root))
        {
            return self.root_key.clone();
        }
        self.root
            .borrow()
            .path_in(&fs.paths, b"/")
            .unwrap_or_else(|| self.root_key.clone())
    }
}
pub(super) struct Table {
    pub id: u64,
    pub root: Arc<Mount>,
    pub mounts: Vec<Arc<Mount>>,
    pub events: Arc<watch::MountEvents>,
    pub(super) admin: Arc<admin::Admin>,
    // A query-local topology snapshot is observation, never mutable authority.
    // Accepted nsfs opens upgrade this original resource instead.
    original: Option<std::sync::Weak<SharedCell<Table>>>,
}
impl Table {
    fn new(id: u64, root: Arc<Mount>, mounts: Vec<Arc<Mount>>) -> Self {
        Self {
            id,
            root,
            mounts,
            events: Arc::default(),
            admin: Arc::default(),
            original: None,
        }
    }
    pub(super) fn project(source: &Arc<SharedCell<Self>>) -> Self {
        let table = source.borrow();
        let mut cache = BTreeMap::new();
        let mut project =
            |mount: &Arc<Mount>| Mount::query_projection(mount.shared.clone(), &mut cache);
        Self {
            id: table.id,
            root: project(&table.root),
            mounts: table.mounts.iter().map(&mut project).collect(),
            events: table.events.clone(),
            admin: table.admin.clone(),
            original: Some(
                table
                    .original
                    .clone()
                    .unwrap_or_else(|| Arc::downgrade(source)),
            ),
        }
    }
}
#[derive(Clone)]
pub struct MountNamespace(pub(super) Arc<SharedCell<Table>>);
impl MountNamespace {
    pub(super) fn original(&self) -> Option<Self> {
        let original = self.0.borrow().original.clone();
        match original {
            Some(weak) => weak.upgrade().map(Self),
            None => Some(self.clone()),
        }
    }
    pub fn id(&self) -> u64 {
        self.0.borrow().id
    }
}

/// A resolved storage key together with the exact mount used to reach it.
/// Plain byte paths are reserved for the embedding/storage implementation.
#[derive(Clone)]
pub struct ResolvedPath {
    pub(super) key: Vec<u8>,
    pub(super) mount: Option<Arc<Mount>>,
    pub(super) proc_binding: Option<Arc<proc_source::ProcPath>>,
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
        Self {
            key,
            mount: None,
            proc_binding: None,
        }
    }
}
impl ResolvedPath {
    pub fn into_bytes(self) -> Vec<u8> {
        self.key
    }
    pub(super) fn filesystem(&self, vfs: &Vfs) -> FsHandle {
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
    fn mount(&self) -> Option<&Arc<Mount>> {
        None
    }
    fn proc_binding(&self) -> Option<&Arc<proc_source::ProcPath>> {
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
    fn proc_binding(&self) -> Option<&Arc<proc_source::ProcPath>> {
        self.proc_binding.as_ref()
    }
    fn key(&self) -> &[u8] {
        &self.key
    }
    fn mount(&self) -> Option<&Arc<Mount>> {
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
        let root = Arc::new(Mount::new(MountInit {
            id: 1,
            fs: self.fs.clone(),
            root,
            root_key: b"/".to_vec(),
            kind: Kind::Root,
            namespace: None,
            pid_namespace: None,
            devpts: None,
            flags: Cell::new(MS_RELATIME),
            writers: Arc::default(),
            parent: RefCell::new(None),
        }));
        let mut mounts = vec![root.clone()];
        let enabled = self.pseudo.borrow().enabled;
        self.pseudo.borrow_mut().enabled = true;
        for (id, path, kind, flags) in [
            (2, b"/proc".as_slice(), Kind::Proc, 14),
            (3, b"/sys".as_slice(), Kind::Sysfs, 15),
            (4, b"/dev/pts".as_slice(), Kind::Devpts, 10),
        ] {
            let node = self.pseudo_node(path)?.ok_or(Errno(2))?;
            mounts.push(Arc::new(Mount::new(MountInit {
                id,
                fs: self.fs.clone(),
                root: node.clone(),
                root_key: path.to_vec(),
                kind,
                namespace: None,
                pid_namespace: (kind == Kind::Proc).then(|| self.pid_ns.clone()),
                devpts: None,
                flags: Cell::new(flags),
                writers: Arc::default(),
                parent: RefCell::new(Some(Attachment {
                    parent: root.clone(),
                    node,
                    fallback: path.to_vec(),
                })),
            })));
        }
        let point = self.pseudo_node(b"/sys/fs/cgroup")?.ok_or(Errno(2))?;
        let fs = self.cgroups.borrow().fs.clone();
        let cgroup_root = fs.borrow().paths[b"/".as_slice()].clone();
        mounts.push(Arc::new(Mount::new(MountInit {
            id: 5,
            fs,
            root: cgroup_root,
            root_key: b"/".to_vec(),
            kind: Kind::Cgroup,
            namespace: None,
            pid_namespace: None,
            devpts: None,
            flags: Cell::new(14),
            writers: Arc::default(),
            parent: RefCell::new(Some(Attachment {
                parent: mounts[2].clone(),
                node: point,
                fallback: b"/sys/fs/cgroup".to_vec(),
            })),
        })));
        self.pseudo.borrow_mut().enabled = enabled;
        {
            let mut paths = self.context.paths.borrow_mut();
            paths.cwd_mount = Some(root.clone());
            paths.root_mount = Some(root.clone());
        }
        self.register_mounts(&mounts)?;
        self.mounts = Some(MountNamespace::create(Table::new(
            NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed),
            root,
            mounts,
        )));
        Ok(())
    }
    // Resolve owner topology only for pathname/namespace operations. Ordinary
    // OFD data/flag access uses shared mount resources without Rc projections.
    pub(super) fn mount_for_path(&self, mount: Option<&OpenMount>) -> Option<Arc<Mount>> {
        mount.map(|mount| match mount {
            OpenMount::Owner(owner) => owner.clone(),
            OpenMount::Shared(shared) => self
                .mount_registry
                .borrow()
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .find(|owner| Arc::ptr_eq(&owner.shared, shared))
                .unwrap_or_else(|| Mount::resource_projection(shared.clone())),
        })
    }
    pub(super) fn location(
        &self,
        node: &NodeRef,
        mount: &Option<Arc<Mount>>,
    ) -> Result<ResolvedPath> {
        // Pseudo endpoints are stored separately. Looking in an unrelated disk
        // map first turns every proc FD snapshot into a full rootfs scan.
        if node.borrow().volatile {
            if let Some(mount) = mount.as_ref().filter(|m| m.kind == Kind::Cgroup) {
                // cgroup directories and control files have original shared
                // filesystem identities; no process/proc snapshot is needed.
                return Ok(ResolvedPath {
                    key: mount.key_of(node).ok_or(Errno(2))?,
                    mount: Some(mount.clone()),
                    proc_binding: None,
                });
            }
            if let Some(proc) = node.proc_node.get() {
                return Ok(ResolvedPath {
                    key: proc.path.clone(),
                    mount: mount.clone(),
                    proc_binding: proc.binding.clone(),
                });
            }
            if let Some(key) = self.pseudo.borrow().path_of(node) {
                return Ok(ResolvedPath {
                    proc_binding: None,
                    key,
                    mount: mount.clone(),
                });
            }
            if let Some(query) = &self.query {
                return query.defer();
            }
        }
        let key = match mount {
            Some(m) => m
                .key_of(node)
                .or_else(|| self.pseudo.borrow().path_of(node))
                .ok_or(Errno(2))?,
            None => self.path_of(node)?,
        };
        Ok(ResolvedPath {
            proc_binding: None,
            key,
            mount: mount.clone(),
        })
    }
    pub(super) fn root_location(&self) -> Result<ResolvedPath> {
        let paths = self.context.paths.borrow();
        if let Some(n) = &paths.root_node {
            self.location(n, &paths.root_mount)
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
                proc_binding: None,
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
            #[cfg(all(feature = "hostfs", unix))]
            if !current.has_children.load(Ordering::Relaxed) {
                return Ok(path);
            }
            #[cfg(all(feature = "hostfs", unix))]
            if current.fs.host.is_none()
                && self
                    .node(&path)
                    .is_ok_and(|node| !node.mount_target.load(Ordering::Relaxed))
            {
                // A monotonic inode marker avoids scanning unrelated mounts.
                // Rename keeps inode identity; another namespace may mark a
                // false positive, which simply uses the existing full lookup.
                return Ok(path);
            }
            let next =
                self.mount_registry
                    .borrow()
                    .iter()
                    .rev()
                    .filter_map(std::sync::Weak::upgrade)
                    .find(|m| {
                        (self.pseudo.borrow().enabled
                            || !matches!(
                                m.kind,
                                Kind::Proc | Kind::Sysfs | Kind::Devpts | Kind::Cgroup
                            ))
                            && m.parent.borrow().as_ref().is_some_and(|a| {
                                Arc::ptr_eq(&a.parent, current) && a.key() == path.key
                            })
                    });
            let Some(next) = next else {
                return Ok(path);
            };
            let binding = next
                .root
                .proc_node
                .get()
                .and_then(|proc| proc.binding.clone());
            path = ResolvedPath {
                proc_binding: binding,
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
                proc_binding: None,
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
                proc_binding: None,
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
        let admin = self.mount_admin()?;
        let _lease = admin.enter();
        self.unshare_mounts_locked()
    }
    pub(super) fn unshare_mounts_locked(&mut self) -> Result<()> {
        let old = self.mounts.as_ref().ok_or(Errno(22))?.0.borrow();
        // Linux copy_mnt_ns omits mount-namespace nsfs bindings and everything
        // mounted on them. Retaining an older namespace here would defeat the
        // ordered bind rule and allow reference cycles after unshare.
        let mounts: Vec<_> = old
            .mounts
            .iter()
            .filter(|mount| {
                let mut current = Some((*mount).clone());
                while let Some(mount) = current {
                    if matches!(
                        mount.namespace,
                        Some(linux_namespace::NamespaceHandle::Mount(_))
                    ) {
                        return false;
                    }
                    current = mount.parent.borrow().as_ref().map(|a| a.parent.clone());
                }
                true
            })
            .collect();
        let mut copies = BTreeMap::new();
        for m in &mounts {
            copies.insert(m.id, copy_mount(m)?);
        }
        let shared_admin = mounts
            .iter()
            .any(|m| m.propagation() != propagation::State::default())
            .then(|| old.admin.clone());
        for m in &mounts {
            if let Some(a) = m.parent.borrow().as_ref() {
                *copies[&m.id].parent.borrow_mut() = Some(Attachment {
                    parent: copies[&a.parent.id].clone(),
                    node: a.node.clone(),
                    fallback: a.fallback.clone(),
                });
            }
        }
        let remap = |mount: &mut Option<Arc<Mount>>| {
            if let Some(new) = mount.as_ref().and_then(|m| copies.get(&m.id)) {
                *mount = Some(new.clone());
            }
        };
        let root = copies[&old.root.id].clone();
        let mounts: Vec<_> = mounts.iter().map(|m| copies[&m.id].clone()).collect();
        drop(old);
        self.register_mounts(&mounts)?;
        // CLONE_NEWNS/unshare also detaches fs_struct. Keep the VFS API correct
        // when called directly with a shared context, not only through Kernel.
        if self.context.paths.has_observers() {
            self.unshare_context();
        }
        {
            let mut paths = self.context.paths.borrow_mut();
            remap(&mut paths.cwd_mount);
            remap(&mut paths.root_mount);
        }
        let mut table = Table::new(NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed), root, mounts);
        if let Some(admin) = shared_admin {
            table.admin = admin;
        }
        self.mounts = Some(MountNamespace::create(table));
        Ok(())
    }
}

impl Vfs {
    pub(super) fn uses_pseudo<P: PathArg + ?Sized>(&self, path: &P) -> bool {
        if path.mount().is_some_and(|m| m.devpts.is_some()) {
            return false;
        }
        match path.mount().map(|m| m.kind) {
            Some(Kind::Tmpfs | Kind::Cgroup | Kind::Nsfs | Kind::Mqueue | Kind::Overlay) => false,
            #[cfg(all(feature = "hostfs", unix))]
            Some(Kind::Host) => false,
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
        let open_descriptor = self.descriptor(fd)?;
        let open = open_descriptor.open.borrow();
        Ok(self.description_available_bytes(&open))
    }
    pub(super) fn description_available_bytes(&self, open: &OpenDescription) -> u64 {
        #[cfg(all(feature = "hostfs", unix))]
        if open.mount.as_ref().is_some_and(|m| m.fs.host.is_some()) {
            // Native volume/quota admission belongs to the actual write. Never
            // scan cached host inodes or charge them to the private store.
            return u64::MAX;
        }
        Self::filesystem_bytes(&open.mount.as_ref().map_or(&self.fs, |m| &m.fs).borrow()).2
    }
    pub fn mapping_executable(&self, fd: u32) -> Result<bool> {
        if self.uring(fd).is_ok() {
            return Ok(false);
        }
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
    // A proc FD magic link is a retained mount/inode capability. Its display
    // label may have been renamed or replaced and must not select the target.
    pub(super) fn mount_location(&self, path: &[u8], follow: bool) -> Result<ResolvedPath> {
        let (path, magic) = self.resolve_entry(AT_FDCWD, path, follow, true)?;
        match magic {
            Some(ResolvedTarget::Inode(file)) => self.location(&file.node, &file.mount),
            Some(ResolvedTarget::Descriptor(open)) => {
                if open.borrow().namespace_resource.is_some() {
                    return Ok(path);
                }
                let file = self.proc_open_node(&open, &path)?;
                self.location(&file.node, &file.mount)
            }
            // Mount syscalls select the top mount even when pathname walking
            // starts at a retained cwd and consumes only ".". In particular,
            // pivot_root(".", ".") stacks the old root on that cwd until
            // umount2(".", MNT_DETACH) reveals the new root.
            None => self.follow_mounts(path),
        }
    }
    /// Mounts belong entirely to the guest. No host mount or pathname is used.
    pub fn mount(
        &mut self,
        source: Option<&[u8]>,
        target: &[u8],
        kind: Option<&[u8]>,
        flags: u64,
        data: Option<&[u8]>,
    ) -> Result<()> {
        let admin = self.mount_admin()?;
        let _lease = admin.enter();
        self.mount_locked(source, target, kind, flags, data)
    }
    pub(super) fn mount_locked(
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
        const SLAVE: u64 = 1 << 19;
        const SHARED: u64 = 1 << 20;
        const ATTRS: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME;
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        let flags = if flags & 0xffff0000 == 0xc0ed0000 {
            flags & 0xffff
        } else {
            flags
        };
        // MS_SILENT only suppresses kernel mount diagnostics.
        let flags = flags & !0x8000;
        // Strict atime is the absence of relatime in the selected VFS model.
        // Linux gives MS_STRICTATIME precedence when both are supplied.
        let flags = if flags & (1 << 24) != 0 {
            flags & !((1 << 24) | MS_RELATIME)
        } else {
            flags
        };
        let target = self.mount_location(target, true)?;
        let target_node = self.node(&target)?;
        let parent = target.mount.as_ref().ok_or(Errno(22))?.clone();
        if self
            .mounts
            .as_ref()
            .is_none_or(|ns| !ns.0.borrow().mounts.iter().any(|m| Arc::ptr_eq(m, &parent)))
        {
            return Err(Errno(22));
        }
        if flags & (PRIVATE | SLAVE | SHARED) != 0 {
            return self.change_propagation(&target, flags);
        }
        if flags & REMOUNT != 0 {
            #[cfg(all(feature = "hostfs", unix))]
            if flags & MS_RDONLY == 0 && parent.fs.host.as_ref().is_some_and(|host| host.readonly())
            {
                return Err(Errno(30));
            }
            if parent.devpts.is_some() && data.is_some_and(|d| !d.is_empty()) {
                return Err(Errno(95));
            }
            // Linux accepts MS_REC here but MS_REMOUNT|MS_BIND updates only
            // this mount. Recursive attribute changes require mount_setattr.
            let ignored = if flags & BIND != 0 { REC } else { 0 };
            if flags & !(REMOUNT | BIND | ATTRS | ignored) != 0 {
                return Err(Errno(95));
            }
            if !self.is_mount_root(&target) {
                return Err(Errno(22));
            }
            if parent.kind == Kind::Sysfs && flags & MS_RDONLY == 0 {
                return Err(Errno(30));
            }
            if flags & MS_RDONLY == 0
                && parent
                    .fs
                    .borrow()
                    .overlay
                    .as_ref()
                    .is_some_and(|o| !o.has_upper())
            {
                return Err(Errno(30));
            }
            if flags & MS_RDONLY != 0 && parent.writers.active() {
                return Err(Errno(16));
            }
            parent.flags.set(flags & ATTRS);
            let events = self.mounts.as_ref().unwrap().0.borrow().events.clone();
            events.changed();
            return Ok(());
        }
        if flags & 8192 != 0 && flags & BIND == 0 {
            if flags & !8192 != 0 {
                return Err(Errno(95));
            }
            let source = self.mount_location(source.ok_or(Errno(22))?, true)?;
            let moved = source.mount.as_ref().ok_or(Errno(22))?;
            if parent.propagation() != propagation::State::default()
                || moved.propagation() != propagation::State::default()
                || moved
                    .parent
                    .borrow()
                    .as_ref()
                    .is_some_and(|a| a.parent.propagation() != propagation::State::default())
            {
                return Err(Errno(95));
            }

            let table = self.mounts.as_ref().ok_or(Errno(22))?.0.borrow_mut();
            if !self.is_mount_root(&source)
                || Arc::ptr_eq(moved, &table.root)
                || !table.mounts.iter().any(|mount| Arc::ptr_eq(mount, moved))
            {
                return Err(Errno(22));
            }
            if matches!(moved.root.borrow().content, Content::Directory)
                != matches!(target_node.borrow().content, Content::Directory)
            {
                return Err(Errno(20));
            }
            let mut ancestor = Some(parent.clone());
            while let Some(mount) = ancestor {
                if Arc::ptr_eq(&mount, moved) {
                    return Err(Errno(40));
                }
                ancestor = mount.parent.borrow().as_ref().map(|a| a.parent.clone());
            }
            *moved.parent.borrow_mut() = Some(Attachment {
                parent,
                node: target_node,
                fallback: target.key,
            });
            let events = table.events.clone();
            drop(table);
            events.changed();
            return Ok(());
        }
        if flags & !(ATTRS | BIND | REC) != 0 {
            return Err(Errno(95));
        }
        if flags & REC != 0 && flags & BIND == 0 {
            return Err(Errno(22));
        }
        let ns = self.mounts.as_ref().ok_or(Errno(22))?.clone();
        let mut additions = Vec::new();
        let mut devpts = None;
        let mut namespace = None;
        if flags & BIND != 0 {
            let (_, target) =
                self.resolve_entry_policy(AT_FDCWD, source.ok_or(Errno(22))?, true, true, 0, true)?;
            if let Some(ResolvedTarget::Descriptor(open)) = target {
                namespace = open.borrow().namespace.clone();
            }
        }
        // Linux mnt_ns_loop: bindings point strictly toward newer namespaces.
        // This preserves actual ownership without a cycle collector/service.
        if let Some(linux_namespace::NamespaceHandle::Mount(target)) = &namespace {
            if ns.id() >= target.id() {
                return Err(Errno(22));
            }
        }
        let (fs, root, root_key, mount_kind, attrs) = if let Some(handle) = &namespace {
            if matches!(target_node.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            let root = Arc::new(Inode::new(Node {
                identity: 0,
                record_locks: std::sync::OnceLock::new(),
                whole_locks: std::sync::OnceLock::new(),
                notifications: inotify::Marks::default(),
                path_hint: SharedCell::default(),
                device: 17,
                inode: handle.id(),
                content: Content::Null,
                mode: 0o100444,
                uid: 0,
                gid: 0,
                volatile: true,
                links: 1,
                times: [storage::Timestamp::default(); 3],
                xattrs: BTreeMap::new(),
                seals: None,
            }));
            let fs = FsHandle::new(Filesystem {
                shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
                paths: BTreeMap::from([(b"/".to_vec(), root.clone())]),
                inodes: vec![Arc::downgrade(&root)],
                next_inode: handle.id() + 1,
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            });
            (
                fs,
                root,
                b"/".to_vec(),
                Kind::Nsfs,
                MS_NOSUID | MS_NODEV | MS_NOEXEC,
            )
        } else if flags & BIND != 0 {
            let source = self.mount_location(source.ok_or(Errno(22))?, true)?;
            let node = self.node(&source)?;
            if matches!(node.borrow().content, Content::Directory)
                != matches!(target_node.borrow().content, Content::Directory)
            {
                return Err(Errno(20));
            }
            let m = source.mount.as_ref().ok_or(Errno(22))?;
            devpts = m.devpts.clone();
            if flags & REC != 0 {
                for child in &ns.0.borrow().mounts {
                    if Arc::ptr_eq(child, m) {
                        continue;
                    }
                    let mut at = child.clone();
                    for _ in 0..MAX_MOUNTS {
                        let Some(a) = at.parent.borrow().clone() else {
                            break;
                        };
                        if Arc::ptr_eq(&a.parent, m) {
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
                b"overlay" => {
                    let (fs, readonly) =
                        self.overlay_mount(data.ok_or(Errno(22))?, flags & MS_RDONLY != 0)?;
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    (
                        fs,
                        root,
                        b"/".to_vec(),
                        Kind::Overlay,
                        (flags & ATTRS) | if readonly { MS_RDONLY } else { 0 },
                    )
                }
                b"mqueue" if self.ipc_namespace.mqueue.get().is_some() => {
                    if data.is_some_and(|d| !d.is_empty()) {
                        return Err(Errno(95));
                    }
                    let fs = self.ipc_namespace.mqueue.get().unwrap().clone();
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    (fs, root, b"/".to_vec(), Kind::Mqueue, flags & ATTRS)
                }
                b"tmpfs" | b"mqueue" => {
                    let mqueue = kind == Some(b"mqueue");
                    let (limit, nodes, mode, uid, gid) = if mqueue {
                        if data.is_some_and(|d| !d.is_empty()) {
                            return Err(Errno(95));
                        }
                        (0, 1, 0o1777, None, None)
                    } else {
                        tmpfs_options(
                            data.unwrap_or_default(),
                            self.pseudo.borrow().runtime.memory_limit as u64,
                        )?
                    };
                    let id = new_mount_id()?;
                    let inode = id << 32;
                    let root = Arc::new(Inode::new(Node {
                        identity: 0,
                        record_locks: std::sync::OnceLock::new(),
                        whole_locks: std::sync::OnceLock::new(),
                        notifications: inotify::Marks::default(),
                        path_hint: SharedCell::default(),
                        device: id,
                        content: Content::Directory,
                        mode: 0o40000 | mode,
                        uid: uid.unwrap_or(self.credentials.fsuid),
                        gid: gid.unwrap_or(self.credentials.fsgid),
                        volatile: false,
                        inode,
                        links: 1,
                        times: [storage::Timestamp::now(); 3],
                        xattrs: BTreeMap::new(),
                        seals: None,
                    }));
                    let fs = FsHandle::new(Filesystem {
                        shared_budget: trames_shared::SharedBudget::new(
                            memfd::MEMFD_BYTES as usize,
                        ),
                        paths: BTreeMap::from([(b"/".to_vec(), root.clone())]),
                        inodes: vec![Arc::downgrade(&root)],
                        next_inode: inode + 1,
                        limits: StorageLimits {
                            file_bytes: limit,
                            nodes,
                        },
                        disk: None,
                        volume: None,
                    });
                    let (fs, root) = if mqueue {
                        let shared = self.ipc_namespace.mqueue.get_or_init(|| fs).clone();
                        let root = shared.borrow().paths[b"/".as_slice()].clone();
                        (shared, root)
                    } else {
                        (fs, root)
                    };
                    (
                        fs,
                        root,
                        b"/".to_vec(),
                        if mqueue { Kind::Mqueue } else { Kind::Tmpfs },
                        flags & ATTRS,
                    )
                }
                b"cgroup2" => {
                    if data.is_some_and(|d| !d.is_empty()) {
                        return Err(Errno(95));
                    }
                    let fs = self.cgroups.borrow().fs.clone();
                    let (root, key) = if let Some(root) = &self.cgroup_namespace.root {
                        let key = fs
                            .borrow()
                            .paths
                            .iter()
                            .find(|(_, n)| Arc::ptr_eq(n, root))
                            .map(|(p, _)| p.clone())
                            .ok_or(Errno(2))?;
                        (root.clone(), key)
                    } else {
                        (fs.borrow().paths[b"/".as_slice()].clone(), b"/".to_vec())
                    };
                    (fs, root, key, Kind::Cgroup, flags & ATTRS)
                }
                b"devpts" => {
                    let pts = pty::Devpts::new(new_mount_id()?, data.unwrap_or_default())?;
                    let fs = pts.fs.clone();
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    devpts = Some(Arc::new(pts));
                    (fs, root, b"/".to_vec(), Kind::Devpts, flags & ATTRS)
                }
                b"proc" | b"sysfs" => {
                    if data.is_some_and(|d| !d.is_empty()) {
                        return Err(Errno(95));
                    }
                    let (key, k) = match kind.unwrap() {
                        b"proc" => (b"/proc".as_slice(), Kind::Proc),
                        b"sysfs" => (b"/sys".as_slice(), Kind::Sysfs),
                        _ => unreachable!(),
                    };
                    let node = self.pseudo_node(key)?.ok_or(Errno(19))?;
                    (
                        self.fs.clone(),
                        node,
                        key.to_vec(),
                        k,
                        (flags & ATTRS) | if k == Kind::Sysfs { MS_RDONLY } else { 0 },
                    )
                }
                _ => return Err(Errno(19)),
            }
        };
        if ns.0.borrow().mounts.len() + additions.len() + 1 > MAX_MOUNTS {
            return Err(Errno(28));
        }
        if additions.iter().any(|mount| {
            matches!(&mount.namespace,
            Some(linux_namespace::NamespaceHandle::Mount(target)) if ns.id() >= target.id())
        }) {
            return Err(Errno(22));
        }
        let proc_ns = if namespace.is_some() {
            None
        } else if flags & 4096 != 0 {
            self.mount_location(source.ok_or(Errno(22))?, true)?
                .mount
                .and_then(|m| m.pid_namespace.clone())
        } else {
            (mount_kind == Kind::Proc).then(|| self.pid_ns.clone())
        };
        let root = Arc::new(Mount::new(MountInit {
            id: new_mount_id()?,
            fs,
            root,
            root_key,
            kind: mount_kind,
            namespace,
            pid_namespace: proc_ns,
            devpts,
            flags: Cell::new(attrs),
            writers: Arc::default(),
            parent: RefCell::new(Some(Attachment {
                parent,
                node: target_node,
                fallback: target.key,
            })),
        }));
        if flags & BIND != 0 && root.namespace.is_none() {
            let source_mount = self
                .mount_location(source.ok_or(Errno(22))?, true)?
                .mount
                .ok_or(Errno(22))?;
            root.set_propagation(source_mount.propagation());
        }
        let mut copies = BTreeMap::new();
        if !additions.is_empty() {
            let source = self.mount_location(source.ok_or(Errno(22))?, true)?;
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
        self.publish_mounts(&ns, added)
    }
    pub fn umount(&mut self, target: &[u8], flags: u64) -> Result<()> {
        let admin = self.mount_admin()?;
        let _lease = admin.enter();
        self.umount_locked(target, flags)
    }
    pub(super) fn umount_locked(&mut self, target: &[u8], flags: u64) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        if flags & !(2 | 8) != 0 {
            return Err(Errno(22));
        }
        let target = self.mount_location(target, flags & 8 == 0)?;
        let mount = target.mount.as_ref().ok_or(Errno(22))?;
        if !self.is_mount_root(&target) {
            return Err(Errno(22));
        }
        let result = self.unmount_propagated(mount, flags);
        drop(target);
        self.reap_detached_mounts();
        result
    }
    pub fn pivot_root(&mut self, new_root: &[u8], put_old: &[u8]) -> Result<()> {
        let admin = self.mount_admin()?;
        let _lease = admin.enter();
        self.pivot_root_locked(new_root, put_old)
    }
    pub(super) fn pivot_root_locked(&mut self, new_root: &[u8], put_old: &[u8]) -> Result<()> {
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
            || !Arc::ptr_eq(&new_mount, &old_mount)
            || !below(&old.key, &new.key)
            || !self.is_mount_root(&current_root)
        {
            return Err(Errno(22));
        }
        let mut table = ns.0.borrow_mut();
        // A retained directory can name a detached or foreign namespace mount.
        // It remains traversable, but cannot become this namespace's root.
        if !table
            .mounts
            .iter()
            .any(|mount| Arc::ptr_eq(mount, &new_mount))
        {
            return Err(Errno(22));
        }
        if Arc::ptr_eq(&new_mount, &table.root)
            || current_root
                .mount
                .as_ref()
                .is_none_or(|m| !Arc::ptr_eq(m, &table.root))
        {
            return Err(Errno(16));
        }
        let previous = table.root.clone();
        if previous.propagation() != propagation::State::default()
            || new_mount.propagation() != propagation::State::default()
            || new_mount
                .parent
                .borrow()
                .as_ref()
                .is_some_and(|a| a.parent.propagation() != propagation::State::default())
        {
            return Err(Errno(22));
        }

        *new_mount.parent.borrow_mut() = None;
        *previous.parent.borrow_mut() = Some(Attachment {
            parent: new_mount.clone(),
            node: old_node,
            fallback: old.key,
        });
        table.root = new_mount.clone();
        let events = table.events.clone();
        drop(table);
        events.changed();
        self.context
            .paths
            .pivot(&previous.shared, &new_mount.shared);
        Ok(())
    }
    pub(super) fn mount_admin(&self) -> Result<Arc<admin::Admin>> {
        Ok(self
            .mounts
            .as_ref()
            .ok_or(Errno(22))?
            .0
            .borrow()
            .admin
            .clone())
    }
    pub fn mount_id_at(&self, dirfd: i32, path: &[u8], nofollow: bool) -> Result<u64> {
        let (path, target) =
            self.resolve_entry_policy(dirfd, path, !nofollow, !nofollow, 0, !nofollow)?;
        match target {
            Some(ResolvedTarget::Descriptor(open)) => Ok(Self::open_mount_id(&open.borrow())),
            Some(ResolvedTarget::Inode(file)) => Ok(file.mount.as_ref().map_or(1, |m| m.id)),
            None => Ok(path.mount.as_ref().map_or(1, |m| m.id)),
        }
    }
    pub fn mount_id_fd(&self, fd: u32) -> Result<u64> {
        let o_descriptor = self.descriptor(fd)?;
        let o = o_descriptor.open.borrow();
        Ok(Self::open_mount_id(&o))
    }
    pub(super) fn open_mount_id(o: &OpenDescription) -> u64 {
        o.mount.as_ref().map_or(
            if o.namespace.is_some() {
                17
            } else if matches!(o.kind, FdKind::Terminal) {
                4
            } else {
                1
            },
            |m| m.id,
        )
    }
    pub(super) fn mounted_pseudo_children(&self, path: &ResolvedPath) -> Result<Vec<Vec<u8>>> {
        if path.mount.as_ref().is_some_and(|m| m.devpts.is_some()) {
            return Ok(Vec::new());
        }
        if !self.uses_pseudo(path)
            || path.mount.as_ref().is_some_and(|m| m.kind == Kind::Root)
                && matches!(path.key.as_slice(), b"/proc" | b"/sys" | b"/dev/pts")
        {
            return Ok(Vec::new());
        }
        self.pseudo_children(path)
    }
}
pub(super) fn new_mount_id() -> Result<u64> {
    NEXT_MOUNT
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_add(1).filter(|n| *n < 0x1000_0000)
        })
        .map_err(|_| Errno(28))
}
fn copy_mount(m: &Mount) -> Result<Arc<Mount>> {
    let copy = Arc::new(Mount::new(MountInit {
        id: new_mount_id()?,
        fs: m.fs.clone(),
        root: m.root.clone(),
        root_key: m.root_key.clone(),
        kind: m.kind,
        namespace: m.namespace.clone(),
        pid_namespace: m.pid_namespace.clone(),
        devpts: m.devpts.clone(),
        flags: Cell::new(m.flags.get()),
        writers: Arc::default(),
        parent: RefCell::new(None),
    }));
    copy.set_propagation(m.propagation());
    Ok(copy)
}
pub(super) fn below(path: &[u8], root: &[u8]) -> bool {
    path == root || path.starts_with(root) && (root == b"/" || path.get(root.len()) == Some(&b'/'))
}
fn tmpfs_quantity(value: &str) -> Result<u64> {
    let (number, shift) = match value.as_bytes().last() {
        Some(b'k' | b'K') => (&value[..value.len() - 1], 10),
        Some(b'm' | b'M') => (&value[..value.len() - 1], 20),
        Some(b'g' | b'G') => (&value[..value.len() - 1], 30),
        Some(b't' | b'T') => (&value[..value.len() - 1], 40),
        Some(b'p' | b'P') => (&value[..value.len() - 1], 50),
        Some(b'e' | b'E') => (&value[..value.len() - 1], 60),
        _ => (value, 0),
    };
    number
        .parse::<u64>()
        .map_err(|_| Errno(22))?
        .checked_mul(1u64 << shift)
        .ok_or(Errno(22))
}
type TmpfsOptions = (u64, usize, u32, Option<u32>, Option<u32>);
fn tmpfs_options(data: &[u8], memory: u64) -> Result<TmpfsOptions> {
    let mut size = MAX_FILE_BYTES as u64;
    let mut nodes = MAX_NODES;
    let mut mode = 0o1777;
    let mut uid = None;
    let mut gid = None;
    for item in data.split(|b| *b == b',').filter(|v| !v.is_empty()) {
        let at = item.iter().position(|b| *b == b'=').ok_or(Errno(22))?;
        let (key, value) = (&item[..at], &item[at + 1..]);
        let value = std::str::from_utf8(value).map_err(|_| Errno(22))?;
        match key {
            b"uid" | b"gid" => {
                let id = value.parse::<u32>().map_err(|_| Errno(22))?;
                if id == u32::MAX {
                    return Err(Errno(22));
                }
                if key == b"uid" {
                    uid = Some(id);
                } else {
                    gid = Some(id);
                }
            }
            b"mode" => {
                mode = u32::from_str_radix(value, 8).map_err(|_| Errno(22))?;
                if mode & !0o7777 != 0 {
                    return Err(Errno(22));
                }
            }
            b"size" => {
                let bytes = if let Some(percent) = value.strip_suffix('%') {
                    let percent = percent.parse::<u64>().map_err(|_| Errno(22))?;
                    // Use the same session capacity reported by /proc/meminfo.
                    // The mount records a ceiling; it does not reserve memory.
                    u64::try_from((memory as u128 * percent as u128) / 100)
                        .map_err(|_| Errno(22))?
                } else {
                    tmpfs_quantity(value)?
                };
                size = if bytes == 0 {
                    i64::MAX as u64
                } else {
                    bytes.checked_add(4095).ok_or(Errno(22))? & !4095
                };
                if size > i64::MAX as u64 {
                    return Err(Errno(22));
                }
            }
            b"nr_inodes" => {
                let quantity = tmpfs_quantity(value)?;
                nodes = if quantity == 0 {
                    usize::MAX
                } else {
                    usize::try_from(quantity).map_err(|_| Errno(22))?
                };
            }
            _ => return Err(Errno(95)),
        }
    }
    Ok((size, nodes, mode, uid, gid))
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
            Kind::Nsfs => "nsfs",
            Kind::Mqueue => "mqueue",
            Kind::Overlay => "overlay",
            #[cfg(all(feature = "hostfs", unix))]
            Kind::Host => "trames-host",
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
    let alive = if table.mounts.iter().any(|m| m.propagation().master != 0) {
        propagation::live_groups(&table.admin.namespaces())
    } else {
        Default::default()
    };
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
            if Arc::ptr_eq(m, &root_mount) {
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
        let super_options =
            m.fs.borrow()
                .overlay
                .as_ref()
                .map(|o| format!(",{}", escape_mount_field(o.options())))
                .unwrap_or_default();
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
            let dev = m.device();
            let parent = m.parent.borrow().as_ref().map_or(m.id, |a| a.parent.id);
            text.push_str(&format!(
                "{} {} {}:{} {} {} {}{} - {} {} {}{}\n",
                m.id,
                parent,
                (dev >> 8) & 0xfff,
                dev & 0xff,
                escape_mount_field(&root),
                escape_mount_field(&target),
                flags,
                {
                    let p = m.propagation().resolved(&alive);
                    let mut tags = String::new();
                    if p.shared != 0 {
                        tags.push_str(&format!(" shared:{}", p.shared));
                    }
                    if p.master != 0 {
                        tags.push_str(&format!(" master:{}", p.master));
                    }
                    tags
                },
                m.fs_name(),
                source,
                if m.readonly() { "ro" } else { "rw" },
                super_options,
            ));
        } else {
            text.push_str(&format!(
                "{} {} {} {}{} 0 0\n",
                source,
                escape_mount_field(&target),
                m.fs_name(),
                flags,
                super_options,
            ));
        }
    }
    text.into_bytes()
}
impl Vfs {
    pub(super) fn mount_statfs(&self, mount: Option<&MountData>) -> Result<[u8; 120]> {
        let Some(m) = mount else {
            return Ok(self.storage_stat());
        };
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &m.fs.host {
            return host.statfs(m.flags.get());
        }
        let mut out = [0; 120];
        let magic = match m.kind {
            Kind::Root => 0x5452414d4553u64,
            Kind::Tmpfs => 0x01021994,
            Kind::Proc => 0x9fa0,
            Kind::Sysfs => 0x62656572,
            Kind::Devpts => 0x1cd1,
            Kind::Cgroup => 0x63677270,
            Kind::Nsfs => 0x6e736673,
            Kind::Mqueue => 0x19800202,
            Kind::Overlay => 0x794c7630,
            #[cfg(all(feature = "hostfs", unix))]
            Kind::Host => 0x686f7374,
        };
        let capacity = Self::filesystem_capacity(&m.fs.borrow());
        if matches!(m.kind, Kind::Root | Kind::Tmpfs | Kind::Overlay) {
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
            (56, m.device()),
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
        Ok(out)
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
    #[test]
    fn shared_mount_data_observes_remount_detach_and_releases_filesystem_on_worker() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<MountData>();
        send_sync::<MountIdentity>();
        let mut v = setup();
        v.mount(None, b"/dst", Some(b"tmpfs"), 0, None).unwrap();
        let fd = v.open_at(AT_FDCWD, b"/dst/file", 0x42, 0o600).unwrap();
        let at = v.mount_location(b"/dst", true).unwrap();
        let mount = at.mount.as_ref().unwrap();
        let shared = mount.shared.clone();
        assert!(shared.namespace.is_none());
        assert_eq!(shared.parent.borrow().as_ref().unwrap()._parent.id, 1);
        let filesystem = Arc::downgrade(&shared.fs.shared);
        let root = Arc::downgrade(&shared.root);
        v.mount(None, b"/dst", None, 32 | MS_RDONLY, None).unwrap();
        assert_eq!(v.write(fd, b"x"), Err(Errno(30)));
        let reader = shared.clone();
        assert!(
            std::thread::spawn(move || reader.flags.get() & MS_RDONLY != 0)
                .join()
                .unwrap()
        );
        v.close(fd).unwrap();
        drop(at);
        v.umount(b"/dst", 2).unwrap();
        assert!(shared.parent.borrow().is_none());
        v.reap_detached_mounts();
        assert!(filesystem.upgrade().is_some());
        std::thread::spawn(move || drop(shared)).join().unwrap();
        assert!(filesystem.upgrade().is_none());
        assert!(root.upgrade().is_none());
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
    fn namespace_bind_order_unshare_and_last_close_match_linux() {
        fn refresh(v: &mut Vfs) {
            v.set_runtime_info(
                1,
                RuntimeInfo {
                    processes: vec![ProcessInfo {
                        pid: 1,
                        tgid: 1,
                        fds: v.fd_snapshot(),
                        namespaces: v.namespace_snapshot(),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            );
        }
        let mut older = setup();
        older.import_file(b"/ns-alias", Vec::new()).unwrap();
        let oldfd = older.open_at(AT_FDCWD, b"/proc/self/ns/mnt", 0, 0).unwrap();
        let mut newer = older.clone();
        newer.unshare_mounts().unwrap();
        refresh(&mut newer);
        let original = Arc::downgrade(&newer.mounts.as_ref().unwrap().0);
        let open = older.namespace_description(
            linux_namespace::NamespaceHandle::Mount(newer.mounts.as_ref().unwrap().clone()),
            None,
        );
        let newfd = older
            .shared_files()
            .reserve()
            .unwrap()
            .publish(
                Descriptor {
                    open,
                    cloexec: false.into(),
                },
                None,
            )
            .unwrap();
        refresh(&mut older);
        let oldpath = format!("/proc/self/fd/{oldfd}");
        let newpath = format!("/proc/self/fd/{newfd}");
        assert_eq!(
            older.mount(Some(oldpath.as_bytes()), b"/ns-alias", None, 4096, None),
            Err(Errno(22))
        );
        assert_eq!(
            newer.mount(Some(oldpath.as_bytes()), b"/ns-alias", None, 4096, None),
            Err(Errno(22))
        );
        older
            .mount(Some(newpath.as_bytes()), b"/ns-alias", None, 4096, None)
            .unwrap();
        let bound = older.open_at(AT_FDCWD, b"/ns-alias", 0, 0).unwrap();
        assert_eq!(older.stat_fd(bound).unwrap(), older.stat_fd(newfd).unwrap());
        // Hidden namespace bindings and their children are omitted together.
        older
            .mount(Some(b"/src/file"), b"/ns-alias", None, 4096, None)
            .unwrap();
        older.unshare_mounts().unwrap();
        let plain = older.open_at(AT_FDCWD, b"/ns-alias", 0, 0).unwrap();
        assert_eq!(older.namespace_type(plain), Ok(None));
        assert_eq!(older.read(plain, 16).unwrap(), b"");
        older.close(plain).unwrap();
        older.close(oldfd).unwrap();
        older.close(newfd).unwrap();
        drop(newer);
        assert!(
            original.upgrade().is_some(),
            "opened nsfs alias retains original table"
        );
        older.close(bound).unwrap();
        older.reap_detached_mounts();
        assert!(
            original.upgrade().is_none(),
            "no mount namespace reference cycle"
        );
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
    fn pivot_root_dot_dot_detaches_old_root_from_retained_cwd() {
        let mut v = setup();
        v.import_file(b"/outside", b"old root".to_vec()).unwrap();
        bind(&mut v, b"/src", b"/new");
        v.chdir(b"/new").unwrap();
        let retained = v.open_at(AT_FDCWD, b".", O_DIRECTORY, 0).unwrap();
        v.pivot_root(b".", b".").unwrap();
        v.umount(b".", 2).unwrap();
        v.chroot(b".").unwrap();
        assert_eq!(read(&mut v, b"/file"), b"shared");
        assert!(v.stat_at(AT_FDCWD, b"/outside").is_err());
        assert_eq!(v.cwd().unwrap(), b"/");
        v.chdir_fd(retained).unwrap();
        assert_eq!(read(&mut v, b"file"), b"shared");
    }
    #[test]
    fn bind_remount_accepts_rec_without_changing_nested_or_source_mounts() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/src/sub", 0o755).unwrap();
        v.mount(None, b"/src/sub", Some(b"tmpfs"), 0, None).unwrap();
        v.mount(Some(b"/src"), b"/dst", None, 4096 | 16384, None)
            .unwrap();
        v.mount(
            None,
            b"/dst",
            None,
            32 | 4096 | 16384 | 1 | MS_RELATIME,
            None,
        )
        .unwrap();
        assert_eq!(v.open_at(AT_FDCWD, b"/dst/file", 1, 0), Err(Errno(30)));
        // MS_REC does not make the nested tmpfs read-only on a bind remount.
        let child = v.open_at(AT_FDCWD, b"/dst/sub/new", 0x41, 0o600).unwrap();
        v.close(child).unwrap();
        let source = v.open_at(AT_FDCWD, b"/src/file", 1, 0).unwrap();
        v.close(source).unwrap();
        // Clearing read-only is likewise confined to this mount.
        v.mount(None, b"/dst", None, 32 | 4096 | 16384 | MS_RELATIME, None)
            .unwrap();
        let reopened = v.open_at(AT_FDCWD, b"/dst/file", 1, 0).unwrap();
        v.close(reopened).unwrap();
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
    pub(super) fn register_mounts(&self, mounts: &[Arc<Mount>]) -> Result<()> {
        self.reap_detached_mounts();
        let mut resources = self.mount_resources.borrow_mut();
        resources.retain(|m| m.strong_count() != 0);
        // This is a weak lookup/retirement index shared by every namespace,
        // not a mount table. Applying the per-namespace bound here couples
        // unrelated containers and can make unshare fail before init starts.
        let mut registry = self.mount_registry.borrow_mut();
        registry.retain(|m| m.strong_count() != 0);
        for mount in mounts {
            let resource = Arc::downgrade(&mount.identity);
            if !resources.iter().any(|old| old.ptr_eq(&resource)) {
                resources.push(resource);
            }
            let mount = Arc::downgrade(mount);
            if !registry.iter().any(|old| old.ptr_eq(&mount)) {
                registry.push(mount);
            }
        }
        Ok(())
    }
    pub(super) fn reap_detached_mounts(&self) {
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
                            .is_some_and(|a| Arc::ptr_eq(&a.parent, m))
                    })
                    .count();
                Arc::strong_count(m) > internal || m.directory_users.load(Ordering::Relaxed) != 0
            })
        });
    }
}

pub(super) fn mount_absolute(mount: &Arc<Mount>, key: &[u8], root: &Arc<Mount>) -> Option<Vec<u8>> {
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
        if Arc::ptr_eq(&at, root) {
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
    fn proc_paths_keep_their_mount_identity_after_bind_and_namespace_clone() {
        let mut v = vfs();
        v.mount(Some(b"/proc"), b"/b", None, 4096, None).unwrap();
        v.chdir(b"/b/1").unwrap();
        let fd = v.open_at(-100, b"status", 0, 0).unwrap();
        assert_eq!(v.cwd().unwrap(), b"/b/1");
        assert_eq!(
            v.fd_snapshot().iter().find(|f| f.fd == fd).unwrap().target,
            b"/b/1/status"
        );
        v.unshare_mounts().unwrap();
        assert_eq!(v.cwd().unwrap(), b"/b/1");
        let after = v.open_at(-100, b"status", 0, 0).unwrap();
        assert_eq!(
            v.fd_snapshot()
                .iter()
                .find(|f| f.fd == after)
                .unwrap()
                .target,
            b"/b/1/status"
        );
        assert!(v.read(fd, 4096).unwrap().starts_with(b"Name:"));
    }
    #[test]
    fn detached_subtree_remains_traversable_and_releases_its_quota() {
        for retirement in 0..4 {
            let mut v = vfs();
            v.mount(None, b"/a/sub", Some(b"tmpfs"), 0, None).unwrap();
            let fd = v.open_at(-100, b"/a/sub/data", 0x42, 0o600).unwrap();
            v.write(fd, b"live").unwrap();
            v.close(fd).unwrap();
            v.mount(Some(b"/a"), b"/b", None, 4096 | 16384, None)
                .unwrap();
            let dir = v.open_at(-100, b"/b", O_DIRECTORY | O_CLOEXEC, 0).unwrap();
            v.umount(b"/b", 2).unwrap();
            assert!(!v.detached_mounts.borrow().is_empty());
            let fd = v.open_at(dir as i32, b"sub/data", 0, 0).unwrap();
            assert_eq!(v.read(fd, 4).unwrap(), b"live");
            v.close(fd).unwrap();
            match retirement {
                0 => v.close(dir).unwrap(),
                1 => {
                    let replacement = v.memfd_create(b"replacement", 0).unwrap();
                    v.dup3(replacement, dir, 0).unwrap();
                }
                2 => v.close_all(),
                _ => v.close_exec(),
            }
            assert!(v.detached_mounts.borrow().is_empty());
        }
    }
    #[test]
    fn sibling_namespaces_do_not_share_the_mount_table_quota() {
        let mut parent = vfs();
        parent.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
        let initial = parent
            .mount_resources
            .borrow()
            .iter()
            .filter(|w| w.strong_count() != 0)
            .count();
        let mut siblings = Vec::new();
        for _ in 0..MAX_MOUNTS + 16 {
            let mut child = parent.clone();
            child.unshare_mounts().unwrap();
            child.mount(None, b"/b", Some(b"tmpfs"), 0, None).unwrap();
            siblings.push(child);
        }
        assert!(parent.mount_resources.borrow().len() > MAX_MOUNTS);
        for child in &siblings {
            assert_eq!(
                child.mounts.as_ref().unwrap().0.borrow().mounts.len(),
                initial + 1
            );
        }
        drop(siblings);
        parent.register_mounts(&[]).unwrap();
        assert_eq!(parent.mount_resources.borrow().len(), initial);
    }
    #[test]
    fn per_namespace_mount_limit_failure_is_atomic_and_recoverable() {
        let mut v = vfs();
        while v.mounts.as_ref().unwrap().0.borrow().mounts.len() < MAX_MOUNTS {
            v.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
        }
        let id = v.mounts.as_ref().unwrap().id();
        let cwd = v.cwd().unwrap();
        assert_eq!(
            v.mount(None, b"/a", Some(b"tmpfs"), 0, None),
            Err(Errno(28))
        );
        assert_eq!(v.mounts.as_ref().unwrap().id(), id);
        assert_eq!(v.cwd().unwrap(), cwd);
        let mut child = v.clone();
        child.unshare_mounts().unwrap();
        assert_eq!(
            child.mounts.as_ref().unwrap().0.borrow().mounts.len(),
            MAX_MOUNTS
        );
        v.umount(b"/a", 0).unwrap();
        v.mount(None, b"/a", Some(b"tmpfs"), 0, None).unwrap();
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
    #[test]
    fn systemd_tmpfs_percentage_and_inode_suffix_are_lazy_limits() {
        let mut v = vfs();
        v.pseudo.borrow_mut().runtime.memory_limit = 8usize << 30;
        v.mount(
            None,
            b"/a",
            Some(b"tmpfs"),
            6,
            Some(b"mode=01777,size=20%,nr_inodes=800k"),
        )
        .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/a/f", 0x42, 0o600).unwrap();
        let open = v.descriptor(fd).unwrap().open.clone();
        let mount = open.borrow().mount.clone().unwrap();
        let capacity = Vfs::filesystem_capacity(&mount.fs.borrow());
        assert_eq!(
            capacity.budget_bytes,
            ((8u64 << 30) / 5).div_ceil(4096) * 4096
        );
        assert_eq!(capacity.node_limit, 800 * 1024);
        assert_eq!(capacity.used_bytes, 0);
        v.write(fd, b"x").unwrap();
        assert_eq!(Vfs::filesystem_capacity(&mount.fs.borrow()).used_bytes, 1);
        assert_eq!(tmpfs_options(b"size=invalid%", 1 << 30), Err(Errno(22)));
        assert_eq!(tmpfs_options(b"size=200%", 1 << 30).unwrap().0, 2 << 30);
        assert_eq!(
            tmpfs_options(b"size=18446744073709551615k", 0),
            Err(Errno(22))
        );
        assert_eq!(tmpfs_options(b"nr_inodes=1%", 0), Err(Errno(22)));
        assert_eq!(
            tmpfs_options(b"size=0,nr_inodes=0", 0),
            Ok((i64::MAX as u64, usize::MAX, 0o1777, None, None))
        );
    }
    #[test]
    fn docker_tmpfs_size_is_lazy_and_strictatime_overrides_relatime() {
        let mut v = vfs();
        v.mount(
            None,
            b"/a",
            Some(b"tmpfs"),
            MS_RELATIME,
            Some(b"size=65536k,mode=755"),
        )
        .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/a/f", 0x42, 0o600).unwrap();
        v.write(fd, b"x").unwrap();
        let open = v.descriptor(fd).unwrap().open.clone();
        let mount = open.borrow().mount.clone().unwrap();
        let capacity = Vfs::filesystem_capacity(&mount.fs.borrow());
        assert_eq!(capacity.budget_bytes, 64 * 1024 * 1024);
        assert_eq!(capacity.used_bytes, 1);
        let node = open.borrow().node.clone().unwrap();
        let future = storage::Timestamp {
            seconds: storage::Timestamp::now().seconds + 100000,
            nanos: 0,
        };
        node.borrow_mut().times[0] = future;
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 1).unwrap(), b"x");
        assert_eq!(node.borrow().times[0], future);
        v.mount(None, b"/a", None, 32 | MS_RELATIME | (1 << 24), None)
            .unwrap();
        assert_eq!(mount.flags.get() & MS_RELATIME, 0);
        v.seek(fd, 0, 0).unwrap();
        v.read(fd, 1).unwrap();
        assert!(node.borrow().file_metadata().times[0].seconds < future.seconds);
    }
    #[test]
    fn empty_mqueue_mounts_share_identity_without_creatable_regular_files() {
        let mut v = vfs();
        v.mount(None, b"/a", Some(b"mqueue"), 14, None).unwrap();
        v.mount(None, b"/b", Some(b"mqueue"), 14, None).unwrap();
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/a").unwrap()[..16],
            &v.stat_at(AT_FDCWD, b"/b").unwrap()[..16]
        );
        let fd = v.open_at(AT_FDCWD, b"/a", O_DIRECTORY, 0).unwrap();
        let descriptor = v.descriptor(fd).unwrap();
        let open = descriptor.open.borrow();
        let fs = v.mount_statfs(open.mount.as_deref()).unwrap();
        assert_eq!(u64::from_le_bytes(fs[..8].try_into().unwrap()), 0x19800202);
        drop(open);
        assert_eq!(v.open_at(AT_FDCWD, b"/a/queue", 0x42, 0o600), Err(Errno(1)));
        assert_eq!(v.mkdir_at(AT_FDCWD, b"/b/dir", 0o700), Err(Errno(1)));
        assert_eq!(v.mknod_at(AT_FDCWD, b"/b/fifo", 0o10600, 0), Err(Errno(1)));
        v.mount(None, b"/b", None, 32 | MS_RDONLY, None).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/b/queue", 0x42, 0o600),
            Err(Errno(30))
        );
        v.umount(b"/a", 2).unwrap();
        assert!(v.stat_fd(fd).is_ok());
        assert!(v.stat_at(AT_FDCWD, b"/b").is_ok());
    }
}

pub(super) fn accessed(node: &mut Node, mount: Option<&MountData>) {
    if node.volatile || mount.is_some_and(|m| m.readonly()) {
        return;
    }
    if let Content::File(storage::FileData::Plain(data)) = &node.content {
        if data
            .accessed(
                false,
                mount.is_some_and(|m| m.flags.get() & MS_RELATIME != 0),
            )
            .is_some()
        {
            return; // The original shared file metadata is canonical already.
        }
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
