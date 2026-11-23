// SPDX-License-Identifier: GPL-3.0-or-later
//! Mount identity and metadata are separate from owner namespace controls.
use super::*;
pub(super) mod admin;
pub(crate) mod fd;
mod propagation;
pub(crate) mod query;
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
pub(super) const MS_NOATIME: u64 = 1 << 10;
pub(super) const MS_NODIRATIME: u64 = 1 << 11;
const MS_STRICTATIME: u64 = 1 << 24;
const ATIME_FLAGS: u64 = MS_NOATIME | MS_NODIRATIME | MS_RELATIME;
pub(super) const MS_RELATIME: u64 = 1 << 21;
const LOCK_ATTACHMENT: u64 = 1 << 63;
fn hides_locked_child(mounts: &[Arc<Mount>], parent: &Arc<Mount>, key: &[u8]) -> bool {
    mounts.iter().any(|child| {
        child.inherited.load(Ordering::Relaxed) & LOCK_ATTACHMENT != 0
            && child
                .parent
                .borrow()
                .as_ref()
                .is_some_and(|a| Arc::ptr_eq(&a.parent, parent) && below(&a.key(), key))
    })
}
// This is an environment-wide setting applied separately to each mount table.
pub(super) struct MountPolicy {
    limit: std::sync::atomic::AtomicU32,
    groups: propagation::Groups,
    path_changes: AtomicU64,
    namespaces: SharedCell<BTreeMap<u64, std::sync::Weak<SharedCell<Table>>>>,
}
impl Default for MountPolicy {
    fn default() -> Self {
        Self {
            limit: std::sync::atomic::AtomicU32::new(128),
            groups: Default::default(),
            path_changes: AtomicU64::new(0),
            namespaces: Default::default(),
        }
    }
}
// The low word counts active writers, including overlapping renames on different
// filesystems. The high word distinguishes completed changes during a scoped walk.
pub(super) struct PathChange(Arc<MountPolicy>);
impl Drop for PathChange {
    fn drop(&mut self) {
        self.0
            .path_changes
            .fetch_add((1u64 << 32) - 1, Ordering::Release);
    }
}
impl Vfs {
    pub(super) fn path_change(&self) -> PathChange {
        let policy = self.pseudo.borrow().mount_policy.clone();
        policy.path_changes.fetch_add(1, Ordering::AcqRel);
        PathChange(policy)
    }
    pub(super) fn path_sequence(&self) -> u64 {
        self.pseudo
            .borrow()
            .mount_policy
            .path_changes
            .load(Ordering::Acquire)
    }
}
impl MountPolicy {
    pub(super) fn get(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, value: u32) {
        self.limit.store(value, Ordering::Relaxed);
    }
}
impl Vfs {
    // Most paths stay in one mount. Only a deep traversal needs the size
    // of the live registry, which also contains detached descriptor trees.
    fn mount_walk(&self) -> impl Iterator<Item = usize> + '_ {
        (0..8).chain(std::iter::once_with(|| 8..=self.mount_registry.borrow().len()).flatten())
    }
    pub(super) fn mount_limit(&self) -> usize {
        self.pseudo.borrow().mount_policy.get() as usize
    }
}
static NEXT_MOUNT: AtomicU64 = AtomicU64::new(16);
static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(0xe000_0000);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Root,
    Tmpfs,
    Fuse,
    FuseControl,
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
impl Kind {
    fn statfs_magic(self) -> u64 {
        match self {
            Kind::Root => 0x5452414d4553u64,
            Kind::Tmpfs => 0x01021994,
            Kind::Fuse => 0x65735546,
            Kind::FuseControl => 0x65735543,
            Kind::Proc => 0x9fa0,
            Kind::Sysfs => 0x62656572,
            Kind::Devpts => 0x1cd1,
            Kind::Cgroup => 0x63677270,
            Kind::Nsfs => 0x6e736673,
            Kind::Mqueue => 0x19800202,
            Kind::Overlay => 0x794c7630,
            #[cfg(all(feature = "hostfs", unix))]
            Kind::Host => 0x686f7374,
        }
    }
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
#[derive(Clone, Default)]
pub(super) struct MountDisplay {
    nsdelegate: Option<Arc<std::sync::atomic::AtomicBool>>,
    source: Option<Arc<[u8]>>,
    tmpfs_mode: Option<u32>,
}
pub(super) struct MountInit {
    pub id: u64,
    pub fs: FsHandle,
    pub root: NodeRef,
    pub root_key: Vec<u8>,
    pub kind: Kind,
    pub display: MountDisplay,
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
    inherited: AtomicU64,
    anonymous_tree: std::sync::OnceLock<fd::TreeOrigin>,
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
    pub display: MountDisplay,
    pub pid_namespace: Option<PidNamespace>,
    pub devpts: Option<Arc<pty::Devpts>>,
    pub flags: Arc<MountFlags>,
    propagation: propagation::Metadata,
    pub writers: Arc<mapped::Writers>,
    // Serialize a read-only transition with admission of new shared writers.
    pub(super) writer_admission: std::sync::Mutex<()>,
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
    fn hold_mount_writers(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        let guard = self.writer_admission.lock().unwrap();
        if self.writers.active() {
            return Err(Errno(16));
        }
        Ok(guard)
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
pub(super) struct MountFlags(AtomicU64, Option<Arc<std::sync::atomic::AtomicBool>>);
impl MountFlags {
    pub fn get(&self) -> u64 {
        self.local() | u64::from(self.1.as_ref().is_some_and(|ro| ro.load(Ordering::Relaxed)))
    }
    fn local(&self) -> u64 {
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
            inherited: AtomicU64::new(0),
            anonymous_tree: Default::default(),
            users: Default::default(),
            #[cfg(all(feature = "hostfs", unix))]
            has_children: std::sync::atomic::AtomicBool::new(false),
            id: init.id,
            device: init
                .fs
                .overlay_device()
                .unwrap_or_else(|| init.root.borrow().device),
            flags: Arc::new(MountFlags(
                AtomicU64::new(init.flags.get()),
                init.fs.super_readonly.clone(),
            )),
            fs: init.fs,
            root: init.root,
            root_key: init.root_key,
            kind: init.kind,
            display: init.display,
            pid_namespace: init.pid_namespace,
            devpts: init.devpts,
            writer_admission: Default::default(),
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
    // Overlay layers retain validated directory capabilities. Their
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
pub(super) fn special_file(node: Option<&NodeRef>) -> bool {
    node.is_some_and(|node| {
        matches!(
            node.borrow().content,
            Content::Fifo(_)
                | Content::Socket(_)
                | Content::Null
                | Content::Terminal
                | Content::Device(_)
        )
    })
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
        } else if self.kind == Kind::Fuse {
            Err(Errno(95))
        } else {
            Ok(())
        }
    }
    /// A FIFO or device write transfers data to its endpoint without writing the filesystem.
    pub(super) fn writable_data(&self, node: Option<&NodeRef>) -> Result<()> {
        if self.readonly() && !special_file(node) {
            return Err(Errno(30));
        }
        Ok(())
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
    pub(super) user_namespace: UserNamespace,
    pub id: u64,
    // The guest volume (/dev/vda1 at boot) is mounted at this namespace's
    // root slot. Its bootstrap parent has an ID but no guest-visible pathname.
    // Pivot replaces the volume in the slot and preserves the parent identity.
    root_parent_id: u64,
    pub root: Arc<Mount>,
    pub mounts: Vec<Arc<Mount>>,
    pub events: Arc<readiness::ProcEvents>,
    pub(super) admin: Arc<admin::Admin>,
    // A query-local topology snapshot is observation, never mutable authority.
    // Accepted nsfs opens upgrade this original resource instead.
    original: Option<std::sync::Weak<SharedCell<Table>>>,
    registry: Option<std::sync::Weak<MountPolicy>>,
}
impl Table {
    fn new(root: Arc<Mount>, mounts: Vec<Arc<Mount>>) -> Result<Self> {
        Ok(Self {
            root_parent_id: new_mount_id()?,
            user_namespace: UserNamespace::default(),
            id: NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed),
            root,
            mounts,
            events: Arc::default(),
            admin: Arc::default(),
            original: None,
            registry: None,
        })
    }
    pub(super) fn project(source: &Arc<SharedCell<Self>>) -> Self {
        let table = source.borrow();
        let mut cache = BTreeMap::new();
        let mut project =
            |mount: &Arc<Mount>| Mount::query_projection(mount.shared.clone(), &mut cache);
        Self {
            user_namespace: table.user_namespace.clone(),
            id: table.id,
            root_parent_id: table.root_parent_id,
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
            registry: None,
        }
    }
}
impl Drop for Table {
    fn drop(&mut self) {
        if let Some(policy) = self.registry.as_ref().and_then(std::sync::Weak::upgrade) {
            policy.namespaces.borrow_mut().remove(&self.id);
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
    pub(super) retained_directory: Option<NodeRef>,
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
            && self.retained_directory.as_ref().map(Arc::as_ptr)
                == other.retained_directory.as_ref().map(Arc::as_ptr)
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
            retained_directory: None,
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
    fn retained_directory(&self) -> Option<&NodeRef> {
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
    fn retained_directory(&self) -> Option<&NodeRef> {
        self.retained_directory.as_ref()
    }
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
            display: Default::default(),
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
                display: Default::default(),
                namespace: None,
                pid_namespace: (kind == Kind::Proc).then(|| self.pid_ns.clone()),
                devpts: None,
                flags: Cell::new(flags | MS_RELATIME),
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
            display: MountDisplay {
                nsdelegate: Some(self.cgroups.borrow().nsdelegate.clone()),
                ..Default::default()
            },
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
        let table = Table::new(root.clone(), mounts)?;
        self.register_mounts(&table.mounts)?;
        {
            let mut paths = self.context.paths.borrow_mut();
            paths.cwd_mount = Some(root.clone());
            paths.root_mount = Some(root);
        }
        self.mounts = Some(MountNamespace::create(
            table,
            &self.pseudo.borrow().mount_policy,
        ));
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
                    retained_directory: None,
                    proc_binding: None,
                });
            }
            if let Some(proc) = node.proc_node.get() {
                return Ok(ResolvedPath {
                    key: proc.path.clone(),
                    mount: mount.clone(),
                    retained_directory: None,
                    proc_binding: proc.binding.clone(),
                });
            }
            if let Some(key) = self.pseudo.borrow().path_of(node) {
                return Ok(ResolvedPath {
                    retained_directory: None,
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
                .or_else(|| self.pseudo.borrow().path_of(node)),
            None => self.path_of(node).ok(),
        };
        let (key, retained_directory) = match key {
            Some(key) => (key, None),
            None if node.removed_directory_parent.get().is_some() => {
                (Vec::new(), Some(node.clone()))
            }
            None => return Err(Errno(2)),
        };
        Ok(ResolvedPath {
            retained_directory,
            proc_binding: None,
            key,
            mount: mount.clone(),
        })
    }
    pub(super) fn root_location(&self) -> Result<ResolvedPath> {
        self.root_location_in(&self.context.paths.borrow())
    }
    pub(super) fn root_location_in(&self, paths: &fs_context::Paths) -> Result<ResolvedPath> {
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
                retained_directory: None,
                proc_binding: None,
                key: root.root_path(),
                mount: Some(root),
            })
        }
    }
    pub(super) fn follow_mounts(&self, mut path: ResolvedPath) -> Result<ResolvedPath> {
        if path.retained_directory.is_some() {
            return Ok(path);
        }
        for _ in self.mount_walk() {
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
                retained_directory: None,
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
        if let Some(directory) = &path.retained_directory {
            let parent = directory.removed_directory_parent.get().ok_or(Errno(2))?;
            return self.location(parent, &path.mount);
        }
        let mut at = path.clone();
        for _ in self.mount_walk() {
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
                retained_directory: None,
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
        self.render_path::<false>(path, &self.root_location()?)
    }
    pub(super) fn render_path<const GETCWD: bool>(
        &self,
        path: &ResolvedPath,
        root: &ResolvedPath,
    ) -> Result<Vec<u8>> {
        if path.retained_directory.is_some() {
            return Err(Errno(2));
        }
        let mut at = path.clone();
        let mut suffix = Vec::new();
        for _ in self.mount_walk() {
            // An OFD opened before CLONE_NEWNS retains its original mount tree.
            // Both namespace roots can still name the same filesystem root;
            // finish that original ancestry rather than exposing its backing
            // bind source (e.g. /system/apex instead of /apex) on proc FD links.
            let same_root = !GETCWD
                && at
                    .mount
                    .as_ref()
                    .zip(root.mount.as_ref())
                    .is_some_and(|(a, b)| {
                        a.parent.borrow().is_none()
                            && b.parent.borrow().is_none()
                            && a.fs.same_data(&b.fs)
                            && Arc::ptr_eq(&a.root, &b.root)
                    });
            if (at.mount.as_ref().map(|m| m.id) == root.mount.as_ref().map(|m| m.id) || same_root)
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
            let Some(a) = m.parent.borrow().clone() else {
                if GETCWD {
                    // Linux getcwd labels a still-linked cwd outside fs.root.
                    let mut out = b"(unreachable)".to_vec();
                    if suffix.is_empty() {
                        out.push(b'/');
                    } else {
                        out.extend(suffix);
                    }
                    return Ok(out);
                }
                return Err(Errno(2));
            };
            at = ResolvedPath {
                retained_directory: None,
                proc_binding: None,
                key: a.key(),
                mount: Some(a.parent),
            };
        }
        Err(Errno(40))
    }
    pub fn unshare_mounts(&mut self) -> Result<()> {
        if !self.credentials.has_local_cap(capabilities::SYS_ADMIN) {
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
            let copy = copy_mount(m)?;
            if old.user_namespace != self.credentials.user_namespace {
                copy.set_propagation(m.propagation().inherited_slave());
                copy.inherited.fetch_or(
                    LOCK_ATTACHMENT | ATIME_FLAGS | (m.flags.get() & 15),
                    Ordering::Relaxed,
                );
            }
            copies.insert(m.id, copy);
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
        let mut table = Table::new(root, mounts)?;
        self.register_mounts(&table.mounts)?;
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
        table.user_namespace = self.credentials.user_namespace.clone();
        if let Some(admin) = shared_admin {
            table.admin = admin;
        }
        self.mounts = Some(MountNamespace::create(
            table,
            &self.pseudo.borrow().mount_policy,
        ));
        Ok(())
    }
}

impl Vfs {
    pub(super) fn uses_pseudo<P: PathArg + ?Sized>(&self, path: &P) -> bool {
        if path.mount().is_some_and(|m| m.devpts.is_some()) {
            return false;
        }
        match path.mount().map(|m| m.kind) {
            Some(
                Kind::Tmpfs
                | Kind::Fuse
                | Kind::FuseControl
                | Kind::Cgroup
                | Kind::Nsfs
                | Kind::Mqueue
                | Kind::Overlay,
            ) => false,
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
        self.mount_location_at(AT_FDCWD, path, follow)
    }
    fn mount_location_at(&self, fd: i32, path: &[u8], follow: bool) -> Result<ResolvedPath> {
        let (path, magic) = self.resolve_entry_policy(fd, path, follow, true, 0, true)?;
        match magic {
            Some(ResolvedTarget::Inode(file)) => self.location(&file.node, &file.mount),
            Some(ResolvedTarget::Descriptor(open)) => {
                if open.borrow().namespace_resource.is_some() {
                    return Ok(path);
                }
                if open.borrow().node.is_none() {
                    // Anonymous inodes have no mountpoint in the caller's tree.
                    return Err(Errno(2));
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
    fn cgroup_mount_options(&self, data: Option<&[u8]>) -> Result<Option<bool>> {
        if !self.credentials.has_ns_cap(
            &self.cgroup_namespace.user_namespace,
            capabilities::SYS_ADMIN,
        ) {
            return Err(Errno(1));
        }
        let mut delegate = false;
        for option in data.unwrap_or_default().split(|&b| b == b',') {
            match option {
                b"" => {}
                b"nsdelegate" => delegate = true,
                _ => return Err(Errno(95)),
            }
        }
        Ok(self.cgroup_namespace.root.is_none().then_some(delegate))
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
        const ATTRS: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | ATIME_FLAGS;
        if !self.credentials.has_ns_cap(
            &self
                .mounts
                .as_ref()
                .map_or_else(UserNamespace::default, |n| {
                    n.0.borrow().user_namespace.clone()
                }),
            capabilities::SYS_ADMIN,
        ) {
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
        let preserve_atime = flags & (ATIME_FLAGS | MS_STRICTATIME) == 0;
        let strict_atime = flags & MS_STRICTATIME != 0;
        let flags = if strict_atime {
            flags & !(MS_STRICTATIME | MS_NOATIME | MS_RELATIME)
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
        let _change = self.path_change();
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
            let mut attrs = flags & ATTRS;
            if preserve_atime {
                attrs |= parent.flags.get() & ATIME_FLAGS;
            }
            let locked = parent.inherited.load(Ordering::Relaxed);
            if (attrs ^ parent.flags.get()) & locked != 0 {
                return Err(Errno(1));
            }
            let _writers = (attrs & MS_RDONLY != 0 && !parent.readonly())
                .then(|| parent.hold_mount_writers())
                .transpose()?;
            if parent.kind == Kind::Cgroup && flags & BIND == 0 {
                if let Some(value) = self.cgroup_mount_options(data)? {
                    self.cgroups
                        .borrow()
                        .nsdelegate
                        .store(value, Ordering::Relaxed);
                }
            }
            parent.flags.set(attrs);
            let events = self.mounts.as_ref().unwrap().0.borrow().events.clone();
            events.changed();
            return Ok(());
        }
        if flags & 8192 != 0 && flags & BIND == 0 {
            if flags & !8192 != 0 {
                return Err(Errno(95));
            }
            let source = self.mount_location(source.ok_or(Errno(22))?, true)?;
            return self.move_attached(&source, &target, parent, target_node);
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
        let mut bind_origin = None;
        let mut fuse_binding = None;
        let mut tmpfs_mode = None;
        let mut cgroup_options = None;
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
            if !ns
                .0
                .borrow()
                .mounts
                .iter()
                .any(|attached| Arc::ptr_eq(attached, m))
            {
                return Err(Errno(22));
            }
            if flags & REC == 0 && hides_locked_child(&ns.0.borrow().mounts, m, &source.key) {
                return Err(Errno(22));
            }
            devpts = m.devpts.clone();
            bind_origin = Some(m.clone());
            if flags & REC != 0 {
                for child in &ns.0.borrow().mounts {
                    if Arc::ptr_eq(child, m) {
                        continue;
                    }
                    let mut at = child.clone();
                    for _ in 0..ns.0.borrow().mounts.len() {
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
            (m.fs.clone(), node, source.key, m.kind, m.flags.local())
        } else {
            if !matches!(target_node.borrow().content, Content::Directory) {
                return Err(Errno(20));
            }
            let flags = if !strict_atime && flags & MS_NOATIME == 0 {
                flags | MS_RELATIME
            } else {
                flags
            };
            match kind.ok_or(Errno(22))? {
                b"fuse" => {
                    let (fs, binding) = fuse::prepare(self, data.ok_or(Errno(22))?)?;
                    fuse_binding = binding;
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    (fs, root, b"/".to_vec(), Kind::Fuse, flags & ATTRS)
                }
                b"fusectl" => {
                    if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
                        return Err(Errno(1));
                    }
                    if data.is_some_and(|data| !data.is_empty()) {
                        return Err(Errno(22));
                    }
                    let fs = self.pseudo.borrow().fuse_control.filesystem()?;
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    (
                        fs,
                        root,
                        b"/".to_vec(),
                        Kind::FuseControl,
                        (flags & ATTRS) | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                    )
                }
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
                b"mqueue" => {
                    if data.is_some_and(|d| !d.is_empty()) {
                        return Err(Errno(95));
                    }
                    let fs = self.mqueue_fs()?;
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    (fs, root, b"/".to_vec(), Kind::Mqueue, flags & ATTRS)
                }
                b"tmpfs" => {
                    let (limit, nodes, mode, uid, gid) = tmpfs_options(
                        data.unwrap_or_default(),
                        self.pseudo.borrow().runtime.memory_limit as u64,
                    )?;
                    tmpfs_mode = (mode != 0o1777).then_some(mode);
                    let fs = ram_filesystem(
                        limit,
                        nodes,
                        mode,
                        uid.unwrap_or(self.credentials.fsuid),
                        gid.unwrap_or(self.credentials.fsgid),
                        true,
                    )?;
                    let root = fs.borrow().paths[b"/".as_slice()].clone();
                    (fs, root, b"/".to_vec(), Kind::Tmpfs, flags & ATTRS)
                }
                b"cgroup2" => {
                    cgroup_options = self.cgroup_mount_options(data)?;
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
                    if parent.kind == Kind::Cgroup && Arc::ptr_eq(&target_node, &root) {
                        return Err(Errno(16));
                    }
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
                    (self.fs.clone(), node, key.to_vec(), k, flags & ATTRS)
                }
                _ => return Err(Errno(19)),
            }
        };
        if ns.0.borrow().mounts.len() + additions.len() + 1 > self.mount_limit() {
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
        } else if let Some(m) = &bind_origin {
            m.pid_namespace.clone()
        } else {
            (mount_kind == Kind::Proc).then(|| self.pid_ns.clone())
        };
        let locked_visible = if bind_origin.is_none() {
            self.visible_pseudo_flags(mount_kind, attrs)?
        } else {
            0
        };
        let root = Arc::new(Mount::new(MountInit {
            id: new_mount_id()?,
            fs,
            root,
            root_key,
            kind: mount_kind,
            display: if let Some(m) = &bind_origin {
                m.display.clone()
            } else if namespace.is_some() {
                MountDisplay::default()
            } else {
                MountDisplay {
                    source: Some(Arc::from(
                        source.filter(|s| !s.is_empty()).unwrap_or(b"none"),
                    )),
                    nsdelegate: (mount_kind == Kind::Cgroup)
                        .then(|| self.cgroups.borrow().nsdelegate.clone()),
                    tmpfs_mode,
                }
            },
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
        root.inherited.store(locked_visible, Ordering::Relaxed);
        if let Some(source_mount) = &bind_origin {
            root.set_propagation(source_mount.propagation());
            root.inherited.store(
                source_mount.inherited.load(Ordering::Relaxed) & !LOCK_ATTACHMENT,
                Ordering::Relaxed,
            );
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
        self.publish_mounts(&ns, added, || {
            if let Some(value) = cgroup_options {
                self.cgroups
                    .borrow()
                    .nsdelegate
                    .store(value, Ordering::Relaxed);
            }
        })?;
        if let Some(binding) = fuse_binding {
            binding.publish();
        }
        Ok(())
    }
    fn visible_pseudo_flags(&self, kind: Kind, attrs: u64) -> Result<u64> {
        if !matches!(kind, Kind::Proc | Kind::Sysfs) {
            return Ok(0);
        }
        let table = self.mounts.as_ref().ok_or(Errno(22))?.0.borrow();
        if table.user_namespace.is_initial() {
            return Ok(0);
        }
        let root = if kind == Kind::Proc {
            b"/proc".as_slice()
        } else {
            b"/sys"
        };
        for m in &table.mounts {
            if m.kind != kind || m.root_key != root {
                continue;
            }
            let locked = m.inherited.load(Ordering::Relaxed) & (MS_RDONLY | ATIME_FLAGS);
            if (m.flags.get() ^ attrs) & locked != 0 {
                continue;
            }
            if table.mounts.iter().any(|child| {
                child.inherited.load(Ordering::Relaxed) & LOCK_ATTACHMENT != 0
                    && child.parent.borrow().as_ref().is_some_and(|a| {
                        // sysfs deliberately exposes an empty mountpoint for cgroupfs.
                        Arc::ptr_eq(&a.parent, m)
                            && !(kind == Kind::Sysfs && a.key() == b"/sys/fs/cgroup")
                    })
            }) {
                continue;
            }
            return Ok(locked);
        }
        Err(Errno(1))
    }
    fn move_attached(
        &self,
        source: &ResolvedPath,
        target: &ResolvedPath,
        parent: Arc<Mount>,
        target_node: NodeRef,
    ) -> Result<()> {
        let moved = source.mount.as_ref().ok_or(Errno(22))?;
        if moved.inherited.load(Ordering::Relaxed) & LOCK_ATTACHMENT != 0 {
            return Err(Errno(22));
        }
        if moved
            .parent
            .borrow()
            .as_ref()
            .is_some_and(|a| a.parent.propagation().shared.is_some())
        {
            return Err(Errno(22));
        }
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
        if !self.is_mount_root(source)
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
            fallback: target.key.clone(),
        });
        let events = table.events.clone();
        drop(table);
        events.changed();
        Ok(())
    }
    pub fn umount(&mut self, target: &[u8], flags: u64) -> Result<()> {
        let admin = self.mount_admin()?;
        let _lease = admin.enter();
        self.umount_locked(target, flags)
    }
    pub(super) fn umount_locked(&mut self, target: &[u8], flags: u64) -> Result<()> {
        if !self.credentials.has_ns_cap(
            &self
                .mounts
                .as_ref()
                .map_or_else(UserNamespace::default, |n| {
                    n.0.borrow().user_namespace.clone()
                }),
            capabilities::SYS_ADMIN,
        ) {
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
        let _change = self.path_change();
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
        let ns = self.mounts.as_ref().ok_or(Errno(22))?;
        if !self
            .credentials
            .has_ns_cap(&ns.0.borrow().user_namespace, capabilities::SYS_ADMIN)
        {
            return Err(Errno(1));
        }
        let _change = self.path_change();
        let new = self.resolve(AT_FDCWD, new_root)?;
        if !matches!(self.node(&new)?.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let old = self.mount_location(put_old, true)?;
        let old_node = self.node(&old)?;
        if !matches!(old_node.borrow().content, Content::Directory) {
            return Err(Errno(20));
        }
        let current = self.root_location()?;
        let previous = current.mount.as_ref().ok_or(Errno(22))?;
        let new_mount = new.mount.as_ref().ok_or(Errno(22))?;
        let old_mount = old.mount.as_ref().ok_or(Errno(22))?;
        let original_link = previous.parent.borrow().clone();
        let source_link = new_mount.parent.borrow().clone();
        let shared_parent = |link: &Attachment| link.parent.propagation().shared.is_some();
        let mut table = ns.0.borrow_mut();
        if old_mount.propagation().shared.is_some()
            || original_link.as_ref().is_some_and(shared_parent)
            || source_link.as_ref().is_some_and(shared_parent)
            || new_mount.inherited.load(Ordering::Relaxed) & LOCK_ATTACHMENT != 0
            || [previous, new_mount, old_mount]
                .iter()
                .any(|m| !table.mounts.iter().any(|entry| Arc::ptr_eq(entry, m)))
        {
            return Err(Errno(22));
        }
        if Arc::ptr_eq(previous, new_mount) || Arc::ptr_eq(previous, old_mount) {
            return Err(Errno(16));
        }
        if source_link.is_none()
            || !self.is_mount_root(&current)
            || !self.is_mount_root(&new)
            || mount_absolute(new_mount, &new.key, previous, table.mounts.len()).is_none()
            || mount_absolute(old_mount, &old.key, new_mount, table.mounts.len()).is_none()
        {
            return Err(Errno(22));
        }

        // Replace the caller's root at its original attachment. Other roots
        // in this namespace keep their own mount and see the exchanged subtree.
        // Check both ancestry chains before moving either edge.
        *new_mount.parent.borrow_mut() = original_link;
        *previous.parent.borrow_mut() = Some(Attachment {
            parent: old_mount.clone(),
            node: old_node,
            fallback: old.key,
        });
        if previous
            .inherited
            .fetch_and(!LOCK_ATTACHMENT, Ordering::Relaxed)
            & LOCK_ATTACHMENT
            != 0
        {
            new_mount
                .inherited
                .fetch_or(LOCK_ATTACHMENT, Ordering::Relaxed);
        }
        if Arc::ptr_eq(&table.root, previous) {
            table.root = new_mount.clone();
        }
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
pub(super) fn ram_filesystem(
    limit: u64,
    nodes: usize,
    mode: u32,
    uid: u32,
    gid: u32,
    tmpfs: bool,
) -> Result<FsHandle> {
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
        uid,
        gid,
        volatile: false,
        inode,
        links: 1,
        times: [storage::Timestamp::now(); 3],
        xattrs: BTreeMap::new(),
        seals: None,
    }));
    let fs = FsHandle::with_page_accounting(
        Filesystem {
            shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
            paths: BTreeMap::from([(b"/".to_vec(), root.clone())]),
            inodes: vec![Arc::downgrade(&root)],
            next_inode: inode + 1,
            limits: StorageLimits {
                file_bytes: limit,
                nodes,
            },
            disk: None,
            volume: None,
        },
        tmpfs,
    );
    Ok(fs)
}

pub(super) fn new_mount_id() -> Result<u64> {
    NEXT_MOUNT
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_add(1).filter(|n| *n < 0x1000_0000)
        })
        .map_err(|_| Errno(28))
}
fn copy_mount(m: &Mount) -> Result<Arc<Mount>> {
    copy_mount_root(m, m.root.clone(), m.root_key.clone())
}
fn copy_mount_root(m: &Mount, root: NodeRef, key: Vec<u8>) -> Result<Arc<Mount>> {
    let copy = Arc::new(Mount::new(MountInit {
        id: new_mount_id()?,
        fs: m.fs.clone(),
        root,
        root_key: key,
        kind: m.kind,
        display: m.display.clone(),
        namespace: m.namespace.clone(),
        pid_namespace: m.pid_namespace.clone(),
        devpts: m.devpts.clone(),
        flags: Cell::new(m.flags.local()),
        writers: Arc::default(),
        parent: RefCell::new(None),
    }));
    copy.inherited
        .store(m.inherited.load(Ordering::Relaxed), Ordering::Relaxed);
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
            b"nr_blocks" => {
                let blocks = tmpfs_quantity(value)?;
                size = if blocks == 0 {
                    i64::MAX as u64
                } else {
                    blocks
                        .checked_mul(trames_memory::PAGE_SIZE)
                        .filter(|&v| v <= i64::MAX as u64)
                        .ok_or(Errno(22))?
                };
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
            Kind::Fuse => "fuse",
            Kind::FuseControl => "fusectl",
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
    fn source(&self) -> &[u8] {
        self.display.source.as_deref().unwrap_or_else(|| {
            if self.kind == Kind::Root {
                b"/dev/vda1"
            } else {
                self.fs_name().as_bytes()
            }
        })
    }
    fn super_options(&self) -> String {
        if self
            .display
            .nsdelegate
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            "nsdelegate".to_owned()
        } else if let Some(mode) = self.display.tmpfs_mode {
            format!("mode={mode:o}")
        } else {
            self.fs
                .borrow()
                .overlay
                .as_ref()
                .map(|o| escape_mount_field(o.options()))
                .unwrap_or_default()
        }
    }
    fn super_readonly(&self) -> bool {
        self.fs
            .super_readonly
            .as_ref()
            .map_or_else(|| self.readonly(), |ro| ro.load(Ordering::Relaxed))
    }
    fn reported_root(&self, filesystem_root: Vec<u8>, cgroup_root: &[u8]) -> Vec<u8> {
        let root = match self.kind {
            Kind::Cgroup => linux_namespace::relative_cgroup_path(cgroup_root, &filesystem_root),
            Kind::Proc | Kind::Sysfs | Kind::Devpts => self
                .root_path()
                .strip_prefix(self.root_key.as_slice())
                .unwrap_or(b"/")
                .to_vec(),
            _ => filesystem_root,
        };
        if root.is_empty() {
            b"/".to_vec()
        } else {
            root
        }
    }
    fn options(&self) -> String {
        let flags = self.flags.get();
        let mut out = if flags & MS_RDONLY != 0 { "ro" } else { "rw" }.to_owned();
        for (bit, label) in [
            (MS_NOSUID, ",nosuid"),
            (MS_NODEV, ",nodev"),
            (MS_NOEXEC, ",noexec"),
            (MS_NOATIME, ",noatime"),
            (MS_NODIRATIME, ",nodiratime"),
            (MS_RELATIME, ",relatime"),
        ] {
            if flags & bit != 0 {
                out.push_str(label);
            }
        }
        out
    }
}
pub(super) fn table_text(snapshot: &NamespaceSnapshot, info: bool, cgroup_root: &[u8]) -> Vec<u8> {
    let Some(table) = snapshot.mount.upgrade() else {
        return Vec::new();
    };
    let table = table.borrow();
    let alive = if table
        .mounts
        .iter()
        .any(|m| m.propagation().master.is_some())
    {
        propagation::live_groups(&table.admin.namespaces())
    } else {
        Default::default()
    };
    let mut text = String::new();
    for m in &table.mounts {
        let Some(mut target) = mount_absolute(m, &m.root_path(), &table.root, table.mounts.len())
        else {
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
            let Some(root_path) =
                mount_absolute(&root_mount, &root_key, &table.root, table.mounts.len())
            else {
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
        let source = escape_mount_field(m.source());
        let flags = m.options();
        let super_options = m.super_options();
        let separator = if super_options.is_empty() { "" } else { "," };
        if info {
            let root = m.reported_root(filesystem_root, cgroup_root);
            let dev = m.device();
            let parent = m
                .parent
                .borrow()
                .as_ref()
                .map_or(table.root_parent_id, |a| a.parent.id);
            text.push_str(&format!(
                "{} {} {}:{} {} {} {}{} - {} {} {}{}{}\n",
                m.id,
                parent,
                (dev >> 8) & 0xfff,
                (dev & 0xff) | ((dev >> 12) & !0xff),
                escape_mount_field(&root),
                escape_mount_field(&target),
                flags,
                {
                    let p = m.propagation().resolved(&alive);
                    let mut tags = String::new();
                    if let Some(group) = p.shared {
                        tags.push_str(&format!(" shared:{}", group.id));
                    }
                    if let Some(group) = p.master {
                        tags.push_str(&format!(" master:{}", group.id));
                    }
                    tags
                },
                m.fs_name(),
                source,
                if m.super_readonly() { "ro" } else { "rw" },
                separator,
                super_options,
            ));
        } else {
            text.push_str(&format!(
                "{} {} {} {}{}{} 0 0\n",
                source,
                escape_mount_field(&target),
                m.fs_name(),
                flags,
                separator,
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
        let flags = m.flags.get();
        let stat_flags = (flags
            & (MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_NODIRATIME))
            | if flags & MS_RELATIME != 0 { 4096 } else { 0 };
        #[cfg(all(feature = "hostfs", unix))]
        if let Some(host) = &m.fs.host {
            return host.statfs(stat_flags);
        }
        let mut out = [0; 120];
        if let Some(fs) = &m.fs.fuse {
            let query = self.query.as_ref().ok_or(Errno(95))?;
            query.prepared.borrow_mut().fuse =
                Some(Box::new(fuse::Metadata::statfs(self, m, fs, stat_flags)?));
            return query.defer();
        }
        let magic = m.kind.statfs_magic();
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
            (80, stat_flags),
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
    fn getcwd_renders_an_outside_bind_directory_until_its_name_is_removed() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/src/sub", 0o755).unwrap();
        v.mount(Some(b"/src"), b"/dst", None, 4096, None).unwrap();
        v.chdir(b"/dst/sub").unwrap();
        let mut peer = v.clone();
        v.chroot(b"/new").unwrap();
        assert_eq!(
            v.cwd_name::<true>(&v.context.paths.borrow()).unwrap(),
            b"(unreachable)/dst/sub"
        );
        assert_eq!(v.cwd(), Err(Errno(2)));
        assert_eq!(
            peer.cwd_name::<true>(&peer.context.paths.borrow()).unwrap(),
            b"/dst/sub"
        );
        peer.unlink_at(AT_FDCWD, b"/src/sub", true).unwrap();
        assert_eq!(v.cwd_name::<true>(&v.context.paths.borrow()), Err(Errno(2)));
    }

    #[test]
    fn proc_lookup_follows_the_mount_across_bind_and_overmount() {
        let mut v = setup();
        v.mount(Some(b"/proc/fs"), b"/dst", None, 4096, None)
            .unwrap();
        v.mount(None, b"/proc/fs", Some(b"tmpfs"), 0, None).unwrap();

        let dir = v.open_at(AT_FDCWD, b"/dst", 0, 0).unwrap() as i32;
        assert_eq!(v.mkdir_at(dir, b"child", 0o755), Err(Errno(2)));
        assert_eq!(v.open_at(dir, &[b'x'; 256], 0, 0), Err(Errno(2)));
        v.mkdir_at(AT_FDCWD, b"/proc/fs/child", 0o755).unwrap();
        let covered = v.open_at(AT_FDCWD, b"/proc/fs", 0, 0).unwrap() as i32;
        assert_eq!(v.open_at(covered, &[b'x'; 256], 0, 0), Err(Errno(36)));
        assert_eq!(v.open_at(dir, b"child", 0, 0), Err(Errno(2)));
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
    fn pivot_preserves_the_root_slot_and_unrelated_fs_roots() {
        let mut parent = setup();
        let slot = parent.mounts.as_ref().unwrap().0.borrow().root_parent_id;
        let original = parent.root_location().unwrap().mount.unwrap().id;
        assert_ne!(slot, original);
        parent
            .mount(None, b"/new", Some(b"tmpfs"), 0, None)
            .unwrap();
        parent.mkdir_at(AT_FDCWD, b"/new/next", 0o755).unwrap();
        parent
            .mount(None, b"/new/next", Some(b"tmpfs"), 0, None)
            .unwrap();
        parent.mkdir_at(AT_FDCWD, b"/new/next/old", 0o755).unwrap();
        let next = parent.mount_id_at(AT_FDCWD, b"/new/next", false).unwrap();
        let mut child = parent.clone();
        child.chroot(b"/new").unwrap();
        child.pivot_root(b"/next", b"/next/old").unwrap();
        assert_eq!(parent.root_location().unwrap().mount.unwrap().id, original);
        assert_eq!(child.root_location().unwrap().mount.unwrap().id, next);
        assert_eq!(parent.mount_id_at(AT_FDCWD, b"/new", false).unwrap(), next);
        parent.pivot_root(b"/new", b"/new/old").unwrap();
        let table = parent.mounts.as_ref().unwrap().0.borrow();
        assert_eq!(table.root.id, next);
        assert_eq!(table.root_parent_id, slot);
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

pub(super) fn mount_absolute(
    mount: &Arc<Mount>,
    key: &[u8],
    root: &Arc<Mount>,
    max_steps: usize,
) -> Option<Vec<u8>> {
    let mut at = mount.clone();
    let mut key = key.to_vec();
    let mut suffix = Vec::new();
    for _ in 0..=max_steps {
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
        assert_eq!(
            v.fd_snapshot().iter().find(|f| f.fd == fd).unwrap().target,
            b"/b/1/status"
        );
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
        for _ in 0..parent.mount_limit() + 16 {
            let mut child = parent.clone();
            child.unshare_mounts().unwrap();
            child.mount(None, b"/b", Some(b"tmpfs"), 0, None).unwrap();
            siblings.push(child);
        }
        assert!(parent.mount_resources.borrow().len() > parent.mount_limit());
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
    fn mount_max_tracks_live_sysctl_across_namespaces_and_existing_trees() {
        let mut parent = vfs();
        let path = b"/proc/sys/fs/mount-max";
        let mut sibling = parent.clone();
        sibling.unshare_mounts().unwrap();
        let fd = parent.open_at(AT_FDCWD, path, 1, 0).unwrap();
        parent.write(fd, b"1\n").unwrap();
        parent.close(fd).unwrap();
        assert_eq!(
            sibling.mount(None, b"/b", Some(b"tmpfs"), 0, None),
            Err(Errno(28))
        );
        let fd = sibling.open_at(AT_FDCWD, path, 0, 0).unwrap();
        assert_eq!(sibling.read(fd, 16).unwrap(), b"1\n");
        sibling.close(fd).unwrap();
        let fd = sibling.open_at(AT_FDCWD, path, 1, 0).unwrap();
        assert_eq!(sibling.write(fd, b"0"), Err(Errno(22)));
        sibling.write(fd, b"512").unwrap();
        sibling.close(fd).unwrap();
        parent.mount(None, b"/b", Some(b"tmpfs"), 0, None).unwrap();
        sibling.mount(None, b"/b", Some(b"tmpfs"), 0, None).unwrap();
    }
    #[test]
    fn per_namespace_mount_limit_failure_is_atomic_and_recoverable() {
        let mut v = vfs();
        while v.mounts.as_ref().unwrap().0.borrow().mounts.len() < v.mount_limit() {
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
            v.mount_limit()
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
        let text = String::from_utf8(table_text(&v.namespace_snapshot(), true, b"/")).unwrap();
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
        assert_eq!(
            Vfs::filesystem_capacity(&mount.fs.borrow()).used_bytes,
            4096
        );
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
        assert_eq!(capacity.used_bytes, 4096);
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
    fn directory_atime_survives_remount_and_bind_keeps_its_own_policy() {
        let mut v = vfs();
        v.mount(
            Some(b"ram disk"),
            b"/a",
            Some(b"tmpfs"),
            MS_NODIRATIME,
            Some(b"mode=755"),
        )
        .unwrap();
        v.mount(Some(b"/a"), b"/b", None, 4096, None).unwrap();
        v.mount(None, b"/a", None, 32 | MS_RDONLY, None).unwrap();
        let dir = v.open_at(AT_FDCWD, b"/b", O_DIRECTORY, 0).unwrap();
        let open = v.descriptor(dir).unwrap().open.clone();
        let node = open.borrow().node.clone().unwrap();
        let old = storage::Timestamp {
            seconds: 5,
            nanos: 0,
        };
        node.borrow_mut().times[0] = old;
        v.getdents(dir, 4096).unwrap();
        assert_eq!(node.borrow().times[0], old);
        v.mount(None, b"/b", None, 4096 | 32 | MS_STRICTATIME, None)
            .unwrap();
        v.getdents(dir, 4096).unwrap();
        assert!(node.borrow().times[0].seconds > old.seconds);
        let text = String::from_utf8(table_text(&v.namespace_snapshot(), false, b"/")).unwrap();
        assert!(text.contains("ram\\040disk /a tmpfs ro,nodiratime,relatime,mode=755 "));
        assert!(text.contains("ram\\040disk /b tmpfs rw,mode=755 "));
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

fn atime_enabled(node: &Node, flags: u64) -> bool {
    !node.volatile
        && flags & (MS_RDONLY | MS_NOATIME) == 0
        && (flags & MS_NODIRATIME == 0 || !matches!(node.content, Content::Directory))
}

fn relatime_due(node: &Node, now: storage::Timestamp) -> bool {
    let atime = node.times[0];
    node.times[1..]
        .iter()
        .any(|t| (t.seconds, t.nanos) >= (atime.seconds, atime.nanos))
        || now.seconds.saturating_sub(atime.seconds) >= 86400
}

pub(super) fn link_accessed(
    node: &NodeRef,
    state: std::sync::RwLockReadGuard<'_, Node>,
    mount: Option<&MountData>,
) {
    let flags = mount.map_or(0, |m| m.flags.get());
    if !atime_enabled(&state, flags)
        || flags & MS_RELATIME != 0 && !relatime_due(&state, storage::Timestamp::now())
    {
        return;
    }
    drop(state);
    accessed(&mut node.borrow_mut(), mount);
}

pub(super) fn accessed(node: &mut Node, mount: Option<&MountData>) {
    let flags = mount.map_or(0, |m| m.flags.get());
    if !atime_enabled(node, flags) {
        return;
    }
    if let Content::File(storage::FileData::Plain(data)) = &node.content {
        if data.accessed(flags & MS_RELATIME != 0).is_some() {
            return; // The original shared file metadata is canonical already.
        }
    }
    let now = storage::Timestamp::now();
    if flags & MS_RELATIME != 0 && !relatime_due(node, now) {
        return;
    }
    node.times[0] = now;
}
