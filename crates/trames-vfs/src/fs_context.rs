// SPDX-License-Identifier: GPL-3.0-or-later
//! One Linux fs_struct per CLONE_FS domain; no per-syscall peer propagation.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize};

/// One original task's fs_struct membership, independently of path observers.
#[derive(Clone)]
pub struct FsOwner(Arc<TaskFs>);
struct TaskFs {
    users: Arc<AtomicUsize>,
    active: AtomicBool,
}
impl FsOwner {
    fn new(users: &Arc<AtomicUsize>) -> Self {
        users.fetch_add(1, Ordering::Relaxed);
        Self(Arc::new(TaskFs {
            users: users.clone(),
            active: AtomicBool::new(true),
        }))
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub fn retire(&self) {
        self.0.retire();
    }
}
impl TaskFs {
    fn retire(&self) {
        if self.active.swap(false, Ordering::Relaxed) {
            self.users.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
impl Drop for TaskFs {
    fn drop(&mut self) {
        self.retire();
    }
}

/// A shared scalar, also usable by workers without retaining paths or a VFS.
#[derive(Clone)]
pub struct Umask(Arc<AtomicU32>);
impl Default for Umask {
    fn default() -> Self {
        Self(Arc::new(AtomicU32::new(0o022)))
    }
}
impl Umask {
    pub fn get(&self) -> u32 {
        self.0.load(Ordering::Relaxed)
    }
    pub fn swap(&self, mask: u32) -> u32 {
        self.0.swap(mask & 0o777, Ordering::Relaxed)
    }
    fn fork(&self) -> Self {
        Self(Arc::new(AtomicU32::new(self.get())))
    }
}

#[derive(Clone, Default)]
pub(super) struct Paths {
    #[cfg(all(feature = "hostfs", unix))]
    pub host_cwd: Option<Arc<hostfs::OpenFile>>,
    pub cwd_node: Option<NodeRef>,
    pub root_node: Option<NodeRef>,
    pub cwd_mount: Option<Arc<Mount>>,
    pub root_mount: Option<Arc<Mount>>,
}
// Canonical fs_struct path resources contain no owner Rc. A control view may
// project mount topology locally, but cwd/root and their detached traversal pins
// belong to the one original shared fs_struct.
#[derive(Default)]
struct SharedPaths {
    #[cfg(all(feature = "hostfs", unix))]
    host_cwd: Option<Arc<hostfs::OpenFile>>,
    cwd_node: Option<NodeRef>,
    root_node: Option<NodeRef>,
    cwd_mount: Option<Arc<mounts::MountData>>,
    root_mount: Option<Arc<mounts::MountData>>,
    _cwd_pin: Option<mounts::DirectoryPin>,
    _root_pin: Option<mounts::DirectoryPin>,
    _cwd_use: Option<mounts::MountUse>,
    _root_use: Option<mounts::MountUse>,
}
/// Read-only authority over the original fs_struct paths, with fresh private
/// mount projections for each observer. It is not a task or namespace owner.
#[derive(Clone)]
pub(super) struct PathSource(std::sync::Weak<SharedCell<SharedPaths>>);
impl PathSource {
    pub(super) fn directories(&self) -> (Option<ProcDirectory>, Option<ProcDirectory>) {
        self.0
            .upgrade()
            .map_or((None, None), |paths| paths.borrow().directories())
    }
    pub(super) fn install(&self, context: &mut FsContext) {
        if let Some(paths) = self.0.upgrade() {
            context.paths.shared = paths;
        }
    }
}
impl SharedPaths {
    fn directories(&self) -> (Option<ProcDirectory>, Option<ProcDirectory>) {
        let directory = |mount: &Option<Arc<mounts::MountData>>, node: &Option<NodeRef>| {
            let mount = mount.as_ref()?;
            Some(ProcDirectory {
                node: node.as_ref().unwrap_or(&mount.root).clone(),
                mount: mount.clone(),
            })
        };
        (
            directory(&self.cwd_mount, &self.cwd_node),
            directory(&self.root_mount, &self.root_node),
        )
    }
    fn from_paths(paths: &Paths) -> Self {
        let cwd_mount = paths.cwd_mount.as_ref().map(|m| m.shared.clone());
        let root_mount = paths.root_mount.as_ref().map(|m| m.shared.clone());
        Self {
            #[cfg(all(feature = "hostfs", unix))]
            host_cwd: paths.host_cwd.clone(),
            cwd_node: paths.cwd_node.clone(),
            root_node: paths.root_node.clone(),
            _cwd_pin: cwd_mount.clone().map(mounts::DirectoryPin::new),
            _root_pin: root_mount.clone().map(mounts::DirectoryPin::new),
            _cwd_use: cwd_mount
                .as_ref()
                .map(|m| mounts::MountUse::new(m.identity.clone())),
            _root_use: root_mount
                .as_ref()
                .map(|m| mounts::MountUse::new(m.identity.clone())),
            cwd_mount,
            root_mount,
        }
    }
}
pub(super) struct PathStore {
    shared: Arc<SharedCell<SharedPaths>>,
    // Cache only the current cwd/root mount handles, never the complete table.
    projections: RefCell<Vec<Arc<Mount>>>,
    pub(super) registry: mounts::Registry,
    contexts: Arc<std::sync::Mutex<Contexts>>,
    users: Arc<AtomicUsize>,
}
struct Contexts {
    paths: Vec<std::sync::Weak<SharedCell<SharedPaths>>>,
    prune_at: usize,
}
impl Contexts {
    fn insert(&mut self, paths: &Arc<SharedCell<SharedPaths>>) {
        // Amortize weak-entry retirement; a live task population must not turn
        // every fork into another all-task scan. This is not a task quota.
        if self.paths.len() >= self.prune_at {
            self.paths.retain(|context| context.strong_count() != 0);
            self.prune_at = self.paths.len().saturating_mul(2).max(64);
        }
        self.paths.push(Arc::downgrade(paths));
    }
}
impl Default for PathStore {
    fn default() -> Self {
        let shared = Arc::new(SharedCell::default());
        Self {
            contexts: Arc::new(std::sync::Mutex::new(Contexts {
                paths: vec![Arc::downgrade(&shared)],
                prune_at: 64,
            })),
            shared,
            users: Arc::default(),
            projections: RefCell::default(),
            registry: mounts::Registry::default(),
        }
    }
}
impl PathStore {
    pub(super) fn directories(&self) -> (Option<ProcDirectory>, Option<ProcDirectory>) {
        self.shared.borrow().directories()
    }
    fn project(&self, state: &SharedPaths) -> Paths {
        // Most reads keep the same mount resources, even when cwd's inode has
        // changed. Reuse this view's projections instead of rebuilding a mount
        // graph or scanning its registry on every pathname lookup.
        {
            let cached = self.projections.borrow();
            let lookup = |mount: &Option<Arc<mounts::MountData>>| match mount {
                None => Some(None),
                Some(mount) => cached
                    .iter()
                    .find(|m| Arc::ptr_eq(&m.shared, mount))
                    .cloned()
                    .map(Some),
            };
            if let (Some(cwd_mount), Some(root_mount)) =
                (lookup(&state.cwd_mount), lookup(&state.root_mount))
            {
                return Paths {
                    #[cfg(all(feature = "hostfs", unix))]
                    host_cwd: state.host_cwd.clone(),
                    cwd_node: state.cwd_node.clone(),
                    root_node: state.root_node.clone(),
                    cwd_mount,
                    root_mount,
                };
            }
        }
        let mut cache = BTreeMap::new();
        // Actual owner mounts retain their original namespace controls and
        // mutable topology; a query's registry contains only fresh projections.
        for mount in self
            .registry
            .borrow()
            .iter()
            .filter_map(std::sync::Weak::upgrade)
        {
            cache.insert(Arc::as_ptr(&mount.shared) as usize, mount);
        }
        for mount in self.projections.borrow().iter() {
            cache
                .entry(Arc::as_ptr(&mount.shared) as usize)
                .or_insert_with(|| mount.clone());
        }
        let mut project =
            |mount: &Arc<mounts::MountData>| Mount::query_projection(mount.clone(), &mut cache);
        let paths = Paths {
            #[cfg(all(feature = "hostfs", unix))]
            host_cwd: state.host_cwd.clone(),
            cwd_node: state.cwd_node.clone(),
            root_node: state.root_node.clone(),
            cwd_mount: state.cwd_mount.as_ref().map(&mut project),
            root_mount: state.root_mount.as_ref().map(&mut project),
        };
        self.remember(&paths);
        paths
    }
    fn remember(&self, paths: &Paths) {
        *self.projections.borrow_mut() = paths
            .cwd_mount
            .iter()
            .chain(paths.root_mount.iter())
            .cloned()
            .collect();
    }
    pub fn borrow(&self) -> Paths {
        self.project(&self.shared.borrow())
    }
    pub fn borrow_mut(&self) -> PathsWrite<'_> {
        let state = self.shared.borrow_mut();
        let paths = self.project(&state);
        PathsWrite {
            store: self,
            state,
            paths,
        }
    }
    fn shared(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            users: self.users.clone(),
            projections: RefCell::default(),
            registry: self.registry.clone(),
            contexts: self.contexts.clone(),
        }
    }
    fn fork(&self) -> Self {
        // Serialize only fs_struct creation with pivot's reference replacement;
        // a copied old root must not be registered after pivot has visited it.
        let mut contexts = self.contexts.lock().unwrap();
        let paths = self.borrow();
        let result = Self {
            shared: Arc::new(SharedCell::new(SharedPaths::from_paths(&paths))),
            users: Arc::default(),
            projections: RefCell::default(),
            registry: self.registry.clone(),
            contexts: self.contexts.clone(),
        };
        result.remember(&paths);
        contexts.insert(&result.shared);
        result
    }
    pub(super) fn pivot(&self, previous: &Arc<mounts::MountData>, new: &Arc<mounts::MountData>) {
        // Like Linux chroot_fs_refs: match the exact original mount+inode,
        // including independent fs_structs, never rewrite an open directory FD.
        let mut contexts = self.contexts.lock().unwrap();
        contexts.paths.retain(|weak| {
            let Some(context) = weak.upgrade() else {
                return false;
            };
            let mut paths = context.borrow_mut();
            let matches = |mount: &Option<Arc<mounts::MountData>>, node: &Option<NodeRef>| {
                mount.as_ref().is_some_and(|m| Arc::ptr_eq(m, previous))
                    && node.as_ref().is_none_or(|n| Arc::ptr_eq(n, &previous.root))
            };
            if matches(&paths.cwd_mount, &paths.cwd_node) {
                paths.cwd_mount = Some(new.clone());
                paths.cwd_node = Some(new.root.clone());
                paths._cwd_pin = Some(mounts::DirectoryPin::new(new.clone()));
                paths._cwd_use = Some(mounts::MountUse::new(new.identity.clone()));
                #[cfg(all(feature = "hostfs", unix))]
                {
                    paths.host_cwd = None;
                }
            }
            if matches(&paths.root_mount, &paths.root_node) {
                paths.root_mount = Some(new.clone());
                paths.root_node = Some(new.root.clone());
                paths._root_pin = Some(mounts::DirectoryPin::new(new.clone()));
                paths._root_use = Some(mounts::MountUse::new(new.identity.clone()));
            }
            true
        });
    }
    pub fn has_observers(&self) -> bool {
        Arc::strong_count(&self.shared) > 1
    }
}
pub(super) struct PathsWrite<'a> {
    store: &'a PathStore,
    state: std::sync::RwLockWriteGuard<'a, SharedPaths>,
    paths: Paths,
}
impl std::ops::Deref for PathsWrite<'_> {
    type Target = Paths;
    fn deref(&self) -> &Paths {
        &self.paths
    }
}
impl std::ops::DerefMut for PathsWrite<'_> {
    fn deref_mut(&mut self) -> &mut Paths {
        &mut self.paths
    }
}
impl Drop for PathsWrite<'_> {
    fn drop(&mut self) {
        *self.state = SharedPaths::from_paths(&self.paths);
        self.store.remember(&self.paths);
    }
}
/// Original fs_struct resources only; private pathname caches do not cross.
#[derive(Clone)]
pub(super) struct ContextPublication {
    shared: Arc<SharedCell<SharedPaths>>,
    users: Arc<AtomicUsize>,
    contexts: Arc<std::sync::Mutex<Contexts>>,
    mask: Umask,
    owner: Option<FsOwner>,
}
impl ContextPublication {
    pub(super) fn same_owner(&self, context: &FsContext) -> bool {
        match (&self.owner, &context.owner) {
            (Some(a), Some(b)) => a.same(b),
            (None, None) => true,
            _ => false,
        }
    }
    pub(super) fn install(&self, registry: mounts::Registry) -> FsContext {
        FsContext {
            paths: PathStore {
                shared: self.shared.clone(),
                users: self.users.clone(),
                contexts: self.contexts.clone(),
                projections: RefCell::default(),
                registry,
            },
            mask: self.mask.clone(),
            owner: self.owner.clone(),
        }
    }
}
pub(super) struct FsContext {
    pub paths: PathStore,
    mask: Umask,
    owner: Option<FsOwner>,
}
impl Default for FsContext {
    fn default() -> Self {
        let paths = PathStore::default();
        Self {
            owner: Some(FsOwner::new(&paths.users)),
            paths,
            mask: Umask::default(),
        }
    }
}
impl FsContext {
    pub(super) fn publication(&self, owner: Option<FsOwner>) -> ContextPublication {
        ContextPublication {
            shared: self.paths.shared.clone(),
            users: self.paths.users.clone(),
            contexts: self.paths.contexts.clone(),
            mask: self.mask.clone(),
            owner,
        }
    }

    pub(super) fn disown(&mut self) {
        self.owner = None;
    }

    pub(super) fn share_mask(&mut self, other: &Self) {
        self.mask = other.mask.clone();
    }
    /// Original fs_struct resources; local mount projections are always fresh.
    pub(super) fn share_paths(&mut self, other: &Self) {
        self.owner = None;
        self.paths = PathStore {
            shared: other.paths.shared.clone(),
            users: other.paths.users.clone(),
            projections: RefCell::default(),
            registry: self.paths.registry.clone(),
            contexts: other.paths.contexts.clone(),
        };
        self.mask = other.mask.clone();
    }
    pub(super) fn shared(&self) -> Self {
        Self {
            paths: self.paths.shared(),
            mask: self.mask.clone(),
            owner: Some(FsOwner::new(&self.paths.users)),
        }
    }
}
impl Drop for FsContext {
    fn drop(&mut self) {
        if let Some(owner) = &self.owner {
            owner.retire();
        }
    }
}
impl Clone for FsContext {
    fn clone(&self) -> Self {
        let paths = self.paths.fork();
        Self {
            owner: Some(FsOwner::new(&paths.users)),
            paths,
            mask: self.mask.fork(),
        }
    }
}
impl Vfs {
    pub(super) fn path_source(&self) -> PathSource {
        PathSource(Arc::downgrade(&self.context.paths.shared))
    }
    pub fn shares_context_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.context.paths.shared, &other.context.paths.shared)
    }
    pub fn context_owner(&self) -> Option<FsOwner> {
        self.context.owner.clone()
    }
    pub fn retire_context(&self) {
        if let Some(owner) = &self.context.owner {
            owner.retire();
        }
    }
    pub fn context_shared(&self) -> bool {
        self.context.paths.users.load(Ordering::Relaxed) > 1
    }
    pub fn unshare_context(&mut self) {
        self.context = self.context.clone();
    }
    pub fn umask(&self) -> u32 {
        self.context.mask.get()
    }
    pub fn set_umask(&self, mask: u32) -> u32 {
        self.context.mask.swap(mask)
    }
    pub fn umask_capability(&self) -> Umask {
        self.context.mask.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fs_membership_counts_tasks_not_queries_and_retires_before_collection() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<FsOwner>();
        let mut task = Vfs::default();
        let queries = task.path_queries();
        let retained = queries.retain_context();
        assert!(!task.context_shared());
        let peer = task.clone_with_resources(false, true);
        assert!(task.context_shared());
        let identity = peer.context_owner().unwrap();
        std::thread::spawn(move || identity.retire())
            .join()
            .unwrap();
        assert!(!task.context_shared(), "a departed task is not an fs user");
        assert!(
            task.shares_context_with(&peer),
            "cold projections still exist"
        );
        let peer = task.clone_with_resources(false, true);
        assert!(task.context_shared());
        let old = task.context_owner().unwrap();
        task.unshare_context();
        assert!(!task.context_shared());
        assert!(
            !peer.context_shared(),
            "replacement retires its old membership"
        );
        old.retire();
        assert!(!peer.context_shared(), "duplicate retirement is idempotent");
        drop((queries, retained));
    }

    #[test]
    fn mount_unshare_preserves_an_accepted_observers_original_context() {
        let mut task = Vfs::default();
        let observer = task.path_queries();
        let old_namespace = task.mounts.as_ref().unwrap().id();
        assert!(!task.context_shared());
        task.unshare_mounts().unwrap();
        assert_ne!(task.mounts.as_ref().unwrap().id(), old_namespace);
        let old = observer.view.borrow();
        assert_eq!(old.mounts.as_ref().unwrap().id(), old_namespace);
        assert!(!task.shares_context_with(&old));
        assert_eq!(old.cwd().unwrap(), b"/");
        assert_eq!(task.cwd().unwrap(), b"/");
    }

    #[test]
    fn shared_paths_and_mask_are_live_while_fork_copies_the_context() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<SharedPaths>();
        send_sync::<SharedCell<SharedPaths>>();
        let mut parent = Vfs::default();
        parent.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        parent.mkdir_at(AT_FDCWD, b"/b", 0o755).unwrap();
        let root = parent.context.paths.borrow().cwd_node.clone().unwrap();
        let refs = Arc::strong_count(&root);
        let mut shared = parent.clone_with_resources(false, true);
        let peers: Vec<_> = (0..32)
            .map(|_| parent.clone_with_resources(true, true))
            .collect();
        assert_eq!(Arc::strong_count(&root), refs);
        let fork = parent.clone();
        shared.chdir(b"/a").unwrap();
        assert_eq!(shared.set_umask(0o1077), 0o022);
        assert_eq!(parent.cwd().unwrap(), b"/a");
        assert_eq!(parent.umask(), 0o077);
        for peer in peers {
            assert!(peer.shares_context_with(&parent));
            assert_eq!(peer.cwd().unwrap(), b"/a");
        }
        assert_eq!(fork.cwd().unwrap(), b"/");
        assert_eq!(fork.umask(), 0o022);
        let directory = parent.open_at(AT_FDCWD, b"/b", 0, 0).unwrap();
        parent.chdir_fd(directory).unwrap();
        assert_eq!(shared.cwd().unwrap(), b"/b");
        assert_eq!(shared.chdir(b"/missing"), Err(Errno(2)));
        assert_eq!(parent.cwd().unwrap(), b"/b");
    }

    #[test]
    fn chroot_and_unshare_keep_paths_mask_and_files_domains_independent() {
        let mut parent = Vfs::default();
        parent.mkdir_at(AT_FDCWD, b"/jail", 0o755).unwrap();
        parent.mkdir_at(AT_FDCWD, b"/jail/inside", 0o755).unwrap();
        let mut shared = parent.clone_with_resources(true, true);
        shared.chroot(b"/jail").unwrap();
        parent.chdir(b"/inside").unwrap();
        assert_eq!(shared.cwd().unwrap(), b"/inside");
        let old_mask = parent.umask_capability();
        shared.unshare_context();
        assert!(!shared.shares_context_with(&parent));
        assert!(shared.shares_descriptors_with(&parent));
        shared.chdir(b"/").unwrap();
        shared.set_umask(0o077);
        assert_eq!(parent.cwd().unwrap(), b"/inside");
        assert_eq!(old_mask.get(), 0o022);
        old_mask.swap(0o027);
        assert_eq!(parent.umask(), 0o027);
        assert_eq!(shared.umask(), 0o077);
        let file = parent
            .open_at(AT_FDCWD, b"/shared-fd", 0x42, 0o666)
            .unwrap();
        assert!(shared.flags(file).is_ok());
    }

    #[test]
    fn mount_unshare_remaps_only_the_callers_context() {
        let parent = Vfs::default();
        let mut child = parent.clone_with_resources(false, true);
        let old = parent.mount_id_at(AT_FDCWD, b"/", false).unwrap();
        child.unshare_mounts().unwrap();
        assert!(!child.shares_context_with(&parent));
        assert_eq!(parent.mount_id_at(AT_FDCWD, b"/", false).unwrap(), old);
        assert_ne!(child.mount_id_at(AT_FDCWD, b"/", false).unwrap(), old);
        child.set_umask(0o077);
        assert_eq!(parent.umask(), 0o022);
        assert_eq!(child.cwd().unwrap(), b"/");
    }

    #[test]
    fn concurrent_umask_exchanges_return_each_predecessor_exactly_once() {
        let mask = Umask::default();
        mask.swap(0);
        let mut results = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|thread| {
                    let mask = &mask;
                    scope.spawn(move || {
                        (1..=32)
                            .map(|i| mask.swap(thread * 32 + i))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            threads
                .into_iter()
                .flat_map(|thread| thread.join().unwrap())
                .collect::<Vec<_>>()
        });
        results.push(mask.get());
        results.sort_unstable();
        assert_eq!(results, (0..=256).collect::<Vec<_>>());
    }
}
