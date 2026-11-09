// SPDX-License-Identifier: GPL-3.0-or-later
//! Task namespace transactions retain original resources and private caches.
//! This capability moves with one task; observers never become task owners.
use super::*;
use linux_namespace::NamespaceHandle;
use std::sync::{atomic::AtomicBool, Mutex};

/// Cold original task binding. Only actual membership commits publish here;
/// normal worker operations use their retained handles without a version check.
#[derive(Default)]
pub(super) struct Publication {
    pending: Mutex<Option<Bindings>>,
    dirty: AtomicBool,
}
struct Bindings {
    credentials: Credentials,
    files: SharedFiles,
    file_owner: FileTableOwner,
    context: fs_context::ContextPublication,
    uts: UtsNamespace,
    network: trames_net::Network,
    root_network: Arc<linux_namespace::RootNetwork>,
    ipc: Arc<linux_namespace::IpcNamespace>,
    cgroup: Arc<linux_namespace::CgroupNamespace>,
    pid_children: PidNamespace,
    mounts: Option<MountNamespace>,
}
impl Bindings {
    fn capture(view: &Vfs, files: FileTableOwner, context: Option<FsOwner>) -> Self {
        Self {
            credentials: view.credentials.clone(),
            files: view.shared_files(),
            file_owner: files,
            context: view.context.publication(context),
            uts: view.uts.clone(),
            network: view.network.clone(),
            root_network: view.root_network.clone(),
            ipc: view.ipc_namespace.clone(),
            cgroup: view.cgroup_namespace.clone(),
            pid_children: view.pid_children.clone(),
            mounts: view.mounts.clone(),
        }
    }
    fn install(self, target: &mut Vfs) {
        target.credentials = self.credentials;
        if !self.file_owner.same(&target.file_table_owner()) {
            target.fds = DescriptorTable::adopt(self.files, self.file_owner);
        }
        if !self.context.same_owner(&target.context) {
            target.context = self.context.install(target.mount_registry.clone());
        }
        target.uts = self.uts;
        target.network = self.network;
        target.root_network = self.root_network;
        target.ipc_namespace = self.ipc;
        target.cgroup_namespace = self.cgroup;
        target.pid_children = self.pid_children;
        target.mounts = self.mounts;
    }
    fn install_shared(&self, target: &mut Vfs) {
        target.credentials = self.credentials.clone();
        target.uts = self.uts.clone();
        target.network = self.network.clone();
        target.root_network = self.root_network.clone();
        target.ipc_namespace = self.ipc.clone();
        target.cgroup_namespace = self.cgroup.clone();
        target.pid_children = self.pid_children.clone();
        target.mounts = self.mounts.clone();
    }
}
impl Publication {
    fn publish(&self, bindings: Bindings) {
        let old = {
            let mut pending = self.pending.lock().unwrap();
            let old = pending.replace(bindings);
            self.dirty.store(true, Ordering::Release);
            old
        };
        drop(old);
    }
    fn take(&self) -> Option<Bindings> {
        if !self.dirty.load(Ordering::Acquire) {
            return None;
        }
        let mut pending = self.pending.lock().unwrap();
        self.dirty.store(false, Ordering::Relaxed);
        pending.take()
    }
}

const FILES: u64 = 0x400;
const FS: u64 = 0x200;
const ALLOWED: u64 = CLONE_NEWUTS
    | CLONE_NEWNS
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWIPC
    | CLONE_NEWCGROUP
    | FILES
    | FS;

/// Owned new-call capabilities. No reference to a private VFS cache escapes.
pub struct TaskNamespaceResources {
    pub credentials: Credentials,
    pub kernel_log: KernelLogAccess,
    pub files: SharedFiles,
    pub descriptors: DirectFds,
    pub direct_files: DirectFiles,
    pub network: DirectNetwork,
    pub paths: PathQueries,
    pub factory: DescriptorFactory,
    pub uring_files: BTreeMap<usize, PreparedFile>,
    pub flags: FdFlags,
    pub umask: Umask,
    pub uts: UtsAccess,
    pub images: Arc<dyn trames_graphics::ImageFds>,
}
pub struct TaskNamespaces {
    view: PathQueries,
    files: FileTableOwner,
    context: Option<FsOwner>,
    publication: Arc<Publication>,
    refresh: bool,
}
enum Change {
    Unshare(u64),
    CloseRange(u32, u32, u32),
    Setns(NamespaceHandle, u64),
}
pub struct TaskNamespaceWork {
    state: TaskNamespaces,
    change: Result<Change>,
    admin: Option<Arc<mounts::admin::Admin>>,
}
pub enum TaskNamespaceOwnerAttempt {
    Complete(Result<u64>),
    Waiting(Box<TaskNamespaceWork>),
}
pub enum TaskNamespaceAttempt {
    Complete(TaskNamespaces, Result<u64>),
    Waiting(TaskNamespaceWork),
}
impl Vfs {
    /// An accepted host filesystem operation retains the original Files/fs and
    /// namespace resources. Read pending source bindings without consuming the
    /// cold owner's publication; later unshare cannot retarget accepted work.
    pub fn host_files_context(&self) -> Self {
        let mut view = self.clone_with_resources(true, true);
        if let Some(publication) = self.task_namespace_publication.get() {
            if let Some(bindings) = publication.pending.lock().unwrap().as_ref() {
                bindings.install_shared(&mut view);
                view.fds = DescriptorTable::observe(bindings.files.clone());
                view.context = bindings.context.observe(view.mount_registry.clone());
            }
        }
        // Observing Files is not another Linux task's ownership reference.
        view.fds = DescriptorTable::observe(view.shared_files());
        view.context = view
            .context
            .publication(None)
            .observe(view.mount_registry.clone());
        view
    }

    /// A non-mount namespace replaces only a task-local handle after validation.
    /// There is no multi-resource rollback state to copy on a serial executor.
    pub fn setns_task(&mut self, fd: u32, kind: u64) -> TaskNamespaceOwnerAttempt {
        let namespace = (|| {
            self.descriptor(fd)?
                .open
                .borrow()
                .namespace
                .clone()
                .ok_or(Errno(22))
        })();
        match namespace {
            Ok(namespace @ NamespaceHandle::Mount(_)) => self
                .task_namespaces()
                .setns_target(Ok(namespace), kind)
                .run_owner(self),
            Ok(namespace) => {
                TaskNamespaceOwnerAttempt::Complete(self.set_namespace(namespace, kind).map(|()| 0))
            }
            Err(error) => TaskNamespaceOwnerAttempt::Complete(Err(error)),
        }
    }
    pub fn close_range_task(
        &mut self,
        first: u32,
        last: u32,
        flags: u32,
    ) -> TaskNamespaceOwnerAttempt {
        if flags & 2 == 0 || !self.shared_files().task_shared() {
            TaskNamespaceOwnerAttempt::Complete(self.close_range(first, last, flags).map(|()| 0))
        } else {
            self.task_namespaces()
                .close_range(first, last, flags)
                .run_owner(self)
        }
    }
    pub fn task_namespaces(&mut self) -> TaskNamespaces {
        self.sync_task_namespaces();
        let view = self.path_queries();
        view.view.borrow_mut().fds = DescriptorTable::observe(self.shared_files());
        TaskNamespaces {
            refresh: false,
            view,
            files: self.file_table_owner(),
            context: self.context_owner(),
            publication: self
                .task_namespace_publication
                .get_or_init(Arc::default)
                .clone(),
        }
    }
    /// Collect the original task's current bindings after source execution.
    /// Namespace mutations already happened; this never replays their effects.
    pub fn adopt_task_namespaces(&mut self, _state: TaskNamespaces) {
        self.sync_task_namespaces();
    }
    /// Import current bindings before handling this stopped/parked task on its
    /// original owner. Peers need not stop and no namespace operation is replayed.
    pub fn sync_task_namespaces(&mut self) -> bool {
        let Some(bindings) = self.task_namespace_publication.get().and_then(|p| p.take()) else {
            return false;
        };
        bindings.install(self);
        true
    }
}
impl TaskNamespaces {
    /// Only owned credential data is exposed; the private VFS/RC island cannot
    /// escape through this callback. The caller publishes after a real commit.
    pub fn with_credentials<T>(
        &mut self,
        call: impl FnOnce(&mut Credentials, &Dumpable) -> T,
    ) -> T {
        self.refresh = false;
        let mut view = self.view.view.borrow_mut();
        let dumpable = view.dumpable.clone();
        call(&mut view.credentials, &dumpable)
    }
    pub fn publish_credentials(&mut self) -> Credentials {
        let view = self.view.view.borrow();
        self.publication.publish(Bindings::capture(
            &view,
            self.files.clone(),
            self.context.clone(),
        ));
        self.refresh = true;
        view.credentials.clone()
    }
    pub fn changed(&self) -> bool {
        self.refresh
    }
    pub fn resources(&self) -> TaskNamespaceResources {
        let view = self.view.view.borrow();
        let mut epoch = FileEpoch::default();
        TaskNamespaceResources {
            credentials: view.credentials.clone(),
            kernel_log: view.kernel_log_capability(),
            files: view.shared_files(),
            descriptors: view.direct_descriptors(),
            direct_files: epoch.capture(&view, true),
            network: view.direct_network(),
            paths: view.path_queries(),
            factory: view.descriptor_factory(),
            uring_files: epoch.capture_uring(&view, true),
            flags: view.fd_flags_snapshot(),
            umask: view.umask_capability(),
            uts: view.uts_capability(),
            images: view.image_fds(),
        }
    }
    pub fn paths(&self) -> PathQueries {
        self.view.retain_context()
    }
    pub fn files_owner(&self) -> FileTableOwner {
        self.files.clone()
    }
    pub fn context_owner(&self) -> Option<FsOwner> {
        self.context.clone()
    }
    pub fn proc_resources(&self) -> ProcResources {
        self.view.view.borrow().proc_resources()
    }
    pub fn unshare(self, flags: u64, pid_allowed: bool) -> TaskNamespaceWork {
        let mut admin = None;
        let change = (|| {
            if flags & !ALLOWED != 0 || flags & CLONE_NEWPID != 0 && !pid_allowed {
                return Err(Errno(22));
            }
            if flags & !(FILES | FS) != 0
                && !self
                    .view
                    .view
                    .borrow()
                    .credentials
                    .has_cap(capabilities::SYS_ADMIN)
            {
                return Err(Errno(1));
            }
            if flags & CLONE_NEWNS != 0 {
                admin = Some(self.view.view.borrow().mount_admin()?);
            }
            Ok(Change::Unshare(flags))
        })();
        TaskNamespaceWork {
            state: self,
            change,
            admin,
        }
    }
    pub fn close_range(self, first: u32, last: u32, flags: u32) -> TaskNamespaceWork {
        let change = if first > last || flags & !6 != 0 {
            Err(Errno(22))
        } else {
            Ok(Change::CloseRange(first, last, flags))
        };
        TaskNamespaceWork {
            state: self,
            change,
            admin: None,
        }
    }
    pub fn setns(self, fd: u32, kind: u64) -> TaskNamespaceWork {
        let namespace = (|| {
            self.view
                .view
                .borrow()
                .descriptor(fd)?
                .open
                .borrow()
                .namespace
                .clone()
                .ok_or(Errno(22))
        })();
        self.setns_target(namespace, kind)
    }
    fn setns_target(self, namespace: Result<NamespaceHandle>, kind: u64) -> TaskNamespaceWork {
        let mut admin = None;
        let change = (|| {
            let view = self.view.view.borrow();
            let namespace = namespace?;
            view.check_namespace(&namespace, kind)?;
            if let NamespaceHandle::Mount(ns) = &namespace {
                let original = ns.original().ok_or(Errno(2))?;
                admin = Some(original.0.borrow().admin.clone());
            }
            Ok(Change::Setns(namespace, kind))
        })();
        TaskNamespaceWork {
            state: self,
            change,
            admin,
        }
    }
    fn apply(&mut self, change: Change) -> Result<u64> {
        let original = self.view.view.borrow();
        let (files, context) = match change.prepare(&original) {
            Ok(detach) => detach,
            Err(result) => return result,
        };
        drop(original);
        let mut view = self.view.retain_context().view.into_inner();
        view.fds = DescriptorTable::observe(self.view.view.borrow().shared_files());
        change.apply(&mut view, files, context)?;
        if files {
            let owner = view.file_table_owner();
            view.fds.disown();
            self.files.detach();
            self.files = owner;
        }
        if context {
            let owner = view.context_owner();
            view.context.disown();
            if let Some(old) = &self.context {
                old.retire();
            }
            self.context = owner;
        }
        self.view = PathQueries {
            view: RefCell::new(view),
        };
        self.refresh = true;
        self.publication.publish(Bindings::capture(
            &self.view.view.borrow(),
            self.files.clone(),
            self.context.clone(),
        ));
        Ok(0)
    }
}
impl Change {
    /// A no-op can use the original objects without constructing a candidate.
    fn prepare(&self, original: &Vfs) -> std::result::Result<(bool, bool), Result<u64>> {
        let (files, context) = match self {
            Change::Unshare(flags) => (
                flags & FILES != 0 && original.shared_files().task_shared(),
                flags & CLONE_NEWNS != 0 || flags & FS != 0 && original.context_shared(),
            ),
            Change::CloseRange(_, _, flags) => (
                flags & 2 != 0 && original.shared_files().task_shared(),
                false,
            ),
            Change::Setns(NamespaceHandle::Mount(_), _) => (false, true),
            Change::Setns(..) => (false, false),
        };
        if let Change::CloseRange(first, last, flags) = *self {
            if !files {
                return Err(original
                    .shared_files()
                    .close_range(first, last, flags, original.lock_owner)
                    .map(|()| 0));
            }
        }
        if matches!(*self, Change::Unshare(flags) if flags & !(FILES | FS) == 0)
            && !files
            && !context
        {
            return Err(Ok(0));
        }
        Ok((files, context))
    }
    fn apply(self, view: &mut Vfs, files: bool, context: bool) -> Result<()> {
        if files {
            let (membership, owner) = view.shared_files().fork();
            view.query.as_mut().unwrap().files = membership.clone();
            view.fds = DescriptorTable::adopt(membership, owner);
        }
        if context {
            view.unshare_context();
        }
        match self {
            Change::Unshare(flags) => {
                if flags & CLONE_NEWPID != 0 {
                    view.unshare_pid()?;
                }
                if flags & CLONE_NEWUTS != 0 {
                    view.unshare_uts()?;
                }
                if flags & CLONE_NEWNS != 0 {
                    if !view.credentials.has_cap(capabilities::SYS_ADMIN) {
                        return Err(Errno(1));
                    }
                    view.unshare_mounts_locked()?;
                }
                if flags & CLONE_NEWNET != 0 {
                    view.unshare_net()?;
                }
                if flags & CLONE_NEWIPC != 0 {
                    view.unshare_ipc()?;
                }
                if flags & CLONE_NEWCGROUP != 0 {
                    view.unshare_cgroup()?;
                }
            }
            Change::CloseRange(first, last, flags) => view.close_range(first, last, flags)?,
            Change::Setns(namespace, kind) => view.set_namespace(namespace, kind)?,
        }
        Ok(())
    }
}
impl TaskNamespaceWork {
    /// Cancel this uncommitted operation without losing earlier successful
    /// namespace changes belonging to the still-live task.
    pub fn cancel(self) -> TaskNamespaces {
        self.state
    }
    pub fn ready(&self) -> bool {
        self.admin.as_ref().is_none_or(|admin| admin.ready())
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        self.admin.as_ref().map(|admin| admin.subscribe(signal))
    }
    /// The original stopped/serial task already owns its rollback state. Consume
    /// the one private candidate directly instead of copying it a second time or
    /// publishing it back through the source-to-owner mailbox.
    pub fn run_owner(self, target: &mut Vfs) -> TaskNamespaceOwnerAttempt {
        let admin = self.admin.clone();
        let _lease = if let Some(admin) = &admin {
            let Some(lease) = admin.try_enter() else {
                return TaskNamespaceOwnerAttempt::Waiting(Box::new(self));
            };
            Some(lease)
        } else {
            None
        };
        let result = (|| {
            let change = self.change?;
            let state = self.state;
            let (files, context) = match change.prepare(&state.view.view.borrow()) {
                Ok(detach) => detach,
                Err(result) => return result,
            };
            let mut view = state.view.view.into_inner();
            change.apply(&mut view, files, context)?;
            let file_owner = if files {
                let owner = view.file_table_owner();
                view.fds.disown();
                owner
            } else {
                state.files
            };
            let context_owner = if context {
                let owner = view.context_owner();
                view.context.disown();
                owner
            } else {
                state.context
            };
            Bindings::capture(&view, file_owner, context_owner).install(target);
            Ok(0)
        })();
        TaskNamespaceOwnerAttempt::Complete(result)
    }
    pub fn run(mut self) -> TaskNamespaceAttempt {
        self.state.refresh = false;
        let admin = self.admin.clone();
        let _lease = if let Some(admin) = &admin {
            let Some(lease) = admin.try_enter() else {
                return TaskNamespaceAttempt::Waiting(self);
            };
            Some(lease)
        } else {
            None
        };
        let result = self.change.and_then(|change| self.state.apply(change));
        TaskNamespaceAttempt::Complete(self.state, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn complete(work: TaskNamespaceWork) -> (TaskNamespaces, Result<u64>) {
        match work.run() {
            TaskNamespaceAttempt::Complete(state, result) => (state, result),
            TaskNamespaceAttempt::Waiting(_) => panic!("uncontended namespace"),
        }
    }
    fn namespace_fd(v: &mut Vfs, fd: u32, ns: NamespaceHandle) {
        let open = v.namespace_description(ns, None);
        v.fds.insert(
            fd,
            Descriptor {
                open,
                cloexec: true.into(),
            },
        );
    }
    #[test]
    fn serial_candidate_commits_once_and_rolls_back_failed_detachment() {
        let mut owner = Vfs::default();
        let fd = owner.eventfd(3, 0).unwrap();
        let peer = owner.clone_with_resources(true, true);
        let TaskNamespaceOwnerAttempt::Complete(result) = owner
            .task_namespaces()
            .unshare(FILES | FS | CLONE_NEWUTS | CLONE_NEWPID, true)
            .run_owner(&mut owner)
        else {
            panic!("uncontended owner");
        };
        assert_eq!(result, Ok(0));
        assert!(!owner.sync_task_namespaces());
        assert!(!owner.shares_context_with(&peer));
        assert!(!owner.shares_descriptors_with(&peer));
        assert_ne!(owner.uts.id(), peer.uts.id());
        assert_eq!(owner.read(fd, 8).unwrap(), 3u64.to_le_bytes());
        let second_peer = owner.clone_with_resources(true, true);
        let TaskNamespaceOwnerAttempt::Complete(result) = owner
            .task_namespaces()
            .unshare(FILES | FS | CLONE_NEWUTS | CLONE_NEWPID, true)
            .run_owner(&mut owner)
        else {
            panic!("uncontended owner");
        };
        assert_eq!(result, Err(Errno(22)));
        assert!(owner.shares_context_with(&second_peer));
        assert!(owner.shares_descriptors_with(&second_peer));
        assert_eq!(owner.uts.id(), second_peer.uts.id());
        assert!(owner.flags(fd).is_ok());
    }

    #[test]
    fn serial_busy_candidate_can_resume_on_a_source_worker() {
        let mut owner = Vfs::default();
        let peer = owner.clone_with_resources(true, true);
        let original = owner.mounts.as_ref().unwrap().id();
        let admin = owner.mount_admin().unwrap();
        let lease = admin.enter();
        let TaskNamespaceOwnerAttempt::Waiting(work) = owner
            .task_namespaces()
            .unshare(FILES | CLONE_NEWNS, true)
            .run_owner(&mut owner)
        else {
            panic!("busy original namespace");
        };
        assert!(owner.shares_descriptors_with(&peer));
        drop(lease);
        let (state, result) = std::thread::spawn(move || complete(*work)).join().unwrap();
        assert_eq!(result, Ok(0));
        owner.adopt_task_namespaces(state);
        assert!(!owner.shares_descriptors_with(&peer));
        assert!(!owner.shares_context_with(&peer));
        assert_ne!(owner.mounts.as_ref().unwrap().id(), original);
    }
    #[test]
    fn complete_unshare_moves_original_domains_and_collects_without_replay() {
        fn send<T: Send>() {}
        send::<TaskNamespaces>();
        send::<TaskNamespaceWork>();
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/child", 0o755).unwrap();
        let epoll = owner.epoll_create(0).unwrap();
        let peer = owner.clone_with_resources(true, true);
        let process = Arc::new(ProcessView::default());
        process.publish(
            &ProcessInfo {
                pid: 1,
                arguments: vec![b"original-image".to_vec()],
                ..Default::default()
            },
            owner.proc_resources(),
        );
        let publication = process.clone();
        let state = owner.task_namespaces();
        let (state, fresh) = std::thread::spawn(move || {
            let (state, result) = complete(state.unshare(ALLOWED, true));
            assert_eq!(result, Ok(0));
            let fresh = {
                let mut v = state.view.view.borrow_mut();
                v.set_uts_name(false, b"private").unwrap();
                v.chdir(b"/child").unwrap();
                v.eventfd(7, 0).unwrap()
            };
            publication.replace_resources(state.proc_resources());
            (state, fresh)
        })
        .join()
        .unwrap();
        assert!(!peer.context_shared());
        assert_eq!(peer.cwd().unwrap(), b"/");
        assert_eq!(peer.uts_name(false), b"trames");
        assert_eq!(peer.flags(fresh), Err(Errno(9)));
        let observed = process.observe(ProcRefresh::Full).unwrap();
        assert_eq!(observed.cwd, b"/child");
        assert!(observed.fds.iter().any(|d| d.fd == fresh));
        assert_eq!(observed.arguments, vec![b"original-image".to_vec()]);
        assert_eq!(
            linux_namespace::snapshot_label(&observed.namespaces, b"uts"),
            Some(state.view.view.borrow().uts.label())
        );
        owner.adopt_task_namespaces(state);
        assert_eq!(owner.uts_name(false), b"private");
        assert_eq!(owner.cwd().unwrap(), b"/child");
        assert_eq!(owner.read(fresh, 8).unwrap(), 7u64.to_le_bytes());
        assert!(owner.flags(epoll).is_ok());
        assert!(!owner.shares_descriptors_with(&peer));
        assert!(!owner.shares_context_with(&peer));
        assert_ne!(
            owner.mounts.as_ref().unwrap().id(),
            peer.mounts.as_ref().unwrap().id()
        );
        assert!(!Arc::ptr_eq(&owner.root_network, &peer.root_network));
        assert!(!Arc::ptr_eq(&owner.ipc_namespace, &peer.ipc_namespace));
        assert!(!Arc::ptr_eq(
            &owner.cgroup_namespace,
            &peer.cgroup_namespace
        ));
        assert_ne!(owner.pid_children.id(), peer.pid_children.id());
        assert_eq!(owner.pid_ns.id(), peer.pid_ns.id());
    }
    #[test]
    fn publication_survives_snapshot_drop_and_repeated_owner_import() {
        let mut owner = Vfs::default();
        let peer = owner.clone_with_resources(true, true);
        let (state, result) = complete(owner.task_namespaces().unshare(FILES | FS, true));
        assert_eq!(result, Ok(0));
        let fd = state.view.view.borrow_mut().eventfd(13, 0).unwrap();
        drop(state);
        // Capturing another dispatch imports the latest resources itself.
        let state = owner.task_namespaces();
        assert_eq!(owner.flags(fd), Ok(2));
        assert_eq!(peer.flags(fd), Err(Errno(9)));
        let (state, result) = complete(state.unshare(CLONE_NEWUTS, true));
        assert_eq!(result, Ok(0));
        assert!(owner.sync_task_namespaces());
        assert!(!owner.sync_task_namespaces());
        // A namespace-only publication must not retire the unchanged Files/fs.
        assert_eq!(owner.read(fd, 8).unwrap(), 13u64.to_le_bytes());
        let shared = owner.clone_with_resources(true, true);
        assert!(shared.context_shared());
        drop(state);
        assert!(shared.context_shared());
    }
    #[test]
    fn latest_publication_retires_superseded_membership_without_collection() {
        let mut owner = Vfs::default();
        let peer = owner.clone_with_resources(true, true);
        let (state, result) = complete(owner.task_namespaces().unshare(FILES | FS, true));
        assert_eq!(result, Ok(0));
        drop(peer);
        let peer = state.view.view.borrow().clone_with_resources(true, true);
        let fd = state.view.view.borrow_mut().eventfd(17, 0).unwrap();
        let old_files = state.view.view.borrow().shared_files();
        let (state, result) = complete(state.unshare(FILES | FS | CLONE_NEWUTS, true));
        assert_eq!(result, Ok(0));
        drop(peer);
        assert!(old_files.lookup(fd).unwrap().is_err());
        let files = state.view.view.borrow().shared_files();
        drop(state);
        assert!(files.lookup(fd).unwrap().is_ok());
        owner.sync_task_namespaces();
        assert!(files.lookup(fd).unwrap().is_ok());
        drop(owner);
        assert!(files.lookup(fd).unwrap().is_err());
    }
    #[test]
    fn native_notifications_keep_accepted_events_and_retarget_only_new_lookups() {
        let mut owner = Vfs::default();
        let fd = owner.eventfd(0, 0).unwrap();
        let mut peer = owner.clone_with_resources(true, true);
        let factory = owner.native_events();
        let accepted = factory.event(fd).unwrap();
        let (state, result) = complete(owner.task_namespaces().unshare(FILES, true));
        assert_eq!(result, Ok(0));
        let resources = state.resources();
        let current = factory.with_files(resources.files.clone());
        resources.files.close_range(fd, fd, 0, 1).unwrap();
        assert_eq!(resources.factory.eventfd(0, 0).unwrap(), fd);
        // Already-issued native producer keeps its original event; a fresh
        // lookup of the reused number targets the private table's new event.
        accepted.notify();
        current.event(fd).unwrap().notify();
        assert_eq!(peer.read(fd, 8).unwrap(), 1u64.to_le_bytes());
        owner.adopt_task_namespaces(state);
        assert_eq!(owner.read(fd, 8).unwrap(), 1u64.to_le_bytes());
    }
    #[test]
    fn failed_transaction_preserves_files_fs_names_and_membership() {
        let mut owner = Vfs::default();
        owner.unshare_pid().unwrap();
        let peer = owner.clone_with_resources(true, true);
        let state = owner.task_namespaces();
        let (state, result) = std::thread::spawn(move || {
            complete(state.unshare(FILES | FS | CLONE_NEWPID | CLONE_NEWUTS, true))
        })
        .join()
        .unwrap();
        assert_eq!(result, Err(Errno(22)));
        assert!(owner.shares_context_with(&peer));
        assert!(owner.context_shared());
        // Failed preparation leaves every original membership intact.
        assert_eq!(
            state.view.view.borrow().uts_name(false),
            peer.uts_name(false)
        );
        assert!(
            state.view.view.borrow().shared_files().capture_identity().0
                == peer.shared_files().capture_identity().0
        );
        drop(state);
    }
    #[test]
    fn accepted_setns_retains_target_across_wait_close_and_fd_reuse() {
        let mut owner = Vfs::default();
        let original = owner.mounts.clone().unwrap();
        namespace_fd(&mut owner, 40, NamespaceHandle::Mount(original.clone()));
        owner.unshare_mounts().unwrap();
        let state = owner.task_namespaces();
        let admin = original.0.borrow().admin.clone();
        let lease = admin.enter();
        let TaskNamespaceAttempt::Waiting(work) = state.setns(40, CLONE_NEWNS).run() else {
            panic!("busy original target must park");
        };
        assert!(!work.ready());
        owner.close(40).unwrap();
        let uts = owner.uts.clone();
        namespace_fd(&mut owner, 40, NamespaceHandle::Uts(uts));
        drop(lease);
        let (state, result) = std::thread::spawn(move || complete(work)).join().unwrap();
        assert_eq!(result, Ok(0));
        owner.adopt_task_namespaces(state);
        assert_eq!(owner.mounts.as_ref().unwrap().id(), original.id());
        assert_eq!(owner.namespace_type(40), Ok(Some(CLONE_NEWUTS)));
    }
    #[test]
    fn shared_fs_rejects_mount_setns_before_detaching_any_context() {
        let mut owner = Vfs::default();
        let mount = owner.mounts.clone().unwrap();
        namespace_fd(&mut owner, 40, NamespaceHandle::Mount(mount));
        let peer = owner.clone_with_resources(false, true);
        let (state, result) = complete(owner.task_namespaces().setns(40, CLONE_NEWNS));
        assert_eq!(result, Err(Errno(22)));
        owner.adopt_task_namespaces(state);
        assert!(owner.shares_context_with(&peer));
        assert!(owner.context_shared());
    }
    #[test]
    fn cancelling_a_later_wait_keeps_previous_committed_membership() {
        let mut owner = Vfs::default();
        let peer = owner.clone_with_resources(true, true);
        let (state, result) = complete(
            owner
                .task_namespaces()
                .unshare(FILES | FS | CLONE_NEWUTS, true),
        );
        assert_eq!(result, Ok(0));
        let admin = state.view.view.borrow().mount_admin().unwrap();
        let lease = admin.enter();
        let TaskNamespaceAttempt::Waiting(work) = state.unshare(CLONE_NEWNS, true).run() else {
            panic!("busy namespace");
        };
        let state = work.cancel();
        drop(lease);
        let fd = state.view.view.borrow_mut().eventfd(11, 0).unwrap();
        assert_eq!(peer.flags(fd), Err(Errno(9)));
        owner.adopt_task_namespaces(state);
        assert_eq!(owner.read(fd, 8).unwrap(), 11u64.to_le_bytes());
        assert!(!owner.shares_descriptors_with(&peer));
        assert!(!owner.shares_context_with(&peer));
        assert_ne!(owner.uts.id(), peer.uts.id());
        assert_eq!(
            owner.mounts.as_ref().unwrap().id(),
            peer.mounts.as_ref().unwrap().id()
        );
    }
}
