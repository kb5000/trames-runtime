// SPDX-License-Identifier: GPL-3.0-or-later
//! Pathname authority over the original filesystem and inode objects.
//! The resolver is the owner VFS's resolver, in a sealed private control view.
//! File, directory and admitted devpts opens publish real OFDs into live Files.
use super::*;

#[derive(Clone)]
pub(super) struct Authority {
    pub(super) files: SharedFiles,
    pub(super) devices: Arc<cgroup::DeviceAccess>,
    deferred: Rc<Cell<bool>>,
    // Keep the private weak mount registry alive, including detached mounts.
    _mounts: Vec<Rc<Mount>>,
}
impl Authority {
    pub(super) fn defer<T>(&self) -> Result<T> {
        self.deferred.set(true);
        Err(Errno(95)) // internal only; PathQueries returns None, not this errno
    }
    pub(super) fn descriptor(&self, fd: u32) -> Result<Descriptor> {
        let Some(file) = self.files.query_lookup(fd) else {
            return self.defer();
        };
        let file = file?;
        if file.open.node.as_ref().is_some_and(|n| n.borrow().volatile) {
            return self.defer();
        }
        Ok(Descriptor {
            open: OpenHandle::Shared(file.open),
            cloexec: false.into(),
        })
    }
}
pub(super) fn ordinary_mount(mount: &Mount) -> bool {
    if mount.devpts.is_some() {
        return true;
    }
    matches!(
        mount.kind,
        mounts::Kind::Root | mounts::Kind::Tmpfs | mounts::Kind::Overlay
    ) || cfg!(all(feature = "hostfs", unix)) && host_mount(mount)
}
#[cfg(all(feature = "hostfs", unix))]
fn host_mount(mount: &Mount) -> bool {
    mount.kind == mounts::Kind::Host
}
#[cfg(not(all(feature = "hostfs", unix)))]
fn host_mount(_: &Mount) -> bool {
    false
}

/// One exclusively owned control island, movable with a retained execution job.
/// No &Vfs, Rc or mutable control handle can escape this type's sealed API.
pub struct PathQueries {
    view: RefCell<Vfs>,
}
// SAFETY: `Vfs::path_queries` constructs every Rc/RefCell/Cell reachable here
// afresh, including mounts, fs context, pseudo state, dummy FD table and namespaces.
// Source resources cross only as their existing Send+Sync Arc capabilities.
// Query-local clones never escape a method. Send moves the entire private island
// exclusively between workers; PathQueries is deliberately NOT Sync or Clone.
// Methods return only owned bytes/results and numeric FDs. Inotify registration
// mutates only the original Arc-backed instance/inode marks, never query-local Rc.
// Ordinary opens publish
// Arc-backed descriptions; no Rc-backed owner control enters shared membership.
// The dummy FD table remains private and empty. Adding an API that
// leaks/retains a local Rc outside this island requires revisiting this proof.
unsafe impl Send for PathQueries {}

impl Vfs {
    pub fn path_queries(&self) -> PathQueries {
        let mut view = Vfs::empty(self.fs.clone());
        let mut mounts = BTreeMap::new();
        let mut project =
            |mount: &Rc<Mount>| Mount::query_projection(mount.shared.clone(), &mut mounts);
        let paths = self.context.paths.borrow();
        {
            let mut own = view.context.paths.borrow_mut();
            own.cwd_node = paths.cwd_node.clone();
            own.root_node = paths.root_node.clone();
            own.cwd_mount = paths.cwd_mount.as_ref().map(&mut project);
            own.root_mount = paths.root_mount.as_ref().map(&mut project);
            #[cfg(all(feature = "hostfs", unix))]
            {
                own.host_cwd = paths.host_cwd.clone();
            }
        }
        if let Some(namespace) = &self.mounts {
            let table = namespace.0.borrow();
            view.mounts = Some(MountNamespace(Rc::new(RefCell::new(mounts::Table {
                events: table.events.clone(),
                id: table.id,
                root: project(&table.root),
                mounts: table.mounts.iter().map(&mut project).collect(),
            }))));
        }
        let registry: Vec<_> = self
            .mount_registry
            .borrow()
            .iter()
            .filter_map(Weak::upgrade)
            .map(|m| project(&m))
            .collect();
        *view.mount_registry.borrow_mut() = registry.iter().map(Rc::downgrade).collect();
        view.credentials = self.credentials.clone();
        view.context.share_mask(&self.context);
        view.record_locks = self.record_locks.clone();
        view.next_open = self.next_open.clone();
        view.ptys = self.ptys.clone();
        view.pseudo.borrow_mut().enabled = self.pseudo.borrow().enabled;
        view.query = Some(Authority {
            files: self.shared_files(),
            devices: self.device_access(),
            deferred: Rc::new(Cell::new(false)),
            _mounts: mounts.into_values().collect(),
        });
        PathQueries {
            view: RefCell::new(view),
        }
    }
}
impl PathQueries {
    pub fn getdents(
        &self,
        fd: u32,
        count: usize,
        preflight: impl FnOnce() -> Result<()>,
    ) -> Option<Result<Vec<u8>>> {
        self.query(|view| {
            // Accept once, before output validation. The deciding operation
            // retains this original OFD even if another worker reuses its FD.
            let descriptor = view.descriptor(fd)?;
            preflight()?;
            view.getdents_description(&descriptor, count)
        })
    }
    pub fn directory_seek(&self, fd: u32, offset: i64, whence: u32) -> Option<Result<u64>> {
        let mut eligible = false;
        let result = self.query(|view| {
            let descriptor = view.descriptor(fd)?;
            if !descriptor
                .open
                .borrow()
                .node
                .as_ref()
                .is_some_and(|node| matches!(node.borrow().content, Content::Directory))
            {
                return Ok(0); // Ineligible, with no resource effects.
            }
            eligible = true;
            Vfs::seek_description(&descriptor, offset, whence)
        })?;
        (eligible || result.is_err()).then_some(result)
    }
    pub fn open_at_resolve(
        &self,
        dirfd: i32,
        path: &[u8],
        flags: u32,
        mode: u32,
        policy: u64,
        files: &DirectFiles,
    ) -> Option<Result<u32>> {
        // Truncation can change mapped backing lifetimes and remains joined.
        if flags & O_PATH == 0 && flags & 0x200 != 0 {
            return None;
        }
        let mut view = self.view.borrow_mut();
        let deferred = view.query.as_ref().unwrap().deferred.clone();
        deferred.set(false);
        let result = view.open_at_resolve_published(dirfd, path, flags, mode, policy, Some(files));
        (!deferred.replace(false)).then_some(result)
    }
    fn query<T>(&self, operation: impl FnOnce(&Vfs) -> Result<T>) -> Option<Result<T>> {
        let view = self.view.borrow();
        let deferred = &view.query.as_ref().unwrap().deferred;
        deferred.set(false);
        let result = operation(&view);
        (!deferred.replace(false)).then_some(result)
    }
    pub fn stat_at_with_mount(
        &self,
        dirfd: i32,
        path: &[u8],
        nofollow: bool,
    ) -> Option<Result<([u8; 128], u64)>> {
        self.query(|v| v.stat_at_with_mount(dirfd, path, nofollow))
    }
    pub fn stat_fd_with_mount(&self, fd: u32) -> Option<Result<([u8; 128], u64)>> {
        self.query(|v| v.stat_fd_with_mount(fd))
    }
    pub fn stat_at(&self, dirfd: i32, path: &[u8], nofollow: bool) -> Option<Result<[u8; 128]>> {
        self.query(|v| v.stat_at_flags(dirfd, path, nofollow))
    }
    pub fn stat_fd(&self, fd: u32) -> Option<Result<[u8; 128]>> {
        self.query(|v| v.stat_fd(fd))
    }
    pub fn mount_id_at(&self, dirfd: i32, path: &[u8], nofollow: bool) -> Option<Result<u64>> {
        self.query(|v| v.mount_id_at(dirfd, path, nofollow))
    }
    pub fn mount_id_fd(&self, fd: u32) -> Option<Result<u64>> {
        self.query(|v| v.mount_id_fd(fd))
    }
    pub fn inotify_add(&self, fd: u32, path: &[u8], mask: u32) -> Option<Result<i32>> {
        self.query(|v| v.inotify_add(fd, path, mask))
    }
    pub fn readlink_at(&self, dirfd: i32, path: &[u8]) -> Option<Result<Vec<u8>>> {
        self.query(|v| v.readlink_at(dirfd, path))
    }
    pub fn access_at(
        &self,
        dirfd: i32,
        path: &[u8],
        mode: u32,
        effective: bool,
        nofollow: bool,
    ) -> Option<Result<()>> {
        self.query(|v| v.access_at(dirfd, path, mode, effective, nofollow))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_inotify_registration_uses_original_instances_and_inode_marks() {
        let mut owner = Vfs::default();
        owner.import_file(b"/file", b"old".to_vec()).unwrap();
        owner.set_runtime_info(1, RuntimeInfo::default());
        let notify = owner.inotify_init(O_NONBLOCK).unwrap();
        let query = owner.path_queries();
        let wd = std::thread::spawn(move || {
            assert_eq!(
                query.inotify_add(notify, b"/missing", 2),
                Some(Err(Errno(2)))
            );
            query.inotify_add(notify, b"/file", 2).unwrap().unwrap()
        })
        .join()
        .unwrap();
        let fd = owner.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        owner.write(fd, b"new").unwrap();
        let events = owner.read(notify, 4096).unwrap();
        assert_eq!(i32::from_le_bytes(events[..4].try_into().unwrap()), wd);
        assert_eq!(u32::from_le_bytes(events[4..8].try_into().unwrap()) & 2, 2);
        assert_eq!(owner.inotify_remove(notify, wd), Ok(()));
        let query = owner.path_queries();
        assert_eq!(query.inotify_add(notify, b"/proc/self/status", 2), None);
        assert_eq!(query.inotify_add(999, b"/file", 2), Some(Err(Errno(9))));
    }
    #[test]
    fn worker_open_publishes_live_membership_and_io_without_recapture() {
        let mut owner = Vfs::default();
        owner.import_file(b"/file", b"old".to_vec()).unwrap();
        let mut epoch = FileEpoch::default();
        let writer = epoch.capture(&owner, true);
        let reader = epoch.capture(&owner, false);
        let query = owner.path_queries();
        owner.set_umask(0o077);
        let fd = query
            .open_at_resolve(
                AT_FDCWD,
                b"/created",
                2 | 0x40 | O_CLOEXEC,
                0o666,
                0,
                &writer,
            )
            .unwrap()
            .unwrap();
        assert_eq!(owner.flags(fd).unwrap() & 3, 2);
        assert!(owner.fds.get(&fd).unwrap().cloexec.get());
        assert_eq!(
            owner.stat_fd(fd).unwrap()[16..20],
            0o100600u32.to_le_bytes()
        );
        assert!(writer
            .get(fd)
            .unwrap()
            .write(b"hello", None, &mut Default::default())
            .is_none());
        owner.write(fd, b".....").unwrap();
        writer
            .get(fd)
            .expect("new file has direct authority")
            .write(b"hello", Some(0), &mut Default::default())
            .unwrap()
            .unwrap();
        assert_eq!(
            reader
                .get(fd)
                .unwrap()
                .read(5, Some(0), &mut Default::default())
                .unwrap()
                .unwrap(),
            b"hello"
        );
        assert!(reader
            .get(fd)
            .unwrap()
            .write(b"limit", Some(0), &mut Default::default())
            .is_none());
        let accepted = reader.get(fd).unwrap();
        owner.close(fd).unwrap();
        let replacement = query
            .open_at_resolve(AT_FDCWD, b"/file", 0, 0, 0, &writer)
            .unwrap()
            .unwrap();
        assert_eq!(replacement, fd);
        assert_eq!(
            reader
                .get(fd)
                .unwrap()
                .read(3, None, &mut Default::default())
                .unwrap()
                .unwrap(),
            b"old"
        );
        assert_eq!(
            accepted
                .read(5, Some(0), &mut Default::default())
                .unwrap()
                .unwrap(),
            b"hello"
        );
        owner.close(replacement).unwrap();
        epoch.finish();
        assert_eq!(
            owner.stat_at(AT_FDCWD, b"/created").unwrap()[48..56],
            5u64.to_le_bytes()
        );
    }
    #[test]
    fn worker_open_fallback_and_errors_do_not_leak_reservations_or_truncate() {
        let mut owner = Vfs::default();
        owner.import_file(b"/file", b"retained".to_vec()).unwrap();
        owner.set_runtime_info(1, RuntimeInfo::default());
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&owner, true);
        let query = owner.path_queries();
        assert!(query
            .open_at_resolve(AT_FDCWD, b"/file", 2 | 0x200, 0, 0, &files)
            .is_none());
        assert!(query
            .open_at_resolve(AT_FDCWD, b"/proc/self/status", 0, 0, 0, &files)
            .is_none());
        let directory = query
            .open_at_resolve(AT_FDCWD, b"/", O_DIRECTORY, 0, 0, &files)
            .unwrap()
            .unwrap();
        assert!(owner.shared_files().lookup(directory).unwrap().is_ok());
        owner.close(directory).unwrap();
        assert_eq!(
            query.open_at_resolve(AT_FDCWD, b"/missing", 0, 0, 0, &files),
            Some(Err(Errno(2)))
        );
        assert_eq!(
            owner.stat_at(AT_FDCWD, b"/file").unwrap()[48..56],
            8u64.to_le_bytes()
        );
        let fd = query
            .open_at_resolve(AT_FDCWD, b"/file", 0, 0, 0, &files)
            .unwrap()
            .unwrap();
        assert_eq!(fd, 3);
        owner.close(fd).unwrap();
        epoch.finish();
    }
    #[test]
    fn concurrent_exclusive_create_has_one_inode_and_disjoint_published_fds() {
        let mut owner = Vfs::default();
        let mut epoch = FileEpoch::default();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let query = owner.path_queries();
                let files = epoch.capture(&owner, true);
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let result = query
                        .open_at_resolve(AT_FDCWD, b"/race", 2 | 0xc0, 0o600, 0, &files)
                        .unwrap();
                    (query, files, result)
                })
            })
            .collect();
        let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.2.is_ok()).count(), 1);
        assert!(results.iter().all(|r| r.2.is_ok() || r.2 == Err(Errno(17))));
        for (_, _, result) in results {
            if let Ok(fd) = result {
                owner.close(fd).unwrap();
            }
        }
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let query = owner.path_queries();
                let files = epoch.capture(&owner, true);
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    query
                        .open_at_resolve(AT_FDCWD, b"/shared-race", 2 | 0x40, 0o600, 0, &files)
                        .unwrap()
                        .unwrap()
                })
            })
            .collect();
        let fds: std::collections::BTreeSet<_> =
            jobs.into_iter().map(|j| j.join().unwrap()).collect();
        assert_eq!(fds.len(), 8);
        for fd in fds {
            owner.close(fd).unwrap();
        }
        epoch.finish();
    }
    #[test]
    fn concurrent_creation_and_directory_queries_do_not_invert_inode_namespace_locks() {
        let owner = Vfs::default();
        let mut epoch = FileEpoch::default();
        let jobs: Vec<_> = (0..8)
            .map(|id| {
                let query = owner.path_queries();
                let files = epoch.capture(&owner, true);
                let membership = owner.shared_files();
                std::thread::spawn(move || {
                    for i in 0..40 {
                        let path = format!("/worker-{id}-{i}");
                        let fd = query
                            .open_at_resolve(AT_FDCWD, path.as_bytes(), 2 | 0x40, 0o600, 0, &files)
                            .unwrap()
                            .unwrap();
                        assert!(files.get(fd).is_some());
                        assert!(query.stat_at(AT_FDCWD, b"/", false).unwrap().is_ok());
                        membership.close(fd, 1).unwrap().unwrap();
                    }
                })
            })
            .collect();
        for job in jobs {
            job.join().unwrap();
        }
        epoch.finish();
    }
    #[test]
    fn opens_on_distinct_workers_have_distinct_ofd_lock_owners() {
        let mut owner = Vfs::default();
        owner.import_file(b"/file", b"data".to_vec()).unwrap();
        let original = owner.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&owner, true);
        let a = owner
            .path_queries()
            .open_at_resolve(AT_FDCWD, b"/file", 2, 0, 0, &files)
            .unwrap()
            .unwrap();
        let b = owner
            .path_queries()
            .open_at_resolve(AT_FDCWD, b"/file", 2, 0, 0, &files)
            .unwrap()
            .unwrap();
        let ids: std::collections::BTreeSet<_> = [original, a, b]
            .into_iter()
            .map(|fd| owner.descriptor(fd).unwrap().open.borrow().id)
            .collect();
        assert_eq!(ids.len(), 3);
        files.get(a).unwrap().flock(6).unwrap();
        assert_eq!(files.get(b).unwrap().flock(6), Err(Errno(11)));
        assert_eq!(files.get(original).unwrap().flock(6), Err(Errno(11)));
        files.get(a).unwrap().flock(8).unwrap();
        for fd in [original, a, b] {
            owner.close(fd).unwrap();
        }
        epoch.finish();
    }
    #[test]
    fn published_file_admission_does_not_survive_its_original_epoch() {
        let mut owner = Vfs::default();
        owner.import_file(b"/file", b"data".to_vec()).unwrap();
        let mut epoch = FileEpoch::default();
        let files = epoch.capture(&owner, true);
        let fd = owner
            .path_queries()
            .open_at_resolve(AT_FDCWD, b"/file", 0, 0, 0, &files)
            .unwrap()
            .unwrap();
        let accepted = files.get(fd).unwrap().shared_file().unwrap();
        owner.close(fd).unwrap();
        epoch.finish();
        let mut next = FileEpoch::default();
        let next_files = next.capture(&owner, true);
        assert!(next_files.accept(accepted).is_none());
        next.finish();
    }
    #[test]
    fn captured_resources_are_send_sync_and_private_control_moves_exclusively() {
        fn shared<T: Send + Sync>() {}
        fn movable<T: Send>() {}
        shared::<FsHandle>();
        shared::<NodeRef>();
        shared::<mounts::MountData>();
        shared::<SharedFiles>();
        movable::<PathQueries>();
        let mut owner = Vfs::default();
        owner.import_file(b"/file", b"bytes".to_vec()).unwrap();
        let query = owner.path_queries();
        let query = std::thread::spawn(move || {
            assert_eq!(
                query.stat_at(AT_FDCWD, b"/file", false).unwrap().unwrap()[48..56],
                5u64.to_le_bytes()
            );
            query
        })
        .join()
        .unwrap();
        std::thread::spawn(move || {
            assert!(query.stat_at(AT_FDCWD, b"/file", false).unwrap().is_ok());
        })
        .join()
        .unwrap();
    }
    #[test]
    fn same_resolver_covers_symlinks_permissions_errors_and_non_utf8() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/d", 0o755).unwrap();
        owner.import_file(b"/d/f\xff", b"data".to_vec()).unwrap();
        owner.symlink_at(b"d/f\xff", AT_FDCWD, b"/alias").unwrap();
        owner.symlink_at(b"/loop", AT_FDCWD, b"/loop").unwrap();
        let query = owner.path_queries();
        for path in [
            b"/alias".as_slice(),
            b"/d/f\xff",
            b"/d/../alias",
            b"/missing",
            b"/d/f\xff/",
            b"/loop",
            b"/d",
        ] {
            for nofollow in [false, true] {
                assert_eq!(
                    query.stat_at(AT_FDCWD, path, nofollow),
                    Some(owner.stat_at_flags(AT_FDCWD, path, nofollow)),
                    "{path:?}"
                );
            }
        }
        assert_eq!(
            query.readlink_at(AT_FDCWD, b"/alias"),
            Some(owner.readlink_at(AT_FDCWD, b"/alias"))
        );
        owner.chmod_at(AT_FDCWD, b"/d", 0o000).unwrap();
        owner.credentials = Credentials::user(123, 456);
        let query = owner.path_queries();
        assert_eq!(
            query.stat_at(AT_FDCWD, b"/d/f\xff", false),
            Some(Err(Errno(13)))
        );
        for mode in 0..8 {
            assert_eq!(
                query.access_at(AT_FDCWD, b"/d/f\xff", mode, false, false),
                Some(owner.access_at(AT_FDCWD, b"/d/f\xff", mode, false, false))
            );
        }
    }
    #[test]
    fn live_inodes_and_dirfd_follow_rename_unlink_and_fd_reuse() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/d", 0o755).unwrap();
        owner.import_file(b"/d/f", b"one".to_vec()).unwrap();
        let dir = owner.open_at(AT_FDCWD, b"/d", O_DIRECTORY, 0).unwrap();
        let fd = owner.open_at(AT_FDCWD, b"/d/f", 2, 0).unwrap();
        let query = owner.path_queries();
        owner
            .rename_at(AT_FDCWD, b"/d", AT_FDCWD, b"/renamed", 0)
            .unwrap();
        assert_eq!(
            query.stat_at(dir as i32, b"f", false),
            Some(owner.stat_at(dir as i32, b"f"))
        );
        owner.pwrite(fd, b"longer", 0).unwrap();
        assert_eq!(query.stat_fd(fd), Some(owner.stat_fd(fd)));
        owner.unlink_at(AT_FDCWD, b"/renamed/f", false).unwrap();
        assert_eq!(query.stat_fd(fd), Some(owner.stat_fd(fd)));
        owner.close(fd).unwrap();
        assert_eq!(query.stat_fd(fd), Some(Err(Errno(9))));
        let reused = owner
            .open_at(AT_FDCWD, b"/replacement", 0x42, 0o644)
            .unwrap();
        assert_eq!(reused, fd);
        assert_eq!(query.stat_fd(fd), Some(owner.stat_fd(fd)));
        drop(query);
        assert!(owner.stat_fd(dir).is_ok());
        assert!(owner.stat_fd(fd).is_ok());
    }
    #[test]
    fn pseudo_traversals_and_owner_fds_defer_even_through_aliases() {
        let mut owner = Vfs::default();
        owner.set_runtime_info(1, RuntimeInfo::default());
        owner
            .symlink_at(b"/proc/self/status", AT_FDCWD, b"/alias")
            .unwrap();
        let query = owner.path_queries();
        for path in [
            b"/proc/self/status".as_slice(),
            b"/alias",
            b"/sys/kernel",
            b"/dev/null",
        ] {
            assert!(query.stat_at(AT_FDCWD, path, false).is_none(), "{path:?}");
        }
        // A deferred result must not poison a later ordinary query.
        assert_eq!(
            query.stat_at(AT_FDCWD, b"/missing", false),
            Some(Err(Errno(2)))
        );
        assert_eq!(query.stat_fd(u32::MAX), Some(Err(Errno(9))));
    }
    #[test]
    fn mount_projection_preserves_crossings_parent_identity_readonly_and_chroot() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/mount", 0o755).unwrap();
        owner
            .mount(Some(b"tmpfs"), b"/mount", Some(b"tmpfs"), 0, None)
            .unwrap();
        owner.import_file(b"/mount/f", b"inside".to_vec()).unwrap();
        owner.mkdir_at(AT_FDCWD, b"/bind", 0o755).unwrap();
        owner
            .mount(Some(b"/mount"), b"/bind", None, 4096, None)
            .unwrap();
        let query = owner.path_queries();
        for path in [b"/mount/f".as_slice(), b"/bind/f", b"/mount/../mount/f"] {
            assert_eq!(
                query.stat_at(AT_FDCWD, path, false),
                Some(owner.stat_at(AT_FDCWD, path))
            );
            assert_eq!(
                query.mount_id_at(AT_FDCWD, path, false),
                Some(owner.mount_id_at(AT_FDCWD, path, false))
            );
        }
        owner
            .mount(None, b"/bind", None, 4096 | 32 | 1, None)
            .unwrap();
        let query = owner.path_queries();
        assert_eq!(
            query.access_at(AT_FDCWD, b"/bind/f", 2, true, false),
            Some(Err(Errno(30)))
        );
        owner.chroot(b"/mount").unwrap();
        owner.chdir(b"/").unwrap();
        let query = owner.path_queries();
        assert_eq!(
            query.stat_at(AT_FDCWD, b"/f", false),
            Some(owner.stat_at(AT_FDCWD, b"/f"))
        );
        assert_eq!(
            query.stat_at(AT_FDCWD, b"/../f", false),
            Some(owner.stat_at(AT_FDCWD, b"/../f"))
        );
    }
    #[test]
    fn directory_queries_do_not_move_cursors_or_keep_last_close_alive() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/d", 0o755).unwrap();
        let fd = owner.open_at(AT_FDCWD, b"/d", O_DIRECTORY, 0).unwrap();
        let weak = {
            let open = owner.descriptor(fd).unwrap();
            let open = open.open.borrow();
            Arc::downgrade(&open.shared)
        };
        let query = owner.path_queries();
        let first = owner.getdents(fd, 24).unwrap();
        assert_eq!(first[19], b'.');
        assert_eq!(query.stat_fd(fd), Some(owner.stat_fd(fd)));
        let next = owner.getdents(fd, 24).unwrap();
        assert_eq!(&next[19..21], b"..");
        owner.unlink_at(AT_FDCWD, b"/d", true).unwrap();
        owner.close(fd).unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(query.stat_fd(fd), Some(Err(Errno(9))));
    }
    #[test]
    fn namespace_mutations_and_parallel_queries_share_real_objects() {
        let mut owner = Vfs::default();
        owner.import_file(b"/a", vec![1; 16]).unwrap();
        let queries: Vec<_> = (0..4).map(|_| owner.path_queries()).collect();
        std::thread::scope(|scope| {
            let jobs: Vec<_> = queries
                .into_iter()
                .map(|query| {
                    scope.spawn(move || {
                        for _ in 0..2000 {
                            for name in [b"/a", b"/b"] {
                                if let Ok(stat) = query.stat_at(AT_FDCWD, name, false).unwrap() {
                                    assert_eq!(
                                        u64::from_le_bytes(stat[48..56].try_into().unwrap()),
                                        16
                                    );
                                }
                            }
                        }
                    })
                })
                .collect();
            for i in 0..1000 {
                let (from, to) = if i % 2 == 0 {
                    (b"/a", b"/b")
                } else {
                    (b"/b", b"/a")
                };
                owner.rename_at(AT_FDCWD, from, AT_FDCWD, to, 0).unwrap();
            }
            for job in jobs {
                job.join().unwrap();
            }
        });
    }
    #[cfg(all(feature = "hostfs", unix))]
    #[test]
    fn concurrent_host_creators_open_one_winning_inode() {
        let root =
            std::env::temp_dir().join(format!("trames-worker-open-host-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/host", 0o755).unwrap();
        owner.mount_host(b"/host", &root, false).unwrap();
        let mut epoch = FileEpoch::default();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let query = owner.path_queries();
                let files = epoch.capture(&owner, true);
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    query
                        .open_at_resolve(AT_FDCWD, b"/host/new", 2 | 0x40, 0o600, 0, &files)
                        .unwrap()
                        .unwrap()
                })
            })
            .collect();
        let fds: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
        let inodes: std::collections::BTreeSet<_> = fds
            .iter()
            .map(|&fd| owner.stat_fd(fd).unwrap()[8..16].to_vec())
            .collect();
        assert_eq!(inodes.len(), 1);
        assert_eq!(
            fds.iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            8
        );
        for fd in fds {
            owner.close(fd).unwrap();
        }
        epoch.finish();
        drop(owner);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(all(feature = "hostfs", unix))]
    #[test]
    fn host_mutations_remain_visible_without_a_recapture_or_query_cache() {
        use std::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "trames-path-query-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("f"), b"before").unwrap();
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/host", 0o755).unwrap();
        owner.mount_host(b"/host", &root, false).unwrap();
        let query = owner.path_queries();
        assert_eq!(
            query.stat_at(AT_FDCWD, b"/host/f", false),
            Some(owner.stat_at(AT_FDCWD, b"/host/f"))
        );
        std::fs::write(root.join("next"), b"after replacement").unwrap();
        std::fs::rename(root.join("next"), root.join("f")).unwrap();
        assert_eq!(
            query.stat_at(AT_FDCWD, b"/host/f", false),
            Some(owner.stat_at(AT_FDCWD, b"/host/f"))
        );
        std::os::unix::fs::symlink("f", root.join("link")).unwrap();
        assert_eq!(
            query.readlink_at(AT_FDCWD, b"/host/link"),
            Some(Ok(b"f".to_vec()))
        );
        std::fs::remove_file(root.join("f")).unwrap();
        assert_eq!(
            query.stat_at(AT_FDCWD, b"/host/f", false),
            Some(Err(Errno(2)))
        );
        drop(query);
        drop(owner);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod directory_tests;
