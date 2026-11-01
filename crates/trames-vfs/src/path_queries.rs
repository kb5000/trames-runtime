// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only pathname authority over the original filesystem and inode objects.
//! The resolver is the owner VFS's resolver, in a sealed private control view.
use super::*;

#[derive(Clone)]
pub(super) struct Authority {
    files: SharedFiles,
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
        return false;
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
/// No &Vfs, Rc or mutable control handle can escape this type's query-only API.
pub struct PathQueries {
    view: Vfs,
}
// SAFETY: `Vfs::path_queries` constructs every Rc/RefCell/Cell reachable here
// afresh, including mounts, fs context, pseudo state, dummy FD table and namespaces.
// Source resources cross only as their existing Send+Sync Arc capabilities.
// Query-local clones never escape a method. Send moves the entire private island
// exclusively between workers; PathQueries is deliberately NOT Sync or Clone.
// All methods return owned bytes/results. They cannot publish owner controls or
// mutate the dummy FD table into the real shared membership. Adding an API that
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
        view.pseudo.borrow_mut().enabled = self.pseudo.borrow().enabled;
        view.query = Some(Authority {
            files: self.shared_files(),
            deferred: Rc::new(Cell::new(false)),
            _mounts: mounts.into_values().collect(),
        });
        PathQueries { view }
    }
}
impl PathQueries {
    fn query<T>(&self, operation: impl FnOnce(&Vfs) -> Result<T>) -> Option<Result<T>> {
        let deferred = &self.view.query.as_ref().unwrap().deferred;
        deferred.set(false);
        let result = operation(&self.view);
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
