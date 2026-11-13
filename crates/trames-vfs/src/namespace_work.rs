// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned namespace calls over the original fs_struct, Files and filesystem.
use super::*;

pub enum NamespaceCall {
    Memfd(MemfdParameters),
    Mount {
        source: Option<Vec<u8>>,
        target: Vec<u8>,
        kind: Option<Vec<u8>>,
        flags: u64,
        data: Option<Vec<u8>>,
    },
    Umount {
        target: Vec<u8>,
        flags: u64,
    },
    PivotRoot {
        new_root: Vec<u8>,
        put_old: Vec<u8>,
    },
    Mkdir {
        fd: i32,
        path: Vec<u8>,
        mode: u32,
    },
    Mknod {
        fd: i32,
        path: Vec<u8>,
        mode: u32,
        device: u64,
    },
    Symlink {
        target: Vec<u8>,
        fd: i32,
        path: Vec<u8>,
    },
    Unlink {
        fd: i32,
        path: Vec<u8>,
        directory: bool,
    },
    Link {
        oldfd: i32,
        old: Vec<u8>,
        newfd: i32,
        new: Vec<u8>,
    },
    Rename {
        oldfd: i32,
        old: Vec<u8>,
        newfd: i32,
        new: Vec<u8>,
        flags: u32,
    },
    Chmod {
        fd: i32,
        path: Option<Vec<u8>>,
        mode: u32,
        nofollow: bool,
        empty: bool,
    },
    Chown {
        fd: i32,
        path: Option<Vec<u8>>,
        uid: u32,
        gid: u32,
        nofollow: bool,
        empty: bool,
    },
    Times {
        fd: i32,
        path: Option<Vec<u8>>,
        times: Option<[[i64; 2]; 2]>,
        flags: u32,
    },
    Xattr {
        fd: i32,
        path: Option<Vec<u8>>,
        follow: bool,
        name: Vec<u8>,
        value: Option<Vec<u8>>,
        flags: u32,
    },
    GetXattr {
        fd: i32,
        path: Option<Vec<u8>>,
        follow: bool,
        name: Option<Vec<u8>>,
    },
    Chdir(Vec<u8>),
    Fchdir(u32),
    Chroot(Vec<u8>),
    Cwd,
    Statfs {
        fd: i32,
        path: Option<Vec<u8>>,
    },
}
impl NamespaceCall {
    fn paths(&self) -> Vec<(i32, Option<&[u8]>, bool)> {
        match self {
            Self::Memfd(_) => Vec::new(),
            Self::Mount {
                source,
                target,
                flags,
                ..
            } => {
                let mut paths = vec![(AT_FDCWD, Some(target.as_slice()), true)];
                if flags & (4096 | 8192) != 0 {
                    if let Some(source) = source {
                        paths.push((AT_FDCWD, Some(source.as_slice()), true));
                    }
                }
                paths
            }
            Self::Umount { target, flags } => vec![(AT_FDCWD, Some(target), flags & 8 == 0)],
            Self::PivotRoot { new_root, put_old } => vec![
                (AT_FDCWD, Some(new_root), true),
                (AT_FDCWD, Some(put_old), true),
            ],
            Self::Mkdir { fd, path, .. }
            | Self::Mknod { fd, path, .. }
            | Self::Symlink { fd, path, .. }
            | Self::Unlink { fd, path, .. } => vec![(*fd, Some(path), false)],
            Self::Link {
                oldfd,
                old,
                newfd,
                new,
            }
            | Self::Rename {
                oldfd,
                old,
                newfd,
                new,
                ..
            } => vec![(*oldfd, Some(old), false), (*newfd, Some(new), false)],
            Self::Chmod {
                fd, path, nofollow, ..
            }
            | Self::Chown {
                fd, path, nofollow, ..
            } => vec![(*fd, path.as_deref(), !nofollow)],
            Self::Times {
                fd, path, flags, ..
            } => vec![(*fd, path.as_deref(), flags & 0x100 == 0)],
            Self::Xattr {
                fd, path, follow, ..
            }
            | Self::GetXattr {
                fd, path, follow, ..
            } => vec![(*fd, path.as_deref(), *follow)],
            Self::Chdir(path) | Self::Chroot(path) => vec![(AT_FDCWD, Some(path), true)],
            Self::Fchdir(fd) => vec![(*fd as i32, None, true)],
            Self::Statfs { fd, path } => vec![(*fd, path.as_deref(), true)],
            Self::Cwd => vec![(AT_FDCWD, Some(b"."), true)],
        }
    }
    fn topology(&self) -> bool {
        matches!(
            self,
            Self::Mount { .. } | Self::Umount { .. } | Self::PivotRoot { .. }
        )
    }
    fn execute_locked(&self, v: &mut Vfs) -> Result<FileValue> {
        match self {
            Self::Mount {
                source,
                target,
                kind,
                flags,
                data,
            } => v.mount_locked(
                source.as_deref(),
                target,
                kind.as_deref(),
                *flags,
                data.as_deref(),
            )?,
            Self::Umount { target, flags } => v.umount_locked(target, *flags)?,
            Self::PivotRoot { new_root, put_old } => v.pivot_root_locked(new_root, put_old)?,
            _ => return self.execute(v),
        }
        Ok(FileValue::Count(0))
    }
    pub fn execute(&self, v: &mut Vfs) -> Result<FileValue> {
        match self {
            Self::Memfd(parameters) => {
                return parameters.create(v).map(|fd| FileValue::Count(fd as u64))
            }
            Self::Mount {
                source,
                target,
                kind,
                flags,
                data,
            } => v.mount(
                source.as_deref(),
                target,
                kind.as_deref(),
                *flags,
                data.as_deref(),
            )?,
            Self::Umount { target, flags } => v.umount(target, *flags)?,
            Self::PivotRoot { new_root, put_old } => v.pivot_root(new_root, put_old)?,
            Self::Mkdir { fd, path, mode } => v.mkdir_at(*fd, path, *mode)?,
            Self::Mknod {
                fd,
                path,
                mode,
                device,
            } => v.mknod_at(*fd, path, *mode, *device)?,
            Self::Symlink { target, fd, path } => v.symlink_at(target, *fd, path)?,
            Self::Unlink {
                fd,
                path,
                directory,
            } => v.unlink_at(*fd, path, *directory)?,
            Self::Link {
                oldfd,
                old,
                newfd,
                new,
            } => v.link_at(*oldfd, old, *newfd, new)?,
            Self::Rename {
                oldfd,
                old,
                newfd,
                new,
                flags,
            } => v.rename_at(*oldfd, old, *newfd, new, *flags)?,
            Self::Chmod {
                fd,
                path,
                mode,
                nofollow,
                empty,
            } => match path {
                Some(path) => v.chmod_at_flags(*fd, path, *mode, *nofollow)?,
                None if *empty => v.chmod_fd_at(*fd as u32, *mode)?,
                None => v.chmod_fd(*fd as u32, *mode)?,
            },
            Self::Chown {
                fd,
                path,
                uid,
                gid,
                nofollow,
                empty,
            } => match path {
                Some(path) => v.chown_at(*fd, path, *uid, *gid, *nofollow)?,
                None if *empty => v.chown_fd_at(*fd as u32, *uid, *gid)?,
                None => v.chown_fd(*fd as u32, *uid, *gid)?,
            },
            Self::Times {
                fd,
                path,
                times,
                flags,
            } => v.set_times_flags(*fd, path.as_deref(), *times, *flags)?,
            Self::Xattr {
                fd,
                path,
                follow,
                name,
                value,
                flags,
            } => v.set_xattr(
                *fd,
                path.as_deref(),
                *follow,
                name,
                value.as_deref(),
                *flags,
            )?,
            Self::GetXattr {
                fd,
                path,
                follow,
                name,
            } => {
                return name
                    .as_ref()
                    .map_or_else(
                        || v.list_xattrs(*fd, path.as_deref(), *follow),
                        |name| v.get_xattr(*fd, path.as_deref(), *follow, name),
                    )
                    .map(FileValue::Bytes)
            }
            Self::Chdir(path) => v.chdir(path)?,
            Self::Fchdir(fd) => v.chdir_fd(*fd)?,
            Self::Chroot(path) => v.chroot(path)?,
            Self::Cwd => {
                let mut bytes = v.cwd()?;
                bytes.push(0);
                return Ok(FileValue::Bytes(bytes));
            }
            Self::Statfs { fd, path } => {
                return path
                    .as_ref()
                    .map_or_else(|| v.statfs_fd(*fd as u32), |path| v.statfs_at(path))
                    .map(|stat| FileValue::Bytes(stat.to_vec()))
            }
        }
        Ok(FileValue::Count(0))
    }
}
pub(super) struct NamespaceWork {
    call: NamespaceCall,
    host_work: bool,
    waiting: Option<Arc<mounts::admin::Admin>>,
}
pub(super) enum NamespaceRun {
    Complete(Result<FileValue>),
    Waiting,
    Owner,
}
pub enum NamespaceAttempt {
    Complete(Result<FileValue>),
    Retained(FileWork),
}
impl Vfs {
    pub fn namespace_host_work(&self) -> bool {
        let native = |fs: &FsHandle| {
            #[cfg(all(feature = "hostfs", unix))]
            if fs.host.is_some() {
                return true;
            }
            fs.has_overlay() || fs.borrow().disk.is_some()
        };
        native(&self.fs)
            || self
                .mount_resources
                .borrow()
                .iter()
                .filter_map(std::sync::Weak::upgrade)
                .any(|m| native(&m.fs))
    }
}
fn prepare_namespace(view: &mut Vfs, call: &NamespaceCall) -> bool {
    let mut host_work = false;
    let operands = call.paths();
    let files = view.query.as_ref().unwrap().files.clone();
    let mut accepted = BTreeMap::new();
    for (fd, path, _) in &operands {
        if path.is_none() || *fd != AT_FDCWD && path.is_some_and(|p| !p.starts_with(b"/")) {
            accepted
                .entry(*fd as u32)
                .or_insert_with(|| files.query_lookup(*fd as u32));
        }
    }
    view.query.as_mut().unwrap().accepted = Some(accepted);
    // Anonymous backing construction is real native filesystem I/O, with no
    // pathname/mount lookup or namespace administration transaction.
    if matches!(call, NamespaceCall::Memfd(_)) {
        return true;
    }
    // Socket ownership is original sockfs metadata plus sk_uid. It performs
    // no filesystem I/O merely because the calling task's root is disk-backed.
    if let NamespaceCall::Chown { fd, path: None, .. } = call {
        if view
            .descriptor(*fd as u32)
            .is_ok_and(|d| d.open.borrow().socket.is_some())
        {
            return false;
        }
    }
    if !view.query.as_ref().unwrap().namespace_io {
        return false;
    }
    // Scheduling advice only: errors/validation order belong to the
    // unchanged algorithm. No namespace effect occurs in this probe.
    for (fd, path, follow) in operands {
        let fs = match path {
            Some(path) => view
                .resolve_final(fd, path, follow)
                .ok()
                .map(|p| p.filesystem(view)),
            None => view.descriptor(fd as u32).ok().map(|d| {
                d.open
                    .borrow()
                    .mount
                    .as_ref()
                    .map_or_else(|| view.fs.clone(), |m| m.fs.clone())
            }),
        };
        if let Some(fs) = fs {
            #[cfg(all(feature = "hostfs", unix))]
            {
                host_work |= fs.host.is_some();
            }
            host_work |= fs.borrow().disk.is_some() || fs.has_overlay();
        }
    }
    host_work
}
impl PathQueries {
    /// The ordinary short path borrows only this caller's existing control
    /// view. No private VFS, namespace graph or descriptor table is copied.
    pub fn namespace_attempt(&self, call: NamespaceCall) -> NamespaceAttempt {
        struct Restore<'a> {
            view: &'a mut Vfs,
            accepted: Option<BTreeMap<u32, Option<Result<SharedFd>>>>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.view.query.as_mut().unwrap().accepted = self.accepted.take();
            }
        }
        let (work, accepted, reply) = {
            let mut view = self.view.borrow_mut();
            let accepted = view.query.as_mut().unwrap().accepted.take();
            let scope = Restore {
                view: &mut view,
                accepted,
            };
            let host_work = prepare_namespace(scope.view, &call);
            let mut work = NamespaceWork {
                call,
                host_work,
                waiting: None,
            };
            let reply = if host_work {
                NamespaceRun::Owner
            } else {
                work.execute(scope.view)
            };
            let accepted = scope.view.query.as_mut().unwrap().accepted.take();
            (work, accepted, reply)
        };
        if let NamespaceRun::Complete(reply) = reply {
            return NamespaceAttempt::Complete(reply);
        }
        let paths = self.retain_context();
        paths.view.borrow_mut().query.as_mut().unwrap().accepted = accepted;
        NamespaceAttempt::Retained(FileWork::namespace(paths, work))
    }
    pub fn namespace_work(&self, call: NamespaceCall) -> FileWork {
        let paths = self.retain_context();
        let host_work = prepare_namespace(&mut paths.view.borrow_mut(), &call);
        paths.view.borrow().query.as_ref().unwrap().clear_deferred();
        FileWork::namespace(
            paths,
            NamespaceWork {
                call,
                host_work,
                waiting: None,
            },
        )
    }
}
impl NamespaceWork {
    pub(super) fn host_work(&self) -> bool {
        self.host_work
    }
    pub(super) fn waiting(&self) -> bool {
        self.waiting.is_some()
    }
    pub(super) fn ready(&self) -> bool {
        self.waiting.as_ref().is_none_or(|admin| admin.ready())
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        self.waiting.as_ref().map(|admin| admin.subscribe(signal))
    }
    pub(super) fn run(&mut self, paths: &PathQueries) -> NamespaceRun {
        self.execute(&mut paths.view.borrow_mut())
    }
    fn execute(&mut self, view: &mut Vfs) -> NamespaceRun {
        self.waiting = None;
        let admin = if self.call.topology() {
            match view.mount_admin() {
                Ok(admin) => Some(admin),
                Err(error) => return NamespaceRun::Complete(Err(error)),
            }
        } else {
            None
        };
        let _lease = if let Some(admin) = &admin {
            let Some(lease) = admin.try_enter() else {
                self.waiting = Some(admin.clone());
                return NamespaceRun::Waiting;
            };
            Some(lease)
        } else {
            None
        };
        view.query.as_ref().unwrap().clear_deferred();
        // A topology transaction already retains its namespace. Its own path
        // lookup is not an external fs/file user that makes umount EBUSY.
        if !self.call.topology() {
            view.query.as_ref().unwrap().namespace_uses.begin();
        }
        let result = self.call.execute_locked(view);
        let query = view.query.as_ref().unwrap();
        let uses = query.namespace_uses.finish();
        let deferred = query.take_deferred();
        drop(uses);
        if deferred {
            NamespaceRun::Owner
        } else {
            NamespaceRun::Complete(result)
        }
    }
    pub(super) fn run_owner(&self, paths: &PathQueries, owner: &mut Vfs) -> Result<FileValue> {
        // Rare owner-only proc/task/mount descriptions retain the original
        // resolver. Accepted shared descriptions override only their own slots;
        // the original /proc/self/fd namespace remains visible.
        struct Restore<'a> {
            owner: &'a mut Vfs,
            fds: DescriptorTable,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.owner.fds = std::mem::take(&mut self.fds);
            }
        }
        let fds = std::mem::take(&mut owner.fds);
        owner.fds = fds.clone();
        let guard = Restore { owner, fds };
        let view = paths.view.borrow();
        for (&fd, file) in view.query.as_ref().unwrap().accepted.as_ref().unwrap() {
            match file {
                Some(Ok(file)) => {
                    guard.owner.fds.insert(
                        fd,
                        Descriptor {
                            open: OpenHandle::Shared(file.open.clone()),
                            cloexec: false.into(),
                        },
                    );
                }
                Some(Err(_)) => {
                    guard.owner.fds.remove(&fd);
                }
                None => (),
            }
        }
        self.call.execute(guard.owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn executing_namespace_io_pins_only_walked_mounts_until_completion() {
        use std::time::{Duration, Instant};
        let mut owner = Vfs::default();
        for path in [b"/used".as_slice(), b"/unrelated"] {
            owner.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
            owner.mount(None, path, Some(b"tmpfs"), 0, None).unwrap();
        }
        let at = owner.mount_location(b"/used", true).unwrap();
        let used = at.mount.as_ref().unwrap().identity.clone();
        let namespace = at.filesystem(&owner).namespace.clone();
        drop(at);
        let work = owner.path_queries().namespace_work(NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/used/new".to_vec(),
            mode: 0o755,
        });
        let blocked = namespace.lock().unwrap();
        let worker = std::thread::spawn(move || finish(work));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !used.in_use() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let active = used.in_use();
        let in_use = owner.umount(b"/used", 0);
        let unrelated = owner.umount(b"/unrelated", 0);
        drop(blocked);
        let completed = worker.join().unwrap();
        assert!(
            active,
            "operation reached its original mount before blocking on namespace I/O"
        );
        assert_eq!(in_use, Err(Errno(16)));
        assert_eq!(unrelated, Ok(()));
        assert!(matches!(completed, Ok(FileValue::Count(0))));
        owner.umount(b"/used", 0).unwrap();
    }
    fn finish(work: FileWork) -> Result<FileValue> {
        match work.run() {
            FileOutcome::Complete(reply) => reply.result,
            FileOutcome::Waiting(_) => panic!("unexpected stream wait"),
            FileOutcome::Owner(_) => panic!("ordinary namespace reached owner"),
            FileOutcome::Layout(_) => panic!("namespace unexpectedly changed mapped backing"),
        }
    }
    fn count(work: FileWork) -> Result<u64> {
        match finish(work)? {
            FileValue::Count(n) => Ok(n),
            _ => panic!("expected count"),
        }
    }
    #[test]
    fn canonical_cwd_root_and_clone_fs_are_visible_to_existing_query_views() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/a", 0o755).unwrap();
        owner.mkdir_at(AT_FDCWD, b"/jail", 0o755).unwrap();
        owner.mkdir_at(AT_FDCWD, b"/jail/inside", 0o755).unwrap();
        let shared = owner.clone_with_resources(false, true);
        let fork = owner.clone();
        let source = owner.path_queries();
        let observer = shared.path_queries();
        assert_eq!(
            count(source.namespace_work(NamespaceCall::Chdir(b"/a".to_vec()))),
            Ok(0)
        );
        assert_eq!(owner.cwd().unwrap(), b"/a");
        assert_eq!(shared.cwd().unwrap(), b"/a");
        assert_eq!(fork.cwd().unwrap(), b"/");
        let FileValue::Bytes(cwd) = finish(observer.namespace_work(NamespaceCall::Cwd)).unwrap()
        else {
            panic!()
        };
        assert_eq!(cwd, b"/a\0");
        assert_eq!(
            count(source.namespace_work(NamespaceCall::Chroot(b"/jail".to_vec()))),
            Ok(0)
        );
        assert_eq!(
            count(observer.namespace_work(NamespaceCall::Chdir(b"/inside".to_vec()))),
            Ok(0)
        );
        assert_eq!(owner.cwd().unwrap(), b"/inside");
        assert_eq!(shared.cwd().unwrap(), b"/inside");
        assert_eq!(fork.cwd().unwrap(), b"/");
    }
    #[test]
    fn competing_creators_do_not_replace_an_existing_directory() {
        let owner = Vfs::default();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let work = owner.path_queries().namespace_work(NamespaceCall::Mkdir {
                    fd: AT_FDCWD,
                    path: b"/winner".to_vec(),
                    mode: 0o755,
                });
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    count(work)
                })
            })
            .collect();
        let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| **r == Ok(0)).count(), 1);
        assert_eq!(results.iter().filter(|r| **r == Err(Errno(17))).count(), 7);
        assert_eq!(
            u32::from_le_bytes(
                owner.stat_at(AT_FDCWD, b"/winner").unwrap()[16..20]
                    .try_into()
                    .unwrap()
            ) & 0o170000,
            0o40000
        );
    }
    #[test]
    fn accepted_directory_fd_and_inode_metadata_survive_close_and_reuse() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/old", 0o755).unwrap();
        owner.mkdir_at(AT_FDCWD, b"/new", 0o755).unwrap();
        let fd = owner.open_at(AT_FDCWD, b"/old", 0, 0).unwrap();
        let work = owner.path_queries().namespace_work(NamespaceCall::Mkdir {
            fd: fd as i32,
            path: b"/absolute".to_vec(),
            mode: 0o700,
        });
        // Absolute operands ignore even a replaced dirfd.
        owner.close(fd).unwrap();
        assert_eq!(owner.open_at(AT_FDCWD, b"/new", 0, 0).unwrap(), fd);
        assert_eq!(count(work), Ok(0));
        owner.close(fd).unwrap();
        let fd = owner.open_at(AT_FDCWD, b"/old", 0, 0).unwrap();
        let work = owner.path_queries().namespace_work(NamespaceCall::Mkdir {
            fd: fd as i32,
            path: b"child".to_vec(),
            mode: 0o700,
        });
        owner.close(fd).unwrap();
        assert_eq!(owner.open_at(AT_FDCWD, b"/new", 0, 0).unwrap(), fd);
        assert_eq!(count(work), Ok(0));
        assert!(owner.stat_at(AT_FDCWD, b"/old/child").is_ok());
        assert_eq!(owner.stat_at(AT_FDCWD, b"/new/child"), Err(Errno(2)));
    }
    #[test]
    fn published_global_readonly_namespace_rejection_completes_on_source() {
        let mut owner = Vfs::default();
        owner.set_runtime_info(1, RuntimeInfo::default());
        let work = owner.path_queries().namespace_work(NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/proc/new".to_vec(),
            mode: 0o755,
        });
        assert_eq!(count(work), Err(Errno(30)));
        assert_eq!(owner.stat_at(AT_FDCWD, b"/proc/new"), Err(Errno(2)));
    }
    #[test]
    fn explicitly_unavailable_provider_has_no_namespace_effect_before_retained_handoff() {
        struct Unavailable;
        impl ProcSource for Unavailable {
            fn available(&self, _: ProcRefresh) -> bool {
                false
            }
            fn observe(&self, _: ProcQuery<'_>) -> RuntimeInfo {
                panic!("unavailable source provider")
            }
        }
        let mut owner = Vfs::default();
        owner.set_runtime_info(1, RuntimeInfo::default());
        owner.set_proc_source(Arc::new(Unavailable));
        let work = owner.path_queries().namespace_work(NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/proc/new".to_vec(),
            mode: 0o755,
        });
        let FileOutcome::Owner(work) = work.run() else {
            panic!("proc control must retain owner resolver")
        };
        assert_eq!(
            work.run_owner(&mut owner).result.map(|v| match v {
                FileValue::Count(n) => n,
                _ => panic!(),
            }),
            Err(Errno(30))
        );
        assert_eq!(owner.stat_at(AT_FDCWD, b"/proc/new"), Err(Errno(2)));
    }
}
