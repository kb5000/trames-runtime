// SPDX-License-Identifier: GPL-3.0-or-later
//! Owned namespace calls over the original fs_struct, Files and filesystem.
use super::*;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PathKey(usize, i32, Vec<u8>, bool, bool, u64, bool);
impl PathKey {
    pub(super) fn new(
        operand: usize,
        fd: i32,
        path: &[u8],
        follow: bool,
        retain: bool,
        policy: u64,
        stop: bool,
    ) -> Self {
        Self(operand, fd, path.to_vec(), follow, retain, policy, stop)
    }
}
#[derive(Default)]
pub(super) struct AcceptedPaths {
    pub accepted: BTreeMap<PathKey, ResolvedEntry>,
    pub pending: Option<PathKey>,
    pub cursor: usize,
    pub native: bool,
}

pub enum NamespaceCall {
    LocalBind {
        socket: LocalOperation,
        address: Vec<u8>,
    },
    LocalConnect {
        socket: LocalOperation,
        address: Vec<u8>,
        identity: [u32; 3],
    },
    LocalDatagram {
        socket: LocalOperation,
        address: Option<Vec<u8>>,
    },
    MountFd(MountFdCall),
    MountQuery(MountQuery),
    MqOpen {
        name: Vec<u8>,
        flags: u32,
        mode: u32,
        attr: Option<[i64; 2]>,
    },
    MqUnlink(Vec<u8>),
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
        follow: bool,
        empty_path: bool,
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
        capacity: u64,
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
    fn stale_retry(&self) -> bool {
        matches!(
            self,
            Self::Mkdir { .. }
                | Self::LocalBind { .. }
                | Self::Mknod { .. }
                | Self::Symlink { .. }
                | Self::Unlink { .. }
                | Self::Link { .. }
                | Self::Rename { .. }
                | Self::Chmod { empty: true, .. }
                | Self::Chown { empty: true, .. }
        ) || matches!(self, Self::Times { path: Some(path), flags, .. } if path.is_empty() && flags & 0x1000 != 0)
            || self.metadata()
                && self
                    .paths()
                    .iter()
                    .any(|(_, path, _)| path.is_some_and(|p| !p.is_empty()))
    }
    fn paths(&self) -> Vec<(i32, Option<&[u8]>, bool)> {
        match self {
            Self::LocalBind { address, .. } | Self::LocalConnect { address, .. }
                if address.len() > 2 && address[2] != 0 =>
            {
                let end = address[2..]
                    .iter()
                    .position(|b| *b == 0)
                    .map_or(address.len(), |i| i + 2);
                vec![(
                    AT_FDCWD,
                    Some(&address[2..end]),
                    !matches!(self, Self::LocalBind { .. }),
                )]
            }
            Self::LocalDatagram {
                address: Some(address),
                ..
            } if address.len() > 2 && address[2] != 0 => {
                let end = address[2..]
                    .iter()
                    .position(|b| *b == 0)
                    .map_or(address.len(), |i| i + 2);
                vec![(AT_FDCWD, Some(&address[2..end]), true)]
            }
            Self::LocalBind { .. } | Self::LocalConnect { .. } | Self::LocalDatagram { .. } => {
                Vec::new()
            }
            Self::MountFd(call) => call.operands(),
            Self::Memfd(_) | Self::MqOpen { .. } | Self::MqUnlink(_) | Self::MountQuery(_) => {
                Vec::new()
            }
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
                follow,
                ..
            } => vec![(*oldfd, Some(old), *follow), (*newfd, Some(new), false)],
            Self::Rename {
                oldfd,
                old,
                newfd,
                new,
                ..
            } => vec![(*oldfd, Some(old), false), (*newfd, Some(new), false)],
            Self::Chmod {
                fd,
                path,
                nofollow,
                empty,
                ..
            }
            | Self::Chown {
                fd,
                path,
                nofollow,
                empty,
                ..
            } => {
                let path = if *empty && *fd == AT_FDCWD && path.is_none() {
                    Some(b".".as_slice())
                } else {
                    path.as_deref()
                };
                vec![(*fd, path, !nofollow)]
            }
            Self::Times { times: Some(t), .. } if t.iter().all(|pair| pair[1] == UTIME_OMIT) => {
                Vec::new()
            }
            Self::Times {
                fd, path, flags, ..
            } => {
                let path = match path.as_deref() {
                    None | Some(b"") if flags & 0x1000 != 0 && *fd == AT_FDCWD => {
                        Some(b".".as_slice())
                    }
                    Some(b"") if flags & 0x1000 != 0 => None,
                    p => p,
                };
                vec![(*fd, path, flags & 0x100 == 0)]
            }
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
        matches!(self, Self::MountFd(call) if call.topology())
            || matches!(
                self,
                Self::Mount { .. }
                    | Self::Umount { .. }
                    | Self::PivotRoot { .. }
                    | Self::MountQuery(_)
            )
    }
    fn metadata(&self) -> bool {
        matches!(
            self,
            Self::Chmod { .. }
                | Self::Chown { .. }
                | Self::Times { .. }
                | Self::Xattr { .. }
                | Self::GetXattr { .. }
        )
    }
    fn retains_paths(&self) -> bool {
        matches!(
            self,
            Self::LocalBind { .. }
                | Self::LocalConnect { .. }
                | Self::LocalDatagram { .. }
                | Self::Mount { .. }
                | Self::Link { .. }
                | Self::Umount { .. }
                | Self::PivotRoot { .. }
                | Self::MountFd(
                    MountFdCall::Tree { .. } | MountFdCall::Move { .. } | MountFdCall::Pick { .. }
                )
        ) || matches!(self, Self::MountFd(MountFdCall::SetAttr { attrs, .. }) if !attrs.is_empty())
    }
    fn admin(&self, v: &Vfs) -> Result<Arc<mounts::admin::Admin>> {
        match self {
            Self::MountQuery(query) => v.mount_query_admin(query.namespace),
            _ => v.mount_admin(),
        }
    }
    fn execute_locked(&self, v: &mut Vfs) -> Result<FileValue> {
        match self {
            Self::MountFd(call) => return call.run(v).map(FileValue::Count),
            Self::MountQuery(query) => return v.mount_query(query).map(FileValue::Bytes),
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
            Self::LocalBind { socket, address } => v.local_bind_entered(socket.core(), address)?,
            Self::LocalConnect {
                socket,
                address,
                identity,
            } => {
                return v
                    .local_connection_core(socket.core(), address, *identity)
                    .map(FileValue::LocalConnection)
            }
            Self::LocalDatagram { socket, address } => {
                return v
                    .local_datagram_core(socket.core(), address.as_deref())
                    .map(FileValue::LocalDatagram)
            }
            Self::MqOpen {
                name,
                flags,
                mode,
                attr,
            } => {
                return v
                    .mq_open(name, *flags, *mode, *attr)
                    .map(|fd| FileValue::Count(fd.into()))
            }
            Self::MqUnlink(name) => v.mq_unlink(name)?,
            Self::Memfd(parameters) => {
                return parameters.create(v).map(|fd| FileValue::Count(fd as u64))
            }
            Self::MountFd(call) => {
                if call.topology() {
                    let admin = v.mount_admin()?;
                    let _guard = admin.enter();
                    return call.run(v).map(FileValue::Count);
                }
                return call.run(v).map(FileValue::Count);
            }
            Self::MountQuery(query) => {
                let admin = self.admin(v)?;
                let _lease = admin.enter();
                return v.mount_query(query).map(FileValue::Bytes);
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
                follow,
                empty_path,
            } => v.link_at_follow(*oldfd, old, *newfd, new, *follow, *empty_path)?,
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
                None if *empty && *fd == AT_FDCWD => {
                    v.chmod_at_flags(*fd, b".", *mode, *nofollow)?
                }
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
                None if *empty && *fd == AT_FDCWD => {
                    v.chown_at(*fd, b".", *uid, *gid, *nofollow)?
                }
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
                capacity,
            } => return v.read_xattrs(*fd, path.as_deref(), *follow, name.as_deref(), *capacity),
            Self::Chdir(path) => v.chdir(path)?,
            Self::Fchdir(fd) => v.chdir_fd(*fd)?,
            Self::Chroot(path) => v.chroot(path)?,
            Self::Cwd => return v.cwd_reply(&v.context.paths.borrow()),
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
    bind: Option<ipc::BindLease>,
    call: NamespaceCall,
    revalidated: bool,
    host_work: bool,
    waiting: Option<Arc<mounts::admin::Admin>>,
    fuse: Option<Box<fuse::Metadata>>,
    parents: Option<Box<fuse::PendingNamespace>>,
    paths: Option<Arc<SharedCell<AcceptedPaths>>>,
}
pub(super) enum NamespaceRun {
    Complete(Result<FileValue>),
    Waiting,
    Owner,
}
pub enum NamespaceAttempt {
    Complete(FileReply),
    Retained(FileWork),
}
impl Vfs {
    fn cwd_reply(&self, paths: &fs_context::Paths) -> Result<FileValue> {
        crate::output_resources::OutputScope::retain(|| {
            (
                paths.clone(),
                paths
                    .cwd_mount
                    .as_ref()
                    .map(|mount| mounts::MountUse::new(mount.identity.clone())),
                paths
                    .root_mount
                    .as_ref()
                    .map(|mount| mounts::MountUse::new(mount.identity.clone())),
            )
        });
        let mut name = self.cwd_name::<true>(paths)?;
        if name.len() >= MAX_PATH {
            return Err(Errno(36));
        }
        name.push(0);
        Ok(FileValue::Bytes(name))
    }
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
    if let NamespaceCall::Mount {
        kind: Some(kind),
        data: Some(data),
        flags,
        ..
    } = call
    {
        if kind == b"fuse" && flags & (32 | 4096 | 8192) == 0 {
            if let Ok(fd) = fuse::option_fd(data, &view.credentials.user_namespace) {
                accepted.insert(fd, files.query_lookup(fd));
            }
        }
    }
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
    if matches!(
        call,
        NamespaceCall::MountFd(
            MountFdCall::Open { .. } | MountFdCall::Config { .. } | MountFdCall::Mount { .. }
        )
    ) {
        // These contexts only construct in-memory filesystems or pseudo roots.
        return false;
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
        let scope = crate::output_resources::OutputScope::enter();
        if matches!(call, NamespaceCall::Cwd) {
            let reply = self.query(|view| {
                // Both names in the private volume come from its in-memory
                // directory index, even when the guest volume is persistent.
                // Capture the pair once, including for concurrent CLONE_FS peers.
                let paths = view.context.paths.borrow();
                if paths
                    .cwd_mount
                    .as_ref()
                    .zip(paths.root_mount.as_ref())
                    .is_some_and(|(cwd, root)| {
                        cwd.kind == mounts::Kind::Root
                            && Arc::ptr_eq(&cwd.shared, &root.shared)
                            && cwd.parent.borrow().is_none()
                    })
                {
                    view.cwd_reply(&paths)
                } else {
                    view.query.as_ref().unwrap().defer()
                }
            });
            if let Some(reply) = reply {
                return NamespaceAttempt::Complete(
                    FileReply {
                        result: reply,
                        resources: Default::default(),
                        file_size_signal: false,
                        scratch: None,
                    }
                    .retain_output(scope.finish()),
                );
            }
        }
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
            let paths = call
                .retains_paths()
                .then(|| Arc::new(SharedCell::default()));
            let mut work = NamespaceWork {
                bind: None,
                call,
                revalidated: false,
                paths,
                host_work,
                waiting: None,
                fuse: None,
                parents: None,
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
            return NamespaceAttempt::Complete(
                FileReply {
                    result: reply,
                    resources: Default::default(),
                    file_size_signal: false,
                    scratch: None,
                }
                .retain_output(scope.finish()),
            );
        }
        let paths = self.retain_context();
        paths.view.borrow_mut().query.as_mut().unwrap().accepted = accepted;
        NamespaceAttempt::Retained(FileWork::namespace(paths, work))
    }
    pub fn namespace_work(&self, call: NamespaceCall) -> FileWork {
        let paths = self.retain_context();
        let host_work = prepare_namespace(&mut paths.view.borrow_mut(), &call);
        paths.view.borrow().query.as_ref().unwrap().clear_deferred();
        let accepted_paths = call
            .retains_paths()
            .then(|| Arc::new(SharedCell::default()));
        FileWork::namespace(
            paths,
            NamespaceWork {
                bind: None,
                call,
                revalidated: false,
                paths: accepted_paths,
                host_work,
                waiting: None,
                fuse: None,
                parents: None,
            },
        )
    }
}
impl NamespaceWork {
    fn complete(
        &mut self,
        view: &mut Vfs,
        value: Result<FileValue>,
        stale_retry: bool,
    ) -> NamespaceRun {
        if matches!(value, Err(Errno(116)))
            && stale_retry
            && !self.revalidated
            && self.call.stale_retry()
        {
            self.revalidated = true;
            // An explicit native revalidation starts another pathname attempt.
            // Waiting, page copy and daemon interruption never enter here.
            self.fuse = None;
            self.parents = None;
            self.waiting = None;
            if let Some(paths) = &self.paths {
                *paths.borrow_mut() = AcceptedPaths::default();
            }
            view.query
                .as_ref()
                .unwrap()
                .metadata_entry
                .borrow_mut()
                .take();
            if let Some(namespace) = view.mounts.as_ref().and_then(MountNamespace::original) {
                // root/cwd and the live registry name these original mount
                // objects. A fresh projection cannot follow their attachments.
                view.mounts = Some(namespace);
            }
            let aliases: BTreeMap<_, _> = view
                .query
                .as_ref()
                .unwrap()
                .accepted
                .as_ref()
                .into_iter()
                .flat_map(|files| files.iter())
                .filter(|(fd, _)| **fd >= MAX_FDS)
                .map(|(fd, file)| (*fd, file.clone()))
                .collect();
            self.host_work = prepare_namespace(view, &self.call);
            view.query
                .as_mut()
                .unwrap()
                .accepted
                .as_mut()
                .unwrap()
                .extend(aliases);
            // Owner-only numeric operands also need their new admission. Fixed
            // retained/peer aliases still override these observation slots.
            let query = view.query.as_ref().unwrap();
            for (&fd, file) in query.accepted.as_ref().unwrap() {
                if file.is_none() {
                    if let Ok(descriptor) = query.files.observation_descriptor(fd) {
                        view.fds.insert(fd, descriptor);
                    } else {
                        view.fds.remove(&fd);
                    }
                }
            }
            view.query.as_ref().unwrap().clear_deferred();
            return self.execute(view);
        }
        NamespaceRun::Complete(value)
    }
    pub(super) fn fuse_request(&self) -> Option<&fuse::Metadata> {
        self.parents
            .as_ref()
            .and_then(|parents| parents.request())
            .or(self.fuse.as_deref())
    }
    pub(super) fn host_work(&self) -> bool {
        if let Some(pending) = &self.fuse {
            return pending.host_work();
        }
        self.parents
            .as_ref()
            .map_or(self.host_work, |parents| parents.host_work())
    }
    pub(super) fn owner_work(&self) -> bool {
        self.parents
            .as_ref()
            .is_some_and(|pending| pending.owner_work())
            || self
                .fuse
                .as_ref()
                .is_some_and(|pending| pending.owner_work())
    }
    pub(super) fn join_owner(&mut self) {
        if let Some(parents) = &mut self.parents {
            parents.join_owner();
        }
        if let Some(pending) = &mut self.fuse {
            pending.join_owner();
        }
    }
    pub(super) fn waiting(&self) -> bool {
        self.bind_wait().is_some()
            || self.waiting.is_some()
            || self.fuse.is_some()
            || self.parents.is_some()
    }
    fn bind_wait(&self) -> Option<&Arc<ipc::BindLock>> {
        match &self.call {
            NamespaceCall::LocalBind { socket, .. } if self.bind.is_none() => {
                Some(&socket.bind_lock)
            }
            _ => None,
        }
    }
    pub(super) fn ready(&self) -> bool {
        self.bind_wait().is_none_or(|bind| bind.ready())
            && self.waiting.as_ref().is_none_or(|admin| admin.ready())
            && self.fuse.as_ref().is_none_or(|f| f.ready())
            && self.parents.as_ref().is_none_or(|parents| parents.ready())
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Option<IoSubscription> {
        if let Some(bind) = self.bind_wait() {
            return Some(bind.subscribe(signal));
        }
        self.waiting
            .as_ref()
            .map(|admin| admin.subscribe(signal))
            .or_else(|| self.fuse_request().and_then(|f| f.subscribe(signal)))
    }
    pub(super) fn run(&mut self, paths: &PathQueries) -> NamespaceRun {
        self.execute(&mut paths.view.borrow_mut())
    }
    fn execute(&mut self, view: &mut Vfs) -> NamespaceRun {
        if let Some(bind) = self.bind_wait() {
            let Some(lease) = bind.try_enter() else {
                return NamespaceRun::Waiting;
            };
            self.bind = Some(lease);
        }
        let native = self.host_work();
        if self.owner_work() {
            return NamespaceRun::Owner;
        }
        if let Some(parents) = &mut self.parents {
            return match parents.run(view) {
                Ok(fuse::ParentStep::Waiting | fuse::ParentStep::Host) => NamespaceRun::Waiting,
                Ok(fuse::ParentStep::Mutation(pending)) => {
                    self.fuse = Some(pending);
                    self.parents = None;
                    self.host_work = false;
                    NamespaceRun::Waiting
                }
                Ok(fuse::ParentStep::Complete(value)) => NamespaceRun::Complete(Ok(value)),
                Err(error) => NamespaceRun::Complete(Err(error)),
            };
        }
        if let Some(f) = &mut self.fuse {
            if let Some(paths) = &self.paths {
                if paths.borrow().pending.is_some() {
                    self.host_work |= f.host_work();
                    let Some(value) = f.take(view) else {
                        return NamespaceRun::Waiting;
                    };
                    if let Err(error) = value {
                        return NamespaceRun::Complete(Err(error));
                    }
                    let Some(entry) = f.resolved_entry.take() else {
                        return NamespaceRun::Complete(Err(Errno(5)));
                    };
                    let mut paths = paths.borrow_mut();
                    let key = paths.pending.take().unwrap();
                    let entry = match view.pin_topology_entry(*entry) {
                        Ok(entry) => entry,
                        Err(error) => return NamespaceRun::Complete(Err(error)),
                    };
                    paths.accepted.insert(key, entry);
                    drop(paths);
                    self.fuse = None;
                    // A prior operand may have been accepted by the native
                    // executor before this daemon wait. Re-enter it for the
                    // final topology algorithm instead of doing its remaining
                    // native path work on the worker that received the reply.
                    if self.host_work && !native {
                        return NamespaceRun::Waiting;
                    }
                    return self.execute(view);
                }
            }
            if self.call.metadata() {
                self.host_work |= f.host_work();
                let Some(value) = f.take(view) else {
                    return NamespaceRun::Waiting;
                };
                if value.is_ok() {
                    if let Some(entry) = f.resolved_entry.take() {
                        let entry = match view.pin_topology_entry(*entry) {
                            Ok(entry) => Box::new(entry),
                            Err(error) => return NamespaceRun::Complete(Err(error)),
                        };
                        *view.query.as_ref().unwrap().metadata_entry.borrow_mut() = Some(entry);
                        self.fuse = None;
                        if self.host_work && !native {
                            return NamespaceRun::Waiting;
                        }
                        return self.execute(view);
                    }
                }
                if FileResources::needed(&value) {
                    f.retain_output();
                }
                let stale_retry = f.namespace_stale_retry();
                return self.complete(view, value, stale_retry);
            }
            let Some(value) = f.take(view) else {
                return NamespaceRun::Waiting;
            };
            let stale_retry = f.namespace_stale_retry();
            return self.complete(view, value, stale_retry);
        }
        self.waiting = None;
        let admin = if self.call.topology() {
            match self.call.admin(view) {
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
        let result = {
            struct Restore<'a> {
                view: &'a mut Vfs,
                previous: Option<Arc<SharedCell<AcceptedPaths>>>,
                metadata: bool,
            }
            impl Drop for Restore<'_> {
                fn drop(&mut self) {
                    self.view.query.as_mut().unwrap().metadata_call = self.metadata;
                    self.view.query.as_mut().unwrap().topology_paths = self.previous.take();
                }
            }
            let previous = std::mem::replace(
                &mut view.query.as_mut().unwrap().topology_paths,
                self.paths.clone(),
            );
            let previous_metadata = std::mem::replace(
                &mut view.query.as_mut().unwrap().metadata_call,
                self.call.metadata(),
            );
            let scope = Restore {
                view,
                previous,
                metadata: previous_metadata,
            };
            if let Some(paths) = &self.paths {
                let mut paths = paths.borrow_mut();
                paths.cursor = 0;
                paths.native = native;
            }
            self.call.execute_locked(scope.view)
        };
        let query = view.query.as_ref().unwrap();
        let uses = query.namespace_uses.finish();
        let deferred = query.take_deferred();
        drop(uses);
        if !deferred {
            return NamespaceRun::Complete(result);
        }
        let parents = query.prepared.borrow_mut().namespace.take();
        if let Some(parents) = parents {
            self.parents = Some(parents);
            return self.execute(view);
        }
        let pending = query.prepared.borrow_mut().fuse.take();
        if let Some(f) = pending {
            self.fuse = Some(f);
            NamespaceRun::Waiting
        } else {
            let owner = query.prepared.borrow_mut().owner_continuation.take();
            let needs_owner = owner.is_some();
            let walk = owner.or_else(|| query.prepared.borrow_mut().continuation.take());
            if let Some(walk) = walk {
                self.fuse = Some(Box::new(fuse::Metadata::continuation(
                    view,
                    walk,
                    needs_owner,
                )));
                NamespaceRun::Waiting
            } else {
                NamespaceRun::Owner
            }
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
    fn empty_chmod_and_chown_at_fdcwd_use_the_live_cwd_instead_of_a_numeric_descriptor() {
        let mut owner = Vfs::default();
        owner.mkdir_at(AT_FDCWD, b"/before", 0o755).unwrap();
        owner.mkdir_at(AT_FDCWD, b"/after", 0o755).unwrap();
        owner.chdir(b"/before").unwrap();
        let paths = owner.path_queries();
        owner.chdir(b"/after").unwrap();
        assert_eq!(
            count(paths.namespace_work(NamespaceCall::Chmod {
                fd: AT_FDCWD,
                path: None,
                mode: 0o711,
                nofollow: false,
                empty: true,
            })),
            Ok(0)
        );
        assert_eq!(
            count(paths.namespace_work(NamespaceCall::Chown {
                fd: AT_FDCWD,
                path: None,
                uid: 42,
                gid: 43,
                nofollow: false,
                empty: true,
            })),
            Ok(0)
        );
        let before = owner.stat_at(AT_FDCWD, b"/before").unwrap();
        let after = owner.stat_at(AT_FDCWD, b"/after").unwrap();
        assert_eq!(
            u32::from_le_bytes(before[16..20].try_into().unwrap()) & 0o7777,
            0o755
        );
        assert_eq!(
            u32::from_le_bytes(after[16..20].try_into().unwrap()) & 0o7777,
            0o711
        );
        assert_eq!(u32::from_le_bytes(after[24..28].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(after[28..32].try_into().unwrap()), 43);
    }
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
    fn missing_proc_dentry_completes_on_source() {
        let mut owner = Vfs::default();
        owner.set_runtime_info(1, RuntimeInfo::default());
        let work = owner.path_queries().namespace_work(NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/proc/new".to_vec(),
            mode: 0o755,
        });
        assert_eq!(count(work), Err(Errno(2)));
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
            Err(Errno(2))
        );
        assert_eq!(owner.stat_at(AT_FDCWD, b"/proc/new"), Err(Errno(2)));
    }
}
