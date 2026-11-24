// SPDX-License-Identifier: GPL-3.0-or-later
//! Fresh opens of an inode retained by a proc magic link, without path replay.
use super::*;

impl Metadata {
    pub(super) fn begin_open(
        &mut self,
        v: &mut Vfs,
        mount_flags: &mounts::MountFlags,
        flags: u32,
        attr: &[u8],
    ) -> Result<Option<FileValue>> {
        self.begin_open_checked(v, mount_flags, flags, attr, false)
    }
    pub(super) fn begin_open_checked(
        &mut self,
        v: &mut Vfs,
        mount_flags: &mounts::MountFlags,
        flags: u32,
        attr: &[u8],
        permission_checked: bool,
    ) -> Result<Option<FileValue>> {
        let reference = self.reference.as_ref().unwrap();
        let node = reference.node;
        let fs = reference.fs.clone();
        let caller = fs.caller(v);
        let kind = u32::from_le_bytes(attr[60..64].try_into().unwrap()) & 0o170000;
        if flags & (O_CREAT | 0x80) == O_CREAT | 0x80 {
            return Err(Errno(17));
        }
        if kind == 0o040000 && flags & O_CREAT != 0 {
            return Err(Errno(21));
        }
        if !permission_checked && flags & O_CREAT != 0 {
            if let Some(parent) = self
                .open
                .as_ref()
                .and_then(|plan| plan.sticky_parent.as_ref())
            {
                let owner = fs
                    .namespace
                    .to_global(false, u32::from_le_bytes(attr[68..72].try_into().unwrap()))
                    .ok_or(Errno(75))?;
                let mode = u32::from_le_bytes(attr[60..64].try_into().unwrap());
                v.check_sticky_create_in(mode, owner, parent)?;
            }
        }
        if flags & O_DIRECTORY != 0 && kind != 0o040000 {
            return Err(Errno(20));
        }
        if flags & O_PATH != 0 {
            return self
                .publish_open(None, attr.try_into().unwrap(), 0)
                .map(Some);
        }
        if let Some(node) = reference.leaf.as_ref().or(reference.directory.as_ref()) {
            fs.check_inode(node)?;
        }
        let access = if kind == 0o040000 {
            landlock::READ_DIR
        } else {
            (if fd_can_read(flags) {
                landlock::READ_FILE
            } else {
                0
            }) | (if fd_can_write(flags) {
                landlock::WRITE_FILE
            } else {
                0
            }) | (if flags & O_TRUNC != 0 {
                landlock::TRUNCATE
            } else {
                0
            })
        };
        if self.open.as_ref().expect("FUSE open intent").denied & access != 0 {
            return Err(Errno(13));
        }
        if kind == 0o120000 {
            return Err(Errno(40));
        }
        if (fd_can_write(flags) || flags & O_TRUNC != 0)
            && mount_flags.get() & mounts::MS_RDONLY != 0
        {
            return Err(Errno(30));
        }
        if kind == 0o040000 && flags & (3 | O_TRUNC) != 0 {
            return Err(Errno(21));
        }
        if !matches!(kind, 0o100000 | 0o040000) {
            return Err(Errno(95));
        }
        if fs.local_permissions() && !permission_checked {
            let mask =
                [4, 2, 6, 6][(flags & 3) as usize] | if flags & O_TRUNC != 0 { 2 } else { 0 };
            return self.begin_permission(
                v,
                v.credentials.clone(),
                mask,
                permissions::After::Open(flags),
            );
        }
        let mut body = [0; 8];
        // ATOMIC_O_TRUNC is not negotiated: Linux completes OPEN first, then
        // sends SETATTR without FATTR_FH and publishes the FD only on success.
        let open_flags = flags & !(O_CLOEXEC | OPEN_ONLY_FLAGS | O_TRUNC) | O_LARGEFILE;
        if fd_can_write(flags) || flags & O_TRUNC != 0 {
            let plan = self.open.as_mut().unwrap();
            if plan.writer.is_none() {
                plan.writer = Some(mapped::MountWrite::new(&plan.mount.identity)?);
            }
        }
        body[..4].copy_from_slice(&open_flags.to_le_bytes());
        self.request = Some(Arc::new(fs.connection.request(
            if kind == 0o040000 { 27 } else { 14 },
            node,
            caller,
            &body,
        )?));
        self.kind = ResultKind::Open(attr.try_into().unwrap());
        Ok(None)
    }
    pub(crate) fn reopen_file(v: &Vfs, file: Arc<File>) -> Result<Self> {
        let fs = &file.reference.fs;
        fs.check(&v.credentials)?;
        file.attr.check()?;
        let mut body = [0; 16];
        if let Some(fh) = file.fh {
            body[..4].copy_from_slice(&1u32.to_le_bytes());
            body[8..].copy_from_slice(&fh.to_le_bytes());
        }
        if let Some(node) = file.inode() {
            fs.invalidate_acl(&node);
        }
        Ok(Self {
            request: Some(Arc::new(fs.connection.request(
                3,
                file.reference.node,
                fs.caller(v),
                &body,
            )?)),
            reference: Some(file.reference.clone()),
            _usage: Some(mounts::MountUse::new(file.mount.identity.clone())),
            resolved: None,
            resolved_entry: None,
            open: None,
            mount: StatMount::mounted(file.mount.id, false),
            dev: file.mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
            kind: ResultKind::ReopenFile(file),
        })
    }
}
impl Vfs {
    pub(crate) fn reopen_fuse_file(
        &self,
        file: Arc<File>,
        path: Vec<u8>,
        flags: u32,
        mode: u32,
        publication: Option<&DirectFiles>,
        reservation: fd_table::ReservedFd,
    ) -> Result<u32> {
        let query = self.query.as_ref().ok_or(Errno(95))?;
        let root = ResolvedPath {
            key: file.mount.root_path(),
            mount: Some(Mount::resource_projection(file.mount.clone())),
            proc_binding: None,
            directory_inode: None,
            indexed_position: None,
            #[cfg(all(feature = "hostfs", unix))]
            host_position: None,
            retained_directory: None,
        };
        let denied = if flags & O_PATH != 0 {
            0
        } else {
            self.landlock_denied(
                &root,
                None,
                landlock::READ_FILE
                    | landlock::WRITE_FILE
                    | landlock::READ_DIR
                    | landlock::TRUNCATE,
            )?
        };
        let mount = file.mount.clone();
        let mut pending = Metadata::reopen_file(self, file)?;
        pending.prepare_open(
            self.open_id(),
            mount,
            path,
            flags,
            denied,
            self.credentials.open_identity(),
        );
        pending.reserve_open(
            reservation,
            mode,
            self.umask_capability(),
            publication.cloned(),
        );
        query.prepared.borrow_mut().fuse = Some(Box::new(pending));
        query.defer()
    }
}
