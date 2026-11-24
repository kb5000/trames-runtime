// SPDX-License-Identifier: GPL-3.0-or-later
//! Resume the original VFS pathname walk after one daemon-owned component.
use super::*;

pub(super) struct RestoreCredentials<'a> {
    pub(super) view: &'a mut Vfs,
    pub(super) previous: Credentials,
}
impl Drop for RestoreCredentials<'_> {
    fn drop(&mut self) {
        std::mem::swap(&mut self.view.credentials, &mut self.previous);
    }
}

impl Metadata {
    fn adopt_walk_request(&mut self, mut pending: Box<Self>) {
        if let Some(mut accepted) = self.open.take() {
            if let Some(next) = &mut pending.open {
                next.id = accepted.id;
                next.slot = accepted.slot.take();
                next.mode = accepted.mode;
                next.link_credentials = accepted.link_credentials.clone();
                next.umask = accepted.umask;
                next.publication = accepted.publication.take();
            } else {
                pending.open = Some(accepted);
            }
        }
        *self = *pending;
    }
    pub(super) fn resume_walk(
        &mut self,
        v: &mut Vfs,
        walk: PathWalk,
        operation: PathOperation,
    ) -> Result<Option<FileValue>> {
        self.resume_walk_in(v, walk, operation, false)
    }
    pub(super) fn resume_walk_in(
        &mut self,
        v: &mut Vfs,
        walk: PathWalk,
        operation: PathOperation,
        native: bool,
    ) -> Result<Option<FileValue>> {
        if v.query
            .as_ref()
            .is_some_and(|query| query.joined_owner && !query.original)
        {
            v.with_original_resources(None, |v| {
                self.resume_original_walk(v, walk, operation, native, false)
            })
            .0
        } else {
            self.resume_original_walk(v, walk, operation, native, false)
        }
    }
    pub(super) fn resume_walk_permission(
        &mut self,
        v: &mut Vfs,
        walk: PathWalk,
        operation: PathOperation,
        native: bool,
    ) -> Result<Option<FileValue>> {
        if v.query
            .as_ref()
            .is_some_and(|q| q.joined_owner && !q.original)
        {
            v.with_original_resources(None, |v| {
                self.resume_original_walk(v, walk, operation, native, true)
            })
            .0
        } else {
            self.resume_original_walk(v, walk, operation, native, true)
        }
    }
    fn resume_original_walk(
        &mut self,
        v: &mut Vfs,
        mut walk: PathWalk,
        operation: PathOperation,
        native: bool,
        permission_checked: bool,
    ) -> Result<Option<FileValue>> {
        // access(2) may have selected real IDs, while the retained FileWork
        // control view has the caller's ordinary credentials. Keep the exact
        // accepted authority through traversal and the final operation.
        let credentials = *walk
            .credentials
            .take()
            .expect("accepted pathname credentials");
        let previous = std::mem::replace(&mut v.credentials, credentials);
        let restore = RestoreCredentials { view: v, previous };
        let v = &mut *restore.view;
        let result = {
            v.query.as_ref().unwrap().clear_deferred();
            let resolved = v.resolve_walk_permission(
                walk,
                Some(ResolveOperation::ResumeFuse(operation, native)),
                permission_checked,
            );
            let result = resolved.and_then(|entry| self.finish_entry(v, entry, operation, native));
            self.take_resolution(v, result)
        };
        result
    }
    pub(super) fn resume_entry(
        &mut self,
        v: &mut Vfs,
        entry: ResolvedEntry,
        operation: PathOperation,
        credentials: Credentials,
    ) -> Result<Option<FileValue>> {
        if v.query
            .as_ref()
            .is_some_and(|query| query.joined_owner && !query.original)
        {
            v.with_original_resources(None, |v| {
                self.resume_original_entry(v, entry, operation, credentials)
            })
            .0
        } else {
            self.resume_original_entry(v, entry, operation, credentials)
        }
    }
    fn resume_original_entry(
        &mut self,
        v: &mut Vfs,
        entry: ResolvedEntry,
        operation: PathOperation,
        credentials: Credentials,
    ) -> Result<Option<FileValue>> {
        let previous = std::mem::replace(&mut v.credentials, credentials);
        let restore = RestoreCredentials { view: v, previous };
        let v = &mut *restore.view;
        v.query.as_ref().unwrap().clear_deferred();
        let result = self.finish_entry(v, entry, operation, true);
        self.take_resolution(v, result)
    }
    fn finish_entry(
        &mut self,
        v: &mut Vfs,
        entry: ResolvedEntry,
        operation: PathOperation,
        native: bool,
    ) -> Result<Option<FileValue>> {
        if !native && v.entry_native_work(&entry) {
            let mount = match &entry.1 {
                Some(ResolvedTarget::Descriptor(open)) => {
                    v.mount_for_path(open.borrow().mount.as_ref())
                }
                Some(ResolvedTarget::Inode(file)) => file.mount.clone(),
                None => entry.0.mount.clone(),
            };
            self._usage = mount
                .as_ref()
                .map(|mount| mounts::MountUse::new(mount.identity.clone()));
            self.reference = None;
            self.kind =
                ResultKind::NativeEntry(Box::new((entry, operation, v.credentials.clone())));
            return Ok(None);
        }
        let result = match operation {
            PathOperation::ResolveEntry => {
                self.resolved_entry = Some(Box::new(entry));
                Ok(FileValue::Count(0))
            }
            PathOperation::ResolveDirectory => {
                let directory = v.directory_resolved(entry)?;
                self.resolved = Some(Box::new(directory));
                Ok(FileValue::Count(0))
            }
            PathOperation::Stat => v.stat_resolved(entry).map(|(stat, mount)| {
                FileValue::FuseStat(v.credentials.user_namespace.stat(stat), mount)
            }),
            PathOperation::Statfs => v
                .statfs_resolved(entry)
                .map(|stat| FileValue::Bytes(stat.to_vec())),
            PathOperation::Readlink => v.readlink_resolved(&entry.0).map(FileValue::Bytes),
            PathOperation::Access(mode) => {
                v.access_resolved(entry, mode).map(|()| FileValue::Count(0))
            }
            PathOperation::Chroot => v
                .change_directory_resolved(entry, true)
                .map(|()| FileValue::Count(0)),
            PathOperation::Chdir => v.chdir_resolved(entry).map(|()| FileValue::Count(0)),
            PathOperation::Truncate(length) => v
                .prepare_path_truncate(entry, length)
                .map(|_| FileValue::Count(0)),
            PathOperation::Open(flags) => {
                let mut plan = self.open.take().expect("accepted open reservation");
                // The retained final entry and reservation cross the
                // cold admission boundary; no pathname is looked up again.
                let open = |v: &mut Vfs| {
                    v.open_resolved::<false>(
                        entry,
                        flags,
                        plan.mode & 0o7777,
                        plan.publication.as_ref(),
                        plan.slot.take().unwrap(),
                    )
                };
                let result = if v.query.as_ref().unwrap().original {
                    open(v)
                } else {
                    v.with_original_resources(None, open).0
                };
                result.map(|fd| FileValue::Count(fd as u64))
            }
        };
        result.map(Some)
    }
    pub(super) fn take_resolution(
        &mut self,
        v: &Vfs,
        result: Result<Option<FileValue>>,
    ) -> Result<Option<FileValue>> {
        let query = v.query.as_ref().unwrap();
        if let Some(continuation) = query.prepared.borrow_mut().owner_continuation.take() {
            self._usage = continuation
                .0
                .current
                .mount
                .as_ref()
                .map(|mount| mounts::MountUse::new(mount.identity.clone()));
            self.reference = None;
            self.kind = ResultKind::OwnerWalk(continuation);
            return Ok(None);
        }
        if let Some(continuation) = query.prepared.borrow_mut().continuation.take() {
            self._usage = continuation
                .0
                .current
                .mount
                .as_ref()
                .map(|mount| mounts::MountUse::new(mount.identity.clone()));
            self.reference = None;
            self.kind = ResultKind::NativeWalk(continuation);
            return Ok(None);
        }
        let pending = query.prepared.borrow_mut().fuse.take();
        if let Some(pending) = pending {
            self.adopt_walk_request(pending);
            Ok(None)
        } else {
            result
        }
    }
    pub(super) fn follow_link(
        &mut self,
        v: &mut Vfs,
        mut target: Vec<u8>,
    ) -> Result<Option<FileValue>> {
        let ResultKind::FollowLink(link) = std::mem::replace(&mut self.kind, ResultKind::Readlink)
        else {
            unreachable!()
        };
        if target.len() >= MAX_PATH {
            return Err(Errno(5));
        }
        if let Some(end) = target.iter().position(|byte| *byte == 0) {
            target.truncate(end);
        }
        let Link {
            mut walk,
            base,
            operation,
        } = *link;
        if walk.policy & 4 != 0 {
            return Err(Errno(40));
        }
        if walk.policy & 8 != 0 && target.starts_with(b"/") {
            return Err(Errno(18));
        }
        walk.links += 1;
        if walk.links > 40 {
            return Err(Errno(40));
        }
        walk.current = if target.starts_with(b"/") {
            Vfs::check_resolve_mount(&walk.current, &walk.root, walk.policy)?;
            walk.root.clone()
        } else {
            base
        };
        let mut parts: VecDeque<_> = target
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        if target.ends_with(b"/") {
            parts.push_back(b".".to_vec());
        }
        parts.append(&mut walk.parts);
        if parts.iter().map(|part| part.len() + 1).sum::<usize>() >= MAX_PATH {
            return Err(Errno(36));
        }
        walk.parts = parts;
        self.resume_walk(v, walk, operation)
    }
}
