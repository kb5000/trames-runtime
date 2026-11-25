// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded pathname revalidation, separate from resuming an accepted request.
use super::*;

pub(crate) struct PathRetry {
    dirfd: i32,
    path: Vec<u8>,
    explicit: Option<Descriptor>,
    credentials: Credentials,
    follow: bool,
    retain_magic: bool,
    policy: u64,
    stop_magic: bool,
    operation: PathOperation,
    lookup_done: bool,
    lookup_retried: bool,
    call_retried: bool,
    native_restart: bool,
}
impl PathRetry {
    pub(super) fn looked_up(&mut self) {
        self.lookup_done = true;
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn arm(
        v: &Vfs,
        dirfd: i32,
        path: &[u8],
        follow: bool,
        retain_magic: bool,
        policy: u64,
        stop_magic: bool,
        operation: PathOperation,
        accepted: Option<&Descriptor>,
        lookup_done: bool,
    ) {
        let Some(query) = &v.query else { return };
        let mut prepared = query.prepared.borrow_mut();
        if let Some(pending) = &mut prepared.fuse {
            if !pending.retry_armed() {
                let mut retry = Self::capture(
                    v,
                    dirfd,
                    path,
                    follow,
                    retain_magic,
                    policy,
                    stop_magic,
                    operation,
                    accepted,
                );
                retry.lookup_done = lookup_done;
                pending.arm_retry(retry);
            }
        } else {
            let crate::path_queries::PreparedPath {
                owner_continuation,
                continuation,
                ..
            } = &mut *prepared;
            if let Some((walk, _)) = owner_continuation
                .as_deref_mut()
                .or(continuation.as_deref_mut())
            {
                if walk.retry.is_none() {
                    let mut retry = Self::capture(
                        v,
                        dirfd,
                        path,
                        follow,
                        retain_magic,
                        policy,
                        stop_magic,
                        operation,
                        accepted,
                    );
                    retry.lookup_done = lookup_done;
                    walk.retry = Some(retry);
                }
            }
        }
    }
    #[allow(clippy::too_many_arguments)] // The original pathname lookup operands.
    pub(crate) fn capture(
        v: &Vfs,
        dirfd: i32,
        path: &[u8],
        follow: bool,
        retain_magic: bool,
        policy: u64,
        stop_magic: bool,
        operation: PathOperation,
        accepted: Option<&Descriptor>,
    ) -> Box<Self> {
        // Explicit root/fixed-file aliases remain capabilities. An ordinary
        // numeric dirfd is looked up anew only at the native ESTALE boundary.
        let explicit = accepted.cloned().or_else(|| {
            let query = v.query.as_ref()?;
            query
                .retained
                .as_ref()
                .filter(|(fd, _)| *fd == dirfd as u32)
                .map(|(_, file)| file.0.clone())
                .or_else(|| {
                    query
                        .peer
                        .as_ref()
                        .filter(|(fd, _)| *fd == dirfd as u32)
                        .map(|(_, file)| Descriptor {
                            open: OpenHandle::Shared(file.open.clone()),
                            cloexec: false.into(),
                        })
                })
                .or_else(|| {
                    // fd_pair uses private role numbers outside the guest FD
                    // range. They name admitted OFDs, not live numeric slots.
                    if (dirfd as u32) < MAX_FDS {
                        return None;
                    }
                    let file = query
                        .accepted
                        .as_ref()?
                        .get(&(dirfd as u32))?
                        .as_ref()?
                        .as_ref()
                        .ok()?;
                    Some(Descriptor {
                        open: OpenHandle::Shared(file.open.clone()),
                        cloexec: false.into(),
                    })
                })
        });
        Box::new(Self {
            dirfd,
            path: path.to_vec(),
            explicit,
            credentials: v.credentials.clone(),
            follow,
            retain_magic,
            policy,
            stop_magic,
            operation,
            lookup_done: false,
            lookup_retried: false,
            call_retried: false,
            native_restart: false,
        })
    }
    pub(super) fn parent(&mut self) {
        while self.path.last() == Some(&b'/') {
            self.path.pop();
        }
        if let Some(slash) = self.path.iter().rposition(|byte| *byte == b'/') {
            self.path.truncate(slash + 1);
        } else {
            self.path = b".".to_vec();
        }
        self.follow = true;
        self.retain_magic = true;
        self.stop_magic = false;
        self.operation = PathOperation::ResolveDirectory;
    }
    fn admit(&mut self) -> bool {
        if matches!(self.operation, PathOperation::Open(_)) {
            if self.call_retried {
                return false;
            }
            self.call_retried = true;
        } else if !self.lookup_done && !self.lookup_retried {
            self.lookup_retried = true;
        } else if !self.call_retried
            && (self.lookup_done || matches!(self.operation, PathOperation::Truncate(_)))
            && !matches!(
                self.operation,
                PathOperation::ResolveEntry | PathOperation::ResolveDirectory
            )
        {
            self.call_retried = true;
            self.lookup_retried = false;
        } else {
            return false;
        }
        self.lookup_done = false;
        true
    }
    fn start(&self, v: &mut Vfs) -> Result<PathWalk> {
        struct Restore<'a> {
            v: &'a mut Vfs,
            original: bool,
            credentials: Credentials,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.v.query.as_mut().unwrap().original = self.original;
                std::mem::swap(&mut self.v.credentials, &mut self.credentials);
            }
        }
        let original = std::mem::replace(&mut v.query.as_mut().unwrap().original, true);
        let credentials = std::mem::replace(&mut v.credentials, self.credentials.clone());
        let scope = Restore {
            v,
            original,
            credentials,
        };
        // Start from the live namespace's original mount objects. root/cwd and
        // the mount registry retain those same capabilities; a new projection
        // would give them different topology identities and miss child mounts.
        if let Some(namespace) = scope.v.mounts.as_ref().and_then(MountNamespace::original) {
            scope.v.mounts = Some(namespace);
        }
        let mut walk = scope.v.start_path_walk(
            self.dirfd,
            &self.path,
            self.follow,
            self.retain_magic,
            self.policy,
            self.stop_magic,
            self.explicit.as_ref(),
        )?;
        walk.credentials = Some(Box::new(self.credentials.clone()));
        Ok(walk)
    }
}
impl PathPlan {
    pub(crate) fn arm_retry(&mut self, retry: impl FnOnce() -> Box<PathRetry>) {
        if let Some(walk) = &mut self.walk {
            if walk.retry.is_none() {
                walk.retry = Some(retry());
            }
        }
    }
}
impl Metadata {
    pub(crate) fn arm_retry(&mut self, retry: Box<PathRetry>) {
        if self.retry.is_none() {
            self.retry = Some(retry);
        }
    }
    pub(crate) fn retry_armed(&self) -> bool {
        self.retry.is_some()
    }
    pub(crate) fn native_stale(&mut self, slot: Option<fd_table::ReservedFd>) -> bool {
        let Some(retry) = &mut self.retry else {
            return false;
        };
        if !retry.admit() {
            return false;
        }
        retry.native_restart = true;
        if let Some(open) = &mut self.open {
            open.slot = Some(slot.expect("native open retains its original reservation"));
        }
        self.request = None;
        self.kind = ResultKind::Readlink;
        true
    }
    pub(crate) fn namespace_stale_retry(&self) -> bool {
        // A complete pathname walk has already consumed its own inner budget.
        // NamespaceWork owns only the outer syscall retry after final lookup.
        self.retry.is_none()
            && match &self.kind {
                ResultKind::Mutation(mutation) => mutation.stale_retry(),
                _ => true,
            }
    }
    pub(super) fn adopt(&mut self, mut next: Self) {
        if self.retry.is_some() {
            next.retry = self.retry.take();
        }
        *self = next;
    }
    pub(crate) fn take(&mut self, v: &mut Vfs) -> Option<Result<FileValue>> {
        let restart = self
            .retry
            .as_mut()
            .is_some_and(|retry| std::mem::take(&mut retry.native_restart));
        let mut result = if restart {
            self.restart_path(v).transpose()
        } else {
            self.take_once(v)
        };
        while matches!(result, Some(Err(Errno(116)))) {
            let Some(retry) = self.retry.as_mut() else {
                return result;
            };
            if !retry.admit() {
                return result;
            }
            result = self.restart_path(v).transpose();
        }
        result
    }
    fn restart_path(&mut self, v: &mut Vfs) -> Result<Option<FileValue>> {
        let retry = self.retry.take().expect("original pathname revalidation");
        let operation = retry.operation;
        // Balance the failed lookup/open and its guards before a new lookup.
        // The syscall's unused FD reservation survives an open retry.
        self.request = None;
        self.kind = ResultKind::Readlink;
        self.reference = None;
        self.resolved = None;
        self.resolved_entry = None;
        self._usage = None;
        if let Some(open) = &mut self.open {
            open.writer = None;
            open.sticky_parent = None;
            open.created = false;
        }
        let walk = retry.start(v);
        self.retry = Some(retry);
        self.resume_walk(v, walk?, operation)
    }
}
