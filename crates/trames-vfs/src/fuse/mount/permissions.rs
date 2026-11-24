// SPDX-License-Identifier: GPL-3.0-or-later
//! Local FUSE mode checks retain the original inode while refreshing attributes.
use super::*;

#[derive(Default)]
pub(super) struct Validity(std::sync::atomic::AtomicU64);
fn now() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64
        + 1
}
impl Validity {
    fn fresh(&self) -> bool {
        now() < self.0.load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, seconds: u64, nanos: u32) {
        let span = seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(nanos as u64);
        self.0.store(now().saturating_add(span), Ordering::Relaxed);
    }
}
impl Mounted {
    pub(super) fn invalidate_permission_attr(&self, node: &NodeRef) {
        self.validity(node).0.store(0, Ordering::Relaxed);
    }
    fn validity<'a>(&self, node: &'a NodeRef) -> &'a Validity {
        node.fuse_leaf
            .get()
            .map(|n| &n.attr.validity)
            .or_else(|| node.fuse_directory.get().map(|n| &n.attr.validity))
            .expect("FUSE inode")
    }
    pub(super) fn permission_attr_fresh(&self, node: &NodeRef) -> bool {
        self.validity(node).fresh()
    }
    pub(crate) fn permission_refresh(&self, node: &NodeRef, c: &Credentials, mask: u32) -> bool {
        !self.connection.initialized()
            || !self.validity(node).fresh()
            || self.permission_result(node, c, mask) != Ok(Some(true))
    }
    pub(super) fn refresh_permission_attr(
        &self,
        node: &NodeRef,
        bytes: &mut [u8],
        version: u64,
        set: bool,
    ) -> Result<()> {
        if bytes.len() != 104 {
            return Err(Errno(5));
        }
        let valid = (
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
        );
        self.refresh_inode_at(
            node,
            &mut bytes[16..],
            version,
            valid,
            if set {
                inode::Update::Set
            } else {
                inode::Update::Read
            },
        )
    }
}
pub(super) enum After {
    Search(Box<(PathWalk, PathOperation, bool)>),
    Open(u32),
    Access {
        mask: u32,
        flags: Arc<mounts::MountFlags>,
        kind: u32,
    },
    Change {
        change: directory::Change,
        root: bool,
    },
}
pub(super) struct Permission {
    check: posix::Check,
    caller: Caller,
    after: After,
}
impl Metadata {
    fn permission_metadata(
        v: &Vfs,
        mount: &mounts::MountData,
        reference: LookupRef,
        check: posix::Check,
        after: After,
    ) -> Result<Self> {
        let fs = reference.fs.clone();
        let caller = fs.caller(v);
        let mut p = Permission {
            check,
            caller,
            after,
        };
        let request = p.check.next(&fs, caller)?;
        Ok(Self {
            request,
            reference: Some(reference),
            kind: ResultKind::Permission(Box::new(p)),
            _usage: Some(mounts::MountUse::new(mount.identity.clone())),
            resolved: None,
            resolved_entry: None,
            open: None,
            mount: StatMount::mounted(mount.id, false),
            dev: mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
        })
    }
    pub(super) fn local_access(
        v: &Vfs,
        mount: &mounts::MountData,
        reference: LookupRef,
        mask: u32,
        kind: u32,
    ) -> Result<Option<Self>> {
        reference.fs.check(&v.credentials)?;
        if mask & 1 != 0 && kind == 0o100000 && mount.flags.get() & mounts::MS_NOEXEC != 0 {
            return Err(Errno(13));
        }
        let node = reference
            .leaf
            .as_ref()
            .or(reference.directory.as_ref())
            .unwrap()
            .clone();
        if !reference.fs.permission_refresh(&node, &v.credentials, mask) {
            Self::access_write(&mount.flags, mask, kind)?;
            return Ok(None);
        }
        Self::permission_metadata(
            v,
            mount,
            reference,
            posix::Check::new(node, v.credentials.clone(), mask),
            After::Access {
                mask,
                flags: mount.flags.clone(),
                kind,
            },
        )
        .map(Some)
    }
    pub(crate) fn search_permission(
        v: &Vfs,
        mount: &mounts::MountData,
        fs: &Arc<Mounted>,
        node: NodeRef,
        walk: PathWalk,
        operation: PathOperation,
        native: bool,
    ) -> Result<Self> {
        if !fs.connection.initialized() {
            let mut pending = Self::continuation(v, Box::new((walk, operation)), false);
            let ResultKind::NativeWalk(walk) = pending.kind else {
                unreachable!()
            };
            pending.kind = ResultKind::InitWalk(walk, fs.clone(), native);
            pending._usage = Some(mounts::MountUse::new(mount.identity.clone()));
            return Ok(pending);
        }
        Self::permission_metadata(
            v,
            mount,
            LookupRef::retained(fs, node.clone()),
            posix::Check::new(node, v.credentials.clone(), 1),
            After::Search(Box::new((walk, operation, native))),
        )
    }
    pub(super) fn begin_permission(
        &mut self,
        v: &mut Vfs,
        credentials: Credentials,
        mask: u32,
        after: After,
    ) -> Result<Option<FileValue>> {
        let reference = self.reference.as_ref().unwrap();
        let node = reference
            .leaf
            .as_ref()
            .or(reference.directory.as_ref())
            .unwrap()
            .clone();
        let mut p = Permission {
            check: posix::Check::new(node, credentials, mask),
            caller: reference.fs.caller(v),
            after,
        };
        let Some(request) = p.check.next(&reference.fs, p.caller)? else {
            return self.finish_permission(v, p);
        };
        self.request = Some(request);
        self.kind = ResultKind::Permission(Box::new(p));
        Ok(None)
    }
    pub(super) fn advance_permission(
        &mut self,
        v: &mut Vfs,
        result: Option<Result<Vec<u8>>>,
    ) -> Result<Option<FileValue>> {
        let ResultKind::Permission(mut p) = std::mem::replace(&mut self.kind, ResultKind::Readlink)
        else {
            unreachable!()
        };
        let fs = &self.reference.as_ref().unwrap().fs;
        if let Some(result) = result {
            p.check.accept(fs, result)?;
        }
        if let Some(request) = p.check.next(fs, p.caller)? {
            self.request = Some(request);
            self.kind = ResultKind::Permission(p);
            return Ok(None);
        }
        self.request = None;
        self.finish_permission(v, *p)
    }
    fn finish_permission(&mut self, v: &mut Vfs, p: Permission) -> Result<Option<FileValue>> {
        match p.after {
            After::Search(walk) => {
                let (walk, operation, native) = *walk;
                self.resume_walk_permission(v, walk, operation, native)
            }
            After::Access { mask, flags, kind } => {
                Self::access_write(&flags, mask, kind)?;
                Ok(Some(FileValue::Count(0)))
            }
            After::Change { change, root } => Ok(Some(change.publish(p.check.node.clone(), root))),
            After::Open(flags) => {
                let reference = self.reference.as_ref().unwrap();
                let flags_ref = self.open.as_ref().unwrap().mount.flags.clone();
                let attr = reference
                    .leaf
                    .as_ref()
                    .and_then(|n| n.fuse_leaf.get().map(|f| f.attr.clone()))
                    .or_else(|| {
                        reference
                            .directory
                            .as_ref()?
                            .fuse_directory
                            .get()
                            .map(|f| f.attr.clone())
                    })
                    .unwrap();
                let bytes = **attr.lock().unwrap();
                self.begin_open_checked(v, &flags_ref, flags, &bytes, true)
            }
        }
    }
}
