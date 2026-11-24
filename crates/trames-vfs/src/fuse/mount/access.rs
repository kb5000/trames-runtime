// SPDX-License-Identifier: GPL-3.0-or-later
//! Access uses the final inode, including one returned by a proc magic link.
use super::*;

pub(super) struct Access {
    fs: Arc<Mounted>,
    flags: Arc<mounts::MountFlags>,
    mask: u32,
    kind: u32,
}
impl Access {
    pub(super) fn new(
        fs: Arc<Mounted>,
        flags: Arc<mounts::MountFlags>,
        mask: u32,
        kind: u32,
    ) -> Self {
        Self {
            fs,
            flags,
            mask,
            kind,
        }
    }
    pub(super) fn finish(&self, result: Result<Vec<u8>>) -> Result<FileValue> {
        match result {
            Ok(bytes) if bytes.is_empty() => {}
            Ok(_) => return Err(Errno(5)),
            Err(Errno(38)) => self.fs.access_unsupported.store(true, Ordering::Relaxed),
            Err(error) => return Err(error),
        }
        Metadata::access_write(&self.flags, self.mask, self.kind)?;
        Ok(FileValue::Count(0))
    }
}

impl Metadata {
    pub(super) fn access_write(flags: &mounts::MountFlags, mask: u32, kind: u32) -> Result<()> {
        if mask & 2 != 0
            && !matches!(kind, 0o010000 | 0o020000 | 0o060000 | 0o140000)
            && flags.get() & mounts::MS_RDONLY != 0
        {
            return Err(Errno(30));
        }
        Ok(())
    }
    pub(super) fn access_needed(
        v: &Vfs,
        flags: &mounts::MountFlags,
        fs: &Mounted,
        mask: u32,
        kind: u32,
    ) -> Result<bool> {
        fs.check(&v.credentials)?;
        if mask & 1 != 0 && kind == 0o100000 && flags.get() & mounts::MS_NOEXEC != 0 {
            return Err(Errno(13));
        }
        // Linux passes MAY_ACCESS even for F_OK; its wire mask is then zero.
        if fs.access_unsupported.load(Ordering::Relaxed) {
            Self::access_write(flags, mask, kind)?;
            Ok(false)
        } else {
            Ok(true)
        }
    }
    pub(crate) fn access_inode(
        v: &Vfs,
        mount: &mounts::MountData,
        fs: &Arc<Mounted>,
        node: NodeRef,
        mask: u32,
    ) -> Result<Option<Self>> {
        let reference = LookupRef::retained(fs, node);
        let kind = reference
            .leaf
            .as_ref()
            .map_or(0o040000, |node| node.borrow().mode & 0o170000);
        Self::access_reference(v, mount, reference, mask, kind)
    }
    pub(crate) fn access_file(v: &Vfs, file: &Arc<File>, mask: u32) -> Result<Option<Self>> {
        file.attr.check()?;
        let kind =
            u32::from_le_bytes(file.attr.lock().unwrap()[60..64].try_into().unwrap()) & 0o170000;
        Self::access_reference(v, &file.mount, file.reference.clone(), mask, kind)
    }
    fn access_reference(
        v: &Vfs,
        mount: &mounts::MountData,
        reference: LookupRef,
        mask: u32,
        kind: u32,
    ) -> Result<Option<Self>> {
        let fs = &reference.fs;
        if let Some(node) = reference.leaf.as_ref().or(reference.directory.as_ref()) {
            fs.check_inode(node)?;
        }
        if fs.local_permissions() {
            return Self::local_access(v, mount, reference, mask, kind);
        }
        if !Self::access_needed(v, &mount.flags, fs, mask, kind)? {
            return Ok(None);
        }
        let mut body = [0; 8];
        body[..4].copy_from_slice(&mask.to_le_bytes());
        Ok(Some(Self {
            request: Some(Arc::new(fs.connection.request(
                34,
                reference.node,
                fs.caller(v),
                &body,
            )?)),
            _usage: Some(mounts::MountUse::new(mount.identity.clone())),
            resolved: None,
            resolved_entry: None,
            open: None,
            kind: ResultKind::Access(Access::new(fs.clone(), mount.flags.clone(), mask, kind)),
            mount: StatMount::mounted(
                mount.id,
                reference
                    .directory
                    .as_ref()
                    .is_some_and(|node| Arc::ptr_eq(node, &mount.root)),
            ),
            dev: mount.device(),
            owner_ns: fs.namespace.clone(),
            reader_ns: v.credentials.user_namespace.clone(),
            reference: Some(reference),
        }))
    }
}
