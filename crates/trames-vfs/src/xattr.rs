// SPDX-License-Identifier: GPL-3.0-or-later
//! Persistent inode attributes, including the original guest POSIX ACL policy.
use super::*;
enum AttributeNode {
    Stored(NodeRef, FsHandle, Option<Arc<mounts::MountIdentity>>),
    #[cfg(all(feature = "hostfs", unix))]
    Host(hostfs::XattrTarget),
}
pub(super) const XATTR_BUDGET: usize = 1024 * 1024;
pub(super) fn trusted_attribute(name: &[u8]) -> bool {
    name.strip_prefix(b"trusted.")
        .is_some_and(|suffix| !suffix.is_empty())
}
pub(super) fn xattr_size(attrs: &BTreeMap<Vec<u8>, Vec<u8>>) -> usize {
    attrs.iter().map(|(k, v)| k.len() + 1 + v.len()).sum()
}

/// One accepted capability update owns its original inode and implicit mapped
/// writeback. A resource wait must not rerun already completed provider pages.
pub(super) struct CapabilitiesWork {
    node: NodeRef,
    filesystem: FsHandle,
    _mount: Option<mounts::MountUse>,
    caps: Option<file_caps::FileCaps>,
    flags: u32,
    prepared: bool,
    admitted: bool,
    synced: bool,
    sync: Option<mapped::DataSync>,
    lease: Option<trames_shared::FileTransactionLease>,
    publication: Option<CapabilityPublication>,
    rollback: Option<Errno>,
    notify: bool,
}
struct CapabilityPublication {
    old: Option<file_caps::FileCaps>,
    old_time: storage::Timestamp,
    time: storage::Timestamp,
}
impl CapabilitiesWork {
    pub(super) fn run(&mut self) -> Result<()> {
        let _namespace = self.filesystem.namespace.lock().unwrap();
        let _metadata = self.node.metadata.lock().unwrap();
        if !self.prepared {
            self.filesystem.prepare_metadata(&self.node)?;
            self.prepared = true;
        }
        if !self.admitted {
            let mut node = self.node.borrow_mut();
            let Content::File(data) = &mut node.content else {
                return Err(Errno(95));
            };
            self.lease = match data.begin_transaction()? {
                Ok(lease) => lease,
                Err(wait) => {
                    return Err(resource_io::memory_error(
                        trames_memory::PageWait::resource(wait).fault(0),
                    ))
                }
            };
            let old = node.file_caps();
            if old.is_some() && self.flags & 1 != 0 {
                return Err(Errno(17));
            }
            if old.is_none() && (self.caps.is_none() || self.flags & 2 != 0) {
                return Err(Errno(61));
            }
            self.admitted = true;
        }
        let _transaction = self.lease.as_ref().map(|lease| lease.enter());
        if let Some(error) = self.rollback {
            return self.restore(error);
        }
        if self.publication.is_none() {
            let node = self.node.borrow();
            let Content::File(data) = &node.content else {
                return Err(Errno(95));
            };
            if self.caps.is_some() && data.has_writable_mappings() {
                return Err(Errno(16));
            }
            if !self.synced {
                if self.caps.is_some() {
                    if self.sync.is_none() {
                        self.sync = mapped::DataSync::before_capabilities(data)?;
                    }
                    if let Some(sync) = &mut self.sync {
                        let _writeback = trames_shared::FileTransactionScope::writeback();
                        sync.run()?;
                    }
                }
                self.synced = true;
            }
            let old = node.file_caps();
            let old_time = node.times[2];
            node.edit_caps_after_sync(self.caps, self.flags)?;
            drop(node);
            let time = storage::Timestamp::now();
            self.node.borrow_mut().times[2] = time;
            self.publication = Some(CapabilityPublication {
                old,
                old_time,
                time,
            });
        }
        if let Err(error) = self.filesystem.checkpoint_metadata(&self.node) {
            if resource_io::waiting() {
                // The sidecar is already published. Keep that stage and its
                // original ctime; XATTR_CREATE/REPLACE must not execute again.
                return Err(error);
            }
            self.rollback = Some(error);
            return self.restore(error);
        }
        self.notify = true;
        Ok(())
    }
    fn restore(&self, error: Errno) -> Result<()> {
        let original = self
            .publication
            .as_ref()
            .expect("published capability rollback");
        let mut node = self.node.borrow_mut();
        // A real checkpoint failure keeps the old best-effort rollback, but
        // its sidecar write can itself wait. Preserve the original terminal
        // error while resuming that write under the same object transaction.
        let scope = resource_io::Scope::enter();
        let _ = node.edit_caps_after_sync(original.old, 0);
        let pending = scope.finish();
        if let Some(pending) = pending {
            return Err(resource_io::memory_error(pending.wait.fault(0)));
        }
        if node.times[2] == original.time {
            node.times[2] = original.old_time;
        }
        Err(error)
    }
    pub(super) fn notify(&mut self) {
        if let Some(sync) = &mut self.sync {
            sync.notify();
        }
        if std::mem::take(&mut self.notify) {
            inotify::notify(&self.node, inotify::ATTRIB, None);
        }
    }
}
impl Vfs {
    fn xattr_node(
        &self,
        fd: i32,
        path: Option<&[u8]>,
        follow: bool,
        call: fuse::XattrCall<'_>,
    ) -> Result<AttributeNode> {
        let write = matches!(call, fuse::XattrCall::Write { .. });
        if let Some(path) = path {
            let target = self.metadata_target(fd, path, follow)?;
            if !write {
                crate::output_resources::OutputScope::path(&target.path);
                crate::output_resources::OutputScope::retain(|| target.clone());
            }
            if let Some(mount) = target.path.mount.as_ref().filter(|m| m.fs.fuse.is_some()) {
                self.defer_fuse_xattr(
                    &mount.shared,
                    target.node.clone(),
                    None,
                    call,
                    self.event_link(&target.path, &target.node),
                )?;
                return Ok(AttributeNode::Stored(
                    target.node,
                    mount.fs.clone(),
                    Some(mount.identity.clone()),
                ));
            }
            let at = target.path;
            #[cfg(all(feature = "hostfs", unix))]
            if at.filesystem(self).host.is_some() {
                let file = target
                    ._magic
                    .as_ref()
                    .and_then(|m| {
                        m.host_file
                            .clone()
                            .or_else(|| m.file.as_ref()?.host_file.clone())
                    })
                    .or_else(|| at.host_position.as_ref()?.known_file())
                    .map_or_else(|| target.node.host.get().ok_or(Errno(95))?.pin_path(), Ok)?;
                let link = self.event_link(&at, &target.node);
                return hostfs::XattrTarget::new(
                    target.node,
                    file,
                    at.mount.as_ref().map(|m| m.shared.as_ref()),
                    link,
                    write,
                )
                .map(AttributeNode::Host);
            }
            if write {
                at.writable()?;
            }
            Ok(AttributeNode::Stored(
                target.node,
                at.filesystem(self),
                at.mount.as_ref().map(|m| m.identity.clone()),
            ))
        } else {
            let descriptor = self.descriptor(fd as u32)?;
            if !write {
                crate::output_resources::OutputScope::retain(|| descriptor.clone());
            }
            let open = descriptor.open.borrow();
            if open.flags.get() & O_PATH != 0 {
                return Err(Errno(9));
            }
            if let Some(mount) = open.mount.as_ref().filter(|m| m.fs.fuse.is_some()) {
                let file = match &open.control {
                    Some(events::SharedControl::FuseFile(file)) => Some(file.clone()),
                    _ => None,
                };
                let node = open
                    .node
                    .clone()
                    .or_else(|| file.as_ref()?.inode())
                    .ok_or(Errno(95))?;
                self.defer_fuse_xattr(
                    mount,
                    node.clone(),
                    file,
                    call,
                    open.notification.as_ref().and_then(|n| n.link.clone()),
                )?;
                return Ok(AttributeNode::Stored(
                    node,
                    mount.fs.clone(),
                    Some(mount.identity.clone()),
                ));
            }
            #[cfg(all(feature = "hostfs", unix))]
            if open.mount.as_ref().is_some_and(|m| m.fs.host.is_some()) {
                return hostfs::XattrTarget::new(
                    open.node.clone().ok_or(Errno(95))?,
                    open.host_file.clone().ok_or(Errno(95))?,
                    open.mount.as_deref(),
                    open.notification.as_ref().and_then(|n| n.link.clone()),
                    write,
                )
                .map(AttributeNode::Host);
            }
            if write
                && open
                    .mount
                    .as_ref()
                    .is_some_and(|m| m.flags.get() & mounts::MS_RDONLY != 0)
            {
                return Err(Errno(30));
            }
            Ok(AttributeNode::Stored(
                open.node.clone().ok_or(Errno(95))?,
                open.mount
                    .as_ref()
                    .map_or_else(|| self.fs.clone(), |m| m.fs.clone()),
                open.mount.as_ref().map(|m| m.identity.clone()),
            ))
        }
    }
    fn xattr_name(name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > 255 {
            return Err(Errno(34));
        }
        if name.contains(&0) {
            return Err(Errno(22));
        }
        Ok(())
    }
    #[cfg(all(feature = "hostfs", unix))]
    pub(super) fn xattr_allowed(&self, node: &Node, name: &[u8], write: bool) -> Result<()> {
        self.xattr_allowed_mapped(node, name, write, mounts::idmap::Ids::plain(&self.fs.owner))
    }
    fn xattr_allowed_mapped(
        &self,
        node: &Node,
        name: &[u8],
        write: bool,
        ids: mounts::idmap::Ids<'_>,
    ) -> Result<()> {
        let (uid, gid) = ids.owner(node.uid, node.gid);
        if write && (uid == u32::MAX || gid == u32::MAX) {
            return Err(Errno(1));
        }
        // Public get/set import and validate the name before resolving an inode.
        if name == file_caps::NAME {
            if write && !self.credentials.inode_cap(capabilities::SETFCAP, uid, gid) {
                return Err(Errno(1));
            }
            return Ok(());
        }
        if acl::name(name) {
            if matches!(node.content, Content::Symlink(_)) {
                return Err(Errno(95));
            }
            if name == acl::DEFAULT && !matches!(node.content, Content::Directory) {
                // Linux allows anyone to clear a non-directory's nonexistent
                // default ACL. set_xattr rejects a nonempty default below.
                return if write { Ok(()) } else { Err(Errno(61)) };
            }
            if write
                && self.credentials.fsuid != uid
                && !self.credentials.inode_cap(capabilities::FOWNER, uid, gid)
            {
                return Err(Errno(1));
            }
            return Ok(());
        }
        if name.starts_with(b"trusted.") {
            if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
                return Err(Errno(if write { 1 } else { 61 }));
            }
            if !trusted_attribute(name) {
                return Err(Errno(22));
            }
            return Ok(());
        }
        if name.starts_with(b"user.") && name.len() > 5 {
            if !matches!(node.content, Content::File(_) | Content::Directory) {
                return Err(Errno(if write { 1 } else { 61 }));
            }
            if !self
                .credentials
                .allows_mapped(node, if write { 2 } else { 4 }, ids)
            {
                return Err(Errno(13));
            }
            if write
                && matches!(node.content, Content::Directory)
                && node.mode & 0o1000 != 0
                && self.credentials.fsuid != uid
                && !self.credentials.inode_cap(capabilities::FOWNER, uid, gid)
            {
                return Err(Errno(1));
            }
            return Ok(());
        }
        if !write && (name.starts_with(b"security.") || name.starts_with(b"system.")) {
            // Unimplemented security/system policies report absence.
            return Err(Errno(61));
        }
        if !write && !self.credentials.allows_mapped(node, 4, ids) {
            return Err(Errno(13));
        }
        Err(Errno(95))
    }
    pub fn get_xattr(
        &self,
        fd: i32,
        path: Option<&[u8]>,
        follow: bool,
        name: &[u8],
    ) -> Result<Vec<u8>> {
        match self.read_xattrs(fd, path, follow, Some(name), 65536)? {
            FileValue::Bytes(bytes) => Ok(bytes),
            _ => unreachable!(),
        }
    }
    pub fn list_xattrs(&self, fd: i32, path: Option<&[u8]>, follow: bool) -> Result<Vec<u8>> {
        match self.read_xattrs(fd, path, follow, None, 65536)? {
            FileValue::Bytes(bytes) => Ok(bytes),
            _ => unreachable!(),
        }
    }
    pub(crate) fn read_xattrs(
        &self,
        fd: i32,
        path: Option<&[u8]>,
        follow: bool,
        name: Option<&[u8]>,
        capacity: u64,
    ) -> Result<FileValue> {
        if self.host_resources() {
            return self.host_file_work(self.path_queries().namespace_work(
                NamespaceCall::GetXattr {
                    fd,
                    path: path.map(<[u8]>::to_vec),
                    follow,
                    name: name.map(<[u8]>::to_vec),
                    capacity,
                },
            ));
        }
        if let Some(name) = name {
            Self::xattr_name(name)?;
        }
        let (node, fs, mount) =
            match self.xattr_node(fd, path, follow, fuse::XattrCall::Read { name, capacity })? {
                AttributeNode::Stored(node, fs, mount) => (node, fs, mount),
                #[cfg(all(feature = "hostfs", unix))]
                AttributeNode::Host(target) => {
                    let value = target.read(self, name, capacity);
                    crate::output_resources::OutputScope::retain(|| target);
                    return value;
                }
            };
        let n = node.borrow();
        let ids = mount.as_ref().map_or_else(
            || mounts::idmap::Ids::plain(&fs.owner),
            |m| mounts::idmap::Ids::from_mount(m),
        );
        let bytes = if let Some(name) = name {
            self.xattr_allowed_mapped(&n, name, false, ids)?;
            if name == file_caps::NAME {
                n.file_caps()
                    .ok_or(Errno(61))?
                    .mapped(ids)
                    .ok_or(Errno(61))?
                    .encode(&self.credentials.user_namespace)?
            } else {
                let mut value = n.xattrs.get(name).cloned().ok_or(Errno(61))?;
                if acl::name(name) {
                    acl::translate(&mut value, |group, id| {
                        Ok(self
                            .credentials
                            .user_namespace
                            .from_global(group, ids.visible(group, id))
                            .unwrap_or(u32::MAX))
                    })?;
                }
                value
            }
        } else {
            let mut names: Vec<u8> = n
                .xattrs
                .keys()
                .filter(|name| {
                    !name.starts_with(b"trusted.")
                        || self.credentials.has_cap(capabilities::SYS_ADMIN)
                })
                .flat_map(|k| k.iter().copied().chain([0]))
                .collect();
            if n.file_caps().is_some() {
                names.extend(file_caps::NAME);
                names.push(0);
            }
            names
        };
        if capacity == 0 {
            return Ok(FileValue::Count(bytes.len() as u64));
        }
        if bytes.len() as u64 > capacity.min(65536) {
            return Err(Errno(34));
        }
        Ok(FileValue::Bytes(bytes))
    }
    pub fn set_xattr(
        &mut self,
        fd: i32,
        path: Option<&[u8]>,
        follow: bool,
        name: &[u8],
        value: Option<&[u8]>,
        flags: u32,
    ) -> Result<()> {
        if self.host_resources() {
            return self.host_namespace_work(NamespaceCall::Xattr {
                fd,
                path: path.map(<[u8]>::to_vec),
                follow,
                name: name.to_vec(),
                value: value.map(<[u8]>::to_vec),
                flags,
            });
        }
        if flags & !3 != 0 {
            return Err(Errno(22));
        }
        if value.is_some_and(|v| v.len() > 65536) {
            return Err(Errno(7));
        }
        Self::xattr_name(name)?;
        let (node, fs, mount) = match self.xattr_node(
            fd,
            path,
            follow,
            fuse::XattrCall::Write { name, value, flags },
        )? {
            AttributeNode::Stored(node, fs, mount) => (node, fs, mount),
            #[cfg(all(feature = "hostfs", unix))]
            AttributeNode::Host(target) => return target.write(self, name, value, flags),
        };
        // A successful FUSE return here is a validated default-ACL no-op.
        // Real daemon requests return the internal deferred result above.
        if fs.fuse.is_some() {
            return Ok(());
        }
        // This original filesystem-wide attribute budget and its checkpoint
        // must commit/roll back together. No ordinary byte/metadata read uses
        // this namespace transaction guard.
        let _namespace = fs.namespace.lock().unwrap();
        let lower_acl_remove = name == acl::ACCESS
            && value.is_none()
            && fs
                .borrow()
                .overlay
                .as_ref()
                .is_some_and(|overlay| overlay.uncopied_inode(&node));
        let _metadata = node.metadata.lock().unwrap();
        if name.starts_with(b"user.") || trusted_attribute(name) {
            self.pseudo_metadata_mutable(&node)?;
        } else {
            self.pseudo_immutable(&node)?;
        }
        let mut n = node.borrow_mut();
        let ids = mount.as_ref().map_or_else(
            || mounts::idmap::Ids::plain(&fs.owner),
            |m| mounts::idmap::Ids::from_mount(m),
        );
        let (uid, gid) = ids.owner(n.uid, n.gid);
        if name == file_caps::NAME {
            if value.is_none() {
                self.xattr_allowed_mapped(&n, name, true, ids)?;
            }
            let caps = value
                .map(|bytes| file_caps::FileCaps::for_inode(bytes, &self.credentials, &n, ids))
                .transpose()?;
            let old = n.file_caps();
            let old_time = n.times[2];
            if old.is_some() && flags & 1 != 0 {
                return Err(Errno(17));
            }
            if old.is_none() && (caps.is_none() || flags & 2 != 0) {
                return Err(Errno(61));
            }
            drop(n);
            if let Some(query) = self.query.as_ref().filter(|query| query.metadata_call) {
                query.prepared.borrow_mut().capabilities = Some(Box::new(CapabilitiesWork {
                    node: node.clone(),
                    filesystem: fs.clone(),
                    _mount: mount
                        .as_ref()
                        .map(|mount| mounts::MountUse::new(mount.clone())),
                    caps,
                    flags,
                    prepared: false,
                    admitted: false,
                    synced: false,
                    lease: None,
                    sync: None,
                    publication: None,
                    rollback: None,
                    notify: false,
                }));
                return query.defer();
            }
            fs.prepare_metadata(&node)?;
            let mut n = node.borrow_mut();
            n.edit_caps(caps, flags)?;
            n.times[2] = storage::Timestamp::now();
            drop(n);
            if let Err(error) = fs.checkpoint_metadata(&node) {
                let mut n = node.borrow_mut();
                let _ = n.edit_caps(old, 0);
                n.times[2] = old_time;
                return Err(error);
            }
            inotify::notify(&node, inotify::ATTRIB, None);
            return Ok(());
        }
        self.xattr_allowed_mapped(&n, name, true, ids)?;
        let old = n.xattrs.get(name).cloned();
        if name == acl::ACCESS && value.is_none() && old.is_none() && lower_acl_remove {
            return Err(Errno(61));
        }
        if flags & 1 != 0 && old.is_some() {
            return Err(Errno(17));
        }
        if (flags & 2 != 0 || value.is_none() && !acl::name(name)) && old.is_none() {
            return Err(Errno(61));
        }
        let old_times = n.times;
        let old_mode = n.mode;
        let mut next = value
            .filter(|bytes| !acl::name(name) || !bytes.is_empty())
            .map(<[u8]>::to_vec);
        if acl::name(name) {
            if let Some(value) = &mut next {
                acl::validate(value)?;
                acl::translate(value, |group, id| {
                    ids.stored(group, self.credentials.mapped_id(group, id)?)
                        .map_err(|_| Errno(22))
                })?;
                acl::normalize(value);
                if value.len() == 4 {
                    next = None;
                } else if name == acl::DEFAULT && !matches!(n.content, Content::Directory) {
                    return Err(Errno(13));
                } else if name == acl::ACCESS {
                    n.mode = acl::mode(value, n.mode);
                    if !acl::extended(value) {
                        next = None;
                    }
                }
            }
            if name == acl::ACCESS
                && !self.credentials.inode_cap(capabilities::FSETID, uid, gid)
                && !self.credentials.in_group(gid)
            {
                n.mode &= !0o2000;
            }
            if name == acl::DEFAULT && !matches!(n.content, Content::Directory) && next.is_none() {
                // No metadata mutation or overlay copy-up for this no-op.
                return Ok(());
            }
        }
        if let Some(value) = next {
            n.xattrs.insert(name.to_vec(), value);
        } else {
            n.xattrs.remove(name);
        }
        let invalid = n.xattrs.len() > 128 || xattr_size(&n.xattrs) > 65536;
        n.times[2] = storage::Timestamp::now();
        drop(n);
        let used: usize = fs
            .borrow()
            .inodes
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(|n| xattr_size(&n.borrow().xattrs))
            .sum();
        let result = if invalid || used > XATTR_BUDGET {
            Err(Errno(28))
        } else if node.borrow().links != 0 {
            fs.borrow().checkpoint()
        } else {
            Ok(())
        };
        if let Err(e) = result {
            let mut n = node.borrow_mut();
            if let Some(old) = old {
                n.xattrs.insert(name.to_vec(), old);
            } else {
                n.xattrs.remove(name);
            }
            n.times = old_times;
            n.mode = old_mode;
            return Err(e);
        }
        inotify::notify(&node, inotify::ATTRIB, None);
        Ok(())
    }
}
