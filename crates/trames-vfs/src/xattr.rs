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
            n.edit_caps(caps, flags)?;
            n.times[2] = storage::Timestamp::now();
            drop(n);
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
