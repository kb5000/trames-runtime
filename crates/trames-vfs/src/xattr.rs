// SPDX-License-Identifier: GPL-3.0-or-later
//! Persistent inode attributes, including the original guest POSIX ACL policy.
use super::*;
type AttributeNode = (NodeRef, FsHandle);
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
        write: bool,
    ) -> Result<AttributeNode> {
        if let Some(path) = path {
            let at = self.resolve_final(fd, path, follow)?;
            #[cfg(all(feature = "hostfs", unix))]
            if at.filesystem(self).host.is_some() {
                return Err(Errno(95));
            }
            if write {
                at.writable()?;
            }
            Ok((self.node(&at)?, at.filesystem(self)))
        } else {
            let open_descriptor = self.descriptor(fd as u32)?;
            let open = open_descriptor.open.borrow();
            #[cfg(all(feature = "hostfs", unix))]
            if open.mount.as_ref().is_some_and(|m| m.fs.host.is_some()) {
                return Err(Errno(95));
            }
            if open.flags.get() & O_PATH != 0 {
                return Err(Errno(9));
            }
            if write
                && open
                    .mount
                    .as_ref()
                    .is_some_and(|m| m.flags.get() & mounts::MS_RDONLY != 0)
            {
                return Err(Errno(30));
            }
            Ok((
                open.node.clone().ok_or(Errno(95))?,
                open.mount
                    .as_ref()
                    .map_or_else(|| self.fs.clone(), |m| m.fs.clone()),
            ))
        }
    }
    fn xattr_allowed(&self, node: &Node, name: &[u8], write: bool) -> Result<()> {
        if name.is_empty() {
            return Err(Errno(34));
        }
        if name.contains(&0) {
            return Err(Errno(22));
        }
        if name.len() > 255 {
            return Err(Errno(34));
        }
        if name == file_caps::NAME {
            if write
                && !self
                    .credentials
                    .inode_cap(capabilities::SETFCAP, node.uid, node.gid)
            {
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
                && self.credentials.fsuid != node.uid
                && !self
                    .credentials
                    .inode_cap(capabilities::FOWNER, node.uid, node.gid)
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
            if !self.allowed(node, if write { 2 } else { 4 }) {
                return Err(Errno(13));
            }
            if write
                && matches!(node.content, Content::Directory)
                && node.mode & 0o1000 != 0
                && self.credentials.fsuid != node.uid
                && !self
                    .credentials
                    .inode_cap(capabilities::FOWNER, node.uid, node.gid)
            {
                return Err(Errno(1));
            }
            return Ok(());
        }
        if !write && (name.starts_with(b"security.") || name.starts_with(b"system.")) {
            // Unimplemented security/system policies report absence.
            return Err(Errno(61));
        }
        if !write && !self.allowed(node, 4) {
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
        let (node, _) = self.xattr_node(fd, path, follow, false)?;
        let n = node.borrow();
        self.xattr_allowed(&n, name, false)?;
        if name == file_caps::NAME {
            return n
                .file_caps()
                .ok_or(Errno(61))?
                .encode(&self.credentials.user_namespace);
        }
        n.xattrs.get(name).cloned().ok_or(Errno(61))
    }
    pub fn list_xattrs(&self, fd: i32, path: Option<&[u8]>, follow: bool) -> Result<Vec<u8>> {
        let (node, _) = self.xattr_node(fd, path, follow, false)?;
        let n = node.borrow();
        let mut names: Vec<u8> = n
            .xattrs
            .keys()
            .filter(|name| {
                !name.starts_with(b"trusted.") || self.credentials.has_cap(capabilities::SYS_ADMIN)
            })
            .flat_map(|k| k.iter().copied().chain([0]))
            .collect();
        if n.file_caps().is_some() {
            names.extend(file_caps::NAME);
            names.push(0);
        }
        Ok(names)
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
        let (node, fs) = self.xattr_node(fd, path, follow, true)?;
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
        self.xattr_allowed(&n, name, true)?;
        if name == file_caps::NAME {
            let caps = value
                .map(|bytes| file_caps::FileCaps::parse(bytes, &self.credentials.user_namespace))
                .transpose()?;
            n.edit_caps(caps, flags)?;
            n.times[2] = storage::Timestamp::now();
            drop(n);
            inotify::notify(&node, inotify::ATTRIB, None);
            return Ok(());
        }
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
                && !self
                    .credentials
                    .inode_cap(capabilities::FSETID, n.uid, n.gid)
                && !self.credentials.in_group(n.gid)
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
