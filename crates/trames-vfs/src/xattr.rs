// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded inode attributes. File capabilities and ACLs require separate policy.
use super::*;
type AttributeNode = (NodeRef, FsHandle);
pub(super) const XATTR_BUDGET: usize = 1024 * 1024;
pub(super) fn overlay_attribute(name: &[u8]) -> bool {
    matches!(
        name,
        b"trusted.overlay.opaque" | b"trusted.overlay.whiteout"
    )
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
            if write {
                at.writable()?;
            }
            Ok((self.node(&at)?, at.filesystem(self)))
        } else {
            let open_descriptor = self.descriptor(fd as u32)?;
            let open = open_descriptor.open.borrow();
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
        if name.is_empty() || name.contains(&0) {
            return Err(Errno(22));
        }
        if name.len() > 255 {
            return Err(Errno(34));
        }
        if name.starts_with(b"trusted.") {
            if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
                return Err(Errno(if write { 1 } else { 61 }));
            }
            if overlay_attribute(name)
                && matches!(node.content, Content::File(_) | Content::Directory)
            {
                return Ok(());
            }
            return Err(Errno(if write { 95 } else { 61 }));
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
                && !self.credentials.has_cap(capabilities::FOWNER)
            {
                return Err(Errno(1));
            }
            return Ok(());
        }
        if !write && (name.starts_with(b"security.") || name.starts_with(b"system.")) {
            // These attributes cannot be installed: no file-capability or ACL
            // metadata exists. Queries report absence, not invented policies.
            return Err(Errno(61));
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
        n.xattrs.get(name).cloned().ok_or(Errno(61))
    }
    pub fn list_xattrs(&self, fd: i32, path: Option<&[u8]>, follow: bool) -> Result<Vec<u8>> {
        let (node, _) = self.xattr_node(fd, path, follow, false)?;
        let n = node.borrow();
        Ok(n.xattrs
            .keys()
            .filter(|name| {
                !name.starts_with(b"trusted.") || self.credentials.has_cap(capabilities::SYS_ADMIN)
            })
            .flat_map(|k| k.iter().copied().chain([0]))
            .collect())
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
        if flags & !3 != 0 || flags == 3 {
            return Err(Errno(22));
        }
        if value.is_some_and(|v| v.len() > 65536) {
            return Err(Errno(7));
        }
        let (node, fs) = self.xattr_node(fd, path, follow, true)?;
        self.pseudo_immutable(&node)?;
        let mut n = node.borrow_mut();
        self.xattr_allowed(&n, name, true)?;
        let old = n.xattrs.get(name).cloned();
        if flags & 1 != 0 && old.is_some() {
            return Err(Errno(17));
        }
        if (flags & 2 != 0 || value.is_none()) && old.is_none() {
            return Err(Errno(61));
        }
        let old_times = n.times;
        if let Some(value) = value {
            n.xattrs.insert(name.to_vec(), value.to_vec());
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
            return Err(e);
        }
        inotify::notify(&node, inotify::ATTRIB, None);
        Ok(())
    }
}
