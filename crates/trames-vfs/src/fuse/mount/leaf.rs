// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical daemon leaf identity, independent of any particular open handle.
use super::*;

pub(crate) struct Leaf {
    pub(super) node: u64,
    pub(super) _lookup: Arc<LookupLease>,
    pub(super) attr: Arc<inode::Attr>,
    pub(super) acl: posix::Cache,
    cache: (std::sync::Weak<directory::Directories>, (u64, u64)),
}
impl Drop for Leaf {
    fn drop(&mut self) {
        if let Some(cache) = self.cache.0.upgrade() {
            let mut cache = cache.lock().unwrap();
            if cache
                .get(&self.cache.1)
                .is_some_and(|node| node.strong_count() == 0)
            {
                cache.remove(&self.cache.1);
            }
        }
    }
}
impl Mounted {
    pub(super) fn leaf_inode(
        &self,
        reference: &LookupRef,
        generation: u64,
        parent: &NodeRef,
        attr: &mut [u8],
        version: u64,
        valid: (u64, u32),
    ) -> Result<NodeRef> {
        inode::validate(attr)?;
        let retired;
        let mut inodes = self.directories.lock().unwrap();
        retired = self.retire_inodes(
            &mut inodes,
            reference.node,
            generation,
            u32::from_le_bytes(attr[60..64].try_into().unwrap()) & 0o170000,
        );
        let key = (reference.node, generation);
        if let Some(node) = inodes.get(&key).and_then(std::sync::Weak::upgrade) {
            drop(inodes);
            drop(retired);
            if node.fuse_leaf.get().is_none() {
                return Err(Errno(5));
            }
            self.refresh_inode_at(&node, attr, version, valid, inode::Update::Lookup)?;
            return Ok(node);
        }
        let cached_attr = self.fresh_attr(attr, valid)?;
        let word = |i| u32::from_le_bytes(attr[i..i + 4].try_into().unwrap());
        let node = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: Default::default(),
            whole_locks: Default::default(),
            notifications: Default::default(),
            path_hint: Default::default(),
            device: parent.borrow().device,
            content: Content::Fuse,
            mode: word(60) & 0o177777,
            uid: self
                .namespace
                .to_global(false, word(68))
                .unwrap_or(u32::MAX),
            gid: self.namespace.to_global(true, word(72)).unwrap_or(u32::MAX),
            volatile: false,
            inode: u64::from_le_bytes(attr[..8].try_into().unwrap()),
            links: word(64),
            times: inode::times(attr),
            seals: None,
            xattrs: BTreeMap::new(),
        }));
        let _ = node.fuse_leaf.set(Arc::new(Leaf {
            node: reference.node,
            _lookup: reference.lease.clone(),
            attr: cached_attr,
            acl: Default::default(),
            cache: (Arc::downgrade(&self.directories), key),
        }));
        inodes.insert(key, Arc::downgrade(&node));
        drop(inodes);
        drop(retired);
        Ok(node)
    }
}
impl File {
    pub(crate) fn inode(&self) -> Option<NodeRef> {
        self.reference
            .directory
            .clone()
            .or_else(|| self.reference.leaf.clone())
    }
}
