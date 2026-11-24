// SPDX-License-Identifier: GPL-3.0-or-later
//! Directory identity retained by open descriptions and fs_struct paths.
//!
//! This is an inode identity table, not a pathname/attribute lookup cache:
//! new pathname components still go through the daemon. Weak entries do not
//! keep daemon lookup references alive after the last actual path user exits.
use super::*;

pub(super) type Directories = std::sync::Mutex<BTreeMap<(u64, u64), std::sync::Weak<Inode>>>;

pub(crate) struct Directory {
    pub(super) node: u64,
    pub(super) attr: Arc<inode::Attr>,
    pub(super) acl: posix::Cache,
    pub(super) _lookup: Arc<LookupLease>,
    pub(super) linked: std::sync::atomic::AtomicBool,
    pub(super) cache: Option<(std::sync::Weak<Directories>, (u64, u64))>,
    pub(super) location: std::sync::Mutex<Option<(NodeRef, Vec<u8>)>>,
}
impl Drop for Directory {
    fn drop(&mut self) {
        if let Some((cache, key)) = &self.cache {
            if let Some(cache) = cache.upgrade() {
                let mut cache = cache.lock().unwrap();
                // A concurrent lookup may already have installed a new inode
                // for this key after the old strong count reached zero.
                if cache.get(key).is_some_and(|node| node.strong_count() == 0) {
                    cache.remove(key);
                }
            }
        }
    }
}
impl Directory {
    pub(crate) fn linked(&self) -> bool {
        self.linked.load(Ordering::Relaxed)
    }
    pub(super) fn rename(&self, parent: NodeRef, name: Vec<u8>) {
        *self.location.lock().unwrap() = Some((parent, name));
    }
    pub(super) fn unlink(&self) {
        self.linked.store(false, Ordering::Relaxed);
    }
    pub(crate) fn id(&self) -> u64 {
        self.node
    }
    pub(super) fn descendant_of(&self, ancestor: u64) -> bool {
        if self.node == ancestor {
            return true;
        }
        let mut next = self.parent();
        // A pathname is bounded even if concurrent directory moves change the
        // observed ancestry. Never hold two directory locks while climbing.
        for _ in 0..MAX_PATH {
            let Some(node) = next else { return false };
            let Some(directory) = node.fuse_directory.get() else {
                return false;
            };
            if directory.node == ancestor {
                return true;
            }
            next = directory.parent();
        }
        false
    }
    pub(crate) fn parent(&self) -> Option<NodeRef> {
        self.location.lock().unwrap().as_ref().map(|p| p.0.clone())
    }
    pub(crate) fn path(&self) -> Result<Vec<u8>> {
        if !self.linked() {
            return Err(Errno(2));
        }
        let mut names = Vec::new();
        let mut bytes = 0;
        let mut parent = self.location.lock().unwrap().clone();
        while let Some((node, name)) = parent {
            bytes += name.len() + 1;
            if bytes >= MAX_PATH {
                return Err(Errno(36));
            }
            names.push(name);
            let directory = node.fuse_directory.get().ok_or(Errno(5))?;
            if !directory.linked() {
                return Err(Errno(2));
            }
            parent = directory.location.lock().unwrap().clone();
        }
        let mut path = Vec::with_capacity(bytes.max(1));
        for name in names.iter().rev() {
            path.push(b'/');
            path.extend(name);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        Ok(path)
    }
}
impl Mounted {
    pub(super) fn known_leaf(&self, node: u64, generation: u64) -> Option<NodeRef> {
        self.directories
            .lock()
            .unwrap()
            .get(&(node, generation))
            .and_then(std::sync::Weak::upgrade)
            .filter(|node| !node.directory)
    }
    pub(super) fn known_directory(&self, node: u64, generation: u64) -> Option<NodeRef> {
        self.directories
            .lock()
            .unwrap()
            .get(&(node, generation))
            .and_then(std::sync::Weak::upgrade)
            .filter(|node| node.directory)
    }
    pub(super) fn root_directory(&self) -> NodeRef {
        self.filesystem.borrow().paths[b"/".as_slice()].clone()
    }
    pub(super) fn directory(
        &self,
        reference: &LookupRef,
        generation: u64,
        location: (&NodeRef, &[u8]),
        attr: &mut [u8],
        version: u64,
        valid: (u64, u32),
    ) -> Result<NodeRef> {
        let (parent, name) = location;
        inode::validate(attr)?;
        if reference.node == 1 {
            let node = self.root_directory();
            self.refresh_inode_at(&node, attr, version, valid, inode::Update::Lookup)?;
            return Ok(node);
        }
        let retired;
        let mut directories = self.directories.lock().unwrap();
        retired = self.retire_inodes(&mut directories, reference.node, generation, 0o040000);
        let key = (reference.node, generation);
        if let Some(node) = directories.get(&key).and_then(std::sync::Weak::upgrade) {
            // One retained lookup is sufficient to keep a canonical directory
            // live. The independently granted reference is forgotten normally.
            drop(directories);
            drop(retired);
            self.refresh_inode_at(&node, attr, version, valid, inode::Update::Lookup)?;
            return Ok(node);
        }
        let cached_attr = self.fresh_attr(attr, valid)?;
        let word = |offset| u32::from_le_bytes(attr[offset..offset + 4].try_into().unwrap());
        let global = |offset, group| {
            self.namespace
                .to_global(group, word(offset))
                .unwrap_or(u32::MAX)
        };
        let node = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: Default::default(),
            whole_locks: Default::default(),
            notifications: Default::default(),
            path_hint: Default::default(),
            device: parent.borrow().device,
            content: Content::Directory,
            mode: word(60) & 0o177777,
            uid: global(68, false),
            gid: global(72, true),
            volatile: false,
            inode: u64::from_le_bytes(attr[..8].try_into().unwrap()),
            links: word(64),
            times: inode::times(attr),
            seals: None,
            xattrs: BTreeMap::new(),
        }));
        let _ = node.fuse_directory.set(Arc::new(Directory {
            node: reference.node,
            attr: cached_attr,
            acl: Default::default(),
            _lookup: reference.lease.clone(),
            linked: std::sync::atomic::AtomicBool::new(true),
            cache: Some((Arc::downgrade(&self.directories), key)),
            location: std::sync::Mutex::new(Some((parent.clone(), name.to_vec()))),
        }));
        directories.insert(key, Arc::downgrade(&node));
        drop(directories);
        drop(retired);
        Ok(node)
    }
}

// A pending chdir/chroot retains the original fs_struct, not a numeric descriptor or
// whichever cwd another CLONE_FS task may install while the daemon is asleep.
pub(super) struct Change {
    context: fs_context::ContextPublication,
    mount: Arc<mounts::MountData>,
}
impl Change {
    pub(super) fn new(v: &Vfs, mount: Arc<mounts::MountData>) -> Self {
        Self {
            context: v.context.publication(None),
            mount,
        }
    }
    pub(super) fn publish(&self, node: NodeRef, root: bool) -> FileValue {
        if root {
            self.context.set_root(node, self.mount.clone());
        } else {
            self.context.set_cwd(node, self.mount.clone());
        }
        FileValue::Count(0)
    }
}
