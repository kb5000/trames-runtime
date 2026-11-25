// SPDX-License-Identifier: GPL-3.0-or-later
//! Names held by original lookups, open descriptions and directory paths.
//! The index is weak and never bypasses a fresh daemon LOOKUP.
use super::*;
use std::sync::{Mutex, Weak};

type Key = (u64, Vec<u8>);
#[derive(Default)]
pub(super) struct Entries(Mutex<BTreeMap<Key, Weak<Entry>>>);
pub(crate) struct Entry {
    node: Weak<Inode>,
    index: Weak<Entries>,
    pub(super) location: Mutex<Option<(NodeRef, Vec<u8>)>>,
    hashed: std::sync::atomic::AtomicBool,
}
impl Entries {
    pub(super) fn new_entry(
        self: &Arc<Self>,
        node: &NodeRef,
        location: Option<(NodeRef, Vec<u8>)>,
    ) -> Arc<Entry> {
        Arc::new(Entry {
            node: Arc::downgrade(node),
            index: Arc::downgrade(self),
            location: Mutex::new(location),
            hashed: true.into(),
        })
    }
    pub(super) fn bind(
        self: &Arc<Self>,
        node: &NodeRef,
        parent: &NodeRef,
        name: &[u8],
    ) -> Arc<Entry> {
        let mut names = self.0.lock().unwrap();
        let key = (parent.identity, name.to_vec());
        if let Some(entry) = names.get(&key).and_then(Weak::upgrade) {
            if entry.node.ptr_eq(&Arc::downgrade(node)) {
                return entry;
            }
            entry.hashed.store(false, Ordering::Relaxed);
        }
        if names.len() >= 4096 {
            names.retain(|_, entry| entry.strong_count() != 0);
        }
        let entry = self.new_entry(node, Some((parent.clone(), name.to_vec())));
        names.insert(key, Arc::downgrade(&entry));
        entry
    }
    pub(super) fn matching(
        &self,
        parent: &NodeRef,
        name: &[u8],
        node: &NodeRef,
    ) -> Option<Arc<Entry>> {
        self.0
            .lock()
            .unwrap()
            .get(&(parent.identity, name.to_vec()))?
            .upgrade()
            .filter(|entry| entry.node.ptr_eq(&Arc::downgrade(node)))
    }
    pub(super) fn unlink(&self, parent: &NodeRef, name: &[u8], node: &NodeRef) {
        let mut names = self.0.lock().unwrap();
        let key = (parent.identity, name.to_vec());
        if let Some(entry) = names
            .get(&key)
            .and_then(Weak::upgrade)
            .filter(|entry| entry.node.ptr_eq(&Arc::downgrade(node)))
        {
            names.remove(&key);
            entry.hashed.store(false, Ordering::Relaxed);
        }
    }
    pub(super) fn rename(
        &self,
        source: (&NodeRef, &[u8], Option<Arc<Entry>>),
        dest: (&NodeRef, &[u8], Option<Arc<Entry>>),
        exchange: bool,
        lookup: bool,
    ) -> Result<()> {
        let mut names = self.0.lock().unwrap();
        Self::rename_locked(&mut names, source, dest, exchange, lookup)
    }
    fn rename_locked(
        names: &mut BTreeMap<Key, Weak<Entry>>,
        source: (&NodeRef, &[u8], Option<Arc<Entry>>),
        dest: (&NodeRef, &[u8], Option<Arc<Entry>>),
        exchange: bool,
        lookup: bool,
    ) -> Result<()> {
        let source_key = (source.0.identity, source.1.to_vec());
        let dest_key = (dest.0.identity, dest.1.to_vec());
        if source_key == dest_key {
            if let Some(entry) = source.2 {
                let publish = lookup
                    || names
                        .get(&source_key)
                        .is_none_or(|named| named.ptr_eq(&Arc::downgrade(&entry)));
                if publish {
                    let old = names.insert(source_key, Arc::downgrade(&entry));
                    if let Some(old) = old.and_then(|old| old.upgrade()) {
                        if !Arc::ptr_eq(&old, &entry) {
                            old.hashed.store(false, Ordering::Relaxed);
                        }
                    }
                }
                entry.hashed.store(publish, Ordering::Relaxed);
            }
            return Ok(());
        }
        let source_entry = source
            .2
            .or_else(|| lookup.then(|| names.get(&source_key)?.upgrade()).flatten());
        let dest_entry = dest
            .2
            .or_else(|| lookup.then(|| names.get(&dest_key)?.upgrade()).flatten());
        // Every topology edit shares this object admission. A daemon alias
        // cannot introduce a strong parent cycle through concurrent lookups.
        Self::check_parent(source_entry.as_ref(), dest.0)?;
        if exchange {
            Self::check_parent(dest_entry.as_ref(), source.0)?;
        }
        for (key, entry) in [(&source_key, &source_entry), (&dest_key, &dest_entry)] {
            if entry.as_ref().is_some_and(|entry| {
                names
                    .get(key)
                    .is_some_and(|named| named.ptr_eq(&Arc::downgrade(entry)))
            }) {
                names.remove(key);
            }
        }
        if let Some(entry) = source_entry {
            *entry.location.lock().unwrap() = Some((dest.0.clone(), dest.1.to_vec()));
            let publish = lookup || !names.contains_key(&dest_key);
            entry.hashed.store(publish, Ordering::Relaxed);
            if publish {
                names.insert(dest_key, Arc::downgrade(&entry));
            }
        }
        if let Some(entry) = dest_entry {
            if exchange {
                *entry.location.lock().unwrap() = Some((source.0.clone(), source.1.to_vec()));
                let publish = lookup || !names.contains_key(&source_key);
                entry.hashed.store(publish, Ordering::Relaxed);
                if publish {
                    names.insert(source_key, Arc::downgrade(&entry));
                }
            } else {
                entry.hashed.store(false, Ordering::Relaxed);
            }
        }
        Ok(())
    }
    fn check_parent(entry: Option<&Arc<Entry>>, parent: &NodeRef) -> Result<()> {
        let Some(node) = entry
            .and_then(|entry| entry.node.upgrade())
            .filter(|node| node.directory)
        else {
            return Ok(());
        };
        let mut next = Some(parent.clone());
        for _ in 0..MAX_PATH {
            let Some(parent) = next else { return Ok(()) };
            if Arc::ptr_eq(&node, &parent) {
                return Err(Errno(40));
            }
            next = parent
                .fuse_directory
                .get()
                .and_then(|directory| directory.parent());
        }
        Err(Errno(40))
    }
    pub(super) fn notification(
        &self,
        parent: &NodeRef,
        name: &[u8],
        expire_only: bool,
    ) -> Result<(Arc<Entry>, NodeRef)> {
        let mut names = self.0.lock().unwrap();
        let key = (parent.identity, name.to_vec());
        let entry = names.get(&key).and_then(Weak::upgrade).ok_or(Errno(2))?;
        let node = entry.node.upgrade().ok_or(Errno(2))?;
        if !expire_only {
            names.remove(&key);
            entry.hashed.store(false, Ordering::Relaxed);
        }
        Ok((entry, node))
    }
    pub(super) fn has_children(&self, parent: &NodeRef) -> bool {
        self.0
            .lock()
            .unwrap()
            .range((parent.identity, Vec::new())..)
            .take_while(|((id, _), _)| *id == parent.identity)
            .any(|(_, entry)| {
                entry
                    .upgrade()
                    .is_some_and(|entry| entry.node.strong_count() != 0)
            })
    }
}
impl Entry {
    pub(crate) fn attach<T>(
        entry: Option<&Arc<Self>>,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let Some(entry) = entry else { return action() };
        let index = entry.index.upgrade().ok_or(Errno(2))?;
        let _names = index.0.lock().unwrap();
        if !entry.mountable() {
            return Err(Errno(2));
        }
        action()
    }
    pub(crate) fn attach_pair<T>(
        first: Option<&Arc<Self>>,
        second: Option<&Arc<Self>>,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let (Some(first), Some(second)) = (first, second) else {
            return Self::attach(first.or(second), action);
        };
        let first_index = first.index.upgrade().ok_or(Errno(2))?;
        let second_index = second.index.upgrade().ok_or(Errno(2))?;
        // Cross-filesystem pivots take only their actual name admissions, in
        // address order. A same-filesystem pivot must not lock twice.
        let (low, high) = if Arc::as_ptr(&first_index) <= Arc::as_ptr(&second_index) {
            (&first_index, &second_index)
        } else {
            (&second_index, &first_index)
        };
        let _low = low.0.lock().unwrap();
        let _high = (!Arc::ptr_eq(low, high)).then(|| high.0.lock().unwrap());
        if !first.mountable() || !second.mountable() {
            return Err(Errno(2));
        }
        action()
    }
    pub(crate) fn below(&self, ancestor: &Arc<Self>) -> bool {
        if std::ptr::eq(self, ancestor.as_ref()) {
            return true;
        }
        let mut next = self
            .location
            .lock()
            .unwrap()
            .as_ref()
            .map(|(parent, _)| parent.clone());
        for _ in 0..MAX_PATH {
            let Some(parent) = next else { return false };
            let Some(directory) = parent.fuse_directory.get() else {
                return false;
            };
            if Arc::ptr_eq(&directory.entry, ancestor) {
                return true;
            }
            next = directory.parent();
        }
        false
    }
    pub(crate) fn mountable(&self) -> bool {
        if !self.hashed() {
            return false;
        }
        let mut next = self
            .location
            .lock()
            .unwrap()
            .as_ref()
            .map(|(parent, _)| parent.clone());
        for _ in 0..MAX_PATH {
            let Some(parent) = next else { return true };
            let Some(directory) = parent.fuse_directory.get() else {
                return false;
            };
            if !directory.linked() || !directory.entry.hashed() {
                return false;
            }
            next = directory.parent();
        }
        false
    }
    pub(crate) fn directory(node: &NodeRef) -> Option<Arc<Self>> {
        node.fuse_directory
            .get()
            .map(|directory| directory.entry.clone())
    }
    pub(super) fn hashed(&self) -> bool {
        self.hashed.load(Ordering::Relaxed)
    }
    pub(super) fn publish(self: &Arc<Self>) {
        let Some(index) = self.index.upgrade() else {
            return;
        };
        let mut names = index.0.lock().unwrap();
        if names.len() >= 4096 {
            names.retain(|_, entry| entry.strong_count() != 0);
        }
        if let Some((parent, name)) = &*self.location.lock().unwrap() {
            let old = names.insert((parent.identity, name.clone()), Arc::downgrade(self));
            if let Some(old) = old.and_then(|old| old.upgrade()) {
                if !Arc::ptr_eq(&old, self) {
                    old.hashed.store(false, Ordering::Relaxed);
                }
            }
        }
        self.hashed.store(true, Ordering::Relaxed);
    }
    pub(super) fn relocate(
        self: &Arc<Self>,
        fs: &Mounted,
        parent: NodeRef,
        name: Vec<u8>,
    ) -> Result<()> {
        let Some(index) = self.index.upgrade() else {
            return Ok(());
        };
        // Keep the real try-lock receipts outside the index scope. Unlocking
        // an inode/rename may wake a continuation which uses this same index.
        let mut rename = None;
        let mut old_read = None;
        let result = {
            let mut names = index.0.lock().unwrap();
            let location = self.location.lock().unwrap().clone();
            let Some((old_parent, old_name)) = location else {
                return Ok(());
            };
            Entries::check_parent(Some(self), &parent)?;
            if !Arc::ptr_eq(&old_parent, &parent) {
                // Native d_splice_alias uses try-locks and ESTALE here: waiting
                // while holding the new parent's read lock can deadlock rename.
                rename = Some(fs.rename.try_enter().ok_or(Errno(116))?);
                old_read = Some(inode::attr(&old_parent).try_read().ok_or(Errno(116))?);
            }
            Entries::rename_locked(
                &mut names,
                (&old_parent, &old_name, Some(self.clone())),
                (&parent, &name, None),
                false,
                true,
            )
        };
        drop(old_read);
        drop(rename);
        result
    }
    pub(super) fn unhash(&self) {
        let Some(index) = self.index.upgrade() else {
            return;
        };
        let mut names = index.0.lock().unwrap();
        if let Some((parent, name)) = &*self.location.lock().unwrap() {
            let key = (parent.identity, name.clone());
            if names
                .get(&key)
                .is_some_and(|entry| std::ptr::eq(entry.as_ptr(), self))
            {
                names.remove(&key);
            }
        }
        self.hashed.store(false, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuse::tests::{mounted, open_file};

    #[test]
    fn weak_name_index_does_not_retain_original_ofd_inode_or_lookup_lease() {
        let (mut v, dev) = mounted();
        let c = &dev.daemon.get().unwrap().connection;
        let (paths, fd) = open_file(&v, c, 0);
        let original = v.shared_files().lookup(fd).unwrap().unwrap();
        let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
            panic!("original FUSE open description");
        };
        let inode = Arc::downgrade(&file.inode().unwrap());
        let entry = Arc::downgrade(file.reference.entry.as_ref().unwrap());
        let ofd = Arc::downgrade(file);
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), fd);
        assert!(entry.upgrade().is_some() && inode.upgrade().is_some());
        drop(original);
        // An implicit close retains the original OFD until FLUSH completes.
        // The weak name index must not retain it beyond that real protocol use.
        assert!(ofd.upgrade().is_some());
        let flush = crate::fuse::tests::receive(c, 25, 10);
        crate::fuse::tests::answer(c, &flush, &[]);
        assert!(ofd.upgrade().is_none());
        assert!(entry.upgrade().is_none());
        assert!(inode.upgrade().is_none());
        assert_eq!(v.read(fd, 8).unwrap(), 99u64.to_le_bytes());
        drop(paths);
    }
}
