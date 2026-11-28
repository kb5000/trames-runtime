// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-executor bounded name cache under the original filesystem read guard.
//! Only namespace edits invalidate it; inode attributes remain live.
use super::*;
use std::ops::{Deref, DerefMut};
const SLOTS: usize = 256;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
struct Entry {
    owner: u64,
    generation: u64,
    key: Vec<u8>,
    node: Option<std::sync::Weak<Inode>>,
}
thread_local! {
    static CACHE: RefCell<Vec<Option<Entry>>> = RefCell::new((0..SLOTS).map(|_| None).collect());
}
pub(super) struct Index {
    entries: BTreeMap<Vec<u8>, NodeRef>,
    identity: u64,
    generation: u64,
}
impl From<BTreeMap<Vec<u8>, NodeRef>> for Index {
    fn from(entries: BTreeMap<Vec<u8>, NodeRef>) -> Self {
        Self {
            entries,
            identity: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            generation: 0,
        }
    }
}
impl Index {
    pub(super) fn cached(&self, key: &[u8]) -> Option<NodeRef> {
        let hash = key.iter().fold(self.identity, |h, b| {
            (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
        });
        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            let slot = &mut cache[hash as usize & (SLOTS - 1)];
            if let Some(entry) = slot.as_ref().filter(|e| {
                e.owner == self.identity && e.generation == self.generation && e.key == key
            }) {
                match &entry.node {
                    None => return None,
                    Some(node) => {
                        if let Some(node) = node.upgrade() {
                            return Some(node);
                        }
                    }
                }
            }
            let node = self.entries.get(key).cloned();
            *slot = Some(Entry {
                owner: self.identity,
                generation: self.generation,
                key: key.to_vec(),
                node: node.as_ref().map(Arc::downgrade),
            });
            node
        })
    }
}
impl Deref for Index {
    type Target = BTreeMap<Vec<u8>, NodeRef>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
impl DerefMut for Index {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // The owning filesystem write guard already excludes every reader.
        // Invalidate even on rollback; no atomics on ordinary pathname reads.
        if self.generation == u64::MAX {
            self.identity = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            self.generation = 0;
        } else {
            self.generation += 1;
        }
        &mut self.entries
    }
}
impl<'a> IntoIterator for &'a Index {
    type Item = (&'a Vec<u8>, &'a NodeRef);
    type IntoIter = std::collections::btree_map::Iter<'a, Vec<u8>, NodeRef>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn warm_names_follow_replacement_permissions_links_and_negative_entries() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/hot", 0o755).unwrap();
        v.import_file(b"/hot/a", b"a".to_vec()).unwrap();
        for _ in 0..4 {
            v.stat_at(AT_FDCWD, b"/hot/a").unwrap();
            assert_eq!(v.stat_at(AT_FDCWD, b"/hot/missing"), Err(Errno(2)));
        }
        let old = v.node(b"/hot/a").unwrap();
        v.rename_at(AT_FDCWD, b"/hot/a", AT_FDCWD, b"/hot/missing", 0)
            .unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/hot/a"), Err(Errno(2)));
        assert!(Arc::ptr_eq(&old, &v.node(b"/hot/missing").unwrap()));
        v.import_file(b"/hot/a", b"replacement".to_vec()).unwrap();
        assert!(!Arc::ptr_eq(&old, &v.node(b"/hot/a").unwrap()));
        v.link_at(AT_FDCWD, b"/hot/a", AT_FDCWD, b"/hot/link")
            .unwrap();
        assert!(Arc::ptr_eq(
            &v.node(b"/hot/link").unwrap(),
            &v.node(b"/hot/a").unwrap()
        ));
        // Metadata is never copied into the name cache.
        let node = v.node(b"/hot/a").unwrap();
        node.borrow_mut().mode = 0o100640;
        assert_eq!(v.node(b"/hot/a").unwrap().borrow().mode, 0o100640);
    }
}
