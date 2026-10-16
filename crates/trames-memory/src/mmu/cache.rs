// SPDX-License-Identifier: GPL-3.0-or-later
//! One direct-mapped level over sparse host mapping windows. No byte ownership,
//! permission grants, shared atomics, or access-frequency bookkeeping lives here.
use super::*;

const SLOTS: usize = 16;
#[derive(Clone, Copy)]
struct Entry {
    tag: u64,
    pointer: usize,
}
impl Entry {
    const EMPTY: Self = Self { tag: 0, pointer: 0 };
}

pub(crate) struct Cache {
    entries: [Cell<Entry>; SLOTS],
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            entries: [const { Cell::new(Entry::EMPTY) }; SLOTS],
        }
    }
}
impl Cache {
    #[inline(always)]
    fn index(base: u64) -> usize {
        let window = base / WINDOW as u64;
        // Fold high bits: code, heap and mmap commonly share the low index bits.
        (window ^ (window >> 4) ^ (window >> 8) ^ (window >> 16)) as usize & (SLOTS - 1)
    }
    #[inline(always)]
    pub fn get(&self, base: u64) -> Option<Option<NonNull<Window>>> {
        let entry = self.entries[Self::index(base)].get();
        if entry.tag == base | 1 {
            Some(NonNull::new(entry.pointer as *mut Window))
        } else {
            None
        }
    }
    #[inline]
    pub fn insert(&self, base: u64, pointer: NonNull<Window>) {
        let pointer = pointer.as_ptr() as usize;
        self.entries[Self::index(base)].set(Entry {
            tag: base | 1,
            pointer,
        });
    }
    pub fn absent(&self, base: u64) {
        self.entries[Self::index(base)].set(Entry {
            tag: base | 1,
            pointer: 0,
        });
    }
    pub fn clear(&self) {
        for entry in &self.entries {
            entry.set(Entry::EMPTY);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_windows_do_not_conflict_and_collisions_replace_only_their_slot() {
        let common = [0x10000000, 0x40000000, 0x70000000, 0x7fffff000000];
        let indexes: BTreeSet<_> = common.into_iter().map(Cache::index).collect();
        assert_eq!(indexes.len(), common.len());
        let cache = Cache::default();
        let mut window = 0u8;
        // No dereference: this verifies replacement/tag lookup only.
        let pointer = NonNull::from(&mut window).cast::<Window>();
        for base in common {
            cache.insert(base, pointer);
        }
        for base in common {
            assert_eq!(cache.get(base), Some(Some(pointer)));
        }
        let collision = (1..1024)
            .map(|n| n * WINDOW as u64)
            .find(|&base| base != common[0] && Cache::index(base) == Cache::index(common[0]))
            .unwrap();
        cache.insert(collision, pointer);
        assert!(cache.get(common[0]).is_none());
        assert_eq!(cache.get(collision), Some(Some(pointer)));
        for base in common.into_iter().skip(1) {
            assert_eq!(cache.get(base), Some(Some(pointer)));
        }
        cache.absent(collision);
        assert_eq!(cache.get(collision), Some(None));
        cache.clear();
        assert!(cache.get(collision).is_none());
    }
}
