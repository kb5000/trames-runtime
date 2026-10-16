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
    last: Cell<usize>,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            entries: [const { Cell::new(Entry::EMPTY) }; SLOTS],
            last: Cell::new(0),
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
            if entry.pointer != 0 {
                self.last.set(entry.pointer);
            }
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
        self.last.set(pointer);
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
        self.last.set(0);
    }
    #[inline]
    pub fn hint(&self, owner: u64) -> DirectHint {
        let pointer = self.last.get();
        if pointer == 0 {
            return DirectHint::EMPTY;
        }
        // SAFETY: callers clear this cache before dropping their pinned windows;
        // a worker cache belongs to one retained immutable Snapshot only.
        let window = unsafe { &*(pointer as *const Window) };
        DirectHint {
            owner,
            window: pointer,
            bias: (window.mapping.cpu.as_ptr() as usize).wrapping_sub(window.base as usize),
        }
    }
}

/// Opaque, non-owning CPU-slice translation hint. The owner generation is checked
/// BEFORE dereferencing the window; old hints cannot keep fork/remap aliases alive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectHint {
    owner: u64,
    window: usize,
    pub(super) bias: usize,
}
impl DirectHint {
    pub const EMPTY: Self = Self {
        owner: 0,
        window: 0,
        bias: 0,
    };
    /// Scalars carried explicitly by the interpreter's preserve-none tail ABI.
    pub fn into_parts(self) -> (u64, usize, usize) {
        (self.owner, self.window, self.bias)
    }
    /// Reconstitute unmodified parts obtained from `into_parts` on a real hint.
    ///
    /// # Safety
    /// All three values must come from the SAME hint, without modification.
    /// Stale hints are allowed: each memory implementation checks the owner
    /// generation before accessing their raw window descriptor.
    #[inline]
    pub unsafe fn from_parts(owner: u64, window: usize, bias: usize) -> Self {
        Self {
            owner,
            window,
            bias,
        }
    }
    #[inline(always)]
    pub(super) fn reached(&self, owner: u64, address: u64) -> Option<(&Window, usize)> {
        if self.owner != owner || self.window == 0 {
            return None;
        }
        // SAFETY: opaque hints are constructed solely from pinned live windows;
        // their owner key changes before any of those windows can be freed.
        let window = unsafe { &*(self.window as *const Window) };
        if address.wrapping_sub(window.base) >= WINDOW as u64 {
            return None;
        }
        Some((window, self.bias))
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
        assert_eq!(cache.hint(1), DirectHint::EMPTY);
    }
}
