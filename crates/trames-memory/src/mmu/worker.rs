// SPDX-License-Identifier: GPL-3.0-or-later
//! Physical slots are shared only inside a frozen worker epoch. Replacing a
//! still-owned slot advances its physical window, preserving retained views.
use super::*;
use std::{marker::PhantomData, sync::Weak};

pub(crate) struct Slot {
    pub(crate) owner: Arc<host::Mapping>,
    pub(crate) offset: usize,
}
impl Slot {
    pub fn pointer(&self) -> *mut u8 {
        self.owner.kernel.as_ptr().wrapping_add(self.offset)
    }
    pub fn initialize(&self, bytes: &[u8; P]) {
        // SAFETY: Pool returns a new slot only when no earlier owner can still
        // observe its bytes. Initialization finishes before frame publication.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.pointer(), P);
        }
    }
}
struct PhysicalWindow {
    owner: Weak<host::Mapping>,
    slots: Box<[Weak<Slot>]>,
}
#[derive(Default)]
pub(crate) struct Pool {
    windows: BTreeMap<(u64, u64), PhysicalWindow>,
}
impl Pool {
    pub fn prune(&mut self) {
        self.windows
            .retain(|_, window| window.owner.strong_count() != 0);
    }
    pub fn slot(&mut self, space: u64, address: u64) -> Option<Arc<Slot>> {
        let base = address & !(WINDOW as u64 - 1);
        let offset = (address - base) as usize;
        let entry = self
            .windows
            .entry((space, base))
            .or_insert_with(|| PhysicalWindow {
                owner: Weak::new(),
                slots: (0..WINDOW / P).map(|_| Weak::new()).collect(),
            });
        let owner = match entry
            .owner
            .upgrade()
            .filter(|_| entry.slots[offset / P].strong_count() == 0)
        {
            Some(owner) => owner,
            None => {
                let owner = Arc::new(host::Mapping::new()?);
                entry.owner = Arc::downgrade(&owner);
                entry.slots.fill_with(Weak::new);
                owner
            }
        };
        let slot = Arc::new(Slot { owner, offset });
        entry.slots[offset / P] = Arc::downgrade(&slot);
        Some(slot)
    }
}

/// Only mapping/checkpoint code mutates this object. A View retains its whole
/// Snapshot, so published windows are immutable until every worker is joined.
pub(crate) struct Frozen {
    windows: BTreeMap<u64, Arc<Window>>,
    granule: usize,
    key: u64,
}
impl Default for Frozen {
    fn default() -> Self {
        Self {
            windows: BTreeMap::new(),
            granule: host::page_size().unwrap_or(0),
            key: NEXT_SPACE.fetch_add(1, Ordering::Relaxed),
        }
    }
}
pub(crate) struct Operand<'a> {
    pub(crate) frame: usize,
    target: *mut u8,
    _owner: PhantomData<&'a Frozen>,
}
impl Operand<'_> {
    /// Caller holds the exact worker byte-region guard, or an immutable frame.
    pub(crate) unsafe fn read<const N: usize>(&self) -> Option<[u8; N]> {
        let mut bytes = [0; N];
        // SAFETY: Frozen validated the complete hardware-page-contained target;
        // the caller excludes overlapping writers for this operation.
        if unsafe { access::access::<N>(false, self.target, bytes.as_mut_ptr()) } {
            Some(bytes)
        } else {
            None
        }
    }
    /// Caller holds the frame's write-region guard through dirty publication.
    pub(crate) unsafe fn write<const N: usize>(&self, mut bytes: [u8; N]) -> bool {
        // SAFETY: same target lifetime/bounds as read and an exclusive guard.
        unsafe { access::access::<N>(true, self.target, bytes.as_mut_ptr()) }
    }
}
impl Frozen {
    pub fn granule(&self) -> usize {
        self.granule
    }
    pub fn invalidate_hints(&mut self) {
        self.key = NEXT_SPACE.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn hint(&self, cache: &Cache) -> DirectHint {
        cache.hint(self.key)
    }
    /// Entries contain root slab IDs, which survive incremental frame swaps.
    /// A partial/mixed/IO-backed group passes None and becomes inaccessible.
    pub fn update(
        &mut self,
        address: u64,
        permissions: Option<Permissions>,
        physical: &[(&Arc<host::Mapping>, usize, usize)],
    ) {
        if self.granule == 0 {
            return;
        }
        let base = address & !(WINDOW as u64 - 1);
        let offset = (address - base) as usize;
        let mut state = 0;
        if let Some(permissions) = permissions {
            if physical.len() == self.granule / P && (permissions.read || !permissions.write) {
                let (owner, at, _) = physical[0];
                if at.is_multiple_of(self.granule)
                    && physical
                        .iter()
                        .enumerate()
                        .all(|(index, (next, offset, _))| {
                            Arc::ptr_eq(owner, next) && *offset == at + index * P
                        })
                {
                    if !self.windows.contains_key(&base) {
                        let Some(window) = Window::new(base, self.granule) else {
                            return;
                        };
                        self.windows.insert(base, Arc::new(window));
                    }
                    let window = &self.windows[&base];
                    if window.mapping.alias(offset, owner, at, self.granule) {
                        for (index, (_, _, root)) in physical.iter().enumerate() {
                            window.frames[offset / P + index].store(*root, Ordering::Relaxed);
                        }
                        state = ELIGIBLE
                            | if permissions.read { READ } else { 0 }
                            | if permissions.write && !permissions.execute {
                                WRITE
                            } else {
                                0
                            }
                            | if permissions.execute { CODE } else { 0 };
                    }
                }
            }
        }
        if let Some(window) = self.windows.get(&base) {
            window.protect_run(offset / self.granule, offset / self.granule + 1, state);
        }
    }
    #[cold]
    #[inline(never)]
    fn reached_slow(&self, cache: &Cache, base: u64) -> Option<NonNull<Window>> {
        let Some(window) = self.windows.get(&base) else {
            cache.absent(base);
            return None;
        };
        let pointer = NonNull::from(window.as_ref());
        cache.insert(base, pointer);
        Some(pointer)
    }
    #[inline(always)]
    pub fn operand_hint<'a>(
        &'a self,
        cache: &Cache,
        address: u64,
        len: usize,
        write: bool,
        hint: &mut DirectHint,
    ) -> Option<Operand<'a>> {
        if !matches!(len, 1 | 2 | 4 | 8 | 16) || len > P - (address as usize & (P - 1)) {
            return None;
        }
        let (window, bias) = if let Some(reached) = hint.reached(self.key, address) {
            reached
        } else {
            let base = address & !(WINDOW as u64 - 1);
            let pointer = if let Some(pointer) = cache.get(base) {
                pointer?
            } else {
                self.reached_slow(cache, base)?
            };
            *hint = cache.hint(self.key);
            // SAFETY: the cache is owned by this snapshot's View and only
            // contains immutable pinned windows retained by that snapshot.
            let window = unsafe { pointer.as_ref() };
            (window, hint.bias)
        };
        let offset = (address - window.base) as usize;
        let state = window.flags[offset / window.granule].load(Ordering::Relaxed);
        if state & ELIGIBLE == 0 || (write && state & CODE != 0) {
            return None;
        }
        Some(Operand {
            frame: window.frames[offset / P].load(Ordering::Relaxed),
            target: bias.wrapping_add(address as usize) as *mut u8,
            _owner: PhantomData,
        })
    }
}
