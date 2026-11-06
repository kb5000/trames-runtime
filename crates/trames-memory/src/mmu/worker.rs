// SPDX-License-Identifier: GPL-3.0-or-later
//! Physical slots are shared only inside a frozen worker epoch. Replacing a
//! still-owned slot advances its physical window, preserving retained views.
use super::*;
use parking_lot::Mutex;
use std::sync::Weak;

pub(crate) struct Slot {
    pub(crate) owner: Arc<host::Mapping>,
    pub(crate) offset: usize,
    fresh: bool,
}
impl Slot {
    pub fn new(owner: Arc<host::Mapping>, offset: usize, fresh: bool) -> Arc<Self> {
        owner.retain_slot(offset);
        Arc::new(Self {
            owner,
            offset,
            fresh,
        })
    }
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
    pub fn initialize_zero(&self) {
        if !self.fresh {
            self.initialize(&[0; P]);
        }
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.owner.release_slot(self.offset);
    }
}
#[derive(Default)]
struct PhysicalWindow {
    owner: Weak<host::Mapping>,
    slots: Box<[Weak<Slot>]>,
    used: Box<[bool]>,
}
type Windows = BTreeMap<(u64, u64), Arc<Mutex<PhysicalWindow>>>;
#[derive(Clone, Default)]
pub(crate) struct Pool {
    windows: Arc<Mutex<Windows>>,
}
impl Pool {
    pub fn prune(&self) {
        self.windows.lock().retain(|_, window| {
            // A pending slot request keeps its window registered even before
            // allocation. Never wait for host mapping while holding membership.
            Arc::strong_count(window) != 1
                || window
                    .try_lock()
                    .is_none_or(|window| window.owner.strong_count() != 0)
        });
    }
    pub fn slot(&self, space: u64, address: u64) -> Option<Arc<Slot>> {
        let base = address & !(WINDOW as u64 - 1);
        let offset = (address - base) as usize;
        let window = self
            .windows
            .lock()
            .entry((space, base))
            .or_default()
            .clone();
        let mut entry = window.lock();
        if entry.slots.is_empty() {
            entry.slots = (0..WINDOW / P).map(|_| Weak::new()).collect();
            entry.used = vec![false; WINDOW / P].into_boxed_slice();
        }
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
                entry.used.fill(false);
                owner
            }
        };
        let slot = Slot::new(owner, offset, !entry.used[offset / P]);
        entry.used[offset / P] = true;
        entry.slots[offset / P] = Arc::downgrade(&slot);
        Some(slot)
    }
}

/// Only mapping/checkpoint code mutates this object. A View retains its whole
/// Snapshot, so published windows are immutable until every worker is joined.
pub(crate) struct Frozen {
    windows: BTreeMap<u64, Arc<Window>>,
    granule: usize,
}
impl Default for Frozen {
    fn default() -> Self {
        Self {
            windows: BTreeMap::new(),
            granule: host::page_size().unwrap_or(0),
        }
    }
}
impl Frozen {
    pub fn granule(&self) -> usize {
        self.granule
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
                        let Some(window) = Window::for_workers(base, self.granule) else {
                            return;
                        };
                        self.windows.insert(base, Arc::new(window));
                    }
                    let window = &self.windows[&base];
                    if window.cpu.alias(offset, owner, at, self.granule) {
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
            // No active View can observe this joined snapshot mutation. When
            // the last eligible group disappears, keep the physical frames,
            // not a permanently inaccessible CPU reservation.
            if state & ELIGIBLE == 0
                && window
                    .flags
                    .iter()
                    .all(|flag| flag.load(Ordering::Relaxed) & ELIGIBLE == 0)
            {
                self.windows.remove(&base);
            }
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
    /// Snapshot-owned CPU alias. Views are recreated after snapshot edits, so
    /// a cached page address cannot outlive its frozen mapping or permissions.
    pub fn page_alias(&self, cache: &Cache, address: u64) -> usize {
        let base = address & !(WINDOW as u64 - 1);
        let pointer = if let Some(pointer) = cache.get(base) {
            pointer
        } else {
            self.reached_slow(cache, base)
        };
        let Some(pointer) = pointer else { return 0 };
        // SAFETY: cache and pinned windows belong to the same immutable snapshot.
        let window = unsafe { pointer.as_ref() };
        let offset = (address - window.base) as usize;
        if window.flags[offset >> window.shift].load(Ordering::Relaxed) & ELIGIBLE == 0 {
            return 0;
        }
        window.cpu.cpu.as_ptr().wrapping_add(offset) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn executor_pools_share_windows_without_reusing_live_slots() {
        let pool = Pool::default();
        let start = Arc::new(std::sync::Barrier::new(4));
        let joins: Vec<_> = (0..4)
            .map(|index| {
                let pool = pool.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let slot = pool.slot(1, (index * P) as u64).unwrap();
                    slot.initialize(&[index as u8 + 1; P]);
                    slot
                })
            })
            .collect();
        let slots: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
        for (index, slot) in slots.iter().enumerate() {
            assert!(Arc::ptr_eq(&slot.owner, &slots[0].owner));
            // SAFETY: retained test slots have disjoint initialized storage.
            assert_eq!(unsafe { slot.pointer().read() }, index as u8 + 1);
        }
        let replacement = pool.clone().slot(1, 0).unwrap();
        assert!(!Arc::ptr_eq(&replacement.owner, &slots[0].owner));
        replacement.initialize(&[42; P]);
        // SAFETY: both live generations retain their own initialized storage.
        assert_eq!(unsafe { slots[0].pointer().read() }, 1);
        assert_eq!(unsafe { replacement.pointer().read() }, 42);
    }

    #[test]
    fn pruning_and_other_spaces_do_not_wait_for_an_allocating_window() {
        let pool = Pool::default();
        let window = Arc::new(Mutex::new(PhysicalWindow::default()));
        pool.windows.lock().insert((1, 0), window.clone());
        let held = window.lock();
        let remote = pool.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            remote.prune();
            let slot = remote.slot(2, 0).unwrap();
            tx.send(slot).unwrap();
        });
        let slot = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        join.join().unwrap();
        assert!(Arc::ptr_eq(&pool.windows.lock()[&(1, 0)], &window));
        drop(held);
        drop(window);
        pool.prune();
        assert!(!pool.windows.lock().contains_key(&(1, 0)));
        assert!(pool.windows.lock().contains_key(&(2, 0)));
        drop(slot);
        pool.prune();
        assert!(pool.windows.lock().is_empty());
    }

    #[test]
    fn a_reused_worker_slot_zeroes_retired_data() {
        let pool = Pool::default();
        let first = pool.slot(1, 0x40000).unwrap();
        first.initialize(&[42; P]);
        let peer = pool.slot(1, 0x41000).unwrap();
        let owner = first.owner.clone();
        drop(first);
        let reused = pool.slot(1, 0x40000).unwrap();
        assert!(Arc::ptr_eq(&reused.owner, &owner));
        assert!(!reused.fresh);
        reused.initialize_zero();
        // SAFETY: retained exclusive unpublished test slots.
        assert!(unsafe { std::slice::from_raw_parts(reused.pointer(), P) }
            .iter()
            .all(|&b| b == 0));
        peer.initialize_zero();
    }
    #[test]
    fn frozen_views_own_no_unused_ram_and_release_the_last_demoted_window() {
        let physical = Arc::new(host::Mapping::new().unwrap());
        let granule = host::page_size().unwrap();
        let frames: Vec<_> = (0..granule / P).map(|i| (&physical, i * P, i)).collect();
        let mut frozen = Frozen::default();
        frozen.update(0x40000, Some(Permissions::RW), &frames);
        let window = frozen.windows.values().next().unwrap();
        assert!(
            window.mapping.is_none(),
            "workers reserve no unused physical window"
        );
        let old = Arc::downgrade(window);
        frozen.update(0x40000, None, &[]);
        assert!(frozen.windows.is_empty());
        assert!(old.upgrade().is_none());
        // The source owner remains usable after its protected CPU view retires.
        // SAFETY: exclusively owned in-bounds physical storage.
        unsafe {
            physical.kernel.as_ptr().write(19);
        }
        frozen.update(0x40000, Some(Permissions::R), &frames);
        let window = frozen.windows.values().next().unwrap();
        let offset = 0x40000 - window.base as usize;
        // SAFETY: live readable CPU alias, coherent with the retained source.
        assert_eq!(unsafe { window.cpu.cpu.as_ptr().add(offset).read() }, 19);
    }
}
