// SPDX-License-Identifier: GPL-3.0-or-later
//! Named zero extents own allocated guest pages without eagerly allocating
//! host buffers. Materialized byte pins inherit slices of that same resource.
use super::*;
use std::collections::BTreeMap;

struct Slice {
    objects: usize,
    cached: Weak<PhysicalCharge>,
}
struct State {
    pages: usize,
    slices: BTreeMap<usize, Slice>,
}
struct Reservation {
    group: Option<Arc<MemoryCgroup>>,
    kind: CgroupMemoryKind,
    state: parking_lot::Mutex<State>,
}
/// The inode's allocation owner. Dropping it retires the extent; retained
/// physical slices keep only their own pages charged until their last pin.
pub struct CgroupReservation(Arc<Reservation>);
pub(super) struct ReservedSlice {
    reservation: Arc<Reservation>,
    index: usize,
}
impl Reservation {
    fn release(&self, pages: usize) {
        if let Some(group) = &self.group {
            let bytes = pages * PAGE_SIZE as usize;
            group.account_kind(self.kind, bytes, false);
            group.release_bytes(bytes);
        }
    }
}
impl CgroupReservation {
    pub fn new(pages: usize, kind: CgroupMemoryKind) -> Result<Self, MemoryError> {
        let bytes = pages
            .checked_mul(PAGE_SIZE as usize)
            .ok_or(MemoryError::Limit)?;
        let group = CgroupMemoryTarget::charge_bytes(bytes)?;
        if let Some(group) = &group {
            group.account_kind(kind, bytes, true);
        }
        Ok(Self(Arc::new(Reservation {
            group,
            kind,
            state: parking_lot::Mutex::new(State {
                pages,
                slices: BTreeMap::new(),
            }),
        })))
    }
    pub fn pages(&self) -> usize {
        self.0.state.lock().pages
    }
    pub fn controlled(&self) -> bool {
        self.0.group.is_some()
    }
    pub fn page(&self, index: usize) -> Result<CgroupPageCharge, MemoryError> {
        let mut state = self.0.state.lock();
        if index >= state.pages {
            return Err(MemoryError::InvalidRange);
        }
        let Some(group) = &self.0.group else {
            return Ok(CgroupPageCharge(None));
        };
        let slice = state.slices.entry(index).or_insert_with(|| Slice {
            objects: 0,
            cached: Weak::new(),
        });
        if let Some(existing) = slice.cached.upgrade() {
            return Ok(CgroupPageCharge(Some(existing)));
        }
        // A former Arc's destructor may still be waiting for this object lock.
        // Track live lease objects here rather than inferring them from Weak.
        slice.objects += 1;
        let physical = Arc::new(PhysicalCharge(
            Some(group.clone()),
            self.0.kind,
            Some(ReservedSlice {
                reservation: self.0.clone(),
                index,
            }),
            AtomicBool::new(false),
        ));
        slice.cached = Arc::downgrade(&physical);
        Ok(CgroupPageCharge(Some(physical)))
    }
    pub fn truncate(&self, pages: usize) {
        let mut state = self.0.state.lock();
        let before = state.pages;
        let pages = pages.min(before);
        let pinned = state
            .slices
            .range(pages..before)
            .filter(|(_, slice)| slice.objects != 0)
            .count();
        state.pages = pages;
        drop(state);
        self.0.release(before - pages - pinned);
    }
}
impl Drop for CgroupReservation {
    fn drop(&mut self) {
        self.truncate(0);
    }
}
impl ReservedSlice {
    pub(super) fn release(&self) {
        let mut state = self.reservation.state.lock();
        let retired = self.index >= state.pages;
        let slice = state
            .slices
            .get_mut(&self.index)
            .expect("original reservation slice");
        slice.objects -= 1;
        let last = slice.objects == 0;
        if last {
            state.slices.remove(&self.index);
        }
        drop(state);
        if retired && last {
            self.reservation.release(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_last_slice_drop_and_extent_retirement_refund_once() {
        let group = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _scope = target.scope();
        for _ in 0..64 {
            let extent = CgroupReservation::new(1, CgroupMemoryKind::Shmem).unwrap();
            let pin = extent.page(0).unwrap();
            let start = Arc::new(std::sync::Barrier::new(2));
            let worker_start = start.clone();
            let worker = std::thread::spawn(move || {
                worker_start.wait();
                drop(pin);
            });
            start.wait();
            extent.truncate(0);
            worker.join().unwrap();
            drop(extent);
            assert_eq!(group.current(), 0);
        }
    }
    #[test]
    fn zero_extents_keep_first_owner_and_retire_only_unpinned_slices() {
        let parent = MemoryCgroup::new(None);
        let first = MemoryCgroup::new(Some(parent.clone()));
        let second = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(first.clone()));
        let _scope = target.scope();
        let extent = CgroupReservation::new(4, CgroupMemoryKind::Shmem).unwrap();
        target.set(Some(second.clone()));
        let pin = extent.page(3).unwrap();
        let alias = pin.clone();
        extent.truncate(1);
        assert_eq!(first.current(), 2 * PAGE_SIZE as usize);
        assert_eq!(parent.current(), first.current());
        assert_eq!(second.current(), 0);
        drop(extent);
        assert_eq!(first.current(), PAGE_SIZE as usize);
        drop(pin);
        assert_eq!(first.current(), PAGE_SIZE as usize);
        drop(alias);
        assert_eq!(first.current(), 0);
        assert_eq!(parent.current(), 0);
    }
    #[test]
    fn ancestor_rejection_rolls_back_whole_extent_without_page_descriptors() {
        let parent = MemoryCgroup::new(None);
        let child = MemoryCgroup::new(Some(parent.clone()));
        parent.set_limit(3 * PAGE_SIZE as usize);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(child.clone()));
        let _scope = target.scope();
        assert!(CgroupReservation::new(1 << 28, CgroupMemoryKind::Shmem).is_err());
        assert_eq!(parent.current(), 0);
        assert_eq!(child.current(), 0);
        let extent = CgroupReservation::new(3, CgroupMemoryKind::Shmem).unwrap();
        assert_eq!(extent.0.state.lock().slices.len(), 0);
        assert_eq!(child.current(), 3 * PAGE_SIZE as usize);
        assert!(child
            .format_stat()
            .contains(&format!("shmem {}\n", 3 * PAGE_SIZE)));
    }
}
