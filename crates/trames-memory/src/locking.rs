// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest residency policy belongs to an mm. Views only query it for MS_INVALIDATE.
//! Ordinary guest accesses use the existing resident backing and fault path.
use super::*;
use std::sync::{OnceLock, RwLock};
use vma_policy::Ranges;

#[derive(Default)]
pub(super) struct LockedRanges {
    all: Ranges,
    on_fault: Ranges,
}
impl LockedRanges {
    fn remove(&mut self, start: u64, end: u64) {
        self.all.remove(start, end);
        self.on_fault.remove(start, end);
    }
}
#[derive(Default, Clone)]
pub(super) struct Locks(Arc<OnceLock<RwLock<LockedRanges>>>);
impl Locks {
    fn read<T: Default>(&self, f: impl FnOnce(&LockedRanges) -> T) -> T {
        self.0
            .get()
            .map_or_else(T::default, |s| f(&s.read().unwrap()))
    }
    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.read(|r| r.all.pieces(start, end).next().is_some())
    }
    pub(super) fn remove(&self, start: u64, end: u64) {
        if let Some(s) = self.0.get() {
            s.write().unwrap().remove(start, end);
        }
    }
    pub(super) fn moved(&self, old: u64, len: u64, new: u64, new_len: u64) -> LockedRanges {
        self.read(|r| {
            let mut moved = LockedRanges::default();
            for (source, dest) in [(&r.all, &mut moved.all), (&r.on_fault, &mut moved.on_fault)] {
                for (a, b) in source.pieces(old, old + len.min(new_len)) {
                    dest.insert(new + (a - old), new + (b - old));
                }
                if new_len > len && source.contains(old + len - 1) {
                    dest.insert(new + len, new + new_len);
                }
            }
            moved
        })
    }
    pub(super) fn finish_move(
        &self,
        old: u64,
        len: u64,
        new: u64,
        new_len: u64,
        moved: LockedRanges,
    ) {
        if let Some(s) = self.0.get() {
            let mut r = s.write().unwrap();
            r.remove(old, old + len);
            r.remove(new, new + new_len);
            for (a, b) in moved.all.0 {
                r.all.insert(a, b);
            }
            for (a, b) in moved.on_fault.0 {
                r.on_fault.insert(a, b);
            }
        }
    }
}
impl Memory {
    pub fn locked_bytes_in(&self, start: u64, len: u64) -> u64 {
        if let Some(s) = &self.shared {
            return s.borrow().locked_bytes_in(start, len);
        }
        self.locks.read(|r| {
            r.all
                .pieces(start, start.saturating_add(len))
                .map(|(a, b)| b - a)
                .sum()
        })
    }
    /// Some(true) marks future mappings on fault; Some(false) eagerly populates.
    pub fn future_lock(&self) -> Option<bool> {
        if let Some(s) = &self.shared {
            return s.borrow().future_lock();
        }
        self.future_lock
    }
    pub fn lock_mode_at(&self, address: u64) -> Option<bool> {
        if let Some(s) = &self.shared {
            return s.borrow().lock_mode_at(address);
        }
        self.locks.read(|r| {
            r.all
                .contains(address)
                .then(|| r.on_fault.contains(address))
        })
    }
    pub fn set_range_lock(
        &mut self,
        start: u64,
        len: u64,
        mode: Option<bool>,
    ) -> Result<(), MemoryError> {
        if let Some(s) = &self.shared {
            return s.borrow_mut().set_range_lock(start, len, mode);
        }
        let end = Self::mapping_end(start, len)?;
        self.check_mapped_range(start, end)?;
        let Some(on_fault) = mode else {
            self.locks.remove(start, end);
            return Ok(());
        };
        {
            let mut ranges = self.locks.0.get_or_init(Default::default).write().unwrap();
            ranges.all.insert(start, end);
            if on_fault {
                ranges.on_fault.insert(start, end);
            } else {
                ranges.on_fault.remove(start, end);
            }
        }
        if !on_fault {
            self.populate_range(start, end - start)?;
        }
        Ok(())
    }
    /// Fault accessible pages without changing the VMA's locking policy.
    pub fn populate_range(&self, start: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(s) = &self.shared {
            return s.borrow().populate_range(start, len);
        }
        let end = Self::mapping_end(start, len)?;
        for base in (start..end).step_by(PAGE_SIZE as usize) {
            let desc = self
                .page_for_access_unchecked(base)
                .ok_or(MemoryError::Unmapped(base))?;
            let access = if desc.permissions.read {
                Access::Read
            } else if desc.permissions.write {
                Access::Write
            } else {
                Access::Execute
            };
            let page = self.page_for_access(base, 1, access)?;
            page.prepare_source(base)?;
            page.charge.ensure()?;
            page.read_bytes(0, &mut [0])
                .map_err(|e| e.at_access(base))?;
        }
        Ok(())
    }
    pub fn set_all_locks(&mut self, current: bool, future: bool, on_fault: bool) {
        if let Some(s) = &self.shared {
            return s.borrow_mut().set_all_locks(current, future, on_fault);
        }
        self.future_lock = future.then_some(on_fault);
        if current {
            for (a, b, _) in self.regions() {
                // Linux marks every VMA and attempts population of accessible pages.
                let _ = self.set_range_lock(a, b - a, Some(on_fault));
            }
        } else if !future {
            if let Some(ranges) = self.locks.0.get() {
                *ranges.write().unwrap() = Default::default();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlapping_locks_keep_cow_data_and_relocated_policy_but_forks_start_unlocked() {
        let mut m = Memory::default();
        let a = 0x10000;
        let b = 0x80000;
        m.map(a, 4 * PAGE_SIZE, Permissions::RW).unwrap();
        m.write(a, &[93]).unwrap();
        m.set_range_lock(a, 2 * PAGE_SIZE, Some(false)).unwrap();
        m.set_range_lock(a + PAGE_SIZE, 3 * PAGE_SIZE, Some(true))
            .unwrap();
        assert_eq!(m.resident(a, 4 * PAGE_SIZE).unwrap(), [1, 1, 0, 0]);
        assert_eq!(m.locked_bytes_in(0, ADDRESS_LIMIT), 4 * PAGE_SIZE);
        let child = m.try_fork().unwrap();
        assert_eq!(child.locked_bytes_in(0, ADDRESS_LIMIT), 0);
        m.remap(a, 4 * PAGE_SIZE, b, 5 * PAGE_SIZE, true).unwrap();
        assert_eq!(m.lock_mode_at(b), Some(false));
        assert_eq!(m.lock_mode_at(b + 4 * PAGE_SIZE), Some(true));
        assert_eq!(m.read_array::<1>(b).unwrap(), [93]);
        m.set_range_lock(b + PAGE_SIZE, PAGE_SIZE, None).unwrap();
        m.map_fixed(b, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.locked_bytes_in(0, ADDRESS_LIMIT), 3 * PAGE_SIZE);
    }
}
