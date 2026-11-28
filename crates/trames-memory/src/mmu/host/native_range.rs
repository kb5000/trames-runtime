// SPDX-License-Identifier: GPL-3.0-or-later
//! Variable-sized protected operands use the original VA budget and fault table.
use super::{Budget, Reservation, BUDGET, WINDOW};
use std::ptr::NonNull;

pub(crate) struct NativeRange {
    pointer: NonNull<u8>,
    length: usize,
    granule: usize,
    registrations: Vec<usize>,
    _reservations: Vec<Reservation>,
}
impl NativeRange {
    pub fn new(length: usize) -> Option<Self> {
        Self::with_budget(length, &BUDGET)
    }
    fn with_budget(length: usize, budget: &'static Budget) -> Option<Self> {
        if length == 0 || !super::super::fault::install() {
            return None;
        }
        let granule = super::page_size()?;
        let length = length.checked_add(WINDOW - 1)? & !(WINDOW - 1);
        if length > budget.limit {
            return None;
        }
        let count = length / WINDOW;
        let mut reservations = Vec::with_capacity(count);
        for _ in 0..count {
            reservations.push(budget.acquire()?);
        }
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return None;
        }
        let Some(pointer) = NonNull::new(pointer.cast::<u8>()) else {
            unsafe { libc::munmap(pointer, length) };
            return None;
        };
        let mut result = Self {
            pointer,
            length,
            granule,
            registrations: Vec::with_capacity(count),
            _reservations: reservations,
        };
        for offset in (0..length).step_by(WINDOW) {
            result.registrations.push(super::super::fault::register(
                pointer.as_ptr() as usize + offset,
            )?);
        }
        Some(result)
    }
    pub fn address(&self) -> usize {
        self.pointer.as_ptr() as usize
    }
    pub fn length(&self) -> usize {
        self.length
    }
    fn contains(&self, offset: usize, len: usize) -> bool {
        offset.is_multiple_of(self.granule)
            && len != 0
            && len.is_multiple_of(self.granule)
            && offset <= self.length
            && len <= self.length - offset
    }
    /// Caller retains the original protected CPU-page loan and admits precisely
    /// this non-executable source interval until reset/drop, before any callback.
    pub unsafe fn alias(&mut self, offset: usize, source: usize, len: usize) -> bool {
        if !self.contains(offset, len) {
            return false;
        }
        unsafe {
            super::clone_alias(
                source as *mut _,
                self.pointer.as_ptr().add(offset).cast(),
                len,
            )
        }
    }
    pub fn read_only(&mut self, offset: usize, len: usize) -> bool {
        self.contains(offset, len)
            && unsafe {
                libc::mprotect(
                    self.pointer.as_ptr().add(offset).cast(),
                    len,
                    libc::PROT_READ,
                ) == 0
            }
    }
    /// Replace with fresh private bytes or an inaccessible guard. Replacing
    /// instead of only mprotect releases old physical aliases on pool return.
    pub fn replace(&mut self, offset: usize, len: usize, accessible: bool) -> bool {
        if !self.contains(offset, len) {
            return false;
        }
        unsafe {
            let target = self.pointer.as_ptr().add(offset).cast();
            libc::mmap(
                target,
                len,
                if accessible {
                    libc::PROT_READ | libc::PROT_WRITE
                } else {
                    libc::PROT_NONE
                },
                libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
                -1,
                0,
            ) == target
        }
    }
}
impl Drop for NativeRange {
    fn drop(&mut self) {
        for &registration in &self.registrations {
            super::super::fault::unregister(registration);
        }
        unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.length) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    #[test]
    fn variable_operands_share_the_original_budget_and_release_on_failure() {
        static BUDGET: Budget = Budget::new(3 * WINDOW);
        let first = NativeRange::with_budget(WINDOW + 1, &BUDGET).unwrap();
        assert_eq!(first.length(), 2 * WINDOW);
        assert_eq!(BUDGET.used.load(Ordering::Relaxed), 2 * WINDOW);
        assert!(NativeRange::with_budget(2 * WINDOW, &BUDGET).is_none());
        assert_eq!(BUDGET.used.load(Ordering::Relaxed), 2 * WINDOW);
        let last = NativeRange::with_budget(1, &BUDGET).unwrap();
        assert!(NativeRange::with_budget(1, &BUDGET).is_none());
        drop(first);
        drop(last);
        assert_eq!(BUDGET.used.load(Ordering::Relaxed), 0);
        assert!(NativeRange::with_budget(0, &BUDGET).is_none());
        assert!(NativeRange::with_budget(usize::MAX, &BUDGET).is_none());
    }
    #[test]
    fn canonical_aliases_and_staging_keep_guards_and_reset_physical_ownership() {
        let physical = super::super::Mapping::new().unwrap();
        let mut operand = NativeRange::new(2 * WINDOW).unwrap();
        let granule = super::super::page_size().unwrap();
        let offset = WINDOW;
        unsafe {
            physical.kernel.as_ptr().write(41);
            assert!(operand.alias(offset, physical.kernel.as_ptr() as usize, granule));
            let pointer = (operand.address() + offset) as *mut u8;
            assert_eq!(pointer.read(), 41);
            pointer.write(42);
            assert_eq!(physical.kernel.as_ptr().read(), 42);
            assert!(operand.replace(offset, granule, false));
            assert!(operand.replace(offset, granule, true));
            assert_eq!(pointer.read(), 0);
            pointer.write(43);
            assert_eq!(physical.kernel.as_ptr().read(), 42);
        }
        assert!(!operand.replace(1, granule, true));
        assert!(!operand.replace(2 * WINDOW, granule, true));
    }
}
