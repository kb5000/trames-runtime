// SPDX-License-Identifier: GPL-3.0-or-later
//! Anonymous inaccessible ranges: virtual ownership without page allocations.
use super::*;
pub const MAX_RESERVATIONS: usize = 65_536;

impl Memory {
    pub fn virtual_bytes(&self) -> u64 {
        if let Some(shared) = &self.shared {
            return shared.borrow().virtual_bytes();
        }
        self.mapped_bytes() as u64 + self.reservations.iter().map(|(&a, &b)| b - a).sum::<u64>()
    }
    pub fn validate_mapped(&self, address: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().validate_mapped(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)
    }
    pub fn is_reserved(&self, address: u64, len: u64) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow().is_reserved(address, len);
        }
        Self::mapping_end(address, len)
            .is_ok_and(|end| self.reserved_end(address).is_some_and(|stop| stop >= end))
    }
    pub(super) fn reserved_end(&self, address: u64) -> Option<u64> {
        self.reservations
            .range(..=address)
            .next_back()
            .and_then(|(_, &end)| (address < end).then_some(end))
    }
    pub(super) fn reservation_collision_end(&self, start: u64, end: u64) -> Option<u64> {
        self.reserved_end(start).or_else(|| {
            self.reservations
                .range(start..end)
                .next()
                .map(|(_, &stop)| stop)
        })
    }
    pub(super) fn reservation_overlaps(&self, start: u64, end: u64) -> bool {
        self.reservation_collision_end(start, end).is_some()
    }
    pub(super) fn check_reservation_split(
        &self,
        start: u64,
        end: u64,
        extra: usize,
    ) -> Result<(), MemoryError> {
        if self.reservations.len() + 2 + extra <= MAX_RESERVATIONS {
            return Ok(());
        }
        let mut count = self.reservations.len() + extra;
        for (&a, &b) in self.reservations.range(..end) {
            if b > start {
                count = count - 1 + usize::from(a < start) + usize::from(b > end);
            }
        }
        if count > MAX_RESERVATIONS {
            Err(MemoryError::Limit)
        } else {
            Ok(())
        }
    }
    pub(super) fn remove_reservations(&mut self, start: u64, end: u64) -> Result<(), MemoryError> {
        self.check_reservation_split(start, end, 0)?;
        let mut overlaps: Vec<_> = self
            .reservations
            .range(start..end)
            .map(|(&a, &b)| (a, b))
            .collect();
        if let Some((&a, &b)) = self.reservations.range(..start).next_back() {
            if b > start {
                overlaps.push((a, b));
            }
        }
        if !overlaps.is_empty() && self.parallel_cache.is_some() {
            self.parallel_reservations_dirty = true;
        }
        for (a, b) in overlaps {
            self.reservations.remove(&a);
            if a < start {
                self.reservations.insert(a, start);
            }
            if b > end {
                self.reservations.insert(end, b);
            }
        }
        Ok(())
    }
    pub(super) fn missing_page(&self, address: u64, access: Access) -> MemoryError {
        if self.reserved_end(address).is_some() {
            MemoryError::Permission { address, access }
        } else {
            MemoryError::Unmapped(address)
        }
    }
    pub(super) fn check_mapped_range(&self, start: u64, end: u64) -> Result<(), MemoryError> {
        let mut address = start;
        while address < end {
            if let Some(stop) = self.reserved_end(address) {
                address = stop.min(end);
            } else if self.pages.contains_key(&address) {
                address += PAGE_SIZE;
            } else {
                return Err(MemoryError::Unmapped(address));
            }
        }
        Ok(())
    }
    /// Reserve private anonymous PROT_NONE addresses, including guard ranges.
    /// Commit through protect(); committed bytes retain the normal memory cap.
    pub fn reserve(&mut self, address: u64, len: u64, fixed: bool) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().reserve(address, len, fixed);
        }
        let end = Self::mapping_end(address, len)?;
        if !fixed && !self.is_free(address, len) {
            return Err(MemoryError::Overlap(address));
        }
        self.check_reservation_split(address, end, 1)?;
        if fixed {
            self.unmap(address, len)?;
        }
        let mut start = address;
        let mut stop = end;
        if let Some((&a, &b)) = self.reservations.range(..address).next_back() {
            if b == address {
                start = a;
                self.reservations.remove(&a);
            }
        }
        if let Some(&b) = self.reservations.get(&end) {
            stop = b;
            self.reservations.remove(&end);
        }
        self.reservations.insert(start, stop);
        if self.parallel_cache.is_some() {
            self.parallel_reservations_dirty = true;
        }
        self.revision = self.revision.wrapping_add(1);
        self.advance_code_revision();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_budget_and_commit_failures_preserve_reservations() {
        let mut m = Memory::new(PAGE_SIZE as usize);
        for i in 0..MAX_RESERVATIONS as u64 {
            let start = i * 4 * PAGE_SIZE;
            m.reservations.insert(start, start + 3 * PAGE_SIZE);
        }
        let before = m.instruction_identity();
        assert_eq!(m.unmap(PAGE_SIZE, PAGE_SIZE), Err(MemoryError::Limit));
        assert_eq!(
            m.protect(PAGE_SIZE, PAGE_SIZE, Permissions::RW),
            Err(MemoryError::Limit)
        );
        assert_eq!(m.instruction_identity(), before);
        assert_eq!(m.mapped_bytes(), 0);
        assert!(m.is_reserved(0, 3 * PAGE_SIZE));
        assert_eq!(
            m.reserve(MAX_RESERVATIONS as u64 * 4 * PAGE_SIZE, PAGE_SIZE, false),
            Err(MemoryError::Limit)
        );
        m.unmap(0, 3 * PAGE_SIZE).unwrap();
        m.reserve(MAX_RESERVATIONS as u64 * 4 * PAGE_SIZE, PAGE_SIZE, false)
            .unwrap();
    }
    #[test]
    fn large_reservation_commit_split_fork_share_and_failed_commit_are_atomic() {
        let mut m = Memory::new(2 * PAGE_SIZE as usize);
        let start = 0x10000;
        let len = MAX_DESCRIBED_BYTES as u64 + PAGE_SIZE;
        m.reserve(start, len, false).unwrap();
        assert_eq!(m.mapped_bytes(), 0);
        assert!(!m.is_free(start + PAGE_SIZE, PAGE_SIZE));
        assert_eq!(m.find_free(start, PAGE_SIZE), Some(start + len));
        assert_eq!(m.highest_mapped_end(), start + len);
        assert_eq!(
            m.read_array::<1>(start),
            Err(MemoryError::Permission {
                address: start,
                access: Access::Read
            })
        );
        assert_eq!(
            m.fetch_u32(start),
            Err(MemoryError::Permission {
                address: start,
                access: Access::Execute
            })
        );
        assert_eq!(
            m.protect(start, len, Permissions::RW),
            Err(MemoryError::Limit)
        );
        assert_eq!(m.mapped_bytes(), 0);
        m.protect(start + PAGE_SIZE, PAGE_SIZE, Permissions::RW)
            .unwrap();
        assert_eq!(m.read_u64(start + PAGE_SIZE).unwrap(), 0);
        m.write_array(start + PAGE_SIZE, 42u64.to_le_bytes())
            .unwrap();
        let mut child = m.clone();
        child.protect(start, PAGE_SIZE, Permissions::RW).unwrap();
        child
            .write_array(start + PAGE_SIZE, 99u64.to_le_bytes())
            .unwrap();
        assert_eq!(m.read_u64(start + PAGE_SIZE).unwrap(), 42);
        let mut thread = m.share();
        thread.protect(start, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.read_u64(start).unwrap(), 0);
        thread.unmap(start + 2 * PAGE_SIZE, PAGE_SIZE).unwrap();
        assert!(m.is_free(start + 2 * PAGE_SIZE, PAGE_SIZE));
        assert!(!m.is_free(start + 3 * PAGE_SIZE, PAGE_SIZE));
        thread.reserve(start + PAGE_SIZE, PAGE_SIZE, true).unwrap();
        assert_eq!(m.mapped_bytes(), PAGE_SIZE as usize);
        thread
            .protect(start + PAGE_SIZE, PAGE_SIZE, Permissions::RX)
            .unwrap();
        assert_eq!(m.fetch_u32(start + PAGE_SIZE).unwrap(), 0);
        thread.unmap(start, len).unwrap();
        assert_eq!(m.mapped_bytes(), 0);
        assert!(m.regions().is_empty());
    }
}
