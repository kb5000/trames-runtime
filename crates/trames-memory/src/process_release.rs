// SPDX-License-Identifier: GPL-3.0-or-later
//! OOM reaping drops private PTE/storage leases, retaining the virtual layout
//! and shared providers. Callers admit only a dying original mm.
use crate::*;
impl MemoryReport {
    pub fn process_reaped(&self) -> bool {
        self.0.process_reaped.load(Ordering::Relaxed)
    }
}
impl Memory {
    pub fn release_process_memory(&mut self) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().release_process_memory();
        }
        if !self.parallel_views_quiescent() {
            return Err(MemoryError::BackingIo(11));
        }
        let report = self.memory_report();
        if report.process_reaped() {
            return Ok(());
        }
        // Committed snapshots and read exports retain real bytes. Revoke them
        // before reporting completion; a separately accepted external pin still
        // owns its own lease, just as a Linux pinned page does.
        drop(self.parallel_cache.take());
        let regions = self.regions();
        for (base, end, _) in regions {
            self.discard_for_reaper(base, end - base)?;
        }
        report.0.process_reaped.store(true, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_reap_releases_actual_storage_preserves_fork_and_is_idempotent() {
        let mut memory = Memory::default();
        memory
            .map(0x10000, PAGE_SIZE * 32, Permissions::RW)
            .unwrap();
        memory.write(0x11000, b"retained child bytes").unwrap();
        let child = memory.clone();
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        memory.release_process_memory().unwrap();
        assert!(memory.memory_report().process_reaped());
        assert_eq!(memory.resident_bytes(), 0);
        assert_eq!(
            memory.read_array::<1>(0x11000),
            Err(MemoryError::Bus(0x11000))
        );
        assert_eq!(
            child.read_array::<20>(0x11000).unwrap(),
            *b"retained child bytes"
        );
        assert_eq!(memory.virtual_bytes(), PAGE_SIZE * 32);
        memory.release_process_memory().unwrap();
        assert_eq!(memory.resident_bytes(), 0);
    }
}
