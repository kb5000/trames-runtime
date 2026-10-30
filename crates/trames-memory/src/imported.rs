// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained external resource bytes use the same shared-page memory model.
use crate::*;
use std::sync::Arc;

struct ImportedPage(Arc<SharedPage>, u64);
impl PageBacking for ImportedPage {
    fn external_code_updates(&self) -> bool {
        self.0.has_external_revision()
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.0.identity, 0))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.0.clone())
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_metadata_domain(&self) -> Option<(u64, u64)> {
        // The allocation/page identity and infallible checks never change.
        // CPU bytes and their live SharedPage version are not cached here.
        Some((self.1, 0))
    }
    fn parallel_commit_isolated(&self) -> bool {
        true
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
        backing_changed();
        Ok(())
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        self.0.copy_read(offset, out);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0.copy_write(offset, bytes);
        backing_changed();
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, MemoryError> {
        self.0.with_read(offset, len, f);
        Ok(true)
    }
    fn with_write(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, MemoryError> {
        self.0.with_write(offset, len, f);
        backing_changed();
        Ok(true)
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        self.0.revision()
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}

impl Memory {
    /// Replace an already-reserved writable range with an explicit shared resource
    /// mapping. The caller must use the ordinary joined structural-change boundary.
    /// Mapping owners, not a temporary native-call lease, retain the external bytes.
    pub fn import_mapping(
        &mut self,
        address: u64,
        len: u64,
        mapping: SharedMapping,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().import_mapping(address, len, mapping);
        }
        Self::mapping_end(address, len)?;
        let n = usize::try_from(len).map_err(|_| MemoryError::InvalidRange)?;
        if !mapping
            .allocation_offset()
            .is_multiple_of(PAGE_SIZE as usize)
            || mapping
                .allocation_offset()
                .checked_add(n)
                .is_none_or(|end| end > mapping.allocation_len())
        {
            return Err(MemoryError::InvalidRange);
        }
        self.check(address, n, Access::Write)?;
        self.check(address, n, Access::Read)?;
        let domain = new_backing_identity();
        let objects = (0..n)
            .step_by(PAGE_SIZE as usize)
            .map(|offset| {
                // SAFETY: SharedMapping owns the complete stable initialized resource.
                // Every exported page uses the existing shared-region/hardware gate.
                let page = unsafe {
                    SharedPage::from_resource_mapping(
                        mapping
                            .with_offset(mapping.allocation_offset() + offset)
                            .unwrap(),
                    )
                };
                Rc::new(ImportedPage(Arc::new(page), domain)) as Rc<dyn PageBacking>
            })
            .collect();
        self.map_backed(address, objects, true, Permissions::RW, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        alloc::{alloc_zeroed, dealloc, Layout},
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct Owner {
        pointer: usize,
        layout: Layout,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            unsafe { dealloc(self.pointer as *mut u8, self.layout) };
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn mapping(drops: Arc<AtomicUsize>) -> SharedMapping {
        let size = crate::host_mapping_granule();
        let layout = Layout::from_size_align(size, size).unwrap();
        let pointer = unsafe { alloc_zeroed(layout) };
        assert!(!pointer.is_null());
        unsafe {
            SharedMapping::from_allocation(
                pointer,
                size,
                Owner {
                    pointer: pointer as usize,
                    layout,
                    drops,
                },
            )
        }
    }
    #[test]
    fn imported_bytes_are_canonical_for_cpu_views_fork_and_retained_lifetimes() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mapping = mapping(drops.clone());
        let pointer = mapping.pointer();
        let mut memory = Memory::default();
        memory.map(0x10000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        memory.import_mapping(0x10000, PAGE_SIZE, mapping).unwrap();
        memory.write(0x10000, &[7; 8]).unwrap();
        assert_eq!(unsafe { pointer.read_volatile() }, 7);
        unsafe { pointer.add(8).write_volatile(9) };
        assert_eq!(memory.read_array::<1>(0x10008).unwrap(), [9]);
        memory.write(0x11000, &[11]).unwrap();
        let mut child = memory.clone();
        child.write(0x10000, &[13]).unwrap();
        child.write(0x11000, &[17]).unwrap();
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [13]);
        assert_eq!(memory.read_array::<1>(0x11000).unwrap(), [11]);
        drop(child);
        let mut registry = crate::parallel::Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write(0x10000, &[19]).unwrap();
        assert_eq!(unsafe { pointer.read_volatile() }, 19);
        memory.unmap(0x10000, PAGE_SIZE).unwrap();
        drop(memory);
        drop(registry);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(view.read_array::<1>(0x10000).unwrap(), [19]);
        drop(view);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn import_checks_complete_geometry_and_permissions_before_replacing_bytes() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mapping = mapping(drops);
        let mut memory = Memory::default();
        memory.map(0x10000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0x10000, &[23]).unwrap();
        memory.protect(0x11000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(memory
            .import_mapping(0x10000, 2 * PAGE_SIZE, mapping.clone())
            .is_err());
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [23]);
        assert!(memory.import_mapping(0x10001, PAGE_SIZE, mapping).is_err());
        assert_eq!(memory.read_array::<1>(0x10000).unwrap(), [23]);
    }
    #[test]
    fn stable_data_domains_skip_byte_version_scans_but_executable_pages_stay_live() {
        let mapping = mapping(Arc::new(AtomicUsize::new(0)));
        let mut memory = Memory::default();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.import_mapping(0x10000, PAGE_SIZE, mapping).unwrap();
        let mut registry = crate::parallel::Registry::default();
        drop(memory.parallel_view(&mut registry).unwrap());
        memory.commit_parallel().unwrap();
        let before = registry.metrics.backing_page_checks;
        memory.write(0x10000, &[7; 4]).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<4>(0x10000).unwrap(), [7; 4]);
        let data_epoch = view.instruction_identity();
        external_memory_changed();
        assert_eq!(view.instruction_identity(), data_epoch);
        drop(view);
        assert_eq!(registry.metrics.backing_page_checks, before);
        memory.commit_parallel().unwrap();
        memory
            .protect(
                0x10000,
                PAGE_SIZE,
                Permissions {
                    execute: true,
                    ..Permissions::RW
                },
            )
            .unwrap();
        let before = memory.instruction_page_identity(0x10000).unwrap();
        memory.write(0x10000, &0xd503201fu32.to_le_bytes()).unwrap();
        assert_ne!(memory.instruction_page_identity(0x10000).unwrap(), before);
        drop(memory.parallel_view(&mut registry).unwrap());
        memory.commit_parallel().unwrap();
        let before = registry.metrics.backing_page_checks;
        backing_changed();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.fetch_u32(0x10000).unwrap(), 0xd503201f);
        assert!(registry.metrics.backing_page_checks > before);
    }
    #[test]
    fn external_publication_invalidates_serial_worker_code_and_exclusive_tokens() {
        let revision = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mapping =
            mapping(Arc::new(AtomicUsize::new(0))).with_external_revision(revision.clone());
        let pointer = mapping.pointer();
        let mut memory = Memory::default();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.import_mapping(0x10000, PAGE_SIZE, mapping).unwrap();
        memory
            .protect(
                0x10000,
                PAGE_SIZE,
                Permissions {
                    execute: true,
                    ..Permissions::RW
                },
            )
            .unwrap();
        memory.write(0x10000, &0xd503201fu32.to_le_bytes()).unwrap();
        let serial = memory.instruction_page_identity(0x10000).unwrap();
        let serial_epoch = memory.instruction_identity();
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let worker = view.instruction_page_identity(0x10000).unwrap();
        let worker_epoch = view.instruction_identity();
        let mut old = [0; 8];
        let token = view.exclusive_read(0x10000, &mut old).unwrap();
        // Simulate device-owned raw bytes followed by its Vulkan wait boundary.
        unsafe { pointer.cast::<u32>().write_volatile(0xd65f03c0) };
        revision.fetch_add(1, Ordering::Relaxed);
        external_memory_changed();
        assert_ne!(memory.instruction_identity(), serial_epoch);
        assert_ne!(view.instruction_identity(), worker_epoch);
        assert_ne!(memory.instruction_page_identity(0x10000).unwrap(), serial);
        assert_ne!(view.instruction_page_identity(0x10000).unwrap(), worker);
        assert_eq!(view.fetch_u32(0x10000).unwrap(), 0xd65f03c0);
        assert!(!view.exclusive_write(0x10000, &old, Some(token)).unwrap());
    }
}
