// SPDX-License-Identifier: GPL-3.0-or-later
//! The AIO file VMA survives fork; its current-mm context identity does not.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use trames_memory::{MappingCleanup, MappingRemap, MemoryError, PageBacking};
#[cfg(test)]
#[path = "mapping_tests.rs"]
mod tests;

pub(super) struct Mapping {
    pub(super) address: AtomicU64,
    pub(super) length: u64,
    mm: u64,
    inode: u64,
    context: Weak<Context>,
}
impl Mapping {
    pub(super) fn new(mm: u64, address: u64, length: u64, context: Weak<Context>) -> Arc<Self> {
        Arc::new(Self {
            mm,
            address: address.into(),
            length,
            context,
            inode: trames_memory::new_backing_identity(),
        })
    }
    pub(super) fn address(&self) -> u64 {
        self.address.load(Ordering::Relaxed)
    }
    pub(super) fn pages(
        self: &Arc<Self>,
        pages: &[Arc<dyn PageBacking>],
    ) -> Vec<Arc<dyn PageBacking>> {
        pages
            .iter()
            .map(|page| {
                Arc::new(Page {
                    inner: page.clone(),
                    mapping: self.clone(),
                }) as Arc<dyn PageBacking>
            })
            .collect()
    }
}
impl MappingRemap for Mapping {
    fn remapped(&self, mm: u64, address: u64) -> Result<(), MemoryError> {
        let context = self.context.upgrade().ok_or(MemoryError::BackingIo(22))?;
        let state = context.state.lock().unwrap();
        if self.mm != mm || state.dead {
            return Err(MemoryError::BackingIo(22));
        }
        self.address.store(address, Ordering::Relaxed);
        Ok(())
    }
}
impl MappingCleanup for Mapping {
    fn cleanup(&self, memory: &mut trames_memory::Memory) -> Result<(), MemoryError> {
        // Linux kill_ioctx uses the recorded mmap_base/mmap_size range, even
        // after an application has replaced pages there. Its vm_munmap return
        // is ignored; a second kill must not perform another range unmap.
        let _ = memory.unmap(self.address(), self.length);
        Ok(())
    }
}
struct Page {
    inner: Arc<dyn PageBacking>,
    mapping: Arc<Mapping>,
}
impl PageBacking for Page {
    fn expandable(&self) -> bool {
        false
    }
    fn executable(&self) -> bool {
        false
    }
    fn mapping_remap(&self) -> Option<Arc<dyn MappingRemap>> {
        Some(self.mapping.clone())
    }
    fn mapped_residents(&self) -> Option<&trames_memory::MappedResidents> {
        self.inner.mapped_residents()
    }
    fn proc_dirty(&self) -> bool {
        self.inner.proc_dirty()
    }
    fn proc_shmem_inode(&self) -> Option<u64> {
        Some(self.mapping.inode)
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        self.inner.parallel_key()
    }
    fn parallel_versioned(&self) -> bool {
        self.inner.parallel_versioned()
    }
    fn parallel_commit_isolated(&self) -> bool {
        self.inner.parallel_commit_isolated()
    }
    fn shared_page(&self) -> Option<Arc<trames_memory::SharedPage>> {
        self.inner.shared_page()
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn charge_reads(&self) -> bool {
        false
    }
    fn check(&self, address: u64) -> Result<(), MemoryError> {
        self.inner.check(address)
    }
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.inner.read(offset, bytes)
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.write(offset, bytes)
    }
    fn with_read(
        &self,
        offset: usize,
        length: usize,
        read: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, MemoryError> {
        self.inner.with_read(offset, length, read)
    }
    fn with_write(
        &self,
        offset: usize,
        length: usize,
        write: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, MemoryError> {
        self.inner.with_write(offset, length, write)
    }
    fn publish_write(&self, offset: usize, length: usize) -> Result<(), MemoryError> {
        self.inner.publish_write(offset, length)
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn version(&self) -> u64 {
        self.inner.version()
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::BackingIo(14))
    }
}
