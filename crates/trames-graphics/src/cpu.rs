// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical guest pages alias the retained native plane, including across mms.
use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
};
use trames_memory::{MemoryError, PageBacking, SharedPage, PAGE_SIZE};
pub(super) struct Plane {
    address: usize,
    length: usize,
    offset: usize,
    size: usize,
    owner: Arc<dyn Send + Sync>,
    identity: u64,
    epoch: Arc<AtomicU64>,
    pages: Mutex<Vec<Weak<SharedPage>>>,
}
impl Plane {
    /// # Safety
    /// The retained owner keeps the page-aligned native allocation live and
    /// stationary. Its initialized bytes include every exposed guest page.
    pub(super) unsafe fn new(
        address: usize,
        length: usize,
        offset: usize,
        size: usize,
        owner: Arc<dyn Send + Sync>,
    ) -> Self {
        Self {
            address,
            length,
            offset,
            size,
            owner,
            identity: trames_memory::new_backing_identity(),
            epoch: Arc::default(),
            pages: Mutex::new(
                (0..size.div_ceil(PAGE_SIZE as usize))
                    .map(|_| Weak::new())
                    .collect(),
            ),
        }
    }
    pub(super) fn pages(
        self: &Arc<Self>,
        offset: u64,
        length: u64,
    ) -> io::Result<Vec<Arc<dyn PageBacking>>> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::from_raw_os_error(22))?;
        if !offset.is_multiple_of(PAGE_SIZE)
            || !length.is_multiple_of(PAGE_SIZE)
            || end > self.size.div_ceil(PAGE_SIZE as usize) as u64 * PAGE_SIZE
        {
            return Err(io::Error::from_raw_os_error(22));
        }
        let mut cache = self.pages.lock().unwrap();
        let mut result = Vec::new();
        for offset in (offset..end).step_by(PAGE_SIZE as usize) {
            let slot = &mut cache[(offset / PAGE_SIZE) as usize];
            let page = slot.upgrade().unwrap_or_else(|| {
                // SAFETY: the native allocation and plane geometry were checked
                // at adoption; all aliases use this one canonical page cache.
                let page = Arc::new(unsafe {
                    SharedPage::from_shared_mapping(
                        self.address as *mut u8,
                        self.length,
                        self.offset + offset as usize,
                        self.owner.clone(),
                    )
                });
                *slot = Arc::downgrade(&page);
                page
            });
            result.push(Arc::new(Page {
                plane: self.clone(),
                page,
                offset,
            }) as Arc<dyn PageBacking>);
        }
        Ok(result)
    }
}
struct Page {
    plane: Arc<Plane>,
    page: Arc<SharedPage>,
    offset: u64,
}
impl PageBacking for Page {
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.plane.identity, self.offset))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.page.clone())
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_metadata_domain(&self) -> Option<(u64, u64)> {
        Some((self.plane.identity, 0))
    }
    fn parallel_commit_isolated(&self) -> bool {
        true
    }
    fn parallel_domain_offset(&self) -> Option<u64> {
        Some(self.offset)
    }
    fn hardware_write_epoch(&self) -> Option<Arc<AtomicU64>> {
        Some(self.plane.epoch.clone())
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        self.page.copy_read(offset, out);
        Ok(())
    }
    fn write(&self, offset: usize, input: &[u8]) -> Result<(), MemoryError> {
        self.page.copy_write(offset, input);
        self.publish_write(offset, input.len())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, MemoryError> {
        self.page.with_read(offset, len, f);
        Ok(true)
    }
    fn with_write(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, MemoryError> {
        self.page.with_write(offset, len, f);
        self.publish_write(offset, len)?;
        Ok(true)
    }
    fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
        self.plane.epoch.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn version(&self) -> u64 {
        self.page
            .revision()
            .wrapping_add(self.plane.epoch.load(Ordering::Relaxed))
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn writable(&self) -> bool {
        true
    }
    fn executable(&self) -> bool {
        false
    }
    fn next_page(&self, pages: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        self.plane
            .pages(self.offset + pages * PAGE_SIZE, PAGE_SIZE)
            .map_err(|_| MemoryError::BackingIo(22))?
            .pop()
            .ok_or(MemoryError::BackingIo(22))
    }
}
