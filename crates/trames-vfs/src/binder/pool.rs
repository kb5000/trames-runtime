// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only guest receive mappings over canonical, lazily materialized pages.
use super::*;
use trames_memory::{MemoryError, PageBacking, SharedPage, PAGE_SIZE};

pub(super) struct Pool {
    pub base: u64,
    pub length: usize,
    pub live: AtomicBool,
    identity: u64,
    pages: Vec<Arc<SharedPage>>,
    allocated: Mutex<BTreeMap<usize, usize>>,
}
impl Pool {
    pub fn new(base: u64, length: u64) -> Result<Arc<Self>> {
        // The Linux Binder mapping is capped at 4 MiB, irrespective of the
        // user's larger hint. Metadata reservation does not charge 4 MiB RAM.
        let length = usize::try_from(length.min(4 * 1024 * 1024)).map_err(|_| Errno(22))?;
        if length == 0 || !(length as u64).is_multiple_of(PAGE_SIZE) {
            return Err(Errno(22));
        }
        Ok(Arc::new(Self {
            base,
            length,
            live: AtomicBool::new(true),
            identity: trames_memory::new_backing_identity(),
            pages: (0..length / PAGE_SIZE as usize)
                .map(|_| Arc::new(SharedPage::zero()))
                .collect(),
            allocated: Mutex::default(),
        }))
    }
    pub fn backings(self: &Arc<Self>) -> Vec<Arc<dyn PageBacking>> {
        (0..self.pages.len())
            .map(|index| {
                Arc::new(Page {
                    pool: self.clone(),
                    index,
                }) as Arc<dyn PageBacking>
            })
            .collect()
    }
    pub fn allocate(&self, length: usize) -> Result<usize> {
        if !self.live.load(Ordering::Relaxed) {
            return Err(Errno(3));
        }
        let length = align(length.max(1))?;
        let mut allocations = self.allocated.lock().unwrap();
        let mut at = 0;
        for (&start, &size) in allocations.iter() {
            if start - at >= length {
                break;
            }
            at = start + size;
        }
        if length > self.length.saturating_sub(at) {
            return Err(Errno(28));
        }
        allocations.insert(at, length);
        Ok(at)
    }
    pub fn free(&self, offset: usize, clear: bool) {
        let mut allocations = self.allocated.lock().unwrap();
        let length = allocations.get(&offset).copied();
        if clear {
            if let Some(length) = length {
                // Reuse is published only after clearing through the original
                // page byte protocol. Caller serializes its buffer registry.
                self.copy(offset, length, |bytes, _| bytes.fill(0));
            }
        }
        allocations.remove(&offset);
    }
    pub fn write(&self, offset: usize, data: &[u8]) {
        self.copy(offset, data.len(), |bytes, at| {
            bytes.copy_from_slice(&data[at..at + bytes.len()])
        });
    }
    fn copy(&self, offset: usize, length: usize, mut copy: impl FnMut(&mut [u8], usize)) {
        assert!(offset <= self.length && length <= self.length - offset);
        let mut done = 0;
        while done < length {
            let at = offset + done;
            let within = at % PAGE_SIZE as usize;
            let size = (PAGE_SIZE as usize - within).min(length - done);
            self.pages[at / PAGE_SIZE as usize].with_write(within, size, |bytes| copy(bytes, done));
            done += size;
        }
    }
}
pub(super) fn align(value: usize) -> Result<usize> {
    value.checked_add(7).map(|v| v & !7).ok_or(Errno(22))
}
struct Page {
    pool: Arc<Pool>,
    index: usize,
}
impl PageBacking for Page {
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.pool.identity, self.index as u64))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.pool.pages[self.index].clone())
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_metadata_domain(&self) -> Option<(u64, u64)> {
        Some((self.pool.identity, 0))
    }
    fn parallel_domain_offset(&self) -> Option<u64> {
        Some(self.index as u64 * PAGE_SIZE)
    }
    fn parallel_commit_isolated(&self) -> bool {
        true
    }
    fn check(&self, _: u64) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> std::result::Result<(), MemoryError> {
        self.pool.pages[self.index].copy_read(offset, out);
        Ok(())
    }
    fn write(&self, _: usize, _: &[u8]) -> std::result::Result<(), MemoryError> {
        Err(MemoryError::BackingIo(1))
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, MemoryError> {
        self.pool.pages[self.index].with_read(offset, len, f);
        Ok(true)
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn version(&self) -> u64 {
        self.pool.pages[self.index].revision()
    }
    fn writable(&self) -> bool {
        false
    }
    fn executable(&self) -> bool {
        false
    }
    fn next_page(&self, pages: u64) -> std::result::Result<Arc<dyn PageBacking>, MemoryError> {
        let index = self
            .index
            .checked_add(pages as usize)
            .filter(|i| *i < self.pool.pages.len())
            .ok_or(MemoryError::InvalidRange)?;
        Ok(Arc::new(Self {
            pool: self.pool.clone(),
            index,
        }))
    }
}
