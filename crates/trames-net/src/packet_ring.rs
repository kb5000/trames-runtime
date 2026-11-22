// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-owned AF_PACKET receive rings. Frame ownership is published through
//! the same physical pages that the interpreter and hardware executor map.
use super::{NetError, Result};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use trames_memory::{MemoryError, PageBacking, SharedPage, MAX_DESCRIBED_BYTES, PAGE_SIZE};

const PAGE: usize = PAGE_SIZE as usize;
const HEADER: usize = 32;
const SOCKADDR_END: usize = HEADER + 20;
const NET_OFFSET: usize = (SOCKADDR_END + 16).next_multiple_of(16);

pub(super) struct Ring {
    storage: Arc<Storage>,
    block: usize,
    frame: usize,
    per_block: usize,
    count: usize,
    head: usize,
    version: u32,
    net: usize,
}
struct Storage {
    id: u64,
    pages: Vec<OnceLock<Arc<SharedPage>>>,
}
impl Storage {
    fn page(&self, index: usize) -> &Arc<SharedPage> {
        self.pages[index].get_or_init(|| Arc::new(SharedPage::zero()))
    }
    fn write(&self, mut offset: usize, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let within = offset % PAGE;
            let n = bytes.len().min(PAGE - within);
            self.page(offset / PAGE).copy_write(within, &bytes[..n]);
            offset += n;
            bytes = &bytes[n..];
        }
    }
}

pub(super) enum Delivery {
    Full,
    Captured,
    Copied,
}
impl Ring {
    pub fn configure(bytes: &[u8], version: u32, reserve: u32) -> Result<Option<Self>> {
        let request: &[u8; 16] = bytes.get(..16).ok_or(NetError(22))?.try_into().unwrap();
        let [block, blocks, frame, count] = std::array::from_fn(|i| {
            u32::from_le_bytes(request[i * 4..i * 4 + 4].try_into().unwrap()) as usize
        });
        if blocks == 0 {
            return if count == 0 {
                Ok(None)
            } else {
                Err(NetError(22))
            };
        }
        let net = NET_OFFSET + reserve as usize;
        if block == 0
            || !block.is_multiple_of(PAGE)
            || !frame.is_multiple_of(16)
            || frame < SOCKADDR_END + reserve as usize
            || net > u16::MAX as usize
        {
            return Err(NetError(22));
        }
        let per_block = block / frame;
        if per_block == 0 || per_block.checked_mul(blocks) != Some(count) {
            return Err(NetError(22));
        }
        let size = block
            .checked_mul(blocks)
            .filter(|&v| v <= MAX_DESCRIBED_BYTES)
            .ok_or(NetError(12))?;
        let mut pages = Vec::new();
        pages
            .try_reserve_exact(size / PAGE)
            .map_err(|_| NetError(12))?;
        pages.resize_with(size / PAGE, OnceLock::new);
        Ok(Some(Self {
            storage: Arc::new(Storage {
                id: trames_memory::new_backing_identity(),
                pages,
            }),
            block,
            frame,
            per_block,
            count,
            head: 0,
            version,
            net,
        }))
    }
    fn offset(&self, index: usize) -> usize {
        index / self.per_block * self.block + index % self.per_block * self.frame
    }
    fn owned(&self, offset: usize) -> bool {
        let Some(page) = self.storage.pages[offset / PAGE].get() else {
            return false;
        };
        // Frame starts are 16-byte aligned, so the ABI status cell fits in one page.
        unsafe {
            if self.version == 0 {
                page.load_acquire_u64(offset % PAGE) != 0
            } else {
                page.load_acquire_u32(offset % PAGE) != 0
            }
        }
    }
    pub fn readable(&self) -> bool {
        let last = if self.head == 0 {
            self.count - 1
        } else {
            self.head - 1
        };
        self.owned(self.offset(last))
    }
    pub fn mapped(&self) -> bool {
        Arc::strong_count(&self.storage) > 1
    }
    pub fn pages(
        &self,
        owner: Arc<dyn Send + Sync>,
        len: u64,
    ) -> Result<Vec<Arc<dyn PageBacking>>> {
        if len != self.storage.pages.len() as u64 * PAGE_SIZE {
            return Err(NetError(22));
        }
        let mapping = Arc::new(Mapping {
            storage: self.storage.clone(),
            _description: owner,
        });
        Ok((0..self.storage.pages.len())
            .map(|index| {
                Arc::new(Page {
                    mapping: mapping.clone(),
                    index,
                }) as Arc<dyn PageBacking>
            })
            .collect())
    }
    pub fn receive(
        &mut self,
        bytes: &[u8],
        captured: usize,
        link_len: usize,
        address: &[u8; 20],
        copy: bool,
        losing: bool,
    ) -> Delivery {
        let start = self.offset(self.head);
        if self.owned(start) {
            return Delivery::Full;
        }
        let mac = self.net - link_len;
        let snap = captured.min(self.frame.saturating_sub(mac));
        let copied = copy && snap < captured;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut header = [0u8; SOCKADDR_END];
        let fields = if self.version == 0 { 8 } else { 4 };
        header[fields..fields + 4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        header[fields + 4..fields + 8].copy_from_slice(&(snap as u32).to_le_bytes());
        header[fields + 8..fields + 10].copy_from_slice(&(mac as u16).to_le_bytes());
        header[fields + 10..fields + 12].copy_from_slice(&(self.net as u16).to_le_bytes());
        header[fields + 12..fields + 16].copy_from_slice(&(stamp.as_secs() as u32).to_le_bytes());
        let fraction = if self.version == 0 {
            stamp.subsec_micros()
        } else {
            stamp.subsec_nanos()
        };
        header[fields + 16..fields + 20].copy_from_slice(&fraction.to_le_bytes());
        header[HEADER..].copy_from_slice(address);
        self.storage.write(start + fields, &header[fields..]);
        self.storage.write(start + mac, &bytes[..snap]);
        let status = 1 | (u32::from(copied) << 1) | (u32::from(losing) << 2) | (1 << 29);
        let page = self.storage.page(start / PAGE);
        // Release ownership only after publishing the header and all payload pages.
        unsafe {
            if self.version == 0 {
                page.store_release_u64(start % PAGE, status.into());
            } else {
                page.store_release_u32(start % PAGE, status);
            }
        }
        self.head = (self.head + 1) % self.count;
        if copied {
            Delivery::Copied
        } else {
            Delivery::Captured
        }
    }
}

struct Mapping {
    storage: Arc<Storage>,
    _description: Arc<dyn Send + Sync>,
}
struct Page {
    mapping: Arc<Mapping>,
    index: usize,
}
impl Page {
    fn bytes(&self) -> &Arc<SharedPage> {
        self.mapping.storage.page(self.index)
    }
}
impl PageBacking for Page {
    fn check(&self, _: u64) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.mapping.storage.id, self.index as u64))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.bytes().clone())
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn publish_write(&self, _: usize, _: usize) -> std::result::Result<(), MemoryError> {
        // Workers already write the canonical SharedPage. There is no file to flush.
        trames_memory::backing_changed();
        Ok(())
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_commit_isolated(&self) -> bool {
        true
    }
    fn read(&self, start: usize, dst: &mut [u8]) -> std::result::Result<(), MemoryError> {
        self.bytes().copy_read(start, dst);
        Ok(())
    }
    fn write(&self, start: usize, src: &[u8]) -> std::result::Result<(), MemoryError> {
        self.bytes().copy_write(start, src);
        Ok(())
    }
    fn with_read(
        &self,
        start: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, MemoryError> {
        self.bytes().with_read(start, len, f);
        Ok(true)
    }
    fn with_write(
        &self,
        start: usize,
        len: usize,
        f: &mut dyn FnMut(&mut [u8]),
    ) -> std::result::Result<bool, MemoryError> {
        self.bytes().with_write(start, len, f);
        Ok(true)
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        self.bytes().revision()
    }
    fn writable(&self) -> bool {
        true
    }
    fn executable(&self) -> bool {
        false
    }
    fn next_page(&self, pages: u64) -> std::result::Result<Arc<dyn PageBacking>, MemoryError> {
        let index = self
            .index
            .checked_add(pages as usize)
            .filter(|i| *i < self.mapping.storage.pages.len())
            .ok_or(MemoryError::InvalidRange)?;
        Ok(Arc::new(Self {
            mapping: self.mapping.clone(),
            index,
        }))
    }
}
