// SPDX-License-Identifier: GPL-3.0-or-later
//! Demand-read MAP_PRIVATE pages. Guest COW owns writes; native bytes and the
//! ordinary inode's I/O cache are never replaced by private mapping snapshots.
use super::*;
use std::os::unix::fs::FileExt;
use trames_memory::{MemoryError, PageBacking, PageSource, SharedPage, PAGE_SIZE};

// One mapping's page-in metadata, not a byte-coherence mechanism. Physical
// identities remain per page; immutable private source bytes never change.
struct LoadDomain {
    identity: u64,
    host: Arc<HostFile>,
    generation: AtomicU64,
    changes: Mutex<VecDeque<LoadedRange>>,
}
struct LoadedRange {
    before: u64,
    after: u64,
    bytes: std::ops::Range<u64>,
}
impl LoadDomain {
    fn revision(&self) -> u64 {
        self.generation
            .load(Ordering::Relaxed)
            .wrapping_add(self.host.length_generation.load(Ordering::Relaxed))
    }
    fn loaded(&self, offset: u64) {
        // Only first page-in records a range, under this mapping's own lock.
        // Capture EOF once: a concurrent resize must leave a token gap, never
        // be accidentally covered by a page-in range.
        let mut changes = self.changes.lock().unwrap();
        let before = self.revision();
        self.generation.fetch_add(1, Ordering::Relaxed);
        let after = before.wrapping_add(1);
        if let Some(last) = changes
            .back_mut()
            .filter(|c| c.after == before && c.bytes.end == offset)
        {
            last.after = after;
            last.bytes.end = offset + PAGE_SIZE;
        } else {
            changes.push_back(LoadedRange {
                before,
                after,
                bytes: offset..offset + PAGE_SIZE,
            });
            if changes.len() > 128 {
                changes.pop_front();
            }
        }
    }
    fn changes_since(&self, generation: u64) -> Option<Vec<std::ops::Range<u64>>> {
        let changes = self.changes.lock().unwrap();
        let current = self.revision();
        if current == generation {
            return Some(Vec::new());
        }
        let start = changes.iter().position(|change| {
            generation.wrapping_sub(change.before) < change.after.wrapping_sub(change.before)
        })?;
        let mut expected = changes[start].before;
        let mut ranges = Vec::new();
        for change in changes.iter().skip(start) {
            if change.before != expected {
                return None;
            }
            ranges.push(change.bytes.clone());
            expected = change.after;
        }
        (expected == current).then_some(ranges)
    }
}
struct Source {
    file: Arc<OpenFile>,
    offset: u64,
    bytes: std::sync::OnceLock<Arc<SharedPage>>,
    domain: Arc<LoadDomain>,
}
impl PageSource for Source {
    fn load(&self) -> std::result::Result<Arc<SharedPage>, MemoryError> {
        if let Some(page) = self.bytes.get() {
            return Ok(page.clone());
        }
        let mut bytes = Box::new([0; PAGE_SIZE as usize]);
        let count = self
            .file
            .file
            .read_at(bytes.as_mut_slice(), self.offset)
            .map_err(|error| MemoryError::BackingIo(errno(error).0))?;
        if count == 0 {
            return Err(MemoryError::Bus(0));
        }
        if self
            .bytes
            .set(Arc::new(SharedPage::from_box(bytes)))
            .is_ok()
        {
            self.domain.loaded(self.offset);
            trames_memory::backing_changed();
        }
        Ok(self.bytes.get().expect("published private source").clone())
    }
}
struct PrivatePage {
    open: Arc<SharedOpenDescription>,
    source: Arc<Source>,
    identity: u64,
    executable: bool,
}
impl PrivatePage {
    fn new(
        open: Arc<SharedOpenDescription>,
        file: Arc<OpenFile>,
        domain: Arc<LoadDomain>,
        offset: u64,
        executable: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            open,
            source: Arc::new(Source {
                file,
                offset,
                bytes: std::sync::OnceLock::new(),
                domain,
            }),
            identity: trames_memory::new_backing_identity(),
            executable,
        })
    }
}
impl PageBacking for PrivatePage {
    fn sync_required(&self) -> bool {
        false
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.identity, 0))
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_change_domain(&self) -> Option<(u64, u64)> {
        Some((self.source.domain.identity, self.source.domain.revision()))
    }
    fn parallel_domain_offset(&self) -> Option<u64> {
        Some(self.source.offset)
    }
    fn parallel_changes_since(&self, generation: u64) -> Option<Vec<std::ops::Range<u64>>> {
        self.source.domain.changes_since(generation)
    }
    fn parallel_commit_isolated(&self) -> bool {
        true
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        self.source.bytes.get().cloned()
    }
    fn page_source(&self) -> Option<Arc<dyn PageSource>> {
        Some(self.source.clone())
    }
    fn native_resident(&self) -> bool {
        self.source.bytes.get().is_some()
    }
    fn check(&self, address: u64) -> std::result::Result<(), MemoryError> {
        if self.source.offset / PAGE_SIZE
            >= self
                .source
                .domain
                .host
                .length
                .load(Ordering::Relaxed)
                .div_ceil(PAGE_SIZE)
        {
            return Err(MemoryError::Bus(address));
        }
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> std::result::Result<(), MemoryError> {
        self.source.load()?.copy_read(offset, out);
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, MemoryError> {
        self.source.load()?.with_read(offset, len, f);
        Ok(true)
    }
    fn write(&self, _: usize, _: &[u8]) -> std::result::Result<(), MemoryError> {
        Err(MemoryError::BackingIo(13))
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        self.source
            .domain
            .host
            .length_generation
            .load(Ordering::Relaxed)
            .wrapping_mul(2)
            .wrapping_add(u64::from(self.source.bytes.get().is_some()))
    }
    fn writable(&self) -> bool {
        false
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn next_page(&self, pages: u64) -> std::result::Result<Arc<dyn PageBacking>, MemoryError> {
        let offset = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|n| self.source.offset.checked_add(n))
            .ok_or(MemoryError::InvalidRange)?;
        Ok(Self::new(
            self.open.clone(),
            self.source.file.clone(),
            self.source.domain.clone(),
            offset,
            self.executable,
        ))
    }
}
pub(crate) fn pages(
    open: Arc<SharedOpenDescription>,
    file: Arc<OpenFile>,
    host: Arc<HostFile>,
    offset: u64,
    len: u64,
    executable: bool,
) -> Result<Vec<Arc<dyn PageBacking>>> {
    let end = offset
        .checked_add(len)
        .filter(|&end| end <= i64::MAX as u64)
        .ok_or(Errno(22))?;
    host.publish_length(file.file.metadata().map_err(errno)?.len());
    let domain = Arc::new(LoadDomain {
        identity: trames_memory::new_backing_identity(),
        host,
        generation: AtomicU64::new(0),
        changes: Mutex::default(),
    });
    Ok((offset..end)
        .step_by(PAGE_SIZE as usize)
        .map(|at| {
            PrivatePage::new(open.clone(), file.clone(), domain.clone(), at, executable)
                as Arc<dyn PageBacking>
        })
        .collect())
}
