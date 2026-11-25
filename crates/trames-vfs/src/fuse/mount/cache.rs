// SPDX-License-Identifier: GPL-3.0-or-later
//! Inode-owned clean pages and retained, independently completed read requests.
//! Mapping/writeback admission is deliberately separate from byte reception.
use super::*;
use std::sync::{Mutex, Weak};
use trames_memory::{MappedResidents, MemoryError, PageSource, PageWait, SharedPage, PAGE_SIZE};
#[path = "read_batch.rs"]
mod batch;
#[cfg(test)]
#[path = "../cache_tests.rs"]
mod tests;

pub(super) struct Cache {
    pages: Mutex<BTreeMap<u64, Arc<Page>>>,
    mappings: std::sync::atomic::AtomicUsize,
    pub(super) identity: u64,
    pub(super) metadata_identity: u64,
    pub(super) revision: AtomicU64,
    pub(super) metadata_revision: AtomicU64,
    pub(super) writeback: Mutex<super::writeback::Queue>,
    pub(super) writers: Mutex<Vec<Weak<super::writeback::OpenWriter>>>,
    buffered_writers: Mutex<Vec<Weak<SharedOpenDescription>>>,
    // Conservative dirty-page pressure, not a completion or ownership count.
    // Repeated writes may overcount; close/sync inspect the original pages.
    pub(super) buffered_pressure: AtomicU64,
    error: Mutex<(u64, Option<Errno>)>,
    executor: Mutex<Option<Weak<dyn trames_memory::SyncExecutor>>>,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            pages: Default::default(),
            mappings: Default::default(),
            identity: trames_memory::new_backing_identity(),
            metadata_identity: trames_memory::new_backing_identity(),
            revision: AtomicU64::new(1),
            metadata_revision: AtomicU64::new(1),
            writeback: Mutex::default(),
            writers: Mutex::default(),
            buffered_writers: Mutex::default(),
            buffered_pressure: Default::default(),
            error: Mutex::default(),
            executor: Mutex::default(),
        }
    }
}
pub(super) struct Page {
    pub(super) identity: u64,
    bytes: OnceLock<Arc<SharedPage>>,
    // The physical cache charge lives with this page, including accepted
    // sources which survive removal from the inode's current cache map.
    pub(super) owners: MappedResidents,
    pub(super) dirty: AtomicU64,
    mappings: std::sync::atomic::AtomicUsize,
    state: Mutex<PageState>,
}
impl Page {
    pub(super) fn bytes(&self) -> &Arc<SharedPage> {
        self.bytes.get_or_init(|| Arc::new(SharedPage::zero()))
    }
    pub(super) fn valid(&self) -> bool {
        self.state.lock().unwrap().valid
    }
    pub(super) fn revision(&self) -> u64 {
        self.bytes.get().map_or(0, |bytes| bytes.revision())
    }
    pub(super) fn dirty(&self) -> bool {
        self.dirty.load(Ordering::Relaxed) != 0
    }
    pub(super) fn mark_dirty(&self) -> bool {
        self.dirty.fetch_add(1, Ordering::Relaxed) == 0
    }
    pub(super) fn wrote_back(&self, generation: u64) {
        if self
            .dirty
            .compare_exchange(generation, 0, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let mut state = self.state.lock().unwrap();
            if state.invalidate_after_write {
                state.valid = false;
                state.invalidate_after_write = false;
                state.generation = state.generation.wrapping_add(1);
            }
        }
    }
}
#[derive(Default)]
struct PageState {
    valid: bool,
    reading: Weak<ReadWave>,
    generation: u64,
    invalidate_after_write: bool,
}
pub(super) enum Read {
    Ready(Arc<Page>),
    Pending(Arc<ReadWave>),
}
impl Read {
    pub(super) fn take_reply(reads: &[Self], offset: u64, count: usize) -> Option<Vec<u8>> {
        let Self::Pending(first) = reads.first()? else {
            return None;
        };
        let batch = first.state.lock().unwrap()._batch.clone()?;
        for (index, read) in reads.iter().enumerate() {
            let Self::Pending(read) = read else {
                return None;
            };
            if read.offset != first.offset + index as u64 * PAGE_SIZE {
                return None;
            }
            let state = read.state.lock().unwrap();
            if !state
                ._batch
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &batch))
            {
                return None;
            }
        }
        batch.take_reply(first.offset, reads.len(), offset, count)
    }
    pub(super) fn result(&self) -> Option<Result<Arc<Page>>> {
        match self {
            Self::Ready(page) => Some(Ok(page.clone())),
            Self::Pending(read) => read.state.lock().unwrap().result.clone(),
        }
    }
    pub(super) fn copy_to(&self, offset: usize, output: &mut [u8]) -> Result<()> {
        self.output()
            .expect("accepted read completed")?
            .copy_read(offset, output);
        Ok(())
    }
    fn output(&self) -> Option<Result<Arc<SharedPage>>> {
        match self {
            Self::Ready(page) => Some(Ok(page.bytes().clone())),
            Self::Pending(read) => {
                let state = read.state.lock().unwrap();
                state.result.as_ref().map(|result| {
                    result
                        .as_ref()
                        .map(|page| {
                            state
                                .uncached
                                .as_ref()
                                .unwrap_or_else(|| page.bytes())
                                .clone()
                        })
                        .map_err(|error| *error)
                })
            }
        }
    }
}
pub(super) struct ReadWave {
    this: Weak<ReadWave>,
    executor: Option<Arc<dyn trames_memory::SyncExecutor>>,
    page: Arc<Page>,
    // Keep the original OFD, daemon FH, mount and lookup reference. Neither a
    // numerical descriptor lookup nor the replying daemon supplies this owner.
    _original: SharedFd,
    file: Arc<File>,
    offset: u64,
    count: usize,
    attr_version: u64,
    page_generation: u64,
    pub(super) wait: Arc<PageWait>,
    state: Mutex<ReadState>,
}
#[derive(Default)]
struct ReadState {
    result: Option<Result<Arc<Page>>>,
    request: Option<Request>,
    _batch: Option<Arc<batch::Batch>>,
    uncached: Option<Arc<SharedPage>>,
}
impl Cache {
    pub(super) fn bind_executor(&self, executor: &Arc<dyn trames_memory::SyncExecutor>) {
        let mut current = self.executor.lock().unwrap();
        if current.as_ref().and_then(Weak::upgrade).is_none() {
            *current = Some(Arc::downgrade(executor));
        }
    }
    pub(super) fn executor(&self) -> Option<Arc<dyn trames_memory::SyncExecutor>> {
        self.executor
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
    }
    pub(super) fn mapped(&self) -> bool {
        // The original Mapping objects own this count across VMA/view clones.
        // This remains an observation, never a substitute for Layout admission.
        self.mappings.load(Ordering::Relaxed) != 0
    }
    pub(super) fn error_sequence(&self) -> u64 {
        self.error.lock().unwrap().0
    }
    pub(super) fn record_error(&self, error: Errno) {
        let mut state = self.error.lock().unwrap();
        state.0 = state.0.wrapping_add(1);
        state.1 = Some(error);
    }
    pub(super) fn check_error(&self, seen: &AtomicU64) -> Result<()> {
        let state = self.error.lock().unwrap();
        let previous = seen.swap(state.0, Ordering::Relaxed);
        if previous != state.0 {
            if let Some(error) = state.1 {
                return Err(error);
            }
        }
        Ok(())
    }
    pub(super) fn writer(&self) -> Option<Arc<super::writeback::OpenWriter>> {
        let mut writers = self.writers.lock().unwrap();
        writers.retain(|writer| writer.strong_count() != 0);
        if let Some(writer) = writers.iter().find_map(Weak::upgrade) {
            return Some(writer);
        }
        drop(writers);
        let original = {
            let mut originals = self.buffered_writers.lock().unwrap();
            originals.retain(|open| open.strong_count() != 0);
            SharedFd {
                open: originals.iter().find_map(Weak::upgrade)?,
            }
        };
        let Some(events::SharedControl::FuseFile(file)) = &original.open.control else {
            return None;
        };
        super::writeback::OpenWriter::new(file.clone(), original, self.executor()?).ok()
    }
    pub(super) fn remember_writer(&self, original: &SharedFd) {
        let mut originals = self.buffered_writers.lock().unwrap();
        originals.retain(|open| open.strong_count() != 0);
        let weak = Arc::downgrade(&original.open);
        if !originals.iter().any(|open| open.ptr_eq(&weak)) {
            originals.push(weak);
        }
    }
    pub(super) fn dirty(&self) -> bool {
        self.pages.lock().unwrap().values().any(|page| page.dirty())
    }
    /// The server reply supplies holes; resident inode pages supply newer mmap
    /// stores. Extend a short reply only through a contiguous resident prefix.
    pub(super) fn overlay(&self, offset: u64, count: usize, bytes: &mut Vec<u8>) {
        let pages = self.pages.lock().unwrap();
        let mut done = 0;
        while done < count {
            let address = offset + done as u64;
            let at = (address % PAGE_SIZE) as usize;
            let n = (count - done).min(PAGE_SIZE as usize - at);
            if let Some(page) = pages
                .get(&(address / PAGE_SIZE))
                .filter(|page| page.valid())
            {
                if done <= bytes.len() {
                    bytes.resize(bytes.len().max(done + n), 0);
                    page.bytes().copy_read(at, &mut bytes[done..done + n]);
                }
            }
            done += n;
        }
    }
    pub(super) fn cached(&self, offset: u64, count: usize) -> Option<Vec<u8>> {
        if count == 0 && !self.mapped() {
            return None;
        }
        let mut bytes = Vec::new();
        self.overlay(offset, count, &mut bytes);
        (bytes.len() == count).then_some(bytes)
    }
    pub(super) fn retrieve(&self, offset: u64, count: usize) -> Vec<u8> {
        // Native RETRIEVE tests page-cache presence, not PageUptodate. A
        // partial STORE is observable here while ordinary reads still need
        // their full-page fill. Stop at the first absent page without filling
        // a hole from a later resident page or issuing a daemon READ.
        let pages = self.pages.lock().unwrap();
        let mut bytes = Vec::new();
        while bytes.len() < count {
            let address = offset + bytes.len() as u64;
            let Some(page) = pages.get(&(address / PAGE_SIZE)) else {
                break;
            };
            let at = (address % PAGE_SIZE) as usize;
            let n = (count - bytes.len()).min(PAGE_SIZE as usize - at);
            let start = bytes.len();
            bytes.resize(start + n, 0);
            page.bytes().copy_read(at, &mut bytes[start..]);
        }
        bytes
    }
    pub(super) fn reserve_store(&self, offset: u64, count: usize) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        for index in offset / PAGE_SIZE..=(offset + count as u64 - 1) / PAGE_SIZE {
            self.page(index)
                .owners
                .reserve_cache()
                .map_err(|error| match error {
                    MemoryError::BackingIo(code) => Errno(code),
                    _ => Errno(12),
                })?;
        }
        Ok(())
    }
    pub(super) fn store(&self, offset: u64, bytes: &[u8], size: u64) {
        let mut done = 0;
        while done < bytes.len() {
            let address = offset + done as u64;
            let at = (address % PAGE_SIZE) as usize;
            let n = (bytes.len() - done).min(PAGE_SIZE as usize - at);
            let page = self.page(address / PAGE_SIZE);
            let mut state = page.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.reading = Weak::new();
            page.bytes().copy_write(at, &bytes[done..done + n]);
            if !state.valid && at == 0 && (n == PAGE_SIZE as usize || address + n as u64 == size) {
                page.bytes()
                    .with_write(n, PAGE_SIZE as usize - n, |tail| tail.fill(0));
                state.valid = true;
            }
            if page.dirty() {
                page.mark_dirty();
            }
            done += n;
        }
        self.changed(true);
    }
    pub(super) fn written(&self, offset: u64, bytes: &[u8]) {
        let pages = self.pages.lock().unwrap();
        let mut done = 0;
        while done < bytes.len() {
            let address = offset + done as u64;
            let at = (address % PAGE_SIZE) as usize;
            let n = (bytes.len() - done).min(PAGE_SIZE as usize - at);
            if let Some(page) = pages.get(&(address / PAGE_SIZE)) {
                let mut state = page.state.lock().unwrap();
                state.generation = state.generation.wrapping_add(1);
                state.reading = Weak::new();
                if state.valid || at == 0 && n == PAGE_SIZE as usize {
                    page.bytes().copy_write(at, &bytes[done..done + n]);
                    state.valid = true;
                    if page.dirty() {
                        page.mark_dirty();
                    }
                }
            }
            done += n;
        }
        self.changed(true);
    }
    /// Admit the original cache page before a buffered write. Only an overwrite
    /// of all existing bytes may initialize a cold page without a daemon READ.
    pub(super) fn prepare_write(
        &self,
        file: &Arc<File>,
        original: &SharedFd,
        index: u64,
        range: (u64, u64),
        size: u64,
        caller: Caller,
    ) -> std::result::Result<Read, MemoryError> {
        let (start, end) = range;
        let page = self.page(index);
        let offset = index * PAGE_SIZE;
        {
            let state = page.state.lock().unwrap();
            if !state.valid
                && (offset >= size || start <= offset && end >= size.min(offset + PAGE_SIZE))
            {
                page.owners.reserve_cache()?;
                // Reservation is not publication. A different edge page can
                // still fail or be cancelled before this write is accepted.
                return Ok(Read::Ready(page.clone()));
            }
        }
        self.read_from_as(file, original, index, page, caller)
    }
    pub(super) fn buffered_write(&self, offset: u64, bytes: &[u8]) {
        let mut done = 0;
        while done < bytes.len() {
            let address = offset + done as u64;
            let at = (address % PAGE_SIZE) as usize;
            let count = (bytes.len() - done).min(PAGE_SIZE as usize - at);
            let page = self.page(address / PAGE_SIZE);
            let mut state = page.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.reading = Weak::new();
            let mut installed = false;
            let storage = page.bytes.get_or_init(|| {
                installed = true;
                let mut content = [0; PAGE_SIZE as usize];
                content[at..at + count].copy_from_slice(&bytes[done..done + count]);
                Arc::new(SharedPage::new(content))
            });
            if !installed {
                if state.valid {
                    storage.copy_write(at, &bytes[done..done + count]);
                } else {
                    storage.with_write(0, PAGE_SIZE as usize, |page| {
                        page[..at].fill(0);
                        page[at..at + count].copy_from_slice(&bytes[done..done + count]);
                        page[at + count..].fill(0);
                    });
                }
            }
            state.valid = true;
            page.mark_dirty();
            done += count;
        }
        self.changed(true);
    }
    pub(super) fn zero(&self, offset: u64, length: u64) {
        let end = offset + length;
        let pages = self.pages.lock().unwrap();
        for (&index, page) in pages.range(offset / PAGE_SIZE..=(end - 1) / PAGE_SIZE) {
            let start = index * PAGE_SIZE;
            let at = offset.saturating_sub(start) as usize;
            let count = (end - start).min(PAGE_SIZE) as usize - at;
            let mut state = page.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.reading = Weak::new();
            if state.valid {
                page.bytes().with_write(at, count, |bytes| bytes.fill(0));
                if page.dirty() {
                    page.mark_dirty();
                }
            }
        }
        drop(pages);
        self.changed(true);
    }
    /// Truncation discards dirty bytes past EOF, retaining dirty prefix bytes.
    /// A mapping keeps its physical identity so existing CPU views see the tail
    /// zeroing and SIGBUS checks use the new inode size.
    pub(super) fn resize(&self, old: u64, size: u64) {
        let pages = self.pages.lock().unwrap();
        for (&index, page) in pages.iter() {
            let start = index * PAGE_SIZE;
            let mut state = page.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.reading = Weak::new();
            if start >= size {
                page.dirty.store(0, Ordering::Relaxed);
                state.valid = false;
                state.invalidate_after_write = false;
            } else if state.valid && size < start + PAGE_SIZE {
                let tail = (size - start) as usize;
                page.bytes()
                    .with_write(tail, PAGE_SIZE as usize - tail, |bytes| bytes.fill(0));
                if page.dirty() {
                    page.mark_dirty();
                }
            } else if state.valid && old < size && old > start && old < start + PAGE_SIZE {
                let tail = (old - start) as usize;
                page.bytes()
                    .with_write(tail, PAGE_SIZE as usize - tail, |bytes| bytes.fill(0));
            }
        }
        drop(pages);
        self.changed(true);
    }
    fn page_locked(pages: &mut BTreeMap<u64, Arc<Page>>, index: u64) -> Arc<Page> {
        pages
            .entry(index)
            .or_insert_with(|| {
                Arc::new(Page {
                    identity: trames_memory::new_backing_identity(),
                    bytes: OnceLock::new(),
                    owners: Default::default(),
                    dirty: Default::default(),
                    mappings: Default::default(),
                    state: Mutex::default(),
                })
            })
            .clone()
    }
    pub(super) fn page(&self, index: u64) -> Arc<Page> {
        Self::page_locked(&mut self.pages.lock().unwrap(), index)
    }
    pub(super) fn mapped_page(&self, index: u64) -> Arc<Page> {
        let mut pages = self.pages.lock().unwrap();
        let page = Self::page_locked(&mut pages, index);
        self.mappings.fetch_add(1, Ordering::Relaxed);
        page.mappings.fetch_add(1, Ordering::Relaxed);
        page
    }
    pub(super) fn release_mapping(&self, page: &Page) {
        page.mappings.fetch_sub(1, Ordering::Relaxed);
        self.mappings.fetch_sub(1, Ordering::Relaxed);
    }
    pub(super) fn dirty_pages(&self) -> Vec<(u64, Arc<Page>)> {
        self.pages
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, page)| page.dirty())
            .map(|(&index, page)| (index, page.clone()))
            .collect()
    }
    pub(super) fn changed(&self, metadata: bool) {
        self.revision.fetch_add(1, Ordering::Relaxed);
        if metadata {
            self.metadata_revision.fetch_add(1, Ordering::Relaxed);
        }
        trames_memory::backing_changed();
    }
    fn read(
        &self,
        file: &Arc<File>,
        original: &SharedFd,
        index: u64,
    ) -> std::result::Result<Read, MemoryError> {
        self.read_from(file, original, index, self.page(index))
    }
    fn read_from(
        &self,
        file: &Arc<File>,
        original: &SharedFd,
        index: u64,
        page: Arc<Page>,
    ) -> std::result::Result<Read, MemoryError> {
        let caller = file
            .reference
            .fs
            .fault_caller()
            .map_err(|e| MemoryError::BackingIo(e.0))?;
        self.read_from_as(file, original, index, page, caller)
    }
    fn read_from_as(
        &self,
        file: &Arc<File>,
        original: &SharedFd,
        index: u64,
        page: Arc<Page>,
        caller: Caller,
    ) -> std::result::Result<Read, MemoryError> {
        let fs = &file.reference.fs;
        file.attr.check().map_err(|e| MemoryError::BackingIo(e.0))?;
        let fh = file.fh.unwrap_or(0);
        let offset = index
            .checked_mul(PAGE_SIZE)
            .filter(|offset| *offset < i64::MAX as u64)
            .ok_or(MemoryError::InvalidRange)?;
        let count = (PAGE_SIZE.min(i64::MAX as u64 - offset)) as usize;
        let read = {
            let mut state = page.state.lock().unwrap();
            if state.valid {
                return Ok(Read::Ready(page.clone()));
            }
            if let Some(read) = state.reading.upgrade().filter(|read| !read.wait.ready()) {
                return Ok(Read::Pending(read));
            }
            page.owners.reserve_cache()?;
            // A failed request remains immutable for its original waiters. A
            // later caller may retry the same physical cache page with a new
            // request; old waiters continue to observe the original error.
            let read = Arc::new_cyclic(|this| ReadWave {
                this: this.clone(),
                executor: crate::file_actor::sync_executor().or_else(|| self.executor()),
                page: page.clone(),
                _original: original.clone(),
                file: file.clone(),
                offset,
                count,
                attr_version: fs.connection.current_attr_version(),
                page_generation: state.generation,
                wait: Arc::default(),
                state: Mutex::default(),
            });
            state.reading = Arc::downgrade(&read);
            read
        };
        let mut body = [0; 40];
        body[..8].copy_from_slice(&fh.to_le_bytes());
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..20].copy_from_slice(&(count as u32).to_le_bytes());
        body[32..36].copy_from_slice(&file.current_flags().to_le_bytes());
        let receiver: Arc<dyn transport::ReplyReceiver> = read.clone();
        let request = fs.connection.request_received(
            15,
            file.reference.node,
            caller,
            &body,
            Arc::downgrade(&receiver),
        );
        match request {
            Ok(request) => read.install(request),
            Err(error) => transport::ReplyReceiver::complete(read.as_ref(), Err(error)),
        }
        Ok(Read::Pending(read))
    }
    /// Remove current cache identities. Outstanding readers own their old page
    /// and reply; a delayed reply cannot repopulate this map after invalidation.
    /// Mapping and dirty-page invalidation must join this before mmap admission.
    pub(super) fn invalidate(&self, offset: u64, length: u64) {
        if length == 0 {
            return;
        }
        let first = offset / PAGE_SIZE;
        let last = offset.saturating_add(length - 1) / PAGE_SIZE;
        let retired = {
            let mut pages = self.pages.lock().unwrap();
            let keys: Vec<_> = pages.range(first..=last).map(|(&index, _)| index).collect();
            let mut retired = Vec::new();
            for index in keys {
                let page = &pages[&index];
                if page.mappings.load(Ordering::Relaxed) != 0 || page.dirty() {
                    let mut state = page.state.lock().unwrap();
                    state.generation = state.generation.wrapping_add(1);
                    state.reading = Weak::new();
                    if page.dirty() {
                        state.invalidate_after_write = true;
                    } else {
                        state.valid = false;
                    }
                } else {
                    retired.push(pages.remove(&index).unwrap());
                }
            }
            retired
        };
        // Release physical charges and retained pages outside the cache lock.
        drop(retired);
        self.changed(true);
    }
    pub(super) fn invalidate_all(&self) {
        self.invalidate(0, u64::MAX);
    }
}
impl ReadWave {
    fn install(&self, request: Request) {
        // A daemon can complete after publication but before request_received
        // returns. In that case do not retain the already completed handle.
        let retired = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_some() {
                Some(request)
            } else {
                state.request = Some(request);
                None
            }
        };
        drop(retired);
    }
}
struct Publish {
    read: Arc<ReadWave>,
    result: Mutex<Option<Result<Vec<u8>>>>,
}
impl trames_memory::SyncResource for Publish {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        Some(self.read.file.attr.layout.clone())
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        if let Some(result) = self.result.lock().unwrap().take() {
            self.read.publish(result);
        }
        Ok(())
    }
}
struct Published(Arc<ReadWave>);
impl trames_memory::SyncCompletion for Published {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        if result.is_err() {
            self.0.publish(Err(Errno(5)));
        }
    }
}
impl transport::ReplyReceiver for ReadWave {
    fn complete(&self, result: Result<Vec<u8>>) {
        if let Some(executor) = self
            .executor
            .as_ref()
            .filter(|_| self.file.attr.cache.mapped())
        {
            if let Some(read) = self.this.upgrade() {
                executor.submit(
                    Arc::new(Publish {
                        read: read.clone(),
                        result: Mutex::new(Some(result)),
                    }),
                    Box::new(Published(read)),
                );
                return;
            }
        }
        self.publish(result);
    }
}
impl ReadWave {
    fn publish(&self, result: Result<Vec<u8>>) {
        self.publish_bytes(result.as_ref().map(Vec::as_slice).map_err(|error| *error));
    }
    fn publish_bytes(&self, result: Result<&[u8]>) -> bool {
        let mut compatible = false;
        let (request, compatible) = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_some() {
                return false;
            }
            let result = result.and_then(|bytes| {
                if bytes.len() > self.count {
                    return Err(Errno(5));
                }
                self.file.attr.check()?;
                let mut page = self.page.state.lock().unwrap();
                if page.generation != self.page_generation || self.page.dirty() {
                    // Mapped identities retain their physical page. A stale
                    // reply cannot replace a newer write or refill a page that
                    // was invalidated after this accepted read began.
                    if !page.valid && !self.page.dirty() {
                        let mut content = [0; PAGE_SIZE as usize];
                        content[..bytes.len()].copy_from_slice(bytes);
                        state.uncached = Some(Arc::new(SharedPage::new(content)));
                        compatible = true;
                    }
                    return Ok(self.page.clone());
                }
                // No page frame is visible before successful IO. Zero only the
                // unread tail of this accepted reply, including short EOF reads.
                let mut content = [0; PAGE_SIZE as usize];
                content[..bytes.len()].copy_from_slice(bytes);
                compatible = true;
                if self.page.mappings.load(Ordering::Relaxed) != 0
                    || self.file.reference.fs.connection.option(1 << 16)
                {
                    let size = u64::from_le_bytes(
                        self.file.attr.lock().unwrap()[8..16].try_into().unwrap(),
                    );
                    let count = size.saturating_sub(self.offset).min(PAGE_SIZE) as usize;
                    compatible = bytes.len() <= count;
                    content[count..].fill(0);
                }
                let mut installed = false;
                let storage = self.page.bytes.get_or_init(|| {
                    installed = true;
                    Arc::new(SharedPage::new(content))
                });
                if !installed {
                    storage.copy_write(0, &content);
                }
                page.valid = true;
                drop(page);
                if bytes.len() < self.count && !self.file.reference.fs.connection.option(1 << 16) {
                    self.file.attr.read_size(
                        &self.file.reference.fs,
                        self.offset + bytes.len() as u64,
                        self.attr_version,
                    );
                }
                self.file.attr.cache.changed(true);
                Ok(self.page.clone())
            });
            let compatible = compatible && result.is_ok();
            state.result = Some(result);
            (state.request.take(), compatible)
        };
        drop(request);
        self.wait.finish();
        compatible
    }
}
impl Drop for ReadWave {
    fn drop(&mut self) {
        let request = self.state.get_mut().unwrap().request.take();
        drop(request);
        self.wait.finish();
    }
}
impl File {
    pub(crate) fn page_source(
        self: &Arc<Self>,
        original: SharedFd,
        offset: u64,
    ) -> Result<Arc<dyn PageSource>> {
        if !fd_can_read(original.open.flags.get()) {
            return Err(Errno(9));
        }
        if self.directory {
            return Err(Errno(21));
        }
        if !offset.is_multiple_of(PAGE_SIZE) || offset >= i64::MAX as u64 {
            return Err(Errno(22));
        }
        Ok(Arc::new(Source {
            file: self.clone(),
            original,
            index: offset / PAGE_SIZE,
            page: None,
            read: Mutex::default(),
        }))
    }

    pub(super) fn cached_source(
        self: &Arc<Self>,
        original: SharedFd,
        index: u64,
        page: Arc<Page>,
    ) -> Arc<dyn PageSource> {
        Arc::new(Source {
            file: self.clone(),
            original,
            index,
            page: Some(page),
            read: Mutex::default(),
        })
    }

    pub(super) fn read_page(
        self: &Arc<Self>,
        original: &SharedFd,
        index: u64,
    ) -> std::result::Result<Read, MemoryError> {
        if self.directory {
            return Err(MemoryError::BackingIo(21));
        }
        if !matches!(&original.open.control, Some(events::SharedControl::FuseFile(file)) if Arc::ptr_eq(file, self))
        {
            return Err(MemoryError::BackingIo(9));
        }
        self.attr.cache.read(self, original, index)
    }
}

/// An accepted page resource, not a numeric FD lookup or a mapping grant.
/// First use submits through the original connection on the existing worker;
/// Pending hands control back to the existing PageWait execution route.
struct Source {
    file: Arc<File>,
    original: SharedFd,
    index: u64,
    page: Option<Arc<Page>>,
    read: Mutex<BTreeMap<u32, Read>>,
}
impl PageSource for Source {
    fn load(&self) -> std::result::Result<Arc<SharedPage>, MemoryError> {
        let actor = if self.page.is_some() {
            crate::file_actor::current().map_or(0, |(_, tid)| tid)
        } else {
            0
        };
        let mut reads = self.read.lock().unwrap();
        if let Some(page) = &self.page {
            if page.valid() {
                reads.remove(&actor);
                return Ok(page.bytes().clone());
            }
        }
        let slot = reads.get(&actor);
        let invalidated = self.page.is_some()
            && slot
                .and_then(Read::result)
                .is_some_and(|result| result.is_ok_and(|page| !page.valid()));
        if slot.is_none() || invalidated {
            let read = match &self.page {
                Some(page) => self.file.attr.cache.read_from(
                    &self.file,
                    &self.original,
                    self.index,
                    page.clone(),
                )?,
                None => self.file.read_page(&self.original, self.index)?,
            };
            reads.insert(actor, read);
        }
        let read = reads.get(&actor).unwrap();
        // A non-mapping source owns the accepted output even if a notification
        // retires its cache generation. Mapping faults still revalidate below.
        if self.page.is_none() {
            if let Some(result) = read.output() {
                return result.map_err(|error| MemoryError::BackingIo(error.0));
            }
        }
        let result = match read.result() {
            Some(Ok(page)) if self.page.is_none() || page.valid() => Ok(page.bytes().clone()),
            Some(Ok(_)) => {
                let Read::Pending(read) = read else {
                    unreachable!("invalidated read wave")
                };
                Err(read.wait.fault(0))
            }
            Some(Err(error)) => Err(MemoryError::BackingIo(error.0)),
            None => {
                let Read::Pending(read) = read else {
                    unreachable!("a resident page has its original result")
                };
                Err(read.wait.fault(0))
            }
        };
        // Each faulting TID observes its own accepted failure once. Another
        // waiter's retry cannot replace that result; later faults can retry.
        if self.page.is_some() && !matches!(result, Err(MemoryError::Pending(_))) {
            reads.remove(&actor);
        }
        result
    }
}
