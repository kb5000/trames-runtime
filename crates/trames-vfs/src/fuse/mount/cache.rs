// SPDX-License-Identifier: GPL-3.0-or-later
//! Inode-owned clean pages and retained, independently completed read requests.
//! Mapping/writeback admission is deliberately separate from byte reception.
use super::*;
use std::sync::{Mutex, Weak};
use trames_memory::{MappedResidents, MemoryError, PageSource, PageWait, SharedPage, PAGE_SIZE};
#[cfg(test)]
#[path = "../cache_tests.rs"]
mod tests;

#[derive(Default)]
pub(super) struct Cache {
    pages: Mutex<BTreeMap<u64, Arc<Page>>>,
}
pub(super) struct Page {
    pub(super) bytes: Arc<SharedPage>,
    // The physical cache charge lives with this page, including accepted
    // sources which survive removal from the inode's current cache map.
    _owners: MappedResidents,
    state: Mutex<PageState>,
}
#[derive(Default)]
struct PageState {
    valid: bool,
    reading: Weak<ReadWave>,
}
pub(super) enum Read {
    Ready(Arc<Page>),
    Pending(Arc<ReadWave>),
}
impl Read {
    pub(super) fn result(&self) -> Option<Result<Arc<Page>>> {
        match self {
            Self::Ready(page) => Some(Ok(page.clone())),
            Self::Pending(read) => read.state.lock().unwrap().result.clone(),
        }
    }
}
pub(super) struct ReadWave {
    page: Arc<Page>,
    // Keep the original OFD, daemon FH, mount and lookup reference. Neither a
    // numerical descriptor lookup nor the replying daemon supplies this owner.
    _original: SharedFd,
    file: Arc<File>,
    offset: u64,
    count: usize,
    attr_version: u64,
    pub(super) wait: Arc<PageWait>,
    state: Mutex<ReadState>,
}
#[derive(Default)]
struct ReadState {
    result: Option<Result<Arc<Page>>>,
    request: Option<Request>,
}
impl Cache {
    fn read(
        &self,
        file: &Arc<File>,
        original: &SharedFd,
        index: u64,
    ) -> std::result::Result<Read, MemoryError> {
        let fs = &file.reference.fs;
        let caller = fs.fault_caller().map_err(|e| MemoryError::BackingIo(e.0))?;
        file.attr.check().map_err(|e| MemoryError::BackingIo(e.0))?;
        let fh = file.fh.ok_or(MemoryError::BackingIo(9))?;
        let offset = index
            .checked_mul(PAGE_SIZE)
            .filter(|offset| *offset < i64::MAX as u64)
            .ok_or(MemoryError::InvalidRange)?;
        let count = (PAGE_SIZE.min(i64::MAX as u64 - offset)) as usize;
        let page = {
            let mut pages = self.pages.lock().unwrap();
            if let Some(page) = pages.get(&index) {
                page.clone()
            } else {
                let owners = MappedResidents::default();
                owners.reserve_cache()?;
                let page = Arc::new(Page {
                    bytes: Arc::new(SharedPage::from_box(Box::new([0; PAGE_SIZE as usize]))),
                    _owners: owners,
                    state: Mutex::default(),
                });
                pages.insert(index, page.clone());
                page
            }
        };
        let read = {
            let mut state = page.state.lock().unwrap();
            if state.valid {
                return Ok(Read::Ready(page.clone()));
            }
            if let Some(read) = state.reading.upgrade().filter(|read| !read.wait.ready()) {
                return Ok(Read::Pending(read));
            }
            // A failed request remains immutable for its original waiters. A
            // later caller may retry the same physical cache page with a new
            // request; old waiters continue to observe the original error.
            let read = Arc::new(ReadWave {
                page: page.clone(),
                _original: original.clone(),
                file: file.clone(),
                offset,
                count,
                attr_version: fs.connection.current_attr_version(),
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
            let mut tail = pages.split_off(&first);
            let keep = if last == u64::MAX {
                BTreeMap::new()
            } else {
                tail.split_off(&(last + 1))
            };
            pages.extend(keep);
            tail
        };
        // Release physical charges and retained pages outside the cache lock.
        drop(retired);
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
impl transport::ReplyReceiver for ReadWave {
    fn complete(&self, result: Result<Vec<u8>>) {
        let request = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_some() {
                return;
            }
            let result = result.and_then(|bytes| {
                if bytes.len() > self.count {
                    return Err(Errno(5));
                }
                self.file.attr.check()?;
                let mut page = self.page.state.lock().unwrap();
                // No page frame is visible before successful IO. Zero only the
                // unread tail of this accepted reply, including short EOF reads.
                let mut content = [0; PAGE_SIZE as usize];
                content[..bytes.len()].copy_from_slice(&bytes);
                self.page.bytes.copy_write(0, &content);
                if bytes.len() < self.count && !self.file.reference.fs.connection.option(1 << 16) {
                    self.file.attr.read_size(
                        &self.file.reference.fs,
                        self.offset + bytes.len() as u64,
                        self.attr_version,
                    );
                }
                page.valid = true;
                Ok(self.page.clone())
            });
            state.result = Some(result);
            state.request.take()
        };
        drop(request);
        self.wait.finish();
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
            read: Mutex::default(),
        }))
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
    read: Mutex<Option<Read>>,
}
impl PageSource for Source {
    fn load(&self) -> std::result::Result<Arc<SharedPage>, MemoryError> {
        let mut slot = self.read.lock().unwrap();
        if slot.is_none() {
            *slot = Some(self.file.read_page(&self.original, self.index)?);
        }
        let read = slot.as_ref().unwrap();
        match read.result() {
            Some(Ok(page)) => Ok(page.bytes.clone()),
            Some(Err(error)) => Err(MemoryError::BackingIo(error.0)),
            None => {
                let Read::Pending(read) = read else {
                    unreachable!("a resident page has its original result")
                };
                Err(read.wait.fault(0))
            }
        }
    }
}
