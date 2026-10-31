// SPDX-License-Identifier: GPL-3.0-or-later
//! Demand-read MAP_PRIVATE pages. Guest COW owns writes; native bytes and the
//! ordinary inode's I/O cache are never replaced by private mapping snapshots.
use super::*;
use std::os::unix::fs::FileExt;
use trames_memory::{MemoryError, PageBacking, PageSource, SharedPage, PAGE_SIZE};

struct Source {
    file: Arc<OpenFile>,
    offset: u64,
    bytes: std::sync::OnceLock<Arc<SharedPage>>,
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
            trames_memory::backing_changed();
        }
        Ok(self.bytes.get().expect("published private source").clone())
    }
}
struct PrivatePage {
    open: OpenHandle,
    source: Arc<Source>,
    identity: u64,
    host: Arc<HostFile>,
    executable: bool,
}
impl PrivatePage {
    fn new(
        open: OpenHandle,
        file: Arc<OpenFile>,
        host: Arc<HostFile>,
        offset: u64,
        executable: bool,
    ) -> Rc<Self> {
        Rc::new(Self {
            open,
            source: Arc::new(Source {
                file,
                offset,
                bytes: std::sync::OnceLock::new(),
            }),
            identity: trames_memory::new_backing_identity(),
            host,
            executable,
        })
    }
}
impl PageBacking for PrivatePage {
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
        Some((self.identity, self.version()))
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
            >= self.host.length.load(Ordering::Relaxed).div_ceil(PAGE_SIZE)
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
        self.host
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
    fn next_page(&self, pages: u64) -> std::result::Result<Rc<dyn PageBacking>, MemoryError> {
        let offset = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|n| self.source.offset.checked_add(n))
            .ok_or(MemoryError::InvalidRange)?;
        Ok(Self::new(
            self.open.clone(),
            self.source.file.clone(),
            self.host.clone(),
            offset,
            self.executable,
        ))
    }
}
pub(crate) fn pages(
    open: OpenHandle,
    file: Arc<OpenFile>,
    host: Arc<HostFile>,
    offset: u64,
    len: u64,
    executable: bool,
) -> Result<Vec<Rc<dyn PageBacking>>> {
    let end = offset
        .checked_add(len)
        .filter(|&end| end <= i64::MAX as u64)
        .ok_or(Errno(22))?;
    host.publish_length(file.file.metadata().map_err(errno)?.len());
    Ok((offset..end)
        .step_by(PAGE_SIZE as usize)
        .map(|at| {
            PrivatePage::new(open.clone(), file.clone(), host.clone(), at, executable)
                as Rc<dyn PageBacking>
        })
        .collect())
}
