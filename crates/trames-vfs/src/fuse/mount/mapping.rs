// SPDX-License-Identifier: GPL-3.0-or-later
//! Original FUSE inode pages; CPU faults and writeback use existing resources.
use super::*;
use trames_memory::{MemoryError, PageBacking, PageSource, SharedPage, SyncResource, PAGE_SIZE};
#[cfg(test)]
#[path = "../mapping_tests.rs"]
mod tests;

struct Mapping {
    file: Arc<File>,
    original: SharedFd,
    node: NodeRef,
    page: Arc<cache::Page>,
    source: Arc<dyn PageSource>,
    index: u64,
    writable: bool,
    writer: Option<Arc<writeback::OpenWriter>>,
    _executor: Option<Arc<dyn trames_memory::SyncExecutor>>,
}
impl Mapping {
    fn new(
        file: Arc<File>,
        original: SharedFd,
        node: NodeRef,
        index: u64,
        writable: bool,
        writer: Option<Arc<writeback::OpenWriter>>,
    ) -> Arc<Self> {
        let page = file.attr.cache.mapped_page(index);
        let source = file.cached_source(original.clone(), index, page.clone());
        let executor = file.attr.cache.executor();
        Arc::new(Self {
            file,
            original,
            node,
            page,
            source,
            index,
            writable,
            writer,
            _executor: executor,
        })
    }
    fn bytes(&self) -> std::result::Result<Arc<SharedPage>, MemoryError> {
        self.source.load()
    }
    fn changed(&self) {
        let first = self.page.mark_dirty();
        self.file.attr.cache.changed(false);
        if first {
            self.file.attr.modified(&self.file.reference.fs);
        }
    }
    fn flush_on_close(&self) {
        if self.writable && self.page.dirty() {
            if let Some(writer) = &self.writer {
                writeback::background(writer);
            }
        }
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        self.flush_on_close();
        self.file.attr.cache.release_mapping(&self.page);
    }
}
impl PageBacking for Mapping {
    fn mapped_residents(&self) -> Option<&trames_memory::MappedResidents> {
        Some(&self.page.owners)
    }
    fn proc_dirty(&self) -> bool {
        self.page.dirty()
    }
    fn proc_file(&self) -> Option<trames_memory::MappingFileInfo> {
        let FdKind::Node(path) = &self.original.open.kind else {
            return None;
        };
        let mut path = path.clone();
        if self.node.borrow().links == 0 {
            path.extend_from_slice(b" (deleted)");
        }
        Some(trames_memory::MappingFileInfo {
            device: self.file.mount.device(),
            inode: self.node.borrow().inode,
            path: path.into(),
            path_mount: Some(self.file.mount.id),
        })
    }
    fn retain_in_view(&self) -> bool {
        true
    }
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        Some(self.file.attr.layout.clone())
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.page.identity, 0))
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_commit_isolated(&self) -> bool {
        true
    }
    fn parallel_change_domain(&self) -> Option<(u64, u64)> {
        let cache = &self.file.attr.cache;
        Some((cache.identity, cache.revision.load(Ordering::Relaxed)))
    }
    fn parallel_metadata_domain(&self) -> Option<(u64, u64)> {
        let cache = &self.file.attr.cache;
        Some((
            cache.metadata_identity,
            cache.metadata_revision.load(Ordering::Relaxed),
        ))
    }
    fn parallel_domain_offset(&self) -> Option<u64> {
        Some(self.index * PAGE_SIZE)
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        self.page.valid().then(|| self.page.bytes().clone())
    }
    fn page_source(&self) -> Option<Arc<dyn PageSource>> {
        Some(self.source.clone())
    }
    fn native_resident(&self) -> bool {
        self.page.valid()
    }
    fn check(&self, address: u64) -> std::result::Result<(), MemoryError> {
        self.file
            .attr
            .check()
            .map_err(|e| MemoryError::BackingIo(e.0))?;
        let size = u64::from_le_bytes(self.file.attr.lock().unwrap()[8..16].try_into().unwrap());
        if self.index >= size.div_ceil(PAGE_SIZE) {
            return Err(MemoryError::Bus(address));
        }
        Ok(())
    }
    fn read(&self, offset: usize, output: &mut [u8]) -> std::result::Result<(), MemoryError> {
        self.bytes()?.copy_read(offset, output);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> std::result::Result<(), MemoryError> {
        if !self.writable {
            return Err(MemoryError::BackingIo(13));
        }
        self.bytes()?.copy_write(offset, bytes);
        self.changed();
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        read: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, MemoryError> {
        self.bytes()?.with_read(offset, len, read);
        Ok(true)
    }
    fn with_write(
        &self,
        offset: usize,
        len: usize,
        write: &mut dyn FnMut(&mut [u8]),
    ) -> std::result::Result<bool, MemoryError> {
        if !self.writable {
            return Err(MemoryError::BackingIo(13));
        }
        self.bytes()?.with_write(offset, len, write);
        self.changed();
        Ok(true)
    }
    fn publish_write(&self, _: usize, _: usize) -> std::result::Result<(), MemoryError> {
        if !self.writable {
            return Err(MemoryError::BackingIo(13));
        }
        self.changed();
        Ok(())
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        if self.writable {
            return Err(MemoryError::BackingIo(95));
        }
        Ok(())
    }
    fn sync_resource(&self) -> Option<std::result::Result<Arc<dyn SyncResource>, MemoryError>> {
        if !self.writable {
            return None;
        }
        Some(
            self.file
                .reference
                .fs
                .fault_caller()
                .map(|caller| {
                    Arc::new(writeback::Sync::new(
                        self.file.clone(),
                        self.original.clone(),
                        caller,
                        self.writer.clone(),
                    )) as Arc<dyn SyncResource>
                })
                .map_err(|e| MemoryError::BackingIo(e.0)),
        )
    }
    fn sync_required(&self) -> bool {
        self.writable
    }
    fn sync_key(&self) -> Option<u64> {
        Some(self.file.attr.cache.identity)
    }
    fn close_resource(&self) -> Option<Arc<dyn SyncResource>> {
        let writer = self.writer.as_ref()?;
        Some(Arc::new(writeback::Sync::with_options(
            self.file.clone(),
            self.original.clone(),
            Caller::default(),
            false,
            false,
            Some(writer.clone()),
            Some(writer.executor()),
        )))
    }
    fn version(&self) -> u64 {
        self.page.revision().wrapping_add(
            self.file
                .attr
                .cache
                .metadata_revision
                .load(Ordering::Relaxed),
        )
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn executable(&self) -> bool {
        self.file.mount.flags.get() & mounts::MS_NOEXEC == 0
    }
    fn next_page(&self, pages: u64) -> std::result::Result<Arc<dyn PageBacking>, MemoryError> {
        let index = self
            .index
            .checked_add(pages)
            .filter(|index| {
                index
                    .checked_mul(PAGE_SIZE)
                    .is_some_and(|n| n < i64::MAX as u64)
            })
            .ok_or(MemoryError::InvalidRange)?;
        Ok(Self::new(
            self.file.clone(),
            self.original.clone(),
            self.node.clone(),
            index,
            self.writable,
            self.writer.clone(),
        ))
    }
}
impl File {
    pub(crate) fn mapping_pages(
        self: &Arc<Self>,
        original: SharedFd,
        offset: u64,
        len: u64,
        shared: bool,
        writable: bool,
    ) -> Result<Vec<Arc<dyn PageBacking>>> {
        self.attr.check()?;
        if self.directory || !self.attr.kind_is_regular() {
            return Err(Errno(19));
        }
        if !fd_can_read(original.open.flags.get()) {
            return Err(Errno(13));
        }
        if shared && self.open_flags & 1 != 0 {
            return Err(Errno(19));
        }
        if !offset.is_multiple_of(PAGE_SIZE)
            || len == 0
            || !len.is_multiple_of(PAGE_SIZE)
            || offset
                .checked_add(len)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(Errno(22));
        }
        let readonly = self.mount.flags.get() & mounts::MS_RDONLY != 0;
        if shared && writable && readonly {
            return Err(Errno(30));
        }
        let may_write = shared && original.open.flags.get() & 3 == 2 && !readonly;
        let executor = crate::file_actor::sync_executor();
        if let Some(executor) = &executor {
            self.attr.cache.bind_executor(executor);
        }
        if may_write && executor.is_none() {
            return Err(Errno(95));
        }
        let writer = if may_write {
            Some(writeback::OpenWriter::new(
                self.clone(),
                original.clone(),
                executor.unwrap(),
            )?)
        } else {
            None
        };
        let node = self.inode().ok_or(Errno(19))?;
        Ok((offset / PAGE_SIZE..(offset + len) / PAGE_SIZE)
            .map(|index| {
                Mapping::new(
                    self.clone(),
                    original.clone(),
                    node.clone(),
                    index,
                    may_write,
                    writer.clone(),
                ) as Arc<dyn PageBacking>
            })
            .collect())
    }
}
