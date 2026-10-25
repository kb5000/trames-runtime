// SPDX-License-Identifier: GPL-3.0-or-later
//! Coherent mapped pages retained by mappings, not by the inode's weak cache.
use super::*;
use std::sync::{atomic::AtomicBool, Arc, RwLock};
mod writers;
use storage::FileData;
use trames_memory::{MemoryError, PageBacking, SharedPage, PAGE_SIZE};
use writers::WriteLease;
pub(super) use writers::Writers;
pub(super) struct FilePage {
    identity: u64,
    bytes: RwLock<PageStorage>,
    layout: AtomicU64,
    dirty: AtomicBool,
    version: AtomicU64,
}
#[derive(Clone)]
enum PageStorage {
    // Only the coordinator's Rc-backed FileMapping/MappedData APIs access this
    // capability. Before first publication there is one actor; layout changes
    // occur at joined checkpoints. No unpublished capability reaches a worker.
    Unpublished {
        bytes: Arc<SharedPage>,
        shared: bool,
    },
    Published {
        bytes: Arc<SharedPage>,
        shared: bool,
    },
}
impl PageStorage {
    fn zero() -> Self {
        Self::Unpublished {
            bytes: Arc::new(SharedPage::zero()),
            shared: false,
        }
    }
    fn heap(bytes: Box<[u8; PAGE_SIZE as usize]>) -> Self {
        Self::Unpublished {
            bytes: Arc::new(SharedPage::from_box(bytes)),
            shared: false,
        }
    }
    fn mapped(map: trames_shared::Mapping) -> Self {
        // SAFETY: the retained mapping covers one initialized guest page. CPU
        // access uses SharedPage guards; raw GPU access retains its existing
        // display-buffer ownership protocol.
        Self::Unpublished {
            bytes: Arc::new(unsafe { SharedPage::from_mapping(map.pointer(), map) }),
            shared: true,
        }
    }
    fn is_shared(&self) -> bool {
        matches!(
            self,
            Self::Unpublished { shared: true, .. } | Self::Published { shared: true, .. }
        )
    }
    fn version(&self) -> u64 {
        match self {
            Self::Unpublished { .. } => 0,
            Self::Published { bytes, .. } => bytes.revision(),
        }
    }
    fn with_read<T>(&self, offset: usize, len: usize, f: impl FnOnce(&[u8]) -> T) -> T {
        match self {
            // SAFETY: this private tag cannot escape FileMapping/MappedData.
            // Publication invalidates every local cache before any worker runs.
            Self::Unpublished { bytes, .. } => unsafe {
                bytes.with_unpublished_read(offset, len, f)
            },
            Self::Published { bytes, .. } => bytes.with_read(offset, len, f),
        }
    }
    fn with_write<T>(&self, offset: usize, len: usize, f: impl FnOnce(&mut [u8]) -> T) -> T {
        match self {
            // SAFETY: same coordinator-only ownership; original provider dirty
            // and generation hooks are applied by every caller after mutation.
            Self::Unpublished { bytes, .. } => unsafe {
                bytes.with_unpublished_write(offset, len, f)
            },
            Self::Published { bytes, .. } => bytes.with_write(offset, len, f),
        }
    }
}
struct CachedPage {
    layout: u64,
    bytes: PageStorage,
}
impl FilePage {
    fn new(bytes: PageStorage) -> Arc<Self> {
        Arc::new(Self {
            identity: trames_memory::new_backing_identity(),
            bytes: RwLock::new(bytes),
            layout: AtomicU64::new(0),
            dirty: AtomicBool::new(false),
            version: AtomicU64::new(0),
        })
    }
    fn changed(&self) {
        self.version.store(
            self.version.load(Ordering::Relaxed).wrapping_add(1),
            Ordering::Relaxed,
        );
    }
    fn replace(&self, bytes: PageStorage) {
        *self.bytes.write().unwrap() = bytes;
        self.layout.fetch_add(1, Ordering::Relaxed);
    }
    fn shared_page(&self) -> Arc<SharedPage> {
        let mut layout = self.bytes.write().unwrap();
        match &*layout {
            PageStorage::Published { bytes, .. } => bytes.clone(),
            PageStorage::Unpublished { bytes, shared } => {
                let bytes = bytes.clone();
                let shared = *shared;
                *layout = PageStorage::Published {
                    bytes: bytes.clone(),
                    shared,
                };
                self.layout.fetch_add(1, Ordering::Relaxed);
                bytes
            }
        }
    }
    fn cached(&self) -> CachedPage {
        CachedPage {
            layout: self.layout.load(Ordering::Relaxed),
            bytes: self.bytes.read().unwrap().clone(),
        }
    }
}
// The live length is a capability to the actual storage, never a cached length
// sampled at mmap. PlainFile and SharedFile already publish it atomically.
// Overlay Lower and volatile files retain an inode's live scalar dependency,
// including when that inode changes its storage representation.
enum LiveLength {
    Plain(Arc<file_data::PlainFile>),
    Shared(trames_shared::SharedFile),
    Inode(trames_shared::LogicalSize),
}
struct MappingState {
    identity: u64,
    generation: AtomicU64,
    length: LiveLength,
}
impl MappingState {
    fn new(data: &FileData, stable: bool, inode: Option<trames_shared::LogicalSize>) -> Arc<Self> {
        Arc::new(Self {
            identity: trames_memory::new_backing_identity(),
            generation: AtomicU64::new(0),
            length: match data {
                _ if !stable => {
                    LiveLength::Inode(inode.clone().unwrap_or_else(|| data.logical_size()))
                }
                FileData::Plain(data) => LiveLength::Plain(data.clone()),
                FileData::Shared(file) => LiveLength::Shared(file.clone()),
                _ => LiveLength::Inode(inode.clone().unwrap_or_else(|| data.logical_size())),
            },
        })
    }
    fn len(&self) -> u64 {
        match &self.length {
            LiveLength::Plain(data) => data.len(),
            LiveLength::Shared(file) => file.len() as u64,
            LiveLength::Inode(size) => size.load(Ordering::Relaxed),
        }
    }
    fn domain(&self) -> (u64, u64) {
        (
            self.identity,
            self.generation
                .load(Ordering::Relaxed)
                .wrapping_add(match &self.length {
                    LiveLength::Inode(size) => size.revision(),
                    _ => 0,
                }),
        )
    }
    fn changed(&self) {
        // These counters invalidate caches; byte/VM ownership supplies ordering.
        self.generation.fetch_add(1, Ordering::Relaxed);
        trames_memory::backing_changed();
    }
}
pub(super) struct MappedData {
    state: Arc<MappingState>,
    data: SharedCell<Box<FileData>>,
    pages: SharedCell<BTreeMap<u64, std::sync::Weak<FilePage>>>,
    writers: Arc<Writers>,
}
impl MappedData {
    #[cfg(test)]
    pub(super) fn new(data: FileData, stable: bool) -> Self {
        Self::with_inode(data, stable, None)
    }
    fn with_inode(data: FileData, stable: bool, inode: Option<trames_shared::LogicalSize>) -> Self {
        Self {
            state: MappingState::new(&data, stable, inode),
            data: SharedCell::new(Box::new(data)),
            pages: SharedCell::new(BTreeMap::new()),
            writers: Arc::default(),
        }
    }
    pub(super) fn logical_size(&self) -> trames_shared::LogicalSize {
        self.data.borrow().logical_size()
    }
    pub(super) fn len(&self) -> u64 {
        self.data.borrow().len()
    }
    fn changed(&self) {
        self.state.changed();
    }
    pub(super) fn epoch_io_safe(&self, write: bool) -> bool {
        // FileMapping owns these pages across all VMs, hard links and retained
        // open descriptions. Bytes are shared with workers; dirty metadata and
        // persistence hooks still require a joined checkpoint.
        let conflict = if write {
            self.has_writers()
                || self
                    .pages
                    .borrow()
                    .values()
                    .any(|page| page.strong_count() != 0)
        } else {
            // Private COW never publishes to FileMapping; read-only mappings
            // cannot dirty the inode. Only possible shared writers conflict.
            self.has_writers()
        };
        !conflict && self.data.borrow().epoch_io_safe(write)
    }
    pub(super) fn inode(&self) -> Option<u64> {
        self.data.borrow().inode()
    }
    pub(super) fn blocks(&self) -> Result<u64> {
        self.data.borrow().blocks()
    }
    pub(super) fn orphan(&self, value: bool) {
        self.data.borrow_mut().orphan(value);
    }
    pub(super) fn shared_file(&self) -> Option<trames_shared::SharedFile> {
        self.data.borrow().shared_file()
    }
    fn refresh_shared_pages(&self) {
        let Some(file) = self.shared_file() else {
            return;
        };
        for (&offset, page) in self.pages.borrow().iter() {
            let Some(page) = page.upgrade() else { continue };
            if !page.bytes.read().unwrap().is_shared() {
                if let Ok(map) = file.map(offset as usize, PAGE_SIZE as usize) {
                    page.replace(PageStorage::mapped(map));
                    // Snapshot versions cover physical identity, including
                    // untouched pages upgraded when an inode gains SHM storage.
                    page.changed();
                }
            }
        }
    }
    fn page(&self, offset: u64) -> Result<Arc<FilePage>> {
        if let Some(p) = self
            .pages
            .borrow()
            .get(&offset)
            .and_then(std::sync::Weak::upgrade)
        {
            return Ok(p);
        }
        let bytes = if let Some(map) = self
            .shared_file()
            .and_then(|file| file.map(offset as usize, PAGE_SIZE as usize).ok())
        {
            PageStorage::mapped(map)
        } else {
            let data = self.data.borrow().read_at(offset, PAGE_SIZE as usize)?;
            if data.is_empty() {
                PageStorage::zero()
            } else {
                let mut bytes = Box::new([0; PAGE_SIZE as usize]);
                bytes[..data.len()].copy_from_slice(&data);
                PageStorage::heap(bytes)
            }
        };
        let page = FilePage::new(bytes);
        let mut pages = self.pages.borrow_mut();
        pages.insert(offset, Arc::downgrade(&page));
        Ok(page)
    }
    fn batch(&self, offset: u64, len: u64) -> Result<Vec<Arc<FilePage>>> {
        self.pages.borrow_mut().retain(|_, p| p.strong_count() != 0);
        if self.shared_file().is_some() {
            return (offset..offset + len)
                .step_by(PAGE_SIZE as usize)
                .map(|at| self.page(at))
                .collect();
        }
        let mut result = Vec::new();
        for batch in (0..len).step_by(storage::MAX_TRANSFER) {
            let size = (len - batch).min(storage::MAX_TRANSFER as u64);
            let bytes = self.data.borrow().read_at(offset + batch, size as usize)?;
            for inside in (0..size).step_by(PAGE_SIZE as usize) {
                let at = offset + batch + inside;
                let existing = self
                    .pages
                    .borrow()
                    .get(&at)
                    .and_then(std::sync::Weak::upgrade);
                let page = if let Some(page) = existing {
                    page
                } else {
                    let available = bytes
                        .len()
                        .saturating_sub(inside as usize)
                        .min(PAGE_SIZE as usize);
                    let storage = if available != 0 {
                        let mut data = Box::new([0; PAGE_SIZE as usize]);
                        data[..available]
                            .copy_from_slice(&bytes[inside as usize..inside as usize + available]);
                        PageStorage::heap(data)
                    } else {
                        PageStorage::zero()
                    };
                    let page = FilePage::new(storage);
                    self.pages.borrow_mut().insert(at, Arc::downgrade(&page));
                    page
                };
                result.push(page);
            }
        }
        Ok(result)
    }
    pub(super) fn read_at(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        let mut out = self.data.borrow().read_at(offset, count)?;
        let end = offset + out.len() as u64;
        for (&base, p) in self.pages.borrow().range((offset & !(PAGE_SIZE - 1))..end) {
            if let Some(p) = p.upgrade() {
                let start = base.max(offset);
                let to = (base + PAGE_SIZE).min(end);
                p.bytes.read().unwrap().with_read(
                    (start - base) as usize,
                    (to - start) as usize,
                    |bytes| {
                        out[(start - offset) as usize..(to - offset) as usize]
                            .copy_from_slice(bytes);
                    },
                );
            }
        }
        Ok(out)
    }
    pub(super) fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        let count = self.data.borrow_mut().write_at(offset, bytes)?;
        self.refresh_shared_pages();
        let end = offset + count as u64;
        for (&base, p) in self.pages.borrow().range((offset & !(PAGE_SIZE - 1))..end) {
            if let Some(p) = p.upgrade() {
                let start = base.max(offset);
                let to = (base + PAGE_SIZE).min(end);
                if !p.bytes.read().unwrap().is_shared() {
                    p.bytes.write().unwrap().with_write(
                        (start - base) as usize,
                        (to - start) as usize,
                        |out| {
                            out.copy_from_slice(
                                &bytes[(start - offset) as usize..(to - offset) as usize],
                            );
                        },
                    );
                }
                p.changed();
            }
        }
        self.changed();
        Ok(count)
    }
    fn flush(&self, offset: u64, page: &FilePage) -> Result<()> {
        if !page.dirty.load(Ordering::Relaxed) {
            return Ok(());
        }
        if page.bytes.read().unwrap().is_shared() {
            page.dirty.store(false, Ordering::Relaxed);
            return Ok(());
        }
        let count = self.len().saturating_sub(offset).min(PAGE_SIZE) as usize;
        if count != 0 {
            let written = page.bytes.read().unwrap().with_read(0, count, |bytes| {
                self.data.borrow_mut().write_at(offset, bytes)
            })?;
            if written != count {
                return Err(Errno(5));
            }
        }
        page.dirty.store(false, Ordering::Relaxed);
        Ok(())
    }
    pub(super) fn has_writers(&self) -> bool {
        self.writers.active()
    }
    pub(super) fn sync(&self, data_only: bool) -> Result<()> {
        for (&base, page) in self.pages.borrow().iter() {
            if let Some(page) = page.upgrade() {
                self.flush(base, &page)?;
            }
        }
        self.data.borrow().sync(data_only)
    }
    pub(super) fn truncate(&self, length: u64) -> Result<()> {
        self.sync(false)?;
        self.data.borrow_mut().truncate(length)?;
        // The length has changed even if a later page reload fails. Publish
        // that fact before fallible I/O; no VM/provider re-entry occurs here.
        self.changed();
        self.refresh_shared_pages();
        for (&base, page) in self.pages.borrow().iter() {
            if let Some(page) = page.upgrade() {
                if !page.bytes.read().unwrap().is_shared() {
                    let bytes = self.data.borrow().read_at(base, PAGE_SIZE as usize)?;
                    let mut content = page.bytes.write().unwrap();
                    if bytes.is_empty() {
                        *content = PageStorage::zero();
                        page.layout.fetch_add(1, Ordering::Relaxed);
                    } else {
                        content.with_write(0, PAGE_SIZE as usize, |out| {
                            out.fill(0);
                            out[..bytes.len()].copy_from_slice(&bytes);
                        });
                    }
                }
                page.changed();
                page.dirty.store(false, Ordering::Relaxed);
            }
        }
        Ok(())
    }
}
#[derive(Clone)]
enum MappingMount {
    Shared(Arc<mounts::MountIdentity>),
    Owner(Rc<Mount>),
}
impl MappingMount {
    fn new(mount: &OpenMount) -> Self {
        match mount {
            OpenMount::Owner(owner) if owner.shared_resources().is_none() => {
                Self::Owner(owner.clone())
            }
            _ => Self::Shared(mount.identity.clone()),
        }
    }
    fn identity(&self) -> &Arc<mounts::MountIdentity> {
        match self {
            Self::Shared(identity) => identity,
            Self::Owner(mount) => &mount.identity,
        }
    }
}
#[derive(Clone)]
struct MappingWriter {
    _lease: WriteLease,
    _owner: Option<Rc<RefCell<OpenDescription>>>,
}
impl MappingWriter {
    fn new(
        open: &OpenHandle,
        node: &NodeRef,
        writers: &Arc<Writers>,
        mount: Option<&MappingMount>,
    ) -> Self {
        let (shared, owner) = match open {
            OpenHandle::Shared(open) => (Some(open), None),
            OpenHandle::Owner(open) => (None, Some(open.clone())),
        };
        Self {
            _lease: WriteLease::new(node, writers, mount.map(MappingMount::identity), shared),
            _owner: owner,
        }
    }
    #[cfg(test)]
    fn shared(&self) -> Option<WriteLease> {
        self._owner.is_none().then(|| self._lease.clone())
    }
}
struct FileMapping {
    // The VMA pins its original OFD even after private COW. Page bytes alone
    // cannot preserve flock, close notification or owner-control lifetime.
    open: OpenHandle,
    // Normal mappings need resource/flag identity. Namespace-control ancestry
    // stays explicitly owner-only rather than escaping in a shared byte lease.
    mount: Option<MappingMount>,
    node: NodeRef,
    page: Arc<FilePage>,
    cached: RefCell<CachedPage>,
    state: Arc<MappingState>,
    offset: u64,
    writable: bool,
    writer: Option<MappingWriter>,
    executable: bool,
}
impl FileMapping {
    fn with_bytes<T>(&self, f: impl FnOnce(&PageStorage) -> T) -> T {
        let mut cache = self.cached.borrow_mut();
        if cache.layout != self.page.layout.load(Ordering::Relaxed) {
            *cache = self.page.cached();
        }
        f(&cache.bytes)
    }
    fn changed(&self) {
        // Like the first writable fault of a dirty mmap interval, update mtime
        // once until writeback/truncate cleans this page. Repeated CPU/native
        // stores must not acquire inode metadata or read the host clock. Page
        // and backing generations still change on EVERY write, for executable
        // aliases, exclusive monitors and incremental worker snapshots.
        if !self.page.dirty.load(Ordering::Relaxed) {
            self.page.dirty.store(true, Ordering::Relaxed);
            self.node.borrow_mut().times[1] = storage::Timestamp::now();
        }
        self.page.changed();
        self.state.changed();
    }
    fn create(
        open: OpenHandle,
        node: NodeRef,
        mount: Option<MappingMount>,
        offset: u64,
        writable: bool,
        executable: bool,
    ) -> Result<Rc<Self>> {
        let (page, state, writers) =
            if let Content::File(FileData::Mapped(data)) = &node.borrow().content {
                (data.page(offset)?, data.state.clone(), data.writers.clone())
            } else {
                return Err(Errno(19));
            };
        let writer = writable.then(|| MappingWriter::new(&open, &node, &writers, mount.as_ref()));
        Ok(Rc::new(Self {
            open,
            mount,
            node,
            cached: RefCell::new(page.cached()),
            page,
            state,
            offset,
            writable,
            writer,
            executable,
        }))
    }
}
impl PageBacking for FileMapping {
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_change_domain(&self) -> Option<(u64, u64)> {
        // Pseudo inodes can replace their entire content when refreshed. Lower
        // projections also retain their original owner-based change domain.
        if matches!(self.state.length, LiveLength::Inode(_)) {
            return match &self.node.borrow().content {
                Content::File(FileData::Mapped(data)) => Some(data.state.domain()),
                _ => None,
            };
        }
        Some(self.state.domain())
    }
    fn cpu_borrow_safe(&self) -> bool {
        // CPU and native-span methods inspect resident file bytes/metadata
        // only; they cannot re-enter the containing VM. Span callbacks invoke
        // only the supplied memory operation, without yielding to guest code.
        true
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.page.identity, 0))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.page.shared_page())
    }
    fn publish_write(&self, _: usize, _: usize) -> std::result::Result<(), MemoryError> {
        if !self.writable {
            return Err(MemoryError::BackingIo(13));
        }
        self.changed();
        Ok(())
    }
    fn check(&self, address: u64) -> std::result::Result<(), MemoryError> {
        let length = self.state.len();
        if self.offset / PAGE_SIZE >= length.div_ceil(PAGE_SIZE) {
            return Err(MemoryError::Bus(address));
        }
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> std::result::Result<(), MemoryError> {
        self.with_bytes(|storage| {
            storage.with_read(offset, out.len(), |bytes| out.copy_from_slice(bytes))
        });
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> std::result::Result<(), MemoryError> {
        if !self.writable {
            return Err(MemoryError::BackingIo(13));
        }
        self.with_bytes(|storage| {
            storage.with_write(offset, bytes.len(), |out| out.copy_from_slice(bytes))
        });
        self.changed();
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, MemoryError> {
        self.with_bytes(|storage| storage.with_read(offset, len, f));
        Ok(true)
    }
    fn with_write(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&mut [u8]),
    ) -> std::result::Result<bool, MemoryError> {
        if !self.writable {
            return Err(MemoryError::BackingIo(13));
        }
        self.changed();
        self.with_bytes(|storage| storage.with_write(offset, len, f));
        Ok(true)
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        let node = self.node.borrow();
        if let Content::File(FileData::Mapped(data)) = &node.content {
            data.sync(false).map_err(|e| MemoryError::BackingIo(e.0))?;
        }
        Ok(())
    }
    fn sync_key(&self) -> Option<u64> {
        Some(self.node.borrow().inode)
    }
    fn version(&self) -> u64 {
        self.page
            .version
            .load(Ordering::Relaxed)
            .wrapping_add(self.with_bytes(PageStorage::version))
    }
    fn executable(&self) -> bool {
        self.executable
    }
    fn writable(&self) -> bool {
        self.writable
    }
    fn next_page(&self, pages: u64) -> std::result::Result<Rc<dyn PageBacking>, MemoryError> {
        let offset = self
            .offset
            .checked_add(
                pages
                    .checked_mul(PAGE_SIZE)
                    .ok_or(MemoryError::InvalidRange)?,
            )
            .ok_or(MemoryError::InvalidRange)?;
        Self::create(
            self.open.clone(),
            self.node.clone(),
            self.mount.clone(),
            offset,
            self.writable,
            self.executable,
        )
        .map(|page| page as Rc<dyn PageBacking>)
        .map_err(|e| MemoryError::BackingIo(e.0))
    }
}
impl Drop for FileMapping {
    fn drop(&mut self) {
        // Closing the descriptor/unlinking the path never invalidates this inode.
        if let Content::File(FileData::Mapped(data)) = &self.node.borrow().content {
            let _ = data.flush(self.offset, &self.page);
            if Arc::strong_count(&self.page) == 1 {
                data.pages.borrow_mut().remove(&self.offset);
            }
        }
        // Release only after the existing writeback/cleanup attempt.
        drop(self.writer.take());
    }
}
impl Vfs {
    pub fn mapping_pages(
        &self,
        fd: u32,
        offset: u64,
        len: u64,
        shared: bool,
        writable: bool,
    ) -> Result<Vec<Rc<dyn PageBacking>>> {
        let o_descriptor = self.descriptor(fd)?;
        let o = o_descriptor.open.borrow();
        let offset = if let Some(events::Anonymous::Uring(ring)) = &o.anonymous {
            ring.mapping_offset(offset, len, shared)?
        } else {
            offset
        };
        if o.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        if o.flags.get() & 3 == 1 {
            return Err(Errno(13));
        }
        if shared && writable && o.flags.get() & 3 != 2 {
            return Err(Errno(13));
        }
        if o.oom.is_some()
            || o.mount
                .as_ref()
                .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
        {
            return Err(Errno(19));
        }
        let node = o.data_node().ok_or(Errno(19))?;
        let readonly = o.mount.as_ref().is_some_and(|m| m.readonly());
        if shared && writable && readonly {
            return Err(Errno(30));
        }
        let sealed = node.borrow().seals.is_some_and(|s| s & 8 != 0);
        if shared && writable && sealed {
            return Err(Errno(1));
        }
        let may_write =
            !readonly && shared && o.flags.get() & 3 == 2 && !sealed && !node.borrow().volatile;
        let mut n = node.borrow_mut();
        let length = node.length_for(&n);
        let stable = !n.volatile;
        let Content::File(data) = &mut n.content else {
            return Err(Errno(19));
        };
        if !matches!(data, FileData::Mapped(_)) {
            let original = std::mem::replace(data, FileData::memory(Vec::new()));
            *data = FileData::Mapped(Box::new(MappedData::with_inode(
                original,
                stable,
                Some(length),
            )));
        }
        offset.checked_add(len).ok_or(Errno(22))?;
        let (buffers, state, writers) = if let FileData::Mapped(data) = data {
            (
                data.batch(offset, len)?,
                data.state.clone(),
                data.writers.clone(),
            )
        } else {
            unreachable!("mapped data")
        };
        drop(n);
        let mount = o.mount.as_ref().map(MappingMount::new);
        let executable = !matches!(o.anonymous, Some(events::Anonymous::Uring(_)))
            && mount
                .as_ref()
                .is_none_or(|m| m.identity().flags.get() & mounts::MS_NOEXEC == 0);
        drop(o);
        let open = o_descriptor.open;
        let writer = may_write.then(|| MappingWriter::new(&open, &node, &writers, mount.as_ref()));
        let mut pages: Vec<Rc<dyn PageBacking>> = Vec::new();
        for (i, page) in buffers.into_iter().enumerate() {
            pages.push(Rc::new(FileMapping {
                open: open.clone(),
                mount: mount.clone(),
                node: node.clone(),
                cached: RefCell::new(page.cached()),
                page,
                state: state.clone(),
                offset: offset + i as u64 * PAGE_SIZE,
                writable: may_write,
                writer: writer.clone(),
                executable,
            }));
        }
        Ok(pages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_storage_is_send_sync_and_last_worker_release_retires_the_allocation() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<FilePage>();
        let page = FilePage::new(PageStorage::zero());
        let weak = Arc::downgrade(&page);
        let (release, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            wait.recv().unwrap();
            drop(page);
        });
        assert!(weak.upgrade().is_some());
        release.send(()).unwrap();
        worker.join().unwrap();
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn cached_mapping_refreshes_after_storage_replacement_and_preserves_live_eof() {
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/cached-page", 0x42, 0o600).unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let mut m = trames_memory::Memory::default();
        mapped(
            &v,
            &mut m,
            fd,
            0x40000,
            PAGE_SIZE,
            true,
            trames_memory::Permissions::RW,
        );
        m.write_array(0x40008, *b"before!!").unwrap();
        assert_eq!(m.read_array::<8>(0x40008).unwrap(), *b"before!!");
        v.truncate_fd(fd, 0).unwrap();
        assert_eq!(m.read_array::<8>(0x40008), Err(MemoryError::Bus(0x40008)));
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        assert_eq!(m.read_array::<8>(0x40008).unwrap(), [0; 8]);
        m.write_array(0x40008, *b"after!!!").unwrap();
        m.sync_range(0x40000, PAGE_SIZE).unwrap();
        v.seek(fd, 8, 0).unwrap();
        assert_eq!(v.read(fd, 8).unwrap(), b"after!!!");
    }
    use trames_memory::{Access, Memory, Permissions};
    #[test]
    fn mappings_keep_original_ofd_through_cow_fork_discard_remap_and_final_unmap() {
        use trames_memory::parallel::Registry;
        for (shared, permissions) in [
            (false, Permissions::RW),
            (true, Permissions::RW),
            (false, Permissions::R),
        ] {
            let mut v = Vfs::default();
            let fd = v.open_at(AT_FDCWD, b"/mapped-ofd", 0x42, 0o600).unwrap();
            v.truncate_fd(fd, PAGE_SIZE * 4).unwrap();
            let contender = v.open_at(AT_FDCWD, b"/mapped-ofd", 2, 0).unwrap();
            v.flock(fd, 6).unwrap();
            let notify = v.inotify_init(O_NONBLOCK).unwrap();
            v.inotify_add(notify, b"/mapped-ofd", 8).unwrap();
            let mut m = Memory::default();
            mapped(&v, &mut m, fd, 0x40000, PAGE_SIZE * 2, shared, permissions);
            if permissions.write {
                m.write_array(0x40000, [7; 8]).unwrap();
            }
            let mut child = m.clone();
            if permissions.write {
                child.write_array(0x41000, [9; 8]).unwrap();
            }
            v.close(fd).unwrap();
            assert_eq!(v.flock(contender, 6), Err(Errno(11)));
            assert_eq!(v.read(notify, 4096), Err(Errno(11)));
            m.discard(0x40000, PAGE_SIZE * 2).unwrap();
            assert_eq!(
                m.read_array::<8>(0x40000).unwrap(),
                [if shared { 7 } else { 0 }; 8]
            );
            m.unmap(0x40000, PAGE_SIZE).unwrap();
            m.remap(0x41000, PAGE_SIZE, 0x80000, PAGE_SIZE * 2, false)
                .unwrap();
            assert_eq!(m.read_array::<8>(0x81000).unwrap(), [0; 8]);
            m.protect(0x80000, PAGE_SIZE * 2, Permissions::R).unwrap();
            let mut registry = Registry::default();
            drop(m.parallel_view(&mut registry).unwrap());
            drop(child);
            assert_eq!(v.flock(contender, 6), Err(Errno(11)));
            m.map_fixed(0x80000, PAGE_SIZE, Permissions::RW).unwrap();
            assert_eq!(v.flock(contender, 6), Err(Errno(11)));
            assert_eq!(v.read(notify, 4096), Err(Errno(11)));
            // The cached parallel byte snapshot can outlive the provider. It
            // must neither discard an active VMA pin nor delay final OFD close.
            m.unmap(0x81000, PAGE_SIZE).unwrap();
            v.flock(contender, 6).unwrap();
            let event = v.read(notify, 4096).unwrap();
            assert_eq!(event.len(), 16);
            assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
            assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        }
    }
    #[test]
    fn live_mapping_state_is_shared_without_sampling_or_retaining_inode() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<MappingState>();
        for shared in [false, true] {
            let mut v = Vfs::default();
            let fd = if shared {
                v.memfd_create(b"mapping-state", 0).unwrap()
            } else {
                v.open_at(AT_FDCWD, b"/mapping-state", 0x42, 0o600).unwrap()
            };
            v.truncate_fd(fd, PAGE_SIZE).unwrap();
            let maps = v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap();
            let node = v
                .descriptor(fd)
                .unwrap()
                .open
                .borrow()
                .node
                .clone()
                .unwrap();
            let state = match &node.borrow().content {
                Content::File(FileData::Mapped(data)) => data.state.clone(),
                _ => unreachable!(),
            };
            let weak_node = Arc::downgrade(&node);
            let domain = state.domain();
            let (tx, rx) = std::sync::mpsc::channel();
            let (answer, result) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                for () in rx {
                    answer.send((state.len(), state.domain())).unwrap();
                }
                state
            });
            for length in [PAGE_SIZE * 2, 0, PAGE_SIZE + 1] {
                v.truncate_fd(fd, length).unwrap();
                tx.send(()).unwrap();
                let (live, changed) = result
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                assert_eq!(live, length);
                assert_eq!(changed.0, domain.0);
                assert_ne!(changed.1, domain.1);
            }
            drop(node);
            if !shared {
                v.unlink_at(AT_FDCWD, b"/mapping-state", false).unwrap();
            }
            v.close(fd).unwrap();
            drop(maps);
            assert!(weak_node.upgrade().is_none());
            drop(tx);
            let state = worker.join().unwrap();
            assert_eq!(state.len(), PAGE_SIZE + 1);
        }
    }
    #[test]
    fn dirty_mapping_access_avoids_inode_and_clock_but_versions_every_write() {
        for shared in [false, true] {
            let mut v = Vfs::default();
            let fd = if shared {
                v.memfd_create(b"mapping-hot", 0).unwrap()
            } else {
                v.open_at(AT_FDCWD, b"/mapping-hot", 0x42, 0o600).unwrap()
            };
            v.truncate_fd(fd, PAGE_SIZE).unwrap();
            let maps = v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap();
            let node = v
                .descriptor(fd)
                .unwrap()
                .open
                .borrow()
                .node
                .clone()
                .unwrap();
            node.borrow_mut().times[1] = storage::Timestamp::default();
            maps[0].write(0, b"first").unwrap();
            let first = node.borrow().times[1];
            assert_ne!(first, storage::Timestamp::default());
            let mut version = maps[0].version();
            let mut domain = maps[0].parallel_change_domain().unwrap();
            // A real outstanding exclusive inode borrow makes any accidental
            // metadata access panic, without adding instrumentation to hot code.
            let guard = node.borrow_mut();
            for native in [false, true] {
                maps[0].check(0x1000).unwrap();
                if native {
                    assert!(maps[0]
                        .with_write(0, 5, &mut |b| b.copy_from_slice(b"again"))
                        .unwrap());
                } else {
                    maps[0].write(0, b"again").unwrap();
                }
                let mut bytes = [0; 5];
                maps[0].read(0, &mut bytes).unwrap();
                assert_eq!(&bytes, b"again");
                assert_ne!(maps[0].version(), version);
                assert_ne!(maps[0].parallel_change_domain().unwrap(), domain);
                version = maps[0].version();
                domain = maps[0].parallel_change_domain().unwrap();
            }
            maps[0].publish_write(0, 5).unwrap();
            assert_ne!(maps[0].version(), version);
            assert_eq!(guard.times[1], first);
            drop(guard);
            // Successful sync starts a new dirty interval. Explicit timestamps
            // are not used as a cache key; the next dirtying updates them again.
            maps[0].sync().unwrap();
            v.set_times(fd as i32, None, Some([[1, 0], [2, 0]]))
                .unwrap();
            maps[0]
                .with_write(0, 5, &mut |b| b.copy_from_slice(b"after"))
                .unwrap();
            assert_ne!(node.borrow().times[1].seconds, 2);
            assert_eq!(v.read(fd, 5).unwrap(), b"after");
        }
    }
    #[test]
    fn lower_mapping_length_follows_shared_inode_identity() {
        let mut v = Vfs::default();
        let lower = v.open_at(AT_FDCWD, b"/lower-state", 0x42, 0o600).unwrap();
        let alias = v.open_at(AT_FDCWD, b"/alias-state", 0x42, 0o600).unwrap();
        v.truncate_fd(lower, PAGE_SIZE).unwrap();
        let source = v
            .descriptor(lower)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        let node = v
            .descriptor(alias)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        node.borrow_mut().content = Content::File(FileData::Lower(source.clone()));
        let maps = v.mapping_pages(alias, 0, PAGE_SIZE, false, false).unwrap();
        let guard = node.borrow();
        let Content::File(FileData::Mapped(data)) = &guard.content else {
            unreachable!()
        };
        assert_eq!(data.state.len(), PAGE_SIZE);
        drop(guard);
        // EOF admission is a scalar capability. It must neither reacquire the
        // projection's metadata nor enter the source inode during a resize.
        let source_guard = source.borrow_mut();
        let alias_guard = node.borrow_mut();
        maps[0].check(0x9000).unwrap();
        let Content::File(FileData::Plain(bytes)) = &source_guard.content else {
            unreachable!()
        };
        bytes.truncate(0).unwrap();
        assert_eq!(maps[0].check(0x9000), Err(MemoryError::Bus(0x9000)));
        bytes.truncate(PAGE_SIZE).unwrap();
        maps[0].check(0x9000).unwrap();
        drop(alias_guard);
        drop(source_guard);
        maps[0].check(0x9000).unwrap();
        v.truncate_fd(lower, 0).unwrap();
        assert_eq!(maps[0].check(0x9000), Err(MemoryError::Bus(0x9000)));
        v.truncate_fd(lower, 1).unwrap();
        maps[0].check(0x9000).unwrap();
    }
    #[test]
    fn volatile_mapping_refresh_keeps_live_eof_and_change_domain() {
        let mut v = Vfs::default();
        let fd = v
            .open_at(AT_FDCWD, b"/volatile-state", 0x42, 0o600)
            .unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let node = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        node.borrow_mut().volatile = true;
        let maps = v.mapping_pages(fd, 0, PAGE_SIZE, false, false).unwrap();
        maps[0].check(0x1000).unwrap();
        assert!(maps[0].parallel_change_domain().is_some());
        // The same replacement used by PseudoFs::cache. A saved PlainFile
        // capability here would incorrectly continue to allow the old EOF.
        node.borrow_mut().content = Content::File(FileData::memory(Vec::new()));
        assert_eq!(maps[0].check(0x1000), Err(MemoryError::Bus(0x1000)));
        assert_eq!(maps[0].parallel_change_domain(), None);
    }
    #[test]
    fn retained_writer_blocks_file_io_and_readonly_remount_without_owner_cache_updates() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/mapped-mount", 0o755).unwrap();
        v.mount(Some(b"tmpfs"), b"/mapped-mount", Some(b"tmpfs"), 0, None)
            .unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/mapped-mount/file", 0x42, 0o600)
            .unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let maps = v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap();
        let (node, mount) = {
            let descriptor = v.descriptor(fd).unwrap();
            let open = descriptor.open.borrow();
            (
                open.node.clone().unwrap(),
                open.mount.as_ref().map(MappingMount::new),
            )
        };
        drop(maps);
        assert!(v.epoch_file_io(fd, false));
        let mapping =
            FileMapping::create(v.descriptor(fd).unwrap().open, node, mount, 0, true, false)
                .unwrap();
        mapping.write(0, b"written").unwrap();
        let retained = mapping.writer.as_ref().unwrap().shared().unwrap();
        let alias = mapping.clone();
        drop(mapping);
        assert!(!v.epoch_file_io(fd, false));
        drop(alias);
        assert_eq!(v.pread(fd, 7, 0).unwrap(), b"written");
        // The page cache is empty now, but an accepted writable operation still
        // owns this inode/mount. No owner scan may report it as read-only-safe.
        assert!(!v.epoch_file_io(fd, false));
        assert!(!v.epoch_file_io(fd, true));
        assert_eq!(
            v.mount(None, b"/mapped-mount", None, 32 | mounts::MS_RDONLY, None),
            Err(Errno(16))
        );
        std::thread::spawn(move || drop(retained)).join().unwrap();
        assert!(v.epoch_file_io(fd, false));
        assert!(v.epoch_file_io(fd, true));
        v.mount(None, b"/mapped-mount", None, 32 | mounts::MS_RDONLY, None)
            .unwrap();
        assert!(matches!(
            v.mapping_pages(fd, 0, PAGE_SIZE, true, true),
            Err(Errno(30))
        ));
    }
    #[test]
    fn retained_writer_keeps_original_ofd_after_last_mapping_provider_is_retired() {
        let mut v = Vfs::default();
        let fd = v
            .open_at(AT_FDCWD, b"/retained-write-ofd", 0x42, 0o600)
            .unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let contender = v.open_at(AT_FDCWD, b"/retained-write-ofd", 2, 0).unwrap();
        v.flock(fd, 6).unwrap();
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/retained-write-ofd", 8).unwrap();
        drop(v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap());
        let descriptor = v.descriptor(fd).unwrap();
        let (node, mount) = {
            let open = descriptor.open.borrow();
            (
                open.node.clone().unwrap(),
                open.mount.as_ref().map(MappingMount::new),
            )
        };
        let mapping = FileMapping::create(descriptor.open, node, mount, 0, true, false).unwrap();
        let retained = mapping.writer.as_ref().unwrap().shared().unwrap();
        v.close(fd).unwrap();
        drop(mapping);
        assert_eq!(v.flock(contender, 6), Err(Errno(11)));
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        std::thread::spawn(move || drop(retained)).join().unwrap();
        v.flock(contender, 6).unwrap();
        let event = v.read(notify, 4096).unwrap();
        assert_eq!(event.len(), 16);
        assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
    }
    #[test]
    fn retained_writer_pins_resources_without_retaining_detached_owner_topology() {
        for lazy in [false, true] {
            let mut v = Vfs::default();
            v.mkdir_at(AT_FDCWD, b"/pinned-mount", 0o755).unwrap();
            v.mount(Some(b"tmpfs"), b"/pinned-mount", Some(b"tmpfs"), 0, None)
                .unwrap();
            let fd = v
                .open_at(AT_FDCWD, b"/pinned-mount/file", 0x42, 0o600)
                .unwrap();
            v.truncate_fd(fd, PAGE_SIZE).unwrap();
            drop(v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap());
            let (node, mount) = {
                let descriptor = v.descriptor(fd).unwrap();
                let open = descriptor.open.borrow();
                (open.node.clone().unwrap(), open.mount.clone())
            };
            let weak = Rc::downgrade(&v.mount_for_path(mount.as_ref()).unwrap());
            let resource = Arc::downgrade(&mount.as_ref().unwrap().identity);
            let mapping = FileMapping::create(
                v.descriptor(fd).unwrap().open,
                node,
                mount.as_ref().map(MappingMount::new),
                0,
                true,
                false,
            )
            .unwrap();
            drop(mount);
            let retained = mapping.writer.as_ref().unwrap().shared().unwrap();
            v.close(fd).unwrap();
            drop(mapping);
            assert_eq!(v.umount(b"/pinned-mount", 0), Err(Errno(16)));
            if lazy {
                v.umount(b"/pinned-mount", 2).unwrap();
                assert!(v.detached_mounts.borrow().is_empty());
                assert!(weak.upgrade().is_none());
                assert!(resource.upgrade().is_some());
            }
            std::thread::spawn(move || drop(retained)).join().unwrap();
            if !lazy {
                v.umount(b"/pinned-mount", 0).unwrap();
            }
            assert!(weak.upgrade().is_none());
            assert!(resource.upgrade().is_none());
        }
    }
    #[test]
    fn retained_writer_releases_real_inode_filesystem_and_mount_on_last_worker_drop() {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/writer-lifetime", 0o755).unwrap();
        v.mount(Some(b"tmpfs"), b"/writer-lifetime", Some(b"tmpfs"), 0, None)
            .unwrap();
        let fd = v
            .open_at(AT_FDCWD, b"/writer-lifetime/file", 0x42, 0o600)
            .unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        drop(v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap());
        let (node, mount) = {
            let descriptor = v.descriptor(fd).unwrap();
            let open = descriptor.open.borrow();
            (
                open.node.clone().unwrap(),
                open.mount.as_ref().unwrap().identity.clone(),
            )
        };
        let inode = Arc::downgrade(&node);
        let filesystem = Arc::downgrade(&mount.fs.shared);
        let resource = Arc::downgrade(&mount);
        let mapping = FileMapping::create(
            v.descriptor(fd).unwrap().open,
            node,
            Some(MappingMount::Shared(mount)),
            0,
            true,
            false,
        )
        .unwrap();
        mapping.write(0, b"retained bytes").unwrap();
        let retained = mapping.writer.as_ref().unwrap().shared().unwrap();
        let aliases: Vec<_> = (0..8).map(|_| retained.clone()).collect();
        v.close(fd).unwrap();
        drop(mapping);
        v.umount(b"/writer-lifetime", 2).unwrap();
        assert!(v.detached_mounts.borrow().is_empty());
        drop(v);
        assert!(resource.upgrade().is_some());
        assert!(filesystem.upgrade().is_some());
        std::thread::spawn(move || {
            drop(aliases);
            let node = inode.upgrade().unwrap();
            let n = node.borrow();
            let Content::File(data) = &n.content else {
                panic!("retained file")
            };
            assert_eq!(data.read_at(0, 14).unwrap(), b"retained bytes");
            drop(n);
            drop(node);
            drop(retained);
            assert!(inode.upgrade().is_none());
        })
        .join()
        .unwrap();
        assert!(filesystem.upgrade().is_none());
        assert!(resource.upgrade().is_none());
    }
    #[test]
    fn mapping_under_namespace_control_retains_owner_and_has_no_worker_lease() {
        let mut v = Vfs::default();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    namespaces: v.namespace_snapshot(),
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        let control = Rc::downgrade(&v.root_network);
        v.import_file(b"/namespace", vec![]).unwrap();
        v.import_file(b"/data", vec![0; PAGE_SIZE as usize])
            .unwrap();
        v.mount(Some(b"/proc/self/ns/net"), b"/namespace", None, 4096, None)
            .unwrap();
        v.mount(Some(b"/data"), b"/namespace", None, 4096, None)
            .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/namespace", 2, 0).unwrap();
        assert!(v.shared_files().lookup(fd).is_none());
        drop(v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap());
        let (node, mount) = {
            let descriptor = v.descriptor(fd).unwrap();
            let open = descriptor.open.borrow();
            (
                open.node.clone().unwrap(),
                MappingMount::new(open.mount.as_ref().unwrap()),
            )
        };
        assert!(matches!(mount, MappingMount::Owner(_)));
        let mapping = FileMapping::create(
            v.descriptor(fd).unwrap().open,
            node,
            Some(mount),
            0,
            true,
            false,
        )
        .unwrap();
        assert!(mapping.writer.as_ref().unwrap().shared().is_none());
        v.close(fd).unwrap();
        drop(v);
        assert!(control.upgrade().is_some());
        mapping.write(0, b"owner-bound").unwrap();
        let mut bytes = [0; 11];
        mapping.read(0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"owner-bound");
        drop(mapping);
        assert!(control.upgrade().is_none());
    }
    #[test]
    fn serial_private_file_atomics_detach_without_modifying_file_or_peer() {
        use trames_memory::CpuMemory;
        for exclusive in [false, true] {
            let mut v = Vfs::default();
            let fd = v.memfd_create(b"private-atomic", 0).unwrap();
            v.truncate_fd(fd, PAGE_SIZE).unwrap();
            let mut memory = Memory::default();
            for base in [0x40000, 0x50000] {
                mapped(&v, &mut memory, fd, base, PAGE_SIZE, false, Permissions::RW);
            }
            if exclusive {
                let mut old = [0; 8];
                let token = memory.exclusive_read(0x40000, &mut old).unwrap();
                assert!(memory
                    .exclusive_write(0x40000, &[7; 8], Some(token))
                    .unwrap());
            } else {
                memory
                    .atomic_update(0x40000, 8, |b| {
                        b.fill(7);
                        ((), true)
                    })
                    .unwrap();
            }
            assert_eq!(memory.read_array::<8>(0x40000), Ok([7; 8]));
            assert_eq!(memory.read_array::<8>(0x50000), Ok([0; 8]));
            v.seek(fd, 0, 0).unwrap();
            assert_eq!(v.read(fd, 8).unwrap(), [0; 8]);
        }
    }
    #[test]
    fn backing_epochs_rebuild_only_changed_file_pages_and_still_check_eof_and_cow() {
        use trames_memory::{parallel::Registry, CpuMemory};
        let mut v = Vfs::default();
        let cold = v.open_at(AT_FDCWD, b"/elf-text", 0x42, 0o600).unwrap();
        let hot = v.memfd_create(b"display-buffer", 0).unwrap();
        v.truncate_fd(cold, PAGE_SIZE * 256).unwrap();
        v.truncate_fd(hot, PAGE_SIZE).unwrap();
        let mut m = Memory::default();
        mapped(
            &v,
            &mut m,
            cold,
            0x100000,
            PAGE_SIZE * 256,
            false,
            Permissions::RX,
        );
        mapped(
            &v,
            &mut m,
            cold,
            0x400000,
            PAGE_SIZE,
            false,
            Permissions::RW,
        );
        mapped(&v, &mut m, hot, 0x500000, PAGE_SIZE, true, Permissions::RW);
        m.write_array(0x400000, [88]).unwrap();
        let mut registry = Registry::default();
        let view = m.parallel_view(&mut registry).unwrap();
        let code = view.instruction_identity();
        drop(view);
        for value in 1..=8u8 {
            v.seek(hot, 0, 0).unwrap();
            v.write(hot, &[value]).unwrap();
            let view = m.parallel_view(&mut registry).unwrap();
            assert_eq!(view.instruction_identity(), code);
            assert_eq!(view.read_array::<1>(0x500000).unwrap(), [value]);
            assert_eq!(view.fetch_u32(0x100000).unwrap(), 0);
            assert_eq!(view.read_array::<1>(0x400000).unwrap(), [88]);
            drop(view);
        }
        assert_eq!(registry.metrics.full_rebuilds, 1);
        assert_eq!(registry.metrics.incremental_pages, 8);
        // Display-buffer writes must not revisit all 257 unrelated ELF/COW
        // mappings. File versions and EOF checks remain live for changed files.
        assert_eq!(registry.metrics.backing_page_checks, 8);
        v.seek(cold, 0, 0).unwrap();
        v.write(cold, &0xd503201fu32.to_le_bytes()).unwrap();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_ne!(view.instruction_identity(), code);
        assert_eq!(view.fetch_u32(0x100000).unwrap(), 0xd503201f);
        assert_eq!(view.read_array::<1>(0x400000).unwrap(), [88]);
        drop(view);
        v.truncate_fd(cold, 0).unwrap();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(view.fetch_u32(0x100000), Err(MemoryError::Bus(0x100000)));
        assert_eq!(
            view.read_array::<1>(0x400000),
            Err(MemoryError::Bus(0x400000))
        );
        drop(view);
        v.truncate_fd(cold, PAGE_SIZE * 256).unwrap();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(view.fetch_u32(0x100000).unwrap(), 0);
        assert_eq!(view.read_array::<1>(0x400000).unwrap(), [88]);
    }
    #[test]
    fn file_change_domains_survive_mapping_replacement_and_retained_views() {
        use trames_memory::{parallel::Registry, CpuMemory};
        let mut v = Vfs::default();
        let a = v.open_at(AT_FDCWD, b"/a", 0x42, 0o600).unwrap();
        let b = v.open_at(AT_FDCWD, b"/b", 0x42, 0o600).unwrap();
        v.truncate_fd(a, 2 * PAGE_SIZE).unwrap();
        v.write(b, &[2]).unwrap();
        let mut m = Memory::default();
        mapped(&v, &mut m, a, 0x10000, 2 * PAGE_SIZE, true, Permissions::R);
        mapped(&v, &mut m, b, 0x20000, PAGE_SIZE, true, Permissions::R);
        let mut registry = Registry::default();
        drop(m.parallel_view(&mut registry).unwrap());

        // Remove the old representative, reuse its root slot with another
        // file, and add a fresh alias after changing a surviving old page.
        m.unmap(0x10000, PAGE_SIZE).unwrap();
        v.seek(a, PAGE_SIZE as i64, 0).unwrap();
        v.write(a, &[11]).unwrap();
        mapped(&v, &mut m, b, 0x10000, PAGE_SIZE, true, Permissions::R);
        mapped(&v, &mut m, a, 0x30000, PAGE_SIZE, true, Permissions::R);
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<1>(0x11000), Ok([11]));
        assert_eq!(view.read_array::<1>(0x10000), Ok([2]));
        assert_eq!(view.read_array::<1>(0x30000), Ok([0]));
        drop(view);

        // EOF must still invalidate every alias even when another member is
        // simultaneously unmapped. Then remove the last member of the domain.
        v.truncate_fd(a, 0).unwrap();
        m.unmap(0x11000, PAGE_SIZE).unwrap();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(
            view.read_array::<1>(0x30000),
            Err(MemoryError::Bus(0x30000))
        );
        drop(view);
        m.unmap(0x30000, PAGE_SIZE).unwrap();
        drop(m.parallel_view(&mut registry).unwrap());
        v.truncate_fd(a, PAGE_SIZE).unwrap();
        mapped(&v, &mut m, a, 0x40000, PAGE_SIZE, true, Permissions::R);
        let old = m.parallel_view(&mut registry).unwrap();
        assert_eq!(old.read_array::<1>(0x40000), Ok([0]));

        // An externally retained View takes the full snapshot path. Its address
        // table stays frozen, and shared file bytes remain coherent in both.
        v.seek(b, 0, 0).unwrap();
        v.write(b, &[9]).unwrap();
        m.unmap(0x10000, PAGE_SIZE).unwrap();
        let new = m.parallel_view(&mut registry).unwrap();
        assert_eq!(old.read_array::<1>(0x10000), Ok([9]));
        assert_eq!(
            new.read_array::<1>(0x10000),
            Err(MemoryError::Unmapped(0x10000))
        );
        assert_eq!(new.read_array::<1>(0x20000), Ok([9]));
        assert_eq!(registry.metrics.full_rebuilds, 2);
    }
    #[test]
    fn workers_share_file_and_memfd_bytes_without_a_publication_copy() {
        use trames_memory::{parallel::Registry, CpuMemory, NativeMemory};
        for memfd in [false, true] {
            let mut v = Vfs::default();
            let fd = if memfd {
                v.memfd_create(b"shared-page", 0).unwrap()
            } else {
                v.open_at(AT_FDCWD, b"/shared-page", 0x42, 0o600).unwrap()
            };
            v.truncate_fd(fd, PAGE_SIZE).unwrap();
            let mut memory = Memory::default();
            mapped(
                &v,
                &mut memory,
                fd,
                0x40000,
                PAGE_SIZE,
                true,
                Permissions::RW,
            );
            mapped(
                &v,
                &mut memory,
                fd,
                0x50000,
                PAGE_SIZE,
                false,
                Permissions::RX,
            );
            assert_eq!(memory.read_array::<8>(0x40008).unwrap(), [0; 8]);
            assert_eq!(memory.read_array::<8>(0x50008).unwrap(), [0; 8]);
            let mut registry = Registry::default();
            let mut view = memory.parallel_view(&mut registry).unwrap();
            assert_eq!(registry.metrics.copied_publish_bytes, 0);
            let code_epoch = view.instruction_identity();
            let code_page = memory.instruction_page_identity(0x50008).unwrap();
            view.write_array(0x40008, *b"worker!!").unwrap();
            assert_ne!(code_epoch, view.instruction_identity());
            assert_ne!(
                code_page,
                memory.instruction_page_identity(0x50008).unwrap()
            );
            // File I/O and a private read-only alias read the same physical bytes
            // even before metadata/persistence commit.
            v.seek(fd, 8, 0).unwrap();
            assert_eq!(v.read(fd, 8).unwrap(), b"worker!!");
            assert_eq!(memory.read_array::<8>(0x50008).unwrap(), *b"worker!!");
            let pair =
                NativeMemory::with_read_pair(&memory, 0x40008, 0x50008, 8, |a, b| a == b).unwrap();
            assert_eq!(pair, (true, true, true));
            let mut old = [0; 8];
            let token = view.exclusive_read(0x40008, &mut old).unwrap();
            memory
                .with_write_chunk(0x40008, 8, |bytes| bytes.copy_from_slice(b"native!!"))
                .unwrap();
            assert!(!view
                .exclusive_write(0x40008, b"stale!!!", Some(token))
                .unwrap());
            assert_eq!(view.read_array::<8>(0x50008).unwrap(), *b"native!!");
            drop(view);
            memory.commit_parallel().unwrap();
            drop(memory.parallel_view(&mut registry).unwrap());
            assert_eq!(registry.metrics.copied_publish_bytes, 0);
            memory.sync_range(0x40000, PAGE_SIZE).unwrap();
            v.seek(fd, 8, 0).unwrap();
            assert_eq!(v.read(fd, 8).unwrap(), b"native!!");
        }
    }
    #[test]
    fn eof_placeholders_stay_zero_and_growth_updates_existing_mappings() {
        let data = MappedData::new(FileData::memory(vec![17; 10]), true);
        let pages = data.batch(0, 32 * PAGE_SIZE).unwrap();
        assert!(!pages[0]
            .bytes
            .read()
            .unwrap()
            .with_read(0, 10, |bytes| bytes.iter().all(|&b| b == 0)));
        assert!(pages[1..]
            .iter()
            .all(|p| matches!(&*p.bytes.read().unwrap(), PageStorage::Unpublished { bytes, .. } if bytes.unmaterialized_zero())));
        data.truncate(4 * PAGE_SIZE).unwrap();
        data.write_at(3 * PAGE_SIZE + 8, b"grown").unwrap();
        assert_eq!(
            pages[3]
                .bytes
                .read()
                .unwrap()
                .with_read(8, 5, |bytes| bytes.to_vec()),
            b"grown"
        );
        assert!(
            matches!(&*pages[31].bytes.read().unwrap(), PageStorage::Unpublished { bytes, .. } if bytes.unmaterialized_zero())
        );
        data.truncate(0).unwrap();
        assert!(pages
            .iter()
            .all(|p| matches!(&*p.bytes.read().unwrap(), PageStorage::Unpublished { bytes, .. } if bytes.unmaterialized_zero())));

        use trames_memory::{parallel::Registry, CpuMemory};
        let mut v = Vfs::default();
        let fd = v.open_at(AT_FDCWD, b"/grow-eof", 0x42, 0o600).unwrap();
        v.write(fd, b"x").unwrap();
        let mut m = Memory::default();
        mapped(
            &v,
            &mut m,
            fd,
            0x10000,
            4 * PAGE_SIZE,
            true,
            Permissions::RW,
        );
        let mut registry = Registry::default();
        let mut before = m.parallel_view(&mut registry).unwrap();
        assert_eq!(
            before.read_array::<1>(0x13000),
            Err(MemoryError::Bus(0x13000))
        );
        assert_eq!(
            before.write_array(0x13000, [42u8]),
            Err(MemoryError::Bus(0x13000))
        );
        drop(before);
        v.truncate_fd(fd, 4 * PAGE_SIZE).unwrap();
        v.seek(fd, (3 * PAGE_SIZE) as i64, 0).unwrap();
        v.write(fd, b"z").unwrap();
        let mut grown = m.parallel_view(&mut registry).unwrap();
        assert_eq!(grown.read_array::<1>(0x13000), Ok(*b"z"));
        grown.write_array(0x13000, *b"!").unwrap();
        drop(grown);
        m.commit_parallel().unwrap();
        v.seek(fd, (3 * PAGE_SIZE) as i64, 0).unwrap();
        assert_eq!(v.read(fd, 1).unwrap(), b"!");
    }
    #[test]
    fn epoch_file_io_checks_live_inode_aliases_in_any_vm_not_the_cached_fd_mask() {
        let mut v = Vfs::default();
        v.import_file(b"/original", b"abcdefgh".to_vec()).unwrap();
        v.link_at(AT_FDCWD, b"/original", AT_FDCWD, b"/alias")
            .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/original", 2, 0).unwrap();
        let alias = v.open_at(AT_FDCWD, b"/alias", 2, 0).unwrap();
        let candidate = v.file_descriptors();
        assert!(v.epoch_file_io(alias, false));
        assert!(v.epoch_file_io(alias, true));
        let mut other_vm = Memory::default();
        let pages = v.mapping_pages(fd, 0, PAGE_SIZE, false, false).unwrap();
        other_vm
            .map_backed(0x8000, pages, false, Permissions::R, false)
            .unwrap();
        assert_eq!(v.file_descriptors(), candidate);
        assert!(v.epoch_file_io(alias, false));
        assert!(!v.epoch_file_io(alias, true));
        let shared = v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap();
        other_vm
            .map_backed(0x9000, shared, true, Permissions::RW, false)
            .unwrap();
        assert!(!v.epoch_file_io(alias, false));
        v.rename_at(AT_FDCWD, b"/alias", AT_FDCWD, b"/moved", 0)
            .unwrap();
        v.unlink_at(AT_FDCWD, b"/original", false).unwrap();
        assert!(!v.epoch_file_io(alias, false));
        // A pathname replacement is a different inode; it remains eligible.
        v.import_file(b"/original", b"replacement".to_vec())
            .unwrap();
        let replacement = v.open_at(AT_FDCWD, b"/original", 0, 0).unwrap();
        assert!(v.epoch_file_io(replacement, false));
        other_vm.unmap(0x8000, PAGE_SIZE).unwrap();
        assert!(!v.epoch_file_io(alias, false));
        other_vm.unmap(0x9000, PAGE_SIZE).unwrap();
        assert!(v.epoch_file_io(alias, false));
        assert!(v.epoch_file_io(alias, true));
        let host_shared = v.memfd_create(b"host-display", 0).unwrap();
        assert!(!v.epoch_file_io(host_shared, false));
        v.set_runtime_info(1, RuntimeInfo::default());
        let dynamic = v.open_at(AT_FDCWD, b"/proc/stat", 0, 0).unwrap();
        assert!(!v.epoch_file_io(dynamic, false));
        let _ = v.file_descriptors();
        v.close(replacement).unwrap();
        assert_eq!(
            v.file_descriptors()[replacement as usize / 64] & (1 << (replacement % 64)),
            0
        );
    }
    #[test]
    fn memfd_native_views_share_guest_pages_and_keep_physical_budget_until_last_lease() {
        let mut v = Vfs::default();
        let fd = v.memfd_create(b"wayland-pool", 0).unwrap();
        v.truncate_fd(fd, PAGE_SIZE * 2).unwrap();
        let file = v.shared_file(fd).unwrap();
        let native = file.map(0, (PAGE_SIZE * 2) as usize).unwrap();
        let mut m = Memory::default();
        mapped(
            &v,
            &mut m,
            fd,
            0x40000,
            PAGE_SIZE * 2,
            true,
            Permissions::RW,
        );
        m.write_array(0x41008, *b"pixels!!").unwrap();
        // SAFETY: no guest CPU runs while this coordinator test reads the view.
        unsafe {
            native.with_read(4104, 8, |b| assert_eq!(b, b"pixels!!"));
        }
        file.write_at(8, b"native!!").unwrap();
        assert_eq!(m.read_array::<8>(0x40008).unwrap(), *b"native!!");
        let charged = crate::memfd::MEMFD_BYTES - file.capacity() as u64;
        v.close(fd).unwrap();
        drop(m);
        drop(file);
        assert_eq!(v.memfd_available(), charged);
        drop(native);
        assert_eq!(v.memfd_available(), crate::memfd::MEMFD_BYTES);
    }

    #[test]
    fn direct_file_borrows_dirty_writeback_alias_tokens_and_live_eof() {
        let mut v = Vfs::default();
        let fd = v.open_at(-100, b"/native-mapped", 0x42, 0o600).unwrap();
        v.truncate_fd(fd, PAGE_SIZE * 2).unwrap();
        let mut m = Memory::default();
        mapped(&v, &mut m, fd, 0x1000, PAGE_SIZE * 2, true, Permissions::RW);
        mapped(&v, &mut m, fd, 0x5000, PAGE_SIZE * 2, true, Permissions::RX);
        let token = m.instruction_page_identity(0x5000).unwrap();
        assert_eq!(
            m.fill_with(0x1ffe, 8, |b| b.fill(91)).unwrap().direct_write,
            8
        );
        assert_eq!(
            m.with_read_chunk(0x5ffe, 2, |b| b.to_vec()).unwrap(),
            (vec![91; 2], true)
        );
        assert_ne!(token, m.instruction_page_identity(0x5000).unwrap());
        m.sync_range(0x1000, PAGE_SIZE * 2).unwrap();
        v.seek(fd, 4094, 0).unwrap();
        assert_eq!(v.read(fd, 8).unwrap(), vec![91; 8]);
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        assert_eq!(
            m.with_read_chunk(0x6000, 1, |b| b[0]),
            Err(MemoryError::Bus(0x6000))
        );
        assert!(m.fill_with(0x1fff, 2, |b| b.fill(0)).is_err());
        assert_eq!(m.read_array::<1>(0x1fff).unwrap(), [91]);
    }

    #[test]
    fn parallel_readonly_alias_dirty_fragments_private_refresh_and_live_eof() {
        use trames_memory::{parallel::Registry, CpuMemory};
        let mut v = Vfs::default();
        let fd = v.open_at(-100, b"/parallel-mapped", 0x42, 0o600).unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let mut memory = Memory::default();
        mapped(&v, &mut memory, fd, 0x1000, PAGE_SIZE, true, Permissions::R);
        mapped(
            &v,
            &mut memory,
            fd,
            0x5000,
            PAGE_SIZE,
            true,
            Permissions::RW,
        );
        let mut child = memory.clone();
        let mut registry = Registry::default();
        let reader = memory.parallel_view(&mut registry).unwrap();
        let mut writer = child.parallel_view(&mut registry).unwrap();
        writer.write_array(0x5008, 42u64.to_le_bytes()).unwrap();
        assert_eq!(reader.read_u64(0x1008).unwrap(), 42);
        drop((reader, writer));
        memory.commit_parallel().unwrap();
        child.commit_parallel().unwrap();
        assert_eq!(memory.read_u64(0x1008).unwrap(), 42);
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(
            u64::from_le_bytes(v.read(fd, 16).unwrap()[8..16].try_into().unwrap()),
            42
        );
        // An undetached private snapshot must refresh after fd writes and must
        // still check EOF; it cannot become an authoritative detached file copy.
        mapped(
            &v,
            &mut memory,
            fd,
            0x9000,
            PAGE_SIZE,
            false,
            Permissions::RX,
        );
        let reader = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(reader.read_u64(0x9008).unwrap(), 42);
        let old_global = reader.instruction_identity();
        let old_page = reader.instruction_page_identity(0x9000).unwrap();
        drop(reader);
        v.seek(fd, 8, 0).unwrap();
        v.write(fd, &99u64.to_le_bytes()).unwrap();
        let reader = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(reader.read_u64(0x9008).unwrap(), 99);
        assert_ne!(reader.instruction_identity(), old_global);
        assert_ne!(reader.instruction_page_identity(0x9000).unwrap(), old_page);
        drop(reader);
        v.truncate_fd(fd, 0).unwrap();
        let reader = memory.parallel_view(&mut registry).unwrap();
        assert!(matches!(
            reader.read_u64(0x9008),
            Err(MemoryError::Bus(0x9008))
        ));
    }
    fn mapped(v: &Vfs, m: &mut Memory, fd: u32, at: u64, len: u64, shared: bool, p: Permissions) {
        m.map_backed(
            at,
            v.mapping_pages(fd, 0, len, shared, p.write).unwrap(),
            shared,
            p,
            false,
        )
        .unwrap();
    }
    #[test]
    fn alias_fd_io_cow_truncate_permissions_and_unlinked_lifetime() {
        let mut v = Vfs::default();
        let mut m = Memory::default();
        let fd = v.open_at(-100, b"/mapped", 0x42, 0o600).unwrap();
        v.truncate_fd(fd, PAGE_SIZE + 2).unwrap();
        mapped(&v, &mut m, fd, 0x1000, PAGE_SIZE * 2, true, Permissions::RW);
        mapped(&v, &mut m, fd, 0x4000, PAGE_SIZE, false, Permissions::RW);
        m.write_array(0x1000, [1, 2, 3, 4]).unwrap();
        assert_eq!(v.pread(fd, 4, 0).unwrap(), [1, 2, 3, 4]);
        v.pwrite(fd, &[5], 1).unwrap();
        assert_eq!(m.read_array::<4>(0x1000).unwrap(), [1, 5, 3, 4]);
        m.write_array(0x4000, [9; 4]).unwrap();
        v.pwrite(fd, &[7], 0).unwrap();
        assert_eq!(m.read_array::<4>(0x4000).unwrap(), [9; 4]);
        m.discard(0x4000, PAGE_SIZE).unwrap();
        assert_eq!(m.read_array::<4>(0x4000).unwrap(), [7, 5, 3, 4]);
        m.write_array(0x2003, [8]).unwrap();
        assert_eq!(
            v.stat_fd(fd).unwrap()[48..56],
            (PAGE_SIZE + 2).to_le_bytes()
        );
        v.truncate_fd(fd, 1).unwrap();
        assert_eq!(m.read_array::<1>(0x2000), Err(MemoryError::Bus(0x2000)));
        m.protect(
            0x2000,
            PAGE_SIZE,
            Permissions {
                read: false,
                write: false,
                execute: false,
            },
        )
        .unwrap();
        assert!(matches!(
            m.read_array::<1>(0x2000),
            Err(MemoryError::Permission { .. })
        ));
        v.truncate_fd(fd, PAGE_SIZE * 2).unwrap();
        m.protect(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.read_array::<1>(0x2003).unwrap(), [0]);
        v.close(fd).unwrap();
        v.unlink_at(-100, b"/mapped", false).unwrap();
        m.write_array(0x1000, [6]).unwrap();
        assert_eq!(m.read_array::<1>(0x1000).unwrap(), [6]);
        m.unmap(0x1000, PAGE_SIZE * 2).unwrap();
        m.unmap(0x4000, PAGE_SIZE).unwrap();
        assert_eq!(v.allocated_bytes(), 0);
    }
    #[test]
    fn read_only_shared_mapping_cannot_gain_write_access() {
        let mut v = Vfs::default();
        v.import_file(b"/file", vec![1; 4096]).unwrap();
        let fd = v.open_at(-100, b"/file", 0, 0).unwrap();
        let mut m = Memory::default();
        mapped(&v, &mut m, fd, 0x1000, PAGE_SIZE, true, Permissions::R);
        assert_eq!(
            m.protect(0x1000, PAGE_SIZE, Permissions::RW),
            Err(MemoryError::Permission {
                address: 0x1000,
                access: Access::Write
            })
        );
        assert_eq!(m.read_array::<1>(0x1000).unwrap(), [1]);
    }
    #[test]
    fn mapped_code_aliases_and_fd_writes_change_decoder_tokens() {
        let mut v = Vfs::default();
        let fd = v.open_at(-100, b"/code", 0x42, 0o600).unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let mut m = Memory::default();
        mapped(&v, &mut m, fd, 0x1000, PAGE_SIZE, true, Permissions::RW);
        mapped(&v, &mut m, fd, 0x3000, PAGE_SIZE, true, Permissions::RX);
        m.write_array(0x1000, 0xd2800020u32.to_le_bytes()).unwrap();
        let before = m.instruction_page_identity(0x3000).unwrap();
        let epoch = m.instruction_identity();
        v.pwrite(fd, &0xd2800040u32.to_le_bytes(), 0).unwrap();
        assert_ne!(epoch, m.instruction_identity());
        assert_ne!(before, m.instruction_page_identity(0x3000).unwrap());
        assert_eq!(m.fetch_u32(0x3000).unwrap(), 0xd2800040);
        m.unmap(0x1000, PAGE_SIZE).unwrap();
        m.unmap(0x3000, PAGE_SIZE).unwrap();
        let n = v
            .descriptor(fd)
            .unwrap()
            .open
            .borrow()
            .node
            .clone()
            .unwrap();
        if let Content::File(FileData::Mapped(data)) = &n.borrow().content {
            assert!(data.pages.borrow().is_empty());
        };
    }
}
