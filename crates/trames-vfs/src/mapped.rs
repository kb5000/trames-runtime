// SPDX-License-Identifier: GPL-3.0-or-later
//! Coherent mapped pages retained by mappings, not by the inode's weak cache.
use super::*;
use storage::FileData;
use trames_memory::{MemoryError, PageBacking, PAGE_SIZE};
pub(super) struct FilePage {
    identity: u64,
    bytes: RefCell<Box<[u8; PAGE_SIZE as usize]>>,
    dirty: Cell<bool>,
    writers: Cell<u32>,
    version: Cell<u64>,
}
pub(super) struct MappedData {
    data: RefCell<Box<FileData>>,
    pages: RefCell<BTreeMap<u64, Weak<FilePage>>>,
}
impl MappedData {
    pub(super) fn new(data: FileData) -> Self {
        Self {
            data: RefCell::new(Box::new(data)),
            pages: RefCell::new(BTreeMap::new()),
        }
    }
    pub(super) fn len(&self) -> u64 {
        self.data.borrow().len()
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
    fn page(&self, offset: u64) -> Result<Rc<FilePage>> {
        if let Some(p) = self.pages.borrow().get(&offset).and_then(Weak::upgrade) {
            return Ok(p);
        }
        let data = self.data.borrow().read_at(offset, PAGE_SIZE as usize)?;
        let mut bytes = Box::new([0; PAGE_SIZE as usize]);
        bytes[..data.len()].copy_from_slice(&data);
        let page = Rc::new(FilePage {
            identity: trames_memory::new_backing_identity(),
            bytes: RefCell::new(bytes),
            dirty: Cell::new(false),
            writers: Cell::new(0),
            version: Cell::new(0),
        });
        let mut pages = self.pages.borrow_mut();
        pages.insert(offset, Rc::downgrade(&page));
        Ok(page)
    }
    fn batch(&self, offset: u64, len: u64) -> Result<Vec<Rc<FilePage>>> {
        self.pages.borrow_mut().retain(|_, p| p.strong_count() != 0);
        let mut result = Vec::new();
        for batch in (0..len).step_by(storage::MAX_TRANSFER) {
            let size = (len - batch).min(storage::MAX_TRANSFER as u64);
            let bytes = self.data.borrow().read_at(offset + batch, size as usize)?;
            for inside in (0..size).step_by(PAGE_SIZE as usize) {
                let at = offset + batch + inside;
                let existing = self.pages.borrow().get(&at).and_then(Weak::upgrade);
                let page = if let Some(page) = existing {
                    page
                } else {
                    let mut data = Box::new([0; PAGE_SIZE as usize]);
                    let available = bytes
                        .len()
                        .saturating_sub(inside as usize)
                        .min(PAGE_SIZE as usize);
                    if available != 0 {
                        data[..available]
                            .copy_from_slice(&bytes[inside as usize..inside as usize + available]);
                    }
                    let page = Rc::new(FilePage {
                        identity: trames_memory::new_backing_identity(),
                        bytes: RefCell::new(data),
                        dirty: Cell::new(false),
                        writers: Cell::new(0),
                        version: Cell::new(0),
                    });
                    self.pages.borrow_mut().insert(at, Rc::downgrade(&page));
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
                out[(start - offset) as usize..(to - offset) as usize].copy_from_slice(
                    &p.bytes.borrow()[(start - base) as usize..(to - base) as usize],
                );
            }
        }
        Ok(out)
    }
    pub(super) fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<usize> {
        let count = self.data.borrow_mut().write_at(offset, bytes)?;
        let end = offset + count as u64;
        for (&base, p) in self.pages.borrow().range((offset & !(PAGE_SIZE - 1))..end) {
            if let Some(p) = p.upgrade() {
                let start = base.max(offset);
                let to = (base + PAGE_SIZE).min(end);
                p.bytes.borrow_mut()[(start - base) as usize..(to - base) as usize]
                    .copy_from_slice(&bytes[(start - offset) as usize..(to - offset) as usize]);
                p.version.set(p.version.get().wrapping_add(1));
            }
        }
        trames_memory::backing_changed();
        Ok(count)
    }
    fn flush(&self, offset: u64, page: &FilePage) -> Result<()> {
        if !page.dirty.get() {
            return Ok(());
        }
        let count = self.len().saturating_sub(offset).min(PAGE_SIZE) as usize;
        if count != 0 {
            let written = self
                .data
                .borrow_mut()
                .write_at(offset, &page.bytes.borrow()[..count])?;
            if written != count {
                return Err(Errno(5));
            }
        }
        page.dirty.set(false);
        Ok(())
    }
    pub(super) fn has_writers(&self) -> bool {
        self.pages
            .borrow()
            .values()
            .filter_map(Weak::upgrade)
            .any(|p| p.writers.get() != 0)
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
        for (&base, page) in self.pages.borrow().iter() {
            if let Some(page) = page.upgrade() {
                let bytes = self.data.borrow().read_at(base, PAGE_SIZE as usize)?;
                let mut content = page.bytes.borrow_mut();
                content.fill(0);
                content[..bytes.len()].copy_from_slice(&bytes);
                page.version.set(page.version.get().wrapping_add(1));
                page.dirty.set(false);
            }
        }
        trames_memory::backing_changed();
        Ok(())
    }
}
struct FileMapping {
    mount: Option<Rc<Mount>>,
    node: Rc<RefCell<Node>>,
    page: Rc<FilePage>,
    offset: u64,
    writable: bool,
    executable: bool,
}
impl FileMapping {
    fn create(
        node: Rc<RefCell<Node>>,
        mount: Option<Rc<Mount>>,
        offset: u64,
        writable: bool,
        executable: bool,
    ) -> Result<Rc<dyn PageBacking>> {
        let page = if let Content::File(FileData::Mapped(data)) = &node.borrow().content {
            data.page(offset)?
        } else {
            return Err(Errno(19));
        };
        if writable {
            page.writers.set(page.writers.get() + 1);
            if let Some(m) = &mount {
                m.writers.set(m.writers.get() + 1);
            }
        }
        Ok(Rc::new(Self {
            mount,
            node,
            page,
            offset,
            writable,
            executable,
        }))
    }
}
impl PageBacking for FileMapping {
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
    fn check(&self, address: u64) -> std::result::Result<(), MemoryError> {
        let n = self.node.borrow();
        let Content::File(data) = &n.content else {
            return Err(MemoryError::Bus(address));
        };
        if self.offset >= data.len().div_ceil(PAGE_SIZE) * PAGE_SIZE {
            return Err(MemoryError::Bus(address));
        }
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> std::result::Result<(), MemoryError> {
        out.copy_from_slice(&self.page.bytes.borrow()[offset..offset + out.len()]);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> std::result::Result<(), MemoryError> {
        if !self.writable {
            return Err(MemoryError::BackingIo(13));
        }
        self.page.bytes.borrow_mut()[offset..offset + bytes.len()].copy_from_slice(bytes);
        self.page.dirty.set(true);
        self.page
            .version
            .set(self.page.version.get().wrapping_add(1));
        self.node.borrow_mut().times[1] = storage::Timestamp::now();
        trames_memory::backing_changed();
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, MemoryError> {
        f(&self.page.bytes.borrow()[offset..offset + len]);
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
        let mut bytes = self.page.bytes.borrow_mut();
        self.page.dirty.set(true);
        self.page
            .version
            .set(self.page.version.get().wrapping_add(1));
        self.node.borrow_mut().times[1] = storage::Timestamp::now();
        trames_memory::backing_changed();
        f(&mut bytes[offset..offset + len]);
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
        self.page.version.get()
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
            self.node.clone(),
            self.mount.clone(),
            offset,
            self.writable,
            self.executable,
        )
        .map_err(|e| MemoryError::BackingIo(e.0))
    }
}
impl Drop for FileMapping {
    fn drop(&mut self) {
        if self.writable {
            self.page.writers.set(self.page.writers.get() - 1);
            if let Some(m) = &self.mount {
                m.writers.set(m.writers.get() - 1);
            }
        }
        // Closing the descriptor/unlinking the path never invalidates this inode.
        if let Content::File(FileData::Mapped(data)) = &self.node.borrow().content {
            let _ = data.flush(self.offset, &self.page);
            if Rc::strong_count(&self.page) == 1 {
                data.pages.borrow_mut().remove(&self.offset);
            }
        }
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
        let o = self.descriptor(fd)?.open.borrow();
        if o.flags & O_PATH != 0 {
            return Err(Errno(9));
        }
        if o.flags & 3 == 1 {
            return Err(Errno(13));
        }
        if shared && writable && o.flags & 3 != 2 {
            return Err(Errno(13));
        }
        if o.mount
            .as_ref()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
        {
            return Err(Errno(19));
        }
        let node = o.node.clone().ok_or(Errno(19))?;
        let readonly = o.mount.as_ref().is_some_and(|m| m.readonly());
        if shared && writable && readonly {
            return Err(Errno(30));
        }
        let sealed = node.borrow().seals.is_some_and(|s| s & 8 != 0);
        if shared && writable && sealed {
            return Err(Errno(1));
        }
        let may_write =
            !readonly && shared && o.flags & 3 == 2 && !sealed && !node.borrow().volatile;
        let mut n = node.borrow_mut();
        let Content::File(data) = &mut n.content else {
            return Err(Errno(19));
        };
        if !matches!(data, FileData::Mapped(_)) {
            let original = std::mem::replace(data, FileData::Memory(Vec::new()));
            *data = FileData::Mapped(Box::new(MappedData::new(original)));
        }
        offset.checked_add(len).ok_or(Errno(22))?;
        let buffers = if let FileData::Mapped(data) = data {
            data.batch(offset, len)?
        } else {
            unreachable!("mapped data")
        };
        drop(n);
        let mount = o.mount.clone();
        let executable = mount
            .as_ref()
            .is_none_or(|m| m.flags.get() & mounts::MS_NOEXEC == 0);
        drop(o);
        let mut pages: Vec<Rc<dyn PageBacking>> = Vec::new();
        for (i, page) in buffers.into_iter().enumerate() {
            if may_write {
                page.writers.set(page.writers.get() + 1);
                if let Some(m) = &mount {
                    m.writers.set(m.writers.get() + 1);
                }
            }
            pages.push(Rc::new(FileMapping {
                mount: mount.clone(),
                node: node.clone(),
                page,
                offset: offset + i as u64 * PAGE_SIZE,
                writable: may_write,
                executable,
            }));
        }
        Ok(pages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Access, Memory, Permissions};
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
