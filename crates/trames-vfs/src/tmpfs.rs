// SPDX-License-Identifier: GPL-3.0-or-later
//! tmpfs charges guest pages at write, allocation or fault time. Logical EOF
//! and reservations without contents both remain sparse in the host process.
use super::*;
use trames_memory::{CgroupMemoryKind, CgroupReservation, PAGE_SIZE};

pub(super) struct SparseFile {
    pub length: u64,
    pub(super) capabilities: Option<file_caps::FileCaps>,
    pub charge: Arc<file_accounting::FileCharge>,
    // Half-open ranges of allocated guest page numbers, including unwritten pages.
    extents: BTreeMap<u64, u64>,
    bytes: BTreeMap<u64, Arc<file_cache::Page>>,
    resident: BTreeMap<u64, CgroupReservation>,
}
impl SparseFile {
    pub fn new(quota: &Arc<file_accounting::FileQuota>) -> Result<Self> {
        Ok(Self {
            length: 0,
            capabilities: None,
            charge: file_accounting::FileCharge::admit(quota, 0)?,
            extents: BTreeMap::new(),
            bytes: BTreeMap::new(),
            resident: BTreeMap::new(),
        })
    }
    pub fn reserve(&mut self, start: u64, end: u64) -> Result<()> {
        if start == end {
            return Ok(());
        }
        let first = start / PAGE_SIZE;
        let last = end.div_ceil(PAGE_SIZE);
        let left = match self.extents.range(..=first).next_back() {
            Some((_, &stop)) if stop >= last => return Ok(()),
            Some((&begin, &stop)) if stop >= first => begin,
            _ => first,
        };
        let mut right = last;
        let mut occupied = 0;
        for (&a, &b) in self.extents.range(left..=last) {
            occupied += b - a;
            right = right.max(b);
        }
        let extra = (right - left - occupied) * PAGE_SIZE;
        self.charge
            .reserve(self.charge.size().checked_add(extra).ok_or(Errno(28))?)?;
        while let Some(key) = self.extents.range(left..=last).next().map(|(&a, _)| a) {
            self.extents.remove(&key);
        }
        self.extents.insert(left, right);
        Ok(())
    }
    pub fn copy_up(&self, quota: &Arc<file_accounting::FileQuota>) -> Result<Self> {
        let mut copy = Self::new(quota)?;
        let limit = self.length.div_ceil(PAGE_SIZE);
        for (&start, &end) in self.extents.range(..limit) {
            copy.allocate(start * PAGE_SIZE, (end * PAGE_SIZE).min(self.length))?;
        }
        // Unwritten allocations consume guest quota but have no host byte buffers.
        for (&index, page) in self.bytes.range(..limit) {
            if let Some(contents) = page.contents() {
                let mut bytes = vec![0; PAGE_SIZE as usize];
                contents.bytes.copy_read(0, &mut bytes);
                copy.page(index).load(None, || Ok(bytes))?;
            }
        }
        copy.length = self.length;
        Ok(copy)
    }
    pub fn resize(&mut self, length: u64) {
        self.capabilities = None;
        if length <= self.length {
            let limit = length.div_ceil(PAGE_SIZE);
            let mut released: u64 = self
                .extents
                .split_off(&limit)
                .into_iter()
                .map(|(a, b)| b - a)
                .sum();
            if let Some(mut extent) = self.extents.last_entry() {
                let end = extent.get_mut();
                if *end > limit {
                    released += *end - limit;
                    *end = limit;
                }
            }
            self.charge
                .publish(self.charge.size() - released * PAGE_SIZE);
            for (_, page) in self.bytes.range(limit..) {
                page.invalidate();
            }
            self.bytes.retain(|&index, page| {
                index < limit || page.retained() || Arc::strong_count(page) != 1
            });
            for (&base, extent) in self.resident.range(..limit) {
                extent.truncate(limit.saturating_sub(base) as usize);
            }
            self.resident.split_off(&limit);
            if !length.is_multiple_of(PAGE_SIZE) {
                if let Some(page) = self.bytes.get_mut(&(length / PAGE_SIZE)) {
                    page.zero_tail((length % PAGE_SIZE) as usize);
                }
            }
        }
        self.length = length;
    }
    pub fn read(&self, offset: u64, count: usize) -> Result<Vec<u8>> {
        let end = offset + count as u64;
        let within = (offset % PAGE_SIZE) as usize;
        if count <= PAGE_SIZE as usize - within {
            return Ok(self
                .bytes
                .get(&(offset / PAGE_SIZE))
                .and_then(|page| page.contents())
                .map_or_else(
                    || vec![0; count],
                    |page| {
                        let mut bytes = vec![0; count];
                        page.bytes.copy_read(within, &mut bytes);
                        bytes
                    },
                ));
        }
        let mut out = trames_shared::read_buffer(count).map_err(storage::host_errno)?;
        for (&index, page) in self
            .bytes
            .range(offset / PAGE_SIZE..end.div_ceil(PAGE_SIZE))
        {
            let Some(page) = page.contents() else {
                continue;
            };
            let base = index * PAGE_SIZE;
            let from = offset.max(base);
            let to = end.min(base + PAGE_SIZE);
            page.bytes.copy_read(
                (from - base) as usize,
                &mut out[(from - offset) as usize..(to - offset) as usize],
            );
        }
        Ok(out)
    }
    pub fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<usize> {
        let mut written = 0;
        while written < bytes.len() {
            let at = offset + written as u64;
            let within = (at % PAGE_SIZE) as usize;
            let chunk = (bytes.len() - written).min(PAGE_SIZE as usize - within);
            let end = at + chunk as u64;
            let index = at / PAGE_SIZE;
            let page = self.admit_page(index, at, end);
            let page = match page {
                Ok(page) => page,
                Err(error) => {
                    return if written == 0 {
                        Err(error)
                    } else {
                        Ok(written)
                    }
                }
            };
            if written == 0 {
                self.capabilities = None;
            }
            page.bytes
                .copy_write(within, &bytes[written..written + chunk]);
            self.length = self.length.max(end);
            written += chunk;
        }
        Ok(written)
    }
    pub fn page(&mut self, index: u64) -> Arc<file_cache::Page> {
        let page = self
            .bytes
            .entry(index)
            .or_insert_with(|| file_cache::Page::new(CgroupMemoryKind::Shmem))
            .clone();
        if let Some((&base, extent)) = self.resident.range(..=index).next_back() {
            if index - base < extent.pages() as u64 {
                page.adopt(
                    &extent
                        .page((index - base) as usize)
                        .expect("live allocated shmem slice"),
                );
            }
        }
        page
    }
    pub fn has_allocated_after(&self, length: u64) -> bool {
        self.extents
            .last_key_value()
            .is_some_and(|(_, &end)| end > length.div_ceil(PAGE_SIZE))
    }
    pub fn allocate(&mut self, start: u64, end: u64) -> Result<()> {
        if start == end {
            return Ok(());
        }
        let first = start / PAGE_SIZE;
        let last = end.div_ceil(PAGE_SIZE);
        let mut cursor = first;
        if let Some((_, &end)) = self.extents.range(..=first).next_back() {
            cursor = cursor.max(end.min(last));
        }
        let mut gaps = Vec::new();
        for (&begin, &end) in self.extents.range(first..last) {
            if begin > cursor {
                gaps.push(cursor..begin);
            }
            cursor = cursor.max(end.min(last));
        }
        if cursor < last {
            gaps.push(cursor..last);
        }
        // Both resources commit together. Large zero extents need one lease per
        // gap, not a host buffer or page descriptor for every reserved address.
        let mut admitted = Vec::with_capacity(gaps.len());
        for gap in gaps {
            let extent =
                CgroupReservation::new((gap.end - gap.start) as usize, CgroupMemoryKind::Shmem)
                    .map_err(crate::resource_io::memory_error)?;
            admitted.push((gap, extent));
        }
        self.reserve(start, end)?;
        for (gap, extent) in admitted {
            for (&index, page) in self.bytes.range(gap.clone()) {
                page.adopt(
                    &extent
                        .page((index - gap.start) as usize)
                        .expect("new shmem slice"),
                );
            }
            self.resident.insert(gap.start, extent);
        }
        Ok(())
    }
    fn admit_page(&mut self, index: u64, start: u64, end: u64) -> Result<file_cache::Contents> {
        let page = self.page(index);
        if let Some(contents) = page.contents() {
            self.reserve(start, end)?;
            return Ok(contents);
        }
        // Physical admission precedes the storage reservation. Failure in
        // either resource leaves neither an unwritten extent nor a page lease.
        let contents = page.load(None, || Ok(Vec::new()))?;
        if let Err(error) = self.reserve(start, end) {
            page.invalidate();
            return Err(error);
        }
        Ok(contents)
    }
    pub fn fault_page(&mut self, offset: u64) -> Result<Arc<trames_memory::SharedPage>> {
        self.admit_page(
            offset / PAGE_SIZE,
            offset,
            (offset + PAGE_SIZE).min(self.length),
        )
        .map(|page| page.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{parallel::Registry, CpuMemory, Memory, MemoryError, Permissions};

    fn mount(blocks: u32) -> (Vfs, u32) {
        let mut v = Vfs::default();
        v.mkdir_at(AT_FDCWD, b"/tmp", 0o777).unwrap();
        v.mount(
            None,
            b"/tmp",
            Some(b"tmpfs"),
            0,
            Some(format!("nr_blocks={blocks}").as_bytes()),
        )
        .unwrap();
        let fd = v.open_at(AT_FDCWD, b"/tmp/file", 0x42, 0o600).unwrap();
        (v, fd)
    }
    fn blocks(v: &Vfs, fd: u32) -> u64 {
        u64::from_le_bytes(v.stat_fd(fd).unwrap()[64..72].try_into().unwrap()) / 8
    }
    #[test]
    fn preallocated_zero_extents_keep_owner_across_migration_and_return_last_pin() {
        use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        second.set_limit(0);
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.set(Some(first.clone()));
        let _scope = actor.scope();
        let quota = file_accounting::FileQuota::new(Arc::default(), 1 << 40, None, true);
        let mut file = SparseFile::new(&quota).unwrap();
        file.allocate(0, 2 * PAGE_SIZE).unwrap();
        file.resize(2 * PAGE_SIZE);
        assert_eq!(
            file.bytes.len(),
            0,
            "unwritten allocation has no eager host buffers"
        );
        assert_eq!(first.current(), 2 * PAGE_SIZE as usize);
        actor.set(Some(second.clone()));
        file.write(0, b"existing allocation").unwrap();
        assert_eq!(first.current(), 2 * PAGE_SIZE as usize);
        assert_eq!(second.current(), 0);
        let pin = file.page(0).contents().unwrap().bytes;
        file.resize(0);
        assert_eq!(first.current(), PAGE_SIZE as usize);
        assert_eq!(file.charge.size(), 0);
        drop(file);
        assert_eq!(first.current(), PAGE_SIZE as usize);
        drop(pin);
        assert_eq!(first.current(), 0);
    }
    #[test]
    fn fallocate_and_same_size_truncate_preserve_or_release_original_reservations() {
        use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
        let group = MemoryCgroup::new(None);
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.set(Some(group.clone()));
        let _scope = actor.scope();
        let (mut v, fd) = mount(4);
        v.allocate_fd(fd, 1, 2 * PAGE_SIZE, PAGE_SIZE).unwrap();
        v.allocate_fd(fd, 0, 0, PAGE_SIZE).unwrap();
        assert_eq!(group.current(), 2 * PAGE_SIZE as usize);
        assert_eq!(blocks(&v, fd), 2);
        v.allocate_fd(fd, 0, 0, 1).unwrap();
        assert_eq!(
            group.current(),
            2 * PAGE_SIZE as usize,
            "fallocate inside EOF does not truncate other allocations"
        );
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        assert_eq!(group.current(), PAGE_SIZE as usize);
        assert_eq!(blocks(&v, fd), 1);
        v.truncate_fd(fd, 0).unwrap();
        v.allocate_fd(fd, 1, 0, 2 * PAGE_SIZE).unwrap();
        v.truncate_fd(fd, 0).unwrap();
        assert_eq!(
            group.current(),
            0,
            "same EOF still retires keep-size allocations"
        );
        assert_eq!(blocks(&v, fd), 0);
    }
    #[test]
    fn failed_fallocate_refunds_memory_and_storage_together() {
        use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
        let group = MemoryCgroup::new(None);
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.set(Some(group.clone()));
        let _scope = actor.scope();
        let (mut v, fd) = mount(1);
        assert_eq!(v.allocate_fd(fd, 1, 0, 2 * PAGE_SIZE), Err(Errno(28)));
        assert_eq!(group.current(), 0);
        assert_eq!(blocks(&v, fd), 0);
        group.set_limit(PAGE_SIZE as usize);
        assert_eq!(v.allocate_fd(fd, 1, 0, 2 * PAGE_SIZE), Err(Errno(12)));
        assert_eq!(group.current(), 0);
        assert_eq!(blocks(&v, fd), 0);
    }
    #[test]
    fn ordinary_tmpfs_io_and_mapping_share_charges_and_truncate_recharges_new_bytes() {
        use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.set(Some(first.clone()));
        let _scope = actor.scope();
        let (mut v, fd) = mount(4);
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        v.pwrite(fd, b"old", 0).unwrap();
        assert_eq!(first.current(), PAGE_SIZE as usize);
        actor.set(Some(second.clone()));
        let mut memory = Memory::default();
        memory
            .map_backed(
                PAGE_SIZE,
                v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        assert_eq!(memory.read_array::<3>(PAGE_SIZE).unwrap(), *b"old");
        memory.write(PAGE_SIZE, b"new").unwrap();
        assert_eq!(v.pread(fd, 3, 0).unwrap(), b"new");
        assert_eq!(first.current(), PAGE_SIZE as usize);
        assert_eq!(second.current(), 0);
        let pin = {
            let node = v
                .descriptor(fd)
                .unwrap()
                .open
                .borrow()
                .node
                .clone()
                .unwrap();
            let node = node.borrow();
            let Content::File(storage::FileData::Mapped(data)) = &node.content else {
                panic!("mapped tmpfs")
            };
            data.tmpfs_file()
                .unwrap()
                .cache_page(0)
                .unwrap()
                .contents()
                .unwrap()
                .bytes
        };
        v.truncate_fd(fd, 0).unwrap();
        assert_eq!(
            first.current(),
            PAGE_SIZE as usize,
            "old retained bytes remain charged"
        );
        assert!(matches!(
            memory.read_array::<1>(PAGE_SIZE),
            Err(MemoryError::Bus(_))
        ));
        drop(pin);
        assert_eq!(first.current(), 0);
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        assert_eq!(memory.read_array::<3>(PAGE_SIZE).unwrap(), [0; 3]);
        assert_eq!(first.current(), 0);
        assert_eq!(second.current(), PAGE_SIZE as usize);
        assert!(second
            .format_stat()
            .contains(&format!("shmem {}\n", PAGE_SIZE)));
        memory.unmap(PAGE_SIZE, PAGE_SIZE).unwrap();
        drop(memory);
        v.close(fd).unwrap();
        v.unlink_at(AT_FDCWD, b"/tmp/file", false).unwrap();
        assert_eq!(second.current(), 0);
    }

    #[test]
    fn tmpfs_copy_allocates_new_physical_owner_and_failed_memory_admission_keeps_quota() {
        use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.set(Some(first.clone()));
        let _scope = actor.scope();
        let quota = || file_accounting::FileQuota::new(Arc::default(), 4 * PAGE_SIZE, None, true);
        let mut original = SparseFile::new(&quota()).unwrap();
        original.write(0, b"source").unwrap();
        actor.set(Some(second.clone()));
        second.set_limit(0);
        let before = original.charge.size();
        assert_eq!(original.write(PAGE_SIZE, b"x"), Err(Errno(12)));
        assert_eq!(original.charge.size(), before);
        assert_eq!(original.length, 6);
        second.set_limit(PAGE_SIZE as usize);
        let mut copy = original.copy_up(&quota()).unwrap();
        assert_eq!(first.current(), PAGE_SIZE as usize);
        assert_eq!(second.current(), PAGE_SIZE as usize);
        copy.write(0, b"target").unwrap();
        assert_eq!(original.read(0, 6).unwrap(), b"source");
        assert_eq!(copy.read(0, 6).unwrap(), b"target");
        drop(copy);
        assert_eq!(second.current(), 0);
        drop(original);
        assert_eq!(first.current(), 0);
    }
    #[test]
    fn retained_deferred_snapshot_does_not_reuse_bytes_after_truncate_and_regrowth() {
        use trames_memory::{CgroupMemoryTarget, MemoryCgroup};
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(first.clone()));
        let _scope = target.scope();
        let (mut v, fd) = mount(4);
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let mut memory = Memory::default();
        memory
            .map_backed(
                PAGE_SIZE,
                v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let mut registry = Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write_array(PAGE_SIZE, [91]).unwrap();
        assert_eq!(view.read_array::<1>(PAGE_SIZE), Ok([91]));
        drop(view);
        memory.commit_parallel().unwrap();
        target.set(Some(second.clone()));
        let target = v
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let FileOutcome::Layout(work) =
            FileWork::from_vfs(&v, target, FileCommand::Truncate(0)).run()
        else {
            panic!("mapped shrink requests original layout admission");
        };
        let writer = work.begin_layout().unwrap();
        memory.commit_parallel().unwrap();
        let admission = writer
            .try_enter()
            .ok()
            .expect("original mm released its publication");
        let FileOutcome::Complete(reply) = work.enter_layout(admission).run() else {
            panic!("original shrink completes");
        };
        reply.result.unwrap();
        v.truncate_fd(fd, PAGE_SIZE).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<1>(PAGE_SIZE), Ok([0]));
        assert_eq!(first.current(), 0, "obsolete cached byte owner retired");
        assert_eq!(second.current(), PAGE_SIZE as usize);
        drop(view);
        memory.commit_parallel().unwrap();
    }
    #[test]
    fn named_tmpfs_files_keep_the_default_seal_after_unlink() {
        let (mut v, fd) = mount(4);
        assert_eq!(v.seals(fd, None), Ok(1));
        assert_eq!(v.seals(fd, Some(8)), Err(Errno(1)));
        v.unlink_at(AT_FDCWD, b"/tmp/file", false).unwrap();
        assert_eq!(v.seals(fd, None), Ok(1));
        assert_eq!(v.pwrite(fd, b"x", 0), Ok(1));
    }

    #[test]
    fn tmpfs_sparse_ranges_survive_unlink_and_overlapping_reservations() {
        let (mut v, fd) = mount(4);
        let far = 1 << 40;
        v.truncate_fd(fd, far + PAGE_SIZE).unwrap();
        assert_eq!(blocks(&v, fd), 0);
        assert_eq!(v.pread(fd, 8, far).unwrap(), [0; 8]);
        assert_eq!(v.pwrite(fd, b"tail", far).unwrap(), 4);
        v.allocate_fd(fd, 1, 0, 1).unwrap();
        v.allocate_fd(fd, 1, 2 * PAGE_SIZE, 1).unwrap();
        v.allocate_fd(fd, 1, 0, 3 * PAGE_SIZE).unwrap();
        assert_eq!(blocks(&v, fd), 4);
        assert_eq!(
            v.allocate_fd(fd, 1, 2 * PAGE_SIZE, 2 * PAGE_SIZE),
            Err(Errno(28))
        );
        assert_eq!(v.pread(fd, 4, far).unwrap(), b"tail");
        v.unlink_at(AT_FDCWD, b"/tmp/file", false).unwrap();
        v.truncate_fd(fd, PAGE_SIZE + 1).unwrap();
        assert_eq!(blocks(&v, fd), 2);
        v.truncate_fd(fd, far + 4).unwrap();
        assert_eq!(v.pread(fd, 4, far).unwrap(), [0; 4]);
    }

    #[test]
    fn copying_an_unwritten_extent_retains_the_quota_without_materializing_pages() {
        let limit = 1 << 38;
        let quota = || file_accounting::FileQuota::new(Arc::default(), limit, None, true);
        let mut source = SparseFile::new(&quota()).unwrap();
        source.reserve(0, limit).unwrap();
        source.resize(limit);
        source.write(limit - 1, b"x").unwrap();
        let copy = source.copy_up(&quota()).unwrap();
        assert_eq!(copy.bytes.len(), 1);
        assert_eq!(copy.extents.len(), 1);
        assert_eq!(copy.charge.size(), limit);
        assert_eq!(copy.read(limit - 1, 1).unwrap(), b"x");
        assert_eq!(copy.read(0, 1).unwrap(), [0]);
    }
    #[test]
    fn tmpfs_faults_charge_once_and_report_the_accessed_alias() {
        let (mut v, fd) = mount(1);
        v.truncate_fd(fd, 2 * PAGE_SIZE).unwrap();
        let mut m = Memory::new(16 * PAGE_SIZE as usize);
        for address in [0x10000, 0x20000] {
            m.map_backed(
                address,
                v.mapping_pages(fd, 0, 2 * PAGE_SIZE, true, true).unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        }
        assert_eq!(blocks(&v, fd), 0);
        assert_eq!(m.read_array::<1>(0x10001), Ok([0]));
        assert_eq!(m.read_array::<1>(0x20002), Ok([0]));
        assert_eq!(blocks(&v, fd), 1);
        assert_eq!(m.read_array::<1>(0x21003), Err(MemoryError::Bus(0x21003)));
        let mut registry = Registry::default();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(
            view.read_array::<1>(0x11005),
            Err(MemoryError::Bus(0x11005))
        );
        drop(view);
        m.commit_parallel().unwrap();
        v.truncate_fd(fd, 0).unwrap();
        v.truncate_fd(fd, 2 * PAGE_SIZE).unwrap();
        assert_eq!(m.read_array::<1>(0x21003), Ok([0]));
        assert_eq!(m.read_array::<1>(0x10001), Err(MemoryError::Bus(0x10001)));
    }
}
