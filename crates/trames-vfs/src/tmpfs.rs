// SPDX-License-Identifier: GPL-3.0-or-later
//! tmpfs charges guest pages at write, allocation or fault time. Logical EOF
//! and reservations without contents both remain sparse in the host process.
use super::*;
use trames_memory::PAGE_SIZE;

pub(super) struct SparseFile {
    pub length: u64,
    pub charge: Arc<file_accounting::FileCharge>,
    // Half-open ranges of allocated guest page numbers, including unwritten pages.
    extents: BTreeMap<u64, u64>,
    bytes: BTreeMap<u64, Box<[u8; PAGE_SIZE as usize]>>,
}
impl SparseFile {
    pub fn new(quota: &Arc<file_accounting::FileQuota>) -> Result<Self> {
        Ok(Self {
            length: 0,
            charge: file_accounting::FileCharge::admit(quota, 0)?,
            extents: BTreeMap::new(),
            bytes: BTreeMap::new(),
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
            copy.reserve(start * PAGE_SIZE, (end * PAGE_SIZE).min(self.length))?;
        }
        // Unwritten allocations consume guest quota but have no host byte buffers.
        copy.bytes = self.bytes.clone();
        copy.length = self.length;
        Ok(copy)
    }
    pub fn resize(&mut self, length: u64) {
        if length < self.length {
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
            self.bytes.split_off(&limit);
            if !length.is_multiple_of(PAGE_SIZE) {
                if let Some(page) = self.bytes.get_mut(&(length / PAGE_SIZE)) {
                    page[(length % PAGE_SIZE) as usize..].fill(0);
                }
            }
        }
        self.length = length;
    }
    pub fn read(&self, offset: u64, count: usize) -> Vec<u8> {
        let end = offset + count as u64;
        let within = (offset % PAGE_SIZE) as usize;
        if count <= PAGE_SIZE as usize - within {
            return self.bytes.get(&(offset / PAGE_SIZE)).map_or_else(
                || vec![0; count],
                |page| page[within..within + count].to_vec(),
            );
        }
        let mut out = vec![0; count];
        for (&index, page) in self
            .bytes
            .range(offset / PAGE_SIZE..end.div_ceil(PAGE_SIZE))
        {
            let base = index * PAGE_SIZE;
            let from = offset.max(base);
            let to = end.min(base + PAGE_SIZE);
            out[(from - offset) as usize..(to - offset) as usize]
                .copy_from_slice(&page[(from - base) as usize..(to - base) as usize]);
        }
        out
    }
    pub fn write(&mut self, offset: u64, bytes: &[u8]) -> Result<usize> {
        let mut written = 0;
        while written < bytes.len() {
            let at = offset + written as u64;
            let within = (at % PAGE_SIZE) as usize;
            let chunk = (bytes.len() - written).min(PAGE_SIZE as usize - within);
            let end = at + chunk as u64;
            let index = at / PAGE_SIZE;
            let page = if let Some(page) = self.bytes.get_mut(&index) {
                page
            } else {
                if let Err(error) = self.reserve(at, end) {
                    return if written == 0 {
                        Err(error)
                    } else {
                        Ok(written)
                    };
                }
                self.bytes
                    .entry(index)
                    .or_insert_with(|| Box::new([0; PAGE_SIZE as usize]))
            };
            page[within..within + chunk].copy_from_slice(&bytes[written..written + chunk]);
            self.length = self.length.max(end);
            written += chunk;
        }
        Ok(written)
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
        assert_eq!(copy.read(limit - 1, 1), b"x");
        assert_eq!(copy.read(0, 1), [0]);
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
