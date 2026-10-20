// SPDX-License-Identifier: GPL-3.0-or-later
//! Page-sized virtual backing objects, with no host pointers exposed to guests.
use super::*;
static BACKING_REVISION: AtomicU64 = AtomicU64::new(0);
/// Notify decoder caches and exclusive monitors about externally visible changes.
pub fn backing_changed() {
    BACKING_REVISION.fetch_add(1, Ordering::Relaxed);
}
pub(super) fn backing_revision() -> u64 {
    BACKING_REVISION.load(Ordering::Relaxed)
}
pub trait PageBacking {
    /// Check/read/write/version and scoped native-span methods never re-enter
    /// their containing Memory or invoke an arbitrary host callback. Allows one
    /// local VM borrow per interpreter slice or native call; external/custom
    /// backings conservatively opt out. Span methods may invoke only the supplied
    /// memory operation, which cannot yield to guest code while bytes are borrowed.
    fn cpu_borrow_safe(&self) -> bool {
        false
    }
    /// Stable backing-page identity for quiescent parallel snapshots. External
    /// shared backings must opt in; no thread ever receives this Rc object.
    fn parallel_key(&self) -> Option<(u64, u64)> {
        None
    }
    /// Share resident physical bytes with workers. The provider keeps metadata
    /// coordinator-local; every CPU/native byte access must use these guards.
    fn shared_page(&self) -> Option<std::sync::Arc<SharedPage>> {
        None
    }
    /// Publish dirty metadata after workers have joined, without copying bytes.
    /// Called only for a provider that returned shared_page().
    fn publish_write(&self, _offset: usize, _len: usize) -> Result<(), MemoryError> {
        Err(MemoryError::BackingIo(95))
    }
    fn check(&self, address: u64) -> Result<(), MemoryError>;
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError>;
    /// Resident operations cannot perform fallible backing I/O after complete
    /// permission/EOF preflight. External backings must explicitly opt in.
    fn native_resident(&self) -> bool {
        false
    }
    /// Invoke once on a coherent resident fragment, or return false without
    /// invoking. Implementations retain the backing borrow for the callback.
    /// Called only at a joined coordinator checkpoint; no Rc reaches workers.
    fn with_read(
        &self,
        _offset: usize,
        _len: usize,
        _f: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, MemoryError> {
        Ok(false)
    }
    /// As above, with write/version/dirty hooks before exposing mutable bytes.
    fn with_write(
        &self,
        _offset: usize,
        _len: usize,
        _f: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, MemoryError> {
        Ok(false)
    }
    fn sync(&self) -> Result<(), MemoryError>;
    fn sync_key(&self) -> Option<u64> {
        None
    }
    fn version(&self) -> u64;
    fn writable(&self) -> bool;
    /// Maximum mapping permission, sampled by mmap/mprotect, never CPU loads.
    fn executable(&self) -> bool {
        true
    }
    fn next_page(&self, pages: u64) -> Result<Rc<dyn PageBacking>, MemoryError>;
}
#[derive(Clone)]
pub(super) struct Backed {
    pub object: Rc<dyn PageBacking>,
    pub shared: bool,
    pub private_copy: bool,
}
impl Page {
    #[inline]
    pub(super) fn check_backing(&self, address: u64) -> Result<(), MemoryError> {
        if let Some(b) = &self.backing {
            b.object.check(address)?;
        }
        Ok(())
    }
    pub(crate) fn shared_storage(&self) -> Option<std::sync::Arc<SharedPage>> {
        if let Some(b) = &self.backing {
            if b.shared || !b.private_copy {
                return b.object.shared_page();
            }
        }
        self.bytes.shared().cloned()
    }
    // Fixed-size interpreter callers should compile resident copies to host
    // loads/stores. Live backing and COW checks still run on every access.
    #[inline]
    pub(super) fn read_bytes(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        if let Some(b) = &self.backing {
            if b.shared || !b.private_copy {
                return b.object.read(offset, out);
            }
        }
        self.bytes
            .with_read(offset, out.len(), |bytes| out.copy_from_slice(bytes));
        Ok(())
    }
    #[inline]
    pub(super) fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if let Some(b) = &mut self.backing {
            if b.shared {
                return b.object.write(offset, bytes);
            }
            if !b.private_copy {
                let mut page = [0; PAGE_SIZE as usize];
                b.object.read(0, &mut page)?;
                self.bytes = Rc::new(PageBytes::new(page));
                b.private_copy = true;
            }
        }
        Rc::make_mut(&mut self.bytes)
            .with_write(offset, bytes.len(), |out| out.copy_from_slice(bytes));
        Ok(())
    }
}
impl Memory {
    pub fn map_backed(
        &mut self,
        address: u64,
        objects: Vec<Rc<dyn PageBacking>>,
        shared_mapping: bool,
        permissions: Permissions,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().map_backed(
                address,
                objects,
                shared_mapping,
                permissions,
                fixed,
            );
        }
        let len = (objects.len() as u64)
            .checked_mul(PAGE_SIZE)
            .ok_or(MemoryError::Limit)?;
        Self::mapping_end(address, len)?;
        if shared_mapping && permissions.write && objects.iter().any(|b| !b.writable()) {
            return Err(MemoryError::Permission {
                address,
                access: Access::Write,
            });
        }
        let cpu_safe = objects.iter().all(|object| object.cpu_borrow_safe());
        self.check_backed_mapping(address, len, fixed)?;
        let charges: Vec<_> = objects
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let charge = if fixed {
                    self.pages
                        .get(&(address + i as u64 * PAGE_SIZE))
                        .and_then(|&frame| self.frames[frame].as_ref())
                        .filter(|page| page.charge.resident())
                        .map(|page| page.charge.clone())
                        .unwrap_or_else(|| Charge::new(&self.account))
                } else {
                    Charge::new(&self.account)
                };
                charge.ensure()?;
                Ok(charge)
            })
            .collect::<Result<_, MemoryError>>()?;
        if fixed {
            self.map_fixed(address, len, permissions)?;
        } else {
            self.map(address, len, permissions)?;
        }
        let zero = Rc::new(PageBytes::Zero);
        for (i, (object, charge)) in objects.into_iter().zip(charges).enumerate() {
            let frame = self.pages[&(address + i as u64 * PAGE_SIZE)];
            let page = self.frames[frame].as_mut().expect("mapped page");
            page.bytes = zero.clone();
            page.charge = charge;
            page.backing = Some(Backed {
                object,
                shared: shared_mapping,
                private_copy: false,
            });
        }
        self.refresh_mmu(address, len);
        self.invalidate_translations();
        self.has_backings = true;
        self.cpu_borrow_safe &= cpu_safe;
        Ok(())
    }
    pub fn sync_range(&self, address: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().sync_range(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        let mut synced = std::collections::BTreeSet::new();
        for (_, &frame) in self.pages.range(address..end) {
            if let Some(b) = &self.frames[frame].as_ref().expect("page").backing {
                if b.shared && b.object.sync_key().is_none_or(|key| synced.insert(key)) {
                    b.object.sync()?;
                }
            }
        }
        Ok(())
    }
    pub fn resident(&self, address: u64, len: u64) -> Result<Vec<u8>, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().resident(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        Ok((address..end)
            .step_by(PAGE_SIZE as usize)
            .map(|base| {
                self.pages.get(&base).map_or(0, |&frame| {
                    let page = self.frames[frame].as_ref().expect("page");
                    u8::from(page.charge.resident() && page.check_backing(base).is_ok())
                })
            })
            .collect())
    }
    pub fn discard(&mut self, address: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().discard(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        self.advance_code_revision();
        for (&base, &frame) in self.pages.range(address..end) {
            let page = self.frames[frame].as_mut().expect("page");
            if page.backing.as_ref().is_some_and(|b| b.shared) {
                continue;
            }
            if self.parallel_cache.is_some() {
                self.parallel_mappings.insert(base);
            }
            page.bytes = Rc::new(PageBytes::Zero);
            if page.backing.is_none() {
                page.charge = Charge::new(&self.account);
            }
            if let Some(b) = &mut page.backing {
                b.private_copy = false;
            }
            page.instruction_revision = self.code_revision;
        }
        self.refresh_mmu(address, len);
        self.invalidate_translations();
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
    /// Transactional page-table movement; page bytes/backing identity are retained.
    pub fn remap(
        &mut self,
        old: u64,
        old_len: u64,
        new: u64,
        new_len: u64,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().remap(old, old_len, new, new_len, fixed);
        }
        let old_end = Self::mapping_end(old, old_len)?;
        let new_end = Self::mapping_end(new, new_len)?;
        if fixed && old == new {
            return Err(MemoryError::InvalidRange);
        }
        if old != new && new < old_end && old < new_end {
            return Err(MemoryError::InvalidRange);
        }
        if self.is_reserved(old, old_len) {
            // Both splits and the final insertion must fit before either
            // source or destination changes. Conservative near the metadata cap.
            self.check_reservation_split(0, 0, 4)?;
            if old == new && new_len > old_len && !self.is_free(old_end, new_len - old_len) {
                return Err(MemoryError::Overlap(old_end));
            }
            if old != new && !fixed && !self.is_free(new, new_len) {
                return Err(MemoryError::Overlap(new));
            }
            self.unmap(old, old_len)?;
            return self.reserve(new, new_len, fixed);
        }
        self.invalidate_translations();
        self.mmu.retire();
        let mut pages = Vec::new();
        for base in (old..old_end).step_by(PAGE_SIZE as usize) {
            pages.push(
                self.frames[*self.pages.get(&base).ok_or(MemoryError::Unmapped(base))?]
                    .as_ref()
                    .expect("page")
                    .clone(),
            );
        }
        // Linux requires a single mapping; reject mixed protection/backing ranges.
        let permissions = pages[0].permissions;
        let first_backed = pages[0].backing.is_some();
        let mapping = pages[0].mapping;
        if pages.iter().any(|p| {
            p.mapping != mapping
                || p.permissions != permissions
                || p.backing.is_some() != first_backed
        }) {
            return Err(MemoryError::InvalidRange);
        }
        let replaced = if old == new {
            old_len
        } else if fixed {
            (self.pages.range(new..new_end).count() as u64) * PAGE_SIZE
        } else {
            0
        };
        if old != new && !fixed && !self.is_free(new, new_len) {
            return Err(MemoryError::Overlap(new));
        }
        if fixed && old != new {
            self.check_reservation_split(new, new_end, 0)?;
        }
        if (self.mapped_bytes() as u64)
            .saturating_sub(old_len + if old == new { 0 } else { replaced })
            .checked_add(new_len)
            .is_none_or(|n| n > self.limit as u64)
        {
            return Err(MemoryError::Limit);
        }
        if old == new && new_len > old_len && !self.is_free(old_end, new_len - old_len) {
            return Err(MemoryError::Overlap(old_end));
        }
        let count = (new_len / PAGE_SIZE) as usize;
        if count > pages.len() {
            let last = pages.last().expect("page").clone();
            let original_count = pages.len();
            for i in original_count..count {
                let mut page = last.clone();
                page.bytes = Rc::new(PageBytes::Zero);
                page.charge = Charge::new(&self.account);
                if let Some(b) = &mut page.backing {
                    page.charge.ensure()?;
                    b.object = last
                        .backing
                        .as_ref()
                        .expect("backed")
                        .object
                        .next_page((i + 1 - original_count) as u64)?;
                    b.private_copy = false;
                }
                pages.push(page);
            }
        }
        self.unmap(old, old_len)?;
        if fixed && old != new {
            self.unmap(new, new_len)?;
        }
        self.map_fixed(new, new_len, permissions)?;
        self.cpu_borrow_safe &= pages.iter().all(|p| {
            p.backing
                .as_ref()
                .is_none_or(|b| b.object.cpu_borrow_safe())
        });
        for (i, mut page) in pages.into_iter().take(count).enumerate() {
            page.instruction_revision = self.code_revision;
            let frame = self.pages[&(new + i as u64 * PAGE_SIZE)];
            self.frames[frame] = Some(page);
        }
        self.refresh_mmu(new, new_len);
        self.invalidate_translations();
        Ok(())
    }
}

struct AnonymousPage {
    bytes: std::sync::Arc<SharedPage>,
    revision: Cell<u64>,
    identity: u64,
}
impl AnonymousPage {
    fn allocate() -> Rc<dyn PageBacking> {
        Rc::new(Self {
            bytes: std::sync::Arc::new(SharedPage::new([0; PAGE_SIZE as usize])),
            revision: Cell::new(0),
            identity: new_backing_identity(),
        })
    }
}
impl PageBacking for AnonymousPage {
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.identity, 0))
    }
    fn shared_page(&self) -> Option<std::sync::Arc<SharedPage>> {
        Some(self.bytes.clone())
    }
    fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
        self.revision.set(self.revision.get().wrapping_add(1));
        backing_changed();
        Ok(())
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        self.bytes
            .with_read(offset, out.len(), |bytes| out.copy_from_slice(bytes));
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.bytes
            .with_write(offset, bytes.len(), |out| out.copy_from_slice(bytes));
        self.revision.set(self.revision.get().wrapping_add(1));
        backing_changed();
        Ok(())
    }
    fn with_read(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> Result<bool, MemoryError> {
        self.bytes.with_read(offset, len, f);
        Ok(true)
    }
    fn with_write(
        &self,
        offset: usize,
        len: usize,
        f: &mut dyn FnMut(&mut [u8]),
    ) -> Result<bool, MemoryError> {
        self.revision.set(self.revision.get().wrapping_add(1));
        backing_changed();
        self.bytes.with_write(offset, len, f);
        Ok(true)
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        self.revision
            .get()
            .wrapping_add(self.bytes.version.load(Ordering::Acquire))
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
        Ok(Self::allocate())
    }
}
impl Memory {
    pub fn map_shared_anonymous(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        Self::mapping_end(address, len)?;
        self.check_backed_mapping(address, len, fixed)?;
        let objects = (0..len / PAGE_SIZE)
            .map(|_| AnonymousPage::allocate())
            .collect();
        self.map_backed(address, objects, true, permissions, fixed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fork_shares_anonymous_bytes_but_not_protections_or_mapping_table() {
        let mut m = Memory::default();
        m.map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        let mut child = m.clone();
        child.write_array(0x1000, [7; 8]).unwrap();
        assert_eq!(m.read_array::<8>(0x1000).unwrap(), [7; 8]);
        child.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        m.write_array(0x1000, [8; 8]).unwrap();
        assert_eq!(child.read_array::<8>(0x1000).unwrap(), [8; 8]);
        child.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(m.read_array::<8>(0x1000).is_ok());
    }
    #[test]
    fn failed_remap_is_atomic_and_success_preserves_bytes_and_zero_grows() {
        let mut m = Memory::new(PAGE_SIZE as usize * 4);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        m.write_array(0x1000, [3; 8]).unwrap();
        assert!(m
            .remap(0x1000, PAGE_SIZE, 0x1000, PAGE_SIZE * 2, false)
            .is_err());
        assert_eq!(m.read_array::<8>(0x1000).unwrap(), [3; 8]);
        assert!(m
            .remap(0x1000, PAGE_SIZE, 0x8000, PAGE_SIZE * 5, false)
            .is_err());
        assert!(m.is_free(0x8000, PAGE_SIZE * 3));
        m.remap(0x1000, PAGE_SIZE, 0x8000, PAGE_SIZE * 3, false)
            .unwrap();
        assert!(m.is_free(0x1000, PAGE_SIZE));
        assert_eq!(m.read_array::<8>(0x8000).unwrap(), [3; 8]);
        assert_eq!(m.read_array::<8>(0xa000).unwrap(), [0; 8]);
    }
}
