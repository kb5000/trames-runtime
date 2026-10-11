// SPDX-License-Identifier: GPL-3.0-or-later
//! Sparse, bounded guest address spaces. Guest addresses are never host pointers.
use std::{cell::RefCell, collections::BTreeMap, fmt, rc::Rc, sync::Arc};

pub const PAGE_SIZE: u64 = 4096;
pub const ADDRESS_LIMIT: u64 = 1 << 48;
pub const DEFAULT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    fn allows(self, access: Access) -> bool {
        match access {
            Access::Read => self.read,
            Access::Write => self.write,
            Access::Execute => self.execute,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryError {
    InvalidRange,
    UnalignedMapping,
    Overlap(u64),
    Limit,
    Unmapped(u64),
    Permission { address: u64, access: Access },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "guest memory: {self:?}")
    }
}
impl std::error::Error for MemoryError {}

#[derive(Clone)]
struct Page {
    bytes: Arc<[u8; PAGE_SIZE as usize]>,
    permissions: Permissions,
}

pub struct Memory {
    pages: BTreeMap<u64, Page>,
    limit: usize,
    revision: u64,
    code_revision: u64,
    shared: Option<Rc<RefCell<Memory>>>,
}
impl Clone for Memory {
    fn clone(&self) -> Self {
        // fork always takes a COW snapshot, including when its parent has threads.
        if let Some(shared) = &self.shared {
            return shared.borrow().clone();
        }
        Self {
            pages: self.pages.clone(),
            limit: self.limit,
            revision: self.revision,
            code_revision: self.code_revision,
            shared: None,
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new(DEFAULT_MEMORY_LIMIT)
    }
}

impl Memory {
    /// CLONE_VM shares mappings, protections, bytes and the decoder revision.
    /// The inner address space remains private; no RefCell guard crosses an API call.
    pub fn share(&mut self) -> Self {
        if self.shared.is_none() {
            let owned = std::mem::replace(self, Self::new(self.limit));
            self.shared = Some(Rc::new(RefCell::new(owned)));
        }
        Self {
            pages: BTreeMap::new(),
            limit: self.limit,
            revision: 0,
            code_revision: 0,
            shared: self.shared.clone(),
        }
    }
    pub fn set_limit(&mut self, limit: usize) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().set_limit(limit);
        }
        if self.mapped_bytes() > limit {
            return Err(MemoryError::Limit);
        }
        self.limit = limit;
        Ok(())
    }
    pub fn new(limit: usize) -> Self {
        Self {
            pages: BTreeMap::new(),
            limit,
            revision: 0,
            code_revision: 0,
            shared: None,
        }
    }
    pub fn mapped_bytes(&self) -> usize {
        if let Some(shared) = &self.shared {
            return shared.borrow().mapped_bytes();
        }
        self.pages.len() * PAGE_SIZE as usize
    }

    /// Contiguous guest mappings for procfs; no native address is exposed.
    pub fn regions(&self) -> Vec<(u64, u64, Permissions)> {
        if let Some(shared) = &self.shared {
            return shared.borrow().regions();
        }
        let mut regions: Vec<(u64, u64, Permissions)> = Vec::new();
        for (&address, page) in &self.pages {
            if let Some(last) = regions.last_mut() {
                if last.1 == address && last.2 == page.permissions {
                    last.1 += PAGE_SIZE;
                    continue;
                }
            }
            regions.push((address, address + PAGE_SIZE, page.permissions));
        }
        regions
    }

    pub fn highest_mapped_end(&self) -> u64 {
        if let Some(shared) = &self.shared {
            return shared.borrow().highest_mapped_end();
        }
        self.pages
            .last_key_value()
            .map_or(0, |(&address, _)| address + PAGE_SIZE)
    }
    pub fn revision(&self) -> u64 {
        if let Some(shared) = &self.shared {
            return shared.borrow().revision();
        }
        self.revision
    }
    /// Decode-cache epoch: data stores preserve checked executable blocks.
    /// Mapping/protection changes and writes into executable pages invalidate.
    pub fn instruction_revision(&self) -> u64 {
        if let Some(shared) = &self.shared {
            return shared.borrow().instruction_revision();
        }
        self.code_revision
    }

    pub fn is_free(&self, address: u64, len: u64) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow().is_free(address, len);
        }
        Self::mapping_end(address, len)
            .is_ok_and(|end| self.pages.range(address..end).next().is_none())
    }
    pub fn find_free(&self, start: u64, len: u64) -> Option<u64> {
        if let Some(shared) = &self.shared {
            return shared.borrow().find_free(start, len);
        }
        let mut candidate = start.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
        Self::mapping_end(candidate, len).ok()?;
        for (&base, _) in self.pages.range(candidate..) {
            if base >= candidate.checked_add(len)? {
                return Some(candidate);
            }
            if base >= candidate {
                candidate = base + PAGE_SIZE;
            }
        }
        Self::mapping_end(candidate, len).ok().map(|_| candidate)
    }
    /// Atomic anonymous MAP_FIXED: account for replaced pages before changing data.
    pub fn map_fixed(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().map_fixed(address, len, permissions);
        }
        let end = Self::mapping_end(address, len)?;
        let replaced = self.pages.range(address..end).count() * PAGE_SIZE as usize;
        let size = usize::try_from(len).map_err(|_| MemoryError::Limit)?;
        if self
            .mapped_bytes()
            .saturating_sub(replaced)
            .checked_add(size)
            .is_none_or(|n| n > self.limit)
        {
            return Err(MemoryError::Limit);
        }
        for base in (address..end).step_by(PAGE_SIZE as usize) {
            self.pages.insert(
                base,
                Page {
                    bytes: Arc::new([0; PAGE_SIZE as usize]),
                    permissions,
                },
            );
        }
        self.revision = self.revision.wrapping_add(1);
        self.code_revision = self.code_revision.wrapping_add(1);
        Ok(())
    }

    /// Linux munmap permits holes; validate the range before removing mapped pages.
    pub fn unmap(&mut self, address: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().unmap(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        let keys: Vec<_> = self
            .pages
            .range(address..end)
            .map(|(&base, _)| base)
            .collect();
        for base in keys {
            self.pages.remove(&base);
        }
        self.revision = self.revision.wrapping_add(1);
        self.code_revision = self.code_revision.wrapping_add(1);
        Ok(())
    }

    /// Read a bounded NUL-terminated byte string, without UTF-8 assumptions.
    pub fn read_c_string(&self, address: u64, limit: usize) -> Result<Vec<u8>, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().read_c_string(address, limit);
        }
        let mut bytes = Vec::new();
        for index in 0..limit {
            let current = address
                .checked_add(index as u64)
                .ok_or(MemoryError::InvalidRange)?;
            let mut byte = [0];
            self.read(current, &mut byte)?;
            if byte[0] == 0 {
                return Ok(bytes);
            }
            bytes.push(byte[0]);
        }
        Err(MemoryError::Limit)
    }

    fn end(address: u64, len: u64) -> Result<u64, MemoryError> {
        let end = address.checked_add(len).ok_or(MemoryError::InvalidRange)?;
        if address >= ADDRESS_LIMIT || end > ADDRESS_LIMIT {
            return Err(MemoryError::InvalidRange);
        }
        Ok(end)
    }

    fn mapping_end(address: u64, len: u64) -> Result<u64, MemoryError> {
        if len == 0 || !address.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE) {
            return Err(MemoryError::UnalignedMapping);
        }
        Self::end(address, len)
    }

    /// Validate the entire operation before changing any page.
    pub fn map(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().map(address, len, permissions);
        }
        let end = Self::mapping_end(address, len)?;
        let len = usize::try_from(len).map_err(|_| MemoryError::Limit)?;
        if self
            .mapped_bytes()
            .checked_add(len)
            .ok_or(MemoryError::Limit)?
            > self.limit
        {
            return Err(MemoryError::Limit);
        }
        if let Some((&base, _)) = self.pages.range(address..end).next() {
            return Err(MemoryError::Overlap(base));
        }
        for base in (address..end).step_by(PAGE_SIZE as usize) {
            self.pages.insert(
                base,
                Page {
                    bytes: Arc::new([0; PAGE_SIZE as usize]),
                    permissions,
                },
            );
        }
        self.revision = self.revision.wrapping_add(1);
        self.code_revision = self.code_revision.wrapping_add(1);
        Ok(())
    }

    pub fn protect(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().protect(address, len, permissions);
        }
        let end = Self::mapping_end(address, len)?;
        for base in (address..end).step_by(PAGE_SIZE as usize) {
            if !self.pages.contains_key(&base) {
                return Err(MemoryError::Unmapped(base));
            }
        }
        for base in (address..end).step_by(PAGE_SIZE as usize) {
            self.pages
                .get_mut(&base)
                .expect("validated page")
                .permissions = permissions;
        }
        self.revision = self.revision.wrapping_add(1);
        self.code_revision = self.code_revision.wrapping_add(1);
        Ok(())
    }

    pub fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().check(address, len, access);
        }
        if len == 0 {
            return Ok(());
        }
        let end = Self::end(address, len as u64)?;
        let first = address & !(PAGE_SIZE - 1);
        for base in (first..end).step_by(PAGE_SIZE as usize) {
            let fault_address = base.max(address);
            let page = self
                .pages
                .get(&base)
                .ok_or(MemoryError::Unmapped(fault_address))?;
            if !page.permissions.allows(access) {
                return Err(MemoryError::Permission {
                    address: fault_address,
                    access,
                });
            }
        }
        Ok(())
    }

    fn copy_read(&self, mut address: u64, mut out: &mut [u8]) {
        while !out.is_empty() {
            let base = address & !(PAGE_SIZE - 1);
            let offset = (address - base) as usize;
            let len = out.len().min(PAGE_SIZE as usize - offset);
            out[..len].copy_from_slice(&self.pages[&base].bytes[offset..offset + len]);
            address += len as u64;
            out = &mut out[len..];
        }
    }

    pub fn read(&self, address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().read(address, out);
        }
        self.check(address, out.len(), Access::Read)?;
        self.copy_read(address, out);
        Ok(())
    }

    pub fn write(&mut self, mut address: u64, mut input: &[u8]) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().write(address, input);
        }
        self.check(address, input.len(), Access::Write)?;
        if !input.is_empty() {
            self.revision = self.revision.wrapping_add(1);
        }
        let mut executable = false;
        while !input.is_empty() {
            let base = address & !(PAGE_SIZE - 1);
            let offset = (address - base) as usize;
            let len = input.len().min(PAGE_SIZE as usize - offset);
            let page = self.pages.get_mut(&base).expect("validated page");
            executable |= page.permissions.execute;
            Arc::make_mut(&mut page.bytes)[offset..offset + len].copy_from_slice(&input[..len]);
            address += len as u64;
            input = &input[len..];
        }
        if executable {
            self.code_revision = self.code_revision.wrapping_add(1);
        }
        Ok(())
    }

    pub fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().fetch_u32(address);
        }
        if !address.is_multiple_of(4) {
            return Err(MemoryError::InvalidRange);
        }
        self.check(address, 4, Access::Execute)?;
        let mut bytes = [0; 4];
        self.copy_read(address, &mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&self, address: u64) -> Result<u64, MemoryError> {
        let mut bytes = [0; 8];
        self.read(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cross_page_write_is_atomic_on_fault() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1fff, &[7]).unwrap();
        assert!(matches!(
            m.write(0x1fff, &[1, 2]),
            Err(MemoryError::Unmapped(0x2000))
        ));
        let mut byte = [0];
        m.read(0x1fff, &mut byte).unwrap();
        assert_eq!(byte, [7]);
    }
    #[test]
    fn permissions_are_separate_and_protection_is_atomic() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert!(m.fetch_u32(0x1000).is_err());
        assert!(m.protect(0x1000, PAGE_SIZE * 2, Permissions::RX).is_err());
        m.write(0x1000, &[0; 4]).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert_eq!(m.fetch_u32(0x1000).unwrap(), 0);
        assert!(m.write(0x1000, &[0]).is_err());
    }
    #[test]
    fn overflow_overlap_and_limit_are_rejected() {
        let mut m = Memory::new(PAGE_SIZE as usize * 2);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert!(matches!(
            m.map(0x1000, PAGE_SIZE, Permissions::RW),
            Err(MemoryError::Overlap(_))
        ));
        assert_eq!(
            m.map(0x2000, PAGE_SIZE * 2, Permissions::RW),
            Err(MemoryError::Limit)
        );
        assert_eq!(m.mapped_bytes(), PAGE_SIZE as usize);
        assert!(m.check(u64::MAX, 2, Access::Read).is_err());
        assert!(m.check(ADDRESS_LIMIT - 1, 2, Access::Read).is_err());
        assert!(m.check(u64::MAX, 0, Access::Read).is_ok());
    }
    #[test]
    fn mapped_pages_are_zeroed_and_reads_cross_boundaries() {
        let mut m = Memory::default();
        m.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.read_u64(0x1ffc).unwrap(), 0);
        m.write(0x1ffc, &42u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_u64(0x1ffc).unwrap(), 42);
    }

    #[test]
    fn unmap_holes_and_remapping_zeroes_old_data() {
        let mut m = Memory::new(8192);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, b"old").unwrap();
        assert!(!m.is_free(0x1000, PAGE_SIZE));
        assert!(m.unmap(0x1001, PAGE_SIZE).is_err());
        assert_eq!(m.mapped_bytes(), 4096);
        m.unmap(0x1000, PAGE_SIZE * 2).unwrap();
        assert!(m.is_free(0x1000, PAGE_SIZE));
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.read_u64(0x1000).unwrap(), 0);
    }

    #[test]
    fn c_strings_obey_bounds_and_accept_non_utf8() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1ffe, &[0xff, 0]).unwrap();
        assert_eq!(m.read_c_string(0x1ffe, 2).unwrap(), [0xff]);
        assert_eq!(m.read_c_string(0x1ffe, 1), Err(MemoryError::Limit));
        m.write(0x1fff, &[1]).unwrap();
        assert!(m.read_c_string(0x1ffe, 4).is_err());
    }

    #[test]
    fn fixed_mapping_failure_preserves_existing_bytes() {
        let mut m = Memory::new(4096);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, b"data").unwrap();
        assert_eq!(
            m.map_fixed(0x1000, PAGE_SIZE * 2, Permissions::R),
            Err(MemoryError::Limit)
        );
        let mut bytes = [0; 4];
        m.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"data");
        m.map_fixed(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert_eq!(m.read_u64(0x1000).unwrap(), 0);
        assert!(m.write(0x1000, b"x").is_err());
    }

    #[test]
    fn free_range_search_skips_only_conflicting_pages() {
        let mut m = Memory::default();
        m.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x5000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.find_free(0x1000, PAGE_SIZE), Some(0x1000));
        assert_eq!(m.find_free(0x1000, PAGE_SIZE * 2), Some(0x3000));
        assert_eq!(m.find_free(ADDRESS_LIMIT - PAGE_SIZE, PAGE_SIZE * 2), None);
    }
}

#[cfg(test)]
mod fork_tests {
    use super::*;
    #[test]
    fn instruction_revision_tracks_shared_code_but_not_data_writes() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .protect(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        let mut thread = memory.share();
        let code = memory.instruction_revision();
        let all = memory.revision();
        thread.write(0x2000, b"data").unwrap();
        assert_eq!(memory.instruction_revision(), code);
        assert!(memory.revision() > all);
        thread.write(0x1000, &0xd503201fu32.to_le_bytes()).unwrap();
        assert!(memory.instruction_revision() > code);
        let code = memory.instruction_revision();
        assert!(thread
            .protect(0x2000, PAGE_SIZE * 2, Permissions::RX)
            .is_err());
        assert_eq!(memory.instruction_revision(), code);
        thread.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(memory.instruction_revision() > code);
    }
    #[test]
    fn shared_vm_updates_mappings_bytes_and_revision_but_fork_is_private() {
        let mut parent = Memory::default();
        parent.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut thread = parent.share();
        let revision = parent.revision();
        thread.write(0x1000, b"thread").unwrap();
        assert!(parent.revision() > revision);
        let mut bytes = [0; 6];
        parent.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"thread");
        let mut fork = thread.clone();
        fork.write(0x1000, b"forked").unwrap();
        parent.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"thread");
        thread.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(parent.write(0x1000, b"x").is_err());
        assert!(fork.write(0x1000, b"x").is_ok());
        parent.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(thread.mapped_bytes(), PAGE_SIZE as usize * 2);
        thread.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(parent.read(0x1000, &mut bytes).is_err());
        assert!(fork.read(0x1000, &mut bytes).is_ok());
    }
    #[test]
    fn fork_copies_pages_on_write_and_keeps_protection_independent() {
        let mut parent = Memory::default();
        parent.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        parent.write(0x1fff, b"ab").unwrap();
        let mut child = parent.clone();
        child.write(0x1fff, b"XY").unwrap();
        let mut bytes = [0; 2];
        parent.read(0x1fff, &mut bytes).unwrap();
        assert_eq!(&bytes, b"ab");
        child.read(0x1fff, &mut bytes).unwrap();
        assert_eq!(&bytes, b"XY");
        child.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(parent.write(0x1000, b"z").is_ok());
        assert!(child.write(0x1000, b"z").is_err());
        child.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(parent.read(0x1000, &mut bytes).is_ok());
    }
}
