// SPDX-License-Identifier: GPL-3.0-or-later
//! Sparse, bounded guest address spaces. Guest addresses are never host pointers.
use std::{collections::BTreeMap, fmt};

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

struct Page {
    bytes: Box<[u8; PAGE_SIZE as usize]>,
    permissions: Permissions,
}

pub struct Memory {
    pages: BTreeMap<u64, Page>,
    limit: usize,
}

impl Default for Memory {
    fn default() -> Self {
        Self::new(DEFAULT_MEMORY_LIMIT)
    }
}

impl Memory {
    pub fn new(limit: usize) -> Self {
        Self {
            pages: BTreeMap::new(),
            limit,
        }
    }
    pub fn mapped_bytes(&self) -> usize {
        self.pages.len() * PAGE_SIZE as usize
    }

    fn end(address: u64, len: u64) -> Result<u64, MemoryError> {
        let end = address.checked_add(len).ok_or(MemoryError::InvalidRange)?;
        if address >= ADDRESS_LIMIT || end > ADDRESS_LIMIT {
            return Err(MemoryError::InvalidRange);
        }
        Ok(end)
    }

    fn mapping_end(address: u64, len: u64) -> Result<u64, MemoryError> {
        if len == 0 || address % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
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
                    bytes: Box::new([0; PAGE_SIZE as usize]),
                    permissions,
                },
            );
        }
        Ok(())
    }

    pub fn protect(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
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
        Ok(())
    }

    pub fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
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
        self.check(address, out.len(), Access::Read)?;
        self.copy_read(address, out);
        Ok(())
    }

    pub fn write(&mut self, mut address: u64, mut input: &[u8]) -> Result<(), MemoryError> {
        self.check(address, input.len(), Access::Write)?;
        while !input.is_empty() {
            let base = address & !(PAGE_SIZE - 1);
            let offset = (address - base) as usize;
            let len = input.len().min(PAGE_SIZE as usize - offset);
            self.pages.get_mut(&base).expect("validated page").bytes[offset..offset + len]
                .copy_from_slice(&input[..len]);
            address += len as u64;
            input = &input[len..];
        }
        Ok(())
    }

    pub fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        if address % 4 != 0 {
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
}
