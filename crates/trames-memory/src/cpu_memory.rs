// SPDX-License-Identifier: GPL-3.0-or-later
//! The interpreter's checked memory contract. Both views use the same CPU engine.
use crate::{Access, DirectHint, Memory, MemoryError};
use std::sync::atomic::Ordering;

pub enum CpuSlice<'a, M> {
    Direct(&'a mut M),
    Shared(std::cell::RefMut<'a, M>),
}
impl<M> std::ops::Deref for CpuSlice<'_, M> {
    type Target = M;
    fn deref(&self) -> &M {
        match self {
            Self::Direct(m) => m,
            Self::Shared(m) => m,
        }
    }
}
impl<M> std::ops::DerefMut for CpuSlice<'_, M> {
    fn deref_mut(&mut self) -> &mut M {
        match self {
            Self::Direct(m) => m,
            Self::Shared(m) => m,
        }
    }
}

pub trait CpuMemory {
    /// A slice-scoped local borrow; no guard survives its owned CPU outcome.
    #[inline]
    fn cpu_slice(&mut self) -> CpuSlice<'_, Self>
    where
        Self: Sized,
    {
        CpuSlice::Direct(self)
    }
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError>;
    fn check_translation(&self, address: u64) -> Result<(), MemoryError>;
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError>;
    fn instruction_identity(&self) -> (u64, u64, u64);
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError>;
    fn read_array<const N: usize>(&self, address: u64) -> Result<[u8; N], MemoryError> {
        let mut bytes = [0; N];
        self.read(address, &mut bytes)?;
        Ok(bytes)
    }
    fn write_array<const N: usize>(
        &mut self,
        address: u64,
        bytes: [u8; N],
    ) -> Result<(), MemoryError> {
        self.write(address, &bytes)
    }
    /// Opaque generation-checked hint, valid only as an acceleration suggestion.
    /// Mapping mutation, cross-memory reuse, and stale hints remain safe.
    #[inline]
    fn direct_hint(&self) -> DirectHint {
        DirectHint::EMPTY
    }
    #[inline(always)]
    fn read_array_hint<const N: usize>(
        &self,
        address: u64,
        _hint: &mut DirectHint,
    ) -> Result<[u8; N], MemoryError> {
        self.read_array(address)
    }
    #[inline(always)]
    fn write_array_hint<const N: usize>(
        &mut self,
        address: u64,
        bytes: [u8; N],
        _hint: &mut DirectHint,
    ) -> Result<(), MemoryError> {
        self.write_array(address, bytes)
    }
    fn read_u64(&self, address: u64) -> Result<u64, MemoryError> {
        Ok(u64::from_le_bytes(self.read_array(address)?))
    }
    /// A single-copy read/modify/write, including 128-bit paired atomics.
    /// The callback reports whether a write actually happened (CAS may fail).
    fn atomic_update<T>(
        &mut self,
        address: u64,
        len: usize,
        update: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError>;
    fn exclusive_read(&self, address: u64, out: &mut [u8]) -> Result<u128, MemoryError>;
    fn exclusive_write(
        &mut self,
        address: u64,
        bytes: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError>;
    /// The local coordinator is quiescent; parallel views implement host fences.
    fn fence(&self, _order: Ordering) {}
}

impl CpuMemory for Memory {
    #[inline]
    fn cpu_slice(&mut self) -> CpuSlice<'_, Self> {
        if self
            .shared
            .as_ref()
            .is_some_and(|m| m.borrow().cpu_borrow_safe)
        {
            CpuSlice::Shared(self.shared.as_ref().expect("shared space").borrow_mut())
        } else {
            CpuSlice::Direct(self)
        }
    }
    #[inline]
    fn read(&self, a: u64, b: &mut [u8]) -> Result<(), MemoryError> {
        Memory::read(self, a, b)
    }
    #[inline]
    fn write(&mut self, a: u64, b: &[u8]) -> Result<(), MemoryError> {
        Memory::write(self, a, b)
    }
    #[inline]
    fn check(&self, a: u64, n: usize, x: Access) -> Result<(), MemoryError> {
        Memory::check(self, a, n, x)
    }
    #[inline]
    fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
        Memory::check_translation(self, a)
    }
    #[inline]
    fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
        Memory::fetch_u32(self, a)
    }
    #[inline]
    fn instruction_identity(&self) -> (u64, u64, u64) {
        Memory::instruction_identity(self)
    }
    #[inline]
    fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
        Memory::instruction_page_identity(self, a)
    }
    #[inline]
    fn read_array<const N: usize>(&self, a: u64) -> Result<[u8; N], MemoryError> {
        Memory::read_array(self, a)
    }
    #[inline]
    fn write_array<const N: usize>(&mut self, a: u64, b: [u8; N]) -> Result<(), MemoryError> {
        Memory::write_array(self, a, b)
    }
    #[inline]
    fn direct_hint(&self) -> DirectHint {
        if self.shared.is_none() {
            self.mmu.hint()
        } else {
            DirectHint::EMPTY
        }
    }
    #[inline(always)]
    fn read_array_hint<const N: usize>(
        &self,
        address: u64,
        hint: &mut DirectHint,
    ) -> Result<[u8; N], MemoryError> {
        if self.shared.is_none() {
            if let Some(bytes) = self.mmu.read_hint(address & 0x00ffffffffffffff, hint) {
                return Ok(bytes);
            }
        }
        let result = if self.shared.is_none() {
            self.read_array_soft(address & 0x00ffffffffffffff)
        } else {
            self.read_array(address)
        };
        *hint = self.direct_hint();
        result
    }
    #[inline(always)]
    fn write_array_hint<const N: usize>(
        &mut self,
        address: u64,
        bytes: [u8; N],
        hint: &mut DirectHint,
    ) -> Result<(), MemoryError> {
        if self.shared.is_none() {
            if let Some(frame) = self
                .mmu
                .write_hint(address & 0x00ffffffffffffff, bytes, hint)
            {
                self.revision = self.revision.wrapping_add(1);
                self.note_parallel_write(frame);
                return Ok(());
            }
        }
        let result = if self.shared.is_none() {
            self.write_array_soft(address & 0x00ffffffffffffff, bytes)
        } else {
            self.write_array(address, bytes)
        };
        *hint = self.direct_hint();
        result
    }
    fn atomic_update<T>(
        &mut self,
        a: u64,
        n: usize,
        f: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        self.check(a, n, Access::Write)?;
        let mut bytes = [0; 16];
        if n > bytes.len() {
            return Err(MemoryError::InvalidRange);
        }
        self.read(a, &mut bytes[..n])?;
        let (result, write) = f(&mut bytes[..n]);
        if write {
            self.write(a, &bytes[..n])?;
        }
        Ok(result)
    }
    fn exclusive_read(&self, a: u64, b: &mut [u8]) -> Result<u128, MemoryError> {
        self.read(a, b)?;
        Ok(self.revision() as u128)
    }
    fn exclusive_write(
        &mut self,
        a: u64,
        b: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        if token != Some(self.revision() as u128) {
            return Ok(false);
        }
        self.write(a, b)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PageBacking, Permissions, PAGE_SIZE};
    use std::{
        cell::RefCell,
        rc::{Rc, Weak},
    };

    #[test]
    fn trusted_backings_borrow_once_and_unknown_read_callbacks_can_reenter() {
        let mut memory = Memory::default();
        memory
            .map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        let mut peer = memory.share();
        {
            let mut slice = peer.cpu_slice();
            assert!(matches!(slice, CpuSlice::Shared(_)));
            slice.write(0x1000, &[7; 8]).unwrap();
            assert_eq!(slice.read_array::<8>(0x1000).unwrap(), [7; 8]);
        }
        // Slice scope is finished before any coordinator or native callback.
        memory.write(0x1000, &[8; 8]).unwrap();

        struct Reentrant {
            owner: Weak<RefCell<Memory>>,
        }
        impl PageBacking for Reentrant {
            fn check(&self, _: u64) -> Result<(), MemoryError> {
                assert!(
                    self.owner.upgrade().unwrap().borrow().mapped_bytes() >= PAGE_SIZE as usize
                );
                Ok(())
            }
            fn read(&self, _: usize, out: &mut [u8]) -> Result<(), MemoryError> {
                assert!(
                    self.owner.upgrade().unwrap().borrow().mapped_bytes() >= PAGE_SIZE as usize
                );
                out.fill(9);
                Ok(())
            }
            fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
                Err(MemoryError::BackingIo(13))
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn version(&self) -> u64 {
                0
            }
            fn writable(&self) -> bool {
                false
            }
            fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
                Err(MemoryError::InvalidRange)
            }
        }
        let object = Rc::new(Reentrant {
            owner: Rc::downgrade(memory.shared.as_ref().unwrap()),
        });
        memory
            .map_backed(0x3000, vec![object], false, Permissions::R, false)
            .unwrap();
        let slice = peer.cpu_slice();
        assert!(matches!(slice, CpuSlice::Direct(_)));
        assert_eq!(slice.read_array::<8>(0x3000).unwrap(), [9; 8]);
    }
}
