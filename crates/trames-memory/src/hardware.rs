// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold hardware-MMU binding. Virtual mappings, quotas and backing semantics
//! stay in Memory; an executor only retains physical storage for its mappings.
use super::*;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwarePageInfo {
    pub permissions: Permissions,
    pub storage_id: u64,
    pub backing_version: u64,
    pub instruction_revision: (u64, u64),
    pub exclusive: bool,
    /// First writes must enter the existing resident/COW admission boundary.
    pub writable: bool,
}
impl Memory {
    pub fn hardware_page_info(&self, base: u64) -> Result<HardwarePageInfo, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().hardware_page_info(base);
        }
        if !base.is_multiple_of(PAGE_SIZE) {
            return Err(MemoryError::InvalidRange);
        }
        let frame = self.frame(base).ok_or(MemoryError::Unmapped(base))?;
        let page = self.frames[frame].as_ref().unwrap();
        page.check_backing(base)?;
        // Shared providers need a common physical export, not a private shadow
        // that silently diverges from file I/O or another VM. Pins remain actors.
        if page.backing.as_ref().is_some_and(|b| b.shared) || self.page_pinned(page) {
            return Err(MemoryError::BackingIo(95));
        }
        Ok(HardwarePageInfo {
            permissions: page.permissions,
            instruction_revision: (page.instruction_revision, 0),
            storage_id: page.bytes.shared().map_or(0, |b| b.identity),
            backing_version: page
                .backing
                .as_ref()
                .filter(|b| !b.private_copy)
                .map_or(0, |b| b.object.version()),
            exclusive: Rc::strong_count(&page.bytes) == 1,
            writable: page.permissions.write
                && page.charge.resident()
                && Rc::strong_count(&page.bytes) == 1
                && page.backing.as_ref().is_none_or(|b| b.private_copy),
        })
    }
    /// Bind a hardware-aligned host allocation to the original guest page.
    /// This is first population/COW, not a second persistent guest RAM copy.
    ///
    /// # Safety
    /// The executor must own all execution of this address space and exclude
    /// external byte actors until it stops. No Rust byte slice may span hardware
    /// execution. Stop/unmap hardware aliases before changing or releasing their
    /// storage; publish hardware writes through finish_hardware_write afterward.
    /// Existing shared Views and pinned buffers are rejected before effects.
    /// `initially_zero` promises untouched zero-filled physical storage; it
    /// avoids copying an anonymous demand-zero page before its first access.
    pub unsafe fn bind_hardware_page(
        &mut self,
        base: u64,
        storage: Arc<SharedPage>,
        write: bool,
        initially_zero: bool,
    ) -> Result<HardwarePageInfo, MemoryError> {
        if let Some(shared) = &self.shared {
            // SAFETY: same original VM ownership contract, with one local borrow.
            return unsafe {
                shared
                    .borrow_mut()
                    .bind_hardware_page(base, storage, write, initially_zero)
            };
        }
        self.hardware_page_info(base)?;
        if !self.parallel_views_quiescent() {
            return Err(MemoryError::InvalidRange);
        }
        let frame = self.frame(base).unwrap();
        let page = self.frames[frame].as_mut().unwrap();
        if write {
            if !page.permissions.write {
                return Err(MemoryError::Permission {
                    address: base,
                    access: Access::Write,
                });
            }
            page.charge.ensure()?;
        }
        let same = page
            .bytes
            .shared()
            .is_some_and(|bytes| Arc::ptr_eq(bytes, &storage));
        if write && same && Rc::strong_count(&page.bytes) != 1 {
            return Err(MemoryError::InvalidRange);
        }
        if (!same || page.backing.as_ref().is_some_and(|b| !b.private_copy))
            && !(initially_zero && page.backing.is_none() && page.bytes.is_zero())
        {
            let mut bytes = [0; PAGE_SIZE as usize];
            page.read_bytes(0, &mut bytes)?;
            storage.with_write(0, bytes.len(), |out| out.copy_from_slice(&bytes));
        }
        if write {
            if let Some(backing) = &mut page.backing {
                backing.private_copy = true;
            }
        }
        page.bytes = Rc::new(PageBytes::Concurrent(storage));
        self.parallel_cache = None;
        self.mmu.retire();
        self.revision = self.revision.wrapping_add(1);
        self.invalidate_translations();
        self.hardware_page_info(base)
    }
    /// Publish a stopped hardware CPU's possibly-written page conservatively.
    ///
    /// # Safety
    /// All hardware stores have stopped and no concurrent byte accessor exists.
    /// `base` must identify a page bound under bind_hardware_page's contract.
    pub unsafe fn finish_hardware_write(&mut self, base: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            // SAFETY: same stopped original VM.
            return unsafe { shared.borrow_mut().finish_hardware_write(base) };
        }
        let frame = self.frame(base).ok_or(MemoryError::Unmapped(base))?;
        let page = self.frames[frame].as_mut().unwrap();
        let bytes = page.bytes.shared().ok_or(MemoryError::InvalidRange)?;
        bytes.with_write(0, PAGE_SIZE as usize, |_| {});
        page.data_revision = page.data_revision.wrapping_add(1);
        if page.permissions.execute {
            self.advance_code_revision();
            self.frames[frame].as_mut().unwrap().instruction_revision = self.code_revision;
        }
        Ok(())
    }
}
