// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded shared page pins. Retain physical byte owners and residency charges,
//! never guest virtual addresses or a whole Memory handle. No ordinary load/store
//! gains a pin lookup or lock. Private pinned pages are copied on the child's
//! side of fork, keeping the parent's registered bytes stable.
use super::*;
use std::sync::Arc;

pub(crate) struct PinnedPage {
    bytes: Arc<SharedPage>,
    _charge: Arc<Charge>,
}
#[derive(Clone)]
pub struct PinnedBuffer {
    address: u64,
    length: usize,
    parts: Vec<(Arc<PinnedPage>, usize, usize)>,
}
impl PinnedBuffer {
    pub fn range(&self, address: u64, length: usize) -> Result<usize, MemoryError> {
        let address = address & 0x00ffffffffffffff;
        let offset = address
            .checked_sub(self.address)
            .ok_or(MemoryError::InvalidRange)?;
        if offset > self.length as u64 || length > self.length - offset as usize {
            return Err(MemoryError::InvalidRange);
        }
        Ok(offset as usize)
    }
    pub fn read(&self, offset: usize, length: usize) -> Result<Vec<u8>, MemoryError> {
        if offset > self.length || length > self.length - offset {
            return Err(MemoryError::InvalidRange);
        }
        let mut out = vec![0; length];
        self.read_into(offset, &mut out)?;
        Ok(out)
    }
    /// Reuse a worker's bounded transfer buffer without a second allocation.
    pub fn read_into(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        let length = out.len();
        if offset > self.length || length > self.length - offset {
            return Err(MemoryError::InvalidRange);
        }
        self.visit(offset, length, |page, at, cursor, len| {
            page.bytes
                .with_read(at, len, |b| out[cursor..cursor + len].copy_from_slice(b))
        });
        Ok(())
    }
    /// Stack-sized metadata read from retained pages, without allocating a Vec.
    pub fn read_array<const N: usize>(&self, offset: usize) -> Result<[u8; N], MemoryError> {
        if offset > self.length || N > self.length - offset {
            return Err(MemoryError::InvalidRange);
        }
        let mut out = [0; N];
        self.visit(offset, N, |page, at, cursor, len| {
            page.bytes
                .with_read(at, len, |b| out[cursor..cursor + len].copy_from_slice(b));
        });
        Ok(out)
    }
    pub fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if offset > self.length || bytes.len() > self.length - offset {
            return Err(MemoryError::InvalidRange);
        }
        self.visit(offset, bytes.len(), |page, at, cursor, len| {
            page.bytes
                .with_write(at, len, |b| b.copy_from_slice(&bytes[cursor..cursor + len]))
        });
        // Pins can outlive unmap/mprotect and can be used through another VM's
        // ring FD. The byte revision invalidates page tokens; the backing epoch
        // also invalidates the original VM's whole-image decoder fast cache.
        if !bytes.is_empty() {
            backing_changed();
        }
        Ok(())
    }
    fn visit(
        &self,
        mut offset: usize,
        mut length: usize,
        mut f: impl FnMut(&PinnedPage, usize, usize, usize),
    ) {
        let mut cursor = 0;
        for (page, at, len) in &self.parts {
            if offset >= *len {
                offset -= *len;
                continue;
            }
            let count = length.min(*len - offset);
            if count != 0 {
                f(page, at + offset, cursor, count);
            }
            cursor += count;
            length -= count;
            offset = 0;
            if length == 0 {
                break;
            }
        }
    }
}
impl Memory {
    /// Linux fixed I/O buffers need writable pages even for WRITE_FIXED.
    /// Anonymous private heap/stack pages are supported first. Live file/shared
    /// backings need provider-specific pin/truncate semantics and return ENOTSUP.
    pub fn pin_rw(&mut self, address: u64, length: usize) -> Result<PinnedBuffer, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().pin_rw(address, length);
        }
        if length == 0 {
            return Err(MemoryError::InvalidRange);
        }
        let address = address & 0x00ffffffffffffff;
        self.check(address, length, Access::Read)?;
        self.check(address, length, Access::Write)?;
        self.materialize_descriptors(address, length);
        let mut cursor = address;
        let end = address
            .checked_add(length as u64)
            .ok_or(MemoryError::InvalidRange)?;
        // All unsupported providers are rejected before promoting any page.
        while cursor < end {
            let frame = self.frame(cursor & !(PAGE_SIZE - 1)).unwrap();
            if self.frames[frame].as_ref().unwrap().backing.is_some() {
                return Err(MemoryError::BackingIo(95));
            }
            cursor = (cursor | (PAGE_SIZE - 1)) + 1;
        }
        self.prepare_mmu_write(address, length)?;
        self.pinned.retain(|_, page| page.strong_count() != 0);
        let mut parts = Vec::new();
        cursor = address;
        while cursor < end {
            let base = cursor & !(PAGE_SIZE - 1);
            let frame = self.frame(base).unwrap();
            // Reuse the interpreter's existing coherent page promotion. It
            // detaches pre-existing COW owners and preserves hardware aliases.
            self.exclusive_read(cursor, &mut [0u8; 1])?;
            let page = self.frames[frame].as_mut().unwrap();
            page.charge.ensure()?;
            if let Some(storage) = page
                .bytes
                .shared()
                .filter(|storage| storage.physical().is_some())
            {
                // Arena-owned physical offsets can be zeroed/reused after a
                // partial unmap even while the arena itself remains alive.
                // Move this private page into stable independent storage once
                // at registration. Retaining an arena Arc alone is not a pin.
                page.bytes = Rc::new(PageBytes::Concurrent(Arc::new(SharedPage::from_box(
                    Box::new(storage.snapshot()),
                ))));
            }
            // A new pin is an independent execution actor even if storage was
            // already promoted by an earlier epoch/registration. Rebuild only
            // this frame's private-access bits before publishing another View;
            // cached unique ownership must not bypass the pin's region guards.
            if self.parallel_cache.is_some() {
                self.parallel_mappings.insert(base);
            }
            self.revision = self.revision.wrapping_add(1);
            let bytes = page.bytes.shared().expect("promoted private page");
            let pin = self
                .pinned
                .get(&bytes.identity)
                .and_then(std::sync::Weak::upgrade)
                .filter(|pin| Arc::ptr_eq(&pin.bytes, bytes))
                .unwrap_or_else(|| {
                    Arc::new(PinnedPage {
                        bytes: bytes.clone(),
                        _charge: page.charge.clone(),
                    })
                });
            self.pinned.insert(bytes.identity, Arc::downgrade(&pin));
            let at = (cursor - base) as usize;
            let count = (end - cursor).min(PAGE_SIZE - at as u64) as usize;
            parts.push((pin, at, count));
            cursor += count as u64;
        }
        self.has_backings = true;
        self.refresh_mapping_mmu(address, length as u64);
        self.invalidate_translations();
        Ok(PinnedBuffer {
            address,
            length,
            parts,
        })
    }
    pub(crate) fn page_pinned(&self, page: &Page) -> bool {
        let Some(bytes) = page.bytes.shared() else {
            return false;
        };
        self.pinned
            .get(&bytes.identity)
            .and_then(std::sync::Weak::upgrade)
            .zip(page.bytes.shared())
            .is_some_and(|(pin, bytes)| Arc::ptr_eq(&pin.bytes, bytes))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_pin_transfers_across_threads_and_keeps_residency_until_last_owner() {
        fn shared<T: Send + Sync>() {}
        shared::<PinnedBuffer>();
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let pin = Arc::new(m.pin_rw(0x1ffc, 16).unwrap());
        pin.write(0, b"0123456789abcdef").unwrap();
        let remote = pin.clone();
        let (ready, begin) = std::sync::mpsc::channel();
        let (reply, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            begin.recv().unwrap();
            remote.write(4, b"DATA").unwrap();
            let mut out = [0; 8];
            remote.read_into(2, &mut out).unwrap();
            reply.send(out).unwrap();
            remote
        });
        m.unmap(0x1000, PAGE_SIZE * 2).unwrap();
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize * 2);
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        m.write(0x1ffc, b"xxxxxxxxxxxxxxxx").unwrap();
        ready.send(()).unwrap();
        assert_eq!(result.recv().unwrap(), *b"23DATA89");
        let remote = worker.join().unwrap();
        drop(pin);
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize * 4);
        let mut unchanged = [7; 4];
        assert!(remote.read_into(14, &mut unchanged).is_err());
        assert_eq!(unchanged, [7; 4]);
        assert!(remote.read(0, usize::MAX).is_err());
        assert_eq!(m.read_array::<16>(0x1ffc).unwrap(), *b"xxxxxxxxxxxxxxxx");
        drop(remote);
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize * 2);
    }
    #[test]
    fn pinned_private_pages_survive_fork_unmap_replacement_and_protection() {
        let mut m = Memory::new(PAGE_SIZE as usize * 8);
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        m.write(0x1ffe, b"abcd").unwrap();
        let pin = m.pin_rw(0x1ffe, 4).unwrap();
        m.write(0x1ffe, b"efgh").unwrap();
        assert_eq!(pin.read(0, 4).unwrap(), b"efgh");
        let child = m.clone();
        pin.write(0, b"ijkl").unwrap();
        assert_eq!(m.read_array::<4>(0x1ffe).unwrap(), *b"ijkl");
        assert_eq!(child.read_array::<4>(0x1ffe).unwrap(), *b"efgh");
        m.protect(0x1000, PAGE_SIZE * 2, Permissions::R).unwrap();
        pin.write(1, b"xx").unwrap();
        assert_eq!(m.read_array::<4>(0x1ffe).unwrap(), *b"ixxl");
        m.unmap(0x1000, PAGE_SIZE * 2).unwrap();
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize * 2);
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        m.write(0x1ffe, b"mmmm").unwrap();
        pin.write(0, b"zzzz").unwrap();
        assert_eq!(m.read_array::<4>(0x1ffe).unwrap(), *b"mmmm");
        drop(pin);
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize * 2);
    }
    #[test]
    fn pins_follow_physical_bytes_across_mremap_and_clone_vm() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let pin = m.pin_rw(0x1000, 8).unwrap();
        m.remap(0x1000, PAGE_SIZE * 2, 0x10000, PAGE_SIZE * 2, false)
            .unwrap();
        pin.write(0, &7u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_u64(0x10000).unwrap(), 7);
        let mut shared = m.share();
        shared.write_array(0x10000, 8u64.to_le_bytes()).unwrap();
        assert_eq!(pin.read(0, 8).unwrap(), 8u64.to_le_bytes());
        let child = m.clone();
        pin.write(0, &9u64.to_le_bytes()).unwrap();
        assert_eq!(shared.read_u64(0x10000).unwrap(), 9);
        assert_eq!(child.read_u64(0x10000).unwrap(), 8);
    }
    #[test]
    fn pinned_code_writes_invalidate_tokens_and_ranges_are_bounded() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let pin = m.pin_rw(0x1000, 16).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let image = m.instruction_identity();
        let page = m.instruction_page_identity(0x1000).unwrap();
        pin.write(0, &0xd503201fu32.to_le_bytes()).unwrap();
        assert_ne!(m.instruction_identity(), image);
        assert_ne!(m.instruction_page_identity(0x1000).unwrap(), page);
        assert!(pin.range(0xfff, 1).is_err());
        assert!(pin.range(0x1010, 1).is_err());
        assert!(pin.read(usize::MAX, 1).is_err());
        assert!(m.pin_rw(0x1000, 16).is_err());
    }
    #[test]
    fn pinned_page_is_not_reused_by_partial_remap_and_views_keep_coherent_bytes() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 4, Permissions::RW).unwrap();
        m.write_array(0x1000, 1u64.to_le_bytes()).unwrap();
        let pin = m.pin_rw(0x1000, 8).unwrap();
        let mut registry = parallel::Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        view.write_array(0x1000, 2u64.to_le_bytes()).unwrap();
        assert_eq!(pin.read(0, 8).unwrap(), 2u64.to_le_bytes());
        pin.write(0, &3u64.to_le_bytes()).unwrap();
        assert_eq!(view.read_u64(0x1000).unwrap(), 3);
        drop(view);
        m.commit_parallel().unwrap();
        m.unmap(0x1000, PAGE_SIZE).unwrap();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x1000, 4u64.to_le_bytes()).unwrap();
        assert_eq!(pin.read(0, 8).unwrap(), 3u64.to_le_bytes());
        pin.write(0, &5u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_u64(0x1000).unwrap(), 4);
    }
    #[test]
    fn pinned_metadata_arrays_cross_page_fragments_without_heap_allocation() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let pin = m.pin_rw(0x1ffb, 16).unwrap();
        pin.write(0, b"0123456789abcdef").unwrap();
        assert_eq!(pin.read_array::<8>(2).unwrap(), *b"23456789");
        assert_eq!(pin.read_array::<0>(16).unwrap(), []);
        assert!(pin.read_array::<4>(14).is_err());
        assert!(pin.read_array::<1>(usize::MAX).is_err());
    }
}
