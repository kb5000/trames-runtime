// SPDX-License-Identifier: GPL-3.0-or-later
//! Hardware aliases retain the same region, atomic and dirty-byte protocol.
use super::*;

impl Snapshot {
    pub(super) fn refresh_mmu_all(&mut self) {
        let addresses: Slots<_> = self.pages.keys().copied().collect();
        self.refresh_mmu(addresses);
    }
    pub(super) fn refresh_mmu(&mut self, changed: impl IntoIterator<Item = u64>) {
        if self.hardware {
            return;
        }
        let granule = self.mmu.granule();
        if granule == 0 {
            return;
        }
        let groups: BTreeSet<_> = changed
            .into_iter()
            .map(|address| address & !(granule as u64 - 1))
            .collect();
        for base in groups {
            let mut permissions = None;
            let mut physical = Vec::new();
            for at in (base..base + granule as u64).step_by(PAGE_SIZE as usize) {
                let Some(&position) = self.pages.get(&at) else {
                    break;
                };
                let frame = &self.frames[position];
                if self.backed_pages.contains(&at)
                    || frame.error.is_some()
                    || permissions.is_some_and(|p| p != frame.permissions)
                {
                    break;
                }
                let storage = if let Some(bytes) = &frame.bytes.constant {
                    bytes.physical()
                } else {
                    frame
                        .bytes
                        .bytes
                        .as_ref()
                        .and_then(|bytes| bytes.physical())
                };
                let Some((mapping, offset)) = storage else {
                    break;
                };
                permissions = Some(frame.permissions);
                physical.push((mapping, offset, frame.root_frame));
            }
            self.mmu.update(base, permissions, &physical);
        }
    }
}
impl View {
    #[inline]
    pub(super) fn operand_translation(
        &self,
        address: u64,
        access: Access,
    ) -> Result<Translation, MemoryError> {
        let base = address & !(PAGE_SIZE - 1);
        let entry = self.translations[Translation::slot(base)].get();
        if entry.matches(base, Translation::VALID) {
            return Ok(entry);
        }
        Memory::end(address, 1)?;
        self.frame_slow(address, access)?;
        Ok(self.translations[Translation::slot(base)].get())
    }
    #[inline(always)]
    pub(super) fn mmu_read_entry<const N: usize>(
        &self,
        entry: Translation,
        offset: usize,
    ) -> Option<[u8; N]> {
        if entry.cpu == 0 {
            return None;
        }
        // SAFETY: only this immutable snapshot fills this view's TLB. The caller
        // proves one-page bounds; no mapping can change during a view's lifetime.
        let frame = unsafe { self.snapshot.frames.get_unchecked(entry.frame) };
        let _guard = frame
            .bytes
            .bytes
            .as_ref()
            .map(|_| self.frame_guard(frame, offset, N));
        // SAFETY: mutable physical bytes retain the exact same region guard;
        // constant frames cannot be mutated through any published view.
        unsafe { entry.read(offset) }
    }
    #[inline(always)]
    pub(super) fn mmu_write_entry<const N: usize>(
        &self,
        entry: Translation,
        offset: usize,
        bytes: [u8; N],
    ) -> bool {
        if entry.cpu == 0 || entry.tag & (4 | Translation::RESIDENT) != Translation::RESIDENT {
            return false;
        }
        // SAFETY: same retained immutable snapshot and page-contained operand.
        let frame = unsafe { self.snapshot.frames.get_unchecked(entry.frame) };
        let Some(_) = &frame.bytes.bytes else {
            return false;
        };
        let mut guard = self.frame_guard(frame, offset, N);
        // SAFETY: same guarded physical bytes back the protected alias. A failed
        // store leaves them unchanged and the checked path supplies the errno.
        if unsafe { entry.write(offset, bytes) } {
            self.changed(frame, &mut guard, offset, N);
            true
        } else {
            false
        }
    }
    pub(crate) fn mmu_read<const N: usize>(&self, address: u64) -> Option<[u8; N]> {
        let address = address & 0x00ffffffffffffff;
        let offset = address as usize & (PAGE_SIZE as usize - 1);
        if !matches!(N, 1 | 2 | 4 | 8 | 16) || N > PAGE_SIZE as usize - offset {
            return None;
        }
        let entry = self.operand_translation(address, Access::Read).ok()?;
        self.mmu_read_entry(entry, offset)
    }
}
