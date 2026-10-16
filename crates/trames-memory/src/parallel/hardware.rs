// SPDX-License-Identifier: GPL-3.0-or-later
//! Hardware aliases retain the same region, atomic and dirty-byte protocol.
use super::*;

impl Snapshot {
    pub(super) fn refresh_mmu_all(&mut self) {
        let addresses: Vec<_> = self.pages.keys().copied().collect();
        self.refresh_mmu(&addresses);
    }
    pub(super) fn refresh_mmu(&mut self, changed: &[u64]) {
        self.mmu.invalidate_hints();
        let granule = self.mmu.granule();
        if granule == 0 {
            return;
        }
        let groups: BTreeSet<_> = changed
            .iter()
            .map(|&address| address & !(granule as u64 - 1))
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
                        .and_then(page::MutablePage::physical)
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
    pub(crate) fn mmu_read<const N: usize>(&self, address: u64) -> Option<[u8; N]> {
        self.mmu_read_hint(address, &mut self.snapshot.mmu.hint(&self.mmu_cache))
    }
    #[inline(always)]
    pub(super) fn mmu_read_hint<const N: usize>(
        &self,
        address: u64,
        hint: &mut DirectHint,
    ) -> Option<[u8; N]> {
        let address = address & 0x00ffffffffffffff;
        let operand = self
            .snapshot
            .mmu
            .operand_hint(&self.mmu_cache, address, N, false, hint)?;
        let position = self.snapshot.positions[operand.frame]?;
        let frame = &self.snapshot.frames[position];
        let _guard = frame
            .bytes
            .bytes
            .as_ref()
            .map(|bytes| bytes.lock(address as usize & 4095, N));
        // SAFETY: mutable frames retain the exact region guard; constant frames
        // cannot be mutated through any published view. CPU permissions are
        // enforced by the hardware alias, not a second software permission test.
        unsafe { operand.read() }
    }
    #[inline]
    pub(super) fn mmu_write<const N: usize>(&self, address: u64, bytes: [u8; N]) -> bool {
        self.mmu_write_hint(address, bytes, &mut self.snapshot.mmu.hint(&self.mmu_cache))
    }
    #[inline(always)]
    pub(super) fn mmu_write_hint<const N: usize>(
        &self,
        address: u64,
        bytes: [u8; N],
        hint: &mut DirectHint,
    ) -> bool {
        let address = address & 0x00ffffffffffffff;
        let Some(operand) = self
            .snapshot
            .mmu
            .operand_hint(&self.mmu_cache, address, N, true, hint)
        else {
            return false;
        };
        let Some(position) = self.snapshot.positions[operand.frame] else {
            return false;
        };
        let frame = &self.snapshot.frames[position];
        let offset = address as usize & 4095;
        // A read-only constant frame must fault without constructing a writable
        // Rust reference. The fixed store instruction supplies that proof.
        let Some(storage) = &frame.bytes.bytes else {
            // SAFETY: a constant mapping has no hardware write permission.
            debug_assert!(!unsafe { operand.write(bytes) });
            return false;
        };
        let mut guard = storage.lock(offset, N);
        // SAFETY: the same guarded physical bytes back the hardware alias.
        if unsafe { operand.write(bytes) } {
            self.changed(frame, &mut guard, offset, N);
            true
        } else {
            false
        }
    }
}
