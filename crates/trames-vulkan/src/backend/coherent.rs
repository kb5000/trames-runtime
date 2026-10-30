// SPDX-License-Identifier: GPL-3.0-or-later
//! HOST_COHERENT shadow mappings at the exposed Vulkan host synchronization
//! boundaries. Pixel presentation remains an independent no-readback path.
use super::*;

pub(super) struct CoherentBytes {
    bytes: Vec<u8>,
    budget: crate::Budget,
}
impl CoherentBytes {
    pub(super) fn new(size: usize, budget: crate::Budget) -> Result<Self> {
        if !budget.reserve(size as u64) {
            return Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into());
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(size).is_err() {
            budget.release(size as u64);
            return Err(vk::Result::ERROR_OUT_OF_HOST_MEMORY.into());
        }
        bytes.resize(size, 0);
        Ok(Self { bytes, budget })
    }
    pub(super) fn initialize(&mut self, m: &impl CpuMemory, guest: u64) -> Result<()> {
        m.read(guest, &mut self.bytes)?;
        Ok(())
    }
}
impl Drop for CoherentBytes {
    fn drop(&mut self) {
        self.budget.release(self.bytes.len() as u64);
    }
}

// SAFETY for both helpers: native spans the retained mapped VkDeviceMemory
// range, disjoint from guest/baseline storage. Volatile raw accesses do not form
// Rust references to storage the GPU may change. Existing guest region guards
// cover CPU aliases. The guest supplies Vulkan execution dependencies; racing
// writes to the same byte may resolve either way, as on actual coherent memory.
unsafe fn upload(guest: &[u8], baseline: &mut [u8], native: *mut u8) -> usize {
    let mut changed = 0;
    for (i, (value, previous)) in guest.iter().zip(baseline).enumerate() {
        if value != previous {
            unsafe { native.add(i).write_volatile(*value) };
            *previous = *value;
            changed += 1;
        }
    }
    changed
}
unsafe fn download(guest: &mut [u8], baseline: &mut [u8], native: *const u8) -> usize {
    let mut changed = 0;
    for (i, (value, previous)) in guest.iter_mut().zip(baseline).enumerate() {
        if value == previous {
            let next = unsafe { native.add(i).read_volatile() };
            if next != *value {
                *value = next;
                changed += 1;
            }
            *previous = next;
        }
        // A host write since the last synchronization remains host-owned. In
        // particular, output readback cannot overwrite a different input range.
    }
    changed
}
// Commit only GPU-changed runs. Copying the complete staged page back would
// overwrite CPU-owned input bytes that may change independently of GPU output.
fn download_changes(
    guest: &mut [u8],
    baseline: &mut [u8],
    native: *const u8,
    mut write: impl FnMut(usize, &[u8]) -> std::result::Result<(), MemoryError>,
) -> Result<usize> {
    let mut previous = [0; trames_memory::PAGE_SIZE as usize];
    previous[..baseline.len()].copy_from_slice(baseline);
    // SAFETY: caller retains the mapped native range. Guest/baseline are owned
    // staging buffers; the existing volatile GPU-byte rules remain unchanged.
    let count = unsafe { download(guest, baseline, native) };
    let mut at = 0;
    while at < baseline.len() {
        if baseline[at] == previous[at] {
            at += 1;
            continue;
        }
        let begin = at;
        while at < baseline.len() && baseline[at] != previous[at] {
            at += 1;
        }
        if let Err(error) = write(begin, &guest[begin..at]) {
            // Earlier runs committed. Keep every remaining baseline byte old
            // so a failed guest write cannot silently suppress the next retry.
            let len = baseline.len();
            baseline[begin..].copy_from_slice(&previous[begin..len]);
            return Err(error.into());
        }
    }
    Ok(count)
}
fn synchronize_chunk(
    m: &mut impl CpuMemory,
    guest: u64,
    baseline: &mut [u8],
    native: *mut u8,
    up: bool,
) -> Result<(usize, bool)> {
    // Ordinary CPU copies already use the shared raw-region access model on
    // hardware. Borrowing a guest &[u8]/&mut [u8] instead revokes stage-two
    // access for each 4 KiB fragment (possibly a much larger retained extent).
    // A bounded owned buffer avoids those revocations without a new permission,
    // aliasing or synchronization policy. Whole-map preflight remains above.
    let mut bytes = [0; trames_memory::PAGE_SIZE as usize];
    let bytes = &mut bytes[..baseline.len()];
    if let Err(error) = m.read(guest, bytes) {
        if up {
            return Err(error.into());
        }
        // The old write-chunk contract can read/modify a write-only mapping.
        // Retain that original checked path rather than adding read permission.
        return Ok(m.cpu_write_chunk(guest, baseline.len(), |bytes| unsafe {
            download(bytes, baseline, native)
        })?);
    }
    let count = if up {
        // SAFETY: native is retained by Mapping and disjoint from owned bytes.
        unsafe { upload(bytes, baseline, native) }
    } else {
        download_changes(bytes, baseline, native, |offset, bytes| {
            m.write(guest + offset as u64, bytes)
        })?
    };
    Ok((count, false))
}
pub(super) fn synchronize(
    map: &mut Mapping,
    m: &mut impl CpuMemory,
    offset: u64,
    len: u64,
    up: bool,
) -> Result<TransferMetrics> {
    let Some(coherent) = &mut map.coherent else {
        return Ok(TransferMetrics::default());
    };
    let start = (offset - map.offset) as usize;
    let len = len as usize;
    let guest = map.guest + start as u64;
    m.check(guest, len, if up { Access::Read } else { Access::Write })?;
    let native = (map.memory.mapped.get() as *mut u8).wrapping_add(offset as usize);
    let mut at = 0;
    let mut metrics = TransferMetrics::default();
    while at < len {
        let address = guest + at as u64;
        let n = (len - at)
            .min((trames_memory::PAGE_SIZE - address % trames_memory::PAGE_SIZE) as usize);
        let baseline = &mut coherent.bytes[start + at..start + at + n];
        let (count, direct) = synchronize_chunk(m, address, baseline, native.wrapping_add(at), up)?;
        if up {
            metrics.upload_bytes += count as u64;
        } else {
            metrics.download_bytes += count as u64;
        }
        if direct {
            metrics.direct_bytes += count as u64;
        } else {
            metrics.buffered_bytes += count as u64;
        }
        at += n;
    }
    Ok(metrics)
}
impl Backend {
    pub(super) fn record_transfer(&mut self, t: TransferMetrics) {
        self.transfers.upload_bytes += t.upload_bytes;
        self.transfers.download_bytes += t.download_bytes;
        self.transfers.direct_bytes += t.direct_bytes;
        self.transfers.buffered_bytes += t.buffered_bytes;
    }
    pub(super) fn coherent_sync(&mut self, m: &mut impl CpuMemory, up: bool) -> Result<()> {
        let mut totals = TransferMetrics::default();
        for map in self.mappings.values_mut() {
            let t = synchronize(map, m, map.offset, map.size, up)?;
            totals.upload_bytes += t.upload_bytes;
            totals.download_bytes += t.download_bytes;
            totals.direct_bytes += t.direct_bytes;
            totals.buffered_bytes += t.buffered_bytes;
        }
        self.record_transfer(totals);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_cpu_inputs_and_gpu_outputs_do_not_overwrite_each_other() {
        let mut guest = [0u8; 16];
        let mut native = guest;
        let mut baseline = guest;
        guest[1..4].copy_from_slice(b"cpu");
        native[10..13].copy_from_slice(b"gpu");
        unsafe {
            assert_eq!(upload(&guest, &mut baseline, native.as_mut_ptr()), 3);
            assert_eq!(download(&mut guest, &mut baseline, native.as_ptr()), 3);
        }
        assert_eq!(&guest[1..4], b"cpu");
        assert_eq!(&guest[10..13], b"gpu");
        assert_eq!(guest, native);
        assert_eq!(guest, baseline);
        guest[0] = 7;
        native[15] = 9;
        unsafe {
            download(&mut guest, &mut baseline, native.as_ptr());
        }
        assert_eq!(guest[0], 7);
        assert_eq!(guest[15], 9);
        unsafe {
            upload(&guest, &mut baseline, native.as_mut_ptr());
        }
        assert_eq!(guest, native);
        assert_eq!(guest, baseline);
    }
    #[test]
    fn hardware_coherent_transfers_use_cpu_bytes_without_revoking_hardware() {
        use std::{cell::UnsafeCell, sync::atomic::AtomicUsize};
        use trames_memory::{HardwareStorage, Permissions, PAGE_SIZE};
        struct Storage {
            bytes: Box<UnsafeCell<[u8; PAGE_SIZE as usize]>>,
            borrows: AtomicUsize,
        }
        // SAFETY: one test thread owns the view and its root. Guest byte access
        // uses the page's existing raw region protocol; there are no HV actors.
        unsafe impl Sync for Storage {}
        unsafe impl HardwareStorage for Storage {
            fn pointer(&self) -> *mut u8 {
                self.bytes.get().cast()
            }
            fn physical_address(&self) -> u64 {
                0
            }
            fn begin_host_access(&self) {
                self.borrows.fetch_add(1, Ordering::Relaxed);
            }
            fn end_host_access(&self) {}
        }
        let storage = Arc::new(Storage {
            bytes: Box::new(UnsafeCell::new([0; PAGE_SIZE as usize])),
            borrows: AtomicUsize::new(0),
        });
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = trames_memory::parallel::Registry::default();
        registry.use_hardware();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.enable_hardware();
        // SAFETY: this test owns the root and sole frozen view; the initialized
        // zero storage is retained until all exported aliases are dropped.
        unsafe {
            view.export_hardware_page(0x1000, Access::Write, |_| Ok(storage.clone()))
                .unwrap();
        }
        let mut baseline = [0; 64];
        let mut native = [0; 64];
        view.write(0x1001, b"cpu").unwrap();
        let (count, _) =
            synchronize_chunk(&mut view, 0x1000, &mut baseline, native.as_mut_ptr(), true).unwrap();
        assert_eq!(count, 3);
        assert_eq!(storage.borrows.load(Ordering::Relaxed), 0);
        native[10..13].copy_from_slice(b"gpu");
        let (count, _) =
            synchronize_chunk(&mut view, 0x1000, &mut baseline, native.as_mut_ptr(), false)
                .unwrap();
        assert_eq!(count, 3);
        let mut guest = [0; 64];
        view.read(0x1000, &mut guest).unwrap();
        assert_eq!(guest, native);
        view.write(0x1000, &[9]).unwrap();
        native[63] = 7;
        assert_eq!(
            synchronize_chunk(&mut view, 0x1000, &mut baseline, native.as_mut_ptr(), false)
                .unwrap()
                .0,
            1
        );
        view.read(0x1000, &mut guest).unwrap();
        assert_eq!((guest[0], guest[63]), (9, 7));
        assert_eq!(storage.borrows.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn staged_download_preserves_independent_inputs_and_failed_write_baselines() {
        let mut baseline = [0; 16];
        let mut guest = baseline;
        let mut native = baseline;
        let mut stored = baseline;
        guest[2] = 9; // CPU input is not part of either GPU output run.
        stored[2] = 9;
        native[0] = 1;
        native[8] = 2;
        let result = download_changes(&mut guest, &mut baseline, native.as_ptr(), |at, bytes| {
            if at == 8 {
                return Err(MemoryError::Unmapped(0x1008));
            }
            stored[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        });
        assert!(matches!(
            result,
            Err(Failure::Memory(MemoryError::Unmapped(0x1008)))
        ));
        assert_eq!((stored[0], stored[2], stored[8]), (1, 9, 0));
        assert_eq!((baseline[0], baseline[2], baseline[8]), (1, 0, 0));
        guest = stored;
        let count = download_changes(&mut guest, &mut baseline, native.as_ptr(), |at, bytes| {
            stored[at..at + bytes.len()].copy_from_slice(bytes);
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!((stored[0], stored[2], stored[8]), (1, 9, 2));
    }
    #[test]
    fn write_only_mapping_keeps_original_checked_download() {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions {
                    read: false,
                    write: true,
                    execute: false,
                },
            )
            .unwrap();
        let mut baseline = [0; 16];
        let mut native = [7; 16];
        assert_eq!(
            synchronize_chunk(
                &mut memory,
                0x1000,
                &mut baseline,
                native.as_mut_ptr(),
                false
            )
            .unwrap()
            .0,
            16
        );
        memory
            .protect(
                0x1000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RW,
            )
            .unwrap();
        assert_eq!(memory.read_array::<16>(0x1000).unwrap(), native);
    }
    #[test]
    fn coherent_tracking_is_charged_and_released_with_the_mapping() {
        let budget = crate::Budget::default();
        let bytes = CoherentBytes::new(4096, budget.clone()).unwrap();
        assert_eq!(budget.used(), 4096);
        drop(bytes);
        assert_eq!(budget.used(), 0);
    }
}
