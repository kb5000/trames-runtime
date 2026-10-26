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
        let (count, direct) = if up {
            m.cpu_read_chunk(address, n, |bytes| unsafe {
                upload(bytes, baseline, native.add(at))
            })?
        } else {
            m.cpu_write_chunk(address, n, |bytes| unsafe {
                download(bytes, baseline, native.add(at))
            })?
        };
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
    fn coherent_tracking_is_charged_and_released_with_the_mapping() {
        let budget = crate::Budget::default();
        let bytes = CoherentBytes::new(4096, budget.clone()).unwrap();
        assert_eq!(budget.used(), 4096);
        drop(bytes);
        assert_eq!(budget.used(), 0);
    }
}
