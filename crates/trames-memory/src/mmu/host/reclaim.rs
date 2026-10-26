// SPDX-License-Identifier: GPL-3.0-or-later
//! Only physical-slot creation/final release synchronizes here. Guest accesses
//! retain the existing ARM/region model and never visit this metadata.
use super::*;
use std::sync::Mutex;

#[derive(Default, Clone, Copy)]
struct Group {
    owners: usize,
    reusable: bool,
}
pub(super) struct Slots {
    granule: usize,
    groups: Mutex<Box<[Group]>>,
    #[cfg(test)]
    pub retired_bytes: AtomicUsize,
}
impl Slots {
    pub fn new(granule: usize) -> Self {
        Self {
            granule,
            groups: Mutex::new(vec![Group::default(); WINDOW / granule].into_boxed_slice()),
            #[cfg(test)]
            retired_bytes: AtomicUsize::new(0),
        }
    }
    pub fn retain(&self, address: *mut u8, offset: usize) {
        let mut groups = self.groups.lock().unwrap();
        let index = offset / self.granule;
        let group = &mut groups[index];
        #[cfg(target_vendor = "apple")]
        if group.reusable {
            // SAFETY: this mapping and the complete aligned host group are
            // owned; no new slot is published before reusable status ends.
            assert_eq!(
                unsafe {
                    libc::madvise(
                        address.add(index * self.granule).cast(),
                        self.granule,
                        libc::MADV_FREE_REUSE,
                    )
                },
                0,
                "reactivate owned reusable RAM before publishing a slot"
            );
        }
        #[cfg(not(target_vendor = "apple"))]
        let _ = address;
        group.reusable = false;
        group.owners += 1;
    }
    pub fn release(&self, address: *mut u8, offset: usize) {
        let mut groups = self.groups.lock().unwrap();
        let index = offset / self.granule;
        let group = &mut groups[index];
        assert!(group.owners != 0);
        group.owners -= 1;
        if group.owners != 0 {
            return;
        }
        #[cfg(target_os = "linux")]
        let advice = libc::MADV_REMOVE; // punch the shared memfd, including CPU aliases
        #[cfg(target_vendor = "apple")]
        let advice = libc::MADV_FREE_REUSABLE;
        // SAFETY: every 4KiB byte/slot owner in this host granule has ended.
        // Slot registration and retirement share this object lock, preventing
        // a concurrent new slot from racing the discard. CPU views only retain
        // raw aliases; any reached nonzero page also retains its physical slot.
        let result = unsafe {
            libc::madvise(
                address.add(index * self.granule).cast(),
                self.granule,
                advice,
            )
        };
        group.reusable = result == 0;
        #[cfg(test)]
        if result == 0 {
            self.retired_bytes
                .fetch_add(self.granule, Ordering::Relaxed);
        }
    }
}
