// SPDX-License-Identifier: GPL-3.0-or-later
//! Audited mutable bytes: guards protect only the 64-byte regions they touch.
use crate::PAGE_SIZE;
use std::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU64, Ordering},
};

const REGION: usize = 64;
const PAGE: usize = PAGE_SIZE as usize;

/// Byte cells are never exposed without a matching, live range guard. The Box
/// stays at one allocation for the lifetime of every guard and borrowed slice.
enum Bytes {
    Heap(Box<[UnsafeCell<u8>; PAGE]>),
    Mapped(std::sync::Arc<crate::mmu::Slot>),
}
impl Bytes {
    fn as_ptr(&self) -> *const UnsafeCell<u8> {
        match self {
            Self::Heap(bytes) => bytes.as_ptr(),
            Self::Mapped(slot) => slot.pointer().cast(),
        }
    }
}
pub(super) struct MutablePage {
    bytes: Bytes,
    held: AtomicU64,
    reservations: [UnsafeCell<[u64; 4]>; PAGE / REGION],
    reservation_overrides: [UnsafeCell<u8>; PAGE / REGION],
    reservation_base: AtomicU64,
    reservation_written: AtomicU64,
}
// SAFETY: all non-atomic byte accesses are inside a guard for their complete
// region mask. Overlapping masks are mutually exclusive; disjoint slice ranges
// cannot alias. Each reservation row/override byte uses its same region guard;
// page-wide epochs/masks are atomic and resets hold every region. No whole-page
// mutable reference or bare pointer escapes this module.
unsafe impl Sync for MutablePage {}

fn mask(offset: usize, len: usize) -> u64 {
    assert!(offset <= PAGE && len <= PAGE - offset);
    if len == 0 {
        return 0;
    }
    let first = offset / REGION;
    let last = (offset + len - 1) / REGION;
    (u64::MAX >> (63 - (last - first))) << first
}

impl MutablePage {
    pub fn new(bytes: [u8; PAGE]) -> Self {
        Self::with_storage(Bytes::Heap(Box::new(bytes.map(UnsafeCell::new))))
    }
    fn with_storage(bytes: Bytes) -> Self {
        Self {
            bytes,
            held: AtomicU64::new(0),
            reservations: std::array::from_fn(|_| UnsafeCell::new([0; 4])),
            reservation_overrides: std::array::from_fn(|_| UnsafeCell::new(0)),
            reservation_base: AtomicU64::new(0),
            reservation_written: AtomicU64::new(0),
        }
    }
    pub(super) fn new_mapped(bytes: [u8; PAGE], slot: std::sync::Arc<crate::mmu::Slot>) -> Self {
        slot.initialize(&bytes);
        Self::with_storage(Bytes::Mapped(slot))
    }
    pub(super) fn physical(&self) -> Option<(&std::sync::Arc<crate::mmu::host::Mapping>, usize)> {
        match &self.bytes {
            Bytes::Mapped(slot) => Some((&slot.owner, slot.offset)),
            _ => None,
        }
    }
    pub fn lock(&self, offset: usize, len: usize) -> Guard<'_> {
        self.lock_mask(mask(offset, len))
    }
    pub fn lock_pair(&self, a: usize, b: usize, len: usize) -> Guard<'_> {
        self.lock_mask(mask(a, len) | mask(b, len))
    }
    fn lock_mask(&self, mask: u64) -> Guard<'_> {
        let mut attempts = 0;
        loop {
            if self
                .held
                .try_update(Ordering::Acquire, Ordering::Relaxed, |held| {
                    (held & mask == 0).then_some(held | mask)
                })
                .is_ok()
            {
                return Guard { page: self, mask };
            }
            // Native borrows are bounded. Avoid an unbounded tight spin when a
            // peer is descheduled while holding an overlapping region.
            if attempts < 16 {
                std::hint::spin_loop();
                attempts += 1;
            } else {
                std::thread::yield_now();
            }
        }
    }
}

pub(super) struct Guard<'a> {
    page: &'a MutablePage,
    mask: u64,
}
impl Guard<'_> {
    fn covers(&self, offset: usize, len: usize) {
        assert_eq!(mask(offset, len) & !self.mask, 0, "unguarded byte range");
    }
    pub fn read(&self, offset: usize, len: usize) -> &[u8] {
        self.covers(offset, len);
        // SAFETY: UnsafeCell is transparent over u8; bounds and ownership of
        // every touched region were checked. The reference ends before unlock.
        unsafe {
            std::slice::from_raw_parts(self.page.bytes.as_ptr().cast::<u8>().add(offset), len)
        }
    }
    pub fn write(&mut self, offset: usize, len: usize) -> &mut [u8] {
        self.covers(offset, len);
        // SAFETY: the live exclusive region mask excludes every overlapping
        // reader/writer. &mut self also excludes another slice from this guard.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.page.bytes.as_ptr().cast::<u8>().cast_mut().add(offset),
                len,
            )
        }
    }
    pub fn copy_within(&mut self, source: usize, destination: usize, len: usize) {
        self.covers(source, len);
        self.covers(destination, len);
        // SAFETY: both ranges are protected by this single guard; ptr::copy
        // permits overlap. No byte reference is alive across this mutable call.
        unsafe {
            let ptr = self.page.bytes.as_ptr().cast::<u8>().cast_mut();
            std::ptr::copy(ptr.add(source), ptr.add(destination), len);
        }
    }
    pub fn reservation(&self, slot: usize) -> u64 {
        self.covers(slot * 16, 16);
        let region = slot / 4;
        if self.page.reservation_written.load(Ordering::Relaxed) & (1 << region) == 0 {
            return self.page.reservation_base.load(Ordering::Relaxed);
        }
        // SAFETY: this region's byte mask also protects its reservation row
        // and override byte; no mutable metadata reference survives unlock.
        let (values, overrides) = unsafe {
            (
                &*self.page.reservations[region].get(),
                *self.page.reservation_overrides[region].get(),
            )
        };
        let local = slot % 4;
        values[if local == 0 || overrides & (1 << local) != 0 {
            local
        } else {
            0
        }]
    }
    pub fn invalidate(&mut self, offset: usize, len: usize, version: u64) {
        self.covers(offset, len);
        if len == 0 {
            return;
        }
        if offset == 0 && len == PAGE {
            self.page.reservation_base.store(version, Ordering::Relaxed);
            self.page.reservation_written.store(0, Ordering::Relaxed);
        } else {
            let active = self.page.reservation_written.load(Ordering::Relaxed);
            let base = self.page.reservation_base.load(Ordering::Relaxed);
            let mut added = 0;
            for region in offset / REGION..=(offset + len - 1) / REGION {
                // SAFETY: covers() ensures exclusive ownership of every touched
                // region. Different guards only access disjoint metadata rows.
                let (values, overrides) = unsafe {
                    (
                        &mut *self.page.reservations[region].get(),
                        &mut *self.page.reservation_overrides[region].get(),
                    )
                };
                if active & (1 << region) == 0 {
                    values[0] = base;
                    *overrides = 0;
                    added |= 1 << region;
                }
                let first = offset.max(region * REGION) / 16 % 4;
                let last = (offset + len - 1).min(region * REGION + REGION - 1) / 16 % 4;
                if first == 0 && last == 3 {
                    // A complete 64-byte write invalidates four granules with
                    // one base store, including unaligned bulk-copy interiors.
                    values[0] = version;
                    *overrides = 0;
                } else {
                    if first == 0 {
                        // Preserve unaffected granules before replacing their
                        // inherited base. No spurious neighbor invalidation.
                        for slot in last + 1..4 {
                            if *overrides & (1 << slot) == 0 {
                                values[slot] = values[0];
                                *overrides |= 1 << slot;
                            }
                        }
                    }
                    for (slot, value) in values.iter_mut().enumerate().take(last + 1).skip(first) {
                        *value = version;
                        if slot != 0 {
                            *overrides |= 1 << slot;
                        }
                    }
                }
            }
            if added != 0 {
                self.page
                    .reservation_written
                    .fetch_or(added, Ordering::Relaxed);
            }
        }
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.page.held.fetch_and(!self.mask, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{mpsc, Arc},
        time::Duration,
    };

    #[test]
    fn disjoint_regions_progress_while_a_peer_borrows_the_same_page() {
        let page = Arc::new(MutablePage::new([0; PAGE]));
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let first_page = page.clone();
        let first = std::thread::spawn(move || {
            let mut guard = first_page.lock(0, 64);
            let bytes = guard.write(0, 64);
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            bytes.fill(11);
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let peer_page = page.clone();
        let peer = std::thread::spawn(move || {
            // A real live mutable slice exists in the first region. Only this
            // disjoint byte interval may be exposed on the other thread.
            let mut guard = peer_page.lock(64, 64);
            guard.write(64, 64).fill(22);
            done_tx.send(()).unwrap();
        });
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        release_tx.send(()).unwrap();
        first.join().unwrap();
        peer.join().unwrap();
        let guard = page.lock(0, PAGE);
        assert_eq!(guard.read(0, 64), [11; 64]);
        assert_eq!(guard.read(64, 64), [22; 64]);
        assert_eq!(guard.read(128, PAGE - 128), [0; PAGE - 128]);
    }

    #[test]
    fn overlapping_masks_publish_bytes_and_unwind_releases_the_guard() {
        let page = Arc::new(MutablePage::new([0; PAGE]));
        let guard = page.lock(63, 2);
        let (done_tx, done_rx) = mpsc::channel();
        let peer_page = page.clone();
        let peer = std::thread::spawn(move || {
            let mut guard = peer_page.lock(64, 8);
            assert_eq!(guard.read(64, 1), [33]);
            guard.write(64, 8).fill(44);
            done_tx.send(()).unwrap();
        });
        let mut guard = guard;
        guard.write(63, 2).fill(33);
        drop(guard);
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        peer.join().unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = page.lock(128, 1);
            guard.write(128, 1)[0] = 55;
            panic!("internal operation unwinds");
        }));
        let guard = page.lock(0, PAGE);
        assert_eq!(guard.read(63, 9), [33, 44, 44, 44, 44, 44, 44, 44, 44]);
        assert_eq!(guard.read(128, 1), [55]);
    }
}
