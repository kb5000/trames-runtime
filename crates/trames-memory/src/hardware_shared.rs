// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared physical exports and one-shot wakeups. No hardware policy is added
//! to ordinary guest loads; only host byte borrows revoke hardware access.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

/// A complete stable initialized RW guest page, with scoped host ownership.
///
/// # Safety
/// The pointer remains valid until the last owner drops. begin_host_access
/// must synchronously exclude every hardware access to the page before any
/// Rust reference is made, until the matching end_host_access. Calls may nest
/// for disjoint regions. Failures must not grant access. Hardware page tables
/// or execution Views retain this owner while hardware can run. A stopped
/// table may retain weak aliases only if it invalidates them before reuse.
pub unsafe trait HardwareStorage: Send + Sync {
    fn pointer(&self) -> *mut u8;
    fn physical_address(&self) -> u64;
    /// False only after this storage can never again have a hardware actor.
    fn is_live(&self) -> bool {
        true
    }
    fn begin_host_access(&self);
    fn end_host_access(&self);
}

/// Race-free one-shot readiness. Callbacks carry only scheduling authority,
/// never guest bytes. A blocked hardware task returns its execution slot.
#[derive(Default)]
pub struct HardwareWait {
    ready: AtomicBool,
    wake: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl HardwareWait {
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    pub fn subscribe(&self, wake: impl FnOnce() + Send + 'static) {
        let mut slot = self.wake.lock().unwrap();
        if self.ready() {
            drop(slot);
            wake();
        } else {
            assert!(slot.is_none());
            *slot = Some(Box::new(wake));
        }
    }
    pub fn fire(&self) {
        let mut slot = self.wake.lock().unwrap();
        self.ready.store(true, Ordering::Release);
        let wake = slot.take();
        drop(slot);
        if let Some(wake) = wake {
            wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HardwareStorage, SharedPage, PAGE_SIZE};
    use std::{
        cell::UnsafeCell,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    struct Storage {
        bytes: Box<UnsafeCell<[u8; PAGE_SIZE as usize]>>,
        borrows: AtomicUsize,
    }
    // SAFETY: tests grant bytes only through the page's existing region locks.
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
        fn end_host_access(&self) {
            assert!(self.borrows.fetch_sub(1, Ordering::Relaxed) != 0);
        }
    }
    #[test]
    fn canonical_export_gates_reads_writes_and_releases_region_ownership() {
        let page = SharedPage::new([73; PAGE_SIZE as usize]);
        let storage = Arc::new(Storage {
            bytes: Box::new(UnsafeCell::new([0; PAGE_SIZE as usize])),
            borrows: AtomicUsize::new(0),
        });
        // SAFETY: unpublished test page, no native aliases or external actors.
        let first = unsafe {
            page.export_hardware(|bytes| {
                std::ptr::copy_nonoverlapping(
                    bytes.unwrap().as_ptr(),
                    storage.pointer(),
                    PAGE_SIZE as usize,
                );
                Ok(storage.clone())
            })
        }
        .unwrap();
        page.with_read(17, 2, |bytes| {
            assert_eq!(bytes, [73, 73]);
            assert_eq!(storage.borrows.load(Ordering::Relaxed), 1);
        });
        page.with_write(17, 1, |bytes| {
            bytes[0] = 29;
            assert_eq!(storage.borrows.load(Ordering::Relaxed), 1);
        });
        page.with_read(17, 1, |bytes| assert_eq!(bytes, [29]));
        assert_eq!(storage.borrows.load(Ordering::Relaxed), 0);
        // SAFETY: same stopped storage; re-export must retain canonical bytes.
        let second =
            unsafe { page.export_hardware(|_| panic!("duplicate physical storage")) }.unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(!page.unmaterialized_zero());
        assert_eq!(storage.borrows.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn readiness_race_never_loses_or_replays_a_wakeup() {
        for _ in 0..128 {
            let wait = Arc::new(HardwareWait::default());
            let called = Arc::new(AtomicUsize::new(0));
            let peer = wait.clone();
            let thread = std::thread::spawn(move || {
                peer.fire();
                peer.fire();
            });
            let result = called.clone();
            wait.subscribe(move || {
                result.fetch_add(1, Ordering::Relaxed);
            });
            thread.join().unwrap();
            assert!(wait.ready());
            assert_eq!(called.load(Ordering::Relaxed), 1);
        }
    }
}
