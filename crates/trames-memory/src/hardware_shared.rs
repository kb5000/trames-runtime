// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared physical exports and one-shot wakeups. No hardware policy is added
//! to ordinary guest loads; only host byte borrows revoke hardware access.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

/// Retained file-backed host mapping. Geometry is explicit: an executor may
/// import complete host granules without moving bytes observed by a presenter.
#[derive(Clone)]
pub struct SharedMapping {
    pub(crate) base: usize,
    pub(crate) length: usize,
    pub(crate) offset: usize,
    pub(crate) _owner: std::sync::Arc<dyn Send + Sync>,
}
impl SharedMapping {
    pub fn allocation_pointer(&self) -> *mut u8 {
        self.base as *mut u8
    }
    pub fn allocation_len(&self) -> usize {
        self.length
    }
    pub fn allocation_offset(&self) -> usize {
        self.offset
    }
    pub fn pointer(&self) -> *mut u8 {
        (self.base + self.offset) as *mut u8
    }
    pub fn with_offset(&self, offset: usize) -> Option<Self> {
        offset
            .checked_add(crate::PAGE_SIZE as usize)
            .filter(|end| *end <= self.length)?;
        Some(Self {
            offset,
            ..self.clone()
        })
    }
}

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
    /// Preserves stable external aliases when a retired VM is replaced.
    fn shared_mapping(&self) -> Option<SharedMapping> {
        None
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
    fn explicit_shared_mapping_keeps_external_aliases_and_opaque_exports_refused() {
        use std::{fs::OpenOptions, os::fd::AsRawFd};
        struct Mapping {
            pointer: usize,
            file: std::fs::File,
        }
        impl Drop for Mapping {
            fn drop(&mut self) {
                unsafe {
                    libc::munmap(self.pointer as *mut _, 16384);
                }
            }
        }
        struct Imported {
            mapping: SharedMapping,
            borrows: AtomicUsize,
        }
        unsafe impl HardwareStorage for Imported {
            fn pointer(&self) -> *mut u8 {
                self.mapping.pointer()
            }
            fn physical_address(&self) -> u64 {
                0
            }
            fn shared_mapping(&self) -> Option<SharedMapping> {
                Some(self.mapping.clone())
            }
            fn begin_host_access(&self) {
                self.borrows.fetch_add(1, Ordering::Relaxed);
            }
            fn end_host_access(&self) {
                assert!(self.borrows.fetch_sub(1, Ordering::Relaxed) > 0);
            }
        }
        let path =
            std::env::temp_dir().join(format!("trames-hardware-test-{}", std::process::id()));
        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        file.set_len(16384).unwrap();
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                16384,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        let owner = Arc::new(Mapping {
            pointer: pointer as usize,
            file,
        });
        assert_eq!(owner.file.metadata().unwrap().len(), 16384);
        let page =
            unsafe { SharedPage::from_shared_mapping(pointer.cast(), 16384, 4096, owner.clone()) };
        let opaque = unsafe { SharedPage::from_mapping(pointer.cast(), owner.clone()) };
        assert!(matches!(
            unsafe { opaque.export_hardware(|_| panic!("opaque pointer moved")) },
            Err(crate::MemoryError::BackingIo(95))
        ));
        let imported = std::sync::Mutex::new(None);
        let storage = unsafe {
            page.export_hardware_with_mapping(
                |_| panic!("shared mapping copied"),
                |mapping| {
                    assert_eq!(mapping.allocation_len(), 16384);
                    assert_eq!(mapping.allocation_offset(), 4096);
                    let physical = Arc::new(Imported {
                        mapping,
                        borrows: AtomicUsize::new(0),
                    });
                    *imported.lock().unwrap() = Some(physical.clone());
                    Ok(physical)
                },
            )
        }
        .unwrap();
        drop(owner);
        page.with_write(7, 3, |bytes| bytes.copy_from_slice(b"RGB"));
        assert_eq!(
            unsafe { std::ptr::read_unaligned(storage.pointer().add(7).cast::<[u8; 3]>()) },
            *b"RGB"
        );
        page.with_read(7, 3, |bytes| {
            assert_eq!(bytes, b"RGB");
            assert_eq!(
                imported
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .borrows
                    .load(Ordering::Relaxed),
                1
            );
        });
        let again = unsafe {
            page.export_hardware_with_mapping(|_| panic!(), |_| panic!("duplicate import"))
        }
        .unwrap();
        assert!(Arc::ptr_eq(&storage, &again));
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
    fn hardware_metadata_does_not_require_read_access_or_hide_code_changes() {
        use crate::{Access, CpuMemory, Memory, MemoryError, Permissions};
        let mut memory = Memory::default();
        memory
            .map(
                0x10000,
                crate::PAGE_SIZE,
                Permissions {
                    read: false,
                    write: false,
                    execute: true,
                },
            )
            .unwrap();
        let mut registry = crate::parallel::Registry::default();
        registry.use_hardware();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert!(
            view.hardware_page_info(0x10000)
                .unwrap()
                .permissions
                .execute
        );
        assert!(matches!(
            view.check(0x10007, 1, Access::Read),
            Err(MemoryError::Permission {
                address: 0x10007,
                ..
            })
        ));
        let before = view
            .hardware_page_info(0x10000)
            .unwrap()
            .instruction_revision;
        drop(view);
        memory
            .protect(
                0x10000,
                crate::PAGE_SIZE,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        memory.write(0x10000, &[1]).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_ne!(
            view.hardware_page_info(0x10000)
                .unwrap()
                .instruction_revision,
            before
        );
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
