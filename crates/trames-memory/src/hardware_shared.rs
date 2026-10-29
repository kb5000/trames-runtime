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
    /// Publish exactly a host-written range for instruction fetch. This may
    /// run concurrently with hardware; it must not create a guest reference.
    /// Data-only storage needs no action. Guest IC/DC instructions retain the
    /// architectural guest responsibility for self-modifying code.
    fn publish_host_write(&self, _offset: usize, _len: usize) {}
    fn begin_host_access(&self);
    fn end_host_access(&self);
}

/// Stable demand-zero private RAM for one uniform anonymous extent.
///
/// # Safety
/// Every page has HardwareStorage's lifetime and borrow contract. The complete
/// initialized range remains at pointer()/physical_address() until Drop. Native
/// hardware writes are canonical immediately, even before a page wrapper exists.
/// Residency queries inspect host metadata only, never guest byte references.
pub unsafe trait HardwareRange: HardwareStorage {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn resident_bytes(&self) -> usize;
    /// Guest-page offsets whose bytes may differ from untouched zeroes, including
    /// compressed/paged-out storage. Returning every page is a safe fallback.
    /// Omitted pages must still be the original zeroes; residency alone is not
    /// sufficient, since a nonresident page can retain modified contents.
    fn populated_pages(&self) -> Vec<usize> {
        (0..self.len()).step_by(crate::PAGE_SIZE as usize).collect()
    }
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
    fn retaining_live_hardware_storage_never_borrows_its_bytes() {
        use std::sync::mpsc;
        struct Counted {
            bytes: Box<UnsafeCell<[u8; PAGE_SIZE as usize]>>,
            entries: AtomicUsize,
            active: AtomicUsize,
        }
        // SAFETY: all mock byte access follows the original page region guards;
        // metadata exports never inspect the byte allocation.
        unsafe impl Sync for Counted {}
        unsafe impl HardwareStorage for Counted {
            fn pointer(&self) -> *mut u8 {
                self.bytes.get().cast()
            }
            fn physical_address(&self) -> u64 {
                0
            }
            fn begin_host_access(&self) {
                self.entries.fetch_add(1, Ordering::Relaxed);
                self.active.fetch_add(1, Ordering::Relaxed);
            }
            fn end_host_access(&self) {
                assert!(self.active.fetch_sub(1, Ordering::Relaxed) > 0);
            }
        }
        let page = Arc::new(SharedPage::new([19; PAGE_SIZE as usize]));
        let storage = Arc::new(Counted {
            bytes: Box::new(UnsafeCell::new([19; PAGE_SIZE as usize])),
            entries: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
        });
        // SAFETY: unpublished canonical page, no native/hardware alias yet.
        unsafe { page.export_hardware(|_| Ok(storage.clone())) }.unwrap();
        for _ in 0..128 {
            // SAFETY: same canonical allocation, metadata is region-protected.
            let retained =
                unsafe { page.export_hardware(|_| panic!("duplicate allocation")) }.unwrap();
            assert_eq!(retained.pointer(), storage.pointer());
        }
        assert_eq!(storage.entries.load(Ordering::Relaxed), 0);
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let reader = page.clone();
        let reading = std::thread::spawn(move || {
            reader.with_read(0, 1, |bytes| {
                assert_eq!(bytes, [19]);
                held_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        });
        held_rx.recv().unwrap();
        assert_eq!(storage.active.load(Ordering::Relaxed), 1);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let exporter = page.clone();
        let exporting = std::thread::spawn(move || {
            entered_tx.send(()).unwrap();
            // SAFETY: only retain metadata under the same complete region mask.
            let retained =
                unsafe { exporter.export_hardware(|_| panic!("duplicate allocation")) }.unwrap();
            done_tx.send(retained.physical_address()).unwrap();
        });
        entered_rx.recv().unwrap();
        assert!(done_rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err());
        release_tx.send(()).unwrap();
        reading.join().unwrap();
        assert_eq!(done_rx.recv().unwrap(), 0);
        exporting.join().unwrap();
        assert_eq!(storage.entries.load(Ordering::Relaxed), 1);
        page.with_write(0, 1, |bytes| bytes[0] = 31);
        page.with_read(0, 1, |bytes| assert_eq!(bytes, [31]));
        assert_eq!(storage.entries.load(Ordering::Relaxed), 3);
        assert_eq!(storage.active.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn ordinary_raw_transfers_never_enter_a_hardware_byte_borrow() {
        struct NoBorrow {
            bytes: Box<UnsafeCell<[u8; PAGE_SIZE as usize]>>,
        }
        // All host operations hold the page's regions and use asm for bytes.
        unsafe impl Sync for NoBorrow {}
        unsafe impl HardwareStorage for NoBorrow {
            fn pointer(&self) -> *mut u8 {
                self.bytes.get().cast()
            }
            fn physical_address(&self) -> u64 {
                0
            }
            fn begin_host_access(&self) {
                panic!("ordinary transfer borrowed hardware bytes");
            }
            fn end_host_access(&self) {
                panic!("ordinary transfer ended a byte borrow");
            }
        }
        let storage = Arc::new(NoBorrow {
            bytes: Box::new(UnsafeCell::new([0; PAGE_SIZE as usize])),
        });
        let page = SharedPage::zero();
        unsafe {
            page.export_hardware(|_| Ok(storage.clone())).unwrap();
        }
        for offset in [0, 1, 63, 64, 4096 - 17] {
            let input = [0x39; 17];
            page.copy_write(offset, &input);
            let mut output = [0; 17];
            page.copy_read(offset, &mut output);
            assert_eq!(output, input);
        }
        let _ = page.snapshot();
        assert!(page.revision() > 0);
        // Scalar fast paths must not acquire a byte borrow for an absent
        // protected CPU alias before falling back to ordinary raw transfers.
        let mut memory = crate::Memory::default();
        memory
            .map(0x1000, PAGE_SIZE, crate::Permissions::RW)
            .unwrap();
        let frame = memory.pages[&0x1000];
        memory.frames[frame].as_mut().unwrap().bytes =
            std::rc::Rc::new(crate::mmu::PageBytes::Concurrent(Arc::new(page)));
        for word in 0..32u64 {
            memory.write_array(0x1018, word.to_le_bytes()).unwrap();
            assert_eq!(memory.read_array::<8>(0x1018).unwrap(), word.to_le_bytes());
        }
    }

    #[test]
    fn hardware_view_versions_separate_mapping_and_joined_publication() {
        use crate::{CpuMemory, Memory, Permissions};
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = crate::parallel::Registry::default();
        registry.use_hardware();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.enable_hardware();
        let original = view.hardware_view_version();
        view.write_array(0x1000, 19u64.to_le_bytes()).unwrap();
        assert_eq!(view.hardware_view_version(), original);
        drop(view);
        memory.commit_parallel().unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        let joined = view.hardware_view_version();
        assert_eq!(joined.0, original.0);
        assert_ne!(joined.1, original.1);
        drop(view);
        memory.write_array(0x1000, 23u64.to_le_bytes()).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.hardware_view_version().0, original.0);
        drop(view);
        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_ne!(view.hardware_view_version().0, original.0);
    }

    #[test]
    fn mapping_deltas_are_bounded_and_write_indices_reject_stale_membership() {
        use crate::{CpuMemory, Memory, Permissions};
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 8, Permissions::RW).unwrap();
        let mut registry = crate::parallel::Registry::default();
        registry.use_hardware();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.enable_hardware();
        view.write_array(0x1000, [1]).unwrap();
        let token = view.hardware_write_frame(0x1000).unwrap();
        let original = view.hardware_view_version().0;
        assert_eq!(view.hardware_mapping_changes(original).unwrap().count(), 0);
        drop(view);
        memory.commit_parallel().unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(
            view.hardware_mapping_changes(original)
                .unwrap()
                .collect::<Vec<_>>(),
            [0x1000]
        );
        assert!(view.mark_hardware_frame_write(token).is_err());
        drop(view);
        for round in 0..40 {
            memory
                .protect(
                    0x2000,
                    PAGE_SIZE,
                    if round % 2 == 0 {
                        Permissions::R
                    } else {
                        Permissions::RW
                    },
                )
                .unwrap();
            drop(memory.parallel_view(&mut registry).unwrap());
        }
        let view = memory.parallel_view(&mut registry).unwrap();
        assert!(
            view.hardware_mapping_changes(original).is_none(),
            "lagging consumers must reconcile fully"
        );
        drop(view);
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.enable_hardware();
        view.write_array(0x1000, [2]).unwrap();
        assert!(view.mark_hardware_frame_write(token).is_err());
        let current = view.hardware_write_frame(0x1000).unwrap();
        view.mark_hardware_frame_write(current).unwrap();
    }

    #[test]
    fn large_contiguous_vma_changes_keep_a_compact_hardware_journal() {
        use crate::{Memory, Permissions};
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = crate::parallel::Registry::default();
        registry.use_hardware();
        let view = memory.parallel_view(&mut registry).unwrap();
        let original = view.hardware_view_version().0;
        drop(view);
        let length = 8192 * PAGE_SIZE;
        memory.map(0x100000, length, Permissions::RW).unwrap();
        memory.materialize_descriptors(0x100000, length as usize);
        let view = memory.parallel_view(&mut registry).unwrap();
        let mut ranges = view.hardware_mapping_ranges(original).unwrap();
        assert_eq!(ranges.next(), Some(0x100000..0x100000 + length));
        assert!(ranges.next().is_none());
        drop(ranges);
        assert_eq!(
            view.hardware_mapping_changes(original).unwrap().count(),
            8192
        );
        drop(view);
        memory.unmap(0x100000, length).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        let ranges: Vec<_> = view.hardware_mapping_ranges(original).unwrap().collect();
        assert!(!ranges.is_empty());
        assert!(ranges
            .iter()
            .all(|range| range == &(0x100000..0x100000 + length)));
        assert_eq!(memory.resident_bytes(), 0);
    }

    #[test]
    fn private_hardware_ram_is_canonical_without_per_page_fake_dirty_writes() {
        use crate::{Memory, Permissions};
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let original = memory.revision();
        let mut registry = crate::parallel::Registry::default();
        registry.use_hardware();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.enable_hardware();
        let storage = Arc::new(Storage {
            bytes: Box::new(UnsafeCell::new([0; PAGE_SIZE as usize])),
            borrows: AtomicUsize::new(0),
        });
        unsafe {
            view.export_hardware_page(0x1000, crate::Access::Write, |_| Ok(storage.clone()))
                .unwrap();
        }
        let token = view.hardware_write_frame(0x1000).unwrap();
        assert!(!token.needs_publication());
        // Stand in for a hardware store, not a software View write.
        unsafe {
            storage.pointer().cast::<u64>().write(713);
        }
        view.mark_hardware_frame_write(token).unwrap();
        assert!(!token.needs_publication());
        drop(view);
        memory.commit_parallel().unwrap();
        assert!(memory.revision() > original);
        assert_eq!(
            memory.read_array::<8>(0x1000).unwrap(),
            713u64.to_le_bytes()
        );
        let mut child = memory.clone();
        child.write_array(0x1000, 919u64.to_le_bytes()).unwrap();
        assert_eq!(
            memory.read_array::<8>(0x1000).unwrap(),
            713u64.to_le_bytes()
        );
        assert_eq!(child.read_array::<8>(0x1000).unwrap(), 919u64.to_le_bytes());
    }

    #[test]
    fn private_hardware_code_does_not_invent_joined_instruction_changes() {
        let mut memory = crate::Memory::default();
        memory
            .map(
                0x1000,
                crate::PAGE_SIZE,
                crate::Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        let mut registry = crate::parallel::Registry::default();
        registry.use_hardware();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.enable_hardware();
        let storage = Arc::new(Storage {
            bytes: Box::new(UnsafeCell::new([0; PAGE_SIZE as usize])),
            borrows: AtomicUsize::new(0),
        });
        // SAFETY: no external actors; all execution Views use hardware mode.
        unsafe {
            view.export_hardware_page(0x1000, crate::Access::Write, |_| Ok(storage.clone()))
                .unwrap();
        }
        let original = view.hardware_page_info(0x1000).unwrap();
        let mapping = view.hardware_view_version().0;
        for _ in 0..8 {
            let token = view.hardware_write_frame(0x1000).unwrap();
            assert!(!token.needs_publication());
            view.mark_hardware_frame_write(token).unwrap();
            drop(view);
            memory.commit_parallel().unwrap();
            view = memory.parallel_view(&mut registry).unwrap();
            view.enable_hardware();
            assert_eq!(view.hardware_page_info(0x1000).unwrap(), original);
            assert_eq!(view.hardware_view_version().0, mapping);
        }
    }

    #[test]
    fn entering_hardware_mode_cannot_reuse_a_software_snapshot_token() {
        let mut memory = crate::Memory::default();
        memory
            .map(0x1000, PAGE_SIZE, crate::Permissions::RW)
            .unwrap();
        let mut registry = crate::parallel::Registry::default();
        let software = memory
            .parallel_view(&mut registry)
            .unwrap()
            .hardware_view_version()
            .0;
        registry.use_hardware();
        memory.prepare_hardware().unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_ne!(view.hardware_view_version().0, software);
        assert!(view.hardware_mapping_changes(software).is_none());
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
