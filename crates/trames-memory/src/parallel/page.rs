// SPDX-License-Identifier: GPL-3.0-or-later
//! Audited bytes: region locks, or proven exclusive/immutable epoch ownership.
use crate::PAGE_SIZE;
use std::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    sync::OnceLock,
};

const REGION: usize = 64;
const PAGE: usize = PAGE_SIZE as usize;
static ZERO: [u8; PAGE] = [0; PAGE];

/// Byte cells are never exposed without a matching, live range guard. The Box
/// stays at one allocation for the lifetime of every guard and borrowed slice.
enum Bytes {
    Hardware(std::sync::Arc<dyn crate::HardwareStorage>),
    Heap(Box<[UnsafeCell<u8>; PAGE]>),
    Zero(OnceLock<Box<[UnsafeCell<u8>; PAGE]>>),
    External {
        pointer: usize,
        _owner: std::sync::Arc<dyn Send + Sync>,
        mapping: Option<(usize, usize)>,
    },
    Mapped {
        owner: std::sync::Arc<crate::mmu::host::Mapping>,
        offset: usize,
        _lease: Option<std::sync::Arc<crate::mmu::Slot>>,
    },
}
impl Bytes {
    fn write_ptr(&self, unmaterialized: &AtomicBool) -> *mut u8 {
        if let Self::Zero(bytes) = self {
            bytes
                .get_or_init(|| {
                    unmaterialized.store(false, Ordering::Relaxed);
                    Box::new(std::array::from_fn(|_| UnsafeCell::new(0)))
                })
                .as_ptr()
                .cast::<u8>()
                .cast_mut()
        } else {
            self.as_ptr().cast::<u8>().cast_mut()
        }
    }
    fn as_ptr(&self) -> *const UnsafeCell<u8> {
        match self {
            Self::Hardware(storage) => storage.pointer().cast(),
            Self::Heap(bytes) => bytes.as_ptr(),
            Self::Zero(bytes) => bytes
                .get()
                .map_or(ZERO.as_ptr().cast(), |bytes| bytes.as_ptr()),
            Self::External { pointer, .. } => *pointer as *const UnsafeCell<u8>,
            Self::Mapped { owner, offset, .. } => {
                owner.kernel.as_ptr().wrapping_add(*offset).cast()
            }
        }
    }
}
pub struct MutablePage {
    external_revision: Option<std::sync::Arc<AtomicU64>>,
    pub(crate) identity: u64,
    pub(crate) version: AtomicU64,
    bytes: UnsafeCell<Bytes>,
    held: AtomicU64,
    unmaterialized: AtomicBool,
    #[cfg(test)]
    acquisitions: AtomicU64,
    reservations: OnceLock<Box<ReservationRows>>,
    reservation_base: AtomicU64,
    reservation_written: AtomicU64,
}
struct ReservationRows {
    values: [UnsafeCell<[u64; 4]>; PAGE / REGION],
    overrides: [UnsafeCell<u8>; PAGE / REGION],
}
// SAFETY: rows are published once, then every row/override uses the same byte
// ownership as MutablePage. Allocating a table never grants byte access.
unsafe impl Sync for ReservationRows {}
// SAFETY: all non-atomic byte accesses are inside a guard for their complete
// region mask, or unsafe admission proves exclusive/immutable private ownership.
// Overlapping locked masks are mutually exclusive; disjoint slices cannot alias.
// Immutable epochs have shared byte references and no byte/row invalidators;
// first monitor initialization is published by OnceLock. Each reservation
// row/override byte otherwise uses the same exclusive byte ownership;
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
    // Storage changes only under all region bits, before hardware publication;
    // ordinary access holds its regions, and hardware storage never moves again.
    fn storage(&self) -> &Bytes {
        // SAFETY: callers hold region ownership (metadata or bytes), or the
        // cold physical-export contract. Hardware actors never modify Bytes.
        unsafe { &*self.bytes.get() }
    }
    /// Retain a previously exported owner without touching guest bytes, paging
    /// in a source or revoking hardware access. Cold translation reuse only.
    pub(crate) fn retained_hardware(&self) -> Option<std::sync::Arc<dyn crate::HardwareStorage>> {
        let _regions = self.lock_regions(u64::MAX);
        match self.storage() {
            Bytes::Hardware(storage) if storage.is_live() => Some(storage.clone()),
            _ => None,
        }
    }
    /// Export canonical storage once; all future host borrows revoke hardware
    /// access through its granule gate. External GPU pointers are not movable.
    ///
    /// # Safety
    /// No physical/native MMU alias or unpublished accessor may survive this
    /// operation. Every other byte actor uses this page's region guards.
    pub unsafe fn export_hardware(
        &self,
        allocate: impl FnOnce(
            Option<&[u8]>,
        )
            -> Result<std::sync::Arc<dyn crate::HardwareStorage>, crate::MemoryError>,
    ) -> Result<std::sync::Arc<dyn crate::HardwareStorage>, crate::MemoryError> {
        // SAFETY: inherited cold export contract; opaque external mappings stay refused.
        unsafe {
            self.export_hardware_with_mapping(allocate, |_| Err(crate::MemoryError::BackingIo(95)))
        }
    }
    /// Export explicit file mappings through the same region and host-borrow gate.
    ///
    /// # Safety
    /// Same as export_hardware. The importer must retain and alias the supplied
    /// mapping; external raw display readers retain protocol frame leases and
    /// must never turn concurrently writable bytes into Rust references.
    pub unsafe fn export_hardware_with_mapping(
        &self,
        allocate: impl FnOnce(
            Option<&[u8]>,
        )
            -> Result<std::sync::Arc<dyn crate::HardwareStorage>, crate::MemoryError>,
        import: impl FnOnce(
            crate::SharedMapping,
        )
            -> Result<std::sync::Arc<dyn crate::HardwareStorage>, crate::MemoryError>,
    ) -> Result<std::sync::Arc<dyn crate::HardwareStorage>, crate::MemoryError> {
        // Holding the region mask stabilizes the storage enum/owner. Keeping
        // an existing handle does not read guest bytes or create a byte reference.
        let regions = self.lock_regions(u64::MAX);
        if let Bytes::Hardware(storage) = self.storage() {
            if storage.is_live() {
                return Ok(storage.clone());
            }
        }
        // Cold export/rebinding may inspect or copy bytes. Enter exactly the
        // original host-access gate before forming any byte reference.
        let mut guard = regions.into_bytes();
        if let Bytes::Hardware(storage) = self.storage() {
            // The former VM is gone permanently. End its host-only gate before
            // moving the bytes into a new VM; the full region lock stays held.
            storage.end_host_access();
            guard.page = guard.page.map_addr(|at| at & !3);
        }
        let mapping = match self.storage() {
            Bytes::External {
                pointer,
                _owner,
                mapping: Some((base, length)),
            } => Some(crate::SharedMapping {
                external_revision: self.external_revision.clone(),
                base: *base,
                length: *length,
                offset: pointer - base,
                _owner: _owner.clone(),
            }),
            Bytes::External { mapping: None, .. } => return Err(crate::MemoryError::BackingIo(95)),
            Bytes::Hardware(storage) => storage.shared_mapping(),
            _ => None,
        };
        let storage = if let Some(mapping) = mapping {
            let pointer = mapping.pointer();
            let storage = import(mapping)?;
            assert_eq!(
                storage.pointer(),
                pointer,
                "shared hardware import must preserve byte identity"
            );
            storage
        } else {
            allocate(
                if matches!(self.storage(), Bytes::Zero(bytes) if bytes.get().is_none()) {
                    None
                } else {
                    Some(guard.read(0, PAGE))
                },
            )?
        };
        assert!(!storage.pointer().is_null());
        // SAFETY: the full byte lock excludes all readers/writers; the caller
        // has retired cached aliases. No reference to the old Bytes survives.
        self.unmaterialized.store(false, Ordering::Relaxed);
        unsafe {
            *self.bytes.get() = Bytes::Hardware(storage.clone());
        }
        Ok(storage)
    }

    /// Retain an externally mapped page in the CPU byte domain.
    ///
    /// # Safety
    /// `pointer` denotes a complete initialized RW page owned by `owner` until
    /// its drop. All CPU references/accesses use this SharedPage's guards;
    /// external raw GPU access follows the display protocol's buffer ownership.
    pub unsafe fn from_mapping(pointer: *mut u8, owner: impl Send + Sync + 'static) -> Self {
        assert!(!pointer.is_null());
        Self::with_storage(Bytes::External {
            pointer: pointer as usize,
            _owner: std::sync::Arc::new(owner),
            mapping: None,
        })
    }
    /// Retain a complete host resource mapping with explicit allocation geometry.
    ///
    /// # Safety
    /// The allocation is initialized RW storage retained by owner; offset
    /// covers one guest page. CPU accesses use this page's guards. External raw
    /// display/GPU actors obey their API dependencies and create no Rust byte refs.
    pub unsafe fn from_shared_mapping(
        base: *mut u8,
        length: usize,
        offset: usize,
        owner: impl Send + Sync + 'static,
    ) -> Self {
        assert!(!base.is_null());
        assert!(offset.checked_add(PAGE).is_some_and(|end| end <= length));
        Self::with_storage(Bytes::External {
            pointer: base as usize + offset,
            _owner: std::sync::Arc::new(owner),
            mapping: Some((base as usize, length)),
        })
    }
    /// # Safety
    /// Same initialized-storage and foreign-access contract as from_shared_mapping.
    pub unsafe fn from_resource_mapping(mapping: crate::SharedMapping) -> Self {
        let revision = mapping.external_revision.clone();
        let mut page = unsafe {
            Self::from_shared_mapping(
                mapping.allocation_pointer(),
                mapping.allocation_len(),
                mapping.allocation_offset(),
                mapping,
            )
        };
        page.external_revision = revision;
        page
    }
    /// Move a coordinator allocation into the shared byte domain without copying.
    pub fn from_box(bytes: Box<[u8; PAGE]>) -> Self {
        // SAFETY: UnsafeCell<u8> is transparent, with the same allocation layout.
        // Ownership is transferred; no reference to the old Box survives.
        let bytes = unsafe { Box::from_raw(Box::into_raw(bytes).cast::<[UnsafeCell<u8>; PAGE]>()) };
        Self::with_storage(Bytes::Heap(bytes))
    }
    pub(crate) fn from_hardware(storage: std::sync::Arc<dyn crate::HardwareStorage>) -> Self {
        Self::with_storage(Bytes::Hardware(storage))
    }
    pub(crate) fn from_owned(
        bytes: crate::mmu::PageBytes,
        slot: Option<std::sync::Arc<crate::mmu::Slot>>,
    ) -> Self {
        match bytes {
            crate::mmu::PageBytes::Zero => Self::new_zero(slot),
            crate::mmu::PageBytes::Heap(bytes) => Self::from_box(bytes),
            crate::mmu::PageBytes::Mapped {
                owner,
                offset,
                _lease,
            } => Self::with_storage(Bytes::Mapped {
                owner,
                offset,
                _lease,
            }),
            crate::mmu::PageBytes::Concurrent(_) => unreachable!("already shared"),
        }
    }
    /// Scoped access, using the very same region guard as CPU/native workers.
    pub fn with_read<T>(&self, offset: usize, len: usize, f: impl FnOnce(&[u8]) -> T) -> T {
        let guard = self.lock(offset, len);
        f(guard.read(offset, len))
    }
    pub fn with_write<T>(&self, offset: usize, len: usize, f: impl FnOnce(&mut [u8]) -> T) -> T {
        let mut guard = self.lock(offset, len);
        self.changed(&mut guard, offset, len);
        f(guard.write(offset, len))
    }
    /// Read an allocation before its first publication to concurrent actors.
    ///
    /// # Safety
    /// The caller owns all byte accesses until the callback ends. No concurrent
    /// accessor or exclusive monitor may exist. Publication must invalidate any
    /// cached unpublished capability before another actor can access the page.
    #[inline]
    pub unsafe fn with_unpublished_read<T>(
        &self,
        offset: usize,
        len: usize,
        f: impl FnOnce(&[u8]) -> T,
    ) -> T {
        assert!(offset <= PAGE && len <= PAGE - offset);
        // SAFETY: complete bounded allocation, caller-owned unpublished bytes;
        // this callback is the entire lifetime of the exclusive byte borrow.
        f(unsafe {
            std::slice::from_raw_parts(self.storage().as_ptr().cast::<u8>().add(offset), len)
        })
    }
    /// Write under the unpublished ownership contract above. The provider must
    /// maintain its own byte/version/dirty hooks, as for its original heap page.
    ///
    /// # Safety
    /// Same as with_unpublished_read, with exclusive writable byte ownership.
    #[inline]
    pub unsafe fn with_unpublished_write<T>(
        &self,
        offset: usize,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> T,
    ) -> T {
        assert!(offset <= PAGE && len <= PAGE - offset);
        // SAFETY: no external actor/monitor exists. UnsafeCell permits this
        // bounded mutation, and no slice survives the synchronous callback.
        f(unsafe {
            std::slice::from_raw_parts_mut(
                self.storage().write_ptr(&self.unmaterialized).add(offset),
                len,
            )
        })
    }
    /// Whether this logical zero page still has no allocated byte storage.
    pub fn unmaterialized_zero(&self) -> bool {
        self.unmaterialized.load(Ordering::Relaxed)
    }

    pub(crate) fn changed(&self, guard: &mut Guard<'_>, offset: usize, len: usize) {
        let version = self.version.fetch_add(1, Ordering::Release).wrapping_add(1);
        guard.invalidate(offset, len, version);
    }
    pub fn revision(&self) -> u64 {
        self.version.load(Ordering::Acquire).wrapping_add(
            self.external_revision
                .as_ref()
                .map_or(0, |v| v.load(Ordering::Relaxed)),
        )
    }
    pub(crate) fn has_external_revision(&self) -> bool {
        self.external_revision.is_some()
    }
    pub(crate) fn snapshot(&self) -> [u8; PAGE] {
        let mut bytes = [0; PAGE];
        self.copy_read(0, &mut bytes);
        bytes
    }
    /// Ordinary guest transfer: no reference into potentially concurrent RAM.
    pub fn copy_read(&self, offset: usize, out: &mut [u8]) {
        self.raw_lock(offset, out.len()).read_into(offset, out);
    }
    pub fn copy_write(&self, offset: usize, bytes: &[u8]) {
        let mut raw = self.raw_lock(offset, bytes.len());
        self.changed(&mut raw.ownership, offset, bytes.len());
        raw.write_from(offset, bytes);
    }
    pub(crate) fn raw_lock(&self, offset: usize, len: usize) -> RawGuard<'_> {
        let regions = self.lock_regions(mask(offset, len));
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        let ownership = Guard {
            page: std::ptr::from_ref(regions.page),
            mask: regions.mask,
            _owner: std::marker::PhantomData,
        };
        // Unsupported raw-copy architectures retain the original exclusion.
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let ownership = Guard::new(regions.page, regions.mask, 0);
        std::mem::forget(regions);
        RawGuard { ownership }
    }
    /// A shared logical zero page stays unallocated until its first write.
    pub fn zero() -> Self {
        Self::with_storage(Bytes::Zero(OnceLock::new()))
    }
    pub fn new(bytes: [u8; PAGE]) -> Self {
        Self::with_storage(Bytes::Heap(Box::new(bytes.map(UnsafeCell::new))))
    }
    fn with_storage(bytes: Bytes) -> Self {
        let unmaterialized = matches!(&bytes, Bytes::Zero(storage) if storage.get().is_none());
        Self {
            external_revision: None,
            unmaterialized: AtomicBool::new(unmaterialized),
            bytes: UnsafeCell::new(bytes),
            identity: crate::new_backing_identity(),
            version: AtomicU64::new(0),
            held: AtomicU64::new(0),
            #[cfg(test)]
            acquisitions: AtomicU64::new(0),
            reservations: OnceLock::new(),
            reservation_base: AtomicU64::new(0),
            reservation_written: AtomicU64::new(0),
        }
    }
    pub(super) fn new_mapped(bytes: [u8; PAGE], slot: std::sync::Arc<crate::mmu::Slot>) -> Self {
        slot.initialize(&bytes);
        Self::with_storage(Bytes::Mapped {
            owner: slot.owner.clone(),
            offset: slot.offset,
            _lease: Some(slot),
        })
    }
    pub(super) fn new_zero(slot: Option<std::sync::Arc<crate::mmu::Slot>>) -> Self {
        if let Some(slot) = slot {
            slot.initialize_zero();
            Self::with_storage(Bytes::Mapped {
                owner: slot.owner.clone(),
                offset: slot.offset,
                _lease: Some(slot),
            })
        } else {
            Self::zero()
        }
    }
    pub(crate) fn physical(&self) -> Option<(&std::sync::Arc<crate::mmu::host::Mapping>, usize)> {
        match self.storage() {
            Bytes::Mapped { owner, offset, .. } => Some((owner, *offset)),
            _ => None,
        }
    }
    pub(crate) fn lock(&self, offset: usize, len: usize) -> Guard<'_> {
        self.lock_mask(mask(offset, len))
    }
    /// # Safety
    /// The caller owns these private byte ranges and monitor metadata until the
    /// guard and derived slices end: either one exclusive actor, or read-only
    /// actors with no byte/monitor writers (OnceLock initialization is allowed).
    /// Read-only ownership never grants mutable access through this guard.
    pub(crate) unsafe fn unlocked(&self, offset: usize, len: usize, readonly: bool) -> Guard<'_> {
        Guard::new(self, mask(offset, len), if readonly { 2 } else { 1 })
    }
    /// # Safety
    /// Same ownership contract as unlocked(), for the union of both ranges.
    pub(crate) unsafe fn unlocked_pair(
        &self,
        a: usize,
        b: usize,
        len: usize,
        readonly: bool,
    ) -> Guard<'_> {
        Guard::new(
            self,
            mask(a, len) | mask(b, len),
            if readonly { 2 } else { 1 },
        )
    }
    pub(crate) fn lock_pair(&self, a: usize, b: usize, len: usize) -> Guard<'_> {
        self.lock_mask(mask(a, len) | mask(b, len))
    }
    #[cfg(test)]
    pub(super) fn acquisitions(&self) -> u64 {
        self.acquisitions.load(Ordering::Relaxed)
    }
    fn lock_mask(&self, mask: u64) -> Guard<'_> {
        self.lock_regions(mask).into_bytes()
    }
    fn lock_regions(&self, mask: u64) -> Regions<'_> {
        let mut attempts = 0;
        loop {
            if self
                .held
                .try_update(Ordering::Acquire, Ordering::Relaxed, |held| {
                    (held & mask == 0).then_some(held | mask)
                })
                .is_ok()
            {
                #[cfg(test)]
                self.acquisitions.fetch_add(1, Ordering::Relaxed);
                return Regions { page: self, mask };
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

// Metadata ownership only: no byte accessor or raw byte pointer is exposed.
// The existing region mask excludes storage replacement; hardware may still
// access the stable allocation's bytes. Conversion transfers the same mask to
// a byte Guard after beginning its original hardware host-access gate.
struct Regions<'a> {
    page: &'a MutablePage,
    mask: u64,
}
impl<'a> Regions<'a> {
    fn into_bytes(self) -> Guard<'a> {
        let guard = Guard::new(self.page, self.mask, 0);
        std::mem::forget(self);
        guard
    }
}
impl Drop for Regions<'_> {
    fn drop(&mut self) {
        self.page.held.fetch_and(!self.mask, Ordering::Release);
    }
}

/// A region/lifetime capability with no guest slice accessor. Its embedded
/// guard is used only for monitor metadata and unlocking, never read()/write().
/// Hardware and raw asm may race with ordinary ARM semantics. Existing host
/// slice callbacks still acquire these regions AND their hardware gate.
pub(crate) struct RawGuard<'a> {
    pub(super) ownership: Guard<'a>,
}
impl RawGuard<'_> {
    pub fn read_into(&self, offset: usize, out: &mut [u8]) {
        self.ownership.covers(offset, out.len());
        let page = self.ownership.page();
        // SAFETY: region ownership stabilizes storage/its allocation and
        // excludes host references. asm permits concurrent hardware bytes.
        unsafe {
            crate::raw::copy(
                page.storage().as_ptr().cast::<u8>().add(offset),
                out.as_mut_ptr(),
                out.len(),
            );
        }
    }
    pub fn write_from(&mut self, offset: usize, input: &[u8]) {
        self.ownership.covers(offset, input.len());
        let page = self.ownership.page();
        unsafe {
            crate::raw::copy(
                input.as_ptr(),
                page.storage().write_ptr(&page.unmaterialized).add(offset),
                input.len(),
            );
        }
        if let Bytes::Hardware(storage) = page.storage() {
            storage.publish_host_write(offset, input.len());
        }
    }
}

// The mode occupies two unused aligned pointer bits, keeping this hot return
// value at two words on supported 64-bit hosts. map_addr preserves provenance;
// no tagged pointer is dereferenced or exposed outside this scoped guard.
const _: () = assert!(std::mem::align_of::<MutablePage>() >= 4);
pub(crate) struct Guard<'a> {
    page: *const MutablePage,
    mask: u64,
    _owner: std::marker::PhantomData<&'a MutablePage>,
}
impl<'a> Guard<'a> {
    fn new(page: &'a MutablePage, mask: u64, mut mode: usize) -> Self {
        if mode == 0 {
            if let Bytes::Hardware(storage) = page.storage() {
                storage.begin_host_access();
                mode = 3;
            }
        }
        Self {
            page: std::ptr::from_ref(page).map_addr(|at| at | mode),
            mask,
            _owner: std::marker::PhantomData,
        }
    }
    #[inline]
    fn page(&self) -> &'a MutablePage {
        // SAFETY: constructed from a live, aligned page with its provenance and
        // lifetime retained. Clearing only our low tags restores that pointer.
        unsafe { &*self.page.map_addr(|at| at & !3) }
    }
    pub(crate) fn is_exclusive(&self) -> bool {
        self.page.addr() & 3 == 1
    }
    fn is_readonly(&self) -> bool {
        self.page.addr() & 3 == 2
    }
    fn is_locked(&self) -> bool {
        matches!(self.page.addr() & 3, 0 | 3)
    }
    fn covers(&self, offset: usize, len: usize) {
        assert_eq!(mask(offset, len) & !self.mask, 0, "unguarded byte range");
    }
    pub fn read(&self, offset: usize, len: usize) -> &[u8] {
        self.covers(offset, len);
        // SAFETY: UnsafeCell is transparent over u8; bounds and ownership of
        // every touched region were checked. The reference ends before unlock.
        unsafe {
            std::slice::from_raw_parts(self.page().storage().as_ptr().cast::<u8>().add(offset), len)
        }
    }
    pub fn write(&mut self, offset: usize, len: usize) -> &mut [u8] {
        debug_assert!(!self.is_readonly(), "read-only guard cannot grant mutation");
        self.covers(offset, len);
        // SAFETY: the live exclusive region mask excludes every overlapping
        // reader/writer. &mut self also excludes another slice from this guard.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.page()
                    .storage()
                    .write_ptr(&self.page().unmaterialized)
                    .add(offset),
                len,
            )
        }
    }
    pub fn copy_within(&mut self, source: usize, destination: usize, len: usize) {
        debug_assert!(!self.is_readonly(), "read-only guard cannot grant mutation");
        self.covers(source, len);
        self.covers(destination, len);
        // SAFETY: both ranges are protected by this single guard; ptr::copy
        // permits overlap. No byte reference is alive across this mutable call.
        unsafe {
            let ptr = self.page().storage().write_ptr(&self.page().unmaterialized);
            std::ptr::copy(ptr.add(source), ptr.add(destination), len);
        }
    }
    pub fn reservation(&self, slot: usize) -> u64 {
        self.covers(slot * 16, 16);
        let external = self
            .page()
            .external_revision
            .as_ref()
            .map_or(0, |v| v.load(Ordering::Relaxed));
        let rows = self.page().reservations.get_or_init(|| {
            self.page().reservation_base.store(
                self.page().version.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            Box::new(ReservationRows {
                values: std::array::from_fn(|_| UnsafeCell::new([0; 4])),
                overrides: std::array::from_fn(|_| UnsafeCell::new(0)),
            })
        });
        let region = slot / 4;
        if self.page().reservation_written.load(Ordering::Relaxed) & (1 << region) == 0 {
            return self
                .page()
                .reservation_base
                .load(Ordering::Relaxed)
                .wrapping_add(external);
        }
        // SAFETY: this region's ownership also protects its reservation row and
        // override byte. Immutable epochs have no invalidators; OnceLock above
        // publishes initialization to all readers. No mutable reference survives
        // a locked/exclusive epoch boundary.
        let (values, overrides) =
            unsafe { (&*rows.values[region].get(), *rows.overrides[region].get()) };
        let local = slot % 4;
        values[if local == 0 || overrides & (1 << local) != 0 {
            local
        } else {
            0
        }]
        .wrapping_add(external)
    }
    pub fn invalidate(&mut self, offset: usize, len: usize, version: u64) {
        debug_assert!(
            !self.is_readonly(),
            "read-only guard cannot change monitors"
        );
        self.covers(offset, len);
        if len == 0 {
            return;
        }
        // Before the first exclusive read there is no monitor to invalidate.
        // A writer that observes no table still holds its region guard: an
        // overlapping reader can only create/capture a monitor after unlock.
        // Disjoint initialization/readers do not monitor this writer's region.
        let Some(rows) = self.page().reservations.get() else {
            return;
        };
        if offset == 0 && len == PAGE {
            self.page()
                .reservation_base
                .store(version, Ordering::Relaxed);
            self.page().reservation_written.store(0, Ordering::Relaxed);
        } else {
            let active = self.page().reservation_written.load(Ordering::Relaxed);
            let base = self.page().reservation_base.load(Ordering::Relaxed);
            let mut added = 0;
            for region in offset / REGION..=(offset + len - 1) / REGION {
                // SAFETY: covers() ensures exclusive ownership of every touched
                // region. Different guards only access disjoint metadata rows.
                let (values, overrides) = unsafe {
                    (
                        &mut *rows.values[region].get(),
                        &mut *rows.overrides[region].get(),
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
                if self.is_exclusive() {
                    self.page()
                        .reservation_written
                        .store(active | added, Ordering::Relaxed);
                } else {
                    self.page()
                        .reservation_written
                        .fetch_or(added, Ordering::Relaxed);
                }
            }
        }
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.page.addr() & 3 == 3 {
            if let Bytes::Hardware(storage) = self.page().storage() {
                // Scoped callbacks can write or unwind; conservatively publish
                // this page before restoring hardware, never the whole image.
                storage.publish_host_write(0, PAGE);
                storage.end_host_access();
            }
        }
        if self.is_locked() {
            self.page().held.fetch_and(!self.mask, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unpublished_bytes_keep_one_allocation_and_switch_to_guarded_publication() {
        let page = MutablePage::zero();
        assert!(page.unmaterialized_zero());
        // SAFETY: this test owns the only page and has not exported a handle.
        unsafe { page.with_unpublished_write(7, 4, |b| b.copy_from_slice(b"warm")) };
        assert!(!page.unmaterialized_zero());
        // SAFETY: still the sole unpublished actor, with no active monitors.
        let pointer = unsafe { page.with_unpublished_read(7, 4, |b| b.as_ptr() as usize) };
        assert_eq!(page.acquisitions(), 0);
        assert_eq!(page.revision(), 0);
        let page = std::sync::Arc::new(page);
        let worker = page.clone();
        std::thread::spawn(move || {
            worker.with_write(7, 4, |b| b.copy_from_slice(b"live"));
        })
        .join()
        .unwrap();
        page.with_read(7, 4, |b| {
            assert_eq!(b, b"live");
            assert_eq!(b.as_ptr() as usize, pointer);
        });
        assert!(page.acquisitions() > 0);
        assert!(page.revision() > 0);
    }
    #[test]
    fn readonly_guard_keeps_region_ownership_and_the_compact_layout() {
        let page = MutablePage::new([37; PAGE]);
        let held = page.lock(0, REGION);
        let before = page.held.load(Ordering::Relaxed);
        // SAFETY: this scope only reads bytes; even the overlapping held guard
        // remains read-only. No byte/monitor invalidation can run concurrently.
        let read = unsafe { page.unlocked_pair(0, 32, 8, true) };
        assert_eq!(read.read(0, 8), read.read(32, 8));
        assert!(!read.is_exclusive());
        assert!(read.is_readonly());
        assert_eq!(std::mem::size_of_val(&read), 16);
        drop(read);
        assert_eq!(page.held.load(Ordering::Relaxed), before);
        drop(held);
        assert_eq!(page.held.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn software_zero_pages_allocate_only_on_first_write() {
        let page = MutablePage::zero();
        page.with_read(0, PAGE, |bytes| assert!(bytes.iter().all(|&b| b == 0)));
        assert!(matches!(page.storage(), Bytes::Zero(bytes) if bytes.get().is_none()));
        page.with_write(64, 8, |bytes| bytes.fill(42));
        page.with_read(0, PAGE, |bytes| {
            assert_eq!(&bytes[64..72], &[42; 8]);
            assert!(bytes[..64].iter().chain(&bytes[72..]).all(|&b| b == 0));
        });
        assert!(matches!(page.storage(), Bytes::Zero(bytes) if bytes.get().is_some()));
    }
    #[test]
    fn ordinary_writes_need_no_exclusive_table_and_late_monitors_observe_aba() {
        let page = MutablePage::new([0; PAGE]);
        {
            let mut guard = page.lock(0, PAGE);
            guard.write(0, 8).copy_from_slice(&17u64.to_le_bytes());
            guard.invalidate(0, 8, 1);
        }
        assert!(page.reservations.get().is_none());
        let token = page.lock(0, 16).reservation(0);
        assert!(page.reservations.get().is_some());
        {
            let mut peer = page.lock(64, 16);
            peer.invalidate(64, 8, 2);
        }
        assert_eq!(page.lock(0, 16).reservation(0), token);
        {
            let mut writer = page.lock(0, 16);
            writer.invalidate(0, 8, 3);
            writer.invalidate(0, 8, 4);
        }
        assert_ne!(page.lock(0, 16).reservation(0), token);
    }
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
