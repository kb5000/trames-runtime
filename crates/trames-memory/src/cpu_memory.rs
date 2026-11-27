// SPDX-License-Identifier: GPL-3.0-or-later
//! The interpreter's checked memory contract. Both views use the same CPU engine.
use crate::{Access, Memory, MemoryError, PAGE_SIZE};
use std::sync::atomic::Ordering;

pub enum CpuSlice<'a, M> {
    Direct(&'a mut M),
    Shared(crate::SharedMemoryWrite<'a, M>),
}
impl<M> std::ops::Deref for CpuSlice<'_, M> {
    type Target = M;
    fn deref(&self) -> &M {
        match self {
            Self::Direct(m) => m,
            Self::Shared(m) => m,
        }
    }
}
impl<M> std::ops::DerefMut for CpuSlice<'_, M> {
    fn deref_mut(&mut self) -> &mut M {
        match self {
            Self::Direct(m) => m,
            Self::Shared(m) => m,
        }
    }
}

/// Existing live instruction-change counters, borrowed for one CPU entry.
/// Counter 0 uses acquire ordering (parallel code publication); counters 1/2
/// retain relaxed backing/external notifications. Mapping custody and immutable
/// address-space identity stay with the borrowed Memory/View, not these counters.
pub struct InstructionEpochs<'a>(pub [Option<&'a std::sync::atomic::AtomicU64>; 3]);

pub trait CpuMemory {
    /// Cold embedding capability: RAM and publication obey the host memory model.
    /// Unknown embeddings retain their existing abstract fence/interpreter path.
    #[cfg(feature = "native-code")]
    fn cpu_hardware_ordering(&self) -> bool {
        false
    }
    #[cfg(feature = "native-code")]
    fn cpu_acquire_chunk<T>(
        &self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        if !crate::ordered::valid(len) || len as u64 > PAGE_SIZE - address % PAGE_SIZE {
            return Err(MemoryError::InvalidRange);
        }
        let mut bytes = crate::ordered::Operand([0; 8]);
        self.read(address, &mut bytes.0[..len])?;
        std::sync::atomic::fence(Ordering::Acquire);
        Ok((operation(&bytes.0[..len]), false))
    }
    #[cfg(feature = "native-code")]
    fn cpu_release_chunk<T>(
        &mut self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        if !crate::ordered::valid(len) || len as u64 > PAGE_SIZE - address % PAGE_SIZE {
            return Err(MemoryError::InvalidRange);
        }
        self.check(address, len, Access::Write)?;
        let mut bytes = crate::ordered::Operand([0; 8]);
        let result = operation(&mut bytes.0[..len]);
        std::sync::atomic::fence(Ordering::Release);
        self.write(address, &bytes.0[..len])?;
        Ok((result, false))
    }
    /// Cold entry capability, separate from CPU instruction support. A false
    /// result keeps the existing checked lowering without inline cache probes.
    #[cfg(feature = "native-code")]
    fn cpu_native_available(&self) -> bool {
        false
    }
    /// Whether exported aliases/ownership survive further checked scalar
    /// reads/stores, further exports and metadata-only observations (including
    /// instruction identity) on this same frozen View. Never permits mapping operations,
    /// atomics, native callbacks or retaining exports beyond this CPU entry.
    #[cfg(feature = "native-code")]
    fn cpu_native_stable(&self) -> bool {
        false
    }
    /// Export an existing, resident protected alias after a successful checked
    /// access. `write` admits further stores and publishes private-page dirty
    /// and reservation metadata once for this entry, never for a read alone.
    ///
    /// # Safety
    /// All earlier exports must be discarded before ANY other CpuMemory call,
    /// except further exports, metadata-only observations and checked scalar reads/stores when
    /// cpu_native_stable() admits them.
    /// The caller may access only this guest page through the returned alias,
    /// with the admitted read/write rights until its next non-admitted call. No
    /// guest exclusive operation or native callback may overlap that interval.
    /// Never retain an export across CPU entries, mapping edits or a syscall.
    #[cfg(feature = "native-code")]
    unsafe fn cpu_native_page(&mut self, _address: u64, _write: bool) -> Option<crate::NativePage> {
        None
    }
    /// Optional cold capability for chaining derived executable code. Every
    /// instruction-identity change possible during this borrow must be covered
    /// by these counters. None keeps the ordinary per-block interpreter/cache
    /// boundary. This adds no checks to guest memory reads/writes.
    fn instruction_epochs(&self) -> Option<InstructionEpochs<'_>> {
        None
    }

    /// User-only missing faults need an execution-origin scope. Ordinary mm's
    /// do not touch thread-local origin state on each CPU/native entry.
    fn userfaults_active(&self) -> bool {
        false
    }
    /// Cold VMA observation for exception classification: whether a mapping
    /// covers or follows this address, irrespective of permissions/residency.
    /// It must not fault in bytes, allocate pages or edit mapping ownership.
    fn mapped_at_or_after(&self, address: u64) -> bool;
    /// Cold syscall import capability. Memory/View keep a monotonic summary so
    /// ordinary address spaces do not allocate asynchronous import journals.
    fn async_faults_possible(&self) -> bool {
        true
    }
    /// Optional address-specific policy metadata. Small CPU embeddings with
    /// no placement controls expose the guest default on their mapped pages.
    fn numa_mode_at(&self, _address: u64) -> u32 {
        0
    }
    /// Structural syscalls can edit the original mm only after existing CPU
    /// views have returned. A worker View declines before any side effects.
    fn mapping_owner(&mut self) -> Option<&mut Memory> {
        None
    }
    /// VMA inheritance changes require original mapping custody. A worker View
    /// declines before effects and uses the existing affected-mm transaction.
    fn range_locked(&self, _address: u64, _length: u64) -> bool {
        false
    }
    fn advise_fork(
        &mut self,
        _address: u64,
        _len: u64,
        _advice: u32,
    ) -> Option<Result<(), MemoryError>> {
        None
    }
    /// Capture original mapped writeback resources, without reading/faulting
    /// bytes. An embedding missing this capability defers before effects.
    fn prepare_sync(
        &self,
        _address: u64,
        _len: u64,
    ) -> Option<Result<crate::SyncRange, MemoryError>> {
        None
    }
    /// Read-only VMA/residency observations. Missing embedding capabilities defer
    /// before effects; neither hook may fault in bytes or allocate observed pages.
    fn validate_mapped(&self, _address: u64, _len: u64) -> Option<Result<(), MemoryError>> {
        None
    }
    fn resident(&self, _address: u64, _len: u64) -> Option<Result<Vec<u8>, MemoryError>> {
        None
    }
    /// Immutable original mm identity, independent of decoder revision wraps.
    /// This is only consulted by accepted proc reads, never ordinary accesses.
    fn proc_address_space(&self) -> Option<u64> {
        None
    }
    /// Proc image bytes accept anonymous pages (including private COW), as
    /// Linux FOLL_ANON does. None means this backend has no such capability;
    /// it must defer before exposing bytes or changing an OFD offset.
    fn proc_read_chunk(&self, _address: u64, _out: &mut [u8]) -> Option<Result<(), MemoryError>> {
        None
    }
    /// Kernel resource registration may require this mm's structural owner to
    /// stabilize/relocate pages. Ordinary byte access never queries this hook.
    fn pin_buffer_rw(
        &mut self,
        _address: u64,
        _length: usize,
    ) -> Option<Result<crate::PinnedBuffer, MemoryError>> {
        None
    }

    /// Structural replacement requires the original mapping authority, as mmap
    /// does. A worker View defers to its affected-mm checkpoint before effects.
    fn can_import_mapping(&self) -> bool {
        false
    }
    fn import_mapping(
        &mut self,
        _address: u64,
        _len: u64,
        _mapping: crate::SharedMapping,
    ) -> Result<(), MemoryError> {
        Err(MemoryError::BackingIo(95))
    }
    /// A slice-scoped local borrow; no guard survives its owned CPU outcome.
    #[inline]
    fn cpu_slice(&mut self) -> CpuSlice<'_, Self>
    where
        Self: Sized,
    {
        CpuSlice::Direct(self)
    }
    /// Bounded NUL-terminated guest bytes, read once per page fragment.
    fn read_c_string(&self, address: u64, limit: usize) -> Result<Vec<u8>, MemoryError>
    where
        Self: Sized,
    {
        c_string(self, address & 0x00ff_ffff_ffff_ffff, limit)
    }
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>;
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError>;
    fn check_translation(&self, address: u64) -> Result<(), MemoryError>;
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError>;
    fn instruction_identity(&self) -> (u64, u64, u64);
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError>;
    /// Immutable shared-backing identity for futexes. Ordinary anonymous/private
    /// memory falls back to the caller's VM + virtual address, without a fence.
    fn shared_futex_key(&self, _address: u64) -> Result<Option<(u64, u64, u64)>, MemoryError> {
        Ok(None)
    }
    fn read_array<const N: usize>(&self, address: u64) -> Result<[u8; N], MemoryError> {
        let mut bytes = [0; N];
        self.read(address, &mut bytes)?;
        Ok(bytes)
    }
    fn write_array<const N: usize>(
        &mut self,
        address: u64,
        bytes: [u8; N],
    ) -> Result<(), MemoryError> {
        self.write(address, &bytes)
    }
    /// Checked page-fragment borrow for an external/native consumer. The
    /// callback is synchronous and cannot retain guest pointers or page guards.
    /// Implementations without resident borrowing use bounded staging.
    fn cpu_read_chunk<T>(
        &self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        if len > (crate::PAGE_SIZE - address % crate::PAGE_SIZE) as usize {
            return Err(MemoryError::InvalidRange);
        }
        let mut bytes = vec![0; len];
        self.read(address, &mut bytes)?;
        Ok((operation(&bytes), false))
    }
    fn cpu_write_chunk<T>(
        &mut self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        if len > (crate::PAGE_SIZE - address % crate::PAGE_SIZE) as usize {
            return Err(MemoryError::InvalidRange);
        }
        self.check(address, len, Access::Write)?;
        let mut bytes = vec![0; len];
        self.read(address, &mut bytes)?;
        let result = operation(&mut bytes);
        self.write(address, &bytes)?;
        Ok((result, false))
    }
    /// Full-overwrite fragment: prior contents are unspecified. Unlike the
    /// read/modify/write borrow, a staging-only embedding needs no guest read
    /// permission. Production Memory/View reuse their existing write borrow.
    fn cpu_store_chunk<T>(
        &mut self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        if len > (crate::PAGE_SIZE - address % crate::PAGE_SIZE) as usize {
            return Err(MemoryError::InvalidRange);
        }
        let mut bytes = vec![0; len];
        let result = operation(&mut bytes);
        self.write(address, &bytes)?;
        Ok((result, false))
    }
    fn read_u64(&self, address: u64) -> Result<u64, MemoryError> {
        Ok(u64::from_le_bytes(self.read_array(address)?))
    }
    /// A single-copy read/modify/write, including 128-bit paired atomics.
    /// The callback reports whether a write actually happened (CAS may fail).
    fn atomic_update<T>(
        &mut self,
        address: u64,
        len: usize,
        update: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError>;
    fn exclusive_read(&mut self, address: u64, out: &mut [u8]) -> Result<u128, MemoryError>;
    fn exclusive_write(
        &mut self,
        address: u64,
        bytes: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError>;
    /// The local coordinator is quiescent; parallel views implement host fences.
    fn fence(&self, _order: Ordering) {}
}

impl CpuMemory for Memory {
    #[cfg(feature = "native-code")]
    fn cpu_hardware_ordering(&self) -> bool {
        true
    }
    #[cfg(feature = "native-code")]
    fn cpu_acquire_chunk<T>(
        &self,
        a: u64,
        n: usize,
        f: impl FnOnce(&[u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        self.with_acquire_chunk(a, n, f)
    }
    #[cfg(feature = "native-code")]
    fn cpu_release_chunk<T>(
        &mut self,
        a: u64,
        n: usize,
        f: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        self.with_release_chunk(a, n, f)
    }
    #[cfg(feature = "native-code")]
    fn cpu_native_available(&self) -> bool {
        self.shared.is_none() && !self.async_faults_possible() && !self.userfaults_active()
    }
    #[cfg(feature = "native-code")]
    unsafe fn cpu_native_page(&mut self, address: u64, write: bool) -> Option<crate::NativePage> {
        if !self.cpu_native_available() {
            return None;
        }
        let base = (address & 0x00ff_ffff_ffff_ffff) & !(PAGE_SIZE - 1);
        let entry = self.translation(base)?;
        let page = self.translated_page(entry);
        // No fork owner, concurrent/native borrower, provider, executable store,
        // unpaid zero page, userfault or software-only 16K permission group.
        if entry.cpu == 0
            || page.backing.is_some()
            || page.permissions.execute
            || !page.charge.write_ready()
            || std::sync::Arc::strong_count(&page.bytes) != 1
            || page.bytes.shared().is_some()
        {
            return None;
        }
        let read = if page.permissions.read { entry.cpu } else { 0 };
        let writable = write && page.permissions.write;
        if writable {
            let page = self.translated_page_mut(entry);
            page.data_revision = page.data_revision.wrapping_add(1);
            self.revision = self.revision.wrapping_add(1);
            self.note_parallel_write(entry.frame);
        }
        Some(crate::NativePage {
            base,
            read,
            write: if writable { entry.cpu } else { 0 },
        })
    }
    #[inline]
    fn userfaults_active(&self) -> bool {
        self.shared.as_ref().map_or_else(
            || {
                self.userfaults
                    .as_ref()
                    .is_some_and(|faults| faults.active())
            },
            |shared| shared.borrow().userfaults_active(),
        )
    }
    fn mapped_at_or_after(&self, address: u64) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow().mapped_at_or_after(address);
        }
        let address = address & 0x00ff_ffff_ffff_ffff;
        self.region_layout
            .ranges
            .last()
            .is_some_and(|&(_, end, _)| address < end)
    }
    fn async_faults_possible(&self) -> bool {
        self.account.pressure_possible()
            || crate::CgroupMemoryTarget::active()
            || self
                .shared
                .as_ref()
                .map_or(self.has_async_sources, |shared| {
                    shared.borrow().has_async_sources
                })
    }
    fn numa_mode_at(&self, address: u64) -> u32 {
        if let Some(shared) = &self.shared {
            return shared.borrow().numa_mode_at(address);
        }
        self.vma_policy.nodes.at(address)
    }
    fn mapping_owner(&mut self) -> Option<&mut Memory> {
        Some(self)
    }
    fn advise_fork(
        &mut self,
        address: u64,
        len: u64,
        advice: u32,
    ) -> Option<Result<(), MemoryError>> {
        Some(Memory::advise_fork(self, address, len, advice))
    }
    fn range_locked(&self, address: u64, length: u64) -> bool {
        self.locked_bytes_in(address, length) != 0
    }
    fn prepare_sync(
        &self,
        address: u64,
        len: u64,
    ) -> Option<Result<crate::SyncRange, MemoryError>> {
        Some(Memory::prepare_sync(self, address, len))
    }
    fn validate_mapped(&self, address: u64, len: u64) -> Option<Result<(), MemoryError>> {
        Some(Memory::validate_mapped(self, address, len))
    }
    fn resident(&self, address: u64, len: u64) -> Option<Result<Vec<u8>, MemoryError>> {
        Some(Memory::resident(self, address, len))
    }
    fn proc_address_space(&self) -> Option<u64> {
        self.shared.as_ref().map_or_else(
            || Some(self.original_identity),
            |m| m.borrow().proc_address_space(),
        )
    }
    fn proc_read_chunk(&self, address: u64, out: &mut [u8]) -> Option<Result<(), MemoryError>> {
        Some(self.read_proc_chunk(address, out))
    }
    fn pin_buffer_rw(
        &mut self,
        address: u64,
        length: usize,
    ) -> Option<Result<crate::PinnedBuffer, MemoryError>> {
        Some(Memory::pin_rw(self, address, length))
    }

    fn can_import_mapping(&self) -> bool {
        true
    }
    fn import_mapping(
        &mut self,
        address: u64,
        len: u64,
        mapping: crate::SharedMapping,
    ) -> Result<(), MemoryError> {
        self.import_mapping(address, len, mapping)
    }
    fn shared_futex_key(&self, address: u64) -> Result<Option<(u64, u64, u64)>, MemoryError> {
        Memory::shared_futex_key(self, address)
    }
    fn cpu_read_chunk<T>(
        &self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        self.with_read_chunk(address, len, operation)
    }
    fn cpu_write_chunk<T>(
        &mut self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        self.with_write_chunk(address, len, operation)
    }
    fn cpu_store_chunk<T>(
        &mut self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        self.with_store_chunk(address, len, operation)
    }
    #[inline]
    fn cpu_slice(&mut self) -> CpuSlice<'_, Self> {
        if self
            .shared
            .as_ref()
            .is_some_and(|m| m.borrow().cpu_borrow_safe)
        {
            CpuSlice::Shared(self.shared.as_ref().expect("shared space").borrow_mut())
        } else {
            CpuSlice::Direct(self)
        }
    }
    #[inline]
    fn read_c_string(&self, address: u64, limit: usize) -> Result<Vec<u8>, MemoryError> {
        Memory::read_c_string(self, address, limit)
    }
    #[inline]
    fn read(&self, a: u64, b: &mut [u8]) -> Result<(), MemoryError> {
        Memory::read(self, a, b)
    }
    #[inline]
    fn write(&mut self, a: u64, b: &[u8]) -> Result<(), MemoryError> {
        Memory::write(self, a, b)
    }
    #[inline]
    fn check(&self, a: u64, n: usize, x: Access) -> Result<(), MemoryError> {
        Memory::check(self, a, n, x)
    }
    #[inline]
    fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
        Memory::check_translation(self, a)
    }
    #[inline]
    fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
        Memory::fetch_u32(self, a)
    }
    #[inline]
    fn instruction_identity(&self) -> (u64, u64, u64) {
        Memory::instruction_identity(self)
    }
    fn instruction_epochs(&self) -> Option<InstructionEpochs<'_>> {
        if self.shared.is_some() {
            return None;
        }
        Some(InstructionEpochs([
            self.parallel_cache
                .as_ref()
                .and_then(|cache| cache.instruction_epoch()),
            self.has_backings.then(crate::backing::revision_epoch),
            self.has_external_code.then(crate::backing::external_epoch),
        ]))
    }

    #[inline]
    fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
        Memory::instruction_page_identity(self, a)
    }
    #[inline]
    fn read_array<const N: usize>(&self, a: u64) -> Result<[u8; N], MemoryError> {
        Memory::read_array(self, a)
    }
    #[inline]
    fn write_array<const N: usize>(&mut self, a: u64, b: [u8; N]) -> Result<(), MemoryError> {
        Memory::write_array(self, a, b)
    }
    fn atomic_update<T>(
        &mut self,
        a: u64,
        n: usize,
        f: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().atomic_update(a, n, f);
        }
        let a = a & 0x00ffffffffffffff;
        self.check(a, n, Access::Write)?;
        self.check(a, n, Access::Read)?;
        if n == 0 || n > 16 {
            return Err(MemoryError::InvalidRange);
        }
        self.prepare_mmu_write(a, n)?;
        let page = self.page_for_access(a, n, Access::Write)?;
        if let Some(storage) = page.shared_write_storage() {
            let offset = (a % crate::PAGE_SIZE) as usize;
            let backing = page
                .backing
                .as_ref()
                .filter(|b| b.shared)
                .map(|b| b.object.clone());
            let mut guard = storage.lock(offset, n);
            let (value, write) = f(guard.write(offset, n));
            if write {
                storage.changed(&mut guard, offset, n);
                drop(guard);
                if let Some(backing) = backing {
                    backing.publish_write(offset, n)?;
                }
                let frame = self
                    .frame(a & !(crate::PAGE_SIZE - 1))
                    .expect("checked atomic");
                self.mark_native_write(frame);
            }
            return Ok(value);
        }
        let mut bytes = [0; 16];
        if n > bytes.len() {
            return Err(MemoryError::InvalidRange);
        }
        self.read(a, &mut bytes[..n])?;
        let (result, write) = f(&mut bytes[..n]);
        if write {
            self.write(a, &bytes[..n])?;
        }
        Ok(result)
    }
    fn exclusive_read(&mut self, a: u64, b: &mut [u8]) -> Result<u128, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().exclusive_read(a, b);
        }
        let a = a & 0x00ffffffffffffff;
        self.check(a, b.len(), Access::Read)?;
        self.materialize_descriptors(a, b.len());
        let page = self.page_for_access(a, b.len(), Access::Read)?;
        if page
            .backing
            .as_ref()
            .is_none_or(|b| !b.shared && (b.private_copy || page.permissions.write))
            && (page.bytes.shared().is_none() || std::sync::Arc::strong_count(&page.bytes) > 1)
        {
            // Give serial LL/SC the same 16-byte reservation domain as workers.
            // A global memory revision makes a compiler's unrelated stack spill
            // between LDAXR/STLXR fail every retry. Only atomic pages are promoted;
            // non-atomic pages acquire no new monitor bookkeeping.
            let base = a & !(crate::PAGE_SIZE - 1);
            let frame = self.frame(base).expect("checked exclusive page");
            let page = self.frames[frame].as_mut().unwrap();
            // Private file reads may borrow the page cache; an exclusive store
            // must instead reserve private COW bytes, never the file's bytes.
            page.detach_private()?;
            let old = std::mem::replace(
                &mut page.bytes,
                std::sync::Arc::new(crate::mmu::PageBytes::Zero),
            );
            let mut owned = std::sync::Arc::try_unwrap(old).unwrap_or_else(|old| {
                if page.charge.resident() {
                    (*old).clone()
                } else {
                    crate::mmu::PageBytes::Zero
                }
            });
            if owned.is_zero() {
                if let Some(bytes) = self.mmu.page(base) {
                    owned = std::sync::Arc::try_unwrap(bytes)
                        .unwrap_or_else(|_| unreachable!("fresh MMU page"));
                }
            }
            let storage = std::sync::Arc::new(crate::SharedPage::from_owned(owned, None));
            self.frames[frame].as_mut().unwrap().bytes =
                std::sync::Arc::new(crate::mmu::PageBytes::Concurrent(storage));
            if self.parallel_cache.is_some() {
                self.parallel_mappings.insert(base);
            }
            self.revision = self.revision.wrapping_add(1);
            self.invalidate_translations();
        }
        let page = self.page_for_access(a, b.len(), Access::Read)?;
        if let Some(storage) = page.shared_storage() {
            let offset = (a % crate::PAGE_SIZE) as usize;
            let guard = storage.lock(offset, b.len());
            b.copy_from_slice(guard.read(offset, b.len()));
            return Ok((storage.identity as u128) << 64 | guard.reservation(offset / 16) as u128);
        }
        self.read(a, b)?;
        Ok(self.revision() as u128)
    }
    fn exclusive_write(
        &mut self,
        a: u64,
        b: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().exclusive_write(a, b, token);
        }
        let a = a & 0x00ffffffffffffff;
        if token.is_none() {
            return Ok(false);
        }
        self.check(a, b.len(), Access::Write)?;
        self.prepare_mmu_write(a, b.len())?;
        let page = self.page_for_access(a, b.len(), Access::Write)?;
        if let Some(storage) = page.shared_write_storage() {
            let offset = (a % crate::PAGE_SIZE) as usize;
            let backing = page
                .backing
                .as_ref()
                .filter(|b| b.shared)
                .map(|b| b.object.clone());
            let mut guard = storage.lock(offset, b.len());
            if token
                != Some((storage.identity as u128) << 64 | guard.reservation(offset / 16) as u128)
            {
                return Ok(false);
            }
            guard.write(offset, b.len()).copy_from_slice(b);
            storage.changed(&mut guard, offset, b.len());
            drop(guard);
            if let Some(backing) = backing {
                backing.publish_write(offset, b.len())?;
            }
            let frame = self
                .frame(a & !(crate::PAGE_SIZE - 1))
                .expect("checked exclusive");
            self.mark_native_write(frame);
            return Ok(true);
        }
        if token != Some(self.revision() as u128) {
            return Ok(false);
        }
        self.write(a, b)?;
        Ok(true)
    }
    fn fence(&self, order: Ordering) {
        std::sync::atomic::fence(order);
    }
}

/// Shared string scan; callers apply guest address tagging once.
pub(crate) fn c_string(
    memory: &impl CpuMemory,
    address: u64,
    limit: usize,
) -> Result<Vec<u8>, MemoryError> {
    let mut bytes = Vec::new();
    while bytes.len() < limit {
        let current = address
            .checked_add(bytes.len() as u64)
            .ok_or(MemoryError::InvalidRange)?;
        let offset = (current & (PAGE_SIZE - 1)) as usize;
        let length = (limit - bytes.len()).min(PAGE_SIZE as usize - offset);
        // Borrow resident bytes directly. Live backings retain the scoped
        // snapshot and EOF checks; only the returned owned string allocates.
        let (terminated, _) = memory.cpu_read_chunk(current, length, |part| {
            let end = part.iter().position(|&byte| byte == 0);
            bytes.extend_from_slice(&part[..end.unwrap_or(part.len())]);
            end.is_some()
        })?;
        if terminated {
            return Ok(bytes);
        }
    }
    Err(MemoryError::Limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PageBacking, Permissions, PAGE_SIZE};
    use std::sync::{Arc, Weak};
    #[test]
    fn external_chunks_share_worker_reservations_permissions_and_dirty_publication() {
        let mut memory = Memory::default();
        memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x1000, 7u64.to_le_bytes()).unwrap();
        memory.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let mut old = [0; 8];
        let token = view.exclusive_read(0x1000, &mut old).unwrap();
        assert!(
            view.cpu_write_chunk(0x1000, 8, |b| b.copy_from_slice(&9u64.to_le_bytes()))
                .unwrap()
                .1
        );
        assert!(!view.exclusive_write(0x1000, &[3; 8], Some(token)).unwrap());
        assert_eq!(
            view.cpu_read_chunk(0x1000, 8, |b| b.to_vec()).unwrap(),
            (9u64.to_le_bytes().to_vec(), true)
        );
        assert!(view
            .cpu_write_chunk(0x2000, 1, |_| panic!("read-only callback"))
            .is_err());
        assert!(view
            .cpu_read_chunk(0x1fff, 2, |_| panic!("cross-page callback"))
            .is_err());
        drop(view);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<8>(0x1000).unwrap(), 9u64.to_le_bytes());
    }

    #[test]
    fn serial_reservations_track_granules_aba_native_writes_and_fork_cow() {
        let base = 0x40000;
        let mut memory = Memory::default();
        memory.map(base, 65536, Permissions::RW).unwrap();
        memory.write_array(base, 1u64.to_le_bytes()).unwrap();
        let mut old = [0; 8];
        let token = memory.exclusive_read(base, &mut old).unwrap();
        memory.write_array(base + 16, [7; 8]).unwrap();
        assert!(memory
            .exclusive_write(base, &2u64.to_le_bytes(), Some(token))
            .unwrap());
        let token = memory.exclusive_read(base, &mut old).unwrap();
        memory.write_array(base + 8, [8; 8]).unwrap();
        memory.write_array(base + 8, [0; 8]).unwrap();
        assert!(!memory.exclusive_write(base, &[3; 8], Some(token)).unwrap());
        let token = memory.exclusive_read(base, &mut old).unwrap();
        memory.with_write_chunk(base, 8, |b| b.fill(5)).unwrap();
        assert!(!memory.exclusive_write(base, &[3; 8], Some(token)).unwrap());
        let mut child = memory.clone();
        let mut stored = false;
        for _ in 0..3 {
            let token = child.exclusive_read(base, &mut old).unwrap();
            stored = child.exclusive_write(base, &[9; 8], Some(token)).unwrap();
            if stored {
                break;
            }
        }
        assert!(stored);
        assert_eq!(child.read_array::<8>(base), Ok([9; 8]));
        assert_eq!(memory.read_array::<8>(base), Ok([5; 8]));
        let token = memory.exclusive_read(base, &mut old).unwrap();
        memory.unmap(base, PAGE_SIZE).unwrap();
        memory.map(base, PAGE_SIZE, Permissions::RW).unwrap();
        assert!(!memory.exclusive_write(base, &[3; 8], Some(token)).unwrap());
    }

    #[test]
    fn serial_exclusive_zero_load_preserves_demand_zero_accounting_and_cpu_alias() {
        let base = 0x40000;
        let mut memory = Memory::default();
        memory.map(base, 65536, Permissions::RW).unwrap();
        let mut old = [0; 8];
        let token = memory.exclusive_read(base, &mut old).unwrap();
        assert_eq!(old, [0; 8]);
        assert_eq!(memory.resident_bytes(), 0);
        assert!(memory.exclusive_write(base, &[7; 8], Some(token)).unwrap());
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(memory.read_array::<8>(base), Ok([7; 8]));
        memory.write_array(base, [9; 8]).unwrap();
        assert_eq!(memory.read_array::<8>(base), Ok([9; 8]));
    }

    #[test]
    fn trusted_backings_borrow_once_and_unknown_read_callbacks_can_reenter() {
        let mut memory = Memory::default();
        memory
            .map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        let mut peer = memory.share();
        {
            let mut slice = peer.cpu_slice();
            assert!(matches!(slice, CpuSlice::Shared(_)));
            slice.write(0x1000, &[7; 8]).unwrap();
            assert_eq!(slice.read_array::<8>(0x1000).unwrap(), [7; 8]);
        }
        // Slice scope is finished before any coordinator or native callback.
        memory.write(0x1000, &[8; 8]).unwrap();

        struct Reentrant {
            owner: Weak<crate::root::Root<Memory>>,
        }
        impl PageBacking for Reentrant {
            fn check(&self, _: u64) -> Result<(), MemoryError> {
                assert!(
                    self.owner.upgrade().unwrap().borrow().mapped_bytes() >= PAGE_SIZE as usize
                );
                Ok(())
            }
            fn read(&self, _: usize, out: &mut [u8]) -> Result<(), MemoryError> {
                assert!(
                    self.owner.upgrade().unwrap().borrow().mapped_bytes() >= PAGE_SIZE as usize
                );
                out.fill(9);
                Ok(())
            }
            fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
                Err(MemoryError::BackingIo(13))
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn version(&self) -> u64 {
                0
            }
            fn writable(&self) -> bool {
                false
            }
            fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
                Err(MemoryError::InvalidRange)
            }
        }
        let object = Arc::new(Reentrant {
            owner: Arc::downgrade(memory.shared.as_ref().unwrap()),
        });
        memory
            .map_backed(0x3000, vec![object], false, Permissions::R, false)
            .unwrap();
        let slice = peer.cpu_slice();
        assert!(matches!(slice, CpuSlice::Direct(_)));
        assert_eq!(slice.read_array::<8>(0x3000).unwrap(), [9; 8]);
    }
}
