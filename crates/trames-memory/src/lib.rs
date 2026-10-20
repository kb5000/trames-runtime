// SPDX-License-Identifier: GPL-3.0-or-later
//! Sparse, bounded guest address spaces. Guest addresses are never host pointers.
mod backing;
mod cpu_memory;
mod mmu;
use mmu::PageBytes;
mod native_access;
pub mod parallel;
pub use parallel::page::MutablePage as SharedPage;
mod reservations;
mod residency;
use backing::Backed;
pub use backing::{backing_changed, PageBacking};
pub use cpu_memory::{CpuMemory, CpuSlice};
pub use native_access::{NativeAccessError, NativeMemory, Transfer};
pub use reservations::MAX_RESERVATIONS;
use residency::{Account, Charge};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

pub const PAGE_SIZE: u64 = 4096;
pub const ADDRESS_LIMIT: u64 = 1 << 48;
pub const DEFAULT_MEMORY_LIMIT: usize = 512 * 1024 * 1024;
static NEXT_SPACE: AtomicU64 = AtomicU64::new(1);
static NEXT_BACKING: AtomicU64 = AtomicU64::new(1);
/// Opaque identity shared by aliases of one backing page, never a host pointer.
pub fn new_backing_identity() -> u64 {
    NEXT_BACKING.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Permissions {
    pub const NONE: Self = Self {
        read: false,
        write: false,
        execute: false,
    };
    pub const RW: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    pub const RX: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
    pub const R: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    fn allows(self, access: Access) -> bool {
        match access {
            Access::Read => self.read,
            Access::Write => self.write,
            Access::Execute => self.execute,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryError {
    InvalidRange,
    AddressRange(u64),
    Alignment(u64),
    UnalignedMapping,
    Overlap(u64),
    Limit,
    Unmapped(u64),
    Bus(u64),
    BackingIo(u32),
    Permission { address: u64, access: Access },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "guest memory: {self:?}")
    }
}
impl std::error::Error for MemoryError {}

#[derive(Clone)]
struct Page {
    // Rc counts coordinator/fork owners only; worker Arc handles refer to the
    // same SharedPage without causing false COW. The Rc and backing providers
    // stay !Send/!Sync; every shared byte borrow uses the common region guards.
    bytes: Rc<PageBytes>,
    charge: std::sync::Arc<Charge>,
    permissions: Permissions,
    instruction_revision: u64,
    backing: Option<Backed>,
    mapping: u64,
    data_revision: u64,
    parallel_dirty: bool,
}

const TRANSLATION_SLOTS: usize = 256;
/// Single-level direct-mapped page TLB: guest tag, stable frame ID, and an
/// optional hardware-protected CPU page address. Local mapping/COW mutations
/// invalidate entries before alias retirement; worker snapshots are immutable.
#[derive(Clone, Copy, Debug)]
struct Translation {
    tag: u64,
    frame: usize,
    cpu: usize,
}
impl Translation {
    const VALID: u64 = 16;
    const BACKED: u64 = 8;
    const RESIDENT: u64 = 32;
    const EMPTY: Self = Self {
        tag: 0,
        frame: 0,
        cpu: 0,
    };
    fn new(base: u64, frame: usize, permissions: Permissions, backed: bool, cpu: usize) -> Self {
        debug_assert!(base < ADDRESS_LIMIT && base.is_multiple_of(PAGE_SIZE));
        Self {
            tag: base
                | Self::VALID
                | u64::from(permissions.read)
                | (u64::from(permissions.write) << 1)
                | (u64::from(permissions.execute) << 2)
                | if backed { Self::BACKED } else { 0 },
            frame,
            cpu,
        }
    }
    #[inline]
    fn matches(self, base: u64, access_bit: u64) -> bool {
        self.tag & (!(PAGE_SIZE - 1) | access_bit) == base | access_bit
    }
    #[inline]
    fn access_bit(access: Access) -> u64 {
        match access {
            Access::Read => 1,
            Access::Write => 2,
            Access::Execute => 4,
        }
    }
    #[inline]
    fn slot(base: u64) -> usize {
        (base / PAGE_SIZE) as usize & (TRANSLATION_SLOTS - 1)
    }
    /// # Safety
    /// This entry is from the caller's live TLB, and offset..offset+N is inside
    /// its guest page. Worker callers hold the same physical byte-region guard.
    #[inline(always)]
    unsafe fn read<const N: usize>(self, offset: usize) -> Option<[u8; N]> {
        let mut bytes = [0; N];
        if self.cpu != 0
            && self.tag & Self::RESIDENT != 0
            && unsafe {
                mmu::access::access::<N>(
                    false,
                    self.cpu.wrapping_add(offset) as *mut u8,
                    bytes.as_mut_ptr(),
                )
            }
        {
            Some(bytes)
        } else {
            None
        }
    }
    /// # Safety
    /// Same lifetime/range contract as read, with exclusive region ownership.
    #[inline(always)]
    unsafe fn write<const N: usize>(self, offset: usize, mut bytes: [u8; N]) -> bool {
        self.cpu != 0
            && self.tag & (4 | Self::RESIDENT) == Self::RESIDENT
            && unsafe {
                mmu::access::access::<N>(
                    true,
                    self.cpu.wrapping_add(offset) as *mut u8,
                    bytes.as_mut_ptr(),
                )
            }
    }
}

pub struct Memory {
    mmu: mmu::Arena,
    // Ordered mappings serve mmap and procfs; stable frame indices serve the
    // interpreter. The translation cache owns no bytes, so it cannot trigger
    // false COW or retain an old allocation after a write.
    pages: BTreeMap<u64, usize>,
    // Anonymous PROT_NONE ranges own virtual addresses, without resident pages.
    reservations: BTreeMap<u64, u64>,
    frames: Vec<Option<Page>>,
    free_frames: Vec<usize>,
    translations: [Cell<Translation>; TRANSLATION_SLOTS],
    limit: usize,
    account: std::sync::Arc<Account>,
    revision: u64,
    code_revision: u64,
    identity: u64,
    shared: Option<Rc<RefCell<Memory>>>,
    has_backings: bool,
    cpu_borrow_safe: bool,
    parallel_cache: Option<parallel::SnapshotCache>,
    fork_epoch: Cell<u64>,
    parallel_users: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    parallel_dirty: Vec<usize>,
    parallel_mappings: BTreeSet<u64>,
    parallel_reservations_dirty: bool,
}
impl Clone for Memory {
    fn clone(&self) -> Self {
        // fork always takes a COW snapshot, including when its parent has threads.
        if let Some(shared) = &self.shared {
            return shared.borrow().clone();
        }
        self.invalidate_translations();
        self.mmu.retire();
        self.fork_epoch.set(self.fork_epoch.get().wrapping_add(1));
        let account = self.fork_account();
        Self {
            mmu: mmu::Arena::default(),
            pages: self.pages.clone(),
            reservations: self.reservations.clone(),
            frames: self
                .frames
                .iter()
                .map(|page| {
                    page.as_ref().map(|page| {
                        let mut page = page.clone();
                        if self.has_parallel_users() && page.bytes.shared().is_some() {
                            page.bytes = Rc::new(if page.charge.resident() {
                                (*page.bytes).clone()
                            } else {
                                PageBytes::Zero
                            });
                        }
                        let charge = Charge::new(&account);
                        if page.charge.resident() {
                            charge.ensure().expect("fork admitted by can_fork");
                        }
                        page.charge = charge;
                        page.parallel_dirty = false;
                        page
                    })
                })
                .collect(),
            free_frames: self.free_frames.clone(),
            translations: std::array::from_fn(|_| Cell::new(Translation::EMPTY)),
            limit: self.limit,
            account,
            revision: self.revision,
            code_revision: self.code_revision,
            identity: NEXT_SPACE.fetch_add(1, Ordering::Relaxed),
            shared: None,
            has_backings: self.has_backings,
            cpu_borrow_safe: self.cpu_borrow_safe,
            parallel_cache: None,
            fork_epoch: Cell::new(0),
            parallel_users: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            parallel_dirty: Vec::new(),
            parallel_mappings: BTreeSet::new(),
            parallel_reservations_dirty: false,
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new(DEFAULT_MEMORY_LIMIT)
    }
}

impl Memory {
    /// CLONE_VM shares mappings, protections, bytes and the decoder revision.
    /// The inner address space remains private. A local CPU slice may borrow it
    /// once; no guard crosses a scheduler turn or native/host callback.
    pub fn share(&mut self) -> Self {
        if self.shared.is_none() {
            let owned = std::mem::replace(self, Self::new(self.limit));
            self.shared = Some(Rc::new(RefCell::new(owned)));
        }
        Self {
            shared: self.shared.clone(),
            ..Self::new(self.limit)
        }
    }
    pub fn limit(&self) -> usize {
        self.shared
            .as_ref()
            .map_or(self.limit, |shared| shared.borrow().limit())
    }
    pub fn set_limit(&mut self, limit: usize) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().set_limit(limit);
        }
        if self.mapped_bytes() > limit {
            return Err(MemoryError::Limit);
        }
        self.limit = limit;
        self.update_resident_limit(limit);
        Ok(())
    }
    pub fn new(limit: usize) -> Self {
        Self {
            mmu: mmu::Arena::default(),
            pages: BTreeMap::new(),
            reservations: BTreeMap::new(),
            frames: Vec::new(),
            free_frames: Vec::new(),
            translations: std::array::from_fn(|_| Cell::new(Translation::EMPTY)),
            limit,
            account: Account::new(limit),
            revision: 0,
            code_revision: 0,
            identity: NEXT_SPACE.fetch_add(1, Ordering::Relaxed),
            shared: None,
            has_backings: false,
            cpu_borrow_safe: true,
            parallel_cache: None,
            fork_epoch: Cell::new(0),
            parallel_users: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            parallel_dirty: Vec::new(),
            parallel_mappings: BTreeSet::new(),
            parallel_reservations_dirty: false,
        }
    }
    pub fn mapped_bytes(&self) -> usize {
        if let Some(shared) = &self.shared {
            return shared.borrow().mapped_bytes();
        }
        self.pages.len() * PAGE_SIZE as usize
    }

    /// Contiguous guest mappings for procfs; no native address is exposed.
    pub fn regions(&self) -> Vec<(u64, u64, Permissions)> {
        if let Some(shared) = &self.shared {
            return shared.borrow().regions();
        }
        let mut regions: Vec<(u64, u64, Permissions)> = Vec::new();
        for (&address, &frame) in &self.pages {
            let page = self.frames[frame].as_ref().expect("mapped frame");
            if let Some(last) = regions.last_mut() {
                if last.1 == address && last.2 == page.permissions {
                    last.1 += PAGE_SIZE;
                    continue;
                }
            }
            regions.push((address, address + PAGE_SIZE, page.permissions));
        }
        regions.extend(
            self.reservations
                .iter()
                .map(|(&start, &end)| (start, end, Permissions::NONE)),
        );
        regions.sort_unstable_by_key(|region| region.0);
        regions
    }

    fn invalidate_translations(&self) {
        for entry in &self.translations {
            entry.set(Translation::EMPTY);
        }
    }

    #[inline]
    fn frame(&self, base: u64) -> Option<usize> {
        self.translation(base).map(|entry| entry.frame)
    }

    #[inline]
    fn translation(&self, base: u64) -> Option<Translation> {
        let entry = self.translations[Translation::slot(base)].get();
        if entry.matches(base, Translation::VALID) {
            return Some(entry);
        }
        self.fill_translation(base)
    }

    #[cold]
    #[inline(never)]
    fn fill_translation(&self, base: u64) -> Option<Translation> {
        let frame = *self.pages.get(&base)?;
        let page = self.frames[frame].as_ref().expect("mapped frame");
        let mut entry = Translation::new(
            base,
            frame,
            page.permissions,
            page.backing.is_some(),
            self.mmu.page_alias(base),
        );
        if page.charge.resident() {
            entry.tag |= Translation::RESIDENT;
        }
        self.translations[Translation::slot(base)].set(entry);
        Some(entry)
    }

    #[inline]
    fn access_translation(
        &self,
        address: u64,
        len: usize,
        access: Access,
    ) -> Result<Translation, MemoryError> {
        let base = address & !(PAGE_SIZE - 1);
        let entry = self.translations[Translation::slot(base)].get();
        // A matching mapped page proves the 48-bit range. Callers normally
        // already established the single-page bound, allowing LLVM to fold it.
        if len <= (PAGE_SIZE - (address & (PAGE_SIZE - 1))) as usize
            && entry.matches(base, Translation::access_bit(access))
        {
            return Ok(entry);
        }
        self.access_translation_slow(address, len, access)
    }

    #[cold]
    #[inline(never)]
    fn access_translation_slow(
        &self,
        address: u64,
        len: usize,
        access: Access,
    ) -> Result<Translation, MemoryError> {
        Self::end(address, len as u64)?;
        let entry = self
            .translation(address & !(PAGE_SIZE - 1))
            .ok_or_else(|| self.missing_page(address, access))?;
        if entry.tag & Translation::access_bit(access) == 0 {
            return Err(MemoryError::Permission { address, access });
        }
        Ok(entry)
    }

    #[inline]
    fn translated_page(&self, entry: Translation) -> &Page {
        // SAFETY: entries are filled only from pages -> live slab slots. Every
        // mapping mutation flushes translations before another access, and no
        // callback/mutation occurs between translation and dereference. This
        // local Memory is !Send/!Sync; no worker can edit its page table.
        debug_assert!(self.frames.get(entry.frame).is_some_and(Option::is_some));
        unsafe {
            self.frames
                .get_unchecked(entry.frame)
                .as_ref()
                .unwrap_unchecked()
        }
    }

    #[inline]
    fn translated_page_mut(&mut self, entry: Translation) -> &mut Page {
        // SAFETY: same live-slot invariant as translated_page, with exclusive
        // access to this coordinator Memory. The entry owns no byte allocation.
        debug_assert!(self.frames.get(entry.frame).is_some_and(Option::is_some));
        unsafe {
            self.frames
                .get_unchecked_mut(entry.frame)
                .as_mut()
                .unwrap_unchecked()
        }
    }

    fn insert_page(&mut self, base: u64, permissions: Permissions) {
        if self.parallel_cache.is_some() {
            self.parallel_mappings.insert(base);
        }
        let page = Page {
            bytes: Rc::new(PageBytes::Zero),
            charge: Charge::new(&self.account),
            permissions,
            instruction_revision: self.code_revision,
            backing: None,
            mapping: self.code_revision,
            data_revision: 0,
            parallel_dirty: false,
        };
        if let Some(&frame) = self.pages.get(&base) {
            self.frames[frame] = Some(page);
        } else {
            let frame = if let Some(frame) = self.free_frames.pop() {
                self.frames[frame] = Some(page);
                frame
            } else {
                self.frames.push(Some(page));
                self.frames.len() - 1
            };
            self.pages.insert(base, frame);
        }
    }

    pub fn highest_mapped_end(&self) -> u64 {
        if let Some(shared) = &self.shared {
            return shared.borrow().highest_mapped_end();
        }
        self.pages
            .last_key_value()
            .map_or(0, |(&address, _)| address + PAGE_SIZE)
            .max(
                self.reservations
                    .last_key_value()
                    .map_or(0, |(_, &end)| end),
            )
    }
    pub fn revision(&self) -> u64 {
        if let Some(shared) = &self.shared {
            return shared.borrow().revision();
        }
        self.revision.wrapping_add(if self.has_backings {
            backing::backing_revision()
        } else {
            0
        })
    }
    /// Decode-cache epoch: data stores preserve checked executable blocks.
    /// Mapping/protection changes and writes into executable pages invalidate.
    pub fn instruction_revision(&self) -> u64 {
        if let Some(shared) = &self.shared {
            return shared.borrow().instruction_revision();
        }
        self.code_revision
    }
    /// A decoder must also distinguish independent spaces with equal epochs.
    pub fn instruction_identity(&self) -> (u64, u64, u64) {
        if let Some(shared) = &self.shared {
            return shared.borrow().instruction_identity();
        }
        (
            self.identity,
            self.code_revision,
            (if self.has_backings {
                backing::backing_revision()
            } else {
                0u64
            })
            .wrapping_add(self.parallel_cache.as_ref().map_or(0, |c| c.code_epoch())),
        )
    }

    /// Checked identity of the reached executable page. Unrelated mappings and
    /// code writes keep this token, while replacement/protection changes do not.
    pub fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        if !address.is_multiple_of(4) {
            return Err(MemoryError::Alignment(address));
        }
        if let Some(shared) = &self.shared {
            return shared.borrow().instruction_page_identity(address);
        }
        let page = self.page_for_access(address, 4, Access::Execute)?;
        Ok((
            self.identity,
            page.instruction_revision,
            page.backing
                .as_ref()
                .filter(|b| b.shared || !b.private_copy)
                .map_or(0, |b| b.object.version())
                .wrapping_add(page.bytes.shared().map_or(0, |bytes| bytes.revision())),
        ))
    }

    fn advance_code_revision(&mut self) {
        self.code_revision = self.code_revision.wrapping_add(1);
        if self.code_revision == 0 {
            // Repeated page tokens after wrap must belong to a new space key.
            self.identity = NEXT_SPACE.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn is_free(&self, address: u64, len: u64) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow().is_free(address, len);
        }
        Self::mapping_end(address, len).is_ok_and(|end| {
            self.pages.range(address..end).next().is_none()
                && !self.reservation_overlaps(address, end)
        })
    }
    pub fn find_free(&self, start: u64, len: u64) -> Option<u64> {
        if let Some(shared) = &self.shared {
            return shared.borrow().find_free(start, len);
        }
        let mut candidate = start.checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
        if let Some(stop) = self.reserved_end(candidate) {
            candidate = stop;
        }
        let mut pages = self
            .pages
            .range(candidate..)
            .map(|(&a, _)| (a, a + PAGE_SIZE))
            .peekable();
        let mut reserved = self
            .reservations
            .range(candidate..)
            .map(|(&a, &b)| (a, b))
            .peekable();
        loop {
            let next = match (pages.peek(), reserved.peek()) {
                (Some(a), Some(b)) if a.0 < b.0 => pages.next(),
                (_, Some(_)) => reserved.next(),
                (Some(_), None) => pages.next(),
                (None, None) => return Self::mapping_end(candidate, len).ok().map(|_| candidate),
            };
            let (base, stop) = next.expect("occupied range");
            if base >= Self::mapping_end(candidate, len).ok()? {
                return Some(candidate);
            }
            candidate = candidate.max(stop);
        }
    }
    /// Atomic anonymous MAP_FIXED: account for replaced pages before changing data.
    pub fn map_fixed(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().map_fixed(address, len, permissions);
        }
        let end = Self::mapping_end(address, len)?;
        let replaced = self.pages.range(address..end).count() * PAGE_SIZE as usize;
        let size = usize::try_from(len).map_err(|_| MemoryError::Limit)?;
        if self
            .mapped_bytes()
            .saturating_sub(replaced)
            .checked_add(size)
            .is_none_or(|n| n > self.limit)
        {
            return Err(MemoryError::Limit);
        }
        self.remove_reservations(address, end)?;
        self.advance_code_revision();
        for base in (address..end).step_by(PAGE_SIZE as usize) {
            self.insert_page(base, permissions);
        }
        self.revision = self.revision.wrapping_add(1);
        self.refresh_mapping_mmu(address, len);
        self.invalidate_translations();
        Ok(())
    }

    /// Linux munmap permits holes; validate the range before removing mapped pages.
    pub fn unmap(&mut self, address: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().unmap(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        self.remove_reservations(address, end)?;
        let keys: Vec<_> = self
            .pages
            .range(address..end)
            .map(|(&base, _)| base)
            .collect();
        for base in keys {
            if self.parallel_cache.is_some() {
                self.parallel_mappings.insert(base);
            }
            let frame = self.pages.remove(&base).expect("mapped frame");
            self.frames[frame] = None;
            self.free_frames.push(frame);
        }
        self.revision = self.revision.wrapping_add(1);
        self.advance_code_revision();
        self.refresh_mapping_mmu(address, len);
        self.invalidate_translations();
        Ok(())
    }

    /// Read a bounded NUL-terminated byte string, without UTF-8 assumptions.
    pub fn read_c_string(&self, address: u64, limit: usize) -> Result<Vec<u8>, MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow().read_c_string(address, limit);
        }
        let mut bytes = Vec::new();
        while bytes.len() < limit {
            let current = address
                .checked_add(bytes.len() as u64)
                .ok_or(MemoryError::InvalidRange)?;
            let offset = (current & (PAGE_SIZE - 1)) as usize;
            let length = (limit - bytes.len()).min(PAGE_SIZE as usize - offset);
            // Borrow resident bytes directly. Live backings retain the scoped
            // snapshot and EOF checks; only the returned owned string allocates.
            let (terminated, _) = self.with_read_chunk(current, length, |part| {
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

    fn end(address: u64, len: u64) -> Result<u64, MemoryError> {
        let end = address
            .checked_add(len)
            .ok_or(MemoryError::AddressRange(address))?;
        if address >= ADDRESS_LIMIT || end > ADDRESS_LIMIT {
            return Err(MemoryError::AddressRange(address));
        }
        Ok(end)
    }

    fn mapping_end(address: u64, len: u64) -> Result<u64, MemoryError> {
        if len == 0 || !address.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE) {
            return Err(MemoryError::UnalignedMapping);
        }
        Self::end(address, len)
    }

    /// Validate the entire operation before changing any page.
    pub fn map(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().map(address, len, permissions);
        }
        let end = Self::mapping_end(address, len)?;
        let len = usize::try_from(len).map_err(|_| MemoryError::Limit)?;
        if self
            .mapped_bytes()
            .checked_add(len)
            .ok_or(MemoryError::Limit)?
            > self.limit
        {
            return Err(MemoryError::Limit);
        }
        if let Some((&base, _)) = self.pages.range(address..end).next() {
            return Err(MemoryError::Overlap(base));
        }
        if self.reservation_overlaps(address, end) {
            return Err(MemoryError::Overlap(address));
        }
        self.advance_code_revision();
        for base in (address..end).step_by(PAGE_SIZE as usize) {
            self.insert_page(base, permissions);
        }
        self.revision = self.revision.wrapping_add(1);
        self.refresh_mapping_mmu(address, len as u64);
        self.invalidate_translations();
        Ok(())
    }

    pub fn protect(
        &mut self,
        address: u64,
        len: u64,
        permissions: Permissions,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().protect(address, len, permissions);
        }
        let end = Self::mapping_end(address, len)?;
        self.check_mapped_range(address, end)?;
        let committed = self.pages.range(address..end).count() as u64 * PAGE_SIZE;
        let commit = permissions != Permissions::NONE;
        if commit
            && (end - address - committed) > self.limit.saturating_sub(self.mapped_bytes()) as u64
        {
            return Err(MemoryError::Limit);
        }
        for (&base, &frame) in self.pages.range(address..end) {
            let p = self.frames[frame].as_ref().expect("page");
            if permissions.execute && p.backing.as_ref().is_some_and(|b| !b.object.executable()) {
                return Err(MemoryError::Permission {
                    address: base,
                    access: Access::Execute,
                });
            }
            if permissions.write
                && p.backing
                    .as_ref()
                    .is_some_and(|b| b.shared && !b.object.writable())
            {
                return Err(MemoryError::Permission {
                    address: base,
                    access: Access::Write,
                });
            }
        }
        if commit {
            self.remove_reservations(address, end)?;
        }
        self.advance_code_revision();
        if commit {
            for base in (address..end).step_by(PAGE_SIZE as usize) {
                if !self.pages.contains_key(&base) {
                    self.insert_page(base, permissions);
                }
            }
        }
        for (&base, &frame) in self.pages.range(address..end) {
            if self.parallel_cache.is_some() {
                self.parallel_mappings.insert(base);
            }
            let page = self.frames[frame].as_mut().expect("validated page");
            page.permissions = permissions;
            page.instruction_revision = self.code_revision;
        }
        self.revision = self.revision.wrapping_add(1);
        self.refresh_mapping_mmu(address, len);
        self.invalidate_translations();
        Ok(())
    }

    /// Cache maintenance translates a virtual address without doing a data read.
    pub fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow().check_translation(address);
        }
        Self::end(address, 1)?;
        if self.pages.contains_key(&(address & !(PAGE_SIZE - 1)))
            || self.reserved_end(address).is_some()
        {
            Ok(())
        } else {
            Err(MemoryError::Unmapped(address))
        }
    }

    pub fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        let address = if access == Access::Execute {
            address
        } else {
            address & 0x00ffffffffffffff
        };
        if let Some(shared) = &self.shared {
            return shared.borrow().check(address, len, access);
        }
        self.checked_pages(address, len, access, |_| true)
            .map(|_| ())
    }

    /// Validate every page once, retaining the first precise fault, while
    /// collecting native admission facts. The caller handles tagged/shared VMs.
    fn checked_pages(
        &self,
        address: u64,
        len: usize,
        access: Access,
        mut eligible: impl FnMut(&Page) -> bool,
    ) -> Result<bool, MemoryError> {
        if len == 0 {
            return Ok(true);
        }
        let end = Self::end(address, len as u64)?;
        let first = address & !(PAGE_SIZE - 1);
        let mut allowed = true;
        for base in (first..end).step_by(PAGE_SIZE as usize) {
            let fault_address = base.max(address);
            let frame = self
                .frame(base)
                .ok_or_else(|| self.missing_page(fault_address, access))?;
            let page = self.frames[frame].as_ref().expect("mapped frame");
            if !page.permissions.allows(access) {
                return Err(MemoryError::Permission {
                    address: fault_address,
                    access,
                });
            }
            page.check_backing(fault_address)?;
            // Kernel/native output preflight must reserve capacity before a
            // read consumes a queue or advances an open-file description.
            if access == Access::Write {
                page.charge.ensure()?;
            }
            allowed &= eligible(page);
        }
        Ok(allowed)
    }

    fn copy_read(&self, mut address: u64, mut out: &mut [u8]) -> Result<(), MemoryError> {
        while !out.is_empty() {
            let base = address & !(PAGE_SIZE - 1);
            let offset = (address - base) as usize;
            let len = out.len().min(PAGE_SIZE as usize - offset);
            let frame = self.frame(base).expect("validated page");
            self.frames[frame]
                .as_ref()
                .expect("mapped frame")
                .read_bytes(offset, &mut out[..len])?;
            address += len as u64;
            out = &mut out[len..];
        }
        Ok(())
    }

    // Callers handle shared memory and ensure the range fits within one page.
    #[inline]
    fn page_for_access(
        &self,
        address: u64,
        len: usize,
        access: Access,
    ) -> Result<&Page, MemoryError> {
        let entry = self.access_translation(address, len, access)?;
        let page = self.translated_page(entry);
        if entry.tag & Translation::BACKED != 0 {
            page.check_backing(address)?;
        }
        Ok(page)
    }

    pub fn read(&self, address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow().read(address, out);
        }
        if out.is_empty() {
            return Ok(());
        }
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if out.len() <= PAGE_SIZE as usize - offset {
            let page = self.page_for_access(address, out.len(), Access::Read)?;
            page.read_bytes(offset, out)?;
            return Ok(());
        }
        self.check(address, out.len(), Access::Read)?;
        self.copy_read(address, out)?;
        Ok(())
    }

    pub fn write(&mut self, mut address: u64, mut input: &[u8]) -> Result<(), MemoryError> {
        address &= 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().write(address, input);
        }
        if input.is_empty() {
            return Ok(());
        }
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if input.len() <= PAGE_SIZE as usize - offset {
            let entry = self.access_translation(address, input.len(), Access::Write)?;
            let frame = entry.frame;
            self.prepare_mmu_write(address, input.len())?;
            let next_code_revision = self.code_revision.wrapping_add(1);
            let page = self.translated_page_mut(entry);
            if entry.tag & Translation::BACKED != 0 {
                page.check_backing(address)?;
            }
            page.write_bytes(offset, input)?;
            let executable = entry.tag & Translation::access_bit(Access::Execute) != 0;
            if executable {
                page.instruction_revision = next_code_revision;
            }
            self.revision = self.revision.wrapping_add(1);
            if executable {
                self.advance_code_revision();
            }
            self.note_parallel_write(frame);
            return Ok(());
        }
        self.check(address, input.len(), Access::Write)?;
        if !input.is_empty() {
            self.revision = self.revision.wrapping_add(1);
        }
        self.prepare_mmu_write(address, input.len())?;
        let mut executable = false;
        while !input.is_empty() {
            let base = address & !(PAGE_SIZE - 1);
            let offset = (address - base) as usize;
            let len = input.len().min(PAGE_SIZE as usize - offset);
            let frame = self.frame(base).expect("validated page");
            let page = self.frames[frame].as_mut().expect("mapped frame");
            executable |= page.permissions.execute;
            if page.permissions.execute {
                page.instruction_revision = self.code_revision.wrapping_add(1);
            }
            page.write_bytes(offset, &input[..len])?;
            self.note_parallel_write(frame);
            address += len as u64;
            input = &input[len..];
        }
        if executable {
            self.advance_code_revision();
        }
        Ok(())
    }

    pub fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().fetch_u32(address);
        }
        if !address.is_multiple_of(4) {
            return Err(MemoryError::Alignment(address));
        }
        // An aligned A64 instruction cannot straddle a 4 KiB page.
        let page = self.page_for_access(address, 4, Access::Execute)?;
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        let mut bytes = [0; 4];
        page.read_bytes(offset, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Fixed-size interpreter operands avoid a variable-size memcpy. The slow
    /// path still validates a complete cross-page operation before any effect.
    #[inline]
    pub fn read_array<const N: usize>(&self, address: u64) -> Result<[u8; N], MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow().read_array(address);
        }
        if N == 0 {
            return Ok([0; N]);
        }
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if N <= PAGE_SIZE as usize - offset {
            let base = address & !(PAGE_SIZE - 1);
            let entry = self.translation(base).ok_or_else(|| {
                Self::end(address, N as u64)
                    .err()
                    .unwrap_or_else(|| self.missing_page(address, Access::Read))
            })?;
            if matches!(N, 1 | 2 | 4 | 8 | 16) {
                // SAFETY: live owning TLB, page-contained operand, no callbacks
                // or mutation before the guarded CPU load.
                let page = self.translated_page(entry);
                let _guard = page.bytes.shared().map(|b| b.lock(offset, N));
                if let Some(bytes) = unsafe { entry.read::<N>(offset) } {
                    return Ok(bytes);
                }
            }
            let page = self.page_for_access(address, N, Access::Read)?;
            let mut bytes = [0; N];
            page.read_bytes(offset, &mut bytes)?;
            return Ok(bytes);
        }
        let mut bytes = [0; N];
        self.read(address, &mut bytes)?;
        Ok(bytes)
    }

    #[inline]
    pub fn write_array<const N: usize>(
        &mut self,
        address: u64,
        bytes: [u8; N],
    ) -> Result<(), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().write_array(address, bytes);
        }
        if N == 0 {
            return Ok(());
        }
        let offset = (address & (PAGE_SIZE - 1)) as usize;
        if N > PAGE_SIZE as usize - offset {
            return self.write(address, &bytes);
        }
        let base = address & !(PAGE_SIZE - 1);
        let entry = self.translation(base).ok_or_else(|| {
            Self::end(address, N as u64)
                .err()
                .unwrap_or_else(|| self.missing_page(address, Access::Write))
        })?;
        // SAFETY: same owning-TLB/lifetime bound as read, exclusive coordinator
        // access and one guest page. Failed protected stores have no effects.
        let stored = if matches!(N, 1 | 2 | 4 | 8 | 16) {
            let page = self.translated_page(entry);
            let mut guard = page.bytes.shared().map(|b| b.lock(offset, N));
            let stored = unsafe { entry.write(offset, bytes) };
            if stored {
                if let (Some(shared), Some(guard)) = (page.bytes.shared(), guard.as_mut()) {
                    shared.changed(guard, offset, N);
                }
            }
            stored
        } else {
            false
        };
        if stored {
            self.revision = self.revision.wrapping_add(1);
            self.note_parallel_write(entry.frame);
            return Ok(());
        }
        let entry = self.access_translation(address, N, Access::Write)?;
        let frame = entry.frame;
        self.prepare_mmu_write(address, N)?;
        let next_code_revision = self.code_revision.wrapping_add(1);
        let page = self.translated_page_mut(entry);
        if entry.tag & Translation::BACKED != 0 {
            page.check_backing(address)?;
        }
        page.write_bytes(offset, &bytes)?;
        let executable = entry.tag & Translation::access_bit(Access::Execute) != 0;
        if executable {
            page.instruction_revision = next_code_revision;
        }
        self.revision = self.revision.wrapping_add(1);
        if executable {
            self.advance_code_revision();
        }
        self.note_parallel_write(frame);
        Ok(())
    }

    pub fn read_u64(&self, address: u64) -> Result<u64, MemoryError> {
        Ok(u64::from_le_bytes(self.read_array(address)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_code_tokens_preserve_unrelated_code_and_track_wrap_shared_and_failed_writes() {
        let mut memory = Memory::default();
        let rwx = Permissions {
            execute: true,
            ..Permissions::RW
        };
        memory.map(0x1000, PAGE_SIZE * 2, rwx).unwrap();
        let first = memory.instruction_page_identity(0x1000).unwrap();
        let second = memory.instruction_page_identity(0x2000).unwrap();
        memory.map(0x9000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x9000, [7; 8]).unwrap();
        assert_eq!(memory.instruction_page_identity(0x1000).unwrap(), first);
        memory.write_array(0x2000, [8; 8]).unwrap();
        assert_eq!(memory.instruction_page_identity(0x1000).unwrap(), first);
        assert_ne!(memory.instruction_page_identity(0x2000).unwrap(), second);
        memory.write_array(0x1ffc, [9; 8]).unwrap();
        let updated = memory.instruction_page_identity(0x1000).unwrap();
        assert_ne!(updated, first);
        assert_eq!(updated, memory.instruction_page_identity(0x2000).unwrap());
        memory.protect(0x2000, PAGE_SIZE, Permissions::RX).unwrap();
        assert!(memory.write_array(0x1ffc, [10; 8]).is_err());
        assert_eq!(memory.instruction_page_identity(0x1000).unwrap(), updated);
        assert!(memory
            .protect(0x1000, PAGE_SIZE * 3, Permissions::R)
            .is_err());
        assert_eq!(memory.instruction_page_identity(0x1000).unwrap(), updated);
        // Wrap invalidates the space key, including otherwise unchanged pages.
        memory.code_revision = u64::MAX;
        memory.map(0xa000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_ne!(
            memory.instruction_page_identity(0x1000).unwrap().0,
            updated.0
        );
        let mut shared = memory.share();
        shared.write_array(0x1000, [11; 4]).unwrap();
        assert_eq!(
            memory.instruction_page_identity(0x1000),
            shared.instruction_page_identity(0x1000)
        );
        assert_ne!(
            memory.clone().instruction_page_identity(0x1000).unwrap().0,
            memory.instruction_page_identity(0x1000).unwrap().0
        );
    }
    #[test]
    fn fixed_operands_match_generic_access_across_pages_and_faults() {
        fn compare<const N: usize>(memory: &Memory, address: u64) {
            let mut fast = memory.clone();
            let mut generic = memory.clone();
            let mut bytes = [0; N];
            let expected = generic.read(address, &mut bytes).map(|_| bytes);
            assert_eq!(fast.read_array::<N>(address), expected);
            let bytes = [0x5a; N];
            assert_eq!(
                fast.write_array(address, bytes),
                generic.write(address, &bytes)
            );
            assert_eq!(fast.revision(), generic.revision());
            assert_eq!(fast.instruction_revision(), generic.instruction_revision());
            let mut a = [0; 8192];
            let mut b = [0; 8192];
            fast.read(0x1000, &mut a).unwrap();
            generic.read(0x1000, &mut b).unwrap();
            assert_eq!(a, b);
        }
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        for address in [0x1000, 0x1ff8, 0x1fff, 0x2ff8, ADDRESS_LIMIT - 4, u64::MAX] {
            compare::<0>(&memory, address);
            compare::<1>(&memory, address);
            compare::<2>(&memory, address);
            compare::<4>(&memory, address);
            compare::<8>(&memory, address);
            compare::<16>(&memory, address);
            compare::<32>(&memory, address);
        }
        memory.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        compare::<8>(&memory, 0x1ffc);
        compare::<32>(&memory, 0x1ff8);
        let mut thread = memory.share();
        thread.write_array(0x1000, 42u64.to_le_bytes()).unwrap();
        assert_eq!(memory.read_array::<8>(0x1000).unwrap(), 42u64.to_le_bytes());
        assert!(thread.write_array::<8>(0x1ffc, [0; 8]).is_err());
    }
    #[test]
    fn cached_frames_reuse_slots_without_stale_bytes_permissions_or_false_cow() {
        let mut memory = Memory::default();
        memory.map(0, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write(0, b"first").unwrap();
        let mut bytes = [0; 5];
        memory.read(0, &mut bytes).unwrap();
        let frame = memory.pages[&0];
        assert_eq!(
            Rc::strong_count(&memory.frames[frame].as_ref().unwrap().bytes),
            1
        );
        let mut child = memory.clone();
        child.write(0, b"child").unwrap();
        memory.read(0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"first");
        // A colliding translation and a reused slab index cannot alias an old mapping.
        memory
            .map(
                PAGE_SIZE * TRANSLATION_SLOTS as u64,
                PAGE_SIZE,
                Permissions::RW,
            )
            .unwrap();
        memory
            .write(PAGE_SIZE * TRANSLATION_SLOTS as u64, b"other")
            .unwrap();
        memory.read(0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"first");
        memory.unmap(0, PAGE_SIZE).unwrap();
        memory.map(PAGE_SIZE, PAGE_SIZE, Permissions::RW).unwrap();
        assert!(matches!(
            memory.read(0, &mut bytes),
            Err(MemoryError::Unmapped(0))
        ));
        memory
            .map_fixed(PAGE_SIZE, PAGE_SIZE, Permissions::R)
            .unwrap();
        assert_eq!(memory.read_u64(PAGE_SIZE).unwrap(), 0);
        assert!(memory.write(PAGE_SIZE, b"x").is_err());
        for _ in 0..100 {
            memory.unmap(PAGE_SIZE, PAGE_SIZE).unwrap();
            memory.map(PAGE_SIZE, PAGE_SIZE, Permissions::RW).unwrap();
        }
        assert_eq!(memory.frames.len(), 2);
        memory
            .protect(
                PAGE_SIZE,
                PAGE_SIZE,
                Permissions {
                    read: false,
                    write: false,
                    execute: false,
                },
            )
            .unwrap();
        assert!(memory.read(PAGE_SIZE, &mut bytes).is_err());
        memory
            .protect(PAGE_SIZE, PAGE_SIZE, Permissions::RW)
            .unwrap();
        assert!(memory.write(PAGE_SIZE, b"x").is_ok());
    }
    #[test]
    fn optimized_access_preserves_fault_atomicity_and_execute_only_pages() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        memory.write(0x1ffc, &0xd503201fu32.to_le_bytes()).unwrap();
        memory.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        let revision = memory.revision();
        let code_revision = memory.instruction_revision();
        assert!(matches!(
            memory.write(0x1fff, &[1, 2]),
            Err(MemoryError::Permission {
                address: 0x2000,
                access: Access::Write
            })
        ));
        assert!(matches!(
            memory.write(0x2000, &[1]),
            Err(MemoryError::Permission {
                address: 0x2000,
                access: Access::Write
            })
        ));
        assert_eq!(memory.revision(), revision);
        assert_eq!(memory.instruction_revision(), code_revision);
        let mut output = [0xaa; 8];
        assert!(memory.read(0x2ffc, &mut output).is_err());
        assert_eq!(output, [0xaa; 8]);
        memory
            .protect(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    read: false,
                    write: false,
                    execute: true,
                },
            )
            .unwrap();
        assert_eq!(memory.fetch_u32(0x1ffc).unwrap(), 0xd503201f);
        assert!(memory.read(0x1ffc, &mut output[..4]).is_err());
        assert_eq!(output, [0xaa; 8]);
        assert!(memory.read(ADDRESS_LIMIT, &mut output[..1]).is_err());
        assert!(memory.write(ADDRESS_LIMIT, &[1]).is_err());
        assert!(memory.fetch_u32(ADDRESS_LIMIT).is_err());
        assert!(memory.read(u64::MAX, &mut []).is_ok());
        assert!(memory.write(u64::MAX, &[]).is_ok());
    }
    #[test]
    fn cross_page_write_is_atomic_on_fault() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1fff, &[7]).unwrap();
        assert!(matches!(
            m.write(0x1fff, &[1, 2]),
            Err(MemoryError::Unmapped(0x2000))
        ));
        let mut byte = [0];
        m.read(0x1fff, &mut byte).unwrap();
        assert_eq!(byte, [7]);
    }
    #[test]
    fn permissions_are_separate_and_protection_is_atomic() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert!(m.fetch_u32(0x1000).is_err());
        assert!(m.protect(0x1000, PAGE_SIZE * 2, Permissions::RX).is_err());
        m.write(0x1000, &[0; 4]).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        assert_eq!(m.fetch_u32(0x1000).unwrap(), 0);
        assert!(m.write(0x1000, &[0]).is_err());
    }
    #[test]
    fn overflow_overlap_and_limit_are_rejected() {
        let mut m = Memory::new(PAGE_SIZE as usize * 2);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert!(matches!(
            m.map(0x1000, PAGE_SIZE, Permissions::RW),
            Err(MemoryError::Overlap(_))
        ));
        assert_eq!(
            m.map(0x2000, PAGE_SIZE * 2, Permissions::RW),
            Err(MemoryError::Limit)
        );
        assert_eq!(m.mapped_bytes(), PAGE_SIZE as usize);
        assert!(m.check(u64::MAX, 2, Access::Read).is_err());
        assert!(m.check(ADDRESS_LIMIT - 1, 2, Access::Read).is_err());
        assert!(m.check(u64::MAX, 0, Access::Read).is_ok());
    }
    #[test]
    fn mapped_pages_are_zeroed_and_reads_cross_boundaries() {
        let mut m = Memory::default();
        m.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.read_u64(0x1ffc).unwrap(), 0);
        m.write(0x1ffc, &42u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_u64(0x1ffc).unwrap(), 42);
    }

    #[test]
    fn unmap_holes_and_remapping_zeroes_old_data() {
        let mut m = Memory::new(8192);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, b"old").unwrap();
        assert!(!m.is_free(0x1000, PAGE_SIZE));
        assert!(m.unmap(0x1001, PAGE_SIZE).is_err());
        assert_eq!(m.mapped_bytes(), 4096);
        m.unmap(0x1000, PAGE_SIZE * 2).unwrap();
        assert!(m.is_free(0x1000, PAGE_SIZE));
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.read_u64(0x1000).unwrap(), 0);
    }

    #[test]
    fn c_strings_obey_bounds_and_accept_non_utf8() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1ffe, &[0xff, 0]).unwrap();
        assert_eq!(m.read_c_string(0x1ffe, 2).unwrap(), [0xff]);
        assert_eq!(m.read_c_string(0x1ffe, 1), Err(MemoryError::Limit));
        m.write(0x1fff, &[1]).unwrap();
        assert!(m.read_c_string(0x1ffe, 4).is_err());
    }
    #[test]
    fn borrowed_c_strings_keep_page_boundaries_tags_and_shared_vm_permissions() {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        m.write(0x1ffe, b"ab\xff\0").unwrap();
        assert_eq!(
            m.read_c_string(0xab00_0000_0000_1ffe, 4).unwrap(),
            b"ab\xff"
        );
        assert_eq!(m.read_c_string(0x1ffe, 3), Err(MemoryError::Limit));
        let mut thread = m.share();
        thread.write(0x2fff, &[0]).unwrap();
        assert_eq!(m.read_c_string(0x2fff, 65536).unwrap(), b"");
        thread
            .protect(
                0x2000,
                PAGE_SIZE,
                Permissions {
                    read: false,
                    write: true,
                    execute: false,
                },
            )
            .unwrap();
        assert_eq!(
            m.read_c_string(0x2000, 1),
            Err(MemoryError::Permission {
                address: 0x2000,
                access: Access::Read
            })
        );
        assert_eq!(m.read_c_string(u64::MAX, 0), Err(MemoryError::Limit));
    }

    #[test]
    fn fixed_mapping_failure_preserves_existing_bytes() {
        let mut m = Memory::new(4096);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, b"data").unwrap();
        assert_eq!(
            m.map_fixed(0x1000, PAGE_SIZE * 2, Permissions::R),
            Err(MemoryError::Limit)
        );
        let mut bytes = [0; 4];
        m.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"data");
        m.map_fixed(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert_eq!(m.read_u64(0x1000).unwrap(), 0);
        assert!(m.write(0x1000, b"x").is_err());
    }

    #[test]
    fn free_range_search_skips_only_conflicting_pages() {
        let mut m = Memory::default();
        m.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x5000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(m.find_free(0x1000, PAGE_SIZE), Some(0x1000));
        assert_eq!(m.find_free(0x1000, PAGE_SIZE * 2), Some(0x3000));
        assert_eq!(m.find_free(ADDRESS_LIMIT - PAGE_SIZE, PAGE_SIZE * 2), None);
    }
}

#[cfg(test)]
mod fork_tests {
    use super::*;
    #[test]
    fn instruction_revision_tracks_shared_code_but_not_data_writes() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .protect(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        let mut thread = memory.share();
        let code = memory.instruction_revision();
        let all = memory.revision();
        thread.write(0x2000, b"data").unwrap();
        assert_eq!(memory.instruction_revision(), code);
        assert!(memory.revision() > all);
        thread.write(0x1000, &0xd503201fu32.to_le_bytes()).unwrap();
        assert!(memory.instruction_revision() > code);
        let code = memory.instruction_revision();
        assert!(thread
            .protect(0x2000, PAGE_SIZE * 2, Permissions::RX)
            .is_err());
        assert_eq!(memory.instruction_revision(), code);
        thread.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(memory.instruction_revision() > code);
    }
    #[test]
    fn shared_vm_updates_mappings_bytes_and_revision_but_fork_is_private() {
        let mut parent = Memory::default();
        parent.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut thread = parent.share();
        let revision = parent.revision();
        thread.write(0x1000, b"thread").unwrap();
        assert!(parent.revision() > revision);
        let mut bytes = [0; 6];
        parent.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"thread");
        let mut fork = thread.clone();
        fork.write(0x1000, b"forked").unwrap();
        parent.read(0x1000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"thread");
        thread.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(parent.write(0x1000, b"x").is_err());
        assert!(fork.write(0x1000, b"x").is_ok());
        parent.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(thread.mapped_bytes(), PAGE_SIZE as usize * 2);
        thread.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(parent.read(0x1000, &mut bytes).is_err());
        assert!(fork.read(0x1000, &mut bytes).is_ok());
    }
    #[test]
    fn fork_copies_pages_on_write_and_keeps_protection_independent() {
        let mut parent = Memory::default();
        parent.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        parent.write(0x1fff, b"ab").unwrap();
        let mut child = parent.clone();
        child.write(0x1fff, b"XY").unwrap();
        let mut bytes = [0; 2];
        parent.read(0x1fff, &mut bytes).unwrap();
        assert_eq!(&bytes, b"ab");
        child.read(0x1fff, &mut bytes).unwrap();
        assert_eq!(&bytes, b"XY");
        child.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        assert!(parent.write(0x1000, b"z").is_ok());
        assert!(child.write(0x1000, b"z").is_err());
        child.unmap(0x1000, PAGE_SIZE).unwrap();
        assert!(parent.read(0x1000, &mut bytes).is_ok());
    }
}
