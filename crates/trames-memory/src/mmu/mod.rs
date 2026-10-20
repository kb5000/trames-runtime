// SPDX-License-Identifier: GPL-3.0-or-later
//! Sparse, non-executable hardware-protected views of ordinary guest RAM.
pub(super) mod access;
mod cache;
pub(crate) use cache::Cache;
mod fault;
pub(crate) mod host;
mod worker;
use super::*;
use host::WINDOW;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize};
use std::{
    ops::{Deref, DerefMut},
    ptr::NonNull,
    sync::Arc,
};
pub(crate) use worker::{Frozen, Pool, Slot};
#[cfg(test)]
mod tests;

const ELIGIBLE: u8 = 4;
const CODE: u8 = 8;
const READ: u8 = 1;
const WRITE: u8 = 2;
// A mapping boundary already proved this host group software-only. Ordinary
// stores cannot fill holes or change permissions/backing, so do not retry its
// preparation until the next map/protect/unmap/discard/remap or fork boundary.
const SOFTWARE: u8 = 16;
const P: usize = PAGE_SIZE as usize;

/// Kernel/native alias; never changes protection while a Rust slice exists.
/// A clone copies bytes instead of aliasing writable pages: Rc::make_mut keeps
/// the existing fork-COW contract even when the physical storage is mapped.
pub(super) enum PageBytes {
    Zero,
    Concurrent(Arc<crate::SharedPage>),
    Heap(Box<[u8; P]>),
    Mapped {
        owner: Arc<host::Mapping>,
        offset: usize,
        _lease: Option<Arc<Slot>>,
    },
}
impl PageBytes {
    pub(crate) fn shared(&self) -> Option<&Arc<crate::SharedPage>> {
        if let Self::Concurrent(bytes) = self {
            Some(bytes)
        } else {
            None
        }
    }
    pub(crate) fn snapshot(&self) -> [u8; P] {
        if let Some(bytes) = self.shared() {
            bytes.snapshot()
        } else {
            **self
        }
    }
    pub(crate) fn with_read<T>(&self, offset: usize, len: usize, f: impl FnOnce(&[u8]) -> T) -> T {
        if let Some(bytes) = self.shared() {
            bytes.with_read(offset, len, f)
        } else {
            f(&self[offset..offset + len])
        }
    }
    pub(crate) fn with_write<T>(
        &mut self,
        offset: usize,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> T,
    ) -> T {
        if let Self::Concurrent(bytes) = self {
            bytes.with_write(offset, len, f)
        } else {
            f(&mut self[offset..offset + len])
        }
    }
    pub fn is_zero(&self) -> bool {
        matches!(self, Self::Zero)
    }
    pub fn new(bytes: [u8; P]) -> Self {
        Self::Heap(Box::new(bytes))
    }
    pub(super) fn from_slot(slot: Arc<Slot>) -> Self {
        Self::Mapped {
            owner: slot.owner.clone(),
            offset: slot.offset,
            _lease: Some(slot),
        }
    }
    pub(super) fn physical(&self) -> Option<(&Arc<host::Mapping>, usize)> {
        match self {
            Self::Mapped { owner, offset, .. } => Some((owner, *offset)),
            Self::Concurrent(bytes) => bytes.physical(),
            _ => None,
        }
    }
    fn belongs(&self, owner: &Arc<host::Mapping>, offset: usize) -> bool {
        self.physical()
            .is_some_and(|(old, at)| Arc::ptr_eq(owner, old) && at == offset)
    }
}
impl Clone for PageBytes {
    fn clone(&self) -> Self {
        if self.is_zero() {
            Self::Zero
        } else {
            Self::new(self.snapshot())
        }
    }
}
impl Deref for PageBytes {
    type Target = [u8; P];
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Concurrent(_) => panic!("shared bytes require a scoped region guard"),
            Self::Zero => &[0; P],
            Self::Heap(bytes) => bytes,
            // SAFETY: offset denotes one complete, initialized, 4KiB page of
            // this live RW kernel mapping. Coordinator access is !Send/!Sync;
            // no direct CPU write occurs while a shared byte borrow is live.
            Self::Mapped { owner, offset, .. } => unsafe {
                &*owner.kernel.as_ptr().add(*offset).cast()
            },
        }
    }
}
impl DerefMut for PageBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        if self.is_zero() {
            *self = Self::new([0; P]);
        }
        match self {
            Self::Concurrent(_) => panic!("shared bytes require a scoped region guard"),
            Self::Zero => unreachable!(),
            Self::Heap(bytes) => bytes,
            // SAFETY: Rc::make_mut detached any fork peers. Different page
            // objects cover disjoint subranges; this exclusive borrow excludes
            // CPU access, native callbacks and mapping mutation on the owner.
            Self::Mapped { owner, offset, .. } => unsafe {
                &mut *owner.kernel.as_ptr().add(*offset).cast()
            },
        }
    }
}

pub(crate) struct Window {
    base: u64,
    // Workers need only the CPU view. Coordinator windows additionally own
    // physical bytes; PageBytes retain that owner independently of this view.
    mapping: Option<Arc<host::Mapping>>,
    cpu: host::CpuMapping,
    flags: Box<[AtomicU8]>,
    frames: Box<[AtomicUsize]>,
    initialized: Box<[AtomicBool]>,
    zeroed: Box<[AtomicBool]>,
    granule: usize,
    shift: u32,
}
impl Window {
    fn new(base: u64, granule: usize) -> Option<Self> {
        let mapping = Arc::new(host::Mapping::new()?);
        let cpu = host::CpuMapping::new()?;
        if !cpu.alias(0, &mapping, 0, WINDOW) || !cpu.protect(0, WINDOW, libc::PROT_NONE) {
            return None;
        }
        Some(Self::with_view(base, granule, cpu, Some(mapping)))
    }
    fn for_workers(base: u64, granule: usize) -> Option<Self> {
        Some(Self::with_view(
            base,
            granule,
            host::CpuMapping::new()?,
            None,
        ))
    }
    fn with_view(
        base: u64,
        granule: usize,
        cpu: host::CpuMapping,
        mapping: Option<Arc<host::Mapping>>,
    ) -> Self {
        Self {
            base,
            mapping,
            cpu,
            granule,
            shift: granule.trailing_zeros(),
            flags: (0..WINDOW / granule).map(|_| AtomicU8::new(0)).collect(),
            frames: (0..WINDOW / P)
                .map(|_| AtomicUsize::new(usize::MAX))
                .collect(),
            initialized: (0..WINDOW / P).map(|_| AtomicBool::new(false)).collect(),
            zeroed: (0..WINDOW / P).map(|_| AtomicBool::new(true)).collect(),
        }
    }
    fn page(&self, offset: usize, zero: bool) -> Rc<PageBytes> {
        let mapping = self.mapping.as_ref().expect("coordinator physical storage");
        if zero
            && self.initialized[offset / P].swap(true, Ordering::Relaxed)
            && !self.zeroed[offset / P].load(Ordering::Relaxed)
        {
            // SAFETY: a newly installed private anonymous page has no existing
            // byte borrows. Fork retires the complete CPU arena before sharing.
            unsafe {
                std::ptr::write_bytes(mapping.kernel.as_ptr().add(offset), 0, P);
            }
        } else {
            self.initialized[offset / P].store(true, Ordering::Relaxed);
        }
        self.zeroed[offset / P].store(false, Ordering::Relaxed);
        Rc::new(PageBytes::Mapped {
            owner: mapping.clone(),
            offset,
            _lease: None,
        })
    }
    fn zero_page(&self, offset: usize) {
        self.initialized[offset / P].store(true, Ordering::Relaxed);
        if !self.zeroed[offset / P].swap(true, Ordering::Relaxed) {
            // SAFETY: mapping checkpoint, no CPU or byte borrow is live. A
            // previously used slot must be cleared before exposing a zero page.
            unsafe {
                std::ptr::write_bytes(
                    self.mapping.as_ref().unwrap().kernel.as_ptr().add(offset),
                    0,
                    P,
                );
            }
        }
    }
    fn protect_run(&self, begin: usize, end: usize, state: u8) {
        let protection = (if state & READ != 0 {
            libc::PROT_READ
        } else {
            0
        }) | if state & WRITE != 0 {
            libc::PROT_WRITE
        } else {
            0
        };
        let ok = self.cpu.protect(
            begin * self.granule,
            (end - begin) * self.granule,
            protection,
        );
        for index in begin..end {
            self.flags[index].store(if ok { state } else { SOFTWARE }, Ordering::Relaxed);
        }
    }
}

pub(super) struct Arena {
    windows: RefCell<BTreeMap<u64, Rc<Window>>>,
    unavailable: RefCell<BTreeSet<u64>>,
    cache: Cache,
    granule: usize,
    #[cfg(test)]
    preparations: Cell<usize>,
}
impl Default for Arena {
    fn default() -> Self {
        Self {
            windows: RefCell::new(BTreeMap::new()),
            unavailable: RefCell::default(),
            cache: Cache::default(),
            granule: host::page_size().unwrap_or(0),
            #[cfg(test)]
            preparations: Cell::new(0),
        }
    }
}
impl Arena {
    fn window(&self, address: u64, create: bool) -> Option<Rc<Window>> {
        if self.granule == 0 {
            return None;
        }
        let base = address & !(WINDOW as u64 - 1);
        if let Some(window) = self.windows.borrow().get(&base) {
            return Some(window.clone());
        }
        if !create {
            return None;
        }
        let Some(window) = Window::new(base, self.granule) else {
            self.unavailable.borrow_mut().insert(base);
            self.cache.absent(base);
            return None;
        };
        self.unavailable.borrow_mut().remove(&base);
        let window = Rc::new(window);
        self.windows.borrow_mut().insert(base, window.clone());
        self.cache.insert(base, NonNull::from(window.as_ref()));
        Some(window)
    }
    #[inline]
    fn reached(&self, address: u64) -> Option<&Window> {
        let base = address & !(WINDOW as u64 - 1);
        if let Some(pointer) = self.cache.get(base) {
            // SAFETY: retire clears all entries before dropping pinned windows.
            return Some(unsafe { pointer?.as_ref() });
        }
        self.reached_slow(base)
    }
    #[cold]
    fn reached_slow(&self, base: u64) -> Option<&Window> {
        let windows = self.windows.borrow();
        let Some(window) = windows.get(&base) else {
            self.cache.absent(base);
            return None;
        };
        let pointer = NonNull::from(window.as_ref());
        self.cache.insert(base, pointer);
        // SAFETY: the map retains this allocation after the temporary RefCell
        // borrow ends. No callback or map mutation occurs during this access.
        Some(unsafe { pointer.as_ref() })
    }
    pub fn page(&self, base: u64) -> Option<Rc<PageBytes>> {
        if self
            .unavailable
            .borrow()
            .contains(&(base & !(WINDOW as u64 - 1)))
        {
            return None;
        }
        let window = self.window(base, true)?;
        Some(window.page((base - window.base) as usize, true))
    }
    /// Fork stops using the old CPU aliases before sharing any Rc byte owner.
    /// Retired kernel aliases stay alive through their PageBytes. New mapping
    /// windows are populated lazily; fork does not eagerly copy guest RAM.
    pub fn retire(&self) {
        self.cache.clear();
        self.unavailable.borrow_mut().clear();
        for window in self.windows.borrow().values() {
            for flag in &window.flags {
                flag.store(0, Ordering::Relaxed);
            }
            window.cpu.protect(0, WINDOW, libc::PROT_NONE);
        }
        self.windows.borrow_mut().clear();
    }
    /// Cached only in the owning Memory's page TLB. Mapping edits and arena
    /// retirement flush that TLB before any alias can be replaced or unmapped.
    pub fn page_alias(&self, base: u64) -> usize {
        let Some(window) = self.reached(base) else {
            return 0;
        };
        let offset = (base - window.base) as usize;
        if window.flags[offset >> window.shift].load(Ordering::Relaxed) & ELIGIBLE == 0 {
            return 0;
        }
        window.cpu.cpu.as_ptr().wrapping_add(offset) as usize
    }
    #[inline]
    fn prepared(&self, address: u64) -> bool {
        self.granule == 0
            || match self.reached(address) {
                Some(window) => {
                    window.flags[(address - window.base) as usize >> window.shift]
                        .load(Ordering::Relaxed)
                        & (ELIGIBLE | SOFTWARE)
                        != 0
                }
                // Optional VA pressure is not a reason to retry a host mapping
                // on every store. Mapping boundaries retry once per window.
                None => self
                    .unavailable
                    .borrow()
                    .contains(&(address & !(WINDOW as u64 - 1))),
            }
    }
    #[inline]
    #[cfg(test)]
    pub fn read<const N: usize>(&self, address: u64) -> Option<[u8; N]> {
        if !matches!(N, 1 | 2 | 4 | 8 | 16) || N > P - (address as usize & (P - 1)) {
            return None;
        }
        let window = self.reached(address)?;
        Self::read_at(
            window,
            (window.cpu.cpu.as_ptr() as usize).wrapping_sub(window.base as usize),
            address,
        )
    }
    #[inline(always)]
    #[cfg(test)]
    fn read_at<const N: usize>(window: &Window, bias: usize, address: u64) -> Option<[u8; N]> {
        if !matches!(N, 1 | 2 | 4 | 8 | 16) || N > P - (address as usize & (P - 1)) {
            return None;
        }
        let offset = (address - window.base) as usize;
        if window.flags[offset >> window.shift].load(Ordering::Relaxed) & ELIGIBLE == 0 {
            return None;
        }
        let mut bytes = [0; N];
        // SAFETY: the target remains inside our registered CPU alias and one
        // host page; the asm fixup returns false without touching the output.
        if unsafe {
            access::access::<N>(
                false,
                bias.wrapping_add(address as usize) as *mut u8,
                bytes.as_mut_ptr(),
            )
        } {
            Some(bytes)
        } else {
            None
        }
    }
    #[inline]
    #[cfg(test)]
    pub fn write<const N: usize>(&self, address: u64, bytes: [u8; N]) -> Option<usize> {
        if !matches!(N, 1 | 2 | 4 | 8 | 16) || N > P - (address as usize & (P - 1)) {
            return None;
        }
        let window = self.reached(address)?;
        Self::write_at(
            window,
            (window.cpu.cpu.as_ptr() as usize).wrapping_sub(window.base as usize),
            address,
            bytes,
        )
    }
    #[inline(always)]
    #[cfg(test)]
    fn write_at<const N: usize>(
        window: &Window,
        bias: usize,
        address: u64,
        mut bytes: [u8; N],
    ) -> Option<usize> {
        if !matches!(N, 1 | 2 | 4 | 8 | 16) || N > P - (address as usize & (P - 1)) {
            return None;
        }
        let offset = (address - window.base) as usize;
        let state = window.flags[offset >> window.shift].load(Ordering::Relaxed);
        if state & (ELIGIBLE | CODE) != ELIGIBLE {
            return None;
        }
        // SAFETY: same bounded target invariant as read. A rejected store is
        // wholly inside one hardware page, so it has no partial guest effects.
        if unsafe {
            access::access::<N>(
                true,
                bias.wrapping_add(address as usize) as *mut u8,
                bytes.as_mut_ptr(),
            )
        } {
            Some(window.frames[offset / P].load(Ordering::Relaxed))
        } else {
            None
        }
    }
}

impl Memory {
    pub(super) fn prepare_mmu_write(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<(), MemoryError> {
        if self.materialize_zero(address, len)? {
            self.invalidate_translations();
        }
        if len <= P - (address as usize & (P - 1)) {
            if self.mmu.prepared(address) {
                return Ok(());
            }
            // Backings always retain the software path (including live EOF
            // checks after private COW). Rebuilding host groups on every file
            // store can never make this page eligible.
            let base = address & !(PAGE_SIZE - 1);
            if self.frame(base).is_some_and(|frame| {
                self.frames[frame]
                    .as_ref()
                    .is_some_and(|page| page.backing.is_some())
            }) {
                return Ok(());
            }
        }
        if self.refresh_mmu(address, len as u64) {
            self.invalidate_translations();
        }
        Ok(())
    }
    /// Called only at quiescent mapping/COW boundaries. Hardware groups with
    /// holes, mixed permissions or backing I/O stay on the shared software path.
    pub(super) fn refresh_mmu(&mut self, address: u64, len: u64) -> bool {
        #[cfg(test)]
        self.mmu.preparations.set(self.mmu.preparations.get() + 1);
        let granule = self.mmu.granule;
        if granule == 0 || len == 0 {
            return false;
        }
        let mut changed = false;
        let begin = address & !(granule as u64 - 1);
        let end = address
            .saturating_add(len)
            .saturating_add(granule as u64 - 1)
            & !(granule as u64 - 1);
        let mut at = begin;
        while at < end {
            let stop = end.min((at & !(WINDOW as u64 - 1)) + WINDOW as u64);
            let Some(window) = self
                .mmu
                .window(at, self.pages.range(at..stop).next().is_some())
            else {
                let base = at & !(WINDOW as u64 - 1);
                if self
                    .pages
                    .range(base..base + WINDOW as u64)
                    .next()
                    .is_none()
                {
                    self.mmu.unavailable.borrow_mut().remove(&base);
                }
                // Huge reserved/hole ranges own no physical windows. Skip the
                // entire sparse window instead of inspecting every 4KiB page.
                at = stop;
                continue;
            };
            if self
                .pages
                .range(window.base..window.base + WINDOW as u64)
                .next()
                .is_none()
            {
                // Quiescent unmap/fixed-replacement boundary. Byte owners in a
                // fork or retained snapshot may live on, but not this CPU VA.
                self.mmu.cache.clear();
                self.mmu.windows.borrow_mut().remove(&window.base);
                changed = true;
                at = stop;
                continue;
            }
            let mapping = window
                .mapping
                .as_ref()
                .expect("coordinator physical storage");
            let mut run: Option<(usize, usize, u8)> = None;
            while at < stop {
                let first = (at - window.base) as usize;
                let group = first / granule;
                let mut frames = Vec::new();
                let mut permissions = None;
                for base in (at..at + granule as u64).step_by(P) {
                    let Some(&frame) = self.pages.get(&base) else {
                        break;
                    };
                    let page = self.frames[frame].as_ref().expect("mapped page");
                    if page.backing.is_some() || permissions.is_some_and(|p| p != page.permissions)
                    {
                        break;
                    }
                    permissions = Some(page.permissions);
                    frames.push(frame);
                }
                let mut state = SOFTWARE;
                if frames.len() == granule / P
                    && permissions.is_some_and(|p: Permissions| p.read || !p.write)
                {
                    let permissions = permissions.expect("complete group");
                    if frames.iter().enumerate().any(|(index, &frame)| {
                        let page = self.frames[frame].as_ref().expect("mapped page");
                        !page.bytes.is_zero()
                            && (Rc::strong_count(&page.bytes) != 1
                                || !page.bytes.belongs(mapping, first + index * P))
                    }) {
                        changed = true;
                        // Capture the complete group before writing: remap may
                        // move overlapping ranges within an existing window.
                        let data: Vec<_> = frames
                            .iter()
                            .map(|&frame| {
                                let page = self.frames[frame].as_ref().unwrap();
                                (!page.bytes.is_zero()).then(|| page.bytes.snapshot())
                            })
                            .collect();
                        for (index, (&frame, bytes)) in frames.iter().zip(&data).enumerate() {
                            let Some(bytes) = bytes else {
                                continue;
                            };
                            let offset = first + index * P;
                            // SAFETY: private destination, all old sources were
                            // captured; no Rust references alias this write.
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    bytes.as_ptr(),
                                    mapping.kernel.as_ptr().add(offset),
                                    P,
                                );
                            }
                            self.frames[frame].as_mut().unwrap().bytes = window.page(offset, false);
                        }
                    }
                    for (index, &frame) in frames.iter().enumerate() {
                        if self.frames[frame].as_ref().unwrap().bytes.is_zero() {
                            window.zero_page(first + index * P);
                        }
                        window.frames[first / P + index].store(frame, Ordering::Relaxed);
                    }
                    state = ELIGIBLE
                        | if permissions.read { READ } else { 0 }
                        | if permissions.write && !permissions.execute {
                            WRITE
                        } else {
                            0
                        }
                        | if permissions.execute { CODE } else { 0 };
                }
                if state != window.flags[group].load(Ordering::Relaxed) {
                    changed = true;
                    match run {
                        Some((start, last, previous)) if last == group && previous == state => {
                            run = Some((start, group + 1, state))
                        }
                        previous => {
                            if let Some((start, last, state)) = previous {
                                window.protect_run(start, last, state);
                            }
                            run = Some((group, group + 1, state));
                        }
                    }
                } else if let Some((start, last, state)) = run.take() {
                    window.protect_run(start, last, state);
                }
                at += granule as u64;
            }
            if let Some((start, last, state)) = run {
                window.protect_run(start, last, state);
            }
        }
        changed
    }
}
