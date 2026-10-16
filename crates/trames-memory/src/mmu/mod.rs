// SPDX-License-Identifier: GPL-3.0-or-later
//! Sparse, non-executable hardware-protected views of ordinary guest RAM.
mod access;
mod cache;
pub(crate) use cache::Cache;
pub use cache::DirectHint;
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
const P: usize = PAGE_SIZE as usize;

/// Kernel/native alias; never changes protection while a Rust slice exists.
/// A clone copies bytes instead of aliasing writable pages: Rc::make_mut keeps
/// the existing fork-COW contract even when the physical storage is mapped.
pub(super) enum PageBytes {
    Heap(Box<[u8; P]>),
    Mapped {
        owner: Arc<host::Mapping>,
        offset: usize,
        _lease: Option<Arc<Slot>>,
    },
}
impl PageBytes {
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
        if let Self::Mapped { owner, offset, .. } = self {
            Some((owner, *offset))
        } else {
            None
        }
    }
    fn belongs(&self, owner: &Arc<host::Mapping>, offset: usize) -> bool {
        matches!(self, Self::Mapped { owner: old, offset: at, .. } if Arc::ptr_eq(owner, old) && *at == offset)
    }
}
impl Clone for PageBytes {
    fn clone(&self) -> Self {
        Self::new(**self)
    }
}
impl Deref for PageBytes {
    type Target = [u8; P];
    fn deref(&self) -> &Self::Target {
        match self {
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
        match self {
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
    mapping: Arc<host::Mapping>,
    flags: Box<[AtomicU8]>,
    frames: Box<[AtomicUsize]>,
    initialized: Box<[AtomicBool]>,
    granule: usize,
    shift: u32,
}
impl Window {
    fn new(base: u64, granule: usize) -> Option<Self> {
        Some(Self {
            base,
            mapping: Arc::new(host::Mapping::new()?),
            granule,
            shift: granule.trailing_zeros(),
            flags: (0..WINDOW / granule).map(|_| AtomicU8::new(0)).collect(),
            frames: (0..WINDOW / P)
                .map(|_| AtomicUsize::new(usize::MAX))
                .collect(),
            initialized: (0..WINDOW / P).map(|_| AtomicBool::new(false)).collect(),
        })
    }
    fn page(&self, offset: usize, zero: bool) -> Rc<PageBytes> {
        if zero && self.initialized[offset / P].swap(true, Ordering::Relaxed) {
            // SAFETY: a newly installed private anonymous page has no existing
            // byte borrows. Fork retires the complete CPU arena before sharing.
            unsafe {
                std::ptr::write_bytes(self.mapping.kernel.as_ptr().add(offset), 0, P);
            }
        } else {
            self.initialized[offset / P].store(true, Ordering::Relaxed);
        }
        Rc::new(PageBytes::Mapped {
            owner: self.mapping.clone(),
            offset,
            _lease: None,
        })
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
        let ok = self.mapping.protect(
            begin * self.granule,
            (end - begin) * self.granule,
            protection,
        );
        for index in begin..end {
            self.flags[index].store(if ok { state } else { 0 }, Ordering::Relaxed);
        }
    }
}

pub(super) struct Arena {
    windows: RefCell<BTreeMap<u64, Rc<Window>>>,
    cache: Cache,
    key: Cell<u64>,
    granule: usize,
}
impl Default for Arena {
    fn default() -> Self {
        Self {
            windows: RefCell::new(BTreeMap::new()),
            cache: Cache::default(),
            key: Cell::new(NEXT_SPACE.fetch_add(1, Ordering::Relaxed)),
            granule: host::page_size().unwrap_or(0),
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
        let window = Rc::new(Window::new(base, self.granule)?);
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
        let window = self.window(base, true)?;
        Some(window.page((base - window.base) as usize, true))
    }
    /// Fork stops using the old CPU aliases before sharing any Rc byte owner.
    /// Retired kernel aliases stay alive through their PageBytes. New mapping
    /// windows are populated lazily; fork does not eagerly copy guest RAM.
    pub fn retire(&self) {
        self.key.set(NEXT_SPACE.fetch_add(1, Ordering::Relaxed));
        self.cache.clear();
        for window in self.windows.borrow().values() {
            for flag in &window.flags {
                flag.store(0, Ordering::Relaxed);
            }
            window.mapping.protect(0, WINDOW, libc::PROT_NONE);
        }
        self.windows.borrow_mut().clear();
    }
    #[inline]
    pub fn hint(&self) -> DirectHint {
        self.cache.hint(self.key.get())
    }
    #[inline(always)]
    pub fn read_hint<const N: usize>(
        &self,
        address: u64,
        hint: &mut DirectHint,
    ) -> Option<[u8; N]> {
        if let Some((window, bias)) = hint.reached(self.key.get(), address) {
            return Self::read_at(window, bias, address);
        }
        let result = self.read(address);
        *hint = self.hint();
        result
    }
    #[inline(always)]
    pub fn write_hint<const N: usize>(
        &self,
        address: u64,
        bytes: [u8; N],
        hint: &mut DirectHint,
    ) -> Option<usize> {
        if let Some((window, bias)) = hint.reached(self.key.get(), address) {
            return Self::write_at(window, bias, address, bytes);
        }
        let result = self.write(address, bytes);
        *hint = self.hint();
        result
    }
    #[inline]
    fn ready(&self, address: u64) -> bool {
        self.reached(address).is_some_and(|window| {
            window.flags[(address - window.base) as usize >> window.shift].load(Ordering::Relaxed)
                & ELIGIBLE
                != 0
        })
    }
    #[inline]
    pub fn read<const N: usize>(&self, address: u64) -> Option<[u8; N]> {
        if !matches!(N, 1 | 2 | 4 | 8 | 16) || N > P - (address as usize & (P - 1)) {
            return None;
        }
        let window = self.reached(address)?;
        Self::read_at(
            window,
            (window.mapping.cpu.as_ptr() as usize).wrapping_sub(window.base as usize),
            address,
        )
    }
    #[inline(always)]
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
    pub fn write<const N: usize>(&self, address: u64, bytes: [u8; N]) -> Option<usize> {
        if !matches!(N, 1 | 2 | 4 | 8 | 16) || N > P - (address as usize & (P - 1)) {
            return None;
        }
        let window = self.reached(address)?;
        Self::write_at(
            window,
            (window.mapping.cpu.as_ptr() as usize).wrapping_sub(window.base as usize),
            address,
            bytes,
        )
    }
    #[inline(always)]
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
    pub(super) fn prepare_mmu_write(&mut self, address: u64, len: usize) {
        if len <= P - (address as usize & (P - 1)) && self.mmu.ready(address) {
            return;
        }
        self.refresh_mmu(address, len as u64);
    }
    /// Called only at quiescent mapping/COW boundaries. Hardware groups with
    /// holes, mixed permissions or backing I/O stay on the shared software path.
    pub(super) fn refresh_mmu(&mut self, address: u64, len: u64) {
        let granule = self.mmu.granule;
        if granule == 0 || len == 0 {
            return;
        }
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
                // Huge reserved/hole ranges own no physical windows. Skip the
                // entire sparse window instead of inspecting every 4KiB page.
                at = stop;
                continue;
            };
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
                let mut state = 0;
                if frames.len() == granule / P
                    && permissions.is_some_and(|p: Permissions| p.read || !p.write)
                {
                    let permissions = permissions.expect("complete group");
                    if frames.iter().enumerate().any(|(index, &frame)| {
                        let page = self.frames[frame].as_ref().expect("mapped page");
                        Rc::strong_count(&page.bytes) != 1
                            || !page.bytes.belongs(&window.mapping, first + index * P)
                    }) {
                        // Capture the complete group before writing: remap may
                        // move overlapping ranges within an existing window.
                        let data: Vec<_> = frames
                            .iter()
                            .map(|&frame| **self.frames[frame].as_ref().unwrap().bytes)
                            .collect();
                        for (index, (&frame, bytes)) in frames.iter().zip(&data).enumerate() {
                            let offset = first + index * P;
                            // SAFETY: private destination, all old sources were
                            // captured; no Rust references alias this write.
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    bytes.as_ptr(),
                                    window.mapping.kernel.as_ptr().add(offset),
                                    P,
                                );
                            }
                            self.frames[frame].as_mut().unwrap().bytes = window.page(offset, false);
                        }
                    }
                    for (index, &frame) in frames.iter().enumerate() {
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
    }
}
