// SPDX-License-Identifier: GPL-3.0-or-later
//! Anonymous missing faults share the original mm and PageWait with CPU,
//! native and syscall users. No execution thread waits inside this resource.
use crate::*;
use std::{
    collections::VecDeque,
    sync::{atomic::AtomicBool, Mutex, Weak},
};
#[cfg(test)]
mod tests;

thread_local! {
    static USER: Cell<bool> = const { Cell::new(false) };
    static RESOLVING: Cell<bool> = const { Cell::new(false) };
}
pub struct UserAccessScope(bool, std::marker::PhantomData<std::rc::Rc<()>>);
impl UserAccessScope {
    #[inline]
    pub fn for_memory(memory: &impl CpuMemory) -> Option<Self> {
        memory.userfaults_active().then(Self::enter)
    }
    #[inline]
    pub fn enter() -> Self {
        Self(USER.with(|v| v.replace(true)), std::marker::PhantomData)
    }
}
impl Drop for UserAccessScope {
    #[inline]
    fn drop(&mut self) {
        USER.with(|v| v.set(self.0));
    }
}
struct Resolving(bool);
impl Drop for Resolving {
    fn drop(&mut self) {
        RESOLVING.with(|v| v.set(self.0));
    }
}

#[derive(Default)]
pub(super) struct Faults(Mutex<State>, AtomicBool);
#[derive(Default)]
struct State {
    ranges: BTreeMap<u64, Registration>,
    present: BTreeSet<u64>,
    pending: BTreeMap<u64, Vec<Weak<Event>>>,
}
#[derive(Clone)]
struct Registration {
    end: u64,
    id: u64,
    file: Weak<UserfaultFile>,
}
pub(super) struct InPlace {
    ranges: Vec<(u64, Registration)>,
    present: Vec<u64>,
    old_end: u64,
    new_end: u64,
}
struct Event {
    page: u64,
    write: bool,
    id: u64,
    resolved: AtomicBool,
    wait: std::sync::OnceLock<Weak<PageWait>>,
    changed: Arc<trames_shared::Readiness>,
    allocation: CgroupMemoryContext,
}
pub struct UserfaultFile {
    id: u64,
    report: MemoryReport,
    faults: Arc<Faults>,
    user_only: bool,
    initialized: AtomicBool,
    queue: Mutex<VecDeque<Weak<Event>>>,
    changed: Arc<trames_shared::Readiness>,
    epoch: AtomicU64,
    allocation: CgroupMemoryContext,
}
impl State {
    fn take_pending(&mut self, start: u64, end: u64, owner: Option<u64>) -> Vec<Arc<Event>> {
        let keys: Vec<_> = self
            .pending
            .range(start..end)
            .map(|(&page, _)| page)
            .collect();
        let mut taken = Vec::new();
        for page in keys {
            let mut retained = Vec::new();
            for event in self
                .pending
                .remove(&page)
                .unwrap()
                .into_iter()
                .filter_map(|e| e.upgrade())
            {
                if owner.is_none_or(|id| id == event.id) {
                    taken.push(event);
                } else {
                    retained.push(Arc::downgrade(&event));
                }
            }
            if !retained.is_empty() {
                self.pending.insert(page, retained);
            }
        }
        taken
    }
}
impl Faults {
    #[inline]
    pub(super) fn active(&self) -> bool {
        self.1.load(Ordering::Relaxed)
    }
    pub(super) fn missing(&self, page: u64) -> bool {
        if !self.active() {
            return false;
        }
        let state = self.0.lock().unwrap();
        !state.present.contains(&page)
            && state
                .ranges
                .range(..=page)
                .next_back()
                .is_some_and(|(_, r)| page < r.end && r.file.strong_count() != 0)
    }
    pub(super) fn in_place(&self, start: u64, old_end: u64, new_end: u64) -> InPlace {
        let state = self.0.lock().unwrap();
        InPlace {
            ranges: state
                .ranges
                .iter()
                .filter_map(|(&a, r)| {
                    (a < old_end && r.end > start).then_some((a.max(start), r.clone()))
                })
                .collect(),
            present: state
                .present
                .range(start..old_end.min(new_end))
                .copied()
                .collect(),
            old_end,
            new_end,
        }
    }
    pub(super) fn restore_in_place(&self, saved: InPlace) {
        let mut state = self.0.lock().unwrap();
        state.present.extend(saved.present);
        for (a, mut range) in saved.ranges {
            range.end = if range.end == saved.old_end {
                saved.new_end
            } else {
                range.end.min(saved.new_end)
            };
            if a < range.end && range.file.strong_count() != 0 {
                state.ranges.insert(a, range);
            }
        }
        self.1.store(!state.ranges.is_empty(), Ordering::Relaxed);
    }
    pub(super) fn check(&self, address: u64, access: Access) -> Result<(), MemoryError> {
        if !self.active() {
            return Ok(());
        }
        if RESOLVING.with(Cell::get) {
            return Ok(());
        }
        let page = address & !(PAGE_SIZE - 1);
        let mut state = self.0.lock().unwrap();
        if state.present.contains(&page) {
            return Ok(());
        }
        let Some((_, registration)) = state
            .ranges
            .range(..=page)
            .next_back()
            .filter(|(_, r)| page < r.end)
        else {
            return Ok(());
        };
        let Some(file) = registration.file.upgrade() else {
            return Ok(());
        };
        if file.user_only && !USER.with(Cell::get) {
            drop(state);
            return Err(MemoryError::Bus(address));
        }
        if state.pending.len() >= 4096 {
            state.pending.retain(|_, events| {
                events.retain(|event| event.strong_count() != 0);
                !events.is_empty()
            });
        }
        let event = Arc::new(Event {
            page,
            write: access == Access::Write,
            id: file.id,
            resolved: AtomicBool::new(false),
            wait: Default::default(),
            changed: file.changed.clone(),
            allocation: CgroupMemoryContext::capture(),
        });
        let wait = PageWait::resource(event.clone());
        let _ = event.wait.set(Arc::downgrade(&wait));
        state
            .pending
            .entry(page)
            .or_default()
            .push(Arc::downgrade(&event));
        {
            let mut queue = file.queue.lock().unwrap();
            if queue.len() >= 4096 {
                queue.retain(|e| e.strong_count() != 0);
            }
            queue.push_back(Arc::downgrade(&event));
        }
        drop(state);
        file.changed();
        Err(wait.fault(address))
    }

    pub(super) fn remove(&self, start: u64, end: u64, unregister: bool, owner: Option<u64>) {
        let mut state = self.0.lock().unwrap();
        let owned: Vec<_> = state
            .ranges
            .iter()
            .filter_map(|(&a, r)| {
                (a < end && r.end > start && owner.is_none_or(|id| id == r.id))
                    .then_some((a.max(start), r.end.min(end)))
            })
            .collect();
        if unregister {
            let keys: Vec<_> = state
                .ranges
                .iter()
                .filter_map(|(&a, r)| {
                    (a < end && r.end > start && owner.is_none_or(|id| id == r.id)).then_some(a)
                })
                .collect();
            for a in keys {
                let r = state.ranges.remove(&a).unwrap();
                if r.end > end {
                    state.ranges.insert(
                        end,
                        Registration {
                            end: r.end,
                            id: r.id,
                            file: r.file.clone(),
                        },
                    );
                }
                if a < start {
                    state.ranges.insert(a, Registration { end: start, ..r });
                }
            }
        }
        state.present.retain(|&page| {
            if owner.is_none() {
                page < start || page >= end
            } else {
                !owned.iter().any(|&(a, b)| page >= a && page < b)
            }
        });
        let events = state.take_pending(start, end, owner);
        self.1.store(!state.ranges.is_empty(), Ordering::Relaxed);
        drop(state);
        for event in events {
            event.resolved.store(true, Ordering::Relaxed);
            event.wake();
        }
    }
}
impl Event {
    fn wake(&self) {
        if let Some(wait) = self.wait.get().and_then(Weak::upgrade) {
            wait.finish();
        }
    }
}
impl trames_shared::ResourceWait for Event {
    fn ready(&self) -> bool {
        false
    }
    fn subscribe(&self, _: &Arc<trames_shared::IoSignal>) -> Vec<trames_shared::IoSubscription> {
        Vec::new()
    }
}
impl Drop for Event {
    fn drop(&mut self) {
        self.changed.notify_atomic();
    }
}
impl UserfaultFile {
    fn changed(&self) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
        self.changed.notify_atomic();
    }
    pub fn initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed)
    }
    pub fn initialize(&self) -> Result<(), u32> {
        self.initialized
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .map(|_| self.changed())
            .map_err(|_| 22)
    }
    pub fn poll(&self, events: u16, nonblocking: bool) -> (u16, [u64; 2]) {
        let ready = if !self.initialized() || !nonblocking {
            8
        } else if self
            .queue
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .any(|event| !event.resolved.load(Ordering::Relaxed))
        {
            events & 1
        } else {
            0
        };
        (ready, [self.epoch.load(Ordering::Relaxed), 0])
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.changed.subscribe(signal)
    }
    pub fn read(&self, count: usize) -> Result<Vec<u8>, u32> {
        if !self.initialized() || count < 32 {
            return Err(22);
        }
        let mut queue = self.queue.lock().unwrap();
        let mut out = Vec::new();
        while out.len() + 32 <= count {
            let Some(event) = queue.pop_front() else {
                break;
            };
            let Some(event) = event.upgrade() else {
                continue;
            };
            if event.resolved.load(Ordering::Relaxed) {
                continue;
            }
            let mut msg = [0; 32];
            msg[0] = 0x12;
            msg[8..16].copy_from_slice(&u64::from(event.write).to_le_bytes());
            msg[16..24].copy_from_slice(&event.page.to_le_bytes());
            out.extend_from_slice(&msg);
        }
        if out.is_empty() {
            Err(11)
        } else {
            Ok(out)
        }
    }
    pub fn range(start: u64, len: u64) -> Result<u64, u32> {
        if !start.is_multiple_of(PAGE_SIZE) || len == 0 || !len.is_multiple_of(PAGE_SIZE) {
            return Err(22);
        }
        start
            .checked_add(len)
            .filter(|&end| end <= ADDRESS_LIMIT)
            .ok_or(22)
    }
    pub fn register(self: &Arc<Self>, start: u64, len: u64) -> Result<Arc<MmControl>, u32> {
        let end = Self::range(start, len)?;
        let file = self.clone();
        self.report.submit_control(move |memory| {
            memory.check_mapped_range(start, end).map_err(|_| 12u32)?;
            // Only private anonymous missing faults are advertised. Shared,
            // minor and WP registration are deliberately not negotiated.
            let mut at = start;
            while at < end {
                if let Some((_, range)) = memory.anonymous.containing(at) {
                    at = range.end.min(end);
                } else {
                    let page = memory.page_for_access_unchecked(at).ok_or(12u32)?;
                    if page.backing.is_some() {
                        return Err(22);
                    }
                    at += PAGE_SIZE;
                }
            }
            {
                let state = file.faults.0.lock().unwrap();
                if state
                    .ranges
                    .iter()
                    .any(|(&a, r)| a < end && r.end > start && r.id != file.id)
                {
                    return Err(16);
                }
            }
            let mut present: BTreeSet<u64> = memory
                .pages
                .range(start..end)
                .filter_map(|(&a, &i)| {
                    memory.frames[i]
                        .as_ref()
                        .unwrap()
                        .charge
                        .present()
                        .then_some(a)
                })
                .collect();
            present.extend(
                memory
                    .sparse_pages
                    .borrow()
                    .range(start..end)
                    .filter_map(|(&a, p)| p.charge.present().then_some(a)),
            );
            present.extend(
                memory
                    .anonymous
                    .populated()
                    .into_iter()
                    .filter(|&a| a >= start && a < end),
            );
            memory.set_userfault_controlled()?;
            // Only registered ranges can introduce missing-fault imports.
            // API-only ART probes retain ordinary syscall and native paths.
            memory.has_async_sources = true;
            let mut state = file.faults.0.lock().unwrap();
            state.present.extend(present);
            // Preserve adjacent pieces, including this context's earlier range.
            let keys: Vec<_> = state
                .ranges
                .iter()
                .filter_map(|(&a, r)| (a < end && r.end > start).then_some(a))
                .collect();
            for a in keys {
                let r = state.ranges.remove(&a).unwrap();
                if r.end > end {
                    state.ranges.insert(
                        end,
                        Registration {
                            end: r.end,
                            id: r.id,
                            file: r.file.clone(),
                        },
                    );
                }
                if a < start {
                    state.ranges.insert(a, Registration { end: start, ..r });
                }
            }
            state.ranges.insert(
                start,
                Registration {
                    end,
                    id: file.id,
                    file: Arc::downgrade(&file),
                },
            );
            file.faults.1.store(true, Ordering::Relaxed);
            drop(state);
            memory.invalidate_translations();
            memory.parallel_cache = None;
            Ok(((1u64 << 2) | (1 << 3) | (1 << 4)).to_le_bytes().to_vec())
        })
    }
    pub fn unregister(self: &Arc<Self>, start: u64, len: u64) -> Result<Arc<MmControl>, u32> {
        let end = Self::range(start, len)?;
        let file = self.clone();
        self.report.submit_control(move |memory| {
            if !memory
                .region_layout
                .ranges
                .iter()
                .any(|&(a, b, _)| a < end && b > start)
            {
                return Err(22);
            }
            file.faults.remove(start, end, true, None);
            memory.invalidate_translations();
            memory.parallel_cache = None;
            Ok(Vec::new())
        })
    }
    pub fn wake(&self, start: u64, len: u64) -> Result<(), u32> {
        let end = Self::range(start, len)?;
        let mut state = self.faults.0.lock().unwrap();
        let events = state.take_pending(start, end, Some(self.id));
        drop(state);
        for e in events {
            e.resolved.store(true, Ordering::Relaxed);
            e.wake();
        }
        self.changed();
        Ok(())
    }
    pub fn fill(
        self: &Arc<Self>,
        address: u64,
        bytes: Option<Vec<u8>>,
        wake: bool,
    ) -> Result<Arc<MmControl>, u32> {
        Self::range(address, PAGE_SIZE)?;
        if bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() != PAGE_SIZE as usize)
        {
            return Err(22);
        }
        let file = self.clone();
        self.report.submit_deferred_control(move |memory| {
            let (events, allocation) = {
                let state = file.faults.0.lock().unwrap();
                if !state
                    .ranges
                    .range(..=address)
                    .next_back()
                    .is_some_and(|(_, r)| address < r.end && r.id == file.id)
                {
                    return Err(2.into());
                }
                if state.present.contains(&address) {
                    return Err(17.into());
                }
                let events: Vec<_> = state
                    .pending
                    .get(&address)
                    .into_iter()
                    .flatten()
                    .filter_map(Weak::upgrade)
                    .collect();
                let allocation = events
                    .first()
                    .map_or_else(|| file.allocation.clone(), |e| e.allocation.clone());
                (events, allocation)
            };
            let _allocation = allocation.enter();
            let _resolving = Resolving(RESOLVING.with(|v| v.replace(true)));
            // Install bytes even in a read-only VMA, as UFFDIO_COPY does. The
            // original page and physical charge remain canonical for every View.
            if let Some(mut data) = bytes {
                memory
                    .forced_bytes(address, &mut data, true)
                    .map_err(|e| match e {
                        MemoryError::Pending(fault) => ControlError::Pending(fault.wait),
                        MemoryError::Limit => ControlError::Errno(12),
                        _ => ControlError::Errno(14),
                    })?;
            } else {
                let entry = memory.translation(address).ok_or(2u32)?;
                memory.translated_page(entry).charge.note_zero_read();
            }
            let mut state = file.faults.0.lock().unwrap();
            state.present.insert(address);
            if wake {
                state.pending.remove(&address);
            }
            drop(state);
            for event in events {
                event.resolved.store(true, Ordering::Relaxed);
                if wake {
                    event.wake();
                }
            }
            memory.invalidate_translations();
            file.changed();
            Ok(Vec::new())
        })
    }
}
impl Drop for UserfaultFile {
    fn drop(&mut self) {
        self.faults.remove(0, ADDRESS_LIMIT, true, Some(self.id));
    }
}
impl Memory {
    pub fn userfaultfd(&mut self, user_only: bool) -> Arc<UserfaultFile> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().userfaultfd(user_only);
        }
        let faults = self.userfaults.get_or_insert_with(Arc::default).clone();
        self.parallel_cache = None;
        let report = self.memory_report();
        report.0.userfaults.get_or_init(|| Arc::downgrade(&faults));
        Arc::new(UserfaultFile {
            id: new_backing_identity(),
            report,
            faults,
            user_only,
            initialized: AtomicBool::new(false),
            queue: Mutex::new(VecDeque::new()),
            changed: Arc::default(),
            epoch: AtomicU64::new(0),
            allocation: CgroupMemoryContext::capture_live(),
        })
    }
    fn set_userfault_controlled(&mut self) -> Result<(), u32> {
        self.set_native_control(None, Some(true)).map_err(|_| 11)
    }
    pub(super) fn check_userfault(&self, address: u64, access: Access) -> Result<(), MemoryError> {
        if let Some(faults) = &self.userfaults {
            faults.check(address, access)?;
        }
        Ok(())
    }
}
