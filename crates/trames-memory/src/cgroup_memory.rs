// SPDX-License-Identifier: GPL-3.0-or-later
//! Hierarchical resident-page accounting on the original page lease.
use crate::{MemoryError, MemoryPressure, PressureTask, PAGE_SIZE};
use parking_lot::RwLock;
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
        Arc, Weak,
    },
};
pub(super) mod reclaim;
mod reservation;
mod writeback;
pub use reservation::CgroupReservation;
use reservation::ReservedSlice;
pub use writeback::CgroupWriteback;

#[derive(Default)]
struct Events {
    high: AtomicUsize,
    max: AtomicUsize,
    oom: AtomicUsize,
    oom_kill: AtomicUsize,
    oom_group_kill: AtomicUsize,
}

/// Reclaim only reconstructible bytes which are not in use. Implementations
/// must try object locks: admission can already hold a file or page lock.
/// Callbacks run on the requesting worker with no controller lock held.
pub trait CgroupReclaim: Send + Sync {
    fn reclaim(&self, group: &MemoryCgroup, bytes: usize) -> usize;
    /// Submit retained original dirty resources to an existing executor. No
    /// resource/layout or byte borrow may survive this callback into the wait.
    fn writeback(&self, _group: &Arc<MemoryCgroup>, _bytes: usize) -> Option<Arc<crate::PageWait>> {
        None
    }
    /// After writeback/layout quiescence, retire old mapped/native byte pins
    /// at their original mm checkpoints before retrying physical accounting.
    fn release_mappings(
        &self,
        _group: &Arc<MemoryCgroup>,
        _bytes: usize,
    ) -> Option<Arc<crate::PageWait>> {
        None
    }
}
/// Controller-owned notification identity; callbacks must not borrow an inode
/// or hierarchy. Memory admission can already hold the original data object.
pub trait CgroupMemoryEvents: Send + Sync {
    fn changed(&self);
}

/// Physical allocation category. Shmem contributes to file as in memory.stat.
#[derive(Clone, Copy)]
pub enum CgroupMemoryKind {
    Anonymous,
    File,
    Shmem,
}

#[derive(Default)]
struct Usage {
    anon: AtomicUsize,
    file: AtomicUsize,
    shmem: AtomicUsize,
    reclaimed: AtomicUsize,
}

pub struct MemoryCgroup {
    parent: Option<Arc<Self>>,
    current: AtomicUsize,
    high: AtomicUsize,
    limit: AtomicUsize,
    oom_group: AtomicBool,
    local: Events,
    events: Events,
    usage: Usage,
    reclaimers: parking_lot::Mutex<Vec<Weak<dyn CgroupReclaim>>>,
    observers: parking_lot::Mutex<Vec<(bool, Weak<dyn CgroupMemoryEvents>)>>,
    configuration: Arc<trames_shared::Readiness>,
}

impl MemoryCgroup {
    pub fn new(parent: Option<Arc<Self>>) -> Arc<Self> {
        Arc::new(Self {
            parent,
            current: AtomicUsize::new(0),
            high: AtomicUsize::new(usize::MAX),
            limit: AtomicUsize::new(usize::MAX),
            oom_group: AtomicBool::new(false),
            local: Events::default(),
            events: Events::default(),
            usage: Usage::default(),
            reclaimers: Default::default(),
            observers: Default::default(),
            configuration: Arc::default(),
        })
    }
    pub fn current(&self) -> usize {
        self.current.load(Relaxed)
    }
    pub fn limit(&self) -> usize {
        self.limit.load(Relaxed)
    }
    pub fn set_limit(&self, bytes: usize) {
        self.limit.store(bytes, Relaxed);
        self.configuration.notify_atomic();
    }
    pub fn high(&self) -> usize {
        self.high.load(Relaxed)
    }
    pub fn set_high(&self, bytes: usize) {
        self.high.store(bytes, Relaxed);
        self.configuration.notify_atomic();
    }
    pub fn subscribe_configuration(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.configuration.subscribe(signal)
    }
    pub fn oom_group(&self) -> bool {
        self.oom_group.load(Relaxed)
    }
    pub fn set_oom_group(&self, enabled: bool) {
        self.oom_group.store(enabled, Relaxed);
    }
    pub fn format_stat(&self) -> String {
        format!(
            "anon {}\nfile {}\nshmem {}\npgsteal {}\n",
            self.usage.anon.load(Relaxed),
            self.usage.file.load(Relaxed),
            self.usage.shmem.load(Relaxed),
            self.usage.reclaimed.load(Relaxed) / PAGE_SIZE as usize,
        )
    }
    pub fn reclaimed_bytes(&self) -> usize {
        self.usage.reclaimed.load(Relaxed)
    }
    fn account_reclaimed(&self, bytes: usize) {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            group.usage.reclaimed.fetch_add(bytes, Relaxed);
            cursor = group.parent.as_deref();
        }
    }
    fn account_kind(&self, kind: CgroupMemoryKind, bytes: usize, add: bool) {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            let fields: &[&AtomicUsize] = match kind {
                CgroupMemoryKind::Anonymous => &[&group.usage.anon],
                CgroupMemoryKind::File => &[&group.usage.file],
                CgroupMemoryKind::Shmem => &[&group.usage.file, &group.usage.shmem],
            };
            for field in fields {
                if add {
                    field.fetch_add(bytes, Relaxed);
                } else {
                    field.fetch_sub(bytes, Relaxed);
                }
            }
            cursor = group.parent.as_deref();
        }
    }
    pub(super) fn register_reclaimer(&self, resource: &Arc<dyn CgroupReclaim>) {
        let weak = Arc::downgrade(resource);
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            let mut resources = group.reclaimers.lock();
            resources.retain(|entry| entry.strong_count() != 0);
            if !resources.iter().any(|entry| entry.ptr_eq(&weak)) {
                resources.push(weak.clone());
            }
            cursor = group.parent.as_deref();
        }
    }
    /// One bounded pass over original resource owners. Dirty or pinned pages
    /// may prevent reclaim; callers must not infer success from a lower limit.
    pub fn reclaim(&self, bytes: usize) -> usize {
        if bytes == 0 {
            return 0;
        }
        let resources = {
            let mut resources = self.reclaimers.lock();
            resources.retain(|resource| resource.strong_count() != 0);
            resources.clone()
        };
        let mut freed = 0usize;
        for resource in resources {
            if let Some(resource) = resource.upgrade() {
                freed = freed.saturating_add(resource.reclaim(self, bytes.saturating_sub(freed)));
                if freed >= bytes {
                    break;
                }
            }
        }
        freed
    }
    /// Dirty writeback is distinct from freeing bytes. Callers retry real
    /// reclaim after this original-resource completion; a ready wait is not
    /// evidence that any physical allocation was released.
    pub fn writeback(self: &Arc<Self>, bytes: usize) -> Option<Arc<crate::PageWait>> {
        if bytes == 0 {
            return None;
        }
        let resources = {
            let mut resources = self.reclaimers.lock();
            resources.retain(|resource| resource.strong_count() != 0);
            resources.clone()
        };
        let waits: Vec<_> = resources
            .into_iter()
            .filter_map(|resource| resource.upgrade()?.writeback(self, bytes))
            .collect();
        if waits.is_empty() {
            None
        } else {
            Some(crate::PageWait::resource(Arc::new(writeback::Batch(waits))))
        }
    }
    pub fn release_mappings(self: &Arc<Self>, bytes: usize) -> Option<Arc<crate::PageWait>> {
        let resources = self.reclaimers.lock().clone();
        let waits: Vec<_> = resources
            .into_iter()
            .filter_map(|resource| resource.upgrade()?.release_mappings(self, bytes))
            .collect();
        (!waits.is_empty()).then(|| crate::PageWait::resource(Arc::new(writeback::Batch(waits))))
    }
    /// A bounded pass: unchanged writeback and mm generations are remembered
    /// by their original owners, including failures. No quota lock is held
    /// while providers run, and no ready completion is mistaken for free bytes.
    pub fn pressure(self: &Arc<Self>, bytes: usize) -> Option<Arc<crate::PageWait>> {
        let _pressure = CgroupMemoryTarget::pressure_task().map(|task| task.stall());
        let goal = self.current().saturating_sub(bytes);
        self.reclaim(bytes);
        if self.current() <= goal {
            return None;
        }
        if let Some(wait) = self.writeback(bytes).filter(|wait| !wait.ready()) {
            return Some(
                CgroupMemoryTarget::pressure_task().map_or(wait.clone(), |task| {
                    crate::PageWait::resource(task.reclaim_wait(wait))
                }),
            );
        }
        self.reclaim(bytes);
        if self.current() <= goal {
            return None;
        }
        if let Some(wait) = self.release_mappings(bytes).filter(|wait| !wait.ready()) {
            return Some(
                CgroupMemoryTarget::pressure_task().map_or(wait.clone(), |task| {
                    crate::PageWait::resource(task.reclaim_wait(wait))
                }),
            );
        }
        self.reclaim(bytes);
        None
    }
    pub fn format_events(&self, local: bool) -> String {
        let ev = if local { &self.local } else { &self.events };
        format!(
            "low 0\nhigh {}\nmax {}\noom {}\noom_kill {}\noom_group_kill {}\n",
            ev.high.load(Relaxed),
            ev.max.load(Relaxed),
            ev.oom.load(Relaxed),
            ev.oom_kill.load(Relaxed),
            ev.oom_group_kill.load(Relaxed),
        )
    }
    fn event(&self, select: impl Fn(&Events) -> &AtomicUsize) {
        select(&self.local).fetch_add(1, Relaxed);
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            select(&group.events).fetch_add(1, Relaxed);
            let observers: Vec<_> = {
                let mut entries = group.observers.lock();
                entries.retain(|(_, observer)| observer.strong_count() != 0);
                entries
                    .iter()
                    .filter(|(local, _)| !*local || std::ptr::eq(group, self))
                    .filter_map(|(_, observer)| observer.upgrade())
                    .collect()
            };
            for observer in observers {
                observer.changed();
            }
            cursor = group.parent.as_deref();
        }
    }
    pub fn observe_events(&self, local: bool, observer: &Arc<dyn CgroupMemoryEvents>) {
        let mut observers = self.observers.lock();
        observers.retain(|(_, observer)| observer.strong_count() != 0);
        let weak = Arc::downgrade(observer);
        if !observers
            .iter()
            .any(|(kind, entry)| *kind == local && entry.ptr_eq(&weak))
        {
            observers.push((local, weak));
        }
    }
    pub fn record_oom(&self) {
        self.event(|ev| &ev.oom);
    }
    pub fn is_within(&self, ancestor: &Self) -> bool {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            if std::ptr::eq(group, ancestor) {
                return true;
            }
            cursor = group.parent.as_deref();
        }
        false
    }
    pub fn oom_group_within(self: &Arc<Self>, limit: &Self) -> Option<Arc<Self>> {
        if !self.is_within(limit) {
            return None;
        }
        let mut victim = None;
        let mut current = Some(self);
        while let Some(group) = current {
            if group.oom_group() {
                victim = Some(group.clone());
            }
            if std::ptr::eq(group.as_ref(), limit) {
                break;
            }
            current = group.parent.as_ref();
        }
        victim
    }
    pub fn record_oom_kill(&self) {
        self.event(|ev| &ev.oom_kill);
    }
    pub fn record_group_kill(&self) {
        self.event(|ev| &ev.oom_group_kill);
    }
    fn take(self: &Arc<Self>, bytes: usize) -> Result<bool, AdmissionError> {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            let high = group.high();
            let excess = group.current().saturating_add(bytes).saturating_sub(high);
            if excess != 0 {
                if let Some(wait) = group.pressure(excess) {
                    return Err(AdmissionError::Pending(crate::PageWait::resource(
                        Arc::new(HighWait {
                            wait,
                            group: group.clone(),
                            high,
                        }),
                    )));
                }
            }
            cursor = group.parent.as_ref();
        }
        if let Err(failed) = self.try_take(bytes) {
            failed.event(|ev| &ev.max);
            let needed = failed
                .current()
                .saturating_add(bytes)
                .saturating_sub(failed.limit());
            failed.reclaim(needed);
            if let Err(failed) = self.try_take(bytes) {
                let needed = failed
                    .current()
                    .saturating_add(bytes)
                    .saturating_sub(failed.limit());
                if let Some(wait) = failed.pressure(needed) {
                    return Err(AdmissionError::Pending(crate::PageWait::resource(
                        Arc::new(QuotaWait {
                            wait,
                            group: self.clone(),
                            bytes,
                        }),
                    )));
                }
                match self.try_take(bytes) {
                    Ok(()) => return Ok(self.above_high()),
                    Err(failed) => {
                        failed.event(|ev| &ev.oom);
                        return Err(AdmissionError::Oom(failed));
                    }
                }
            }
        }
        let mut high = false;
        let mut cursor = Some(self.as_ref());
        while let Some(group) = cursor {
            if group.current() > group.high() {
                group.event(|ev| &ev.high);
                group.reclaim(group.current().saturating_sub(group.high()));
                high |= group.current() > group.high();
            }
            cursor = group.parent.as_deref();
        }
        Ok(high)
    }
    fn above_high(&self) -> bool {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            if group.current() > group.high() {
                return true;
            }
            cursor = group.parent.as_deref();
        }
        false
    }
    fn try_take(self: &Arc<Self>, bytes: usize) -> Result<(), Arc<Self>> {
        if let Some(parent) = &self.parent {
            parent.try_take(bytes)?;
        }
        let limit = self.limit();
        let update = self.current.try_update(Relaxed, Relaxed, |used| {
            used.checked_add(bytes).filter(|&next| next <= limit)
        });
        let Ok(_) = update else {
            if let Some(parent) = &self.parent {
                parent.release_bytes(bytes);
            }
            return Err(self.clone());
        };
        Ok(())
    }
    pub(super) fn release(&self) {
        self.release_bytes(PAGE_SIZE as usize);
    }
    fn release_bytes(&self, bytes: usize) {
        let mut cursor = Some(self);
        while let Some(group) = cursor {
            group.current.fetch_sub(bytes, Relaxed);
            cursor = group.parent.as_deref();
        }
    }
}
enum AdmissionError {
    Pending(Arc<crate::PageWait>),
    Oom(Arc<MemoryCgroup>),
}
struct HighWait {
    wait: Arc<crate::PageWait>,
    group: Arc<MemoryCgroup>,
    high: usize,
}
impl trames_shared::ResourceWait for HighWait {
    fn ready(&self) -> bool {
        self.wait.ready() || self.group.high() != self.high
    }
    fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        let mut subscriptions = self.wait.subscribe(signal);
        subscriptions.push(self.group.subscribe_configuration(signal));
        subscriptions
    }
    fn deadline(&self) -> Option<std::time::Instant> {
        self.wait.deadline()
    }
}
struct QuotaWait {
    wait: Arc<crate::PageWait>,
    group: Arc<MemoryCgroup>,
    bytes: usize,
}
impl trames_shared::ResourceWait for QuotaWait {
    fn ready(&self) -> bool {
        if self.wait.ready() {
            return true;
        }
        let mut cursor = Some(self.group.as_ref());
        while let Some(group) = cursor {
            if group.limit().saturating_sub(group.current()) < self.bytes {
                return false;
            }
            cursor = group.parent.as_deref();
        }
        true
    }
    fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        let mut subscriptions = self.wait.subscribe(signal);
        let mut cursor = Some(self.group.as_ref());
        while let Some(group) = cursor {
            subscriptions.push(group.subscribe_configuration(signal));
            cursor = group.parent.as_deref();
        }
        subscriptions
    }
    fn deadline(&self) -> Option<std::time::Instant> {
        self.wait.deadline()
    }
}

#[derive(Default)]
pub struct CgroupMemoryTarget {
    pressure: std::sync::OnceLock<Arc<PressureTask>>,
    pressure_delay: parking_lot::Mutex<Option<crate::pressure::PressureStall>>,
    current: RwLock<Option<Arc<MemoryCgroup>>>,
    oom: parking_lot::Mutex<Option<(Arc<MemoryCgroup>, Arc<MemoryCgroup>)>>,
    high_pages: AtomicUsize,
}

thread_local! {
    static SOURCE: RefCell<Option<Binding>> = const { RefCell::new(None) };
}
#[derive(Clone)]
enum Binding {
    Root,
    Live(Arc<CgroupMemoryTarget>),
    Frozen {
        target: Arc<CgroupMemoryTarget>,
        group: Option<Arc<MemoryCgroup>>,
    },
}
impl Binding {
    fn resolve(&self) -> Option<(Arc<CgroupMemoryTarget>, Option<Arc<MemoryCgroup>>)> {
        match self {
            Self::Root => None,
            Self::Live(target) => Some((target.clone(), target.current.read().clone())),
            Self::Frozen { target, group } => Some((target.clone(), group.clone())),
        }
    }
}
/// Accepted asynchronous work keeps its allocation owner across migration and
/// execution on another worker. Feedback still reaches the original task.
#[derive(Clone)]
pub struct CgroupMemoryContext(Binding);
impl Default for CgroupMemoryContext {
    fn default() -> Self {
        Self(Binding::Root)
    }
}
impl CgroupMemoryContext {
    /// An mm provider follows its original task's current allocation target.
    /// Individual faults freeze this binding when they are actually accepted.
    pub(crate) fn capture_live() -> Self {
        Self(SOURCE.with(|slot| match slot.borrow().as_ref() {
            Some(Binding::Live(target) | Binding::Frozen { target, .. }) => {
                Binding::Live(target.clone())
            }
            _ => Binding::Root,
        }))
    }

    pub fn capture() -> Self {
        Self(SOURCE.with(|slot| {
            slot.borrow().as_ref().and_then(Binding::resolve).map_or(
                Binding::Root,
                |(target, group)| Binding::Frozen { target, group },
            )
        }))
    }
    pub fn enter(&self) -> CgroupMemoryScope {
        CgroupMemoryScope {
            previous: SOURCE.with(|slot| slot.replace(Some(self.0.clone()))),
            _executor: std::marker::PhantomData,
        }
    }
    pub fn enter_if_absent(&self) -> Option<CgroupMemoryScope> {
        if SOURCE.with(|source| source.borrow().is_some()) {
            None
        } else {
            Some(self.enter())
        }
    }
}
pub struct CgroupMemoryScope {
    previous: Option<Binding>,
    _executor: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Drop for CgroupMemoryScope {
    fn drop(&mut self) {
        SOURCE.with(|source| {
            source.replace(self.previous.take());
        });
    }
}

impl CgroupMemoryTarget {
    pub fn finish_pressure_execution(&self) {
        if let Some(pressure) = self.pressure.get() {
            pressure.execution_finished();
        }
    }
    pub fn bind_pressure(&self, domain: &Arc<MemoryPressure>) -> Arc<PressureTask> {
        self.pressure.get_or_init(|| domain.task()).clone()
    }
    pub fn memory_pressure_task(&self) -> Option<Arc<PressureTask>> {
        self.pressure.get().cloned()
    }
    pub fn pressure_delay_until(&self, deadline: std::time::Instant) {
        if let Some(task) = self.pressure.get() {
            *self.pressure_delay.lock() = Some(task.stall_until(Some(deadline)));
        }
    }
    pub(crate) fn pressure_task() -> Option<Arc<PressureTask>> {
        SOURCE.with(|source| match source.borrow().as_ref() {
            Some(Binding::Live(target) | Binding::Frozen { target, .. }) => {
                target.pressure.get().cloned()
            }
            _ => None,
        })
    }
    pub(crate) fn pressure_admitted() {
        SOURCE.with(|source| {
            if let Some(Binding::Live(target) | Binding::Frozen { target, .. }) =
                source.borrow().as_ref()
            {
                if let Some(task) = target.pressure.get() {
                    task.admitted();
                }
            }
        });
    }

    /// Available whole-page allocation in the current resource actor. This is
    /// an admission hint; the hierarchical atomic take remains authoritative.
    pub fn allocation_capacity() -> usize {
        let group = SOURCE.with(|source| {
            source
                .borrow()
                .as_ref()
                .and_then(Binding::resolve)
                .and_then(|(_, group)| group)
        });
        let mut cursor = group.as_deref();
        let mut capacity = usize::MAX;
        while let Some(group) = cursor {
            capacity = capacity.min(group.limit().saturating_sub(group.current()));
            cursor = group.parent.as_deref();
        }
        capacity
    }
    pub fn set(&self, group: Option<Arc<MemoryCgroup>>) -> bool {
        let mut current = self.current.write();
        let changed = match (&*current, &group) {
            (Some(old), Some(next)) => !Arc::ptr_eq(old, next),
            (None, None) => false,
            _ => true,
        };
        *current = group;
        changed
    }
    pub fn controlled(&self) -> bool {
        self.current.read().is_some()
    }
    pub fn scope(self: &Arc<Self>) -> CgroupMemoryScope {
        CgroupMemoryScope {
            previous: SOURCE.with(|slot| slot.replace(Some(Binding::Live(self.clone())))),
            _executor: std::marker::PhantomData,
        }
    }
    pub fn take_oom(&self) -> Option<(Arc<MemoryCgroup>, Arc<MemoryCgroup>)> {
        self.oom.lock().take()
    }
    pub fn above_high(&self) -> bool {
        self.high_pages.load(Relaxed) != 0
    }
    pub fn high_delay(&self) -> std::time::Duration {
        // Bound a single delay while the guest is over its configured high mark.
        // The executor releases its slot between bursts of page admissions.
        std::time::Duration::from_micros(self.high_pages.swap(0, Relaxed).min(500) as u64 * 100)
    }
    /// Whether the current accepted resource context enforces memory limits.
    /// Short file paths use this before effects so pressure can retain the
    /// original request instead of escaping through an errno-only interface.
    pub fn active() -> bool {
        SOURCE.with(|s| {
            s.borrow()
                .as_ref()
                .and_then(Binding::resolve)
                .is_some_and(|(_, group)| group.is_some())
        })
    }
    pub(super) fn charge_page() -> Result<Option<Arc<MemoryCgroup>>, MemoryError> {
        Self::charge_bytes(PAGE_SIZE as usize)
    }
    fn charge_bytes(bytes: usize) -> Result<Option<Arc<MemoryCgroup>>, MemoryError> {
        if bytes == 0 {
            return Ok(None);
        }
        let binding = SOURCE.with(|s| s.borrow().clone());
        (|| {
            let Some(binding) = binding else {
                return Ok(None);
            };
            let Some((target, group)) = binding.resolve() else {
                return Ok(None);
            };
            let Some(group) = group else {
                return Ok(None);
            };
            match group.take(bytes) {
                Ok(high) => {
                    if high {
                        target
                            .high_pages
                            .fetch_add(bytes.div_ceil(PAGE_SIZE as usize), Relaxed);
                    }
                    Ok(Some(group))
                }
                Err(AdmissionError::Pending(wait)) => Err(wait.fault(0)),
                Err(AdmissionError::Oom(failed)) => {
                    *target.oom.lock() = Some((group, failed));
                    Err(MemoryError::Limit)
                }
            }
        })()
    }
}

/// One physical guest page's cgroup lease, independent of per-mm RSS tickets.
/// Uncontrolled/root-owned pages need no extra allocation. A shared cache cell
/// nevertheless remembers that first ownership so task migration cannot charge
/// an existing root page to a later reader's cgroup.
pub(super) struct PhysicalCharge(
    Option<Arc<MemoryCgroup>>,
    CgroupMemoryKind,
    Option<ReservedSlice>,
    AtomicBool,
);
impl PhysicalCharge {
    pub(super) fn owner(&self) -> Option<Arc<MemoryCgroup>> {
        self.0.clone()
    }
    pub(super) fn register_reclaimer(&self, resource: &Arc<dyn CgroupReclaim>) {
        if let Some(group) = &self.0 {
            group.register_reclaimer(resource);
        }
    }
    pub(super) fn new() -> Result<Option<Arc<Self>>, MemoryError> {
        Self::of_kind(CgroupMemoryKind::Anonymous)
    }
    fn of_kind(kind: CgroupMemoryKind) -> Result<Option<Arc<Self>>, MemoryError> {
        CgroupMemoryTarget::charge_page().map(|group| {
            group.map(|group| {
                group.account_kind(kind, PAGE_SIZE as usize, true);
                Arc::new(Self(Some(group), kind, None, AtomicBool::new(false)))
            })
        })
    }
    /// Fork needs an identity even for an uncharged root page. Ordinary root
    /// first touches still avoid a lease allocation.
    pub(super) fn root() -> Arc<Self> {
        Arc::new(Self(
            None,
            CgroupMemoryKind::Anonymous,
            None,
            AtomicBool::new(false),
        ))
    }
}
impl Drop for PhysicalCharge {
    fn drop(&mut self) {
        if let Some(slice) = &self.2 {
            slice.release();
            return;
        }
        if let Some(group) = &self.0 {
            group.account_kind(self.1, PAGE_SIZE as usize, false);
            group.release();
            if self.3.load(Relaxed) {
                group.account_reclaimed(PAGE_SIZE as usize);
            }
        }
    }
}

/// Lease for physical bytes held outside a guest page table. Cloning a lease
/// shares ownership; a physical copy must request a new lease instead.
#[derive(Clone)]
pub struct CgroupPageCharge(Option<Arc<PhysicalCharge>>);
impl CgroupPageCharge {
    pub(super) fn existing(charge: Option<Arc<PhysicalCharge>>) -> Self {
        Self(charge)
    }
    pub fn new(kind: CgroupMemoryKind) -> Result<Self, MemoryError> {
        PhysicalCharge::of_kind(kind).map(Self)
    }
    pub fn register_reclaimer(&self, resource: &Arc<dyn CgroupReclaim>) {
        if let Some(group) = self.0.as_ref().and_then(|charge| charge.0.as_ref()) {
            group.register_reclaimer(resource);
        }
    }
    /// Bind an admitted allocation to its actual bytes. Aliases retain this
    /// same page; allocating a physical copy requires a separate lease.
    pub fn bind(&self, page: &Arc<crate::SharedPage>) {
        if page.cgroup_ready.load(Relaxed) {
            return;
        }
        let mut physical = page.cgroup.lock();
        if physical.is_none() {
            *physical = Some(self.0.clone());
            page.cgroup_ready.store(true, Relaxed);
        }
    }
}

#[derive(Default)]
struct CacheOwner {
    charge: Option<Option<Arc<PhysicalCharge>>>,
    bytes: Weak<crate::SharedPage>,
    resources: Vec<Weak<dyn CgroupReclaim>>,
}
pub(super) struct SharedCharge(parking_lot::Mutex<CacheOwner>, CgroupMemoryKind);
impl Default for SharedCharge {
    fn default() -> Self {
        Self::new(CgroupMemoryKind::File)
    }
}
impl SharedCharge {
    pub(super) fn reset(&mut self) {
        *self.0.get_mut() = CacheOwner::default();
    }
    fn register_resources(owner: &mut CacheOwner) {
        owner
            .resources
            .retain(|resource| resource.strong_count() != 0);
        if let Some(physical) = owner.charge.as_ref().and_then(Option::as_ref) {
            for resource in owner.resources.iter().filter_map(Weak::upgrade) {
                physical.register_reclaimer(&resource);
            }
        }
    }
    pub(super) fn physical_owner(&self) -> Option<Arc<MemoryCgroup>> {
        self.0.try_lock()?.charge.as_ref()?.as_ref()?.0.clone()
    }
    pub(super) fn mark_reclaimed(&self) -> bool {
        let Some(owner) = self.0.try_lock() else {
            return false;
        };
        let Some(physical) = owner.charge.as_ref().and_then(Option::as_ref) else {
            return false;
        };
        // Only pressure eviction uses this marker. Truncation and normal last
        // close do not contribute to pgsteal. The final lease accounts once in
        // its original group and ancestors, even if an old byte pin survives.
        physical.3.store(true, Relaxed);
        true
    }
    pub(super) fn new(kind: CgroupMemoryKind) -> Self {
        Self(Default::default(), kind)
    }
    pub(super) fn adopt(&self, charge: &CgroupPageCharge) {
        let mut owner = self.0.lock();
        debug_assert!(
            owner
                .bytes
                .upgrade()
                .is_none_or(|bytes| !bytes.cgroup_ready.load(Relaxed)),
            "adopt before byte publication"
        );
        owner.charge = Some(charge.0.clone());
        Self::register_resources(&mut owner);
    }
    pub(super) fn get(&self) -> Result<Option<Arc<PhysicalCharge>>, MemoryError> {
        let mut owner = self.0.lock();
        let charge = if let Some(page) = owner.bytes.upgrade() {
            let mut physical = page.cgroup.lock();
            if let Some(charge) = &*physical {
                charge.clone()
            } else {
                let charge = if let Some(charge) = &owner.charge {
                    charge.clone()
                } else {
                    PhysicalCharge::of_kind(self.1)?
                };
                *physical = Some(charge.clone());
                page.cgroup_ready.store(true, Relaxed);
                charge
            }
        } else if let Some(charge) = &owner.charge {
            charge.clone()
        } else {
            PhysicalCharge::of_kind(self.1)?
        };
        owner.charge = Some(charge.clone());
        Self::register_resources(&mut owner);
        Ok(charge)
    }
    pub(super) fn existing(&self) -> Option<Arc<PhysicalCharge>> {
        self.0.lock().charge.as_ref().and_then(Clone::clone)
    }
    pub(super) fn bind(&self, page: &Arc<crate::SharedPage>) {
        let mut owner = self.0.lock();
        owner.bytes = Arc::downgrade(page);
        if let Some(charge) = &*page.cgroup.lock() {
            owner.charge = Some(charge.clone());
        }
        Self::register_resources(&mut owner);
    }
    pub(super) fn publish(&self, page: &Arc<crate::SharedPage>) -> Result<(), MemoryError> {
        // This scalar only skips repeated binding; byte access still uses its
        // original guards. No new ordering is imposed on normal guest loads.
        if page.cgroup_ready.load(Relaxed) {
            return Ok(());
        }
        let mut owner = self.0.lock();
        let mut physical = page.cgroup.lock();
        let charge = if let Some(charge) = &*physical {
            charge.clone()
        } else if let Some(charge) = &owner.charge {
            charge.clone()
        } else {
            PhysicalCharge::of_kind(self.1)?
        };
        *physical = Some(charge.clone());
        owner.charge = Some(charge);
        owner.bytes = Arc::downgrade(page);
        Self::register_resources(&mut owner);
        page.cgroup_ready.store(true, Relaxed);
        Ok(())
    }
    pub(super) fn retain_existing(&self, page: &Arc<crate::SharedPage>) {
        if page.cgroup_ready.load(Relaxed) {
            return;
        }
        let mut owner = self.0.lock();
        owner.bytes = Arc::downgrade(page);
        let mut physical = page.cgroup.lock();
        if let Some(charge) = &*physical {
            owner.charge = Some(charge.clone());
        } else if let Some(charge) = &owner.charge {
            *physical = Some(charge.clone());
            page.cgroup_ready.store(true, Relaxed);
        }
        Self::register_resources(&mut owner);
    }
    pub(super) fn invalidate(&self) {
        let mut owner = self.0.lock();
        let resources = std::mem::take(&mut owner.resources);
        *owner = CacheOwner {
            resources,
            ..CacheOwner::default()
        };
    }
    pub(super) fn register_reclaimer(&self, resource: &Arc<dyn CgroupReclaim>) {
        let mut owner = self.0.lock();
        let weak = Arc::downgrade(resource);
        if !owner.resources.iter().any(|old| old.ptr_eq(&weak)) {
            owner.resources.push(weak);
        }
        Self::register_resources(&mut owner);
    }
    pub(super) fn is_within(&self, group: &MemoryCgroup) -> bool {
        self.0.try_lock().is_some_and(|owner| {
            owner
                .charge
                .as_ref()
                .and_then(|charge| charge.as_ref())
                .and_then(|charge| charge.0.as_ref())
                .is_some_and(|owner| owner.is_within(group))
        })
    }
    pub(super) fn cancel_unused(&self) {
        let mut owner = self.0.lock();
        if owner.charge.as_ref().is_some_and(|charge| {
            charge
                .as_ref()
                .is_none_or(|charge| Arc::strong_count(charge) == 1)
        }) {
            owner.charge = None;
        }
    }
}

#[cfg(test)]
#[path = "cgroup_cache_tests.rs"]
mod cache_tests;

#[cfg(test)]
#[path = "cgroup_cow_tests.rs"]
mod cow_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Memory, Permissions};

    #[test]
    fn raising_high_wakes_admission_without_completing_original_writeback() {
        struct Held(Arc<crate::PageWait>);
        impl CgroupReclaim for Held {
            fn reclaim(&self, _: &MemoryCgroup, _: usize) -> usize {
                0
            }
            fn writeback(&self, _: &Arc<MemoryCgroup>, _: usize) -> Option<Arc<crate::PageWait>> {
                Some(self.0.clone())
            }
        }
        let group = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _scope = target.scope();
        let held = Arc::new(Held(Arc::default()));
        let resource: Arc<dyn CgroupReclaim> = held.clone();
        let allocation = CgroupPageCharge::new(CgroupMemoryKind::File).unwrap();
        allocation.register_reclaimer(&resource);
        group.set_high(PAGE_SIZE as usize);
        let wait = match CgroupPageCharge::new(CgroupMemoryKind::Anonymous) {
            Err(MemoryError::Pending(fault)) => fault.wait,
            _ => panic!("high pressure retains its original wait"),
        };
        assert!(!wait.ready());
        group.set_high(usize::MAX);
        assert!(wait.ready());
        assert!(!held.0.ready());
        let next = CgroupPageCharge::new(CgroupMemoryKind::Anonymous).unwrap();
        assert_eq!(group.current(), 2 * PAGE_SIZE as usize);
        drop((next, allocation));
        assert_eq!(group.current(), 0);
    }
    #[test]
    fn physical_byte_pins_outlive_cache_invalidation_and_aliases_keep_one_owner() {
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(first.clone()));
        let _scope = target.scope();
        let owners = crate::MappedResidents::with_kind(CgroupMemoryKind::Shmem);
        let bytes = Arc::new(crate::SharedPage::zero());
        owners.bind_cache(&bytes);
        owners.reserve_cache().unwrap();
        let alias = crate::MappedResidents::default();
        alias.bind_cache(&bytes);
        target.set(Some(second.clone()));
        alias.reserve_cache().unwrap();
        assert_eq!(first.current(), PAGE_SIZE as usize);
        assert_eq!(second.current(), 0);
        owners.invalidate_cache();
        alias.invalidate_cache();
        assert_eq!(
            first.current(),
            PAGE_SIZE as usize,
            "external byte pin retains the allocation"
        );
        drop(bytes);
        assert_eq!(first.current(), 0);
        let fresh = Arc::new(crate::SharedPage::zero());
        owners.bind_cache(&fresh);
        owners.publish_cache(&fresh).unwrap();
        assert_eq!(second.current(), PAGE_SIZE as usize);
        drop(owners);
        assert_eq!(second.current(), PAGE_SIZE as usize);
        drop(fresh);
        assert_eq!(second.current(), 0);
    }

    #[test]
    fn accepted_work_keeps_its_group_but_reports_pressure_to_original_task() {
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        first.set_limit(PAGE_SIZE as usize);
        first.set_high(0);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(first.clone()));
        let scope = target.scope();
        let accepted = CgroupMemoryContext::capture();
        target.set(Some(second.clone()));
        drop(scope);
        std::thread::spawn(move || {
            let _scope = accepted.enter();
            let lease = CgroupPageCharge::new(CgroupMemoryKind::Shmem).unwrap();
            assert!(CgroupPageCharge::new(CgroupMemoryKind::File).is_err());
            lease
        })
        .join()
        .unwrap();
        assert!(!target.high_delay().is_zero());
        let (origin, failed) = target.take_oom().unwrap();
        assert!(Arc::ptr_eq(&origin, &first) && Arc::ptr_eq(&failed, &first));
        assert_eq!(first.current(), 0);
        assert_eq!(second.current(), 0);
    }

    #[test]
    fn root_snapshot_does_not_inherit_the_delivering_workers_group() {
        let root = CgroupMemoryContext::capture();
        let group = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _worker = target.scope();
        {
            let _accepted = root.enter();
            let _page = CgroupPageCharge::new(CgroupMemoryKind::File).unwrap();
            assert_eq!(group.current(), 0);
        }
        let page = CgroupPageCharge::new(CgroupMemoryKind::Shmem).unwrap();
        let alias = page.clone();
        drop(page);
        assert_eq!(group.current(), PAGE_SIZE as usize);
        assert!(group
            .format_stat()
            .contains(&format!("file {}\nshmem {}\n", PAGE_SIZE, PAGE_SIZE)));
        drop(alias);
        assert_eq!(group.current(), 0);
    }

    #[test]
    fn resident_pages_keep_the_controller_that_accepted_them() {
        let parent = MemoryCgroup::new(None);
        let child = MemoryCgroup::new(Some(parent.clone()));
        let other = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(child.clone()));
        let _scope = target.scope();
        let mut memory = Memory::default();
        let start = PAGE_SIZE;
        memory.map(start, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(child.current(), 0);
        memory.write_array(start, [1]).unwrap();
        target.set(Some(other.clone()));
        memory.write_array(start + PAGE_SIZE, [2]).unwrap();
        assert_eq!(child.current(), PAGE_SIZE as usize);
        assert_eq!(parent.current(), PAGE_SIZE as usize);
        assert_eq!(other.current(), PAGE_SIZE as usize);
        memory.unmap(start, PAGE_SIZE).unwrap();
        assert_eq!(child.current(), 0);
        assert_eq!(parent.current(), 0);
        assert_eq!(other.current(), PAGE_SIZE as usize);
    }

    #[test]
    fn a_failed_hierarchical_charge_rolls_back_and_reports_its_limit() {
        let parent = MemoryCgroup::new(None);
        let child = MemoryCgroup::new(Some(parent.clone()));
        child.set_limit(PAGE_SIZE as usize);
        child.set_high(0);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(child.clone()));
        let _scope = target.scope();
        let mut memory = Memory::default();
        memory
            .map(PAGE_SIZE, 2 * PAGE_SIZE, Permissions::RW)
            .unwrap();
        memory.write_array(PAGE_SIZE, [1]).unwrap();
        assert!(!target.high_delay().is_zero());
        assert_eq!(
            memory.write_array(2 * PAGE_SIZE, [1]),
            Err(MemoryError::Limit)
        );
        assert_eq!(parent.current(), PAGE_SIZE as usize);
        let (origin, limit) = target.take_oom().unwrap();
        assert!(Arc::ptr_eq(&origin, &child) && Arc::ptr_eq(&limit, &child));
        memory.unmap(PAGE_SIZE, PAGE_SIZE).unwrap();
        memory.write_array(2 * PAGE_SIZE, [1]).unwrap();
        assert_eq!(parent.current(), PAGE_SIZE as usize);
    }
}
