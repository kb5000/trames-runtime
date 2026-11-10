// SPDX-License-Identifier: GPL-3.0-or-later
//! VM quiescence owns jobs, never their guest bytes. The queue mutex publishes
//! handoff; the relaxed bit only asks a running CPU to return its current slice.
// Jobs retain their allocation through queues and VM checkpoints.
// Moving only Box pointers also avoids copying CPUs and translation caches.
#![allow(clippy::vec_box)]
use super::*;
use std::sync::{atomic::AtomicBool, mpsc::Sender};

pub(crate) struct Domain {
    pub id: u64,
    paused: AtomicBool,
    host_pause: Arc<AtomicBool>,
    interrupts: Mutex<BTreeMap<usize, Active>>,
}
struct Active {
    interrupt: Option<Arc<dyn trames_engine::ExecutionInterrupt>>,
    pending: Arc<AtomicBool>,
    barriers: Vec<Arc<crate::barrier::Request>>,
}

/// Bound once per running job, not per instruction, syscall or CPU slice.
/// Publication and pause share this object lock, closing the pre-entry race.
/// No guest data or execution is covered by the lock.
pub(crate) struct ExecutionGuard {
    domain: Arc<Domain>,
    slot: usize,
    pending: Arc<AtomicBool>,
    scoped: bool,
}
impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        let active = self
            .domain
            .interrupts
            .lock()
            .unwrap()
            .remove(&self.slot)
            .expect("original execution lease");
        // Actual barrier requests order both guest CPU and synchronous native
        // accesses on this host executor. Ordinary lease retirement adds no fence.
        if !active.barriers.is_empty() {
            std::sync::atomic::fence(Ordering::SeqCst);
            for barrier in active.barriers {
                barrier.acknowledge();
            }
        }
    }
}
impl ExecutionGuard {
    pub fn pending(&self) -> bool {
        self.pending.load(Ordering::Relaxed)
    }
    pub fn bind_interrupt(&self, interrupt: Arc<dyn trames_engine::ExecutionInterrupt>) -> bool {
        let mut active = self.domain.interrupts.lock().unwrap();
        let running = active
            .get_mut(&self.slot)
            .expect("original execution lease");
        running.interrupt = Some(interrupt);
        (self.scoped || !self.domain.paused()) && !self.pending()
    }
}
impl Domain {
    #[cfg(all(test, trames_interpreter_conformance))]
    fn bind_interrupt(
        self: &Arc<Self>,
        slot: usize,
        interrupt: Arc<dyn trames_engine::ExecutionInterrupt>,
    ) -> Option<ExecutionGuard> {
        let guard = self.enter(slot, Arc::new(AtomicBool::new(false)))?;
        guard.bind_interrupt(interrupt).then_some(guard)
    }
    pub fn enter(
        self: &Arc<Self>,
        slot: usize,
        pending: Arc<AtomicBool>,
    ) -> Option<ExecutionGuard> {
        self.enter_inner(slot, pending, false)
    }
    pub fn enter_scoped(self: &Arc<Self>, slot: usize) -> ExecutionGuard {
        self.enter_inner(slot, Arc::new(AtomicBool::new(false)), true)
            .expect("owned mapping execution")
    }
    fn enter_inner(
        self: &Arc<Self>,
        slot: usize,
        pending: Arc<AtomicBool>,
        scoped: bool,
    ) -> Option<ExecutionGuard> {
        let mut active = self.interrupts.lock().unwrap();
        let host_paused = self.host_pause.load(Ordering::Relaxed);
        if (self.paused() || host_paused) && !scoped {
            return None;
        }
        // Accepted scoped work may finish while paused, but its optional guest
        // instruction batch must not start. Ordinary entry keeps one lease.
        pending.store(host_paused, Ordering::Relaxed);
        assert!(
            active
                .insert(
                    slot,
                    Active {
                        interrupt: None,
                        pending: pending.clone(),
                        barriers: Vec::new()
                    }
                )
                .is_none(),
            "one running job per worker"
        );
        Some(ExecutionGuard {
            domain: self.clone(),
            slot,
            pending,
            scoped,
        })
    }
    pub fn barrier(&self, request: &Arc<crate::barrier::Request>, caller: usize) {
        let mut active = self.interrupts.lock().unwrap();
        for (&slot, running) in active.iter_mut() {
            if slot == caller {
                continue;
            }
            request.add();
            running.barriers.push(request.clone());
            running.pending.store(true, Ordering::Relaxed);
            if let Some(interrupt) = &running.interrupt {
                interrupt.request_exit();
            }
        }
    }
    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
        self.interrupt();
    }
    pub fn interrupted(&self) -> bool {
        self.paused() || self.host_pause.load(Ordering::Relaxed)
    }
    fn interrupt(&self) {
        // A CPU published before pause is kicked, including a not-yet-entered
        // CPU (the backend must latch the request). A later binder cannot enter.
        for active in self.interrupts.lock().unwrap().values() {
            active.pending.store(true, Ordering::Relaxed);
            if let Some(interrupt) = &active.interrupt {
                interrupt.request_exit();
            }
        }
    }
    pub fn paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
}
struct Entry<C: Cpu> {
    domain: Arc<Domain>,
    keys: BTreeSet<(u8, u64)>,
    jobs: Vec<Box<Job<C>>>,
    running: usize,
    members: usize,
    notified: bool,
    owned: bool,
    source_owned: bool,
    repeat_bytes: bool,
    mm_only: bool,
    proc_reads: bool,
    layouts: bool,
    requested: Option<Instant>,
    quiescent: Option<Instant>,
}
#[derive(Default)]
pub(super) struct Domains<C: Cpu> {
    pub host_pause: Arc<AtomicBool>,
    entries: BTreeMap<u64, Entry<C>>,
    tasks: BTreeMap<u32, u64>,
    retired: Vec<u64>,
    #[cfg(all(test, trames_interpreter_conformance))]
    pub events: Option<Sender<crate::workers::Event<C>>>,
    pub source_lifecycle: bool,
}
pub(crate) struct Checkpoint<C: Cpu> {
    pub ids: BTreeSet<u64>,
    pub mm_only: bool,
    pub proc_reads: bool,
    pub layouts: bool,
    pub layout_only: bool,
    pub source_retry: bool,
    pub jobs: Vec<Box<Job<C>>>,
    pub requested: Instant,
    pub quiescent: Instant,
    pub taken: Instant,
    source_owned: bool,
    requesters: BTreeSet<u32>,
}
impl<C: Cpu> Domains<C> {
    pub fn barrier_domains(&self, original: u64, global: bool) -> Vec<Arc<Domain>> {
        if global {
            self.entries
                .values()
                .map(|entry| entry.domain.clone())
                .collect()
        } else {
            vec![self.entries[&original].domain.clone()]
        }
    }
    pub fn interrupt_host_pause(&self) {
        for entry in self.entries.values() {
            entry.domain.interrupt();
        }
    }
    pub fn new(_events: Option<Sender<crate::workers::Event<C>>>) -> Self {
        Self {
            #[cfg(all(test, trames_interpreter_conformance))]
            events: _events,
            ..Self::default()
        }
    }
    pub fn register(&mut self, job: &mut Job<C>) {
        let view = job.work.memory.as_deref().expect("cohort view");
        let id = trames_memory::CpuMemory::instruction_identity(view).0;
        let pending = view.layout_requested();
        self.register_metadata(job, id, view.commit_domains());
        if pending {
            self.pause_layouts(job.work.pid);
        }
    }
    pub fn register_waiting(&mut self, job: &mut Job<C>, id: u64) {
        self.register_metadata(job, id, BTreeSet::new());
    }
    fn register_metadata(&mut self, job: &mut Job<C>, id: u64, keys: BTreeSet<(u8, u64)>) {
        let entry = self.entries.entry(id).or_insert_with(|| Entry::<C> {
            domain: Arc::new(Domain {
                id,
                paused: AtomicBool::new(false),
                host_pause: self.host_pause.clone(),
                interrupts: Mutex::new(BTreeMap::new()),
            }),
            keys,
            jobs: Vec::new(),
            running: 0,
            members: 0,
            notified: false,
            owned: false,
            source_owned: false,
            repeat_bytes: false,
            mm_only: false,
            proc_reads: false,
            layouts: false,
            requested: None,
            quiescent: None,
        });
        entry.members += 1;
        assert!(self.tasks.insert(job.work.pid, id).is_none());
        job.domain = Some(entry.domain.clone());
    }
    pub fn retire(&mut self, pid: u32) {
        let id = self.tasks.remove(&pid).expect("returned original task");
        let entry = self.entries.get_mut(&id).unwrap();
        entry.members -= 1;
        if entry.members == 0 {
            assert_eq!(entry.running, 0);

            assert!(entry.jobs.is_empty());
            if !entry.owned {
                self.entries.remove(&id);
                if self.source_lifecycle {
                    self.retired.push(id);
                }
            }
        }
    }
    /// An exec checkpoint owns this returned job; keep the empty owned entry
    /// until restore consumes its scope, even when its last PID was replaced.
    pub fn forget_owned(&mut self, pid: u32) {
        let id = self.tasks.remove(&pid).expect("owned original task");
        let entry = self.entries.get_mut(&id).unwrap();
        assert!(entry.owned && entry.domain.paused());
        assert_eq!(entry.running, 0);

        entry.members -= 1;
    }
    pub fn contains(&self, id: u64) -> bool {
        self.entries.contains_key(&id)
    }
    pub fn take_retired(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.retired)
    }
    pub fn suspended(&self, id: u64) -> bool {
        self.entries
            .get(&id)
            .is_some_and(|entry| entry.domain.paused() && entry.running == 0)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn memory_owned(&self, id: u64) -> bool {
        self.entries
            .get(&id)
            .is_none_or(|entry| entry.owned && !entry.source_owned)
    }
    pub fn pause_bytes(&mut self, id: u64) {
        let entry = self.entries.get_mut(&id).unwrap();
        if entry.owned {
            // A request published after this executor took its work belongs to
            // a subsequent scope. Keep the pause across its eventual restore.
            entry.repeat_bytes = true;
        }
        if !entry.domain.paused() {
            entry.mm_only = true;
            entry.requested = Some(Instant::now());
            entry.quiescent = None;
            entry.domain.pause();
        }
    }
    pub fn pause_proc_reads(&mut self, pid: u32) -> bool {
        let Some(&id) = self.tasks.get(&pid) else {
            return false;
        };
        self.pause_bytes(id);
        self.entries.get_mut(&id).unwrap().proc_reads = true;
        true
    }
    pub fn pause_layouts(&mut self, pid: u32) -> bool {
        let Some(&id) = self.tasks.get(&pid) else {
            return false;
        };
        self.pause_bytes(id);
        self.entries.get_mut(&id).unwrap().layouts = true;
        true
    }
    pub fn running(&mut self, pid: u32) {
        let entry = self.entry(pid);
        assert!(!entry.domain.paused());
        entry.running += 1;
    }
    fn entry(&mut self, pid: u32) -> &mut Entry<C> {
        let id = self.tasks[&pid];
        self.entries.get_mut(&id).unwrap()
    }
    pub fn returned(&mut self, pid: u32) {
        self.entry(pid).running -= 1;
    }

    pub fn hold(&mut self, job: Box<Job<C>>) {
        let entry = self.entry(job.work.pid);
        assert!(entry.domain.paused() && !entry.owned);
        entry.jobs.push(job);
    }
    fn closure(&self, mut ids: BTreeSet<u64>) -> BTreeSet<u64> {
        let mut keys: BTreeSet<_> = ids
            .iter()
            .flat_map(|id| self.entries[id].keys.iter().copied())
            .collect();
        loop {
            let mut changed = false;
            for (&id, entry) in &self.entries {
                if !ids.contains(&id) && entry.keys.iter().any(|key| keys.contains(key)) {
                    ids.insert(id);
                    keys.extend(entry.keys.iter().copied());
                    changed = true;
                }
            }
            if !changed {
                return ids;
            }
        }
    }
    pub fn pause(&mut self, ids: BTreeSet<u64>) {
        for id in self.closure(ids) {
            let entry = self.entries.get_mut(&id).unwrap();
            entry.mm_only = false;
            if !entry.domain.paused() {
                entry.requested = Some(Instant::now());
                entry.quiescent = None;
                entry.domain.pause();
            }
        }
    }
    pub fn paused(&self, pid: u32) -> bool {
        self.entries[&self.tasks[&pid]].domain.paused()
    }
    pub fn any_paused(&self) -> bool {
        self.entries.values().any(|entry| entry.domain.paused())
    }
    pub fn notify_ready(&mut self) {
        let ready: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(&id, entry)| {
                (entry.domain.paused() && entry.running == 0 && !entry.owned && !entry.notified)
                    .then_some(id)
            })
            .collect();
        for id in ready {
            let entry = self.entries.get_mut(&id).unwrap();
            entry.notified = true;
            entry.quiescent = Some(Instant::now());
            #[cfg(all(test, trames_interpreter_conformance))]
            let ids = if entry.mm_only {
                BTreeSet::from([id])
            } else {
                self.closure(BTreeSet::from([id]))
            };
            #[cfg(all(test, trames_interpreter_conformance))]
            if !self.source_group(&ids) {
                if let Some(events) = &self.events {
                    let _ = events.send(crate::workers::Event::<C>::VmReady);
                }
            }
        }
    }
    fn source_group(&self, _ids: &BTreeSet<u64>) -> bool {
        #[cfg(all(test, trames_interpreter_conformance))]
        {
            let ids = _ids;
            self.source_lifecycle
                && crate::process::lifecycle::eligible(
                    ids.iter()
                        .flat_map(|id| self.entries[id].jobs.iter().map(Box::as_ref)),
                    ids.iter().any(|id| self.entries[id].proc_reads),
                    ids.iter().all(|id| self.entries[id].mm_only),
                    false,
                    ids.iter().any(|id| self.entries[id].layouts),
                )
        }
        #[cfg(not(all(test, trames_interpreter_conformance)))]
        {
            self.source_lifecycle
        }
    }
    /// A file writer needs returned bytes, not admission to another mm's
    /// structural operation. Drain this original domain independently even
    /// when its pending mmap closure intersects an already-owned scope.
    fn take_layout(&mut self) -> Option<Checkpoint<C>> {
        let id = self.entries.iter().find_map(|(&id, entry)| {
            (entry.layouts
                && entry.domain.paused()
                && !entry.owned
                && entry.running == 0
                && entry.jobs.iter().all(|job| job.work.task.is_some()))
            .then_some(id)
        })?;
        let entry = self.entries.get_mut(&id).unwrap();
        entry.owned = true;
        entry.source_owned = true;
        entry.layouts = false;
        let jobs = std::mem::take(&mut entry.jobs);
        let now = Instant::now();
        Some(Checkpoint {
            ids: BTreeSet::from([id]),
            mm_only: entry.mm_only,
            proc_reads: false,
            layouts: true,
            layout_only: true,
            source_retry: true,
            requesters: jobs
                .iter()
                .filter(|job| job.checkpoint.is_some())
                .map(|job| job.work.pid)
                .collect(),
            jobs,
            requested: entry.requested.unwrap_or(now),
            quiescent: entry.quiescent.unwrap_or(now),
            taken: now,
            source_owned: true,
        })
    }
    pub fn take(&mut self, source: bool) -> Option<Checkpoint<C>> {
        if source && self.source_lifecycle {
            if let Some(checkpoint) = self.take_layout() {
                return Some(checkpoint);
            }
        }
        let mut seen = BTreeSet::new();
        for (&id, entry) in &self.entries {
            if !entry.domain.paused() || entry.owned || seen.contains(&id) {
                continue;
            }
            let ids = if entry.mm_only {
                BTreeSet::from([id])
            } else {
                self.closure(BTreeSet::from([id]))
            };
            seen.extend(ids.iter().copied());
            if ids.iter().any(|id| {
                let entry = &self.entries[id];
                !entry.domain.paused() || entry.owned || entry.running != 0
            }) {
                continue;
            }
            if self.source_group(&ids) != source {
                continue;
            }
            let taken = Instant::now();
            let requested = ids
                .iter()
                .filter_map(|id| self.entries[id].requested)
                .min()
                .unwrap_or(taken);
            let quiescent = ids
                .iter()
                .filter_map(|id| self.entries[id].quiescent)
                .max()
                .unwrap_or(taken);
            let mut jobs = Vec::new();
            for id in &ids {
                let entry = self.entries.get_mut(id).unwrap();
                entry.owned = true;
                entry.source_owned = source;
                jobs.append(&mut entry.jobs);
            }
            let requesters = jobs
                .iter()
                .filter(|job| job.checkpoint.is_some())
                .map(|job| job.work.pid)
                .collect();
            return Some(Checkpoint::<C> {
                mm_only: ids.iter().all(|id| self.entries[id].mm_only),
                proc_reads: ids.iter().any(|id| self.entries[id].proc_reads),
                layouts: ids.iter().any(|id| self.entries[id].layouts),
                layout_only: false,
                source_retry: false,
                ids,
                jobs,
                requested,
                quiescent,
                taken,
                requesters,
                source_owned: source,
            });
        }
        None
    }
    pub fn admit(&mut self, checkpoint: &mut Checkpoint<C>, job: Box<Job<C>>) {
        let id = self.tasks[&job.work.pid];
        let entry = self.entries.get_mut(&id).unwrap();
        if checkpoint.ids.insert(id) {
            // A fork made a new mm. It has no execution or service actor yet.
            assert_eq!(entry.running, 0);

            assert!(entry.jobs.is_empty());
            entry.domain.pause();
            entry.owned = true;
            entry.source_owned = checkpoint.source_owned;
            entry.mm_only = checkpoint.mm_only;
            entry.proc_reads = checkpoint.proc_reads;
            entry.layouts = checkpoint.layouts;
            entry.requested = Some(checkpoint.requested);
            entry.quiescent = Some(checkpoint.quiescent);
        } else {
            assert!(entry.owned);
        }
        checkpoint.jobs.push(job);
    }
    /// Update layout dependencies before releasing any CPU. A new alias may
    /// join another already-paused VM; merge that checkpoint before resuming.
    pub fn restore(&mut self, checkpoint: Checkpoint<C>, resume: bool) -> Vec<Box<Job<C>>> {
        let Checkpoint::<C> {
            mut ids,
            jobs,
            requesters,
            mm_only,
            ..
        } = checkpoint;
        let mut updated = BTreeSet::new();
        for job in jobs {
            let id = self.tasks[&job.work.pid];
            let entry = self.entries.get_mut(&id).unwrap();
            if updated.insert(id) {
                if let Some(view) = job.work.memory.as_deref() {
                    entry.keys = view.commit_domains();
                }
            }
            entry.jobs.push(job);
        }
        for id in &ids {
            let entry = self.entries.get_mut(id).unwrap();
            assert!(entry.owned);
            entry.owned = false;
            entry.source_owned = false;
            entry.notified = false;
        }
        ids.retain(|id| {
            if self.entries[id].members != 0 {
                return true;
            }
            let entry = self.entries.remove(id).unwrap();
            assert!(entry.jobs.is_empty());
            if self.source_lifecycle {
                self.retired.push(*id);
            }
            false
        });
        if !resume {
            return Vec::new();
        }
        if ids.iter().any(|id| self.entries[id].repeat_bytes) {
            for id in &ids {
                let entry = self.entries.get_mut(id).unwrap();
                entry.repeat_bytes = false;
            }
            return Vec::new();
        }
        let closure = if mm_only && ids.iter().all(|id| self.entries[id].mm_only) {
            ids.clone()
        } else {
            self.closure(ids.clone())
        };
        if closure
            .iter()
            .any(|id| !ids.contains(id) && self.entries[id].domain.paused())
        {
            self.pause(closure);
            return Vec::new();
        }
        let mut ready = Vec::new();
        for id in ids {
            let entry = self.entries.get_mut(&id).unwrap();
            entry.domain.paused.store(false, Ordering::Relaxed);
            entry.requested = None;
            entry.quiescent = None;
            entry.proc_reads = false;
            entry.layouts = false;
            ready.append(&mut entry.jobs);
        }
        // Give preempted peers their first claim before the mapping callers.
        // A caller returning directly to another VM syscall must not repeatedly
        // pause the same peers before they can resume useful guest execution.
        ready.sort_by_key(|job| requesters.contains(&job.work.pid));
        ready
    }
    pub fn drain(&mut self) -> Vec<Box<Job<C>>> {
        let mut jobs = Vec::new();
        for entry in self.entries.values_mut() {
            assert_eq!(entry.running, 0);

            assert!(!entry.owned, "coordinator still owns a VM checkpoint");
            jobs.append(&mut entry.jobs);
        }
        jobs
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Work = crate::workers::Work<Cpu>;
    type Epoch = crate::run_queue::Epoch<Cpu>;
    type Job = crate::run_queue::Job<Cpu>;

    use super::*;
    use trames_memory::{
        CpuMemory, Memory, MemoryError, PageBacking, Permissions, SharedPage, PAGE_SIZE,
    };
    use trames_vfs::Errno;

    struct Interrupt(std::sync::atomic::AtomicUsize);
    impl trames_engine::ExecutionInterrupt for Interrupt {
        fn request_exit(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn domain(id: u64) -> Arc<Domain> {
        Arc::new(Domain {
            id,
            paused: AtomicBool::new(false),
            host_pause: Arc::default(),
            interrupts: Mutex::default(),
        })
    }
    #[test]
    fn a_pending_barrier_returns_the_only_slot_and_keeps_its_original_view() {
        let epoch = Epoch::new(Arc::new(Control::new(10000)));
        let mut first = memory();
        let mut second = memory();
        for (pid, m) in [(1, &mut first), (2, &mut second)] {
            epoch.add(job(
                pid,
                Box::new(m.parallel_view(&mut Default::default()).unwrap()),
                &epoch,
            ));
        }
        let mut caller = epoch.take(0).unwrap();
        assert_eq!(caller.work.pid, 1);
        let identity = caller.work.memory.as_deref().unwrap() as *const _ as usize;
        let domain = caller.domain.as_ref().unwrap().clone();
        let native = domain.enter(3, Arc::new(AtomicBool::new(false))).unwrap();
        let request = epoch.memory_barrier(domain.id, false, 0);
        let wait = crate::barrier::Wait::new(request.clone());
        let wake = trames_vfs::IoSignal::new(1, epoch.io_target.clone());
        wait.bind(&wake);
        caller.waiting = Some(WaitState::Barrier(wait.clone()));
        epoch.park(caller, None);
        let foreign = epoch.take(0).unwrap();
        assert_eq!(foreign.work.pid, 2);
        assert!(!wait.ready());
        epoch.park(foreign, None);
        drop(native);
        let mut found = None;
        for _ in 0..2 {
            let next = epoch.take(0).unwrap();
            if next.work.pid == 1 {
                found = Some(next);
                break;
            }
            epoch.park(next, None);
        }
        let mut caller = found.expect("original barrier readiness woke its caller");
        assert_eq!(
            caller.work.memory.as_deref().unwrap() as *const _ as usize,
            identity
        );
        assert_eq!(wait.finish(), Some(0));
        caller.waiting = None;
        epoch.park(caller, None);
        epoch.stop();
        assert_eq!(epoch.drain().len(), 2);
    }
    #[test]
    fn barriers_cover_native_preentry_scopes_and_original_leases_without_pausing_domains() {
        let original = domain(1);
        let unrelated = domain(2);
        let first = original.enter(0, Arc::new(AtomicBool::new(false))).unwrap();
        let native = original.enter(1, Arc::new(AtomicBool::new(false))).unwrap();
        let other = unrelated
            .enter(2, Arc::new(AtomicBool::new(false)))
            .unwrap();
        let request = crate::barrier::Request::new();
        original.barrier(&request, 0);
        request.acknowledge();
        assert!(native.pending() && !first.pending() && !other.pending());
        assert!(!request.ready() && !original.paused());
        let interrupt = Arc::new(Interrupt(Default::default()));
        assert!(!native.bind_interrupt(interrupt)); // request before CPU binding
        let late = original.enter(3, Arc::new(AtomicBool::new(false))).unwrap();
        assert!(!late.pending()); // admitted after the barrier publication
        drop(native);
        assert_eq!(request.finish(), Some(0));
        drop((late, first, other));
        original.pause();
        let scope = original.enter_scoped(0);
        let request = crate::barrier::Request::new();
        original.barrier(&request, 1);
        request.acknowledge();
        assert!(scope.pending() && !request.ready());
        drop(scope);
        assert_eq!(request.finish(), Some(0));
    }
    #[test]
    fn concurrent_barriers_keep_native_acknowledgements_after_waiter_cancellation() {
        let original = domain(1);
        let (started, ready) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let value = Arc::new(AtomicU64::new(0));
        let thread = {
            let original = original.clone();
            let value = value.clone();
            std::thread::spawn(move || {
                let guard = original.enter(0, Arc::new(AtomicBool::new(false))).unwrap();
                started.send(()).unwrap();
                released.recv().unwrap();
                value.store(77, Ordering::Relaxed);
                drop(guard);
            })
        };
        ready.recv().unwrap();
        let requests: Vec<_> = (0..16)
            .map(|_| {
                let r = crate::barrier::Request::new();
                original.barrier(&r, 1);
                r.acknowledge();
                r
            })
            .collect();
        assert!(requests.iter().all(|r| !r.ready()));
        let cancelled = crate::barrier::Wait::new(requests[0].clone());
        drop(cancelled);
        release.send(()).unwrap();
        thread.join().unwrap();
        assert!(requests.iter().all(|r| r.finish() == Some(0)));
        assert_eq!(value.load(Ordering::Relaxed), 77);
    }
    #[test]
    fn custody_release_before_or_after_queue_publication_preserves_the_original_checkpoint() {
        for early in [false, true] {
            let epoch = Epoch::new(Arc::new(Control::new(10000)));
            let mut memory = memory();
            epoch.add(job(
                1,
                Box::new(memory.parallel_view(&mut Default::default()).unwrap()),
                &epoch,
            ));
            let caller = epoch.take(0).unwrap();
            let original = (&*caller) as *const Job as usize;
            epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 1 });
            let checkpoint = epoch.take_checkpoint().unwrap();
            let object = trames_shared::Custody::new(0);
            let held = object.borrow_mut();
            let signal = trames_vfs::IoSignal::new(0, epoch.io_target.clone());
            let subscription = object.subscribe(&signal);
            let held = if early {
                drop(held);
                None
            } else {
                Some(held)
            };
            epoch.defer_checkpoint(checkpoint, signal, vec![subscription]);
            if !early {
                assert!(epoch.take_checkpoint().is_none());
            }
            drop(held);
            let checkpoint = epoch.take_checkpoint().expect("latched resource release");
            assert_eq!((&*checkpoint.jobs[0]) as *const Job as usize, original);
            assert!(epoch.take_checkpoint().is_none(), "one claim per wake");
            epoch.restore_checkpoint(checkpoint, false);
            epoch.stop();
            let done = epoch.drain();
            assert_eq!(done.len(), 1);
            assert!(matches!(
                done[0].outcome,
                Some(SliceOutcome::Syscall { instructions: 1 })
            ));
        }
    }
    #[test]
    fn pause_closes_both_preentry_orders_and_guard_withdraws_the_cpu() {
        let domain = Arc::new(Domain {
            id: 1,
            paused: AtomicBool::new(false),
            host_pause: Arc::default(),
            interrupts: Mutex::new(BTreeMap::new()),
        });
        let interrupt = Arc::new(Interrupt(Default::default()));
        let guard = domain.enter(0, Arc::new(AtomicBool::new(false))).unwrap();
        assert!(guard.bind_interrupt(interrupt.clone()));
        domain.pause();
        assert_eq!(interrupt.0.load(Ordering::Relaxed), 1);
        assert!(domain.enter(1, Arc::new(AtomicBool::new(false))).is_none());
        drop(guard);
        domain.paused.store(false, Ordering::Relaxed);
        let guard = domain.enter(0, Arc::new(AtomicBool::new(false))).unwrap();
        assert!(guard.bind_interrupt(interrupt.clone()));
        drop(guard);
        domain.pause();
        assert_eq!(interrupt.0.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn host_pause_parks_dispatch_preserves_admission_and_cancellation() {
        for resume in [true, false] {
            let epoch = Epoch::new(Arc::new(Control::new(10000)));
            let mut a = memory();
            epoch.add(job(
                1,
                Box::new(a.parallel_view(&mut Default::default()).unwrap()),
                &epoch,
            ));
            let (original, view) = {
                let q = epoch.queues.lock().unwrap();
                (
                    (&*q.ready[0]) as *const Job as usize,
                    q.ready[0].work.memory.as_deref().unwrap() as *const _ as usize,
                )
            };
            epoch.pause_host(true);
            let mut b = memory();
            let second = job(
                2,
                Box::new(b.parallel_view(&mut Default::default()).unwrap()),
                &epoch,
            );
            epoch.add(second);
            {
                let q = epoch.queues.lock().unwrap();
                assert_eq!(q.ready.len(), 2);
                assert!(q
                    .ready
                    .iter()
                    .all(|j| j.domain.as_ref().unwrap().interrupted()));
            }
            assert!(epoch.additional_slots(1, 4).is_empty());
            assert!(!epoch.idle());
            let (send, receive) = std::sync::mpsc::channel();
            let worker_epoch = epoch.clone();
            let worker = std::thread::spawn(move || send.send(worker_epoch.take(0)).unwrap());
            assert!(matches!(
                receive.recv_timeout(Duration::from_millis(20)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ));
            if resume {
                epoch.pause_host(false);
                let j = receive
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .unwrap();
                assert_eq!((&*j) as *const Job as usize, original);
                assert_eq!(j.work.memory.as_deref().unwrap() as *const _ as usize, view);
                epoch.park(j, None);
            } else {
                epoch.stop();
                assert!(receive
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .is_none());
            }
            worker.join().unwrap();
            epoch.stop();
            assert_eq!(epoch.drain().len(), 2);
        }
    }
    #[test]
    fn host_pause_closes_preentry_and_binding_without_changing_vm_pause() {
        let original = domain(1);
        let guard = original.enter(0, Arc::new(AtomicBool::new(false))).unwrap();
        original.host_pause.store(true, Ordering::Relaxed);
        original.interrupt();
        assert!(guard.pending());
        let interrupt = Arc::new(Interrupt(Default::default()));
        assert!(!guard.bind_interrupt(interrupt.clone()));
        assert!(original
            .enter(1, Arc::new(AtomicBool::new(false)))
            .is_none());
        assert!(
            !original.paused(),
            "host suspension owns no mapping checkpoint"
        );
        let accepted_scope = original.enter_scoped(1);
        assert!(
            accepted_scope.pending(),
            "accepted work cannot batch guest instructions"
        );
        drop((guard, accepted_scope));
        original.host_pause.store(false, Ordering::Relaxed);
        let resumed = original.enter(0, Arc::new(AtomicBool::new(false))).unwrap();
        assert!(resumed.bind_interrupt(interrupt.clone()));
        original.host_pause.store(true, Ordering::Relaxed);
        original.interrupt();
        assert!(resumed.pending());
        assert_eq!(interrupt.0.load(Ordering::Relaxed), 1);
        drop(resumed);
        original.pause();
        original.host_pause.store(false, Ordering::Relaxed);
        assert!(
            original.paused(),
            "resume cannot clear an actual mapping pause"
        );
    }
    #[test]
    fn pause_interrupts_aliased_backings_and_leaves_an_unrelated_cpu_running() {
        let epoch = Epoch::new(Arc::new(Control::new(10000)));
        let shared = Arc::new(SharedPage::new([0; PAGE_SIZE as usize]));
        let mut a = memory();
        let mut b = memory();
        let mut c = memory();
        map(&mut a, 0x3000, shared.clone());
        map(&mut b, 0x4000, shared);
        let mut registry = Default::default();
        for (pid, m) in [(1, &mut a), (2, &mut b), (3, &mut c)] {
            epoch.add(job(
                pid,
                Box::new(m.parallel_view(&mut registry).unwrap()),
                &epoch,
            ));
        }
        let caller = epoch.take(0).unwrap();
        let sibling = epoch.take(1).unwrap();
        let unrelated = epoch.take(2).unwrap();
        let related = Arc::new(Interrupt(Default::default()));
        let foreign = Arc::new(Interrupt(Default::default()));
        let related_guard = sibling
            .domain
            .as_ref()
            .unwrap()
            .bind_interrupt(1, related.clone())
            .unwrap();
        let foreign_guard = unrelated
            .domain
            .as_ref()
            .unwrap()
            .bind_interrupt(2, foreign.clone())
            .unwrap();
        epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 1 });
        assert_eq!(related.0.load(Ordering::Relaxed), 1);
        assert_eq!(foreign.0.load(Ordering::Relaxed), 0);
        assert!(epoch.take_checkpoint().is_none());
        drop(related_guard);
        epoch.park(sibling, None);
        let checkpoint = epoch.take_checkpoint().unwrap();
        assert_eq!(checkpoint.jobs.len(), 2);
        assert_eq!(checkpoint.ids.len(), 2);
        assert!(!epoch.checkpoint_owns_all_jobs(&checkpoint));
        assert!(checkpoint.requested <= checkpoint.quiescent);
        assert!(checkpoint.quiescent <= checkpoint.taken);
        epoch.restore_checkpoint(checkpoint, false);
        drop(foreign_guard);
        epoch.stop();
        epoch.park(unrelated, None);
        assert_eq!(epoch.drain().len(), 3);
    }
    #[test]
    fn source_exit_publishes_the_final_view_return_to_a_waiting_mm_checkpoint() {
        let (send, receive) = std::sync::mpsc::channel();
        let control = Arc::new(Control::new(10000));
        let epoch = Epoch::with_events(control.clone(), send, true);
        let mut memory = memory();
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        epoch.add(job(1, Box::new(view.clone()), &epoch));
        epoch.add(job(2, Box::new(view), &epoch));
        let caller = epoch.take(0).unwrap();
        let peer = epoch.take(1).unwrap();
        epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 1 });
        assert!(epoch.take_checkpoint().is_none());
        assert!(receive.try_recv().is_err());
        let mut completed = peer.finish(Some(SliceOutcome::Syscall { instructions: 1 }), 0);
        completed.thread_exit = Some(0);
        epoch.finish(completed);
        assert!(!control.stopped());
        assert!(matches!(
            receive.recv_timeout(std::time::Duration::from_secs(1)),
            Ok(crate::workers::Event::VmReady)
        ));
        let checkpoint = epoch.take_checkpoint().unwrap();
        assert_eq!(checkpoint.jobs.len(), 1);
        epoch.restore_checkpoint(checkpoint, false);
        epoch.stop();
        assert_eq!(epoch.drain().len(), 2);
    }

    #[test]
    fn exclusive_cpu_capacity_requires_every_admitted_job_to_be_in_the_checkpoint() {
        let epoch = Epoch::new(Arc::new(Control::new(10000)));
        let mut memory = memory();
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        epoch.add(job(1, Box::new(view.clone()), &epoch));
        epoch.add(job(2, Box::new(view), &epoch));
        let caller = epoch.take(0).unwrap();
        let peer = epoch.take(1).unwrap();
        epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 1 });
        assert!(epoch.take_checkpoint().is_none());
        epoch.park(peer, None);
        let checkpoint = epoch.take_checkpoint().unwrap();
        assert!(epoch.checkpoint_owns_all_jobs(&checkpoint));
        epoch.restore_checkpoint(checkpoint, false);
        epoch.stop();
        assert_eq!(epoch.drain().len(), 2);
    }
    #[test]
    fn byte_request_during_an_owned_scope_is_not_lost_on_restore() {
        let epoch = Epoch::new(Arc::new(Control::new(10000)));
        let mut memory = memory();
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        let id = memory.coordinator_ownership().0;
        epoch.add(job(1, Box::new(view), &epoch));
        assert!(epoch.pause_memory(id));
        let checkpoint = epoch.take_checkpoint().unwrap();
        assert!(epoch.pause_memory(id), "late original mm request");
        epoch.restore_checkpoint(checkpoint, true);
        let checkpoint = epoch
            .take_checkpoint()
            .expect("late request keeps its pause");
        epoch.restore_checkpoint(checkpoint, true);
        let job = epoch.take(0).unwrap();
        assert_eq!(job.work.pid, 1);
        epoch.park(job, None);
        epoch.stop();
        assert_eq!(epoch.drain().len(), 1);
    }
    struct Backing(Arc<SharedPage>);
    impl PageBacking for Backing {
        fn parallel_key(&self) -> Option<(u64, u64)> {
            Some((Arc::as_ptr(&self.0) as usize as u64, 0))
        }
        fn shared_page(&self) -> Option<Arc<SharedPage>> {
            Some(self.0.clone())
        }
        fn check(&self, _: u64) -> Result<(), MemoryError> {
            Ok(())
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
            self.0
                .with_read(offset, out.len(), |bytes| out.copy_from_slice(bytes));
            Ok(())
        }
        fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
            self.0
                .with_write(offset, bytes.len(), |out| out.copy_from_slice(bytes));
            Ok(())
        }
        fn sync(&self) -> Result<(), MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            self.0.revision()
        }
        fn publish_write(&self, _: usize, _: usize) -> Result<(), MemoryError> {
            Ok(())
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(&self, _: u64) -> Result<std::sync::Arc<dyn PageBacking>, MemoryError> {
            Err(MemoryError::InvalidRange)
        }
    }
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        m
    }
    fn map(m: &mut Memory, address: u64, page: Arc<SharedPage>) {
        m.map_backed(
            address,
            vec![Arc::new(Backing(page))],
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    }
    fn job(pid: u32, view: Box<trames_memory::parallel::View>, epoch: &Arc<Epoch>) -> Box<Job> {
        Job::new(
            Work {
                trace: Default::default(),
                task: None,
                audio: None,
                pid,
                cpu: Default::default(),
                memory: Some(view),
                control: epoch.control.clone(),
                syscalls: None,
                gpu: None,
            },
            u64::MAX,
            0,
            None,
        )
    }
    #[test]
    fn new_layout_alias_merges_already_paused_domains_before_any_cpu_resumes() {
        let (send, _events) = std::sync::mpsc::channel();
        let epoch = Epoch::with_events(Arc::new(Control::new(10000)), send, true);
        let mut a = memory();
        let mut b = memory();
        let mut c = memory();
        let mut d = memory();
        let shared = Arc::new(SharedPage::new([0; PAGE_SIZE as usize]));
        map(&mut b, 0x3000, shared.clone());
        map(&mut c, 0x3000, shared.clone());
        let mut registry = Default::default();
        for (pid, m) in [(1, &mut a), (2, &mut b), (3, &mut c), (4, &mut d)] {
            epoch.add(job(
                pid,
                Box::new(m.parallel_view(&mut registry).unwrap()),
                &epoch,
            ));
        }
        let a_job = epoch.take(0).unwrap();
        let a_ptr = &*a_job as *const Job;
        let b_job = epoch.take(1).unwrap();
        epoch.checkpoint(a_job, SliceOutcome::Syscall { instructions: 1 });
        epoch.checkpoint(b_job, SliceOutcome::Syscall { instructions: 1 });
        let mut first = epoch.take_checkpoint().unwrap();
        assert_eq!(first.jobs.len(), 1);
        assert_eq!(first.jobs[0].work.pid, 1);
        drop(first.jobs[0].work.memory.take());
        a.commit_parallel().unwrap();
        map(&mut a, 0x3000, shared);
        first.jobs[0].work.memory = Some(Box::new(a.parallel_view(&mut registry).unwrap()));
        first.jobs[0].checkpoint = None;
        epoch.restore_checkpoint(first, true);
        let unrelated = epoch.take(2).unwrap();
        assert_eq!(unrelated.work.pid, 4);
        let joined = epoch.take_checkpoint().unwrap();
        assert_eq!(joined.jobs.len(), 3);
        assert_eq!(joined.ids.len(), 3);
        assert!(joined.jobs.iter().any(|job| std::ptr::eq(&**job, a_ptr)));
        // Cancellation returns each original pending SVC once, while the
        // already-completed layout operation has no SVC left to replay.
        epoch.restore_checkpoint(joined, false);
        epoch.stop();
        epoch.park(unrelated, None);
        let done = epoch.drain();
        assert_eq!(done.len(), 4);
        assert!(matches!(
            done.iter().find(|d| d.pid == 2).unwrap().outcome,
            Some(SliceOutcome::Syscall { .. })
        ));
        assert!(matches!(
            done.iter().find(|d| d.pid == 1).unwrap().outcome,
            Some(SliceOutcome::Yield { .. })
        ));
    }

    #[test]
    fn paused_io_keeps_original_ofd_and_box_then_consumes_a_wake_after_layout_change() {
        let epoch = Epoch::new(Arc::new(Control::new(10000)));
        let mut m = memory();
        let mut registry = Default::default();
        let view = m.parallel_view(&mut registry).unwrap();
        let sibling = view.clone();
        epoch.add(job(1, Box::new(view), &epoch));
        epoch.add(job(2, Box::new(sibling), &epoch));
        let caller = epoch.take(0).unwrap();
        let mut waiting = epoch.take(1).unwrap();
        let address = &*waiting as *const Job;
        let mut v = trames_vfs::Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let direct = trames_linux::DirectSyscalls::new(v.direct_descriptors());
        let Some(trames_linux::IoAttempt::Blocked(pending)) = direct.start(
            63,
            [reader as u64, 0x1000, 1, 0, 0, 0],
            waiting.work.memory.as_deref_mut().unwrap(),
            2,
            &epoch.io_target,
            None,
        ) else {
            panic!("must wait")
        };
        epoch.park_io(waiting, pending);
        epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 1 });
        let mut checkpoint = epoch.take_checkpoint().unwrap();
        v.close(reader).unwrap();
        assert_eq!(v.eventfd(9, trames_vfs::O_NONBLOCK).unwrap(), reader);
        v.write(writer, b"o").unwrap();
        for job in &mut checkpoint.jobs {
            drop(job.work.memory.take());
            job.checkpoint = None;
        }
        m.commit_parallel().unwrap();
        m.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        let view = m.parallel_view(&mut registry).unwrap();
        let mut views = vec![view.clone(), view];
        for job in &mut checkpoint.jobs {
            job.work.memory = Some(Box::new(views.pop().unwrap()));
        }
        epoch.restore_checkpoint(checkpoint, true);
        let one = epoch.take(0).unwrap();
        let two = epoch.take(1).unwrap();
        let (mut waiting, other) = if one.work.pid == 2 {
            (one, two)
        } else {
            (two, one)
        };
        assert!(std::ptr::eq(&*waiting, address));
        let pending = waiting.io.take().unwrap();
        assert!(matches!(
            direct.resume(pending, waiting.work.memory.as_deref_mut().unwrap()),
            trames_linux::IoAttempt::Complete(Ok(1))
        ));
        assert_eq!(
            waiting
                .work
                .memory
                .as_deref()
                .unwrap()
                .read_array::<1>(0x1000)
                .unwrap(),
            *b"o"
        );
        assert_eq!(v.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(v.read(reader, 8).unwrap(), 9u64.to_le_bytes());
        epoch.stop();
        epoch.park(waiting, None);
        epoch.park(other, None);
        assert_eq!(epoch.drain().len(), 2);
    }
}
