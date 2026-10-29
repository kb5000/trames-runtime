// SPDX-License-Identifier: GPL-3.0-or-later
//! VM quiescence owns jobs, never their guest bytes. The queue mutex publishes
//! handoff; the relaxed bit only asks a running CPU to return its current slice.
// Jobs retain their allocation through queues, services and VM checkpoints.
// Moving only Box pointers also avoids copying CPUs and translation caches.
#![allow(clippy::vec_box)]
use super::*;
use std::sync::{atomic::AtomicBool, mpsc::Sender};

pub(crate) struct Domain {
    pub id: u64,
    paused: AtomicBool,
    interrupts: Mutex<BTreeMap<usize, Arc<dyn trames_engine::ExecutionInterrupt>>>,
}

/// Bound once per running job, not per instruction, syscall or CPU slice.
/// Publication and pause share this object lock, closing the pre-entry race.
/// No guest data or execution is covered by the lock.
pub(crate) struct ExecutionGuard {
    domain: Arc<Domain>,
    slot: usize,
}
impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        self.domain.interrupts.lock().unwrap().remove(&self.slot);
    }
}
impl Domain {
    pub fn bind_interrupt(
        self: &Arc<Self>,
        slot: usize,
        interrupt: Arc<dyn trames_engine::ExecutionInterrupt>,
    ) -> Option<ExecutionGuard> {
        let mut active = self.interrupts.lock().unwrap();
        if self.paused() {
            return None;
        }
        assert!(
            active.insert(slot, interrupt).is_none(),
            "one running job per worker"
        );
        Some(ExecutionGuard {
            domain: self.clone(),
            slot,
        })
    }
    fn pause(&self) {
        self.paused.store(true, Ordering::Relaxed);
        // A CPU published before pause is kicked, including a not-yet-entered
        // CPU (the backend must latch the request). A later binder cannot enter.
        for interrupt in self.interrupts.lock().unwrap().values() {
            interrupt.request_exit();
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
    services: usize,
    notified: bool,
    owned: bool,
    requested: Option<Instant>,
    quiescent: Option<Instant>,
}
#[derive(Default)]
pub(super) struct Domains<C: Cpu> {
    entries: BTreeMap<u64, Entry<C>>,
    tasks: BTreeMap<u32, u64>,
    pub events: Option<Sender<crate::workers::Event<C>>>,
}
pub(crate) struct Checkpoint<C: Cpu> {
    pub ids: BTreeSet<u64>,
    pub jobs: Vec<Box<Job<C>>>,
    pub requested: Instant,
    pub quiescent: Instant,
    pub taken: Instant,
    requesters: BTreeSet<u32>,
}
impl<C: Cpu> Domains<C> {
    pub fn new(events: Option<Sender<crate::workers::Event<C>>>) -> Self {
        Self {
            events,
            ..Self::default()
        }
    }
    pub fn register(&mut self, job: &mut Job<C>) {
        let view = job.work.memory.as_deref().expect("cohort view");
        let id = trames_memory::CpuMemory::instruction_identity(view).0;
        let entry = self.entries.entry(id).or_insert_with(|| Entry::<C> {
            domain: Arc::new(Domain {
                id,
                paused: AtomicBool::new(false),
                interrupts: Mutex::new(BTreeMap::new()),
            }),
            keys: view.commit_domains(),
            jobs: Vec::new(),
            running: 0,
            services: 0,
            notified: false,
            owned: false,
            requested: None,
            quiescent: None,
        });
        assert!(self.tasks.insert(job.work.pid, id).is_none());
        job.domain = Some(entry.domain.clone());
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
    pub fn start_service(&mut self, pid: u32) {
        let entry = self.entry(pid);
        entry.running -= 1;
        entry.services += 1;
    }
    pub fn end_service(&mut self, pid: u32) {
        self.entry(pid).services -= 1;
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
        for entry in self.entries.values_mut() {
            if entry.domain.paused()
                && entry.running == 0
                && entry.services == 0
                && !entry.owned
                && !entry.notified
            {
                entry.notified = true;
                entry.quiescent = Some(Instant::now());
                if let Some(events) = &self.events {
                    let _ = events.send(crate::workers::Event::<C>::VmReady);
                }
            }
        }
    }
    pub fn take(&mut self) -> Option<Checkpoint<C>> {
        let mut seen = BTreeSet::new();
        for (&id, entry) in &self.entries {
            if !entry.domain.paused() || entry.owned || seen.contains(&id) {
                continue;
            }
            let ids = self.closure(BTreeSet::from([id]));
            seen.extend(ids.iter().copied());
            if ids.iter().any(|id| {
                let entry = &self.entries[id];
                !entry.domain.paused() || entry.owned || entry.running != 0 || entry.services != 0
            }) {
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
                jobs.append(&mut entry.jobs);
            }
            let requesters = jobs
                .iter()
                .filter(|job| job.checkpoint.is_some())
                .map(|job| job.work.pid)
                .collect();
            return Some(Checkpoint::<C> {
                ids,
                jobs,
                requested,
                quiescent,
                taken,
                requesters,
            });
        }
        None
    }
    /// Update layout dependencies before releasing any CPU. A new alias may
    /// join another already-paused VM; merge that checkpoint before resuming.
    pub fn restore(&mut self, checkpoint: Checkpoint<C>, resume: bool) -> Vec<Box<Job<C>>> {
        let Checkpoint::<C> {
            ids,
            jobs,
            requesters,
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
            entry.notified = false;
        }
        if !resume {
            return Vec::new();
        }
        let closure = self.closure(ids.clone());
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
            assert_eq!(entry.services, 0);
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
        CpuMemory, Memory, MemoryError, PAGE_SIZE, PageBacking, Permissions, SharedPage,
    };
    use trames_vfs::Errno;

    struct Interrupt(std::sync::atomic::AtomicUsize);
    impl trames_engine::ExecutionInterrupt for Interrupt {
        fn request_exit(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn pause_closes_both_preentry_orders_and_guard_withdraws_the_cpu() {
        let domain = Arc::new(Domain {
            id: 1,
            paused: AtomicBool::new(false),
            interrupts: Mutex::new(BTreeMap::new()),
        });
        let interrupt = Arc::new(Interrupt(Default::default()));
        let guard = domain.bind_interrupt(0, interrupt.clone()).unwrap();
        domain.pause();
        assert_eq!(interrupt.0.load(Ordering::Relaxed), 1);
        assert!(domain.bind_interrupt(1, interrupt.clone()).is_none());
        drop(guard);
        domain.paused.store(false, Ordering::Relaxed);
        drop(domain.bind_interrupt(0, interrupt.clone()).unwrap());
        domain.pause();
        assert_eq!(interrupt.0.load(Ordering::Relaxed), 1);
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
        fn next_page(&self, _: u64) -> Result<std::rc::Rc<dyn PageBacking>, MemoryError> {
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
            vec![std::rc::Rc::new(Backing(page))],
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    }
    fn job(pid: u32, view: Box<trames_memory::parallel::View>, epoch: &Arc<Epoch>) -> Box<Job> {
        Job::new(
            Work {
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
    fn vm_pause_waits_for_its_own_inflight_service_and_not_an_unrelated_service() {
        let epoch = Epoch::new(Arc::new(Control::new(10000)));
        let mut a = memory();
        let mut b = memory();
        let mut registry = Default::default();
        let view = a.parallel_view(&mut registry).unwrap();
        let sibling = view.clone();
        epoch.add(job(1, Box::new(view), &epoch));
        epoch.add(job(2, Box::new(sibling), &epoch));
        epoch.add(job(
            3,
            Box::new(b.parallel_view(&mut registry).unwrap()),
            &epoch,
        ));
        let caller = epoch.take(0).unwrap();
        let mut own = epoch.take(1).unwrap();
        let foreign = epoch.take(2).unwrap();
        epoch.start_service(2);
        epoch.start_service(3);
        epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 1 });
        assert!(epoch.take_checkpoint().is_none());
        own.work
            .memory
            .as_deref_mut()
            .unwrap()
            .write(0x1000, b"original service")
            .unwrap();
        epoch.end_service(own, Ok(Some(16)));
        let mut checkpoint = epoch.take_checkpoint().unwrap();
        assert_eq!(checkpoint.jobs.len(), 2);
        assert_eq!(epoch.pending_services(), 1);
        assert_eq!(
            checkpoint
                .jobs
                .iter()
                .find(|j| j.work.pid == 2)
                .unwrap()
                .work
                .cpu
                .x(0),
            16
        );
        for job in &mut checkpoint.jobs {
            drop(job.work.memory.take());
        }
        a.commit_parallel().unwrap();
        assert_eq!(a.read_array::<16>(0x1000).unwrap(), *b"original service");
        epoch.restore_checkpoint(checkpoint, false);
        epoch.end_service(foreign, Ok(Some(7)));
        epoch.stop();
        assert_eq!(epoch.drain().len(), 3);
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
