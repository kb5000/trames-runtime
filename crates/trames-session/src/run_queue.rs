// SPDX-License-Identifier: GPL-3.0-or-later
//! A frozen VM cohort owns every execution View until its workers have stopped.
//! Ready/parked tasks move between existing workers; no coordinator RPC or spin.
use crate::{
    futex::{Ticket, Wait},
    workers::{Control, Done, Work},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};
use trames_engine::{Cpu, DecodeStats, SliceOutcome};
mod domains;
pub(super) use domains::{Checkpoint, Domain};

#[derive(Clone)]
pub(super) struct WaitState {
    pub wait: Arc<Wait>,
    pub deadline: Option<Instant>,
}
#[derive(Clone)]
pub(super) struct IoCall {
    pub number: u32,
    pub args: [u64; 6],
    pub flock: Option<trames_vfs::FlockRequest>,
    pub retained_byte: Option<trames_linux::RetainedByte>,
    pub retained_poll: Option<trames_linux::RetainedPoll>,
    pub deadline: Option<Instant>,
}
impl From<&trames_linux::PendingIo> for IoCall {
    fn from(io: &trames_linux::PendingIo) -> Self {
        Self {
            number: io.number,
            args: io.args,
            flock: io.flock.clone(),
            retained_byte: io.retained_byte.clone(),
            retained_poll: io.retained_poll.clone(),
            deadline: io.deadline,
        }
    }
}
#[derive(Default)]
pub(super) struct Stats {
    pub elapsed: Duration,
    pub before: DecodeStats,
    pub after: DecodeStats,
    pub worker: usize,
    pub instructions: u64,
    pub chunks: u64,
    pub syscalls: u64,
    pub direct_syscalls: u64,
    pub futex_wakes: u64,
    pub futex_woken: u64,
    pub futex_requeues: u64,
    pub serviced_syscalls: u64,
    pub service_wait: Duration,
    pub syscall_time: Duration,
    pub native: trames_accel::native::Metrics,
    pub rejected_native: Option<(u64, u64, u64)>,
    pub cpu_times: [Duration; 32],
    pub assignments: u64,
    pub waits: u64,
    pub resumes: u64,
    pub yields: u64,
    pub io_waits: u64,
    pub service_waits: u64,
    pub file_syscalls: u64,
    pub socket_syscalls: u64,
    pub timer_syscalls: u64,
    pub poll_syscalls: u64,
    pub uring_syscalls: u64,
    pub fd_syscalls: u64,
    pub gpu: crate::workers::GpuStats,
}
pub(super) struct Job<C: Cpu> {
    pub work: Work<C>,
    pub stats: Stats,
    pub affinity: u64,
    pub waiting: Option<WaitState>,
    pub io: Option<trames_linux::PendingIo>,
    pub retry: Option<IoCall>,
    pub hardware_wait: Option<Arc<trames_memory::HardwareWait>>,
    pub gpu_pending: Option<crate::gpu::Pending>,
    pub domain: Option<Arc<Domain>>,
    pub checkpoint: Option<SliceOutcome>,
    /// Guest code reached this exit during a bounded exclusive-mm window.
    /// Its syscall/native/fault handling still belongs to normal dispatch.
    pub pending_cpu: Option<SliceOutcome>,
    /// A filtered FD entry may defer before membership effects. Carry its
    /// decision to the owner instead of evaluating the same BPF entry twice.
    pub seccomp_entry: Option<crate::process::seccomp::EntryDecision>,
}
impl<C: Cpu> Job<C> {
    pub fn new(
        work: Work<C>,
        affinity: u64,
        last_cpu: usize,
        waiting: Option<WaitState>,
    ) -> Box<Self> {
        let before = work.cpu.decode_stats();
        Box::new(Self {
            work,
            affinity,
            waiting,
            io: None,
            retry: None,
            hardware_wait: None,
            gpu_pending: None,
            domain: None,
            checkpoint: None,
            pending_cpu: None,
            seccomp_entry: None,
            stats: Stats {
                before,
                after: before,
                worker: last_cpu,
                ..Default::default()
            },
        })
    }
    pub fn finish(self, outcome: Option<SliceOutcome>, peer: u64) -> Done<C> {
        // Cancellation can join a ready job before a worker consumes its
        // accepted CPU exit. Preserve it rather than skipping a past-PC SVC.
        let outcome = self.pending_cpu.or(outcome);
        let io = self.io.as_ref().map(IoCall::from).or(self.retry);
        drop(self.io);
        let gpu_pending = self.gpu_pending.as_ref().and_then(|p| p.checkpoint(peer));
        drop(self.gpu_pending);
        let work = self.work;
        // Drop the retained View before any coordinator mapping operation.
        drop(work.memory);
        let mut done =
            self.stats
                .finish(work.pid, work.cpu, outcome, self.waiting, io, gpu_pending);
        done.seccomp_entry = self.seccomp_entry;
        done
    }
}

impl Stats {
    pub fn finish<C: Cpu>(
        self,
        pid: u32,
        cpu: C,
        outcome: Option<SliceOutcome>,
        waiting: Option<WaitState>,
        io: Option<IoCall>,
        gpu_pending: Option<crate::gpu::Compile>,
    ) -> Done<C> {
        Done::<C> {
            pid,
            cpu,
            outcome,
            waiting,
            io,
            elapsed: self.elapsed,
            before: self.before,
            after: self.after,
            worker: self.worker,
            instructions: self.instructions,
            chunks: self.chunks,
            syscalls: self.syscalls,
            direct_syscalls: self.direct_syscalls,
            futex_wakes: self.futex_wakes,
            futex_woken: self.futex_woken,
            futex_requeues: self.futex_requeues,
            serviced_syscalls: self.serviced_syscalls,
            service_wait: self.service_wait,
            syscall_time: self.syscall_time,
            native: self.native,
            rejected_native: self.rejected_native,
            cpu_times: self.cpu_times,
            assignments: self.assignments,
            waits: self.waits,
            resumes: self.resumes,
            yields: self.yields,
            io_waits: self.io_waits,
            service_waits: self.service_waits,
            file_syscalls: self.file_syscalls,
            socket_syscalls: self.socket_syscalls,
            timer_syscalls: self.timer_syscalls,
            poll_syscalls: self.poll_syscalls,
            uring_syscalls: self.uring_syscalls,
            fd_syscalls: self.fd_syscalls,
            gpu: self.gpu,
            gpu_pending,
            seccomp_entry: None,
        }
    }
}

#[derive(Default)]
struct Queues<C: Cpu> {
    ready: VecDeque<Box<Job<C>>>,
    parked: BTreeMap<u32, Box<Job<C>>>,
    members: BTreeSet<u32>,
    running: usize,
    services: usize,
    finished: Vec<Done<C>>,
    initial_slots: BTreeMap<u32, usize>,
    gpu_peak_pending: usize,
    host_waiting: bool,
    domains: domains::Domains<C>,
    retired: Vec<(Box<Job<C>>, Option<SliceOutcome>)>,
    idle_notified: bool,
    sleeping_slots: u64,
}
pub(super) struct Epoch<C: Cpu> {
    pub control: Arc<Control>,
    queues: Mutex<Queues<C>>,
    changed: Condvar,
    slot_changed: [Condvar; 32],
    host_events: OnceLock<Option<Arc<trames_vfs::HostEvents>>>,
    pub io_target: Weak<dyn trames_vfs::IoWake>,
    deadline_origin: Instant,
    next_deadline: AtomicU64,
    ready_slots: AtomicU64,
    #[cfg(all(test, trames_interpreter_conformance))]
    preemption: std::sync::atomic::AtomicBool,
    pub progress: AtomicU64,
    pub local_vm: bool,
    persistent: bool,
}
impl<C: Cpu> Epoch<C> {
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn new(control: Arc<Control>) -> Arc<Self> {
        Self::configured(control, None, false)
    }
    fn configured(
        control: Arc<Control>,
        events: Option<std::sync::mpsc::Sender<crate::workers::Event<C>>>,
        persistent: bool,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me: &Weak<Self>| Self {
            control,
            queues: Mutex::new(Queues::<C> {
                domains: domains::Domains::<C>::new(events.clone()),
                ..Default::default()
            }),
            changed: Condvar::new(),
            slot_changed: std::array::from_fn(|_| Condvar::new()),
            host_events: OnceLock::new(),
            io_target: me.clone(),
            deadline_origin: Instant::now(),
            next_deadline: AtomicU64::new(u64::MAX),
            ready_slots: AtomicU64::new(0),
            #[cfg(all(test, trames_interpreter_conformance))]
            preemption: std::sync::atomic::AtomicBool::new(true),
            progress: AtomicU64::new(0),
            local_vm: events.is_some(),
            persistent,
        })
    }
    pub fn with_events(
        control: Arc<Control>,
        events: std::sync::mpsc::Sender<crate::workers::Event<C>>,
        persistent: bool,
    ) -> Arc<Self> {
        Self::configured(control, Some(events), persistent)
    }
    fn deadline_ticks(&self, deadline: Instant) -> u64 {
        deadline
            .saturating_duration_since(self.deadline_origin)
            .as_nanos()
            .min((u64::MAX - 1) as u128) as u64
    }
    // Called under the existing queue mutex. A sleeper registers before the
    // atomic mutex-release/wait, so targeted notifications cannot be lost.
    fn notify(&self, q: &mut Queues<C>) {
        let mut wake = 0;
        if self.control.stopped() {
            wake = q.sleeping_slots;
        } else {
            for job in &q.ready {
                let eligible = q
                    .initial_slots
                    .get(&job.work.pid)
                    .map_or(job.affinity, |slot| 1 << slot)
                    & q.sleeping_slots
                    & !wake;
                if eligible != 0 {
                    let previous = 1u64 << job.stats.worker;
                    wake |= if eligible & previous != 0 {
                        previous
                    } else {
                        1 << eligible.trailing_zeros()
                    };
                }
            }
            // With no eligible ready job, one existing worker must observe new
            // I/O/deadline/control state and enter the shared host wait source.
            if wake == 0 && q.sleeping_slots != 0 {
                wake = 1 << q.sleeping_slots.trailing_zeros();
            }
        }
        q.sleeping_slots &= !wake;
        while wake != 0 {
            let slot = wake.trailing_zeros() as usize;
            wake &= wake - 1;
            self.slot_changed[slot].notify_one();
        }
        // This condition is for test/owner observers, never production workers.
        self.changed.notify_all();
        if let Some(Some(events)) = self.host_events.get() {
            events.wake();
        }
    }
    fn publish_deadline(&self, deadline: Option<Instant>) {
        if let Some(deadline) = deadline {
            self.next_deadline
                .fetch_min(self.deadline_ticks(deadline), Ordering::Relaxed);
        }
    }
    /// Scheduling hint only; the queue lock owns and publishes actual jobs.
    /// With no deadline, CPU/native execution does not query the host clock.
    pub fn deadline_due(&self) -> bool {
        let next = self.next_deadline.load(Ordering::Relaxed);
        next != u64::MAX && self.deadline_ticks(Instant::now()) >= next
    }
    fn refresh_ready(&self, q: &Queues<C>) {
        let slots = q.ready.iter().fold(0, |mask, job| {
            mask | q
                .initial_slots
                .get(&job.work.pid)
                .map_or(job.affinity, |slot| 1 << slot)
        });
        self.ready_slots.store(slots, Ordering::Relaxed);
    }
    fn ready(&self, q: &mut Queues<C>, job: Box<Job<C>>) {
        q.idle_notified = false;
        q.ready.push_back(job);
        self.refresh_ready(q);
    }
    pub fn should_yield(&self, slot: usize, began: Instant, progressed: bool) -> bool {
        // Handoff/retirement tests control scheduling explicitly; their result
        // must not depend on whether instrumentation takes 250 microseconds.
        #[cfg(all(test, trames_interpreter_conformance))]
        if !self.preemption.load(Ordering::Relaxed) {
            return self.deadline_due();
        }
        self.deadline_due()
            || (progressed
                && self.ready_slots.load(Ordering::Relaxed) & (1 << slot) != 0
                && began.elapsed() >= Duration::from_micros(250))
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn unpreempted(control: Arc<Control>) -> Arc<Self> {
        let epoch = Self::new(control);
        epoch.preemption.store(false, Ordering::Relaxed);
        epoch
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn expire_parked_io(&self, pid: u32) {
        let until = Instant::now() + Duration::from_secs(5);
        let mut q = self.queues.lock().unwrap();
        while !q.parked.get(&pid).is_some_and(|job| job.io.is_some()) {
            assert!(!self.control.stopped(), "cohort stopped before I/O park");
            let left = until.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "I/O did not park");
            q = self.changed.wait_timeout(q, left).unwrap().0;
        }
        let deadline = Instant::now();
        q.parked
            .get_mut(&pid)
            .unwrap()
            .io
            .as_mut()
            .unwrap()
            .deadline = Some(deadline);
        self.publish_deadline(Some(deadline));
        self.notify(&mut q);
    }
    /// Only before launch: every View is prepared/admitted before any CPU runs.
    pub fn add(self: &Arc<Self>, mut job: Box<Job<C>>) {
        let pid = job.work.pid;
        let mut q = self.queues.lock().unwrap();
        assert!(q.members.insert(pid), "duplicate cohort task");
        q.domains.register(&mut job);
        if let Some(waiting) = &job.waiting {
            waiting.wait.ticket.bind(self);
            if !waiting.wait.woken() {
                self.publish_deadline(waiting.deadline);
                q.parked.insert(pid, job);
                return;
            }
            job.work.cpu.set_x(0, 0);
            job.waiting = None;
        }
        self.ready(&mut q, job);
    }
    pub fn stop(&self) {
        let mut q = self.queues.lock().unwrap();
        self.control.stop();
        self.notify(&mut q);
    }
    pub fn assign(&self, chosen: &[(u32, usize)]) {
        let mut q = self.queues.lock().unwrap();
        q.initial_slots.extend(chosen.iter().copied());
        self.refresh_ready(&q);
    }
    fn capture_paused(&self, q: &mut Queues<C>) {
        for job in std::mem::take(&mut q.ready) {
            if q.domains.paused(job.work.pid) {
                q.domains.hold(job);
            } else {
                q.ready.push_back(job);
            }
        }
        for (pid, job) in std::mem::take(&mut q.parked) {
            if q.domains.paused(pid) {
                q.domains.hold(job);
            } else {
                q.parked.insert(pid, job);
            }
        }
        self.refresh_ready(q);
        q.domains.notify_ready();
    }
    pub fn checkpoint(&self, mut job: Box<Job<C>>, outcome: SliceOutcome) {
        let id = job.domain.as_ref().expect("registered VM").id;
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.domains.returned(job.work.pid);
        job.checkpoint = Some(outcome);
        q.domains.pause(BTreeSet::from([id]));
        q.domains.hold(job);
        self.capture_paused(&mut q);
        self.notify(&mut q);
    }
    pub fn take_checkpoint(&self) -> Option<Checkpoint<C>> {
        self.queues.lock().unwrap().domains.take()
    }
    /// The existing owner may briefly execute guest code only when no worker
    /// can claim an unrelated job. This reserves logical CPU capacity without
    /// adding an execution slot or pausing unrelated address spaces.
    pub fn checkpoint_owns_all_jobs(&self, checkpoint: &Checkpoint<C>) -> bool {
        checkpoint.jobs.len() == self.queues.lock().unwrap().members.len()
    }
    pub fn idle(&self) -> bool {
        let q = self.queues.lock().unwrap();
        q.running == 0 && q.services == 0 && q.ready.is_empty() && !q.domains.any_paused()
    }
    pub fn restore_checkpoint(&self, checkpoint: Checkpoint<C>, resume: bool) {
        let mut q = self.queues.lock().unwrap();
        let jobs = q.domains.restore(checkpoint, resume);
        for mut job in jobs {
            if job.waiting.as_ref().is_some_and(|w| w.wait.woken()) {
                job.waiting = None;
                job.work.cpu.set_x(0, 0);
                job.stats.resumes += 1;
            }
            let pending = job.hardware_wait.as_ref().is_some_and(|w| !w.ready())
                || job.waiting.is_some()
                || job.io.as_ref().is_some_and(|io| !io.signal.ready())
                || job.gpu_pending.as_ref().is_some_and(|gpu| gpu.waiting());
            if pending {
                self.publish_deadline(
                    job.waiting
                        .as_ref()
                        .and_then(|w| w.deadline)
                        .or_else(|| job.io.as_ref().and_then(|io| io.wake_deadline()))
                        .or_else(|| job.gpu_pending.as_ref().and_then(|gpu| gpu.deadline())),
                );
                assert!(q.parked.insert(job.work.pid, job).is_none());
            } else {
                self.ready(&mut q, job);
            }
        }
        self.capture_paused(&mut q);
        self.notify(&mut q);
    }
    pub fn wake(&self, ticket: &Arc<Ticket>) -> bool {
        let mut q = self.queues.lock().unwrap();
        if self.control.stopped() || !q.members.contains(&ticket.pid) {
            return false;
        }
        if q.parked.get(&ticket.pid).is_some_and(|job| {
            job.waiting
                .as_ref()
                .is_some_and(|w| Arc::ptr_eq(&w.wait.ticket, ticket))
        }) {
            let mut job = q.parked.remove(&ticket.pid).unwrap();
            job.work.cpu.set_x(0, 0);
            job.waiting = None;
            job.stats.resumes += 1;
            self.ready(&mut q, job);
            self.notify(&mut q); // affinity can require a particular worker
        }
        // Wake may precede park. The ticket CAS is then consumed by park below.
        true
    }
    pub fn take(&self, slot: usize) -> Option<Box<Job<C>>> {
        let mut q = self.queues.lock().unwrap();
        let mut dispatched = false;
        loop {
            if self.control.stopped() {
                return None;
            }
            let now = Instant::now();
            let expired: Vec<_> = q
                .parked
                .iter()
                .filter_map(|(&pid, job)| {
                    (job.waiting
                        .as_ref()
                        .and_then(|w| w.deadline)
                        .or_else(|| job.io.as_ref().and_then(|io| io.wake_deadline()))
                        .or_else(|| job.gpu_pending.as_ref().and_then(|gpu| gpu.deadline()))
                        .is_some_and(|d| d <= now))
                    .then_some(pid)
                })
                .collect();
            for pid in expired {
                let mut job = q.parked.remove(&pid).unwrap();
                if let Some(waiting) = job.waiting.take() {
                    let value = if waiting.wait.timeout() {
                        0u64.wrapping_sub(110)
                    } else {
                        0
                    };
                    job.work.cpu.set_x(0, value);
                }
                // I/O must perform a final resource check and scatter, even on
                // timeout. Keep its pending call and do not execute SVC twice.
                job.stats.resumes += 1;
                self.ready(&mut q, job);
            }
            let deadline = q
                .parked
                .values()
                .filter_map(|j| {
                    j.waiting
                        .as_ref()
                        .and_then(|w| w.deadline)
                        .or_else(|| j.io.as_ref().and_then(|io| io.wake_deadline()))
                        .or_else(|| j.gpu_pending.as_ref().and_then(|gpu| gpu.deadline()))
                })
                .min();
            self.next_deadline.store(
                deadline.map_or(u64::MAX, |d| self.deadline_ticks(d)),
                Ordering::Relaxed,
            );
            let preferred = q
                .ready
                .iter()
                .position(|j| q.initial_slots.get(&j.work.pid) == Some(&slot));
            let available = preferred.or_else(|| {
                q.ready.iter().position(|j| {
                    j.affinity & (1 << slot) != 0 && !q.initial_slots.contains_key(&j.work.pid)
                })
            });
            let external = q
                .parked
                .values()
                .any(|j| j.io.as_ref().is_some_and(|io| io.external_wait()));
            if external && !q.host_waiting && (available.is_none() || !dispatched) {
                let events = self
                    .host_events
                    .get()
                    .and_then(Option::as_ref)
                    .expect("host wait source");
                q.host_waiting = true;
                #[cfg(all(test, trames_interpreter_conformance))]
                self.changed.notify_all();
                events.arm();
                // With runnable work this is one nonblocking dispatch at a
                // scheduling boundary. Otherwise sleep until an actual event
                // or deadline. No timer polling or dedicated reactor thread.
                let until = if available.is_some() {
                    Some(Instant::now())
                } else {
                    deadline
                };
                drop(q);
                let result = events.wait(until);
                q = self.queues.lock().unwrap();
                events.disarm();
                q.host_waiting = false;
                dispatched = true;
                if result.is_err() {
                    self.control.stop();
                }
                self.notify(&mut q);
                continue;
            }
            if let Some(i) = available {
                let mut job = q.ready.remove(i).unwrap();
                self.refresh_ready(&q);
                let work = &mut job.work;
                q.initial_slots.remove(&work.pid);
                if job.stats.worker != slot {
                    work.cpu.clear_exclusive();
                }
                job.stats.worker = slot;
                if let Some(snapshot) = &mut work.syscalls {
                    snapshot.processor = slot as u32;
                }
                q.running += 1;
                q.domains.running(work.pid);
                // A woken worker may have taken a pinned task ahead of the
                // flexible task that selected it. Pass remaining ready work on.
                if !q.ready.is_empty() {
                    self.notify(&mut q);
                }
                return Some(job);
            }
            if q.running == 0
                && q.services == 0
                && q.ready.is_empty()
                && deadline.is_none()
                && !q.parked.values().any(|j| j.gpu_pending.is_some())
                && !external
                && !q.domains.any_paused()
            {
                if self.persistent {
                    if !q.idle_notified {
                        q.idle_notified = true;
                        if let Some(events) = &q.domains.events {
                            let _ = events.send(crate::workers::Event::<C>::Idle);
                        }
                    }
                } else {
                    self.control.stop();
                    self.notify(&mut q);
                    return None;
                }
            }
            q.sleeping_slots |= 1 << slot;
            #[cfg(all(test, trames_interpreter_conformance))]
            self.changed.notify_all();
            q = if let Some(deadline) = deadline {
                self.slot_changed[slot]
                    .wait_timeout(q, deadline.saturating_duration_since(Instant::now()))
                    .unwrap()
                    .0
            } else {
                self.slot_changed[slot].wait(q).unwrap()
            };
            q.sleeping_slots &= !(1 << slot);
        }
    }
    pub fn park(&self, mut job: Box<Job<C>>, waiting: Option<WaitState>) {
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.domains.returned(job.work.pid);
        let pid = job.work.pid;
        if q.domains.paused(pid) {
            if waiting.is_some() {
                job.stats.waits += 1;
                job.waiting = waiting;
            }
            q.domains.hold(job);
            q.domains.notify_ready();
            self.notify(&mut q);
            return;
        }
        if let Some(waiting) = waiting {
            job.stats.waits += 1;
            if waiting.wait.woken() {
                job.work.cpu.set_x(0, 0);
                job.stats.resumes += 1;
                self.ready(&mut q, job);
            } else {
                self.publish_deadline(waiting.deadline);
                job.waiting = Some(waiting);
                assert!(q.parked.insert(pid, job).is_none());
            }
        } else {
            job.stats.yields += 1;
            self.ready(&mut q, job);
        }
        self.notify(&mut q);
    }
    pub fn park_hardware(
        self: &Arc<Self>,
        mut job: Box<Job<C>>,
        wait: Arc<trames_memory::HardwareWait>,
    ) {
        let weak = Arc::downgrade(self);
        let pid = job.work.pid;
        wait.subscribe(move || {
            if let Some(epoch) = weak.upgrade() {
                let mut q = epoch.queues.lock().unwrap();
                if q.parked
                    .get(&pid)
                    .is_some_and(|j| j.hardware_wait.as_ref().is_some_and(|w| w.ready()))
                {
                    let mut job = q.parked.remove(&pid).unwrap();
                    job.hardware_wait = None;
                    epoch.ready(&mut q, job);
                    epoch.notify(&mut q);
                }
            }
        });
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.domains.returned(pid);
        let ready = wait.ready();
        job.hardware_wait = Some(wait);
        if q.domains.paused(pid) {
            q.domains.hold(job);
            q.domains.notify_ready();
        } else if ready {
            job.hardware_wait = None;
            self.ready(&mut q, job);
        } else {
            assert!(q.parked.insert(pid, job).is_none());
        }
        self.notify(&mut q);
    }
    pub fn park_io(&self, mut job: Box<Job<C>>, pending: trames_linux::PendingIo) {
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.domains.returned(job.work.pid);
        job.stats.io_waits += 1;
        let ready = pending.signal.ready();
        job.io = Some(pending);
        if q.domains.paused(job.work.pid) {
            q.domains.hold(job);
            q.domains.notify_ready();
        } else if ready {
            job.stats.resumes += 1;
            self.ready(&mut q, job);
        } else {
            self.publish_deadline(job.io.as_ref().and_then(|io| io.wake_deadline()));
            assert!(q.parked.insert(job.work.pid, job).is_none());
        }
        self.notify(&mut q);
    }
    pub fn park_gpu(&self, mut job: Box<Job<C>>, pending: crate::gpu::Pending) {
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.domains.returned(job.work.pid);
        job.stats.gpu.waits += 1;
        let ready = !pending.waiting();
        self.publish_deadline(pending.deadline());
        job.gpu_pending = Some(pending);
        if q.domains.paused(job.work.pid) {
            q.domains.hold(job);
            q.domains.notify_ready();
        } else if ready {
            job.stats.resumes += 1;
            self.ready(&mut q, job);
        } else {
            assert!(q.parked.insert(job.work.pid, job).is_none());
            let count = q
                .parked
                .values()
                .filter(|j| j.gpu_pending.as_ref().is_some_and(|p| p.compile.is_some()))
                .count();
            q.gpu_peak_pending = q.gpu_peak_pending.max(count);
        }
        self.notify(&mut q);
    }
    pub fn gpu_peak_pending(&self) -> usize {
        self.queues.lock().unwrap().gpu_peak_pending
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn await_gpu_park(&self, pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut q = self.queues.lock().unwrap();
        while !q.parked.get(&pid).is_some_and(|j| j.gpu_pending.is_some()) {
            assert!(!self.control.stopped(), "cohort stopped before GPU park");
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "GPU did not park");
            q = self.changed.wait_timeout(q, left).unwrap().0;
        }
    }
    /// Transfer an execution slot to a request before publishing it. A queued
    /// service prevents quiescence even when every worker has run out of work.
    pub fn start_service(&self, pid: u32) {
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.services += 1;
        q.domains.start_service(pid);
        self.notify(&mut q);
    }
    pub fn pending_services(&self) -> usize {
        self.queues.lock().unwrap().services
    }
    /// None checkpoints before effects; Err means an abandoned/panicked request.
    /// Completed effects must commit even when stop raced with their completion.
    pub fn end_service(&self, mut job: Box<Job<C>>, value: Result<Option<u64>, ()>) {
        let mut q = self.queues.lock().unwrap();
        q.services -= 1;
        q.domains.end_service(job.work.pid);
        match value {
            Ok(Some(value)) => {
                job.work.cpu.set_x(0, value);
                job.stats.serviced_syscalls += 1;
                job.stats.resumes += 1;
                if q.domains.paused(job.work.pid) {
                    q.domains.hold(job);
                    q.domains.notify_ready();
                } else {
                    self.ready(&mut q, job);
                }
            }
            value => {
                let outcome = value
                    .ok()
                    .map(|_| SliceOutcome::Syscall { instructions: 0 });
                q.retired.push((job, outcome));
                self.control.stop();
            }
        }
        self.notify(&mut q);
    }
    pub fn finish(&self, done: Done<C>) {
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.domains.returned(done.pid);
        q.finished.push(done);
        self.control.stop();
        self.notify(&mut q);
    }
    /// All launched workers must have acknowledged stop before this call.
    pub fn drain(&self) -> Vec<Done<C>> {
        let mut q = self.queues.lock().unwrap();
        assert_eq!(q.running, 0);
        assert_eq!(q.services, 0, "in-flight service still owns a View");
        let mut done = std::mem::take(&mut q.finished);
        let mut jobs: Vec<_> = q.ready.drain(..).collect();
        jobs.extend(std::mem::take(&mut q.parked).into_values());
        jobs.extend(q.domains.drain());
        let retired = std::mem::take(&mut q.retired);
        drop(q);
        // Final OFD release can notify another job in this same queue.
        done.extend(jobs.into_iter().map(|mut job| {
            let outcome = job
                .checkpoint
                .take()
                .unwrap_or(SliceOutcome::Yield { instructions: 0 });
            job.finish(Some(outcome), self.progress.load(Ordering::Relaxed))
        }));
        done.extend(
            retired
                .into_iter()
                .map(|(job, outcome)| job.finish(outcome, self.progress.load(Ordering::Relaxed))),
        );
        done
    }
}

impl<C: Cpu> trames_vfs::IoWake for Epoch<C> {
    fn host_events(&self) -> Option<Arc<trames_vfs::HostEvents>> {
        self.host_events
            .get_or_init(|| trames_vfs::HostEvents::new().ok())
            .clone()
    }
    fn wake_io(&self, signal: &Arc<trames_vfs::IoSignal>) {
        let mut q = self.queues.lock().unwrap();
        if self.control.stopped() {
            return;
        }
        if q.parked.get(&signal.pid).is_some_and(|job| {
            job.io
                .as_ref()
                .is_some_and(|io| Arc::ptr_eq(&io.signal, signal))
                || job
                    .gpu_pending
                    .as_ref()
                    .is_some_and(|gpu| Arc::ptr_eq(gpu.signal(), signal))
        }) {
            let mut job = q.parked.remove(&signal.pid).unwrap();
            job.stats.resumes += 1;
            self.ready(&mut q, job);
            self.notify(&mut q);
        }
        // If still running, park_io consumes the signal's fired bit under this
        // same queue lock. Notifications never access a guest Memory or CPU.
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Work = crate::workers::Work<Cpu>;
    type Epoch = crate::run_queue::Epoch<Cpu>;
    type Job = crate::run_queue::Job<Cpu>;

    use super::*;
    use trames_memory::{CpuMemory, Memory, Permissions, PAGE_SIZE};
    #[test]
    fn vm_checkpoint_requeues_an_unarmed_adopted_gpu_compile() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        let mut gpu = job(1, &epoch);
        let mut mapper = job(2, &epoch);
        mapper.affinity = 2;
        mapper.work.memory = gpu.work.memory.clone();
        gpu.gpu_pending = Some(crate::gpu::Pending::adopted(crate::gpu::Compile {
            call: crate::gpu::Call {
                pc: 0x1000,
                operation: 65,
                args: [65, 0, 0],
            },
            job: 71,
            began: Instant::now(),
            peer_instructions: 0,
        }));
        epoch.add(gpu);
        epoch.add(mapper);
        let gpu = epoch.take(0).unwrap();
        let mapper = epoch.take(1).unwrap();
        epoch.park(gpu, None);
        epoch.checkpoint(mapper, SliceOutcome::Syscall { instructions: 0 });
        let checkpoint = epoch.take_checkpoint().unwrap();
        epoch.restore_checkpoint(checkpoint, true);
        let mut resumed = [epoch.take(0).unwrap(), epoch.take(1).unwrap()];
        resumed.sort_by_key(|job| job.work.pid);
        assert_eq!(resumed[0].work.pid, 1);
        assert_eq!(
            resumed[0]
                .gpu_pending
                .as_ref()
                .unwrap()
                .checkpoint(0)
                .unwrap()
                .job,
            71
        );
    }

    #[test]
    fn ready_peer_preempts_only_after_progress_and_quantum() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        let now = Instant::now();
        let old = now - Duration::from_secs(1);
        assert!(!epoch.should_yield(0, old, false));
        assert!(!epoch.should_yield(0, now + Duration::from_secs(1), true));
        assert!(epoch.should_yield(0, old, true));
        assert!(!epoch.should_yield(1, old, true));
        let unpreempted = Epoch::unpreempted(Arc::new(Control::new(100)));
        unpreempted.add(job(1, &unpreempted));
        assert!(!unpreempted.should_yield(0, old, true));
        unpreempted.publish_deadline(Some(old));
        assert!(unpreempted.should_yield(0, old, true));
    }
    #[test]
    fn gpu_timeout_returns_its_slot_and_wakes_without_a_completion_or_poll_timer() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        epoch.add(job(2, &epoch));
        let gpu = epoch.take(0).unwrap();
        let began = Instant::now();
        let deadline = began + Duration::from_millis(30);
        let pending = crate::gpu::Pending::timed_for_test(deadline, 1, &epoch.io_target);
        epoch.park_gpu(gpu, pending);
        let peer = epoch.take(0).unwrap();
        assert_eq!(peer.work.pid, 2);
        epoch.park_hardware(peer, Arc::new(trames_memory::HardwareWait::default()));
        let resumed = epoch.take(0).unwrap();
        assert_eq!(resumed.work.pid, 1);
        assert!(Instant::now() >= deadline && began.elapsed() < Duration::from_secs(2));
        assert!(!resumed.gpu_pending.as_ref().unwrap().waiting());
    }
    fn job(pid: u32, epoch: &Arc<Epoch>) -> Box<Job> {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        Job::new(
            Work {
                gpu: None,
                pid,
                cpu: trames_cpu::Cpu::default(),
                memory: Some(Box::new(
                    memory.parallel_view(&mut Default::default()).unwrap(),
                )),
                control: epoch.control.clone(),
                syscalls: None,
            },
            1,
            0,
            None,
        )
    }
    #[test]
    fn targeted_wakes_preserve_pinned_affinity_and_stop_every_waiting_slot() {
        let (events, _receive) = std::sync::mpsc::channel();
        let epoch = Epoch::with_events(Arc::new(Control::new(100)), events, true);
        for pid in 1..=2 {
            let mut task = job(pid, &epoch);
            task.affinity = 1 << (pid - 1);
            epoch.add(task);
        }
        let first = epoch.take(0).unwrap();
        let second = epoch.take(1).unwrap();
        let waits = [
            Arc::new(trames_memory::HardwareWait::default()),
            Arc::new(trames_memory::HardwareWait::default()),
        ];
        epoch.park_hardware(first, waits[0].clone());
        epoch.park_hardware(second, waits[1].clone());
        let (send, receive) = std::sync::mpsc::channel();
        let mut workers = Vec::new();
        for slot in 0..2 {
            let epoch = epoch.clone();
            let send = send.clone();
            workers.push(std::thread::spawn(move || {
                if let Some(task) = epoch.take(slot) {
                    send.send((task.work.pid, slot)).unwrap();
                    epoch.park_hardware(task, Arc::new(trames_memory::HardwareWait::default()));
                }
                assert!(epoch.take(slot).is_none());
            }));
        }
        let until = Instant::now() + Duration::from_secs(5);
        let mut q = epoch.queues.lock().unwrap();
        while q.sleeping_slots & 3 != 3 {
            let left = until.saturating_duration_since(Instant::now());
            assert!(!left.is_zero());
            q = epoch.changed.wait_timeout(q, left).unwrap().0;
        }
        drop(q);
        waits[1].fire();
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(5)).unwrap(),
            (2, 1)
        );
        waits[0].fire();
        assert_eq!(
            receive.recv_timeout(Duration::from_secs(5)).unwrap(),
            (1, 0)
        );
        epoch.stop();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(epoch.drain().len(), 2);
    }
    #[test]
    fn stop_keeps_an_accepted_cpu_exit_until_the_joined_kernel_consumes_it() {
        for outcome in [
            SliceOutcome::Syscall { instructions: 0 },
            SliceOutcome::NativeCall {
                instructions: 0,
                pc: 0x1000,
                module: 0x10001,
                function: 3,
            },
            SliceOutcome::Fault(trames_engine::CpuFault::Host("accepted fault".into())),
        ] {
            let expected = format!("{outcome:?}");
            let epoch = Epoch::new(Arc::new(Control::new(100)));
            let mut task = job(1, &epoch);
            task.pending_cpu = Some(outcome);
            epoch.add(task);
            epoch.stop();
            let mut done = epoch.drain();
            assert_eq!(done.len(), 1);
            assert_eq!(
                format!("{:?}", done.pop().unwrap().outcome.unwrap()),
                expected
            );
            assert!(epoch.drain().is_empty());
        }
    }
    #[test]
    fn hardware_borrow_wait_releases_slot_and_resumes_same_task() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        epoch.add(job(2, &epoch));
        let mut first = epoch.take(0).unwrap();
        first.work.cpu.set_x(0, 47);
        let wait = Arc::new(trames_memory::HardwareWait::default());
        epoch.park_hardware(first, wait.clone());
        let peer = epoch.take(0).unwrap();
        assert_eq!(peer.work.pid, 2);
        wait.fire();
        epoch.park(peer, None);
        let resumed = epoch.take(0).unwrap();
        assert_eq!(resumed.work.pid, 1);
        assert_eq!(resumed.work.cpu.x(0), 47);
    }
    #[test]
    fn hardware_borrow_release_before_park_is_consumed_once() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        let running = epoch.take(0).unwrap();
        let wait = Arc::new(trames_memory::HardwareWait::default());
        wait.fire();
        epoch.park_hardware(running, wait.clone());
        wait.fire();
        let q = epoch.queues.lock().unwrap();
        assert_eq!(q.ready.len(), 1);
        assert!(q.parked.is_empty());
        assert_eq!(q.running, 0);
    }
    #[test]
    fn stopping_a_hardware_borrow_wait_drops_the_retained_view() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        let running = epoch.take(0).unwrap();
        let wait = Arc::new(trames_memory::HardwareWait::default());
        epoch.park_hardware(running, wait.clone());
        epoch.control.stop();
        assert_eq!(epoch.drain().len(), 1);
        wait.fire();
        assert!(epoch.queues.lock().unwrap().parked.is_empty());
    }
    fn tcp() -> (trames_vfs::Vfs, u32, std::net::TcpStream) {
        use std::net::{Ipv4Addr, TcpListener};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = trames_vfs::Vfs::default();
        v.configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let peer = listener.accept().unwrap().0;
        assert_eq!(socket.connect_complete(), Ok(true));
        (v, fd, peer)
    }
    fn tcp_wait(epoch: &Arc<Epoch>, direct: &trames_linux::DirectSyscalls, fd: u32, pid: u32) {
        epoch.add(job(pid, epoch));
        let mut running = epoch.take(0).unwrap();
        let Some(trames_linux::IoAttempt::Blocked(pending)) = direct.start(
            63,
            [fd as u64, 0x1000, 1, 0, 0, 0],
            running.work.memory.as_deref_mut().unwrap(),
            pid,
            &epoch.io_target,
            None,
        ) else {
            panic!("TCP must park");
        };
        assert!(pending.external_wait());
        epoch.park_io(running, pending);
    }
    fn await_host_wait(epoch: &Arc<Epoch>) {
        let until = Instant::now() + Duration::from_secs(2);
        let mut q = epoch.queues.lock().unwrap();
        while !q.host_waiting {
            let left = until.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "executor never entered host wait");
            q = epoch.changed.wait_timeout(q, left).unwrap().0;
        }
    }
    #[test]
    fn tcp_readiness_resumes_parked_view_and_socket_deadline_survives_retry() {
        use std::io::Write;
        let (v, fd, mut peer) = tcp();
        v.socket_fd(fd)
            .unwrap()
            .set_io_timeout(true, Some(Duration::from_secs(2)));
        let direct = trames_linux::DirectSyscalls::new(v.direct_descriptors())
            .with_network(v.direct_network());
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        tcp_wait(&epoch, &direct, fd, 1);
        let deadline = epoch.queues.lock().unwrap().parked[&1]
            .io
            .as_ref()
            .unwrap()
            .deadline
            .unwrap();
        // Data precedes take/host wait: a level registration must retain it.
        peer.write_all(b"x").unwrap();
        let mut running = epoch.take(0).unwrap();
        assert_eq!(running.stats.resumes, 1);
        assert!(matches!(
            direct.resume(
                running.io.take().unwrap(),
                running.work.memory.as_deref_mut().unwrap()
            ),
            trames_linux::IoAttempt::Complete(Ok(1))
        ));
        assert_eq!(
            running
                .work
                .memory
                .as_ref()
                .unwrap()
                .read_array::<1>(0x1000)
                .unwrap(),
            *b"x"
        );
        // A checkpointed timeout must not be extended by cohort re-entry.
        let expired = Instant::now() - Duration::from_secs(1);
        assert!(deadline > expired);
        assert!(matches!(
            direct.start(
                63,
                [fd as u64, 0x1000, 1, 0, 0, 0],
                running.work.memory.as_deref_mut().unwrap(),
                1,
                &epoch.io_target,
                Some(expired)
            ),
            Some(trames_linux::IoAttempt::Complete(Err(trames_vfs::Errno(
                11
            ))))
        ));
        epoch.finish(running.finish(None, 0));
        assert_eq!(epoch.drain().len(), 1);
    }
    #[test]
    fn stop_wakes_host_wait_and_releases_pending_fd_leases() {
        let (mut v, fd, mut peer) = tcp();
        let direct = trames_linux::DirectSyscalls::new(v.direct_descriptors())
            .with_network(v.direct_network());
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        tcp_wait(&epoch, &direct, fd, 1);
        let e = epoch.clone();
        let thread = std::thread::spawn(move || assert!(e.take(0).is_none()));
        await_host_wait(&epoch);
        epoch.stop();
        thread.join().unwrap();
        assert_eq!(epoch.drain().len(), 1);
        v.close(fd).unwrap();
        use std::io::Read;
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
    }
    #[test]
    fn socket_timeout_resumes_original_call_without_external_traffic() {
        let (v, fd, _peer) = tcp();
        v.socket_fd(fd)
            .unwrap()
            .set_io_timeout(true, Some(Duration::from_millis(20)));
        let direct = trames_linux::DirectSyscalls::new(v.direct_descriptors())
            .with_network(v.direct_network());
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        tcp_wait(&epoch, &direct, fd, 1);
        let mut running = epoch.take(0).unwrap();
        let pending = running.io.take().unwrap();
        assert!(pending.deadline.unwrap() <= Instant::now());
        assert!(matches!(
            direct.resume(pending, running.work.memory.as_deref_mut().unwrap()),
            trames_linux::IoAttempt::Complete(Err(trames_vfs::Errno(11)))
        ));
        epoch.finish(running.finish(None, 0));
        assert_eq!(epoch.drain().len(), 1);
    }
    #[test]
    fn local_resource_notification_interrupts_host_wait_without_network_traffic() {
        let (mut v, fd, _peer) = tcp();
        let [r, w] = v.pipe(0).unwrap();
        let direct = trames_linux::DirectSyscalls::new(v.direct_descriptors())
            .with_network(v.direct_network());
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        tcp_wait(&epoch, &direct, fd, 1);
        epoch.add(job(2, &epoch));
        let mut running = epoch.take(0).unwrap();
        let Some(trames_linux::IoAttempt::Blocked(pending)) = direct.start(
            63,
            [r as u64, 0x1000, 1, 0, 0, 0],
            running.work.memory.as_deref_mut().unwrap(),
            2,
            &epoch.io_target,
            None,
        ) else {
            panic!("pipe wait");
        };
        epoch.park_io(running, pending);
        let e = epoch.clone();
        let thread = std::thread::spawn(move || e.take(0).unwrap());
        await_host_wait(&epoch);
        v.write(w, b"p").unwrap();
        let mut running = thread.join().unwrap();
        assert_eq!(running.work.pid, 2);
        assert!(matches!(
            direct.resume(
                running.io.take().unwrap(),
                running.work.memory.as_deref_mut().unwrap()
            ),
            trames_linux::IoAttempt::Complete(Ok(1))
        ));
        epoch.finish(running.finish(None, 0));
        assert_eq!(epoch.drain().len(), 2);
    }
    #[test]
    fn flock_stop_hands_off_original_request_and_drops_old_subscriptions() {
        let mut vfs = trames_vfs::Vfs::default();
        let a = vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = vfs.open_at(-100, b"/lock", 2, 0).unwrap();
        vfs.flock(b, 6).unwrap();
        let mut files = trames_vfs::FileEpoch::default();
        let direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors())
            .with_files(files.capture(&vfs, true));
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        let mut running = epoch.take(0).unwrap();
        let args = [a as u64, 2, 0, 0, 0, 0];
        let Some(trames_linux::IoAttempt::Blocked(pending)) = direct.start(
            32,
            args,
            running.work.memory.as_deref_mut().unwrap(),
            1,
            &epoch.io_target,
            None,
        ) else {
            panic!("flock wait");
        };
        let signal = Arc::downgrade(&pending.signal);
        let request = pending.flock.as_ref().unwrap().clone();
        epoch.park_io(running, pending);
        epoch.stop();
        let done = epoch.drain();
        assert!(signal.upgrade().is_none());
        assert!(done[0]
            .io
            .as_ref()
            .unwrap()
            .flock
            .as_ref()
            .unwrap()
            .same_owner(&request));
        assert_eq!(done[0].io.as_ref().unwrap().args, args);
        vfs.flock(b, 8).unwrap(); // Old callback cannot resurrect this stopped epoch.
        assert!(epoch.take(0).is_none());
        assert_eq!(request.try_lock(), Ok(()));
        files.finish();
    }

    #[test]
    fn io_wake_before_park_and_stop_preserve_pending_call_and_release_subscriptions() {
        let mut vfs = trames_vfs::Vfs::default();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors());
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        let mut running = epoch.take(0).unwrap();
        let args = [read as u64, 0x1000, 1, 0, 0, 0];
        let attempt = direct
            .start(
                63,
                args,
                running.work.memory.as_deref_mut().unwrap(),
                1,
                &epoch.io_target,
                None,
            )
            .unwrap();
        let trames_linux::IoAttempt::Blocked(pending) = attempt else {
            panic!("expected wait");
        };
        // Wake while the task is running and has not yet entered parked.
        vfs.write(write, b"x").unwrap();
        assert!(pending.signal.ready());
        epoch.park_io(running, pending);
        let mut running = epoch.take(0).unwrap();
        assert_eq!(running.stats.resumes, 1);
        let pending = running.io.take().unwrap();
        assert!(matches!(
            direct.resume(pending, running.work.memory.as_deref_mut().unwrap()),
            trames_linux::IoAttempt::Complete(Ok(1))
        ));
        let attempt = direct
            .start(
                63,
                args,
                running.work.memory.as_deref_mut().unwrap(),
                1,
                &epoch.io_target,
                None,
            )
            .unwrap();
        let trames_linux::IoAttempt::Blocked(pending) = attempt else {
            panic!("expected wait");
        };
        let signal = Arc::downgrade(&pending.signal);
        epoch.park_io(running, pending);
        epoch.stop();
        let done = epoch.drain();
        assert_eq!(done[0].io.as_ref().unwrap().args, args);
        assert!(signal.upgrade().is_none());
        // Old callbacks cannot resurrect a stopped cohort or retain a View.
        vfs.write(write, b"y").unwrap();
        assert!(epoch.take(0).is_none());
    }
    #[test]
    fn wake_before_park_is_retained_and_cancellation_drops_blocked_leases() {
        let table = crate::futex::Futexes::default();
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        epoch.add(job(1, &epoch));
        let running = epoch.take(0).unwrap();
        let wait = table
            .wait_target(
                (0, 1, 0x1000),
                1,
                1,
                Some({
                    let target = Arc::downgrade(&epoch);
                    let target: std::sync::Weak<dyn crate::futex::Wake> = target;
                    target
                }),
                || Ok::<_, ()>(()),
            )
            .unwrap();
        assert_eq!(table.wake((0, 1, 0x1000), 1, 1), 1);
        assert!(!epoch.control.stopped());
        epoch.park(
            running,
            Some(WaitState {
                wait,
                deadline: None,
            }),
        );
        let running = epoch.take(0).unwrap();
        assert_eq!(running.stats.resumes, 1);
        let wait = table
            .wait_target(
                (0, 1, 0x1000),
                1,
                1,
                Some({
                    let target = Arc::downgrade(&epoch);
                    let target: std::sync::Weak<dyn crate::futex::Wake> = target;
                    target
                }),
                || Ok::<_, ()>(()),
            )
            .unwrap();
        epoch.park(
            running,
            Some(WaitState {
                wait,
                deadline: None,
            }),
        );
        epoch.stop();
        let drained = epoch.drain();
        assert_eq!(drained.len(), 1);
        assert!(drained[0].waiting.is_some());
        drop(drained);
        assert_eq!(table.wake((0, 1, 0x1000), 1, 1), 0);
    }
    #[test]
    fn expired_wait_resumes_on_eligible_cpu_without_a_coordinator() {
        let table = crate::futex::Futexes::default();
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        let wait = table
            .wait((0, 1, 0x1000), 1, 1, || Ok::<_, ()>(()))
            .unwrap();
        let mut task = job(1, &epoch);
        task.affinity = 2;
        task.waiting = Some(WaitState {
            wait,
            deadline: Some(Instant::now() + Duration::from_millis(1)),
        });
        epoch.add(task);
        // A worker sleeps until the actual deadline; no polling retry loop.
        let task = epoch.take(1).unwrap();
        assert_eq!(task.work.cpu.x(0), 0u64.wrapping_sub(110));
        assert_eq!(task.stats.resumes, 1);
        assert_eq!(task.stats.worker, 1);
        epoch.finish(task.finish(Some(SliceOutcome::Yield { instructions: 0 }), 0));
        assert_eq!(epoch.drain().len(), 1);
        assert_eq!(table.wake((0, 1, 0x1000), 1, 1), 0);
    }
    #[test]
    fn initial_assignment_keeps_a_flexible_task_out_of_a_pinned_tasks_slot() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        let mut flexible = job(1, &epoch);
        flexible.affinity = 3;
        epoch.add(flexible);
        epoch.add(job(2, &epoch));
        epoch.assign(&[(1, 1), (2, 0)]);
        let pinned = epoch.take(0).unwrap();
        let flexible = epoch.take(1).unwrap();
        assert_eq!(pinned.work.pid, 2);
        assert_eq!(flexible.work.pid, 1);
        epoch.finish(pinned.finish(Some(SliceOutcome::Yield { instructions: 0 }), 0));
        epoch.finish(flexible.finish(Some(SliceOutcome::Yield { instructions: 0 }), 0));
        assert_eq!(epoch.drain().len(), 2);
    }
    #[test]
    fn stop_notifies_an_idle_worker_and_returns_every_view() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        let table = crate::futex::Futexes::default();
        let mut task = job(1, &epoch);
        task.waiting = Some(WaitState {
            wait: table
                .wait((0, 1, 0x1000), 1, 1, || Ok::<_, ()>(()))
                .unwrap(),
            deadline: Some(Instant::now() + Duration::from_secs(3600)),
        });
        epoch.add(task);
        let peer = epoch.clone();
        let thread = std::thread::spawn(move || assert!(peer.take(0).is_none()));
        epoch.stop();
        thread.join().unwrap();
        assert_eq!(epoch.drain().len(), 1);
    }
}
