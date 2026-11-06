// SPDX-License-Identifier: GPL-3.0-or-later
//! CPU workers retain state and run until an event or a requested checkpoint.
//! Pure NativeCall and seccomp-allowed snapshot/clock syscalls run on workers.
//! Task handoff uses retained views; admitted path metadata uses the common
//! resolver and shared inode objects. Lifecycle and namespace changes still join.
//! No queue lock spans interpreter or native execution.
#[cfg(all(test, trames_interpreter_conformance))]
#[path = "coordination_cost.rs"]
mod coordination_cost;

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use trames_engine::{Cpu, DecodeStats, SliceOutcome};
use trames_memory::parallel::View;
use trames_memory::CpuMemory;

/// Local interpreter polls, not scheduler quanta. Completing one of these does
/// not send a message, wait for peers, or give up the CPU or memory view.
const POLL_INSTRUCTIONS: u64 = 16_384;

pub(super) struct Control {
    stop: AtomicBool,
    remaining: AtomicU64,
}
impl Control {
    pub fn new(budget: u64) -> Self {
        Self {
            stop: AtomicBool::new(false),
            remaining: AtomicU64::new(budget),
        }
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
    fn claim(&self) -> Option<u64> {
        if self.stop.load(Ordering::Acquire) {
            return None;
        }
        match self
            .remaining
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                (left != 0).then(|| left.saturating_sub(POLL_INSTRUCTIONS))
            }) {
            Ok(left) => Some(left.min(POLL_INSTRUCTIONS)),
            Err(_) => {
                self.stop();
                None
            }
        }
    }
}

pub(super) struct Work<C: Cpu> {
    pub pid: u32,
    pub cpu: C,
    // Keep worker-local translation caches stationary through preparation,
    // queues and services. Interpreter/native code still borrows the View itself.
    pub memory: Option<Box<View>>,
    pub control: Arc<Control>,
    pub syscalls: Option<crate::worker_syscalls::Snapshot>,
    pub gpu: Option<crate::gpu::Authority>,
    pub audio: Option<crate::devices::Audio>,
}
#[derive(Default)]
pub(super) struct GpuStats {
    pub calls: u64,
    pub transfers: trames_vulkan::TransferMetrics,
    pub errors: u64,
    pub last_error: Option<(u64, u64, u64)>,
    pub compiles: u64,
    pub waits: u64,
    pub wait_time: Duration,
    pub peer_instructions: u64,
}
impl GpuStats {
    pub(super) fn record(
        &mut self,
        pc: u64,
        operation: u64,
        value: &Result<trames_vulkan::Invocation, trames_memory::MemoryError>,
        transfers: trames_vulkan::TransferMetrics,
    ) {
        self.calls += 1;
        self.transfers.merge(transfers);
        if let Ok(trames_vulkan::Invocation::Complete(value)) = value {
            self.record_error(pc, operation, *value);
        }
    }
    pub(super) fn record_error(&mut self, pc: u64, operation: u64, value: u64) {
        if (value as i64) < 0 {
            self.errors += 1;
            self.last_error = Some((pc, operation, value));
        }
    }
    pub fn merge(&mut self, other: Self) {
        self.calls += other.calls;
        self.transfers.merge(other.transfers);
        self.errors += other.errors;
        self.last_error = other.last_error.or(self.last_error);
        self.compiles += other.compiles;
        self.waits += other.waits;
        self.wait_time += other.wait_time;
        self.peer_instructions += other.peer_instructions;
    }
}
pub(super) struct Done<C: Cpu> {
    pub thread_exit: Option<i32>,
    pub fatal_fault: Option<trames_engine::CpuFault>,
    pub exit_groups: Vec<Arc<trames_kernel::task_control::Group>>,
    pub seccomp_entry: Option<crate::process::seccomp::EntryDecision>,
    pub pid: u32,
    pub cpu: C,
    pub outcome: Option<SliceOutcome>,
    pub elapsed: Duration,
    pub before: DecodeStats,
    pub after: DecodeStats,
    pub worker: usize,
    /// All retired instructions, including earlier uninterrupted local polls.
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
    pub waiting: Option<crate::run_queue::WaitState>,
    pub io: Option<crate::run_queue::IoCall>,
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
    pub gpu: GpuStats,
    pub gpu_pending: Option<crate::gpu::Compile>,
}
pub(super) enum Event<C: Cpu> {
    Done(Box<Done<C>>),
    Service(Box<Request<C>>),
    EpochStopped(usize),
    VmReady,
    Retired,
    Idle,
}
/// A production request retains the task's original allocation and View. The
/// coordinator may access this stopped caller, never Process::memory/CPU.
pub(super) struct Request<C: Cpu> {
    pub pid: u32,
    pub pc: u64,
    pub number: u32,
    pub args: [u64; 6],
    target: ReturnTo<C>,
}
// The test-only transport deliberately keeps its original by-value View
// envelope for the existing coordinator cost experiment. Production has only
// the small Cohort variant and no reply channel.
#[cfg_attr(test, allow(clippy::large_enum_variant))]
enum ReturnTo<C: Cpu> {
    Cohort(ServiceReturn<C>),
    #[cfg(all(test, trames_interpreter_conformance))]
    Thread {
        memory: View,
        reply: mpsc::Sender<Reply>,
    },
}
struct ServiceReturn<C: Cpu> {
    job: Option<Box<crate::run_queue::Job<C>>>,
    epoch: Arc<crate::run_queue::Epoch<C>>,
    began: Instant,
}
impl<C: Cpu> Drop for ServiceReturn<C> {
    fn drop(&mut self) {
        if let Some(mut job) = self.job.take() {
            job.stats.service_wait += self.began.elapsed();
            // Return failure, wake idle workers and release the retained View.
            // No dropped request can leave the cohort asleep indefinitely.
            self.epoch.end_service(job, Err(()));
        }
    }
}
#[cfg(all(test, trames_interpreter_conformance))]
struct Reply {
    memory: View,
    value: Option<u64>,
    reply: mpsc::Sender<Reply>,
}
impl<C: Cpu> Request<C> {
    fn for_epoch(
        mut job: Box<crate::run_queue::Job<C>>,
        epoch: Arc<crate::run_queue::Epoch<C>>,
    ) -> Self {
        job.stats.service_waits += 1;
        epoch.start_service(job.work.pid);
        Self {
            pid: job.work.pid,
            pc: job.work.cpu.pc(),
            number: job.work.cpu.x(8) as u32,
            args: std::array::from_fn(|i| job.work.cpu.x(i)),
            target: ReturnTo::<C>::Cohort(ServiceReturn::<C> {
                job: Some(job),
                epoch,
                began: Instant::now(),
            }),
        }
    }
    pub fn memory(&self) -> &View {
        match &self.target {
            ReturnTo::<C>::Cohort(pending) => pending
                .job
                .as_ref()
                .unwrap()
                .work
                .memory
                .as_deref()
                .unwrap(),
            #[cfg(all(test, trames_interpreter_conformance))]
            ReturnTo::<C>::Thread { memory, .. } => memory,
        }
    }
    pub fn memory_mut(&mut self) -> &mut View {
        match &mut self.target {
            ReturnTo::<C>::Cohort(pending) => pending
                .job
                .as_mut()
                .unwrap()
                .work
                .memory
                .as_deref_mut()
                .unwrap(),
            #[cfg(all(test, trames_interpreter_conformance))]
            ReturnTo::<C>::Thread { memory, .. } => memory,
        }
    }
    /// None checkpoints before effects. A completed operation must always
    /// return its result, including when a concurrent stop has been requested.
    pub fn respond(self, value: Option<u64>) {
        match self.target {
            ReturnTo::<C>::Cohort(mut pending) => {
                let mut job = pending.job.take().unwrap();
                job.stats.service_wait += pending.began.elapsed();
                pending.epoch.end_service(job, Ok(value));
            }
            #[cfg(all(test, trames_interpreter_conformance))]
            ReturnTo::<C>::Thread { memory, reply } => {
                let _ = reply.send(Reply {
                    memory,
                    value,
                    reply: reply.clone(),
                });
            }
        }
    }
}
fn native_fault(
    error: trames_accel::native::Error,
    pc: u64,
    module: u64,
    function: u64,
    rejected: &mut Option<(u64, u64, u64)>,
) -> SliceOutcome {
    let fault = match error {
        trames_accel::native::Error::Memory(error) => trames_engine::CpuFault::Memory { pc, error },
        trames_accel::native::Error::InvalidEntry => {
            *rejected = Some((pc, module, function));
            trames_engine::CpuFault::Trap {
                pc,
                instruction: trames_accel::native::INSTRUCTION,
                signal: 4,
                code: 1,
            }
        }
        trames_accel::native::Error::Checkpoint => {
            unreachable!("GPU result cannot defer after effects")
        }
    };
    SliceOutcome::Fault(fault)
}
/// Native scopes begin after stub validation; even unwinding releases the count.
struct NativeScope<'a>(Option<&'a AtomicUsize>);
impl Drop for NativeScope<'_> {
    fn drop(&mut self) {
        if let Some(active) = self.0 {
            active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
enum Command<C: Cpu> {
    #[cfg(all(test, trames_interpreter_conformance))]
    One(Box<Work<C>>),
    Epoch(Arc<crate::run_queue::Epoch<C>>),
}
struct Worker<C: Cpu> {
    send: mpsc::Sender<Command<C>>,
    join: thread::JoinHandle<()>,
    control: Option<Arc<Control>>,
    epoch: Option<Arc<crate::run_queue::Epoch<C>>>,
}
struct DiskWorker {
    send: mpsc::Sender<DiskJob>,
    join: thread::JoinHandle<()>,
}
struct DiskJob(trames_vfs::FileWork, Arc<trames_linux::FileResult>);
impl DiskJob {
    fn run(self) {
        let Self(job, result) = self;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.run())) {
            Ok(reply) => result.complete(reply),
            Err(_) => result.fail(5),
        }
    }
}
struct DiskPool<C: Cpu> {
    workers: Mutex<Vec<DiskWorker>>,
    next: AtomicUsize,
    limit: usize,
    marker: std::marker::PhantomData<fn() -> C>,
    closed: AtomicBool,
}
impl<C: Cpu> DiskPool<C> {
    fn submit(&self, job: DiskJob) {
        let mut workers = self.workers.lock().unwrap();
        if self.closed.load(Ordering::Relaxed) {
            drop(workers);
            job.1.fail(5);
            return;
        }
        // The existing lazy pool keeps at most two host workers. Ordinary
        // requests and bounded ring submissions share these same queues.
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.limit;
        if index >= workers.len() {
            let (send, receive) = mpsc::channel::<DiskJob>();
            if let Ok(join) = thread::Builder::new()
                .name("trames-disk".into())
                .spawn(move || {
                    while let Ok(work) = receive.recv() {
                        work.run();
                    }
                })
            {
                workers.push(DiskWorker { send, join });
            }
        }
        let send = workers.get(index).map(|worker| worker.send.clone());
        drop(workers);
        let job = if let Some(send) = send {
            match send.send(job) {
                Ok(()) => return,
                Err(error) => error.0,
            }
        } else {
            job
        };
        // Thread resource failure preserves one execution and one completion.
        job.run();
    }

    fn shutdown(&self) {
        let workers = {
            let mut workers = self.workers.lock().unwrap();
            self.closed.store(true, Ordering::Relaxed);
            std::mem::take(&mut *workers)
        };
        for worker in workers {
            drop(worker.send);
            let _ = worker.join.join();
        }
    }
}
impl<C: Cpu> trames_linux::FileExecutor for DiskPool<C> {
    fn submit_file(&self, job: trames_vfs::FileWork, result: Arc<trames_linux::FileResult>) {
        result.begin();
        self.submit(DiskJob(job.queued(), result));
    }
}
/// Shared authority over existing CPU slots. Only startup/teardown and command
/// publication take a per-slot lock; no guest CPU/Memory crosses that lock.
pub(super) struct Starter<C: Cpu> {
    workers: Arc<Vec<Mutex<Option<Worker<C>>>>>,
    send: mpsc::Sender<Event<C>>,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    peak_native: Arc<AtomicUsize>,
    active_native: Arc<AtomicUsize>,
    profile_native_overlap: bool,
    closed: Arc<AtomicBool>,
}
pub(super) struct Pool<C: Cpu> {
    workers: Arc<Vec<Mutex<Option<Worker<C>>>>>,
    closed: Arc<AtomicBool>,
    send: mpsc::Sender<Event<C>>,
    receive: mpsc::Receiver<Event<C>>,
    active: Arc<AtomicUsize>,
    pub peak: Arc<AtomicUsize>,
    pub peak_native: Arc<AtomicUsize>,
    active_native: Arc<AtomicUsize>,
    profile_native_overlap: bool,
    disk: Arc<DiskPool<C>>,
}
impl<C: Cpu> Pool<C> {
    pub fn events(&self) -> mpsc::Sender<Event<C>> {
        self.send.clone()
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn new(count: usize) -> Self {
        Self::with_profiling(count, true)
    }
    pub fn with_profiling(count: usize, profile_native_overlap: bool) -> Self {
        let (send, receive) = mpsc::channel();
        Self {
            workers: Arc::new((0..count).map(|_| Mutex::new(None)).collect()),
            closed: Arc::new(AtomicBool::new(false)),
            disk: Arc::new(DiskPool {
                workers: Mutex::new(Vec::new()),
                next: AtomicUsize::new(0),
                limit: count.clamp(1, 2),
                marker: std::marker::PhantomData,
                closed: AtomicBool::new(false),
            }),
            send,
            receive,
            active: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            peak_native: Arc::new(AtomicUsize::new(0)),
            active_native: Arc::new(AtomicUsize::new(0)),
            profile_native_overlap,
        }
    }
    pub fn starter(&self) -> Starter<C> {
        Starter {
            workers: self.workers.clone(),
            send: self.send.clone(),
            active: self.active.clone(),
            peak: self.peak.clone(),
            peak_native: self.peak_native.clone(),
            active_native: self.active_native.clone(),
            profile_native_overlap: self.profile_native_overlap,
            closed: self.closed.clone(),
        }
    }
    pub fn ensure(&mut self, index: usize) -> std::io::Result<()> {
        self.starter().ensure(index)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn dispatch(&mut self, index: usize, work: Work<C>) -> Result<(), ()> {
        let mut slot = self.workers[index].lock().unwrap();
        let worker = slot.as_mut().ok_or(())?;
        if worker.control.is_some() {
            return Err(());
        }
        worker.control = Some(work.control.clone());
        worker
            .send
            .send(Command::<C>::One(Box::new(work)))
            .map_err(|_| ())
    }
    pub fn launch(
        &mut self,
        index: usize,
        epoch: Arc<crate::run_queue::Epoch<C>>,
    ) -> Result<(), ()> {
        epoch.bind_starter(self.starter());
        epoch.activate(index).map_err(|_| ())
    }
    pub fn file_executor(&self) -> Arc<dyn trames_linux::FileExecutor> {
        self.disk.clone()
    }
    fn received(&mut self, event: Event<C>) -> Event<C> {
        if let Event::<C>::EpochStopped(slot) = &event {
            let mut entry = self.workers[*slot].lock().unwrap();
            let worker = entry.as_mut().expect("cohort worker");
            worker.control = None;
            worker.epoch = None;
        }
        if let Event::<C>::Done(done) = &event {
            self.workers[done.worker]
                .lock()
                .unwrap()
                .as_mut()
                .expect("completed worker")
                .control = None;
        }
        event
    }
    pub fn event_timeout(&mut self, timeout: Duration) -> Result<Option<Event<C>>, ()> {
        match self.receive.recv_timeout(timeout) {
            Ok(event) => Ok(Some(self.received(event))),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(()),
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn complete(&mut self) -> Result<Done<C>, ()> {
        loop {
            let event = self.receive.recv().map_err(|_| ())?;
            match self.received(event) {
                Event::<C>::Done(done) => return Ok(*done),
                Event::<C>::Service(request) => request.respond(None),
                Event::<C>::EpochStopped(_)
                | Event::<C>::VmReady
                | Event::<C>::Idle
                | Event::<C>::Retired => return Err(()),
            }
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn complete_timeout(&mut self, timeout: Duration) -> Result<Option<Done<C>>, ()> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.event_timeout(deadline.saturating_duration_since(Instant::now()))? {
                Some(Event::<C>::Done(done)) => return Ok(Some(*done)),
                Some(Event::<C>::Service(request)) => request.respond(None),
                Some(
                    Event::<C>::EpochStopped(_)
                    | Event::<C>::VmReady
                    | Event::<C>::Idle
                    | Event::<C>::Retired,
                ) => return Err(()),
                None => return Ok(None),
            }
        }
    }
}

impl<C: Cpu> Starter<C> {
    pub fn capacity(&self) -> usize {
        self.workers.len()
    }
    pub fn start(
        &self,
        index: usize,
        epoch: Arc<crate::run_queue::Epoch<C>>,
    ) -> std::io::Result<()> {
        self.ensure(index)?;
        let mut slot = self.workers[index].lock().unwrap();
        if self.closed.load(Ordering::Relaxed) {
            return Err(std::io::Error::other("CPU pool closed"));
        }
        let worker = slot.as_mut().expect("started CPU");
        if worker.control.is_some() {
            return Err(std::io::Error::other("CPU slot already executing"));
        }
        worker.control = Some(epoch.control.clone());
        worker.epoch = Some(epoch.clone());
        worker
            .send
            .send(Command::Epoch(epoch))
            .map_err(|_| std::io::Error::other("CPU worker disconnected"))
    }
    #[rustfmt::skip]
    pub fn ensure(&self, index: usize) -> std::io::Result<()> {
        let mut slot = self.workers[index].lock().unwrap();
        if self.closed.load(Ordering::Relaxed) { return Err(std::io::Error::other("CPU pool closed")); }
        if slot.is_some() {
            return Ok(());
        }
        let (send, receive) = mpsc::channel::<Command<C>>();
        let done = self.send.clone();
        let active = self.active.clone();
        let peak = self.peak.clone();
        let active_native = self.active_native.clone();
        let peak_native = self.peak_native.clone();
        let profile_native_overlap = self.profile_native_overlap;
        let join = thread::Builder::new()
            .name(format!("trames-cpu-{index}"))
            .spawn(move || {
                let mut engine = C::Engine::default();
                let mut registry = trames_accel::native::Registry::default();
                let mut direct_scratch = Vec::new();
                let mut file_cache = trames_vfs::DiskReadCache::default();
                #[cfg(all(test, trames_interpreter_conformance))] let (reply, response) = mpsc::channel();
                #[cfg(all(test, trames_interpreter_conformance))] let mut reply = Some(reply);
                while let Ok(command) = receive.recv() {
                    let (epoch, mut single) = match command {
                        #[cfg(all(test, trames_interpreter_conformance))]
                        Command::<C>::One(work) => (None, Some(crate::run_queue::Job::<C>::new(*work, u64::MAX, index, None))),
                        Command::<C>::Epoch(epoch) => (Some(epoch), None),
                    };
                    loop {
                    let Some(mut job) = (if let Some(epoch) = &epoch { epoch.take(index) } else { single.take() }) else { break };
                    let domain = job.domain.clone();
                    let work = &mut job.work;
                    let mut parked = None;
                    let mut parked_hardware = None;
                    let mut parked_io = None;
                    let mut parked_gpu = None;
                    let mut maintenance = false;
                    let mut thread_exit = None;
                    let mut fatal_fault = None;
                    let mut yielded = false;
                    let mut service = false;
                    let mut vm_checkpoint = false;
                    let mut interrupt_prepared = false;
                    let mut execution_guard = None;
                    let control_lease = work.syscalls.as_ref().map(|s|s.io_signals.lifecycle().enter(&s.io_signals,work.pid));

                    if let Some(snapshot) = &work.syscalls {
                        snapshot.direct.swap_scratch(&mut direct_scratch);
                        snapshot.direct.swap_disk_cache(&mut file_cache);
                    }
                    let began = Instant::now();
                    let mut instructions = 0;
                    let mut chunks = 0;
                    let mut running = false;
                    let mut rejected_native = None;
                    let mut gpu_stats = GpuStats::default();
                    let mut credit = 0;
                    let mut syscalls = 0;
                    let mut syscall_time = Duration::ZERO;
                    #[allow(unused_mut)] let mut serviced_syscalls = 0;
                    #[allow(unused_mut)] let mut service_wait = Duration::ZERO;
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        loop {
                            if work.control.stop.load(Ordering::Acquire) {
                                break SliceOutcome::Yield { instructions: 0 };
                            }
                            if domain.as_ref().is_some_and(|domain| domain.paused()) {
                                yielded = true;
                                break SliceOutcome::Yield { instructions: 0 };
                            }
                            if let Some(snapshot) = &work.syscalls {
                                if epoch.is_some() && snapshot.io_signals.scheduling.affinity() & (1u64 << index) == 0 {
                                    yielded = true;
                                    break SliceOutcome::Yield { instructions: 0 };
                                }
                                if let Some(status) = snapshot.io_signals.lifecycle().termination() {
                                    if let (Some(pending),Some(authority)) = (job.gpu_pending.as_mut(),work.gpu.as_ref()) {
                                        if let Some(compile) = pending.compile.take() { authority.context.abandon(compile.job); }
                                    }
                                    if let Some(crate::run_queue::WaitState::Futex { wait, .. }) = &job.waiting { wait.cancel(); }
                                    thread_exit = snapshot.exit_thread(work.pid, status, work.memory.as_deref_mut().expect("exit View"));
                                    if snapshot.futex.take_readied() { work.control.stop(); }
                                    break SliceOutcome::Yield { instructions: 0 };
                                }
                                if let Some(wake) = snapshot.io_wake.as_ref().filter(|s| s.ready()) { wake.reset(); }
                                if matches!(&job.waiting,Some(crate::run_queue::WaitState::Completion(wait)) if wait.release.finished()) {
                                    job.waiting=None;continue;
                                }
                                if let Some(crate::run_queue::WaitState::Signal(wait)) = &job.waiting {
                                    if !snapshot.quiesced() {
                                    if let Some(value) = wait.request.check(&snapshot.io_signals, work.memory.as_deref_mut().expect("signal wait View"), &snapshot.io_routes.namespace) {
                                        work.cpu.set_x(0, value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                        job.waiting = None;
                                        continue;
                                    }
                                }
                                    }
                                if let Some(crate::run_queue::WaitState::Child(wait)) = &job.waiting {
                                    if !snapshot.quiesced() {
                                    if let Some(value) = snapshot.children.wait(wait.request, &snapshot.io_routes.namespace, snapshot.io_signals.group(), work.memory.as_deref_mut().expect("child wait View")).transpose() {
                                        work.cpu.set_x(0, value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                        job.waiting = None;
                                        continue;
                                    }
                                }
                                    }
                                if let Some((sig, shared)) = snapshot.next_io_signal() {
                                    let action = snapshot.actions.get(sig as usize);
                                    let disposition = trames_kernel::signal::disposition(sig, action);
                                    let namespace_init = snapshot.io_routes.namespace.is_nested() && snapshot.identities[0] == 1;
                                    if action.handler == 0 && namespace_init && !matches!(sig, 9 | 19) || disposition == trames_kernel::signal::Disposition::Ignore {
                                        snapshot.io_signals.take(sig, shared);
                                        continue;
                                    }
                                    if disposition == trames_kernel::signal::Disposition::Terminate {
                                        snapshot.io_signals.lifecycle().request_exit(sig as i32);
                                        continue;
                                    }
                                    let stop_held=matches!(&job.waiting,Some(crate::run_queue::WaitState::Namespace(_))) || matches!(&job.waiting,Some(crate::run_queue::WaitState::Completion(wait)) if !wait.release.finished()) || job.pending_cpu.is_some() || job.hardware_wait.as_ref().is_some_and(|w|!w.ready())
                                        || job.gpu_pending.as_ref().is_some_and(|g|g.compile.is_some())
                                        || job.io.as_ref().is_some_and(|io|io.number==2 || io.file_pending().is_some_and(|f|!f.interruptible()))
                                        || job.retry.as_ref().is_some_and(|io|io.number==2 || io.file_checkpoint.is_some() || io.file.as_ref().is_some_and(|f|!f.interruptible()));
                                    if disposition == trames_kernel::signal::Disposition::Stop && !stop_held {
                                        if sig!=19 && snapshot.io_routes.directory.orphaned(&snapshot.io_signals) {
                                            snapshot.io_signals.take(sig,shared);continue;
                                        }
                                        if snapshot.io_signals.lifecycle().consume_stop(sig,||snapshot.io_signals.take(sig,shared).is_some()) {
                                            maintenance=true;break SliceOutcome::Yield {instructions:0};
                                        }
                                        continue;
                                    }
                                    let uninterruptible = matches!(&job.waiting,Some(crate::run_queue::WaitState::Namespace(_))) || matches!(&job.waiting,Some(crate::run_queue::WaitState::Completion(wait)) if !wait.release.finished()) || job.pending_cpu.is_some() || job.gpu_pending.is_some() || job.io.as_ref().is_some_and(|io| io.file_pending().is_some_and(|f|!f.interruptible()) || io.number == 2)
                                        || job.retry.as_ref().is_some_and(|call| call.file.as_ref().is_some_and(|f|!f.interruptible()) || call.number == 2);
                                    if disposition == trames_kernel::signal::Disposition::Handler && !uninterruptible {
                                        if let Some(info) = snapshot.io_signals.take(sig, shared) {
                                            if let Some(waiting) = job.waiting.take() {
                                                if let crate::run_queue::WaitState::Futex { wait, .. } = &waiting {
                                                    wait.cancel();
                                                }
                                                if let crate::run_queue::WaitState::Sleep { deadline, remaining } = &waiting {
                                                    if *remaining != 0 {
                                                        let ns = deadline.saturating_duration_since(Instant::now()).as_nanos();
                                                        let memory = work.memory.as_deref_mut().expect("signal View");
                                                        let _ = memory.write_array(*remaining, ((ns / 1_000_000_000) as u64).to_le_bytes());
                                                        let _ = memory.write_array(*remaining + 8, ((ns % 1_000_000_000) as u64).to_le_bytes());
                                                    }
                                                }
                                                if let crate::run_queue::WaitState::Child(wait) = &waiting {
                                                    if action.flags & 0x10000000 != 0 {
                                                        for (i, value) in wait.request.args.iter().enumerate() { work.cpu.set_x(i, *value); }
                                                        work.cpu.set_pc(work.cpu.pc().wrapping_sub(4));
                                                    } else { work.cpu.set_x(0, 0u64.wrapping_sub(4)); }
                                                } else { work.cpu.set_x(0, 0u64.wrapping_sub(4)); }
                                            }
                                            let pending = job.io.take().as_ref().map(crate::run_queue::IoCall::from).or_else(|| job.retry.take());
                                            if let Some(pending) = pending {
                                                syscalls += 1;
                                                let interrupted=if let Some(wait)=&pending.retained_poll {
                                                    wait.finish(work.memory.as_deref_mut().expect("signal View"),Err(trames_vfs::Errno(4)))
                                                }else{Err(trames_vfs::Errno(4))};
                                                if action.flags & 0x10000000 != 0 && matches!(pending.number, 25 | 32 | 63..=66 | 71 | 76 | 206 | 207 | 211 | 212 | 269) && pending.deadline.is_none() {
                                                    for (i, value) in pending.args.iter().enumerate() { work.cpu.set_x(i, *value); }
                                                    work.cpu.set_pc(work.cpu.pc().wrapping_sub(4));
                                                } else { work.cpu.set_x(0, 0u64.wrapping_sub(interrupted.err().unwrap().0 as u64)); }
                                            }
                                            if snapshot.enter_io_signal(&mut work.cpu, work.memory.as_deref_mut().expect("signal View"), sig, info, action).is_err() {
                                                let _ = snapshot.io_signals.inbox.enqueue(11, trames_kernel::signal::Info::default());
                                                work.control.stop(); break SliceOutcome::Yield { instructions: 0 };
                                            }
                                            continue;
                                        }
                                    }
                                }
                            }
                            if let Some(crate::run_queue::WaitState::Namespace(wait)) = &job.waiting {
                                if wait.ready() {
                                    if let Some((state, result)) = wait.run() {
                                        work.finish_namespaces(state, result);
                                        job.waiting = None;
                                        continue;
                                    }
                                }
                                maintenance = true;
                                break SliceOutcome::Yield { instructions: 0 };
                            }
                            if work.syscalls.as_ref().is_some_and(|s|s.quiesced()) {
                                if job.hardware_wait.as_ref().is_some_and(|w|w.ready()) {job.hardware_wait=None;}
                                let kernel_pending=job.pending_cpu.is_some()
                                    || job.gpu_pending.as_ref().is_some_and(|g|g.compile.is_some())
                                    || job.io.as_ref().is_some_and(|io|io.number==2 || io.file_pending().is_some_and(|f|!f.interruptible()))
                                    || job.retry.as_ref().is_some_and(|io|io.number==2 || io.file_checkpoint.is_some() || io.file.as_ref().is_some_and(|f|!f.interruptible()));
                                if !kernel_pending {maintenance=true;break SliceOutcome::Yield {instructions:0};}
                            }
                            if let Some(epoch) = &epoch {
                                if job.uring.is_none() { job.uring = work.syscalls.as_ref().and_then(|snapshot| snapshot.direct.uring_background(work.pid, &epoch.io_target)); }
                                if let Some(ring) = &mut job.uring {
                                    if !ring.progress(work.memory.as_deref_mut().expect("source task View")) {
                                        maintenance = true;
                                        work.control.stop();
                                        break SliceOutcome::Yield { instructions: 0 };
                                    }
                                    if !ring.active() { job.uring = None; }
                                }
                                if job.hardware_wait.as_ref().is_some_and(|wait| !wait.ready())
                                    || job.waiting.is_some()
                                    || job.io.as_ref().is_some_and(|io| !io.signal.ready() && !io.wake_deadline().is_some_and(|d| d <= Instant::now()))
                                    || job.gpu_pending.as_ref().is_some_and(|gpu| gpu.waiting()) {
                                    maintenance = true; break SliceOutcome::Yield { instructions: 0 };
                                }
                                job.hardware_wait = None;
                            }
                            if let Some(pending) = job.gpu_pending.take() {
                                let accepted = pending.compile.is_some();
                                let call = pending.call;
                                if !accepted && credit == 0 {
                                    let Some(claimed) = work.control.claim() else { job.gpu_pending = Some(pending); break SliceOutcome::Yield { instructions: 0 }; };
                                    credit = claimed;
                                }
                                let epoch = epoch.as_ref().expect("GPU cohort wait");
                                match pending.progress(work.gpu.as_ref().expect("GPU authority"), work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.io_target, &mut gpu_stats, epoch.progress.load(Ordering::Relaxed)) {
                                    crate::gpu::Attempt::Complete(Ok(value)) => {
                                        if !accepted { instructions += 1; credit -= 1; }
                                        work.cpu.set_x(0, value.value); work.cpu.set_x(1, u64::from(value.fallback)); work.cpu.set_pc(call.pc + 4);
                                        continue;
                                    }
                                    crate::gpu::Attempt::Complete(Err(error)) => {
                                        break native_fault(error, call.pc, trames_vulkan::PROFILE, 1, &mut rejected_native);
                                    }
                                    crate::gpu::Attempt::Blocked(pending) => {
                                        if !accepted && pending.compile.is_some() { instructions += 1; credit -= 1; }
                                        parked_gpu = Some(pending); break SliceOutcome::Yield { instructions: 0 };
                                    }
                                    crate::gpu::Attempt::Checkpoint => {
                                        assert!(!accepted, "cannot replay an accepted GPU compile");
                                        credit -= 1;
                                        break SliceOutcome::NativeCall { instructions: 0, pc: call.pc, module: trames_vulkan::PROFILE, function: 1 };
                                    }
                                }
                            }
                            if job.io.is_some() || job.retry.is_some() {
                                let snapshot = work.syscalls.as_ref().expect("retained I/O authority");
                                let began = snapshot.profile.then(Instant::now);
                                let saved_call = job.io.as_ref().map(crate::run_queue::IoCall::from)
                                    .or_else(|| job.retry.clone());
                                let result = if let Some(pending) = job.io.take() {
                                    snapshot.direct.resume(pending, work.memory.as_deref_mut().expect("worker view"))
                                } else {
                                    let call = job.retry.take().unwrap();
                                    let tcp_handoff=call.tcp_liveness.is_some();
                                    let _tcp_liveness=call.tcp_liveness;
                                    if let Some(aio) = call.aio {
                                        snapshot.direct.start_retained_aio(aio, work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.as_ref().unwrap().io_target)
                                    } else if let Some(file) = call.file {
                                        snapshot.direct.start_retained_file(file,call.number,call.args,work.memory.as_deref_mut().expect("worker view"),work.pid,&epoch.as_ref().unwrap().io_target)
                                    } else if let Some(uring) = call.uring {
                                        snapshot.direct.start_retained_uring(uring, call.args, work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.as_ref().unwrap().io_target)
                                    } else if let Some(socket) = call.retained_socket {
                                        snapshot.direct.start_retained_socket(socket,work.memory.as_deref_mut().expect("worker view"),work.pid,&epoch.as_ref().unwrap().io_target)
                                    } else if let Some(request) = call.flock {
                                        snapshot.direct.start_flock(request, call.args, work.memory.as_deref_mut().expect("worker view"),
                                            work.pid, &epoch.as_ref().unwrap().io_target)
                                    } else if let Some(file) = call.retained_byte {
                                        snapshot.direct.start_retained_byte(file, call.number, call.args,
                                            work.memory.as_deref_mut().expect("worker view"), work.pid,
                                            &epoch.as_ref().unwrap().io_target)
                                    } else if let Some(poll) = call.retained_poll {
                                        snapshot.direct.start_retained_poll(poll, call.args,
                                            work.memory.as_deref_mut().expect("worker view"), work.pid,
                                            &epoch.as_ref().unwrap().io_target, call.deadline)
                                    } else {
                                        snapshot.direct.start(call.number, call.args, work.memory.as_deref_mut().expect("worker view"),
                                            work.pid, &epoch.as_ref().unwrap().io_target, call.deadline).unwrap_or_else(||if tcp_handoff {trames_linux::IoAttempt::Checkpoint} else {panic!("admitted I/O retry")})
                                    }
                                };
                                if let Some(began) = began { syscall_time += began.elapsed(); }
                                match result {
                                    trames_linux::IoAttempt::Complete(result) => {
                                        if saved_call.as_ref().is_some_and(|c|trames_linux::event_wait(c.number)) { snapshot.finish_wait_mask(); }
                                        work.cpu.set_x(0, result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                        syscalls += 1;
                                        continue;
                                    }
                                    trames_linux::IoAttempt::Blocked(pending) => {
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}
                                        parked_io = Some(pending);
                                        break SliceOutcome::Yield { instructions: 0 };
                                    }
                                    trames_linux::IoAttempt::FileCheckpoint(file) => {
    let saved = saved_call.as_ref().expect("retained byte call");
    let call = crate::run_queue::IoCall::from_file_checkpoint(file, saved.number, saved.args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break SliceOutcome::Syscall {instructions:0};
},
trames_linux::IoAttempt::ByteCheckpoint(file) => {
    let saved = saved_call.as_ref().expect("retained byte call");
    let call = crate::run_queue::IoCall::from_byte(file, saved.number, saved.args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break SliceOutcome::Syscall {instructions:0};
},
trames_linux::IoAttempt::SocketCheckpoint(socket) => {
                                        for (i,value) in socket.args.iter().enumerate() {work.cpu.set_x(i,*value);}
                                        work.cpu.set_x(8,socket.number as u64);
                                        job.retry=Some(crate::run_queue::IoCall::from_socket(socket));
                                        break SliceOutcome::Syscall {instructions:0};
                                    }
                                    trames_linux::IoAttempt::WaitCheckpoint(wait) => {
 let call=crate::run_queue::IoCall::from_wait(wait);
 for(i,value) in call.args.iter().enumerate(){work.cpu.set_x(i,*value);}
 work.cpu.set_x(8,call.number as u64);job.retry=Some(call);
 break SliceOutcome::Syscall{instructions:0};
},
                                    trames_linux::IoAttempt::Checkpoint => {
                                        // An owner-blocked call can leave -EAGAIN
                                        // in x0. The joined path needs the original
                                        // entry ABI, including when SCM_RIGHTS
                                        // causes an ordinary byte wait to defer.
                                        let call = saved_call.as_ref().expect("accepted I/O arguments");
                                        for (i, value) in call.args.iter().enumerate() {
                                            work.cpu.set_x(i, *value);
                                        }
                                        work.cpu.set_x(8, call.number as u64);
                                        // A SIGPIPE/checkpoint must still reach the
                                        // original accepted OFD in the joined kernel.
                                        job.retry = saved_call.filter(|call| call.retained_socket.is_some() || call.retained_byte.is_some() || call.retained_poll.is_some() || call.tcp_liveness.is_some());
                                        break SliceOutcome::Syscall { instructions: 0 };
                                    }
                                }
                            }
                            if job.pending_cpu.is_none() && work.syscalls.as_ref().is_some_and(|s|s.quiesced()) {
                                maintenance=true;break SliceOutcome::Yield {instructions:0};
                            }
                            if epoch.as_ref().is_some_and(|epoch| epoch.should_yield(index, began, instructions != 0 || syscalls != 0 || (!C::EXACT_INSTRUCTIONS && chunks != 0))) {
                                yielded = true;
                                break SliceOutcome::Yield { instructions: 0 };
                            }
                            if credit == 0 {
                                let Some(claimed) = work.control.claim() else {
                                    break SliceOutcome::Yield { instructions: 0 };
                                };
                                credit = claimed;
                            }
                            let budget = credit;
                            if !running {
                                if profile_native_overlap {
                                    let n = active.fetch_add(1, Ordering::Relaxed) + 1;
                                    peak.fetch_max(n, Ordering::Relaxed);
                                }
                                running = true;
                            }
                            let result = if let Some(pending) = job.pending_cpu.take() {
                                pending
                            } else {
                                if !interrupt_prepared {
                                    let interrupt = match C::execution_interrupt(&mut engine) {
                                        Ok(interrupt) => interrupt,
                                        Err(error) => break SliceOutcome::Fault(error),
                                    };
                                    if let Some(interrupt) = interrupt {
                                        if control_lease.as_ref().is_some_and(|lease|!lease.bind_interrupt(interrupt.clone()) || work.syscalls.as_ref().is_some_and(|s|s.frozen())) {maintenance=true;break SliceOutcome::Yield {instructions:0};}
                                        if let Some(domain)=&domain {
                                        let Some(guard) = domain.bind_interrupt(index, interrupt) else {
                                            yielded = true;
                                            break SliceOutcome::Yield { instructions: 0 };
                                        };
                                        execution_guard = Some(guard);
                                        }
                                    }
                                    interrupt_prepared = true;
                                }
                                let result = work.cpu.run_parallel(
                                    &mut engine,
                                    work.memory.as_deref_mut().expect("worker view"),
                                    budget,
                                );
                                chunks += 1;
                                result
                            };
                            if let Some(wait) = C::take_hardware_wait(&mut engine) {
                                parked_hardware = Some(wait);
                                break result;
                            }
                            let retired = match &result {
                                SliceOutcome::Fault(_) => work.cpu.fault_retired(),
                                SliceOutcome::Yield { instructions }
                                | SliceOutcome::Syscall { instructions }
                                | SliceOutcome::NativeCall { instructions, .. } => *instructions,
                            };
                            instructions += retired;
                            credit -= retired;
                            if profile_native_overlap {
                                if let Some(epoch) = &epoch { epoch.progress.fetch_add(retired, Ordering::Relaxed); }
                            }
                            if let (SliceOutcome::Fault(fault),Some(snapshot)) = (&result,work.syscalls.as_ref()) {
                                if let Some(info) = crate::process::fault_info(fault) {
                                    let blocked = snapshot.io_signals.context.lock().unwrap().mask & (1 << (info.signal-1)) != 0;
                                    if snapshot.actions.get(info.signal as usize).handler <= 1 || blocked {
                                        fatal_fault=match result { SliceOutcome::Fault(fault)=>Some(fault), _=>unreachable!() };
                                        snapshot.io_signals.lifecycle().request_exit(info.signal as i32);
                                        continue;
                                    }
                                }
                            }
                            if matches!(result, SliceOutcome::Syscall { .. }) {
                                work.cpu.clear_exclusive();
                                if work.syscalls.as_ref().is_some_and(|s| s.owner_syscalls) { break result; }
                                if (matches!(work.cpu.x(8) as u32, 97 | 268) || work.cpu.x(8) as u32 == 436 && work.cpu.x(2) as u32 & 2 != 0)
                                    && work.syscalls.as_ref().is_some_and(|s| s.namespaces.is_some()) {
                                    let number = work.cpu.x(8) as u32;
                                    let args = std::array::from_fn(|i| work.cpu.x(i));
                                    let snapshot = work.syscalls.as_ref().unwrap();
                                    let began = snapshot.profile.then(Instant::now);
                                    let entry = snapshot.seccomp.entry_decision(number, work.cpu.pc(), args);
                                    if !entry.allowed() { job.seccomp_entry = Some(entry); break result; }
                                    let attempt = work.namespace_work(number, args).run();
                                    if let Some(began) = began { syscall_time += began.elapsed(); }
                                    syscalls += 1;
                                    match attempt {
                                        trames_vfs::TaskNamespaceAttempt::Complete(state, result) => {
                                            work.finish_namespaces(state, result);
                                            continue;
                                        }
                                        trames_vfs::TaskNamespaceAttempt::Waiting(pending) => {
                                            let wait = crate::run_queue::NamespaceWait::new(pending);
                                            if let Some(signal) = work.syscalls.as_ref().and_then(|s| s.io_wake.as_ref()) { wait.bind(signal); }
                                            parked = Some(crate::run_queue::WaitState::Namespace(wait));
                                            break SliceOutcome::Yield { instructions: 0 };
                                        }
                                    }
                                }
                                if let Some(snapshot) = work.syscalls.as_ref().filter(|s| work.cpu.x(8) as u32 == 139 && s.admit(&work.cpu)) {
                                    if snapshot.return_io_signal(&mut work.cpu, work.memory.as_deref().expect("signal View")).is_ok() { syscalls += 1; continue; }
                                    let _ = snapshot.io_signals.inbox.enqueue(11, trames_kernel::signal::Info::default());
                                    break result;
                                }
                                if let Some(snapshot) = work.syscalls.as_ref().filter(|snapshot| {
                                    snapshot.seccomp.mode() != 0
                                        && (trames_linux::DirectSyscalls::file_call(work.cpu.x(8) as u32)
                                            || snapshot.direct.supports_creation(work.cpu.x(8) as u32)
                                            || snapshot.direct.supports_socket_control(work.cpu.x(8) as u32)
                                            || snapshot.direct.supports_local_message(work.cpu.x(8) as u32, work.cpu.x(0) as u32)
                                            || snapshot.direct.supports_path_query(work.cpu.x(8) as u32)
                                            || snapshot.direct.supports_epoll_control(work.cpu.x(8) as u32)
                                            || matches!(work.cpu.x(8) as u32, 23 | 24 | 57 | 101 | 115 | 436)
                                            || work.cpu.x(8) as u32 == 25
                                                && matches!(work.cpu.x(1), 0 | 1030))
                                }) {
                                    let began = snapshot.profile.then(Instant::now);
                                    let number = work.cpu.x(8) as u32;
                                    let args = std::array::from_fn(|i| work.cpu.x(i));
                                    let entry = snapshot.seccomp.entry_decision(number, work.cpu.pc(), args);
                                    if entry.allowed() {
                                        if let Some(epoch) = &epoch {
                                        if snapshot.direct.supports_call(number, args) {
                                            let attempt = snapshot.direct.start(number, args,
                                                work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.io_target, None)
                                                .expect("retained I/O");
                                            if let Some(began) = began { syscall_time += began.elapsed(); }
                                            match attempt {
                                                trames_linux::IoAttempt::Complete(result) => {
                                                    if trames_linux::event_wait(number) { snapshot.finish_wait_mask(); }
                                                    work.cpu.set_x(0, result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                                    syscalls += 1;
                                                    continue;
                                                }
                                                trames_linux::IoAttempt::Blocked(pending) => {
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}
                                                    parked_io = Some(pending);
                                                    break SliceOutcome::Yield { instructions: 0 };
                                                }
                                                trames_linux::IoAttempt::FileCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_file_checkpoint(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::ByteCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_byte(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::SocketCheckpoint(socket) => {for (i,value) in socket.args.iter().enumerate() {work.cpu.set_x(i,*value);}
                                        work.cpu.set_x(8,socket.number as u64);
                                        job.retry=Some(crate::run_queue::IoCall::from_socket(socket));break result;}
                                                trames_linux::IoAttempt::WaitCheckpoint(wait) => {
 let call=crate::run_queue::IoCall::from_wait(wait);
 for(i,value) in call.args.iter().enumerate(){work.cpu.set_x(i,*value);}
 work.cpu.set_x(8,call.number as u64);job.retry=Some(call);
 break SliceOutcome::Syscall{instructions:0};
},
                                                trames_linux::IoAttempt::Checkpoint => { job.seccomp_entry = Some(entry); break result; },
                                            }
                                        }
                                        if let Some(attempt) = snapshot.direct.start_file_call(number, args,
                                            work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.io_target) {
                                            if let Some(began) = began { syscall_time += began.elapsed(); }
                                            match attempt {
                                                trames_linux::IoAttempt::Complete(value) => {
                                                    work.cpu.set_x(0, value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                                    syscalls += 1; continue;
                                                }
                                                trames_linux::IoAttempt::Blocked(pending) => {
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}
                                                    parked_io = Some(pending); break SliceOutcome::Yield { instructions: 0 };
                                                }
                                                trames_linux::IoAttempt::FileCheckpoint(file) => {
                                                    job.retry = Some(crate::run_queue::IoCall::from_file_checkpoint(file, number, args));
                                                    job.seccomp_entry = Some(entry); break result;
                                                }
                                                _ => unreachable!("typed file entry"),
                                            }
                                        }
                                        }
                                        if let Some(value)=snapshot.direct.invoke_epoll_control(number,args,work.memory.as_deref().expect("worker view")) {
                                            if let Some(began)=began {syscall_time+=began.elapsed();}
                                            work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));
                                            syscalls+=1;continue;
                                        }
                                        if let Some(epoch)=&epoch {
                                            if let Some(attempt)=snapshot.direct.start_socket_control(number,args,work.memory.as_deref_mut().expect("worker view"),work.pid,&epoch.io_target) {
                                                if let Some(began)=began {syscall_time+=began.elapsed();}
                                                match attempt {
                                                    trames_linux::IoAttempt::Complete(value)=>{work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));syscalls+=1;continue;}
                                                    trames_linux::IoAttempt::Blocked(pending)=>{
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}parked_io=Some(pending);break SliceOutcome::Yield {instructions:0};}
                                                    trames_linux::IoAttempt::FileCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_file_checkpoint(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::ByteCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_byte(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::SocketCheckpoint(socket)=>{for (i,value) in socket.args.iter().enumerate() {work.cpu.set_x(i,*value);}
                                        work.cpu.set_x(8,socket.number as u64);
                                        job.retry=Some(crate::run_queue::IoCall::from_socket(socket));break result;}
                                                    trames_linux::IoAttempt::WaitCheckpoint(wait) => {
 let call=crate::run_queue::IoCall::from_wait(wait);
 for(i,value) in call.args.iter().enumerate(){work.cpu.set_x(i,*value);}
 work.cpu.set_x(8,call.number as u64);job.retry=Some(call);
 break SliceOutcome::Syscall{instructions:0};
},
                                                    trames_linux::IoAttempt::Checkpoint =>{job.seccomp_entry=Some(entry);break result;}
                                                }
                                            }
                                        }
                                        if snapshot.direct.supports_local_message(number, args[0] as u32) {
                                            if let Some(epoch) = &epoch {
                                                if let Some(attempt) = snapshot.direct.start(number, args, work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.io_target, None) {
                                                    if let Some(began) = began { syscall_time += began.elapsed(); }
                                                    match attempt {
                                                        trames_linux::IoAttempt::Complete(value) => { work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64))); syscalls+=1; continue; }
                                                        trames_linux::IoAttempt::Blocked(pending) => {
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);} parked_io=Some(pending); break SliceOutcome::Yield { instructions:0 }; }
                                                        trames_linux::IoAttempt::FileCheckpoint(file) => {
                                                            let call=crate::run_queue::IoCall::from_file_checkpoint(file, number, args);
                                                            for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
                                                            work.cpu.set_x(8,call.number as u64);job.retry=Some(call);break result;
                                                        },
trames_linux::IoAttempt::ByteCheckpoint(file) => {
                                                            let call=crate::run_queue::IoCall::from_byte(file, number, args);
                                                            for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
                                                            work.cpu.set_x(8,call.number as u64);job.retry=Some(call);break result;
                                                        }
                                                        trames_linux::IoAttempt::WaitCheckpoint(wait) => {
 let call=crate::run_queue::IoCall::from_wait(wait);
 for(i,value) in call.args.iter().enumerate(){work.cpu.set_x(i,*value);}
 work.cpu.set_x(8,call.number as u64);job.retry=Some(call);
 break SliceOutcome::Syscall{instructions:0};
},
                                                        trames_linux::IoAttempt::Checkpoint => { job.seccomp_entry=Some(entry);break result; }
                                                        trames_linux::IoAttempt::SocketCheckpoint(_) => unreachable!("Unix message start"),
                                                    }
                                                }
                                            }
                                            job.seccomp_entry=Some(entry);break result;
                                        }
                                        if let Some(value)=snapshot.direct.invoke_socket_control(number,args,work.memory.as_deref_mut().expect("worker view")) {
                                            if let Some(began)=began {syscall_time+=began.elapsed();}
                                            work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));
                                            syscalls+=1;continue;
                                        }
                                        if let Some(value)=snapshot.direct.invoke_creation(number,args,work.memory.as_deref_mut().expect("worker view")) {
                                            if let Some(began)=began {syscall_time+=began.elapsed();}
                                            work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));
                                            syscalls+=1;continue;
                                        }
                                        if snapshot.direct.supports_path_query(number) {
                                            let value = snapshot.direct.invoke_file(number,args,work.memory.as_deref_mut().expect("worker view"))
                                                .or_else(||snapshot.direct.invoke_path(number,args,work.memory.as_deref_mut().expect("worker view")));
                                            if let Some(value)=value {
                                                if let Some(began)=began {syscall_time+=began.elapsed();}
                                                work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));
                                                syscalls+=1;continue;
                                            }
                                            job.seccomp_entry=Some(entry);break result;
                                        }

                                        if matches!(number, 101 | 115) {
                                            if epoch.is_none() { job.seccomp_entry = Some(entry); break result; }
                                            let waiting = crate::worker_syscalls::sleep_parameters(
                                                work.memory.as_deref().expect("worker view"), number, args, snapshot.started);
                                            if let Some(began) = began { syscall_time += began.elapsed(); }
                                            syscalls += 1;
                                            match waiting {
                                                Ok((deadline, remaining)) => {
                                                    parked = Some(crate::run_queue::WaitState::Sleep { deadline, remaining });
                                                    break SliceOutcome::Yield { instructions: 0 };
                                                }
                                                Err(error) => { work.cpu.set_x(0, 0u64.wrapping_sub(error.0 as u64)); continue; }
                                            }
                                        }
                                        if let Some(value) = snapshot.direct.invoke_membership(number, args) {
                                            if let Some(began) = began { syscall_time += began.elapsed(); }
                                            work.cpu.set_x(0, value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                            syscalls += 1;
                                            continue;
                                        }
                                    }
                                    // Deferred entries and denials retain
                                    // their normal joined effects. The entry
                                    // token binds this exact ABI and policy.
                                    job.seccomp_entry = Some(entry);
                                    break result;
                                }
                                // Decide before custody: pure policy errors need
                                // neither mm quiescence nor an owner callback.
                                // Carry an allowed/deferred decision exactly once.
                                if epoch.as_ref().is_some_and(|epoch| epoch.local_vm)
                                    && work.syscalls.as_ref().is_some_and(|snapshot| snapshot.seccomp.mode() != 0 || work.cpu.x(8) as u32 == 427)
                                    && crate::worker_syscalls::custody_entry(&work.cpu)
                                    && !(work.cpu.x(8) as u32 == 214 && work.cpu.x(0) == 0)
                                {
                                    let snapshot=work.syscalls.as_ref().expect("custody task");
                                    if snapshot.seccomp.mode()!=0 {
                                        let entry=snapshot.seccomp.entry_decision(work.cpu.x(8) as u32,work.cpu.pc(),std::array::from_fn(|i|work.cpu.x(i)));
                                        if let Some(value)=entry.completed() {work.cpu.set_x(0,value);syscalls+=1;continue;}
                                        job.seccomp_entry=Some(entry);
                                    }
                                    vm_checkpoint = true;
                                    break result;
                                }
                                if let Some(snapshot)=&work.syscalls {
                                    if matches!(work.cpu.x(8) as u32, 132..=137) || epoch.is_some() && matches!(work.cpu.x(8) as u32, 95 | 260) || snapshot.signal_send(&work.cpu) || snapshot.thread_call(&work.cpu) || snapshot.limit_call(work.cpu.x(8) as u32) {
                                        let mut entry = snapshot.task_entry(&work.cpu);
                                        if let Some(decision)=entry.as_ref() {
                                            if !decision.allowed() {
                                                if let Some(value)=decision.completed() {work.cpu.set_x(0,value);syscalls+=1;continue;}
                                                job.seccomp_entry=entry.take();break result;
                                            }
                                        }
                                        if matches!(work.cpu.x(8) as u32, 93 | 94) {
                                            let status=(work.cpu.x(0) as u8 as i32)<<8;
                                            if work.cpu.x(8) as u32 == 94 { snapshot.io_signals.lifecycle().request_exit(status); }
                                            if let Some(exit) = epoch.as_ref().and_then(|_| snapshot.exit_thread(work.pid,status,work.memory.as_deref_mut().expect("exit View"))) {
                                                thread_exit=Some(exit);syscalls+=1;
                                                // An actual excluded legacy waiter still needs its
                                                // existing owner adoption, after accepted cleanup.
                                                if snapshot.futex.take_readied() {work.control.stop();}
                                            } else {job.seccomp_entry=entry;}
                                            break result;
                                        }
                                        let began=snapshot.profile.then(Instant::now);
                                        let number=work.cpu.x(8) as u32;
                                        if matches!(number,95|260) {
                                            let request=match trames_kernel::children::Wait::prepare(number,std::array::from_fn(|i|work.cpu.x(i))) {
                                                Ok(request)=>request, Err(e)=>{work.cpu.set_x(0,0u64.wrapping_sub(e.0 as u64));syscalls+=1;continue;}
                                            };
                                            // Subscribe before checking: an exit between checking and
                                            // parking cannot strand the accepted source wait.
                                            let waiting=snapshot.begin_child_wait(request);
                                            let attempt=snapshot.children.wait(request,&snapshot.io_routes.namespace,snapshot.io_signals.group(),work.memory.as_deref_mut().expect("child wait View"));
                                            if let Some(value)=attempt.transpose() {
                                                work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));syscalls+=1;continue;
                                            }
                                            parked=Some(waiting);
                                            if let Some(began)=began{syscall_time+=began.elapsed();}
                                            syscalls+=1;break SliceOutcome::Yield{instructions:0};
                                        }
                                        if matches!(number,133|137) {
                                            let attempt=trames_kernel::signal::SignalWait::prepare(number,std::array::from_fn(|i|work.cpu.x(i)),work.memory.as_deref().expect("signal wait View"));
                                            let request=match attempt {Ok(r)=>r,Err(e)=>{work.cpu.set_x(0,0u64.wrapping_sub(e.0 as u64));syscalls+=1;continue;}};
                                            if let Some(value)=request.check(&snapshot.io_signals,work.memory.as_deref_mut().expect("signal wait View"),&snapshot.io_routes.namespace) {
                                                work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));syscalls+=1;continue;
                                            }
                                            parked=Some(snapshot.begin_signal_wait(request));
                                            if let Some(began)=began{syscall_time+=began.elapsed();}
                                            syscalls+=1;break SliceOutcome::Yield{instructions:0};
                                        }
                                        if number == 122 {
                                            let reply = snapshot.io_routes.scheduling_request(&snapshot.io_signals, snapshot.cpus, number, std::array::from_fn(|i| work.cpu.x(i)), work.memory.as_deref_mut().expect("affinity View"));
                                            if let Some(began)=began {syscall_time+=began.elapsed();}
                                            syscalls+=1;
                                            match reply {
                                                Err(e) => {work.cpu.set_x(0,0u64.wrapping_sub(e.0 as u64));continue;}
                                                Ok((value, wait)) => {
                                                    work.cpu.set_x(0,value);
                                                    if let (Some(_),Some(wait)) = (&epoch, wait.filter(|w| !w.finished())) {
                                                        let waiting = crate::run_queue::CompletionWait::new(wait);
                                                        if let Some(signal)=&snapshot.io_wake {waiting.bind(&snapshot.io_signals,signal);}
                                                        parked=Some(crate::run_queue::WaitState::Completion(waiting));
                                                        break SliceOutcome::Yield {instructions:0};
                                                    }
                                                    continue;
                                                }
                                            }
                                        }
                                        let value=snapshot.invoke(&work.cpu,work.memory.as_deref_mut().expect("task control View")).expect("shared task control");
                                        if let Some(began)=began{syscall_time+=began.elapsed();}
                                        work.cpu.set_x(0,value);syscalls+=1;continue;
                                    }
                                    if let Some(entry)=snapshot.timer_entry(&work.cpu) {
                                        if !entry.allowed() {job.seccomp_entry=Some(entry);break result;}
                                        let began=snapshot.profile.then(Instant::now);
                                        let value=snapshot.invoke(&work.cpu,work.memory.as_deref_mut().expect("timer View")).expect("shared timer authority");
                                        if let Some(began)=began{syscall_time+=began.elapsed();}
                                        work.cpu.set_x(0,value);syscalls+=1;continue;
                                    }
                                    if let Some(entry)=snapshot.event_entry(&work.cpu) {
                                        if !entry.allowed() {job.seccomp_entry=Some(entry);break result;}
                                        if let Some(epoch)=&epoch {
                                            let number=work.cpu.x(8) as u32;
                                            let args=std::array::from_fn(|i|work.cpu.x(i));
                                            let began=snapshot.profile.then(Instant::now);
                                            if let Some(attempt)=snapshot.direct.start(number,args,work.memory.as_deref_mut().expect("wait View"),work.pid,&epoch.io_target,None) {
                                                if let Some(began)=began{syscall_time+=began.elapsed();}
                                                match attempt {
                                                    trames_linux::IoAttempt::Complete(value)=>{snapshot.finish_wait_mask();work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));syscalls+=1;continue;}
                                                    trames_linux::IoAttempt::Blocked(pending)=>{
                                                        if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}
                                                        parked_io=Some(pending);break SliceOutcome::Yield{instructions:0};
                                                    }
                                                    trames_linux::IoAttempt::WaitCheckpoint(wait)=>{job.retry=Some(crate::run_queue::IoCall::from_wait(wait));break result;}
                                                    trames_linux::IoAttempt::Checkpoint=>{job.seccomp_entry=Some(entry);break result;}
                                                    _=>unreachable!("typed event wait"),
                                                }
                                            }
                                        }
                                        job.seccomp_entry=Some(entry);break result;
                                    }
                                }
                                if let Some(snapshot) = work
                                    .syscalls
                                    .as_ref()
                                    .filter(|snapshot| snapshot.admit(&work.cpu))
                                {
                                    let began = snapshot.profile.then(Instant::now);
                                    if let Some(epoch) = &epoch {
                                        if work.cpu.x(8) as u32 == 124 {
                                            work.cpu.set_x(0, 0);
                                            syscalls += 1;
                                            yielded = true;
                                            break SliceOutcome::Yield { instructions: 0 };
                                        }
                                        if let Some(result) = snapshot.wait(&work.cpu, work.memory.as_deref_mut().expect("worker view"), work.pid, epoch) {
                                            if let Some(began) = began { syscall_time += began.elapsed(); }
                                            syscalls += 1;
                                            match result {
                                                Ok(waiting) => { parked = Some(waiting); break SliceOutcome::Yield { instructions: 0 }; }
                                                Err(error) => { work.cpu.set_x(0, 0u64.wrapping_sub(error.0 as u64)); continue; }
                                            }
                                        }
                                    }
                                    if let Some(epoch) = &epoch {
                                        let number = work.cpu.x(8) as u32;
                                        let args = std::array::from_fn(|i| work.cpu.x(i));

                                        if let Some(attempt)=snapshot.direct.start_socket_control(number,args,work.memory.as_deref_mut().expect("worker view"),work.pid,&epoch.io_target) {
                                            if let Some(began)=began {syscall_time+=began.elapsed();}
                                            match attempt {
                                                trames_linux::IoAttempt::Complete(value)=>{work.cpu.set_x(0,value.unwrap_or_else(|e|0u64.wrapping_sub(e.0 as u64)));syscalls+=1;continue;}
                                                trames_linux::IoAttempt::Blocked(pending)=>{
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}parked_io=Some(pending);break SliceOutcome::Yield {instructions:0};}
                                                trames_linux::IoAttempt::FileCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_file_checkpoint(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::ByteCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_byte(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::SocketCheckpoint(socket)=>{for (i,value) in socket.args.iter().enumerate() {work.cpu.set_x(i,*value);}
                                        work.cpu.set_x(8,socket.number as u64);
                                        job.retry=Some(crate::run_queue::IoCall::from_socket(socket));break result;}
                                                trames_linux::IoAttempt::WaitCheckpoint(wait) => {
 let call=crate::run_queue::IoCall::from_wait(wait);
 for(i,value) in call.args.iter().enumerate(){work.cpu.set_x(i,*value);}
 work.cpu.set_x(8,call.number as u64);job.retry=Some(call);
 break SliceOutcome::Syscall{instructions:0};
},
                                                trames_linux::IoAttempt::Checkpoint =>break result,
                                            }
                                        }
                                        if snapshot.direct.supports_call(number, args) {
                                            let attempt = snapshot.direct.start(number, args,
                                                work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.io_target, None)
                                                .expect("retained I/O");
                                            if let Some(began) = began { syscall_time += began.elapsed(); }
                                            match attempt {
                                                trames_linux::IoAttempt::Complete(result) => {
                                                    work.cpu.set_x(0, result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                                    syscalls += 1;
                                                    continue;
                                                }
                                                trames_linux::IoAttempt::Blocked(pending) => {
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}
                                                    parked_io = Some(pending);
                                                    break SliceOutcome::Yield { instructions: 0 };
                                                }
                                                trames_linux::IoAttempt::FileCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_file_checkpoint(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::ByteCheckpoint(file) => {
    let call = crate::run_queue::IoCall::from_byte(file, number, args);
    for (i,value) in call.args.iter().enumerate() {work.cpu.set_x(i,*value);}
    work.cpu.set_x(8,call.number as u64);
    job.retry=Some(call);
    break result;
},
trames_linux::IoAttempt::SocketCheckpoint(socket) => {for (i,value) in socket.args.iter().enumerate() {work.cpu.set_x(i,*value);}
                                        work.cpu.set_x(8,socket.number as u64);
                                        job.retry=Some(crate::run_queue::IoCall::from_socket(socket));break result;}
                                                trames_linux::IoAttempt::WaitCheckpoint(wait) => {
 let call=crate::run_queue::IoCall::from_wait(wait);
 for(i,value) in call.args.iter().enumerate(){work.cpu.set_x(i,*value);}
 work.cpu.set_x(8,call.number as u64);job.retry=Some(call);
 break SliceOutcome::Syscall{instructions:0};
},
                                                trames_linux::IoAttempt::Checkpoint => break result,
                                            }
                                        }
                                        if let Some(attempt) = snapshot.direct.start_file_call(number, args,
                                            work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.io_target) {
                                            if let Some(began) = began { syscall_time += began.elapsed(); }
                                            match attempt {
                                                trames_linux::IoAttempt::Complete(value) => {
                                                    work.cpu.set_x(0, value.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
                                                    syscalls += 1; continue;
                                                }
                                                trames_linux::IoAttempt::Blocked(pending) => {
 if let Some(wait)=&pending.retained_poll {snapshot.begin_wait_mask(wait);}
                                                    parked_io = Some(pending); break SliceOutcome::Yield { instructions: 0 };
                                                }
                                                trames_linux::IoAttempt::FileCheckpoint(file) => {
                                                    job.retry = Some(crate::run_queue::IoCall::from_file_checkpoint(file, number, args));
                                                    break result;
                                                }
                                                _ => unreachable!("typed file entry"),
                                            }
                                        }

                                    }
                                    if let Some(value) = snapshot
                                        .invoke(&work.cpu, work.memory.as_deref_mut().expect("worker view"))
                                    {
                                        if let Some(began) = began {
                                            syscall_time += began.elapsed();
                                        }
                                        work.cpu.set_x(0, value);
                                        syscalls += 1;
                                        if work.cpu.x(8) as u32 == 98
                                            && snapshot.futex.take_readied()
                                        {
                                            // A task became runnable: request a
                                            // scheduling boundary, not an RPC or
                                            // a replay of this completed wake.
                                            work.control.stop();
                                        }
                                        continue;
                                    }
                                    if epoch.as_ref().is_some_and(|epoch| epoch.local_vm)
                                        && snapshot.seccomp.mode() == 0
                                        && work.cpu.x(8) as u32 == 222
                                        && trames_linux::Linux::mmap_is_additive(std::array::from_fn(|i|work.cpu.x(i)))
                                    {
                                        // New anonymous ownership only. The
                                        // existing owner publishes its interval;
                                        // peers and their translations continue.
                                        service = true;
                                        break SliceOutcome::Yield { instructions: 0 };
                                    }
                                    if epoch.as_ref().is_some_and(|epoch| epoch.local_vm)
                                        && snapshot.seccomp.mode() == 0
                                        && crate::worker_syscalls::custody_entry(&work.cpu)
                                    {
                                        vm_checkpoint = true;
                                        break result;
                                    }
                                    // A retained resource deferred before effects
                                    // for scheduling/SIGPIPE. Do not send the
                                    // same failed operation through RPC first.
                                    if snapshot
                                        .direct
                                        .supports(work.cpu.x(8) as u32, work.cpu.x(0) as u32)
                                    {
                                        break result;
                                    }
                                    if crate::worker_syscalls::service_candidate(
                                        &work.cpu, snapshot,
                                    ) {
                                        if epoch.is_some() {
                                            service = true;
                                            break SliceOutcome::Yield { instructions: 0 };
                                        }
                                        #[cfg(not(test))] unreachable!("single dispatch is test-only");
                                        #[cfg(all(test, trames_interpreter_conformance))] {
                                        let began = Instant::now();
                                        if profile_native_overlap {
                                            active.fetch_sub(1, Ordering::Relaxed);
                                        }
                                        running = false;
                                        let request = Request::<C> {
                                            pid: work.pid,
                                            pc: work.cpu.pc(),
                                            number: work.cpu.x(8) as u32,
                                            args: std::array::from_fn(|i| work.cpu.x(i)),
                                            target: ReturnTo::<C>::Thread {
                                                memory: *work.memory.take().expect("worker view"),
                                                reply: reply.take().expect("worker reply channel"),
                                            },
                                        };
                                        assert!(
                                            done.send(Event::<C>::Service(Box::new(request))).is_ok(),
                                            "coordinator receiver"
                                        );
                                        // Never abandon an in-flight request on stop: it
                                        // may already have consumed input or written bytes.
                                        let answer = response.recv().expect("coordinator response");
                                        work.memory = Some(Box::new(answer.memory));
                                        reply = Some(answer.reply);
                                        service_wait += began.elapsed();
                                        if let Some(value) = answer.value {
                                            work.cpu.set_x(0, value);
                                            serviced_syscalls += 1;
                                            continue;
                                        }
                                        break result;
                                        }
                                    }
                                }
                            }
                            if let SliceOutcome::NativeCall {
                                pc,
                                module,
                                function,
                                ..
                            } = &result
                            {
                                work.cpu.clear_exclusive();
                                let args = [work.cpu.x(0), work.cpu.x(1), work.cpu.x(2)];
                                let gpu = work.gpu.as_ref().filter(|_| *module == trames_vulkan::PROFILE && (epoch.is_some() || !matches!(args[0], 27 | 70 | 110 | 111 | 201 | 202)));
                                let video = work.gpu.as_ref().filter(|_| *module == trames_video::PROFILE);
                                let audio=work.audio.as_ref().filter(|_|*module==trames_audio::PROFILE);
                                let native = if let Some(authority)=audio {
                                    registry.authorize_stateful(work.memory.as_deref().expect("worker view"),*pc,*module,*function)
                                        .and_then(|()|crate::devices::audio(&authority.context,Some(&authority.events),work.memory.as_deref_mut().expect("worker view"),args[0],args[1],args[2]).map_err(trames_accel::native::Error::Memory))
                                        .map(|value|trames_accel::native::Return {value,fallback:false})
                                } else if let Some(authority) = video {
                                    registry.authorize_stateful(work.memory.as_deref().expect("worker view"), *pc, *module, *function)
                                        .and_then(|()| {
                                            let memory=work.memory.as_deref_mut().expect("worker view");
                                            crate::devices::video(&authority.video,authority.events.as_ref(),authority.images.as_ref(),memory,args[0],args[1],args[2])
                                        }
                                        .map(|value| trames_accel::native::Return { value, fallback: false })
                                        .map_err(trames_accel::native::Error::Memory))
                                } else if let Some(authority) = gpu {
                                    match registry.authorize_stateful(work.memory.as_deref().expect("worker view"), *pc, *module, *function) {
                                        Err(error) => Err(error),
                                        Ok(()) => if let Some(epoch) = &epoch {
                                            let call = crate::gpu::Call { pc: *pc, operation: args[0], args };
                                            match crate::gpu::Pending::new(call).progress(authority, work.memory.as_deref_mut().expect("worker view"), work.pid, &epoch.io_target, &mut gpu_stats, epoch.progress.load(Ordering::Relaxed)) {
                                                crate::gpu::Attempt::Complete(value) => value,
                                                crate::gpu::Attempt::Blocked(pending) => {
                                                    // An accepted asynchronous request owns its HLT
                                                    // retirement now, exactly like a blocking SVC.
                                                    if pending.compile.is_some() { instructions += 1; credit -= 1; }
                                                    parked_gpu = Some(pending); break SliceOutcome::Yield { instructions: 0 };
                                                }
                                                crate::gpu::Attempt::Checkpoint => { credit -= 1; break result; }
                                            }
                                        } else {
                                            let (value, transfers) = authority.context.invoke(work.memory.as_deref_mut().expect("worker view"), args[0], args[1], args[2], None);
                                            gpu_stats.record(*pc, args[0], &value, transfers);
                                            value.map_err(trames_accel::native::Error::Memory).map(|value| {
                                                let trames_vulkan::Invocation::Complete(value) = value else { unreachable!("test-only compile admission"); };
                                                trames_accel::native::Return { value, fallback: false }
                                            })
                                        }
                                    }
                                } else { registry.invoke_scoped(
                                    work.memory.as_deref_mut().expect("worker view"),
                                    *pc,
                                    *module,
                                    *function,
                                    args,
                                    || {
                                        if profile_native_overlap {
                                            let n =
                                                active_native.fetch_add(1, Ordering::Relaxed) + 1;
                                            peak_native.fetch_max(n, Ordering::Relaxed);
                                            NativeScope(Some(&active_native))
                                        } else {
                                            NativeScope(None)
                                        }
                                    },
                                ) };
                                match native {
                                    Ok(value) => {
                                        work.cpu.set_x(0, value.value);
                                        work.cpu.set_x(1, u64::from(value.fallback));
                                        work.cpu.set_pc(pc + 4);
                                        instructions += 1;
                                        credit -= 1;
                                        continue;
                                    }
                                    Err(trames_accel::native::Error::Checkpoint) => {
                                        // The pending HLT is reserved for the
                                        // coordinator, and has no body effects.
                                        credit -= 1;
                                        break result;
                                    }
                                    Err(error) => {
                                        let fault = match error {
                                            trames_accel::native::Error::Memory(error) => {
                                                trames_engine::CpuFault::Memory { pc: *pc, error }
                                            }
                                            trames_accel::native::Error::InvalidEntry => {
                                                rejected_native = Some((*pc, *module, *function));
                                                trames_engine::CpuFault::Trap {
                                                    pc: *pc,
                                                    instruction: trames_accel::native::INSTRUCTION,
                                                    signal: 4,
                                                    code: 1,
                                                }
                                            }
                                            trames_accel::native::Error::Checkpoint => {
                                                unreachable!("handled checkpoint")
                                            }
                                        };
                                        break SliceOutcome::Fault(fault);
                                    }
                                }
                            }
                            if !matches!(result,
                                SliceOutcome::Yield { instructions } if !C::EXACT_INSTRUCTIONS || instructions == budget
                            ) {
                                break result;
                            }
                        }
                    }))
                    .ok();
                    if let Some(epoch) = epoch.as_ref().filter(|_|thread_exit.is_none()) {
                        if job.uring.is_none() { job.uring = work.syscalls.as_ref().and_then(|snapshot| snapshot.direct.uring_background(work.pid, &epoch.io_target)); }
                        if let Some(ring) = &mut job.uring {
                            if !ring.progress(work.memory.as_deref_mut().expect("source task View")) { work.control.stop(); }
                            if !ring.active() { job.uring = None; }
                        }
                    }
                    // Withdraw before requesting a checkpoint: this worker is
                    // already out of guest code and must not kick its next job.
                    drop(execution_guard.take());
                    // Reuse credits across native returns. Refund only when this
                    // assignment ends, avoiding a global RMW pair per libc call.
                    work.control.remaining.fetch_add(credit, Ordering::Relaxed);
                    // Syscall, deferred native, fault and yield request a checkpoint
                    // immediately, before the coordinator receives this message.
                    if thread_exit.is_none() && !maintenance && parked.is_none() && parked_hardware.is_none() && parked_io.is_none() && parked_gpu.is_none() && !yielded && !service && !vm_checkpoint { work.control.stop(); }
                    let elapsed = began.elapsed().saturating_sub(service_wait);
                    let after = work.cpu.decode_stats();
                    if running && profile_native_overlap {
                        active.fetch_sub(1, Ordering::Relaxed);
                    }
                    if let Some(snapshot) = &work.syscalls {
                        snapshot.direct.swap_scratch(&mut direct_scratch);
                        snapshot.direct.swap_disk_cache(&mut file_cache);
                    }
                    let stats = &mut job.stats;
                    if let Some(snapshot) = &work.syscalls {
                        snapshot.io_signals.proc_view.account(elapsed, index);
                    }
                    stats.elapsed += elapsed;
                    stats.after = after;
                    stats.worker = index;
                    stats.cpu_times[index] += elapsed;
                    stats.instructions += instructions;
                    stats.chunks += chunks;
                    stats.syscalls += syscalls;
                    stats.serviced_syscalls += serviced_syscalls;
                    stats.service_wait += service_wait;
                    stats.syscall_time += syscall_time;
                    stats.assignments += 1;
                    stats.gpu.merge(gpu_stats);
                    if let Some(snapshot) = &work.syscalls {
                        stats.direct_syscalls = snapshot.direct.completed();
                        stats.file_syscalls = snapshot.direct.file_completed();
                        stats.socket_syscalls = snapshot.direct.socket_completed();
                        stats.timer_syscalls = snapshot.direct.timer_completed();
                        stats.poll_syscalls = snapshot.direct.poll_completed();
                        stats.uring_syscalls = snapshot.direct.uring_completed();
                        stats.fd_syscalls = snapshot.direct.fd_control_completed();
                        stats.futex_wakes = snapshot.futex.completed();
                        stats.futex_woken = snapshot.futex.woken();
                        stats.futex_requeues = snapshot.futex.requeues();
                    }
                    registry.metrics.worker_calls = registry.metrics.calls;
                    stats.native.merge(std::mem::take(&mut registry.metrics));
                    stats.rejected_native = rejected_native.or(stats.rejected_native);
                    if let Some(lease)=control_lease {
                        let held=job.stop_hold().map(|held|held || service || vm_checkpoint || (!maintenance && !yielded && parked.is_none() && parked_hardware.is_none() && parked_io.is_none() && parked_gpu.is_none() && matches!(outcome,Some(SliceOutcome::Syscall{..}|SliceOutcome::NativeCall{..}|SliceOutcome::Fault(_)))));
                        lease.finish(held);
                    }
                    if let Some(task)=job.work.syscalls.as_ref().and_then(|s|s.io_signals.cgroup()) {task.acknowledge();}
                    // The same allocation retains CPU, translations and View;
                    // only its Box pointer enters the shared queues.
                    if let Some(epoch) = &epoch {
                        if vm_checkpoint {
                            epoch.checkpoint(job, outcome.expect("VM syscall outcome"));
                            continue;
                        }
                        if service {
                            let request = Request::<C>::for_epoch(job, epoch.clone());
                            assert!(done.send(Event::<C>::Service(Box::new(request))).is_ok(), "coordinator receiver");
                            continue;
                        }
                        if maintenance { epoch.park_maintenance(job); continue; }
                        if let Some(wait) = parked_hardware { epoch.park_hardware(job, wait); continue; }
                        if let Some(pending) = parked_io { epoch.park_io(job, pending); continue; }
                        if let Some(pending) = parked_gpu { epoch.park_gpu(job, pending); continue; }
                        if parked.is_some() || yielded { epoch.park(job, parked); continue; }
                        let mut completed = if let Some(status)=thread_exit {
                            job.finish_retired(outcome, epoch.progress.load(Ordering::Relaxed),status)
                        } else {job.finish(outcome, epoch.progress.load(Ordering::Relaxed))};
                        // The returned CPU publishes completion. Original
                        // membership also covers cold Rc/Memory projections;
                        // their actual owner finishes it on the Retired event.
                        completed.fatal_fault = fatal_fault;
                        epoch.finish(completed);
                    } else if done.send(Event::<C>::Done(Box::new(job.finish(outcome, 0)))).is_err() { return; }
                    }
                    // Bound descriptors by host workers, not queued guest
                    // tasks, and release orphan handles at the cohort boundary.
                    file_cache = trames_vfs::DiskReadCache::default();
                    if epoch.is_some() && done.send(Event::<C>::EpochStopped(index)).is_err() { return; }
                }
            })?;
        *slot = Some(Worker::<C> {
            send,
            join,
            control: None,
            epoch: None,
        });
        Ok(())
    }
}

impl<C: Cpu> Drop for Pool<C> {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        let controls: Vec<_> = self
            .workers
            .iter()
            .filter_map(|slot| {
                slot.lock()
                    .unwrap()
                    .as_ref()
                    .map(|worker| (worker.control.clone(), worker.epoch.clone()))
            })
            .collect();
        for (control, epoch) in controls {
            if let Some(control) = control {
                control.stop();
            }
            if let Some(epoch) = epoch {
                epoch.stop();
            }
        }
        // A stopped worker may be parked waiting for a queued service request.
        // Return its view before joining; no request is abandoned or replayed.
        while self.workers.iter().any(|slot| {
            slot.lock()
                .unwrap()
                .as_ref()
                .is_some_and(|w| w.control.is_some())
        }) {
            match self.event_timeout(Duration::from_millis(10)) {
                Ok(Some(Event::<C>::Service(request))) => request.respond(None),
                Ok(Some(Event::<C>::Done(_) | Event::<C>::EpochStopped(_))) => {}
                Ok(Some(Event::<C>::VmReady | Event::<C>::Idle | Event::<C>::Retired)) => {}
                Ok(None) => {
                    for slot in self.workers.iter() {
                        if let Some(worker) = slot.lock().unwrap().as_mut() {
                            if worker.join.is_finished() {
                                worker.control = None;
                            }
                        }
                    }
                }
                Err(()) => break,
            }
        }
        for slot in self.workers.iter() {
            let worker = slot.lock().unwrap().take();
            let Some(worker) = worker else { continue };
            drop(worker.send);
            let _ = worker.join.join();
        }
        self.disk.shutdown();
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Pool = crate::workers::Pool<Cpu>;
    type Work = crate::workers::Work<Cpu>;

    #[test]
    fn closed_cpu_pool_reports_source_activation_failure_and_keeps_the_job() {
        let pool = Pool::new(2);
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::with_events(control.clone(), pool.events(), true);
        epoch.bind_starter(pool.starter());
        pool.closed.store(true, Ordering::Relaxed);
        epoch.add(crate::run_queue::Job::new(
            work(7, &[0xd4000001], 0, control),
            2,
            0,
            None,
        ));
        assert!(epoch.activation_failed());
        assert!(epoch.control.stopped());
        assert_eq!(epoch.active_slots(), 0);
        let returned = epoch.drain();
        assert_eq!(returned.len(), 1);
        assert_eq!(returned[0].pid, 7);
    }

    use super::*;
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    use trames_memory::{
        CpuMemory, Memory, MemoryError, NativeMemory, PageBacking, Permissions, PAGE_SIZE,
    };

    #[test]
    fn cohort_blocked_recvmsg_checkpoint_restores_original_arguments() {
        let mut vfs = trames_vfs::Vfs::default();
        let [receiver, sender] = vfs.socketpair(1, 1, 0).unwrap();
        let passed = vfs.eventfd(0, 0).unwrap();
        let socket = vfs.local_socket(sender).unwrap().unwrap();
        socket
            .send_rights(b"x", 0, vfs.send_rights(&[passed]).unwrap())
            .unwrap();
        let mut memory = Memory::default();
        memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .write_array(0x1000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        memory.write_array(0x2010, 0x2100u64.to_le_bytes()).unwrap();
        memory.write_array(0x2018, 1u64.to_le_bytes()).unwrap();
        memory.write_array(0x2020, 0x2300u64.to_le_bytes()).unwrap();
        memory.write_array(0x2028, 24u64.to_le_bytes()).unwrap();
        memory.write_array(0x2100, 0x2200u64.to_le_bytes()).unwrap();
        memory.write_array(0x2108, 8u64.to_le_bytes()).unwrap();
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        // SAFETY: this test owns the root and its only execution View. Root
        // byte access resumes after the worker has stopped and been drained.
        assert!(unsafe { View::try_private_epoch(&mut [&mut view]) });
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::unpreempted(control.clone());
        let args = [receiver as u64, 0x2000, 0, 0x4455, 0x6677, 0x8899];
        let mut cpu = Cpu::new(0x1004, 0);
        cpu.set_x(8, 212);
        for (i, value) in args.into_iter().enumerate() {
            cpu.set_x(i, value);
        }
        // The owner already attempted this blocking call. x0 holds EAGAIN,
        // while the pending call, not the CPU return register, owns its args.
        cpu.set_x(0, 0u64.wrapping_sub(11));
        let mut snapshot = syscall_snapshot();
        snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors());
        let mut job = crate::run_queue::Job::new(
            Work {
                audio: None,
                gpu: None,
                pid: 7,
                cpu,
                memory: Some(Box::new(view)),
                control: control.clone(),
                syscalls: Some(snapshot),
            },
            1,
            0,
            None,
        );
        job.retry = Some(crate::run_queue::IoCall {
            aio: None,
            file: None,
            file_checkpoint: None,
            uring: None,
            number: 212,
            args,
            deadline: None,
            flock: None,
            retained_socket: None,
            retained_byte: None,
            tcp_liveness: None,
            retained_poll: None,
        });
        epoch.add(job);
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert!(matches!(
            done.outcome,
            Some(SliceOutcome::Syscall { instructions: 0 })
        ));
        assert_eq!(std::array::from_fn::<_, 6, _>(|i| done.cpu.x(i)), args);
        assert_eq!((done.cpu.x(8), done.cpu.pc), (212, 0x1004));
        assert_eq!(done.instructions, 0);
        memory.commit_parallel().unwrap();
        let received = vfs
            .local_socket(receiver)
            .unwrap()
            .unwrap()
            .recv(8, 0)
            .unwrap();
        assert_eq!(received.data, b"x");
        let (fds, truncated) = vfs.receive_rights(received.rights, 1, false);
        assert!(!truncated);
        assert_eq!(fds.len(), 1);
    }

    struct LivePage {
        bytes: RefCell<[u8; PAGE_SIZE as usize]>,
        version: Cell<u64>,
        unstable: Cell<bool>,
    }
    impl PageBacking for LivePage {
        fn parallel_key(&self) -> Option<(u64, u64)> {
            Some((self as *const Self as usize as u64, 0))
        }
        fn check(&self, _: u64) -> Result<(), MemoryError> {
            Ok(())
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
            out.copy_from_slice(&self.bytes.borrow()[offset..offset + out.len()]);
            if self.unstable.get() {
                self.version.set(self.version.get().wrapping_add(1));
            }
            Ok(())
        }
        fn write(&self, offset: usize, input: &[u8]) -> Result<(), MemoryError> {
            self.bytes.borrow_mut()[offset..offset + input.len()].copy_from_slice(input);
            self.version.set(self.version.get().wrapping_add(1));
            Ok(())
        }
        fn native_resident(&self) -> bool {
            true
        }
        fn sync(&self) -> Result<(), MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            self.version.get()
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
            Err(MemoryError::InvalidRange)
        }
    }

    fn work(pid: u32, code: &[u32], count: u64, control: Arc<Control>) -> Work {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in code.iter().enumerate() {
            memory
                .write(0x1000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(0, count);
        cpu.set_native_calls(true);
        Work {
            audio: None,
            gpu: None,
            pid,
            cpu,
            memory: Some(Box::new(
                memory.parallel_view(&mut Default::default()).unwrap(),
            )),
            control,
            syscalls: None,
        }
    }

    fn syscall_snapshot() -> crate::worker_syscalls::Snapshot {
        crate::worker_syscalls::Snapshot {
            owner_syscalls: false,
            vfork_release: None,
            native_space: None,
            namespaces: None,
            exit_files: None,
            exit_context: None,
            children: Default::default(),
            limits: None,
            timers: None,

            saved_wait_mask: Default::default(),
            io_signals: Default::default(),
            io_routes: Default::default(),
            io_wake: None,
            futex: Default::default(),
            seccomp: Default::default(),
            identities: [21, 12, 1000, 1001, 2000, 2001, 22],
            started: Instant::now(),
            processor: 1,
            cpus: 4,
            profile: true,
            streams: Default::default(),

            fd_flags: Default::default(),
            umask: Default::default(),
            actions: Default::default(),
            program_break: Default::default(),
            uts: None,
            direct: Default::default(),
        }
    }

    #[test]
    fn child_waits_and_signal_restarts_share_one_slot_without_owner_requests() {
        for (number, caught, restart, adopted) in [
            (260, false, false, false),
            (95, false, false, true),
            (260, true, false, false),
            (260, true, true, false),
            (95, true, true, false),
        ] {
            let mut memory = Memory::default();
            for (address, length) in [
                (0x1000, PAGE_SIZE),
                (0x2000, PAGE_SIZE),
                (0x8000, 3 * PAGE_SIZE),
            ] {
                memory.map(address, length, Permissions::RW).unwrap();
            }
            for (pc, words) in [
                (
                    0x1000,
                    vec![0xd4000001u32, 0xaa0003f3, 0xd2800ba8, 0xd4000001],
                ),
                (0x1100, vec![0xf90002a0u32, 0xd2801168, 0xd4000001]),
            ] {
                for (i, word) in words.into_iter().enumerate() {
                    memory
                        .write_array(pc + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
            }
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            let signals = trames_kernel::signal::Signals::default();
            signals.actions.set(
                10,
                trames_kernel::signal::Action {
                    handler: 0x1100,
                    flags: if restart { 0x10000000 } else { 0 },
                    ..Default::default()
                },
            );
            signals.begin_io();
            let mut snapshot = syscall_snapshot();
            snapshot.io_signals = signals.io.clone();
            snapshot.actions = signals.actions.shared();
            let child = Arc::new(trames_kernel::children::Child::default());
            child.attach(Some(&snapshot.children), 42, 1, 1234);
            let args = if number == 260 {
                [u32::MAX as u64, 0x2100, 0, 0x2200, 0, 0]
            } else {
                [0, 0, 0x2100, 4, 0x2200, 0]
            };
            let request = trames_kernel::children::Wait::prepare(number, args).unwrap();
            let mut cpu = Cpu::new(if adopted { 0x1004 } else { 0x1000 }, 0xb000);
            cpu.set_x(8, number as u64);
            cpu.set_x(21, 0x2000);
            for (i, value) in args.into_iter().enumerate() {
                cpu.set_x(i, value);
            }
            let control = Arc::new(Control::new(u64::MAX));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            epoch.add(crate::run_queue::Job::new(
                Work {
                    pid: 1,
                    cpu,
                    memory: Some(Box::new(
                        memory.parallel_view(&mut Default::default()).unwrap(),
                    )),
                    control: control.clone(),
                    syscalls: Some(snapshot),
                    gpu: None,
                    audio: None,
                },
                1,
                0,
                adopted.then(|| {
                    crate::run_queue::WaitState::Child(crate::run_queue::ChildWait::new(request))
                }),
            ));
            epoch.add(crate::run_queue::Job::new(
                work(2, &[0x14000000], 0, control),
                1,
                0,
                None,
            ));
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.launch(0, epoch.clone()).unwrap();
            epoch.wait_child_parked(1);
            let baseline = epoch.progress.load(Ordering::Relaxed);
            let until = Instant::now() + Duration::from_secs(2);
            while epoch.progress.load(Ordering::Relaxed) == baseline {
                assert!(Instant::now() < until, "peer did not use the released slot");
                std::thread::yield_now();
            }
            assert!(!epoch.control.stopped());
            if caught {
                signals
                    .io
                    .inbox
                    .enqueue(10, trames_kernel::signal::Info::default())
                    .unwrap();
                if restart {
                    epoch.wait_child_parked(1);
                }
            }
            if !caught || restart {
                child.exited(23 << 8);
            }
            let event = pool.event_timeout(Duration::from_secs(5)).unwrap();
            if !matches!(event, Some(Event::EpochStopped(0))) {
                epoch.stop();
                panic!("child wait completion missing: number={number} caught={caught} restart={restart} adopted={adopted} event={}", match event {None=>"none",Some(Event::Service(_))=>"service",Some(Event::Done(_))=>"done",Some(Event::Idle)=>"idle",Some(Event::VmReady)=>"vm",Some(Event::Retired)=>"retired",Some(Event::EpochStopped(_))=>"other worker"});
            }
            let done = epoch.drain();
            let caller = done.iter().find(|d| d.pid == 1).unwrap();
            assert_eq!(
                caller.cpu.x(19),
                if caught && !restart {
                    0u64.wrapping_sub(4)
                } else if number == 260 {
                    42
                } else {
                    0
                }
            );
            assert_eq!(caller.serviced_syscalls, 0);
            assert_eq!(child.reaped(), !caught || restart);
            assert!(
                done.iter().find(|d| d.pid == 2).unwrap().instructions > 0,
                "peer uses the released slot"
            );
            memory.commit_parallel().unwrap();
            assert_eq!(
                memory.read_u64(0x2000).unwrap(),
                if caught { 10 } else { 0 }
            );
        }
    }

    #[test]
    fn caught_io_signal_and_sigreturn_complete_on_the_source_worker() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x8000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        for (address, words) in [
            (0x1000, vec![0xaa0003f3u32, 0xd2800ba8, 0xd4000001]),
            (0x1100, vec![0xf90002a0u32, 0xd2801168, 0xd4000001]),
        ] {
            for (i, word) in words.into_iter().enumerate() {
                memory
                    .write_array(address + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut cpu = Cpu::new(0x1000, 0xa000);
        cpu.set_x(0, 77);
        cpu.set_x(21, 0x2000);
        let snapshot = syscall_snapshot();
        snapshot.actions.set(
            29,
            trames_kernel::signal::Action {
                handler: 0x1100,
                ..Default::default()
            },
        );
        snapshot
            .io_signals
            .inbox
            .enqueue(29, trames_kernel::signal::Info::default())
            .unwrap();
        let signal_task = snapshot.io_signals.clone();
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(100));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        let work = Work {
            pid: 1,
            cpu,
            memory: Some(Box::new(
                memory.parallel_view(&mut Default::default()).unwrap(),
            )),
            control,
            syscalls: Some(snapshot),
            gpu: None,
            audio: None,
        };
        epoch.add(crate::run_queue::Job::new(work, 1, 0, None));
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(done.cpu.x(19), 77);
        assert_eq!(done.syscalls, 1, "sigreturn must retire on worker");
        assert_eq!(done.serviced_syscalls, 0);
        assert_eq!(signal_task.context.lock().unwrap().frames, 0);
        memory.commit_parallel().unwrap();
        assert_eq!(u64::from_le_bytes(memory.read_array(0x2000).unwrap()), 29);
    }

    #[test]
    fn source_thread_exit_releases_resources_and_notifies_children_without_stopping_peers() {
        for slots in [1, 4] {
            for (owner_control, legacy_wait) in [(false, false), (true, false), (false, true)] {
                let control = Arc::new(Control::new(100000));
                let (send, receive) = std::sync::mpsc::channel();
                let epoch = crate::run_queue::Epoch::with_events(control.clone(), send, true);
                let mut caller = work(30, &[0xd2800ba8, 0xd4000001], 23, control.clone());
                let mut snapshot = syscall_snapshot();
                let signals = trames_kernel::signal::Signals::default();
                signals.publish_policy(&trames_vfs::PidNamespace::default(), false);
                let visible = signals.presence.visibility();
                snapshot.io_signals = signals.io.clone();
                let survivor = Arc::new(trames_kernel::signal::IoTask::default());
                snapshot.io_signals.share_process(&survivor);
                let directory = &snapshot.io_routes.directory;
                directory.publish(&survivor, 10, 10, 10, 0, 0);
                directory.publish(&snapshot.io_signals, 30, 10, 10, 0, 0);
                directory.parents.publish(&survivor, 10, &Arc::default());
                directory
                    .parents
                    .publish(&snapshot.io_signals, 30, &Arc::default());
                let child = Arc::new(trames_kernel::signal::IoTask::default());
                let parentage = Arc::new(trames_kernel::task_parent::Parentage::default());
                parentage.set_parent_thread(30);
                parentage.set_death_signal(35);
                directory.parents.publish(&child, 40, &parentage);
                let address = if legacy_wait { 0x1000 } else { 0x9000 };
                let legacy = legacy_wait.then(|| {
                    snapshot
                        .futex
                        .table
                        .wait((0, 0, address), 99, u32::MAX, || Ok::<(), ()>(()))
                        .unwrap()
                });
                let second_legacy = legacy_wait.then(|| {
                    snapshot
                        .futex
                        .table
                        .wait((0, 0, address), 100, u32::MAX, || Ok::<(), ()>(()))
                        .unwrap()
                });
                let addresses = Arc::new(trames_execution::ThreadAddresses::new(address));
                snapshot.io_signals.bind_thread_addresses(&addresses);
                let original = snapshot.io_signals.clone();
                let mut vfs = trames_vfs::Vfs::default();
                let fs_peer = vfs.clone_with_resources(false, true);
                assert!(fs_peer.context_shared());
                let [reader, writer] = vfs.pipe(trames_vfs::O_NONBLOCK).unwrap();
                let accepted = vfs
                    .shared_files()
                    .lookup(reader)
                    .unwrap()
                    .unwrap()
                    .direct_byte()
                    .unwrap();
                if owner_control {
                    vfs.epoll_create(0).unwrap();
                }
                let space = crate::space::Native::default();
                let native_peer = space.share();
                let context = trames_vulkan::Context::new(Default::default());
                let native = context.downgrade();
                space.with(|resources| resources.gpu = Some(context));
                snapshot.native_space = Some(space.clone());
                snapshot.exit_files = Some(vfs.file_table_owner());
                snapshot.exit_context = vfs.context_owner();
                caller.syscalls = Some(snapshot);
                epoch.add(crate::run_queue::Job::new(
                    caller,
                    (1 << slots) - 1,
                    0,
                    None,
                ));
                let mut pool = Pool::new(slots);
                for slot in 0..slots {
                    pool.ensure(slot).unwrap();
                    pool.launch(slot, epoch.clone()).unwrap();
                }
                let mut returned = None;
                if !legacy_wait {
                    assert!(matches!(
                        receive.recv_timeout(Duration::from_secs(5)),
                        Ok(Event::Retired)
                    ));
                    let mut results = epoch.take_retired();
                    assert_eq!(results.len(), 1);
                    assert_eq!(
                        (results[0].pid, results[0].thread_exit),
                        (30, Some(23 << 8))
                    );
                    returned = results.pop();
                    assert!(epoch.take_retired().is_empty());
                    assert!(matches!(
                        receive.recv_timeout(Duration::from_secs(5)),
                        Ok(Event::Idle)
                    ));
                    assert!(!control.stopped(), "individual exit stopped its live peer");
                    epoch.stop();
                }
                for _ in 0..slots {
                    assert!(matches!(
                        pool.event_timeout(Duration::from_secs(5)).unwrap(),
                        Some(Event::EpochStopped(_))
                    ));
                }
                let mut rest = epoch.drain();
                let completed = returned.or_else(|| rest.pop()).unwrap();
                assert!(rest.is_empty(), "accepted CPU was returned twice");
                assert!(
                    !fs_peer.context_shared(),
                    "source exit retires fs membership before collection"
                );
                vfs.collect_retired_descriptors();
                original.finish_exit(30);
                assert_eq!(completed.thread_exit, Some(23 << 8));
                assert_eq!(completed.serviced_syscalls, 0);
                assert!(
                    native.upgrade().is_some(),
                    "the real mm peer still owns its devices"
                );
                native_peer.retire();
                assert!(
                    native.upgrade().is_none(),
                    "source exit, not a later owner projection, retires its mm reference"
                );
                {
                    assert!(!original.live());
                    assert!(
                        !visible.present(),
                        "dead thread remains in shared PID directories"
                    );
                    assert_eq!(addresses.clear_tid(), 0);
                    assert_eq!(accepted.read(1).unwrap(), b"");
                    assert_eq!(vfs.flags(writer), Err(trames_vfs::Errno(9)));
                    assert_eq!(parentage.parent_thread(), 10);
                    assert_eq!(child.process().take(35).unwrap().sender, 10);
                    if let Some(wait) = &legacy {
                        assert!(wait.woken());
                    }
                    if let Some(wait) = &second_legacy {
                        assert!(!wait.woken(), "clear_tid must wake only one waiter");
                    }
                }
            }
        }
    }

    #[test]
    fn thread_exit_address_registration_uses_original_task_state_without_owner_requests() {
        for slots in [1, 4] {
            let linux = trames_linux::Linux::new(0);
            let addresses = linux.thread_addresses().clone();
            let control = Arc::new(Control::new(100000));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            let mut caller = work(
                1,
                &[
                    0xd2800c08, 0xd4000001, 0xaa0003f3, 0xd2800000, 0xd2800ba8, 0xd4000001,
                ],
                0x9000,
                control,
            );
            let snapshot = syscall_snapshot();
            snapshot.io_signals.bind_thread_addresses(&addresses);
            caller.syscalls = Some(snapshot);
            epoch.add(crate::run_queue::Job::new(
                caller,
                (1 << slots) - 1,
                0,
                None,
            ));
            let mut pool = Pool::new(slots);
            for slot in 0..slots {
                pool.ensure(slot).unwrap();
                pool.launch(slot, epoch.clone()).unwrap();
            }
            for _ in 0..slots {
                let event = pool.event_timeout(Duration::from_secs(5)).unwrap();
                if !matches!(event, Some(Event::EpochStopped(_))) {
                    epoch.stop();
                    panic!("thread registration requested an owner");
                }
            }
            let result = epoch.drain().pop().unwrap();
            assert_eq!(result.cpu.x(8), 93);
            assert_eq!(result.cpu.x(19), 22);
            assert_eq!(result.syscalls, 1);
            assert_eq!(result.serviced_syscalls, 0);
            assert_eq!(addresses.clear_tid(), 0x9000);
            assert_eq!(linux.clear_tid_address(), 0x9000);
        }
    }

    #[test]
    fn cgroup_freeze_thaw_and_completed_events_use_existing_executor_slots() {
        use trames_kernel::signal::{IoDirectory, Signals};
        for slots in [1, 4] {
            let mut v = trames_vfs::Vfs::default();
            v.set_runtime_info(1, Default::default());
            v.mkdir_at(-100, b"/sys/fs/cgroup/x", 0o755).unwrap();
            v.cgroup_fork(1, 2, 2);
            let procs = v
                .open_at(-100, b"/sys/fs/cgroup/x/cgroup.procs", 1, 0)
                .unwrap();
            v.write(procs, b"2").unwrap();
            let freeze = v
                .open_at(-100, b"/sys/fs/cgroup/x/cgroup.freeze", 1, 0)
                .unwrap();
            let events = v
                .open_at(-100, b"/sys/fs/cgroup/x/cgroup.events", 0, 0)
                .unwrap();
            let directory = IoDirectory::default();
            let parent = Signals::default();
            let child = Signals::default();
            for (task, pid) in [(&parent, 1), (&child, 2)] {
                task.publish_policy(&Default::default(), true);
                task.begin_io();
                directory.publish(&task.io, pid, pid, pid, 0, 0);
                task.io.bind_cgroup(v.cgroup_task(pid).unwrap());
            }
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.write(0x2100, b"10").unwrap();
            memory
                .write_array(0x2118, 1_000_000u64.to_le_bytes())
                .unwrap();
            let mov = |r: u32, n: u32| 0xd2800000 | (n << 5) | r;
            let mut words = vec![mov(20, 0x2000), mov(21, 0x2200)];
            let call = |words: &mut Vec<u32>, number: u32, args: &[u32]| {
                for (i, arg) in args.iter().enumerate() {
                    words.push(mov(i as u32, *arg));
                }
                words.extend([mov(8, number), 0xd4000001]);
            };
            call(&mut words, 64, &[freeze, 0x2100, 1]);
            let frozen = words.len();
            call(&mut words, 67, &[events, 0x2200, 64, 0]);
            words.extend([0x39404eadu32, 0x7100c5bf]); // ldrb w13,[x21,#19]; cmp w13,#'1'
            let branch = words.len();
            words.push(0x54000001 | ((((frozen as i32 - branch as i32) as u32) & 0x7ffff) << 5));
            words.push(0xf9400293); // save frozen target counter in x19
            call(&mut words, 101, &[0x2110, 0]);
            words.extend([0xf940028a, 0xeb13015f]); // current target counter == x19
            let failure_branch = words.len();
            words.push(0);
            call(&mut words, 64, &[freeze, 0x2101, 1]);
            let resumed = words.len();
            words.extend([0xf940028a, 0xeb13015f]);
            let branch = words.len();
            words.push(0x54000000 | ((((resumed as i32 - branch as i32) as u32) & 0x7ffff) << 5));
            call(&mut words, 93, &[0]);
            let failure = words.len();
            call(&mut words, 93, &[99]);
            words[failure_branch] = 0x54000001 | (((failure - failure_branch) as u32) << 5);
            for (i, word) in words.into_iter().enumerate() {
                memory
                    .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            for (i, word) in [0xf940028au32, 0x9100054a, 0xf900028a, 0x17fffffd]
                .into_iter()
                .enumerate()
            {
                memory
                    .write_array(0x1800 + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            let control = Arc::new(Control::new(20_000_000));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            for (task, pid, pc) in [(&child, 2, 0x1800), (&parent, 1, 0x1000)] {
                let mut snapshot = syscall_snapshot();
                snapshot.io_signals = task.io.clone();
                snapshot.actions = task.actions.shared();
                if pid == 1 {
                    snapshot.direct = trames_linux::DirectSyscalls::new(v.direct_descriptors());
                }
                let mut cpu = Cpu::new(pc, 0);
                cpu.set_x(20, 0x2000);
                epoch.add(crate::run_queue::Job::new(
                    Work {
                        pid,
                        cpu,
                        memory: Some(Box::new(
                            memory.parallel_view(&mut Default::default()).unwrap(),
                        )),
                        control: control.clone(),
                        syscalls: Some(snapshot),
                        gpu: None,
                        audio: None,
                    },
                    (1 << slots) - 1,
                    0,
                    None,
                ));
            }
            let mut pool = Pool::new(slots);
            for slot in 0..slots {
                pool.ensure(slot).unwrap();
                pool.launch(slot, epoch.clone()).unwrap();
            }
            for _ in 0..slots {
                let event = pool.event_timeout(Duration::from_secs(5)).unwrap();
                if !matches!(event, Some(Event::EpochStopped(_))) {
                    epoch.stop();
                    panic!("cgroup control requested an owner or lost its wake");
                }
            }
            let results = epoch.drain();
            let parent = results.iter().find(|d| d.pid == 1).unwrap();
            assert_eq!(
                (parent.cpu.x(8), parent.cpu.x(0)),
                (93, 0),
                "target executed after completed freeze, or thaw failed"
            );
            assert!(results.iter().all(|d| d.serviced_syscalls == 0));
            assert!(!child.io.cgroup().unwrap().frozen());
            drop(results);
            memory.commit_parallel().unwrap();
            assert!(memory.read_u64(0x2000).unwrap() > 0);
        }
    }

    #[test]
    fn thread_group_stop_wait_continue_runs_on_one_slot_without_owner_requests() {
        for slots in [1, 4] {
            use trames_kernel::{
                children::{Child, Children},
                signal::{IoDirectory, Signals},
            };
            let directory = Arc::new(IoDirectory::default());
            let parent = Signals {
                io_directory: directory.clone(),
                ..Default::default()
            };
            let child = Signals {
                io_directory: directory.clone(),
                ..Default::default()
            };
            let sibling = Signals {
                actions: child.actions.shared(),
                io_directory: directory.clone(),
                ..Default::default()
            };
            sibling.io.share_process(&child.io);
            for (task, pid, tgid) in [(&parent, 1, 1), (&child, 42, 42), (&sibling, 43, 42)] {
                task.publish_policy(&Default::default(), true);
                task.begin_io();
                task.io.set_session(1);
                directory.publish(&task.io, pid, tgid, if pid == 1 { 1 } else { 42 }, 0, 0);
            }
            let children = Arc::new(Children::default());
            let event = Arc::new(Child::default());
            event.attach(Some(&children), 42, 1, 0);
            child
                .io
                .lifecycle()
                .bind(&event, Some(parent.io.lifecycle()), 42, 0);
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
            let mov = |r: u32, v: u32| 0xd2800000 | (v << 5) | r;
            let mut code = Vec::new();
            for round in 0..4 {
                code.extend([
                    mov(0, 42),
                    mov(1, 43),
                    mov(2, if round == 0 { 19 } else { 20 }),
                    mov(8, 131),
                    0xd4000001,
                ]);
                for (flags, status) in [(2, 0x2000 + 8 * round), (8, 0x2004 + 8 * round)] {
                    code.extend([
                        mov(0, 42),
                        mov(1, status),
                        mov(2, flags),
                        mov(3, 0),
                        mov(8, 260),
                        0xd4000001,
                    ]);
                    if flags == 2 {
                        code.extend([mov(0, 42), mov(1, 18), mov(8, 129), 0xd4000001]);
                    }
                }
            }
            code.extend([mov(8, 93), 0xd4000001]);
            for (i, word) in code.into_iter().enumerate() {
                memory
                    .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            for (i, word) in [0x91000673u32, 0x17ffffff].into_iter().enumerate() {
                memory
                    .write_array(0x1800 + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            let control = Arc::new(Control::new(20_000_000));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            // Both group members must return their own CPU before the parent's
            // WUNTRACED completes. No spare host slot is reserved for the sender.
            for (task, pid, pc) in [
                (&child, 42, 0x1800),
                (&sibling, 43, 0x1800),
                (&parent, 1, 0x1000),
            ] {
                let mut snapshot = syscall_snapshot();
                snapshot.io_signals = task.io.clone();
                snapshot.actions = task.actions.shared();
                snapshot.children = children.clone();
                snapshot.io_routes = trames_kernel::signal::IoRoutes {
                    directory: directory.clone(),
                    ..Default::default()
                };
                epoch.add(crate::run_queue::Job::new(
                    Work {
                        pid,
                        cpu: Cpu::new(pc, 0),
                        memory: Some(Box::new(
                            memory.parallel_view(&mut Default::default()).unwrap(),
                        )),
                        control: control.clone(),
                        syscalls: Some(snapshot),
                        gpu: None,
                        audio: None,
                    },
                    (1 << slots) - 1,
                    0,
                    None,
                ));
            }
            let mut pool = Pool::new(slots);
            for slot in 0..slots {
                pool.ensure(slot).unwrap();
                pool.launch(slot, epoch.clone()).unwrap();
            }
            let observed = pool.event_timeout(Duration::from_secs(5)).unwrap();
            if !matches!(observed, Some(Event::EpochStopped(_))) {
                epoch.stop();
                panic!("STOP/CONT requested an owner boundary or failed to wake the sole slot");
            }
            for _ in 1..slots {
                assert!(matches!(
                    pool.event_timeout(Duration::from_secs(5)).unwrap(),
                    Some(Event::EpochStopped(_))
                ));
            }
            let results = epoch.drain();
            assert!(results.iter().all(|d| d.serviced_syscalls == 0));
            let sender = results.iter().find(|d| d.pid == 1).unwrap();
            assert_eq!(
                sender.syscalls,
                16,
                "slots={slots} pending={:x}/{:x} mask={:x}/{:x} stopped={} next={:?}",
                child.io.pending_bits(),
                sibling.io.pending_bits(),
                child.io.mask(),
                sibling.io.mask(),
                child.io.lifecycle().stopped(),
                sibling.io.next(u64::MAX)
            );
            assert_eq!((sender.cpu.x(0), sender.cpu.x(8)), (42, 93));
            assert!(!child.io.lifecycle().stopped());
            drop(results);
            memory.commit_parallel().unwrap();
            assert_eq!(
                u32::from_le_bytes(memory.read_array(0x2000).unwrap()),
                (19 << 8) | 0x7f
            );
            assert_eq!(
                u32::from_le_bytes(memory.read_array(0x2008).unwrap()),
                (20 << 8) | 0x7f
            );
            assert_eq!(
                u32::from_le_bytes(memory.read_array(0x2004).unwrap()),
                0xffff
            );
        }
    }

    #[test]
    fn guest_signal_send_wakes_all_signal_wait_apis_on_the_only_worker_slot() {
        for number in [137, 63, 65, 22, 73, 133] {
            let directory = Arc::new(trames_kernel::signal::IoDirectory::default());
            let receiver = trames_kernel::signal::Signals {
                mask: 1 << 9,
                io_directory: directory.clone(),
                ..Default::default()
            };
            receiver.actions.set_handler(10, 0x1200);
            receiver.begin_io();
            receiver.publish_policy(&Default::default(), true);
            let sender = trames_kernel::signal::Signals {
                io_directory: directory.clone(),
                ..Default::default()
            };
            sender.publish_policy(&Default::default(), true);
            directory.publish(&receiver.io, 1, 1, 1, 0, 0);
            directory.publish(&sender.io, 2, 2, 1, 0, 0);
            let mut v = trames_vfs::Vfs::default();
            v.bind_signal_reader(receiver.reader(&Default::default()));
            let fd = v.signalfd(-1, 1 << 9, 0).unwrap();
            let ep = v.epoll_create(0).unwrap();
            v.epoll_ctl(ep, 1, fd, 1, 77).unwrap();
            let mut memory = Memory::default();
            for (a, n) in [
                (0x1000, PAGE_SIZE),
                (0x2000, PAGE_SIZE),
                (0x8000, 3 * PAGE_SIZE),
            ] {
                memory.map(a, n, Permissions::RW).unwrap();
            }
            let mov = |r: u32, v: u32| 0xd2800000 | (v << 5) | r;
            for (address, code) in [
                (0x1000, vec![0xd4000001, 0xaa0003f3, mov(8, 93), 0xd4000001]),
                (0x1100, vec![0xd4000001, 0x14000000]),
                (0x1200, vec![0xf90002a0, mov(8, 139), 0xd4000001]),
            ] {
                for (i, word) in code.into_iter().enumerate() {
                    memory
                        .write_array(address + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
            }
            memory
                .write_array(0x2000, (1u64 << 9).to_le_bytes())
                .unwrap();
            if number == 65 {
                memory.write_array(0x2200, 0x2100u64.to_le_bytes()).unwrap();
                memory.write_array(0x2208, 128u64.to_le_bytes()).unwrap();
            } else if number == 73 {
                memory.write_array(0x2200, fd.to_le_bytes()).unwrap();
                memory.write_array(0x2204, 1u32.to_le_bytes()).unwrap();
            }
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            let args = match number {
                137 => [0x2000, 0x2100, 0, 8, 0, 0],
                63 => [fd as u64, 0x2100, 128, 0, 0, 0],
                65 => [fd as u64, 0x2200, 1, 0, 0, 0],
                22 => [ep as u64, 0x2300, 1, u64::MAX, 0, 8],
                73 => [0x2200, 1, 0, 0, 0, 0],
                _ => [0x2010, 8, 0, 0, 0, 0],
            };
            let control = Arc::new(Control::new(100000));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            for (pid, pc, signals, args, number) in [
                (1, 0x1000, &receiver, args, number),
                (2, 0x1100, &sender, [1, 1, 10, 0, 0, 0], 131),
            ] {
                let mut cpu = Cpu::new(pc, 0xb000);
                cpu.set_x(8, number as u64);
                cpu.set_x(21, 0x2400);
                for (i, a) in args.into_iter().enumerate() {
                    cpu.set_x(i, a);
                }
                let mut snapshot = syscall_snapshot();
                snapshot.io_signals = signals.io.clone();
                snapshot.actions = signals.actions.shared();
                snapshot.io_routes = trames_kernel::signal::IoRoutes {
                    directory: directory.clone(),
                    ..Default::default()
                };
                if pid == 1 {
                    snapshot.direct = trames_linux::DirectSyscalls::new(v.direct_descriptors())
                        .with_membership(v.shared_files());
                }
                epoch.add(crate::run_queue::Job::new(
                    Work {
                        pid,
                        cpu,
                        memory: Some(Box::new(
                            memory.parallel_view(&mut Default::default()).unwrap(),
                        )),
                        control: control.clone(),
                        syscalls: Some(snapshot),
                        gpu: None,
                        audio: None,
                    },
                    1,
                    0,
                    None,
                ));
            }
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.launch(0, epoch.clone()).unwrap();
            assert!(
                matches!(
                    pool.event_timeout(Duration::from_secs(5)).unwrap(),
                    Some(Event::EpochStopped(0))
                ),
                "wait {number}"
            );
            let results = epoch.drain();
            let done = results.iter().find(|d| d.pid == 1).unwrap();
            let expected = match number {
                137 => 10,
                63 | 65 => 128,
                133 => 0u64.wrapping_sub(4),
                _ => 1,
            };
            assert_eq!(done.cpu.x(19), expected, "wait {number}");
            assert_eq!(done.syscalls, if number == 133 { 2 } else { 1 });
            assert!(results.iter().all(|d| d.serviced_syscalls == 0));
            assert_eq!(receiver.io.mask(), 1 << 9);
            drop(results);
            memory.commit_parallel().unwrap();
            if number == 133 {
                assert_eq!(memory.read_u64(0x2400).unwrap(), 10);
            }
        }
    }

    #[test]
    fn posix_timer_api_expiry_and_signal_return_use_the_only_worker_slot() {
        let mut memory = Memory::default();
        for (a, n) in [
            (0x1000, PAGE_SIZE),
            (0x2000, PAGE_SIZE),
            (0x8000, 3 * PAGE_SIZE),
        ] {
            memory.map(a, n, Permissions::RW).unwrap();
        }
        let mov = |r: u32, v: u32| 0xd2800000 | (v << 5) | r;
        let svc = 0xd4000001;
        let code = [
            mov(0, 1),
            mov(1, 0x2200),
            mov(2, 0x2300),
            mov(8, 107),
            svc,
            0xaa0003f3,
            0xb9400300,
            mov(1, 0),
            mov(2, 0x2100),
            mov(3, 0),
            mov(8, 110),
            svc,
            0xaa0003f4,
            mov(0, 0),
            mov(1, 0),
            mov(2, 0x2400),
            mov(3, 0),
            mov(8, 73),
            svc,
            0xaa0003f6,
            0xb9400300,
            mov(8, 111),
            svc,
            0xaa0003f7,
            mov(8, 93),
            svc,
        ];
        for (a, code) in [
            (0x1000, code.to_vec()),
            (0x1100, vec![0xf90002a0, mov(8, 139), svc]),
        ] {
            for (i, word) in code.into_iter().enumerate() {
                memory
                    .write_array(a + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
        }
        for (a, v) in [
            (0x2118, 10_000_000u64),
            (0x2200, 42),
            (0x2208, 10),
            (0x2400, 3600),
        ] {
            memory.write_array(a, v.to_le_bytes()).unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let timers = Arc::new(trames_kernel::timers::Timers::default());
        let mut snapshot = syscall_snapshot();
        snapshot.timers = Some(timers.clone());
        snapshot
            .io_routes
            .directory
            .publish(&snapshot.io_signals, 1, 1, 1, 0, 0);
        snapshot.actions.set(
            10,
            trames_kernel::signal::Action {
                handler: 0x1100,
                flags: 0x10000000,
                ..Default::default()
            },
        );
        let task = snapshot.io_signals.clone();
        let mut cpu = Cpu::new(0x1000, 0xb000);
        cpu.set_x(21, 0x2000);
        cpu.set_x(24, 0x2300);
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        epoch.bind_timers(timers.clone());
        epoch.add(crate::run_queue::Job::new(
            Work {
                pid: 1,
                cpu,
                memory: Some(Box::new(
                    memory.parallel_view(&mut Default::default()).unwrap(),
                )),
                control,
                syscalls: Some(snapshot),
                gpu: None,
                audio: None,
            },
            1,
            0,
            None,
        ));
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(
            (
                done.cpu.x(19),
                done.cpu.x(20),
                done.cpu.x(22),
                done.cpu.x(23)
            ),
            (0, 0, 0u64.wrapping_sub(4), 0)
        );
        assert_eq!(done.serviced_syscalls, 0);
        assert_eq!(done.syscalls, 5);
        assert!(timers.next_deadline().is_none());
        assert_eq!(task.context.lock().unwrap().frames, 0);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_u64(0x2000).unwrap(), 10);
    }
    #[test]
    fn masked_event_wait_signal_and_sigreturn_need_no_owner_service() {
        for number in [22, 72, 73, 441] {
            let mut v = trames_vfs::Vfs::default();
            let epoll = v.epoll_create(0).unwrap();
            let mut memory = Memory::default();
            memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
            memory.map(0x8000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
            for (address, words) in [
                (
                    0x1000,
                    vec![0xd4000001u32, 0xaa0003f3, 0xd2800ba8, 0xd4000001],
                ),
                (0x1100, vec![0xf90002a0u32, 0xd2801168, 0xd4000001]),
            ] {
                for (i, word) in words.into_iter().enumerate() {
                    memory
                        .write_array(address + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
            }
            memory.write_array(0x2100, 3600u64.to_le_bytes()).unwrap();
            memory.write_array(0x2200, 0x2210u64.to_le_bytes()).unwrap();
            memory.write_array(0x2208, 8u64.to_le_bytes()).unwrap();
            memory
                .write_array(0x2210, (1u64 << 11).to_le_bytes())
                .unwrap();
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            let mut snapshot = syscall_snapshot();
            snapshot.direct = trames_linux::DirectSyscalls::new(v.direct_descriptors());
            snapshot.io_signals.context.lock().unwrap().mask = 1 << 9;
            snapshot.io_signals.publish_mask(1 << 9);
            snapshot.actions.set(
                10,
                trames_kernel::signal::Action {
                    handler: 0x1100,
                    flags: 0x10000000,
                    ..Default::default()
                },
            );
            snapshot
                .io_signals
                .inbox
                .enqueue(10, Default::default())
                .unwrap();
            let task = snapshot.io_signals.clone();
            let mut cpu = Cpu::new(0x1000, 0xb000);
            cpu.set_x(8, number as u64);
            cpu.set_x(21, 0x2000);
            let args = match number {
                72 => [0, 0, 0, 0, 0x2100, 0x2200],
                73 => [0, 0, 0x2100, 0x2210, 8, 0],
                22 => [epoll as u64, 0x2300, 1, 3600000, 0x2210, 8],
                _ => [epoll as u64, 0x2300, 1, 0x2100, 0x2210, 8],
            };
            for (i, a) in args.iter().enumerate() {
                cpu.set_x(i, *a);
            }
            let control = Arc::new(Control::new(100));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            epoch.add(crate::run_queue::Job::new(
                Work {
                    pid: 1,
                    cpu,
                    memory: Some(Box::new(
                        memory.parallel_view(&mut Default::default()).unwrap(),
                    )),
                    control,
                    syscalls: Some(snapshot),
                    gpu: None,
                    audio: None,
                },
                1,
                0,
                None,
            ));
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.launch(0, epoch.clone()).unwrap();
            assert!(
                matches!(
                    pool.event_timeout(Duration::from_secs(5)).unwrap(),
                    Some(Event::EpochStopped(0))
                ),
                "wait {number} did not retire"
            );
            let done = epoch.drain().pop().unwrap();
            assert_eq!(done.cpu.x(19), 0u64.wrapping_sub(4));
            assert_eq!(done.syscalls, 2, "interrupted wait plus sigreturn");
            assert_eq!(done.serviced_syscalls, 0);
            let state = *task.context.lock().unwrap();
            assert_eq!(state.mask, 1 << 9);
            assert_eq!(state.wait_mask, None);
            assert_eq!(state.frames, 0);
            memory.commit_parallel().unwrap();
            assert_eq!(memory.read_u64(0x2000).unwrap(), 10);
        }
    }
    #[test]
    fn aio_releases_the_only_slot_and_retains_its_batch_across_cohort_handoff() {
        struct Disk(Mutex<Option<(trames_vfs::FileWork, Arc<trames_linux::FileResult>)>>);
        impl trames_linux::FileExecutor for Disk {
            fn submit_file(
                &self,
                work: trames_vfs::FileWork,
                result: Arc<trames_linux::FileResult>,
            ) {
                *self.0.lock().unwrap() = Some((work, result));
            }
        }
        let disk = Arc::new(Disk(Mutex::new(None)));
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/data", b"payload".to_vec()).unwrap();
        let fd = v.open_at(trames_vfs::AT_FDCWD, b"/data", 0, 0).unwrap();
        let aio = trames_linux::Aio::default();
        let mut memory = Memory::default();
        memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        aio.install(&mut memory).unwrap();
        for (i, word) in [0xaa0003f3u32, 0xd2800ba8, 0xd4000001]
            .into_iter()
            .enumerate()
        {
            memory
                .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let direct = || {
            trames_linux::DirectSyscalls::new(v.direct_descriptors())
                .with_paths(v.path_queries())
                .with_aio(aio.clone(), v.native_events())
                .with_file_executor(disk.clone())
        };
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        assert!(matches!(
            direct().start(
                0,
                [8, 0x2000, 0, 0, 0, 0],
                &mut memory,
                1,
                &epoch.io_target,
                None
            ),
            Some(trames_linux::IoAttempt::Complete(Ok(0)))
        ));
        let context = u64::from_le_bytes(memory.read_array(0x2000).unwrap());
        let mut cb = [0; 64];
        cb[20..24].copy_from_slice(&fd.to_le_bytes());
        cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
        cb[32..40].copy_from_slice(&7u64.to_le_bytes());
        memory.write_array(0x2100, cb).unwrap();
        memory.write_array(0x2200, 0x2100u64.to_le_bytes()).unwrap();
        let pending = match direct()
            .start(
                2,
                [context, 1, 0x2200, 0, 0, 0],
                &mut memory,
                1,
                &epoch.io_target,
                None,
            )
            .unwrap()
        {
            trames_linux::IoAttempt::Blocked(p) => p,
            _ => panic!("disk work must park"),
        };
        let mut snapshot = syscall_snapshot();
        snapshot.direct = direct();
        let source = Work {
            pid: 1,
            cpu: Cpu::new(0x1000, 0),
            memory: Some(Box::new(
                memory.parallel_view(&mut Default::default()).unwrap(),
            )),
            control: control.clone(),
            syscalls: Some(snapshot),
            gpu: None,
            audio: None,
        };
        let mut source = crate::run_queue::Job::new(source, 1, 0, None);
        source.io = Some(pending);
        epoch.add(source);
        epoch.add(crate::run_queue::Job::new(
            work(2, &[0xd4000001], 0, control),
            1,
            0,
            None,
        ));
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let mut results = epoch.drain();
        let source = results.remove(results.iter().position(|d| d.pid == 1).unwrap());
        assert_eq!(
            results[0].instructions, 1,
            "peer must use the only slot while disk is pending"
        );
        assert!(source.io.as_ref().unwrap().aio.is_some());
        assert_eq!(source.serviced_syscalls, 0);
        memory.commit_parallel().unwrap();
        let (work, result) = disk.0.lock().unwrap().take().unwrap();
        result.complete(work.run());
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        let mut snapshot = syscall_snapshot();
        snapshot.direct = direct();
        let work = Work {
            pid: 1,
            cpu: source.cpu,
            memory: Some(Box::new(
                memory.parallel_view(&mut Default::default()).unwrap(),
            )),
            control,
            syscalls: Some(snapshot),
            gpu: None,
            audio: None,
        };
        let mut job = crate::run_queue::Job::new(work, 1, 0, None);
        job.retry = source.io;
        epoch.add(job);
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(done.cpu.x(19), 1);
        assert_eq!(done.syscalls, 1);
        assert_eq!(done.serviced_syscalls, 0);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<7>(0x3000).unwrap(), *b"payload");
    }

    #[test]
    fn accepted_syscall_and_fault_are_dispatched_without_executing_past_them() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(100));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        // The previous engine already accepted getpid; the PC is at mov x19,x0.
        let mut task = work(1, &[0xaa0003f3, 0xd2800ba8, 0xd4000001], 7, control);
        task.cpu.set_x(8, 172);
        task.syscalls = Some(syscall_snapshot());
        let mut task = crate::run_queue::Job::new(task, 1, 0, None);
        task.pending_cpu = Some(SliceOutcome::Syscall { instructions: 0 });
        epoch.add(task);
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(
            (
                done.cpu.x(19),
                done.syscalls,
                done.instructions,
                done.chunks
            ),
            (21, 1, 3, 1)
        );
        assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));

        let control = Arc::new(Control::new(100));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        let mut task = crate::run_queue::Job::new(work(1, &[0xd4000001], 0, control), 1, 0, None);
        task.pending_cpu = Some(SliceOutcome::Fault(trames_engine::CpuFault::Host(
            "accepted fault".into(),
        )));
        epoch.add(task);
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(
            (done.cpu.pc, done.instructions, done.chunks),
            (0x1000, 0, 0)
        );
        assert!(
            matches!(done.outcome, Some(SliceOutcome::Fault(trames_engine::CpuFault::Host(ref error))) if error == "accepted fault")
        );
    }

    #[test]
    fn accepted_native_exit_enters_its_body_once_on_the_worker() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(100));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        let (mut task, mut memory) = native_work(3, [0x2000, 0x6b, 128], Permissions::RW, control);
        task.cpu.pc = 0x100c;
        task.cpu.set_x(16, trames_accel::native::PROFILE);
        task.cpu.set_x(17, 3);
        let mut task = crate::run_queue::Job::new(task, 1, 0, None);
        task.pending_cpu = Some(SliceOutcome::NativeCall {
            instructions: 0,
            pc: 0x100c,
            module: trames_accel::native::PROFILE,
            function: 3,
        });
        epoch.add(task);
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(
            (
                done.native.calls,
                done.native.worker_calls,
                done.instructions,
                done.chunks
            ),
            (1, 1, 3, 1)
        );
        assert_eq!(done.cpu.pc, 0x1018);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [0x6b; 128]);
    }
    #[test]
    fn shared_futex_alias_requeue_and_wake_release_one_slot_with_exact_svc_retirement() {
        let mut parent = Memory::default();
        parent.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        parent
            .map_shared_anonymous(0x3000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        for (base, words) in [
            (0x1000, &[0xd4000001u32, 0xd2800ba8, 0xd4000001][..]),
            (
                0x2000,
                &[
                    0xd4000001u32,
                    0xaa0003f3,
                    0xaa0403e0,
                    0xd2800141,
                    0xd2800022,
                    0xd2800045,
                    0xd4000001,
                    0xaa0003f4,
                    0xd2800f88,
                    0xd4000001,
                    0x14000000,
                ][..],
            ),
        ] {
            for (i, word) in words.iter().enumerate() {
                parent
                    .write_array(base + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
        }
        parent
            .protect(0x1000, 2 * PAGE_SIZE, Permissions::RX)
            .unwrap();
        let mut child = parent.clone();
        child
            .remap(0x3000, PAGE_SIZE, 0x5000, PAGE_SIZE, false)
            .unwrap();
        let mut registry = Default::default();
        let views = [
            parent.parallel_view(&mut registry).unwrap(),
            child.parallel_view(&mut registry).unwrap(),
        ];
        let table = crate::futex::Futexes::default();
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::unpreempted(control.clone());
        for (i, view) in views.into_iter().enumerate() {
            let mut cpu = Cpu::new(if i == 0 { 0x1000 } else { 0x2000 }, 0);
            let args = if i == 0 {
                [0x3000, 9, 0, 0, 0, 2]
            } else {
                [0x5000, 4, 0, 1, 0x5004, 0]
            };
            cpu.set_x(8, 98);
            for (r, value) in args.into_iter().enumerate() {
                cpu.set_x(r, value);
            }
            let mut snapshot = syscall_snapshot();
            snapshot.futex = crate::futex::Authority::new(table.clone(), i as u64 + 10);
            epoch.add(crate::run_queue::Job::new(
                Work {
                    audio: None,
                    gpu: None,
                    pid: i as u32 + 1,
                    cpu,
                    memory: Some(Box::new(view)),
                    control: control.clone(),
                    syscalls: Some(snapshot),
                },
                1,
                0,
                None,
            ));
        }
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let mut results = epoch.drain();
        results.sort_by_key(|r| r.pid);
        assert_eq!(results.len(), 2);
        assert_eq!((results[0].waits, results[0].resumes), (1, 1));
        assert_eq!(
            (results[1].cpu.x(19), results[1].cpu.x(20)),
            (1, 1),
            "wake pc={:#x} x0={} x8={} outcome={:?}",
            results[1].cpu.pc,
            results[1].cpu.x(0),
            results[1].cpu.x(8),
            results[1].outcome
        );
        assert_eq!(
            (results[1].futex_requeues, results[1].futex_wakes),
            (1, 1),
            "wake pc={:#x} x0={} x8={} outcome={:?}",
            results[1].cpu.pc,
            results[1].cpu.x(0),
            results[1].cpu.x(8),
            results[1].outcome
        );
        assert_eq!(results.iter().map(|r| r.instructions).sum::<u64>(), 13);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 987);
        assert!(results
            .iter()
            .all(|r| r.serviced_syscalls == 0 && r.waiting.is_none()));
    }

    #[test]
    fn cohort_wait_wake_and_yield_release_one_host_slot_without_a_checkpoint() {
        let mut memory = Memory::default();
        memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        for (base, words) in [
            (0x1000, &[0xd4000001u32, 0xd2800ba8, 0xd4000001][..]),
            (
                0x2000,
                &[
                    0xd280054a, 0xb900000a, 0xd4000001, 0xaa0003f3, 0xd2800f88, 0xd4000001,
                    0x14000000,
                ][..],
            ),
        ] {
            for (i, word) in words.iter().enumerate() {
                memory
                    .write_array(base + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
        }
        memory
            .protect(0x1000, 2 * PAGE_SIZE, Permissions::RX)
            .unwrap();
        let mut first = memory.parallel_view(&mut Default::default()).unwrap();
        let mut second = first.clone();
        // SAFETY: the test owns every Memory root and both Views. It accesses
        // no coordinator bytes until the cohort has stopped and dropped Views.
        assert!(unsafe { View::try_private_epoch(&mut [&mut first, &mut second]) });
        let table = crate::futex::Futexes::default();
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::unpreempted(control.clone());
        for (pid, pc, op, value, view) in [(1, 0x1000, 128, 0, first), (2, 0x2000, 129, 1, second)]
        {
            let mut cpu = Cpu::new(pc, 0);
            for (reg, value) in [(8, 98), (0, 0x3000), (1, op), (2, value)] {
                cpu.set_x(reg, value);
            }
            let mut snapshot = syscall_snapshot();
            snapshot.futex = crate::futex::Authority::new(table.clone(), 1);
            epoch.add(crate::run_queue::Job::new(
                Work {
                    audio: None,
                    gpu: None,
                    pid,
                    cpu,
                    memory: Some(Box::new(view)),
                    control: control.clone(),
                    syscalls: Some(snapshot),
                },
                1,
                0,
                None,
            ));
        }
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let mut results = epoch.drain();
        results.sort_by_key(|d| d.pid);
        assert_eq!(results.len(), 2);
        assert_eq!(
            (results[0].waits, results[0].resumes, results[1].yields),
            (1, 1, 1)
        );
        assert_eq!(results[0].cpu.x(0), 0);
        assert_eq!(
            results[1].cpu.x(19),
            1,
            "wake pc={:#x} x0={} x8={} outcome={:?}",
            results[1].cpu.pc,
            results[1].cpu.x(0),
            results[1].cpu.x(8),
            results[1].outcome
        );
        assert_eq!(results.iter().map(|r| r.instructions).sum::<u64>(), 9);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 991);
        assert_eq!(results.iter().map(|r| r.assignments).sum::<u64>(), 3);
        assert!(results
            .iter()
            .all(|r| r.serviced_syscalls == 0 && r.waiting.is_none()));
        memory.commit_parallel().unwrap();
        assert_eq!(u32::from_le_bytes(memory.read_array(0x3000).unwrap()), 42);
    }

    #[test]
    fn byte_resource_and_epoll_handoff_release_one_slot_and_retire_each_svc_once() {
        // Pipe, eventfd, pipe epoll, Unix read/write, Unix epoll, Unix send/recv.
        for mode in 0..6 {
            let mut vfs = trames_vfs::Vfs::default();
            let (read, write, syscall, count) = if mode == 1 {
                let event = vfs.eventfd(0, 0).unwrap();
                (event, event, 63, 8)
            } else {
                let [read, write] = if mode >= 3 {
                    vfs.socketpair(1, 1, 0).unwrap()
                } else {
                    vfs.pipe(0).unwrap()
                };
                if matches!(mode, 2 | 4) {
                    let ep = vfs.epoll_create(0).unwrap();
                    vfs.epoll_ctl(ep, 1, read, 0xc0000001, 42).unwrap();
                    (ep, write, 22, 1)
                } else {
                    (read, write, if mode == 5 { 207 } else { 63 }, 1)
                }
            };
            let mut memory = Memory::default();
            memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
            for (base, words) in [
                (0x1000, &[0xd4000001u32, 0xd2800ba8, 0xd4000001][..]),
                (
                    0x2000,
                    &[0xd4000001, 0xaa0003f3, 0xd2800f88, 0xd4000001, 0x14000000][..],
                ),
            ] {
                for (i, word) in words.iter().enumerate() {
                    memory
                        .write_array(base + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
            }
            memory.write_array(0x3100, 1u64.to_le_bytes()).unwrap();
            memory
                .protect(0x1000, 2 * PAGE_SIZE, Permissions::RX)
                .unwrap();
            let mut first = memory.parallel_view(&mut Default::default()).unwrap();
            let mut second = first.clone();
            // SAFETY: test owns every root/View; no owner byte access until drain.
            assert!(unsafe { View::try_private_epoch(&mut [&mut first, &mut second]) });
            let control = Arc::new(Control::new(100));
            let epoch = crate::run_queue::Epoch::unpreempted(control.clone());
            for (pid, pc, fd, number, address, view) in [
                (1, 0x1000, read, syscall, 0x3200, first),
                (
                    2,
                    0x2000,
                    write,
                    if mode == 5 { 206 } else { 64 },
                    0x3100,
                    second,
                ),
            ] {
                let mut cpu = Cpu::new(pc, 0);
                for (reg, value) in [
                    (8, number),
                    (0, fd as u64),
                    (1, address),
                    (2, count),
                    (
                        3,
                        if matches!(number, 206 | 207) {
                            0
                        } else {
                            u64::MAX
                        },
                    ),
                ] {
                    cpu.set_x(reg, value);
                }
                let mut snapshot = syscall_snapshot();
                snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors());
                epoch.add(crate::run_queue::Job::new(
                    Work {
                        audio: None,
                        gpu: None,
                        pid,
                        cpu,
                        memory: Some(Box::new(view)),
                        control: control.clone(),
                        syscalls: Some(snapshot),
                    },
                    1,
                    0,
                    None,
                ));
            }
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.launch(0, epoch.clone()).unwrap();
            assert!(matches!(
                pool.event_timeout(Duration::from_secs(5)).unwrap(),
                Some(Event::EpochStopped(0))
            ));
            let mut results = epoch.drain();
            results.sort_by_key(|d| d.pid);
            assert_eq!(
                (results[0].io_waits, results[0].resumes, results[1].yields),
                (1, 1, 1),
                "mode={mode} read pc={:#x} x0={} x8={} outcome={:?}; write x0={} x8={} outcome={:?}",results[0].cpu.pc,results[0].cpu.x(0),results[0].cpu.x(8),results[0].outcome,results[1].cpu.x(0),results[1].cpu.x(8),results[1].outcome
            );
            assert_eq!(results[0].cpu.x(0), if mode == 1 { 8 } else { 1 });
            assert_eq!(results[1].cpu.x(19), if mode == 1 { 8 } else { 1 });
            assert_eq!(results.iter().map(|r| r.instructions).sum::<u64>(), 7);
            assert_eq!(control.remaining.load(Ordering::Relaxed), 93);
            assert_eq!(results.iter().map(|r| r.direct_syscalls).sum::<u64>(), 2);
            assert!(results
                .iter()
                .all(|r| r.serviced_syscalls == 0 && r.io.is_none()));
            memory.commit_parallel().unwrap();
            if matches!(mode, 2 | 4) {
                assert_eq!(u64::from_le_bytes(memory.read_array(0x3208).unwrap()), 42);
            } else {
                assert_eq!(u64::from_le_bytes(memory.read_array(0x3200).unwrap()), 1);
            }
        }
    }

    #[test]
    fn epoll_timeout_reuses_pending_call_without_retiring_a_second_svc() {
        let mut vfs = trames_vfs::Vfs::default();
        let ep = vfs.epoll_create(0).unwrap();
        let (mut task, _memory) = direct_read_work(&vfs, ep);
        task.cpu.set_x(8, 22);
        task.cpu.set_x(2, 1);
        // Expire only after the worker has actually parked. A 1 ms timeout
        // can finish in start() under QEMU or sanitizer instrumentation.
        task.cpu.set_x(3, 3_600_000);
        let control = task.control.clone();
        let epoch = crate::run_queue::Epoch::new(control.clone());
        // End at a cold syscall after the timeout, instead of a compute loop.
        let mut code = Memory::default();
        code.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in [0xd4000001u32, 0xd2800ba8, 0xd4000001].iter().enumerate() {
            code.write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        code.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        task.memory = Some(Box::new(
            code.parallel_view(&mut Default::default()).unwrap(),
        ));
        epoch.add(crate::run_queue::Job::new(task, 1, 0, None));
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        epoch.expire_parked_io(1);
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let result = epoch.drain().pop().unwrap();
        assert_eq!(result.cpu.x(0), 0);
        assert_eq!(
            (
                result.instructions,
                result.io_waits,
                result.resumes,
                result.direct_syscalls
            ),
            (3, 1, 1, 1),
            "pc={:#x} x0={} x8={} outcome={:?}",
            result.cpu.pc,
            result.cpu.x(0),
            result.cpu.x(8),
            result.outcome
        );
        assert_eq!(control.remaining.load(Ordering::Relaxed), 97);
    }

    #[test]
    fn log_readers_park_and_resume_on_one_slot_without_services_or_svc_replay() {
        for stream in [false, true] {
            let mut vfs = trames_vfs::Vfs::default();
            vfs.set_runtime_info(1, trames_vfs::RuntimeInfo::default());
            let fd = vfs.open_at(-100, b"/dev/kmsg", 2, 0).unwrap();
            let mut memory = Memory::default();
            memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
            for (base, words) in [
                (0x1000, &[0xd4000001u32, 0xd2800728, 0xd4000001][..]), // read; close checkpoint
                (
                    0x2000,
                    &[0xd4000001u32, 0xd2800f88, 0xd4000001, 0x14000000][..],
                ), // write; yield
            ] {
                for (i, word) in words.iter().enumerate() {
                    memory
                        .write_array(base + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
            }
            memory.write(0x3000, b"wake").unwrap();
            memory
                .protect(0x1000, 2 * PAGE_SIZE, Permissions::RX)
                .unwrap();
            let mut first = memory.parallel_view(&mut Default::default()).unwrap();
            let mut second = first.clone();
            // SAFETY: root memory is not accessed until both owned Views stop.
            assert!(unsafe { View::try_private_epoch(&mut [&mut first, &mut second]) });
            let control = Arc::new(Control::new(1000));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            for (pid, pc, number, arg0, address, count, view) in [
                (
                    1,
                    0x1000,
                    if stream { 116 } else { 63 },
                    if stream { 2 } else { fd as u64 },
                    0x3100,
                    1024,
                    first,
                ),
                (2, 0x2000, 64, fd as u64, 0x3000, 4, second),
            ] {
                let mut cpu = Cpu::new(pc, 0);
                for (r, value) in [(8, number), (0, arg0), (1, address), (2, count)] {
                    cpu.set_x(r, value);
                }
                let mut snapshot = syscall_snapshot();
                snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors())
                    .with_kernel_log(vfs.kernel_log_capability());
                epoch.add(crate::run_queue::Job::new(
                    Work {
                        audio: None,
                        gpu: None,
                        pid,
                        cpu,
                        memory: Some(Box::new(view)),
                        control: control.clone(),
                        syscalls: Some(snapshot),
                    },
                    1,
                    0,
                    None,
                ));
            }
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.launch(0, epoch.clone()).unwrap();
            assert!(matches!(
                pool.event_timeout(Duration::from_secs(5)).unwrap(),
                Some(Event::EpochStopped(0))
            ));
            let mut done = epoch.drain();
            done.sort_by_key(|d| d.pid);
            assert_eq!((done[0].io_waits, done[0].resumes), (1, 1));
            assert!(done[0].cpu.x(0) > 4 && done[0].cpu.x(0) < 1024);
            assert_eq!(done.iter().map(|d| d.instructions).sum::<u64>(), 6);
            assert_eq!(control.remaining.load(Ordering::Relaxed), 994);
            assert_eq!(done.iter().map(|d| d.direct_syscalls).sum::<u64>(), 2);
            assert!(done
                .iter()
                .all(|d| d.serviced_syscalls == 0 && d.io.is_none()));
            memory.commit_parallel().unwrap();
            let mut bytes = vec![0; done[0].cpu.x(0) as usize];
            memory.read(0x3100, &mut bytes).unwrap();
            assert!(bytes.windows(4).any(|w| w == b"wake"));
        }
    }

    #[test]
    fn blocking_flock_releases_one_host_slot_and_retires_each_svc_once() {
        let mut vfs = trames_vfs::Vfs::default();
        let a = vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = vfs.open_at(-100, b"/lock", 2, 0).unwrap();
        vfs.flock(b, 6).unwrap();
        let mut files = trames_vfs::FileEpoch::default();
        let capabilities = files.capture(&vfs, true);
        let mut memory = Memory::default();
        memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        for (base, words) in [
            (0x1000, &[0xd4000001u32, 0xd2800728, 0xd4000001][..]), // flock; close checkpoint
            (
                0x2000,
                &[0xd4000001u32, 0xd2800f88, 0xd4000001, 0x14000000][..],
            ), // unlock; yield
        ] {
            for (i, word) in words.iter().enumerate() {
                memory
                    .write_array(base + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
        }
        memory
            .protect(0x1000, 2 * PAGE_SIZE, Permissions::RX)
            .unwrap();
        let mut first = memory.parallel_view(&mut Default::default()).unwrap();
        let mut second = first.clone();
        // SAFETY: all root byte access waits until the owned Views are drained.
        assert!(unsafe { View::try_private_epoch(&mut [&mut first, &mut second]) });
        let control = Arc::new(Control::new(1000));
        // This asserts exact retirement at the explicit close checkpoint,
        // independently of host-load time-slice preemption.
        let epoch = crate::run_queue::Epoch::unpreempted(control.clone());
        for (pid, pc, fd, op, view) in [(1, 0x1000, a, 2, first), (2, 0x2000, b, 8, second)] {
            let mut cpu = Cpu::new(pc, 0);
            cpu.set_x(8, 32);
            cpu.set_x(0, fd as u64);
            cpu.set_x(1, op);
            let mut snapshot = syscall_snapshot();
            snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors())
                .with_files(capabilities.clone());
            epoch.add(crate::run_queue::Job::new(
                Work {
                    audio: None,
                    gpu: None,
                    pid,
                    cpu,
                    memory: Some(Box::new(view)),
                    control: control.clone(),
                    syscalls: Some(snapshot),
                },
                1,
                0,
                None,
            ));
        }
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let mut done = epoch.drain();
        done.sort_by_key(|d| d.pid);
        assert_eq!((done[0].io_waits, done[0].resumes), (1, 1));
        assert_eq!(done[0].cpu.x(0), 0);
        assert_eq!(done.iter().map(|d| d.fd_syscalls).sum::<u64>(), 2);
        assert_eq!(done.iter().map(|d| d.instructions).sum::<u64>(), 6);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 994);
        assert!(done
            .iter()
            .all(|d| d.serviced_syscalls == 0 && d.io.is_none()));
        assert_eq!(vfs.flock(b, 6), Err(trames_vfs::Errno(11)));
        files.finish();
    }

    #[test]
    fn nanosleep_resumes_with_success_while_a_peer_uses_the_same_host_slot() {
        let mut memory = Memory::default();
        memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
        for (base, words) in [
            (
                0x1000,
                &[0xd4000001u32, 0xaa0003f3, 0xd2800ba8, 0xd4000001][..],
            ),
            (0x2000, &[0x91000694u32, 0x17ffffff][..]),
        ] {
            for (i, word) in words.iter().enumerate() {
                memory
                    .write_array(base + i as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
        }
        memory
            .write_array(0x3008, 2_000_000u64.to_le_bytes())
            .unwrap();
        memory.write_array(0x3020, [0xa5; 16]).unwrap();
        memory
            .protect(0x1000, 2 * PAGE_SIZE, Permissions::RX)
            .unwrap();
        let first = memory.parallel_view(&mut Default::default()).unwrap();
        let second = first.clone();
        let control = Arc::new(Control::new(100_000_000));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        for (pid, pc, view) in [(1, 0x1000, first), (2, 0x2000, second)] {
            let mut cpu = Cpu::new(pc, 0);
            cpu.set_x(8, 101);
            cpu.set_x(0, 0x3000);
            cpu.set_x(1, 0x3020);
            epoch.add(crate::run_queue::Job::new(
                Work {
                    audio: None,
                    gpu: None,
                    pid,
                    cpu,
                    memory: Some(Box::new(view)),
                    control: control.clone(),
                    syscalls: Some(syscall_snapshot()),
                },
                1,
                0,
                None,
            ));
        }
        epoch.assign(&[(1, 0)]);
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let began = Instant::now();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain();
        let sleeper = done.iter().find(|d| d.pid == 1).unwrap();
        assert_eq!(sleeper.cpu.x(19), 0);
        assert_eq!(sleeper.cpu.x(8), 93);
        assert_eq!((sleeper.waits, sleeper.resumes), (1, 1));
        assert!(began.elapsed() >= Duration::from_millis(2));
        assert!(done.iter().find(|d| d.pid == 2).unwrap().cpu.x(20) > 0);
        assert!(done.iter().all(|d| d.serviced_syscalls == 0));
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<16>(0x3020).unwrap(), [0xa5; 16]);
    }

    #[test]
    fn timer_read_epoll_and_ppoll_rearm_and_wake_on_one_host_slot_without_services() {
        for mode in 0..3 {
            let mut vfs = trames_vfs::Vfs::default();
            let timer = vfs.timerfd(1, 0).unwrap();
            let ep = vfs.epoll_create(0).unwrap();
            vfs.epoll_ctl(ep, 1, timer, 0x80000001, 42).unwrap();
            vfs.timerfd_set(
                timer,
                Duration::ZERO,
                Some(Instant::now() + Duration::from_secs(3600)),
            )
            .unwrap();
            let mut memory = Memory::default();
            memory.map(0x1000, 3 * PAGE_SIZE, Permissions::RW).unwrap();
            for (base, words) in [
                (0x1000, &[0xd4000001u32, 0xd2800ba8, 0xd4000001][..]),
                (
                    0x2000,
                    &[
                        0xd4000001u32,
                        0xaa0003f3,
                        0xd2800f88,
                        0xd4000001,
                        0x14000000,
                    ][..],
                ),
            ] {
                for (i, word) in words.iter().enumerate() {
                    memory
                        .write_array(base + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
            }
            memory
                .write_array(0x3118, 100_000u64.to_le_bytes())
                .unwrap();
            memory.write_array(0x3200, timer.to_le_bytes()).unwrap();
            memory.write_array(0x3204, 1u32.to_le_bytes()).unwrap();
            memory
                .protect(0x1000, 2 * PAGE_SIZE, Permissions::RX)
                .unwrap();
            let mut first = memory.parallel_view(&mut Default::default()).unwrap();
            let mut second = first.clone();
            // SAFETY: this test owns the root and both Views. Owner byte access
            // resumes only after every job is drained and its View released.
            assert!(unsafe { View::try_private_epoch(&mut [&mut first, &mut second]) });
            // B . may fast-forward an idle loop. Keep enough instruction
            // credit that the budget cannot masquerade as a timer wakeup.
            let control = Arc::new(Control::new(1_000_000_000));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            let first_args = match mode {
                0 => [timer as u64, 0x3300, 8, 0, 0, 0],
                1 => [ep as u64, 0x3300, 1, u64::MAX, 0, 0],
                _ => [0x3200, 1, 0, 0, 0, 0],
            };
            for (pid, pc, number, args, view) in [
                (
                    1,
                    0x1000,
                    if mode == 0 {
                        63
                    } else if mode == 1 {
                        22
                    } else {
                        73
                    },
                    first_args,
                    first,
                ),
                (2, 0x2000, 86, [timer as u64, 0, 0x3100, 0, 0, 0], second),
            ] {
                let mut cpu = Cpu::new(pc, 0);
                cpu.set_x(8, number);
                for (i, value) in args.into_iter().enumerate() {
                    cpu.set_x(i, value);
                }
                let mut snapshot = syscall_snapshot();
                snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors());
                epoch.add(crate::run_queue::Job::new(
                    Work {
                        audio: None,
                        gpu: None,
                        pid,
                        cpu,
                        memory: Some(Box::new(view)),
                        control: control.clone(),
                        syscalls: Some(snapshot),
                    },
                    1,
                    0,
                    None,
                ));
            }
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.launch(0, epoch.clone()).unwrap();
            assert!(matches!(
                pool.event_timeout(Duration::from_secs(5)).unwrap(),
                Some(Event::EpochStopped(0))
            ));
            let mut done = epoch.drain();
            done.sort_by_key(|d| d.pid);
            memory.commit_parallel().unwrap();
            assert_eq!(done[0].cpu.x(0), if mode == 0 { 8 } else { 1 },
                "mode={mode} first pc={:x} outcome={:?} peer pc={:x} outcome={:?} x0={} x8={} x19={} instructions={} remaining={} input={} timer={:?} io_waits={} resumes={}",
                done[0].cpu.pc,done[0].outcome,done[1].cpu.pc,done[1].outcome,done[1].cpu.x(0),done[1].cpu.x(8),done[1].cpu.x(19),
                done.iter().map(|d|d.instructions).sum::<u64>(),control.remaining.load(Ordering::Relaxed),memory.read_u64(0x3118).unwrap(),vfs.timerfd_get(timer),done[0].io_waits,done[0].resumes);
            assert_eq!(done[1].cpu.x(19), 0);
            assert!(done[0].io_waits >= 1 && done[0].resumes >= 1);
            assert!(done.iter().all(|d| d.serviced_syscalls == 0));
            assert_eq!(
                done.iter().map(|d| d.timer_syscalls).sum::<u64>(),
                if mode == 0 { 2 } else { 1 }
            );
            assert_eq!(
                done.iter().map(|d| d.poll_syscalls).sum::<u64>(),
                // Both epoll_wait and ppoll now use the common retained poll
                // completion path; neither is counted as a byte read.
                u64::from(mode != 0)
            );
            match mode {
                0 => assert_eq!(memory.read_u64(0x3300).unwrap(), 1),
                1 => assert_eq!(memory.read_u64(0x3308).unwrap(), 42),
                _ => assert_eq!(memory.read_array::<2>(0x3206).unwrap(), 1u16.to_le_bytes()),
            }
        }
    }

    #[test]
    fn cohort_services_release_one_slot_keep_views_and_complete_after_stop_once() {
        let control = Arc::new(Control::new(100));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        let mut view_addresses = Vec::new();
        for pid in 1..=2 {
            let mut task = work(
                pid,
                &[0xd4000001, 0xaa0003f3, 0xd4000001, 0x14000000],
                7,
                control.clone(),
            );
            task.cpu.set_x(8, 62);
            task.syscalls = Some(syscall_snapshot());
            let job = crate::run_queue::Job::new(task, 1, 0, None);
            view_addresses.push(job.work.memory.as_deref().unwrap() as *const View as usize);
            epoch.add(job);
        }
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        let next = |pool: &mut Pool| {
            let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("one worker must submit both services without awaiting the first reply");
            };
            request
        };
        let first = next(&mut pool);
        let second = next(&mut pool);
        assert_eq!((first.pid, second.pid, epoch.pending_services()), (1, 2, 2));
        for request in [&first, &second] {
            assert_eq!(
                request.memory() as *const View as usize,
                view_addresses[request.pid as usize - 1]
            );
        }
        second.respond(Some(0x22));
        let again = next(&mut pool);
        assert_eq!(
            (again.pid, again.args[0], epoch.pending_services()),
            (2, 0x22, 2)
        );
        assert_eq!(again.memory() as *const View as usize, view_addresses[1]);
        epoch.stop();
        first.respond(Some(0x11));
        again.respond(Some(0x33));
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let mut results = epoch.drain();
        results.sort_by_key(|r| r.pid);
        assert_eq!(
            (
                results[0].cpu.x(0),
                results[1].cpu.x(0),
                results[1].cpu.x(19)
            ),
            (0x11, 0x33, 0x22)
        );
        assert_eq!(results.iter().map(|r| r.serviced_syscalls).sum::<u64>(), 3);
        assert_eq!(results.iter().map(|r| r.service_waits).sum::<u64>(), 3);
        assert_eq!(results.iter().map(|r| r.instructions).sum::<u64>(), 4);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 96);
        assert!(results
            .iter()
            .all(|r| matches!(r.outcome, Some(SliceOutcome::Yield { .. }))));
    }
    #[test]
    fn dropped_cohort_request_wakes_idle_slot_and_returns_failure_instead_of_hanging() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(100));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        epoch.add(crate::run_queue::Job::new(query_work(control), 1, 0, None));
        pool.launch(0, epoch.clone()).unwrap();
        let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing request");
        };
        drop(request);
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        assert_eq!(epoch.pending_services(), 0);
        let done = epoch.drain().pop().unwrap();
        assert!(done.outcome.is_none());
        assert_eq!(
            (
                done.instructions,
                done.service_waits,
                done.serviced_syscalls
            ),
            (1, 1, 0)
        );
    }
    #[test]
    fn cohort_service_checkpoint_returns_original_svc_without_counting_a_completion() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(100));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        let task = query_work(control.clone());
        let args: [u64; 6] = std::array::from_fn(|i| task.cpu.x(i));
        epoch.add(crate::run_queue::Job::new(task, 1, 0, None));
        pool.launch(0, epoch.clone()).unwrap();
        let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing request");
        };
        request.respond(None);
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert!(matches!(
            done.outcome,
            Some(SliceOutcome::Syscall { instructions: 0 })
        ));
        assert_eq!(std::array::from_fn::<_, 6, _>(|i| done.cpu.x(i)), args);
        assert_eq!((done.instructions, done.serviced_syscalls), (1, 0));
        assert_eq!(control.remaining.load(Ordering::Relaxed), 99);
    }

    #[test]
    fn cohort_native_peer_finishes_on_the_same_slot_while_service_is_unanswered() {
        let control = Arc::new(Control::new(1000));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        epoch.add(crate::run_queue::Job::new(
            query_work(control.clone()),
            1,
            0,
            None,
        ));
        let (mut peer, mut bytes) =
            native_work(3, [0x2000, 0x72, 128], Permissions::RW, control.clone());
        peer.pid = 2;
        epoch.add(crate::run_queue::Job::new(peer, 1, 0, None));
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing request");
        };
        // No answer: this same host worker must execute the native peer and
        // reach its cold boundary instead of blocking on a reply channel.
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(5)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        assert_eq!(epoch.pending_services(), 1);
        request.respond(Some(0x55));
        let mut results = epoch.drain();
        results.sort_by_key(|r| r.pid);
        assert_eq!(results[0].cpu.x(0), 0x55);
        assert_eq!(results[0].serviced_syscalls, 1);
        assert_eq!(results[1].native.worker_calls, 1);
        assert_eq!(results.iter().map(|r| r.instructions).sum::<u64>(), 7);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 993);
        bytes.commit_parallel().unwrap();
        assert_eq!(bytes.read_array::<128>(0x2000).unwrap(), [0x72; 128]);
    }
    #[test]
    fn pool_drop_returns_cohort_requests_without_waiting_for_a_reply_thread() {
        let (finished, completion) = mpsc::channel();
        thread::spawn(move || {
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            let control = Arc::new(Control::new(100));
            let epoch = crate::run_queue::Epoch::new(control.clone());
            epoch.add(crate::run_queue::Job::new(query_work(control), 1, 0, None));
            pool.launch(0, epoch.clone()).unwrap();
            let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("missing request");
            };
            assert!(pool.send.send(Event::Service(request)).is_ok());
            drop(pool);
            assert_eq!(epoch.pending_services(), 0);
            assert_eq!(epoch.drain().len(), 1);
            finished.send(()).unwrap();
        });
        completion
            .recv_timeout(Duration::from_secs(5))
            .expect("cohort shutdown must return requests");
    }

    fn query_work(control: Arc<Control>) -> Work {
        let mut job = work(1, &[0xd4000001, 0x14000000], 0, control);
        job.cpu.set_x(8, 62);
        job.cpu.set_x(1, 0);
        job.syscalls = Some(syscall_snapshot());
        job
    }
    fn direct_read_work(vfs: &trames_vfs::Vfs, fd: u32) -> (Work, Memory) {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .write_array(0x1000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        memory
            .write_array(0x1004, 0x14000000u32.to_le_bytes())
            .unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut snapshot = syscall_snapshot();
        snapshot.streams = vfs.stream_descriptors();
        snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors());
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(8, 63);
        cpu.set_x(0, fd as u64);
        cpu.set_x(1, 0x2000);
        cpu.set_x(2, 8);
        (
            Work {
                audio: None,
                gpu: None,
                pid: 1,
                cpu,
                memory: Some(Box::new(
                    memory.parallel_view(&mut Default::default()).unwrap(),
                )),
                control: Arc::new(Control::new(100)),
                syscalls: Some(snapshot),
            },
            memory,
        )
    }
    #[test]
    fn native_notification_source_can_appear_after_park_and_fd_close_without_owner_service() {
        let mut vfs = trames_vfs::Vfs::default();
        let events = vfs.native_events();
        let fd = vfs.eventfd(0, 0).unwrap();
        let (work, mut memory) = direct_read_work(&vfs, fd);
        let control = work.control.clone();
        let mut pool = Pool::new(1);
        let epoch = crate::run_queue::Epoch::with_events(control.clone(), pool.events(), true);
        epoch.add(crate::run_queue::Job::new(work, 1, 0, None));
        epoch.assign(&[(1, 0)]);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        epoch.await_io_park(1);
        let event = std::thread::spawn(move || events.event(fd).unwrap())
            .join()
            .unwrap();
        vfs.close(fd).unwrap();
        assert_eq!(vfs.eventfd(93, 0).unwrap(), fd);
        event.notify();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match pool
                .event_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
            {
                Some(Event::Idle) => {}
                Some(Event::EpochStopped(0)) => break,
                _ => panic!("native notification did not complete the parked read"),
            }
        }
        let done = epoch.drain().pop().unwrap();
        memory.commit_parallel().unwrap();
        assert_eq!(
            done.syscalls,
            1,
            "outcome={:?} io={} x0={} data={:?} waits={}",
            done.outcome,
            done.io.is_some(),
            done.cpu.x(0),
            memory.read_u64(0x2000),
            done.waits
        );
        assert_eq!(epoch.pending_services(), 0);
        assert_eq!(memory.read_u64(0x2000).unwrap(), 1);
        assert_eq!(vfs.read(fd, 8).unwrap(), 93u64.to_le_bytes());
    }
    #[test]
    fn native_audio_open_and_video_surface_creation_use_live_notification_fds_on_workers() {
        let vfs = trames_vfs::Vfs::default();
        let events = vfs.native_events();
        let factory = vfs.descriptor_factory();
        let fd = std::thread::spawn(move || factory.eventfd(0, 0).unwrap())
            .join()
            .unwrap();
        for audio in [false, true] {
            let profile = if audio {
                trames_audio::PROFILE
            } else {
                trames_video::PROFILE
            };
            let operation = if audio {
                trames_audio::OPEN
            } else {
                trames_video::CREATE_SURFACE
            };
            for candidate in [fd, u32::MAX] {
                let control = Arc::new(Control::new(100));
                let (mut work, mut memory) = native_work(
                    1,
                    [operation, 0x2000, 128],
                    Permissions::RW,
                    control.clone(),
                );
                drop(work.memory.take());
                memory.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
                memory
                    .write_array(
                        0x1000,
                        (0xd2800010u32 | ((profile as u32 & 0xffff) << 5)).to_le_bytes(),
                    )
                    .unwrap();
                memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
                let mut record = [0u8; 128];
                record[..8].copy_from_slice(&(candidate as u64).to_le_bytes());
                if !audio {
                    record[8..16].copy_from_slice(&64u64.to_le_bytes());
                    record[16..24].copy_from_slice(&64u64.to_le_bytes());
                }
                memory.write(0x2000, &record).unwrap();
                work.memory = Some(Box::new(
                    memory.parallel_view(&mut Default::default()).unwrap(),
                ));
                let video = trames_video::Context::default();
                if audio {
                    <Cpu as trames_engine::Cpu>::set_audio_calls(&mut work.cpu, true);
                    work.audio = Some(crate::devices::Audio {
                        context: trames_audio::Context::new(0),
                        events: events.clone(),
                    });
                } else {
                    <Cpu as trames_engine::Cpu>::set_video_calls(&mut work.cpu, true);
                    let mut authority: crate::gpu::Authority =
                        trames_vulkan::Context::new(trames_vulkan::Backend::new()).into();
                    authority.video = video.clone();
                    authority.events = Some(events.clone());
                    work.gpu = Some(authority);
                }
                let epoch = crate::run_queue::Epoch::new(control);
                epoch.add(crate::run_queue::Job::new(work, 1, 0, None));
                epoch.assign(&[(1, 0)]);
                let mut pool = Pool::new(1);
                pool.ensure(0).unwrap();
                pool.launch(0, epoch.clone()).unwrap();
                assert!(matches!(
                    pool.event_timeout(Duration::from_secs(2)).unwrap(),
                    Some(Event::EpochStopped(0))
                ));
                let done = epoch.drain().pop().unwrap();
                let expected = if candidate == u32::MAX {
                    -22i64
                } else if audio {
                    -13
                } else {
                    1
                };
                assert_eq!(done.cpu.x(0), expected as u64);
                assert_eq!(done.instructions, 6);
                assert_eq!(done.native.checkpoint_retries, 0);
                assert_eq!(epoch.pending_services(), 0);
                memory.commit_parallel().unwrap();
                if !audio && candidate == fd {
                    assert!(vfs.has_native_event_sources());
                    memory.write_array(0x2000, 1u64.to_le_bytes()).unwrap();
                    assert_eq!(video.invoke(&mut memory, 4, 0x2000, 128, None).unwrap(), 0);
                    assert!(!vfs.has_native_event_sources());
                }
            }
        }
    }
    #[test]
    fn actual_futex_wake_commits_locally_and_requests_only_a_scheduling_boundary() {
        let table = crate::futex::Futexes::default();
        let wait = table
            .wait((0, 7, 0x2000), 2, 1, || Ok::<_, ()>(()))
            .unwrap();
        let mut vfs = trames_vfs::Vfs::default();
        let [fd, _] = vfs.pipe(0).unwrap();
        let (mut job, mut memory) = direct_read_work(&vfs, fd);
        job.cpu.set_x(8, 98);
        job.cpu.set_x(0, 0x2000);
        job.cpu.set_x(1, 129);
        job.cpu.set_x(2, 1);
        job.syscalls.as_mut().unwrap().futex = crate::futex::Authority::new(table.clone(), 7);
        let mut pool = Pool::with_profiling(1, false);
        pool.ensure(0).unwrap();
        pool.dispatch(0, job).unwrap();
        let Some(Event::Done(done)) = pool.event_timeout(Duration::from_secs(5)).unwrap() else {
            panic!("futex wake requested coordinator RPC");
        };
        assert_eq!(done.syscalls, 1);
        assert_eq!(done.futex_wakes, 1);
        assert_eq!(done.futex_woken, 1);
        assert_eq!(done.serviced_syscalls, 0);
        assert_eq!(done.cpu.x(0), 1);
        assert_eq!(done.cpu.pc, 0x1004);
        assert_eq!(done.instructions, 1);
        assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
        assert!(wait.woken());
        let mut ready = Vec::new();
        table.take_ready(&mut ready);
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0], &wait.ticket));
        assert_eq!(table.wake((0, 7, 0x2000), 1, 1), 0);
        memory.commit_parallel().unwrap();
    }
    #[test]
    fn shared_pipe_read_finishes_without_any_coordinator_request() {
        let mut vfs = trames_vfs::Vfs::default();
        let [read, write] = vfs.pipe(0).unwrap();
        vfs.write(write, b"abcdefgh").unwrap();
        let (job, mut memory) = direct_read_work(&vfs, read);
        let mut pool = Pool::with_profiling(1, false);
        pool.ensure(0).unwrap();
        pool.dispatch(0, job).unwrap();
        let Some(Event::Done(done)) = pool.event_timeout(Duration::from_secs(5)).unwrap() else {
            panic!("local I/O requested coordinator service");
        };
        assert_eq!(done.direct_syscalls, 1);
        assert_eq!(done.syscalls, 1);
        assert_eq!(done.serviced_syscalls, 0);
        assert_eq!(done.cpu.x(0), 8);
        assert_eq!(done.instructions, 100);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<8>(0x2000).unwrap(), *b"abcdefgh");
    }
    #[test]
    fn blocking_local_io_returns_to_scheduler_without_a_failed_rpc() {
        let mut vfs = trames_vfs::Vfs::default();
        let [read, _write] = vfs.pipe(0).unwrap();
        let (job, mut memory) = direct_read_work(&vfs, read);
        let mut pool = Pool::with_profiling(1, false);
        pool.ensure(0).unwrap();
        pool.dispatch(0, job).unwrap();
        let Some(Event::Done(done)) = pool.event_timeout(Duration::from_secs(5)).unwrap() else {
            panic!("blocking I/O made an unnecessary service roundtrip");
        };
        assert_eq!(done.direct_syscalls, 0);
        assert_eq!(done.serviced_syscalls, 0);
        assert_eq!(done.instructions, 1);
        assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<8>(0x2000).unwrap(), [0; 8]);
    }
    #[test]
    fn reusable_reply_channel_handles_many_requests_and_views_without_replay() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let mut job = work(
            1,
            &[0xd4000001, 0x17ffffff],
            0,
            Arc::new(Control::new(1000)),
        );
        job.cpu.set_x(8, 62);
        job.syscalls = Some(syscall_snapshot());
        pool.dispatch(0, job).unwrap();
        for i in 0..128u64 {
            let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("missing request")
            };
            if i != 0 {
                assert_eq!(request.args[0], i - 1);
            }
            assert_eq!(
                request.memory().read_array::<4>(0x1000).unwrap(),
                0xd4000001u32.to_le_bytes()
            );
            request.respond(Some(i));
        }
        let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing final request")
        };
        assert_eq!(request.args[0], 127);
        request.respond(None);
        let done = pool.complete().unwrap();
        assert_eq!(done.serviced_syscalls, 128);
        assert_eq!(done.instructions, 257);
        assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
    }
    #[test]
    fn dropping_an_unanswered_request_disconnects_a_reusable_reply_receiver() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.dispatch(0, query_work(Arc::new(Control::new(100))))
            .unwrap();
        let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing request")
        };
        drop(request);
        let done = pool
            .complete_timeout(Duration::from_secs(5))
            .unwrap()
            .expect("worker did not unblock");
        assert!(done.outcome.is_none());
    }

    #[test]
    fn native_peer_finishes_while_a_syscall_caller_is_parked_without_a_global_stop() {
        let mut pool = Pool::new(2);
        pool.ensure(0).unwrap();
        pool.ensure(1).unwrap();
        let control = Arc::new(Control::new(100_000));
        pool.dispatch(0, query_work(control.clone())).unwrap();
        let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing query request");
        };
        assert!(!control.stop.load(Ordering::Acquire));
        let (mut peer, mut bytes) =
            native_work(3, [0x2000, 0x72, 128], Permissions::RW, control.clone());
        peer.pid = 2;
        pool.dispatch(1, peer).unwrap();
        let Some(Event::Done(peer)) = pool.event_timeout(Duration::from_secs(5)).unwrap() else {
            panic!("native peer could not progress while caller waited");
        };
        assert_eq!(peer.pid, 2);
        assert_eq!(peer.native.worker_calls, 1);
        assert!(matches!(peer.outcome, Some(SliceOutcome::Syscall { .. })));
        // Peer checkpoint arrived while this request was in flight. A completed
        // result must still be committed, never replayed on the coordinator.
        request.respond(Some(0x55));
        let caller = pool.complete().unwrap();
        assert_eq!(caller.cpu.x(0), 0x55);
        assert_eq!(caller.instructions, 1);
        assert_eq!(caller.serviced_syscalls, 1);
        assert!(matches!(caller.outcome, Some(SliceOutcome::Yield { .. })));
        bytes.commit_parallel().unwrap();
        assert_eq!(bytes.read_array::<128>(0x2000).unwrap(), [0x72; 128]);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 100_000 - 7);
    }
    #[test]
    fn production_native_calls_do_not_update_global_overlap_instrumentation() {
        let mut pool = Pool::with_profiling(1, false);
        pool.ensure(0).unwrap();
        let (job, mut bytes) = native_work(
            3,
            [0x2000, 0x72, 128],
            Permissions::RW,
            Arc::new(Control::new(100)),
        );
        pool.dispatch(0, job).unwrap();
        let done = pool.complete().unwrap();
        assert_eq!(done.native.worker_calls, 1);
        assert_eq!(pool.peak_native.load(Ordering::Relaxed), 0);
        assert_eq!(pool.active_native.load(Ordering::Relaxed), 0);
        bytes.commit_parallel().unwrap();
        assert_eq!(bytes.read_array::<128>(0x2000).unwrap(), [0x72; 128]);
    }

    #[test]
    fn pool_drop_drains_a_queued_request_and_returns_its_view_before_join() {
        let (finished, completion) = mpsc::channel();
        thread::spawn(move || {
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            let active = pool.active.clone();
            pool.dispatch(0, query_work(Arc::new(Control::new(100))))
                .unwrap();
            let Some(Event::Service(request)) = pool.event_timeout(Duration::from_secs(5)).unwrap()
            else {
                panic!("missing query request");
            };
            assert!(pool.send.send(Event::Service(request)).is_ok());
            drop(pool);
            assert_eq!(active.load(Ordering::Relaxed), 0);
            finished.send(()).unwrap();
        });
        completion
            .recv_timeout(Duration::from_secs(5))
            .expect("pool shutdown must drain requests");
    }

    #[test]
    fn local_syscalls_continue_with_exact_budget_and_fall_back_before_mutations() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        for budget in 1..=5 {
            let control = Arc::new(Control::new(budget));
            // mov x8,#178; svc #0; mov x1,x0; mov x8,#64; svc #0.
            let mut work = work(
                22,
                &[0xd2801648, 0xd4000001, 0xaa0003e1, 0xd2800808, 0xd4000001],
                0,
                control.clone(),
            );
            work.syscalls = Some(syscall_snapshot());
            work.cpu.set_x(19, 0x1234);
            work.cpu.tpidr_el0 = 0x5678;
            pool.dispatch(0, work).unwrap();
            let done = pool
                .complete_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            assert_eq!(done.instructions, budget);
            assert_eq!(control.remaining.load(Ordering::Relaxed), 0);
            assert_eq!(done.syscalls, u64::from(budget >= 2));
            assert_eq!(done.cpu.x(19), 0x1234);
            assert_eq!(done.cpu.tpidr_el0, 0x5678);
            if budget >= 2 {
                assert_eq!(done.cpu.x(0), 22);
            }
            if budget >= 3 {
                assert_eq!(done.cpu.x(1), 22);
            }
            if budget == 5 {
                assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
                assert_eq!(done.cpu.x(8), 64);
                assert_eq!(done.cpu.pc, 0x1014);
            }
        }
        // Filtered/trace assignments receive no snapshot and must checkpoint at
        // the original SVC, before the query returns or any following stores.
        let work = work(
            22,
            &[0xd2801648, 0xd4000001, 0xaa0003e1],
            0,
            Arc::new(Control::new(10)),
        );
        pool.dispatch(0, work).unwrap();
        let done = pool.complete().unwrap();
        assert_eq!(
            (done.instructions, done.syscalls, done.cpu.pc),
            (2, 0, 0x1008)
        );
        assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
    }

    #[test]
    fn private_futex_wakes_without_waiters_run_to_the_instruction_budget() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let budget = 99;
        let mut job = work(
            22,
            &[0xd4000001, 0xd2820000, 0x17fffffe],
            0,
            Arc::new(Control::new(budget)),
        );
        job.cpu.set_x(0, 0x1000);
        job.cpu.set_x(1, 129);
        job.cpu.set_x(2, 1);
        job.cpu.set_x(8, 98);
        job.syscalls = Some(syscall_snapshot());
        pool.dispatch(0, job).unwrap();
        let done = pool
            .complete_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!((done.instructions, done.syscalls), (budget, 33));
        assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
    }
    #[test]
    fn repeated_queries_run_without_a_coordinator_rendezvous() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let budget = 65_539;
        let control = Arc::new(Control::new(budget));
        let mut work = work(22, &[0xd4000001, 0x17ffffff], 0, control.clone());
        work.cpu.set_x(8, 172);
        work.syscalls = Some(syscall_snapshot());
        pool.dispatch(0, work).unwrap();
        let done = pool
            .complete_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert_eq!(done.instructions, budget);
        assert_eq!(done.syscalls, budget.div_ceil(2));
        assert_eq!(done.cpu.x(0), 21);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 0);
        assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
    }

    fn native_work(
        function: u64,
        args: [u64; 3],
        permissions: Permissions,
        control: Arc<Control>,
    ) -> (Work, Memory) {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE * 2, permissions).unwrap();
        let code = [
            0xd2800030u32,
            0xf2a00030,
            0xd2800011 | (function as u32) << 5,
            trames_accel::native::INSTRUCTION,
            0xd65f03c0,
            0xd4000001,
        ];
        for (i, word) in code.iter().enumerate() {
            memory
                .write(0x1000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut cpu = Cpu::new(0x1000, 0x3000);
        cpu.set_native_calls(true);
        for (i, a) in args.iter().enumerate() {
            cpu.set_x(i, *a);
        }
        cpu.set_x(30, 0x1014);
        cpu.set_x(19, 0x1234);
        cpu.tpidr_el0 = 0x5678;
        cpu.fpcr = 0x400000;
        cpu.fpsr = 17;
        let memory_view = memory.parallel_view(&mut Default::default()).unwrap();
        (
            Work {
                audio: None,
                gpu: None,
                pid: 1,
                cpu,
                memory: Some(Box::new(memory_view)),
                control,
                syscalls: None,
            },
            memory,
        )
    }

    #[test]
    fn gpu_calls_retire_once_on_the_calling_worker_and_owner_fallback_has_no_effects() {
        for (operation, context, function) in
            [(79, true, 1), (79, false, 1), (27, true, 1), (79, true, 2)]
        {
            let control = Arc::new(Control::new(4));
            let (work, mut memory) = native_work(
                1,
                [operation, 0x2000, 128],
                Permissions::RW,
                control.clone(),
            );
            let Work {
                mut cpu,
                memory: old,
                ..
            } = work;
            drop(old);
            memory.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            memory
                .write_array(0x1000, 0xd28000d0u32.to_le_bytes())
                .unwrap(); // movz x16, #6
            memory
                .write_array(0x1008, (0xd2800011u32 | function << 5).to_le_bytes())
                .unwrap();
            memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
            memory.write_array(0x2000, 0x3000u64.to_le_bytes()).unwrap();
            memory.write(0x3000, &[0xa5; 32]).unwrap();
            cpu.set_vulkan_calls(true);
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.dispatch(
                0,
                Work {
                    audio: None,
                    gpu: context
                        .then(|| trames_vulkan::Context::new(trames_vulkan::Backend::new()).into()),
                    pid: 1,
                    cpu,
                    memory: Some(Box::new(
                        memory.parallel_view(&mut Default::default()).unwrap(),
                    )),
                    control: control.clone(),
                    syscalls: None,
                },
            )
            .unwrap();
            let done = pool
                .complete_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            // Invalid transport faults before reserving/retiring the HLT.
            assert_eq!(
                control.remaining.load(Ordering::Relaxed),
                u64::from(function == 2)
            );
            memory.commit_parallel().unwrap();
            if operation == 79 && context && function == 1 {
                assert_eq!(done.instructions, 4);
                assert_eq!(done.cpu.pc, 0x1010);
                assert_eq!((done.cpu.x(0), done.cpu.x(1)), (0, 0));
                assert_eq!(done.gpu.calls, 1);
                assert_eq!((done.native.calls, done.native.checkpoint_retries), (1, 0));
                assert_eq!(memory.read_array::<24>(0x3000).unwrap(), [0; 24]);
                assert_eq!(memory.read_array::<8>(0x3018).unwrap(), [0xa5; 8]);
            } else {
                assert_eq!(done.instructions, 3);
                assert_eq!(done.cpu.pc, 0x100c);
                assert_eq!(done.gpu.calls, 0);
                assert_eq!(memory.read_array::<32>(0x3000).unwrap(), [0xa5; 32]);
                if function == 2 {
                    assert!(matches!(done.outcome, Some(SliceOutcome::Fault(_))));
                } else {
                    assert!(matches!(
                        done.outcome,
                        Some(SliceOutcome::NativeCall { .. })
                    ));
                }
            }
        }
    }

    fn gpu_query_work(context: trames_vulkan::Context, control: Arc<Control>) -> (Work, Memory) {
        let (work, mut memory) =
            native_work(1, [79, 0x2000, 128], Permissions::RW, control.clone());
        let Work {
            mut cpu,
            memory: old,
            ..
        } = work;
        drop(old);
        memory.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
            .write_array(0x1000, 0xd28000d0u32.to_le_bytes())
            .unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        memory.write_array(0x2000, 0x3000u64.to_le_bytes()).unwrap();
        memory.write(0x3000, &[0xa5; 32]).unwrap();
        cpu.set_vulkan_calls(true);
        (
            Work {
                audio: None,
                gpu: Some(context.into()),
                pid: 1,
                cpu,
                memory: Some(Box::new(
                    memory.parallel_view(&mut Default::default()).unwrap(),
                )),
                control,
                syscalls: None,
            },
            memory,
        )
    }
    #[test]
    fn gpu_context_wait_releases_one_slot_and_unlock_wakes_an_otherwise_idle_cohort() {
        let context = trames_vulkan::Context::new(trames_vulkan::Backend::new());
        let lease = context.try_lock().unwrap();
        let control = Arc::new(Control::new(100));
        let (work, mut memory) = gpu_query_work(context.clone(), control.clone());
        let epoch = crate::run_queue::Epoch::new(control.clone());
        epoch.add(crate::run_queue::Job::new(work, 1, 0, None));
        epoch.assign(&[(1, 0)]);
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        epoch.await_gpu_park(1);
        assert!(!control.stopped());
        assert_eq!(control.remaining.load(Ordering::Relaxed), 97);
        drop(lease);
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(2)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(done.instructions, 6);
        assert_eq!(done.gpu.calls, 1);
        assert_eq!(done.gpu.waits, 1);
        assert_eq!(done.native.calls, 1);
        assert_eq!(done.native.checkpoint_retries, 0);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 94);
        assert!(done.gpu_pending.is_none());
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<24>(0x3000).unwrap(), [0; 24]);
    }
    #[test]
    fn live_wayland_gpu_auth_finishes_real_and_invalid_grants_without_owner_handoff() {
        let mut vfs = trames_vfs::Vfs::default();
        let _server = vfs.enable_wayland(b"/run/user/0").unwrap();
        let fd = vfs.local_create(1 | trames_vfs::O_NONBLOCK, 0).unwrap();
        let socket = vfs.local_socket(fd).unwrap().unwrap();
        let mut address = vec![1, 0];
        address.extend_from_slice(b"/run/user/0/wayland-0\0");
        vfs.local_connect(&socket, &address).unwrap();
        vfs.wayland_connection(fd).unwrap();
        let foreign = vfs.socketpair(1, 1, 0).unwrap()[0];
        let copied = vfs.memfd_create(b"copied-wsi-capability", 0).unwrap();
        vfs.write(copied, b"copied bytes").unwrap();
        let auth = vfs.wayland_auth();
        for candidate in [fd, foreign, copied] {
            let context = trames_vulkan::Context::new(trames_vulkan::Backend::new());
            let control = Arc::new(Control::new(100));
            let (mut work, mut memory) = gpu_query_work(context, control.clone());
            work.gpu.as_mut().unwrap().auth = auth.clone();
            work.cpu.set_x(0, 110);
            trames_memory::CpuMemory::write_array(
                work.memory.as_deref_mut().unwrap(),
                0x2008,
                (candidate as u64).to_le_bytes(),
            )
            .unwrap();
            let epoch = crate::run_queue::Epoch::new(control.clone());
            epoch.add(crate::run_queue::Job::new(work, 1, 0, None));
            epoch.assign(&[(1, 0)]);
            let mut pool = Pool::new(1);
            pool.ensure(0).unwrap();
            pool.launch(0, epoch.clone()).unwrap();
            assert!(matches!(
                pool.event_timeout(Duration::from_secs(2)).unwrap(),
                Some(Event::EpochStopped(0))
            ));
            let done = epoch.drain().pop().unwrap();
            if candidate == fd {
                assert_eq!(done.cpu.x(0), (-8i64) as u64);
            } else {
                assert_eq!(done.cpu.x(0), (-1_000_000_000i64) as u64);
            }
            assert_eq!((done.gpu.calls, done.instructions), (1, 6));
            assert_eq!(done.native.checkpoint_retries, 0);
            memory.commit_parallel().unwrap();
            assert_eq!(memory.read_array::<32>(0x3000).unwrap(), [0xa5; 32]);
        }
    }
    #[test]
    fn a_native_peer_runs_while_gpu_lock_is_held_and_stop_cancels_only_the_unstarted_call() {
        let context = trames_vulkan::Context::new(trames_vulkan::Backend::new());
        let lease = context.try_lock().unwrap();
        let control = Arc::new(Control::new(100));
        let (work, mut memory) = gpu_query_work(context.clone(), control.clone());
        let (mut peer, mut peer_memory) =
            native_work(3, [0x2000, 42, 128], Permissions::RW, control.clone());
        peer.pid = 2;
        let epoch = crate::run_queue::Epoch::new(control.clone());
        epoch.add(crate::run_queue::Job::new(work, 1, 0, None));
        epoch.add(crate::run_queue::Job::new(peer, 1, 0, None));
        epoch.assign(&[(1, 0)]);
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(2)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain();
        let gpu = done.iter().find(|d| d.pid == 1).unwrap();
        let peer = done.iter().find(|d| d.pid == 2).unwrap();
        assert_eq!((gpu.instructions, gpu.gpu.calls, gpu.gpu.waits), (3, 0, 1));
        assert_eq!(gpu.cpu.pc, 0x100c);
        assert!(gpu.gpu_pending.is_none());
        assert_eq!(peer.native.function_calls[2], 1);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 91);
        memory.commit_parallel().unwrap();
        peer_memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<32>(0x3000).unwrap(), [0xa5; 32]);
        assert_eq!(peer_memory.read_array::<128>(0x2000).unwrap(), [42; 128]);
        drop(lease);
        assert!(epoch.take(0).is_none());
    }
    #[test]
    fn adopted_gpu_completion_never_replays_or_retires_its_accepted_hlt_twice() {
        let context = trames_vulkan::Context::new(trames_vulkan::Backend::new());
        let control = Arc::new(Control::new(100));
        let (mut work, _memory) = gpu_query_work(context, control.clone());
        work.cpu.pc = 0x100c;
        let mut job = crate::run_queue::Job::new(work, 1, 0, None);
        job.gpu_pending = Some(crate::gpu::Pending::adopted(crate::gpu::Compile {
            call: crate::gpu::Call {
                pc: 0x100c,
                operation: 27,
                args: [27, 0x2000, 128],
            },
            job: 1,
            began: Instant::now(),
            peer_instructions: 37,
        }));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        epoch.add(job);
        epoch.assign(&[(1, 0)]);
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.launch(0, epoch.clone()).unwrap();
        assert!(matches!(
            pool.event_timeout(Duration::from_secs(2)).unwrap(),
            Some(Event::EpochStopped(0))
        ));
        let done = epoch.drain().pop().unwrap();
        assert_eq!(done.cpu.x(0), (-4i64) as u64);
        assert_eq!(done.instructions, 2); // RET + SVC; HLT retired in prior cohort.
        assert_eq!(done.native.calls, 0);
        assert_eq!((done.gpu.calls, done.gpu.compiles), (0, 0));
        assert_eq!(done.gpu.errors, 1);
        assert_eq!(done.gpu.peer_instructions, 37);
        assert!(done.gpu_pending.is_none());
        assert_eq!(control.remaining.load(Ordering::Relaxed), 98);
    }

    #[test]
    fn deferred_native_reserves_hlt_before_effects_and_unstable_code_never_enters_body() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(4));
        let (work, mut memory) = native_work(3, [0x2000, 7, 128], Permissions::RW, control.clone());
        let Work {
            cpu,
            memory: old_view,
            ..
        } = work;
        drop(old_view);
        let live = Rc::new(LivePage {
            bytes: RefCell::new([0; PAGE_SIZE as usize]),
            version: Cell::new(0),
            unstable: Cell::new(false),
        });
        memory
            .map_backed(0x2000, vec![live.clone()], false, Permissions::RW, true)
            .unwrap();
        let work = Work {
            audio: None,
            gpu: None,
            pid: 1,
            cpu,
            memory: Some(Box::new(
                memory.parallel_view(&mut Default::default()).unwrap(),
            )),
            control: control.clone(),
            syscalls: None,
        };
        pool.dispatch(0, work).unwrap();
        let done = pool.complete().unwrap();
        assert!(matches!(
            done.outcome,
            Some(SliceOutcome::NativeCall { pc: 0x100c, .. })
        ));
        assert_eq!(done.instructions, 3);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 0);
        assert_eq!(done.cpu.pc, 0x100c);
        assert_eq!((done.cpu.x(0), done.cpu.x(1)), (0x2000, 7));
        assert_eq!(done.native.checkpoint_retries, 1);
        assert_eq!(done.native.faults, 0);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [0; 128]);
        let mut registry = trames_accel::native::Registry::default();
        let value = registry
            .invoke(
                &mut memory,
                0x100c,
                trames_accel::native::PROFILE,
                3,
                [0x2000, 7, 128],
            )
            .unwrap();
        assert!(!value.fallback);
        assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [7; 128]);
        assert_eq!(live.bytes.borrow()[..128], [0; 128]);

        let code = Rc::new(LivePage {
            bytes: RefCell::new(memory.read_array(0x1000).unwrap()),
            version: Cell::new(0),
            unstable: Cell::new(true),
        });
        memory
            .map_backed(0x1000, vec![code.clone()], false, Permissions::RX, true)
            .unwrap();
        let entered = Cell::new(false);
        for _ in 0..2 {
            assert!(matches!(
                registry.invoke_scoped(
                    &mut memory,
                    0x100c,
                    trames_accel::native::PROFILE,
                    3,
                    [0x2000, 9, 128],
                    || entered.set(true)
                ),
                Err(trames_accel::native::Error::Checkpoint)
            ));
        }
        assert!(!entered.get());
        assert_eq!(registry.metrics.faults, 0);
        assert_eq!(registry.metrics.checkpoint_retries, 2);
        assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [7; 128]);
        code.unstable.set(false);
        registry
            .invoke_scoped(
                &mut memory,
                0x100c,
                trames_accel::native::PROFILE,
                3,
                [0x2000, 9, 128],
                || entered.set(true),
            )
            .unwrap();
        assert!(entered.get());
        assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [9; 128]);
    }

    #[test]
    fn a_peer_completes_native_work_while_another_native_body_is_blocked_on_its_page() {
        for (peer_address, held_length) in [(0x3000, 4096), (0x2100, 128)] {
            let mut pool = Pool::new(2);
            pool.ensure(0).unwrap();
            pool.ensure(1).unwrap();
            let control = Arc::new(Control::new(POLL_INSTRUCTIONS * 4));
            let (first, mut memory) =
                native_work(3, [0x2000, 0x6b, 128], Permissions::RW, control.clone());
            let mut held_view = first.memory.clone().unwrap();
            let mut peer_cpu = first.cpu.clone();
            peer_cpu.set_x(0, peer_address);
            peer_cpu.set_x(1, 0x52);
            let peer = Work {
                audio: None,
                gpu: None,
                pid: 2,
                cpu: peer_cpu,
                memory: first.memory.clone(),
                control: control.clone(),
                syscalls: None,
            };
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let held = thread::spawn(move || {
                held_view
                    .fill_with(0x2000, held_length, |bytes| {
                        held_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        bytes.fill(0);
                    })
                    .unwrap()
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            pool.dispatch(0, first).unwrap();
            let began = Instant::now();
            while pool.active_native.load(Ordering::Relaxed) == 0
                && began.elapsed() < Duration::from_secs(5)
            {
                thread::yield_now();
            }
            assert_eq!(pool.active_native.load(Ordering::Relaxed), 1);
            pool.dispatch(1, peer).unwrap();
            let peer = pool
                .complete_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            assert_eq!(peer.pid, 2);
            assert_eq!(peer.instructions, 6);
            assert_eq!(peer.native.worker_calls, 1);
            assert!(matches!(peer.outcome, Some(SliceOutcome::Syscall { .. })));
            assert_eq!(pool.peak_native.load(Ordering::Relaxed), 2);
            release_tx.send(()).unwrap();
            held.join().unwrap();
            let first = pool
                .complete_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            assert_eq!(first.pid, 1);
            assert_eq!(first.native.worker_calls, 1);
            assert_eq!(pool.active_native.load(Ordering::Relaxed), 0);
            memory.commit_parallel().unwrap();
            assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [0x6b; 128]);
            assert_eq!(memory.read_array::<128>(peer_address).unwrap(), [0x52; 128]);
        }
    }

    #[test]
    fn native_returns_continue_locally_with_exact_retirement_and_guest_state() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        for budget in 3..=6 {
            let control = Arc::new(Control::new(budget));
            let (work, mut memory) =
                native_work(3, [0x2000, 0x6b, 128], Permissions::RW, control.clone());
            pool.dispatch(0, work).unwrap();
            let done = pool
                .complete_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            assert_eq!(done.instructions, budget);
            assert_eq!(control.remaining.load(Ordering::Relaxed), 0);
            assert_eq!(done.cpu.x(19), 0x1234);
            assert_eq!(done.cpu.sp, 0x3000);
            assert_eq!(done.cpu.tpidr_el0, 0x5678);
            assert_eq!(done.cpu.fpcr, 0x400000);
            assert_eq!(done.cpu.fpsr, 17);
            memory.commit_parallel().unwrap();
            if budget >= 4 {
                assert_eq!(done.native.worker_calls, 1);
                assert_eq!(done.native.calls, 1);
                assert_eq!(done.native.faults, 0);
                assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [0x6b; 128]);
            } else {
                assert_eq!(done.native.calls, 0);
                assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [0; 128]);
            }
            assert!(!matches!(
                done.outcome,
                Some(SliceOutcome::NativeCall { .. })
            ));
        }
        assert_eq!(pool.active_native.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn native_fallback_retires_once_but_fault_refunds_its_credit() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(4));
        let (work, mut memory) = native_work(
            3,
            [0x2000, 7, trames_accel::native::MAX_BULK_BYTES as u64 + 1],
            Permissions::RW,
            control.clone(),
        );
        pool.dispatch(0, work).unwrap();
        let done = pool.complete().unwrap();
        assert_eq!(done.instructions, 4);
        assert_eq!(done.cpu.pc, 0x1010);
        assert_eq!(done.cpu.x(0), 0x2000);
        assert_eq!(done.cpu.x(1), 1);
        assert_eq!(done.native.fallbacks, 1);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 0);
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [0; 128]);
        let control = Arc::new(Control::new(4));
        let (work, mut memory) = native_work(3, [0x2000, 7, 128], Permissions::R, control.clone());
        pool.dispatch(0, work).unwrap();
        let done = pool.complete().unwrap();
        assert_eq!(done.instructions, 3);
        assert_eq!(done.cpu.pc, 0x100c);
        assert_eq!(done.cpu.x(0), 0x2000);
        assert_eq!(done.cpu.x(1), 7);
        assert_eq!(done.native.faults, 1);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 1);
        assert!(matches!(
            done.outcome,
            Some(SliceOutcome::Fault(trames_cpu::CpuFault::Memory {
                pc: 0x100c,
                error: trames_memory::MemoryError::Permission {
                    address: 0x2000,
                    access: trames_memory::Access::Write
                }
            }))
        ));
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_array::<128>(0x2000).unwrap(), [0; 128]);
    }

    #[test]
    fn retains_cpu_through_many_polls_without_a_peer_or_coordinator_message() {
        let mut pool = Pool::new(2);
        pool.ensure(0).unwrap();
        let control = Arc::new(Control::new(1_000_000));
        // subs x0,x0,#1; b.ne -4; svc #0.
        pool.dispatch(
            0,
            work(1, &[0xf1000400, 0x54ffffe1, 0xd4000001], 100_000, control),
        )
        .unwrap();
        let done = pool
            .complete_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
        assert_eq!(done.instructions, 200_001);
        assert_eq!(done.cpu.x(0), 0);
        assert!(done.chunks > 10);
        assert_eq!(pool.active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn concurrent_workers_share_an_exact_non_divisible_budget() {
        let mut pool = Pool::new(2);
        for slot in 0..2 {
            pool.ensure(slot).unwrap();
        }
        for budget in [1, 17, POLL_INSTRUCTIONS + 3, 77_777] {
            let control = Arc::new(Control::new(budget));
            for slot in 0..2 {
                pool.dispatch(
                    slot,
                    work(slot as u32 + 1, &[0x14000000], 0, control.clone()),
                )
                .unwrap();
            }
            let a = pool.complete().unwrap();
            let b = pool.complete().unwrap();
            assert_eq!(a.instructions + b.instructions, budget);
            assert_eq!(control.remaining.load(Ordering::Relaxed), 0);
            assert_eq!(pool.active.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn rejected_native_does_not_retire_and_stops_queued_peers() {
        let mut pool = Pool::new(2);
        pool.ensure(0).unwrap();
        pool.ensure(1).unwrap();
        let control = Arc::new(Control::new(1));
        pool.dispatch(
            0,
            work(1, &[trames_accel::native::INSTRUCTION], 0, control.clone()),
        )
        .unwrap();
        let done = pool.complete().unwrap();
        assert!(matches!(
            done.outcome,
            Some(SliceOutcome::Fault(trames_cpu::CpuFault::Trap {
                signal: 4,
                ..
            }))
        ));
        assert_eq!(done.instructions, 0);
        assert_eq!(done.native.rejected, 1);
        assert_eq!(control.remaining.load(Ordering::Relaxed), 1);
        pool.dispatch(1, work(2, &[0x14000000], 0, control))
            .unwrap();
        let peer = pool.complete().unwrap();
        assert_eq!(peer.instructions, 0);
        assert_eq!(peer.chunks, 0);
        assert_eq!(pool.peak.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fault_reports_retirement_from_all_preceding_polls() {
        let mut pool = Pool::new(1);
        pool.ensure(0).unwrap();
        pool.dispatch(
            0,
            work(
                1,
                &[0xf1000400, 0x54ffffe1, 0],
                100_000,
                Arc::new(Control::new(1_000_000)),
            ),
        )
        .unwrap();
        let done = pool.complete().unwrap();
        assert!(matches!(done.outcome, Some(SliceOutcome::Fault(_))));
        assert_eq!(done.instructions, 200_000);
        assert!(done.cpu.fault_retired() < POLL_INSTRUCTIONS);
    }

    #[test]
    fn request_and_pool_teardown_stop_endless_guest_workers() {
        let mut pool = Pool::new(2);
        for slot in 0..2 {
            pool.ensure(slot).unwrap();
        }
        let control = Arc::new(Control::new(u64::MAX));
        for slot in 0..2 {
            pool.dispatch(
                slot,
                work(slot as u32 + 1, &[0x14000000], 0, control.clone()),
            )
            .unwrap();
        }
        assert!(pool
            .complete_timeout(Duration::from_millis(10))
            .unwrap()
            .is_none());
        control.stop();
        let a = pool.complete().unwrap();
        let b = pool.complete().unwrap();
        assert!(a.instructions + b.instructions > 0);
        assert_eq!(pool.active.load(Ordering::Relaxed), 0);
        let control = Arc::new(Control::new(u64::MAX));
        pool.dispatch(0, work(1, &[0x14000000], 0, control))
            .unwrap();
        // Drop requests a stop before joining, even without a caller-held control.
        drop(pool);
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
#[path = "workers_uring_tests.rs"]
mod uring_tests;
