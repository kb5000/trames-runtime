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
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex, OnceLock, Weak,
    },
    time::{Duration, Instant},
};
use trames_engine::{Cpu, DecodeStats, SliceOutcome};
mod domains;
pub(super) use domains::{Checkpoint, Domain};

#[derive(Clone)]
pub(super) enum WaitState {
    /// A lifecycle-owned wait; ring maintenance must not retire its syscall.
    OwnerEvent,
    Signal(Arc<SignalWait>),
    Child(Arc<ChildWait>),
    Completion(Arc<CompletionWait>),
    Namespace(Arc<NamespaceWait>),
    Policy(Arc<PolicyWait>),
    Barrier(Arc<crate::barrier::Wait>),
    /// Retry the retained pending CPU syscall after original task/mm custody.
    /// This is not a completed guest wait and must not overwrite its arguments.
    Custody(Arc<crate::process::tasks::AdmissionWait>),
    Futex {
        wait: Arc<Wait>,
        deadline: Option<Instant>,
    },
    Sleep {
        deadline: Instant,
        remaining: u64,
    },
}
/// One accepted namespace operation, including its retained target and state.
/// The mutex protects transfer between a parked job and its next executor.
/// It never serializes different tasks or ordinary syscalls.
pub(super) struct NamespaceWait {
    work: Mutex<Option<trames_vfs::TaskNamespaceWork>>,
    subscription: Mutex<Option<trames_vfs::IoSubscription>>,
}
impl NamespaceWait {
    pub fn new(work: trames_vfs::TaskNamespaceWork) -> Arc<Self> {
        Arc::new(Self {
            work: Mutex::new(Some(work)),
            subscription: Mutex::default(),
        })
    }
    pub fn ready(&self) -> bool {
        self.work
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|w| w.ready())
    }
    pub fn bind(&self, signal: &Arc<trames_vfs::IoSignal>) {
        *self.subscription.lock().unwrap() = self
            .work
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|w| w.subscribe(signal));
    }
    pub fn run(&self) -> Option<(trames_vfs::TaskNamespaces, Result<u64, trames_vfs::Errno>)> {
        let work = self.work.lock().unwrap().take()?;
        match work.run() {
            trames_vfs::TaskNamespaceAttempt::Complete(state, result) => {
                self.subscription.lock().unwrap().take();
                Some((state, result))
            }
            trames_vfs::TaskNamespaceAttempt::Waiting(work) => {
                *self.work.lock().unwrap() = Some(work);
                None
            }
        }
    }
}
/// One accepted installation, retained across slot release and cancellation.
pub(super) struct PolicyWait {
    work: Mutex<Option<crate::process::seccomp::Install>>,
    subscription: Mutex<Option<trames_vfs::IoSubscription>>,
}
impl PolicyWait {
    pub fn new(work: crate::process::seccomp::Install) -> Arc<Self> {
        Arc::new(Self {
            work: Mutex::new(Some(work)),
            subscription: Mutex::default(),
        })
    }
    pub fn ready(&self) -> bool {
        self.work
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|w| w.ready())
    }
    pub fn bind(&self, signal: &Arc<trames_vfs::IoSignal>) {
        *self.subscription.lock().unwrap() = self
            .work
            .lock()
            .unwrap()
            .as_ref()
            .map(|w| w.subscribe(signal));
    }
    pub fn run(&self) -> Option<Result<u64, trames_vfs::Errno>> {
        let work = self.work.lock().unwrap().take()?;
        match work.run() {
            crate::process::seccomp::Attempt::Complete(result) => {
                self.subscription.lock().unwrap().take();
                Some(result)
            }
            crate::process::seccomp::Attempt::Waiting(work) => {
                *self.work.lock().unwrap() = Some(*work);
                None
            }
        }
    }
}
pub(super) struct CompletionWait {
    pub release: Arc<trames_kernel::completion::Completion>,
    subscriptions: Mutex<Vec<trames_vfs::IoSubscription>>,
}
impl CompletionWait {
    pub fn new(release: Arc<trames_kernel::completion::Completion>) -> Arc<Self> {
        Arc::new(Self {
            release,
            subscriptions: Default::default(),
        })
    }
    pub fn bind(&self, task: &trames_kernel::signal::IoTask, signal: &Arc<trames_vfs::IoSignal>) {
        let mut subscriptions = task.subscribe(signal);
        subscriptions.push(self.release.subscribe(signal));
        *self.subscriptions.lock().unwrap() = subscriptions;
    }
}
pub(super) struct ChildWait {
    pub request: trames_kernel::children::Wait,
    subscriptions: Mutex<Vec<trames_vfs::IoSubscription>>,
}
impl ChildWait {
    pub fn new(request: trames_kernel::children::Wait) -> Arc<Self> {
        Arc::new(Self {
            request,
            subscriptions: Mutex::default(),
        })
    }
    pub fn bind(
        &self,
        family: &trames_kernel::children::Children,
        task: &trames_kernel::signal::IoTask,
        signal: &Arc<trames_vfs::IoSignal>,
    ) {
        let mut subscriptions = task.subscribe(signal);
        subscriptions.push(family.subscribe(signal));
        *self.subscriptions.lock().unwrap() = subscriptions;
    }
}
pub(super) struct SignalWait {
    pub request: trames_kernel::signal::SignalWait,
    subscriptions: Mutex<Vec<trames_vfs::IoSubscription>>,
}
impl SignalWait {
    pub fn new(request: trames_kernel::signal::SignalWait) -> Arc<Self> {
        Arc::new(Self {
            request,
            subscriptions: Mutex::default(),
        })
    }
    pub fn bind(&self, task: &trames_kernel::signal::IoTask, signal: &Arc<trames_vfs::IoSignal>) {
        *self.subscriptions.lock().unwrap() = task.subscribe(signal);
    }
}
impl WaitState {
    fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Futex { deadline, .. } => *deadline,
            Self::Sleep { deadline, .. } => Some(*deadline),
            Self::OwnerEvent
            | Self::Child(_)
            | Self::Completion(_)
            | Self::Namespace(_)
            | Self::Policy(_)
            | Self::Barrier(_)
            | Self::Custody(_) => None,
            Self::Signal(wait) => wait.request.deadline(),
        }
    }
    fn woken(&self) -> bool {
        matches!(self, Self::Futex { wait, .. } if wait.woken())
    }
    fn bind<C: Cpu>(&self, epoch: &Arc<Epoch<C>>) {
        if let Self::Futex { wait, .. } = self {
            wait.ticket.bind(epoch);
        }
    }
    fn matches_ticket(&self, ticket: &Arc<Ticket>) -> bool {
        matches!(self, Self::Futex { wait, .. } if Arc::ptr_eq(&wait.ticket, ticket))
    }
    fn expire(&self) -> u64 {
        match self {
            Self::Futex { wait, .. } if wait.timeout() => 0u64.wrapping_sub(110),
            _ => 0,
        }
    }
}
#[derive(Clone)]
pub(super) struct IoCall {
    pub aio: Option<trames_linux::RetainedAio>,
    pub number: u32,
    pub args: [u64; 6],
    pub flock: Option<trames_vfs::FlockRequest>,
    pub record: Option<trames_vfs::RecordWait>,
    pub retained_byte: Option<trames_linux::RetainedByte>,
    pub retained_socket: Option<trames_linux::RetainedSocket>,
    pub tcp_liveness: Option<trames_net::TcpLease>,
    pub retained_poll: Option<Arc<trames_linux::RetainedWait>>,
    pub uring: Option<trames_linux::UringEnter>,
    pub file: Option<trames_linux::FilePending>,
    pub file_checkpoint: Option<trames_linux::FileCheckpoint>,
    pub deadline: Option<Instant>,
}
impl IoCall {
    pub fn from_wait(wait: Arc<trames_linux::RetainedWait>) -> Self {
        Self {
            number: wait.number,
            args: wait.args,
            deadline: wait.deadline,
            retained_poll: Some(wait),
            retained_byte: None,
            retained_socket: None,
            flock: None,
            record: None,
            tcp_liveness: None,
            uring: None,
            file: None,
            file_checkpoint: None,
            aio: None,
        }
    }
    pub fn from_file_checkpoint(
        file: trames_linux::FileCheckpoint,
        number: u32,
        args: [u64; 6],
    ) -> Self {
        Self {
            number,
            args,
            flock: None,
            record: None,
            retained_byte: None,
            retained_socket: None,
            tcp_liveness: None,
            retained_poll: None,
            uring: None,
            file: None,
            file_checkpoint: Some(file),
            aio: None,
            deadline: None,
        }
    }

    pub fn from_byte(file: trames_linux::RetainedByte, number: u32, args: [u64; 6]) -> Self {
        let (number, args) = file.local_message_entry().unwrap_or((number, args));
        Self {
            number,
            args,
            deadline: None,
            retained_byte: Some(file),
            retained_socket: None,
            flock: None,
            record: None,
            tcp_liveness: None,
            retained_poll: None,
            uring: None,
            file: None,
            file_checkpoint: None,
            aio: None,
        }
    }
    pub fn from_socket(call: trames_linux::RetainedSocket) -> Self {
        Self {
            number: call.number,
            args: call.args,
            deadline: call.deadline,
            retained_socket: Some(call),
            flock: None,
            record: None,
            retained_byte: None,
            tcp_liveness: None,
            retained_poll: None,
            uring: None,
            file: None,
            file_checkpoint: None,
            aio: None,
        }
    }
}
impl From<&trames_linux::PendingIo> for IoCall {
    fn from(io: &trames_linux::PendingIo) -> Self {
        Self {
            number: io.number,
            args: io.args,
            flock: io.flock.clone(),
            record: io.record.clone(),
            retained_byte: io.retained_byte.clone(),
            retained_socket: io.retained_socket.clone(),
            tcp_liveness: io.tcp_liveness(),
            retained_poll: io.retained_poll.clone(),
            uring: io.uring_enter(),
            file: io.file_pending(),
            file_checkpoint: None,
            aio: io.aio.clone(),
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
    pub additive_mmaps: u64,
    pub additive_time: Duration,
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
impl<C: Cpu> Done<C> {
    pub fn take_stats(&mut self) -> Stats {
        Stats {
            elapsed: std::mem::take(&mut self.elapsed),
            before: std::mem::take(&mut self.before),
            after: std::mem::take(&mut self.after),
            worker: std::mem::take(&mut self.worker),
            instructions: std::mem::take(&mut self.instructions),
            chunks: std::mem::take(&mut self.chunks),
            syscalls: std::mem::take(&mut self.syscalls),
            direct_syscalls: std::mem::take(&mut self.direct_syscalls),
            futex_wakes: std::mem::take(&mut self.futex_wakes),
            futex_woken: std::mem::take(&mut self.futex_woken),
            futex_requeues: std::mem::take(&mut self.futex_requeues),
            serviced_syscalls: std::mem::take(&mut self.serviced_syscalls),
            additive_mmaps: std::mem::take(&mut self.additive_mmaps),
            additive_time: std::mem::take(&mut self.additive_time),
            service_wait: std::mem::take(&mut self.service_wait),
            syscall_time: std::mem::take(&mut self.syscall_time),
            native: std::mem::take(&mut self.native),
            rejected_native: std::mem::take(&mut self.rejected_native),
            cpu_times: std::mem::take(&mut self.cpu_times),
            assignments: std::mem::take(&mut self.assignments),
            waits: std::mem::take(&mut self.waits),
            resumes: std::mem::take(&mut self.resumes),
            yields: std::mem::take(&mut self.yields),
            io_waits: std::mem::take(&mut self.io_waits),
            service_waits: std::mem::take(&mut self.service_waits),
            file_syscalls: std::mem::take(&mut self.file_syscalls),
            socket_syscalls: std::mem::take(&mut self.socket_syscalls),
            timer_syscalls: std::mem::take(&mut self.timer_syscalls),
            poll_syscalls: std::mem::take(&mut self.poll_syscalls),
            uring_syscalls: std::mem::take(&mut self.uring_syscalls),
            fd_syscalls: std::mem::take(&mut self.fd_syscalls),
            gpu: std::mem::take(&mut self.gpu),
        }
    }
}
impl Stats {
    pub fn merge(&mut self, other: Self) {
        self.after.lookups += other.after.lookups - other.before.lookups;
        self.after.misses += other.after.misses - other.before.misses;
        self.after.instructions += other.after.instructions - other.before.instructions;
        for (target, value) in self.cpu_times.iter_mut().zip(other.cpu_times) {
            *target += value;
        }
        self.native.merge(other.native);
        self.gpu.merge(other.gpu);
        self.rejected_native = self.rejected_native.or(other.rejected_native);
        self.elapsed += other.elapsed;
        self.instructions += other.instructions;
        self.chunks += other.chunks;
        self.syscalls += other.syscalls;
        self.direct_syscalls += other.direct_syscalls;
        self.futex_wakes += other.futex_wakes;
        self.futex_woken += other.futex_woken;
        self.futex_requeues += other.futex_requeues;
        self.serviced_syscalls += other.serviced_syscalls;
        self.additive_mmaps += other.additive_mmaps;
        self.additive_time += other.additive_time;
        self.service_wait += other.service_wait;
        self.syscall_time += other.syscall_time;
        self.assignments += other.assignments;
        self.waits += other.waits;
        self.resumes += other.resumes;
        self.yields += other.yields;
        self.io_waits += other.io_waits;
        self.service_waits += other.service_waits;
        self.file_syscalls += other.file_syscalls;
        self.socket_syscalls += other.socket_syscalls;
        self.timer_syscalls += other.timer_syscalls;
        self.poll_syscalls += other.poll_syscalls;
        self.uring_syscalls += other.uring_syscalls;
        self.fd_syscalls += other.fd_syscalls;
    }
}

/// Publish source ownership before a born host task becomes externally visible.
/// CPU membership follows only after its original View can actually execute.
pub(crate) struct HostAdmission<C: Cpu> {
    epoch: Weak<Epoch<C>>,
    id: u32,
}
impl<C: Cpu> Drop for HostAdmission<C> {
    fn drop(&mut self) {
        if let Some(epoch) = self.epoch.upgrade() {
            let mut q = epoch.queues.lock().unwrap();
            q.host_admissions.remove(&self.id);
            epoch.notify(&mut q);
        }
    }
}
pub(super) struct Job<C: Cpu> {
    pub work: Work<C>,
    pub stats: Stats,
    pub affinity: u64,
    pub waiting: Option<WaitState>,
    pub io: Option<trames_linux::PendingIo>,
    pub uring: Option<trames_linux::UringBackground>,
    pub retry: Option<IoCall>,
    pub hardware_wait: Option<Arc<trames_memory::HardwareWait>>,
    pub gpu_pending: Option<crate::gpu::Pending>,
    pub domain: Option<Arc<Domain>>,
    pub checkpoint: Option<SliceOutcome>,
    /// Guest code reached this exit during a bounded exclusive-mm window.
    /// Its syscall/native/fault handling still belongs to normal dispatch.
    pub pending_cpu: Option<SliceOutcome>,
    pub pending_accounted: bool,
    /// A filtered syscall entry may defer before effects. Carry its
    /// decision to the owner instead of evaluating the same BPF entry twice.
    pub seccomp_entry: Option<crate::process::seccomp::EntryDecision>,
}
impl<C: Cpu> Job<C> {
    pub fn structural_call(&self) -> Option<crate::structural::Call> {
        self.checkpoint_syscall()?;
        crate::structural::Call::from_cpu(&self.work.cpu)
    }
    pub fn checkpoint_syscall(&self) -> Option<u32> {
        matches!(self.checkpoint, Some(SliceOutcome::Syscall { .. }))
            .then(|| self.work.cpu.x(8) as u32)
    }
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
            uring: None,
            retry: None,
            hardware_wait: None,
            gpu_pending: None,
            domain: None,
            checkpoint: None,
            pending_cpu: None,
            pending_accounted: false,
            seccomp_entry: None,
            stats: Stats {
                before,
                after: before,
                worker: last_cpu,
                ..Default::default()
            },
        })
    }
    pub fn affinity(&self) -> u64 {
        self.work
            .syscalls
            .as_ref()
            .map_or(self.affinity, |s| s.io_signals.scheduling.affinity())
    }
    pub(super) fn guest_waiting(&self) -> bool {
        self.stopped()
            || self
                .hardware_wait
                .as_ref()
                .is_some_and(|wait| !wait.ready())
            || self.waiting.as_ref().is_some_and(|wait| !wait.woken())
            || self.io.as_ref().is_some_and(|io| {
                !io.signal.ready() && !io.wake_deadline().is_some_and(|d| d <= Instant::now())
            })
            || self.gpu_pending.as_ref().is_some_and(|gpu| gpu.waiting())
    }
    /// Rearm the original task notification before the final level-state
    /// check under the run-queue lock. A previous STOP wake may remain fired
    /// while the stopped job parks; CONT must be able to notify it again.
    fn rearm_signals(&self) {
        if let Some(wake) = self
            .work
            .syscalls
            .as_ref()
            .and_then(|s| s.io_wake.as_ref())
            .filter(|s| s.ready())
        {
            wake.reset();
        }
    }
    fn stopped(&self) -> bool {
        self.work.syscalls.as_ref().is_some_and(|s| s.quiesced())
    }
    pub fn stop_hold(&self) -> Option<bool> {
        if matches!(self.waiting, Some(WaitState::OwnerEvent)) {
            return None;
        }
        Some(
            matches!(
                self.waiting,
                Some(WaitState::Namespace(_) | WaitState::Policy(_) | WaitState::Barrier(_))
            ) || matches!(self.waiting, Some(WaitState::Completion(ref wait)) if !wait.release.finished())
                || self.pending_cpu.is_some()
                || self.checkpoint.is_some()
                || self.hardware_wait.as_ref().is_some_and(|w| !w.ready())
                || self
                    .gpu_pending
                    .as_ref()
                    .is_some_and(|p| p.compile.is_some())
                || self.io.as_ref().is_some_and(|io| {
                    io.number == 2 || io.file_pending().is_some_and(|f| !f.interruptible())
                })
                || self.retry.as_ref().is_some_and(|io| {
                    io.number == 2
                        || io.file_checkpoint.is_some()
                        || io.file.as_ref().is_some_and(|f| !f.interruptible())
                }),
        )
    }
    fn wake_deadline(&self) -> Option<Instant> {
        let stopped = self.stopped();
        [
            self.waiting
                .as_ref()
                .filter(|w| !stopped || !matches!(w, WaitState::Signal(_)))
                .and_then(WaitState::deadline),
            self.io
                .as_ref()
                .filter(|io| {
                    !stopped
                        || io.number == 2
                        || io.file_pending().is_some_and(|f| !f.interruptible())
                })
                .and_then(|io| io.wake_deadline()),
            self.gpu_pending
                .as_ref()
                .filter(|g| !stopped || g.compile.is_some())
                .and_then(|g| g.deadline()),
            self.uring.as_ref().and_then(|r| r.deadline()),
        ]
        .into_iter()
        .flatten()
        .min()
    }
    fn ring_ready(&self) -> bool {
        if matches!(&self.waiting, Some(WaitState::Custody(wait)) if wait.signal.ready()) {
            return true;
        }
        if self
            .work
            .syscalls
            .as_ref()
            .is_some_and(|s| s.io_signals.lifecycle().termination().is_some())
        {
            return true;
        }
        if self.stopped() {
            return self
                .work
                .syscalls
                .as_ref()
                .is_some_and(|s| s.next_io_signal().is_some_and(|(sig, _)| sig == 9))
                || self.uring.as_ref().is_some_and(|r| {
                    r.signal.ready() || r.deadline().is_some_and(|d| d <= Instant::now())
                })
                || self
                    .gpu_pending
                    .as_ref()
                    .is_some_and(|g| g.compile.is_some() && !g.waiting())
                || (matches!(&self.waiting, Some(WaitState::Namespace(wait)) if wait.ready())
                    || matches!(&self.waiting, Some(WaitState::Policy(wait)) if wait.ready())
                    || matches!(&self.waiting, Some(WaitState::Barrier(wait)) if wait.ready()))
                || matches!(&self.waiting, Some(WaitState::Completion(wait)) if wait.release.finished())
                || self.io.as_ref().is_some_and(|io| {
                    (io.number == 2 || io.file_pending().is_some_and(|f| !f.interruptible()))
                        && io.signal.ready()
                });
        }
        if (matches!(&self.waiting, Some(WaitState::Namespace(wait)) if wait.ready())
            || matches!(&self.waiting, Some(WaitState::Policy(wait)) if wait.ready())
            || matches!(&self.waiting, Some(WaitState::Barrier(wait)) if wait.ready()))
        {
            return true;
        }
        if let Some(WaitState::Completion(wait)) = &self.waiting {
            if wait.release.finished() {
                return true;
            }
        }
        if let Some(WaitState::Child(wait)) = &self.waiting {
            if self.work.syscalls.as_ref().is_some_and(|s| {
                s.children
                    .ready(wait.request, &s.io_routes.namespace, s.io_signals.group())
            }) {
                return true;
            }
        }
        if let Some(WaitState::Signal(wait)) = &self.waiting {
            if self
                .work
                .syscalls
                .as_ref()
                .is_some_and(|s| wait.request.ready(&s.io_signals))
            {
                return true;
            }
        }
        self.work.syscalls.as_ref().is_some_and(|s| {
            s.next_io_signal().is_some_and(|(sig, _)| {
                (s.actions.get(sig as usize).handler <= 1
                    && !(matches!(sig, 19..=22) && self.stop_hold() == Some(true)))
                    || s.actions.get(sig as usize).handler > 1
                        && !(matches!(&self.waiting, Some(WaitState::Namespace(_) | WaitState::Policy(_) | WaitState::Barrier(_)))
                            || matches!(&self.waiting, Some(WaitState::Completion(wait)) if !wait.release.finished())
                            || self.gpu_pending.is_some()
                            || self
                                .retry
                                .as_ref()
                                .is_some_and(|call| call.file.is_some() || call.number == 2)
                            || self
                                .io
                                .as_ref()
                                .is_some_and(|io| io.file_pending().is_some() || io.number == 2))
            })
        }) || self.uring.as_ref().is_some_and(|ring| {
            ring.signal.ready() || ring.deadline().is_some_and(|d| d <= Instant::now())
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
        done.task = work.task;
        done.trace = work.trace;
        done.seccomp_entry = self.seccomp_entry;
        done
    }
    pub fn finish_retired(
        self,
        outcome: Option<SliceOutcome>,
        peer: u64,
        exit: crate::worker_syscalls::Exit,
    ) -> Done<C> {
        let vfork = self
            .work
            .syscalls
            .as_ref()
            .and_then(|s| s.vfork_release.clone());
        let mut done = self.finish(outcome, peer);
        if done.outcome.is_some() {
            // The dying CPU can no longer access the old mm. Parent release
            // does not wait for unrelated FD/metadata destruction on its owner.
            if let Some(release) = vfork {
                release.finish();
            }
            done.thread_exit = Some(exit.status);
            done.exit_groups = exit.groups;
        }
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
            task: None,
            thread_exit: None,
            trace: Default::default(),
            fatal_fault: None,
            exit_groups: Vec::new(),
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
            additive_mmaps: self.additive_mmaps,
            additive_time: self.additive_time,
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
    host_admissions: BTreeSet<u32>,
    running: usize,
    completing: usize,
    finished: Vec<Done<C>>,
    retirement_notified: bool,
    initial_slots: BTreeMap<u32, usize>,
    gpu_peak_pending: usize,
    host_waiting: bool,
    domains: domains::Domains<C>,
    custody_waits: Vec<CustodyWait<C>>,
    retired: Vec<(Box<Job<C>>, Option<SliceOutcome>)>,
    idle_notified: bool,
    sleeping_slots: u64,
}
struct CustodyWait<C: Cpu> {
    checkpoint: Checkpoint<C>,
    signal: Arc<trames_vfs::IoSignal>,
    _subscriptions: Vec<trames_vfs::IoSubscription>,
}
pub(super) struct Epoch<C: Cpu> {
    pub control: Arc<Control>,
    host_pause: Arc<std::sync::atomic::AtomicBool>,
    queues: Mutex<Queues<C>>,
    changed: Condvar,
    slot_changed: [Condvar; 32],
    host_events: OnceLock<Result<Arc<trames_vfs::HostEvents>, Arc<std::io::Error>>>,
    host_error: OnceLock<Arc<std::io::Error>>,
    pub io_target: Weak<dyn trames_vfs::IoWake>,
    me: Weak<Self>,
    timers: OnceLock<Arc<trames_kernel::timers::Timers>>,
    starter: OnceLock<crate::workers::Starter<C>>,
    lifecycle: OnceLock<crate::process::lifecycle::Lifecycle<C>>,
    active_slots: AtomicU64,
    activation_failed: std::sync::atomic::AtomicBool,
    deadline_origin: Instant,
    next_deadline: AtomicU64,
    ready_slots: AtomicU64,
    #[cfg(all(test, trames_interpreter_conformance))]
    preemption: std::sync::atomic::AtomicBool,
    pub progress: AtomicU64,
    pub local_vm: bool,
    persistent: bool,
    terminal: AtomicBool,
}
impl<C: Cpu> Epoch<C> {
    pub fn memory_barrier(
        &self,
        original: u64,
        global: bool,
        caller: usize,
    ) -> Arc<crate::barrier::Request> {
        let request = crate::barrier::Request::new();
        let domains = self
            .queues
            .lock()
            .unwrap()
            .domains
            .barrier_domains(original, global);
        // Do not notify/drop acknowledgement resources under the queue lock.
        for domain in domains {
            domain.barrier(&request, caller);
        }
        request.acknowledge();
        request
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn new(control: Arc<Control>) -> Arc<Self> {
        Self::configured(control, None, false)
    }
    fn configured(
        control: Arc<Control>,
        events: Option<std::sync::mpsc::Sender<crate::workers::Event<C>>>,
        persistent: bool,
    ) -> Arc<Self> {
        let domains = domains::Domains::<C>::new(events.clone());
        let host_pause = domains.host_pause.clone();
        Arc::new_cyclic(|me: &Weak<Self>| Self {
            control,
            host_pause,
            queues: Mutex::new(Queues::<C> {
                domains,
                ..Default::default()
            }),
            changed: Condvar::new(),
            slot_changed: std::array::from_fn(|_| Condvar::new()),
            host_events: OnceLock::new(),
            host_error: OnceLock::new(),
            io_target: me.clone(),
            me: me.clone(),
            timers: OnceLock::new(),
            starter: OnceLock::new(),
            lifecycle: OnceLock::new(),
            active_slots: AtomicU64::new(0),
            activation_failed: std::sync::atomic::AtomicBool::new(false),
            deadline_origin: Instant::now(),
            next_deadline: AtomicU64::new(u64::MAX),
            ready_slots: AtomicU64::new(0),
            #[cfg(all(test, trames_interpreter_conformance))]
            preemption: std::sync::atomic::AtomicBool::new(true),
            progress: AtomicU64::new(0),
            local_vm: events.is_some(),
            persistent,
            terminal: AtomicBool::new(false),
        })
    }
    pub fn with_events(
        control: Arc<Control>,
        events: std::sync::mpsc::Sender<crate::workers::Event<C>>,
        persistent: bool,
    ) -> Arc<Self> {
        Self::configured(control, Some(events), persistent)
    }
    /// Suspend guest dispatch without returning CPUs, Views or accepted waits.
    /// The original execution leases close both pause/pre-entry orders. Existing
    /// workers remain available for accepted backing and lifecycle completion.
    pub fn pause_host(&self, paused: bool) {
        if self.host_pause.load(Ordering::Relaxed) == paused {
            return;
        }
        let mut q = self.queues.lock().unwrap();
        if self.host_pause.swap(paused, Ordering::Relaxed) == paused {
            return;
        }
        if paused {
            q.domains.interrupt_host_pause();
        } else {
            // An Idle event observed during host suspension is deliberately
            // ignored. Resume must let the queue publish that state again.
            q.idle_notified = false;
        }
        self.refresh_ready(&q);
        self.notify(&mut q);
        drop(q);
        if !paused {
            if let Some(starter) = self.starter.get() {
                for slot in self.additional_slots(self.active_slots(), starter.capacity()) {
                    let _ = self.activate(slot);
                }
            }
        }
    }
    pub(crate) fn bind_session(&self, terminal: bool) {
        self.terminal.store(terminal, Ordering::Relaxed);
    }
    pub fn bind_lifecycle(&self, lifecycle: crate::process::lifecycle::Lifecycle<C>) {
        lifecycle.bind_memory(self.io_target.clone(), &self.control);
        assert!(self.lifecycle.set(lifecycle).is_ok());
        self.queues.lock().unwrap().domains.source_lifecycle = true;
    }
    pub fn collect_lifecycle(
        &self,
        kernel: &mut crate::process::Kernel<C>,
    ) -> Option<crate::RuntimeError> {
        let lifecycle = self
            .lifecycle
            .get()
            .and_then(|lifecycle| lifecycle.collect(kernel));
        self.host_error
            .get()
            .cloned()
            .map(crate::RuntimeError::HostIo)
            .or(lifecycle)
    }
    /// Run only on a returned executor. No mutable Kernel or host callback enters.
    pub(crate) fn finish_closed(&self) {
        assert!(self.control.closing());
        let lifecycle = self.lifecycle.get().expect("source completion lifecycle");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lifecycle.finish_closed(
                self,
                self.control.end() != Some(crate::execution_control::End::Budget),
            )
        }))
        .unwrap_or(Err(crate::RuntimeError::Arguments(
            "session completion panicked",
        )));
        if let Err(error) = result {
            lifecycle.host_error(error);
        }
    }
    pub(crate) fn collect_closed(
        &self,
        kernel: &mut crate::process::Kernel<C>,
    ) -> Option<crate::RuntimeError> {
        let lifecycle = self
            .lifecycle
            .get()
            .expect("source completion lifecycle")
            .collect_closed(kernel);
        self.host_error
            .get()
            .cloned()
            .map(crate::RuntimeError::HostIo)
            .or(lifecycle)
    }
    pub(crate) fn drain_closed(&self) -> Vec<Done<C>> {
        assert!(self.control.closing());
        let done = self.drain();
        self.queues.lock().unwrap().members.clear();
        done
    }
    pub fn bind_starter(&self, starter: crate::workers::Starter<C>) {
        self.starter.get_or_init(|| starter);
    }
    pub fn active_slots(&self) -> u64 {
        self.active_slots.load(Ordering::Relaxed)
    }
    pub fn activation_failed(&self) -> bool {
        self.activation_failed.load(Ordering::Relaxed)
    }
    pub fn activate(&self, slot: usize) -> std::io::Result<()> {
        let bit = 1u64 << slot;
        if self.active_slots.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
            return Ok(());
        }
        let starter = self.starter.get().expect("bound CPU pool");
        let epoch = self.me.upgrade().expect("live execution epoch");
        if let Err(error) = starter.start(slot, epoch) {
            self.active_slots.fetch_and(!bit, Ordering::Relaxed);
            self.activation_failed.store(true, Ordering::Relaxed);
            self.control.close(crate::execution_control::End::Failed);
            return Err(error);
        }
        Ok(())
    }
    fn activate_for(&self, mask: u64) {
        if self.control.stopped() || self.host_pause.load(Ordering::Relaxed) {
            return;
        }
        let Some(starter) = self.starter.get() else {
            return;
        };
        let mask = mask & ((1u64 << starter.capacity()) - 1);
        if mask != 0 && mask & self.active_slots() == 0 {
            let _ = self.activate(mask.trailing_zeros() as usize);
        }
    }
    pub fn bind_timers(self: &Arc<Self>, timers: Arc<trames_kernel::timers::Timers>) {
        assert!(self.timers.set(timers.clone()).is_ok());
        let target: Arc<dyn trames_kernel::timers::TimerWake> = self.clone();
        timers.bind(Arc::downgrade(&target));
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
                    .map_or(job.affinity(), |slot| 1 << slot)
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
        if let Some(Ok(events)) = self.host_events.get() {
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
        (next != u64::MAX && self.deadline_ticks(Instant::now()) >= next)
            || self.timers.get().is_some_and(|t| t.due())
    }
    fn refresh_ready(&self, q: &Queues<C>) {
        let slots = if self.host_pause.load(Ordering::Relaxed) {
            0
        } else {
            q.ready.iter().fold(0, |mask, job| {
                mask | q
                    .initial_slots
                    .get(&job.work.pid)
                    .map_or(job.affinity(), |slot| 1 << slot)
            })
        };
        self.ready_slots.store(slots, Ordering::Relaxed);
    }
    fn ready(&self, q: &mut Queues<C>, job: Box<Job<C>>) {
        if job.work.memory.is_none() {
            // A dormant original actor has no byte View until an actual event
            // makes it runnable. Existing workers prepare only this mm under
            // its original custody; unrelated executing domains keep their Views.
            let id = job.domain.as_ref().expect("registered dormant mm").id;
            q.idle_notified = false;
            q.domains.pause_bytes(id);
            q.domains.hold(job);
            self.capture_paused(q);
            // An idle executor is notified by the caller. With every slot busy,
            // reuse the existing bounded-slice hint for one maintenance turn.
            self.next_deadline.store(0, Ordering::Relaxed);
            return;
        }
        if let Some(snapshot) = &job.work.syscalls {
            snapshot.io_signals.proc_view.waiting(false);
        }
        q.idle_notified = false;
        let slot = job.stats.worker;
        if job.stats.assignments != 0
            && job.affinity() & (1 << slot) != 0
            && q.sleeping_slots & (1 << slot) != 0
            && q.ready.len() < q.sleeping_slots.count_ones() as usize
            && !q.initial_slots.values().any(|&reserved| reserved == slot)
        {
            // Reserve the first claim on an idle original executor, retaining
            // its MMU/native caches. Never wait for a busy CPU; new tasks have
            // no prior executor and remain freely stealable.
            q.initial_slots.insert(job.work.pid, slot);
            self.slot_changed[slot].notify_one();
        }
        self.activate_for(job.affinity());
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
        let io = q.parked.get_mut(&pid).unwrap().io.as_mut().unwrap();
        io.deadline = Some(deadline);
        if let Some(wait) = io.retained_poll.as_mut() {
            Arc::make_mut(wait).deadline = Some(deadline);
        }
        self.publish_deadline(Some(deadline));
        self.notify(&mut q);
    }
    /// Only before launch: every View is prepared/admitted before any CPU runs.
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn wait_child_parked(&self, pid: u32) {
        let until = Instant::now() + Duration::from_secs(5);
        let mut q = self.queues.lock().unwrap();
        while !q
            .parked
            .get(&pid)
            .is_some_and(|j| matches!(j.waiting, Some(WaitState::Child(_))))
        {
            assert!(!self.control.stopped(), "cohort stopped before child wait");
            let left = until.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "child wait did not park");
            q = self.changed.wait_timeout(q, left).unwrap().0;
        }
    }
    /// Bind original readiness before publishing either an initial or new job.
    fn bind_job(&self, job: &mut Job<C>) {
        let pid = job.work.pid;
        if let Some(snapshot) = &mut job.work.syscalls {
            let signal = trames_vfs::IoSignal::new(pid, self.io_target.clone());
            snapshot.io_signals.set_wake(&signal);
            if let Some(WaitState::Signal(wait)) = &job.waiting {
                wait.bind(&snapshot.io_signals, &signal);
            }
            if let Some(WaitState::Child(wait)) = &job.waiting {
                wait.bind(&snapshot.children, &snapshot.io_signals, &signal);
            }
            if let Some(WaitState::Completion(wait)) = &job.waiting {
                wait.bind(&snapshot.io_signals, &signal);
            }
            if let Some(WaitState::Namespace(wait)) = &job.waiting {
                wait.bind(&signal);
            }
            if let Some(WaitState::Barrier(wait)) = &job.waiting {
                wait.bind(&signal);
            }
            if let Some(WaitState::Policy(wait)) = &job.waiting {
                wait.bind(&signal);
            }
            snapshot.io_wake = Some(signal);
            job.uring = snapshot.direct.uring_background(pid, &self.io_target);
        }
    }
    pub fn add(self: &Arc<Self>, job: Box<Job<C>>) {
        self.add_inner(job, None);
    }
    pub fn add_dormant(self: &Arc<Self>, job: Box<Job<C>>, memory: u64) {
        assert!(
            job.work.memory.is_none(),
            "dormant admission owns no byte View"
        );
        self.add_inner(job, Some(memory));
    }
    fn add_inner(self: &Arc<Self>, mut job: Box<Job<C>>, dormant: Option<u64>) {
        self.bind_job(&mut job);
        let pid = job.work.pid;
        let mut q = self.queues.lock().unwrap();
        assert!(q.members.insert(pid), "duplicate cohort task");
        if let Some(memory) = dormant {
            q.domains.register_waiting(&mut job, memory);
        } else {
            q.domains.register(&mut job);
        }
        if q.domains.paused(pid) {
            q.domains.hold(job);
            self.capture_paused(&mut q);
            self.notify(&mut q);
            return;
        }
        if let Some(waiting) = &job.waiting {
            waiting.bind(self);
            if waiting.woken() {
                job.work.trace.finish(&mut job.work.cpu, 0);
                job.waiting = None;
            } else if job.uring.is_none() && !job.ring_ready() {
                self.publish_deadline(waiting.deadline());
                q.parked.insert(pid, job);
                return;
            }
        }
        self.ready(&mut q, job);
    }
    pub(crate) fn reserve_host(&self, id: u32) -> HostAdmission<C> {
        assert!(self.queues.lock().unwrap().host_admissions.insert(id));
        HostAdmission {
            epoch: self.me.clone(),
            id,
        }
    }
    pub(crate) fn controls(&self, id: u32) -> bool {
        let q = self.queues.lock().unwrap();
        q.members.contains(&id) || q.host_admissions.contains(&id)
    }
    pub(crate) fn admit_live(&self, job: Box<Job<C>>) {
        let original = self.me.upgrade().expect("live host admission");
        original.add(job);
        if let Some(starter) = self.starter.get() {
            for slot in self.additional_slots(self.active_slots(), starter.capacity()) {
                let _ = self.activate(slot);
            }
        }
    }
    pub(crate) fn admit_dormant(&self, job: Box<Job<C>>, memory: u64) {
        self.me
            .upgrade()
            .expect("live futex admission")
            .add_dormant(job, memory);
    }
    pub(crate) fn submit_host(&self, request: trames_linux::HostSpawn) -> bool {
        if let Some(lifecycle) = self.lifecycle.get() {
            lifecycle.submit_host(request);
            true
        } else {
            request.process.fail(38);
            false
        }
    }
    pub fn handoff(&self) {
        let mut q = self.queues.lock().unwrap();
        self.control.handoff();
        self.notify(&mut q);
    }
    /// One-way session completion. The waiting host receives no guest work.
    fn end(&self, reason: crate::execution_control::End) {
        let mut q = self.queues.lock().unwrap();
        self.control.close(reason);
        q.domains.interrupt_host_pause();
        self.notify(&mut q);
    }
    pub(crate) fn fail(&self) {
        self.end(crate::execution_control::End::Failed);
    }
    pub(crate) fn cancel(&self) {
        self.end(crate::execution_control::End::Cancelled);
    }
    pub(crate) fn complete(&self) {
        if self.terminal.load(Ordering::Relaxed) {
            self.end(crate::execution_control::End::Exited);
        } else {
            self.handoff();
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(crate) fn stop(&self) {
        self.handoff();
    }
    /// Terminal host failure. Keep the first cause and drain original actors;
    /// never reinterpret it as a missing guest operation or owner retry.
    pub fn fail_host_io(&self, error: std::io::Error) {
        let _ = self.host_error.set(Arc::new(error));
        self.fail();
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(crate) fn reject_host_events(&self, error: std::io::Error) {
        assert!(self.host_events.set(Err(Arc::new(error))).is_ok());
    }
    pub fn assign(&self, chosen: &[(u32, usize)]) {
        let mut q = self.queues.lock().unwrap();
        // Initial placement belongs to runnable work. A parked parent must
        // not reserve a CPU that its child's new peer can later occupy.
        for &(pid, slot) in chosen {
            if q.ready.iter().any(|job| job.work.pid == pid) {
                q.initial_slots.insert(pid, slot);
            }
        }
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
        if job.structural_call().is_some_and(|call| call.task()) {
            q.domains.pause_bytes(id);
        } else {
            q.domains.pause(BTreeSet::from([id]));
        }
        q.domains.hold(job);
        self.capture_paused(&mut q);
        self.notify(&mut q);
    }
    /// The creator's checkpoint still owns all private execution actors of
    /// this mm. Register a child there, never in the runnable queue early.
    pub fn admit_checkpoint(&self, checkpoint: &mut Checkpoint<C>, mut job: Box<Job<C>>) {
        self.bind_job(&mut job);
        let mut q = self.queues.lock().unwrap();
        assert!(q.members.insert(job.work.pid), "duplicate created task");
        q.domains.register(&mut job);
        q.domains.admit(checkpoint, job);
    }
    /// Publish an already-created task into the owned scope before rebuilding
    /// Views. A pending file layout can now defer the scope without losing the
    /// child or replaying its creator's syscall, including epoch cancellation.
    pub fn admit_waiting_checkpoint(
        &self,
        checkpoint: &mut Checkpoint<C>,
        mut job: Box<Job<C>>,
        memory: u64,
    ) {
        self.bind_job(&mut job);
        let mut q = self.queues.lock().unwrap();
        assert!(q.members.insert(job.work.pid), "duplicate created task");
        q.domains.register_waiting(&mut job, memory);
        q.domains.admit(checkpoint, job);
    }
    /// A completed peer can still be queued for asynchronous accounting when
    /// exec replaces its group. Claim that exact return, never a reused PID.
    pub fn take_replaced_return(
        &self,
        pid: u32,
        task: &crate::process::tasks::Handle<C>,
    ) -> Option<Done<C>> {
        let mut q = self.queues.lock().unwrap();
        let index = q.finished.iter().position(|done| {
            done.pid == pid && done.task.as_ref().is_some_and(|old| old.same(task))
        })?;
        let done = q.finished.swap_remove(index);
        assert!(q.members.remove(&pid));
        q.initial_slots.remove(&pid);
        q.domains.retire(pid);
        Some(done)
    }
    pub fn forget_checkpoint_member(&self, pid: u32) {
        let mut q = self.queues.lock().unwrap();
        assert!(q.members.remove(&pid));
        q.initial_slots.remove(&pid);
        q.domains.forget_owned(pid);
    }
    /// Extend existing CPU participation only when ready/running work needs
    /// it, including a child whose affinity excludes every active executor.
    pub fn additional_slots(&self, active: u64, cpus: usize) -> Vec<usize> {
        let q = self.queues.lock().unwrap();
        if self.host_pause.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let valid = if cpus == 64 {
            u64::MAX
        } else {
            (1u64 << cpus) - 1
        };
        let desired = (q.running + q.ready.len()).min(cpus);
        let eligible = q.ready.iter().fold(0, |mask, job| mask | job.affinity()) & valid;
        let mut selected = active;
        for job in &q.ready {
            let choices = job.affinity() & valid;
            if choices != 0 && choices & selected == 0 {
                selected |= 1 << choices.trailing_zeros();
            }
        }
        let mut available = eligible & !selected;
        while (selected.count_ones() as usize) < desired && available != 0 {
            let bit = 1 << available.trailing_zeros();
            selected |= bit;
            available &= !bit;
        }
        (0..cpus)
            .filter(|slot| (selected & !active) & (1 << slot) != 0)
            .collect()
    }
    fn claim_checkpoint(
        q: &mut Queues<C>,
        source: bool,
    ) -> Option<(Checkpoint<C>, Vec<trames_vfs::IoSubscription>)> {
        if let Some(index) = q.custody_waits.iter().position(|wait| {
            wait.signal.ready()
                && (q.domains.source_lifecycle
                    && crate::process::lifecycle::eligible(
                        wait.checkpoint.jobs.iter().map(Box::as_ref),
                        wait.checkpoint.proc_reads,
                        wait.checkpoint.mm_only,
                        wait.checkpoint.source_retry,
                        wait.checkpoint.layout_only,
                    ))
                    == source
        }) {
            let wait = q.custody_waits.swap_remove(index);
            Some((wait.checkpoint, wait._subscriptions))
        } else {
            q.domains
                .take(source)
                .map(|checkpoint| (checkpoint, Vec::new()))
        }
    }
    pub fn take_checkpoint(&self) -> Option<Checkpoint<C>> {
        let claimed = Self::claim_checkpoint(&mut self.queues.lock().unwrap(), false);
        // Subscription destruction stays outside the queue mutex.
        claimed.map(|(checkpoint, _subscriptions)| checkpoint)
    }
    pub fn defer_checkpoint(
        &self,
        checkpoint: Checkpoint<C>,
        signal: Arc<trames_vfs::IoSignal>,
        subscriptions: Vec<trames_vfs::IoSubscription>,
    ) {
        let mut q = self.queues.lock().unwrap();
        let ready = signal.ready();
        let source = q.domains.source_lifecycle
            && crate::process::lifecycle::eligible(
                checkpoint.jobs.iter().map(Box::as_ref),
                checkpoint.proc_reads,
                checkpoint.mm_only,
                checkpoint.source_retry,
                checkpoint.layout_only,
            );
        q.custody_waits.push(CustodyWait {
            checkpoint,
            signal,
            _subscriptions: subscriptions,
        });
        // Publication and wake share this mutex. A release before publication
        // is latched in the signal; a later release finds the published wait.
        if ready {
            if let Some(events) = q.domains.events.as_ref().filter(|_| !source) {
                let _ = events.send(crate::workers::Event::VmReady);
            }
            self.notify(&mut q);
        }
    }
    /// Locate the scheduler's current domain through an actual original task.
    /// The owner selected that task by MemoryReport resource identity, never a
    /// decoder epoch number or a PID from a prior incarnation.
    pub fn request_proc_reads(&self, pid: u32) -> bool {
        let mut q = self.queues.lock().unwrap();
        if !q.domains.pause_proc_reads(pid) {
            return false;
        }
        self.capture_paused(&mut q);
        self.notify(&mut q);
        true
    }
    pub fn request_file_layouts(&self, pid: u32) -> bool {
        let mut q = self.queues.lock().unwrap();
        if !q.domains.pause_layouts(pid) {
            return false;
        }
        self.capture_paused(&mut q);
        self.notify(&mut q);
        true
    }
    /// The existing owner may briefly execute guest code only when no worker
    /// can claim an unrelated job. This reserves logical CPU capacity without
    /// adding an execution slot or pausing unrelated address spaces.
    pub fn checkpoint_owns_all_jobs(&self, checkpoint: &Checkpoint<C>) -> bool {
        checkpoint.jobs.len() == self.queues.lock().unwrap().members.len()
    }
    pub fn idle(&self) -> bool {
        let q = self.queues.lock().unwrap();
        if self.host_pause.load(Ordering::Relaxed) {
            return false;
        }
        q.running == 0
            && q.completing == 0
            && q.ready.is_empty()
            && !q.domains.any_paused()
            && self.lifecycle.get().is_none_or(|lifecycle| {
                !lifecycle.retirements_pending()
                    && !lifecycle.layouts_pending()
                    && !lifecycle.host_pending()
            })
    }
    pub fn restore_checkpoint(&self, checkpoint: Checkpoint<C>, resume: bool) {
        let mut q = self.queues.lock().unwrap();
        let jobs = q.domains.restore(checkpoint, resume);
        for mut job in jobs {
            job.rearm_signals();
            if job.waiting.as_ref().is_some_and(|w| w.woken()) {
                job.waiting = None;
                job.work.trace.finish(&mut job.work.cpu, 0);
                job.stats.resumes += 1;
            }
            let pending = job.hardware_wait.as_ref().is_some_and(|w| !w.ready())
                || job.waiting.is_some()
                || job.io.as_ref().is_some_and(|io| !io.signal.ready())
                || job.gpu_pending.as_ref().is_some_and(|gpu| gpu.waiting());
            if pending && !job.ring_ready() {
                self.publish_deadline(job.wake_deadline());
                assert!(q.parked.insert(job.work.pid, job).is_none());
            } else {
                self.ready(&mut q, job);
            }
        }
        self.capture_paused(&mut q);
        self.notify(&mut q);
        drop(q);
        if let Some(starter) = self.starter.get() {
            for slot in self.additional_slots(self.active_slots(), starter.capacity()) {
                let _ = self.activate(slot);
            }
        }
    }
    pub fn wake(&self, ticket: &Arc<Ticket>) -> bool {
        let mut q = self.queues.lock().unwrap();
        if self.control.stopped() || !q.members.contains(&ticket.pid) {
            return false;
        }
        if q.parked.get(&ticket.pid).is_some_and(|job| {
            job.waiting
                .as_ref()
                .is_some_and(|w| w.matches_ticket(ticket))
        }) {
            let mut job = q.parked.remove(&ticket.pid).unwrap();
            job.work.trace.finish(&mut job.work.cpu, 0);
            job.waiting = None;
            job.stats.resumes += 1;
            self.ready(&mut q, job);
            self.notify(&mut q); // affinity can require a particular worker
        }
        // Wake may precede park. The ticket CAS is then consumed by park below.
        true
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn take(&self, slot: usize) -> Option<Box<Job<C>>> {
        self.take_with_engine(slot, &mut C::Engine::default())
    }
    pub fn take_with_engine(&self, slot: usize, engine: &mut C::Engine) -> Option<Box<Job<C>>> {
        let mut q = self.queues.lock().unwrap();
        let mut dispatched = false;
        loop {
            if self.control.stopped() {
                return None;
            }
            // Timer/sleeper events can make a dormant mm need its first View.
            // Publish those scopes before claiming source work, so one executor
            // cannot sleep with freshly prepared metadata work still unclaimed.
            if let Some(timers) = self.timers.get().filter(|t| t.due()) {
                // Signal callbacks may acquire this queue. Timer maintenance
                // runs on this existing executor, always outside its mutex.
                drop(q);
                timers.tick();
                q = self.queues.lock().unwrap();
            }
            let now = Instant::now();
            let expired: Vec<_> = q
                .parked
                .iter()
                .filter_map(|(&pid, job)| {
                    (job.wake_deadline().is_some_and(|d| d <= now)).then_some(pid)
                })
                .collect();
            for pid in expired {
                // The first dormant wake may already hold expired siblings of
                // the same mm in its preparation scope.
                let Some(mut job) = q.parked.remove(&pid) else {
                    continue;
                };
                if job
                    .waiting
                    .as_ref()
                    .and_then(WaitState::deadline)
                    .is_some_and(|d| d <= now)
                    && !matches!(job.waiting, Some(WaitState::Signal(_)))
                {
                    let waiting = job.waiting.take().unwrap();
                    job.work.trace.finish(&mut job.work.cpu, waiting.expire());
                }
                // I/O must perform a final resource check and scatter, even on
                // timeout. Keep its pending call and do not execute SVC twice.
                job.stats.resumes += 1;
                self.ready(&mut q, job);
            }
            if let Some(lifecycle) = self.lifecycle.get() {
                let retired = q.domains.take_retired();
                if !retired.is_empty() {
                    q.completing += 1;
                    drop(q);
                    lifecycle.retire_memory_domains(retired);
                    q = self.queues.lock().unwrap();
                    q.completing -= 1;
                    continue;
                }
                if lifecycle.host_ready() {
                    q.completing += 1;
                    drop(q);
                    if let Err(error) = lifecycle.pump_host(Some(self), slot) {
                        lifecycle.host_error(error);
                        self.fail();
                    }
                    q = self.queues.lock().unwrap();
                    q.completing -= 1;
                    continue;
                }
                if lifecycle.layouts_ready() {
                    q.completing += 1;
                    drop(q);
                    lifecycle.pump_layouts(self);
                    q = self.queues.lock().unwrap();
                    q.completing -= 1;
                    continue;
                }
                if lifecycle.retirement_ready() || q.retirement_notified {
                    q.completing += 1;
                    drop(q);
                    lifecycle.retire_ready(self);
                    q = self.queues.lock().unwrap();
                    q.completing -= 1;
                    continue;
                }
                if lifecycle.futex_ready() {
                    q.completing += 1;
                    drop(q);
                    lifecycle.activate_futexes(self);
                    q = self.queues.lock().unwrap();
                    q.completing -= 1;
                    continue;
                }
                if lifecycle.proc_ready() {
                    q.completing += 1;
                    drop(q);
                    lifecycle.activate_reads(self);
                    q = self.queues.lock().unwrap();
                    q.completing -= 1;
                    continue;
                }
                if lifecycle.memory_ready() {
                    q.completing += 1;
                    drop(q);
                    lifecycle.reclaim(self);
                    q = self.queues.lock().unwrap();
                    q.completing -= 1;
                    continue;
                }
                if let Some((checkpoint, subscriptions)) = Self::claim_checkpoint(&mut q, true) {
                    // The existing executor owns only this quiescent scope.
                    // No task/mm acquisition or operation holds the queue lock.
                    drop(q);
                    drop(subscriptions);
                    lifecycle.run(self, checkpoint, slot, engine);
                    q = self.queues.lock().unwrap();
                    continue;
                }
            }
            let deadline = q
                .parked
                .values()
                .filter_map(|j| j.wake_deadline())
                .chain(self.timers.get().and_then(|t| t.next_deadline()))
                .min();
            self.next_deadline.store(
                deadline.map_or(u64::MAX, |d| self.deadline_ticks(d)),
                Ordering::Relaxed,
            );
            let preferred = q
                .ready
                .iter()
                .position(|j| q.initial_slots.get(&j.work.pid) == Some(&slot));
            let available = (!self.host_pause.load(Ordering::Relaxed))
                .then(|| {
                    preferred.or_else(|| {
                        q.ready.iter().position(|j| {
                            j.affinity() & (1 << slot) != 0
                                && !q.initial_slots.contains_key(&j.work.pid)
                        })
                    })
                })
                .flatten();
            let external = q.parked.values().any(|j| {
                j.io.as_ref().is_some_and(|io| io.external_wait())
                    || j.uring.as_ref().is_some_and(|ring| ring.external())
            });
            if external && !q.host_waiting && (available.is_none() || !dispatched) {
                // A parked eventfd can acquire its first native producer on
                // another worker. Its resource metadata wakes us; initialize
                // the existing host wait hub here before arming it.
                let events = match trames_vfs::IoWake::host_events(self) {
                    Ok(Some(events)) => events,
                    Ok(None) => unreachable!("original epoch provides native events"),
                    Err(error) => {
                        let _ = self.host_error.set(Arc::new(error));
                        self.control.close(crate::execution_control::End::Failed);
                        self.notify(&mut q);
                        continue;
                    }
                };
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
                if let Err(error) = result {
                    let _ = self.host_error.set(Arc::new(error));
                    self.control.close(crate::execution_control::End::Failed);
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
                    snapshot.io_signals.proc_view.dispatched(slot);
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
                && q.completing == 0
                && q.ready.is_empty()
                && deadline.is_none()
                && !q.parked.values().any(|j| j.gpu_pending.is_some())
                && !external
                && !q.domains.any_paused()
                && self.lifecycle.get().is_none_or(|lifecycle| {
                    !lifecycle.retirements_pending()
                        && !lifecycle.layouts_pending()
                        && !lifecycle.host_pending()
                        && !lifecycle.futex_pending()
                })
            {
                if self.persistent {
                    if !q.idle_notified {
                        q.idle_notified = true;
                        if let Some(events) = &q.domains.events {
                            let _ = events.send(crate::workers::Event::<C>::Idle);
                        }
                    }
                } else {
                    self.control.handoff();
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
        if let Some(snapshot) = &job.work.syscalls {
            snapshot.io_signals.proc_view.waiting(waiting.is_some());
        }
        let mut q = self.queues.lock().unwrap();
        job.rearm_signals();
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
            if waiting.woken() {
                job.work.trace.finish(&mut job.work.cpu, 0);
                job.stats.resumes += 1;
                self.ready(&mut q, job);
            } else {
                job.waiting = Some(waiting);
                self.publish_deadline(job.wake_deadline());
                if job.ring_ready() {
                    self.ready(&mut q, job);
                } else {
                    assert!(q.parked.insert(pid, job).is_none());
                }
            }
        } else {
            job.stats.yields += 1;
            self.ready(&mut q, job);
        }
        self.notify(&mut q);
    }
    /// Source-task maintenance reuses the task's existing wait subscriptions.
    /// It cannot complete an unrelated syscall or rearm a hardware/GPU wait.
    pub fn park_maintenance(&self, mut job: Box<Job<C>>) {
        if let Some(snapshot) = &job.work.syscalls {
            snapshot.io_signals.proc_view.waiting(job.guest_waiting());
        }
        let mut q = self.queues.lock().unwrap();
        job.rearm_signals();
        q.running -= 1;
        q.domains.returned(job.work.pid);
        if q.domains.paused(job.work.pid) {
            q.domains.hold(job);
            q.domains.notify_ready();
        } else {
            if job.waiting.as_ref().is_some_and(WaitState::woken) {
                job.waiting = None;
                job.work.trace.finish(&mut job.work.cpu, 0);
            } else if job
                .waiting
                .as_ref()
                .and_then(WaitState::deadline)
                .is_some_and(|d| d <= Instant::now())
                && !matches!(job.waiting, Some(WaitState::Signal(_)))
            {
                let waiting = job.waiting.take().unwrap();
                job.work.trace.finish(&mut job.work.cpu, waiting.expire());
            }
            if job.ring_ready() || !job.guest_waiting() {
                self.ready(&mut q, job);
            } else {
                self.publish_deadline(job.wake_deadline());
                assert!(q.parked.insert(job.work.pid, job).is_none());
            }
        }
        self.notify(&mut q);
    }
    pub fn park_hardware(
        self: &Arc<Self>,
        mut job: Box<Job<C>>,
        wait: Arc<trames_memory::HardwareWait>,
    ) {
        if let Some(snapshot) = &job.work.syscalls {
            snapshot.io_signals.proc_view.waiting(true);
        }
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
        job.rearm_signals();
        q.running -= 1;
        q.domains.returned(pid);
        let ready = wait.ready();
        job.hardware_wait = Some(wait);
        if q.domains.paused(pid) {
            q.domains.hold(job);
            q.domains.notify_ready();
        } else if ready || job.ring_ready() {
            job.hardware_wait = None;
            self.ready(&mut q, job);
        } else {
            assert!(q.parked.insert(pid, job).is_none());
        }
        self.notify(&mut q);
    }
    pub fn park_io(&self, mut job: Box<Job<C>>, pending: trames_linux::PendingIo) {
        if let Some(snapshot) = &job.work.syscalls {
            snapshot.io_signals.proc_view.waiting(true);
        }
        let mut q = self.queues.lock().unwrap();
        job.rearm_signals();
        q.running -= 1;
        q.domains.returned(job.work.pid);
        job.stats.io_waits += 1;
        let ready = pending.signal.ready();
        job.io = Some(pending);
        if q.domains.paused(job.work.pid) {
            q.domains.hold(job);
            q.domains.notify_ready();
        } else if ready || job.ring_ready() {
            job.stats.resumes += 1;
            self.ready(&mut q, job);
        } else {
            self.publish_deadline(job.wake_deadline());
            assert!(q.parked.insert(job.work.pid, job).is_none());
        }
        self.notify(&mut q);
    }
    pub fn park_gpu(&self, mut job: Box<Job<C>>, pending: crate::gpu::Pending) {
        if let Some(snapshot) = &job.work.syscalls {
            snapshot.io_signals.proc_view.waiting(true);
        }
        let mut q = self.queues.lock().unwrap();
        job.rearm_signals();
        q.running -= 1;
        q.domains.returned(job.work.pid);
        job.stats.gpu.waits += 1;
        let ready = !pending.waiting();
        job.gpu_pending = Some(pending);
        self.publish_deadline(job.wake_deadline());
        if q.domains.paused(job.work.pid) {
            q.domains.hold(job);
            q.domains.notify_ready();
        } else if ready || job.ring_ready() {
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
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn await_io_park(&self, pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut q = self.queues.lock().unwrap();
        while !q.parked.get(&pid).is_some_and(|j| j.io.is_some()) {
            assert!(!self.control.stopped(), "cohort stopped before I/O park");
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "I/O did not park");
            q = self.changed.wait_timeout(q, left).unwrap().0;
        }
    }
    pub fn finish(&self, done: Done<C>) {
        let mut q = self.queues.lock().unwrap();
        q.running -= 1;
        q.domains.returned(done.pid);
        // A source exit can be the final active View of an already requested
        // mm checkpoint. Publish its quiescence without stopping other jobs.
        q.domains.notify_ready();
        let exited = done.thread_exit.is_some();
        q.finished.push(done);
        if exited && !q.retirement_notified {
            q.retirement_notified = true;
            if let Some(events) = q
                .domains
                .events
                .as_ref()
                .filter(|_| self.lifecycle.get().is_none())
            {
                let _ = events.send(crate::workers::Event::<C>::Retired);
            }
        }
        if !exited {
            self.control.handoff();
        }
        self.notify(&mut q);
        drop(q);
        if exited {
            if let Some(lifecycle) = self.lifecycle.get() {
                lifecycle.notify_retirement();
            }
        }
    }
    /// The complete CPU/metrics return once, without waiting for unrelated Views.
    pub fn take_retired(&self) -> Vec<Done<C>> {
        if self.lifecycle.get().is_some() {
            return Vec::new();
        }
        self.take_source_retired()
    }
    pub fn take_source_retired(&self) -> Vec<Done<C>> {
        let mut q = self.queues.lock().unwrap();
        let mut retired = Vec::new();
        let mut i = 0;
        while i < q.finished.len() {
            if q.finished[i].thread_exit.is_some() {
                let done = q.finished.swap_remove(i);
                assert!(q.members.remove(&done.pid));
                q.domains.retire(done.pid);
                retired.push(done);
            } else {
                i += 1;
            }
        }
        q.retirement_notified = false;
        retired
    }
    pub fn member_ids(&self) -> Vec<u32> {
        self.queues
            .lock()
            .unwrap()
            .members
            .iter()
            .copied()
            .collect()
    }
    pub fn contains(&self, pid: u32) -> bool {
        self.queues.lock().unwrap().members.contains(&pid)
    }
    pub fn memory_owned(&self, id: u64) -> bool {
        self.queues.lock().unwrap().domains.memory_owned(id)
    }
    pub fn contains_memory(&self, id: u64) -> bool {
        self.queues.lock().unwrap().domains.contains(id)
    }
    pub fn suspended_memory(&self, id: u64) -> bool {
        self.queues.lock().unwrap().domains.suspended(id)
    }
    pub fn source_lifecycle(&self) -> bool {
        self.lifecycle.get().is_some()
    }
    pub fn pause_memory(&self, id: u64) -> bool {
        let mut q = self.queues.lock().unwrap();
        if !q.domains.contains(id) {
            return false;
        }
        q.domains.pause_bytes(id);
        self.capture_paused(&mut q);
        self.notify(&mut q);
        true
    }
    /// All launched workers must have acknowledged stop before this call.
    pub fn drain(&self) -> Vec<Done<C>> {
        let mut q = self.queues.lock().unwrap();
        assert_eq!(q.running, 0);
        assert_eq!(
            q.completing, 0,
            "in-flight resource completion still owns a View"
        );
        let mut done = std::mem::take(&mut q.finished);
        q.retirement_notified = false;
        let mut jobs: Vec<_> = q.ready.drain(..).collect();
        jobs.extend(std::mem::take(&mut q.parked).into_values());
        let waits = std::mem::take(&mut q.custody_waits);
        let mut subscriptions = Vec::new();
        for wait in waits {
            q.domains.restore(wait.checkpoint, false);
            subscriptions.extend(wait._subscriptions);
        }
        jobs.extend(q.domains.drain());
        let retired = std::mem::take(&mut q.retired);
        drop(q);
        drop(subscriptions);
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

impl<C: Cpu> trames_kernel::timers::TimerWake for Epoch<C> {
    fn timers_changed(&self) {
        let mut q = self.queues.lock().unwrap();
        if !self.control.stopped() {
            self.notify(&mut q);
        }
    }
}

impl<C: Cpu> trames_vfs::IoWake for Epoch<C> {
    fn host_events(&self) -> std::io::Result<Option<Arc<trames_vfs::HostEvents>>> {
        match self
            .host_events
            .get_or_init(|| trames_vfs::HostEvents::new().map_err(Arc::new))
        {
            Ok(events) => Ok(Some(events.clone())),
            Err(error) => Err(error.raw_os_error().map_or_else(
                || std::io::Error::new(error.kind(), error.clone()),
                std::io::Error::from_raw_os_error,
            )),
        }
    }
    fn wake_io(&self, signal: &Arc<trames_vfs::IoSignal>) {
        let mut q = self.queues.lock().unwrap();
        if self.control.stopped() {
            return;
        }
        if self
            .lifecycle
            .get()
            .is_some_and(|lifecycle| lifecycle.memory_signal(signal))
        {
            // Reuse the existing scheduling hint when every slot is running.
            // One bounded CPU slice yields for resource maintenance; no new
            // instruction-path check, timer or polling task is introduced.
            self.next_deadline.store(0, Ordering::Relaxed);
            self.notify(&mut q);
            return;
        }
        if let Some(wait) = q
            .custody_waits
            .iter()
            .find(|wait| Arc::ptr_eq(&wait.signal, signal))
        {
            let source = q.domains.source_lifecycle
                && crate::process::lifecycle::eligible(
                    wait.checkpoint.jobs.iter().map(Box::as_ref),
                    wait.checkpoint.proc_reads,
                    wait.checkpoint.mm_only,
                    wait.checkpoint.source_retry,
                    wait.checkpoint.layout_only,
                );
            if let Some(events) = q.domains.events.as_ref().filter(|_| !source) {
                let _ = events.send(crate::workers::Event::VmReady);
            }
            self.notify(&mut q);
            return;
        }
        if q.parked.get(&signal.pid).is_some_and(|job| {
            matches!(&job.waiting, Some(WaitState::Custody(wait)) if Arc::ptr_eq(&wait.signal, signal)) || job.work
                .syscalls
                .as_ref()
                .and_then(|s| s.io_wake.as_ref())
                .is_some_and(|s| Arc::ptr_eq(s, signal))
                || job
                    .io
                    .as_ref()
                    .is_some_and(|io| Arc::ptr_eq(&io.signal, signal))
                || job
                    .gpu_pending
                    .as_ref()
                    .is_some_and(|gpu| Arc::ptr_eq(gpu.signal(), signal))
                || job
                    .uring
                    .as_ref()
                    .is_some_and(|ring| Arc::ptr_eq(&ring.signal, signal))
        }) {
            let mut job = q.parked.remove(&signal.pid).unwrap();
            job.stats.resumes += 1;
            self.ready(&mut q, job);
            self.notify(&mut q);
        }
        if q.ready.iter().any(|job| {
            job.work.pid == signal.pid
                && job
                    .work
                    .syscalls
                    .as_ref()
                    .and_then(|s| s.io_wake.as_ref())
                    .is_some_and(|s| Arc::ptr_eq(s, signal))
        }) {
            let mask = q
                .ready
                .iter()
                .find(|j| j.work.pid == signal.pid)
                .unwrap()
                .affinity();
            self.activate_for(mask);
            q.initial_slots.remove(&signal.pid);
            self.refresh_ready(&q);
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
    fn ready_affinity_starts_only_the_required_cold_cpu_without_an_owner_request() {
        for pause in [false, true] {
            let mut pool = crate::workers::Pool::<Cpu>::new(4);
            let epoch = Epoch::with_events(Arc::new(Control::new(1000)), pool.events(), true);
            epoch.bind_starter(pool.starter());
            epoch.pause_host(pause);
            let mut source = job(7, &epoch);
            source.affinity = 8;
            epoch.add(source);
            if pause {
                assert_eq!(epoch.active_slots(), 0);
                epoch.pause_host(false);
            }
            assert_eq!(epoch.active_slots(), 8);
            assert!(!epoch.activation_failed());
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                match pool
                    .event_timeout(until.saturating_duration_since(Instant::now()))
                    .unwrap()
                {
                    Some(crate::workers::Event::EpochStopped(3)) => break,
                    Some(crate::workers::Event::Idle | crate::workers::Event::Retired) => {
                        epoch.stop()
                    }
                    None => panic!("cold CPU did not finish"),
                    _ => panic!("unexpected owner request"),
                }
            }
            let returned = epoch.drain();
            assert_eq!(returned.len(), 1);
            assert_eq!(returned[0].worker, 3);
            assert_eq!(returned[0].pid, 7);
        }
    }
    #[test]
    fn host_pause_resume_reannounces_idle_after_ignored_paused_notification() {
        let (send, receive) = std::sync::mpsc::channel();
        let epoch = Epoch::with_events(Arc::new(Control::new(1000)), send, true);
        epoch.pause_host(true);
        let worker_epoch = epoch.clone();
        let worker = std::thread::spawn(move || assert!(worker_epoch.take(0).is_none()));
        assert!(matches!(
            receive.recv_timeout(Duration::from_secs(2)),
            Ok(crate::workers::Event::Idle)
        ));
        assert!(!epoch.idle());
        assert!(matches!(
            receive.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        epoch.pause_host(false);
        let resumed = receive.recv_timeout(Duration::from_millis(100));
        epoch.stop();
        worker.join().unwrap();
        assert!(
            matches!(resumed, Ok(crate::workers::Event::Idle)),
            "resume must reannounce a previously ignored idle state"
        );
        assert!(epoch.idle());
    }
    #[test]
    fn initially_parked_task_can_resume_while_its_old_cpu_is_occupied() {
        let epoch = Epoch::new(Arc::new(Control::new(1000)));
        let mut parent = job(1, &epoch);
        parent.affinity = 3;
        parent.waiting = Some(WaitState::Sleep {
            deadline: Instant::now() + Duration::from_millis(30),
            remaining: 0,
        });
        let mut producer = job(2, &epoch);
        producer.affinity = 3;
        epoch.add(parent);
        epoch.add(producer);
        epoch.assign(&[(1, 0), (2, 1)]);
        let producer = epoch.take(1).unwrap();
        let mut peer = job(3, &epoch);
        peer.affinity = 3;
        epoch.add(peer);
        let peer = epoch.take(0).unwrap();
        assert_eq!(peer.work.pid, 3);
        epoch.finish(producer.finish_retired(
            Some(SliceOutcome::Yield { instructions: 0 }),
            0,
            crate::worker_syscalls::Exit {
                status: 0,
                groups: Vec::new(),
            },
        ));
        let (send, receive) = std::sync::mpsc::channel();
        let worker = {
            let epoch = epoch.clone();
            std::thread::spawn(move || {
                let result = epoch.take(1).map(|job| {
                    let pid = job.work.pid;
                    epoch.finish(job.finish(Some(SliceOutcome::Yield { instructions: 0 }), 0));
                    pid
                });
                send.send(result).unwrap();
            })
        };
        let result = receive.recv_timeout(Duration::from_secs(1));
        epoch.stop();
        worker.join().unwrap();
        epoch.finish(peer.finish(Some(SliceOutcome::Yield { instructions: 0 }), 0));
        let _ = epoch.drain();
        assert_eq!(result, Ok(Some(1)));
    }
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
                task: None,
                audio: None,
                gpu: None,
                pid,
                cpu: trames_cpu::Cpu::default(),
                memory: Some(Box::new(
                    memory.parallel_view(&mut Default::default()).unwrap(),
                )),
                control: epoch.control.clone(),
                trace: Default::default(),
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
    #[test]
    fn late_native_source_backend_failure_stops_the_idle_executor_without_owner_retry() {
        let mut v = trames_vfs::Vfs::default();
        let fd = v.eventfd(0, 0).unwrap();
        let direct = trames_linux::DirectSyscalls::new(v.direct_descriptors());
        let epoch = Epoch::new(Arc::new(Control::new(1000)));
        epoch.reject_host_events(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "original idle backend failure",
        ));
        epoch.add(job(1, &epoch));
        let mut running = epoch.take(0).unwrap();
        let Some(trames_linux::IoAttempt::Blocked(wait)) = direct.start(
            63,
            [fd as u64, 0x1000, 8, 0, 0, 0],
            running.work.memory.as_deref_mut().unwrap(),
            1,
            &epoch.io_target,
            None,
        ) else {
            panic!("an ordinary eventfd requires no native backend");
        };
        epoch.park_io(running, wait);
        let native = v.native_events().event(fd).unwrap();
        // Publication may first wake the original task to recheck its level.
        // No bytes were produced. Its next real native idle wait must retain
        // the backend error rather than returning a guest/owner checkpoint.
        for _ in 0..2 {
            let Some(mut running) = epoch.take(0) else {
                break;
            };
            let wait = running.io.take().unwrap();
            let trames_linux::IoAttempt::Blocked(wait) =
                direct.resume(wait, running.work.memory.as_deref_mut().unwrap())
            else {
                panic!("no eventfd bytes were produced");
            };
            epoch.park_io(running, wait);
        }
        assert!(epoch.control.stopped());
        let error = epoch.host_error.get().unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("original idle backend failure"));
        let done = epoch.drain();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].syscalls, 0);
        assert_eq!(done[0].serviced_syscalls, 0);
        drop(native);
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
            Some(WaitState::Futex {
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
            Some(WaitState::Futex {
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
    fn sleep_releases_its_slot_and_retains_deadline_and_remaining_on_stop() {
        let epoch = Epoch::new(Arc::new(Control::new(100)));
        let deadline = Instant::now() + Duration::from_millis(2);
        let mut sleeper = job(1, &epoch);
        sleeper.waiting = Some(WaitState::Sleep {
            deadline,
            remaining: 0x1080,
        });
        epoch.add(sleeper);
        epoch.add(job(2, &epoch));
        let peer = epoch.take(0).unwrap();
        assert_eq!(peer.work.pid, 2);
        epoch.park(
            peer,
            Some(WaitState::Sleep {
                deadline: deadline + Duration::from_secs(3600),
                remaining: 0,
            }),
        );
        let sleeper = epoch.take(0).unwrap();
        assert!(Instant::now() >= deadline);
        assert_eq!(
            sleeper.work.cpu.x(0),
            0,
            "sleep expiry is success, not ETIMEDOUT"
        );
        assert!(sleeper.waiting.is_none());
        epoch.park(
            sleeper,
            Some(WaitState::Sleep {
                deadline,
                remaining: 0x1080,
            }),
        );
        epoch.stop();
        let done = epoch.drain();
        assert!(done.iter().any(|d| matches!(d.waiting, Some(WaitState::Sleep { deadline: d, remaining: 0x1080 }) if d == deadline)));
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
        task.waiting = Some(WaitState::Futex {
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
        task.waiting = Some(WaitState::Futex {
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
