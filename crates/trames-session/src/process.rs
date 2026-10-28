// SPDX-License-Identifier: GPL-3.0-or-later
//! Virtual processes and continuous parallel CPU execution. Guest fork/exec stay virtual.
use super::{Exit, Runtime, RuntimeError};
use crate::terminal::Terminal;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};
use trames_engine::{Cpu, SliceOutcome};
use trames_linux::{GuestOutput, Linux, OutputFd, SyscallOutcome, TerminalEvent, MAX_WRITE};
use trames_memory::{Access, Memory};
use trames_vfs::capabilities;
use trames_vfs::{Errno, FdKind, AT_FDCWD, MAX_FDS, O_NONBLOCK};

#[cfg(all(test, trames_interpreter_conformance))]
const MAX_PROCESSES: usize = trames_vfs::MAX_TASKS;
#[cfg(all(test, trames_interpreter_conformance))]
const TOTAL_MAPPED_LIMIT: usize = 1024 * 1024 * 1024;
use trames_kernel::scheduling::assign_cpus;
pub(crate) use trames_kernel::signal::UNBLOCKABLE;
#[path = "process_caps.rs"]
mod caps;
#[path = "process_compat.rs"]
mod compat;
#[path = "process_events.rs"]
mod events;
#[path = "process_pid.rs"]
mod pid_namespace;
#[path = "process_signals.rs"]
mod signals;
use trames_kernel::signal::AltStack;
#[path = "process_scheduling.rs"]
mod scheduling;
#[path = "process_seccomp.rs"]
pub(crate) mod seccomp;
#[path = "process_service.rs"]
mod service;
#[path = "process_vm.rs"]
mod vm;
#[cfg(all(test, trames_interpreter_conformance))]
use crate::signal_actions::Action;
use service::DiskEpoch;

use trames_kernel::signal::{Info, Signals};
#[derive(Clone)]
enum State {
    Ready,
    Gpu {
        retired: bool,
        peer_instructions: u64,
        job: u64,
        pc: u64,
        operation: u64,
        instructions: u64,
        began: Instant,
    },
    Blocked(u32, [u64; 6]),
    Sleep(Instant, u64),
    Suspend(u64),
    Vfork(u32),
    Futex {
        wait: std::sync::Arc<crate::futex::Wait>,
        deadline: Option<Instant>,
    },
    Sigwait {
        mask: u64,
        info: u64,
        deadline: Option<Instant>,
    },
    Stopped,
    Zombie(i32),
}
pub(crate) struct Process<C: Cpu> {
    cpu: C,
    affinity: u64,
    last_cpu: usize,
    nice: i32,
    scheduler: u32,
    memory: Memory,
    linux: Linux,
    parent: u32,
    parent_thread: u32,
    pdeath_signal: u32,
    group: u32,
    session: u32,
    state: State,
    signals: Signals,
    wait_event: Option<i32>,
    poll_deadline: Option<Instant>,
    socket_deadline: Option<Instant>,
    poll_mask: Option<u64>,
    uring_wait: Option<(u32, Rc<trames_vfs::Uring>, Option<Instant>)>,
    flock_wait: Option<(trames_vfs::FlockRequest, Option<trames_vfs::RetainedFd>)>,
    byte_wait: Option<trames_linux::PendingIo>,
    retained_byte: Option<trames_linux::RetainedByte>,
    retained_poll: Option<trames_linux::RetainedPoll>,
    retained_select: Option<trames_linux::RetainedSelect>,
    pending_open: Option<u32>,
    stopped_state: Option<Box<State>>,
    auto_reap: bool,
    tgid: u32,
    started: Instant,
    cpu_time: Duration,
    vm_id: u64,
    rekey: Option<u32>,
    subreaper: bool,
    membarrier_registered: Rc<Cell<bool>>,
    file_size_limit: Rc<Cell<(u64, u64)>>,
    oom: Arc<trames_vfs::OomTask>,
    seccomp: seccomp::Seccomp,
}
impl<C: Cpu> Process<C> {
    fn shares_wait_resources(&self, fds: &trames_vfs::DirectFds) -> bool {
        self.retained_poll
            .as_ref()
            .is_some_and(|poll| poll.shares_resources(fds))
            || self
                .retained_byte
                .as_ref()
                .is_some_and(|byte| byte.shares_resources(fds))
            || self
                .byte_wait
                .as_ref()
                .and_then(|wait| wait.retained_byte.as_ref())
                .is_some_and(|byte| byte.shares_resources(fds))
    }
    /// Only unfiltered, untraced already-blocked calls can be adopted without
    /// another authority evaluation. New calls use Snapshot::admit on-worker.
    fn worker_ring_event_wait(&self, id: u32) -> bool {
        let owner = self.memory.instruction_identity().0;
        if let Some((_, ring, deadline)) = &self.uring_wait {
            return trames_linux::UringEpoch::has_event_wait(ring, owner, id, *deadline);
        }
        if let Some(poll) = &self.retained_poll {
            return poll.owner_controls().into_iter().any(|(fd, original)| {
                self.linux.vfs.matches_open_description(fd, &original)
                    && self.linux.vfs.uring(fd).is_ok_and(|ring| {
                        trames_linux::UringEpoch::has_event_wait(&ring, owner, id, None)
                    })
            });
        }
        if let State::Blocked(number, args) = self.state {
            return trames_linux::UringEpoch::poll_rings(
                &self.linux.vfs,
                number,
                args,
                &self.memory,
                id,
            )
            .is_some_and(|rings| {
                rings
                    .iter()
                    .any(|ring| trames_linux::UringEpoch::has_event_wait(ring, owner, id, None))
            });
        }
        false
    }

    fn worker_io_candidate(&self, id: u32) -> bool {
        if let Some(poll) = &self.retained_poll {
            return !self.linux.trace
                && self.seccomp.mode() == 0
                && poll.supports_worker(&self.linux.vfs);
        }
        if self.retained_byte.is_some() || self.byte_wait.is_some() {
            return !self.linux.trace && self.seccomp.mode() == 0;
        }
        if matches!(self.state, State::Blocked(116, a) if a[0] as u32 == 2) {
            return !self.linux.trace && self.seccomp.mode() == 0;
        }
        if matches!(self.state, State::Blocked(32, _)) {
            return !self.linux.trace && self.seccomp.mode() == 0 && self.flock_wait.is_some();
        }
        if let State::Blocked(426, a) = self.state {
            return !self.linux.trace
                && self.seccomp.mode() == 0
                && a[3] & !9 == 0
                && self.uring_wait.as_ref().is_some_and(|(_, ring, _)| {
                    self.linux
                        .vfs
                        .uring(a[0] as u32)
                        .is_ok_and(|current| Rc::ptr_eq(&current, ring))
                        && trames_linux::UringEpoch::can_adopt(ring)
                });
        }
        if let State::Blocked(number @ (22 | 73 | 441), args) = self.state {
            if !self.linux.trace
                && self.seccomp.mode() == 0
                && trames_linux::UringEpoch::poll_rings(
                    &self.linux.vfs,
                    number,
                    args,
                    &self.memory,
                    id,
                )
                .is_some()
            {
                return true;
            }
        }
        let State::Blocked(number @ (22 | 63..=66 | 73 | 206 | 207 | 211 | 212 | 441), args) =
            self.state
        else {
            return false;
        };
        if self.linux.trace || self.seccomp.mode() != 0 {
            return false;
        }
        // Most retained waits are poll/epoll, pipes or Unix sockets. Their
        // eligibility never depends on scanning every native TCP socket.
        trames_linux::DirectSyscalls::new(self.linux.vfs.direct_descriptors())
            .supports_call(number, args)
            || matches!(number, 63..=66) && self.linux.vfs.direct_tcp_fd(args[0] as u32).is_some()
    }
    fn byte_wait_deadline(&self) -> Option<Instant> {
        if matches!(self.state, State::Blocked(..)) {
            self.byte_wait
                .as_ref()
                .and_then(|wait| wait.wake_deadline())
        } else {
            None
        }
    }

    /// Preserve the complete OFD before owner-side close/dup can resume.
    fn retain_worker_flock(&mut self, call: Option<&crate::run_queue::IoCall>) {
        if let Some(request) = call.and_then(|call| call.flock.as_ref()) {
            if request.retains_file() {
                // Already accepted on the executing worker. Numeric membership
                // may have changed before this join, so never look it up again.
                self.flock_wait = Some((request.clone(), None));
                return;
            }
            match self.flock_wait.as_mut() {
                Some((saved, _)) if saved.same_owner(request) => {
                    // The previous wait may have completed and this same OFD
                    // started a different lock operation before the join.
                    // Reuse the full file lease, but always update the request.
                    *saved = request.clone();
                }
                _ => {
                    // Every worker has stopped; no cold close/dup has run yet.
                    // Retain the original OFD before table mutation becomes legal.
                    let call = call.unwrap();
                    let (current, file) = self
                        .linux
                        .vfs
                        .retain_flock(call.args[0] as u32, call.args[1] as u32)
                        .expect("frozen flock descriptor");
                    assert!(current.same_owner(request));
                    self.flock_wait = Some((request.clone(), file));
                }
            }
        } else {
            self.flock_wait = None;
        }
    }

    fn worker_gpu_candidate(&self) -> bool {
        matches!(self.state, State::Gpu { retired: true, .. })
    }

    fn frozen(&self, pid: u32) -> bool {
        self.linux.vfs.cgroup_frozen(pid) && self.pending_bits() & (1 << 8) == 0
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    fn fork(&self) -> Box<Self> {
        self.fork_state(self.memory.clone(), false, false, false)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    fn fork_with_memory(&self, memory: Memory) -> Box<Self> {
        self.fork_state(memory, true, true, true)
    }
    fn fork_state(
        &self,
        memory: Memory,
        shared_files: bool,
        shared_fs: bool,
        shared_actions: bool,
    ) -> Box<Self> {
        // Bind allocation metadata to actual Memory identity, including test
        // and embedding clones; a copied address space must not share a cursor.
        let shared_vm = memory.coordinator_ownership().0 == self.memory.coordinator_ownership().0;
        let linux = self
            .linux
            .clone_with_resources(shared_files, shared_fs, shared_vm);
        Box::new(Self {
            cpu: self.cpu.clone(),
            affinity: self.affinity,
            last_cpu: self.last_cpu,
            nice: self.nice,
            scheduler: self.scheduler,
            memory,
            linux,
            parent: 0,
            parent_thread: 0,
            pdeath_signal: 0,
            group: self.group,
            session: self.session,
            state: State::Ready,
            signals: self.signals.fork(shared_actions),
            wait_event: None,
            poll_deadline: None,
            socket_deadline: None,
            poll_mask: None,
            uring_wait: None,
            flock_wait: None,
            byte_wait: None,
            retained_byte: None,
            retained_poll: None,
            retained_select: None,
            pending_open: None,
            stopped_state: None,
            auto_reap: false,
            tgid: self.tgid,
            started: Instant::now(),
            cpu_time: Duration::ZERO,
            vm_id: self.vm_id,
            rekey: None,
            subreaper: false,
            membarrier_registered: Rc::new(Cell::new(self.membarrier_registered.get())),
            file_size_limit: Rc::new(Cell::new(self.file_size_limit.get())),
            oom: Arc::new(self.oom.fork()),
            seccomp: self.seccomp.clone(),
        })
    }
}
struct ProcMaps {
    identity: (u64, u64),
    bytes: Vec<u8>,
}
// Joined shared resources notify through guest execution or a worker. Timers
// also resume at the accepted wait's deadline. Host-backed resources retain
// their host event path.
struct JoinedByteWake;
impl trames_vfs::IoWake for JoinedByteWake {
    fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {}
}
pub(crate) struct Kernel<C: Cpu> {
    byte_target: Arc<dyn trames_vfs::IoWake>,
    memory_limits: super::MemoryLimits,
    cpu_count: usize,
    task_limit: usize,
    workers: crate::workers::Pool<C>,
    engine: C::Engine,
    backend_error: Option<String>,
    futexes: crate::futex::Futexes,
    futex_ready: Vec<std::sync::Arc<crate::futex::Ticket>>,
    parallel_memory: trames_memory::parallel::Registry,
    parallel_rounds: u64,
    vm_checkpoint_groups: u64,
    vm_checkpoint_spaces: u64,
    vm_local_syscalls: u64,
    persistent_control_checks: u64,
    worker_slices: u64,
    worker_chunks: u64,
    worker_syscalls: u64,
    worker_direct_syscalls: u64,
    worker_futex_wakes: u64,
    worker_futex_woken: u64,
    worker_futex_requeues: u64,
    worker_futex_waits: u64,
    worker_task_resumes: u64,
    worker_task_yields: u64,
    worker_io_waits: u64,
    worker_service_waits: u64,
    worker_file_syscalls: u64,
    worker_socket_syscalls: u64,
    worker_timer_syscalls: u64,
    worker_poll_syscalls: u64,
    worker_uring_syscalls: u64,
    worker_fd_syscalls: u64,
    worker_gpu_calls: u64,
    worker_gpu_waits: u64,
    service_requests: u64,
    disk_reads: u64,
    peak_disk_reads: usize,
    disk_read_bytes: u64,
    service_write_buffer: Vec<u8>,
    serviced_syscalls: u64,
    service_wait: Duration,
    parallel_memory_time: Duration,
    parallel_dispatch_time: Duration,
    parallel_stop_time: Duration,
    next_parallel_pid: u32,
    per_cpu: Vec<Duration>,
    // Scheduler passes remove/reinsert tasks while invoking Kernel methods.
    // Keep the large CPU/Linux/VFS state stationary: B-tree node compaction
    // must move only pointers, including when most guest threads are asleep.
    processes: BTreeMap<u32, Box<Process<C>>>,
    next_pid: u32,
    terminal: Option<Terminal>,
    started: Instant,
    instructions: u64,
    boot_time: u64,
    context_switches: u64,
    decode_lookups: u64,
    instructions_decoded: u64,
    decode_misses: u64,
    cpu_total: Duration,
    syscall_total: Duration,
    syscalls: u64,
    proc_refreshes: u64,
    proc_maps: RefCell<BTreeMap<u64, ProcMaps>>,
    profile_syscalls: bool,
    idle: Duration,
    load: [f64; 3],
    load_sample: Instant,
    next_resource: u64,
    timers: BTreeMap<i32, events::Timer>,
    next_timer: i32,
    native: trames_accel::native::Registry,
    gpu: RefCell<BTreeMap<u64, trames_vulkan::Context>>,
    gpu_budget: trames_vulkan::Budget,
    gpu_display: trames_vulkan::Display,
    gpu_compiles: u64,
    gpu_peak_pending: usize,
    gpu_peer_instructions: u64,
    gpu_wait_time: Duration,
    gpu_transfers: trames_vulkan::TransferMetrics,
}
fn error(e: Errno) -> u64 {
    0u64.wrapping_sub(e.0 as u64)
}
fn accelerated<C: Cpu>(p: &Process<C>, key: u64, profile: u64) -> bool {
    p.linux
        .auxiliary
        .chunks_exact(16)
        .any(|pair| pair[..8] == key.to_le_bytes() && pair[8..] == profile.to_le_bytes())
}
fn args<C: Cpu>(cpu: &C) -> [u64; 6] {
    std::array::from_fn(|i| cpu.x(i))
}
fn put_args<C: Cpu>(cpu: &mut C, a: [u64; 6]) {
    for (i, value) in a.into_iter().enumerate() {
        cpu.set_x(i, value);
    }
}
fn read_u32(m: &Memory, a: u64) -> Result<u32, Errno> {
    let mut b = [0; 4];
    m.read(a, &mut b).map_err(|_| Errno(14))?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64(m: &Memory, a: u64) -> Result<u64, Errno> {
    m.read_u64(a).map_err(|_| Errno(14))
}
fn write_u64(m: &mut Memory, a: u64, v: u64) -> Result<(), Errno> {
    m.write(a, &v.to_le_bytes()).map_err(|_| Errno(14))
}
fn write_u32(m: &mut Memory, a: u64, v: u32) -> Result<(), Errno> {
    m.write(a, &v.to_le_bytes()).map_err(|_| Errno(14))
}
fn strings(m: &Memory, address: u64) -> Result<Vec<Vec<u8>>, Errno> {
    if address == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut total = 0;
    for i in 0..4096 {
        let a = read_u64(m, address.checked_add(i * 8).ok_or(Errno(14))?)?;
        if a == 0 {
            return Ok(out);
        }
        let value = m.read_c_string(a, 65536).map_err(|_| Errno(14))?;
        total += value.len() + 1;
        if total > 65536 {
            return Err(Errno(7));
        }
        out.push(value);
    }
    Err(Errno(7))
}
impl<C: Cpu> Kernel<C> {
    fn native_call(
        &mut self,
        p: &mut Process<C>,
        pc: u64,
        module: u64,
        function: u64,
        a: [u64; 3],
    ) -> Result<Option<trames_accel::native::Return>, trames_accel::native::Error> {
        if module != trames_vulkan::PROFILE {
            return self
                .native
                .invoke(&mut p.memory, pc, module, function, a)
                .map(Some);
        }
        if !accelerated(p, trames_vulkan::AUXV_KEY, trames_vulkan::PROFILE) {
            return Err(trames_accel::native::Error::InvalidEntry);
        }
        self.native
            .authorize_stateful(&p.memory, pc, module, function)?;
        let backend = self.gpu_context(p);
        let authenticated = if matches!(a[0], 110 | 111) && a[2] == 128 {
            let address = a[1]
                .checked_add(8)
                .ok_or(trames_accel::native::Error::InvalidEntry)?;
            let fd = p
                .memory
                .read_u64(address)
                .map_err(trames_accel::native::Error::Memory)?;
            u32::try_from(fd)
                .ok()
                .and_then(|fd| p.linux.vfs.wayland_connection(fd).ok())
        } else {
            None
        };
        let (value, transfers) = backend.invoke(&mut p.memory, a[0], a[1], a[2], authenticated);
        self.gpu_transfers.upload_bytes += transfers.upload_bytes;
        self.gpu_transfers.download_bytes += transfers.download_bytes;
        self.gpu_transfers.direct_bytes += transfers.direct_bytes;
        self.gpu_transfers.buffered_bytes += transfers.buffered_bytes;
        let value = value.map_err(trames_accel::native::Error::Memory)?;
        let value = match value {
            trames_vulkan::Invocation::Complete(value) => value,
            trames_vulkan::Invocation::Pending(job) => {
                self.gpu_compiles += 1;
                let pending = 1 + self
                    .processes
                    .values()
                    .filter(|other| matches!(other.state, State::Gpu { .. }))
                    .count();
                self.gpu_peak_pending = self.gpu_peak_pending.max(pending);
                p.state = State::Gpu {
                    retired: false,
                    peer_instructions: 0,
                    job,
                    pc,
                    operation: a[0],
                    instructions: self.instructions,
                    began: Instant::now(),
                };
                return Ok(None);
            }
        };
        if (value as i64) < 0 {
            p.linux.vfs.log(
                4,
                &format!(
                    "pid={} Vulkan op={} result={} pc={pc:#x} comm={:?}",
                    p.tgid,
                    a[0],
                    value as i64,
                    String::from_utf8_lossy(&p.linux.command_name)
                ),
            );
        }
        Ok(Some(trames_accel::native::Return {
            value,
            fallback: false,
        }))
    }
    fn gpu_context(&self, p: &Process<C>) -> trames_vulkan::Context {
        self.gpu
            .borrow_mut()
            .entry(p.vm_id)
            .or_insert_with(|| {
                trames_vulkan::Context::new(
                    trames_vulkan::Backend::with_budget(self.gpu_budget.clone())
                        .with_display(self.gpu_display.clone())
                        .with_wayland(p.linux.vfs.wayland_server()),
                )
            })
            .clone()
    }
    fn resume_gpu(&mut self, pid: u32, p: &mut Process<C>) -> bool {
        let State::Gpu {
            retired,
            peer_instructions,
            job,
            pc,
            operation,
            instructions,
            began,
        } = p.state
        else {
            return false;
        };
        let result = self
            .gpu
            .borrow_mut()
            .get_mut(&p.vm_id)
            .map_or(Ok(Some((-4i64) as u64)), |backend| {
                backend.poll(&mut p.memory, job)
            });
        if matches!(result, Ok(None)) {
            return false;
        }
        self.gpu_peer_instructions +=
            peer_instructions + self.instructions.saturating_sub(instructions);
        self.gpu_wait_time += began.elapsed();
        p.state = State::Ready;
        match result {
            Ok(Some(value)) => {
                if (value as i64) < 0 {
                    p.linux.vfs.log(
                        4,
                        &format!(
                            "pid={} Vulkan op={operation} result={} pc={pc:#x} comm={:?}",
                            p.tgid,
                            value as i64,
                            String::from_utf8_lossy(&p.linux.command_name)
                        ),
                    );
                }
                p.cpu.set_x(0, value);
                p.cpu.set_x(1, 0);
                p.cpu.set_pc(pc + 4);
                if !retired {
                    self.instructions += 1;
                }
            }
            Err(error) => {
                self.synchronous_fault(pid, p, &trames_engine::CpuFault::Memory { pc, error })
            }
            Ok(None) => unreachable!(),
        }
        true
    }
    fn resource_id(&mut self) -> u64 {
        let id = self.next_resource;
        self.next_resource += 1;
        id
    }
    fn other_memory(&self, vm_id: u64) -> usize {
        let mut spaces = BTreeMap::new();
        for p in self
            .processes
            .values()
            .filter(|p| p.vm_id != vm_id && !matches!(p.state, State::Zombie(_)))
        {
            spaces.entry(p.vm_id).or_insert(p.memory.resident_bytes());
        }
        spaces.values().sum()
    }
    fn control(&mut self, io: &mut impl GuestOutput) -> Result<(), RuntimeError> {
        let Some(root) = self.processes.get_mut(&1) else {
            return Ok(());
        };
        let result = io.control(&mut root.linux.vfs);
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err(RuntimeError::Cancelled),
            Err(_) => Err(RuntimeError::Arguments("host session control failed")),
        }
    }
    fn process_maps(&self, p: &Process<C>) -> Vec<u8> {
        // Mapping edits (including PROT_NONE reservations) advance the code
        // generation. Ordinary data stores do not. Fork/exec have a new space
        // identity; shared VM wrappers report their underlying owner's key.
        // Backing byte/EOF epochs do not change the displayed mapping ranges.
        let (space, generation, _) = p.memory.instruction_identity();
        let identity = (space, generation);
        let mut cache = self.proc_maps.borrow_mut();
        if let Some(maps) = cache.get(&space).filter(|maps| maps.identity == identity) {
            return maps.bytes.clone();
        }
        let mut maps = String::new();
        for (start, end, access) in p.memory.regions() {
            use std::fmt::Write;
            let _ = writeln!(
                maps,
                "{start:012x}-{end:012x} {}{}{}p 00000000 00:00 0",
                if access.read { 'r' } else { '-' },
                if access.write { 'w' } else { '-' },
                if access.execute { 'x' } else { '-' }
            );
            if maps.len() >= 1024 * 1024 {
                break;
            }
        }
        let maps = maps.into_bytes();
        cache.insert(
            space,
            ProcMaps {
                identity,
                bytes: maps.clone(),
            },
        );
        maps
    }
    fn process_info(&self, pid: u32, p: &Process<C>) -> trames_vfs::ProcessInfo {
        let maps = self.process_maps(p);
        let arguments = p
            .linux
            .argument_pointers
            .iter()
            .enumerate()
            .map(|(i, pointer)| {
                p.memory
                    .read_c_string(
                        *pointer,
                        p.linux.arguments.get(i).map_or(65536, |a| a.len() + 1),
                    )
                    .unwrap_or_else(|_| p.linux.arguments.get(i).cloned().unwrap_or_default())
            })
            .collect();
        let (ignored, caught) = p.signals.actions.masks();
        trames_vfs::ProcessInfo {
            pid,
            tgid: p.tgid,
            parent: p.parent,
            group: p.group,
            session: p.session,
            state: match p.state {
                State::Ready => 'R',
                State::Stopped => 'T',
                State::Zombie(_) => 'Z',
                _ => 'S',
            },
            credentials: p.linux.vfs.credentials.clone(),
            namespaces: p.linux.vfs.namespace_snapshot(),
            namespace_ids: [p.tgid, pid, p.group, p.session]
                .map(|id| p.linux.vfs.pid_namespace().hierarchy(id)),
            command: p.linux.command_name.clone(),
            cgroup: p.linux.vfs.cgroup_path(pid),
            nondumpable: p.linux.vfs.dumpable() != 1,
            seccomp: p.seccomp.mode(),
            seccomp_filters: p.seccomp.count(),
            arguments,
            environment: p.linux.environment.clone(),
            executable: p.linux.executable_file.as_ref().map_or_else(
                || p.linux.executable_path.clone(),
                |file| p.linux.vfs.executable_display(file),
            ),
            executable_file: p.linux.executable_file.as_ref().map(Rc::downgrade),
            cwd: p.linux.vfs.cwd().unwrap_or_else(|_| b"/".to_vec()),
            mapped_bytes: p.memory.resident_bytes(),
            virtual_bytes: p.memory.virtual_bytes(),
            maps,
            affinity: p.affinity,
            processor: p.last_cpu as u32,
            nice: p.nice,
            scheduler: p.scheduler,
            user_ticks: (p.cpu_time.as_millis() / 10) as u64,
            start_ticks: (p
                .started
                .saturating_duration_since(self.started)
                .as_millis()
                / 10) as u64,
            terminal: p.linux.vfs.controlling_terminal.is_some(),
            terminal_number: p.linux.vfs.controlling_terminal.unwrap_or(0),
            fds: p.linux.vfs.fd_snapshot(),
            auxiliary: p.linux.auxiliary.clone(),
            file_size_limits: Some(p.file_size_limit.get()),
            oom: Arc::downgrade(&p.oom),
            pending: p.signals.pending.bits(),
            shared_pending: p.signals.shared_pending.borrow().bits(),
            blocked: p.signals.mask,
            ignored,
            caught,
        }
    }
    fn refresh_proc(&self, pid: u32, p: &mut Process<C>) {
        // Bound cached bytes by the current memory-owner set, even after repeated
        // fork/exec. Never cache fd paths, credentials, names, argv bytes or
        // other mutable process metadata under a mapping-generation key.
        let live: std::collections::BTreeSet<_> = self
            .processes
            .values()
            .map(|p| p.memory.instruction_identity().0)
            .chain(std::iter::once(p.memory.instruction_identity().0))
            .collect();
        self.proc_maps
            .borrow_mut()
            .retain(|vm, _| live.contains(vm));
        let mut processes: Vec<_> = self
            .processes
            .iter()
            .map(|(&id, other)| self.process_info(id, other))
            .collect();
        processes.push(self.process_info(pid, p));
        p.linux.vfs.set_runtime_info(
            pid,
            trames_vfs::RuntimeInfo {
                cpu_count: self.cpu_count,
                task_limit: self.task_limit,
                per_cpu_ticks: self
                    .per_cpu
                    .iter()
                    .map(|t| (t.as_millis() / 10) as u64)
                    .collect(),
                cpu_features: C::feature_names(),
                processes,
                uptime: self.started.elapsed(),
                boot_time: self.boot_time,
                context_switches: self.context_switches,
                cpu_user_ticks: (self.cpu_total.as_millis() / 10) as u64,
                idle: self.idle,
                memory_limit: self.memory_limits.total,
                load: self.load,
                processes_created: self.next_pid - 1,
                used_memory: self.other_memory(p.vm_id) + p.memory.resident_bytes(),
            },
        );
    }
    fn notify(&mut self, parent: u32, child: u32, uid: u32, status: i32, code: i32) {
        if let Some(p) = self.processes.get_mut(&parent) {
            let action = p.signals.actions.get(17);
            if action.handler == 1 || (matches!(code, 5 | 6) && action.flags & 1 != 0) {
                return;
            }
            let _ = p.signals.shared_pending.borrow_mut().enqueue(
                17,
                Info {
                    sender: child,
                    uid,
                    status,
                    code,
                    timer: None,
                    fault: None,
                },
            );
        }
    }
    fn close_exit_files(&self, p: &mut Process<C>) {
        p.linux.executable_file = None;
        if !self
            .processes
            .values()
            .any(|other| other.vm_id == p.vm_id && !matches!(other.state, State::Zombie(_)))
        {
            self.gpu.borrow_mut().remove(&p.vm_id);
        }
        p.linux.vfs.set_lock_owner(p.tgid);
        let live = |t: &&Process<C>| !matches!(t.state, State::Zombie(_));
        if !self
            .processes
            .values()
            .map(Box::as_ref)
            .filter(live)
            .any(|t| t.tgid == p.tgid)
        {
            p.linux.vfs.release_process_locks();
        }
        p.linux.vfs.release_descriptors();
    }
    fn exit_one(&mut self, pid: u32, p: &mut Process<C>, status: i32) {
        p.linux.cancel_uring(&mut p.memory, pid);
        p.uring_wait = None;
        p.flock_wait = None;
        p.byte_wait = None;
        p.retained_byte = None;
        p.retained_poll = None;
        p.retained_select = None;
        self.parent_thread_exited(pid, p, None);
        p.linux.vfs.cgroup_exit(pid);
        let state = if matches!(p.state, State::Stopped) {
            p.stopped_state.as_deref()
        } else {
            Some(&p.state)
        };
        if let Some(State::Gpu { job, .. }) = state {
            if let Some(backend) = self.gpu.borrow_mut().get_mut(&p.vm_id) {
                backend.abandon(*job);
            }
        }
        // Release active/stopped wait registrations before clear_tid wakes.
        // A zombie must not stay eligible through a saved stopped State.
        p.stopped_state = None;
        p.state = State::Zombie(status);
        let address = p.linux.clear_tid_address();
        p.linux.exit_tid(&mut p.memory);
        self.wake_futex(p, address, u32::MAX, u32::MAX);
        self.wake_vfork(pid);
        if pid != p.tgid {
            p.state = State::Zombie(status);
            p.auto_reap = true;
            self.close_exit_files(p);
            p.memory = Memory::default();
            self.finish_group(p.tgid);
            return;
        }
        p.auto_reap = self.processes.get(&p.parent).is_some_and(|parent| {
            let action = parent.signals.actions.get(17);
            action.handler == 1 || action.flags & 2 != 0
        });
        if pid != 1 {
            p.memory = Memory::default();
        }
        p.state = State::Zombie(status);
        self.close_exit_files(p);
        p.signals.pending.clear();
        p.wait_event = None;
        if !self
            .processes
            .values()
            .any(|t| t.tgid == p.tgid && !matches!(t.state, State::Zombie(_)))
        {
            self.reap_namespace_children(pid, p.linux.vfs.pid_namespace(), p.parent);
            self.timers.retain(|_, t| t.tgid != p.tgid);
            self.notify(
                p.parent,
                pid,
                p.linux.vfs.credentials.uid,
                if status & 127 == 0 {
                    status >> 8
                } else {
                    status & 127
                },
                if status & 127 == 0 { 1 } else { 2 },
            );
        } else {
            p.auto_reap = false;
        }
    }
    fn finish_group(&mut self, tgid: u32) {
        if self
            .processes
            .values()
            .any(|t| t.tgid == tgid && !matches!(t.state, State::Zombie(_)))
        {
            return;
        }
        self.timers.retain(|_, t| t.tgid != tgid);
        if let Some(leader) = self.processes.get(&tgid) {
            if let State::Zombie(status) = leader.state {
                let parent = leader.parent;
                let uid = leader.linux.vfs.credentials.uid;
                let namespace = leader.linux.vfs.pid_namespace().clone();
                self.reap_namespace_children(tgid, &namespace, parent);
                self.notify(
                    parent,
                    tgid,
                    uid,
                    if status & 127 == 0 {
                        status >> 8
                    } else {
                        status & 127
                    },
                    if status & 127 == 0 { 1 } else { 2 },
                );
                let auto = self.processes.get(&parent).is_some_and(|p| {
                    let action = p.signals.actions.get(17);
                    action.handler == 1 || action.flags & 2 != 0
                });
                if auto && tgid != 1 {
                    self.processes.remove(&tgid);
                }
            }
        }
    }
    fn exit(&mut self, pid: u32, p: &mut Process<C>, status: i32) {
        let members: Vec<_> = self
            .processes
            .iter()
            .filter(|(_, t)| t.tgid == p.tgid)
            .map(|(&id, _)| id)
            .collect();
        for id in members.iter().copied().filter(|id| *id != p.tgid) {
            if let Some(mut thread) = self.processes.remove(&id) {
                thread.linux.vfs.cgroup_exit(id);
                let address = thread.linux.clear_tid_address();
                thread.linux.exit_tid(&mut thread.memory);
                self.wake_futex(&thread, address, u32::MAX, u32::MAX);
                self.close_exit_files(&mut thread);
            }
        }
        if pid != p.tgid {
            if let Some(mut leader) = self.processes.remove(&p.tgid) {
                self.exit_one(p.tgid, &mut leader, status);
                self.processes.insert(p.tgid, leader);
            }
        }
        self.exit_one(pid, p, status);
    }
    fn wake_vfork(&mut self, child: u32) {
        for parent in self.processes.values_mut() {
            if matches!(parent.state, State::Vfork(id) if id == child) {
                parent.state = State::Ready;
            }
        }
    }
    fn prepare_signal(p: &mut Process<C>, sig: u32, sender: u32) -> bool {
        if sig == 0 || matches!(p.state, State::Zombie(_)) {
            return false;
        }
        p.signals.clear_opposing(sig);
        if sig == 18 && matches!(p.state, State::Stopped) {
            p.state = p.stopped_state.take().map_or(State::Ready, |s| *s);
            p.wait_event = Some(0xffff);
        }
        // Unblocked default dispositions are ignored by namespace init. Blocked
        // signals remain available to signalfd/sigwait. Ancestor KILL/STOP and
        // synchronous faults retain their forced-delivery behavior.
        if p.linux.vfs.pid_namespace().is_nested()
            && p.linux.vfs.visible_pid(p.tgid) == 1
            && p.signals.actions.get(sig as usize).handler <= 1
            && p.signals.mask & (1 << (sig - 1)) == 0
            && !(matches!(sig, 9 | 19) && p.linux.vfs.visible_pid(sender) == 0)
        {
            return false;
        }
        p.signals.should_queue(sig)
    }
    fn queue_one(_pid: u32, p: &mut Process<C>, sig: u32, sender: u32) {
        if Self::prepare_signal(p, sig, sender) {
            let _ = p.signals.pending.enqueue(
                sig,
                Info {
                    sender,
                    uid: 0,
                    status: 0,
                    code: 0,
                    timer: None,
                    fault: None,
                },
            );
        }
    }
    fn may_signal(source: &Process<C>, target: &Process<C>, sig: u32) -> bool {
        let a = &source.linux.vfs.credentials;
        let b = &target.linux.vfs.credentials;
        a.has_cap(capabilities::KILL)
            || [a.uid, a.euid]
                .iter()
                .any(|id| *id == b.uid || *id == b.suid)
            || sig == 18 && source.session == target.session
    }
    fn thread_signal(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        tid: u32,
        tgid: Option<u32>,
        sig: u32,
    ) -> Result<u64, Errno> {
        if sig > 64 {
            return Err(Errno(22));
        }
        if tid == 0 || tid > i32::MAX as u32 {
            return Err(Errno(22));
        }
        let tid = p.linux.vfs.global_pid(tid)?;
        let tgid = tgid.map(|id| p.linux.vfs.global_pid(id)).transpose()?;
        let allowed = if tid == pid {
            if tgid.is_some_and(|id| id != p.tgid) {
                return Err(Errno(3));
            }
            Self::may_signal(p, p, sig)
        } else {
            let target = self.processes.get(&tid).ok_or(Errno(3))?;
            if tgid.is_some_and(|id| id != target.tgid) {
                return Err(Errno(3));
            }
            Self::may_signal(p, target, sig)
        };
        if !allowed {
            return Err(Errno(1));
        }
        let sender = p.tgid;
        let uid = p.linux.vfs.credentials.uid;
        if matches!(sig, 18..=22) {
            // Stop/continue cancellation and group resume apply to every member
            // even when tgkill selects one thread for the pending signal.
            let group = if tid == pid {
                p.tgid
            } else {
                self.processes[&tid].tgid
            };
            if p.tgid == group {
                Self::prepare_signal(p, sig, sender);
            }
            for other in self
                .processes
                .values_mut()
                .filter(|other| other.tgid == group)
            {
                Self::prepare_signal(other, sig, sender);
            }
        }
        let target = if tid == pid {
            p
        } else {
            self.processes.get_mut(&tid).ok_or(Errno(3))?
        };
        if Self::prepare_signal(target, sig, sender) {
            target.signals.pending.enqueue(
                sig,
                Info {
                    sender,
                    uid,
                    status: 0,
                    code: -6,
                    timer: None,
                    fault: None,
                },
            )?;
        }
        Ok(0)
    }
    fn signal(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        target: i32,
        sig: u32,
    ) -> Result<u64, Errno> {
        if sig > 64 {
            return Err(Errno(22));
        }
        let positive = if target > 0 {
            let target = p.linux.vfs.global_pid(target as u32)?;
            if target == pid {
                p.tgid
            } else {
                self.processes.get(&target).ok_or(Errno(3))?.tgid
            }
        } else {
            0
        };
        let matches = |id: u32, group: u32| {
            if p.linux.vfs.visible_pid(id) == 0 {
                return false;
            }
            if target > 0 {
                id == positive
            } else if target == 0 {
                group == p.group
            } else if target == -1 {
                p.linux.vfs.visible_pid(id) != 1 && id != p.tgid
            } else {
                p.linux.vfs.visible_pid(group) == target.unsigned_abs()
            }
        };
        // One process-directed pending signal per thread group; stop/continue
        // state changes must reach every member, not just the group leader.
        let mut groups = Vec::new();
        let mut found = false;
        if pid == p.tgid && matches(p.tgid, p.group) {
            found = true;
            if Self::may_signal(p, p, sig) {
                groups.push(p.tgid);
            }
        }
        for (&id, other) in &self.processes {
            if id == other.tgid && matches(other.tgid, other.group) {
                found = true;
                if Self::may_signal(p, other, sig) {
                    groups.push(other.tgid);
                }
            }
        }
        if groups.is_empty() {
            return Err(Errno(if found { 1 } else { 3 }));
        }
        let sender = p.tgid;
        let uid = p.linux.vfs.credentials.uid;
        let mut queued = Vec::new();
        let mut queue = |other: &mut Process<C>| -> Result<(), Errno> {
            if groups.contains(&other.tgid)
                && Self::prepare_signal(other, sig, sender)
                && !queued.contains(&other.tgid)
            {
                other.signals.shared_pending.borrow_mut().enqueue(
                    sig,
                    Info {
                        sender,
                        uid,
                        status: 0,
                        code: 0,
                        timer: None,
                        fault: None,
                    },
                )?;
                queued.push(other.tgid);
            }
            Ok(())
        };
        queue(p)?;
        for other in self.processes.values_mut() {
            queue(other)?;
        }
        Ok(0)
    }
    fn synchronous_fault(&mut self, pid: u32, p: &mut Process<C>, fault: &trames_engine::CpuFault) {
        p.linux.vfs.log(
            4,
            &format!(
                "pid={pid} tgid={} {fault} comm={:?}",
                p.tgid,
                String::from_utf8_lossy(&p.linux.command_name)
            ),
        );
        use trames_engine::CpuFault as F;
        use trames_kernel::signal::Fault;
        let fault_info = match fault {
            F::Host(error) => {
                self.backend_error = Some(error.clone());
                return;
            }
            F::Trap {
                pc, signal, code, ..
            } => Fault {
                signal: *signal,
                code: *code,
                address: *pc,
            },
            F::Instruction { pc, .. } => Fault {
                signal: 4,
                code: 1,
                address: *pc,
            },
            F::Memory { pc, error } => Fault::memory(*pc, error),
        };
        if !p.signals.force_fault(fault_info) {
            if pid == 1 {
                eprintln!("trames: {fault}");
            }
            self.exit(pid, p, fault_info.signal as i32);
            return;
        }
        if self.deliver(pid, p).is_err() {
            self.exit(pid, p, 11);
        }
    }
    fn deliver(&mut self, pid: u32, p: &mut Process<C>) -> Result<bool, Errno> {
        let stopped = matches!(p.state, State::Stopped);
        let selected = p
            .signals
            .select(stopped, matches!(p.state, State::Gpu { .. }));
        let Some((sig, shared)) = selected else {
            return Ok(false);
        };
        if stopped && sig != 9 && sig != 18 {
            return Ok(false);
        }
        let info = p.take_signal(sig, shared);
        let action = p.signals.actions.get(sig as usize);
        // Timer-generated signals also reach this queue without queue_one.
        // Namespace init ignores default dispositions, except forced ancestor
        // KILL/STOP and synchronous faults, which must still make progress.
        if p.linux.vfs.pid_namespace().is_nested()
            && p.linux.vfs.visible_pid(p.tgid) == 1
            && action.handler == 0
            && info.fault.is_none()
            && !(matches!(sig, 9 | 19) && info.timer.is_none())
        {
            return Ok(true);
        }
        let disposition = trames_kernel::signal::disposition(sig, action);
        if disposition == trames_kernel::signal::Disposition::Terminate {
            self.exit(pid, p, sig as i32);
            return Ok(true);
        }
        if disposition == trames_kernel::signal::Disposition::Stop {
            if !matches!(p.state, State::Stopped) {
                p.stopped_state = Some(Box::new(p.state.clone()));
            }
            p.state = State::Stopped;
            for other in self.processes.values_mut().filter(|other| {
                other.tgid == p.tgid && !matches!(other.state, State::Zombie(_) | State::Stopped)
            }) {
                other.stopped_state = Some(Box::new(other.state.clone()));
                other.state = State::Stopped;
            }
            p.wait_event = Some(((sig as i32) << 8) | 0x7f);
            self.notify(p.parent, p.tgid, p.linux.vfs.credentials.uid, sig as i32, 5);
            return Ok(true);
        }
        if disposition == trames_kernel::signal::Disposition::Ignore {
            return Ok(true);
        }
        if p.signals.frames >= 8 {
            self.exit(pid, p, 11);
            return Ok(true);
        }
        match p.state.clone() {
            State::Blocked(number, a) => {
                if let Some(fd) = p.pending_open.take() {
                    p.linux.vfs.cancel_fifo_open(fd);
                }
                if let Some(mask) = p.poll_mask.take() {
                    p.signals.mask = mask;
                }
                p.poll_deadline = None;
                p.uring_wait = None;
                p.flock_wait = None;
                p.byte_wait = None;
                p.retained_byte = None;
                p.retained_poll = None;
                p.retained_select = None;
                let timed_socket = p.socket_deadline.take().is_some();
                if !timed_socket
                    && action.flags & 0x10000000 != 0
                    && matches!(
                        number,
                        25 | 32
                            | 56
                            | 63
                            | 64
                            | 65
                            | 66
                            | 95
                            | 260
                            | 202
                            | 242
                            | 206
                            | 207
                            | 211
                            | 212
                    )
                {
                    put_args(&mut p.cpu, a);
                    p.cpu.set_pc(p.cpu.pc().wrapping_sub(4));
                } else {
                    p.cpu.set_x(0, error(Errno(4)));
                }
            }
            State::Sleep(deadline, remaining) => {
                if remaining != 0 {
                    let ns = deadline
                        .saturating_duration_since(Instant::now())
                        .as_nanos();
                    let _ = write_u64(&mut p.memory, remaining, (ns / 1_000_000_000) as u64);
                    let _ = write_u64(&mut p.memory, remaining + 8, (ns % 1_000_000_000) as u64);
                }
                p.cpu.set_x(0, error(Errno(4)));
            }
            State::Suspend(old) => {
                p.signals.mask = old;
                p.cpu.set_x(0, error(Errno(4)));
            }
            State::Futex { .. } | State::Sigwait { .. } => {
                p.cpu.set_x(0, error(Errno(4)));
            }
            _ => {}
        }
        let mut state = p.cpu.architectural_state();
        p.signals
            .enter(&mut state, &mut p.memory, sig, info, action)?;
        p.cpu.restore_architectural_state(&state);
        p.state = State::Ready;
        Ok(true)
    }
    fn sigreturn(p: &mut Process<C>) -> Result<(), Errno> {
        let mut state = p.cpu.architectural_state();
        p.signals.restore(&mut state, &p.memory)?;
        p.cpu.restore_architectural_state(&state);
        p.state = State::Ready;
        Ok(())
    }
    fn exec(p: &mut Process<C>, a: [u64; 6], budget: usize) -> Result<(), Errno> {
        Self::exec_at(p, AT_FDCWD, a, 0, budget)
    }
    fn exec_at(
        p: &mut Process<C>,
        dirfd: i32,
        a: [u64; 6],
        flags: u32,
        budget: usize,
    ) -> Result<(), Errno> {
        let mut path = Linux::path(&p.memory, a[0])?;
        if path.is_empty() && flags & 0x1000 == 0 {
            return Err(Errno(2));
        }
        if flags & !0x1100 != 0 {
            return Err(Errno(22));
        }
        let via_fd = path.is_empty() || !path.starts_with(b"/") && dirfd != AT_FDCWD;
        let filename = if via_fd {
            let mut name = format!("/dev/fd/{dirfd}").into_bytes();
            if !path.is_empty() {
                name.push(b'/');
                name.extend_from_slice(&path);
            }
            name
        } else {
            path.clone()
        };
        let mut file = p.linux.vfs.executable_file_at(dirfd, &path, flags)?;
        let inaccessible = via_fd && p.linux.vfs.flags(dirfd as u32)? & trames_vfs::O_CLOEXEC != 0;
        let mut argv = strings(&p.memory, a[1])?;
        let envp = strings(&p.memory, a[2])?;
        if argv.is_empty() {
            argv.push(Vec::new());
        }
        for depth in 0..5 {
            let bytes = file.bytes()?;
            if bytes.starts_with(b"#!") {
                if depth == 0 && inaccessible {
                    return Err(Errno(2));
                }
                if depth == 4 {
                    return Err(Errno(40));
                }
                let line = bytes[2..].split(|&b| b == b'\n').next().ok_or(Errno(8))?;
                if line.len() > 254 {
                    return Err(Errno(8));
                }
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                let start = line
                    .iter()
                    .position(|b| !b.is_ascii_whitespace())
                    .ok_or(Errno(8))?;
                let line = &line[start..];
                let mut parts = line.splitn(2, |b| b.is_ascii_whitespace());
                let interpreter = parts.next().unwrap_or_default();
                if interpreter.is_empty() {
                    return Err(Errno(8));
                }
                let mut next = vec![interpreter.to_vec()];
                if let Some(optional) = parts.next() {
                    let trimmed = optional
                        .iter()
                        .position(|b| !b.is_ascii_whitespace())
                        .map(|i| &optional[i..])
                        .unwrap_or_default();
                    if !trimmed.is_empty() {
                        next.push(trimmed.to_vec());
                    }
                }
                next.push(if depth == 0 {
                    filename.clone()
                } else {
                    path.clone()
                });
                next.extend(argv.into_iter().skip(1));
                argv = next;
                path = interpreter.to_vec();
                file = p.linux.vfs.executable_file_at(AT_FDCWD, &path, 0)?;
                continue;
            }
            let mut execute_vfs = p.linux.vfs.clone();
            execute_vfs.apply_exec_file_credentials(&file)?;
            let mut runtime = Runtime::<C>::load_guest_execfn(
                &bytes,
                &argv,
                &envp,
                &execute_vfs,
                super::RuntimeOptions {
                    memory_limits: super::MemoryLimits {
                        per_process: budget,
                        total: budget,
                    },
                    pure_accelerator: accelerated(
                        p,
                        trames_accel::native::AUXV_KEY,
                        trames_accel::native::PROFILE,
                    ),
                    vulkan_accelerator: accelerated(
                        p,
                        trames_vulkan::AUXV_KEY,
                        trames_vulkan::PROFILE,
                    ),
                    native_bsearch: p.linux.auxiliary.chunks_exact(16).any(|pair| {
                        pair[..8] == trames_accel::callbacks::SEARCH_AUXV_KEY.to_le_bytes()
                            && pair[8..] == 1u64.to_le_bytes()
                    }),
                    native_allocator: p.linux.auxiliary.chunks_exact(16).any(|pair| {
                        pair[..8] == trames_accel::allocator::AUXV_KEY.to_le_bytes()
                            && pair[8..] == trames_accel::allocator::PROFILE.to_le_bytes()
                    }),
                },
                Some(&filename),
            )
            .map_err(|e| match e {
                RuntimeError::Arguments(_) => Errno(7),
                RuntimeError::Memory(_) | RuntimeError::Configuration(_) => Errno(12),
                RuntimeError::Elf(trames_elf::ElfError::Interpreter(n)) => Errno(n),
                _ => Errno(8),
            })?;
            if runtime.memory.resident_bytes() > budget {
                return Err(Errno(12));
            }
            runtime
                .memory
                .inherit_total_limit(&p.memory)
                .map_err(|_| Errno(12))?;
            runtime.linux.executable_path = p.linux.vfs.executable_display(&file);
            runtime.linux.executable_file = Some(file);
            runtime.linux.command_name = filename
                .rsplit(|b| *b == b'/')
                .next()
                .unwrap_or_default()
                .iter()
                .copied()
                .take(15)
                .collect();
            let task = p.linux.vfs.process_context();
            p.linux.cancel_uring(&mut p.memory, task);
            p.uring_wait = None;
            p.flock_wait = None;
            p.byte_wait = None;
            p.retained_byte = None;
            p.retained_poll = None;
            p.retained_select = None;
            p.linux.vfs.unshare_descriptors();
            p.linux.vfs.close_exec();
            let credentials = execute_vfs.credentials.clone();
            std::mem::swap(&mut runtime.linux.vfs, &mut p.linux.vfs);
            runtime.linux.vfs.credentials = credentials;
            runtime.linux.vfs.unshare_dumpable();
            runtime.linux.vfs.set_dumpable(execute_vfs.dumpable())?;
            runtime.linux.trace = p.linux.trace;
            runtime.linux.task_limit = p.linux.task_limit;
            p.linux = runtime.linux;
            p.cpu = runtime.cpu;
            p.memory = runtime.memory;
            p.signals.exec();
            p.membarrier_registered = Rc::new(Cell::new(false));
            p.state = State::Ready;
            return Ok(());
        }
        Err(Errno(40))
    }
    fn wait(&mut self, _pid: u32, p: &mut Process<C>, a: [u64; 6]) -> Result<Option<u64>, Errno> {
        // __WALL includes all waitable clone children. Non-thread guest clones
        // currently all use SIGCHLD, so this preserves the ordinary selection.
        if a[2] & !(11 | 0x40000000) != 0 {
            return Err(Errno(22));
        }
        if a[1] != 0 {
            Linux::check(&p.memory, a[1], 4, Access::Write)?;
        }
        if a[3] != 0 {
            Linux::check(&p.memory, a[3], 144, Access::Write)?;
        }
        let target = a[0] as i32;
        let matching: Vec<u32> = self
            .processes
            .iter()
            .filter(|(id, c)| {
                c.parent == p.tgid
                    && **id == c.tgid
                    && (target == -1
                        || (target == 0 && c.group == p.group)
                        || (target < -1
                            && p.linux.vfs.visible_pid(c.group) == target.unsigned_abs())
                        || (target > 0 && p.linux.vfs.visible_pid(**id) == target as u32))
            })
            .map(|(&id, _)| id)
            .collect();
        if matching.is_empty() {
            return Err(Errno(10));
        }
        for child in matching {
            let c = &self.processes[&child];
            let status = match c.state {
                State::Zombie(s)
                    if !self
                        .processes
                        .values()
                        .any(|t| t.tgid == c.tgid && !matches!(t.state, State::Zombie(_))) =>
                {
                    Some(s)
                }
                State::Stopped if a[2] & 2 != 0 => c.wait_event,
                _ if a[2] & 8 != 0 && c.wait_event == Some(0xffff) => Some(0xffff),
                _ => None,
            };
            if let Some(status) = status {
                if a[1] != 0 {
                    p.memory
                        .write(a[1], &status.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if a[3] != 0 {
                    p.memory.write(a[3], &[0; 144]).map_err(|_| Errno(14))?;
                }
                if matches!(c.state, State::Zombie(_)) {
                    self.processes.remove(&child);
                } else {
                    self.processes.get_mut(&child).expect("child").wait_event = None;
                }
                return Ok(Some(p.linux.vfs.visible_pid(child) as u64));
            }
        }
        if a[2] & 1 != 0 {
            Ok(Some(0))
        } else {
            Ok(None)
        }
    }
    fn syscall(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
        io: &mut impl GuestOutput,
    ) -> Result<Option<u64>, Errno> {
        match number {
            32 => {
                let (request, file) = match p.flock_wait.take() {
                    Some(wait) => wait,
                    None => {
                        // Uncontended calls need no persistent request/extra
                        // OFD lease. Retain only when this invocation parks.
                        match p.linux.vfs.flock(a[0] as u32, a[1] as u32) {
                            Err(Errno(11)) if a[1] as u32 & 4 == 0 => {
                                p.flock_wait =
                                    Some(p.linux.vfs.retain_flock(a[0] as u32, a[1] as u32)?);
                                p.state = State::Blocked(number, a);
                                return Ok(None);
                            }
                            result => return result.map(|()| Some(0)),
                        }
                    }
                };
                match request.try_lock() {
                    Err(Errno(11)) if !request.nonblocking() => {
                        p.flock_wait = Some((request, file));
                        p.state = State::Blocked(number, a);
                        Ok(None)
                    }
                    result => result.map(|()| Some(0)),
                }
            }
            426 => {
                p.linux.set_uring_clock(self.started);
                let (saved, ring, deadline) = match p.uring_wait.take() {
                    Some((submitted, ring, deadline)) => (Some(submitted), ring, deadline),
                    None => (
                        None,
                        p.linux.vfs.uring(a[0] as u32)?,
                        p.linux.uring_enter_deadline(a, &p.memory)?,
                    ),
                };
                let (submitted, ready) =
                    p.linux
                        .uring_enter_ring(ring.clone(), a, &mut p.memory, saved, pid)?;
                if ready {
                    Ok(Some(submitted as u64))
                } else if deadline.is_some_and(|d| Instant::now() >= d) {
                    if submitted != 0 {
                        Ok(Some(submitted as u64))
                    } else {
                        Err(Errno(62))
                    }
                } else {
                    p.uring_wait = Some((submitted, ring, deadline));
                    Ok(None)
                }
            }
            277 => self.seccomp(p, a).map(Some),
            167 if a[0] == 21 => Ok(Some(p.seccomp.mode() as u64)),
            167 if a[0] == 22 => match a[1] {
                // PR_SET_SECCOMP uses mode 1/2, while seccomp(2) uses
                // operation 0/1. Keep validation and actual filters shared.
                1 => self.seccomp(p, [0, 0, 0, 0, 0, 0]).map(Some),
                2 => self.seccomp(p, [1, 0, a[2], 0, 0, 0]).map(Some),
                _ => Err(Errno(22)),
            },
            140 | 141 => self.priority(pid, p, number, a),
            236 => Self::mempolicy(p, a),
            90 | 91 => self.capcall(pid, p, number == 91, a).map(Some),
            93 | 94 => {
                if number == 93 {
                    self.exit_one(pid, p, (a[0] as u8 as i32) << 8);
                } else {
                    self.exit(pid, p, (a[0] as u8 as i32) << 8);
                }
                Ok(None)
            }
            118..=123 => {
                if (a[0] as u32 as i32) < 0 {
                    return Err(Errno(22));
                }
                let target_id = if a[0] as u32 == 0 {
                    pid
                } else {
                    p.linux.vfs.global_pid(a[0] as u32)?
                };
                let target = if target_id == pid {
                    &*p
                } else {
                    self.processes
                        .get(&target_id)
                        .filter(|p| !matches!(p.state, State::Zombie(_)))
                        .ok_or(Errno(3))?
                };
                if matches!(number, 118 | 119 | 122)
                    && !p.linux.vfs.credentials.has_cap(capabilities::SYS_NICE)
                    && ((p.linux.vfs.credentials.euid != target.linux.vfs.credentials.uid
                        && p.linux.vfs.credentials.euid != target.linux.vfs.credentials.euid)
                        || target.linux.vfs.credentials.caps.permitted
                            & !p.linux.vfs.credentials.caps.permitted
                            != 0)
                {
                    return Err(Errno(1));
                }
                match number {
                    118 | 119 => {
                        let pointer = if number == 118 { a[1] } else { a[2] };
                        let priority = read_u32(&p.memory, pointer)? as i32;
                        if number == 119 && !matches!(a[1] as u32, 0 | 3 | 5) {
                            return Err(Errno(if matches!(a[1] as u32, 1 | 2) { 95 } else { 22 }));
                        }
                        if priority != 0 {
                            return Err(Errno(22));
                        }
                        if number == 119 {
                            if target_id == pid {
                                p.scheduler = a[1] as u32;
                            } else {
                                self.processes.get_mut(&target_id).unwrap().scheduler = a[1] as u32;
                            }
                        }
                        Ok(Some(0)) // Policy is guest metadata; host workers retain their priorities.
                    }
                    120 => Ok(Some(target.scheduler as u64)),
                    121 => {
                        Linux::check(&p.memory, a[1], 4, Access::Write)?;
                        p.memory.write(a[1], &[0; 4]).map_err(|_| Errno(14))?;
                        Ok(Some(0))
                    }
                    122 => {
                        if a[1] == 0 {
                            return Err(Errno(22));
                        }
                        Linux::check(&p.memory, a[2], a[1].min(8) as usize, Access::Read)?;
                        let mut bytes = [0; 8];
                        p.memory
                            .read(a[2], &mut bytes[..a[1].min(8) as usize])
                            .map_err(|_| Errno(14))?;
                        let mask = u64::from_le_bytes(bytes) & ((1u64 << self.cpu_count) - 1);
                        if mask == 0 {
                            return Err(Errno(22));
                        }
                        if target_id == pid {
                            p.affinity = mask;
                        } else {
                            self.processes.get_mut(&target_id).ok_or(Errno(3))?.affinity = mask;
                        }
                        Ok(Some(0))
                    }
                    _ => {
                        if a[1] < 8 {
                            return Err(Errno(22));
                        }
                        let mask = target.affinity;
                        write_u64(&mut p.memory, a[2], mask)?;
                        Ok(Some(8))
                    }
                }
            }
            39 => {
                p.linux.vfs.umount(&Linux::path(&p.memory, a[0])?, a[1])?;
                Ok(Some(0))
            }
            40 => {
                let optional = |ptr| {
                    if ptr == 0 {
                        Ok(None)
                    } else {
                        Linux::path(&p.memory, ptr).map(Some)
                    }
                };
                let source = optional(a[0])?;
                let target = Linux::path(&p.memory, a[1])?;
                let kind = optional(a[2])?;
                let data = optional(a[4])?;
                p.linux.vfs.mount(
                    source.as_deref(),
                    &target,
                    kind.as_deref(),
                    a[3],
                    data.as_deref(),
                )?;
                Ok(Some(0))
            }
            41 => {
                let before = p.linux.vfs.clone();
                p.linux.vfs.pivot_root(
                    &Linux::path(&p.memory, a[0])?,
                    &Linux::path(&p.memory, a[1])?,
                )?;
                for other in self.processes.values_mut() {
                    other.linux.vfs.sync_pivot_from(&before, &p.linux.vfs);
                }
                Ok(Some(0))
            }
            97 => {
                const ALLOWED: u64 = trames_vfs::CLONE_NEWUTS
                    | trames_vfs::CLONE_NEWNS
                    | trames_vfs::CLONE_NEWPID
                    | trames_vfs::CLONE_NEWNET
                    | trames_vfs::CLONE_NEWIPC
                    | trames_vfs::CLONE_NEWCGROUP
                    | 0x200
                    | 0x400;
                if a[0] & !ALLOWED != 0 {
                    return Err(Errno(22));
                }
                if a[0] & trames_vfs::CLONE_NEWPID != 0
                    && (pid != p.tgid
                        || self
                            .processes
                            .values()
                            .any(|t| t.tgid == p.tgid && !matches!(t.state, State::Zombie(_))))
                {
                    return Err(Errno(22));
                }
                let mut view = p.linux.vfs.clone_with_resources(
                    a[0] & 0x400 == 0,
                    a[0] & (0x200 | trames_vfs::CLONE_NEWNS) == 0,
                );
                if a[0] & trames_vfs::CLONE_NEWPID != 0 {
                    view.unshare_pid()?;
                }
                if a[0] & trames_vfs::CLONE_NEWUTS != 0 {
                    view.unshare_uts()?;
                }
                if a[0] & trames_vfs::CLONE_NEWNS != 0 {
                    view.unshare_mounts()?;
                }
                if a[0] & trames_vfs::CLONE_NEWNET != 0 {
                    view.unshare_net()?;
                }
                if a[0] & trames_vfs::CLONE_NEWIPC != 0 {
                    view.unshare_ipc()?;
                }
                if a[0] & trames_vfs::CLONE_NEWCGROUP != 0 {
                    view.unshare_cgroup()?;
                }
                p.linux.vfs = view;
                Ok(Some(0))
            }
            268 => {
                if p.linux.vfs.namespace_type(a[0] as u32)? == Some(trames_vfs::CLONE_NEWNS)
                    && self.processes.values().any(|other| {
                        other.linux.vfs.shares_context_with(&p.linux.vfs)
                            && !matches!(other.state, State::Zombie(_))
                    })
                {
                    return Err(Errno(22));
                }
                p.linux.vfs.setns(a[0] as u32, a[1])?;
                Ok(Some(0))
            }
            436 => {
                let (first, last, flags) = (a[0] as u32, a[1] as u32, a[2] as u32);
                if first > last || flags & !6 != 0 {
                    return Err(Errno(22));
                }
                if flags & 2 != 0 {
                    p.linux.vfs.unshare_descriptors();
                }
                p.linux.vfs.close_range(first, last, flags)?;
                Ok(Some(0))
            }
            168 => {
                if a[0] != 0 {
                    Linux::check(&p.memory, a[0], 4, Access::Write)?;
                }
                if a[1] != 0 {
                    Linux::check(&p.memory, a[1], 4, Access::Write)?;
                }
                if a[0] != 0 {
                    p.memory
                        .write(a[0], &(p.last_cpu as u32).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if a[1] != 0 {
                    p.memory
                        .write(a[1], &0u32.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                Ok(Some(0))
            }
            172 => Ok(Some(p.linux.vfs.visible_pid(p.tgid) as u64)),
            178 => Ok(Some(p.linux.vfs.visible_pid(pid) as u64)),
            173 => Ok(Some(p.linux.vfs.visible_pid(p.parent) as u64)),
            96 => {
                p.linux.dispatch(&mut p.cpu, &mut p.memory, io);
                Ok(Some(p.linux.vfs.visible_pid(pid) as u64))
            }
            220 => {
                const ALLOWED: u64 = 0xff
                    | 0xf00
                    | 0x4000
                    | 0x8000
                    | 0x10000
                    | 0xfc0000
                    | 0x1000000
                    | trames_vfs::CLONE_NEWUTS
                    | trames_vfs::CLONE_NEWNS
                    | trames_vfs::CLONE_NEWPID
                    | trames_vfs::CLONE_NEWNET
                    | trames_vfs::CLONE_NEWIPC
                    | trames_vfs::CLONE_NEWCGROUP;
                let threaded = a[0] & 0x10000 != 0;
                let shared_vm = a[0] & 0x100 != 0;
                if a[0] & !ALLOWED != 0
                    || (a[0] & trames_vfs::CLONE_NEWPID != 0 && a[0] & (0x10000 | 0x8000) != 0)
                    || (threaded
                        && p.linux.vfs.pid_namespace().id()
                            != p.linux.vfs.pid_children_namespace().id())
                    || (a[0] & 0x8000 != 0 && p.linux.vfs.visible_pid(p.tgid) == 1)
                    || (a[0] & trames_vfs::CLONE_NEWNS != 0 && a[0] & 0x200 != 0)
                    || (a[0] & trames_vfs::CLONE_NEWIPC != 0 && a[0] & 0x40000 != 0)
                    || (!threaded && a[0] & 255 != 17)
                    || (threaded && (a[0] & 0x900 != 0x900 || a[0] & 255 != 0))
                    || (a[0] & 0x800 != 0 && !shared_vm)
                {
                    return Err(Errno(22));
                }
                if self.processes.len() + 1 >= self.task_limit
                    || (!shared_vm && !p.memory.can_fork())
                {
                    return Err(Errno(11));
                }
                if a[0] & 0x100000 != 0 {
                    Linux::check(&p.memory, a[2], 4, Access::Write)?;
                }
                if a[0] & (0x1000000 | 0x200000) != 0 {
                    Linux::check(&p.memory, a[4], 4, Access::Write)?;
                }
                let id = self.next_pid;
                p.linux.vfs.cgroup_can_fork(pid)?;
                self.next_pid = self
                    .next_pid
                    .checked_add(1)
                    .filter(|v| *v < i32::MAX as u32)
                    .ok_or(Errno(11))?;
                let live = self
                    .processes
                    .iter()
                    .flat_map(|(&id, t)| {
                        [id, t.tgid, t.group, t.session]
                            .into_iter()
                            .chain(t.signal_senders())
                    })
                    .chain([pid, p.tgid, p.group, p.session])
                    .chain(p.signal_senders())
                    .collect();
                p.linux.vfs.pid_namespace().retain_ids(&live);
                let memory = if shared_vm {
                    p.memory.share()
                } else {
                    p.memory.clone()
                };
                let mut child = p.fork_state(
                    memory,
                    a[0] & 0x400 != 0,
                    a[0] & 0x200 != 0,
                    a[0] & 0x800 != 0,
                );
                if a[0] & trames_vfs::CLONE_NEWPID != 0 {
                    child.linux.vfs.unshare_pid()?;
                }
                if a[0] & trames_vfs::CLONE_NEWUTS != 0 {
                    child.linux.vfs.unshare_uts()?;
                }
                if a[0] & trames_vfs::CLONE_NEWNS != 0 {
                    child.linux.vfs.unshare_mounts()?;
                }
                if a[0] & trames_vfs::CLONE_NEWNET != 0 {
                    child.linux.vfs.unshare_net()?;
                }
                if a[0] & trames_vfs::CLONE_NEWIPC != 0 {
                    child.linux.vfs.unshare_ipc()?;
                }
                if a[0] & trames_vfs::CLONE_NEWCGROUP != 0 {
                    child.linux.vfs.unshare_cgroup()?;
                }
                child.linux.vfs.activate_child_pid(id)?;
                let parent_tid = p.linux.vfs.visible_pid(id);
                let child_tid = child.linux.vfs.visible_pid(id);
                // PID namespace init inherits its parent's PGID/SID/tty, as
                // Linux copy_process does. Ancestor-only IDs appear as zero
                // inside the new namespace; init can then establish setsid().
                let resource = self.resource_id();
                if shared_vm {
                    child.membarrier_registered = p.membarrier_registered.clone();
                    if a[0] & 0x4000 == 0 {
                        child.signals.alt_stack = AltStack::default();
                    }
                } else {
                    child.vm_id = resource;
                    child.linux.vfs.unshare_dumpable();
                }
                child.tgid = if threaded { p.tgid } else { id };
                if threaded {
                    child.oom = Arc::new(p.oom.thread());
                    child.signals.shared_pending = p.signals.shared_pending.clone();
                    child.subreaper = p.subreaper;
                    child.file_size_limit = p.file_size_limit.clone();
                }
                child
                    .linux
                    .fork_tid(if a[0] & 0x200000 != 0 { a[4] } else { 0 });
                child.parent = if threaded || a[0] & 0x8000 != 0 {
                    p.parent
                } else {
                    p.tgid
                };
                child.parent_thread = if threaded || a[0] & 0x8000 != 0 {
                    p.parent_thread
                } else {
                    pid
                };
                child.cpu.set_x(0, 0);
                if a[1] != 0 {
                    child.cpu.set_sp(a[1]);
                }
                if a[0] & 0x80000 != 0 {
                    child.cpu.set_tls(a[3]);
                }
                if a[0] & 0x100000 != 0 {
                    p.memory
                        .write(a[2], &parent_tid.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if a[0] & 0x1000000 != 0 {
                    child
                        .memory
                        .write(a[4], &child_tid.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                child.linux.vfs.cgroup_fork(pid, id, child.tgid);
                self.processes.insert(id, child);
                if a[0] & 0x4000 != 0 {
                    p.state = State::Vfork(id);
                    p.cpu.set_x(0, parent_tid as u64);
                    return Ok(None);
                }
                Ok(Some(parent_tid as u64))
            }
            221 | 281 => {
                let old_vm = p.vm_id;
                if number == 221 {
                    Self::exec(p, a, self.memory_limits.per_process)?;
                } else {
                    Self::exec_at(
                        p,
                        a[0] as i32,
                        [a[1], a[2], a[3], 0, 0, 0],
                        a[4] as u32,
                        self.memory_limits.per_process,
                    )?;
                }
                let ids: Vec<_> = self
                    .processes
                    .iter()
                    .filter(|(_, t)| t.tgid == p.tgid)
                    .map(|(&id, _)| id)
                    .collect();
                for id in ids {
                    if let Some(mut t) = self.processes.remove(&id) {
                        t.linux.cancel_uring(&mut t.memory, id);
                        self.parent_thread_exited(id, &t, Some(p.tgid));
                        t.linux.vfs.cgroup_exit(id);
                        let address = t.linux.clear_tid_address();
                        t.linux.exit_tid(&mut t.memory);
                        self.wake_futex(&t, address, u32::MAX, u32::MAX);
                        t.linux.vfs.release_descriptors();
                    }
                }
                self.timers.retain(|_, t| t.tgid != p.tgid);
                self.wake_vfork(pid);
                if pid != p.tgid {
                    p.linux.vfs.cgroup_exec_rekey(pid, p.tgid);
                    p.rekey = Some(p.tgid);
                    for child in self.processes.values_mut() {
                        if child.parent_thread == pid {
                            child.parent_thread = p.tgid;
                        }
                    }
                }
                let resource = self.resource_id();
                p.vm_id = resource;
                if !self
                    .processes
                    .values()
                    .any(|other| other.vm_id == old_vm && !matches!(other.state, State::Zombie(_)))
                {
                    self.gpu.borrow_mut().remove(&old_vm);
                }
                Ok(None)
            }
            98 | 102 | 103 | 107..=111 | 137 => self.event_call(pid, p, number, a),
            260 => self.wait(pid, p, a),
            95 => self.waitid(p, a),
            167 if a[0] == 1 => {
                if a[1] > 64 {
                    return Err(Errno(22));
                }
                p.pdeath_signal = a[1] as u32;
                Ok(Some(0))
            }
            167 if a[0] == 2 => {
                write_u32(&mut p.memory, a[1], p.pdeath_signal)?;
                Ok(Some(0))
            }
            167 if a[0] == 3 => Ok(Some(p.linux.vfs.dumpable())),
            167 if a[0] == 4 => p.linux.vfs.set_dumpable(a[1]).map(|()| Some(0)),
            167 if matches!(a[0], 36 | 37) => match a[0] {
                36 => {
                    p.subreaper = a[1] != 0;
                    for t in self.processes.values_mut().filter(|t| t.tgid == p.tgid) {
                        t.subreaper = p.subreaper;
                    }
                    Ok(Some(0))
                }
                37 => {
                    write_u32(&mut p.memory, a[1], u32::from(p.subreaper))?;
                    Ok(Some(0))
                }
                _ => Err(Errno(22)),
            },
            167 if matches!(a[0], 7 | 8 | 23 | 24 | 27 | 28 | 38 | 39 | 47) => {
                p.linux.vfs.credentials.caps.prctl(a).map(Some)
            }
            167 if !matches!(a[0], 15 | 16) => Err(Errno(22)),
            72 | 73 => self.poll(p, number, a, io),
            22 | 441 => self.epoll(p, number, a, io),
            74 => self.signalfd(p, a),
            85..=87 => self.timerfd(p, number, a),
            134 => {
                let sig = a[0] as u32;
                if let Some(action) = p.signals.action_call(a, &mut p.memory)? {
                    if trames_kernel::signal::ignored(sig, action) {
                        for other in self.processes.values_mut().filter(|o| o.tgid == p.tgid) {
                            other.signals.pending.discard(sig);
                        }
                    }
                }
                Ok(Some(0))
            }
            135 => p.signals.mask_call(a, &mut p.memory).map(Some),
            136 => {
                if a[1] != 8 {
                    return Err(Errno(22));
                }
                let bits = p.pending_bits() & p.signals.mask;
                write_u64(&mut p.memory, a[0], bits)?;
                Ok(Some(0))
            }
            133 => {
                if a[1] != 8 {
                    return Err(Errno(22));
                }
                let mask = read_u64(&p.memory, a[0])? & !UNBLOCKABLE;
                let old = p.signals.mask;
                p.signals.mask = mask;
                p.state = State::Suspend(old);
                Ok(None)
            }
            139 => {
                Self::sigreturn(p)?;
                Ok(None)
            }
            129 => self.signal(pid, p, a[0] as i32, a[1] as u32).map(Some),
            130 => self
                .thread_signal(pid, p, a[0] as u32, None, a[1] as u32)
                .map(Some),
            131 => {
                if a[0] == 0 || a[0] > i32::MAX as u64 {
                    return Err(Errno(22));
                }
                self.thread_signal(pid, p, a[1] as u32, Some(a[0] as u32), a[2] as u32)
                    .map(Some)
            }
            154 => {
                if a[1] > i32::MAX as u64 {
                    return Err(Errno(22));
                }
                let target = if a[0] == 0 {
                    p.tgid
                } else {
                    p.linux.vfs.global_pid(a[0] as u32)?
                };
                let group = if a[1] == 0 {
                    target
                } else {
                    p.linux.vfs.global_pid(a[1] as u32).map_err(|_| Errno(1))?
                };
                let (session, parent) = if target == p.tgid {
                    (p.session, p.parent)
                } else {
                    let c = self
                        .processes
                        .get(&target)
                        .filter(|c| c.tgid == target)
                        .ok_or(Errno(3))?;
                    (c.session, c.parent)
                };
                if target != p.tgid && parent != p.tgid {
                    return Err(Errno(3));
                }
                if session != p.session || target == session {
                    return Err(Errno(1));
                }
                if group != target
                    && group != p.group
                    && !self
                        .processes
                        .values()
                        .any(|c| c.group == group && c.session == p.session)
                {
                    return Err(Errno(1));
                }
                if target == p.tgid {
                    p.group = group;
                }
                for other in self.processes.values_mut().filter(|t| t.tgid == target) {
                    other.group = group;
                }
                Ok(Some(0))
            }
            155 | 156 => {
                let id = if a[0] == 0 {
                    p.tgid
                } else {
                    p.linux.vfs.global_pid(a[0] as u32)?
                };
                let (group, session) = if id == pid {
                    (p.group, p.session)
                } else {
                    let c = self.processes.get(&id).ok_or(Errno(3))?;
                    (c.group, c.session)
                };
                Ok(Some(
                    p.linux
                        .vfs
                        .visible_pid(if number == 155 { group } else { session })
                        as u64,
                ))
            }
            157 => {
                if p.group == p.tgid || self.processes.values().any(|c| c.group == p.tgid) {
                    return Err(Errno(1));
                }
                p.session = p.tgid;
                p.group = p.tgid;
                p.linux.vfs.set_controlling_terminal(None)?;
                for t in self.processes.values_mut().filter(|t| t.tgid == p.tgid) {
                    t.session = p.session;
                    t.group = p.group;
                    t.linux.vfs.set_controlling_terminal(None)?;
                }
                Ok(Some(p.linux.vfs.visible_pid(p.tgid) as u64))
            }
            101 | 115 => {
                if number == 115 && (!matches!(a[0], 0 | 1) || a[1] & !1 != 0) {
                    return Err(Errno(22));
                }
                let (request, remaining) = if number == 101 {
                    (a[0], a[1])
                } else {
                    (a[2], if a[1] & 1 == 0 { a[3] } else { 0 })
                };
                let sec = read_u64(&p.memory, request)?;
                let ns = read_u64(&p.memory, request + 8)?;
                if ns >= 1_000_000_000 || sec > i64::MAX as u64 {
                    return Err(Errno(22));
                }
                if remaining != 0 {
                    Linux::check(&p.memory, remaining, 16, Access::Write)?;
                }
                let mut duration = Duration::new(sec, ns as u32);
                if number == 115 && a[1] & 1 != 0 {
                    let now = if a[0] == 0 {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_err(|_| Errno(5))?
                    } else {
                        self.started.elapsed()
                    };
                    duration = duration.saturating_sub(now);
                }
                p.state = State::Sleep(
                    Instant::now().checked_add(duration).ok_or(Errno(22))?,
                    remaining,
                );
                Ok(None)
            }
            113 | 114 => {
                crate::worker_syscalls::clock(&mut p.memory, number, a[0], a[1], self.started)
                    .map(Some)
            }
            179 => {
                Linux::check(&p.memory, a[0], 112, Access::Write)?;
                let used = self.other_memory(p.vm_id) + p.memory.resident_bytes();
                let mut out = [0; 112];
                for (offset, value) in [
                    (0, self.started.elapsed().as_secs()),
                    (32, self.memory_limits.total as u64),
                    (40, self.memory_limits.total.saturating_sub(used) as u64),
                ] {
                    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
                for (i, load) in self.load.iter().enumerate() {
                    out[8 + i * 8..16 + i * 8]
                        .copy_from_slice(&((load * 65536.0) as u64).to_le_bytes());
                }
                out[80..82].copy_from_slice(&((self.processes.len() + 1) as u16).to_le_bytes());
                out[104..108].copy_from_slice(&1u32.to_le_bytes());
                p.memory.write(a[0], &out).map_err(|_| Errno(14))?;
                Ok(Some(0))
            }
            31 => self.ioprio_get(pid, p, a[0], a[1]).map(Some),
            132 => Self::sigaltstack(p, a[0], a[1]).map(Some),
            283 => Self::membarrier(p, a[0], a[1]).map(Some),
            163 | 164 | 261 => self.rlimit(p, number, a).map(Some),
            124 => Ok(Some(0)),
            203 if matches!(p.state, State::Blocked(203, _))
                && p.linux.vfs.local_socket(a[0] as u32)?.is_none() =>
            {
                if p.linux.resume_connect(a[0] as u32)? {
                    Ok(Some(0))
                } else if p
                    .socket_deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    Err(Errno(115))
                } else {
                    Ok(None)
                }
            }
            63 | 65 if p.linux.vfs.signalfd_mask(a[0] as u32)?.is_some() => {
                self.read_signalfd(p, number, a)
            }
            63 | 64 | 65 | 66 | 29
                if (number != 29 || a[1] as u32 != 0x5421)
                    && p.linux.vfs.fd_kind(a[0] as u32)? == FdKind::Terminal =>
            {
                self.terminal_call(pid, p, number, a, io)
            }
            _ => {
                if number == 56 {
                    if let Some(fd) = p.pending_open {
                        if p.linux.vfs.fifo_open_ready(fd)? {
                            p.pending_open = None;
                            return Ok(Some(fd as u64));
                        }
                        return Ok(None);
                    }
                }
                let trace = p.linux.trace;
                p.linux.trace = false;
                let outcome = p.linux.dispatch(&mut p.cpu, &mut p.memory, io);
                p.linux.trace = trace;
                if let SyscallOutcome::Exit(code) = outcome {
                    self.exit(pid, p, (code as i32) << 8);
                    return Ok(None);
                }
                let raw = p.cpu.x(0);
                // A blocking FIFO open reserves a hidden descriptor. Resolve its
                // rendezvous before descriptor-based PTY inspection, which must
                // reject that descriptor while the open is still pending.
                if number == 56
                    && raw < MAX_FDS as u64
                    && !p.linux.vfs.fifo_open_ready(raw as u32)?
                {
                    p.pending_open = Some(raw as u32);
                    return Ok(None);
                }
                if number == 56
                    && raw < MAX_FDS as u64
                    && a[2] & 0x100 == 0
                    && pid == p.session
                    && p.linux.vfs.controlling_terminal.is_none()
                {
                    if let Some(end) = p.linux.vfs.pty(raw as u32)?.filter(|end| !end.master) {
                        let mut tty = end.pair.terminal.borrow_mut();
                        if tty.session == 0 {
                            tty.session = p.session;
                            tty.foreground = p.group;
                            p.linux.vfs.set_controlling_terminal(Some(end.pair.id))?;
                        }
                    }
                }
                if number == 25 && a[1] == 7 && raw == error(Errno(11)) {
                    let mut owner = p.linux.record_lock_holder(&p.memory, a)?;
                    let mut visited = Vec::new();
                    while let Some(id) = owner {
                        if id == p.tgid {
                            return Err(Errno(35));
                        }
                        if visited.contains(&id) {
                            break;
                        }
                        visited.push(id);
                        owner = self.processes.values().find_map(|other| {
                            if other.tgid == id {
                                if let State::Blocked(25, a) = other.state {
                                    if a[1] == 7 {
                                        return other
                                            .linux
                                            .record_lock_holder(&other.memory, a)
                                            .ok()
                                            .flatten();
                                    }
                                }
                            }
                            None
                        });
                    }
                }
                let per_call_nonblock = match number {
                    76 => a[5] & 2 != 0 || p.linux.vfs.flags(a[2] as u32)? & O_NONBLOCK != 0,
                    206 => a[3] & 0x40 != 0,
                    207 => a[3] & (0x40 | 0x2000) != 0,
                    211 => a[2] & 0x40 != 0,
                    212 => a[2] & (0x40 | 0x2000) != 0,
                    _ => false,
                };
                if number == 116 && a[0] as u32 == 2 && raw == error(Errno(11)) {
                    return Ok(None);
                }
                if ((raw == error(Errno(11))
                    && matches!(
                        number,
                        63 | 64 | 65 | 66 | 71 | 76 | 202 | 203 | 242 | 206 | 207 | 211 | 212
                    )
                    && !per_call_nonblock)
                    || (raw == error(Errno(115)) && number == 203)
                    || (raw == error(Errno(11)) && number == 25 && a[1] == 7))
                    && (number == 25 || p.linux.vfs.flags(a[0] as u32)? & O_NONBLOCK == 0)
                {
                    if !matches!(p.state, State::Blocked(..)) {
                        p.socket_deadline = match number {
                            63 | 65 | 202 | 242 | 207 | 212 => Some(true),
                            64 | 66 | 203 | 206 | 211 => Some(false),
                            _ => None,
                        }
                        .and_then(|receive| {
                            p.linux
                                .vfs
                                .socket_fd(a[0] as u32)
                                .ok()
                                .and_then(|socket| socket.io_timeout(receive))
                        })
                        .and_then(|duration| Instant::now().checked_add(duration));
                    }
                    if p.socket_deadline
                        .is_some_and(|deadline| Instant::now() >= deadline)
                    {
                        return Ok(Some(raw));
                    }
                    Ok(None)
                } else {
                    Ok(Some(raw))
                }
            }
        }
    }
    fn call(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
        io: &mut impl GuestOutput,
    ) {
        if p.byte_wait.as_ref().is_some_and(|wait| {
            !wait.signal.ready()
                && !wait
                    .wake_deadline()
                    .is_some_and(|deadline| Instant::now() >= deadline)
        }) {
            return;
        }
        let began = self.profile_syscalls.then(Instant::now);
        self.syscalls += 1;
        if !matches!(p.state, State::Blocked(..)) && self.filter_syscall(pid, p, number, a) {
            return;
        }
        p.linux.vfs.set_process_context(pid);
        p.linux.vfs.set_lock_owner(p.tgid);
        p.linux.vfs.set_file_size_limit(p.file_size_limit.get().0);
        let proc_path = match number {
            27 => Some((trames_vfs::AT_FDCWD, a[1])),
            43 | 45 | 221 => Some((trames_vfs::AT_FDCWD, a[0])),
            48 | 53 | 54 | 56 | 78 | 79 | 88 | 281 | 291 | 437 | 439 | 452 => {
                Some((a[0] as i32, a[1]))
            }
            _ => None,
        };
        let reads_proc = matches!(number, 39..=41) || proc_path.is_some_and(|(dirfd, address)| {
            p.memory.read_c_string(address, 4096).is_ok_and(|path| {
                p.linux.vfs.accesses_proc(dirfd, &path)
            })
        }) || (matches!(number, 44 | 61 | 63 | 65 | 67 | 69 | 78 | 80)
            && p.linux.vfs.fd_kind(a[0] as u32).is_ok_and(|kind| {
                matches!(kind, FdKind::Node(path) if path == b"/proc" || path.starts_with(b"/proc/"))
            }));
        if reads_proc {
            self.proc_refreshes += 1;
            self.refresh_proc(pid, p);
        }
        let was_blocked = matches!(p.state, State::Blocked(..));
        p.cpu.set_x(8, number as u64);
        put_args(&mut p.cpu, a);
        let ids = |c: &trames_vfs::Credentials| [c.euid, c.egid, c.fsuid, c.fsgid];
        let before_ids = ids(&p.linux.vfs.credentials);
        let byte = if matches!(number, 63..=66) {
            let direct =
                trames_linux::DirectSyscalls::default().with_membership(p.linux.vfs.shared_files());
            if let Some(wait) = p.byte_wait.take() {
                Some(direct.resume_owned_byte(wait, &mut p.memory))
            } else {
                direct.start_owned_byte(
                    p.retained_byte.take(),
                    number,
                    a,
                    &mut p.memory,
                    pid,
                    &Arc::downgrade(&self.byte_target),
                )
            }
        } else {
            None
        };
        let result = match byte {
            Some(trames_linux::IoAttempt::Complete(result)) => result.map(Some),
            Some(trames_linux::IoAttempt::Blocked(wait)) => {
                p.byte_wait = Some(wait);
                Ok(None)
            }
            Some(trames_linux::IoAttempt::Checkpoint) => {
                unreachable!("joined shared byte call")
            }
            None => self.syscall(pid, p, number, a, io),
        };
        if ids(&p.linux.vfs.credentials) != before_ids {
            p.pdeath_signal = 0;
        }
        let raw = match result {
            Ok(Some(raw)) => {
                p.cpu.set_x(0, raw);
                p.state = State::Ready;
                p.socket_deadline = None;
                Some(raw)
            }
            Ok(None) => {
                if matches!(p.state, State::Ready) && !matches!(number, 221 | 281 | 139 | 93 | 94) {
                    p.state = State::Blocked(number, a);
                    put_args(&mut p.cpu, a);
                }
                None
            }
            Err(e) => {
                p.socket_deadline = None;
                if matches!(number, 22 | 72 | 73 | 441) {
                    // A failed poll ends its wait just as a successful return
                    // does. Do not leak its deadline or temporary signal mask
                    // into a later read, poll, or runnable CPU epoch.
                    p.poll_deadline = None;
                    p.retained_poll = None;
                    p.retained_select = None;
                    if let Some(mask) = p.poll_mask.take() {
                        p.signals.mask = mask;
                    }
                }
                if matches!(e.0, 38 | 95) {
                    p.linux.vfs.log_syscall(
                        number as u64,
                        p.cpu.pc().saturating_sub(4),
                        a,
                        e.0,
                        &p.linux.command_name,
                    );
                }
                let raw = error(e);
                p.cpu.set_x(0, raw);
                p.state = State::Ready;
                Some(raw)
            }
        };
        let signal_pipe = match number {
            64 | 66 | 71 | 76 => true,
            206 => a[3] & 0x4000 == 0,
            211 => a[2] & 0x4000 == 0,
            _ => false,
        };
        if signal_pipe && raw == Some(error(Errno(32))) {
            Self::queue_one(pid, p, 13, pid);
        }
        if p.linux.vfs.take_file_size_signal() {
            Self::queue_one(pid, p, 25, pid);
        }
        for target in p.linux.vfs.take_cgroup_kills() {
            if target == pid {
                Self::queue_one(pid, p, 9, 0);
            } else if let Some(task) = self.processes.get_mut(&target) {
                Self::queue_one(target, task, 9, 0);
            }
        }
        if p.linux.trace && !(raw.is_none() && matches!(p.state, State::Blocked(..)) && was_blocked)
        {
            eprintln!(
                "trames pid {pid} syscall {number}({:#x}, {:#x}, {:#x}) = {}",
                a[0],
                a[1],
                a[2],
                raw.map_or_else(|| "suspended/replaced".into(), |v| (v as i64).to_string())
            );
        }
        if let Some(began) = began {
            self.syscall_total += began.elapsed();
        }
    }
    fn waits_for_host_stdin(p: &Process<C>) -> bool {
        match p.state {
            State::Blocked(63 | 65, a) => {
                p.linux.vfs.fd_kind(a[0] as u32).ok() == Some(FdKind::Stdin)
            }
            State::Blocked(73, _) => p
                .retained_poll
                .as_ref()
                .is_some_and(|poll| poll.waits_for_stdin(&p.linux.vfs)),
            State::Blocked(72, _) => p
                .retained_select
                .as_ref()
                .is_some_and(|select| select.waits_for_stdin(&p.linux.vfs)),
            State::Blocked(22 | 441, a) => p
                .linux
                .vfs
                .epoll_waits_for_stdin(a[0] as u32)
                .unwrap_or(false),
            _ => false,
        }
    }
    fn readiness(
        &self,
        p: &Process<C>,
        fd: u32,
        events: u16,
        io: &mut impl GuestOutput,
    ) -> Result<u16, Errno> {
        let kind = p.linux.vfs.fd_kind(fd);
        let ready = match kind {
            Ok(FdKind::Stdin) => {
                if io.stdin_ready().map_err(|_| Errno(5))? {
                    events & 1
                } else {
                    0
                }
            }
            Ok(FdKind::Terminal) => {
                if let Some(end) = p.linux.vfs.pty(fd)? {
                    return Ok(end.pair.poll(end.master, events));
                }
                let t = self.terminal.as_ref().ok_or(Errno(25))?;
                (events & 4) | if t.readable() { events & 1 } else { 0 }
            }
            _ => p.linux.vfs.poll_signals(fd, events, p.pending_bits()),
        };
        Ok(ready)
    }
    fn poll(
        &mut self,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
        io: &mut impl GuestOutput,
    ) -> Result<Option<u64>, Errno> {
        let timeout = if number == 73 { a[2] } else { a[4] };
        let mut expired = false;
        if timeout != 0 && p.retained_poll.is_none() && p.retained_select.is_none() {
            let sec = read_u64(&p.memory, timeout)?;
            let ns = read_u64(&p.memory, timeout + 8)?;
            if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
                return Err(Errno(22));
            }
            if p.poll_deadline.is_none() {
                p.poll_deadline = Some(
                    Instant::now()
                        .checked_add(Duration::new(sec, ns as u32))
                        .ok_or(Errno(22))?,
                );
            }
        }
        expired |= p.poll_deadline.is_some_and(|d| Instant::now() >= d);
        let mask = if p.retained_poll.is_some() || p.retained_select.is_some() {
            None
        } else if number == 73 {
            if a[3] != 0 {
                if a[4] != 8 {
                    return Err(Errno(22));
                }
                Some(read_u64(&p.memory, a[3])?)
            } else {
                None
            }
        } else if a[5] != 0 {
            let ptr = read_u64(&p.memory, a[5])?;
            let len = read_u64(&p.memory, a[5] + 8)?;
            if ptr != 0 {
                if len != 8 {
                    return Err(Errno(22));
                }
                Some(read_u64(&p.memory, ptr)?)
            } else {
                None
            }
        } else {
            None
        };
        let mut count = 0;
        let mut outputs = Vec::new();
        if number == 73 {
            let poll = match p.retained_poll.take() {
                Some(poll) => poll,
                None => trames_linux::RetainedPoll::prepare_joined(&p.linux.vfs, &p.memory, a)?,
            };
            let rows = poll.ready_joined(|fd, original, events| {
                if !p.linux.vfs.matches_open_description(fd, original) {
                    return Ok(32);
                }
                self.readiness(p, fd, events, io)
            })?;
            for (address, ready) in rows {
                if ready != 0 {
                    count += 1;
                }
                outputs.push((address, ready.to_le_bytes().to_vec()));
            }
            p.retained_poll = Some(poll);
        } else {
            let select = match p.retained_select.take() {
                Some(select) => select,
                None => trames_linux::RetainedSelect::prepare_joined(&p.linux.vfs, &p.memory, a)?,
            };
            (count, outputs) = select.ready_joined(|fd, original, events| {
                if !p.linux.vfs.matches_open_description(fd, original) {
                    return Ok(32);
                }
                self.readiness(p, fd, events, io)
            })?;
            p.retained_select = Some(select);
        }
        if count != 0 || expired {
            for (ptr, bytes) in outputs {
                p.memory.write(ptr, &bytes).map_err(|_| Errno(14))?;
            }
            if let Some(old) = p.poll_mask.take() {
                p.signals.mask = old;
            }
            p.poll_deadline = None;
            p.retained_poll = None;
            p.retained_select = None;
            Ok(Some(count))
        } else {
            if let Some(mask) = mask {
                if p.poll_mask.is_none() {
                    p.poll_mask = Some(p.signals.mask);
                }
                p.signals.mask = mask & !UNBLOCKABLE;
            }
            Ok(None)
        }
    }
    fn terminal_signal(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        session: u32,
        group: u32,
        signal: u32,
    ) {
        if session == 0 || group == 0 {
            return;
        }
        if p.session == session && p.group == group {
            Self::queue_one(pid, p, signal, 0);
        }
        for (&id, other) in self.processes.iter_mut() {
            if other.session == session && other.group == group {
                Self::queue_one(id, other, signal, 0);
            }
        }
    }
    fn terminal_call(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
        io: &mut impl GuestOutput,
    ) -> Result<Option<u64>, Errno> {
        let flags = p.linux.vfs.flags(a[0] as u32)?;
        if flags & trames_vfs::O_PATH != 0 {
            return Err(Errno(9));
        }
        if matches!(number, 63 | 65) && flags & 3 == 1
            || matches!(number, 64 | 66) && flags & 3 == 0
        {
            return Err(Errno(9));
        }
        let endpoint = p.linux.vfs.pty(a[0] as u32)?;
        let master = endpoint.as_ref().is_some_and(|end| end.master);
        let id = endpoint.as_ref().map_or(0, |end| end.pair.id);
        if number == 29 {
            let request = a[1] as u32;
            if matches!(
                request,
                0x80045430 | 0x40045431 | 0x80045439 | 0x5420 | 0x80045438 | 0x5441
            ) {
                let end = endpoint
                    .as_ref()
                    .filter(|end| end.master)
                    .ok_or(Errno(25))?;
                match request {
                    0x80045430 => write_u32(&mut p.memory, a[2], end.pair.number)?,
                    0x40045431 => end.pair.locked.set(read_u32(&p.memory, a[2])? != 0),
                    0x80045439 => write_u32(&mut p.memory, a[2], u32::from(end.pair.locked.get()))?,
                    0x5420 => {
                        end.pair.packet.store(
                            read_u32(&p.memory, a[2])? != 0,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        end.pair
                            .packet_status
                            .store(0, std::sync::atomic::Ordering::Relaxed);
                    }
                    0x80045438 => write_u32(
                        &mut p.memory,
                        a[2],
                        u32::from(end.pair.packet.load(std::sync::atomic::Ordering::Relaxed)),
                    )?,
                    0x5441 => {
                        return p
                            .linux
                            .vfs
                            .open_pty_peer(a[0] as u32, a[2] as u32)
                            .map(|fd| Some(fd as u64))
                    }
                    _ => unreachable!(),
                }
                return Ok(Some(0));
            }
        }
        let mut dynamic = endpoint.as_ref().map(|end| end.pair.terminal.borrow_mut());
        let tty = match dynamic.as_mut() {
            Some(tty) => &mut **tty,
            None => self.terminal.as_mut().ok_or(Errno(25))?,
        };
        if number == 63 || number == 65 {
            let (parts, count) = if number == 65 {
                Linux::readv_parts(&p.memory, a)?
            } else {
                let count = a[2].min(MAX_WRITE as u64) as usize;
                Linux::check(&p.memory, a[1], count, Access::Write)?;
                (vec![(a[1], count)], count)
            };
            if count == 0 {
                return Ok(Some(0));
            }
            if master {
                drop(dynamic);
                return match endpoint.as_ref().expect("master").pair.master_read(count) {
                    Ok(bytes) => {
                        Linux::scatter(&mut p.memory, &parts, &bytes)?;
                        Ok(Some(bytes.len() as u64))
                    }
                    Err(Errno(11)) if p.linux.vfs.flags(a[0] as u32)? & O_NONBLOCK == 0 => Ok(None),
                    Err(e) => Err(e),
                };
            }
            if endpoint.as_ref().is_some_and(|end| {
                !end.pair
                    .master_alive
                    .load(std::sync::atomic::Ordering::Relaxed)
            }) {
                return Ok(Some(0));
            }
            if p.linux.vfs.controlling_terminal == Some(id)
                && p.session == tty.session
                && p.group != tty.foreground
            {
                if p.signals.mask & (1 << 20) != 0 || p.signals.actions.get(21).handler == 1 {
                    return Err(Errno(5));
                }
                let group = p.group;
                let session = tty.session;
                self.terminal_signal(pid, p, session, group, 21);
                return Ok(None);
            }
            match tty.read(count) {
                Ok(bytes) => {
                    Linux::scatter(&mut p.memory, &parts, &bytes)?;
                    Ok(Some(bytes.len() as u64))
                }
                Err(Errno(11)) if p.linux.vfs.flags(a[0] as u32)? & O_NONBLOCK == 0 => Ok(None),
                Err(e) => Err(e),
            }
        } else if number == 64 || number == 66 {
            let mut bytes = Vec::new();
            if number == 64 {
                let count = a[2].min(MAX_WRITE as u64) as usize;
                Linux::check(&p.memory, a[1], count, Access::Read)?;
                bytes.resize(count, 0);
                p.memory.read(a[1], &mut bytes).map_err(|_| Errno(14))?;
            } else {
                if a[2] > 1024 {
                    return Err(Errno(22));
                }
                Linux::check(&p.memory, a[1], a[2] as usize * 16, Access::Read)?;
                let mut vectors = Vec::new();
                let mut total = 0;
                for i in 0..a[2] {
                    let ptr = read_u64(&p.memory, a[1] + i * 16)?;
                    let len = read_u64(&p.memory, a[1] + i * 16 + 8)?;
                    if len > i64::MAX as u64 {
                        return Err(Errno(22));
                    }
                    let count = len.min((MAX_WRITE - total) as u64) as usize;
                    Linux::check(&p.memory, ptr, count, Access::Read)?;
                    vectors.push((ptr, count));
                    total += count;
                }
                for (ptr, count) in vectors {
                    let start = bytes.len();
                    bytes.resize(start + count, 0);
                    p.memory
                        .read(ptr, &mut bytes[start..])
                        .map_err(|_| Errno(14))?;
                }
            }
            if master {
                let group = tty.foreground;
                let session = tty.session;
                drop(dynamic);
                let (count, signals) =
                    match endpoint.as_ref().expect("master").pair.master_write(&bytes) {
                        Err(Errno(11)) if flags & O_NONBLOCK == 0 => return Ok(None),
                        result => result?,
                    };
                for sig in signals {
                    if group != 0 {
                        self.terminal_signal(pid, p, session, group, sig);
                    }
                }
                return Ok(Some(count as u64));
            }
            if endpoint.as_ref().is_some_and(|end| {
                !end.pair
                    .master_alive
                    .load(std::sync::atomic::Ordering::Relaxed)
            }) {
                return Err(Errno(5));
            }
            if p.linux.vfs.controlling_terminal == Some(id)
                && p.session == tty.session
                && tty.lflag() & 256 != 0
                && p.group != tty.foreground
                && p.signals.mask & (1 << 21) == 0
                && p.signals.actions.get(22).handler != 1
            {
                let group = p.group;
                let session = tty.session;
                self.terminal_signal(pid, p, session, group, 22);
                return Ok(None);
            }
            let count = match tty.queue_output(&bytes) {
                Err(Errno(11)) if p.linux.vfs.flags(a[0] as u32)? & O_NONBLOCK == 0 => {
                    return Ok(None)
                }
                result => result?,
            };
            let _ = io;
            Ok(Some(count as u64))
        } else {
            let request = a[1] as u32;
            if matches!(request, 0x540f | 0x5410 | 0x5429)
                && !master
                && (p.session != tty.session || p.linux.vfs.controlling_terminal != Some(id))
            {
                return Err(Errno(25));
            }
            if !master
                && p.linux.vfs.controlling_terminal == Some(id)
                && p.session == tty.session
                && p.group != tty.foreground
                && matches!(request, 0x5402..=0x5404 | 0x5410)
                && p.signals.mask & (1 << 21) == 0
                && p.signals.actions.get(22).handler != 1
            {
                let group = p.group;
                let session = tty.session;
                self.terminal_signal(pid, p, session, group, 22);
                return Ok(None);
            }
            match request {
                0x5401 => {
                    Linux::check(&p.memory, a[2], 36, Access::Write)?;
                    p.memory
                        .write(a[2], &tty.attributes)
                        .map_err(|_| Errno(14))?;
                }
                0x5402..=0x5404 => {
                    let mut attr = [0; 36];
                    p.memory.read(a[2], &mut attr).map_err(|_| Errno(14))?;
                    if attr[22] != 0 {
                        return Err(Errno(95));
                    }
                    tty.attributes = attr;
                    if request == 0x5404 {
                        tty.flush_input();
                    }
                }
                0x540f => {
                    p.memory
                        .write(a[2], &p.linux.vfs.visible_pid(tty.foreground).to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                0x5410 => {
                    let group = read_u32(&p.memory, a[2])?;
                    if group == 0 || group > i32::MAX as u32 {
                        return Err(Errno(22));
                    }
                    let group = p.linux.vfs.global_pid(group).map_err(|_| Errno(1))?;
                    if group != p.group
                        && !self
                            .processes
                            .values()
                            .any(|c| c.group == group && c.session == p.session)
                    {
                        return Err(Errno(1));
                    }
                    tty.foreground = group;
                }
                0x5413 => {
                    p.memory.write(a[2], &tty.window).map_err(|_| Errno(14))?;
                }
                0x5414 => {
                    let mut window = [0; 8];
                    p.memory.read(a[2], &mut window).map_err(|_| Errno(14))?;
                    let changed = tty.window != window;
                    tty.window = window;
                    if changed {
                        let group = tty.foreground;
                        let session = tty.session;
                        self.terminal_signal(pid, p, session, group, 28);
                    }
                }
                0x541b => {
                    p.memory
                        .write(
                            a[2],
                            &(if master {
                                tty.output_queue.len()
                            } else {
                                tty.available()
                            } as u32)
                                .to_le_bytes(),
                        )
                        .map_err(|_| Errno(14))?;
                }
                0x540e => {
                    if master
                        || pid != p.session
                        || p.linux
                            .vfs
                            .controlling_terminal
                            .is_some_and(|old| old != id)
                    {
                        return Err(Errno(1));
                    }
                    if tty.session != 0
                        && tty.session != p.session
                        && self.processes.values().any(|other| {
                            other.session == tty.session
                                && other.linux.vfs.controlling_terminal == Some(id)
                        })
                        && !(a[2] == 1 && p.linux.vfs.credentials.has_cap(capabilities::SYS_ADMIN))
                    {
                        return Err(Errno(1));
                    }
                    tty.session = p.session;
                    tty.foreground = p.group;
                    p.linux.vfs.set_controlling_terminal(Some(id))?;
                }
                0x5429 => write_u32(&mut p.memory, a[2], p.linux.vfs.visible_pid(tty.session))?,
                0x5422 => {
                    if p.linux.vfs.controlling_terminal != Some(id) {
                        return Err(Errno(25));
                    }
                    p.linux.vfs.set_controlling_terminal(None)?;
                    if pid == tty.session {
                        tty.session = 0;
                    }
                }
                0x540b => {
                    if a[2] > 2 {
                        return Err(Errno(22));
                    }
                    if a[2] == 0 || a[2] == 2 {
                        tty.flush_input();
                    }
                    if a[2] == 1 || a[2] == 2 {
                        tty.output_queue.clear();
                        tty.output_space_epoch = tty.output_space_epoch.wrapping_add(1);
                    }
                }
                _ => return Err(Errno(25)),
            }
            Ok(Some(0))
        }
    }
    fn pump_guest_ptys(&mut self) {
        let pairs = self
            .processes
            .values()
            .next()
            .map(|p| p.linux.vfs.live_ptys())
            .unwrap_or_default();
        for pair in pairs {
            pair.flush_echo();
            if pair.host_resize_pending.replace(false) {
                pair.host_signals.set(pair.host_signals.get() | (1 << 27));
            }
            let signals = pair.host_signals.replace(0);
            if signals != 0 {
                let tty = pair.terminal.borrow();
                for (&pid, process) in &mut self.processes {
                    if tty.session != 0
                        && process.session == tty.session
                        && process.group == tty.foreground
                    {
                        for sig in 1..=64 {
                            if signals & (1 << (sig - 1)) != 0 {
                                Self::queue_one(pid, process, sig, 0);
                            }
                        }
                    }
                }
            }
            if pair.master_alive.load(std::sync::atomic::Ordering::Relaxed)
                || pair.hangup_notified.replace(true)
            {
                continue;
            }
            let mut tty = pair.terminal.borrow_mut();
            let (session, group) = (tty.session, tty.foreground);
            tty.flush_input();
            tty.eof = true;
            tty.session = 0;
            tty.foreground = 0;
            drop(tty);
            for (&pid, process) in self.processes.iter_mut() {
                if process.linux.vfs.controlling_terminal == Some(pair.id) {
                    process
                        .linux
                        .vfs
                        .set_controlling_terminal(None)
                        .expect("detach");
                }
                if session != 0
                    && process.session == session
                    && (pid == session || process.group == group)
                {
                    Self::queue_one(pid, process, 1, 0);
                    Self::queue_one(pid, process, 18, 0);
                }
            }
        }
    }
    fn pump_terminal(&mut self, io: &mut impl GuestOutput) -> Result<bool, RuntimeError> {
        let Some(tty) = self.terminal.as_mut() else {
            return Ok(false);
        };
        let mut input = [0; 4096];
        let mut progress = false;
        let capacity = tty.input_capacity().min(input.len());
        let mut signals = if capacity == 0 {
            Vec::new()
        } else {
            match io.poll_stdin(&mut input[..capacity]) {
                Ok(0) => {
                    let changed = !tty.eof;
                    tty.eof = true;
                    progress |= changed;
                    Vec::new()
                }
                Ok(n) if n <= capacity => {
                    progress = true;
                    tty.input(&input[..n])
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Vec::new(),
                _ => return Err(RuntimeError::Arguments("terminal master input failed")),
            }
        };
        for _ in 0..16 {
            match io.terminal_event() {
                Some(TerminalEvent::Resize { rows, columns }) => {
                    let old = tty.window;
                    tty.resize(rows, columns);
                    if old != tty.window {
                        signals.push(28);
                        progress = true;
                    }
                }
                Some(TerminalEvent::Signal(sig)) if sig > 0 && sig <= 64 => {
                    signals.push(sig);
                    progress = true;
                }
                None => break,
                _ => {}
            }
        }
        let group = tty.foreground;
        let echo = std::mem::take(&mut tty.echo);
        if !echo.is_empty() {
            let consumed = match tty.queue_output(&echo) {
                Ok(n) => n,
                Err(Errno(11)) => 0,
                Err(_) => return Err(RuntimeError::Arguments("terminal echo failed")),
            };
            tty.echo = echo[consumed..].to_vec();
        }
        let bytes: Vec<_> = if tty.flow_stopped {
            Vec::new()
        } else {
            tty.output_queue.iter().copied().take(4096).collect()
        };
        if !bytes.is_empty() {
            match io.write(OutputFd::Stdout, &bytes) {
                Ok(n) if n <= bytes.len() => {
                    tty.drain_output(n);
                    progress |= n != 0;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                _ => return Err(RuntimeError::Arguments("terminal master output failed")),
            }
        }
        for sig in signals {
            for (&pid, p) in &mut self.processes {
                if p.group == group {
                    Self::queue_one(pid, p, sig, 0);
                }
            }
        }
        Ok(progress)
    }
    fn finish_slice(
        &mut self,
        id: u32,
        p: &mut Process<C>,
        outcome: SliceOutcome,
        io: &mut impl GuestOutput,
        account: bool,
    ) -> bool {
        let mut immediate_return = false;
        match outcome {
            SliceOutcome::Fault(e) => {
                if p.linux.trace {
                    eprintln!("trames pid {id}: {e}");
                }
                if account {
                    self.instructions += p.cpu.fault_retired();
                }
                self.synchronous_fault(id, p, &e);
            }
            SliceOutcome::Yield { instructions } => {
                if account {
                    self.instructions += instructions
                }
            }
            SliceOutcome::NativeCall {
                instructions,
                pc,
                module,
                function,
            } => {
                p.cpu.clear_exclusive();
                if account {
                    self.instructions += instructions
                };
                let began = Instant::now();
                let a = [p.cpu.x(0), p.cpu.x(1), p.cpu.x(2)];
                // Views can defer before effects when code changes during
                // validation or backing writes need coordinator authority. A
                // joined coordinator revalidates with a bounded retry.
                let mut result = self.native_call(p, pc, module, function, a);
                for _ in 0..2 {
                    if !matches!(result, Err(trames_accel::native::Error::Checkpoint)) {
                        break;
                    }
                    result = self.native_call(p, pc, module, function, a);
                }
                match result {
                    Ok(Some(value)) => {
                        p.cpu.set_x(0, value.value);
                        p.cpu.set_x(1, u64::from(value.fallback));
                        p.cpu.set_pc(pc + 4);
                        self.instructions += 1;
                        immediate_return = true;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        use trames_accel::native::Error;
                        let fault = match error {
                            Error::Memory(error) => trames_engine::CpuFault::Memory { pc, error },
                            Error::InvalidEntry | Error::Checkpoint => {
                                p.linux.vfs.log(4, &format!("pid={id} NativeCall rejected module={module:#x} function={function} pc={pc:#x} comm={:?}", String::from_utf8_lossy(&p.linux.command_name)));
                                trames_engine::CpuFault::Trap {
                                    pc,
                                    instruction: trames_accel::native::INSTRUCTION,
                                    signal: 4,
                                    code: 1,
                                }
                            }
                        };
                        self.synchronous_fault(id, p, &fault);
                    }
                }
                let elapsed = began.elapsed();
                p.cpu_time += elapsed;
                self.cpu_total += elapsed;
                self.per_cpu[p.last_cpu] += elapsed;
            }
            SliceOutcome::Syscall { instructions } => {
                p.cpu.clear_exclusive();
                if account {
                    self.instructions += instructions
                };
                let number = p.cpu.x(8) as u32;
                let a = args(&p.cpu);
                let return_pc = p.cpu.pc();
                self.call(id, p, number, a, io);
                // Pure queries have no scheduling/FD/mapping effects. Keep the
                // serial quantum just as workers keep theirs, rather than scan
                // every blocked task after each TimeStamp/getpid query. The
                // normal time/instruction/return bounds still poll control and
                // timers; a delivered/pending signal must return to the kernel.
                immediate_return = matches!(number, 113 | 114 | 168 | 172..=178)
                    && matches!(p.state, State::Ready)
                    && p.cpu.pc() == return_pc
                    && p.pending_bits() & (!p.signals.mask | UNBLOCKABLE) == 0;
            }
        }
        immediate_return
    }
    fn prepare_parallel_views(
        &mut self,
        chosen: &[(u32, usize)],
    ) -> Option<Vec<(u32, usize, Box<trames_memory::parallel::View>)>> {
        let mut views: Vec<(u32, usize, Box<trames_memory::parallel::View>)> =
            Vec::with_capacity(chosen.len());
        let mut published = BTreeMap::<u64, usize>::new();
        for &(id, slot) in chosen {
            let p = self.processes.get_mut(&id).expect("selected process");
            let (identity, _) = p.memory.coordinator_ownership();
            let view = if let Some(&index) = published.get(&identity) {
                // Freeze one VM once per epoch. Backing checks of another VM
                // may advance a global epoch between selected CPU preparations;
                // they must not give this VM's peers different snapshots.
                self.parallel_memory.metrics.cache_hits += 1;
                views[index].2.clone()
            } else {
                if let Err(error) =
                    C::prepare_hardware_memory(&mut p.memory, &mut self.parallel_memory)
                {
                    self.backend_error = Some(error.to_string());
                    return None;
                }
                let mut view = Box::new(p.memory.parallel_view(&mut self.parallel_memory)?);
                C::prepare_hardware_view(&mut view);
                published.insert(identity, views.len());
                view
            };
            views.push((id, slot, view));
        }
        Some(views)
    }
    fn admit_private_views(
        &mut self,
        views: &mut [(u32, usize, Box<trames_memory::parallel::View>)],
    ) {
        // Count actual Memory roots, including blocked/zombie processes. vm_id
        // alone cannot detect a retired handle or an alias in a host callback.
        let mut spaces = BTreeMap::<u64, (usize, usize)>::new();
        for p in self.processes.values() {
            let (identity, owners) = p.memory.coordinator_ownership();
            let counts = spaces.entry(identity).or_default();
            counts.0 += 1;
            counts.1 = owners;
        }
        let mut groups = BTreeMap::<u64, Vec<&mut trames_memory::parallel::View>>::new();
        for (id, _, view) in views {
            let (identity, _) = self.processes[id].memory.coordinator_ownership();
            groups.entry(identity).or_default().push(view.as_mut());
        }
        for (identity, mut group) in groups {
            let (local, owners) = spaces[&identity];
            if local != owners {
                continue;
            }
            // SAFETY: all Views have been prepared before dispatch, this group
            // contains every chosen CPU of this VM and every coordinate handle
            // belongs to this Kernel. All runnable/parked cohort Views are
            // prepared here; moving their owned Box does not clone a View.
            // Maps/signals and coordinate byte access wait for the whole cohort
            // to stop and release its Views. Worker futex reads use their own
            // View and queue synchronization, never coordinate bytes. Services take
            // this very View while its CPU is parked, never another byte owner;
            // async disk jobs use host buffers only. Admission requires matching
            // snapshots and no external View in any generation. Multiple CPUs
            // can bypass locks only for immutable, physically private frames;
            // shared/custom/retained fork storage and RW frames remain guarded.
            if unsafe { trames_memory::parallel::View::try_private_epoch(&mut group) } {
                if group.len() == 1 {
                    self.parallel_memory.metrics.exclusive_private_views += 1;
                } else {
                    self.parallel_memory.metrics.readonly_private_views += group.len() as u64;
                }
            }
        }
    }
    fn parallel_candidate(&self) -> bool {
        let mut active = self.processes.iter().filter(|(id, p)| {
            (matches!(p.state, State::Ready) || p.worker_gpu_candidate()) && !p.frozen(**id)
        });
        let Some((&id, first)) = active.next() else {
            // Interactive transports can wake retained I/O while every CPU is
            // parked. The solo-CPU admission branch below remains unchanged.
            if self.terminal.is_some()
                && self
                    .processes
                    .iter()
                    .filter(|(id, p)| !p.frozen(**id) && p.worker_io_candidate(**id))
                    .take(2)
                    .count()
                    == 2
            {
                return true;
            }
            // A parked ring with a real host event or imported deadline and a
            // related peer can retain event-driven execution with every CPU
            // asleep. Unrelated terminals/timers do not change the solo gate.
            return self.processes.iter().any(|(&id, p)| {
                if p.frozen(id) || !p.worker_io_candidate(id) || !p.worker_ring_event_wait(id) {
                    return false;
                }
                let fds = p.linux.vfs.direct_descriptors();
                let network = p.linux.vfs.direct_network();
                self.processes.iter().any(|(&other, q)| {
                    other != id
                        && !q.frozen(other)
                        && q.worker_io_candidate(other)
                        && (fds.shares_resources(&q.linux.vfs.direct_descriptors())
                            || q.shares_wait_resources(&fds)
                            || network.shares_resources(&q.linux.vfs.direct_network()))
                })
            });
        };
        if first.worker_gpu_candidate() || active.next().is_some() {
            return true;
        }
        // A sleeping init pipe/idle terminal is not runnable CPU work. Keep
        // solo computation on Memory's direct MMU path unless a related task
        // can actually benefit from worker handoff. This only selects an
        // execution strategy: unmatched waits still use the ordinary kernel.
        let fds = first.linux.vfs.direct_descriptors();
        let network = first.linux.vfs.direct_network();
        self.processes.iter().any(|(&other, p)| {
            other != id
                && !p.frozen(other)
                && (matches!(p.state, State::Futex { .. }) && p.vm_id == first.vm_id
                    || p.worker_io_candidate(other)
                        && (p
                            .flock_wait
                            .as_ref()
                            .is_some_and(|(r, _)| first.linux.vfs.shares_flock(r))
                            || matches!(p.state, State::Blocked(116, _))
                                && first.linux.vfs.can_write_kernel_log_for(&p.linux.vfs)
                            || fds.shares_resources(&p.linux.vfs.direct_descriptors())
                            || p.shares_wait_resources(&fds)
                            || network.shares_resources(&p.linux.vfs.direct_network())))
        })
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    fn parallel_round(
        &mut self,
        io: &mut impl GuestOutput,
        limit: u64,
    ) -> Result<bool, RuntimeError> {
        self.parallel_epoch(io, limit, false)
    }
    fn parallel_epoch(
        &mut self,
        io: &mut impl GuestOutput,
        limit: u64,
        persistent: bool,
    ) -> Result<bool, RuntimeError> {
        if self
            .processes
            .get(&1)
            .is_some_and(|p| matches!(p.state, State::Zombie(_)))
            && !self
                .processes
                .values()
                .any(|p| p.tgid == 1 && !matches!(p.state, State::Zombie(_)))
        {
            return Ok(false);
        }
        if self.cpu_count < 2 || !self.parallel_candidate() {
            return Ok(false);
        }
        // Mapping/signal effects precede dispatch. Ready services may take a
        // parked CPU's own View; mapping mutation waits for every CPU to return.
        let ids: Vec<_> = self.processes.keys().copied().collect();
        for id in ids {
            let Some(mut p) = self.processes.remove(&id) else {
                continue;
            };
            if !matches!(p.state, State::Zombie(_)) && !p.frozen(id) {
                if !p.worker_gpu_candidate() {
                    self.resume_gpu(id, &mut p);
                }
                let local_ring = p.worker_io_candidate(id)
                    && match p.state {
                        State::Blocked(426, _) => true,
                        State::Blocked(number @ (22 | 73 | 441), args) => {
                            trames_linux::UringEpoch::poll_rings(
                                &p.linux.vfs,
                                number,
                                args,
                                &p.memory,
                                id,
                            )
                            .is_some()
                        }
                        _ => false,
                    };
                if !local_ring {
                    p.linux.progress_uring(&mut p.memory, id);
                }
                self.resume_event(&mut p);
                if self.deliver(id, &mut p).is_err() {
                    self.exit(id, &mut p, 11);
                }
                // call/control/deliver publish resource changes immediately.
                match p.state.clone() {
                    State::Blocked(..) if p.worker_io_candidate(id) => {
                        // The worker owns the retry; do not perform byte I/O in
                        // the coordinator before preparing its execution View.
                    }
                    State::Blocked(number, a) => self.call(id, &mut p, number, a, io),
                    State::Sleep(deadline, _) if Instant::now() >= deadline => {
                        p.state = State::Ready;
                        p.cpu.set_x(0, 0);
                    }
                    _ => {}
                }
            }
            let actual = p.rekey.take().unwrap_or(id);
            if !p.auto_reap || actual == 1 {
                self.processes.insert(actual, p);
            }
        }
        let mut ready: Vec<_> = self
            .processes
            .iter()
            .filter(|(id, p)| {
                (matches!(p.state, State::Ready) || p.worker_gpu_candidate()) && !p.frozen(**id)
            })
            .map(|(&id, _)| id)
            .collect();
        let rotate = ready.partition_point(|id| *id <= self.next_parallel_pid);
        ready.rotate_left(rotate);
        // Freeze a complete execution cohort before launch. Retained blocked
        // Views may move to a worker on wake, but are never cloned mid-epoch.
        let vms: std::collections::BTreeSet<_> =
            ready.iter().map(|id| self.processes[id].vm_id).collect();
        let mut members: Vec<_> = ready.iter().map(|&id| (id, 0)).collect();
        members.extend(self.processes.iter().filter_map(|(&id, p)| {
            if p.frozen(id) {
                return None;
            }
            ((matches!(p.state, State::Futex { .. }) && vms.contains(&p.vm_id))
                || p.worker_io_candidate(id))
            .then_some((id, 0))
        }));
        if members.len() < 2
            && !members
                .iter()
                .any(|(id, _)| self.processes[id].worker_gpu_candidate())
        {
            return Ok(false);
        }
        let chosen = assign_cpus(
            members
                .iter()
                .map(|(id, _)| (*id, self.processes[id].affinity)),
            self.cpu_count,
        );
        if chosen.is_empty() {
            return Ok(false);
        }
        let remaining = limit.saturating_sub(self.instructions);
        if remaining == 0 {
            return Ok(false);
        }
        let timeout = self.parallel_timeout();
        let began = Instant::now();
        let Some(mut views) = self.prepare_parallel_views(&members) else {
            return Ok(false);
        };
        self.admit_private_views(&mut views);
        self.parallel_memory_time += began.elapsed();
        for &(_, slot) in &chosen {
            self.workers
                .ensure(slot)
                .map_err(|_| RuntimeError::Arguments("cannot start CPU worker"))?;
        }
        let control = std::sync::Arc::new(crate::workers::Control::new(remaining));
        let epoch = crate::run_queue::Epoch::<C>::with_events(
            control.clone(),
            self.workers.events(),
            persistent,
        );
        let mut file_epoch = trames_vfs::FileEpoch::default();
        let mut uring_epoch = trames_linux::UringEpoch::default();
        let mut network_epoch = trames_vfs::NetworkEpoch::default();
        let began = Instant::now();
        for (id, _, view) in views {
            let p = &self.processes[&id];
            let gpu = accelerated(p, trames_vulkan::AUXV_KEY, trames_vulkan::PROFILE).then(|| {
                crate::gpu::Authority {
                    context: self.gpu_context(p),
                    auth: p.linux.vfs.wayland_auth_snapshot(),
                }
            });
            let p = self.processes.get_mut(&id).expect("cohort process");
            let waiting = if let State::Futex { wait, deadline } = &p.state {
                Some(crate::run_queue::WaitState {
                    wait: wait.clone(),
                    deadline: *deadline,
                })
            } else {
                None
            };
            let c = &p.linux.vfs.credentials;
            let direct_files = if !p.linux.trace {
                file_epoch.capture(&p.linux.vfs, p.file_size_limit.get().0 == u64::MAX)
            } else {
                Default::default()
            };
            let retained_files = if !p.linux.trace {
                file_epoch.capture_uring(&p.linux.vfs, p.file_size_limit.get().0 == u64::MAX)
            } else {
                Default::default()
            };
            let work = crate::workers::Work::<C> {
                gpu,
                pid: id,
                cpu: std::mem::take(&mut p.cpu),
                memory: Some(view),
                control: control.clone(),
                syscalls: (!p.linux.trace).then(|| crate::worker_syscalls::Snapshot {
                    seccomp: p.seccomp.clone(),
                    identities: [
                        p.linux.vfs.visible_pid(p.tgid) as u64,
                        p.linux.vfs.visible_pid(p.parent) as u64,
                        c.uid as u64,
                        c.euid as u64,
                        c.gid as u64,
                        c.egid as u64,
                        p.linux.vfs.visible_pid(id) as u64,
                    ],
                    started: self.started,
                    processor: p.last_cpu as u32,
                    profile: self.profile_syscalls,
                    streams: p.linux.vfs.stream_descriptors(),
                    files: p.linux.vfs.file_descriptors(),
                    fd_flags: p.linux.vfs.fd_flags_snapshot(),
                    umask: p.linux.vfs.umask_capability(),
                    actions: p.signals.actions.shared(),
                    program_break: p.linux.program_break(),
                    uts: Some(p.linux.vfs.uts_capability()),
                    direct: trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                        .with_membership(p.linux.vfs.shared_files())
                        .with_kernel_log(p.linux.vfs.kernel_log_capability())
                        .with_urings(uring_epoch.capture_all(
                            &p.linux.vfs,
                            p.memory.instruction_identity().0,
                            id,
                            &direct_files,
                            &retained_files,
                        ))
                        .with_network(network_epoch.capture(&p.linux.vfs))
                        .with_clock(self.started)
                        .with_terminal(trames_vfs::TerminalAccess {
                            session: p.session,
                            group: p.group,
                            controlling: p.linux.vfs.controlling_terminal,
                            ignore_ttou: p.signals.mask & (1 << 21) != 0
                                || p.signals.actions.get(22).handler == 1,
                        })
                        .with_files(direct_files)
                        .with_lock_context(p.linux.vfs.record_lock_context(p.tgid)),
                    futex: crate::futex::Authority::new(self.futexes.clone(), p.vm_id),
                }),
            };
            let mut job = crate::run_queue::Job::<C>::new(work, p.affinity, p.last_cpu, waiting);
            if let State::Blocked(426, args) = p.state {
                if job
                    .work
                    .syscalls
                    .as_ref()
                    .is_some_and(|s| s.direct.supports_call(426, args))
                {
                    if let Some((submitted, ring, deadline)) = &p.uring_wait {
                        if uring_epoch.adopt_wait(id, ring, *submitted, *deadline) {
                            p.uring_wait = None;
                        }
                    }
                }
            }
            if let State::Gpu {
                job: compile,
                pc,
                operation,
                began,
                retired: true,
                instructions,
                peer_instructions,
            } = p.state
            {
                job.gpu_pending = Some(crate::gpu::Pending::adopted(crate::gpu::Compile {
                    call: crate::gpu::Call {
                        pc,
                        operation,
                        args: [operation, 0, 0],
                    },
                    job: compile,
                    began,
                    peer_instructions: peer_instructions
                        + self.instructions.saturating_sub(instructions),
                }));
            }
            if let State::Blocked(number, args) = p.state {
                // Re-arm against the new epoch target. The owner's notification
                // target cannot schedule a parked worker in this cohort.
                let retained_byte = p
                    .byte_wait
                    .take()
                    .and_then(|wait| wait.retained_byte)
                    .or_else(|| p.retained_byte.take());
                job.retry = Some(crate::run_queue::IoCall {
                    flock: if p.flock_wait.as_ref().is_some_and(|(r, _)| r.retains_file()) {
                        // The parked owner must not delay a worker's final
                        // close/notification until the next cohort join.
                        p.flock_wait.take().map(|(request, _)| request)
                    } else {
                        p.flock_wait.as_ref().map(|(request, _)| request.clone())
                    },
                    retained_byte,
                    retained_poll: p.retained_poll.take(),
                    number,
                    args,
                    deadline: if matches!(number, 63..=66) {
                        p.socket_deadline
                    } else {
                        p.poll_deadline
                    },
                });
            }
            epoch.add(job);
        }
        // No cached connection/policy decision survives into guest execution.
        drop(network_epoch);
        epoch.assign(&chosen);
        for &(_, slot) in &chosen {
            self.workers
                .launch(slot, epoch.clone())
                .map_err(|_| RuntimeError::Arguments("CPU worker disconnected"))?;
        }
        self.parallel_dispatch_time += began.elapsed();
        let mut deadline = Instant::now() + timeout;
        let mut stopped = 0;
        let mut disk = DiskEpoch::<C>::default();
        let mut checkpoint_error = None;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                if !persistent {
                    break;
                }
                match self.cohort_control(&members, io) {
                    Ok(false) => deadline = Instant::now() + self.parallel_timeout(),
                    result => {
                        checkpoint_error = result.err();
                        break;
                    }
                }
                continue;
            }
            match self
                .workers
                .event_timeout(left)
                .map_err(|_| RuntimeError::Arguments("CPU worker failed"))?
            {
                Some(crate::workers::Event::<C>::EpochStopped(_)) => {
                    stopped += 1;
                    break;
                }
                Some(crate::workers::Event::<C>::Done(_)) => unreachable!("cohort completion"),
                Some(crate::workers::Event::<C>::VmReady) => {
                    while !control.stopped() {
                        let Some(checkpoint) = epoch.take_checkpoint() else {
                            break;
                        };
                        match self.vm_checkpoint(&epoch, checkpoint, io) {
                            Ok(true) => {}
                            result => {
                                checkpoint_error = result.err();
                                epoch.stop();
                                break;
                            }
                        }
                    }
                }
                Some(crate::workers::Event::<C>::Idle) => {
                    match self.cohort_control(&members, io) {
                        Ok(false) => {}
                        result => {
                            checkpoint_error = result.err();
                            break;
                        }
                    }
                    if self.terminal.is_none() && epoch.idle() {
                        break;
                    }
                }
                Some(crate::workers::Event::<C>::Service(request)) => {
                    self.service_requests += 1;
                    if !self.epoch_request(request, &mut disk, io) {
                        break;
                    }
                }
                Some(crate::workers::Event::<C>::DiskRead(id, result)) => {
                    self.finish_disk_read(id, result, &mut disk);
                    if !self.resume_disk_waiters(&mut disk, io) {
                        break;
                    }
                }
                None => {}
            }
        }
        epoch.stop();
        let began = Instant::now();
        // An already submitted read must finish/commit exactly once before
        // mapping, process or FD mutation. Do not wait in Pool::complete while
        // its caller is parked awaiting a disk completion on this same channel.
        for request in disk.waiting.drain(..) {
            request.respond(None);
        }
        while stopped < chosen.len() || disk.in_flight != 0 || epoch.pending_services() != 0 {
            match self
                .workers
                .event_timeout(Duration::from_secs(1))
                .map_err(|_| RuntimeError::Arguments("CPU worker failed"))?
            {
                Some(crate::workers::Event::<C>::EpochStopped(_)) => stopped += 1,
                Some(crate::workers::Event::<C>::Done(_)) => unreachable!("cohort completion"),
                Some(crate::workers::Event::<C>::VmReady | crate::workers::Event::<C>::Idle) => {}
                Some(crate::workers::Event::<C>::Service(request)) => request.respond(None),
                Some(crate::workers::Event::<C>::DiskRead(id, result)) => {
                    self.finish_disk_read(id, result, &mut disk);
                }
                None => {}
            }
        }
        self.parallel_stop_time += began.elapsed();
        let completed = epoch.drain();
        for handoff in uring_epoch.finish() {
            let p = self
                .processes
                .get_mut(&handoff.task)
                .expect("io_uring cohort task");
            p.linux.track_uring(&handoff.ring);
            if let Some(submitted) = handoff.submitted {
                p.uring_wait = Some((submitted, handoff.ring, handoff.deadline));
            }
        }
        self.gpu_peak_pending = self.gpu_peak_pending.max(epoch.gpu_peak_pending());
        file_epoch.finish();
        if let Some(error) = checkpoint_error {
            return Err(error);
        }
        if completed.iter().any(|r| r.outcome.is_none()) {
            for done in completed {
                self.processes
                    .get_mut(&done.pid)
                    .expect("dispatched process")
                    .cpu = done.cpu;
            }
            return Err(RuntimeError::Arguments("CPU worker panicked"));
        }
        // Release every cohort View and restore all CPUs/bytes before handling
        // exits/exec/fork, which may remove peers. Worker WAIT already compared
        // and enqueued under its futex bucket; completed calls are not replayed.
        let began = Instant::now();
        for (index, &(id, _)) in members.iter().enumerate() {
            let vm_id = self.processes[&id].vm_id;
            if members[..index]
                .iter()
                .any(|&(peer, _)| self.processes[&peer].vm_id == vm_id)
            {
                continue;
            }
            self.processes
                .get_mut(&id)
                .expect("dispatched process")
                .memory
                .commit_parallel()?;
        }
        self.parallel_memory_time += began.elapsed();
        let mut outcomes = Vec::new();
        for done in completed {
            self.native.metrics.merge(done.native);
            let p = self
                .processes
                .get_mut(&done.pid)
                .expect("dispatched process");
            p.cpu = done.cpu;
            p.retain_worker_flock(done.io.as_ref());
            p.retained_byte = done.io.as_ref().and_then(|call| call.retained_byte.clone());
            p.retained_poll = done.io.as_ref().and_then(|call| call.retained_poll.clone());
            p.state = if let Some(compile) = done.gpu_pending {
                State::Gpu {
                    retired: true,
                    peer_instructions: compile.peer_instructions,
                    job: compile.job,
                    pc: compile.call.pc,
                    operation: compile.call.operation,
                    began: compile.began,
                    instructions: self.instructions,
                }
            } else if let Some(call) = done.io {
                if matches!(call.number, 63..=66) {
                    p.socket_deadline = call.deadline;
                } else {
                    p.poll_deadline = call.deadline;
                }
                State::Blocked(call.number, call.args)
            } else {
                p.poll_deadline = None;
                done.waiting.map_or(State::Ready, |w| State::Futex {
                    wait: w.wait,
                    deadline: w.deadline,
                })
            };
            if let Some((pc, module, function)) = done.rejected_native {
                p.linux.vfs.log(4,&format!("pid={} NativeCall rejected module={module:#x} function={function} pc={pc:#x} comm={:?}",done.pid,String::from_utf8_lossy(&p.linux.command_name)));
            }
            p.last_cpu = done.worker;
            p.cpu_time += done.elapsed;
            self.cpu_total += done.elapsed;
            for (slot, time) in done.cpu_times.iter().take(self.cpu_count).enumerate() {
                self.per_cpu[slot] += *time;
            }
            self.decode_lookups += done.after.lookups - done.before.lookups;
            self.decode_misses += done.after.misses - done.before.misses;
            self.instructions_decoded += done.after.instructions - done.before.instructions;
            let outcome = done.outcome.expect("checked worker completion");
            self.instructions += done.instructions;
            self.worker_chunks += done.chunks;
            self.worker_syscalls += done.syscalls;
            self.worker_direct_syscalls += done.direct_syscalls;
            self.worker_futex_wakes += done.futex_wakes;
            self.worker_futex_woken += done.futex_woken;
            self.worker_futex_requeues += done.futex_requeues;
            self.serviced_syscalls += done.serviced_syscalls;
            self.service_wait += done.service_wait;
            self.syscalls += done.syscalls + done.serviced_syscalls;
            self.syscall_total += done.syscall_time;
            self.worker_slices += done.assignments;
            self.context_switches += done.assignments;
            self.worker_futex_waits += done.waits;
            self.worker_task_resumes += done.resumes;
            self.worker_task_yields += done.yields;
            self.worker_io_waits += done.io_waits;
            self.worker_service_waits += done.service_waits;
            self.worker_file_syscalls += done.file_syscalls;
            self.worker_socket_syscalls += done.socket_syscalls;
            self.worker_timer_syscalls += done.timer_syscalls;
            self.worker_poll_syscalls += done.poll_syscalls;
            self.worker_uring_syscalls += done.uring_syscalls;
            self.worker_fd_syscalls += done.fd_syscalls;
            self.worker_gpu_calls += done.gpu.calls;
            self.worker_gpu_waits += done.gpu.waits;
            self.gpu_compiles += done.gpu.compiles;
            self.gpu_wait_time += done.gpu.wait_time;
            self.gpu_peer_instructions += done.gpu.peer_instructions;
            self.gpu_transfers.upload_bytes += done.gpu.transfers.upload_bytes;
            self.gpu_transfers.download_bytes += done.gpu.transfers.download_bytes;
            self.gpu_transfers.direct_bytes += done.gpu.transfers.direct_bytes;
            self.gpu_transfers.buffered_bytes += done.gpu.transfers.buffered_bytes;
            if let Some((pc, operation, value)) = done.gpu.last_error {
                p.linux.vfs.log(
                    4,
                    &format!(
                        "pid={} Vulkan op={operation} result={} pc={pc:#x} errors={} comm={:?}",
                        done.pid,
                        value as i64,
                        done.gpu.errors,
                        String::from_utf8_lossy(&p.linux.command_name)
                    ),
                );
            }
            outcomes.push((done.pid, outcome));
        }
        self.parallel_rounds += 1;
        self.next_parallel_pid = chosen.last().expect("two workers").0;
        // Successful worker wakes are already committed. Publish readiness
        // before any returned syscall (requeue/exit/signal) can change tasks.
        self.resume_futex_ready();
        outcomes.sort_by_key(|v| v.0);
        for (id, _) in &outcomes {
            if let State::Gpu {
                retired: true,
                instructions,
                ..
            } = &mut self.processes.get_mut(id).unwrap().state
            {
                *instructions = self.instructions;
            }
        }
        for (id, outcome) in outcomes {
            let Some(mut p) = self.processes.remove(&id) else {
                continue;
            };
            // A preceding exit_group/exec may have killed this returned peer.
            if !matches!(p.state, State::Zombie(_)) {
                // KILL queued by a preceding cgroup.kill cannot permit an
                // uncommitted fork to create a survivor outside its snapshot.
                if p.pending_bits() & (1 << 8) != 0 {
                    let _ = self.deliver(id, &mut p);
                } else {
                    self.finish_slice(id, &mut p, outcome, io, false);
                }
            }
            let actual = p.rekey.take().unwrap_or(id);
            if !p.auto_reap || actual == 1 {
                self.processes.insert(actual, p);
            }
        }
        Ok(true)
    }
    fn parallel_timeout(&self) -> Duration {
        let now = Instant::now();
        // Bounded host control and affinity fairness even when every guest spins
        // forever. A local instruction poll does not yield to the coordinator.
        let mut timeout = Duration::from_millis(10);
        if self.terminal.is_some() {
            timeout = Duration::from_millis(2);
        }
        for timer in self.timers.values() {
            if let Some(deadline) = timer.deadline {
                timeout = timeout.min(deadline.saturating_duration_since(now));
            }
        }
        for (&id, p) in &self.processes {
            if p.frozen(id) {
                continue;
            }
            if matches!(p.state, State::Gpu { .. }) && !p.worker_gpu_candidate() {
                timeout = timeout.min(Duration::from_millis(1));
            }
            // Worker-owned waits schedule their deadlines on the shared run
            // queue. Only owner-side blocked waits need a timerfd scan/cutoff;
            // a runnable process with open timers must not pause every CPU.
            let local_wait = p.worker_io_candidate(id);
            for deadline in [
                (!local_wait).then(|| p.linux.uring_deadline()).flatten(),
                (!local_wait)
                    .then(|| p.uring_wait.as_ref().and_then(|(_, _, d)| *d))
                    .flatten(),
            ]
            .into_iter()
            .flatten()
            {
                timeout = timeout.min(deadline.saturating_duration_since(now));
            }
            let timerfd = (matches!(p.state, State::Blocked(..)) && !local_wait)
                .then(|| p.linux.vfs.next_timerfd_deadline().filter(|d| *d > now))
                .flatten();
            let poll = (!local_wait && matches!(p.state, State::Blocked(22 | 72 | 73 | 441, _)))
                .then_some(p.poll_deadline)
                .flatten();
            let socket = (!local_wait && matches!(p.state, State::Blocked(..)))
                .then_some(p.socket_deadline)
                .flatten();
            for deadline in [poll, timerfd, socket].into_iter().flatten() {
                timeout = timeout.min(deadline.saturating_duration_since(now));
            }
            if let State::Futex {
                deadline: Some(d), ..
            }
            | State::Sigwait {
                deadline: Some(d), ..
            }
            | State::Sleep(d, _) = p.state
            {
                timeout = timeout.min(d.saturating_duration_since(now));
            }
            if !local_wait
                && matches!(p.state, State::Blocked(..))
                && p.linux.vfs.live_sockets() != 0
            {
                timeout = timeout.min(Duration::from_millis(1));
            }
        }
        timeout
    }
    fn serial_quantum(&self) -> u64 {
        // No runnable peer needs a turn. Keep a bounded CPU slice while
        // amortizing control/PTY/timer and blocked-task checks. A syscall or
        // native callback outcome still returns through finish_slice normally.
        if self
            .processes
            .iter()
            .any(|(&id, p)| matches!(p.state, State::Ready) && !p.frozen(id))
        {
            4096
        } else {
            65536
        }
    }
    fn drive(&mut self, io: &mut impl GuestOutput, limit: u64) -> Result<Exit, RuntimeError> {
        'drive: loop {
            if let Some(error) = self.backend_error.take() {
                return Err(RuntimeError::Backend(error));
            }
            self.pump_guest_ptys();
            self.tick_timers();
            let elapsed = self.load_sample.elapsed().as_secs_f64();
            if elapsed >= 5.0 {
                let running = self
                    .processes
                    .values()
                    .filter(|p| matches!(p.state, State::Ready))
                    .count() as f64;
                for (load, seconds) in self.load.iter_mut().zip([60.0, 300.0, 900.0]) {
                    let decay = (-elapsed / seconds).exp();
                    *load = *load * decay + running * (1.0 - decay);
                }
                self.load_sample = Instant::now();
            }
            self.control(io)?;
            for backend in self.gpu.borrow_mut().values_mut() {
                backend.reap_abandoned();
            }
            let mut progress = self.pump_terminal(io)?;
            if let Some(root) = self.processes.get(&1) {
                progress |= root.linux.vfs.pump_native_services();
            }
            if self.parallel_epoch(io, limit, true)? {
                continue;
            }
            let ids: Vec<u32> = self.processes.keys().copied().collect();
            for id in ids {
                let Some(mut p) = self.processes.remove(&id) else {
                    continue;
                };
                if !matches!(p.state, State::Zombie(_)) && !p.frozen(id) {
                    let was_parked = matches!(p.state, State::Sleep(..) | State::Blocked(..));
                    progress |= self.resume_gpu(id, &mut p);
                    progress |= p.linux.progress_uring(&mut p.memory, id);
                    progress |= self.resume_event(&mut p);
                    match self.deliver(id, &mut p) {
                        Ok(changed) => progress |= changed,
                        Err(_) => {
                            self.exit(id, &mut p, 11);
                            progress = true;
                        }
                    }
                    // call/control/deliver publish resource changes immediately.
                    match p.state.clone() {
                        State::Blocked(number, a) => {
                            self.call(id, &mut p, number, a, io);
                            progress |= !matches!(p.state, State::Blocked(..));
                        }
                        State::Sleep(deadline, _) if Instant::now() >= deadline => {
                            p.state = State::Ready;
                            p.cpu.set_x(0, 0);
                            progress = true;
                        }
                        _ => {}
                    }
                    // The first candidate check ran before this task woke. A
                    // ring caller with a related peer should resume on workers,
                    // rather than execute a whole owner quantum first. This is
                    // a wake boundary check, never a normal instruction check.
                    if was_parked
                        && matches!(p.state, State::Ready)
                        && self.cpu_count > 1
                        && p.rekey.is_none()
                        && !p.auto_reap
                        && !p.linux.vfs.urings().is_empty()
                    {
                        self.processes.insert(id, p);
                        if self.parallel_candidate() {
                            continue 'drive;
                        }
                        p = self.processes.remove(&id).expect("same joined task");
                    }
                    // Immediate native returns and pure queries keep the quantum.
                    // No native borrow survives; blocking syscalls/faults still
                    // return to the scheduler. Bound work/time between control,
                    // signal and timer polls independently of guest retirement.
                    let mut quantum = if matches!(p.state, State::Ready) {
                        self.serial_quantum()
                    } else {
                        4096
                    };
                    let quantum_started = Instant::now();
                    let mut immediate_returns = 0;
                    while matches!(p.state, State::Ready) && quantum != 0 {
                        if self.instructions >= limit {
                            self.processes.insert(id, p);
                            return Err(RuntimeError::BudgetExceeded(limit));
                        }
                        let instructions_before = self.instructions;
                        let began = Instant::now();
                        let decode_before = p.cpu.decode_stats();
                        let outcome = p.cpu.run_coordinated(
                            &mut self.engine,
                            &mut p.memory,
                            &mut self.parallel_memory,
                            (limit - self.instructions).min(quantum),
                        );
                        let elapsed = began.elapsed();
                        let decode_after = p.cpu.decode_stats();
                        self.decode_lookups += decode_after.lookups - decode_before.lookups;
                        self.decode_misses += decode_after.misses - decode_before.misses;
                        self.instructions_decoded +=
                            decode_after.instructions - decode_before.instructions;
                        p.cpu_time += elapsed;
                        self.cpu_total += elapsed;
                        p.last_cpu = p.affinity.trailing_zeros() as usize;
                        self.per_cpu[p.last_cpu] += elapsed;
                        self.context_switches += 1;
                        let immediate_return = self.finish_slice(id, &mut p, outcome, io, true);
                        if let Some(error) = self.backend_error.take() {
                            self.processes.insert(id, p);
                            return Err(RuntimeError::Backend(error));
                        }
                        if immediate_return {
                            immediate_returns += 1;
                        }
                        progress = true;
                        quantum = quantum.saturating_sub(self.instructions - instructions_before);
                        if !immediate_return
                            || immediate_returns >= 32
                            || quantum_started.elapsed() >= Duration::from_millis(2)
                        {
                            break;
                        }
                    }
                }
                let actual_id = p.rekey.take().unwrap_or(id);
                if !p.auto_reap || actual_id == 1 {
                    self.processes.insert(actual_id, p);
                }
                let root_status = self.processes.get(&1).and_then(|root| {
                    if let State::Zombie(s) = root.state {
                        Some(s)
                    } else {
                        None
                    }
                });
                if let Some(status) = root_status {
                    if !self
                        .processes
                        .values()
                        .any(|t| t.tgid == 1 && !matches!(t.state, State::Zombie(_)))
                    {
                        // Session teardown is explicit: root exit cancels remaining virtual children.
                        if let Some(root) = self.processes.get(&1) {
                            root.linux.vfs.finish_network();
                        }
                        while self
                            .terminal
                            .as_ref()
                            .is_some_and(|t| !t.output_queue.is_empty())
                        {
                            self.control(io)?;
                            if !self.pump_terminal(io)? {
                                // A native renderer can legitimately be full.
                                // Preserve final output until it drains or the
                                // embedding app explicitly cancels the session.
                                self.wait_external();
                            }
                        }
                        return Ok(Exit {
                            code: if status & 127 == 0 {
                                (status >> 8) as u8
                            } else {
                                128 + (status & 127) as u8
                            },
                            instructions: self.instructions,
                        });
                    }
                }
            }
            if !progress {
                let external = self.processes.values().any(|p| {
                    p.poll_deadline.is_some()
                        || p.byte_wait_deadline().is_some()
                        || matches!(p.state, State::Gpu { .. })
                        || p.linux.vfs.next_timerfd_deadline().is_some()
                        || p.linux.uring_pending()
                        || p.uring_wait.as_ref().is_some_and(|(_, _, d)| d.is_some())
                        || matches!(p.state, State::Futex { deadline: Some(_), .. } | State::Sigwait { deadline: Some(_), .. })
                        || matches!(p.state, State::Sleep(..))
                        || Self::waits_for_host_stdin(p)
                        || matches!(p.state, State::Blocked(number, a)
                        if matches!(number, 63 | 64 | 65 | 66 | 202 | 203 | 242 | 206 | 207 | 211 | 212)
                        && p.linux.vfs.fd_kind(a[0] as u32).ok() == Some(FdKind::Socket))
                        || matches!(p.state,State::Blocked(76,a)if [a[0],a[2]].iter().any(|fd|p.linux.vfs.fd_kind(*fd as u32).ok()==Some(FdKind::Socket)))
                        || (matches!(p.state, State::Blocked(22 | 72 | 73 | 441, _))
                            && p.linux.vfs.live_sockets() != 0)
                        || p.linux.vfs.has_bridge_descriptors()
                        || p.linux.vfs.has_native_services()
                }) || self.terminal.is_some() || self.timers.values().any(|t| t.deadline.is_some());
                if !external {
                    return Err(RuntimeError::Deadlock);
                }
                self.wait_external();
            }
        }
    }
    fn wait_external(&mut self) {
        let began = Instant::now();
        let mut sockets = Vec::new();
        let now = Instant::now();
        let mut timeout = Duration::from_millis(20);
        if self.terminal.is_some() {
            timeout = Duration::from_millis(1);
        }
        for timer in self.timers.values() {
            if let Some(d) = timer.deadline {
                timeout = timeout.min(d.saturating_duration_since(now));
            }
        }
        for (&id, p) in &self.processes {
            if p.frozen(id) {
                continue;
            }
            sockets.extend(p.linux.uring_sockets());
            for deadline in [
                p.linux.uring_deadline(),
                p.uring_wait.as_ref().and_then(|(_, _, d)| *d),
                p.byte_wait_deadline(),
            ]
            .into_iter()
            .flatten()
            {
                timeout = timeout.min(deadline.saturating_duration_since(now));
            }
            if matches!(p.state, State::Gpu { .. }) {
                timeout = timeout.min(Duration::from_millis(1));
            }
            if let Some(deadline) = p.linux.vfs.next_timerfd_deadline() {
                timeout = timeout.min(deadline.saturating_duration_since(now));
            }
            if let State::Futex {
                deadline: Some(d), ..
            }
            | State::Sigwait {
                deadline: Some(d), ..
            } = p.state
            {
                timeout = timeout.min(d.saturating_duration_since(now));
            }
            if let Some(deadline) = p.poll_deadline {
                timeout = timeout.min(deadline.saturating_duration_since(now));
            }
            if matches!(p.state, State::Blocked(..)) {
                if let Some(deadline) = p.socket_deadline {
                    timeout = timeout.min(deadline.saturating_duration_since(now));
                }
            }
            if let State::Sleep(deadline, _) = p.state {
                timeout = timeout.min(deadline.saturating_duration_since(now));
            }
            let State::Blocked(number, a) = p.state else {
                continue;
            };
            let mut add = |fd, events| {
                if let Ok(socket) = p.linux.vfs.socket_fd(fd) {
                    sockets.push((socket, events));
                }
            };
            match number {
                63 | 65 | 202 | 242 | 207 | 212 => {
                    add(a[0] as u32, 1);
                    if p.linux.vfs.fd_kind(a[0] as u32).ok() == Some(FdKind::Stdin) {
                        timeout = timeout.min(Duration::from_millis(1));
                    }
                }
                76 => {
                    add(a[0] as u32, 1);
                    add(a[2] as u32, 4);
                }
                64 | 66 | 203 | 206 | 211 => add(a[0] as u32, 4),
                73 => {
                    for i in 0..a[1].min(256) {
                        if let (Ok(fd), Ok(events)) = (
                            read_u32(&p.memory, a[0] + i * 8),
                            read_u32(&p.memory, a[0] + i * 8 + 4),
                        ) {
                            if fd < i32::MAX as u32 {
                                add(fd, events as u16);
                            }
                            if p.linux.vfs.fd_kind(fd).ok() == Some(FdKind::Stdin) {
                                timeout = timeout.min(Duration::from_millis(1));
                            }
                        }
                    }
                }
                72 => {
                    for (index, event) in [(1, 1), (2, 4), (3, 2)] {
                        if a[index] == 0 {
                            continue;
                        }
                        for fd in 0..a[0].min(256) as u32 {
                            if let Ok(bits) = read_u64(&p.memory, a[index] + (fd as u64 / 64) * 8) {
                                if bits & (1 << (fd % 64)) != 0 {
                                    add(fd, event);
                                    if p.linux.vfs.fd_kind(fd).ok() == Some(FdKind::Stdin) {
                                        timeout = timeout.min(Duration::from_millis(1));
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if sockets.is_empty() || timeout < Duration::from_millis(1) {
            std::thread::sleep(timeout.min(Duration::from_millis(1)));
        } else if trames_net::wait(&sockets, timeout).is_err() {
            // Native adapter failures are surfaced by the next guest IO/poll.
            std::thread::sleep(Duration::from_millis(1));
        }
        self.idle += began.elapsed();
    }
}
pub(super) fn run<C: Cpu>(
    runtime: &mut Runtime<C>,
    io: &mut impl GuestOutput,
    limit: u64,
) -> Result<Exit, RuntimeError> {
    runtime.memory_limits.validate()?;
    runtime
        .memory
        .set_limit(runtime.memory_limits.per_process)?;
    runtime
        .memory
        .set_total_limit(runtime.memory_limits.total)?;
    let mut root = Process::<C> {
        cpu: std::mem::take(&mut runtime.cpu),
        affinity: (1u64 << runtime.cpu_count.clamp(1, 32)) - 1,
        last_cpu: 0,
        nice: 0,
        scheduler: 0,
        memory: std::mem::take(&mut runtime.memory),
        linux: std::mem::replace(&mut runtime.linux, Linux::new(0)),
        parent: 0,
        parent_thread: 0,
        pdeath_signal: 0,
        group: 1,
        session: 1,
        state: State::Ready,
        signals: Signals::default(),
        wait_event: None,
        poll_deadline: None,
        socket_deadline: None,
        poll_mask: None,
        uring_wait: None,
        flock_wait: None,
        byte_wait: None,
        retained_byte: None,
        retained_poll: None,
        retained_select: None,
        pending_open: None,
        stopped_state: None,
        auto_reap: false,
        tgid: 1,
        started: Instant::now(),
        cpu_time: Duration::ZERO,
        vm_id: 1,
        rekey: None,
        subreaper: false,
        membarrier_registered: Rc::new(Cell::new(false)),
        file_size_limit: Rc::new(Cell::new((u64::MAX, u64::MAX))),
        oom: Arc::new(trames_vfs::OomTask::default()),
        seccomp: seccomp::Seccomp::default(),
    };
    let count = runtime.cpu_count.clamp(1, if C::PARALLEL { 32 } else { 1 });
    let started = root
        .linux
        .vfs
        .wayland_server()
        .map_or_else(Instant::now, |server| server.guest_clock_origin());
    let mut kernel = Kernel::<C> {
        byte_target: Arc::new(JoinedByteWake),
        memory_limits: runtime.memory_limits,
        cpu_count: count,
        task_limit: root.linux.task_limit.max(1),
        workers: crate::workers::Pool::<C>::with_profiling(count, runtime.profile_syscalls),
        engine: std::mem::take(&mut runtime.engine),
        backend_error: None,
        futexes: Default::default(),
        futex_ready: Vec::new(),
        parallel_memory: trames_memory::parallel::Registry::default(),
        parallel_rounds: 0,
        vm_checkpoint_groups: 0,
        vm_checkpoint_spaces: 0,
        vm_local_syscalls: 0,
        persistent_control_checks: 0,
        worker_slices: 0,
        worker_chunks: 0,
        worker_syscalls: 0,
        worker_direct_syscalls: 0,
        worker_futex_wakes: 0,
        worker_futex_woken: 0,
        worker_futex_requeues: 0,
        worker_futex_waits: 0,
        worker_task_resumes: 0,
        worker_task_yields: 0,
        worker_io_waits: 0,
        worker_service_waits: 0,
        worker_file_syscalls: 0,
        worker_socket_syscalls: 0,
        worker_timer_syscalls: 0,
        worker_poll_syscalls: 0,
        worker_uring_syscalls: 0,
        worker_fd_syscalls: 0,
        worker_gpu_calls: 0,
        worker_gpu_waits: 0,
        service_requests: 0,
        disk_reads: 0,
        peak_disk_reads: 0,
        disk_read_bytes: 0,
        service_write_buffer: Vec::new(),
        serviced_syscalls: 0,
        service_wait: Duration::ZERO,
        parallel_memory_time: Duration::ZERO,
        parallel_dispatch_time: Duration::ZERO,
        parallel_stop_time: Duration::ZERO,
        next_parallel_pid: 0,
        per_cpu: vec![Duration::ZERO; count],
        processes: BTreeMap::new(),
        next_pid: 2,
        terminal: runtime.terminal.take(),
        started,
        instructions: 0,
        boot_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        context_switches: 0,
        decode_lookups: 0,
        instructions_decoded: 0,
        decode_misses: 0,
        cpu_total: Duration::ZERO,
        syscall_total: Duration::ZERO,
        syscalls: 0,
        proc_refreshes: 0,
        proc_maps: RefCell::new(BTreeMap::new()),
        profile_syscalls: runtime.profile_syscalls,
        idle: Duration::ZERO,
        load: [0.0; 3],
        load_sample: Instant::now(),
        next_resource: 2,
        timers: BTreeMap::new(),
        next_timer: 1,
        native: trames_accel::native::Registry::default(),
        gpu: RefCell::new(BTreeMap::new()),
        gpu_budget: trames_vulkan::Budget::for_guest_memory(runtime.memory_limits.total),
        gpu_display: runtime.vulkan_display.clone(),
        gpu_compiles: 0,
        gpu_peak_pending: 0,
        gpu_peer_instructions: 0,
        gpu_wait_time: Duration::ZERO,
        gpu_transfers: trames_vulkan::TransferMetrics::default(),
    };
    // Enable all virtual mounts once, including /dev and /sys for programs
    // that never touch /proc. Subsequent full snapshots are demand-driven.
    kernel.refresh_proc(1, &mut root);
    kernel.proc_refreshes += 1;
    kernel.processes.insert(1, Box::new(root));
    let result = kernel.drive(io, limit);
    runtime.metrics = super::RuntimeMetrics {
        instructions: kernel.instructions,
        parallel_snapshots: kernel.parallel_memory.metrics,
        cpu_count: kernel.cpu_count,
        parallel_rounds: kernel.parallel_rounds,
        vm_checkpoint_groups: kernel.vm_checkpoint_groups,
        vm_checkpoint_spaces: kernel.vm_checkpoint_spaces,
        vm_local_syscalls: kernel.vm_local_syscalls,
        persistent_control_checks: kernel.persistent_control_checks,
        worker_slices: kernel.worker_slices,
        worker_chunks: kernel.worker_chunks,
        worker_syscalls: kernel.worker_syscalls,
        worker_direct_syscalls: kernel.worker_direct_syscalls,
        worker_futex_wakes: kernel.worker_futex_wakes,
        worker_futex_woken: kernel.worker_futex_woken,
        worker_futex_requeues: kernel.worker_futex_requeues,
        worker_futex_waits: kernel.worker_futex_waits,
        worker_task_resumes: kernel.worker_task_resumes,
        worker_task_yields: kernel.worker_task_yields,
        worker_io_waits: kernel.worker_io_waits,
        worker_service_waits: kernel.worker_service_waits,
        worker_file_syscalls: kernel.worker_file_syscalls,
        worker_socket_syscalls: kernel.worker_socket_syscalls,
        worker_timer_syscalls: kernel.worker_timer_syscalls,
        worker_poll_syscalls: kernel.worker_poll_syscalls,
        worker_uring_syscalls: kernel.worker_uring_syscalls,
        worker_fd_syscalls: kernel.worker_fd_syscalls,
        worker_gpu_calls: kernel.worker_gpu_calls,
        worker_gpu_waits: kernel.worker_gpu_waits,
        service_requests: kernel.service_requests,
        disk_reads: kernel.disk_reads,
        peak_disk_reads: kernel.peak_disk_reads,
        disk_read_bytes: kernel.disk_read_bytes,
        serviced_syscalls: kernel.serviced_syscalls,
        service_wait_time: kernel.service_wait,
        peak_parallel_native_calls: kernel
            .workers
            .peak_native
            .load(std::sync::atomic::Ordering::Relaxed),
        peak_parallel_cpus: kernel
            .workers
            .peak
            .load(std::sync::atomic::Ordering::Relaxed),
        parallel_memory_time: kernel.parallel_memory_time,
        parallel_dispatch_time: kernel.parallel_dispatch_time,
        parallel_stop_time: kernel.parallel_stop_time,
        cpu_time: kernel.cpu_total,
        syscall_time: kernel.syscall_total,
        idle_time: kernel.idle,
        syscalls: kernel.syscalls,
        proc_refreshes: kernel.proc_refreshes,
        context_switches: kernel.context_switches,
        decode_lookups: kernel.decode_lookups,
        instructions_decoded: kernel.instructions_decoded,
        decode_misses: kernel.decode_misses,
        native: kernel.native.metrics,
        gpu_compiles: kernel.gpu_compiles,
        gpu_peak_pending: kernel.gpu_peak_pending,
        gpu_peer_instructions: kernel.gpu_peer_instructions,
        gpu_wait_time: kernel.gpu_wait_time,
        gpu_transfers: kernel.gpu_transfers,
    };
    // Session teardown cancels forked children, including their process locks.
    // Root-thread locks are already released on normal group exit; preserve
    // the root's state when returning a resumable runtime error.
    for p in kernel.processes.values_mut().filter(|p| p.tgid != 1) {
        p.linux.vfs.set_lock_owner(p.tgid);
        p.linux.vfs.release_process_locks();
    }
    if let Some(p) = kernel.processes.remove(&1) {
        runtime.cpu = p.cpu;
        runtime.memory = p.memory;
        runtime.linux = p.linux;
    }
    runtime.terminal = kernel.terminal;
    runtime.engine = kernel.engine;
    result
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Process = crate::process::Process<Cpu>;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn shared_resources_are_visible_without_propagation_and_private_domains_remain_separate() {
        let mut k = kernel();
        let mut p = process();
        p.linux.vfs.mkdir_at(AT_FDCWD, b"/dir", 0o700).unwrap();
        let fd = p
            .linux
            .vfs
            .open_at(AT_FDCWD, b"/file", 0x42, 0o600)
            .unwrap();
        let memory = p.memory.share();
        k.processes.insert(2, p.fork_with_memory(memory));
        let mut independent = p.fork();
        independent.vm_id = 9;
        k.processes.insert(3, independent);
        let mut io = trames_linux::CapturedOutput::default();

        k.call(1, &mut p, 25, [fd as u64, 2, 1, 0, 0, 0], &mut io);
        assert_eq!(
            k.processes[&2]
                .linux
                .vfs
                .fd_flags_snapshot()
                .get(fd)
                .unwrap()
                & 0x80000,
            0x80000
        );
        assert_eq!(
            k.processes[&3]
                .linux
                .vfs
                .fd_flags_snapshot()
                .get(fd)
                .unwrap()
                & 0x80000,
            0
        );
        p.memory.write(0x1000, b"/dir\0").unwrap();
        k.call(1, &mut p, 49, [0x1000, 0, 0, 0, 0, 0], &mut io);
        assert_eq!(k.processes[&2].linux.vfs.cwd().unwrap(), b"/dir");
        assert_eq!(k.processes[&3].linux.vfs.cwd().unwrap(), b"/");
        k.call(1, &mut p, 166, [0o077, 0, 0, 0, 0, 0], &mut io);
        assert_eq!(k.processes[&2].linux.vfs.umask(), 0o077);
        assert_eq!(k.processes[&3].linux.vfs.umask(), 0o022);
        k.call(1, &mut p, 214, [0xb000, 0, 0, 0, 0, 0], &mut io);
        assert_eq!(k.processes[&2].linux.heap_context(), p.linux.heap_context());
        assert_ne!(k.processes[&3].linux.heap_context(), p.linux.heap_context());
        k.call(1, &mut p, 57, [fd as u64, 0, 0, 0, 0, 0], &mut io);
        assert_eq!(k.processes[&2].linux.vfs.fd_kind(fd), Err(Errno(9)));
        assert!(k.processes[&3].linux.vfs.fd_kind(fd).is_ok());
    }

    #[test]
    fn reset_hand_is_published_before_another_shared_thread_can_deliver_it() {
        let mut k = kernel();
        let mut p = process();
        k.processes
            .insert(2, p.fork_state(p.memory.clone(), false, false, true));
        let mut io = trames_linux::CapturedOutput::default();
        for (offset, value) in [(0, 0x4000u64), (8, 0x80000000), (16, 0), (24, 0)] {
            write_u64(&mut p.memory, 0x2000 + offset, value).unwrap();
        }
        k.call(1, &mut p, 134, [10, 0x2000, 0, 8, 0, 0], &mut io);
        assert_eq!(k.processes[&2].signals.actions.get(10).handler, 0x4000);
        Kernel::queue_one(1, &mut p, 10, 0);
        assert_eq!(k.deliver(1, &mut p), Ok(true));
        assert_eq!(p.cpu.pc, 0x4000);
        assert_eq!(k.processes[&2].signals.actions.get(10).handler, 0);
    }

    #[test]
    fn host_control_publishes_partial_context_and_fd_changes_before_error() {
        struct Control(u32);
        impl GuestOutput for Control {
            fn control(&mut self, vfs: &mut trames_vfs::Vfs) -> std::io::Result<bool> {
                vfs.close(self.0).unwrap();
                vfs.set_umask(0o077);
                Err(std::io::Error::other("after authorized mutation"))
            }
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
        }
        let mut k = kernel();
        let mut p = process();
        let fd = p
            .linux
            .vfs
            .open_at(AT_FDCWD, b"/file", 0x42, 0o600)
            .unwrap();
        k.processes
            .insert(2, p.fork_state(p.memory.clone(), true, true, true));
        k.processes.insert(1, p);
        assert!(k.control(&mut Control(fd)).is_err());
        assert_eq!(k.processes[&2].linux.vfs.fd_kind(fd), Err(Errno(9)));
        assert_eq!(k.processes[&2].linux.vfs.umask(), 0o077);
    }

    #[test]
    fn solo_quantum_does_not_delay_a_runnable_peer() {
        let mut k = kernel();
        assert_eq!(k.serial_quantum(), 65536);
        let mut blocked = process();
        blocked.state = State::Blocked(260, [0; 6]);
        k.processes.insert(2, blocked);
        assert_eq!(k.serial_quantum(), 65536);
        k.processes.get_mut(&2).unwrap().state = State::Ready;
        assert_eq!(k.serial_quantum(), 4096);
    }
    #[test]
    fn solo_cpu_with_unrelated_blocked_io_keeps_serial_mmu_but_connected_peer_can_handoff() {
        let mut k = kernel();
        let cpu = process();
        let mut idle = process();
        idle.vm_id = cpu.vm_id + 1;
        let [read, _] = idle.linux.vfs.pipe(0).unwrap();
        idle.state = State::Blocked(63, [read as u64, 0x1000, 1, 0, 0, 0]);
        assert!(idle.worker_io_candidate(1));
        k.processes.insert(1, cpu);
        k.processes.insert(2, idle);
        assert!(!k.parallel_candidate());

        // A pipe crossing VM boundaries still admits single-slot producer /
        // consumer handoff. This must not be replaced with "two ready only".
        let mut sender = process();
        let [read, write] = sender.linux.vfs.pipe(0).unwrap();
        let mut receiver = sender.fork();
        receiver.vm_id += 1;
        sender.linux.vfs.close(read).unwrap();
        receiver.linux.vfs.close(write).unwrap();
        receiver.state = State::Blocked(63, [read as u64, 0x1000, 1, 0, 0, 0]);
        k.processes.insert(1, sender);
        k.processes.insert(2, receiver);
        assert!(k.parallel_candidate());
        k.processes.get_mut(&2).unwrap().linux.trace = true;
        assert!(!k.parallel_candidate());
        k.processes.get_mut(&2).unwrap().state = State::Ready;
        assert!(k.parallel_candidate());
    }
    #[test]
    fn legacy_log_waiter_needs_a_real_writer_to_divert_solo_cpu() {
        let mut k = kernel();
        let mut cpu = process();
        cpu.linux.vfs.set_runtime_info(1, Default::default());
        let mut waiter = cpu.fork();
        waiter.vm_id += 1;
        waiter.state = State::Blocked(116, [2, 0x1000, 128, 0, 0, 0]);
        assert!(waiter.worker_io_candidate(2));
        k.processes.insert(1, cpu);
        k.processes.insert(2, waiter);
        assert!(!k.parallel_candidate());
        let fd = k
            .processes
            .get_mut(&1)
            .unwrap()
            .linux
            .vfs
            .open_at(-100, b"/dev/kmsg", 1, 0)
            .unwrap();
        assert!(k.parallel_candidate());
        k.processes
            .get_mut(&1)
            .unwrap()
            .linux
            .vfs
            .close(fd)
            .unwrap();
        assert!(!k.parallel_candidate());
    }
    #[test]
    fn solo_cpu_can_adopt_its_vm_futex_waiter_but_not_an_unrelated_vm() {
        let mut k = kernel();
        let cpu = process();
        let mut waiter = cpu.fork();
        let wait = k
            .futexes
            .wait((0, cpu.vm_id, 0x1000), 2, u32::MAX, || Ok::<_, Errno>(()))
            .unwrap();
        waiter.state = State::Futex {
            wait,
            deadline: None,
        };
        k.processes.insert(1, cpu);
        k.processes.insert(2, waiter);
        assert!(k.parallel_candidate());
        k.processes.get_mut(&2).unwrap().vm_id += 1;
        assert!(!k.parallel_candidate());
        k.processes.get_mut(&1).unwrap().state = State::Blocked(260, [0; 6]);
        assert!(!k.parallel_candidate());
    }
    #[test]
    fn solo_cpu_adopts_inherited_tcp_waiter_but_not_unrelated_socket_waiter() {
        use std::net::{Ipv4Addr, TcpListener};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut k = kernel();
        let mut cpu = process();
        cpu.linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = cpu.linux.vfs.socket(2, 1, 0).unwrap();
        let socket = cpu.linux.vfs.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let _peer = listener.accept().unwrap().0;
        assert_eq!(socket.connect_complete(), Ok(true));
        let mut waiter = cpu.fork();
        waiter.vm_id += 1;
        waiter.state = State::Blocked(63, [fd as u64, 0x1000, 1, 0, 0, 0]);
        k.processes.insert(1, cpu);
        k.processes.insert(2, waiter);
        assert!(k.parallel_candidate());
        // Shared socket identity, rather than a guest FD number or namespace,
        // must decide the single-active-task exception.
        k.processes.insert(1, process());
        assert!(!k.parallel_candidate());
    }
    #[test]
    fn flock_wait_survives_owner_handoff_close_reuse_and_cleans_up_on_completion() {
        let mut k = kernel();
        let mut p = process();
        let a = p.linux.vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = p.linux.vfs.open_at(-100, b"/lock", 2, 0).unwrap();
        p.linux.vfs.flock(b, 6).unwrap();
        let (request, file) = p.linux.vfs.retain_flock(a, 2).unwrap();
        let call = crate::run_queue::IoCall {
            number: 32,
            args: [a as u64, 2, 0, 0, 0, 0],
            deadline: None,
            flock: Some(request),
            retained_byte: None,
            retained_poll: None,
        };
        drop(file);
        p.retain_worker_flock(Some(&call)); // Joined before close/dup.
        p.linux.vfs.close(a).unwrap();
        assert_eq!(p.linux.vfs.open_at(-100, b"/new", 0x42, 0o600).unwrap(), a);
        p.linux.vfs.flock(a, 6).unwrap();
        p.retain_worker_flock(Some(&call)); // Next join must not switch to /new.
        p.state = State::Blocked(32, call.args);
        assert!(p.worker_io_candidate(1));
        let mut io = trames_linux::CapturedOutput::default();
        assert_eq!(k.syscall(1, &mut p, 32, call.args, &mut io), Ok(None));
        p.linux.vfs.flock(b, 8).unwrap();
        drop(call.flock); // worker handoff no longer owns a lease.
        assert_eq!(k.syscall(1, &mut p, 32, call.args, &mut io), Ok(Some(0)));
        assert!(p.flock_wait.is_none());
        assert_eq!(p.linux.vfs.flock(b, 6), Ok(()));
    }

    #[test]
    fn joined_pipe_wait_skips_unrelated_retries_and_keeps_original_ofd() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        let args = [reader as u64, 0x1000, 1, 0, 0, 0];
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 63, args, &mut io);
        assert!(matches!(p.state, State::Blocked(63, _)));
        assert!(p.byte_wait.is_some());
        let before = k.syscalls;
        p.linux.vfs.close(reader).unwrap();
        let [replacement, replacement_writer] = p.linux.vfs.pipe(0).unwrap();
        assert_eq!(reader, replacement);
        p.linux.vfs.write(replacement_writer, b"n").unwrap();
        for _ in 0..100 {
            k.call(1, &mut p, 63, args, &mut io);
        }
        assert_eq!(k.syscalls, before);
        p.linux.vfs.write(writer, b"o").unwrap();
        k.call(1, &mut p, 63, args, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 1);
        let mut byte = [0];
        p.memory.read(0x1000, &mut byte).unwrap();
        assert_eq!(byte, *b"o");
        assert!(p.byte_wait.is_none());
        assert_eq!(p.linux.vfs.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(p.linux.vfs.read(replacement, 1).unwrap(), b"n");
    }

    #[test]
    fn joined_ppoll_keeps_imported_fds_and_timeout_through_close_and_guest_buffer_changes() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        p.memory.map(0x20000, PAGE_SIZE, Permissions::RW).unwrap();
        p.memory.write_array(0x20000, 60u64.to_le_bytes()).unwrap();
        p.memory.write_array(0x20008, 0u64.to_le_bytes()).unwrap();
        p.memory.write_array(0x1000, reader.to_le_bytes()).unwrap();
        p.memory.write_array(0x1004, 1u32.to_le_bytes()).unwrap();
        let args = [0x1000, 1, 0x20000, 0, 0, 0];
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 73, args, &mut io);
        let deadline = p.poll_deadline;
        assert!(deadline.is_some() && p.retained_poll.is_some());
        p.linux.vfs.close(reader).unwrap();
        let [replacement, new_writer] = p.linux.vfs.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        p.linux.vfs.write(new_writer, b"new").unwrap();
        p.memory.write_array(0x1000, writer.to_le_bytes()).unwrap();
        p.memory.write_array(0x1004, 4u32.to_le_bytes()).unwrap();
        p.memory.unmap(0x20000, PAGE_SIZE).unwrap();
        k.call(1, &mut p, 73, args, &mut io);
        assert!(matches!(p.state, State::Blocked(73, _)));
        assert_eq!(p.poll_deadline, deadline);
        p.poll_deadline = Some(Instant::now());
        k.call(1, &mut p, 73, args, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 0);
        assert!(p.retained_poll.is_none() && p.poll_deadline.is_none());
        assert_eq!(
            p.memory.read_array::<2>(0x1006).unwrap(),
            0u16.to_le_bytes()
        );
        assert_eq!(p.linux.vfs.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(p.linux.vfs.read(replacement, 3).unwrap(), b"new");
    }

    #[test]
    fn pselect_keeps_original_set_and_shared_ofd_after_close_reuse_and_timeout_buffer_unmap() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        p.memory.map(0x20000, PAGE_SIZE, Permissions::RW).unwrap();
        p.memory.write_array(0x20000, 60u64.to_le_bytes()).unwrap();
        p.memory.write_array(0x20008, 0u64.to_le_bytes()).unwrap();
        p.memory
            .write_array(0x1000, (1u64 << reader).to_le_bytes())
            .unwrap();
        let args = [writer as u64 + 1, 0x1000, 0, 0, 0x20000, 0];
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 72, args, &mut io);
        assert!(matches!(p.state, State::Blocked(72, _)));
        assert!(p.retained_select.is_some());
        assert!(!p.worker_io_candidate(1));
        let deadline = p.poll_deadline;
        p.linux.vfs.close(reader).unwrap();
        let [replacement, new_writer] = p.linux.vfs.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        p.linux.vfs.write(new_writer, b"new").unwrap();
        p.memory.unmap(0x20000, PAGE_SIZE).unwrap();
        k.call(1, &mut p, 72, args, &mut io);
        assert!(matches!(p.state, State::Blocked(72, _)));
        assert_eq!(p.poll_deadline, deadline);
        p.memory
            .write_array(0x1000, (1u64 << writer).to_le_bytes())
            .unwrap();
        p.linux.vfs.write(writer, b"old").unwrap();
        k.call(1, &mut p, 72, args, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 1);
        assert_eq!(
            p.memory.read_array::<8>(0x1000).unwrap(),
            (1u64 << reader).to_le_bytes()
        );
        assert!(p.retained_select.is_none() && p.poll_deadline.is_none());
        assert_eq!(p.linux.vfs.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(p.linux.vfs.read(replacement, 3).unwrap(), b"new");
    }

    #[test]
    fn retained_ppoll_stop_continue_signal_and_exit_preserve_or_release_original_ofds() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        p.memory.write_array(0x1000, reader.to_le_bytes()).unwrap();
        p.memory.write_array(0x1004, 1u32.to_le_bytes()).unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 73, [0x1000, 1, 0, 0, 0, 0], &mut io);
        p.linux.vfs.close(reader).unwrap();
        Kernel::queue_one(1, &mut p, 19, 1);
        k.deliver(1, &mut p).unwrap();
        assert!(matches!(p.state, State::Stopped));
        assert!(p.retained_poll.is_some());
        Kernel::queue_one(1, &mut p, 18, 1);
        assert!(matches!(p.state, State::Blocked(73, _)));
        p.signals.actions.set_handler(10, 0x5000);
        Kernel::queue_one(1, &mut p, 10, 1);
        k.deliver(1, &mut p).unwrap();
        assert!(p.retained_poll.is_none());
        assert_eq!(p.linux.vfs.write(writer, b"x"), Err(Errno(32)));

        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        p.memory.write_array(0x1000, reader.to_le_bytes()).unwrap();
        p.memory.write_array(0x1004, 1u32.to_le_bytes()).unwrap();
        k.call(1, &mut p, 73, [0x1000, 1, 0, 0, 0, 0], &mut io);
        p.linux.vfs.close(reader).unwrap();
        let mut peer = p.fork();
        assert!(peer.retained_poll.is_none());
        k.exit(1, &mut p, 0);
        assert!(p.retained_poll.is_none());
        assert_eq!(peer.linux.vfs.write(writer, b"x"), Err(Errno(32)));
    }

    #[test]
    fn mixed_ppoll_keeps_shared_ofd_and_rejects_reused_owner_control_identity() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        let signal = p.linux.vfs.signalfd(-1, 1 << 10, 0).unwrap();
        for (i, fd) in [reader, signal].into_iter().enumerate() {
            p.memory
                .write_array(0x1000 + i as u64 * 8, fd.to_le_bytes())
                .unwrap();
            p.memory
                .write_array(0x1004 + i as u64 * 8, 1u32.to_le_bytes())
                .unwrap();
        }
        let mut io = trames_linux::CapturedOutput::default();
        let args = [0x1000, 2, 0, 0, 0, 0];
        k.call(1, &mut p, 73, args, &mut io);
        assert!(matches!(p.state, State::Blocked(73, _)));
        assert!(!p.worker_io_candidate(1));
        p.linux.vfs.close(reader).unwrap();
        let [replacement, new_writer] = p.linux.vfs.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        p.linux.vfs.close(signal).unwrap();
        let replacement_signal = p.linux.vfs.eventfd(1, 0).unwrap();
        assert_eq!(replacement_signal, signal);
        p.linux.vfs.write(new_writer, b"new").unwrap();
        k.call(1, &mut p, 73, args, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 1);
        assert_eq!(
            p.memory.read_array::<2>(0x1006).unwrap(),
            0u16.to_le_bytes()
        );
        assert_eq!(
            p.memory.read_array::<2>(0x100e).unwrap(),
            32u16.to_le_bytes()
        );
        assert!(p.retained_poll.is_none());
        assert_eq!(p.linux.vfs.write(writer, b"x"), Err(Errno(32)));
        assert_eq!(p.linux.vfs.read(replacement, 3).unwrap(), b"new");
    }

    #[test]
    fn actual_ppoll_worker_handoff_releases_original_reader_before_the_next_join() {
        let mut k = kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        let mut p = process();
        p.affinity = 3;
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        let [ack_reader, ack_writer] = p.linux.vfs.pipe(0).unwrap();
        p.memory.write(0x1200, b"a").unwrap();
        p.memory.write_array(0x1000, reader.to_le_bytes()).unwrap();
        p.memory.write_array(0x1004, 1u32.to_le_bytes()).unwrap();
        // The ACK is sent only after poll completes. The producer must see
        // EPIPE before an owner checkpoint can retire an extra saved poll pin.
        let parent_code: Vec<_> = [
            0xd2800000u32 | (ack_writer << 5),
            0xd2824001,
            0xd2800022,
            0xd2800808,
            0xd4000001,
            0x14000000,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        p.memory.write(0x4000, &parent_code).unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 73, [0x1000, 1, 0, 0, 0, 0], &mut io);
        assert!(p.retained_poll.is_some());
        p.linux.vfs.close(reader).unwrap();
        let [replacement, new_writer] = p.linux.vfs.pipe(0).unwrap();
        assert_eq!(replacement, reader);
        p.linux.vfs.write(new_writer, b"new").unwrap();
        let mut producer = p.fork();
        assert!(producer.retained_poll.is_none());
        producer.tgid = 2;
        producer.vm_id = 2;
        producer.parent = 1;
        producer.signals.actions.set_handler(13, 1);
        producer.memory.write(0x1100, b"o").unwrap();
        // write(old_writer); read(ack_reader); write(old_writer).
        let code: Vec<_> = [
            0xd4000001u32,
            0xd2800000 | (ack_reader << 5),
            0xd2826001,
            0xd2800022,
            0xd28007e8,
            0xd4000001,
            0xd2800000 | (writer << 5),
            0xd2822001,
            0xd2800022,
            0xd2800808,
            0xd4000001,
            0x14000000,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        producer.memory.write(0x4000, &code).unwrap();
        producer.cpu.set_x(0, writer as u64);
        producer.cpu.set_x(1, 0x1100);
        producer.cpu.set_x(2, 1);
        producer.cpu.set_x(8, 64);
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        producer
            .memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        k.processes.insert(1, p);
        k.processes.insert(2, producer);
        for _ in 0..4 {
            let limit = k.instructions + 1_000_000;
            assert!(k.parallel_round(&mut io, limit).unwrap());
            if k.processes[&2].cpu.x(0) == error(Errno(32)) {
                break;
            }
        }
        assert_eq!(k.processes[&2].cpu.x(0), error(Errno(32)));
        assert!(k.worker_poll_syscalls > 0);
        let p = k.processes.get_mut(&1).unwrap();
        assert!(p.retained_poll.is_none());
        assert_eq!(p.cpu.x(0), 1);
        assert_eq!(
            p.memory.read_array::<2>(0x1006).unwrap(),
            1u16.to_le_bytes()
        );
        assert_eq!(p.linux.vfs.read(replacement, 3).unwrap(), b"new");
    }

    #[test]
    fn solo_cpu_adopts_related_retained_poll_after_all_original_numeric_fds_are_closed() {
        let mut k = kernel();
        let mut waiter = process();
        let [reader, writer] = waiter.linux.vfs.pipe(0).unwrap();
        waiter
            .memory
            .write_array(0x1000, reader.to_le_bytes())
            .unwrap();
        waiter
            .memory
            .write_array(0x1004, 1u32.to_le_bytes())
            .unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut waiter, 73, [0x1000, 1, 0, 0, 0, 0], &mut io);
        waiter.linux.vfs.close(reader).unwrap();
        let producer = waiter.fork();
        waiter.linux.vfs.close(writer).unwrap();
        assert!(waiter.retained_poll.is_some());
        assert!(waiter.worker_io_candidate(1));
        k.processes.insert(1, waiter);
        k.processes.insert(2, producer);
        assert!(k.parallel_candidate());
        k.processes.insert(2, process());
        assert!(!k.parallel_candidate());
    }

    #[test]
    fn exiting_blocked_pipe_reader_releases_accepted_ofd() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        let mut peer = p.fork();
        peer.linux.vfs.close(reader).unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 63, [reader as u64, 0x1000, 1, 0, 0, 0], &mut io);
        p.linux.vfs.close(reader).unwrap();
        assert_eq!(peer.linux.vfs.write(writer, b"x"), Ok(1));
        k.exit(1, &mut p, 0);
        assert!(p.byte_wait.is_none());
        assert_eq!(peer.linux.vfs.write(writer, b"x"), Err(Errno(32)));
    }

    #[test]
    fn stopped_pipe_wait_survives_continue_but_caught_signal_releases_it() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 63, [reader as u64, 0x1000, 1, 0, 0, 0], &mut io);
        p.linux.vfs.close(reader).unwrap();
        Kernel::queue_one(1, &mut p, 19, 1);
        k.deliver(1, &mut p).unwrap();
        assert!(matches!(p.state, State::Stopped));
        assert!(p.byte_wait.is_some());
        Kernel::queue_one(1, &mut p, 18, 1);
        assert!(matches!(p.state, State::Blocked(63, _)));
        p.signals.actions.set_handler(10, 0x5000);
        Kernel::queue_one(1, &mut p, 10, 1);
        k.deliver(1, &mut p).unwrap();
        assert!(p.byte_wait.is_none());
        assert!(p.retained_byte.is_none());
        assert_eq!(p.linux.vfs.write(writer, b"x"), Err(Errno(32)));
    }

    #[test]
    fn retained_writer_checkpoint_delivers_sigpipe_from_original_endpoint() {
        let mut k = kernel();
        let mut p = process();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        p.linux.vfs.write(writer, &vec![0; 65536]).unwrap();
        p.memory.write(0x1000, b"x").unwrap();
        let args = [writer as u64, 0x1000, 1, 0, 0, 0];
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 64, args, &mut io);
        let wait = p.byte_wait.take().unwrap();
        let call = crate::run_queue::IoCall::from(&wait);
        drop(wait);
        p.linux.vfs.close(writer).unwrap();
        let [replacement, _] = p.linux.vfs.pipe(0).unwrap();
        assert_eq!(replacement, writer);
        p.linux.vfs.close(reader).unwrap();
        // A fresh worker checkpoints EPIPE for joined signal delivery.
        let result = trames_linux::DirectSyscalls::default().start_retained_byte(
            call.retained_byte.clone().unwrap(),
            64,
            args,
            &mut p.memory,
            1,
            &Arc::downgrade(&k.byte_target),
        );
        assert!(matches!(result, trames_linux::IoAttempt::Checkpoint));
        p.retained_byte = call.retained_byte;
        k.call(1, &mut p, 64, args, &mut io);
        assert_eq!(p.cpu.x(0), error(Errno(32)));
        assert_ne!(p.pending_bits() & (1 << 12), 0);
        assert!(p.retained_byte.is_none());
    }

    #[test]
    fn owner_pipe_wait_rearms_on_worker_and_reads_original_after_fd_reuse() {
        let mut k = kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        let mut p = process();
        p.affinity = 3;
        // Spin after the read completes, while the producer's exit joins.
        p.memory
            .write(0x4000, &0x14000000u32.to_le_bytes())
            .unwrap();
        let [reader, writer] = p.linux.vfs.pipe(0).unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 63, [reader as u64, 0x1000, 1, 0, 0, 0], &mut io);
        p.linux.vfs.close(reader).unwrap();
        let [replacement, replacement_writer] = p.linux.vfs.pipe(0).unwrap();
        assert_eq!(reader, replacement);
        p.linux.vfs.write(replacement_writer, b"n").unwrap();
        let mut producer = p.fork();
        producer.tgid = 2;
        producer.vm_id = 2;
        producer.parent = 1;
        producer.memory.write(0x1100, b"o").unwrap();
        // write(writer, buf, 1); exit(0).
        let code: Vec<_> = [0xd4000001u32, 0xd2800ba8, 0xd2800000, 0xd4000001]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        producer.memory.write(0x4000, &code).unwrap();
        producer.cpu.set_x(0, writer as u64);
        producer.cpu.set_x(1, 0x1100);
        producer.cpu.set_x(2, 1);
        producer.cpu.set_x(8, 64);
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        producer
            .memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        k.processes.insert(1, p);
        k.processes.insert(2, producer);
        assert!(k.parallel_round(&mut io, 1_000_000).unwrap());
        let mut p = k.processes.remove(&1).unwrap();
        if matches!(p.state, State::Blocked(63, args) if args[0] == reader as u64) {
            let State::Blocked(number, args) = p.state else {
                unreachable!()
            };
            k.call(1, &mut p, number, args, &mut io);
        }
        let mut byte = [0];
        p.memory.read(0x1000, &mut byte).unwrap();
        assert_eq!(byte, *b"o");
        assert!(matches!(p.state, State::Ready));
        assert!(p.byte_wait.is_none());
        assert!(p.retained_byte.is_none());
        assert_eq!(p.linux.vfs.read(replacement, 1).unwrap(), b"n");
    }

    #[test]
    fn joined_timer_wait_expires_without_a_notification_after_close_and_fd_reuse() {
        let mut k = kernel();
        let mut p = process();
        let timer = p.linux.vfs.timerfd(1, 0).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        p.linux
            .vfs
            .timerfd_set(timer, Duration::ZERO, Some(deadline))
            .unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 63, [timer as u64, 0x1000, 8, 0, 0, 0], &mut io);
        assert!(matches!(p.state, State::Blocked(63, _)));
        assert_eq!(
            p.byte_wait.as_ref().unwrap().wake_deadline(),
            Some(deadline)
        );
        assert!(!p.byte_wait.as_ref().unwrap().signal.ready());
        p.state = State::Stopped;
        assert!(p.byte_wait_deadline().is_none());
        p.state = State::Blocked(63, [timer as u64, 0x1000, 8, 0, 0, 0]);
        assert_eq!(p.byte_wait_deadline(), Some(deadline));
        p.linux.vfs.close(timer).unwrap();
        assert_eq!(
            p.linux.vfs.eventfd(9, trames_vfs::O_NONBLOCK).unwrap(),
            timer
        );
        let replacement = p.linux.vfs.direct_descriptors().get(timer).unwrap();
        assert!(p.linux.vfs.next_timerfd_deadline().is_none());
        // Exit after the original pending read completes. No guest or host
        // write will notify it, and the table now contains only the eventfd.
        let code: Vec<_> = [0xd2800000u32, 0xd2800ba8, 0xd4000001]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        p.memory.write(0x4000, &code).unwrap();
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        k.processes.insert(1, p);
        assert_eq!(k.drive(&mut io, 1000).unwrap().code, 0);
        assert_eq!(k.processes[&1].memory.read_u64(0x1000).unwrap(), 1);
        assert_eq!(replacement.read(8).unwrap(), 9u64.to_le_bytes());
        assert!(k.processes[&1].byte_wait.is_none());
    }

    #[test]
    fn flock_handoff_reuses_file_but_replaces_a_completed_requests_operation() {
        let mut k = kernel();
        let mut p = process();
        let a = p.linux.vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = p.linux.vfs.open_at(-100, b"/lock", 2, 0).unwrap();
        let (shared, _) = p.linux.vfs.retain_flock(a, 1).unwrap();
        let mut call = crate::run_queue::IoCall {
            number: 32,
            args: [a as u64, 1, 0, 0, 0, 0],
            deadline: None,
            flock: Some(shared.clone()),
            retained_byte: None,
            retained_poll: None,
        };
        p.retain_worker_flock(Some(&call));
        shared.try_lock().unwrap(); // First SH wait completed on the worker.
        p.linux.vfs.flock(b, 5).unwrap();
        let (exclusive, _) = p.linux.vfs.retain_flock(a, 2).unwrap();
        assert_eq!(exclusive.try_lock(), Err(Errno(11)));
        call.args[1] = 2;
        call.flock = Some(exclusive);
        p.retain_worker_flock(Some(&call));
        p.state = State::Blocked(32, call.args);
        let mut io = trames_linux::CapturedOutput::default();
        assert_eq!(k.syscall(1, &mut p, 32, call.args, &mut io), Ok(None));
        p.linux.vfs.flock(b, 8).unwrap();
        assert_eq!(k.syscall(1, &mut p, 32, call.args, &mut io), Ok(Some(0)));
        assert_eq!(p.linux.vfs.flock(b, 5), Err(Errno(11))); // a acquired EX, not stale SH.
    }

    #[test]
    fn actual_flock_worker_handoff_releases_original_ofd_before_the_next_join() {
        let mut k = kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        let mut p = process();
        p.affinity = 3;
        let a = p.linux.vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = p.linux.vfs.open_at(-100, b"/lock", 2, 0).unwrap();
        p.linux.vfs.flock(b, 6).unwrap();
        let [ack_reader, ack_writer] = p.linux.vfs.pipe(trames_vfs::O_NONBLOCK).unwrap();
        p.memory.write(0x1200, b"a").unwrap();
        let parent_code: Vec<_> = [
            0xd2800000u32 | (ack_writer << 5),
            0xd2824001,
            0xd2800022,
            0xd2800808,
            0xd4000001,
            0x14000000,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        p.memory.write(0x4000, &parent_code).unwrap();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 32, [a as u64, 2, 0, 0, 0, 0], &mut io);
        assert!(p.flock_wait.as_ref().unwrap().0.retains_file());
        p.linux.vfs.close(a).unwrap();
        assert_eq!(
            p.linux
                .vfs
                .open_at(-100, b"/replacement", 0x42, 0o600)
                .unwrap(),
            a
        );
        p.linux.vfs.flock(a, 6).unwrap();
        let mut producer = p.fork();
        assert!(producer.flock_wait.is_none());
        producer.tgid = 2;
        producer.vm_id = 2;
        producer.parent = 1;
        // unlock(b); read(ack) until not EAGAIN; flock(b, LOCK_EX | LOCK_NB).
        // Keep a guest runnable across a cohort's host-time cutoff. If both
        // tasks block, the kernel may legitimately return to owner scheduling,
        // which would stop this test from isolating worker-side final release.
        // The parent sends ACK after its accepted flock and last OFD drop.
        let code: Vec<_> = [
            0xd4000001u32,
            0xd2800000 | (ack_reader << 5),
            0xd2826001,
            0xd2800022,
            0xd28007e8,
            0xd4000001,
            0xb1002c1f, // cmn x0, #11: retry only -EAGAIN
            0x54ffff40, // b.eq back to the read argument setup
            0xd2800000 | (b << 5),
            0xd28000c1,
            0xd2800408,
            0xd4000001,
            0x14000000,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        producer.memory.write(0x4000, &code).unwrap();
        producer.cpu.set_x(0, b as u64);
        producer.cpu.set_x(1, 8);
        producer.cpu.set_x(8, 32);
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        producer
            .memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        k.processes.insert(1, p);
        k.processes.insert(2, producer);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let limit = k.instructions + 1_000_000;
            assert!(
                k.parallel_round(&mut io, limit).unwrap(),
                "parent pc={:#x}/ready={}, producer pc={:#x}/ready={}, candidate={}",
                k.processes[&1].cpu.pc,
                matches!(k.processes[&1].state, State::Ready),
                k.processes[&2].cpu.pc,
                matches!(k.processes[&2].state, State::Ready),
                k.parallel_candidate()
            );
            if k.processes[&2].cpu.pc == 0x4030 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "worker ACK/lock handshake timed out"
            );
        }
        assert_eq!(k.processes[&2].cpu.pc, 0x4030);
        assert_eq!(k.processes[&2].cpu.x(0), 0);
        assert!(k.processes[&1].flock_wait.is_none());
        assert_eq!(k.processes[&1].cpu.x(0), 1);
        assert_eq!(
            k.processes.get_mut(&1).unwrap().linux.vfs.flock(a, 6),
            Ok(())
        );
    }

    #[test]
    fn solo_cpu_adopts_related_flock_waiter_but_not_unrelated_waiter() {
        let mut k = kernel();
        let mut cpu = process();
        let a = cpu.linux.vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
        let b = cpu.linux.vfs.open_at(-100, b"/lock", 2, 0).unwrap();
        cpu.linux.vfs.flock(a, 6).unwrap();
        let mut waiter = cpu.fork();
        waiter.vm_id += 1;
        waiter.flock_wait = Some(waiter.linux.vfs.retain_flock(b, 2).unwrap());
        waiter.state = State::Blocked(32, [b as u64, 2, 0, 0, 0, 0]);
        k.processes.insert(1, cpu);
        k.processes.insert(2, waiter);
        assert!(k.parallel_candidate());
        k.processes.insert(1, process());
        assert!(!k.parallel_candidate());
    }

    #[test]
    fn flock_wait_is_retained_by_stop_but_released_by_caught_signal_and_exit() {
        for restart in [false, true] {
            let mut k = kernel();
            let mut p = process();
            let a = p.linux.vfs.open_at(-100, b"/lock", 0x42, 0o600).unwrap();
            p.flock_wait = Some(p.linux.vfs.retain_flock(a, 2).unwrap());
            p.state = State::Blocked(32, [a as u64, 2, 0, 0, 0, 0]);
            Kernel::queue_one(1, &mut p, 19, 0);
            assert_eq!(k.deliver(1, &mut p), Ok(true));
            assert!(matches!(p.state, State::Stopped) && p.flock_wait.is_some());
            p.state = *p.stopped_state.take().unwrap();
            let original_pc = p.cpu.pc;
            p.signals.actions.set(
                10,
                Action {
                    handler: 0x5000,
                    flags: if restart { 0x10000000 } else { 0 },
                    ..Action::default()
                },
            );
            Kernel::queue_one(1, &mut p, 10, 0);
            assert_eq!(k.deliver(1, &mut p), Ok(true));
            assert!(p.flock_wait.is_none());
            // Signal frame restores either EINTR or the original SVC for restart.
            assert!(k
                .syscall(
                    1,
                    &mut p,
                    139,
                    [0; 6],
                    &mut trames_linux::CapturedOutput::default()
                )
                .is_ok());
            assert_eq!(
                p.cpu.pc,
                if restart {
                    original_pc - 4
                } else {
                    original_pc
                }
            );
            if !restart {
                assert_eq!(p.cpu.x(0), error(Errno(4)));
            }
            p.flock_wait = Some(p.linux.vfs.retain_flock(a, 2).unwrap());
            k.exit_one(1, &mut p, 0);
            assert!(p.flock_wait.is_none());
        }
    }

    #[test]
    fn solo_gpu_completion_still_uses_worker_handoff_without_an_io_peer() {
        let mut k = kernel();
        let mut gpu = process();
        gpu.state = State::Gpu {
            retired: true,
            peer_instructions: 0,
            job: 1,
            pc: 0,
            operation: 1,
            instructions: 0,
            began: Instant::now(),
        };
        k.processes.insert(1, gpu);
        assert!(k.parallel_candidate());
    }
    #[test]
    fn affinity_assignment_keeps_flexible_tasks_fair_and_relocates_for_pinned_peers() {
        assert_eq!(
            assign_cpus([(1, 3), (2, 1), (3, 2)], 2),
            vec![(1, 1), (2, 0)]
        );
        assert_eq!(
            assign_cpus([(3, 2), (1, 3), (2, 1)], 2),
            vec![(3, 1), (1, 0)]
        );
        assert_eq!(
            assign_cpus([(1, 1), (2, 1), (3, 2)], 2),
            vec![(1, 0), (3, 1)]
        );
        assert_eq!(assign_cpus([(1, 3), (2, 3)], 2), vec![(1, 0), (2, 1)]);
    }
    pub(super) fn process() -> Box<Process> {
        let mut memory = Memory::default();
        memory.map(0x1000, 8 * PAGE_SIZE, Permissions::RW).unwrap();
        Box::new(Process {
            cpu: Cpu::new(0x4000, 0x9000),
            affinity: 1,
            last_cpu: 0,
            nice: 0,
            scheduler: 0,
            memory,
            linux: Linux::new(0xa000),
            parent: 0,
            parent_thread: 0,
            pdeath_signal: 0,
            group: 1,
            session: 1,
            state: State::Ready,
            signals: Signals::default(),
            wait_event: None,
            poll_deadline: None,
            socket_deadline: None,
            poll_mask: None,
            uring_wait: None,
            flock_wait: None,
            byte_wait: None,
            retained_byte: None,
            retained_poll: None,
            retained_select: None,
            pending_open: None,
            stopped_state: None,
            auto_reap: false,
            tgid: 1,
            started: Instant::now(),
            cpu_time: Duration::ZERO,
            vm_id: 1,
            rekey: None,
            subreaper: false,
            membarrier_registered: Rc::new(Cell::new(false)),
            file_size_limit: Rc::new(Cell::new((u64::MAX, u64::MAX))),
            oom: Arc::new(trames_vfs::OomTask::default()),
            seccomp: seccomp::Seccomp::default(),
        })
    }
    #[test]
    #[ignore = "manual fixed-cohort preparation benchmark; not Firefox acceptance"]
    fn cohort_preparation_profile() {
        use std::hint::black_box;
        const TASKS: u32 = 128;
        const ROUNDS: u64 = 4096;
        let mut k = kernel();
        k.cpu_count = 8;
        k.workers = crate::workers::Pool::new(8);
        k.per_cpu.resize(8, Duration::ZERO);
        let mut cpu = process();
        cpu.affinity = 255;
        // One real owner syscall per round, with no guest byte effects.
        // getrusage(RUSAGE_SELF, NULL) returns EFAULT through the normal path.
        let code: Vec<_> = [
            0xd2800000u32,
            0xd2800001,
            0xd28014a8,
            0xd4000001,
            0x17fffffc,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        cpu.memory.write(0x4000, &code).unwrap();
        cpu.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        for id in 2..=TASKS {
            let mut peer = cpu.fork();
            peer.memory = cpu.memory.share();
            peer.affinity = 255;
            peer.state = State::Futex {
                wait: k
                    .futexes
                    .wait((0, 1, 0x1000), id, u32::MAX, || Ok::<_, ()>(()))
                    .unwrap(),
                deadline: None,
            };
            k.processes.insert(id, peer);
        }
        k.processes.insert(1, cpu);
        let mut io = trames_linux::CapturedOutput::default();
        for _ in 0..16 {
            assert!(k.parallel_round(&mut io, u64::MAX).unwrap());
        }
        let before = (k.instructions, k.syscalls, k.parallel_rounds);
        let began = Instant::now();
        for _ in 0..ROUNDS {
            assert!(black_box(&mut k).parallel_round(&mut io, u64::MAX).unwrap());
        }
        let seconds = began.elapsed().as_secs_f64();
        assert_eq!(k.syscalls - before.1, ROUNDS);
        assert_eq!(k.parallel_rounds - before.2, ROUNDS);
        assert_eq!(k.instructions - before.0, ROUNDS * 5);
        assert_eq!(k.processes.len(), TASKS as usize);
        assert!(k
            .processes
            .iter()
            .filter(|(id, _)| **id != 1)
            .all(|(_, p)| matches!(p.state, State::Futex { ref wait, .. } if !wait.woken())));
        assert_eq!(k.processes[&1].memory.read_u64(0x1000).unwrap(), 0);
        println!(
            "cohort_preparation tasks={TASKS} rounds={ROUNDS} instructions={} seconds={seconds:.6}",
            k.instructions - before.0
        );
    }
    #[test]
    #[ignore = "manual scheduler metadata benchmark; not an end-to-end speed ratio"]
    fn process_table_churn_profile() {
        const TASKS: u32 = 128;
        const ROUNDS: u32 = 1024;
        // Reproduce the old value layout only here, with identical real task
        // state. No guest instructions, memory bytes, or syscall work is timed.
        let mut values: BTreeMap<_, _> = (1..=TASKS).map(|id| (id, *process())).collect();
        let began = Instant::now();
        for _ in 0..ROUNDS {
            for id in 1..=TASKS {
                let p = std::hint::black_box(values.remove(&id).unwrap());
                values.insert(id, p);
            }
        }
        let value_seconds = began.elapsed().as_secs_f64();
        assert_eq!(std::hint::black_box(&values).len(), TASKS as usize);
        drop(values);
        let mut pointers: BTreeMap<_, _> = (1..=TASKS).map(|id| (id, process())).collect();
        let began = Instant::now();
        for _ in 0..ROUNDS {
            for id in 1..=TASKS {
                let p = std::hint::black_box(pointers.remove(&id).unwrap());
                pointers.insert(id, p);
            }
        }
        let pointer_seconds = began.elapsed().as_secs_f64();
        assert_eq!(std::hint::black_box(&pointers).len(), TASKS as usize);
        println!(
            "process_table tasks={TASKS} rounds={ROUNDS} state_bytes={} value_seconds={value_seconds:.6} pointer_seconds={pointer_seconds:.6}",
            std::mem::size_of::<Process>()
        );
    }
    #[test]
    fn terminal_control_signals_use_kernel_authority_and_the_foreground_session() {
        let mut k = kernel();
        let mut sender = process();
        sender.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        let mut root_command = process();
        root_command.session = 9;
        root_command.group = 3;
        assert!(!Kernel::may_signal(&sender, &root_command, 2));
        let mut another_session = root_command.fork();
        another_session.session = 10;
        k.processes.insert(3, root_command);
        k.processes.insert(4, another_session);
        k.terminal_signal(1, &mut sender, 9, 3, 2);
        assert!(k.processes[&3].signals.pending.contains_key(&2));
        assert!(!k.processes[&4].signals.pending.contains_key(&2));
        assert!(!sender.signals.pending.contains_key(&2));
    }
    #[test]
    fn host_pty_keyboard_and_resize_signals_are_scoped_to_the_foreground_session() {
        let mut k = kernel();
        let mut root = process();
        k.refresh_proc(1, &mut root);
        let fd = root.linux.vfs.open_at(-100, b"/dev/ptmx", 2, 0).unwrap();
        let pair = root.linux.vfs.pty(fd).unwrap().unwrap().pair.clone();
        {
            let mut tty = pair.terminal.borrow_mut();
            tty.session = 9;
            tty.foreground = 3;
        }
        pair.resize_from_host(40, 120);
        pair.host_signals.set(1 << 1);
        let mut foreground = process();
        foreground.session = 9;
        foreground.group = 3;
        let mut other = foreground.fork();
        other.session = 10;
        let mut background = foreground.fork();
        background.group = 4;
        k.processes.insert(1, root);
        k.processes.insert(3, foreground);
        k.processes.insert(4, other);
        k.processes.insert(5, background);
        k.pump_guest_ptys();
        assert!(k.processes[&3].signals.pending.contains_key(&2));
        assert!(k.processes[&3].signals.pending.contains_key(&28));
        for id in [1, 4, 5] {
            assert!(!k.processes[&id].signals.pending.contains_key(&2));
            assert!(!k.processes[&id].signals.pending.contains_key(&28));
        }
        assert_eq!(pair.host_signals.get(), 0);
        assert!(!pair.host_resize_pending.get());
    }
    pub(super) fn kernel() -> Kernel {
        Kernel {
            byte_target: Arc::new(JoinedByteWake),
            memory_limits: super::super::MemoryLimits::default(),
            cpu_count: 1,
            task_limit: trames_vfs::MAX_TASKS,
            engine: Default::default(),
            backend_error: None,
            workers: crate::workers::Pool::new(1),
            futexes: Default::default(),
            futex_ready: Vec::new(),
            parallel_memory: trames_memory::parallel::Registry::default(),
            parallel_rounds: 0,
            vm_checkpoint_groups: 0,
            vm_checkpoint_spaces: 0,
            vm_local_syscalls: 0,
            persistent_control_checks: 0,
            worker_slices: 0,
            worker_chunks: 0,
            worker_syscalls: 0,
            worker_direct_syscalls: 0,
            worker_futex_wakes: 0,
            worker_futex_woken: 0,
            worker_futex_requeues: 0,
            worker_futex_waits: 0,
            worker_task_resumes: 0,
            worker_task_yields: 0,
            worker_io_waits: 0,
            worker_service_waits: 0,
            worker_file_syscalls: 0,
            worker_socket_syscalls: 0,
            worker_timer_syscalls: 0,
            worker_poll_syscalls: 0,
            worker_uring_syscalls: 0,
            worker_fd_syscalls: 0,
            worker_gpu_calls: 0,
            worker_gpu_waits: 0,
            service_requests: 0,
            disk_reads: 0,
            peak_disk_reads: 0,
            disk_read_bytes: 0,
            service_write_buffer: Vec::new(),
            serviced_syscalls: 0,
            service_wait: Duration::ZERO,
            parallel_memory_time: Duration::ZERO,
            parallel_dispatch_time: Duration::ZERO,
            parallel_stop_time: Duration::ZERO,
            next_parallel_pid: 0,
            per_cpu: vec![Duration::ZERO; 1],
            processes: BTreeMap::new(),
            next_pid: 2,
            terminal: None,
            started: Instant::now(),
            instructions: 0,
            boot_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            context_switches: 0,
            decode_lookups: 0,
            instructions_decoded: 0,
            decode_misses: 0,
            cpu_total: Duration::ZERO,
            syscall_total: Duration::ZERO,
            syscalls: 0,
            proc_refreshes: 0,
            proc_maps: RefCell::new(BTreeMap::new()),
            profile_syscalls: false,
            idle: Duration::ZERO,
            load: [0.0; 3],
            load_sample: Instant::now(),
            next_resource: 2,
            timers: BTreeMap::new(),
            next_timer: 1,
            native: trames_accel::native::Registry::default(),
            gpu: RefCell::new(BTreeMap::new()),
            gpu_budget: trames_vulkan::Budget::default(),
            gpu_display: trames_vulkan::Display::default(),
            gpu_compiles: 0,
            gpu_peak_pending: 0,
            gpu_peer_instructions: 0,
            gpu_wait_time: Duration::ZERO,
            gpu_transfers: trames_vulkan::TransferMetrics::default(),
        }
    }
    #[test]
    fn proc_maps_refresh_after_shared_protect_reserve_unmap_and_fork() {
        let k = kernel();
        let mut p = process();
        assert_eq!(
            k.process_maps(&p),
            b"000000001000-000000009000 rw-p 00000000 00:00 0\n"
        );
        let mut peer = p.fork();
        peer.memory = p.memory.share();
        peer.memory
            .protect(0x2000, PAGE_SIZE, Permissions::R)
            .unwrap();
        let maps = k.process_maps(&p);
        assert!(String::from_utf8_lossy(&maps).contains("000000002000-000000003000 r--p"));
        assert_eq!(k.process_maps(&peer), maps);
        p.memory.reserve(0x100000, 2 * PAGE_SIZE, false).unwrap();
        let maps = String::from_utf8(k.process_maps(&p)).unwrap();
        assert!(maps.contains("000000100000-000000102000 ---p"));
        p.memory
            .protect(0x100000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        let maps = String::from_utf8(k.process_maps(&peer)).unwrap();
        assert!(maps.contains("000000100000-000000101000 rw-p"));
        p.memory.unmap(0x100000, 2 * PAGE_SIZE).unwrap();
        assert!(!String::from_utf8(k.process_maps(&p))
            .unwrap()
            .contains("000000100000-"));
        let mut child = p.fork();
        child.vm_id = 2;
        child
            .memory
            .protect(0x2000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        assert_eq!(
            k.process_maps(&child),
            b"000000001000-000000009000 rw-p 00000000 00:00 0\n"
        );
        assert_eq!(k.process_maps(&p), k.process_maps(&peer));
        assert_ne!(k.process_maps(&p), k.process_maps(&child));
        // An exited group leader has released its Memory while surviving
        // threads still share the old vm_id. It must not evict their maps.
        let mut leader = process();
        leader.vm_id = p.vm_id;
        leader.memory = Memory::default();
        assert!(k.process_maps(&leader).is_empty());
        assert_eq!(k.process_maps(&p), k.process_maps(&peer));
        assert_eq!(k.proc_maps.borrow().len(), 3);
    }

    #[test]
    fn proc_mapping_cache_never_freezes_argv_fds_or_credentials_and_retires_dead_vms() {
        let k = kernel();
        let mut p = process();
        p.linux.arguments = vec![b"first".to_vec()];
        p.linux.argument_pointers = vec![0x1000];
        p.memory.write(0x1000, b"first\0").unwrap();
        let before = k.process_info(1, &p);
        p.memory.write(0x1000, b"other\0").unwrap();
        let pipe = p.linux.vfs.pipe(0).unwrap();
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        let after = k.process_info(1, &p);
        assert_eq!(before.maps, after.maps);
        assert_eq!(before.arguments, [b"first".to_vec()]);
        assert_eq!(after.arguments, [b"other".to_vec()]);
        assert_eq!(after.credentials.euid, 1000);
        assert_eq!(after.fds.len(), before.fds.len() + 2);
        assert!(after.fds.iter().any(|fd| fd.fd == pipe[0]));
        let mut old = p.fork();
        old.vm_id = 2;
        k.process_maps(&old);
        assert_eq!(k.proc_maps.borrow().len(), 2);
        k.refresh_proc(1, &mut p);
        assert_eq!(k.proc_maps.borrow().len(), 1);
    }

    #[test]
    fn private_epoch_admission_counts_real_vm_roots_and_external_aliases() {
        let mut k = kernel();
        let mut p = process();
        let mut peer = p.fork();
        peer.memory = p.memory.share();
        peer.state = State::Blocked(98, [0; 6]);
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        k.processes.insert(3, process());
        let prepare = |k: &mut Kernel, ids: &[u32]| {
            let chosen = ids
                .iter()
                .enumerate()
                .map(|(slot, &id)| (id, slot))
                .collect::<Vec<_>>();
            k.prepare_parallel_views(&chosen).unwrap()
        };
        let mut views = prepare(&mut k, &[1, 3]);
        k.admit_private_views(&mut views);
        assert!(views.iter().all(|(_, _, v)| v.exclusive_private_enabled()));
        drop(views);
        let mut views = prepare(&mut k, &[1, 2]);
        k.admit_private_views(&mut views);
        assert!(views.iter().all(|(_, _, v)| !v.exclusive_private_enabled()));
        assert!(views.iter().all(|(_, _, v)| v.readonly_private_enabled()));
        assert!(k.parallel_memory.metrics.cache_hits > 0);
        drop(views);
        // A safe host callback could retain this alias and access it during an
        // unrelated VM's output. Its presence must disable the private fast path.
        let external = k.processes.get_mut(&1).unwrap().memory.share();
        let mut views = prepare(&mut k, &[1, 2]);
        k.admit_private_views(&mut views);
        assert!(views.iter().all(|(_, _, v)| !v.readonly_private_enabled()));
        drop(views);
        // A zombie may retain vm_id while its memory has already been retired.
        // Counting only vm_id would accidentally substitute it for `external`.
        k.processes.get_mut(&2).unwrap().memory = Memory::default();
        let mut views = prepare(&mut k, &[1, 3]);
        k.admit_private_views(&mut views);
        assert!(!views[0].2.exclusive_private_enabled());
        assert!(views[1].2.exclusive_private_enabled());
        drop(views);
        drop(external);
        // Surviving external Views also block admission, even with no extra
        // coordinator Memory wrapper.
        let mut views = prepare(&mut k, &[1, 3]);
        let external = views[0].2.clone();
        k.admit_private_views(&mut views);
        assert!(!views[0].2.exclusive_private_enabled());
        drop(external);
        drop(views);
    }
    #[test]
    fn independent_fork_workers_use_private_memory_without_merging_writes() {
        let mut p = process();
        // ldaddal x1,x3,[x0]; subs x2,x2,#1; b.ne -8; exit(0).
        for (i, word) in [
            0xf8e10003u32,
            0xf1000442,
            0x54ffffc1,
            0xd2800ba8,
            0xd2800000,
            0xd4000001,
        ]
        .into_iter()
        .enumerate()
        {
            p.memory
                .write(0x4000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        p.cpu.set_x(0, 0x8000);
        p.cpu.set_x(1, 1);
        p.cpu.set_x(2, 50000);
        p.affinity = 3;
        let mut peer = p.fork();
        peer.vm_id = 2;
        peer.parent = 1;
        let mut k = kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.next_pid = 3;
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        let exit = k
            .drive(&mut trames_linux::CapturedOutput::default(), 400000)
            .unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(exit.instructions, 300006);
        for p in k.processes.values() {
            assert_eq!(p.memory.read_u64(0x8000).unwrap(), 50000);
        }
        assert!(k.parallel_memory.metrics.exclusive_private_views >= 2);
    }
    #[test]
    fn native_workers_execute_shared_atomic_guest_loops_and_account_the_budget() {
        let mut p = process();
        p.memory = Memory::default();
        p.memory
            .map(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RW,
            )
            .unwrap();
        p.memory
            .map(
                0x8000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RW,
            )
            .unwrap();
        // ldaddal x1,x3,[x0]; subs x2,x2,#1; b.ne -8; exit(0).
        let code = [
            0xf8e10003u32,
            0xf1000442,
            0x54ffffc1,
            0xd2800ba8,
            0xd2800000,
            0xd4000001,
        ];
        for (i, word) in code.iter().enumerate() {
            p.memory
                .write(0x4000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.cpu.set_x(0, 0x8000);
        p.cpu.set_x(1, 1);
        p.cpu.set_x(2, 50000);
        p.affinity = 3;
        let mut peer = p.fork();
        peer.memory = p.memory.share();
        peer.tgid = 1;
        peer.parent = 1;
        peer.auto_reap = false;
        let mut k = kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.next_pid = 3;
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        let exit = k
            .drive(&mut trames_linux::CapturedOutput::default(), 400000)
            .unwrap();
        assert_eq!(exit.code, 0);
        assert_eq!(k.processes[&1].memory.read_u64(0x8000).unwrap(), 100000);
        assert_eq!(exit.instructions, 300006);
        assert!(k.parallel_rounds > 0);
        assert!(k.parallel_memory.metrics.readonly_private_views > 0);
        // Without a startup barrier the host may schedule these finite tasks
        // consecutively. Real SMP publication fixtures require overlapping work.
        assert!(k.workers.peak.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }
    fn spinning_peers() -> Kernel {
        let mut p = process();
        // add x0,x0,#1; b -4. No guest syscall can bring these CPUs back.
        for (i, word) in [0x91000400u32, 0x17ffffff].into_iter().enumerate() {
            p.memory
                .write(0x4000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.affinity = 3;
        let mut peer = p.fork();
        peer.memory = p.memory.share();
        peer.parent = 1;
        let mut k = kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        k
    }
    #[test]
    fn pure_queries_keep_a_bounded_serial_quantum_with_blocked_peers() {
        struct Polls(usize);
        impl GuestOutput for Polls {
            fn control(&mut self, _: &mut trames_vfs::Vfs) -> std::io::Result<bool> {
                self.0 += 1;
                Ok(true)
            }
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
        }
        let mut p = process();
        for (i, word) in [0xd4000001u32, 0x17ffffff].into_iter().enumerate() {
            p.memory
                .write_array(0x4000 + 4 * i as u64, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(
                0x4000,
                trames_memory::PAGE_SIZE,
                trames_memory::Permissions::RX,
            )
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.cpu.set_x(8, 172);
        let mut peer = p.fork();
        peer.state = State::Sleep(Instant::now() + Duration::from_secs(86400), 0);
        let mut k = kernel();
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        let mut io = Polls(0);
        assert!(matches!(
            k.drive(&mut io, 1000),
            Err(RuntimeError::BudgetExceeded(1000))
        ));
        assert_eq!(k.instructions, 1000);
        assert_eq!(k.processes[&1].cpu.x(0), 1);
        assert_eq!(k.syscalls, 500);
        assert!(
            io.0 < 64,
            "pure queries repeatedly rescanned blocked peers: {}",
            io.0
        );
    }
    #[test]
    fn futex_ready_tickets_do_not_wake_a_reused_pid_or_timeout_a_woken_task() {
        let mut k = kernel();
        let mut p = process();
        let old = k
            .futexes
            .wait((0, 7, 0x1000), 1, 1, || Ok::<_, ()>(()))
            .unwrap();
        p.state = State::Futex {
            wait: old,
            deadline: None,
        };
        k.processes.insert(1, p);
        assert_eq!(k.futexes.wake((0, 7, 0x1000), 1, 1), 1);
        let new = k
            .futexes
            .wait((0, 7, 0x1000), 1, 1, || Ok::<_, ()>(()))
            .unwrap();
        k.processes.get_mut(&1).unwrap().state = State::Futex {
            wait: new.clone(),
            deadline: None,
        };
        assert!(!k.resume_futex_ready());
        assert!(matches!(k.processes[&1].state, State::Futex { .. }));
        assert!(!new.woken());
        assert_eq!(k.futexes.wake((0, 7, 0x1000), 1, 1), 1);
        let mut p = k.processes.remove(&1).unwrap();
        p.state = State::Futex {
            wait: new,
            deadline: Some(Instant::now()),
        };
        assert!(k.resume_event(&mut p));
        assert_eq!(p.cpu.x(0), 0); // completed wake wins over the later timeout
        k.processes.insert(1, p);
        assert!(!k.resume_futex_ready());
    }
    #[test]
    fn futex_signal_cancels_registration_and_stopped_exit_cannot_leave_a_waiter() {
        let mut k = kernel();
        let mut p = process();
        assert_eq!(
            k.event_call(1, &mut p, 98, [0x1000, 128, 0, 0, 0, 0]),
            Ok(None)
        );
        p.signals.actions.set_handler(10, 0x5000);
        Kernel::queue_one(1, &mut p, 10, 1);
        assert!(k.deliver(1, &mut p).unwrap());
        assert_eq!(k.futexes.wake((0, 1, 0x1000), 1, u32::MAX), 0);
        let mut stopped = process();
        assert_eq!(
            k.event_call(2, &mut stopped, 98, [0x1000, 128, 0, 0, 0, 0]),
            Ok(None)
        );
        Kernel::queue_one(2, &mut stopped, 19, 1);
        assert!(k.deliver(2, &mut stopped).unwrap());
        assert!(matches!(stopped.state, State::Stopped));
        k.exit_one(2, &mut stopped, 9);
        assert!(stopped.stopped_state.is_none());
        assert_eq!(k.futexes.wake((0, 1, 0x1000), 1, u32::MAX), 0);
    }
    #[test]
    fn futex_requeue_retains_stopped_registration_and_deadline_until_continue() {
        let mut k = kernel();
        let mut waiter = process();
        let mut caller = process();
        let deadline = Instant::now() + Duration::from_secs(60);
        let wait = k
            .futexes
            .wait((0, 1, 0x1000), 2, 2, || Ok::<_, ()>(()))
            .unwrap();
        waiter.state = State::Futex {
            wait,
            deadline: Some(deadline),
        };
        Kernel::queue_one(2, &mut waiter, 19, 1);
        assert!(k.deliver(2, &mut waiter).unwrap());
        k.processes.insert(2, waiter);
        // CMP_REQUEUE moves the stopped task too; no process-wide scan.
        assert_eq!(
            k.event_call(1, &mut caller, 98, [0x1000, 132, 0, 1, 0x2000, 0]),
            Ok(Some(1))
        );
        assert_eq!(k.futexes.wake((0, 1, 0x1000), 1, 2), 0);
        assert_eq!(k.futexes.wake((0, 1, 0x2000), 1, 1), 0);
        assert_eq!(k.futexes.wake((0, 1, 0x2000), 1, 2), 1);
        assert!(!k.resume_futex_ready());
        let mut p = k.processes.remove(&2).unwrap();
        assert!(
            matches!(p.stopped_state.as_deref(), Some(State::Futex { deadline: Some(d), .. }) if *d == deadline)
        );
        Kernel::queue_one(2, &mut p, 18, 1);
        assert!(k.resume_event(&mut p));
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 0);
    }
    #[test]
    fn continuous_peers_cancel_at_control_checkpoints_and_commit_the_exact_budget() {
        struct CancelAfterTwoPolls(usize);
        impl GuestOutput for CancelAfterTwoPolls {
            fn control(&mut self, _: &mut trames_vfs::Vfs) -> std::io::Result<bool> {
                self.0 += 1;
                Ok(self.0 < 3)
            }
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
        }
        let mut k = spinning_peers();
        assert!(matches!(
            k.drive(&mut CancelAfterTwoPolls(0), u64::MAX),
            Err(RuntimeError::Cancelled)
        ));
        assert!(k.instructions > 0);
        assert!(k.worker_chunks > 0);
        for limit in [1, 17, 65_539] {
            let mut k = spinning_peers();
            assert!(
                matches!(k.drive(&mut trames_linux::CapturedOutput::default(), limit), Err(RuntimeError::BudgetExceeded(n)) if n == limit)
            );
            assert_eq!(k.instructions, limit);
            assert_eq!(
                k.processes.values().map(|p| p.cpu.x(0)).sum::<u64>(),
                limit.div_ceil(2)
            );
        }
    }
    #[test]
    fn continuous_deadlines_include_sleep_and_do_not_spin_on_unread_expired_timerfd() {
        let mut k = spinning_peers();
        let p = k.processes.get_mut(&1).unwrap();
        let fd = p.linux.vfs.timerfd(1, 0).unwrap();
        p.linux
            .vfs
            .timerfd_set(fd, Duration::ZERO, Some(Instant::now()))
            .unwrap();
        p.poll_deadline = Some(Instant::now());
        assert_eq!(k.parallel_timeout(), Duration::from_millis(10));
        k.processes.get_mut(&1).unwrap().state = State::Blocked(63, [0; 6]);
        assert_eq!(k.parallel_timeout(), Duration::from_millis(10));
        k.processes.get_mut(&1).unwrap().state = State::Blocked(22, [0; 6]);
        assert_eq!(k.parallel_timeout(), Duration::ZERO);
        k.processes.get_mut(&1).unwrap().state =
            State::Sleep(Instant::now() + Duration::from_millis(1), 0);
        assert!(k.parallel_timeout() <= Duration::from_millis(1));
    }
    #[test]
    fn worker_poll_deadlines_do_not_force_unrelated_cpus_to_checkpoint() {
        let mut k = spinning_peers();
        let p = k.processes.get_mut(&1).unwrap();
        let fd = p.linux.vfs.timerfd(1, 0).unwrap();
        p.linux
            .vfs
            .timerfd_set(
                fd,
                Duration::ZERO,
                Some(Instant::now() + Duration::from_millis(1)),
            )
            .unwrap();
        p.poll_deadline = Some(Instant::now());
        p.state = State::Blocked(73, [0, 0, 0, 0, 0, 0]);
        assert_eq!(k.parallel_timeout(), Duration::from_millis(10));
        // An owner-side pselect still needs its saved timeout boundary.
        k.processes.get_mut(&1).unwrap().state = State::Blocked(72, [0; 6]);
        assert_eq!(k.parallel_timeout(), Duration::ZERO);
    }
    #[test]
    fn socket_timeout_wakes_continuous_peers_but_not_stopped_or_runnable_tasks() {
        let mut k = spinning_peers();
        k.processes.get_mut(&1).unwrap().socket_deadline = Some(Instant::now());
        assert_eq!(k.parallel_timeout(), Duration::from_millis(10));
        k.processes.get_mut(&1).unwrap().state = State::Blocked(212, [0; 6]);
        assert_eq!(k.parallel_timeout(), Duration::ZERO);
        k.processes.get_mut(&1).unwrap().state = State::Stopped;
        assert_eq!(k.parallel_timeout(), Duration::from_millis(10));
    }
    #[test]
    fn worker_tcp_waits_do_not_keep_owner_socket_polling_or_reset_deadlines() {
        use std::net::{Ipv4Addr, TcpListener};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut k = spinning_peers();
        let p = k.processes.get_mut(&1).unwrap();
        p.linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = p.linux.vfs.socket(2, 1, 0).unwrap();
        let socket = p.linux.vfs.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let _peer = listener.accept().unwrap().0;
        assert_eq!(socket.connect_complete(), Ok(true));
        p.state = State::Blocked(63, [fd as u64, 0x1000, 1, 0, 0, 0]);
        p.socket_deadline = Some(Instant::now());
        assert!(p.worker_io_candidate(1));
        assert_eq!(k.parallel_timeout(), Duration::from_millis(10));
        // Message ABI is still owner-side, including its timer/poll boundary.
        let p = k.processes.get_mut(&1).unwrap();
        p.state = State::Blocked(207, [fd as u64, 0x1000, 1, 0, 0, 0]);
        assert!(!p.worker_io_candidate(1));
        assert_eq!(k.parallel_timeout(), Duration::ZERO);
        k.processes.get_mut(&1).unwrap().socket_deadline = None;
        assert_eq!(k.parallel_timeout(), Duration::from_millis(1));
    }
    #[test]
    fn prctl_seccomp_modes_translate_to_syscall_operations() {
        let mut k = kernel();
        let mut p = process();
        let mut io = trames_linux::CapturedOutput::default();
        assert_eq!(
            k.syscall(1, &mut p, 167, [22, 0, 0, 0, 0, 0], &mut io),
            Err(Errno(22))
        );
        assert_eq!(
            k.syscall(1, &mut p, 167, [22, 1, 0xffff, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(p.seccomp.mode(), 1);
        let mut p = process();
        p.memory.write(0x1000, &[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        write_u64(&mut p.memory, 0x1008, 0x1100).unwrap();
        p.memory
            .write(0x1100, &[6, 0, 0, 0, 0, 0, 0xff, 0x7f])
            .unwrap();
        assert_eq!(
            k.syscall(1, &mut p, 167, [22, 2, 0x1000, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_eq!(p.seccomp.mode(), 2);
        assert_eq!(p.seccomp.count(), 1);
    }
    #[test]
    fn gpu_wait_defers_caught_handlers_but_preserves_stop_continue() {
        let mut p = process();
        let mut k = kernel();
        p.state = State::Gpu {
            retired: false,
            peer_instructions: 0,
            job: 1,
            pc: 0x4000,
            operation: 27,
            instructions: 0,
            began: Instant::now(),
        };
        p.signals.actions.set_handler(10, 0x5000);
        Kernel::queue_one(1, &mut p, 10, 1);
        assert!(!k.deliver(1, &mut p).unwrap());
        assert!(p.signals.pending.contains_key(&10));
        Kernel::queue_one(1, &mut p, 19, 1);
        assert!(k.deliver(1, &mut p).unwrap());
        assert!(matches!(p.state, State::Stopped));
        assert!(matches!(
            p.stopped_state.as_deref(),
            Some(State::Gpu { job: 1, .. })
        ));
        Kernel::queue_one(1, &mut p, 18, 1);
        assert!(matches!(p.state, State::Gpu { job: 1, .. }));
    }
    #[test]
    fn a_removed_gpu_context_completes_once_without_reexecuting_the_stub() {
        let mut p = process();
        let mut k = kernel();
        k.instructions = 123;
        p.state = State::Gpu {
            retired: false,
            peer_instructions: 0,
            job: 1,
            pc: 0x4000,
            operation: 27,
            instructions: 10,
            began: Instant::now(),
        };
        assert!(k.resume_gpu(1, &mut p));
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.pc, 0x4004);
        assert_eq!(p.cpu.x(0), (-4i64) as u64);
        assert_eq!(k.gpu_peer_instructions, 113);
        assert_eq!(k.instructions, 124);
        assert!(!k.resume_gpu(1, &mut p));
        assert_eq!(k.instructions, 124);
    }
    #[test]
    fn worker_gpu_completion_preserves_accepted_retirement_and_uses_local_deadlines() {
        let mut p = process();
        let mut k = kernel();
        k.instructions = 123;
        p.state = State::Gpu {
            retired: true,
            peer_instructions: 0,
            job: 1,
            pc: 0x4000,
            operation: 27,
            instructions: 10,
            began: Instant::now(),
        };
        assert!(k.resume_gpu(1, &mut p));
        assert_eq!(k.instructions, 123);
        assert_eq!(p.cpu.pc, 0x4004);
        let mut k = spinning_peers();
        k.processes.get_mut(&1).unwrap().state = State::Gpu {
            retired: true,
            peer_instructions: 0,
            job: 1,
            pc: 0x4000,
            operation: 27,
            instructions: 0,
            began: Instant::now(),
        };
        assert_eq!(k.parallel_timeout(), Duration::from_millis(10));
    }
    #[test]
    fn session_leader_fifo_open_waits_before_terminal_inspection_and_is_interruptible() {
        let mut p = process();
        let mut k = kernel();
        let mut io = trames_linux::CapturedOutput::default();
        p.linux.vfs.mknod_at(-100, b"/fifo", 0o10600, 0).unwrap();
        p.memory.write(0x1000, b"/fifo\0").unwrap();
        let args = [(-100i64) as u64, 0x1000, 0, 0, 0, 0];
        k.call(1, &mut p, 56, args, &mut io);
        assert!(matches!(p.state, State::Blocked(56, _)));
        let hidden = p.pending_open.unwrap();
        assert!(p.linux.vfs.fd_kind(hidden).is_err());
        p.signals.actions.set_handler(10, 0x4000);
        Kernel::queue_one(1, &mut p, 10, 1);
        assert!(k.deliver(1, &mut p).unwrap());
        assert!(p.pending_open.is_none());
        assert!(p.linux.vfs.fifo_open_ready(hidden).is_err());
        // The handler's saved ucontext contains EINTR, not a reserved fd/EBADF.
        let mut result = [0; 8];
        p.memory.read(p.cpu.sp + 312, &mut result).unwrap();
        assert_eq!(u64::from_le_bytes(result), error(Errno(4)));
    }
    #[test]
    fn failed_blocked_epoll_clears_deadline_and_restores_its_temporary_signal_mask() {
        let mut p = process();
        let mut k = kernel();
        p.poll_deadline = Some(Instant::now());
        p.poll_mask = Some(0x200);
        p.signals.mask = 0x400;
        let a = [999, 0x4800, 1, u64::MAX, 0, 8];
        p.state = State::Blocked(22, a);
        k.call(
            1,
            &mut p,
            22,
            a,
            &mut trames_linux::CapturedOutput::default(),
        );
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), error(Errno(9)));
        assert!(p.poll_deadline.is_none());
        assert!(p.poll_mask.is_none());
        assert_eq!(p.signals.mask, 0x200);
    }
    #[test]
    fn indefinite_poll_waits_keep_host_stdin_as_an_external_source() {
        struct Input(bool);
        impl GuestOutput for Input {
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn stdin_ready(&mut self) -> std::io::Result<bool> {
                Ok(self.0)
            }
        }
        for number in [73, 72, 22, 441] {
            let mut k = kernel();
            let mut p = process();
            let a = if number == 73 {
                write_u64(&mut p.memory, 0x1000, 1u64 << 32).unwrap();
                [0x1000, 1, 0, 0, 0, 0]
            } else if number == 72 {
                write_u64(&mut p.memory, 0x1000, 1).unwrap();
                [1, 0x1000, 0, 0, 0, 0]
            } else {
                let epoll = p.linux.vfs.epoll_create(0).unwrap();
                p.linux.vfs.epoll_ctl(epoll, 1, 0, 1, 42).unwrap();
                [
                    epoll as u64,
                    0x1000,
                    1,
                    if number == 22 { u64::MAX } else { 0 },
                    0,
                    8,
                ]
            };
            let mut input = Input(false);
            k.call(1, &mut p, number, a, &mut input);
            assert!(matches!(p.state, State::Blocked(n, _) if n == number));
            assert_eq!(p.linux.vfs.live_sockets(), 0);
            assert!(p.poll_deadline.is_none());
            assert!(Kernel::waits_for_host_stdin(&p), "syscall={number}");
            if number == 73 {
                // Mutation of the guest array cannot retarget an accepted wait.
                write_u64(&mut p.memory, 0x1000, u32::MAX as u64).unwrap();
                assert!(Kernel::waits_for_host_stdin(&p));
            }
            input.0 = true;
            k.call(1, &mut p, number, a, &mut input);
            assert!(matches!(p.state, State::Ready));
            assert_eq!(p.cpu.x(0), 1);
            assert!(!Kernel::waits_for_host_stdin(&p));
        }
        let mut k = kernel();
        let mut p = process();
        let [reader, _writer] = p.linux.vfs.pipe(0).unwrap();
        write_u64(&mut p.memory, 0x1000, reader as u64 | (1u64 << 32)).unwrap();
        k.call(1, &mut p, 73, [0x1000, 1, 0, 0, 0, 0], &mut Input(false));
        assert!(matches!(p.state, State::Blocked(73, _)));
        assert!(!Kernel::waits_for_host_stdin(&p));
    }
    #[test]
    fn stdio_eagain_blocks_only_without_nonblocking_flag() {
        struct Pending;
        impl GuestOutput for Pending {
            fn write(&mut self, _: OutputFd, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
            fn poll_stdin(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
        }
        let mut k = kernel();
        let mut p = process();
        p.memory.write(0x1000, b"a").unwrap();
        let mut io = Pending;
        for (number, fd, flags) in [(64, 1, 1), (63, 0, 0)] {
            let args = [fd, 0x1000, 1, 0, 0, 0];
            k.call(1, &mut p, number, args, &mut io);
            assert!(matches!(p.state, State::Blocked(n, _) if n == number));
            p.linux
                .vfs
                .set_status_flags(fd as u32, flags | O_NONBLOCK)
                .unwrap();
            k.call(1, &mut p, number, args, &mut io);
            assert!(matches!(p.state, State::Ready));
            assert_eq!(p.cpu.x(0), error(Errno(11)));
        }
    }

    #[test]
    fn splice_blocks_on_backpressure_and_respects_output_nonblocking() {
        let mut k = kernel();
        let mut p = process();
        let mut io = trames_linux::CapturedOutput::default();
        let [r, w] = p.linux.vfs.pipe(0).unwrap();
        let [r2, w2] = p.linux.vfs.pipe(0).unwrap();
        p.linux.vfs.write(w, b"abc").unwrap();
        while p.linux.vfs.write(w2, &[0; 4096]).is_ok() {}
        let a = [r as u64, 0, w2 as u64, 0, 3, 0];
        k.call(1, &mut p, 76, a, &mut io);
        assert!(matches!(p.state, State::Blocked(76, _)));
        p.linux.vfs.set_status_flags(w2, 1 | O_NONBLOCK).unwrap();
        k.call(1, &mut p, 76, a, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), error(Errno(11)));
        p.linux.vfs.read(r2, 3).unwrap();
        k.call(1, &mut p, 76, a, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 3);
        assert_eq!(p.linux.vfs.read(r, 3), Err(Errno(11)));
    }
    #[test]
    fn close_range_unshare_detaches_only_callers_shared_table() {
        let mut k = kernel();
        let mut p = process();
        let mut io = trames_linux::CapturedOutput::default();
        let fd = p.linux.vfs.open_at(-100, b"/file", 0x42, 0o600).unwrap();
        k.processes
            .insert(2, p.fork_state(p.memory.clone(), true, true, true));
        assert_eq!(
            k.syscall(
                1,
                &mut p,
                436,
                [fd as u64, u32::MAX as u64, 8, 0, 0, 0],
                &mut io
            ),
            Err(Errno(22))
        );
        assert!(p
            .linux
            .vfs
            .shares_descriptors_with(&k.processes[&2].linux.vfs));
        assert_eq!(
            k.syscall(
                1,
                &mut p,
                436,
                [fd as u64, u32::MAX as u64, 2, 0, 0, 0],
                &mut io
            ),
            Ok(Some(0))
        );
        assert!(!p
            .linux
            .vfs
            .shares_descriptors_with(&k.processes[&2].linux.vfs));
        assert_eq!(p.linux.vfs.fd_kind(fd), Err(Errno(9)));
        assert!(k.processes[&2].linux.vfs.fd_kind(fd).is_ok());
        let fd = p.linux.vfs.open_at(-100, b"/file", 0, 0).unwrap();
        assert_eq!(
            k.syscall(1, &mut p, 436, [fd as u64, fd as u64, 4, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert!(p.linux.vfs.fd_kind(fd).is_ok());
        p.linux.vfs.close_exec();
        assert_eq!(p.linux.vfs.fd_kind(fd), Err(Errno(9)));
    }

    #[test]
    fn clone_files_controls_live_descriptor_bits_independently_of_clone_vm() {
        use trames_linux::CapturedOutput;
        for flags in [0, 0x100, 0x400, 0x500] {
            let mut k = kernel();
            let mut p = process();
            let [fd, _] = p.linux.vfs.pipe(0).unwrap();
            let id = k
                .syscall(
                    1,
                    &mut p,
                    220,
                    [flags | 17, 0, 0, 0, 0, 0],
                    &mut CapturedOutput::default(),
                )
                .unwrap()
                .unwrap() as u32;
            let child = &k.processes[&id];
            let bits = child.linux.vfs.fd_flags_snapshot();
            bits.fcntl(fd, 2, 1).unwrap();
            assert_eq!(
                p.linux.vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC != 0,
                flags & 0x400 != 0,
                "clone flags {flags:x}"
            );
        }
    }
    #[test]
    fn metadata_unshare_range_and_fs_only_unshare_preserve_table_domains() {
        use trames_linux::CapturedOutput;
        let mut k = kernel();
        let mut p = process();
        let [fd, _] = p.linux.vfs.pipe(0).unwrap();
        let memory = p.memory.share();
        let peer = p.fork_with_memory(memory);
        k.processes.insert(2, peer);
        let old = p.linux.vfs.fd_flags_snapshot();
        let mut io = CapturedOutput::default();
        assert_eq!(
            k.syscall(1, &mut p, 97, [0x200, 0, 0, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert!(!p.linux.vfs.shares_context_with(&k.processes[&2].linux.vfs));
        p.linux.vfs.set_umask(0o077);
        assert_eq!(k.processes[&2].linux.vfs.umask(), 0o022);
        old.fcntl(fd, 2, 1).unwrap();
        assert_ne!(p.linux.vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC, 0);
        assert_ne!(
            k.processes[&2].linux.vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC,
            0
        );
        old.fcntl(fd, 2, 0).unwrap();
        assert_eq!(
            k.syscall(1, &mut p, 436, [fd as u64, fd as u64, 6, 0, 0, 0], &mut io),
            Ok(Some(0))
        );
        assert_ne!(p.linux.vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC, 0);
        assert_eq!(
            k.processes[&2].linux.vfs.flags(fd).unwrap() & trames_vfs::O_CLOEXEC,
            0
        );
    }
    #[test]
    fn unsupported_instruction_log_survives_child_exit() {
        let mut k = kernel();
        let parent = process();
        let mut child = parent.fork();
        k.synchronous_fault(
            2,
            &mut child,
            &trames_cpu::CpuFault::Instruction {
                pc: 0x4560,
                instruction: 0x2518e3e0,
            },
        );
        let text = String::from_utf8(parent.linux.vfs.syslog(3, 4096).unwrap()).unwrap();
        assert!(text.contains("pid=2"));
        assert!(text.contains("0x2518e3e0"));
        assert!(text.contains("0x4560"));
    }
    #[test]
    fn thread_directed_stop_and_continue_change_the_entire_group() {
        let mut k = kernel();
        let leader = process();
        let mut thread = leader.fork();
        thread.signals.shared_pending = leader.signals.shared_pending.clone();
        k.processes.insert(1, leader);
        Kernel::queue_one(2, &mut thread, 19, 1);
        assert!(k.deliver(2, &mut thread).unwrap());
        assert!(matches!(thread.state, State::Stopped));
        assert!(matches!(k.processes[&1].state, State::Stopped));
        k.processes.insert(2, thread);
        let mut caller = process();
        caller.tgid = 3;
        assert_eq!(k.thread_signal(3, &mut caller, 2, Some(1), 18), Ok(0));
        assert!(matches!(k.processes[&1].state, State::Ready));
        assert!(matches!(k.processes[&2].state, State::Ready));
        assert_eq!(k.processes[&1].wait_event, Some(0xffff));
    }
    #[test]
    fn process_signals_are_single_delivery_and_thread_signals_check_identity_and_permissions() {
        let mut p = process();
        let mut k = kernel();
        let mut thread = p.fork();
        thread.tgid = 1;
        k.processes.insert(2, thread);
        assert_eq!(k.signal(1, &mut p, 0, 10), Ok(0));
        assert!(p.signals.shared_pending.borrow().contains_key(&10));
        assert!(k.processes[&2].signals.pending.is_empty());
        assert_eq!(k.thread_signal(1, &mut p, 2, Some(3), 10), Err(Errno(3)));
        assert_eq!(k.thread_signal(1, &mut p, 2, Some(1), 10), Ok(0));
        assert_eq!(k.processes[&2].signals.pending[&10].code, -6);
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 0);
        assert_eq!(k.thread_signal(1, &mut p, 2, None, 0), Err(Errno(1)));
        assert_eq!(k.thread_signal(1, &mut p, 2, None, 18), Ok(0));
        assert_eq!(k.thread_signal(1, &mut p, 0, None, 10), Err(Errno(22)));
    }
    #[test]
    fn signal_frame_restores_integer_vector_fp_state_and_accepts_guest_context_edits() {
        let mut p = process();
        let mut k = kernel();
        p.cpu.set_x(5, 55);
        p.cpu.fpsr = 17;
        p.cpu.fpcr = 1 << 22;
        p.cpu.set_vector(8, 0x0123456789abcdef0011223344556677);
        p.signals.mask = 1 << 11;
        p.signals.actions.set(
            10,
            Action {
                handler: 0x5000,
                flags: 4,
                ..Action::default()
            },
        );
        Kernel::queue_one(1, &mut p, 10, 2);
        assert!(k.deliver(1, &mut p).unwrap());
        let sp = p.cpu.sp;
        assert_eq!(p.cpu.x(0), 10);
        assert_eq!(p.cpu.x(1), sp);
        assert_eq!(p.cpu.x(2), sp + 128);
        assert_eq!(p.cpu.x(30), 0x7fff_ffd0_0000);
        assert_ne!(p.signals.mask & (1 << 9), 0);
        write_u64(&mut p.memory, sp + 312 + 5 * 8, 77).unwrap();
        p.cpu.set_vector(8, 0);
        p.cpu.fpcr = 0;
        p.cpu.fpsr = 0;
        Kernel::sigreturn(&mut p).unwrap();
        assert_eq!(p.cpu.x(5), 77);
        assert_eq!(p.cpu.sp, 0x9000);
        assert_eq!(p.cpu.pc, 0x4000);
        assert_eq!(p.cpu.vector(8), 0x0123456789abcdef0011223344556677);
        assert_eq!(p.cpu.fpcr, 1 << 22);
        assert_eq!(p.cpu.fpsr, 17);
        assert_eq!(p.signals.mask, 1 << 11);
    }
    #[test]
    fn signal_return_restores_interrupted_leaf_stack_without_call_boundary_alignment() {
        let mut p = process();
        let mut k = kernel();
        p.cpu.sp -= 8;
        let old_sp = p.cpu.sp;
        p.signals.actions.set(
            10,
            Action {
                handler: 0x5000,
                ..Action::default()
            },
        );
        Kernel::queue_one(1, &mut p, 10, 2);
        assert!(k.deliver(1, &mut p).unwrap());
        assert_eq!(p.cpu.sp & 15, 0); // The handler's new frame is aligned.
        Kernel::sigreturn(&mut p).unwrap();
        assert_eq!(p.cpu.sp, old_sp); // The interrupted leaf's SP need not be.
        assert_eq!(p.cpu.pc, 0x4000);
        assert_eq!(p.signals.frames, 0);
    }
    #[test]
    fn malformed_signal_frame_fails_without_partial_register_restoration() {
        let mut p = process();
        let mut k = kernel();
        p.signals.actions.set(
            10,
            Action {
                handler: 0x5000,
                ..Action::default()
            },
        );
        Kernel::queue_one(1, &mut p, 10, 2);
        k.deliver(1, &mut p).unwrap();
        let sp = p.cpu.sp;
        p.memory.write(sp + 592, &[0; 4]).unwrap();
        let old = p.cpu.clone();
        assert_eq!(Kernel::sigreturn(&mut p), Err(Errno(14)));
        assert_eq!(p.cpu.pc, old.pc);
        assert_eq!(p.cpu.sp, old.sp);
        assert_eq!(p.cpu.x(0), old.x(0));
    }
    #[test]
    fn stop_continue_preserves_a_blocked_timer() {
        let mut p = process();
        let mut k = kernel();
        let deadline = Instant::now() + Duration::from_secs(1);
        p.state = State::Sleep(deadline, 0);
        Kernel::queue_one(1, &mut p, 19, 1);
        k.deliver(1, &mut p).unwrap();
        assert!(matches!(p.state, State::Stopped));
        Kernel::queue_one(1, &mut p, 18, 1);
        assert!(matches!(p.state,State::Sleep(d,_) if d==deadline));
    }
    #[test]
    fn restart_rewinds_the_syscall_and_eintr_does_not() {
        for restart in [false, true] {
            let mut p = process();
            let mut k = kernel();
            p.cpu.pc = 0x4004;
            p.state = State::Blocked(63, [3, 0x1000, 7, 0, 0, 0]);
            p.signals.actions.set(
                10,
                Action {
                    handler: 0x5000,
                    flags: if restart { 0x10000000 } else { 0 },
                    ..Action::default()
                },
            );
            Kernel::queue_one(1, &mut p, 10, 2);
            k.deliver(1, &mut p).unwrap();
            Kernel::sigreturn(&mut p).unwrap();
            assert_eq!(p.cpu.pc, if restart { 0x4000 } else { 0x4004 });
            assert_eq!(p.cpu.x(0), if restart { 3 } else { error(Errno(4)) });
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod boundary_tests {
    use super::tests::{kernel, process};
    use super::*;
    use crate::PAGE_SIZE;
    use trames_linux::CapturedOutput;
    #[test]
    fn first_touch_quota_failure_kills_the_guest_group_instead_of_segv() {
        let mut p = process();
        let mut k = kernel();
        p.memory.set_total_limit(PAGE_SIZE as usize).unwrap();
        p.memory.write_array(0x1000, [17u8]).unwrap();
        let error = p.memory.write_array(0x2000, [42u8]).unwrap_err();
        assert_eq!(error, trames_memory::MemoryError::Limit);
        p.signals.actions.set_handler(11, 0x4000);
        k.synchronous_fault(
            1,
            &mut p,
            &trames_cpu::CpuFault::Memory { pc: 0x4000, error },
        );
        assert!(matches!(p.state, State::Zombie(9)));
    }
    #[test]
    fn clone_vm_shares_the_full_budget_without_a_temporary_fork_or_mmu_retirement() {
        let mut p = process();
        let mut k = kernel();
        p.memory.write_array(0x1000, [17u8]).unwrap();
        p.memory.set_total_limit(PAGE_SIZE as usize).unwrap();
        assert!(!p.memory.can_fork());
        let before = p.memory.instruction_identity();
        assert_eq!(
            k.syscall(
                1,
                &mut p,
                220,
                [17, 0, 0, 0, 0, 0],
                &mut CapturedOutput::default()
            ),
            Err(Errno(11))
        );
        let result = k
            .syscall(
                1,
                &mut p,
                220,
                [0x10900, 0x8000, 0, 0, 0, 0],
                &mut CapturedOutput::default(),
            )
            .unwrap();
        let id = result.unwrap() as u32;
        let child = k.processes.get_mut(&id).unwrap();
        child.memory.write_array(0x1000, [42u8]).unwrap();
        assert_eq!(p.memory.read_array::<1>(0x1000), Ok([42]));
        assert_eq!(p.memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(p.memory.instruction_identity(), before);
    }
    #[test]
    fn kill_is_delivered_even_with_an_older_pending_signal_while_stopped() {
        let mut p = process();
        let mut k = kernel();
        p.state = State::Stopped;
        Kernel::queue_one(1, &mut p, 10, 2);
        Kernel::queue_one(1, &mut p, 9, 2);
        k.deliver(1, &mut p).unwrap();
        assert!(matches!(p.state, State::Zombie(9)));
    }
    #[test]
    fn configured_task_capacity_admits_more_than_256_threads_and_reports_the_limit() {
        let mut p = process();
        let mut k = kernel();
        k.task_limit = 300;
        let before = p.memory.resident_bytes();
        for _ in 1..300 {
            k.syscall(
                1,
                &mut p,
                220,
                [0x10900, 0x8000, 0, 0, 0, 0],
                &mut CapturedOutput::default(),
            )
            .unwrap();
        }
        assert_eq!(k.processes.len(), 299);
        assert_eq!(p.memory.resident_bytes(), before);
        assert_eq!(
            k.syscall(
                1,
                &mut p,
                220,
                [0x10900, 0x8000, 0, 0, 0, 0],
                &mut CapturedOutput::default()
            ),
            Err(Errno(11))
        );
        k.rlimit(&mut p, 163, [6, 0x1000, 0, 0, 0, 0]).unwrap();
        assert_eq!(read_u64(&p.memory, 0x1000).unwrap(), 300);
        k.refresh_proc(1, &mut p);
        let fd = p
            .linux
            .vfs
            .open_at(-100, b"/proc/sys/kernel/threads-max", 0, 0)
            .unwrap();
        assert_eq!(p.linux.vfs.read(fd, 64).unwrap(), b"300\n");
        let fd = p.linux.vfs.open_at(-100, b"/proc/1/limits", 0, 0).unwrap();
        let limits = String::from_utf8(p.linux.vfs.read(fd, 4096).unwrap()).unwrap();
        assert!(limits.lines().any(|line| line.starts_with("Max processes")
            && line
                .split_whitespace()
                .skip(2)
                .take(2)
                .all(|value| value == "300")));
    }
    #[test]
    fn process_limit_rejects_fork_without_changing_parent_memory() {
        let mut p = process();
        let mut k = kernel();
        for id in 2..=MAX_PROCESSES as u32 {
            k.processes.insert(id, process());
        }
        let before = p.memory.mapped_bytes();
        assert_eq!(
            k.syscall(
                1,
                &mut p,
                220,
                [17, 0, 0, 0, 0, 0],
                &mut CapturedOutput::default()
            ),
            Err(Errno(11))
        );
        assert_eq!(p.memory.mapped_bytes(), before);
    }
    #[test]
    fn failed_exec_preserves_image_and_cloexec_descriptor() {
        let mut p = process();
        p.linux
            .vfs
            .import_executable(b"/bad", b"not ELF".to_vec())
            .unwrap();
        let fd = p.linux.vfs.open_at(-100, b"/bad", 0x80000, 0).unwrap();
        let peer = p.linux.vfs.clone_with_resources(true, true);
        p.memory.write(0x1000, b"/bad\0").unwrap();
        p.memory.write(0x1100, &[0; 8]).unwrap();
        assert_eq!(
            Kernel::exec(&mut p, [0x1000, 0x1100, 0, 0, 0, 0], TOTAL_MAPPED_LIMIT),
            Err(Errno(8))
        );
        assert_eq!(p.cpu.pc, 0x4000);
        assert!(p.linux.vfs.fd_kind(fd).is_ok());
        assert!(p.linux.vfs.shares_context_with(&peer));
        p.linux.vfs.set_umask(0o077);
        assert_eq!(peer.umask(), 0o077);
    }
    #[test]
    fn parked_uring_admission_preserves_idle_mmu_trace_and_fd_authority() {
        let mut k = kernel();
        let mut p = process();
        let (fd, ring) = p.linux.vfs.uring_create(2, 4).unwrap();
        p.state = State::Blocked(426, [fd as u64, 0, 1, 1, 0, 0]);
        p.uring_wait = Some((0, ring, None));
        assert!(p.worker_io_candidate(1));
        p.linux.trace = true;
        assert!(!p.worker_io_candidate(1));
        p.linux.trace = false;
        p.uring_wait.as_mut().unwrap().2 = Some(Instant::now());
        assert!(p.worker_io_candidate(1));
        p.uring_wait.as_mut().unwrap().2 = None;
        let mut idle = process();
        idle.state = State::Sleep(
            Instant::now() + Duration::from_secs(3600),
            Default::default(),
        );
        k.processes.insert(1, idle);
        k.processes.insert(2, p);
        assert!(!k.parallel_candidate());
        k.processes.get_mut(&1).unwrap().state = State::Ready;
        assert!(!k.parallel_candidate());
        let p = k.processes.get_mut(&2).unwrap();
        p.linux.vfs.close(fd).unwrap();
        let (replacement, _) = p.linux.vfs.uring_create(2, 4).unwrap();
        assert_eq!(replacement, fd);
        assert!(!p.worker_io_candidate(1));
    }
    #[test]
    fn blocked_uring_ext_arg_retains_deadline_without_reimporting_guest_memory() {
        let mut k = kernel();
        let mut p = process();
        let mut io = trames_linux::CapturedOutput::default();
        let (fd, _ring) = p.linux.vfs.uring_create(2, 4).unwrap();
        p.memory.write(0x1100, &[0; 24]).unwrap();
        p.memory
            .write_array(0x1110, 0x1200u64.to_le_bytes())
            .unwrap();
        p.memory.write_array(0x1200, 3600u64.to_le_bytes()).unwrap();
        p.memory.write_array(0x1208, 0u64.to_le_bytes()).unwrap();
        let args = [fd as u64, 0, 1, 9, 0x1100, 24];
        assert_eq!(k.syscall(1, &mut p, 426, args, &mut io), Ok(None));
        let wait = p.uring_wait.as_mut().unwrap();
        wait.2 = Some(Instant::now());
        p.memory.write(0x1100, &[255; 24]).unwrap();
        assert_eq!(k.syscall(1, &mut p, 426, args, &mut io), Err(Errno(62)));
        assert!(p.uring_wait.is_none());
    }
    #[test]
    fn blocked_uring_enter_retains_original_ring_across_fd_close_and_reuse() {
        let mut k = kernel();
        let mut p = process();
        let mut io = trames_linux::CapturedOutput::default();
        let (fd, ring) = p.linux.vfs.uring_create(2, 4).unwrap();
        let [read, write] = p.linux.vfs.pipe(0).unwrap();
        for (address, offset, len) in [
            (0x10000, 0, ring.ring_bytes),
            (0x20000, 0x10000000, ring.sqe_bytes),
        ] {
            let pages = p
                .linux
                .vfs
                .mapping_pages(fd, offset, len, true, true)
                .unwrap();
            p.memory
                .map_backed(address, pages, true, trames_memory::Permissions::RW, false)
                .unwrap();
        }
        let mut sqe = [0; 64];
        sqe[0] = 22;
        sqe[4..8].copy_from_slice(&read.to_le_bytes());
        sqe[16..24].copy_from_slice(&0x1f00u64.to_le_bytes());
        sqe[24..28].copy_from_slice(&1u32.to_le_bytes());
        p.memory.write(0x20000, &sqe).unwrap();
        p.memory
            .write_array(
                0x10000 + trames_vfs::URING_SQ_ARRAY as u64,
                0u32.to_le_bytes(),
            )
            .unwrap();
        p.memory.write_array(0x10004, 1u32.to_le_bytes()).unwrap();
        let args = [fd as u64, 1, 1, 1, 0, 0];
        assert_eq!(k.syscall(1, &mut p, 426, args, &mut io), Ok(None));
        assert!(p.uring_wait.is_some());
        p.linux.vfs.close(fd).unwrap();
        let replacement = p
            .linux
            .vfs
            .open_at(-100, b"/replacement", 0x42, 0o600)
            .unwrap();
        assert_eq!(replacement, fd);
        assert!(p.linux.vfs.uring(fd).is_err());
        p.linux.vfs.write(write, b"x").unwrap();
        assert_eq!(k.syscall(1, &mut p, 426, args, &mut io), Ok(Some(1)));
        assert!(p.uring_wait.is_none());
        assert_eq!(p.memory.read_array::<1>(0x1f00).unwrap(), *b"x");
        assert_eq!(k.syscall(1, &mut p, 426, args, &mut io), Err(Errno(9)));
    }
    #[test]
    fn terminal_resize_event_is_scoped_to_the_foreground_group() {
        struct Events(Option<TerminalEvent>);
        impl GuestOutput for Events {
            fn write(&mut self, _: OutputFd, b: &[u8]) -> std::io::Result<usize> {
                Ok(b.len())
            }
            fn poll_stdin(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::WouldBlock.into())
            }
            fn terminal_event(&mut self) -> Option<TerminalEvent> {
                self.0.take()
            }
        }
        let mut k = kernel();
        k.terminal = Some(Terminal::default());
        k.processes.insert(1, process());
        let mut other = process();
        other.group = 2;
        k.processes.insert(2, other);
        assert!(k
            .pump_terminal(&mut Events(Some(TerminalEvent::Resize {
                rows: 40,
                columns: 120
            })))
            .unwrap());
        assert_eq!(&k.terminal.as_ref().unwrap().window[..4], &[40, 0, 120, 0]);
        assert!(k.processes[&1].signals.pending.contains_key(&28));
        assert!(!k.processes[&2].signals.pending.contains_key(&28));
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod cpu_fault_tests {
    use trames_cpu::Cpu;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::tests::{kernel, process};
    use super::*;
    use trames_cpu::CpuFault;
    use trames_memory::{MemoryError, Permissions};
    #[test]
    fn synchronous_signal_contains_fault_address_and_resumes_from_edited_context() {
        let mut k = kernel();
        let mut p = process();
        p.signals.actions.set(
            11,
            Action {
                handler: 0x2000,
                flags: 4,
                restorer: 0,
                mask: 0,
            },
        );
        p.cpu.pc = 0x1330;
        p.cpu.set_x(7, 0x123456);
        let fault = CpuFault::Memory {
            pc: 0x1330,
            error: MemoryError::Permission {
                address: 0x3456,
                access: Access::Write,
            },
        };
        Kernel::queue_one(1, &mut p, 11, 2);
        k.synchronous_fault(1, &mut p, &fault);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 11);
        assert_eq!(p.cpu.pc, 0x2000);
        let frame = p.cpu.sp;
        assert_eq!(
            p.memory.read_array::<4>(frame + 8).unwrap(),
            2i32.to_le_bytes()
        );
        assert_eq!(p.memory.read_u64(frame + 16).unwrap(), 0x3456);
        assert_eq!(p.memory.read_u64(frame + 304).unwrap(), 0x3456);
        assert_eq!(p.memory.read_u64(frame + 568).unwrap(), 0x1330);
        p.memory
            .write_array(frame + 568, 0x1334u64.to_le_bytes())
            .unwrap();
        Kernel::sigreturn(&mut p).unwrap();
        assert_eq!(p.cpu.pc, 0x1334);
        assert_eq!(p.cpu.x(7), 0x123456);
        assert_eq!(p.signals.frames, 0);
    }
    #[test]
    fn masked_or_ignored_synchronous_faults_terminate_instead_of_looping() {
        for (blocked, handler) in [(false, 1), (true, 0x2000)] {
            let mut k = kernel();
            let mut p = process();
            p.signals.actions.set_handler(5, handler);
            if blocked {
                p.signals.mask |= 1 << 4;
            }
            let fault = CpuFault::Trap {
                pc: 0x1000,
                instruction: 0xd4200020,
                signal: 5,
                code: 1,
            };
            k.synchronous_fault(2, &mut p, &fault);
            assert!(matches!(p.state, State::Zombie(5)));
        }
    }
    #[test]
    fn data_top_byte_tags_work_across_pages_and_fork_copy_on_write() {
        let mut m = Memory::default();
        m.map(0x1000, 8192, Permissions::RW).unwrap();
        let tagged = 0xab00000000001ffc;
        m.write_array(tagged, 12345u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_u64(0x1ffc).unwrap(), 12345);
        let mut child = m.clone();
        child.write_array(tagged, 6789u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_u64(tagged).unwrap(), 12345);
        assert_eq!(child.read_u64(tagged).unwrap(), 6789);
        assert!(
            m.fetch_u32(tagged).is_err(),
            "data tags do not authorize tagged code addresses"
        );
    }
}
