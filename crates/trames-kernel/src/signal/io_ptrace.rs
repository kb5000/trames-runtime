// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest tasks stop on their own execution workers. Debuggers consume normal
//! wait events; register changes return to the same worker before execution.
use super::*;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_KILL: u64 = 8;
const PTRACE_GETEVENTMSG: u64 = 0x4201;
const PTRACE_GETSIGINFO: u64 = 0x4202;
const PTRACE_CONT: u64 = 7;
const PTRACE_SINGLESTEP: u64 = 9;
const PTRACE_SYSCALL: u64 = 24;
const PTRACE_GET_SYSCALL_INFO: u64 = 0x420e;
const PTRACE_O_TRACESYSGOOD: u64 = 1;
const PTRACE_DETACH: u64 = 17;
const PTRACE_SETOPTIONS: u64 = 0x4200;
const PTRACE_GETREGSET: u64 = 0x4204;
const PTRACE_SETREGSET: u64 = 0x4205;
const PTRACE_SETSIGINFO: u64 = 0x4203;
const PTRACE_INTERRUPT: u64 = 0x4207;
const PTRACE_LISTEN: u64 = 0x4208;
const PTRACE_GETSIGMASK: u64 = 0x420a;
const PTRACE_SETSIGMASK: u64 = 0x420b;
const PTRACE_O_TRACEFORK: u64 = 1 << 1;
const PTRACE_O_TRACEEXEC: u64 = 1 << 4;
const PTRACE_O_TRACECLONE: u64 = 1 << 3;
const PTRACE_O_TRACEVFORK: u64 = 1 << 2;
const PTRACE_O_TRACEVFORKDONE: u64 = 1 << 5;
const PTRACE_O_TRACEEXIT: u64 = 1 << 6;
const PTRACE_O_EXITKILL: u64 = 1 << 20;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;
const PTRACE_O_SUSPEND_SECCOMP: u64 = 1 << 21;
const PTRACE_O_MASK: u64 = 0xff | (1 << 20) | PTRACE_O_SUSPEND_SECCOMP;

pub(super) enum Exception {
    Any,
    Task(Weak<IoTask>),
}

const SUPPORTED_OPTIONS: u64 = PTRACE_O_TRACEFORK
    | PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEVFORKDONE
    | PTRACE_O_TRACEEXIT
    | PTRACE_O_EXITKILL;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Voluntary,
    Inherited,
    Attach,
    Seize,
}
#[derive(Clone, Copy)]
enum StopOrigin<'a> {
    Retiring(&'a Arc<ExecPeerExit>),
    Normal,
    Control,
    Step,
    Fork(u32),
    Clone(u32),
    Vfork(u32),
    VforkDone(u32),
}
#[derive(Clone, Copy)]
enum ControlStop {
    Attach,
    Group,
    Interrupt,
}
#[derive(Default)]
pub(super) struct TraceSlot {
    relationship: Option<Relationship>,
    retirement: Weak<ExecPeerExit>,
    resume: Option<trames_execution::Aarch64State>,
}
struct Relationship {
    cpu_override: Option<trames_execution::Aarch64State>,
    signal_override: Option<RetainedInfo>,
    retiring: bool,
    mode: Mode,
    thread_source: Option<Arc<crate::children::Child>>,
    admission: Option<Box<trames_vfs::Credentials>>,
    pending: Option<ControlStop>,
    listening: bool,
    continued_while_stopped: bool,
    tracer: Weak<IoTask>,
    child: Arc<crate::children::Child>,
    stop: Option<Arc<TraceStop>>,
    options: u64,
    trace_syscalls: bool,
    exit_reported: bool,
    former_tid: Option<u32>,
}
struct TraceStop {
    cpu: trames_execution::Aarch64State,
    status: u32,
    signal: Option<RetainedInfo>,
    syscall: Option<SyscallStop>,
    exit_status: Option<i32>,
    acknowledgement: Option<Arc<crate::completion::Completion>>,
    group_stop: bool,
    event_pid: Option<u32>,
}

#[derive(Clone, Copy)]
enum SyscallStop {
    Entry,
    Exit,
}

impl Drop for TraceStop {
    fn drop(&mut self) {
        if let Some(ack) = &self.acknowledgement {
            ack.finish();
        }
    }
}

/// A prepared nonleader exec retains the retiring leader until its debugger
/// acknowledges the exit. No CPU slot or address-space custody is held.
pub struct ExecPeerExit {
    task: Arc<IoTask>,
    pub acknowledgement: Arc<crate::completion::Completion>,
}
impl Drop for ExecPeerExit {
    fn drop(&mut self) {
        let mut slot = self.task.trace.get().unwrap().lock().unwrap();
        if !std::ptr::eq(slot.retirement.as_ptr(), self) {
            return;
        }
        slot.retirement = Weak::new();
        let mut notice = None;
        let mut released = None;
        if let Some(rel) = slot.relationship.as_mut().filter(|rel| rel.retiring) {
            rel.retiring = false;
            if rel.stop.as_ref().is_some_and(|stop| {
                stop.acknowledgement
                    .as_ref()
                    .is_some_and(|a| Arc::ptr_eq(a, &self.acknowledgement))
            }) {
                released = rel.stop.take();
                notice = Some(rel.child.trace_event(None));
                self.task.trace_stop.fetch_and(!1, Ordering::Release);
            }
            rel.exit_reported = false;
        }
        self.task.trace_stop.fetch_and(!2, Ordering::Release);
        drop(slot);
        drop(released);
        if let Some(notice) = notice {
            notice.notify();
        }
        self.task.wake_control();
    }
}

impl TraceStop {
    fn read_syscall_info(
        &self,
        cpu: &trames_execution::Aarch64State,
        len: u64,
        output: u64,
        memory: &mut impl trames_memory::CpuMemory,
    ) -> Result<u64, Errno> {
        // ARM64 ptrace_syscall_info uses the last meaningful byte, excluding tail padding.
        let mut bytes = [0; 80];
        bytes[4..8].copy_from_slice(&0xc00000b7u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&cpu.pc.to_le_bytes());
        bytes[16..24].copy_from_slice(&cpu.sp.to_le_bytes());
        let available = match self.syscall {
            Some(SyscallStop::Entry) if self.status & 0x80 != 0 => {
                bytes[0] = 1;
                bytes[24..32].copy_from_slice(&cpu.registers[8].to_le_bytes());
                for (dst, value) in bytes[32..].chunks_exact_mut(8).zip(&cpu.registers[..6]) {
                    dst.copy_from_slice(&value.to_le_bytes());
                }
                80
            }
            Some(SyscallStop::Exit) if self.status & 0x80 != 0 => {
                bytes[0] = 2;
                let value = cpu.registers[0];
                bytes[24..32].copy_from_slice(&value.to_le_bytes());
                bytes[32] = u8::from((-4095..0).contains(&(value as i64)));
                33
            }
            _ => 24,
        };
        let n = len.min(available) as usize;
        if n != 0 {
            memory.write(output, &bytes[..n]).map_err(|_| Errno(14))?;
        }
        Ok(available)
    }

    fn read_regset(
        &self,
        cpu: &trames_execution::Aarch64State,
        kind: u64,
        iov: u64,
        memory: &mut impl trames_memory::CpuMemory,
    ) -> Result<u64, Errno> {
        let (width, size) = match kind {
            1 => (8, 272),   // NT_PRSTATUS
            0x401 => (8, 8), // NT_ARM_TLS
            2 => (4, 528),   // NT_FPREGSET, including the ABI tail padding
            _ => return Err(Errno(22)),
        };
        let desc = memory.read_array::<16>(iov).map_err(|_| Errno(14))?;
        let base = u64::from_le_bytes(desc[..8].try_into().unwrap());
        let requested = u64::from_le_bytes(desc[8..].try_into().unwrap());
        if requested % width != 0 {
            return Err(Errno(22));
        }
        let len = requested.min(size) as usize;
        let out = iov.checked_add(8).ok_or(Errno(14))?;
        let mut bytes = [0; 528];
        if kind == 1 {
            let words = cpu
                .registers
                .iter()
                .copied()
                .chain([cpu.sp, cpu.pc, cpu.nzcv as u64]);
            for (dst, word) in bytes.chunks_exact_mut(8).zip(words) {
                dst.copy_from_slice(&word.to_le_bytes());
            }
        } else if kind == 0x401 {
            bytes[..8].copy_from_slice(&cpu.tpidr_el0.to_le_bytes());
        } else {
            for (dst, vector) in bytes.chunks_exact_mut(16).zip(cpu.vectors.iter()) {
                dst.copy_from_slice(&vector.to_le_bytes());
            }
            bytes[512..516].copy_from_slice(&cpu.fpsr.to_le_bytes());
            bytes[516..520].copy_from_slice(&cpu.fpcr.to_le_bytes());
        }
        if len != 0 {
            memory.write(base, &bytes[..len]).map_err(|_| Errno(14))?;
        }
        memory
            .write_array(out, (len as u64).to_le_bytes())
            .map_err(|_| Errno(14))?;
        Ok(0)
    }
}

fn write_regset(
    cpu: &trames_execution::Aarch64State,
    kind: u64,
    iov: u64,
    memory: &mut impl trames_memory::CpuMemory,
) -> Result<trames_execution::Aarch64State, Errno> {
    let (width, size) = match kind {
        1 => (8, 272),
        2 => (4, 528),
        0x401 => (8, 8),
        _ => return Err(Errno(22)),
    };
    let desc = memory.read_array::<16>(iov).map_err(|_| Errno(14))?;
    let base = u64::from_le_bytes(desc[..8].try_into().unwrap());
    let requested = u64::from_le_bytes(desc[8..].try_into().unwrap());
    if requested % width != 0 {
        return Err(Errno(22));
    }
    let len = requested.min(size) as usize;
    let mut state = cpu.clone();
    let mut bytes = [0; 528];
    // Partial regsets preserve the bytes beyond the supplied prefix.
    if kind == 1 {
        for (dst, word) in bytes
            .chunks_exact_mut(8)
            .zip(
                cpu.registers
                    .iter()
                    .copied()
                    .chain([cpu.sp, cpu.pc, cpu.nzcv as u64]),
            )
        {
            dst.copy_from_slice(&word.to_le_bytes());
        }
    } else if kind == 0x401 {
        bytes[..8].copy_from_slice(&cpu.tpidr_el0.to_le_bytes());
    } else {
        for (dst, vector) in bytes.chunks_exact_mut(16).zip(cpu.vectors) {
            dst.copy_from_slice(&vector.to_le_bytes());
        }
        bytes[512..516].copy_from_slice(&cpu.fpsr.to_le_bytes());
        bytes[516..520].copy_from_slice(&cpu.fpcr.to_le_bytes());
    }
    if len != 0 {
        memory
            .read(base, &mut bytes[..len])
            .map_err(|_| Errno(14))?;
    }
    if kind == 1 {
        for (value, src) in state
            .registers
            .iter_mut()
            .chain([&mut state.sp, &mut state.pc])
            .zip(bytes.chunks_exact(8))
        {
            *value = u64::from_le_bytes(src.try_into().unwrap());
        }
        let pstate = u64::from_le_bytes(bytes[264..272].try_into().unwrap());
        // Only EL0t is a valid user mode; privileged execution bits never reach a backend.
        if pstate & 0x1f != 0 {
            return Err(Errno(22));
        }
        state.nzcv = (pstate as u32) & 0xf0000000;
    } else if kind == 0x401 {
        state.tpidr_el0 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    } else {
        for (value, src) in state.vectors.iter_mut().zip(bytes.chunks_exact(16)) {
            *value = u128::from_le_bytes(src.try_into().unwrap());
        }
        state.fpsr = u32::from_le_bytes(bytes[512..516].try_into().unwrap()) & 0xf800009f;
        state.fpcr = u32::from_le_bytes(bytes[516..520].try_into().unwrap()) & 0x07f79f00;
    }
    memory
        .write_array(
            iov.checked_add(8).ok_or(Errno(14))?,
            (len as u64).to_le_bytes(),
        )
        .map_err(|_| Errno(14))?;
    Ok(state)
}

#[derive(Default)]
pub(super) struct Tracees {
    retired: bool,
    tasks: Vec<Weak<IoTask>>,
    observers: Vec<Weak<crate::children::Child>>,
}

impl IoTask {
    /// Return whether admission also requires CAP_SYS_PTRACE in the target
    /// namespace. The credentials layer checks it against the same image.
    pub(super) fn trace_requires_cap(&self, caller_group: u32, scope: u32) -> Result<bool, Errno> {
        if self.tgid() == caller_group || scope == 0 {
            return Ok(false);
        }
        if scope == 3 {
            return Err(Errno(1));
        }
        if scope == 2 {
            return Ok(true);
        }
        let Some(parents) = self.parents.get().and_then(Weak::upgrade) else {
            return Ok(true);
        };
        let Some(caller) = parents.original(caller_group) else {
            return Ok(true);
        };
        if parents.descendant(self, &caller) {
            return Ok(false);
        }
        if self
            .trace
            .get()
            .and_then(|s| {
                let slot = s.lock().unwrap();
                let rel = slot.relationship.as_ref()?;
                rel.tracer.upgrade()
            })
            .is_some_and(|t| t.live() && t.tgid() == caller_group)
        {
            return Ok(false);
        }
        Ok(!self.nominated_observer(&caller))
    }

    fn nominated_observer(&self, caller: &IoTask) -> bool {
        let Some(parents) = self.parents.get().and_then(Weak::upgrade) else {
            return false;
        };
        let Some(leader) = parents.original(self.tgid()) else {
            return false;
        };
        let Some(exception) = leader.ptracer.get() else {
            return false;
        };
        let selected = exception.lock().unwrap();
        match selected.as_ref() {
            Some(Exception::Any) => true,
            Some(Exception::Task(task)) => task
                .upgrade()
                .is_some_and(|t| parents.descendant(caller, &t)),
            None => false,
        }
    }

    pub fn set_ptracer(&self, ns: &PidNamespace, pid: u64) -> Result<u64, Errno> {
        let parents = self.parents.get().and_then(Weak::upgrade).ok_or(Errno(3))?;
        let leader = parents.original(self.tgid()).ok_or(Errno(3))?;
        let exception = if pid == 0 {
            None
        } else if pid as i32 == -1 {
            Some(Exception::Any)
        } else {
            let task = ns
                .global(pid as u32)
                .and_then(|id| parents.original(id))
                .filter(|t| t.live())
                .ok_or(Errno(22))?;
            Some(Exception::Task(Arc::downgrade(&task)))
        };
        *leader.ptracer.get_or_init(Default::default).lock().unwrap() = exception;
        Ok(0)
    }
    #[inline]
    pub fn trace_stopped(&self) -> bool {
        self.trace_stop.load(Ordering::Acquire) != 0
    }

    pub fn take_trace_update(&self) -> Option<trames_execution::Aarch64State> {
        let slot = self.trace.get()?;
        if !self.trace_update.load(Ordering::Acquire) {
            return None;
        }
        let mut slot = slot.lock().unwrap();
        self.trace_update.store(false, Ordering::Relaxed);
        slot.resume.take()
    }

    pub fn tracer_tid(&self) -> u32 {
        self.trace
            .get()
            .and_then(|slot| slot.lock().unwrap().relationship.as_ref()?.tracer.upgrade())
            .filter(|t| t.live())
            .map_or(0, |t| t.tid())
    }

    #[inline]
    pub fn trace_single_step(&self) -> bool {
        self.trace.get().is_some() && self.trace_step.load(Ordering::Relaxed)
    }
    pub fn trace_step_stop(
        &self,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        self.publish_trace_stop(5, None, None, None, StopOrigin::Step, registers)
    }

    pub fn trace_control_pending(&self) -> bool {
        self.trace_control.load(Ordering::Acquire)
    }
    pub fn trace_control_point(
        &self,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        self.trace_control_pending()
            && self.publish_trace_stop(5, None, None, None, StopOrigin::Control, registers)
    }
    pub fn job_stopped(&self) -> bool {
        self.lifecycle().stopped()
            && self.trace_run_generation.load(Ordering::Relaxed)
                != self.lifecycle().stop_generation()
    }

    pub(crate) fn trace_job_event(&self, continued: bool) {
        let Some(slot) = self.trace.get() else {
            return;
        };
        let mut lock = slot.lock().unwrap();
        let Some(rel) = lock.relationship.as_mut() else {
            return;
        };
        if !continued {
            self.trace_run_generation.store(0, Ordering::Relaxed);
        }
        if continued
            && rel.mode == Mode::Seize
            && rel.stop.as_ref().is_some_and(|s| s.status >> 8 == 128)
        {
            // SIGCONT may arrive after the wait event but before LISTEN.
            rel.continued_while_stopped = true;
        }
        if rel.mode == Mode::Seize && rel.stop.is_none() && (!continued || rel.listening) {
            rel.pending = Some(if continued {
                ControlStop::Interrupt
            } else {
                ControlStop::Group
            });
            self.trace_control.store(true, Ordering::Release);
        }
    }

    pub(super) fn thread_wait(&self, tid: u32) -> Option<Arc<crate::children::Child>> {
        let mut record = self.thread_wait.lock().unwrap();
        if tid != self.tid() || tid == self.tgid() {
            return None;
        }
        match &*record {
            ThreadWait::Open(source) => Some(source.clone()),
            ThreadWait::Unopened if self.live() => {
                let source = crate::children::Child::thread_source(self);
                *record = ThreadWait::Open(source.clone());
                Some(source)
            }
            _ => None,
        }
    }

    pub(super) fn trace_thread_exit(&self, status: i32) {
        if self.tid() == self.tgid() {
            return;
        }
        let source = std::mem::replace(&mut *self.thread_wait.lock().unwrap(), ThreadWait::Retired);
        if let ThreadWait::Open(source) = source {
            if let Some((notice, signo, status)) = source.finish_quiet(Some(status), None, None) {
                notice.signal(
                    signo,
                    crate::family::exit_info(self.tid(), self.credentials().read().uid, status),
                );
            }
        }
    }

    pub(super) fn rebind_thread_observer(&self, previous_leader: &IoTask) {
        let Some(slot) = self.trace.get() else { return };
        let mut guard = slot.lock().unwrap();
        let Some(rel) = guard
            .relationship
            .as_mut()
            .filter(|r| r.thread_source.is_some())
        else {
            return;
        };
        let Some(tracer) = rel.tracer.upgrade() else {
            return;
        };
        let Some(queue) = tracer.lifecycle().wait_children() else {
            return;
        };
        let Some(original) = self.lifecycle().wait_child() else {
            return;
        };
        // Nonleader exec retires the old leader and takes its PID. Its previous
        // observer record belongs to that task, even if the debugger is the same.
        if let Some(old) = previous_leader.trace.get() {
            let former = old.lock().unwrap().relationship.take();
            if let Some(former) = former {
                former.child.detach_trace().notify();
            }
        }
        rel.former_tid = Some(
            tracer
                .inbox
                .namespace
                .get()
                .map_or(self.tid(), |ns| ns.local(self.tid())),
        );
        rel.child.detach_trace().notify();
        if let Ok(notice) = original.trace_by_parent(&queue) {
            rel.child = original;
            rel.thread_source = None;
            drop(guard);
            notice.notify();
            return;
        }
        let Ok(wait) = original.observe(&tracer, &queue) else {
            guard.relationship = None;
            return;
        };
        rel.child = wait.clone();
        rel.thread_source = None;
        drop(guard);
        // Preserve lock order with tracer retirement and cover a simultaneous
        // departure between rebinding the task and registering its exit record.
        let mut list = tracer.tracees.lock().unwrap();
        if list.retired {
            drop(list);
            wait.detach_trace().notify();
        } else {
            list.observers.push(Arc::downgrade(&wait));
        }
    }
    pub fn is_traced(&self) -> bool {
        self.trace
            .get()
            .is_some_and(|slot| slot.lock().unwrap().relationship.is_some())
    }

    pub(crate) fn release_tracees(&self) {
        // Close admission even when retirement races this parent's first tracee.
        let list = &self.tracees;
        let (tasks, observers) = {
            let mut list = list.lock().unwrap();
            list.retired = true;
            (
                std::mem::take(&mut list.tasks),
                std::mem::take(&mut list.observers),
            )
        };
        for task in tasks.into_iter().filter_map(|t| t.upgrade()) {
            let mut slot = task.trace.get().unwrap().lock().unwrap();
            if slot
                .relationship
                .as_ref()
                .is_none_or(|r| !std::ptr::eq(r.tracer.as_ptr(), self))
            {
                continue;
            }
            let mut rel = slot.relationship.take().unwrap();
            if let Some(state) = rel.cpu_override.take() {
                slot.resume = Some(state);
                task.trace_update.store(true, Ordering::Release);
            }
            let notice = rel.child.detach_trace();
            task.trace_run_generation.store(0, Ordering::Relaxed);
            task.trace_control.store(false, Ordering::Release);
            task.trace_step.store(false, Ordering::Relaxed);
            task.trace_stop.fetch_and(!1, Ordering::Release);
            drop(slot);
            if let Some(ack) = rel.stop.as_ref().and_then(|s| s.acknowledgement.as_ref()) {
                ack.finish();
            }
            if rel.options & PTRACE_O_EXITKILL != 0 {
                task.lifecycle().request_exit(9);
            }
            notice.notify();
            task.wake_control();
        }
        // A task may already have retired while its exit still belongs to
        // this tracer. Release the original wait record in that case too.
        for wait in observers.into_iter().filter_map(|w| w.upgrade()) {
            wait.detach_trace().notify();
        }
    }

    /// Only the tracee's worker publishes its stopped register snapshot. Signal
    /// consumption and wait publication precede waking the observing parent.
    pub fn trace_point(
        &self,
        sig: u32,
        shared: Option<bool>,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        self.publish_trace_stop(sig, shared, None, None, StopOrigin::Normal, registers)
    }

    #[inline]
    pub fn trace_syscall_stop(
        &self,
        entering: bool,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        if self.trace.get().is_none() {
            return false;
        }
        self.publish_trace_stop(
            5,
            None,
            Some(if entering {
                SyscallStop::Entry
            } else {
                SyscallStop::Exit
            }),
            None,
            StopOrigin::Normal,
            registers,
        )
    }

    /// Called after successful birth and before the guest child becomes runnable.
    pub fn trace_birth(
        &self,
        child: &Arc<IoTask>,
        vfork: bool,
        exit_signal: u32,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) {
        let Some(slot) = self.trace.get() else { return };
        let option = if vfork {
            PTRACE_O_TRACEVFORK
        } else if exit_signal == 17 {
            PTRACE_O_TRACEFORK
        } else {
            PTRACE_O_TRACECLONE
        };
        let (tracer, options, mode, admission) = {
            let guard = slot.lock().unwrap();
            let Some(rel) = guard
                .relationship
                .as_ref()
                .filter(|r| r.options & option != 0)
            else {
                return;
            };
            let Some(tracer) = rel.tracer.upgrade() else {
                return;
            };
            let admission = rel
                .admission
                .as_deref()
                .cloned()
                .unwrap_or_else(|| tracer.credentials().read().clone());
            (
                tracer,
                rel.options,
                if rel.mode == Mode::Seize {
                    Mode::Seize
                } else {
                    Mode::Inherited
                },
                admission,
            )
        };
        let tid = child.tid();
        let thread_source = child.thread_wait(tid);
        let original = if tid == child.tgid() {
            child.lifecycle().wait_child()
        } else {
            thread_source.clone()
        };
        let Some(original) = original else {
            return;
        };
        let Some(family) = tracer.lifecycle().wait_children() else {
            return;
        };
        let mut list = tracer.tracees.lock().unwrap();
        if list.retired {
            return;
        }
        let mut child_slot = child.trace.get_or_init(Default::default).lock().unwrap();
        if child_slot.relationship.is_some() {
            return;
        }
        let Ok(wait) = original.observe(&tracer, &family) else {
            return;
        };
        list.tasks.retain(|t| t.strong_count() != 0);
        list.tasks.push(Arc::downgrade(child));
        list.observers.retain(|w| w.strong_count() != 0);
        list.observers.push(Arc::downgrade(&wait));
        child_slot.relationship = Some(Relationship {
            cpu_override: None,
            signal_override: None,
            retiring: false,
            mode,
            thread_source,
            admission: Some(Box::new(admission)),
            pending: Some(ControlStop::Attach),
            listening: false,
            continued_while_stopped: false,
            tracer: Arc::downgrade(&tracer),
            child: wait,
            stop: None,
            options,
            trace_syscalls: false,
            exit_reported: false,
            former_tid: None,
        });
        child.trace_control.store(true, Ordering::Release);
        drop(child_slot);
        drop(list);
        self.publish_trace_stop(
            5,
            None,
            None,
            None,
            if vfork {
                StopOrigin::Vfork(child.tid())
            } else if exit_signal == 17 {
                StopOrigin::Fork(child.tid())
            } else {
                StopOrigin::Clone(child.tid())
            },
            registers,
        );
    }

    pub fn trace_vfork_done(
        &self,
        release: &crate::completion::Completion,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        self.trace.get().is_some()
            && release.vfork_child().is_some_and(|id| {
                self.publish_trace_stop(5, None, None, None, StopOrigin::VforkDone(id), registers)
            })
    }

    pub fn trace_exec_peer_exit(
        self: &Arc<Self>,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> Option<Arc<ExecPeerExit>> {
        // Group admission serializes image replacements. Competing nonleader
        // execs must still await the same retiring leader after releasing custody.
        {
            let mut slot = self.trace.get()?.lock().unwrap();
            if let Some(hold) = slot.retirement.upgrade() {
                return Some(hold);
            }
            let rel = slot.relationship.as_ref()?;
            if rel.retiring {
                // A canceled exec dropped its final reference while we took
                // the lock. Adopt the outstanding stop (or its acknowledgement).
                let ack = rel
                    .stop
                    .as_ref()
                    .and_then(|s| s.acknowledgement.clone())
                    .unwrap_or_else(|| {
                        let ack = Arc::new(crate::completion::Completion::default());
                        ack.finish();
                        ack
                    });
                let hold = Arc::new(ExecPeerExit {
                    task: self.clone(),
                    acknowledgement: ack,
                });
                slot.retirement = Arc::downgrade(&hold);
                return Some(hold);
            }
            if rel.options & PTRACE_O_TRACEEXIT == 0 {
                return None;
            }
        }
        let hold = Arc::new(ExecPeerExit {
            task: self.clone(),
            acknowledgement: Arc::new(crate::completion::Completion::default()),
        });
        self.publish_trace_stop(
            5,
            None,
            None,
            Some(0),
            StopOrigin::Retiring(&hold),
            registers,
        )
        .then_some(hold)
    }

    pub fn trace_exit_stop(
        &self,
        status: i32,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        self.publish_trace_stop(5, None, None, Some(status), StopOrigin::Normal, registers)
    }

    /// A pending group termination normally wakes every task. A tracer holding
    /// the final event owns the next wake until it resumes or detaches.
    pub fn exit_stop_held(&self) -> bool {
        self.trace_stopped()
            && self.trace.get().is_some_and(|slot| {
                slot.lock()
                    .unwrap()
                    .relationship
                    .as_ref()
                    .is_some_and(|rel| {
                        rel.stop
                            .as_ref()
                            .is_some_and(|stop| stop.exit_status.is_some())
                    })
            })
    }

    fn publish_trace_stop(
        &self,
        sig: u32,
        shared: Option<bool>,
        syscall: Option<SyscallStop>,
        exit_status: Option<i32>,
        origin: StopOrigin<'_>,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        let Some(slot) = self.trace.get() else {
            return false;
        };
        let mut lock = slot.lock().unwrap();
        let TraceSlot {
            relationship,
            retirement,
            ..
        } = &mut *lock;
        let Some(rel) = relationship.as_mut() else {
            return false;
        };
        let vfork_child = if let StopOrigin::Fork(id)
        | StopOrigin::Clone(id)
        | StopOrigin::Vfork(id)
        | StopOrigin::VforkDone(id) = origin
        {
            let required = match origin {
                StopOrigin::Fork(_) => PTRACE_O_TRACEFORK,
                StopOrigin::Clone(_) => PTRACE_O_TRACECLONE,
                StopOrigin::Vfork(_) => PTRACE_O_TRACEVFORK,
                _ => PTRACE_O_TRACEVFORKDONE,
            };
            if rel.options & required == 0 {
                return false;
            }
            let Some(tracer) = rel.tracer.upgrade() else {
                return false;
            };
            Some(tracer.inbox.namespace.get().map_or(id, |ns| ns.local(id)))
        } else {
            None
        };
        let control = matches!(origin, StopOrigin::Control);
        if rel.stop.is_some() && exit_status.is_none()
            || syscall.is_some() && !rel.trace_syscalls
            || exit_status.is_some() && (rel.exit_reported || rel.options & PTRACE_O_TRACEEXIT == 0)
        {
            return false;
        }
        // A signal or syscall stop can win the race with INTERRUPT. The stop
        // satisfies that request too, so a parked child has no runnable hint.
        if !control && rel.pending.is_some() {
            rel.pending = None;
            self.trace_control.store(false, Ordering::Release);
        }
        let mut group_stop = false;
        let mut control_status = None;
        if control {
            let pending = rel.pending.take();
            self.trace_control.store(false, Ordering::Release);
            let Some(pending) = pending else {
                return false;
            };
            rel.listening = false;
            let group_signal = self.lifecycle().stop_signal();
            group_stop = group_signal.is_some();
            let signal = match (pending, group_signal) {
                (_, Some(sig)) => sig,
                (ControlStop::Group, None) => return false,
                (ControlStop::Interrupt, None) => 5,
                (ControlStop::Attach, None) => 19,
            };
            control_status = Some(if rel.mode == Mode::Seize {
                signal | (128 << 8)
            } else {
                signal
            });
        }
        let cpu = registers();
        let signal = match shared {
            Some(shared) => match (if shared { self.process() } else { &self.inbox })
                .take_selected(|pending| pending.remove_for_trace(sig))
            {
                Some(info) => Some(info),
                None => return false,
            },
            None if matches!(origin, StopOrigin::Step) => Some(RetainedInfo::debugger(Info {
                code: 2,
                fault: Some(cpu.pc),
                ..Default::default()
            })),
            None => None,
        };
        let status = if let Some(status) = control_status {
            status
        } else if matches!(origin, StopOrigin::Fork(_)) {
            sig | (1 << 8)
        } else if matches!(origin, StopOrigin::Clone(_)) {
            sig | (3 << 8)
        } else if matches!(origin, StopOrigin::Vfork(_)) {
            sig | (2 << 8)
        } else if vfork_child.is_some() {
            sig | (5 << 8)
        } else if exit_status.is_some() {
            rel.exit_reported = true;
            if let StopOrigin::Retiring(hold) = origin {
                *retirement = Arc::downgrade(hold);
                rel.retiring = true;
            }
            sig | (6 << 8)
        } else if syscall.is_some() {
            if rel.options & PTRACE_O_TRACESYSGOOD != 0 {
                sig | 0x80
            } else {
                sig
            }
        } else if matches!(origin, StopOrigin::Normal)
            && shared.is_none()
            && rel.options & PTRACE_O_TRACEEXEC != 0
        {
            sig | (4 << 8)
        } else {
            sig
        };
        rel.continued_while_stopped = false;
        rel.cpu_override = None;
        rel.signal_override = None;
        rel.stop = Some(Arc::new(TraceStop {
            cpu,
            acknowledgement: if let StopOrigin::Retiring(hold) = origin {
                Some(hold.acknowledgement.clone())
            } else {
                None
            },
            group_stop,
            event_pid: if matches!(origin, StopOrigin::Normal)
                && shared.is_none()
                && syscall.is_none()
                && exit_status.is_none()
            {
                rel.former_tid.take().filter(|_| status >> 8 == 4)
            } else {
                vfork_child
            },
            syscall,
            exit_status,
            status,
            signal,
        }));
        self.trace_stop.fetch_or(
            if matches!(origin, StopOrigin::Retiring(_)) {
                3
            } else {
                1
            },
            Ordering::Release,
        );
        let notice = rel.child.trace_event(Some(status as i32));
        let uid = self.credentials().read().uid;
        drop(lock);
        notice.signal(
            17,
            Info {
                code: 4,
                sender: self.tid(),
                uid,
                status: status as i32,
                ..Default::default()
            },
        );
        true
    }
}

impl IoRoutes {
    fn trace_me(&self, task: &IoTask) -> Result<u64, Errno> {
        let parent = task.parentage().ok_or(Errno(3))?;
        let tracer = self
            .directory
            .tasks(0, parent.parent_thread())
            .into_iter()
            .next()
            .ok_or(Errno(3))?;
        let tracee = self
            .directory
            .tasks(0, task.tid())
            .into_iter()
            .find(|t| std::ptr::eq(&**t, task))
            .ok_or(Errno(3))?;
        let creds = tracer.credentials().read().clone();
        let own = task.credentials().read();
        let scope = self.namespace.ptrace_scope();
        if scope == 3
            || scope == 2
                && !creds.has_ns_cap(&own.user_namespace, trames_vfs::capabilities::SYS_PTRACE)
        {
            return Err(Errno(1));
        }
        if !(creds.user_namespace == own.user_namespace
            && own.caps.permitted & !creds.caps.permitted == 0)
            && !creds.has_ns_cap(&own.user_namespace, trames_vfs::capabilities::SYS_PTRACE)
        {
            return Err(Errno(1));
        }
        drop(own);
        self.trace_child(&tracer, &tracee, Mode::Voluntary, 0, Some(creds))
    }

    fn trace_child(
        &self,
        tracer: &Arc<IoTask>,
        task: &Arc<IoTask>,
        mode: Mode,
        options: u64,
        admission: Option<trames_vfs::Credentials>,
    ) -> Result<u64, Errno> {
        let tid = task.tid();
        let thread_source = task.thread_wait(tid);
        let child = if tid == task.tgid() {
            task.lifecycle().wait_child()
        } else {
            thread_source.clone()
        }
        .ok_or(Errno(3))?;
        let mut list = tracer.tracees.lock().unwrap();
        if list.retired || !tracer.live() || !task.live() {
            return Err(Errno(3));
        }
        let parent_tid = task.parentage().ok_or(Errno(3))?.parent_thread();
        if mode == Mode::Voluntary && parent_tid != tracer.tid() {
            return Err(Errno(3));
        }
        let mut slot = task.trace.get_or_init(Default::default).lock().unwrap();
        if slot.relationship.is_some() {
            return Err(Errno(1));
        }
        let parent_wait = tracer.lifecycle().wait_children().ok_or(Errno(3))?;
        let (child, notice) = match child.trace_by_parent(&parent_wait) {
            Ok(notice) => (child, Some(notice)),
            Err(_) => {
                let wait = child.observe(tracer, &parent_wait)?;
                list.observers.retain(|w| w.strong_count() != 0);
                list.observers.push(Arc::downgrade(&wait));
                (wait, None)
            }
        };
        list.tasks
            .retain(|t| t.strong_count() != 0 && !Weak::ptr_eq(t, &Arc::downgrade(task)));
        list.tasks.push(Arc::downgrade(task));
        let pending = match mode {
            Mode::Attach => Some(ControlStop::Attach),
            Mode::Seize if task.lifecycle().stopped() => Some(ControlStop::Group),
            _ => None,
        };
        slot.relationship = Some(Relationship {
            cpu_override: None,
            signal_override: None,
            retiring: false,
            mode,
            thread_source,
            admission: admission.map(Box::new),
            listening: false,
            continued_while_stopped: false,
            pending,
            tracer: Arc::downgrade(tracer),
            child,
            stop: None,
            options,
            trace_syscalls: false,
            exit_reported: false,
            former_tid: None,
        });
        task.trace_control
            .store(pending.is_some(), Ordering::Release);
        drop(slot);
        drop(list);
        if let Some(notice) = notice {
            notice.notify();
        }
        if pending.is_some() {
            task.wake_control();
        }
        Ok(0)
    }

    /// Word access binds the original stopped task, saved attach credentials
    /// and exact address space. Exec cannot redirect an accepted transfer.
    pub fn trace_read_target(
        &self,
        caller: &IoTask,
        pid: u32,
    ) -> Result<Option<trames_memory::TransferTarget>, Errno> {
        let id = self.namespace.global(pid).ok_or(Errno(3))?;
        let task = self
            .directory
            .tasks(0, id)
            .into_iter()
            .find(|t| t.live())
            .ok_or(Errno(3))?;
        let slot = task.trace.get().ok_or(Errno(3))?.lock().unwrap();
        let rel = slot.relationship.as_ref().ok_or(Errno(3))?;
        if rel.stop.is_none()
            || !rel
                .tracer
                .upgrade()
                .is_some_and(|t| t.tgid() == caller.tgid())
        {
            return Err(Errno(3));
        }
        let mm = task.proc_view.memory_report().ok_or(Errno(3))?;
        let credentials = caller.credentials().read().clone();
        let original = rel.admission.as_deref().unwrap_or(&credentials);
        task.credentials()
            .admit_process_memory(original, &mm, false)
            .map_err(|e| if e.0 == 1 { Errno(5) } else { e })
            .map(Some)
    }

    pub fn ptrace(
        &self,
        caller: &IoTask,
        args: [u64; 6],
        memory: &mut impl trames_memory::CpuMemory,
    ) -> Result<u64, Errno> {
        let [request, pid, addr, options, ..] = args;
        if request == PTRACE_TRACEME {
            return self.trace_me(caller);
        }

        let id = self.namespace.global(pid as u32).ok_or(Errno(3))?;
        let target = self
            .directory
            .tasks(0, id)
            .into_iter()
            .next()
            .ok_or(Errno(3))?;
        if !target.live() {
            return Err(Errno(3));
        }
        if let Some(lock) = target.trace.get() {
            let mut slot = lock.lock().unwrap();
            if let Some(rel) = slot.relationship.as_mut().filter(|r| {
                r.tracer
                    .upgrade()
                    .is_some_and(|t| t.tgid() == caller.tgid())
            }) {
                if matches!(request, PTRACE_ATTACH | PTRACE_SEIZE) {
                    return Err(Errno(1));
                }
                if request == PTRACE_INTERRUPT && rel.mode == Mode::Seize {
                    if rel.stop.is_none() {
                        rel.pending = Some(ControlStop::Interrupt);
                        target.trace_control.store(true, Ordering::Release);
                        drop(slot);
                        target.wake_control();
                    }
                    return Ok(0);
                }
                let stop = rel.stop.as_ref().ok_or(Errno(3))?;
                let stop = stop.clone();
                match request {
                    PTRACE_CONT | PTRACE_SINGLESTEP | PTRACE_SYSCALL | PTRACE_DETACH => {
                        if options > 64 {
                            return Err(Errno(5));
                        }
                        // Linux injects the requested signal at signal-delivery stops.
                        // Resume a retained record once, bypassing a second debugger stop.
                        if options != 0 && (stop.signal.is_some() || stop.status == 19) {
                            let mut info = rel
                                .signal_override
                                .clone()
                                .or_else(|| stop.signal.clone())
                                .unwrap_or_else(|| RetainedInfo::debugger(Info::default()));
                            let info_signal = info.user.map_or(stop.status & 0xff, |b| {
                                u32::from_le_bytes(b[..4].try_into().unwrap())
                            });
                            if options != u64::from(info_signal) {
                                info = RetainedInfo::debugger(Info {
                                    sender: caller.tgid(),
                                    uid: caller.credentials().read().uid,
                                    code: 0,
                                    ..Default::default()
                                });
                            }
                            target.inbox.resume_observed_quiet(options as u32, info);
                        }
                        if stop.group_stop && request != PTRACE_DETACH {
                            target
                                .trace_run_generation
                                .store(target.lifecycle().stop_generation(), Ordering::Relaxed);
                        }
                        let notice = if request == PTRACE_DETACH {
                            target.trace_run_generation.store(0, Ordering::Relaxed);
                            rel.child.detach_trace()
                        } else {
                            rel.child.trace_event(None)
                        };
                        rel.trace_syscalls = request == PTRACE_SYSCALL;
                        target
                            .trace_step
                            .store(request == PTRACE_SINGLESTEP, Ordering::Relaxed);
                        rel.continued_while_stopped = false;
                        let released = rel.stop.take();
                        let changed = rel.cpu_override.take();
                        rel.signal_override = None;
                        slot.resume = changed;
                        target
                            .trace_update
                            .store(slot.resume.is_some(), Ordering::Release);
                        if request == PTRACE_DETACH {
                            slot.relationship = None;
                            target.trace_control.store(false, Ordering::Release);
                        }
                        target.trace_stop.fetch_and(!1, Ordering::Release);
                        drop(slot);
                        // Completion may enter the run queue. Wake after unlocking
                        // the tracee, including when a reader still holds its snapshot.
                        if let Some(ack) =
                            released.as_ref().and_then(|s| s.acknowledgement.as_ref())
                        {
                            ack.finish();
                        }
                        if options != 0 {
                            target.inbox.changed();
                        }
                        notice.notify();
                        target.wake_control();
                        return Ok(0);
                    }
                    PTRACE_SETOPTIONS if options & !SUPPORTED_OPTIONS == 0 => {
                        rel.options = options;
                        return Ok(0);
                    }
                    PTRACE_GET_SYSCALL_INFO => {
                        let cpu = rel.cpu_override.as_ref().unwrap_or(&stop.cpu).clone();
                        let stop = stop.clone();
                        drop(slot);
                        return stop.read_syscall_info(&cpu, addr, options, memory);
                    }
                    PTRACE_SETREGSET => {
                        let cpu = rel.cpu_override.as_ref().unwrap_or(&stop.cpu);
                        rel.cpu_override = Some(write_regset(cpu, addr, options, memory)?);
                        return Ok(0);
                    }
                    PTRACE_GETREGSET => {
                        let cpu = rel.cpu_override.as_ref().unwrap_or(&stop.cpu).clone();
                        let stop = stop.clone();
                        drop(slot);
                        return stop.read_regset(&cpu, addr, options, memory);
                    }
                    PTRACE_GETEVENTMSG => {
                        let message = if let Some(status) = stop.exit_status {
                            status as u32 as u64
                        } else if let Some(id) = stop.event_pid {
                            u64::from(id)
                        } else if stop.status >> 8 == 4 {
                            u64::from(self.namespace.local(target.tid()))
                        } else {
                            0
                        };
                        drop(slot);
                        memory
                            .write_array(options, message.to_le_bytes())
                            .map_err(|_| Errno(14))?;
                        return Ok(0);
                    }
                    PTRACE_GETSIGINFO if stop.group_stop && rel.mode == Mode::Attach => {
                        return Err(Errno(22))
                    }
                    PTRACE_GETSIGINFO => {
                        let mut info = rel
                            .signal_override
                            .as_ref()
                            .or(stop.signal.as_ref())
                            .map(|s| **s)
                            .unwrap_or_else(|| Info {
                                sender: target.tgid(),
                                uid: target.credentials().read().uid,
                                code: if stop.syscall.is_none() && stop.status >> 8 == 0 {
                                    0
                                } else {
                                    stop.status as i32
                                },
                                ..Default::default()
                            });
                        if info.user.is_none()
                            && info.fault.is_none()
                            && info.poll.is_none()
                            && info.timer.is_none()
                        {
                            info.sender = self.namespace.local(info.sender);
                            info.uid = caller
                                .credentials()
                                .read()
                                .user_namespace
                                .visible(false, info.uid);
                        }
                        let mut bytes = [0; 128];
                        write_siginfo(
                            &mut bytes,
                            if stop.syscall.is_some() {
                                5
                            } else {
                                stop.status & 0xff
                            },
                            info,
                        );
                        drop(slot);
                        memory.write_array(options, bytes).map_err(|_| Errno(14))?;
                        return Ok(0);
                    }
                    PTRACE_SETSIGINFO => {
                        if stop.group_stop {
                            return Err(Errno(22));
                        }
                        let bytes = memory.read_array::<128>(options).map_err(|_| Errno(14))?;
                        let user: [u8; 48] = bytes[..48].try_into().unwrap();
                        rel.signal_override = Some(RetainedInfo::debugger(Info {
                            code: i32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                            user: Some(user),
                            ..Default::default()
                        }));
                        return Ok(0);
                    }
                    PTRACE_KILL => {
                        if stop.exit_status.is_some() {
                            let notice = rel.child.trace_event(None);
                            let released = rel.stop.take();
                            target.trace_stop.fetch_and(!1, Ordering::Release);
                            drop(slot);
                            if let Some(ack) =
                                released.as_ref().and_then(|s| s.acknowledgement.as_ref())
                            {
                                ack.finish();
                            }
                            notice.notify();
                        } else {
                            drop(slot);
                        }
                        target.lifecycle().request_exit(9);
                        target.wake_control();
                        return Ok(0);
                    }
                    PTRACE_SETSIGMASK => {
                        if addr != 8 {
                            return Err(Errno(22));
                        }
                        let mask = u64::from_le_bytes(
                            memory.read_array::<8>(options).map_err(|_| Errno(14))?,
                        ) & !UNBLOCKABLE;
                        let mut context = target.context.lock().unwrap();
                        context.mask = mask;
                        context.wait_mask = None;
                        target.publish_mask(mask);
                        return Ok(0);
                    }
                    PTRACE_GETSIGMASK => {
                        if addr != 8 {
                            return Err(Errno(22));
                        }
                        let mask = target.mask();
                        drop(slot);
                        memory
                            .write_array(options, mask.to_le_bytes())
                            .map_err(|_| Errno(14))?;
                        return Ok(0);
                    }
                    PTRACE_LISTEN if rel.mode == Mode::Seize && stop.status >> 8 == 128 => {
                        let notice = rel.child.trace_event(None);
                        rel.listening = true;
                        rel.stop = None;
                        let retrap = std::mem::take(&mut rel.continued_while_stopped);
                        if retrap {
                            rel.pending = Some(ControlStop::Interrupt);
                            target.trace_control.store(true, Ordering::Release);
                        }
                        drop(slot);
                        notice.notify();
                        if retrap {
                            target.wake_control();
                        }
                        return Ok(0);
                    }
                    PTRACE_INTERRUPT | PTRACE_LISTEN => return Err(Errno(5)),
                    _ => return Err(Errno(95)),
                }
            }
        }
        if !matches!(request, PTRACE_ATTACH | PTRACE_SEIZE) {
            // Linux checks for an existing tracer relationship before decoding
            // the operation or accessing any of the caller's guest pointers.
            return Err(Errno(3));
        }
        if request == PTRACE_SEIZE {
            if addr != 0 || options & !PTRACE_O_MASK != 0 {
                return Err(Errno(5));
            }
            if options & PTRACE_O_SUSPEND_SECCOMP != 0 {
                // This runtime does not implement checkpoint/restore of seccomp.
                return Err(Errno(22));
            }
        }
        if target.tgid() == caller.tgid() {
            return Err(Errno(1));
        }
        let credentials = caller.credentials().read().clone();
        target.credentials().check_trace_attach(
            &credentials,
            target.trace_requires_cap(caller.tgid(), self.namespace.ptrace_scope())?,
        )?;
        if options & !SUPPORTED_OPTIONS != 0 && request == PTRACE_SEIZE {
            return Err(Errno(95));
        }
        let tracer = self
            .directory
            .tasks(0, caller.tid())
            .into_iter()
            .find(|t| std::ptr::eq(&**t, caller))
            .ok_or(Errno(3))?;
        let mode = if request == PTRACE_SEIZE {
            Mode::Seize
        } else {
            Mode::Attach
        };
        self.trace_child(
            &tracer,
            &target,
            mode,
            if request == PTRACE_SEIZE { options } else { 0 },
            Some(credentials),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regset_prefix_preserves_tls_and_rejects_privileged_state() {
        use trames_memory::{Memory, Permissions, PAGE_SIZE};
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x1000, 0x1100u64.to_le_bytes()).unwrap();
        memory.write_array(0x1008, 8u64.to_le_bytes()).unwrap();
        memory.write_array(0x1100, 123u64.to_le_bytes()).unwrap();
        let mut cpu = trames_execution::Aarch64State {
            tpidr_el0: 0xabc,
            sp: 0x2000,
            pc: 0x3000,
            ..Default::default()
        };
        cpu.registers[1] = 456;
        let changed = write_regset(&cpu, 1, 0x1000, &mut memory).unwrap();
        assert_eq!(changed.registers[..2], [123, 456]);
        assert_eq!(
            (changed.tpidr_el0, changed.pc, changed.sp),
            (0xabc, 0x3000, 0x2000)
        );
        memory.write_array(0x1008, 272u64.to_le_bytes()).unwrap();
        memory.write_array(0x1208, 5u64.to_le_bytes()).unwrap();
        assert_eq!(write_regset(&cpu, 1, 0x1000, &mut memory), Err(Errno(22)));
        memory.write_array(0x1008, 7u64.to_le_bytes()).unwrap();
        assert_eq!(write_regset(&cpu, 1, 0x1000, &mut memory), Err(Errno(22)));
    }

    #[test]
    fn designated_debugger_follows_the_original_task_and_its_descendants() {
        let directory = IoDirectory::default();
        let ns = PidNamespace::default();
        let task = |id, parent| {
            let task = Arc::new(IoTask::default());
            directory.publish(&task, id, id, 1, 1000, 1000);
            let relation = Arc::new(crate::task_parent::Parentage::default());
            relation.set_parent_thread(parent);
            directory.parents.publish(&task, id, &relation);
            task
        };
        let owner = task(40, 0);
        let target = task(41, 40);
        let debugger = task(42, 40);
        let descendant = task(43, 42);
        assert_eq!(target.trace_requires_cap(owner.tgid(), 1), Ok(false));
        assert_eq!(target.trace_requires_cap(debugger.tgid(), 1), Ok(true));
        target.set_ptracer(&ns, debugger.tid().into()).unwrap();
        assert_eq!(target.trace_requires_cap(descendant.tgid(), 1), Ok(false));
        assert_eq!(target.trace_requires_cap(descendant.tgid(), 2), Ok(true));
        assert_eq!(
            target.trace_requires_cap(descendant.tgid(), 3),
            Err(Errno(1))
        );
        assert_eq!(target.set_ptracer(&ns, 999), Err(Errno(22)));
        assert_eq!(target.trace_requires_cap(debugger.tgid(), 1), Ok(false));
        directory
            .parents
            .retire(&debugger, None, Default::default());
        let replacement = task(42, 40);
        assert_eq!(target.trace_requires_cap(replacement.tgid(), 1), Ok(true));
        target.set_ptracer(&ns, u64::MAX).unwrap();
        assert_eq!(target.trace_requires_cap(replacement.tgid(), 1), Ok(false));
        target.set_ptracer(&ns, 0).unwrap();
        assert_eq!(target.trace_requires_cap(replacement.tgid(), 1), Ok(true));
    }

    #[test]
    fn syscall_info_reports_full_size_and_copies_only_the_requested_prefix() {
        use trames_memory::{Memory, Permissions, PAGE_SIZE};
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut stop = TraceStop {
            cpu: Default::default(),
            status: 0x85,
            signal: None,
            syscall: Some(SyscallStop::Entry),
            exit_status: None,
            group_stop: false,
            acknowledgement: None,
            event_pid: None,
        };
        stop.cpu.registers[..6].copy_from_slice(&[10, 11, 12, 13, 14, 15]);
        stop.cpu.registers[8] = 57;
        stop.cpu.pc = 0x1234;
        stop.cpu.sp = 0x9876;
        assert_eq!(
            stop.read_syscall_info(&stop.cpu, 0, u64::MAX, &mut memory),
            Ok(80)
        );
        assert_eq!(
            stop.read_syscall_info(&stop.cpu, 1, u64::MAX, &mut memory),
            Err(Errno(14))
        );
        memory.write_array(0x1000, [0xdd; 81]).unwrap();
        assert_eq!(
            stop.read_syscall_info(&stop.cpu, 7, 0x1000, &mut memory),
            Ok(80)
        );
        assert_eq!(
            memory.read_array::<8>(0x1000).unwrap(),
            [1, 0, 0, 0, 0xb7, 0, 0, 0xdd]
        );
        assert_eq!(
            stop.read_syscall_info(&stop.cpu, 100, 0x1000, &mut memory),
            Ok(80)
        );
        let bytes = memory.read_array::<81>(0x1000).unwrap();
        assert_eq!(&bytes[4..8], &0xc00000b7u32.to_le_bytes());
        let words: Vec<_> = bytes[8..80]
            .chunks_exact(8)
            .map(|w| u64::from_le_bytes(w.try_into().unwrap()))
            .collect();
        assert_eq!(words, [0x1234, 0x9876, 57, 10, 11, 12, 13, 14, 15]);
        assert_eq!(bytes[80], 0xdd);
        stop.syscall = Some(SyscallStop::Exit);
        for (result, error) in [(0i64, 0), (-1, 1), (-4095, 1), (-4096, 0)] {
            stop.cpu.registers[0] = result as u64;
            assert_eq!(
                stop.read_syscall_info(&stop.cpu, 80, 0x1000, &mut memory),
                Ok(33)
            );
            assert_eq!(memory.read_array::<1>(0x1000).unwrap(), [2]);
            assert_eq!(
                memory.read_array::<8>(0x1018).unwrap(),
                result.to_le_bytes()
            );
            assert_eq!(memory.read_array::<1>(0x1020).unwrap(), [error]);
        }
        stop.status = 5;
        assert_eq!(
            stop.read_syscall_info(&stop.cpu, 80, 0x1000, &mut memory),
            Ok(24)
        );
        assert_eq!(memory.read_array::<1>(0x1000).unwrap(), [0]);
    }

    #[test]
    fn tracer_retirement_releases_a_stopped_child_and_closes_future_admission() {
        let routes = IoRoutes {
            directory: Arc::default(),
            namespace: Default::default(),
            uid: 1000,
            euid: 1000,
        };
        let tracer = Arc::new(IoTask::default());
        let task = Arc::new(IoTask::default());
        routes.directory.publish(&tracer, 42, 42, 42, 1000, 1000);
        routes.directory.publish(&task, 43, 43, 42, 1000, 1000);
        let parentage = Arc::new(crate::task_parent::Parentage::default());
        parentage.set_parent_thread(42);
        task.bind_parentage(&parentage);
        let child = Arc::new(crate::children::Child::default());
        let children = Arc::new(crate::children::Children::default());
        task.lifecycle()
            .bind(&child, Some(tracer.lifecycle()), 43, 1000);
        child.attach(Some(&children), 43, 42, 1000);
        assert_eq!(routes.trace_me(&task), Ok(0));
        assert_eq!(routes.trace_me(&task), Err(Errno(1)));
        let request = |op, data| {
            routes.ptrace(
                &tracer,
                [op, 43, 0, data, 0, 0],
                &mut trames_memory::Memory::default(),
            )
        };
        assert!(task.trace_point(5, None, Default::default));
        assert_eq!(request(PTRACE_SETOPTIONS, PTRACE_O_TRACEEXIT), Ok(0));
        assert_eq!(request(PTRACE_CONT, 0), Ok(0));
        for acknowledge in [false, true] {
            let hold = task.trace_exec_peer_exit(Default::default).unwrap();
            let other = task.trace_exec_peer_exit(|| unreachable!()).unwrap();
            assert!(Arc::ptr_eq(&hold, &other));
            let acknowledgement = hold.acknowledgement.clone();
            drop(hold);
            assert!(!acknowledgement.finished());
            if acknowledge {
                assert_eq!(request(PTRACE_CONT, 0), Ok(0));
                assert!(acknowledgement.finished());
            }
            assert!(task.trace_stopped());
            drop(other);
            assert!(acknowledgement.finished());
            assert!(!task.trace_stopped());
        }
        assert!(task.trace_point(5, None, Default::default));
        assert!(task.trace_stopped());
        assert_eq!(task.tracer_tid(), 42);
        tracer.release_tracees();
        assert!(!task.trace_stopped());
        assert_eq!(task.tracer_tid(), 0);
        assert_eq!(routes.trace_me(&task), Err(Errno(3)));
    }

    #[test]
    fn tracing_requests_resolve_the_target_before_reading_arguments() {
        let directory = Arc::new(IoDirectory::default());
        let caller = Arc::new(IoTask::default());
        let sibling = Arc::new(IoTask::default());
        directory.publish(&caller, 42, 42, 42, 1000, 1000);
        directory.publish(&sibling, 43, 42, 42, 1000, 1000);
        let routes = IoRoutes {
            directory,
            namespace: Default::default(),
            uid: 1000,
            euid: 1000,
        };
        let request = |op, pid, addr, flags| {
            routes.ptrace(
                &caller,
                [op, pid, addr, flags, 0, 0],
                &mut trames_memory::Memory::default(),
            )
        };
        assert_eq!(request(PTRACE_ATTACH, 99, 0, 0), Err(Errno(3)));
        assert_eq!(request(PTRACE_SEIZE, 99, 1, u64::MAX), Err(Errno(3)));
        for tid in [42, 43] {
            assert_eq!(request(PTRACE_ATTACH, tid, 0, 0), Err(Errno(1)));
            assert_eq!(request(PTRACE_SEIZE, tid, 0, 0), Err(Errno(1)));
            assert_eq!(request(PTRACE_SEIZE, tid, 1, 0), Err(Errno(5)));
            assert_eq!(request(PTRACE_SEIZE, tid, 0, 1 << 12), Err(Errno(5)));
            assert_eq!(request(0x4204, tid, u64::MAX, u64::MAX), Err(Errno(3)));
        }
    }
}
