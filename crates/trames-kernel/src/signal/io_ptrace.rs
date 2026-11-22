// SPDX-License-Identifier: GPL-3.0-or-later
//! A voluntary guest tracee stops on its execution worker. Its parent consumes
//! normal wait events and observes an immutable snapshot of that stop.
use super::*;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_KILL: u64 = 8;
const PTRACE_GETEVENTMSG: u64 = 0x4201;
const PTRACE_GETSIGINFO: u64 = 0x4202;
const PTRACE_CONT: u64 = 7;
const PTRACE_SYSCALL: u64 = 24;
const PTRACE_GET_SYSCALL_INFO: u64 = 0x420e;
const PTRACE_O_TRACESYSGOOD: u64 = 1;
const PTRACE_DETACH: u64 = 17;
const PTRACE_SETOPTIONS: u64 = 0x4200;
const PTRACE_GETREGSET: u64 = 0x4204;
const PTRACE_INTERRUPT: u64 = 0x4207;
const PTRACE_LISTEN: u64 = 0x4208;
const PTRACE_GETSIGMASK: u64 = 0x420a;
const PTRACE_SETSIGMASK: u64 = 0x420b;
const PTRACE_O_TRACEEXEC: u64 = 1 << 4;
const PTRACE_O_TRACEEXIT: u64 = 1 << 6;
const PTRACE_O_EXITKILL: u64 = 1 << 20;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;
const PTRACE_O_SUSPEND_SECCOMP: u64 = 1 << 21;
const PTRACE_O_MASK: u64 = 0xff | (1 << 20) | PTRACE_O_SUSPEND_SECCOMP;

pub(super) struct Relationship {
    tracer: Weak<IoTask>,
    child: Arc<crate::children::Child>,
    stop: Option<Arc<TraceStop>>,
    options: u64,
    trace_syscalls: bool,
    exit_reported: bool,
}
struct TraceStop {
    cpu: trames_execution::Aarch64State,
    status: u32,
    signal: Option<RetainedInfo>,
    syscall: Option<SyscallStop>,
    exit_status: Option<i32>,
}

#[derive(Clone, Copy)]
enum SyscallStop {
    Entry,
    Exit,
}

impl TraceStop {
    fn read_syscall_info(
        &self,
        len: u64,
        output: u64,
        memory: &mut impl trames_memory::CpuMemory,
    ) -> Result<u64, Errno> {
        // ARM64 ptrace_syscall_info uses the last meaningful byte, excluding tail padding.
        let mut bytes = [0; 80];
        bytes[4..8].copy_from_slice(&0xc00000b7u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.cpu.pc.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.cpu.sp.to_le_bytes());
        let available = match self.syscall {
            Some(SyscallStop::Entry) if self.status & 0x80 != 0 => {
                bytes[0] = 1;
                bytes[24..32].copy_from_slice(&self.cpu.registers[8].to_le_bytes());
                for (dst, value) in bytes[32..]
                    .chunks_exact_mut(8)
                    .zip(&self.cpu.registers[..6])
                {
                    dst.copy_from_slice(&value.to_le_bytes());
                }
                80
            }
            Some(SyscallStop::Exit) if self.status & 0x80 != 0 => {
                bytes[0] = 2;
                let value = self.cpu.registers[0];
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
        kind: u64,
        iov: u64,
        memory: &mut impl trames_memory::CpuMemory,
    ) -> Result<u64, Errno> {
        let (width, size) = match kind {
            1 => (8, 272), // NT_PRSTATUS
            2 => (4, 528), // NT_FPREGSET, including the ABI tail padding
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
            let words = self.cpu.registers.iter().copied().chain([
                self.cpu.sp,
                self.cpu.pc,
                self.cpu.nzcv as u64,
            ]);
            for (dst, word) in bytes.chunks_exact_mut(8).zip(words) {
                dst.copy_from_slice(&word.to_le_bytes());
            }
        } else {
            for (dst, vector) in bytes.chunks_exact_mut(16).zip(self.cpu.vectors.iter()) {
                dst.copy_from_slice(&vector.to_le_bytes());
            }
            bytes[512..516].copy_from_slice(&self.cpu.fpsr.to_le_bytes());
            bytes[516..520].copy_from_slice(&self.cpu.fpcr.to_le_bytes());
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

#[derive(Default)]
pub(super) struct Tracees {
    retired: bool,
    tasks: Vec<Weak<IoTask>>,
}

impl IoTask {
    #[inline]
    pub fn trace_stopped(&self) -> bool {
        self.trace_stop.load(Ordering::Acquire)
    }

    pub fn tracer_tid(&self) -> u32 {
        self.trace
            .get()
            .and_then(|slot| slot.lock().unwrap().as_ref()?.tracer.upgrade())
            .filter(|t| t.live())
            .map_or(0, |t| t.tid())
    }

    pub fn voluntarily_traced(&self) -> bool {
        self.trace
            .get()
            .is_some_and(|slot| slot.lock().unwrap().is_some())
    }

    pub(crate) fn release_tracees(&self) {
        // Close admission even when retirement races this parent's first tracee.
        let list = &self.tracees;
        let tasks = {
            let mut list = list.lock().unwrap();
            list.retired = true;
            std::mem::take(&mut list.tasks)
        };
        for task in tasks.into_iter().filter_map(|t| t.upgrade()) {
            let mut slot = task.trace.get().unwrap().lock().unwrap();
            if slot
                .as_ref()
                .is_none_or(|r| !std::ptr::eq(r.tracer.as_ptr(), self))
            {
                continue;
            }
            let rel = slot.take().unwrap();
            let notice = rel.child.detach_trace();
            if rel.options & PTRACE_O_EXITKILL != 0 {
                task.lifecycle().request_exit(9);
            }
            task.trace_stop.store(false, Ordering::Release);
            drop(slot);
            notice.notify();
            task.wake_control();
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
        self.publish_trace_stop(sig, shared, None, None, registers)
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
            registers,
        )
    }

    pub fn trace_exit_stop(
        &self,
        status: i32,
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        self.publish_trace_stop(5, None, None, Some(status), registers)
    }

    /// A pending group termination normally wakes every task. A tracer holding
    /// the final event owns the next wake until it resumes or detaches.
    pub fn exit_stop_held(&self) -> bool {
        self.trace_stopped()
            && self.trace.get().is_some_and(|slot| {
                slot.lock().unwrap().as_ref().is_some_and(|rel| {
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
        registers: impl FnOnce() -> trames_execution::Aarch64State,
    ) -> bool {
        let Some(slot) = self.trace.get() else {
            return false;
        };
        let mut lock = slot.lock().unwrap();
        let Some(rel) = lock.as_mut() else {
            return false;
        };
        if rel.stop.is_some()
            || syscall.is_some() && !rel.trace_syscalls
            || exit_status.is_some() && (rel.exit_reported || rel.options & PTRACE_O_TRACEEXIT == 0)
        {
            return false;
        }
        let signal = match shared {
            Some(shared) => match (if shared { self.process() } else { &self.inbox })
                .take_selected(|pending| pending.remove_for_trace(sig))
            {
                Some(info) => Some(info),
                None => return false,
            },
            None => None,
        };
        let status = if exit_status.is_some() {
            rel.exit_reported = true;
            sig | (6 << 8)
        } else if syscall.is_some() {
            if rel.options & PTRACE_O_TRACESYSGOOD != 0 {
                sig | 0x80
            } else {
                sig
            }
        } else if shared.is_none() && rel.options & PTRACE_O_TRACEEXEC != 0 {
            sig | (4 << 8)
        } else {
            sig
        };
        rel.stop = Some(Arc::new(TraceStop {
            cpu: registers(),
            syscall,
            exit_status,
            status,
            signal,
        }));
        self.trace_stop.store(true, Ordering::Release);
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
        if task.tgid() != task.tid() {
            return Err(Errno(95));
        }
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
        let child = task.lifecycle().wait_child().ok_or(Errno(3))?;
        let creds = tracer.credentials().read().clone();
        let own = task.credentials().read();
        if !(creds.user_namespace == own.user_namespace
            && own.caps.permitted & !creds.caps.permitted == 0)
            && !creds.has_ns_cap(&own.user_namespace, trames_vfs::capabilities::SYS_PTRACE)
        {
            return Err(Errno(1));
        }
        drop(own);
        let mut list = tracer.tracees.lock().unwrap();
        if list.retired || !tracer.live() || parent.parent_thread() != tracer.tid() {
            return Err(Errno(3));
        }
        let mut slot = task.trace.get_or_init(Default::default).lock().unwrap();
        if slot.is_some() {
            return Err(Errno(1));
        }
        let parent_wait = tracer.lifecycle().wait_children().ok_or(Errno(3))?;
        let notice = child.trace_by_parent(&parent_wait)?;
        list.tasks
            .retain(|t| t.strong_count() != 0 && !Weak::ptr_eq(t, &Arc::downgrade(&tracee)));
        list.tasks.push(Arc::downgrade(&tracee));
        *slot = Some(Relationship {
            tracer: Arc::downgrade(&tracer),
            child,
            stop: None,
            options: 0,
            trace_syscalls: false,
            exit_reported: false,
        });
        drop(slot);
        drop(list);
        notice.notify();
        Ok(0)
    }

    /// A word read requires the original stopped child and current permission
    /// to read its exact address space. An exec cannot redirect an accepted read.
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
        let rel = slot.as_ref().ok_or(Errno(3))?;
        if rel.stop.is_none() || !std::ptr::eq(rel.tracer.as_ptr(), caller) {
            return Err(Errno(3));
        }
        let mm = task.proc_view.memory_report().ok_or(Errno(3))?;
        if caller
            .proc_view
            .memory_report()
            .is_some_and(|m| m.same_resource(&mm))
        {
            return Ok(None);
        }
        let credentials = caller.credentials().read().clone();
        task.credentials()
            .admit_process_memory(&credentials, &mm)
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
            if let Some(rel) = slot
                .as_mut()
                .filter(|r| std::ptr::eq(r.tracer.as_ptr(), caller))
            {
                if matches!(request, PTRACE_ATTACH | PTRACE_SEIZE) {
                    return Err(Errno(1));
                }
                let stop = rel.stop.as_ref().ok_or(Errno(3))?;
                match request {
                    PTRACE_CONT | PTRACE_SYSCALL | PTRACE_DETACH => {
                        if options > 64 {
                            return Err(Errno(5));
                        }
                        if options != 0 {
                            // Only the original selected signal can be resumed. Keep its
                            // namespace identity alive and let normal delivery consume it.
                            let info = stop
                                .signal
                                .as_ref()
                                .filter(|_| options == u64::from(stop.status))
                                .ok_or(Errno(95))?;
                            target
                                .inbox
                                .resume_observed_quiet(stop.status, info.clone());
                        }
                        let notice = if request == PTRACE_DETACH {
                            rel.child.detach_trace()
                        } else {
                            rel.child.trace_event(None)
                        };
                        rel.trace_syscalls = request == PTRACE_SYSCALL;
                        rel.stop = None;
                        if request == PTRACE_DETACH {
                            *slot = None;
                        }
                        target.trace_stop.store(false, Ordering::Release);
                        drop(slot);
                        if options != 0 {
                            target.inbox.changed();
                        }
                        notice.notify();
                        target.wake_control();
                        return Ok(0);
                    }
                    PTRACE_SETOPTIONS
                        if options
                            & !(PTRACE_O_TRACESYSGOOD
                                | PTRACE_O_TRACEEXEC
                                | PTRACE_O_TRACEEXIT
                                | PTRACE_O_EXITKILL)
                            == 0 =>
                    {
                        rel.options = options;
                        return Ok(0);
                    }
                    PTRACE_GET_SYSCALL_INFO => {
                        let stop = stop.clone();
                        drop(slot);
                        return stop.read_syscall_info(addr, options, memory);
                    }
                    PTRACE_GETREGSET => {
                        let stop = stop.clone();
                        drop(slot);
                        return stop.read_regset(addr, options, memory);
                    }
                    PTRACE_GETEVENTMSG => {
                        // Voluntary tracing currently admits leaders, so their TID survives exec.
                        let message = if let Some(status) = stop.exit_status {
                            status as u32 as u64
                        } else if stop.status >> 8 == 4 {
                            self.namespace.local(target.tid()) as u64
                        } else {
                            0
                        };
                        drop(slot);
                        memory
                            .write_array(options, message.to_le_bytes())
                            .map_err(|_| Errno(14))?;
                        return Ok(0);
                    }
                    PTRACE_GETSIGINFO => {
                        let mut info = stop.signal.as_deref().copied().unwrap_or_else(|| Info {
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
                    PTRACE_KILL => {
                        if stop.exit_status.is_some() {
                            let notice = rel.child.trace_event(None);
                            rel.stop = None;
                            target.trace_stop.store(false, Ordering::Release);
                            drop(slot);
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
        target.credentials().check_trace_attach(&credentials)?;
        // Keep authorized requests visibly unsupported until a live task can
        // publish and acknowledge its own tracing stop.
        Err(Errno(38))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        stop.cpu.registers[..6].copy_from_slice(&[10, 11, 12, 13, 14, 15]);
        stop.cpu.registers[8] = 57;
        stop.cpu.pc = 0x1234;
        stop.cpu.sp = 0x9876;
        assert_eq!(stop.read_syscall_info(0, u64::MAX, &mut memory), Ok(80));
        assert_eq!(
            stop.read_syscall_info(1, u64::MAX, &mut memory),
            Err(Errno(14))
        );
        memory.write_array(0x1000, [0xdd; 81]).unwrap();
        assert_eq!(stop.read_syscall_info(7, 0x1000, &mut memory), Ok(80));
        assert_eq!(
            memory.read_array::<8>(0x1000).unwrap(),
            [1, 0, 0, 0, 0xb7, 0, 0, 0xdd]
        );
        assert_eq!(stop.read_syscall_info(100, 0x1000, &mut memory), Ok(80));
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
            assert_eq!(stop.read_syscall_info(80, 0x1000, &mut memory), Ok(33));
            assert_eq!(memory.read_array::<1>(0x1000).unwrap(), [2]);
            assert_eq!(
                memory.read_array::<8>(0x1018).unwrap(),
                result.to_le_bytes()
            );
            assert_eq!(memory.read_array::<1>(0x1020).unwrap(), [error]);
        }
        stop.status = 5;
        assert_eq!(stop.read_syscall_info(80, 0x1000, &mut memory), Ok(24));
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
