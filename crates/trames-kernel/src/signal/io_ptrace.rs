// SPDX-License-Identifier: GPL-3.0-or-later
//! A voluntary guest tracee stops on its execution worker. Its parent consumes
//! normal wait events and observes an immutable snapshot of that stop.
use super::*;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_CONT: u64 = 7;
const PTRACE_DETACH: u64 = 17;
const PTRACE_SETOPTIONS: u64 = 0x4200;
const PTRACE_GETREGSET: u64 = 0x4204;
const PTRACE_INTERRUPT: u64 = 0x4207;
const PTRACE_LISTEN: u64 = 0x4208;
const PTRACE_GETSIGMASK: u64 = 0x420a;
const PTRACE_O_TRACEEXEC: u64 = 1 << 4;
const PTRACE_O_EXITKILL: u64 = 1 << 20;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;
const PTRACE_O_SUSPEND_SECCOMP: u64 = 1 << 21;
const PTRACE_O_MASK: u64 = 0xff | (1 << 20) | PTRACE_O_SUSPEND_SECCOMP;

pub(super) struct Relationship {
    tracer: Weak<IoTask>,
    child: Arc<crate::children::Child>,
    regs: Option<Box<[u64; 34]>>,
    options: u64,
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
        let Some(slot) = self.trace.get() else {
            return false;
        };
        let mut lock = slot.lock().unwrap();
        let Some(rel) = lock.as_mut() else {
            return false;
        };
        if let Some(shared) = shared {
            if self.take(sig, shared).is_none() {
                return false;
            }
        }
        let status = if shared.is_none() && rel.options & PTRACE_O_TRACEEXEC != 0 {
            sig | (4 << 8)
        } else {
            sig
        };
        let cpu = registers();
        let mut regs = Box::new([0; 34]);
        regs[..31].copy_from_slice(&cpu.registers);
        regs[31..].copy_from_slice(&[cpu.sp, cpu.pc, cpu.nzcv as u64]);
        rel.regs = Some(regs);
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
            regs: None,
            options: 0,
        });
        drop(slot);
        drop(list);
        notice.notify();
        Ok(0)
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
                let regs = rel.regs.as_ref().ok_or(Errno(3))?;
                match request {
                    PTRACE_CONT | PTRACE_DETACH => {
                        if options != 0 {
                            return Err(Errno(95));
                        }
                        let notice = if request == PTRACE_DETACH {
                            rel.child.detach_trace()
                        } else {
                            rel.child.trace_event(None)
                        };
                        rel.regs = None;
                        if request == PTRACE_DETACH {
                            *slot = None;
                        }
                        target.trace_stop.store(false, Ordering::Release);
                        drop(slot);
                        notice.notify();
                        target.wake_control();
                        return Ok(0);
                    }
                    PTRACE_SETOPTIONS
                        if options & !(PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL) == 0 =>
                    {
                        rel.options = options;
                        return Ok(0);
                    }
                    PTRACE_GETREGSET if addr == 1 => {
                        let iov = memory.read_array::<16>(options).map_err(|_| Errno(14))?;
                        let base = u64::from_le_bytes(iov[..8].try_into().unwrap());
                        let len = u64::from_le_bytes(iov[8..].try_into().unwrap());
                        if len % 8 != 0 {
                            return Err(Errno(22));
                        }
                        let size = (len.min(34 * 8)) as usize;
                        let mut bytes = [0; 34 * 8];
                        for (dst, word) in bytes.chunks_exact_mut(8).zip(regs.iter()) {
                            dst.copy_from_slice(&word.to_le_bytes());
                        }
                        let out = options.checked_add(8).ok_or(Errno(14))?;
                        drop(slot);
                        if size != 0 {
                            memory.write(base, &bytes[..size]).map_err(|_| Errno(14))?;
                        }
                        memory
                            .write_array(out, (size as u64).to_le_bytes())
                            .map_err(|_| Errno(14))?;
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
