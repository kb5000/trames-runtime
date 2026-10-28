// SPDX-License-Identifier: GPL-3.0-or-later
//! Compatibility state belongs to virtual tasks, never the host process.
use super::*;

#[cfg(all(test, trames_interpreter_conformance))]
use trames_kernel::signal::SS_DISABLE;

impl<C: Cpu> Kernel<C> {
    pub(super) fn sigaltstack(p: &mut Process<C>, new: u64, old: u64) -> Result<u64, Errno> {
        p.signals
            .alt_stack
            .call(p.cpu.sp(), new, old, &mut p.memory)
    }
    pub(super) fn membarrier(p: &Process<C>, command: u64, flags: u64) -> Result<u64, Errno> {
        if flags != 0 {
            return Err(Errno(22));
        }
        // Every CPU has returned before coordinator syscalls. The joined
        // checkpoint and host fence order guest, backing and native accesses.
        match command {
            0 => Ok(1 | 8 | 16 | 512),
            16 => {
                p.membarrier_registered.set(true);
                Ok(0)
            }
            512 => Ok(if p.membarrier_registered.get() { 16 } else { 0 }),
            8 if !p.membarrier_registered.get() => Err(Errno(1)),
            1 | 8 => {
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                Ok(0)
            }
            _ => Err(Errno(22)),
        }
    }
    pub(super) fn ioprio_get(
        &self,
        pid: u32,
        p: &Process<C>,
        which: u64,
        who: u64,
    ) -> Result<u64, Errno> {
        if !(1..=3).contains(&which) || (who as i32) < 0 {
            return Err(Errno(22));
        }
        if which != 1 {
            return Err(Errno(95));
        }
        let target = if who as u32 == 0 {
            0
        } else {
            p.linux.vfs.global_pid(who as u32)?
        };
        if target == 0 || target == pid || self.processes.contains_key(&target) {
            // No explicit I/O priority is installed (CLASS_NONE, data 0).
            // This describes the virtual scheduler; no host PID is consulted.
            Ok(0)
        } else {
            Err(Errno(3))
        }
    }
    pub(super) fn rlimit(
        &self,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let (resource, new, old) = if number == 261 {
            if a[0] != 0 && a[0] != p.linux.vfs.visible_pid(p.tgid) as u64 {
                return Err(Errno(3));
            }
            (a[1], a[2], a[3])
        } else {
            (
                a[0],
                if number == 164 { a[1] } else { 0 },
                if number == 163 { a[1] } else { 0 },
            )
        };
        let fixed = match resource {
            0 | 1 | 10 | 15 => u64::MAX,
            2 | 5 | 9 if self.memory_limits.is_host_managed() => u64::MAX,
            2 | 5 | 9 => self.memory_limits.per_process as u64,
            3 => super::super::STACK_SIZE,
            4 | 8 | 12 | 13 | 14 => 0,
            6 => self.task_limit as u64,
            7 => trames_vfs::MAX_FDS as u64,
            11 => 64,
            _ => return Err(Errno(22)),
        };
        let previous = if resource == 1 {
            p.file_size_limit.get()
        } else {
            (fixed, fixed)
        };
        if old != 0 {
            Linux::check(&p.memory, old, 16, Access::Write)?;
        }
        let next = if new != 0 {
            Linux::check(&p.memory, new, 16, Access::Read)?;
            let limits = (read_u64(&p.memory, new)?, read_u64(&p.memory, new + 8)?);
            if limits.0 > limits.1 {
                return Err(Errno(22));
            }
            if limits.1 > previous.1 && !p.linux.vfs.credentials.has_cap(capabilities::SYS_RESOURCE)
            {
                return Err(Errno(1));
            }
            if resource != 1 && limits.1 > fixed {
                return Err(Errno(1));
            }
            if resource != 1 && limits != previous {
                return Err(Errno(95));
            }
            Some(limits)
        } else {
            None
        };
        if old != 0 {
            write_u64(&mut p.memory, old, previous.0)?;
            write_u64(&mut p.memory, old + 8, previous.1)?;
        }
        if let Some(next) = next {
            if resource == 1 {
                p.file_size_limit.set(next);
            }
        }
        Ok(0)
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::super::tests::{kernel, process};
    use super::*;
    #[test]
    fn compatibility_state_and_fault_preflight() {
        let mut p = process();
        write_u64(&mut p.memory, 0x1000, 0x2000).unwrap();
        write_u64(&mut p.memory, 0x1008, 0).unwrap();
        write_u64(&mut p.memory, 0x1010, 2048).unwrap();
        assert_eq!(Kernel::sigaltstack(&mut p, 0x1000, 0xffff), Err(Errno(14)));
        assert_eq!(p.signals.alt_stack.flags, SS_DISABLE);
        assert_eq!(Kernel::sigaltstack(&mut p, 0x1000, 0), Ok(0));
        p.cpu.sp = 0x2400;
        assert_eq!(Kernel::sigaltstack(&mut p, 0x1000, 0), Err(Errno(1)));
        assert_eq!(Kernel::sigaltstack(&mut p, 0, 0x1100), Ok(0));
        assert_eq!(read_u32(&p.memory, 0x1108), Ok(1));
        assert_eq!(Kernel::membarrier(&p, 8, 0), Err(Errno(1)));
        assert_eq!(Kernel::membarrier(&p, 16, 0), Ok(0));
        assert_eq!(Kernel::membarrier(&p.fork(), 512, 0), Ok(16));
        assert_eq!(Kernel::membarrier(&p, 32, 0), Err(Errno(22)));
        let k = kernel();
        assert_eq!(k.ioprio_get(1, &p, 1, 1), Ok(0));
        assert_eq!(k.ioprio_get(1, &p, 1, 200), Err(Errno(3)));
        assert_eq!(k.ioprio_get(1, &p, 3, 0), Err(Errno(95)));
    }
    #[test]
    fn file_size_limit_changes_are_atomic_and_hard_limit_is_privileged() {
        let mut p = process();
        let k = kernel();
        write_u64(&mut p.memory, 0x1000, 10).unwrap();
        write_u64(&mut p.memory, 0x1008, 20).unwrap();
        assert_eq!(
            k.rlimit(&mut p, 261, [0, 1, 0x1000, 0xffff, 0, 0]),
            Err(Errno(14))
        );
        assert_eq!(p.file_size_limit.get(), (u64::MAX, u64::MAX));
        assert_eq!(k.rlimit(&mut p, 261, [0, 1, 0x1000, 0x1000, 0, 0]), Ok(0));
        assert_eq!(p.file_size_limit.get(), (10, 20));
        assert_eq!(read_u64(&p.memory, 0x1000), Ok(u64::MAX));
        let child = p.fork();
        child.file_size_limit.set((5, 20));
        assert_eq!(p.file_size_limit.get(), (10, 20));
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        write_u64(&mut p.memory, 0x1000, 10).unwrap();
        write_u64(&mut p.memory, 0x1008, 21).unwrap();
        assert_eq!(
            k.rlimit(&mut p, 164, [1, 0x1000, 0, 0, 0, 0]),
            Err(Errno(1))
        );
        assert_eq!(p.file_size_limit.get(), (10, 20));
    }
}
