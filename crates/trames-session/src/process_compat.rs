// SPDX-License-Identifier: GPL-3.0-or-later
//! Compatibility state belongs to virtual tasks, never the host process.
use super::*;

#[cfg(all(test, trames_interpreter_conformance))]
use trames_kernel::signal::SS_DISABLE;

impl<C: Cpu> Kernel<C> {
    pub(super) fn reboot_guest(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        a: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        if !p.linux.vfs.credentials.has_cap(capabilities::SYS_BOOT) {
            return Err(Errno(1));
        }
        if a[0] as u32 != 0xfee1_dead
            || !matches!(
                a[1] as u32,
                0x2812_1969 | 0x0512_1996 | 0x1604_1998 | 0x2011_2000
            )
        {
            return Err(Errno(22));
        }
        match a[2] as u32 {
            0xcdef_0123 | 0x4321_fedc => {}
            0x0123_4567 | 0xa1b2_c3d4 | 0x4558_4543 | 0xd000_fce2 | 0x89ab_cdef | 0 => {
                return Err(Errno(95))
            }
            _ => return Err(Errno(22)),
        }
        // Nested PID namespace restart/status translation is not implemented.
        // Never let its init stop the containing guest environment.
        if p.linux.vfs.pid_namespace().is_nested() {
            return Err(Errno(95));
        }
        // A guest halt/poweroff ends this userspace kernel using the existing
        // root-exit teardown. No host reboot, signal or device API is invoked.
        if p.tgid != 1 {
            if let Some(mut root) = self.processes.remove(&1) {
                self.exit(1, &mut root, 0);
                self.processes.insert(1, root);
            }
        }
        self.exit(pid, p, 0);
        Ok(None)
    }
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
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let target_pid = if number == 261 && a[0] as u32 != 0 {
            p.linux.vfs.global_pid(a[0] as u32)?
        } else {
            pid
        };
        let target = if target_pid == pid {
            &*p
        } else {
            self.processes.get(&target_pid).ok_or(Errno(3))?
        };
        if target.tgid != p.tgid {
            let caller = &p.linux.vfs.credentials;
            let other = &target.linux.vfs.credentials;
            if !caller.has_cap(capabilities::SYS_RESOURCE)
                && !([other.uid, other.euid, other.suid]
                    .iter()
                    .all(|id| *id == caller.uid)
                    && [other.gid, other.egid, other.sgid]
                        .iter()
                        .all(|id| *id == caller.gid))
            {
                return Err(Errno(1));
            }
        }
        let (resource, new, old) = if number == 261 {
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
            target.file_size_limit.get()
        } else if resource == 7 {
            target.nofile_limit.get()
        } else if resource == 4 {
            target.core_limit.get()
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
            if !matches!(resource, 1 | 4) && limits.1 > fixed {
                return Err(Errno(1));
            }
            if !matches!(resource, 1 | 4 | 7) && limits != previous {
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
            // Limits are process-owned and shared by its threads. The FD
            // allocator already uses the same atomic soft limit on workers.
            // Keep caller memory/capabilities separate from the target state.
            let target = if target_pid == pid {
                &*p
            } else {
                &self.processes[&target_pid]
            };
            if resource == 1 {
                target.file_size_limit.set(next);
            } else if resource == 7 {
                target.nofile_limit.set(next);
                target.linux.vfs.set_descriptor_limit(next.0 as u32);
            } else if resource == 4 {
                target.core_limit.set(next);
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
    fn guest_poweroff_checks_authority_magic_and_stops_the_whole_root_group() {
        let mut k = kernel();
        let mut p = process();
        let halt = [0xfee1_dead, 0x2812_1969, 0xcdef_0123, 0, 0, 0];
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        assert_eq!(k.reboot_guest(1, &mut p, [0; 6]), Err(Errno(1)));
        p.linux.vfs.credentials = trames_vfs::Credentials::default();
        assert_eq!(k.reboot_guest(1, &mut p, [0; 6]), Err(Errno(22)));
        assert_eq!(
            k.reboot_guest(1, &mut p, [halt[0], halt[1], 0x01234567, 0, 0, 0]),
            Err(Errno(95))
        );
        assert!(matches!(p.state, State::Ready));
        let memory = p.memory.share();
        let mut thread = p.fork_with_memory(memory);
        thread.tgid = 1;
        k.processes.insert(2, thread);
        assert_eq!(k.reboot_guest(1, &mut p, halt), Ok(None));
        assert!(matches!(p.state, State::Zombie(0)));
        assert!(!k.processes.contains_key(&2));
    }
    #[test]
    fn privileged_child_poweroff_finishes_guest_init_instead_of_only_the_caller() {
        let mut k = kernel();
        let root = process();
        let mut child = root.fork();
        child.tgid = 2;
        child.parent = 1;
        k.processes.insert(1, root);
        assert_eq!(
            k.reboot_guest(
                2,
                &mut child,
                [0xfee1_dead, 0x2812_1969, 0x4321_fedc, 0, 0, 0]
            ),
            Ok(None)
        );
        assert!(matches!(child.state, State::Zombie(0)));
        assert!(matches!(k.processes[&1].state, State::Zombie(0)));
    }
    #[test]
    fn nofile_limits_apply_to_allocation_and_fork_independently() {
        let k = kernel();
        let mut p = process();
        write_u64(&mut p.memory, 0x1000, 8).unwrap();
        write_u64(&mut p.memory, 0x1008, 16).unwrap();
        assert_eq!(
            k.rlimit(1, &mut p, 261, [0, 7, 0x1000, 0x1100, 0, 0]),
            Ok(0)
        );
        assert_eq!(
            read_u64(&p.memory, 0x1100).unwrap(),
            trames_vfs::MAX_FDS as u64
        );
        assert_eq!(p.linux.vfs.descriptor_limit(), 8);
        let mut child = p.fork();
        write_u64(&mut child.memory, 0x1000, 4).unwrap();
        write_u64(&mut child.memory, 0x1008, 8).unwrap();
        assert_eq!(k.rlimit(1, &mut child, 261, [0, 7, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(p.nofile_limit.get(), (8, 16));
        assert_eq!(p.linux.vfs.descriptor_limit(), 8);
        assert_eq!(child.nofile_limit.get(), (4, 8));
        assert_eq!(child.linux.vfs.descriptor_limit(), 4);
        child.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        write_u64(&mut child.memory, 0x1008, 16).unwrap();
        assert_eq!(
            k.rlimit(1, &mut child, 261, [0, 7, 0x1000, 0, 0, 0]),
            Err(Errno(1))
        );
        assert_eq!(child.nofile_limit.get(), (4, 8));
    }
    #[test]
    fn prlimit_targets_child_thread_limits_and_keeps_caller_memory_separate() {
        let mut k = kernel();
        let mut p = process();
        let mut child = p.fork();
        child.tgid = 2;
        child.linux.vfs.activate_child_pid(2).unwrap();
        let mut thread = child.fork();
        thread.tgid = 2;
        thread.linux.vfs.activate_child_pid(3).unwrap();
        thread.nofile_limit = child.nofile_limit.clone();
        thread.linux.vfs.share_descriptor_limit(&child.linux.vfs);
        k.processes.insert(2, child);
        k.processes.insert(3, thread);
        write_u64(&mut p.memory, 0x1000, 8).unwrap();
        write_u64(&mut p.memory, 0x1008, 16).unwrap();
        assert_eq!(
            k.rlimit(1, &mut p, 261, [3, 7, 0x1000, 0xffff, 0, 0]),
            Err(Errno(14))
        );
        assert_eq!(
            k.processes[&2].nofile_limit.get().0,
            trames_vfs::MAX_FDS as u64
        );
        assert_eq!(
            k.rlimit(1, &mut p, 261, [3, 7, 0x1000, 0x1000, 0, 0]),
            Ok(0)
        );
        assert_eq!(read_u64(&p.memory, 0x1000), Ok(trames_vfs::MAX_FDS as u64));
        assert_eq!(p.nofile_limit.get().0, trames_vfs::MAX_FDS as u64);
        for id in [2, 3] {
            assert_eq!(k.processes[&id].nofile_limit.get(), (8, 16));
            assert_eq!(k.processes[&id].linux.vfs.descriptor_limit(), 8);
        }
        let fork = k.processes[&2].fork();
        assert_eq!(fork.nofile_limit.get(), (8, 16));
        write_u64(&mut p.memory, 0x1000, 4).unwrap();
        write_u64(&mut p.memory, 0x1008, 8).unwrap();
        assert_eq!(k.rlimit(1, &mut p, 261, [2, 7, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(fork.nofile_limit.get(), (8, 16));
        assert_eq!(fork.linux.vfs.descriptor_limit(), 8);
        k.processes.remove(&3);
        assert_eq!(k.rlimit(1, &mut p, 261, [3, 7, 0, 0, 0, 0]), Err(Errno(3)));
    }
    #[test]
    fn prlimit_checks_target_ids_and_callers_resource_capability() {
        let mut k = kernel();
        let mut p = process();
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        let mut child = p.fork();
        child.tgid = 2;
        child.linux.vfs.activate_child_pid(2).unwrap();
        k.processes.insert(2, child);
        assert_eq!(k.rlimit(1, &mut p, 261, [2, 7, 0, 0x1100, 0, 0]), Ok(0));
        for field in 0..3 {
            let c = &mut k.processes.get_mut(&2).unwrap().linux.vfs.credentials;
            *c = trames_vfs::Credentials::user(1000, 1000);
            match field {
                0 => c.euid = 1001,
                1 => c.suid = 1001,
                _ => c.sgid = 1001,
            }
            assert_eq!(
                k.rlimit(1, &mut p, 261, [2, 7, 0, 0x1100, 0, 0]),
                Err(Errno(1))
            );
        }
        // A matching effective UID alone is insufficient; real IDs authorize it.
        p.linux.vfs.credentials.euid = 1001;
        k.processes.get_mut(&2).unwrap().linux.vfs.credentials =
            trames_vfs::Credentials::user(1001, 1000);
        assert_eq!(k.rlimit(1, &mut p, 261, [2, 7, 0, 0, 0, 0]), Err(Errno(1)));
        p.linux.vfs.credentials = trames_vfs::Credentials::default();
        k.processes[&2].nofile_limit.set((4, 8));
        write_u64(&mut p.memory, 0x1000, 16).unwrap();
        write_u64(&mut p.memory, 0x1008, 32).unwrap();
        assert_eq!(k.rlimit(1, &mut p, 261, [2, 7, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(k.processes[&2].nofile_limit.get(), (16, 32));
        // The target remains unprivileged; raising uses the caller's capability.
        assert!(!k.processes[&2]
            .linux
            .vfs
            .credentials
            .has_cap(capabilities::SYS_RESOURCE));
    }
    #[test]
    fn prlimit_resolves_nested_pids_and_accepts_the_calling_thread_id() {
        let mut k = kernel();
        let mut p = process();
        p.linux.vfs.unshare_pid().unwrap();
        p.linux.vfs.activate_child_pid(42).unwrap();
        p.tgid = 42;
        let mut child = p.fork();
        child.tgid = 43;
        child.linux.vfs.activate_child_pid(43).unwrap();
        assert_eq!(p.linux.vfs.visible_pid(43), 2);
        k.processes.insert(43, child);
        assert_eq!(k.rlimit(42, &mut p, 261, [2, 7, 0, 0x1100, 0, 0]), Ok(0));
        assert_eq!(
            k.rlimit(42, &mut p, 261, [43, 7, 0, 0, 0, 0]),
            Err(Errno(3))
        );
        assert_eq!(k.rlimit(42, &mut p, 261, [1, 7, 0, 0, 0, 0]), Ok(0));
        let mut thread = p.fork();
        thread.tgid = 42;
        thread.linux.vfs.activate_child_pid(44).unwrap();
        let visible = thread.linux.vfs.visible_pid(44);
        assert_eq!(
            k.rlimit(44, &mut thread, 261, [visible as u64, 7, 0, 0, 0, 0]),
            Ok(0)
        );
    }
    #[test]
    fn core_limits_are_process_owned_capability_checked_and_reported() {
        let k = kernel();
        let mut p = process();
        write_u64(&mut p.memory, 0x1000, u64::MAX).unwrap();
        write_u64(&mut p.memory, 0x1008, u64::MAX).unwrap();
        assert_eq!(
            k.rlimit(1, &mut p, 261, [0, 4, 0x1000, 0x1100, 0, 0]),
            Ok(0)
        );
        assert_eq!(p.core_limit.get(), (u64::MAX, u64::MAX));
        assert_eq!(read_u64(&p.memory, 0x1100).unwrap(), 0);
        let child = p.fork();
        child.core_limit.set((1, 2));
        assert_eq!(p.core_limit.get(), (u64::MAX, u64::MAX));
        p.core_limit.set((0, 0));
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        assert_eq!(
            k.rlimit(1, &mut p, 261, [0, 4, 0x1000, 0, 0, 0]),
            Err(Errno(1))
        );
        assert_eq!(p.core_limit.get(), (0, 0));
    }
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
            k.rlimit(1, &mut p, 261, [0, 1, 0x1000, 0xffff, 0, 0]),
            Err(Errno(14))
        );
        assert_eq!(p.file_size_limit.get(), (u64::MAX, u64::MAX));
        assert_eq!(
            k.rlimit(1, &mut p, 261, [0, 1, 0x1000, 0x1000, 0, 0]),
            Ok(0)
        );
        assert_eq!(p.file_size_limit.get(), (10, 20));
        assert_eq!(read_u64(&p.memory, 0x1000), Ok(u64::MAX));
        let child = p.fork();
        child.file_size_limit.set((5, 20));
        assert_eq!(p.file_size_limit.get(), (10, 20));
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        write_u64(&mut p.memory, 0x1000, 10).unwrap();
        write_u64(&mut p.memory, 0x1008, 21).unwrap();
        assert_eq!(
            k.rlimit(1, &mut p, 164, [1, 0x1000, 0, 0, 0, 0]),
            Err(Errno(1))
        );
        assert_eq!(p.file_size_limit.get(), (10, 20));
    }
}
