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
        trames_kernel::power::prepare(&p.linux.vfs.credentials, p.linux.vfs.pid_namespace(), a)?;
        // A guest halt/poweroff ends this userspace kernel using the existing
        // root-exit teardown. No host reboot, signal or device API is invoked.
        if p.tgid != 1 {
            if let Some(mut root) = self.processes.checkout(&1) {
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
        match crate::barrier::prepare(&p.membarrier_registered, command, flags)? {
            crate::barrier::Action::Complete(value) => Ok(value),
            crate::barrier::Action::Fence(_) => {
                // Joined/solo callers already own all guest execution actors.
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                Ok(0)
            }
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
    pub(super) fn fixed_limits(&self) -> trames_kernel::limits::Fixed {
        trames_kernel::limits::Fixed {
            address_space: if self.memory_limits.is_host_managed() {
                u64::MAX
            } else {
                self.memory_limits.per_process as u64
            },
            stack: super::super::STACK_SIZE,
            tasks: self.task_capacity.limit() as u64,
        }
    }
    pub(super) fn limit_authority(
        &self,
        pid: u32,
        p: &Process<C>,
    ) -> trames_kernel::limits::Authority {
        trames_kernel::limits::Authority {
            directory: self.limit_directory.clone(),
            limits: p.limits.clone(),
            namespace: p.linux.vfs.pid_namespace().clone(),
            pid,
            credentials: p.linux.vfs.credentials.clone(),
            fixed: self.fixed_limits(),
        }
    }
    pub(super) fn rlimit(
        &self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        let target = if number == 261 && a[0] as u32 != 0 {
            p.linux.vfs.global_pid(a[0] as u32)?
        } else {
            pid
        };
        if target == pid {
            // Solo execution borrows its actual limit object. No directory
            // refresh, authority cloning or second namespace translation.
            return p.limits.call(
                number,
                a,
                &mut p.memory,
                self.fixed_limits(),
                p.linux.vfs.credentials.has_cap(capabilities::SYS_RESOURCE),
            );
        }
        self.publish_io_tasks(Some((pid, p)));
        self.limit_authority(pid, p)
            .call_resolved(target, number, a, &mut p.memory)
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Kernel = crate::process::Kernel<Cpu>;

    use super::super::tests::{kernel, process};
    use super::*;
    #[test]
    fn complete_membarrier_abi_runs_on_sources_without_owner_or_mm_checkpoints() {
        for (command, flags, registered, expected) in [
            (0, 0, false, 537i64),
            (16, 0, false, 0),
            (512, 0, true, 16),
            (8, 0, false, -1),
            (8, 0, true, 0),
            (1, 0, false, 0),
            (32, 0, true, -22),
            (8, 1, true, -22),
        ] {
            let mut p = process();
            p.membarrier_registered
                .store(registered, std::sync::atomic::Ordering::Relaxed);
            let mov = |rd: u32, value: u32| 0xd2800000u32 | (value << 5) | rd;
            let code = [
                mov(0, command),
                mov(1, flags),
                0xd4000001,
                0xaa0003f3,
                0x17fffffc,
            ];
            for (n, word) in code.iter().enumerate() {
                p.memory
                    .write_array(0x4000 + n as u64 * 4, word.to_le_bytes())
                    .unwrap();
            }
            p.memory
                .protect(
                    0x4000,
                    trames_memory::PAGE_SIZE,
                    trames_memory::Permissions::RX,
                )
                .unwrap();
            p.cpu.set_x(8, 283);
            p.signals.io.scheduling.set_affinity(3);
            let peer = p.fork();
            peer.family.set_parent(1);
            let mut k = kernel();
            k.cpu_count = 2;
            k.workers = crate::workers::Pool::new(2);
            k.per_cpu = vec![Duration::ZERO; 2];
            k.processes.insert(1, p);
            k.processes.insert(2, peer);
            assert!(k
                .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 50_000, true)
                .unwrap());
            assert!(k.syscalls > 100);
            assert!(
                k.processes.values().all(|p| p.cpu.x(19) == expected as u64),
                "command {command}"
            );
            assert_eq!(k.service_requests, 0);
            assert!(
                k.cohort_return_syscalls.is_empty(),
                "{:?}",
                k.cohort_return_syscalls
            );
            assert_eq!(k.vm_checkpoint_groups, 0);
        }
    }
    #[test]
    fn joined_credential_change_publishes_the_resource_signal_origin() {
        let mut k = kernel();
        let mut p = process();
        p.signals.actions.set_handler(25, 0x5000);
        k.publish_io_tasks(Some((1, &p)));
        k.call(
            1,
            &mut p,
            146,
            [1000, 0, 0, 0, 0, 0],
            &mut trames_linux::CapturedOutput::default(),
        );
        assert_eq!(p.linux.vfs.credentials.uid, 1000);
        trames_vfs::TaskSignal::raise(&*p.signals.io, 25);
        let info = p.signals.io.inbox.take(25).unwrap();
        assert_eq!((info.code, info.sender, info.uid), (0, 1, 1000));
    }
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
        child.family.set_parent(1);
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
        assert!(matches!(k.processes.read(&1).state, State::Zombie(0)));
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
        assert_eq!(p.limits.get(7), (8, 16));
        assert_eq!(p.linux.vfs.descriptor_limit(), 8);
        assert_eq!(child.limits.get(7), (4, 8));
        assert_eq!(child.linux.vfs.descriptor_limit(), 4);
        child.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        write_u64(&mut child.memory, 0x1008, 16).unwrap();
        assert_eq!(
            k.rlimit(1, &mut child, 261, [0, 7, 0x1000, 0, 0, 0]),
            Err(Errno(1))
        );
        assert_eq!(child.limits.get(7), (4, 8));
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
        thread.limits = child.limits.clone();
        thread.limits.bind(&mut thread.linux.vfs);
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
            k.processes.read(&2).limits.get(7).0,
            trames_vfs::MAX_FDS as u64
        );
        assert_eq!(
            k.rlimit(1, &mut p, 261, [3, 7, 0x1000, 0x1000, 0, 0]),
            Ok(0)
        );
        assert_eq!(read_u64(&p.memory, 0x1000), Ok(trames_vfs::MAX_FDS as u64));
        assert_eq!(p.limits.get(7).0, trames_vfs::MAX_FDS as u64);
        for id in [2, 3] {
            assert_eq!(k.processes.read(&id).limits.get(7), (8, 16));
            assert_eq!(k.processes.read(&id).linux.vfs.descriptor_limit(), 8);
        }
        let fork = k.processes.read(&2).fork();
        assert_eq!(fork.limits.get(7), (8, 16));
        write_u64(&mut p.memory, 0x1000, 4).unwrap();
        write_u64(&mut p.memory, 0x1008, 8).unwrap();
        assert_eq!(k.rlimit(1, &mut p, 261, [2, 7, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(fork.limits.get(7), (8, 16));
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
            {
                let c = &mut k.processes.get_mut(&2).unwrap().linux.vfs.credentials;
                *c = trames_vfs::Credentials::user(1000, 1000);
                match field {
                    0 => c.euid = 1001,
                    1 => c.suid = 1001,
                    _ => c.sgid = 1001,
                }
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
        k.processes.read(&2).limits.set(7, (4, 8));
        write_u64(&mut p.memory, 0x1000, 16).unwrap();
        write_u64(&mut p.memory, 0x1008, 32).unwrap();
        assert_eq!(k.rlimit(1, &mut p, 261, [2, 7, 0x1000, 0, 0, 0]), Ok(0));
        assert_eq!(k.processes.read(&2).limits.get(7), (16, 32));
        // The target remains unprivileged; raising uses the caller's capability.
        assert!(!k
            .processes
            .read(&2)
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
        assert_eq!(p.limits.get(4), (u64::MAX, u64::MAX));
        assert_eq!(read_u64(&p.memory, 0x1100).unwrap(), 0);
        let child = p.fork();
        child.limits.set(4, (1, 2));
        assert_eq!(p.limits.get(4), (u64::MAX, u64::MAX));
        p.limits.set(4, (0, 0));
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        assert_eq!(
            k.rlimit(1, &mut p, 261, [0, 4, 0x1000, 0, 0, 0]),
            Err(Errno(1))
        );
        assert_eq!(p.limits.get(4), (0, 0));
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
        assert_eq!(p.limits.get(1), (u64::MAX, u64::MAX));
        assert_eq!(
            k.rlimit(1, &mut p, 261, [0, 1, 0x1000, 0x1000, 0, 0]),
            Ok(0)
        );
        assert_eq!(p.limits.get(1), (10, 20));
        assert_eq!(read_u64(&p.memory, 0x1000), Ok(u64::MAX));
        let child = p.fork();
        child.limits.set(1, (5, 20));
        assert_eq!(p.limits.get(1), (10, 20));
        p.linux.vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
        write_u64(&mut p.memory, 0x1000, 10).unwrap();
        write_u64(&mut p.memory, 0x1008, 21).unwrap();
        assert_eq!(
            k.rlimit(1, &mut p, 164, [1, 0x1000, 0, 0, 0, 0]),
            Err(Errno(1))
        );
        assert_eq!(p.limits.get(1), (10, 20));
    }
}
