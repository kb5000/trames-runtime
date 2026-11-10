// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{admitted_process, kernel};
use super::*;
use crate::execution_control::{Control, End};
use trames_execution::Registers;
use trames_memory::Permissions;

fn executable(p: &mut Process<trames_cpu::Cpu>, words: &[u32]) {
    for (i, word) in words.iter().enumerate() {
        p.memory
            .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    p.memory.protect(0x4000, 4096, Permissions::RX).unwrap();
}

#[test]
fn closing_is_one_way_even_when_legacy_handoff_races_completion() {
    for reason in [End::Budget, End::Cancelled, End::Exited, End::Failed] {
        let control = Arc::new(Control::new(10));
        control.close(reason);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let control = &control;
                scope.spawn(move || control.handoff());
            }
        });
        assert_eq!(control.end(), Some(reason));
        assert!(control.claim().is_none());
    }
}

#[test]
fn single_cpu_root_exit_is_completed_by_the_source_lifecycle() {
    for cpus in [1, 4, 12] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.per_cpu.resize(cpus, Duration::ZERO);
        k.profile_syscalls = true;
        let mut root = admitted_process(&k);
        executable(&mut root, &[0xd28000e0, 0xd2800ba8, 0xd4000001]);
        k.publish_task(1, &root);
        k.processes.insert(1, root);
        let exit = k
            .drive(&mut trames_linux::CapturedOutput::default(), 100000)
            .unwrap();
        assert_eq!(exit.code, 7);
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.worker_slices > 0);
        assert!(k.cohort_return_syscalls.is_empty());
        assert_eq!(k.serviced_syscalls, 0);
        assert!(k.processes.read(&1).family.status().is_some());
    }
}

#[test]
fn initial_busy_memory_is_admitted_without_host_cpu_execution() {
    struct Backing(Arc<trames_memory::layout::Layout>);
    impl trames_memory::PageBacking for Backing {
        fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
            Some(self.0.clone())
        }
        fn parallel_key(&self) -> Option<(u64, u64)> {
            Some((self.0.identity(), 0))
        }
        fn check(&self, _: u64) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn read(&self, _: usize, out: &mut [u8]) -> Result<(), trames_memory::MemoryError> {
            out.fill(0);
            Ok(())
        }
        fn write(&self, _: usize, _: &[u8]) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn sync(&self) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            0
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(
            &self,
            _: u64,
        ) -> Result<Arc<dyn trames_memory::PageBacking>, trames_memory::MemoryError> {
            Err(trames_memory::MemoryError::InvalidRange)
        }
    }
    struct Host {
        polls: usize,
        release: Option<trames_memory::layout::LayoutWrite>,
    }
    impl GuestOutput for Host {
        fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
            Arc::new(trames_vfs::CapturedConsole::default())
        }
        fn poll_host(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<HostState> {
            self.polls += 1;
            if self.polls == 2 {
                drop(self.release.take().unwrap());
            }
            assert!(
                self.polls < 100,
                "original memory release did not wake admission"
            );
            Ok(HostState::Running)
        }
        fn control_poll_interval(&self) -> Duration {
            Duration::from_millis(1)
        }
        fn write(&mut self, _: trames_linux::OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
    }
    for cpus in [1, 4, 12] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.per_cpu.resize(cpus, Duration::ZERO);
        let mut root = admitted_process(&k);
        executable(&mut root, &[0xd28000e0, 0xd2800ba8, 0xd4000001]);
        let layout = Arc::<trames_memory::layout::Layout>::default();
        root.memory
            .map_backed(
                0x10000,
                vec![Arc::new(Backing(layout.clone()))],
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let writer = layout.write();
        assert!(!root.memory.admit_parallel_layouts());
        k.publish_task(1, &root);
        k.processes.insert(1, root);
        let mut host = Host {
            polls: 0,
            release: Some(writer),
        };
        assert_eq!(k.drive(&mut host, 100000).unwrap().code, 7);
        assert!(host.polls >= 2);
        assert_eq!(k.parallel_rounds, 1);
        assert!(k.worker_slices > 0);
        assert!(k.cohort_return_syscalls.is_empty());
    }
}

#[test]
fn explicit_host_cancel_finishes_on_source_without_a_stopped_host_hook() {
    struct Output {
        cancel: bool,
        polls: usize,
    }
    impl GuestOutput for Output {
        fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
            trames_linux::CapturedOutput::default().source_console()
        }
        fn write(&mut self, _: trames_linux::OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }
        fn control_poll_interval(&self) -> Duration {
            Duration::from_millis(1)
        }
        fn poll_host(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<trames_linux::HostState> {
            self.polls += 1;
            self.cancel = self.polls > 1;
            Ok(trames_linux::HostState::Running)
        }
        fn cancellation_requested(&self) -> bool {
            self.cancel
        }
    }
    for cpus in [1, 4, 12] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.per_cpu.resize(cpus, Duration::ZERO);
        let mut root = admitted_process(&k);
        executable(&mut root, &[0xd2820001, 0xd2800540, 0xb9000020, 0x14000000]);
        k.publish_task(1, &root);
        k.processes.insert(1, root);
        let mut output = Output {
            cancel: false,
            polls: 0,
        };
        assert!(matches!(
            k.drive(&mut output, u64::MAX),
            Err(RuntimeError::Cancelled)
        ));
        assert!(output.polls > 1);
        assert_eq!(
            k.processes.read(&1).memory.read_array::<4>(0x1000).unwrap(),
            42u32.to_le_bytes()
        );
        assert!(k.worker_slices > 0);
    }
}

#[test]
fn closing_preserves_an_accepted_cpu_trap_without_executing_it_on_the_waiting_host() {
    let mut k = kernel();
    let mut root = admitted_process(&k);
    executable(
        &mut root,
        &[
            0xd4000001, 0xd2820001, 0xb9000020, 0xd28000e0, 0xd2800ba8, 0xd4000001,
        ],
    );
    root.cpu.set_x(0, 77);
    root.cpu.set_x(8, 172);
    root.cpu.set_pc(0x4004);
    root.pending_cpu = Some(SliceOutcome::Syscall { instructions: 0 });
    root.seccomp_entry = Some(
        root.seccomp
            .entry_decision(172, root.cpu.pc(), args(&root.cpu)),
    );
    // A later policy publication must not re-evaluate the already accepted SVC.
    let filter = [
        (0x20u16, 0u8, 0u8, 0u32),
        (0x15, 0, 1, 172),
        (6, 0, 0, 0x50007),
        (6, 0, 0, 0x7fff0000),
    ];
    for (index, (op, yes, no, value)) in filter.into_iter().enumerate() {
        let mut bytes = [0; 8];
        bytes[..2].copy_from_slice(&op.to_le_bytes());
        bytes[2] = yes;
        bytes[3] = no;
        bytes[4..].copy_from_slice(&value.to_le_bytes());
        root.memory
            .write_array(0x1400 + index as u64 * 8, bytes)
            .unwrap();
    }
    root.memory
        .write_array(0x1300, [4, 0, 0, 0, 0, 0, 0, 0, 0, 0x14, 0, 0, 0, 0, 0, 0])
        .unwrap();
    root.linux.vfs.credentials.caps.no_new_privs.set();
    assert_eq!(k.seccomp(&mut root, [1, 0, 0x1300, 0, 0, 0]), Ok(0));
    k.publish_task(1, &root);
    k.processes.insert(1, root);
    let control = Arc::new(Control::new(10000));
    let epoch = crate::run_queue::Epoch::with_events(control.clone(), k.workers.events(), true);
    epoch.bind_lifecycle(lifecycle::Lifecycle::capture(&k));
    let (_, _, view) = k.prepare_parallel_views(&[(1, 0)]).unwrap().pop().unwrap();
    epoch.add(k.capture_worker(
        1,
        view,
        &control,
        &mut Default::default(),
        &mut Default::default(),
        &mut Default::default(),
    ));
    control.close(End::Budget);
    k.workers.ensure(0).unwrap();
    k.workers.finish_closed(epoch.clone()).unwrap();
    assert!(epoch.collect_closed(&mut k).is_none());
    {
        let root = k.processes.read(&1);
        assert_eq!(root.cpu.x(0), 77, "closed report executed getpid");
        assert!(matches!(
            root.pending_cpu,
            Some(SliceOutcome::Syscall { .. })
        ));
    }
    assert_eq!(
        k.drive(&mut trames_linux::CapturedOutput::default(), 10000)
            .unwrap()
            .code,
        7
    );
    assert_eq!(
        k.processes.read(&1).memory.read_array::<4>(0x1000).unwrap(),
        1u32.to_le_bytes()
    );
}

#[test]
fn source_backend_fault_closes_without_returning_to_generic_dispatch() {
    let mut k = kernel();
    let mut root = admitted_process(&k);
    executable(&mut root, &[0x14000000]);
    root.pending_cpu = Some(SliceOutcome::Fault(trames_engine::CpuFault::Host(
        "original backend failure".into(),
    )));
    k.publish_task(1, &root);
    k.processes.insert(1, root);
    let control = Arc::new(Control::new(10000));
    let epoch = crate::run_queue::Epoch::with_events(control.clone(), k.workers.events(), true);
    epoch.bind_lifecycle(lifecycle::Lifecycle::capture(&k));
    let (_, _, view) = k.prepare_parallel_views(&[(1, 0)]).unwrap().pop().unwrap();
    epoch.add(k.capture_worker(
        1,
        view,
        &control,
        &mut Default::default(),
        &mut Default::default(),
        &mut Default::default(),
    ));
    k.workers.ensure(0).unwrap();
    k.workers.launch(0, epoch.clone()).unwrap();
    assert!(matches!(
        k.workers.event_timeout(Duration::from_secs(2)).unwrap(),
        Some(crate::workers::Event::EpochStopped(0))
    ));
    assert_eq!(control.end(), Some(End::Failed));
    k.workers.finish_closed(epoch.clone()).unwrap();
    assert!(
        matches!(epoch.collect_closed(&mut k), Some(RuntimeError::Backend(error)) if error == "original backend failure")
    );
    assert!(k.cohort_return_syscalls.is_empty());
    assert_eq!(k.serviced_syscalls, 0);
}

#[test]
fn single_cpu_bootstrap_opens_original_embedding_terminal_zero_without_owner_return() {
    let mut k = kernel();
    k.profile_syscalls = true;
    let mut root = admitted_process(&k);
    root.linux.vfs.enable_terminal().unwrap();
    root.memory.write(0x1000, b"/dev/tty\0").unwrap();
    root.cpu.set_x(0, (-100i64) as u64);
    root.cpu.set_x(1, 0x1000);
    root.cpu.set_x(2, 0x20002);
    root.cpu.set_x(8, 56);
    executable(
        &mut root,
        &[0xd4000001, 0xaa0003f3, 0xd2800000, 0xd2800ba8, 0xd4000001],
    );
    k.publish_task(1, &root);
    k.processes.insert(1, root);
    assert_eq!(
        k.drive(&mut trames_linux::CapturedOutput::default(), 100000)
            .unwrap()
            .code,
        0
    );
    assert!((3..trames_vfs::MAX_FDS as u64).contains(&k.processes.read(&1).cpu.x(19)));
    assert_eq!(k.parallel_rounds, 1);
    assert!(k.cohort_return_syscalls.is_empty());
    assert_eq!(k.serviced_syscalls, 0);
}

#[test]
fn reserved_budget_waits_for_actual_source_cpu_quiescence_and_refunds_unused_credit() {
    let mut k = kernel();
    for pid in [1, 2] {
        let mut task = admitted_process(&k);
        task.tgid = pid;
        executable(&mut task, &[0x14000000]);
        k.publish_task(pid, &task);
        k.processes.insert(pid, task);
    }
    let control = Arc::new(Control::with_budget(10, true));
    let epoch = crate::run_queue::Epoch::with_events(control.clone(), k.workers.events(), true);
    epoch.bind_lifecycle(lifecycle::Lifecycle::capture(&k));
    for (pid, _, view) in k.prepare_parallel_views(&[(1, 0), (2, 0)]).unwrap() {
        epoch.add(k.capture_worker(
            pid,
            view,
            &control,
            &mut Default::default(),
            &mut Default::default(),
            &mut Default::default(),
        ));
    }
    let mut first = epoch.take(0).unwrap();
    assert_eq!(control.claim(), Some(10));
    assert_eq!(control.claim(), None);
    assert_eq!(
        control.end(),
        None,
        "unallocated zero is not retired budget"
    );
    control.refund(4);
    first.stats.instructions = 6;
    epoch.park(first, None);
    let mut second = epoch.take(0).unwrap();
    assert_eq!(control.claim(), Some(4));
    assert_eq!(control.claim(), None);
    assert_eq!(
        control.end(),
        None,
        "the second CPU still owns its reservation"
    );
    second.stats.instructions = 4;
    epoch.park(second, None);
    assert!(epoch.take(0).is_none());
    assert_eq!(control.end(), Some(End::Budget));
    k.workers.ensure(0).unwrap();
    k.workers.finish_closed(epoch.clone()).unwrap();
    assert!(epoch.collect_closed(&mut k).is_none());
    assert_eq!(k.instructions, 10);
}
