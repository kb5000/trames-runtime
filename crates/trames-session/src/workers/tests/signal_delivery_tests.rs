// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::run_queue::{ChildWait, Delivery, WaitState};
use trames_engine::Cpu as _;
use trames_execution::Registers as _;
use trames_kernel::signal::{Action, Info};
use trames_memory::{
    MemoryError, PageBacking, PageSource, PageWait, Permissions, SharedPage, PAGE_SIZE,
};

struct Deferred {
    wait: Arc<PageWait>,
    page: Arc<SharedPage>,
    identity: u64,
}
impl Deferred {
    fn install(memory: &mut Memory, address: u64) -> Arc<Self> {
        let page = Arc::new(Self {
            wait: Arc::default(),
            page: Arc::new(SharedPage::new([0; PAGE_SIZE as usize])),
            identity: trames_memory::new_backing_identity(),
        });
        memory
            .map_backed(
                address,
                vec![Arc::new(Backing(page.clone()))],
                true,
                Permissions::RW,
                true,
            )
            .unwrap();
        page
    }
}
impl PageSource for Deferred {
    fn load(&self) -> Result<Arc<SharedPage>, MemoryError> {
        if self.wait.ready() {
            Ok(self.page.clone())
        } else {
            Err(self.wait.fault(0))
        }
    }
}
struct Backing(Arc<Deferred>);
impl PageBacking for Backing {
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn page_source(&self) -> Option<Arc<dyn PageSource>> {
        Some(self.0.clone())
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.0.identity, 0))
    }
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.0.load()?.copy_read(offset, bytes);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0.load()?.copy_write(offset, bytes);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}
fn memory() -> Memory {
    let mut memory = Memory::default();
    memory.map(0x1000, 0x40000, Permissions::RW).unwrap();
    memory
}
fn selected(
    snapshot: &crate::worker_syscalls::Snapshot,
    status: i32,
) -> trames_kernel::signal::RetainedInfo {
    snapshot
        .io_signals
        .inbox
        .enqueue(
            35,
            Info {
                status,
                ..Default::default()
            },
        )
        .unwrap();
    snapshot.io_signals.take(35, false).unwrap()
}

#[test]
fn interrupted_sleep_retains_its_signal_and_original_remaining_time_through_a_copy_wait() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    let action = Action {
        handler: 0x20000,
        flags: 0x1000_0000,
        ..Default::default()
    };
    let delivery = Delivery::new(
        35,
        selected(&snapshot, 17),
        action,
        Some(WaitState::Sleep {
            deadline: Instant::now() + Duration::from_secs(60),
            remaining: 0x1ff8,
        }),
        None,
    );
    assert!(delivery.progress(&mut memory).is_none());
    assert!(!delivery.ready());
    assert!(
        snapshot.io_signals.dequeue(1 << 34).is_none(),
        "the accepted delivery is not available to another reader"
    );
    snapshot
        .io_signals
        .inbox
        .enqueue(
            35,
            Info {
                status: 23,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(snapshot.io_signals.dequeue(1 << 34).unwrap().1.status, 23);
    let seconds = memory.read_u64(0x1ff8).unwrap();
    memory.write_array(0x1ff8, 99u64.to_le_bytes()).unwrap();
    page.wait.finish();
    let delivered = delivery
        .progress(&mut memory)
        .expect("the original copy must finish");
    assert_eq!(delivered.info.status, 17);
    assert!(
        !delivered.completion.as_ref().unwrap().restart,
        "nanosleep is not restarted by SA_RESTART"
    );
    assert_eq!(memory.read_u64(0x1ff8).unwrap(), 99);
    assert!(seconds <= 60);
    let mut cpu = Cpu::new(0x30004, 0x40000);
    let mut trace = crate::syscall_trace::Trace::default();
    assert!(snapshot
        .finish_delivery(&mut cpu, &mut memory, &mut trace, delivered)
        .unwrap()
        .is_none());
    assert_eq!(memory.read_u64(cpu.sp + 312).unwrap(), (-4i64) as u64);
    assert_eq!(memory.read_u64(cpu.sp + 568).unwrap(), 0x30004);
    assert_eq!(
        i32::from_le_bytes(memory.read_array(cpu.sp + 24).unwrap()),
        17
    );
    assert!(
        delivery.progress(&mut memory).is_none(),
        "a stale clone cannot enter the handler twice"
    );
}

#[test]
fn interrupted_sleep_reports_only_actual_remainder_copy_errors_and_never_restarts() {
    for (address, readonly, errno) in [
        (0, false, 4),
        (0x1000, false, 4),
        (0x1000, true, 14),
        (0x50000, false, 14),
    ] {
        let snapshot = syscall_snapshot();
        let mut memory = memory();
        if readonly {
            memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        }
        let delivery = Delivery::new(
            35,
            selected(&snapshot, 17),
            Action {
                handler: 0x20000,
                flags: 0x1000_0000,
                ..Default::default()
            },
            Some(WaitState::Sleep {
                deadline: Instant::now() + Duration::from_secs(3),
                remaining: address,
            }),
            None,
        );
        let delivered = delivery.progress(&mut memory).unwrap();
        assert_eq!(
            delivered.completion.as_ref().unwrap().result,
            Err(trames_vfs::Errno(errno))
        );
        assert!(!delivered.completion.as_ref().unwrap().restart);
        let mut cpu = Cpu::new(0x30004, 0x40000);
        let mut trace = crate::syscall_trace::Trace::default();
        assert!(snapshot
            .finish_delivery(&mut cpu, &mut memory, &mut trace, delivered)
            .unwrap()
            .is_none());
        assert_eq!(
            memory.read_u64(cpu.sp + 312).unwrap(),
            0u64.wrapping_sub(errno as u64)
        );
        assert_eq!(memory.read_u64(cpu.sp + 568).unwrap(), 0x30004);
    }
}

#[test]
fn interrupted_waitid_keeps_restart_arguments_and_ein_fault_precedence_until_copy_finishes() {
    for fail in [false, true] {
        let snapshot = syscall_snapshot();
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x2000);
        let args = [0, 0, 0x1ff0, 4, 0, 0];
        let request = trames_kernel::children::Wait::prepare(1, 95, args).unwrap();
        let delivery = Delivery::new(
            35,
            selected(&snapshot, 17),
            Action {
                handler: 0x20000,
                flags: 0x1000_0000,
                ..Default::default()
            },
            Some(WaitState::Child(ChildWait::new(request))),
            None,
        );
        assert!(delivery.progress(&mut memory).is_none());
        memory.write_array(0x1ff0, 77u32.to_le_bytes()).unwrap();
        if fail {
            memory.unmap(0x2000, PAGE_SIZE).unwrap();
        }
        page.wait.finish();
        let delivered = delivery
            .progress(&mut memory)
            .expect("original interrupted wait output");
        let completion = delivered.completion.as_ref().unwrap();
        assert_eq!(
            completion.result,
            Err(trames_vfs::Errno(if fail { 14 } else { 4 }))
        );
        assert_eq!(completion.restart, !fail);
        assert_eq!(completion.args, args);
        assert_eq!(memory.read_array::<4>(0x1ff0).unwrap(), 77u32.to_le_bytes());
        let mut cpu = Cpu::new(0x30004, 0x40000);
        cpu.set_x(8, 95);
        let mut trace = crate::syscall_trace::Trace::default();
        assert!(snapshot
            .finish_delivery(&mut cpu, &mut memory, &mut trace, delivered)
            .unwrap()
            .is_none());
        assert_eq!(
            memory.read_u64(cpu.sp + 568).unwrap(),
            if fail { 0x30004 } else { 0x30000 }
        );
        assert_eq!(
            memory.read_u64(cpu.sp + 312).unwrap(),
            if fail { (-14i64) as u64 } else { args[0] }
        );
        if !fail {
            assert_eq!(memory.read_u64(cpu.sp + 312 + 2 * 8).unwrap(), args[2]);
        }
    }
}

#[test]
fn one_shot_handler_is_claimed_before_copy_wait_and_later_identical_installation_survives() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    let action = Action {
        handler: 0x20000,
        flags: 0x8000_0000,
        mask: 1 << 10,
        restorer: 0x24000,
    };
    snapshot.actions.set(35, action);
    snapshot
        .io_signals
        .inbox
        .enqueue(
            35,
            Info {
                status: 17,
                ..Default::default()
            },
        )
        .unwrap();
    snapshot
        .io_signals
        .inbox
        .enqueue(
            35,
            Info {
                status: 23,
                ..Default::default()
            },
        )
        .unwrap();
    let (accepted, info) = snapshot
        .actions
        .take_handler(&snapshot.io_signals, 35, false)
        .unwrap();
    assert_eq!(
        snapshot.actions.get(35),
        Action {
            handler: 0,
            ..action
        }
    );
    assert!(snapshot
        .actions
        .take_handler(&snapshot.io_signals, 35, false)
        .is_none());
    let delivery = Delivery::new(
        35,
        info,
        accepted,
        Some(WaitState::Sleep {
            deadline: Instant::now() + Duration::from_secs(60),
            remaining: 0x1ff8,
        }),
        None,
    );
    assert!(delivery.progress(&mut memory).is_none());
    snapshot.actions.set(35, action);
    page.wait.finish();
    let delivered = delivery.progress(&mut memory).unwrap();
    let mut cpu = Cpu::new(0x30004, 0x40000);
    let mut trace = crate::syscall_trace::Trace::default();
    assert!(snapshot
        .finish_delivery(&mut cpu, &mut memory, &mut trace, delivered)
        .unwrap()
        .is_none());
    assert_eq!(snapshot.actions.get(35), action);
    assert_eq!(
        snapshot
            .actions
            .take_handler(&snapshot.io_signals, 35, false)
            .unwrap()
            .1
            .status,
        23
    );
}

#[test]
fn cancelling_a_parked_delivery_invalidates_old_snapshots_and_keeps_the_signal_consumed() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    let delivery = Delivery::new(
        35,
        selected(&snapshot, 17),
        Action {
            handler: 0x20000,
            ..Default::default()
        },
        Some(WaitState::Sleep {
            deadline: Instant::now() + Duration::from_secs(60),
            remaining: 0x1ff8,
        }),
        None,
    );
    assert!(delivery.progress(&mut memory).is_none());
    let old = delivery.clone();
    delivery.cancel();
    page.wait.finish();
    assert!(old.progress(&mut memory).is_none());
    assert!(snapshot.io_signals.dequeue(1 << 34).is_none());
}

struct ControlWake;
impl trames_shared::IoWake for ControlWake {
    fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
}
#[test]
fn ioctl_source_keeps_original_snapshot_and_ofd_across_cpu_return_and_new_owner_capabilities() {
    let mut vfs = trames_vfs::Vfs::default();
    let [fd, writer] = vfs.pipe(0).unwrap();
    vfs.write(writer, b"abc").unwrap();
    let mut snapshot = syscall_snapshot();
    snapshot.fd_flags = vfs.fd_flags_snapshot();
    snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors())
        .with_paths(vfs.path_queries())
        .with_resources(vfs.descriptor_factory());
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    memory.write(0x1ffe, &[0x55; 2]).unwrap();
    let mut cpu = Cpu::new(0x30004, 0x40000);
    cpu.set_x(8, 29);
    for (i, value) in [fd as u64, 0x541b, 0x1ffe, 0, 0, 0].into_iter().enumerate() {
        cpu.set_x(i, value);
    }
    let control = Arc::new(Control::new(100));
    let epoch = crate::run_queue::Epoch::new(control.clone());
    let mut job = crate::run_queue::Job::new(
        Work {
            task: None,
            audio: None,
            gpu: None,
            pid: 7,
            cpu,
            memory: None,
            control,
            trace: Default::default(),
            syscalls: Some(snapshot),
        },
        1,
        0,
        None,
    );
    let step = crate::syscall_dispatch::execute(
        &mut job,
        &mut memory,
        Some(&epoch),
        0,
        false,
        SliceOutcome::Syscall { instructions: 0 },
    );
    assert!(matches!(
        step.outcome,
        Some(SliceOutcome::Yield { instructions: 0 })
    ));
    job.waiting = step.parked;
    job.io = step.io;
    assert!(job.io.is_some());
    assert_eq!(job.stop_hold(), Some(true));
    assert_eq!(job.work.cpu.x(0), fd as u64);
    let done = job.finish(None, 0);
    let io = done.io.expect("original ioctl must survive the CPU return");
    let file = io.file.expect("original ioctl copy receipt");
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(99, 0).unwrap(), fd);
    assert_eq!(vfs.write(writer, b"more"), Ok(4));
    let owner = trames_linux::DirectSyscalls::default();
    let wake: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
    let trames_linux::IoAttempt::Blocked(wait) =
        owner.start_retained_file(file, 29, io.args, &mut memory, 7, &Arc::downgrade(&wake))
    else {
        panic!("same original output page");
    };
    assert_eq!(wait.interruptible_file_wait(), Some(false));
    assert_eq!(memory.read_array::<2>(0x1ffe).unwrap(), [0x55; 2]);
    page.wait.finish();
    assert!(wait.signal.ready());
    assert!(matches!(
        owner.resume(wait, &mut memory),
        trames_linux::IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(memory.read_array::<4>(0x1ffe).unwrap(), 3u32.to_le_bytes());
    assert_eq!(vfs.read(fd, 8).unwrap(), 99u64.to_le_bytes());
    assert_eq!(vfs.write(writer, b"late"), Err(trames_vfs::Errno(32)));
}
#[test]
fn task_metadata_source_releases_slot_and_keeps_original_name_or_scalar_across_return() {
    for option in [2, 15, 16, 37] {
        let snapshot = syscall_snapshot();
        let task = snapshot.io_signals.clone();
        let name = snapshot.name.clone();
        name.set(b"original-tail");
        let parent = Arc::new(trames_kernel::task_parent::Parentage::default());
        parent.set_death_signal(17);
        task.bind_parentage(&parent);
        let family = Arc::new(trames_kernel::family::Family::default());
        family.set_subreaper(true);
        task.bind_family(&family);
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x2000);
        let address = if matches!(option, 2 | 37) {
            0x1ffe
        } else {
            0x1ff8
        };
        if option == 15 {
            name.set(b"before");
            memory.write(address, b"original").unwrap();
        } else {
            memory.write(address, &[0x55; 2]).unwrap();
        }
        let mut cpu = Cpu::new(0x30004, 0x40000);
        cpu.set_x(8, 167);
        for (i, value) in [option, address, 0, 0, 0, 0].into_iter().enumerate() {
            cpu.set_x(i, value);
        }
        let mut job = crate::run_queue::Job::new(
            Work {
                task: None,
                audio: None,
                gpu: None,
                pid: 7,
                cpu,
                memory: None,
                control: Arc::new(Control::new(100)),
                trace: Default::default(),
                syscalls: Some(snapshot),
            },
            1,
            0,
            None,
        );
        let step = crate::syscall_dispatch::execute(
            &mut job,
            &mut memory,
            None,
            0,
            false,
            SliceOutcome::Syscall { instructions: 0 },
        );
        assert!(matches!(
            step.outcome,
            Some(SliceOutcome::Yield { instructions: 0 })
        ));
        assert_eq!(step.syscalls, 1);
        job.waiting = step.parked;
        assert_eq!(job.stop_hold(), Some(true));
        let done = job.finish(None, 0);
        let Some(WaitState::Signal(wait)) = done.waiting else {
            panic!("accepted task metadata must survive CPU return");
        };
        assert!(!wait.interruptible());
        assert!(!wait.ready(&task));
        parent.set_death_signal(19);
        family.set_subreaper(false);
        name.set(b"later");
        memory.write(address, &[0x77; 2]).unwrap();
        let wake: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
        let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&wake));
        wait.bind(&task, &signal);
        page.wait.finish();
        assert!(signal.ready());
        let other = syscall_snapshot();
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        match option {
            2 => assert_eq!(
                memory.read_array::<4>(address).unwrap(),
                17u32.to_le_bytes()
            ),
            37 => assert_eq!(memory.read_array::<4>(address).unwrap(), 1u32.to_le_bytes()),
            15 => assert_eq!(name.get(), b"original"),
            _ => {
                assert_eq!(memory.read_array::<2>(address).unwrap(), [0x77; 2]);
                assert_eq!(memory.read_array::<8>(0x2000).unwrap(), *b"-tail\0\0\0");
            }
        }
        assert_eq!(parent.death_signal(), 19);
        assert!(!family.subreaper());
        name.set(b"after");
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        assert_eq!(name.get(), b"after");
    }
}
#[test]
fn key_description_source_keeps_original_registry_key_and_snapshot_after_return() {
    let mut vfs = trames_vfs::Vfs::default();
    let mut snapshot = syscall_snapshot();
    let task = snapshot.io_signals.clone();
    let registry = vfs.key_registry();
    let credentials = vfs.credentials.clone();
    let keys = snapshot.session_keys.clone();
    let id = keys
        .join(&registry, &credentials, Some(b"original-ring".to_vec()))
        .unwrap();
    let trames_vfs::KeyResult::Description(expected) = keys
        .access(
            &registry,
            &credentials,
            id as i32,
            trames_vfs::KeyOperation::Describe,
        )
        .unwrap()
    else {
        panic!("description");
    };
    snapshot.namespaces = Some(vfs.task_namespaces());
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    let mut cpu = Cpu::new(0x30004, 0x40000);
    cpu.set_x(8, 219);
    for (i, value) in [6, id, 0x1ff8, 4096, 0, 0].into_iter().enumerate() {
        cpu.set_x(i, value);
    }
    let mut job = crate::run_queue::Job::new(
        Work {
            task: None,
            audio: None,
            gpu: None,
            pid: 7,
            cpu,
            memory: None,
            control: Arc::new(Control::new(100)),
            trace: Default::default(),
            syscalls: Some(snapshot),
        },
        1,
        0,
        None,
    );
    let step = crate::syscall_dispatch::execute(
        &mut job,
        &mut memory,
        None,
        0,
        false,
        SliceOutcome::Syscall { instructions: 0 },
    );
    assert!(matches!(
        step.outcome,
        Some(SliceOutcome::Yield { instructions: 0 })
    ));
    assert_eq!(step.syscalls, 1);
    job.waiting = step.parked;
    assert_eq!(job.stop_hold(), Some(true));
    let done = job.finish(None, 0);
    let Some(WaitState::Signal(wait)) = done.waiting else {
        panic!("accepted key description must survive CPU return");
    };
    assert!(!wait.interruptible());
    assert!(!wait.ready(&task));
    keys.join(&registry, &credentials, Some(b"later-ring".to_vec()))
        .unwrap();
    let observer = trames_vfs::SessionKeys::default();
    assert!(observer
        .access(
            &registry,
            &credentials,
            id as i32,
            trames_vfs::KeyOperation::Describe
        )
        .is_ok());
    memory.write(0x1ff8, &[0x77; 8]).unwrap();
    let wake: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
    let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&wake));
    wait.bind(&task, &signal);
    page.wait.finish();
    assert!(signal.ready());
    let other = syscall_snapshot();
    assert_eq!(
        wait.check(
            &other.io_signals,
            &mut memory,
            &other.io_routes.namespace,
            None
        ),
        Some(Ok(expected.len() as u64))
    );
    assert_eq!(memory.read_array::<8>(0x1ff8).unwrap(), [0x77; 8]);
    let mut tail = vec![0; expected.len() - 8];
    memory.read(0x2000, &mut tail).unwrap();
    assert_eq!(tail, expected[8..]);
    assert!(matches!(
        observer.access(
            &registry,
            &credentials,
            id as i32,
            trames_vfs::KeyOperation::Describe
        ),
        Err(trames_vfs::Errno(126))
    ));
}
#[test]
fn fd_status_source_preserves_original_ofd_and_copy_stage_through_return_and_rebinding() {
    for (number, command) in [(25, 15), (25, 16), (29, 0x5421)] {
        let mut vfs = trames_vfs::Vfs::default();
        let [fd, _writer] = vfs.pipe(0).unwrap();
        let alias = vfs.dup(fd, 0, false).unwrap();
        let mut snapshot = syscall_snapshot();
        let task = snapshot.io_signals.clone();
        snapshot.fd_flags = vfs.fd_flags_snapshot();
        let owner = trames_kernel::signal::Signals {
            io_directory: snapshot.io_routes.directory.clone(),
            ..Default::default()
        };
        snapshot
            .io_routes
            .directory
            .publish(&owner.io, 8, 8, 8, 0, 0);
        let replacement = trames_kernel::signal::Signals {
            io_directory: snapshot.io_routes.directory.clone(),
            ..Default::default()
        };
        snapshot
            .io_routes
            .directory
            .publish(&replacement.io, 9, 9, 9, 0, 0);
        let routes = snapshot.io_routes.clone();
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x2000);
        let address = if command == 0x5421 { 0x1ffe } else { 0x1ffc };
        if command == 16 {
            vfs.fd_flags_snapshot()
                .async_control(
                    fd,
                    8,
                    8,
                    &mut memory,
                    &routes.async_owners(&Default::default()),
                )
                .unwrap();
        } else {
            memory
                .write(
                    address,
                    &1u32.to_le_bytes()[..if command == 15 { 4 } else { 2 }],
                )
                .unwrap();
            if command == 15 {
                page.page.copy_write(0, &8u32.to_le_bytes());
            }
        }
        let mut cpu = Cpu::new(0x30004, 0x40000);
        cpu.set_x(8, number);
        for (i, value) in [fd as u64, command, address, 0, 0, 0]
            .into_iter()
            .enumerate()
        {
            cpu.set_x(i, value);
        }
        let mut job = crate::run_queue::Job::new(
            Work {
                task: None,
                audio: None,
                gpu: None,
                pid: 7,
                cpu,
                memory: None,
                control: Arc::new(Control::new(100)),
                trace: Default::default(),
                syscalls: Some(snapshot),
            },
            1,
            0,
            None,
        );
        let step = crate::syscall_dispatch::execute(
            &mut job,
            &mut memory,
            None,
            0,
            false,
            SliceOutcome::Syscall { instructions: 0 },
        );
        assert!(matches!(
            step.outcome,
            Some(SliceOutcome::Yield { instructions: 0 })
        ));
        assert_eq!(step.syscalls, 1);
        job.waiting = step.parked;
        assert_eq!(job.stop_hold(), Some(true));
        let done = job.finish(None, 0);
        let Some(WaitState::Signal(wait)) = done.waiting else {
            panic!("accepted fd control must survive CPU return");
        };
        assert!(!wait.interruptible());
        assert!(!wait.ready(&task));
        vfs.close(fd).unwrap();
        assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
        if command == 16 {
            vfs.fd_flags_snapshot()
                .async_control(
                    alias,
                    8,
                    9,
                    &mut memory,
                    &routes.async_owners(&Default::default()),
                )
                .unwrap();
        }
        memory.write(address, &[0x77; 2]).unwrap();
        let wake: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
        let old = trames_shared::IoSignal::new(7, Arc::downgrade(&wake));
        wait.bind(&task, &old);
        let current = trames_shared::IoSignal::new(7, Arc::downgrade(&wake));
        wait.bind(&task, &current);
        page.wait.finish();
        assert!(!old.ready());
        assert!(current.ready());
        let other = syscall_snapshot();
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        match command {
            15 => assert_eq!(
                vfs.fd_flags_snapshot().async_control(
                    alias,
                    9,
                    0,
                    &mut memory,
                    &routes.async_owners(&Default::default())
                ),
                Ok(8)
            ),
            16 => {
                assert_eq!(memory.read_array::<2>(address).unwrap(), [0x77; 2]);
                assert_eq!(memory.read_array::<4>(0x2000).unwrap(), 8u32.to_le_bytes());
            }
            _ => {
                assert_ne!(vfs.flags(alias).unwrap() & trames_vfs::O_NONBLOCK, 0);
                assert_eq!(vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
            }
        }
        vfs.fd_flags_snapshot()
            .async_control(
                alias,
                8,
                9,
                &mut memory,
                &routes.async_owners(&Default::default()),
            )
            .unwrap();
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        assert_eq!(
            vfs.fd_flags_snapshot().async_control(
                alias,
                9,
                0,
                &mut memory,
                &routes.async_owners(&Default::default())
            ),
            Ok(9)
        );
    }
}
#[test]
fn queued_signal_source_keeps_original_input_and_pidfd_after_return_and_rebinding() {
    for number in [138, 240, 424] {
        let mut vfs = trames_vfs::Vfs::default();
        let mut snapshot = syscall_snapshot();
        let source = trames_kernel::signal::Signals {
            io_directory: snapshot.io_routes.directory.clone(),
            ..Default::default()
        };
        source.publish_policy(&snapshot.io_routes.namespace, true);
        snapshot.io_signals = source.io.clone();
        snapshot
            .io_routes
            .directory
            .publish(&source.io, 7, 7, 7, 0, 0);
        let mut target = trames_kernel::signal::Signals {
            io_directory: snapshot.io_routes.directory.clone(),
            ..Default::default()
        };
        target.publish_policy(&snapshot.io_routes.namespace, true);
        target.set_mask(1 << 34);
        snapshot
            .io_routes
            .directory
            .publish(&target.io, 8, 8, 8, 0, 0);
        let child = Arc::new(trames_kernel::children::Child::default());
        target.io.lifecycle().bind(&child, None, 8, 0);
        let fd = snapshot
            .io_routes
            .pidfd_open(&vfs.descriptor_factory(), 8, 0)
            .unwrap();
        snapshot.fd_flags = vfs.fd_flags_snapshot();
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x2000);
        let mut info = [0; 48];
        info[..4].copy_from_slice(&35u32.to_le_bytes());
        info[8..12].copy_from_slice(&(-1i32).to_le_bytes());
        info[24..32].copy_from_slice(&0x1234u64.to_le_bytes());
        memory.write(0x1ff0, &info[..16]).unwrap();
        page.page.copy_write(0, &info[16..]);
        let args = match number {
            138 => [8, 35, 0x1ff0, 0, 0, 0],
            240 => [8, 8, 35, 0x1ff0, 0, 0],
            _ => [fd, 35, 0x1ff0, 0, 0, 0],
        };
        let task = snapshot.io_signals.clone();
        let mut cpu = Cpu::new(0x30004, 0x40000);
        cpu.set_x(8, number);
        for (i, value) in args.into_iter().enumerate() {
            cpu.set_x(i, value);
        }
        let mut job = crate::run_queue::Job::new(
            Work {
                task: None,
                audio: None,
                gpu: None,
                pid: 7,
                cpu,
                memory: None,
                control: Arc::new(Control::new(100)),
                trace: Default::default(),
                syscalls: Some(snapshot),
            },
            1,
            0,
            None,
        );
        let step = crate::syscall_dispatch::execute(
            &mut job,
            &mut memory,
            None,
            0,
            false,
            SliceOutcome::Syscall { instructions: 0 },
        );
        assert!(matches!(
            step.outcome,
            Some(SliceOutcome::Yield { instructions: 0 })
        ));
        assert_eq!(step.syscalls, 1);
        job.waiting = step.parked;
        assert_eq!(job.stop_hold(), Some(true));
        let done = job.finish(None, 0);
        let Some(WaitState::Signal(wait)) = done.waiting else {
            panic!("accepted signal input must survive CPU return");
        };
        assert!(!wait.interruptible());
        assert!(!wait.ready(&task));
        assert!(target.io.dequeue(1 << 34).is_none());
        vfs.close(fd as u32).unwrap();
        assert_eq!(
            vfs.open_at(-100, b"/reused", 0x42, 0o600).unwrap(),
            fd as u32
        );
        memory.write_array(0x1ff8, (-6i32).to_le_bytes()).unwrap();
        let wake: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
        let old = trames_shared::IoSignal::new(7, Arc::downgrade(&wake));
        wait.bind(&task, &old);
        let current = trames_shared::IoSignal::new(7, Arc::downgrade(&wake));
        wait.bind(&task, &current);
        page.wait.finish();
        assert!(!old.ready());
        assert!(current.ready());
        let other = syscall_snapshot();
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        let (_, received) = target.io.dequeue(1 << 34).unwrap();
        let accepted = received.user.unwrap();
        assert_eq!(i32::from_le_bytes(accepted[8..12].try_into().unwrap()), -1);
        assert_eq!(
            u64::from_le_bytes(accepted[24..32].try_into().unwrap()),
            0x1234
        );
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        assert!(target.io.dequeue(1 << 34).is_none());
    }
}
#[test]
fn perf_source_resumes_original_attributes_and_factory_after_cpu_return() {
    let mut vfs = trames_vfs::Vfs::default();
    let mut snapshot = syscall_snapshot();
    let task = snapshot.io_signals.clone();
    snapshot.io_routes.directory.publish(&task, 7, 7, 7, 0, 0);
    task.credentials().publish_pidfd_resources(
        &vfs.credentials,
        &vfs.shared_files(),
        vfs.dumpable_state(),
        vfs.pidfd_namespace_source(),
    );
    snapshot.fd_flags = vfs.fd_flags_snapshot();
    snapshot.direct = trames_linux::DirectSyscalls::new(vfs.direct_descriptors())
        .with_resources(vfs.descriptor_factory());
    let expected = vfs.open_at(-100, b"/probe", 0x42, 0o600).unwrap();
    vfs.close(expected).unwrap();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    let mut attr = [0; 136];
    attr[..4].copy_from_slice(&1u32.to_le_bytes());
    attr[4..8].copy_from_slice(&136u32.to_le_bytes());
    attr[8..16].copy_from_slice(&1u64.to_le_bytes());
    memory.write(0x1ff0, &attr[..16]).unwrap();
    page.page.copy_write(0, &attr[16..]);
    let mut cpu = Cpu::new(0x30004, 0x40000);
    cpu.set_x(8, 241);
    for (i, value) in [0x1ff0, 0, u64::MAX, u64::MAX, 0, 0]
        .into_iter()
        .enumerate()
    {
        cpu.set_x(i, value);
    }
    let mut job = crate::run_queue::Job::new(
        Work {
            task: None,
            audio: None,
            gpu: None,
            pid: 7,
            cpu,
            memory: None,
            control: Arc::new(Control::new(100)),
            trace: Default::default(),
            syscalls: Some(snapshot),
        },
        1,
        0,
        None,
    );
    let step = crate::syscall_dispatch::execute(
        &mut job,
        &mut memory,
        None,
        0,
        false,
        SliceOutcome::Syscall { instructions: 0 },
    );
    assert!(matches!(
        step.outcome,
        Some(SliceOutcome::Yield { instructions: 0 })
    ));
    assert_eq!(step.syscalls, 1);
    job.waiting = step.parked;
    assert_eq!(job.stop_hold(), Some(true));
    let done = job.finish(None, 0);
    let Some(WaitState::Signal(wait)) = done.waiting else {
        panic!("accepted perf attr must survive CPU return");
    };
    assert!(!wait.interruptible());
    assert!(!wait.ready(&task));
    let reused = vfs.open_at(-100, b"/during-copy", 0x42, 0o600).unwrap();
    assert_eq!(reused, expected);
    memory.write_array(0x1ff8, 9u64.to_le_bytes()).unwrap();
    let wake: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
    let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&wake));
    wait.bind(&task, &signal);
    page.wait.finish();
    assert!(signal.ready());
    let other = syscall_snapshot();
    let fd = wait
        .check(
            &other.io_signals,
            &mut memory,
            &other.io_routes.namespace,
            None,
        )
        .unwrap()
        .unwrap() as u32;
    assert_ne!(fd, reused);
    task.proc_view.account(Duration::from_nanos(73), 0);
    assert_eq!(
        u64::from_le_bytes(vfs.read(fd, 8).unwrap().try_into().unwrap()),
        73
    );
    vfs.close(fd).unwrap();
    assert_eq!(
        wait.check(
            &other.io_signals,
            &mut memory,
            &other.io_routes.namespace,
            None
        ),
        Some(Ok(fd as u64))
    );
    assert_eq!(vfs.open_at(-100, b"/after-close", 0x42, 0o600).unwrap(), fd);
}
#[test]
fn original_usage_and_robust_queries_release_source_slot_and_keep_their_snapshot_after_return() {
    for number in [100, 153, 165] {
        let snapshot = syscall_snapshot();
        let task = snapshot.io_signals.clone();
        let addresses = Arc::new(trames_execution::ThreadAddresses::default());
        addresses.set_robust(0x1234);
        task.bind_thread_addresses(&addresses);
        task.proc_view.account(Duration::new(2, 250_000_000), 0);
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x2000);
        let args = match number {
            100 => [0, 0x2000, 0x1100, 0, 0, 0],
            153 => [0x1ff8, 0, 0, 0, 0, 0],
            _ => [1, 0x1ff8, 0, 0, 0, 0],
        };
        let mut cpu = Cpu::new(0x30004, 0x40000);
        cpu.set_x(8, number);
        for (i, value) in args.into_iter().enumerate() {
            cpu.set_x(i, value);
        }
        let mut job = crate::run_queue::Job::new(
            Work {
                task: None,
                audio: None,
                gpu: None,
                pid: 7,
                cpu,
                memory: None,
                control: Arc::new(Control::new(100)),
                trace: Default::default(),
                syscalls: Some(snapshot),
            },
            1,
            0,
            None,
        );
        let step = crate::syscall_dispatch::execute(
            &mut job,
            &mut memory,
            None,
            0,
            false,
            SliceOutcome::Syscall { instructions: 0 },
        );
        assert!(matches!(
            step.outcome,
            Some(SliceOutcome::Yield { instructions: 0 })
        ));
        assert_eq!(step.syscalls, 1);
        job.waiting = step.parked;
        assert_eq!(job.stop_hold(), Some(true));
        let done = job.finish(None, 0);
        let Some(WaitState::Signal(wait)) = done.waiting else {
            panic!("original query must survive CPU return");
        };
        assert!(wait.external());
        assert!(!wait.ready(&task));
        let address = if number == 100 { 0x1100 } else { 0x1ff8 };
        memory.write(address, &[0x77; 2]).unwrap();
        addresses.set_robust(0x9999);
        task.proc_view.account(Duration::from_secs(9), 1);
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
        let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        wait.bind(&task, &signal);
        page.wait.finish();
        assert!(signal.ready());
        let other = syscall_snapshot();
        assert!(wait
            .check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            )
            .unwrap()
            .is_ok());
        assert_eq!(memory.read_array::<2>(address).unwrap(), [0x77; 2]);
        if number == 100 {
            assert_eq!(memory.read_u64(0x2000).unwrap(), 0x1234);
        }
        if number == 165 {
            assert_eq!(memory.read_u64(0x2000).unwrap(), 250_000);
        }
    }
}
#[test]
fn scheduling_source_rearms_from_original_input_page_to_original_migration_completion() {
    let snapshot = syscall_snapshot();
    let task = snapshot.io_signals.clone();
    snapshot.io_routes.directory.publish(&task, 7, 7, 7, 0, 0);
    task.scheduling.set_affinity(15);
    let lease = task.lifecycle().enter(&task, 7);
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    memory.write_array(0x1ffc, 2u32.to_le_bytes()).unwrap();
    let mut cpu = Cpu::new(0x30004, 0x40000);
    cpu.set_x(8, 122);
    for (i, value) in [0, 8, 0x1ffc, 0, 0, 0].into_iter().enumerate() {
        cpu.set_x(i, value);
    }
    let mut job = crate::run_queue::Job::new(
        Work {
            task: None,
            audio: None,
            gpu: None,
            pid: 7,
            cpu,
            memory: None,
            control: Arc::new(Control::new(100)),
            trace: Default::default(),
            syscalls: Some(snapshot),
        },
        1,
        0,
        None,
    );
    let step = crate::syscall_dispatch::execute(
        &mut job,
        &mut memory,
        None,
        0,
        false,
        SliceOutcome::Syscall { instructions: 0 },
    );
    assert!(matches!(
        step.outcome,
        Some(SliceOutcome::Yield { instructions: 0 })
    ));
    assert_eq!(step.syscalls, 1);
    job.waiting = step.parked;
    let done = job.finish(None, 0);
    let Some(WaitState::Signal(wait)) = done.waiting else {
        panic!("accepted affinity input");
    };
    assert_eq!(task.scheduling.affinity(), 15);
    let target: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
    let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
    wait.bind(&task, &signal);
    page.wait.finish();
    signal.reset();
    let other = syscall_snapshot();
    assert_eq!(
        wait.check(
            &other.io_signals,
            &mut memory,
            &other.io_routes.namespace,
            Some(&signal)
        ),
        None
    );
    assert_eq!(task.scheduling.affinity(), 2);
    assert!(!wait.ready(&task));
    assert!(!signal.ready());
    memory.write_array(0x1ffc, 4u64.to_le_bytes()).unwrap();
    drop(lease);
    assert!(signal.ready());
    assert_eq!(
        wait.check(
            &other.io_signals,
            &mut memory,
            &other.io_routes.namespace,
            None
        ),
        Some(Ok(0))
    );
    assert_eq!(task.scheduling.affinity(), 2);
}
#[test]
fn limit_and_timer_controls_release_source_slot_and_resume_original_state_after_rebinding() {
    for number in [103, 107, 261] {
        let vfs = trames_vfs::Vfs::default();
        let limits = trames_kernel::limits::Limits::new(&vfs);
        limits.set(7, (64, 128));
        let timers = Arc::new(trames_kernel::timers::Timers::default());
        let mut snapshot = syscall_snapshot();
        snapshot
            .io_routes
            .directory
            .publish(&snapshot.io_signals, 7, 7, 7, 0, 0);
        snapshot.limits = Some(trames_kernel::limits::Authority {
            directory: Arc::default(),
            limits: limits.clone(),
            namespace: snapshot.io_routes.namespace.clone(),
            pid: 7,
            credentials: Default::default(),
            fixed: trames_kernel::limits::Fixed {
                address_space: u64::MAX,
                stack: 8 << 20,
                tasks: 1024,
            },
        });
        snapshot.timers = Some(timers.clone());
        let task = snapshot.io_signals.clone();
        let directory = snapshot.io_routes.directory.clone();
        let namespace = snapshot.io_routes.namespace.clone();
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x2000);
        let address = match number {
            103 => 0x1ff0,
            107 => 0x1ffe,
            _ => 0x1ff8,
        };
        let args = match number {
            103 => {
                memory.write_array(0x1000, 7u64.to_le_bytes()).unwrap();
                memory.write_array(0x1010, 3600u64.to_le_bytes()).unwrap();
                timers
                    .call(
                        103,
                        [0, 0x1000, 0, 0, 0, 0],
                        &mut memory,
                        snapshot.started,
                        &task,
                        &directory,
                        &namespace,
                    )
                    .unwrap();
                memory.write_array(0x1000, 11u64.to_le_bytes()).unwrap();
                memory.write_array(0x1010, 7200u64.to_le_bytes()).unwrap();
                [0, 0x1000, address, 0, 0, 0]
            }
            107 => [1, 0, address, 0, 0, 0],
            _ => {
                memory.write_array(0x1000, 8u64.to_le_bytes()).unwrap();
                memory.write_array(0x1008, 16u64.to_le_bytes()).unwrap();
                [0, 7, 0x1000, address, 0, 0]
            }
        };
        let mut cpu = Cpu::new(0x30004, 0x40000);
        cpu.set_x(8, number);
        for (i, value) in args.into_iter().enumerate() {
            cpu.set_x(i, value);
        }
        let mut job = crate::run_queue::Job::new(
            Work {
                task: None,
                audio: None,
                gpu: None,
                pid: 7,
                cpu,
                memory: None,
                control: Arc::new(Control::new(100)),
                trace: Default::default(),
                syscalls: Some(snapshot),
            },
            1,
            0,
            None,
        );
        let step = crate::syscall_dispatch::execute(
            &mut job,
            &mut memory,
            None,
            0,
            false,
            SliceOutcome::Syscall { instructions: 0 },
        );
        assert!(matches!(
            step.outcome,
            Some(SliceOutcome::Yield { instructions: 0 })
        ));
        assert_eq!(step.syscalls, 1);
        job.waiting = step.parked;
        assert_eq!(job.stop_hold(), Some(true));
        let done = job.finish(None, 0);
        let Some(WaitState::Signal(wait)) = done.waiting else {
            panic!("accepted control must survive original CPU return");
        };
        assert!(!wait.interruptible());
        assert!(!wait.ready(&task));
        match number {
            103 => {
                timers
                    .call(
                        103,
                        [0, 0, 0, 0, 0, 0],
                        &mut memory,
                        Instant::now(),
                        &task,
                        &directory,
                        &namespace,
                    )
                    .unwrap();
            }
            107 => assert_eq!(
                timers.call(
                    108,
                    [1, 0x1300, 0, 0, 0, 0],
                    &mut memory,
                    Instant::now(),
                    &task,
                    &directory,
                    &namespace
                ),
                Err(trames_vfs::Errno(22))
            ),
            _ => {
                assert_eq!(limits.get(7), (8, 16));
                limits.set(7, (4, 8));
            }
        }
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
        let old = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        wait.bind(&task, &old);
        let current = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        wait.bind(&task, &current);
        memory.write(address, &[0x77; 2]).unwrap();
        page.wait.finish();
        assert!(!old.ready());
        assert!(current.ready());
        let other = syscall_snapshot();
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        assert_eq!(memory.read_array::<2>(address).unwrap(), [0x77; 2]);
        match number {
            103 => assert!(timers.next_deadline().is_none()),
            107 => assert_eq!(
                timers.call(
                    108,
                    [1, 0x1300, 0, 0, 0, 0],
                    &mut memory,
                    Instant::now(),
                    &task,
                    &directory,
                    &namespace
                ),
                Ok(0)
            ),
            _ => assert_eq!(limits.get(7), (4, 8)),
        }
    }
}
#[test]
fn signal_controls_release_the_original_source_slot_and_survive_return_and_rebinding() {
    for number in [132, 134, 135, 136] {
        let snapshot = syscall_snapshot();
        let task = snapshot.io_signals.clone();
        let actions = snapshot.actions.shared();
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x2000);
        let address = if matches!(number, 135 | 136) {
            0x1ffc
        } else {
            0x1ff0
        };
        let args = match number {
            132 => {
                memory.write_array(0x1000, 0x6000u64.to_le_bytes()).unwrap();
                memory.write_array(0x1010, 8192u64.to_le_bytes()).unwrap();
                [0x1000, address, 0, 0, 0, 0]
            }
            134 => {
                memory.write_array(0x1000, 0x5000u64.to_le_bytes()).unwrap();
                [10, 0x1000, address, 8, 0, 0]
            }
            135 => {
                memory
                    .write_array(0x1000, (1u64 << 15).to_le_bytes())
                    .unwrap();
                [2, 0x1000, address, 8, 0, 0]
            }
            _ => {
                task.context.lock().unwrap().mask = 1 << 34;
                task.publish_mask(1 << 34);
                task.inbox.enqueue(35, Info::default()).unwrap();
                [address, 8, 0, 0, 0, 0]
            }
        };
        let mut cpu = Cpu::new(0x30004, 0x40000);
        cpu.set_x(8, number as u64);
        for (i, value) in args.into_iter().enumerate() {
            cpu.set_x(i, value);
        }
        let mut job = crate::run_queue::Job::new(
            Work {
                task: None,
                audio: None,
                gpu: None,
                pid: 7,
                cpu,
                memory: None,
                control: Arc::new(Control::new(100)),
                trace: Default::default(),
                syscalls: Some(snapshot),
            },
            1,
            0,
            None,
        );
        let step = crate::syscall_dispatch::execute(
            &mut job,
            &mut memory,
            None,
            0,
            false,
            SliceOutcome::Syscall { instructions: 0 },
        );
        assert!(matches!(
            step.outcome,
            Some(SliceOutcome::Yield { instructions: 0 })
        ));
        assert_eq!(step.syscalls, 1);
        job.waiting = step.parked;
        assert_eq!(job.stop_hold(), Some(true));
        let done = job.finish(None, 0);
        let Some(WaitState::Signal(wait)) = done.waiting else {
            panic!("the accepted control must survive the CPU return");
        };
        assert!(!wait.interruptible());
        assert!(wait.external());
        assert!(!wait.ready(&task));
        match number {
            132 => assert_eq!(task.context.lock().unwrap().alt_stack.sp, 0x6000),
            134 => assert_eq!(actions.get(10).handler, 0x5000),
            135 => assert_eq!(task.mask(), 1 << 15),
            _ => {
                assert!(task.dequeue(1 << 34).is_some());
            }
        }
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
        let old = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        wait.bind(&task, &old);
        let current = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
        wait.bind(&task, &current);
        if number == 134 {
            actions.set(
                10,
                Action {
                    handler: 0x7000,
                    ..Default::default()
                },
            );
        }
        memory.write(address, b"KEEP").unwrap();
        page.wait.finish();
        assert!(!old.ready());
        assert!(current.ready());
        assert!(wait.ready(&task));
        let other = syscall_snapshot();
        assert_eq!(
            wait.check(
                &other.io_signals,
                &mut memory,
                &other.io_routes.namespace,
                None
            ),
            Some(Ok(0))
        );
        assert_eq!(memory.read_array::<4>(address).unwrap(), *b"KEEP");
        if number == 134 {
            assert_eq!(actions.get(10).handler, 0x7000);
        }
        if number == 136 {
            assert_eq!(memory.read_array::<4>(0x2000).unwrap(), 4u32.to_le_bytes());
        }
    }
}
#[test]
fn cancelling_a_signal_control_invalidates_shared_handoffs_and_releases_page_subscriptions() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    memory.write_array(0x1000, 0x5000u64.to_le_bytes()).unwrap();
    let mut call = trames_kernel::signal::ControlCall::new(
        134,
        [10, 0x1000, 0x1ff0, 8, 0, 0],
        0x40000,
        snapshot.actions.shared(),
        snapshot.io_routes.directory.clone(),
    );
    assert_eq!(call.check(&snapshot.io_signals, &mut memory), None);
    let wait = crate::run_queue::SignalWait::control(call);
    let old = wait.clone();
    let target: Arc<dyn trames_shared::IoWake> = Arc::new(ControlWake);
    let signal = trames_shared::IoSignal::new(7, Arc::downgrade(&target));
    wait.bind(&snapshot.io_signals, &signal);
    wait.cancel();
    drop(wait);
    memory.write(0x1ff0, b"KEEP").unwrap();
    page.page.copy_write(0, &[0x5a; 16]);
    page.wait.finish();
    assert!(!signal.ready());
    assert_eq!(
        old.check(
            &snapshot.io_signals,
            &mut memory,
            &snapshot.io_routes.namespace,
            None
        ),
        Some(Err(trames_vfs::Errno(4)))
    );
    assert_eq!(memory.read_array::<4>(0x1ff0).unwrap(), *b"KEEP");
    assert_eq!(memory.read_array::<16>(0x2000).unwrap(), [0x5a; 16]);
    assert_eq!(snapshot.actions.get(10).handler, 0x5000);
}

#[test]
fn failed_setup_can_deliver_sigsegv_on_the_original_ordinary_stack() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    snapshot.io_signals.context.lock().unwrap().alt_stack = trames_kernel::signal::AltStack {
        sp: 0x50000,
        size: 8192,
        flags: 0,
    };
    let fault_handler = Action {
        handler: 0x21000,
        flags: 4,
        ..Default::default()
    };
    snapshot.actions.set(11, fault_handler);
    let mut cpu = Cpu::new(0x30004, 0x40000);
    let original = cpu.architectural_state();
    assert!(snapshot
        .enter_io_signal(
            &mut cpu,
            &mut memory,
            35,
            Info::default(),
            Action {
                handler: 0x20000,
                flags: 0x08000000,
                ..Default::default()
            }
        )
        .unwrap()
        .is_none());
    assert_eq!(cpu.architectural_state(), original);
    assert_eq!(snapshot.io_signals.context.lock().unwrap().frames, 0);
    assert!(snapshot.io_signals.lifecycle().termination().is_none());
    let (action, info) = snapshot
        .actions
        .take_handler(&snapshot.io_signals, 11, false)
        .unwrap();
    assert_eq!((info.code, info.fault), (128, Some(0)));
    assert!(snapshot
        .enter_io_signal(&mut cpu, &mut memory, 11, *info, action)
        .unwrap()
        .is_none());
    assert_eq!(cpu.pc(), 0x21000);
    assert_eq!(snapshot.io_signals.context.lock().unwrap().frames, 1);
    assert_eq!(memory.read_u64(cpu.sp() + 568).unwrap(), original.pc);
}
#[test]
fn recursive_sigsegv_setup_failure_selects_the_default_disposition_through_the_signal_path() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    snapshot.io_signals.context.lock().unwrap().alt_stack = trames_kernel::signal::AltStack {
        sp: 0x50000,
        size: 8192,
        flags: 0,
    };
    let action = Action {
        handler: 0x20000,
        flags: 0x08000004,
        mask: 1 << 15,
        ..Default::default()
    };
    snapshot.actions.set(11, action);
    let mut cpu = Cpu::new(0x30004, 0x40000);
    assert!(snapshot
        .enter_io_signal(&mut cpu, &mut memory, 11, Info::default(), action)
        .unwrap()
        .is_none());
    assert_eq!(
        snapshot.actions.get(11),
        Action {
            handler: 0,
            ..action
        }
    );
    assert_eq!(snapshot.io_signals.inbox.peek(11).unwrap().code, 128);
    assert!(
        snapshot.io_signals.lifecycle().termination().is_none(),
        "forced delivery remains observable to the original signal/ptrace selection"
    );
}
#[test]
fn resumed_setup_failure_keeps_its_original_signal_and_does_not_return_efault() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x3f000);
    snapshot.actions.set(
        11,
        Action {
            handler: 0x21000,
            ..Default::default()
        },
    );
    let mut cpu = Cpu::new(0x30004, 0x40000);
    let original = cpu.architectural_state();
    assert!(snapshot
        .enter_io_signal(
            &mut cpu,
            &mut memory,
            35,
            Info::default(),
            Action {
                handler: 0x20000,
                ..Default::default()
            }
        )
        .unwrap()
        .is_some());
    assert!(snapshot.io_signals.inbox.peek(11).is_none());
    memory.unmap(0x3f000, PAGE_SIZE).unwrap();
    page.wait.finish();
    assert_eq!(
        snapshot.resume_io_frame(&mut cpu, &mut memory),
        Ok((None, false))
    );
    assert_eq!(snapshot.actions.get(11).handler, 0x21000);
    assert_eq!(snapshot.io_signals.inbox.peek(11).unwrap().code, 128);
    assert_eq!(cpu.architectural_state(), original);
}
#[test]
fn bad_sigreturn_forces_original_fault_info_and_returns_zero_at_the_syscall_boundary() {
    for (sp, blocked, address, code) in [
        (0x3001, false, 0x3001, 2),
        (0x700000, false, 0, 2),
        (0x3001, true, 0x3001, 2),
    ] {
        let snapshot = syscall_snapshot();
        let mut memory = memory();
        let page = Deferred::install(&mut memory, 0x3000);
        let action = Action {
            handler: 0x21000,
            flags: 4,
            ..Default::default()
        };
        snapshot.actions.set(11, action);
        if blocked {
            snapshot.io_signals.context.lock().unwrap().mask = 1 << 10;
            snapshot.io_signals.publish_mask(1 << 10);
        }
        let mut cpu = Cpu::new(0x30004, sp);
        cpu.set_x(0, 99);
        assert!(snapshot
            .return_io_signal(&mut cpu, &mut memory)
            .unwrap()
            .is_none());
        assert_eq!(cpu.x(0), 0);
        assert!(!page.wait.ready());
        let info = snapshot.io_signals.inbox.peek(11).unwrap();
        // An unaligned frame fails before GPR restore. An aligned unmapped
        // frame instead attempts each get_user, zeroing SP before badframe.
        assert_eq!((info.code, info.fault), (code, Some(address)));
        assert_eq!(cpu.sp, address);
        assert_eq!(
            snapshot.actions.get(11).handler,
            if blocked { 0 } else { action.handler }
        );
        assert_eq!(snapshot.io_signals.mask() & (1 << 10), 0);
    }
}
#[test]
fn original_rseq_notify_waits_for_the_descriptor_page_without_forcing_a_signal() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x2000);
    memory.write_array(0x1008, 0x1ff0u64.to_le_bytes()).unwrap();
    memory.write_array(0x1ff8, 0x4000u64.to_le_bytes()).unwrap();
    page.page.copy_write(0, &0x40u64.to_le_bytes());
    page.page.copy_write(8, &0x4080u64.to_le_bytes());
    memory
        .write_array(0x407c, 0xd428bc00u32.to_le_bytes())
        .unwrap();
    snapshot
        .io_signals
        .rseq
        .call(&mut memory, [0x1000, 32, 0, 0xd428bc00, 0, 0])
        .unwrap();
    snapshot.io_signals.rseq.preempt();
    let mut cpu = Cpu::new(0x4010, 0x40000);
    assert!(snapshot.resume_rseq(&mut cpu, &mut memory, 2).is_err());
    assert_eq!(cpu.pc(), 0x4010);
    assert!(snapshot.io_signals.has_pending_frame());
    assert!(snapshot.io_signals.inbox.peek(11).is_none());
    memory.write_array(0x1008, 0x9000u64.to_le_bytes()).unwrap();
    memory.write_array(0x1ff8, u64::MAX.to_le_bytes()).unwrap();
    page.wait.finish();
    assert_eq!(
        snapshot.resume_io_frame(&mut cpu, &mut memory),
        Ok((None, false))
    );
    assert_eq!(cpu.pc(), 0x4080);
    assert_eq!(memory.read_u64(0x1008).unwrap(), 0);
    assert_eq!(memory.read_array::<4>(0x1004).unwrap(), 2u32.to_le_bytes());
    assert!(snapshot.io_signals.inbox.peek(11).is_none());
    assert!(!snapshot.io_signals.has_pending_frame());
}
#[test]
fn rseq_abort_pc_is_kept_when_later_signal_frame_publication_waits_and_fails() {
    let snapshot = syscall_snapshot();
    let mut memory = memory();
    let page = Deferred::install(&mut memory, 0x3000);
    memory.write_array(0x1008, 0x1100u64.to_le_bytes()).unwrap();
    memory.write_array(0x1108, 0x4000u64.to_le_bytes()).unwrap();
    memory.write_array(0x1110, 0x40u64.to_le_bytes()).unwrap();
    memory.write_array(0x1118, 0x4080u64.to_le_bytes()).unwrap();
    memory
        .write_array(0x407c, 0xd428bc00u32.to_le_bytes())
        .unwrap();
    snapshot
        .io_signals
        .rseq
        .call(&mut memory, [0x1000, 32, 0, 0xd428bc00, 0, 0])
        .unwrap();
    snapshot.actions.set(
        11,
        Action {
            handler: 0x21000,
            ..Default::default()
        },
    );
    let mut cpu = Cpu::new(0x4010, 0x4000);
    assert!(snapshot
        .enter_io_signal(
            &mut cpu,
            &mut memory,
            35,
            Info::default(),
            Action {
                handler: 0x20000,
                ..Default::default()
            }
        )
        .unwrap()
        .is_some());
    assert_eq!(cpu.pc(), 0x4080);
    assert_eq!(cpu.sp(), 0x4000);
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    page.wait.finish();
    assert_eq!(
        snapshot.resume_io_frame(&mut cpu, &mut memory),
        Ok((None, false))
    );
    assert_eq!(cpu.pc(), 0x4080);
    assert_eq!(cpu.sp(), 0x4000);
    assert_eq!(snapshot.io_signals.inbox.peek(11).unwrap().code, 128);
}
