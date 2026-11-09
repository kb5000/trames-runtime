// SPDX-License-Identifier: GPL-3.0-or-later
use super::tests::{kernel, process};
use super::*;
use trames_memory::{Permissions, PAGE_SIZE};

fn words<C: Cpu>(p: &mut Process<C>, at: u64, code: &[u32]) {
    let page = at & !(PAGE_SIZE - 1);
    p.memory.protect(page, PAGE_SIZE, Permissions::RW).unwrap();
    p.memory
        .write(
            at,
            &code
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    p.memory.protect(page, PAGE_SIZE, Permissions::RX).unwrap();
}
fn wait() -> [u32; 7] {
    [
        0xd2860000, 0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001, 0x14000000,
    ]
}
#[test]
fn cross_mm_shared_futex_wake_admits_the_original_dormant_task_without_joining_peers() {
    for (cpus, slots, requeue) in [
        (4, 4, false),
        (12, 12, false),
        (4, 1, false),
        (4, 4, true),
        (12, 12, true),
        (4, 1, true),
    ] {
        let mut k = kernel();
        k.cpu_count = cpus;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; cpus];
        k.profile_syscalls = true;
        let mut root = process();
        root.linux
            .vfs
            .import_file(b"/dormant-futex", vec![0; PAGE_SIZE as usize])
            .unwrap();
        let fd = root
            .linux
            .vfs
            .open_at(-100, b"/dormant-futex", 2, 0)
            .unwrap();
        root.memory.unmap(0x2000, PAGE_SIZE).unwrap();
        root.memory
            .map_backed(
                0x2000,
                root.linux
                    .vfs
                    .mapping_pages(fd, 0, PAGE_SIZE, true, true)
                    .unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let key = root.memory.shared_futex_key(0x2000).unwrap().unwrap();
        let mut producer = Vec::new();
        if requeue {
            producer.extend([
                0xd2840000, 0xd2800061, 0xd2800002, 0xd2800023, 0xd2840084, 0xd2800005, 0xd2800c48,
                0xd4000001, 0xaa0003f4,
            ]);
        }
        producer.extend([
            if requeue { 0xd2840080 } else { 0xd2840000 },
            0xd2800021,
            0xd2800022,
            0xd2800c48,
            0xd4000001,
            0xaa0003f3,
        ]);
        producer.extend(wait());
        words(&mut root, 0x4000, &producer);
        let mut resumed = vec![0xaa0003f3, 0xd2850000, 0xd2800021, 0xb9000001];
        resumed.extend(wait());
        words(&mut root, 0x5000, &resumed);
        words(&mut root, 0x6000, &wait());
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x6000);
        let mut sleeper = root.fork();
        sleeper.vm_id = 3;
        sleeper.tgid = 3;
        sleeper.cpu.set_pc(0x5000);
        let registration = k
            .futexes
            .wait(key, 3, u32::MAX, || Ok::<_, Errno>(()))
            .unwrap();
        sleeper.state = State::Futex {
            wait: registration,
            deadline: None,
        };
        for p in [&root, &peer, &sleeper] {
            p.signals.io.scheduling.set_affinity((1 << slots) - 1);
        }
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        k.processes.insert(3, sleeper);
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        eprintln!("dormant CPUs={cpus} slots={slots} root_x0={} root_x19={} marker={:?} cohorts={} scopes={} returned={:?}", k.processes.read(&1).cpu.x(0),k.processes.read(&1).cpu.x(19),k.processes.read(&3).memory.read_array::<4>(0x2800).unwrap(),k.parallel_rounds,k.vm_checkpoint_spaces,k.cohort_return_syscalls);
        assert_eq!(
            k.processes.read(&3).memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes(),
            "the original cold mm must continue before this cohort drains"
        );
        assert_eq!(k.processes.read(&1).cpu.x(19), 1);
        if requeue {
            assert_eq!(k.processes.read(&1).cpu.x(20), 1);
        }
        assert_eq!(k.processes.read(&3).cpu.x(19), 0);
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.service_requests, 0);
        assert!(
            k.cohort_return_syscalls.is_empty(),
            "{:?}",
            k.cohort_return_syscalls
        );
        assert_eq!(
            k.vm_checkpoint_spaces, 1,
            "only the newly active mm needs a view"
        );
    }
}

#[test]
fn cold_futex_timeout_and_sleep_deadline_resume_on_the_original_queue() {
    for timed_futex in [false, true] {
        let mut k = kernel();
        k.cpu_count = 4;
        k.workers = crate::workers::Pool::new(1);
        k.per_cpu = vec![Duration::ZERO; 4];
        k.profile_syscalls = true;
        let mut root = process();
        words(&mut root, 0x4000, &wait());
        let mut resumed = vec![0xaa0003f3, 0xd2850000, 0xd2800021, 0xb9000001];
        resumed.extend(wait());
        words(&mut root, 0x5000, &resumed);
        let mut sibling_code = vec![0xaa0003f3, 0xd2850080, 0xd2800021, 0xb9000001];
        sibling_code.extend(wait());
        words(&mut root, 0x5100, &sibling_code);
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        let mut cold = root.fork();
        cold.vm_id = 3;
        cold.tgid = 3;
        cold.cpu.set_pc(0x5000);
        let deadline = Instant::now() + Duration::from_millis(100);
        cold.state = if timed_futex {
            State::Futex {
                wait: k
                    .futexes
                    .wait((0, 3, 0x1000), 3, u32::MAX, || Ok::<_, Errno>(()))
                    .unwrap(),
                deadline: Some(deadline),
            }
        } else {
            State::Sleep(deadline, 0)
        };
        let shared = cold.memory.share();
        let mut sibling = cold.fork_with_memory(shared);
        sibling.cpu.set_pc(0x5100);
        sibling.tgid = 4;
        sibling.state = if timed_futex {
            State::Futex {
                wait: k
                    .futexes
                    .wait((0, 3, 0x1000), 4, u32::MAX, || Ok::<_, Errno>(()))
                    .unwrap(),
                deadline: Some(deadline),
            }
        } else {
            State::Sleep(deadline, 0)
        };
        k.processes.insert(4, sibling);
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        k.processes.insert(3, cold);
        assert!(k
            .parallel_epoch(
                &mut trames_linux::CapturedOutput::default(),
                1_000_000,
                true
            )
            .unwrap());
        assert_eq!(
            k.processes.read(&3).memory.read_array::<4>(0x2800).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            k.processes.read(&3).cpu.x(19),
            if timed_futex {
                0u64.wrapping_sub(110)
            } else {
                0
            }
        );
        assert_eq!(
            k.processes.read(&4).memory.read_array::<4>(0x2804).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            k.processes.read(&4).cpu.x(19),
            if timed_futex {
                0u64.wrapping_sub(110)
            } else {
                0
            }
        );
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.vm_checkpoint_spaces, 1);
        assert!(k.cohort_return_syscalls.is_empty());
        if timed_futex {
            assert_eq!(k.futexes.wake((0, 3, 0x1000), 1, u32::MAX), 0);
        }
    }
}
#[test]
fn caught_and_fatal_signals_reach_cold_futex_tasks_without_owner_adoption() {
    for fatal in [false, true] {
        let mut k = kernel();
        k.cpu_count = 4;
        k.workers = crate::workers::Pool::new(1);
        k.per_cpu = vec![Duration::ZERO; 4];
        k.profile_syscalls = true;
        let mut root = process();
        let mut send = vec![
            0xd2800060,
            0xd2800061,
            if fatal { 0xd28001e2 } else { 0xd2800142 },
            0xd2801068,
            0xd4000001,
            0xaa0003f3,
        ];
        send.extend(wait());
        words(&mut root, 0x4000, &send);
        let mut resumed = vec![0xaa0003f3, 0xd2850000, 0xd2800021, 0xb9000001];
        resumed.extend(wait());
        words(&mut root, 0x5000, &resumed);
        words(&mut root, 0x4200, &wait());
        words(
            &mut root,
            0x6000,
            &[
                0xd2850200, 0xd2800041, 0xb9000001, 0xd2801168, 0xd4000001, 0x14000000,
            ],
        );
        let mut peer = root.fork();
        peer.vm_id = 2;
        peer.tgid = 2;
        peer.cpu.set_pc(0x4200);
        let mut cold = root.fork();
        cold.vm_id = 3;
        cold.tgid = 3;
        cold.cpu.set_pc(0x5000);
        cold.signals.actions.set_handler(10, 0x6000);
        cold.state = State::Futex {
            wait: k
                .futexes
                .wait((0, 3, 0x1000), 3, u32::MAX, || Ok::<_, Errno>(()))
                .unwrap(),
            deadline: None,
        };
        k.processes.insert(1, root);
        k.processes.insert(2, peer);
        k.processes.insert(3, cold);
        let original = k.processes.handle(&3).unwrap();
        assert!(k
            .parallel_round(&mut trames_linux::CapturedOutput::default(), 1_000_000)
            .unwrap());
        assert_eq!(k.processes.read(&1).cpu.x(19), 0);
        if fatal {
            assert!(!original.read().signals.io.live());
        } else {
            let cold = original.read();
            assert_eq!(
                cold.memory.read_array::<4>(0x2810).unwrap(),
                2u32.to_le_bytes()
            );
            assert_eq!(
                cold.memory.read_array::<4>(0x2800).unwrap(),
                1u32.to_le_bytes()
            );
            assert_eq!(cold.cpu.x(19), 0u64.wrapping_sub(4));
        }
        assert_eq!(k.futexes.wake((0, 3, 0x1000), 1, u32::MAX), 0);
        assert_eq!(k.parallel_rounds, 1);
        assert_eq!(k.service_requests, 0);
        assert!(
            k.cohort_return_syscalls.is_empty(),
            "{:?}",
            k.cohort_return_syscalls
        );
    }
}
#[test]
fn dormant_cancellation_preserves_original_waits_without_preparing_byte_views() {
    for already_woken in [false, true] {
        let mut k = kernel();
        let mut cold = process();
        cold.vm_id = 3;
        cold.tgid = 3;
        let wait = k
            .futexes
            .wait((0, 3, 0x1000), 3, u32::MAX, || Ok::<_, Errno>(()))
            .unwrap();
        cold.state = State::Futex {
            wait: wait.clone(),
            deadline: None,
        };
        k.processes.insert(1, process());
        k.processes.insert(3, cold);
        k.publish_io_tasks(None);
        let control = Arc::new(crate::workers::Control::new(1000));
        let epoch = crate::run_queue::Epoch::new(control.clone());
        epoch.bind_lifecycle(lifecycle::Lifecycle::capture(&k));
        let identity = k.processes.read(&3).memory.instruction_identity().0;
        let job = k.capture_worker(
            3,
            None,
            &control,
            &mut Default::default(),
            &mut Default::default(),
            &mut Default::default(),
        );
        if already_woken {
            assert_eq!(k.futexes.wake((0, 3, 0x1000), 1, u32::MAX), 1);
        }
        epoch.add_dormant(job, identity);
        assert!(k.processes.read(&3).memory.parallel_views_quiescent());
        assert!(epoch.take_checkpoint().is_none());
        epoch.stop();
        let done = epoch.drain();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].instructions, 0);
        k.adopt_worker_return(done.into_iter().next().unwrap(), true);
        assert!(k.processes.read(&3).memory.parallel_views_quiescent());
        if already_woken {
            assert!(matches!(k.processes.read(&3).state, State::Ready));
        } else {
            assert!(
                matches!(&k.processes.read(&3).state,State::Futex {wait:original,..} if Arc::ptr_eq(original,&wait))
            );
            assert_eq!(k.futexes.wake((0, 3, 0x1000), 1, u32::MAX), 1);
            assert!(k.resume_futex_ready());
        }
        assert_eq!(k.processes.read(&3).cpu.x(0), 0);
        assert!(!k.resume_futex_ready());
    }
}
#[test]
fn cold_task_custody_wait_releases_the_slot_and_wakes_on_its_original_resource() {
    let mut k = kernel();
    let mut root = process();
    words(&mut root, 0x4000, &[0x91000400, 0x17ffffff]);
    let mut cold = root.fork();
    cold.vm_id = 3;
    cold.tgid = 3;
    cold.state = State::Futex {
        wait: k
            .futexes
            .wait((0, 3, 0x1000), 3, u32::MAX, || Ok::<_, Errno>(()))
            .unwrap(),
        deadline: None,
    };
    k.processes.insert(1, root);
    k.processes.insert(3, cold);
    k.publish_io_tasks(None);
    let original = k.processes.handle(&3).unwrap();
    let control = Arc::new(crate::workers::Control::new(1000));
    let epoch = crate::run_queue::Epoch::new(control.clone());
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
    let identity = original.read().memory.instruction_identity().0;
    epoch.add_dormant(
        k.capture_worker(
            3,
            None,
            &control,
            &mut Default::default(),
            &mut Default::default(),
            &mut Default::default(),
        ),
        identity,
    );
    assert!(original.read().memory.parallel_views_quiescent());
    let (held, ready) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let borrowed = original.clone();
    let borrower = std::thread::spawn(move || {
        let _permit = borrowed.try_admit().unwrap();
        held.send(()).unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(2));
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(k.futexes.wake((0, 3, 0x1000), 1, u32::MAX), 1);
    let warm = epoch.take(0).unwrap();
    assert_eq!(
        warm.work.pid, 1,
        "a blocked cold admission cannot consume the only slot"
    );
    assert!(!control.stopped());
    epoch.park(
        warm,
        Some(crate::run_queue::WaitState::Sleep {
            deadline: Instant::now() + Duration::from_secs(60),
            remaining: 0,
        }),
    );
    release.send(()).unwrap();
    borrower.join().unwrap();
    assert!(original.read().memory.parallel_views_quiescent());
    assert!(!k.processes.read(&1).memory.parallel_views_quiescent());
    assert!(
        epoch.take_checkpoint().is_none(),
        "original admission must not become owner work"
    );
    let resumed = epoch.take(0).unwrap();
    assert_eq!(resumed.work.pid, 3);
    assert!(resumed.work.memory.is_some());
    assert_eq!(resumed.work.cpu.x(0), 0);
    epoch.finish(resumed.finish(Some(SliceOutcome::Yield { instructions: 0 }), 0));
    epoch.stop();
    for done in epoch.drain() {
        k.adopt_worker_return(done, true);
    }
    assert!(original.read().memory.parallel_views_quiescent());
    assert!(k.processes.read(&1).memory.parallel_views_quiescent());
}

#[test]
fn enrolled_deadlines_do_not_poll_stale_projections_or_hide_legacy_waits() {
    let mut k = kernel();
    let mut waiting = process();
    waiting.vm_id = 91;
    waiting.state = State::Sleep(Instant::now() - Duration::from_secs(1), 0);
    k.processes.insert(1, waiting);
    k.processes.insert(2, process());
    let owned = std::collections::BTreeSet::from([1]);
    assert_eq!(k.parallel_timeout(), Duration::ZERO);
    assert_eq!(
        k.parallel_timeout_for(Some(&owned)),
        Duration::from_millis(10)
    );
    k.processes.get_mut(&1).unwrap().state = State::Sigwait {
        mask: 0,
        info: 0,
        deadline: Some(Instant::now()),
    };
    assert_eq!(
        k.parallel_timeout_for(Some(&owned)),
        Duration::from_millis(10)
    );
    {
        let mut p = k.processes.get_mut(&1).unwrap();
        let ep = p.linux.vfs.epoll_create(0).unwrap();
        p.linux.vfs.epoll_ctl(ep, 1, 0, 1, 0).unwrap();
        assert!(p.linux.vfs.direct_descriptors().epoll(ep).is_none());
        p.state = State::Blocked(22, [ep as u64, 0x1000, 1, u64::MAX, 0, 0]);
        p.poll_deadline = Some(Instant::now());
    }
    assert_eq!(k.parallel_timeout_for(Some(&owned)), Duration::ZERO);
}

#[test]
fn initially_frozen_cold_futex_preserves_its_wake_until_source_thaw() {
    let mut k = kernel();
    k.cpu_count = 4;
    k.workers = crate::workers::Pool::new(1);
    k.per_cpu = vec![Duration::ZERO; 4];
    k.profile_syscalls = true;
    let mut root = process();
    root.linux.vfs.set_runtime_info(1, Default::default());
    root.linux
        .vfs
        .mkdir_at(-100, b"/sys/fs/cgroup/cold", 0o755)
        .unwrap();
    root.linux.vfs.cgroup_fork(1, 3, 3);
    let procs = root
        .linux
        .vfs
        .open_at(-100, b"/sys/fs/cgroup/cold/cgroup.procs", 1, 0)
        .unwrap();
    root.linux.vfs.write(procs, b"3").unwrap();
    let freeze = root
        .linux
        .vfs
        .open_at(-100, b"/sys/fs/cgroup/cold/cgroup.freeze", 2, 0)
        .unwrap();
    root.linux.vfs.write(freeze, b"1").unwrap();
    root.linux
        .vfs
        .import_file(b"/frozen-futex", vec![0; PAGE_SIZE as usize])
        .unwrap();
    let file = root
        .linux
        .vfs
        .open_at(-100, b"/frozen-futex", 2, 0)
        .unwrap();
    root.memory.unmap(0x2000, PAGE_SIZE).unwrap();
    root.memory
        .map_backed(
            0x2000,
            root.linux
                .vfs
                .mapping_pages(file, 0, PAGE_SIZE, true, true)
                .unwrap(),
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    root.memory
        .write_array(0x3108, 1_000_000u64.to_le_bytes())
        .unwrap();
    root.memory.write(0x3200, b"0").unwrap();
    let mov = |r: u32, n: u32| 0xd2800000 | (n << 5) | r;
    let mut send = vec![
        mov(0, 0x2000),
        mov(1, 1),
        mov(2, 1),
        mov(8, 98),
        0xd4000001,
        0xaa0003f3,
        mov(0, 0x3100),
        mov(1, 0),
        mov(8, 101),
        0xd4000001,
        mov(0, 0x2800),
        0xb9400014,
        mov(0, freeze),
        mov(1, 0x3200),
        mov(2, 1),
        mov(8, 64),
        0xd4000001,
    ];
    send.extend(wait());
    words(&mut root, 0x4000, &send);
    let mut resumed = vec![0xaa0003f3, 0xd2850000, 0xd2800021, 0xb9000001];
    resumed.extend(wait());
    words(&mut root, 0x5000, &resumed);
    words(&mut root, 0x6000, &wait());
    let key = root.memory.shared_futex_key(0x2000).unwrap().unwrap();
    let mut peer = root.fork();
    peer.vm_id = 2;
    peer.tgid = 2;
    peer.cpu.set_pc(0x6000);
    let mut cold = root.fork();
    cold.vm_id = 3;
    cold.tgid = 3;
    cold.cpu.set_pc(0x5000);
    cold.state = State::Futex {
        wait: k
            .futexes
            .wait(key, 3, u32::MAX, || Ok::<_, Errno>(()))
            .unwrap(),
        deadline: None,
    };
    assert!(cold.frozen(3));
    k.processes.insert(1, root);
    k.processes.insert(2, peer);
    k.processes.insert(3, cold);
    assert!(k
        .parallel_epoch(
            &mut trames_linux::CapturedOutput::default(),
            1_000_000,
            true
        )
        .unwrap());
    assert_eq!(k.processes.read(&1).cpu.x(19), 1);
    assert_eq!(
        k.processes.read(&1).cpu.x(20),
        0,
        "no guest instruction may run while frozen"
    );
    assert_eq!(
        k.processes.read(&3).memory.read_array::<4>(0x2800).unwrap(),
        1u32.to_le_bytes()
    );
    assert_eq!(k.processes.read(&3).cpu.x(19), 0);
    assert!(!k.processes.read(&3).frozen(3));
    assert_eq!(k.parallel_rounds, 1);
    assert_eq!(k.service_requests, 0);
    assert_eq!(k.vm_checkpoint_spaces, 1);
    assert!(
        k.cohort_return_syscalls.is_empty(),
        "{:?}",
        k.cohort_return_syscalls
    );
}
