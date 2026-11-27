// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::time::Duration;
use trames_memory::{CpuMemory, Memory, MemoryError, Permissions, PAGE_SIZE};

const BASE: u64 = 0x10000;
fn memory() -> Memory {
    let mut memory = Memory::default();
    memory.map(BASE, PAGE_SIZE, Permissions::RW).unwrap();
    memory
}
fn attr(config: u64, format: u64, disabled: bool) -> Attr {
    Attr {
        config,
        metadata: 0,
        format,
        disabled,
        pinned: false,
        exclusive: false,
        period: 0,
        sample_type: 0,
        wakeup: 0,
        watermark: false,
        sample_id_all: false,
        inherit: false,
        inherit_thread: false,
        enable_on_exec: false,
        remove_on_exec: false,
        frequency: None,
        exclude_user: false,
        exclude_kernel: true,
    }
}
fn words(bytes: Vec<u8>) -> Vec<u64> {
    bytes
        .chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
        .collect()
}

#[test]
fn exec_and_inherited_enable_reactivate_real_fault_producers() {
    let domain = Domain::default();
    let parent = ProcessView::default();
    let child = ProcessView::default();
    let context = Sample {
        ip: 0x1234,
        pid: 1,
        tid: 1,
        time: 1,
        cpu: 0,
    };
    let mut a = attr(2, 0, true);
    a.enable_on_exec = true;
    a.inherit = true;
    let event = Event::new(a, parent.perf_clock(), None).unwrap();
    drop(domain.enter(&parent, None, context));
    assert!(!domain.observing(&parent, 0));
    parent.exec_perf();
    assert!(domain.observing(&parent, 0));
    let mut m = memory();
    let execution = domain.enter(&parent, None, context).unwrap();
    m.write(BASE, &[1]).unwrap();
    drop(execution);
    assert_eq!(words(event.read(8).unwrap()), [1]);

    event.ioctl(0x2401, 0, &mut m).unwrap();
    child.inherit_perf(&parent, false);
    drop(domain.enter(
        &child,
        None,
        Sample {
            pid: 2,
            tid: 2,
            ..context
        },
    ));
    assert!(!domain.observing(&child, 0));
    event.ioctl(0x2400, 0, &mut m).unwrap();
    assert!(domain.observing(&child, 0));
    let mut child_memory = memory();
    let execution = domain
        .enter(
            &child,
            None,
            Sample {
                pid: 2,
                tid: 2,
                ..context
            },
        )
        .unwrap();
    child_memory.write(BASE, &[2]).unwrap();
    drop(execution);
    assert_eq!(words(event.read(8).unwrap()), [2]);
}

#[test]
fn cpu_filter_distinguishes_enabled_task_context_from_running_selected_cpu() {
    let task = ProcessView::default();
    let filtered = task.perf_clock().for_cpu(0);
    let event = Event::new(attr(1, 3, false), filtered, None).unwrap();
    task.account(Duration::from_nanos(17), 1);
    assert_eq!(words(event.read(24).unwrap()), [0, 17, 0]);
    let domain = Domain::default();
    let began = std::time::Instant::now();
    task.begin_accounting(began, 0);
    let execution = domain
        .enter(
            &task,
            None,
            Sample {
                ip: 1,
                pid: 1,
                tid: 1,
                cpu: 0,
                time: 1,
            },
        )
        .unwrap();
    drop(execution);
    task.finish_accounting(began, began.elapsed(), 0);
    let read = words(event.read(24).unwrap());
    assert!(read[0] > 0 && read[1] >= read[2] + 17 && read[2] == read[0]);
}

#[test]
fn a_new_filter_does_not_use_a_cpu_observed_before_collection_stopped() {
    let task = ProcessView::default();
    let domain = Domain::default();
    let context = Sample {
        ip: 1,
        pid: 1,
        tid: 1,
        cpu: 0,
        time: 1,
    };
    let previous = Event::new(attr(1, 0, false), task.perf_clock(), None).unwrap();
    let began = std::time::Instant::now();
    task.begin_accounting(began, 0);
    let execution = domain.enter(&task, None, context).unwrap();
    drop(previous);
    drop(execution);
    task.finish_accounting(began, began.elapsed(), 0);
    assert!(!domain.observing(&task, 0));

    let began = std::time::Instant::now();
    task.begin_accounting(began, 1);
    let event = Event::new(attr(1, 3, false), task.perf_clock().for_cpu(0), None).unwrap();
    let execution = domain
        .enter(&task, None, Sample { cpu: 1, ..context })
        .unwrap();
    let read = words(event.read(24).unwrap());
    assert_eq!(read[0], 0);
    assert_eq!(read[2], 0);
    assert!(read[1] > 0);
    drop(execution);
    task.finish_accounting(began, began.elapsed(), 1);
}

#[test]
fn a_new_cpu_filter_cannot_revive_a_retired_original_task() {
    let task = ProcessView::default();
    let original = task.perf_clock();
    task.retire_perf();
    assert!(matches!(
        Event::new(attr(1, 0, false), original.for_cpu(0), None),
        Err(Errno(3))
    ));
}

#[test]
fn the_session_hint_covers_original_and_inherited_observer_publication() {
    let domain = Domain::default();
    let task = ProcessView::default();
    task.bind_perf_domain(domain.clone());
    assert!(!domain.observed());
    let _ = Event::new(attr(1, 0, true), task.perf_clock(), None).unwrap();
    assert!(domain.observed());

    let inherited_domain = Domain::default();
    let child = ProcessView::default();
    let _ = child.perf_clock();
    assert!(!inherited_domain.observed());
    child.bind_perf_domain(inherited_domain.clone());
    assert!(inherited_domain.observed());
}

#[test]
fn kernel_fault_sample_never_labels_a_guest_user_pc_as_kernel_text() {
    let vfs = Vfs::default();
    let task = ProcessView::default();
    let mut memory = memory();
    let mut a = attr(5, 0, false);
    a.exclude_kernel = false;
    a.exclude_user = true;
    a.period = 1;
    a.sample_type = 1;
    let fd = vfs
        .descriptor_factory()
        .perf_event(a, task.perf_clock(), None, false)
        .unwrap();
    map_ring(&vfs, fd, &mut memory, 1, true);
    task.perf_clock().record(
        5,
        1,
        &Sample {
            ip: 0x4455,
            pid: 1,
            tid: 1,
            cpu: 0,
            time: 1,
        },
        true,
        0,
    );
    let mut record = vec![0; 16];
    memory.read(MAP + PAGE_SIZE, &mut record).unwrap();
    assert_eq!(words(record), [9 | (1u64 << 32) | (16u64 << 48), 0]);
}

#[test]
fn live_counts_disable_reset_and_aliases_keep_one_original_event() {
    let mut v = Vfs::default();
    let source = ProcessView::default();
    let mut m = memory();
    let fd = v
        .descriptor_factory()
        .perf_event(attr(1, 23, true), source.perf_clock(), None, true)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    let alias = v.dup(fd, 0, false).unwrap();
    source.account(Duration::from_nanos(100), 0);
    assert_eq!(words(v.read(fd, 40).unwrap()), [0, 0, 0, event.id(), 0]);
    event.ioctl(0x2400, 0, &mut m).unwrap();
    source.account(Duration::from_nanos(37), 0);
    assert_eq!(
        words(v.read(alias, 40).unwrap()),
        [37, 37, 37, event.id(), 0]
    );
    assert_eq!(v.read(alias, 39), Err(Errno(28)));
    event.ioctl(0x2401, 0, &mut m).unwrap();
    source.account(Duration::from_nanos(100), 0);
    event.ioctl(0x2403, 0, &mut m).unwrap();
    assert_eq!(
        words(v.read(alias, 40).unwrap()),
        [0, 37, 37, event.id(), 0]
    );
    event.ioctl(0x80082407, BASE, &mut m).unwrap();
    assert_eq!(m.read_array::<8>(BASE).unwrap(), event.id().to_le_bytes());
    v.close_exec();
    assert!(matches!(v.read(fd, 40), Err(Errno(9))));
    assert_eq!(words(v.read(alias, 40).unwrap())[0], 0);
}

#[test]
fn group_controls_and_leader_close_preserve_surviving_independent_events() {
    let source = ProcessView::default();
    let mut m = memory();
    let leader = Event::new(attr(1, 31, true), source.perf_clock(), None).unwrap();
    let child = Event::new(attr(0, 31, false), source.perf_clock(), Some(&leader)).unwrap();
    let dummy = Event::new(attr(9, 31, false), source.perf_clock(), Some(&leader)).unwrap();
    source.account(Duration::from_nanos(13), 0);
    assert_eq!(words(leader.read(96).unwrap())[3], 0);
    leader.ioctl(0x2400, 0, &mut m).unwrap();
    source.account(Duration::from_nanos(17), 0);
    assert_eq!(
        words(leader.read(96).unwrap()),
        [
            3,
            17,
            17,
            17,
            leader.id(),
            0,
            17,
            child.id(),
            0,
            0,
            dummy.id(),
            0
        ]
    );
    child.ioctl(0x2403, 1, &mut m).unwrap();
    source.account(Duration::from_nanos(19), 0);
    assert_eq!(words(leader.read(96).unwrap())[3], 19);
    drop(leader);
    assert_eq!(
        words(child.read(48).unwrap()),
        [1, 36, 36, 19, child.id(), 0]
    );
    child.ioctl(0x2401, 1, &mut m).unwrap();
    source.account(Duration::from_nanos(23), 0);
    assert_eq!(words(child.read(48).unwrap())[1], 36);
    assert_eq!(words(dummy.read(48).unwrap())[1], 59);
    let joined = Event::new(attr(1, 8, false), source.perf_clock(), Some(&child)).unwrap();
    child.ioctl(0x2400, 1, &mut m).unwrap();
    source.account(Duration::from_nanos(29), 0);
    assert_eq!(words(joined.read(24).unwrap()), [2, 48, 29]);
}

#[test]
fn clock_retention_does_not_retain_the_process_image_or_its_files() {
    let mut v = Vfs::default();
    let mut m = memory();
    let source = Arc::new(ProcessView::default());
    let weak = Arc::downgrade(&source);
    let fd = v
        .descriptor_factory()
        .perf_event(attr(1, 0, false), source.perf_clock(), None, false)
        .unwrap();
    let accepted = v.perf_event(fd).unwrap().unwrap();
    source.account(Duration::from_nanos(7), 0);
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(1, Arc::downgrade(&wake));
    let _subscription = accepted.subscribe(&signal);
    source.retire_perf();
    assert!(signal.ready());
    assert_eq!(accepted.poll(0).0, 16);
    source.account(Duration::from_nanos(99), 0);
    assert_eq!(words(v.read(fd, 8).unwrap()), [7]);
    drop(source);
    assert!(weak.upgrade().is_none());
    v.close(fd).unwrap();
    let replacement = ProcessView::default();
    let new = v
        .descriptor_factory()
        .perf_event(attr(1, 0, false), replacement.perf_clock(), None, false)
        .unwrap();
    assert_eq!(new, fd);
    replacement.account(Duration::from_nanos(101), 0);
    accepted.ioctl(0x2403, 0, &mut m).unwrap();
    assert_eq!(words(v.read(new, 8).unwrap()), [101]);
    assert_eq!(words(accepted.read(8).unwrap()), [0]);
}

#[test]
fn attr_negotiation_preserves_faults_and_rejects_unconnected_producers() {
    let mut m = memory();
    let write_attr = |m: &mut Memory, size: u32| {
        m.write(BASE, &[0; 144]).unwrap();
        m.write_array(BASE, 1u32.to_le_bytes()).unwrap();
        m.write_array(BASE + 4, size.to_le_bytes()).unwrap();
        m.write_array(BASE + 8, 1u64.to_le_bytes()).unwrap();
    };
    write_attr(&mut m, 0);
    assert!(Attr::read(&mut m, BASE).is_ok());
    write_attr(&mut m, 63);
    assert!(matches!(Attr::read(&mut m, BASE), Err(Errno(7))));
    assert_eq!(m.read_array::<4>(BASE + 4).unwrap(), 136u32.to_le_bytes());
    write_attr(&mut m, 144);
    assert!(Attr::read(&mut m, BASE).is_ok());
    m.write_array(BASE + 136, [1]).unwrap();
    assert!(matches!(Attr::read(&mut m, BASE), Err(Errno(7))));
    write_attr(&mut m, 136);
    m.write_array(BASE + 16, 99u64.to_le_bytes()).unwrap();
    assert!(Attr::read(&mut m, BASE).is_ok());
    m.write_array(BASE + 24, (1u64 << 5).to_le_bytes()).unwrap();
    assert!(matches!(Attr::read(&mut m, BASE), Err(Errno(95))));
    write_attr(&mut m, 136);
    m.write_array(BASE + 40, 1u64.wrapping_shl(63).to_le_bytes())
        .unwrap();
    assert!(matches!(Attr::read(&mut m, BASE), Err(Errno(22))));
    assert!(matches!(
        Attr::read(&mut m, BASE + PAGE_SIZE - 4),
        Err(Errno(14))
    ));
}

const MAP: u64 = 0x40000;
fn tick(source: &ProcessView, ip: u64) {
    source.account(Duration::from_nanos(10_000), 0);
    source.sample_perf(|_| Sample {
        ip,
        pid: 101,
        tid: 102,
        cpu: 0,
        time: 70000,
    });
}
fn map_ring(vfs: &Vfs, fd: u32, memory: &mut Memory, data_pages: u64, writable: bool) {
    let len = (data_pages + 1) * PAGE_SIZE;
    let pages = vfs
        .mapping_file(fd)
        .unwrap()
        .pages_for_memory(0, len, true, writable, memory)
        .unwrap();
    memory
        .map_backed(
            MAP,
            pages,
            true,
            if writable {
                Permissions::RW
            } else {
                Permissions::R
            },
            false,
        )
        .unwrap();
}

#[test]
fn sampling_publishes_the_abi_and_keeps_the_original_mapped_event_after_fd_close() {
    let mut v = Vfs::default();
    let source = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 0, false);
    a.period = 10_000;
    a.wakeup = 1;
    a.sample_type = 1 | 2 | 4 | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 16);
    let fd = v
        .descriptor_factory()
        .perf_event(a, source.perf_clock(), None, false)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    assert_eq!(event.poll(1).0, 16, "an unmapped perf FD reports HUP");
    map_ring(&v, fd, &mut m, 1, true);
    assert_eq!(event.poll(1).0, 0);
    assert_eq!(
        u64::from_le_bytes(m.read_array(MAP + 1040).unwrap()),
        PAGE_SIZE
    );
    assert_eq!(
        u64::from_le_bytes(m.read_array(MAP + 1048).unwrap()),
        PAGE_SIZE
    );
    tick(&source, 0x12345678);
    assert_eq!(u64::from_le_bytes(m.read_array(MAP + 1024).unwrap()), 64);
    let mut record = vec![0; 64];
    m.read(MAP + PAGE_SIZE, &mut record).unwrap();
    assert_eq!(
        words(record),
        [
            9 | (2u64 << 32) | (64u64 << 48),
            event.id(),
            0x12345678,
            101 | (102u64 << 32),
            70000,
            event.id(),
            0,
            10000
        ]
    );
    assert_eq!(event.peek(1).0, 1);
    assert_eq!(event.peek(1).0, 1);
    assert_eq!(event.poll(1).0, 1);
    assert_eq!(event.poll(1).0, 0);
    m.write_array(MAP + 1032, 64u64.to_le_bytes()).unwrap();
    v.close(fd).unwrap();
    drop(event);
    tick(&source, 0x87654321);
    assert_eq!(u64::from_le_bytes(m.read_array(MAP + 1024).unwrap()), 128);
    assert_eq!(
        u64::from_le_bytes(m.read_array(MAP + PAGE_SIZE + 80).unwrap()),
        0x87654321
    );
}

#[test]
fn full_forward_ring_reports_loss_and_wraps_without_overwriting_unread_samples() {
    let mut v = Vfs::default();
    let source = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 16, false);
    a.period = 10_000;
    a.sample_type = 1;
    let fd = v
        .descriptor_factory()
        .perf_event(a, source.perf_clock(), None, false)
        .unwrap();
    map_ring(&v, fd, &mut m, 1, true);
    for ip in 0..256 {
        tick(&source, ip);
    }
    assert_eq!(u64::from_le_bytes(m.read_array(MAP + 1024).unwrap()), 4080);
    assert_eq!(words(v.read(fd, 16).unwrap()), [2_560_000, 1]);
    m.write_array(MAP + 1032, 4080u64.to_le_bytes()).unwrap();
    tick(&source, 256);
    assert_eq!(u64::from_le_bytes(m.read_array(MAP + 1024).unwrap()), 4120);
    let mut record = vec![0; 24];
    m.read(MAP + PAGE_SIZE + 4080, &mut record[..16]).unwrap();
    m.read(MAP + PAGE_SIZE, &mut record[16..]).unwrap();
    let id = v.perf_event(fd).unwrap().unwrap().id();
    assert_eq!(words(record), [2 | (24u64 << 48), id, 1]);
    assert_eq!(
        u64::from_le_bytes(m.read_array(MAP + PAGE_SIZE + 16).unwrap()),
        256
    );
    assert_eq!(words(v.read(fd, 16).unwrap())[1], 1);
}

#[test]
fn refresh_pause_and_rearm_use_existing_readiness_and_preserve_total_counts() {
    let mut v = Vfs::default();
    let source = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 16, true);
    a.period = 10_000;
    a.sample_type = 1;
    let fd = v
        .descriptor_factory()
        .perf_event(a, source.perf_clock(), None, false)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    map_ring(&v, fd, &mut m, 1, true);
    event.ioctl(0x2402, 2, &mut m).unwrap();
    event.ioctl(0x40042409, 1, &mut m).unwrap();
    tick(&source, 1);
    assert_eq!(u64::from_le_bytes(m.read_array(MAP + 1024).unwrap()), 0);
    assert_eq!(words(v.read(fd, 16).unwrap()), [10000, 1]);
    event.ioctl(0x40042409, 0, &mut m).unwrap();
    tick(&source, 2);
    assert_eq!(event.poll(1).0 & 16, 16);
    let stopped_head = m.read_array::<8>(MAP + 1024).unwrap();
    tick(&source, 3);
    assert_eq!(m.read_array::<8>(MAP + 1024).unwrap(), stopped_head);
    assert_eq!(words(v.read(fd, 16).unwrap())[0], 20000);
    event.ioctl(0x2402, 1, &mut m).unwrap();
    tick(&source, 4);
    assert_eq!(words(v.read(fd, 16).unwrap())[0], 30000);
    event.ioctl(0x2400, 0, &mut m).unwrap();
    tick(&source, 5);
    tick(&source, 6);
    assert_eq!(words(v.read(fd, 16).unwrap())[0], 50000);
}

#[test]
fn data_page_stores_fault_in_cpu_native_worker_and_hardware_paths_and_fork_excludes_the_ring() {
    let v = Vfs::default();
    let source = ProcessView::default();
    let mut m = memory();
    let fd = v
        .descriptor_factory()
        .perf_event(attr(1, 0, false), source.perf_clock(), None, false)
        .unwrap();
    map_ring(&v, fd, &mut m, 1, true);
    let data = MAP + PAGE_SIZE;
    assert_eq!(m.read_array::<1>(data), Ok([0])); // prime read translation
    assert_eq!(m.write_array(data, [1]), Err(MemoryError::Bus(data)));
    assert!(matches!(m.with_write_chunk(data, 1, |_| ()), Err(MemoryError::Bus(a)) if a == data));
    let mut view = m
        .parallel_view(&mut trames_memory::parallel::Registry::default())
        .unwrap();
    view.read_array::<1>(data).unwrap();
    assert_eq!(view.write_array(data, [1]), Err(MemoryError::Bus(data)));
    view.enable_hardware();
    let info = view.hardware_page_info(data).unwrap();
    assert_eq!(info.permissions, Permissions::RW);
    assert!(!info.writable);
    assert!(matches!(view.hardware_write_frame(data), Err(MemoryError::Bus(a)) if a == data));
    drop(view);
    m.commit_parallel().unwrap();
    m.write_array(MAP + 1032, [0u8; 8]).unwrap();
    let child = m.try_fork().unwrap();
    assert!(matches!(child.read_array::<1>(data), Err(MemoryError::Unmapped(a)) if a == data));
}

#[test]
fn pinned_ring_admission_uses_the_environment_uid_and_original_mm_and_retries_live_limits() {
    let v = Vfs {
        credentials: Credentials::user(1000, 1000),
        ..Vfs::default()
    };
    let source = ProcessView::default();
    let mut m = memory();
    let factory = v.descriptor_factory();
    v.memory_resource_limits().set(8, 0);
    let first = factory
        .perf_event(attr(1, 0, false), source.perf_clock(), None, false)
        .unwrap();
    map_ring(&v, first, &mut m, 128, true);
    v.memory_resource_limits().set(8, 64 * 1024);
    let second = factory
        .perf_event(attr(1, 0, false), source.perf_clock(), None, false)
        .unwrap();
    let file = v.mapping_file(second).unwrap();
    assert!(matches!(
        file.pages_for_memory(0, 129 * PAGE_SIZE, true, true, &m),
        Err(Errno(1))
    ));
    v.memory_resource_limits().set(8, 1024 * 1024);
    let pages = file
        .pages_for_memory(0, 129 * PAGE_SIZE, true, true, &m)
        .unwrap();
    drop(pages);
    // Failed admission and a temporary successful map both return their quota.
    m.unmap(MAP, 129 * PAGE_SIZE).unwrap();
    v.memory_resource_limits().set(8, 64 * 1024);
    assert!(file
        .pages_for_memory(0, 129 * PAGE_SIZE, true, true, &m)
        .is_ok());
}

#[test]
fn final_release_does_not_reenter_a_counter_group_and_closed_leaders_detach_at_their_close_time() {
    let source = ProcessView::default();
    let leader = Event::new(attr(1, 0, true), source.perf_clock(), None).unwrap();
    let child = Event::new(attr(1, 8, false), source.perf_clock(), Some(&leader)).unwrap();
    source.account(Duration::from_nanos(11), 0);
    let group = leader.group.clone();
    let guard = group.lock();
    let (sender, receiver) = std::sync::mpsc::channel();
    let done = std::thread::spawn(move || {
        drop(leader);
        let _ = sender.send(());
    });
    // Always release before joining, even if the regression times out. A bad
    // destructor then produces a bounded failure instead of hanging the suite.
    let released = receiver.recv_timeout(Duration::from_secs(1));
    drop(guard);
    done.join().unwrap();
    assert!(
        released.is_ok(),
        "last Event tried to reacquire its original group"
    );
    source.account(Duration::from_nanos(13), 0);
    // No read/control is needed to turn this surviving member into a leader.
    let joined = Event::new(attr(1, 0, false), source.perf_clock(), Some(&child)).unwrap();
    assert_eq!(words(child.read(24).unwrap()), [2, 13, 0]);
    drop(joined);
}

#[test]
fn retained_view_keeps_the_original_mapping_until_its_actual_last_actor_releases_it() {
    let mut v = Vfs::default();
    let source = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 0, false);
    a.period = 10000;
    a.sample_type = 1;
    a.wakeup = 1;
    let fd = v
        .descriptor_factory()
        .perf_event(a, source.perf_clock(), None, false)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    map_ring(&v, fd, &mut m, 1, true);
    let mut registry = trames_memory::parallel::Registry::default();
    let view = m.parallel_view(&mut registry).unwrap();
    m.unmap(MAP, 2 * PAGE_SIZE).unwrap();
    v.close(fd).unwrap();
    tick(&source, 7);
    assert_eq!(u64::from_le_bytes(view.read_array(MAP + 1024).unwrap()), 16);
    assert_eq!(event.peek(1).0, 1);
    drop(view);
    // Refresh the frozen generation after its actors join, removing old leases.
    drop(m.parallel_view(&mut registry).unwrap());
    assert_eq!(event.peek(1).0, 16);
}

#[test]
fn redirected_samples_keep_the_source_identity_and_unmap_revokes_all_attachments() {
    let v = Vfs::default();
    let task = ProcessView::default();
    let mut m = memory();
    let factory = v.descriptor_factory();
    let sink_fd = factory
        .perf_event(attr(9, 0, false), task.perf_clock(), None, false)
        .unwrap();
    let sink = v.perf_event(sink_fd).unwrap().unwrap();
    let mut a = attr(1, 0, false);
    a.period = 10000;
    a.sample_type = 1 | (1 << 6);
    a.wakeup = 1;
    let source_fd = factory
        .perf_event(a, task.perf_clock(), None, false)
        .unwrap();
    let source = v.perf_event(source_fd).unwrap().unwrap();
    assert_eq!(source.set_output(Some(&sink)), Err(Errno(22)));
    map_ring(&v, sink_fd, &mut m, 1, true);
    source.set_output(Some(&sink)).unwrap();
    let observer = sink.output.capture().unwrap();
    assert!(matches!(
        v.mapping_file(source_fd)
            .unwrap()
            .pages_for_memory(0, 2 * PAGE_SIZE, true, true, &m),
        Err(Errno(16))
    ));
    assert_eq!(
        sink.set_output(None),
        Err(Errno(22)),
        "an own mmap cannot be redirected"
    );
    let other = Event::new(attr(1, 0, false), ProcessView::default().perf_clock(), None).unwrap();
    assert_eq!(other.set_output(Some(&sink)), Err(Errno(22)));
    tick(&task, 0x4455);
    let mut record = vec![0; 24];
    m.read(MAP + PAGE_SIZE, &mut record).unwrap();
    assert_eq!(
        words(record),
        [9 | (2u64 << 32) | (24u64 << 48), 0x4455, source.id()]
    );
    assert_eq!(
        u64::from_le_bytes(m.read_array(MAP + 16).unwrap()),
        0,
        "only the ring owner publishes its count"
    );
    assert_eq!(source.poll(1).0, 1);
    assert_eq!(sink.poll(1).0, 0, "buffer poll state is shared");
    m.unmap(MAP, 2 * PAGE_SIZE).unwrap();
    assert_eq!(source.peek(1).0, 16);
    assert!(!observer.mapped());
    assert_eq!(other.set_output(Some(&sink)), Err(Errno(22)));
    map_ring(&v, sink_fd, &mut m, 1, true);
    assert_eq!(
        source.peek(1).0,
        16,
        "old associations do not follow a future buffer"
    );
    source.set_output(Some(&sink)).unwrap();
    drop(observer);
    assert_eq!(source.peek(1).0, 0);
    source.set_output(None).unwrap();
    assert_eq!(source.peek(1).0, 16);
}

#[test]
fn a_zero_wakeup_count_uses_the_buffers_byte_watermark() {
    let v = Vfs::default();
    let task = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 0, false);
    a.period = 10000;
    a.sample_type = 1;
    let fd = v
        .descriptor_factory()
        .perf_event(a, task.perf_clock(), None, false)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    map_ring(&v, fd, &mut m, 1, true);
    for ip in 0..128 {
        tick(&task, ip);
    }
    assert_eq!(event.peek(1).0, 0);
    tick(&task, 128);
    assert_eq!(event.poll(1).0, 1);
}

#[test]
fn exec_enable_is_one_shot_and_removal_freezes_values_without_reusing_the_target() {
    let task = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 0, true);
    a.enable_on_exec = true;
    let enabled = Event::new(a, task.perf_clock(), None).unwrap();
    let mut a = attr(1, 0, false);
    a.remove_on_exec = true;
    let removed = Event::new(a, task.perf_clock(), None).unwrap();
    let sibling = Event::new(attr(1, 8, false), task.perf_clock(), Some(&removed)).unwrap();
    task.account(Duration::from_nanos(7), 0);
    task.exec_perf();
    task.account(Duration::from_nanos(11), 0);
    assert_eq!(words(enabled.read(8).unwrap()), [11]);
    assert_eq!(words(removed.read(8).unwrap()), [7]);
    assert_eq!(removed.peek(1).0, 16);
    assert_eq!(words(sibling.read(16).unwrap()), [1, 18]);
    removed.ioctl(0x2400, 0, &mut m).unwrap();
    enabled.ioctl(0x2401, 0, &mut m).unwrap();
    task.exec_perf();
    task.account(Duration::from_nanos(13), 0);
    assert_eq!(words(enabled.read(8).unwrap()), [11]);
    assert_eq!(words(removed.read(8).unwrap()), [7]);
}

#[test]
fn descendants_are_counted_live_controlled_at_their_original_clocks_and_retired_once() {
    let parent = ProcessView::default();
    let child = ProcessView::default();
    let grandchild = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 3, false);
    a.inherit = true;
    let event = Event::new(a, parent.perf_clock(), None).unwrap();
    child.inherit_perf(&parent, false);
    grandchild.inherit_perf(&child, false);
    parent.account(Duration::from_nanos(3), 0);
    child.account(Duration::from_nanos(5), 0);
    grandchild.account(Duration::from_nanos(7), 0);
    assert_eq!(words(event.read(24).unwrap()), [15, 15, 15]);
    event.ioctl(0x2401, 0, &mut m).unwrap();
    parent.account(Duration::from_nanos(11), 0);
    child.account(Duration::from_nanos(13), 0);
    grandchild.account(Duration::from_nanos(17), 0);
    assert_eq!(words(event.read(24).unwrap()), [15, 15, 15]);
    event.ioctl(0x2403, 0, &mut m).unwrap();
    event.ioctl(0x2400, 0, &mut m).unwrap();
    parent.account(Duration::from_nanos(19), 0);
    child.account(Duration::from_nanos(23), 0);
    grandchild.account(Duration::from_nanos(29), 0);
    assert_eq!(words(event.read(24).unwrap()), [71, 86, 86]);
    parent.retire_perf();
    child.retire_perf();
    grandchild.retire_perf();
    assert_eq!(words(event.read(24).unwrap()), [71, 86, 86]);
    child.account(Duration::from_nanos(31), 0);
    drop(child);
    drop(grandchild);
    assert_eq!(words(event.read(24).unwrap()), [71, 86, 86]);
}

#[test]
fn thread_only_inheritance_and_child_exec_keep_the_original_event_family() {
    let parent = ProcessView::default();
    let fork = ProcessView::default();
    let thread = ProcessView::default();
    let mut a = attr(1, 0, true);
    a.inherit = true;
    a.inherit_thread = true;
    a.enable_on_exec = true;
    let event = Event::new(a, parent.perf_clock(), None).unwrap();
    fork.inherit_perf(&parent, false);
    thread.inherit_perf(&parent, true);
    fork.exec_perf();
    thread.exec_perf();
    fork.account(Duration::from_nanos(101), 0);
    thread.account(Duration::from_nanos(17), 0);
    parent.account(Duration::from_nanos(11), 0);
    assert_eq!(words(event.read(8).unwrap()), [17]);
    parent.exec_perf();
    parent.account(Duration::from_nanos(13), 0);
    assert_eq!(words(event.read(8).unwrap()), [30]);
    thread.retire_perf();
    assert_eq!(words(event.read(8).unwrap()), [30]);
}

#[test]
fn inherited_samples_use_primary_ids_and_distinct_stream_ids_in_the_accepted_ring() {
    let v = Vfs::default();
    let parent = ProcessView::default();
    let child = ProcessView::default();
    let mut m = memory();
    let factory = v.descriptor_factory();
    let sink_fd = factory
        .perf_event(attr(9, 0, false), parent.perf_clock(), None, false)
        .unwrap();
    let sink = v.perf_event(sink_fd).unwrap().unwrap();
    map_ring(&v, sink_fd, &mut m, 1, true);
    let mut a = attr(1, 0, false);
    a.inherit = true;
    a.period = 10000;
    a.sample_type = (1 << 6) | (1 << 9);
    a.wakeup = 1;
    let fd = factory
        .perf_event_configured(a, parent.perf_clock(), None, Some(&sink), false, 1)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    assert!(matches!(
        v.mapping_file(fd)
            .unwrap()
            .pages_for_memory(0, 2 * PAGE_SIZE, true, true, &m),
        Err(Errno(22))
    ));
    assert_eq!(event.ioctl(0x2402, 1, &mut m), Err(Errno(22)));
    child.inherit_perf(&parent, false);
    tick(&child, 0x1234);
    let mut bytes = vec![0; 24];
    m.read(MAP + PAGE_SIZE, &mut bytes).unwrap();
    let record = words(bytes);
    assert_eq!(record[1], event.id());
    assert_ne!(record[2], event.id());
    assert_eq!(u64::from_le_bytes(m.read_array(MAP + 1024).unwrap()), 24);
    assert_eq!(words(event.read(8).unwrap()), [10000]);
}

#[test]
fn live_perf_policy_controls_new_event_and_map_admission_and_frequency_ioctl() {
    let mut v = Vfs::default();
    let settings = v.perf_settings();
    let mut credentials = Credentials::user(1000, 1000);
    credentials.user_namespace = v.credentials.user_namespace.clone();
    v.credentials = credentials;
    v.memory_resource_limits().set(8, 0);
    let task = ProcessView::default();
    let mut m = memory();
    let mut a = attr(1, 0, false);
    a.exclude_kernel = false;
    assert_eq!(v.descriptor_factory().check_perf_attr(&a), Err(Errno(13)));
    settings.set(Setting::Paranoid, 1).unwrap();
    assert_eq!(v.descriptor_factory().check_perf_attr(&a), Ok(()));
    a.exclude_kernel = true;
    a.frequency = Some(100001);
    a.period = 9999;
    assert_eq!(v.descriptor_factory().check_perf_attr(&a), Err(Errno(22)));
    settings.set(Setting::MaxSampleRate, 200000).unwrap();
    let fd = v
        .descriptor_factory()
        .perf_event(a, task.perf_clock(), None, false)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    settings.set(Setting::MlockKb, 0).unwrap();
    let file = v.mapping_file(fd).unwrap();
    assert!(matches!(
        file.pages_for_memory(0, 2 * PAGE_SIZE, true, true, &m),
        Err(Errno(1))
    ));
    settings.set(Setting::Paranoid, -1).unwrap();
    let pages = file
        .pages_for_memory(0, 2 * PAGE_SIZE, true, true, &m)
        .unwrap();
    drop(pages);
    settings.set(Setting::MaxSampleRate, 1000).unwrap();
    m.write_array(BASE, 1001u64.to_le_bytes()).unwrap();
    assert_eq!(event.ioctl(0x40082404, BASE, &mut m), Ok(0));
    m.write_array(BASE, 500u64.to_le_bytes()).unwrap();
    event.ioctl(0x40082404, BASE, &mut m).unwrap();
    let group = event.group.lock();
    assert_eq!(group.members[&event.id()].attr.period, 500);
    assert_eq!(group.members[&event.id()].remaining, 10_000);
}

#[test]
fn ring_mapping_growth_and_zero_size_remap_fail_without_losing_the_original_buffer() {
    let v = Vfs::default();
    let task = ProcessView::default();
    let mut m = memory();
    let fd = v
        .descriptor_factory()
        .perf_event(attr(1, 0, false), task.perf_clock(), None, false)
        .unwrap();
    let event = v.perf_event(fd).unwrap().unwrap();
    map_ring(&v, fd, &mut m, 1, true);
    m.protect(MAP + PAGE_SIZE, PAGE_SIZE, Permissions::RW)
        .unwrap();
    assert_eq!(
        m.protect(MAP + PAGE_SIZE, PAGE_SIZE, Permissions::R),
        Err(MemoryError::InvalidRange)
    );
    let len = 2 * PAGE_SIZE;
    assert_eq!(
        m.remap(MAP, len, MAP, len + PAGE_SIZE, false),
        Err(MemoryError::BackingIo(14))
    );
    assert_eq!(
        m.alias_shared_mapping(MAP, MAP + 0x10000, len),
        Err(MemoryError::BackingIo(14))
    );
    assert_eq!(event.peek(1).0, 0);
    m.remap(MAP, len, MAP + 0x10000, len, false).unwrap();
    assert!(matches!(
        m.read_array::<1>(MAP),
        Err(MemoryError::Unmapped(_))
    ));
    assert_eq!(
        m.read_array::<8>(MAP + 0x10000 + 1040).unwrap(),
        PAGE_SIZE.to_le_bytes()
    );
    assert_eq!(event.peek(1).0, 0);
}
