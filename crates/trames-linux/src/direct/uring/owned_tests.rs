// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::uring::tests::{add, cq, setup, sqe};
use trames_memory::{Memory, MemoryError, Permissions, PAGE_SIZE};
use trames_vfs::{URING_CQES, URING_SQ_ARRAY};
struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn target() -> Arc<dyn IoWake> {
    Arc::new(Target)
}
fn start(s: &UringSnapshot, fd: u32, n: u32, min: u32, m: &mut impl CpuMemory) -> IoAttempt {
    s.start(
        [fd as u64, n as u64, min as u64, u64::from(min != 0), 0, 0],
        m,
        s.task,
        &Arc::downgrade(&target()),
    )
    .unwrap()
}
fn complete(a: IoAttempt, n: u64) {
    assert!(matches!(a,IoAttempt::Complete(Ok(v)) if v==n));
}
fn data(op: u8, fd: u32, address: u64, len: u32, id: u64, flags: u8) -> [u8; 64] {
    let mut s = sqe(op, fd, id);
    s[1] = flags;
    s[16..24].copy_from_slice(&address.to_le_bytes());
    s[24..28].copy_from_slice(&len.to_le_bytes());
    s
}
fn register_buffers(l: &mut Linux, m: &mut Memory, fd: u32, address: u64, len: u64) {
    m.write_array(0x1100, address.to_le_bytes()).unwrap();
    m.write_array(0x1108, len.to_le_bytes()).unwrap();
    l.uring_register([fd as u64, 0, 0x1100, 1, 0, 0], m)
        .unwrap();
}
fn register_files(l: &mut Linux, m: &mut Memory, fd: u32, files: &[i32]) {
    for (i, file) in files.iter().enumerate() {
        m.write_array(0x1200 + i as u64 * 4, file.to_le_bytes())
            .unwrap();
    }
    l.uring_register([fd as u64, 2, 0x1200, files.len() as u64, 0, 0], m)
        .unwrap();
}
#[derive(Default)]
struct SignalQueue {
    queue: std::sync::Mutex<std::collections::VecDeque<[u8; 128]>>,
    ready: Arc<trames_vfs::Readiness>,
}
impl trames_vfs::SignalReader for SignalQueue {
    fn poll(&self, mask: u64) -> (u16, [u64; 2]) {
        (
            u16::from(mask & (1 << 9) != 0 && !self.queue.lock().unwrap().is_empty()),
            [0; 2],
        )
    }
    fn take(&self, mask: u64) -> Option<[u8; 128]> {
        if mask & (1 << 9) == 0 {
            None
        } else {
            self.queue.lock().unwrap().pop_front()
        }
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<trames_vfs::IoSubscription> {
        vec![self.ready.subscribe(signal)]
    }
}
#[test]
fn solo_accepted_signalfd_keeps_original_reader_across_foreign_capture_and_source_pump() {
    for op in [22, 1, 4, 6] {
        for cancel in [false, true] {
            let (mut l, mut m, fd, ring) = setup(8);
            let original = Arc::new(SignalQueue::default());
            let original_lifetime = Arc::downgrade(&original);
            let observer = Arc::new(SignalQueue::default());
            l.vfs.bind_signal_reader(original.clone());
            let signal = l.vfs.signalfd(-1, 1 << 9, 0).unwrap();
            register_files(&mut l, &mut m, fd, &[signal as i32]);
            let mut entry = match op {
                1 => {
                    m.write_array(0x2000, 0x3000u64.to_le_bytes()).unwrap();
                    m.write_array(0x2008, 128u64.to_le_bytes()).unwrap();
                    data(op, 0, 0x2000, 1, 121, 1)
                }
                6 => {
                    let mut entry = sqe(6, 0, 121);
                    entry[1] = 1;
                    entry[28..32].copy_from_slice(&1u32.to_le_bytes());
                    entry
                }
                _ => data(op, 0, 0x3000, 128, 121, 1),
            };
            if op == 4 {
                register_buffers(&mut l, &mut m, fd, 0x3000, 128);
                entry[40..42].copy_from_slice(&0u16.to_le_bytes());
            }
            m.write(0x3000, &[0xa5; 128]).unwrap();
            add(&mut m, &ring, entry);
            assert_eq!(
                l.uring_enter([fd as u64, 1, 0, 0, 0, 0], &mut m, None, 7),
                Ok((1, true))
            );
            assert_eq!(
                ring.state.lock().unwrap().pending.len(),
                1,
                "solo import must retain signal authority: op={op}"
            );
            l.vfs.close(signal).unwrap();
            assert_eq!(l.vfs.eventfd(93, 0).unwrap(), signal);
            l.vfs.bind_signal_reader(observer.clone());
            let mut epoch = UringEpoch::default();
            // Foreign CQ observation cannot donate another task's reader.
            let _foreign = epoch
                .capture(&l.vfs, m.instruction_identity().0, 8)
                .with_actor(l.uring_actor_root());
            let d = DirectSyscalls::new(l.vfs.direct_descriptors())
                .with_paths(l.vfs.path_queries())
                .with_resources(l.vfs.descriptor_factory())
                .with_signal_reader(observer.clone())
                .with_urings(
                    epoch
                        .capture(&l.vfs, m.instruction_identity().0, 7)
                        .with_actor(l.uring_actor_root()),
                );
            let t = target();
            let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
            assert!(background.progress(&mut m).unwrap());
            assert!(background.active());
            let mut wrong = [0; 128];
            wrong[..4].copy_from_slice(&10u32.to_le_bytes());
            wrong[8..12].copy_from_slice(&99u32.to_le_bytes());
            observer.queue.lock().unwrap().push_back(wrong);
            observer.ready.notify_atomic();
            assert!(
                !background.signal.ready(),
                "an observer cannot wake original signal I/O"
            );
            if cancel {
                d.cancel_task_uring(m.instruction_identity().0, 7);
                assert!(background.progress(&mut m).unwrap());
                assert_eq!(cq(&mut m, &ring), (121, -125));
                assert_eq!(m.read_array::<128>(0x3000).unwrap(), [0xa5; 128]);
            } else {
                let mut right = [0; 128];
                right[..4].copy_from_slice(&10u32.to_le_bytes());
                right[8..12].copy_from_slice(&41u32.to_le_bytes());
                original.queue.lock().unwrap().push_back(right);
                original.ready.notify_atomic();
                assert!(background.signal.ready());
                assert!(background.progress(&mut m).unwrap());
                assert_eq!(cq(&mut m, &ring), (121, if op == 6 { 1 } else { 128 }));
                if op != 6 {
                    assert_eq!(m.read_array::<128>(0x3000).unwrap(), right);
                }
            }
            assert_eq!(observer.queue.lock().unwrap().len(), 1);
            // Later SQEs use their own submitter, not a permanent reader stored
            // on the signalfd or ring. Its fixed OFD mask is still the same one.
            entry[32..40].copy_from_slice(&122u64.to_le_bytes());
            add(&mut m, &ring, entry);
            assert!(matches!(
                d.start(
                    426,
                    [fd as u64, 1, 1, 1, 0, 0],
                    &mut m,
                    7,
                    &Arc::downgrade(&t),
                    None
                ),
                Some(IoAttempt::Complete(Ok(1)))
            ));
            assert_eq!(cq(&mut m, &ring), (122, if op == 6 { 1 } else { 128 }));
            if op != 6 {
                assert_eq!(m.read_array::<128>(0x3000).unwrap(), wrong);
            }
            drop(original);
            assert!(
                original_lifetime.upgrade().is_none(),
                "completed/cancelled requests release the original reader"
            );
        }
    }
}
#[test]
fn foreign_capture_leaves_legacy_requests_unbound_until_the_original_submitter_admits_them() {
    let (mut l, mut m, _fd, ring) = setup(8);
    let original = Arc::new(SignalQueue::default());
    let observer = Arc::new(SignalQueue::default());
    l.vfs.bind_signal_reader(original.clone());
    let signal = l.vfs.signalfd(-1, 1 << 9, 0).unwrap();
    let entry = data(22, signal, 0x3000, 128, 123, 0);
    {
        let mut state = ring.state.lock().unwrap();
        state.next += 1;
        let request = crate::uring::import_request(
            UringSqe(entry),
            state.next,
            &state,
            &m,
            7,
            None,
            l.uring_clock,
            |fd| Some(l.vfs.retain_uring_file(fd)),
        )
        .unwrap();
        assert!(request.resource.is_none() && request.execution.is_none());
        state.pending.push_back(request);
    }
    l.track_uring(&ring);
    l.vfs.bind_signal_reader(observer);
    let mut epoch = UringEpoch::default();
    let _foreign = epoch
        .capture(&l.vfs, m.instruction_identity().0, 8)
        .with_actor(l.uring_actor_root());
    {
        let state = ring.state.lock().unwrap();
        assert!(state.pending[0].resource.is_none());
        assert!(state.pending[0].execution.is_none());
    }
    l.vfs.bind_signal_reader(original.clone());
    let d = DirectSyscalls::new(l.vfs.direct_descriptors())
        .with_paths(l.vfs.path_queries())
        .with_resources(l.vfs.descriptor_factory())
        .with_urings(
            epoch
                .capture(&l.vfs, m.instruction_identity().0, 7)
                .with_actor(l.uring_actor_root()),
        );
    let t = target();
    let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
    assert!(background.progress(&mut m).unwrap());
    let mut record = [0; 128];
    record[..4].copy_from_slice(&10u32.to_le_bytes());
    original.queue.lock().unwrap().push_back(record);
    original.ready.notify_atomic();
    assert!(background.signal.ready());
    assert!(background.progress(&mut m).unwrap());
    assert_eq!(cq(&mut m, &ring), (123, 128));
    assert_eq!(m.read_array::<128>(0x3000).unwrap(), record);
}
#[test]
fn proc_image_reads_use_original_mm_for_fixed_fds_vectors_and_registered_buffers() {
    use std::sync::atomic::Ordering;
    use trames_vfs::{ProcRefresh, ProcSource, ProcTask, ProcessInfo, ProcessView, RuntimeInfo};
    struct Task {
        view: Weak<ProcessView>,
        identity: u64,
    }
    impl ProcTask for Task {
        fn identity(&self) -> u64 {
            self.identity
        }
        fn pid(&self) -> u32 {
            7
        }
        fn observe(&self, demand: ProcRefresh, residency: Option<usize>) -> Option<ProcessInfo> {
            self.view
                .upgrade()?
                .observe_with_residency(demand, residency)
        }
        fn memory_report(&self) -> Option<trames_memory::MemoryReport> {
            self.view.upgrade()?.memory_report()
        }
    }
    struct Source(Arc<Task>);
    impl ProcSource for Source {
        fn observe(&self, query: trames_vfs::ProcQuery<'_>) -> RuntimeInfo {
            RuntimeInfo {
                processes: self.0.observe(query.demand, None).into_iter().collect(),
                ..Default::default()
            }
        }
        fn task(&self, pid: u32) -> Option<Arc<dyn ProcTask>> {
            (pid == 7).then(|| self.0.clone() as Arc<dyn ProcTask>)
        }
    }
    for title in [false, true] {
        for same_mm in [false, true] {
            for op in [22, 1, 4] {
                for offset in [0u64, 2] {
                    let (mut l, mut m, ring_fd, ring) = setup(8);
                    let mut remote = Memory::default();
                    remote.map(0x1000, PAGE_SIZE * 4, Permissions::RW).unwrap();
                    let image = if same_mm { &mut m } else { &mut remote };
                    image.write(0x3ff8, b"cmd\0A=1\0B=2\0").unwrap();
                    if title {
                        image.write(0x3ff8, b"changed-title\0").unwrap();
                    }
                    image.set_image_ranges(trames_memory::ImageRanges {
                        arguments: (0x3ff8, 0x3ffc),
                        environment: (0x3ffc, 0x4004),
                    });
                    let report = image.memory_report();
                    let activations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let count = activations.clone();
                    report.bind_read_waker(Arc::new(move |_| {
                        count.fetch_add(1, Ordering::Relaxed);
                    }));
                    let process = Arc::new(ProcessView::default());
                    process.publish_with_memory(
                        &ProcessInfo {
                            pid: 7,
                            tgid: 7,
                            ..Default::default()
                        },
                        l.vfs.proc_resources(),
                        Some(report),
                    );
                    l.vfs.set_proc_source(Arc::new(Source(Arc::new(Task {
                        identity: process.identity(),
                        view: Arc::downgrade(&process),
                    }))));
                    let path = if title {
                        b"/proc/7/cmdline".as_slice()
                    } else {
                        b"/proc/7/environ".as_slice()
                    };
                    let file = l
                        .vfs
                        .path_queries()
                        .open_at_resolve(-100, path, 0, 0, 0, &trames_vfs::DirectFiles::default())
                        .unwrap()
                        .unwrap();
                    let alias = l.vfs.dup(file, 32, false).unwrap();
                    register_files(&mut l, &mut m, ring_fd, &[file as i32]);
                    let mut entry = if op == 1 {
                        for (at, value) in [
                            (0x2000, 0x3000u64),
                            (0x2008, 3),
                            (0x2010, 0x3100),
                            (0x2018, 5),
                        ] {
                            m.write_array(at, value.to_le_bytes()).unwrap();
                        }
                        data(op, 0, 0x2000, 2, 91, 1)
                    } else {
                        data(op, 0, 0x3000, 8, 91, 1)
                    };
                    if op == 4 {
                        register_buffers(&mut l, &mut m, ring_fd, 0x3000, 8);
                    }
                    entry[8..16].copy_from_slice(&offset.to_le_bytes());
                    l.vfs.close(file).unwrap();
                    assert_eq!(l.vfs.eventfd(1, 0).unwrap(), file);
                    add(&mut m, &ring, entry);
                    let mut epoch = UringEpoch::default();
                    let snapshot = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
                    snapshot.ensure_context(
                        Some(&l.vfs.path_queries()),
                        Some(&l.vfs.descriptor_factory()),
                        &trames_vfs::DirectFiles::default(),
                        None,
                        None,
                        None,
                    );
                    let mut attempt = start(&snapshot, ring_fd, 1, 1, &mut m);
                    let mut rounds = 0;
                    loop {
                        match attempt {
                            IoAttempt::Complete(value) => {
                                assert_eq!(value, Ok(1));
                                break;
                            }
                            IoAttempt::Blocked(wait) => {
                                assert!(!same_mm, "caller-mm bytes need no activation");
                                rounds += 1;
                                assert!(
                                    rounds <= if title { 2 } else { 1 },
                                    "one wake per newly discovered dependency batch"
                                );
                                assert!(remote.activate_proc_reads());
                                assert!(wait.signal.ready());
                                attempt = snapshot.resume(wait, &mut m);
                            }
                            _ => panic!("complete proc read must not require the owner"),
                        }
                    }
                    assert_eq!(
                        activations.load(Ordering::Relaxed),
                        if same_mm {
                            0
                        } else if title {
                            2
                        } else {
                            1
                        }
                    );
                    let expected = if title {
                        &b"changed-title\0"[offset as usize..offset as usize + 8]
                    } else {
                        &b"A=1\0B=2\0"[offset as usize..]
                    };
                    assert_eq!(cq(&mut m, &ring), (91, expected.len() as i32));
                    let actual = if op == 1 {
                        let mut bytes = vec![0; expected.len()];
                        m.read(0x3000, &mut bytes[..3]).unwrap();
                        m.read(0x3100, &mut bytes[3..]).unwrap();
                        bytes
                    } else {
                        let mut bytes = vec![0; expected.len()];
                        m.read(0x3000, &mut bytes).unwrap();
                        bytes
                    };
                    assert_eq!(actual, expected);
                    assert_eq!(
                        l.vfs.seek(alias, 0, 1),
                        Ok(0),
                        "positioned reads preserve f_pos"
                    );
                    assert!(epoch.finish().is_empty());
                }
            }
        }
    }
}
#[test]
fn signalfd_uring_read_vector_fixed_and_poll_keep_submitter_and_original_ofd() {
    for op in [22, 1, 4, 6] {
        let (mut l, mut m, fd, r) = setup(8);
        let queue = Arc::new(SignalQueue::default());
        l.vfs.bind_signal_reader(queue.clone());
        let signal = l.vfs.signalfd(-1, 1 << 9, 0).unwrap();
        register_files(&mut l, &mut m, fd, &[signal as i32]);
        let mut pin = None;
        let mut entry = if op == 1 {
            m.write_array(0x2000, 0x3000u64.to_le_bytes()).unwrap();
            m.write_array(0x2008, 128u64.to_le_bytes()).unwrap();
            data(op, 0, 0x2000, 1, 9, 1)
        } else if op == 6 {
            let mut e = sqe(6, 0, 9);
            e[1] = 1;
            e[28..32].copy_from_slice(&1u32.to_le_bytes());
            e
        } else {
            data(op, 0, 0x3000, 128, 9, 1)
        };
        if op == 4 {
            register_buffers(&mut l, &mut m, fd, 0x3000, 128);
            pin = Some(r.state.lock().unwrap().buffers.as_ref().unwrap()[0].clone());
            entry[40..42].copy_from_slice(&0u16.to_le_bytes());
        }
        l.vfs.close(signal).unwrap();
        assert_eq!(l.vfs.eventfd(1, 0).unwrap(), signal);
        add(&mut m, &r, entry);
        let mut epoch = UringEpoch::default();
        let snapshot = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let IoAttempt::Blocked(wait) = start(&snapshot, fd, 1, 1, &mut m) else {
            panic!("signalfd operation {op} must park")
        };
        assert!(!wait.signal.ready());
        if op == 4 {
            m.unmap(0x3000, PAGE_SIZE).unwrap();
            m.map(0x3000, PAGE_SIZE, Permissions::RW).unwrap();
            m.write_array(0x3000, 55u32.to_le_bytes()).unwrap();
        }
        let mut record = [0; 128];
        record[..4].copy_from_slice(&10u32.to_le_bytes());
        queue.queue.lock().unwrap().push_back(record);
        queue.ready.notify_atomic();
        assert!(wait.signal.ready());
        complete(snapshot.resume(wait, &mut m), 1);
        assert_eq!(cq(&mut m, &r), (9, if op == 6 { 1 } else { 128 }));
        if let Some(pin) = pin {
            assert_eq!(&pin.read(0, 4).unwrap(), &10u32.to_le_bytes());
            assert_eq!(m.read_array::<4>(0x3000).unwrap(), 55u32.to_le_bytes());
        } else if op != 6 {
            assert_eq!(m.read_array::<4>(0x3000).unwrap(), 10u32.to_le_bytes());
        }
        assert!(epoch.finish().is_empty());
    }
}
#[test]
fn numeric_shared_uring_caches_do_not_retain_closed_files_or_pipe_endpoints() {
    let (mut l, m, fd, _r) = setup(8);
    l.vfs.import_file(b"/original", b"abc".to_vec()).unwrap();
    let file = l.vfs.open_at(-100, b"/original", 2, 0).unwrap();
    let close = Arc::downgrade(
        &l.vfs
            .retain_uring_fd(file)
            .unwrap()
            .close_notification()
            .unwrap(),
    );
    let notify = l.vfs.inotify_init(trames_vfs::O_NONBLOCK).unwrap();
    l.vfs.inotify_add(notify, b"/", 8).unwrap();
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let snapshot = epoch.capture_with_files(&l.vfs, m.instruction_identity().0, 7, &caps);
    assert!(snapshot.contains(fd));
    l.vfs.unlink_at(-100, b"/original", false).unwrap();
    let membership = l.vfs.shared_files();
    std::thread::spawn(move || {
        membership.close(file, 1).unwrap().unwrap();
        membership.close(reader, 1).unwrap().unwrap();
    })
    .join()
    .unwrap();
    assert!(close.upgrade().is_none());
    assert_eq!(l.vfs.allocated_bytes(), 0);
    assert_eq!(l.vfs.write(writer, b"x"), Err(Errno(32)));
    let event = l.vfs.read(notify, 1024).unwrap();
    assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
    assert_eq!(l.vfs.read(notify, 1024), Err(Errno(11)));
    assert!(epoch.finish().is_empty());
    files.finish();
}
#[test]
fn shared_sqe_acceptance_resolves_new_file_aliases_replacement_and_missing_slots() {
    let (mut l, mut m, fd, r) = setup(8);
    l.vfs.import_file(b"/original", b"old".to_vec()).unwrap();
    l.vfs.import_file(b"/other", b"new".to_vec()).unwrap();
    let file = l.vfs.open_at(-100, b"/original", 2, 0).unwrap();
    let other = l.vfs.open_at(-100, b"/other", 2, 0).unwrap();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let snapshot = epoch.capture_with_files(&l.vfs, m.instruction_identity().0, 7, &caps);
    let membership = l.vfs.shared_files();
    let alias = membership.duplicate(file, 200, false).unwrap().unwrap();
    membership.duplicate_to(other, file, 0, 1).unwrap().unwrap();
    add(&mut m, &r, data(22, alias, 0x2000, 3, 1, 0));
    add(&mut m, &r, data(22, file, 0x2100, 3, 2, 0));
    complete(start(&snapshot, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (1, 3));
    assert_eq!(cq(&mut m, &r), (2, 3));
    assert_eq!(m.read_array::<3>(0x2000).unwrap(), *b"old");
    assert_eq!(m.read_array::<3>(0x2100).unwrap(), *b"new");
    membership.close(alias, 1).unwrap().unwrap();
    add(&mut m, &r, data(22, alias, 0x2000, 3, 3, 0));
    complete(start(&snapshot, fd, 1, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (3, -9));
    assert!(epoch.finish().is_empty());
    files.finish();
}
#[test]
fn shared_pending_pipe_keeps_original_across_handoff_and_releases_at_completion() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let [new_reader, new_writer] = l.vfs.pipe(0).unwrap();
    let owner = m.instruction_identity().0;
    let mut epoch = UringEpoch::default();
    let snapshot = epoch.capture(&l.vfs, owner, 7);
    add(&mut m, &r, data(22, reader, 0x2000, 1, 1, 0));
    let IoAttempt::Blocked(wait) = start(&snapshot, fd, 1, 1, &mut m) else {
        panic!("pipe wait")
    };
    l.vfs
        .shared_files()
        .duplicate_to(new_reader, reader, 0, 1)
        .unwrap()
        .unwrap();
    l.vfs.write(new_writer, b"new").unwrap();
    drop(wait);
    drop(snapshot);
    let handoff = epoch.finish();
    assert!(handoff.is_empty());
    assert_eq!(r.state.lock().unwrap().waits[&7].0, 1);
    let mut epoch = UringEpoch::default();
    let snapshot = epoch.capture(&l.vfs, owner, 7);
    assert!(epoch.adopt_wait(7, &r, 1, None));
    l.vfs.write(writer, b"o").unwrap();
    complete(start(&snapshot, fd, 0, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (1, 1));
    assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"o");
    assert_eq!(l.vfs.write(writer, b"x"), Err(Errno(32))); // before epoch.finish
    assert_eq!(l.vfs.read(reader, 3).unwrap(), b"new");
    assert!(epoch.finish().is_empty());
}
struct CloseWake {
    ring: Weak<Ring>,
    calls: std::sync::atomic::AtomicUsize,
}
impl IoWake for CloseWake {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        let ring = self.ring.upgrade().unwrap();
        // Synchronous resource notifications can re-enter the ring. Check
        // without blocking so a regression fails instead of hanging the suite.
        let guard = ring
            .state
            .try_lock()
            .expect("final close callback outside ring lock");
        drop(guard);
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}
#[test]
fn accepted_shared_file_releases_at_completion_or_cancel_after_handoff_and_reuse() {
    for cancel in [false, true] {
        let (mut l, mut m, fd, r) = setup(8);
        l.vfs.import_file(b"/original", b"old".to_vec()).unwrap();
        l.vfs.import_file(b"/other", b"new".to_vec()).unwrap();
        let file = l.vfs.open_at(-100, b"/original", 2, 0).unwrap();
        let other = l.vfs.open_at(-100, b"/other", 2, 0).unwrap();
        let close = Arc::downgrade(
            &l.vfs
                .retain_uring_fd(file)
                .unwrap()
                .close_notification()
                .unwrap(),
        );
        let notify = l.vfs.inotify_init(trames_vfs::O_NONBLOCK).unwrap();
        l.vfs.inotify_add(notify, b"/", 8).unwrap();
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        let owner = m.instruction_identity().0;
        let mut files = trames_vfs::FileEpoch::default();
        let caps = files.capture(&l.vfs, true);
        let mut epoch = UringEpoch::default();
        let snapshot = epoch.capture_with_files(&l.vfs, owner, 7, &caps);
        add(&mut m, &r, data(22, reader, 0x2200, 1, 10, 4));
        add(&mut m, &r, data(22, file, 0x2000, 3, 11, 0));
        complete(start(&snapshot, fd, 2, 0, &mut m), 2);
        l.vfs.unlink_at(-100, b"/original", false).unwrap();
        l.vfs
            .shared_files()
            .duplicate_to(other, file, 0, 1)
            .unwrap()
            .unwrap();
        assert!(close.upgrade().is_some());
        assert_eq!(l.vfs.read(notify, 1024), Err(Errno(11)));
        drop(snapshot);
        assert!(epoch.finish().is_empty());
        files.finish();
        let mut files = trames_vfs::FileEpoch::default();
        let caps = files.capture(&l.vfs, true);
        let retained = files.capture_uring(&l.vfs, true);
        let mut epoch = UringEpoch::default();
        let snapshot = epoch.capture_all(&l.vfs, owner, 7, &caps, &retained);
        let wake = Arc::new(CloseWake {
            ring: Arc::downgrade(&snapshot.rings[&fd]),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        let callback: Arc<dyn IoWake> = wake.clone();
        let signal = IoSignal::new(99, Arc::downgrade(&callback));
        let subscriptions = l
            .vfs
            .direct_descriptors()
            .get(notify)
            .unwrap()
            .subscribe(&signal);
        if cancel {
            add(&mut m, &r, data(14, 0, 11, 0, 12, 0));
            complete(start(&snapshot, fd, 1, 0, &mut m), 1);
            assert_eq!(cq(&mut m, &r), (11, -125));
            assert_eq!(cq(&mut m, &r), (12, 0));
        } else {
            l.vfs.write(writer, b"o").unwrap();
            complete(start(&snapshot, fd, 0, 0, &mut m), 0);
            assert_eq!(cq(&mut m, &r), (10, 1));
            assert_eq!(cq(&mut m, &r), (11, 3));
            assert_eq!(m.read_array::<3>(0x2000).unwrap(), *b"old");
        }
        assert!(close.upgrade().is_none()); // no completed/cancelled owner pin
        assert_eq!(wake.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(signal.ready());
        drop(subscriptions);
        let event = l.vfs.read(notify, 1024).unwrap();
        assert_eq!(u32::from_le_bytes(event[4..8].try_into().unwrap()), 8);
        assert_eq!(l.vfs.pread(file, 3, 0).unwrap(), b"new");
        epoch.finish();
        files.finish();
    }
}
#[test]
fn fixed_request_keeps_pin_and_ofd_across_unmap_unregister_and_epoch_handoff() {
    let (mut l, mut m, fd, r) = setup(8);
    let owner = m.instruction_identity().0;
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    register_buffers(&mut l, &mut m, fd, 0x3ffe, 4);
    let pin = r.state.lock().unwrap().buffers.as_ref().unwrap()[0].clone();
    register_files(&mut l, &mut m, fd, &[reader as i32]);
    l.vfs.close(reader).unwrap();
    let [replacement, _] = l.vfs.pipe(0).unwrap();
    assert_eq!(reader, replacement);
    m.protect(0x3000, PAGE_SIZE * 2, Permissions::R).unwrap();
    m.unmap(0x3000, PAGE_SIZE * 2).unwrap();
    m.map(0x3000, PAGE_SIZE * 2, Permissions::RW).unwrap();
    m.write(0x3ffe, b"xxxx").unwrap();
    add(&mut m, &r, data(4, 0, 0x3ffe, 4, 1, 1));
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, owner, 7);
    let IoAttempt::Blocked(wait) = start(&s, fd, 1, 1, &mut m) else {
        panic!("expected fixed read wait")
    };
    drop(wait);
    drop(s);
    assert!(epoch.finish().is_empty());
    assert_eq!(r.state.lock().unwrap().waits[&7].0, 1);
    l.uring_register([fd as u64, 1, 0, 0, 0, 0], &mut m)
        .unwrap();
    l.uring_register([fd as u64, 3, 0, 0, 0, 0], &mut m)
        .unwrap();
    l.vfs.write(writer, b"new!").unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, owner, 7);
    assert!(epoch.adopt_wait(7, &r, 1, None));
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (1, 4));
    assert_eq!(pin.read(0, 4).unwrap(), b"new!");
    assert_eq!(m.read_array::<4>(0x3ffe).unwrap(), *b"xxxx");
    drop(s);
    assert!(epoch.finish().is_empty());
    let resident = m.resident_bytes();
    drop(pin);
    assert_eq!(resident - m.resident_bytes(), PAGE_SIZE as usize * 2);
}
#[test]
fn fixed_buffer_cross_vm_uses_registered_bytes_and_shared_page_guards() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    register_buffers(&mut l, &mut m, fd, 0x3000, 8);
    m.write_array(0x3000, 3u64.to_le_bytes()).unwrap();
    let mut child = m.clone();
    child.write_array(0x3000, 9u64.to_le_bytes()).unwrap();
    add(&mut child, &r, data(5, writer, 0x3000, 8, 2, 0));
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, child.instruction_identity().0, 8);
    let mut view = child.parallel_view(&mut Default::default()).unwrap();
    complete(start(&s, fd, 1, 1, &mut view), 1);
    drop(view);
    assert_eq!(cq(&mut child, &r), (2, 8));
    assert_eq!(l.vfs.read(reader, 8).unwrap(), 3u64.to_le_bytes());
    l.vfs.write(writer, &11u64.to_le_bytes()).unwrap();
    add(&mut child, &r, data(4, reader, 0x3000, 8, 3, 0));
    let mut view = child.parallel_view(&mut Default::default()).unwrap();
    complete(start(&s, fd, 1, 1, &mut view), 1);
    drop(view);
    assert_eq!(cq(&mut child, &r), (3, 8));
    assert_eq!(m.read_u64(0x3000).unwrap(), 11);
    assert_eq!(child.read_u64(0x3000).unwrap(), 9);
    assert!(epoch.finish().is_empty());
}
#[test]
fn fixed_sparse_and_bad_indexes_complete_errors_without_disabling_ring() {
    let (mut l, mut m, fd, r) = setup(8);
    register_files(&mut l, &mut m, fd, &[-1]);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    add(&mut m, &r, data(22, 0, 0x2000, 1, 4, 1 | 4));
    add(&mut m, &r, sqe(0, 0, 5));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (4, -9));
    assert_eq!(cq(&mut m, &r), (5, -125));
    add(&mut m, &r, data(22, 50000, 0x2000, 1, 6, 1 | 8));
    add(&mut m, &r, sqe(0, 0, 7));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (6, -9));
    assert_eq!(cq(&mut m, &r), (7, 0));
    let [reader, _] = l.vfs.pipe(0).unwrap();
    drop(s);
    assert!(epoch.finish().is_empty());
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    add(&mut m, &r, data(4, reader, 0x2000, 1, 8, 0));
    complete(start(&s, fd, 1, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (8, -14));
    assert!(epoch.finish().is_empty());
}
#[test]
fn linked_short_vector_uses_uncapped_requested_length_and_hardlink_continues() {
    let (mut l, mut m, fd, r) = setup(8);
    let length = crate::MAX_WRITE;
    l.vfs
        .import_file(b"/large", vec![b'a'; length + 1])
        .unwrap();
    let file = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/large", 2, 0)
        .unwrap();
    m.map(0x100000, (length as u64) + PAGE_SIZE, Permissions::RW)
        .unwrap();
    m.write_array(0x1100, 0x100000u64.to_le_bytes()).unwrap();
    m.write_array(0x1108, (length as u64 + 1).to_le_bytes())
        .unwrap();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture_with_files(&l.vfs, m.instruction_identity().0, 7, &caps);
    add(&mut m, &r, data(1, file, 0x1100, 1, 9, 4));
    add(&mut m, &r, sqe(0, 0, 10));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (9, length as i32));
    assert_eq!(cq(&mut m, &r), (10, -125));
    assert_eq!(
        m.read_array::<1>(0x100000 + length as u64 - 1).unwrap(),
        [b'a']
    );
    assert_eq!(m.read_array::<1>(0x100000 + length as u64).unwrap(), [0]);
    add(&mut m, &r, data(22, file, u64::MAX, 1, 11, 8));
    add(&mut m, &r, sqe(0, 0, 12));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (11, -14));
    assert_eq!(cq(&mut m, &r), (12, 0));
    assert!(epoch.finish().is_empty());
    files.finish();
}
#[test]
fn linked_eagain_and_drain_survive_owner_handoff_without_early_effects() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let owner = m.instruction_identity().0;
    add(&mut m, &r, data(22, reader, 0x2000, 1, 13, 4));
    add(&mut m, &r, sqe(0, 0, 14));
    let mut drain = sqe(0, 0, 15);
    drain[1] = 2;
    add(&mut m, &r, drain);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, owner, 7);
    complete(start(&s, fd, 3, 0, &mut m), 3);
    drop(s);
    let handoff = epoch.finish();
    assert!(handoff.is_empty());
    assert!(!r.state.lock().unwrap().waits.contains_key(&7));
    assert_eq!(r.state.lock().unwrap().pending.len(), 3);
    assert_eq!(
        r.state
            .lock()
            .unwrap()
            .pending
            .iter()
            .find(|r| r.sequence == 2)
            .unwrap()
            .dependency,
        Some((1, false))
    );
    assert!(
        !r.state
            .lock()
            .unwrap()
            .pending
            .iter()
            .find(|r| r.sequence == 2)
            .unwrap()
            .started
    );
    l.vfs.write(writer, b"l").unwrap();
    assert_eq!(
        l.uring_enter([fd as u64, 0, 3, 1, 0, 0], &mut m, None, 7),
        Ok((0, true))
    );
    assert_eq!(cq(&mut m, &r), (13, 1));
    assert_eq!(cq(&mut m, &r), (14, 0));
    assert_eq!(cq(&mut m, &r), (15, 0));
}
#[test]
fn retained_regular_fixed_file_keeps_original_data_permissions_and_position() {
    let (mut l, mut m, fd, r) = setup(8);
    l.vfs.import_file(b"/original", b"abc".to_vec()).unwrap();
    let file = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/original", 2, 0)
        .unwrap();
    register_files(&mut l, &mut m, fd, &[file as i32]);
    l.vfs.close(file).unwrap();
    let replacement = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/replacement", 0x42, 0o600)
        .unwrap();
    assert_eq!(replacement, file);
    l.vfs.write(replacement, b"xyz").unwrap();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let retained = files.capture_uring(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let s = epoch.capture_all(&l.vfs, m.instruction_identity().0, 7, &caps, &retained);
    let mut request = data(22, 0, 0x2000, 1, 16, 1 | 4);
    request[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    add(&mut m, &r, request);
    add(&mut m, &r, data(23, 0, 0x2000, 1, 17, 1));
    complete(start(&s, fd, 2, 2, &mut m), 2);
    assert_eq!(cq(&mut m, &r), (16, 1));
    assert_eq!(cq(&mut m, &r), (17, 1));
    assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"a");
    assert!(epoch.finish().is_empty());
    files.finish();
    assert_eq!(l.vfs.pread(replacement, 3, 0).unwrap(), b"xyz");
    let source = l
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/original", 0, 0)
        .unwrap();
    assert_eq!(l.vfs.read(source, 3).unwrap(), b"abc");
}

#[test]
fn ring_fd_aliases_share_one_fixed_table_per_task_and_execute_same_queue() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    register_files(&mut l, &mut m, fd, &[reader as i32]);
    l.vfs.close(reader).unwrap();
    let alias = l.vfs.dup(fd, 0, false).unwrap();
    let second = l.vfs.dup(alias, 0, false).unwrap();
    let owner = m.instruction_identity().0;
    let mut epoch = UringEpoch::default();
    let a = epoch.capture(&l.vfs, owner, 7);
    let b = epoch.capture(&l.vfs, owner, 8);
    assert!(Arc::ptr_eq(&a.rings[&fd], &a.rings[&alias]));
    assert!(Arc::ptr_eq(&a.rings[&alias], &a.rings[&second]));
    assert!(Arc::ptr_eq(&a.rings[&fd], &b.rings[&fd]));
    assert!(r.state.lock().unwrap().files.as_ref().unwrap()[0]
        .as_ref()
        .unwrap()
        .shared_file()
        .is_some());
    l.vfs.write(writer, b"q").unwrap();
    add(&mut m, &r, data(22, 0, 0x2000, 1, 22, 1));
    complete(start(&a, alias, 1, 1, &mut m), 1);
    assert_eq!(cq(&mut m, &r), (22, 1));
    assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"q");
    assert!(epoch.finish().is_empty());
}

/// A real transfer pauses during gather, after claiming its request. Only the
/// test transport waits; production still uses the unmodified memory model.
struct Gate<M> {
    inner: M,
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
    once: Cell<bool>,
}
impl<M: CpuMemory> CpuMemory for Gate<M> {
    fn read(&self, a: u64, b: &mut [u8]) -> std::result::Result<(), MemoryError> {
        if a == 0x2100 && !self.once.replace(true) {
            self.entered.send(()).unwrap();
            self.release.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        self.inner.read(a, b)
    }
    fn write(&mut self, a: u64, b: &[u8]) -> std::result::Result<(), MemoryError> {
        if a == 0x2200 && !self.once.replace(true) {
            self.entered.send(()).unwrap();
            self.release.recv_timeout(Duration::from_secs(2)).unwrap();
        }
        self.inner.write(a, b)
    }
    fn check(&self, a: u64, n: usize, x: Access) -> std::result::Result<(), MemoryError> {
        self.inner.check(a, n, x)
    }
    fn check_translation(&self, a: u64) -> std::result::Result<(), MemoryError> {
        self.inner.check_translation(a)
    }
    fn fetch_u32(&self, a: u64) -> std::result::Result<u32, MemoryError> {
        self.inner.fetch_u32(a)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.inner.instruction_identity()
    }
    fn instruction_page_identity(
        &self,
        a: u64,
    ) -> std::result::Result<(u64, u64, u64), MemoryError> {
        self.inner.instruction_page_identity(a)
    }
    fn atomic_update<T>(
        &mut self,
        a: u64,
        n: usize,
        f: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> std::result::Result<T, MemoryError> {
        self.inner.atomic_update(a, n, f)
    }
    fn exclusive_read(&mut self, a: u64, b: &mut [u8]) -> std::result::Result<u128, MemoryError> {
        self.inner.exclusive_read(a, b)
    }
    fn exclusive_write(
        &mut self,
        a: u64,
        b: &[u8],
        t: Option<u128>,
    ) -> std::result::Result<bool, MemoryError> {
        self.inner.exclusive_write(a, b, t)
    }
}
fn add_view(m: &mut impl CpuMemory, r: &Uring, s: [u8; 64]) {
    let tail = u32::from_le_bytes(m.read_array(0x10004).unwrap());
    let slot = tail & (r.entries - 1);
    m.write_array(0x20000 + slot as u64 * 64, s).unwrap();
    m.write_array(
        0x10000 + URING_SQ_ARRAY as u64 + slot as u64 * 4,
        slot.to_le_bytes(),
    )
    .unwrap();
    m.write_array(0x10004, tail.wrapping_add(1).to_le_bytes())
        .unwrap();
}
fn cq_view(m: &mut impl CpuMemory, r: &Uring) -> (u64, i32) {
    let head = u32::from_le_bytes(m.read_array(0x10040).unwrap());
    let b = m
        .read_array::<16>(0x10000 + URING_CQES as u64 + (head & (r.cq_entries - 1)) as u64 * 16)
        .unwrap();
    m.write_array(0x10040, head.wrapping_add(1).to_le_bytes())
        .unwrap();
    (
        u64::from_le_bytes(b[..8].try_into().unwrap()),
        i32::from_le_bytes(b[8..12].try_into().unwrap()),
    )
}
#[test]
fn concurrent_drain_waits_for_claimed_io_but_unrelated_work_uses_same_ring() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    m.write(0x2100, b"z").unwrap();
    let owner = m.instruction_identity().0;
    add(&mut m, &r, data(23, writer, 0x2100, 1, 18, 0));
    let mut epoch = UringEpoch::default();
    let a = epoch.capture(&l.vfs, owner, 7);
    let b = epoch.capture(&l.vfs, owner, 8);
    let va = m.parallel_view(&mut Default::default()).unwrap();
    let mut vb = m.parallel_view(&mut Default::default()).unwrap();
    let (entered, receive) = std::sync::mpsc::sync_channel(1);
    let (release, blocked) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let job = scope.spawn(move || {
            let mut memory = Gate {
                inner: va,
                entered,
                release: blocked,
                once: Cell::new(false),
            };
            complete(start(&a, fd, 1, 0, &mut memory), 1);
        });
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(b.rings[&fd].state.lock().unwrap().inflight, 1);
        add_view(&mut vb, &r, sqe(0, 0, 19));
        let mut drain = sqe(0, 0, 20);
        drain[1] = 2;
        add_view(&mut vb, &r, drain);
        add_view(&mut vb, &r, sqe(0, 0, 21));
        complete(start(&b, fd, 3, 0, &mut vb), 3);
        assert_eq!(cq_view(&mut vb, &r), (19, 0));
        assert_eq!(
            vb.read_array::<4>(0x10040).unwrap(),
            vb.read_array::<4>(0x10044).unwrap()
        );
        release.send(()).unwrap();
        job.join().unwrap();
        assert_eq!(cq_view(&mut vb, &r), (18, 1));
        complete(start(&b, fd, 0, 2, &mut vb), 0);
        assert_eq!(cq_view(&mut vb, &r), (20, 0));
        assert_eq!(cq_view(&mut vb, &r), (21, 0));
    });
    drop(vb);
    assert!(epoch.finish().is_empty());
    assert_eq!(l.vfs.read(reader, 2).unwrap(), b"z");
}

#[path = "async_tests.rs"]
mod asynchronous;

#[test]
fn unregister_and_reuse_buffer_group_keeps_the_inflight_original_generation() {
    let (mut l, mut m, fd, r) = setup(8);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    m.write_array(0x3000, 0x2200u64.to_le_bytes()).unwrap();
    m.write_array(0x3008, 1u32.to_le_bytes()).unwrap();
    m.write_array(0x300c, 42u16.to_le_bytes()).unwrap();
    m.write_array(0x300e, 1u16.to_le_bytes()).unwrap();
    m.write(0x1200, &[0; 40]).unwrap();
    m.write_array(0x1200, 0x3000u64.to_le_bytes()).unwrap();
    m.write_array(0x1208, 1u32.to_le_bytes()).unwrap();
    m.write_array(0x120c, 9u16.to_le_bytes()).unwrap();
    l.uring_register([fd as u64, 22, 0x1200, 1, 0, 0], &mut m)
        .unwrap();
    // A different mm can register its own descriptor page while this mm's
    // original byte operation is in flight; no root Memory aliases a live View.
    let mut child = m.clone();
    child.write_array(0x4000, 0x2300u64.to_le_bytes()).unwrap();
    child.write_array(0x4008, 1u32.to_le_bytes()).unwrap();
    child.write_array(0x400c, 43u16.to_le_bytes()).unwrap();
    child.write_array(0x400e, 1u16.to_le_bytes()).unwrap();
    let mut read = data(22, reader, 0, 1, 77, 32);
    read[40..42].copy_from_slice(&9u16.to_le_bytes());
    add(&mut m, &r, read);
    l.vfs.write(writer, b"o").unwrap();
    let mut epoch = UringEpoch::default();
    let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
    let view = m.parallel_view(&mut Default::default()).unwrap();
    let (entered, receive) = std::sync::mpsc::sync_channel(1);
    let (release, blocked) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let job = scope.spawn(move || {
            let mut gated = Gate {
                inner: view,
                entered,
                release: blocked,
                once: Cell::new(false),
            };
            complete(start(&s, fd, 1, 1, &mut gated), 1);
        });
        receive.recv_timeout(Duration::from_secs(3)).unwrap();
        let original = r.state.lock().unwrap().provided[&9].identity;
        child.write(0x1200, &[0; 40]).unwrap();
        child.write_array(0x120c, 9u16.to_le_bytes()).unwrap();
        l.uring_register([fd as u64, 23, 0x1200, 1, 0, 0], &mut child)
            .unwrap();
        assert!(r
            .state
            .lock()
            .unwrap()
            .retired_groups
            .contains_key(&original));
        child.write_array(0x1200, 0x4000u64.to_le_bytes()).unwrap();
        child.write_array(0x1208, 1u32.to_le_bytes()).unwrap();
        l.uring_register([fd as u64, 22, 0x1200, 1, 0, 0], &mut child)
            .unwrap();
        assert_ne!(r.state.lock().unwrap().provided[&9].identity, original);
        release.send(()).unwrap();
        job.join().unwrap();
    });
    m.commit_parallel().unwrap();
    assert_eq!(cq(&mut m, &r), (77, 1));
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"o");
    let state = r.state.lock().unwrap();
    assert!(state.retired_groups.is_empty() && state.busy_groups.is_empty());
    assert!(matches!(
        &state.provided[&9].source,
        trames_vfs::UringBufferSource::Ring { head: 0, .. }
    ));
    assert_eq!(child.read_array::<1>(0x2300).unwrap(), [0]);
}
