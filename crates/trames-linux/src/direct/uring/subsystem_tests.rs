// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::uring::tests::{add, cq, setup, sqe};
use trames_memory::{Memory, Permissions};
struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn target() -> Arc<dyn IoWake> {
    Arc::new(Target)
}
fn direct(
    l: &Linux,
    m: &Memory,
    epoch: &mut UringEpoch,
    files: &trames_vfs::DirectFiles,
) -> DirectSyscalls {
    DirectSyscalls::new(l.vfs.direct_descriptors())
        .with_paths(l.vfs.path_queries())
        .with_resources(l.vfs.descriptor_factory())
        .with_files(files.clone())
        .with_urings(
            epoch
                .capture_with_files(&l.vfs, m.instruction_identity().0, 7, files)
                .with_actor(l.uring_actor_root()),
        )
}
fn enter(
    d: &DirectSyscalls,
    fd: u32,
    n: u32,
    min: u32,
    m: &mut impl CpuMemory,
    t: &Arc<dyn IoWake>,
) -> IoAttempt {
    d.start(
        426,
        [fd as u64, n as u64, min as u64, u64::from(min != 0), 0, 0],
        m,
        7,
        &Arc::downgrade(t),
        None,
    )
    .unwrap()
}
fn submit(
    d: &DirectSyscalls,
    m: &mut Memory,
    fd: u32,
    r: &Uring,
    s: [u8; 64],
    t: &Arc<dyn IoWake>,
) -> i32 {
    let id = UringSqe(s).user_data();
    add(m, r, s);
    assert!(
        matches!(enter(d, fd, 1, 1, m, t), IoAttempt::Complete(Ok(1))),
        "op={}",
        s[0]
    );
    let completion = cq(m, r);
    assert_eq!(completion.0, id);
    completion.1
}
fn scalar(op: u8, fd: u32, address: u64, length: u32, tag: u64) -> [u8; 64] {
    let mut s = sqe(op, fd, tag);
    s[16..24].copy_from_slice(&address.to_le_bytes());
    s[24..28].copy_from_slice(&length.to_le_bytes());
    s
}
#[test]
fn worker_path_and_socket_controls_publish_live_ofds_and_share_the_original_engine() {
    let (l, mut m, fd, r) = setup(32);
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &caps);
    let t = target();
    let address = b"\x01\x00\0uring-whole-subsystem";
    m.write(0x2100, address).unwrap();
    let mut s = scalar(45, 1, 0, 0, 1);
    s[8..16].copy_from_slice(&1u64.to_le_bytes());
    let listener = submit(&d, &mut m, fd, &r, s, &t);
    assert!(listener >= 0);
    let mut s = scalar(56, listener as u32, 0x2100, 0, 2);
    s[8..16].copy_from_slice(&(address.len() as u64).to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, s, &t), 0);
    assert_eq!(
        submit(&d, &mut m, fd, &r, scalar(57, listener as u32, 0, 4, 3), &t),
        0
    );
    let mut s = scalar(45, 1, 0, 0, 4);
    s[8..16].copy_from_slice(&1u64.to_le_bytes());
    let client = submit(&d, &mut m, fd, &r, s, &t);
    assert!(client >= 0);
    let mut s = scalar(16, client as u32, 0x2100, 0, 5);
    s[8..16].copy_from_slice(&(address.len() as u64).to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, s, &t), 0);
    let accepted = submit(&d, &mut m, fd, &r, sqe(13, listener as u32, 6), &t);
    assert!(accepted >= 0);
    m.write(0x2200, b"live").unwrap();
    assert_eq!(
        submit(
            &d,
            &mut m,
            fd,
            &r,
            scalar(26, client as u32, 0x2200, 4, 7),
            &t
        ),
        4
    );
    assert_eq!(
        submit(
            &d,
            &mut m,
            fd,
            &r,
            scalar(27, accepted as u32, 0x2300, 4, 8),
            &t
        ),
        4
    );
    assert_eq!(m.read_array::<4>(0x2300).unwrap(), *b"live");
    assert_eq!(
        submit(&d, &mut m, fd, &r, scalar(34, client as u32, 0, 1, 9), &t),
        0
    );
    assert_eq!(
        submit(
            &d,
            &mut m,
            fd,
            &r,
            scalar(27, accepted as u32, 0x2300, 4, 10),
            &t
        ),
        0
    );
    for (tag, number) in [(11, client), (12, accepted), (13, listener)] {
        assert_eq!(
            submit(&d, &mut m, fd, &r, sqe(19, number as u32, tag), &t),
            0
        );
    }
    m.write(0x2000, b"/whole-subsystem\0").unwrap();
    let mut s = scalar(18, (-100i32) as u32, 0x2000, 0o600, 14);
    s[28..32].copy_from_slice(&0x42u32.to_le_bytes());
    let file = submit(&d, &mut m, fd, &r, s, &t);
    assert!(file >= 0);
    assert!(
        caps.published(file as u32),
        "worker open did not publish file authority"
    );
    assert!(
        caps.get(file as u32).is_some(),
        "published file authority cannot be retained"
    );
    // File growth is a filesystem/backing operation. Reserve it through its
    // typed control path before testing the existing in-place byte fast path.
    assert_eq!(
        submit(&d, &mut m, fd, &r, scalar(17, file as u32, 8192, 0, 22), &t),
        0
    );
    m.write(0x2200, b"data").unwrap();
    let mut s = scalar(23, file as u32, 0x2200, 4, 15);
    s[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, s, &t), 4);
    assert_eq!(submit(&d, &mut m, fd, &r, sqe(3, file as u32, 16), &t), 0);
    assert_eq!(
        submit(&d, &mut m, fd, &r, scalar(17, file as u32, 8192, 0, 17), &t),
        0
    );
    let mut s = sqe(55, file as u32, 18);
    s[8..16].copy_from_slice(&2u64.to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, s, &t), 0);
    m.write(0x2300, &[0]).unwrap();
    let mut s = scalar(21, file as u32, 0x2300, 0x7ff, 19);
    s[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
    s[28..32].copy_from_slice(&0x1000u32.to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, s, &t), 0);
    assert_eq!(m.read_u64(0x3028).unwrap(), 2);
    m.write(0x2400, &[0; 24]).unwrap();
    let mut s = scalar(28, (-100i32) as u32, 0x2000, 24, 20);
    s[8..16].copy_from_slice(&0x2400u64.to_le_bytes());
    let reader = submit(&d, &mut m, fd, &r, s, &t);
    assert!(reader >= 0);
    assert_eq!(
        submit(
            &d,
            &mut m,
            fd,
            &r,
            scalar(22, reader as u32, 0x2500, 8, 21),
            &t
        ),
        2
    );
    assert_eq!(m.read_array::<2>(0x2500).unwrap(), *b"da");
    assert!(r.state.lock().unwrap().pending.is_empty());
    assert!(epoch.finish().is_empty());
    drop(d);
    files.finish();
}
#[test]
fn worker_setup_publishes_a_new_ring_without_recapturing_the_descriptor_table() {
    let (l, mut m, _, original) = setup(2);
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &Default::default());
    let t = target();
    m.write(0x1000, &[0; 120]).unwrap();
    let fd = d
        .invoke_creation(425, [4, 0x1000, 0, 0, 0, 0], &mut m)
        .unwrap()
        .unwrap() as u32;
    assert!(!d.urings.rings.contains_key(&fd));
    let r = l.vfs.uring(fd).unwrap();
    m.unmap(0x10000, original.ring_bytes).unwrap();
    m.unmap(0x20000, original.sqe_bytes).unwrap();
    for (address, offset, len) in [
        (0x10000, 0, r.ring_bytes),
        (0x20000, 0x10000000, r.sqe_bytes),
    ] {
        m.map_backed(
            address,
            l.vfs.mapping_pages(fd, offset, len, true, true).unwrap(),
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    }
    assert_eq!(submit(&d, &mut m, fd, &r, sqe(0, 0, 1), &t), 0);
    assert!(epoch.finish().is_empty());
}
#[test]
fn registrations_remain_live_across_snapshots_and_source_fd_reuse() {
    let (mut l, mut m, fd, r) = setup(8);
    let [a, aw] = l.vfs.pipe(0).unwrap();
    let [b, bw] = l.vfs.pipe(0).unwrap();
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &Default::default());
    let t = target();
    m.write_array(0x2000, a.to_le_bytes()).unwrap();
    assert!(matches!(
        d.urings
            .register([fd as u64, 2, 0x2000, 1, 0, 0], &mut m, 7),
        Some(IoAttempt::Complete(Ok(0)))
    ));
    let mut read = scalar(22, 0, 0x2200, 1, 1);
    read[1] = 1;
    add(&mut m, &r, read);
    assert!(matches!(
        enter(&d, fd, 1, 0, &mut m, &t),
        IoAttempt::Complete(Ok(1))
    ));
    m.write(0x2100, &[0; 16]).unwrap();
    m.write_array(0x2108, 0x2000u64.to_le_bytes()).unwrap();
    m.write_array(0x2000, b.to_le_bytes()).unwrap();
    assert!(matches!(
        d.urings
            .register([fd as u64, 6, 0x2100, 1, 0, 0], &mut m, 7),
        Some(IoAttempt::Complete(Ok(1)))
    ));
    l.vfs.close(a).unwrap();
    assert_eq!(l.vfs.eventfd(7, 0).unwrap(), a);
    l.vfs.write(aw, b"a").unwrap();
    l.vfs.write(bw, b"b").unwrap();
    assert!(matches!(
        enter(&d, fd, 0, 1, &mut m, &t),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(cq(&mut m, &r), (1, 1));
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"a");
    read[32..40].copy_from_slice(&2u64.to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, read, &t), 1);
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"b");
    assert!(epoch.finish().is_empty());
}
#[test]
fn source_maintenance_owns_the_original_vm_after_the_ring_fd_is_closed() {
    let (mut l, mut m, fd, r) = setup(4);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &Default::default());
    let t = target();
    add(&mut m, &r, scalar(22, reader, 0x2200, 1, 5));
    assert!(matches!(
        enter(&d, fd, 1, 0, &mut m, &t),
        IoAttempt::Complete(Ok(1))
    ));
    let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
    assert!(background.progress(&mut m));
    l.vfs.close(fd).unwrap();
    l.vfs.close(reader).unwrap();
    let foreign = m.clone();
    l.vfs.write(writer, b"s").unwrap();
    assert!(background.signal.ready());
    assert_eq!(foreign.read_array::<1>(0x2200).unwrap(), [0]);
    assert!(background.progress(&mut m));
    assert_eq!(cq(&mut m, &r), (5, 1));
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"s");
    assert_eq!(foreign.read_array::<1>(0x2200).unwrap(), [0]);
    assert!(!background.active());
    assert!(epoch.finish().is_empty());
}

#[test]
fn owner_accepted_drain_gains_source_context_and_real_fallback_stops_readmission() {
    let (mut l, mut m, fd, r) = setup(8);
    l.vfs.mkdir_at(-100, b"/tmp", 0o777).unwrap();
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    m.write(0x2100, b"/tmp/owner-to-source\0").unwrap();
    add(&mut m, &r, scalar(22, reader, 0x2200, 1, 1));
    let mut open = scalar(18, (-100i32) as u32, 0x2100, 0o600, 2);
    open[1] = 2; // IO_DRAIN; source bytes must complete first.
    open[28..32].copy_from_slice(&0x42u32.to_le_bytes()); // O_CREAT | O_RDWR
    add(&mut m, &r, open);
    crate::uring::tests::enter(&mut l, &mut m, fd, 2);
    assert!(r
        .state
        .lock()
        .unwrap()
        .pending
        .iter()
        .all(|r| r.execution.is_none()));
    let mut epoch = UringEpoch::default();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let d = direct(&l, &m, &mut epoch, &caps);
    let t = target();
    let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
    assert!(background.progress(&mut m));
    l.vfs.write(writer, b"s").unwrap();
    assert!(background.progress(&mut m));
    assert_eq!(cq(&mut m, &r), (1, 1));
    let (tag, opened) = cq(&mut m, &r);
    assert_eq!(tag, 2);
    assert!(opened >= 0 && l.vfs.stat_at(-100, b"/tmp/owner-to-source").is_ok());
    assert!(!l.uring_requires_owner());

    // An ordinary truncate-open is a source file operation. Only an actual
    // live mapping layout would request scoped mm ownership.
    open[1] = 0;
    open[28..32].copy_from_slice(&0x202u32.to_le_bytes());
    open[32..40].copy_from_slice(&3u64.to_le_bytes());
    add(&mut m, &r, open);
    assert!(matches!(
        enter(&d, fd, 1, 0, &mut m, &t),
        IoAttempt::Complete(Ok(1))
    ));
    assert!(!l.uring_requires_owner());
    let (tag, opened) = cq(&mut m, &r);
    assert_eq!(tag, 3);
    assert!(opened >= 0);
}

#[test]
fn retained_enter_survives_cohort_stop_close_reuse_and_unmapped_queue() {
    let (mut l, mut m, fd, r) = setup(4);
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &Default::default());
    let t = target();
    add(&mut m, &r, scalar(22, reader, 0x2200, 1, 88));
    let IoAttempt::Blocked(wait) = enter(&d, fd, 1, 1, &mut m, &t) else {
        panic!("accepted enter")
    };
    let call = wait.uring_enter().unwrap();
    drop(wait);
    drop(d);
    assert!(epoch.finish().is_empty());
    l.vfs.close(fd).unwrap();
    l.vfs.close(reader).unwrap();
    m.unmap(0x10000, r.ring_bytes).unwrap();
    m.unmap(0x20000, r.sqe_bytes).unwrap();
    drop(r);
    let (replacement, new_ring) = l.vfs.uring_create(4, 8).unwrap();
    assert_eq!(fd, replacement);
    l.vfs.write(writer, b"r").unwrap();
    let old_ring = call.ring.clone();
    let mut next = UringEpoch::default();
    let d = direct(&l, &m, &mut next, &Default::default());
    assert!(matches!(
        d.start_retained_uring(
            call,
            [fd as u64, 1, 1, 1, 0, 0],
            &mut m,
            7,
            &Arc::downgrade(&t)
        ),
        IoAttempt::Complete(Ok(1))
    ));
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"r");
    assert_eq!(old_ring.cq_ready(), 1);
    assert_eq!(new_ring.cq_ready(), 0);
    assert_eq!(
        old_ring.read_queue::<8>(trames_vfs::URING_CQES),
        88u64.to_le_bytes()
    );
    assert!(next.finish().is_empty());
}

#[test]
fn queued_disk_sync_keeps_the_actual_ofd_after_ring_close_until_host_work_finishes() {
    struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<crate::FileResult>)>);
    impl FileExecutor for Queue {
        fn submit_file(&self, job: trames_vfs::FileWork, result: Arc<crate::FileResult>) {
            assert!(self.0.send((job, result)).is_ok());
        }
    }
    let directory = std::env::temp_dir().join(format!(
        "trames-uring-host-job-{}-{}",
        std::process::id(),
        trames_memory::new_backing_identity()
    ));
    std::fs::create_dir(&directory).unwrap();
    {
        let mut l = Linux::new(0x100000);
        l.vfs = Vfs::open_disk(&directory, trames_vfs::DiskOptions::default()).unwrap();
        l.vfs.import_file(b"/data", b"payload".to_vec()).unwrap();
        let file = l.vfs.open_at(-100, b"/data", 2, 0).unwrap();
        let close = Arc::downgrade(
            &l.vfs
                .retain_uring_fd(file)
                .unwrap()
                .close_notification()
                .unwrap(),
        );
        let (fd, r) = l.vfs.uring_create(4, 8).unwrap();
        let mut m = Memory::default();
        m.map(0x1000, 4 * trames_memory::PAGE_SIZE, Permissions::RW)
            .unwrap();
        for (address, offset, len) in [
            (0x10000, 0, r.ring_bytes),
            (0x20000, 0x10000000, r.sqe_bytes),
        ] {
            m.map_backed(
                address,
                l.vfs.mapping_pages(fd, offset, len, true, true).unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        }
        let mut files = trames_vfs::FileEpoch::default();
        let caps = files.capture(&l.vfs, true);
        let (send, receive) = std::sync::mpsc::channel();
        let mut epoch = UringEpoch::default();
        let d = direct(&l, &m, &mut epoch, &caps).with_file_executor(Arc::new(Queue(send)));
        let t = target();
        add(&mut m, &r, sqe(3, file, 99));
        assert!(matches!(
            enter(&d, fd, 1, 0, &mut m, &t),
            IoAttempt::Complete(Ok(1))
        ));
        let (job, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(!result.ready());
        l.vfs.close(fd).unwrap();
        l.vfs.close(file).unwrap();
        drop(d);
        drop(m);
        drop(r);
        assert!(epoch.finish().is_empty());
        assert!(
            close.upgrade().is_some(),
            "queued host work lost its original OFD"
        );
        result.complete(job.run());
        assert!(matches!(
            result.take(),
            Some(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
                result: Ok(trames_vfs::FileValue::Count(0)),
                ..
            }))
        ));
        drop(result);
        assert!(
            close.upgrade().is_none(),
            "finished host job retained a closed OFD"
        );
        files.finish();
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn proc_control_registered_files_keep_original_resource_and_complete_on_source() {
    let (mut l, mut m, fd, r) = setup(8);
    let oom = Arc::new(trames_vfs::OomTask::default());
    l.vfs.set_runtime_info(
        1,
        trames_vfs::RuntimeInfo {
            processes: vec![trames_vfs::ProcessInfo {
                pid: 1,
                tgid: 1,
                command: b"trames".to_vec(),
                oom: Arc::downgrade(&oom),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let file = l
        .vfs
        .open_at(-100, b"/proc/self/oom_score_adj", 0, 0)
        .unwrap();
    assert!(l.vfs.shared_files().lookup(file).unwrap().is_ok());
    m.write_array(0x1200, file.to_le_bytes()).unwrap();
    l.uring_register([fd as u64, 2, 0x1200, 1, 0, 0], &mut m)
        .unwrap();
    l.vfs.close(file).unwrap();
    let replacement = l.vfs.eventfd(3, 0).unwrap();
    assert_eq!(replacement, file);
    let mut files = trames_vfs::FileEpoch::default();
    assert!(files.capture_uring(&l.vfs, true).is_empty());
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &Default::default());
    let t = target();
    let mut read = scalar(22, 0, 0x2200, 512, 77);
    read[1] = 1;
    add(&mut m, &r, read);
    assert!(matches!(
        enter(&d, fd, 1, 1, &mut m, &t),
        IoAttempt::Complete(Ok(1))
    ));
    let completion = cq(&mut m, &r);
    assert_eq!(completion.0, 77);
    assert_eq!(completion.1, 2);
    assert_eq!(m.read_array::<2>(0x2200).unwrap(), *b"0\n");
    assert!(matches!(
        d.urings.register([fd as u64, 3, 0, 0, 0, 0], &mut m, 7),
        Some(IoAttempt::Complete(Ok(0)))
    ));
    assert_eq!(l.vfs.read(replacement, 8).unwrap(), 3u64.to_le_bytes());
    assert!(epoch.finish().is_empty());
    files.finish();
}

#[test]
fn shared_volatile_registered_file_keeps_its_body_boundary_and_original_ofd() {
    let (mut l, mut m, fd, r) = setup(8);
    l.vfs.set_runtime_info(1, Default::default());
    let file = l.vfs.open_at(-100, b"/proc/version", 0, 0).unwrap();
    assert!(l.vfs.shared_files().lookup(file).unwrap().is_ok());
    m.write_array(0x1200, file.to_le_bytes()).unwrap();
    l.uring_register([fd as u64, 2, 0x1200, 1, 0, 0], &mut m)
        .unwrap();
    l.vfs.close(file).unwrap();
    let replacement = l.vfs.eventfd(3, 0).unwrap();
    assert_eq!(replacement, file);
    let mut files = trames_vfs::FileEpoch::default();
    assert!(files.capture_uring(&l.vfs, true).is_empty());
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &Default::default());
    let mut read = scalar(22, 0, 0x2200, 512, 77);
    read[1] = 1;
    add(&mut m, &r, read);
    assert!(matches!(
        enter(&d, fd, 1, 1, &mut m, &target()),
        IoAttempt::Checkpoint
    ));
    assert_eq!(r.load_queue(0), 0);
    assert_eq!(
        l.uring_enter([fd as u64, 1, 1, 1, 0, 0], &mut m, None, 7),
        Ok((1, true))
    );
    let completion = cq(&mut m, &r);
    assert_eq!(completion.0, 77);
    assert!(completion.1 > 0);
    assert_eq!(&m.read_array::<5>(0x2200).unwrap(), b"Linux");
    assert!(matches!(
        d.urings.register([fd as u64, 3, 0, 0, 0, 0], &mut m, 7),
        Some(IoAttempt::Complete(Ok(0)))
    ));
    assert_eq!(l.vfs.read(replacement, 8).unwrap(), 3u64.to_le_bytes());
    assert!(epoch.finish().is_empty());
    files.finish();
}

#[test]
fn queued_file_read_reserves_its_selected_buffer_and_copies_out_on_the_source() {
    struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<crate::FileResult>)>);
    impl FileExecutor for Queue {
        fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<crate::FileResult>) {
            result.begin();
            assert!(self.0.send((work.queued(), result)).is_ok());
        }
    }
    let directory = std::env::temp_dir().join(format!(
        "trames-selected-file-{}-{}",
        std::process::id(),
        trames_memory::new_backing_identity()
    ));
    let mut l = Linux::new(0x100000);
    l.vfs = Vfs::open_disk(&directory, Default::default()).unwrap();
    l.vfs
        .import_file(b"/data", b"abcdefghijklmnop".to_vec())
        .unwrap();
    let file = l.vfs.open_at(-100, b"/data", 2, 0).unwrap();
    let (fd, r) = l.vfs.uring_create(8, 16).unwrap();
    let mut m = Memory::default();
    m.map(0x1000, 4 * trames_memory::PAGE_SIZE, Permissions::RW)
        .unwrap();
    for (address, offset, len) in [
        (0x10000, 0, r.ring_bytes),
        (0x20000, 0x10000000, r.sqe_bytes),
    ] {
        m.map_backed(
            address,
            l.vfs.mapping_pages(fd, offset, len, true, true).unwrap(),
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    }
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let (send, receive) = std::sync::mpsc::channel();
    let d = direct(&l, &m, &mut epoch, &caps).with_file_executor(Arc::new(Queue(send)));
    let t = target();
    let mut provide = scalar(31, 1, 0x3000, 16, 900);
    provide[8..16].copy_from_slice(&7u64.to_le_bytes());
    provide[40..42].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, provide, &t), 0);
    for tag in [901, 902] {
        let mut read = scalar(22, file, 0, 16, tag);
        read[1] = 32;
        read[40..42].copy_from_slice(&3u16.to_le_bytes());
        add(&mut m, &r, read);
    }
    assert!(matches!(
        enter(&d, fd, 2, 0, &mut m, &t),
        IoAttempt::Complete(Ok(2))
    ));
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(receive.try_recv().is_err());
    assert_eq!(m.read_array::<16>(0x3000).unwrap(), [0; 16]);
    std::thread::spawn(move || result.complete(work.run()))
        .join()
        .unwrap();
    assert!(matches!(
        enter(&d, fd, 0, 0, &mut m, &t),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(cq(&mut m, &r), (901, 16));
    assert_eq!(cq(&mut m, &r), (902, -105));
    assert_eq!(m.read_array::<16>(0x3000).unwrap(), *b"abcdefghijklmnop");
    assert!(r.state.lock().unwrap().busy_groups.is_empty());
    drop((d, m, r));
    assert!(epoch.finish().is_empty());
    files.finish();
    drop(l);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn fixed_file_size_failure_keeps_original_submitter_signal_when_another_context_pumps() {
    #[derive(Default)]
    struct Signals(std::sync::atomic::AtomicUsize);
    impl trames_vfs::TaskSignal for Signals {
        fn raise(&self, sig: u32) {
            assert_eq!(sig, 25);
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<crate::FileResult>)>);
    impl FileExecutor for Queue {
        fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<crate::FileResult>) {
            result.begin();
            assert!(self.0.send((work.queued(), result)).is_ok());
        }
    }
    let directory = std::env::temp_dir().join(format!(
        "trames-limit-source-{}",
        trames_memory::new_backing_identity()
    ));
    let mut l = Linux::new(0x100000);
    l.vfs = Vfs::open_disk(&directory, Default::default()).unwrap();
    l.vfs.import_file(b"/limited", Vec::new()).unwrap();
    let file = l.vfs.open_at(-100, b"/limited", 2, 0).unwrap();
    let (fd, r) = l.vfs.uring_create(8, 16).unwrap();
    let mut m = Memory::default();
    m.map(0x1000, 4 * trames_memory::PAGE_SIZE, Permissions::RW)
        .unwrap();
    for (address, offset, len) in [
        (0x10000, 0, r.ring_bytes),
        (0x20000, 0x10000000, r.sqe_bytes),
    ] {
        m.map_backed(
            address,
            l.vfs.mapping_pages(fd, offset, len, true, true).unwrap(),
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    }
    m.write_array(0x1200, file.to_le_bytes()).unwrap();
    l.uring_register([fd as u64, 2, 0x1200, 1, 0, 0], &mut m)
        .unwrap();
    l.vfs.close(file).unwrap();
    m.write(0x3000, b"x").unwrap();
    l.vfs.file_size_limit_handle().set(1);
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let retained = files.capture_uring(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let a = Arc::new(Signals::default());
    let b = Arc::new(Signals::default());
    let (send, receive) = std::sync::mpsc::channel();
    let d = direct(&l, &m, &mut epoch, &caps)
        .with_task_signal(a.clone())
        .with_file_executor(Arc::new(Queue(send)))
        .with_urings(
            epoch
                .capture_all(&l.vfs, m.instruction_identity().0, 7, &caps, &retained)
                .with_actor(l.uring_actor_root()),
        );
    let t = target();
    let mut write = scalar(23, 0, 0x3000, 1, 77);
    write[1] = 1;
    write[8..16].copy_from_slice(&1u64.to_le_bytes());
    add(&mut m, &r, write);
    assert!(matches!(
        enter(&d, fd, 1, 0, &mut m, &t),
        IoAttempt::Complete(Ok(1))
    ));
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    l.vfs.file_size_limit_handle().set(0);
    result.complete(work.run());
    let pump = direct(&l, &m, &mut epoch, &caps).with_task_signal(b.clone());
    assert!(matches!(
        enter(&pump, fd, 0, 0, &mut m, &t),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(cq(&mut m, &r), (77, -27));
    assert_eq!(a.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(b.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(d.urings.actor().take_file_signals().is_empty());
    assert!(!d.urings.actor().owner_required());
    drop((d, pump, l));
    files.finish();
    std::fs::remove_dir_all(directory).unwrap();
}
