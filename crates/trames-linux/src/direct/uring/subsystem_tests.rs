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
fn mqueue_uring_paths_and_accepted_directory_fds_do_not_require_owner_maintenance() {
    for cancel in [false, true] {
        let (mut l, mut m, fd, ring) = setup(16);
        l.vfs.mkdir_at(-100, b"/mq", 0o755).unwrap();
        let mut files = trames_vfs::FileEpoch::default();
        let caps = files.capture(&l.vfs, true);
        let d = direct(&l, &m, &mut UringEpoch::default(), &caps);
        // This original mount is published after source-context capture.
        l.vfs
            .mount(None, b"/mq", Some(b"mqueue"), 14, None)
            .unwrap();
        let t = target();
        m.write(0x2100, b"/mq\0").unwrap();
        m.write(0x2200, b".\0").unwrap();
        let mut open = scalar(18, (-100i32) as u32, 0x2100, 0, 1);
        open[28..32].copy_from_slice(&trames_vfs::O_DIRECTORY.to_le_bytes());
        let dir = submit(&d, &mut m, fd, &ring, open, &t);
        assert!(dir >= 0, "source open returned {dir}");
        let old = l.vfs.stat_fd(dir as u32).unwrap();
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        add(&mut m, &ring, scalar(22, reader, 0x2300, 1, 2));
        let mut stat = scalar(21, dir as u32, 0x2200, 0x7ff, 3);
        stat[1] = 2; // Drain retains the accepted dirfd behind the original read.
        stat[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        add(&mut m, &ring, stat);
        assert!(matches!(
            enter(&d, fd, 2, 0, &mut m, &t),
            IoAttempt::Complete(Ok(2))
        ));
        let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
        assert!(background.progress(&mut m).unwrap());
        l.vfs.close(dir as u32).unwrap();
        // Reuse the numeric fd and replace the pathname while the original
        // accepted operation retains its old directory and mount identity.
        let replacement = l
            .vfs
            .open_at(-100, b"/", trames_vfs::O_DIRECTORY, 0)
            .unwrap();
        assert_eq!(replacement, dir as u32);
        l.vfs.umount(b"/mq", 2).unwrap();
        l.vfs.mount(None, b"/mq", Some(b"tmpfs"), 0, None).unwrap();
        if cancel {
            d.urings.actor().cancel_task(m.instruction_identity().0, 7);
            let mut completions = [cq(&mut m, &ring), cq(&mut m, &ring)];
            completions.sort_unstable();
            assert_eq!(completions, [(2, -125), (3, -125)]);
            assert_eq!(m.read_u64(0x3020).unwrap(), 0);
        } else {
            l.vfs.write(writer, b"x").unwrap();
            assert!(background.progress(&mut m).unwrap());
            assert_eq!(cq(&mut m, &ring), (2, 1));
            assert_eq!(cq(&mut m, &ring), (3, 0));
            assert_eq!(
                m.read_u64(0x3020).unwrap(),
                u64::from_le_bytes(old[8..16].try_into().unwrap())
            );
        }
        assert!(!l.uring_requires_owner());
        stat[1] = 0;
        stat[4..8].copy_from_slice(&((-100i32) as u32).to_le_bytes());
        stat[16..24].copy_from_slice(&0x2100u64.to_le_bytes());
        stat[32..40].copy_from_slice(&5u64.to_le_bytes());
        assert_eq!(submit(&d, &mut m, fd, &ring, stat, &t), 0);
        let current = l.vfs.stat_at(-100, b"/mq").unwrap();
        assert_ne!(&old[..8], &current[..8]);
        assert_eq!(
            m.read_u64(0x3020).unwrap(),
            u64::from_le_bytes(current[8..16].try_into().unwrap())
        );
        assert_eq!(
            submit(&d, &mut m, fd, &ring, sqe(19, replacement, 6), &t),
            0
        );
        assert!(!l.uring_requires_owner());
    }
}
#[test]
fn native_device_scalar_vector_and_positioned_errors_share_the_original_abi() {
    let (mut l, mut m, _, _) = setup(16);
    l.vfs.set_runtime_info(7, Default::default());
    l.vfs.enable_video_device();
    l.vfs.attach_bridge(Default::default());
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &caps);
    m.write(0x2100, b"x").unwrap();
    m.write(0x2200, &0x2100u64.to_le_bytes()).unwrap();
    m.write(0x2208, &1u64.to_le_bytes()).unwrap();
    for path in [
        b"/dev/dri/renderD128".as_slice(),
        b"/dev/vda",
        b"/dev/vda1",
        b"/dev/trames-bridge",
    ] {
        for flags in [0, 1, 2, 0x200000] {
            let fd = l.vfs.open_at(-100, path, flags, 0).unwrap() as u64;
            let mut calls = vec![(62, [fd, 0, 999, 0, 0, 0])];
            for number in 63..=66 {
                calls.push((
                    number,
                    [fd, if number < 65 { 0x2100 } else { 0x2200 }, 0, 0, 0, 0],
                ));
            }
            for offset in [0, u64::MAX] {
                for length in [0, 1] {
                    for number in 67..=70 {
                        calls.push((
                            number,
                            [
                                fd,
                                if number < 69 { 0x2100 } else { 0x2200 },
                                length,
                                offset,
                                0,
                                0,
                            ],
                        ));
                    }
                }
            }
            if path != b"/dev/trames-bridge" {
                calls.extend([
                    (63, [fd, 0x2100, 1, 0, 0, 0]),
                    (64, [fd, 0x2100, 1, 0, 0, 0]),
                ]);
            }
            for (number, args) in calls {
                let expected = l.syscall(
                    number as u64,
                    args,
                    &mut m,
                    &mut crate::CapturedOutput::default(),
                );
                assert_eq!(
                    d.invoke(number, args, &mut m),
                    Some(expected),
                    "{} syscall {number} args {args:?}",
                    String::from_utf8_lossy(path)
                );
            }
            l.vfs.close(fd as u32).unwrap();
        }
    }
}
#[test]
fn native_device_opens_and_bridge_requests_use_original_source_resources() {
    let (mut l, mut m, ring_fd, ring) = setup(16);
    l.vfs.set_runtime_info(7, Default::default());
    l.vfs.enable_video_device();
    l.vfs.attach_bridge(Default::default());
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &caps);
    let t = target();
    for (tag, path) in [
        b"/dev/dri/renderD128".as_slice(),
        b"/dev/kmsg",
        b"/dev/vda",
        b"/dev/vda1",
        b"/dev/trames-bridge",
    ]
    .into_iter()
    .enumerate()
    {
        m.write(0x2100, &[path, b"\0"].concat()).unwrap();
        let mut open = scalar(18, (-100i32) as u32, 0x2100, 0, tag as u64 + 100);
        open[28..32].copy_from_slice(&2u32.to_le_bytes());
        let fd = submit(&d, &mut m, ring_fd, &ring, open, &t);
        assert!(fd >= 0, "{} returned {fd}", String::from_utf8_lossy(path));
        assert!(l.vfs.stat_fd(fd as u32).is_ok());
        if path == b"/dev/trames-bridge" {
            let fd = fd as u32;
            let frame = b"{\"version\":1,\"id\":7,\"method\":\"bridge.info\",\"params\":{}}\n";
            m.write(0x3000, frame).unwrap();
            let mut write = scalar(23, fd, 0x3000, frame.len() as u32, 170);
            write[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            assert_eq!(
                submit(&d, &mut m, ring_fd, &ring, write, &t),
                frame.len() as i32
            );
            let mut read = scalar(22, fd, 0x3100, 1024, 171);
            read[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(submit(&d, &mut m, ring_fd, &ring, read, &t) > 0);
            let original = l
                .vfs
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .direct_byte()
                .unwrap();
            let mut read = scalar(22, fd, 0x3100, 1024, 172);
            read[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
            add(&mut m, &ring, read);
            assert!(matches!(
                enter(&d, ring_fd, 1, 0, &mut m, &t),
                IoAttempt::Complete(Ok(1))
            ));
            let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
            assert!(background.progress(&mut m).unwrap());
            l.vfs.close(fd).unwrap();
            assert_eq!(l.vfs.open_at(-100, path, 2, 0).unwrap(), fd);
            assert_eq!(original.write(frame), Ok(frame.len()));
            assert!(background.signal.ready());
            assert!(background.progress(&mut m).unwrap());
            assert!(!background.active());
            assert!(!l.uring_requires_owner());
            assert_eq!(cq(&mut m, &ring).0, 172);
            assert_eq!(
                l.vfs.read(fd, 1024),
                Err(Errno(11)),
                "FD reuse cannot receive the original connection's reply"
            );
        }
    }
}
#[test]
fn mapped_layout_sqe_uses_source_resource_and_keeps_accepted_work_after_cancellation() {
    struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<crate::FileResult>)>);
    impl FileExecutor for Queue {
        fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<crate::FileResult>) {
            result.begin();
            assert!(self.0.send((work.queued(), result)).is_ok());
        }
    }
    for cancel in [false, true] {
        let (mut l, mut m, ring_fd, ring) = setup(8);
        l.vfs
            .import_file(b"/mapped", vec![7; trames_memory::PAGE_SIZE as usize])
            .unwrap();
        let fd = l.vfs.open_at(-100, b"/mapped", 2, 0).unwrap();
        m.map_backed(
            0x30000,
            l.vfs
                .mapping_pages(fd, 0, trames_memory::PAGE_SIZE, true, true)
                .unwrap(),
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
        let mut files = trames_vfs::FileEpoch::default();
        let caps = files.capture(&l.vfs, true);
        let mut epoch = UringEpoch::default();
        let (send, receive) = std::sync::mpsc::channel();
        let disk: Arc<dyn FileExecutor> = Arc::new(Queue(send));
        let layouts = crate::FileLayouts::new(disk.clone());
        let t = target();
        let driver = layouts.bind_reader(IoSignal::new(0, Arc::downgrade(&t)));
        let d = direct(&l, &m, &mut epoch, &caps)
            .with_file_executor(disk)
            .with_file_layouts(layouts.clone());
        let mut truncate = sqe(55, fd, 991);
        truncate[8..16].copy_from_slice(&1u64.to_le_bytes());
        add(&mut m, &ring, truncate);
        let view = m.parallel_view(&mut Default::default()).unwrap();
        assert!(matches!(
            enter(&d, ring_fd, 1, 0, &mut m, &t),
            IoAttempt::Complete(Ok(1))
        ));
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        result.complete(work.run());
        assert!(matches!(
            enter(&d, ring_fd, 0, 0, &mut m, &t),
            IoAttempt::Complete(Ok(0))
        ));
        assert!(!d.urings.actor().owner_required());
        let request = driver.take_ready().pop().unwrap();
        let request = layouts.try_submit(request).err().unwrap();
        layouts.restore(request);
        l.vfs.close(fd).unwrap();
        assert_eq!(l.vfs.eventfd(0, 0).unwrap(), fd);
        if cancel {
            d.urings.actor().cancel_task(m.instruction_identity().0, 7);
        }
        drop(view);
        m.commit_parallel().unwrap();
        let request = driver.take_ready().pop().unwrap();
        assert!(layouts.try_submit(request).is_ok());
        let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
        result.complete(work.run());
        if !cancel {
            assert!(matches!(
                enter(&d, ring_fd, 0, 0, &mut m, &t),
                IoAttempt::Complete(Ok(0))
            ));
            assert_eq!(cq(&mut m, &ring), (991, 0));
        }
        let original = l.vfs.open_at(-100, b"/mapped", 0, 0).unwrap();
        assert_eq!(l.vfs.read(original, 32).unwrap(), [7]);
        assert!(!layouts.pending());
        assert!(receive.try_recv().is_err());
        assert!(!d.urings.actor().owner_required());
        drop(d);
        assert!(epoch.finish().is_empty());
        files.finish();
    }
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
    assert!(background.progress(&mut m).unwrap());
    l.vfs.close(fd).unwrap();
    l.vfs.close(reader).unwrap();
    let foreign = m.clone();
    l.vfs.write(writer, b"s").unwrap();
    assert!(background.signal.ready());
    assert_eq!(foreign.read_array::<1>(0x2200).unwrap(), [0]);
    assert!(background.progress(&mut m).unwrap());
    assert_eq!(cq(&mut m, &r), (5, 1));
    assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"s");
    assert_eq!(foreign.read_array::<1>(0x2200).unwrap(), [0]);
    assert!(!background.active());
    assert!(epoch.finish().is_empty());
}

#[test]
fn solo_accepted_drain_keeps_source_context_across_worker_admission() {
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
        .all(|r| r.execution.is_some()));
    let mut epoch = UringEpoch::default();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let d = direct(&l, &m, &mut epoch, &caps);
    let t = target();
    let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
    assert!(background.progress(&mut m).unwrap());
    l.vfs.write(writer, b"s").unwrap();
    assert!(background.progress(&mut m).unwrap());
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
    assert_eq!(r.load_queue(0), 1);
    assert_eq!(
        l.uring_enter([fd as u64, 0, 1, 1, 0, 0], &mut m, Some(1), 7),
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
        "trames-limit-source-{}-{}",
        std::process::id(),
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
    let pump = d.with_task_signal(b.clone());
    assert!(matches!(
        enter(&pump, fd, 0, 0, &mut m, &t),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(cq(&mut m, &r), (77, -27));
    assert_eq!(a.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(b.0.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert!(!l.take_file_size_signal());
    // Updating a caller changes future acceptance; old in-flight work above
    // still publishes to its original submitter. A new request uses B.
    write[32..40].copy_from_slice(&78u64.to_le_bytes());
    add(&mut m, &r, write);
    assert!(matches!(
        enter(&pump, fd, 1, 0, &mut m, &t),
        IoAttempt::Complete(Ok(1))
    ));
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    result.complete(work.run());
    assert!(matches!(
        enter(&pump, fd, 0, 0, &mut m, &t),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(cq(&mut m, &r), (78, -27));
    assert_eq!(a.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(b.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(!pump.urings.actor().owner_required());
    drop((pump, l));
    files.finish();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn namespace_switch_preserves_accepted_sqe_context_and_refreshes_new_submissions() {
    let (mut l, mut m, fd, r) = setup(16);
    l.vfs.mkdir_at(-100, b"/old", 0o755).unwrap();
    l.vfs.mkdir_at(-100, b"/new", 0o755).unwrap();
    l.vfs.chdir(b"/old").unwrap();
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut peer = l.vfs.clone_with_resources(true, true);
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut d = direct(&l, &m, &mut UringEpoch::default(), &caps);
    let t = target();
    m.write(0x2100, b"accepted\0").unwrap();
    add(&mut m, &r, scalar(22, reader, 0x2200, 1, 1));
    let mut open = scalar(18, (-100i32) as u32, 0x2100, 0o600, 2);
    open[1] = 2; // IO_DRAIN: preserve imported path and fs until read completes.
    open[28..32].copy_from_slice(&0x42u32.to_le_bytes());
    add(&mut m, &r, open);
    assert!(matches!(
        enter(&d, fd, 2, 0, &mut m, &t),
        IoAttempt::Complete(Ok(2))
    ));
    let actor = l.uring_actor_root().get().unwrap().clone();
    let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
    assert!(background.progress(&mut m).unwrap());
    let trames_vfs::TaskNamespaceAttempt::Complete(state, result) =
        l.vfs.task_namespaces().unshare(0x600, true).run()
    else {
        panic!("uncontended Files/fs");
    };
    assert_eq!(result, Ok(0));
    d.refresh_namespaces(state.resources());
    l.vfs.adopt_task_namespaces(state);
    l.vfs.chdir(b"/new").unwrap();
    assert!(Arc::ptr_eq(&actor, l.uring_actor_root().get().unwrap()));
    m.write(0x2100, b"fresh\0").unwrap();
    // Original accepted request must not re-read this changed guest pointer.
    peer.write(writer, b"x").unwrap();
    assert!(background.progress(&mut m).unwrap());
    assert_eq!(cq(&mut m, &r), (1, 1));
    let (tag, old_fd) = cq(&mut m, &r);
    assert_eq!(tag, 2);
    assert!(old_fd >= 0);
    assert!(peer.stat_at(-100, b"/old/accepted").is_ok());
    assert!(l.vfs.stat_at(-100, b"/new/accepted").is_err());
    assert_eq!(l.vfs.flags(old_fd as u32), Err(Errno(9)));
    open[1] = 0;
    open[32..40].copy_from_slice(&3u64.to_le_bytes());
    let new_fd = submit(&d, &mut m, fd, &r, open, &t);
    assert!(new_fd >= 0);
    assert!(l.vfs.flags(new_fd as u32).is_ok());
    assert!(l.vfs.stat_at(-100, b"/new/fresh").is_ok());
    assert!(peer.stat_at(-100, b"/old/fresh").is_err());
}

#[test]
fn credential_drop_keeps_accepted_sqe_authority_but_rejects_future_opens() {
    let (mut l, mut m, fd, r) = setup(16);
    let secret = l.vfs.open_at(-100, b"/root-only", 0x42, 0o600).unwrap();
    l.vfs.close(secret).unwrap();
    let [reader, writer] = l.vfs.pipe(0).unwrap();
    let mut files = trames_vfs::FileEpoch::default();
    let caps = files.capture(&l.vfs, true);
    let mut d = direct(&l, &m, &mut UringEpoch::default(), &caps);
    let t = target();
    m.write(0x2100, b"/root-only\0").unwrap();
    add(&mut m, &r, scalar(22, reader, 0x2200, 1, 1));
    let mut open = scalar(18, (-100i32) as u32, 0x2100, 0, 2);
    open[1] = 2; // Drain keeps this imported operation behind the pipe read.
    add(&mut m, &r, open);
    assert!(matches!(
        enter(&d, fd, 2, 0, &mut m, &t),
        IoAttempt::Complete(Ok(2))
    ));
    let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
    assert!(background.progress(&mut m).unwrap());
    let mut state = l.vfs.task_namespaces();
    state.with_credentials(|c, dumpable| {
        let result =
            crate::credential_call(c, dumpable, 7, 146, [1000, 0, 0, 0, 0, 0], &mut m, |_| {
                Err(Errno(3))
            })
            .unwrap();
        assert!(result.changed);
    });
    state.publish_credentials();
    d.refresh_namespaces(state.resources());
    l.vfs.adopt_task_namespaces(state);
    l.vfs.write(writer, b"x").unwrap();
    assert!(background.progress(&mut m).unwrap());
    assert_eq!(cq(&mut m, &r), (1, 1));
    let (tag, old_fd) = cq(&mut m, &r);
    assert_eq!(tag, 2);
    assert!(
        old_fd >= 0,
        "accepted open lost its original credentials: {old_fd}"
    );
    open[1] = 0;
    open[32..40].copy_from_slice(&3u64.to_le_bytes());
    assert_eq!(submit(&d, &mut m, fd, &r, open, &t), -13);
}

#[test]
fn corrupt_cq_during_accepted_enter_returns_error_without_replay_or_owner_pump() {
    for complete_before_repair in [false, true] {
        let (mut l, mut m, fd, ring) = setup(8);
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        let mut epoch = UringEpoch::default();
        let d = direct(&l, &m, &mut epoch, &Default::default());
        let t = target();
        add(&mut m, &ring, scalar(22, reader, 0x2200, 1, 91));
        let IoAttempt::Blocked(wait) = enter(&d, fd, 1, 1, &mut m, &t) else {
            panic!("accepted read must wait");
        };
        m.write_array(0x10040, 1000u32.to_le_bytes()).unwrap();
        if complete_before_repair {
            l.vfs.write(writer, b"x").unwrap();
        }
        assert!(matches!(
            d.urings.resume(wait, &mut m),
            IoAttempt::Complete(Err(Errno(22)))
        ));
        assert_eq!(ring.load_queue(0), 1);
        assert!(!ring.state.lock().unwrap().waits.contains_key(&7));
        let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
        assert!(background.progress(&mut m).unwrap());
        assert!(!l.uring_requires_owner());
        m.write_array(0x10040, 0u32.to_le_bytes()).unwrap();
        if !complete_before_repair {
            l.vfs.write(writer, b"x").unwrap();
        }
        assert!(matches!(
            enter(&d, fd, 0, 1, &mut m, &t),
            IoAttempt::Complete(Ok(0))
        ));
        assert_eq!(cq(&mut m, &ring), (91, 1));
        assert_eq!(m.read_array::<1>(0x2200).unwrap(), *b"x");
        assert_eq!(ring.load_queue(68), 1);
        assert!(ring.state.lock().unwrap().pending.is_empty());
    }
}

#[test]
fn layout_completion_without_driver_waits_on_original_backing_and_cancels_cleanly() {
    struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<crate::FileResult>)>);
    impl FileExecutor for Queue {
        fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<crate::FileResult>) {
            result.begin();
            self.0.send((work.queued(), result)).unwrap();
        }
    }
    for queued in [false, true] {
        for cancellation in 0..=2 {
            if !queued && cancellation == 2 {
                continue;
            }
            let cancel = cancellation == 1;
            let cancel_native = cancellation == 2;
            let (mut l, mut m, ring_fd, ring) = setup(8);
            l.vfs
                .import_file(
                    b"/layout-original",
                    vec![7; trames_memory::PAGE_SIZE as usize],
                )
                .unwrap();
            let fd = l.vfs.open_at(-100, b"/layout-original", 2, 0).unwrap();
            m.map_backed(
                0x30000,
                l.vfs
                    .mapping_pages(fd, 0, trames_memory::PAGE_SIZE, true, true)
                    .unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
            let mut epoch = UringEpoch::default();
            let (send, receive) = std::sync::mpsc::channel();
            let mut d = direct(&l, &m, &mut epoch, &Default::default());
            if queued {
                d = d.with_file_executor(Arc::new(Queue(send)));
            }
            let t = target();
            let view = m.parallel_view(&mut Default::default()).unwrap();
            let mut truncate = sqe(55, fd, 991);
            truncate[8..16].copy_from_slice(&1u64.to_le_bytes());
            add(&mut m, &ring, truncate);
            assert!(matches!(
                enter(&d, ring_fd, 1, 0, &mut m, &t),
                IoAttempt::Complete(Ok(1))
            ));
            if queued {
                let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
                result.complete(work.run());
            }
            let mut background = d.uring_background(7, &Arc::downgrade(&t)).unwrap();
            assert!(background.progress(&mut m).unwrap());
            assert!(background.progress(&mut m).unwrap());
            assert!(
                !background.external(),
                "a backing publication is not a native disk completion"
            );
            assert!(!l.uring_requires_owner());
            l.vfs.close(fd).unwrap();
            assert_eq!(l.vfs.eventfd(9, 0).unwrap(), fd);
            if cancel {
                d.urings.actor().cancel_task(m.instruction_identity().0, 7);
                assert_eq!(cq(&mut m, &ring), (991, -125));
            }
            drop(view);
            m.commit_parallel().unwrap();
            if !cancel {
                assert!(
                    background.signal.ready(),
                    "original publication release must wake its request"
                );
                assert!(background.progress(&mut m).unwrap());
                if queued {
                    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
                    if cancel_native {
                        d.urings.actor().cancel_task(m.instruction_identity().0, 7);
                        assert_eq!(cq(&mut m, &ring), (991, -125));
                        assert!(
                            m.parallel_view(&mut Default::default()).is_none(),
                            "accepted native work retains original publication exclusion"
                        );
                    }
                    result.complete(work.run());
                    assert!(background.progress(&mut m).unwrap());
                }
                if !cancel_native {
                    assert_eq!(cq(&mut m, &ring), (991, 0));
                }
                let publication = m
                    .parallel_view(&mut Default::default())
                    .expect("native completion releases its original ticket");
                drop(publication);
                m.commit_parallel().unwrap();
            }
            let original = l.vfs.open_at(-100, b"/layout-original", 0, 0).unwrap();
            assert_eq!(
                l.vfs.read(original, 2).unwrap(),
                if cancel { vec![7, 7] } else { vec![7] }
            );
            assert_eq!(l.vfs.read(fd, 8).unwrap(), 9u64.to_le_bytes());
            assert!(receive.try_recv().is_err(), "no replay or post-cancel job");
            assert!(!l.uring_requires_owner());
        }
    }
}

#[test]
fn file_size_completion_without_mailbox_uses_original_task_flag_not_an_owner_message() {
    let (mut l, mut m, fd, ring) = setup(8);
    l.vfs.import_file(b"/limit", Vec::new()).unwrap();
    let file = l.vfs.open_at(-100, b"/limit", 2, 0).unwrap();
    l.vfs.file_size_limit_handle().set(0);
    m.write(0x2200, b"x").unwrap();
    let mut epoch = UringEpoch::default();
    let d = direct(&l, &m, &mut epoch, &Default::default());
    let t = target();
    for tag in [1, 2] {
        add(&mut m, &ring, scalar(23, file, 0x2200, 1, tag));
    }
    assert!(matches!(
        enter(&d, fd, 2, 2, &mut m, &t),
        IoAttempt::Complete(Ok(2))
    ));
    assert_eq!(cq(&mut m, &ring), (1, -27));
    assert_eq!(cq(&mut m, &ring), (2, -27));
    let child = l.clone_with_files(true);
    assert!(
        !child.take_file_size_signal(),
        "a new task must not inherit pending source signals"
    );
    assert!(l.take_file_size_signal());
    assert!(
        !l.take_file_size_signal(),
        "standard signals coalesce and consume once"
    );
    assert!(!l.uring_requires_owner());
    assert!(l.vfs.read(file, 1).unwrap().is_empty());
}
