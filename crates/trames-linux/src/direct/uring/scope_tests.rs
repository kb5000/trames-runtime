// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::uring::tests::{add, cq, setup, sqe};
use trames_memory::Memory;

struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn caller(l: &Linux, m: &Memory, epoch: &mut UringEpoch, task: u32) -> DirectSyscalls {
    DirectSyscalls::new(l.vfs.direct_descriptors())
        .with_paths(l.vfs.path_queries())
        .with_resources(l.vfs.descriptor_factory())
        .with_urings(
            epoch
                .capture(&l.vfs, m.instruction_identity().0, task)
                .with_actor(l.uring_actor_root()),
        )
}
fn read(fd: u32, address: u64, tag: u64) -> [u8; 64] {
    let mut entry = sqe(22, fd, tag);
    entry[16..24].copy_from_slice(&address.to_le_bytes());
    entry[24..28].copy_from_slice(&8u32.to_le_bytes());
    entry
}
#[test]
fn completing_one_submitter_keeps_other_original_scope_active() {
    let (mut l, mut m, fd, ring) = setup(8);
    let a = l.vfs.eventfd(0, 0).unwrap();
    let b = l.vfs.eventfd(0, 0).unwrap();
    for (task, file, at) in [(7, a, 0x2000), (8, b, 0x2100)] {
        add(&mut m, &ring, read(file, at, task as u64));
        assert_eq!(
            l.uring_enter([fd as u64, 1, 0, 0, 0, 0], &mut m, None, task),
            Ok((1, true))
        );
    }
    let mut epoch = UringEpoch::default();
    let first = caller(&l, &m, &mut epoch, 7);
    let second = caller(&l, &m, &mut epoch, 8);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let mut first_wait = first.uring_background(7, &Arc::downgrade(&target)).unwrap();
    let mut second_wait = second
        .uring_background(8, &Arc::downgrade(&target))
        .unwrap();
    assert!(first_wait.progress(&mut m).unwrap());
    assert!(second_wait.progress(&mut m).unwrap());
    first.cancel_task_uring(m.instruction_identity().0, 7);
    assert!(first_wait.progress(&mut m).unwrap());
    assert!(!first_wait.active());
    assert!(
        second_wait.active(),
        "another task's completion must not retire this source"
    );
    l.vfs.write(b, &5u64.to_le_bytes()).unwrap();
    assert!(second_wait.signal.ready());
    assert!(second_wait.progress(&mut m).unwrap());
    assert!(!second_wait.active());
    assert_eq!(cq(&mut m, &ring), (7, -125));
    assert_eq!(cq(&mut m, &ring), (8, 8));
    assert_eq!(m.read_array::<8>(0x2100).unwrap(), 5u64.to_le_bytes());
}
#[test]
fn foreign_background_does_not_adopt_another_submitters_pending_request() {
    let (mut l, mut m, fd, ring) = setup(8);
    let file = l.vfs.eventfd(0, 0).unwrap();
    add(&mut m, &ring, read(file, 0x2000, 7));
    assert_eq!(
        l.uring_enter([fd as u64, 1, 0, 0, 0, 0], &mut m, None, 7),
        Ok((1, true))
    );
    let foreign = caller(&l, &m, &mut UringEpoch::default(), 8);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    assert!(
        foreign
            .uring_background(8, &Arc::downgrade(&target))
            .is_none(),
        "CQ visibility does not grant another task's maintenance ownership"
    );
}
#[test]
fn body_deferral_does_not_disable_another_submitters_live_maintenance() {
    let (mut l, mut m, fd, ring) = setup(8);
    l.vfs.set_runtime_info(1, Default::default());
    let excluded = l.vfs.open_at(-100, b"/proc/version", 0, 0).unwrap();
    let ordinary = l.vfs.eventfd(0, 0).unwrap();
    let mut epoch = UringEpoch::default();
    let first = caller(&l, &m, &mut epoch, 7);
    let second = caller(&l, &m, &mut epoch, 8);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    for (task, call, file) in [(7, &first, excluded), (8, &second, ordinary)] {
        add(
            &mut m,
            &ring,
            read(file, 0x2000 + task as u64 * 32, task as u64),
        );
        assert!(matches!(
            call.start(
                426,
                [fd as u64, 1, 0, 0, 0, 0],
                &mut m,
                task,
                &Arc::downgrade(&target),
                None
            ),
            Some(IoAttempt::Complete(Ok(1)))
        ));
    }
    let mut background = first.uring_background(7, &Arc::downgrade(&target)).unwrap();
    assert!(!background.progress(&mut m).unwrap());
    assert!(
        l.worker_uring_pending(&m, 8),
        "a real excluded body cannot disable another source"
    );
    let mut other = second
        .uring_background(8, &Arc::downgrade(&target))
        .unwrap();
    assert!(other.progress(&mut m).unwrap());
    l.vfs.write(ordinary, &9u64.to_le_bytes()).unwrap();
    assert!(other.signal.ready());
    assert!(other.progress(&mut m).unwrap());
    assert_eq!(cq(&mut m, &ring), (8, 8));
    assert!(l.uring_requires_owner_for(&m, 7));
    assert!(!l.uring_requires_owner_for(&m, 8));
    assert!(l.progress_uring(&mut m, 7));
    assert_eq!(cq(&mut m, &ring), (7, 8));
    assert_eq!(&m.read_array::<5>(0x2000 + 7 * 32).unwrap(), b"Linux");
    assert!(!l.uring_requires_owner());
}

#[test]
fn missing_native_wait_capability_only_escalates_its_original_submitter() {
    use std::io::Write;
    use std::net::{Ipv4Addr, TcpListener};
    for cancel in [false, true] {
        let (mut l, mut m, ring_fd, ring) = setup(8);
        l.vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let socket_fd = l.vfs.socket(2, 1, 0).unwrap();
        let socket = l.vfs.socket_fd(socket_fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        drop(socket);
        let ordinary = l.vfs.eventfd(0, 0).unwrap();
        let mut epoch = UringEpoch::default();
        let native = caller(&l, &m, &mut epoch, 7);
        let local = caller(&l, &m, &mut epoch, 8);
        let target: Arc<dyn IoWake> = Arc::new(Target);
        m.write(0x2000, &[0xa5; 8]).unwrap();
        for (pid, call, file, at) in [
            (7, &native, socket_fd, 0x2000),
            (8, &local, ordinary, 0x2100),
        ] {
            add(&mut m, &ring, read(file, at, pid as u64));
            assert!(matches!(
                call.start(
                    426,
                    [ring_fd as u64, 1, 0, 0, 0, 0],
                    &mut m,
                    pid,
                    &Arc::downgrade(&target),
                    None
                ),
                Some(IoAttempt::Complete(Ok(1)))
            ));
        }
        let mut native_wait = native
            .uring_background(7, &Arc::downgrade(&target))
            .unwrap();
        assert!(!native_wait.progress(&mut m).unwrap());
        assert!(l.uring_requires_owner_for(&m, 7));
        assert!(l.worker_uring_pending(&m, 8));
        assert!(!l.uring_requires_owner_for(&m, 8));
        let mut local_wait = local.uring_background(8, &Arc::downgrade(&target)).unwrap();
        assert!(local_wait.progress(&mut m).unwrap());
        l.vfs.write(ordinary, &9u64.to_le_bytes()).unwrap();
        assert!(local_wait.signal.ready());
        assert!(local_wait.progress(&mut m).unwrap());
        assert_eq!(cq(&mut m, &ring), (8, 8));
        if cancel {
            native.cancel_task_uring(m.instruction_identity().0, 7);
            assert!(native_wait.progress(&mut m).unwrap());
            assert_eq!(cq(&mut m, &ring), (7, -125));
            assert_eq!(m.read_array::<8>(0x2000).unwrap(), [0xa5; 8]);
        } else {
            let hub = trames_vfs::HostEvents::new().unwrap();
            let ready = IoSignal::new(0, Arc::downgrade(&target));
            let tcp = l.vfs.direct_network().get(socket_fd).unwrap().tcp.clone();
            let _subscription = hub
                .subscribe(tcp_wait_fd(&tcp).unwrap(), false, &ready)
                .unwrap();
            peer.write_all(b"x").unwrap();
            hub.wait(Some(Instant::now() + Duration::from_secs(2)))
                .unwrap();
            assert!(ready.ready());
            assert!(native_wait.progress(&mut m).unwrap());
            assert_eq!(cq(&mut m, &ring), (7, 1));
            assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"x");
        }
        assert!(!native_wait.active() && !local_wait.active());
        assert!(!l.uring_requires_owner());
    }
}

#[test]
fn queued_file_work_is_external_only_to_its_original_submitter() {
    struct Queue(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<crate::FileResult>)>);
    impl FileExecutor for Queue {
        fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<crate::FileResult>) {
            self.0.send((work, result)).unwrap();
        }
    }
    let (mut l, mut m, fd, ring) = setup(8);
    let file = l.vfs.open_at(-100, b"/scope-sync", 0x42, 0o600).unwrap();
    let ordinary = l.vfs.eventfd(0, 0).unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let disk = Arc::new(Queue(send));
    l.set_file_executor(disk.clone());
    let mut epoch = UringEpoch::default();
    let first = caller(&l, &m, &mut epoch, 7).with_file_executor(disk);
    let second = caller(&l, &m, &mut epoch, 8);
    let target: Arc<dyn IoWake> = Arc::new(Target);
    for (pid, entry, call) in [
        (7, sqe(3, file, 7), &first),
        (8, read(ordinary, 0x2100, 8), &second),
    ] {
        add(&mut m, &ring, entry);
        assert!(matches!(
            call.start(
                426,
                [fd as u64, 1, 0, 0, 0, 0],
                &mut m,
                pid,
                &Arc::downgrade(&target),
                None
            ),
            Some(IoAttempt::Complete(Ok(1)))
        ));
    }
    let mut native = first.uring_background(7, &Arc::downgrade(&target)).unwrap();
    let mut local = second
        .uring_background(8, &Arc::downgrade(&target))
        .unwrap();
    assert!(native.progress(&mut m).unwrap());
    assert!(local.progress(&mut m).unwrap());
    assert!(native.external());
    assert!(!local.external());
    assert!(!l.worker_uring_event(&m, 8));
    let (work, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
    result.complete(work.run());
    assert!(native.signal.ready());
    assert!(native.progress(&mut m).unwrap());
    assert!(!native.active());
    assert!(local.active());
    assert_eq!(cq(&mut m, &ring), (7, 0));
    second.cancel_task_uring(m.instruction_identity().0, 8);
    assert!(local.progress(&mut m).unwrap());
    assert!(!local.active());
    assert_eq!(cq(&mut m, &ring), (8, -125));
}
