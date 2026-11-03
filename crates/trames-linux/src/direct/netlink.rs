// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual shared netlink I/O, readiness and worker ruleset publication.
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vfs::Vfs;
struct Target;
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn request() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&32u32.to_le_bytes());
    bytes[4..6].copy_from_slice(&18u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
    bytes[8..12].copy_from_slice(&42u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes
}
fn setup() -> (Vfs, u32, DirectSyscalls, Memory, Arc<dyn IoWake>) {
    let mut v = Vfs::default();
    v.configure_network(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let fd = v.socket(16, 3, 0).unwrap();
    let d = DirectSyscalls::new(v.direct_descriptors()).with_resources(v.descriptor_factory());
    let mut m = Memory::default();
    m.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
    m.write(0x1400, &request()).unwrap();
    for (at, value) in [
        (0x1010, 0x1300u64),
        (0x1018, 1),
        (0x1300, 0x1400),
        (0x1308, 32),
    ] {
        m.write_array(at, value.to_le_bytes()).unwrap();
    }
    (v, fd, d, m, Arc::new(Target))
}
fn complete(attempt: Option<IoAttempt>) -> Result<u64, Errno> {
    match attempt {
        Some(IoAttempt::Complete(result)) => result,
        _ => panic!("netlink operation did not complete locally"),
    }
}
#[test]
fn reply_notifications_allow_reentering_the_original_socket_read_and_control() {
    use std::sync::mpsc;
    struct Readback {
        socket: Arc<trames_net::Socket>,
        done: mpsc::Sender<()>,
    }
    impl IoWake for Readback {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            let reply = self.socket.recv(1024, 0).unwrap();
            assert_eq!(&reply.data[4..6], &16u16.to_le_bytes());
            self.socket.set_option(270, 11, 1).unwrap();
            self.done.send(()).unwrap();
        }
    }
    let (v, fd, _, _, _) = setup();
    let socket = v.socket_fd(fd).unwrap();
    let (send, recv) = mpsc::channel();
    let target: Arc<dyn IoWake> = Arc::new(Readback {
        socket: socket.clone(),
        done: send,
    });
    let signal = IoSignal::new(1, Arc::downgrade(&target));
    let _subscription = socket.subscribe(&signal).unwrap();
    let worker = std::thread::spawn(move || socket.send_bytes(&request(), 0, None));
    recv.recv_timeout(Duration::from_secs(3))
        .expect("notification ran under socket/queue lock");
    assert_eq!(worker.join().unwrap(), Ok(32));
}
#[test]
fn route_scalar_message_vector_and_batch_queries_complete_on_original_socket() {
    for number in [64, 66, 206, 211, 269] {
        let (v, fd, d, mut m, target) = setup();
        let a = match number {
            64 | 206 => [fd as u64, 0x1400, 32, 0, 0, 0],
            66 => [fd as u64, 0x1300, 1, 0, 0, 0],
            211 => [fd as u64, 0x1000, 0, 0, 0, 0],
            _ => [fd as u64, 0x1000, 1, 0, 0, 0],
        };
        let attempt = if matches!(number, 64 | 66) {
            d.start(number, a, &mut m, 1, &Arc::downgrade(&target), None)
        } else {
            d.start_socket_control(number, a, &mut m, 1, &Arc::downgrade(&target))
        };
        assert_eq!(complete(attempt), Ok(if number == 269 { 1 } else { 32 }));
        if number == 269 {
            assert_eq!(m.read_array::<4>(0x1038).unwrap(), 32u32.to_le_bytes());
        }
        assert!(
            complete(d.start(
                63,
                [fd as u64, 0x1800, 1024, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
                None
            ))
            .unwrap()
                >= 32
        );
        assert_eq!(m.read_array::<2>(0x1804).unwrap(), 16u16.to_le_bytes());
        assert_eq!(m.read_array::<4>(0x1808).unwrap(), 42u32.to_le_bytes());
        assert_eq!(m.read_array::<4>(0x1814).unwrap(), 1u32.to_le_bytes());
        assert_eq!(v.socket_fd(fd).unwrap().poll(1).unwrap(), 0);
    }
}
#[test]
fn netlink_receive_and_poll_waits_wake_without_reactor_and_survive_close_reuse() {
    let (mut v, fd, d, mut m, target) = setup();
    let alias = v.dup(fd, 0, false).unwrap();
    let weak = Arc::downgrade(&v.socket_fd(fd).unwrap());
    let pending = match d.start(
        63,
        [fd as u64, 0x1800, 1024, 0, 0, 0],
        &mut m,
        1,
        &Arc::downgrade(&target),
        None,
    ) {
        Some(IoAttempt::Blocked(wait)) => wait,
        _ => panic!("netlink receive did not park on its resource"),
    };
    assert!(!pending.external_wait());
    assert!(!pending.signal.ready());
    let epoll = v.epoll_create(0).unwrap();
    assert_eq!(
        d.invoke_epoll_control(21, [epoll as u64, 1, fd as u64, 0x1600, 0, 0], &m),
        Some(Ok(0))
    ); // initially an empty event mask
    m.write_array(0x1600, 1u32.to_le_bytes()).unwrap();
    m.write_array(0x1608, 77u64.to_le_bytes()).unwrap();
    assert_eq!(
        d.invoke_epoll_control(21, [epoll as u64, 3, fd as u64, 0x1600, 0, 0], &m),
        Some(Ok(0))
    );
    v.close(fd).unwrap();
    assert_eq!(v.eventfd(0, 0).unwrap(), fd);
    assert_eq!(
        complete(d.start(
            64,
            [alias as u64, 0x1400, 32, 0, 0, 0],
            &mut m,
            2,
            &Arc::downgrade(&target),
            None
        )),
        Ok(32)
    );
    assert!(pending.signal.ready());
    assert_eq!(
        complete(d.start(
            22,
            [epoll as u64, 0x1700, 1, 0, 0, 0],
            &mut m,
            2,
            &Arc::downgrade(&target),
            None
        )),
        Ok(1)
    );
    assert_eq!(m.read_u64(0x1708).unwrap(), 77);

    assert!(complete(Some(d.resume(pending, &mut m))).unwrap() >= 32);
    v.close(alias).unwrap();
    assert!(
        weak.upgrade().is_none(),
        "poll snapshot must not pin final netlink close"
    );
}
#[test]
fn nf_tables_batch_completes_every_message_on_worker() {
    let mut v = Vfs::default();
    let fd = v.socket(16, 3, 12).unwrap();
    let d = DirectSyscalls::new(v.direct_descriptors()).with_resources(v.descriptor_factory());
    let mut m = Memory::default();
    m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    // An ordinary NF query precedes a batch marker in the next mmsghdr.
    for (at, value) in [
        (0x1010, 0x1300u64),
        (0x1018, 1),
        (0x1050, 0x1310),
        (0x1058, 1),
        (0x1300, 0x1400),
        (0x1308, 20),
        (0x1310, 0x1420),
        (0x1318, 20),
    ] {
        m.write_array(at, value.to_le_bytes()).unwrap();
    }
    for (at, kind) in [(0x1400, 0x0a10u16), (0x1420, 16u16)] {
        let mut bytes = [0; 20];
        bytes[..4].copy_from_slice(&20u32.to_le_bytes());
        bytes[4..6].copy_from_slice(&kind.to_le_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        m.write(at, &bytes).unwrap();
    }
    let target: Arc<dyn IoWake> = Arc::new(Target);
    let a = [fd as u64, 0x1000, 2, 0, 0, 0];
    assert_eq!(
        complete(d.start_socket_control(269, a, &mut m, 1, &Arc::downgrade(&target))),
        Ok(2)
    );
    assert_eq!(m.read_array::<4>(0x1038).unwrap(), 20u32.to_le_bytes());
    assert_eq!(m.read_array::<4>(0x1078).unwrap(), 20u32.to_le_bytes());
}
