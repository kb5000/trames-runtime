// SPDX-License-Identifier: GPL-3.0-or-later
//! Connected event-subsystem regressions, including late interest changes.
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
use trames_vfs::Vfs;
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn blocked(attempt: IoAttempt) -> PendingIo {
    match attempt {
        IoAttempt::Blocked(wait) => wait,
        _ => panic!("expected original retained wait"),
    }
}
fn done(attempt: IoAttempt) -> Result<u64, Errno> {
    match attempt {
        IoAttempt::Complete(result) => result,
        _ => panic!("expected completion"),
    }
}
#[test]
fn event_family_rearms_nested_original_graph_after_close_reuse_and_executor_handoff() {
    for number in [22, 441, 73, 72] {
        let mut v = Vfs::default();
        let leaf = v.eventfd(0, 0).unwrap();
        let child = v.epoll_create(0).unwrap();
        let root = v.epoll_create(0).unwrap();
        v.epoll_ctl(child, 1, leaf, 1, 11).unwrap();
        v.epoll_ctl(root, 1, child, 1, 42).unwrap();
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x1100, root.to_le_bytes()).unwrap();
        m.write_array(0x1104, 1u32.to_le_bytes()).unwrap();
        if number == 72 {
            m.write_array(0x1100, (1u64 << root).to_le_bytes()).unwrap();
        }
        let args = match number {
            22 => [root as u64, 0x1100, 1, u64::MAX, 0, 0],
            441 => [root as u64, 0x1100, 1, 0, 0, 0],
            73 => [0x1100, 1, 0, 0, 0, 0],
            _ => [root as u64 + 1, 0x1100, 0, 0, 0, 0],
        };
        let target: Arc<dyn IoWake> = Arc::new(Wake);
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let wait = blocked(
            direct
                .start(number, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        v.close(root).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), root);
        assert!(!wait.signal.ready(), "replacement is not the accepted root");
        let late = v.eventfd(0, 0).unwrap();
        v.epoll_ctl(child, 1, late, 1, 77).unwrap();
        assert!(
            wait.signal.ready(),
            "child change must reach the original root"
        );
        // No replacement Files or context may donate numeric FD authority.
        let fresh = DirectSyscalls::default();
        let wait = blocked(fresh.resume(wait, &mut m));
        assert!(!wait.signal.ready());
        v.write(late, &1u64.to_le_bytes()).unwrap();
        assert!(
            wait.signal.ready(),
            "rearm must subscribe to the late original leaf"
        );
        assert_eq!(done(fresh.resume(wait, &mut m)), Ok(1));
        match number {
            22 | 441 => assert_eq!(m.read_u64(0x1108).unwrap(), 42),
            73 => assert_eq!(m.read_array::<2>(0x1106).unwrap(), 1u16.to_le_bytes()),
            _ => assert_eq!(m.read_u64(0x1100).unwrap(), 1u64 << root),
        }
        assert_eq!(v.read(root, 8).unwrap(), 99u64.to_le_bytes());
    }
}
#[test]
fn nested_wait_cancellation_drops_child_subscriptions_and_oneshot_is_shared() {
    let mut v = Vfs::default();
    let event = v.eventfd(0, 0).unwrap();
    let child = v.epoll_create(0).unwrap();
    let root = v.epoll_create(0).unwrap();
    v.epoll_ctl(child, 1, event, 0xc0000001, 11).unwrap();
    v.epoll_ctl(root, 1, child, 1, 42).unwrap();
    let mut m = Memory::default();
    m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let direct = DirectSyscalls::new(v.direct_descriptors());
    let args = [root as u64, 0x1100, 1, u64::MAX, 0, 0];
    let wait = blocked(
        direct
            .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
            .unwrap(),
    );
    let signal = wait.signal.clone();
    drop(wait);
    v.write(event, &1u64.to_le_bytes()).unwrap();
    assert!(!signal.ready());
    assert_eq!(
        direct
            .descriptors
            .epoll(root)
            .unwrap()
            .unwrap()
            .epoll_wait(1)
            .unwrap(),
        vec![(1, 42)]
    );
    assert_eq!(
        v.epoll_wait(child, 1, |_, _| Ok(None)).unwrap(),
        vec![(1, 11)]
    );
    assert!(direct
        .descriptors
        .epoll(root)
        .unwrap()
        .unwrap()
        .epoll_wait(1)
        .unwrap()
        .is_empty());
    v.epoll_ctl(child, 3, event, 0xc0000001, 22).unwrap();
    assert_eq!(
        done(
            direct
                .start(22, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap()
        ),
        Ok(1)
    );
}

struct NativeWake(Arc<trames_vfs::HostEvents>);
impl IoWake for NativeWake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
    fn host_events(&self) -> std::io::Result<Option<Arc<trames_vfs::HostEvents>>> {
        Ok(Some(self.0.clone()))
    }
}
#[test]
fn generic_native_udp_poll_and_nested_epoll_share_original_observers_and_close_lifetime() {
    for number in [73, 22] {
        let mut v = Vfs::default();
        v.configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = v.socket(2, 2, 0).unwrap();
        let socket = v.socket_operation(fd).unwrap();
        socket
            .with_tcp_publication(|| socket.bind("127.0.0.1:0".parse().unwrap()))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let child = v.epoll_create(0).unwrap();
        let root = v.epoll_create(0).unwrap();
        v.epoll_ctl(child, 1, fd, 1, 11).unwrap();
        v.epoll_ctl(root, 1, child, 1, 42).unwrap();
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write_array(0x1100, fd.to_le_bytes()).unwrap();
        m.write_array(0x1104, 1u32.to_le_bytes()).unwrap();
        let args = if number == 73 {
            [0x1100, 1, 0, 0, 0, 0]
        } else {
            [root as u64, 0x1100, 1, u64::MAX, 0, 0]
        };
        let hub = trames_vfs::HostEvents::new().unwrap();
        let target: Arc<dyn IoWake> = Arc::new(NativeWake(hub.clone()));
        let direct = DirectSyscalls::new(v.direct_descriptors());
        let wait = blocked(
            direct
                .start(number, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        if number == 73 {
            v.close(fd).unwrap();
            assert_eq!(v.eventfd(9, 0).unwrap(), fd);
        }
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"original", address).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while !wait.signal.ready() && Instant::now() < until {
            hub.wait(Some(until)).unwrap();
        }
        assert!(
            wait.signal.ready(),
            "native observer must wake original wait"
        );
        assert_eq!(done(DirectSyscalls::default().resume(wait, &mut m)), Ok(1));
        if number == 22 {
            assert_eq!(m.read_u64(0x1108).unwrap(), 42);
        }
        assert_eq!(socket.recv(64, 0).unwrap().data, b"original");
        if number == 73 {
            assert_eq!(v.read(fd, 8).unwrap(), 9u64.to_le_bytes());
        }
    }
}
#[test]
fn generic_socket_host_registration_failure_is_not_a_guest_errno_or_checkpoint() {
    struct Broken;
    impl IoWake for Broken {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
        fn host_events(&self) -> std::io::Result<Option<Arc<trames_vfs::HostEvents>>> {
            Err(std::io::Error::other("original native observer failure"))
        }
    }
    let mut v = Vfs::default();
    v.configure_network(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let fd = v.socket(2, 2, 0).unwrap();
    v.socket_fd(fd)
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let mut m = Memory::default();
    m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write_array(0x1100, fd.to_le_bytes()).unwrap();
    m.write_array(0x1104, 1u32.to_le_bytes()).unwrap();
    let target: Arc<dyn IoWake> = Arc::new(Broken);
    let direct = DirectSyscalls::new(v.direct_descriptors());
    match direct
        .start(
            73,
            [0x1100, 1, 0, 0, 0, 0],
            &mut m,
            1,
            &Arc::downgrade(&target),
            None,
        )
        .unwrap()
    {
        IoAttempt::HostError(error) => {
            assert_eq!(error.to_string(), "original native observer failure")
        }
        _ => panic!("preserve the host backend failure"),
    }
}

fn vector_memory(length: u64) -> Memory {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x1000, 0x1100u64.to_le_bytes()).unwrap();
    memory.write_array(0x1008, length.to_le_bytes()).unwrap();
    memory
}
#[test]
fn current_position_v2_unix_and_signal_waits_keep_original_resources_and_captured_packets() {
    for kind in [1, 2, 5] {
        let mut v = Vfs::default();
        let [read, write] = v.socketpair(1, kind, 0).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_paths(v.path_queries())
            .with_resources(v.descriptor_factory());
        let target: Arc<dyn IoWake> = Arc::new(Wake);
        let mut memory = vector_memory(4);
        let args = [read as u64, 0x1000, 1, u64::MAX, 0, 0];
        let wait = blocked(
            direct
                .start_file_call(286, args, &mut memory, 1, &Arc::downgrade(&target))
                .unwrap(),
        );
        v.close(read).unwrap();
        assert_eq!(v.eventfd(77, 0).unwrap(), read);
        if kind != 1 {
            memory.write_array(0x1000, 0x1300u64.to_le_bytes()).unwrap();
        }
        v.write(write, b"old!").unwrap();
        assert!(wait.signal.ready());
        assert_eq!(
            done(DirectSyscalls::default().resume(wait, &mut memory)),
            Ok(4)
        );
        assert_eq!(memory.read_array::<4>(0x1100).unwrap(), *b"old!");
        assert_eq!(memory.read_array::<4>(0x1300).unwrap(), [0; 4]);
        assert_eq!(v.read(read, 8).unwrap(), 77u64.to_le_bytes());
    }
    struct Signals {
        pending: std::sync::atomic::AtomicBool,
        changed: Arc<trames_shared::Readiness>,
    }
    impl trames_vfs::SignalReader for Signals {
        fn poll(&self, mask: u64) -> (u16, [u64; 2]) {
            (
                u16::from(mask & 1 != 0 && self.pending.load(std::sync::atomic::Ordering::Relaxed)),
                [0; 2],
            )
        }
        fn take(&self, mask: u64) -> Option<[u8; 128]> {
            (mask & 1 != 0
                && self
                    .pending
                    .swap(false, std::sync::atomic::Ordering::Relaxed))
            .then(|| {
                let mut record = [0; 128];
                record[..4].copy_from_slice(&1u32.to_le_bytes());
                record
            })
        }
        fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
            vec![self.changed.subscribe(signal)]
        }
    }
    let mut v = Vfs::default();
    let fd = v.signalfd(-1, 1, 0).unwrap();
    let reader = Arc::new(Signals {
        pending: false.into(),
        changed: Arc::default(),
    });
    let direct = DirectSyscalls::new(v.direct_descriptors())
        .with_paths(v.path_queries())
        .with_signal_reader(reader.clone());
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let mut memory = vector_memory(128);
    let args = [fd as u64, 0x1000, 1, u64::MAX, 0, 0];
    let wait = blocked(
        direct
            .start_file_call(286, args, &mut memory, 1, &Arc::downgrade(&target))
            .unwrap(),
    );
    v.close(fd).unwrap();
    assert_eq!(v.eventfd(88, 0).unwrap(), fd);
    memory.write_array(0x1000, 0x1300u64.to_le_bytes()).unwrap();
    reader
        .pending
        .store(true, std::sync::atomic::Ordering::Relaxed);
    reader.changed.notify_atomic();
    assert!(wait.signal.ready());
    assert_eq!(
        done(DirectSyscalls::default().resume(wait, &mut memory)),
        Ok(128)
    );
    assert_eq!(memory.read_array::<4>(0x1100).unwrap(), 1u32.to_le_bytes());
    assert_eq!(memory.read_array::<4>(0x1300).unwrap(), [0; 4]);
}

#[test]
fn current_position_v2_native_tcp_and_udp_retain_transport_timeout_and_post_write_sync() {
    use std::io::{Read, Write};
    for tcp in [false, true] {
        let mut v = Vfs::default();
        v.configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = v.socket(2, if tcp { 1 } else { 2 }, 0).unwrap();
        let socket = v.socket_operation(fd).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let address = if tcp {
            listener.local_addr().unwrap()
        } else {
            udp.local_addr().unwrap()
        };
        let result = socket.with_tcp_publication(|| socket.connect(address));
        assert!(matches!(result, Ok(()) | Err(trames_net::NetError(115))));
        let mut peer = if tcp {
            Some(listener.accept().unwrap().0)
        } else {
            None
        };
        if tcp {
            assert_eq!(socket.connect_complete(), Ok(true));
            socket.refresh_tcp();
        }
        socket.set_io_timeout(true, Some(Duration::from_secs(30)));
        socket.refresh_tcp();
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_paths(v.path_queries())
            .with_resources(v.descriptor_factory())
            .with_network(v.direct_network());
        let hub = trames_vfs::HostEvents::new().unwrap();
        let target: Arc<dyn IoWake> = Arc::new(NativeWake(hub.clone()));
        let mut memory = vector_memory(4);
        let args = [fd as u64, 0x1000, 1, u64::MAX, 0, 0];
        let wait = blocked(
            direct
                .start_file_call(286, args, &mut memory, 1, &Arc::downgrade(&target))
                .unwrap(),
        );
        assert!(
            wait.deadline.is_some(),
            "original receive timeout belongs to v2 wait"
        );
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), fd);
        if !tcp {
            memory.write_array(0x1000, 0x1300u64.to_le_bytes()).unwrap();
        }
        if let Some(peer) = &mut peer {
            peer.write_all(b"old!").unwrap();
        } else {
            udp.send_to(b"old!", socket.local_addr().unwrap()).unwrap();
        }
        let until = Instant::now() + Duration::from_secs(2);
        while !wait.signal.ready() && Instant::now() < until {
            hub.wait(Some(until)).unwrap();
        }
        assert!(wait.signal.ready());
        assert_eq!(
            done(DirectSyscalls::default().resume(wait, &mut memory)),
            Ok(4)
        );
        assert_eq!(memory.read_array::<4>(0x1100).unwrap(), *b"old!");
        assert_eq!(memory.read_array::<4>(0x1300).unwrap(), [0; 4]);
        // A second accepted OFD reaches its existing sync error only after
        // exactly one real transport write, independently of the reused FD.
        let second = v.socket(2, if tcp { 1 } else { 2 }, 0).unwrap();
        let outgoing = v.socket_operation(second).unwrap();
        let result = outgoing.with_tcp_publication(|| outgoing.connect(address));
        assert!(matches!(result, Ok(()) | Err(trames_net::NetError(115))));
        let mut second_peer = if tcp {
            Some(listener.accept().unwrap().0)
        } else {
            None
        };
        if tcp {
            assert_eq!(outgoing.connect_complete(), Ok(true));
            outgoing.refresh_tcp();
        }
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_paths(v.path_queries())
            .with_resources(v.descriptor_factory());
        memory.write_array(0x1000, 0x1100u64.to_le_bytes()).unwrap();
        memory.write(0x1100, b"sent").unwrap();
        let args = [second as u64, 0x1000, 1, u64::MAX, 0, 2];
        assert_eq!(
            done(
                direct
                    .start_file_call(287, args, &mut memory, 1, &Arc::downgrade(&target))
                    .unwrap()
            ),
            Err(Errno(22))
        );
        let mut bytes = [0; 4];
        if let Some(peer) = &mut second_peer {
            peer.read_exact(&mut bytes).unwrap();
        } else {
            assert_eq!(udp.recv(&mut bytes).unwrap(), 4);
        }
        assert_eq!(&bytes, b"sent");
    }
}

#[test]
fn v2_socket_sync_checkpoint_keeps_terminal_byte_effect_and_original_ofd() {
    let mut v = Vfs::default();
    v.configure_network(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let fd = v.socket(2, 2, 0).unwrap();
    let socket = v.socket_operation(fd).unwrap();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket
        .with_tcp_publication(|| socket.connect(peer.local_addr().unwrap()))
        .unwrap();
    let direct = DirectSyscalls::new(v.direct_descriptors()).with_resources(v.descriptor_factory());
    let mut memory = vector_memory(4);
    memory.write(0x1100, b"once").unwrap();
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let args = [fd as u64, 0x1000, 1, u64::MAX, 0, 2];
    let call = match direct
        .start_file_call(287, args, &mut memory, 1, &Arc::downgrade(&target))
        .unwrap()
    {
        IoAttempt::SocketCheckpoint(call) => call,
        _ => panic!("only the absent canonical sync provider may defer"),
    };
    let mut bytes = [0; 8];
    assert_eq!(peer.recv(&mut bytes).unwrap(), 4);
    assert_eq!(&bytes[..4], b"once");
    v.close(fd).unwrap();
    assert_eq!(v.memfd_create(b"replacement", 0).unwrap(), fd);
    let fresh = DirectSyscalls::default().with_paths(v.path_queries());
    assert_eq!(
        done(fresh.start_retained_socket(call, &mut memory, 1, &Arc::downgrade(&target))),
        Err(Errno(22))
    );
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.recv(&mut bytes).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn nested_virtual_udp_wait_uses_original_stack_deadline_without_owner_or_service_thread() {
    fn case() {
        let fabric = trames_net::Fabric::new().unwrap();
        let mut a = Vfs::default();
        let mut b = Vfs::default();
        a.configure_virtual_network(&fabric, 2, trames_net::NetworkMode::Outbound)
            .unwrap();
        b.configure_virtual_network(&fabric, 3, trames_net::NetworkMode::Outbound)
            .unwrap();
        let fd = a.socket(2, 2, 0).unwrap();
        let peer = b.socket(2, 2, 0).unwrap();
        let socket = a.socket_operation(fd).unwrap();
        let sender = b.socket_operation(peer).unwrap();
        socket
            .with_tcp_publication(|| socket.bind("10.0.0.2:18002".parse().unwrap()))
            .unwrap();
        sender
            .with_tcp_publication(|| sender.bind("10.0.0.3:18003".parse().unwrap()))
            .unwrap();
        let child = a.epoll_create(0).unwrap();
        let root = a.epoll_create(0).unwrap();
        a.epoll_ctl(child, 1, fd, 1, 11).unwrap();
        a.epoll_ctl(root, 1, child, 1, 42).unwrap();
        let direct = DirectSyscalls::new(a.direct_descriptors());
        let mut memory = vector_memory(4);
        let target: Arc<dyn IoWake> = Arc::new(Wake);
        let args = [root as u64, 0x1100, 1, u64::MAX, 0, 0];
        let wait = blocked(
            direct
                .start(22, args, &mut memory, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        assert!(
            wait.wake_deadline().is_some(),
            "original fabric timer must remain schedulable"
        );
        sender
            .send(b"data", 0, Some("10.0.0.2:18002".parse().unwrap()))
            .unwrap();
        assert_eq!(
            done(DirectSyscalls::default().resume(wait, &mut memory)),
            Ok(1)
        );
        assert_eq!(memory.read_u64(0x1108).unwrap(), 42);
        assert_eq!(socket.recv(4, 0).unwrap().data, b"data");
    }
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(case)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn stable_socket_data_and_would_block_do_not_self_wake_topology_waiters() {
    let mut v = Vfs::default();
    v.configure_network(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let fd = v.socket(2, 2, 0).unwrap();
    let socket = v.socket_operation(fd).unwrap();
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(1, Arc::downgrade(&target));
    let _subscription = socket.subscribe_changes(&signal);
    socket
        .with_tcp_publication(|| socket.bind("127.0.0.1:0".parse().unwrap()))
        .unwrap();
    assert!(
        signal.ready(),
        "native/guest selection changes the original event-source set"
    );
    signal.reset();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..32 {
        assert_eq!(
            socket
                .with_tcp_publication(|| socket.recv(1, 0))
                .err()
                .unwrap()
                .0,
            11
        );
        assert_eq!(
            socket.with_tcp_publication(|| socket.send(
                b"data",
                0,
                Some(peer.local_addr().unwrap())
            )),
            Ok(4)
        );
        assert!(
            !signal.ready(),
            "stable data retries must not create structural self-wakes"
        );
    }
}
