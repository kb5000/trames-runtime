// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-accepted-call IP message state; no socket or Files algorithm lock.
use super::*;
use crate::network::data::Prepared;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

pub(super) fn number(number: u32) -> bool {
    matches!(number, 206 | 207 | 211 | 212 | 269)
}

pub(super) struct Message {
    state: Mutex<State>,
    pipe: AtomicBool,
}
#[derive(Default)]
struct State {
    completed: u64,
    requested: u64,
    active: Option<Prepared>,
    terminal: Option<Result<u64, Errno>>,
    recheck: bool,
}
impl Message {
    pub fn raw(
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        flags: u32,
    ) -> Result<Self, Errno> {
        Ok(Self {
            pipe: AtomicBool::new(false),
            state: Mutex::new(State {
                active: Some(Prepared::raw(number, args, memory, flags)?),
                ..State::default()
            }),
        })
    }
    pub fn new(
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        address_size: usize,
    ) -> Result<Self, Errno> {
        let active = if number == 269 {
            None
        } else {
            Some(Prepared::new(number, args, memory, address_size)?)
        };
        Ok(Self {
            pipe: AtomicBool::new(false),
            state: Mutex::new(State {
                active,
                ..State::default()
            }),
        })
    }
    pub fn pipe_signal(&self) -> bool {
        self.pipe.load(Ordering::Relaxed)
    }
    pub fn progress(
        &self,
        socket: &trames_vfs::SocketOperation,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        factory: &trames_vfs::DescriptorFactory,
        owner: bool,
    ) -> Option<Result<u64, Errno>> {
        let mut deferred = false;
        let result = self.progress_context(
            socket,
            number,
            a,
            memory,
            owner,
            &mut deferred,
            |bytes, flags, peer| factory.send_socket_bytes(socket, bytes, flags, peer),
        );
        (!deferred).then_some(result)
    }
    #[cfg(test)]
    fn progress_with(
        &self,
        socket: &trames_vfs::SocketOperation,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        send: impl FnMut(&[u8], u32, Option<&[u8]>) -> Result<usize, Errno>,
    ) -> Result<u64, Errno> {
        self.progress_context(socket, number, a, memory, false, &mut false, send)
    }
    #[allow(clippy::too_many_arguments)]
    fn progress_context(
        &self,
        socket: &trames_vfs::SocketOperation,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        owner: bool,
        deferred: &mut bool,
        mut send: impl FnMut(&[u8], u32, Option<&[u8]>) -> Result<usize, Errno>,
    ) -> Result<u64, Errno> {
        let mut state = self.state.lock().unwrap();
        let batch = number == 269;
        let flags = socket_flags(number, a);
        let count = if batch {
            (a[2] as u32).min(1024) as u64
        } else {
            1
        };
        loop {
            if let Some(result) = state.terminal {
                return result;
            }
            if state.completed == count {
                state.terminal = Some(Ok(count));
                continue;
            }
            let result = (|| {
                let header = if batch {
                    a[1].checked_add(state.completed * 64).ok_or(Errno(14))?
                } else {
                    a[1]
                };
                if state.active.is_none() {
                    state.requested = crate::network_batch::requested(memory, header)?;
                    state.active = Some(Prepared::new(
                        211,
                        [a[0], header, flags as u64, 0, 0, 0],
                        memory,
                        socket.address_size(),
                    )?);
                }
                if !owner && !state.active.as_ref().unwrap().worker_admitted(socket) {
                    *deferred = true;
                    return Err(Errno(11));
                }
                if state.recheck {
                    state.active.as_ref().unwrap().recheck(memory)?;
                    state.recheck = false;
                }
                let mut transfer = || {
                    state
                        .active
                        .as_ref()
                        .unwrap()
                        .progress(socket, memory, &mut send)
                };
                // Preserve the existing per-message publication boundary, not
                // a batch-wide socket lock. No Files lookup enters this guard.
                let sent = if matches!(number, 206 | 211 | 269) && !socket.is_netlink() {
                    socket.with_tcp_publication(transfer)
                } else {
                    transfer()
                }?;
                if batch {
                    // The original ABI copies msg_len after transport effects.
                    memory
                        .write(
                            header.checked_add(56).ok_or(Errno(14))?,
                            &(sent as u32).to_le_bytes(),
                        )
                        .map_err(|_| Errno(14))?;
                }
                Ok(sent)
            })();
            if *deferred {
                return Err(Errno(11));
            }
            match result {
                Ok(sent) if !batch => state.terminal = Some(Ok(sent)),
                Ok(sent) => {
                    state.completed += 1;
                    state.active = None;
                    if sent < state.requested {
                        state.terminal = Some(Ok(state.completed));
                    }
                }
                Err(Errno(11)) if state.completed == 0 => {
                    state.recheck = true;
                    return Err(Errno(11));
                }
                Err(error) => {
                    if error.0 == 32 && signals_pipe(number, a) {
                        self.pipe.store(true, Ordering::Relaxed);
                    }
                    state.terminal = Some(if state.completed == 0 {
                        Err(error)
                    } else {
                        Ok(state.completed)
                    });
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    use trames_vfs::{NetworkMode, Vfs};
    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.map(0x3000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1400, b"abcxyz").unwrap();
        for i in 0..2 {
            for (at, value) in [
                (0x1010 + i * 64, 0x1300 + i * 16),
                (0x1018 + i * 64, 1),
                (0x1300 + i * 16, 0x1400 + i * 3),
                (0x1308 + i * 16, 3),
            ] {
                m.write_array(at, value.to_le_bytes()).unwrap();
            }
        }
        m
    }
    fn socket() -> (Vfs, u32, trames_vfs::SocketOperation) {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 2, 0).unwrap();
        let op = v.socket_operation(fd).unwrap();
        (v, fd, op)
    }
    #[test]
    fn raw_ip_nonblocking_timeout_and_netlink_exclusion_use_existing_semantics() {
        let (mut v, fd, socket) = socket();
        let netlink = v.socket(16, 3, 0).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let d = DirectSyscalls::new(v.direct_descriptors()).with_resources(v.descriptor_factory());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        for number in [63, 64, 65, 66] {
            assert!(d.supports_call(number, [netlink as u64, u64::MAX, 1, 0, 0, 0]));
            assert!(matches!(
                d.start(
                    number,
                    [netlink as u64, u64::MAX, 1, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None
                ),
                Some(IoAttempt::Complete(Err(Errno(14))))
            ));
        }
        for number in [63, 65] {
            for timeout in [false, true] {
                v.set_nonblocking(fd, !timeout).unwrap();
                socket.set_io_timeout(true, timeout.then_some(Duration::ZERO));
                let a = if number == 63 {
                    [fd as u64, 0x3000, 3, 0, 0, 0]
                } else {
                    [fd as u64, 0x1300, 1, 0, 0, 0]
                };
                assert!(matches!(
                    d.start(number, a, &mut m, 1, &Arc::downgrade(&target), None),
                    Some(IoAttempt::Complete(Err(Errno(11))))
                ));
            }
        }
    }
    #[test]
    fn virtual_tcp_raw_epipe_retains_terminal_result_through_owner_handoff_and_fd_reuse() {
        for number in [64, 66] {
            let mut v = Vfs::default();
            v.configure_local_fabric(NetworkMode::Full).unwrap();
            let listener = v.socket(2, 1, 0).unwrap();
            let l = v.socket_fd(listener).unwrap();
            l.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            l.listen(1).unwrap();
            let fd = v.socket(2, 1, 0).unwrap();
            let socket = v.socket_fd(fd).unwrap();
            assert!(matches!(
                socket.connect(l.local_addr().unwrap()),
                Ok(()) | Err(trames_net::NetError(115))
            ));
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                match v.accept(listener, 0) {
                    Ok(_) => break,
                    Err(Errno(11)) => {
                        assert!(Instant::now() < until);
                        std::thread::yield_now();
                    }
                    other => panic!("{other:?}"),
                }
            }
            while !socket.connect_complete().unwrap() {
                assert!(Instant::now() < until);
                std::thread::yield_now();
            }
            socket.shutdown(1).unwrap();
            drop(socket);
            let d = DirectSyscalls::new(v.direct_descriptors())
                .with_network(v.direct_network())
                .with_resources(v.descriptor_factory());
            let mut m = memory();
            let target: Arc<dyn IoWake> = Arc::new(Target);
            let a = if number == 64 {
                [fd as u64, 0x1400, 3, 0, 0, 0]
            } else {
                [fd as u64, 0x1300, 1, 0, 0, 0]
            };
            let call = match d
                .start(number, a, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap()
            {
                IoAttempt::SocketCheckpoint(call) => call,
                _ => panic!("raw EPIPE must retain task handoff"),
            };
            assert!(call.pipe_signal());
            v.close(fd).unwrap();
            assert_eq!(v.eventfd(0, 0).unwrap(), fd);
            assert!(matches!(
                d.retry_owned_socket(call, &mut m, 1, &Arc::downgrade(&target)),
                IoAttempt::Complete(Err(Errno(32)))
            ));
        }
    }
    #[test]
    fn raw_ip_bytes_keep_one_packet_and_the_original_vector_fault_order() {
        let (v, fd, socket) = socket();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        socket.connect(peer.local_addr().unwrap()).unwrap();
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_membership(v.shared_files())
            .with_resources(v.descriptor_factory());
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        for (at, value) in [
            (0x1300, 0x1400u64),
            (0x1308, 1),
            (0x1310, 0x1401),
            (0x1318, 2),
        ] {
            m.write_array(at, value.to_le_bytes()).unwrap();
        }
        let invoke = |number, args, memory: &mut Memory| {
            assert!(direct.supports_call(number, args));
            match direct
                .start(number, args, memory, 1, &Arc::downgrade(&target), None)
                .unwrap()
            {
                IoAttempt::Complete(result) => result,
                _ => panic!("ready raw IP call did not complete"),
            }
        };
        assert_eq!(invoke(66, [fd as u64, 0x1300, 2, 0, 0, 0], &mut m), Ok(3));
        let mut bytes = [0; 16];
        assert_eq!(peer.recv(&mut bytes).unwrap(), 3);
        assert_eq!(&bytes[..3], b"abc");
        peer.send_to(b"abcdef", socket.local_addr().unwrap())
            .unwrap();
        peer.send_to(b"next", socket.local_addr().unwrap()).unwrap();
        trames_net::wait(&[(socket.socket_handle(), 1)], Duration::from_secs(2)).unwrap();
        assert_eq!(
            invoke(65, [fd as u64, 0x1300, 1025, 0, 0, 0], &mut m),
            Err(Errno(22))
        );
        m.write_array(0x1310, u64::MAX.to_le_bytes()).unwrap();
        assert_eq!(
            invoke(65, [fd as u64, 0x1300, 2, 0, 0, 0], &mut m),
            Err(Errno(14))
        );
        m.write_array(0x1310, 0x1401u64.to_le_bytes()).unwrap();
        assert_eq!(invoke(65, [fd as u64, 0x1300, 2, 0, 0, 0], &mut m), Ok(3));
        assert_eq!(m.read_array::<3>(0x1400).unwrap(), *b"abc");
        assert_eq!(invoke(63, [fd as u64, 0x1500, 16, 0, 0, 0], &mut m), Ok(4));
        assert_eq!(m.read_array::<4>(0x1500).unwrap(), *b"next");
        m.write_array(0x1310, u64::MAX.to_le_bytes()).unwrap();
        assert_eq!(
            invoke(66, [fd as u64, 0x1300, 2, 0, 0, 0], &mut m),
            Err(Errno(14))
        );
        assert_eq!(
            invoke(66, [fd as u64, 0x1300, 1025, 0, 0, 0], &mut m),
            Err(Errno(22))
        );
        for number in [63, 64, 65, 66] {
            let a = [fd as u64, u64::MAX, 1, 0, 0, 0];
            assert!(matches!(
                Prepared::raw(number, a, &m, if matches!(number, 63 | 65) { 1 } else { 0 }),
                Err(Errno(14))
            ));
        }
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.recv(&mut bytes).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn parked_raw_ip_call_retains_scalar_or_vector_outputs_and_full_ofd() {
        for number in [63, 65] {
            for fault in [false, true] {
                let (mut v, fd, socket) = socket();
                socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                let address = socket.local_addr().unwrap();
                drop(socket);
                let direct = DirectSyscalls::new(v.direct_descriptors())
                    .with_resources(v.descriptor_factory());
                let target: Arc<dyn IoWake> = Arc::new(Target);
                let mut m = memory();
                m.write_array(0x1300, 0x3000u64.to_le_bytes()).unwrap();
                let args = if number == 63 {
                    [fd as u64, 0x3000, 3, 0, 0, 0]
                } else {
                    [fd as u64, 0x1300, 1, 0, 0, 0]
                };
                let call = match direct
                    .start(number, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap()
                {
                    IoAttempt::SocketCheckpoint(call) => call,
                    _ => panic!("expected accepted raw IP wait"),
                };
                let old = call.socket_handle().unwrap();
                v.close(fd).unwrap();
                assert_eq!(v.eventfd(0, 0).unwrap(), fd);
                m.write_array(0x1300, 0x1500u64.to_le_bytes()).unwrap();
                if fault {
                    m.unmap(0x3000, PAGE_SIZE).unwrap();
                }
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                peer.send_to(b"abc", address).unwrap();
                trames_net::wait(&[(old.clone(), 1)], Duration::from_secs(2)).unwrap();
                match direct.retry_owned_socket(call, &mut m, 1, &Arc::downgrade(&target)) {
                    IoAttempt::Complete(result) => {
                        assert_eq!(result, if fault { Err(Errno(14)) } else { Ok(3) })
                    }
                    _ => panic!("raw receive did not finish"),
                }
                if fault {
                    assert_eq!(old.recv(3, 0).unwrap().data, b"abc");
                } else {
                    assert_eq!(m.read_array::<3>(0x3000).unwrap(), *b"abc");
                    assert_eq!(m.read_array::<3>(0x1500).unwrap(), [0; 3]);
                }
            }
        }
    }
    #[test]
    fn ip_admission_preserves_empty_batch_errors_nonblocking_timeout_and_netlink_boundary() {
        let (mut v, fd, socket) = socket();
        let event = v.eventfd(0, 0).unwrap();
        let netlink = v.socket(16, 3, 0).unwrap();
        let d = DirectSyscalls::default().with_resources(v.descriptor_factory());
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        for (a, result) in [
            ([999, 0, 0, 0x8000_0000, 0, 0], Err(Errno(22))),
            ([999, 0, 0, 0, 0, 0], Err(Errno(9))),
            ([event as u64, 0, 0, 0, 0, 0], Err(Errno(88))),
            ([fd as u64, u64::MAX, 0, 0, 0, 0], Ok(0)),
        ] {
            assert!(
                matches!(d.start_socket_control(269,a,&mut m,1,&Arc::downgrade(&target)),Some(IoAttempt::Complete(value)) if value==result)
            );
        }
        assert!(matches!(
            d.start_socket_control(
                211,
                [netlink as u64, u64::MAX, 0, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target)
            ),
            Some(IoAttempt::Complete(Err(Errno(14))))
        ));
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        for timeout in [false, true] {
            if timeout {
                socket.set_io_timeout(true, Some(Duration::ZERO));
            }
            assert!(matches!(
                d.start_socket_control(
                    207,
                    [fd as u64, 0x3000, 3, if timeout { 0 } else { 0x40 }, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target)
                ),
                Some(IoAttempt::Complete(Err(Errno(11))))
            ));
        }
    }
    #[test]
    fn batch_retains_only_the_accepted_item_and_never_replays_terminal_effects() {
        let (_v, fd, socket) = socket();
        let mut m = memory();
        let args = [fd as u64, 0x1000, 2, 0, 0, 0];
        let batch = Message::new(269, args, &m, 16).unwrap();
        assert_eq!(
            batch.progress_with(&socket, 269, args, &mut m, |bytes, _, _| {
                assert_eq!(bytes, b"abc");
                Err(Errno(11))
            }),
            Err(Errno(11))
        );
        m.write(0x1400, b"BADnew").unwrap();
        m.write_array(0x1010, u64::MAX.to_le_bytes()).unwrap();
        let mut delivered = Vec::new();
        assert_eq!(
            batch.progress_with(&socket, 269, args, &mut m, |bytes, _, _| {
                delivered.push(bytes.to_vec());
                Ok(bytes.len())
            }),
            Ok(2)
        );
        assert_eq!(delivered, [b"abc".to_vec(), b"new".to_vec()]);
        assert_eq!(m.read_array::<4>(0x1038).unwrap(), 3u32.to_le_bytes());
        assert_eq!(m.read_array::<4>(0x1078).unwrap(), 3u32.to_le_bytes());
        assert_eq!(
            batch.progress_with(&socket, 269, args, &mut m, |_, _, _| panic!(
                "terminal replay"
            )),
            Ok(2)
        );
    }
    #[test]
    fn batch_partial_errors_short_send_and_post_transport_fault_preserve_progress() {
        let (_v, fd, socket) = socket();
        for error in [11, 14, 32] {
            for flags in [0, 0x4000] {
                let mut m = memory();
                let a = [fd as u64, 0x1000, 2, flags, 0, 0];
                let batch = Message::new(269, a, &m, 16).unwrap();
                let mut calls = 0;
                assert_eq!(
                    batch.progress_with(&socket, 269, a, &mut m, |bytes, _, _| {
                        calls += 1;
                        if calls == 1 {
                            Ok(bytes.len())
                        } else {
                            Err(Errno(error))
                        }
                    }),
                    Ok(1)
                );
                assert_eq!(calls, 2);
                assert_eq!(batch.pipe_signal(), error == 32 && flags == 0);
                assert_eq!(
                    batch
                        .progress_with(&socket, 269, a, &mut m, |_, _, _| panic!("partial replay")),
                    Ok(1)
                );
            }
        }
        let mut m = memory();
        let a = [fd as u64, 0x1000, 2, 0, 0, 0];
        let batch = Message::new(269, a, &m, 16).unwrap();
        assert_eq!(
            batch.progress_with(&socket, 269, a, &mut m, |_, _, _| Ok(1)),
            Ok(1)
        );
        assert_eq!(m.read_array::<4>(0x1038).unwrap(), 1u32.to_le_bytes());
        let mut m = memory();
        m.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        let batch = Message::new(269, a, &m, 16).unwrap();
        let mut effects = 0;
        assert_eq!(
            batch.progress_with(&socket, 269, a, &mut m, |_, _, _| {
                effects += 1;
                Ok(3)
            }),
            Err(Errno(14))
        );
        assert_eq!(effects, 1);
        assert_eq!(
            batch.progress_with(&socket, 269, a, &mut m, |_, _, _| panic!("copyout replay")),
            Err(Errno(14))
        );
        let mut m = memory();
        m.write_array(0x1050, u64::MAX.to_le_bytes()).unwrap();
        let batch = Message::new(269, a, &m, 16).unwrap();
        let mut effects = 0;
        assert_eq!(
            batch.progress_with(&socket, 269, a, &mut m, |_, _, _| {
                effects += 1;
                Ok(3)
            }),
            Ok(1)
        );
        assert_eq!(effects, 1);
        for (count, expected) in [(0, 0), (1025, 1024)] {
            let a = [fd as u64, 0x1000, count, 0, 0, 0];
            let mut m = Memory::default();
            m.map(0x1000, PAGE_SIZE * 17, Permissions::RW).unwrap();
            let batch = Message::new(269, a, &m, 16).unwrap();
            let mut calls = 0;
            assert_eq!(
                batch.progress_with(&socket, 269, a, &mut m, |bytes, _, _| {
                    calls += 1;
                    assert!(bytes.is_empty());
                    Ok(0)
                }),
                Ok(expected)
            );
            assert_eq!(calls, expected);
        }
    }
    #[test]
    fn parked_receive_uses_original_ofd_and_destinations_or_faults_before_dequeue() {
        for number in [207, 212] {
            for fault in [false, true] {
                let (mut v, fd, socket) = socket();
                socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
                let address = socket.local_addr().unwrap();
                drop(socket);
                let d = DirectSyscalls::default().with_resources(v.descriptor_factory());
                let mut m = memory();
                m.write_array(0x1300, 0x3000u64.to_le_bytes()).unwrap();
                let args = if number == 207 {
                    [fd as u64, 0x3000, 3, 0, 0, 0]
                } else {
                    [fd as u64, 0x1000, 0, 0, 0, 0]
                };
                let target: Arc<dyn IoWake> = Arc::new(Target);
                let call = match d
                    .start_socket_control(number, args, &mut m, 1, &Arc::downgrade(&target))
                    .unwrap()
                {
                    IoAttempt::SocketCheckpoint(call) => call,
                    _ => panic!("empty blocking receive must retain"),
                };
                let old = call.socket_handle().unwrap();
                v.close(fd).unwrap();
                assert_eq!(v.eventfd(0, 0).unwrap(), fd);
                m.write_array(0x1300, 0x1500u64.to_le_bytes()).unwrap();
                if fault {
                    m.unmap(0x3000, PAGE_SIZE).unwrap();
                }
                let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                peer.send_to(b"abc", address).unwrap();
                trames_net::wait(&[(old.clone(), 1)], Duration::from_secs(2)).unwrap();
                match d.retry_owned_socket(call, &mut m, 1, &Arc::downgrade(&target)) {
                    IoAttempt::Complete(result) => {
                        assert_eq!(result, if fault { Err(Errno(14)) } else { Ok(3) })
                    }
                    _ => panic!("received packet did not finish"),
                }
                if fault {
                    assert_eq!(old.recv(3, 0).unwrap().data, b"abc");
                } else {
                    assert_eq!(m.read_array::<3>(0x3000).unwrap(), *b"abc");
                    assert_eq!(m.read_array::<3>(0x1500).unwrap(), [0; 3]);
                }
            }
        }
    }
    #[test]
    fn native_udp_message_copyout_preserves_truncation_pktinfo_and_preflight() {
        for capacity in [16, 64] {
            let (v, fd, socket) = socket();
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            socket.set_option(0, 8, 1).unwrap();
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.send_to(b"abcde", socket.local_addr().unwrap())
                .unwrap();
            trames_net::wait(&[(socket.socket_handle(), 1)], Duration::from_secs(2)).unwrap();
            let d = DirectSyscalls::default().with_resources(v.descriptor_factory());
            let mut m = memory();
            for (at, value) in [
                (0x1000, 0x1700u64),
                (0x1008, 16),
                (0x1020, 0x1500),
                (0x1028, capacity),
                (0x1308, 2),
            ] {
                m.write_array(at, value.to_le_bytes()).unwrap();
            }
            let a = [fd as u64, 0x1000, 0x20, 0, 0, 0];
            let target: Arc<dyn IoWake> = Arc::new(Target);
            m.write_array(0x1020, u64::MAX.to_le_bytes()).unwrap();
            assert!(matches!(
                d.start_socket_control(212, a, &mut m, 1, &Arc::downgrade(&target)),
                Some(IoAttempt::Complete(Err(Errno(14))))
            ));
            m.write_array(0x1020, 0x1500u64.to_le_bytes()).unwrap();
            assert!(matches!(
                d.start_socket_control(212, a, &mut m, 1, &Arc::downgrade(&target)),
                Some(IoAttempt::Complete(Ok(5)))
            ));
            assert_eq!(m.read_array::<2>(0x1400).unwrap(), *b"ab");
            assert_eq!(m.read_array::<4>(0x1008).unwrap(), 16u32.to_le_bytes());
            assert_eq!(
                m.read_u64(0x1028).unwrap(),
                if capacity == 16 { 16 } else { 32 }
            );
            assert_eq!(
                m.read_array::<4>(0x1030).unwrap(),
                (if capacity == 16 { 0x28u32 } else { 0x20u32 }).to_le_bytes()
            );
            assert_eq!(m.read_array::<4>(0x150c).unwrap(), 8u32.to_le_bytes());
            assert_eq!(m.read_array::<4>(0x1700).unwrap()[..2], [2, 0]);
        }
    }
}
