// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_cpu::Cpu as Interpreter;
use trames_memory::{Permissions, PAGE_SIZE};

fn program(p: &mut Process<Interpreter>, code: Vec<u32>) {
    for (i, word) in code.into_iter().enumerate() {
        p.memory
            .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    p.memory
        .protect(0x4000, PAGE_SIZE, Permissions::RX)
        .unwrap();
    p.cpu = Interpreter::new(0x4000, 0);
    p.affinity = 1;
}
fn mov(rd: u32, value: u32) -> u32 {
    0xd2800000 | (value << 5) | rd
}
fn filter(k: &mut Kernel<Interpreter>, p: &mut Process<Interpreter>, value: u32) {
    p.memory.write(0x1700, &[6, 0, 0, 0]).unwrap();
    p.memory.write(0x1704, &value.to_le_bytes()).unwrap();
    p.memory.write(0x1600, &1u16.to_le_bytes()).unwrap();
    p.memory.write(0x1608, &0x1700u64.to_le_bytes()).unwrap();
    k.seccomp(p, [1, 0, 0x1600, 0, 0, 0]).unwrap();
}
fn listener(p: &mut Process<Interpreter>) -> (u32, std::net::SocketAddr) {
    p.linux
        .vfs
        .configure_network(trames_vfs::NetworkMode::Loopback)
        .unwrap();
    let fd = p.linux.vfs.socket(2, 1, 0).unwrap();
    let s = p.linux.vfs.socket_fd(fd).unwrap();
    s.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    s.listen(4).unwrap();
    (fd, s.local_addr().unwrap())
}

#[test]
fn blocking_accept_returns_the_only_slot_for_a_connecting_peer_without_service() {
    for filtered in [false, true] {
        let mut p = super::tests::process();
        let mut k = super::tests::kernel();
        p.linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = p.linux.vfs.socket(2, 1, 0).unwrap();
        let address = {
            let s = p.linux.vfs.socket_fd(fd).unwrap();
            s.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            s.listen(4).unwrap();
            s.local_addr().unwrap()
        };
        p.memory
            .write(0x1000, &trames_net::encode_address(address))
            .unwrap();
        p.memory.write(0x1800, &[0xff; 32]).unwrap();
        if filtered {
            filter(&mut k, &mut p, 0x7fff0000);
        }
        let mut peer = p.fork();
        peer.parent = 1;
        // Parent accept parks. The only worker must then run the peer's
        // blocking connect, and return to the accepted original call.
        program(
            &mut p,
            vec![
                mov(0, fd),
                mov(1, 0),
                mov(2, 0),
                mov(8, 202),
                0xd4000001,
                mov(1, 0x1800),
                0xf9000020,
                0x14000000,
            ],
        );
        program(
            &mut peer,
            vec![
                mov(0, 2),
                mov(1, 1),
                mov(2, 0),
                mov(8, 198),
                0xd4000001,
                mov(1, 0x1000),
                mov(2, 16),
                mov(8, 203),
                0xd4000001,
                mov(1, 0x1810),
                0xf9000020,
                0x14000000,
            ],
        );
        // Both tasks are pinned to virtual CPU 0. Advertise two CPUs to enter
        // the cohort path, while allowing only one host execution worker.
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(1);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            let limit = k.instructions + 100_000;
            assert!(k
                .parallel_epoch(&mut trames_linux::CapturedOutput::default(), limit, true)
                .unwrap(), "cohort refused: instructions={} rounds={} states={:?} accepted={:?} connected={:?}", k.instructions, k.parallel_rounds,
                k.processes.iter().map(|(id,p)| (*id,matches!(p.state,State::Ready),matches!(p.state,State::Blocked(..)),matches!(p.state,State::Zombie(_)))).collect::<Vec<_>>(),
                k.processes[&1].memory.read_u64(0x1800), k.processes[&2].memory.read_u64(0x1810));
            let accepted = k.processes[&1].memory.read_u64(0x1800).unwrap();
            let connected = k.processes[&2].memory.read_u64(0x1810).unwrap();
            if accepted != u64::MAX && connected != u64::MAX {
                assert!(accepted >= 4 && accepted < trames_vfs::MAX_FDS as u64);
                assert_eq!(connected, 0);
                break;
            }
            assert!(Instant::now() < until, "accept/connect did not progress");
        }
        assert_eq!(k.service_requests, 0);
        assert!(k.worker_io_waits > 0, "blocking accept never parked");
        assert!(k.worker_socket_syscalls >= 2);
        if filtered {
            assert_eq!(k.processes[&1].seccomp.evaluations(), k.syscalls);
        }
    }
}

#[test]
fn accepted_socket_checkpoint_keeps_original_ofd_and_next_svc_uses_new_filter() {
    let mut p = super::tests::process();
    let mut k = super::tests::kernel();
    let (fd, address) = listener(&mut p);
    filter(&mut k, &mut p, 0x7fff0000);
    let args = [fd as u64, 0, 0, 0, 0, 0];
    assert!(!k.filter_syscall(1, &mut p, 202, args));
    let evaluations = p.seccomp.evaluations();
    let call = match trames_linux::DirectSyscalls::default()
        .with_resources(p.linux.vfs.descriptor_factory())
        .start_socket_control(202, args, &mut p.memory, 1, &Arc::downgrade(&k.byte_target))
        .unwrap()
    {
        trames_linux::IoAttempt::SocketCheckpoint(call) => call,
        _ => panic!("owner target has no host reactor"),
    };
    p.retained_socket = Some(call);
    p.state = State::Blocked(202, args);
    p.linux.vfs.close(fd).unwrap();
    assert_eq!(p.linux.vfs.eventfd(0, 0).unwrap(), fd);
    filter(&mut k, &mut p, 0x5000d);
    let _peer = std::net::TcpStream::connect(address).unwrap();
    k.call(
        1,
        &mut p,
        202,
        args,
        &mut trames_linux::CapturedOutput::default(),
    );
    assert!(matches!(p.state, State::Ready));
    let accepted = p.cpu.x(0) as u32;
    assert_eq!(
        p.linux
            .vfs
            .socket_fd(accepted)
            .unwrap()
            .local_addr()
            .unwrap(),
        address
    );
    assert!(p.retained_socket.is_none());
    assert_eq!(
        p.seccomp.evaluations(),
        evaluations,
        "accepted entry must not re-evaluate BPF"
    );
    k.call(
        1,
        &mut p,
        202,
        args,
        &mut trames_linux::CapturedOutput::default(),
    );
    assert_eq!(p.cpu.x(0), error(Errno(13)));
    assert_eq!(p.seccomp.evaluations(), evaluations + 1);
}

#[test]
fn stopped_socket_wait_retains_ofd_but_signal_releases_it_with_original_restart_rules() {
    for timed in [false, true] {
        for restart in [false, true] {
            let mut p = super::tests::process();
            let mut k = super::tests::kernel();
            let (fd, _) = listener(&mut p);
            let weak = {
                let socket = p.linux.vfs.socket_fd(fd).unwrap();
                if timed {
                    socket.set_io_timeout(true, Some(Duration::from_secs(60)));
                }
                Arc::downgrade(&socket)
            };
            let args = [fd as u64, 0, 0, 0, 0, 0];
            k.call(
                1,
                &mut p,
                202,
                args,
                &mut trames_linux::CapturedOutput::default(),
            );
            assert!(matches!(p.state, State::Blocked(202, _)));
            assert!(p.byte_wait.as_ref().unwrap().retained_socket.is_some());
            assert!(
                p.fork().byte_wait.is_none(),
                "fork must not inherit accepted calls"
            );
            p.linux.vfs.close(fd).unwrap();
            Kernel::queue_one(1, &mut p, 19, 0);
            assert_eq!(k.deliver(1, &mut p), Ok(true));
            assert!(matches!(p.state, State::Stopped));
            assert!(weak.upgrade().is_some());
            p.state = *p.stopped_state.take().unwrap();
            let pc = p.cpu.pc;
            p.signals.actions.set(
                10,
                Action {
                    handler: 0x5000,
                    flags: if restart { 0x10000000 } else { 0 },
                    ..Action::default()
                },
            );
            Kernel::queue_one(1, &mut p, 10, 0);
            assert_eq!(k.deliver(1, &mut p), Ok(true));
            assert!(p.byte_wait.is_none() && p.retained_socket.is_none());
            assert!(weak.upgrade().is_none());
            Kernel::sigreturn(&mut p).unwrap();
            assert_eq!(p.cpu.pc, if restart && !timed { pc - 4 } else { pc });
            if timed || !restart {
                assert_eq!(p.cpu.x(0), error(Errno(4)));
            }
        }
    }
}

#[test]
fn all_blocked_related_accepts_are_adopted_without_an_interactive_service() {
    let mut p = super::tests::process();
    let mut k = super::tests::kernel();
    let (fd, address) = listener(&mut p);
    p.memory.write(0x1800, &[0xff; 8]).unwrap();
    let mut peer = p.fork();
    program(&mut p, vec![mov(1, 0x1800), 0xf9000020, 0x14000000]);
    program(&mut peer, vec![mov(1, 0x1800), 0xf9000020, 0x14000000]);
    let args = [fd as u64, 0, 0, 0, 0, 0];
    k.call(
        1,
        &mut p,
        202,
        args,
        &mut trames_linux::CapturedOutput::default(),
    );
    k.call(
        2,
        &mut peer,
        202,
        args,
        &mut trames_linux::CapturedOutput::default(),
    );
    k.cpu_count = 2;
    k.per_cpu = vec![Duration::ZERO; 2];
    k.workers = crate::workers::Pool::new(1);
    k.processes.insert(1, p);
    k.processes.insert(2, peer);
    assert!(
        k.parallel_candidate(),
        "related parked sockets must retain worker adoption"
    );
    let _a = std::net::TcpStream::connect(address).unwrap();
    let _b = std::net::TcpStream::connect(address).unwrap();
    assert!(k
        .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
        .unwrap());
    // A budget boundary may join before the second pinned task runs.
    if k.processes[&2].memory.read_u64(0x1800).unwrap() == u64::MAX {
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 200_000, true)
            .unwrap());
    }
    for p in k.processes.values() {
        assert!(p.memory.read_u64(0x1800).unwrap() < MAX_FDS as u64);
    }
    assert_eq!(k.service_requests, 0);
    assert!(k.worker_socket_syscalls >= 2);
}
