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

#[test]
fn filtered_unix_rights_resume_on_one_worker_after_owner_fd_reuse_without_rechecking_entry() {
    let mut p = super::tests::process();
    let mut k = super::tests::kernel();
    let [tx, rx] = p.linux.vfs.socketpair(1, 1, 0).unwrap();
    let event = p.linux.vfs.eventfd(19, 0).unwrap();
    let weak = Rc::downgrade(&p.linux.vfs.local_socket(rx).unwrap().unwrap());
    let mut header = [0; 56];
    for (at, value) in [(16, 0x1100u64), (24, 1), (32, 0x1300), (40, 24)] {
        header[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    p.memory.write(0x1000, &header).unwrap();
    p.memory
        .write_array(0x1100, 0x1200u64.to_le_bytes())
        .unwrap();
    p.memory.write_array(0x1108, 4u64.to_le_bytes()).unwrap();
    p.memory.write(0x1200, b"abcd").unwrap();
    p.memory.write(0x1800, &[0xff; 16]).unwrap();
    filter(&mut k, &mut p, 0x7fff0000);
    let mut peer = p.fork();
    peer.tgid = 2;
    peer.parent = 1;
    p.linux.vfs.close(tx).unwrap();
    p.linux.vfs.close(event).unwrap();
    peer.linux.vfs.close(rx).unwrap();
    peer.memory
        .write_array(0x1300, 20u64.to_le_bytes())
        .unwrap();
    peer.memory.write_array(0x1308, 1u32.to_le_bytes()).unwrap();
    peer.memory.write_array(0x130c, 1u32.to_le_bytes()).unwrap();
    peer.memory
        .write_array(0x1310, event.to_le_bytes())
        .unwrap();
    program(
        &mut p,
        vec![
            mov(0, rx),
            mov(1, 0x1000),
            mov(2, 0),
            mov(8, 212),
            0xd4000001,
            mov(1, 0x1800),
            0xf9000020,
            mov(0, rx),
            mov(1, 0x1000),
            mov(2, 0),
            mov(8, 212),
            0xd4000001,
            mov(1, 0x1808),
            0xf9000020,
            0x14000000,
        ],
    );
    program(&mut peer, vec![0x14000000]);
    k.cpu_count = 2;
    k.per_cpu = vec![Duration::ZERO; 2];
    k.workers = crate::workers::Pool::new(1);
    k.processes.insert(1, p);
    k.processes.insert(2, peer);
    assert!(k
        .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
        .unwrap());
    let mut p = k.processes.remove(&1).unwrap();
    assert!(matches!(p.state, State::Blocked(212, _)));
    assert!(p.retained_message_owner.is_some());
    Kernel::queue_one(1, &mut p, 19, 0);
    assert_eq!(k.deliver(1, &mut p), Ok(true));
    assert!(matches!(p.state, State::Stopped));
    assert!(
        !p.worker_io_candidate(1),
        "a retained message does not make a stopped task runnable"
    );
    Kernel::queue_one(1, &mut p, 18, 0);
    assert!(
        !k.resume_event(&mut p),
        "continued socket still waits for its message"
    );
    assert!(matches!(p.state, State::Blocked(212, _)));
    p.linux.vfs.close(rx).unwrap();
    let replacement = p.linux.vfs.eventfd(99, 0).unwrap();
    if replacement != rx {
        assert_eq!(p.linux.vfs.dup(replacement, rx, false).unwrap(), rx);
        p.linux.vfs.close(replacement).unwrap();
    }
    assert!(
        weak.upgrade().is_some(),
        "accepted call retains its original local OFD"
    );
    filter(&mut k, &mut p, 0x5000d);
    k.processes.insert(1, p);
    let peer = k.processes.get_mut(&2).unwrap();
    peer.memory
        .protect(0x4000, PAGE_SIZE, Permissions::RW)
        .unwrap();
    program(
        peer,
        vec![
            mov(0, tx),
            mov(1, 0x1000),
            mov(2, 0),
            mov(8, 211),
            0xd4000001,
            mov(1, 0x1800),
            0xf9000020,
            0x14000000,
        ],
    );
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let limit = k.instructions + 100_000;
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), limit, true)
            .unwrap());
        if k.processes[&1].memory.read_u64(0x1808).unwrap() == error(Errno(13)) {
            break;
        }
        assert!(
            Instant::now() < until,
            "retained filtered message did not progress"
        );
    }
    let p = k.processes.get_mut(&1).unwrap();
    assert_eq!(p.memory.read_u64(0x1800).unwrap(), 4);
    let imported = u32::from_le_bytes(p.memory.read_array(0x1310).unwrap());
    assert_eq!(p.linux.vfs.read(imported, 8).unwrap(), 19u64.to_le_bytes());
    assert_eq!(p.linux.vfs.read(rx, 8).unwrap(), 99u64.to_le_bytes());
    assert!(
        weak.upgrade().is_none(),
        "completed call releases old transport"
    );
    assert_eq!(p.seccomp.evaluations(), 3);
    assert_eq!(k.service_requests, 0);
    assert!(
        k.worker_io_waits > 0 && k.worker_socket_syscalls >= 2,
        "waits={} socket={} direct={} services={}",
        k.worker_io_waits,
        k.worker_socket_syscalls,
        k.worker_direct_syscalls,
        k.service_requests
    );
}

#[test]
fn directory_lifecycle_and_enumeration_stay_on_workers_with_one_filter_decision_per_entry() {
    for slots in [1, 2] {
        let mut p = super::tests::process();
        let mut k = super::tests::kernel();
        p.linux.vfs.mkdir_at(-100, b"/dir", 0o755).unwrap();
        p.memory.write(0x1000, b"/dir\0").unwrap();
        filter(&mut k, &mut p, 0x7fff0000);
        let mut code = Vec::new();
        // Each opened directory must be visible to the next call without
        // recapture. Validate read, shared seek, reread, and final close.
        for i in 0..16 {
            code.extend([
                mov(0, 0),
                mov(1, 0x1000),
                mov(2, 0),
                mov(3, 0),
                mov(8, 56),
                0xd4000001,
                0xaa0003f3,
            ]);
            for (j, (number, arg1, arg2)) in
                [(61, 0x1100, 48), (62, 0, 0), (61, 0x1100, 24), (57, 0, 0)]
                    .into_iter()
                    .enumerate()
            {
                code.extend([
                    0xaa1303e0,
                    mov(1, arg1),
                    mov(2, arg2),
                    mov(8, number),
                    0xd4000001,
                    mov(1, 0x1800 + (i * 4 + j as u32) * 8),
                    0xf9000020,
                ]);
            }
        }
        code.push(0x14000000);
        let mut peer = p.fork();
        peer.parent = 1;
        peer.tgid = 2;
        program(&mut p, code.clone());
        program(&mut peer, code);
        if slots == 2 {
            peer.affinity = 2;
        }
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
            .unwrap());
        for p in k.processes.values() {
            for i in 0..16 {
                for (j, value) in [48, 0, 24, 0].into_iter().enumerate() {
                    assert_eq!(
                        p.memory.read_u64(0x1800 + (i * 4 + j as u64) * 8).unwrap(),
                        value,
                        "slot count {slots}, iteration {i}, call {j}"
                    );
                }
            }
            assert_eq!(
                p.seccomp.evaluations(),
                160,
                "shared filter counts both workers' 80 entries"
            );
        }
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.syscalls, 160);
    }
}

#[test]
fn joined_pty_wait_and_signal_handoff_keep_accepted_endpoints_after_fd_reuse() {
    let mut p = super::tests::process();
    let mut k = super::tests::kernel();
    p.linux.vfs.set_runtime_info(1, Default::default());
    let master = p
        .linux
        .vfs
        .open_at(trames_vfs::AT_FDCWD, b"/dev/ptmx", 2, 0)
        .unwrap();
    let pair = p.linux.vfs.pty(master).unwrap().unwrap().pair.clone();
    pair.locked
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let slave = p.linux.vfs.open_pty_peer(master, 2).unwrap();
    p.session = 1;
    p.group = 1;
    p.linux.vfs.set_controlling_terminal(Some(pair.id)).unwrap();
    {
        let mut tty = pair.terminal.borrow_mut();
        tty.session = 1;
        tty.foreground = 1;
    }
    let read = [slave as u64, 0x1100, 3, 0, 0, 0];
    let mut output = trames_linux::CapturedOutput::default();
    k.call(1, &mut p, 63, read, &mut output);
    assert!(
        p.byte_wait.is_some(),
        "ordinary PTY input uses its resource wait"
    );
    p.linux.vfs.close(slave).unwrap();
    assert_eq!(p.linux.vfs.eventfd(99, 0).unwrap(), slave);
    assert_eq!(pair.master_write(b"ok\n").unwrap().0, 3);
    assert!(p.byte_wait.as_ref().unwrap().signal.ready());
    k.call(1, &mut p, 63, read, &mut output);
    assert_eq!(p.cpu.x(0), 3);
    assert_eq!(p.memory.read_array::<3>(0x1100).unwrap(), *b"ok\n");
    assert!(p.byte_wait.is_none());

    p.memory.write(0x1100, b"\x03").unwrap();
    let write = [master as u64, 0x1100, 1, 0, 0, 0];
    let direct = trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
        .with_membership(p.linux.vfs.shared_files());
    let accepted = match direct
        .start(
            64,
            write,
            &mut p.memory,
            1,
            &Arc::downgrade(&k.byte_target),
            None,
        )
        .unwrap()
    {
        trames_linux::IoAttempt::ByteCheckpoint(file) => file,
        _ => panic!("terminal input signal must retain its original endpoint"),
    };
    p.linux.vfs.close(master).unwrap();
    assert_eq!(p.linux.vfs.eventfd(100, 0).unwrap(), master);
    p.retained_byte = Some(accepted);
    k.call(1, &mut p, 64, write, &mut output);
    assert_eq!(p.cpu.x(0), 1);
    assert!(p.signals.pending.contains_key(&2));
    assert!(p.retained_byte.is_none());
    assert!(!pair.master_alive.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn pty_aliases_and_short_controls_run_on_workers_with_one_filter_decision() {
    for slots in [1, 2] {
        let mut p = super::tests::process();
        let mut k = super::tests::kernel();
        p.linux.vfs.set_runtime_info(1, Default::default());
        let master = p
            .linux
            .vfs
            .open_at(trames_vfs::AT_FDCWD, b"/dev/ptmx", 2, 0)
            .unwrap();
        let pair = p.linux.vfs.pty(master).unwrap().unwrap().pair.clone();
        pair.locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let slave = p.linux.vfs.open_pty_peer(master, 2).unwrap();
        p.memory.write_array(0x1000, 1u32.to_le_bytes()).unwrap();
        filter(&mut k, &mut p, 0x7fff0000);
        let mut code = Vec::new();
        for i in 0..8 {
            let base = 0x1800 + i * 56;
            code.extend([
                mov(0, slave),
                mov(8, 23),
                0xd4000001,
                0xaa0003f3,
                mov(1, base),
                0xf9000020,
            ]);
            // Use the master for controls; the slave alias exercises real
            // endpoint dup/close, without generating a task hangup boundary.
            for (j, request) in [0x80045430u32, 0x40045431, 0x80045439, 0x5420, 0x80045438]
                .into_iter()
                .enumerate()
            {
                let address = match request {
                    0x40045431 | 0x5420 => 0x1000,
                    0x80045430 => 0x1010,
                    0x80045439 => 0x1014,
                    _ => 0x1018,
                };
                code.extend([
                    mov(0, master),
                    mov(1, request & 0xffff),
                    0xf2a00001 | ((request >> 16) << 5),
                    mov(2, address),
                    mov(8, 29),
                    0xd4000001,
                    mov(1, base + (j as u32 + 1) * 8),
                    0xf9000020,
                ]);
            }
            code.extend([
                0xaa1303e0,
                mov(8, 57),
                0xd4000001,
                mov(1, base + 48),
                0xf9000020,
            ]);
        }
        code.push(0x14000000);
        let mut peer = p.fork();
        peer.parent = 1;
        peer.tgid = 2;
        program(&mut p, code.clone());
        program(&mut peer, code);
        if slots == 2 {
            peer.affinity = 2;
        }
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
            .unwrap());
        for p in k.processes.values() {
            for i in 0..8 {
                for (j, value) in [5, 0, 0, 0, 0, 0, 0].into_iter().enumerate() {
                    assert_eq!(
                        p.memory.read_u64(0x1800 + i * 56 + j as u64 * 8).unwrap(),
                        value,
                        "slots={slots} iteration={i} call={j}"
                    );
                }
            }
            assert_eq!(
                p.memory.read_array::<4>(0x1010).unwrap(),
                pair.number.to_le_bytes()
            );
            assert_eq!(
                p.memory.read_array::<4>(0x1014).unwrap(),
                1u32.to_le_bytes()
            );
            assert_eq!(
                p.memory.read_array::<4>(0x1018).unwrap(),
                1u32.to_le_bytes()
            );
            assert_eq!(p.seccomp.evaluations(), 112);
        }
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.syscalls, 112);
    }
}

#[test]
fn signalfd_lifecycle_updates_and_aliases_run_on_workers_with_one_filter_decision() {
    for slots in [1, 2] {
        let mut p = super::tests::process();
        let mut k = super::tests::kernel();
        p.memory
            .write_array(0x1000, (1u64 << 9).to_le_bytes())
            .unwrap();
        p.memory
            .write_array(0x1010, (1u64 << 11).to_le_bytes())
            .unwrap();
        filter(&mut k, &mut p, 0x7fff0000);
        let mut code = Vec::new();
        for i in 0..8 {
            let base = 0x1800 + i * 40;
            code.extend([
                0x92800000,
                mov(1, 0x1000),
                mov(2, 8),
                mov(3, trames_vfs::O_NONBLOCK),
                mov(8, 74),
                0xd4000001,
                0xaa0003f3,
                mov(1, base),
                0xf9000020,
            ]);
            code.extend([
                0xaa1303e0,
                mov(8, 23),
                0xd4000001,
                0xaa0003f4,
                mov(1, base + 8),
                0xf9000020,
            ]);
            code.extend([
                0xaa1303e0,
                mov(8, 57),
                0xd4000001,
                mov(1, base + 16),
                0xf9000020,
            ]);
            code.extend([
                0xaa1403e0,
                mov(1, 0x1010),
                mov(2, 8),
                mov(3, 0),
                mov(8, 74),
                0xd4000001,
                mov(1, base + 24),
                0xf9000020,
            ]);
            code.extend([
                0xaa1403e0,
                mov(8, 57),
                0xd4000001,
                mov(1, base + 32),
                0xf9000020,
            ]);
        }
        code.push(0x14000000);
        let mut peer = p.fork();
        peer.parent = 1;
        peer.tgid = 2;
        program(&mut p, code.clone());
        program(&mut peer, code);
        if slots == 2 {
            peer.affinity = 2;
        }
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(slots);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
            .unwrap());
        for p in k.processes.values() {
            for i in 0..8 {
                for (j, value) in [3, 4, 0, 4, 0].into_iter().enumerate() {
                    assert_eq!(
                        p.memory.read_u64(0x1800 + i * 40 + j as u64 * 8).unwrap(),
                        value,
                        "slots={slots} iteration={i} call={j}"
                    );
                }
            }
            assert_eq!(p.seccomp.evaluations(), 80);
        }
        assert_eq!(k.service_requests, 0);
        assert_eq!(k.syscalls, 80);
    }
}
#[test]
fn shared_signalfd_reads_the_current_tasks_queue_and_does_not_capture_its_creator() {
    let mut p = super::tests::process();
    let k = super::tests::kernel();
    let fd = p
        .linux
        .vfs
        .signalfd(-1, (1 << 9) | (1 << 11), trames_vfs::O_NONBLOCK)
        .unwrap();
    let mut peer = p.fork();
    let info = |sender| Info {
        sender,
        uid: 123,
        status: 0,
        code: -6,
        timer: None,
        fault: None,
    };
    p.signals.pending.enqueue(10, info(31)).unwrap();
    peer.signals.pending.enqueue(12, info(41)).unwrap();
    let args = [fd as u64, 0x1800, 128, 0, 0, 0];
    assert_eq!(k.read_signalfd(&mut peer, 63, args), Ok(Some(128)));
    assert_eq!(
        u32::from_le_bytes(peer.memory.read_array(0x1800).unwrap()),
        12
    );
    assert!(p.signals.pending.contains_key(&10));
    assert!(peer.signals.pending.is_empty());
    assert_eq!(k.read_signalfd(&mut p, 63, args), Ok(Some(128)));
    assert_eq!(u32::from_le_bytes(p.memory.read_array(0x1800).unwrap()), 10);
    assert_eq!(k.read_signalfd(&mut peer, 63, args), Err(Errno(11)));
}
