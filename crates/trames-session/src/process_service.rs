// SPDX-License-Identifier: GPL-3.0-or-later
//! In-epoch services: coordinator-owned FD state, caller-owned concurrent bytes.
//! Ordinary I/O uses caller Views. New private-anonymous intervals may be
//! published through the append-only mapping authority while peers execute.
use super::*;

impl<C: Cpu> Kernel<C> {
    pub(super) fn epoch_request(
        &mut self,
        mut request: Box<crate::workers::Request<C>>,
        io: &mut impl GuestOutput,
    ) -> bool {
        let value = self.service_request(&mut request, io);
        request.respond(value);
        value.is_some()
    }
    pub(super) fn service_request(
        &mut self,
        request: &mut crate::workers::Request<C>,
        io: &mut impl GuestOutput,
    ) -> Option<u64> {
        let p = self.processes.get_mut(&request.pid)?;
        // The worker already evaluated its immutable epoch filter. Recheck
        // here before any VFS effects, using the actual post-SVC PC/arguments.
        // Installation/TSYNC cannot change authority until all CPUs join.
        if !p.seccomp.allows(request.number, request.pc, request.args)
            || p.linux.trace
            || !matches!(p.state, State::Ready)
        {
            return None;
        }
        let a = request.args;
        // Filtered networking retains its existing joined security boundary.
        if p.seccomp.mode() == 0
            && crate::worker_syscalls::network_service_candidate(request.number)
        {
            let began = self.profile_syscalls.then(Instant::now);
            let result = p
                .linux
                .network_service(request.number, a, request.memory_mut());
            if let Some(began) = began {
                self.syscall_total += began.elapsed();
            }
            // An admitted network result is final, including EINPROGRESS and
            // EAGAIN. Replaying a connect/accept can change its meaning.
            return result.map(|value| value.unwrap_or_else(error));
        }
        if request.number == 20 && p.seccomp.mode() == 0 {
            return Some(
                p.linux
                    .vfs
                    .epoll_create(a[0] as u32)
                    .map(u64::from)
                    .unwrap_or_else(error),
            );
        }
        if request.number == 222 && p.seccomp.mode() == 0 {
            let began = Instant::now();
            let result = p.linux.mmap_additive(a, &mut p.memory)?;
            self.parallel_memory_time += began.elapsed();
            self.vm_local_syscalls += 1;
            // Every result is final, including errors. No mapping effect can
            // fall back/replay through a later joined request.
            return Some(result.unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64)));
        }
        match request.number {
            25 if matches!(a[1], 1 | 3) => {}
            62 | 80 => {
                let kind = p.linux.vfs.fd_kind(a[0] as u32);
                // Dynamic proc endpoints require a joined process snapshot.
                if matches!(&kind, Ok(FdKind::Node(path)) if path == b"/proc" || path.starts_with(b"/proc/") || path == b"/sys" || path.starts_with(b"/sys/"))
                {
                    return None;
                }
            }
            63..=70 | 82 | 83 => {
                // Start with streams that cannot modify mapped file backing,
                // transfer FD rights, acquire a terminal, or queue guest signals.
                // Ordinary files join only when retained inode/backing state
                // requires it. The cached bitmap is merely an RPC candidate.
                let write = matches!(request.number, 64 | 66 | 68 | 70);
                let admitted = match p.linux.vfs.epoch_io(a[0] as u32, write) {
                    Some(trames_vfs::EpochIo::Stream) => matches!(request.number, 63..=66),
                    // Ordinary files, including FSIZE and its signal, use the
                    // retained FileWork path instead of this legacy FD service.
                    Some(trames_vfs::EpochIo::File) => false,
                    None => false,
                };
                if !admitted {
                    return None;
                }
            }
            _ => return None,
        }
        p.linux.vfs.set_process_context(request.pid);
        p.linux.vfs.set_lock_owner(p.tgid);
        let began = self.profile_syscalls.then(Instant::now);
        let number = request.number;
        let result = match number {
            63 => p.linux.read(a, request.memory_mut(), io),
            64 => p
                .linux
                .write_scratch(a, request.memory(), io, &mut self.service_write_buffer),
            65 => p.linux.readv(a, request.memory_mut(), io),
            66 => p
                .linux
                .writev_scratch(a, request.memory(), io, &mut self.service_write_buffer),
            67 | 68 => p.linux.positioned_scratch(
                a,
                request.memory_mut(),
                number == 68,
                &mut self.service_write_buffer,
            ),
            69 | 70 => p.linux.positioned_vector_scratch(
                a,
                request.memory_mut(),
                number == 70,
                &mut self.service_write_buffer,
            ),
            82 | 83 => p
                .linux
                .vfs
                .sync_fd(a[0] as u32, request.number == 83)
                .map(|()| 0),
            number => p.linux.fd_query(number, a, request.memory_mut()),
        };
        if let Some(began) = began {
            self.syscall_total += began.elapsed();
        }
        match result {
            // Both return before effects on these admitted streams. Let the
            // original joined path install waits/timeouts and deliver SIGPIPE.
            Err(Errno(11))
                if p.linux
                    .vfs
                    .flags(a[0] as u32)
                    .is_ok_and(|f| f & O_NONBLOCK == 0) =>
            {
                None
            }
            Err(Errno(32)) if matches!(request.number, 64 | 66) => None,
            Err(Errno(38 | 95)) => None,
            other => Some(other.unwrap_or_else(error)),
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use trames_cpu::Cpu;
    type Process = crate::process::Process<Cpu>;
    type Kernel = crate::process::Kernel<Cpu>;
    type Work = crate::workers::Work<Cpu>;
    type Request = crate::workers::Request<Cpu>;

    use super::*;
    use crate::workers::{Control, Event};
    use std::sync::Arc;
    use trames_memory::{CpuMemory, Permissions, PAGE_SIZE};

    fn pending(
        mut p: Box<Process>,
        number: u32,
        a: [u64; 6],
    ) -> (Kernel, Box<Request>, Arc<Control>) {
        p.memory
            .write_array(0x4000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        let mut cpu = Cpu::new(0x4000, 0);
        cpu.set_x(8, number as u64);
        put_args(&mut cpu, a);
        let snapshot = crate::worker_syscalls::Snapshot {
            limits: None,
            timers: None,

            saved_wait_mask: Default::default(),
            io_signals: Default::default(),
            io_routes: Default::default(),
            io_wake: None,
            seccomp: p.seccomp.clone(),
            identities: [0; 7],
            started: Instant::now(),
            processor: 0,
            profile: false,
            streams: p.linux.vfs.stream_descriptors(),

            fd_flags: p.linux.vfs.fd_flags_snapshot(),
            umask: p.linux.vfs.umask_capability(),
            actions: p.signals.actions.shared(),
            program_break: p.linux.program_break(),
            uts: None,
            direct: if number == 57 {
                trames_linux::DirectSyscalls::default().with_network(p.linux.vfs.direct_network())
            } else {
                Default::default()
            },
            futex: Default::default(),
        };
        let memory = p.memory.parallel_view(&mut Default::default()).unwrap();
        let control = Arc::new(Control::new(100));
        let mut k = super::super::tests::kernel();
        k.processes.insert(1, p);
        k.workers.ensure(0).unwrap();
        k.workers
            .dispatch(
                0,
                Work {
                    audio: None,
                    gpu: None,
                    pid: 1,
                    cpu,
                    memory: Some(Box::new(memory)),
                    control: control.clone(),
                    syscalls: Some(snapshot),
                },
            )
            .unwrap();
        let Some(Event::Service(request)) =
            k.workers.event_timeout(Duration::from_secs(5)).unwrap()
        else {
            panic!("missing in-epoch request");
        };
        (k, request, control)
    }
    fn finish(
        k: &mut Kernel,
        request: Box<Request>,
        control: Arc<Control>,
        value: Option<u64>,
    ) -> crate::workers::Done<Cpu> {
        control.stop();
        request.respond(value);
        let done = k.workers.complete().unwrap();
        assert_eq!(done.instructions, 1);
        assert_eq!(done.serviced_syscalls, u64::from(value.is_some()));
        k.processes
            .get_mut(&1)
            .unwrap()
            .memory
            .commit_parallel()
            .unwrap();
        done
    }
    #[test]
    fn socket_creation_and_address_errors_finish_through_existing_service() {
        let mut p = super::super::tests::process();
        p.linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let (mut k, mut request, control) = pending(p, 198, [2, 1, 0, 0, 0, 0]);
        let result = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(result, Some(3));
        finish(&mut k, request, control, result);
        let mut p = k.processes.remove(&1).unwrap();
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        p.memory.write_array(0x1000, 16u32.to_le_bytes()).unwrap();
        let (mut k, mut request, control) = pending(p, 204, [3, 0x9000, 0x1000, 0, 0, 0]);
        let result = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(result, Some(error(Errno(14))));
        finish(&mut k, request, control, result);
        assert_eq!(k.processes[&1].linux.vfs.fd_snapshot().len(), 4);
    }
    #[test]
    fn tcp_handoff_retains_lifetime_without_reusing_native_authority() {
        use std::io::Write;
        struct Target(Arc<trames_vfs::HostEvents>);
        impl trames_vfs::IoWake for Target {
            fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {}
            fn host_events(&self) -> Option<Arc<trames_vfs::HostEvents>> {
                Some(self.0.clone())
            }
        }
        let mut p = super::super::tests::process();
        p.linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = p.linux.vfs.socket(2, 1, 0).unwrap();
        let socket = p.linux.vfs.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        drop(socket);
        let direct =
            trames_linux::DirectSyscalls::default().with_network(p.linux.vfs.direct_network());
        let target: Arc<dyn trames_vfs::IoWake> =
            Arc::new(Target(trames_vfs::HostEvents::new().unwrap()));
        let args = [fd as u64, 0x1800, 1, 0, 0, 0];
        let trames_linux::IoAttempt::Blocked(wait) = direct
            .start(63, args, &mut p.memory, 1, &Arc::downgrade(&target), None)
            .unwrap()
        else {
            panic!("TCP wait")
        };
        let call = crate::run_queue::IoCall::from(&wait);
        assert!(call.tcp_liveness.is_some());
        drop(wait);
        assert_eq!(p.linux.vfs.close_quiescent_tcp(fd), None);
        p.tcp_liveness = call.tcp_liveness;
        p.state = State::Blocked(63, args);
        let mut k = super::super::tests::kernel();
        let mut io = trames_linux::CapturedOutput::default();
        k.call(1, &mut p, 63, args, &mut io);
        assert!(p.tcp_liveness.is_some());
        assert_eq!(p.linux.vfs.close_quiescent_tcp(fd), None);
        peer.write_all(b"x").unwrap();
        // A successful host write need not already be readable on Darwin's
        // receiving thread. Wait for the actual read event without consuming it.
        {
            let socket = p.linux.vfs.socket_fd(fd).unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            while socket.poll(1).unwrap() & 1 == 0 {
                assert!(Instant::now() < until);
                trames_net::wait(
                    &[(socket.clone(), 1)],
                    until.saturating_duration_since(Instant::now()),
                )
                .unwrap();
            }
        }
        k.call(1, &mut p, 63, args, &mut io);
        assert_eq!(p.cpu.x(0), 1);
        assert!(p.tcp_liveness.is_none());
        assert_eq!(p.memory.read_array::<1>(0x1800).unwrap(), *b"x");
        assert_eq!(p.linux.vfs.close_quiescent_tcp(fd), Some(Ok(())));
    }
    #[test]
    fn connected_tcp_close_services_finish_or_defer_before_fd_mutation() {
        for busy in [false, true] {
            let mut p = super::super::tests::process();
            p.linux
                .vfs
                .configure_network(trames_vfs::NetworkMode::Loopback)
                .unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let fd = p.linux.vfs.socket(2, 1, 0).unwrap();
            let socket = p.linux.vfs.socket_fd(fd).unwrap();
            assert!(matches!(
                socket.connect(listener.local_addr().unwrap()),
                Ok(()) | Err(trames_net::NetError(115))
            ));
            let (_peer, _) = listener.accept().unwrap();
            assert_eq!(socket.connect_complete(), Ok(true));
            drop(socket);
            let accepted = busy.then(|| p.linux.vfs.direct_network().get(fd).unwrap());
            let (mut k, mut request, control) = pending(p, 57, [fd as u64, 0, 0, 0, 0, 0]);
            let result =
                k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
            assert_eq!(result, if busy { None } else { Some(0) });
            finish(&mut k, request, control, result);
            assert_eq!(k.processes[&1].linux.vfs.socket_fd(fd).is_ok(), busy);
            drop(accepted);
        }
    }

    #[test]
    fn idle_socket_create_close_loops_need_no_coordinator_or_peer_checkpoint() {
        let mut p = super::super::tests::process();
        p.linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        p.memory.write_array(0x1800, [0xff; 8]).unwrap();
        // socket(AF_INET,SOCK_STREAM,0); close(fd); store result; repeat.
        let code = [
            0xd2800040u32,
            0xd2800021,
            0xd2800002,
            0xd28018c8,
            0xd4000001,
            0xd2800728,
            0xd4000001,
            0xd2830004,
            0xf9000080,
            0x17fffff7,
        ];
        for (i, word) in code.into_iter().enumerate() {
            p.memory
                .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.affinity = 3;
        let mut peer = p.fork();
        peer.parent = 1;
        let mut k = super::super::tests::kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
            .unwrap());
        assert_eq!(k.service_requests, 0);
        assert!(
            k.worker_fd_syscalls > 100,
            "worker_fd_syscalls={}",
            k.worker_fd_syscalls
        );
        assert!(k.parallel_rounds <= 4, "rounds={}", k.parallel_rounds);
        for p in k.processes.values() {
            assert_eq!(p.memory.read_array::<8>(0x1800).unwrap(), [0; 8]);
            assert!(p.linux.vfs.fd_snapshot().len() <= 4);
        }
    }

    #[test]
    fn direct_socket_controls_do_not_checkpoint_or_service_peer_cpus() {
        let mut p = super::super::tests::process();
        p.linux
            .vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let fd = p.linux.vfs.socket(2, 1, 0).unwrap();
        p.memory.write(0x1800, &16u32.to_le_bytes()).unwrap();
        // mov x0,fd; mov x1,0x1900; mov x2,0x1800; mov x8,204; svc; b loop
        for (index, word) in [
            0xd2800000u32 | (fd << 5),
            0xd2832001,
            0xd2830002,
            0xd2801988,
            0xd4000001,
            0x17fffffb,
        ]
        .into_iter()
        .enumerate()
        {
            p.memory
                .write_array(0x4000 + index as u64 * 4, word.to_le_bytes())
                .unwrap();
        }
        p.memory
            .protect(0x4000, PAGE_SIZE, Permissions::RX)
            .unwrap();
        p.cpu = Cpu::new(0x4000, 0);
        p.affinity = 3;
        let mut peer = p.fork();
        peer.parent = 1;
        let mut k = super::super::tests::kernel();
        k.cpu_count = 2;
        k.workers = crate::workers::Pool::new(2);
        k.per_cpu = vec![Duration::ZERO; 2];
        k.processes.insert(1, p);
        k.processes.insert(2, peer);
        assert!(k
            .parallel_epoch(&mut trames_linux::CapturedOutput::default(), 100_000, true)
            .unwrap());
        assert_eq!(k.service_requests, 0);
        assert!(k.worker_socket_syscalls > 100);
        assert!(k.parallel_rounds <= 4, "rounds={}", k.parallel_rounds);
        for p in k.processes.values() {
            assert_eq!(p.memory.read_array::<2>(0x1900).unwrap(), [2, 0]);
        }
    }

    #[test]
    fn unix_stream_services_preserve_ready_blocking_nonblocking_and_sigpipe_paths() {
        for mode in 0..4 {
            let mut p = super::super::tests::process();
            let [r, w] = p
                .linux
                .vfs
                .socketpair(1, 1 | if mode == 2 { O_NONBLOCK } else { 0 }, 0)
                .unwrap();
            let number = if mode == 3 { 64 } else { 63 };
            if mode == 0 {
                p.linux.vfs.write(w, b"ab").unwrap();
            }
            if mode == 3 {
                p.linux
                    .vfs
                    .local_socket(w)
                    .unwrap()
                    .unwrap()
                    .shutdown(0)
                    .unwrap();
            }
            let args = [r as u64, 0x2000, 1, 0, 0, 0];
            let (mut k, mut request, control) = pending(p, number, args);
            let value =
                k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
            assert_eq!(
                value,
                match mode {
                    0 => Some(1),
                    2 => Some(error(Errno(11))),
                    _ => None,
                }
            );
            let done = finish(&mut k, request, control, value);
            if mode == 0 {
                assert_eq!(
                    k.processes[&1].memory.read_array::<1>(0x2000).unwrap(),
                    *b"a"
                );
            }
            if mode == 1 || mode == 3 {
                let mut p = k.processes.remove(&1).unwrap();
                p.cpu = done.cpu;
                k.call(
                    1,
                    &mut p,
                    number,
                    args,
                    &mut trames_linux::CapturedOutput::default(),
                );
                if mode == 1 {
                    assert!(matches!(p.state, State::Blocked(63, _)));
                } else {
                    assert_eq!(p.cpu.x(0), error(Errno(32)));
                    assert!(p.signals.io.inbox.contains_key(&13));
                }
            }
        }
    }
    #[test]
    fn pipe_read_uses_the_callers_view_and_commits_once_when_a_peer_requests_stop() {
        let mut p = super::super::tests::process();
        let [r, w] = p.linux.vfs.pipe(0).unwrap();
        p.linux.vfs.write(w, b"ab").unwrap();
        let (mut k, mut request, control) = pending(p, 63, [r as u64, 0x2000, 1, 0, 0, 0]);
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, Some(1));
        assert_eq!(request.memory().read_array::<1>(0x2000).unwrap(), *b"a");
        assert_eq!(
            k.processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .read(r, 1)
                .unwrap(),
            b"b"
        );
        let done = finish(&mut k, request, control, value);
        assert_eq!(done.cpu.x(0), 1);
        assert!(matches!(done.outcome, Some(SliceOutcome::Yield { .. })));
        assert_eq!(
            k.processes[&1].memory.read_array::<1>(0x2000).unwrap(),
            *b"a"
        );
    }
    #[test]
    fn stream_preflight_rejects_bad_destinations_without_consuming_input() {
        let mut p = super::super::tests::process();
        let [r, w] = p.linux.vfs.pipe(0).unwrap();
        p.linux.vfs.write(w, b"ab").unwrap();
        let (mut k, mut request, control) = pending(p, 63, [r as u64, 0x9000, 2, 0, 0, 0]);
        let value = k.service_request(&mut request, &mut trames_linux::CapturedOutput::default());
        assert_eq!(value, Some(error(Errno(14))));
        assert_eq!(
            k.processes
                .get_mut(&1)
                .unwrap()
                .linux
                .vfs
                .read(r, 2)
                .unwrap(),
            b"ab"
        );
        finish(&mut k, request, control, value);
    }
    #[test]
    fn blocking_and_sigpipe_paths_checkpoint_but_nonblocking_eagain_completes() {
        for mode in 0..3 {
            let mut p = super::super::tests::process();
            let [r, w] = p
                .linux
                .vfs
                .pipe(if mode == 1 { O_NONBLOCK } else { 0 })
                .unwrap();
            let number = if mode == 2 { 64 } else { 63 };
            let fd = if mode == 2 {
                p.linux.vfs.close(r).unwrap();
                w
            } else {
                r
            };
            let a = [fd as u64, 0x2000, 1, 0, 0, 0];
            let (mut k, mut request, control) = pending(p, number, a);
            let mut io = trames_linux::CapturedOutput::default();
            let value = k.service_request(&mut request, &mut io);
            assert_eq!(value, (mode == 1).then(|| error(Errno(11))));
            let done = finish(&mut k, request, control, value);
            if mode != 1 {
                assert!(matches!(done.outcome, Some(SliceOutcome::Syscall { .. })));
                let mut p = k.processes.remove(&1).unwrap();
                p.cpu = done.cpu;
                k.call(1, &mut p, number, a, &mut io);
                if mode == 0 {
                    assert!(matches!(p.state, State::Blocked(63, _)));
                } else {
                    assert_eq!(p.cpu.x(0), error(Errno(32)));
                    assert!(p.signals.io.inbox.contains_key(&13));
                }
            }
        }
    }
}
