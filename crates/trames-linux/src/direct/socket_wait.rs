// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted socket control lifetime across parking, epochs and owner fallback.
use super::*;
#[derive(Clone)]
enum Control {
    Network(trames_vfs::SocketOperation),
    Unix {
        socket: trames_vfs::LocalOperation,
        address: Option<Vec<u8>>,
        connection: Option<trames_vfs::LocalConnection>,
    },
}
#[derive(Clone)]
pub struct RetainedSocket {
    socket: Control,
    factory: trames_vfs::DescriptorFactory,
    pub number: u32,
    pub args: [u64; 6],
    pub deadline: Option<Instant>,
    connecting: bool,
    accepted_address: Option<Vec<u8>>,
    message: Option<Arc<ip_message::Message>>,
}
impl RetainedSocket {
    pub(super) fn uring(
        factory: &trames_vfs::DescriptorFactory,
        request: &trames_vfs::UringRequest,
        memory: &impl CpuMemory,
    ) -> Option<Result<Self, Errno>> {
        let s = &request.sqe;
        let (number, args) = match s.opcode() {
            13 if s.length() == 0 => (242, [0, s.address(), s.offset(), s.op_flags() as u64, 0, 0]),
            16 | 56 if s.op_flags() == 0 && s.length() == 0 => (
                if s.opcode() == 16 { 203 } else { 200 },
                [0, s.address(), s.offset(), 0, 0, 0],
            ),
            26 | 27 if s.offset() == 0 => (
                if s.opcode() == 26 { 206 } else { 207 },
                [0, s.address(), s.length() as u64, s.op_flags() as u64, 0, 0],
            ),
            34 | 57 if s.op_flags() == 0 => (
                if s.opcode() == 34 { 210 } else { 201 },
                [0, s.length() as u64, 0, 0, 0, 0],
            ),
            _ => return Some(Err(Errno(22))),
        };
        let accepted = request.file.as_ref()?.socket_control()?;
        Some((|| {
            let socket = match accepted? {
                trames_vfs::SocketControlOperation::Network(socket) => Control::Network(socket),
                trames_vfs::SocketControlOperation::Unix(socket) => Control::Unix {
                    socket,
                    address: request.path.clone(),
                    connection: None,
                },
            };
            let message = match &socket {
                Control::Network(socket) if matches!(number, 206 | 207) => Some(Arc::new(
                    ip_message::Message::new(number, args, memory, socket.address_size())?,
                )),
                _ => None,
            };
            Ok(Self {
                socket,
                factory: factory.clone(),
                number,
                args,
                deadline: None,
                connecting: false,
                accepted_address: request.path.clone(),
                message,
            })
        })())
    }
    pub(super) fn uring_wait_kind(&self) -> u8 {
        match &self.socket {
            Control::Network(_) => 0,
            Control::Unix { connection, .. } => 1 + u8::from(connection.is_some()),
        }
    }
    pub(super) fn uring_subscribe(
        &self,
        signal: &Arc<IoSignal>,
    ) -> Option<trames_vfs::IoSubscription> {
        match &self.socket {
            Control::Network(socket) => socket.subscribe(signal),
            Control::Unix {
                socket, connection, ..
            } => Some(if let Some(connection) = connection {
                connection.subscribe(signal)
            } else {
                socket.subscribe(signal)
            }),
        }
    }
    pub(super) fn uring_attempt(
        &mut self,
        memory: &mut impl CpuMemory,
        paths: Option<&trames_vfs::PathQueries>,
    ) -> Option<Result<u64, Errno>> {
        if matches!(&self.socket, Control::Unix { .. }) && matches!(self.number, 206 | 207) {
            return None;
        }
        self.attempt(memory, paths)
    }
    pub fn external_wait(&self) -> bool {
        matches!(&self.socket, Control::Network(socket) if !socket.is_netlink())
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        match &self.socket {
            Control::Network(socket) => socket.shares_resources(fds),
            Control::Unix {
                socket, connection, ..
            } => {
                socket.shares_resources(fds)
                    || connection
                        .as_ref()
                        .is_some_and(|connection| connection.shares_resources(fds))
            }
        }
    }
    pub fn socket_handle(&self) -> Option<Arc<trames_net::Socket>> {
        match &self.socket {
            Control::Network(socket) => Some(socket.socket_handle()),
            Control::Unix { .. } => None,
        }
    }
    pub fn pipe_signal(&self) -> bool {
        self.message
            .as_ref()
            .is_some_and(|message| message.pipe_signal())
    }
    pub fn events(&self) -> u16 {
        if matches!(self.number, 64 | 66 | 203 | 206 | 211 | 269) {
            4
        } else {
            1
        }
    }
    fn blocking(&self) -> bool {
        if self.message.is_some() {
            let Control::Network(socket) = &self.socket else {
                unreachable!()
            };
            return socket.flags() & trames_vfs::O_NONBLOCK == 0
                && socket_flags(self.number, self.args) & 0x40 == 0;
        }
        match &self.socket {
            Control::Network(socket) => {
                socket.flags() & trames_vfs::O_NONBLOCK == 0
                    && (self.number != 203 || socket.info().is_some_and(|info| info.kind == 1))
            }
            Control::Unix { socket, .. } => {
                socket.flags() & trames_vfs::O_NONBLOCK == 0
                    && (self.number != 203 || socket.kind() != 2)
            }
        }
    }
    fn attempt(
        &mut self,
        memory: &mut impl CpuMemory,
        paths: Option<&trames_vfs::PathQueries>,
    ) -> Option<Result<u64, Errno>> {
        match &mut self.socket {
            Control::Network(socket) => {
                if let Some(message) = &self.message {
                    return Some(message.progress(
                        socket,
                        self.number,
                        self.args,
                        memory,
                        &self.factory,
                    ));
                }
                let result = if let Some(address) = &self.accepted_address {
                    socket.with_tcp_publication(|| {
                        let result = if self.number == 200 {
                            socket.bind_authorized(address, self.factory.can_bind_service())
                        } else if self.connecting {
                            socket.resume_connect().and_then(|ready| {
                                if ready {
                                    Ok(())
                                } else {
                                    Err(trames_net::NetError(11))
                                }
                            })
                        } else {
                            socket.connect_bytes(address)
                        };
                        result
                            .map(|()| 0)
                            .map_err(|e| Errno(if e.0 == 115 { 11 } else { e.0 }))
                    })
                } else if self.number == 203 && self.connecting {
                    socket.with_tcp_publication(|| {
                        socket
                            .resume_connect()
                            .map_err(|e| Errno(e.0))
                            .and_then(|ready| if ready { Ok(0) } else { Err(Errno(11)) })
                    })
                } else if crate::network::control_publishes(self.number, self.args) {
                    socket.with_tcp_publication(|| {
                        crate::network::control(
                            &self.factory,
                            socket,
                            self.number,
                            self.args,
                            memory,
                        )
                        .expect("accepted control ABI")
                    })
                } else {
                    crate::network::control(&self.factory, socket, self.number, self.args, memory)
                        .expect("accepted control ABI")
                };
                if self.number == 203 && matches!(result, Err(Errno(11 | 115))) {
                    self.connecting = true;
                }
                Some(result)
            }
            Control::Unix {
                socket,
                address,
                connection,
            } => {
                if self.number == 200 {
                    return paths?
                        .local_bind(socket, address.as_deref().expect("accepted bind address"))
                        .map(|result| result.map(|()| 0));
                }
                if self.number == 203 {
                    if connection.is_none() {
                        match paths?.local_connection(
                            socket,
                            address.as_deref().expect("accepted connect address"),
                            self.factory.local_peer_identity(),
                        )? {
                            Ok(prepared) => {
                                *connection = Some(prepared);
                                *address = None;
                            }
                            Err(error) => return Some(Err(error)),
                        }
                    }
                    return Some(connection.as_ref().unwrap().attempt().map(|()| 0));
                }
                if matches!(self.number, 201 | 210) {
                    return crate::network::unix::control(
                        &self.factory,
                        socket,
                        self.number,
                        self.args,
                        memory,
                    );
                }
                Some(crate::network::unix::accept(
                    &self.factory,
                    socket,
                    self.number,
                    self.args,
                    memory,
                ))
            }
        }
    }
    fn waits(&self, result: &Result<u64, Errno>) -> bool {
        (matches!(self.number, 202 | 203 | 242) || self.message.is_some())
            && self.blocking()
            && (matches!(result, Err(Errno(11)))
                || self.number == 203 && matches!(result, Err(Errno(115))))
            && !self.deadline.is_some_and(|d| Instant::now() >= d)
    }
    fn finish(&self, result: Result<u64, Errno>) -> Result<u64, Errno> {
        if self.connecting && result == Err(Errno(11)) {
            Err(Errno(115))
        } else {
            result
        }
    }
}
impl DirectSyscalls {
    pub(super) fn raw_ip_socket(&self, fd: u32) -> Option<trames_vfs::SocketOperation> {
        let socket = self.resources.as_ref()?.socket_operation(fd)?.ok()?;
        matches!(socket.address_size(), 12 | 16 | 28).then_some(socket)
    }
    pub(super) fn start_raw_ip(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if !matches!(number, 63..=66) {
            return None;
        }
        let socket = self.raw_ip_socket(args[0] as u32)?;
        let message = match ip_message::Message::raw(number, args, memory, socket.flags()) {
            Ok(message) => Arc::new(message),
            Err(error) => return Some(self.complete_socket(Err(error))),
        };
        let deadline = socket
            .io_timeout(matches!(number, 63 | 65))
            .and_then(|d| Instant::now().checked_add(d));
        Some(self.start_retained_socket(
            RetainedSocket {
                socket: Control::Network(socket),
                factory: self.resources.as_ref()?.clone(),
                number,
                args,
                deadline,
                connecting: false,
                accepted_address: None,
                message: Some(message),
            },
            memory,
            pid,
            target,
        ))
    }
    fn prepare_socket_call(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Option<Result<RetainedSocket, Errno>> {
        if !(matches!(number, 200 | 202 | 203 | 242) || ip_message::number(number))
            || !self.supports_socket_control(number)
        {
            return None;
        }
        if number == 269 && args[3] as u32 & 0x8000_0000 != 0 {
            return Some(Err(Errno(22)));
        }
        let factory = self.resources.as_ref()?;
        let accepted = factory.socket_control_operation(args[0] as u32)?;
        let accepted = match accepted {
            Ok(trames_vfs::SocketControlOperation::Unix(_)) if ip_message::number(number) => {
                return None
            }
            Ok(trames_vfs::SocketControlOperation::Network(ref socket))
                if ip_message::number(number) && !matches!(socket.address_size(), 12 | 16 | 28) =>
            {
                return None
            }
            other => other,
        };
        Some((|| {
            let socket = match accepted? {
                trames_vfs::SocketControlOperation::Network(socket) => Control::Network(socket),
                trames_vfs::SocketControlOperation::Unix(socket) => Control::Unix {
                    socket,
                    address: if matches!(number, 200 | 203) {
                        Some(crate::network::address(memory, args[1], args[2])?)
                    } else {
                        None
                    },
                    connection: None,
                },
            };
            let deadline = match &socket {
                Control::Network(socket) => socket
                    .io_timeout(matches!(number, 202 | 242 | 207 | 212))
                    .and_then(|d| Instant::now().checked_add(d)),
                Control::Unix { .. } => None,
            };
            let message = match &socket {
                Control::Network(socket) if ip_message::number(number) => Some(Arc::new(
                    ip_message::Message::new(number, args, memory, socket.address_size())?,
                )),
                _ => None,
            };
            Ok(RetainedSocket {
                socket,
                factory: factory.clone(),
                number,
                args,
                deadline,
                connecting: false,
                accepted_address: None,
                message,
            })
        })())
    }
    pub fn start_socket_control(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        Some(match self.prepare_socket_call(number, args, memory)? {
            Ok(call) => self.start_retained_socket(call, memory, pid, target),
            Err(error) => self.complete_socket(Err(error)),
        })
    }
    fn complete_socket(&self, result: Result<u64, Errno>) -> IoAttempt {
        self.completed.set(self.completed.get() + 1);
        self.socket_completed.set(self.socket_completed.get() + 1);
        IoAttempt::Complete(result)
    }
    fn socket_wait(&self, call: RetainedSocket, pid: u32, target: &Weak<dyn IoWake>) -> PendingIo {
        PendingIo {
            number: call.number,
            args: call.args,
            deadline: call.deadline,
            signal: IoSignal::new(pid, target.clone()),
            retained_socket: Some(call),
            retained_byte: None,
            native_tcp: None,
            flock: None,
            retained_poll: None,
            resource_deadline: None,
            epoll_revision: None,
            _subscriptions: Vec::new(),
            socket_subscriptions: Vec::new(),
            host_subscription: None,
            uring: None,
            poll_uring: None,
            target: target.clone(),
        }
    }
    pub fn start_retained_socket(
        &self,
        mut call: RetainedSocket,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let Some(result) = call.attempt(memory, self.paths.as_ref()) else {
            return IoAttempt::SocketCheckpoint(call);
        };
        if call.pipe_signal() {
            return IoAttempt::SocketCheckpoint(call);
        }
        if !call.waits(&result) {
            return self.complete_socket(call.finish(result));
        }
        let mut pending = self.socket_wait(call, pid, target);
        if !self.arm_socket(&mut pending) {
            return IoAttempt::SocketCheckpoint(pending.retained_socket.take().unwrap());
        }
        self.retry_socket(pending, memory)
    }
    fn arm_socket(&self, pending: &mut PendingIo) -> bool {
        let call = pending.retained_socket.as_ref().unwrap();
        if let Control::Unix {
            socket, connection, ..
        } = &call.socket
        {
            let subscription = if let Some(connection) = connection {
                connection.subscribe(&pending.signal)
            } else {
                socket.subscribe(&pending.signal)
            };
            pending._subscriptions = vec![subscription];
            return true;
        }
        let Control::Network(socket) = &call.socket else {
            unreachable!()
        };
        if let Some(subscription) = socket.subscribe(&pending.signal) {
            pending._subscriptions = vec![subscription];
            return true;
        }
        let Some(events) = pending.target.upgrade().and_then(|t| t.host_events()) else {
            return false;
        };
        let Ok((fds, delay)) = socket.wait_sources() else {
            return false;
        };
        let mut subscriptions = Vec::new();
        for fd in fds {
            let Ok(subscription) = events.subscribe(fd, false, &pending.signal) else {
                return false;
            };
            subscriptions.push(subscription);
        }
        pending.socket_subscriptions = subscriptions;
        pending.resource_deadline = delay.and_then(|d| Instant::now().checked_add(d));
        true
    }
    pub(super) fn resume_socket(
        &self,
        mut pending: PendingIo,
        memory: &mut impl CpuMemory,
    ) -> IoAttempt {
        pending.signal.reset();
        if !self.arm_socket(&mut pending) {
            return IoAttempt::SocketCheckpoint(pending.retained_socket.take().unwrap());
        }
        self.retry_socket(pending, memory)
    }
    fn retry_socket(&self, mut pending: PendingIo, memory: &mut impl CpuMemory) -> IoAttempt {
        let call = pending.retained_socket.as_mut().unwrap();
        let Some(result) = call.attempt(memory, self.paths.as_ref()) else {
            return IoAttempt::SocketCheckpoint(pending.retained_socket.take().unwrap());
        };
        if call.pipe_signal() {
            IoAttempt::SocketCheckpoint(pending.retained_socket.take().unwrap())
        } else if call.waits(&result) {
            IoAttempt::Blocked(pending)
        } else {
            self.complete_socket(call.finish(result))
        }
    }
    pub fn start_owned_socket_control(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        Some(match self.prepare_socket_call(number, args, memory)? {
            Ok(call) => self.retry_owned_socket(call, memory, pid, target),
            Err(error) => self.complete_socket(Err(error)),
        })
    }
    /// Resolve excluded owner paths through the real VFS, using the accepted
    /// original OFD and address bytes. Normal worker waits never enter here.
    pub fn retry_owned_socket_vfs(
        &self,
        mut call: RetainedSocket,
        vfs: &mut trames_vfs::Vfs,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if let Control::Unix {
            socket,
            address,
            connection,
        } = &mut call.socket
        {
            if call.number == 200 {
                return self.complete_socket(
                    vfs.local_bind_operation(
                        socket,
                        address.as_deref().expect("accepted bind address"),
                    )
                    .map(|()| 0),
                );
            }
            if call.number == 203 && connection.is_none() {
                match vfs.local_connection_operation(
                    socket,
                    address.as_deref().expect("accepted connect address"),
                    call.factory.local_peer_identity(),
                ) {
                    Ok(prepared) => {
                        *connection = Some(prepared);
                        *address = None;
                    }
                    Err(error) => return self.complete_socket(Err(error)),
                }
            }
        }
        self.retry_owned_socket(call, memory, pid, target)
    }
    pub fn retry_owned_socket(
        &self,
        mut call: RetainedSocket,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let Some(result) = call.attempt(memory, self.paths.as_ref()) else {
            return IoAttempt::SocketCheckpoint(call);
        };
        if !call.waits(&result) {
            return self.complete_socket(call.finish(result));
        }
        if matches!(call.socket, Control::Unix { .. }) {
            return self.start_retained_socket(call, memory, pid, target);
        }
        IoAttempt::Blocked(self.socket_wait(call, pid, target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    use trames_vfs::{Vfs, O_CLOEXEC, O_NONBLOCK};
    struct Target(Arc<trames_vfs::HostEvents>);
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
        fn host_events(&self) -> Option<Arc<trames_vfs::HostEvents>> {
            Some(self.0.clone())
        }
    }
    fn target() -> (Arc<dyn IoWake>, Arc<trames_vfs::HostEvents>) {
        let hub = trames_vfs::HostEvents::new().unwrap();
        (Arc::new(Target(hub.clone())), hub)
    }
    fn memory() -> Memory {
        let mut m = Memory::new(0x10000);
        m.map(0x1000, 0x1000, Permissions::RW).unwrap();
        m
    }
    fn blocked(attempt: IoAttempt) -> PendingIo {
        match attempt {
            IoAttempt::Blocked(wait) => wait,
            _ => panic!("expected retained socket wait"),
        }
    }
    #[test]
    fn accept_rearms_on_a_new_target_and_keeps_original_files_after_close_reuse() {
        let mut v = Vfs::default();
        v.configure_network(trames_net::NetworkMode::Loopback)
            .unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let (address, weak) = {
            let socket = v.socket_fd(fd).unwrap();
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            socket.listen(4).unwrap();
            (socket.local_addr().unwrap(), Arc::downgrade(&socket))
        };
        let direct = DirectSyscalls::default().with_resources(v.descriptor_factory());
        let (old_target, _) = target();
        let mut m = memory();
        m.write(0x1200, &16u32.to_le_bytes()).unwrap();
        let wait = blocked(
            direct
                .start_socket_control(
                    242,
                    [
                        fd as u64,
                        0x1100,
                        0x1200,
                        (O_NONBLOCK | O_CLOEXEC) as u64,
                        0,
                        0,
                    ],
                    &mut m,
                    1,
                    &Arc::downgrade(&old_target),
                )
                .unwrap(),
        );
        let call = wait.retained_socket.clone().unwrap();
        drop(wait);
        drop(old_target);
        let files = v.shared_files();
        std::thread::spawn(move || files.close(fd, 1).unwrap().unwrap())
            .join()
            .unwrap();
        assert_eq!(v.eventfd(0, 0).unwrap(), fd);
        assert!(weak.upgrade().is_some());
        let unrelated = Vfs::default();
        let next = DirectSyscalls::default().with_resources(unrelated.descriptor_factory());
        let (new_target, hub) = target();
        let wait =
            blocked(next.start_retained_socket(call, &mut m, 1, &Arc::downgrade(&new_target)));
        hub.wait(Some(Instant::now() + Duration::from_millis(10)))
            .unwrap();
        assert!(
            !wait.signal.ready(),
            "idle listener must not spin on writable readiness"
        );
        let _peer = std::net::TcpStream::connect(address).unwrap();
        hub.wait(Some(Instant::now() + Duration::from_secs(2)))
            .unwrap();
        assert!(wait.signal.ready());
        let accepted = match next.resume(wait, &mut m) {
            IoAttempt::Complete(Ok(fd)) => fd as u32,
            _ => panic!("accept did not finish"),
        };
        assert_eq!(
            v.socket_fd(accepted).unwrap().local_addr().unwrap(),
            address
        );
        assert!(
            unrelated.socket_fd(accepted).is_err(),
            "accept publishes to original Files"
        );
        assert_eq!(
            v.flags(accepted).unwrap() & (O_NONBLOCK | O_CLOEXEC),
            O_NONBLOCK | O_CLOEXEC
        );
        assert!(
            weak.upgrade().is_none(),
            "subscription must not keep closed listener alive"
        );
        v.close(accepted).unwrap();
        v.close(fd).unwrap();
    }
    #[test]
    fn virtual_connect_timeout_survives_handoff_without_rereading_peer_or_fd() {
        let fabric = trames_net::Fabric::new().unwrap();
        let mut v = Vfs::default();
        v.configure_virtual_network(&fabric, 2, trames_net::NetworkMode::Outbound)
            .unwrap();
        let mut server = Vfs::default();
        server
            .configure_virtual_network(&fabric, 3, trames_net::NetworkMode::Outbound)
            .unwrap();
        let listener = server.socket(2, 1, 0).unwrap();
        let receiver = server.socket_fd(listener).unwrap();
        receiver.bind("10.0.0.3:34567".parse().unwrap()).unwrap();
        receiver.listen(4).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let weak = {
            let socket = v.socket_fd(fd).unwrap();
            socket.set_io_timeout(false, Some(Duration::from_millis(20)));
            Arc::downgrade(&socket)
        };
        fabric.set_link_faults(1, 0);
        let direct = DirectSyscalls::default().with_resources(v.descriptor_factory());
        let (old_target, _) = target();
        let mut m = memory();
        m.write(
            0x1000,
            &trames_net::encode_address(receiver.local_addr().unwrap()),
        )
        .unwrap();
        let wait = blocked(
            direct
                .start_socket_control(
                    203,
                    [fd as u64, 0x1000, 16, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&old_target),
                )
                .unwrap(),
        );
        let deadline = wait.deadline;
        let call = wait.retained_socket.clone().unwrap();
        drop(wait);
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(0, 0).unwrap(), fd);
        m.write(0x1000, &[0xff; 16]).unwrap();
        while Instant::now() < deadline.unwrap() {
            std::thread::sleep(Duration::from_millis(1));
        }
        let (new_target, _) = target();
        assert!(matches!(
            direct.start_retained_socket(call, &mut m, 1, &Arc::downgrade(&new_target)),
            IoAttempt::Complete(Err(Errno(115)))
        ));
        assert!(weak.upgrade().is_none());
        v.close(fd).unwrap();
        server.close(listener).unwrap();
    }
    #[test]
    fn connect_checkpoint_resumes_original_handshake_after_peer_bytes_and_fd_change() {
        struct NoEvents;
        impl IoWake for NoEvents {
            fn wake_io(&self, _: &Arc<IoSignal>) {}
        }
        let fabric = trames_net::Fabric::new().unwrap();
        let mut v = Vfs::default();
        v.configure_virtual_network(&fabric, 2, trames_net::NetworkMode::Outbound)
            .unwrap();
        let mut server = Vfs::default();
        server
            .configure_virtual_network(&fabric, 3, trames_net::NetworkMode::Outbound)
            .unwrap();
        let listener = server.socket(2, 1, 0).unwrap();
        let receiver = server.socket_fd(listener).unwrap();
        receiver.bind("10.0.0.3:34568".parse().unwrap()).unwrap();
        receiver.listen(4).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let mut m = memory();
        m.write(
            0x1000,
            &trames_net::encode_address(receiver.local_addr().unwrap()),
        )
        .unwrap();
        let direct = DirectSyscalls::default().with_resources(v.descriptor_factory());
        fabric.set_link_faults(1, 0);
        let no_events: Arc<dyn IoWake> = Arc::new(NoEvents);
        let call = match direct
            .start_socket_control(
                203,
                [fd as u64, 0x1000, 16, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&no_events),
            )
            .unwrap()
        {
            IoAttempt::SocketCheckpoint(call) => call,
            _ => panic!("started handshake must survive missing reactor"),
        };
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(0, 0).unwrap(), fd);
        m.write(0x1000, &[0xff; 16]).unwrap();
        fabric.set_link_faults(0, 0);
        let (target, hub) = target();
        let until = Instant::now() + Duration::from_secs(4);
        let mut attempt = direct.start_retained_socket(call, &mut m, 1, &Arc::downgrade(&target));
        loop {
            match attempt {
                IoAttempt::Complete(result) => {
                    assert_eq!(result, Ok(0));
                    break;
                }
                IoAttempt::Blocked(wait) => {
                    assert!(Instant::now() < until, "original handshake did not finish");
                    hub.wait(Some(wait.wake_deadline().unwrap_or(until).min(until)))
                        .unwrap();
                    attempt = direct.resume(wait, &mut m);
                }
                _ => panic!("new reactor must retain original connect"),
            }
        }
        assert!(receiver.accept().is_ok());
    }
}

#[cfg(test)]
mod unix_tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    use trames_vfs::Vfs;
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    fn memory(address: &[u8]) -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, 4096, Permissions::RW).unwrap();
        m.write(0x1000, address).unwrap();
        m
    }
    fn listener(v: &mut Vfs, address: &[u8]) -> u32 {
        let fd = v.local_create(1, 0).unwrap();
        let s = v.local_socket(fd).unwrap().unwrap();
        v.local_bind(&s, address).unwrap();
        v.local_listen(&s, 0).unwrap();
        fd
    }
    fn direct(v: &Vfs) -> DirectSyscalls {
        DirectSyscalls::new(v.direct_descriptors())
            .with_resources(v.descriptor_factory())
            .with_paths(v.path_queries())
    }
    fn blocked(attempt: IoAttempt) -> PendingIo {
        match attempt {
            IoAttempt::Blocked(wait) => {
                assert!(!wait.external_wait());
                wait
            }
            _ => panic!("expected local resource wait"),
        }
    }
    fn target() -> Arc<dyn IoWake> {
        Arc::new(Wake)
    }
    #[test]
    fn full_backlog_connect_parks_then_uses_original_client_and_resolved_target() {
        let mut v = Vfs::default();
        let address = b"\x01\x00\0retained-connect";
        let listener = listener(&mut v, address);
        let first = v.local_create(1, 0).unwrap();
        v.local_connect(&v.local_socket(first).unwrap().unwrap(), address)
            .unwrap();
        let client = v.local_create(1, 0).unwrap();
        let original = v.local_socket(client).unwrap().unwrap();
        let d = direct(&v);
        let mut m = memory(address);
        let target = target();
        let wait = blocked(
            d.start_socket_control(
                203,
                [client as u64, 0x1000, address.len() as u64, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
            )
            .unwrap(),
        );
        v.close(client).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), client);
        m.write(0x1000, &vec![0xff; address.len()]).unwrap();
        v.local_accept(&v.local_socket(listener).unwrap().unwrap(), 0)
            .unwrap();
        assert!(wait.signal.ready());
        assert!(matches!(d.resume(wait, &mut m), IoAttempt::Complete(Ok(0))));
        let (accepted, _) = v
            .local_accept(&v.local_socket(listener).unwrap().unwrap(), 0)
            .unwrap();
        v.write(accepted, b"x").unwrap();
        assert_eq!(original.recv(1, 0).unwrap().data, b"x");
        assert_eq!(v.read(client, 8).unwrap(), 99u64.to_le_bytes());
    }
    #[test]
    fn closing_the_original_listener_wakes_connect_and_does_not_follow_rebind() {
        let mut v = Vfs::default();
        let address = b"\x01\x00\0closed-listener";
        let listener_fd = listener(&mut v, address);
        let first = v.local_create(1, 0).unwrap();
        v.local_connect(&v.local_socket(first).unwrap().unwrap(), address)
            .unwrap();
        let client = v.local_create(1, 0).unwrap();
        let d = direct(&v);
        let mut m = memory(address);
        let target = target();
        let wait = blocked(
            d.start_socket_control(
                203,
                [client as u64, 0x1000, address.len() as u64, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
            )
            .unwrap(),
        );
        v.close(listener_fd).unwrap();
        assert!(wait.signal.ready());
        let replacement = listener(&mut v, address);
        assert!(matches!(
            d.resume(wait, &mut m),
            IoAttempt::Complete(Err(Errno(111)))
        ));
        assert_eq!(
            v.local_socket(replacement)
                .unwrap()
                .unwrap()
                .accept_address_size(),
            Err(Errno(11))
        );
    }
    #[test]
    fn accepted_listener_ofd_survives_close_reuse_until_accept_returns() {
        let mut v = Vfs::default();
        let address = b"\x01\x00\0accepted-listener";
        let listener = listener(&mut v, address);
        let client = v.local_create(1, 0).unwrap();
        let d = direct(&v);
        let mut m = memory(address);
        let target = target();
        let wait = blocked(
            d.start_socket_control(
                202,
                [listener as u64, 0, 0, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
            )
            .unwrap(),
        );
        v.close(listener).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), listener);
        assert!(matches!(
            d.start_socket_control(
                203,
                [client as u64, 0x1000, address.len() as u64, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target)
            )
            .unwrap(),
            IoAttempt::Complete(Ok(0))
        ));
        assert!(wait.signal.ready());
        let accepted = match d.resume(wait, &mut m) {
            IoAttempt::Complete(Ok(fd)) => fd as u32,
            _ => panic!("expected original listener acceptance"),
        };
        v.write(client, b"x").unwrap();
        assert_eq!(v.read(accepted, 1).unwrap(), b"x");
        assert_eq!(v.read(listener, 8).unwrap(), 99u64.to_le_bytes());
    }
    #[test]
    fn deferred_bind_handoff_keeps_accepted_ofd_and_original_address_bytes() {
        let mut v = Vfs::default();
        let fd = v.local_create(1, 0).unwrap();
        let original = v.local_socket(fd).unwrap().unwrap();
        let address = b"\x01\x00/original-bind\0";
        let mut m = memory(address);
        let target = target();
        let d = DirectSyscalls::default().with_resources(v.descriptor_factory());
        let call = match d
            .start_socket_control(
                200,
                [fd as u64, 0x1000, address.len() as u64, 0, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
            )
            .unwrap()
        {
            IoAttempt::SocketCheckpoint(call) => call,
            _ => panic!("expected excluded pathname authority"),
        };
        assert_eq!(original.name(false).unwrap(), [1, 0]);
        v.close(fd).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), fd);
        m.write(0x1000, &vec![0xff; address.len()]).unwrap();
        assert!(matches!(
            d.retry_owned_socket_vfs(call, &mut v, &mut m, 1, &Arc::downgrade(&target)),
            IoAttempt::Complete(Ok(0))
        ));
        assert_eq!(original.name(false).unwrap(), address);
        assert_eq!(v.read(fd, 8).unwrap(), 99u64.to_le_bytes());
    }
}
