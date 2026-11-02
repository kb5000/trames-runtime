// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted socket control lifetime across parking, epochs and owner fallback.
use super::*;
#[derive(Clone)]
pub struct RetainedSocket {
    socket: trames_vfs::SocketOperation,
    factory: trames_vfs::DescriptorFactory,
    pub number: u32,
    pub args: [u64; 6],
    pub deadline: Option<Instant>,
    connecting: bool,
}
impl RetainedSocket {
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        self.socket.shares_resources(fds)
    }
    pub fn socket_handle(&self) -> Arc<trames_net::Socket> {
        self.socket.socket_handle()
    }
    pub fn events(&self) -> u16 {
        if self.number == 203 {
            4
        } else {
            1
        }
    }
    fn attempt(&mut self, memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        let result = if self.number == 203 && self.connecting {
            self.socket.with_tcp_publication(|| {
                self.socket
                    .resume_connect()
                    .map_err(|e| Errno(e.0))
                    .and_then(|ready| if ready { Ok(0) } else { Err(Errno(11)) })
            })
        } else if crate::network::control_publishes(self.number, self.args) {
            self.socket.with_tcp_publication(|| {
                crate::network::control(&self.factory, &self.socket, self.number, self.args, memory)
                    .expect("accepted control ABI")
            })
        } else {
            crate::network::control(&self.factory, &self.socket, self.number, self.args, memory)
                .expect("accepted control ABI")
        };
        if self.number == 203 && matches!(result, Err(Errno(11 | 115))) {
            self.connecting = true;
        }
        result
    }
    fn waits(&self, result: &Result<u64, Errno>) -> bool {
        matches!(self.number, 202 | 203 | 242)
            && self.socket.flags() & trames_vfs::O_NONBLOCK == 0
            && matches!(result, Err(Errno(11)) | Err(Errno(115)))
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
    pub fn start_socket_control(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if !matches!(number, 202 | 203 | 242) || !self.supports_socket_control(number) {
            return None;
        }
        let factory = self.resources.as_ref()?;
        let socket = match factory.socket_operation(args[0] as u32)? {
            Ok(s) => s,
            Err(e) => return Some(self.complete_socket(Err(e))),
        };
        let blocking = socket.flags() & trames_vfs::O_NONBLOCK == 0
            && (number != 203 || socket.info().is_some_and(|info| info.kind == 1));
        let deadline = blocking
            .then(|| socket.io_timeout(number != 203))
            .flatten()
            .and_then(|d| Instant::now().checked_add(d));
        let result = if crate::network::control_publishes(number, args) {
            socket.with_tcp_publication(|| {
                crate::network::control(factory, &socket, number, args, memory)
                    .expect("control ABI")
            })
        } else {
            crate::network::control(factory, &socket, number, args, memory).expect("control ABI")
        };
        if !blocking
            || !matches!(result, Err(Errno(11 | 115)))
            || deadline.is_some_and(|d| Instant::now() >= d)
        {
            return Some(self.complete_socket(result));
        }
        Some(self.start_retained_socket(
            RetainedSocket {
                socket,
                factory: factory.clone(),
                number,
                args,
                deadline,
                connecting: number == 203,
            },
            memory,
            pid,
            target,
        ))
    }
    fn complete_socket(&self, result: Result<u64, Errno>) -> IoAttempt {
        self.completed.set(self.completed.get() + 1);
        self.socket_completed.set(self.socket_completed.get() + 1);
        IoAttempt::Complete(result)
    }
    pub fn start_retained_socket(
        &self,
        mut call: RetainedSocket,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let result = call.attempt(memory);
        if !call.waits(&result) {
            return self.complete_socket(call.finish(result));
        }
        let signal = IoSignal::new(pid, target.clone());
        let mut pending = PendingIo {
            number: call.number,
            args: call.args,
            deadline: call.deadline,
            signal,
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
        };
        if !self.arm_socket(&mut pending) {
            return IoAttempt::SocketCheckpoint(pending.retained_socket.take().unwrap());
        }
        self.retry_socket(pending, memory)
    }
    fn arm_socket(&self, pending: &mut PendingIo) -> bool {
        let Some(events) = pending.target.upgrade().and_then(|t| t.host_events()) else {
            return false;
        };
        let call = pending.retained_socket.as_ref().unwrap();
        let Ok((fds, delay)) = call.socket.wait_sources() else {
            return false;
        };
        let mut subscriptions = Vec::new();
        for fd in fds {
            let Ok(subscription) = events.subscribe(fd, false, &pending.signal) else {
                return false;
            };
            subscriptions.push(subscription);
        }
        // Keep host subscriptions separate from resource notifications.
        // Their original event queues are drained before the deciding retry.
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
        let result = call.attempt(memory);
        if call.waits(&result) {
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
        if !matches!(number, 202 | 203 | 242) {
            return None;
        }
        let factory = self.resources.as_ref()?;
        let socket = match factory.socket_operation(args[0] as u32)? {
            Ok(s) => s,
            Err(e) => return Some(self.complete_socket(Err(e))),
        };
        let deadline = socket
            .io_timeout(number != 203)
            .and_then(|d| Instant::now().checked_add(d));
        Some(self.retry_owned_socket(
            RetainedSocket {
                socket,
                factory: factory.clone(),
                number,
                args,
                deadline,
                connecting: false,
            },
            memory,
            pid,
            target,
        ))
    }
    /// Existing joined executor fallback retains the same operation and uses
    /// its opaque socket in the original native/fabric wait path.
    pub fn retry_owned_socket(
        &self,
        mut call: RetainedSocket,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let result = call.attempt(memory);
        if !call.waits(&result) {
            return self.complete_socket(call.finish(result));
        }
        let pending = PendingIo {
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
        };
        IoAttempt::Blocked(pending)
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
