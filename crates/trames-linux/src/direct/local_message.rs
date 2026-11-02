// SPDX-License-Identifier: GPL-3.0-or-later
//! The shared original ancillary ABI on one accepted Unix transport.
use super::*;
pub(super) struct AcceptedMessage {
    prepared: crate::network::unix::PreparedMessage<trames_vfs::SharedRights>,
    factory: trames_vfs::DescriptorFactory,
    identity: [u32; 3],
    number: u32,
    args: [u64; 6],
}
struct Message<'a> {
    factory: &'a trames_vfs::DescriptorFactory,
    fd: &'a trames_vfs::DirectFd,
    identity: [u32; 3],
}
impl crate::network::unix::MessageIo for Message<'_> {
    type Rights = trames_vfs::SharedRights;
    fn kind(&self) -> u32 {
        self.fd.local_kind()
    }
    fn nonblocking(&self) -> u32 {
        if self.fd.nonblocking() {
            0x40
        } else {
            0
        }
    }
    fn recv(
        &mut self,
        count: usize,
        flags: u32,
    ) -> Option<Result<trames_vfs::LocalReceived<Self::Rights>, Errno>> {
        self.fd.recv_local_message(count, flags)
    }
    fn send(
        &mut self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: Self::Rights,
        identity: [u32; 3],
    ) -> Option<Result<usize, Errno>> {
        if destination.is_some() {
            return Some(Err(Errno(106)));
        }
        self.fd.send_local_message(bytes, flags, &rights, identity)
    }
    fn sender_credentials(&self) -> [u32; 3] {
        self.identity
    }
    fn credentials(&self) -> &trames_vfs::Credentials {
        self.factory.local_credentials()
    }
    fn local_pid(&self, global: u32) -> u32 {
        self.factory.local_pid(global)
    }
    fn global_pid(&self, local: u32) -> Result<u32, Errno> {
        self.factory.local_global_pid(local)
    }
    fn send_rights(&self, fds: &[u32]) -> Option<Result<Self::Rights, Errno>> {
        self.factory.send_local_rights(fds)
    }
    fn receive_rights(
        &mut self,
        rights: Self::Rights,
        capacity: usize,
        cloexec: bool,
    ) -> (Vec<u32>, bool) {
        self.factory.receive_local_rights(rights, capacity, cloexec)
    }
}
impl DirectSyscalls {
    pub(super) fn start_local_message(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let factory = self.resources.as_ref()?;
        let fd = self.descriptors.get(args[0] as u32)?;
        if !fd.is_unix() {
            return None;
        }
        let identity = self
            .local_identity
            .unwrap_or_else(|| factory.local_sender_credentials());
        let mut io = Message {
            factory,
            fd: &fd,
            identity,
        };
        let prepared = match crate::network::unix::prepare_message(number, args, memory, &io) {
            Some(Ok(prepared)) => prepared,
            Some(Err(error)) => return Some(self.complete(number, args, Err(error))),
            None => return Some(IoAttempt::Checkpoint),
        };
        let result = prepared.progress(memory, &mut io);
        if let Some(result) = result {
            if !(result == Err(Errno(11))
                && !fd.nonblocking()
                && socket_flags(number, args) & 0x40 == 0
                || result == Err(Errno(32)) && signals_pipe(number, args))
            {
                return Some(self.complete(number, args, result));
            }
        }
        let file = RetainedByte {
            fd,
            message: Some(Arc::new(AcceptedMessage {
                prepared,
                factory: factory.clone(),
                identity,
                number,
                args,
            })),
        };
        if result.is_none() || result == Some(Err(Errno(32))) {
            return Some(IoAttempt::ByteCheckpoint(file));
        }
        Some(self.start_retained_byte(file, number, args, memory, pid, target))
    }
    pub(super) fn transfer_retained(
        &self,
        file: &RetainedByte,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if let Some(accepted) = &file.message {
            if let Err(error) = accepted.prepared.recheck(memory) {
                return Some(Err(error));
            }
            accepted.prepared.progress(
                memory,
                &mut Message {
                    factory: &accepted.factory,
                    fd: &file.fd,
                    identity: accepted.identity,
                },
            )
        } else {
            self.transfer_fd(&file.fd, number, args, memory)
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn start_owned_local_message(
        &self,
        file: RetainedByte,
        vfs: &mut trames_vfs::Vfs,
        owner: &trames_vfs::RetainedFd,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let accepted = file.message.as_ref().expect("accepted local message");
        let number = accepted.number;
        let args = accepted.args;
        let socket = owner.local_socket().expect("original local OFD");
        let result = crate::network::unix::progress_owned(
            &accepted.prepared,
            vfs,
            &socket,
            if file.fd.nonblocking() { 0x40 } else { 0 },
            memory,
        );
        if result != Err(Errno(11))
            || file.fd.nonblocking()
            || socket_flags(number, args) & 0x40 != 0
        {
            return self.complete_byte(&file, result);
        }
        let signal = IoSignal::new(pid, target.clone());
        let subscriptions = file.fd.subscribe(&signal);
        IoAttempt::Blocked(PendingIo {
            number,
            args,
            deadline: None,
            signal,
            flock: None,
            retained_byte: Some(file),
            retained_socket: None,
            native_tcp: None,
            resource_deadline: None,
            retained_poll: None,
            epoll_revision: None,
            _subscriptions: subscriptions,
            host_subscription: None,
            socket_subscriptions: Vec::new(),
            uring: None,
            poll_uring: None,
            target: target.clone(),
        })
    }
    pub(super) fn local_message(
        &self,
        fd: &trames_vfs::DirectFd,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        let factory = self.resources.as_ref()?;
        crate::network::unix::message(
            number,
            args,
            memory,
            &mut Message {
                factory,
                fd,
                identity: self
                    .local_identity
                    .unwrap_or_else(|| factory.local_sender_credentials()),
            },
        )
    }
}
impl RetainedByte {
    pub fn local_message_entry(&self) -> Option<(u32, [u64; 6])> {
        self.message.as_ref().map(|m| (m.number, m.args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    use trames_vfs::{Vfs, O_CLOEXEC};
    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    fn blocked(attempt: IoAttempt) -> PendingIo {
        match attempt {
            IoAttempt::Blocked(wait) => wait,
            _ => panic!("expected message wait"),
        }
    }

    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, 0x2000, Permissions::RW).unwrap();
        m.write(0x1200, b"abcd").unwrap();
        m.write_array(0x1100, 0x1200u64.to_le_bytes()).unwrap();
        m.write_array(0x1108, 4u64.to_le_bytes()).unwrap();
        header(&mut m, 24);
        m
    }
    fn header(m: &mut Memory, capacity: u64) {
        let mut h = [0; 56];
        for (at, value) in [(16, 0x1100u64), (24, 1), (32, 0x1300), (40, capacity)] {
            h[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        m.write(0x1000, &h).unwrap();
    }
    fn rights(m: &mut Memory, fds: &[u32]) {
        let length = 16 + fds.len() * 4;
        let mut control = vec![0; (length + 7) & !7];
        control[..8].copy_from_slice(&(length as u64).to_le_bytes());
        control[8..12].copy_from_slice(&1u32.to_le_bytes());
        control[12..16].copy_from_slice(&1u32.to_le_bytes());
        for (i, fd) in fds.iter().enumerate() {
            control[16 + i * 4..20 + i * 4].copy_from_slice(&fd.to_le_bytes());
        }
        header(m, control.len() as u64);
        m.write(0x1300, &control).unwrap();
    }
    fn word(m: &Memory, at: u64) -> u32 {
        u32::from_le_bytes(m.read_array(at).unwrap())
    }
    fn direct(v: &Vfs) -> DirectSyscalls {
        DirectSyscalls::new(v.direct_descriptors()).with_resources(v.descriptor_factory())
    }
    #[test]
    fn independent_files_receive_actual_ofds_credentials_and_timestamps_on_workers() {
        let mut sender = Vfs::default();
        sender.set_lock_owner(42);
        sender.credentials = trames_vfs::Credentials::user(1000, 1001);
        let [tx, rx] = sender.socketpair(1, 1, 0).unwrap();
        let event = sender.eventfd(73, 0).unwrap();
        let mut receiver = sender.clone();
        receiver.close(tx).unwrap();
        receiver.close(event).unwrap();
        sender.close(rx).unwrap();
        {
            let socket = receiver.local_socket(rx).unwrap().unwrap();
            socket.set_reuse(16, 1).unwrap();
            socket.set_reuse(35, 1).unwrap();
        }
        let send = direct(&sender);
        std::thread::spawn(move || {
            let mut m = memory();
            rights(&mut m, &[event]);
            assert_eq!(
                send.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
                Some(Ok(4))
            );
        })
        .join()
        .unwrap();
        sender.close(event).unwrap();
        let receive = direct(&receiver);
        let (fd, types, identity) = std::thread::spawn(move || {
            let mut m = memory();
            header(&mut m, 88);
            assert_eq!(
                receive.invoke(212, [rx as u64, 0x1000, 0x40000000, 0, 0, 0], &mut m),
                Some(Ok(4))
            );
            assert_eq!(m.read_array::<4>(0x1200).unwrap(), *b"abcd");
            assert_eq!(m.read_u64(0x1028).unwrap(), 88);
            assert_eq!(word(&m, 0x1030), 0);
            (
                word(&m, 0x1350),
                [word(&m, 0x130c), word(&m, 0x132c), word(&m, 0x134c)],
                [word(&m, 0x1310), word(&m, 0x1314), word(&m, 0x1318)],
            )
        })
        .join()
        .unwrap();
        assert_eq!(types, [2, 35, 1]);
        assert_eq!(identity, [42, 1000, 1001]);
        assert_ne!(receiver.flags(fd).unwrap() & O_CLOEXEC, 0);
        assert_eq!(receiver.read(fd, 8).unwrap(), 73u64.to_le_bytes());
        assert!(
            sender.flags(event).is_err(),
            "original sender FD stays closed"
        );
    }
    #[test]
    fn peek_installs_aliases_of_the_same_ofd_and_truncation_releases_unreceived_rights() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let event = v.eventfd(19, 0).unwrap();
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[event]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        v.close(event).unwrap();
        let mut aliases = Vec::new();
        for flags in [2, 2, 0x40000000] {
            header(&mut m, 24);
            assert_eq!(
                d.invoke(212, [rx as u64, 0x1000, flags, 0, 0, 0], &mut m),
                Some(Ok(4))
            );
            aliases.push(word(&m, 0x1310));
        }
        assert_ne!(aliases[0], aliases[1]);
        assert_eq!(v.read(aliases[0], 8).unwrap(), 19u64.to_le_bytes());
        assert_eq!(v.read(aliases[1], 8), Err(Errno(11)));
        assert_eq!(v.flags(aliases[0]).unwrap() & O_CLOEXEC, 0);
        assert_ne!(v.flags(aliases[2]).unwrap() & O_CLOEXEC, 0);
        let [read, write] = v.pipe(0).unwrap();
        rights(&mut m, &[write]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        v.close(write).unwrap();
        assert_eq!(
            v.read(read, 1),
            Err(Errno(11)),
            "queued right retains writer"
        );
        header(&mut m, 0);
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(word(&m, 0x1030), 8);
        assert_eq!(v.read(read, 1).unwrap(), b"", "truncated right is closed");
    }
    #[test]
    fn mixed_owner_rights_and_output_faults_defer_or_fail_before_queue_effects() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let event = v.eventfd(1, 0).unwrap();
        let directory = v.open_at(-100, b"/", 0, 0).unwrap();
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[event, directory]);
        assert_eq!(d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m), None);
        assert_eq!(v.readable_bytes(rx).unwrap(), Some(0));
        assert_eq!(
            Linux::network_vfs(&mut v, 211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Ok(4)
        );
        header(&mut m, 24);
        assert_eq!(d.invoke(212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m), None);
        assert_eq!(v.readable_bytes(rx).unwrap(), Some(4));
        assert_eq!(
            Linux::network_vfs(&mut v, 212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Ok(4)
        );
        rights(&mut m, &[event]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        header(&mut m, 24);
        m.write_array(0x1100, 0x9000u64.to_le_bytes()).unwrap();
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(v.readable_bytes(rx).unwrap(), Some(4));
    }
    #[test]
    fn blocked_send_keeps_original_rights_and_bytes_after_source_fd_and_header_reuse() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        v.local_socket(rx)
            .unwrap()
            .unwrap()
            .set_reuse(8, 256)
            .unwrap();
        assert_eq!(v.write(tx, &[0x55; 512]), Ok(512));
        let event = v.eventfd(19, 0).unwrap();
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[event]);
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let args = [tx as u64, 0x1000, 0, 0, 0, 0];
        let wait = blocked(
            d.start(211, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        let file = wait.retained_byte.clone().unwrap();
        drop(wait);
        let files = v.shared_files();
        std::thread::spawn(move || files.close(event, 1).unwrap().unwrap())
            .join()
            .unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), event);
        m.write(0x1000, &[0xff; 56]).unwrap();
        m.write(0x1200, b"evil").unwrap();
        m.write(0x1300, &[0xff; 24]).unwrap();
        assert_eq!(v.read(rx, 512).unwrap(), [0x55; 512]);
        assert!(matches!(
            d.start_retained_byte(file, 211, args, &mut m, 1, &Arc::downgrade(&target)),
            IoAttempt::Complete(Ok(4))
        ));
        let received = v.local_socket(rx).unwrap().unwrap().recv(4, 0).unwrap();
        assert_eq!(received.data, b"abcd");
        let (fds, truncated) = v.receive_rights(received.rights, 1, false);
        assert!(!truncated);
        assert_eq!(v.read(fds[0], 8).unwrap(), 19u64.to_le_bytes());
        assert_eq!(v.read(event, 8).unwrap(), 99u64.to_le_bytes());
    }
    #[test]
    fn blocked_receive_and_owner_fallback_keep_original_transport_and_output_ranges() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let directory = v.open_at(-100, b"/", 0, 0).unwrap();
        let d = direct(&v);
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let args = [rx as u64, 0x1000, 0, 0, 0, 0];
        let wait = blocked(
            d.start(212, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
        );
        let file = wait.retained_byte.clone().unwrap();
        drop(wait);
        let owner = v.retain_uring_fd(rx).unwrap();
        assert!(owner.ofd_identity() == file.local_owner_identity().unwrap());
        v.close(rx).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), rx);
        m.write(0x1000, &[0xff; 56]).unwrap();
        m.write(0x1100, &[0xff; 16]).unwrap();
        v.local_socket(tx)
            .unwrap()
            .unwrap()
            .send_rights(b"real", 0, v.send_rights(&[directory]).unwrap())
            .unwrap();
        let file = match d.start_retained_byte(file, 212, args, &mut m, 1, &Arc::downgrade(&target))
        {
            IoAttempt::ByteCheckpoint(file) => file,
            _ => panic!("owner-only right needs retained fallback"),
        };
        assert!(matches!(
            d.start_owned_local_message(file, &mut v, &owner, &mut m, 1, &Arc::downgrade(&target)),
            IoAttempt::Complete(Ok(4))
        ));
        assert_eq!(m.read_array::<4>(0x1200).unwrap(), *b"real");
        assert_eq!(
            v.fd_kind(word(&m, 0x1310)).unwrap(),
            v.fd_kind(directory).unwrap()
        );
        assert_eq!(v.read(rx, 8).unwrap(), 99u64.to_le_bytes());
    }
}
