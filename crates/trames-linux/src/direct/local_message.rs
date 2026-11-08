// SPDX-License-Identifier: GPL-3.0-or-later
//! The shared original ancillary ABI on one accepted Unix transport.
use super::*;
mod batch;
use batch::Batch;
// Keep the existing single-message records inline in their Arc allocation.
// Boxing them would add an allocation to every normal message for a cold batch.
#[allow(clippy::large_enum_variant)]
enum Transfer {
    Single {
        prepared: crate::network::unix::PreparedTransfer<trames_vfs::SharedRights>,
        datagram: Option<crate::network::unix::DatagramState>,
    },
    Batch(Box<Batch>),
}
pub(super) struct AcceptedMessage {
    transfer: Transfer,
    factory: trames_vfs::DescriptorFactory,
    identity: [u32; 3],
    number: u32,
    args: [u64; 6],
}
struct Message<'a> {
    factory: &'a trames_vfs::DescriptorFactory,
    fd: &'a trames_vfs::DirectFd,
    identity: [u32; 3],
    datagram: Option<&'a crate::network::unix::DatagramState>,
    paths: Option<&'a trames_vfs::PathQueries>,
    original_paths: Option<&'a trames_vfs::Vfs>,
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
        if let Some(datagram) = self.datagram {
            return datagram.source.send_datagram(
                &datagram.target,
                bytes,
                flags,
                rights,
                identity,
                || {
                    if let Some(vfs) = self.original_paths {
                        Some(vfs.resolve_local_datagram(&datagram.source, destination))
                    } else {
                        self.paths?.local_datagram(&datagram.source, destination)
                    }
                },
            );
        }
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
    fn prepare_local_fd(
        &self,
        fd: &trames_vfs::DirectFd,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Option<Result<RetainedByte, Errno>> {
        let factory = self.resources.as_ref()?;
        let identity = self
            .local_identity
            .unwrap_or_else(|| factory.local_sender_credentials());
        self.prepare_local_context(fd, number, args, memory, (factory, identity))
    }
    fn prepare_local_context(
        &self,
        fd: &trames_vfs::DirectFd,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        (factory, identity): (&trames_vfs::DescriptorFactory, [u32; 3]),
    ) -> Option<Result<RetainedByte, Errno>> {
        if number == 269 {
            return Some(Batch::new(args).map(|batch| RetainedByte {
                fd: fd.clone(),
                operation: ByteOperation::Message(Arc::new(AcceptedMessage {
                    transfer: Transfer::Batch(Box::new(batch)),
                    factory: factory.clone(),
                    identity,
                    number,
                    args,
                })),
            }));
        }
        let datagram = if fd.is_addressed_datagram() {
            Some(crate::network::unix::DatagramState::new(
                fd.local_operation()?,
            ))
        } else {
            None
        };
        let io = Message {
            factory,
            fd,
            identity,
            datagram: datagram.as_ref(),
            paths: self.paths.as_ref(),
            original_paths: None,
        };
        Some(
            crate::network::unix::prepare_transfer(number, args, memory, &io)?.map(|prepared| {
                RetainedByte {
                    fd: fd.clone(),
                    operation: ByteOperation::Message(Arc::new(AcceptedMessage {
                        transfer: Transfer::Single { prepared, datagram },
                        factory: factory.clone(),
                        identity,
                        number,
                        args,
                    })),
                }
            }),
        )
    }
    pub(super) fn start_local_message(
        &self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let fd = self.descriptors.get(args[0] as u32)?;
        if !fd.is_unix() || matches!(number, 206 | 207) && fd.local_kind() == 1 {
            return None;
        }
        Some(match self.prepare_local_fd(&fd, number, args, memory) {
            Some(Ok(file)) => self.start_retained_byte(file, number, args, memory, pid, target),
            Some(Err(error)) => self.complete(number, args, Err(error)),
            None => IoAttempt::Checkpoint,
        })
    }
    pub(super) fn prepare_packet_byte(
        &self,
        file: &RetainedByte,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Option<Result<RetainedByte, Errno>> {
        self.prepare_local_fd(&file.fd, number, args, memory)
    }
    /// Same accepted ABI on the caller's original path context. No private VFS
    /// projection is constructed for a ready solo message or its byte consumers.
    #[allow(clippy::too_many_arguments)]
    pub fn start_local_transfer(
        &self,
        retained: Option<RetainedByte>,
        number: u32,
        args: [u64; 6],
        vfs: &trames_vfs::Vfs,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let prepared = if let Some(file) = retained {
            Ok(file)
        } else {
            let fd = vfs.direct_descriptors().get(args[0] as u32)?;
            if !fd.is_unix() {
                return None;
            }
            self.prepare_local_fd(&fd, number, args, memory)?
        };
        Some(match prepared {
            Ok(file) => {
                self.start_byte_in(file, number, args, memory, pid, target, false, Some(vfs))
            }
            Err(error) => self.complete(number, args, Err(error)),
        })
    }
    pub(super) fn transfer_retained(
        &self,
        file: &RetainedByte,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        original_paths: Option<&trames_vfs::Vfs>,
    ) -> Option<Result<u64, Errno>> {
        self.terminal_stop.set(false);
        if let ByteOperation::Signal(read) = &file.operation {
            return Some(read.check(&file.fd, memory));
        }
        if let Some(accepted) = file.message() {
            let Transfer::Single { prepared, datagram } = &accepted.transfer else {
                let Transfer::Batch(batch) = &accepted.transfer else {
                    unreachable!()
                };
                let result = batch.progress(self, accepted, &file.fd, memory, original_paths);
                if let Some(task) = self
                    .task_signal
                    .as_ref()
                    .filter(|_| matches!(result, Some(Ok(_))))
                {
                    if batch.take_pipe_signal() {
                        task.raise(13);
                    }
                }
                return result;
            };
            if let Err(error) = prepared.recheck(memory) {
                return Some(Err(error));
            }
            prepared.progress(
                memory,
                &mut Message {
                    factory: &accepted.factory,
                    fd: &file.fd,
                    identity: accepted.identity,
                    datagram: datagram.as_ref(),
                    paths: self.paths.as_ref(),
                    original_paths,
                },
            )
        } else {
            self.transfer_fd(&file.fd, number, args, memory)
        }
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
                datagram: None,
                paths: self.paths.as_ref(),
                original_paths: None,
                identity: self
                    .local_identity
                    .unwrap_or_else(|| factory.local_sender_credentials()),
            },
        )
    }
}
impl RetainedByte {
    pub(super) fn datagram_target(&self) -> Option<&trames_vfs::LocalDatagram> {
        match &self.message()?.transfer {
            Transfer::Single { datagram, .. } => datagram.as_ref()?.target.get(),
            Transfer::Batch(_) => None,
        }
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<trames_vfs::IoSubscription> {
        let mut subscriptions = self.fd.subscribe(signal);
        if let Some(Transfer::Batch(batch)) = self.message().map(|m| &m.transfer) {
            subscriptions.extend(batch.subscribe(signal));
        }
        if let Some(target) = self.datagram_target() {
            subscriptions.push(target.subscribe(signal));
        }
        subscriptions
    }
    pub(super) fn batch_shares_resources(&self, fds: &DirectFds) -> bool {
        matches!(self.message().map(|m| &m.transfer), Some(Transfer::Batch(batch)) if batch.shares_resources(fds))
    }
    pub fn batch_pipe_signal(&self) -> bool {
        matches!(self.message().map(|m| &m.transfer), Some(Transfer::Batch(batch)) if batch.pipe_signal())
    }
    pub fn local_message_entry(&self) -> Option<(u32, [u64; 6])> {
        self.message().map(|m| (m.number, m.args))
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
    fn epoll_control(v: &mut Vfs) -> u32 {
        // Epoll transfers the original complete graph, including legacy watches.
        v.epoll_create(0).unwrap()
    }
    fn direct(v: &Vfs) -> DirectSyscalls {
        DirectSyscalls::new(v.direct_descriptors()).with_resources(v.descriptor_factory())
    }
    #[test]
    fn unix_owning_rights_preserve_fault_before_dequeue_and_original_fd_after_reuse() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let [carried, peer] = v.socketpair(1, 1, 0).unwrap();
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[carried]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        v.close(carried).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), carried);
        header(&mut m, 24);
        m.write_array(0x1100, 0x9000u64.to_le_bytes()).unwrap();
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Err(Errno(14)))
        );
        assert_eq!(v.readable_bytes(rx).unwrap(), Some(4));
        header(&mut m, 24);
        m.write_array(0x1100, 0x1200u64.to_le_bytes()).unwrap();
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        let imported = word(&m, 0x1310);
        v.write(imported, b"alive").unwrap();
        assert_eq!(v.read(peer, 5).unwrap(), b"alive");
        assert_eq!(v.read(carried, 8).unwrap(), 99u64.to_le_bytes());
    }
    #[test]
    fn parked_shared_unix_rights_receive_resumes_without_an_owner_checkpoint() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let [carried, peer] = v.socketpair(1, 1, 0).unwrap();
        let d = direct(&v);
        let mut m = memory();
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let args = [rx as u64, 0x1000, 0, 0, 0, 0];
        let pending = match d
            .start(212, args, &mut m, 1, &Arc::downgrade(&target), None)
            .unwrap()
        {
            IoAttempt::Blocked(wait) => wait,
            _ => panic!("receive must park before a sender runs"),
        };
        m.write(0x1000, &[0xff; 56]).unwrap();
        m.write(0x1100, &[0xff; 16]).unwrap();
        let mut outgoing = memory();
        rights(&mut outgoing, &[carried]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut outgoing),
            Some(Ok(4))
        );
        v.close(carried).unwrap();
        assert_eq!(v.eventfd(73, 0).unwrap(), carried);
        assert!(pending.signal.ready());
        assert!(matches!(
            d.resume(pending, &mut m),
            IoAttempt::Complete(Ok(4))
        ));
        let imported = word(&m, 0x1310);
        assert_eq!(m.read_array::<4>(0x1200).unwrap(), *b"abcd");
        v.write(imported, b"original").unwrap();
        assert_eq!(v.read(peer, 8).unwrap(), b"original");
        assert_eq!(v.read(carried, 8).unwrap(), 73u64.to_le_bytes());
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
    fn directory_and_memfd_rights_keep_actual_cursor_seals_and_backing_after_reuse() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let directory = v.open_at(-100, b"/", 0, 0).unwrap();
        assert_eq!(v.getdents(directory, 24).unwrap().len(), 24);
        let shared = v.memfd_create(b"portable", 2).unwrap();
        v.write(shared, b"hello").unwrap();
        v.seek(shared, 1, 0).unwrap();
        let mapping = v.shared_file(shared).unwrap().map(0, 5).unwrap();
        v.seals(shared, Some(4 | 8)).unwrap();
        let mut epoch = trames_vfs::FileEpoch::default();
        let files = epoch.capture(&v, true);
        assert!(
            files.get(shared).is_none(),
            "sharing ownership must not bypass seals/VM admission"
        );
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[directory, shared]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        v.close(directory).unwrap();
        v.close(shared).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), directory);
        assert_eq!(v.eventfd(100, 0).unwrap(), shared);
        header(&mut m, 24);
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0x40000000, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        let received_dir = word(&m, 0x1310);
        let received_file = word(&m, 0x1314);
        assert!(
            v.fd_snapshot()
                .iter()
                .find(|f| f.fd == received_dir)
                .unwrap()
                .flags
                & O_CLOEXEC
                != 0
        );
        let next = v.getdents(received_dir, 24).unwrap();
        assert_eq!(&next[19..21], b"..");
        assert_eq!(v.read(received_file, 4).unwrap(), b"ello");
        assert_eq!(v.seals(received_file, None), Ok(12));
        assert_eq!(v.write(received_file, b"x"), Err(Errno(1)));
        assert_eq!(v.truncate_fd(received_file, 6), Err(Errno(1)));
        v.close(received_file).unwrap();
        // SAFETY: this retained managed mapping owns five initialized bytes;
        // no other thread mutates them in this test.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(mapping.pointer(), 5) },
            b"hello"
        );
        epoch.finish();
    }
    #[test]
    fn pty_rights_retain_real_endpoints_after_source_close_and_reuse() {
        let mut v = Vfs::default();
        v.set_runtime_info(1, Default::default());
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let master = v.open_at(-100, b"/dev/ptmx", 2, 0).unwrap();
        let pair = v.pty(master).unwrap().unwrap().pair.clone();
        pair.locked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let slave = v.open_pty_peer(master, 2).unwrap();
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[master, slave]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        for fd in [master, slave] {
            v.close(fd).unwrap();
            assert_eq!(v.eventfd(99, 0).unwrap(), fd);
        }
        assert!(pair.master_alive.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(pair.slaves.load(std::sync::atomic::Ordering::Relaxed), 1);
        header(&mut m, 24);
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0x40000000, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        let got_master = word(&m, 0x1310);
        let got_slave = word(&m, 0x1314);
        assert_eq!(
            d.invoke(29, [got_master as u64, 0x80045430, 0x1400, 0, 0, 0], &mut m),
            Some(Ok(0))
        );
        assert_eq!(word(&m, 0x1400), pair.number);
        let bytes = direct(&v).with_terminal(trames_vfs::TerminalAccess {
            session: 0,
            group: 0,
            controlling: None,
            ignore_ttou: false,
        });
        m.write(0x1400, b"live").unwrap();
        assert_eq!(
            bytes.invoke(64, [got_slave as u64, 0x1400, 4, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(
            bytes.invoke(63, [got_master as u64, 0x1500, 4, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(m.read_array::<4>(0x1500).unwrap(), *b"live");
        v.close(got_master).unwrap();
        assert!(!pair.master_alive.load(std::sync::atomic::Ordering::Relaxed));
        v.close(got_slave).unwrap();
        assert_eq!(pair.slaves.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
    #[test]
    fn signal_bpf_and_namespace_rights_use_original_shared_objects_after_source_reuse() {
        let mut v = Vfs::default();
        v.set_runtime_info(
            1,
            trames_vfs::RuntimeInfo {
                processes: vec![trames_vfs::ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let signal = v.signalfd(-1, 1 << 9, trames_vfs::O_NONBLOCK).unwrap();
        let namespace = v.open_at(-100, b"/proc/self/ns/uts", 0, 0).unwrap();
        let program = v
            .bpf_load_device(&[0xb7, 0, 0, 0, 1, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[signal, namespace, program]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        for fd in [signal, namespace, program] {
            v.close(fd).unwrap();
            assert_eq!(v.eventfd(99, 0).unwrap(), fd);
        }
        v.unshare_uts().unwrap();
        v.set_uts_name(false, b"new").unwrap();
        header(&mut m, 32);
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        let got = [word(&m, 0x1310), word(&m, 0x1314), word(&m, 0x1318)];
        assert_eq!(v.signalfd_mask(got[0]), Ok(Some(1 << 9)));
        v.signalfd(got[0] as i32, 1 << 11, 0).unwrap();
        assert_eq!(v.signalfd_mask(got[0]), Ok(Some(1 << 11)));
        v.setns(got[1], trames_vfs::CLONE_NEWUTS).unwrap();
        assert_eq!(v.uts_name(false), b"trames");
        let reopened = v.bpf_get_fd(1).unwrap();
        v.close(reopened).unwrap();
        assert_eq!(v.read(got[2], 8), Err(Errno(22)));
        v.close(got[2]).unwrap();
        assert_eq!(v.bpf_get_fd(1), Err(Errno(2)));
    }
    #[test]
    fn mixed_epoll_rights_and_output_faults_keep_source_effect_order() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let event = v.eventfd(1, 0).unwrap();
        let owner_socket = epoll_control(&mut v);
        let d = direct(&v);
        let mut m = memory();
        rights(&mut m, &[event, owner_socket]);
        assert_eq!(
            d.invoke(211, [tx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(v.readable_bytes(rx).unwrap(), Some(4));
        header(&mut m, 24);
        assert_eq!(
            d.invoke(212, [rx as u64, 0x1000, 0, 0, 0, 0], &mut m),
            Some(Ok(4))
        );
        assert_eq!(v.readable_bytes(rx).unwrap(), Some(0));
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
    fn blocked_receive_of_epoll_right_keeps_original_transport_and_output_ranges() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let owner_socket = epoll_control(&mut v);
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
        assert!(owner.ofd_identity() == file.ofd_identity());
        v.close(rx).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), rx);
        m.write(0x1000, &[0xff; 56]).unwrap();
        m.write(0x1100, &[0xff; 16]).unwrap();
        v.local_socket(tx)
            .unwrap()
            .unwrap()
            .send_rights(b"real", 0, v.send_rights(&[owner_socket]).unwrap())
            .unwrap();
        assert!(matches!(
            d.start_retained_byte(file, 212, args, &mut m, 1, &Arc::downgrade(&target)),
            IoAttempt::Complete(Ok(4))
        ));
        assert_eq!(m.read_array::<4>(0x1200).unwrap(), *b"real");
        assert_eq!(
            v.fd_kind(word(&m, 0x1310)).unwrap(),
            v.fd_kind(owner_socket).unwrap()
        );
        assert_eq!(v.read(rx, 8).unwrap(), 99u64.to_le_bytes());
    }
    fn datagrams() -> (Vfs, u32, u32) {
        let mut v = Vfs::default();
        let tx = v.local_create(2, 0).unwrap();
        let rx = v.local_create(2, 0).unwrap();
        v.local_bind(&v.local_socket(tx).unwrap().unwrap(), b"\x01\x00/source\0")
            .unwrap();
        v.local_bind(&v.local_socket(rx).unwrap().unwrap(), b"\x01\x00/target\0")
            .unwrap();
        (v, tx, rx)
    }
    fn datagram_direct(v: &Vfs) -> DirectSyscalls {
        direct(v).with_paths(v.path_queries())
    }
    fn packet_args(m: &mut Memory, tx: u32) -> [u64; 6] {
        let address = b"\x01\x00/target\0";
        m.write(0x1400, address).unwrap();
        [tx as u64, 0x1200, 4, 0, 0x1400, address.len() as u64]
    }
    #[test]
    fn datagram_blocked_send_subscribes_target_space_and_retains_original_target_bytes_and_ofd() {
        for close_target in [false, true] {
            let (mut v, tx, rx) = datagrams();
            let receiver = v.local_socket(rx).unwrap().unwrap();
            receiver.set_reuse(8, 256).unwrap();
            v.local_send_to(
                &v.local_socket(tx).unwrap().unwrap(),
                &[0x55; 512],
                0,
                Some(b"\x01\x00/target\0"),
                Default::default(),
            )
            .unwrap();
            let d = datagram_direct(&v);
            let mut m = memory();
            let args = packet_args(&mut m, tx);
            let target: Arc<dyn IoWake> = Arc::new(Target);
            let wait = blocked(
                d.start(206, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap(),
            );
            assert!(!wait.signal.ready());
            assert!(!wait.external_wait());
            v.close(tx).unwrap();
            assert_eq!(v.eventfd(99, 0).unwrap(), tx);
            m.write(0x1200, b"evil").unwrap();
            m.write(0x1400, &[0xff; 10]).unwrap();
            v.unlink_at(-100, b"/target", false).unwrap();
            if close_target {
                v.close(rx).unwrap();
            }
            let replacement = v.socket(1, 2 | O_CLOEXEC, 0).unwrap();
            v.local_bind(
                &v.local_socket(replacement).unwrap().unwrap(),
                b"\x01\x00/target\0",
            )
            .unwrap();
            if close_target {
                drop(receiver);
                assert!(
                    wait.signal.ready(),
                    "final target close wakes refused sender"
                );
                assert!(matches!(
                    d.resume(wait, &mut m),
                    IoAttempt::Complete(Err(Errno(111)))
                ));
            } else {
                assert_eq!(receiver.recv(512, 0).unwrap().data, [0x55; 512]);
                assert!(
                    wait.signal.ready(),
                    "receive frees target capacity, not source capacity"
                );
                assert!(matches!(d.resume(wait, &mut m), IoAttempt::Complete(Ok(4))));
                assert_eq!(receiver.recv(4, 0).unwrap().data, b"abcd");
            }
            assert_eq!(v.read(replacement, 4), Err(Errno(11)));
            assert_eq!(v.read(tx, 8).unwrap(), 99u64.to_le_bytes());
        }
    }
    #[test]
    fn datagram_raw_vectors_and_message_rights_keep_packet_abi_and_original_outputs_on_wait() {
        let (mut v, tx, rx) = datagrams();
        v.local_connect(&v.local_socket(tx).unwrap().unwrap(), b"\x01\x00/target\0")
            .unwrap();
        let d = datagram_direct(&v);
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let mut m = memory();
        for send_number in [64, 66, 206, 211] {
            header(&mut m, 0);
            m.write(0x1200, b"abcd").unwrap();
            let args = match send_number {
                66 => [tx as u64, 0x1100, 1, 0, 0, 0],
                211 => [tx as u64, 0x1000, 0, 0, 0, 0],
                _ => [tx as u64, 0x1200, 4, 0, 0, 0],
            };
            assert!(matches!(
                d.start(send_number, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap(),
                IoAttempt::Complete(Ok(4))
            ));
            assert_eq!(
                v.local_socket(rx)
                    .unwrap()
                    .unwrap()
                    .recv(1, 0x20)
                    .unwrap()
                    .length,
                4
            );
            assert_eq!(
                v.read(rx, 4),
                Err(Errno(11)),
                "vector send emits one packet"
            );
        }
        for recv_number in [63, 65, 207, 212] {
            header(&mut m, 24);
            m.write_array(0x1460, 110u32.to_le_bytes()).unwrap();
            let args = match recv_number {
                65 => [rx as u64, 0x1100, 1, 0, 0, 0],
                212 => [rx as u64, 0x1000, 0, 0, 0, 0],
                207 => [rx as u64, 0x1200, 4, 0, 0x1400, 0x1460],
                _ => [rx as u64, 0x1200, 4, 0, 0, 0],
            };
            let wait = blocked(
                d.start(recv_number, args, &mut m, 1, &Arc::downgrade(&target), None)
                    .unwrap(),
            );
            let file = wait.retained_byte.clone().unwrap();
            drop(wait);
            // Freeze outputs once; neither an edited iovec nor changed capacity
            // may redirect copyout after wait/owner handoff.
            m.write_array(0x1100, 0x9000u64.to_le_bytes()).unwrap();
            m.write_array(0x1460, 0u32.to_le_bytes()).unwrap();
            let owner_socket = epoll_control(&mut v);
            v.local_socket(tx)
                .unwrap()
                .unwrap()
                .send_rights(b"real", 0, v.send_rights(&[owner_socket]).unwrap())
                .unwrap();
            assert!(matches!(
                d.start_retained_byte(file, recv_number, args, &mut m, 1, &Arc::downgrade(&target)),
                IoAttempt::Complete(Ok(4))
            ));
            assert_eq!(m.read_array::<4>(0x1200).unwrap(), *b"real");
            if recv_number == 207 {
                assert_eq!(m.read_array::<10>(0x1400).unwrap(), *b"\x01\x00/source\0");
                assert_eq!(word(&m, 0x1460), 10);
            }
            v.close(owner_socket).unwrap();
            m.write_array(0x1100, 0x1200u64.to_le_bytes()).unwrap();
        }
    }
    fn batch_headers(m: &mut Memory, messages: usize) {
        m.write(0x1800, &vec![0; messages * 64]).unwrap();
        for index in 0..messages as u64 {
            let header = 0x1800 + index * 64;
            m.write_array(header + 16, 0x1100u64.to_le_bytes()).unwrap();
            m.write_array(header + 24, 1u64.to_le_bytes()).unwrap();
        }
    }
    fn start_batch(d: &DirectSyscalls, fd: u32, count: u64, m: &mut Memory) -> IoAttempt {
        let target: Arc<dyn IoWake> = Arc::new(Target);
        d.start(
            269,
            [fd as u64, 0x1800, count, 0x4000, 0, 0],
            m,
            1,
            &Arc::downgrade(&target),
            None,
        )
        .unwrap()
    }
    #[test]
    fn worker_batches_preserve_packet_lengths_late_faults_and_post_send_copyout_order() {
        for kind in [1, 2, 5] {
            let mut v = Vfs::default();
            let [tx, rx] = v.socketpair(1, kind, 0).unwrap();
            let d = direct(&v);
            let mut m = memory();
            batch_headers(&mut m, 3);
            assert!(matches!(
                start_batch(&d, tx, 3, &mut m),
                IoAttempt::Complete(Ok(3))
            ));
            for index in 0..3 {
                assert_eq!(word(&m, 0x1838 + index * 64), 4);
            }
            if kind == 1 {
                assert_eq!(v.read(rx, 12).unwrap(), b"abcdabcdabcd");
            } else {
                for _ in 0..3 {
                    assert_eq!(v.read(rx, 12).unwrap(), b"abcd");
                }
            }
            m.write_array(0x1850, 0x9000u64.to_le_bytes()).unwrap();
            assert!(matches!(
                start_batch(&d, tx, 3, &mut m),
                IoAttempt::Complete(Ok(1))
            ));
            assert_eq!(v.read(rx, 12).unwrap(), b"abcd");
            batch_headers(&mut m, 1);
            m.protect(0x1000, 0x1000, Permissions::R).unwrap();
            assert!(matches!(
                start_batch(&d, tx, 1, &mut m),
                IoAttempt::Complete(Err(Errno(14)))
            ));
            assert_eq!(
                v.read(rx, 12).unwrap(),
                b"abcd",
                "length copyout faults after delivery"
            );
        }
    }
    #[test]
    fn batch_capacity_wait_keeps_first_input_target_and_ofd_then_imports_later_messages_once() {
        let (mut v, tx, rx) = datagrams();
        let receiver = v.local_socket(rx).unwrap().unwrap();
        receiver.set_reuse(8, 256).unwrap();
        v.local_send_to(
            &v.local_socket(tx).unwrap().unwrap(),
            &[0x55; 512],
            0,
            Some(b"\x01\x00/target\0"),
            Default::default(),
        )
        .unwrap();
        let event = v.eventfd(77, 0).unwrap();
        let d = datagram_direct(&v);
        let mut m = memory();
        batch_headers(&mut m, 2);
        m.write(0x1400, b"\x01\x00/target\0").unwrap();
        for header in [0x1800, 0x1840] {
            m.write_array(header, 0x1400u64.to_le_bytes()).unwrap();
            m.write_array(header + 8, 10u32.to_le_bytes()).unwrap();
        }
        rights(&mut m, &[event]);
        m.write_array(0x1860, 0x1300u64.to_le_bytes()).unwrap();
        m.write_array(0x1868, 24u64.to_le_bytes()).unwrap();
        let wait = blocked(start_batch(&d, tx, 2, &mut m));
        v.close(tx).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), tx);
        v.unlink_at(-100, b"/target", false).unwrap();
        let other = v.local_create(2, 0).unwrap();
        v.local_bind(
            &v.local_socket(other).unwrap().unwrap(),
            b"\x01\x00/target\0",
        )
        .unwrap();
        m.write(0x1200, b"next").unwrap();
        assert_eq!(receiver.recv(512, 0).unwrap().data, [0x55; 512]);
        assert!(wait.signal.ready());
        assert!(matches!(
            datagram_direct(&v)
                .with_resources(Vfs::default().descriptor_factory())
                .resume(wait, &mut m),
            IoAttempt::Complete(Ok(2))
        ));
        assert_eq!(
            receiver.recv(4, 0).unwrap().data,
            b"abcd",
            "waiting item uses original target and input"
        );
        let received = v.local_socket(other).unwrap().unwrap().recv(4, 0).unwrap();
        assert_eq!(
            received.data, b"next",
            "next unaccepted item resolves independently"
        );
        let (fds, truncated) = v.receive_rights(received.rights, 1, false);
        assert!(!truncated);
        assert_eq!(v.read(fds[0], 8).unwrap(), 77u64.to_le_bytes());
        assert_eq!(v.read(tx, 8).unwrap(), 99u64.to_le_bytes());
    }
    #[test]
    fn batch_epoll_rights_complete_on_source_without_replaying_any_item() {
        let (mut v, tx, rx) = datagrams();
        v.local_connect(&v.local_socket(tx).unwrap().unwrap(), b"\x01\x00/target\0")
            .unwrap();
        let legacy = epoll_control(&mut v);
        let d = datagram_direct(&v);
        let mut m = memory();
        batch_headers(&mut m, 3);
        rights(&mut m, &[legacy]);
        m.write_array(0x1860, 0x1300u64.to_le_bytes()).unwrap();
        m.write_array(0x1868, 24u64.to_le_bytes()).unwrap();
        let args = [tx as u64, 0x1800, 3, 0x4000, 0, 0];
        let target: Arc<dyn IoWake> = Arc::new(Target);
        assert!(matches!(
            d.start(269, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap(),
            IoAttempt::Complete(Ok(3))
        ));
        v.close(tx).unwrap();
        assert_eq!(v.eventfd(99, 0).unwrap(), tx);
        assert_eq!(
            v.local_socket(rx)
                .unwrap()
                .unwrap()
                .recv(4, 0)
                .unwrap()
                .data,
            b"abcd"
        );
        let second = v.local_socket(rx).unwrap().unwrap().recv(4, 0).unwrap();
        assert_eq!(second.data, b"abcd");
        let (fds, truncated) = v.receive_rights(second.rights, 1, false);
        assert!(!truncated);
        assert_eq!(v.fd_kind(fds[0]).unwrap(), v.fd_kind(legacy).unwrap());
        assert_eq!(v.read(rx, 4).unwrap(), b"abcd");
        assert_eq!(
            v.read(rx, 4),
            Err(Errno(11)),
            "first packet was not replayed"
        );
        assert_eq!(v.read(tx, 8).unwrap(), 99u64.to_le_bytes());
    }
    #[test]
    fn batch_partial_datagram_epipe_returns_count_without_signal_or_owner_handoff() {
        #[derive(Default)]
        struct Signals(std::sync::atomic::AtomicUsize);
        impl trames_vfs::TaskSignal for Signals {
            fn raise(&self, signal: u32) {
                assert_eq!(signal, 13);
                self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        for no_signal in [false, true] {
            let (mut v, tx, rx) = datagrams();
            let bad = v.local_create(2, 0).unwrap();
            let socket = v.local_socket(bad).unwrap().unwrap();
            v.local_bind(&socket, b"\x01\x00/broken\0").unwrap();
            socket.shutdown(0).unwrap();
            let signals = Arc::new(Signals::default());
            let d = datagram_direct(&v).with_task_signal(signals.clone());
            let mut m = memory();
            batch_headers(&mut m, 2);
            m.write(0x1400, b"\x01\x00/target\0").unwrap();
            m.write(0x1420, b"\x01\x00/broken\0").unwrap();
            for (header, address) in [(0x1800, 0x1400u64), (0x1840, 0x1420)] {
                m.write_array(header, address.to_le_bytes()).unwrap();
                m.write_array(header + 8, 10u32.to_le_bytes()).unwrap();
            }
            let target: Arc<dyn IoWake> = Arc::new(Target);
            let args = [
                tx as u64,
                0x1800,
                2,
                if no_signal { 0x4000 } else { 0 },
                0,
                0,
            ];
            let attempt = d
                .start(269, args, &mut m, 1, &Arc::downgrade(&target), None)
                .unwrap();
            assert!(matches!(attempt, IoAttempt::Complete(Ok(1))));
            assert_eq!(signals.0.load(std::sync::atomic::Ordering::Relaxed), 0);
            assert_eq!(v.read(rx, 4).unwrap(), b"abcd");
            assert_eq!(v.read(rx, 4), Err(Errno(11)));
        }
    }
    #[test]
    fn worker_batch_zero_count_cap_short_stream_and_partial_eagain_keep_linux_results() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 2, 0).unwrap();
        v.local_socket(rx)
            .unwrap()
            .unwrap()
            .set_reuse(8, 256)
            .unwrap();
        v.write(tx, &[0x55; 508]).unwrap();
        let d = direct(&v);
        let mut m = memory();
        batch_headers(&mut m, 2);
        assert!(matches!(
            start_batch(&d, tx, 2, &mut m),
            IoAttempt::Complete(Ok(1))
        ));
        assert_eq!(v.read(rx, 512).unwrap(), [0x55; 508]);
        assert_eq!(v.read(rx, 4).unwrap(), b"abcd");
        assert_eq!(v.read(rx, 4), Err(Errno(11)));
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        v.local_socket(rx)
            .unwrap()
            .unwrap()
            .set_reuse(8, 256)
            .unwrap();
        v.write(tx, &[0x55; 510]).unwrap();
        let d = direct(&v);
        batch_headers(&mut m, 2);
        assert!(matches!(
            start_batch(&d, tx, 2, &mut m),
            IoAttempt::Complete(Ok(1))
        ));
        assert_eq!(word(&m, 0x1838), 2);
        assert_eq!(
            v.read(rx, 512).unwrap(),
            [vec![0x55; 510], b"ab".to_vec()].concat()
        );
        assert!(matches!(
            start_batch(&d, tx, 0, &mut m),
            IoAttempt::Complete(Ok(0))
        ));
        let target: Arc<dyn IoWake> = Arc::new(Target);
        assert!(matches!(
            d.start(
                269,
                [tx as u64, 0, 0, 0x8000_0000, 0, 0],
                &mut m,
                1,
                &Arc::downgrade(&target),
                None
            )
            .unwrap(),
            IoAttempt::Complete(Err(Errno(22)))
        ));
        m.map(0x3000, 0x10000, Permissions::RW).unwrap();
        batch_headers(&mut m, 1024);
        v.local_socket(rx)
            .unwrap()
            .unwrap()
            .set_reuse(8, 8192)
            .unwrap();
        assert!(matches!(
            start_batch(&d, tx, 1025, &mut m),
            IoAttempt::Complete(Ok(1024))
        ));
        assert_eq!(v.read(rx, 4096).unwrap(), b"abcd".repeat(1024));
    }
}

#[cfg(test)]
mod signal_interleaving_tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    struct Shut(trames_vfs::LocalOperation);
    impl IoWake for Shut {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.shutdown(0).unwrap();
        }
    }
    #[derive(Default)]
    struct Signals(std::sync::atomic::AtomicUsize);
    impl trames_vfs::TaskSignal for Signals {
        fn raise(&self, n: u32) {
            assert_eq!(n, 13);
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    #[test]
    fn closed_unix_transports_match_linux_sigpipe_for_scalar_vector_message_and_batch() {
        for kind in [1, 2, 5] {
            for number in [64, 66, 206, 211, 269] {
                for no_signal in [false, true] {
                    if no_signal && matches!(number, 64 | 66) {
                        continue;
                    }
                    let mut v = trames_vfs::Vfs::default();
                    let [tx, rx] = v.socketpair(1, kind, 0).unwrap();
                    v.local_socket(rx).unwrap().unwrap().shutdown(0).unwrap();
                    let raised = Arc::new(Signals::default());
                    let direct = DirectSyscalls::new(v.direct_descriptors())
                        .with_resources(v.descriptor_factory())
                        .with_task_signal(raised.clone());
                    let mut m = Memory::default();
                    m.map(0x1000, 4096, Permissions::RW).unwrap();
                    m.write(0x1100, b"x").unwrap();
                    m.write_array(0x1200, 0x1100u64.to_le_bytes()).unwrap();
                    m.write_array(0x1208, 1u64.to_le_bytes()).unwrap();
                    m.write_array(0x1310, 0x1200u64.to_le_bytes()).unwrap();
                    m.write_array(0x1318, 1u64.to_le_bytes()).unwrap();
                    let flags = if no_signal { 0x4000 } else { 0 };
                    let args = match number {
                        64 => [tx as u64, 0x1100, 1, 0, 0, 0],
                        66 => [tx as u64, 0x1200, 1, 0, 0, 0],
                        206 => [tx as u64, 0x1100, 1, flags, 0, 0],
                        211 => [tx as u64, 0x1300, flags, 0, 0, 0],
                        _ => [tx as u64, 0x1300, 1, flags, 0, 0],
                    };
                    let receiver = v.descriptor_factory().local_operation(rx).unwrap().unwrap();
                    let wake: Arc<dyn IoWake> = Arc::new(Shut(receiver));
                    assert!(
                        matches!(
                            direct
                                .start(number, args, &mut m, 1, &Arc::downgrade(&wake), None)
                                .unwrap(),
                            IoAttempt::Complete(Err(Errno(32)))
                        ),
                        "kind={kind} number={number}"
                    );
                    assert_eq!(
                        raised.0.load(std::sync::atomic::Ordering::Relaxed),
                        usize::from(kind == 1 && !no_signal),
                        "kind={kind} number={number}"
                    );
                }
            }
        }
    }
    #[test]
    fn partial_stream_batch_signals_once_after_peer_shutdown_between_messages() {
        let mut v = trames_vfs::Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let receiver = v.descriptor_factory().local_operation(rx).unwrap().unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Shut(receiver));
        let signal = IoSignal::new(1, Arc::downgrade(&wake));
        let _subscription = v.direct_descriptors().get(rx).unwrap().subscribe(&signal);
        let raised = Arc::new(Signals::default());
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_resources(v.descriptor_factory())
            .with_task_signal(raised.clone());
        let mut m = Memory::default();
        m.map(0x1000, 4096, Permissions::RW).unwrap();
        m.write(0x1100, b"x").unwrap();
        m.write_array(0x1200, 0x1100u64.to_le_bytes()).unwrap();
        m.write_array(0x1208, 1u64.to_le_bytes()).unwrap();
        for header in [0x1300, 0x1340] {
            m.write_array(header + 16, 0x1200u64.to_le_bytes()).unwrap();
            m.write_array(header + 24, 1u64.to_le_bytes()).unwrap();
        }
        let target: Arc<dyn IoWake> = wake.clone();
        assert!(matches!(
            direct
                .start(
                    269,
                    [tx as u64, 0x1300, 2, 0, 0, 0],
                    &mut m,
                    1,
                    &Arc::downgrade(&target),
                    None
                )
                .unwrap(),
            IoAttempt::Complete(Ok(1))
        ));
        assert_eq!(raised.0.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(m.read_array::<4>(0x1338).unwrap(), 1u32.to_le_bytes());
        assert_eq!(m.read_array::<4>(0x1378).unwrap(), [0; 4]);
    }
}
