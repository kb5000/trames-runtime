// SPDX-License-Identifier: GPL-3.0-or-later
//! Real Files publication for shared anonymous resources and network sockets.
use super::*;

#[derive(Clone)]
pub struct DescriptorFactory {
    pub(super) files: SharedFiles,
    ids: Arc<AtomicU64>,
    owner: (u32, u32),
    network: trames_net::Network,
    local_network: Arc<linux_namespace::RootNetwork>,
    credentials: Credentials,
    local_identity: [u32; 3],
    pid_namespace: PidNamespace,
    devices: Arc<cgroup::DeviceAccess>,
}
pub(super) fn next_id(ids: &AtomicU64) -> u64 {
    (1u64 << 62) | ids.fetch_add(1, Ordering::Relaxed)
}
impl Vfs {
    pub fn descriptor_factory(&self) -> DescriptorFactory {
        DescriptorFactory {
            files: self.shared_files(),
            ids: self.next_open.clone(),
            owner: (self.credentials.fsuid, self.credentials.fsgid),
            network: self.network.clone(),
            local_network: self.root_network.clone(),
            credentials: self.credentials.clone(),
            local_identity: self.local_sender_credentials(),
            pid_namespace: self.pid_namespace().clone(),
            devices: self.device_access(),
        }
    }
}
impl DescriptorFactory {
    fn local_parameters(kind: u32, protocol: u32) -> Result<()> {
        if kind & !(0xf | O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        if !matches!(kind & 0xf, 1 | 2 | 5) {
            return Err(Errno(94));
        }
        if protocol != 0 {
            return Err(Errno(93));
        }
        Ok(())
    }
    fn new_local(&self, kind: u32) -> Result<Arc<ipc::LocalResource>> {
        ipc::LocalResource::allocate(
            kind,
            [
                self.local_identity[0],
                self.credentials.euid,
                self.credentials.egid,
            ],
            self.local_network.clone(),
        )
    }
    pub fn local_create(&self, kind: u32, protocol: u32) -> Result<u32> {
        Self::local_parameters(kind, protocol)?;
        let reserved = self.files.reserve()?;
        let core = self.new_local(kind & 0xf)?;
        let descriptor = Vfs::local_description(self.open_id(), self.owner, core, kind);
        Ok(reserved.publish(descriptor, None))
    }
    pub fn local_pair_with_output(
        &self,
        family: u32,
        kind: u32,
        protocol: u32,
        output: impl FnOnce([u32; 2]) -> Result<()>,
    ) -> Result<[u32; 2]> {
        if family != 1 {
            return Err(Errno(97));
        }
        Self::local_parameters(kind, protocol)?;
        let reserved = self.files.reserve_pair()?;
        let a = self.new_local(kind & 0xf)?;
        let b = self.new_local(kind & 0xf)?;
        ipc::LocalResource::pair(&a, &b);
        let descriptors =
            [a, b].map(|socket| Vfs::local_description(self.open_id(), self.owner, socket, kind));
        let fds = reserved.numbers();
        output(fds)?;
        Ok(reserved.publish(descriptors))
    }
    /// TIOCGPTPEER accepts the original full master OFD; no pathname relookup.
    pub fn open_pty_peer(&self, end: &PtyEnd, flags: u32) -> Result<u32> {
        if !end.master {
            return Err(Errno(25));
        }
        if flags & !(3 | 0x100 | O_NONBLOCK | O_CLOEXEC) != 0 || flags & 3 != 2 {
            return Err(Errno(22));
        }
        if end.pair.locked.load(Ordering::Relaxed) {
            return Err(Errno(5));
        }
        let reservation = self.files.reserve()?;
        {
            let node = end.pair.slave.borrow();
            if !self.credentials.allows_node(&node, 6) {
                return Err(Errno(13));
            }
            let Content::Device(device) = node.content else {
                unreachable!("PTY slave device");
            };
            self.devices.check(node.mode, device.rdev(), 6)?;
        }
        let descriptor = pty::peer_descriptor(end, flags, self.open_id(), self.owner);
        Ok(reservation.publish(descriptor, None))
    }
    /// Signals belong to the reading task, while the mask belongs to this OFD.
    /// None defers an owner-only type before any mask or membership effects.
    pub fn signalfd(&self, fd: i32, mask: u64, flags: u32) -> Option<Result<u32>> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Some(Err(Errno(22)));
        }
        if fd == -1 {
            return Some((|| {
                let reserved = self.files.reserve()?;
                let descriptor = events::anonymous_descriptor(
                    self.open_id(),
                    flags,
                    events::Anonymous::Signal(Arc::new(events::SignalMask::new(mask))),
                );
                Ok(reserved.publish(descriptor, None))
            })());
        }
        Some(self.files.lookup(fd as u32)?.and_then(|file| {
            let Some(events::SharedControl::Signal(current)) = &file.open.control else {
                return Err(Errno(22));
            };
            current.set(mask);
            Ok(fd as u32)
        }))
    }
    pub fn with_local_identity(mut self, identity: [u32; 3]) -> Self {
        self.local_identity = identity;
        self
    }
    pub fn local_sender_credentials(&self) -> [u32; 3] {
        self.local_identity
    }
    pub fn local_credentials(&self) -> &Credentials {
        &self.credentials
    }
    pub fn local_pid(&self, global: u32) -> u32 {
        self.pid_namespace.local(global)
    }
    pub fn local_global_pid(&self, local: u32) -> Result<u32> {
        self.pid_namespace.global(local).ok_or(Errno(3))
    }
    pub(super) fn open_id(&self) -> u64 {
        next_id(&self.ids)
    }
    /// IP and Unix creation retain their actual namespace and credentials.
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<u32> {
        if family == 1 {
            return self.local_create(kind, protocol);
        }
        if matches!((family, kind & 0xf, protocol), (2, 2, 1) | (10, 2, 58)) {
            let [low, high] = self.network.ping_range();
            if !std::iter::once(self.credentials.egid)
                .chain(self.credentials.groups.iter().copied())
                .any(|gid| (low..=high).contains(&gid))
            {
                return Err(Errno(13));
            }
        }
        if matches!(family, 2 | 10)
            && kind & 0xf == 3
            && !self.credentials.has_cap(capabilities::NET_RAW)
        {
            return Err(Errno(1));
        }
        if kind & !(O_CLOEXEC | O_NONBLOCK | 0xf) != 0 {
            return Err(Errno(22));
        }
        let reserved = self.files.reserve()?;
        let socket = self
            .network
            .socket(family, kind & 0xf, protocol)
            .map_err(|e| Errno(e.0))?;
        let descriptor = Vfs::socket_descriptor(self.open_id(), self.owner, socket, kind);
        Ok(reserved.publish(descriptor, None))
    }
    /// None leaves an excluded owner object untouched; missing/invalid shared
    /// entries preserve the ordinary EBADF/ENOTSOCK result.
    pub fn socket_operation(&self, fd: u32) -> Option<Result<SocketOperation>> {
        match self.socket_control_operation(fd)? {
            Ok(SocketControlOperation::Network(socket)) => Some(Ok(socket)),
            Ok(SocketControlOperation::Unix(_)) => None,
            Err(error) => Some(Err(error)),
        }
    }
    /// Accept once before deciding the transport; close/reuse cannot change it
    /// between Unix admission and network admission.
    pub fn socket_control_operation(&self, fd: u32) -> Option<Result<SocketControlOperation>> {
        Some(self.files.lookup(fd)?.and_then(|file| {
            if file.open.local.is_some() {
                LocalOperation::from_shared(file).map(SocketControlOperation::Unix)
            } else {
                SocketOperation::from_shared(file).map(SocketControlOperation::Network)
            }
        }))
    }
    pub fn can_bind_service(&self) -> bool {
        self.credentials.has_cap(capabilities::NET_BIND_SERVICE)
    }
    pub fn accept_socket_output(
        &self,
        socket: &NetSocket,
        flags: u32,
        output: impl FnOnce(std::net::SocketAddr) -> Result<()>,
    ) -> Result<(u32, std::net::SocketAddr)> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        let reserved = self.files.reserve()?;
        let (socket, address) = socket.accept().map_err(|e| Errno(e.0))?;
        output(address)?;
        let descriptor = Vfs::socket_descriptor(self.open_id(), self.owner, socket, flags);
        {
            // Prepare the accepted original OFD before its number is visible.
            // A concurrent close/reuse must not redirect this publication.
            let open = descriptor.open.borrow();
            *open.tcp_publication.lock().unwrap() = Vfs::direct_tcp_shared(&open.shared);
        }
        let fd = reserved.publish(descriptor, None);
        Ok((fd, address))
    }
    fn anonymous(&self, flags: u32, resource: events::Anonymous) -> Result<u32> {
        let reservation = self.files.reserve()?;
        let descriptor = events::anonymous_descriptor(self.open_id(), flags, resource);
        Ok(reservation.publish(descriptor, None))
    }
    pub fn eventfd(&self, initial: u32, flags: u32) -> Result<u32> {
        if flags & !(O_CLOEXEC | O_NONBLOCK | 1) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(
            flags,
            events::Anonymous::Event(Arc::new(direct_io::EventCounter::new(
                initial as u64,
                flags & 1 != 0,
            ))),
        )
    }
    pub fn timerfd(&self, clock: u32, flags: u32) -> Result<u32> {
        if !matches!(clock, 0 | 1 | 7) || flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(flags, events::Anonymous::Timer(TimerFd::new(clock)))
    }
    pub fn inotify_init(&self, flags: u32) -> Result<u32> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(flags, events::Anonymous::Inotify(Arc::default()))
    }
    pub fn pipe(&self, flags: u32) -> Result<[u32; 2]> {
        self.pipe_with_output(flags, |_| Ok(()))
    }
    /// Output runs before either descriptor becomes visible, with no Files lock.
    /// Failure/panic releases both reservations and the original pipe ends.
    pub fn pipe_with_output(
        &self,
        flags: u32,
        output: impl FnOnce([u32; 2]) -> Result<()>,
    ) -> Result<[u32; 2]> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno(22));
        }
        let reservation = self.files.reserve_pair()?;
        let p = Pipe::new(self.open_id());
        let inode = p.inode;
        let metadata = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            device: 6,
            content: Content::Null,
            mode: 0o10600,
            uid: self.owner.0,
            gid: self.owner.1,
            volatile: false,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        let read = PipeEnd::new(p.clone(), true, false, Some(metadata.clone()));
        let write = PipeEnd::new(p, false, true, Some(metadata));

        let descriptions = [(read, FdKind::PipeRead, 0), (write, FdKind::PipeWrite, 1)].map(
            |(end, kind, access)| Descriptor {
                open: OpenHandle::new(OpenDescription {
                    shared: Arc::new(SharedOpenDescription {
                        socket: None,
                        _disk_file: None,
                        #[cfg(all(feature = "hostfs", unix))]
                        host_file: None,
                        native_image: None,
                        mount_resource: std::sync::OnceLock::new(),
                        directory_mount: Default::default(),
                        namespace_resource: None,
                        file_authority: Default::default(),
                        tcp_publication: Default::default(),
                        socket_control: None,
                        control: None,
                        read_node: None,
                        id: self.open_id(),
                        owner: self.owner,
                        kind,
                        flags: ((flags & O_NONBLOCK) | access).into(),
                        file_position: Arc::default(),
                        flock: std::sync::OnceLock::new(),
                        ofd_records: Default::default(),
                        node: None,
                        pipe: Some(end),
                        pty: None,
                        local: None,
                        bridge: None,
                        kernel_log: None,
                        notification: None,
                    }),
                    position: 0,
                    anonymous: None,
                    namespace: None,
                    network_control: None,
                    mount_file: None,
                    oom: None,
                    mount: None,
                }),
                cloexec: (flags & O_CLOEXEC != 0).into(),
            },
        );
        output(reservation.numbers())?;
        Ok(reservation.publish(descriptions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_socket_creation_publishes_complete_ofds_and_keeps_creating_authority() {
        let mut owner = Vfs::default();
        owner.configure_network(NetworkMode::Loopback).unwrap();
        owner.credentials = Credentials::user(1000, 1000);
        owner.network.set_ping_range([0, 0]);
        let original = owner.network.clone();
        let factory = owner.descriptor_factory();
        let files = owner.shared_files();
        let network = owner.direct_network();
        // Authority changes checkpoint workers; a retained capture still owns
        // the exact creating namespace/credentials rather than looking up Vfs.
        owner.credentials = Credentials::user(0, 0);
        owner.unshare_net().unwrap();
        let fds = std::thread::spawn(move || {
            assert_eq!(factory.socket(2, 2, 1), Err(Errno(13)));
            assert_eq!(factory.socket(2, 3, 1), Err(Errno(1)));
            [
                factory.socket(2, 1 | O_NONBLOCK | O_CLOEXEC, 0).unwrap(),
                factory.socket(16, 3 | O_CLOEXEC, 0).unwrap(),
            ]
        })
        .join()
        .unwrap();
        assert_eq!(original.live_sockets(), 2);
        let socket = owner.socket_fd(fds[0]).unwrap();
        assert_eq!(socket.info().unwrap().namespace_id, original.namespace_id());
        assert_ne!(
            socket.info().unwrap().namespace_id,
            owner.network.namespace_id()
        );
        let weak = Arc::downgrade(&socket);
        drop(socket);
        for fd in fds {
            assert!(network.is_socket(fd));
            assert!(files.lookup(fd).unwrap().is_ok());
            assert!(owner.fds.lookup(fd).unwrap().cloexec.get());
        }
        std::thread::spawn(move || {
            for fd in fds {
                files.close(fd, 1).unwrap().unwrap();
            }
        })
        .join()
        .unwrap();
        assert!(weak.upgrade().is_none());
        assert_eq!(original.live_sockets(), 0);
        assert!(!network.is_socket(fds[0]));
    }
    #[test]
    fn factories_are_send_sync_and_publish_real_resources_into_existing_views() {
        fn shared<T: Send + Sync>() {}
        shared::<DescriptorFactory>();
        let mut owner = Vfs {
            credentials: Credentials::user(123, 456),
            ..Vfs::default()
        };
        let direct = owner.direct_descriptors();
        let factory = owner.descriptor_factory();
        let resources = std::thread::spawn(move || {
            let pipe = factory.pipe(O_NONBLOCK | O_CLOEXEC).unwrap();
            [
                pipe[0],
                pipe[1],
                factory.eventfd(7, O_NONBLOCK | O_CLOEXEC).unwrap(),
                factory.timerfd(1, O_NONBLOCK | O_CLOEXEC).unwrap(),
                factory.inotify_init(O_NONBLOCK | O_CLOEXEC).unwrap(),
            ]
        })
        .join()
        .unwrap();
        for &fd in &resources {
            assert!(owner.fds.lookup(fd).unwrap().cloexec.get());
            assert!(direct.get(fd).is_some());
        }
        let stat = owner.stat_fd(resources[0]).unwrap();
        assert_eq!(stat[24..28], 123u32.to_le_bytes());
        assert_eq!(stat[28..32], 456u32.to_le_bytes());
        assert!(direct.get(resources[2]).unwrap().is_eventfd());
        assert_eq!(direct.get(resources[3]).unwrap().timer().unwrap().clock, 1);
        assert!(direct.get(resources[4]).unwrap().is_inotify());
        for fd in resources {
            owner.close(fd).unwrap();
        }
    }
    #[test]
    fn pipe_copyout_failure_and_panic_release_both_unpublished_numbers() {
        let mut owner = Vfs::default();
        let factory = owner.descriptor_factory();
        let files = owner.shared_files();
        assert_eq!(
            factory.pipe_with_output(0, |fds| {
                for fd in fds {
                    assert!(matches!(files.lookup(fd), Some(Err(Errno(9)))));
                }
                // The Files lock must not be held over a guest-memory callback.
                let other = factory.eventfd(1, 0).unwrap();
                assert_eq!(other, 5);
                files.close(other, 1).unwrap().unwrap();
                Err(Errno(14))
            }),
            Err(Errno(14))
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || factory.pipe_with_output(0, |_| panic!("copyout interrupted"))
        ))
        .is_err());
        assert_eq!(owner.fd_snapshot().len(), 3);
        let pair = factory.pipe(0).unwrap();
        assert_eq!(pair, [3, 4]);
        for fd in pair {
            owner.close(fd).unwrap();
        }
    }
    #[test]
    fn fd_limit_and_flag_errors_have_no_partial_pipe_or_output_effects() {
        let mut owner = Vfs::default();
        owner.set_descriptor_limit(4);
        let factory = owner.descriptor_factory();
        assert_eq!(
            factory.pipe_with_output(0, |_| panic!("EMFILE cannot copy output")),
            Err(Errno(24))
        );
        let event = factory.eventfd(0, 0).unwrap();
        assert_eq!(event, 3);
        owner.close(event).unwrap();
        assert_eq!(
            factory.pipe_with_output(1, |_| panic!("EINVAL cannot copy output")),
            Err(Errno(22))
        );
        assert_eq!(factory.eventfd(0, 2), Err(Errno(22)));
        assert_eq!(factory.timerfd(2, 0), Err(Errno(22)));
        assert_eq!(factory.inotify_init(1), Err(Errno(22)));
        owner.set_descriptor_limit(5);
        let pair = factory.pipe(0).unwrap();
        assert_eq!(pair, [3, 4]);
        for fd in pair {
            owner.close(fd).unwrap();
        }
    }
    #[test]
    fn concurrent_creators_publish_disjoint_live_slots_and_unique_ofd_ids() {
        let mut owner = Vfs::default();
        let factory = owner.descriptor_factory();
        let gate = Arc::new(std::sync::Barrier::new(8));
        let jobs: Vec<_> = (0..8)
            .map(|_| {
                let factory = factory.clone();
                let gate = gate.clone();
                std::thread::spawn(move || {
                    gate.wait();
                    let p = factory.pipe(0).unwrap();
                    [
                        p[0],
                        p[1],
                        factory.eventfd(0, 0).unwrap(),
                        factory.timerfd(1, 0).unwrap(),
                        factory.inotify_init(0).unwrap(),
                    ]
                })
            })
            .collect();
        let fds: Vec<_> = jobs.into_iter().flat_map(|j| j.join().unwrap()).collect();
        assert_eq!(
            fds.iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            40
        );
        let ids: std::collections::BTreeSet<_> = fds
            .iter()
            .map(|&fd| owner.descriptor(fd).unwrap().open.borrow().id)
            .collect();
        assert_eq!(ids.len(), 40);
        for fd in fds {
            owner.close(fd).unwrap();
        }
    }
}
