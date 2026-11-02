// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared socket OFDs and live TCP publication; policy captures remain joined.
use super::*;
#[derive(Clone)]
pub struct DirectTcpFd {
    pub tcp: trames_net::DirectTcp,
    pub(super) lease: Option<trames_net::TcpLease>,
    pub flags: u32,
    pub(super) status: StatusFlags,
    pub timeouts: [Option<std::time::Duration>; 2],
}
impl DirectTcpFd {
    pub fn nonblocking(&self) -> bool {
        self.status.get() & O_NONBLOCK != 0
    }
}
/// Weak full-socket control admission. The socket owns the sole control gate;
/// no separate VFS publication lock or Files lock covers a native operation.
#[derive(Clone)]
pub(super) struct SocketControl(std::sync::Weak<NetSocket>);
impl SocketControl {
    pub(super) fn new(socket: &Arc<NetSocket>) -> Self {
        Self(Arc::downgrade(socket))
    }
    fn with_native<T>(&self, operation: impl FnOnce(&trames_net::DirectControl) -> T) -> Option<T> {
        self.0.upgrade()?.with_direct_control(operation)
    }
}
#[derive(Clone, Default)]
pub struct DirectNetwork(Arc<[Option<DirectTcpFd>]>, Option<SharedFiles>);
impl DirectNetwork {
    pub fn with_control<T>(
        &self,
        fd: u32,
        operation: impl FnOnce(&trames_net::DirectControl) -> T,
    ) -> Option<T> {
        self.with_control_refresh(fd, false, operation)
    }
    pub fn with_control_refresh<T>(
        &self,
        fd: u32,
        refresh: bool,
        operation: impl FnOnce(&trames_net::DirectControl) -> T,
    ) -> Option<T> {
        let open = self.1.as_ref()?.socket_control(fd)?;
        let mut publication = refresh.then(|| open.tcp_publication.lock().unwrap());
        open.socket_control.as_ref()?.with_native(|control| {
            let result = operation(control);
            if let Some(publication) = publication.as_mut() {
                **publication = control.direct_tcp().map(|tcp| DirectTcpFd {
                    tcp,
                    lease: None,
                    flags: open.flags.get(),
                    status: open.flags.clone(),
                    timeouts: [false, true].map(|receive| control.io_timeout(receive)),
                });
            }
            result
        })
    }

    pub fn is_socket(&self, fd: u32) -> bool {
        self.1.as_ref().is_some_and(|files| files.is_socket(fd))
    }
    pub fn get(&self, fd: u32) -> Option<DirectTcpFd> {
        self.1.as_ref()?.tcp_lookup(fd)
    }
    pub fn shares_resources(&self, other: &Self) -> bool {
        self.0.iter().flatten().any(|a| {
            other
                .0
                .iter()
                .flatten()
                .any(|b| a.tcp.shares_socket(&b.tcp))
        })
    }
}
/// Reuse TCP capabilities while preparing one stopped execution cohort.
/// Discard before running guests: connect, timeout and policy changes need not
/// change FD membership. Key by actual Files membership: forks can share a
/// content version while owning independently mutable numeric tables. Captures
/// retain that membership allocation, preventing address reuse during the epoch.
#[derive(Default)]
pub struct NetworkEpoch {
    captures: BTreeMap<usize, (Rc<fd_table::DescriptorVersion>, DirectNetwork)>,
}
impl NetworkEpoch {
    pub fn capture(&mut self, vfs: &Vfs) -> DirectNetwork {
        let identity = vfs.fds.identity();
        self.captures
            .entry(vfs.fds.membership().capture_identity().0)
            .or_insert_with(|| (identity, vfs.direct_network()))
            .1
            .clone()
    }
}
impl Vfs {
    /// Inspect only the requested FD when deciding whether byte I/O can run
    /// on a worker. Unrelated sockets do not affect this capability.
    pub fn direct_tcp_fd(&self, fd: u32) -> Option<DirectTcpFd> {
        let descriptor = self.fds.get(&fd)?;
        let result = Self::direct_tcp_open(&descriptor.open.borrow());
        result
    }
    fn direct_tcp_open(open: &OpenDescription) -> Option<DirectTcpFd> {
        Self::direct_tcp_shared(&open.shared)
    }
    pub(super) fn direct_tcp_shared(open: &SharedOpenDescription) -> Option<DirectTcpFd> {
        let socket = open.socket.as_ref()?;
        Some(DirectTcpFd {
            tcp: socket.direct_tcp()?,
            lease: None,
            flags: open.flags.get(),
            status: open.flags.clone(),
            timeouts: [false, true].map(|receive| socket.io_timeout(receive)),
        })
    }
    /// Owner-only control publishes transport authority to existing workers.
    /// Routing/firewall changes still require the original joined boundary.
    pub fn refresh_tcp(&self, fd: u32) {
        if let Some(descriptor) = self.fds.get(&fd) {
            let open = descriptor.open.borrow();
            let mut publication = open.shared.tcp_publication.lock().unwrap();
            *publication = Self::direct_tcp_open(&open);
        }
    }
    /// The original OFD, rather than a possibly reused number, owns publication.
    /// Retain its owner projection only for this synchronous control operation.
    /// This also preserves aliases when the addressed FD is closed.
    pub fn with_socket_control<T>(&mut self, fd: u32, operation: impl FnOnce(&mut Self) -> T) -> T {
        let descriptor = self.fds.get(&fd);
        let result = operation(self);
        if let Some(descriptor) = descriptor {
            let open = descriptor.open.borrow();
            let mut publication = open.shared.tcp_publication.lock().unwrap();
            *publication = Self::direct_tcp_open(&open);
        }
        result
    }
    pub fn direct_network(&self) -> DirectNetwork {
        let mut entries = Vec::new();
        for (&fd, descriptor) in self.fds.entries().iter() {
            let open = descriptor.open.borrow();
            let tcp = {
                let mut publication = open.shared.tcp_publication.lock().unwrap();
                let tcp = Self::direct_tcp_open(&open);
                *publication = tcp.clone();
                tcp
            };
            let Some(tcp) = tcp else { continue };
            entries.resize_with(fd as usize + 1, || None);
            entries[fd as usize] = Some(tcp);
        }
        DirectNetwork(entries.into(), Some(self.fds.worker_membership()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        net::{Ipv4Addr, TcpListener},
        time::Duration,
    };
    #[test]
    fn control_and_timeout_publication_share_the_existing_admission_transaction() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let original = v.socket_operation(fd).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(matches!(
            original.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let _peer = listener.accept().unwrap().0;
        assert_eq!(original.connect_complete(), Ok(true));
        v.refresh_tcp(fd);
        let open = v.descriptor(fd).unwrap().open.borrow().shared.clone();
        let publication = open.tcp_publication.lock().unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (changed_tx, changed_rx) = std::sync::mpsc::channel();
        let control = original.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            control.with_tcp_publication(|| {
                control.set_io_timeout(true, Some(Duration::from_millis(7)));
                changed_tx.send(()).unwrap();
            });
        });
        started_rx.recv().unwrap();
        assert_eq!(
            changed_rx.recv_timeout(Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        );
        assert_eq!(
            original.io_timeout(true),
            None,
            "mutation must wait too, not just its cache write"
        );
        // Holding this object's publication never holds the Files table.
        let other = v.eventfd(0, 0).unwrap();
        drop(publication);
        changed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        worker.join().unwrap();
        assert_eq!(
            open.tcp_publication
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .timeouts[1],
            Some(Duration::from_millis(7))
        );
        v.close(other).unwrap();
        v.close(fd).unwrap();
    }
    #[test]
    fn promoted_tcp_interest_preserves_oneshot_aliases_and_worker_control() {
        use std::io::Write;
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let ep = v.epoll_create(0).unwrap();
        v.epoll_ctl(ep, 1, fd, 0xc0000004, 7).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        drop(socket);
        // Consume ONESHOT through the original owner interest after connect,
        // then prove the subsequent capture cannot silently rearm its state.
        assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), vec![(4, 7)]);
        v.direct_network();
        let direct = v.direct_descriptors();
        assert!(direct.get(ep).unwrap().epoll_wait(1).unwrap().is_empty());
        assert_eq!(
            direct.epoll_control(ep, 3, fd, 0xc0000001, 99),
            Some(Ok(()))
        );
        peer.write_all(b"x").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while direct.get(fd).unwrap().poll_ready(1) == Some(0) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        let count = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let (direct, count) = (&direct, &count);
                scope.spawn(move || {
                    let events = direct.get(ep).unwrap().epoll_wait(1).unwrap();
                    if !events.is_empty() {
                        assert_eq!(events, vec![(1, 99)]);
                    }
                    count.fetch_add(events.len(), Ordering::Relaxed);
                });
            }
        });
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert_eq!(direct.epoll_control(ep, 3, fd, 1, 123), Some(Ok(())));
        assert_eq!(v.close_quiescent_tcp(fd), Some(Ok(())));
        assert_eq!(v.eventfd(1, 0).unwrap(), fd);
        assert_eq!(
            direct.get(ep).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 123)]
        );
        assert_eq!(v.read(alias, 1).unwrap(), b"x");
        assert_eq!(v.close_quiescent_tcp(alias), Some(Ok(())));
        assert!(direct.get(ep).unwrap().epoll_wait(1).unwrap().is_empty());
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn worker_completion_publishes_original_tcp_to_live_aliases_with_timeouts() {
        use std::io::Read;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let network = v.direct_network(); // capture before creation
        let fd = v.socket(2, 1 | O_NONBLOCK, 0).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        socket.set_io_timeout(true, Some(Duration::from_millis(123)));
        let result = v.with_socket_control(fd, |v| {
            v.socket_fd(fd)
                .unwrap()
                .connect(listener.local_addr().unwrap())
        });
        assert!(matches!(result, Ok(()) | Err(trames_net::NetError(115))));
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let worker = network.clone();
        std::thread::spawn(move || {
            assert_eq!(
                worker.with_control_refresh(alias, true, |control| control.get_option(1, 4)),
                Some(Ok(0))
            );
            let tcp = worker
                .get(alias)
                .expect("completion publishes without owner refresh");
            assert_eq!(tcp.timeouts[1], Some(Duration::from_millis(123)));
            assert!(tcp.nonblocking());
            tcp.tcp.send(b"x", 0).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        let mut byte = [0];
        peer.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
        assert!(network.get(fd).is_some());
    }
    #[test]
    fn connected_close_is_atomic_with_accepted_leases_and_preserves_aliases() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        drop(socket);
        let network = v.direct_network();
        let alias = v.dup(fd, 0, false).unwrap();
        let accepted = network.get(fd).unwrap();
        assert_eq!(v.close_quiescent_tcp(fd), None);
        assert!(v.socket_fd(fd).is_ok());
        drop(accepted);
        assert_eq!(v.close_quiescent_tcp(fd), Some(Ok(())));
        assert!(network.get(fd).is_none());
        assert_eq!(
            network.with_control(alias, |c| c.get_option(6, 1)),
            Some(Ok(0))
        );
        assert_eq!(v.close_quiescent_tcp(alias), Some(Ok(())));
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        assert_eq!(v.socket(2, 1, 0).unwrap(), fd);
    }

    #[test]
    fn control_publication_preserves_aliases_after_close_and_fd_reuse() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let network = v.direct_network();
        let fd = v.socket(2, 1, 0).unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        assert_eq!(
            network.with_control(fd, |c| c.set_option_bytes(6, 1, &1i32.to_le_bytes())),
            Some(Ok(()))
        );
        assert_eq!(v.with_socket_control(fd, |v| v.close(fd)), Ok(()));
        let event = v.eventfd(0, 0).unwrap();
        assert_eq!(event, fd);
        assert!(network
            .with_control(event, |c| c.get_option(6, 1))
            .is_none());
        assert_eq!(
            network.with_control(alias, |c| c.get_option(6, 1)),
            Some(Ok(1))
        );
        let weak = network.with_control(alias, Clone::clone).unwrap();
        assert_eq!(v.with_socket_control(alias, |v| v.close(alias)), Ok(()));
        assert_eq!(v.live_sockets(), 0);
        assert_eq!(weak.get_option(6, 1), Err(trames_net::NetError(9)));
    }
    #[test]
    fn object_transition_waits_for_controls_without_holding_files_or_other_sockets() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let other = v.socket(2, 1, 0).unwrap();
        let network = v.direct_network();
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let active = network.clone();
        let worker = std::thread::spawn(move || {
            active.with_control(fd, |c| {
                entered.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(3)).unwrap();
                c.get_option(6, 1)
            })
        });
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        let factory = v.descriptor_factory();
        let concurrent = network.clone();
        let helper = std::thread::spawn(move || {
            let event = factory.eventfd(0, 0).unwrap();
            assert_eq!(
                concurrent.with_control(other, |c| c.set_option_bytes(6, 1, &1i32.to_le_bytes())),
                Some(Ok(()))
            );
            release.send(()).unwrap();
            event
        });
        // Owner mutation takes this socket's writer side only. The helper can
        // allocate through Files and control another socket while it waits.
        assert_eq!(
            v.with_socket_control(fd, |v| v.socket_fd(fd).unwrap().set_option(6, 1, 1)),
            Ok(())
        );
        assert_eq!(worker.join().unwrap(), Some(Ok(0)));
        let event = helper.join().unwrap();
        v.close(event).unwrap();
        assert_eq!(
            network.with_control(fd, |c| c.get_option(6, 1)),
            Some(Ok(1))
        );
        let mut virtual_vfs = Vfs::default();
        virtual_vfs
            .configure_local_fabric(NetworkMode::Full)
            .unwrap();
        let fd = virtual_vfs.socket(2, 1, 0).unwrap();
        assert!(virtual_vfs
            .direct_network()
            .with_control(fd, |c| c.get_option(6, 1))
            .is_none());
    }

    #[test]
    fn equal_fork_versions_bind_each_capture_to_its_actual_files_membership() {
        let mut parent = Vfs::default();
        parent.configure_network(NetworkMode::Loopback).unwrap();
        let mut child = parent.clone();
        assert!(Rc::ptr_eq(&parent.fds.identity(), &child.fds.identity()));
        let mut epoch = NetworkEpoch::default();
        let a = epoch.capture(&parent);
        let b = epoch.capture(&child);
        let tcp = parent.socket(2, 1, 0).unwrap();
        assert!(a.is_socket(tcp));
        assert!(!b.is_socket(tcp));
        let event = child.eventfd(0, 0).unwrap();
        assert_eq!(event, tcp);
        assert!(!b.is_socket(event));
        assert!(a.is_socket(tcp));
        let child_tcp = child.socket(2, 1, 0).unwrap();
        assert!(b.is_socket(child_tcp));
        assert!(!a.is_socket(child_tcp));
        parent.close(tcp).unwrap();
        assert!(!a.is_socket(tcp));
        assert!(b.is_socket(child_tcp));
    }
    #[test]
    fn existing_empty_capture_observes_new_connections_and_actual_close_reuse() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let capture = v.direct_network();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        v.refresh_tcp(fd);
        let accepted = capture.get(fd).unwrap();
        assert_eq!(
            std::thread::spawn(move || {
                let result = accepted.tcp.send(b"live", 0);
                drop(accepted);
                result
            })
            .join()
            .unwrap(),
            Ok(4)
        );
        let mut bytes = [0; 4];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"live");
        let retained = capture.get(fd).unwrap();
        drop(socket);
        v.close(fd).unwrap();
        assert_eq!(v.socket(2, 2, 0).unwrap(), fd);
        assert!(capture.get(fd).is_none());
        assert_eq!(retained.tcp.send(b"held", 0), Ok(4));
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"held");
        drop(retained);
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut bytes).unwrap(), 0);
    }
    #[test]
    fn accept_copyout_reserves_slot_without_locking_or_partial_publication() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        socket.listen(2).unwrap();
        let capture = v.direct_network();
        let factory = v.descriptor_factory();
        let mut client = std::net::TcpStream::connect(socket.local_addr().unwrap()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let failed = loop {
            let factory = factory.clone();
            let result = v.accept_output(fd, 0, |_| {
                let other = std::thread::spawn(move || factory.eventfd(0, 0).unwrap())
                    .join()
                    .unwrap();
                assert_eq!(other, fd + 2);
                Err(Errno(14))
            });
            if result != Err(Errno(11)) {
                break result;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        };
        assert_eq!(failed, Err(Errno(14)));
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(client.read(&mut [0]).unwrap(), 0);
        let _client = std::net::TcpStream::connect(socket.local_addr().unwrap()).unwrap();
        let (new, _) = loop {
            match v.accept(fd, O_CLOEXEC | O_NONBLOCK) {
                Ok(result) => break result,
                Err(Errno(11)) => {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::yield_now();
                }
                other => panic!("{other:?}"),
            }
        };
        assert_eq!(new, fd + 1);
        assert!(capture.get(new).unwrap().nonblocking());
        assert!(v.descriptor(new).unwrap().cloexec.get());
    }

    #[test]
    fn tcp_capabilities_refresh_without_fd_mutation_and_do_not_delay_last_close() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        let flags = v.fd_flags_snapshot().get(fd).unwrap();
        assert!(v.direct_network().get(fd).is_none());
        let mut before_connect = NetworkEpoch::default();
        assert!(before_connect.capture(&v).get(fd).is_none());
        drop(before_connect);
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        assert_eq!(v.fd_flags_snapshot().get(fd).unwrap(), flags);
        // Connection completion has not changed FD membership. A new cohort
        // must still discover it, then share that one capture across threads.
        let shared = v.clone_with_resources(true, true);
        let mut epoch = NetworkEpoch::default();
        let capability = epoch.capture(&v);
        let sibling = epoch.capture(&shared);
        assert!(Arc::ptr_eq(&capability.0, &sibling.0));
        assert!(capability.get(fd).is_some());
        assert!(v.direct_tcp_fd(fd).is_some());
        assert!(v.direct_tcp_fd(u32::MAX).is_none());
        drop(epoch);
        drop(shared);
        let weak_tcp = capability.get(fd).unwrap().tcp.clone();
        drop(socket);
        v.close(fd).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(weak_tcp.send(b"closed", 0), Err(trames_net::NetError(9)));
        assert!(capability.get(fd).is_none());
        assert!(v.direct_network().get(fd).is_none());
        assert!(NetworkEpoch::default().capture(&v).get(fd).is_none());
    }
    #[test]
    fn accepted_tcp_lease_survives_alias_close_and_fd_reuse_until_worker_release() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        drop(socket);
        let cap = v.direct_network().get(fd).unwrap().tcp.clone();
        let lease = v.retain_uring_fd(fd).unwrap().tcp_lease().unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let mut child = v.clone();
        v.close(fd).unwrap();
        v.close(alias).unwrap();
        child.close_all();
        let replacement = v.socket(2, 2, 0).unwrap();
        assert_eq!(replacement, fd);
        assert!(v
            .retain_uring_fd(replacement)
            .unwrap()
            .tcp_lease()
            .is_none());
        assert_eq!(cap.send(b"original", 0), Ok(8));
        let mut bytes = [0; 8];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"original");
        drop((v, child));
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        std::thread::spawn(move || drop(lease)).join().unwrap();
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(cap.recv(1, 0), Err(trames_net::NetError(9)));
    }
}
