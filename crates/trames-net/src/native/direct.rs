// SPDX-License-Identifier: GPL-3.0-or-later
//! Established BSD TCP bytes without sharing namespace Rc/RefCell authority.
use super::*;
use std::{
    io::Read,
    sync::{
        atomic::{AtomicU64, Ordering},
        Weak,
    },
};

#[derive(Default)]
struct Link {
    rx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    tx_packets: AtomicU64,
}
#[derive(Default)]
pub(super) struct Links([Link; 2]);
fn add(value: &AtomicU64, n: u64) {
    // Counters do not publish packet or guest bytes. Keep the original
    // saturation rule while allowing independent sockets to account in parallel.
    let _ = value.try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
        Some(v.saturating_add(n))
    });
}
impl Links {
    pub(super) fn snapshot(&self) -> [crate::LinkStats; 2] {
        self.0.each_ref().map(|s| crate::LinkStats {
            rx_bytes: s.rx_bytes.load(Ordering::Relaxed),
            rx_packets: s.rx_packets.load(Ordering::Relaxed),
            tx_bytes: s.tx_bytes.load(Ordering::Relaxed),
            tx_packets: s.tx_packets.load(Ordering::Relaxed),
            ..Default::default()
        })
    }
    pub(super) fn account(&self, ip: Option<IpAddr>, count: usize, transmit: bool) {
        let link = &self.0[usize::from(!ip.is_some_and(loopback))];
        if transmit {
            add(&link.tx_packets, 1);
            add(&link.tx_bytes, count as u64);
        } else {
            add(&link.rx_packets, 1);
            add(&link.rx_bytes, count as u64);
        }
    }
}
pub(super) fn send_flags() -> i32 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        nix::libc::MSG_NOSIGNAL
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        0
    } // Apple socket is configured with SO_NOSIGPIPE at creation.
}
pub(super) fn send_connected(socket: &NativeSocket, bytes: &[u8]) -> Result<usize> {
    socket
        .control()
        .send_with_flags(bytes, send_flags())
        .map_err(from_io)
}
pub(super) fn read_tcp(socket: &TcpStream, data: &mut [u8], flags: u32) -> Result<usize> {
    if flags & MSG_PEEK != 0 {
        socket.peek(data)
    } else {
        let mut socket = socket;
        socket.read(data)
    }
    .map_err(from_io)
}

/// A cohort capability, not a new guest open description. Weak storage leaves
/// the host FD with its actual socket owner; stale snapshots cannot delay FIN.
#[derive(Clone)]
pub struct DirectTcp {
    socket: Weak<Endpoint>,
    links: Arc<Links>,
    peer: SocketAddr,
}
impl Socket {
    pub(crate) fn direct_tcp(&self) -> Option<DirectTcp> {
        if self.kind != 1
            || self.connection.get() != Connection::Connected
            || self.dns_peer.get()
            || !self.dns.borrow().is_empty()
            || self.pending_error.get().is_some()
        {
            return None;
        }
        // Every firewall/route/connection/FD authority change still joins.
        // A live ruleset can depend on packet content and conntrack; never
        // replace that decision with a cached "allow".
        if self
            .policy
            .borrow()
            .as_ref()
            .is_some_and(|ns| ns.graph.borrow().firewall(ns.id()).borrow().has_rules())
        {
            return None;
        }
        Some(DirectTcp {
            socket: Arc::downgrade(&self.native),
            links: self.network.0.links.clone(),
            peer: self.peer_addr().ok()?,
        })
    }
}
impl DirectTcp {
    /// Retain the actual transport for an accepted operation, independently of
    /// namespace/owner projections. Ordinary capability snapshots stay weak.
    pub fn retain(&self) -> Result<TcpLease> {
        self.socket.upgrade().map(TcpLease).ok_or(NetError(9))
    }
    /// The original host edge observer, shared with the serial socket path.
    /// Sampling does not re-register a level-ready descriptor as a new edge.
    pub fn poll_epoch(&self) -> Option<[u64; 2]> {
        self.socket.upgrade()?.poll_epoch()
    }
    /// Scheduling identity only; not an authority or a readiness result.
    pub fn shares_socket(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.socket, &other.socket)
    }
    /// A wait-scoped lease, released before any joined FD/namespace mutation.
    /// Ordinary capability snapshots remain weak and never delay guest FIN.
    pub fn readiness_fd(&self) -> io::Result<(std::os::fd::OwnedFd, TcpLease)> {
        let socket = self
            .socket
            .upgrade()
            .ok_or_else(|| io::Error::from_raw_os_error(9))?;
        let fd = socket.as_fd().try_clone_to_owned()?;
        Ok((fd, TcpLease(socket)))
    }
    pub fn send(&self, bytes: &[u8], flags: u32) -> Result<usize> {
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > MAX_TRANSFER {
            return Err(NetError(90));
        }
        let socket = self.socket.upgrade().ok_or(NetError(9))?;
        let n = send_connected(&socket, bytes)?;
        if n != 0 {
            self.links.account(Some(self.peer.ip()), n, true);
        }
        Ok(n)
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Vec<u8>> {
        if flags & !(MSG_PEEK | MSG_DONTWAIT) != 0 {
            return Err(NetError(95));
        }
        if count > MAX_TRANSFER {
            return Err(NetError(22));
        }
        let socket = self.socket.upgrade().ok_or(NetError(9))?;
        let NativeSocket::Tcp(tcp) = &socket.socket else {
            unreachable!("TCP capability");
        };
        if count == 0 {
            return Ok(Vec::new());
        }
        let mut data = vec![0; count];
        let n = read_tcp(tcp, &mut data, flags)?;
        data.truncate(n);
        if flags & MSG_PEEK == 0 && n != 0 {
            self.links.account(Some(self.peer.ip()), n, false);
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, net::TcpListener};
    fn pair() -> (Network, Rc<Socket>, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let native = RawNativeSocket::from(client);
        configure(&native).unwrap();
        let network = Network::new(NetworkMode::Loopback);
        let socket = network.wrap(
            native,
            network.reserve().unwrap(),
            2,
            1,
            Connection::Connected,
        );
        (network, socket, peer)
    }
    #[test]
    fn connected_tcp_bytes_peek_and_counters_share_the_original_socket() {
        let (network, socket, mut peer) = pair();
        let direct = socket.direct_tcp().unwrap();
        assert_eq!(direct.recv(1, 0), Err(NetError(11)));
        peer.write_all(b"hello").unwrap();
        wait_with_fds(&[(socket.clone(), 1)], &[], Duration::from_secs(2)).unwrap();
        assert_eq!(direct.recv(5, MSG_PEEK).unwrap(), b"hello");
        assert_eq!(network.links()[0].rx_bytes, 0);
        assert_eq!(socket.recv(5, 0).unwrap().data, b"hello");
        assert_eq!(direct.send(b"one", 0), Ok(3));
        assert_eq!(socket.send(b"two", 0, None), Ok(3));
        let mut data = [0; 6];
        peer.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"onetwo");
        let stats = network.links()[0];
        assert_eq!(
            (
                stats.tx_bytes,
                stats.tx_packets,
                stats.rx_bytes,
                stats.rx_packets
            ),
            (6, 2, 5, 1)
        );
        assert_eq!(direct.recv(0, 0), Ok(vec![]));
        assert_eq!(direct.recv(1, MSG_TRUNC), Err(NetError(95)));
        assert_eq!(direct.recv(MAX_TRANSFER + 1, 0), Err(NetError(22)));
        assert_eq!(direct.send(b"x", MSG_PEEK), Err(NetError(95)));
        peer.shutdown(Shutdown::Write).unwrap();
        wait_with_fds(&[(socket.clone(), 1)], &[], Duration::from_secs(2)).unwrap();
        assert_eq!(direct.recv(1, 0), Ok(vec![]));
    }
    #[test]
    fn retained_capabilities_do_not_keep_the_host_connection_open() {
        let (network, socket, mut peer) = pair();
        let direct = socket.direct_tcp().unwrap();
        drop(socket);
        assert_eq!(network.live_sockets(), 0);
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(direct.send(b"closed", 0), Err(NetError(9)));
        assert_eq!(direct.recv(1, 0), Err(NetError(9)));
    }
    #[test]
    fn accepted_transport_keeps_quota_until_final_worker_close() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<TcpLease>();
        let (network, socket, mut peer) = pair();
        let direct = socket.direct_tcp().unwrap();
        let lease = direct.retain().unwrap();
        let alias = lease.clone();
        assert!(lease.shares_socket(&alias));
        drop(socket);
        drop(lease);
        assert_eq!(network.live_sockets(), 1);
        assert_eq!(direct.send(b"original", 0), Ok(8));
        let mut bytes = [0; 8];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"original");
        let remaining: Vec<_> = (1..MAX_SOCKETS)
            .map(|_| network.socket(2, 2, 0).unwrap())
            .collect();
        assert!(matches!(network.socket(2, 2, 0), Err(NetError(24))));
        std::thread::spawn(move || drop(alias)).join().unwrap();
        assert_eq!(network.live_sockets(), MAX_SOCKETS - 1);
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert!(matches!(direct.retain(), Err(NetError(9))));
        assert_eq!(direct.send(b"closed", 0), Err(NetError(9)));
        let replacement = network.socket(2, 2, 0).unwrap();
        assert_eq!(network.live_sockets(), MAX_SOCKETS);
        drop((remaining, replacement));
        assert_eq!(network.live_sockets(), 0);
    }
    #[test]
    fn failed_accept_returns_its_reserved_slot() {
        let network = Network::new(NetworkMode::Loopback);
        let listener = network.socket(2, 1, 0).unwrap();
        listener.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        listener.listen(1).unwrap();
        for _ in 0..MAX_SOCKETS * 2 {
            assert!(matches!(listener.accept(), Err(NetError(11))));
            assert_eq!(network.live_sockets(), 1);
        }
        let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        // Darwin may complete connect before the nonblocking listener's accept
        // queue is readable. Preserve the assertion after its real readiness.
        wait_with_fds(&[(listener.clone(), 1)], &[], Duration::from_secs(2)).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let direct = accepted.direct_tcp().unwrap();
        let lease = direct.retain().unwrap();
        drop(accepted);
        assert_eq!(network.live_sockets(), 2);
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert_eq!(network.live_sockets(), 1);
        drop(listener);
        assert_eq!(network.live_sockets(), 0);
    }
    #[test]
    fn owner_and_workers_share_one_persistent_edge_observer() {
        let (_, socket, mut peer) = pair();
        let direct = socket.direct_tcp().unwrap();
        let before = socket.poll_epoch().unwrap()[0];
        peer.write_all(b"first").unwrap();
        wait_with_fds(&[(socket.clone(), 1)], &[], Duration::from_secs(2)).unwrap();
        let worker = direct.clone();
        let first = std::thread::spawn(move || worker.poll_epoch().unwrap()[0])
            .join()
            .unwrap();
        assert_ne!(first, before);
        assert_eq!(socket.poll_epoch().unwrap()[0], first);
        std::thread::scope(|s| {
            for _ in 0..8 {
                let direct = &direct;
                s.spawn(move || assert_eq!(direct.poll_epoch().unwrap()[0], first));
            }
        });
        assert_eq!(direct.recv(5, 0).unwrap(), b"first");
        peer.write_all(b"second").unwrap();
        wait_with_fds(&[(socket.clone(), 1)], &[], Duration::from_secs(2)).unwrap();
        let second = socket.poll_epoch().unwrap()[0];
        assert_ne!(second, first);
        assert_eq!(direct.poll_epoch().unwrap()[0], second);
        assert_eq!(direct.recv(6, 0).unwrap(), b"second");
        let lease = direct.retain().unwrap();
        drop(socket);
        peer.shutdown(Shutdown::Write).unwrap();
        let mut polls = [PollFd::new(lease.0.as_fd(), PollFlags::POLLIN)];
        poll(
            &mut polls,
            PollTimeout::try_from(Duration::from_secs(2)).unwrap(),
        )
        .unwrap();
        assert_ne!(direct.poll_epoch().unwrap()[0], second);
        assert_eq!(direct.recv(1, 0), Ok(vec![]));
        std::thread::spawn(move || drop(lease)).join().unwrap();
        assert_eq!(direct.poll_epoch(), None);
    }
    #[test]
    fn parallel_tcp_writers_need_no_namespace_or_socket_data_lock() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<DirectTcp>();
        let (network, socket, mut peer) = pair();
        let direct = socket.direct_tcp().unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let direct = &direct;
                scope.spawn(move || assert_eq!(direct.send(&[7; 64], 0), Ok(64)));
            }
        });
        let mut data = [0; 512];
        peer.read_exact(&mut data).unwrap();
        assert_eq!(data, [7; 512]);
        assert_eq!(
            (network.links()[0].tx_packets, network.links()[0].tx_bytes),
            (8, 512)
        );
    }
    #[test]
    fn idle_connecting_dns_udp_and_saturated_stats_keep_their_boundaries() {
        let n = Network::new(NetworkMode::Loopback);
        for kind in [1, 2] {
            assert!(n.socket(2, kind, 0).unwrap().direct_tcp().is_none());
        }
        let (_, socket, _) = pair();
        socket.connection.set(Connection::Connecting);
        assert!(socket.direct_tcp().is_none());
        socket.connection.set(Connection::Connected);
        socket.dns_peer.set(true);
        assert!(socket.direct_tcp().is_none());
        let count = AtomicU64::new(u64::MAX - 1);
        add(&count, 3);
        assert_eq!(count.load(Ordering::Relaxed), u64::MAX);
    }
}
