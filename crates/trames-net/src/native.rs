// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded native sockets. All host operations are nonblocking; guest ABI
//! addresses, flags and errno numbers are translated explicitly.
use crate::direct_dns;
mod control;
mod direct;
mod state;
pub use control::DirectControl;
pub(crate) use control::SavedOptions;
mod endpoint;
use crate::socket_quota::{Quota, Reservation};
use direct::Links;
pub use direct::{DirectTcp, TcpPoll};
use endpoint::Endpoint;
pub use endpoint::TcpLease;
use std::sync::{Arc, Mutex};
#[path = "native_events.rs"]
mod edge;
#[path = "native_pktinfo.rs"]
mod pktinfo;
use std::os::fd::AsRawFd;
#[path = "native_icmp.rs"]
mod icmp;
use nix::{
    errno::Errno as HostErrno,
    poll::{poll, PollFd, PollFlags, PollTimeout},
};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket as RawNativeSocket, TcpKeepalive, Type};
use std::{
    cell::{Cell, RefCell},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpStream, UdpSocket},
    os::fd::{AsFd, BorrowedFd},
    rc::Rc,
    time::{Duration, Instant},
};

pub const MAX_SOCKETS: usize = 64;
pub const MAX_BUFFER: usize = 256 * 1024;
pub const MAX_TRANSFER: usize = 1024 * 1024;
pub const MSG_PEEK: u32 = 2;
pub const MSG_TRUNC: u32 = 0x20;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_NOSIGNAL: u32 = 0x4000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetError(pub u32);
impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "guest network errno {}", self.0)
    }
}
impl std::error::Error for NetError {}
type Result<T> = std::result::Result<T, NetError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NetworkMode {
    #[default]
    Off,
    Loopback,
    Outbound,
    Full,
}
/// The scheduler waits on a bounded, deduplicated set of opaque socket handles.
/// No guest descriptor number is used as a host descriptor.
pub fn wait_with_fds(
    sockets: &[(Rc<Socket>, u16)],
    extra: &[std::os::fd::BorrowedFd<'_>],
    timeout: Duration,
) -> Result<()> {
    let has_dns = sockets.iter().any(|(s, _)| !s.dns.borrow().is_empty());
    let timeout = if has_dns {
        timeout.min(Duration::from_millis(2))
    } else {
        timeout
    };
    let mut unique: Vec<(Rc<Socket>, u16)> = Vec::new();
    for (socket, events) in sockets {
        if socket.dns_peer.get() {
            continue;
        }
        if let Some((_, interest)) = unique.iter_mut().find(|(s, _)| Rc::ptr_eq(s, socket)) {
            *interest |= events;
        } else {
            if unique.len() == 1024 {
                return Err(NetError(22));
            }
            unique.push((socket.clone(), *events));
        }
    }
    let mut fds: Vec<_> = unique
        .iter()
        .map(|(socket, events)| {
            let mut flags = PollFlags::empty();
            if events & 1 != 0 {
                flags |= PollFlags::POLLIN;
            }
            if events & 2 != 0 {
                flags |= PollFlags::POLLPRI;
            }
            if events & 4 != 0 {
                flags |= PollFlags::POLLOUT;
            }
            PollFd::new(socket.native.as_fd(), flags)
        })
        .collect();
    fds.extend(extra.iter().map(|fd| PollFd::new(*fd, PollFlags::POLLIN)));
    let timeout = PollTimeout::try_from(timeout).map_err(|_| NetError(22))?;
    match poll(&mut fds, timeout) {
        Ok(_) | Err(HostErrno::EINTR) => Ok(()),
        Err(error) => Err(from_errno(error)),
    }
}
fn unmapped(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .map_or(a, |v| SocketAddr::new(v.into(), a.port())),
        _ => a,
    }
}
struct Namespace {
    mode: NetworkMode,
    sockets: Arc<Quota>,
    dns: Arc<direct_dns::Service>,
    interfaces: Mutex<Option<(Instant, Option<crate::NetworkInfo>)>>,
    links: Arc<Links>,
}
#[derive(Clone)]
pub struct Network(Arc<Namespace>);
/// Actual transport and creating native namespace, before owner-only socket
/// projections are attached. Creation/cancellation can run on an executor;
/// finishing attaches controls to this same endpoint, without another quota.
struct PreparedSocket {
    native: Arc<Endpoint>,
    network: Network,
    family: u32,
    kind: u32,
}
impl PreparedSocket {
    fn finish(self) -> Rc<Socket> {
        Rc::new(Socket {
            native: self.native,
            network: self.network,
            family: self.family,
            kind: self.kind,
            dns: RefCell::default(),
            dns_target: Cell::new(direct_dns::ADDRESS),
            dns_peer: Cell::new(false),
            dns_receive_errors: Cell::new(false),
            echo: RefCell::default(),
            policy: RefCell::default(),
            receive_packet_info: Cell::new(false),
            policy_forward: RefCell::default(),
        })
    }
}
impl Default for Network {
    fn default() -> Self {
        Self::new(NetworkMode::Off)
    }
}
impl Network {
    pub(super) fn mode(&self) -> NetworkMode {
        self.0.mode
    }
    pub fn new(mode: NetworkMode) -> Self {
        Self(Arc::new(Namespace {
            mode,
            sockets: Arc::default(),
            dns: direct_dns::Service::new(mode),
            interfaces: Mutex::new(None),
            links: Arc::default(),
        }))
    }
    pub fn info(&self) -> Option<crate::NetworkInfo> {
        if matches!(self.0.mode, NetworkMode::Off | NetworkMode::Loopback) {
            return None;
        }
        let mut cached = self.0.interfaces.lock().unwrap();
        if cached
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= Duration::from_secs(1))
        {
            *cached = Some((Instant::now(), crate::interfaces::primary()));
        }
        cached.as_ref().and_then(|(_, info)| *info)
    }
    pub fn links(&self) -> [crate::LinkStats; 2] {
        self.0.links.snapshot()
    }
    fn account(&self, ip: Option<IpAddr>, count: usize, transmit: bool) {
        self.0.links.account(ip, count, transmit);
    }
    #[cfg(test)]
    pub fn live_sockets(&self) -> usize {
        self.0.sockets.live()
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Rc<Socket>> {
        Ok(self.prepare_socket(family, kind, protocol)?.finish())
    }
    fn prepare_socket(&self, family: u32, kind: u32, protocol: u32) -> Result<PreparedSocket> {
        let domain = match family {
            2 => Domain::IPV4,
            10 => Domain::IPV6,
            _ => return Err(NetError(97)),
        };
        let (ty, native_protocol) = match (kind, protocol) {
            (1, 0 | 6) => (Type::STREAM, Protocol::TCP),
            (2, 0 | 17) => (Type::DGRAM, Protocol::UDP),
            (2 | 3, 1) if family == 2 => (Type::DGRAM, Protocol::ICMPV4),
            (2 | 3, 58) if family == 10 => (Type::DGRAM, Protocol::ICMPV6),
            (1 | 2, _) => return Err(NetError(93)),
            _ => return Err(NetError(94)),
        };
        let reservation = self.reserve()?;
        let native = RawNativeSocket::new(domain, ty, Some(native_protocol)).map_err(from_io)?;
        configure(&native)?;
        if kind == 3 {
            icmp::configure(&native, family)?;
        }
        if family == 10 {
            // Linux TCP/UDP default to dual stack, including on Apple hosts
            // whose system default may differ. ICMP sockets stay v6-only.
            native
                .set_only_v6(native_protocol == Protocol::ICMPV6)
                .map_err(from_io)?;
        }
        let kind = if kind == 3 {
            4
        } else if kind == 2 && matches!(protocol, 1 | 58) {
            3
        } else {
            kind
        };
        Ok(PreparedSocket {
            native: Endpoint::new(native, kind, reservation, Connection::Idle),
            network: self.clone(),
            family,
            kind,
        })
    }
    fn reserve(&self) -> Result<Reservation> {
        if self.0.mode == NetworkMode::Off {
            Err(NetError(13))
        } else {
            self.0.sockets.reserve()
        }
    }
    fn wrap(
        &self,
        native: RawNativeSocket,
        reservation: Reservation,
        family: u32,
        kind: u32,
        connection: Connection,
    ) -> Rc<Socket> {
        PreparedSocket {
            native: Endpoint::new(native, kind, reservation, connection),
            network: self.clone(),
            family,
            kind,
        }
        .finish()
    }
    fn destination(&self, address: SocketAddr) -> Result<()> {
        let ip = address.ip();
        if self.0.mode == NetworkMode::Off
            || self.0.mode == NetworkMode::Loopback && !loopback(ip)
            || ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, IpAddr::V4(v) if v.is_broadcast())
        {
            Err(NetError(13))
        } else {
            Ok(())
        }
    }
    fn binding(&self, address: SocketAddr, kind: u32) -> Result<()> {
        if self.0.mode != NetworkMode::Full && address.port() != 0 && address.port() < 1024 {
            return Err(NetError(13));
        }
        if self.0.mode == NetworkMode::Full || loopback(address.ip()) {
            return Ok(());
        }
        // DNS clients commonly explicitly bind INADDR_ANY:0. This allows an
        // ephemeral UDP endpoint, not a guest-selected public service port.
        if self.0.mode == NetworkMode::Outbound
            && matches!(kind, 2 | 3)
            && address.ip().is_unspecified()
            && address.port() == 0
        {
            Ok(())
        } else {
            Err(NetError(13))
        }
    }
}
fn loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
        || matches!(ip, IpAddr::V6(v) if v.to_ipv4_mapped().is_some_and(|v| v.is_loopback()))
}
fn configure(socket: &RawNativeSocket) -> Result<()> {
    socket.set_nonblocking(true).map_err(from_io)?;
    socket.set_recv_buffer_size(64 * 1024).map_err(from_io)?;
    socket.set_send_buffer_size(64 * 1024).map_err(from_io)?;
    // Never let a guest socket deliver SIGPIPE to the host application.
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    socket.set_nosigpipe(true).map_err(from_io)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Connection {
    Idle,
    Connecting,
    Connected,
    Listening,
    Failed(u32),
}
enum NativeSocket {
    Tcp(TcpStream),
    Udp(UdpSocket),
}
impl NativeSocket {
    fn control(&self) -> SockRef<'_> {
        match self {
            Self::Tcp(socket) => SockRef::from(socket),
            Self::Udp(socket) => SockRef::from(socket),
        }
    }
}
impl AsFd for NativeSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(socket) => socket.as_fd(),
            Self::Udp(socket) => socket.as_fd(),
        }
    }
}
pub struct Socket {
    native: Arc<Endpoint>,
    network: Network,
    family: u32,
    kind: u32,
    dns: RefCell<std::collections::BTreeMap<SocketAddr, Arc<direct_dns::Endpoint>>>,
    dns_target: Cell<SocketAddr>,
    dns_peer: Cell<bool>,
    dns_receive_errors: Cell<bool>,
    echo: RefCell<icmp::Echo>,
    receive_packet_info: Cell<bool>,
    policy: RefCell<Option<Rc<crate::netlink::Namespace>>>,
    policy_forward: RefCell<
        std::collections::BTreeMap<
            (SocketAddr, SocketAddr),
            (crate::netdev::NativeForward, Instant),
        >,
    >,
}
pub struct Received {
    /// Non-IP source identity, retained with the individual netlink datagram.
    pub(crate) netlink_address: Option<[u8; 12]>,
    pub packet_info: Option<crate::PacketInfo>,
    pub data: Vec<u8>,
    pub address: Option<SocketAddr>,
    pub length: usize,
    pub truncated: bool,
}
impl Socket {
    pub fn poll_epoch(&self) -> Option<[u64; 2]> {
        let mut epoch = self.native.poll_epoch()?;
        for dns in self.dns.borrow().values() {
            epoch[0] = epoch[0].wrapping_add(dns.epoch());
        }
        Some(epoch)
    }
    pub(crate) fn attach_policy(&self, namespace: Rc<crate::netlink::Namespace>) {
        *self.policy.borrow_mut() = Some(namespace);
    }
    fn policy_check(&self, input: bool, peer: SocketAddr, bytes: &[u8], flags: u8) -> Result<()> {
        self.policy_check_source(input, peer, bytes, flags, None)
    }
    fn policy_check_source(
        &self,
        input: bool,
        peer: SocketAddr,
        bytes: &[u8],
        flags: u8,
        source: Option<IpAddr>,
    ) -> Result<()> {
        if self.dns_receive_errors.get() && !direct_dns::system_address(peer) {
            return Err(NetError(92));
        }

        let policy = self.policy.borrow();
        let Some(namespace) = policy.as_ref() else {
            return Ok(());
        };
        if !namespace
            .graph
            .read()
            .unwrap()
            .firewall(namespace.id())
            .read()
            .unwrap()
            .has_rules()
        {
            return Ok(());
        }
        namespace.refresh_native();
        let mut local = self.local_addr()?;
        let peer = unmapped(peer);
        if local.port() == 0 && matches!(self.kind, 1 | 2) {
            self.native
                .control()
                .bind(
                    &SocketAddr::new(
                        if self.family == 2 {
                            Ipv4Addr::UNSPECIFIED.into()
                        } else {
                            Ipv6Addr::UNSPECIFIED.into()
                        },
                        0,
                    )
                    .into(),
                )
                .map_err(from_io)?;
            local = self.local_addr()?;
        }
        local = unmapped(local);
        if let Some(source) = source.filter(|ip| !ip.is_unspecified()) {
            local.set_ip(unmapped(SocketAddr::new(source, 0)).ip());
        }
        if local.ip().is_unspecified() {
            local.set_ip(if peer.ip().is_loopback() {
                if peer.is_ipv4() {
                    Ipv4Addr::LOCALHOST.into()
                } else {
                    Ipv6Addr::LOCALHOST.into()
                }
            } else {
                namespace
                    .graph
                    .read()
                    .unwrap()
                    .source(namespace.id(), peer.ip())
                    .map(|v| v.0)
                    .unwrap_or(local.ip())
            });
        }
        let protocol = if self.kind == 1 {
            6
        } else if self.kind == 2 {
            17
        } else if peer.is_ipv4() {
            1
        } else {
            58
        };
        let (source, dest) = if input { (peer, local) } else { (local, peer) };
        let mut packet = crate::conntrack::message(source, dest, protocol, flags, bytes);
        let binding = self
            .policy_forward
            .borrow()
            .get(&(local, peer))
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(300))
            .map(|(f, _)| *f);
        let result = namespace.graph.read().unwrap().native_policy(
            namespace.id(),
            input,
            &mut packet,
            binding,
        );
        if let Some(forward) = result {
            if input {
                let mut cache = self.policy_forward.borrow_mut();
                if let Some(forward) = forward {
                    cache.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(300));
                    if cache.len() >= 512 && !cache.contains_key(&(local, peer)) {
                        if let Some(key) =
                            cache.iter().min_by_key(|(_, (_, at))| *at).map(|(k, _)| *k)
                        {
                            cache.remove(&key);
                        }
                    }
                    cache.insert((local, peer), (forward, Instant::now()));
                } else {
                    cache.remove(&(local, peer));
                }
            }
            Ok(())
        } else {
            Err(NetError(13))
        }
    }
    fn dns_endpoint(&self, address: SocketAddr) -> Result<Arc<direct_dns::Endpoint>> {
        self.network.destination(address)?;
        if self.family != 2 || !matches!(self.kind, 1 | 2) {
            return Err(NetError(97));
        }
        if !self.dns.borrow().contains_key(&address) {
            if self.local_addr()?.port() == 0 {
                self.native
                    .control()
                    .bind(
                        &SocketAddr::from((
                            if self.kind == 1 {
                                [127, 0, 0, 1]
                            } else {
                                [0; 4]
                            },
                            0,
                        ))
                        .into(),
                    )
                    .map_err(from_io)?;
            }
            self.dns.borrow_mut().insert(
                address,
                direct_dns::Endpoint::new(self.network.0.dns.clone(), self.kind == 1),
            );
        }
        Ok(self.dns.borrow()[&address].clone())
    }
    pub fn info(&self) -> super::SocketInfo {
        super::SocketInfo {
            namespace_id: 0, // Filled by the public socket wrapper.
            family: self.family,
            kind: match self.kind {
                3 => 2,
                4 => 3,
                n => n,
            },
            protocol: if self.kind == 1 {
                6
            } else if matches!(self.kind, 3 | 4) {
                if self.family == 2 {
                    1
                } else {
                    58
                }
            } else {
                17
            },
            state: if self.kind != 1 {
                if self.peer_addr().is_ok() {
                    1
                } else {
                    7
                }
            } else {
                match self.native.state.connection() {
                    Connection::Listening => 10,
                    Connection::Connecting => 2,
                    Connection::Connected => 1,
                    _ => 7,
                }
            },
            local: self.local_addr().ok(),
            peer: self.peer_addr().ok(),
            tx_queue: None,
            rx_queue: None,
        }
    }
    pub fn address_size(&self) -> usize {
        if self.family == 2 {
            16
        } else {
            28
        }
    }
    fn address(&self, address: SocketAddr) -> Result<SockAddr> {
        if address.is_ipv4() != (self.family == 2) {
            return Err(NetError(97));
        }
        // Native interface indices are not exposed to the guest namespace yet.
        if matches!(address, SocketAddr::V6(v) if v.scope_id() != 0) {
            return Err(NetError(95));
        }
        Ok(address.into())
    }
    pub fn bind(&self, address: SocketAddr) -> Result<()> {
        if direct_dns::system_address(address) {
            return Err(NetError(98));
        }
        let native = self.address(address)?;
        self.network.binding(address, self.kind)?;
        self.native.control().bind(&native).map_err(from_io)
    }
    pub fn listen(&self, backlog: u32) -> Result<()> {
        if self.kind != 1 {
            return Err(NetError(95));
        }
        if self.dns_peer.get() {
            return Err(NetError(22));
        }
        // Do not let listen() implicitly bind a wildcard TCP endpoint.
        let local = self.local_addr()?;
        if local.port() == 0 {
            return Err(NetError(22));
        }
        self.network.binding(local, self.kind)?;
        self.native
            .control()
            .listen(backlog.min(128) as i32)
            .map_err(from_io)?;
        self.native.state.set_connection(Connection::Listening);
        Ok(())
    }
    pub fn accept(&self) -> Result<(Rc<Socket>, SocketAddr)> {
        if self.native.state.connection() != Connection::Listening {
            return Err(NetError(22));
        }
        let reservation = self.network.reserve()?;
        let (native, peer) = self.native.control().accept().map_err(from_io)?;
        configure(&native)?;
        let peer = peer.as_socket().ok_or(NetError(5))?;
        let accepted =
            self.network
                .wrap(native, reservation, self.family, 1, Connection::Connected);
        if let Some(policy) = self.policy.borrow().as_ref() {
            accepted.attach_policy(policy.clone());
        }
        if accepted.policy_check(true, peer, &[], 2).is_err()
            || accepted.policy_check(false, peer, &[], 18).is_err()
        {
            let _ = accepted.shutdown(2);
            return Err(NetError(11));
        }
        Ok((accepted, peer))
    }
    pub fn connect(&self, address: SocketAddr) -> Result<()> {
        let native = self.address(address)?;
        self.network.destination(address)?;
        if self.kind == 1 {
            match self.native.state.connection() {
                Connection::Connecting => return Err(NetError(114)),
                Connection::Connected => return Err(NetError(106)),
                Connection::Listening => return Err(NetError(22)),
                Connection::Failed(e) => return Err(NetError(e)),
                Connection::Idle => {}
            }
        }
        if matches!(self.kind, 1 | 2) {
            self.policy_check(false, address, &[], 2)?;
        }
        if direct_dns::system_address(address) {
            self.dns_endpoint(address)?;
            self.dns_target.set(address);
            self.dns_peer.set(true);
            self.native.state.set_connection(Connection::Connected);
            return Ok(());
        }
        self.dns_peer.set(false);
        match self.native.control().connect(&native).map_err(from_io) {
            Ok(()) => {
                self.native.state.set_connection(Connection::Connected);
                Ok(())
            }
            Err(NetError(115 | 114)) if self.kind == 1 => {
                self.native.state.set_connection(Connection::Connecting);
                Err(NetError(115))
            }
            Err(e) => Err(e),
        }
    }
    /// A blocked guest connect resumes without issuing connect a second time.
    pub fn connect_complete(&self) -> Result<bool> {
        self.native
            .complete_connect(|peer| self.policy_check(true, peer, &[], 18))
    }

    pub fn resume_connect(&self) -> Result<bool> {
        let result = self.connect_complete();
        if matches!(self.native.state.connection(), Connection::Failed(_)) {
            // Blocking connect itself consumes the pending connection error.
            self.native.state.take_error();
            self.native
                .state
                .blocking_failed
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }
    fn before_io(&self) -> Result<()> {
        if self.native.state.connection() == Connection::Connecting {
            match self.connect_complete() {
                Ok(false) => return Err(NetError(11)),
                Ok(true) => {}
                Err(_) => {}
            }
        }
        if matches!(self.native.state.connection(), Connection::Failed(_)) {
            if let Some(error) = self.native.state.take_error() {
                return Err(NetError(error));
            }
        }
        Ok(())
    }
    /// Owner-only admission: no accepted direct TCP byte request can exist.
    /// Called with the actual Files membership locked. Every normal worker
    /// byte admission retains Endpoint under that same lock. Snapshot controls
    /// remain weak, and their read gate is excluded by the caller's writer.
    pub fn quiescent_tcp(&self) -> bool {
        (self.idle_tcp() || self.direct_tcp_admitted()) && Arc::strong_count(&self.native) == 1
    }
    pub fn idle_tcp(&self) -> bool {
        self.kind == 1
            && self.native.state.connection() == Connection::Idle
            && !self.dns_peer.get()
            && self.dns.borrow().is_empty()
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.native
            .control()
            .local_addr()
            .map_err(from_io)?
            .as_socket()
            .ok_or(NetError(5))
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        if self.dns_peer.get() {
            return Ok(self.dns_target.get());
        }
        self.native
            .control()
            .peer_addr()
            .map_err(from_io)?
            .as_socket()
            .ok_or(NetError(5))
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if self.dns_peer.get() {
            return self.dns_endpoint(self.dns_target.get())?.shutdown(how);
        }
        let how = match how {
            0 => Shutdown::Read,
            1 => Shutdown::Write,
            2 => Shutdown::Both,
            _ => return Err(NetError(22)),
        };
        self.native.control().shutdown(how).map_err(from_io)
    }
    pub fn send_packet(
        &self,
        bytes: &[u8],
        flags: u32,
        address: Option<SocketAddr>,
        info: crate::PacketInfo,
    ) -> Result<usize> {
        if self.kind != 2 {
            return Err(NetError(95));
        }
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > if self.family == 2 { 65507 } else { 65527 } {
            return Err(NetError(90));
        }
        let peer = address
            .or_else(|| self.peer_addr().ok())
            .ok_or(NetError(89))?;
        self.network.destination(peer)?;
        if peer.is_ipv4() != info.address.is_ipv4() {
            return Err(NetError(22));
        }
        if info.address.is_unspecified() {
            return self.send(bytes, flags, address);
        }
        self.policy_check_source(false, peer, bytes, 24, Some(info.address))?;
        let n = if direct_dns::system_address(peer) {
            self.send_inner(bytes, flags, address)?
        } else {
            pktinfo::send(self.native.as_fd().as_raw_fd(), bytes, peer, info.address)?
        };
        self.network.account(Some(peer.ip()), n, true);
        Ok(n)
    }
    pub fn send(&self, bytes: &[u8], flags: u32, address: Option<SocketAddr>) -> Result<usize> {
        if let Some(peer) = address.or_else(|| self.peer_addr().ok()) {
            self.policy_check(false, peer, bytes, 24)?;
        }
        let sent = self.send_inner(bytes, flags, address)?;
        if sent != 0 || self.kind != 1 {
            self.network.account(
                address.or_else(|| self.peer_addr().ok()).map(|a| a.ip()),
                sent,
                true,
            );
        }
        Ok(sent)
    }
    fn send_inner(&self, bytes: &[u8], flags: u32, address: Option<SocketAddr>) -> Result<usize> {
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > MAX_TRANSFER {
            return Err(NetError(90));
        }
        if self.kind == 2 && bytes.len() > if self.family == 2 { 65507 } else { 65527 } {
            return Err(NetError(90));
        }
        if address.is_some_and(direct_dns::system_address)
            || address.is_none() && self.dns_peer.get()
        {
            return self
                .dns_endpoint(address.unwrap_or(self.dns_target.get()))?
                .send(bytes);
        }
        if self.kind == 1 {
            self.before_io()?;
            if matches!(self.native.state.connection(), Connection::Failed(_)) {
                return Err(NetError(32));
            }
        }
        let echo_id = if self.kind == 4 {
            Some(self.check_echo(bytes)?)
        } else {
            None
        };
        let result = if let Some(address) = address {
            let address_native = self.address(address)?;
            self.network.destination(address)?;
            self.native
                .control()
                .send_to_with_flags(bytes, &address_native, direct::send_flags())
                .map_err(from_io)
        } else {
            direct::send_connected(&self.native, bytes)
        };
        if result.is_ok() {
            if let Some(id) = echo_id {
                self.echo.borrow_mut().identifier = Some(id);
            }
        }
        result
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Received> {
        let mut received = self.recv_inner(count, flags)?;
        let mut allowed = false;
        for attempt in 0..16 {
            let Some(peer) = received.address.or_else(|| self.peer_addr().ok()) else {
                break;
            };
            if self
                .policy_check_source(
                    true,
                    peer,
                    &received.data,
                    24,
                    received.packet_info.map(|i| i.address),
                )
                .is_ok()
            {
                allowed = true;
                break;
            }
            if self.kind == 1 {
                let _ = self.shutdown(2);
                return Err(NetError(13));
            }
            if flags & MSG_PEEK != 0 {
                let _ = self.recv_inner(65536, flags & !MSG_PEEK);
            }
            if attempt == 15 {
                return Err(NetError(11));
            }
            received = self.recv_inner(count, flags)?;
        }
        if !allowed && (received.address.is_some() || self.peer_addr().is_ok()) {
            return Err(NetError(11));
        }
        if flags & MSG_PEEK == 0 && (received.length != 0 || self.kind != 1) {
            self.network.account(
                received
                    .address
                    .or_else(|| self.peer_addr().ok())
                    .map(|a| a.ip()),
                received.length,
                false,
            );
        }
        Ok(received)
    }
    fn recv_inner(&self, count: usize, flags: u32) -> Result<Received> {
        if flags & 0x2000 != 0 {
            // MSG_ERRQUEUE is always nonblocking.
            if flags & !(0x2000 | MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC) != 0 {
                return Err(NetError(95));
            }
            if self.kind == 2
                && (self.dns_peer.get()
                    || self.dns_receive_errors.get()
                        && self.native.state.connection() == Connection::Idle)
            {
                // An in-process DNS service has no ICMP route: failures are DNS
                // replies. Reading its genuinely empty error queue consumes no
                // normal reply. Ordinary host UDP error queues stay unsupported.
                return Err(NetError(11));
            }
            return Err(NetError(95));
        }

        if flags & !(MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT) != 0 {
            return Err(NetError(95));
        }
        if self.kind == 1 && flags & MSG_TRUNC != 0 {
            return Err(NetError(95));
        }
        if count > MAX_TRANSFER {
            return Err(NetError(22));
        }
        if self.kind == 4 {
            return self.recv_echo(count, flags);
        }
        for (&address, dns) in self.dns.borrow().iter() {
            if self.dns_peer.get() && address != self.dns_target.get() {
                continue;
            }
            match dns.recv(count, flags) {
                Err(NetError(11)) => {}
                Ok(mut r) => {
                    if r.address.is_some() {
                        r.address = Some(address);
                    }
                    return Ok(r);
                }
                Err(e) => return Err(e),
            }
        }
        if self.dns_peer.get() || self.dns_receive_errors.get() && !self.dns.borrow().is_empty() {
            return Err(NetError(11));
        }
        if self.dns_receive_errors.get() {
            return Err(NetError(92));
        }
        if self.kind == 1 {
            self.before_io()?;
            if matches!(self.native.state.connection(), Connection::Failed(_)) {
                if self
                    .native
                    .state
                    .blocking_failed
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    return Err(NetError(107));
                }
                return Ok(Received {
                    netlink_address: None,
                    packet_info: None,
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
            if count == 0 {
                return Ok(Received {
                    netlink_address: None,
                    packet_info: None,
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
        }
        // Receive a complete UDP datagram into one bounded scratch buffer, even
        // for a zero-sized guest buffer. This preserves MSG_TRUNC and datagrams.
        let mut data = vec![0; if self.kind != 1 { 65536 } else { count }];
        let mut packet_info = None;
        let (length, address) = match &self.native.socket {
            NativeSocket::Tcp(socket) => {
                let length = direct::read_tcp(socket, &mut data, flags)?;
                (length, None)
            }
            NativeSocket::Udp(socket) => {
                if self.receive_packet_info.get() {
                    let (length, peer, dest) = pktinfo::receive(
                        self.native.as_fd().as_raw_fd(),
                        &mut data,
                        flags & MSG_PEEK != 0,
                    )?;
                    packet_info = dest.map(|ip| crate::PacketInfo {
                        address: ip,
                        interface: if unmapped(SocketAddr::new(ip, 0)).ip().is_loopback() {
                            1
                        } else {
                            2
                        },
                    });
                    (length, Some(peer))
                } else {
                    let (length, address) = if flags & MSG_PEEK != 0 {
                        socket.peek_from(&mut data)
                    } else {
                        socket.recv_from(&mut data)
                    }
                    .map_err(from_io)?;
                    (length, Some(address))
                }
            }
        };
        data.truncate(length.min(count));
        Ok(Received {
            netlink_address: None,
            packet_info,
            data,
            address,
            length,
            truncated: self.kind == 2 && length > count,
        })
    }
    fn native_poll(&self, events: u16) -> Result<u16> {
        self.native.poll(events)
    }

    pub fn poll(&self, events: u16) -> Result<u16> {
        if self.native.state.connection() == Connection::Connecting {
            let _ = self.connect_complete();
        }
        if let Connection::Failed(_) = self.native.state.connection() {
            return Ok((events & 4)
                | 16
                | if self.native.state.pending_error().is_some() {
                    8
                } else {
                    0
                });
        }
        if !self.dns.borrow().is_empty() {
            let ready = self
                .dns
                .borrow()
                .iter()
                .filter(|(a, _)| !self.dns_peer.get() || **a == self.dns_target.get())
                .fold(0, |out, (_, dns)| out | dns.poll(events));
            if self.dns_peer.get() {
                return Ok(ready);
            }
            return self.native_poll(events).map(|native| native | ready);
        }
        self.native_poll(events)
    }
    pub fn ancillary_hop(&self) -> Option<(u32, u32, u8)> {
        let e = self.echo.borrow();
        if !e.receive_hop {
            return None;
        }
        e.hop.map(|h| {
            if self.family == 2 {
                (0, 2, h)
            } else {
                (41, 52, h)
            }
        })
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if (level, name) == (58, 1) && self.family == 10 && self.kind == 4 {
            if value.len() != 32 {
                return Err(NetError(22));
            }
            let mut e = self.echo.borrow_mut();
            for (out, bytes) in e.filter.iter_mut().zip(value.chunks_exact(4)) {
                *out = u32::from_le_bytes(bytes.try_into().unwrap());
            }
            return Ok(());
        }
        if value.len() < 4 {
            return Err(NetError(22));
        }
        self.set_option(
            level,
            name,
            i32::from_le_bytes(value[..4].try_into().unwrap()),
        )
    }
    pub fn set_option(&self, level: u32, name: u32, value: i32) -> Result<()> {
        if (level, name) == (0, 11) && self.family == 2 && self.kind == 2 {
            if value != 0
                && self.native.state.connection() != Connection::Idle
                && !self.dns_peer.get()
            {
                return Err(NetError(92));
            }
            self.dns_receive_errors.set(value != 0);
            return Ok(());
        }
        if self.kind == 4 {
            if (level, name) == (255, 7) && self.family == 10 {
                return if value == 2 {
                    Ok(())
                } else {
                    Err(NetError(95))
                };
            }
            if (level == 41 && matches!(name, 8 | 51) && self.family == 10)
                || (level == 0 && name == 12 && self.family == 2)
            {
                self.echo.borrow_mut().receive_hop = value != 0;
                return Ok(());
            }
        }
        if matches!((level,name),(0,8)if self.family==2)
            || matches!((level,name),(41,49)if self.family==10)
        {
            if self.kind != 2 {
                return Err(NetError(92));
            }
            pktinfo::enable(
                self.native.as_fd().as_raw_fd(),
                self.family == 10,
                value != 0,
            )?;
            self.receive_packet_info.set(value != 0);
            return Ok(());
        }
        self.native
            .set_option(self.family, self.kind, level, name, value)
    }

    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        match (level, name) {
            (0, 11) if self.family == 2 && self.kind == 2 => {
                Ok(i32::from(self.dns_receive_errors.get()))
            }
            (0, 8) if self.family == 2 => Ok(i32::from(self.receive_packet_info.get())),
            (41, 49) if self.family == 10 => Ok(i32::from(self.receive_packet_info.get())),
            (1, 3) => Ok(match self.kind {
                3 => 2,
                4 => 3,
                n => n as i32,
            }),
            (1, 39) => Ok(self.family as i32),
            (1, 38) => Ok(if self.kind == 1 {
                6
            } else if matches!(self.kind, 3 | 4) {
                if self.family == 2 {
                    1
                } else {
                    58
                }
            } else {
                17
            }),
            (1, 30) => Ok(i32::from(
                self.native.state.connection() == Connection::Listening,
            )),
            (1, 4) => {
                if self.native.state.connection() == Connection::Connecting {
                    let _ = self.connect_complete();
                }
                if let Some(error) = self.native.state.take_error() {
                    return Ok(error as i32);
                }
                Ok(self
                    .native
                    .control()
                    .take_error()
                    .map_err(from_io)?
                    .map_or(0, |e| from_io(e).0 as i32))
            }
            _ => self.native.get_option(self.family, self.kind, level, name),
        }
    }
}

pub fn decode_address(bytes: &[u8]) -> Result<SocketAddr> {
    if bytes.len() < 2 {
        return Err(NetError(22));
    }
    let family = u16::from_le_bytes(bytes[..2].try_into().expect("family"));
    let port = || u16::from_be_bytes(bytes[2..4].try_into().expect("port"));
    match family {
        2 if bytes.len() >= 16 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            port(),
        )),
        10 if bytes.len() >= 28 => Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).expect("IPv6")),
            port(),
            u32::from_be_bytes(bytes[4..8].try_into().expect("flow")),
            u32::from_le_bytes(bytes[24..28].try_into().expect("scope")),
        ))),
        2 | 10 => Err(NetError(22)),
        _ => Err(NetError(97)),
    }
}
pub fn encode_address(address: SocketAddr) -> Vec<u8> {
    match address {
        SocketAddr::V4(v) => {
            let mut bytes = vec![0; 16];
            bytes[..2].copy_from_slice(&2u16.to_le_bytes());
            bytes[2..4].copy_from_slice(&v.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&v.ip().octets());
            bytes
        }
        SocketAddr::V6(v) => {
            let mut bytes = vec![0; 28];
            bytes[..2].copy_from_slice(&10u16.to_le_bytes());
            bytes[2..4].copy_from_slice(&v.port().to_be_bytes());
            bytes[4..8].copy_from_slice(&v.flowinfo().to_be_bytes());
            bytes[8..24].copy_from_slice(&v.ip().octets());
            bytes[24..28].copy_from_slice(&v.scope_id().to_le_bytes());
            bytes
        }
    }
}
fn from_io(error: io::Error) -> NetError {
    error
        .raw_os_error()
        .map_or(NetError(5), |e| from_errno(HostErrno::from_raw(e)))
}
fn from_errno(error: HostErrno) -> NetError {
    // Host errno numbers differ on Darwin. Only supported errors cross the ABI.
    use HostErrno::*;
    NetError(match error {
        EPERM => 1,
        EINTR => 4,
        EIO => 5,
        EBADF => 9,
        EAGAIN => 11,
        ENOMEM => 12,
        EACCES => 13,
        EFAULT => 14,
        EINVAL => 22,
        ENFILE => 23,
        EMFILE => 24,
        ENOSPC => 28,
        EPIPE => 32,
        EPROTO => 71,
        ENOTSOCK => 88,
        EDESTADDRREQ => 89,
        EMSGSIZE => 90,
        EPROTOTYPE => 91,
        ENOPROTOOPT => 92,
        EPROTONOSUPPORT => 93,
        ESOCKTNOSUPPORT => 94,
        EOPNOTSUPP => 95,
        #[cfg(target_vendor = "apple")]
        ENOTSUP => 95,
        EPFNOSUPPORT => 96,
        EAFNOSUPPORT => 97,
        EADDRINUSE => 98,
        EADDRNOTAVAIL => 99,
        ENETDOWN => 100,
        ENETUNREACH => 101,
        ENETRESET => 102,
        ECONNABORTED => 103,
        ECONNRESET => 104,
        ENOBUFS => 105,
        EISCONN => 106,
        ENOTCONN => 107,
        ESHUTDOWN => 108,
        ETOOMANYREFS => 109,
        ETIMEDOUT => 110,
        ECONNREFUSED => 111,
        EHOSTDOWN => 112,
        EHOSTUNREACH => 113,
        EALREADY => 114,
        EINPROGRESS => 115,
        ECANCELED => 125,
        _ => 5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_native_namespace_reserves_real_transports_and_cancels_on_workers() {
        fn shared<T: Send + Sync>() {}
        shared::<Network>();
        shared::<PreparedSocket>();
        let network = Network::new(NetworkMode::Loopback);
        let ready = std::sync::Barrier::new(9);
        let release = std::sync::Barrier::new(9);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let (network, ready, release) = (network.clone(), &ready, &release);
                scope.spawn(move || {
                    let sockets: Vec<_> = (0..8)
                        .map(|_| network.prepare_socket(2, 2, 0).unwrap())
                        .collect();
                    ready.wait();
                    release.wait();
                    drop(sockets);
                });
            }
            ready.wait();
            assert_eq!(network.live_sockets(), MAX_SOCKETS);
            assert!(matches!(network.prepare_socket(2, 2, 0), Err(NetError(24))));
            release.wait();
        });
        assert_eq!(network.live_sockets(), 0);
        assert!(matches!(
            Network::new(NetworkMode::Off).prepare_socket(2, 1, 0),
            Err(NetError(13))
        ));
    }
    #[test]
    fn prepared_socket_attaches_original_namespace_and_can_outlive_its_creator() {
        let network = Network::new(NetworkMode::Loopback);
        let worker = network.clone();
        let prepared = std::thread::spawn(move || worker.prepare_socket(2, 2, 0).unwrap())
            .join()
            .unwrap();
        let original = prepared.native.clone();
        assert_eq!(network.live_sockets(), 1);
        let socket = prepared.finish();
        assert!(Arc::ptr_eq(&socket.native, &original));
        assert!(Arc::ptr_eq(&socket.network.0, &network.0));
        let dns = socket.dns_endpoint(direct_dns::ADDRESS).unwrap();
        drop(socket);
        assert_eq!(network.live_sockets(), 1); // actual endpoint lease
        std::thread::spawn(move || drop(original)).join().unwrap();
        assert_eq!(network.live_sockets(), 0);
        drop(dns);
        let prepared = network.prepare_socket(10, 1, 0).unwrap();
        let namespace = Arc::downgrade(&network.0);
        drop(network);
        assert!(namespace.upgrade().is_some());
        std::thread::spawn(move || drop(prepared)).join().unwrap();
        assert!(namespace.upgrade().is_none());
    }
    #[test]
    fn sockaddr_roundtrip_network_port_and_flow_host_scope() {
        for address in [
            "127.0.0.1:32123".parse().unwrap(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0x12345678, 7)),
        ] {
            let bytes = encode_address(address);
            assert_eq!(decode_address(&bytes), Ok(address));
            assert_eq!(&bytes[2..4], &address.port().to_be_bytes());
        }
    }
    #[test]
    fn short_and_unknown_sockaddrs_are_bounded_errors() {
        for family in [2u16, 10] {
            let length = if family == 2 { 16 } else { 28 };
            for n in 0..length {
                let mut bytes = vec![0; n];
                if n >= 2 {
                    bytes[..2].copy_from_slice(&family.to_le_bytes());
                }
                assert_eq!(decode_address(&bytes), Err(NetError(22)));
            }
        }
        assert_eq!(decode_address(&[1, 0]), Err(NetError(97)));
    }
    #[test]
    fn policy_checks_mapped_loopback_and_client_udp_binding() {
        let local = Network::new(NetworkMode::Loopback);
        assert!(local
            .destination("[::ffff:127.0.0.1]:1234".parse().unwrap())
            .is_ok());
        assert_eq!(
            local.destination("192.0.2.1:443".parse().unwrap()),
            Err(NetError(13))
        );
        assert_eq!(
            local.binding("0.0.0.0:0".parse().unwrap(), 2),
            Err(NetError(13))
        );
        let outbound = Network::new(NetworkMode::Outbound);
        assert!(outbound.binding("0.0.0.0:0".parse().unwrap(), 2).is_ok());
        assert_eq!(
            outbound.binding("0.0.0.0:0".parse().unwrap(), 1),
            Err(NetError(13))
        );
        assert_eq!(
            outbound.binding("127.0.0.1:53".parse().unwrap(), 2),
            Err(NetError(13))
        );
        assert_eq!(
            outbound.destination("0.0.0.0:443".parse().unwrap()),
            Err(NetError(13))
        );
        let full = Network::new(NetworkMode::Full);
        assert!(full.binding("[::]:12345".parse().unwrap(), 1).is_ok());
    }
}

#[cfg(test)]
mod dns_error_options {
    use super::*;
    #[test]
    fn resolver_error_option_and_empty_error_queue_preserve_normal_reply() {
        let network = crate::Network::new(NetworkMode::Outbound);
        let socket = network.socket(2, 2, 0).unwrap();
        socket.set_option(0, 11, 1).unwrap();
        assert_eq!(socket.get_option(0, 11), Ok(1));
        socket.connect(direct_dns::ROUTABLE_ADDRESS).unwrap();
        assert_eq!(socket.send(b"xx", 0, None), Ok(2));
        assert!(matches!(socket.recv(512, 0x2000), Err(NetError(11))));
        let answer = socket.recv(512, 0).unwrap();
        assert_eq!(&answer.data[..2], b"xx");
        assert_eq!(answer.data[3] & 15, 1);
        assert!(matches!(
            socket.recv(512, 0x2000 | MSG_DONTWAIT),
            Err(NetError(11))
        ));
        socket.set_option(0, 11, 0).unwrap();
        assert_eq!(socket.get_option(0, 11), Ok(0));
    }
    #[test]
    fn native_udp_does_not_silently_claim_linux_icmp_error_queue_support() {
        let network = crate::Network::new(NetworkMode::Loopback);
        let socket = network.socket(2, 2, 0).unwrap();
        socket.set_option(0, 11, 1).unwrap();
        let peer = SocketAddr::from(([127, 0, 0, 1], 9));
        assert_eq!(socket.connect(peer), Err(NetError(92)));
        assert_eq!(socket.send(b"not sent", 0, Some(peer)), Err(NetError(92)));
        socket.set_option(0, 11, 0).unwrap();
        socket.connect(peer).unwrap();
        assert_eq!(socket.set_option(0, 11, 1), Err(NetError(92)));
        assert_eq!(socket.get_option(0, 11), Ok(0));
    }
}
