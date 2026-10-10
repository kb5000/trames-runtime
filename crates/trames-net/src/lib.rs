// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded native sockets. All host operations are nonblocking; guest ABI
//! addresses, flags and errno numbers are translated explicitly.
use nix::{
    errno::Errno as HostErrno,
    poll::{poll, PollFd, PollFlags, PollTimeout},
};
use socket2::{Domain, Protocol, SockAddr, SockRef, Socket as RawNativeSocket, Type};
use std::{
    cell::Cell,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpStream, UdpSocket},
    os::fd::{AsFd, BorrowedFd},
    rc::Rc,
    time::Duration,
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
pub fn wait(sockets: &[(Rc<Socket>, u16)], timeout: Duration) -> Result<()> {
    let mut unique: Vec<(Rc<Socket>, u16)> = Vec::new();
    for (socket, events) in sockets {
        if let Some((_, interest)) = unique.iter_mut().find(|(s, _)| Rc::ptr_eq(s, socket)) {
            *interest |= events;
        } else {
            if unique.len() == MAX_SOCKETS {
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
    let timeout = PollTimeout::try_from(timeout).map_err(|_| NetError(22))?;
    match poll(&mut fds, timeout) {
        Ok(_) | Err(HostErrno::EINTR) => Ok(()),
        Err(error) => Err(from_errno(error)),
    }
}
struct Namespace {
    mode: NetworkMode,
    sockets: Cell<usize>,
}
#[derive(Clone)]
pub struct Network(Rc<Namespace>);
impl Default for Network {
    fn default() -> Self {
        Self::new(NetworkMode::Off)
    }
}
impl Network {
    pub fn new(mode: NetworkMode) -> Self {
        Self(Rc::new(Namespace {
            mode,
            sockets: Cell::new(0),
        }))
    }
    pub fn live_sockets(&self) -> usize {
        self.0.sockets.get()
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Rc<Socket>> {
        let domain = match family {
            2 => Domain::IPV4,
            10 => Domain::IPV6,
            _ => return Err(NetError(97)),
        };
        let (ty, native_protocol) = match (kind, protocol) {
            (1, 0 | 6) => (Type::STREAM, Protocol::TCP),
            (2, 0 | 17) => (Type::DGRAM, Protocol::UDP),
            (1 | 2, _) => return Err(NetError(93)),
            _ => return Err(NetError(94)),
        };
        self.reserve()?;
        let native = RawNativeSocket::new(domain, ty, Some(native_protocol)).map_err(from_io)?;
        configure(&native)?;
        if family == 10 {
            native.set_only_v6(true).map_err(from_io)?;
        }
        Ok(self.wrap(native, family, kind, Connection::Idle))
    }
    fn reserve(&self) -> Result<()> {
        if self.0.mode == NetworkMode::Off {
            Err(NetError(13))
        } else if self.live_sockets() >= MAX_SOCKETS {
            Err(NetError(24))
        } else {
            Ok(())
        }
    }
    fn wrap(
        &self,
        native: RawNativeSocket,
        family: u32,
        kind: u32,
        connection: Connection,
    ) -> Rc<Socket> {
        self.0.sockets.set(self.live_sockets() + 1);
        Rc::new(Socket {
            native: if kind == 1 {
                NativeSocket::Tcp(native.into())
            } else {
                NativeSocket::Udp(native.into())
            },
            network: self.clone(),
            family,
            kind,
            connection: Cell::new(connection),
            pending_error: Cell::new(None),
            blocking_failed: Cell::new(false),
        })
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
        if address.port() != 0 && address.port() < 1024 {
            return Err(NetError(13));
        }
        if self.0.mode == NetworkMode::Full || loopback(address.ip()) {
            return Ok(());
        }
        // DNS clients commonly explicitly bind INADDR_ANY:0. This allows an
        // ephemeral UDP endpoint, not a guest-selected public service port.
        if self.0.mode == NetworkMode::Outbound
            && kind == 2
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
    native: NativeSocket,
    network: Network,
    family: u32,
    kind: u32,
    connection: Cell<Connection>,
    pending_error: Cell<Option<u32>>,
    blocking_failed: Cell<bool>,
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.network.0.sockets.set(self.network.live_sockets() - 1);
    }
}
pub struct Received {
    pub data: Vec<u8>,
    pub address: Option<SocketAddr>,
    pub length: usize,
    pub truncated: bool,
}
impl Socket {
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
        let native = self.address(address)?;
        self.network.binding(address, self.kind)?;
        self.native.control().bind(&native).map_err(from_io)
    }
    pub fn listen(&self, backlog: u32) -> Result<()> {
        if self.kind != 1 {
            return Err(NetError(95));
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
        self.connection.set(Connection::Listening);
        Ok(())
    }
    pub fn accept(&self) -> Result<(Rc<Socket>, SocketAddr)> {
        if self.connection.get() != Connection::Listening {
            return Err(NetError(22));
        }
        self.network.reserve()?;
        let (native, peer) = self.native.control().accept().map_err(from_io)?;
        configure(&native)?;
        let peer = peer.as_socket().ok_or(NetError(5))?;
        Ok((
            self.network
                .wrap(native, self.family, 1, Connection::Connected),
            peer,
        ))
    }
    pub fn connect(&self, address: SocketAddr) -> Result<()> {
        let native = self.address(address)?;
        self.network.destination(address)?;
        if self.kind == 1 {
            match self.connection.get() {
                Connection::Connecting => return Err(NetError(114)),
                Connection::Connected => return Err(NetError(106)),
                Connection::Listening => return Err(NetError(22)),
                Connection::Failed(e) => return Err(NetError(e)),
                Connection::Idle => {}
            }
        }
        match self.native.control().connect(&native).map_err(from_io) {
            Ok(()) => {
                self.connection.set(Connection::Connected);
                Ok(())
            }
            Err(NetError(115 | 114)) if self.kind == 1 => {
                self.connection.set(Connection::Connecting);
                Err(NetError(115))
            }
            Err(e) => Err(e),
        }
    }
    /// A blocked guest connect resumes without issuing connect a second time.
    pub fn connect_complete(&self) -> Result<bool> {
        if self.connection.get() == Connection::Connecting {
            let ready = self.native_poll(4)?;
            if ready & (4 | 8 | 16) != 0 {
                if let Some(error) = self.native.control().take_error().map_err(from_io)? {
                    let error = from_io(error).0;
                    self.connection.set(Connection::Failed(error));
                    self.pending_error.set(Some(error));
                } else {
                    self.connection.set(Connection::Connected);
                }
            }
        }
        match self.connection.get() {
            Connection::Connecting => Ok(false),
            Connection::Connected => Ok(true),
            Connection::Failed(e) => Err(NetError(e)),
            _ => Err(NetError(107)),
        }
    }
    pub fn resume_connect(&self) -> Result<bool> {
        let result = self.connect_complete();
        if matches!(self.connection.get(), Connection::Failed(_)) {
            // Blocking connect itself consumes the pending connection error.
            self.pending_error.set(None);
            self.blocking_failed.set(true);
        }
        result
    }
    fn before_io(&self) -> Result<()> {
        if self.connection.get() == Connection::Connecting {
            match self.connect_complete() {
                Ok(false) => return Err(NetError(11)),
                Ok(true) => {}
                Err(_) => {}
            }
        }
        if matches!(self.connection.get(), Connection::Failed(_)) {
            if let Some(error) = self.pending_error.take() {
                return Err(NetError(error));
            }
        }
        Ok(())
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
        self.native
            .control()
            .peer_addr()
            .map_err(from_io)?
            .as_socket()
            .ok_or(NetError(5))
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        let how = match how {
            0 => Shutdown::Read,
            1 => Shutdown::Write,
            2 => Shutdown::Both,
            _ => return Err(NetError(22)),
        };
        self.native.control().shutdown(how).map_err(from_io)
    }
    pub fn send(&self, bytes: &[u8], flags: u32, address: Option<SocketAddr>) -> Result<usize> {
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > MAX_TRANSFER {
            return Err(NetError(90));
        }
        if self.kind == 2 && bytes.len() > if self.family == 2 { 65507 } else { 65527 } {
            return Err(NetError(90));
        }
        if self.kind == 1 {
            self.before_io()?;
            if matches!(self.connection.get(), Connection::Failed(_)) {
                return Err(NetError(32));
            }
        }
        let native_flags;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            native_flags = nix::libc::MSG_NOSIGNAL;
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            native_flags = 0;
        }
        if let Some(address) = address {
            let address_native = self.address(address)?;
            self.network.destination(address)?;
            self.native
                .control()
                .send_to_with_flags(bytes, &address_native, native_flags)
                .map_err(from_io)
        } else {
            self.native
                .control()
                .send_with_flags(bytes, native_flags)
                .map_err(from_io)
        }
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Received> {
        if flags & !(MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT) != 0 {
            return Err(NetError(95));
        }
        if self.kind == 1 && flags & MSG_TRUNC != 0 {
            return Err(NetError(95));
        }
        if count > MAX_TRANSFER {
            return Err(NetError(22));
        }
        if self.kind == 1 {
            self.before_io()?;
            if matches!(self.connection.get(), Connection::Failed(_)) {
                if self.blocking_failed.get() {
                    return Err(NetError(107));
                }
                return Ok(Received {
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
            if count == 0 {
                return Ok(Received {
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
        }
        // Receive a complete UDP datagram into one bounded scratch buffer, even
        // for a zero-sized guest buffer. This preserves MSG_TRUNC and datagrams.
        let mut data = vec![0; if self.kind == 2 { 65536 } else { count }];
        let (length, address) = match &self.native {
            NativeSocket::Tcp(socket) => {
                let length = if flags & MSG_PEEK != 0 {
                    socket.peek(&mut data)
                } else {
                    let mut socket = socket;
                    socket.read(&mut data)
                }
                .map_err(from_io)?;
                (length, None)
            }
            NativeSocket::Udp(socket) => {
                let (length, address) = if flags & MSG_PEEK != 0 {
                    socket.peek_from(&mut data)
                } else {
                    socket.recv_from(&mut data)
                }
                .map_err(from_io)?;
                (length, Some(address))
            }
        };
        data.truncate(length.min(count));
        Ok(Received {
            data,
            address,
            length,
            truncated: self.kind == 2 && length > count,
        })
    }
    fn native_poll(&self, events: u16) -> Result<u16> {
        let mut wanted = PollFlags::empty();
        if events & 1 != 0 {
            wanted |= PollFlags::POLLIN;
        }
        if events & 2 != 0 {
            wanted |= PollFlags::POLLPRI;
        }
        if events & 4 != 0 {
            wanted |= PollFlags::POLLOUT;
        }
        let mut fds = [PollFd::new(self.native.as_fd(), wanted)];
        poll(&mut fds, PollTimeout::ZERO).map_err(from_errno)?;
        let ready = fds[0].revents().unwrap_or(PollFlags::empty());
        let mut result = 0;
        for (native, guest) in [
            (PollFlags::POLLIN, 1),
            (PollFlags::POLLPRI, 2),
            (PollFlags::POLLOUT, 4),
            (PollFlags::POLLERR, 8),
            (PollFlags::POLLHUP, 16),
            (PollFlags::POLLNVAL, 32),
        ] {
            if ready.contains(native) {
                result |= guest;
            }
        }
        Ok(result)
    }
    pub fn poll(&self, events: u16) -> Result<u16> {
        if self.connection.get() == Connection::Connecting {
            let _ = self.connect_complete();
        }
        if let Connection::Failed(_) = self.connection.get() {
            return Ok((events & 4)
                | 16
                | if self.pending_error.get().is_some() {
                    8
                } else {
                    0
                });
        }
        self.native_poll(events)
    }
    pub fn set_option(&self, level: u32, name: u32, value: i32) -> Result<()> {
        let result = match (level, name) {
            (1, 2) => self.native.control().set_reuse_address(value != 0),
            (1, 9) => self.native.control().set_keepalive(value != 0),
            (1, 7 | 8) => {
                if value <= 0 || value as usize > MAX_BUFFER {
                    return Err(NetError(22));
                }
                if name == 7 {
                    self.native.control().set_send_buffer_size(value as usize)
                } else {
                    self.native.control().set_recv_buffer_size(value as usize)
                }
            }
            (6, 1) if self.kind == 1 => self.native.control().set_tcp_nodelay(value != 0),
            (41, 26) if self.family == 10 => self.native.control().set_only_v6(value != 0),
            (1, 20 | 21) => return Err(NetError(95)), // guest timeout state is not implemented
            _ => return Err(NetError(92)),
        };
        result.map_err(from_io)
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        match (level, name) {
            (1, 3) => Ok(self.kind as i32),
            (1, 39) => Ok(self.family as i32),
            (1, 38) => Ok(if self.kind == 1 { 6 } else { 17 }),
            (1, 30) => Ok(i32::from(self.connection.get() == Connection::Listening)),
            (1, 4) => {
                if self.connection.get() == Connection::Connecting {
                    let _ = self.connect_complete();
                }
                if let Some(error) = self.pending_error.take() {
                    return Ok(error as i32);
                }
                Ok(self
                    .native
                    .control()
                    .take_error()
                    .map_err(from_io)?
                    .map_or(0, |e| from_io(e).0 as i32))
            }
            (1, 2) => Ok(i32::from(
                self.native.control().reuse_address().map_err(from_io)?,
            )),
            (1, 9) => Ok(i32::from(
                self.native.control().keepalive().map_err(from_io)?,
            )),
            (1, 7) => Ok(self.native.control().send_buffer_size().map_err(from_io)? as i32),
            (1, 8) => Ok(self.native.control().recv_buffer_size().map_err(from_io)? as i32),
            (6, 1) if self.kind == 1 => Ok(i32::from(
                self.native.control().tcp_nodelay().map_err(from_io)?,
            )),
            (41, 26) if self.family == 10 => {
                Ok(i32::from(self.native.control().only_v6().map_err(from_io)?))
            }
            _ => Err(NetError(92)),
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
