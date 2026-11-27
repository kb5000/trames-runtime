// SPDX-License-Identifier: GPL-3.0-or-later
//! A bounded IP fabric. Only the trusted gateway opens native sockets.
use crate::dns;
use crate::shared_state::FabricState;
use crate::shared_state::{Cell, State as SharedState};
use crate::socket_quota::{Quota, Reservation};
use std::ops::Deref;
mod ethernet;
mod multicast;
mod wire;
pub use wire::WireWait;
mod gateway;
#[cfg(test)]
mod icmp_tests;
pub(crate) mod packet;
mod raw_errors;
mod sockets;
mod udp_errors;
use super::native::{
    self, NetError, NetworkMode, Received, MAX_BUFFER, MAX_TRANSFER, MSG_DONTWAIT, MSG_NOSIGNAL,
    MSG_OOB, MSG_PEEK, MSG_TRUNC,
};
use crate::ethernet::PacketType;
use packet::{Port, Tuple};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{icmp, raw, tcp, udp},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, NetError>;
fn tcp_errno(failure: tcp::Failure) -> u32 {
    match failure {
        tcp::Failure::HostUnreachable => 113,
        tcp::Failure::Refused => 111,
        tcp::Failure::Reset => 104,
        tcp::Failure::PeerAlreadyClosed => 32,
        tcp::Failure::TimedOut => 110,
    }
}
const BUFFER: usize = 65536;
const MAX_ENVIRONMENTS: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkInfo {
    pub id: u8,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub gateway4: Ipv4Addr,
    pub gateway6: Ipv6Addr,
    pub mtu: u32,
    pub prefix4: u8,
    pub prefix6: u8,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkStats {
    pub packets: u64,
    pub dropped: u64,
    pub corrupted: u64,
    pub native_flows: usize,
    pub stack_sockets: usize,
    pub environments: usize,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkStats {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_dropped: u64,
}
#[derive(Clone)]
pub struct Fabric(Arc<FabricState<Inner>>);
struct InjectedPacket {
    mark: u32,
    node: u64,
    interface: u32,
    kind: PacketType,
    source: [u8; 6],
    bytes: Vec<u8>,
}
struct Inner {
    drivers: Vec<Weak<trames_shared::Readiness>>,
    driver_dirty: bool,
    driver_maintenance: bool,
    close_batch_until: Option<Instant>,
    notifications: Vec<Arc<trames_shared::Readiness>>,
    injected: VecDeque<InjectedPacket>,
    ethernet: VecDeque<(crate::netdev::View, crate::ethernet::Action)>,
    ethernet_switch: crate::ethernet::Switch,
    started: Instant,
    next_node: u64,
    // Keep large smoltcp interface buffers out of B-tree insertion/split frames.
    nodes: BTreeMap<u64, Box<Node>>,
    gateway: gateway::Gateway,
    stats: NetworkStats,
    drop_every: u32,
    corrupt_every: u32,
    external: Option<wire::Wire>,
    revision: u64,
}
struct DetachedTcp {
    reuse_addr: bool,
    device: Option<u32>,
    handle: SocketHandle,
    deadline: Instant,
    fin_wait_seconds: i32,
    in_fin_wait2: bool,
}

impl DetachedTcp {
    fn new(
        handle: SocketHandle,
        fin_wait_seconds: i32,
        now: Instant,
        reuse_addr: bool,
        device: Option<u32>,
    ) -> Self {
        Self {
            handle,
            reuse_addr,
            device,
            fin_wait_seconds,
            deadline: now + Duration::from_secs(30),
            in_fin_wait2: false,
        }
    }

    fn observe(&mut self, state: tcp::State, now: Instant) {
        let fin_wait2 = state == tcp::State::FinWait2;
        if self.in_fin_wait2 != fin_wait2 {
            self.in_fin_wait2 = fin_wait2;
            let seconds = if fin_wait2 {
                self.fin_wait_seconds.max(0) as u64
            } else {
                30
            };
            self.deadline = now + Duration::from_secs(seconds);
        }
    }
}

// Linux TCP remembers the last admitted reuse-port owner at bind time.
// A mixed REUSEADDR/REUSEPORT bucket uses a directional address match.
struct TcpBindBucket {
    owners: usize,
    reuse: Option<TcpReuseOwner>,
}

struct TcpReuseOwner {
    uid: u32,
    address: Option<(SocketAddr, bool)>,
}

impl TcpReuseOwner {
    fn admits(&self, uid: u32, address: SocketAddr, dual: bool) -> bool {
        self.uid == uid
            && self.address.is_none_or(|(cached, cached_dual)| {
                (cached.ip().is_unspecified() || cached.ip() == address.ip())
                    && sockets::addresses_overlap(cached, cached_dual, address, dual)
            })
    }
}

impl TcpBindBucket {
    fn record(&mut self, reusable: bool, uid: u32, address: SocketAddr, dual: bool) {
        if !reusable {
            self.reuse = None;
        } else if !self
            .reuse
            .as_ref()
            .is_some_and(|owner| owner.admits(uid, address, dual))
        {
            self.reuse = Some(TcpReuseOwner {
                uid,
                address: (self.owners != 0).then_some((address, dual)),
            });
        }
    }
}

struct Node {
    tcp_binds: BTreeMap<u16, TcpBindBucket>,
    udp_bind_order: u64,
    udp_readers: BTreeMap<u64, Arc<trames_shared::Readiness>>,
    next_listener: u64,
    growing_listeners: Vec<Weak<SocketMeta>>,
    tcp_waiters: BTreeMap<SocketHandle, Arc<trames_shared::Readiness>>,
    id: u8,
    owner: Weak<NamespaceData>,
    iface: Interface,
    sockets: SocketSet<'static>,
    port: Port,
    filter_rx: Port,
    gateway_rx: Port,
    registry: Vec<Weak<SocketMeta>>,
    detached: Vec<DetachedTcp>,
    links: [LinkStats; 2],
    configuration_revision: u64,
    dirty: bool,
    next_poll: Option<smoltcp::time::Instant>,
    #[cfg(test)]
    polls: u64,
    configuration_lo: bool,
}
impl Node {
    fn set_ip_settings(&mut self, settings: &Arc<crate::IpSettings>) {
        for port in [&mut self.port, &mut self.filter_rx, &mut self.gateway_rx] {
            port.ip_settings = Some(settings.clone());
        }
    }
}
struct Namespace {
    data: Arc<NamespaceData>,
}
impl Deref for Namespace {
    type Target = NamespaceData;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}
// Packet observers may outlive the final control owner briefly. Their metadata
// carries no close callback, so dropping an observer under the fabric cannot
// recursively acquire the fabric lock.
struct NamespaceData {
    fabric: Fabric,
    key: u64,
    info: NetworkInfo,
    mode: NetworkMode,
    live: Arc<Quota>,
    ephemeral_port: Cell<u16>,
    port_range: Cell<u32>,
    binding: parking_lot::Mutex<()>,
    finished: Cell<bool>,
    isolated: Cell<bool>,
    loopback_up: std::sync::Arc<crate::netdev::Loopback>,
    routing: std::sync::OnceLock<crate::netdev::View>,
    managed_uplink: bool,
}
#[derive(Clone)]
pub(super) struct Network(Arc<Namespace>);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Connection {
    Idle,
    Connecting,
    Connected,
    Listening,
    Failed(u32),
}
#[derive(Clone, Copy, Default)]
struct UdpOptions {
    fields: crate::IpFields,
    receive_class: bool,
    receive_hops: bool,
    receive_info: bool,
    original_destination: bool,
}
/// Linux IP_MTU_DISCOVER for IPv4 traffic, including v4-mapped peers.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(i32)]
enum Ipv4Pmtu {
    Dont,
    #[default]
    Want,
    Do,
    Probe,
    Interface,
    Omit,
}

impl Ipv4Pmtu {
    fn parse(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Dont),
            1 => Ok(Self::Want),
            2 => Ok(Self::Do),
            3 => Ok(Self::Probe),
            4 => Ok(Self::Interface),
            5 => Ok(Self::Omit),
            _ => Err(NetError(22)),
        }
    }
    fn enforce_mtu(self) -> bool {
        matches!(self, Self::Do | Self::Probe | Self::Interface)
    }
    fn udp_df(self) -> bool {
        matches!(self, Self::Want | Self::Do | Self::Probe)
    }
    fn tcp_df(self) -> bool {
        matches!(self, Self::Want | Self::Do)
    }
}

struct State {
    handles: Vec<SocketHandle>,
    connection: Connection,
    bound: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    error: Option<u32>,
    connect_result_pending: bool,
    read_closed: bool,
    write_closed: bool,
    v6_only: bool,
    reuse: bool,
    reuse_port: bool,
    listener_rank: u64,
    shared_tcp_binding: bool,
    tcp_bind_port: u16,
    udp_bind_order: u64,
    // Address and port requested by bind(2), before ephemeral allocation.
    requested_bind: Option<SocketAddr>,
    udp_shared: bool,
    udp_readable: Option<Arc<trames_shared::Readiness>>,
    listener_ready: Option<Arc<trames_shared::Readiness>>,
    udp_group: Option<u64>,
    nodelay: bool,
    cork: bool,
    max_segment: Option<u16>,
    quick_ack: bool,
    congestion: tcp::CongestionControl,
    fin_wait_seconds: i32,
    syn_retries: Option<u8>,
    defer_accept_secs: u32,
    user_timeout_ms: u32,
    window_clamp: u32,
    linger_enabled: bool,
    linger_seconds: u32,
    linger_closing: bool,
    receive_inq: bool,
    receive_low_water: i32,
    oob_inline: bool,
    no_check: bool,
    timestamp_option: u32,
    last_packet_ns: Option<u64>,
    keepalive: bool,
    keep_idle: u32,
    keep_interval: u32,
    keep_count: u32,
    backlog: usize,
    icmp_pending: Option<(Vec<u8>, IpAddr, u64)>,
    hop_limit: u8,
    receive_hops: bool,
    ipv4_pmtu: Ipv4Pmtu,
    udp_options: [UdpOptions; 2],
    receive_filter: Option<Arc<dyn smoltcp::socket::ReceiveFilter>>,
    udp_errors: Option<Arc<udp_errors::Errors>>,
    multicast: Option<Box<multicast::Options>>,
    last_hop: Option<u8>,
    broadcast: bool,
    icmp_filter: [u8; 4],
    icmp6_filter: [u8; 32],
    raw_checksum: i32,
    header_included: bool,
    raw_ingress: u32,
    hop_message: u32,
    device: Option<u32>,
    raw_identifiers: std::collections::BTreeSet<u16>,
    receive_buffer: usize,
    send_buffer: usize,
}
pub(super) struct Socket {
    network: Network,
    meta: Arc<SocketMeta>,
    _reservation: Reservation,
}
impl Deref for Socket {
    type Target = SocketMeta;
    fn deref(&self) -> &Self::Target {
        &self.meta
    }
}
pub(super) struct SocketMeta {
    family: u32,
    protocol: u8,
    kind: u32,
    state: SharedState<State>,
    mark: Cell<u32>,
    uid: Cell<u32>,
    route_device: Cell<u32>,
    connecting: std::sync::atomic::AtomicBool,
}
impl SocketMeta {
    fn raw_transport(&self) -> bool {
        self.kind == 4 && matches!(self.protocol, 6 | 17 | 255)
    }
    fn raw_udp(&self) -> bool {
        self.family == 2 && self.kind == 4 && self.protocol == 17
    }
}
fn v4(id: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, id)
}
fn v6(id: u8) -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, id as u16)
}
fn ip(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(a) => IpAddress::Ipv4(a),
        IpAddr::V6(a) => IpAddress::Ipv6(a),
    }
}
fn addr(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4(a) => IpAddr::V4(a),
        IpAddress::Ipv6(a) => IpAddr::V6(a),
    }
}
fn endpoint(a: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(ip(a.ip()), a.port())
}
fn address(a: IpEndpoint) -> SocketAddr {
    SocketAddr::new(addr(a.addr), a.port)
}
fn tcp_socket() -> tcp::Socket<'static> {
    tcp_socket_with_buffers(BUFFER, BUFFER)
}
fn initial_buffer(bytes: usize) -> usize {
    if bytes > MAX_BUFFER {
        BUFFER
    } else {
        bytes
    }
}
fn tcp_socket_with_buffers(receive: usize, send: usize) -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; initial_buffer(receive)]),
        tcp::SocketBuffer::new(vec![0; initial_buffer(send)]),
    );
    if receive > MAX_BUFFER {
        configure_tcp_buffer(&mut s, true, receive);
    }
    if send > MAX_BUFFER {
        configure_tcp_buffer(&mut s, false, send);
    }
    s.set_ack_delay(Some(smoltcp::time::Duration::from_millis(10)));
    s.set_handshake_timeout(smoltcp::time::Duration::from_secs(60));
    s
}
fn packet_slots(bytes: usize) -> usize {
    (bytes / 64).max(1)
}
fn udp_socket() -> udp::Socket<'static> {
    udp_socket_with_buffers(BUFFER, BUFFER)
}
impl State {
    /// A pending nonblocking result is consumed once by a repeated connect.
    fn existing_tcp_connect(&mut self) -> Result<bool> {
        match self.connection {
            Connection::Connecting => Err(NetError(114)),
            Connection::Connected if std::mem::take(&mut self.connect_result_pending) => Ok(true),
            Connection::Connected => Err(NetError(106)),
            Connection::Listening => Err(NetError(22)),
            Connection::Failed(_) => {
                self.connection = Connection::Idle;
                self.connect_result_pending = false;
                Err(NetError(self.error.take().unwrap_or(103)))
            }
            Connection::Idle => Ok(false),
        }
    }

    fn release_tcp_bind(&mut self, buckets: &mut BTreeMap<u16, TcpBindBucket>) {
        let port = std::mem::take(&mut self.tcp_bind_port);
        if port != 0 {
            let bucket = buckets.get_mut(&port).unwrap();
            bucket.owners -= 1;
            if bucket.owners == 0 {
                buckets.remove(&port);
            }
        }
    }

    fn fail_connect(&mut self, error: u32, buckets: &mut BTreeMap<u16, TcpBindBucket>) {
        self.error = Some(error);
        self.peer = None;
        // An explicitly chosen port remains bound. An ephemeral port is
        // released as soon as the active open fails, even if the FD lives on.
        self.bound = self.requested_bind.filter(|addr| addr.port() != 0);
        if self.bound.is_none() {
            self.release_tcp_bind(buckets);
        }
        self.connection = Connection::Failed(error);
    }

    fn add_listener_slot(
        &mut self,
        socket: tcp::Socket<'static>,
        sockets: &mut SocketSet<'static>,
        waiters: &mut BTreeMap<SocketHandle, Arc<trames_shared::Readiness>>,
    ) {
        let handle = sockets.add(socket);
        if let Some(source) = &self.listener_ready {
            sockets
                .get_mut::<tcp::Socket>(handle)
                .observe_io(Some(handle));
            waiters.insert(handle, source.clone());
        }
        self.handles.push(handle);
    }

    fn new_tcp_socket(&self, local: IpAddr, mark: u32) -> tcp::Socket<'static> {
        let mut socket = tcp_socket_with_buffers(self.receive_buffer, self.send_buffer);
        socket.set_mark(mark);
        if local.is_loopback() {
            socket.set_tsval_generator(Some(|| {
                static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
                EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u32
            }));
        }
        socket.set_receive_filter(self.receive_filter.clone());
        socket.set_ipv4_dont_fragment(self.ipv4_pmtu.tcp_df());
        socket.set_linux_binding(
            self.device.unwrap_or(0),
            self.listener_rank,
            self.bound.is_some_and(|a| !a.ip().is_unspecified()),
        );
        if socket.congestion_control() != self.congestion {
            socket.set_congestion_control(self.congestion);
        }
        socket.enable_receive_timestamps(self.timestamp_option != 0);
        socket.set_defer_accept(self.defer_accept_secs);
        if let Some(retries) = self.syn_retries {
            socket.set_syn_retries(retries);
        }
        if self.user_timeout_ms != 0 {
            socket.set_user_timeout(Some(smoltcp::time::Duration::from_millis(
                self.user_timeout_ms.into(),
            )));
        }
        if self.window_clamp != 0 {
            socket.set_receive_window_limit(self.receive_buffer.min(self.window_clamp as usize));
        }
        socket.set_nagle_enabled(!self.nodelay);
        socket.set_cork(self.cork);
        socket.set_max_segment(self.max_segment);
        socket.set_quick_ack(self.quick_ack);
        socket.set_hop_limit(Some(self.hop_limit));
        if self.keepalive {
            socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(
                self.keep_idle as u64,
            )));
        }
        socket
    }
    fn bound_udp_handle(&self, local: SocketAddr, specific: bool) -> Result<udp::Socket<'static>> {
        let mut socket = udp_socket_with_buffers(self.receive_buffer, self.send_buffer);
        self.bind_udp_handle(&mut socket, local, specific)?;
        Ok(socket)
    }
    fn bind_udp_handle(
        &self,
        socket: &mut udp::Socket,
        local: SocketAddr,
        specific: bool,
    ) -> Result<()> {
        socket.set_receive_filter(self.receive_filter.clone());
        socket.enable_linux_receive();
        socket.set_ingress_device(self.device.unwrap_or(0));
        socket.observe_errors(self.udp_errors.as_ref().unwrap().clone());
        socket.set_bind_priority(self.udp_bind_order, specific);
        if self.udp_readable.is_some() {
            socket.observe_readable(self.udp_bind_order);
        }
        if self.udp_shared {
            socket.allow_shared_delivery();
        }
        socket.set_reuse_port_group(self.udp_group);
        socket.set_receive_peer(self.peer.filter(|p| p.port() != 0).map(endpoint));
        socket.set_hop_limit(Some(self.hop_limit));
        socket.bind(endpoint(local)).map_err(|_| NetError(22))
    }
}
impl SocketMeta {
    fn reuse_port_group(&self) -> u64 {
        (u64::from(self.family) << 32) | u64::from(self.uid.get())
    }
}
fn configure_tcp_buffer(socket: &mut tcp::Socket, receive: bool, bytes: usize) {
    if bytes > MAX_BUFFER {
        socket.set_owned_buffer_budget(receive, bytes);
    } else {
        socket.resize_owned_buffer(receive, bytes);
    }
}
fn configure_udp_buffer(socket: &mut udp::Socket, receive: bool, bytes: usize) {
    if bytes > MAX_BUFFER {
        socket.set_owned_buffer_budget(receive, packet_slots(bytes), bytes);
    } else if receive {
        socket.resize_receive_buffer(packet_slots(bytes), bytes);
    } else {
        socket.resize_send_buffer(packet_slots(bytes), bytes);
    }
}
fn udp_socket_with_buffers(receive: usize, send: usize) -> udp::Socket<'static> {
    let buffer = |bytes: usize| {
        let initial = initial_buffer(bytes);
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; packet_slots(initial)],
            vec![0; initial],
        )
    };
    let mut socket = udp::Socket::new(buffer(receive), buffer(send));
    if receive > MAX_BUFFER {
        configure_udp_buffer(&mut socket, true, receive);
    }
    if send > MAX_BUFFER {
        configure_udp_buffer(&mut socket, false, send);
    }
    socket
}
fn make_node(id: u8, now: smoltcp::time::Instant) -> Result<Box<Node>> {
    let mut port = Port::default();
    let mut config = Config::new(HardwareAddress::Ip);
    let mut seed = [0; 8];
    getrandom::fill(&mut seed).map_err(|_| NetError(5))?;
    config.random_seed = u64::from_ne_bytes(seed);
    let mut iface = Interface::new(config, &mut port, now);
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::new(ip(v4(id).into()), 24)).unwrap();
        a.push(IpCidr::new(ip(v6(id).into()), 64)).unwrap();
        if id != 1 {
            a.push(IpCidr::new(ip(Ipv4Addr::LOCALHOST.into()), 8))
                .unwrap();
            a.push(IpCidr::new(ip(Ipv6Addr::LOCALHOST.into()), 128))
                .unwrap();
        }
    });
    iface.routes_mut().add_default_ipv4_route(v4(1)).unwrap();
    iface.routes_mut().add_default_ipv6_route(v6(1)).unwrap();
    if id == 1 {
        iface.set_any_ip(true);
    }
    Ok(Box::new(Node {
        tcp_binds: BTreeMap::new(),
        udp_bind_order: 0,
        udp_readers: BTreeMap::new(),
        next_listener: 0,
        growing_listeners: Vec::new(),
        tcp_waiters: BTreeMap::new(),
        id,
        owner: Weak::new(),
        iface,
        sockets: SocketSet::new(Vec::new()),
        port,
        filter_rx: Port::default(),
        gateway_rx: Port::default(),
        registry: Vec::new(),
        detached: Vec::new(),
        links: [LinkStats::default(); 2],
        configuration_revision: u64::MAX,
        dirty: true,
        next_poll: None,
        #[cfg(test)]
        polls: 0,
        configuration_lo: false,
    }))
}
impl Fabric {
    pub fn new() -> Result<Self> {
        Ok(Self(Arc::new(FabricState::new(Inner {
            drivers: Vec::new(),
            driver_dirty: false,
            driver_maintenance: false,
            close_batch_until: None,
            notifications: Vec::new(),
            injected: VecDeque::new(),
            ethernet: VecDeque::new(),
            ethernet_switch: Default::default(),
            started: Instant::now(),
            next_node: 1,
            nodes: BTreeMap::new(),
            gateway: gateway::Gateway::new()?,
            stats: NetworkStats::default(),
            drop_every: 0,
            corrupt_every: 0,
            external: None,
            revision: 0,
        }))))
    }
    /// Attach a host-authorized private Trames network. The product owns its
    /// directory/lease; bind is exclusive and never replaces a live endpoint.
    pub fn attach(&self, directory: &std::path::Path, id: u8, nat: bool) -> Result<()> {
        if !(2..=254).contains(&id) {
            return Err(NetError(22));
        }
        let mut inner = self.0.borrow_mut();
        if inner.external.is_some() {
            return Err(NetError(16));
        }
        let path = directory.join(format!("p{id}"));
        inner.external = Some(
            wire::Wire::bind(path, id, nat)
                .map_err(|e| NetError(e.raw_os_error().unwrap_or(5) as u32))?,
        );
        Ok(())
    }
    pub(crate) fn bind_driver(&self, changed: &Arc<trames_shared::Readiness>) {
        let mut inner = self.0.borrow_mut();
        if !inner
            .drivers
            .iter()
            .any(|d| d.as_ptr() == Arc::as_ptr(changed))
        {
            inner.drivers.push(Arc::downgrade(changed));
        }
    }
    pub(crate) fn protocol_tick(&self) {
        for (socket, _) in self.native_waiters() {
            for source in socket.wait_interests() {
                source.drain();
            }
        }
        let mut inner = self.0.borrow_mut();
        inner.driver_maintenance = true;
        if let Some(wire) = &inner.external {
            wire.wait.drain();
        }
        inner.tick();
    }
    pub(crate) fn protocol_delay(&self) -> Option<Duration> {
        let mut inner = self.0.borrow_mut();
        let now = inner.now();
        if !inner.ethernet.is_empty()
            || !inner.injected.is_empty()
            || inner.external.as_ref().is_some_and(wire::Wire::runnable)
            || inner.nodes.values().any(|n| n.dirty)
        {
            return Some(Duration::ZERO);
        }
        let mut next = {
            let Inner { nodes, gateway, .. } = &mut *inner;
            nodes
                .values_mut()
                .chain(std::iter::once(&mut gateway.node))
                .filter_map(|n| n.iface.poll_delay(now, &n.sockets))
                .map(|d| Duration::from_millis(d.total_millis()))
                .min()
        };
        if let Some(deadline) = inner
            .nodes
            .values()
            .flat_map(|n| &n.detached)
            .map(|e| e.deadline)
            .min()
        {
            let delay = deadline.saturating_duration_since(Instant::now());
            next = Some(next.map_or(delay, |d| d.min(delay)));
        }
        // A burst of final closes shares one follow-up wake. Other socket I/O
        // can deliver the queued FINs earlier on the normal packet path.
        if let Some(until) = inner.close_batch_until {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                inner.close_batch_until = None;
            } else {
                next = Some(next.map_or(remaining, |d| d.min(remaining)));
            }
        }
        for view in inner
            .nodes
            .values()
            .filter_map(|n| n.owner.upgrade())
            .filter_map(|o| o.routing.get().cloned())
        {
            let graph = view.graph.read().unwrap();
            if let Some(delay) = graph.packet_block_delay(view.namespace) {
                next = Some(next.map_or(delay, |d| d.min(delay)));
            }
            if let Some(delay) = graph.neighbor_delay(view.namespace) {
                next = Some(next.map_or(delay, |d| d.min(delay)));
            }
        }
        next
    }
    pub(super) fn external_waiter(&self) -> Option<Arc<WireWait>> {
        self.0.borrow().external.as_ref().map(|e| e.wait.clone())
    }
    pub fn publish(&self, host: SocketAddr, guest: SocketAddr, kind: u32) -> Result<()> {
        let mut i = self.0.borrow_mut();
        i.gateway.publish(host, guest, kind)?;
        i.revision = i.revision.wrapping_add(1);
        if let Some(link) = &i.external {
            link.wait.wake();
        }
        Ok(())
    }
    pub fn unpublish(&self, host: SocketAddr, kind: u32) -> Result<()> {
        let mut i = self.0.borrow_mut();
        i.gateway.unpublish(host, kind)?;
        i.revision = i.revision.wrapping_add(1);
        if let Some(link) = &i.external {
            link.wait.wake();
        }
        Ok(())
    }
    pub(super) fn revision(&self) -> u64 {
        self.0.borrow().revision
    }
    /// Explicit trusted native service mapping; never callable by a guest syscall.
    pub fn map_host_ip(&self, virtual_ip: IpAddr, host_ip: IpAddr) -> Result<()> {
        if virtual_ip.is_unspecified()
            || virtual_ip.is_loopback()
            || virtual_ip.is_multicast()
            || private_ip(virtual_ip)
        {
            return Err(NetError(22));
        }
        let mut inner = self.0.borrow_mut();
        if inner.gateway.mappings.len() >= 16 && !inner.gateway.mappings.contains_key(&virtual_ip) {
            return Err(NetError(105));
        }
        inner.gateway.mappings.insert(virtual_ip, host_ip);
        Ok(())
    }
    /// Deterministic link faults for embedders/tests. Corruption happens after checksums.
    pub fn set_link_faults(&self, drop_every: u32, corrupt_every: u32) {
        let mut i = self.0.borrow_mut();
        i.drop_every = drop_every;
        i.corrupt_every = corrupt_every;
    }
    pub fn stats(&self) -> NetworkStats {
        let i = self.0.borrow();
        let mut s = i.stats;
        s.environments = i.nodes.len();
        s.native_flows = i.gateway.flow_count();
        s.stack_sockets = i.handles();
        s
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(super) fn environment(&self, id: u8, mode: NetworkMode) -> Result<Network> {
        let mut i = self.0.borrow_mut();
        if !(2..=254).contains(&id) {
            return Err(NetError(22));
        }
        if i.nodes.values().any(|n| n.id == id) {
            return Err(NetError(98));
        }
        if i.nodes.len() >= MAX_ENVIRONMENTS {
            return Err(NetError(105));
        }
        let key = i.next_node;
        i.next_node = i.next_node.checked_add(1).ok_or(NetError(105))?;
        let info = NetworkInfo {
            id,
            ipv4: v4(id),
            ipv6: v6(id),
            gateway4: v4(1),
            gateway6: v6(1),
            mtu: packet::MTU as u32,
            prefix4: 24,
            prefix6: 64,
        };
        let mut node = make_node(id, i.now())?;
        let ns = Arc::new(Namespace {
            data: Arc::new(NamespaceData {
                fabric: self.clone(),
                key,
                info,
                mode,
                live: Arc::new(Quota::with_limit(crate::socket_quota::GUEST_SOCKET_LIMIT)),
                ephemeral_port: Cell::new(0),
                port_range: Cell::new((65535 << 16) | 49152),
                binding: parking_lot::Mutex::new(()),
                finished: Cell::new(false),
                isolated: Cell::new(false),
                loopback_up: std::sync::Arc::new(crate::netdev::Loopback::new(true)),
                routing: std::sync::OnceLock::new(),
                managed_uplink: true,
            }),
        });
        node.owner = Arc::downgrade(&ns.data);
        i.nodes.insert(key, node);
        Ok(Network(ns))
    }
    pub(super) fn dynamic_environment(
        &self,
        mode: NetworkMode,
        routing: crate::netdev::View,
        loopback_up: std::sync::Arc<crate::netdev::Loopback>,
    ) -> Result<Network> {
        let mut i = self.0.borrow_mut();
        if i.nodes.len() >= 128 {
            return Err(NetError(28));
        }
        let key = i.next_node;
        i.next_node = i.next_node.checked_add(1).ok_or(NetError(28))?;
        let mut node = make_node(2, i.now())?;
        node.set_ip_settings(&routing.ip_settings);
        let ns = Arc::new(Namespace {
            data: Arc::new(NamespaceData {
                fabric: self.clone(),
                key,
                info: NetworkInfo {
                    id: 2,
                    ipv4: Ipv4Addr::UNSPECIFIED,
                    ipv6: Ipv6Addr::UNSPECIFIED,
                    gateway4: Ipv4Addr::UNSPECIFIED,
                    gateway6: Ipv6Addr::UNSPECIFIED,
                    mtu: 1500,
                    prefix4: 0,
                    prefix6: 0,
                },
                mode,
                live: Arc::new(Quota::with_limit(crate::socket_quota::GUEST_SOCKET_LIMIT)),
                ephemeral_port: Cell::new(0),
                port_range: Cell::new((65535 << 16) | 49152),
                binding: parking_lot::Mutex::new(()),
                finished: Cell::new(false),
                isolated: Cell::new(true),
                loopback_up,
                managed_uplink: routing.managed_uplink(),
                routing: std::sync::OnceLock::from(routing),
            }),
        });
        node.owner = Arc::downgrade(&ns.data);
        node.iface.set_any_ip(true);
        node.configure_dynamic();
        i.nodes.insert(key, node);
        Ok(Network(ns))
    }
    pub(super) fn tick(&self) {
        let mut inner = self.0.borrow_mut();
        if let Some(wire) = &inner.external {
            wire.wait.drain();
        }
        // Control operations mutate socket sets/topology through this entry.
        // Data operations mark only their original node; never poll all nodes
        // just because another application tried to read an empty queue.
        for n in inner.nodes.values_mut() {
            n.dirty = true;
        }
        inner.tick();
    }
    pub(super) fn next_wait(&self) -> Duration {
        let mut i = self.0.borrow_mut();
        let now = i.now();
        let Inner { nodes, gateway, .. } = &mut *i;
        nodes
            .values_mut()
            .chain(std::iter::once(&mut gateway.node))
            .filter_map(|n| n.iface.poll_delay(now, &n.sockets))
            .map(|d| Duration::from_millis(d.total_millis()))
            .min()
            .unwrap_or(Duration::from_millis(20))
            .min(Duration::from_millis(20))
    }
    pub(super) fn native_waiters(&self) -> Vec<(Arc<native::Socket>, u16)> {
        self.0.borrow().gateway.waiters()
    }
}
fn gateway_ip(a: IpAddr) -> bool {
    a == IpAddr::V4(v4(1))
        || a == IpAddr::V6(v6(1))
        || a == crate::direct_dns::ROUTABLE_ADDRESS.ip()
}
fn private_ip(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => a.octets()[..3] == [10, 0, 0],
        IpAddr::V6(a) => a.segments()[..4] == [0xfd00, 0, 0, 0],
    }
}
impl crate::shared_state::AfterUnlock for Inner {
    fn take_callbacks(&mut self) -> Vec<Box<dyn FnOnce() + Send>> {
        let dirty = std::mem::take(&mut self.driver_dirty);
        let maintenance = std::mem::take(&mut self.driver_maintenance);
        if !dirty || maintenance {
            return vec![];
        }
        self.drivers.retain(|d| d.strong_count() != 0);
        let changed: Vec<_> = self.drivers.iter().filter_map(Weak::upgrade).collect();
        if changed.is_empty() {
            return vec![];
        }
        vec![Box::new(move || {
            for changed in changed {
                changed.notify_atomic();
            }
        })]
    }
    fn take_notifications(&mut self) -> Vec<Arc<trames_shared::Readiness>> {
        std::mem::take(&mut self.notifications)
    }
}
impl Inner {
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_millis(
            self.started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        )
    }
    // Statistics only: live descriptors and protocol closing states have
    // independent lifetimes. Counting both must never gate a new connection.
    fn handles(&self) -> usize {
        self.nodes
            .values()
            .map(|n| n.sockets.iter().count())
            .sum::<usize>()
            + self.gateway.node.sockets.iter().count()
            + self.gateway.pending_handles()
    }
    fn tick(&mut self) {
        self.driver_dirty = true;
        self.ethernet_timers();
        self.pump_ethernet();
        let now = self.now();
        let time = Instant::now();
        for node in self.nodes.values_mut() {
            node.configure_dynamic();
            node.registry.retain(|s| s.strong_count() != 0);
        }
        self.receive_external();
        self.pump_ethernet();
        // Bound work per scheduler slice even when a peer produces data continuously.
        for round in 0..32 {
            self.pump_ethernet();
            self.gateway.service(now, &self.nodes);
            let mut packets: Vec<_> = self
                .injected
                .drain(..)
                .map(|p| {
                    (
                        p.node,
                        Some((p.interface, p.kind)),
                        p.source,
                        None,
                        p.mark,
                        p.bytes,
                    )
                })
                .collect();
            for (&key, node) in &mut self.nodes {
                let poll = node.dirty
                    || !node.port.rx.is_empty()
                    || node.next_poll.is_some_and(|d| d <= now);
                if poll {
                    node.dirty = false;
                    node.iface.poll(now, &mut node.port, &mut node.sockets);
                    node.next_poll = node.iface.poll_at(now, &node.sockets);
                    #[cfg(test)]
                    {
                        node.polls += 1;
                    }
                }
                if (round == 0 || poll) && !node.detached.is_empty() {
                    node.detached.retain_mut(|entry| {
                        let socket = node.sockets.get_mut::<tcp::Socket>(entry.handle);
                        let state = socket.state();
                        entry.observe(state, time);
                        if state != tcp::State::Closed && entry.deadline > time {
                            return true;
                        }
                        if state == tcp::State::FinWait2 {
                            socket.abort_with_context(node.iface.context());
                            node.iface.poll(now, &mut node.port, &mut node.sockets);
                        }
                        node.sockets.remove(entry.handle);
                        false
                    });
                }
                // A verified SYN can arrive over loopback, Ethernet, or a guest link.
                // Grow the listener only after its transport has consumed a slot.
                while let Some(endpoint) = node.iface.pop_filled_listener() {
                    node.grow_accept_queue(address(endpoint));
                }
                for h in node.iface.drain_tcp_ready() {
                    if let Some(source) = node.tcp_waiters.get(&h) {
                        self.notifications.push(source.clone());
                    }
                }
                for token in node.iface.drain_udp_readable() {
                    if let Some(source) = node.udp_readers.get(&token) {
                        self.notifications.push(source.clone());
                    }
                }
                while let Some((p, route, mark)) = node.port.tx.pop_front() {
                    packets.push((key, None, [0; 6], route, mark, p));
                }
            }
            self.gateway.node.iface.poll(
                now,
                &mut self.gateway.node.port,
                &mut self.gateway.node.sockets,
            );
            while let Some((p, route, mark)) = self.gateway.node.port.tx.pop_front() {
                packets.push((0, None, [0; 6], route, mark, p));
            }
            if packets.is_empty() {
                break;
            }
            for (source, ingress, peer, route, mut mark, mut p) in packets {
                let injected = ingress.map(|(index, _)| index);
                let packet_type = ingress.map_or(PacketType::Host, |(_, kind)| kind);
                let lo = route.map_or_else(
                    || packet::header(&p).is_some_and(|h| h.tuple.destination.ip().is_loopback()),
                    |ip| ip.is_loopback(),
                );
                if let Some(n) = self.nodes.get_mut(&source) {
                    let s = &mut n.links[usize::from(!lo)];
                    s.tx_packets += 1;
                    s.tx_bytes += p.len() as u64;
                }
                self.stats.packets += 1;
                if self.drop_every != 0 && self.stats.packets.is_multiple_of(self.drop_every as u64)
                {
                    self.stats.dropped += 1;
                    if let Some(n) = self.nodes.get_mut(&source) {
                        n.links[usize::from(!lo)].tx_dropped += 1;
                    }
                    continue;
                }
                if self.corrupt_every != 0
                    && self.stats.packets.is_multiple_of(self.corrupt_every as u64)
                {
                    if let Some(b) = p.last_mut() {
                        *b ^= 1;
                    }
                    self.stats.corrupted += 1;
                }
                let Some(_h) = packet::header(&p) else {
                    self.stats.dropped += 1;
                    if let Some(n) = self.nodes.get_mut(&source) {
                        n.links[usize::from(!lo)].tx_dropped += 1;
                    }
                    continue;
                };
                if source == 0 {
                    let rx = &mut self.gateway.node.filter_rx;
                    if !rx.receive_marked(p, injected.unwrap_or(0), mark) {
                        self.stats.dropped += 1;
                        continue;
                    }
                    let Some((complete, _, reassembled_mark)) = rx.rx.pop_front() else {
                        continue;
                    };
                    mark = reassembled_mark;
                    p = complete;
                }
                let Some(h) = packet::header(&p) else {
                    continue;
                };
                let routed_reply = if source == 0 {
                    self.gateway.reply_route(&p)
                } else {
                    None
                };
                let dynamic = routed_reply.as_ref().map(|r| r.0.clone()).or_else(|| {
                    if source == 0 {
                        return self
                            .nodes
                            .values()
                            .find(|n| {
                                h.tuple.destination.ip() == IpAddr::V4(v4(n.id))
                                    || h.tuple.destination.ip() == IpAddr::V6(v6(n.id))
                            })
                            .and_then(|n| n.owner.upgrade())
                            .and_then(|n| n.routing.get().cloned());
                    }

                    self.nodes
                        .get(&source)
                        .and_then(|n| n.owner.upgrade())
                        .and_then(|ns| ns.routing.get().cloned())
                });
                let mut delivery = None;
                let target = if let Some(view) = &dynamic {
                    // Reassemble before L4 matching/NAT. A bounded IP queue is
                    // also used for unfragmented packets without copying them.
                    if source != 0 {
                        let rx = &mut self.nodes.get_mut(&source).unwrap().filter_rx;
                        if !rx.receive_marked(p, injected.unwrap_or(0), mark) {
                            self.stats.dropped += 1;
                            continue;
                        }
                        let Some((complete, _, reassembled_mark)) = rx.rx.pop_front() else {
                            continue;
                        };
                        mark = reassembled_mark;
                        p = complete;
                    }
                    if !packet::valid_transport(&p) {
                        // Raw sockets observe local IP traffic before the protocol validates its
                        // header. Keep invalid transport data off forwarding paths and
                        // out of transport queues. Apply the normal local output/input hooks.
                        let delivered = injected.is_none()
                            && matches!(h.protocol, 1 | 6 | 17)
                            && self.nodes.get_mut(&source).is_some_and(|node| {
                                node.receive_local_raw(
                                    view,
                                    &mut p,
                                    h.tuple.destination.ip(),
                                    h.protocol,
                                    route,
                                    mark,
                                )
                            });
                        if !delivered {
                            self.stats.dropped += 1;
                        }
                        continue;
                    }
                    if let Some(index) = injected {
                        if h.tuple.source.is_ipv4()
                            && !view.graph.read().unwrap().accepts_ipv4_ingress(
                                view.namespace,
                                index,
                                h.tuple.source.ip(),
                                h.tuple.destination.ip(),
                            )
                        {
                            self.stats.dropped += 1;
                            continue;
                        }
                        if h.protocol == 17
                            && multicast::group_on(
                                Some(view),
                                Some(index),
                                h.tuple.destination.ip(),
                            )
                        {
                            self.group_input(source, view, index, packet_type, &mut p, mark);
                            continue;
                        }
                    }
                    let original = crate::conntrack::key(&p);
                    let incoming = injected
                        .or_else(|| routed_reply.as_ref().map(|r| r.1))
                        .or_else(|| (source == 0).then_some(2));
                    if let Some(index) = incoming {
                        let d = view
                            .graph
                            .read()
                            .unwrap()
                            .device(view.namespace, index)
                            .ok();
                        if let Some(d) = d {
                            if source == 0 && d.kind == crate::DeviceKind::Ethernet {
                                let actions = view.graph.read().unwrap().ethernet_arrival(
                                    view.namespace,
                                    index,
                                    [2, 0x54, 0x72, 0x61, 0, 1],
                                    p,
                                );
                                self.queue_frames(view, actions);
                                continue;
                            }
                        }
                    }

                    let step = view.graph.read().unwrap().route_one(
                        view.namespace,
                        incoming.map(|index| (index, packet_type)),
                        &mut p,
                        route,
                        &mut mark,
                    );
                    let Some((route, next_hop)) = step else {
                        self.stats.dropped += 1;
                        continue;
                    };
                    // A frame written to lo in loopback-only mode must remain local
                    // even if a guest route or NAT rule points at another device.
                    if injected == Some(1)
                        && next_hop.is_some()
                        && self
                            .nodes
                            .get(&source)
                            .and_then(|n| n.owner.upgrade())
                            .is_some_and(|n| n.mode == NetworkMode::Loopback)
                    {
                        self.stats.dropped += 1;
                        continue;
                    }
                    delivery = Some(route);
                    if let Some(next_hop) = next_hop.filter(|_| !route.tunnel && !route.external) {
                        let actions = view.graph.read().unwrap().ethernet_ip(
                            view.namespace,
                            route.output,
                            next_hop,
                            p,
                            mark,
                        );
                        self.queue_frames(view, actions);
                        continue;
                    }
                    if route.input == 1 && incoming.is_none() {
                        view.graph.read().unwrap().observe_local_loopback(
                            view.namespace,
                            &p,
                            &mut self.notifications,
                        );
                    } else if route.input == 1 && injected.is_none() {
                        view.graph.read().unwrap().observe(
                            view.namespace,
                            1,
                            peer,
                            &p,
                            false,
                            &mut self.notifications,
                        );
                    }
                    if route.tunnel {
                        view.graph.read().unwrap().observe(
                            view.namespace,
                            route.output,
                            [0; 6],
                            &p,
                            true,
                            &mut self.notifications,
                        );
                        let graph = view.graph.read().unwrap();
                        let len = p.len();
                        let delivered = graph.transmit_tun(
                            route.namespace,
                            route.input,
                            p,
                            &mut self.notifications,
                        );
                        graph.account(route.namespace, route.input, len, true, !delivered);
                        if !delivered {
                            self.stats.dropped += 1;
                        }
                        continue;
                    }
                    if route.external {
                        let Some(wire) = crate::conntrack::key(&p) else {
                            self.stats.dropped += 1;
                            continue;
                        };
                        let mut gateway_view = view.clone();
                        gateway_view.namespace = route.namespace;
                        let allowed = self
                            .nodes
                            .get(&source)
                            .and_then(|n| n.owner.upgrade())
                            .is_some_and(|ns| {
                                matches!(ns.mode, NetworkMode::Full | NetworkMode::Outbound)
                            });
                        let allowed = allowed
                            && (self.external.as_ref().is_none_or(|e| e.nat)
                                || gateway_ip(wire.tuple.destination.ip()));
                        let ok = allowed
                            && self.gateway.route_flow(
                                wire,
                                original.unwrap(),
                                source,
                                gateway_view,
                                route.input,
                            );
                        let h = packet::header(&p).unwrap();
                        if !ok || !self.gateway.ingress(source, p, &h, &self.nodes, now) {
                            self.stats.dropped += 1;
                        }
                        continue;
                    }
                    self.nodes.iter().find_map(|(&key, n)| {
                        n.owner.upgrade().and_then(|ns| {
                            ns.routing.get().and_then(|r| {
                                (r.namespace == route.namespace
                                    && std::sync::Arc::ptr_eq(&r.graph, &view.graph))
                                .then_some(key)
                            })
                        })
                    })
                } else {
                    let dst = h.tuple.destination.ip();
                    if dst.is_loopback() {
                        (source != 0).then_some(source)
                    } else {
                        self.nodes
                            .iter()
                            .find(|(_, n)| {
                                n.owner
                                    .upgrade()
                                    .is_some_and(|ns| ns.routing.get().is_none())
                                    && (dst == IpAddr::V4(v4(n.id)) || dst == IpAddr::V6(v6(n.id)))
                            })
                            .map(|(&key, _)| key)
                    }
                };
                let Some(h) = packet::header(&p) else {
                    self.stats.dropped += 1;
                    continue;
                };
                let dst = h.tuple.destination.ip();
                if let Some(key) = target {
                    let permitted = source == key
                        || source == 0
                        || self
                            .nodes
                            .get(&source)
                            .and_then(|n| n.owner.upgrade())
                            .is_some_and(|ns| {
                                matches!(ns.mode, NetworkMode::Outbound | NetworkMode::Full)
                            });
                    let node = self.nodes.get_mut(&key).unwrap();
                    let enabled = node.owner.upgrade().is_some_and(|ns| {
                        ns.mode != NetworkMode::Off
                            && (!lo || ns.loopback_up.get())
                            && (source == key
                                || matches!(ns.mode, NetworkMode::Outbound | NetworkMode::Full))
                    });
                    let size = p.len() as u64;
                    let dropped = !permitted
                        || !enabled
                        || !node.port.receive_on(
                            p,
                            delivery.map_or(if lo { 1 } else { 2 }, |path| path.input),
                        );
                    if let (Some(view), Some(path)) = (&dynamic, delivery) {
                        let graph = view.graph.read().unwrap();
                        graph.account(view.namespace, path.output, size as usize, true, dropped);
                        graph.account(path.namespace, path.input, size as usize, false, dropped);
                    }
                    if dropped {
                        node.links[usize::from(!lo)].rx_dropped += 1;
                        self.stats.dropped += 1;
                    } else {
                        let s = &mut node.links[usize::from(!lo)];
                        s.rx_packets += 1;
                        s.rx_bytes += size;
                    }
                } else if source != 0 && dynamic.is_none() && private_ip(dst) && !gateway_ip(dst) {
                    // Guest-owned links always use Ethernet; no legacy raw-IP wire.
                    self.stats.dropped += 1;
                } else if source != 0
                    && dynamic.is_none()
                    && (gateway_ip(dst) || self.external.as_ref().is_none_or(|e| e.nat))
                    && (!private_ip(dst) || gateway_ip(dst))
                {
                    if !self.gateway.ingress(source, p, &h, &self.nodes, now) {
                        self.stats.dropped += 1;
                    }
                } else {
                    self.stats.dropped += 1;
                    if let Some(n) = self.nodes.get_mut(&source) {
                        n.links[usize::from(!lo)].tx_dropped += 1;
                    }
                }
            }
        }
        for node in self.nodes.values_mut() {
            for weak in &node.registry {
                if let Some(socket) = weak.upgrade() {
                    if !socket.connecting.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    let mut state = socket.state.borrow_mut();
                    if state.connection == Connection::Connecting {
                        if let Some(&h) = state.handles.first() {
                            match node.sockets.get::<tcp::Socket>(h).state() {
                                tcp::State::Established | tcp::State::CloseWait => {
                                    state.connection = Connection::Connected
                                }
                                tcp::State::Closed => {
                                    let e = state
                                        .error
                                        .or_else(|| {
                                            node.sockets
                                                .get_mut::<tcp::Socket>(h)
                                                .take_failure()
                                                .map(tcp_errno)
                                        })
                                        .unwrap_or(110);
                                    state.fail_connect(e, &mut node.tcp_binds);
                                    state.handles.clear();
                                    node.sockets.remove(h);
                                }
                                _ => {}
                            }
                        }
                    }
                    socket.connecting.store(
                        state.connection == Connection::Connecting,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
        }
    }
}
impl Node {
    fn receive_local_raw(
        &mut self,
        view: &crate::netdev::View,
        packet: &mut [u8],
        dest: IpAddr,
        protocol: u8,
        route_hint: Option<IpAddr>,
        mut mark: u32,
    ) -> bool {
        let matches = |s: &SocketMeta| {
            s.kind == 4 && s.protocol == protocol && (s.family == 2) == dest.is_ipv4()
        };
        if !self
            .registry
            .iter()
            .filter_map(Weak::upgrade)
            .any(|s| matches(&s))
        {
            return false;
        }
        let graph = view.graph.read().unwrap();
        if !graph.own(view.namespace, route_hint.unwrap_or(dest)) {
            return false;
        }
        let Some((route, None)) =
            graph.route_one(view.namespace, None, packet, route_hint, &mut mark)
        else {
            return false;
        };
        if route.namespace != view.namespace || route.external || route.tunnel {
            return false;
        }
        let Some(header) = packet::header(packet) else {
            return false;
        };
        drop(graph);
        let mut delivered = false;
        for socket in self
            .registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|s| matches(s))
        {
            let state = socket.state.borrow();
            if protocol == 1
                && packet.get(header.offset).is_some_and(|kind| {
                    *kind < 32 && u32::from_le_bytes(state.icmp_filter) & (1u32 << *kind) != 0
                })
            {
                continue;
            }
            if protocol == 58
                && packet.get(header.offset).is_none_or(|kind| {
                    state.icmp6_filter[*kind as usize / 8] & (1 << (*kind % 8)) != 0
                })
            {
                continue;
            }
            if state.accepts_raw(header.tuple, route.input) {
                if let Some(handle) = state.handles.first() {
                    self.sockets
                        .get_mut::<raw::Socket>(*handle)
                        .enqueue_ip_packet(packet, route.input);
                    delivered = true;
                }
            }
        }
        delivered
    }

    fn grow_accept_queue(&mut self, target: SocketAddr) {
        'listeners: for entry in &self.growing_listeners {
            let Some(listener) = entry.upgrade() else {
                continue;
            };
            let mut state = listener.state.borrow_mut();
            if state.connection != Connection::Listening
                || state.bound.is_none_or(|b| b.port() != target.port())
            {
                continue;
            }
            let endpoint = endpoint(target);
            let mut slots = 0;
            let mut listen_endpoint = endpoint;
            for &handle in &state.handles {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if socket.listens_on_address(endpoint.addr) {
                    listen_endpoint.addr =
                        socket.listen_endpoint().addr.expect("per-address listener");
                    if socket.is_listening() {
                        continue 'listeners;
                    }
                    slots += 1;
                }
            }
            if slots > 0 && slots < state.backlog {
                let mut socket =
                    state.new_tcp_socket(addr(listen_endpoint.addr), listener.mark.get());
                if socket.listen_queued(listen_endpoint, state.backlog).is_ok() {
                    state.add_listener_slot(socket, &mut self.sockets, &mut self.tcp_waiters);
                }
            }
        }
    }
    fn configure_dynamic(&mut self) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let Some(view) = owner.routing.get() else {
            return;
        };
        let revision = view.graph.read().unwrap().revision();
        if self.configuration_revision == revision
            && self.configuration_lo == owner.loopback_up.get()
        {
            return;
        }
        self.dirty = true;
        self.iface.set_any_ip(true);
        self.configuration_revision = revision;
        self.configuration_lo = owner.loopback_up.get();
        let mut addresses = view.addresses(true);
        // The IP-medium ICMPv4 socket uses the interface's primary address.
        // Preserve the real link address before loopback when installing a view.
        addresses.sort_by_key(|a| a.ip.is_loopback());
        let old = self.iface.ip_addrs();
        if old.len() == addresses.len()
            && old
                .iter()
                .zip(&addresses)
                .all(|(old, new)| old.address() == ip(new.ip) && old.prefix_len() == new.prefix)
        {
            return;
        }
        self.iface.update_ip_addrs(|out| {
            out.clear();
            for a in &addresses {
                out.push(IpCidr::new(ip(a.ip), a.prefix))
                    .expect("topology address budget");
            }
        });
        self.iface.routes_mut().remove_default_ipv4_route();
        self.iface.routes_mut().remove_default_ipv6_route();
        // Actual egress selection is performed by the topology. Give smoltcp
        // an on-link next hop for off-link datagrams; this never grants access
        // through an absent guest route or between disconnected bridges.
        if let Some(a) = addresses.iter().find_map(|a| {
            if let IpAddr::V4(a) = a.ip {
                Some(a)
            } else {
                None
            }
        }) {
            self.iface.routes_mut().add_default_ipv4_route(a).unwrap();
        }
        if let Some(a) = addresses.iter().find_map(|a| {
            if let IpAddr::V6(a) = a.ip {
                Some(a)
            } else {
                None
            }
        }) {
            self.iface.routes_mut().add_default_ipv6_route(a).unwrap();
        }
        // Wildcard listeners/bindings must acquire addresses configured after
        // bind(). Keep established TCP handles intact during address changes.
        let all = view.addresses(false);
        let expected: Vec<_> = all.iter().map(|a| a.ip).collect();
        for weak in &self.registry {
            let Some(socket) = weak.upgrade() else {
                continue;
            };
            let mut state = socket.state.borrow_mut();
            let Some(bound) = state.bound.filter(|a| a.ip().is_unspecified()) else {
                continue;
            };
            if socket.kind != 2 && !(socket.kind == 1 && state.connection == Connection::Listening)
            {
                continue;
            }
            let ipv4 = socket.family == 2;
            let dual = socket.family == 10 && !state.v6_only;
            let desired: Vec<_> = expected
                .iter()
                .copied()
                .filter(|a| a.is_ipv4() == ipv4 || dual)
                .collect();
            state.handles.retain(|&h| {
                let endpoint = if socket.kind == 2 {
                    self.sockets.get::<udp::Socket>(h).endpoint().addr
                } else {
                    self.sockets.get::<tcp::Socket>(h).listen_endpoint().addr
                };
                if endpoint.is_some_and(|a| !desired.contains(&addr(a))) {
                    if socket.kind == 1
                        && (self.sockets.get::<tcp::Socket>(h).is_active()
                            || self.sockets.get::<tcp::Socket>(h).accept_ready())
                    {
                        true
                    } else {
                        self.tcp_waiters.remove(&h);
                        self.sockets.remove(h);
                        false
                    }
                } else {
                    true
                }
            });
            for a in &desired {
                let count = state
                    .handles
                    .iter()
                    .filter(|&&h| {
                        if socket.kind == 2 {
                            self.sockets.get::<udp::Socket>(h).endpoint().addr == Some(ip(*a))
                        } else {
                            self.sockets.get::<tcp::Socket>(h).listen_endpoint().addr
                                == Some(ip(*a))
                        }
                    })
                    .count();
                if count == 0 {
                    let ep = SocketAddr::new(*a, bound.port());
                    if socket.kind == 2 {
                        let Ok(u) = state.bound_udp_handle(ep, false) else {
                            continue;
                        };
                        state.handles.push(self.sockets.add(u));
                    } else {
                        let mut t = state.new_tcp_socket(*a, socket.mark.get());
                        if t.listen_queued(endpoint(ep), state.backlog).is_err() {
                            continue;
                        }
                        state.add_listener_slot(t, &mut self.sockets, &mut self.tcp_waiters);
                    }
                }
            }
        }
    }
}
impl NamespaceData {
    fn finish(&self) {
        if self.finished.replace(true) {
            return;
        }
        let mut i = self.fabric.0.borrow_mut();
        let now = i.now();
        if let Some(n) = i.nodes.get_mut(&self.key) {
            for (_, item) in n.sockets.iter_mut() {
                if let smoltcp::socket::Socket::Tcp(t) = item {
                    t.abort();
                }
            }
            n.iface.poll(now, &mut n.port, &mut n.sockets);
        }
        i.tick();
        i.gateway.close_node(self.key);
        i.nodes.remove(&self.key);
        if i.external.is_none() {
            i.ethernet_switch.forget(self.key as u32);
        }
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        self.finish();
    }
}
impl Network {
    pub(super) fn loopback(&self) -> Arc<crate::netdev::Loopback> {
        self.0.loopback_up.clone()
    }
    pub(super) fn fabric(&self) -> Fabric {
        self.0.fabric.clone()
    }
    pub(crate) fn inject(&self, interface: u32, protocol: u16, packet: &[u8]) -> Result<()> {
        if self.0.mode == NetworkMode::Off {
            return Err(NetError(13));
        }
        let view = self.0.routing.get().ok_or(NetError(95))?;
        let mut inner = self.0.fabric.0.borrow_mut();
        if inner.injected.len() >= 96 {
            return Err(NetError(11));
        }
        if packet.len() > 65575 {
            return Err(NetError(90));
        }
        {
            let graph = view.graph.read().unwrap();
            let device = graph
                .device(view.namespace, interface)
                .map_err(|_| NetError(77))?;
            if !device.up {
                return Err(NetError(5));
            }
            let hub = graph.packet_hub(view.namespace);
            if hub.active() {
                let frame = crate::ethernet::Frame::build([0; 6], [0; 6], protocol, packet);
                hub.observe_wire(&device, &frame, false, &mut inner.notifications);
            }
        }
        // Packet sockets tap ingress before IP validates its header or checksum.
        if !matches!(
            (protocol, packet.first().map(|b| b >> 4)),
            (0x0800, Some(4)) | (0x86dd, Some(6))
        ) {
            return Ok(());
        }
        inner.injected.push_back(InjectedPacket {
            node: self.0.key,
            interface,
            kind: PacketType::Host,
            source: [0; 6],
            mark: 0,
            bytes: packet.to_vec(),
        });
        inner.tick();
        Ok(())
    }
    pub(crate) fn attach_routing(&self, view: crate::netdev::View) -> Result<()> {
        if let Some(old) = self.0.routing.get() {
            return if old.namespace == view.namespace && Arc::ptr_eq(&old.graph, &view.graph) {
                Ok(())
            } else {
                Err(NetError(16))
            };
        }
        let settings = view.ip_settings.clone();
        self.0.routing.set(view).map_err(|_| NetError(16))?;
        let mut fabric = self.0.fabric.0.borrow_mut();
        fabric
            .nodes
            .get_mut(&self.0.key)
            .ok_or(NetError(100))?
            .set_ip_settings(&settings);
        Ok(())
    }
    pub(crate) fn inject_frame(
        &self,
        index: u32,
        frame: crate::ethernet::Frame,
        sender: Option<&crate::packet_socket::Receiver>,
    ) -> Result<()> {
        if self.0.mode == NetworkMode::Off || self.0.mode == NetworkMode::Loopback && index != 1 {
            return Err(NetError(13));
        }
        let view = self.0.routing.get().ok_or(NetError(95))?;
        let d = view.graph.read().unwrap().device(view.namespace, index)?;
        if !d.up {
            return Err(NetError(100));
        }
        if !matches!(
            d.kind,
            crate::DeviceKind::Loopback
                | crate::DeviceKind::Veth { .. }
                | crate::DeviceKind::Bridge
                | crate::DeviceKind::Tap
                | crate::DeviceKind::Ethernet
        ) {
            return Err(NetError(95));
        }
        if (d.kind != crate::DeviceKind::Tap || sender.is_some())
            && frame.0.len() > d.mtu as usize + 22
        {
            return Err(NetError(90));
        }
        let mut inner = self.0.fabric.0.borrow_mut();
        if inner.ethernet.len() >= 96 {
            return Err(NetError(11));
        }
        let action = if d.kind == crate::DeviceKind::Loopback {
            let graph = view.graph.read().unwrap();
            graph.packet_hub(view.namespace).observe_wire_except(
                &d,
                &frame,
                true,
                sender,
                &mut inner.notifications,
            );
            graph.account(view.namespace, index, frame.0.len(), true, false);
            crate::ethernet::Action::Receive(view.namespace, index, frame)
        } else if sender.is_some() {
            crate::ethernet::Action::Send(view.namespace, index, frame)
        } else {
            crate::ethernet::Action::Receive(view.namespace, index, frame)
        };
        inner.ethernet.push_back((view.clone(), action));
        inner.tick();
        Ok(())
    }
    pub(super) fn transport_counters(&self) -> Option<(smoltcp::iface::TransportCounters, usize)> {
        let fabric = self.0.fabric.0.borrow();
        let node = fabric.nodes.get(&self.0.key)?;
        let established = node
            .sockets
            .iter()
            .filter(|(_, socket)| {
                matches!(socket, smoltcp::socket::Socket::Tcp(t)
                if matches!(t.state(), tcp::State::Established | tcp::State::CloseWait))
            })
            .count();
        Some((node.iface.transport_counters(), established))
    }

    pub(super) fn port_range(&self) -> [u16; 2] {
        let range = self.0.port_range.get();
        [range as u16, (range >> 16) as u16]
    }
    pub(super) fn set_port_range(&self, low: u16, high: u16) {
        self.0
            .port_range
            .set(u32::from(low) | (u32::from(high) << 16));
    }
    pub(super) fn tcp_sack(&self) -> Result<bool> {
        let fabric = self.0.fabric.0.borrow();
        Ok(fabric
            .nodes
            .get(&self.0.key)
            .ok_or(NetError(100))?
            .iface
            .tcp_sack())
    }
    pub(super) fn set_tcp_sack(&self, enabled: bool) -> Result<()> {
        let mut fabric = self.0.fabric.0.borrow_mut();
        fabric
            .nodes
            .get_mut(&self.0.key)
            .ok_or(NetError(100))?
            .iface
            .set_tcp_sack(enabled);
        Ok(())
    }
    pub(super) fn mode(&self) -> NetworkMode {
        self.0.mode
    }
    pub(super) fn is_isolated(&self) -> bool {
        self.0.isolated.get()
    }
    pub fn links(&self) -> [LinkStats; 2] {
        self.0
            .fabric
            .0
            .borrow()
            .nodes
            .get(&self.0.key)
            .map_or([LinkStats::default(); 2], |n| n.links)
    }
    pub fn info(&self) -> NetworkInfo {
        self.0.info
    }
    pub fn finish(&self) {
        self.0.finish();
    }
    fn reserve(&self) -> Result<Reservation> {
        if self.0.finished.get() {
            Err(NetError(100))
        } else if self.0.mode == NetworkMode::Off {
            Err(NetError(13))
        } else {
            self.0.live.reserve()
        }
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Arc<Socket>> {
        if !matches!(family, 2 | 10) {
            return Err(NetError(97));
        }
        if kind == 4 {
            return Err(NetError(94));
        }
        if kind == 3 && !matches!((family, protocol), (_, 6 | 17 | 255) | (2, 1) | (10, 58)) {
            return Err(NetError(93));
        }
        let kind = if kind == 3 {
            4
        } else if kind == 2 && ((family == 2 && protocol == 1) || (family == 10 && protocol == 58))
        {
            3
        } else {
            kind
        };
        match (kind, protocol) {
            (1, 0 | 6) | (2, 0 | 17) | (3 | 4, 1 | 58) | (4, 6 | 17 | 255) => {}
            (1 | 2, _) => return Err(NetError(93)),
            _ => return Err(NetError(94)),
        };
        let reservation = self.reserve()?;
        let protocol = if protocol != 0 {
            protocol as u8
        } else if kind == 1 {
            6
        } else {
            17
        };
        let socket = self.wrap(
            family,
            kind,
            protocol,
            State {
                handles: Vec::new(),
                connection: Connection::Idle,
                bound: None,
                peer: None,
                error: None,
                connect_result_pending: false,
                read_closed: false,
                write_closed: false,
                v6_only: family == 10 && matches!(kind, 3 | 4),
                reuse: false,
                reuse_port: false,
                listener_rank: 0,
                shared_tcp_binding: false,
                tcp_bind_port: 0,
                udp_bind_order: 0,
                requested_bind: None,
                udp_shared: false,
                udp_readable: None,
                listener_ready: None,
                receive_filter: None,
                udp_errors: matches!(kind, 2..=4).then(|| Arc::new(udp_errors::Errors::default())),
                udp_group: None,
                nodelay: false,
                cork: false,
                max_segment: None,
                quick_ack: true,
                congestion: tcp::CongestionControl::Cubic,
                fin_wait_seconds: 60,
                syn_retries: None,
                defer_accept_secs: 0,
                user_timeout_ms: 0,
                window_clamp: 0,
                linger_enabled: false,
                linger_seconds: 0,
                linger_closing: false,
                receive_inq: false,
                receive_low_water: 1,
                oob_inline: false,
                no_check: false,
                timestamp_option: 0,
                last_packet_ns: None,
                keepalive: false,
                keep_idle: 7200,
                keep_interval: 75,
                keep_count: 9,
                backlog: 1,
                icmp_pending: None,
                hop_limit: 64,
                receive_hops: false,
                ipv4_pmtu: Ipv4Pmtu::default(),
                udp_options: Default::default(),
                last_hop: None,
                broadcast: false,
                multicast: None,
                icmp_filter: [0; 4],
                icmp6_filter: [0; 32],
                raw_ingress: 0,
                header_included: protocol == 255,
                raw_checksum: if protocol == 58 { 2 } else { -1 },
                hop_message: 52,
                device: None,
                raw_identifiers: std::collections::BTreeSet::new(),
                receive_buffer: BUFFER,
                send_buffer: BUFFER,
            },
            reservation,
        );
        if socket.kind == 4 {
            socket.open_raw()?;
        }
        Ok(socket)
    }
    fn wrap(
        &self,
        family: u32,
        kind: u32,
        protocol: u8,
        state: State,
        reservation: Reservation,
    ) -> Arc<Socket> {
        let s = Arc::new(Socket {
            network: self.clone(),
            meta: Arc::new(SocketMeta {
                family,
                kind,
                protocol,
                state: SharedState::new(state),
                mark: Cell::new(0),
                uid: Cell::new(0),
                route_device: Cell::new(0),
                connecting: std::sync::atomic::AtomicBool::new(false),
            }),
            _reservation: reservation,
        });
        if let Some(n) = self.0.fabric.0.borrow_mut().nodes.get_mut(&self.0.key) {
            n.registry.push(Arc::downgrade(&s.meta));
        }
        s
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let mut i = self.network.0.fabric.0.borrow_mut();
        let now = i.now();
        let mut pending_fin = false;
        if let Some(n) = i.nodes.get_mut(&self.network.0.key) {
            n.dirty = true;
            let mut state = self.state.borrow_mut();
            state.release_tcp_bind(&mut n.tcp_binds);
            if state.udp_readable.is_some() {
                n.udp_readers.remove(&state.udp_bind_order);
            }
            if state.connection == Connection::Listening && state.backlog > 1 {
                n.growing_listeners
                    .retain(|weak| weak.as_ptr() != Arc::as_ptr(&self.meta));
            }
            let abort = state.connection == Connection::Listening
                || (state.linger_enabled && state.linger_seconds == 0);
            let fin_wait_seconds = state.fin_wait_seconds;
            let reuse_addr = state.reuse;
            let device = state.device;
            let linger_closing = state.linger_closing;
            for h in state.handles.drain(..) {
                if self.kind == 1 {
                    let s = n.sockets.get_mut::<tcp::Socket>(h);
                    if n.tcp_waiters.remove(&h).is_some() {
                        s.observe_io(None);
                    }
                    if s.is_listening() || s.state() == tcp::State::Closed {
                        n.sockets.remove(h);
                    } else if abort || !linger_closing && s.recv_queue() != 0 {
                        // Linux aborts a stream whose final owner discards unread data.
                        s.abort_with_context(n.iface.context());
                        n.iface.poll(now, &mut n.port, &mut n.sockets);
                        n.sockets.remove(h);
                    } else {
                        s.close_final();
                        pending_fin |= matches!(
                            s.state(),
                            tcp::State::FinWait1 | tcp::State::LastAck | tcp::State::FinWait2
                        );
                        n.detached.push(DetachedTcp::new(
                            h,
                            fin_wait_seconds,
                            Instant::now(),
                            reuse_addr,
                            device,
                        ));
                    }
                } else {
                    n.sockets.remove(h);
                }
            }
        }
        if pending_fin && i.close_batch_until.is_none() {
            // Wake the existing driver on the first close. Further closes in
            // this interval are covered by its deadline, including an idle guest.
            i.close_batch_until = Some(Instant::now() + Duration::from_millis(4));
            i.driver_dirty = true;
        }
    }
}

#[cfg(test)]
mod shared_lifetime_tests {
    use super::*;
    #[test]
    fn host_publication_owns_requested_wildcard_bind_until_teardown() {
        for kind in [1, 2] {
            let fabric = Fabric::new().unwrap();
            fabric
                .publish(
                    "0.0.0.0:0".parse().unwrap(),
                    "10.0.0.2:32123".parse().unwrap(),
                    kind,
                )
                .unwrap();
            let address = fabric
                .native_waiters()
                .into_iter()
                .find_map(|(s, _)| {
                    s.local_addr()
                        .ok()
                        .filter(|a| a.ip().is_unspecified() && a.port() != 0)
                })
                .expect("published host socket");
            if kind == 1 {
                assert!(std::net::TcpListener::bind(address).is_err());
            } else {
                assert!(std::net::UdpSocket::bind(address).is_err());
            }
            fabric.unpublish(address, kind).unwrap();
            if kind == 1 {
                std::net::TcpListener::bind(address).unwrap();
            } else {
                std::net::UdpSocket::bind(address).unwrap();
            }
        }
    }

    #[test]
    fn namespace_nodes_survive_tree_splits_and_removals() {
        let fabric = Fabric::new().unwrap();
        let mut networks: Vec<_> = (2..18)
            .map(|id| fabric.environment(id, NetworkMode::Full).unwrap())
            .collect();
        assert_eq!(fabric.stats().environments, 16);
        networks.retain(|network| network.0.info.id % 2 != 0);
        assert_eq!(fabric.stats().environments, 8);
        for network in &networks {
            let rx = network.socket(2, 2, 0).unwrap();
            let tx = network.socket(2, 2, 0).unwrap();
            let address = "127.0.0.1:34373".parse().unwrap();
            rx.bind(address).unwrap();
            let data = [network.0.info.id];
            assert_eq!(tx.send(&data, 0, Some(address)), Ok(1));
            assert_eq!(rx.recv(1, 0).unwrap().data, data);
        }
        drop(networks);
        assert_eq!(fabric.stats().environments, 0);
    }
    #[test]
    fn abortive_close_reaches_the_virtual_peer() {
        let fabric = Fabric::new().unwrap();
        let network = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = network.socket(2, 1, 0).unwrap();
        let address = "127.0.0.1:34031".parse().unwrap();
        listener.bind(address).unwrap();
        listener.listen(1).unwrap();
        let abort = crate::linger_bytes(Some(Duration::ZERO));
        listener.set_option_bytes(1, 13, &abort).unwrap();
        let client = network.socket(2, 1, 0).unwrap();
        assert_eq!(client.connect(address), Err(NetError(115)));
        for _ in 0..100 {
            if client.connect_complete().unwrap() {
                break;
            }
        }
        let (peer, _) = listener.accept().unwrap();
        assert_eq!(peer.linger(), Ok(abort));
        drop(peer);
        for _ in 0..100 {
            if client.poll(0x19).unwrap() & (8 | 16) != 0 {
                break;
            }
        }
        assert!(client.poll(0x19).unwrap() & (8 | 16) != 0);
    }
    #[test]
    fn unspecified_connect_tcp_info_and_half_close_share_original_transport() {
        let fabric = Fabric::new().unwrap();
        let network = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = network.socket(2, 1, 0).unwrap();
        listener.bind("127.0.0.1:34011".parse().unwrap()).unwrap();
        listener.listen(2).unwrap();
        let client = network.socket(2, 1, 0).unwrap();
        assert_eq!(client.tcp_info().unwrap()[0], 7);
        assert_eq!(
            client.connect("0.0.0.0:34011".parse().unwrap()),
            Err(NetError(115))
        );
        for _ in 0..100 {
            if client.connect_complete().unwrap() {
                break;
            }
        }
        let (peer, _) = listener.accept().unwrap();
        let info = client.tcp_info().unwrap();
        assert_eq!(info[0], 1);
        for offset in [8, 16, 80] {
            assert!(u32::from_le_bytes(info[offset..offset + 4].try_into().unwrap()) > 0);
        }
        assert_eq!(peer.send(b"tail", 0, None), Ok(4));
        peer.shutdown(1).unwrap();
        for _ in 0..100 {
            if client.poll(0x2001).unwrap() & 0x2000 != 0 {
                break;
            }
        }
        assert_eq!(client.poll(0x2001), Ok(0x2001));
        assert_eq!(client.tcp_info().unwrap()[0], 8);
    }
    #[test]
    fn closed_tcp_protocol_states_do_not_exhaust_later_accepts() {
        let fabric = Fabric::new().unwrap();
        let clients = fabric.environment(2, NetworkMode::Full).unwrap();
        let servers = fabric.environment(3, NetworkMode::Full).unwrap();
        let listener = servers.socket(2, 1, 0).unwrap();
        let address = "10.0.0.3:34001".parse().unwrap();
        listener.bind(address).unwrap();
        listener.listen(2).unwrap();
        for sequence in 0u32..384 {
            let client = clients.socket(2, 1, 0).unwrap();
            client
                .bind(SocketAddr::new(v4(2).into(), 35000 + sequence as u16))
                .unwrap();
            assert_eq!(
                client.connect(address),
                Err(NetError(115)),
                "connect {sequence}"
            );
            let mut connected = false;
            for _ in 0..100 {
                if client.connect_complete().unwrap() {
                    connected = true;
                    break;
                }
            }
            assert!(connected, "connect {sequence}");
            let (accepted, _) = listener
                .accept()
                .unwrap_or_else(|e| panic!("accept {sequence}: {e:?}"));
            assert_eq!(client.send(&sequence.to_le_bytes(), 0, None), Ok(4));
            assert_eq!(accepted.recv(4, 0).unwrap().data, sequence.to_le_bytes());
            drop(client);
            drop(accepted);
            fabric.0.borrow_mut().tick();
        }
        assert!(
            fabric.stats().stack_sockets > 256,
            "protocol close states are retained until their actual deadlines"
        );
        assert_eq!(clients.0.live.live(), 0);
        assert_eq!(servers.0.live.live(), 1);
    }

    #[test]
    fn concurrent_short_connections_progress_with_closing_peers() {
        let fabric = Fabric::new().unwrap();
        let clients = fabric.environment(2, NetworkMode::Full).unwrap();
        let servers = fabric.environment(3, NetworkMode::Full).unwrap();
        let listener = servers.socket(2, 1, 0).unwrap();
        let address = "10.0.0.3:34003".parse().unwrap();
        listener.bind(address).unwrap();
        listener.listen(8).unwrap();
        for _ in 0..64 {
            let batch: Vec<_> = (0..8)
                .map(|_| {
                    let socket = clients.socket(2, 1, 0).unwrap();
                    assert_eq!(socket.connect(address), Err(NetError(115)));
                    socket
                })
                .collect();
            for client in &batch {
                let mut connected = false;
                for _ in 0..100 {
                    if client.connect_complete().unwrap() {
                        connected = true;
                        break;
                    }
                }
                assert!(connected);
            }
            for _ in 0..8 {
                let (accepted, peer) = listener.accept().unwrap();
                let client = batch
                    .iter()
                    .find(|c| c.local_addr().unwrap() == peer)
                    .unwrap();
                assert_eq!(client.send(b"short", 0, None), Ok(5));
                let mut received = None;
                for _ in 0..100 {
                    match accepted.recv(5, 0) {
                        Ok(message) => {
                            received = Some(message.data);
                            break;
                        }
                        Err(NetError(11)) => {}
                        Err(error) => panic!("{error:?}"),
                    }
                }
                assert_eq!(received.as_deref(), Some(b"short".as_slice()));
            }
        }
    }

    #[test]
    fn automatic_port_cursor_wraps_skips_live_bindings_and_survives_fd_close() {
        let fabric = Fabric::new().unwrap();
        let network = fabric.environment(2, NetworkMode::Full).unwrap();
        let busy = network.socket(2, 2, 0).unwrap();
        busy.bind("10.0.0.2:49152".parse().unwrap()).unwrap();
        network.0.ephemeral_port.set(65535);
        for expected in [65535, 49153, 49154] {
            let socket = network.socket(2, 2, 0).unwrap();
            socket.bind("10.0.0.2:0".parse().unwrap()).unwrap();
            assert_eq!(socket.local_addr().unwrap().port(), expected);
        }
    }

    #[test]
    fn datagram_size_queries_preserve_empty_records_and_pending_delivery() {
        let fabric = Fabric::new().unwrap();
        let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
        for (family, address) in [(2, "127.0.0.1:34113"), (10, "[::1]:34113")] {
            let socket = net.socket(family, 2, 0).unwrap();
            let address = address.parse().unwrap();
            socket.bind(address).unwrap();
            socket.connect(address).unwrap();
            for payload in [b"".as_slice(), b"12", b"345"] {
                socket.send(payload, 0, None).unwrap();
            }
            socket.shutdown(0).unwrap();
            for length in [0, 2, 3] {
                assert_eq!(socket.readable_bytes(), Ok(Some(length)));
                assert_eq!(socket.recv(1, MSG_PEEK | MSG_TRUNC).unwrap().length, length);
                assert_eq!(socket.readable_bytes(), Ok(Some(length)));
                socket.recv(1, 0).unwrap();
            }
            assert!(matches!(socket.recv(1, MSG_DONTWAIT), Err(NetError(11))));
            assert_eq!(socket.recv(1, 0).unwrap().length, 0);
        }
        let ping = net.socket(2, 2, 1).unwrap();
        assert_eq!(ping.readable_bytes(), Err(NetError(25)));
    }

    #[test]
    fn udp_header_overrides_stay_with_one_datagram_across_peeks() {
        let fabric = Fabric::new().unwrap();
        let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
        for (family, address) in [(2, "127.0.0.1:34113"), (10, "[::1]:34113")] {
            let v6 = family == 10;
            let level = if v6 { 41 } else { 0 };
            let socket = net.socket(family, 2, 0).unwrap();
            let address = address.parse().unwrap();
            socket.bind(address).unwrap();
            socket.connect(address).unwrap();
            socket
                .set_option(level, if v6 { 51 } else { 12 }, 1)
                .unwrap();
            socket
                .set_option(level, if v6 { 66 } else { 13 }, 1)
                .unwrap();
            socket
                .set_option(level, if v6 { 16 } else { 2 }, 32)
                .unwrap();
            socket
                .set_option(level, if v6 { 67 } else { 1 }, 0x23)
                .unwrap();
            let defaults = crate::IpFields {
                hop_limit: Some(32),
                traffic_class: Some(0x23),
            };
            let once = crate::IpFields {
                hop_limit: Some(if v6 { 0 } else { 1 }),
                traffic_class: Some(0xc3),
            };
            let mut control = crate::DatagramControl::default();
            control.fields[usize::from(v6)] = once;
            socket.send(b"a", 0, None).unwrap();
            socket.send_datagram(b"b", 0, None, control).unwrap();
            socket.send(b"c", 0, None).unwrap();
            for (byte, fields) in [(b'a', defaults), (b'b', once), (b'c', defaults)] {
                for flags in [MSG_PEEK, 0] {
                    let record = socket.recv(4, flags).unwrap();
                    assert_eq!(record.data, [byte]);
                    assert_eq!(record.ip.fields, fields);
                    assert_eq!(record.ip.ipv6, v6);
                }
            }
        }
    }

    #[test]
    fn udp_disconnect_retains_queued_records_and_releases_only_automatic_ports() {
        let fabric = Fabric::new().unwrap();
        let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
        for (family, addr, level, orig) in
            [(2, "127.0.0.1:34117", 0, 20), (10, "[::1]:34117", 41, 74)]
        {
            let server = net.socket(family, 2, 0).unwrap();
            let address: SocketAddr = addr.parse().unwrap();
            server.bind(address).unwrap();
            let client = net.socket(family, 2, 0).unwrap();
            client.connect(address).unwrap();
            client.set_option(level, orig, 1).unwrap();
            let previous = client.local_addr().unwrap();
            server.send(b"queued", 0, Some(previous)).unwrap();

            client.connect_bytes(&[0, 0]).unwrap();
            assert_eq!(client.peer_addr(), Err(NetError(107)));
            assert_eq!(client.local_addr().unwrap().port(), 0);
            assert_eq!(client.readable_bytes().unwrap(), Some(6));
            let replacement = net.socket(family, 2, 0).unwrap();
            replacement.bind(previous).unwrap();
            server.send(b"new owner", 0, Some(previous)).unwrap();
            assert_eq!(
                replacement.recv(32, MSG_DONTWAIT).unwrap().data,
                b"new owner"
            );

            client.connect(address).unwrap();
            let current = client.local_addr().unwrap();
            assert_ne!(previous.port(), current.port());
            server.send(b"new", 0, Some(current)).unwrap();
            for (bytes, dst) in [
                (b"queued".as_slice(), previous),
                (b"new".as_slice(), current),
            ] {
                for flag in [MSG_PEEK, 0] {
                    let packet = client.recv(32, flag | MSG_DONTWAIT).unwrap();
                    assert_eq!(packet.data, bytes);
                    assert_eq!(packet.ip.original_destination, Some(dst));
                }
            }
            let bound = net.socket(family, 2, 0).unwrap();
            let mut specific = address;
            specific.set_port(0);
            bound.bind(specific).unwrap();
            bound.connect(address).unwrap();
            bound.connect_bytes(&[0, 0]).unwrap();
            assert_eq!(bound.local_addr().unwrap(), specific);
            bound.connect(address).unwrap();
            assert_eq!(bound.local_addr().unwrap().ip(), specific.ip());
        }
    }

    #[test]
    fn udp_timestamp_stays_with_the_packet_across_peeks_and_option_changes() {
        let fabric = Fabric::new().unwrap();
        let net = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
        let socket = net.socket(2, 2, 0).unwrap();
        let address = "127.0.0.1:34114".parse().unwrap();
        socket.bind(address).unwrap();
        socket.connect(address).unwrap();
        assert_eq!(socket.last_packet_ns(), Err(NetError(2)));
        socket.send(b"first", 0, None).unwrap();
        assert!(socket.recv(8, 0).unwrap().ip.timestamp.is_none());
        let first = socket.last_packet_ns().unwrap();
        assert_ne!(first, 0);
        socket.send(b"second", 0, None).unwrap();
        let mut previous = None;
        for (kind, flags) in [(35, MSG_PEEK), (63, MSG_PEEK), (64, 0)] {
            socket.set_option(1, kind, 1).unwrap();
            let (returned_kind, ns) = socket.recv(8, flags).unwrap().ip.timestamp.unwrap();
            assert_eq!(returned_kind, kind);
            assert_ne!(ns, 0);
            assert_eq!(previous.replace(ns).unwrap_or(ns), ns);
            assert_eq!(socket.last_packet_ns(), Ok(first));
        }
    }

    #[test]
    fn udp_counters_follow_the_receiving_namespace_and_ignore_peeks() {
        let fabric = Fabric::new().unwrap();
        let clients = fabric.environment(2, NetworkMode::Full).unwrap();
        let servers = fabric.environment(3, NetworkMode::Full).unwrap();
        let tx = clients.socket(2, 2, 0).unwrap();
        let rx = servers.socket(2, 2, 0).unwrap();
        let endpoint = "10.0.0.3:34112".parse().unwrap();
        rx.bind(endpoint).unwrap();
        tx.send(b"sample", 0, Some(endpoint)).unwrap();
        assert_eq!(rx.recv(1, MSG_PEEK).unwrap().data, b"s");
        let sent = clients.transport_counters().unwrap().0;
        let pending = servers.transport_counters().unwrap().0;
        assert_eq!((sent.udp_out, sent.udp_in), (1, 0));
        assert_eq!((pending.udp_out, pending.udp_in), (0, 0));
        assert_eq!(rx.recv(1, 0).unwrap().data, b"s");
        assert_eq!(servers.transport_counters().unwrap().0.udp_in, 1);
        drop(rx);
        tx.send(b"dropped", 0, Some(endpoint)).unwrap();
        fabric.tick();
        assert_eq!(servers.transport_counters().unwrap().0.udp_no_ports, 1);
        assert_eq!(clients.transport_counters().unwrap().0.udp_no_ports, 0);
    }

    #[test]
    fn sack_negotiation_survives_later_namespace_changes() {
        for (active, passive) in [(false, false), (false, true), (true, false), (true, true)] {
            let fabric = Fabric::new().unwrap();
            let clients = fabric.environment(2, NetworkMode::Full).unwrap();
            let servers = fabric.environment(3, NetworkMode::Full).unwrap();
            let listener = servers.socket(2, 1, 0).unwrap();
            let address = "10.0.0.3:34012".parse().unwrap();
            listener.bind(address).unwrap();
            listener.listen(1).unwrap();
            clients.set_tcp_sack(active).unwrap();
            servers.set_tcp_sack(passive).unwrap();
            let client = clients.socket(2, 1, 0).unwrap();
            assert_eq!(client.connect(address), Err(NetError(115)));
            assert!((0..100).any(|_| client.connect_complete().unwrap()));
            let (accepted, _) = listener.accept().unwrap();
            clients.set_tcp_sack(!active).unwrap();
            servers.set_tcp_sack(!passive).unwrap();
            for end in [&client, &accepted] {
                assert_eq!(end.tcp_info().unwrap()[5] & 2 != 0, active && passive);
            }
        }
    }

    #[test]
    fn shared_udp_binding_delivers_once_and_prefers_the_connected_peer() {
        let fabric = Fabric::new().unwrap();
        let clients = fabric.environment(2, NetworkMode::Full).unwrap();
        let servers = fabric.environment(3, NetworkMode::Full).unwrap();
        let destination = "10.0.0.3:41012".parse().unwrap();
        let source = "10.0.0.2:41011".parse().unwrap();
        let sender = clients.socket(2, 2, 0).unwrap();
        sender.bind(source).unwrap();
        let first = servers.socket(2, 2, 0).unwrap();
        let last = servers.socket(2, 2, 0).unwrap();
        for sock in [&first, &last] {
            sock.set_option(1, 2, 1).unwrap();
            sock.bind(destination).unwrap();
        }
        assert_eq!(sender.send(b"a", 0, Some(destination)), Ok(1));
        assert_eq!(last.recv(1, 0).unwrap().data, b"a");
        assert!(matches!(first.recv(1, 0), Err(NetError(11))));
        first.connect(source).unwrap();
        assert_eq!(sender.send(b"b", 0, Some(destination)), Ok(1));
        assert_eq!(first.recv(1, 0).unwrap().data, b"b");
        let other = clients.socket(2, 2, 0).unwrap();
        assert_eq!(other.send(b"c", 0, Some(destination)), Ok(1));
        assert_eq!(last.recv(1, 0).unwrap().data, b"c");
        drop(last);
        assert_eq!(sender.send(b"d", 0, Some(destination)), Ok(1));
        assert_eq!(first.recv(1, 0).unwrap().data, b"d");
    }

    #[test]
    fn failed_neighbor_probe_matches_only_the_original_syn() {
        for (local, remote) in [
            ("10.0.0.2:41002", "10.0.0.3:0"),
            ("[fd00::2]:41002", "[fd00::3]:0"),
        ] {
            let fabric = Fabric::new().unwrap();
            let network = fabric.environment(2, NetworkMode::Full).unwrap();
            let mut inner = fabric.0.borrow_mut();
            let now = inner.now();
            let node = inner.nodes.get_mut(&network.0.key).unwrap();
            let (local, remote) = (
                endpoint(local.parse().unwrap()),
                endpoint(remote.parse().unwrap()),
            );
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 1024]),
                tcp::SocketBuffer::new(vec![0; 1024]),
            );
            socket.connect(node.iface.context(), remote, local).unwrap();
            let handle = node.sockets.add(socket);
            node.iface.poll(now, &mut node.port, &mut node.sockets);
            let syn = node
                .port
                .tx
                .iter()
                .find_map(|(p, _, _)| {
                    let h = packet::header(p)?;
                    if h.protocol != 6 {
                        return None;
                    }
                    let tcp = smoltcp::wire::TcpPacket::new_checked(&p[h.offset..]).ok()?;
                    tcp.syn().then_some(tcp.seq_number())
                })
                .unwrap();
            let tcp = node.sockets.get_mut::<tcp::Socket>(handle);
            let cx = node.iface.context();
            assert!(!tcp.fail_unresolved_syn(cx, local, remote, syn + 1));
            assert!(!tcp.fail_unresolved_syn(cx, remote, local, syn));
            assert_eq!(tcp.state(), tcp::State::SynSent);
            assert!(tcp.fail_unresolved_syn(cx, local, remote, syn));
            assert_eq!(tcp.take_failure(), Some(tcp::Failure::HostUnreachable));
            assert!(!tcp.fail_unresolved_syn(cx, local, remote, syn));
        }
    }

    #[test]
    fn tcp_mixed_bind_bucket_tracks_owner_listener_and_last_close() {
        for (family, local) in [(2, "127.0.0.1:42017"), (10, "[::1]:42017")] {
            let fabric = Fabric::new().unwrap();
            let net = fabric.environment(2, NetworkMode::Full).unwrap();
            let address = local.parse().unwrap();
            let socket = |uid, addr, port| {
                let s = net.socket(family, 1, 0).unwrap();
                s.set_owner_uid(uid);
                s.set_option(1, 2, addr).unwrap();
                s.set_option(1, 15, port).unwrap();
                s
            };
            let first = socket(1000, 1, 0);
            first.bind(address).unwrap();
            let mixed = socket(1000, 1, 1);
            mixed.bind(address).unwrap();
            drop(mixed);
            let outsider = socket(1001, 0, 1);
            assert_eq!(outsider.bind(address), Err(NetError(98)));
            let same = socket(1000, 0, 1);
            same.bind(address).unwrap();
            first.listen(1).unwrap();
            assert_eq!(same.listen(1), Err(NetError(98)));
            assert_eq!(socket(1000, 0, 1).bind(address), Err(NetError(98)));
            drop(first);
            drop(same);
            outsider.bind(address).unwrap();
            assert_eq!(socket(1000, 0, 1).bind(address), Err(NetError(98)));
        }
    }

    #[test]
    fn reuseport_enforces_guest_owner_and_keeps_each_flow_on_one_receiver() {
        struct Reader;
        impl trames_shared::IoWake for Reader {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
        }
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Reader);
        let waiter = Arc::downgrade(&target);
        for (family, target) in [(2, "10.0.0.3:41017"), (10, "[fd00::3]:41017")] {
            let fabric = Fabric::new().unwrap();
            let clients = fabric.environment(2, NetworkMode::Full).unwrap();
            let servers = fabric.environment(3, NetworkMode::Full).unwrap();
            let destination = target.parse().unwrap();
            let mut group = Vec::new();
            let mut readers = Vec::new();
            for idx in 0..3 {
                let socket = servers.socket(family, 2, 0).unwrap();
                socket.set_owner_uid(1000);
                socket.set_option(1, 15, 1).unwrap();
                let signal = trames_shared::IoSignal::new(idx, waiter.clone());
                let subscription = if idx == 0 {
                    let sub = socket.subscribe_udp_readable(&signal).unwrap();
                    socket.bind(destination).unwrap();
                    sub
                } else {
                    socket.bind(destination).unwrap();
                    socket.subscribe_udp_readable(&signal).unwrap()
                };
                group.push(socket);
                readers.push((signal, subscription));
            }
            let outsider = servers.socket(family, 2, 0).unwrap();
            outsider.set_owner_uid(1001);
            outsider.set_option(1, 15, 1).unwrap();
            assert_eq!(outsider.bind(destination), Err(NetError(98)));
            let mut hits = [0; 3];
            for _ in 0..64 {
                let sender = clients.socket(family, 2, 0).unwrap();
                for data in [b"a", b"b"] {
                    sender.send(data, 0, Some(destination)).unwrap();
                }
                let mut owners = 0;
                for (idx, receiver) in group.iter().enumerate() {
                    match receiver.recv(1, 0) {
                        Ok(packet) => {
                            assert!(readers[idx].0.ready());
                            readers[idx].0.reset();
                            assert_eq!(packet.data, b"a");
                            assert_eq!(receiver.recv(1, 0).unwrap().data, b"b");
                            hits[idx] += 1;
                            owners += 1;
                        }
                        Err(NetError(11)) => assert!(!readers[idx].0.ready()),
                        Err(err) => panic!("{err:?}"),
                    }
                }
                assert_eq!(owners, 1);
            }
            assert!(hits.iter().all(|n| *n > 0), "{hits:?}");
            assert_eq!(group[0].shutdown(0), Err(NetError(107)));
            assert!(readers[0].0.ready());
        }
    }

    #[test]
    fn ephemeral_range_and_privileged_floor_are_namespace_local() {
        let fabric = Fabric::new().unwrap();
        let first = crate::Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
        let second = crate::Network::virtual_network(&fabric, 3, NetworkMode::Full).unwrap();
        first.set_local_port_range(65534, 65535).unwrap();
        assert_eq!(first.local_port_range(), [65534, 65535]);
        assert_eq!(second.local_port_range(), [49152, 65535]);
        assert_eq!(first.set_unprivileged_port(65535), Err(NetError(22)));
        first.set_unprivileged_port(65534).unwrap();
        assert_eq!(first.set_local_port_range(65533, 65535), Err(NetError(22)));
        assert_eq!(first.local_port_range(), [65534, 65535]);
    }

    fn tcp_io_waiter() -> (Arc<dyn trames_shared::IoWake>, Arc<trames_shared::IoSignal>) {
        struct Reader;
        impl trames_shared::IoWake for Reader {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
        }
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Reader);
        let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&target));
        (target, signal)
    }

    #[test]
    fn growing_listener_retains_reset_child_until_accepted() {
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = net.socket(2, 1, 0).unwrap();
        let addr = "127.0.0.1:34037".parse().unwrap();
        listener.bind(addr).unwrap();
        listener.listen(512).unwrap();
        assert_eq!(listener.state.borrow().handles.len(), 1);
        let connect = || {
            let client = net.socket(2, 1, 0).unwrap();
            assert_eq!(client.connect(addr), Err(NetError(115)));
            assert_eq!(client.resume_connect(), Ok(true));
            client
        };
        let mut clients = (0..12).map(|_| connect()).collect::<Vec<_>>();
        assert_eq!(listener.state.borrow().handles.len(), clients.len() + 1);
        let reset = clients.pop().unwrap();
        let reset_peer = reset.local_addr().unwrap();
        reset
            .set_option_bytes(1, 13, &crate::linger_bytes(Some(Duration::ZERO)))
            .unwrap();
        drop(reset);
        clients.push(connect());
        // One reset child, all live children, and one spare listening slot.
        assert_eq!(listener.state.borrow().handles.len(), clients.len() + 2);
        let mut errors = Vec::new();
        for _ in 0..=clients.len() {
            let (child, peer) = listener.accept().unwrap();
            if child.get_option(1, 4).unwrap() == 104 {
                assert_eq!(child.get_option(1, 4), Ok(0));
                assert_eq!(child.peer_addr(), Err(NetError(107)));
                errors.push(peer);
            } else {
                assert_eq!(child.peer_addr(), Ok(peer));
            }
        }
        assert_eq!(errors, [reset_peer]);
        assert_eq!(listener.state.borrow().handles.len(), 1);
    }

    #[test]
    fn observed_tcp_reader_wakes_for_data_and_peer_shutdown() {
        let (_target, signal) = tcp_io_waiter();
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = net.socket(2, 1, 0).unwrap();
        let addr = "127.0.0.1:34033".parse().unwrap();
        listener.bind(addr).unwrap();
        listener.listen(1).unwrap();
        let client = net.socket(2, 1, 0).unwrap();
        assert_eq!(client.connect(addr), Err(NetError(115)));
        assert!(client.connect_complete().unwrap());
        let (peer, _) = listener.accept().unwrap();
        let _subscription = peer.subscribe_tcp_ready(&signal).unwrap();
        assert!(!signal.ready());
        client.send(b"x", 0, None).unwrap();
        assert!(signal.ready());
        client.set_option(6, 1, 1).unwrap();
        peer.set_option(1, 18, 6).unwrap();
        assert_eq!(peer.poll(1).unwrap(), 0);
        assert_eq!(peer.recv(4, MSG_PEEK | 0x100).unwrap().data, b"x");
        signal.reset();
        client.send(b"yz", 0, None).unwrap();
        assert!(!signal.ready());
        client.send(b"4", 0, None).unwrap();
        assert!(signal.ready());
        assert_eq!(peer.poll(1).unwrap(), 0);
        signal.reset();
        client.send(b"56", 0, None).unwrap();
        assert!(signal.ready());
        assert_eq!(peer.poll(1).unwrap(), 1);
        assert_eq!(peer.recv(6, 0).unwrap().data, b"xyz456");
        signal.reset();
        client.shutdown(1).unwrap();
        assert!(signal.ready());
        assert_eq!(peer.recv(1, 0).unwrap().length, 0);
    }

    #[test]
    fn forced_udp_buffers_admit_more_than_the_regular_maximum_and_shrink_losslessly() {
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let rx = net.socket(2, 2, 0).unwrap();
        let tx = net.socket(2, 2, 0).unwrap();
        let addr = "127.0.0.1:34371".parse().unwrap();
        rx.set_option(1, 33, i32::MAX).unwrap();
        rx.bind(addr).unwrap();
        tx.set_option(1, 32, i32::MAX).unwrap();
        assert_eq!(tx.get_option(1, 7), Ok(i32::MAX - 1));
        let mut data = [0x51; 1024];
        for id in 0..384u32 {
            data[..4].copy_from_slice(&id.to_le_bytes());
            assert_eq!(tx.send(&data, 0, Some(addr)), Ok(data.len()));
        }
        rx.set_option(1, 8, 4096).unwrap();
        assert_eq!(rx.get_option(1, 8), Ok(8192));
        for id in 0..384u32 {
            data[..4].copy_from_slice(&id.to_le_bytes());
            assert_eq!(rx.recv(1024, 0).unwrap().data, data);
        }
    }

    #[test]
    fn forced_tcp_budgets_follow_the_listener_and_grow_with_live_data() {
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = net.socket(2, 1, 0).unwrap();
        listener.set_option(1, 33, i32::MAX).unwrap();
        let addr = "127.0.0.1:34372".parse().unwrap();
        listener.bind(addr).unwrap();
        listener.listen(8).unwrap();
        let client = net.socket(2, 1, 0).unwrap();
        client.set_option(1, 32, i32::MAX).unwrap();
        assert_eq!(client.connect(addr), Err(NetError(115)));
        assert!(client.connect_complete().unwrap());
        let (peer, _) = listener.accept().unwrap();
        assert_eq!(peer.get_option(1, 8), Ok(i32::MAX - 1));
        assert_eq!(client.get_option(1, 7), Ok(i32::MAX - 1));
        let capacity = |socket: &Socket, receive| {
            let guard = fabric.0.borrow();
            let handle = socket.state.borrow().handles[0];
            let tcp = guard.nodes[&net.0.key].sockets.get::<tcp::Socket>(handle);
            if receive {
                tcp.recv_capacity()
            } else {
                tcp.send_capacity()
            }
        };
        assert_eq!(capacity(&peer, true), BUFFER);
        assert_eq!(capacity(&client, false), BUFFER);
        let data: Vec<u8> = (0..(2 * MAX_BUFFER)).map(|i| (i % 251) as u8).collect();
        assert_eq!(client.send(&data, 0, None), Ok(data.len()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while peer.tcp_readable_bytes().unwrap() < data.len() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(capacity(&peer, true) >= data.len());
        assert_eq!(capacity(&client, false), data.len());
        peer.set_option(1, 33, -1).unwrap();
        assert_eq!(peer.get_option(1, 8), Ok(2304));
        assert_eq!(peer.recv(data.len(), 0).unwrap().data, data);
    }

    #[test]
    fn raising_the_send_budget_wakes_a_blocked_stream_writer() {
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = net.socket(2, 1, 0).unwrap();
        let addr = "127.0.0.1:34373".parse().unwrap();
        listener.bind(addr).unwrap();
        listener.listen(1).unwrap();
        let client = net.socket(2, 1, 0).unwrap();
        assert_eq!(client.connect(addr), Err(NetError(115)));
        assert!(client.connect_complete().unwrap());
        let (_peer, _) = listener.accept().unwrap();
        let data = vec![23; BUFFER];
        let deadline = Instant::now() + Duration::from_secs(5);
        while client.send(&data, 0, None).is_ok() {
            assert!(Instant::now() < deadline);
        }
        let (_target, signal) = tcp_io_waiter();
        let _sub = client.subscribe_tcp_ready(&signal).unwrap();
        assert!(!signal.ready());
        client.set_option(1, 32, 2 * MAX_BUFFER as i32).unwrap();
        assert!(signal.ready());
        assert_eq!(client.send(&data, 0, None), Ok(BUFFER));
    }

    #[test]
    fn draining_full_tcp_receive_window_releases_already_queued_sender_data() {
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = net.socket(2, 1, 0).unwrap();
        let addr = "127.0.0.1:34032".parse().unwrap();
        listener.bind(addr).unwrap();
        listener.listen(1).unwrap();
        let client = net.socket(2, 1, 0).unwrap();
        assert_eq!(client.connect(addr), Err(NetError(115)));
        assert!(client.connect_complete().unwrap());
        let (peer, _) = listener.accept().unwrap();
        client.set_option(6, 1, 1).unwrap();
        assert_eq!(client.send(&vec![0x25; BUFFER], 0, None), Ok(BUFFER));
        let end = Instant::now() + Duration::from_secs(3);
        while peer.tcp_readable_bytes().unwrap() < BUFFER {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(client.send(b"tail", 0, None), Ok(4));
        assert_eq!(peer.recv(BUFFER, MSG_TRUNC).unwrap().length, BUFFER);
        // Inspect the queue before another guest send/receive or fabric tick.
        let handle = peer.state.borrow().handles[0];
        let inner = fabric.0.borrow();
        let socket = inner.nodes[&net.0.key].sockets.get::<tcp::Socket>(handle);
        assert_eq!(socket.recv_queue(), 4);

        drop(inner);
        let payload = vec![0x42; BUFFER];
        while peer.tcp_readable_bytes().unwrap() < BUFFER {
            let _ = client.send(&payload, 0, None);
            assert!(Instant::now() < end);
        }
        loop {
            match client.send(&payload, 0, None) {
                Ok(_) => assert!(Instant::now() < end),
                Err(NetError(11)) => break,
                other => panic!("unexpected send result {other:?}"),
            }
        }
        let (_target, signal) = tcp_io_waiter();
        let _subscription = client.subscribe_tcp_ready(&signal).unwrap();
        assert!(!signal.ready());
        assert_eq!(peer.recv(BUFFER, MSG_TRUNC).unwrap().length, BUFFER);
        while !signal.ready() {
            fabric.tick();
            assert!(Instant::now() < end);
            std::thread::yield_now();
        }
        assert_eq!(client.send(b"x", 0, None), Ok(1));
    }

    #[test]
    fn tcp_urgent_byte_survives_wire_and_preserves_read_boundaries() {
        for addr in ["127.0.0.1:34285", "[::1]:34285"] {
            for inline in [false, true] {
                let fabric = Fabric::new().unwrap();
                let net = fabric.environment(2, NetworkMode::Full).unwrap();
                let addr: SocketAddr = addr.parse().unwrap();
                let family = if addr.is_ipv4() { 2 } else { 10 };
                let listener = net.socket(family, 1, 0).unwrap();
                listener.set_option(1, 10, i32::from(inline)).unwrap();
                listener.bind(addr).unwrap();
                listener.listen(1).unwrap();
                let client = net.socket(family, 1, 0).unwrap();
                assert_eq!(client.connect(addr), Err(NetError(115)));
                let (peer, _) = listener.accept().unwrap();
                assert_eq!(peer.get_option(1, 10), Ok(i32::from(inline)));
                client.set_option(6, 1, 1).unwrap();
                client.send(b"ab", MSG_OOB, None).unwrap();
                client.send(b"cd!", MSG_OOB, None).unwrap();
                client.send(b"tail", 0, None).unwrap();
                assert_eq!(peer.poll(2).unwrap(), 2);
                assert_eq!(peer.recv(64, MSG_PEEK).unwrap().data, b"abcd");
                assert_eq!(peer.tcp_readable_bytes(), Ok(4));
                assert_eq!(peer.recv(64, 0).unwrap().data, b"abcd");
                assert!(peer.at_mark().unwrap());
                if inline {
                    assert!(matches!(peer.recv(1, MSG_OOB), Err(NetError(22))));
                    assert_eq!(peer.recv(1, 0).unwrap().data, b"!");
                } else {
                    assert_eq!(peer.recv(1, MSG_OOB | MSG_PEEK).unwrap().data, b"!");
                    assert_eq!(peer.recv(1, MSG_OOB).unwrap().data, b"!");
                    assert_eq!(peer.poll(2).unwrap(), 0);
                    assert!(matches!(peer.recv(1, MSG_OOB), Err(NetError(22))));
                }
                assert_eq!(peer.recv(8, MSG_PEEK).unwrap().data, b"tail");
                assert_eq!(peer.recv(8, 0).unwrap().data, b"tail");
                assert!(!peer.at_mark().unwrap());
                assert_eq!(peer.poll(2).unwrap(), 0);
            }
        }
    }

    #[test]
    fn tcp_inq_includes_peer_fin_and_preserves_zero_length_and_peek_reads() {
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = net.socket(2, 1, 0).unwrap();
        let addr = "127.0.0.1:34284".parse().unwrap();
        listener.set_option(6, 36, 1).unwrap();
        listener.bind(addr).unwrap();
        listener.listen(1).unwrap();
        let client = net.socket(2, 1, 0).unwrap();
        assert_eq!(client.connect(addr), Err(NetError(115)));
        let (peer, _) = listener.accept().unwrap();
        client.send(b"tail", 0, None).unwrap();
        client.shutdown(1).unwrap();
        fabric.tick();
        assert_eq!(peer.recv(0, 0).unwrap().ip.tcp_inq, Some(5));
        assert_eq!(peer.recv(2, MSG_PEEK).unwrap().ip.tcp_inq, Some(5));
        assert_eq!(peer.recv(4, 0).unwrap().ip.tcp_inq, Some(1));
        assert_eq!(peer.recv(1, 0).unwrap().ip.tcp_inq, Some(1));
    }

    #[test]
    fn inherited_delivery_deadline_wakes_and_reports_the_error_once() {
        let fabric = Fabric::new().unwrap();
        let net = fabric.environment(2, NetworkMode::Full).unwrap();
        let listener = net.socket(2, 1, 0).unwrap();
        let addr = "127.0.0.1:34037".parse().unwrap();
        listener.bind(addr).unwrap();
        listener.listen(1).unwrap();
        listener.set_option(6, 18, 200).unwrap();
        let client = net.socket(2, 1, 0).unwrap();
        assert_eq!(client.connect(addr), Err(NetError(115)));
        let (peer, _) = listener.accept().unwrap();
        assert_eq!(peer.get_option(6, 18), Ok(200));
        fabric.0.borrow_mut().started -= Duration::from_secs(2);
        assert_eq!(peer.get_option(1, 4), Ok(0));
        fabric.set_link_faults(1, 0);
        assert_eq!(peer.send(b"data", 0, None), Ok(4));
        let (_target, signal) = tcp_io_waiter();
        let _subscription = peer.subscribe_tcp_ready(&signal).unwrap();
        fabric.0.borrow_mut().started -= Duration::from_millis(201);
        fabric.tick();
        assert!(signal.ready());
        assert_ne!(peer.poll(1).unwrap() & 8, 0);
        assert_eq!(peer.get_option(1, 4), Ok(110));
        assert_eq!(peer.get_option(1, 4), Ok(0));
        assert_eq!(peer.poll(1).unwrap() & 8, 0);
    }

    #[test]
    fn accepted_transport_inherits_congestion_and_expires_only_after_last_close() {
        for seconds in [-1, 17] {
            let fabric = Fabric::new().unwrap();
            let network = fabric.environment(2, NetworkMode::Full).unwrap();
            let listener = network.socket(2, 1, 0).unwrap();
            let address = "127.0.0.1:35012".parse().unwrap();
            listener.set_option_bytes(6, 13, b"reno").unwrap();
            listener.set_option(6, 8, seconds).unwrap();
            listener.bind(address).unwrap();
            listener.listen(1).unwrap();
            let client = network.socket(2, 1, 0).unwrap();
            assert_eq!(client.connect(address), Err(NetError(115)));
            for _ in 0..100 {
                if client.connect_complete().unwrap() {
                    break;
                }
            }
            let (peer, _) = listener.accept().unwrap();
            let handle = peer.state.borrow().handles[0];
            {
                let inner = fabric.0.borrow();
                let tcp = inner.nodes[&network.0.key]
                    .sockets
                    .get::<tcp::Socket>(handle);
                assert_eq!(tcp.congestion_control(), tcp::CongestionControl::Reno);
                assert_eq!(tcp.timeout(), None);
            }
            peer.set_option_bytes(6, 13, b"cubic").unwrap();
            assert_eq!(peer.get_option(6, 8), Ok(seconds));
            peer.shutdown(1).unwrap();
            fabric.tick();
            assert_eq!(peer.tcp_info().unwrap()[0], 5);
            assert_eq!(client.send(b"still open", 0, None), Ok(10));
            assert_eq!(peer.recv(10, 0).unwrap().data, b"still open");
            drop(peer);
            fabric.tick();
            if seconds > 0 {
                let mut inner = fabric.0.borrow_mut();
                let node = inner.nodes.get_mut(&network.0.key).unwrap();
                let orphan = node
                    .detached
                    .iter_mut()
                    .find(|e| e.handle == handle)
                    .unwrap();
                assert!(orphan.in_fin_wait2);
                assert!(
                    orphan.deadline.saturating_duration_since(Instant::now())
                        > Duration::from_secs(15)
                );
                orphan.deadline = Instant::now();
            }
            fabric.tick();
            assert!(fabric.0.borrow().nodes[&network.0.key].detached.is_empty());
            assert_ne!(client.poll(0x18).unwrap() & 0x18, 0);
        }
    }

    #[test]
    fn active_opens_share_only_distinct_tuples_and_recycle_quiet_loopback() {
        for (family, local) in [(2, "127.0.0.1"), (10, "::1")] {
            let fabric = Fabric::new().unwrap();
            let net = fabric.environment(2, NetworkMode::Full).unwrap();
            net.set_port_range(38000, 38000);
            let local: IpAddr = local.parse().unwrap();
            let listen = |port| {
                let socket = net.socket(family, 1, 0).unwrap();
                socket.bind(SocketAddr::new(local, port)).unwrap();
                socket.listen(2).unwrap();
                socket
            };
            let first = listen(34041);
            let second = listen(34042);
            let client = || net.socket(family, 1, 0).unwrap();
            let a = client();
            let b = client();
            let dst = first.local_addr().unwrap();
            assert_eq!(a.connect(dst), Err(NetError(115)));
            assert_eq!(b.connect(second.local_addr().unwrap()), Err(NetError(115)));
            assert_eq!(a.local_addr().unwrap(), b.local_addr().unwrap());
            let (a_peer, _) = first.accept().unwrap();
            let (b_peer, _) = second.accept().unwrap();
            assert_ne!(a.tcp_info().unwrap()[5] & 1, 0);
            let retry = client();
            assert_eq!(retry.connect(dst), Err(NetError(99)));
            assert_eq!(retry.local_addr().unwrap().port(), 0);
            let bind = client();
            assert_eq!(bind.bind(SocketAddr::new(local, 0)), Err(NetError(98)));

            a.shutdown(2).unwrap();
            a_peer.shutdown(2).unwrap();
            drop(a);
            drop(a_peer);
            fabric.tick();
            assert_eq!(retry.connect(dst), Err(NetError(99)));
            fabric.0.borrow_mut().started -= Duration::from_millis(1100);
            assert_eq!(retry.connect(dst), Err(NetError(115)));
            let (new_peer, _) = first.accept().unwrap();
            retry.send(b"new", 0, None).unwrap();
            b.send(b"other", 0, None).unwrap();
            assert_eq!(new_peer.recv(8, 0).unwrap().data, b"new");
            assert_eq!(b_peer.recv(8, 0).unwrap().data, b"other");
        }
    }

    #[test]
    fn closing_tcp_ports_remain_bound_until_protocol_retirement() {
        for (family, address, local) in [
            (2, "10.0.0.3:34002", "10.0.0.2:35000"),
            (10, "[fd00::3]:34002", "[fd00::2]:35000"),
        ] {
            let fabric = Fabric::new().unwrap();
            let clients = fabric.environment(2, NetworkMode::Full).unwrap();
            let servers = fabric.environment(3, NetworkMode::Full).unwrap();
            let listener = servers.socket(family, 1, 0).unwrap();
            listener.bind(address.parse().unwrap()).unwrap();
            listener.listen(1).unwrap();
            let client = clients.socket(family, 1, 0).unwrap();
            client.bind(local.parse().unwrap()).unwrap();
            assert_eq!(client.connect(address.parse().unwrap()), Err(NetError(115)));
            for _ in 0..100 {
                if client.connect_complete().unwrap() {
                    break;
                }
            }
            let (accepted, _) = listener.accept().unwrap();
            drop(client);
            drop(accepted);
            fabric.tick();
            let next = clients.socket(family, 1, 0).unwrap();
            assert_eq!(next.bind(local.parse().unwrap()), Err(NetError(98)));
            // Expiring the original protocol lease, rather than another FD's
            // close, makes this port available again. No wall-clock sleep.
            {
                let mut inner = fabric.0.borrow_mut();
                let node = inner.nodes.get_mut(&clients.0.key).unwrap();
                assert!(!node.detached.is_empty());
                for entry in &mut node.detached {
                    entry.deadline = Instant::now();
                }
            }
            fabric.tick();
            next.bind(local.parse().unwrap()).unwrap();
        }
    }

    #[test]
    fn packet_observers_never_own_socket_or_namespace_close_callbacks() {
        let fabric = Fabric::new().unwrap();
        let network = fabric.environment(2, NetworkMode::Outbound).unwrap();
        let original_handles = fabric.stats().stack_sockets;
        let socket = network.socket(2, 2, 0).unwrap();
        let socket_observer = socket.meta.clone();
        let namespace_observer = network.0.data.clone();
        socket.bind("10.0.0.2:34000".parse().unwrap()).unwrap();
        drop(socket);
        assert_eq!(fabric.stats().stack_sockets, original_handles);
        drop(network);
        assert_eq!(fabric.stats().environments, 0);
        // These are the last references. Neither destructor may reenter fabric.
        let _fabric = fabric.0.borrow_mut();
        drop(socket_observer);
        drop(namespace_observer);
    }
}

#[cfg(test)]
mod work_tests {
    use super::*;
    #[test]
    fn empty_reads_and_buffered_udp_do_not_poll_unrelated_protocol_resources() {
        let fabric = Fabric::new().unwrap();
        let a = crate::Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
        let b = crate::Network::virtual_network(&fabric, 3, NetworkMode::Outbound).unwrap();
        let _other = crate::Network::virtual_network(&fabric, 4, NetworkMode::Outbound).unwrap();
        let tx = a.socket(2, 2, 0).unwrap();
        tx.bind("10.0.0.2:34801".parse().unwrap()).unwrap();
        let rx = b.socket(2, 2, 0).unwrap();
        rx.bind("10.0.0.3:34800".parse().unwrap()).unwrap();
        assert_eq!(rx.recv(100, 0).err(), Some(NetError(11)));
        let counts = || {
            fabric
                .0
                .borrow()
                .nodes
                .iter()
                .map(|(&k, n)| (k, n.polls))
                .collect::<Vec<_>>()
        };
        let idle = counts();
        for _ in 0..64 {
            assert_eq!(rx.recv(100, 0).err(), Some(NetError(11)));
        }
        assert_eq!(counts(), idle, "empty reader repolled an idle fabric");
        tx.send(b"ready", 0, Some("10.0.0.3:34800".parse().unwrap()))
            .unwrap();
        let queued = counts();
        assert_eq!(rx.recv(100, 0).unwrap().data, b"ready");
        assert_eq!(
            counts(),
            queued,
            "buffered UDP read advanced unrelated resources"
        );
        let other = fabric
            .0
            .borrow()
            .nodes
            .iter()
            .find(|(_, n)| n.id == 4)
            .map(|(&k, _)| k)
            .unwrap();
        assert_eq!(
            idle.iter().find(|v| v.0 == other),
            queued.iter().find(|v| v.0 == other)
        );
    }
}
