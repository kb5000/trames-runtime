// SPDX-License-Identifier: GPL-3.0-or-later
//! A bounded IP fabric. Only the trusted gateway opens native sockets.
mod dns;
mod gateway;
mod packet;
mod sockets;
use super::native::{
    self, NetError, NetworkMode, Received, MAX_BUFFER, MAX_SOCKETS, MAX_TRANSFER, MSG_DONTWAIT,
    MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC,
};
use packet::{Port, Tuple};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{icmp, raw, tcp, udp},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint},
};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::{Rc, Weak},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, NetError>;
const BUFFER: usize = 65536;
const MAX_HANDLES: usize = 256;
const MAX_ENVIRONMENTS: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkInfo {
    pub id: u8,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub gateway4: Ipv4Addr,
    pub gateway6: Ipv6Addr,
    pub mtu: u32,
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
pub struct Fabric(Rc<RefCell<Inner>>);
struct Inner {
    started: Instant,
    next_node: u64,
    nodes: BTreeMap<u64, Node>,
    gateway: gateway::Gateway,
    stats: NetworkStats,
    drop_every: u32,
    corrupt_every: u32,
}
struct Node {
    id: u8,
    owner: Weak<Namespace>,
    iface: Interface,
    sockets: SocketSet<'static>,
    port: Port,
    registry: Vec<Weak<Socket>>,
    detached: Vec<(SocketHandle, Instant)>,
    resets: Vec<(Weak<Socket>, Connection)>,
    links: [LinkStats; 2],
}
struct Namespace {
    fabric: Fabric,
    key: u64,
    info: NetworkInfo,
    mode: NetworkMode,
    live: Cell<usize>,
    finished: Cell<bool>,
}
#[derive(Clone)]
pub(super) struct Network(Rc<Namespace>);
#[derive(Clone, Copy, PartialEq, Eq)]
enum Connection {
    Idle,
    Connecting,
    Connected,
    Listening,
    Failed(u32),
}
struct State {
    handles: Vec<SocketHandle>,
    connection: Connection,
    bound: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    error: Option<u32>,
    blocking_failed: bool,
    read_closed: bool,
    write_closed: bool,
    v6_only: bool,
    reuse: bool,
    nodelay: bool,
    keepalive: bool,
    keep_idle: u32,
    keep_interval: u32,
    keep_count: u32,
    backlog: usize,
    icmp_pending: Option<(Vec<u8>, IpAddr)>,
    hop_limit: u8,
    receive_hops: bool,
    last_hop: Option<u8>,
    broadcast: bool,
    icmp6_filter: [u8; 32],
    hop_message: u32,
    device: Option<u32>,
    raw_identifiers: std::collections::BTreeSet<u16>,
}
pub(super) struct Socket {
    network: Network,
    family: u32,
    kind: u32,
    state: RefCell<State>,
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
    let mut s = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER]),
        tcp::SocketBuffer::new(vec![0; BUFFER]),
    );
    s.set_ack_delay(Some(smoltcp::time::Duration::from_millis(10)));
    s.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    s
}
fn udp_socket() -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUFFER]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; BUFFER]),
    )
}
fn make_node(id: u8, now: smoltcp::time::Instant) -> Result<Node> {
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
    Ok(Node {
        id,
        owner: Weak::new(),
        iface,
        sockets: SocketSet::new(Vec::new()),
        port,
        registry: Vec::new(),
        detached: Vec::new(),
        resets: Vec::new(),
        links: [LinkStats::default(); 2],
    })
}
impl Fabric {
    pub fn new() -> Result<Self> {
        Ok(Self(Rc::new(RefCell::new(Inner {
            started: Instant::now(),
            next_node: 1,
            nodes: BTreeMap::new(),
            gateway: gateway::Gateway::new()?,
            stats: NetworkStats::default(),
            drop_every: 0,
            corrupt_every: 0,
        }))))
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
        Rc::ptr_eq(&self.0, &other.0)
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
        };
        let mut node = make_node(id, i.now())?;
        let ns = Rc::new(Namespace {
            fabric: self.clone(),
            key,
            info,
            mode,
            live: Cell::new(0),
            finished: Cell::new(false),
        });
        node.owner = Rc::downgrade(&ns);
        i.nodes.insert(key, node);
        Ok(Network(ns))
    }
    pub(super) fn tick(&self) {
        self.0.borrow_mut().tick();
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
    pub(super) fn native_waiters(&self) -> Vec<(Rc<native::Socket>, u16)> {
        self.0.borrow().gateway.waiters()
    }
}
fn private_ip(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => a.octets()[..3] == [10, 0, 0],
        IpAddr::V6(a) => a.segments()[..4] == [0xfd00, 0, 0, 0],
    }
}
impl Inner {
    fn now(&self) -> smoltcp::time::Instant {
        smoltcp::time::Instant::from_millis(
            self.started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        )
    }
    fn handles(&self) -> usize {
        self.nodes
            .values()
            .map(|n| n.sockets.iter().count())
            .sum::<usize>()
            + self.gateway.node.sockets.iter().count()
            + self.gateway.pending_handles()
    }
    fn reserve(&self, n: usize) -> Result<()> {
        if self.handles() + n > MAX_HANDLES {
            Err(NetError(105))
        } else {
            Ok(())
        }
    }
    fn tick(&mut self) {
        let now = self.now();
        let time = Instant::now();
        for node in self.nodes.values_mut() {
            node.registry.retain(|s| s.strong_count() != 0);
            for (_, socket) in node.sockets.iter_mut() {
                if let smoltcp::socket::Socket::Tcp(t) = socket {
                    if matches!(t.state(), tcp::State::Established | tcp::State::CloseWait) {
                        t.set_timeout(None);
                    }
                }
            }
            let gone: Vec<_> = node
                .detached
                .iter()
                .filter(|(h, end)| {
                    *end <= time
                        || node.sockets.get::<tcp::Socket>(*h).state() == tcp::State::Closed
                })
                .map(|(h, _)| *h)
                .collect();
            node.detached.retain(|(h, _)| !gone.contains(h));
            for h in gone {
                node.sockets.remove(h);
            }
        }
        // Bound work per scheduler slice even when a peer produces data continuously.
        for _ in 0..32 {
            self.gateway.service(now, &self.nodes);
            let mut packets = Vec::new();
            for (&key, node) in &mut self.nodes {
                node.iface.poll(now, &mut node.port, &mut node.sockets);
                while let Some(p) = node.port.tx.pop_front() {
                    packets.push((key, p));
                }
            }
            self.gateway.node.iface.poll(
                now,
                &mut self.gateway.node.port,
                &mut self.gateway.node.sockets,
            );
            while let Some(p) = self.gateway.node.port.tx.pop_front() {
                packets.push((0, p));
            }
            if packets.is_empty() {
                break;
            }
            for (source, mut p) in packets {
                let lo = packet::header(&p).is_some_and(|h| h.tuple.destination.ip().is_loopback());
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
                let Some(h) = packet::header(&p) else {
                    self.stats.dropped += 1;
                    if let Some(n) = self.nodes.get_mut(&source) {
                        n.links[usize::from(!lo)].tx_dropped += 1;
                    }
                    continue;
                };
                let dst = h.tuple.destination.ip();
                let target = if dst.is_loopback() {
                    if source == 0 {
                        None
                    } else {
                        Some(source)
                    }
                } else {
                    self.nodes
                        .iter()
                        .find(|(_, n)| dst == IpAddr::V4(v4(n.id)) || dst == IpAddr::V6(v6(n.id)))
                        .map(|(&key, _)| key)
                };
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
                    if h.protocol == 6 && h.first {
                        if let Ok(t) = smoltcp::wire::TcpPacket::new_checked(&p[h.offset..]) {
                            if t.rst() && t.verify_checksum(&ip(h.tuple.source.ip()), &ip(dst)) {
                                for socket in node.registry.iter().filter_map(Weak::upgrade) {
                                    if socket.kind == 1 {
                                        let state = socket.state.borrow();
                                        if state.peer == Some(h.tuple.source)
                                            && state.bound == Some(h.tuple.destination)
                                            && state.handles.first().is_some_and(|h| {
                                                matches!(
                                                    node.sockets.get::<tcp::Socket>(*h).state(),
                                                    tcp::State::SynSent
                                                        | tcp::State::SynReceived
                                                        | tcp::State::Established
                                                        | tcp::State::FinWait1
                                                        | tcp::State::FinWait2
                                                        | tcp::State::CloseWait
                                                )
                                            })
                                            && node.resets.len() < 96
                                        {
                                            node.resets
                                                .push((Rc::downgrade(&socket), state.connection));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let enabled = node.owner.upgrade().is_some_and(|ns| {
                        ns.mode != NetworkMode::Off
                            && (source == key
                                || matches!(ns.mode, NetworkMode::Outbound | NetworkMode::Full))
                    });
                    let size = p.len() as u64;
                    if !permitted || !enabled || !node.port.receive_packet(p) {
                        node.links[usize::from(!lo)].rx_dropped += 1;
                        self.stats.dropped += 1;
                    } else {
                        let s = &mut node.links[usize::from(!lo)];
                        s.rx_packets += 1;
                        s.rx_bytes += size;
                    }
                } else if source != 0
                    && (!private_ip(dst) || dst == IpAddr::V4(v4(1)) || dst == IpAddr::V6(v6(1)))
                {
                    if !self.gateway.ingress(
                        source,
                        p,
                        &h,
                        &self.nodes,
                        now,
                        self.handles() < MAX_HANDLES,
                    ) {
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
            for (weak, connection) in node.resets.drain(..) {
                if let Some(socket) = weak.upgrade() {
                    let mut state = socket.state.borrow_mut();
                    if state.handles.first().is_some_and(|h| {
                        node.sockets.get::<tcp::Socket>(*h).state() == tcp::State::Closed
                    }) {
                        state.error = Some(if connection == Connection::Connecting {
                            111
                        } else {
                            104
                        });
                    }
                }
            }
            for weak in &node.registry {
                if let Some(socket) = weak.upgrade() {
                    let mut state = socket.state.borrow_mut();
                    if state.connection == Connection::Connecting {
                        if let Some(&h) = state.handles.first() {
                            match node.sockets.get::<tcp::Socket>(h).state() {
                                tcp::State::Established => state.connection = Connection::Connected,
                                tcp::State::Closed => {
                                    let e = state.error.unwrap_or(110);
                                    state.error = Some(e);
                                    state.connection = Connection::Failed(e);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
}
impl Namespace {
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
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        self.finish();
    }
}
impl Network {
    pub fn links(&self) -> [LinkStats; 2] {
        self.0
            .fabric
            .0
            .borrow()
            .nodes
            .get(&self.0.key)
            .map_or([LinkStats::default(); 2], |n| n.links)
    }
    pub fn live_sockets(&self) -> usize {
        self.0.live.get()
    }
    pub fn info(&self) -> NetworkInfo {
        self.0.info
    }
    pub fn finish(&self) {
        self.0.finish();
    }
    fn reserve(&self) -> Result<()> {
        if self.0.finished.get() {
            Err(NetError(100))
        } else if self.0.mode == NetworkMode::Off {
            Err(NetError(13))
        } else if self.live_sockets() >= MAX_SOCKETS {
            Err(NetError(24))
        } else {
            Ok(())
        }
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Rc<Socket>> {
        if !matches!(family, 2 | 10) {
            return Err(NetError(97));
        }
        if kind == 3 && !((family == 2 && protocol == 1) || (family == 10 && protocol == 58)) {
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
            (1, 0 | 6) | (2, 0 | 17) | (3 | 4, 1 | 58) => {}
            (1 | 2, _) => return Err(NetError(93)),
            _ => return Err(NetError(94)),
        };
        self.reserve()?;
        Ok(self.wrap(
            family,
            kind,
            State {
                handles: Vec::new(),
                connection: Connection::Idle,
                bound: None,
                peer: None,
                error: None,
                blocking_failed: false,
                read_closed: false,
                write_closed: false,
                v6_only: family == 10,
                reuse: false,
                nodelay: false,
                keepalive: false,
                keep_idle: 7200,
                keep_interval: 75,
                keep_count: 9,
                backlog: 1,
                icmp_pending: None,
                hop_limit: 64,
                receive_hops: false,
                last_hop: None,
                broadcast: false,
                icmp6_filter: [0; 32],
                hop_message: 52,
                device: None,
                raw_identifiers: std::collections::BTreeSet::new(),
            },
        ))
    }
    fn wrap(&self, family: u32, kind: u32, state: State) -> Rc<Socket> {
        self.0.live.set(self.live_sockets() + 1);
        let s = Rc::new(Socket {
            network: self.clone(),
            family,
            kind,
            state: RefCell::new(state),
        });
        if let Some(n) = self.0.fabric.0.borrow_mut().nodes.get_mut(&self.0.key) {
            n.registry.push(Rc::downgrade(&s));
        }
        s
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.network.0.live.set(self.network.live_sockets() - 1);
        let mut i = self.network.0.fabric.0.borrow_mut();
        if let Some(n) = i.nodes.get_mut(&self.network.0.key) {
            for h in self.state.get_mut().handles.drain(..) {
                if self.kind == 1 {
                    let s = n.sockets.get_mut::<tcp::Socket>(h);
                    if s.is_listening() || s.state() == tcp::State::Closed {
                        n.sockets.remove(h);
                    } else {
                        s.close();
                        n.detached
                            .push((h, Instant::now() + Duration::from_secs(30)));
                    }
                } else {
                    n.sockets.remove(h);
                }
            }
        }
    }
}
