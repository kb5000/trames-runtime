// SPDX-License-Identifier: GPL-3.0-or-later
//! A bounded IP fabric. Only the trusted gateway opens native sockets.
use crate::dns;
use crate::shared_state::FabricState;
use crate::shared_state::{Cell, State as SharedState};
use crate::socket_quota::{Quota, Reservation};
use std::ops::Deref;
mod ethernet;
mod wire;
pub use wire::WireWait;
mod gateway;
pub(crate) mod packet;
mod sockets;
use super::native::{
    self, NetError, NetworkMode, Received, MAX_BUFFER, MAX_TRANSFER, MSG_DONTWAIT, MSG_NOSIGNAL,
    MSG_PEEK, MSG_TRUNC,
};
use packet::{Port, Tuple};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{icmp, raw, tcp, udp},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint},
};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Weak},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, NetError>;
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
struct Inner {
    drivers: Vec<Weak<trames_shared::Readiness>>,
    driver_dirty: bool,
    driver_maintenance: bool,
    notifications: Vec<Arc<trames_shared::Readiness>>,
    injected: VecDeque<(u64, u32, [u8; 6], Vec<u8>)>,
    ethernet: VecDeque<(crate::netdev::View, crate::ethernet::Action)>,
    ethernet_switch: crate::ethernet::Switch,
    started: Instant,
    next_node: u64,
    nodes: BTreeMap<u64, Node>,
    gateway: gateway::Gateway,
    stats: NetworkStats,
    drop_every: u32,
    corrupt_every: u32,
    external: Option<wire::Wire>,
    revision: u64,
}
struct Node {
    udp_bind_order: u64,
    id: u8,
    owner: Weak<NamespaceData>,
    iface: Interface,
    sockets: SocketSet<'static>,
    port: Port,
    filter_rx: Port,
    gateway_rx: Port,
    registry: Vec<Weak<SocketMeta>>,
    detached: Vec<(SocketHandle, Instant)>,
    resets: Vec<(Weak<SocketMeta>, Connection)>,
    links: [LinkStats; 2],
    configuration_revision: u64,
    dirty: bool,
    next_poll: Option<smoltcp::time::Instant>,
    #[cfg(test)]
    polls: u64,
    configuration_lo: bool,
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
    abort_on_close: bool,
    keepalive: bool,
    keep_idle: u32,
    keep_interval: u32,
    keep_count: u32,
    backlog: usize,
    icmp_pending: Option<(Vec<u8>, IpAddr)>,
    hop_limit: u8,
    receive_hops: bool,
    receive_packet_info: bool,
    last_hop: Option<u8>,
    broadcast: bool,
    icmp6_filter: [u8; 32],
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
    kind: u32,
    state: SharedState<State>,
    mark: Cell<u32>,
    uid: Cell<u32>,
    route_device: Cell<u32>,
    connecting: std::sync::atomic::AtomicBool,
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
fn packet_slots(bytes: usize) -> usize {
    (bytes / 64).max(1)
}
fn udp_socket() -> udp::Socket<'static> {
    udp_socket_with_buffers(BUFFER, BUFFER)
}
fn udp_socket_with_buffers(receive: usize, send: usize) -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; packet_slots(receive)],
            vec![0; receive],
        ),
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; packet_slots(send)],
            vec![0; send],
        ),
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
        udp_bind_order: 0,
        id,
        owner: Weak::new(),
        iface,
        sockets: SocketSet::new(Vec::new()),
        port,
        filter_rx: Port::default(),
        gateway_rx: Port::default(),
        registry: Vec::new(),
        detached: Vec::new(),
        resets: Vec::new(),
        links: [LinkStats::default(); 2],
        configuration_revision: u64::MAX,
        dirty: true,
        next_poll: None,
        #[cfg(test)]
        polls: 0,
        configuration_lo: false,
    })
}
impl Fabric {
    pub fn new() -> Result<Self> {
        Ok(Self(Arc::new(FabricState::new(Inner {
            drivers: Vec::new(),
            driver_dirty: false,
            driver_maintenance: false,
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
        for view in inner
            .nodes
            .values()
            .filter_map(|n| n.owner.upgrade())
            .filter_map(|o| o.routing.get().cloned())
        {
            let graph = view.graph.read().unwrap();
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
                live: Arc::new(Quota::default()),
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
                live: Arc::new(Quota::default()),
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
        self.receive_external();
        self.pump_ethernet();
        // Bound work per scheduler slice even when a peer produces data continuously.
        for _ in 0..32 {
            self.pump_ethernet();
            self.gateway.service(now, &self.nodes);
            let mut packets: Vec<_> = self
                .injected
                .drain(..)
                .map(|(key, index, peer, p)| (key, Some(index), peer, p))
                .collect();
            for (&key, node) in &mut self.nodes {
                if node.dirty
                    || !node.port.rx.is_empty()
                    || node.next_poll.is_some_and(|d| d <= now)
                {
                    node.dirty = false;
                    node.iface.poll(now, &mut node.port, &mut node.sockets);
                    node.next_poll = node.iface.poll_at(now, &node.sockets);
                    #[cfg(test)]
                    {
                        node.polls += 1;
                    }
                }
                while let Some(p) = node.port.tx.pop_front() {
                    packets.push((key, None, [0; 6], p));
                }
            }
            self.gateway.node.iface.poll(
                now,
                &mut self.gateway.node.port,
                &mut self.gateway.node.sockets,
            );
            while let Some(p) = self.gateway.node.port.tx.pop_front() {
                packets.push((0, None, [0; 6], p));
            }
            if packets.is_empty() {
                break;
            }
            for (source, injected, peer, mut p) in packets {
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
                let Some(_h) = packet::header(&p) else {
                    self.stats.dropped += 1;
                    if let Some(n) = self.nodes.get_mut(&source) {
                        n.links[usize::from(!lo)].tx_dropped += 1;
                    }
                    continue;
                };
                if source == 0 {
                    let rx = &mut self.gateway.node.filter_rx;
                    if !rx.receive_packet(p) {
                        self.stats.dropped += 1;
                        continue;
                    }
                    let Some(complete) = rx.rx.pop_front() else {
                        continue;
                    };
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
                        if !rx.receive_packet(p) {
                            self.stats.dropped += 1;
                            continue;
                        }
                        let Some(complete) = rx.rx.pop_front() else {
                            continue;
                        };
                        p = complete;
                    }
                    if !packet::valid_transport(&p) {
                        self.stats.dropped += 1;
                        continue;
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
                            if d.kind == crate::DeviceKind::Tun {
                                view.graph.read().unwrap().observe(
                                    view.namespace,
                                    index,
                                    peer,
                                    &p,
                                    false,
                                    &mut self.notifications,
                                );
                            }
                        }
                    }

                    let step =
                        view.graph
                            .read()
                            .unwrap()
                            .route_one(view.namespace, incoming, &mut p);
                    let Some((route, next_hop)) = step else {
                        self.stats.dropped += 1;
                        continue;
                    };
                    delivery = Some(route);
                    if let Some(next_hop) = next_hop.filter(|_| !route.tunnel && !route.external) {
                        let actions = view.graph.read().unwrap().ethernet_ip(
                            view.namespace,
                            route.output,
                            next_hop,
                            p,
                        );
                        self.queue_frames(view, actions);
                        continue;
                    }
                    if route.input == 1 {
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
                        let delivered = graph
                            .tunnel(route.namespace, route.input)
                            .is_some_and(|port| port.enqueue(&p, &mut self.notifications));
                        graph.account(route.namespace, route.input, p.len(), true, !delivered);
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
                                                .push((Arc::downgrade(&socket), state.connection));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    let enabled = node.owner.upgrade().is_some_and(|ns| {
                        ns.mode != NetworkMode::Off
                            && (!lo || ns.loopback_up.get())
                            && (source == key
                                || matches!(ns.mode, NetworkMode::Outbound | NetworkMode::Full))
                    });
                    let size = p.len() as u64;
                    let dropped = !permitted || !enabled || !node.port.receive_packet(p);
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
                } else if source != 0
                    && dynamic.is_none()
                    && private_ip(dst)
                    && dst != IpAddr::V4(v4(1))
                    && dst != IpAddr::V6(v6(1))
                {
                    // Guest-owned links always use Ethernet; no legacy raw-IP wire.
                    self.stats.dropped += 1;
                } else if source != 0
                    && dynamic.is_none()
                    && (dst == IpAddr::V4(v4(1))
                        || dst == IpAddr::V6(v6(1))
                        || self.external.as_ref().is_none_or(|e| e.nat))
                    && (!private_ip(dst) || dst == IpAddr::V4(v4(1)) || dst == IpAddr::V6(v6(1)))
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
                    if !socket.connecting.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
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
                    self.sockets
                        .get::<tcp::Socket>(h)
                        .local_endpoint()
                        .map(|e| e.addr)
                };
                if endpoint.is_some_and(|a| !desired.contains(&addr(a))) {
                    if socket.kind == 1 && self.sockets.get::<tcp::Socket>(h).is_active() {
                        true
                    } else {
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
                            self.sockets
                                .get::<tcp::Socket>(h)
                                .local_endpoint()
                                .is_some_and(|e| e.addr == ip(*a))
                        }
                    })
                    .count();
                let needed = if socket.kind == 2 { 1 } else { state.backlog };
                for _ in count..needed {
                    let ep = SocketAddr::new(*a, bound.port());
                    let handle = if socket.kind == 2 {
                        let mut u =
                            udp_socket_with_buffers(state.receive_buffer, state.send_buffer);
                        u.set_hop_limit(Some(state.hop_limit));
                        if u.bind(endpoint(ep)).is_err() {
                            break;
                        }
                        self.sockets.add(u)
                    } else {
                        let mut t = tcp_socket();
                        t.set_hop_limit(Some(state.hop_limit));
                        if t.listen(endpoint(ep)).is_err() {
                            break;
                        }
                        self.sockets.add(t)
                    };
                    state.handles.push(handle);
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
    pub(super) fn fabric(&self) -> Fabric {
        self.0.fabric.clone()
    }
    pub(crate) fn inject(&self, interface: u32, packet: &[u8]) -> Result<()> {
        if self.0.mode == NetworkMode::Off {
            return Err(NetError(13));
        }
        if packet.len() > 65535 || packet::header(packet).is_none() {
            return Err(NetError(22));
        }
        let mut inner = self.0.fabric.0.borrow_mut();
        if inner.injected.len() >= 96 {
            return Err(NetError(11));
        }
        inner
            .injected
            .push_back((self.0.key, interface, [0; 6], packet.to_vec()));
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
        self.0.routing.set(view).map_err(|_| NetError(16))
    }
    pub(crate) fn inject_frame(
        &self,
        index: u32,
        frame: crate::ethernet::Frame,
        outgoing: bool,
    ) -> Result<()> {
        if matches!(self.0.mode, NetworkMode::Off | NetworkMode::Loopback) {
            return Err(NetError(13));
        }
        let view = self.0.routing.get().ok_or(NetError(95))?;
        let d = view.graph.read().unwrap().device(view.namespace, index)?;
        if !d.up {
            return Err(NetError(100));
        }
        if !matches!(
            d.kind,
            crate::DeviceKind::Veth { .. }
                | crate::DeviceKind::Bridge
                | crate::DeviceKind::Tap
                | crate::DeviceKind::Ethernet
        ) {
            return Err(NetError(95));
        }
        if frame.0.len() > d.mtu as usize + 22 {
            return Err(NetError(90));
        }
        let mut inner = self.0.fabric.0.borrow_mut();
        if inner.ethernet.len() >= 96 {
            return Err(NetError(11));
        }
        let action = if outgoing {
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
        let reservation = self.reserve()?;
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
                v6_only: family == 10 && matches!(kind, 3 | 4),
                reuse: false,
                nodelay: false,
                abort_on_close: false,
                keepalive: false,
                keep_idle: 7200,
                keep_interval: 75,
                keep_count: 9,
                backlog: 1,
                icmp_pending: None,
                hop_limit: 64,
                receive_hops: false,
                receive_packet_info: false,
                last_hop: None,
                broadcast: false,
                icmp6_filter: [0; 32],
                hop_message: 52,
                device: None,
                raw_identifiers: std::collections::BTreeSet::new(),
                receive_buffer: BUFFER,
                send_buffer: BUFFER,
            },
            reservation,
        ))
    }
    fn wrap(&self, family: u32, kind: u32, state: State, reservation: Reservation) -> Arc<Socket> {
        let s = Arc::new(Socket {
            network: self.clone(),
            meta: Arc::new(SocketMeta {
                family,
                kind,
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
        if let Some(n) = i.nodes.get_mut(&self.network.0.key) {
            n.dirty = true;
            let mut state = self.state.borrow_mut();
            let abort = state.abort_on_close;
            for h in state.handles.drain(..) {
                if self.kind == 1 {
                    let s = n.sockets.get_mut::<tcp::Socket>(h);
                    if s.is_listening() || s.state() == tcp::State::Closed {
                        n.sockets.remove(h);
                    } else if abort || s.recv_queue() != 0 {
                        // Linux aborts a stream whose final owner discards unread data.
                        s.abort_with_context(n.iface.context());
                        n.iface.poll(now, &mut n.port, &mut n.sockets);
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

#[cfg(test)]
mod shared_lifetime_tests {
    use super::*;
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
                for (_, deadline) in &mut node.detached {
                    *deadline = Instant::now();
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
