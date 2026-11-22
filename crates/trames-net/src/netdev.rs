// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared guest-owned topology, with namespace-local rules and connection state.
//! Veth/bridge connectivity is explicit; a shared fabric is never all-to-all.
use crate::{LinkStats, NetError, NetworkInfo};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc, Mutex, RwLock,
    },
};
/// The same loopback flag is shared by topology and its packet-stack view.
/// This metadata does not publish packet/guest bytes.
pub(crate) struct Loopback(AtomicBool);
impl Loopback {
    pub fn new(up: bool) -> Self {
        Self(AtomicBool::new(up))
    }
    pub fn get(&self) -> bool {
        self.0.load(Relaxed)
    }
    pub fn set(&self, up: bool) {
        self.0.store(up, Relaxed);
    }
}
type Result<T> = std::result::Result<T, NetError>;
/// An unchanged host interface is a read query. Recheck changed metadata under
/// the writer before publication, without locking topology during host queries.
pub(crate) fn refresh_native(
    graph: &RwLock<Topology>,
    id: u64,
    enabled: bool,
    info: Option<NetworkInfo>,
) {
    if graph.read().unwrap().direct_current(id, enabled, info) {
        return;
    }
    graph.write().unwrap().refresh_direct(id, enabled, info);
}
#[path = "netdev_router.rs"]
mod router;
pub(crate) use router::NativeForward;
#[path = "netdev_ipv6.rs"]
mod ipv6;
#[path = "netdev_policy.rs"]
mod policy;
pub(crate) use policy::{Context as RouteContext, Entry as PolicyRoute, Rule};
const MAX_LINKS: usize = 256;
// Each veth additionally has one link-local address slot on its interface.
const MAX_ADDRESSES: usize = 8;
const MAX_ROUTES: usize = 64;
#[path = "ethernet_neighbor.rs"]
mod ethernet_neighbor;
#[path = "ethernet_switch.rs"]
mod ethernet_switch;
#[path = "neighbors.rs"]
mod neighbors;
#[path = "netdev_packet.rs"]
mod packet;
pub(crate) use ethernet_neighbor::ethernet_gateway;
#[path = "ethernet_control.rs"]
mod ethernet_control;
pub(crate) use neighbors::Entry as NeighborEntry;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Loopback,
    Direct,
    Veth { peer: u32 },
    Bridge,
    Tun,
    Tap,
    Ethernet,
}
impl DeviceKind {
    pub(crate) fn hardware_type(self) -> u16 {
        match self {
            Self::Loopback => 772,
            Self::Direct | Self::Tun => 65534,
            _ => 1,
        }
    }
    pub(crate) fn link_kind(self) -> Option<&'static std::ffi::CStr> {
        match self {
            Self::Bridge => Some(c"bridge"),
            Self::Veth { .. } => Some(c"veth"),
            Self::Tun | Self::Tap => Some(c"tun"),
            _ => None,
        }
    }
}
/// Linux per-interface IPv4 ingress controls for packets arriving from a guest link.
#[derive(Clone, Copy)]
pub enum Ipv4Ingress {
    AcceptLocal = 1,
    RouteLocalnet = 2,
}
#[derive(Clone, Debug)]
pub struct Device {
    pub index: u32,
    pub name: Vec<u8>,
    pub namespace: u64,
    pub kind: DeviceKind,
    pub up: bool,
    pub mtu: u32,
    /// Linux netdev queue metadata; noqueue devices still use bounded transport buffers.
    pub tx_queue_len: u32,
    pub mac: [u8; 6],
    pub master: Option<u32>,
    pub addresses: Vec<Address>,
    pub stats: LinkStats,
}
impl Device {
    pub(crate) fn same_link_configuration(&self, other: &Self) -> bool {
        self.namespace == other.namespace
            && self.name == other.name
            && self.up == other.up
            && self.mtu == other.mtu
            && self.tx_queue_len == other.tx_queue_len
            && self.mac == other.mac
            && self.master == other.master
    }
}
// Stored links share only their actual counters. The public Device remains an
// owned reporting snapshot, with no second mutable counter authority.
#[derive(Default)]
struct Counters([AtomicU64; 6]);
impl Counters {
    fn snapshot(&self) -> LinkStats {
        let values = self.0.each_ref().map(|n| n.load(Relaxed));
        LinkStats {
            rx_bytes: values[0],
            rx_packets: values[1],
            rx_dropped: values[2],
            tx_bytes: values[3],
            tx_packets: values[4],
            tx_dropped: values[5],
        }
    }
    fn account(&self, len: usize, tx: bool, dropped: bool) {
        let at = if tx { 3 } else { 0 };
        self.0[at].fetch_add(len as u64, Relaxed);
        self.0[at + 1].fetch_add(1, Relaxed);
        self.0[at + 2].fetch_add(u64::from(dropped), Relaxed);
    }
}
#[derive(Clone)]
struct Link {
    l2: crate::ethernet::PortConfig,
    bridge_config: crate::ethernet::BridgeConfig,
    switch: Arc<crate::ethernet::Switch>,
    index: u32,
    name: Vec<u8>,
    namespace: u64,
    kind: DeviceKind,
    up: bool,
    mtu: u32,
    tx_queue_len: u32,
    mac: [u8; 6],
    master: Option<u32>,
    addresses: Vec<Address>,
    stats: Arc<Counters>,
    ipv4_ingress: u8,
    ipv6: [i32; 5],
    stable_secret: Option<std::net::Ipv6Addr>,
}
impl Link {
    fn snapshot(&self) -> Device {
        Device {
            index: self.index,
            name: self.name.clone(),
            namespace: self.namespace,
            kind: self.kind,
            up: self.up,
            mtu: self.mtu,
            tx_queue_len: self.tx_queue_len,
            mac: self.mac,
            master: self.master,
            addresses: self.addresses.clone(),
            stats: self.stats.snapshot(),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub ip: IpAddr,
    pub prefix: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub onlink: bool,
    pub destination: Address,
    pub device: u32,
    pub gateway: Option<IpAddr>,
    pub metric: u32,
    pub protocol: u8,
}
#[derive(Clone)]
struct Space {
    lo: Option<Arc<Loopback>>,
    packets: Arc<crate::packet_socket::Hub>,
    tunnels: BTreeMap<u32, crate::tun::Binding>,
    neighbors: BTreeMap<(u32, IpAddr), NeighborEntry>,
    neighbor_cache: Arc<crate::ethernet::NeighborCache>,
    ip_serial: Arc<AtomicU64>,
    routes: Vec<Route>,
    direct: bool,
    managed_uplink: bool,
    policy: policy::Policy,
    ipv4_all: u8,
    ipv4_default: u8,
    ipv6_all: [i32; 5],
    ipv6_default: [i32; 5],
    stable_secret: Option<std::net::Ipv6Addr>,
    forwarding: [bool; 2],
    firewall: Arc<crate::nftables::Firewall>,
    connections: Arc<Mutex<crate::conntrack::State>>,
    bridge_filter: [bool; 2],
}
#[derive(Clone, Default)]
pub(crate) struct Topology {
    next: u32,
    revision: u64,
    spaces: BTreeMap<u64, Space>,
    devices: BTreeMap<(u64, u32), Link>,
}
#[derive(Clone)]
pub(crate) struct View {
    pub graph: Arc<RwLock<Topology>>,
    pub namespace: u64,
}
const LOOPBACK_V4: Address = Address {
    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
    prefix: 8,
};
const LOOPBACK_V6: Address = Address {
    ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
    prefix: 128,
};

pub(crate) fn source_address(addresses: &[Address], destination: IpAddr) -> Option<IpAddr> {
    let link_local = |ip| matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local());
    let prefer_local = link_local(destination)
        || matches!(destination, IpAddr::V6(ip) if ip.is_multicast() && ip.octets()[1] & 15 <= 2);
    let mut fallback = None;
    for a in addresses
        .iter()
        .filter(|a| a.ip.is_ipv4() == destination.is_ipv4())
    {
        if link_local(a.ip) == prefer_local {
            return Some(a.ip);
        }
        fallback.get_or_insert(a.ip);
    }
    fallback
}

impl Address {
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                (u32::from(a) ^ u32::from(b)).leading_zeros() >= u32::from(self.prefix)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                (u128::from(a) ^ u128::from(b)).leading_zeros() >= u32::from(self.prefix)
            }
            _ => false,
        }
    }
    pub fn network(self) -> Self {
        let ip = match self.ip {
            IpAddr::V4(a) => IpAddr::V4(
                (u32::from(a)
                    & u32::MAX
                        .checked_shl(32 - u32::from(self.prefix))
                        .unwrap_or(0))
                .into(),
            ),
            IpAddr::V6(a) => IpAddr::V6(
                (u128::from(a)
                    & u128::MAX
                        .checked_shl(128 - u32::from(self.prefix))
                        .unwrap_or(0))
                .into(),
            ),
        };
        Self {
            ip,
            prefix: self.prefix,
        }
    }
}
impl Topology {
    /// A guest-owned IP uplink uses the existing native gateway. Its metadata
    /// never refreshes from or configures an actual host interface.
    pub fn manage_uplink(&mut self, id: u64, enabled: bool) {
        let space = self.spaces.get_mut(&id).unwrap();
        space.managed_uplink = true;
        space.direct = enabled;
        space.routes.clear();
        self.devices.insert(
            (id, 2),
            Link {
                l2: Default::default(),
                bridge_config: Default::default(),
                switch: Arc::default(),
                index: 2,
                name: b"eth0".to_vec(),
                namespace: id,
                kind: DeviceKind::Direct,
                up: true,
                mtu: 1500,
                tx_queue_len: 0,
                mac: [0; 6],
                master: None,
                addresses: Vec::new(),
                stats: Arc::default(),
                ipv4_ingress: self.spaces[&id].ipv4_default,
                ipv6: self.spaces[&id].ipv6_default,
                stable_secret: None,
            },
        );
        self.changed();
    }
    pub fn ioctl_ipv4(
        &mut self,
        id: u64,
        index: u32,
        address: Option<Ipv4Addr>,
        prefix: Option<u8>,
    ) -> Result<()> {
        let d = self.device(id, index)?;
        if d.kind == DeviceKind::Loopback && self.spaces[&id].lo.is_none()
            || d.kind == DeviceKind::Direct && !self.spaces[&id].managed_uplink
        {
            return Err(NetError(95));
        }
        if prefix.is_some_and(|p| p > 32) || address.is_some_and(|a| a.octets()[0] >= 224) {
            return Err(NetError(22));
        }
        let previous = d.addresses.iter().find(|a| a.ip.is_ipv4()).copied();
        let supplied = address.is_some();
        let address = address
            .or_else(|| {
                previous.and_then(|a| {
                    if let IpAddr::V4(ip) = a.ip {
                        Some(ip)
                    } else {
                        None
                    }
                })
            })
            .ok_or(NetError(99))?;
        if prefix.is_none() && previous.is_some_and(|a| a.ip == IpAddr::V4(address)) {
            return Ok(());
        }
        let prefix = prefix
            .or_else(|| (!supplied).then(|| previous.map(|a| a.prefix)).flatten())
            .unwrap_or(if address.octets()[0] < 128 {
                8
            } else if address.octets()[0] < 192 {
                16
            } else {
                24
            });
        if previous.is_none()
            && !address.is_unspecified()
            && !self.address_slot_available(id, index, address.into())
        {
            return Err(NetError(28));
        }
        let d = self.devices.get_mut(&(id, index)).unwrap();
        if let Some(old) = previous {
            d.addresses.retain(|a| *a != old);
        }
        if !address.is_unspecified() {
            d.addresses.insert(
                0,
                Address {
                    ip: address.into(),
                    prefix,
                },
            );
        }
        self.changed();
        Ok(())
    }
    fn direct_current(&self, id: u64, enabled: bool, info: Option<NetworkInfo>) -> bool {
        let Some(space) = self.spaces.get(&id) else {
            return true;
        };
        if space.managed_uplink {
            return true;
        }
        if space.direct != enabled {
            return false;
        }
        if !enabled {
            return !self.devices.contains_key(&(id, 2));
        }
        let Some(link) = self.devices.get(&(id, 2)) else {
            return false;
        };
        let addresses = info
            .into_iter()
            .flat_map(|info| {
                [
                    Address {
                        ip: info.ipv4.into(),
                        prefix: info.prefix4,
                    },
                    Address {
                        ip: info.ipv6.into(),
                        prefix: info.prefix6,
                    },
                ]
            })
            .filter(|a| !a.ip.is_unspecified());
        link.kind == DeviceKind::Direct
            && link.mtu == info.map_or(1500, |i| i.mtu)
            && link.addresses.iter().copied().eq(addresses)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    fn changed(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }
    pub fn removed_with_space(&self, id: u64) -> Vec<Device> {
        let owned = self.devices(id);
        let mut out = owned.clone();
        for d in owned {
            if let DeviceKind::Veth { peer } = d.kind {
                if let Some(peer) = self.peer_device(peer) {
                    if peer.namespace != id {
                        out.push(peer);
                    }
                }
            }
        }
        out
    }
    pub fn can_add_space(&self) -> bool {
        self.devices.len() < MAX_LINKS
    }
    pub fn add_space(&mut self, id: u64, lo: Option<Arc<Loopback>>, info: Option<NetworkInfo>) {
        self.changed();
        self.next = self.next.max(3);
        let loopback_up = lo.as_ref().is_none_or(|flag| flag.get());
        self.spaces.insert(
            id,
            Space {
                lo,
                packets: Arc::default(),
                tunnels: BTreeMap::new(),
                neighbors: BTreeMap::new(),
                neighbor_cache: Arc::default(),
                ip_serial: Arc::default(),
                routes: vec![],
                direct: false,
                managed_uplink: false,
                policy: policy::Policy::default(),
                ipv4_all: 0,
                ipv4_default: 0,
                ipv6_all: [1, 0, 0, 0, 0],
                ipv6_default: [1, 0, 0, 0, 0],
                stable_secret: None,
                forwarding: [false; 2],
                firewall: Arc::default(),
                connections: Arc::default(),
                bridge_filter: [true; 2],
            },
        );
        self.devices.insert(
            (id, 1),
            Link {
                l2: Default::default(),
                bridge_config: Default::default(),
                switch: Arc::default(),
                index: 1,
                name: b"lo".to_vec(),
                namespace: id,
                kind: DeviceKind::Loopback,
                up: true,
                mtu: 65536,
                tx_queue_len: 0,
                mac: [0; 6],
                master: None,
                addresses: if loopback_up {
                    vec![LOOPBACK_V4, LOOPBACK_V6]
                } else {
                    Vec::new()
                },
                stats: Arc::default(),
                ipv4_ingress: self.spaces[&id].ipv4_default,
                ipv6: self.spaces[&id].ipv6_default,
                stable_secret: None,
            },
        );
        if let Some(info) = info {
            for (ip, gateway) in [
                (IpAddr::V4(info.ipv4), IpAddr::V4(info.gateway4)),
                (IpAddr::V6(info.ipv6), IpAddr::V6(info.gateway6)),
            ] {
                if !ip.is_unspecified() {
                    self.spaces.get_mut(&id).unwrap().routes.push(Route {
                        onlink: false,
                        destination: Address {
                            ip: if ip.is_ipv4() {
                                Ipv4Addr::UNSPECIFIED.into()
                            } else {
                                Ipv6Addr::UNSPECIFIED.into()
                            },
                            prefix: 0,
                        },
                        device: 2,
                        gateway: (!gateway.is_unspecified() && info.id != 0).then_some(gateway),
                        metric: 0,
                        protocol: 3,
                    });
                }
            }
            let addresses = [
                (IpAddr::V4(info.ipv4), info.prefix4),
                (IpAddr::V6(info.ipv6), info.prefix6),
            ]
            .into_iter()
            .filter(|(ip, _)| !ip.is_unspecified())
            .map(|(ip, prefix)| Address { ip, prefix })
            .collect();
            self.devices.insert(
                (id, 2),
                Link {
                    l2: Default::default(),
                    bridge_config: Default::default(),
                    switch: Arc::default(),
                    index: 2,
                    name: b"eth0".to_vec(),
                    namespace: id,
                    kind: DeviceKind::Ethernet,
                    up: true,
                    mtu: info.mtu,
                    tx_queue_len: 0,
                    mac: [2, 0x54, 0x72, 0x61, 0, info.id],
                    master: None,
                    addresses,
                    stats: Arc::default(),
                    ipv4_ingress: self.spaces[&id].ipv4_default,
                    ipv6: self.spaces[&id].ipv6_default,
                    stable_secret: None,
                },
            );
        }
    }
    pub fn refresh_direct(&mut self, id: u64, enabled: bool, info: Option<NetworkInfo>) {
        let Some(space) = self.spaces.get_mut(&id) else {
            return;
        };
        space.direct = enabled;
        let addresses: Vec<_> = info
            .into_iter()
            .flat_map(|i| {
                [
                    (IpAddr::V4(i.ipv4), i.prefix4),
                    (IpAddr::V6(i.ipv6), i.prefix6),
                ]
            })
            .filter(|(ip, _)| !ip.is_unspecified())
            .map(|(ip, prefix)| Address { ip, prefix })
            .collect();
        if !enabled {
            if self.devices.remove(&(id, 2)).is_some() {
                self.spaces
                    .get_mut(&id)
                    .unwrap()
                    .routes
                    .retain(|r| r.device != 2);
                self.changed();
            }
            return;
        }
        let mtu = info.map_or(1500, |i| i.mtu);
        if self.devices.get(&(id, 2)).is_some_and(|d| {
            d.kind == DeviceKind::Direct && d.addresses == addresses && d.mtu == mtu
        }) {
            return;
        }
        self.devices.insert(
            (id, 2),
            Link {
                l2: Default::default(),
                bridge_config: Default::default(),
                switch: Arc::default(),
                index: 2,
                name: b"eth0".to_vec(),
                namespace: id,
                kind: DeviceKind::Direct,
                up: true,
                mtu,
                tx_queue_len: 0,
                mac: [0; 6],
                master: None,
                addresses: addresses.clone(),
                stats: Arc::default(),
                ipv4_ingress: self.spaces[&id].ipv4_default,
                ipv6: self.spaces[&id].ipv6_default,
                stable_secret: None,
            },
        );
        let space = self.spaces.get_mut(&id).unwrap();
        space.routes.retain(|r| r.device != 2);
        for a in addresses {
            space.routes.push(Route {
                onlink: false,
                destination: Address {
                    ip: if a.ip.is_ipv4() {
                        Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        Ipv6Addr::UNSPECIFIED.into()
                    },
                    prefix: 0,
                },
                device: 2,
                gateway: None,
                metric: 0,
                protocol: 3,
            });
        }
        self.changed();
    }
    pub fn ipv4_ingress(&self, ns: u64, index: u32, flag: Ipv4Ingress) -> Result<bool> {
        let space = self.spaces.get(&ns).ok_or(NetError(19))?;
        let bits = match index {
            0 => space.ipv4_all,
            u32::MAX => space.ipv4_default,
            _ => {
                self.devices
                    .get(&(ns, index))
                    .ok_or(NetError(19))?
                    .ipv4_ingress
            }
        };
        Ok(bits & flag as u8 != 0)
    }
    pub fn set_ipv4_ingress(
        &mut self,
        ns: u64,
        index: u32,
        flag: Ipv4Ingress,
        enabled: bool,
    ) -> Result<()> {
        let space = self.spaces.get_mut(&ns).ok_or(NetError(19))?;
        let bits = match index {
            0 => &mut space.ipv4_all,
            u32::MAX => &mut space.ipv4_default,
            _ => {
                &mut self
                    .devices
                    .get_mut(&(ns, index))
                    .ok_or(NetError(19))?
                    .ipv4_ingress
            }
        };
        if enabled {
            *bits |= flag as u8;
        } else {
            *bits &= !(flag as u8);
        }
        Ok(())
    }
    pub(super) fn accepts_ipv4_ingress(
        &self,
        ns: u64,
        index: u32,
        source: IpAddr,
        dest: IpAddr,
    ) -> bool {
        let Some(link) = self.devices.get(&(ns, index)) else {
            return false;
        };
        let flags = self.spaces[&ns].ipv4_all | link.ipv4_ingress;
        (!(source.is_loopback() || dest.is_loopback())
            || flags & Ipv4Ingress::RouteLocalnet as u8 != 0)
            && (flags & Ipv4Ingress::AcceptLocal as u8 != 0 || !self.own(ns, source))
    }
    pub fn forwarding(&self, id: u64, ipv6: bool) -> bool {
        self.spaces
            .get(&id)
            .is_some_and(|s| s.forwarding[usize::from(ipv6)])
    }
    pub fn bridge_filter(&self, id: u64, ipv6: bool) -> bool {
        self.spaces
            .get(&id)
            .is_some_and(|s| s.bridge_filter[usize::from(ipv6)])
    }
    pub fn set_bridge_filter(&mut self, id: u64, ipv6: bool, enabled: bool) {
        if let Some(s) = self.spaces.get_mut(&id) {
            s.bridge_filter[usize::from(ipv6)] = enabled;
        }
    }
    pub fn set_forwarding(&mut self, id: u64, ipv6: bool, enabled: bool) {
        if let Some(s) = self.spaces.get_mut(&id) {
            s.forwarding[usize::from(ipv6)] = enabled;
            self.changed();
        }
    }
    pub fn remove_space(&mut self, id: u64) {
        let ips: Vec<_> = self
            .devices(id)
            .iter()
            .flat_map(|d| d.addresses.iter().map(|a| a.ip))
            .filter(|ip| !ip.is_loopback())
            .collect();
        for space in self.spaces.values() {
            space.connections.lock().unwrap().remove_addresses(&ips);
        }
        let links: Vec<_> = self
            .devices
            .keys()
            .filter_map(|&(ns, i)| (ns == id).then_some(i))
            .collect();
        for i in links {
            self.remove_link_inner(id, i);
        }
        self.spaces.remove(&id);
        self.changed();
    }
    pub fn devices(&self, id: u64) -> Vec<Device> {
        self.devices
            .range((id, 0)..=(id, u32::MAX))
            .map(|(_, d)| {
                let mut d = d.snapshot();
                if d.kind == DeviceKind::Loopback {
                    d.up = self.spaces[&id].lo.as_ref().is_none_or(|lo| lo.get());
                }
                d
            })
            .collect()
    }
    pub(super) fn link_mtu(&self, id: u64, index: u32) -> Result<u32> {
        Ok(self.devices.get(&(id, index)).ok_or(NetError(19))?.mtu)
    }
    pub fn device(&self, id: u64, index: u32) -> Result<Device> {
        let mut d = self
            .devices
            .get(&(id, index))
            .ok_or(NetError(19))?
            .snapshot();
        if d.kind == DeviceKind::Loopback {
            d.up = self.spaces[&id].lo.as_ref().is_none_or(|lo| lo.get());
        }
        Ok(d)
    }
    pub fn named(&self, id: u64, name: &[u8]) -> Result<Device> {
        self.devices(id)
            .into_iter()
            .find(|d| d.name == name)
            .ok_or(NetError(19))
    }
    pub fn automatic_name(&self, id: u64, kind: &str, reserved: Option<&[u8]>) -> Result<Vec<u8>> {
        for i in 0..=MAX_LINKS {
            let name = format!("{kind}{i}").into_bytes();
            if Some(name.as_slice()) != reserved && self.name_available(id, &name, None).is_ok() {
                return Ok(name);
            }
        }
        Err(NetError(28))
    }
    fn name_available(&self, id: u64, name: &[u8], except: Option<u32>) -> Result<()> {
        if name == b"eth0" && except != Some(2) && self.spaces.get(&id).is_some_and(|s| s.direct) {
            return Err(NetError(17));
        }
        if name.is_empty()
            || name.len() > 15
            || name == b"."
            || name == b".."
            || name
                .iter()
                .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b':'))
        {
            return Err(NetError(22));
        }
        if self
            .devices(id)
            .iter()
            .any(|d| d.name == name && Some(d.index) != except)
        {
            return Err(NetError(17));
        }
        Ok(())
    }
    fn allocate(&mut self) -> Result<u32> {
        if self.devices.len() >= MAX_LINKS {
            return Err(NetError(28));
        }
        let i = self.next;
        self.next = self.next.checked_add(1).ok_or(NetError(28))?;
        Ok(i)
    }
    fn new_device(&mut self, id: u64, name: &[u8], kind: DeviceKind) -> Result<u32> {
        if !self.spaces.contains_key(&id) {
            return Err(NetError(2));
        }
        self.name_available(id, name, None)?;
        let index = self.allocate()?;
        self.changed();
        self.devices.insert(
            (id, index),
            Link {
                l2: Default::default(),
                bridge_config: Default::default(),
                switch: Arc::default(),
                index,
                name: name.to_vec(),
                namespace: id,
                kind,
                up: false,
                mtu: 1500,
                tx_queue_len: 1000,
                mac: [
                    2,
                    0,
                    (index >> 16) as u8,
                    (index >> 8) as u8,
                    index as u8,
                    1,
                ],
                master: None,
                addresses: vec![],
                stats: Arc::default(),
                ipv4_ingress: self.spaces[&id].ipv4_default,
                ipv6: self.spaces[&id].ipv6_default,
                stable_secret: None,
            },
        );
        Ok(index)
    }
    pub fn create_bridge(&mut self, id: u64, name: &[u8]) -> Result<u32> {
        self.new_device(id, name, DeviceKind::Bridge)
    }
    pub fn create_veth(
        &mut self,
        id: u64,
        name: &[u8],
        peer_ns: u64,
        peer_name: &[u8],
    ) -> Result<(u32, u32)> {
        // Validate both ends and quota before either is published.
        self.name_available(id, name, None)?;
        self.name_available(peer_ns, peer_name, None)?;
        if id == peer_ns && name == peer_name {
            return Err(NetError(17));
        }
        if !self.spaces.contains_key(&peer_ns) {
            return Err(NetError(2));
        }
        if self.devices.len() + 2 > MAX_LINKS || self.next.checked_add(2).is_none() {
            return Err(NetError(28));
        }
        let a = self.new_device(id, name, DeviceKind::Veth { peer: 0 })?;
        let b = self.new_device(peer_ns, peer_name, DeviceKind::Veth { peer: a })?;
        self.devices.get_mut(&(id, a)).unwrap().kind = DeviceKind::Veth { peer: b };
        Ok((a, b))
    }
    #[allow(clippy::too_many_arguments)] // Atomic Linux link attributes, including cross-netns move.
    pub fn change_link(
        &mut self,
        id: u64,
        index: u32,
        name: Option<&[u8]>,
        destination: Option<&crate::Network>,
        up: Option<bool>,
        master: Option<u32>,
        mac: Option<[u8; 6]>,
        tx_queue_len: Option<u32>,
        mtu: Option<u32>,
    ) -> Result<crate::rtnetlink::Changes> {
        let mut changes = Vec::new();
        let old = self.device(id, index)?;
        let target = destination.map(crate::Network::namespace_id);
        if old.kind == DeviceKind::Direct && !self.spaces[&id].managed_uplink {
            return Err(NetError(95));
        }
        if old.kind == DeviceKind::Direct
            && (name.is_some() || target.is_some() || master.is_some() || mac.is_some())
        {
            return Err(NetError(95));
        }
        let mtu = mtu.filter(|value| *value != old.mtu);
        if let Some(value) = mtu {
            if value > i32::MAX as u32 {
                return Err(NetError(22));
            }
            match old.kind {
                DeviceKind::Loopback if self.spaces[&id].lo.is_some() => {}
                DeviceKind::Tun | DeviceKind::Tap => {
                    let max = if old.kind == DeviceKind::Tap {
                        65535 - 14
                    } else {
                        65535
                    };
                    if !(68..=max).contains(&value) {
                        return Err(NetError(22));
                    }
                }
                _ => return Err(NetError(95)),
            }
        }
        if old.kind == DeviceKind::Loopback {
            let name = name.filter(|value| *value != old.name);
            if let Some(name) = name {
                if self.spaces[&id].lo.is_none() {
                    return Err(NetError(95));
                }
                self.name_available(id, name, Some(index))?;
            }
            if target.is_some() || master.is_some() || mac.is_some() {
                return Err(NetError(95));
            }
            if name.is_none()
                && mtu.is_none()
                && up.is_none_or(|value| value == old.up)
                && tx_queue_len.is_none_or(|value| value == old.tx_queue_len)
            {
                return Ok(changes);
            }
            if let Some(up) = up {
                match self.spaces[&id].lo.clone() {
                    Some(lo) => {
                        let dev = self.devices.get_mut(&(id, index)).unwrap();
                        if old.up != up {
                            if up {
                                if !dev.addresses.iter().any(|a| a.ip.is_ipv4()) {
                                    dev.addresses.push(LOOPBACK_V4);
                                }
                                if dev.ipv6[2] == 0
                                    && !dev.addresses.iter().any(|a| a.ip == LOOPBACK_V6.ip)
                                {
                                    dev.addresses.push(LOOPBACK_V6);
                                }
                            } else {
                                let all = self.spaces[&id].ipv6_all[4];
                                let keep = if all == 0 { dev.ipv6[4] } else { all } > 0;
                                dev.addresses.retain(|a| match a.ip {
                                    IpAddr::V4(_) => true,
                                    IpAddr::V6(ip) => {
                                        keep && !ip.is_unicast_link_local() && !ip.is_loopback()
                                    }
                                });
                            }
                        }
                        lo.set(up)
                    }
                    None if up => {}
                    None => return Err(NetError(95)),
                }
            }
            if old.up && up == Some(false) {
                self.flush_ipv6_routes(id, index, &mut changes);
            }
            let dev = self.devices.get_mut(&(id, index)).unwrap();
            if let Some(name) = name {
                dev.name = name.to_vec();
            }
            if let Some(value) = mtu {
                dev.mtu = value;
            }
            if let Some(len) = tx_queue_len {
                dev.tx_queue_len = len;
            }
            crate::rtnetlink::address_changes(&old, &self.device(id, index)?, &mut changes);
            self.changed();
            return Ok(changes);
        }
        let target = target.unwrap_or(id);
        if !self.spaces.contains_key(&target) {
            return Err(NetError(2));
        }
        if target != id && matches!(old.kind, DeviceKind::Bridge | DeviceKind::Ethernet) {
            return Err(NetError(22));
        }
        if target != id && master.is_some_and(|m| m != 0) {
            return Err(NetError(22));
        }
        let newname = name.unwrap_or(&old.name);
        self.name_available(target, newname, (target == id).then_some(index))?;
        if let Some(master) = master.filter(|m| *m != 0) {
            if !matches!(
                old.kind,
                DeviceKind::Veth { .. } | DeviceKind::Tap | DeviceKind::Ethernet
            ) || self.device(target, master)?.kind != DeviceKind::Bridge
            {
                return Err(NetError(22));
            }
        }
        if mac.is_some_and(|m| m == [0; 6] || m[0] & 1 != 0) {
            return Err(NetError(22));
        }
        if let Some(master) = master.filter(|m| *m != 0) {
            self.check_bridge_loop(id, index, master)?;
        }
        if target != id || master.is_some_and(|m| Some(m).filter(|m| *m != 0) != old.master) {
            self.forget_l2_port(id, index);
        }
        let mut d = self.devices.remove(&(id, index)).unwrap();
        d.namespace = target;
        d.name = newname.to_vec();
        if target != id {
            if let Some(binding) = self.spaces.get_mut(&id).unwrap().tunnels.remove(&index) {
                // A queue descriptor follows the same device across namespaces.
                // Publish its new endpoint with the link under the topology writer.
                if let Some(port) = binding.port.upgrade() {
                    port.move_to(&destination.unwrap().1);
                }
                self.spaces
                    .get_mut(&target)
                    .unwrap()
                    .tunnels
                    .insert(index, binding);
            }
            self.spaces
                .get_mut(&id)
                .unwrap()
                .neighbors
                .retain(|(i, _), _| *i != index);
            d.up = false;
            d.master = None;
            d.addresses.clear();
            self.spaces
                .get_mut(&id)
                .unwrap()
                .routes
                .retain(|r| r.device != index);
            self.spaces
                .get_mut(&id)
                .unwrap()
                .policy
                .forget_device(index);
        }
        if let Some(up) = up {
            if d.up && !up {
                self.flush_ipv6_routes(id, index, &mut changes);
                // All configured addresses are permanent. Linux retains only
                // global-scope IPv6 addresses on an ordinary link-down.
                let all = self.spaces[&id].ipv6_all[4];
                let keep = if all == 0 { d.ipv6[4] } else { all } > 0;
                d.addresses.retain(|a| match a.ip {
                    IpAddr::V6(ip) => keep && !ip.is_unicast_link_local() && !ip.is_loopback(),
                    IpAddr::V4(_) => true,
                });
            }
            d.up = up;
        }
        if let Some(master) = master {
            d.master = (master != 0).then_some(master);
        }
        if let Some(mac) = mac {
            d.mac = mac;
        }
        if let Some(len) = tx_queue_len {
            d.tx_queue_len = len;
        }
        if let Some(value) = mtu {
            d.mtu = value;
        }
        self.devices.insert((target, index), d);
        if let DeviceKind::Veth { peer } = old.kind {
            if up == Some(true) && (!old.up || target != id) {
                if let Some(peer) = self.peer_device(peer).filter(|link| link.up) {
                    self.assign_veth_link_local(target, index);
                    self.assign_veth_link_local(peer.namespace, peer.index);
                    crate::rtnetlink::address_changes(
                        &peer,
                        &self.device(peer.namespace, peer.index)?,
                        &mut changes,
                    );
                }
            }
        }
        if id == target {
            crate::rtnetlink::address_changes(&old, &self.device(target, index)?, &mut changes);
        }
        self.changed();
        Ok(changes)
    }
    fn assign_veth_link_local(&mut self, ns: u64, index: u32) {
        let d = &self.devices[&(ns, index)];
        if d.ipv6[2] != 0
            || d.ipv6[3] != 0
            || d.mtu < 1280
            || d.addresses
                .iter()
                .any(|a| matches!(a.ip, IpAddr::V6(ip) if ip.is_unicast_link_local()))
        {
            return;
        }
        let [a, b, c, d, e, f] = d.mac;
        let ip = Ipv6Addr::from([
            0xfe,
            0x80,
            0,
            0,
            0,
            0,
            0,
            0,
            a ^ 2,
            b,
            c,
            0xff,
            0xfe,
            d,
            e,
            f,
        ])
        .into();
        if self.address_slot_available(ns, index, ip) {
            self.devices
                .get_mut(&(ns, index))
                .unwrap()
                .addresses
                .push(Address { ip, prefix: 64 });
        }
    }

    pub fn remove_link(&mut self, id: u64, index: u32) -> Result<()> {
        if matches!(
            self.device(id, index)?.kind,
            DeviceKind::Loopback | DeviceKind::Direct
        ) {
            return Err(NetError(95));
        }
        self.remove_link_inner(id, index);
        self.changed();
        Ok(())
    }
    fn remove_link_inner(&mut self, id: u64, index: u32) {
        self.forget_l2_port(id, index);
        let Some(d) = self.devices.remove(&(id, index)) else {
            return;
        };
        if let DeviceKind::Veth { peer } = d.kind {
            if let Some(key) = self
                .devices
                .iter()
                .find_map(|(&key, d)| (d.index == peer).then_some(key))
            {
                self.forget_l2_port(key.0, key.1);
                self.devices.remove(&key);
                if let Some(s) = self.spaces.get_mut(&key.0) {
                    s.neighbors.retain(|(i, _), _| *i != peer);
                    s.routes.retain(|r| r.device != peer);
                    s.policy.forget_device(peer);
                }
            }
        }
        if let Some(s) = self.spaces.get_mut(&id) {
            // Attached queues remain reachable for the link-deletion wake.
            if s.tunnels
                .get(&index)
                .is_some_and(|b| b.port.strong_count() == 0)
            {
                s.tunnels.remove(&index);
            }
            s.neighbors.retain(|(i, _), _| *i != index);
            s.routes.retain(|r| r.device != index);
            s.policy.forget_device(index);
        }
        for d in self.devices.values_mut() {
            if d.namespace == id && d.master == Some(index) {
                d.master = None;
            }
        }
    }
    fn address_slot_available(&self, id: u64, index: u32, ip: IpAddr) -> bool {
        // The kernel restores ::1 on loopback-up. Reserve its slot while it
        // is absent, including when aliases arrive through SIOCSIFADDR.
        let link_local = |ip| matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local());
        let used: usize = self
            .devices
            .range((id, 0)..=(id, u32::MAX))
            .map(|(_, d)| {
                let has_link_local = matches!(d.kind, DeviceKind::Veth { .. })
                    && d.addresses.iter().any(|a| link_local(a.ip));
                d.addresses.len() - usize::from(has_link_local)
                    + usize::from(
                        d.kind == DeviceKind::Loopback
                            && !(index == d.index && ip.is_ipv4())
                            && !d.addresses.iter().any(|a| a.ip.is_ipv4()),
                    )
                    + usize::from(
                        d.kind == DeviceKind::Loopback
                            && !(index == d.index && ip == Ipv6Addr::LOCALHOST)
                            && !d.addresses.iter().any(|a| a.ip == Ipv6Addr::LOCALHOST),
                    )
            })
            .sum();
        used < MAX_ADDRESSES
            || (link_local(ip)
                && self.devices.get(&(id, index)).is_some_and(|d| {
                    matches!(d.kind, DeviceKind::Veth { .. })
                        && !d.addresses.iter().any(|a| link_local(a.ip))
                }))
    }
    pub fn address(
        &mut self,
        id: u64,
        index: u32,
        address: Address,
        add: bool,
        replace: bool,
    ) -> Result<()> {
        if address.prefix > if address.ip.is_ipv4() { 32 } else { 128 }
            || address.ip.is_unspecified()
            || address.ip.is_multicast()
        {
            return Err(NetError(22));
        }
        let d = self.devices.get(&(id, index)).ok_or(NetError(19))?;
        if add && address.ip.is_ipv6() && d.ipv6[2] != 0 {
            return Err(NetError(13));
        }
        if d.kind == DeviceKind::Loopback && self.spaces[&id].lo.is_none()
            || d.kind == DeviceKind::Direct && !self.spaces[&id].managed_uplink
            || d.master.is_some()
        {
            return Err(NetError(95));
        }
        if !add && !d.addresses.contains(&address) {
            return Err(NetError(99));
        }
        if add && d.addresses.contains(&address) {
            return if replace { Ok(()) } else { Err(NetError(17)) };
        }
        if add && !self.address_slot_available(id, index, address.ip) {
            return Err(NetError(28));
        }
        let d = self.devices.get_mut(&(id, index)).unwrap();
        if add {
            d.addresses.push(address);
        } else {
            d.addresses.retain(|a| *a != address);
        }
        self.changed();
        Ok(())
    }
    pub fn routes(&self, id: u64) -> Vec<Route> {
        let mut routes = self
            .spaces
            .get(&id)
            .map_or_else(Vec::new, |s| s.routes.clone());
        for (_, d) in self.devices.range((id, 0)..=(id, u32::MAX)) {
            let up = if d.kind == DeviceKind::Loopback {
                self.spaces[&id].lo.as_ref().is_none_or(|lo| lo.get())
            } else {
                d.up
            };
            if up {
                for (i, a) in d.addresses.iter().enumerate() {
                    if d.addresses[..i]
                        .iter()
                        .any(|other| other.network() == a.network())
                    {
                        continue;
                    }
                    routes.push(Route {
                        onlink: false,
                        destination: a.network(),
                        device: d.index,
                        gateway: None,
                        metric: 0,
                        protocol: 2,
                    });
                }
            }
        }
        routes
    }
    // A gateway must be reachable by a connected prefix or an installed
    // direct route. A route through a second gateway cannot establish this.
    pub(super) fn gateway_device(&self, id: u64, ip: IpAddr, device: Option<u32>) -> Option<u32> {
        self.routes(id)
            .into_iter()
            .filter(|r| {
                r.gateway.is_none()
                    && r.destination.contains(ip)
                    && device.is_none_or(|index| index == r.device)
                    && self
                        .device(id, r.device)
                        .is_ok_and(|d| d.up && d.master.is_none())
            })
            .min_by_key(|r| (std::cmp::Reverse(r.destination.prefix), r.metric, r.device))
            .map(|r| r.device)
    }
    pub fn route(
        &mut self,
        id: u64,
        route: Route,
        add: bool,
        replace: bool,
        exclusive: bool,
    ) -> Result<()> {
        let d = self.device(id, route.device)?;
        if d.kind == DeviceKind::Direct && !self.spaces[&id].managed_uplink
            || route.destination != route.destination.network()
        {
            return Err(NetError(95));
        }
        if let Some(g) = route.gateway.filter(|_| add) {
            if g.is_ipv4() != route.destination.ip.is_ipv4()
                || g.is_unspecified()
                || g.is_multicast()
                || !(route.onlink && d.up
                    || matches!(g, IpAddr::V6(ip) if ip.is_unicast_link_local()) && d.up
                    || self.gateway_device(id, g, Some(d.index)).is_some())
            {
                return Err(NetError(101));
            }
        }
        let routes = &mut self.spaces.get_mut(&id).ok_or(NetError(2))?.routes;
        let at = routes.iter().position(|r| {
            r.destination == route.destination
                && r.metric == route.metric
                && (exclusive
                    || replace
                    || (r.device == route.device && r.gateway == route.gateway))
        });
        if add {
            if let Some(at) = at {
                if exclusive || !replace {
                    return Err(NetError(17));
                }
                routes[at] = route;
            } else {
                if routes.len() >= MAX_ROUTES {
                    return Err(NetError(28));
                }
                routes.push(route);
            }
        } else {
            let at = at
                .filter(|&at| {
                    routes[at].device == route.device && routes[at].gateway == route.gateway
                })
                .ok_or(NetError(3))?;
            routes.remove(at);
        }
        self.changed();
        Ok(())
    }
    // Linux IPv4 local routes cover the configured loopback prefix. IPv6
    // addresses and ordinary interfaces own only their assigned addresses.
    fn local_source<const REQUIRE_UP: bool>(&self, id: u64, ip: IpAddr) -> Option<IpAddr> {
        let mut subnet = None;
        for (_, d) in self.devices.range((id, 0)..=(id, u32::MAX)) {
            let lo = d.kind == DeviceKind::Loopback;
            if REQUIRE_UP && lo && self.spaces[&id].lo.as_ref().is_some_and(|flag| !flag.get()) {
                continue;
            }
            for a in &d.addresses {
                if a.ip == ip {
                    return Some(ip);
                }
                if lo && ip.is_ipv4() && a.contains(ip) {
                    subnet.get_or_insert(a.ip);
                }
            }
        }
        subnet
    }
    pub fn own(&self, id: u64, ip: IpAddr) -> bool {
        self.local_source::<true>(id, ip).is_some()
    }
    pub fn source(&self, id: u64, destination: IpAddr) -> Result<(IpAddr, u32, Option<IpAddr>)> {
        self.source_for(id, destination, RouteContext::default())
    }
    fn source_main(
        &self,
        id: u64,
        destination: IpAddr,
        device: Option<u32>,
    ) -> Result<(IpAddr, u32, Option<IpAddr>)> {
        if let Some(source) = self.local_source::<true>(id, destination) {
            return Ok((source, 1, None));
        }
        if destination.is_loopback() {
            return Err(NetError(if destination.is_ipv4() { 101 } else { 99 }));
        }
        let mut routes = self.routes(id);
        routes.sort_by_key(|r| (std::cmp::Reverse(r.destination.prefix), r.metric));
        for r in routes {
            let d = self.device(id, r.device)?;
            if d.up
                && d.master.is_none()
                && device.is_none_or(|index| index == d.index)
                && r.destination.contains(destination)
            {
                if let Some(a) = source_address(&d.addresses, destination) {
                    return Ok((a, d.index, r.gateway));
                }
            }
        }
        Err(NetError(101))
    }
    pub(super) fn directed_broadcast(&self, id: u64, interface: Option<u32>, ip: Ipv4Addr) -> bool {
        let range = (id, interface.unwrap_or(0))..=(id, interface.unwrap_or(u32::MAX));
        self.devices.range(range).any(|(_,d)| d.addresses.iter().any(|a|
            matches!(a.ip, IpAddr::V4(local) if a.prefix<=30 && u32::from(local) | u32::MAX.checked_shr(a.prefix.into()).unwrap_or(0)==u32::from(ip))))
    }
    pub fn interface_address(&self, id: u64, index: u32, ipv4: bool) -> Option<IpAddr> {
        self.devices
            .get(&(id, index))?
            .addresses
            .iter()
            .find(|a| a.ip.is_ipv4() == ipv4)
            .map(|a| a.ip)
    }
    pub(super) fn redirect_address(
        &self,
        id: u64,
        index: u32,
        destination: IpAddr,
    ) -> Option<IpAddr> {
        let IpAddr::V6(destination) = destination else {
            return self
                .interface_address(id, index, true)
                .filter(|a| !a.is_unspecified());
        };
        // Linux restricts ingress REDIRECT only for node-, link- and site-local destinations.
        fn scope(ip: std::net::Ipv6Addr) -> u8 {
            if ip.is_multicast() {
                return match ip.octets()[1] & 15 {
                    n @ (1 | 2 | 5) => n,
                    _ => 0,
                };
            }
            if ip.is_loopback() {
                1
            } else if ip.is_unicast_link_local() {
                2
            } else if ip.segments()[0] & 0xffc0 == 0xfec0 {
                5
            } else {
                0
            }
        }
        let required = scope(destination);
        self.devices.get(&(id, index))?.addresses.iter().map(|a| a.ip).find(|ip| {
            matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() && (required == 0 || scope(*v6) == required))
        })
    }
    pub(crate) fn device_kind(&self, id: u64, index: u32) -> Option<DeviceKind> {
        self.devices.get(&(id, index)).map(|d| d.kind)
    }
    pub fn device_name(&self, id: u64, index: u32) -> Option<&[u8]> {
        self.devices.get(&(id, index)).map(|d| d.name.as_slice())
    }
    pub fn address_type(&self, id: u64, ip: IpAddr, interface: Option<u32>) -> u32 {
        if ip.is_multicast() {
            return 5;
        }
        if let IpAddr::V4(v) = ip {
            if v.is_broadcast() || self.directed_broadcast(id, interface, v) {
                return 3;
            }
        }
        let local = match interface {
            Some(index) => self.devices.get(&(id, index)).is_some_and(|d| {
                d.addresses.iter().any(|a| {
                    a.ip == ip || (d.kind == DeviceKind::Loopback && ip.is_ipv4() && a.contains(ip))
                })
            }),
            None => self.own(id, ip) || ip.is_loopback(),
        };
        if local {
            2
        } else {
            1
        }
    }
    pub fn connections(&self, id: u64) -> Arc<Mutex<crate::conntrack::State>> {
        self.spaces[&id].connections.clone()
    }
    pub fn firewall(&self, id: u64) -> Arc<crate::nftables::Firewall> {
        self.spaces[&id].firewall.clone()
    }
    pub fn peer_device(&self, index: u32) -> Option<Device> {
        self.devices
            .values()
            .find(|d| d.index == index)
            .and_then(|d| self.device(d.namespace, index).ok())
    }
    pub fn carrier(&self, d: &Device) -> bool {
        if !d.up {
            return false;
        }
        match d.kind {
            DeviceKind::Tun | DeviceKind::Tap => self.tunnel(d.namespace, d.index).is_some(),
            DeviceKind::Veth { peer } => self.devices.values().any(|p| p.index == peer && p.up),
            _ => true,
        }
    }
    pub fn account(&self, id: u64, index: u32, len: usize, tx: bool, dropped: bool) {
        if let Some(d) = self.devices.get(&(id, index)) {
            d.stats.account(len, tx, dropped);
        }
    }
}
impl View {
    pub fn managed_uplink(&self) -> bool {
        self.graph.read().unwrap().spaces[&self.namespace].managed_uplink
    }

    pub fn source_for(&self, ip: IpAddr, context: RouteContext) -> Result<IpAddr> {
        self.graph
            .read()
            .unwrap()
            .source_for(self.namespace, ip, context)
            .map(|v| v.0)
    }
    pub fn device(&self, name: &[u8]) -> Result<u32> {
        self.graph
            .read()
            .unwrap()
            .named(self.namespace, name)
            .map(|d| d.index)
    }
    pub fn own(&self, ip: IpAddr) -> bool {
        // A down link can still own an assigned address for bind.
        self.graph
            .read()
            .unwrap()
            .local_source::<false>(self.namespace, ip)
            .is_some()
    }
    pub fn addresses(&self, up_only: bool) -> Vec<Address> {
        self.graph
            .read()
            .unwrap()
            .devices(self.namespace)
            .into_iter()
            .filter(|d| !up_only || d.up)
            .flat_map(|d| d.addresses)
            .collect()
    }
}

#[cfg(test)]
#[path = "netdev_shared_tests.rs"]
mod shared_tests;
