// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-owned IP link topology. Metadata is touched only by the kernel thread.
//! Veth/bridge connectivity is explicit; a shared fabric is never all-to-all.
use crate::{LinkStats, NetError, NetworkInfo};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
};
type Result<T> = std::result::Result<T, NetError>;
const MAX_LINKS: usize = 256;
const MAX_ADDRESSES: usize = 6; // Plus the two loopback addresses in smoltcp.
const MAX_ROUTES: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    Loopback,
    Direct,
    Veth { peer: u32 },
    Bridge,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub ip: IpAddr,
    pub prefix: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub destination: Address,
    pub device: u32,
    pub gateway: Option<IpAddr>,
    pub metric: u32,
    pub protocol: u8,
}
#[derive(Clone)]
struct Space {
    lo: Option<Rc<Cell<bool>>>,
    routes: Vec<Route>,
    direct: bool,
    forwarding: [bool; 2],
    firewall: Rc<RefCell<crate::nftables::Ruleset>>,
}
#[derive(Clone, Default)]
pub(crate) struct Topology {
    next: u32,
    revision: u64,
    spaces: BTreeMap<u64, Space>,
    devices: BTreeMap<(u64, u32), Device>,
}
#[derive(Clone)]
pub(crate) struct View {
    pub graph: Rc<RefCell<Topology>>,
    pub namespace: u64,
    pub native_root: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct PacketPath {
    pub namespace: u64,
    pub output: u32,
    pub input: u32,
    pub transit: [Option<(u64, u32, u32)>; 16],
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
    pub fn add_space(&mut self, id: u64, lo: Option<Rc<Cell<bool>>>, info: Option<NetworkInfo>) {
        self.changed();
        self.next = self.next.max(3);
        self.spaces.insert(
            id,
            Space {
                lo,
                routes: vec![],
                direct: false,
                forwarding: [false; 2],
                firewall: Rc::default(),
            },
        );
        self.devices.insert(
            (id, 1),
            Device {
                index: 1,
                name: b"lo".to_vec(),
                namespace: id,
                kind: DeviceKind::Loopback,
                up: true,
                mtu: 65536,
                tx_queue_len: 0,
                mac: [0; 6],
                master: None,
                addresses: vec![
                    Address {
                        ip: Ipv4Addr::LOCALHOST.into(),
                        prefix: 8,
                    },
                    Address {
                        ip: Ipv6Addr::LOCALHOST.into(),
                        prefix: 128,
                    },
                ],
                stats: LinkStats::default(),
            },
        );
        if let Some(info) = info {
            for (ip, gateway) in [
                (IpAddr::V4(info.ipv4), IpAddr::V4(info.gateway4)),
                (IpAddr::V6(info.ipv6), IpAddr::V6(info.gateway6)),
            ] {
                if !ip.is_unspecified() {
                    self.spaces.get_mut(&id).unwrap().routes.push(Route {
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
                Device {
                    index: 2,
                    name: b"eth0".to_vec(),
                    namespace: id,
                    kind: DeviceKind::Direct,
                    up: true,
                    mtu: info.mtu,
                    tx_queue_len: 0,
                    mac: [0; 6],
                    master: None,
                    addresses,
                    stats: LinkStats::default(),
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
            Device {
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
                stats: LinkStats::default(),
            },
        );
        let space = self.spaces.get_mut(&id).unwrap();
        space.routes.retain(|r| r.device != 2);
        for a in addresses {
            space.routes.push(Route {
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
    pub fn forwarding(&self, id: u64, ipv6: bool) -> bool {
        self.spaces
            .get(&id)
            .is_some_and(|s| s.forwarding[usize::from(ipv6)])
    }
    pub fn set_forwarding(&mut self, id: u64, ipv6: bool, enabled: bool) {
        if let Some(s) = self.spaces.get_mut(&id) {
            s.forwarding[usize::from(ipv6)] = enabled;
            self.changed();
        }
    }
    pub fn remove_space(&mut self, id: u64) {
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
                let mut d = d.clone();
                if d.kind == DeviceKind::Loopback {
                    d.up = self.spaces[&id].lo.as_ref().is_none_or(|lo| lo.get());
                }
                d
            })
            .collect()
    }
    pub fn device(&self, id: u64, index: u32) -> Result<Device> {
        self.devices(id)
            .into_iter()
            .find(|d| d.index == index)
            .ok_or(NetError(19))
    }
    pub fn named(&self, id: u64, name: &[u8]) -> Result<Device> {
        self.devices(id)
            .into_iter()
            .find(|d| d.name == name)
            .ok_or(NetError(19))
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
            Device {
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
                stats: LinkStats::default(),
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
        target: Option<u64>,
        up: Option<bool>,
        master: Option<u32>,
        mac: Option<[u8; 6]>,
        tx_queue_len: Option<u32>,
    ) -> Result<()> {
        let old = self.device(id, index)?;
        if old.kind == DeviceKind::Direct {
            return Err(NetError(95));
        }
        if old.kind == DeviceKind::Loopback {
            if name.is_some() || target.is_some() || master.is_some() || mac.is_some() {
                return Err(NetError(95));
            }
            if let Some(up) = up {
                match &self.spaces[&id].lo {
                    Some(lo) => lo.set(up),
                    None if up => {}
                    None => return Err(NetError(95)),
                }
            }
            if let Some(len) = tx_queue_len {
                self.devices.get_mut(&(id, index)).unwrap().tx_queue_len = len;
            }
            self.changed();
            return Ok(());
        }
        let target = target.unwrap_or(id);
        if !self.spaces.contains_key(&target) {
            return Err(NetError(2));
        }
        if target != id && old.kind == DeviceKind::Bridge {
            return Err(NetError(22));
        }
        if target != id && master.is_some_and(|m| m != 0) {
            return Err(NetError(22));
        }
        let newname = name.unwrap_or(&old.name);
        self.name_available(target, newname, (target == id).then_some(index))?;
        if let Some(master) = master.filter(|m| *m != 0) {
            if !matches!(old.kind, DeviceKind::Veth { .. })
                || self.device(target, master)?.kind != DeviceKind::Bridge
            {
                return Err(NetError(22));
            }
        }
        if mac.is_some_and(|m| m == [0; 6] || m[0] & 1 != 0) {
            return Err(NetError(22));
        }
        let mut d = self.devices.remove(&(id, index)).unwrap();
        d.namespace = target;
        d.name = newname.to_vec();
        if target != id {
            d.up = false;
            d.master = None;
            d.addresses.clear();
            self.spaces
                .get_mut(&id)
                .unwrap()
                .routes
                .retain(|r| r.device != index);
        }
        if let Some(up) = up {
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
        self.devices.insert((target, index), d);
        self.changed();
        Ok(())
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
        let Some(d) = self.devices.remove(&(id, index)) else {
            return;
        };
        if let DeviceKind::Veth { peer } = d.kind {
            if let Some(key) = self
                .devices
                .iter()
                .find_map(|(&key, d)| (d.index == peer).then_some(key))
            {
                self.devices.remove(&key);
                if let Some(s) = self.spaces.get_mut(&key.0) {
                    s.routes.retain(|r| r.device != peer);
                }
            }
        }
        if let Some(s) = self.spaces.get_mut(&id) {
            s.routes.retain(|r| r.device != index);
        }
        for d in self.devices.values_mut() {
            if d.namespace == id && d.master == Some(index) {
                d.master = None;
            }
        }
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
        if matches!(d.kind, DeviceKind::Loopback | DeviceKind::Direct) || d.master.is_some() {
            return Err(NetError(95));
        }
        if !add && !d.addresses.contains(&address) {
            return Err(NetError(99));
        }
        if add && d.addresses.contains(&address) {
            return if replace { Ok(()) } else { Err(NetError(17)) };
        }
        if add
            && self
                .devices(id)
                .iter()
                .filter(|d| !matches!(d.kind, DeviceKind::Loopback | DeviceKind::Direct))
                .map(|d| d.addresses.len())
                .sum::<usize>()
                >= MAX_ADDRESSES
        {
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
        for d in self.devices(id) {
            if d.up {
                for a in d.addresses {
                    routes.push(Route {
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
    pub fn route(
        &mut self,
        id: u64,
        route: Route,
        add: bool,
        replace: bool,
        exclusive: bool,
    ) -> Result<()> {
        let d = self.device(id, route.device)?;
        if d.kind == DeviceKind::Direct || route.destination != route.destination.network() {
            return Err(NetError(95));
        }
        if let Some(g) = route.gateway {
            if g.is_ipv4() != route.destination.ip.is_ipv4()
                || g.is_unspecified()
                || g.is_multicast()
                || !d.addresses.iter().any(|a| a.contains(g))
            {
                return Err(NetError(101));
            }
        }
        let routes = &mut self.spaces.get_mut(&id).ok_or(NetError(2))?.routes;
        let at = routes
            .iter()
            .position(|r| r.destination == route.destination && r.metric == route.metric);
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
    pub fn own(&self, id: u64, ip: IpAddr) -> bool {
        self.devices(id).iter().any(|d| {
            d.addresses.iter().any(|a| a.ip == ip) && (d.kind != DeviceKind::Loopback || d.up)
        })
    }
    pub fn source(&self, id: u64, destination: IpAddr) -> Result<(IpAddr, u32, Option<IpAddr>)> {
        if self.own(id, destination) {
            let d = self
                .devices(id)
                .into_iter()
                .find(|d| d.addresses.iter().any(|a| a.ip == destination))
                .unwrap();
            return Ok((destination, d.index, None));
        }
        let mut routes = self.routes(id);
        routes.sort_by_key(|r| (std::cmp::Reverse(r.destination.prefix), r.metric));
        for r in routes {
            let d = self.device(id, r.device)?;
            if d.up && d.master.is_none() && r.destination.contains(destination) {
                if let Some(a) = d
                    .addresses
                    .iter()
                    .find(|a| a.ip.is_ipv4() == destination.is_ipv4())
                {
                    return Ok((a.ip, d.index, r.gateway));
                }
            }
        }
        Err(NetError(101))
    }
    /// Resolve actual L2 adjacency at each L3 hop. Routes never create an
    /// implicit fabric connection. Native interfaces are deliberately excluded
    /// from forwarding until explicit filtering/NAT is implemented.
    pub fn target(&self, id: u64, destination: IpAddr) -> Option<PacketPath> {
        let (_, first, _) = self.source(id, destination).ok()?;
        let mut current = id;
        let mut hops = 0;
        let mut transit = [None; 16];
        let mut incoming = 0;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) || hops >= 16 {
                return None;
            }
            let (_, out, gateway) = self.source(current, destination).ok()?;
            if current != id {
                transit[(hops - 1) as usize] = Some((current, incoming, out));
            }
            if self.own(current, destination) {
                return Some(PacketPath {
                    namespace: current,
                    output: first,
                    input: out,
                    transit,
                });
            }
            let next = gateway.unwrap_or(destination);
            let (ns, input) = self.neighbor(current, out, next)?;
            if next == destination || self.own(ns, destination) {
                return Some(PacketPath {
                    namespace: ns,
                    output: first,
                    input,
                    transit,
                });
            }
            if !self.forwarding(ns, destination.is_ipv6()) {
                return None;
            }
            current = ns;
            incoming = input;
            hops += 1;
        }
    }
    pub fn firewall(&self, id: u64) -> Rc<RefCell<crate::nftables::Ruleset>> {
        self.spaces[&id].firewall.clone()
    }
    pub fn filter_path(&self, source: u64, path: PacketPath, packet: &mut [u8]) -> bool {
        use crate::nftables::Context;
        let check = |ns: u64, hook, input, output, packet: &[u8]| {
            let rules = self.spaces[&ns].firewall.borrow();
            if !rules.active(hook) {
                return true;
            }
            let name = |index| self.device(ns, index).map(|d| d.name).unwrap_or_default();
            rules.allows(&Context {
                packet,
                hook,
                input,
                output,
                input_name: &name(input),
                output_name: &name(output),
            })
        };
        if !check(source, 3, 0, path.output, packet) || !check(source, 4, 0, path.output, packet) {
            return false;
        }
        for (ns, input, output) in path.transit.into_iter().flatten() {
            if !check(ns, 0, input, 0, packet) {
                return false;
            }
            let ttl = if packet[0] >> 4 == 4 { 8 } else { 7 };
            if packet[ttl] <= 1 {
                return false;
            }
            packet[ttl] -= 1;
            if packet[0] >> 4 == 4 {
                smoltcp::wire::Ipv4Packet::new_unchecked(&mut *packet).fill_checksum();
            }
            if !check(ns, 2, input, output, packet) || !check(ns, 4, 0, output, packet) {
                return false;
            }
        }
        check(path.namespace, 0, path.input, 0, packet)
            && check(path.namespace, 1, path.input, 0, packet)
    }
    fn neighbor(&self, id: u64, out: u32, address: IpAddr) -> Option<(u64, u32)> {
        let mut todo = vec![(id, out)];
        let mut visited = BTreeSet::new();
        while let Some(key) = todo.pop() {
            if !visited.insert(key) {
                continue;
            }
            let d = self.device(key.0, key.1).ok()?;
            if !d.up {
                continue;
            }
            if d.namespace != id && d.addresses.iter().any(|a| a.ip == address) {
                return Some((d.namespace, d.index));
            }
            match d.kind {
                DeviceKind::Veth { peer } => {
                    if let Some(p) = self.peer_device(peer) {
                        todo.push((p.namespace, p.index));
                    }
                    if let Some(master) = d.master {
                        todo.push((d.namespace, master));
                    }
                }
                DeviceKind::Bridge => todo.extend(self.devices.iter().filter_map(|(&key, v)| {
                    (v.namespace == d.namespace && v.master == Some(d.index)).then_some(key)
                })),
                _ => {}
            }
        }
        None
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
            DeviceKind::Veth { peer } => self.devices.values().any(|p| p.index == peer && p.up),
            _ => true,
        }
    }
    pub fn account(&mut self, id: u64, index: u32, len: usize, tx: bool, dropped: bool) {
        if let Some(d) = self.devices.get_mut(&(id, index)) {
            let s = &mut d.stats;
            if tx {
                s.tx_packets += 1;
                s.tx_bytes += len as u64;
                s.tx_dropped += u64::from(dropped);
            } else {
                s.rx_packets += 1;
                s.rx_bytes += len as u64;
                s.rx_dropped += u64::from(dropped);
            }
        }
    }
}
impl View {
    pub fn own(&self, ip: IpAddr) -> bool {
        if self.native_root {
            return self.addresses(false).iter().any(|a| a.ip == ip);
        }
        self.graph.borrow().own(self.namespace, ip)
    }
    pub fn source(&self, ip: IpAddr) -> Result<IpAddr> {
        let graph = self.graph.borrow();
        let (source, index, _) = graph.source(self.namespace, ip)?;
        if self.native_root
            && matches!(
                graph.device(self.namespace, index)?.kind,
                DeviceKind::Direct | DeviceKind::Loopback
            )
        {
            return Err(NetError(101));
        }
        Ok(source)
    }
    pub fn addresses(&self, up_only: bool) -> Vec<Address> {
        self.graph
            .borrow()
            .devices(self.namespace)
            .into_iter()
            .filter(|d| {
                (!up_only || d.up)
                    && (!self.native_root
                        || !matches!(d.kind, DeviceKind::Loopback | DeviceKind::Direct))
            })
            .flat_map(|d| d.addresses)
            .collect()
    }
}
