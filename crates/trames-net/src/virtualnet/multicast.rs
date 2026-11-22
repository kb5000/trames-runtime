// SPDX-License-Identifier: GPL-3.0-or-later
//! UDP group delivery on the guest's selected link.
use super::*;
use crate::{Device, DeviceKind};
use smoltcp::wire::{IpProtocol, IpRepr, UdpPacket, UdpRepr};

pub(super) fn group(ip: IpAddr) -> bool {
    ip.is_multicast() || matches!(ip, IpAddr::V4(v) if v.is_broadcast())
}

pub(super) fn group_on(
    view: Option<&crate::netdev::View>,
    interface: Option<u32>,
    ip: IpAddr,
) -> bool {
    // /31 and /32 have no broadcast. Every directed broadcast on a shorter
    // prefix ends in two one bits, so most unicast sends avoid the graph.
    group(ip)
        || matches!(ip, IpAddr::V4(v) if u32::from(v) & 3 == 3 &&
        view.is_some_and(|vnet| vnet.graph.read().unwrap().directed_broadcast(vnet.namespace,interface,v)))
}

pub(super) struct Options {
    interface: u32,
    address: Ipv4Addr,
    ttl: u8,
    loopback: bool,
    all: bool,
    pub(super) v6_interface: u32,
    v6_hops: u8,
    v6_loop: bool,
    v6_all: bool,
    groups: Vec<(IpAddr, u32)>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            interface: 0,
            address: Ipv4Addr::UNSPECIFIED,
            ttl: 1,
            loopback: true,
            all: true,
            v6_interface: 0,
            v6_hops: 1,
            v6_loop: true,
            v6_all: true,
            groups: Vec::new(),
        }
    }
}
impl State {
    fn change_membership(&mut self, group: IpAddr, index: u32, join: bool) -> Result<()> {
        let o = self.multicast.get_or_insert_with(Default::default);
        let at = o
            .groups
            .iter()
            .position(|&(ip, i)| ip == group && (index == 0 || i == index));
        if join {
            if at.is_some() {
                return Err(NetError(98));
            }
            if group.is_ipv4() && o.groups.iter().filter(|(ip, _)| ip.is_ipv4()).count() >= 20 {
                return Err(NetError(105));
            }
            o.groups.push((group, index));
        } else {
            o.groups.swap_remove(at.ok_or(NetError(99))?);
        }
        Ok(())
    }
    pub(super) fn accepts_raw(&self, tuple: packet::Tuple, index: u32) -> bool {
        self.bound
            .is_none_or(|a| a.ip().is_unspecified() || a.ip() == tuple.destination.ip())
            && self.peer.is_none_or(|a| a.ip() == tuple.source.ip())
            && self.device.is_none_or(|d| d == index)
    }

    pub(super) fn multicast_value(&self, name: u32) -> i32 {
        let options = self.multicast.as_deref();
        match name {
            17 => options.map_or(0, |o| o.v6_interface as i32),
            18 => i32::from(options.map_or(1, |o| o.v6_hops)),
            19 => i32::from(options.is_none_or(|o| o.v6_loop)),
            29 => i32::from(options.is_none_or(|o| o.v6_all)),
            32 => i32::from_ne_bytes(
                options
                    .map_or(Ipv4Addr::UNSPECIFIED, |o| o.address)
                    .octets(),
            ),
            33 => i32::from(options.map_or(1, |o| o.ttl)),
            34 => i32::from(options.is_none_or(|o| o.loopback)),
            49 => i32::from(options.is_none_or(|o| o.all)),
            _ => unreachable!(),
        }
    }
    pub(super) fn multicast_scalar(&mut self, name: u32, value: i32) -> Result<()> {
        let o = self.multicast.get_or_insert_with(Default::default);
        match name {
            18 if value == -1 => o.v6_hops = 1,
            18 => o.v6_hops = value.try_into().map_err(|_| NetError(22))?,
            19 if matches!(value, 0 | 1) => o.v6_loop = value != 0,
            29 => o.v6_all = value != 0,
            33 if value == -1 => o.ttl = 1,
            33 => o.ttl = value.try_into().map_err(|_| NetError(22))?,
            34 => o.loopback = value != 0,
            49 if matches!(value, 0 | 1) => o.all = value != 0,
            _ => return Err(NetError(22)),
        }
        Ok(())
    }
}

impl Socket {
    pub(super) fn udp_group(&self, ip: IpAddr) -> bool {
        group_on(self.network.0.routing.get(), None, ip)
    }
    fn group_link(&self, index: u32, address: IpAddr, dest: IpAddr) -> Result<(Device, IpAddr)> {
        let view = self.network.0.routing.get().ok_or(NetError(95))?;
        let graph = view.graph.read().unwrap();
        let dev = if index != 0 {
            graph.device(view.namespace, index)?
        } else if !address.is_unspecified() {
            graph
                .devices(view.namespace)
                .into_iter()
                .find(|d| d.addresses.iter().any(|a| a.ip == address))
                .ok_or(NetError(99))?
        } else {
            let (_, idx, _) = graph.source_for(
                view.namespace,
                dest,
                crate::netdev::RouteContext {
                    mark: self.mark.get(),
                    uid: self.uid.get(),
                    device: None,
                },
            )?;
            graph.device(view.namespace, idx)?
        };
        let local = if address.is_unspecified() {
            // Link-scoped multicast uses the link-local source when one is present.
            crate::netdev::source_address(&dev.addresses, dest).ok_or(NetError(99))?
        } else {
            // Linux accepts a local source belonging to another link when the
            // caller independently selects the egress interface.
            if address.is_ipv4() != dest.is_ipv4()
                || !(dev.addresses.iter().any(|a| a.ip == address)
                    || address.is_ipv4() && graph.own(view.namespace, address))
            {
                return Err(NetError(99));
            }
            address
        };
        Ok((dev, local))
    }
    pub(super) fn membership(&self, name: u32, bytes: &[u8]) -> Result<()> {
        let addr = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        if bytes.len() < if name == 32 { 4 } else { 8 } {
            return Err(NetError(22));
        }
        let group = addr(bytes);
        let local = if bytes.len() >= 8 {
            addr(&bytes[4..])
        } else {
            group
        };
        let index = bytes
            .get(8..12)
            .map_or(0, |v| u32::from_ne_bytes(v.try_into().unwrap()));
        if name != 32 && !group.is_multicast() {
            return Err(NetError(22));
        }
        let key = if name == 32 && local.is_unspecified() && index == 0 {
            0
        } else {
            let address = if index != 0 {
                Ipv4Addr::UNSPECIFIED
            } else {
                local
            };
            self.group_link(index, address.into(), group.into())
                .map_err(|err| match (name, err.0) {
                    (32, 19) => NetError(99),
                    (35 | 36, 99 | 101) => NetError(19),
                    _ => err,
                })?
                .0
                .index
        };
        let mut state = self.state.borrow_mut();
        if name == 32 {
            if key != 0 && state.device.is_some_and(|bound| bound != key) {
                return Err(NetError(22));
            }
            let o = state.multicast.get_or_insert_with(Default::default);
            o.interface = key;
            o.address = local;
            return Ok(());
        }
        state.change_membership(group.into(), key, name == 35)
    }

    pub(super) fn ipv6_membership(&self, join: bool, value: &[u8]) -> Result<()> {
        let req = value.get(..20).ok_or(NetError(22))?;
        let group = Ipv6Addr::from(<[u8; 16]>::try_from(&req[..16]).unwrap());
        if !group.is_multicast() {
            return Err(NetError(22));
        }
        let index = u32::from_ne_bytes(req[16..].try_into().unwrap());
        let mut state = self.state.borrow_mut();
        if !join {
            return state.change_membership(group.into(), index, false);
        }
        if index == 0
            && state
                .multicast
                .as_ref()
                .is_some_and(|o| o.groups.iter().any(|&(ip, _)| ip == group))
        {
            return Err(NetError(98));
        }
        let (dev, _) = self
            .group_link(index, Ipv6Addr::UNSPECIFIED.into(), group.into())
            .map_err(|e| if e == NetError(101) { NetError(19) } else { e })?;
        state.change_membership(group.into(), dev.index, true)
    }
    pub(super) fn group_source(
        &self,
        dest: SocketAddr,
        info: Option<crate::PacketInfo>,
    ) -> Result<(Device, IpAddr)> {
        let state = self.state.borrow();
        if !dest.ip().is_multicast() && !state.broadcast {
            return Err(NetError(13));
        }
        let mc = state
            .multicast
            .as_deref()
            .filter(|_| dest.ip().is_multicast());
        let scope = match dest {
            SocketAddr::V6(a) => a.scope_id(),
            _ => 0,
        };
        let index = info
            .map(|i| i.interface)
            .filter(|i| *i != 0)
            .unwrap_or(scope);
        let index = if index != 0 {
            index
        } else {
            state.device.unwrap_or_else(|| {
                mc.map_or(0, |o| {
                    if dest.is_ipv4() {
                        o.interface
                    } else {
                        o.v6_interface
                    }
                })
            })
        };
        if state.device.is_some_and(|d| d != index) {
            return Err(NetError(22));
        }
        let local = info
            .map(|p| p.address)
            .filter(|a| !a.is_unspecified())
            .or_else(|| {
                state
                    .bound
                    .map(|b| b.ip())
                    .filter(|a| !a.is_unspecified() && !self.udp_group(*a))
            })
            .unwrap_or_else(|| {
                if dest.is_ipv6() {
                    Ipv6Addr::UNSPECIFIED.into()
                } else {
                    IpAddr::V4(mc.map_or(Ipv4Addr::UNSPECIFIED, |o| o.address))
                }
            });
        drop(state);
        let (dev, local) = self.group_link(index, local, dest.ip())?;
        if self.network.0.mode == NetworkMode::Off
            || self.network.0.mode == NetworkMode::Loopback && dev.index != 1
        {
            return Err(NetError(13));
        }
        if !dev.up {
            return Err(NetError(100));
        }
        if dev.index != 1
            && !matches!(
                dev.kind,
                DeviceKind::Ethernet
                    | DeviceKind::Bridge
                    | DeviceKind::Tap
                    | DeviceKind::Veth { .. }
            )
        {
            return Err(NetError(95));
        }
        let view = self.network.0.routing.get().ok_or(NetError(95))?;
        view.graph.read().unwrap().check_group_output(
            view.namespace,
            dest.ip(),
            crate::netdev::RouteContext {
                uid: self.uid.get(),
                mark: self.mark.get(),
                device: Some(dev.index),
            },
        )?;
        Ok((dev, local))
    }
    pub(super) fn send_group(
        &self,
        dest: SocketAddr,
        bytes: &[u8],
        control: crate::DatagramControl,
    ) -> Result<usize> {
        let hdrincl = self.kind == 4 && self.state.borrow().header_included;
        if !hdrincl && self.raw_udp() && bytes.len() < 8 {
            return Err(NetError(22));
        }
        if self.kind == 2 && dest.port() == 0 {
            return Err(NetError(22));
        }
        let v6 = dest.is_ipv6();
        if bytes.len()
            > if hdrincl {
                if v6 {
                    65575
                } else {
                    65535
                }
            } else if self.raw_udp() {
                65515
            } else if v6 {
                65527
            } else {
                65507
            }
        {
            return Err(NetError(90));
        }
        let (dev, source) = self.group_source(dest, control.packet_info)?;
        if hdrincl && bytes.len() > dev.mtu as usize {
            return Err(NetError(90));
        }
        let policy = self.state.borrow().ipv4_pmtu;
        if !v6 && self.kind == 2 && policy.enforce_mtu() && bytes.len() + 28 > dev.mtu as usize {
            return Err(self.udp_too_big(dest, dev.mtu));
        }
        self.ensure_bound()?;
        let state = self.state.borrow();
        if state.write_closed {
            return Err(NetError(32));
        }
        let port = state.bound.ok_or(NetError(22))?.port();
        let multicast = dest.ip().is_multicast();
        let ttl = control.fields[usize::from(v6)]
            .hop_limit
            .unwrap_or_else(|| {
                if multicast {
                    state.multicast_value(if v6 { 18 } else { 33 }) as u8
                } else {
                    state.udp_options[usize::from(v6)]
                        .fields
                        .hop_limit
                        .unwrap_or(state.hop_limit)
                }
            });
        let class = control.fields[usize::from(v6)]
            .traffic_class
            .or(state.udp_options[usize::from(v6)].fields.traffic_class)
            .unwrap_or(0);
        let no_checksum = state.no_check;
        let loopback =
            !multicast || dev.index == 1 || state.multicast_value(if v6 { 19 } else { 34 }) != 0;
        drop(state);
        let view = self.network.0.routing.get().ok_or(NetError(95))?;
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let mut packet = if hdrincl {
            let port = &mut fabric
                .nodes
                .get_mut(&self.network.0.key)
                .ok_or(NetError(100))?
                .port;
            let (packet, _) = port.complete_raw_header(bytes, source)?;
            if packet::header(&packet).is_none_or(|h| h.protocol != 17) {
                return Err(NetError(95));
            }
            packet
        } else if self.raw_udp() {
            let (IpAddr::V4(source), IpAddr::V4(destination)) = (source, dest.ip()) else {
                return Err(NetError(97));
            };
            packet::raw_ipv4(source, destination, self.protocol, ttl, bytes)
        } else {
            let mut packet =
                crate::conntrack::message(SocketAddr::new(source, port), dest, 17, 0, bytes);
            if no_checksum && !v6 {
                packet[26..28].fill(0);
            }
            packet
        };
        let ttl = if hdrincl {
            packet[if v6 { 7 } else { 8 }]
        } else {
            ttl
        };
        if v6 && !hdrincl {
            let mut header = smoltcp::wire::Ipv6Packet::new_unchecked(&mut packet);
            header.set_traffic_class(class);
            header.set_hop_limit(ttl);
        } else if !hdrincl {
            packet[1] = class;
            packet[8] = ttl;
            let mut header = smoltcp::wire::Ipv4Packet::new_unchecked(&mut packet);
            if self.kind == 2 {
                header.set_dont_frag(policy.udp_df() && bytes.len() + 28 <= dev.mtu as usize);
            }
            header.fill_checksum();
        }
        if !view
            .graph
            .read()
            .unwrap()
            .udp_group_hooks(view.namespace, dev.index, None, &mut packet)
        {
            return Ok(bytes.len());
        }
        if loopback {
            let mut local = packet.clone();
            let packet_type = if multicast {
                PacketType::Multicast
            } else {
                PacketType::Broadcast
            };
            fabric.group_input(self.network.0.key, view, dev.index, packet_type, &mut local);
        }
        let interface_local = matches!(dest.ip(), IpAddr::V6(a) if a.octets()[1] & 0x0f == 1);
        if dev.index != 1 && ttl != 0 && !interface_local {
            let mac = match dest.ip() {
                IpAddr::V4(ip) if multicast => {
                    let [_, b, c, d] = ip.octets();
                    [1, 0, 94, b & 127, c, d]
                }
                IpAddr::V4(_) => [255; 6],
                IpAddr::V6(ip) => {
                    let b = ip.octets();
                    [0x33, 0x33, b[12], b[13], b[14], b[15]]
                }
            };
            let actions = view.graph.read().unwrap().ethernet_datagrams(
                view.namespace,
                dev.index,
                mac,
                packet,
            );
            fabric.queue_frames(view, actions);
        }
        fabric.tick();
        Ok(bytes.len())
    }
}

impl Inner {
    pub(super) fn group_input(
        &mut self,
        key: u64,
        view: &crate::netdev::View,
        index: u32,
        packet_type: PacketType,
        packet: &mut [u8],
    ) {
        let Some(node) = self.nodes.get_mut(&key) else {
            return;
        };
        if !node.owner.upgrade().is_some_and(|owner| {
            owner.mode != NetworkMode::Off && (index == 1 || owner.mode != NetworkMode::Loopback)
        }) {
            return;
        }
        if !view.graph.read().unwrap().udp_group_hooks(
            view.namespace,
            index,
            Some(packet_type),
            packet,
        ) {
            return;
        }
        let Some(header) = packet::header(packet) else {
            return;
        };
        let src = header.tuple.source;
        let dst = header.tuple.destination;
        let group_ip = dst.ip();
        let v6 = group_ip.is_ipv6();
        let Ok(udp) = UdpPacket::new_checked(&packet[header.offset..]) else {
            return;
        };
        if v6 && (udp.checksum() == 0 || !udp.verify_checksum(&ip(src.ip()), &ip(dst.ip()))) {
            return;
        }
        let membership = (group_ip, index);
        if group_ip.is_multicast()
            && group_ip != Ipv4Addr::new(224, 0, 0, 1)
            && group_ip != Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)
            && group_ip != Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1)
            && !node.registry.iter().filter_map(Weak::upgrade).any(|s| {
                s.state
                    .borrow()
                    .multicast
                    .as_ref()
                    .is_some_and(|o| o.groups.contains(&membership))
            })
        {
            return;
        }
        let mut meta = smoltcp::phy::PacketMeta::default();
        let hops = packet[if v6 { 7 } else { 8 }];
        meta.hop_limit = Some(hops);
        meta.traffic_class = if v6 {
            (packet[0] << 4) | (packet[1] >> 4)
        } else {
            packet[1]
        };
        meta.ingress_index = index;
        let ip_repr = IpRepr::new(
            ip(src.ip()),
            ip(dst.ip()),
            IpProtocol::Udp,
            udp.len() as usize,
            hops,
        );
        let udp_repr = UdpRepr {
            src_port: src.port(),
            dst_port: dst.port(),
        };
        for s in node
            .registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|s| s.kind == 2 || s.raw_udp())
        {
            let state = s.state.borrow();
            if s.raw_udp() {
                if !v6
                    && state.accepts_raw(header.tuple, index)
                    && (!group_ip.is_multicast()
                        || state
                            .multicast
                            .as_ref()
                            .is_none_or(|o| o.all || o.groups.contains(&membership)))
                {
                    if let Some(handle) = state.handles.first() {
                        node.sockets
                            .get_mut::<raw::Socket>(*handle)
                            .enqueue_ip_packet(packet, index);
                    }
                }
                continue;
            }
            let Some(bound) = state.bound else { continue };
            if bound.port() != dst.port()
                || !bound.ip().is_unspecified() && bound.ip() != dst.ip()
                || if v6 {
                    s.family != 10 || bound.is_ipv4()
                } else {
                    s.family == 10 && state.v6_only
                }
                || state.device.is_some_and(|d| d != index)
                || state.peer.is_some_and(|p| p.port() != 0 && p != src)
            {
                continue;
            }
            if group_ip.is_multicast()
                && state.multicast.as_ref().is_some_and(|o| {
                    !(if v6 { o.v6_all } else { o.all }) && !o.groups.contains(&membership)
                })
            {
                continue;
            }
            if let Some(&h) = state.handles.iter().find(|&&h| {
                node.sockets
                    .get::<udp::Socket>(h)
                    .endpoint()
                    .addr
                    .is_some_and(|a| addr(a).is_ipv6() == v6)
            }) {
                node.sockets.get_mut::<udp::Socket>(h).process_wire(
                    node.iface.context(),
                    meta,
                    &ip_repr,
                    &udp_repr,
                    &udp,
                );
            }
        }
    }
}
