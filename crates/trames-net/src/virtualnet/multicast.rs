// SPDX-License-Identifier: GPL-3.0-or-later
//! IPv4 group delivery on the guest's selected link.
use super::*;
use crate::{Device, DeviceKind};
use smoltcp::wire::{IpProtocol, IpRepr, UdpPacket, UdpRepr};

pub(super) fn group(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if v.is_multicast() || v.is_broadcast())
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
    groups: Vec<(Ipv4Addr, u32)>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            interface: 0,
            address: Ipv4Addr::UNSPECIFIED,
            ttl: 1,
            loopback: true,
            all: true,
            groups: Vec::new(),
        }
    }
}
impl State {
    pub(super) fn multicast_value(&self, name: u32) -> i32 {
        let options = self.multicast.as_deref();
        match name {
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
    fn group_link(&self, index: u32, address: IpAddr, dest: IpAddr) -> Result<(Device, Ipv4Addr)> {
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
        let local = dev
            .addresses
            .iter()
            .find_map(|a| match a.ip {
                IpAddr::V4(v) if address.is_unspecified() || address == a.ip => Some(v),
                _ => None,
            })
            .ok_or(NetError(99))?;
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
            let address = if index != 0 && name != 32 {
                Ipv4Addr::UNSPECIFIED
            } else {
                local
            };
            self.group_link(index, address.into(), group.into())?
                .0
                .index
        };
        let mut state = self.state.borrow_mut();
        let o = state.multicast.get_or_insert_with(Default::default);
        match name {
            32 => {
                o.interface = key;
                o.address = local;
            }
            35 => {
                if o.groups.contains(&(group, key)) {
                    return Err(NetError(98));
                }
                if o.groups.len() >= 20 {
                    return Err(NetError(105));
                }
                o.groups.push((group, key));
            }
            36 => {
                let pos = o
                    .groups
                    .iter()
                    .position(|m| *m == (group, key))
                    .ok_or(NetError(99))?;
                o.groups.swap_remove(pos);
            }
            _ => unreachable!(),
        }
        Ok(())
    }
    pub(super) fn group_source(
        &self,
        dest: SocketAddr,
        info: Option<crate::PacketInfo>,
    ) -> Result<(Device, Ipv4Addr)> {
        let state = self.state.borrow();
        if !dest.ip().is_multicast() && !state.broadcast {
            return Err(NetError(13));
        }
        let mc = state
            .multicast
            .as_deref()
            .filter(|_| dest.ip().is_multicast());
        let index = info.map_or(0, |i| i.interface);
        let index = if index != 0 {
            index
        } else {
            state
                .device
                .unwrap_or_else(|| mc.map_or(0, |o| o.interface))
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
            .unwrap_or_else(|| IpAddr::V4(mc.map_or(Ipv4Addr::UNSPECIFIED, |o| o.address)));
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
        if dest.port() == 0 {
            return Err(NetError(22));
        }
        if bytes.len() > 65507 {
            return Err(NetError(90));
        }
        let (dev, source) = self.group_source(dest, control.packet_info)?;
        self.ensure_bound()?;
        let state = self.state.borrow();
        if state.write_closed {
            return Err(NetError(32));
        }
        let port = state.bound.ok_or(NetError(22))?.port();
        let multicast = dest.ip().is_multicast();
        let ttl = control.fields[0].hop_limit.unwrap_or_else(|| {
            if multicast {
                state.multicast_value(33) as u8
            } else {
                state.udp_options[0]
                    .fields
                    .hop_limit
                    .unwrap_or(state.hop_limit)
            }
        });
        let class = control.fields[0]
            .traffic_class
            .or(state.udp_options[0].fields.traffic_class)
            .unwrap_or(0);
        let no_checksum = state.no_check;
        let loopback = !multicast || dev.index == 1 || state.multicast_value(34) != 0;
        drop(state);
        let view = self.network.0.routing.get().ok_or(NetError(95))?;
        let mut packet =
            crate::conntrack::message(SocketAddr::new(source.into(), port), dest, 17, 0, bytes);
        if no_checksum {
            // conntrack::message constructs a 20-byte IPv4 header.
            packet[26..28].fill(0);
        }
        packet[1] = class;
        packet[8] = ttl;
        smoltcp::wire::Ipv4Packet::new_unchecked(&mut packet).fill_checksum();
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        if !view.graph.read().unwrap().udp_group_hooks(
            view.namespace,
            dev.index,
            false,
            &mut packet,
        ) {
            return Ok(bytes.len());
        }
        if loopback {
            let mut local = packet.clone();
            fabric.group_input(self.network.0.key, view, dev.index, &mut local);
        }
        if dev.index != 1 && ttl != 0 {
            let IpAddr::V4(v) = dest.ip() else {
                unreachable!()
            };
            let [_, b, c, d] = v.octets();
            let mac = if multicast {
                [1, 0, 94, b & 127, c, d]
            } else {
                [255; 6]
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
        if !view
            .graph
            .read()
            .unwrap()
            .udp_group_hooks(view.namespace, index, true, packet)
        {
            return;
        }
        let Some(header) = packet::header(packet) else {
            return;
        };
        let src = header.tuple.source;
        let dst = header.tuple.destination;
        let IpAddr::V4(group_ip) = dst.ip() else {
            return;
        };
        let Ok(udp) = UdpPacket::new_checked(&packet[header.offset..]) else {
            return;
        };
        let membership = (group_ip, index);
        if group_ip.is_multicast()
            && group_ip != Ipv4Addr::new(224, 0, 0, 1)
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
        meta.hop_limit = Some(packet[8]);
        meta.traffic_class = packet[1];
        meta.ingress_index = index;
        let ip_repr = IpRepr::new(
            ip(src.ip()),
            ip(dst.ip()),
            IpProtocol::Udp,
            udp.len() as usize,
            packet[8],
        );
        let udp_repr = UdpRepr {
            src_port: src.port(),
            dst_port: dst.port(),
        };
        for s in node
            .registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|s| s.kind == 2)
        {
            let state = s.state.borrow();
            let Some(bound) = state.bound else { continue };
            if bound.port() != dst.port()
                || !bound.ip().is_unspecified() && bound.ip() != dst.ip()
                || (s.family == 10 && state.v6_only)
                || state.device.is_some_and(|d| d != index)
                || state.peer.is_some_and(|p| p.port() != 0 && p != src)
            {
                continue;
            }
            if group_ip.is_multicast()
                && state
                    .multicast
                    .as_ref()
                    .is_some_and(|o| !o.all && !o.groups.contains(&membership))
            {
                continue;
            }
            if let Some(&h) = state.handles.iter().find(|&&h| {
                node.sockets
                    .get::<udp::Socket>(h)
                    .endpoint()
                    .addr
                    .is_some_and(|a| addr(a).is_ipv4())
            }) {
                node.sockets.get_mut::<udp::Socket>(h).process(
                    node.iface.context(),
                    meta,
                    &ip_repr,
                    &udp_repr,
                    udp.payload(),
                );
            }
        }
    }
}
