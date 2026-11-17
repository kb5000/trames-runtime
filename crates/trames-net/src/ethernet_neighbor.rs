// SPDX-License-Identifier: GPL-3.0-or-later
//! Ethernet endpoint ARP/NDP and object-owned resolution queues.
use super::*;
use crate::ethernet::{Action, Frame, Mac, Neighbor};
use std::time::{Duration, Instant};
impl Topology {
    pub fn ethernet_ip(&self, ns: u64, index: u32, target: IpAddr, packet: Vec<u8>) -> Vec<Action> {
        let Ok(d) = self.device(ns, index) else {
            return vec![];
        };
        if !d.up {
            return vec![];
        }
        let multicast=match target {
            IpAddr::V4(ip) if ip.is_multicast()=>{let b=ip.octets();Some([1,0,0x5e,b[1]&127,b[2],b[3]])},
            IpAddr::V4(ip) if ip==Ipv4Addr::BROADCAST || d.addresses.iter().any(|a|matches!(a.ip,IpAddr::V4(v) if u32::from(ip)==(u32::from(v)|u32::MAX.checked_shr(u32::from(a.prefix)).unwrap_or(0))))=>Some([255;6]),
            IpAddr::V6(ip) if ip.is_multicast()=>{let b=ip.octets();Some([0x33,0x33,b[12],b[13],b[14],b[15]])},_=>None,
        };
        if let Some(mac) = multicast {
            return self.ethernet_datagrams(ns, index, mac, packet);
        }
        if let Some(e) = self.spaces[&ns].neighbors.get(&(index, target)) {
            if e.state & (1 | 32) != 0 {
                return vec![];
            }
            if let Some(mac) = e.mac {
                return self.ethernet_datagrams(ns, index, mac, packet);
            }
        }
        let cache = &self.spaces[&ns].neighbor_cache;
        {
            let entries = cache.entries.read();
            if let Some(e) = entries.get(&(index, target)) {
                if let Some(mac) = e.mac {
                    if e.updated.elapsed() < Duration::from_secs(30) {
                        return self.ethernet_datagrams(ns, index, mac, packet);
                    }
                }
            }
        }
        let now = Instant::now();
        let mut entries = cache.entries.write();
        let total = entries
            .values()
            .flat_map(|e| &e.pending)
            .map(Vec::len)
            .sum::<usize>();
        if total + packet.len() > crate::MAX_BUFFER
            || entries.values().map(|e| e.pending.len()).sum::<usize>() >= 96
        {
            return vec![];
        }
        if !entries.contains_key(&(index, target)) && entries.len() >= 1024 {
            return vec![];
        }
        let e = entries.entry((index, target)).or_insert_with(|| Neighbor {
            mac: None,
            state: 1,
            updated: now,
            retry: now,
            probes: 0,
            pending: vec![],
        });
        if e.state == 32 && e.updated.elapsed() < Duration::from_secs(1) {
            return vec![];
        }
        let mut actions = Vec::new();
        if let Some(mac) = e.mac {
            actions.extend(self.ethernet_datagrams(ns, index, mac, packet));
        } else {
            e.pending.push(packet);
        }
        cache.probing.store(true, Relaxed);
        if e.probes == 0 {
            e.probes = 1;
            e.retry = now + Duration::from_secs(1);
            e.state = if e.mac.is_some() { 16 } else { 1 };
            if let Some(frame) = self.neighbor_probe(&d, target) {
                actions.push(Action::Send(ns, index, frame));
            }
        }
        actions
    }
    fn neighbor_probe(&self, d: &Device, target: IpAddr) -> Option<Frame> {
        match target {
            IpAddr::V4(target) => {
                let source = d.addresses.iter().find_map(|a| {
                    if let IpAddr::V4(ip) = a.ip {
                        Some(ip)
                    } else {
                        None
                    }
                })?;
                let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
                arp.extend_from_slice(&d.mac);
                arp.extend_from_slice(&source.octets());
                arp.extend_from_slice(&[0; 6]);
                arp.extend_from_slice(&target.octets());
                Some(Frame::build(d.mac, [255; 6], 0x0806, &arp))
            }
            IpAddr::V6(target) => {
                let source = d.addresses.iter().find_map(|a| {
                    if let IpAddr::V6(ip) = a.ip {
                        Some(ip)
                    } else {
                        None
                    }
                })?;
                let b = target.octets();
                let mut destination = [0u8; 16];
                destination[..2].copy_from_slice(&[0xff, 2]);
                destination[11..13].copy_from_slice(&[1, 0xff]);
                destination[13..].copy_from_slice(&b[13..]);
                let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
                icmp.extend_from_slice(&b);
                icmp.extend_from_slice(&[1, 1]);
                icmp.extend_from_slice(&d.mac);
                Some(Frame::build(
                    d.mac,
                    [0x33, 0x33, 0xff, b[13], b[14], b[15]],
                    0x86dd,
                    &ndp_packet(source, destination.into(), icmp),
                ))
            }
        }
    }
    pub fn ethernet_timers(&self, ns: u64) -> Vec<Action> {
        let Some(space) = self.spaces.get(&ns) else {
            return vec![];
        };
        if !space.neighbor_cache.probing.load(Relaxed) {
            return vec![];
        }
        let now = Instant::now();
        let mut entries = space.neighbor_cache.entries.write();
        let mut actions = vec![];
        for (&(index, target), e) in entries
            .iter_mut()
            .filter(|(_, e)| e.probes != 0 && e.retry <= now)
        {
            if e.probes >= 3 {
                e.mac = None;
                e.state = 32;
                e.pending.clear();
                e.probes = 0;
                e.updated = now;
                continue;
            }
            if let Ok(d) = self.device(ns, index) {
                if let Some(frame) = self.neighbor_probe(&d, target) {
                    actions.push(Action::Send(ns, index, frame));
                }
            }
            e.probes += 1;
            e.retry = now + Duration::from_secs(1);
        }
        space
            .neighbor_cache
            .probing
            .store(entries.values().any(|e| e.probes != 0), Relaxed);
        actions
    }
    fn learn_neighbor(&self, ns: u64, index: u32, ip: IpAddr, mac: Mac) -> Vec<Action> {
        let Some(space) = self.spaces.get(&ns) else {
            return vec![];
        };
        let pending = space.neighbor_cache.learn(index, ip, mac);
        pending
            .into_iter()
            .flat_map(|packet| self.ethernet_datagrams(ns, index, mac, packet))
            .collect()
    }
    fn ethernet_datagrams(&self, ns: u64, index: u32, mac: Mac, packet: Vec<u8>) -> Vec<Action> {
        self.ethernet_ip_frames(ns, index, mac, None, packet)
            .into_iter()
            .map(|f| Action::Send(ns, index, f))
            .collect()
    }
    pub fn ethernet_arrival(
        &self,
        ns: u64,
        index: u32,
        source: Mac,
        packet: Vec<u8>,
    ) -> Vec<Action> {
        let Some(d) = self.devices.get(&(ns, index)) else {
            return vec![];
        };
        self.ethernet_ip_frames(ns, index, d.mac, Some(source), packet)
            .into_iter()
            .map(|f| Action::Receive(ns, index, f))
            .collect()
    }
    fn ethernet_ip_frames(
        &self,
        ns: u64,
        index: u32,
        mac: Mac,
        source: Option<Mac>,
        packet: Vec<u8>,
    ) -> Vec<Frame> {
        let Some(d) = self.devices.get(&(ns, index)) else {
            return vec![];
        };
        let protocol = if packet[0] >> 4 == 4 { 0x0800 } else { 0x86dd };
        let source = source.unwrap_or(d.mac);
        if packet.len() <= d.mtu as usize {
            return vec![Frame::build(source, mac, protocol, &packet)];
        }
        let serial = self.spaces[&ns].ip_serial.fetch_add(1, Relaxed) as u32;
        crate::virtualnet::packet::fragment_link(packet, d.mtu as usize, serial)
            .unwrap_or_default()
            .into_iter()
            .map(|p| Frame::build(source, mac, protocol, &p))
            .collect()
    }
    /// Control messages are consumed here; other protocols enter the L3 stack.
    pub fn ethernet_endpoint(&self, ns: u64, index: u32, f: &Frame) -> (bool, Vec<Action>) {
        if f.vlan().is_some() {
            return (true, vec![]);
        }
        let Ok(d) = self.device(ns, index) else {
            return (true, vec![]);
        };
        let p = f.payload();
        if f.protocol() == 0x0806 {
            if p.len() < 28 || p[..6] != [0, 1, 8, 0, 6, 4] || p[8..14] != f.source() {
                return (true, vec![]);
            }
            let op = u16::from_be_bytes([p[6], p[7]]);
            if !matches!(op, 1 | 2) {
                return (true, vec![]);
            }
            let source = Ipv4Addr::from(<[u8; 4]>::try_from(&p[14..18]).unwrap());
            let target = Ipv4Addr::from(<[u8; 4]>::try_from(&p[24..28]).unwrap());
            let mut actions = self.learn_neighbor(ns, index, source.into(), f.source());
            if op == 1 && d.addresses.iter().any(|a| a.ip == IpAddr::V4(target)) {
                let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 2];
                arp.extend_from_slice(&d.mac);
                arp.extend_from_slice(&target.octets());
                arp.extend_from_slice(&f.source());
                arp.extend_from_slice(&source.octets());
                actions.push(Action::Send(
                    ns,
                    index,
                    Frame::build(d.mac, f.source(), 0x0806, &arp),
                ));
            }
            return (true, actions);
        }
        if f.protocol() == 0x86dd && p.len() >= 64 && p[6] == 58 && matches!(p[40], 135 | 136) {
            if p[7] != 255 || p[41] != 0 || !crate::virtualnet::packet::valid_transport(p) {
                return (true, vec![]);
            }
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
            let target = Ipv6Addr::from(<[u8; 16]>::try_from(&p[48..64]).unwrap());
            if target.is_multicast() {
                return (true, vec![]);
            }
            let mut options = &p[64..];
            let mut mac = None;
            while !options.is_empty() {
                if options.len() < 2
                    || options[1] == 0
                    || usize::from(options[1]) * 8 > options.len()
                {
                    return (true, vec![]);
                }
                let len = usize::from(options[1]) * 8;
                if options[0] == if p[40] == 135 { 1 } else { 2 } {
                    if len != 8 {
                        return (true, vec![]);
                    }
                    mac = Some(<[u8; 6]>::try_from(&options[2..8]).unwrap());
                }
                options = &options[len..];
            }
            if mac.is_some_and(|m| m != f.source()) {
                return (true, vec![]);
            }
            let mut actions = if p[40] == 136 {
                if source.is_unspecified() {
                    return (true, vec![]);
                }
                mac.map_or_else(Vec::new, |m| {
                    self.learn_neighbor(ns, index, target.into(), m)
                })
            } else {
                if source.is_unspecified() && mac.is_some() {
                    return (true, vec![]);
                }
                mac.map_or_else(Vec::new, |m| {
                    self.learn_neighbor(ns, index, source.into(), m)
                })
            };
            if p[40] == 135 && d.addresses.iter().any(|a| a.ip == IpAddr::V6(target)) {
                let (destination, dm, flags) = if source.is_unspecified() {
                    ("ff02::1".parse().unwrap(), [0x33, 0x33, 0, 0, 0, 1], 0x20u8)
                } else {
                    (source, f.source(), 0x60u8)
                };
                let mut icmp = vec![
                    136,
                    0,
                    0,
                    0,
                    flags | if self.forwarding(ns, true) { 0x80 } else { 0 },
                    0,
                    0,
                    0,
                ];
                icmp.extend_from_slice(&target.octets());
                icmp.extend_from_slice(&[2, 1]);
                icmp.extend_from_slice(&d.mac);
                actions.push(Action::Send(
                    ns,
                    index,
                    Frame::build(d.mac, dm, 0x86dd, &ndp_packet(target, destination, icmp)),
                ));
            }
            return (true, actions);
        }
        (!matches!(f.protocol(), 0x0800 | 0x86dd), vec![])
    }
}
fn ndp_packet(source: Ipv6Addr, destination: Ipv6Addr, mut icmp: Vec<u8>) -> Vec<u8> {
    smoltcp::wire::Icmpv6Packet::new_unchecked(&mut icmp).fill_checksum(&source, &destination);
    let mut p = vec![0; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    p[6] = 58;
    p[7] = 255;
    p[8..24].copy_from_slice(&source.octets());
    p[24..40].copy_from_slice(&destination.octets());
    p.extend_from_slice(&icmp);
    p
}
pub(crate) fn ethernet_gateway(f: &Frame, mac: Mac, v4: Ipv4Addr, v6: Ipv6Addr) -> Option<Frame> {
    let p = f.payload();
    if f.vlan().is_some() {
        return None;
    }
    if f.protocol() == 0x0806
        && p.len() >= 28
        && p[..8] == [0, 1, 8, 0, 6, 4, 0, 1]
        && p[24..28] == v4.octets()
        && p[8..14] == f.source()
    {
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 2];
        arp.extend_from_slice(&mac);
        arp.extend_from_slice(&v4.octets());
        arp.extend_from_slice(&f.source());
        arp.extend_from_slice(&p[14..18]);
        return Some(Frame::build(mac, f.source(), 0x0806, &arp));
    }
    if f.protocol() == 0x86dd
        && p.len() >= 64
        && p[6] == 58
        && p[7] == 255
        && p[40..42] == [135, 0]
        && p[48..64] == v6.octets()
        && crate::virtualnet::packet::valid_transport(p)
    {
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
        let (destination, dm, flags) = if source.is_unspecified() {
            ("ff02::1".parse().unwrap(), [0x33, 0x33, 0, 0, 0, 1], 0xa0)
        } else {
            (source, f.source(), 0xe0)
        };
        let mut icmp = vec![136, 0, 0, 0, flags, 0, 0, 0];
        icmp.extend_from_slice(&v6.octets());
        icmp.extend_from_slice(&[2, 1]);
        icmp.extend_from_slice(&mac);
        return Some(Frame::build(
            mac,
            dm,
            0x86dd,
            &ndp_packet(v6, destination, icmp),
        ));
    }
    None
}
impl Topology {
    pub fn neighbor_delay(&self, ns: u64) -> Option<Duration> {
        let s = self.spaces.get(&ns)?;
        if !s.neighbor_cache.probing.load(Relaxed) {
            return None;
        }
        s.neighbor_cache
            .entries
            .read()
            .values()
            .filter(|e| e.probes != 0)
            .map(|e| e.retry.saturating_duration_since(Instant::now()))
            .min()
    }
}
