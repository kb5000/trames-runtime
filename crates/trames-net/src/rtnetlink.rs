// SPDX-License-Identifier: GPL-3.0-or-later
//! NETLINK_ROUTE control for guest links; never calls host interface ioctls.
use crate::{
    netdev::{Address, Device, DeviceKind, Route, Topology},
    netlink::{attr, message},
    NetError, Network,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
type Result<T> = std::result::Result<T, NetError>;
fn u32v(v: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(v.try_into().map_err(|_| NetError(22))?))
}
fn attrs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut out = vec![];
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(NetError(22));
        }
        let n = u16::from_le_bytes(bytes[..2].try_into().unwrap()) as usize;
        let kind = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff;
        if n < 4 || n > bytes.len() || out.iter().any(|(k, _)| *k == kind) {
            return Err(NetError(22));
        }
        out.push((kind, &bytes[4..n]));
        if n == bytes.len() {
            break;
        }
        bytes = bytes.get((n + 3) & !3..).ok_or(NetError(22))?;
    }
    Ok(out)
}
fn get<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs.iter().find_map(|(k, v)| (*k == kind).then_some(*v))
}
fn text(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(NetError(22));
    }
    Ok(&bytes[..bytes.len() - 1])
}
fn ip(family: u8, bytes: &[u8]) -> Result<IpAddr> {
    match family {
        2 => Ok(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).map_err(|_| NetError(22))?).into()),
        10 => Ok(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).map_err(|_| NetError(22))?).into()),
        _ => Err(NetError(97)),
    }
}
fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}
pub(crate) fn link_data(g: &Topology, d: &Device) -> Vec<u8> {
    let mut data = vec![0; 16];
    data[2..4].copy_from_slice(
        &(match d.kind {
            DeviceKind::Loopback => 772u16,
            DeviceKind::Direct => 65534,
            _ => 1,
        })
        .to_le_bytes(),
    );
    data[4..8].copy_from_slice(&d.index.to_le_bytes());
    let carrier = g.carrier(d);
    let flags = match d.kind {
        DeviceKind::Loopback => 8 | if d.up { 0x41 } else { 0 },
        DeviceKind::Direct => 0xc1,
        _ => 0x1002 | u32::from(d.up) | if carrier { 0x10040 } else { 0 },
    };
    data[8..12].copy_from_slice(&flags.to_le_bytes());
    data[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut name = d.name.clone();
    name.push(0);
    attr(&mut data, 3, &name);
    attr(&mut data, 4, &d.mtu.to_le_bytes());
    attr(&mut data, 1, &d.mac);
    attr(
        &mut data,
        2,
        &if d.kind == DeviceKind::Loopback {
            [0; 6]
        } else {
            [255; 6]
        },
    );
    attr(
        &mut data,
        16,
        &[if !carrier {
            2
        } else if d.kind == DeviceKind::Loopback {
            0
        } else {
            6
        }],
    );
    attr(&mut data, 33, &[u8::from(carrier)]);
    attr(&mut data, 13, &1000u32.to_le_bytes());
    if let Some(master) = d.master {
        attr(&mut data, 10, &master.to_le_bytes());
    }
    if let DeviceKind::Veth { peer } = d.kind {
        attr(&mut data, 5, &peer.to_le_bytes());
    }
    if matches!(d.kind, DeviceKind::Bridge | DeviceKind::Veth { .. }) {
        let mut info = vec![];
        attr(
            &mut info,
            1,
            if d.kind == DeviceKind::Bridge {
                b"bridge\0"
            } else {
                b"veth\0"
            },
        );
        attr(&mut data, 18, &info);
    }
    let s = d.stats;
    let mut stats = vec![0; 24 * 8];
    for (i, n) in [
        (0, s.rx_packets),
        (1, s.tx_packets),
        (2, s.rx_bytes),
        (3, s.tx_bytes),
        (6, s.rx_dropped),
        (7, s.tx_dropped),
    ] {
        stats[i * 8..(i + 1) * 8].copy_from_slice(&n.to_le_bytes());
    }
    attr(&mut data, 23, &stats);
    data
}
pub(crate) struct Reply {
    pub messages: Vec<Vec<u8>>,
    pub changes: Vec<(u64, u16, u32, Vec<u8>)>,
}
pub(crate) fn request(
    namespace: &crate::netlink::Namespace,
    request: &[u8],
    port: u32,
    admin: bool,
    resolve: &dyn Fn(u32) -> Result<Network>,
) -> Result<Reply> {
    let kind = u16::from_le_bytes(request[4..6].try_into().unwrap());
    let flags = u16::from_le_bytes(request[6..8].try_into().unwrap());
    let seq = u32::from_le_bytes(request[8..12].try_into().unwrap());
    let dump = flags & 0x300 == 0x300;
    let ns = namespace.id();
    let mut graph = namespace.graph.borrow_mut();
    let mut changes = vec![];
    let mut out = vec![];
    let mut execute = || -> Result<()> {
        if flags & !(1 | 4 | 0x100 | 0x200 | 0x400) != 0 {
            return Err(NetError(95));
        }
        match kind {
            16..=19 => {
                if request.len() < 32 {
                    return Err(NetError(22));
                }
                if !matches!(request[16], 0 | 2 | 10) {
                    return Err(NetError(97));
                }
                let a = attrs(&request[32..])?;
                let index = u32v(&request[20..24])?;
                if kind == 18 {
                    let name = get(&a, 3).map(text).transpose()?;
                    let links = graph
                        .devices(ns)
                        .into_iter()
                        .filter(|d| {
                            dump || (index == 0 || d.index == index)
                                && name.is_none_or(|n| n == d.name)
                        })
                        .collect::<Vec<_>>();
                    if !dump && links.is_empty() {
                        return Err(NetError(19));
                    }
                    for d in links {
                        out.push(message(
                            16,
                            if dump { 2 } else { 0 },
                            seq,
                            port,
                            &link_data(&graph, &d),
                        ));
                    }
                    return Ok(());
                }
                if !admin {
                    return Err(NetError(1));
                }
                let change = u32v(&request[28..32])?;
                let state = u32v(&request[24..28])?;
                if change & !1 != 0 || state & change & !1 != 0 {
                    return Err(NetError(95));
                }
                let up = (change & 1 != 0).then_some(state & 1 != 0);
                for &(k, v) in &a {
                    match k {
                        1 => {
                            if v.len() != 6 {
                                return Err(NetError(22));
                            }
                        }
                        3 | 10 | 18 | 28 => {}
                        4 => {
                            if u32v(v)? != 1500 {
                                return Err(NetError(95));
                            }
                        }
                        _ => return Err(NetError(95)),
                    }
                }
                let name = get(&a, 3).map(text).transpose()?;
                let master = get(&a, 10).map(u32v).transpose()?;
                let mac = get(&a, 1)
                    .map(|v| v.try_into().map_err(|_| NetError(22)))
                    .transpose()?;
                let target = get(&a, 28).map(|fd| resolve(u32v(fd)?)).transpose()?;
                if target
                    .as_ref()
                    .is_some_and(|n| !std::rc::Rc::ptr_eq(&n.1.graph, &namespace.graph))
                {
                    return Err(NetError(22));
                }
                let target = target.as_ref().map(Network::namespace_id);
                if let Some(info) = get(&a, 18) {
                    if kind != 16 || flags & 0x400 == 0 || index != 0 || master.is_some() {
                        return Err(NetError(95));
                    }
                    let name = name.ok_or(NetError(22))?;
                    let info = attrs(info)?;
                    if info.iter().any(|(k, _)| !matches!(k, 1 | 2)) {
                        return Err(NetError(95));
                    }
                    let link_kind = text(get(&info, 1).ok_or(NetError(22))?)?;
                    // Prepare the entire pair/update before publishing it.
                    let mut next = graph.clone();
                    let index = match link_kind {
                        b"bridge" => {
                            if target.is_some() {
                                return Err(NetError(95));
                            }
                            if let Some(data) = get(&info, 2) {
                                if !data.is_empty() {
                                    return Err(NetError(95));
                                }
                            }
                            next.create_bridge(ns, name)?
                        }
                        b"veth" => {
                            let info = attrs(get(&info, 2).ok_or(NetError(22))?)?;
                            if info.len() != 1 || info[0].0 != 1 || info[0].1.len() < 16 {
                                return Err(NetError(22));
                            }
                            let peer = info[0].1;
                            if peer[..8] != [0; 8] {
                                return Err(NetError(95));
                            }
                            let pa = attrs(&peer[16..])?;
                            if pa.iter().any(|(k, _)| !matches!(k, 1 | 3 | 4 | 28)) {
                                return Err(NetError(95));
                            }
                            if get(&pa, 4)
                                .map(u32v)
                                .transpose()?
                                .is_some_and(|m| m != 1500)
                            {
                                return Err(NetError(95));
                            }
                            let pn = get(&pa, 28).map(|v| resolve(u32v(v)?)).transpose()?;
                            if pn
                                .as_ref()
                                .is_some_and(|n| !std::rc::Rc::ptr_eq(&n.1.graph, &namespace.graph))
                            {
                                return Err(NetError(22));
                            }
                            let peer_ns = pn.as_ref().map_or(ns, Network::namespace_id);
                            let peer_name = text(get(&pa, 3).ok_or(NetError(22))?)?;
                            let (i, p) = next.create_veth(ns, name, peer_ns, peer_name)?;
                            let pc = u32v(&peer[12..16])?;
                            let pf = u32v(&peer[8..12])?;
                            if pc & !1 != 0 {
                                return Err(NetError(95));
                            }
                            let pm = get(&pa, 1)
                                .map(|v| v.try_into().map_err(|_| NetError(22)))
                                .transpose()?;
                            next.change_link(
                                peer_ns,
                                p,
                                None,
                                None,
                                (pc & 1 != 0).then_some(pf & 1 != 0),
                                None,
                                pm,
                            )?;
                            changes.push((
                                peer_ns,
                                16,
                                1,
                                link_data(&next, &next.device(peer_ns, p)?),
                            ));
                            i
                        }
                        _ => return Err(NetError(95)),
                    };
                    next.change_link(ns, index, None, target, up, None, mac)?;
                    let current = target.unwrap_or(ns);
                    changes.push((
                        current,
                        16,
                        1,
                        link_data(&next, &next.device(current, index)?),
                    ));
                    *graph = next;
                } else {
                    let d = if index == 0 {
                        graph.named(ns, name.ok_or(NetError(22))?)?
                    } else {
                        graph.device(ns, index)?
                    };
                    if kind == 17 {
                        let old = graph.devices(ns); // Includes bridge member detach notifications below.
                        let peer = if let DeviceKind::Veth { peer } = d.kind {
                            graph.peer_device(peer)
                        } else {
                            None
                        };
                        graph.remove_link(ns, d.index)?;
                        changes.push((ns, 17, 1, link_data(&graph, &d)));
                        if let Some(p) = peer {
                            changes.push((p.namespace, 17, 1, link_data(&graph, &p)));
                        }
                        for before in old {
                            if before.master == Some(d.index) {
                                let after = graph.device(ns, before.index)?;
                                changes.push((ns, 16, 1, link_data(&graph, &after)));
                            }
                        }
                    } else {
                        graph.change_link(
                            ns,
                            d.index,
                            (index != 0).then_some(name).flatten(),
                            target,
                            up,
                            master,
                            mac,
                        )?;
                        if target.is_some_and(|to| to != ns) {
                            changes.push((ns, 17, 1, link_data(&graph, &d)));
                        }
                        let current = target.unwrap_or(ns);
                        let d = graph.device(current, d.index)?;
                        changes.push((current, 16, 1, link_data(&graph, &d)));
                    }
                }
            }
            20..=22 => {
                if request.len() < 24 {
                    return Err(NetError(22));
                }
                let family = request[16];
                if !matches!(family, 0 | 2 | 10) {
                    return Err(NetError(97));
                }
                let prefix = request[17];
                let index = u32v(&request[20..24])?;
                let a = attrs(&request[24..])?;
                if kind == 22 {
                    if !dump {
                        return Err(NetError(95));
                    }
                    for d in graph.devices(ns) {
                        if (index == 0 || index == d.index)
                            && (d.kind != DeviceKind::Loopback || d.up)
                        {
                            for address in &d.addresses {
                                if family == 0 || (family == 2) == address.ip.is_ipv4() {
                                    out.push(message(
                                        20,
                                        2,
                                        seq,
                                        port,
                                        &address_data(&d, *address),
                                    ));
                                }
                            }
                        }
                    }
                    return Ok(());
                }
                if !admin {
                    return Err(NetError(1));
                }
                if a.iter().any(|(k, _)| !matches!(k, 1 | 2 | 3 | 4 | 8))
                    || request[18] & !0x80 != 0
                {
                    return Err(NetError(95));
                }
                let addr = ip(
                    family,
                    get(&a, 2).or_else(|| get(&a, 1)).ok_or(NetError(22))?,
                )?;
                if get(&a, 1)
                    .map(|v| ip(family, v))
                    .transpose()?
                    .is_some_and(|v| v != addr)
                {
                    return Err(NetError(95));
                }
                if let Some(label) = get(&a, 3) {
                    if text(label)? != graph.device(ns, index)?.name {
                        return Err(NetError(95));
                    }
                }
                if let Some(f) = get(&a, 8) {
                    if u32v(f)? & !0x80 != 0 {
                        return Err(NetError(95));
                    }
                }
                if let Some(b) = get(&a, 4) {
                    let expected = match addr {
                        IpAddr::V4(ip) if prefix <= 32 => Ipv4Addr::from(
                            u32::from(ip) | u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0),
                        )
                        .octets()
                        .to_vec(),
                        _ => return Err(NetError(95)),
                    };
                    if b != expected {
                        return Err(NetError(95));
                    }
                }
                if request[19] != 0 {
                    return Err(NetError(95));
                }
                let address = Address { ip: addr, prefix };
                graph.address(ns, index, address, kind == 20, flags & 0x100 != 0)?;
                changes.push((
                    ns,
                    kind,
                    if family == 2 { 0x10 } else { 0x100 },
                    address_data(&graph.device(ns, index)?, address),
                ));
            }
            24..=26 => {
                if request.len() < 28 {
                    return Err(NetError(22));
                }
                let family = request[16];
                if !matches!(family, 0 | 2 | 10) {
                    return Err(NetError(97));
                }
                let a = attrs(&request[28..])?;
                if kind == 26 {
                    if !dump {
                        return Err(NetError(95));
                    }
                    for r in graph.routes(ns) {
                        if family == 0 || (family == 2) == r.destination.ip.is_ipv4() {
                            out.push(message(24, 2, seq, port, &route_data(r)));
                        }
                    }
                    return Ok(());
                }
                if !admin {
                    return Err(NetError(1));
                }
                if request[18..20] != [0; 2]
                    || request[20] != 254
                    || !matches!(request[22], 0 | 253)
                    || request[23] != 1
                    || request[24..28] != [0; 4]
                    || a.iter().any(|(k, _)| !matches!(k, 1 | 4 | 5 | 6 | 7))
                {
                    return Err(NetError(95));
                }
                let destination = Address {
                    ip: get(&a, 1)
                        .map(|v| ip(family, v))
                        .transpose()?
                        .unwrap_or(if family == 2 {
                            Ipv4Addr::UNSPECIFIED.into()
                        } else if family == 10 {
                            Ipv6Addr::UNSPECIFIED.into()
                        } else {
                            return Err(NetError(97));
                        }),
                    prefix: request[17],
                };
                if destination.prefix > if family == 2 { 32 } else { 128 } {
                    return Err(NetError(22));
                }
                let device = u32v(get(&a, 4).ok_or(NetError(22))?)?;
                if let Some(source) = get(&a, 7) {
                    if !graph
                        .device(ns, device)?
                        .addresses
                        .iter()
                        .any(|a| ip(family, source) == Ok(a.ip))
                    {
                        return Err(NetError(99));
                    }
                }
                let route = Route {
                    destination,
                    device,
                    gateway: get(&a, 5).map(|v| ip(family, v)).transpose()?,
                    metric: get(&a, 6).map(u32v).transpose()?.unwrap_or(0),
                    protocol: request[21],
                };
                graph.route(
                    ns,
                    route,
                    kind == 24,
                    flags & 0x100 != 0,
                    flags & 0x200 != 0,
                )?;
                changes.push((
                    ns,
                    kind,
                    if family == 2 { 0x40 } else { 0x400 },
                    route_data(route),
                ));
            }
            _ => return Err(NetError(95)),
        }
        Ok(())
    };
    let result = execute();
    if let Err(e) = result {
        let mut data = (-(e.0 as i32)).to_le_bytes().to_vec();
        data.extend_from_slice(&request[..16]);
        return Ok(Reply {
            messages: vec![message(2, 0, seq, port, &data)],
            changes: vec![],
        });
    }
    if dump {
        out.push(message(3, 2, seq, port, &0i32.to_le_bytes()));
    } else if flags & 4 != 0 {
        let mut data = 0i32.to_le_bytes().to_vec();
        data.extend_from_slice(&request[..16]);
        out.push(message(2, 0, seq, port, &data));
    }
    Ok(Reply {
        messages: out,
        changes,
    })
}
fn address_data(d: &Device, a: Address) -> Vec<u8> {
    let mut data = vec![
        if a.ip.is_ipv4() { 2 } else { 10 },
        a.prefix,
        0x80,
        if a.ip.is_loopback() { 254 } else { 0 },
    ];
    data.extend_from_slice(&d.index.to_le_bytes());
    attr(&mut data, 1, &octets(a.ip));
    attr(&mut data, 2, &octets(a.ip));
    let mut name = d.name.clone();
    name.push(0);
    attr(&mut data, 3, &name);
    attr(&mut data, 8, &0x80u32.to_le_bytes());
    data
}
fn route_data(r: Route) -> Vec<u8> {
    let mut data = vec![
        if r.destination.ip.is_ipv4() { 2 } else { 10 },
        r.destination.prefix,
        0,
        0,
        254,
        r.protocol,
        if r.gateway.is_none() { 253 } else { 0 },
        1,
        0,
        0,
        0,
        0,
    ];
    attr(&mut data, 1, &octets(r.destination.ip));
    attr(&mut data, 4, &r.device.to_le_bytes());
    if let Some(g) = r.gateway {
        attr(&mut data, 5, &octets(g));
    }
    if r.metric != 0 {
        attr(&mut data, 6, &r.metric.to_le_bytes());
    }
    data
}
