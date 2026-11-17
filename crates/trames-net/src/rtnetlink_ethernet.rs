// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux bridge FDB, port and VLAN controls over the original NETLINK_ROUTE socket.
use super::*;
use crate::ethernet::{BridgeConfig, FdbEntry, PortConfig};
fn boolean(bytes: &[u8]) -> Result<bool> {
    match bytes {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(NetError(22)),
    }
}
pub(super) fn bridge_config(bytes: &[u8], mut config: BridgeConfig) -> Result<BridgeConfig> {
    for (kind, v) in attrs(bytes)? {
        match kind {
            4 => config.ageing = u32v(v)?,
            7 => config.vlan_filtering = boolean(v)?,
            5 if u32v(v)? == 0 => (),
            8 if v == 0x8100u16.to_be_bytes() => (),
            23 if !boolean(v)? => (),
            _ => return Err(NetError(95)),
        }
    }
    Ok(config)
}
fn port_config(bytes: &[u8], mut config: PortConfig) -> Result<PortConfig> {
    for (kind, v) in attrs(bytes)? {
        match kind {
            1 if v.len() == 1 && v[0] <= 4 => config.state = v[0],
            4 => config.hairpin = boolean(v)?,
            8 => config.learning = boolean(v)?,
            9 => config.flood = boolean(v)?,
            27 => config.multicast_flood = boolean(v)?,
            30 => config.broadcast_flood = boolean(v)?,
            _ => return Err(NetError(95)),
        }
    }
    Ok(config)
}
fn vlan_config(bytes: &[u8], mut config: PortConfig, add: bool) -> Result<PortConfig> {
    let mut range = None;
    for (kind, v) in repeated_attrs(bytes)? {
        match kind {
            0 if v == 1u16.to_le_bytes() || v == 2u16.to_le_bytes() => (),
            2 if v.len() == 4 => {
                let flags = u16::from_le_bytes(v[..2].try_into().unwrap());
                let vid = u16::from_le_bytes(v[2..].try_into().unwrap());
                if flags & !(2 | 4 | 8 | 16) != 0 || flags & 24 == 24 {
                    return Err(NetError(95));
                }
                if flags & 8 != 0 {
                    if range.is_some() || flags & 2 != 0 {
                        return Err(NetError(22));
                    }
                    range = Some((vid, flags & 6));
                } else if flags & 16 != 0 {
                    let (start, f) = range.take().ok_or(NetError(22))?;
                    if start > vid || flags & 6 != f {
                        return Err(NetError(22));
                    }
                    for vid in start..=vid {
                        config.vlan(vid, f, add)?;
                    }
                } else {
                    if range.is_some() {
                        return Err(NetError(22));
                    }
                    config.vlan(vid, flags, add)?;
                }
            }
            _ => return Err(NetError(95)),
        }
    }
    if range.is_some() {
        return Err(NetError(22));
    }
    Ok(config)
}
pub(super) fn fdb_data(master: u32, e: FdbEntry) -> Vec<u8> {
    let mut d = vec![0; 12];
    d[0] = 7;
    d[4..8].copy_from_slice(&e.port.to_le_bytes());
    d[8..10].copy_from_slice(
        &(if e.local {
            128u16
        } else if e.permanent {
            64
        } else {
            2
        })
        .to_le_bytes(),
    );
    d[10] = 4;
    attr(&mut d, 2, &e.mac);
    attr(&mut d, 9, &master.to_le_bytes());
    if e.vlan != 0 {
        attr(&mut d, 5, &e.vlan.to_le_bytes());
    }
    d
}
pub(super) fn link_data(g: &Topology, d: &Device) -> Vec<u8> {
    let mut data = super::link_data(g, d);
    data[0] = 7;
    if let Ok(p) = g.port_config(d.namespace, d.index) {
        if d.master.is_some() {
            let mut info = vec![];
            for (kind, b) in [
                (1, p.state),
                (4, u8::from(p.hairpin)),
                (8, u8::from(p.learning)),
                (9, u8::from(p.flood)),
                (27, u8::from(p.multicast_flood)),
                (30, u8::from(p.broadcast_flood)),
            ] {
                attr(&mut info, kind, &[b]);
            }
            attr(&mut data, 12 | 0x8000, &info);
        }
        let mut vlans = vec![];
        for (&vid, &flags) in &p.vlans {
            let mut v = flags.to_le_bytes().to_vec();
            v.extend_from_slice(&vid.to_le_bytes());
            attr(&mut vlans, 2, &v);
        }
        attr(&mut data, 26 | 0x8000, &vlans);
    }
    data
}
#[allow(clippy::too_many_arguments)] // One atomic rtnetlink request/reply context.
pub(super) fn request(
    g: &mut Topology,
    ns: u64,
    request: &[u8],
    seq: u32,
    port: u32,
    admin: bool,
    out: &mut Vec<Vec<u8>>,
    changes: &mut Vec<(u64, u16, u32, Vec<u8>)>,
) -> Result<bool> {
    let kind = u16::from_le_bytes(request[4..6].try_into().unwrap());
    let flags = u16::from_le_bytes(request[6..8].try_into().unwrap());
    let dump = flags & 0x300 == 0x300;
    if request.get(16) == Some(&7) && matches!(kind, 28..=30) {
        if request.len() < 28 {
            return Err(NetError(22));
        }
        let index = u32v(&request[20..24])?;
        let a = attrs(&request[28..])?;
        if kind == 30 {
            if !dump {
                return Err(NetError(95));
            }
            for (master, e) in g.fdb(ns, index) {
                out.push(message(28, 2, seq, port, &fdb_data(master, e)));
            }
            return Ok(true);
        }
        if !admin {
            return Err(NetError(1));
        }
        if a.iter().any(|(k, _)| !matches!(k, 2 | 5 | 9)) || request[26] & !6 != 0 {
            return Err(NetError(95));
        }
        let mac = get(&a, 2)
            .ok_or(NetError(22))?
            .try_into()
            .map_err(|_| NetError(22))?;
        let vlan = get(&a, 5)
            .map(|v| {
                v.try_into()
                    .map(u16::from_le_bytes)
                    .map_err(|_| NetError(22))
            })
            .transpose()?
            .unwrap_or(0);
        let master = get(&a, 9).map(u32v).transpose()?.unwrap_or(0);
        let state = u16::from_le_bytes(request[24..26].try_into().unwrap());
        let (master, e) = g.fdb_modify(
            ns,
            master,
            FdbEntry {
                mac,
                vlan,
                port: index,
                permanent: state & 192 != 0,
                local: state & 128 != 0,
            },
            kind == 28,
            flags,
        )?;
        changes.push((ns, kind, 4, fdb_data(master, e)));
        return Ok(true);
    }
    if request.len() >= 32 && matches!(kind, 16..=19) {
        let family = request[16];
        let index = u32v(&request[20..24])?;
        if family == 7 {
            let a = attrs(&request[32..])?;
            if kind == 18 {
                for d in g.devices(ns).into_iter().filter(|d| {
                    (index == 0 || d.index == index)
                        && (d.kind == DeviceKind::Bridge || d.master.is_some())
                }) {
                    out.push(message(
                        16,
                        if dump { 2 } else { 0 },
                        seq,
                        port,
                        &link_data(g, &d),
                    ));
                }
                return Ok(true);
            }
            if !admin {
                return Err(NetError(1));
            }
            if !matches!(kind, 17 | 19)
                || index == 0
                || a.iter().any(|(k, _)| !matches!(k, 12 | 26))
            {
                return Err(NetError(95));
            }
            let mut config = g.port_config(ns, index)?.clone();
            if let Some(v) = get(&a, 12) {
                config = port_config(v, config)?;
            }
            if let Some(v) = get(&a, 26) {
                config = vlan_config(v, config, kind != 17)?;
            }
            g.configure_port(ns, index, config)?;
            let d = g.device(ns, index)?;
            changes.push((ns, 16, 1, link_data(g, &d)));
            return Ok(true);
        }
        if !dump && kind == 16 && flags & 0x400 == 0 {
            let a = attrs(&request[32..])?;
            if let Some(info) = get(&a, 18) {
                let info = attrs(info)?;
                if get(&info, 1).map(text).transpose()? != Some(b"bridge".as_slice()) {
                    return Ok(false);
                }
                if !admin {
                    return Err(NetError(1));
                }
                if a.iter().any(|(k, _)| !matches!(k, 3 | 18))
                    || request[24..32] != [0; 8]
                    || info.iter().any(|(k, _)| !matches!(k, 1 | 2))
                {
                    return Err(NetError(95));
                }
                let d = if index != 0 {
                    g.device(ns, index)?
                } else {
                    g.named(ns, text(get(&a, 3).ok_or(NetError(22))?)?)?
                };
                let config = bridge_config(
                    get(&info, 2).unwrap_or(&[]),
                    g.bridge_config(ns, d.index)?.clone(),
                )?;
                g.configure_bridge(ns, d.index, config)?;
                changes.push((ns, 16, 1, super::link_data(g, &d)));
                return Ok(true);
            }
        }
    }
    Ok(false)
}
