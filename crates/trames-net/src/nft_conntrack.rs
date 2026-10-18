// SPDX-License-Identifier: GPL-3.0-or-later
//! Real namespace conntrack dumps/deletion for Docker's cleanup filters.
use super::*;
use crate::{
    conntrack::{Key, Track},
    virtualnet::packet::Tuple,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
fn tuple(bytes: &[u8], family: u8) -> Result<Key> {
    let a = fields(bytes, &[1, 2])?;
    let ip = fields(need(&a, 1)?, &[1, 2, 3, 4])?;
    let proto = fields(need(&a, 2)?, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    let protocol = *need(&proto, 1)?
        .first()
        .filter(|_| need(&proto, 1).unwrap().len() == 1)
        .ok_or(NetError(22))?;
    let address = |kind| -> Result<IpAddr> {
        let b = need(&ip, kind)?;
        Ok(match family {
            2 => Ipv4Addr::from(<[u8; 4]>::try_from(b).map_err(|_| NetError(22))?).into(),
            10 => Ipv6Addr::from(<[u8; 16]>::try_from(b).map_err(|_| NetError(22))?).into(),
            _ => return Err(NetError(97)),
        })
    };
    let src = address(if family == 2 { 1 } else { 3 })?;
    let dst = address(if family == 2 { 2 } else { 4 })?;
    let port = |kind| -> Result<u16> {
        Ok(u16::from_be_bytes(
            need(&proto, kind)?.try_into().map_err(|_| NetError(22))?,
        ))
    };
    let (sp, dp) = if matches!(protocol, 6 | 17) {
        (port(2)?, port(3)?)
    } else if matches!(protocol, 1 | 58) {
        let id = port(if protocol == 1 { 4 } else { 7 })?;
        let typ = need(&proto, if protocol == 1 { 5 } else { 8 })?;
        if typ.len() != 1 {
            return Err(NetError(22));
        }
        if matches!(typ[0], 8 | 128) {
            (id, 0)
        } else if matches!(typ[0], 0 | 129) {
            (0, id)
        } else {
            return Err(NetError(95));
        }
    } else {
        return Err(NetError(95));
    };
    Ok(Key {
        protocol,
        tuple: Tuple {
            source: SocketAddr::new(src, sp),
            destination: SocketAddr::new(dst, dp),
        },
    })
}
fn encode(k: Key) -> Vec<u8> {
    let mut a = vec![];
    let mut ip = vec![];
    match (k.tuple.source.ip(), k.tuple.destination.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            attr(&mut ip, 1, &s.octets());
            attr(&mut ip, 2, &d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            attr(&mut ip, 3, &s.octets());
            attr(&mut ip, 4, &d.octets());
        }
        _ => unreachable!(),
    }
    attr(&mut a, 1 | 0x8000, &ip);
    let mut proto = vec![];
    attr(&mut proto, 1, &[k.protocol]);
    if matches!(k.protocol, 6 | 17) {
        attr(&mut proto, 2, &k.tuple.source.port().to_be_bytes());
        attr(&mut proto, 3, &k.tuple.destination.port().to_be_bytes());
    } else {
        let v4 = k.protocol == 1;
        let reply = k.tuple.source.port() == 0;
        let id = if reply {
            k.tuple.destination.port()
        } else {
            k.tuple.source.port()
        };
        attr(&mut proto, if v4 { 4 } else { 7 }, &id.to_be_bytes());
        attr(
            &mut proto,
            if v4 { 5 } else { 8 },
            &[if v4 {
                if reply {
                    0
                } else {
                    8
                }
            } else if reply {
                129
            } else {
                128
            }],
        );
        attr(&mut proto, if v4 { 6 } else { 9 }, &[0]);
    }
    attr(&mut a, 2 | 0x8000, &proto);
    a
}
fn record(t: Track, timeout: u32) -> Vec<u8> {
    let mut d = data(if t.original.tuple.source.is_ipv4() {
        2
    } else {
        10
    });
    attr(&mut d, 1 | 0x8000, &encode(t.original));
    attr(&mut d, 2 | 0x8000, &encode(t.translated.reverse()));
    number(&mut d, 3, t.status);
    number(&mut d, 7, timeout);
    number(&mut d, 8, t.mark);
    number(&mut d, 12, t.id as u32);
    attr(&mut d, 18, &t.zone.to_be_bytes());
    d
}
pub(super) fn request(
    ns: &Namespace,
    requests: &[&[u8]],
    port: u32,
    admin: bool,
    slots: usize,
    capacity: usize,
) -> Result<Vec<Vec<u8>>> {
    let shared = ns.graph.borrow().connections(ns.id());
    let mut staged = shared.borrow().clone();
    let mut messages = vec![];
    let mut changed = false;
    for &r in requests {
        let result = (|| -> Result<Vec<Vec<u8>>> {
            if !admin {
                return Err(NetError(1));
            }
            if r.len() < 20 || r[17..20] != [0, 0, 0] || !matches!(r[16], 0 | 2 | 10) {
                return Err(NetError(22));
            }
            let op = kind(r) & 255;
            let f = flags(r);
            let dump = f & 0x300 == 0x300;
            let seq = u32::from_le_bytes(r[8..12].try_into().unwrap());
            if !matches!(op, 1 | 2) || f & !(1 | 4 | 0x300) != 0 {
                return Err(NetError(95));
            }
            let a = fields(&r[20..], &[1, 2, 3, 7, 8, 12, 18, 21])?;
            for kind in [3, 7] {
                if let Some(v) = get(&a, kind) {
                    u32v(v)?;
                }
            }
            let orig = get(&a, 1).map(|v| tuple(v, r[16])).transpose()?;
            let reply = get(&a, 2).map(|v| tuple(v, r[16])).transpose()?;
            let zone = get(&a, 18)
                .map(|v| {
                    <[u8; 2]>::try_from(v)
                        .map(u16::from_be_bytes)
                        .map_err(|_| NetError(22))
                })
                .transpose()?;
            let id = get(&a, 12).map(u32v).transpose()?;
            let mark = get(&a, 8).map(u32v).transpose()?;
            let mask = get(&a, 21).map(u32v).transpose()?.unwrap_or(u32::MAX);
            let entries: Vec<_> = staged
                .records()
                .into_iter()
                .filter(|(t, _)| {
                    (r[16] == 0 || t.original.tuple.source.is_ipv4() == (r[16] == 2))
                        && orig.is_none_or(|k| t.original == k)
                        && reply.is_none_or(|k| t.translated.reverse() == k)
                        && zone.is_none_or(|z| t.zone == z)
                        && id.is_none_or(|id| t.id as u32 == id)
                        && mark.is_none_or(|m| t.mark & mask == m & mask)
                })
                .collect();
            if op == 2 {
                if entries.is_empty() && (orig.is_some() || reply.is_some() || id.is_some()) {
                    return Err(NetError(2));
                }
                for (t, _) in entries {
                    staged.delete(t.id);
                }
                changed = true;
                return Ok(vec![]);
            }
            if !dump && entries.is_empty() {
                return Err(NetError(2));
            }
            let mut out: Vec<_> = entries
                .into_iter()
                .map(|(t, timeout)| {
                    message(
                        0x100,
                        if dump { 2 } else { 0 },
                        seq,
                        port,
                        &record(t, timeout),
                    )
                })
                .collect();
            if dump {
                out.push(message(3, 2, seq, port, &0i32.to_le_bytes()));
            }
            Ok(out)
        })();
        match result {
            Ok(out) => {
                messages.extend(out);
                if flags(r) & 4 != 0 {
                    messages.push(ack(r, port, 0));
                }
            }
            Err(NetError(e)) => {
                messages = vec![ack(r, port, e)];
                changed = false;
                break;
            }
        }
    }
    let mut out = vec![];
    let mut datagram = vec![];
    for m in messages {
        if datagram.len() + m.len() > 32768 && !datagram.is_empty() {
            out.push(std::mem::take(&mut datagram));
        }
        datagram.extend(m);
    }
    if !datagram.is_empty() {
        out.push(datagram);
    }
    if out.len() > slots || out.iter().map(Vec::len).sum::<usize>() > capacity {
        return Err(NetError(105));
    }
    if changed {
        *shared.borrow_mut() = staged;
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_docker_dump_replay_delete_is_scoped_atomic_and_authorized() {
        let ns = Namespace::default();
        let other = Namespace::default();
        let shared = ns.graph.borrow().connections(ns.id());
        let p = crate::conntrack::message(
            "172.17.0.2:40000".parse().unwrap(),
            "198.18.0.1:80".parse().unwrap(),
            6,
            2,
            b"",
        );
        let t = shared.borrow_mut().begin(&p, 42).unwrap();
        shared.borrow_mut().finish(t, true);
        let dump = message(0x101, 0x301, 10, 0, &data(2));
        let replies = request(&ns, &[&dump], 99, true, 128, 65536).unwrap();
        assert_eq!(replies.len(), 1);
        let first_len = u32::from_le_bytes(replies[0][..4].try_into().unwrap()) as usize;
        assert_eq!(
            u16::from_le_bytes(replies[0][4..6].try_into().unwrap()),
            0x100
        );
        assert_eq!(
            u16::from_le_bytes(replies[0][first_len + 4..first_len + 6].try_into().unwrap()),
            3
        );
        // Go copies the complete dump payload back into DELETE, including
        // read-only status/timeout attributes, not only the original tuple.
        let delete = message(0x102, 5, 11, 0, &replies[0][16..first_len]);
        let error = |out: Vec<Vec<u8>>| i32::from_le_bytes(out[0][16..20].try_into().unwrap());
        assert_eq!(
            error(request(&other, &[&delete], 99, true, 128, 65536).unwrap()),
            -2
        );
        assert_eq!(
            error(request(&ns, &[&delete], 99, false, 128, 65536).unwrap()),
            -1
        );
        assert_eq!(request(&ns, &[&delete], 99, true, 0, 0), Err(NetError(105)));
        assert_eq!(shared.borrow().records().len(), 1);
        assert_eq!(
            error(request(&ns, &[&delete], 99, true, 128, 65536).unwrap()),
            0
        );
        assert!(shared.borrow().records().is_empty());
    }
}
