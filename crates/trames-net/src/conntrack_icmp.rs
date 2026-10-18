// SPDX-License-Identifier: GPL-3.0-or-later
//! ICMP errors carry truncated IP packets. Adjust quoted checksums incrementally
//! instead of requiring the original transport payload to still be present.
use super::*;
pub(super) fn error(p: &[u8]) -> Option<(usize, Key)> {
    let h = packet::header(p)?;
    let typ = *p.get(h.offset)?;
    if !(h.protocol == 1 && matches!(typ, 3 | 11 | 12) || h.protocol == 58 && matches!(typ, 1..=4))
    {
        return None;
    }
    let offset = h.offset + 8;
    let q = p.get(offset..)?;
    // Only the header and first eight transport bytes are required by ICMPv4.
    // Keep the original IP length while parsing the bounded quote manually.
    let (source, destination, protocol, n) = match q.first()? >> 4 {
        4 => {
            let n = usize::from(q[0] & 15) * 4;
            if n < 20 || q.len() < n + 8 || u16::from_be_bytes([q[6], q[7]]) & 0x1fff != 0 {
                return None;
            }
            let ip = smoltcp::wire::Ipv4Packet::new_unchecked(q);
            if !ip.verify_checksum() {
                return None;
            }
            (
                IpAddr::V4(
                    <[u8; 4]>::try_from(&q[12..16])
                        .map(std::net::Ipv4Addr::from)
                        .ok()?,
                ),
                IpAddr::V4(
                    <[u8; 4]>::try_from(&q[16..20])
                        .map(std::net::Ipv4Addr::from)
                        .ok()?,
                ),
                q[9],
                n,
            )
        }
        6 => {
            if q.len() < 48 {
                return None;
            }
            (
                IpAddr::V6(
                    <[u8; 16]>::try_from(&q[8..24])
                        .map(std::net::Ipv6Addr::from)
                        .ok()?,
                ),
                IpAddr::V6(
                    <[u8; 16]>::try_from(&q[24..40])
                        .map(std::net::Ipv6Addr::from)
                        .ok()?,
                ),
                q[6],
                40,
            )
        }
        _ => return None,
    };
    let (sp, dp) = if matches!(protocol, 6 | 17) {
        (
            u16::from_be_bytes(q[n..n + 2].try_into().ok()?),
            u16::from_be_bytes(q[n + 2..n + 4].try_into().ok()?),
        )
    } else if matches!(protocol, 1 | 58) {
        let id = u16::from_be_bytes(q[n + 4..n + 6].try_into().ok()?);
        match q[n] {
            8 | 128 => (id, 0),
            0 | 129 => (0, id),
            _ => return None,
        }
    } else {
        return None;
    };
    Some((
        offset,
        Key {
            protocol,
            tuple: Tuple {
                source: SocketAddr::new(source, sp),
                destination: SocketAddr::new(destination, dp),
            },
        },
    ))
}
fn adjust(check: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!check);
    for (a, b) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        sum += u32::from(!u16::from_be_bytes([a[0], a[1]]))
            + u32::from(u16::from_be_bytes([b[0], b[1]]));
        sum = (sum & 65535) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
pub(super) fn translate(p: &mut [u8], t: &Track, source: bool) -> bool {
    let Some((offset, mut quoted)) = error(p) else {
        return false;
    };
    let Some(mut outer) = key(p) else {
        return false;
    };
    let (old, new) = if t.reply {
        if source {
            (t.translated.tuple.destination, t.original.tuple.destination)
        } else {
            (t.translated.tuple.source, t.original.tuple.source)
        }
    } else if source {
        (t.original.tuple.source, t.translated.tuple.source)
    } else {
        (t.original.tuple.destination, t.translated.tuple.destination)
    };
    if source {
        if outer.tuple.source.ip() == old.ip() {
            outer.tuple.source.set_ip(new.ip());
        }
        quoted.tuple.destination = new;
    } else {
        outer.tuple.destination.set_ip(new.ip());
        quoted.tuple.source = new;
    }
    let q = &mut p[offset..];
    let v4 = q[0] >> 4 == 4;
    let n = if v4 { usize::from(q[0] & 15) * 4 } else { 40 };
    let old_addr = if v4 {
        q[12..20].to_vec()
    } else {
        q[8..40].to_vec()
    };
    let old_ports = if matches!(quoted.protocol, 6 | 17) {
        q[n..n + 4].to_vec()
    } else {
        q[n + 4..n + 6].to_vec()
    };
    match (quoted.tuple.source.ip(), quoted.tuple.destination.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) if v4 => {
            q[12..16].copy_from_slice(&s.octets());
            q[16..20].copy_from_slice(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) if !v4 => {
            q[8..24].copy_from_slice(&s.octets());
            q[24..40].copy_from_slice(&d.octets());
        }
        _ => return false,
    }
    let new_addr = if v4 {
        q[12..20].to_vec()
    } else {
        q[8..40].to_vec()
    };
    let checksum = match quoted.protocol {
        6 => n + 16,
        17 => n + 6,
        _ => n + 2,
    };
    if matches!(quoted.protocol, 6 | 17) {
        q[n..n + 2].copy_from_slice(&quoted.tuple.source.port().to_be_bytes());
        q[n + 2..n + 4].copy_from_slice(&quoted.tuple.destination.port().to_be_bytes());
    } else {
        let id = if matches!(q[n], 8 | 128) {
            quoted.tuple.source.port()
        } else {
            quoted.tuple.destination.port()
        };
        q[n + 4..n + 6].copy_from_slice(&id.to_be_bytes());
    }
    let new_ports = if matches!(quoted.protocol, 6 | 17) {
        q[n..n + 4].to_vec()
    } else {
        q[n + 4..n + 6].to_vec()
    };
    if q.len() >= checksum + 2 {
        let mut c = u16::from_be_bytes(q[checksum..checksum + 2].try_into().unwrap());
        if !(quoted.protocol == 17 && v4 && c == 0) {
            if quoted.protocol != 1 {
                c = adjust(c, &old_addr, &new_addr);
            }
            c = adjust(c, &old_ports, &new_ports);
            if c == 0 && quoted.protocol == 17 {
                c = 65535;
            }
            q[checksum..checksum + 2].copy_from_slice(&c.to_be_bytes());
        }
    }
    if v4 {
        smoltcp::wire::Ipv4Packet::new_unchecked(q).fill_checksum();
    }
    rewrite(p, outer)
}
