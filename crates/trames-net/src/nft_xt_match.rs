// SPDX-License-Identifier: GPL-3.0-or-later
//! Packet matchers used by iptables-nft's compatibility expressions.
use super::{Context, NetError, Result};

pub(super) fn check_size(bytes: &[u8], size: usize) -> Result<()> {
    if (size..=size.next_multiple_of(8)).contains(&bytes.len()) {
        Ok(())
    } else {
        Err(NetError(22))
    }
}

pub(super) fn protocol(name: &str, family: u8) -> Option<u8> {
    match (name, family) {
        ("tcp", 2 | 10) => Some(6),
        ("udp", 2 | 10) => Some(17),
        ("icmp", 2) => Some(1),
        ("icmp6", 10) => Some(58),
        _ => None,
    }
}

#[derive(Clone)]
pub(super) struct Transport {
    pub(super) protocol: u8,
    criteria: Criteria,
}

#[derive(Clone)]
enum Criteria {
    Ports {
        source: [u16; 2],
        destination: [u16; 2],
        invert: u8,
        option: u8,
        mask: u8,
        flags: u8,
    },
    Icmp {
        kind: u8,
        codes: [u8; 2],
        invert: bool,
    },
}

impl Transport {
    pub(super) fn info_size(&self) -> usize {
        match self.protocol {
            6 => 12,
            17 => 10,
            _ => 4,
        }
    }
    pub(super) fn parse(protocol: u8, bytes: &[u8]) -> Result<Self> {
        let criteria = match protocol {
            6 | 17 => {
                let tcp = protocol == 6;
                check_size(bytes, if tcp { 12 } else { 10 })?;
                let invert = bytes[if tcp { 11 } else { 8 }];
                if invert & !(if tcp { 15 } else { 3 }) != 0 {
                    return Err(NetError(22));
                }
                let port = |i| u16::from_ne_bytes([bytes[i], bytes[i + 1]]);
                Criteria::Ports {
                    source: [port(0), port(2)],
                    destination: [port(4), port(6)],
                    invert,
                    option: if tcp { bytes[8] } else { 0 },
                    mask: if tcp { bytes[9] } else { 0 },
                    flags: if tcp { bytes[10] } else { 0 },
                }
            }
            1 | 58 => {
                check_size(bytes, 4)?;
                if bytes[3] & !1 != 0 {
                    return Err(NetError(22));
                }
                Criteria::Icmp {
                    kind: bytes[0],
                    codes: [bytes[1], bytes[2]],
                    invert: bytes[3] != 0,
                }
            }
            _ => return Err(NetError(2)),
        };
        Ok(Self { protocol, criteria })
    }

    // None means an incomplete required header; xtables drops the packet.
    pub(super) fn matches(&self, segment: &[u8]) -> Option<bool> {
        segment.get(..if self.protocol == 6 { 20 } else { 8 })?;
        match self.criteria {
            Criteria::Icmp {
                kind,
                codes,
                invert,
            } => {
                let matched = self.protocol == 1 && kind == 255
                    || segment[0] == kind && (codes[0]..=codes[1]).contains(&segment[1]);
                Some(matched ^ invert)
            }
            Criteria::Ports {
                source,
                destination,
                invert,
                option,
                mask,
                flags,
            } => {
                let port = |i| u16::from_be_bytes([segment[i], segment[i + 1]]);
                if (source[0]..=source[1]).contains(&port(0)) == (invert & 1 != 0)
                    || (destination[0]..=destination[1]).contains(&port(2)) == (invert & 2 != 0)
                    || self.protocol == 6 && (segment[13] & mask == flags) == (invert & 4 != 0)
                {
                    return Some(false);
                }
                if option == 0 {
                    return Some(true);
                }
                let mut options = segment.get(20..usize::from(segment[12] >> 4) * 4)?;
                while let Some(&kind) = options.first() {
                    if kind == option {
                        return Some(invert & 8 == 0);
                    }
                    let size = if kind < 2 {
                        1
                    } else {
                        usize::from(*options.get(1)?).max(1)
                    };
                    options = options.get(size..).unwrap_or_default();
                }
                Some(invert & 8 != 0)
            }
        }
    }
}

pub(super) fn conntrack_size(revision: u32) -> Result<usize> {
    // Linux ARM64 sizeof(xt_conntrack_mtinfo1/2/3), before XT_ALIGN.
    match revision {
        1 => Ok(152),
        2 => Ok(156),
        3 => Ok(164),
        _ => Err(NetError(2)),
    }
}

pub(super) fn conntrack_matches(ctx: &Context<'_>, revision: u32, b: &[u8]) -> bool {
    let word = |i| u16::from_le_bytes([b[i], b[i + 1]]);
    let flags = word(146);
    let inverse = word(148);
    let check = |flag, matched| flags & flag == 0 || (matched ^ (inverse & flag != 0));
    let track = ctx.track.as_ref();
    let state = track.map_or(1, |t| {
        (if t.state == 64 { 256 } else { t.state })
            | if t.status & 16 != 0 { 64 } else { 0 }
            | if t.status & 32 != 0 { 128 } else { 0 }
    });
    let (states, statuses) = if revision == 1 {
        (u16::from(b[150]), u16::from(b[151]))
    } else {
        (word(150), word(152))
    };
    if !check(1, state & u32::from(states) != 0) {
        return false;
    }
    let Some(t) = track.filter(|t| t.id != 0) else {
        return flags & 1 != 0;
    };
    if !check(2, u16::from(t.original.protocol) == word(136))
        || !check(64, t.status & u32::from(statuses) != 0)
        || !check(4096, !t.reply)
    {
        return false;
    }
    if flags & 128 != 0 {
        let Some(seconds) = ctx.connections.and_then(|c| c.seconds_remaining(t.id)) else {
            return false;
        };
        let bound = |i| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        if !check(128, (bound(128)..=bound(132)).contains(&seconds)) {
            return false;
        }
    }
    if flags & (0x3c | 0xf00) == 0 {
        return true;
    }
    let reply = t.translated.reverse();
    let endpoints = [
        t.original.tuple.source,
        t.original.tuple.destination,
        reply.tuple.source,
        reply.tuple.destination,
    ];
    for (i, endpoint) in endpoints.into_iter().enumerate() {
        let addr_flag = 4 << i;
        if flags & addr_flag != 0 {
            let a = i * 32;
            let masked = |bytes: &[u8]| {
                bytes
                    .iter()
                    .enumerate()
                    .all(|(j, v)| (v ^ b[a + j]) & b[a + 16 + j] == 0)
            };
            let matched = match endpoint.ip() {
                std::net::IpAddr::V4(ip) => masked(&ip.octets()),
                std::net::IpAddr::V6(ip) => masked(&ip.octets()),
            };
            if !check(addr_flag, matched) {
                return false;
            }
        }
        let port_flag = 256 << i;
        if flags & port_flag != 0 {
            let p = 138 + i * 2;
            let matched = if revision == 3 {
                (word(p)..=word(154 + i * 2)).contains(&endpoint.port())
            } else {
                u16::from_be_bytes([b[p], b[p + 1]]) == endpoint.port()
            };
            if !check(port_flag, matched) {
                return false;
            }
        }
    }
    true
}
