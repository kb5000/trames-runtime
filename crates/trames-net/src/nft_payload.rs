// SPDX-License-Identifier: GPL-3.0-or-later
//! nftables network and transport header expressions for guest IP hooks.
use super::{fields, get, num, reg, u32v, Context, Expr, NetError, Result};

#[derive(Clone)]
pub(super) struct Write {
    network: bool,
    offset: usize,
    checksum: Option<usize>,
    pseudo_header: bool,
}

pub(super) fn parse(data: &[u8], family: u8, initialized: &mut [bool; 64]) -> Result<Expr> {
    let a = fields(data, &[1, 2, 3, 4, 5, 6, 7, 8])?;
    let base = num(&a, 2)?;
    if !matches!(base, 1 | 2) {
        return Err(NetError(95));
    }
    let load = get(&a, 1).is_some();
    if load == get(&a, 5).is_some() {
        return Err(NetError(22));
    }
    let offset = u16::try_from(num(&a, 3)?).map_err(|_| NetError(34))? as usize;
    let len = u8::try_from(num(&a, 4)?).map_err(|_| NetError(34))? as usize;
    let reg_id = num(&a, if load { 1 } else { 5 })?;
    if reg_id == 0 {
        return Err(NetError(22));
    }
    let register = reg(reg_id, 1).map_err(|_| NetError(34))?;
    let slot = initialized
        .get_mut(register..register + len.next_multiple_of(4))
        .ok_or(NetError(34))?;
    if len == 0 {
        return Err(NetError(22));
    }
    if load {
        slot.fill(true);
        return Ok(Expr::Payload {
            dest: register,
            base,
            offset,
            len,
        });
    }
    if slot[..len].contains(&false) {
        return Err(NetError(61));
    }
    let optional = |k| {
        get(&a, k)
            .map(u32v)
            .transpose()
            .map(Option::unwrap_or_default)
    };
    let csum_type = optional(6)?;
    let csum_offset = u8::try_from(optional(7)?).map_err(|_| NetError(34))?;
    let flags = optional(8)?;
    if flags > 1 {
        return Err(NetError(22));
    }
    let checksum = match csum_type {
        0 if csum_offset == 0 => None,
        0 => return Err(NetError(22)),
        1 if base == 1 && (family != 2 || csum_offset == 10) => Some(csum_offset.into()),
        1 if base == 2 && flags == 0 && matches!(csum_offset, 2 | 6 | 16) => {
            Some(csum_offset.into())
        }
        1 => return Err(NetError(22)),
        _ => return Err(NetError(95)),
    };
    Ok(Expr::PayloadSet {
        src: register,
        len,
        write: Write {
            network: base == 1,
            offset,
            checksum,
            pseudo_header: flags != 0,
        },
    })
}

// IP hooks run after header parsing. Preserve fields which determine the layout
// used by routing and transport, including when userspace aligns a TTL/DSCP write.
fn writable_ip(p: &[u8], offset: usize, src: &[u8]) -> bool {
    let n = src.len();
    match (p[0] >> 4, offset) {
        (4, 0) => n == 2 && src[0] == p[0],
        (4, 1) => n == 1,
        (4, 4) => n == 2,
        (4, 8) => n == 1 || (n == 2 && src[1] == p[9]),
        (4, 10 | 12 | 16) => offset + n <= 20,
        (6, 0) => n <= 4 && src[0] >> 4 == 6,
        (6, 2) => n <= 2,
        (6, 7) => n == 1,
        (6, 8 | 24) => offset + n <= 40,
        _ => false,
    }
}

fn transport_checksum(protocol: u8) -> Option<usize> {
    match protocol {
        6 => Some(16),
        17 | 136 => Some(6),
        1 | 58 => Some(2),
        _ => None,
    }
}

// RFC 1624, including byte-sized changes in the low half of a network word.
fn checksum_delta(old: &[u8], new: &[u8], offset: usize) -> u32 {
    let mut delta = 0;
    for (i, (&a, &b)) in old.iter().zip(new).enumerate() {
        let shift = if (offset + i).is_multiple_of(2) { 8 } else { 0 };
        delta += u32::from(!(u16::from(a) << shift)) + (u32::from(b) << shift);
    }
    delta
}
fn updated_checksum(packet: &[u8], offset: usize, delta: u32, keep_zero: bool) -> Option<[u8; 2]> {
    let initial = u16::from_be_bytes(packet.get(offset..offset + 2)?.try_into().ok()?);
    if keep_zero && initial == 0 {
        return Some([0, 0]);
    }
    let mut sum = u32::from(!initial) + delta;
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let value = !(sum as u16);
    Some(if value == 0 { u16::MAX } else { value }.to_be_bytes())
}
impl Write {
    pub(super) fn apply(&self, ctx: &mut Context<'_>, src: &[u8]) -> Option<()> {
        let transport = if !self.network || self.pseudo_header {
            ctx.transport()
        } else {
            None
        };
        let start = if self.network {
            if !writable_ip(ctx.packet, self.offset, src) {
                return None;
            }
            0
        } else {
            let (start, protocol) = transport?;
            if protocol == 6 && self.offset <= 12 && self.offset + src.len() > 12 {
                return None;
            }
            start
        };
        let at = start + self.offset;
        let end = at + src.len();
        let old = ctx.packet.get(at..end)?;
        if self.checksum.is_some() || self.pseudo_header {
            let delta = checksum_delta(old, src, at);
            let explicit = self.checksum.filter(|&off| {
                if self.network {
                    ctx.family() == 2 && off == 10
                } else {
                    transport.and_then(|(_, p)| transport_checksum(p)) == Some(off)
                }
            });
            let layer4 = if self.pseudo_header {
                transport.and_then(|(pos, p)| match p {
                    6 | 17 | 136 | 58 => Some((pos + transport_checksum(p)?, p)),
                    _ => None,
                })
            } else {
                None
            };
            // Check both fields before changing either one.
            let ip = match explicit {
                Some(off) => Some((
                    start + off,
                    updated_checksum(ctx.packet, start + off, delta, false)?,
                )),
                None => None,
            };
            let l4 = match layer4 {
                Some((pos, p)) => Some((pos, updated_checksum(ctx.packet, pos, delta, p == 17)?)),
                None => None,
            };
            for (pos, bytes) in ip.into_iter().chain(l4) {
                ctx.packet[pos..pos + 2].copy_from_slice(&bytes);
            }
        }
        ctx.packet[at..end].copy_from_slice(src);
        // A later fib/addrtype/NAT expression in this chain sees the edited tuple.
        if (self.network && end > if ctx.family() == 2 { 12 } else { 8 })
            || (!self.network && self.offset < 4)
        {
            ctx.tuple = crate::virtualnet::packet::header_after_write(ctx.packet)?.tuple;
        }
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_register_bounds_and_uninitialized_sources() {
        let mut initialized = [false; 64];
        let mut attrs = Vec::new();
        for (key, val) in [(5, 8), (2, 2), (3, 0), (4, 4)] {
            super::super::number(&mut attrs, key, val);
        }
        assert!(matches!(
            parse(&attrs, 2, &mut initialized),
            Err(NetError(61))
        ));
        let mut load = Vec::new();
        for (key, val) in [(1, 23), (2, 2), (3, 0), (4, 5)] {
            super::super::number(&mut load, key, val);
        }
        assert!(matches!(
            parse(&load, 2, &mut initialized),
            Err(NetError(34))
        ));
    }
    #[test]
    fn checksum_preserves_disabled_udp_and_encodes_computed_zero() {
        assert_eq!(updated_checksum(&[0, 0], 0, 1, true), Some([0, 0]));
        assert_eq!(updated_checksum(&[0, 1], 0, 1, false), Some([0xff, 0xff]));
        assert_eq!(updated_checksum(&[0], 0, 1, false), None);
    }
}
