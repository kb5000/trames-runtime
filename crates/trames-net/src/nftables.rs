// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded guest nf_tables ABI and packet filter. Wire identifiers follow Linux
//! UAPI nf_tables.h/nfnetlink.h (GPL-2.0 WITH Linux-syscall-note).
//! No host firewall calls; unsupported hooks/expressions fail before publication.
use crate::{
    netlink::{attr, message, Namespace},
    NetError,
};
use std::{cell::Cell, cmp::Ordering, collections::BTreeMap};
type Result<T> = std::result::Result<T, NetError>;
#[path = "nft_conntrack.rs"]
mod ctnetlink;
const SUBSYSTEM: u16 = 10 << 8;
const MAX_BYTES: usize = 256 * 1024;
type Attrs<'a> = Vec<(u16, &'a [u8])>;
fn attrs(mut bytes: &[u8]) -> Result<Attrs<'_>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(NetError(22));
        }
        let n = u16::from_le_bytes(bytes[..2].try_into().unwrap()) as usize;
        let k = u16::from_le_bytes(bytes[2..4].try_into().unwrap()) & 0x3fff;
        if n < 4 || n > bytes.len() {
            return Err(NetError(22));
        }
        out.push((k, &bytes[4..n]));
        if n == bytes.len() {
            break;
        }
        bytes = bytes.get((n + 3) & !3..).ok_or(NetError(22))?;
    }
    Ok(out)
}
fn fields<'a>(bytes: &'a [u8], allowed: &[u16]) -> Result<Attrs<'a>> {
    let a = attrs(bytes)?;
    for (i, (k, _)) in a.iter().enumerate() {
        if !allowed.contains(k) {
            return Err(NetError(95));
        }
        if a[..i].iter().any(|(other, _)| k == other) {
            return Err(NetError(22));
        }
    }
    Ok(a)
}
fn get<'a>(a: &Attrs<'a>, k: u16) -> Option<&'a [u8]> {
    a.iter().find_map(|(key, v)| (*key == k).then_some(*v))
}
fn need<'a>(a: &Attrs<'a>, k: u16) -> Result<&'a [u8]> {
    get(a, k).ok_or(NetError(22))
}
fn u32v(b: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(b.try_into().map_err(|_| NetError(22))?))
}
fn u64v(b: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(b.try_into().map_err(|_| NetError(22))?))
}
fn num(a: &Attrs<'_>, k: u16) -> Result<u32> {
    u32v(need(a, k)?)
}
fn text(b: &[u8]) -> Result<String> {
    let b = b.strip_suffix(&[0]).ok_or(NetError(22))?;
    if b.is_empty() || b.len() >= 256 || b.contains(&0) {
        return Err(NetError(22));
    }
    String::from_utf8(b.to_vec()).map_err(|_| NetError(22))
}
fn name(a: &Attrs<'_>, k: u16) -> Result<String> {
    text(need(a, k)?)
}
fn string(out: &mut Vec<u8>, k: u16, v: &str) {
    let mut b = v.as_bytes().to_vec();
    b.push(0);
    attr(out, k, &b);
}
fn number(out: &mut Vec<u8>, k: u16, v: u32) {
    attr(out, k, &v.to_be_bytes());
}
fn integer(out: &mut Vec<u8>, k: u16, v: u64) {
    attr(out, k, &v.to_be_bytes());
}
#[derive(Clone, Default)]
pub(crate) struct Ruleset {
    generation: u32,
    next: u64,
    active_hooks: u8,
    tables: BTreeMap<(u8, String), Table>,
}
#[derive(Clone)]
struct Table {
    handle: u64,
    userdata: Vec<u8>,
    chains: BTreeMap<String, Chain>,
}
#[derive(Clone)]
struct Chain {
    handle: u64,
    hook: Option<(u32, i32)>,
    policy: u32,
    chain_type: String,
    userdata: Vec<u8>,
    rules: Vec<Rule>,
    packets: Cell<u64>,
    bytes: Cell<u64>,
}
#[derive(Clone)]
struct Rule {
    handle: u64,
    userdata: Vec<u8>,
    expressions: Vec<Expr>,
    wire: Vec<u8>,
    compatibility: Option<Vec<u8>>,
}
#[derive(Clone)]
enum Expr {
    Immediate {
        dest: usize,
        value: Vec<u8>,
    },
    Verdict(i32, Option<String>),
    Meta {
        dest: usize,
        key: u32,
    },
    Payload {
        dest: usize,
        base: u32,
        offset: usize,
        len: usize,
    },
    Compare {
        src: usize,
        op: u32,
        value: Vec<u8>,
    },
    Bitwise {
        src: usize,
        dest: usize,
        mask: Vec<u8>,
        xor: Vec<u8>,
    },
    CtGet {
        dest: usize,
        key: u32,
        direction: u8,
    },
    CtSet {
        src: usize,
        key: u32,
    },
    Fib {
        dest: usize,
        flags: u32,
    },
    ConntrackMatch {
        revision: u32,
        info: Vec<u8>,
    },
    FixedNat {
        source: bool,
        address: Option<std::net::IpAddr>,
        ports: Option<(u16, u16)>,
        masquerade: bool,
    },
    Zone(u16),
    AddrType {
        source: u16,
        destination: u16,
        flags: u32,
    },
    Nat {
        source: bool,
        family: u32,
        address: Option<usize>,
        address_max: Option<usize>,
        port: Option<usize>,
        port_max: Option<usize>,
    },
    Masquerade {
        port: Option<usize>,
        port_max: Option<usize>,
    },
    Counter {
        packets: Cell<u64>,
        bytes: Cell<u64>,
    },
}
fn reg(n: u32, len: usize) -> Result<usize> {
    let index = match n {
        1..=4 => (n as usize - 1) * 16,
        8..=23 => (n as usize - 8) * 4,
        _ => return Err(NetError(22)),
    };
    if len == 0 || len > 16 || index + len > 64 {
        return Err(NetError(22));
    }
    Ok(index)
}
fn value(bytes: &[u8]) -> Result<Vec<u8>> {
    let a = fields(bytes, &[1])?;
    let v = need(&a, 1)?;
    if v.is_empty() || v.len() > 16 {
        return Err(NetError(22));
    }
    Ok(v.to_vec())
}
fn expressions_in(bytes: &[u8], rule_family: u8) -> Result<Vec<Expr>> {
    let mut out = vec![];
    let mut initialized = [false; 64];
    for (kind, b) in attrs(bytes)? {
        if kind != 1 || out.len() >= 32 {
            return Err(NetError(95));
        }
        let a = fields(b, &[1, 2])?;
        let data = need(&a, 2)?;
        let expr = match name(&a, 1)?.as_str() {
            "immediate" => {
                let a = fields(data, &[1, 2])?;
                if num(&a, 1)? == 0 {
                    let d = fields(need(&a, 2)?, &[2])?;
                    let v = fields(need(&d, 2)?, &[1, 2])?;
                    let code = num(&v, 1)? as i32;
                    if !matches!(code, -5..=1) {
                        return Err(NetError(95));
                    }
                    let chain = get(&v, 2).map(text).transpose()?;
                    if matches!(code, -3 | -4) != chain.is_some() {
                        return Err(NetError(22));
                    }
                    Expr::Verdict(code, chain)
                } else {
                    let v = value(need(&a, 2)?)?;
                    let dest = reg(num(&a, 1)?, v.len())?;
                    initialized[dest..dest + v.len()].fill(true);
                    Expr::Immediate { dest, value: v }
                }
            }
            "meta" => {
                let a = fields(data, &[1, 2])?;
                let key = num(&a, 2)?;
                let len = match key {
                    0 | 4 | 5 => 4,
                    1 => 2,
                    6 | 7 => 16,
                    15 | 16 => 1,
                    _ => return Err(NetError(95)),
                };
                let dest = reg(num(&a, 1)?, len)?;
                initialized[dest..dest + len].fill(true);
                Expr::Meta { dest, key }
            }
            "payload" => {
                let a = fields(data, &[1, 2, 3, 4])?;
                let base = num(&a, 2)?;
                if !matches!(base, 1 | 2) {
                    return Err(NetError(95));
                }
                let len = num(&a, 4)? as usize;
                let dest = reg(num(&a, 1)?, len)?;
                let offset = num(&a, 3)? as usize;
                if offset > 65535 {
                    return Err(NetError(22));
                }
                initialized[dest..dest + len].fill(true);
                Expr::Payload {
                    dest,
                    base,
                    offset,
                    len,
                }
            }
            "cmp" => {
                let a = fields(data, &[1, 2, 3])?;
                let op = num(&a, 2)?;
                if op > 5 {
                    return Err(NetError(95));
                }
                let v = value(need(&a, 3)?)?;
                let src = reg(num(&a, 1)?, v.len())?;
                if initialized[src..src + v.len()].contains(&false) {
                    return Err(NetError(22));
                }
                Expr::Compare { src, op, value: v }
            }
            "bitwise" => {
                let a = fields(data, &[1, 2, 3, 4, 5, 6])?;
                if get(&a, 6).map(u32v).transpose()?.unwrap_or(0) != 0 {
                    return Err(NetError(95));
                }
                let len = num(&a, 3)? as usize;
                let src = reg(num(&a, 1)?, len)?;
                let dest = reg(num(&a, 2)?, len)?;
                let mask = value(need(&a, 4)?)?;
                let xor = value(need(&a, 5)?)?;
                if mask.len() != len
                    || xor.len() != len
                    || initialized[src..src + len].contains(&false)
                {
                    return Err(NetError(22));
                }
                initialized[dest..dest + len].fill(true);
                Expr::Bitwise {
                    src,
                    dest,
                    mask,
                    xor,
                }
            }
            "ct" => {
                let a = fields(data, &[1, 2, 3, 4])?;
                let key = num(&a, 2)?;
                let len = match key {
                    0 | 2 | 3 | 19 | 20 | 23 => 4,
                    1 | 7 | 10 => 1,
                    11 | 12 | 17 => 2,
                    8 | 9 => {
                        if rule_family == 2 {
                            4
                        } else {
                            16
                        }
                    }
                    21 | 22 => 16,
                    _ => return Err(NetError(95)),
                };
                if let Some(src) = get(&a, 4) {
                    if get(&a, 1).is_some() || !matches!(key, 3 | 17) {
                        return Err(NetError(95));
                    }
                    let src = reg(u32v(src)?, len)?;
                    if initialized[src..src + len].contains(&false) {
                        return Err(NetError(22));
                    }
                    Expr::CtSet { src, key }
                } else {
                    let dest = reg(num(&a, 1)?, len)?;
                    initialized[dest..dest + len].fill(true);
                    let direction = get(&a, 3)
                        .map(|b| {
                            if b.len() == 1 && b[0] <= 1 {
                                Ok(b[0])
                            } else {
                                Err(NetError(22))
                            }
                        })
                        .transpose()?
                        .unwrap_or(0);
                    Expr::CtGet {
                        dest,
                        key,
                        direction,
                    }
                }
            }
            "fib" => {
                let a = fields(data, &[1, 2, 3])?;
                let flags = num(&a, 3)?;
                if num(&a, 2)? != 3 || !matches!(flags, 1 | 2) {
                    return Err(NetError(95));
                }
                let dest = reg(num(&a, 1)?, 4)?;
                initialized[dest..dest + 4].fill(true);
                Expr::Fib { dest, flags }
            }
            "match" => {
                let a = fields(data, &[1, 2, 3])?;
                let kind = name(&a, 1)?;
                let revision = num(&a, 2)?;
                let b = need(&a, 3)?;
                if kind == "conntrack" {
                    if revision > 3 || b.len() != if revision == 3 { 168 } else { 160 } {
                        return Err(NetError(95));
                    }
                    let flags = u16::from_le_bytes(b[146..148].try_into().unwrap());
                    let inverse = u16::from_le_bytes(b[148..150].try_into().unwrap());
                    if flags & 128 != 0 || inverse & !flags != 0 {
                        return Err(NetError(95));
                    }
                    Expr::ConntrackMatch {
                        revision,
                        info: b.to_vec(),
                    }
                } else {
                    if kind != "addrtype" || revision != 1 {
                        return Err(NetError(95));
                    }
                    if b.len() != 8 {
                        return Err(NetError(22));
                    }
                    let source = u16::from_le_bytes(b[..2].try_into().unwrap());
                    let destination = u16::from_le_bytes(b[2..4].try_into().unwrap());
                    let flags = u32::from_le_bytes(b[4..].try_into().unwrap());
                    if flags & !3 != 0 || (source | destination) & !0x2e != 0 {
                        return Err(NetError(95));
                    }
                    Expr::AddrType {
                        source,
                        destination,
                        flags,
                    }
                }
            }
            "target" => {
                let a = fields(data, &[1, 2, 3])?;
                let kind = name(&a, 1)?;
                let revision = num(&a, 2)?;
                let b = need(&a, 3)?;
                if kind == "CT" {
                    if revision > 1
                        || b.len() != if revision == 0 { 40 } else { 72 }
                        || b[..2] != [0, 0]
                        || b[4..].iter().any(|b| *b != 0)
                    {
                        return Err(NetError(95));
                    }
                    Expr::Zone(u16::from_le_bytes(b[2..4].try_into().unwrap()))
                } else {
                    if !matches!(kind.as_str(), "MASQUERADE" | "DNAT" | "SNAT") || revision > 2 {
                        return Err(NetError(95));
                    }
                    let old = b.len() == 24;
                    if old && u32::from_le_bytes(b[..4].try_into().unwrap()) != 1
                        || !old && !matches!(b.len(), 40 | 48)
                    {
                        return Err(NetError(22));
                    }
                    let at = if old { 4 } else { 0 };
                    let flags = u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
                    if flags & !3 != 0 {
                        return Err(NetError(95));
                    }
                    if !matches!(rule_family, 2 | 10) {
                        return Err(NetError(95));
                    }
                    let address = if flags & 1 == 0 {
                        None
                    } else if old {
                        Some(
                            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&b[8..12]).unwrap())
                                .into(),
                        )
                    } else {
                        // nf_nat_range uses 16-byte nf_inet_addr even for IPv4.
                        // Rule family is checked when evaluating this expression.
                        if rule_family == 2 {
                            Some(
                                std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&b[4..8]).unwrap())
                                    .into(),
                            )
                        } else {
                            Some(
                                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&b[4..20]).unwrap())
                                    .into(),
                            )
                        }
                    };
                    let p = if old { 16 } else { 36 };
                    let ports = if flags & 2 != 0 {
                        let low = u16::from_be_bytes(b[p..p + 2].try_into().unwrap());
                        let high = u16::from_be_bytes(b[p + 2..p + 4].try_into().unwrap());
                        if low == 0 || low > high {
                            return Err(NetError(22));
                        }
                        Some((low, high))
                    } else {
                        None
                    };
                    Expr::FixedNat {
                        source: kind != "DNAT",
                        address,
                        ports,
                        masquerade: kind == "MASQUERADE",
                    }
                }
            }
            "nat" | "masq" => {
                let kind = name(&a, 1)?;
                let masq = kind == "masq";
                let a = fields(
                    data,
                    if masq {
                        &[1, 2, 3]
                    } else {
                        &[1, 2, 3, 4, 5, 6, 7]
                    },
                )?;
                let flags = get(&a, if masq { 1 } else { 7 })
                    .map(u32v)
                    .transpose()?
                    .unwrap_or(0);
                if flags & !3 != 0 {
                    return Err(NetError(95));
                }
                let register = |field, len| -> Result<Option<usize>> {
                    let r = get(&a, field)
                        .map(u32v)
                        .transpose()?
                        .map(|r| reg(r, len))
                        .transpose()?;
                    if r.is_some_and(|r| initialized[r..r + len].contains(&false)) {
                        return Err(NetError(22));
                    }
                    Ok(r)
                };
                let port = register(if masq { 2 } else { 5 }, 2)?;
                let port_max = register(if masq { 3 } else { 6 }, 2)?;
                if port_max.is_some() && port.is_none() {
                    return Err(NetError(22));
                }
                if masq {
                    Expr::Masquerade { port, port_max }
                } else {
                    let source = match num(&a, 1)? {
                        0 => true,
                        1 => false,
                        _ => return Err(NetError(95)),
                    };
                    let family = num(&a, 2)?;
                    if rule_family != 1 && u32::from(rule_family) != family {
                        return Err(NetError(97));
                    }
                    let len = match family {
                        2 => 4,
                        10 => 16,
                        _ => return Err(NetError(97)),
                    };
                    let address = register(3, len)?;
                    let address_max = register(4, len)?;
                    if address_max.is_some() && address.is_none()
                        || address.is_none() && port.is_none()
                    {
                        return Err(NetError(22));
                    }
                    Expr::Nat {
                        source,
                        family,
                        address,
                        address_max,
                        port,
                        port_max,
                    }
                }
            }
            "counter" => {
                let a = fields(data, &[1, 2, 3])?;
                Expr::Counter {
                    bytes: Cell::new(get(&a, 1).map(u64v).transpose()?.unwrap_or(0)),
                    packets: Cell::new(get(&a, 2).map(u64v).transpose()?.unwrap_or(0)),
                }
            }
            _ => return Err(NetError(95)),
        };
        out.push(expr);
    }
    Ok(out)
}
fn data(family: u8) -> Vec<u8> {
    vec![family, 0, 0, 0]
}
fn table_data(family: u8, name: &str, t: &Table) -> Vec<u8> {
    let mut d = data(family);
    string(&mut d, 1, name);
    number(&mut d, 2, 0);
    number(&mut d, 3, t.chains.len() as u32);
    integer(&mut d, 4, t.handle);
    if !t.userdata.is_empty() {
        attr(&mut d, 6, &t.userdata);
    }
    d
}
fn chain_data(family: u8, table: &str, name: &str, c: &Chain, references: u32) -> Vec<u8> {
    let mut d = data(family);
    string(&mut d, 1, table);
    integer(&mut d, 2, c.handle);
    string(&mut d, 3, name);
    if let Some((hook, priority)) = c.hook {
        let mut h = vec![];
        number(&mut h, 1, hook);
        number(&mut h, 2, priority as u32);
        attr(&mut d, 4 | 0x8000, &h);
        number(&mut d, 5, c.policy);
        string(&mut d, 7, &c.chain_type);
        let mut counters = vec![];
        integer(&mut counters, 1, c.bytes.get());
        integer(&mut counters, 2, c.packets.get());
        attr(&mut d, 8 | 0x8000, &counters);
        number(&mut d, 10, 1);
    }
    number(&mut d, 6, c.rules.len() as u32 + references);
    if !c.userdata.is_empty() {
        attr(&mut d, 12, &c.userdata);
    }
    d
}
fn rule_data(family: u8, table: &str, chain: &str, r: &Rule) -> Vec<u8> {
    let mut d = data(family);
    string(&mut d, 1, table);
    string(&mut d, 2, chain);
    integer(&mut d, 3, r.handle);
    // Retain expression wire metadata but return live packet/byte counters.
    let mut wire = vec![];
    for ((kind, b), expr) in attrs(&r.wire)
        .expect("validated expression wire")
        .into_iter()
        .zip(&r.expressions)
    {
        if let Expr::Counter { packets, bytes } = expr {
            let mut e = vec![];
            string(&mut e, 1, "counter");
            let mut c = vec![];
            integer(&mut c, 1, bytes.get());
            integer(&mut c, 2, packets.get());
            attr(&mut e, 2 | 0x8000, &c);
            attr(&mut wire, kind | 0x8000, &e);
        } else {
            attr(&mut wire, kind | 0x8000, b);
        }
    }
    attr(&mut d, 4 | 0x8000, &wire);
    if let Some(compat) = &r.compatibility {
        attr(&mut d, 5 | 0x8000, compat);
    }
    if !r.userdata.is_empty() {
        attr(&mut d, 7, &r.userdata);
    }
    d
}
fn ack(r: &[u8], port: u32, errno: u32) -> Vec<u8> {
    let mut d = (-(errno as i32)).to_le_bytes().to_vec();
    d.extend_from_slice(if errno == 0 { &r[..16] } else { r });
    message(
        2,
        0,
        u32::from_le_bytes(r[8..12].try_into().unwrap()),
        port,
        &d,
    )
}
fn kind(r: &[u8]) -> u16 {
    u16::from_le_bytes(r[4..6].try_into().unwrap())
}
fn flags(r: &[u8]) -> u16 {
    u16::from_le_bytes(r[6..8].try_into().unwrap())
}
impl Ruleset {
    fn handle(&mut self) -> Result<u64> {
        self.next = self.next.checked_add(1).ok_or(NetError(28))?;
        Ok(self.next)
    }
    fn bounds(&self) -> Result<()> {
        let mut chains = 0;
        let mut rules = 0;
        let mut bytes = 0;
        for ((_, name), t) in &self.tables {
            bytes += name.len() + t.userdata.len() + 128;
            chains += t.chains.len();
            for (name, c) in &t.chains {
                bytes += name.len() + c.userdata.len() + 128;
                rules += c.rules.len();
                for r in &c.rules {
                    bytes += r.wire.len() * 3 + r.userdata.len() + 256;
                }
            }
        }
        if self.tables.len() > 16 || chains > 64 || rules > 512 || bytes > MAX_BYTES {
            return Err(NetError(28));
        }
        Ok(())
    }
    fn validate_jumps(&self) -> Result<()> {
        // Memoize DAG depth and worst-case work. Repeated diamonds cannot turn
        // admission or evaluation into an exponential coordinator stall.
        fn visit(
            t: &Table,
            name: &str,
            path: &mut Vec<String>,
            memo: &mut BTreeMap<String, (usize, usize)>,
        ) -> Result<(usize, usize)> {
            if let Some(v) = memo.get(name) {
                return Ok(*v);
            }
            if path.len() >= 16 || path.iter().any(|p| p == name) {
                return Err(NetError(40));
            }
            let c = t.chains.get(name).ok_or(NetError(2))?;
            path.push(name.to_owned());
            let mut depth = 1;
            let mut work = c.rules.len();
            for r in &c.rules {
                for e in &r.expressions {
                    if let Expr::Verdict(_, Some(next)) = e {
                        if t.chains.get(next).is_some_and(|c| c.hook.is_some()) {
                            return Err(NetError(95));
                        }
                        let (d, w) = visit(t, next, path, memo)?;
                        depth = depth.max(d + 1);
                        work += w;
                        if depth > 16 || work > 8192 {
                            return Err(NetError(40));
                        }
                    }
                }
            }
            path.pop();
            memo.insert(name.to_owned(), (depth, work));
            Ok((depth, work))
        }
        for t in self.tables.values() {
            fn context(
                t: &Table,
                n: &str,
                nat: bool,
                hook: u32,
                priority: i32,
                seen: &mut std::collections::BTreeSet<String>,
            ) -> Result<()> {
                if !seen.insert(n.to_owned()) {
                    return Ok(());
                }
                let c = t.chains.get(n).ok_or(NetError(2))?;
                for r in &c.rules {
                    for e in &r.expressions {
                        match e {
                            Expr::Nat { .. } | Expr::Masquerade { .. } | Expr::FixedNat { .. }
                                if !nat =>
                            {
                                return Err(NetError(95))
                            }
                            Expr::Zone(_) | Expr::CtSet { key: 17, .. }
                                if priority >= -200 || !matches!(hook, 0 | 3) =>
                            {
                                return Err(NetError(95))
                            }
                            Expr::Nat { source: true, .. }
                            | Expr::FixedNat { source: true, .. }
                            | Expr::Masquerade { .. }
                                if hook != 4 =>
                            {
                                return Err(NetError(95))
                            }
                            Expr::Nat { source: false, .. }
                            | Expr::FixedNat { source: false, .. }
                                if !matches!(hook, 0 | 3) =>
                            {
                                return Err(NetError(95))
                            }
                            Expr::Verdict(_, Some(next)) => {
                                context(t, next, nat, hook, priority, seen)?
                            }
                            _ => {}
                        }
                    }
                }
                Ok(())
            }
            for (n, c) in &t.chains {
                if let Some((hook, priority)) = c.hook {
                    context(
                        t,
                        n,
                        c.chain_type == "nat",
                        hook,
                        priority,
                        &mut std::collections::BTreeSet::new(),
                    )?;
                }
            }
            let mut memo = BTreeMap::new();
            for name in t.chains.keys() {
                visit(t, name, &mut vec![], &mut memo)?;
            }
        }
        Ok(())
    }
    fn execute(
        &mut self,
        ns: &Namespace,
        r: &[u8],
        port: u32,
        batch: bool,
    ) -> Result<Vec<Vec<u8>>> {
        let kind = kind(r);
        let flags = flags(r);
        let seq = u32::from_le_bytes(r[8..12].try_into().unwrap());
        if r.len() < 20 || r[17] != 0 || r[18..20] != [0, 0] {
            return Err(NetError(22));
        }
        if kind == 11 << 8 && !batch {
            // Only revision probes for matches translated to our native
            // payload expressions. Opaque xt match/target blobs remain rejected.
            let a = fields(&r[20..], &[1, 2, 3])?;
            let n = name(&a, 1)?;
            let revision = num(&a, 2)?;
            let target = num(&a, 3)?;
            let supported = match (n.as_str(), target) {
                ("tcp" | "udp" | "icmp" | "icmp6", 0) => revision == 0,
                ("addrtype", 0) => revision == 1,
                ("conntrack", 0) => revision <= 3,
                ("MASQUERADE" | "SNAT" | "DNAT", 1) => revision <= 2,
                ("CT", 1) => revision <= 1,
                _ => false,
            };
            if !supported {
                return Err(NetError(95));
            }
            return Ok(vec![message(kind, 0, seq, port, &r[16..])]);
        }
        if kind >> 8 != 10 {
            return Err(NetError(95));
        }
        let op = kind & 255;
        let dump = flags & 0x300 == 0x300;
        let read = matches!(op, 1 | 4 | 7 | 10 | 16);
        if flags & 1 == 0 || flags & !(1 | 4 | 0x100 | 0x200 | 0x400 | 0x800) != 0 {
            return Err(NetError(95));
        }
        if !read && !batch {
            return Err(NetError(95));
        }
        if read && batch {
            return Err(NetError(95));
        }
        let family = r[16];
        if !matches!(family, 0 | 1 | 2 | 10) || (!read && family == 0) {
            return Err(NetError(97));
        }
        let mut out = vec![];
        if op == 16 {
            fields(&r[20..], &[])?;
            let mut d = data(0);
            number(&mut d, 1, self.generation);
            out.push(message(SUBSYSTEM | 15, 0, seq, port, &d));
            return Ok(out);
        }
        let mutation_flags = match op {
            0 | 3 => 0x400 | 0x200,
            2 | 5 => 0x100,
            6 => 0xf00,
            _ => 0,
        };
        if !read && flags & !(1 | 4 | mutation_flags) != 0 {
            return Err(NetError(95));
        }
        if op == 10 {
            // No sets can be created in this implementation. An empty dump is
            // truthful and needed by iptables' rule inspection; single lookup
            // still reports ENOENT, and NEWSET remains unsupported.
            let a = fields(&r[20..], &[1, 2])?;
            for (_, v) in a {
                text(v)?;
            }
            if !dump {
                return Err(NetError(2));
            }
            return Ok(vec![message(3, 2, seq, port, &0i32.to_le_bytes())]);
        }
        let allowed: &[u16] = match op {
            0 => &[1, 2, 6],
            1 | 2 => &[1],
            3 => &[1, 3, 4, 5, 7, 8, 10, 12],
            4 => &[1, 2, 3],
            5 => &[1, 3, 6],
            6 => &[1, 2, 3, 4, 5, 6, 7, 8],
            7 => &[1, 2, 3],
            // libnftnl echoes the selected rule when deleting by handle.
            8 => &[1, 2, 3, 4, 5, 7, 8],
            _ => return Err(NetError(95)),
        };
        let a = fields(&r[20..], allowed)?;
        if read {
            let table = get(&a, 1).map(text).transpose()?;
            let chain = if op == 4 {
                get(&a, 3)
            } else if op == 7 {
                get(&a, 2)
            } else {
                None
            }
            .map(text)
            .transpose()?;
            let handle = get(&a, if op == 4 { 2 } else { 3 }).map(u64v).transpose()?;
            let mut found = false;
            for ((f, n), t) in &self.tables {
                if family != 0 && family != *f || table.as_ref().is_some_and(|v| v != n) {
                    continue;
                }
                if op == 1 {
                    out.push(message(
                        SUBSYSTEM,
                        if dump { 2 } else { 0 },
                        seq,
                        port,
                        &table_data(*f, n, t),
                    ));
                    found = true;
                } else {
                    for (cn, c) in &t.chains {
                        if chain.as_ref().is_some_and(|v| v != cn) {
                            continue;
                        }
                        if op == 4 {
                            if handle.is_none_or(|h| h == c.handle) {
                                out.push(message(
                                    SUBSYSTEM | 3,
                                    if dump { 2 } else { 0 },
                                    seq,
                                    port,
                                    &chain_data(*f, n, cn, c, t.chains.values().flat_map(|c| &c.rules).flat_map(|r| &r.expressions).filter(|e| matches!(e,Expr::Verdict(_,Some(target)) if target==cn)).count() as u32),
                                ));
                                found = true;
                            }
                        } else {
                            for rule in &c.rules {
                                if handle.is_none_or(|h| h == rule.handle) {
                                    out.push(message(
                                        SUBSYSTEM | 6,
                                        if dump { 2 } else { 0 },
                                        seq,
                                        port,
                                        &rule_data(*f, n, cn, rule),
                                    ));
                                    found = true;
                                }
                            }
                        }
                    }
                }
            }
            if !dump && !found {
                return Err(NetError(2));
            }
            if dump {
                out.push(message(3, 2, seq, port, &0i32.to_le_bytes()));
            }
            return Ok(out);
        }
        let key = (family, name(&a, 1)?);
        match op {
            0 => {
                if get(&a, 2).map(u32v).transpose()?.unwrap_or(0) != 0 {
                    return Err(NetError(95));
                }
                if self.tables.contains_key(&key) {
                    if get(&a, 6).is_some() {
                        return Err(NetError(95));
                    }
                    if flags & 0x200 != 0 {
                        return Err(NetError(17));
                    }
                } else {
                    if flags & 0x400 == 0 {
                        return Err(NetError(2));
                    }
                    let handle = self.handle()?;
                    let userdata = get(&a, 6).unwrap_or_default().to_vec();
                    if userdata.len() > 256 {
                        return Err(NetError(22));
                    }
                    self.tables.insert(
                        key,
                        Table {
                            handle,
                            userdata,
                            chains: BTreeMap::new(),
                        },
                    );
                }
            }
            2 => {
                if flags & 0x100 != 0 && self.tables.get(&key).is_some_and(|t| !t.chains.is_empty())
                {
                    return Err(NetError(16));
                }
                if self.tables.remove(&key).is_none() {
                    return Err(NetError(2));
                }
            }
            3 => {
                let cn = name(&a, 3)?;
                let h = get(&a, 4)
                    .map(|b| -> Result<(u32, i32)> {
                        let a = fields(b, &[1, 2])?;
                        Ok((num(&a, 1)?, num(&a, 2)? as i32))
                    })
                    .transpose()?;
                let typ = get(&a, 7).map(text).transpose()?;
                // Native BSD socket I/O does not pass through the packet stack.
                // Root hooks other than FORWARD cannot yet be promised safely.
                if h.is_some_and(|(hook, _)| !ns.nft_packet_hooks.get() || hook > 4)
                    || typ
                        .as_deref()
                        .is_some_and(|v| !matches!(v, "filter" | "nat"))
                {
                    return Err(NetError(95));
                }
                if typ.as_deref() == Some("nat")
                    && h.is_none_or(|(hook, priority)| {
                        !matches!(hook, 0 | 3 | 4) || priority != if hook == 4 { 100 } else { -100 }
                    })
                {
                    return Err(NetError(95));
                }
                let policy = get(&a, 5).map(u32v).transpose()?;
                if policy.is_some_and(|v| v > 1) {
                    return Err(NetError(95));
                }
                let chainflags = get(&a, 10).map(u32v).transpose()?.unwrap_or(0);
                if chainflags & !1 != 0 || chainflags == 1 && h.is_none() {
                    return Err(NetError(95));
                }
                let counters = get(&a, 8)
                    .map(|b| -> Result<(u64, u64)> {
                        let a = fields(b, &[1, 2, 3])?;
                        Ok((
                            get(&a, 1).map(u64v).transpose()?.unwrap_or(0),
                            get(&a, 2).map(u64v).transpose()?.unwrap_or(0),
                        ))
                    })
                    .transpose()?;
                let userdata = get(&a, 12).map(<[u8]>::to_vec);
                if userdata.as_ref().is_some_and(|v| v.len() > 256) {
                    return Err(NetError(22));
                }
                let handle = self.handle()?;
                let table = self.tables.get_mut(&key).ok_or(NetError(2))?;
                if let Some(c) = table.chains.get_mut(&cn) {
                    if flags & 0x200 != 0 {
                        return Err(NetError(17));
                    }
                    if h.is_some_and(|v| Some(v) != c.hook)
                        || typ
                            .as_ref()
                            .is_some_and(|v| c.hook.is_none() || v != &c.chain_type)
                    {
                        return Err(NetError(95));
                    }
                    if policy.is_some() && c.hook.is_none() {
                        return Err(NetError(95));
                    }
                    if let Some(v) = policy {
                        c.policy = v;
                    }
                    if let Some(v) = userdata {
                        c.userdata = v;
                    }
                    if let Some((bytes, packets)) = counters {
                        c.bytes.set(bytes);
                        c.packets.set(packets);
                    }
                } else {
                    if h.is_none() && (policy.is_some() || typ.is_some()) {
                        return Err(NetError(95));
                    }
                    let (bytes, packets) = counters.unwrap_or_default();
                    table.chains.insert(
                        cn,
                        Chain {
                            handle,
                            hook: h,
                            policy: policy.unwrap_or(1),
                            chain_type: typ.unwrap_or_else(|| "filter".to_owned()),
                            userdata: userdata.unwrap_or_default(),
                            rules: vec![],
                            packets: Cell::new(packets),
                            bytes: Cell::new(bytes),
                        },
                    );
                }
            }
            5 => {
                let cn = name(&a, 3)?;
                let t = self.tables.get_mut(&key).ok_or(NetError(2))?;
                let c = t.chains.get(&cn).ok_or(NetError(2))?;
                if (flags & 0x100 != 0 && !c.rules.is_empty())
                    || t.chains.values().any(|c| {
                        c.rules.iter().any(|r| {
                            r.expressions
                                .iter()
                                .any(|e| matches!(e,Expr::Verdict(_,Some(n)) if n==&cn))
                        })
                    })
                {
                    return Err(NetError(16));
                }
                t.chains.remove(&cn);
            }
            6 => {
                let cn = name(&a, 2)?;
                let wire = need(&a, 4)?.to_vec();
                let expressions = expressions_in(&wire, family)?;
                let compatibility = get(&a, 5)
                    .map(|b| -> Result<Vec<u8>> {
                        let a = fields(b, &[1, 2])?;
                        if num(&a, 1)? > 255 || num(&a, 2)? & !2 != 0 {
                            return Err(NetError(95));
                        }
                        Ok(b.to_vec())
                    })
                    .transpose()?;
                if get(&a, 8).is_some_and(|b| !b.is_empty()) {
                    return Err(NetError(22));
                }
                let userdata = get(&a, 7).unwrap_or_default().to_vec();
                if userdata.len() > 256 {
                    return Err(NetError(22));
                }
                let handle = self.handle()?;
                let c = self
                    .tables
                    .get_mut(&key)
                    .and_then(|t| t.chains.get_mut(&cn))
                    .ok_or(NetError(2))?;
                if flags & 0x100 != 0 {
                    let old = u64v(need(&a, 3)?)?;
                    let i = c
                        .rules
                        .iter()
                        .position(|r| r.handle == old)
                        .ok_or(NetError(2))?;
                    c.rules[i] = Rule {
                        handle: old,
                        userdata,
                        expressions,
                        wire,
                        compatibility,
                    };
                } else {
                    if get(&a, 3).is_some() {
                        return Err(NetError(95));
                    }
                    let position = get(&a, 6).map(u64v).transpose()?;
                    let append = flags & 0x800 != 0;
                    let at = if let Some(position) = position {
                        c.rules
                            .iter()
                            .position(|r| r.handle == position)
                            .ok_or(NetError(2))?
                            + usize::from(append)
                    } else if append {
                        c.rules.len()
                    } else {
                        0
                    };
                    c.rules.insert(
                        at,
                        Rule {
                            handle,
                            userdata,
                            expressions,
                            wire,
                            compatibility,
                        },
                    );
                }
            }
            8 => {
                let cn = get(&a, 2).map(text).transpose()?;
                let handle = get(&a, 3).map(u64v).transpose()?;
                let t = self.tables.get_mut(&key).ok_or(NetError(2))?;
                if let Some(cn) = cn {
                    let c = t.chains.get_mut(&cn).ok_or(NetError(2))?;
                    if let Some(handle) = handle {
                        let at = c
                            .rules
                            .iter()
                            .position(|r| r.handle == handle)
                            .ok_or(NetError(2))?;
                        c.rules.remove(at);
                    } else {
                        c.rules.clear();
                    }
                } else if handle.is_none() {
                    for c in t.chains.values_mut() {
                        c.rules.clear();
                    }
                } else {
                    return Err(NetError(22));
                }
            }
            _ => return Err(NetError(95)),
        }
        self.bounds()?;
        Ok(out)
    }
}
/// One datagram is one bounded transaction. Unsupported expressions, split
/// batches, sets and notifications return explicit EOPNOTSUPP.
pub(crate) fn request(
    ns: &Namespace,
    requests: &[&[u8]],
    port: u32,
    admin: bool,
    slots: usize,
    capacity: usize,
) -> Result<Vec<Vec<u8>>> {
    if requests.iter().all(|r| kind(r) >> 8 == 1) {
        return ctnetlink::request(ns, requests, port, admin, slots, capacity);
    }
    let shared = ns.graph.borrow().firewall(ns.id());
    let mut staged = shared.borrow().clone();
    let batch = kind(requests[0]) == 16;
    let mut out = vec![];
    let mut error = None;
    let mut mutated = false;
    for (i, r) in requests.iter().enumerate() {
        let result = (|| -> Result<Vec<Vec<u8>>> {
            if !admin {
                return Err(NetError(1));
            }
            if batch && (i == 0 || i + 1 == requests.len()) {
                if r.len() < 20
                    || kind(r) != if i == 0 { 16 } else { 17 }
                    || r[16..18] != [0, 0]
                    || r[18..20] != [0, 10]
                {
                    return Err(NetError(95));
                }
                let a = fields(&r[20..], if i == 0 { &[1] } else { &[] })?;
                if get(&a, 1)
                    .map(u32v)
                    .transpose()?
                    .is_some_and(|v| v != staged.generation)
                {
                    return Err(NetError(85));
                }
                if requests.len() < 2 {
                    return Err(NetError(95));
                }
                return Ok(vec![]);
            }
            if batch && !matches!(kind(r) & 255, 0 | 2 | 3 | 5 | 6 | 8) {
                return Err(NetError(95));
            }
            let generated = staged.execute(ns, r, port, batch)?;
            mutated |= batch;
            Ok(generated)
        })();
        match result {
            Ok(generated) => {
                out.extend(generated);
                if flags(r) & 4 != 0 {
                    out.push(ack(r, port, 0));
                }
            }
            Err(NetError(errno)) => {
                error = Some((*r, errno));
                break;
            }
        }
    }
    if error.is_none() && mutated {
        if let Err(NetError(e)) = staged.validate_jumps() {
            error = Some((requests[requests.len() - 1], e));
        }
    }
    if let Some((r, e)) = error {
        out = vec![ack(r, port, e)];
        mutated = false;
    }
    // A dump may contain hundreds of rules. Netlink permits multiple aligned
    // messages in one datagram; queue limits count datagrams, not rules.
    let mut packed = vec![];
    let mut datagram = vec![];
    for message in out {
        if datagram.len() + message.len() > 32768 && !datagram.is_empty() {
            packed.push(std::mem::take(&mut datagram));
        }
        datagram.extend(message);
    }
    if !datagram.is_empty() {
        packed.push(datagram);
    }
    let out = packed;
    if out.len() > slots || out.iter().map(Vec::len).sum::<usize>() > capacity {
        return Err(NetError(105));
    }
    if mutated {
        staged.generation = staged.generation.wrapping_add(1);
        staged.active_hooks = staged
            .tables
            .values()
            .flat_map(|t| t.chains.values())
            .filter_map(|c| c.hook)
            .fold(0, |mask, (h, _)| mask | (1 << h));
        *shared.borrow_mut() = staged;
    }
    Ok(out)
}
pub(crate) struct Context<'a> {
    pub packet: &'a [u8],
    pub hook: u32,
    pub input: u32,
    pub output: u32,
    pub input_name: &'a [u8],
    pub output_name: &'a [u8],
    pub track: Option<crate::conntrack::Track>,
    pub source_type: u32,
    pub destination_type: u32,
    pub masquerade: Option<std::net::IpAddr>,
}
impl Context<'_> {
    fn family(&self) -> u8 {
        if self.packet[0] >> 4 == 4 {
            2
        } else {
            10
        }
    }
    fn transport(&self) -> Option<(usize, u8)> {
        let p = self.packet;
        if self.family() == 2 {
            if u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
                None
            } else {
                Some(((p[0] & 15) as usize * 4, p[9]))
            }
        } else {
            let mut proto = p[6];
            let mut offset = 40;
            for _ in 0..8 {
                let len = match proto {
                    0 | 43 | 60 => {
                        let b = p.get(offset..offset + 2)?;
                        (b[1] as usize + 1) * 8
                    }
                    44 => {
                        let b = p.get(offset..offset + 8)?;
                        if u16::from_be_bytes([b[2], b[3]]) & 0xfff8 != 0 {
                            return None;
                        }
                        8
                    }
                    51 => {
                        let b = p.get(offset..offset + 2)?;
                        (b[1] as usize + 2) * 4
                    }
                    _ => return Some((offset, proto)),
                };
                let header = p.get(offset..offset + len)?;
                proto = header[0];
                offset += len;
            }
            None
        }
    }

    fn meta(&self, key: u32) -> Option<Vec<u8>> {
        Some(match key {
            0 => (self.packet.len() as u32).to_le_bytes().to_vec(),
            1 => (if self.family() == 2 { 0x800u16 } else { 0x86dd })
                .to_be_bytes()
                .to_vec(),
            4 => self.input.to_le_bytes().to_vec(),
            5 => self.output.to_le_bytes().to_vec(),
            6 | 7 => {
                let name = if key == 6 {
                    self.input_name
                } else {
                    self.output_name
                };
                let mut b = vec![0; 16];
                let n = name.len().min(15);
                b[..n].copy_from_slice(&name[..n]);
                b
            }
            15 => vec![self.family()],
            16 => vec![self.transport()?.1],
            _ => return None,
        })
    }
}
#[derive(Default)]
struct Effects {
    zone: Option<u16>,
    mark: Option<u32>,
    nat: Option<NatAction>,
}
struct NatAction {
    source: bool,
    address: Option<std::net::IpAddr>,
    ports: Option<(u16, u16)>,
}
pub(crate) struct Hook<'a> {
    pub graph: &'a crate::netdev::Topology,
    pub namespace: u64,
    pub hook: u32,
    pub input: u32,
    pub output: u32,
    pub raw: bool,
}
impl Ruleset {
    pub fn process(
        &self,
        packet: &mut [u8],
        meta: &Hook<'_>,
        track: &mut crate::conntrack::Track,
        conn: &mut crate::conntrack::State,
    ) -> bool {
        let family = if packet[0] >> 4 == 4 { 2 } else { 10 };
        let mut chains = vec![];
        for ((f, _), t) in &self.tables {
            if *f != 1 && *f != family {
                continue;
            }
            for (n, c) in &t.chains {
                if let Some((h, p)) = c.hook {
                    if h == meta.hook && (p < -200) == meta.raw {
                        chains.push((p, t, n, c));
                    }
                }
            }
        }
        chains.sort_by_key(|v| v.0);
        let source = matches!(meta.hook, 1 | 4);
        let nat_priority = if source { 100 } else { -100 };
        let nat_stage = matches!(meta.hook, 0 | 1 | 3 | 4) && !meta.raw;
        let mut applied = false;
        for (priority, t, n, c) in chains {
            if nat_stage && !applied && priority >= nat_priority {
                if !conn.existing_nat(track, packet, source) {
                    return false;
                }
                applied = true;
            }
            if c.chain_type == "nat"
                && (track.reply
                    || if source {
                        track.snat_done
                    } else {
                        track.dnat_done
                    })
            {
                continue;
            }
            let Some(h) = crate::virtualnet::packet::header(packet) else {
                return false;
            };
            let output = if meta.hook == 3 {
                meta.graph
                    .source(meta.namespace, h.tuple.destination.ip())
                    .map(|(_, i, _)| i)
                    .unwrap_or(meta.output)
            } else {
                meta.output
            };
            let name = |i| {
                meta.graph
                    .device(meta.namespace, i)
                    .map(|d| d.name)
                    .unwrap_or_default()
            };
            let src_type = meta.graph.address_type(meta.namespace, h.tuple.source.ip());
            let dst_type = meta
                .graph
                .address_type(meta.namespace, h.tuple.destination.ip());
            let masquerade = meta
                .graph
                .device(meta.namespace, output)
                .ok()
                .and_then(|d| {
                    d.addresses
                        .into_iter()
                        .find(|a| a.ip.is_ipv4() == (family == 2))
                })
                .map(|a| a.ip);
            let ctx = Context {
                packet,
                hook: meta.hook,
                input: meta.input,
                output,
                input_name: &name(meta.input),
                output_name: &name(output),
                track: Some(*track),
                source_type: src_type,
                destination_type: dst_type,
                masquerade,
            };
            let mut effects = Effects::default();
            let v = t.verdict(n, &ctx, &mut 8192, &mut effects);
            if v == 0 {
                return false;
            }
            if v < 0 {
                c.packets.set(c.packets.get().wrapping_add(1));
                c.bytes.set(c.bytes.get().wrapping_add(packet.len() as u64));
                if c.policy == 0 {
                    return false;
                }
            }
            if let Some(zone) = effects.zone {
                if !meta.raw {
                    return false;
                }
                track.zone = zone;
            }
            if let Some(mark) = effects.mark {
                track.mark = mark;
            }
            if let Some(nat) = effects.nat {
                if c.chain_type != "nat"
                    || !conn.nat(track, packet, nat.source, nat.address, nat.ports)
                {
                    return false;
                }
                if nat.source {
                    track.snat_done = true;
                } else {
                    track.dnat_done = true;
                }
            }
        }
        if nat_stage {
            if !applied && !conn.existing_nat(track, packet, source) {
                return false;
            }
            if source {
                track.snat_done = true;
            } else {
                track.dnat_done = true;
            }
        }
        true
    }
}
impl Rule {
    fn verdict(&self, ctx: &Context<'_>, effects: &mut Effects) -> Option<(i32, Option<&str>)> {
        let mut regs = [0u8; 64];
        for expr in &self.expressions {
            match expr {
                Expr::Immediate { dest, value } => {
                    regs[*dest..*dest + value.len()].copy_from_slice(value)
                }
                Expr::Meta { dest, key } => {
                    let b = ctx.meta(*key)?;
                    regs[*dest..*dest + b.len()].copy_from_slice(&b);
                }
                Expr::Payload {
                    dest,
                    base,
                    offset,
                    len,
                } => {
                    let start = if *base == 1 { 0 } else { ctx.transport()?.0 };
                    let b = ctx.packet.get(start + *offset..start + *offset + *len)?;
                    regs[*dest..*dest + *len].copy_from_slice(b);
                }
                Expr::Compare { src, op, value } => {
                    let cmp = regs[*src..*src + value.len()].cmp(value);
                    let matched = match op {
                        0 => cmp == Ordering::Equal,
                        1 => cmp != Ordering::Equal,
                        2 => cmp == Ordering::Less,
                        3 => cmp != Ordering::Greater,
                        4 => cmp == Ordering::Greater,
                        _ => cmp != Ordering::Less,
                    };
                    if !matched {
                        return None;
                    }
                }
                Expr::Bitwise {
                    src,
                    dest,
                    mask,
                    xor,
                } => {
                    let saved = regs;
                    for i in 0..mask.len() {
                        regs[*dest + i] = (saved[*src + i] & mask[i]) ^ xor[i];
                    }
                }
                Expr::Zone(zone) => effects.zone = Some(*zone),
                Expr::FixedNat {
                    source,
                    address,
                    ports,
                    masquerade,
                } => {
                    if *source != matches!(ctx.hook, 1 | 4) {
                        return Some((0, None));
                    }
                    let address = if *masquerade {
                        ctx.masquerade
                    } else {
                        *address
                    };
                    if *masquerade && address.is_none() {
                        return Some((0, None));
                    }
                    effects.nat = Some(NatAction {
                        source: *source,
                        address,
                        ports: *ports,
                    });
                    return Some((1, None));
                }
                Expr::ConntrackMatch { revision, info } => {
                    let t = ctx.track?;
                    let b = info;
                    let le = |i| u16::from_le_bytes(b[i..i + 2].try_into().unwrap());
                    let flags = le(146);
                    let inverse = le(148);
                    let check =
                        |flag, matched| flags & flag == 0 || (matched ^ (inverse & flag != 0));
                    let state = if t.state == 64 { 256 } else { t.state }
                        | if t.status & 16 != 0 { 64 } else { 0 }
                        | if t.status & 32 != 0 { 128 } else { 0 };
                    let mask = if *revision <= 1 {
                        u32::from(b[150])
                    } else {
                        u32::from(le(150))
                    };
                    let status = if *revision <= 1 {
                        u32::from(b[151])
                    } else {
                        u32::from(le(152))
                    };
                    if !check(1, state & mask != 0)
                        || !check(2, u32::from(t.original.protocol) == u32::from(le(136)))
                        || !check(64, t.status & status == status)
                        || !check(4096, !t.reply)
                    {
                        return None;
                    }
                    let reply = t.translated.reverse();
                    let endpoints = [
                        t.original.tuple.source,
                        t.original.tuple.destination,
                        reply.tuple.source,
                        reply.tuple.destination,
                    ];
                    for (i, ep) in endpoints.into_iter().enumerate() {
                        let addr = match ep.ip() {
                            std::net::IpAddr::V4(v) => {
                                let mut a = [0; 16];
                                a[..4].copy_from_slice(&v.octets());
                                a
                            }
                            std::net::IpAddr::V6(v) => v.octets(),
                        };
                        let a = i * 32;
                        let matched = addr
                            .iter()
                            .enumerate()
                            .all(|(j, v)| v & b[a + 16 + j] == b[a + j] & b[a + 16 + j]);
                        if !check(4 << i, matched) {
                            return None;
                        }
                        let p = 138 + i * 2;
                        let low = if *revision == 3 {
                            le(p)
                        } else {
                            u16::from_be_bytes(b[p..p + 2].try_into().unwrap())
                        };
                        let high = if *revision == 3 { le(154 + i * 2) } else { low };
                        if !check(256 << i, ep.port() >= low && ep.port() <= high) {
                            return None;
                        }
                    }
                }
                Expr::CtGet {
                    dest,
                    key,
                    direction,
                } => {
                    let b = ctx.track?.load(*key, *direction)?;
                    regs[*dest..*dest + b.len()].copy_from_slice(&b);
                }
                Expr::CtSet { src, key } => {
                    if *key == 17 {
                        effects.zone =
                            Some(u16::from_le_bytes(regs[*src..*src + 2].try_into().unwrap()));
                    } else {
                        effects.mark =
                            Some(u32::from_le_bytes(regs[*src..*src + 4].try_into().unwrap()));
                    }
                }
                Expr::Fib { dest, flags } => {
                    regs[*dest..*dest + 4].copy_from_slice(
                        &(if *flags == 1 {
                            ctx.source_type
                        } else {
                            ctx.destination_type
                        })
                        .to_le_bytes(),
                    );
                }
                Expr::AddrType {
                    source,
                    destination,
                    flags,
                } => {
                    let test = |mask: u16, kind: u32, invert: bool| {
                        mask == 0 || ((mask & (1 << kind) != 0) ^ invert)
                    };
                    if !test(*source, ctx.source_type, *flags & 1 != 0)
                        || !test(*destination, ctx.destination_type, *flags & 2 != 0)
                    {
                        return None;
                    }
                }
                Expr::Nat {
                    source,
                    family,
                    address,
                    address_max,
                    port,
                    port_max,
                } => {
                    if *family != u32::from(ctx.family()) {
                        return None;
                    }
                    let ip = |r: usize| -> std::net::IpAddr {
                        if *family == 2 {
                            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&regs[r..r + 4]).unwrap())
                                .into()
                        } else {
                            std::net::Ipv6Addr::from(
                                <[u8; 16]>::try_from(&regs[r..r + 16]).unwrap(),
                            )
                            .into()
                        }
                    };
                    let address = address.map(ip);
                    if address_max.is_some_and(|r| address.is_some_and(|a| ip(r) < a)) {
                        return Some((0, None));
                    }
                    let port = port.map(|r| u16::from_be_bytes(regs[r..r + 2].try_into().unwrap()));
                    let high = port_max
                        .map(|r| u16::from_be_bytes(regs[r..r + 2].try_into().unwrap()))
                        .or(port);
                    effects.nat = Some(NatAction {
                        source: *source,
                        address,
                        ports: port.zip(high),
                    });
                    return Some((1, None));
                }
                Expr::Masquerade { port, port_max } => {
                    let Some(address) = ctx.masquerade else {
                        return Some((0, None));
                    };
                    let port = port.map(|r| u16::from_be_bytes(regs[r..r + 2].try_into().unwrap()));
                    let high = port_max
                        .map(|r| u16::from_be_bytes(regs[r..r + 2].try_into().unwrap()))
                        .or(port);
                    effects.nat = Some(NatAction {
                        source: true,
                        address: Some(address),
                        ports: port.zip(high),
                    });
                    return Some((1, None));
                }
                Expr::Counter { packets, bytes } => {
                    packets.set(packets.get().wrapping_add(1));
                    bytes.set(bytes.get().wrapping_add(ctx.packet.len() as u64));
                }
                Expr::Verdict(-1, _) => {}
                Expr::Verdict(code, chain) => return Some((*code, chain.as_deref())),
            }
        }
        None
    }
}
impl Table {
    fn verdict(
        &self,
        chain: &str,
        ctx: &Context<'_>,
        budget: &mut usize,
        effects: &mut Effects,
    ) -> i32 {
        let c = &self.chains[chain];
        for r in &c.rules {
            if *budget == 0 {
                return 0;
            }
            *budget -= 1;
            match r.verdict(ctx, effects) {
                Some((0, _)) => return 0,
                Some((1, _)) => return 1,
                Some((-5, _)) => return -5,
                Some((code, Some(next))) if matches!(code, -3 | -4) => {
                    let v = self.verdict(next, ctx, budget, effects);
                    if v >= 0 {
                        return v;
                    }
                    if code == -4 {
                        return -5;
                    }
                }
                _ => {}
            }
        }
        -5
    }
}
impl Ruleset {
    pub fn has_rules(&self) -> bool {
        self.active_hooks != 0
    }
    pub fn active(&self, hook: u32) -> bool {
        self.active_hooks & (1 << hook) != 0
    }
    #[cfg(test)]
    pub fn allows(&self, ctx: &Context<'_>) -> bool {
        if self.tables.is_empty() {
            return true;
        }
        let mut hooks = vec![];
        for ((family, _), t) in &self.tables {
            if *family != 1 && *family != ctx.family() {
                continue;
            }
            for (n, c) in &t.chains {
                if let Some((h, priority)) = c.hook {
                    if h == ctx.hook {
                        hooks.push((priority, t, n, c));
                    }
                }
            }
        }
        hooks.sort_by_key(|(p, _, _, _)| *p);
        for (_, t, n, c) in hooks {
            let v = t.verdict(n, ctx, &mut 8192, &mut Effects::default());
            if v == 0 {
                return false;
            }
            if v < 0 {
                c.packets.set(c.packets.get().wrapping_add(1));
                c.bytes
                    .set(c.bytes.get().wrapping_add(ctx.packet.len() as u64));
                if c.policy == 0 {
                    return false;
                }
            }
        }
        true
    }
}
#[cfg(test)]
fn expressions(bytes: &[u8]) -> Result<Vec<Expr>> {
    expressions_in(bytes, 2)
}
#[cfg(test)]
#[path = "nftables_tests.rs"]
mod tests;
