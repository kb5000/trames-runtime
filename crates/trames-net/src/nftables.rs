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
fn expressions(bytes: &[u8]) -> Result<Vec<Expr>> {
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
        string(&mut d, 7, "filter");
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
            if !matches!(n.as_str(), "tcp" | "udp" | "icmp" | "icmp6")
                || num(&a, 2)? != 0
                || num(&a, 3)? != 0
            {
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
                if h.is_some_and(|(hook, _)| {
                    !ns.nft_packet_hooks.get() || hook > 4 || ns.native.get().is_some() && hook != 2
                }) || typ.as_deref().is_some_and(|v| v != "filter")
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
                    if h.is_some_and(|v| Some(v) != c.hook) || typ.is_some() && c.hook.is_none() {
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
                let expressions = expressions(&wire)?;
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
/// One datagram is one bounded transaction. Split batches, sets, NAT, conntrack,
/// xt compat and notifications remain explicit EOPNOTSUPP rather than fake ACKs.
pub(crate) fn request(
    ns: &Namespace,
    requests: &[&[u8]],
    port: u32,
    admin: bool,
    slots: usize,
    capacity: usize,
) -> Result<Vec<Vec<u8>>> {
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
impl Rule {
    fn verdict(&self, ctx: &Context<'_>) -> Option<(i32, Option<&str>)> {
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
    fn verdict(&self, chain: &str, ctx: &Context<'_>, budget: &mut usize) -> i32 {
        let c = &self.chains[chain];
        for r in &c.rules {
            if *budget == 0 {
                return 0;
            }
            *budget -= 1;
            match r.verdict(ctx) {
                Some((0, _)) => return 0,
                Some((1, _)) => return 1,
                Some((-5, _)) => return -5,
                Some((code, Some(next))) if matches!(code, -3 | -4) => {
                    let v = self.verdict(next, ctx, budget);
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
    pub fn active(&self, hook: u32) -> bool {
        self.active_hooks & (1 << hook) != 0
    }
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
            let v = t.verdict(n, ctx, &mut 8192);
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
#[path = "nftables_tests.rs"]
mod tests;
