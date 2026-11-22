// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded guest nf_tables ABI and packet filter. Wire identifiers follow Linux
//! UAPI nf_tables.h/nfnetlink.h (GPL-2.0 WITH Linux-syscall-note).
//! No host firewall calls; unsupported hooks/expressions fail before publication.
#[path = "nft_payload.rs"]
mod payload;
#[path = "nft_sets.rs"]
mod sets;
#[path = "nft_xt_match.rs"]
mod xt_match;
use crate::{
    netlink::{attr, message, Namespace},
    NetError,
};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
};
// Counters are independent accounting metadata, not packet publication.
#[derive(Default)]
struct Counter(AtomicU64);
impl Counter {
    fn new(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }
    fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
    fn add(&self, value: u64) {
        self.0.fetch_add(value, Relaxed);
    }
}
impl Clone for Counter {
    fn clone(&self) -> Self {
        Self::new(self.get())
    }
}
type Result<T> = std::result::Result<T, NetError>;
#[path = "nft_conntrack.rs"]
mod ctnetlink;
const SUBSYSTEM: u16 = 10 << 8;
const FIB_SADDR: u32 = 1;
const FIB_DADDR: u32 = 2;
const FIB_MARK: u32 = 4;
const FIB_IIF: u32 = 8;
const FIB_OIF: u32 = 16;
const FIB_PRESENT: u32 = 32;
const FIB_RESULT_OIF: u32 = 1;
const FIB_RESULT_OIFNAME: u32 = 2;
const FIB_RESULT_ADDRTYPE: u32 = 3;
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
#[derive(Clone)]
pub(crate) struct Ruleset {
    generation: u32,
    next: u64,
    active_hooks: u8,
    tables: BTreeMap<(u8, String), Table>,
}
impl Default for Ruleset {
    fn default() -> Self {
        Self {
            generation: 1,
            next: 0,
            active_hooks: 0,
            tables: BTreeMap::new(),
        }
    }
}
/// The published rules and their empty-policy selector are one resource. The
/// selector only skips evaluation when no hook exists; actual filtering still
/// takes the original rules transaction. It publishes no packet/guest bytes.
#[derive(Default)]
pub(crate) struct Firewall {
    rules: std::sync::RwLock<Ruleset>,
    active: std::sync::atomic::AtomicBool,
}
impl From<Ruleset> for Firewall {
    fn from(rules: Ruleset) -> Self {
        Self {
            active: std::sync::atomic::AtomicBool::new(rules.has_rules()),
            rules: std::sync::RwLock::new(rules),
        }
    }
}
impl Firewall {
    pub(super) fn release_port(&self, port: u32) {
        let mut rules = self.rules.write().unwrap();
        let before = rules.tables.len();
        rules.tables.retain(|_, t| t.owner != Some(port));
        if rules.tables.len() != before {
            rules.refresh_hooks();
            rules.generation = rules.generation.wrapping_add(1).max(1);
            self.active.store(rules.has_rules(), Relaxed);
        }
    }
    pub fn has_rules(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn read(&self) -> std::sync::LockResult<std::sync::RwLockReadGuard<'_, Ruleset>> {
        self.rules.read()
    }
}
#[derive(Clone)]
struct Table {
    handle: u64,
    next: u64,
    dormant: bool,
    owner: Option<u32>,
    userdata: Vec<u8>,
    chains: BTreeMap<String, Chain>,
    sets: sets::Sets,
}
/// Netlink batch IDs are temporary. Handles keep a deleted object from being
/// rebound to a new object with the same name.
#[derive(Default)]
struct BatchIds {
    sets: sets::BatchIds,
    chains: Vec<(u64, u32, u64)>,
    rules: BTreeMap<(u64, u64, u32), u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Binding {
    Regular,
    Unbound,
    Bound,
}

#[derive(Clone)]
struct Chain {
    binding: Binding,
    handle: u64,
    hook: Option<(u32, i32)>,
    policy: u32,
    chain_type: String,
    userdata: Vec<u8>,
    rules: Vec<Rule>,
    counters: Option<ChainCounters>,
}
#[derive(Clone)]
struct ChainCounters {
    bytes: Counter,
    packets: Counter,
}
impl ChainCounters {
    fn record(&self, length: usize) {
        self.bytes.add(length as u64);
        self.packets.add(1);
    }
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
    Comment,
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
    PayloadSet {
        src: usize,
        len: usize,
        write: payload::Write,
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
    Shift {
        src: usize,
        dest: usize,
        len: usize,
        left: bool,
        bits: u32,
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
        result: u32,
        dest: usize,
        flags: u32,
    },
    TransportMatch(xt_match::Transport),
    Lookup(sets::Lookup),
    ConntrackMatch {
        revision: u32,
        info: Vec<u8>,
    },
    FixedNat {
        kind: FixedNatKind,
        addresses: Option<(std::net::IpAddr, std::net::IpAddr)>,
        ports: Option<(u16, u16)>,
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
        packets: Counter,
        bytes: Counter,
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
    let a = fields(bytes, &[1]).map_err(|_| NetError(22))?;
    let v = need(&a, 1)?;
    if v.is_empty() || v.len() > 16 {
        return Err(NetError(22));
    }
    Ok(v.to_vec())
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum FixedNatKind {
    Source,
    Destination,
    Masquerade,
    Redirect,
}
impl FixedNatKind {
    fn named(name: &str) -> Option<Self> {
        match name {
            "SNAT" => Some(Self::Source),
            "DNAT" => Some(Self::Destination),
            "MASQUERADE" => Some(Self::Masquerade),
            "REDIRECT" => Some(Self::Redirect),
            _ => None,
        }
    }
    fn valid_hook(self, hook: u32) -> bool {
        match self {
            Self::Source => matches!(hook, 1 | 4),
            Self::Masquerade => hook == 4,
            Self::Destination | Self::Redirect => matches!(hook, 0 | 3),
        }
    }
}

/// Versions with a guest packet implementation, shared by both xtables probe ABIs.
pub fn xt_revision(family: u8, name: &str, revision: u32, target: bool) -> Result<u32> {
    let (min, max) = match (name, target) {
        ("comment", false) => (0, 0),
        (name, false) if xt_match::protocol(name, family).is_some() => (0, 0),
        ("addrtype", false) => (u32::from(family != 2), 1),
        ("conntrack", false) => (1, 3),
        ("CT", true) => (0, 1),
        ("MASQUERADE" | "REDIRECT", true) if matches!(family, 2 | 10) => (0, 0),
        ("SNAT" | "DNAT", true) if matches!(family, 2 | 10) => (u32::from(family != 2), 2),
        _ => return Err(NetError(2)),
    };
    if (min..=max).contains(&revision) {
        Ok(max)
    } else {
        Err(NetError(93))
    }
}
fn expressions_in(
    bytes: &[u8],
    rule_family: u8,
    table: Option<&Table>,
    ids: &BatchIds,
) -> Result<Vec<Expr>> {
    let mut out = vec![];
    let mut initialized = [false; 64];
    for (kind, b) in attrs(bytes)? {
        if kind != 1 || out.len() >= 128 {
            return Err(NetError(22));
        }
        let a = fields(b, &[1, 2])?;
        let data = need(&a, 2)?;
        let expr = match name(&a, 1)?.as_str() {
            "immediate" => {
                let a = fields(data, &[1, 2])?;
                if num(&a, 1)? == 0 {
                    let d = fields(need(&a, 2)?, &[2]).map_err(|_| NetError(22))?;
                    let v = fields(need(&d, 2)?, &[1, 2, 3])?;
                    let code = num(&v, 1)? as i32;
                    if !matches!(code, -5..=1) {
                        return Err(NetError(95));
                    }
                    let chain = if let Some(n) = get(&v, 2) {
                        Some(text(n)?)
                    } else if let Some(id) = get(&v, 3) {
                        Some(table.ok_or(NetError(2))?.batch_chain(ids, u32v(id)?)?)
                    } else {
                        None
                    };
                    if matches!(code, -3 | -4) != chain.is_some() {
                        return Err(NetError(22));
                    }
                    Expr::Verdict(code, chain)
                } else {
                    let mut v = value(need(&a, 2)?)?;
                    let dest = reg(num(&a, 1)?, v.len()).map_err(|_| NetError(34))?;
                    v.resize(v.len().next_multiple_of(4), 0);
                    initialized[dest..dest + v.len()].fill(true);
                    Expr::Immediate { dest, value: v }
                }
            }
            "meta" => {
                let a = fields(data, &[1, 2, 3])?;
                let key = num(&a, 2)?;
                if key > u8::MAX.into() {
                    return Err(NetError(34));
                }
                if get(&a, 1).is_some() == get(&a, 3).is_some() {
                    return Err(NetError(22));
                }
                if get(&a, 3).is_some() {
                    return Err(NetError(95));
                }
                let len = match key {
                    0 | 4 | 5 | 15 | 16 | 19 => 4,
                    1 | 8 | 9 | 36 => 2,
                    6 | 7 | 26 | 27 => 16,
                    _ => return Err(NetError(95)),
                };
                let dest = reg(num(&a, 1)?, len)?;
                initialized[dest..dest + len].fill(true);
                Expr::Meta { dest, key }
            }
            "lookup" => Expr::Lookup(sets::Lookup::parse(
                data,
                table,
                &ids.sets,
                &mut initialized,
            )?),
            "payload" => payload::parse(data, rule_family, &mut initialized)?,
            "cmp" => {
                let a = fields(data, &[1, 2, 3])?;
                let op = num(&a, 2)?;
                if op > 5 {
                    return Err(NetError(22));
                }
                let v = value(need(&a, 3)?)?;
                let src = reg(num(&a, 1)?, v.len())?;
                if initialized[src..src + v.len()].contains(&false) {
                    return Err(NetError(22));
                }
                Expr::Compare { src, op, value: v }
            }
            "bitwise" => {
                let a = fields(data, &[1, 2, 3, 4, 5, 6, 7])?;
                let len = num(&a, 3)? as usize;
                let src = reg(num(&a, 1)?, len)?;
                let dest = reg(num(&a, 2)?, len)?;
                if initialized[src..src + len].contains(&false) {
                    return Err(NetError(22));
                }
                initialized[dest..dest + len].fill(true);
                match get(&a, 6).map(u32v).transpose()?.unwrap_or(0) {
                    0 => {
                        let mask = value(need(&a, 4)?)?;
                        let xor = value(need(&a, 5)?)?;
                        if mask.len() != len || xor.len() != len || get(&a, 7).is_some() {
                            return Err(NetError(22));
                        }
                        Expr::Bitwise {
                            src,
                            dest,
                            mask,
                            xor,
                        }
                    }
                    op @ (1 | 2) => {
                        if get(&a, 4).is_some() || get(&a, 5).is_some() {
                            return Err(NetError(22));
                        }
                        let bytes = value(need(&a, 7)?)?;
                        let bits = u32::from_le_bytes(bytes.try_into().map_err(|_| NetError(22))?);
                        if bits >= 32 {
                            return Err(NetError(22));
                        }
                        Expr::Shift {
                            src,
                            dest,
                            len,
                            left: op == 1,
                            bits,
                        }
                    }
                    _ => return Err(NetError(95)),
                }
            }
            "ct" => {
                let a = fields(data, &[1, 2, 3, 4])?;
                let key = num(&a, 2)?;
                if key > u8::MAX.into() {
                    return Err(NetError(34));
                }
                if get(&a, 1).is_some() == get(&a, 4).is_some() {
                    return Err(NetError(22));
                }
                let directed = get(&a, 3).is_some();
                if matches!(key, 8 | 9 | 11 | 12 | 19..=22) && !directed
                    || matches!(key, 0..=3 | 23) && directed
                {
                    return Err(NetError(22));
                }
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
                    if directed || !matches!(key, 3 | 17) {
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
                let register = num(&a, 1)?;
                let result = num(&a, 2)?;
                let flags = num(&a, 3)?;
                if !matches!(result, 1..=3)
                    || !matches!(flags & (FIB_SADDR | FIB_DADDR), FIB_SADDR | FIB_DADDR)
                    || flags & !(FIB_SADDR | FIB_DADDR | FIB_IIF | FIB_OIF | FIB_MARK | FIB_PRESENT)
                        != 0
                    || flags & FIB_IIF != 0 && flags & FIB_OIF != 0
                    || (result != FIB_RESULT_ADDRTYPE && flags & FIB_OIF != 0)
                    || (result != FIB_RESULT_OIF && flags & FIB_PRESENT != 0)
                {
                    return Err(NetError(22));
                }
                // Socket marks currently select routes at socket send time.
                // Per-packet marks are not carried through every packet hook.
                if flags & FIB_MARK != 0 {
                    return Err(NetError(95));
                }
                let len = if result == FIB_RESULT_OIFNAME { 16 } else { 4 };
                if register == 0 {
                    return Err(NetError(22));
                }
                let dest = reg(register, len).map_err(|_| NetError(34))?;
                initialized[dest..dest + len].fill(true);
                Expr::Fib {
                    dest,
                    result,
                    flags,
                }
            }
            "match" => {
                let a = fields(data, &[1, 2, 3])?;
                let kind = name(&a, 1)?;
                let revision = num(&a, 2)?;
                let b = need(&a, 3)?;
                if kind == "comment" {
                    if revision != 0 {
                        return Err(NetError(2));
                    }
                    if b.len() != 256 {
                        return Err(NetError(22));
                    }
                    Expr::Comment
                } else if kind == "conntrack" {
                    let size = xt_match::conntrack_size(revision)?;
                    xt_match::check_size(b, size)?;
                    Expr::ConntrackMatch {
                        revision,
                        info: b.to_vec(),
                    }
                } else if let Some(proto) = xt_match::protocol(&kind, rule_family) {
                    if revision != 0 {
                        return Err(NetError(2));
                    }
                    Expr::TransportMatch(xt_match::Transport::parse(proto, b)?)
                } else {
                    if kind != "addrtype" || revision > 1 || revision == 0 && rule_family != 2 {
                        return Err(NetError(2));
                    }
                    if (revision == 0 && !matches!(b.len(), 12 | 16))
                        || (revision == 1 && b.len() != 8)
                    {
                        return Err(NetError(22));
                    }
                    let source = u16::from_le_bytes(b[..2].try_into().unwrap());
                    let destination = u16::from_le_bytes(b[2..4].try_into().unwrap());
                    let word = u32::from_le_bytes(b[4..8].try_into().unwrap());
                    let flags = if revision == 0 {
                        u32::from(word != 0) | (u32::from(b[8..12] != [0; 4]) << 1)
                    } else {
                        word
                    };
                    if flags & 12 == 12 {
                        return Err(NetError(22));
                    }
                    if flags & !15 != 0 || (source | destination) & !0x2e != 0 {
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
                    let nat = FixedNatKind::named(&kind).ok_or(NetError(2))?;
                    xt_revision(rule_family, &kind, revision, true).map_err(|_| NetError(2))?;
                    let legacy = revision == 0 && rule_family == 2;
                    let size = if legacy {
                        20usize
                    } else if revision == 2 {
                        44
                    } else {
                        40
                    };
                    if b.len() != size && b.len() != size.next_multiple_of(8) {
                        return Err(NetError(22));
                    }
                    let word = |at| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
                    if legacy && word(0) != 1 {
                        return Err(NetError(22));
                    }
                    let flags = word(if legacy { 4 } else { 0 });
                    if matches!(nat, FixedNatKind::Masquerade | FixedNatKind::Redirect)
                        && flags & 1 != 0
                    {
                        return Err(NetError(22));
                    }
                    if flags & !3 != 0 {
                        return Err(NetError(95));
                    }
                    let addresses = if flags & 1 == 0 {
                        None
                    } else {
                        let address = |at: usize| -> std::net::IpAddr {
                            if rule_family == 2 {
                                std::net::Ipv4Addr::from(
                                    <[u8; 4]>::try_from(&b[at..at + 4]).unwrap(),
                                )
                                .into()
                            } else {
                                std::net::Ipv6Addr::from(
                                    <[u8; 16]>::try_from(&b[at..at + 16]).unwrap(),
                                )
                                .into()
                            }
                        };
                        let (start, end) = if legacy { (8, 12) } else { (4, 20) };
                        let range = (address(start), address(end));
                        if range.0 > range.1 {
                            return Err(NetError(22));
                        }
                        Some(range)
                    };
                    let ports = if flags & 2 == 0 {
                        None
                    } else {
                        let at = if legacy { 16 } else { 36 };
                        let low = u16::from_be_bytes(b[at..at + 2].try_into().unwrap());
                        let high = u16::from_be_bytes(b[at + 2..at + 4].try_into().unwrap());
                        if low > high {
                            return Err(NetError(22));
                        }
                        Some((low, high))
                    };
                    Expr::FixedNat {
                        kind: nat,
                        addresses,
                        ports,
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
                if flags & !0x7f != 0 {
                    return Err(NetError(22));
                }
                if flags & !3 != 0 {
                    return Err(NetError(95));
                }
                let register = |field, len| -> Result<Option<usize>> {
                    let r = get(&a, field)
                        .map(u32v)
                        .transpose()?
                        .map(|r| {
                            if !matches!(r,0..=4|8..=23) {
                                Err(NetError(34))
                            } else {
                                reg(r, len)
                            }
                        })
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
                    bytes: Counter::new(get(&a, 1).map(u64v).transpose()?.unwrap_or(0)),
                    packets: Counter::new(get(&a, 2).map(u64v).transpose()?.unwrap_or(0)),
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
    number(
        &mut d,
        2,
        u32::from(t.dormant) | (u32::from(t.owner.is_some()) << 1),
    );
    if let Some(owner) = t.owner {
        number(&mut d, 7, owner);
    }
    number(&mut d, 3, (t.chains.len() + t.sets.len()) as u32);
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
        attr(&mut d, 4, &h);
        number(&mut d, 5, c.policy);
        string(&mut d, 7, &c.chain_type);
        if let Some(counts) = &c.counters {
            let mut counters = vec![];
            integer(&mut counters, 1, counts.bytes.get());
            integer(&mut counters, 2, counts.packets.get());
            attr(&mut d, 8, &counters);
        }
    }
    number(
        &mut d,
        10,
        if c.binding == Binding::Bound {
            4
        } else {
            u32::from(c.hook.is_some())
        },
    );
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
            attr(&mut e, 2, &c);
            attr(&mut wire, kind, &e);
        } else if matches!(expr, Expr::TransportMatch(_) | Expr::ConntrackMatch { .. }) {
            let outer = attrs(b).expect("validated match expression");
            let inner = attrs(get(&outer, 2).unwrap()).expect("validated xt match");
            let size = match expr {
                Expr::TransportMatch(m) => m.info_size(),
                Expr::ConntrackMatch { revision, .. } => {
                    xt_match::conntrack_size(*revision).unwrap()
                }
                _ => unreachable!(),
            };
            let mut info = get(&inner, 3).unwrap()[..size].to_vec();
            info.resize(size.next_multiple_of(8), 0);
            let mut data = vec![];
            attr(&mut data, 1, get(&inner, 1).unwrap());
            attr(&mut data, 2, get(&inner, 2).unwrap());
            attr(&mut data, 3, &info);
            let mut e = vec![];
            string(&mut e, 1, "match");
            // nftables dumps NFTA_EXPR_DATA without NLA_F_NESTED.
            attr(&mut e, 2, &data);
            attr(&mut wire, kind, &e);
        } else if let Expr::Lookup(lookup) = expr {
            let mut e = vec![];
            string(&mut e, 1, "lookup");
            attr(&mut e, 2, &lookup.wire());
            attr(&mut wire, kind, &e);
        } else if let Expr::Verdict(code, Some(target)) = expr {
            // The original wire names the chain at insertion time. A dump must
            // refer to the same chain after a rename.
            let mut verdict = vec![];
            number(&mut verdict, 1, *code as u32);
            string(&mut verdict, 2, target);
            let mut value = vec![];
            attr(&mut value, 2, &verdict);
            let mut immediate = vec![];
            number(&mut immediate, 1, 0);
            attr(&mut immediate, 2, &value);
            let mut e = vec![];
            string(&mut e, 1, "immediate");
            attr(&mut e, 2, &immediate);
            attr(&mut wire, kind, &e);
        } else {
            attr(&mut wire, kind, b);
        }
    }
    attr(&mut d, 4, &wire);
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
fn next_handle(last: &mut u64) -> Result<u64> {
    *last = last.checked_add(1).ok_or(NetError(28))?;
    Ok(*last)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum PacketHooks {
    Unavailable,
    NativeSocket,
    GuestPackets,
}
impl Ruleset {
    fn bounds(&self) -> Result<()> {
        let mut chains = 0;
        let mut rules = 0;
        let mut bytes = 0;
        for ((_, name), t) in &self.tables {
            bytes += name.len() + t.userdata.len() + 128;
            bytes += t
                .sets
                .iter()
                .map(|(name, s)| name.len() + s.bytes())
                .sum::<usize>();
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
                            Expr::FixedNat { kind, .. } if !nat || !kind.valid_hook(hook) => {
                                return Err(NetError(22))
                            }
                            Expr::Nat { .. } | Expr::Masquerade { .. } if !nat => {
                                return Err(NetError(95))
                            }
                            Expr::AddrType { flags, .. }
                                if (flags & 4 != 0 && hook >= 3)
                                    || (flags & 8 != 0 && hook <= 1) =>
                            {
                                return Err(NetError(22))
                            }
                            Expr::Fib { result, flags, .. }
                                if (*result != FIB_RESULT_ADDRTYPE
                                    && hook != 0
                                    && !(flags & FIB_IIF != 0 && matches!(hook, 1 | 2)))
                                    || (*result == FIB_RESULT_ADDRTYPE
                                        && ((flags & FIB_IIF != 0 && hook >= 3)
                                            || (flags & FIB_OIF != 0 && hook < 2))) =>
                            {
                                return Err(NetError(95))
                            }
                            Expr::Zone(_) | Expr::CtSet { key: 17, .. }
                                if priority >= -200 || !matches!(hook, 0 | 3) =>
                            {
                                return Err(NetError(95))
                            }
                            Expr::Nat { source: true, .. } if !matches!(hook, 1 | 4) => {
                                return Err(NetError(95))
                            }
                            Expr::Masquerade { .. } if hook != 4 => return Err(NetError(95)),
                            Expr::Nat { source: false, .. } if !matches!(hook, 0 | 3) => {
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
                if c.binding == Binding::Unbound {
                    return Err(NetError(22));
                }
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
        packet_hooks: PacketHooks,
        r: &[u8],
        port: u32,
        batch: bool,
        ids: &mut BatchIds,
    ) -> Result<Vec<Vec<u8>>> {
        let kind = kind(r);
        let flags = flags(r);
        let seq = u32::from_le_bytes(r[8..12].try_into().unwrap());
        if r.len() < 20 || r[17] != 0 {
            return Err(NetError(22));
        }
        if kind == 11 << 8 && !batch {
            let a = fields(&r[20..], &[1, 2, 3])?;
            let n = name(&a, 1)?;
            let revision = num(&a, 2)?;
            let target = num(&a, 3)?;
            if target > 1 {
                return Err(NetError(95));
            }
            xt_revision(r[16], &n, revision, target == 1).map_err(|error| {
                if n == "comment" && target == 0 {
                    error
                } else {
                    NetError(95)
                }
            })?;
            return Ok(vec![message(kind, 0, seq, port, &r[16..])]);
        }
        if kind >> 8 != 10 {
            return Err(NetError(95));
        }
        let op = kind & 255;
        let dump = flags & 0x300 == 0x300;
        let read = matches!(op, 1 | 4 | 7 | 10 | 13 | 16);
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
        if !matches!(family, 0 | 1 | 2 | 10) || (!read && family == 0 && op != 2) {
            return Err(NetError(95));
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
            0 | 3 | 9 | 12 => 0x400 | 0x200,
            2 | 5 | 11 => 0x100,
            6 => 0xf00,
            _ => 0,
        };
        if !read && flags & !(1 | 4 | mutation_flags) != 0 {
            return Err(NetError(95));
        }
        let allowed: &[u16] = match op {
            0 => &[1, 2, 6],
            1 | 2 => &[1, 4],
            3 => &[1, 2, 3, 4, 5, 7, 8, 10, 11, 12],
            4 => &[1, 2, 3],
            5 => &[1, 2, 3, 6, 11],
            6 => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            7 => &[1, 2, 3],
            // libnftnl echoes the selected rule when deleting by handle.
            8 => &[1, 2, 3, 4, 5, 7, 8, 9],
            9 => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13],
            10 => &[1, 2],
            11 => &[1, 2, 16],
            12 | 14 => &[1, 2, 3, 4],
            13 => &[1, 2, 3],
            _ => return Err(NetError(95)),
        };
        let a = fields(&r[20..], allowed)?;
        if matches!(op, 10 | 13) {
            return self.read_sets(op, family, &a, dump, seq, port);
        }
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
            let handle_attr = match op {
                1 => 4,
                4 => 2,
                _ => 3,
            };
            let handle = get(&a, handle_attr).map(u64v).transpose()?;
            if !dump
                && match op {
                    1 => table.is_none() && handle.is_none(),
                    4 => table.is_none() || (chain.is_none() && handle.is_none()),
                    _ => table.is_none() || chain.is_none() || handle.is_none(),
                }
            {
                return Err(NetError(22));
            }
            let mut found = false;
            for ((f, n), t) in &self.tables {
                if family != 0 && family != *f || table.as_ref().is_some_and(|v| v != n) {
                    continue;
                }
                if op == 1 {
                    if handle.is_some_and(|h| h != t.handle) {
                        continue;
                    }
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
        if op == 2 {
            let table = get(&a, 1).map(text).transpose()?;
            let handle = get(&a, 4).map(u64v).transpose()?;
            let flush = family == 0 || (table.is_none() && handle.is_none());
            let mut remove = Vec::new();
            for (key, t) in &self.tables {
                if (family != 0 && family != key.0)
                    || table.as_ref().is_some_and(|n| *n != key.1)
                    || handle.is_some_and(|h| h != t.handle)
                {
                    continue;
                }
                if t.owner.is_some_and(|owner| owner != port) {
                    if flush {
                        continue;
                    }
                    return Err(NetError(1));
                }
                if flags & 0x100 != 0 && (!t.chains.is_empty() || !t.sets.is_empty()) {
                    return Err(NetError(16));
                }
                remove.push(key.clone());
            }
            if remove.is_empty() && !flush {
                return Err(NetError(2));
            }
            for key in remove {
                self.tables.remove(&key);
            }
            return Ok(out);
        }
        let key = (family, name(&a, 1)?);
        if let Some(t) = self.tables.get(&key) {
            if t.owner.is_some_and(|owner| owner != port) {
                return Err(NetError(1));
            }
        } else if op != 0 {
            return Err(NetError(2));
        }
        match op {
            0 => {
                let options = get(&a, 2).map(u32v).transpose()?;
                if options.is_some_and(|f| f & !3 != 0) {
                    return Err(NetError(95));
                }
                if let Some(t) = self.tables.get_mut(&key) {
                    if flags & 0x200 != 0 {
                        return Err(NetError(17));
                    }
                    if let Some(f) = options {
                        if (f & 2 != 0) != t.owner.is_some() {
                            return Err(NetError(95));
                        }
                        t.dormant = f & 1 != 0;
                    }
                } else {
                    let handle = next_handle(&mut self.next)?;
                    let userdata = get(&a, 6).unwrap_or_default().to_vec();
                    if userdata.len() > 256 {
                        return Err(NetError(22));
                    }
                    self.tables.insert(
                        key,
                        Table {
                            handle,
                            next: 0,
                            dormant: options.unwrap_or(0) & 1 != 0,
                            owner: (options.unwrap_or(0) & 2 != 0).then_some(port),
                            userdata,
                            chains: BTreeMap::new(),
                            sets: BTreeMap::new(),
                        },
                    );
                }
            }
            3 => {
                let table = self.tables.get_mut(&key).ok_or(NetError(2))?;
                let id = get(&a, 11).map(u32v).transpose()?;
                let chainflags = get(&a, 10).map(u32v).transpose()?.unwrap_or(0);
                let binding = chainflags & 4 != 0;
                let requested = get(&a, 3).map(text).transpose()?;
                let cn = if let Some(handle) = get(&a, 2) {
                    let old = table.chain_name(u64v(handle)?)?;
                    if table.chains[&old].binding != Binding::Regular {
                        return Err(NetError(95));
                    }
                    if flags & 0x200 != 0 {
                        return Err(NetError(17));
                    }
                    match requested {
                        Some(new) if new != old => {
                            table.rename_chain(&old, &new)?;
                            new
                        }
                        _ => old,
                    }
                } else if let Some(n) = requested {
                    n
                } else if binding {
                    let mut suffix = table.next;
                    loop {
                        let n = format!("__chain{}", next_handle(&mut suffix)?);
                        if !table.chains.contains_key(&n) {
                            break n;
                        }
                    }
                } else {
                    return Err(NetError(22));
                };
                let h = get(&a, 4)
                    .map(|b| -> Result<(u32, i32)> {
                        let a = fields(b, &[1, 2])?;
                        Ok((
                            u32v(get(&a, 1).ok_or(NetError(2))?)?,
                            u32v(get(&a, 2).ok_or(NetError(2))?)? as i32,
                        ))
                    })
                    .transpose()?;
                let typ = get(&a, 7).map(text).transpose()?;
                // Native BSD socket I/O does not pass through the packet stack.
                // Root hooks other than FORWARD cannot yet be promised safely.
                if h.is_some_and(|(hook, _)| packet_hooks == PacketHooks::Unavailable || hook > 4)
                    || typ
                        .as_deref()
                        .is_some_and(|v| !matches!(v, "filter" | "nat"))
                {
                    return Err(NetError(95));
                }
                if typ.as_deref() == Some("nat")
                    && h.is_none_or(|(hook, priority)| {
                        !matches!(hook, 0 | 1 | 3 | 4) || priority <= -200
                    })
                {
                    return Err(NetError(95));
                }
                let policy = get(&a, 5).map(u32v).transpose()?;
                if policy.is_some_and(|v| v > 1) {
                    return Err(NetError(22));
                }
                if binding && (h.is_some() || chainflags != 4) || chainflags == 1 && h.is_none() {
                    return Err(NetError(22));
                }
                if chainflags & !5 != 0 {
                    return Err(NetError(95));
                }
                let counters = get(&a, 8)
                    .map(|b| -> Result<ChainCounters> {
                        let a = fields(b, &[1, 2, 3])?;
                        Ok(ChainCounters {
                            bytes: Counter::new(u64v(need(&a, 1)?)?),
                            packets: Counter::new(u64v(need(&a, 2)?)?),
                        })
                    })
                    .transpose()?;
                let userdata = get(&a, 12).map(<[u8]>::to_vec);
                if userdata.as_ref().is_some_and(|v| v.len() > 256) {
                    return Err(NetError(22));
                }
                if let Some(c) = table.chains.get_mut(&cn) {
                    if c.binding != Binding::Regular || binding {
                        return Err(NetError(95));
                    }
                    if h.is_some() && c.hook.is_none() {
                        return Err(NetError(17));
                    }
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
                    if (policy.is_some() || counters.is_some()) && c.hook.is_none() {
                        return Err(NetError(95));
                    }
                    if let Some(v) = policy {
                        c.policy = v;
                    }
                    if let Some(v) = userdata {
                        c.userdata = v;
                    }
                    if counters.is_some() {
                        c.counters = counters;
                    }
                } else {
                    if h.is_none() && (policy.is_some() || typ.is_some()) {
                        return Err(NetError(95));
                    }
                    let handle = next_handle(&mut table.next)?;
                    if let Some(id) = id {
                        ids.chains.push((table.handle, id, handle));
                    }
                    table.chains.insert(
                        cn,
                        Chain {
                            binding: if binding {
                                Binding::Unbound
                            } else {
                                Binding::Regular
                            },
                            handle,
                            hook: h,
                            policy: policy.unwrap_or(1),
                            chain_type: typ.unwrap_or_else(|| "filter".to_owned()),
                            userdata: userdata.unwrap_or_default(),
                            rules: vec![],
                            counters: if h.is_some() { counters } else { None },
                        },
                    );
                }
            }
            5 => {
                let t = self.tables.get_mut(&key).ok_or(NetError(2))?;
                let cn = if let Some(raw) = get(&a, 2) {
                    t.chain_name(u64v(raw)?)?
                } else {
                    name(&a, 3)?
                };
                let c = t.chains.get(&cn).ok_or(NetError(2))?;
                if c.binding != Binding::Regular {
                    return Err(NetError(95));
                }
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
                let deleted = t.chains.remove(&cn).unwrap();
                t.release_bindings(deleted.rules);
            }
            6 => {
                let table = &self.tables[&key];
                let cn = if let Some(n) = get(&a, 2) {
                    text(n)?
                } else {
                    table.batch_chain(ids, num(&a, 11)?)?
                };
                let wire = get(&a, 4).unwrap_or_default().to_vec();
                let expressions = expressions_in(&wire, family, self.tables.get(&key), ids)?;
                // Native socket filters inspect a synthetic header; only a packet
                // backend can deliver a modified datagram to its actual recipient.
                if packet_hooks == PacketHooks::NativeSocket
                    && expressions
                        .iter()
                        .any(|e| matches!(e, Expr::PayloadSet { .. }))
                {
                    return Err(NetError(95));
                }
                if key.1 != "nat"
                    && expressions
                        .iter()
                        .any(|e| matches!(e, Expr::FixedNat { .. }))
                {
                    return Err(NetError(22));
                }
                let mut declared_protocol = None;
                let compatibility = get(&a, 5)
                    .map(|b| -> Result<Vec<u8>> {
                        let a = fields(b, &[1, 2])?;
                        let protocol = num(&a, 1)?;
                        let flags = num(&a, 2)?;
                        if protocol > 255 || flags & !2 != 0 {
                            return Err(NetError(95));
                        }
                        if flags == 0 {
                            declared_protocol = Some(protocol);
                        }
                        Ok(b.to_vec())
                    })
                    .transpose()?;
                if expressions.iter().any(|e| matches!(e, Expr::TransportMatch(m) if declared_protocol != Some(u32::from(m.protocol)))) {
                    return Err(NetError(22));
                }
                if get(&a, 8).is_some_and(|b| !b.is_empty()) {
                    return Err(NetError(22));
                }
                let userdata = get(&a, 7).unwrap_or_default().to_vec();
                if userdata.len() > 256 {
                    return Err(NetError(22));
                }
                let table = self.tables.get_mut(&key).ok_or(NetError(2))?;
                let source_binding = table.chains.get(&cn).ok_or(NetError(2))?.binding;
                if source_binding == Binding::Bound {
                    return Err(NetError(95));
                }
                for expr in &expressions {
                    if let Expr::Verdict(_, Some(n)) = expr {
                        let target = table.chains.get_mut(n).ok_or(NetError(2))?;
                        match target.binding {
                            Binding::Regular => (),
                            Binding::Bound => return Err(NetError(22)),
                            Binding::Unbound if source_binding != Binding::Regular => {
                                return Err(NetError(95))
                            }
                            Binding::Unbound => target.binding = Binding::Bound,
                        }
                    }
                }
                let c = table.chains.get_mut(&cn).unwrap();
                let rule_id = get(&a, 9).map(u32v).transpose()?;
                let chain_handle = c.handle;
                let handle;
                if let Some(old) = get(&a, 3).map(u64v).transpose()? {
                    let i = c
                        .rules
                        .iter()
                        .position(|r| r.handle == old)
                        .ok_or(NetError(2))?;
                    if flags & 0x200 != 0 {
                        return Err(NetError(17));
                    }
                    if flags & 0x100 == 0 {
                        return Err(NetError(95));
                    }
                    handle = old;
                    let previous = std::mem::replace(
                        &mut c.rules[i],
                        Rule {
                            handle: old,
                            userdata,
                            expressions,
                            wire,
                            compatibility,
                        },
                    );
                    table.release_bindings([previous]);
                } else {
                    if flags & 0x400 == 0 || flags & 0x100 != 0 {
                        return Err(NetError(22));
                    }
                    handle = next_handle(&mut table.next)?;
                    let position = if let Some(raw) = get(&a, 6) {
                        Some(u64v(raw)?)
                    } else if let Some(raw) = get(&a, 10) {
                        Some(
                            *ids.rules
                                .get(&(table.handle, chain_handle, u32v(raw)?))
                                .ok_or(NetError(2))?,
                        )
                    } else {
                        None
                    };
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
                if let Some(id) = rule_id {
                    ids.rules
                        .entry((table.handle, chain_handle, id))
                        .or_insert(handle);
                }
            }
            8 => {
                let cn = get(&a, 2).map(text).transpose()?;
                let handle = get(&a, 3).map(u64v).transpose()?;
                let t = self.tables.get_mut(&key).ok_or(NetError(2))?;
                if let Some(cn) = cn {
                    let c = t.chains.get_mut(&cn).ok_or(NetError(2))?;
                    if c.binding != Binding::Regular {
                        return Err(NetError(95));
                    }
                    let id = get(&a, 9).map(u32v).transpose()?;
                    let selected = match (handle, id) {
                        (None, Some(id)) => Some(
                            *ids.rules
                                .get(&(t.handle, c.handle, id))
                                .ok_or(NetError(2))?,
                        ),
                        _ => handle,
                    };
                    if let Some(handle) = selected {
                        let at = c
                            .rules
                            .iter()
                            .position(|r| r.handle == handle)
                            .ok_or(NetError(2))?;
                        let deleted = c.rules.remove(at);
                        t.release_bindings([deleted]);
                    } else {
                        let deleted = std::mem::take(&mut c.rules);
                        t.release_bindings(deleted);
                    }
                } else if handle.is_none() && get(&a, 9).is_none() {
                    t.chains.retain(|_, c| c.binding != Binding::Bound);
                    for c in t.chains.values_mut() {
                        c.rules.clear();
                    }
                } else {
                    return Err(NetError(22));
                }
            }
            9 | 11 | 12 | 14 => self.tables.get_mut(&key).ok_or(NetError(2))?.mutate_set(
                op,
                flags,
                &a,
                &mut ids.sets,
            )?,
            _ => return Err(NetError(95)),
        }
        self.bounds()?;
        Ok(out)
    }
}
/// One datagram is one bounded transaction. Unsupported expressions, split
/// batches and notifications return explicit EOPNOTSUPP.
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
    let shared = ns.graph.read().unwrap().firewall(ns.id());
    request_rules(
        &shared,
        if !ns.nft_packet_hooks.get() {
            PacketHooks::Unavailable
        } else if ns.native.get().is_some() {
            PacketHooks::NativeSocket
        } else {
            PacketHooks::GuestPackets
        },
        requests,
        port,
        admin,
        slots,
        capacity,
    )
}
// The actual object transaction, also usable without a namespace owner graph.
fn request_rules(
    shared: &Firewall,
    packet_hooks: PacketHooks,
    requests: &[&[u8]],
    port: u32,
    admin: bool,
    slots: usize,
    capacity: usize,
) -> Result<Vec<Vec<u8>>> {
    let batch = kind(requests[0]) == 16;
    let mut publication = batch.then(|| shared.rules.write().unwrap());
    let mut staged = match &publication {
        Some(current) => (**current).clone(),
        None => shared.read().unwrap().clone(),
    };
    let mut out = vec![];
    let mut error = None;
    let mut mutated = false;
    let mut ids = BatchIds::default();
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
                    .is_some_and(|v| v != 0 && v != staged.generation)
                {
                    return Err(NetError(85));
                }
                if requests.len() < 2 {
                    return Err(NetError(95));
                }
                return Ok(vec![]);
            }
            if batch && !matches!(kind(r) & 255, 0 | 2 | 3 | 5 | 6 | 8 | 9 | 11 | 12 | 14) {
                return Err(NetError(95));
            }
            let generated = staged.execute(packet_hooks, r, port, batch, &mut ids)?;
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
        staged.generation = staged.generation.wrapping_add(1).max(1);
        staged.refresh_hooks();
        **publication.as_mut().unwrap() = staged;
        // Keep this inside the real publication transaction. A concurrent fast
        // call observing the previous empty selector overlaps this commit;
        // later calls evaluate the actual current rules, never a cached allow.
        shared.active.store(
            publication.as_ref().unwrap().has_rules(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    Ok(out)
}
pub(crate) struct Context<'a> {
    pub packet: &'a mut [u8],
    pub hook: u32,
    pub packet_type: crate::ethernet::PacketType,
    pub input: u32,
    pub output: u32,
    pub tuple: crate::virtualnet::packet::Tuple,
    pub track: Option<crate::conntrack::Track>,
    connections: Option<&'a crate::conntrack::State>,
    pub graph: &'a crate::netdev::Topology,
    pub namespace: u64,
}
impl Context<'_> {
    fn family(&self) -> u8 {
        if self.packet[0] >> 4 == 4 {
            2
        } else {
            10
        }
    }
    fn address(&self, source: bool) -> std::net::IpAddr {
        if source {
            self.tuple.source.ip()
        } else {
            self.tuple.destination.ip()
        }
    }
    fn address_type(&self, source: bool, device: Option<u32>) -> u32 {
        self.graph
            .address_type(self.namespace, self.address(source), device)
    }
    fn nat_address(&self, low: std::net::IpAddr, high: std::net::IpAddr) -> std::net::IpAddr {
        use std::{
            hash::{DefaultHasher, Hash, Hasher},
            net::{IpAddr, Ipv4Addr, Ipv6Addr},
        };
        if low == high {
            return low;
        }
        // Choose on first binding only. Subsequent packets use the stored tuple.
        let mut hasher = DefaultHasher::new();
        self.tuple.source.hash(&mut hasher);
        let upper = hasher.finish();
        self.tuple.destination.hash(&mut hasher);
        let sample = (u128::from(upper) << 64) | u128::from(hasher.finish());
        match (low, high) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let start = u32::from(a);
                let span = u128::from(u32::from(b) - start) + 1;
                Ipv4Addr::from(start + (sample % span) as u32).into()
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let start = u128::from(a);
                let span = (u128::from(b) - start).checked_add(1);
                Ipv6Addr::from(start + span.map_or(sample, |n| sample % n)).into()
            }
            _ => unreachable!("NAT range endpoints share the rule family"),
        }
    }
    fn masquerade(&self) -> Option<std::net::IpAddr> {
        self.graph
            .interface_address(self.namespace, self.output, self.family() == 2)
    }
    fn fib_output(&self, source: bool, device: Option<u32>) -> u32 {
        if self.input == 1 && matches!(self.hook, 0 | 1) {
            return self.input;
        }
        let addr = self.address(source);
        if addr.is_ipv4() && self.graph.own(self.namespace, addr) {
            return 0;
        }
        self.graph
            .source(self.namespace, addr)
            .ok()
            .map(|(_, index, _)| index)
            .filter(|index| device.is_none_or(|d| d == *index))
            .unwrap_or(0)
    }
    fn transport(&self) -> Option<(usize, u8)> {
        let (offset, proto, fragment) = self.transport_header()?;
        (fragment == 0).then_some((offset, proto))
    }
    fn transport_header(&self) -> Option<(usize, u8, u16)> {
        let p = &*self.packet;
        if self.family() == 2 {
            Some((
                (p[0] & 15) as usize * 4,
                p[9],
                u16::from_be_bytes([p[6], p[7]]) & 0x1fff,
            ))
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
                        let fragment = u16::from_be_bytes([b[2], b[3]]) >> 3;
                        if fragment != 0 {
                            return Some((offset + 8, b[0], fragment));
                        }
                        8
                    }
                    51 => {
                        let b = p.get(offset..offset + 2)?;
                        (b[1] as usize + 2) * 4
                    }
                    _ => return Some((offset, proto, 0)),
                };
                let header = p.get(offset..offset + len)?;
                proto = header[0];
                offset += len;
            }
            None
        }
    }

    fn load_meta(&self, key: u32, register: &mut [u8]) -> Option<()> {
        fn store_string(register: &mut [u8], bytes: &[u8]) {
            let slot = &mut register[..16];
            slot.fill(0);
            let n = bytes.len().min(slot.len() - 1);
            slot[..n].copy_from_slice(&bytes[..n]);
        }
        match key {
            0 => register[..4].copy_from_slice(&(self.packet.len() as u32).to_ne_bytes()),
            1 => {
                let protocol = if self.family() == 2 {
                    0x0800u16
                } else {
                    0x86dd
                };
                register[..4].fill(0);
                register[..2].copy_from_slice(&protocol.to_be_bytes());
            }
            4 | 5 => {
                let index = if key == 4 { self.input } else { self.output };
                register[..4].copy_from_slice(&index.to_ne_bytes());
            }
            6 | 7 => {
                let index = if key == 6 { self.input } else { self.output };
                store_string(
                    register,
                    self.graph
                        .device_name(self.namespace, index)
                        .unwrap_or_default(),
                );
            }
            8 | 9 | 36 => {
                // The original IFTYPE reads the current skb device. Linux also
                // has a distinct ingress-only key on newer UAPIs.
                let index = match key {
                    9 => self.output,
                    8 if self.hook == 4 => self.output,
                    _ => self.input,
                };
                let kind = self.graph.device_kind(self.namespace, index)?;
                register[..4].fill(0);
                register[..2].copy_from_slice(&kind.hardware_type().to_ne_bytes());
            }
            15 | 16 | 19 => {
                let value = match key {
                    15 => self.family(),
                    16 => self.transport()?.1,
                    _ => self.packet_type as u8,
                };
                register[..4].copy_from_slice(&u32::from(value).to_ne_bytes());
            }
            26 | 27 => {
                let index = if key == 26 { self.input } else { self.output };
                let kind = self.graph.device_kind(self.namespace, index)?.link_kind()?;
                store_string(register, kind.to_bytes());
            }
            _ => return None,
        }
        Some(())
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
    pub packet_type: crate::ethernet::PacketType,
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
        let source = matches!(meta.hook, 1 | 4);
        let nat_priority = if source { 100 } else { -100 };
        let mut chains = vec![];
        for ((f, _), t) in &self.tables {
            if t.dormant || (*f != 1 && *f != family) {
                continue;
            }
            for (n, c) in &t.chains {
                if let Some((h, p)) = c.hook {
                    if h == meta.hook && (p < -200) == meta.raw {
                        // Linux registers one NAT hook per manipulation. User priorities
                        // order binding callbacks within that hook.
                        let stage = if c.chain_type == "nat" {
                            nat_priority
                        } else {
                            p
                        };
                        chains.push((stage, p, t, n, c));
                    }
                }
            }
        }
        chains.sort_by_key(|v| (v.0, v.1));
        let nat_stage = matches!(meta.hook, 0 | 1 | 3 | 4) && !meta.raw;
        let mut applied = false;
        for (priority, _, t, n, c) in chains {
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
            let mut ctx = Context {
                packet,
                hook: meta.hook,
                packet_type: meta.packet_type,
                input: meta.input,
                output,
                tuple: h.tuple,
                track: Some(*track),
                connections: Some(conn),
                graph: meta.graph,
                namespace: meta.namespace,
            };
            let mut effects = Effects::default();
            let v = t.verdict(n, &mut ctx, &mut 8192, &mut effects);
            if v == 0 {
                return false;
            }
            if v < 0 {
                if let Some(counts) = &c.counters {
                    counts.record(packet.len());
                }
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
    fn verdict(
        &self,
        ctx: &mut Context<'_>,
        effects: &mut Effects,
        sets: &sets::Sets,
    ) -> Option<(i32, Option<&str>)> {
        let mut regs = [0u8; 64];
        for expr in &self.expressions {
            match expr {
                Expr::Immediate { dest, value } => {
                    regs[*dest..*dest + value.len()].copy_from_slice(value)
                }
                Expr::Meta { dest, key } => {
                    ctx.load_meta(*key, &mut regs[*dest..])?;
                }
                Expr::Payload {
                    dest,
                    base,
                    offset,
                    len,
                } => {
                    let start = if *base == 1 { 0 } else { ctx.transport()?.0 };
                    let b = ctx.packet.get(start + *offset..start + *offset + *len)?;
                    regs[*dest + *len..*dest + len.next_multiple_of(4)].fill(0);
                    regs[*dest..*dest + *len].copy_from_slice(b);
                }
                Expr::PayloadSet { src, len, write } => {
                    write.apply(ctx, &regs[*src..*src + *len])?;
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
                Expr::Shift {
                    src,
                    dest,
                    len,
                    left,
                    bits,
                } => {
                    // Each register word is native endian. Left shifts consume the
                    // least significant word first, right shifts the most significant.
                    let count = len.div_ceil(4);
                    let mut carry = 0;
                    for step in 0..count {
                        let offset = 4 * if *left { count - 1 - step } else { step };
                        let from = src + offset;
                        let to = dest + offset;
                        let word = u32::from_le_bytes(regs[from..from + 4].try_into().unwrap());
                        let shifted = if *left { word << bits } else { word >> bits };
                        regs[to..to + 4].copy_from_slice(&(shifted | carry).to_le_bytes());
                        carry = if *left {
                            word.checked_shr(32 - bits)
                        } else {
                            word.checked_shl(32 - bits)
                        }
                        .unwrap_or(0);
                    }
                }
                Expr::Zone(zone) => effects.zone = Some(*zone),
                Expr::FixedNat {
                    kind,
                    addresses,
                    ports,
                } => {
                    if !kind.valid_hook(ctx.hook) {
                        return Some((0, None));
                    }
                    let address = match kind {
                        FixedNatKind::Masquerade => ctx.masquerade(),
                        FixedNatKind::Redirect if ctx.hook == 3 => Some(if ctx.family() == 2 {
                            std::net::Ipv4Addr::LOCALHOST.into()
                        } else {
                            std::net::Ipv6Addr::LOCALHOST.into()
                        }),
                        FixedNatKind::Redirect => {
                            ctx.graph
                                .redirect_address(ctx.namespace, ctx.input, ctx.address(false))
                        }
                        _ => addresses.map(|(low, high)| ctx.nat_address(low, high)),
                    };
                    if matches!(kind, FixedNatKind::Masquerade | FixedNatKind::Redirect)
                        && address.is_none()
                    {
                        return Some((0, None));
                    }
                    effects.nat = Some(NatAction {
                        source: matches!(kind, FixedNatKind::Source | FixedNatKind::Masquerade),
                        address,
                        ports: *ports,
                    });
                    return Some((1, None));
                }
                Expr::Lookup(l) => {
                    if !l.evaluate(sets, &mut regs) {
                        return None;
                    }
                }
                Expr::TransportMatch(m) => {
                    let (offset, protocol, fragment) = ctx.transport_header()?;
                    if protocol != m.protocol {
                        return None;
                    }
                    if fragment != 0 {
                        return if fragment == 1 && protocol == 6 {
                            Some((0, None))
                        } else {
                            None
                        };
                    }
                    match ctx
                        .packet
                        .get(offset..)
                        .and_then(|segment| m.matches(segment))
                    {
                        Some(true) => {}
                        Some(false) => return None,
                        None => return Some((0, None)),
                    }
                }
                Expr::ConntrackMatch { revision, info } => {
                    if !xt_match::conntrack_matches(ctx, *revision, info) {
                        return None;
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
                Expr::Fib {
                    dest,
                    flags,
                    result,
                } => {
                    let source = flags & FIB_SADDR != 0;
                    let device = if flags & FIB_IIF != 0 {
                        Some(ctx.input)
                    } else if flags & FIB_OIF != 0 {
                        Some(ctx.output)
                    } else {
                        None
                    };
                    if *result == FIB_RESULT_ADDRTYPE {
                        regs[*dest..*dest + 4]
                            .copy_from_slice(&ctx.address_type(source, device).to_le_bytes());
                    } else {
                        let index = ctx.fib_output(source, device);
                        if *result == FIB_RESULT_OIF {
                            let value = if flags & FIB_PRESENT != 0 {
                                u32::from(index != 0)
                            } else {
                                index
                            };
                            regs[*dest..*dest + 4].copy_from_slice(&value.to_le_bytes());
                        } else {
                            let output = &mut regs[*dest..*dest + 16];
                            output.fill(0);
                            if let Some(name) = ctx.graph.device_name(ctx.namespace, index) {
                                let n = name.len().min(15);
                                output[..n].copy_from_slice(&name[..n]);
                            }
                        }
                    }
                }
                Expr::AddrType {
                    source,
                    destination,
                    flags,
                } => {
                    let test =
                        |mask: u16, kind: u32, invert: bool| (mask & (1 << kind) != 0) ^ invert;
                    let device = if flags & 4 != 0 {
                        Some(ctx.input)
                    } else if flags & 8 != 0 {
                        Some(ctx.output)
                    } else {
                        None
                    };
                    if (*source != 0
                        && !test(*source, ctx.address_type(true, device), *flags & 1 != 0))
                        || (*destination != 0
                            && !test(
                                *destination,
                                ctx.address_type(false, device),
                                *flags & 2 != 0,
                            ))
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
                    let address = if let Some(low) = address.map(ip) {
                        let high = address_max.map(ip).unwrap_or(low);
                        if high < low {
                            return Some((0, None));
                        }
                        Some(ctx.nat_address(low, high))
                    } else {
                        None
                    };
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
                    let Some(address) = ctx.masquerade() else {
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
                    packets.add(1);
                    bytes.add(ctx.packet.len() as u64);
                }
                Expr::Comment | Expr::Verdict(-1, _) => {}
                Expr::Verdict(code, chain) => return Some((*code, chain.as_deref())),
            }
        }
        None
    }
}
impl Table {
    fn release_bindings(&mut self, removed: impl IntoIterator<Item = Rule>) {
        for rule in removed {
            for expr in rule.expressions {
                if let Expr::Verdict(_, Some(target)) = expr {
                    if self
                        .chains
                        .get(&target)
                        .is_some_and(|c| c.binding == Binding::Bound)
                    {
                        self.chains.remove(&target);
                    }
                }
            }
        }
    }

    fn batch_chain(&self, ids: &BatchIds, id: u32) -> Result<String> {
        ids.chains
            .iter()
            .filter(|(table, candidate, _)| *table == self.handle && *candidate == id)
            .find_map(|(_, _, handle)| self.chain_name(*handle).ok())
            .ok_or(NetError(2))
    }

    fn chain_name(&self, handle: u64) -> Result<String> {
        self.chains
            .iter()
            .find(|(_, c)| c.handle == handle)
            .map(|(n, _)| n.clone())
            .ok_or(NetError(2))
    }
    fn rename_chain(&mut self, old: &str, new: &str) -> Result<()> {
        if self.chains.contains_key(new) {
            return Err(NetError(17));
        }
        let chain = self.chains.remove(old).ok_or(NetError(2))?;
        self.chains.insert(new.to_owned(), chain);
        for chain in self.chains.values_mut() {
            for rule in &mut chain.rules {
                for expr in &mut rule.expressions {
                    if let Expr::Verdict(_, Some(target)) = expr {
                        if target == old {
                            new.clone_into(target);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn verdict(
        &self,
        chain: &str,
        ctx: &mut Context<'_>,
        budget: &mut usize,
        effects: &mut Effects,
    ) -> i32 {
        let c = &self.chains[chain];
        for r in &c.rules {
            if *budget == 0 {
                return 0;
            }
            *budget -= 1;
            match r.verdict(ctx, effects, &self.sets) {
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
    fn refresh_hooks(&mut self) {
        self.active_hooks = self
            .tables
            .values()
            .filter(|t| !t.dormant)
            .flat_map(|t| t.chains.values())
            .filter_map(|c| c.hook)
            .fold(0, |mask, (h, _)| mask | (1 << h));
    }
    pub fn has_rules(&self) -> bool {
        self.active_hooks != 0
    }
    pub fn active(&self, hook: u32) -> bool {
        self.active_hooks & (1 << hook) != 0
    }
    #[cfg(test)]
    pub fn allows(&self, ctx: &mut Context<'_>) -> bool {
        if self.tables.is_empty() {
            return true;
        }
        let mut hooks = vec![];
        for ((family, _), t) in &self.tables {
            if t.dormant || (*family != 1 && *family != ctx.family()) {
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
                if let Some(counts) = &c.counters {
                    counts.record(ctx.packet.len());
                }
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
    expressions_in(bytes, 2, None, &BatchIds::default())
}
#[cfg(test)]
#[path = "nftables_tests.rs"]
pub(crate) mod tests;
