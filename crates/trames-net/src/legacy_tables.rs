// SPDX-License-Identifier: GPL-3.0-or-later
//! Legacy xtables ARM64 table images and their validated packet rules.
use super::*;
use std::sync::Arc;

pub const INFO_SIZE: usize = 84;
pub const ENTRIES_HEADER: usize = 40;
pub const REPLACE_HEADER: usize = 96;
pub const MAX_IMAGE: usize = 4 * 1024 * 1024;
const XT_HEADER: usize = 32;
const STANDARD: usize = 40;
const ERROR: usize = 64;
const HOOKS: usize = 5;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Name {
    Raw,
    Mangle,
    Nat,
    Filter,
}
impl Name {
    fn resolve(bytes: &[u8]) -> Result<Self> {
        match terminated(bytes) {
            b"raw" => Ok(Self::Raw),
            b"mangle" => Ok(Self::Mangle),
            b"nat" => Ok(Self::Nat),
            b"filter" => Ok(Self::Filter),
            _ => Err(NetError(2)),
        }
    }
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Raw => b"raw",
            Self::Mangle => b"mangle",
            Self::Nat => b"nat",
            Self::Filter => b"filter",
        }
    }
    fn hooks(self) -> u8 {
        match self {
            Self::Raw => 0b01001,
            Self::Mangle => 0b11111,
            Self::Nat => 0b11011,
            Self::Filter => 0b01110,
        }
    }
    pub(super) fn priority(self, nat_priority: i32) -> i32 {
        match self {
            Self::Raw => -300,
            Self::Mangle => -150,
            Self::Nat => nat_priority,
            Self::Filter => 0,
        }
    }
}
fn terminated(bytes: &[u8]) -> &[u8] {
    bytes.split(|byte| *byte == 0).next().unwrap_or_default()
}
fn short(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize
}
fn word(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}
fn long(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put_word(bytes: &mut [u8], at: usize, value: usize) {
    bytes[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
fn put_short(bytes: &mut [u8], at: usize, value: usize) {
    bytes[at..at + 2].copy_from_slice(&(value as u16).to_le_bytes());
}

#[derive(Clone, Copy)]
struct Layout {
    address: usize,
    packet: usize,
    target: usize,
    counters: usize,
}
impl Layout {
    fn for_family(family: u8) -> Self {
        if family == 2 {
            Self {
                address: 4,
                packet: 84,
                target: 88,
                counters: 96,
            }
        } else {
            Self {
                address: 16,
                packet: 136,
                target: 140,
                counters: 152,
            }
        }
    }
    fn entry(self) -> usize {
        self.counters + 16
    }
    fn matches(self, bytes: &[u8], ctx: &Context<'_>, protocol: u8, first_fragment: bool) -> bool {
        let a = self.address;
        let p = a * 4 + 64;
        let flags = if a == 4 { bytes[p + 2] } else { bytes[p + 3] };
        let inverse = bytes[p + if a == 4 { 3 } else { 4 }];
        let test_addr = |idx: usize, ip: std::net::IpAddr| {
            let source = if let std::net::IpAddr::V4(ip) = ip {
                let mut address = [0; 16];
                address[..4].copy_from_slice(&ip.octets());
                address
            } else if let std::net::IpAddr::V6(ip) = ip {
                ip.octets()
            } else {
                unreachable!()
            };
            masked(
                &source[..a],
                &bytes[idx * a..(idx + 1) * a],
                &bytes[(idx + 2) * a..(idx + 3) * a],
            )
        };
        let test_device = |idx: usize, device: u32| {
            let start = a * 4 + idx * 16;
            let mut name = [0; 16];
            if let Some(value) = ctx.graph.device_name(ctx.namespace, device) {
                let len = value.len().min(15);
                name[..len].copy_from_slice(&value[..len]);
            }
            masked(
                &name,
                &bytes[start..start + 16],
                &bytes[start + 32..start + 48],
            )
        };
        let wanted_protocol = short(bytes, p);
        let protocol_set = wanted_protocol != 0 && (a == 4 || flags & 1 != 0);
        test_addr(0, ctx.tuple.source.ip()) != (inverse & 8 != 0)
            && test_addr(1, ctx.tuple.destination.ip()) != (inverse & 16 != 0)
            && test_device(0, ctx.input) != (inverse & 1 != 0)
            && test_device(1, ctx.output) != (inverse & 2 != 0)
            && (!protocol_set || (wanted_protocol == usize::from(protocol)) != (inverse & 64 != 0))
            && (a != 4 || flags & 1 == 0 || first_fragment == (inverse & 32 != 0))
    }
}
fn masked(actual: &[u8], wanted: &[u8], mask: &[u8]) -> bool {
    actual
        .iter()
        .zip(wanted)
        .zip(mask)
        .all(|((&a, &b), &m)| (a ^ b) & m == 0)
}

#[derive(Clone, Default)]
pub(super) struct Tables(BTreeMap<(u8, Name), Arc<LegacyTable>>);
impl Tables {
    pub(super) fn active(&self) -> u8 {
        self.0
            .keys()
            .fold(0, |hooks, (_, name)| hooks | name.hooks())
    }
    pub(super) fn at_hook(
        &self,
        family: u8,
        hook: u32,
    ) -> impl Iterator<Item = (Name, &LegacyTable)> {
        self.0.iter().filter_map(move |(&(f, name), table)| {
            (f == family && name.hooks() & (1 << hook) != 0).then_some((name, table.as_ref()))
        })
    }
}

struct Entry {
    offset: usize,
    counters: ChainCounters,
    // Chain labels and the end of the image occupy wire entries with counter
    // slots. Only packet rules have a body that the evaluator can execute.
    packet_rule: Option<PacketRule>,
}
struct PacketRule {
    action: Action,
    unconditional: bool,
    rule: Rule,
}
#[derive(Clone, Copy)]
enum Action {
    Accept,
    Drop,
    Return,
    Jump { offset: usize, tail: bool },
    Continue,
}

pub(super) struct LegacyTable {
    start: [usize; HOOKS],
    policy: [usize; HOOKS],
    layout: Layout,
    wire: Vec<u8>,
    entries: Vec<Entry>,
    empty_sets: sets::Sets,
}
impl LegacyTable {
    fn initial(family: u8, name: Name) -> Self {
        let layout = Layout::for_family(family);
        let mut start = [0; HOOKS];
        let mut wire = Vec::new();
        for (hook, offset) in start.iter_mut().enumerate() {
            if name.hooks() & (1 << hook) == 0 {
                continue;
            }
            *offset = wire.len();
            let entry = default_entry(&mut wire, layout, STANDARD);
            entry[XT_HEADER..XT_HEADER + 4].copy_from_slice(&(-2i32).to_le_bytes());
        }
        let target = default_entry(&mut wire, layout, ERROR);
        target[2..7].copy_from_slice(b"ERROR");
        target[XT_HEADER..XT_HEADER + 5].copy_from_slice(b"ERROR");
        Self::parse(
            family,
            name,
            start,
            start,
            (name.hooks().count_ones() + 1) as usize,
            wire,
        )
        .expect("canonical empty xtables image")
    }

    fn parse(
        family: u8,
        name: Name,
        start: [usize; HOOKS],
        policy: [usize; HOOKS],
        count: usize,
        mut wire: Vec<u8>,
    ) -> Result<Self> {
        let layout = Layout::for_family(family);
        let base = layout.entry();
        if count == 0 || count > wire.len() / (base + XT_HEADER) || wire.len() > MAX_IMAGE {
            return Err(NetError(22));
        }
        let mut out = Vec::with_capacity(count);
        let mut offset = 0;
        while offset < wire.len() {
            let header = wire.get(offset..offset + base).ok_or(NetError(22))?;
            let next = short(header, layout.target + 2);
            let target_at = short(header, layout.target);
            let flags = if family == 2 { header[82] } else { header[131] };
            let inverse = if family == 2 { header[83] } else { header[132] };
            if target_at < base
                || target_at + XT_HEADER > next
                || next % 8 != 0
                || flags & !(if family == 2 { 3 } else { 5 }) != 0
                || inverse & !(if family == 2 { 0x7b } else { 0x5b }) != 0
            {
                return Err(NetError(22));
            }
            let unconditional =
                target_at == base && header[..layout.packet].iter().all(|&b| b == 0);
            let mut expressions = Vec::new();
            let entry = wire.get_mut(offset..offset + next).ok_or(NetError(22))?;
            let mut matches = &entry[base..target_at];
            while !matches.is_empty() {
                let (extension, number, parameters, tail) = extension(matches)?;
                let parsed = xt_match_expression(family, extension, number, parameters)?;
                if let Expr::TransportMatch(m) = &parsed {
                    let proto = short(entry, layout.address * 4 + 64);
                    if proto != usize::from(m.protocol)
                        || inverse & 64 != 0
                        || family == 10 && flags & 1 == 0
                    {
                        return Err(NetError(22));
                    }
                }
                expressions.push(parsed);
                matches = tail;
            }
            let (target, revision, parameters, rest) = extension(&entry[target_at..])?;
            if !rest.is_empty() {
                return Err(NetError(22));
            }
            let action = match target {
                "" if parameters.len() == STANDARD - XT_HEADER && revision == 0 => {
                    Some(match word(parameters, 0) as i32 {
                        -1 => Action::Drop,
                        -2 => Action::Accept,
                        -5 => Action::Return,
                        jump if jump >= 0 => Action::Jump {
                            offset: jump as usize,
                            tail: flags & (if family == 2 { 2 } else { 4 }) != 0,
                        },
                        _ => return Err(NetError(95)),
                    })
                }
                "ERROR"
                    if parameters.len() == ERROR - XT_HEADER
                        && revision == 0
                        && expressions.is_empty() =>
                {
                    None
                }
                "" | "ERROR" => return Err(NetError(22)),
                name_str => {
                    let target = xt_target_expression(family, name_str, revision, parameters)?;
                    if matches!(target, Expr::FixedNat { .. }) && name != Name::Nat
                        || matches!(target, Expr::Zone(_)) && name != Name::Raw
                    {
                        return Err(NetError(22));
                    }
                    expressions.push(target);
                    Some(Action::Continue)
                }
            };
            let packet_rule = action.map(|action| {
                expressions.push(Expr::Verdict(1, None));
                PacketRule {
                    action,
                    unconditional,
                    rule: Rule {
                        handle: 0,
                        userdata: Vec::new(),
                        wire: Vec::new(),
                        compatibility: None,
                        expressions,
                    },
                }
            });
            entry[layout.counters..base].fill(0);
            out.push(Entry {
                offset,
                packet_rule,
                counters: ChainCounters {
                    bytes: Counter::default(),
                    packets: Counter::default(),
                },
            });
            offset += next;
        }
        if out.len() != count || !out.last().is_some_and(|entry| entry.packet_rule.is_none()) {
            return Err(NetError(22));
        }
        let mut start_index = [0; HOOKS];
        let mut policy_index = [0; HOOKS];
        for hook in 0..HOOKS {
            if name.hooks() & (1 << hook) == 0 {
                continue;
            }
            let (start, _) = Self::resolve_rule(&out, start[hook])?;
            let (idx, fallback) = Self::resolve_rule(&out, policy[hook])?;
            if !matches!(fallback.action, Action::Accept | Action::Drop) || !fallback.unconditional
            {
                return Err(NetError(22));
            }
            start_index[hook] = start;
            policy_index[hook] = idx;
        }
        for idx in 0..out.len() {
            if let Some(Action::Jump { offset, tail }) =
                out[idx].packet_rule.as_ref().map(|rule| rule.action)
            {
                let (next, _) = Self::resolve_rule(&out, offset)?;
                out[idx].packet_rule.as_mut().unwrap().action = Action::Jump { offset: next, tail };
            }
        }
        // Iterative graph walk. Each edge stays inside the checked entry index,
        // and a call cannot form a cycle through another chain or a continuation.
        Self::check_links(&out, &start_index, name.hooks())?;
        Ok(Self {
            start: start_index,
            policy: policy_index,
            layout,
            wire,
            entries: out,
            empty_sets: Default::default(),
        })
    }

    fn resolve_rule(entries: &[Entry], offset: usize) -> Result<(usize, &PacketRule)> {
        let index = entries
            .binary_search_by_key(&offset, |entry| entry.offset)
            .map_err(|_| NetError(22))?;
        let rule = entries[index].packet_rule.as_ref().ok_or(NetError(22))?;
        Ok((index, rule))
    }

    fn check_links(entries: &[Entry], start: &[usize; HOOKS], hooks: u8) -> Result<()> {
        let mut states = vec![0; entries.len()];
        let mut pending = Vec::new();
        for (hook, &entry) in start.iter().enumerate() {
            if hooks & (1 << hook) == 0 {
                continue;
            }
            states.fill(0);
            pending.push((entry, false));
            while let Some((idx, returning)) = pending.pop() {
                let state = states.get_mut(idx).ok_or(NetError(22))?;
                if returning {
                    *state = 2;
                    continue;
                }
                match *state {
                    2 => continue,
                    1 => return Err(NetError(40)),
                    _ => {}
                }
                let entry = entries[idx].packet_rule.as_ref().ok_or(NetError(22))?;
                *state = 1;
                pending.push((idx, true));
                for expression in &entry.rule.expressions {
                    match expression {
                        Expr::FixedNat { kind, .. } if !kind.valid_hook(hook as u32) => {
                            return Err(NetError(22));
                        }
                        Expr::AddrType { flags, .. }
                            if (flags & 4 != 0 && hook >= 3) || (flags & 8 != 0 && hook <= 1) =>
                        {
                            return Err(NetError(22));
                        }
                        _ => {}
                    }
                }
                if let Action::Jump { offset, .. } = entry.action {
                    pending.push((offset, false));
                }
                let can_continue = !entry.unconditional
                    || matches!(
                        entry.action,
                        Action::Continue | Action::Jump { tail: false, .. }
                    );
                if can_continue {
                    pending.push((idx + 1, false));
                }
            }
        }
        Ok(())
    }

    pub(super) fn evaluate(&self, ctx: &mut Context<'_>, effects: &mut Effects) -> bool {
        let Some(header) = crate::virtualnet::packet::header(ctx.packet) else {
            return false;
        };
        let hook = ctx.hook as usize;
        let mut index = self.start[hook];
        let mut stack = Vec::new();
        for _ in 0..self.entries.len().saturating_mul(8) {
            let Some(entry) = self.entries.get(index) else {
                return false;
            };
            let Some(rule) = &entry.packet_rule else {
                return false;
            };
            let bytes = &self.wire[entry.offset..entry.offset + self.layout.entry()];
            if !rule.unconditional
                && !self
                    .layout
                    .matches(bytes, ctx, header.protocol, header.first)
            {
                index += 1;
                continue;
            }
            match rule.rule.verdict(ctx, effects, &self.empty_sets) {
                None => {
                    index += 1;
                    continue;
                }
                Some((0, _)) => return false,
                Some(_) => {}
            }
            entry.counters.record(ctx.packet.len());
            match rule.action {
                Action::Accept => return true,
                Action::Drop => return false,
                Action::Continue if effects.nat.is_some() => return true,
                Action::Continue => {
                    index += 1;
                }
                Action::Return => {
                    index = stack.pop().unwrap_or(self.policy[hook]);
                }
                Action::Jump { offset, tail } => {
                    if !tail && offset != index + 1 {
                        if stack.len() == 128 {
                            return false;
                        }
                        stack.push(index + 1);
                    }
                    index = offset;
                }
            }
        }
        false
    }

    fn info(&self, name: Name) -> Vec<u8> {
        let mut info = vec![0; INFO_SIZE];
        info[..name.bytes().len()].copy_from_slice(name.bytes());
        put_word(&mut info, 32, name.hooks() as usize);
        for hook in 0..HOOKS {
            if name.hooks() & (1 << hook) == 0 {
                continue;
            }
            put_word(
                &mut info,
                36 + hook * 4,
                self.entries[self.start[hook]].offset,
            );
            put_word(
                &mut info,
                56 + hook * 4,
                self.entries[self.policy[hook]].offset,
            );
        }
        put_word(&mut info, 76, self.entries.len());
        put_word(&mut info, 80, self.wire.len());
        info
    }
    fn dump(&self) -> Vec<u8> {
        let mut wire = self.wire.clone();
        for entry in &self.entries {
            let at = entry.offset + self.layout.counters;
            wire[at..at + 8].copy_from_slice(&entry.counters.packets.get().to_le_bytes());
            wire[at + 8..at + 16].copy_from_slice(&entry.counters.bytes.get().to_le_bytes());
        }
        wire
    }
    fn counters(&self) -> Vec<u8> {
        self.entries
            .iter()
            .flat_map(|entry| {
                let packets = entry.counters.packets.get().to_le_bytes();
                let bytes = entry.counters.bytes.get().to_le_bytes();
                packets.into_iter().chain(bytes)
            })
            .collect()
    }
}

fn default_entry(wire: &mut Vec<u8>, layout: Layout, target_size: usize) -> &mut [u8] {
    let start = wire.len();
    let base = layout.entry();
    wire.resize(start + base + target_size, 0);
    let entry = &mut wire[start..];
    put_short(entry, layout.target, base);
    put_short(entry, layout.target + 2, base + target_size);
    let target = &mut entry[base..];
    put_short(target, 0, target_size);
    target
}
fn extension(bytes: &[u8]) -> Result<(&str, u32, &[u8], &[u8])> {
    if bytes.len() < XT_HEADER {
        return Err(NetError(22));
    }
    let size = short(bytes, 0);
    if size < XT_HEADER || size % 8 != 0 || size > bytes.len() {
        return Err(NetError(22));
    }
    let name = std::str::from_utf8(terminated(&bytes[2..31])).map_err(|_| NetError(22))?;
    Ok((
        name,
        u32::from(bytes[31]),
        &bytes[XT_HEADER..size],
        &bytes[size..],
    ))
}

impl Firewall {
    pub(crate) fn legacy_names(&self, family: u8) -> Vec<u8> {
        let rules = self.rules.read().unwrap();
        let mut names = Vec::new();
        for &(table_family, name) in rules.legacy.0.keys() {
            if table_family == family {
                names.extend_from_slice(name.bytes());
                names.push(b'\n');
            }
        }
        names
    }

    pub(crate) fn legacy_get(
        &self,
        family: u8,
        option: u32,
        header: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        let info = match option {
            64 if header.len() == INFO_SIZE && len == INFO_SIZE => true,
            65 if header.len() == ENTRIES_HEADER
                && len >= ENTRIES_HEADER
                && len - ENTRIES_HEADER == word(header, 32) =>
            {
                false
            }
            _ => return Err(NetError(22)),
        };
        let name = Name::resolve(&header[..32])?;
        let mut rules = self.rules.write().unwrap();
        let current = rules.legacy.0.get(&(family, name));
        let default = current
            .is_none()
            .then(|| Arc::new(LegacyTable::initial(family, name)));
        let table = current.or(default.as_ref()).unwrap();
        let bytes = if info {
            table.info(name)
        } else {
            if table.wire.len() != len - ENTRIES_HEADER {
                return Err(NetError(11));
            }
            let mut bytes = header[..ENTRIES_HEADER].to_vec();
            bytes.extend(table.dump());
            bytes
        };
        if let Some(default) = default {
            rules.legacy.0.insert((family, name), default);
            rules.refresh_hooks();
            self.active.store(rules.has_rules(), Relaxed);
        }
        Ok(bytes)
    }

    pub(crate) fn legacy_replace(
        &self,
        family: u8,
        bytes: &[u8],
        counters: impl FnOnce(u64, &[u8]) -> Result<()>,
    ) -> Result<()> {
        if bytes.len() < REPLACE_HEADER || bytes.len() - REPLACE_HEADER != word(bytes, 40) {
            return Err(NetError(22));
        }
        let name = Name::resolve(&bytes[..32])?;
        if word(bytes, 32) != name.hooks() as usize {
            return Err(NetError(22));
        }
        let start = std::array::from_fn(|i| word(bytes, 44 + i * 4));
        let policy = std::array::from_fn(|i| word(bytes, 64 + i * 4));
        let replacement = LegacyTable::parse(
            family,
            name,
            start,
            policy,
            word(bytes, 36),
            bytes[REPLACE_HEADER..].to_vec(),
        )?;
        let mut rules = self.rules.write().unwrap();
        let default;
        let old = match rules.legacy.0.get(&(family, name)) {
            Some(table) => table.as_ref(),
            None => {
                default = LegacyTable::initial(family, name);
                &default
            }
        };
        if old.entries.len() != word(bytes, 84) {
            return Err(NetError(11));
        }
        counters(long(bytes, 88), &old.counters())?;
        rules.legacy.0.insert((family, name), Arc::new(replacement));
        rules.refresh_hooks();
        self.active.store(rules.has_rules(), Relaxed);
        Ok(())
    }

    pub(crate) fn legacy_add_counters(&self, family: u8, bytes: &[u8]) -> Result<()> {
        if bytes.len() < ENTRIES_HEADER
            || (bytes.len() - ENTRIES_HEADER) % 16 != 0
            || (bytes.len() - ENTRIES_HEADER) / 16 != word(bytes, 32)
        {
            return Err(NetError(22));
        }
        let name = Name::resolve(&bytes[..32])?;
        let rules = self.rules.read().unwrap();
        let table = rules.legacy.0.get(&(family, name)).ok_or(NetError(2))?;
        if table.entries.len() != word(bytes, 32) {
            return Err(NetError(22));
        }
        for (entry, counters) in table
            .entries
            .iter()
            .zip(bytes[ENTRIES_HEADER..].chunks_exact(16))
        {
            entry.counters.packets.add(long(counters, 0));
            entry.counters.bytes.add(long(counters, 8));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_packet_rules_can_be_resolved_at_wire_offsets() {
        for family in [2, 10] {
            let table = LegacyTable::initial(family, Name::Filter);
            assert!(LegacyTable::resolve_rule(&table.entries, 0).is_ok());
            let end_marker = table.entries.last().unwrap().offset;
            assert!(table.entries.last().unwrap().packet_rule.is_none());
            assert!(matches!(
                LegacyTable::resolve_rule(&table.entries, end_marker),
                Err(NetError(22))
            ));
            assert!(matches!(
                LegacyTable::resolve_rule(&table.entries, 8),
                Err(NetError(22))
            ));
        }
    }

    #[test]
    fn replacement_is_atomic_for_invalid_entry_offsets_and_counter_write_faults() {
        for family in [2, 10] {
            check_replacement_is_atomic(family);
        }
    }

    fn check_replacement_is_atomic(family: u8) {
        let name = Name::Filter;
        let firewall = Firewall::default();
        let initial = LegacyTable::initial(family, name);
        let mut query = [0; ENTRIES_HEADER];
        query[..name.bytes().len()].copy_from_slice(name.bytes());
        put_word(&mut query, 32, initial.wire.len());
        let len = query.len() + initial.wire.len();
        let before = firewall.legacy_get(family, 65, &query, len).unwrap();

        let mut counters = query.to_vec();
        put_word(&mut counters, 32, initial.entries.len());
        counters.resize(ENTRIES_HEADER + initial.entries.len() * 16, 0);
        counters[ENTRIES_HEADER..ENTRIES_HEADER + 8].copy_from_slice(&5u64.to_le_bytes());
        firewall.legacy_add_counters(family, &counters).unwrap();

        let mut replace = vec![0; REPLACE_HEADER];
        replace[..name.bytes().len()].copy_from_slice(name.bytes());
        put_word(&mut replace, 32, name.hooks() as usize);
        put_word(&mut replace, 36, initial.entries.len());
        put_word(&mut replace, 40, initial.wire.len());
        for hook in 1..=3 {
            let offset = initial.entries[initial.start[hook]].offset;
            put_word(&mut replace, 44 + hook * 4, offset);
            put_word(&mut replace, 64 + hook * 4, offset);
        }
        put_word(&mut replace, 84, initial.entries.len());
        replace.extend_from_slice(&initial.wire);
        let input_verdict = REPLACE_HEADER + initial.layout.entry() + XT_HEADER;
        replace[input_verdict..input_verdict + 4].copy_from_slice(&(-1i32).to_le_bytes());

        let before_replacement = firewall.legacy_get(family, 65, &query, len).unwrap();
        let mut partial_entry = replace.clone();
        put_word(&mut partial_entry, 44 + 4, 8);
        assert!(matches!(
            firewall.legacy_replace(family, &partial_entry, |_, _| {
                panic!("validation must precede counter copyout")
            }),
            Err(NetError(22))
        ));
        assert_eq!(
            firewall.legacy_get(family, 65, &query, len).unwrap(),
            before_replacement
        );

        assert!(matches!(
            firewall.legacy_replace(family, &replace, |_, _| Err(NetError(14))),
            Err(NetError(14))
        ));
        let kept = firewall.legacy_get(family, 65, &query, len).unwrap();
        let counter = ENTRIES_HEADER + initial.layout.counters;
        assert_eq!(long(&kept, counter), 5);
        let verdict = ENTRIES_HEADER + initial.layout.entry() + XT_HEADER;
        assert_eq!(kept[verdict..verdict + 4], before[verdict..verdict + 4]);

        firewall
            .legacy_replace(family, &replace, |_, old| {
                assert_eq!(long(old, 0), 5);
                Ok(())
            })
            .unwrap();
        let installed = firewall.legacy_get(family, 65, &query, len).unwrap();
        assert_eq!(long(&installed, counter), 0);
        assert_eq!(&installed[verdict..verdict + 4], &(-1i32).to_le_bytes());
    }
}
