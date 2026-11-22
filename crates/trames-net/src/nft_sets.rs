// SPDX-License-Identifier: GPL-3.0-or-later
//! Named exact-key sets and data maps. The containing rules transaction owns
//! each version, so a packet sees one set for the entire chain traversal.
use super::*;
use std::sync::Arc;

pub(super) type Sets = BTreeMap<String, Arc<Set>>;
pub(super) type BatchIds = BTreeMap<(u64, u32), (String, u64)>;
const MAP: u32 = 8;
const CONSTANT: u32 = 2;

#[derive(Clone, PartialEq)]
struct Spec {
    flags: u32,
    key_type: u32,
    key_len: usize,
    data_type: Option<u32>,
    data_len: usize,
    policy: u32,
    size: u32,
    userdata: Vec<u8>,
}
#[derive(Clone, PartialEq)]
struct Element {
    data: Vec<u8>,
    userdata: Vec<u8>,
}
#[derive(Clone)]
pub(super) struct Set {
    handle: u64,
    spec: Spec,
    // Fixed-width keys are always nonempty. The empty key denotes catch-all.
    elements: BTreeMap<Vec<u8>, Element>,
    element_bytes: usize,
}
fn optional(a: &Attrs<'_>, field: u16) -> Result<Option<u32>> {
    get(a, field).map(u32v).transpose()
}
fn userdata(a: &Attrs<'_>, key: u16) -> Result<Vec<u8>> {
    let v = get(a, key).unwrap_or_default();
    if v.len() > 256 {
        return Err(NetError(22));
    }
    Ok(v.to_vec())
}
impl Spec {
    fn parse(a: &Attrs<'_>) -> Result<Self> {
        let flags = optional(a, 3)?.unwrap_or(0);
        if flags & !(MAP | CONSTANT) != 0 {
            return Err(NetError(95));
        }
        let key_len = num(a, 5)? as usize;
        let data_type = optional(a, 6)?;
        let data_len = optional(a, 7)?;
        if !(1..=64).contains(&key_len)
            || (flags & MAP != 0) != data_type.is_some()
            || data_type.is_some() != data_len.is_some()
            || data_len.is_some_and(|n| !(1..=64).contains(&n))
        {
            return Err(NetError(22));
        }
        let key_type = optional(a, 4)?.unwrap_or(0);
        if key_type >= 0xffffff00 || data_type.is_some_and(|v| v >= 0xffffff00) {
            return Err(NetError(95));
        }
        let policy = optional(a, 8)?.unwrap_or(0);
        if policy > 1 {
            return Err(NetError(22));
        }
        let size = get(a, 9)
            .map(|b| optional(&fields(b, &[1])?, 1))
            .transpose()?
            .flatten()
            .unwrap_or(0);
        Ok(Self {
            flags,
            key_len,
            key_type,
            data_type,
            data_len: data_len.unwrap_or(0) as usize,
            policy,
            size,
            userdata: userdata(a, 13)?,
        })
    }
}
impl Set {
    pub(super) fn bytes(&self) -> usize {
        128 + self.spec.userdata.len() + self.element_bytes
    }
    fn description(&self, family: u8, table: &str, name: &str) -> Vec<u8> {
        let s = &self.spec;
        let mut d = data(family);
        string(&mut d, 1, table);
        string(&mut d, 2, name);
        number(&mut d, 3, s.flags);
        number(&mut d, 4, s.key_type);
        number(&mut d, 5, s.key_len as u32);
        if let Some(ty) = s.data_type {
            number(&mut d, 6, ty);
            number(&mut d, 7, s.data_len as u32);
        }
        number(&mut d, 8, s.policy);
        if s.size != 0 {
            let mut desc = vec![];
            number(&mut desc, 1, s.size);
            attr(&mut d, 9, &desc);
        }
        if !s.userdata.is_empty() {
            attr(&mut d, 13, &s.userdata);
        }
        integer(&mut d, 16, self.handle);
        d
    }
    fn value<'a>(&self, b: &'a [u8], len: usize) -> Result<&'a [u8]> {
        let v = need(&fields(b, &[1])?, 1)?;
        if v.len() != len {
            return Err(NetError(22));
        }
        Ok(v)
    }
    fn key<'a>(&self, a: &Attrs<'a>) -> Result<&'a [u8]> {
        match (optional(a, 3)?.unwrap_or(0), get(a, 1)) {
            (0, Some(b)) => self.value(b, self.spec.key_len),
            (2, None) => Ok(&[]),
            (0 | 2, _) => Err(NetError(22)),
            _ => Err(NetError(95)),
        }
    }
    fn edit(&mut self, list: Option<&[u8]>, add: bool, exclusive: bool) -> Result<()> {
        let Some(list) = list else {
            if add {
                return Err(NetError(22));
            }
            self.elements.clear();
            self.element_bytes = 0;
            return Ok(());
        };
        for (kind, b) in attrs(list)? {
            if kind != 1 {
                return Err(NetError(22));
            }
            let a = fields(b, if add { &[1, 2, 3, 6] } else { &[1, 3] })?;
            let key = self.key(&a)?;
            if !add {
                let old = self.elements.remove(key).ok_or(NetError(2))?;
                self.element_bytes -= 64 + key.len() + old.data.len() + old.userdata.len();
                continue;
            }
            let data = match (self.spec.data_type, get(&a, 2)) {
                (Some(_), Some(b)) => self.value(b, self.spec.data_len)?.to_vec(),
                (None, None) => vec![],
                _ => return Err(NetError(22)),
            };
            let elem = Element {
                data,
                userdata: userdata(&a, 6)?,
            };
            if let Some(old) = self.elements.get(key) {
                if exclusive || old.data != elem.data {
                    return Err(NetError(17));
                }
                continue;
            }
            if self.spec.size != 0 && self.elements.len() >= self.spec.size as usize {
                return Err(NetError(23));
            }
            self.element_bytes += 64 + key.len() + elem.data.len() + elem.userdata.len();
            self.elements.insert(key.to_vec(), elem);
        }
        Ok(())
    }
}
fn element_wire(key: &[u8], e: &Element) -> Vec<u8> {
    let mut a = vec![];
    if key.is_empty() {
        number(&mut a, 3, 2);
    } else {
        let mut v = vec![];
        attr(&mut v, 1, key);
        attr(&mut a, 1, &v);
    }
    if !e.data.is_empty() {
        let mut v = vec![];
        attr(&mut v, 1, &e.data);
        attr(&mut a, 2, &v);
    }
    if !e.userdata.is_empty() {
        attr(&mut a, 6, &e.userdata);
    }
    let mut item = vec![];
    attr(&mut item, 1, &a);
    item
}

impl Table {
    fn set_name<'a>(&'a self, n: &str, id: Option<u32>, ids: &BatchIds) -> Result<&'a str> {
        if let Some((name, _)) = self.sets.get_key_value(n) {
            return Ok(name);
        }
        let (name, handle) = id
            .and_then(|i| ids.get(&(self.handle, i)))
            .ok_or(NetError(2))?;
        self.sets
            .get_key_value(name)
            .filter(|(_, s)| s.handle == *handle)
            .map(|(n, _)| n.as_str())
            .ok_or(NetError(2))
    }
    fn bound(&self, name: &str) -> bool {
        self.chains
            .values()
            .flat_map(|c| &c.rules)
            .flat_map(|r| &r.expressions)
            .any(|e| matches!(e,Expr::Lookup(l) if l.set==name))
    }

    pub(super) fn mutate_set(
        &mut self,
        op: u16,
        flags: u16,
        a: &Attrs<'_>,
        ids: &mut BatchIds,
    ) -> Result<()> {
        match op {
            9 => {
                let name = name(a, 2)?;
                let id = num(a, 10)?;
                let spec = Spec::parse(a)?;
                if let Some(existing) = self.sets.get(&name) {
                    if flags & 0x200 != 0 || existing.spec != spec {
                        return Err(NetError(17));
                    }
                    return Ok(());
                }
                if flags & 0x400 == 0 {
                    return Err(NetError(2));
                }
                let handle = next_handle(&mut self.next)?;
                if ids
                    .insert((self.handle, id), (name.clone(), handle))
                    .is_some()
                {
                    return Err(NetError(17));
                }
                self.sets.insert(
                    name,
                    Arc::new(Set {
                        handle,
                        spec,
                        elements: BTreeMap::new(),
                        element_bytes: 0,
                    }),
                );
            }
            11 => {
                let name = if let Some(raw) = get(a, 16) {
                    let h = u64v(raw)?;
                    self.sets
                        .iter()
                        .find(|(_, s)| s.handle == h)
                        .map(|(name, _)| name.clone())
                        .ok_or(NetError(2))?
                } else {
                    name(a, 2)?
                };
                let set = self.sets.get(&name).ok_or(NetError(2))?;
                if self.bound(&name) || flags & 0x100 != 0 && !set.elements.is_empty() {
                    return Err(NetError(16));
                }
                let handle = set.handle;
                ids.retain(|(table, _), (_, id)| *table != self.handle || *id != handle);
                self.sets.remove(&name);
            }
            12 | 14 => {
                let n = self
                    .set_name(&name(a, 2)?, optional(a, 4)?, ids)?
                    .to_owned();
                if self.sets[&n].spec.flags & CONSTANT != 0 && self.bound(&n) {
                    return Err(NetError(16));
                }
                Arc::make_mut(self.sets.get_mut(&n).unwrap()).edit(
                    get(a, 3),
                    op == 12,
                    flags & 0x200 != 0,
                )?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

impl Ruleset {
    pub(super) fn read_sets(
        &self,
        op: u16,
        family: u8,
        a: &Attrs<'_>,
        dump: bool,
        seq: u32,
        port: u32,
    ) -> Result<Vec<Vec<u8>>> {
        let table = get(a, 1).map(text).transpose()?;
        let name = get(a, 2).map(text).transpose()?;
        if (op == 13 || !dump) && (table.is_none() || name.is_none()) {
            return Err(NetError(22));
        }
        let mut out = vec![];
        let mut found = false;
        for ((f, tn), t) in &self.tables {
            if family != 0 && family != *f || table.as_ref().is_some_and(|s| s != tn) {
                continue;
            }
            for (n, set) in &t.sets {
                if name.as_ref().is_some_and(|s| s != n) {
                    continue;
                }
                found = true;
                let reply =
                    |ty, d: &[u8]| message(SUBSYSTEM | ty, if dump { 2 } else { 0 }, seq, port, d);
                if op == 10 {
                    out.push(reply(9, &set.description(*f, tn, n)));
                    continue;
                }
                let emit = |list: &[u8]| {
                    let mut d = data(*f);
                    string(&mut d, 1, tn);
                    string(&mut d, 2, n);
                    attr(&mut d, 3, list);
                    reply(12, &d)
                };
                let mut list = vec![];
                if dump {
                    for (key, e) in &set.elements {
                        let item = element_wire(key, e);
                        if list.len() + item.len() > 16384 {
                            out.push(emit(&list));
                            list.clear();
                        }
                        list.extend(item);
                    }
                } else {
                    for (kind, b) in attrs(need(a, 3)?)? {
                        if kind != 1 {
                            return Err(NetError(22));
                        }
                        let fields = fields(b, &[1, 3])?;
                        let key = set.key(&fields)?;
                        let e = set.elements.get(key).ok_or(NetError(2))?;
                        out.push(emit(&element_wire(key, e)));
                    }
                }
                if !list.is_empty() {
                    out.push(emit(&list));
                }
            }
        }
        if !found && (!dump || op == 13) {
            return Err(NetError(2));
        }
        if dump {
            out.push(message(3, 2, seq, port, &0i32.to_le_bytes()));
        }
        Ok(out)
    }
}

#[derive(Clone)]
pub(super) struct Lookup {
    set: String,
    src: usize,
    dest: Option<usize>,
    invert: bool,
}
impl Lookup {
    pub(super) fn parse(
        b: &[u8],
        table: Option<&Table>,
        ids: &BatchIds,
        initialized: &mut [bool; 64],
    ) -> Result<Self> {
        let a = fields(b, &[1, 2, 3, 4, 5])?;
        let name = name(&a, 1)?;
        let sreg = num(&a, 2)?;
        let t = table.ok_or(NetError(2))?;
        let name = t.set_name(&name, optional(&a, 4)?, ids)?;
        let set = &t.sets[name];
        let span = |r, len| -> Result<usize> {
            let at = reg(r, 1)?;
            if at + len > 64 {
                return Err(NetError(34));
            }
            Ok(at)
        };
        let src = span(sreg, set.spec.key_len)?;
        if initialized[src..src + set.spec.key_len].contains(&false) {
            return Err(NetError(22));
        }
        let flags = optional(&a, 5)?.unwrap_or(0);
        if flags > 1 {
            return Err(NetError(22));
        }
        let dest = if let Some(r) = optional(&a, 3)? {
            if flags != 0 || set.spec.data_type.is_none() {
                return Err(NetError(22));
            }
            let at = span(r, set.spec.data_len)?;
            initialized[at..at + set.spec.data_len.next_multiple_of(4)].fill(true);
            Some(at)
        } else {
            None
        };
        Ok(Self {
            set: name.to_owned(),
            src,
            dest,
            invert: flags != 0,
        })
    }
    pub(super) fn wire(&self) -> Vec<u8> {
        // Use the wide register encoding for aligned 16-byte banks.
        let regno = |at: usize| {
            if at.is_multiple_of(16) {
                1 + (at / 16) as u32
            } else {
                8 + (at / 4) as u32
            }
        };
        let mut d = vec![];
        string(&mut d, 1, &self.set);
        number(&mut d, 2, regno(self.src));
        if let Some(at) = self.dest {
            number(&mut d, 3, regno(at));
        }
        number(&mut d, 5, u32::from(self.invert));
        d
    }
    pub(super) fn evaluate(&self, sets: &Sets, regs: &mut [u8; 64]) -> bool {
        let set = &sets[&self.set];
        let exact = set
            .elements
            .get(&regs[self.src..self.src + set.spec.key_len]);
        let entry = if exact.is_some() ^ self.invert {
            exact
        } else {
            let Some(fallback) = set.elements.get(&[][..]) else {
                return false;
            };
            Some(fallback)
        };
        if let (Some(at), Some(e)) = (self.dest, entry) {
            let len = e.data.len();
            regs[at..at + len].copy_from_slice(&e.data);
            // The final NFT_REG32 is zero-padded, even for overlapping sreg/dreg.
            regs[at + len..at + len.next_multiple_of(4)].fill(0);
        }
        true
    }
}
