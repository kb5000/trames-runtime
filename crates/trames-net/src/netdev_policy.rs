// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace-owned policy routing for a configurable userspace IP uplink.
//! There is one physical egress; socket policy selects a real guest table and
//! source before the existing gateway transports bytes. No host routes change.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rule {
    pub family: u8,
    pub priority: u32,
    pub table: u32,
    pub action: u8,
    pub mark: u32,
    pub mask: u32,
    pub input: Option<Vec<u8>>,
    pub output: Option<Vec<u8>>,
    pub uid: Option<[u32; 2]>,
    pub invert: bool,
}
impl Rule {
    fn lookup(family: u8, priority: u32, table: u32) -> Self {
        Self {
            family,
            priority,
            table,
            action: 1,
            mark: 0,
            mask: 0,
            input: None,
            output: None,
            uid: None,
            invert: false,
        }
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Context {
    pub mark: u32,
    pub uid: u32,
    pub device: Option<u32>,
}
#[derive(Clone, Copy)]
pub(crate) struct Entry {
    pub route: Route,
    pub kind: u8,
}
#[derive(Clone)]
pub(super) struct Policy {
    active: bool,
    rules: Vec<Rule>,
    tables: BTreeMap<u32, Vec<Entry>>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            active: false,
            rules: [2, 10]
                .into_iter()
                .flat_map(|family| {
                    [(0, 255), (32766, 254), (32767, 253)]
                        .into_iter()
                        .map(move |(p, t)| Rule::lookup(family, p, t))
                })
                .collect(),
            tables: BTreeMap::new(),
        }
    }
}
impl Policy {
    pub(super) fn forget_ipv6_device(&mut self, index: u32) {
        for entries in self.tables.values_mut() {
            entries.retain(|e| e.route.device != index || e.route.destination.ip.is_ipv4());
        }
    }

    pub(super) fn forget_device(&mut self, index: u32) {
        for entries in self.tables.values_mut() {
            entries.retain(|e| e.route.device != index);
        }
    }
}
impl Topology {
    pub fn policy_rules(&self, id: u64, family: u8) -> Vec<Rule> {
        self.spaces[&id]
            .policy
            .rules
            .iter()
            .filter(|r| family == 0 || family == r.family)
            .cloned()
            .collect()
    }
    pub fn policy_rule(
        &mut self,
        id: u64,
        rule: Rule,
        add: bool,
        exclusive: bool,
        priority: bool,
    ) -> Result<()> {
        let space = self.spaces.get_mut(&id).ok_or(NetError(2))?;
        if !space.managed_uplink {
            return Err(NetError(95));
        }
        let rules = &mut space.policy.rules;
        if add {
            if exclusive && rules.contains(&rule) {
                return Err(NetError(17));
            }
            if rules.len() >= 512 {
                return Err(NetError(28));
            }
            rules.push(rule);
            rules.sort_by_key(|r| r.priority);
        } else {
            let i = rules
                .iter()
                .position(|r| {
                    r.family == rule.family
                        && (!priority || r.priority == rule.priority)
                        && (rule.table == 0 || r.table == rule.table)
                        && (rule.action == 0 || r.action == rule.action)
                        && r.invert == rule.invert
                        && (rule.mask == 0 || r.mark == rule.mark && r.mask == rule.mask)
                        && rule.uid.is_none_or(|v| r.uid == Some(v))
                        && rule
                            .input
                            .as_ref()
                            .is_none_or(|v| r.input.as_ref() == Some(v))
                        && rule
                            .output
                            .as_ref()
                            .is_none_or(|v| r.output.as_ref() == Some(v))
                })
                .ok_or(NetError(2))?;
            rules.remove(i);
        }
        space.policy.active = true;
        self.changed();
        Ok(())
    }
    pub fn policy_routes(&self, id: u64) -> Vec<(u32, Entry)> {
        self.routes(id)
            .into_iter()
            .map(|route| (254, Entry { route, kind: 1 }))
            .chain(
                self.spaces[&id]
                    .policy
                    .tables
                    .iter()
                    .flat_map(|(t, r)| r.iter().map(move |r| (*t, *r))),
            )
            .collect()
    }
    pub fn policy_route(
        &mut self,
        id: u64,
        table: u32,
        entry: Entry,
        add: bool,
        replace: bool,
        exclusive: bool,
    ) -> Result<()> {
        if table == 254 && entry.kind == 1 {
            return self.route(id, entry.route, add, replace, exclusive);
        }
        if !self.spaces[&id].managed_uplink {
            return Err(NetError(95));
        }
        let route = entry.route;
        if route.destination != route.destination.network() {
            return Err(NetError(22));
        }
        if entry.kind == 1 {
            let d = self.device(id, route.device)?;
            if let Some(g) = route.gateway {
                if !d.addresses.iter().any(|a| a.contains(g)) {
                    return Err(NetError(101));
                }
            }
        }
        let tables = &mut self.spaces.get_mut(&id).unwrap().policy.tables;
        if !add && !tables.contains_key(&table) {
            return Err(NetError(3));
        }
        if add && !tables.contains_key(&table) && tables.len() >= 128 {
            return Err(NetError(28));
        }
        let routes = tables.entry(table).or_default();
        let at = routes.iter().position(|r| {
            r.route.destination == route.destination && r.route.metric == route.metric
        });
        if add {
            if let Some(i) = at {
                if exclusive || !replace {
                    return Err(NetError(17));
                }
                routes[i] = entry;
            } else {
                if routes.len() >= MAX_ROUTES {
                    return Err(NetError(28));
                }
                routes.push(entry);
            }
        } else {
            let i = at
                .filter(|i| {
                    routes[*i].kind == entry.kind
                        && (route.device == 0 || routes[*i].route.device == route.device)
                })
                .ok_or(NetError(3))?;
            routes.remove(i);
        }
        self.changed();
        Ok(())
    }
    pub fn source_for(
        &self,
        id: u64,
        destination: IpAddr,
        context: Context,
    ) -> Result<(IpAddr, u32, Option<IpAddr>)> {
        let p = &self.spaces[&id].policy;
        if !p.active {
            return self.source_main(id, destination);
        }
        let family = if destination.is_ipv4() { 2 } else { 10 };
        for r in p.rules.iter().filter(|r| r.family == family) {
            let matches = context.mark & r.mask == r.mark & r.mask
                && r.uid
                    .is_none_or(|range| (range[0]..=range[1]).contains(&context.uid))
                && r.input.as_ref().is_none_or(|n| n == b"lo")
                && r.output.as_ref().is_none_or(|n| {
                    context
                        .device
                        .and_then(|i| self.devices.get(&(id, i)))
                        .is_some_and(|d| d.name == *n)
                });
            if matches == r.invert {
                continue;
            }
            match r.action {
                6 => return Err(NetError(22)),
                7 => return Err(NetError(101)),
                8 => return Err(NetError(13)),
                _ => {}
            }
            if r.table == 255 {
                if self.own(id, destination) {
                    return self.source_main(id, destination);
                }
                continue;
            }
            // Main-route synthesis is needed only for that table. Normal
            // Android policy lookups borrow stored entries without allocation.
            let main = if r.table == 254 {
                self.routes(id)
            } else {
                Vec::new()
            };
            let selected =
                main.iter()
                    .map(|route| Entry {
                        route: *route,
                        kind: 1,
                    })
                    .chain(p.tables.get(&r.table).into_iter().flatten().copied())
                    .filter(|e| e.route.destination.contains(destination))
                    .filter(|e| {
                        e.kind != 1
                            || self.devices.get(&(id, e.route.device)).is_some_and(|d| {
                                d.up && context.device.is_none_or(|i| i == d.index)
                            })
                    })
                    .min_by_key(|e| {
                        (
                            std::cmp::Reverse(e.route.destination.prefix),
                            e.route.metric,
                        )
                    });
            if let Some(entry) = selected {
                match entry.kind {
                    6 => return Err(NetError(22)),
                    7 => return Err(NetError(101)),
                    8 => return Err(NetError(13)),
                    9 => continue,
                    _ => {}
                }
                let d = &self.devices[&(id, entry.route.device)];
                if let Some(a) = d
                    .addresses
                    .iter()
                    .find(|a| a.ip.is_ipv4() == destination.is_ipv4())
                {
                    return Ok((a.ip, d.index, entry.route.gateway));
                }
            }
        }
        Err(NetError(101))
    }
}
