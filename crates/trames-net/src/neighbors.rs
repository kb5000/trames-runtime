// SPDX-License-Identifier: GPL-3.0-or-later
//! Neighbors on the IP fabric are resolved from live topology (NUD_NOARP).
//! Explicit entries override that resolution; no ARP/NUD worker or timer is needed.
use super::*;
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    pub index: u32,
    pub address: IpAddr,
    pub mac: Option<[u8; 6]>,
    pub state: u16,
}
impl Topology {
    pub fn neighbors(&self, ns: u64, index: u32, family: u8) -> Vec<Entry> {
        let mut entries = self.spaces[&ns].neighbors.clone();
        for d in self
            .devices(ns)
            .into_iter()
            .filter(|d| index == 0 || index == d.index)
        {
            if !d.up || !matches!(d.kind, DeviceKind::Veth { .. } | DeviceKind::Bridge) {
                continue;
            }
            for remote in self.devices.values().filter(|r| r.namespace != ns && r.up) {
                for a in &remote.addresses {
                    if self
                        .resolve_neighbor_path(ns, d.index, a.ip)
                        .is_some_and(|(target, _)| target == (remote.namespace, remote.index))
                    {
                        entries.entry((d.index, a.ip)).or_insert(Entry {
                            index: d.index,
                            address: a.ip,
                            mac: Some(remote.mac),
                            state: 64,
                        });
                    }
                }
            }
        }
        entries
            .into_values()
            .filter(|e| {
                (index == 0 || e.index == index)
                    && (family == 0 || (family == 2) == e.address.is_ipv4())
            })
            .collect()
    }
    pub fn neighbor(&mut self, ns: u64, entry: Entry, add: bool, flags: u16) -> Result<Entry> {
        let d = self.device(ns, entry.index)?;
        if !matches!(d.kind, DeviceKind::Veth { .. } | DeviceKind::Bridge) {
            return Err(NetError(95));
        }
        if entry.address.is_unspecified() || entry.address.is_multicast() {
            return Err(NetError(22));
        }
        let table = &mut self.spaces.get_mut(&ns).unwrap().neighbors;
        let key = (entry.index, entry.address);
        if !add {
            return table.remove(&key).ok_or(NetError(2));
        }
        if !matches!(entry.state, 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128) {
            return Err(NetError(22));
        }
        if entry.state & (2 | 4 | 8 | 16 | 128) != 0 && entry.mac.is_none() {
            return Err(NetError(22));
        }
        if table.contains_key(&key) {
            if flags & 0x200 != 0 {
                return Err(NetError(17));
            }
            if flags & 0x100 == 0 {
                return Err(NetError(17));
            }
        } else {
            if flags & 0x400 == 0 {
                return Err(NetError(2));
            }
            if table.len() >= 1024 {
                return Err(NetError(105));
            }
        }
        table.insert(key, entry);
        Ok(entry)
    }
}
