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
        for (&(index, address), e) in self.spaces[&ns].neighbor_cache.entries.read().iter() {
            entries.entry((index, address)).or_insert(Entry {
                index,
                address,
                mac: e.mac,
                state: if e.state == 2 && e.updated.elapsed() > std::time::Duration::from_secs(30) {
                    4
                } else {
                    e.state
                },
            });
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
        if !matches!(
            d.kind,
            DeviceKind::Veth { .. } | DeviceKind::Bridge | DeviceKind::Tap
        ) {
            return Err(NetError(95));
        }
        if entry.address.is_unspecified() || entry.address.is_multicast() {
            return Err(NetError(22));
        }
        let table = &mut self.spaces.get_mut(&ns).unwrap().neighbors;
        let key = (entry.index, entry.address);
        if !add {
            if let Some(e) = table.remove(&key) {
                return Ok(e);
            }
            return self.spaces[&ns]
                .neighbor_cache
                .entries
                .write()
                .remove(&key)
                .map(|e| Entry {
                    index: entry.index,
                    address: entry.address,
                    mac: e.mac,
                    state: e.state,
                })
                .ok_or(NetError(2));
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
