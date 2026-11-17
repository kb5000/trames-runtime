// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::ethernet::{BridgeConfig, FdbEntry, PortConfig};
impl Topology {
    pub fn port_config(&self, ns: u64, index: u32) -> Result<&PortConfig> {
        Ok(&self.devices.get(&(ns, index)).ok_or(NetError(19))?.l2)
    }
    pub fn bridge_config(&self, ns: u64, index: u32) -> Result<&BridgeConfig> {
        let d = self.devices.get(&(ns, index)).ok_or(NetError(19))?;
        if d.kind != DeviceKind::Bridge {
            return Err(NetError(22));
        }
        Ok(&d.bridge_config)
    }
    pub fn configure_bridge(&mut self, ns: u64, index: u32, config: BridgeConfig) -> Result<()> {
        self.bridge_config(ns, index)?;
        self.devices.get_mut(&(ns, index)).unwrap().bridge_config = config;
        self.changed();
        Ok(())
    }
    pub fn configure_port(&mut self, ns: u64, index: u32, config: PortConfig) -> Result<()> {
        let d = self.devices.get_mut(&(ns, index)).ok_or(NetError(19))?;
        if d.master.is_none() && d.kind != DeviceKind::Bridge {
            return Err(NetError(22));
        }
        if config.state > 4 {
            return Err(NetError(22));
        }
        d.l2 = config;
        self.changed();
        Ok(())
    }
    pub fn fdb(&self, ns: u64, index: u32) -> Vec<(u32, FdbEntry)> {
        let mut result = Vec::new();
        for br in self
            .devices
            .range((ns, 0)..=(ns, u32::MAX))
            .map(|(_, d)| d)
            .filter(|d| d.kind == DeviceKind::Bridge)
        {
            let mut entries = br.switch.entries(br.bridge_config.ageing);
            for d in self
                .devices
                .range((ns, 0)..=(ns, u32::MAX))
                .map(|(_, d)| d)
                .filter(|d| d.index == br.index || d.master == Some(br.index))
            {
                let vlans: Vec<_> = if br.bridge_config.vlan_filtering {
                    d.l2.vlans.keys().copied().collect()
                } else {
                    vec![0]
                };
                for vlan in vlans {
                    if !entries.iter().any(|e| e.mac == d.mac && e.vlan == vlan) {
                        entries.push(FdbEntry {
                            mac: d.mac,
                            vlan,
                            port: d.index,
                            permanent: true,
                            local: true,
                        });
                    }
                }
            }
            result.extend(
                entries
                    .into_iter()
                    .filter(|e| index == 0 || index == br.index || e.port == index)
                    .map(|e| (br.index, e)),
            );
        }
        result
    }

    pub fn fdb_modify(
        &mut self,
        ns: u64,
        master: u32,
        entry: FdbEntry,
        add: bool,
        flags: u16,
    ) -> Result<(u32, FdbEntry)> {
        let port = self.devices.get(&(ns, entry.port)).ok_or(NetError(19))?;
        let bridge = if port.kind == DeviceKind::Bridge {
            entry.port
        } else {
            port.master.ok_or(NetError(22))?
        };
        if master != 0 && master != bridge {
            return Err(NetError(22));
        }
        let br = self.devices.get(&(ns, bridge)).ok_or(NetError(19))?;
        if br.bridge_config.vlan_filtering && !port.l2.vlans.contains_key(&entry.vlan) {
            return Err(NetError(22));
        }
        br.switch.modify(entry, add, flags).map(|e| (bridge, e))
    }
}
