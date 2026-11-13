// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest interface IPv6 configuration. No host sysctl is read or written.
use super::*;
type Changes = Vec<(u64, u16, u32, Vec<u8>)>;
impl Topology {
    pub fn stable_secret(&self, id: u64, scope: u32) -> Result<std::net::Ipv6Addr> {
        self.ipv6_knob(id, scope, 0)?;
        let secret = match scope {
            0 => None,
            u32::MAX => self.spaces[&id].stable_secret,
            _ => self.devices[&(id, scope)].stable_secret,
        };
        secret.ok_or(NetError(5))
    }
    pub fn set_stable_secret(
        &mut self,
        id: u64,
        scope: u32,
        secret: std::net::Ipv6Addr,
    ) -> Result<()> {
        self.ipv6_knob(id, scope, 0)?;
        // Linux refuses conf/all and makes stable privacy the interface mode
        // when its secret is installed. This IP-only uplink has no autonomous
        // RA source: storing this state does not advertise SLAAC support.
        match scope {
            0 => return Err(NetError(5)),
            u32::MAX => {
                self.spaces.get_mut(&id).unwrap().stable_secret = Some(secret);
                self.spaces.get_mut(&id).unwrap().ipv6_default[3] = 2;
            }
            _ => {
                let d = self.devices.get_mut(&(id, scope)).unwrap();
                d.stable_secret = Some(secret);
                d.ipv6[3] = 2;
            }
        }
        self.changed();
        Ok(())
    }

    pub fn managed(&self, id: u64) -> bool {
        self.spaces[&id].managed_uplink
    }
    pub fn ipv6_knob(&self, id: u64, scope: u32, knob: usize) -> Result<i32> {
        let s = &self.spaces[&id];
        if !s.managed_uplink {
            return Err(NetError(95));
        }
        let values = match scope {
            0 => &s.ipv6_all,
            u32::MAX => &s.ipv6_default,
            _ => &self.devices.get(&(id, scope)).ok_or(NetError(19))?.ipv6,
        };
        values.get(knob).copied().ok_or(NetError(22))
    }
    pub fn set_ipv6_knob(
        &mut self,
        id: u64,
        scope: u32,
        knob: usize,
        value: i32,
    ) -> Result<Changes> {
        self.ipv6_knob(id, scope, knob)?;
        let valid = match knob {
            0 => (0..=2).contains(&value),
            1 => (-1..=2).contains(&value),
            2 => (0..=1).contains(&value),
            3 => (0..=3).contains(&value),
            _ => false,
        };
        if !valid {
            return Err(NetError(22));
        }
        match scope {
            0 => self.spaces.get_mut(&id).unwrap().ipv6_all[knob] = value,
            u32::MAX => self.spaces.get_mut(&id).unwrap().ipv6_default[knob] = value,
            _ => self.devices.get_mut(&(id, scope)).unwrap().ipv6[knob] = value,
        }
        let mut changes = Vec::new();
        if scope != u32::MAX {
            let indices = if scope == 0 && knob == 2 {
                self.devices(id).into_iter().map(|d| d.index).collect()
            } else if scope == 0 {
                Vec::new()
            } else {
                vec![scope]
            };
            for index in indices {
                self.devices.get_mut(&(id, index)).unwrap().ipv6[knob] = value;
                if knob == 2 && value == 1 {
                    let before = self.device(id, index)?;
                    let routes = self
                        .policy_routes(id)
                        .into_iter()
                        .filter(|(_, e)| {
                            e.route.device == index && e.route.destination.ip.is_ipv6()
                        })
                        .collect::<Vec<_>>();
                    self.devices
                        .get_mut(&(id, index))
                        .unwrap()
                        .addresses
                        .retain(|a| a.ip.is_ipv4());
                    let s = self.spaces.get_mut(&id).unwrap();
                    s.routes
                        .retain(|r| r.device != index || r.destination.ip.is_ipv4());
                    s.policy.forget_ipv6_device(index);
                    for address in before.addresses.iter().filter(|a| a.ip.is_ipv6()) {
                        changes.push((
                            id,
                            21,
                            0x100,
                            crate::rtnetlink::address_data(&before, *address),
                        ));
                    }
                    for (table, e) in routes {
                        changes.push((
                            id,
                            25,
                            0x400,
                            crate::rtnetlink::policy_route_data(table, e),
                        ));
                    }
                }
            }
        }
        self.changed();
        Ok(changes)
    }
}
