// SPDX-License-Identifier: GPL-3.0-or-later
//! Real Ethernet forwarding. The bridge looks at MAC/VLAN, never destination IP.
use super::*;
use crate::ethernet::{Action, Frame};
impl Topology {
    pub fn ethernet_step(
        &self,
        ns: u64,
        index: u32,
        frame: Frame,
        outgoing: bool,
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) -> Vec<Action> {
        let Some(d) = self.devices.get(&(ns, index)).filter(|d| d.up) else {
            return vec![];
        };
        if !matches!(
            d.kind,
            DeviceKind::Loopback
                | DeviceKind::Veth { .. }
                | DeviceKind::Bridge
                | DeviceKind::Tap
                | DeviceKind::Ethernet
        ) {
            return vec![];
        }
        if (d.kind != DeviceKind::Tap || outgoing) && frame.0.len() > d.mtu as usize + 22 {
            self.account(ns, index, frame.0.len(), outgoing, true);
            return vec![];
        }
        self.spaces[&ns]
            .packets
            .observe_wire(&d.snapshot(), &frame, outgoing, wakes);
        self.account(ns, index, frame.0.len(), outgoing, false);
        if outgoing {
            return match d.kind {
                DeviceKind::Loopback => vec![Action::Receive(ns, index, frame)],
                DeviceKind::Veth { peer } => self
                    .peer_device(peer)
                    .filter(|d| d.up)
                    .map_or_else(Vec::new, |p| {
                        vec![Action::Receive(p.namespace, p.index, frame)]
                    }),
                DeviceKind::Tap => {
                    if let Some(p) = self.tunnel(ns, index) {
                        p.enqueue(frame.0.to_vec(), frame.outer_protocol(), wakes);
                    }
                    vec![]
                }
                DeviceKind::Bridge => self.ethernet_bridge(ns, index, 0, frame, wakes),
                DeviceKind::Ethernet => vec![Action::External(ns, index, frame)],
                _ => vec![],
            };
        }
        if let Some(master) = d.master {
            if frame.source()[0] & 1 != 0 || frame.source() == [0; 6] {
                return vec![];
            }
            return self.ethernet_bridge(ns, master, index, frame, wakes);
        }
        if frame.destination() == d.mac || frame.multicast() {
            vec![Action::Local(ns, index, frame)]
        } else {
            vec![]
        }
    }
    fn ethernet_bridge(
        &self,
        ns: u64,
        bridge: u32,
        input: u32,
        mut frame: Frame,
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) -> Vec<Action> {
        let Some(br) = self
            .devices
            .get(&(ns, bridge))
            .filter(|d| d.up && d.kind == DeviceKind::Bridge)
        else {
            return vec![];
        };
        let port = if input == 0 {
            br
        } else {
            let Some(p) = self.devices.get(&(ns, input)) else {
                return vec![];
            };
            p
        };
        if !matches!(port.l2.state, 2 | 3) {
            return vec![];
        }
        let vid = if br.bridge_config.vlan_filtering {
            let Some(v) = port.l2.ingress(&frame) else {
                return vec![];
            };
            v
        } else {
            0
        };
        if input != 0
            && port.l2.learning
            && !self
                .devices
                .range((ns, 0)..=(ns, u32::MAX))
                .any(|(_, d)| d.mac == frame.source())
        {
            br.switch
                .learn(vid, frame.source(), input, br.bridge_config.ageing);
        }
        if port.l2.state != 3 {
            return vec![];
        }
        if input != 0 {
            self.spaces[&ns]
                .packets
                .observe_wire(&br.snapshot(), &frame, false, wakes);
        }
        let known = br
            .switch
            .lookup_entry(vid, frame.destination(), br.bridge_config.ageing);
        let local_mac = known.map_or_else(
            || {
                self.devices.range((ns, 0)..=(ns, u32::MAX)).any(|(_, d)| {
                    (d.index == bridge || d.master == Some(bridge))
                        && d.mac == frame.destination()
                        && (!br.bridge_config.vlan_filtering || d.l2.vlans.contains_key(&vid))
                })
            },
            |e| e.local,
        );
        let mut actions = Vec::new();
        // A bridge port's own destination is PACKET_HOST only on ingress
        // through that port. Another port's local MAC terminates forwarding
        // but remains PACKET_OTHERHOST for the bridge IP stack.
        let host_destination = frame.destination() == br.mac || frame.destination() == port.mac;
        if input != 0 && (local_mac && host_destination || frame.multicast()) {
            let local = if br.bridge_config.vlan_filtering {
                br.l2.egress(&frame, vid)
            } else {
                Some(frame.clone())
            };
            if let Some(local) = local {
                actions.push(Action::Local(ns, bridge, local));
            }
        }
        if local_mac || frame.reserved() {
            return actions;
        }
        let mut reassembled = false;
        if input != 0
            && matches!(frame.protocol(), 0x0800 | 0x86dd)
            && self.spaces[&ns].bridge_filter[usize::from(frame.protocol() == 0x86dd)]
            && self.spaces[&ns].firewall.has_rules()
        {
            let Some((whole, was_fragmented)) = br.switch.defragment(input, frame) else {
                return actions;
            };
            frame = whole;
            reassembled = was_fragmented;
            let mut packet = frame.payload().to_vec();
            // Linux presents forwarded unicast as PACKET_HOST at the bridge IP hooks.
            if !crate::virtualnet::packet::valid_transport(&packet)
                || self
                    .bridge_packet(ns, bridge, frame.ingress_type(true), &mut packet)
                    .is_none()
            {
                return actions;
            }
            if packet != frame.payload() {
                frame = frame.with_payload(&packet);
            }
        }
        let known = if frame.multicast() {
            None
        } else {
            known.map(|e| e.port)
        };
        for (&(_, index), p) in self.devices.range((ns, 0)..=(ns, u32::MAX)) {
            if p.master != Some(bridge)
                || !p.up
                || p.l2.state != 3
                || index == input && !p.l2.hairpin
            {
                continue;
            }
            if let Some(known) = known {
                if known != index {
                    continue;
                }
            } else if if frame.destination() == [255; 6] {
                !p.l2.broadcast_flood
            } else if frame.multicast() {
                !p.l2.multicast_flood
            } else {
                !p.l2.flood
            } {
                continue;
            }
            let forwarded = if br.bridge_config.vlan_filtering {
                p.l2.egress(&frame, vid)
            } else {
                Some(frame.clone())
            };
            if let Some(f) = forwarded {
                if reassembled {
                    let serial = self.spaces[&ns].ip_serial.fetch_add(1, Relaxed) as u32;
                    for packet in crate::virtualnet::packet::fragment_link(
                        f.payload().to_vec(),
                        p.mtu as usize,
                        serial,
                    )
                    .unwrap_or_default()
                    {
                        actions.push(Action::Send(ns, index, f.with_payload(&packet)));
                    }
                } else {
                    actions.push(Action::Send(ns, index, f));
                }
            }
        }
        actions
    }
    pub fn forget_l2_port(&self, ns: u64, index: u32) {
        if let Some(s) = self.spaces.get(&ns) {
            s.neighbor_cache.forget(index);
        }
        for d in self
            .devices
            .values()
            .filter(|d| d.namespace == ns && d.kind == DeviceKind::Bridge)
        {
            d.switch.forget(index);
        }
    }
    pub fn check_bridge_loop(&self, ns: u64, index: u32, master: u32) -> Result<()> {
        let Some(d) = self.devices.get(&(ns, index)) else {
            return Err(NetError(19));
        };
        let DeviceKind::Veth { peer } = d.kind else {
            return Ok(());
        };
        let Some(p) = self.devices.values().find(|p| p.index == peer) else {
            return Ok(());
        };
        let Some(peer_master) = p.master else {
            return Ok(());
        };
        let target = (p.namespace, peer_master);
        let mut todo = vec![(ns, master)];
        let mut seen = BTreeSet::new();
        while let Some(key) = todo.pop() {
            if !seen.insert(key) {
                continue;
            }
            if key == target {
                return Err(NetError(40));
            }
            for port in self.devices.values().filter(|p| {
                p.namespace == key.0
                    && p.master == Some(key.1)
                    && p.index != index
                    && p.index != peer
            }) {
                if let DeviceKind::Veth { peer } = port.kind {
                    if let Some(p) = self.devices.values().find(|p| p.index == peer) {
                        if let Some(m) = p.master {
                            todo.push((p.namespace, m));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
