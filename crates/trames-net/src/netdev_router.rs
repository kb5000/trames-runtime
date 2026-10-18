// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-namespace packet routing: raw -> tracking -> NAT/filter -> actual next hop.
use super::*;
use crate::{
    conntrack::{self, Track},
    nftables::Hook,
};
#[derive(Clone, Copy, Debug)]
pub(crate) struct Delivery {
    pub namespace: u64,
    pub input: u32,
    pub output: u32,
    pub external: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct NativeForward {
    pub input: u32,
    pub reply: conntrack::Key,
}
type DeviceKey = (u64, u32);
type Neighbor = (DeviceKey, Option<DeviceKey>);
impl Topology {
    fn hook(
        &self,
        namespace: u64,
        stage: (u32, bool),
        devices: (u32, u32),
        packet: &mut [u8],
        track: &mut Track,
        state: &mut conntrack::State,
    ) -> bool {
        let (hook, raw) = stage;
        let (input, output) = devices;
        self.spaces[&namespace].firewall.borrow().process(
            packet,
            &Hook {
                graph: self,
                namespace,
                hook,
                input,
                output,
                raw,
            },
            track,
            state,
        )
    }
    fn route_namespace(
        &self,
        namespace: u64,
        input: Option<u32>,
        packet: &mut [u8],
        external_reply: bool,
    ) -> Option<(u32, Option<IpAddr>, Track)> {
        let k = conntrack::key(packet)?;
        let connection = self.spaces[&namespace].connections.clone();
        let mut state = connection.borrow_mut();
        let initial_out = self
            .source(namespace, k.tuple.destination.ip())
            .map(|(_, i, _)| i)
            .unwrap_or(0);
        let first = if input.is_some() { 0 } else { 3 };
        let mut raw = Track::untracked(k, 0);
        if !self.hook(
            namespace,
            (first, true),
            (input.unwrap_or(0), initial_out),
            packet,
            &mut raw,
            &mut state,
        ) {
            return None;
        }
        let mut track = state.begin(packet, raw.zone)?;
        let result = (|| {
            if !self.hook(
                namespace,
                (first, false),
                (input.unwrap_or(0), initial_out),
                packet,
                &mut track,
                &mut state,
            ) {
                return None;
            }
            let destination = conntrack::key(packet)?.tuple.destination.ip();
            let local = !external_reply && self.own(namespace, destination);
            if let Some(input) = input.filter(|_| local) {
                if !self.hook(
                    namespace,
                    (1, false),
                    (input, 0),
                    packet,
                    &mut track,
                    &mut state,
                ) {
                    return None;
                }
                return Some((0, None));
            }
            let (out, gateway) = if external_reply {
                (2, None)
            } else {
                let (_, out, gateway) = self.source(namespace, destination).ok()?;
                (out, gateway)
            };
            if let Some(input) = input {
                if !self.forwarding(namespace, destination.is_ipv6()) {
                    return None;
                }
                let ttl = if packet[0] >> 4 == 4 { 8 } else { 7 };
                if packet[ttl] <= 1 {
                    return None;
                }
                packet[ttl] -= 1;
                if packet[0] >> 4 == 4 {
                    smoltcp::wire::Ipv4Packet::new_unchecked(&mut *packet).fill_checksum();
                }
                if !self.hook(
                    namespace,
                    (2, false),
                    (input, out),
                    packet,
                    &mut track,
                    &mut state,
                ) {
                    return None;
                }
            }
            if !self.hook(
                namespace,
                (4, false),
                (0, out),
                packet,
                &mut track,
                &mut state,
            ) {
                return None;
            }
            Some((out, gateway))
        })();
        state.finish(track, result.is_some());
        result.map(|(out, gateway)| (out, gateway, track))
    }
    pub fn route_packet(
        &self,
        source: u64,
        incoming: Option<u32>,
        packet: &mut [u8],
    ) -> Option<Delivery> {
        let mut ns = source;
        let mut input = incoming;
        let mut visited = BTreeSet::new();
        let mut first = 0;
        for _ in 0..16 {
            if !visited.insert(ns) {
                return None;
            }
            let (out, gateway, mut track) = self.route_namespace(ns, input, packet, false)?;
            if first == 0 {
                first = out;
            }
            if out == 0 {
                return Some(Delivery {
                    namespace: ns,
                    input: input.unwrap_or(1),
                    output: first,
                    external: false,
                });
            }
            let destination = conntrack::key(packet)?.tuple.destination.ip();
            if self.own(ns, destination) {
                // Loopback keeps the same conntrack attachment across output
                // and input. Starting a second flow from the translated tuple
                // would steal the reply index and break Docker's DNS redirect.
                let connections = self.spaces[&ns].connections.clone();
                let mut state = connections.borrow_mut();
                let accepted = self.hook(ns, (0, true), (1, 0), packet, &mut track, &mut state)
                    && self.hook(ns, (0, false), (1, 0), packet, &mut track, &mut state)
                    && self.hook(ns, (1, false), (1, 0), packet, &mut track, &mut state);
                state.finish(track, accepted);
                if !accepted {
                    return None;
                }
                return Some(Delivery {
                    namespace: ns,
                    input: 1,
                    output: first,
                    external: false,
                });
            }
            let d = self.device(ns, out).ok()?;
            if d.kind == DeviceKind::Direct {
                // Forwarded egress requires an actual source NAT binding. A
                // route or ip_forward alone never opens the host network.
                if (incoming.is_some() || ns != source) && track.status & 16 == 0 {
                    return None;
                }
                return Some(Delivery {
                    namespace: ns,
                    input: out,
                    output: first,
                    external: true,
                });
            }
            let next = gateway.unwrap_or(destination);
            let ((target, target_input), bridge) = self.neighbor_path(ns, out, next)?;
            if let Some((bridge_ns, bridge_index)) =
                bridge.filter(|(b, _)| *b != ns && *b != target)
            {
                if self.spaces[&bridge_ns].bridge_filter[usize::from(destination.is_ipv6())] {
                    self.bridge_packet(bridge_ns, bridge_index, packet)?;
                }
            }
            ns = target;
            input = Some(target_input);
        }
        None
    }
    fn bridge_packet(&self, ns: u64, bridge: u32, packet: &mut [u8]) -> Option<()> {
        let connection = self.spaces[&ns].connections.clone();
        let mut state = connection.borrow_mut();
        let key = conntrack::key(packet)?;
        let mut raw = Track::untracked(key, 0);
        if !self.hook(ns, (0, true), (bridge, 0), packet, &mut raw, &mut state) {
            return None;
        }
        let mut t = state.begin(packet, raw.zone)?;
        let ok = self.hook(ns, (0, false), (bridge, 0), packet, &mut t, &mut state)
            && self.hook(ns, (2, false), (bridge, bridge), packet, &mut t, &mut state)
            && self.hook(ns, (4, false), (0, bridge), packet, &mut t, &mut state);
        state.finish(t, ok);
        ok.then_some(())
    }
    fn neighbor_path(&self, id: u64, out: u32, address: IpAddr) -> Option<Neighbor> {
        let mut todo = vec![((id, out), None)];
        let mut visited = BTreeSet::new();
        while let Some((key, bridge)) = todo.pop() {
            if !visited.insert(key) {
                continue;
            }
            let d = self.device(key.0, key.1).ok()?;
            if !d.up {
                continue;
            }
            if d.namespace != id && d.addresses.iter().any(|a| a.ip == address) {
                return Some(((d.namespace, d.index), bridge));
            }
            match d.kind {
                DeviceKind::Veth { peer } => {
                    if let Some(p) = self.peer_device(peer) {
                        todo.push(((p.namespace, p.index), bridge));
                    }
                    if let Some(master) = d.master {
                        todo.push(((d.namespace, master), Some((d.namespace, master))));
                    }
                }
                DeviceKind::Bridge => {
                    for (&key, v) in &self.devices {
                        if v.namespace == d.namespace && v.master == Some(d.index) {
                            todo.push((key, Some((d.namespace, d.index))));
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }
    pub fn native_policy(
        &self,
        ns: u64,
        input: bool,
        packet: &mut [u8],
        forward: Option<NativeForward>,
    ) -> Option<Option<NativeForward>> {
        if !input {
            if let Some(forward) = forward {
                if !conntrack::rewrite(packet, forward.reply) {
                    return None;
                }
                let (out, _, _) = self.route_namespace(ns, Some(forward.input), packet, true)?;
                return (out == 2).then_some(Some(forward));
            }
            self.route_namespace(ns, None, packet, false)?;
            return Some(None);
        }
        let result = self.route_packet(ns, Some(2), packet)?;
        if result.namespace == ns && !result.external {
            return Some(None);
        }
        if result.external {
            return None;
        }
        let wire = conntrack::key(packet)?;
        let (_, bridge, _) = self.source(ns, wire.tuple.destination.ip()).ok()?;
        Some(Some(NativeForward {
            input: bridge,
            reply: wire.reverse(),
        }))
    }
    pub fn output_redirect(&self, ns: u64, packet: &mut [u8], bound: bool) -> bool {
        // Route preview uses private copies: no counters, NAT reservations or
        // connection state change until the real SYN/datagram enters the stack.
        let mut copy = self.clone();
        let space = copy.spaces.get_mut(&ns).unwrap();
        let firewall = space.firewall.borrow().clone();
        space.firewall = Rc::new(RefCell::new(firewall));
        let connections = if bound {
            space.connections.borrow().clone()
        } else {
            crate::conntrack::State::default()
        };
        space.connections = Rc::new(RefCell::new(connections));
        let Some((_, _, t)) = copy.route_namespace(ns, None, packet, false) else {
            return false;
        };
        t.status & 32 != 0
    }
}
