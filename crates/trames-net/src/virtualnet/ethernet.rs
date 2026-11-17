// SPDX-License-Identifier: GPL-3.0-or-later
//! Drives internal Ethernet on the original fabric transaction, never a broker.
use super::*;
use crate::ethernet::{Action, Frame};
impl Inner {
    pub(super) fn queue_frames(
        &mut self,
        view: &crate::netdev::View,
        actions: impl IntoIterator<Item = Action>,
    ) {
        self.ethernet.extend(
            actions
                .into_iter()
                .take(1024usize.saturating_sub(self.ethernet.len()))
                .map(|a| (view.clone(), a)),
        );
    }
    fn node_key(&self, view: &crate::netdev::View, ns: u64) -> Option<u64> {
        self.nodes.iter().find_map(|(&key, n)| {
            n.owner.upgrade().and_then(|o| {
                o.routing.get().and_then(|r| {
                    (r.namespace == ns && Arc::ptr_eq(&r.graph, &view.graph)).then_some(key)
                })
            })
        })
    }
    pub(super) fn ethernet_timers(&mut self) {
        let views: Vec<_> = self
            .nodes
            .values()
            .filter_map(|n| n.owner.upgrade())
            .filter_map(|o| o.routing.get().cloned())
            .collect();
        for view in views {
            let actions = view.graph.read().unwrap().ethernet_timers(view.namespace);
            self.queue_frames(&view, actions);
        }
    }
    pub(super) fn pump_ethernet(&mut self) {
        for _ in 0..4096 {
            let Some((view, action)) = self.ethernet.pop_front() else {
                break;
            };
            let outgoing = matches!(&action, Action::Send(..));
            match action {
                Action::Send(ns, index, frame) | Action::Receive(ns, index, frame) => {
                    let actions = view.graph.read().unwrap().ethernet_step(
                        ns,
                        index,
                        frame,
                        outgoing,
                        &mut self.notifications,
                    );
                    self.queue_frames(&view, actions);
                }
                Action::Local(ns, index, frame) => {
                    let (consumed, actions) = view
                        .graph
                        .read()
                        .unwrap()
                        .ethernet_endpoint(ns, index, &frame);
                    self.queue_frames(&view, actions);
                    if !consumed && self.injected.len() < 96 {
                        if let Some(key) = self.node_key(&view, ns) {
                            self.injected.push_back((
                                key,
                                index,
                                frame.source(),
                                frame.payload().to_vec(),
                            ));
                        }
                    }
                }
                Action::External(ns, index, frame) => self.external_frame(view, ns, index, frame),
            }
        }
    }
    fn external_frame(&mut self, view: crate::netdev::View, ns: u64, index: u32, frame: Frame) {
        let Some(source) = self.node_key(&view, ns) else {
            return;
        };
        let gateway_mac = [2, 0x54, 0x72, 0x61, 0, 1];
        if let Some(reply) = crate::netdev::ethernet_gateway(&frame, gateway_mac, v4(1), v6(1)) {
            self.queue_frames(&view, [Action::Receive(ns, index, reply)]);
        }
        if frame.destination() == gateway_mac && matches!(frame.protocol(), 0x0800 | 0x86dd) {
            // The virtual router is an IP endpoint: reassemble real wire fragments
            // before flow lookup. Bridge ports themselves never reassemble frames.
            let rx = &mut self.nodes.get_mut(&source).unwrap().gateway_rx;
            if !rx.receive_packet(frame.payload().to_vec()) {
                return;
            }
            let Some(packet) = rx.rx.pop_front() else {
                return;
            };
            let Some(h) = packet::header(&packet) else {
                return;
            };
            let dst = h.tuple.destination.ip();
            let allowed = self
                .nodes
                .get(&source)
                .and_then(|n| n.owner.upgrade())
                .is_some_and(|o| matches!(o.mode, NetworkMode::Full | NetworkMode::Outbound));
            if !allowed
                || self.external.as_ref().is_some_and(|e| !e.nat)
                    && dst != IpAddr::V4(v4(1))
                    && dst != IpAddr::V6(v6(1))
            {
                return;
            }
            let Some(tuple) = crate::conntrack::key(&packet) else {
                return;
            };
            if self.gateway.route_flow(tuple, tuple, source, view, index) {
                self.gateway
                    .ingress(source, packet, &h, &self.nodes, self.now());
            }
            return;
        }
        if let Some(link) = &mut self.external {
            // Peer discovery is only on flood traffic. Learned unicast avoids filesystem work.
            let known = self.ethernet_switch.lookup(0, frame.destination(), 30000);
            if !frame.multicast() {
                if let Some(id) = known {
                    let path = link.path.parent().unwrap().join(format!("p{id}"));
                    let _ = link.socket.send_to(&frame.0, path);
                    return;
                }
            }
            if let Ok(entries) = std::fs::read_dir(link.path.parent().unwrap()) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path != link.path
                        && entry
                            .file_name()
                            .to_string_lossy()
                            .strip_prefix('p')
                            .is_some_and(|n| {
                                n.parse::<u8>().is_ok_and(|id| (2..=254).contains(&id))
                            })
                    {
                        let _ = link.socket.send_to(&frame.0, path);
                    }
                }
            }
            return;
        }
        self.ethernet_switch
            .learn(0, frame.source(), source as u32, 30000);
        let known = if frame.multicast() {
            None
        } else {
            self.ethernet_switch.lookup(0, frame.destination(), 30000)
        };
        for (&key, n) in &self.nodes {
            if key == source || known.is_some_and(|k| u64::from(k) != key) {
                continue;
            }
            if let Some(target) = n.owner.upgrade().and_then(|o| o.routing.get().cloned()) {
                if self.ethernet.len() >= 1024 {
                    break;
                }
                self.ethernet.push_back((
                    target.clone(),
                    Action::Receive(target.namespace, 2, frame.clone()),
                ));
            }
        }
    }
    pub(super) fn receive_external(&mut self) {
        let Some(link) = &self.external else {
            return;
        };
        let mut packets = Vec::new();
        let mut bytes = [0u8; 65597];
        for _ in 0..64 {
            match link.socket.recv_from(&mut bytes) {
                Ok((n, source)) => {
                    if let Ok(frame) = Frame::new(&bytes[..n]) {
                        let peer = source
                            .as_pathname()
                            .filter(|p| p.parent() == link.path.parent())
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .and_then(|n| n.strip_prefix('p'))
                            .and_then(|n| n.parse::<u32>().ok())
                            .filter(|id| (2..=254).contains(id));
                        if peer.is_none() {
                            continue;
                        }
                        if let Some(peer) = peer {
                            self.ethernet_switch.learn(0, frame.source(), peer, 30000);
                        }
                        packets.push(frame);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        let id = link.id;
        let view = self
            .nodes
            .values()
            .find(|n| n.id == id)
            .and_then(|n| n.owner.upgrade())
            .and_then(|o| o.routing.get().cloned());
        if let Some(view) = view {
            self.queue_frames(
                &view,
                packets
                    .into_iter()
                    .map(|f| Action::Receive(view.namespace, 2, f)),
            );
        }
    }
}
