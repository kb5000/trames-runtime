// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
impl Topology {
    pub fn packet_hub(&self, ns: u64) -> Arc<crate::packet_socket::Hub> {
        self.spaces[&ns].packets.clone()
    }
    pub fn create_tun(&mut self, ns: u64, name: &[u8], tap: bool) -> Result<u32> {
        self.spaces
            .get_mut(&ns)
            .unwrap()
            .tunnels
            .retain(|_, p| p.strong_count() != 0);
        let index = self.new_device(
            ns,
            name,
            if tap {
                DeviceKind::Tap
            } else {
                DeviceKind::Tun
            },
        )?;
        if !tap {
            self.devices.get_mut(&(ns, index)).unwrap().mac = [0; 6];
        }
        Ok(index)
    }
    pub fn attach_tun(&mut self, ns: u64, index: u32, port: std::sync::Weak<crate::tun::Port>) {
        self.spaces
            .get_mut(&ns)
            .unwrap()
            .tunnels
            .insert(index, port);
    }
    pub fn tunnel(&self, ns: u64, index: u32) -> Option<Arc<crate::tun::Port>> {
        self.spaces.get(&ns)?.tunnels.get(&index)?.upgrade()
    }
    pub fn observe(
        &self,
        ns: u64,
        index: u32,
        peer: [u8; 6],
        packet: &[u8],
        outgoing: bool,
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) {
        if !self.spaces[&ns].packets.active() {
            return;
        }
        let Some(d) = self.devices.get(&(ns, index)) else {
            return;
        };
        let peer = if peer == [0; 6] && outgoing {
            crate::conntrack::key(packet)
                .and_then(|key| {
                    self.source(ns, key.tuple.destination.ip())
                        .ok()
                        .and_then(|(_, _, gateway)| {
                            self.resolve_neighbor_path(
                                ns,
                                index,
                                gateway.unwrap_or(key.tuple.destination.ip()),
                            )
                        })
                })
                .and_then(|(key, _)| self.devices.get(&key).map(|d| d.mac))
                .unwrap_or(peer)
        } else {
            peer
        };
        self.spaces[&ns].packets.observe(
            &d.snapshot(),
            if outgoing {
                [d.mac, peer]
            } else {
                [peer, d.mac]
            },
            packet,
            outgoing,
            wakes,
        );
    }
    pub fn link_wakes(&self, ns: u64, index: u32, wakes: &mut Vec<Arc<trames_shared::Readiness>>) {
        if let Some(space) = self.spaces.get(&ns) {
            space.packets.link_wakes(wakes);
            if let Some(port) = space.tunnels.get(&index).and_then(std::sync::Weak::upgrade) {
                wakes.push(port.readiness());
            }
        }
    }
}
