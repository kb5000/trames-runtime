// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
impl Topology {
    pub fn packet_hub(&self, ns: u64) -> Arc<crate::packet_socket::Hub> {
        self.spaces[&ns].packets.clone()
    }
    pub fn create_tun(&mut self, ns: u64, name: &[u8], tap: bool) -> Result<u32> {
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
    pub fn attach_tun(&mut self, ns: u64, index: u32, port: &Arc<crate::tun::Port>) {
        let binding = self
            .spaces
            .get_mut(&ns)
            .unwrap()
            .tunnels
            .entry(index)
            .or_default();
        binding.port = Arc::downgrade(port);
        binding.packet_info = port.flags & 0x1000 == 0;
    }
    pub fn tun_binding(&self, ns: u64, index: u32) -> Option<&crate::tun::Binding> {
        self.spaces.get(&ns)?.tunnels.get(&index)
    }
    pub fn set_tun_persist(&mut self, ns: u64, index: u32, enabled: bool) -> Result<bool> {
        if !self.devices.contains_key(&(ns, index)) {
            return Err(NetError(77));
        }
        let binding = self
            .spaces
            .get_mut(&ns)
            .and_then(|s| s.tunnels.get_mut(&index))
            .ok_or(NetError(77))?;
        Ok(std::mem::replace(&mut binding.persistent, enabled) != enabled)
    }
    pub fn detach_tun(&mut self, ns: u64, index: u32) -> bool {
        let exists = self.devices.contains_key(&(ns, index));
        let Some(space) = self.spaces.get_mut(&ns) else {
            return false;
        };
        if let Some(binding) = space.tunnels.get_mut(&index) {
            if exists && binding.persistent {
                binding.port = Default::default();
                return false;
            }
        }
        space.tunnels.remove(&index);
        exists
    }
    pub fn tunnel(&self, ns: u64, index: u32) -> Option<Arc<crate::tun::Port>> {
        self.tun_binding(ns, index)?.port.upgrade()
    }
    pub fn transmit_tun(
        &self,
        ns: u64,
        index: u32,
        packet: Vec<u8>,
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) -> bool {
        let Some(port) = self.tunnel(ns, index) else {
            return false;
        };
        let Ok(mtu) = self.link_mtu(ns, index) else {
            return false;
        };
        let protocol = if packet[0] >> 4 == 4 { 0x0800 } else { 0x86dd };
        if packet.len() <= mtu as usize {
            return port.enqueue(packet, protocol, wakes);
        }
        let serial = self.spaces[&ns].ip_serial.fetch_add(1, Relaxed) as u32;
        crate::virtualnet::packet::fragment_link(packet, mtu as usize, serial).is_some_and(
            |fragments| {
                fragments
                    .into_iter()
                    .all(|p| port.enqueue(p, protocol, wakes))
            },
        )
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
    pub fn observe_local_loopback(
        &self,
        ns: u64,
        packet: &[u8],
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) {
        let hub = &self.spaces[&ns].packets;
        if !hub.active() {
            return;
        }
        let protocol = match packet.first().map(|b| b >> 4) {
            Some(4) => 0x0800,
            Some(6) => 0x86dd,
            _ => return,
        };
        let device = self.devices[&(ns, 1)].snapshot();
        let frame = crate::ethernet::Frame::build(device.mac, device.mac, protocol, packet);
        hub.observe_wire(&device, &frame, true, wakes);
        hub.observe_wire(&device, &frame, false, wakes);
    }
    pub fn link_wakes(&self, ns: u64, index: u32, wakes: &mut Vec<Arc<trames_shared::Readiness>>) {
        if let Some(space) = self.spaces.get(&ns) {
            space.packets.link_wakes(wakes);
            if let Some(port) = self.tunnel(ns, index) {
                wakes.push(port.readiness());
            }
        }
    }
}
