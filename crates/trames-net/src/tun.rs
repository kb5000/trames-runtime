// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace-owned, single-queue TUN. No host device, worker, or polling thread.
use crate::*;
use parking_lot::Mutex;
use std::collections::VecDeque;
pub const FEATURES: u32 = 1 | 2 | 0x1000; // IFF_TUN | IFF_TAP | IFF_NO_PI
#[derive(Clone, Default)]
pub(crate) struct Binding {
    pub port: std::sync::Weak<Port>,
    pub persistent: bool,
    pub packet_info: bool,
}
pub struct Connection {
    namespace: Arc<netlink::Namespace>,
    port: Mutex<Option<Arc<Port>>>,
    readiness: Arc<trames_shared::Readiness>,
}
pub(crate) struct Port {
    pub index: u32,
    pub(crate) flags: u16,
    location: parking_lot::RwLock<(u64, std::sync::Weak<netlink::Namespace>)>,
    queue: Mutex<Queue>,
    readiness: Arc<trames_shared::Readiness>,
}
#[derive(Default)]
struct Queue {
    packets: VecDeque<(Vec<u8>, u16)>,
    bytes: usize,
    epoch: u64,
}
impl Network {
    pub fn open_tun(&self) -> Arc<Connection> {
        Arc::new(Connection {
            namespace: self.1.clone(),
            port: Mutex::new(None),
            readiness: Arc::default(),
        })
    }
}
impl Connection {
    pub fn attach(&self, name: &[u8], flags: u16, admin: bool) -> Result<Vec<u8>> {
        if !admin {
            return Err(NetError(1));
        }
        if !matches!(flags & 0xf, 1 | 2) || flags & !(FEATURES as u16 | 0x8000) != 0 {
            return Err(NetError(22));
        }
        self.namespace.root_stack()?;
        let mut attached = self.port.lock();
        if attached.is_some() {
            return Err(NetError(17));
        }
        let mut graph = self.namespace.graph.write().unwrap();
        let name = if name.is_empty() || name == b"tun%d" || name == b"tap%d" {
            let prefix = match name {
                b"tun%d" => "tun",
                b"tap%d" => "tap",
                _ if flags & 2 != 0 => "tap",
                _ => "tun",
            };
            graph.automatic_name(self.namespace.id(), prefix, None)?
        } else {
            name.to_vec()
        };
        let ns = self.namespace.id();
        let tap = flags & 2 != 0;
        let index = if let Ok(existing) = graph.named(ns, &name) {
            if flags & 0x8000 != 0 {
                return Err(NetError(16));
            }
            if existing.kind
                != if tap {
                    DeviceKind::Tap
                } else {
                    DeviceKind::Tun
                }
            {
                return Err(NetError(22));
            }
            if graph.tunnel(ns, existing.index).is_some() {
                return Err(NetError(16));
            }
            existing.index
        } else {
            graph.create_tun(ns, &name, tap)?
        };
        let port = Arc::new(Port {
            index,
            flags: flags & !0x8000,
            location: parking_lot::RwLock::new((ns, Arc::downgrade(&self.namespace))),
            queue: Mutex::default(),
            readiness: self.readiness.clone(),
        });
        graph.attach_tun(self.namespace.id(), index, &port);
        let d = graph.device(self.namespace.id(), index)?;
        let data = crate::rtnetlink::link_data(&graph, &d);
        drop(graph);
        *attached = Some(port);
        drop(attached);
        self.namespace
            .notify(vec![(self.namespace.id(), 16, 1, data)]);
        Ok(name)
    }
    pub fn interface(&self) -> Result<(Vec<u8>, u16)> {
        let p = self.port.lock().clone().ok_or(NetError(77))?;
        let graph = self.namespace.graph.read().unwrap();
        let ns = p.location.read().0;
        let name = graph.device_name(ns, p.index).ok_or(NetError(77))?;
        let binding = graph.tun_binding(ns, p.index).ok_or(NetError(77))?;
        // Linux aliases the output-only IFF_NOFILTER with the input IFF_NO_PI.
        Ok((
            name.to_vec(),
            p.flags | 0x1000 | if binding.persistent { 0x0800 } else { 0 },
        ))
    }
    pub fn set_persist(&self, enabled: bool) -> Result<()> {
        let p = self.port.lock().clone().ok_or(NetError(77))?;
        let mut graph = self.namespace.graph.write().unwrap();
        let ns = p.location.read().0;
        if graph.set_tun_persist(ns, p.index, enabled)? {
            let data = crate::rtnetlink::link_data(&graph, &graph.device(ns, p.index)?);
            drop(graph);
            self.namespace.notify(vec![(ns, 16, 1, data)]);
        }
        Ok(())
    }
    pub fn read(&self, count: usize) -> Result<Vec<u8>> {
        let p = self.port.lock().clone().ok_or(NetError(77))?;
        self.namespace.root_stack()?.fabric().tick();
        if self
            .namespace
            .graph
            .read()
            .unwrap()
            .device_name(p.location.read().0, p.index)
            .is_none()
        {
            return Err(NetError(5));
        }
        let mut q = p.queue.lock();
        let (packet, protocol) = q.packets.front().ok_or(NetError(11))?;
        let header = usize::from(p.flags & 0x1000 == 0) * 4;
        if count < header {
            return Err(NetError(22));
        }
        let n = packet.len().min(count - header);
        let mut out = Vec::with_capacity(n + header);
        if header != 0 {
            out.extend_from_slice(&(u16::from(n < packet.len())).to_le_bytes());
            out.extend_from_slice(&protocol.to_be_bytes());
        }
        out.extend_from_slice(&packet[..n]);
        q.bytes -= q.packets.pop_front().unwrap().0.len();
        Ok(out)
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        let p = self.port.lock().clone().ok_or(NetError(77))?;
        let has_pi = p.flags & 0x1000 == 0;
        let packet = if has_pi {
            bytes.get(4..).ok_or(NetError(22))?
        } else {
            bytes
        };
        let tap = p.flags & 2 != 0;
        if tap && packet.len() < 14
            || !tap && !has_pi && !matches!(packet.first().map(|b| b >> 4), Some(4 | 6))
        {
            return Err(NetError(22));
        }
        let namespace = p.location.read().1.upgrade().ok_or(NetError(5))?;
        if tap {
            // TAP takes the protocol from the Ethernet header. The sender supplies
            // frame bytes; packet sockets and the network stack consume them.
            let frame = crate::ethernet::Frame::from_tap(packet)?;
            return match namespace.root_stack()?.inject_frame(p.index, frame, None) {
                Err(NetError(100)) => Err(NetError(5)),
                Err(e) => Err(e),
                Ok(()) => Ok(bytes.len()),
            };
        }
        let protocol = if has_pi {
            u16::from_be_bytes([bytes[2], bytes[3]])
        } else if packet[0] >> 4 == 4 {
            0x0800
        } else {
            0x86dd
        };
        namespace.root_stack()?.inject(p.index, protocol, packet)?;
        Ok(bytes.len())
    }
    pub fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let p = self.port.lock().clone();
        let Some(p) = p else {
            return (8, [0; 2]);
        };
        if let Ok(stack) = self.namespace.root_stack() {
            stack.fabric().tick();
        }
        if self
            .namespace
            .graph
            .read()
            .unwrap()
            .device_name(p.location.read().0, p.index)
            .is_none()
        {
            return (8, [0; 2]);
        }
        let q = p.queue.lock();
        (
            events & (4 | if q.packets.is_empty() { 0 } else { 1 }),
            [q.epoch, 0],
        )
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Option<trames_shared::IoSubscription> {
        Some(self.readiness.subscribe(signal))
    }
}
impl Connection {
    pub fn wait_delay(&self) -> Option<Duration> {
        self.namespace
            .root_stack()
            .ok()
            .map(|s| s.fabric().next_wait())
    }
}
impl Port {
    pub(crate) fn move_to(&self, target: &Arc<netlink::Namespace>) {
        *self.location.write() = (target.id(), Arc::downgrade(target));
    }
    pub(crate) fn readiness(&self) -> Arc<trames_shared::Readiness> {
        self.readiness.clone()
    }
    pub(crate) fn enqueue(
        &self,
        packet: Vec<u8>,
        protocol: u16,
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) -> bool {
        let mut q = self.queue.lock();
        if q.packets.len() >= 500 || q.bytes + packet.len() > MAX_BUFFER {
            return false;
        }
        q.bytes += packet.len();
        q.packets.push_back((packet, protocol));
        q.epoch = q.epoch.wrapping_add(1);
        wakes.push(self.readiness.clone());
        true
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        let Some(port) = self.port.get_mut().take() else {
            return;
        };
        let mut g = self.namespace.graph.write().unwrap();
        let ns = port.location.read().0;
        let remove = g.detach_tun(ns, port.index);
        if let Ok(d) = g.device(ns, port.index) {
            let data = crate::rtnetlink::link_data(&g, &d);
            if remove {
                let _ = g.remove_link(ns, port.index);
            }
            drop(g);
            self.namespace
                .notify(vec![(ns, if remove { 17 } else { 16 }, 1, data)]);
        }
    }
}
