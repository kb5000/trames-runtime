// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace-owned, single-queue TUN. No host device, worker, or polling thread.
use crate::*;
use parking_lot::Mutex;
use std::collections::VecDeque;
pub const FEATURES: u32 = 1 | 2 | 0x1000; // IFF_TUN | IFF_TAP | IFF_NO_PI
pub struct Connection {
    namespace: Arc<netlink::Namespace>,
    port: Mutex<Option<Arc<Port>>>,
    readiness: Arc<trames_shared::Readiness>,
}
pub(crate) struct Port {
    pub index: u32,
    pub(crate) flags: u16,
    queue: Mutex<Queue>,
    readiness: Arc<trames_shared::Readiness>,
}
#[derive(Default)]
struct Queue {
    packets: VecDeque<Vec<u8>>,
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
            return Err(NetError(22));
        }
        let mut graph = self.namespace.graph.write().unwrap();
        let name = if name.is_empty() || name == b"tun%d" || name == b"tap%d" {
            (0..256)
                .map(|n| format!("{}{n}", if flags & 2 != 0 { "tap" } else { "tun" }).into_bytes())
                .find(|name| {
                    graph
                        .devices(self.namespace.id())
                        .iter()
                        .all(|d| d.name != *name)
                })
                .ok_or(NetError(23))?
        } else {
            name.to_vec()
        };
        let index = graph.create_tun(self.namespace.id(), &name, flags & 2 != 0)?;
        let port = Arc::new(Port {
            index,
            flags: flags & !0x8000,
            queue: Mutex::default(),
            readiness: self.readiness.clone(),
        });
        graph.attach_tun(self.namespace.id(), index, Arc::downgrade(&port));
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
        let d = self
            .namespace
            .graph
            .read()
            .unwrap()
            .device(self.namespace.id(), p.index)?;
        Ok((d.name, p.flags))
    }
    pub fn read(&self, count: usize) -> Result<Vec<u8>> {
        let p = self.port.lock().clone().ok_or(NetError(77))?;
        self.namespace.root_stack()?.fabric().tick();
        if self
            .namespace
            .graph
            .read()
            .unwrap()
            .device(self.namespace.id(), p.index)
            .is_err()
        {
            return Err(NetError(5));
        }
        let mut q = p.queue.lock();
        let packet = q.packets.front().ok_or(NetError(11))?;
        let header = usize::from(p.flags & 0x1000 == 0) * 4;
        if count < header {
            return Err(NetError(22));
        }
        let n = packet.len().min(count - header);
        let mut out = Vec::with_capacity(n + header);
        if header != 0 {
            out.extend_from_slice(&(u16::from(n < packet.len())).to_le_bytes());
            out.extend_from_slice(
                &(if p.flags & 2 != 0 {
                    u16::from_be_bytes([packet[12], packet[13]])
                } else if packet[0] >> 4 == 4 {
                    0x0800u16
                } else {
                    0x86dd
                })
                .to_be_bytes(),
            );
        }
        out.extend_from_slice(&packet[..n]);
        q.bytes -= q.packets.pop_front().unwrap().len();
        Ok(out)
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        let p = self.port.lock().clone().ok_or(NetError(77))?;
        if p.flags & 2 != 0 {
            let frame = if p.flags & 0x1000 != 0 {
                bytes
            } else {
                if bytes.len() < 4 {
                    return Err(NetError(22));
                }
                &bytes[4..]
            };
            let frame = crate::ethernet::Frame::new(frame)?;
            if p.flags & 0x1000 == 0 && bytes[2..4] != frame.outer_protocol().to_be_bytes() {
                return Err(NetError(22));
            }
            self.namespace
                .root_stack()?
                .inject_frame(p.index, frame, false)?;
            return Ok(bytes.len());
        }
        let packet = if p.flags & 0x1000 != 0 {
            bytes
        } else {
            if bytes.len() < 4 {
                return Err(NetError(22));
            }
            let proto = u16::from_be_bytes([bytes[2], bytes[3]]);
            if !matches!(
                (proto, bytes.get(4).map(|b| b >> 4)),
                (0x0800, Some(4)) | (0x86dd, Some(6))
            ) {
                return Err(NetError(22));
            }
            &bytes[4..]
        };
        let d = self
            .namespace
            .graph
            .read()
            .unwrap()
            .device(self.namespace.id(), p.index)?;
        if !d.up {
            return Err(NetError(5));
        }
        self.namespace.root_stack()?.inject(p.index, packet)?;
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
            .device(self.namespace.id(), p.index)
            .is_err()
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
    pub(crate) fn readiness(&self) -> Arc<trames_shared::Readiness> {
        self.readiness.clone()
    }
    pub(crate) fn enqueue(
        &self,
        packet: &[u8],
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) -> bool {
        let mut q = self.queue.lock();
        if q.packets.len() >= 500 || q.bytes + packet.len() > MAX_BUFFER {
            return false;
        }
        q.bytes += packet.len();
        q.packets.push_back(packet.to_vec());
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
        if let Ok(d) = g.device(self.namespace.id(), port.index) {
            let data = crate::rtnetlink::link_data(&g, &d);
            let _ = g.remove_link(self.namespace.id(), port.index);
            drop(g);
            self.namespace
                .notify(vec![(self.namespace.id(), 17, 1, data)]);
        }
    }
}
