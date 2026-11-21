// SPDX-License-Identifier: GPL-3.0-or-later
//! AF_PACKET on guest-owned IP-fabric links. Native host sockets are not taps.
use crate::*;
use parking_lot::Mutex;
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        Weak,
    },
};
#[derive(Default)]
pub(crate) struct Hub {
    active: AtomicUsize,
    sockets: Mutex<Vec<Weak<Receiver>>>,
}
impl Hub {
    pub fn link_wakes(&self, wakes: &mut Vec<Arc<trames_shared::Readiness>>) {
        wakes.extend(
            self.sockets
                .lock()
                .iter()
                .filter_map(Weak::upgrade)
                .map(|r| r.readiness.clone()),
        );
    }
    pub fn active(&self) -> bool {
        self.active.load(Relaxed) != 0
    }
    pub fn observe(
        &self,
        device: &Device,
        macs: [[u8; 6]; 2],
        packet: &[u8],
        outgoing: bool,
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) {
        if !self.active() {
            return;
        }
        let protocol = match packet.first().map(|b| b >> 4) {
            Some(4) => 0x0800,
            Some(6) => 0x86dd,
            _ => return,
        };
        self.observe_wire(
            device,
            &crate::ethernet::Frame::build(macs[0], macs[1], protocol, packet),
            outgoing,
            wakes,
        );
    }
    pub fn observe_wire(
        &self,
        device: &Device,
        frame: &crate::ethernet::Frame,
        outgoing: bool,
        wakes: &mut Vec<Arc<trames_shared::Readiness>>,
    ) {
        if !self.active() {
            return;
        }
        let protocol = frame.outer_protocol();
        let kind = if outgoing {
            4
        } else if frame.destination() == [255; 6] {
            1
        } else if frame.multicast() {
            2
        } else if frame.destination() != device.mac {
            3
        } else {
            0
        };
        let sockets: Vec<_> = self
            .sockets
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for socket in sockets {
            let mut state = socket.state.lock();
            if state.protocol == 0
                || state.protocol != 3 && state.protocol != protocol
                || state.index != 0 && state.index != device.index
                || outgoing && state.ignore_outgoing
                || kind == 3
                    && !state
                        .memberships
                        .keys()
                        .any(|(i, k, _)| *i == device.index && *k == 1)
            {
                continue;
            }
            let bytes = if device.kind == DeviceKind::Tun || socket.kind == 2 {
                &frame.0[14..]
            } else {
                &frame.0[..]
            };
            let length = state
                .filter
                .as_ref()
                .map_or(bytes.len(), |p| p.run(bytes).min(bytes.len()));
            if length == 0 {
                continue;
            }
            if state.bytes + length > state.buffer || state.queue.len() >= 1024 {
                state.dropped = state.dropped.wrapping_add(1);
                continue;
            }
            let data = bytes[..length].to_vec();
            state.bytes += length;
            state.packets = state.packets.wrapping_add(1);
            state.epoch = state.epoch.wrapping_add(1);
            let mut source = address(device.index, protocol, kind, frame.source());
            if device.kind == DeviceKind::Tun {
                source[8..10].copy_from_slice(&65534u16.to_le_bytes());
                source[11] = 0;
            }
            if device.kind == DeviceKind::Loopback {
                source[8..10].copy_from_slice(&772u16.to_le_bytes());
            }
            state.queue.push_back((data, source));
            wakes.push(socket.readiness.clone());
        }
    }
}
struct State {
    memberships: std::collections::BTreeMap<(u32, u16, [u8; 6]), u32>,
    index: u32,
    protocol: u16,
    queue: VecDeque<(Vec<u8>, [u8; 20])>,
    bytes: usize,
    buffer: usize,
    epoch: u64,
    filter: Option<crate::socket_filter::Program>,
    locked: bool,
    ignore_outgoing: bool,
    packets: u32,
    dropped: u32,
}
pub(crate) struct Receiver {
    kind: u32,
    state: Mutex<State>,
    readiness: Arc<trames_shared::Readiness>,
}
pub(super) struct Socket {
    namespace: Arc<netlink::Namespace>,
    kind: u32,
    hub: Arc<Hub>,
    receiver: Arc<Receiver>,
}
impl std::ops::Deref for Socket {
    type Target = Receiver;
    fn deref(&self) -> &Receiver {
        &self.receiver
    }
}
pub(crate) fn address(index: u32, protocol: u16, kind: u8, mac: [u8; 6]) -> [u8; 20] {
    let mut a = [0; 20];
    a[..2].copy_from_slice(&17u16.to_le_bytes());
    a[2..4].copy_from_slice(&protocol.to_be_bytes());
    a[4..8].copy_from_slice(&index.to_le_bytes());
    a[8..10].copy_from_slice(&1u16.to_le_bytes());
    a[10] = kind;
    a[11] = 6;
    a[12..18].copy_from_slice(&mac);
    a
}
fn decode(a: &[u8]) -> Result<(u32, u16)> {
    if a.len() < 20 {
        return Err(NetError(22));
    }
    if a[..2] != 17u16.to_le_bytes() {
        return Err(NetError(97));
    }
    let index = i32::from_le_bytes(a[4..8].try_into().unwrap());
    if index < 0 {
        return Err(NetError(22));
    }
    Ok((
        index as u32,
        u16::from_be_bytes(a[2..4].try_into().unwrap()),
    ))
}
impl Socket {
    pub fn new(namespace: Arc<netlink::Namespace>, kind: u32, protocol: u32) -> Result<Arc<Self>> {
        if !matches!(kind, 2 | 3) {
            return Err(NetError(94));
        }
        if protocol > 65535 {
            return Err(NetError(22));
        }
        namespace.root_stack()?;
        let hub = namespace.graph.read().unwrap().packet_hub(namespace.id());
        let socket = Arc::new(Self {
            namespace,
            kind,
            hub: hub.clone(),
            receiver: Arc::new(Receiver {
                kind,
                state: Mutex::new(State {
                    memberships: Default::default(),
                    index: 0,
                    protocol: (protocol as u16).swap_bytes(),
                    queue: VecDeque::new(),
                    bytes: 0,
                    buffer: MAX_BUFFER,
                    epoch: 0,
                    filter: None,
                    locked: false,
                    ignore_outgoing: false,
                    packets: 0,
                    dropped: 0,
                }),
                readiness: Arc::default(),
            }),
        });
        let mut registry = hub.sockets.lock();
        registry.retain(|s| s.strong_count() != 0);
        registry.push(Arc::downgrade(&socket.receiver));
        hub.active.fetch_add(1, Relaxed);
        drop(registry);
        Ok(socket)
    }
    pub fn bind_bytes(&self, a: &[u8]) -> Result<()> {
        let (index, protocol) = decode(a)?;
        if index != 0 {
            let d = self
                .namespace
                .graph
                .read()
                .unwrap()
                .device(self.namespace.id(), index)?;
            if d.kind == DeviceKind::Direct {
                return Err(NetError(95));
            }
        }
        let mut s = self.state.lock();
        s.index = index;
        s.protocol = protocol;
        Ok(())
    }
    pub fn local_bytes(&self) -> Result<Vec<u8>> {
        let (index, protocol) = {
            let s = self.state.lock();
            (s.index, s.protocol)
        };
        let d = self
            .namespace
            .graph
            .read()
            .unwrap()
            .device(self.namespace.id(), index)
            .ok();
        let mut a = address(index, protocol, 0, d.as_ref().map_or([0; 6], |d| d.mac));
        if let Some(d) = d {
            if d.kind == DeviceKind::Tun {
                a[8..10].copy_from_slice(&65534u16.to_le_bytes());
                a[11] = 0;
            }
        }
        Ok(a.to_vec())
    }
    pub fn send_bytes(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
    ) -> Result<usize> {
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        let (index, protocol) = if let Some(a) = destination {
            decode(a)?
        } else {
            let s = self.state.lock();
            (s.index, s.protocol)
        };
        let device = self
            .namespace
            .graph
            .read()
            .unwrap()
            .device(self.namespace.id(), index)?;
        if matches!(
            device.kind,
            DeviceKind::Direct | DeviceKind::Tun | DeviceKind::Loopback
        ) {
            return Err(NetError(95));
        }
        let frame = if self.kind == 3 {
            crate::ethernet::Frame::new(bytes)?
        } else {
            let a = destination.ok_or(NetError(89))?;
            if a[11] != 6 {
                return Err(NetError(22));
            }
            crate::ethernet::Frame::build(
                device.mac,
                a[12..18].try_into().unwrap(),
                protocol,
                bytes,
            )
        };
        self.namespace
            .root_stack()?
            .inject_frame(index, frame, true)?;
        Ok(bytes.len())
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Received> {
        if flags & !(MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT) != 0 {
            return Err(NetError(95));
        }
        self.namespace.root_stack()?.fabric().tick();
        let mut s = self.state.lock();
        let (packet, address) = s.queue.front().ok_or(NetError(11))?;
        let n = count.min(packet.len());
        let result = Received {
            netlink_address: None,
            packet_address: Some(*address),
            credentials: None,
            ip: Default::default(),
            packet_info: None,
            data: packet[..n].to_vec(),
            address: None,
            length: if flags & MSG_TRUNC != 0 {
                packet.len()
            } else {
                n
            },
            truncated: n < packet.len(),
        };
        if flags & MSG_PEEK == 0 {
            s.bytes -= s.queue.pop_front().unwrap().0.len();
        }
        Ok(result)
    }
    pub fn poll(&self, events: u16) -> Result<u16> {
        self.namespace.root_stack()?.fabric().tick();
        let (index, ready) = {
            let s = self.state.lock();
            (s.index, 4 | if s.queue.is_empty() { 0 } else { 1 })
        };
        if index != 0
            && self
                .namespace
                .graph
                .read()
                .unwrap()
                .device(self.namespace.id(), index)
                .is_err()
        {
            return Ok(8);
        }
        Ok(events & ready)
    }
    pub fn wait_delay(&self) -> Option<Duration> {
        self.namespace
            .root_stack()
            .ok()
            .map(|s| s.fabric().next_wait())
    }
    pub fn poll_epoch(&self) -> [u64; 2] {
        [self.state.lock().epoch, 0]
    }
    pub fn subscribe(&self, s: &Arc<trames_shared::IoSignal>) -> trames_shared::IoSubscription {
        self.readiness.subscribe(s)
    }
    pub fn set_filter(&self, bytes: Option<&[u8]>) -> Result<()> {
        let mut s = self.state.lock();
        if s.locked {
            return Err(NetError(1));
        }
        let filter = bytes.map(crate::socket_filter::Program::new).transpose()?;
        if filter.is_none() && s.filter.is_none() {
            return Err(NetError(2));
        }
        s.filter = filter;
        Ok(())
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, bytes: &[u8]) -> Result<()> {
        if level == 263 && matches!(name, 1 | 2) {
            if bytes.len() < 16 {
                return Err(NetError(22));
            }
            let index = u32::from_le_bytes(bytes[..4].try_into().unwrap());
            let kind = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
            let len = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
            self.namespace
                .graph
                .read()
                .unwrap()
                .device(self.namespace.id(), index)?;
            if !matches!(kind, 0..=2) || kind == 0 && len != 6 {
                return Err(NetError(22));
            }
            let key = (index, kind, bytes[8..14].try_into().unwrap());
            let mut s = self.state.lock();
            if name == 1 {
                *s.memberships.entry(key).or_default() += 1;
            } else {
                let n = s.memberships.get_mut(&key).ok_or(NetError(99))?;
                *n -= 1;
                if *n == 0 {
                    s.memberships.remove(&key);
                }
            }
            return Ok(());
        }

        if level == 1 && name == 27 {
            return self.set_filter(None);
        }
        if bytes.len() < 4 {
            return Err(NetError(22));
        }
        self.set_option(
            level,
            name,
            i32::from_le_bytes(bytes[..4].try_into().unwrap()),
        )
    }
    pub fn set_option(&self, level: u32, name: u32, value: i32) -> Result<()> {
        let mut s = self.state.lock();
        match (level, name) {
            (1, 8) => s.buffer = (value.max(128) as usize).saturating_mul(2).min(MAX_BUFFER),
            (1, 44) if !s.locked || value != 0 => s.locked = value != 0,
            (1, 44) => return Err(NetError(1)),
            (263, 23) => s.ignore_outgoing = value != 0,
            _ => return Err(NetError(92)),
        }
        Ok(())
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        let s = self.state.lock();
        match (level, name) {
            (1, 3) => Ok(self.kind as i32),
            (1, 4) => Ok(0),
            (1, 8) => Ok(s.buffer as i32),
            (1, 39) => Ok(17),
            (1, 44) => Ok(i32::from(s.locked)),
            (263, 23) => Ok(i32::from(s.ignore_outgoing)),
            _ => Err(NetError(92)),
        }
    }
    pub fn address_size(&self) -> usize {
        20
    }
    pub fn bind(&self, _: SocketAddr) -> Result<()> {
        Err(NetError(97))
    }
    pub fn listen(&self, _: u32) -> Result<()> {
        Err(NetError(95))
    }
    pub fn connect(&self, _: SocketAddr) -> Result<()> {
        Err(NetError(95))
    }
    pub fn connect_complete(&self) -> Result<bool> {
        Err(NetError(95))
    }
    pub fn resume_connect(&self) -> Result<bool> {
        Err(NetError(95))
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Err(NetError(97))
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Err(NetError(95))
    }
    pub fn shutdown(&self, _: u32) -> Result<()> {
        Err(NetError(95))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.hub.active.fetch_sub(1, Relaxed);
    }
}
