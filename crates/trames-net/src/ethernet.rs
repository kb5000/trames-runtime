// SPDX-License-Identifier: GPL-3.0-or-later
//! Internal Ethernet frames and object-owned switching state; never a host NIC.
use crate::{NetError, Result};
use parking_lot::RwLock;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};
pub(crate) type Mac = [u8; 6];
#[derive(Clone, Debug)]
pub(crate) struct Frame(pub Arc<[u8]>);
impl Frame {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        Self::from_link(bytes, false)
    }
    pub fn from_link(bytes: &[u8], loopback: bool) -> Result<Self> {
        if bytes.len() < 14 || bytes.len() > 65575 + 22 {
            return Err(NetError(22));
        }
        let f = Self(Arc::from(bytes));
        if f.source()[0] & 1 != 0 || (!loopback && f.source() == [0; 6]) {
            return Err(NetError(22));
        }
        if f.outer_protocol() == 0x8100 && bytes.len() < 18 {
            return Err(NetError(22));
        }
        Ok(f)
    }
    pub fn build(source: Mac, destination: Mac, protocol: u16, payload: &[u8]) -> Self {
        let mut v = Vec::with_capacity(14 + payload.len());
        v.extend_from_slice(&destination);
        v.extend_from_slice(&source);
        v.extend_from_slice(&protocol.to_be_bytes());
        v.extend_from_slice(payload);
        Self(v.into())
    }
    pub fn source(&self) -> Mac {
        self.0[6..12].try_into().unwrap()
    }
    pub fn destination(&self) -> Mac {
        self.0[..6].try_into().unwrap()
    }
    pub fn outer_protocol(&self) -> u16 {
        u16::from_be_bytes([self.0[12], self.0[13]])
    }
    pub fn protocol(&self) -> u16 {
        if self.vlan().is_some() {
            u16::from_be_bytes([self.0[16], self.0[17]])
        } else {
            self.outer_protocol()
        }
    }
    pub fn vlan(&self) -> Option<u16> {
        (self.outer_protocol() == 0x8100)
            .then(|| u16::from_be_bytes([self.0[14], self.0[15]]) & 4095)
    }
    pub fn payload(&self) -> &[u8] {
        &self.0[if self.vlan().is_some() { 18 } else { 14 }..]
    }
    pub fn multicast(&self) -> bool {
        self.0[0] & 1 != 0
    }
    pub fn reserved(&self) -> bool {
        self.0[..5] == [1, 0x80, 0xc2, 0, 0] && self.0[5] < 16
    }
    pub fn tagged(&self, vlan: Option<u16>) -> Self {
        if self.vlan() == vlan {
            return self.clone();
        }
        let mut v = Vec::with_capacity(self.payload().len() + 18);
        v.extend_from_slice(&self.0[..12]);
        if let Some(vid) = vlan {
            v.extend_from_slice(&0x8100u16.to_be_bytes());
            let pcp = self
                .vlan()
                .map_or(0, |_| u16::from_be_bytes([self.0[14], self.0[15]]) & 0xf000);
            v.extend_from_slice(&(pcp | vid).to_be_bytes());
        }
        v.extend_from_slice(&self.protocol().to_be_bytes());
        v.extend_from_slice(self.payload());
        Self(v.into())
    }
    pub fn with_payload(&self, payload: &[u8]) -> Self {
        let n = self.0.len() - self.payload().len();
        let mut v = self.0[..n].to_vec();
        v.extend_from_slice(payload);
        Self(v.into())
    }
}
#[derive(Clone)]
pub(crate) struct PortConfig {
    pub state: u8,
    pub hairpin: bool,
    pub learning: bool,
    pub flood: bool,
    pub multicast_flood: bool,
    pub broadcast_flood: bool,
    pub vlans: BTreeMap<u16, u16>,
}
impl Default for PortConfig {
    fn default() -> Self {
        Self {
            state: 3,
            hairpin: false,
            learning: true,
            flood: true,
            multicast_flood: true,
            broadcast_flood: true,
            vlans: BTreeMap::from([(1, 6)]),
        }
    }
}
impl PortConfig {
    pub fn pvid(&self) -> Option<u16> {
        self.vlans
            .iter()
            .find_map(|(v, f)| (f & 2 != 0).then_some(*v))
    }
    pub fn ingress(&self, f: &Frame) -> Option<u16> {
        let vid = f.vlan().filter(|v| *v != 0).or_else(|| self.pvid())?;
        self.vlans.contains_key(&vid).then_some(vid)
    }
    pub fn egress(&self, f: &Frame, vid: u16) -> Option<Frame> {
        let flags = self.vlans.get(&vid)?;
        Some(f.tagged(if flags & 4 != 0 { None } else { Some(vid) }))
    }
    pub fn vlan(&mut self, vid: u16, flags: u16, add: bool) -> Result<()> {
        if !(1..4095).contains(&vid) || flags & !6 != 0 {
            return Err(NetError(22));
        }
        if add {
            if flags & 2 != 0 {
                for f in self.vlans.values_mut() {
                    *f &= !2;
                }
            }
            self.vlans.insert(vid, flags);
        } else if self.vlans.remove(&vid).is_none() {
            return Err(NetError(2));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct BridgeConfig {
    pub vlan_filtering: bool,
    pub ageing: u32,
}
impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            vlan_filtering: false,
            ageing: 30000,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FdbEntry {
    pub mac: Mac,
    pub vlan: u16,
    pub port: u32,
    pub permanent: bool,
    pub local: bool,
}
struct Learned {
    entry: FdbEntry,
    seen: AtomicU64,
}
pub(crate) struct Switch {
    started: Instant,
    fragments: parking_lot::Mutex<BTreeMap<u32, crate::virtualnet::packet::Port>>,
    entries: RwLock<BTreeMap<(u16, Mac), Learned>>,
}
impl Default for Switch {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            fragments: Default::default(),
            entries: RwLock::default(),
        }
    }
}
impl Switch {
    // br_netfilter alone needs IP defragmentation. Ordinary L2 traffic never
    // takes this lock. Caches are bounded by actual bridge input ports.
    pub fn defragment(&self, input: u32, frame: Frame) -> Option<(Frame, bool)> {
        let p = frame.payload();
        let fragmented = match p.first().map(|v| v >> 4) {
            Some(4) if p.len() >= 20 => u16::from_be_bytes([p[6], p[7]]) & 0x3fff != 0,
            Some(6) if p.len() >= 40 => p[6] == 44,
            _ => false,
        };
        if !fragmented {
            return Some((frame, false));
        }
        let mut fragments = self.fragments.lock();
        let rx = fragments.entry(input).or_default();
        if !rx.receive_packet(p.to_vec()) {
            return None;
        }
        rx.rx
            .pop_front()
            .map(|(p, _)| (frame.with_payload(&p), true))
    }
    fn ticks(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64 / 10
    }
    fn live(&self, e: &Learned, ageing: u32) -> bool {
        e.entry.permanent
            || ageing == 0
            || self.ticks().saturating_sub(e.seen.load(Relaxed)) < u64::from(ageing)
    }
    pub fn lookup(&self, vlan: u16, mac: Mac, ageing: u32) -> Option<u32> {
        self.lookup_entry(vlan, mac, ageing).map(|e| e.port)
    }
    pub fn lookup_entry(&self, vlan: u16, mac: Mac, ageing: u32) -> Option<FdbEntry> {
        self.entries
            .read()
            .get(&(vlan, mac))
            .filter(|e| self.live(e, ageing))
            .map(|e| e.entry)
    }
    pub fn learn(&self, vlan: u16, mac: Mac, port: u32, ageing: u32) {
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return;
        }
        {
            let entries = self.entries.read();
            if let Some(e) = entries.get(&(vlan, mac)) {
                if e.entry.permanent {
                    return;
                }
                if e.entry.port == port {
                    e.seen.store(self.ticks(), Relaxed);
                    return;
                }
            }
        }
        let mut entries = self.entries.write();
        entries.retain(|_, e| self.live(e, ageing));
        if entries.len() < 8192 || entries.contains_key(&(vlan, mac)) {
            entries.insert(
                (vlan, mac),
                Learned {
                    entry: FdbEntry {
                        mac,
                        vlan,
                        port,
                        permanent: false,
                        local: false,
                    },
                    seen: AtomicU64::new(self.ticks()),
                },
            );
        }
    }
    pub fn entries(&self, ageing: u32) -> Vec<FdbEntry> {
        self.entries
            .read()
            .values()
            .filter(|e| self.live(e, ageing))
            .map(|e| e.entry)
            .collect()
    }
    pub fn modify(&self, e: FdbEntry, add: bool, flags: u16) -> Result<FdbEntry> {
        if e.mac[0] & 1 != 0 || e.mac == [0; 6] || e.vlan >= 4095 {
            return Err(NetError(22));
        }
        let mut entries = self.entries.write();
        let key = (e.vlan, e.mac);
        if !add {
            return entries.remove(&key).map(|e| e.entry).ok_or(NetError(2));
        }
        if entries.contains_key(&key) && flags & 0x200 != 0 {
            return Err(NetError(17));
        }
        if !entries.contains_key(&key) && flags & 0x400 == 0 {
            return Err(NetError(2));
        }
        entries.insert(
            key,
            Learned {
                entry: e,
                seen: AtomicU64::new(self.ticks()),
            },
        );
        Ok(e)
    }
    pub fn forget(&self, port: u32) {
        self.entries.write().retain(|_, e| e.entry.port != port);
        self.fragments.lock().remove(&port);
    }
}
#[derive(Clone)]
pub(crate) enum Action {
    Send(u64, u32, Frame),
    Receive(u64, u32, Frame),
    Local(u64, u32, Frame),
    External(u64, u32, Frame),
}
#[derive(Default)]
pub(crate) struct NeighborCache {
    pub probing: std::sync::atomic::AtomicBool,
    pub entries: RwLock<BTreeMap<(u32, std::net::IpAddr), Neighbor>>,
}
pub(crate) struct Neighbor {
    pub mac: Option<Mac>,
    pub state: u16,
    pub updated: Instant,
    pub retry: Instant,
    pub probes: u8,
    pub pending: Vec<Vec<u8>>,
}
impl NeighborCache {
    pub fn forget(&self, index: u32) {
        self.entries.write().retain(|(i, _), _| *i != index);
    }
    pub fn learn(&self, index: u32, ip: std::net::IpAddr, mac: Mac) -> Vec<Vec<u8>> {
        if ip.is_unspecified() || ip.is_multicast() || mac[0] & 1 != 0 || mac == [0; 6] {
            return vec![];
        }
        let now = Instant::now();
        let mut entries = self.entries.write();
        let pending = entries
            .remove(&(index, ip))
            .map_or_else(Vec::new, |e| e.pending);
        if entries.len() < 1024 {
            entries.insert(
                (index, ip),
                Neighbor {
                    mac: Some(mac),
                    state: 2,
                    updated: now,
                    retry: now + Duration::from_secs(30),
                    probes: 0,
                    pending: vec![],
                },
            );
        }
        pending
    }
}
