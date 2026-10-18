// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace-local bounded connection tracking and reversible packet NAT.
#[path = "conntrack_icmp.rs"]
mod icmp;
use crate::virtualnet::packet::{self, Tuple};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Key {
    pub protocol: u8,
    pub tuple: Tuple,
}
impl Key {
    pub fn reverse(self) -> Self {
        Self {
            protocol: self.protocol,
            tuple: Tuple {
                source: self.tuple.destination,
                destination: self.tuple.source,
            },
        }
    }
}
pub(crate) fn key(p: &[u8]) -> Option<Key> {
    let h = packet::header(p)?;
    if !h.first {
        return None;
    }
    let mut tuple = h.tuple;
    if matches!(h.protocol, 1 | 58) {
        let b = p.get(h.offset..h.offset + 8)?;
        let id = u16::from_be_bytes([b[4], b[5]]);
        match b[0] {
            8 | 128 => tuple.source.set_port(id),
            0 | 129 => tuple.destination.set_port(id),
            _ if h.protocol == 1 && matches!(b[0], 3 | 11 | 12)
                || h.protocol == 58 && matches!(b[0], 1..=4) => {}
            _ => return None,
        }
    }
    Some(Key {
        protocol: h.protocol,
        tuple,
    })
}
pub(crate) fn rewrite(p: &mut [u8], k: Key) -> bool {
    let Some(h) = packet::header(p) else {
        return false;
    };
    let (src, dst) = (k.tuple.source.ip(), k.tuple.destination.ip());
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) if p[0] >> 4 == 4 => {
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) if p[0] >> 4 == 6 => {
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
        }
        _ => return false,
    }
    if matches!(h.protocol, 6 | 17) {
        let b = &mut p[h.offset..];
        if b.len() < if h.protocol == 6 { 20 } else { 8 } {
            return false;
        }
        b[..2].copy_from_slice(&k.tuple.source.port().to_be_bytes());
        b[2..4].copy_from_slice(&k.tuple.destination.port().to_be_bytes());
        let (s, d) = (
            smoltcp::wire::IpAddress::from(src),
            smoltcp::wire::IpAddress::from(dst),
        );
        if h.protocol == 6 {
            smoltcp::wire::TcpPacket::new_unchecked(b).fill_checksum(&s, &d);
        } else {
            smoltcp::wire::UdpPacket::new_unchecked(b).fill_checksum(&s, &d);
        }
    } else if matches!(h.protocol, 1 | 58) {
        let b = &mut p[h.offset..];
        if b.len() < 8 {
            return false;
        }
        let id = if matches!(b[0], 8 | 128) {
            k.tuple.source.port()
        } else {
            k.tuple.destination.port()
        };
        if matches!(b[0], 0 | 8 | 128 | 129) {
            b[4..6].copy_from_slice(&id.to_be_bytes());
        }
        if h.protocol == 1 {
            smoltcp::wire::Icmpv4Packet::new_unchecked(b).fill_checksum();
        } else if let (IpAddr::V6(s), IpAddr::V6(d)) = (src, dst) {
            smoltcp::wire::Icmpv6Packet::new_unchecked(b).fill_checksum(&s, &d);
        }
    }
    if p[0] >> 4 == 4 {
        smoltcp::wire::Ipv4Packet::new_unchecked(p).fill_checksum();
    }
    true
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Track {
    pub id: u64,
    pub zone: u16,
    pub reply: bool,
    pub state: u32,
    pub status: u32,
    pub mark: u32,
    pub original: Key,
    pub translated: Key,
    pub fresh: bool,
    pub dnat_done: bool,
    pub snat_done: bool,
    pub closing: bool,
    pub related: bool,
}
impl Track {
    pub fn untracked(k: Key, zone: u16) -> Self {
        Self {
            id: 0,
            zone,
            reply: false,
            state: 64,
            status: 0,
            mark: 0,
            original: k,
            translated: k,
            fresh: false,
            dnat_done: false,
            snat_done: false,
            closing: false,
            related: false,
        }
    }
    pub fn load(&self, key: u32, direction: u8) -> Option<Vec<u8>> {
        let k = if direction == 0 {
            self.original
        } else {
            self.translated.reverse()
        };
        Some(match key {
            0 => self.state.to_le_bytes().to_vec(),
            1 => vec![u8::from(self.reply)],
            2 => self.status.to_le_bytes().to_vec(),
            3 => self.mark.to_le_bytes().to_vec(),
            7 => vec![if k.tuple.source.is_ipv4() { 2 } else { 10 }],
            10 => vec![k.protocol],
            11 => k.tuple.source.port().to_be_bytes().to_vec(),
            12 => k.tuple.destination.port().to_be_bytes().to_vec(),
            17 => self.zone.to_le_bytes().to_vec(),
            8 | 19 | 21 => match k.tuple.source.ip() {
                IpAddr::V4(v) => v.octets().to_vec(),
                IpAddr::V6(v) => v.octets().to_vec(),
            },
            9 | 20 | 22 => match k.tuple.destination.ip() {
                IpAddr::V4(v) => v.octets().to_vec(),
                IpAddr::V6(v) => v.octets().to_vec(),
            },
            23 => (self.id as u32).to_le_bytes().to_vec(),
            _ => return None,
        })
    }
}
#[derive(Clone)]
struct Entry {
    track: Track,
    expires: Instant,
    seen_reply: bool,
}
#[derive(Clone, Default)]
pub(crate) struct State {
    next: u64,
    next_sweep: Option<Instant>,
    entries: BTreeMap<u64, Entry>,
    index: BTreeMap<(u16, Key), (u64, bool)>,
}
impl State {
    fn remove(&mut self, id: u64) {
        self.entries.remove(&id);
        self.index.retain(|_, v| v.0 != id);
    }
    pub fn begin(&mut self, p: &[u8], zone: u16) -> Option<Track> {
        let k = key(p)?;
        let now = Instant::now();
        if self.next_sweep.is_none_or(|deadline| now >= deadline) {
            let expired: Vec<_> = self
                .entries
                .iter()
                .filter(|(_, e)| e.expires <= now)
                .map(|(&id, _)| id)
                .collect();
            for id in expired {
                self.remove(id);
            }
            self.next_sweep = Some(now + Duration::from_secs(1));
        }
        if let Some((_, quoted)) = icmp::error(p) {
            let matched = self
                .index
                .get(&(zone, quoted))
                .map(|&(id, reply)| (id, !reply))
                .or_else(|| self.index.get(&(zone, quoted.reverse())).copied());
            if let Some((id, reply)) = matched {
                let mut t = self.entries.get(&id)?.track;
                t.reply = reply;
                t.related = true;
                t.state = 4;
                t.fresh = false;
                return Some(t);
            }
            let mut invalid = Track::untracked(k, zone);
            invalid.state = 1;
            return Some(invalid);
        }
        let closing = packet::header(p)
            .is_some_and(|h| h.protocol == 6 && p.get(h.offset + 13).is_some_and(|f| f & 5 != 0));
        if let Some(&(id, reply)) = self.index.get(&(zone, k)) {
            let entry = self.entries.get_mut(&id)?;
            let mut t = entry.track;
            t.reply = reply;
            t.fresh = false;
            t.closing |= closing;
            t.state = if reply || entry.seen_reply { 2 } else { 8 };
            if reply {
                t.status |= 2;
            }
            return Some(t);
        }
        if self.entries.len() >= 512 {
            return None;
        }
        if !matches!(k.protocol, 1 | 6 | 17 | 58) {
            return Some(Track::untracked(k, zone));
        }
        self.next = self.next.wrapping_add(1).max(1);
        let mut t = Track::untracked(k, zone);
        t.id = self.next;
        t.fresh = true;
        t.state = 8;
        t.closing = closing;
        self.entries.insert(
            t.id,
            Entry {
                track: t,
                expires: now + Duration::from_secs(10),
                seen_reply: false,
            },
        );
        self.index.insert((zone, k), (t.id, false));
        Some(t)
    }
    pub fn existing_nat(&self, t: &mut Track, p: &mut [u8], source: bool) -> bool {
        if t.related {
            return icmp::translate(p, t, source);
        }
        let Some(mut k) = key(p) else {
            return true;
        };
        if source {
            if t.reply && t.status & 32 != 0 {
                k.tuple.source = t.original.tuple.destination;
            } else if !t.reply && t.status & 16 != 0 {
                k.tuple.source = t.translated.tuple.source;
            }
        } else if t.reply && t.status & 16 != 0 {
            k.tuple.destination = t.original.tuple.source;
        } else if !t.reply && t.status & 32 != 0 {
            k.tuple.destination = t.translated.tuple.destination;
        }
        rewrite(p, k)
    }
    pub fn nat(
        &mut self,
        t: &mut Track,
        p: &mut [u8],
        source: bool,
        ip: Option<IpAddr>,
        ports: Option<(u16, u16)>,
    ) -> bool {
        if t.id == 0 || t.reply || t.related {
            return false;
        }
        let Some(mut k) = key(p) else {
            return false;
        };
        let original = if source {
            k.tuple.source
        } else {
            k.tuple.destination
        };
        let mut endpoint = SocketAddr::new(ip.unwrap_or(original.ip()), original.port());
        if endpoint.is_ipv4() != original.is_ipv4() {
            return false;
        }
        if let Some((low, high)) = ports {
            if low == 0 || low > high {
                return false;
            }
            endpoint.set_port(low);
        }
        if source {
            let (low, high) = ports.unwrap_or((32768, 60999));
            let initial = endpoint.port();
            let mut found = false;
            for i in 0..=u32::from(high - low) + 1 {
                if i != 0 {
                    endpoint.set_port(low + ((i - 1) % (u32::from(high - low) + 1)) as u16);
                }
                k.tuple.source = endpoint;
                let conflict = self
                    .index
                    .get(&(t.zone, k.reverse()))
                    .is_some_and(|v| v.0 != t.id);
                if !conflict {
                    found = true;
                    break;
                }
                if initial == 0 && i == 0 {
                    continue;
                }
            }
            if !found {
                return false;
            }
            t.translated.tuple.source = endpoint;
            t.status |= 16;
        } else {
            k.tuple.destination = endpoint;
            t.translated.tuple.destination = endpoint;
            t.status |= 32;
        }
        if self
            .index
            .get(&(t.zone, t.translated.reverse()))
            .is_some_and(|v| v.0 != t.id)
        {
            return false;
        }
        if !rewrite(p, k) {
            return false;
        }
        self.index.retain(|_, v| v.0 != t.id || !v.1);
        self.index
            .insert((t.zone, t.translated.reverse()), (t.id, true));
        true
    }
    pub fn finish(&mut self, t: Track, accepted: bool) {
        if t.id == 0 || t.related {
            return;
        }
        if !accepted {
            if t.fresh {
                self.remove(t.id);
            }
            return;
        }
        let Some(e) = self.entries.get_mut(&t.id) else {
            return;
        };
        let mut saved = t;
        saved.reply = false;
        saved.fresh = false;
        if accepted {
            saved.status |= 8;
            e.seen_reply |= t.reply;
        }
        e.track = saved;
        e.expires = Instant::now()
            + Duration::from_secs(if t.closing {
                10
            } else if e.seen_reply {
                300
            } else {
                60
            });
        self.index.insert((t.zone, t.original), (t.id, false));
        self.index
            .insert((t.zone, t.translated.reverse()), (t.id, true));
    }
    pub fn records(&self) -> Vec<(Track, u32)> {
        let now = Instant::now();
        self.entries
            .values()
            .filter(|e| e.expires > now)
            .map(|e| {
                (
                    e.track,
                    e.expires
                        .saturating_duration_since(now)
                        .as_secs()
                        .min(u32::MAX as u64) as u32,
                )
            })
            .collect()
    }
    pub fn delete(&mut self, id: u64) {
        self.remove(id);
    }
    pub fn remove_addresses(&mut self, ips: &[IpAddr]) {
        let ids: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                [
                    e.track.original.tuple.source.ip(),
                    e.track.original.tuple.destination.ip(),
                    e.track.translated.tuple.source.ip(),
                    e.track.translated.tuple.destination.ip(),
                ]
                .iter()
                .any(|a| ips.contains(a))
            })
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            self.remove(id);
        }
    }
}
/// Logical IP message for native socket policy checks and route selection.
/// BSD owns actual TCP sequencing; payload/tuple/state filtering stays guest-owned.
pub(crate) fn message(
    source: SocketAddr,
    destination: SocketAddr,
    protocol: u8,
    flags: u8,
    body: &[u8],
) -> Vec<u8> {
    let n = if protocol == 6 {
        20
    } else if protocol == 17 {
        8
    } else {
        0
    };
    let offset = if source.is_ipv4() { 20 } else { 40 };
    let size = (offset + n + body.len()).min(if source.is_ipv4() { 65535 } else { 65575 });
    let mut p = vec![0; size];
    if source.is_ipv4() {
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        p[8] = 64;
        p[9] = protocol;
    } else {
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((size - 40) as u16).to_be_bytes());
        p[6] = protocol;
        p[7] = 64;
    }
    if protocol == 6 {
        p[offset + 12] = 0x50;
        p[offset + 13] = flags;
        p[offset + 14..offset + 16].copy_from_slice(&65535u16.to_be_bytes());
    } else if protocol == 17 {
        p[offset + 4..offset + 6].copy_from_slice(&((size - offset) as u16).to_be_bytes());
    }
    p[offset + n..].copy_from_slice(&body[..size - offset - n]);
    if source.is_ipv4() {
        smoltcp::wire::Ipv4Packet::new_unchecked(&mut p).fill_checksum();
    }
    let mut k = Key {
        protocol,
        tuple: Tuple {
            source,
            destination,
        },
    };
    if matches!(protocol, 1 | 58) {
        if let Some(icmp) = key(&p) {
            k.tuple.source.set_port(icmp.tuple.source.port());
            k.tuple.destination.set_port(icmp.tuple.destination.port());
        }
    }
    rewrite(&mut p, k);
    p
}
#[cfg(test)]
mod tests {
    use super::*;
    fn endpoints(v6: bool) -> (SocketAddr, SocketAddr, IpAddr, IpAddr) {
        if v6 {
            (
                "[fd01::2]:40000".parse().unwrap(),
                "[2001:db8::1]:53".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                "fd01::3".parse().unwrap(),
            )
        } else {
            (
                "172.28.0.2:40000".parse().unwrap(),
                "198.18.0.1:53".parse().unwrap(),
                "192.0.2.1".parse().unwrap(),
                "172.28.0.3".parse().unwrap(),
            )
        }
    }
    #[test]
    fn both_families_preserve_reversible_bindings_and_zone_isolation() {
        for v6 in [false, true] {
            for protocol in [6, 17, if v6 { 58 } else { 1 }] {
                let (s, d, public, backend) = endpoints(v6);
                let mut body = vec![0; 12];
                body[0] = if v6 { 128 } else { 8 };
                body[4..6].copy_from_slice(&40000u16.to_be_bytes());
                let mut p = message(
                    s,
                    d,
                    protocol,
                    2,
                    if matches!(protocol, 1 | 58) {
                        &body
                    } else {
                        b"data"
                    },
                );
                let original = key(&p).unwrap();
                let mut state = State::default();
                let mut t = state.begin(&p, 7).unwrap();
                assert_eq!(t.state, 8);
                assert!(state.nat(
                    &mut t,
                    &mut p,
                    false,
                    Some(backend),
                    if matches!(protocol, 1 | 58) {
                        None
                    } else {
                        Some((1234, 1234))
                    }
                ));
                assert!(state.nat(&mut t, &mut p, true, Some(public), Some((45000, 45000))));
                assert!(packet::valid_transport(&p));
                state.finish(t, true);
                let translated = key(&p).unwrap();
                let mut reply_body = body.clone();
                reply_body[0] = if v6 { 129 } else { 0 };
                reply_body[4..6].copy_from_slice(&45000u16.to_be_bytes());
                let mut reply = message(
                    translated.tuple.destination,
                    translated.tuple.source,
                    protocol,
                    18,
                    if matches!(protocol, 1 | 58) {
                        &reply_body
                    } else {
                        b"response"
                    },
                );
                let mut reverse = state.begin(&reply, 7).unwrap();
                assert!(reverse.reply);
                assert_eq!(reverse.state, 2);
                assert_eq!(reverse.id, t.id);
                assert!(state.existing_nat(&mut reverse, &mut reply, false));
                assert!(state.existing_nat(&mut reverse, &mut reply, true));
                assert_eq!(key(&reply), Some(original.reverse()));
                assert!(packet::valid_transport(&reply));
                state.finish(reverse, true);
                let isolated = state.begin(&reply, 8).unwrap();
                assert_ne!(isolated.id, t.id);
                assert!(!isolated.reply);
                state.finish(isolated, false);
                assert_eq!(state.records().len(), 1);
            }
        }
    }
    #[test]
    fn snat_collision_reallocates_and_failed_flow_rolls_back() {
        let (s, d, public, _) = endpoints(false);
        let mut state = State::default();
        let mut a = message(s, d, 17, 0, b"a");
        let mut ta = state.begin(&a, 0).unwrap();
        assert!(state.nat(&mut ta, &mut a, true, Some(public), None));
        state.finish(ta, true);
        let mut other = s;
        other.set_ip("172.28.0.4".parse().unwrap());
        let mut b = message(other, d, 17, 0, b"b");
        let mut tb = state.begin(&b, 0).unwrap();
        assert!(state.nat(&mut tb, &mut b, true, Some(public), None));
        assert_ne!(
            key(&a).unwrap().tuple.source.port(),
            key(&b).unwrap().tuple.source.port()
        );
        state.finish(tb, false);
        assert_eq!(state.records().len(), 1);
        state.remove_addresses(&[s.ip()]);
        assert!(state.records().is_empty());
        assert!(state.index.is_empty());
    }
    #[test]
    fn related_icmp_restores_truncated_udp_quote_and_checksums() {
        for v6 in [false, true] {
            let (s, d, public, _) = endpoints(v6);
            let mut state = State::default();
            let mut outgoing = message(s, d, 17, 0, b"a payload longer than the ICMP quote");
            let original = key(&outgoing).unwrap();
            let mut t = state.begin(&outgoing, 0).unwrap();
            assert!(state.nat(
                &mut t,
                &mut outgoing,
                true,
                Some(public),
                Some((45000, 45000))
            ));
            state.finish(t, true);
            let h = if v6 { 40 } else { 20 };
            let mut body = vec![0; 8];
            body[0] = if v6 { 1 } else { 3 };
            body.extend_from_slice(&outgoing[..h + 8]);
            let mut error = message(
                d,
                SocketAddr::new(public, 0),
                if v6 { 58 } else { 1 },
                0,
                &body,
            );
            assert!(packet::valid_transport(&error));
            let mut related = state.begin(&error, 0).unwrap();
            assert_eq!(related.state, 4);
            assert!(related.reply);
            assert!(state.existing_nat(&mut related, &mut error, false));
            assert!(state.existing_nat(&mut related, &mut error, true));
            assert_eq!(key(&error).unwrap().tuple.destination.ip(), s.ip());
            assert_eq!(icmp::error(&error).unwrap().1, original);
            assert!(packet::valid_transport(&error));
            // Reattach the omitted bytes: incremental checksum must match the
            // original datagram even though they were absent during NAT.
            let mut quote = error[h + 8..].to_vec();
            quote.extend_from_slice(&outgoing[h + 8..]);
            assert!(packet::valid_transport(&quote));
            state.finish(related, true);
            assert_eq!(state.records().len(), 1);
        }
    }
    #[test]
    fn quota_expiry_close_and_teardown_are_bounded() {
        let (s, d, _, _) = endpoints(false);
        let mut state = State::default();
        for i in 0..512 {
            let mut a = s;
            a.set_port(i + 1000);
            let p = message(a, d, 6, 2, b"");
            let t = state.begin(&p, 0).unwrap();
            state.finish(t, true);
        }
        assert!(state.begin(&message(s, d, 6, 2, b""), 0).is_none());
        for e in state.entries.values_mut() {
            e.expires = Instant::now() - Duration::from_secs(1);
        }
        state.next_sweep = None;
        let fin = message(s, d, 6, 1, b"");
        let t = state.begin(&fin, 0).unwrap();
        state.finish(t, true);
        assert_eq!(state.records().len(), 1);
        assert!(state.records()[0].1 <= 10);
        state.delete(t.id);
        assert!(state.index.is_empty());
    }
}
