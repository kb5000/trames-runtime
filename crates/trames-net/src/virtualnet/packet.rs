// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
/// Build the IPv4 envelope for a transport payload supplied by a raw socket.
pub(super) fn raw_ipv4(
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let size = 20 + payload.len();
    let mut packet = Vec::with_capacity(size);
    packet.resize(20, 0);
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet.extend_from_slice(payload);
    packet
}
pub(super) fn raw_v6_checksum(src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, payload: &[u8]) -> u16 {
    use smoltcp::wire::checksum;
    !checksum::combine(&[
        checksum::pseudo_header_v6(&src, &dst, protocol.into(), payload.len() as u32),
        checksum::data(payload),
    ])
}
pub(super) const MTU: usize = 1500;
const QUEUE: usize = 96;
// Bound retained fragment memory, rather than letting a few lost datagrams
// monopolize all reassembly slots until the IP timeout.
const FRAGMENT_BYTES: usize = 512 * 1024;
#[derive(Default)]
pub(crate) struct Port {
    pub rx: VecDeque<(Vec<u8>, u32)>,
    pub tx: VecDeque<Vec<u8>>,
    serial: u32,
    fragments: Vec<Fragments>,
}
struct Fragments {
    key: (IpAddr, IpAddr, u32, u8, u32),
    header: Vec<u8>,
    data: Vec<u8>,
    covered: Vec<bool>,
    end: Option<usize>,
    poisoned: bool,
    expires: Instant,
    updated: Instant,
    received: usize,
}
impl Fragments {
    fn bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.header.len() + self.data.len() + self.covered.len()
    }
}
impl Port {
    /// Queue an already formed IP datagram on the same egress path as the interface.
    pub(super) fn send_raw(&mut self, packet: Vec<u8>) -> Result<()> {
        if self.tx.len() >= QUEUE {
            return Err(NetError(11));
        }
        self.tx.push_back(packet);
        Ok(())
    }
    pub fn receive_packet(&mut self, p: Vec<u8>) -> bool {
        self.receive_on(p, 0)
    }
    pub(super) fn receive_on(&mut self, p: Vec<u8>, ingress: u32) -> bool {
        self.fragments.retain(|f| f.expires > Instant::now());
        if p.len() > 65575 || self.rx.len() == QUEUE {
            return false;
        }
        let Some(h) = header(&p) else {
            return false;
        };
        let version = p[0] >> 4;
        let descriptor = if version == 6 && p[6] == 44 {
            if p.len() < 48 || p[41] != 0 {
                return false;
            }
            let bits = u16::from_be_bytes([p[42], p[43]]);
            if bits & 6 != 0 {
                return false;
            }
            Some((
                u32::from_be_bytes(p[44..48].try_into().unwrap()),
                p[40],
                (bits & 0xfff8) as usize,
                bits & 1 != 0,
                40,
                48,
            ))
        } else if version == 4 {
            let bits = u16::from_be_bytes([p[6], p[7]]);
            if bits & 0x3fff == 0 {
                None
            } else {
                if bits & 0xc000 != 0 {
                    return false;
                }
                Some((
                    u16::from_be_bytes([p[4], p[5]]) as u32,
                    p[9],
                    ((bits & 0x1fff) as usize) * 8,
                    bits & 0x2000 != 0,
                    h.offset,
                    h.offset,
                ))
            }
        } else {
            None
        };
        let Some((id, proto, offset, more, header_len, data_offset)) = descriptor else {
            self.rx.push_back((p, ingress));
            return true;
        };
        let key = (
            h.tuple.source.ip(),
            h.tuple.destination.ip(),
            id,
            proto,
            ingress,
        );
        let n = p.len() - data_offset;
        let maximum = if version == 4 {
            65535 - header_len
        } else {
            65535
        };
        if n == 0 || more && !n.is_multiple_of(8) || offset + n > maximum {
            return false;
        }
        let now = Instant::now();
        let extent = offset + n;
        let extra = self.fragments.iter().find(|f| f.key == key).map_or(
            std::mem::size_of::<Fragments>() + header_len + extent * 2,
            |f| extent.saturating_sub(f.data.len()) * 2,
        );
        let mut retained: usize = self.fragments.iter().map(Fragments::bytes).sum();
        while retained + extra > FRAGMENT_BYTES {
            let Some(oldest) = self
                .fragments
                .iter()
                .enumerate()
                .filter(|(_, f)| f.key != key)
                .min_by_key(|(_, f)| f.updated)
                .map(|(i, _)| i)
            else {
                return false;
            };
            retained -= self.fragments.remove(oldest).bytes();
        }
        let i = match self.fragments.iter().position(|f| f.key == key) {
            Some(i) => i,
            None => {
                self.fragments.push(Fragments {
                    key,
                    header: p[..header_len].to_vec(),
                    data: Vec::new(),
                    covered: Vec::new(),
                    end: None,
                    poisoned: false,
                    expires: now + Duration::from_secs(60),
                    updated: now,
                    received: 0,
                });
                self.fragments.len() - 1
            }
        };
        let f = &mut self.fragments[i];
        if f.poisoned {
            return false;
        }
        if f.header.len() != header_len
            || f.covered
                .get(offset..extent.min(f.covered.len()))
                .is_some_and(|range| range.iter().any(|b| *b))
            || f.end.is_some_and(|end| offset + n > end)
            || !more && f.end.is_some_and(|end| end != offset + n)
        {
            f.poisoned = true;
            return false;
        }
        if !more {
            f.end = Some(offset + n);
            if f.covered
                .get(extent..)
                .is_some_and(|range| range.iter().any(|b| *b))
            {
                f.poisoned = true;
                return false;
            }
        }
        if offset == 0 {
            f.header.copy_from_slice(&p[..header_len]);
        }
        if extent > f.data.len() {
            let extra = extent - f.data.len();
            f.data.reserve_exact(extra);
            f.covered.reserve_exact(extra);
            f.data.resize(extent, 0);
            f.covered.resize(extent, false);
        }
        f.updated = now;
        f.data[offset..extent].copy_from_slice(&p[data_offset..]);
        f.covered[offset..extent].fill(true);
        f.received += n;
        if let Some(end) = f.end {
            if f.received == end {
                let mut f = self.fragments.remove(i);
                if version == 4 {
                    f.header[2..4].copy_from_slice(&((header_len + end) as u16).to_be_bytes());
                    f.header[6..8].fill(0);
                    smoltcp::wire::Ipv4Packet::new_unchecked(&mut f.header).fill_checksum();
                } else {
                    f.header[6] = key.3;
                    f.header[4..6].copy_from_slice(&(end as u16).to_be_bytes());
                }
                f.header.extend_from_slice(&f.data[..end]);
                self.rx.push_back((f.header, ingress));
            }
        }
        true
    }
}
pub(crate) struct Rx(Vec<u8>, u32);
pub(crate) struct Tx<'a>(&'a mut Port);
impl RxToken for Rx {
    fn meta(&self) -> smoltcp::phy::PacketMeta {
        let mut meta = smoltcp::phy::PacketMeta::default();
        meta.ingress_index = self.1;
        meta
    }
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut p = vec![0; len];
        let r = f(&mut p);
        // smoltcp implements IPv4 fragmentation; supply the missing IPv6 adapter.
        if len > MTU && p.first().is_some_and(|b| b >> 4 == 6) && len <= 65575 {
            let chunks = (len - 40).div_ceil(1448);
            if self.0.tx.len() + chunks <= QUEUE {
                self.0.serial = self.0.serial.wrapping_add(1);
                let id = self.0.serial;
                for (i, chunk) in p[40..].chunks(1448).enumerate() {
                    let mut fragment = p[..40].to_vec();
                    fragment[6] = 44;
                    fragment[4..6].copy_from_slice(&((chunk.len() + 8) as u16).to_be_bytes());
                    fragment.extend_from_slice(&[p[6], 0]);
                    let bits = (i * 1448) as u16 | u16::from(i + 1 < chunks);
                    fragment.extend_from_slice(&bits.to_be_bytes());
                    fragment.extend_from_slice(&id.to_be_bytes());
                    fragment.extend_from_slice(chunk);
                    self.0.tx.push_back(fragment);
                }
            }
        } else if len <= MTU && self.0.tx.len() < QUEUE {
            self.0.tx.push_back(p);
        }
        r
    }
}
impl Device for Port {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: smoltcp::time::Instant) -> Option<(Rx, Tx<'_>)> {
        if self.tx.len() == QUEUE {
            return None;
        }
        let (p, index) = self.rx.pop_front()?;
        Some((Rx(p, index), Tx(self)))
    }
    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Tx<'_>> {
        (self.tx.len() < QUEUE).then_some(Tx(self))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Tuple {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}
pub(crate) struct Header {
    pub tuple: Tuple,
    pub protocol: u8,
    pub offset: usize,
    pub first: bool,
}
pub(crate) fn header(p: &[u8]) -> Option<Header> {
    let (src, dst, proto, offset, first) = match p.first()? >> 4 {
        4 => {
            if p.len() < 20 {
                return None;
            }
            let n = ((p[0] & 15) * 4) as usize;
            if n < 20 || p.len() < n || p.len() != u16::from_be_bytes([p[2], p[3]]) as usize {
                return None;
            }
            let packet = smoltcp::wire::Ipv4Packet::new_checked(p).ok()?;
            if !packet.verify_checksum() {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
                IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
                p[9],
                n,
                u16::from_be_bytes([p[6], p[7]]) & 0x1fff == 0,
            )
        }
        6 => {
            if p.len() < 40 || p.len() != 40 + u16::from_be_bytes([p[4], p[5]]) as usize {
                return None;
            }
            let (proto, n, first) = if p[6] == 44 {
                if p.len() < 48 {
                    return None;
                }
                (p[40], 48, u16::from_be_bytes([p[42], p[43]]) & 0xfff8 == 0)
            } else {
                (p[6], 40, true)
            };
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?)),
                proto,
                n,
                first,
            )
        }
        _ => return None,
    };
    let (sp, dp) = if first && matches!(proto, 6 | 17) && p.len() >= offset + 4 {
        (
            u16::from_be_bytes([p[offset], p[offset + 1]]),
            u16::from_be_bytes([p[offset + 2], p[offset + 3]]),
        )
    } else {
        (0, 0)
    };
    Some(Header {
        tuple: Tuple {
            source: SocketAddr::new(src, sp),
            destination: SocketAddr::new(dst, dp),
        },
        protocol: proto,
        offset,
        first,
    })
}
pub(crate) fn valid_transport(p: &[u8]) -> bool {
    let Some(h) = header(p) else {
        return false;
    };
    if !h.first {
        return false;
    }
    let (source, dest) = (
        smoltcp::wire::IpAddress::from(h.tuple.source.ip()),
        smoltcp::wire::IpAddress::from(h.tuple.destination.ip()),
    );
    let b = &p[h.offset..];
    match h.protocol {
        6 => smoltcp::wire::TcpPacket::new_checked(b)
            .is_ok_and(|p| p.verify_checksum(&source, &dest)),
        17 => smoltcp::wire::UdpPacket::new_checked(b)
            .is_ok_and(|p| p.verify_checksum(&source, &dest)),
        1 => smoltcp::wire::Icmpv4Packet::new_checked(b).is_ok_and(|p| p.verify_checksum()),
        58 => {
            if let (IpAddr::V6(s), IpAddr::V6(d)) = (h.tuple.source.ip(), h.tuple.destination.ip())
            {
                smoltcp::wire::Icmpv6Packet::new_checked(b).is_ok_and(|p| p.verify_checksum(&s, &d))
            } else {
                false
            }
        }
        _ => false,
    }
}
/// L3 filtering uses reassembled datagrams; Ethernet egress restores real MTU fragments.
pub(crate) fn fragment_link(packet: Vec<u8>, mtu: usize, serial: u32) -> Option<Vec<Vec<u8>>> {
    if packet.len() <= mtu {
        return Some(vec![packet]);
    }
    let h = header(&packet)?;
    let mut out = Vec::new();
    if packet[0] >> 4 == 4 {
        if packet[6] & 0x40 != 0 {
            return None;
        }
        let chunk = (mtu.checked_sub(h.offset)? / 8) * 8;
        if chunk == 0 {
            return None;
        }
        let chunks = packet[h.offset..].chunks(chunk);
        let total = chunks.len();
        for (n, data) in chunks.enumerate() {
            let mut p = packet[..h.offset].to_vec();
            p[2..4].copy_from_slice(&((h.offset + data.len()) as u16).to_be_bytes());
            p[4..6].copy_from_slice(&(serial as u16).to_be_bytes());
            p[6..8].copy_from_slice(
                &(((n * chunk / 8) as u16) | if n + 1 < total { 0x2000 } else { 0 }).to_be_bytes(),
            );
            smoltcp::wire::Ipv4Packet::new_unchecked(&mut p).fill_checksum();
            p.extend_from_slice(data);
            out.push(p);
        }
    } else {
        let chunk = (mtu.checked_sub(48)? / 8) * 8;
        if chunk == 0 {
            return None;
        }
        let chunks = packet[40..].chunks(chunk);
        let total = chunks.len();
        for (n, data) in chunks.enumerate() {
            let mut p = packet[..40].to_vec();
            p[6] = 44;
            p[4..6].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
            p.extend_from_slice(&[packet[6], 0]);
            p.extend_from_slice(&(((n * chunk) as u16) | u16::from(n + 1 < total)).to_be_bytes());
            p.extend_from_slice(&serial.to_be_bytes());
            p.extend_from_slice(data);
            out.push(p);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fragments(v6: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
        if v6 {
            let mut original = vec![0; 3040];
            original[0] = 0x60;
            original[4..6].copy_from_slice(&3000u16.to_be_bytes());
            original[6] = 17;
            original[7] = 64;
            original[8..24].copy_from_slice(&super::super::v6(2).octets());
            original[24..40].copy_from_slice(&super::super::v6(3).octets());
            for (i, b) in original[40..].iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            let mut port = Port::default();
            Tx(&mut port).consume(original.len(), |b| b.copy_from_slice(&original));
            (original, port.tx.into_iter().collect())
        } else {
            let mut original = vec![0; 3020];
            original[0] = 0x45;
            original[2..4].copy_from_slice(&3020u16.to_be_bytes());
            original[4..6].copy_from_slice(&123u16.to_be_bytes());
            original[8] = 64;
            original[9] = 17;
            original[12..16].copy_from_slice(&super::super::v4(2).octets());
            original[16..20].copy_from_slice(&super::super::v4(3).octets());
            for (i, b) in original[20..].iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            smoltcp::wire::Ipv4Packet::new_unchecked(&mut original).fill_checksum();
            let mut frames = Vec::new();
            for (i, chunk) in original[20..].chunks(1480).enumerate() {
                let mut p = original[..20].to_vec();
                p[2..4].copy_from_slice(&((chunk.len() + 20) as u16).to_be_bytes());
                let bits = (i * 1480 / 8) as u16 | if (i + 1) * 1480 < 3000 { 0x2000 } else { 0 };
                p[6..8].copy_from_slice(&bits.to_be_bytes());
                p.extend_from_slice(chunk);
                smoltcp::wire::Ipv4Packet::new_unchecked(&mut p).fill_checksum();
                frames.push(p);
            }
            (original, frames)
        }
    }
    #[test]
    fn reordered_fragments_complete_and_overlap_poisons_datagram() {
        for v6 in [false, true] {
            let (original, frames) = fragments(v6);
            let mut port = Port::default();
            for f in frames.iter().rev() {
                assert!(port.receive_packet(f.clone()));
            }
            assert_eq!(port.rx.pop_front().unwrap().0, original);
            assert!(port.fragments.is_empty());
            let mut port = Port::default();
            assert!(port.receive_packet(frames[0].clone()));
            assert!(!port.receive_packet(frames[0].clone()));
            for f in &frames[1..] {
                assert!(!port.receive_packet(f.clone()));
            }
            assert!(port.rx.is_empty());
            assert!(port.fragments[0].poisoned);
        }
    }
    #[test]
    fn fragment_pressure_evicts_incomplete_datagrams_and_recovers() {
        for v6 in [false, true] {
            let (original, frames) = fragments(v6);
            let mut port = Port::default();
            let set_id = |mut p: Vec<u8>, id: u32| {
                if v6 {
                    p[44..48].copy_from_slice(&id.to_be_bytes());
                } else {
                    p[4..6].copy_from_slice(&(id as u16).to_be_bytes());
                    smoltcp::wire::Ipv4Packet::new_unchecked(&mut p).fill_checksum();
                }
                p
            };
            // Lose the last fragment of many unrelated datagrams. Neither
            // pressure nor an overlap-poisoned entry may close admission.
            for id in 0..512 {
                assert!(port.receive_packet(set_id(frames[0].clone(), id)));
                assert!(!port.receive_packet(set_id(frames[0].clone(), id)));
                assert!(
                    port.fragments.iter().map(Fragments::bytes).sum::<usize>() <= FRAGMENT_BYTES
                );
            }
            assert!(port.fragments.len() < 512);
            for frame in &frames {
                assert!(port.receive_packet(set_id(frame.clone(), 600)));
            }
            let mut expected = original;
            if !v6 {
                expected[4..6].copy_from_slice(&600u16.to_be_bytes());
                smoltcp::wire::Ipv4Packet::new_unchecked(&mut expected).fill_checksum();
            }
            assert_eq!(port.rx.pop_front().unwrap().0, expected);
        }
    }
    #[test]
    fn incomplete_fragments_expire_and_queues_are_bounded() {
        for v6 in [false, true] {
            let (_, frames) = fragments(v6);
            let mut port = Port::default();
            assert!(port.receive_packet(frames[0].clone()));
            port.fragments[0].expires = Instant::now();
            assert!(port.receive_packet(frames[1].clone()));
            assert!(port.rx.is_empty());
            assert_eq!(port.fragments.len(), 1);
            let (original, _) = fragments(false);
            let small = original[..20].to_vec();
            let mut small = small;
            small[2..4].copy_from_slice(&20u16.to_be_bytes());
            smoltcp::wire::Ipv4Packet::new_unchecked(&mut small).fill_checksum();
            for _ in 0..QUEUE {
                assert!(port.receive_packet(small.clone()));
            }
            assert!(!port.receive_packet(small));
        }
    }
}
