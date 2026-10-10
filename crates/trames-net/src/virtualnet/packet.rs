// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
pub(super) const MTU: usize = 1500;
const QUEUE: usize = 96;
#[derive(Default)]
pub(super) struct Port {
    pub rx: VecDeque<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
    serial: u32,
    fragments: Vec<Fragments>,
}
struct Fragments {
    key: (IpAddr, IpAddr, u32, u8),
    header: Vec<u8>,
    data: Vec<u8>,
    covered: Vec<bool>,
    end: Option<usize>,
    poisoned: bool,
    expires: Instant,
}
impl Port {
    pub fn receive_packet(&mut self, p: Vec<u8>) -> bool {
        self.fragments.retain(|f| f.expires > Instant::now());
        if p.len() > MTU || self.rx.len() == QUEUE {
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
            self.rx.push_back(p);
            return true;
        };
        let key = (h.tuple.source.ip(), h.tuple.destination.ip(), id, proto);
        let n = p.len() - data_offset;
        let maximum = if version == 4 {
            65535 - header_len
        } else {
            65535
        };
        if n == 0 || more && !n.is_multiple_of(8) || offset + n > maximum {
            return false;
        }
        let i = match self.fragments.iter().position(|f| f.key == key) {
            Some(i) => i,
            None => {
                if self.fragments.len() == 2 {
                    return false;
                }
                self.fragments.push(Fragments {
                    key,
                    header: p[..header_len].to_vec(),
                    data: vec![0; 65535],
                    covered: vec![false; 65535],
                    end: None,
                    poisoned: false,
                    expires: Instant::now() + Duration::from_secs(60),
                });
                self.fragments.len() - 1
            }
        };
        let f = &mut self.fragments[i];
        if f.poisoned {
            return false;
        }
        if f.header.len() != header_len
            || f.covered[offset..offset + n].iter().any(|b| *b)
            || f.end.is_some_and(|end| offset + n > end)
            || !more && f.end.is_some_and(|end| end != offset + n)
        {
            f.poisoned = true;
            return false;
        }
        if !more {
            f.end = Some(offset + n);
            if f.covered[offset + n..].iter().any(|b| *b) {
                f.poisoned = true;
                return false;
            }
        }
        if offset == 0 {
            f.header.copy_from_slice(&p[..header_len]);
        }
        f.data[offset..offset + n].copy_from_slice(&p[data_offset..]);
        f.covered[offset..offset + n].fill(true);
        if let Some(end) = f.end {
            if f.covered[..end].iter().all(|b| *b) {
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
                self.rx.push_back(f.header);
            }
        }
        true
    }
}
pub(super) struct Rx(Vec<u8>);
pub(super) struct Tx<'a>(&'a mut Port);
impl RxToken for Rx {
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
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(self)))
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
pub(super) struct Tuple {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}
pub(super) struct Header {
    pub tuple: Tuple,
    pub protocol: u8,
    pub offset: usize,
    pub first: bool,
}
pub(super) fn header(p: &[u8]) -> Option<Header> {
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
            assert_eq!(port.rx.pop_front().unwrap(), original);
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
