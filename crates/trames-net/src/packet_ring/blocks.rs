// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux TPACKET_V3 publishes whole blocks. Producer bookkeeping stays private
//! even while the guest changes its mapping or returns a previously read block.
use super::{Delivery, NetError, Result, Storage, PAGE};
use std::hash::{BuildHasher, RandomState};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BLOCK_HEADER: usize = 48;
const PACKET_HEADER: usize = 48;
const ADDRESS_END: usize = PACKET_HEADER + 20;

pub(super) struct Blocks {
    size: usize,
    hash: bool,
    count: usize,
    first: usize,
    net: usize,
    timeout: Duration,
    head: usize,
    used: usize,
    packets: u32,
    last: usize,
    sequence: u64,
    deadline: Option<Instant>,
    frozen: bool,
    pub(super) freezes: u32,
}

impl Blocks {
    pub(super) fn configure(
        request: &[u8],
        size: usize,
        count: usize,
        reserve: u32,
    ) -> Result<Self> {
        let extension = request.get(16..28).ok_or(NetError(22))?;
        let word = |i| u32::from_le_bytes(extension[i..i + 4].try_into().unwrap());
        if word(8) & !1 != 0 {
            return Err(NetError(22));
        }
        let first = BLOCK_HEADER + (word(4) as usize).next_multiple_of(8);
        let net = (ADDRESS_END.next_multiple_of(16) + 16) + reserve as usize;
        if net > u16::MAX as usize || first + net >= size {
            return Err(NetError(22));
        }
        let ms = word(0);
        Ok(Self {
            size,
            hash: word(8) == 1,
            count,
            first,
            net,
            timeout: Duration::from_millis(if ms == 0 { 8 } else { ms.into() }),
            head: 0,
            used: first,
            packets: 0,
            last: 0,
            sequence: 0,
            deadline: None,
            frozen: false,
            freezes: 0,
        })
    }
    fn owned(&self, storage: &Storage, index: usize) -> bool {
        storage.pages[index * self.size / PAGE]
            .get()
            .is_some_and(|p| unsafe { p.load_acquire_u32(8) != 0 })
    }
    pub(super) fn readable(&self, storage: &Storage) -> bool {
        self.sequence != 0 && self.owned(storage, (self.head + self.count - 1) % self.count)
    }
    pub(super) fn published(&self) -> u64 {
        self.sequence.wrapping_sub(u64::from(self.packets != 0))
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub(super) fn retire_due(&mut self, storage: &Storage, now: Instant, losing: bool) -> bool {
        if self.deadline.is_some_and(|at| at <= now) {
            self.publish(storage, true, losing);
            true
        } else {
            false
        }
    }
    fn publish(&mut self, storage: &Storage, timed_out: bool, losing: bool) {
        let base = self.head * self.size;
        storage.write(base + 12, &self.packets.to_le_bytes());
        storage.write(base + 20, &(self.used as u32).to_le_bytes());
        // All packet records, their data and the block header precede ownership.
        unsafe {
            storage.page(base / PAGE).store_release_u32(
                8,
                1 | (u32::from(timed_out) << 5) | (u32::from(losing) << 2),
            );
        }
        self.head = (self.head + 1) % self.count;
        self.packets = 0;
        self.used = self.first;
        self.deadline = None;
    }
    pub(super) fn receive(
        &mut self,
        storage: &Storage,
        bytes: &[u8],
        captured: usize,
        link: usize,
        address: &[u8; 20],
        losing: bool,
    ) -> Delivery {
        let now = Instant::now();
        self.retire_due(storage, now, losing);
        let mac = self.net - link;
        let snap = captured.min(self.size - self.first - mac);
        let record = (mac + snap).next_multiple_of(8);
        if self.packets != 0 && self.used + record > self.size {
            self.publish(storage, false, losing);
        }
        let base = self.head * self.size;
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut stamp = [0u8; 8];
        stamp[..4].copy_from_slice(&(time.as_secs() as u32).to_le_bytes());
        stamp[4..].copy_from_slice(&time.subsec_nanos().to_le_bytes());
        if self.packets == 0 {
            if self.owned(storage, self.head) {
                if !self.frozen {
                    self.freezes = self.freezes.wrapping_add(1);
                    self.frozen = true;
                }
                return Delivery::Full;
            }
            self.frozen = false;
            self.sequence = self.sequence.wrapping_add(1);
            storage.write(base, &2u32.to_le_bytes());
            storage.write(base + 4, &(BLOCK_HEADER as u32).to_le_bytes());
            storage.write(base + 16, &(self.first as u32).to_le_bytes());
            storage.write(base + 24, &self.sequence.to_le_bytes());
            storage.write(base + 32, &stamp);
            self.deadline = Some(now + self.timeout);
        } else {
            storage.write(
                base + self.last,
                &((self.used - self.last) as u32).to_le_bytes(),
            );
        }
        let mut header = [0u8; ADDRESS_END];
        header[4..12].copy_from_slice(&stamp);
        header[12..16].copy_from_slice(&(snap as u32).to_le_bytes());
        header[16..20].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        header[20..24].copy_from_slice(&((1u32 << 29) | 1).to_le_bytes());
        header[24..26].copy_from_slice(&(mac as u16).to_le_bytes());
        header[26..28].copy_from_slice(&(self.net as u16).to_le_bytes());
        if self.hash {
            if let Some(h) = crate::virtualnet::packet::header_after_write(&bytes[link..]) {
                static SEED: OnceLock<RandomState> = OnceLock::new();
                let a = h.tuple.source;
                let b = h.tuple.destination;
                let hash =
                    SEED.get_or_init(RandomState::new)
                        .hash_one((h.protocol, a.min(b), a.max(b))) as u32;
                header[28..32].copy_from_slice(&hash.max(1).to_le_bytes());
            }
        }
        header[PACKET_HEADER..].copy_from_slice(address);
        storage.write(base + self.used, &header);
        storage.write(base + self.used + mac, &bytes[..snap]);
        storage.write(base + 40, &stamp);
        self.last = self.used;
        self.used += record;
        self.packets += 1;
        if self.used + self.net > self.size {
            self.publish(storage, false, losing);
        }
        Delivery::Captured
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_ring::Ring;
    fn u32_at(s: &Storage, at: usize) -> u32 {
        let mut bytes = [0; 4];
        s.page(at / PAGE).copy_read(at % PAGE, &mut bytes);
        u32::from_le_bytes(bytes)
    }
    #[test]
    fn variable_records_timeout_private_area_and_block_reuse() {
        let request = [8192u32, 2, 256, 64, 10000, 13, 1]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let mut ring = Ring::configure(&request, 2, 0).unwrap().unwrap();
        let s = ring.storage.clone();
        s.write(48, &[0xfa; 13]);
        let mut packet = vec![0x11; 5000];
        // IPv4/UDP flow without a checksum offload dependency.
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&5000u16.to_be_bytes());
        packet[6..8].fill(0);
        packet[9] = 17;
        let addr = [0; 20];
        for n in [45, 5000] {
            assert!(matches!(
                ring.receive(&packet, n, 0, &addr, false, false),
                Delivery::Captured
            ));
        }
        assert_eq!(u32_at(&s, 8), 0);
        let at = ring.block_deadline().unwrap();
        assert!(ring.retire_due(at, false));
        assert!(ring.readable());
        assert_eq!(u32_at(&s, 8), 33);
        assert_eq!(u32_at(&s, 12), 2);
        let first = u32_at(&s, 16) as usize;
        assert_eq!((first, u32_at(&s, 4)), (64, 48));
        assert_eq!(u32_at(&s, 48), 0xfafafafa);
        let next = first + u32_at(&s, first) as usize;
        assert_eq!(u32_at(&s, first + 12), 45);
        assert_eq!(u32_at(&s, next), 0);
        assert_ne!(u32_at(&s, next + 28), 0);
        assert_eq!(u32_at(&s, first + 28), u32_at(&s, next + 28));
        assert_eq!(u32_at(&s, next + 12), 5000);
        assert_eq!(u32_at(&s, 4096), 0x11111111);
        let big = vec![0x23; 9000];
        ring.receive(&big, big.len(), 14, &addr, true, false);
        assert_eq!(u32_at(&s, 8192 + 8), 1);
        assert_eq!(u32_at(&s, 8192 + 24), 2);
        assert!(u32_at(&s, 8192 + 64 + 12) < 9000);
        for _ in 0..2 {
            assert!(matches!(
                ring.receive(&big, big.len(), 14, &addr, false, false),
                Delivery::Full
            ));
        }
        assert_eq!(ring.take_freezes(), 1);
        assert_eq!(ring.take_freezes(), 0);
        unsafe {
            s.page(0).store_release_u32(8, 0);
        }
        ring.receive(&big, big.len(), 14, &addr, false, true);
        assert_eq!(u32_at(&s, 24), 3);
        assert_eq!(u32_at(&s, 48), 0xfafafafa);
        assert_eq!(u32_at(&s, 8) & 5, 5);
        assert_eq!(u32_at(&s, 64 + 20) & 5, 1);
    }
}
