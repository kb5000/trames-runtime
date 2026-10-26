// SPDX-License-Identifier: GPL-3.0-or-later
//! Task-group routing and signalfd integration over common signal state.
use super::*;

impl<C: Cpu> Process<C> {
    pub(super) fn pending_bits(&self) -> u64 {
        self.signals.pending_bits()
    }
    pub(super) fn next_signal(&self, mask: u64) -> Option<(u32, bool)> {
        self.signals.next_signal(mask)
    }
    pub(super) fn take_signal(&mut self, sig: u32, shared: bool) -> Info {
        let mut info = self.signals.take_signal(sig, shared);
        if info.fault.is_none() {
            info.sender = self.linux.vfs.visible_pid(info.sender);
        }
        info
    }
    pub(super) fn signal_senders(&self) -> Vec<u32> {
        self.signals.signal_senders()
    }
}

use trames_kernel::signal::write_signalfd;

impl<C: Cpu> Kernel<C> {
    pub(super) fn signalfd(&self, p: &mut Process<C>, a: [u64; 6]) -> Result<Option<u64>, Errno> {
        if a[2] != 8 {
            return Err(Errno(22));
        }
        let mask = read_u64(&p.memory, a[1])?;
        p.linux
            .vfs
            .signalfd(a[0] as i32, mask, a[3] as u32)
            .map(|fd| Some(fd as u64))
    }
    pub(super) fn read_signalfd(
        &self,
        p: &mut Process<C>,
        number: u32,
        a: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        let fd = a[0] as u32;
        let mask = p.linux.vfs.signalfd_mask(fd)?.ok_or(Errno(22))?;
        let (parts, count) = if number == 65 {
            if a[2] > 1024 {
                return Err(Errno(22));
            }
            Linux::check(&p.memory, a[1], a[2] as usize * 16, Access::Read)?;
            let mut parts = Vec::new();
            let mut requested = 0u64;
            let mut count = 0;
            for i in 0..a[2] {
                let address = read_u64(&p.memory, a[1] + i * 16)?;
                let length = read_u64(&p.memory, a[1] + i * 16 + 8)?;
                requested = requested
                    .checked_add(length)
                    .filter(|n| *n <= i64::MAX as u64)
                    .ok_or(Errno(22))?;
                let take = length.min((MAX_WRITE - count) as u64) as usize;
                parts.push((address, take));
                count += take;
            }
            if count == 0 {
                return Ok(Some(0));
            }
            (parts, count)
        } else {
            let count = a[2].min(MAX_WRITE as u64) as usize;
            (vec![(a[1], count)], count)
        };
        if count < 128 {
            return Err(Errno(22));
        }
        let mut total = 0;
        while total + 128 <= count {
            let Some((sig, shared)) = p.next_signal(mask) else {
                break;
            };
            // Linux dequeues before copying: a fault consumes this signal, and
            // complete preceding records still count as a successful short read.
            let record = write_signalfd(sig, p.take_signal(sig, shared));
            let mut offset = 0;
            for &(address, length) in &parts {
                let start = total.max(offset);
                let end = (total + 128).min(offset + length);
                if start < end {
                    let result = address
                        .checked_add((start - offset) as u64)
                        .ok_or(Errno(14))
                        .and_then(|address| {
                            p.memory
                                .write(address, &record[start - total..end - total])
                                .map_err(|_| Errno(14))
                        });
                    if let Err(e) = result {
                        return if total == 0 {
                            Err(e)
                        } else {
                            Ok(Some(total as u64))
                        };
                    }
                }
                offset += length;
            }
            total += 128;
        }
        if total == 0 {
            return if p.linux.vfs.flags(fd)? & O_NONBLOCK != 0 {
                Err(Errno(11))
            } else {
                Ok(None)
            };
        }
        Ok(Some(total as u64))
    }
}
