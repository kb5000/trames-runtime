// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted signalfd read buffers. Dequeue precedes each copyout, including
//! faults; preceding complete records remain a successful short read.
use super::*;
#[derive(Clone)]
enum Parts {
    Scalar(u64),
    Vector(Vec<(u64, usize)>),
}
#[derive(Clone)]
pub(crate) struct SignalRead {
    parts: Parts,
    count: usize,
}
impl SignalRead {
    pub fn uring(
        fd: &trames_vfs::DirectFd,
        parts: &[(u64, usize)],
        memory: &mut impl CpuMemory,
        vector: bool,
        buffer: Option<&trames_memory::PinnedBuffer>,
    ) -> Result<u64, Errno> {
        fd.check_read_access()?;
        Self::read_with(fd, parts, vector, |address, data| {
            if let Some(buffer) = buffer {
                buffer
                    .write(
                        buffer.range(address, data.len()).map_err(|_| Errno(14))?,
                        data,
                    )
                    .map_err(|_| Errno(14))
            } else {
                memory.write(address, data).map_err(|_| Errno(14))
            }
        })
    }
    pub fn prepare(number: u32, a: [u64; 6], memory: &impl CpuMemory) -> Result<Self, Errno> {
        let (parts, count) = if number == 65 {
            if a[2] > 1024 {
                return Err(Errno(22));
            }
            memory
                .check(a[1], a[2] as usize * 16, Access::Read)
                .map_err(|_| Errno(14))?;
            let mut parts = Vec::with_capacity(a[2] as usize);
            let mut requested = 0u64;
            let mut count = 0usize;
            for i in 0..a[2] {
                let b = memory
                    .read_array::<16>(a[1] + i * 16)
                    .map_err(|_| Errno(14))?;
                let address = u64::from_le_bytes(b[..8].try_into().unwrap());
                let length = u64::from_le_bytes(b[8..].try_into().unwrap());
                requested = requested
                    .checked_add(length)
                    .filter(|n| *n <= i64::MAX as u64)
                    .ok_or(Errno(22))?;
                let n = length.min((crate::MAX_WRITE - count) as u64) as usize;
                parts.push((address, n));
                count += n;
            }
            (Parts::Vector(parts), count)
        } else if number == 63 {
            let count = a[2].min(crate::MAX_WRITE as u64) as usize;
            (Parts::Scalar(a[1]), count)
        } else {
            return Err(Errno(22));
        };
        if count < 128 && !(number == 65 && count == 0) {
            return Err(Errno(22));
        }
        Ok(Self { parts, count })
    }
    pub fn check(
        &self,
        fd: &trames_vfs::DirectFd,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let scalar;
        let parts = match &self.parts {
            Parts::Scalar(address) => {
                scalar = [(*address, self.count)];
                &scalar[..]
            }
            Parts::Vector(parts) => parts.as_slice(),
        };
        Self::read_parts(fd, parts, memory, matches!(self.parts, Parts::Vector(_)))
    }
    pub fn read_parts(
        fd: &trames_vfs::DirectFd,
        parts: &[(u64, usize)],
        memory: &mut impl CpuMemory,
        vector: bool,
    ) -> Result<u64, Errno> {
        Self::read_with(fd, parts, vector, |a, bytes| {
            memory.write(a, bytes).map_err(|_| Errno(14))
        })
    }
    pub fn read_with(
        fd: &trames_vfs::DirectFd,
        parts: &[(u64, usize)],
        vector: bool,
        mut write: impl FnMut(u64, &[u8]) -> Result<(), Errno>,
    ) -> Result<u64, Errno> {
        let count: usize = parts.iter().map(|p| p.1).sum();
        if count < 128 {
            return if count == 0 && vector {
                Ok(0)
            } else {
                Err(Errno(22))
            };
        }
        let mut total = 0;
        while total + 128 <= count {
            let Some(record) = fd.take_signal_record() else {
                break;
            };
            let mut offset = 0;
            let mut copy = Ok(());
            for &(address, length) in parts {
                let start = total.max(offset);
                let end = (total + 128).min(offset + length);
                if start < end {
                    copy = address
                        .checked_add((start - offset) as u64)
                        .ok_or(Errno(14))
                        .and_then(|a| write(a, &record[start - total..end - total]));
                    if copy.is_err() {
                        break;
                    }
                }
                offset += length;
            }
            if let Err(error) = copy {
                return if total == 0 {
                    Err(error)
                } else {
                    Ok(total as u64)
                };
            }
            total += 128;
        }
        if total == 0 {
            Err(Errno(11))
        } else {
            Ok(total as u64)
        }
    }
}
