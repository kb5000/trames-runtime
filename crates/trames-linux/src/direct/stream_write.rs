// SPDX-License-Identifier: GPL-3.0-or-later
//! A blocking Unix stream send owns its iovec layout and byte cursor until completion.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

enum Source {
    Scalar(u64),
    // Each entry holds the guest address and exclusive end in the logical stream.
    Vector(Vec<(u64, usize)>),
}

pub(super) struct StreamWrite {
    source: Source,
    length: usize,
    written: AtomicUsize,
    flags: u32,
    identity: Option<[u32; 3]>,
}

impl StreamWrite {
    pub(super) fn accepts(fd: &trames_vfs::DirectFd, number: u32, args: [u64; 6]) -> bool {
        (matches!(number, 64 | 66) || number == 206 && args[4] == 0 && args[3] & 0x40 == 0)
            && fd.local_kind() == 1
            && !fd.nonblocking()
    }

    pub(super) fn new(
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        identity: Option<[u32; 3]>,
    ) -> Result<Self, Errno> {
        let limit = trames_vfs::Vfs::MAX_RW_COUNT;
        let (source, length) = if number == 66 {
            if args[2] > 1024 {
                return Err(Errno(22));
            }
            Linux::check(memory, args[1], args[2] as usize * 16, Access::Read)?;
            let mut parts = Vec::with_capacity(args[2] as usize);
            let mut total = 0u64;
            for i in 0..args[2] {
                let (addr, len) = Linux::iovec_at(memory, args[1] + 16 * i)?;
                total = total
                    .checked_add(len)
                    .filter(|&n| n <= i64::MAX as u64)
                    .ok_or(Errno(22))?;
                parts.push((addr, total.min(limit) as usize));
            }
            (Source::Vector(parts), total.min(limit))
        } else {
            (Source::Scalar(args[1]), args[2].min(limit))
        };
        Ok(Self {
            source,
            length: length as usize,
            written: 0.into(),
            flags: socket_flags(number, args),
            identity,
        })
    }

    pub(super) fn written(&self) -> usize {
        self.written.load(Ordering::Relaxed)
    }

    fn gather(
        &self,
        memory: &impl CpuMemory,
        mut offset: usize,
        scratch: &mut Vec<u8>,
    ) -> Result<usize, Errno> {
        let size = (self.length - offset).min(crate::MAX_WRITE);
        scratch.resize(size, 0);
        let mut copied = 0;
        let mut index = match &self.source {
            Source::Scalar(_) => 0,
            Source::Vector(parts) => parts.partition_point(|&(_, end)| end <= offset),
        };
        while copied < size {
            let (base, start, end) = match &self.source {
                Source::Scalar(addr) => (*addr, 0, self.length),
                Source::Vector(parts) => (
                    parts[index].0,
                    if index == 0 { 0 } else { parts[index - 1].1 },
                    parts[index].1,
                ),
            };
            index += 1;
            let count = (end - offset).min(size - copied);
            if count == 0 {
                continue;
            }
            let read = (|| {
                let addr = base.checked_add((offset - start) as u64).ok_or(Errno(14))?;
                let n = Linux::file_buffer_prefix(memory, addr, count, Access::Read)?;
                memory
                    .read(addr, &mut scratch[copied..copied + n])
                    .map_err(|_| Errno(14))?;
                Ok(n)
            })();
            match read {
                Ok(n) => {
                    copied += n;
                    offset += n;
                    if n < count {
                        break;
                    }
                }
                Err(_) if copied > 0 => break,
                Err(error) => return Err(error),
            }
        }
        if copied == 0 && size != 0 {
            Err(Errno(14))
        } else {
            Ok(copied)
        }
    }

    pub(super) fn try_whole(
        &self,
        fd: &trames_vfs::DirectFd,
        memory: &impl CpuMemory,
        scratch: &mut Vec<u8>,
    ) -> Option<Result<u64, Errno>> {
        if self.length > crate::MAX_WRITE {
            return None;
        }
        Some(
            self.gather(memory, 0, scratch)
                .and_then(|n| fd.try_send_whole_stream(&scratch[..n], self.flags, self.identity))
                .map(|n| n as u64),
        )
    }

    pub(super) fn progress(
        &self,
        fd: &trames_vfs::DirectFd,
        memory: &impl CpuMemory,
        scratch: &mut Vec<u8>,
    ) -> Result<u64, Errno> {
        let mut offset = self.written();
        loop {
            let result = self
                .gather(memory, offset, scratch)
                .and_then(|n| fd.send_credentials(&scratch[..n], self.flags, self.identity));
            match result {
                Ok(n) => {
                    offset += n;
                    if offset == self.length || n == 0 || fd.nonblocking() {
                        return Ok(offset as u64);
                    }
                    // Only the calling task advances the cursor. Signal/timeout completion reads it.
                    self.written.store(offset, Ordering::Relaxed);
                }
                Err(error) if offset != 0 && (error != Errno(11) || fd.nonblocking()) => {
                    return Ok(offset as u64)
                }
                Err(error) => return Err(error),
            }
        }
    }
}
