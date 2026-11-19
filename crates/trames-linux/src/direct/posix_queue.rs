// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
use trames_vfs::posix_mq::QueueFd;

enum Operation {
    Send(Arc<[u8]>, u32),
    Receive,
}

pub(super) struct Request {
    pub file: QueueFd,
    pub deadline: Option<Instant>,
    operation: Operation,
    nonblocking: bool,
}

impl Request {
    pub(super) fn import(
        factory: &trames_vfs::DescriptorFactory,
        number: u32,
        a: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Result<Self, Errno> {
        let deadline = if a[4] == 0 {
            None
        } else {
            let ts = memory.read_array::<16>(a[4]).map_err(|_| Errno(14))?;
            let seconds = i64::from_le_bytes(ts[..8].try_into().unwrap());
            let nanos = i64::from_le_bytes(ts[8..].try_into().unwrap());
            if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
                return Err(Errno(22));
            }
            let target = Duration::new(seconds as u64, nanos as u32);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            Instant::now().checked_add(target.saturating_sub(now))
        };
        let file = factory.mq_descriptor(a[0] as u32)?;
        let flags = file.flags();
        let operation = if number == 182 {
            let priority = a[3] as u32;
            if priority >= 32768 {
                return Err(Errno(22));
            }
            if flags & 3 == 0 {
                return Err(Errno(9));
            }
            if a[2] > file.queue.message_size() as u64 {
                return Err(Errno(90));
            }
            let mut data = vec![0; a[2] as usize];
            if !data.is_empty() {
                memory.read(a[1], &mut data).map_err(|_| Errno(14))?;
            }
            Operation::Send(data.into(), priority)
        } else {
            if flags & 3 == 1 {
                return Err(Errno(9));
            }
            Operation::Receive
        };
        Ok(Self {
            file,
            deadline,
            operation,
            nonblocking: flags & 0x800 != 0,
        })
    }
    pub(super) fn nonblocking(&self) -> bool {
        self.nonblocking
    }
    pub(super) fn attempt(&self, memory: &mut impl CpuMemory, a: [u64; 6]) -> Result<u64, Errno> {
        let result = match &self.operation {
            Operation::Send(data, priority) => self.file.queue.send(data, *priority).map(|()| 0),
            Operation::Receive => self.file.queue.receive(a[2]).and_then(|(priority, data)| {
                if a[3] != 0 {
                    memory
                        .write_array(a[3], priority.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if !data.is_empty() {
                    memory.write(a[1], &data).map_err(|_| Errno(14))?;
                }
                Ok(data.len() as u64)
            }),
        };
        match result {
            Err(Errno(11))
                if !self.nonblocking && self.deadline.is_some_and(|d| Instant::now() >= d) =>
            {
                Err(Errno(110))
            }
            result => result,
        }
    }
}
pub(super) fn attributes(
    factory: &trames_vfs::DescriptorFactory,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let file = factory.mq_descriptor(a[0] as u32)?;
    let update = if a[1] == 0 {
        None
    } else {
        let input = memory.read_array::<64>(a[1]).map_err(|_| Errno(14))?;
        Some(u64::from_le_bytes(input[..8].try_into().unwrap()))
    };
    let old = file.attributes(update)?;
    if a[2] != 0 {
        let mut out = [0u8; 64];
        for (slot, field) in out.chunks_exact_mut(8).zip(old) {
            slot.copy_from_slice(&field.to_le_bytes());
        }
        memory.write_array(a[2], out).map_err(|_| Errno(14))?;
    }
    Ok(0)
}
