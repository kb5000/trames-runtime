// SPDX-License-Identifier: GPL-3.0-or-later
//! Copied signal-wait ABI; retries use the accepted set and deadline.
use super::*;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum SignalWait {
    Timed {
        mask: u64,
        info: u64,
        deadline: Option<Instant>,
    },
    Suspend {
        mask: u64,
    },
}
impl SignalWait {
    pub fn prepare(number: u32, a: [u64; 6], memory: &impl CpuMemory) -> Result<Self, Errno> {
        if a[if number == 133 { 1 } else { 3 }] != 8 {
            return Err(Errno(22));
        }
        let mask =
            u64::from_le_bytes(memory.read_array::<8>(a[0]).map_err(|_| Errno(14))?) & !UNBLOCKABLE;
        if number == 133 {
            return Ok(Self::Suspend { mask });
        }
        let deadline = if a[2] == 0 {
            None
        } else {
            let bytes = memory.read_array::<16>(a[2]).map_err(|_| Errno(14))?;
            let sec = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let ns = u64::from_le_bytes(bytes[8..].try_into().unwrap());
            if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
                return Err(Errno(22));
            }
            Some(
                Instant::now()
                    .checked_add(Duration::new(sec, ns as u32))
                    .ok_or(Errno(22))?,
            )
        };
        Ok(Self::Timed {
            mask,
            info: a[1],
            deadline,
        })
    }
    pub fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Timed { deadline, .. } => *deadline,
            Self::Suspend { .. } => None,
        }
    }
    pub fn ready(&self, task: &IoTask) -> bool {
        match *self {
            Self::Timed { mask, deadline, .. } => {
                task.pending_bits() & mask != 0 || deadline.is_some_and(|d| d <= Instant::now())
            }
            Self::Suspend { .. } => task.ready(),
        }
    }
    /// Linux consumes the selected signal before attempting siginfo copyout.
    /// A competing signalfd/sigtimedwait reader may consume it first.
    pub fn check(
        &self,
        task: &IoTask,
        memory: &mut impl CpuMemory,
        namespace: &trames_vfs::PidNamespace,
    ) -> Option<Result<u64, Errno>> {
        let Self::Timed {
            mask,
            info,
            deadline,
        } = *self
        else {
            return None;
        };
        if let Some((sig, mut value)) = task.dequeue(mask) {
            if value.timer.is_none() && value.fault.is_none() && value.poll.is_none() {
                value.sender = namespace.local(value.sender);
            }
            return Some((|| {
                if info != 0 {
                    let mut bytes = [0; 128];
                    write_siginfo(&mut bytes, sig, value);
                    memory.write_array(info, bytes).map_err(|_| Errno(14))?;
                }
                Ok(sig as u64)
            })());
        }
        deadline
            .filter(|d| *d <= Instant::now())
            .map(|_| Err(Errno(11)))
    }
}
