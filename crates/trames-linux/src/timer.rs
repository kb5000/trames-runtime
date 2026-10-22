// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared timerfd ABI. Creation/FD installation remains with the VFS owner.
use crate::state::Linux;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use trames_memory::{Access, CpuMemory};
use trames_vfs::{Errno, TimerFd};

pub(crate) fn duration(memory: &impl CpuMemory, address: u64) -> Result<Duration, Errno> {
    let sec = memory.read_u64(address).map_err(|_| Errno(14))?;
    let ns = memory
        .read_u64(address.checked_add(8).ok_or(Errno(14))?)
        .map_err(|_| Errno(14))?;
    if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
        return Err(Errno(22));
    }
    Ok(Duration::new(sec, ns as u32))
}
pub fn timerfd_control(
    timer: &TimerFd,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    started: Instant,
) -> Result<u64, Errno> {
    let output = if number == 87 { a[1] } else { a[3] };
    if number == 87 || output != 0 {
        Linux::check(memory, output, 32, Access::Write)?;
    }
    let new = if number == 86 {
        if a[1] & !3 != 0 {
            return Err(Errno(22));
        }
        if a[1] & 2 != 0 {
            return Err(Errno(95));
        }
        let interval = duration(memory, a[2])?;
        let value = duration(memory, a[2].checked_add(16).ok_or(Errno(14))?)?;
        let delta = if a[1] & 1 == 0 {
            value
        } else {
            let now = if timer.clock == 0 {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Errno(5))?
            } else {
                started.elapsed()
            };
            value.saturating_sub(now)
        };
        let deadline = if value.is_zero() {
            None
        } else {
            Some(Instant::now().checked_add(delta).ok_or(Errno(22))?)
        };
        Some((interval, deadline))
    } else {
        None
    };
    let (interval, remaining) = timer.update(new);
    if number == 87 || output != 0 {
        let mut bytes = [0; 32];
        for (offset, d) in [(0, interval), (16, remaining)] {
            bytes[offset..offset + 8].copy_from_slice(&d.as_secs().to_le_bytes());
            bytes[offset + 8..offset + 16]
                .copy_from_slice(&(d.subsec_nanos() as u64).to_le_bytes());
        }
        memory.write(output, &bytes).map_err(|_| Errno(14))?;
    }
    Ok(0)
}
