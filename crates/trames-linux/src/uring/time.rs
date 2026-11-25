// SPDX-License-Identifier: GPL-3.0-or-later
//! One timeout importer for owner and worker execution.
use super::*;
use std::time::Duration;
use trames_memory::CpuMemory;

pub(crate) fn raw_ktime(bytes: [u8; 16]) -> i64 {
    let seconds = i64::from_le_bytes(bytes[..8].try_into().unwrap());
    let nanos = i64::from_le_bytes(bytes[8..].try_into().unwrap());
    if seconds >= i64::MAX / 1_000_000_000 {
        i64::MAX
    } else {
        seconds.wrapping_mul(1_000_000_000).wrapping_add(nanos)
    }
}
pub(crate) fn enter_timeout(
    memory: &impl CpuMemory,
    address: u64,
    flags: u32,
    clock: Instant,
    start: Instant,
) -> Result<Option<Instant>> {
    if address == 0 {
        return Ok(None);
    }
    let value = raw_ktime(memory.read_array::<16>(address).map_err(|_| Errno(14))?);
    let origin = start
        .saturating_duration_since(clock)
        .as_nanos()
        .min(i64::MAX as u128) as i64;
    let absolute = if flags & 32 != 0 {
        value
    } else {
        value.wrapping_add(origin)
    };
    let duration = Duration::from_nanos((absolute as i128 - origin as i128).max(0) as u64);
    Ok(Some(start.checked_add(duration).ok_or(Errno(22))?))
}

pub(crate) fn deadline(
    memory: &impl CpuMemory,
    address: u64,
    flags: u32,
    clock: Instant,
) -> Result<(Instant, Duration)> {
    if flags & !(1 | 4 | 8 | 32) != 0 || flags & 12 == 12 {
        return Err(Errno(22));
    }
    let duration = crate::timer::duration(memory, address)?;
    let now = Instant::now();
    let delta = if flags & 1 == 0 {
        duration
    } else if flags & 8 != 0 {
        duration.saturating_sub(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Errno(5))?,
        )
    } else {
        duration.saturating_sub(now.saturating_duration_since(clock))
    };
    Ok((now.checked_add(delta).ok_or(Errno(22))?, duration))
}

pub(crate) fn enter_deadline(
    a: [u64; 6],
    memory: &impl CpuMemory,
    clock: Instant,
) -> Result<Option<Instant>> {
    let a = crate::direct::uring::enter_args(a)?;
    if a[3] & 1 == 0 {
        return Ok(None);
    }
    if a[3] & 8 == 0 {
        return Ok(None);
    }
    if a[5] != 24 {
        return Err(Errno(22));
    }
    let arg = memory.read_array::<24>(a[4]).map_err(|_| Errno(14))?;
    let start = Instant::now();
    let deadline = enter_timeout(memory, u64_at(&arg, 16), a[3] as u32, clock, start)?;
    let minimum = u32_at(&arg, 12);
    if minimum != 0 {
        return Ok(start.checked_add(Duration::from_micros(minimum as u64)));
    }
    Ok(deadline)
}
