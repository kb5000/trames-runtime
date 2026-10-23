// SPDX-License-Identifier: GPL-3.0-or-later
//! One timeout importer for owner and worker execution.
use super::*;
use std::time::Duration;
use trames_memory::CpuMemory;

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
    if a[3] & !9 != 0 {
        return Err(Errno(22));
    }
    if a[3] & 8 == 0 {
        return if a[4] == 0 { Ok(None) } else { Err(Errno(95)) };
    }
    if a[5] != 24 {
        return Err(Errno(22));
    }
    let arg = memory.read_array::<24>(a[4]).map_err(|_| Errno(14))?;
    if u64_at(&arg, 0) != 0 {
        return Err(Errno(95));
    }
    if u32_at(&arg, 12) != 0 {
        return Err(Errno(22));
    }
    let ts = u64_at(&arg, 16);
    if ts == 0 {
        Ok(None)
    } else {
        deadline(memory, ts, 0, clock).map(|d| Some(d.0))
    }
}
