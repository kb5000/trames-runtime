// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared timerfd ABI over retained timers, including worker-created resources.
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use trames_memory::CpuMemory;
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
    timerfd_control_with_boot(timer, number, a, memory, started, None)
}
pub fn timerfd_control_with_boot(
    timer: &TimerFd,
    number: u32,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
    started: Instant,
    boot: Option<trames_shared::boottime::Boottime>,
) -> Result<u64, Errno> {
    let output = if number == 87 { a[1] } else { a[3] };
    let new = timerfd_input(number, a, memory)?;
    let bytes = timerfd_update(timer, new, started, boot)?;
    if number == 87 || output != 0 {
        crate::time_read::copy_bytes(memory, output, &bytes)?;
    }
    Ok(0)
}
pub(crate) struct TimerFdInput {
    interval: Duration,
    value: Duration,
    flags: u32,
}
pub(crate) fn timerfd_input(
    number: u32,
    a: [u64; 6],
    memory: &impl CpuMemory,
) -> Result<Option<TimerFdInput>, Errno> {
    if number != 86 {
        return Ok(None);
    }
    // get_itimerspec64 precedes flags, duration validation and fdget. Read the
    // whole descriptor before interpreting either timespec.
    let bytes = memory.read_array::<32>(a[2]).map_err(|_| Errno(14))?;
    let flags = a[1] as u32;
    if flags & !3 != 0 {
        return Err(Errno(22));
    }
    let decode = |offset: usize| {
        let seconds = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let nanos = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        if seconds > i64::MAX as u64 || nanos >= 1_000_000_000 {
            return Err(Errno(22));
        }
        Ok(Duration::new(seconds, nanos as u32))
    };
    Ok(Some(TimerFdInput {
        interval: decode(0)?,
        value: decode(16)?,
        flags,
    }))
}
pub(crate) fn timerfd_update(
    timer: &TimerFd,
    input: Option<TimerFdInput>,
    started: Instant,
    boot: Option<trames_shared::boottime::Boottime>,
) -> Result<[u8; 32], Errno> {
    let new = if let Some(TimerFdInput {
        interval,
        value,
        flags,
    }) = input
    {
        // timerfd_setup converts both validated timespecs through ktime_set;
        // large positive seconds saturate instead of rejecting the syscall.
        let ktime = |value: Duration| {
            if value.as_secs() >= i64::MAX as u64 / 1_000_000_000 {
                Duration::from_nanos(i64::MAX as u64)
            } else {
                value
            }
        };
        let (interval, value) = (ktime(interval), ktime(value));
        let delta = if flags & 1 == 0 {
            value
        } else {
            let now = if matches!(timer.clock, 0 | 8) {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| Errno(5))?
            } else if matches!(timer.clock, 7 | 9) {
                boot.map_or_else(|| started.elapsed(), |b| b.elapsed())
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
        Some((
            interval,
            deadline,
            (matches!(timer.clock, 0 | 8) && flags & 3 == 3).then_some(value),
        ))
    } else {
        None
    };
    let (interval, remaining) = timer.update_mode(new)?;
    let mut bytes = [0; 32];
    for (offset, d) in [(0, interval), (16, remaining)] {
        bytes[offset..offset + 8].copy_from_slice(&d.as_secs().to_le_bytes());
        bytes[offset + 8..offset + 16].copy_from_slice(&(d.subsec_nanos() as u64).to_le_bytes());
    }
    Ok(bytes)
}
