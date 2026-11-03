// SPDX-License-Identifier: GPL-3.0-or-later
//! Host continuous time includes sleep; Linux MONOTONIC keeps its existing Instant.
use std::time::{Duration, Instant};
#[derive(Clone, Copy)]
pub struct Boottime {
    origin: Duration,
}
impl Default for Boottime {
    fn default() -> Self {
        Self::from_start(Instant::now())
    }
}
impl Boottime {
    pub fn from_start(started: Instant) -> Self {
        let now = Instant::now();
        Self {
            origin: continuous().saturating_sub(now.saturating_duration_since(started)),
        }
    }
    pub fn elapsed(self) -> Duration {
        continuous().saturating_sub(self.origin)
    }
}
pub fn continuous() -> Duration {
    #[cfg(target_vendor = "apple")]
    {
        #[repr(C)]
        struct Timebase {
            numer: u32,
            denom: u32,
        }
        unsafe extern "C" {
            fn mach_continuous_time() -> u64;
            fn mach_timebase_info(info: *mut Timebase) -> i32;
        }
        static SCALE: std::sync::OnceLock<(u32, u32)> = std::sync::OnceLock::new();
        let &(numer, denom) = SCALE.get_or_init(|| {
            let mut info = Timebase { numer: 0, denom: 0 };
            // Public host clock metadata; no guest memory or retained pointer.
            assert_eq!(unsafe { mach_timebase_info(&mut info) }, 0);
            (info.numer, info.denom)
        });
        let ns = unsafe { mach_continuous_time() } as u128 * numer as u128 / denom as u128;
        Duration::new((ns / 1_000_000_000) as u64, (ns % 1_000_000_000) as u32)
    }
    #[cfg(target_os = "linux")]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // The native clock is independent of guest clock IDs and address spaces.
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) },
            0
        );
        Duration::new(time.tv_sec as u64, time.tv_nsec as u32)
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
    {
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        START.get_or_init(Instant::now).elapsed()
    }
}
