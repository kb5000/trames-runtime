// SPDX-License-Identifier: GPL-3.0-or-later
//! One architectural counter domain shared by software CPU backends.
//! Linux/Android AArch64 uses its user counter ABI directly; other platforms
//! retain the portable one-GHz counter. No task-local timer state is added.

#[cfg(not(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
)))]
use std::{sync::OnceLock, time::Instant};
#[cfg(not(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
)))]
static ORIGIN: OnceLock<Instant> = OnceLock::new();

#[inline]
pub fn frequency() -> u64 {
    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    ))]
    {
        let value;
        // Linux's arm64 user ABI also handles a trapped CNTFRQ read in-kernel.
        unsafe {
            std::arch::asm!("mrs {v},cntfrq_el0",v=out(reg)value,options(nomem,nostack,preserves_flags));
        }
        value
    }
    #[cfg(not(all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    )))]
    {
        1_000_000_000
    }
}

#[inline]
pub fn read() -> u64 {
    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    ))]
    {
        let value;
        // The explicit counter instruction needs ordering with preceding code;
        // this is not an extra fence on ordinary guest loads/stores.
        unsafe {
            std::arch::asm!("isb", "mrs {v},cntvct_el0",v=out(reg)value,options(nostack,preserves_flags));
        }
        value
    }
    #[cfg(not(all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    )))]
    {
        ORIGIN.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }
}

pub fn sample() -> Option<trames_engine::ClockSample> {
    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    ))]
    {
        Some(trames_engine::ClockSample {
            ticks: read(),
            frequency: frequency(),
        })
    }
    #[cfg(not(all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "android")
    )))]
    {
        None
    }
}
