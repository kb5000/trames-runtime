// SPDX-License-Identifier: GPL-3.0-or-later
//! Environment-wide policy shared across user namespaces and accepted events.
use super::*;
use std::sync::atomic::AtomicI32;

pub(crate) struct Settings([AtomicI32; 4]);
#[derive(Clone, Copy)]
pub(crate) enum Setting {
    Paranoid,
    MlockKb,
    MaxSampleRate,
    CpuTimePercent,
}
impl Default for Settings {
    fn default() -> Self {
        Self(
            [
                2,
                512 + (trames_memory::PAGE_SIZE / 1024) as i32,
                100_000,
                25,
            ]
            .map(AtomicI32::new),
        )
    }
}
impl Setting {
    pub(crate) fn at(path: &[u8]) -> Option<Self> {
        match path {
            b"/proc/sys/kernel/perf_event_paranoid" => Some(Self::Paranoid),
            b"/proc/sys/kernel/perf_event_mlock_kb" => Some(Self::MlockKb),
            b"/proc/sys/kernel/perf_event_max_sample_rate" => Some(Self::MaxSampleRate),
            b"/proc/sys/kernel/perf_cpu_time_max_percent" => Some(Self::CpuTimePercent),
            _ => None,
        }
    }
}
impl Settings {
    pub(crate) fn get(&self, setting: Setting) -> i32 {
        self.0[setting as usize].load(Ordering::Relaxed)
    }
    pub(crate) fn set(&self, setting: Setting, value: i32) -> Result<()> {
        if matches!(setting, Setting::MaxSampleRate) && value < 1 {
            return Err(Errno(22));
        }
        if matches!(setting, Setting::CpuTimePercent) && !(0..=100).contains(&value) {
            return Err(Errno(22));
        }
        self.0[setting as usize].store(value, Ordering::Relaxed);
        Ok(())
    }
    pub(super) fn minimum_period(&self) -> u64 {
        // Software clock PMUs keep a fixed 10us timer floor. The sysctl is
        // frequency admission/interrupt throttling, not a new event period.
        10_000
    }
    pub(super) fn allowance(&self, cpus: usize) -> u64 {
        // Match the signed sysctl's page rounding before unsigned page math.
        let pages = (i64::from(self.get(Setting::MlockKb))
            >> (trames_memory::PAGE_SIZE.trailing_zeros() - 10)) as u64;
        pages
            .wrapping_mul(cpus.max(1) as u64)
            .wrapping_mul(trames_memory::PAGE_SIZE)
    }
    fn admit(&self, attr: &Attr, credentials: &Credentials) -> Result<()> {
        if !attr.exclude_kernel
            && self.get(Setting::Paranoid) > 1
            && !credentials.has_cap(capabilities::PERFMON)
            && !credentials.has_cap(capabilities::SYS_ADMIN)
        {
            return Err(Errno(13));
        }
        if attr
            .frequency
            .is_some_and(|frequency| frequency > self.get(Setting::MaxSampleRate) as u64)
        {
            return Err(Errno(22));
        }
        Ok(())
    }
}
impl Vfs {
    pub(crate) fn perf_settings(&self) -> Arc<Settings> {
        self.credentials
            .user_namespace
            .overflow()
            .1
            .settings
            .clone()
    }
}
impl DescriptorFactory {
    pub fn check_perf_attr(&self, attr: &Attr) -> Result<()> {
        self.credentials
            .user_namespace
            .overflow()
            .1
            .settings
            .admit(attr, &self.credentials)
    }
}

impl DescriptorFactory {
    pub fn check_perf_cpu(&self) -> Result<()> {
        let settings = self
            .credentials
            .user_namespace
            .overflow()
            .1
            .settings
            .clone();
        if settings.get(Setting::Paranoid) > 0
            && !self.credentials.has_cap(capabilities::PERFMON)
            && !self.credentials.has_cap(capabilities::SYS_ADMIN)
        {
            Err(Errno(13))
        } else {
            Ok(())
        }
    }
}
