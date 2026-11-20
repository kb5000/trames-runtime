// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained sleeps whose clocks can advance independently of host Instant.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use trames_kernel::{signal::IoTask, timers::CpuSleep};
use trames_memory::CpuMemory;
use trames_vfs::{BootTimer, Errno, IoSignal};

enum Source {
    Process(Arc<CpuSleep>),
    Boot {
        timer: BootTimer,
        fallback: Instant,
        subscription: Mutex<Option<trames_shared::HostSubscription>>,
    },
}
pub(super) struct ClockSleep {
    source: Source,
    remainder: u64,
}
impl ClockSleep {
    pub fn new(
        clock: u32,
        value: Duration,
        absolute: bool,
        remainder: u64,
        boot: trames_linux::Boottime,
        task: &IoTask,
    ) -> Result<Arc<Self>, Errno> {
        let source = if clock == 2 {
            Source::Process(CpuSleep::new(task, value, absolute)?)
        } else {
            let delay = if absolute {
                value.saturating_sub(boot.elapsed())
            } else {
                value
            };
            let fallback = Instant::now().checked_add(delay).ok_or(Errno(22))?;
            Source::Boot {
                timer: BootTimer::new(fallback)?,
                fallback,
                subscription: Mutex::default(),
            }
        };
        Ok(Arc::new(Self { source, remainder }))
    }
    pub fn ready(&self) -> bool {
        match &self.source {
            Source::Process(wait) => wait.ready(),
            Source::Boot { .. } => self.remaining().is_zero(),
        }
    }
    fn remaining(&self) -> Duration {
        match &self.source {
            Source::Process(wait) => wait.remaining(),
            Source::Boot { timer, .. } => timer
                .deadline
                .saturating_sub(trames_shared::boottime::continuous()),
        }
    }
    pub fn deadline(&self) -> Option<Instant> {
        match &self.source {
            Source::Boot { fallback, .. } => Some(*fallback),
            Source::Process(_) => None,
        }
    }
    pub fn bind(&self, signal: &Arc<IoSignal>) -> std::io::Result<()> {
        match &self.source {
            Source::Process(wait) => wait.bind(signal),
            Source::Boot {
                timer,
                subscription,
                ..
            } => {
                *subscription.lock().unwrap() = signal.subscribe_host(
                    || {
                        timer
                            .fd()
                            .ok_or_else(|| std::io::Error::other("cannot duplicate boottime timer"))
                    },
                    false,
                )?;
            }
        }
        Ok(())
    }
    pub fn interrupt(&self, memory: &mut impl CpuMemory) -> u64 {
        interrupted(memory, self.remainder, self.remaining())
    }
}
pub(super) fn interrupted(memory: &mut impl CpuMemory, address: u64, left: Duration) -> u64 {
    if address != 0 {
        let mut timespec = [0; 16];
        timespec[..8].copy_from_slice(&left.as_secs().to_le_bytes());
        timespec[8..].copy_from_slice(&(left.subsec_nanos() as u64).to_le_bytes());
        if memory.write_array(address, timespec).is_err() {
            return 0u64.wrapping_sub(14);
        }
    }
    0u64.wrapping_sub(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    #[test]
    fn interrupt_reports_fault_only_when_copying_and_preserves_nanoseconds() {
        let mut memory = Memory::default();
        let left = Duration::new(3, 17);
        assert_eq!(interrupted(&mut memory, 0, left), (-4i64) as u64);
        assert_eq!(interrupted(&mut memory, 0x1000, left), (-14i64) as u64);
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(interrupted(&mut memory, 0x1000, left), (-4i64) as u64);
        assert_eq!(memory.read_u64(0x1000).unwrap(), 3);
        assert_eq!(memory.read_u64(0x1008).unwrap(), 17);
    }
}
