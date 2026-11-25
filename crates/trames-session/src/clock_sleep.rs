// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained sleeps whose clocks can advance independently of host Instant.
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use trames_kernel::{signal::IoTask, timers::CpuSleep};
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
    pub fn interruption(&self) -> (u64, Duration) {
        (self.remainder, self.remaining())
    }
}
