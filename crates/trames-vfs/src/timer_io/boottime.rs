// SPDX-License-Identifier: GPL-3.0-or-later
//! A sleep-aware native wait FD, consumed by the existing event hub/executors.
use crate::{Errno, HostFd, Result};
use std::{
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};
pub(super) struct BootTimer {
    pub deadline: Duration,
    pub armed: Duration,
    fd: OwnedFd,
}
impl BootTimer {
    pub fn new(deadline: Instant) -> Result<Self> {
        #[cfg(target_vendor = "apple")]
        let raw = unsafe { libc::kqueue() };
        #[cfg(target_os = "linux")]
        let raw = unsafe {
            libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
        let raw = -1;
        if raw < 0 {
            return Err(Errno(5));
        }
        // A newly owned descriptor; no guest-selected host FD or retained pointer.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(Errno(5));
        }
        let delay = deadline.saturating_duration_since(Instant::now());
        let mut timer = Self {
            armed: Duration::ZERO,
            deadline: trames_shared::boottime::continuous()
                .checked_add(delay)
                .ok_or(Errno(22))?,
            fd,
        };
        timer.arm(delay)?;
        Ok(timer)
    }
    pub fn fd(&self) -> Option<HostFd> {
        self.fd.as_fd().try_clone_to_owned().ok().map(Into::into)
    }
    pub fn arm(&mut self, delay: Duration) -> Result<()> {
        let delay = delay
            .max(Duration::from_nanos(1))
            .min(Duration::from_nanos(i64::MAX as u64));
        self.armed = trames_shared::boottime::continuous() + delay;
        #[cfg(target_vendor = "apple")]
        {
            // NOTE_MACH_CONTINUOUS_TIME applies to relative timers as well;
            // these one-shot events become ready on wake, without a new thread.
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            event.ident = 1;
            event.filter = libc::EVFILT_TIMER;
            event.flags = libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT;
            event.fflags = libc::NOTE_NSECONDS | libc::NOTE_MACH_CONTINUOUS_TIME;
            event.data = i64::try_from(delay.as_nanos()).map_err(|_| Errno(22))? as _;
            if unsafe {
                libc::kevent(
                    self.fd.as_raw_fd(),
                    &event,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            } < 0
            {
                return Err(Errno(5));
            }
        }
        #[cfg(target_os = "linux")]
        {
            let timer = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: i64::try_from(delay.as_secs()).map_err(|_| Errno(22))? as _,
                    tv_nsec: delay.subsec_nanos() as _,
                },
            };
            if unsafe {
                libc::timerfd_settime(self.fd.as_raw_fd(), 0, &timer, std::ptr::null_mut())
            } < 0
            {
                return Err(Errno(5));
            }
        }
        Ok(())
    }
    pub fn drain(&self) {
        #[cfg(target_vendor = "apple")]
        unsafe {
            let mut event: libc::kevent = std::mem::zeroed();
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            libc::kevent(
                self.fd.as_raw_fd(),
                std::ptr::null(),
                0,
                &mut event,
                1,
                &timeout,
            );
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let mut count = 0u64;
            libc::read(self.fd.as_raw_fd(), (&mut count as *mut u64).cast(), 8);
        }
    }
}
