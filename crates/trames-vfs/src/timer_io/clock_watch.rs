// SPDX-License-Identifier: GPL-3.0-or-later
//! Native discontinuous CLOCK_REALTIME changes; existing executors wait on FD.
use crate::{Errno, Result};
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
pub(super) struct ClockWatch {
    #[cfg(unix)]
    fd: OwnedFd,
    #[cfg(target_vendor = "apple")]
    token: i32,
}
#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    fn notify_register_file_descriptor(
        name: *const std::ffi::c_char,
        fd: *mut i32,
        flags: i32,
        token: *mut i32,
    ) -> u32;
    fn notify_cancel(token: i32) -> u32;
}
impl ClockWatch {
    pub fn new() -> Result<Self> {
        #[cfg(target_vendor = "apple")]
        {
            Self::register(c"com.apple.system.clock_set")
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let raw =
                libc::timerfd_create(libc::CLOCK_REALTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC);
            if raw < 0 {
                return Err(Errno(5));
            }
            let fd = OwnedFd::from_raw_fd(raw);
            let timer = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: i64::MAX,
                    tv_nsec: 0,
                },
            };
            if libc::timerfd_settime(
                raw,
                libc::TFD_TIMER_ABSTIME | libc::TFD_TIMER_CANCEL_ON_SET,
                &timer,
                std::ptr::null_mut(),
            ) < 0
            {
                return Err(Errno(5));
            }
            Ok(Self { fd })
        }
        #[cfg(not(any(target_vendor = "apple", target_os = "linux")))]
        Err(Errno(95))
    }
    #[cfg(target_vendor = "apple")]
    fn register(name: &std::ffi::CStr) -> Result<Self> {
        let mut raw = -1;
        let mut token = 0;
        // notify_cancel owns/closes the returned original. Retain a distinct
        // duplicate, so cancellation and OwnedFd destruction cannot double-close.
        if unsafe { notify_register_file_descriptor(name.as_ptr(), &mut raw, 0, &mut token) } != 0 {
            return Err(Errno(5));
        }
        let duplicate = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            unsafe {
                notify_cancel(token);
            }
            return Err(Errno(5));
        }
        let result = Self {
            fd: unsafe { OwnedFd::from_raw_fd(duplicate) },
            token,
        };
        let flags = unsafe { libc::fcntl(duplicate, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(duplicate, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(Errno(5));
        }
        Ok(result)
    }
    pub fn fd(&self) -> Option<crate::HostFd> {
        #[cfg(unix)]
        return self.fd.as_fd().try_clone_to_owned().ok().map(Into::into);
        #[cfg(not(unix))]
        None
    }
    pub fn changed(&self) -> bool {
        #[cfg(unix)]
        {
            let mut changed = false;
            loop {
                let mut bytes = [0u8; 64];
                // SAFETY: live owned nonblocking FD and bounded writable bytes.
                let n = unsafe {
                    libc::read(self.fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len())
                };
                if n > 0 {
                    #[cfg(target_vendor = "apple")]
                    {
                        changed = true;
                    }
                    continue;
                }
                if n == 0 {
                    break;
                }
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                #[cfg(target_os = "linux")]
                if e.raw_os_error() == Some(libc::ECANCELED) {
                    changed = true;
                    continue;
                }
                break;
            }
            changed
        }
        #[cfg(not(unix))]
        false
    }
}
#[cfg(target_vendor = "apple")]
impl Drop for ClockWatch {
    fn drop(&mut self) {
        unsafe {
            notify_cancel(self.token);
        }
    }
}
#[cfg(all(test, target_vendor = "apple"))]
mod tests {
    use super::*;
    #[test]
    fn native_clock_event_uses_an_existing_wait_fd_without_setting_system_time() {
        unsafe extern "C" {
            fn notify_post(name: *const std::ffi::c_char) -> u32;
        }
        let name = std::ffi::CString::new(format!(
            "org.trames.test.clock.{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .unwrap();
        let watch = ClockWatch::register(&name).unwrap();
        let raw = watch.fd.as_raw_fd();
        assert!(!watch.changed());
        let timer = crate::TimerFd::new(0);
        timer.state.lock().unwrap().cancel = Some(watch);
        assert_eq!(unsafe { notify_post(name.as_ptr()) }, 0);
        let mut fd = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut fd, 1, 1000) }, 1);
        assert_eq!(timer.poll(1).0, 1);
        assert_eq!(timer.read(8), Err(Errno(125)));
        assert_eq!(timer.read(8), Err(Errno(11)));
        timer.update(Some((std::time::Duration::ZERO, None)));
        assert!(timer.native_fd().is_none());
    }
}
