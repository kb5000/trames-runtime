// SPDX-License-Identifier: GPL-3.0-or-later
//! Lazy host edge notifications for guest epoll. No guest FD enters the host API.
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
pub(super) struct Events {
    fd: OwnedFd,
    epoch: [u64; 2],
}
impl Events {
    pub fn new(socket: RawFd) -> Option<Self> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // SAFETY: libc creates a fresh owned descriptor. The event contains
            // only fixed flags/data; socket is a live descriptor held by Socket.
            let raw = unsafe { nix::libc::epoll_create1(nix::libc::EPOLL_CLOEXEC) };
            if raw < 0 {
                return None;
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut event = nix::libc::epoll_event {
                events: (nix::libc::EPOLLIN
                    | nix::libc::EPOLLOUT
                    | nix::libc::EPOLLRDHUP
                    | nix::libc::EPOLLET) as u32,
                u64: 0,
            };
            if unsafe {
                nix::libc::epoll_ctl(fd.as_raw_fd(), nix::libc::EPOLL_CTL_ADD, socket, &mut event)
            } < 0
            {
                return None;
            }
            Some(Self { fd, epoch: [0; 2] })
        }
        #[cfg(target_vendor = "apple")]
        {
            let raw = unsafe { nix::libc::kqueue() };
            if raw < 0 {
                return None;
            }
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let changes = [
                nix::libc::kevent {
                    ident: socket as usize,
                    filter: nix::libc::EVFILT_READ,
                    flags: nix::libc::EV_ADD | nix::libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
                nix::libc::kevent {
                    ident: socket as usize,
                    filter: nix::libc::EVFILT_WRITE,
                    flags: nix::libc::EV_ADD | nix::libc::EV_CLEAR,
                    fflags: 0,
                    data: 0,
                    udata: std::ptr::null_mut(),
                },
            ];
            if unsafe {
                nix::libc::kevent(
                    fd.as_raw_fd(),
                    changes.as_ptr(),
                    2,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            } < 0
            {
                return None;
            }
            Some(Self { fd, epoch: [0; 2] })
        }
    }
    pub fn sample(&mut self) -> [u64; 2] {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let mut event = nix::libc::epoll_event { events: 0, u64: 0 };
            if unsafe { nix::libc::epoll_wait(self.fd.as_raw_fd(), &mut event, 1, 0) } > 0 {
                let flags = event.events;
                if flags
                    & (nix::libc::EPOLLIN
                        | nix::libc::EPOLLRDHUP
                        | nix::libc::EPOLLHUP
                        | nix::libc::EPOLLERR) as u32
                    != 0
                {
                    self.epoch[0] = self.epoch[0].wrapping_add(1);
                }
                if flags & (nix::libc::EPOLLOUT | nix::libc::EPOLLHUP | nix::libc::EPOLLERR) as u32
                    != 0
                {
                    self.epoch[1] = self.epoch[1].wrapping_add(1);
                }
            }
        }
        #[cfg(target_vendor = "apple")]
        {
            // SAFETY: initialized POD storage, bounded element counts, zero
            // timeout. kqueue owns neither guest pointers nor socket lifetime.
            let mut events: [nix::libc::kevent; 2] = unsafe { std::mem::zeroed() };
            let timeout = nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let count = unsafe {
                nix::libc::kevent(
                    self.fd.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    2,
                    &timeout,
                )
            };
            for event in events.iter().take(count.max(0) as usize) {
                let i = usize::from(event.filter == nix::libc::EVFILT_WRITE);
                self.epoch[i] = self.epoch[i].wrapping_add(1);
            }
        }
        self.epoch
    }
}
