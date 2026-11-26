// SPDX-License-Identifier: GPL-3.0-or-later
//! Close-only monitoring without consuming a suspended protocol's bytes/FDs.
use std::{io, os::fd::AsRawFd, os::unix::net::UnixStream};
#[cfg(target_vendor = "apple")]
use std::{
    os::fd::{FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
};

pub struct PeerClose {
    socket: UnixStream,
    #[cfg(target_vendor = "apple")]
    monitor: OnceLock<OwnedFd>,
    #[cfg(target_vendor = "apple")]
    closed: AtomicBool,
}
impl From<UnixStream> for PeerClose {
    fn from(socket: UnixStream) -> Self {
        Self {
            socket,
            #[cfg(target_vendor = "apple")]
            monitor: OnceLock::new(),
            #[cfg(target_vendor = "apple")]
            closed: AtomicBool::new(false),
        }
    }
}
impl PeerClose {
    /// Descriptor/mask for the existing event loop. Queued input alone must
    /// not repeatedly wake an executor while its resource is still unavailable.
    pub fn wait_fd(&self) -> io::Result<(i32, i16)> {
        #[cfg(target_vendor = "apple")]
        {
            Ok((self.monitor()?.as_raw_fd(), libc::POLLIN))
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            Ok((self.socket.as_raw_fd(), 0))
        }
    }
    pub fn closed(&self) -> io::Result<bool> {
        #[cfg(target_vendor = "apple")]
        {
            if self.closed.load(Ordering::Relaxed) {
                return Ok(true);
            }
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: owned kqueue and initialized output/timeout; no socket
            // bytes or ancillary descriptors are read by this metadata query.
            let count = unsafe {
                libc::kevent(
                    self.monitor()?.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    &timeout,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            let closed = count != 0 && event.flags & (libc::EV_EOF | libc::EV_ERROR) != 0;
            if closed {
                self.closed.store(true, Ordering::Relaxed);
            }
            Ok(self.closed.load(Ordering::Relaxed))
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let mut fd = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: 0,
                revents: 0,
            };
            // SAFETY: one initialized poll entry for a retained descriptor.
            let count = unsafe { libc::poll(&mut fd, 1, 0) };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(fd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0)
        }
    }
    #[cfg(target_vendor = "apple")]
    fn monitor(&self) -> io::Result<&OwnedFd> {
        if let Some(fd) = self.monitor.get() {
            return Ok(fd);
        }
        // SAFETY: kqueue returns a new owned descriptor or -1.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: fcntl changes only this owned descriptor's close-on-exec flag.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let event = libc::kevent {
            ident: self.socket.as_raw_fd() as libc::uintptr_t,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: retained socket and kqueue, initialized registration. EV_CLEAR
        // consumes the initial input edge; peer EOF supplies a separate edge
        // even while unread protocol bytes remain queued on Darwin sockets.
        if unsafe {
            libc::kevent(
                fd.as_raw_fd(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let _ = self.monitor.set(fd);
        Ok(self.monitor.get().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn close_with_queued_input_wakes_without_consuming_the_protocol() {
        let (mut peer, mut socket) = UnixStream::pair().unwrap();
        let monitor = PeerClose::from(socket.try_clone().unwrap());
        peer.write_all(b"queued").unwrap();
        assert!(!monitor.closed().unwrap());
        drop(peer);
        let (fd, events) = monitor.wait_fd().unwrap();
        let mut fd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: one initialized entry for the monitor's retained descriptor.
        assert_eq!(unsafe { libc::poll(&mut fd, 1, 1000) }, 1);
        assert!(monitor.closed().unwrap());
        let mut bytes = [0; 6];
        socket.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"queued");
    }
}
