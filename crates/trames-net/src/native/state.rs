// SPDX-License-Identifier: GPL-3.0-or-later
//! Connection/error state belongs to the original transport, not an owner copy.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

// The failure cause and its consumable SO_ERROR bit change in one word. These
// are resource metadata; they do not publish guest bytes or require barriers.
const PENDING: u64 = 8;
pub(super) struct State {
    value: AtomicU64,
    pub(super) blocking_failed: AtomicBool,
}
impl State {
    pub(super) fn new(connection: Connection) -> Self {
        Self {
            value: AtomicU64::new(Self::encode(connection)),
            blocking_failed: AtomicBool::new(false),
        }
    }
    fn encode(connection: Connection) -> u64 {
        match connection {
            Connection::Idle => 0,
            Connection::Connecting => 1,
            Connection::Connected => 2,
            Connection::Listening => 3,
            Connection::Failed(error) => 4 | PENDING | ((error as u64) << 32),
        }
    }
    pub(super) fn connection(&self) -> Connection {
        let value = self.value.load(Relaxed);
        match value & 7 {
            0 => Connection::Idle,
            1 => Connection::Connecting,
            2 => Connection::Connected,
            3 => Connection::Listening,
            _ => Connection::Failed((value >> 32) as u32),
        }
    }
    pub(super) fn set_connection(&self, connection: Connection) {
        self.value.store(Self::encode(connection), Relaxed);
    }
    pub(super) fn pending_error(&self) -> Option<u32> {
        let value = self.value.load(Relaxed);
        (value & PENDING != 0).then_some((value >> 32) as u32)
    }
    pub(super) fn take_error(&self) -> Option<u32> {
        let value = self.value.fetch_and(!PENDING, Relaxed);
        (value & PENDING != 0).then_some((value >> 32) as u32)
    }
}
impl Endpoint {
    pub(super) fn poll(&self, events: u16) -> Result<u16> {
        let mut wanted = PollFlags::empty();
        if events & 0x2001 != 0 {
            wanted |= PollFlags::POLLIN;
        }
        if events & 2 != 0 {
            wanted |= PollFlags::POLLPRI;
        }
        if events & 4 != 0 {
            wanted |= PollFlags::POLLOUT;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let (ready, read_hangup) = {
            // nix's PollFlags omits POLLRDHUP and rejects unknown revents.
            // Keep the original native poll, preserving that Linux event bit.
            let mut fd = nix::libc::pollfd {
                fd: self.as_fd().as_raw_fd(),
                events: wanted.bits()
                    | if events & 0x2000 != 0 {
                        nix::libc::POLLRDHUP
                    } else {
                        0
                    },
                revents: 0,
            };
            // SAFETY: one initialized host pollfd, live owned FD, zero timeout.
            if unsafe { nix::libc::poll(&mut fd, 1, 0) } < 0 {
                return Err(from_io(io::Error::last_os_error()));
            }
            (
                PollFlags::from_bits_truncate(fd.revents),
                fd.revents & nix::libc::POLLRDHUP != 0,
            )
        };
        #[cfg(target_vendor = "apple")]
        let ready = {
            let mut fds = [PollFd::new(self.as_fd(), wanted)];
            poll(&mut fds, PollTimeout::ZERO).map_err(from_errno)?;
            fds[0].revents().unwrap_or(PollFlags::empty())
        };
        let mut result = 0;
        for (native, guest) in [
            (PollFlags::POLLIN, 1),
            (PollFlags::POLLPRI, 2),
            (PollFlags::POLLOUT, 4),
            (PollFlags::POLLERR, 8),
            (PollFlags::POLLHUP, 16),
            (PollFlags::POLLNVAL, 32),
        ] {
            if ready.contains(native) {
                result |= guest;
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if read_hangup {
            result |= 0x2000;
        }
        #[cfg(target_vendor = "apple")]
        if events & 0x2000 != 0
            && ready.contains(PollFlags::POLLIN)
            && matches!(self.socket, NativeSocket::Tcp(_))
            && self.state.connection() == Connection::Connected
        {
            // Darwin has no POLLRDHUP. Query the original TCP state only for
            // requested, readable half-close observations, including queued data.
            // A peek alone misses FIN while unread payload remains buffered.
            let mut info: nix::libc::tcp_connection_info = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&info) as nix::libc::socklen_t;
            // SAFETY: initialized local host struct and its exact writable size.
            let ok = unsafe {
                nix::libc::getsockopt(
                    self.as_fd().as_raw_fd(),
                    nix::libc::IPPROTO_TCP,
                    nix::libc::TCP_CONNECTION_INFO,
                    (&mut info as *mut nix::libc::tcp_connection_info).cast(),
                    &mut length,
                )
            } == 0;
            if ok && matches!(info.tcpi_state, 0 | 5 | 7 | 8 | 10) {
                result |= 0x2000;
            }
        }
        Ok(result & (events | 8 | 16 | 32))
    }
    // Only connection completion serializes its host readiness/error sampling
    // and state transition. Ordinary TCP byte calls never take this lock.
    pub(super) fn complete_connect(
        &self,
        policy: impl FnOnce(SocketAddr) -> Result<()>,
    ) -> Result<bool> {
        let _completion = self.completion.lock().unwrap();
        if self.state.connection() == Connection::Connecting && self.poll(4)? & (4 | 8 | 16) != 0 {
            if let Some(error) = self.control().take_error().map_err(from_io)? {
                self.state
                    .set_connection(Connection::Failed(from_io(error).0));
            } else {
                let check = self
                    .control()
                    .peer_addr()
                    .map_err(from_io)
                    .and_then(|a| a.as_socket().ok_or(NetError(5)))
                    .and_then(policy);
                if let Err(error) = check {
                    self.state.set_connection(Connection::Failed(error.0));
                    let _ = self.control().shutdown(Shutdown::Both);
                } else {
                    self.state.set_connection(Connection::Connected);
                }
            }
        }
        match self.state.connection() {
            Connection::Connecting => Ok(false),
            Connection::Connected => Ok(true),
            Connection::Failed(error) => Err(NetError(error)),
            _ => Err(NetError(107)),
        }
    }
}
