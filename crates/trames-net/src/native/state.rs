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
        if events & 1 != 0 {
            wanted |= PollFlags::POLLIN;
        }
        if events & 2 != 0 {
            wanted |= PollFlags::POLLPRI;
        }
        if events & 4 != 0 {
            wanted |= PollFlags::POLLOUT;
        }
        let mut fds = [PollFd::new(self.as_fd(), wanted)];
        poll(&mut fds, PollTimeout::ZERO).map_err(from_errno)?;
        let ready = fds[0].revents().unwrap_or(PollFlags::empty());
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
        Ok(result)
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
