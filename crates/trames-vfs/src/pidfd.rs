// SPDX-License-Identifier: GPL-3.0-or-later
//! A pidfd retains only the identity and two terminal transitions of its target.
use super::*;
use std::sync::atomic::AtomicU8;

pub struct PidFd {
    pid: u32,
    state: AtomicU8,
    changed: Arc<Readiness>,
}

impl PidFd {
    pub fn new(pid: u32, exited: bool, reaped: bool) -> Self {
        Self {
            pid,
            state: AtomicU8::new(if reaped { 2 } else { u8::from(exited) }),
            changed: Arc::default(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn publish(&self, reaped: bool) {
        let state = if reaped { 2 } else { 1 };
        if self.state.fetch_max(state, Ordering::Relaxed) < state {
            self.changed.notify_atomic();
        }
    }
}

impl DirectPoll for PidFd {
    fn identity(&self) -> usize {
        self as *const Self as usize
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let state = self.state.load(Ordering::Relaxed);
        let mask = match state {
            0 => 0,
            1 => events & 0x41,
            _ => events & 0x41 | 0x10,
        };
        (mask, [u64::from(state), 0])
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
}

pub struct PendingPidFd {
    slot: fd_table::ReservedFd,
    description: Descriptor,
}
impl PendingPidFd {
    pub fn number(&self) -> u32 {
        self.slot.number()
    }
    pub fn publish(self) -> Result<u32> {
        self.slot.publish(self.description, None)
    }
}
impl DescriptorFactory {
    pub fn reserve_pidfd(&self, target: Arc<PidFd>, flags: u32) -> Result<PendingPidFd> {
        let slot = self.files.reserve()?;
        let description = events::anonymous_descriptor(
            self.open_id(),
            flags | O_CLOEXEC,
            events::Anonymous::Pid(target),
        );
        Ok(PendingPidFd { slot, description })
    }
}
impl FdFlags {
    pub fn pidfd(&self, fd: u32) -> Result<(Arc<PidFd>, bool)> {
        let descriptor = self.descriptor_control(fd)?;
        descriptor.pidfd()
    }
}
