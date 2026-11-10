// SPDX-License-Identifier: GPL-3.0-or-later
//! The embedding waits on actual transports and resource notifications. This
//! waiter has no guest tasks, scheduler deadlines or dispatch authority.
use crate::{HostEvents, HostFd, HostSubscription, IoSignal, IoSubscription, IoWake};
use std::{
    io,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

pub struct HostWake {
    events: Arc<HostEvents>,
    ready: AtomicBool,
    signal: Arc<IoSignal>,
}
impl HostWake {
    pub fn notify(&self) {
        self.ready.store(true, Ordering::Release);
        self.events.wake();
    }
}
impl IoWake for HostWake {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.notify();
    }
    fn host_events(&self) -> io::Result<Option<Arc<HostEvents>>> {
        Ok(Some(self.events.clone()))
    }
}
pub struct HostWait {
    wake: Arc<HostWake>,
    native: Vec<HostSubscription>,
    resources: Vec<IoSubscription>,
    deadline: Option<Instant>,
}
impl HostWait {
    pub fn new() -> io::Result<Self> {
        let events = HostEvents::new()?;
        let wake = Arc::new_cyclic(|weak: &std::sync::Weak<HostWake>| {
            let target: std::sync::Weak<dyn IoWake> = weak.clone();
            HostWake {
                events,
                ready: AtomicBool::new(false),
                signal: IoSignal::new(0, target),
            }
        });
        Ok(Self {
            wake,
            native: Vec::new(),
            resources: Vec::new(),
            deadline: None,
        })
    }
    pub fn wake(&self) -> Arc<HostWake> {
        self.wake.clone()
    }
    /// Arm before subscriptions and the deciding nonblocking transport pass.
    pub fn begin(&mut self) {
        self.native.clear();
        self.resources.clear();
        self.deadline = None;
        self.wake.events.arm();
        self.wake.ready.swap(false, Ordering::Acquire);
        self.wake.signal.reset();
    }
    pub fn signal(&self) -> &Arc<IoSignal> {
        &self.wake.signal
    }
    pub fn retain(&mut self, subscriptions: impl IntoIterator<Item = IoSubscription>) {
        self.resources.extend(subscriptions);
    }
    pub fn watch(&mut self, fd: impl AsFd, write: bool) -> io::Result<()> {
        self.watch_owned(fd.as_fd().try_clone_to_owned()?.into(), write)
    }
    pub fn watch_owned(&mut self, fd: HostFd, write: bool) -> io::Result<()> {
        self.native
            .push(self.wake.events.subscribe(fd, write, &self.wake.signal)?);
        Ok(())
    }
    /// An actual embedding deadline (for example its requested session expiry).
    pub fn until(&mut self, at: Instant) {
        self.deadline = Some(self.deadline.map_or(at, |old| old.min(at)));
    }
    pub fn wait(&self) -> io::Result<()> {
        let result = if self.wake.ready.swap(false, Ordering::Acquire) {
            Ok(())
        } else {
            self.wake.events.wait(self.deadline)
        };
        self.wake.events.disarm();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::net::UnixStream, time::Duration};

    #[test]
    fn a_notification_between_the_deciding_pass_and_wait_is_latched() {
        let mut wait = HostWait::new().unwrap();
        for _ in 0..100 {
            wait.begin();
            let wake = wait.wake();
            std::thread::spawn(move || wake.notify()).join().unwrap();
            wait.until(Instant::now() + Duration::from_secs(2));
            let start = Instant::now();
            wait.wait().unwrap();
            assert!(start.elapsed() < Duration::from_secs(1));
        }
    }

    #[test]
    fn native_readiness_retains_the_original_descriptor_after_close_and_reuse() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let mut wait = HostWait::new().unwrap();
        wait.begin();
        wait.watch(&reader, false).unwrap();
        drop(reader);
        let (_replacement, _peer) = UnixStream::pair().unwrap();
        writer.write_all(b"original").unwrap();
        wait.until(Instant::now() + Duration::from_secs(2));
        wait.wait().unwrap();
        assert!(wait.signal().ready());
    }

    #[test]
    fn an_idle_embedding_sleeps_until_its_actual_deadline() {
        let mut wait = HostWait::new().unwrap();
        wait.begin();
        let at = Instant::now() + Duration::from_millis(30);
        wait.until(at);
        wait.wait().unwrap();
        assert!(Instant::now() >= at);
        assert!(!wait.signal().ready());
    }
}
