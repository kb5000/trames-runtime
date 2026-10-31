// SPDX-License-Identifier: GPL-3.0-or-later
//! Resource notifications, independent of the scheduler and descriptor tables.
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, Weak,
};

pub trait IoWake: Send + Sync {
    fn wake_io(&self, signal: &Arc<IoSignal>);
    fn host_events(&self) -> Option<Arc<crate::HostEvents>> {
        None
    }
}
pub struct IoSignal {
    pub pid: u32,
    fired: AtomicBool,
    target: Weak<dyn IoWake>,
}
impl IoSignal {
    pub fn new(pid: u32, target: Weak<dyn IoWake>) -> Arc<Self> {
        Arc::new(Self {
            pid,
            fired: AtomicBool::new(false),
            target,
        })
    }
    pub fn ready(&self) -> bool {
        self.fired.load(Ordering::Relaxed)
    }
    pub fn reset(&self) {
        // A coalesced notification can precede this retry while the task is
        // already running. Acquire its release RMW before checking an atomic
        // resource again; otherwise clearing a separate relaxed flag can lose
        // both the notification and the counter update on ARM.
        self.fired.swap(false, Ordering::Acquire);
    }
    pub(crate) fn fire(self: &Arc<Self>) {
        if !self.fired.swap(true, Ordering::Release) {
            if let Some(target) = self.target.upgrade() {
                target.wake_io(self);
            }
        }
    }
}
#[derive(Default)]
pub struct Readiness {
    armed: AtomicUsize,
    next: AtomicU64,
    listeners: Mutex<BTreeMap<u64, Weak<IoSignal>>>,
}
pub struct IoSubscription {
    source: Arc<Readiness>,
    id: u64,
    host: Option<crate::HostSubscription>,
    host_failed: bool,
    external: bool,
}
impl Readiness {
    pub fn subscribe(self: &Arc<Self>, signal: &Arc<IoSignal>) -> IoSubscription {
        let mut listeners = self.listeners.lock().unwrap();
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        listeners.insert(id, Arc::downgrade(signal));
        // Subscribe, then retry the resource before parking. Atomic resources
        // pair this RMW with notify_atomic: either the retry sees the change,
        // or the changer sees this subscription. Separate flag/counter loads
        // would allow store buffering and a lost wake on ARM.
        self.armed.fetch_or(1, Ordering::AcqRel);
        IoSubscription {
            source: self.clone(),
            id,
            host: None,
            host_failed: false,
            external: false,
        }
    }
    pub fn notify_atomic(&self) {
        // Also publishes an eventfd change when nobody is subscribed yet.
        if self.armed.fetch_or(0, Ordering::Release) != 0 {
            self.notify();
        }
    }
    pub fn notify_locked(&self) {
        // Pipe retries and mutations already synchronize through the pipe lock.
        if self.armed.load(Ordering::Relaxed) != 0 {
            self.notify();
        }
    }
    fn notify(&self) {
        let signals: Vec<_> = self
            .listeners
            .lock()
            .unwrap()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        // Never enter the scheduler holding a resource or subscription lock.
        for signal in signals {
            signal.fire();
        }
    }
}
impl IoSubscription {
    /// Retain a native readiness registration on the existing executor's poller.
    /// The normal subscribe-then-retry protocol also covers readiness arriving
    /// before this registration; no service thread is introduced.
    pub fn with_host(mut self, fd: impl Into<crate::HostFd>, signal: &Arc<IoSignal>) -> Self {
        // A joined single-task executor waits on its descriptor set directly;
        // it has no HostEvents hub but must still retry after a native wake.
        self.external = true;
        if let Some(events) = signal
            .target
            .upgrade()
            .and_then(|target| target.host_events())
        {
            match events.subscribe(fd, false, signal) {
                Ok(host) => self.host = Some(host),
                Err(_) => self.host_failed = true,
            }
        }
        self
    }
    pub fn external(&self) -> bool {
        self.external
    }
    pub fn rearm_host(&self) -> std::io::Result<()> {
        if self.host_failed {
            return Err(std::io::Error::other("native subscription failed"));
        }
        self.host.as_ref().map_or(Ok(()), |host| host.rearm())
    }
}
impl Drop for IoSubscription {
    fn drop(&mut self) {
        let mut listeners = self.source.listeners.lock().unwrap();
        listeners.remove(&self.id);
        if listeners.is_empty() {
            self.source.armed.fetch_and(!1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Target;
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            panic!("removed listener");
        }
    }
    #[test]
    fn dropped_subscriptions_release_registry_entries_and_disable_notification() {
        let source = Arc::new(Readiness::default());
        let target: Arc<dyn IoWake> = Arc::new(Target);
        let signal = IoSignal::new(7, Arc::downgrade(&target));
        for _ in 0..1024 {
            drop(source.subscribe(&signal));
        }
        assert!(source.listeners.lock().unwrap().is_empty());
        assert_eq!(source.armed.load(Ordering::Relaxed), 0);
        source.notify_atomic();
        assert!(!signal.ready());
    }
}
