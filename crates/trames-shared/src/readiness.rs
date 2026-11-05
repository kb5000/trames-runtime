// SPDX-License-Identifier: GPL-3.0-or-later
//! Resource notifications, independent of the scheduler and descriptor tables.
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock, Weak,
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
    exclusive: Option<Box<ExclusiveWake>>,
}
struct ExclusiveWake {
    key: u64,
    parent: Weak<IoSignal>,
    ready: Box<dyn Fn() -> bool + Send + Sync>,
}
impl IoSignal {
    pub fn new(pid: u32, target: Weak<dyn IoWake>) -> Arc<Self> {
        Arc::new(Self {
            pid,
            fired: AtomicBool::new(false),
            target,
            exclusive: None,
        })
    }
    /// A wait-scoped exclusive interest. The predicate checks the original
    /// resource after its mutation lock has been released. Weak ownership must
    /// not keep an epoll target or a sleeping task alive after last close.
    pub fn exclusive(
        parent: &Arc<Self>,
        key: u64,
        ready: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            pid: parent.pid,
            fired: AtomicBool::new(false),
            target: parent.target.clone(),
            exclusive: Some(Box::new(ExclusiveWake {
                key,
                parent: Arc::downgrade(parent),
                ready: Box::new(ready),
            })),
        })
    }
    pub(crate) fn exclusive_key(&self) -> Option<u64> {
        self.exclusive.as_ref().map(|w| w.key)
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
    pub fn notify(self: &Arc<Self>) {
        self.fire();
    }
    pub(crate) fn fire(self: &Arc<Self>) -> bool {
        if let Some(wake) = &self.exclusive {
            return (wake.ready)() && wake.parent.upgrade().is_some_and(|p| p.fire());
        }
        if !self.fired.swap(true, Ordering::Release) {
            if let Some(target) = self.target.upgrade() {
                target.wake_io(self);
                return true;
            }
        }
        false
    }
}
/// Wake ordinary listeners and one eligible exclusive listener per original
/// open description. Already-woken tasks do not consume another wakeup.
pub(crate) fn notify(signals: &[Arc<IoSignal>]) -> std::collections::BTreeSet<u64> {
    let mut selected = std::collections::BTreeSet::new();
    for signal in signals {
        if let Some(key) = signal.exclusive_key() {
            if !selected.contains(&key) && signal.fire() {
                selected.insert(key);
            }
        } else {
            signal.fire();
        }
    }
    selected
}
#[derive(Default)]
pub struct Readiness {
    armed: AtomicUsize,
    next: AtomicU64,
    listeners: Mutex<BTreeMap<u64, Weak<IoSignal>>>,
    driver: OnceLock<Weak<dyn ReadinessDriver>>,
}
/// A shared native adapter attaches its existing event queue to the caller's
/// idle executor. The resource keeps only a weak reference, never a service
/// thread or a cycle through the adapter's owned guest endpoint.
pub trait ReadinessDriver: Send + Sync {
    fn external(&self) -> bool {
        true
    }
    fn notification_only(&self) -> bool {
        false
    }
    fn attach(&self, events: Arc<crate::HostEvents>) -> std::io::Result<()>;
}
/// A resource can acquire a native event source after a task already parked.
/// Publish changes through its Readiness; the existing executor rearms it.
pub trait HostSource: Send + Sync {
    fn revision(&self) -> u64;
    fn fd(&self) -> std::io::Result<Option<crate::HostFd>>;
}
struct DynamicHost {
    source: Weak<dyn HostSource>,
    signal: Weak<IoSignal>,
    state: Mutex<DynamicState>,
}
#[derive(Default)]
struct DynamicState {
    revision: Option<u64>,
    host: Option<crate::HostSubscription>,
    external: bool,
}
impl DynamicHost {
    fn rearm(&self) -> std::io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let Some(source) = self.source.upgrade() else {
            let previous = state.host.take();
            state.external = false;
            state.revision = None;
            drop(state);
            drop(previous);
            return Ok(());
        };
        let revision = source.revision();
        if state.revision != Some(revision) {
            let fd = source.fd()?;
            let external = fd.is_some();
            let signal = self.signal.upgrade();
            let events = signal
                .as_ref()
                .and_then(|s| s.target.upgrade())
                .and_then(|t| t.host_events());
            let host = match (fd, events, signal.as_ref()) {
                (Some(fd), Some(events), Some(signal)) => {
                    Some(events.subscribe(fd, false, signal)?)
                }
                _ => None,
            };
            let previous = std::mem::replace(&mut state.host, host);
            state.external = external;
            state.revision = Some(revision);
            drop(state);
            drop(previous);
            return Ok(());
        }
        state.host.as_ref().map_or(Ok(()), |host| host.rearm())
    }
}
pub struct IoSubscription {
    source: Option<Arc<Readiness>>,
    id: u64,
    host: Option<crate::HostSubscription>,
    host_failed: bool,
    external: bool,
    dynamic: Option<Box<DynamicHost>>,
    retained_signal: Option<Arc<IoSignal>>,
}
impl Readiness {
    pub fn set_driver(&self, driver: Weak<dyn ReadinessDriver>) {
        if let Some(current) = self.driver.get() {
            assert!(current.ptr_eq(&driver), "one native driver per resource");
            return;
        }
        if let Err(driver) = self.driver.set(driver) {
            assert!(
                self.driver.get().unwrap().ptr_eq(&driver),
                "one native driver per resource"
            );
        }
    }
    pub fn subscribe(self: &Arc<Self>, signal: &Arc<IoSignal>) -> IoSubscription {
        let mut listeners = self.listeners.lock().unwrap();
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        listeners.insert(id, Arc::downgrade(signal));
        // Subscribe, then retry the resource before parking. Atomic resources
        // pair this RMW with notify_atomic: either the retry sees the change,
        // or the changer sees this subscription. Separate flag/counter loads
        // would allow store buffering and a lost wake on ARM.
        self.armed.fetch_or(1, Ordering::AcqRel);
        drop(listeners);
        let driver = self.driver.get().and_then(Weak::upgrade);
        let host_failed = driver
            .as_ref()
            .filter(|d| d.external())
            .is_some_and(|driver| {
                signal
                    .target
                    .upgrade()
                    .and_then(|t| t.host_events())
                    .is_some_and(|events| driver.attach(events).is_err())
            });
        IoSubscription {
            source: Some(self.clone()),
            id,
            host: None,
            host_failed,
            external: false,
            dynamic: None,
            retained_signal: None,
        }
    }
    pub fn notify_atomic(&self) {
        // Also publishes an eventfd change when nobody is subscribed yet.
        if self.armed.fetch_or(0, Ordering::Release) != 0 {
            self.notify();
        }
    }
    /// Publish a resource unlock while excluding its own maintenance listener.
    /// Normal waiters and exclusive-wake selection keep their original behavior.
    /// This is only used by an actual completion handler, not ordinary I/O.
    pub fn notify_atomic_except(&self, excluded: &Arc<IoSignal>) {
        if self.armed.fetch_or(0, Ordering::Release) == 0 {
            return;
        }
        let signals: Vec<_> = self
            .listeners
            .lock()
            .unwrap()
            .values()
            .filter_map(Weak::upgrade)
            .filter(|s| !Arc::ptr_eq(s, excluded))
            .collect();
        notify(&signals);
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
        notify(&signals);
    }
}
impl IoSubscription {
    pub fn retain_signal(mut self, signal: Arc<IoSignal>) -> Self {
        self.retained_signal = Some(signal);
        self
    }
    /// Register a native event queue directly, without inventing a guest
    /// readiness resource or a shared listener lock. The queue owns no watched
    /// socket; closing the guest socket is independent of this subscription.
    /// Registration failures use the executor's existing host-wait fallback.
    pub fn native(fd: std::io::Result<crate::HostFd>, signal: &Arc<IoSignal>) -> Self {
        let mut subscription = Self {
            source: None,
            id: 0,
            host: None,
            host_failed: false,
            external: true,
            dynamic: None,
            retained_signal: None,
        };
        match fd {
            Ok(fd) => subscription.with_host(fd, signal),
            Err(_) => {
                subscription.host_failed = true;
                subscription
            }
        }
    }
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
    pub fn with_host_source(
        mut self,
        source: Weak<dyn HostSource>,
        signal: &Arc<IoSignal>,
    ) -> Self {
        self.dynamic = Some(Box::new(DynamicHost {
            source,
            signal: Arc::downgrade(signal),
            state: Mutex::default(),
        }));
        if self.dynamic.as_ref().unwrap().rearm().is_err() {
            self.host_failed = true;
        }
        self
    }
    pub fn notification_external(&self) -> bool {
        self.source
            .as_ref()
            .and_then(|s| s.driver.get())
            .and_then(Weak::upgrade)
            .is_some_and(|d| d.notification_only() && d.external())
    }
    pub fn external(&self) -> bool {
        if self
            .source
            .as_ref()
            .and_then(|s| s.driver.get())
            .and_then(Weak::upgrade)
            .is_some_and(|d| d.external())
        {
            return true;
        }
        self.dynamic
            .as_ref()
            .map_or(self.external, |d| d.state.lock().unwrap().external)
    }
    pub fn rearm_host(&self) -> std::io::Result<()> {
        if self.host_failed {
            return Err(std::io::Error::other("native subscription failed"));
        }
        if let Some(dynamic) = &self.dynamic {
            return dynamic.rearm();
        }
        self.host.as_ref().map_or(Ok(()), |host| host.rearm())
    }
}
impl Drop for IoSubscription {
    fn drop(&mut self) {
        let Some(source) = &self.source else { return };
        let mut listeners = source.listeners.lock().unwrap();
        listeners.remove(&self.id);
        if listeners.is_empty() {
            source.armed.fetch_and(!1, Ordering::Relaxed);
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
