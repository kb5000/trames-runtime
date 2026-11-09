// SPDX-License-Identifier: GPL-3.0-or-later
//! Resource notifications, independent of the scheduler and descriptor tables.
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, OnceLock, Weak,
};

pub trait IoWake: Send + Sync {
    fn wake_io(&self, signal: &Arc<IoSignal>);
    fn host_events(&self) -> std::io::Result<Option<Arc<crate::HostEvents>>> {
        Ok(None)
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
    /// A missing embedding capability differs from a failed native backend.
    pub fn host_events(&self) -> std::io::Result<Option<Arc<crate::HostEvents>>> {
        self.target
            .upgrade()
            .map_or(Ok(None), |target| target.host_events())
    }
    pub fn subscribe_host(
        self: &Arc<Self>,
        fd: impl FnOnce() -> std::io::Result<crate::HostFd>,
        write: bool,
    ) -> std::io::Result<Option<crate::HostSubscription>> {
        self.host_events()?
            .map(|events| events.subscribe(fd()?, write, self))
            .transpose()
    }
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
enum HostBinding {
    Registered(crate::HostSubscription),
    Direct(crate::HostFd, bool),
}
impl HostBinding {
    fn rearm(&self) -> std::io::Result<()> {
        match self {
            Self::Registered(subscription) => subscription.rearm(),
            Self::Direct(..) => Ok(()),
        }
    }
    fn direct_interest(&self) -> std::io::Result<Option<(crate::HostFd, bool)>> {
        match self {
            Self::Registered(_) => Ok(None),
            Self::Direct(fd, write) => fd.try_clone().map(|fd| Some((fd, *write))),
        }
    }
}
struct DynamicHost {
    source: Weak<dyn HostSource>,
    signal: Weak<IoSignal>,
    state: Mutex<DynamicState>,
}
#[derive(Default)]
struct DynamicState {
    revision: Option<u64>,
    host: Option<HostBinding>,
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
                .map_or(Ok(None), |signal| signal.host_events())?;
            let host = match (fd, events, signal.as_ref()) {
                (Some(fd), Some(events), Some(signal)) => Some(HostBinding::Registered(
                    events.subscribe(fd, false, signal)?,
                )),
                (Some(fd), _, _) => Some(HostBinding::Direct(fd, false)),
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
    host: Option<HostBinding>,
    host_error: Option<Arc<std::io::Error>>,
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
        let host_error = driver
            .as_ref()
            .filter(|d| d.external())
            .and_then(|driver| match signal.host_events() {
                Ok(Some(events)) => driver.attach(events).err(),
                Ok(None) => None,
                Err(error) => Some(error),
            })
            .map(Arc::new);
        IoSubscription {
            source: Some(self.clone()),
            id,
            host: None,
            host_error,
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
    /// Registration failures retain their original host cause for the executor.
    pub fn native(fd: std::io::Result<crate::HostFd>, signal: &Arc<IoSignal>) -> Self {
        Self::native_direction(fd, false, signal)
    }
    pub fn native_direction(
        fd: std::io::Result<crate::HostFd>,
        write: bool,
        signal: &Arc<IoSignal>,
    ) -> Self {
        let mut subscription = Self {
            source: None,
            id: 0,
            host: None,
            host_error: None,
            external: true,
            dynamic: None,
            retained_signal: None,
        };
        match fd {
            Ok(fd) => subscription.attach_host(fd, write, signal),
            Err(error) => {
                subscription.host_error = Some(Arc::new(error));
                subscription
            }
        }
    }
    /// Attach to the caller's existing poller, or retain the original native
    /// descriptor for a caller-driven wait. Absence of a hub is not absence of
    /// the native event source; backend failure retains its original cause.
    pub fn with_host(self, fd: impl Into<crate::HostFd>, signal: &Arc<IoSignal>) -> Self {
        self.attach_host(fd.into(), false, signal)
    }
    fn attach_host(mut self, fd: crate::HostFd, write: bool, signal: &Arc<IoSignal>) -> Self {
        self.external = true;
        let result = signal.host_events().and_then(|events| match events {
            Some(events) => events
                .subscribe(fd, write, signal)
                .map(HostBinding::Registered),
            None => Ok(HostBinding::Direct(fd, write)),
        });
        match result {
            Ok(host) => self.host = Some(host),
            Err(error) => {
                self.host_error.get_or_insert_with(|| Arc::new(error));
            }
        }
        self
    }
    /// Original descriptors for an embedding's existing direct wait loop.
    /// Hub-backed registrations need no duplicate or second native poller.
    pub fn direct_wait_interest(&self) -> std::io::Result<Option<(crate::HostFd, bool)>> {
        if let Some(dynamic) = &self.dynamic {
            return dynamic
                .state
                .lock()
                .unwrap()
                .host
                .as_ref()
                .map_or(Ok(None), HostBinding::direct_interest);
        }
        self.host
            .as_ref()
            .map_or(Ok(None), HostBinding::direct_interest)
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
        if let Err(error) = self.dynamic.as_ref().unwrap().rearm() {
            self.host_error.get_or_insert_with(|| Arc::new(error));
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
        if let Some(error) = &self.host_error {
            return Err(error.raw_os_error().map_or_else(
                || std::io::Error::new(error.kind(), error.clone()),
                std::io::Error::from_raw_os_error,
            ));
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
    #[test]
    fn hubless_native_interests_preserve_direction_and_drive_the_original_signal() {
        use std::os::fd::AsFd;
        struct Caller;
        impl IoWake for Caller {
            fn wake_io(&self, _: &Arc<IoSignal>) {}
        }
        let target: Arc<dyn IoWake> = Arc::new(Caller);
        for write in [false, true] {
            let signal = IoSignal::new(7, Arc::downgrade(&target));
            let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
            let subscription = IoSubscription::native_direction(
                socket.as_fd().try_clone_to_owned().map(Into::into),
                write,
                &signal,
            );
            subscription.rearm_host().unwrap();
            let (fd, direction) = subscription.direct_wait_interest().unwrap().unwrap();
            assert_eq!(direction, write);
            let events = crate::HostEvents::new().unwrap();
            let registration = events.subscribe(fd, direction, &signal).unwrap();
            if !write {
                use std::io::Write;
                peer.write_all(b"r").unwrap();
            }
            events
                .wait(Some(
                    std::time::Instant::now() + std::time::Duration::from_secs(2),
                ))
                .unwrap();
            assert!(signal.ready());
            drop(registration);
        }
    }
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
    struct Failed;
    impl IoWake for Failed {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
        fn host_events(&self) -> std::io::Result<Option<Arc<crate::HostEvents>>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "original backend creation failure",
            ))
        }
    }
    struct Events(Arc<crate::HostEvents>);
    impl IoWake for Events {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
        fn host_events(&self) -> std::io::Result<Option<Arc<crate::HostEvents>>> {
            Ok(Some(self.0.clone()))
        }
    }
    #[test]
    fn native_subscriptions_distinguish_missing_backend_from_original_host_errors() {
        let missing: Arc<dyn IoWake> = Arc::new(Target);
        let failed: Arc<dyn IoWake> = Arc::new(Failed);
        for (target, failure) in [(missing, false), (failed, true)] {
            let signal = IoSignal::new(1, Arc::downgrade(&target));
            let result = signal.subscribe_host(
                || panic!("capability selection precedes fd acquisition"),
                false,
            );
            if failure {
                let error = result.err().unwrap();
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(error
                    .to_string()
                    .contains("original backend creation failure"));
                let (socket, _) = std::os::unix::net::UnixStream::pair().unwrap();
                use std::os::fd::AsFd;
                let subscription = IoSubscription::native(
                    socket.as_fd().try_clone_to_owned().map(Into::into),
                    &signal,
                );
                let error = subscription.rearm_host().unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert!(error
                    .to_string()
                    .contains("original backend creation failure"));
            } else {
                assert!(result.unwrap().is_none());
            }
        }
        let target: Arc<dyn IoWake> = Arc::new(Events(crate::HostEvents::new().unwrap()));
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let error = signal
            .subscribe_host(
                || {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "original duplicate failure",
                    ))
                },
                false,
            )
            .err()
            .unwrap();
        assert_eq!(error.kind(), std::io::ErrorKind::OutOfMemory);
        assert!(error.to_string().contains("original duplicate failure"));
        let subscription =
            IoSubscription::native(Err(std::io::Error::from_raw_os_error(24)), &signal);
        for _ in 0..2 {
            assert_eq!(
                subscription.rearm_host().unwrap_err().raw_os_error(),
                Some(24)
            );
        }
    }
    #[test]
    fn driver_attach_and_dynamic_source_failures_keep_their_original_error() {
        struct Driver;
        impl ReadinessDriver for Driver {
            fn attach(&self, _: Arc<crate::HostEvents>) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "original attach failure",
                ))
            }
        }
        struct Dynamic;
        impl HostSource for Dynamic {
            fn revision(&self) -> u64 {
                1
            }
            fn fd(&self) -> std::io::Result<Option<crate::HostFd>> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "original dynamic source failure",
                ))
            }
        }
        let target: Arc<dyn IoWake> = Arc::new(Events(crate::HostEvents::new().unwrap()));
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let driver: Arc<dyn ReadinessDriver> = Arc::new(Driver);
        let source = Arc::new(Readiness::default());
        source.set_driver(Arc::downgrade(&driver));
        let subscription = source.subscribe(&signal);
        let error = subscription.rearm_host().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("original attach failure"));
        drop(subscription);
        assert!(source.listeners.lock().unwrap().is_empty());
        let dynamic: Arc<dyn HostSource> = Arc::new(Dynamic);
        let source = Arc::new(Readiness::default());
        let subscription = source
            .subscribe(&signal)
            .with_host_source(Arc::downgrade(&dynamic), &signal);
        let error = subscription.rearm_host().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(error
            .to_string()
            .contains("original dynamic source failure"));
    }
}
