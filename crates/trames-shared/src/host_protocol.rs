// SPDX-License-Identifier: GPL-3.0-or-later
//! Original protocol resources run on existing executors, independently of guest waits.
use crate::{HostEvents, HostFd, HostSubscription, IoSignal, IoSubscription, IoWake, Readiness};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Mutex, Weak,
    },
    time::Instant,
};
pub type ProtocolInterests = (Vec<(usize, HostFd)>, Option<Instant>);

/// Owns transport state only. Never add task, CPU, memory or syscall authority.
pub trait HostProtocol: Send + Sync {
    fn identity(&self) -> usize;
    fn alive(&self) -> bool;
    fn changed(&self) -> Arc<Readiness>;
    fn progress(&self, signal: &Arc<IoSignal>) -> io::Result<()>;
    fn interests(&self) -> io::Result<ProtocolInterests>;
}
struct Entry {
    protocol: Arc<dyn HostProtocol>,
    signal: Arc<IoSignal>,
    _changed: IoSubscription,
    sources: BTreeMap<usize, HostSubscription>,
    deadline: Option<Instant>,
    armed: bool,
}
#[derive(Default)]
pub struct HostProtocols {
    entries: Mutex<BTreeMap<usize, Arc<Mutex<Entry>>>>,
    progressing: Mutex<()>,
    signals: Mutex<BTreeSet<usize>>,
    dirty: AtomicBool,
    external: AtomicBool,
    has_deadline: AtomicBool,
    deadline: Mutex<Option<Instant>>,
}
impl HostProtocols {
    pub fn register(&self, protocol: Arc<dyn HostProtocol>, target: Weak<dyn IoWake>) {
        let id = protocol.identity();
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(&id) {
            return;
        }
        let signal = IoSignal::new(0, target);
        let changed = protocol.changed().subscribe(&signal);
        self.signals
            .lock()
            .unwrap()
            .insert(Arc::as_ptr(&signal) as usize);
        entries.insert(
            id,
            Arc::new(Mutex::new(Entry {
                protocol,
                signal,
                _changed: changed,
                sources: BTreeMap::new(),
                deadline: None,
                armed: false,
            })),
        );
        self.dirty.store(true, Relaxed);
    }
    pub fn wake(&self, signal: &Arc<IoSignal>) -> bool {
        if signal.pid != 0
            || !self
                .signals
                .lock()
                .unwrap()
                .contains(&(Arc::as_ptr(signal) as usize))
        {
            return false;
        }
        self.dirty.store(true, Relaxed);
        true
    }
    pub fn due(&self) -> bool {
        self.dirty.load(Relaxed)
            || self.has_deadline.load(Relaxed)
                && self
                    .deadline
                    .lock()
                    .unwrap()
                    .is_some_and(|d| d <= Instant::now())
    }
    pub fn external(&self) -> bool {
        self.external.load(Relaxed)
    }
    pub fn deadline(&self) -> Option<Instant> {
        if self.has_deadline.load(Relaxed) {
            *self.deadline.lock().unwrap()
        } else {
            None
        }
    }
    pub fn progress(&self, events: &impl Fn() -> io::Result<Arc<HostEvents>>) -> io::Result<()> {
        let Ok(_turn) = self.progressing.try_lock() else {
            return Ok(());
        };
        self.dirty.store(false, Relaxed);
        let entries: Vec<_> = self
            .entries
            .lock()
            .unwrap()
            .iter()
            .map(|(&id, e)| (id, e.clone()))
            .collect();
        let mut retired = Vec::new();
        let mut deadline = None;
        let mut external = false;
        for (id, entry) in entries {
            let mut e = entry.lock().unwrap();
            if !e.protocol.alive() {
                self.signals
                    .lock()
                    .unwrap()
                    .remove(&(Arc::as_ptr(&e.signal) as usize));
                retired.push(id);
                continue;
            }
            if !e.armed || e.signal.ready() || e.deadline.is_some_and(|d| d <= Instant::now()) {
                e.signal.reset();
                e.protocol.progress(&e.signal)?;
                let (sources, next) = e.protocol.interests()?;
                let ids: BTreeSet<_> = sources.iter().map(|(id, _)| *id).collect();
                e.sources.retain(|id, _| ids.contains(id));
                for (id, fd) in sources {
                    if let Some(s) = e.sources.get(&id) {
                        s.rearm()?;
                    } else {
                        let s = events()?.subscribe(fd, false, &e.signal)?;
                        e.sources.insert(id, s);
                    }
                }
                e.deadline = next;
                e.armed = true;
            }
            external |= !e.sources.is_empty();
            deadline = match (deadline, e.deadline) {
                (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
                (a, b) => a.or(b),
            };
        }
        if !retired.is_empty() {
            let mut entries = self.entries.lock().unwrap();
            for id in retired {
                entries.remove(&id);
            }
        }
        *self.deadline.lock().unwrap() = deadline;
        self.has_deadline.store(deadline.is_some(), Relaxed);
        self.external.store(external, Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::{fd::AsFd, unix::net::UnixStream},
        sync::atomic::AtomicUsize,
        time::Duration,
    };
    #[derive(Default)]
    struct Wake {
        registry: HostProtocols,
        calls: AtomicUsize,
    }
    impl IoWake for Wake {
        fn wake_io(&self, signal: &Arc<IoSignal>) {
            assert!(self.registry.wake(signal));
            // Notification can re-enter registry metadata on an executor.
            self.registry.deadline();
            self.calls.fetch_add(1, Relaxed);
        }
    }
    struct Resource {
        live: AtomicBool,
        changed: Arc<Readiness>,
        input: Option<UnixStream>,
        bytes: AtomicUsize,
        turns: AtomicUsize,
    }
    impl HostProtocol for Resource {
        fn identity(&self) -> usize {
            self as *const Self as usize
        }
        fn alive(&self) -> bool {
            self.live.load(Relaxed)
        }
        fn changed(&self) -> Arc<Readiness> {
            self.changed.clone()
        }
        fn progress(&self, _: &Arc<IoSignal>) -> io::Result<()> {
            self.turns.fetch_add(1, Relaxed);
            if let Some(input) = &self.input {
                let mut input = input;
                let mut b = [0; 32];
                while let Ok(n) = input.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    self.bytes.fetch_add(n, Relaxed);
                }
            }
            Ok(())
        }
        fn interests(&self) -> io::Result<ProtocolInterests> {
            Ok((
                self.input
                    .as_ref()
                    .map(|s| {
                        s.as_fd()
                            .try_clone_to_owned()
                            .map(|fd| vec![(1, fd.into())])
                    })
                    .transpose()?
                    .unwrap_or_default(),
                None,
            ))
        }
    }
    fn resource(input: Option<UnixStream>) -> Arc<Resource> {
        Arc::new(Resource {
            live: AtomicBool::new(true),
            changed: Arc::default(),
            input,
            bytes: AtomicUsize::new(0),
            turns: AtomicUsize::new(0),
        })
    }
    fn register(wake: &Arc<Wake>, resource: &Arc<Resource>) {
        let target: Arc<dyn IoWake> = wake.clone();
        wake.registry
            .register(resource.clone(), Arc::downgrade(&target));
    }
    #[test]
    fn idle_protocol_has_no_periodic_timer_or_host_queue_and_final_owner_retires() {
        let wake = Arc::new(Wake::default());
        let r = resource(None);
        register(&wake, &r);
        register(&wake, &r);
        wake.registry
            .progress(&|| panic!("idle protocol allocated a host poller"))
            .unwrap();
        assert_eq!(r.turns.load(Relaxed), 1);
        assert!(!wake.registry.due());
        assert!(!wake.registry.external());
        assert!(wake.registry.deadline().is_none());
        r.live.store(false, Relaxed);
        r.changed.notify_atomic();
        assert!(wake.registry.due());
        wake.registry
            .progress(&|| panic!("retired protocol allocated a host poller"))
            .unwrap();
        assert!(wake.registry.entries.lock().unwrap().is_empty());
        assert!(wake.registry.signals.lock().unwrap().is_empty());
        assert!(!wake.registry.due());
    }
    #[test]
    fn original_fd_drives_sleeping_protocol_and_rearms_without_guest_wait() {
        let (input, mut output) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        let wake = Arc::new(Wake::default());
        let r = resource(Some(input));
        register(&wake, &r);
        let events = HostEvents::new().unwrap();
        wake.registry.progress(&|| Ok(events.clone())).unwrap();
        assert!(wake.registry.external());
        assert!(wake.registry.deadline().is_none());
        for expected in [3, 6] {
            output.write_all(b"abc").unwrap();
            events
                .wait(Some(Instant::now() + Duration::from_secs(1)))
                .unwrap();
            assert!(wake.registry.due());
            wake.registry.progress(&|| Ok(events.clone())).unwrap();
            assert_eq!(r.bytes.load(Relaxed), expected);
            assert!(!wake.registry.due());
        }
        r.live.store(false, Relaxed);
        r.changed.notify_atomic();
        wake.registry.progress(&|| Ok(events.clone())).unwrap();
        assert!(!wake.registry.external());
    }
}
