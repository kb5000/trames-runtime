// SPDX-License-Identifier: GPL-3.0-or-later
//! Structural admission for one original mapped backing, not guest byte access.
//! A publication lease lives until both its original mm commit and all retained
//! Views have returned. Pending mutations exclude new publications; existing
//! readers are asked to quiesce on their ordinary executor readiness.
use crate::MemoryReport;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use trames_shared::{IoSignal, IoSubscription, Readiness};

pub struct Layout {
    identity: u64,
    state: Mutex<State>,
    pending: AtomicBool,
    changed: Arc<Readiness>,
    stop: Arc<Readiness>,
}
#[derive(Default)]
struct State {
    next: u64,
    readers: BTreeMap<u64, Weak<Reader>>,
    writers: BTreeSet<u64>,
    active: Option<u64>,
}
struct Reader {
    layout: Arc<Layout>,
    id: u64,
    owner: MemoryReport,
}
#[derive(Clone)]
pub struct LayoutRead(Arc<Reader>);
pub struct LayoutWrite {
    layout: Arc<Layout>,
    id: u64,
}
/// The accepted mutation owns this token through native completion. Moving the
/// operation to the disk pool does not release publication exclusion early.
pub struct LayoutExclusive(LayoutWrite);

/// The original mm retains one publication until dirty-byte commit. Each View
/// holds the same publication across cloning and cache-generation replacement.
/// It contains backing-level leases only; ordinary translations do not use it.
#[derive(Default)]
pub(crate) struct Publication {
    pub(crate) leases: BTreeMap<u64, LayoutRead>,
}
impl Publication {
    pub(crate) fn pending(&self) -> bool {
        self.leases.values().any(LayoutRead::pending)
    }
    pub(crate) fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.leases
            .values()
            .map(|lease| lease.subscribe_stop(signal))
            .collect()
    }
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            identity: crate::new_backing_identity(),
            state: Mutex::default(),
            pending: AtomicBool::new(false),
            changed: Arc::default(),
            stop: Arc::default(),
        }
    }
}
impl Layout {
    pub fn identity(&self) -> u64 {
        self.identity
    }
    pub fn pending(&self) -> bool {
        // This is only a quiescence hint for existing readers. New readers
        // and actual mutation admission still check the original object lock.
        // No guest-byte ordering is provided or needed by this metadata flag.
        self.pending.load(Ordering::Relaxed)
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
    pub fn try_read(self: &Arc<Self>, owner: MemoryReport) -> Option<LayoutRead> {
        let mut state = self.state.lock().unwrap();
        if !state.writers.is_empty() {
            return None;
        }
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        let reader = Arc::new(Reader {
            layout: self.clone(),
            id,
            owner,
        });
        state.readers.insert(id, Arc::downgrade(&reader));
        Some(LayoutRead(reader))
    }
    pub fn write(self: &Arc<Self>) -> LayoutWrite {
        let mut state = self.state.lock().unwrap();
        let id = state.next;
        state.next = state.next.wrapping_add(1);
        state.writers.insert(id);
        self.pending.store(true, Ordering::Relaxed);
        drop(state);
        self.stop.notify_atomic();
        LayoutWrite {
            layout: self.clone(),
            id,
        }
    }
    /// Stable original mm identities, including cold owners and retained old
    /// generations. No task table, PID lookup or byte operation runs here.
    pub fn readers(&self) -> Vec<MemoryReport> {
        let readers: Vec<_> = self
            .state
            .lock()
            .unwrap()
            .readers
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        let mut owners = Vec::<MemoryReport>::new();
        for reader in readers {
            if !owners
                .iter()
                .any(|owner| owner.same_resource(&reader.owner))
            {
                owners.push(reader.owner.clone());
            }
        }
        owners
    }
}
impl LayoutRead {
    pub fn identity(&self) -> u64 {
        self.0.layout.identity()
    }
    pub fn pending(&self) -> bool {
        self.0.layout.pending()
    }
    pub fn subscribe_stop(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        let subscription = self.0.layout.stop.subscribe(signal);
        if self.pending() {
            signal.notify();
        }
        subscription
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        let mut state = self.layout.state.lock().unwrap();
        assert!(state.readers.remove(&self.id).is_some());
        let ready = state.readers.is_empty() && !state.writers.is_empty();
        drop(state);
        if ready {
            self.layout.changed.notify_atomic();
        }
    }
}
impl LayoutWrite {
    pub fn layout(&self) -> &Arc<Layout> {
        &self.layout
    }
    pub fn ready(&self) -> bool {
        let state = self.layout.state.lock().unwrap();
        state.active.is_none() && state.readers.is_empty()
    }
    pub fn try_enter(self) -> Result<LayoutExclusive, Self> {
        let mut state = self.layout.state.lock().unwrap();
        if state.active.is_some() || !state.readers.is_empty() {
            drop(state);
            return Err(self);
        }
        state.active = Some(self.id);
        drop(state);
        Ok(LayoutExclusive(self))
    }
}
impl LayoutExclusive {
    pub fn layout(&self) -> &Arc<Layout> {
        self.0.layout()
    }
}
impl Drop for LayoutWrite {
    fn drop(&mut self) {
        let mut state = self.layout.state.lock().unwrap();
        assert!(state.writers.remove(&self.id));
        self.layout
            .pending
            .store(!state.writers.is_empty(), Ordering::Relaxed);
        if state.active == Some(self.id) {
            state.active = None;
        }
        drop(state);
        self.layout.changed.notify_atomic();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Memory, Permissions};
    use std::sync::mpsc;
    use std::time::Duration;
    use trames_shared::IoWake;
    struct Wake(mpsc::Sender<()>);
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.send(()).unwrap();
        }
    }
    fn wake() -> (Arc<dyn IoWake>, Arc<IoSignal>, mpsc::Receiver<()>) {
        let (send, receive) = mpsc::channel();
        let target: Arc<dyn IoWake> = Arc::new(Wake(send));
        let signal = IoSignal::new(0, Arc::downgrade(&target));
        (target, signal, receive)
    }
    #[test]
    fn original_publications_and_retained_generations_delay_only_their_backing() {
        let mut memory = Memory::default();
        memory
            .map(0x1000, crate::PAGE_SIZE, Permissions::RW)
            .unwrap();
        let owner = memory.memory_report();
        let layout = Arc::new(Layout::default());
        let unrelated = Arc::new(Layout::default());
        let publication = layout.try_read(owner.clone()).unwrap();
        let view = publication.clone();
        let (_target, stop, receive) = wake();
        let _subscription = view.subscribe_stop(&stop);
        let writer = layout.write();
        receive.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(layout.try_read(owner.clone()).is_none());
        assert!(unrelated.try_read(owner.clone()).is_some());
        assert!(!writer.ready());
        assert_eq!(layout.readers().len(), 1);
        assert!(layout.readers()[0].same_resource(&owner));
        drop(view);
        assert!(
            !writer.ready(),
            "mm must commit before releasing its publication"
        );
        let (_target, changed, receive) = wake();
        let _subscription = layout.subscribe(&changed);
        drop(publication);
        receive.recv_timeout(Duration::from_secs(1)).unwrap();
        let exclusive = writer.try_enter().ok().unwrap();
        assert!(layout.try_read(owner.clone()).is_none());
        drop(exclusive);
        assert!(layout.try_read(owner).is_some());
    }
    #[test]
    fn cancellation_and_overlapping_writers_keep_original_exclusion_and_wakeups() {
        let memory = Memory::default();
        let owner = memory.memory_report();
        let layout = Arc::new(Layout::default());
        let first = layout.write().try_enter().ok().unwrap();
        let second = layout.write();
        let second = second.try_enter().err().unwrap();
        let (_target, signal, receive) = wake();
        let _subscription = layout.subscribe(&signal);
        drop(first);
        receive.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            layout.try_read(owner.clone()).is_none(),
            "another accepted mutation remains"
        );
        assert!(second.ready());
        signal.reset();
        drop(second);
        receive.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(layout.try_read(owner).is_some());
    }
}
