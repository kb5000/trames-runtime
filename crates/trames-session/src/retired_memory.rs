// SPDX-License-Identifier: GPL-3.0-or-later
//! Detached original mms finish on existing executors after their last borrower.
//! Membership never covers memory commits, notifications or final destruction.
use std::collections::BTreeMap;
#[cfg(all(test, trames_interpreter_conformance))]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, Weak};
use trames_memory::{Memory, MemoryError};
use trames_shared::{IoSignal, IoSubscription, IoWake};

#[derive(Default)]
pub(crate) struct RetiredMemory {
    pending: Mutex<BTreeMap<u64, Pending>>,
    cleanup: Mutex<BTreeMap<u64, CleanupEntry>>,
    layouts: Mutex<Option<Weak<trames_linux::FileLayouts>>>,
    #[cfg(all(test, trames_interpreter_conformance))]
    owner: OnceLock<(Arc<dyn IoWake>, Arc<IoSignal>)>,
    executor: Mutex<Option<Weak<IoSignal>>>,
}
pub(crate) struct Driver {
    memory: Arc<RetiredMemory>,
    pub signal: Arc<IoSignal>,
}
impl Drop for Driver {
    fn drop(&mut self) {
        let mut executor = self.memory.executor.lock().unwrap();
        if executor
            .as_ref()
            .is_some_and(|current| current.ptr_eq(&Arc::downgrade(&self.signal)))
        {
            *executor = None;
            drop(executor);
            if self.memory.has_ready() {
                self.memory.notify();
            }
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
#[path = "retired_memory_close_tests.rs"]
mod close_tests;
#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;
    use trames_memory::{CpuMemory, Permissions, PAGE_SIZE};

    struct Wake(mpsc::Sender<()>);
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            let _ = self.0.send(());
        }
    }
    fn wake() -> (Arc<dyn IoWake>, Arc<IoSignal>, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        let wake: Arc<dyn IoWake> = Arc::new(Wake(tx));
        let signal = IoSignal::new(0, Arc::downgrade(&wake));
        (wake, signal, rx)
    }
    fn memory() -> (Memory, trames_memory::parallel::View) {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        drop(memory.share());
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        (memory, view)
    }
    #[test]
    fn cancelled_mapping_on_a_shared_old_mm_uses_weak_custody_and_original_idle_wake() {
        let retired = Arc::new(RetiredMemory::default());
        let (_target, signal, _events) = wake();
        let _driver = retired.bind_reader(signal);
        let mut memory = Memory::default();
        let objects = trames_memory::SharedAnonymousPages::fixed_mapping(1);
        memory
            .map_backed(0x1000, objects.clone(), true, Permissions::RW, false)
            .unwrap();
        let lease = memory.mapping_lease(objects);
        let alias = memory.share();
        let id = memory.coordinator_ownership().0;
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        drop(lease);
        retired.retire(alias).unwrap();
        assert_eq!(
            memory.coordinator_ownership().1,
            1,
            "cleanup is not an extra original mm owner"
        );
        assert_eq!(retired.cleanup_domains(), vec![id]);
        // Admission is deliberately reentrant on the owning host thread.
        // Hold custody on a distinct caller to exercise a genuinely busy mm.
        std::thread::scope(|scope| {
            let holder = memory.share();
            let (entered, ready) = mpsc::channel();
            let (release, done) = mpsc::channel();
            scope.spawn(move || {
                let _held = holder.try_admit().unwrap();
                entered.send(()).unwrap();
                done.recv().unwrap();
            });
            ready.recv().unwrap();
            retired.pump().unwrap();
            assert!(!retired.is_empty());
            assert!(
                retired.cleanup_domains().is_empty(),
                "busy custody waits on its original resource"
            );
            release.send(()).unwrap();
        });
        assert_eq!(retired.cleanup_domains(), vec![id]);
        retired.pump().unwrap();
        assert!(
            !retired.is_empty(),
            "the existing execution View still owns its mapping generation"
        );
        drop(view);
        retired.pump().unwrap();
        assert!(retired.is_empty());
        assert!(memory.validate_mapped(0x1000, PAGE_SIZE).is_err());
        assert_eq!(memory.coordinator_ownership().1, 1);
    }
    #[test]
    fn weak_mapping_cleanup_does_not_keep_an_old_mm_alive_after_its_last_owner() {
        let retired = Arc::new(RetiredMemory::default());
        let mut memory = Memory::default();
        let objects = trames_memory::SharedAnonymousPages::fixed_mapping(1);
        memory
            .map_backed(0x1000, objects.clone(), true, Permissions::RW, false)
            .unwrap();
        let lease = memory.mapping_lease(objects);
        let alias = memory.share();
        let view = memory.parallel_view(&mut Default::default()).unwrap();
        drop(lease);
        retired.retire(alias).unwrap();
        drop(memory);
        retired.pump().unwrap();
        assert!(retired.is_empty());
        assert_eq!(view.read_array::<4>(0x1000).unwrap(), [0; 4]);
    }
    #[test]
    fn last_borrower_wake_survives_subscriber_changes_and_repeated_retirement() {
        let retired = Arc::new(RetiredMemory::default());
        let (owner, _, events) = wake();
        retired.bind_owner(|| owner.clone());
        for release_first in [false, true, false, true] {
            let (memory, mut view) = memory();
            let id = memory.coordinator_ownership().0;
            let (_, old_signal, _) = wake();
            let old_subscription = retired.bind_reader(old_signal.clone());
            retired.retire(memory).unwrap();
            view.write_array(0x1000, 9u64.to_le_bytes()).unwrap();
            assert_eq!(retired.read_u64(id, 0x1000), 9);
            assert!(!old_signal.ready());
            drop(old_subscription);
            let mut view = Some(view);
            if release_first {
                drop(view.take());
            }
            let (_target, signal, notified) = wake();
            let _subscription = retired.bind_reader(signal.clone());
            if !release_first {
                drop(view.take());
            }
            notified.recv_timeout(Duration::from_secs(2)).unwrap();
            if release_first {
                events.recv_timeout(Duration::from_secs(2)).unwrap();
            } else {
                assert!(
                    events.try_recv().is_err(),
                    "active source needs no owner notification"
                );
            }
            retired.pump().unwrap();
            assert!(retired.is_empty());
        }
    }
    #[test]
    fn busy_original_mm_releases_executor_until_custody_notification() {
        let retired = Arc::new(RetiredMemory::default());
        let (memory, view) = memory();
        let id = memory.coordinator_ownership().0;
        retired.retire(memory).unwrap();
        let original = retired
            .pending
            .lock()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .memory
            .share();
        let (held, ready) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            let permit = original.try_admit().unwrap();
            drop(original);
            held.send(()).unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(permit);
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(view);
        let (_wake, signal, _) = wake();
        let _subscription = retired.bind_reader(signal.clone());
        signal.reset();
        let pump = retired.clone();
        let (done, completed) = mpsc::channel();
        let executor = std::thread::spawn(move || {
            pump.pump().unwrap();
            done.send(()).unwrap();
        });
        let result = completed.recv_timeout(Duration::from_secs(1));
        // Always release the holder so a failed regression cannot strand it.
        release.send(()).unwrap();
        holder.join().unwrap();
        executor.join().unwrap();
        result.expect("busy mm must release the existing CPU slot");
        assert!(signal.ready(), "original unlock wakes the admitted waiter");
        retired.pump().unwrap();
        assert!(retired.is_empty());
    }
    #[test]
    fn cancelling_a_ready_source_hands_original_memory_back_without_stealing_a_new_driver() {
        let retired = Arc::new(RetiredMemory::default());
        let (owner, _, events) = wake();
        retired.bind_owner(|| owner.clone());
        let (memory, view) = memory();
        let (_first, first, _) = wake();
        let first = retired.bind_reader(first);
        retired.retire(memory).unwrap();
        drop(view);
        assert!(first.signal.ready());
        assert!(events.try_recv().is_err());
        let (_next, next, _) = wake();
        let next = retired.bind_reader(next);
        drop(first);
        assert!(
            events.try_recv().is_err(),
            "old driver cannot unbind its replacement"
        );
        assert!(next.signal.ready());
        drop(next);
        events.recv_timeout(Duration::from_secs(2)).unwrap();
        retired.pump().unwrap();
        assert!(retired.is_empty());
    }
}
struct Pending {
    id: u64,
    memory: Memory,
    signal: Arc<IoSignal>,
    _idle: IoSubscription,
    custody: Option<IoSubscription>,
    reaped: bool,
    closing: Closing,
}
// Keep membership published while one executor owns the original work. A
// concurrent retire marks another pass instead of replacing checked-out state.
struct CleanupEntry {
    signal: Arc<IoSignal>,
    state: Option<CleanupPending>,
    running: bool,
    again: bool,
}
struct CleanupPending {
    root: trames_memory::SharedRoot,
    signal: Arc<IoSignal>,
    subscriptions: Vec<IoSubscription>,
    reaped: bool,
    closing: Closing,
}
#[derive(Default)]
struct Closing {
    resources: Vec<Arc<dyn trames_memory::SyncResource>>,
    result: Option<Arc<trames_linux::FileResult>>,
    subscription: Option<IoSubscription>,
}
impl IoWake for RetiredMemory {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.notify();
    }
}
impl RetiredMemory {
    pub fn bind_layouts(&self, layouts: &Arc<trames_linux::FileLayouts>) {
        *self.layouts.lock().unwrap() = Some(Arc::downgrade(layouts));
    }
    fn finish_closing(
        &self,
        closing: &mut Closing,
        signal: &Arc<IoSignal>,
    ) -> Result<bool, MemoryError> {
        if let Some(result) = &closing.result {
            closing.subscription = Some(result.subscribe(signal));
            if !result.ready() {
                return Ok(false);
            }
            closing.result = None;
            closing.subscription = None;
        }
        if closing.resources.is_empty() {
            return Ok(true);
        }
        let layouts = self
            .layouts
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or(MemoryError::BackingIo(95))?;
        let result = layouts.close_mappings(std::mem::take(&mut closing.resources), 0);
        closing.subscription = Some(result.subscribe(signal));
        let finished = result.ready();
        closing.result = Some(result);
        Ok(finished)
    }
    /// The legacy outside-epoch driver observes this same resource. It is not
    /// needed for completion while an execution epoch has an active subscriber.
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn bind_owner(&self, target: impl FnOnce() -> Arc<dyn IoWake>) {
        self.owner.get_or_init(|| {
            let target = target();
            let signal = IoSignal::new(0, Arc::downgrade(&target));
            (target, signal)
        });
    }
    fn has_ready(&self) -> bool {
        self.pending
            .lock()
            .unwrap()
            .values()
            .any(|p| p.signal.ready())
            || self
                .cleanup
                .lock()
                .unwrap()
                .values()
                .any(|entry| !entry.running && entry.signal.ready())
    }
    fn notify(&self) {
        let executor = self
            .executor
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(executor) = executor {
            executor.notify();
        } else {
            #[cfg(all(test, trames_interpreter_conformance))]
            if let Some((_, signal)) = self.owner.get() {
                signal.notify();
            }
        }
    }
    pub fn bind_reader(self: &Arc<Self>, signal: Arc<IoSignal>) -> Driver {
        *self.executor.lock().unwrap() = Some(Arc::downgrade(&signal));
        if self.has_ready() {
            signal.notify();
        }
        Driver {
            memory: self.clone(),
            signal,
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn is_empty(&self) -> bool {
        self.pending.lock().unwrap().is_empty() && self.cleanup.lock().unwrap().is_empty()
    }
    pub fn retire(self: &Arc<Self>, mut memory: Memory) -> Result<(), MemoryError> {
        let (id, owners) = memory.coordinator_ownership();
        if owners != 1 {
            if memory.mapping_cleanup_pending() {
                let target: Arc<dyn IoWake> = self.clone();
                let signal = IoSignal::new(0, Arc::downgrade(&target));
                let signal = {
                    let mut cleanup = self.cleanup.lock().unwrap();
                    match cleanup.entry(id) {
                        std::collections::btree_map::Entry::Occupied(mut entry) => {
                            entry.get_mut().again = true;
                            entry.get().signal.clone()
                        }
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            let state = CleanupPending {
                                root: memory.shared_root().expect("shared original mm"),
                                signal: signal.clone(),
                                subscriptions: Vec::new(),
                                reaped: false,
                                closing: Default::default(),
                            };
                            entry.insert(CleanupEntry {
                                signal: signal.clone(),
                                state: Some(state),
                                running: false,
                                again: false,
                            });
                            signal
                        }
                    }
                };
                signal.notify();
            }
            return Ok(());
        }
        memory.retire_memory_report();
        let mut closing = Closing::default();
        let reaped = memory.parallel_views_quiescent();
        if reaped {
            memory.reap_mapping_cleanup()?;
            memory.commit_parallel()?;
            closing.resources = memory.take_closed_resources();
            closing.resources.extend(memory.close_resources());
            if closing.resources.is_empty() {
                return Ok(());
            }
        } else {
            memory.commit_retired_parallel()?;
        }
        let target: Arc<dyn IoWake> = self.clone();
        let signal = IoSignal::new(0, Arc::downgrade(&target));
        let idle = memory.subscribe_parallel_idle(&signal);
        if memory.parallel_views_quiescent() {
            // Release can precede publication. This latch survives an early
            // wake whose consumer finds no pending entry yet.
            signal.notify();
        }
        self.publish(Pending {
            id,
            memory,
            signal,
            _idle: idle,
            custody: None,
            reaped,
            closing,
        });
        Ok(())
    }
    fn publish(&self, pending: Pending) {
        let id = pending.id;
        let signal = pending.signal.clone();
        let old = self.pending.lock().unwrap().insert(id, pending);
        assert!(old.is_none(), "one detached original mm owner");
        if signal.ready() {
            self.notify();
        }
    }
    fn take_cleanup(&self, id: u64) -> Option<CleanupPending> {
        let mut cleanup = self.cleanup.lock().unwrap();
        let entry = cleanup.get_mut(&id)?;
        if entry.running || !entry.signal.ready() {
            return None;
        }
        let mut pending = entry.state.take().expect("unclaimed original cleanup");
        entry.running = true;
        if std::mem::take(&mut entry.again) {
            pending.reaped = false;
        }
        Some(pending)
    }
    fn publish_cleanup(&self, id: u64, mut pending: CleanupPending, finished: bool) {
        let signal = pending.signal.clone();
        let mut removed = None;
        let again = {
            let mut cleanup = self.cleanup.lock().unwrap();
            let entry = cleanup
                .get_mut(&id)
                .expect("original cleanup membership remains published");
            let again = std::mem::take(&mut entry.again);
            if finished && !again {
                removed = cleanup.remove(&id);
            } else {
                if again {
                    pending.reaped = false;
                }
                entry.running = false;
                entry.state = Some(pending);
            }
            again
        };
        drop(removed);
        if again {
            signal.notify();
        } else if !finished && signal.ready() {
            self.notify();
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn pump(&self) -> Result<(), MemoryError> {
        self.pump_with_pause(|_| {})
    }
    pub fn pump_with_pause(&self, mut pause: impl FnMut(u64)) -> Result<(), MemoryError> {
        #[cfg(all(test, trames_interpreter_conformance))]
        if let Some((_, signal)) = self.owner.get() {
            signal.reset();
        }
        let cleanup: Vec<_> = self
            .cleanup
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&id, entry)| (!entry.running && entry.signal.ready()).then_some(id))
            .collect();
        for id in cleanup {
            let Some(mut pending) = self.take_cleanup(id) else {
                continue;
            };
            pending.signal.reset();
            let result = (|| {
                if !pending.reaped {
                    pause(id);
                    let status = pending.root.try_reap_mapping_cleanup(&pending.signal)?;
                    pending.reaped = status.finished;
                    pending.subscriptions = status.subscriptions;
                    pending.closing.resources.extend(status.resources);
                }
                if !pending.reaped {
                    return Ok(false);
                }
                self.finish_closing(&mut pending.closing, &pending.signal)
            })();
            match result {
                Ok(finished) => self.publish_cleanup(id, pending, finished),
                Err(error) => {
                    pending.signal.notify();
                    self.publish_cleanup(id, pending, false);
                    return Err(error);
                }
            }
        }
        let ready: Vec<_> = self
            .pending
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&id, p)| p.signal.ready().then_some(id))
            .collect();
        for id in ready {
            let Some(mut pending) = self.pending.lock().unwrap().remove(&id) else {
                continue;
            };
            pending.signal.reset();
            if pending.reaped {
                match self.finish_closing(&mut pending.closing, &pending.signal) {
                    Ok(true) => {}
                    Ok(false) => self.publish(pending),
                    Err(error) => {
                        pending.signal.notify();
                        self.publish(pending);
                        return Err(error);
                    }
                }
                continue;
            }
            let permit = pending.memory.try_admit().or_else(|| {
                pending.custody = pending.memory.subscribe_custody(&pending.signal);
                pending.memory.try_admit()
            });
            let Some(_permit) = permit else {
                self.publish(pending);
                continue;
            };
            pending.custody = None;
            if pending.memory.parallel_views_quiescent() {
                let result = (|| {
                    if !pending.memory.reap_mapping_cleanup()? {
                        return Ok(false);
                    }
                    pending.memory.commit_parallel()?;
                    pending
                        .closing
                        .resources
                        .extend(pending.memory.take_closed_resources());
                    // A retained View can dirty the original inode after an
                    // earlier exit/exec flush. Its final publication must have
                    // its own close before the last original mm is released.
                    pending
                        .closing
                        .resources
                        .extend(pending.memory.close_resources());
                    pending.reaped = true;
                    self.finish_closing(&mut pending.closing, &pending.signal)
                })();
                match result {
                    Ok(true) => {}
                    Ok(false) => self.publish(pending),
                    Err(error) => {
                        pending.signal.notify();
                        self.publish(pending);
                        return Err(error);
                    }
                }
            } else {
                self.publish(pending);
            }
        }
        Ok(())
    }
    /// Cancellation on an old shared mm needs the existing affected-mm pause,
    /// even when that mm still belongs to a CLONE_VM peer outside an exec group.
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn cleanup_domains(&self) -> Vec<u64> {
        self.cleanup
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&id, entry)| {
                (!entry.running
                    && entry.signal.ready()
                    && (entry.again || entry.state.as_ref().is_some_and(|state| !state.reaped)))
                .then_some(id)
            })
            .collect()
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn contains(&self, id: u64) -> bool {
        self.pending.lock().unwrap().contains_key(&id)
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn read_u64(&self, id: u64, address: u64) -> u64 {
        self.pending.lock().unwrap()[&id]
            .memory
            .read_u64(address)
            .unwrap()
    }
}
