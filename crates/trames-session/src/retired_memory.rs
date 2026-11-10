// SPDX-License-Identifier: GPL-3.0-or-later
//! Detached original mms finish on existing executors after their last borrower.
//! Membership never covers memory commits, notifications or final destruction.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use trames_memory::{Memory, MemoryError};
use trames_shared::{IoSignal, IoSubscription, IoWake};

#[derive(Default)]
pub(crate) struct RetiredMemory {
    pending: Mutex<BTreeMap<u64, Pending>>,
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
}
impl IoWake for RetiredMemory {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.notify();
    }
}
impl RetiredMemory {
    /// The legacy outside-epoch driver observes this same resource. It is not
    /// needed for completion while an execution epoch has an active subscriber.
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
        } else if let Some((_, signal)) = self.owner.get() {
            signal.notify();
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
        self.pending.lock().unwrap().is_empty()
    }
    pub fn retire(self: &Arc<Self>, mut memory: Memory) -> Result<(), MemoryError> {
        let (id, owners) = memory.coordinator_ownership();
        if owners != 1 {
            return Ok(());
        }
        memory.retire_memory_report();
        if memory.parallel_views_quiescent() {
            return memory.commit_parallel();
        }
        memory.commit_retired_parallel()?;
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
    pub fn pump(&self) -> Result<(), MemoryError> {
        if let Some((_, signal)) = self.owner.get() {
            signal.reset();
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
                if let Err(error) = pending.memory.commit_parallel() {
                    pending.signal.notify();
                    self.publish(pending);
                    return Err(error);
                }
            } else {
                self.publish(pending);
            }
        }
        Ok(())
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
