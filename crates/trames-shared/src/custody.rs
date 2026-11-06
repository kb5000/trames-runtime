// SPDX-License-Identifier: GPL-3.0-or-later
//! Original object custody with nonblocking admission and resource wakeups.
//! Execution bytes do not use this lock. A parked operation subscribes, retries
//! admission, then releases its executor slot until the resource notifies it.
use crate::{IoSignal, IoSubscription, Readiness};
use parking_lot::{ReentrantMutex, ReentrantMutexGuard};
use std::cell::{Ref, RefCell, RefMut};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

struct State<T> {
    value: ReentrantMutex<RefCell<T>>,
    ready: Arc<Readiness>,
}
pub struct Custody<T>(Arc<State<T>>);
impl<T> Clone for Custody<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T> Custody<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(State {
            value: ReentrantMutex::new(RefCell::new(value)),
            ready: Arc::default(),
        }))
    }
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    /// Readiness hint only; the caller must still try_admit after subscription.
    /// Observing readiness must not acquire/release custody and notify its own
    /// waiter while a run-queue lock is held.
    pub fn available(&self) -> bool {
        !self.0.value.is_locked()
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.0.ready.subscribe(signal)
    }
    pub fn borrow(&self) -> CustodyRead<'_, T> {
        let guard = self.0.value.lock();
        // SAFETY: the retained lock excludes other threads; the RefCell rejects
        // conflicting reentrant borrows. Ref drops before unlocking this state.
        let value = unsafe { &*self.0.value.data_ptr() }.borrow();
        CustodyRead {
            value,
            _unlock: BorrowedUnlock {
                guard: Some(guard),
                ready: &self.0.ready,
            },
        }
    }
    pub fn borrow_mut(&self) -> CustodyWrite<'_, T> {
        let guard = self.0.value.lock();
        // SAFETY: same lock/RefCell/drop ordering as borrow().
        let value = unsafe { &*self.0.value.data_ptr() }.borrow_mut();
        CustodyWrite {
            value,
            _unlock: BorrowedUnlock {
                guard: Some(guard),
                ready: &self.0.ready,
            },
        }
    }
}
impl<T: 'static> Custody<T> {
    fn lock(&self) -> OwnedUnlock<T> {
        // SAFETY: OwnedUnlock retains this exact stable allocation. Its private
        // guard drops before the retained owner; neither escapes independently.
        let state = unsafe { &*Arc::as_ptr(&self.0) };
        OwnedUnlock {
            guard: Some(state.value.lock()),
            owner: Some(self.clone()),
        }
    }
    /// No waiting and no RefCell bypass. An admitted caller may use the same
    /// original object reentrantly, but cannot keep a conflicting Ref/RefMut.
    pub fn try_admit(&self) -> Option<Admission<T>> {
        // SAFETY: the same owned-allocation contract as lock(). Failed attempts
        // retain neither a guard nor an independent reference to the value.
        let state = unsafe { &*Arc::as_ptr(&self.0) };
        let guard = state.value.try_lock()?;
        drop(guard.try_borrow_mut().ok()?);
        Some(Admission(OwnedUnlock {
            guard: Some(guard),
            owner: Some(self.clone()),
        }))
    }
    pub fn read_owned(&self) -> OwnedRead<T> {
        let unlock = self.lock();
        // SAFETY: unlock owns the stable allocation and the lock. Ref remains
        // private, drops first, and preserves reentrant RefCell exclusion.
        let value = unsafe { &*self.0.value.data_ptr() }.borrow();
        OwnedRead {
            value,
            _unlock: unlock,
        }
    }
    pub fn write_owned(&self) -> OwnedWrite<T> {
        Admission(self.lock()).write()
    }
}

struct BorrowedUnlock<'a, T> {
    guard: Option<ReentrantMutexGuard<'a, RefCell<T>>>,
    ready: &'a Readiness,
}
impl<T> Drop for BorrowedUnlock<'_, T> {
    fn drop(&mut self) {
        drop(self.guard.take());
        // This release RMW pairs with subscription before its admission retry.
        // A relaxed listener check could lose unlock-vs-subscribe on ARM.
        // Callbacks run only AFTER object custody has been released.
        self.ready.notify_atomic();
    }
}
struct OwnedUnlock<T: 'static> {
    guard: Option<ReentrantMutexGuard<'static, RefCell<T>>>,
    owner: Option<Custody<T>>,
}
impl<T> OwnedUnlock<T> {
    fn into_custody(mut self) -> Custody<T> {
        drop(self.guard.take());
        let owner = self.owner.take().expect("retained custody");
        owner.0.ready.notify_atomic();
        owner
    }
}
impl<T> Drop for OwnedUnlock<T> {
    fn drop(&mut self) {
        drop(self.guard.take());
        if let Some(owner) = &self.owner {
            owner.0.ready.notify_atomic();
        }
    }
}

pub struct CustodyRead<'a, T> {
    value: Ref<'a, T>,
    _unlock: BorrowedUnlock<'a, T>,
}
impl<T> Deref for CustodyRead<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
pub struct CustodyWrite<'a, T> {
    value: RefMut<'a, T>,
    _unlock: BorrowedUnlock<'a, T>,
}
impl<T> Deref for CustodyWrite<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> DerefMut for CustodyWrite<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
pub struct OwnedRead<T: 'static> {
    value: Ref<'static, T>,
    _unlock: OwnedUnlock<T>,
}
impl<T> Deref for OwnedRead<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
pub struct OwnedWrite<T: 'static> {
    value: RefMut<'static, T>,
    unlock: OwnedUnlock<T>,
}
impl<T> Deref for OwnedWrite<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T> DerefMut for OwnedWrite<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
impl<T> OwnedWrite<T> {
    pub fn custody(&self) -> &Custody<T> {
        self.unlock.owner.as_ref().expect("retained custody")
    }
    /// End the RefMut while retaining original object custody for a sequence
    /// of reentrant handlers. No mutex reacquisition or value alias escapes.
    pub fn into_admission(self) -> Admission<T> {
        let Self { value, unlock } = self;
        drop(value);
        Admission(unlock)
    }
    pub fn into_custody(self) -> Custody<T> {
        let Self { value, unlock } = self;
        drop(value);
        unlock.into_custody()
    }
}
/// A thread-local structural permit, not an extra guest Memory/Files owner.
/// The original object's normal methods may reenter it on this executor.
pub struct Admission<T: 'static>(OwnedUnlock<T>);
impl<T> Admission<T> {
    pub fn write(self) -> OwnedWrite<T> {
        let owner = self.0.owner.as_ref().expect("retained custody");
        // SAFETY: this owned lock retains the stable cell. RefMut remains
        // private and drops before unlock, as in write_owned().
        let value = unsafe { &*owner.0.value.data_ptr() }.borrow_mut();
        OwnedWrite {
            value,
            unlock: self.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IoWake;
    use std::sync::{mpsc, Barrier};
    use std::time::Duration;

    struct Wake(mpsc::Sender<()>);
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.send(()).unwrap();
        }
    }
    fn signal() -> (Arc<dyn IoWake>, Arc<IoSignal>, mpsc::Receiver<()>) {
        let (tx, rx) = mpsc::channel();
        let wake: Arc<dyn IoWake> = Arc::new(Wake(tx));
        let signal = IoSignal::new(1, Arc::downgrade(&wake));
        (wake, signal, rx)
    }
    #[test]
    fn original_owned_guards_and_permits_keep_allocation_and_refcell_exclusion() {
        let object = Custody::new(vec![7]);
        let permit = object.try_admit().unwrap();
        let held = object.read_owned();
        assert!(
            object.try_admit().is_none(),
            "a permit cannot bypass a live Ref"
        );
        assert_eq!(*held, [7]);
        drop(held);
        let mut write = permit.write();
        assert!(write.custody().same(&object));
        write.push(9);
        drop(object);
        let object = write.into_custody();
        assert_eq!(*object.borrow(), [7, 9]);
        let held = object.read_owned();
        drop(object);
        assert_eq!(
            *held,
            [7, 9],
            "owned reference retains the actual allocation"
        );
    }
    #[test]
    fn write_to_admission_keeps_custody_but_releases_the_mutable_borrow() {
        let object = Custody::new(7);
        let mut write = object.write_owned();
        *write = 9;
        let permit = write.into_admission();
        *object.write_owned() += 1;
        let remote = object.clone();
        std::thread::spawn(move || assert!(remote.try_admit().is_none()))
            .join()
            .unwrap();
        drop(object);
        assert_eq!(*permit.write(), 10);
    }
    #[test]
    fn contended_admission_never_waits_and_unlock_wakes_after_custody_ends() {
        let object = Custody::new(7);
        let held = object.borrow_mut();
        let remote = object.clone();
        let (ready, registered) = mpsc::channel();
        let join = std::thread::spawn(move || {
            assert!(remote.try_admit().is_none());
            let (_wake, signal, event) = signal();
            let subscription = remote.subscribe(&signal);
            assert!(remote.try_admit().is_none());
            ready.send(()).unwrap();
            event.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(subscription);
            let mut body = remote
                .try_admit()
                .expect("unlock precedes callback")
                .write();
            *body += 1;
        });
        registered.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(held);
        join.join().unwrap();
        assert_eq!(*object.borrow(), 8);
    }
    #[test]
    fn racing_subscription_and_unlock_cannot_lose_an_admission_wake() {
        let object = Custody::new(0);
        for _ in 0..256 {
            let (_wake, signal, event) = signal();
            let gate = Arc::new(Barrier::new(2));
            let held = object.borrow_mut();
            let remote = object.clone();
            let start = gate.clone();
            let join = std::thread::spawn(move || {
                start.wait();
                let subscription = remote.subscribe(&signal);
                let permit = match remote.try_admit() {
                    Some(permit) => permit,
                    None => {
                        event.recv_timeout(Duration::from_secs(5)).unwrap();
                        remote.try_admit().expect("original holder released")
                    }
                };
                drop(subscription);
                *permit.write() += 1;
                // The original holder may have copied the callback before
                // unsubscribe. Keep its receiver alive through that unlock.
                event
            });
            gate.wait();
            drop(held);
            let _event = join.join().unwrap();
        }
        assert_eq!(*object.borrow(), 256);
    }
    #[test]
    fn canceled_wait_does_not_notify_a_reused_signal() {
        let object = Custody::new(0);
        let (_wake, signal, event) = signal();
        let held = object.borrow_mut();
        drop(object.subscribe(&signal));
        drop(held);
        assert!(!signal.ready());
        assert!(event.try_recv().is_err());
    }
}
