// SPDX-License-Identifier: GPL-3.0-or-later
//! Structural transactions belong to one original mount namespace. A busy
//! namespace parks its caller on existing readiness; it never requests a
//! coordinator operation or occupies a guest CPU while waiting.
use super::*;

#[derive(Default)]
pub(crate) struct Admin {
    transaction: std::sync::Mutex<()>,
    readiness: Arc<crate::readiness::Readiness>,
    // Only namespaces with real shared/slave mount relationships share this
    // structural transaction domain. Weak entries never retain a namespace.
    namespaces: std::sync::Mutex<Vec<std::sync::Weak<SharedCell<Table>>>>,
}
pub(crate) struct Lease<'a> {
    guard: Option<std::sync::MutexGuard<'a, ()>>,
    admin: &'a Admin,
}
impl Admin {
    pub(super) fn register(&self, table: &Arc<SharedCell<Table>>) {
        let mut namespaces = self.namespaces.lock().unwrap();
        namespaces.retain(|n| n.strong_count() != 0);
        namespaces.push(Arc::downgrade(table));
    }
    pub(super) fn namespaces(&self) -> Vec<MountNamespace> {
        self.namespaces
            .lock()
            .unwrap()
            .iter()
            .filter_map(|n| n.upgrade().map(MountNamespace))
            .collect()
    }
    pub(crate) fn try_enter(&self) -> Option<Lease<'_>> {
        match self.transaction.try_lock() {
            Ok(guard) => Some(Lease {
                guard: Some(guard),
                admin: self,
            }),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(error)) => {
                panic!("mount transaction poisoned: {error}")
            }
        }
    }
    pub(crate) fn enter(&self) -> Lease<'_> {
        Lease {
            guard: Some(self.transaction.lock().unwrap()),
            admin: self,
        }
    }
    pub(crate) fn ready(&self) -> bool {
        match self.transaction.try_lock() {
            Ok(_) => true,
            Err(std::sync::TryLockError::WouldBlock) => false,
            Err(std::sync::TryLockError::Poisoned(error)) => {
                panic!("mount transaction poisoned: {error}")
            }
        }
    }
    pub(crate) fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.readiness.subscribe(signal)
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        // A waiting executor may fail try_lock without acquiring the mutex.
        // Pair the existing readiness subscription RMW with this real unlock.
        self.admin.readiness.notify_atomic();
    }
}
