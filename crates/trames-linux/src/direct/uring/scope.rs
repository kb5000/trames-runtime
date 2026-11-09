// SPDX-License-Identifier: GPL-3.0-or-later
//! Original submitter maintenance state. No request, Files or task is retained.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

type Identity = (u64, u32);
#[derive(Default)]
pub(super) struct Scopes {
    // Production Linux clones have separate actors. Their ordinary one-origin
    // case needs no registry lock or BTree lookup on pending publication/query.
    first: std::sync::OnceLock<Arc<Scope>>,
    other: Mutex<BTreeMap<Identity, Entry>>,
}
struct Entry {
    weak: Weak<Scope>,
    pending: Option<Arc<Scope>>,
}
pub(crate) struct Scope {
    actor: Weak<UringActor>,
    identity: Identity,
    // Low bits: pending, requires legacy body/capability. Remaining bits change
    // only on new pending publication, so a concurrent issue wins over idling.
    status: AtomicU64,
}
impl Scope {
    pub(crate) fn revision(&self) -> u64 {
        self.status.load(Ordering::Relaxed)
    }
    pub(crate) fn active(&self) -> bool {
        self.revision() & 1 != 0
    }
    pub(crate) fn owner_required(&self) -> bool {
        self.revision() & 2 != 0
    }
    pub(crate) fn require_owner(&self) {
        self.status.fetch_or(2, Ordering::Relaxed);
    }
    pub(crate) fn owner_progressed(&self, observed: u64) {
        let _ = self.status.compare_exchange(
            observed,
            observed & !2,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
    fn activate(&self) {
        // Original ring/resource locks publish actual request contents. These
        // bits report metadata and add no ordinary-memory ordering.
        self.status
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.wrapping_add(4) | 1)
            })
            .unwrap();
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Some(actor) = self.actor.upgrade() {
            let mut scopes = actor.scopes.other.lock().unwrap();
            if scopes
                .get(&self.identity)
                .is_some_and(|entry| std::ptr::eq(entry.weak.as_ptr(), self))
            {
                scopes.remove(&self.identity);
            }
        }
    }
}
impl UringActor {
    pub(crate) fn scope(&self, owner: u64, task: u32) -> Option<Arc<Scope>> {
        let first = self.scopes.first.get()?;
        if first.identity == (owner, task) {
            return Some(first.clone());
        }
        self.scopes
            .other
            .lock()
            .unwrap()
            .get(&(owner, task))?
            .weak
            .upgrade()
    }
    pub(crate) fn activate(self: &Arc<Self>, owner: u64, task: u32) {
        let make = || {
            Arc::new(Scope {
                actor: Arc::downgrade(self),
                identity: (owner, task),
                status: AtomicU64::new(0),
            })
        };
        let first = self.scopes.first.get_or_init(make);
        if first.identity == (owner, task) {
            first.activate();
            return;
        }
        let mut scopes = self.scopes.other.lock().unwrap();
        let entry = scopes.entry((owner, task)).or_insert_with(|| Entry {
            weak: Weak::new(),
            pending: None,
        });
        let scope = entry.weak.upgrade().unwrap_or_else(|| {
            let scope = make();
            entry.weak = Arc::downgrade(&scope);
            scope
        });
        scope.activate();
        entry.pending = Some(scope);
    }
    pub(crate) fn finish_scope(&self, scope: &Arc<Scope>, observed: u64) {
        if scope
            .status
            .compare_exchange(
                observed,
                observed & !3,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return; // Another accepted issue owns its new pending publication.
        }
        if self
            .scopes
            .first
            .get()
            .is_some_and(|first| Arc::ptr_eq(first, scope))
        {
            return;
        }
        let retired = {
            let mut scopes = self.scopes.other.lock().unwrap();
            scopes
                .get_mut(&scope.identity)
                .filter(|entry| entry.weak.ptr_eq(&Arc::downgrade(scope)) && !scope.active())
                .and_then(|entry| entry.pending.take())
        };
        drop(retired); // Scope cleanup cannot re-enter its registry lock.
    }
    pub(crate) fn owner_required(&self) -> bool {
        self.scopes
            .first
            .get()
            .is_some_and(|first| first.owner_required())
            || self.scopes.other.lock().unwrap().values().any(|entry| {
                entry
                    .pending
                    .as_ref()
                    .is_some_and(|scope| scope.owner_required())
            })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_idle_and_legacy_progress_cannot_erase_new_pending_publication() {
        let actor = Arc::new(UringActor::default());
        actor.activate(1, 7);
        let scope = actor.scope(1, 7).unwrap();
        scope.require_owner();
        let old = scope.revision();
        actor.activate(1, 7);
        actor.finish_scope(&scope, old);
        scope.owner_progressed(old);
        assert!(scope.active() && scope.owner_required());
        actor.finish_scope(&scope, scope.revision());
        assert!(!scope.active() && !scope.owner_required());
    }
    #[test]
    fn secondary_origins_are_canonical_until_last_drop_without_retaining_history() {
        let actor = Arc::new(UringActor::default());
        actor.activate(1, 7);
        let first = actor.scope(1, 7).unwrap();
        for mm in 2..1024 {
            actor.activate(mm, 7);
            let old = actor.scope(mm, 7).unwrap();
            let weak = Arc::downgrade(&old);
            actor.finish_scope(&old, old.revision());
            actor.activate(mm, 7);
            let new = actor.scope(mm, 7).unwrap();
            assert!(Arc::ptr_eq(&old, &new));
            assert!(first.active());
            actor.finish_scope(&new, new.revision());
            drop((old, new));
            assert!(weak.upgrade().is_none());
            assert!(actor.scopes.other.lock().unwrap().is_empty());
        }
    }
}
