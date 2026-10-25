// SPDX-License-Identifier: GPL-3.0-or-later
//! Live scalar dependencies for retained inode/backing identities. Byte access
//! never takes these binding/observer locks; only real size or source changes do.
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, OnceLock, Weak,
};

#[derive(Clone)]
pub struct LogicalSize(Arc<Value>);
struct Value {
    value: AtomicU64,
    revision: AtomicU64,
    parent: Mutex<Option<Parent>>,
    followers: Mutex<Vec<Weak<Value>>>,
    changed: OnceLock<fn()>,
}
struct Parent {
    source: LogicalSize,
    revision: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeCycle;
impl std::fmt::Display for SizeCycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cyclic size dependency")
    }
}
impl std::error::Error for SizeCycle {}
impl LogicalSize {
    pub fn new(value: u64) -> Self {
        Self(Arc::new(Value {
            value: AtomicU64::new(value),
            revision: AtomicU64::new(0),
            parent: Mutex::default(),
            followers: Mutex::default(),
            changed: OnceLock::new(),
        }))
    }
    pub fn load(&self, order: Ordering) -> u64 {
        self.0.value.load(order)
    }
    pub fn revision(&self) -> u64 {
        self.0.revision.load(Ordering::Relaxed)
    }
    /// The notification must be bounded, nonblocking, and must not reenter the
    /// owning file/inode. VFS uses only its existing backing-generation counter.
    pub fn on_change(&self, changed: fn()) {
        self.0.changed.get_or_init(|| changed);
    }
    /// Publish under the resource's existing mutation ownership. Scalar values
    /// are not a second byte-publication or ordinary-load memory barrier.
    pub fn store(&self, value: u64, order: Ordering) {
        let mut parent = self.0.parent.lock().unwrap();
        let old = parent.take();
        let changed = old.is_some() || self.load(Ordering::Relaxed) != value;
        if changed {
            self.0.value.store(value, order);
        }
        drop(parent);
        if let Some(old) = old {
            old.source.remove(Arc::as_ptr(&self.0));
        }
        if changed {
            self.notify();
        }
    }
    /// Retain a live source, including after an overlay changes its storage
    /// representation. Binding changes use the caller's existing acyclic source
    /// graph ownership; no global graph lock or resource thread is introduced.
    pub fn follow(&self, source: &Self) -> Result<(), SizeCycle> {
        // Metadata-only inode writes retain the same source. Its synchronous
        // notifications already maintain this value; do not traverse/register
        // the dependency graph again for those writes.
        if self
            .0
            .parent
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|p| Arc::ptr_eq(&p.source.0, &source.0))
        {
            return Ok(());
        }
        let mut ancestor = Some(source.clone());
        while let Some(node) = ancestor {
            if Arc::ptr_eq(&self.0, &node.0) {
                return Err(SizeCycle);
            }
            ancestor = node
                .0
                .parent
                .lock()
                .unwrap()
                .as_ref()
                .map(|p| p.source.clone());
        }
        // Registration precedes the deciding snapshot, excluding lost updates.
        let mut followers = source.0.followers.lock().unwrap();
        let mut parent = self.0.parent.lock().unwrap();
        let revision = source.revision();
        if parent
            .as_ref()
            .is_some_and(|p| Arc::ptr_eq(&p.source.0, &source.0) && p.revision == revision)
        {
            return Ok(());
        }
        followers.retain(|w| w.strong_count() != 0 && w.as_ptr() != Arc::as_ptr(&self.0));
        followers.push(Arc::downgrade(&self.0));
        let old = parent.replace(Parent {
            source: source.clone(),
            revision,
        });
        self.0
            .value
            .store(source.load(Ordering::Relaxed), Ordering::Relaxed);
        drop(parent);
        drop(followers);
        if let Some(old) = old.filter(|p| !Arc::ptr_eq(&p.source.0, &source.0)) {
            old.source.remove(Arc::as_ptr(&self.0));
        }
        self.notify();
        Ok(())
    }
    fn remove(&self, target: *const Value) {
        self.0
            .followers
            .lock()
            .unwrap()
            .retain(|w| w.as_ptr() != target && w.strong_count() != 0);
    }
    fn refresh(&self, source: &Self) {
        let mut parent = self.0.parent.lock().unwrap();
        let Some(bound) = parent
            .as_mut()
            .filter(|p| Arc::ptr_eq(&p.source.0, &source.0))
        else {
            return;
        };
        let revision = source.revision();
        if revision == bound.revision {
            return;
        }
        bound.revision = revision;
        self.0
            .value
            .store(source.load(Ordering::Relaxed), Ordering::Relaxed);
        drop(parent);
        self.notify();
    }
    fn notify(&self) {
        self.0.revision.fetch_add(1, Ordering::Relaxed);
        if let Some(changed) = self.0.changed.get() {
            changed();
        }
        let followers = {
            let mut followers = self.0.followers.lock().unwrap();
            followers.retain(|w| w.strong_count() != 0);
            followers.clone()
        };
        // No binding/observer lock spans another object's update or callback.
        for follower in followers.into_iter().filter_map(|w| w.upgrade()) {
            Self(follower).refresh(self);
        }
    }
}
impl Drop for Value {
    fn drop(&mut self) {
        if let Some(parent) = self.parent.get_mut().unwrap().take() {
            parent.source.remove(self as *const Self);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn retained_sources_propagate_rebind_and_reject_cycles() {
        let source = LogicalSize::new(12);
        let inode = LogicalSize::new(0);
        let projection = LogicalSize::new(0);
        inode.follow(&source).unwrap();
        projection.follow(&inode).unwrap();
        assert_eq!(projection.load(Ordering::Relaxed), 12);
        assert_eq!(source.follow(&projection), Err(SizeCycle));
        source.store(37, Ordering::Relaxed);
        assert_eq!(projection.load(Ordering::Relaxed), 37);
        let replacement = LogicalSize::new(9);
        inode.follow(&replacement).unwrap();
        source.store(100, Ordering::Relaxed);
        inode.refresh(&source); // An already captured old-source notification.
        assert_eq!(projection.load(Ordering::Relaxed), 9);
        replacement.store(21, Ordering::Relaxed);
        assert_eq!(projection.load(Ordering::Relaxed), 21);
        inode.store(5, Ordering::Relaxed);
        replacement.store(200, Ordering::Relaxed);
        assert_eq!(projection.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn ordinary_reads_do_not_take_binding_or_follower_locks() {
        let source = LogicalSize::new(7);
        let inode = LogicalSize::new(0);
        inode.follow(&source).unwrap();
        let _parent = inode.0.parent.lock().unwrap();
        let _followers = inode.0.followers.lock().unwrap();
        assert_eq!(inode.load(Ordering::Relaxed), 7);
        assert_ne!(inode.revision(), 0);
    }

    #[test]
    fn dropping_observers_unregisters_and_releases_retained_sources() {
        let source = LogicalSize::new(7);
        let weak = Arc::downgrade(&source.0);
        let inode = LogicalSize::new(0);
        inode.follow(&source).unwrap();
        assert_eq!(source.0.followers.lock().unwrap().len(), 1);
        drop(inode);
        assert!(source.0.followers.lock().unwrap().is_empty());
        let inode = LogicalSize::new(0);
        inode.follow(&source).unwrap();
        drop(source);
        assert!(weak.upgrade().is_some());
        drop(inode);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn concurrent_source_changes_and_registration_do_not_lose_the_last_size() {
        let source = LogicalSize::new(0);
        let other = LogicalSize::new(99);
        let inode = LogicalSize::new(0);
        let projection = LogicalSize::new(0);
        projection.follow(&inode).unwrap();
        let barrier = Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for value in 1..=2000 {
                    barrier.wait();
                    source.store(value, Ordering::Relaxed);
                    barrier.wait();
                    barrier.wait();
                }
            });
            for value in 1..=2000 {
                inode.follow(&other).unwrap();
                barrier.wait();
                inode.follow(&source).unwrap();
                barrier.wait();
                assert_eq!(projection.load(Ordering::Relaxed), value);
                barrier.wait();
            }
        });
    }
}
