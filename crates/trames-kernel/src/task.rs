// SPDX-License-Identifier: GPL-3.0-or-later
//! PID visibility is independent of the executor that later drops its projection.
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
    Arc,
};
/// Session-global task numbers. This is independent of namespace translations
/// and task admission; failed construction may consume an ID, never reuse one.
pub struct Ids(AtomicU32);
impl Default for Ids {
    fn default() -> Self {
        Self(AtomicU32::new(2)) // the initial task already owns ID 1
    }
}
impl Ids {
    pub fn allocate(&self) -> Option<u32> {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                id.checked_add(1).filter(|next| *next < i32::MAX as u32)
            })
            .ok()
    }
    pub fn created(&self) -> u32 {
        self.0.load(Ordering::Relaxed) - 1
    }
    /// Start a restored session's monotonically increasing ID space.
    pub fn from_next(next: u32) -> Self {
        assert!((2..i32::MAX as u32).contains(&next));
        Self(AtomicU32::new(next))
    }
}
/// Admission belongs to the original session resource, not its task table.
/// Reserved construction, live tasks and unreaped zombies all consume a slot.
pub struct Capacity {
    limit: usize,
    used: AtomicUsize,
}
impl Capacity {
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }
    pub fn limit(&self) -> usize {
        self.limit
    }
    pub fn reserve(self: &Arc<Self>) -> Option<Slot> {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < self.limit).then(|| used + 1)
            })
            .ok()?;
        Some(Slot(Some(self.clone())))
    }
}
/// Dropping unfinished construction rolls back admission on its source thread.
pub struct Slot(Option<Arc<Capacity>>);
impl Slot {
    pub fn into_presence(mut self) -> Presence {
        Presence(Visibility(Arc::new(Visible {
            present: AtomicBool::new(true),
            capacity: self.0.take(),
        })))
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(capacity) = self.0.take() {
            capacity.used.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
#[derive(Default)]
struct Visible {
    present: AtomicBool,
    capacity: Option<Arc<Capacity>>,
}
/// A directory may retain visibility, never the actual task lifetime owner.
/// Reaping releases admission once, even if projections still retain this bit.
#[derive(Clone, Default)]
pub struct Visibility(Arc<Visible>);
impl Visibility {
    pub(crate) fn identity(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
    pub fn present(&self) -> bool {
        self.0.present.load(Ordering::Relaxed)
    }
    pub fn reap(&self) {
        if self.0.present.swap(false, Ordering::Relaxed) {
            if let Some(capacity) = &self.0.capacity {
                capacity.used.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}
pub struct Presence(Visibility);
impl Default for Presence {
    fn default() -> Self {
        Self(Visibility(Arc::new(Visible {
            present: AtomicBool::new(true),
            capacity: None,
        })))
    }
}
impl Presence {
    pub fn present(&self) -> bool {
        self.0.present()
    }
    pub fn visibility(&self) -> Visibility {
        self.0.clone()
    }
}
impl Drop for Presence {
    fn drop(&mut self) {
        self.0.reap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_admission_reserves_capacity_before_publication() {
        let capacity = Arc::new(Capacity::new(7));
        let gate = std::sync::Barrier::new(33);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let capacity = &capacity;
                let gate = &gate;
                scope.spawn(move || {
                    let slot = capacity.reserve();
                    gate.wait();
                    gate.wait();
                    // Both abandoned construction and completed task lifetimes
                    // must refund the same original counter.
                    if let Some(slot) = slot {
                        drop(slot.into_presence());
                    }
                });
            }
            gate.wait();
            assert_eq!(capacity.used.load(Ordering::Relaxed), 7);
            assert!(capacity.reserve().is_none());
            gate.wait();
        });
        assert_eq!(capacity.used.load(Ordering::Relaxed), 0);
        drop(capacity.reserve().unwrap());
        assert_eq!(capacity.used.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn source_reap_refunds_once_while_owner_and_directory_still_retain_task() {
        let capacity = Arc::new(Capacity::new(1));
        let task = Arc::new(capacity.reserve().unwrap().into_presence());
        let directory = task.visibility();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| directory.reap());
            }
        });
        assert!(!task.present());
        let next = capacity.reserve().unwrap().into_presence();
        drop(task);
        directory.reap();
        assert!(capacity.reserve().is_none());
        drop(next);
        assert_eq!(capacity.used.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn concurrent_births_allocate_once_and_exhaustion_cannot_wrap() {
        let ids = Ids::default();
        let allocated = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        (0..512)
                            .map(|_| ids.allocate().unwrap())
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<std::collections::BTreeSet<_>>()
        });
        assert_eq!(allocated, (2..4098).collect());
        assert_eq!(ids.created(), 4097);
        let edge = Ids::from_next(i32::MAX as u32 - 2);
        assert_eq!(edge.allocate(), Some(i32::MAX as u32 - 2));
        assert_eq!(edge.allocate(), None);
        assert_eq!(edge.allocate(), None);
        assert_eq!(edge.created(), i32::MAX as u32 - 2);
    }
}
