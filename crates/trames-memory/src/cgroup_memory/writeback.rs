// SPDX-License-Identifier: GPL-3.0-or-later
//! Original dirty generations use existing writeback workers and completion.
use super::MemoryCgroup;
use crate::{MemoryError, PageWait, SyncCompletion, SyncExecutor, SyncResource};
use std::sync::{Arc, Mutex, Weak};
use trames_shared::{IoSignal, IoSubscription, ResourceWait};

/// Per-resource coalescing and bounded failure. An unchanged dirty generation
/// is attempted once, including failure; a new store can submit a new wave.
#[derive(Default)]
pub struct CgroupWriteback {
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    generation: Vec<(u64, u64)>,
    pending: Weak<PageWait>,
}
impl CgroupWriteback {
    pub fn submit(
        &self,
        generation: Vec<(u64, u64)>,
        group: Arc<MemoryCgroup>,
        bytes: usize,
        resource: Arc<dyn SyncResource>,
        executor: Arc<dyn SyncExecutor>,
    ) -> Option<Arc<PageWait>> {
        if generation.is_empty() {
            return None;
        }
        let wait = {
            // This mutex holds only the coalescing scalars, never quota,
            // provider, byte or layout callbacks. Submission is outside it.
            let mut state = self.state.lock().unwrap();
            if let Some(wait) = state.pending.upgrade().filter(|wait| !wait.ready()) {
                return Some(wait);
            }
            if state.generation == generation {
                return None;
            }
            let wait = Arc::new(PageWait::default());
            state.generation = generation;
            state.pending = Arc::downgrade(&wait);
            wait
        };
        executor.submit(
            resource,
            Box::new(Done {
                wait: wait.clone(),
                group,
                bytes,
            }),
        );
        Some(wait)
    }
}
struct Done {
    wait: Arc<PageWait>,
    group: Arc<MemoryCgroup>,
    bytes: usize,
}
impl Drop for Done {
    fn drop(&mut self) {
        // Executor retirement cannot strand the original allocation attempt.
        // It still retries real accounting; cancellation releases no bytes.
        self.wait.finish();
    }
}
impl SyncCompletion for Done {
    fn complete(self: Box<Self>, result: Result<(), MemoryError>) {
        if result.is_ok() {
            self.group.reclaim(self.bytes);
        }
        self.wait.finish();
    }
}
pub(super) struct Batch(pub Vec<Arc<PageWait>>);
impl ResourceWait for Batch {
    fn ready(&self) -> bool {
        self.0.iter().all(|wait| wait.ready())
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.0
            .iter()
            .flat_map(|wait| wait.subscribe(signal))
            .collect()
    }
    fn deadline(&self) -> Option<std::time::Instant> {
        self.0.iter().filter_map(|wait| wait.deadline()).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CgroupMemoryKind, CgroupMemoryTarget, CgroupPageCharge, CgroupReclaim, PAGE_SIZE};
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

    type Writeback = (Arc<dyn SyncResource>, Box<dyn SyncCompletion>);
    #[derive(Default)]
    struct Executor(Mutex<Vec<Writeback>>);
    impl SyncExecutor for Executor {
        fn submit(&self, resource: Arc<dyn SyncResource>, completion: Box<dyn SyncCompletion>) {
            self.0.lock().unwrap().push((resource, completion));
        }
    }
    impl Executor {
        fn complete(&self, success: bool) {
            let (resource, completion) = self.0.lock().unwrap().pop().unwrap();
            completion.complete(if success {
                resource.sync()
            } else {
                Err(MemoryError::BackingIo(5))
            });
        }
    }
    struct Cache {
        dirty: AtomicBool,
        charge: Mutex<Option<CgroupPageCharge>>,
    }
    impl CgroupReclaim for Cache {
        fn reclaim(&self, _: &MemoryCgroup, _: usize) -> usize {
            if !self.dirty.load(Relaxed) && self.charge.lock().unwrap().take().is_some() {
                PAGE_SIZE as usize
            } else {
                0
            }
        }
    }
    impl SyncResource for Cache {
        fn layout(&self) -> Option<Arc<crate::layout::Layout>> {
            None
        }
        fn sync(&self) -> Result<(), MemoryError> {
            self.dirty.store(false, Relaxed);
            Ok(())
        }
    }
    #[test]
    fn dirty_generations_coalesce_cancel_and_fail_without_faking_released_bytes() {
        let group = MemoryCgroup::new(None);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _scope = target.scope();
        let cache = Arc::new(Cache {
            dirty: AtomicBool::new(true),
            charge: Mutex::new(Some(CgroupPageCharge::new(CgroupMemoryKind::File).unwrap())),
        });
        let reclaim: Arc<dyn CgroupReclaim> = cache.clone();
        cache
            .charge
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .register_reclaimer(&reclaim);
        let executor = Arc::new(Executor::default());
        let writeback = CgroupWriteback::default();
        let first = writeback
            .submit(
                vec![(42, 1)],
                group.clone(),
                PAGE_SIZE as usize,
                cache.clone(),
                executor.clone(),
            )
            .unwrap();
        let other = writeback
            .submit(
                vec![(42, 1)],
                group.clone(),
                PAGE_SIZE as usize,
                cache.clone(),
                executor.clone(),
            )
            .unwrap();
        assert!(Arc::ptr_eq(&first, &other));
        assert_eq!(executor.0.lock().unwrap().len(), 1);
        drop(first);
        assert!(!other.ready());
        executor.complete(false);
        assert!(other.ready());
        assert_eq!(group.current(), PAGE_SIZE as usize);
        assert!(writeback
            .submit(
                vec![(42, 1)],
                group.clone(),
                PAGE_SIZE as usize,
                cache.clone(),
                executor.clone()
            )
            .is_none());
        let next = writeback
            .submit(
                vec![(42, 2)],
                group.clone(),
                PAGE_SIZE as usize,
                cache.clone(),
                executor.clone(),
            )
            .unwrap();
        executor.complete(true);
        assert!(next.ready());
        assert_eq!(group.current(), 0);
    }
}
