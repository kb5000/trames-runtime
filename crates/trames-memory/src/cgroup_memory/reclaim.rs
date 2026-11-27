// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold mm reclamation runs at the existing original-address-space checkpoint.
use crate::*;
use std::sync::{
    atomic::{
        AtomicBool,
        Ordering::{Acquire, Release},
    },
    Arc, Mutex, Weak,
};

#[derive(Default)]
pub(crate) struct Requests(Mutex<State>);
#[derive(Default)]
struct State {
    pending: Vec<Weak<Request>>,
    completed: Vec<Completed>,
}
struct Completed {
    group: Weak<MemoryCgroup>,
    generation: (u64, u64),
    bytes: usize,
}
struct Request {
    group: Arc<MemoryCgroup>,
    bytes: usize,
    generation: (u64, u64),
    done: AtomicBool,
    changed: Arc<trames_shared::Readiness>,
}
impl Request {
    fn finish(&self) {
        self.done.store(true, Release);
        self.changed.notify_atomic();
    }
}
impl trames_shared::ResourceWait for Request {
    fn ready(&self) -> bool {
        self.done.load(Acquire)
    }
    fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        vec![self.changed.subscribe(signal)]
    }
}
impl crate::CgroupReclaim for crate::report::Report {
    fn reclaim(&self, _: &MemoryCgroup, _: usize) -> usize {
        0
    }
    fn release_mappings(&self, group: &Arc<MemoryCgroup>, bytes: usize) -> Option<Arc<PageWait>> {
        let report = MemoryReport(self.owner.upgrade()?.0.get()?.upgrade()?);
        if !report.alive() || !report.supports_reads() {
            return None;
        }
        let generation = report.reclaim_generation();
        let request = {
            let mut requests = self
                .reclaims
                .get_or_init(Default::default)
                .0
                .lock()
                .unwrap();
            requests
                .pending
                .retain(|request| request.strong_count() != 0);
            requests
                .completed
                .retain(|entry| entry.group.strong_count() != 0);
            if requests.completed.iter().any(|entry| {
                entry.group.as_ptr() == Arc::as_ptr(group)
                    && entry.generation == generation
                    && entry.bytes >= bytes
            }) {
                return None;
            }
            if let Some(request) =
                requests
                    .pending
                    .iter()
                    .filter_map(Weak::upgrade)
                    .find(|request| {
                        !request.done.load(Acquire)
                            && Arc::ptr_eq(&request.group, group)
                            && request.generation == generation
                            && request.bytes >= bytes
                    })
            {
                request
            } else {
                let request = Arc::new(Request {
                    group: group.clone(),
                    bytes,
                    generation,
                    done: AtomicBool::new(false),
                    changed: Arc::default(),
                });
                requests.pending.push(Arc::downgrade(&request));
                request
            }
        };
        report.wake_reads();
        Some(PageWait::resource(request))
    }
}
impl MemoryReport {
    pub(crate) fn has_reclaims(&self) -> bool {
        self.0.reclaims.get().is_some_and(|requests| {
            requests
                .0
                .lock()
                .unwrap()
                .pending
                .iter()
                .filter_map(Weak::upgrade)
                .any(|request| !request.done.load(Acquire))
        })
    }
    pub(crate) fn finish_reclaims(&self, mut memory: Option<&mut Memory>) {
        let requests: Vec<_> = self.0.reclaims.get().map_or_else(Vec::new, |requests| {
            requests
                .0
                .lock()
                .unwrap()
                .pending
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|request| !request.done.load(Acquire))
                .collect()
        });
        for request in requests {
            if let Some(memory) = memory.as_deref_mut() {
                memory.reclaim_clean_mappings(&request.group, request.bytes);
            }
            let mut state = self.0.reclaims.get().unwrap().0.lock().unwrap();
            state.completed.retain(|entry| {
                entry.group.strong_count() != 0
                    && !(entry.group.as_ptr() == Arc::as_ptr(&request.group)
                        && entry.generation != request.generation)
            });
            if let Some(entry) = state.completed.iter_mut().find(|entry| {
                entry.group.as_ptr() == Arc::as_ptr(&request.group)
                    && entry.generation == request.generation
            }) {
                entry.bytes = entry.bytes.max(request.bytes);
            } else {
                state.completed.push(Completed {
                    group: Arc::downgrade(&request.group),
                    generation: request.generation,
                    bytes: request.bytes,
                });
            }
            drop(state);
            request.finish();
        }
    }
}
impl Memory {
    fn reclaim_clean_mappings(&mut self, group: &MemoryCgroup, bytes: usize) {
        self.scan_pressure_pages();
        if bytes == 0 {
            return;
        }
        // The source checkpoint already committed all returned workers. An
        // external View/byte pin keeps its real physical lease independently.
        if self
            .parallel_cache
            .as_ref()
            .is_some_and(|cache| cache.has_uncommitted())
        {
            return;
        }
        drop(self.parallel_cache.take());
        let mut offered = 0usize;
        for (&base, &index) in &self.pages {
            if offered >= bytes {
                break;
            }
            let page = self.frames[index].as_mut().unwrap();
            let Some(backing) = &page.backing else {
                continue;
            };
            if backing.private_copy {
                continue;
            }
            // Provider writeback/layout admission discarded reconstructible
            // canonical bytes first. This retires only the original mm's old
            // PTE and its cached direct/native aliases, preserving private COW.
            // A different mm may already have reloaded and dirtied the current
            // canonical page. Retiring this PTE does not evict that provider's
            // new bytes; provider custody and dirty writeback remain intact.
            if !backing.object.reclaimed(group) {
                continue;
            }
            page.charge.retire_mapping();
            let charge = page.charge.fresh();
            backing.attach(&charge);
            page.charge = charge;
            page.bytes = Arc::new(PageBytes::Zero);
            page.data_revision = page.data_revision.wrapping_add(1);
            page.instruction_revision = page.instruction_revision.wrapping_add(1);
            self.parallel_mappings.insert(base);
            offered = offered.saturating_add(PAGE_SIZE as usize);
        }
        self.invalidate_translations();
        // Ordinary cache reclaim now observes the actual released pins. Its
        // return value, rather than the number of retired PTEs, accounts bytes.
        group.reclaim(bytes);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn register(memory: &Memory, group: &Arc<MemoryCgroup>) -> MemoryReport {
        let report = memory.memory_report();
        report.bind_read_waker(Arc::new(|_| {}));
        group.register_reclaimer(&(report.0.clone() as Arc<dyn CgroupReclaim>));
        report
    }
    #[test]
    fn cancelled_and_completed_checkpoint_requests_do_not_resubmit_an_unchanged_mm() {
        let mut memory = Memory::default();
        let group = MemoryCgroup::new(None);
        let report = register(&memory, &group);
        let cancelled = group.release_mappings(PAGE_SIZE as usize).unwrap();
        assert!(report.has_requested_reads());
        drop(cancelled);
        assert!(!report.has_requested_reads());
        let first = group.release_mappings(PAGE_SIZE as usize).unwrap();
        let second = group.release_mappings(PAGE_SIZE as usize).unwrap();
        assert!(memory.activate_proc_reads());
        assert!(first.ready() && second.ready());
        drop((first, second));
        assert!(group.release_mappings(PAGE_SIZE as usize).is_none());
        assert_eq!(group.reclaimed_bytes(), 0);
    }
    #[test]
    fn retiring_the_original_mm_finishes_waiters_without_retaining_memory_or_group() {
        let memory = Memory::default();
        let group = MemoryCgroup::new(None);
        let weak = Arc::downgrade(&group);
        let report = register(&memory, &group);
        let wait = group.release_mappings(PAGE_SIZE as usize).unwrap();
        drop(memory);
        assert!(wait.ready());
        assert!(!report.alive());
        drop(group);
        assert!(weak.upgrade().is_some());
        drop(wait);
        assert!(
            weak.upgrade().is_none(),
            "completed metadata holds only a weak group identity"
        );
    }
}
