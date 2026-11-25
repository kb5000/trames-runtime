// SPDX-License-Identifier: GPL-3.0-or-later
//! Cancellation records for allocations owned by the original structural mm.
//! Drop never edits a live mapping or creates an executor. Existing original
//! mm admission drains these records after its execution Views have returned.
use super::*;
use std::sync::{atomic::AtomicBool, Mutex, Weak};

/// Original resource cleanup under admitted, quiescent structural mm custody.
/// Providers define the kernel ABI's range/identity rule; ordinary byte access
/// never invokes this capability or retains a pointer into the address space.
pub trait MappingCleanup: Send + Sync {
    fn cleanup(&self, memory: &mut Memory) -> Result<(), MemoryError>;
}
/// Collected while original mm custody is still held. Close resources must
/// travel with this cleanup, rather than a later unrelated structural call.
pub struct MappingCleanupStatus {
    pub finished: bool,
    pub subscriptions: Vec<trames_shared::IoSubscription>,
    pub resources: Vec<Arc<dyn SyncResource>>,
}
enum Target {
    Objects(Vec<Arc<dyn PageBacking>>),
    Resource(Arc<dyn MappingCleanup>),
}
impl Target {
    fn cleanup(&self, memory: &mut Memory) -> Result<(), MemoryError> {
        match self {
            Self::Objects(objects) => memory.unmap_original_objects(objects),
            Self::Resource(resource) => resource.cleanup(memory),
        }
    }
}

#[derive(Default)]
pub(super) struct Cleanup {
    pending: AtomicBool,
    objects: Mutex<Vec<Target>>,
}
pub struct MappingLease {
    identity: u64,
    cleanup: Weak<Cleanup>,
    objects: Option<Target>,
}
impl MappingLease {
    pub fn commit(mut self) {
        self.objects = None;
    }
    pub fn cancel(&mut self, memory: &mut Memory) -> Result<bool, MemoryError> {
        if let Some(root) = &memory.shared {
            return self.cancel(&mut root.borrow_mut());
        }
        if memory.original_identity != self.identity {
            return Err(MemoryError::InvalidRange);
        }
        if !memory.parallel_views_quiescent() {
            return Ok(false);
        }
        if let Some(objects) = &self.objects {
            objects.cleanup(memory)?;
        }
        self.objects = None;
        Ok(true)
    }
}
impl Drop for MappingLease {
    fn drop(&mut self) {
        if let Some(objects) = self.objects.take() {
            if let Some(cleanup) = self.cleanup.upgrade() {
                let mut pending = cleanup.objects.lock().unwrap();
                pending.push(objects);
                cleanup.pending.store(true, Ordering::Relaxed);
            }
        }
    }
}
impl Memory {
    /// Called with original mapping custody after this allocation is mapped.
    /// The lease carries neither a VM owner nor a borrowed guest pointer.
    pub fn mapping_lease(&mut self, objects: Vec<Arc<dyn PageBacking>>) -> MappingLease {
        if let Some(root) = &self.shared {
            return root.borrow_mut().mapping_lease(objects);
        }
        let cleanup = self.mapping_cleanup.get_or_insert_with(Default::default);
        MappingLease {
            identity: self.original_identity,
            cleanup: Arc::downgrade(cleanup),
            objects: Some(Target::Objects(objects)),
        }
    }
    pub fn mapping_cleanup_lease(&mut self, resource: Arc<dyn MappingCleanup>) -> MappingLease {
        if let Some(root) = &self.shared {
            return root.borrow_mut().mapping_cleanup_lease(resource);
        }
        let cleanup = self.mapping_cleanup.get_or_insert_with(Default::default);
        MappingLease {
            identity: self.original_identity,
            cleanup: Arc::downgrade(cleanup),
            objects: Some(Target::Resource(resource)),
        }
    }
    pub fn mapping_cleanup_pending(&self) -> bool {
        if let Some(root) = &self.shared {
            return root.borrow().mapping_cleanup_pending();
        }
        self.mapping_cleanup
            .as_ref()
            .is_some_and(|cleanup| cleanup.pending.load(Ordering::Relaxed))
    }
    pub fn reap_mapping_cleanup(&mut self) -> Result<bool, MemoryError> {
        if let Some(root) = &self.shared {
            return root.borrow_mut().reap_mapping_cleanup();
        }
        if !self.mapping_cleanup_pending() {
            return Ok(true);
        }
        if !self.parallel_views_quiescent() {
            return Ok(false);
        }
        self.commit_parallel()?;
        let cleanup = self.mapping_cleanup.as_ref().unwrap().clone();
        loop {
            let mut pending = {
                let mut objects = cleanup.objects.lock().unwrap();
                cleanup.pending.store(false, Ordering::Relaxed);
                std::mem::take(&mut *objects)
            };
            while let Some(objects) = pending.pop() {
                if let Err(error) = objects.cleanup(self) {
                    pending.push(objects);
                    let mut objects = cleanup.objects.lock().unwrap();
                    objects.extend(pending);
                    cleanup.pending.store(true, Ordering::Relaxed);
                    return Err(error);
                }
            }
            // Each pass consumes actual cancellation records. A provider dropped
            // by this pass may have queued another original allocation meanwhile.
            if !cleanup.pending.load(Ordering::Relaxed) {
                return Ok(true);
            }
        }
    }
    fn unmap_original_objects(
        &mut self,
        objects: &[Arc<dyn PageBacking>],
    ) -> Result<(), MemoryError> {
        // Identity follows moved aliases. Replacements, and a fork's independent
        // mm, cannot be removed by cancellation of this original allocation.
        let identities: BTreeSet<_> = objects
            .iter()
            .map(|object| Arc::as_ptr(object) as *const () as usize)
            .collect();
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for (&base, &frame) in &self.pages {
            let original = self.frames[frame]
                .as_ref()
                .unwrap()
                .backing
                .as_ref()
                .is_some_and(|backing| {
                    identities.contains(&(Arc::as_ptr(&backing.object) as *const () as usize))
                });
            if original {
                if let Some((_, end)) = ranges.last_mut().filter(|(_, end)| *end == base) {
                    *end += PAGE_SIZE;
                } else {
                    ranges.push((base, base + PAGE_SIZE));
                }
            }
        }
        for (start, end) in ranges {
            self.unmap(start, end - start)?;
        }
        Ok(())
    }
}
