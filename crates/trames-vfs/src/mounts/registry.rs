// SPDX-License-Identifier: GPL-3.0-or-later
//! Weak lookup index over original mounts. A private resolver caches only the
//! index, never topology or owning mount references. Existing mounts expose
//! moves/detachment through their original parent resources without a refresh.
use super::*;

struct Source {
    entries: SharedCell<Arc<Vec<std::sync::Weak<Mount>>>>,
    revision: AtomicU64,
}
impl Default for Source {
    fn default() -> Self {
        Self {
            entries: SharedCell::default(),
            revision: AtomicU64::new(1),
        }
    }
}
#[derive(Default)]
pub(crate) struct Registry {
    source: Arc<Source>,
    observed: Cell<u64>,
    cache: RefCell<Option<Arc<Vec<std::sync::Weak<Mount>>>>>,
}
impl Clone for Registry {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            observed: Cell::new(0),
            cache: RefCell::default(),
        }
    }
}
impl Registry {
    pub(crate) fn borrow(&self) -> std::cell::Ref<'_, Vec<std::sync::Weak<Mount>>> {
        // Acquire pairs only with an actual index edit. Ordinary guest memory
        // and the parent topology do not use this cache's publication protocol.
        let revision = self.source.revision.load(Ordering::Acquire);
        if self.observed.get() != revision {
            let entries = self.source.entries.borrow();
            *self.cache.borrow_mut() = Some(entries.clone());
            self.observed
                .set(self.source.revision.load(Ordering::Relaxed));
        }
        std::cell::Ref::map(self.cache.borrow(), |cache| cache.as_deref().unwrap())
    }
    pub(crate) fn borrow_mut(&self) -> Write<'_> {
        // Drop this writer's observation before COW. Without other readers a
        // serial mutator edits the existing weak index without copying it.
        *self.cache.borrow_mut() = None;
        self.observed.set(0);
        Write {
            entries: self.source.entries.borrow_mut(),
            revision: &self.source.revision,
        }
    }
}
pub(crate) struct Write<'a> {
    entries: std::sync::RwLockWriteGuard<'a, Arc<Vec<std::sync::Weak<Mount>>>>,
    revision: &'a AtomicU64,
}
impl std::ops::Deref for Write<'_> {
    type Target = Vec<std::sync::Weak<Mount>>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
impl std::ops::DerefMut for Write<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.entries)
    }
}
impl Drop for Write<'_> {
    fn drop(&mut self) {
        self.revision.fetch_add(1, Ordering::Release);
    }
}
