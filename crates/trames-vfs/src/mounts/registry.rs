// SPDX-License-Identifier: GPL-3.0-or-later
//! Weak lookup index over original mounts. A private resolver caches only the
//! index, never topology or owning mount references. Existing mounts expose
//! moves/detachment through their original parent resources without a refresh.
use super::*;

struct Source {
    entries: SharedCell<Arc<Vec<std::sync::Weak<Mount>>>>,
    publishing: SharedCell<Publications>,
    revision: AtomicU64,
}
impl Default for Source {
    fn default() -> Self {
        Self {
            entries: SharedCell::default(),
            publishing: SharedCell::default(),
            revision: AtomicU64::new(1),
        }
    }
}
pub(super) type Publications = BTreeMap<(u64, usize), (std::sync::Weak<admin::Admin>, usize)>;
pub(super) struct Publication {
    source: Arc<Source>,
    owner: usize,
    mounts: Vec<u64>,
}
impl Drop for Publication {
    fn drop(&mut self) {
        let mut publishing = self.source.publishing.borrow_mut();
        for mount in &self.mounts {
            let key = (*mount, self.owner);
            let Some((_, count)) = publishing.get_mut(&key) else {
                continue;
            };
            *count -= 1;
            if *count == 0 {
                publishing.remove(&key);
            }
        }
    }
}
#[derive(Default)]
pub(crate) struct Registry {
    source: Arc<Source>,
    observed: Cell<u64>,
    cache: RefCell<Option<Arc<Vec<std::sync::Weak<Mount>>>>>,
}
#[derive(Clone)]
pub(super) struct Snapshot(Arc<Source>);
impl Snapshot {
    pub(super) fn publishing(&self) -> std::sync::RwLockReadGuard<'_, Publications> {
        self.0.publishing.borrow()
    }
    pub(super) fn mounts(&self) -> Vec<Arc<Mount>> {
        let entries = self.0.entries.borrow().clone();
        entries
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect()
    }
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
    /// The original namespace admission protects these drafts until their
    /// namespace or anonymous-tree owner is published. This is a weak index;
    /// it holds no topology, namespace, OFD or administration lease itself.
    pub(super) fn publishing(
        &self,
        admin: &Arc<admin::Admin>,
        mounts: &[Arc<Mount>],
    ) -> Publication {
        let owner = Arc::as_ptr(admin) as usize;
        let mounts: Vec<_> = mounts.iter().map(|mount| mount.id).collect();
        {
            let mut publishing = self.source.publishing.borrow_mut();
            for mount in &mounts {
                publishing
                    .entry((*mount, owner))
                    .or_insert_with(|| (Arc::downgrade(admin), 0))
                    .1 += 1;
            }
        }
        Publication {
            source: self.source.clone(),
            owner,
            mounts,
        }
    }
    pub(super) fn snapshot(&self) -> Snapshot {
        Snapshot(self.source.clone())
    }
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
