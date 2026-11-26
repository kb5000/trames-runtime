// SPDX-License-Identifier: GPL-3.0-or-later
//! Original mapped providers use existing writeback and layout admission.
use super::*;
use std::sync::{Mutex, Weak};
use trames_memory::{CgroupReclaim, CgroupWriteback, MemoryCgroup, PageWait, SyncExecutor};

pub(super) struct Provider {
    node: Weak<Inode>,
    data: Arc<SharedCell<Box<FileData>>>,
    state: Arc<MappingState>,
    pages: Arc<SharedCell<BTreeMap<u64, Weak<FilePage>>>>,
    originals: Mutex<Vec<Weak<SharedOpenDescription>>>,
    executor: Mutex<Option<Weak<dyn SyncExecutor>>>,
    writeback: CgroupWriteback,
}
impl Provider {
    pub(super) fn new(data: &MappedData, node: &NodeRef) -> Arc<Self> {
        Arc::new(Self {
            node: Arc::downgrade(node),
            data: data.data.clone(),
            state: data.state.clone(),
            pages: data.pages.clone(),
            originals: Mutex::default(),
            executor: Mutex::default(),
            writeback: CgroupWriteback::default(),
        })
    }
    pub(super) fn observe(&self, open: &Arc<SharedOpenDescription>) {
        let mut originals = self.originals.lock().unwrap();
        originals.retain(|open| open.strong_count() != 0);
        if !originals
            .iter()
            .any(|old| old.as_ptr() == Arc::as_ptr(open))
        {
            originals.push(Arc::downgrade(open));
        }
        drop(originals);
        if let Some(executor) = crate::file_actor::sync_executor() {
            *self.executor.lock().unwrap() = Some(Arc::downgrade(&executor));
        }
    }
}
impl CgroupReclaim for Provider {
    fn reclaim(&self, _: &MemoryCgroup, _: usize) -> usize {
        0
    }
    fn writeback(&self, group: &Arc<MemoryCgroup>, bytes: usize) -> Option<Arc<PageWait>> {
        let pages: Vec<_> = self
            .pages
            .try_borrow()?
            .iter()
            .filter_map(|(&offset, page)| Some((offset, page.upgrade()?)))
            .filter(|(_, page)| page.owners.charged_within(group) && page.reconstructible())
            .take(bytes.div_ceil(PAGE_SIZE as usize))
            .collect();
        if pages.is_empty() {
            return None;
        }
        let generation = pages
            .iter()
            .map(|(_, page)| {
                (
                    page.identity,
                    page.version
                        .load(Ordering::Relaxed)
                        .wrapping_mul(2)
                        .wrapping_add(u64::from(page.dirty.load(Ordering::Relaxed))),
                )
            })
            .collect();
        let node = self.node.upgrade()?;
        let open = self
            .originals
            .try_lock()
            .ok()?
            .iter()
            .find_map(Weak::upgrade)?;
        let executor = crate::file_actor::sync_executor()
            .or_else(|| self.executor.try_lock().ok()?.as_ref()?.upgrade())?;
        let resource = sync::Resource::pressure(
            node,
            open,
            self.data.clone(),
            self.state.clone(),
            pages,
            group.clone(),
        )?;
        self.writeback.submit(
            generation,
            group.clone(),
            bytes,
            Arc::new(resource),
            executor,
        )
    }
}
impl FilePage {
    fn reconstructible(&self) -> bool {
        matches!(&self.shared_reload, Some(PageStorage::Deferred { source, .. })
            if source.private_disk())
            && self.external_version() == self.loaded_generation.load(Ordering::Relaxed)
            && self
                .bytes
                .try_read()
                .is_ok_and(|bytes| matches!(&*bytes, PageStorage::Published { shared: false, .. }))
    }
    pub(super) fn discard_clean(&self, group: &MemoryCgroup) {
        if self.dirty.load(Ordering::Relaxed) || !self.owners.charged_within(group) {
            return;
        }
        let Some(PageStorage::Deferred {
            source,
            offset,
            state,
        }) = &self.shared_reload
        else {
            return;
        };
        let Ok(mut storage) = self.bytes.try_write() else {
            return;
        };
        let PageStorage::Published {
            bytes,
            shared: false,
        } = &*storage
        else {
            return;
        };
        let Some(owner) = self.owners.physical_owner() else {
            return;
        };
        if !source.discard_mapped_cache(*offset, &self.owners, bytes) {
            return;
        }
        *self.reclaimed_owner.lock().unwrap() = Arc::downgrade(&owner);
        *storage = self.shared_reload.as_ref().unwrap().clone();
        self.source_generation.fetch_add(1, Ordering::Relaxed);
        drop(storage);
        if let Some(state) = state.upgrade() {
            state.changed(None);
        }
    }
}
