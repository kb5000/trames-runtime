// SPDX-License-Identifier: GPL-3.0-or-later
//! Incremental metadata maintenance at joined coordinator checkpoints.
use super::*;

impl Snapshot {
    fn remove_frame(&mut self, base: u64) -> Option<Frame> {
        let index = self.pages.remove(&base)?;
        let frame = self.frames.swap_remove(index);
        if let Some(moved) = self.frames.get(index) {
            self.pages.insert(moved.base, index);
            self.positions[moved.root_frame] = Some(index);
        }
        self.positions[frame.root_frame] = None;
        self.backed_pages.remove(&base);
        let count = self
            .identities
            .get_mut(&frame.bytes.identity)
            .expect("indexed identity");
        self.alias_count -= usize::from(*count == 2);
        *count -= 1;
        if *count == 0 {
            self.identities.remove(&frame.bytes.identity);
        }
        self.dynamic_code_pages -= usize::from(frame.dynamic_code);
        Some(frame)
    }
    fn insert_frame(&mut self, frame: Frame, backed: bool) {
        let count = self.identities.entry(frame.bytes.identity).or_insert(0);
        self.alias_count += usize::from(*count == 1);
        *count += 1;
        self.dynamic_code_pages += usize::from(frame.dynamic_code);
        if backed {
            self.backed_pages.insert(frame.base);
        }
        self.pages.insert(frame.base, self.frames.len());
        self.positions[frame.root_frame] = Some(self.frames.len());
        self.frames.push(frame);
    }
}

impl Memory {
    pub(super) fn update_parallel_snapshot(
        &mut self,
        registry: &mut Registry,
        backing_revision: u64,
    ) -> Option<View> {
        let mut cache = self.parallel_cache.take().expect("checked cache");
        // Workers release views before publishing Done. A retained external
        // view uses the immutable full-snapshot path instead. No raw pointer,
        // permission check or guest byte synchronization changes here.
        let snapshot = Arc::get_mut(&mut cache.snapshot).expect("unique joined snapshot");
        registry.metrics.incremental_updates += 1;
        let mut changed = std::mem::take(&mut self.parallel_mappings);
        let dirty = std::mem::take(&mut self.parallel_dirty);
        for index in dirty {
            if let Some(Some(position)) = snapshot.positions.get(index) {
                changed.insert(snapshot.frames[*position].base);
            }
            if let Some(page) = self.frames[index].as_mut() {
                page.parallel_dirty = false;
            }
        }
        if cache.source_backing_revision != backing_revision {
            registry.metrics.backing_invalidations += 1;
            // Global backing epochs must not force walks of anonymous pages.
            // Every actual file-backed page still checks its own version/EOF.
            changed.extend(snapshot.backed_pages.iter().copied());
        }
        registry.metrics.code_invalidations +=
            u64::from(snapshot.code_revision != self.code_revision);
        registry.metrics.incremental_pages += changed.len() as u64;
        snapshot.positions.resize(self.frames.len(), None);
        if snapshot.dirty_pages.len() < self.frames.len().div_ceil(64) {
            // All worker writes have been committed. A new bitmap changes no
            // page identity or exclusive-monitor generation.
            debug_assert!(snapshot
                .dirty_pages
                .iter()
                .all(|word| word.load(Ordering::Relaxed) == 0));
            snapshot.dirty_pages = (0..self.frames.len().div_ceil(64))
                .map(|_| AtomicU64::new(0))
                .collect();
        }
        // Remove the whole changed set before adding it: munmap may have reused
        // a stable root-frame slot at a different virtual address.
        let previous: BTreeMap<_, _> = changed
            .iter()
            .filter_map(|&base| snapshot.remove_frame(base).map(|frame| (base, frame)))
            .collect();
        let mmu_changed: Vec<_> = changed.iter().copied().collect();
        for base in changed {
            let Some(&root_frame) = self.pages.get(&base) else {
                continue;
            };
            self.prepare_shared_storage(base, root_frame, registry);
            let page = self.frames[root_frame].as_mut().expect("mapped frame");
            if page
                .backing
                .as_ref()
                .is_some_and(|b| b.object.parallel_key().is_none())
            {
                // Cache is dropped; subsequent attempts retain the original
                // conservative serial behavior for custom backings.
                return None;
            }
            let frame = prepare_frame(
                self.identity,
                page,
                base,
                root_frame,
                previous.get(&base),
                registry,
            )?;
            snapshot.insert_frame(frame, page.backing.is_some());
        }
        snapshot.refresh_mmu(&mmu_changed);
        snapshot.has_aliases = snapshot.alias_count != 0;
        snapshot.dynamic_code = snapshot.dynamic_code_pages != 0;
        snapshot.identity = self.identity;
        snapshot.code_revision = self.code_revision;
        snapshot.backing_revision = backing_revision;
        if self.parallel_reservations_dirty {
            snapshot.reservations = self.reservations.clone();
            self.parallel_reservations_dirty = false;
        }
        cache.source_revision = self.revision;
        cache.source_backing_revision = backing_revision;
        if registry.metrics.incremental_updates.is_multiple_of(256) {
            registry.shared.retain(|_, page| page.strong_count() != 0);
        }
        let view = View::new(cache.snapshot.clone());
        self.parallel_cache = Some(cache);
        Some(view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_worker_code_writes_refresh_their_frame_metadata() {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        let mut registry = Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write_array(0x1000, 0xd503201fu32.to_le_bytes())
            .unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.fetch_u32(0x1000).unwrap(), 0xd503201f);
        let frame = &view.snapshot.frames[view.snapshot.pages[&0x1000]];
        assert_eq!(
            frame.code_revision,
            memory.frames[memory.pages[&0x1000]]
                .as_ref()
                .unwrap()
                .instruction_revision
        );
        drop(view);
        assert_eq!(registry.metrics.full_rebuilds, 1);
        assert_eq!(registry.metrics.incremental_pages, 1);
    }

    #[test]
    fn backing_epochs_refresh_only_backed_pages_and_preserve_aliases_and_cow() {
        let mut memory = Memory::default();
        memory
            .map(0x1000000, 1024 * PAGE_SIZE, Permissions::R)
            .unwrap();
        memory
            .map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        let object = memory.frames[memory.pages[&0x1000]]
            .as_ref()
            .unwrap()
            .backing
            .as_ref()
            .unwrap()
            .object
            .clone();
        memory
            .map_backed(0x3000, vec![object.clone()], true, Permissions::RW, false)
            .unwrap();
        memory
            .map_backed(0x5000, vec![object.clone()], false, Permissions::RW, false)
            .unwrap();
        let mut registry = Registry::default();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        assert!(view.snapshot.has_aliases);
        view.write_array(0x1000, [42u8]).unwrap();
        assert_eq!(view.read_array::<1>(0x3000).unwrap(), [42]);
        drop(view);
        memory.commit_parallel().unwrap();
        memory.write_array(0x5000, [88u8]).unwrap();
        object.write(0, &[99]).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<1>(0x1000).unwrap(), [99]);
        assert_eq!(view.read_array::<1>(0x3000).unwrap(), [99]);
        assert_eq!(view.read_array::<1>(0x5000).unwrap(), [88]);
        drop(view);
        memory.unmap(0x3000, PAGE_SIZE).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert!(!view.snapshot.has_aliases);
        assert_eq!(view.read_array::<1>(0x5000).unwrap(), [88]);
        drop(view);
        assert_eq!(registry.metrics.full_rebuilds, 1);
        assert!(
            registry.metrics.incremental_pages <= 8,
            "{:?}",
            registry.metrics
        );
    }

    #[test]
    fn mapping_churn_updates_only_changed_pages_and_reuses_root_slots() {
        let mut memory = Memory::default();
        memory
            .map(0x10000, 1024 * PAGE_SIZE, Permissions::R)
            .unwrap();
        let mut registry = Registry::default();
        drop(memory.parallel_view(&mut registry).unwrap());
        for iteration in 0..64u64 {
            let base = 0x10000000 + iteration * 4 * PAGE_SIZE;
            memory.reserve(base, 3 * PAGE_SIZE, false).unwrap();
            memory.protect(base, PAGE_SIZE, Permissions::RW).unwrap();
            memory
                .write_array(base, 0xd503201fu32.to_le_bytes())
                .unwrap();
            memory.protect(base, PAGE_SIZE, Permissions::RX).unwrap();
            let view = memory.parallel_view(&mut registry).unwrap();
            assert_eq!(view.fetch_u32(base).unwrap(), 0xd503201f);
            assert!(matches!(
                view.read_array::<1>(base + PAGE_SIZE),
                Err(MemoryError::Permission { .. })
            ));
            assert_eq!(view.read_array::<1>(0x10000).unwrap(), [0]);
            drop(view);
            memory.unmap(base, 3 * PAGE_SIZE).unwrap();
            let view = memory.parallel_view(&mut registry).unwrap();
            assert_eq!(view.read_array::<1>(base), Err(MemoryError::Unmapped(base)));
            drop(view);
        }
        assert_eq!(registry.metrics.full_rebuilds, 1);
        assert_eq!(registry.metrics.full_rebuild_pages, 1024);
        assert_eq!(registry.metrics.incremental_pages, 128);
    }

    #[test]
    fn retained_views_keep_frozen_mappings_when_root_slots_are_reused() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let old = memory.parallel_view(&mut registry).unwrap();
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        memory.map(0x3000, PAGE_SIZE, Permissions::R).unwrap();
        let new = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(old.read_array::<1>(0x1000).unwrap(), [0]);
        assert_eq!(
            new.read_array::<1>(0x1000),
            Err(MemoryError::Unmapped(0x1000))
        );
        assert_eq!(new.read_array::<1>(0x3000).unwrap(), [0]);
        assert_eq!(registry.metrics.full_rebuilds, 2);
    }
}
