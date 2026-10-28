// SPDX-License-Identifier: GPL-3.0-or-later
//! Incremental metadata maintenance at joined coordinator checkpoints.
use super::*;

#[derive(Default)]
pub(super) struct BackingIndex {
    domains: BTreeMap<u64, BackingDomain>,
    unscoped: BTreeSet<u64>,
    coupled: BTreeMap<(u8, u64), BTreeSet<u64>>,
    /// Only MAP_SHARED pages need entries. No larger per-page CPU descriptor,
    /// backing Rc, or work on ordinary instruction/data translations.
    pub(super) futex: BTreeMap<u64, (u64, u64)>,
}
struct BackingDomain {
    generation: u64,
    pages: BTreeMap<u64, Option<u64>>,
    offsets: BTreeSet<(u64, u64)>,
    unindexed: BTreeSet<u64>,
}
impl BackingIndex {
    pub(super) fn commit_domains(&self) -> BTreeSet<(u8, u64)> {
        // Content-change domains are not necessarily quiescence dependencies.
        // Stable retained providers permit local mapping commits independently;
        // custom providers keep their original transitive pause boundary.
        self.coupled.keys().copied().collect()
    }
    pub(super) fn insert(
        &mut self,
        base: u64,
        domain: Option<(u64, u64)>,
        object: &dyn PageBacking,
        physical: u64,
        futex: Option<(u64, u64)>,
    ) {
        if !object.parallel_commit_isolated() {
            let key = domain.map_or((0, physical), |(id, _)| (1, id));
            self.coupled.entry(key).or_default().insert(base);
        }
        if let Some(key) = futex {
            self.futex.insert(base, key);
        }
        if let Some((identity, generation)) = domain {
            // Adding one new mapping cannot acknowledge changes to old pages.
            let group = self
                .domains
                .entry(identity)
                .or_insert_with(|| BackingDomain {
                    generation,
                    pages: BTreeMap::new(),
                    offsets: BTreeSet::new(),
                    unindexed: BTreeSet::new(),
                });
            let offset = object.parallel_domain_offset();
            group.pages.insert(base, offset);
            if let Some(offset) = offset {
                debug_assert_eq!(offset % PAGE_SIZE, 0);
                group.offsets.insert((offset, base));
            } else {
                group.unindexed.insert(base);
            }
        } else {
            self.unscoped.insert(base);
        }
    }
    fn remove(&mut self, base: u64, domain: Option<(u64, u64)>, physical: u64) {
        self.futex.remove(&base);
        let key = domain.map_or((0, physical), |(id, _)| (1, id));
        if let Some(pages) = self.coupled.get_mut(&key) {
            pages.remove(&base);
            if pages.is_empty() {
                self.coupled.remove(&key);
            }
        }
        if let Some((identity, _)) = domain {
            let group = self.domains.get_mut(&identity).expect("indexed domain");
            if let Some(Some(offset)) = group.pages.remove(&base) {
                group.offsets.remove(&(offset, base));
            } else {
                group.unindexed.remove(&base);
            }
            if group.pages.is_empty() {
                self.domains.remove(&identity);
            }
        } else {
            self.unscoped.remove(&base);
        }
    }
}

pub(super) struct HardwareChange {
    pub(super) before: u64,
    pub(super) ranges: Vec<std::ops::Range<u64>>,
}
impl Snapshot {
    fn note_anonymous_changes(&mut self, mut ranges: Vec<std::ops::Range<u64>>) {
        if !self.hardware || ranges.is_empty() {
            return;
        }
        ranges.sort_unstable_by_key(|r| r.start);
        let mut merged: Vec<std::ops::Range<u64>> = Vec::new();
        for range in ranges {
            if let Some(last) = merged.last_mut() {
                if range.start <= last.end {
                    last.end = last.end.max(range.end);
                    continue;
                }
            }
            merged.push(range);
        }
        let before = self.hardware_generation;
        self.hardware_generation = new_backing_identity();
        // Allocate stamps only for explicit chunks. An unvisited anonymous
        // chunk uses this range generation on demand. All exported hardware
        // leaves are adopted into explicit descriptors at joined checkpoints.
        for range in &merged {
            let first = range.start / crate::HARDWARE_MAPPING_CHUNK_SIZE;
            let last = (range.end - 1) / crate::HARDWARE_MAPPING_CHUNK_SIZE;
            for (_, stamp) in self.hardware_chunks.range_mut(first..=last) {
                *stamp = self.hardware_generation;
            }
        }
        self.anonymous
            .note_changes(&merged, self.hardware_generation);
        if merged.len() > 4096 {
            self.hardware_changes.clear();
            return;
        }
        self.hardware_changes.push_back(HardwareChange {
            before,
            ranges: merged,
        });
        while self.hardware_changes.len() > 32
            || self
                .hardware_changes
                .iter()
                .map(|c| c.ranges.len())
                .sum::<usize>()
                > 4096
        {
            self.hardware_changes.pop_front();
        }
    }
    fn note_hardware_changes(
        &mut self,
        addresses: impl Iterator<Item = u64>,
        mut ranges: Vec<std::ops::Range<u64>>,
    ) {
        if !self.hardware {
            return;
        }
        let mut last_chunk = None;
        for address in addresses {
            let chunk = address / crate::HARDWARE_MAPPING_CHUNK_SIZE;
            if last_chunk != Some(chunk) {
                let start = chunk * crate::HARDWARE_MAPPING_CHUNK_SIZE;
                if self
                    .pages
                    .range(start..start + crate::HARDWARE_MAPPING_CHUNK_SIZE)
                    .next()
                    .is_some()
                {
                    self.hardware_chunks.entry(chunk).or_insert(0);
                } else {
                    self.hardware_chunks.remove(&chunk);
                }
                last_chunk = Some(chunk);
            }
            ranges.push(address..address + PAGE_SIZE);
        }
        self.note_anonymous_changes(ranges);
    }
    fn remove_frame(&mut self, base: u64) -> Option<Frame> {
        let index = self.pages.remove(&base)?;
        let frame = self.frames.swap_remove(index);
        if let Some(moved) = self.frames.get(index) {
            self.pages.insert(moved.base, index);
            self.positions[moved.root_frame] = Some(index);
        }
        self.positions[frame.root_frame] = None;
        if self.backed_pages.remove(&base) {
            self.backings
                .remove(base, frame.backing_domain, frame.bytes.identity);
        }
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
    fn insert_frame(&mut self, frame: Frame, backing: Option<&Backed>, futex: Option<(u64, u64)>) {
        let count = self.identities.entry(frame.bytes.identity).or_insert(0);
        self.alias_count += usize::from(*count == 1);
        *count += 1;
        self.dynamic_code_pages += usize::from(frame.dynamic_code);
        if let Some(backing) = backing {
            self.backed_pages.insert(frame.base);
            self.backings.insert(
                frame.base,
                frame.backing_domain,
                backing.object.as_ref(),
                frame.bytes.identity,
                futex,
            );
        }
        self.pages.insert(frame.base, self.frames.len());
        self.positions[frame.root_frame] = Some(self.frames.len());
        self.frames.push(frame);
    }
}

impl Memory {
    /// Release obsolete cached byte owners without rebuilding the next View.
    /// Retained Views/pins/fork peers keep their own legitimate storage leases.
    /// The count is retired snapshot frames, not physical bytes or host RSS.
    pub fn reclaim_unused(&mut self) -> usize {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().reclaim_unused();
        }
        if self.has_parallel_users() {
            return 0;
        }
        self.anonymous.prune();
        let anonymous = self.parallel_cache.as_ref().map(|c| {
            super::anonymous::Anonymous::freeze(
                self,
                c.snapshot.code_epoch.clone(),
                c.snapshot.hardware,
                Some(&c.snapshot.anonymous),
            )
        });
        let Some(cache) = &mut self.parallel_cache else {
            return 0;
        };
        let Some(snapshot) = Arc::get_mut(&mut cache.snapshot) else {
            return 0;
        };
        if snapshot
            .dirty_pages
            .iter()
            .any(|word| word.load(Ordering::Relaxed) != 0)
        {
            return 0; // uncommitted worker effects still own their original frames
        }
        if let Some(anonymous) = anonymous {
            snapshot.anonymous = anonymous;
            snapshot.anonymous.prune();
            self.parallel_anonymous_dirty = false;
        }
        let retired: Vec<_> = self
            .parallel_mappings
            .iter()
            .copied()
            .filter(|base| {
                self.pages.get(base).is_none_or(|&index| {
                    let page = self.frames[index].as_ref().unwrap();
                    page.backing.is_none() && page.bytes.is_zero() && !page.charge.resident()
                }) && snapshot.pages.contains_key(base)
            })
            .collect();
        for base in &retired {
            drop(snapshot.remove_frame(*base));
        }
        snapshot.note_hardware_changes(retired.iter().copied(), Vec::new());
        snapshot.refresh_mmu(retired.iter().copied());
        snapshot.has_aliases = snapshot.alias_count != 0;
        snapshot.dynamic_code = snapshot.dynamic_code_pages != 0 || snapshot.anonymous.executable();
        // Keep source_revision/parallel_mappings unchanged. The next normal
        // preparation still installs new permissions/bytes/reservations once.
        retired.len()
    }

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
        let mapping_changes = std::mem::take(&mut self.parallel_mappings);
        let mut changed = mapping_changes.clone();
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
            // Query one live representative per file, not every ELF page after
            // an unrelated SHM write. No provider ownership or Rc is retained
            // here; dropping/unmapping a file keeps its original lifetime.
            let mut candidates = snapshot.backings.unscoped.clone();
            for (&identity, group) in &mut snapshot.backings.domains {
                let Some(base) = group.pages.keys().find(|base| !changed.contains(base)) else {
                    // All old members are already being replaced or removed.
                    continue;
                };
                let frame = &snapshot.frames[snapshot.pages[base]];
                let page = self.frames[frame.root_frame]
                    .as_ref()
                    .expect("backed frame");
                let backing = page.backing.as_ref().expect("indexed backing");
                registry.metrics.backing_domain_checks += 1;
                let mut ranges = None;
                match backing.object.parallel_change_domain() {
                    Some((id, generation)) if id == identity => {
                        if generation == group.generation {
                            continue;
                        }
                        ranges = backing.object.parallel_changes_since(group.generation);
                        group.generation = generation;
                    }
                    // A provider changing its declared domain is conservative.
                    _ => {}
                }
                if let Some(ranges) = ranges {
                    candidates.extend(group.unindexed.iter().copied());
                    for range in ranges {
                        if range.start < range.end {
                            candidates.extend(
                                group
                                    .offsets
                                    .range(((range.start & !(PAGE_SIZE - 1)), 0)..(range.end, 0))
                                    .map(|&(_, base)| base),
                            );
                        }
                    }
                } else {
                    candidates.extend(group.pages.keys().copied());
                }
            }
            // Changed domains retain individual versions and live EOF checks.
            // Unknown providers retain the original conservative preparation.
            for base in candidates {
                if changed.contains(&base) {
                    continue;
                }
                registry.metrics.backing_page_checks += 1;
                let frame = &snapshot.frames[snapshot.pages[&base]];
                let page = self.frames[frame.root_frame]
                    .as_ref()
                    .expect("backed frame");
                let backing = page.backing.as_ref().expect("indexed backing");
                if !backing.object.parallel_versioned()
                    || frame.backing_version.load(Ordering::Relaxed) != backing.object.version()
                    || frame.error != page.check_backing(base).err()
                {
                    changed.insert(base);
                }
            }
        }
        registry.metrics.code_invalidations +=
            u64::from(snapshot.code_revision != self.code_revision);
        registry.metrics.incremental_pages += changed.len() as u64;
        // Canonical direct bytes already include file/worker writes. Content
        // publication does not change a frame's mapping schema. Keep its slab
        // position, alias/backing indices and hardware generation untouched.
        // Actual mapping/admission changes and executable code remain on the
        // normal replacement path; unknown providers keep full preparation.
        changed.retain(|base| {
            if mapping_changes.contains(base) {
                return true;
            }
            let Some(&position) = snapshot.pages.get(base) else {
                return true;
            };
            let frame = &snapshot.frames[position];
            let Some(page) = self.frames.get(frame.root_frame).and_then(Option::as_ref) else {
                return true;
            };
            let stable_domain = page.backing.as_ref().is_none_or(|backing| {
                backing.object.parallel_versioned()
                    && backing.object.parallel_change_domain().map(|(id, _)| id)
                        == frame.backing_domain.map(|(id, _)| id)
            });
            if !frame.direct
                || frame.permissions.execute
                || page.permissions.execute
                || frame.permissions != page.permissions
                || !Arc::ptr_eq(&frame.charge, &page.charge)
                || frame.error.is_some()
                || page.check_backing(*base).is_err()
                || !stable_domain
                || !direct_matches(page, frame)
            {
                return true;
            }
            frame.refresh_content_metadata(page);
            registry.metrics.direct_frame_refreshes += 1;
            false
        });
        // instruction_identity uses this token, not source_backing_revision.
        // Data-only file/SHM writes must not discard every CPU's decoded ELF
        // code. Unknown providers still enter `changed`; executable removals,
        // replacements, version/EOF changes retain conservative invalidation.
        let executable_changed = changed.iter().any(|base| {
            snapshot
                .pages
                .get(base)
                .is_some_and(|&i| snapshot.frames[i].permissions.execute)
                || self.pages.get(base).is_some_and(|&i| {
                    self.frames[i]
                        .as_ref()
                        .is_some_and(|p| p.permissions.execute)
                })
        });
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
        let mut mmu_changed = Slots::new();
        for base in changed {
            let Some(&root_frame) = self.pages.get(&base) else {
                mmu_changed.push(base);
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
            let adoption = snapshot.hardware
                && snapshot.anonymous.cached(base).is_some_and(|old| {
                    old.permissions == frame.permissions
                        && old.code_revision == frame.code_revision
                        && old.bytes.identity == frame.bytes.identity
                        && old.error == frame.error
                        && old.backing_version.load(Ordering::Relaxed)
                            == frame.backing_version.load(Ordering::Relaxed)
                });
            if adoption {
                let chunk = base / crate::HARDWARE_MAPPING_CHUNK_SIZE;
                snapshot
                    .hardware_chunks
                    .entry(chunk)
                    .or_insert(snapshot.hardware_generation);
            } else {
                mmu_changed.push(base);
            }
            snapshot.insert_frame(frame, page.backing.as_ref(), shared_futex_page_key(page));
        }
        if self.parallel_anonymous_dirty {
            snapshot.anonymous = super::anonymous::Anonymous::freeze(
                self,
                registry.code_epoch.clone(),
                registry.hardware,
                Some(&snapshot.anonymous),
            );
            snapshot.anonymous.prune();
            self.parallel_anonymous_dirty = false;
        }
        snapshot.note_hardware_changes(
            mmu_changed.iter().copied(),
            std::mem::take(&mut self.parallel_anonymous_changes),
        );
        snapshot.refresh_mmu(mmu_changed);
        snapshot.has_aliases = snapshot.alias_count != 0;
        snapshot.dynamic_code = snapshot.dynamic_code_pages != 0 || snapshot.anonymous.executable();
        snapshot.identity = self.identity;
        snapshot.code_revision = self.code_revision;
        if executable_changed {
            snapshot.backing_revision = backing_revision;
        }
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
    fn hardware_chunk_versions_survive_journal_expiry_without_retaining_holes() {
        let mut memory = Memory::default();
        let mut registry = Registry::default();
        registry.use_hardware();
        memory.prepare_hardware().unwrap();
        let a = PAGE_SIZE;
        let b = 2 * crate::HARDWARE_MAPPING_CHUNK_SIZE;
        memory.map(a, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(b, PAGE_SIZE, Permissions::RW).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        let old = view.hardware_view_version().0;
        let unchanged = view.hardware_mapping_chunk_version(a).unwrap();
        let changed = view.hardware_mapping_chunk_version(b).unwrap();
        drop(view);
        for i in 0..80 {
            memory
                .protect(
                    b,
                    PAGE_SIZE,
                    if i % 2 == 0 {
                        Permissions::R
                    } else {
                        Permissions::RW
                    },
                )
                .unwrap();
            drop(memory.parallel_view(&mut registry).unwrap());
        }
        let view = memory.parallel_view(&mut registry).unwrap();
        assert!(view.hardware_mapping_ranges(old).is_none());
        assert_eq!(view.hardware_mapping_chunk_version(a), Some(unchanged));
        assert_ne!(view.hardware_mapping_chunk_version(b), Some(changed));
        drop(view);
        memory.unmap(b, PAGE_SIZE).unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.hardware_mapping_chunk_version(b), None);
        assert_eq!(view.snapshot.hardware_chunks.len(), 1);
        drop(view);
        // Sparse addresses must not accumulate permanent invalidation tombstones.
        for i in 2..82 {
            let address = i * crate::HARDWARE_MAPPING_CHUNK_SIZE;
            memory.map(address, PAGE_SIZE, Permissions::RW).unwrap();
            let view = memory.parallel_view(&mut registry).unwrap();
            let version = view.hardware_mapping_chunk_version(address).unwrap();
            assert_ne!(version, changed);
            assert_eq!(view.snapshot.hardware_chunks.len(), 2);
            drop(view);
            memory.unmap(address, PAGE_SIZE).unwrap();
            let view = memory.parallel_view(&mut registry).unwrap();
            assert_eq!(view.snapshot.hardware_chunks.len(), 1);
            assert_eq!(view.hardware_mapping_chunk_version(address), None);
            drop(view);
        }
        // A replacement snapshot has no shared history; even steady chunks get
        // fresh stamps, so an executor cannot mistake it for its previous schema.
        let mut replacement = Registry::default();
        replacement.use_hardware();
        let view = memory.parallel_view(&mut replacement).unwrap();
        assert_ne!(view.hardware_mapping_chunk_version(a), Some(unchanged));
        assert_eq!(memory.resident_bytes(), 0);
    }

    #[test]
    fn hardware_chunk_stamps_cover_interval_overflow_and_stay_absent_in_software_views() {
        let mut memory = Memory::default();
        let mut registry = Registry::default();
        memory
            .map(PAGE_SIZE, 8194 * PAGE_SIZE, Permissions::RW)
            .unwrap();
        memory.materialize_descriptors(PAGE_SIZE, 8194 * PAGE_SIZE as usize);
        let view = memory.parallel_view(&mut registry).unwrap();
        assert!(view.snapshot.hardware_chunks.is_empty());
        drop(view);
        registry.use_hardware();
        memory.prepare_hardware().unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        let old = view.hardware_view_version().0;
        drop(view);
        for page in (1..8195).step_by(2) {
            memory
                .protect(page * PAGE_SIZE, PAGE_SIZE, Permissions::R)
                .unwrap();
        }
        let view = memory.parallel_view(&mut registry).unwrap();
        assert!(view.hardware_mapping_ranges(old).is_none());
        for chunk in 0..17 {
            assert_eq!(
                view.hardware_mapping_chunk_version(chunk * crate::HARDWARE_MAPPING_CHUNK_SIZE),
                Some(view.hardware_view_version().0)
            );
        }
        assert_eq!(view.snapshot.hardware_chunks.len(), 17);
        assert_eq!(memory.resident_bytes(), 0);
    }

    #[test]
    fn unversioned_provider_storage_replacement_keeps_the_conservative_refresh() {
        struct Backing(RefCell<Arc<SharedPage>>);
        impl PageBacking for Backing {
            fn parallel_key(&self) -> Option<(u64, u64)> {
                Some((987654, 0))
            }
            fn shared_page(&self) -> Option<Arc<SharedPage>> {
                Some(self.0.borrow().clone())
            }
            fn check(&self, _: u64) -> Result<(), MemoryError> {
                Ok(())
            }
            fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
                self.0
                    .borrow()
                    .with_read(offset, out.len(), |bytes| out.copy_from_slice(bytes));
                Ok(())
            }
            fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
                unreachable!()
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn version(&self) -> u64 {
                0
            }
            fn writable(&self) -> bool {
                false
            }
            fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
                unreachable!()
            }
        }
        let backing = Rc::new(Backing(RefCell::new(Arc::new(SharedPage::new(
            [1; PAGE_SIZE as usize],
        )))));
        let mut m = Memory::default();
        m.map_backed(0x1000, vec![backing.clone()], true, Permissions::R, false)
            .unwrap();
        let mut registry = Registry::default();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<1>(0x1000).unwrap(), [1]);
        drop(view);
        *backing.0.borrow_mut() = Arc::new(SharedPage::new([2; PAGE_SIZE as usize]));
        backing_changed();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<1>(0x1000).unwrap(), [2]);
        assert_eq!(registry.metrics.incremental_pages, 1);
    }

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
        assert_eq!(registry.metrics.full_rebuild_pages, 0);
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
