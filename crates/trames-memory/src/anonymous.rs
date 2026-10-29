// SPDX-License-Identifier: GPL-3.0-or-later
//! Unreached anonymous addresses own range metadata, not page descriptors.
use super::*;
use std::sync::{Arc, Mutex};

pub(super) struct Resident {
    pub bytes: Arc<SharedPage>,
    pub charge: Arc<Charge>,
}
pub(super) struct Store {
    pages: [Mutex<BTreeMap<u64, Arc<Resident>>>; 16],
    account: Arc<Account>,
    native: Option<Mutex<BTreeMap<u64, Arc<dyn crate::HardwareRange>>>>,
}
impl Store {
    fn new(account: Arc<Account>) -> Arc<Self> {
        Arc::new(Self {
            pages: std::array::from_fn(|_| Mutex::new(BTreeMap::new())),
            native: account
                .native_allowed()
                .then(|| Mutex::new(BTreeMap::new())),
            account,
        })
    }
    pub fn get(&self, base: u64) -> Arc<Resident> {
        let native = self.native.as_ref().map(|n| n.lock().unwrap());
        let range = native
            .as_ref()
            .and_then(|n| n.range(..=base).next_back())
            .filter(|(start, r)| base - **start < r.len() as u64);
        self.pages[((base / PAGE_SIZE) & 15) as usize]
            .lock()
            .unwrap()
            .entry(base)
            .or_insert_with(|| {
                if let Some((&start, range)) = range {
                    let storage = Arc::new(RangePage {
                        range: range.clone(),
                        offset: (base - start) as usize,
                    });
                    Arc::new(Resident {
                        bytes: Arc::new(SharedPage::from_hardware(storage)),
                        charge: Charge::native(&self.account),
                    })
                } else {
                    Arc::new(Resident {
                        bytes: Arc::new(SharedPage::from_owned(PageBytes::Zero, None)),
                        charge: Charge::new(&self.account),
                    })
                }
            })
            .clone()
    }
    pub fn lookup(&self, base: u64) -> Option<Arc<Resident>> {
        self.pages[((base / PAGE_SIZE) & 15) as usize]
            .lock()
            .unwrap()
            .get(&base)
            .cloned()
    }
    pub fn remove(&self, base: u64) {
        self.pages[((base / PAGE_SIZE) & 15) as usize]
            .lock()
            .unwrap()
            .remove(&base);
    }
    pub fn populated(&self, start: u64, end: u64) -> Vec<u64> {
        let mut out = Vec::new();
        for shard in &self.pages {
            out.extend(
                shard
                    .lock()
                    .unwrap()
                    .range(start..end)
                    .filter_map(|(&base, p)| p.charge.resident().then_some(base)),
            );
        }
        if let Some(native) = &self.native {
            for (&base, r) in native.lock().unwrap().iter() {
                out.extend(
                    (base.max(start)..(base + r.len() as u64).min(end)).step_by(PAGE_SIZE as usize),
                );
            }
            out.sort_unstable();
            out.dedup();
        }
        out
    }
    pub fn native_contains(&self, address: u64) -> bool {
        self.native.as_ref().is_some_and(|n| {
            n.lock()
                .unwrap()
                .range(..=address)
                .next_back()
                .is_some_and(|(&base, r)| address - base < r.len() as u64)
        })
    }
    pub fn export_range(
        &self,
        base: u64,
        len: usize,
        allocate: impl FnOnce() -> Result<Arc<dyn crate::HardwareRange>, MemoryError>,
    ) -> Result<Option<Arc<dyn crate::HardwareRange>>, MemoryError> {
        let Some(native) = &self.native else {
            return Ok(None);
        };
        let mut native = native.lock().unwrap();
        if let Some(r) = native.get(&base) {
            return Ok((r.len() == len && r.is_live()).then(|| r.clone()));
        }
        // Get and install take this object lock before the shards. No page can
        // acquire a competing canonical allocation while a range is admitted.
        if self.pages.iter().any(|s| {
            s.lock()
                .unwrap()
                .range(base..base + len as u64)
                .next()
                .is_some()
        }) {
            return Ok(None);
        }
        let range = allocate()?;
        if range.len() != len
            || !range.physical_address().is_multiple_of(len as u64)
            || !(range.pointer() as usize).is_multiple_of(PAGE_SIZE as usize)
        {
            return Err(MemoryError::InvalidRange);
        }
        self.account.register_native(&range);
        native.insert(base, range.clone());
        Ok(Some(range))
    }
}

struct RangePage {
    range: Arc<dyn crate::HardwareRange>,
    offset: usize,
}
// SAFETY: a checked, retained subpage of the canonical complete range. Its
// original hardware gate excludes actors before exposing any Rust byte borrow.
unsafe impl crate::HardwareStorage for RangePage {
    fn pointer(&self) -> *mut u8 {
        self.range.pointer().wrapping_add(self.offset)
    }
    fn physical_address(&self) -> u64 {
        self.range.physical_address() + self.offset as u64
    }
    fn is_live(&self) -> bool {
        self.range.is_live()
    }
    fn begin_host_access(&self) {
        self.range.begin_host_access();
    }
    fn end_host_access(&self) {
        self.range.end_host_access();
    }
    fn publish_host_write(&self, offset: usize, len: usize) {
        self.range.publish_host_write(self.offset + offset, len);
    }
}

#[derive(Clone)]
pub(super) struct Retirement {
    pub start: u64,
    pub end: u64,
    pub store: Arc<Store>,
}

pub(super) const TOKEN: usize = 1usize << (usize::BITS - 1);
#[derive(Clone)]
pub(super) struct Range {
    pub end: u64,
    pub page: Rc<Page>,
    pub store: Arc<Store>,
}
#[derive(Clone, Default)]
pub(super) struct Anonymous {
    pub live: Arc<crate::parallel::anonymous::Additions>,
    pub ranges: BTreeMap<u64, Range>,
}
impl Anonymous {
    pub fn containing(&self, address: u64) -> Option<(u64, &Range)> {
        self.ranges
            .range(..=address)
            .next_back()
            .filter(|(_, r)| address < r.end)
            .map(|(&a, r)| (a, r))
    }
    pub fn page(&self, address: u64) -> Option<&Page> {
        Some(self.containing(address)?.1.page.as_ref())
    }
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.containing(start).is_some() || self.ranges.range(start..end).next().is_some()
    }
    pub fn bytes(&self) -> usize {
        self.ranges.iter().map(|(&a, r)| (r.end - a) as usize).sum()
    }
    pub fn remove(&mut self, start: u64, end: u64) {
        let mut keys: Vec<_> = self.ranges.range(start..end).map(|(&a, _)| a).collect();
        if let Some((a, _)) = self.containing(start) {
            if a < start {
                keys.push(a);
            }
        }
        for a in keys {
            let r = self.ranges.remove(&a).unwrap();
            if a < start {
                self.ranges.insert(
                    a,
                    Range {
                        end: start,
                        page: r.page.clone(),
                        store: r.store.clone(),
                    },
                );
            }
            if r.end > end {
                self.ranges.insert(
                    end,
                    Range {
                        end: r.end,
                        page: r.page,
                        store: r.store,
                    },
                );
            }
        }
    }
    pub fn insert(&mut self, start: u64, end: u64, page: Rc<Page>, account: &Arc<Account>) {
        self.insert_store(start, end, page, Store::new(account.clone()));
    }
    pub fn insert_store(
        &mut self,
        mut start: u64,
        mut end: u64,
        mut page: Rc<Page>,
        store: Arc<Store>,
    ) {
        debug_assert!(start < end && !self.overlaps(start, end));
        let same = |p: &Page, q: &Page| {
            p.permissions == q.permissions
                && p.mapping == q.mapping
                && p.instruction_revision == q.instruction_revision
        };
        if let Some((&a, r)) = self.ranges.range(..start).next_back() {
            if r.end == start && same(&r.page, &page) && Arc::ptr_eq(&r.store, &store) {
                start = a;
                page = r.page.clone();
                self.ranges.remove(&a);
            }
        }
        if self
            .ranges
            .get(&end)
            .is_some_and(|r| same(&r.page, &page) && Arc::ptr_eq(&r.store, &store))
        {
            end = self.ranges.remove(&end).unwrap().end;
        }
        self.ranges.insert(start, Range { end, page, store });
    }
    pub fn populated(&self) -> Vec<u64> {
        let mut seen = BTreeSet::new();
        let mut pages = Vec::new();
        for range in self.ranges.values() {
            if seen.insert(Arc::as_ptr(&range.store) as usize) {
                pages.extend(
                    range
                        .store
                        .populated(0, ADDRESS_LIMIT)
                        .into_iter()
                        .filter(|&base| {
                            self.containing(base)
                                .is_some_and(|(_, r)| Arc::ptr_eq(&r.store, &range.store))
                        }),
                );
            }
        }
        pages
    }
    pub fn prune(&self, changes: &[Retirement]) {
        for change in changes {
            if let Some(native) = &change.store.native {
                let mut native = native.lock().unwrap();
                let first = change.start & !(HARDWARE_MAPPING_CHUNK_SIZE - 1);
                let candidates: Vec<_> = native
                    .range(first..change.end)
                    .map(|(&base, r)| (base, r.len() as u64))
                    .collect();
                for (base, len) in candidates {
                    if !self
                        .overlapping(base, base + len)
                        .iter()
                        .any(|(_, r)| Arc::ptr_eq(&r.store, &change.store))
                    {
                        native.remove(&base);
                    }
                }
            }
            #[cfg(test)]
            note_prune_scope();
            for shard in &change.store.pages {
                let mut pages = shard.lock().unwrap();
                let retired: Vec<_> = pages
                    .range(change.start..change.end)
                    .filter_map(|(&base, _)| {
                        #[cfg(test)]
                        note_prune_visit();
                        (!self
                            .containing(base)
                            .is_some_and(|(_, r)| Arc::ptr_eq(&r.store, &change.store)))
                        .then_some(base)
                    })
                    .collect();
                for base in retired {
                    pages.remove(&base);
                }
            }
        }
    }
    pub fn overlapping(&self, start: u64, end: u64) -> Vec<(u64, &Range)> {
        let mut out = Vec::new();
        if let Some((&base, r)) = self.ranges.range(..start).next_back() {
            if r.end > start {
                out.push((base, r));
            }
        }
        out.extend(self.ranges.range(start..end).map(|(&base, r)| (base, r)));
        out
    }
    pub fn fork(&self, account: &std::sync::Arc<residency::Account>) -> Self {
        Self {
            live: Default::default(),
            ranges: self
                .ranges
                .iter()
                .map(|(&a, r)| {
                    let mut page = (*r.page).clone();
                    page.charge = Charge::new(account);
                    (
                        a,
                        Range {
                            end: r.end,
                            page: Rc::new(page),
                            store: Store::new(account.clone()),
                        },
                    )
                })
                .collect(),
        }
    }
}
impl Memory {
    /// Publish a new RW anonymous range to existing execution Views. No old
    /// address, permission, byte owner, software alias or cached TLB is edited.
    /// Destructive edits still use the joined mapping boundary.
    pub fn map_anonymous_live(&mut self, address: u64, len: u64) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().map_anonymous_live(address, len);
        }
        let end = Self::mapping_end(address, len)?;
        if !self.is_free(address, len) {
            return Err(MemoryError::Overlap(address));
        }
        if self.anonymous.ranges.len() >= MAX_PAGE_DESCRIPTORS {
            return Err(MemoryError::Limit);
        }
        self.advance_code_revision();
        self.anonymous.insert(
            address,
            end,
            self.anonymous_page(Permissions::RW),
            &self.account,
        );
        let range = &self.anonymous.ranges[&address];
        self.anonymous.live.publish(address, range);
        self.note_anonymous_change(address, end);
        self.revision = self.revision.wrapping_add(1);
        self.invalidate_translations();
        Ok(())
    }
    pub(super) fn note_anonymous_change(&mut self, start: u64, end: u64) {
        self.parallel_anonymous_dirty = true;
        if self.parallel_cache.is_none() {
            return;
        }
        if let Some(last) = self.parallel_anonymous_changes.last_mut() {
            if start >= last.start && start <= last.end {
                last.end = last.end.max(end);
                return;
            }
        }
        self.parallel_anonymous_changes.push(start..end);
    }
    pub(super) fn retire_anonymous_range(&mut self, start: u64, end: u64) {
        for (base, r) in self.anonymous.overlapping(start, end) {
            let a = base.max(start);
            let b = r.end.min(end);
            if let Some(last) = self.anonymous_retired.last_mut() {
                if Arc::ptr_eq(&last.store, &r.store) && a >= last.start && a <= last.end {
                    last.end = last.end.max(b);
                    continue;
                }
            }
            self.anonymous_retired.push(Retirement {
                start: a,
                end: b,
                store: r.store.clone(),
            });
        }
    }
    pub(super) fn anonymous_index_changes(&self) -> Vec<std::ops::Range<u64>> {
        let mut ranges = self.parallel_anonymous_changes.clone();
        ranges.extend(self.anonymous_retired.iter().map(|r| r.start..r.end));
        ranges.extend(
            self.parallel_mappings
                .iter()
                .map(|&base| base..base + PAGE_SIZE),
        );
        ranges.sort_unstable_by_key(|r| r.start);
        let mut merged: Vec<std::ops::Range<u64>> = Vec::new();
        for r in ranges {
            if let Some(last) = merged.last_mut() {
                if r.start <= last.end {
                    last.end = last.end.max(r.end);
                    continue;
                }
            }
            merged.push(r);
        }
        merged
    }
    pub(super) fn anonymous_page(&self, permissions: Permissions) -> Rc<Page> {
        Rc::new(Page {
            bytes: Rc::new(PageBytes::Zero),
            charge: Charge::new(&self.account),
            permissions,
            instruction_revision: self.code_revision,
            backing: None,
            mapping: self.code_revision,
            data_revision: 0,
            parallel_dirty: false,
        })
    }
    pub(super) fn materialize_descriptors(&mut self, address: u64, len: usize) {
        if self.anonymous.ranges.is_empty() || len == 0 {
            return;
        }
        let base = address & !(PAGE_SIZE - 1);
        let entry = self.translations[Translation::slot(base)].get();
        if len <= (PAGE_SIZE - address % PAGE_SIZE) as usize
            && entry.matches(base, Translation::VALID)
            && entry.frame & TOKEN == 0
        {
            return;
        }
        let end = address + len as u64;
        for base in (address & !(PAGE_SIZE - 1)..end).step_by(PAGE_SIZE as usize) {
            if self.anonymous.page(base).is_none() {
                continue;
            }
            let range = self.anonymous.containing(base).unwrap().1;
            let mut page = if !self.has_parallel_users()
                && range.store.lookup(base).is_none()
                && !range.store.native_contains(base)
            {
                let mut page = (*range.page).clone();
                page.charge = Charge::new(&self.account);
                page
            } else {
                self.sparse_page(base).clone()
            };
            if !self.has_parallel_users() {
                let range = self.anonymous.containing(base).unwrap().1;
                range.store.remove(base);
                if !page.charge.resident() {
                    page.bytes = Rc::new(PageBytes::Zero);
                }
            }

            self.sparse_pages.get_mut().remove(&base);
            self.invalidate_translations();
            self.retire_anonymous_range(base, base + PAGE_SIZE);
            self.anonymous.remove(base, base + PAGE_SIZE);
            self.insert_owned_page(base, page);
            self.parallel_anonymous_dirty = true;
            self.revision = self.revision.wrapping_add(1);
        }
    }
    pub(super) fn insert_owned_page(&mut self, base: u64, page: Page) {
        if self.parallel_cache.is_some() {
            self.parallel_mappings.insert(base);
        }
        if let Some(&frame) = self.pages.get(&base) {
            self.frames[frame] = Some(page);
        } else {
            let frame = if let Some(frame) = self.free_frames.pop() {
                self.frames[frame] = Some(page);
                frame
            } else {
                self.frames.push(Some(page));
                self.frames.len() - 1
            };
            self.pages.insert(base, frame);
        }
    }
    pub(super) fn sparse_page(&self, base: u64) -> &Page {
        let range = self
            .anonymous
            .containing(base)
            .expect("anonymous translation")
            .1;
        let mut pages = self.sparse_pages.borrow_mut();
        let page = pages.entry(base).or_insert_with(|| {
            let resident = range.store.get(base);
            let mut page = (*range.page).clone();
            page.bytes = Rc::new(PageBytes::Concurrent(resident.bytes.clone()));
            page.charge = resident.charge.clone();
            Rc::new(page)
        });
        let pointer = Rc::as_ptr(page);
        drop(pages);
        // SAFETY: coordinator-local wrappers are retained until a VM mutation
        // invalidates translations. Insertion never moves an Rc allocation.
        unsafe { &*pointer }
    }
    pub(super) fn retire_sparse(&mut self, start: u64, end: u64) {
        // Destructive generations do not reuse the append-only publication
        // index. Retained Views keep the old immutable entries and byte owners.
        self.anonymous.live = Default::default();
        self.invalidate_translations();
        let pages = self.sparse_pages.get_mut();
        let keys: Vec<_> = pages.range(start..end).map(|(&base, _)| base).collect();
        for base in keys {
            pages.remove(&base);
        }
    }
}

#[cfg(test)]
thread_local! {
    static PRUNE_VISITS: Cell<usize> = const { Cell::new(0) };
    static INDEX_VISITS: Cell<usize> = const { Cell::new(0) };
    static PRUNE_SCOPES: Cell<usize> = const { Cell::new(0) };
    static REGION_LISTS: Cell<usize> = const { Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn note_prune_visit() {
    PRUNE_VISITS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
pub(crate) fn note_region_list() {
    REGION_LISTS.with(|count| count.set(count.get() + 1));
}
#[cfg(test)]
pub(crate) fn note_prune_scope() {
    PRUNE_SCOPES.with(|count| count.set(count.get() + 1));
}
#[cfg(test)]
pub(crate) fn note_index_visit() {
    INDEX_VISITS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parallel::Registry, CpuMemory};

    #[test]
    fn huge_accessible_vmas_keep_sparse_metadata_and_precise_faults() {
        let mut m = Memory::new(2 * PAGE_SIZE as usize);
        let base = 1 << 32;
        let len = 64 << 30;
        m.map(base, len, Permissions::RW).unwrap();
        assert!(m.pages.is_empty());
        assert_eq!(m.anonymous.ranges.len(), 1);
        assert_eq!(m.resident_bytes(), 0);
        let mut registry = Registry::default();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(registry.metrics.full_rebuild_pages, 0);
        view.check_translation(base + len - 1).unwrap();
        assert_eq!(
            view.check_translation(base + len),
            Err(MemoryError::Unmapped(base + len))
        );
        assert_eq!(view.read_array::<8>(base + len - 8).unwrap(), [0; 8]);
        drop(view);
        m.protect(base + PAGE_SIZE, PAGE_SIZE, Permissions::R)
            .unwrap();
        assert!(matches!(
            m.write_array(base + PAGE_SIZE, [1]),
            Err(MemoryError::Permission { .. })
        ));
        m.write_array(base, [17]).unwrap();
        m.write_array(base + len - 1, [23]).unwrap();
        assert_eq!(m.resident_bytes(), 2 * PAGE_SIZE as usize);
        assert_eq!(
            m.write_array(base + 2 * PAGE_SIZE, [9]),
            Err(MemoryError::Limit)
        );
        m.unmap(base + 2 * PAGE_SIZE, len - 3 * PAGE_SIZE).unwrap();
        assert_eq!(
            m.read_array::<1>(base + 2 * PAGE_SIZE),
            Err(MemoryError::Unmapped(base + 2 * PAGE_SIZE))
        );
        assert_eq!(m.read_array::<1>(base + len - 1).unwrap(), [23]);
    }

    #[test]
    fn sparse_views_share_canonical_bytes_across_snapshot_generations() {
        let mut m = Memory::new(8 * PAGE_SIZE as usize);
        let base = 1 << 32;
        m.map(base, 1 << 30, Permissions::RW).unwrap();
        assert_eq!(m.read_array::<8>(base).unwrap(), [0; 8]);
        let mut registry = Registry::default();
        let mut first = m.parallel_view(&mut registry).unwrap();
        // Refresh before the first write, retaining both generations of ranges.
        backing::backing_changed();
        let mut second = m.parallel_view(&mut registry).unwrap();
        first.write_array(base, 7u64.to_le_bytes()).unwrap();
        assert_eq!(second.read_array::<8>(base).unwrap(), 7u64.to_le_bytes());
        assert_eq!(m.read_array::<8>(base).unwrap(), 7u64.to_le_bytes());
        second
            .atomic_update(base, 8, |b| {
                let n = u64::from_le_bytes(b.try_into().unwrap()) + 1;
                b.copy_from_slice(&n.to_le_bytes());
                ((), true)
            })
            .unwrap();
        assert_eq!(first.read_array::<8>(base).unwrap(), 8u64.to_le_bytes());
        drop(first);
        drop(second);
        m.commit_parallel().unwrap();
        assert_eq!(m.read_u64(base).unwrap(), 8);
        assert!(
            m.pages.is_empty(),
            "ordinary handoff must retain the sparse canonical page"
        );
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize);
        let mut child = m.clone();
        child.write_array(base, 99u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_u64(base).unwrap(), 8);
        assert_eq!(child.read_u64(base).unwrap(), 99);
    }

    #[test]
    fn sparse_fork_with_retained_writer_copies_only_reached_bytes() {
        let mut m = Memory::default();
        let base = 1 << 32;
        m.map(base, 1 << 30, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        view.write_array(base + PAGE_SIZE, [7; 8]).unwrap();
        let mut child = m.clone();
        view.write_array(base + PAGE_SIZE, [9; 8]).unwrap();
        assert_eq!(child.read_array::<8>(base + PAGE_SIZE).unwrap(), [7; 8]);
        child.write_array(base + 3 * PAGE_SIZE, [17]).unwrap();
        assert_eq!(view.read_array::<1>(base + 3 * PAGE_SIZE).unwrap(), [0]);
        drop(view);
        m.commit_parallel().unwrap();
        assert_eq!(m.read_array::<8>(base + PAGE_SIZE).unwrap(), [9; 8]);
    }

    #[test]
    fn sparse_shared_views_keep_atomic_updates_and_publish_one_vm_generation() {
        let mut m = Memory::default();
        let base = 1 << 32;
        m.map(base, 1 << 30, Permissions::RW).unwrap();
        let before = m.revision();
        let mut registry = Registry::default();
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let mut view = m.parallel_view(&mut registry).unwrap();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..1024 {
                    view.atomic_update(base, 8, |bytes| {
                        let value = u64::from_le_bytes(bytes.try_into().unwrap()) + 1;
                        bytes.copy_from_slice(&value.to_le_bytes());
                        ((), true)
                    })
                    .unwrap();
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        m.commit_parallel().unwrap();
        assert_eq!(m.read_u64(base).unwrap(), 8192);
        assert_ne!(m.revision(), before);
        assert!(m.pages.is_empty());
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize);
    }

    #[test]
    fn sparse_partial_unmap_releases_only_removed_bytes_and_fork_stays_cow() {
        let mut m = Memory::default();
        let base = 1 << 32;
        m.map(base, 1 << 30, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        for page in 0..4 {
            view.write_array(base + page * PAGE_SIZE, [page as u8 + 1])
                .unwrap();
        }
        drop(view);
        m.commit_parallel().unwrap();
        assert!(m.pages.is_empty());
        m.unmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(m.resident_bytes(), 3 * PAGE_SIZE as usize);
        let child = m.clone();
        let mut view = m.parallel_view(&mut registry).unwrap();
        view.write_array(base, [17]).unwrap();
        drop(view);
        m.commit_parallel().unwrap();
        assert_eq!(m.read_array::<1>(base).unwrap(), [17]);
        assert_eq!(child.read_array::<1>(base).unwrap(), [1]);
        assert_eq!(m.read_array::<1>(base + 2 * PAGE_SIZE).unwrap(), [3]);
    }

    #[test]
    fn local_unmap_prunes_only_changed_addresses_in_large_resident_vmas() {
        let mut m = Memory::default();
        let a = 1 << 32;
        let b = 1 << 34;
        let len = 1 << 20;
        for base in [a, b] {
            m.map(base, len, Permissions::RW).unwrap();
        }
        let mut registry = Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        for base in [a, b] {
            for page in 0..len / PAGE_SIZE {
                view.write_array(base + page * PAGE_SIZE, [17]).unwrap();
            }
        }
        drop(view);
        m.commit_parallel().unwrap();
        assert!(m.pages.is_empty());
        PRUNE_VISITS.set(0);
        m.unmap(a + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert!(
            PRUNE_VISITS.get() <= 2,
            "local release visited {} page entries",
            PRUNE_VISITS.get()
        );
        assert_eq!(m.resident_bytes(), (2 * len - PAGE_SIZE) as usize);
        assert_eq!(m.read_array::<1>(b).unwrap(), [17]);
    }

    #[test]
    fn retained_sparse_generation_publishes_late_writes_and_deferred_retirement() {
        let mut m = Memory::default();
        let base = 1 << 32;
        m.map(base, 1 << 30, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut old = m.parallel_view(&mut registry).unwrap();
        old.write_array(base, [7]).unwrap();
        old.write_array(base + PAGE_SIZE, [9]).unwrap();
        backing::backing_changed();
        drop(m.parallel_view(&mut registry).unwrap());
        m.commit_parallel().unwrap();
        let before = m.revision();
        old.write_array(base, [11]).unwrap();
        m.commit_parallel().unwrap();
        assert_ne!(m.revision(), before);
        assert_eq!(m.read_array::<1>(base).unwrap(), [11]);
        m.unmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
        drop(m.parallel_view(&mut registry).unwrap());
        assert_eq!(m.resident_bytes(), 2 * PAGE_SIZE as usize);
        drop(old);
        m.commit_parallel().unwrap();
        m.reclaim_unused();
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(m.read_array::<1>(base).unwrap(), [11]);
    }

    #[test]
    fn fragmented_vmas_use_direct_retirement_and_incremental_snapshot_updates() {
        let mut m = Memory::default();
        let first = 1 << 32;
        let stride = 1 << 20;
        let len = 128 << 10;
        for index in 0..2000 {
            m.map(first + index * stride, len, Permissions::RW).unwrap();
        }
        let mut registry = Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        for index in 0..2000 {
            view.write_array(first + index * stride, [17]).unwrap();
        }
        let target = first + 1000 * stride;
        view.write_array(target + PAGE_SIZE, [23]).unwrap();
        drop(view);
        m.commit_parallel().unwrap();
        PRUNE_SCOPES.set(0);
        INDEX_VISITS.set(0);
        REGION_LISTS.set(0);
        assert_eq!(
            m.find_free(first + 2000 * stride, len),
            Some(first + 2000 * stride)
        );
        assert_eq!(REGION_LISTS.get(), 0);
        m.unmap(target + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert!(
            PRUNE_SCOPES.get() <= 2,
            "visited {} stores/caches",
            PRUNE_SCOPES.get()
        );
        assert!(
            INDEX_VISITS.get() <= 2,
            "rebuilt {} index ranges",
            INDEX_VISITS.get()
        );
        assert_eq!(m.resident_bytes(), 2000 * PAGE_SIZE as usize);
        PRUNE_SCOPES.set(0);
        INDEX_VISITS.set(0);
        m.protect(target + 2 * PAGE_SIZE, PAGE_SIZE, Permissions::R)
            .unwrap();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<1>(first).unwrap(), [17]);
        assert_eq!(view.read_array::<1>(target).unwrap(), [17]);
        assert!(PRUNE_SCOPES.get() <= 1);
        assert!(INDEX_VISITS.get() <= 2);
        assert_eq!(REGION_LISTS.get(), 0);
    }

    #[test]
    fn remap_keeps_unreached_peer_store_canonical_across_incremental_updates() {
        let mut m = Memory::default();
        let a = 1 << 32;
        let b = 1 << 34;
        let c = 1 << 36;
        let len = 1 << 30;
        m.map(a, len, Permissions::RW).unwrap();
        m.map(b, len, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<1>(b).unwrap(), [0]);
        drop(view);
        m.commit_parallel().unwrap();
        assert_eq!(m.read_array::<1>(b).unwrap(), [0]);
        m.write_array(a, [7]).unwrap();
        m.remap(a, len, c, len, false).unwrap();
        let mut view = m.parallel_view(&mut registry).unwrap();
        view.write_array(b, [17]).unwrap();
        drop(view);
        m.commit_parallel().unwrap();
        assert_eq!(m.read_array::<1>(b).unwrap(), [17]);
        assert_eq!(m.read_array::<1>(c).unwrap(), [7]);
    }

    #[test]
    fn sparse_precharged_zero_fork_cannot_be_modified_by_later_parent_worker() {
        let mut m = Memory::default();
        let base = 1 << 32;
        m.map(base, 1 << 30, Permissions::RW).unwrap();
        m.check(base, 1, Access::Write).unwrap();
        let child = m.clone();
        let mut view = m.parallel_view(&mut Registry::default()).unwrap();
        view.write_array(base, [17]).unwrap();
        assert_eq!(child.read_array::<1>(base).unwrap(), [0]);
    }

    #[test]
    fn sparse_remap_grows_zeroes_and_preserves_mapping_and_fork_isolation() {
        let mut m = Memory::default();
        let base = 1 << 32;
        let new = 1 << 36;
        let len = 1 << 30;
        m.map(base, len, Permissions::RW).unwrap();
        m.write_array(base + len - 8, [42; 8]).unwrap();
        let fork = m.clone();
        m.remap(base, len, new, 2 * len, false).unwrap();
        assert!(m.is_free(base, len));
        assert_eq!(m.read_array::<8>(new + len - 8).unwrap(), [42; 8]);
        assert_eq!(m.read_array::<8>(new + len).unwrap(), [0; 8]);
        m.write_array(new + len - 8, [19; 8]).unwrap();
        assert_eq!(fork.read_array::<8>(base + len - 8).unwrap(), [42; 8]);
        m.remap(new, 2 * len, new, len, false).unwrap();
        assert!(m.is_free(new + len, len));
        m.map(base, len, Permissions::R).unwrap();
        assert!(m.remap(new, len, base, len, false).is_err());
        assert_eq!(m.read_array::<8>(new + len - 8).unwrap(), [19; 8]);
    }

    #[test]
    fn sparse_discard_and_retained_views_release_quota_after_handoff() {
        let mut m = Memory::new(2 * PAGE_SIZE as usize);
        let base = 1 << 32;
        let len = 1 << 30;
        m.map(base, len, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        view.write_array(base, [42]).unwrap();
        // Mutation keeps the old View's byte owners alive, as dense pages do.
        m.discard(base, len).unwrap();
        assert_eq!(m.read_array::<1>(base).unwrap(), [0]);
        assert_eq!(view.read_array::<1>(base).unwrap(), [42]);
        drop(view);
        m.commit_parallel().unwrap();
        m.reclaim_unused();
        assert_eq!(m.resident_bytes(), 0);
        m.write_array(base + PAGE_SIZE, [7]).unwrap();
        m.write_array(base + 2 * PAGE_SIZE, [8]).unwrap();
        m.discard(base, len).unwrap();
        assert_eq!(m.resident_bytes(), 0);
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::{parallel::Registry, CpuMemory, HardwareRange, HardwareStorage};
    use std::sync::atomic::AtomicUsize;
    struct Native {
        pointer: usize,
        resident: AtomicUsize,
    }
    impl Native {
        fn new() -> Arc<Self> {
            let layout = std::alloc::Layout::from_size_align(
                HARDWARE_MAPPING_CHUNK_SIZE as usize,
                PAGE_SIZE as usize,
            )
            .unwrap();
            let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!pointer.is_null());
            Arc::new(Self {
                pointer: pointer as usize,
                resident: AtomicUsize::new(0),
            })
        }
    }
    impl Drop for Native {
        fn drop(&mut self) {
            unsafe {
                std::alloc::dealloc(
                    self.pointer as *mut _,
                    std::alloc::Layout::from_size_align(
                        HARDWARE_MAPPING_CHUNK_SIZE as usize,
                        PAGE_SIZE as usize,
                    )
                    .unwrap(),
                );
            }
        }
    }
    // SAFETY: test hardware stores are explicit raw writes; no concurrent actor.
    unsafe impl HardwareStorage for Native {
        fn pointer(&self) -> *mut u8 {
            self.pointer as *mut u8
        }
        fn physical_address(&self) -> u64 {
            0x200000
        }
        fn begin_host_access(&self) {}
        fn end_host_access(&self) {}
    }
    unsafe impl HardwareRange for Native {
        fn len(&self) -> usize {
            HARDWARE_MAPPING_CHUNK_SIZE as usize
        }
        fn resident_bytes(&self) -> usize {
            self.resident.load(Ordering::Relaxed)
        }
    }
    fn setup(limit: usize) -> (Memory, Registry) {
        let mut m = Memory::new(limit);
        m.map(0x200000, HARDWARE_MAPPING_CHUNK_SIZE, Permissions::RW)
            .unwrap();
        let mut r = Registry::default();
        r.use_hardware();
        m.prepare_hardware().unwrap();
        (m, r)
    }
    #[test]
    fn native_ranges_share_late_bytes_and_never_charge_unreached_addresses() {
        let (mut m, mut r) = setup(ADDRESS_LIMIT as usize);
        let native = Native::new();
        let mut v = m.parallel_view(&mut r).unwrap();
        v.enable_hardware();
        unsafe {
            v.export_hardware_range(0x200000, || Ok(native.clone()))
                .unwrap()
                .unwrap();
        }
        assert_eq!(m.resident_bytes(), 0);
        unsafe {
            native
                .pointer()
                .add(3 * PAGE_SIZE as usize)
                .cast::<u64>()
                .write(713);
        }
        native.resident.store(PAGE_SIZE as usize, Ordering::Relaxed);
        assert_eq!(v.read_array::<8>(0x203000).unwrap(), 713u64.to_le_bytes());
        assert_eq!(m.resident_bytes(), PAGE_SIZE as usize);
        drop(v);
        m.commit_parallel().unwrap();
        assert_eq!(m.read_array::<8>(0x203000).unwrap(), 713u64.to_le_bytes());
        let mut child = m.clone();
        child.write_array(0x203000, 919u64.to_le_bytes()).unwrap();
        assert_eq!(m.read_array::<8>(0x203000).unwrap(), 713u64.to_le_bytes());
        assert_eq!(
            child.read_array::<8>(0x203000).unwrap(),
            919u64.to_le_bytes()
        );
    }
    #[test]
    fn native_range_admission_keeps_strict_quotas_and_existing_pages_authoritative() {
        let (mut m, mut r) = setup(64 << 20);
        let mut v = m.parallel_view(&mut r).unwrap();
        v.enable_hardware();
        assert!(unsafe {
            v.export_hardware_range(0x200000, || {
                panic!("bounded quota cannot admit untracked hardware stores")
            })
        }
        .unwrap()
        .is_none());
        drop(v);
        let (mut m, mut r) = setup(ADDRESS_LIMIT as usize);
        m.write_array(0x203000, 713u64.to_le_bytes()).unwrap();
        let mut v = m.parallel_view(&mut r).unwrap();
        v.enable_hardware();
        assert!(unsafe {
            v.export_hardware_range(0x200000, || panic!("never replace reached canonical bytes"))
        }
        .unwrap()
        .is_none());
        assert_eq!(v.read_array::<8>(0x203000).unwrap(), 713u64.to_le_bytes());
    }
    #[test]
    fn native_range_retirement_waits_for_retained_views_and_reuse_is_zero() {
        let (mut m, mut r) = setup(ADDRESS_LIMIT as usize);
        let native = Native::new();
        let weak = Arc::downgrade(&native);
        let mut v = m.parallel_view(&mut r).unwrap();
        v.enable_hardware();
        unsafe {
            v.export_hardware_range(0x200000, || Ok(native.clone()))
                .unwrap()
                .unwrap();
        }
        unsafe {
            native.pointer().cast::<u64>().write(117);
        }
        native.resident.store(PAGE_SIZE as usize, Ordering::Relaxed);
        drop(native);
        m.unmap(0x200000, HARDWARE_MAPPING_CHUNK_SIZE).unwrap();
        assert!(weak.upgrade().is_some());
        assert_eq!(v.read_array::<8>(0x200000).unwrap(), 117u64.to_le_bytes());
        m.map(0x200000, HARDWARE_MAPPING_CHUNK_SIZE, Permissions::RW)
            .unwrap();
        let mut fresh = m.parallel_view(&mut r).unwrap();
        fresh.enable_hardware();
        assert_eq!(fresh.read_array::<8>(0x200000).unwrap(), [0; 8]);
        drop(fresh);
        drop(v);
        m.commit_parallel().unwrap();
        m.reclaim_unused();
        assert!(weak.upgrade().is_none());
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::{parallel::Registry, CpuMemory};
    #[test]
    fn live_anonymous_additions_reach_running_views_without_rebuilding_old_frames() {
        let mut m = Memory::new(2 * PAGE_SIZE as usize);
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut r = Registry::default();
        let mut old = m.parallel_view(&mut r).unwrap();
        old.write_array(0x1000, 7u64.to_le_bytes()).unwrap();
        m.map_anonymous_live(0x200000, HARDWARE_MAPPING_CHUNK_SIZE)
            .unwrap();
        assert_eq!(old.read_array::<8>(0x200000).unwrap(), [0; 8]);
        old.write_array(0x201000, 73u64.to_le_bytes()).unwrap();
        assert_eq!(m.resident_bytes(), 2 * PAGE_SIZE as usize);
        assert_eq!(old.read_array::<8>(0x1000).unwrap(), 7u64.to_le_bytes());
        assert_eq!(
            m.map_anonymous_live(0x201000, PAGE_SIZE),
            Err(MemoryError::Overlap(0x201000))
        );
        assert_eq!(old.write_array(0x202000, [1]), Err(MemoryError::Limit));
        drop(old);
        m.commit_parallel().unwrap();
        let fresh = m.parallel_view(&mut r).unwrap();
        assert_eq!(
            fresh.read_array::<8>(0x201000).unwrap(),
            73u64.to_le_bytes()
        );
        drop(fresh);
        assert_eq!(m.read_array::<8>(0x201000).unwrap(), 73u64.to_le_bytes());
    }
    #[test]
    fn live_range_tokens_survive_other_snapshot_refreshes_and_retirement() {
        let mut m = Memory::default();
        let mut r = Registry::default();
        let mut old = m.parallel_view(&mut r).unwrap();
        m.map_anonymous_live(0x200000, HARDWARE_MAPPING_CHUNK_SIZE)
            .unwrap();
        old.write_array(0x201000, 17u64.to_le_bytes()).unwrap();
        let mut later = m.parallel_view(&mut r).unwrap();
        later.write_array(0x201000, 37u64.to_le_bytes()).unwrap();
        assert_eq!(old.read_array::<8>(0x201000).unwrap(), 37u64.to_le_bytes());
        m.protect(0x201000, PAGE_SIZE, Permissions::R).unwrap();
        let protected = m.parallel_view(&mut r).unwrap();
        assert!(matches!(
            protected.check(0x201000, 1, Access::Write),
            Err(MemoryError::Permission { .. })
        ));
        assert_eq!(old.read_array::<8>(0x201000).unwrap(), 37u64.to_le_bytes());
        drop(protected);
        drop(later);
        drop(old);
        m.commit_parallel().unwrap();
        m.unmap(0x200000, HARDWARE_MAPPING_CHUNK_SIZE).unwrap();
        let absent = m.parallel_view(&mut r).unwrap();
        assert_eq!(
            absent.check_translation(0x201000),
            Err(MemoryError::Unmapped(0x201000))
        );
    }
    #[test]
    fn live_additions_keep_one_store_across_concurrent_software_atomics() {
        let mut m = Memory::default();
        let mut r = Registry::default();
        let original = m.parallel_view(&mut r).unwrap();
        m.map_anonymous_live(0x200000, PAGE_SIZE).unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let mut v = original.clone();
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        loop {
                            let mut bytes = [0; 8];
                            let token = v.exclusive_read(0x200000, &mut bytes).unwrap();
                            let next = u64::from_le_bytes(bytes) + 1;
                            if v.exclusive_write(0x200000, &next.to_le_bytes(), Some(token))
                                .unwrap()
                            {
                                break;
                            }
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            original.read_array::<8>(0x200000).unwrap(),
            1600u64.to_le_bytes()
        );
        drop(original);
        m.commit_parallel().unwrap();
        assert_eq!(m.read_array::<8>(0x200000).unwrap(), 1600u64.to_le_bytes());
    }
}
