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
}
impl Store {
    fn new(account: Arc<Account>) -> Arc<Self> {
        Arc::new(Self {
            pages: std::array::from_fn(|_| Mutex::new(BTreeMap::new())),
            account,
        })
    }
    pub fn get(&self, base: u64) -> Arc<Resident> {
        self.pages[((base / PAGE_SIZE) & 15) as usize]
            .lock()
            .unwrap()
            .entry(base)
            .or_insert_with(|| {
                Arc::new(Resident {
                    bytes: Arc::new(SharedPage::from_owned(PageBytes::Zero, None)),
                    charge: Charge::new(&self.account),
                })
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
    fn is_empty(&self) -> bool {
        self.pages.iter().all(|p| p.lock().unwrap().is_empty())
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
        out
    }
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
    pub fn rebase(&mut self, account: &Arc<Account>) -> bool {
        let mut replacements = BTreeMap::new();
        let mut changed = false;
        for range in self.ranges.values_mut() {
            let source = Arc::as_ptr(&range.store) as usize;
            let replacement = replacements
                .entry(source)
                .or_insert_with(|| (!range.store.is_empty()).then(|| Store::new(account.clone())));
            if let Some(replacement) = replacement {
                range.store = replacement.clone();
                changed = true;
            }
        }
        changed
    }
    pub fn fork(&self, account: &std::sync::Arc<residency::Account>) -> Self {
        Self {
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
            let mut page = if !self.has_parallel_users() && range.store.lookup(base).is_none() {
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
        self.invalidate_translations();
        self.sparse_pages
            .get_mut()
            .retain(|&base, _| base < start || base >= end);
    }
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
