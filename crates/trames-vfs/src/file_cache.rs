// SPDX-License-Identifier: GPL-3.0-or-later
//! Private-disk read cache. Mmap and ordinary IO retain the same bytes and
//! physical owner. Reclaim drops only clean pages with no external byte pin.
#[cfg(test)]
use crate::Errno;
use crate::Result;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Mutex, RwLock,
    },
};
use trames_memory::{
    CgroupMemoryKind, CgroupReclaim, MappedResidents, MemoryCgroup, SharedPage, PAGE_SIZE,
};

const MAX_PAGES: usize = 256;

#[derive(Clone)]
pub(super) struct Contents {
    pub bytes: Arc<SharedPage>,
    pub valid: usize,
}
pub(super) struct Page {
    pub owners: Arc<MappedResidents>,
    pub dirty: Arc<AtomicBool>,
    contents: Mutex<Option<Contents>>,
}
impl Page {
    pub fn new(kind: CgroupMemoryKind) -> Arc<Self> {
        Arc::new(Self {
            owners: Arc::new(MappedResidents::with_kind(kind)),
            dirty: Arc::default(),
            contents: Mutex::new(None),
        })
    }
    pub fn contents(&self) -> Option<Contents> {
        self.contents.lock().unwrap().clone()
    }
    pub fn adopt(&self, charge: &trames_memory::CgroupPageCharge) {
        if self.contents.lock().unwrap().is_none() {
            self.owners.adopt_cache(charge);
        }
    }
    pub fn load(
        &self,
        resource: Option<Arc<dyn CgroupReclaim>>,
        read: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<Contents> {
        let mut contents = self.contents.lock().unwrap();
        if let Some(contents) = &*contents {
            return Ok(contents.clone());
        }
        self.owners
            .reserve_cache()
            .map_err(crate::resource_io::memory_error)?;
        if let Some(resource) = resource {
            self.owners.register_reclaimer(&resource);
        }
        let input = match read() {
            Ok(input) => input,
            Err(error) => {
                self.owners.cancel_cache();
                return Err(error);
            }
        };
        let mut bytes = Box::new([0; PAGE_SIZE as usize]);
        bytes[..input.len()].copy_from_slice(&input);
        let loaded = Contents {
            bytes: Arc::new(SharedPage::from_box(bytes)),
            valid: input.len(),
        };
        self.owners
            .publish_cache(&loaded.bytes)
            .map_err(crate::resource_io::memory_error)?;
        *contents = Some(loaded.clone());
        Ok(loaded)
    }
    pub fn zero_tail(&self, from: usize) {
        if let Some(contents) = &mut *self.contents.lock().unwrap() {
            contents
                .bytes
                .with_write(from, PAGE_SIZE as usize - from, |bytes| bytes.fill(0));
            contents.valid = contents.valid.min(from);
        }
    }
    pub fn invalidate(&self) {
        let mut contents = self.contents.lock().unwrap();
        let retired = contents.take();
        self.owners.invalidate_cache();
        self.dirty.store(false, Relaxed);
        drop(retired); // remaining CPU/provider byte pins retain their old lease
    }
    pub fn retained(&self) -> bool {
        Arc::strong_count(&self.owners) != 1
    }
}
#[derive(Default)]
pub(super) struct Cache {
    pages: RwLock<BTreeMap<u64, Arc<Page>>>,
}
impl Cache {
    /// Called under this inode's original layout exclusion after writeback.
    /// Old executor/native byte pins keep their physical leases independently.
    pub fn discard_mapped(
        &self,
        offset: u64,
        owners: &Arc<MappedResidents>,
        bytes: &Arc<SharedPage>,
    ) -> bool {
        let Ok(pages) = self.pages.try_read() else {
            return false;
        };
        let Some(page) = pages.get(&offset) else {
            return false;
        };
        if !Arc::ptr_eq(&page.owners, owners) || page.dirty.load(Relaxed) {
            return false;
        }
        let Ok(mut contents) = page.contents.try_lock() else {
            return false;
        };
        if contents
            .as_ref()
            .is_none_or(|old| !Arc::ptr_eq(&old.bytes, bytes))
        {
            return false;
        }
        if !page.owners.mark_reclaimed() {
            return false;
        }
        let retired = contents.take();
        page.owners.invalidate_cache();
        drop(retired);
        true
    }
    /// A multi-page fast read may copy resident data, but must not issue a
    /// series of new backend requests which can start waiting halfway through.
    /// None is a before-IO fallback; copied cache hits have no IO side effects.
    pub(super) fn read_resident(&self, offset: u64, count: usize) -> Option<Result<Vec<u8>>> {
        let mut out = Vec::new();
        if out.try_reserve_exact(count).is_err() {
            return Some(Err(crate::Errno(12)));
        }
        while out.len() < count {
            let at = offset + out.len() as u64;
            let base = at & !(PAGE_SIZE - 1);
            let page = self.pages.read().unwrap().get(&base).cloned()?;
            let contents = page.contents()?;
            let within = (at - base) as usize;
            let chunk = (count - out.len()).min(contents.valid.saturating_sub(within));
            if chunk == 0 {
                break;
            }
            let start = out.len();
            out.resize(start + chunk, 0);
            contents.bytes.copy_read(within, &mut out[start..]);
        }
        Some(Ok(out))
    }
    pub fn page(&self, offset: u64) -> Arc<Page> {
        debug_assert!(offset.is_multiple_of(PAGE_SIZE));
        if let Some(page) = self.pages.read().unwrap().get(&offset) {
            return page.clone();
        }
        let mut pages = self.pages.write().unwrap();
        if pages.len() >= MAX_PAGES {
            // A bounded per-file working set also applies to root-owned bytes.
            // Mappings/pins may temporarily retain more; never evict them.
            Self::evict(&mut pages, None, PAGE_SIZE as usize);
        }
        pages
            .entry(offset)
            .or_insert_with(|| Page::new(CgroupMemoryKind::File))
            .clone()
    }
    pub fn load(
        self: &Arc<Self>,
        offset: u64,
        read: impl FnOnce() -> Result<Vec<u8>>,
    ) -> Result<Contents> {
        let page = self.page(offset);
        let resource: Arc<dyn CgroupReclaim> = self.clone();
        page.load(Some(resource), read)
    }
    /// Called under the original PlainFile byte-write transaction. IO is
    /// write-through, so all retained cache pages remain reconstructible.
    pub fn written(&self, offset: u64, input: &[u8]) {
        let end = offset + input.len() as u64;
        let pages = self.pages.read().unwrap();
        for (&base, page) in pages.range((offset & !(PAGE_SIZE - 1))..end) {
            let mut contents = page.contents.lock().unwrap();
            if let Some(contents) = &mut *contents {
                let from = offset.max(base);
                let to = end.min(base + PAGE_SIZE);
                contents.bytes.copy_write(
                    (from - base) as usize,
                    &input[(from - offset) as usize..(to - offset) as usize],
                );
                contents.valid = contents.valid.max((to - base) as usize);
            }
        }
    }
    pub fn truncated(&self, length: u64) {
        let mut pages = self.pages.write().unwrap();
        // A mapped page keeps its original identity for truncate invalidation;
        // its byte pin is zeroed below rather than replaced by a second page.
        for (&base, page) in pages.range((length & !(PAGE_SIZE - 1))..) {
            if base >= length {
                page.invalidate();
                continue;
            }
            if let Some(contents) = &mut *page.contents.lock().unwrap() {
                let valid = length.saturating_sub(base).min(PAGE_SIZE) as usize;
                contents
                    .bytes
                    .with_write(valid, PAGE_SIZE as usize - valid, |bytes| bytes.fill(0));
                contents.valid = valid;
            }
        }
        pages
            .retain(|&base, page| base < length || page.retained() || Arc::strong_count(page) != 1);
    }
    pub fn extended(&self, before: u64, length: u64) {
        for (&base, page) in self
            .pages
            .read()
            .unwrap()
            .range((before & !(PAGE_SIZE - 1))..length)
        {
            if let Some(contents) = &mut *page.contents.lock().unwrap() {
                contents.valid = length.saturating_sub(base).min(PAGE_SIZE) as usize;
            }
        }
    }
    fn evictable(page: &Arc<Page>) -> bool {
        Arc::strong_count(page) == 1
            && Arc::strong_count(&page.owners) == 1
            && !page.dirty.load(Relaxed)
            && page.contents.try_lock().is_ok_and(|contents| {
                contents
                    .as_ref()
                    .is_none_or(|contents| Arc::strong_count(&contents.bytes) == 1)
            })
    }
    fn evict(
        pages: &mut BTreeMap<u64, Arc<Page>>,
        group: Option<&MemoryCgroup>,
        wanted: usize,
    ) -> usize {
        let mut freed = 0usize;
        pages.retain(|_, page| {
            if freed >= wanted
                || !Self::evictable(page)
                || group.is_some_and(|group| !page.owners.charged_within(group))
            {
                return true;
            }
            // Removing the last page and byte references releases both the
            // allocation and its original hierarchical physical lease.
            if page
                .contents
                .try_lock()
                .is_ok_and(|contents| contents.is_some())
            {
                if group.is_some() && !page.owners.mark_reclaimed() {
                    return true;
                }
                freed = freed.saturating_add(PAGE_SIZE as usize);
            }
            false
        });
        freed
    }
}
impl CgroupReclaim for Cache {
    fn reclaim(&self, group: &MemoryCgroup, bytes: usize) -> usize {
        let Ok(mut pages) = self.pages.try_write() else {
            return 0;
        };
        Self::evict(&mut pages, Some(group), bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{CgroupMemoryKind, CgroupMemoryTarget, CgroupPageCharge};

    fn enter(
        group: &Arc<MemoryCgroup>,
    ) -> (Arc<CgroupMemoryTarget>, trames_memory::CgroupMemoryScope) {
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let scope = target.scope();
        (target, scope)
    }
    #[test]
    fn ancestor_pressure_releases_original_cache_bytes_before_oom() {
        let parent = MemoryCgroup::new(None);
        let child = MemoryCgroup::new(Some(parent.clone()));
        parent.set_limit(PAGE_SIZE as usize);
        let (target, _scope) = enter(&child);
        let cache = Arc::new(Cache::default());
        let contents = cache.load(0, || Ok(vec![31; PAGE_SIZE as usize])).unwrap();
        let physical = Arc::downgrade(&contents.bytes);
        drop(contents);
        let anonymous = CgroupPageCharge::new(CgroupMemoryKind::Anonymous).unwrap();
        assert!(
            physical.upgrade().is_none(),
            "reclaim drops the physical allocation"
        );
        assert_eq!(child.current(), PAGE_SIZE as usize);
        assert_eq!(parent.current(), PAGE_SIZE as usize);
        assert!(target.take_oom().is_none());
        assert!(parent.format_stat().contains("pgsteal 1\n"));
        drop(anonymous);
        assert_eq!(parent.current(), 0);
    }
    #[test]
    fn reclaim_respects_original_group_dirty_state_and_byte_pins() {
        let first = MemoryCgroup::new(None);
        let other = MemoryCgroup::new(None);
        let (target, _scope) = enter(&first);
        let cache = Arc::new(Cache::default());
        let contents = cache.load(0, || Ok(vec![7; PAGE_SIZE as usize])).unwrap();
        target.set(Some(other.clone()));
        let again = cache
            .load(0, || panic!("cache hit must not read or recharge"))
            .unwrap();
        assert!(Arc::ptr_eq(&contents.bytes, &again.bytes));
        assert_eq!(other.current(), 0);
        assert_eq!(first.reclaim(PAGE_SIZE as usize), 0);
        drop(contents);
        drop(again);
        let page = cache.page(0);
        page.dirty.store(true, Relaxed);
        drop(page);
        assert_eq!(first.reclaim(PAGE_SIZE as usize), 0);
        cache.page(0).dirty.store(false, Relaxed);
        assert_eq!(other.reclaim(PAGE_SIZE as usize), 0);
        assert_eq!(first.reclaim(PAGE_SIZE as usize), PAGE_SIZE as usize);
        assert_eq!(first.current(), 0);
    }
    #[test]
    fn failed_read_releases_admission_and_growth_keeps_zero_holes() {
        let group = MemoryCgroup::new(None);
        let (_, _scope) = enter(&group);
        let cache = Arc::new(Cache::default());
        assert!(cache.load(0, || Err(Errno(5))).is_err());
        assert_eq!(group.current(), 0);
        let contents = cache.load(0, || Ok(vec![9; 2])).unwrap();
        cache.extended(2, 8);
        cache.written(7, &[3]);
        let mut bytes = [0; 8];
        contents.bytes.copy_read(0, &mut bytes);
        assert_eq!(bytes, [9, 9, 0, 0, 0, 0, 0, 3]);
        cache.truncated(1);
        contents.bytes.copy_read(0, &mut bytes);
        assert_eq!(bytes, [9, 0, 0, 0, 0, 0, 0, 0]);
    }
}
