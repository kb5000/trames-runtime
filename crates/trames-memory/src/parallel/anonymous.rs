// SPDX-License-Identifier: GPL-3.0-or-later
//! Frozen anonymous ranges with metadata allocated only for reached pages.
use super::*;
use std::sync::Mutex;

type FrameCache = [Mutex<BTreeMap<u64, Arc<Frame>>>; 16];

struct Range {
    end: u64,
    permissions: Permissions,
    code_revision: u64,
    store: Arc<crate::anonymous::Store>,
    pages: Arc<FrameCache>,
}
pub(crate) struct Anonymous {
    live: Arc<Additions>,
    ranges: BTreeMap<u64, Range>,
    code_epoch: Arc<AtomicU64>,
    hardware: bool,
    pub(super) native_allowed: bool,
    chunks: Mutex<BTreeMap<u64, u64>>,
    executable_ranges: usize,
}
/// Insert-only range publication. Heap Range/Frame addresses stay owned
/// until every Snapshot using this generation retires. There is no removal,
/// permission edit or frame-cache pruning through this shared index.
#[derive(Default)]
pub(crate) struct Additions {
    ranges: Mutex<BTreeMap<u64, Arc<Range>>>,
}
impl Additions {
    pub(crate) fn publish(&self, base: u64, source: &crate::anonymous::Range) {
        let range = Arc::new(Anonymous::freeze_range(source, None));
        let mut ranges = self.ranges.lock().unwrap();
        assert!(
            ranges.insert(base, range).is_none(),
            "additions never replace a live range"
        );
    }
    fn range(&self, address: u64) -> Option<&Range> {
        let ranges = self.ranges.lock().unwrap();
        let (_, range) = ranges
            .range(..=address)
            .next_back()
            .filter(|(_, r)| address < r.end)?;
        let pointer = Arc::as_ptr(range);
        // SAFETY: this insert-only owner outlives the borrow. Inserts never
        // move/remove heap allocations; no mutable Range/Frame reference exists.
        Some(unsafe { &*pointer })
    }
    fn overlaps(&self, start: u64, end: u64) -> bool {
        let ranges = self.ranges.lock().unwrap();
        ranges
            .range(..=start)
            .next_back()
            .is_some_and(|(_, r)| start < r.end)
            || ranges.range(start..end).next().is_some()
    }
}
impl Anonymous {
    fn freeze_range(source: &crate::anonymous::Range, previous: Option<&Range>) -> Range {
        #[cfg(test)]
        crate::anonymous::note_index_visit();
        Range {
            end: source.end,
            permissions: source.page.permissions,
            code_revision: source.page.instruction_revision,
            store: source.store.clone(),
            pages: previous
                .filter(|old| {
                    old.end >= source.end
                        && old.permissions == source.page.permissions
                        && old.code_revision == source.page.instruction_revision
                        && Arc::ptr_eq(&old.store, &source.store)
                })
                .map(|old| old.pages.clone())
                .unwrap_or_else(|| Arc::new(std::array::from_fn(|_| Mutex::new(BTreeMap::new())))),
        }
    }
    pub(super) fn freeze(memory: &Memory, epoch: Arc<AtomicU64>, hardware: bool) -> Self {
        let ranges: BTreeMap<_, _> = memory
            .anonymous
            .ranges
            .iter()
            .map(|(&base, r)| (base, Self::freeze_range(r, None)))
            .collect();
        let executable_ranges = ranges.values().filter(|r| r.permissions.execute).count();
        Self {
            live: memory.anonymous.live.clone(),
            ranges,
            executable_ranges,
            code_epoch: epoch,
            hardware,
            native_allowed: memory.account.native_allowed(),
            chunks: Mutex::new(BTreeMap::new()),
        }
    }
    fn overlapping(&self, start: u64, end: u64) -> Vec<(u64, &Range)> {
        let mut out = Vec::new();
        if let Some((&base, r)) = self.ranges.range(..start).next_back() {
            if r.end > start {
                out.push((base, r));
            }
        }
        out.extend(self.ranges.range(start..end).map(|(&base, r)| (base, r)));
        out
    }
    // No current Snapshot View is live. Other generations retain their own
    // immutable index; byte/frame owners can be shared through unchanged ranges.
    pub(super) fn refresh(
        &mut self,
        current: &crate::anonymous::Anonymous,
        changes: &[std::ops::Range<u64>],
    ) {
        self.prune_against(current, changes);
        self.live = current.live.clone();
        let mut windows: Vec<std::ops::Range<u64>> = Vec::new();
        for change in changes {
            if windows
                .last()
                .is_some_and(|last| last.start <= change.start && last.end >= change.end)
            {
                continue;
            }
            let mut start = change.start;
            let mut end = change.end;
            loop {
                let mut a = start;
                let mut b = end;
                for (base, r) in self.overlapping(start, end) {
                    a = a.min(base);
                    b = b.max(r.end);
                }
                for (base, r) in current.overlapping(start, end) {
                    a = a.min(base);
                    b = b.max(r.end);
                }
                if a == start && b == end {
                    break;
                }
                start = a;
                end = b;
            }
            if let Some(last) = windows.last_mut() {
                if start <= last.end {
                    last.end = last.end.max(end);
                    continue;
                }
            }
            windows.push(start..end);
        }
        for window in windows {
            let replacements: Vec<_> = current
                .overlapping(window.start, window.end)
                .into_iter()
                .map(|(base, r)| (base, Self::freeze_range(r, self.base_range(base))))
                .collect();
            let keys: Vec<_> = self
                .ranges
                .range(window.clone())
                .map(|(&base, _)| base)
                .collect();
            for base in keys {
                self.executable_ranges -=
                    usize::from(self.ranges.remove(&base).unwrap().permissions.execute);
            }
            for (base, r) in replacements {
                self.executable_ranges += usize::from(r.permissions.execute);
                self.ranges.insert(base, r);
            }
        }
    }
    pub(super) fn export_range(
        &self,
        base: u64,
        len: usize,
        access: Access,
        allocate: impl FnOnce() -> Result<Arc<dyn crate::HardwareRange>, MemoryError>,
    ) -> Result<Option<Arc<dyn crate::HardwareRange>>, MemoryError> {
        let Some(r) = self.range(base) else {
            return Ok(None);
        };
        if base.checked_add(len as u64).is_none_or(|end| end > r.end)
            || r.permissions != Permissions::RW
            || access == Access::Execute
        {
            return Ok(None);
        }
        let result = r.store.export_range(base, len, allocate)?;
        if result.is_some() {
            self.chunks
                .lock()
                .unwrap()
                .entry(base / crate::HARDWARE_MAPPING_CHUNK_SIZE)
                .or_insert_with(new_backing_identity);
        }
        Ok(result)
    }
    pub(super) fn chunk_version(&self, chunk: u64) -> Option<u64> {
        self.chunks.lock().unwrap().get(&chunk).copied()
    }
    pub(super) fn note_changes(&self, ranges: &[std::ops::Range<u64>], generation: u64) {
        let mut chunks = self.chunks.lock().unwrap();
        for range in ranges {
            let first = range.start / crate::HARDWARE_MAPPING_CHUNK_SIZE;
            let last = (range.end - 1) / crate::HARDWARE_MAPPING_CHUNK_SIZE;
            let keys: Vec<_> = chunks.range(first..=last).map(|(&key, _)| key).collect();
            for key in keys {
                if self.overlaps(
                    key * crate::HARDWARE_MAPPING_CHUNK_SIZE,
                    (key + 1) * crate::HARDWARE_MAPPING_CHUNK_SIZE,
                ) {
                    *chunks.get_mut(&key).unwrap() = generation;
                } else {
                    chunks.remove(&key);
                }
            }
        }
    }
    // The current Snapshot is unique before removing Frames. Cold/full rebuilds
    // create fresh frame caches, so other View generations never hold these
    // Frame addresses (only the separate canonical byte stores are shared).
    fn prune_against(
        &self,
        current: &crate::anonymous::Anonymous,
        changes: &[std::ops::Range<u64>],
    ) {
        for change in changes {
            let mut seen = BTreeSet::new();
            for (_, range) in self.overlapping(change.start, change.end) {
                if !seen.insert(Arc::as_ptr(&range.pages) as usize) {
                    continue;
                }
                #[cfg(test)]
                crate::anonymous::note_prune_scope();
                for shard in range.pages.iter() {
                    let mut pages = shard.lock().unwrap();
                    let retired: Vec<_> = pages
                        .range(change.clone())
                        .filter_map(|(&base, frame)| {
                            #[cfg(test)]
                            crate::anonymous::note_prune_visit();
                            (!current.containing(base).is_some_and(|(_, r)| {
                                Arc::ptr_eq(&r.store, &range.store)
                                    && frame.permissions == r.page.permissions
                                    && frame.code_revision == r.page.instruction_revision
                            }))
                            .then_some(base)
                        })
                        .collect();
                    for base in retired {
                        pages.remove(&base);
                    }
                }
            }
        }
    }
    fn base_range(&self, address: u64) -> Option<&Range> {
        self.ranges
            .range(..=address)
            .next_back()
            .filter(|(_, r)| address < r.end)
            .map(|(_, r)| r)
    }
    fn range(&self, address: u64) -> Option<&Range> {
        self.base_range(address)
            .or_else(|| self.live.range(address))
    }
    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.base_range(start).is_some()
            || self.ranges.range(start..end).next().is_some()
            || self.live.overlaps(start, end)
    }
    pub(super) fn executable(&self) -> bool {
        self.executable_ranges != 0
    }
    pub(super) fn retained(&self, address: u64) -> Option<&Frame> {
        if let Some(frame) = self.cached(address) {
            return Some(frame);
        }
        let resident = self.range(address)?.store.lookup(address)?;
        if !resident.charge.resident() || resident.bytes.retained_hardware().is_none() {
            return None;
        }
        self.metadata(address).ok().flatten()
    }
    pub(super) fn cached(&self, address: u64) -> Option<&Frame> {
        let r = self.range(address)?;
        let shard = ((address / PAGE_SIZE) & 15) as usize;
        let pointer = Arc::as_ptr(r.pages[shard].lock().unwrap().get(&address)?);
        // SAFETY: the frozen range owns every Arc until Snapshot teardown or a
        // unique joined replacement. Inserts never move/remove its Frame heap
        // objects. No mutable reference to a published Frame is constructed.
        Some(unsafe { &*pointer })
    }
    pub(super) fn get(&self, address: u64, access: Access) -> Result<Option<&Frame>, MemoryError> {
        self.get_inner(address, Some(access))
    }
    pub(crate) fn metadata(&self, address: u64) -> Result<Option<&Frame>, MemoryError> {
        self.get_inner(address, None)
    }
    fn get_inner(
        &self,
        address: u64,
        access: Option<Access>,
    ) -> Result<Option<&Frame>, MemoryError> {
        let base = address & !(PAGE_SIZE - 1);
        let Some(r) = self.range(base) else {
            return Ok(None);
        };
        if let Some(access) = access {
            if !r.permissions.allows(access) {
                return Err(MemoryError::Permission { address, access });
            }
        }
        let shard = ((base / PAGE_SIZE) & 15) as usize;
        let mut pages = r.pages[shard].lock().unwrap();
        let frame = pages.entry(base).or_insert_with(|| {
            if self.hardware {
                self.chunks
                    .lock()
                    .unwrap()
                    .entry(base / crate::HARDWARE_MAPPING_CHUNK_SIZE)
                    .or_insert_with(new_backing_identity);
            }
            let resident = r.store.get(base);
            let storage = resident.bytes.clone();
            let bytes = Arc::new(ConcurrentPage::shared(storage, self.code_epoch.clone()));
            bytes
                .executable
                .store(r.permissions.execute, Ordering::Relaxed);
            Arc::new(Frame {
                base,
                root_frame: usize::MAX,
                permissions: r.permissions,
                code_revision: r.code_revision,
                data_revision: AtomicU64::new(0),
                backing_version: AtomicU64::new(0),
                backing_domain: None,
                native_retryable: std::sync::atomic::AtomicBool::new(r.permissions.write),
                native_one_shot: std::sync::atomic::AtomicBool::new(true),
                native_live_private: std::sync::atomic::AtomicBool::new(false),
                error: None,
                bytes,
                charge: resident.charge.clone(),
                direct: true,
                hardware_shared_export: true,
                hardware_track_writes: false,
                backed: false,
                dynamic_code: r.permissions.execute && r.permissions.write,
                private_access: 0,
            })
        });
        let pointer = Arc::as_ptr(frame);
        drop(pages);
        // SAFETY: same retained immutable-frame ownership proof as cached().
        Ok(Some(unsafe { &*pointer }))
    }
}
impl Snapshot {
    #[inline]
    pub(super) fn frame_token(&self, token: usize) -> &Frame {
        if token & crate::anonymous::TOKEN != 0 {
            // SAFETY: anonymous Frame pointers are owned by this Snapshot's
            // insertion-only cache; a live View prevents unique replacement.
            unsafe { &*((token & !crate::anonymous::TOKEN) as *const Frame) }
        } else {
            &self.frames[token]
        }
    }
}
impl Memory {
    pub(crate) fn adopt_anonymous(&mut self) {
        let pages = self.anonymous.populated();
        for base in pages {
            self.materialize_descriptors(base, PAGE_SIZE as usize);
        }
    }
}
