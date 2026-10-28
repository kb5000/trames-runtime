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
    ranges: BTreeMap<u64, Range>,
    code_epoch: Arc<AtomicU64>,
    hardware: bool,
    chunks: Mutex<BTreeMap<u64, u64>>,
}
impl Anonymous {
    pub(super) fn freeze(
        memory: &Memory,
        epoch: Arc<AtomicU64>,
        hardware: bool,
        previous: Option<&Self>,
    ) -> Self {
        Self {
            ranges: memory
                .anonymous
                .ranges
                .iter()
                .map(|(&base, r)| {
                    (
                        base,
                        Range {
                            end: r.end,
                            permissions: r.page.permissions,
                            code_revision: r.page.instruction_revision,
                            store: r.store.clone(),
                            pages: previous
                                .and_then(|old| old.range(base))
                                .filter(|old| {
                                    old.end >= r.end
                                        && old.permissions == r.page.permissions
                                        && old.code_revision == r.page.instruction_revision
                                        && Arc::ptr_eq(&old.store, &r.store)
                                })
                                .map(|old| old.pages.clone())
                                .unwrap_or_else(|| {
                                    Arc::new(std::array::from_fn(|_| Mutex::new(BTreeMap::new())))
                                }),
                        },
                    )
                })
                .collect(),
            code_epoch: epoch,
            hardware,
            chunks: Mutex::new(
                previous.map_or_else(BTreeMap::new, |old| old.chunks.lock().unwrap().clone()),
            ),
        }
    }
    pub(super) fn chunk_version(&self, chunk: u64) -> Option<u64> {
        self.chunks.lock().unwrap().get(&chunk).copied()
    }
    pub(super) fn note_changes(&self, ranges: &[std::ops::Range<u64>], generation: u64) {
        let mut chunks = self.chunks.lock().unwrap();
        for range in ranges {
            let first = range.start / crate::HARDWARE_MAPPING_CHUNK_SIZE;
            let last = (range.end - 1) / crate::HARDWARE_MAPPING_CHUNK_SIZE;
            for (_, stamp) in chunks.range_mut(first..=last) {
                *stamp = generation;
            }
        }
        chunks.retain(|&key, _| {
            self.overlaps(
                key * crate::HARDWARE_MAPPING_CHUNK_SIZE,
                (key + 1) * crate::HARDWARE_MAPPING_CHUNK_SIZE,
            )
        });
    }
    // The caller excludes every View generation of this VM before removing
    // Frame allocations: worker TLB tokens can contain their raw addresses.
    pub(super) fn prune(&self) {
        let mut seen = BTreeSet::new();
        for range in self.ranges.values() {
            if seen.insert(Arc::as_ptr(&range.pages) as usize) {
                for shard in range.pages.iter() {
                    shard.lock().unwrap().retain(|&base, frame| {
                        self.range(base).is_some_and(|r| {
                            Arc::ptr_eq(&r.pages, &range.pages)
                                && frame.permissions == r.permissions
                                && frame.code_revision == r.code_revision
                        })
                    });
                }
            }
        }
    }
    fn range(&self, address: u64) -> Option<&Range> {
        self.ranges
            .range(..=address)
            .next_back()
            .filter(|(_, r)| address < r.end)
            .map(|(_, r)| r)
    }
    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.range(start).is_some() || self.ranges.range(start..end).next().is_some()
    }
    pub(super) fn executable(&self) -> bool {
        self.ranges.values().any(|r| r.permissions.execute)
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
        if !self.has_parallel_users() && self.anonymous.rebase(&self.account) {
            self.invalidate_translations();
            self.sparse_pages.get_mut().clear();
            self.parallel_anonymous_dirty = true;
        }
    }
}
