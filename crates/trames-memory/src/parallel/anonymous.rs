// SPDX-License-Identifier: GPL-3.0-or-later
//! Frozen anonymous ranges with metadata allocated only for reached pages.
use super::*;
use std::sync::Mutex;

struct Range {
    end: u64,
    permissions: Permissions,
    code_revision: u64,
    store: Arc<crate::anonymous::Store>,
    pages: [Mutex<BTreeMap<u64, Arc<Frame>>>; 16],
}
pub(crate) struct Anonymous {
    ranges: BTreeMap<u64, Range>,
    code_epoch: Arc<AtomicU64>,
}
impl Anonymous {
    pub(super) fn freeze(memory: &Memory, epoch: Arc<AtomicU64>) -> Self {
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
                            pages: std::array::from_fn(|_| Mutex::new(BTreeMap::new())),
                        },
                    )
                })
                .collect(),
            code_epoch: epoch,
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
