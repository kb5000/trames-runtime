// SPDX-License-Identifier: GPL-3.0-or-later
//! CPU/native views between quiescent kernel checkpoints. Scoped page guards
//! stay on workers; Rc backings, mappings and persistence stay coordinated.
//! Mutable byte cells have an audited region-guard Sync boundary in page.rs.
pub(super) mod anonymous;
#[cfg(test)]
mod exclusive;
mod hardware;
mod native;
pub(super) mod page;
#[cfg(test)]
mod readonly;
#[cfg(test)]
mod sharing;
mod snapshot;
use super::*;
use std::sync::{Arc, Weak};

#[derive(Default)]
pub struct Registry {
    hardware: bool,
    mmu: mmu::Pool,
    shared: BTreeMap<(u64, u64), Weak<ConcurrentPage>>,
    code_epoch: Arc<AtomicU64>,
    pub metrics: Metrics,
}
#[derive(Default, Debug, Clone, Copy)]
pub struct Metrics {
    pub cache_hits: u64,
    pub dirty_refreshes: u64,
    pub full_rebuilds: u64,
    pub full_rebuild_pages: u64,
    pub backing_invalidations: u64,
    /// Joined checks of backing change domains and individual backing pages.
    pub backing_domain_checks: u64,
    pub backing_page_checks: u64,
    pub code_invalidations: u64,
    pub source_page_reads: u64,
    pub incremental_updates: u64,
    /// Content-only direct frames refreshed without rebuilding mapping metadata.
    pub direct_frame_refreshes: u64,
    pub incremental_pages: u64,
    /// Frames sharing the coordinator allocation, without byte transport.
    pub shared_frames: u64,
    pub copied_publish_bytes: u64,
    pub cow_detach_bytes: u64,
    /// Quiescent dispatches with one execution owner for private VM bytes.
    pub exclusive_private_views: u64,
    /// Dispatches sharing immutable private pages across CPUs of one VM.
    pub readonly_private_views: u64,
}
pub(super) struct ConcurrentPage {
    identity: u64,
    hardware_constant: std::sync::OnceLock<Arc<SharedPage>>,
    constant: Option<Arc<PageBytes>>,
    bytes: Option<Arc<page::MutablePage>>,
    loaded: std::sync::OnceLock<Arc<page::MutablePage>>,
    source: Option<Arc<dyn PageSource>>,
    private_source: bool,
    dirty: AtomicU64,
    version: AtomicU64,
    executable: std::sync::atomic::AtomicBool,
    code_epoch: Arc<AtomicU64>,
}
impl ConcurrentPage {
    fn shared(bytes: Arc<SharedPage>, code_epoch: Arc<AtomicU64>) -> Self {
        Self {
            identity: bytes.identity,
            hardware_constant: Default::default(),
            bytes: Some(bytes),
            loaded: Default::default(),
            source: None,
            private_source: false,
            constant: None,
            dirty: AtomicU64::new(0),
            version: AtomicU64::new(0),
            executable: std::sync::atomic::AtomicBool::new(false),
            code_epoch,
        }
    }
    fn deferred(
        identity: u64,
        source: Arc<dyn PageSource>,
        private_source: bool,
        code_epoch: Arc<AtomicU64>,
    ) -> Self {
        Self {
            identity,
            hardware_constant: Default::default(),
            constant: None,
            bytes: None,
            loaded: Default::default(),
            source: Some(source),
            private_source,
            dirty: AtomicU64::new(0),
            version: AtomicU64::new(0),
            executable: std::sync::atomic::AtomicBool::new(false),
            code_epoch,
        }
    }
    pub(super) fn mutable(&self) -> Option<&Arc<page::MutablePage>> {
        self.bytes.as_ref().or_else(|| self.loaded.get())
    }
    fn load(&self) -> Result<(), MemoryError> {
        if self.source.is_none() {
            return Ok(());
        }
        if self.loaded.get().is_none() {
            if let Some(source) = &self.source {
                let page = source.load()?;
                let page = if self.private_source {
                    Arc::new(if page.unmaterialized_zero() {
                        SharedPage::zero()
                    } else {
                        SharedPage::new(page.snapshot())
                    })
                } else {
                    page
                };
                // One retained winner; losing first-access proposals are simply
                // dropped. No coordinator or busy-wait service is introduced.
                let _ = self.loaded.set(page);
            }
        }
        Ok(())
    }
    fn version(&self) -> &AtomicU64 {
        self.mutable().map_or(&self.version, |bytes| &bytes.version)
    }
    fn new(
        bytes: [u8; PAGE_SIZE as usize],
        zero: bool,
        constant: bool,
        code_epoch: Arc<AtomicU64>,
        slot: Option<Arc<mmu::Slot>>,
    ) -> Self {
        let immutable = if constant {
            Some(Arc::new(if let Some(slot) = &slot {
                if zero {
                    slot.initialize_zero();
                } else {
                    slot.initialize(&bytes);
                }
                PageBytes::from_slot(slot.clone())
            } else if zero {
                PageBytes::Zero
            } else {
                PageBytes::new(bytes)
            }))
        } else {
            None
        };
        let mutable = if constant {
            None
        } else {
            Some(Arc::new(if zero {
                page::MutablePage::new_zero(slot)
            } else if let Some(slot) = slot {
                page::MutablePage::new_mapped(bytes, slot)
            } else {
                page::MutablePage::new(bytes)
            }))
        };
        Self {
            identity: new_backing_identity(),
            hardware_constant: Default::default(),
            constant: immutable,
            bytes: mutable,
            loaded: Default::default(),
            source: None,
            private_source: false,
            dirty: AtomicU64::new(0),
            version: AtomicU64::new(0),
            executable: std::sync::atomic::AtomicBool::new(false),
            code_epoch,
        }
    }
    fn changed(&self, state: &mut page::Guard<'_>, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        let version = if state.is_exclusive() {
            let next = self.version().load(Ordering::Relaxed).wrapping_add(1);
            // One private actor; the epoch/channel handoff publishes metadata
            // with the bytes. No per-store inter-CPU fence or RMW is required.
            self.version().store(next, Ordering::Relaxed);
            next
        } else {
            self.version()
                .fetch_add(1, Ordering::Release)
                .wrapping_add(1)
        };
        state.invalidate(offset, len, version);
        // One bit per 64-byte fragment. No unrelated clean bytes are written
        // back over an alias; full-page snapshots would lose concurrent edits.
        let first = offset / 64;
        let last = (offset + len - 1) / 64;
        let mask = (u64::MAX >> (63 - (last - first))) << first;
        // Only the joined coordinator clears dirty bits. Once this region is
        // dirty in an epoch, another RMW per store/copy adds no information.
        if self.dirty.load(Ordering::Relaxed) & mask != mask {
            if state.is_exclusive() {
                self.dirty
                    .store(self.dirty.load(Ordering::Relaxed) | mask, Ordering::Relaxed);
            } else {
                self.dirty.fetch_or(mask, Ordering::Relaxed);
            }
        }
        if self.executable.load(Ordering::Relaxed) {
            self.code_epoch.fetch_add(1, Ordering::Release);
        }
    }
    fn refresh(&self, bytes: &[u8; PAGE_SIZE as usize]) {
        if self.constant.is_some() {
            return;
        }
        let mut guard = self
            .mutable()
            .expect("mutable page")
            .lock(0, PAGE_SIZE as usize);
        {
            // A coordinator ABA write invalidates reservations even if bytes match.
            guard.write(0, PAGE_SIZE as usize).copy_from_slice(bytes);
            let version = self
                .version()
                .fetch_add(1, Ordering::Release)
                .wrapping_add(1);
            guard.invalidate(0, PAGE_SIZE as usize, version);
            if self.executable.load(Ordering::Relaxed) {
                self.code_epoch.fetch_add(1, Ordering::Release);
            }
        }
    }
}
pub(super) struct Frame {
    base: u64,
    root_frame: usize,
    permissions: Permissions,
    code_revision: u64,
    data_revision: AtomicU64,
    backing_version: AtomicU64,
    backing_domain: Option<(u64, u64)>,
    native_retryable: std::sync::atomic::AtomicBool,
    native_one_shot: std::sync::atomic::AtomicBool,
    native_live_private: std::sync::atomic::AtomicBool,
    error: Option<MemoryError>,
    pub(super) bytes: Arc<ConcurrentPage>,
    pub(super) charge: Arc<Charge>,
    direct: bool,
    hardware_shared_export: bool,
    hardware_track_writes: bool,
    backed: bool,
    dynamic_code: bool,
    // Bit 0: unique private storage. Bit 1: also immutable for this snapshot.
    private_access: u8,
}
impl Frame {
    fn refresh_content_metadata(&self, page: &Page) {
        self.native_retryable
            .store(page.native_retryable(), Ordering::Relaxed);
        self.native_one_shot
            .store(page.native_one_shot(), Ordering::Relaxed);
        self.native_live_private.store(
            page.backing
                .as_ref()
                .is_some_and(|backing| !backing.shared && !backing.private_copy && !self.direct),
            Ordering::Relaxed,
        );
        self.data_revision
            .store(page.data_revision, Ordering::Relaxed);
        self.backing_version.store(
            page.backing
                .as_ref()
                .map_or(0, |backing| backing.object.version()),
            Ordering::Relaxed,
        );
    }
}
fn shared_futex_page_key(page: &Page) -> Option<(u64, u64)> {
    page.backing
        .as_ref()
        .filter(|b| b.shared)
        .and_then(|b| b.object.parallel_key())
}
fn direct_matches(page: &Page, frame: &Frame) -> bool {
    let storage = page
        .backing
        .as_ref()
        .filter(|b| b.shared || !b.private_copy)
        .and_then(|b| b.object.shared_page());
    storage
        .as_ref()
        .or_else(|| page.bytes.shared())
        .zip(frame.bytes.mutable())
        .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
}

fn prepare_frame(
    space: u64,
    page: &mut Page,
    base: u64,
    root_frame: usize,
    previous: Option<&Frame>,
    registry: &mut Registry,
) -> Option<Frame> {
    let error = page.check_backing(base).err();
    let backing_version = page.backing.as_ref().map_or(0, |b| b.object.version());
    let source = page
        .backing
        .as_ref()
        .filter(|backing| !backing.private_copy && error.is_none())
        .and_then(|backing| backing.object.page_source());
    let resident_backing = page
        .backing
        .as_ref()
        .filter(|b| b.shared || (!b.private_copy && !page.permissions.write))
        .filter(|_| error.is_none())
        .and_then(|b| b.object.shared_page());
    let hardware_shared_export = page.backing.as_ref().is_none_or(|b| !b.shared)
        || resident_backing.is_some()
        || source.is_some();
    let key = page
        .backing
        .as_ref()
        .filter(|b| b.shared || resident_backing.is_some())
        .and_then(|b| b.object.parallel_key());
    let previous = previous.filter(|f| {
        f.root_frame == root_frame
            && f.code_revision == page.instruction_revision
            && f.permissions == page.permissions
    });
    let same = previous.filter(|f| {
        f.data_revision.load(Ordering::Relaxed) == page.data_revision
            && f.backing_version.load(Ordering::Relaxed) == backing_version
            && f.error == error
    });
    let direct_owned = page
        .backing
        .as_ref()
        .is_none_or(|b| !b.shared && b.private_copy);
    let direct = direct_owned
        || resident_backing.is_some()
        || (source.is_some()
            && page
                .backing
                .as_ref()
                .is_some_and(|b| b.shared || !page.permissions.write));
    let bytes = if let Some(source) = source {
        let private = page
            .backing
            .as_ref()
            .is_some_and(|b| !b.shared && page.permissions.write);
        let source_key = page.backing.as_ref().and_then(|b| b.object.parallel_key());
        let reused = same.map(|frame| frame.bytes.clone()).or_else(|| {
            (!private)
                .then(|| {
                    source_key
                        .and_then(|key| registry.shared.get(&key))
                        .and_then(Weak::upgrade)
                })
                .flatten()
        });
        let bytes = reused.unwrap_or_else(|| {
            Arc::new(ConcurrentPage::deferred(
                if private {
                    new_backing_identity()
                } else {
                    source_key.map_or_else(new_backing_identity, |key| key.0)
                },
                source,
                private,
                registry.code_epoch.clone(),
            ))
        });
        if !private {
            if let Some(key) = source_key {
                registry.shared.insert(key, Arc::downgrade(&bytes));
            }
        }
        bytes
    } else if let Some(shared) = resident_backing {
        registry.metrics.shared_frames += 1;
        let previous = previous.map(|f| &f.bytes);
        let reused = previous
            .filter(|bytes| bytes.mutable().is_some_and(|old| Arc::ptr_eq(old, &shared)))
            .cloned()
            .or_else(|| {
                key.and_then(|key| registry.shared.get(&key))
                    .and_then(Weak::upgrade)
                    .filter(|bytes| bytes.mutable().is_some_and(|old| Arc::ptr_eq(old, &shared)))
            });
        let bytes = reused.unwrap_or_else(|| {
            Arc::new(ConcurrentPage::shared(shared, registry.code_epoch.clone()))
        });
        if let Some(key) = key {
            registry.shared.insert(key, Arc::downgrade(&bytes));
        }
        bytes
    } else if direct_owned {
        let shared = if page.bytes.shared().is_some()
            && (Rc::strong_count(&page.bytes) == 1 || !page.permissions.write)
        {
            page.bytes.shared().unwrap().clone()
        } else {
            let old = std::mem::replace(&mut page.bytes, Rc::new(PageBytes::Zero));
            let owned = Rc::try_unwrap(old).unwrap_or_else(|old| {
                if !page.charge.resident() {
                    return PageBytes::Zero;
                }
                if !old.is_zero() {
                    registry.metrics.cow_detach_bytes += PAGE_SIZE;
                }
                (*old).clone()
            });
            let slot = (owned.is_zero() && page.charge.resident())
                .then(|| {
                    if registry.hardware {
                        None
                    } else {
                        registry.mmu.slot(space, base)
                    }
                })
                .flatten();
            let shared = Arc::new(SharedPage::from_owned(owned, slot));
            page.bytes = Rc::new(PageBytes::Concurrent(shared.clone()));
            shared
        };
        registry.metrics.shared_frames += 1;
        if let Some(previous) = previous.filter(|f| {
            f.direct
                && f.bytes
                    .mutable()
                    .is_some_and(|old| Arc::ptr_eq(old, &shared))
        }) {
            previous.bytes.clone()
        } else {
            Arc::new(ConcurrentPage::shared(shared, registry.code_epoch.clone()))
        }
    } else if let Some(frame) = same {
        frame.bytes.clone()
    } else if error.is_some() {
        Arc::new(ConcurrentPage::new(
            [0; PAGE_SIZE as usize],
            true,
            true,
            registry.code_epoch.clone(),
            None,
        ))
    } else {
        let mut data = [0; PAGE_SIZE as usize];
        // A live EOF/backing error rejects every access before byte transport.
        // Do not allocate/copy placeholder RAM for an oversized ELF mmap tail.
        let zero = error.is_some() || (page.backing.is_none() && page.bytes.is_zero());
        if error.is_none() && !zero {
            registry.metrics.source_page_reads += 1;
            registry.metrics.copied_publish_bytes += PAGE_SIZE;
            page.read_bytes(0, &mut data).ok()?;
        }
        if let Some(key) = key {
            if let Some(bytes) = registry.shared.get(&key).and_then(Weak::upgrade) {
                bytes.refresh(&data);
                bytes
            } else {
                let bytes = Arc::new(ConcurrentPage::new(
                    data,
                    false,
                    false,
                    registry.code_epoch.clone(),
                    None,
                ));
                registry.shared.insert(key, Arc::downgrade(&bytes));
                bytes
            }
        } else if let Some(frame) = previous.filter(|f| f.bytes.constant.is_none()) {
            frame.bytes.refresh(&data);
            frame.bytes.clone()
        } else {
            Arc::new(ConcurrentPage::new(
                data,
                zero,
                !page.permissions.write || error.is_some(),
                registry.code_epoch.clone(),
                if page.backing.is_none() {
                    if registry.hardware {
                        None
                    } else {
                        registry.mmu.slot(space, base)
                    }
                } else {
                    None
                },
            ))
        }
    };
    if page.permissions.execute {
        bytes.executable.store(true, Ordering::Relaxed);
    }

    let private_unique = direct_owned
        && Rc::strong_count(&page.bytes) == 1
        && bytes
            .mutable()
            .is_some_and(|bytes| Arc::strong_count(bytes) == 2);
    Some(Frame {
        base,
        root_frame,
        backed: page
            .backing
            .as_ref()
            .is_some_and(|backing| backing.object.charge_reads()),
        permissions: page.permissions,
        code_revision: page.instruction_revision,
        data_revision: AtomicU64::new(page.data_revision),
        backing_version: AtomicU64::new(backing_version),
        backing_domain: page.backing.as_ref().and_then(|b| {
            b.object
                .parallel_versioned()
                .then(|| b.object.parallel_change_domain())
                .flatten()
        }),
        native_retryable: std::sync::atomic::AtomicBool::new(page.native_retryable()),
        native_one_shot: std::sync::atomic::AtomicBool::new(page.native_one_shot()),
        native_live_private: std::sync::atomic::AtomicBool::new(
            page.backing
                .as_ref()
                .is_some_and(|b| !b.shared && !b.private_copy && !direct),
        ),
        error,
        charge: page.charge.clone(),
        private_access: if private_unique {
            PrivateMode::Exclusive as u8
                | if !page.permissions.write {
                    PrivateMode::ReadOnly as u8
                } else {
                    0
                }
        } else {
            0
        },
        bytes,
        direct,
        hardware_shared_export,
        // Hardware executes private code from these same canonical bytes.
        // Guest IC/DC maintenance handles guest stores; actual host writes
        // publish their range at the producer. Executability alone must not
        // invent a write and rebuild code metadata after every joined epoch.
        hardware_track_writes: !direct || page.backing.as_ref().is_some_and(|b| b.shared),
        dynamic_code: page.permissions.execute
            && (page.permissions.write
                || page
                    .backing
                    .as_ref()
                    .is_some_and(|b| b.shared || !b.private_copy)),
    })
}

pub(super) struct Snapshot {
    pub(super) anonymous: anonymous::Anonymous,
    hardware: bool,
    hardware_generation: u64,
    hardware_chunks: BTreeMap<u64, u64>,
    hardware_changes: std::collections::VecDeque<snapshot::HardwareChange>,
    hardware_writes: AtomicU64,
    hardware_private_dirty: std::sync::atomic::AtomicBool,
    mmu: mmu::Frozen,
    has_aliases: bool,
    dynamic_code: bool,
    dynamic_code_pages: usize,
    identities: BTreeMap<u64, usize>,
    alias_count: usize,
    backed_pages: BTreeSet<u64>,
    backings: snapshot::BackingIndex,
    positions: Slots<Option<usize>>,
    backing_revision: u64,
    identity: u64,
    code_revision: u64,
    pages: BTreeMap<u64, usize>,
    frames: Slots<Frame>,
    // One bit per virtual frame, independent of the physical dirty fragments.
    // Workers mark reached frames; only the joined coordinator clears bits.
    dirty_pages: Arc<[AtomicU64]>,
    reservations: BTreeMap<u64, u64>,
    code_epoch: Arc<AtomicU64>,
    users: Arc<std::sync::atomic::AtomicUsize>,
}
pub(super) struct SnapshotCache {
    pub(super) snapshot: Arc<Snapshot>,
    source_revision: u64,
    source_fork_epoch: u64,
    source_backing_revision: u64,
}
impl SnapshotCache {
    pub(super) fn code_epoch(&self) -> u64 {
        if self.snapshot.dynamic_code {
            self.snapshot.code_epoch.load(Ordering::Acquire)
        } else {
            0
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PrivateMode {
    Guarded = 0,
    Exclusive = 1,
    ReadOnly = 2,
}
/// Send, with worker-local translations; never Sync and never retains Rc data.
pub struct View {
    snapshot: Arc<Snapshot>,
    translations: [Cell<Translation>; TRANSLATION_SLOTS],
    mmu_cache: mmu::Cache,
    private_mode: PrivateMode,
    hardware_mode: bool,
}
/// Clone a worker-local view over the same frozen address space, with its own
/// translation cells. This is a shared-VM view, not a process fork.
impl Clone for View {
    fn clone(&self) -> Self {
        let mut view = Self::new(self.snapshot.clone());
        view.hardware_mode = self.hardware_mode;
        view
    }
}
impl Drop for View {
    fn drop(&mut self) {
        self.snapshot.users.fetch_sub(1, Ordering::Release);
    }
}
impl View {
    /// Cold scheduler metadata, with no guest byte access or provider callback.
    /// VMs sharing a mapped backing must quiesce together before consuming its
    /// dirty publication. Private anonymous VMs remain independent.
    pub fn commit_domains(&self) -> BTreeSet<(u8, u64)> {
        self.snapshot.backings.commit_domains()
    }
    fn new(snapshot: Arc<Snapshot>) -> Self {
        snapshot.users.fetch_add(1, Ordering::Relaxed);
        Self {
            snapshot,
            mmu_cache: mmu::Cache::default(),
            private_mode: PrivateMode::Guarded,
            hardware_mode: false,
            translations: std::array::from_fn(|_| Cell::new(Translation::EMPTY)),
        }
    }
    /// Admit the private-page fast path for one joined runtime epoch.
    /// Returns false if any other View of this VM survives, across generations.
    ///
    /// # Safety
    /// Until this View returns/drops, at most one thread may access its private
    /// byte storage/monitor metadata at a time. The caller must not clone the
    /// View, dispatch another CPU in this VM, fork/mutate mappings, or access
    /// coordinator private bytes concurrently. A stopped caller may transfer
    /// this very View to a service thread and back, after ending its borrows.
    /// Shared/custom backings and physically shared fork pages never qualify.
    pub unsafe fn try_exclusive_private(&mut self) -> bool {
        self.private_mode = PrivateMode::Guarded;
        if self.hardware_mode {
            return false;
        }
        if self.snapshot.users.load(Ordering::Acquire) != 1 {
            return false;
        }
        self.private_mode = PrivateMode::Exclusive;
        true
    }
    pub fn exclusive_private_enabled(&self) -> bool {
        self.private_mode == PrivateMode::Exclusive
    }
    /// Admit all dispatched Views of one frozen VM as a single epoch.
    /// One View receives private read/write ownership; multiple Views can read
    /// immutable private pages without region locks, while RW pages stay guarded.
    ///
    /// # Safety
    /// Every coordinator Memory handle of this VM must be controlled by the
    /// caller. No coordinate byte/monitor access, mapping change, fork or View
    /// cloning may occur until all these Views are dropped. Parked service
    /// actors may move their caller's same View, after ending scoped borrows.
    /// This set must contain every execution actor of the VM. Admission checks
    /// identical snapshots and the all-generations View count, not host aliases.
    pub unsafe fn try_private_epoch(views: &mut [&mut Self]) -> bool {
        for view in views.iter_mut() {
            view.private_mode = PrivateMode::Guarded;
        }
        let Some(first) = views.first() else {
            return false;
        };
        if views.iter().any(|v| v.hardware_mode)
            || first.snapshot.users.load(Ordering::Acquire) != views.len()
            || views
                .iter()
                .any(|v| !Arc::ptr_eq(&first.snapshot, &v.snapshot))
        {
            return false;
        }
        let mode = if views.len() == 1 {
            PrivateMode::Exclusive
        } else {
            PrivateMode::ReadOnly
        };
        for view in views {
            view.private_mode = mode;
        }
        true
    }
    pub fn readonly_private_enabled(&self) -> bool {
        self.private_mode == PrivateMode::ReadOnly
    }
    #[inline]
    fn page_guard<'a>(
        &self,
        bytes: &'a ConcurrentPage,
        private_access: u8,
        offset: usize,
        len: usize,
    ) -> page::Guard<'a> {
        let storage = bytes.mutable().expect("mutable page");
        let mode = self.private_mode as u8 & private_access;
        if mode != 0 {
            // SAFETY: admission proves exclusive or immutable epoch ownership;
            // frame bits exclude other VMs and writable read-only admission.
            unsafe { storage.unlocked(offset, len, mode == PrivateMode::ReadOnly as u8) }
        } else {
            storage.lock(offset, len)
        }
    }
    #[inline]
    fn page_guard_pair<'a>(
        &self,
        bytes: &'a ConcurrentPage,
        private_access: u8,
        a: usize,
        b: usize,
        len: usize,
    ) -> page::Guard<'a> {
        let storage = bytes.mutable().expect("mutable page");
        let mode = self.private_mode as u8 & private_access;
        if mode != 0 {
            // SAFETY: same epoch/physical ownership proof for both subranges.
            unsafe { storage.unlocked_pair(a, b, len, mode == PrivateMode::ReadOnly as u8) }
        } else {
            storage.lock_pair(a, b, len)
        }
    }
    #[inline]
    fn frame_guard<'a>(&self, frame: &'a Frame, offset: usize, len: usize) -> page::Guard<'a> {
        self.page_guard(&frame.bytes, frame.private_access, offset, len)
    }
    #[inline]
    fn frame(&self, address: u64, access: Access) -> Result<&Frame, MemoryError> {
        let base = address & !(PAGE_SIZE - 1);
        let cached = self.translations[Translation::slot(base)].get();
        if cached.matches(base, Translation::access_bit(access)) {
            // SAFETY: a view's snapshot owns an immutable frame slab and page
            // table. Only successfully checked frames populate this view's
            // private TLB. Snapshot refresh creates a new view with empty TLB.
            return Ok(self.snapshot.frame_token(cached.frame));
        }
        self.frame_slow(address, access)
    }
    #[cold]
    #[inline(never)]
    fn frame_slow(&self, address: u64, access: Access) -> Result<&Frame, MemoryError> {
        let base = address & !(PAGE_SIZE - 1);
        let Some(&index) = self.snapshot.pages.get(&base) else {
            if self
                .snapshot
                .reservations
                .range(..=address)
                .next_back()
                .is_some_and(|(_, end)| address < *end)
            {
                return Err(MemoryError::Permission { address, access });
            }
            if let Some(frame) = self.snapshot.anonymous.get(address, access)? {
                let pointer = frame as *const Frame as usize;
                assert_eq!(pointer & crate::anonymous::TOKEN, 0);
                let mut entry = Translation::new(
                    base,
                    pointer | crate::anonymous::TOKEN,
                    frame.permissions,
                    false,
                    0,
                );
                if frame.charge.resident() {
                    entry.tag |= Translation::RESIDENT;
                }
                self.translations[Translation::slot(base)].set(entry);
                return Ok(frame);
            }
            return Err(MemoryError::Unmapped(address));
        };
        let frame = &self.snapshot.frames[index];
        if !frame.permissions.allows(access) {
            return Err(MemoryError::Permission { address, access });
        }
        if let Some(error) = &frame.error {
            return Err(match error {
                MemoryError::Bus(_) => MemoryError::Bus(address),
                other => other.clone(),
            });
        }
        let mut entry = Translation::new(
            base,
            index,
            frame.permissions,
            false,
            if self.hardware_mode {
                0
            } else {
                self.snapshot.mmu.page_alias(&self.mmu_cache, base)
            },
        );
        if frame.charge.resident() {
            entry.tag |= Translation::RESIDENT;
        }
        self.translations[Translation::slot(base)].set(entry);
        Ok(frame)
    }
    #[inline]
    fn reached(
        &self,
        address: u64,
        len: usize,
        access: Access,
    ) -> Result<(&Frame, usize), MemoryError> {
        Memory::end(address, len as u64)?;
        let offset = (address % PAGE_SIZE) as usize;
        if len > PAGE_SIZE as usize - offset {
            return Err(MemoryError::InvalidRange);
        }
        let frame = self.frame(address, access)?;
        self.load_frame(frame)?;
        if frame.backed {
            frame.charge.ensure()?;
        }
        Ok((frame, offset))
    }
    #[inline]
    fn read_fragment(&self, frame: &Frame, offset: usize, out: &mut [u8]) {
        if let Some(bytes) = &frame.bytes.constant {
            out.copy_from_slice(&bytes[offset..offset + out.len()]);
        } else {
            if self.hardware_mode {
                frame
                    .bytes
                    .mutable()
                    .expect("hardware page")
                    .copy_read(offset, out);
            } else {
                let guard = self.frame_guard(frame, offset, out.len());
                out.copy_from_slice(guard.read(offset, out.len()));
            }
        }
    }
    #[inline]
    fn changed(&self, frame: &Frame, state: &mut page::Guard<'_>, offset: usize, len: usize) {
        frame.bytes.changed(state, offset, len);
        if len != 0 && frame.root_frame != usize::MAX {
            let word = &self.snapshot.dirty_pages[frame.root_frame / 64];
            let bit = 1 << (frame.root_frame % 64);
            if word.load(Ordering::Relaxed) & bit == 0 {
                if state.is_exclusive() {
                    word.store(word.load(Ordering::Relaxed) | bit, Ordering::Relaxed);
                } else {
                    word.fetch_or(bit, Ordering::Relaxed);
                }
            }
        }
    }
    fn load_frame(&self, frame: &Frame) -> Result<(), MemoryError> {
        if frame.backed && frame.bytes.source.is_some() && frame.bytes.loaded.get().is_none() {
            frame.charge.check_available()?;
        }
        frame.bytes.load()
    }
    fn ensure_resident(&self, frame: &Frame) -> Result<(), MemoryError> {
        // Residency is monotonic for the lifetime of this immutable frame.
        // CPU software stores and native chunks reuse the same paid TLB bit as
        // hardware stores; no quota acquire is needed on each fragment.
        let cell = &self.translations[Translation::slot(frame.base)];
        let mut entry = cell.get();
        if entry.matches(frame.base, Translation::RESIDENT) {
            return Ok(());
        }
        self.load_frame(frame)?;
        frame.charge.ensure()?;
        if entry.matches(frame.base, Translation::VALID) {
            entry.tag |= Translation::RESIDENT;
            cell.set(entry);
        }
        Ok(())
    }
    /// Mapping/EOF validation is complete before this private transport helper.
    fn copy_read(&self, mut address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        let mut done = 0;
        while done < out.len() {
            let frame = self.frame(address, Access::Read)?;
            self.load_frame(frame)?;
            if frame.backed {
                frame.charge.ensure()?;
            }
            let offset = (address % PAGE_SIZE) as usize;
            let len = (out.len() - done).min(PAGE_SIZE as usize - offset);
            self.read_fragment(frame, offset, &mut out[done..done + len]);
            done += len;
            address += len as u64;
        }
        Ok(())
    }
    /// The CPU and native transport share page translation, permissions and
    /// byte access. Native callers add only their backing-checkpoint admission.
    /// The single-page path reaches the frame once; cross-page reads validate
    /// every frame before exposing any bytes to either caller.
    #[inline]
    fn read_checked<E: From<MemoryError>>(
        &self,
        address: u64,
        out: &mut [u8],
        admit: impl Fn(&Frame) -> Result<(), E>,
    ) -> Result<(), E> {
        let address = address & 0x00ffffffffffffff;
        if out.is_empty() {
            Memory::end(address, 0)?;
            return Ok(());
        }
        if out.len() <= (PAGE_SIZE - address % PAGE_SIZE) as usize {
            let (frame, offset) = self.reached(address, out.len(), Access::Read)?;
            admit(frame)?;
            self.read_fragment(frame, offset, out);
            return Ok(());
        }
        Memory::end(address, out.len() as u64)?;
        let mut admission_error = None;
        for at in
            (address & !(PAGE_SIZE - 1)..address + out.len() as u64).step_by(PAGE_SIZE as usize)
        {
            // An earlier live-backing checkpoint must not hide a later CPU
            // permission/EOF fault. Admission is reported after CPU validation.
            let result = admit(self.frame(at.max(address), Access::Read)?);
            if admission_error.is_none() {
                admission_error = result.err();
            }
        }
        if let Some(error) = admission_error {
            return Err(error);
        }
        self.copy_read(address, out)?;
        Ok(())
    }
    fn write_fragment(
        &self,
        frame: &Frame,
        offset: usize,
        input: &[u8],
    ) -> Result<(), MemoryError> {
        self.ensure_resident(frame)?;
        if self.hardware_mode {
            let mut raw = frame
                .bytes
                .mutable()
                .expect("hardware page")
                .raw_lock(offset, input.len());
            raw.write_from(offset, input);
            self.changed(frame, &mut raw.ownership, offset, input.len());
        } else {
            let mut guard = self.frame_guard(frame, offset, input.len());
            guard.write(offset, input.len()).copy_from_slice(input);
            self.changed(frame, &mut guard, offset, input.len());
        }
        Ok(())
    }
}
impl CpuMemory for View {
    fn shared_futex_key(&self, address: u64) -> Result<Option<(u64, u64, u64)>, MemoryError> {
        let address = address & 0x00ff_ffff_ffff_ffff;
        Memory::end(address, 4)?;
        if 4 > PAGE_SIZE - address % PAGE_SIZE {
            return Err(MemoryError::InvalidRange);
        }
        self.frame(address, Access::Read)?;
        Ok(self
            .snapshot
            .backings
            .futex
            .get(&(address - address % PAGE_SIZE))
            .map(|&(identity, offset)| (identity, offset, address % PAGE_SIZE)))
    }
    fn cpu_read_chunk<T>(
        &self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        if len == 0 {
            return Ok((operation(&[]), true));
        }
        let (frame, offset) = self.reached(address & 0x00ffffffffffffff, len, Access::Read)?;
        let value = if let Some(bytes) = &frame.bytes.constant {
            operation(&bytes[offset..offset + len])
        } else {
            let guard = self.frame_guard(frame, offset, len);
            operation(guard.read(offset, len))
        };
        Ok((value, true))
    }
    fn cpu_write_chunk<T>(
        &mut self,
        address: u64,
        len: usize,
        operation: impl FnOnce(&mut [u8]) -> T,
    ) -> Result<(T, bool), MemoryError> {
        if len == 0 {
            return Ok((operation(&mut []), true));
        }
        let (frame, offset) = self.reached(address & 0x00ffffffffffffff, len, Access::Write)?;
        self.ensure_resident(frame)?;
        let mut guard = self.frame_guard(frame, offset, len);
        // Match native/CPU writes: invalidate reservations and code even when
        // the external callback unwinds. No borrow escapes this call.
        self.changed(frame, &mut guard, offset, len);
        Ok((operation(guard.write(offset, len)), true))
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        Memory::end(address, len as u64)?;
        if len == 0 {
            return Ok(());
        }
        for at in (address & !(PAGE_SIZE - 1)..address + len as u64).step_by(PAGE_SIZE as usize) {
            let frame = self.frame(at.max(address), access)?;
            if access == Access::Write {
                self.ensure_resident(frame)?;
            }
        }
        Ok(())
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        Memory::end(address, 1)?;
        if self
            .snapshot
            .pages
            .contains_key(&(address & !(PAGE_SIZE - 1)))
            || self
                .snapshot
                .reservations
                .range(..=address)
                .next_back()
                .is_some_and(|(_, end)| address < *end)
        {
            Ok(())
        } else {
            Err(MemoryError::Unmapped(address))
        }
    }
    #[inline]
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), MemoryError> {
        self.read_checked(address, out, |_| Ok(()))
    }
    #[inline]
    fn read_array<const N: usize>(&self, address: u64) -> Result<[u8; N], MemoryError> {
        let address = address & 0x00ffffffffffffff;
        let offset = address as usize & (PAGE_SIZE as usize - 1);
        if matches!(N, 1 | 2 | 4 | 8 | 16) && N <= PAGE_SIZE as usize - offset {
            let entry = self.operand_translation(address, Access::Read)?;
            if let Some(bytes) = self.mmu_read_entry::<N>(entry, offset) {
                return Ok(bytes);
            }
        }
        let mut bytes = [0; N];
        self.read(address, &mut bytes)?;
        Ok(bytes)
    }
    #[inline]
    fn write_array<const N: usize>(
        &mut self,
        address: u64,
        bytes: [u8; N],
    ) -> Result<(), MemoryError> {
        let address = address & 0x00ffffffffffffff;
        let offset = address as usize & (PAGE_SIZE as usize - 1);
        if matches!(N, 1 | 2 | 4 | 8 | 16) && N <= PAGE_SIZE as usize - offset {
            let entry = self.operand_translation(address, Access::Write)?;
            if self.mmu_write_entry(entry, offset, bytes) {
                return Ok(());
            }
        }
        self.write(address, &bytes)
    }
    fn write(&mut self, address: u64, input: &[u8]) -> Result<(), MemoryError> {
        let mut address = address & 0x00ffffffffffffff;
        if input.is_empty() {
            Memory::end(address, 0)?;
            return Ok(());
        }
        if input.len() <= (PAGE_SIZE - address % PAGE_SIZE) as usize {
            let (frame, offset) = self.reached(address, input.len(), Access::Write)?;
            self.write_fragment(frame, offset, input)?;
            return Ok(());
        }
        self.check(address, input.len(), Access::Write)?;
        for at in
            (address & !(PAGE_SIZE - 1)..address + input.len() as u64).step_by(PAGE_SIZE as usize)
        {
            self.frame(at.max(address), Access::Write)?
                .charge
                .ensure()?;
        }
        let mut done = 0;
        while done < input.len() {
            let frame = self.frame(address, Access::Write)?;
            let offset = (address % PAGE_SIZE) as usize;
            let len = (input.len() - done).min(PAGE_SIZE as usize - offset);
            self.write_fragment(frame, offset, &input[done..done + len])?;
            address += len as u64;
            done += len;
        }
        Ok(())
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        if !address.is_multiple_of(4) {
            return Err(MemoryError::Alignment(address));
        }
        let (frame, offset) = self.reached(address, 4, Access::Execute)?;
        let mut bytes = [0; 4];
        self.read_fragment(frame, offset, &mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        (
            self.snapshot.identity,
            self.snapshot.code_revision,
            (if self.snapshot.dynamic_code {
                self.snapshot.code_epoch.load(Ordering::Acquire)
            } else {
                0
            })
            .wrapping_add(self.snapshot.backing_revision),
        )
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        if !address.is_multiple_of(4) {
            return Err(MemoryError::Alignment(address));
        }
        Memory::end(address, 4)?;
        let frame = self.frame(address, Access::Execute)?;
        Ok((
            self.snapshot.identity,
            frame.bytes.identity,
            frame.bytes.version().load(Ordering::Acquire),
        ))
    }
    fn atomic_update<T>(
        &mut self,
        address: u64,
        len: usize,
        update: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        let address = address & 0x00ffffffffffffff;
        let (frame, offset) = self.reached(address, len, Access::Write)?;
        if len == 0 || len > 16 {
            return Err(MemoryError::InvalidRange);
        }
        if !frame.permissions.read {
            return Err(MemoryError::Permission {
                address,
                access: Access::Read,
            });
        }
        let mut guard = self.frame_guard(frame, offset, len);
        self.ensure_resident(frame)?;
        let (value, write) = update(guard.write(offset, len));
        if write {
            self.changed(frame, &mut guard, offset, len)
        }
        Ok(value)
    }
    fn exclusive_read(&mut self, address: u64, out: &mut [u8]) -> Result<u128, MemoryError> {
        let address = address & 0x00ffffffffffffff;
        let (frame, offset) = self.reached(address, out.len(), Access::Read)?;
        if let Some(bytes) = &frame.bytes.constant {
            out.copy_from_slice(&bytes[offset..offset + out.len()]);
            return Ok((frame.bytes.identity as u128) << 64);
        }
        let guard = self.frame_guard(frame, offset, out.len());
        out.copy_from_slice(guard.read(offset, out.len()));
        Ok((frame.bytes.identity as u128) << 64 | guard.reservation(offset / 16) as u128)
    }
    fn exclusive_write(
        &mut self,
        address: u64,
        bytes: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        if token.is_none() {
            return Ok(false);
        }
        let address = address & 0x00ffffffffffffff;
        let (frame, offset) = self.reached(address, bytes.len(), Access::Write)?;
        let mut guard = self.frame_guard(frame, offset, bytes.len());
        if token
            != Some((frame.bytes.identity as u128) << 64 | guard.reservation(offset / 16) as u128)
        {
            return Ok(false);
        }
        self.ensure_resident(frame)?;
        guard.write(offset, bytes.len()).copy_from_slice(bytes);
        self.changed(frame, &mut guard, offset, bytes.len());
        Ok(true)
    }
    fn fence(&self, order: Ordering) {
        std::sync::atomic::fence(order)
    }
}
impl Memory {
    /// A layout checkpoint must account for retained Views from every mapping
    /// generation, not just the scheduler's current job list.
    pub fn parallel_views_quiescent(&self) -> bool {
        self.shared.as_ref().map_or_else(
            || !self.has_parallel_users(),
            |memory| memory.borrow().parallel_views_quiescent(),
        )
    }
    #[inline]
    pub(super) fn note_parallel_write(&mut self, frame: usize) {
        if self.parallel_cache.is_some() {
            let page = self.frames[frame].as_mut().expect("written page");
            if !page.parallel_dirty {
                page.data_revision = page.data_revision.wrapping_add(1);
                page.parallel_dirty = true;
                self.parallel_dirty.push(frame);
            }
        }
    }
    pub(super) fn has_parallel_users(&self) -> bool {
        self.parallel_users.load(Ordering::Acquire) != 0
    }
    pub(super) fn prepare_shared_storage(
        &mut self,
        base: u64,
        frame: usize,
        registry: &mut Registry,
    ) {
        // prepare_frame already handles hardware canonical ownership and true
        // fork detachment. A temporary software MMU slot here would be copied
        // into hardware RAM and its protected CPU alias immediately retired.
        if registry.hardware {
            return;
        }
        let page = self.frames[frame].as_ref().expect("mapped frame");
        // Untouched anonymous zeros need neither RAM nor a physical VA owner.
        // Publishing them into mapped storage would retain whole windows over
        // fork even though no guest store has ever charged these bytes. The
        // existing SharedPage::zero path allocates only on its first write.
        if page.backing.is_some() || !page.charge.resident() {
            return;
        }
        let forked = Rc::strong_count(&page.bytes) > 1;
        let zero = page.bytes.is_zero() || (!page.charge.resident() && forked);
        let copy = !zero
            && ((forked && page.permissions.write) || matches!(&*page.bytes, PageBytes::Heap(_)));
        if zero || copy {
            // Keep eligible hardware aliases over the same source physical slot.
            // A true fork detaches a writable COW page once, into mapped RAM;
            // worker Arc owners alone never trigger that copy.
            let data = copy.then(|| page.bytes.snapshot());
            if let Some(mut bytes) = self.mmu.page(base) {
                if let Some(data) = data {
                    Rc::get_mut(&mut bytes)
                        .expect("fresh page owner")
                        .with_write(0, PAGE_SIZE as usize, |out| out.copy_from_slice(&data));
                    if forked {
                        registry.metrics.cow_detach_bytes += PAGE_SIZE;
                    }
                }
                self.frames[frame].as_mut().unwrap().bytes = bytes;
            }
        }
    }
    /// Shared futexes identify the backing page, including aliases at different
    /// virtual addresses and after fork. Private/anonymous addresses use mm+VA.
    pub fn shared_futex_key(&self, address: u64) -> Result<Option<(u64, u64, u64)>, MemoryError> {
        let address = address & 0x00ffffffffffffff;
        if let Some(shared) = &self.shared {
            return shared.borrow().shared_futex_key(address);
        }
        let page = self.page_for_access(address, 4, Access::Read)?;
        Ok(shared_futex_page_key(page)
            .map(|(identity, offset)| (identity, offset, address % PAGE_SIZE)))
    }
    /// Freeze mapping metadata while retaining coherent shared bytes. The host
    /// must join every view user before kernel operations or backing commit.
    pub fn parallel_view(&mut self, registry: &mut Registry) -> Option<View> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().parallel_view(registry);
        }
        self.adopt_anonymous();
        // A resumed runtime can construct a new coordinator registry. Cached
        // shared pages must join that registry's alias/code domain, not silently
        // retain an earlier one while fork peers allocate duplicate snapshots.
        if self.parallel_cache.as_ref().is_some_and(|c| {
            c.snapshot.hardware != registry.hardware
                || !Arc::ptr_eq(&c.snapshot.code_epoch, &registry.code_epoch)
                || c.source_fork_epoch != self.fork_epoch.get()
        }) {
            self.parallel_cache = None;
        }
        let backing_revision = backing::backing_revision();
        if let Some(c) = &self.parallel_cache {
            if c.source_revision == self.revision
                && c.source_backing_revision == backing_revision
                && !self.parallel_anonymous_dirty
            {
                registry.metrics.cache_hits += 1;
                return Some(View::new(c.snapshot.clone()));
            }
        }
        // Data-only coordinator writes reuse the immutable mapping table and
        // refresh just dirty frames. No Arc/map rebuild or full page-table walk
        // for each libc call. Executable/mapping/EOF changes take the slow path.
        if self.parallel_cache.as_ref().is_some_and(|c| {
            c.snapshot.code_revision == self.code_revision
                && c.source_backing_revision == backing_revision
                && c.snapshot.identity == self.identity
                && self.parallel_mappings.is_empty()
                && !self.parallel_reservations_dirty
                && !self.parallel_anonymous_dirty
                && self.parallel_dirty.iter().all(|&index| {
                    let frame =
                        &c.snapshot.frames[c.snapshot.positions[index].expect("dirty frame")];
                    !frame.direct || direct_matches(self.frames[index].as_ref().unwrap(), frame)
                })
        }) {
            registry.metrics.dirty_refreshes += 1;
            let mut cache = self.parallel_cache.take().expect("checked cache");
            let dirty = std::mem::take(&mut self.parallel_dirty);
            for &index in &dirty {
                self.frames[index]
                    .as_mut()
                    .expect("same mapped frame")
                    .parallel_dirty = false;
            }
            for index in dirty {
                let page = self.frames[index].as_mut().expect("same mapped frame");
                let frame = &cache.snapshot.frames
                    [cache.snapshot.positions[index].expect("same mapped frame")];
                if !frame.direct {
                    let mut data = [0; PAGE_SIZE as usize];
                    registry.metrics.source_page_reads += 1;
                    registry.metrics.copied_publish_bytes += PAGE_SIZE;
                    page.read_bytes(0, &mut data).ok()?;
                    frame.bytes.refresh(&data);
                }
                frame.refresh_content_metadata(page);
            }
            cache.source_revision = self.revision;
            let view = View::new(cache.snapshot.clone());
            self.parallel_cache = Some(cache);
            return Some(view);
        }
        if self.parallel_cache.as_ref().is_some_and(|cache| {
            Arc::strong_count(&cache.snapshot) == 1
                && Arc::strong_count(&cache.snapshot.dirty_pages) == 1
        }) {
            return self.update_parallel_snapshot(registry, backing_revision);
        }
        // Unknown mutable backings retain the existing serial path.
        if self.frames.iter().flatten().any(|p| {
            p.backing
                .as_ref()
                .is_some_and(|b| b.object.parallel_key().is_none())
        }) {
            return None;
        }
        registry.shared.retain(|_, page| page.strong_count() != 0);
        registry.mmu.prune();
        registry.metrics.full_rebuilds += 1;
        registry.metrics.full_rebuild_pages += self.pages.len() as u64;
        if let Some(cache) = &self.parallel_cache {
            registry.metrics.backing_invalidations +=
                u64::from(cache.source_backing_revision != backing_revision);
            registry.metrics.code_invalidations +=
                u64::from(cache.snapshot.code_revision != self.code_revision);
        }
        let old = self.parallel_cache.take();
        let mut frames = Slots::new();
        let mut positions: Slots<_> = (0..self.frames.len()).map(|_| None).collect();
        let mut pages = BTreeMap::new();
        let mut identities = BTreeMap::new();
        let mut alias_count = 0usize;
        let mut backed_pages = BTreeSet::new();
        let mut backings = snapshot::BackingIndex::default();
        let mapped: Slots<_> = self
            .pages
            .iter()
            .map(|(&base, &frame)| (base, frame))
            .collect();
        for (base, root_frame) in mapped {
            self.prepare_shared_storage(base, root_frame, registry);
            let page = self.frames[root_frame].as_mut().expect("mapped frame");
            let previous = old
                .as_ref()
                .and_then(|c| c.snapshot.pages.get(&base).map(|&i| &c.snapshot.frames[i]));
            let frame = prepare_frame(self.identity, page, base, root_frame, previous, registry)?;
            let count = identities.entry(frame.bytes.identity).or_insert(0usize);
            alias_count += usize::from(*count == 1);
            *count += 1;
            if let Some(backing) = &page.backing {
                backed_pages.insert(base);
                backings.insert(
                    base,
                    frame.backing_domain,
                    backing.object.as_ref(),
                    frame.bytes.identity,
                    shared_futex_page_key(page),
                );
            }
            pages.insert(base, frames.len());
            positions[root_frame] = Some(frames.len());
            frames.push(frame);
        }
        let dynamic_code_pages = frames.iter().filter(|frame| frame.dynamic_code).count();
        let hardware_generation = new_backing_identity();
        let mut hardware_chunks = BTreeMap::new();
        if registry.hardware {
            let mut last = None;
            for &address in pages.keys() {
                let chunk = address / crate::HARDWARE_MAPPING_CHUNK_SIZE;
                if last != Some(chunk) {
                    hardware_chunks.insert(chunk, hardware_generation);
                    last = Some(chunk);
                }
            }
        }
        let anonymous = anonymous::Anonymous::freeze(self, registry.code_epoch.clone());
        let anonymous_executable = anonymous.executable();
        let mut snapshot = Snapshot {
            anonymous,
            hardware: registry.hardware,
            hardware_generation,
            hardware_chunks,
            hardware_changes: Default::default(),
            hardware_writes: AtomicU64::new(0),
            hardware_private_dirty: std::sync::atomic::AtomicBool::new(false),
            mmu: mmu::Frozen::default(),
            has_aliases: alias_count != 0,
            dynamic_code: dynamic_code_pages != 0 || anonymous_executable,
            dynamic_code_pages,
            identities,
            alias_count,
            backed_pages,
            backings,
            positions,
            backing_revision,
            identity: self.identity,
            code_revision: self.code_revision,
            pages,
            // Backing-epoch refreshes can retain the same ConcurrentPages in
            // earlier views. Keep their publication tracker in that domain too.
            // Mapping changes require joined workers and get a fresh tracker.
            dirty_pages: old
                .as_ref()
                .filter(|c| {
                    c.snapshot.code_revision == self.code_revision
                        && c.snapshot.identity == self.identity
                        && self.parallel_mappings.is_empty()
                        && !self.parallel_reservations_dirty
                })
                .map_or_else(
                    || {
                        (0..self.frames.len().div_ceil(64))
                            .map(|_| AtomicU64::new(0))
                            .collect()
                    },
                    |c| c.snapshot.dirty_pages.clone(),
                ),
            frames,
            reservations: self.reservations.clone(),
            code_epoch: registry.code_epoch.clone(),
            users: self.parallel_users.clone(),
        };
        snapshot.refresh_mmu_all();
        let snapshot = Arc::new(snapshot);
        self.parallel_cache = Some(SnapshotCache {
            snapshot: snapshot.clone(),
            source_revision: self.revision,
            source_fork_epoch: self.fork_epoch.get(),
            source_backing_revision: backing_revision,
        });
        self.parallel_mappings.clear();
        self.parallel_reservations_dirty = false;
        self.parallel_anonymous_dirty = false;
        self.parallel_anonymous_changes.clear();
        for index in self.parallel_dirty.drain(..) {
            if let Some(page) = self.frames[index].as_mut() {
                page.parallel_dirty = false;
            }
        }
        Some(View::new(snapshot))
    }
    /// This mm's joined CPUs publish dirty metadata and persistence/code hooks.
    /// Isolated providers may retain live other-mm users of canonical storage.
    /// Resident
    /// source pages already contain the writes; only legacy/custom backings copy
    /// dirty fragments through the provider's write method.
    pub fn commit_parallel(&mut self) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().commit_parallel();
        }
        self.adopt_anonymous();
        let Some(mut cache) = self.parallel_cache.take() else {
            return Ok(());
        };
        let result = (|| {
            for (word_index, word) in cache.snapshot.dirty_pages.iter().enumerate() {
                // This mm's workers are joined, so its bitmap is stable. A
                // shared ConcurrentPage's dirty mask may also include other-mm
                // stores; swap harvests them without clearing their own bitmap.
                let mut pending = word.load(Ordering::Relaxed);
                while pending != 0 {
                    let bit = pending.trailing_zeros() as usize;
                    let index = cache.snapshot.positions[word_index * 64 + bit]
                        .expect("dirty mapped frame");
                    let frame = &cache.snapshot.frames[index];
                    debug_assert!(frame.permissions.write);
                    let mut dirty = frame.bytes.dirty.swap(0, Ordering::Relaxed);
                    if dirty == 0 {
                        pending &= pending - 1;
                        word.store(pending, Ordering::Relaxed);
                        continue;
                    }
                    if frame.direct {
                        let page = self.frames[frame.root_frame]
                            .as_mut()
                            .expect("mapped shared bytes");
                        assert!(
                            direct_matches(page, frame),
                            "mapping changes require joined commit"
                        );
                        if let Some(backing) = page.backing.as_ref().filter(|b| b.shared) {
                            // Dirty byte ranges still drive persistence/version
                            // hooks; the backing already owns these exact bytes.
                            while dirty != 0 {
                                let first = dirty.trailing_zeros() as usize;
                                let count = (dirty >> first).trailing_ones() as usize;
                                if let Err(error) =
                                    backing.object.publish_write(first * 64, count * 64)
                                {
                                    frame.bytes.dirty.fetch_or(dirty, Ordering::Relaxed);
                                    return Err(error);
                                }
                                dirty &= if count == 64 {
                                    0
                                } else {
                                    !(((1u64 << count) - 1) << first)
                                };
                            }
                        }
                        // The bytes are already authoritative. Only publish the
                        // coordinator's instruction/data generations here.
                        page.data_revision = page.data_revision.wrapping_add(1);
                        self.revision = self.revision.wrapping_add(1);
                        if page.permissions.execute {
                            page.instruction_revision = self.code_revision.wrapping_add(1);
                            self.advance_code_revision();
                        }
                    } else {
                        let guard = frame
                            .bytes
                            .mutable()
                            .expect("dirty writable page")
                            .lock(0, PAGE_SIZE as usize);
                        while dirty != 0 {
                            let first = dirty.trailing_zeros() as usize;
                            let count = (dirty >> first).trailing_ones() as usize;
                            if let Err(error) = self.write(
                                frame.base + (first * 64) as u64,
                                guard.read(first * 64, count * 64),
                            ) {
                                frame.bytes.dirty.fetch_or(dirty, Ordering::Relaxed);
                                return Err(error);
                            }
                            // Coalesce adjacent dirty fragments without writing through
                            // a clean hole or overwriting another backing alias's bytes.
                            if count == 64 {
                                dirty = 0;
                            } else {
                                dirty &= !(((1u64 << count) - 1) << first);
                            }
                        }
                    }
                    let page = self.frames[frame.root_frame]
                        .as_ref()
                        .expect("committed page");
                    if page.instruction_revision != frame.code_revision
                        || (!frame.direct
                            && page
                                .backing
                                .as_ref()
                                .is_some_and(|b| !b.shared && b.private_copy))
                    {
                        self.parallel_mappings.insert(frame.base);
                    }
                    frame
                        .native_retryable
                        .store(page.native_retryable(), Ordering::Relaxed);
                    frame
                        .native_one_shot
                        .store(page.native_one_shot(), Ordering::Relaxed);
                    frame.native_live_private.store(
                        page.backing
                            .as_ref()
                            .is_some_and(|b| !b.shared && !b.private_copy && !frame.direct),
                        Ordering::Relaxed,
                    );
                    frame
                        .data_revision
                        .store(page.data_revision, Ordering::Relaxed);
                    frame.backing_version.store(
                        page.backing.as_ref().map_or(0, |b| b.object.version()),
                        Ordering::Relaxed,
                    );
                    pending &= pending - 1;
                    word.store(pending, Ordering::Relaxed);
                }
            }
            Ok(())
        })();
        // Private RAM already is the coordinator's canonical storage. One
        // conservative VM generation replaces per-page fake dirty writes.
        // Guest code stores use architectural IC/DC maintenance; actual host
        // writers publish their affected range, not a joined code generation.
        if cache
            .snapshot
            .hardware_private_dirty
            .swap(false, Ordering::Relaxed)
        {
            self.revision = self.revision.wrapping_add(1);
        }
        // The joined handoff orders this token; no byte fence is needed.
        cache
            .snapshot
            .hardware_writes
            .fetch_add(1, Ordering::Relaxed);
        // Frame generations are rebuilt after kernel writes. Keep data-only
        // worker rounds cheap when there was no coordinator mutation.
        cache.source_revision = self.revision;
        // Retain the captured backing epoch: writes through another mapping
        // may require refreshing an undetached private file view next round.
        if cache.snapshot.code_revision != self.code_revision
            || !self.parallel_mappings.is_empty()
            || self.parallel_anonymous_dirty
        {
            cache.source_revision = self.revision.wrapping_sub(1);
        }
        self.parallel_cache = Some(cache);
        result
    }
}

impl View {
    /// Called before dispatch; frozen CPU aliases are bypassed because physical
    /// storage can be exported on demand under the original page region lock.
    pub fn enable_hardware(&mut self) {
        self.private_mode = PrivateMode::Guarded;
        self.hardware_mode = true;
    }
    /// Mapping identity is independent of ordinary data writes. The second
    /// token changes only at joined dirty publication, not at every CPU slice.
    pub fn hardware_view_version(&self) -> (u64, u64) {
        (
            self.snapshot.hardware_generation,
            self.snapshot.hardware_writes.load(Ordering::Relaxed),
        )
    }
    /// Deltas after a previously observed mapping token. None means history
    /// expired or a full snapshot replacement: revalidate the cached mappings.
    pub fn hardware_mapping_changes(&self, since: u64) -> Option<impl Iterator<Item = u64> + '_> {
        Some(
            self.hardware_mapping_ranges(since)?
                .flat_map(|range| range.step_by(PAGE_SIZE as usize)),
        )
    }
    /// Bounded interval journal for hardware backends. Intersect with cached
    /// mappings rather than enumerating untouched pages in a large changed VMA.
    /// Intervals from different updates can overlap or arrive out of order.
    pub fn hardware_mapping_ranges(
        &self,
        since: u64,
    ) -> Option<impl Iterator<Item = std::ops::Range<u64>> + '_> {
        let changes = &self.snapshot.hardware_changes;
        let start = if since == self.snapshot.hardware_generation {
            changes.len()
        } else {
            changes.iter().position(|change| change.before == since)?
        };
        Some(
            changes
                .iter()
                .skip(start)
                .flat_map(|change| change.ranges.iter().cloned()),
        )
    }
    /// Persistent metadata stamp for the 2MiB chunk containing `address`.
    /// Unlike the bounded interval journal this survives arbitrarily many joined
    /// updates. None means no mapped page in the chunk. Full snapshot replacement
    /// changes every live stamp; removed chunks retain no tombstone or RAM owner.
    /// This is an invalidation hint only; page permissions/storage still come
    /// from hardware_page_info. No guest byte is loaded, allocated or charged.
    pub fn hardware_mapping_chunk_version(&self, address: u64) -> Option<u64> {
        self.snapshot
            .hardware_chunks
            .get(&(address / crate::HARDWARE_MAPPING_CHUNK_SIZE))
            .copied()
            .or_else(|| {
                let start = address / crate::HARDWARE_MAPPING_CHUNK_SIZE
                    * crate::HARDWARE_MAPPING_CHUNK_SIZE;
                self.snapshot
                    .anonymous
                    .overlaps(start, start + crate::HARDWARE_MAPPING_CHUNK_SIZE)
                    .then_some(self.snapshot.hardware_generation)
            })
    }
    /// Existing hardware storage only: no source load, allocation, quota charge
    /// or byte borrow. The result preserves this View's permission/EOF model.
    pub fn retained_hardware_page(
        &self,
        address: u64,
    ) -> Option<(Arc<dyn crate::HardwareStorage>, HardwarePageInfo)> {
        if !self.hardware_mode {
            return None;
        }
        let frame = if let Some(&i) = self.snapshot.pages.get(&address) {
            &self.snapshot.frames[i]
        } else {
            self.snapshot.anonymous.cached(address)?
        };
        if frame.error.is_some() || !frame.charge.resident() || !frame.hardware_shared_export {
            return None;
        }
        let page = frame
            .bytes
            .mutable()
            .or_else(|| frame.bytes.hardware_constant.get())?;
        let storage = page.retained_hardware()?;
        Some((storage, self.hardware_page_info(address).ok()?))
    }
    pub fn hardware_write_frame(
        &self,
        address: u64,
    ) -> Result<crate::HardwareWriteFrame, MemoryError> {
        let frame = self.frame(address, Access::Write)?;
        if !frame.charge.resident() {
            return Err(MemoryError::InvalidRange);
        }
        Ok(crate::HardwareWriteFrame {
            vm: self.snapshot.identity,
            base: frame.base,
            root: frame.root_frame,
            storage: frame.bytes.identity,
            publication: frame.hardware_track_writes,
        })
    }
    pub fn mark_hardware_frame_write(
        &self,
        token: crate::HardwareWriteFrame,
    ) -> Result<(), MemoryError> {
        let frame = if token.root == usize::MAX {
            self.snapshot
                .anonymous
                .cached(token.base)
                .ok_or(MemoryError::InvalidRange)?
        } else {
            let position = self
                .snapshot
                .positions
                .get(token.root)
                .copied()
                .flatten()
                .ok_or(MemoryError::InvalidRange)?;
            &self.snapshot.frames[position]
        };
        if token.vm != self.snapshot.identity
            || token.base != frame.base
            || token.storage != frame.bytes.identity
            || !frame.permissions.write
        {
            return Err(MemoryError::InvalidRange);
        }
        if let Some(error) = &frame.error {
            return Err(error.clone());
        }
        self.mark_hardware_frame(frame);
        Ok(())
    }
    pub fn hardware_page_info(&self, address: u64) -> Result<HardwarePageInfo, MemoryError> {
        if !address.is_multiple_of(PAGE_SIZE) {
            return Err(MemoryError::InvalidRange);
        }
        let frame = if let Some(&i) = self.snapshot.pages.get(&address) {
            &self.snapshot.frames[i]
        } else {
            self.snapshot
                .anonymous
                .metadata(address)?
                .ok_or(MemoryError::Unmapped(address))?
        };
        if let Some(error) = &frame.error {
            return Err(error.clone());
        }
        if !frame.hardware_shared_export {
            return Err(MemoryError::BackingIo(95));
        }
        Ok(HardwarePageInfo {
            permissions: frame.permissions,
            storage_id: frame.bytes.identity,
            instruction_revision: if frame.permissions.execute {
                (
                    frame.code_revision,
                    frame.bytes.version().load(Ordering::Acquire),
                )
            } else {
                (0, 0)
            },
            backing_version: frame.backing_version.load(Ordering::Relaxed),
            exclusive: false,
            writable: frame.permissions.write && frame.charge.resident(),
        })
    }
    pub fn mark_hardware_write(&self, address: u64) -> Result<(), MemoryError> {
        let frame = self.frame(address, Access::Write)?;
        self.mark_hardware_frame(frame);
        Ok(())
    }
    /// An admitted writable private mapping may have stored directly into
    /// canonical RAM. No per-page byte/monitor counter or copyback is needed.
    /// Guest code stores retain their architectural IC/DC responsibility.
    pub fn mark_hardware_private_writes(&self) {
        self.snapshot
            .hardware_private_dirty
            .store(true, Ordering::Relaxed);
    }
    fn mark_hardware_frame(&self, frame: &Frame) {
        if !frame.hardware_track_writes {
            self.mark_hardware_private_writes();
            return;
        }
        frame.bytes.dirty.store(u64::MAX, Ordering::Relaxed);
        frame.bytes.version().fetch_add(1, Ordering::Relaxed);
        if frame.root_frame != usize::MAX {
            self.snapshot.dirty_pages[frame.root_frame / 64]
                .fetch_or(1 << (frame.root_frame % 64), Ordering::Relaxed);
        }
        if frame.permissions.execute {
            frame.bytes.code_epoch.fetch_add(1, Ordering::Release);
        }
    }
    /// Export one admitted page from the same storage used by CPU/native/VFS.
    ///
    /// # Safety
    /// Every execution View of this VM uses hardware mode; coordinator mapping
    /// mutation and unpublished/pinned actors are excluded until all Views join.
    pub unsafe fn export_hardware_page(
        &self,
        address: u64,
        access: Access,
        allocate: impl FnOnce(Option<&[u8]>) -> Result<Arc<dyn crate::HardwareStorage>, MemoryError>,
    ) -> Result<(Arc<dyn crate::HardwareStorage>, HardwarePageInfo), MemoryError> {
        // SAFETY: inherited frozen-view contract; legacy callers refuse external imports.
        unsafe {
            self.export_hardware_page_with_mapping(address, access, allocate, |_| {
                Err(MemoryError::BackingIo(95))
            })
        }
    }
    /// Import stable file mappings without losing external display aliases.
    ///
    /// # Safety
    /// Same frozen-view contract as export_hardware_page; the importer retains
    /// and aliases the supplied allocation through the HardwareStorage gate.
    pub unsafe fn export_hardware_page_with_mapping(
        &self,
        address: u64,
        access: Access,
        allocate: impl FnOnce(Option<&[u8]>) -> Result<Arc<dyn crate::HardwareStorage>, MemoryError>,
        import: impl FnOnce(
            crate::SharedMapping,
        ) -> Result<Arc<dyn crate::HardwareStorage>, MemoryError>,
    ) -> Result<(Arc<dyn crate::HardwareStorage>, HardwarePageInfo), MemoryError> {
        assert!(self.hardware_mode);
        let frame = self.frame(address, access)?;
        self.load_frame(frame)?;
        if frame.backed {
            frame.charge.ensure()?;
        }
        if !frame.hardware_shared_export {
            return Err(MemoryError::BackingIo(95));
        }
        // A hardware export binds a real physical slot even for a zero read.
        // Ordinary software zero reads remain allocation-free and uncharged.
        self.ensure_resident(frame)?;
        let page = if let Some(page) = frame.bytes.mutable() {
            page
        } else {
            frame.bytes.hardware_constant.get_or_init(|| {
                Arc::new(SharedPage::new(
                    frame.bytes.constant.as_ref().expect("constant frame")[..]
                        .try_into()
                        .unwrap(),
                ))
            })
        };
        // SAFETY: hardware mode bypasses every old protected native alias and
        // retains only region-guarded byte actors for this frozen snapshot.
        let storage = unsafe { page.export_hardware_with_mapping(allocate, import) }?;
        if self.hardware_page_info(address)?.writable {
            self.mark_hardware_write(address)?;
        }
        Ok((storage, self.hardware_page_info(address)?))
    }
}

impl Registry {
    pub fn use_hardware(&mut self) {
        self.hardware = true;
    }
}
impl Memory {
    pub fn prepare_hardware(&mut self) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().prepare_hardware();
        }
        // Most hardware address spaces never register fixed I/O buffers. An
        // empty pin table proves that no mapped page can be pinned; do not walk
        // the entire resident image at every CPU admission in that case.
        if !self.parallel_views_quiescent()
            || (!self.pinned.is_empty()
                && self.frames.iter().flatten().any(|p| self.page_pinned(p)))
        {
            return Err(MemoryError::BackingIo(95));
        }
        // A canonical SharedPage can transfer Heap -> hardware storage during
        // this epoch. Retire coordinator cached byte pointers at every admission,
        // even though the separate software CPU alias arena stays disabled.
        self.invalidate_translations();
        if self.mmu.cpu_aliases_enabled() {
            self.mmu = mmu::Arena::without_cpu_aliases();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn hardware_admission_rejects_only_mapped_live_pins() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        memory.prepare_hardware().unwrap();

        let pin = memory.pin_rw(0x1000, 16).unwrap();
        assert_eq!(memory.prepare_hardware(), Err(MemoryError::BackingIo(95)));
        drop(pin);
        // The weak registration remains, but no byte actor owns the old pin.
        memory.prepare_hardware().unwrap();

        let pin = memory.pin_rw(0x2000, 16).unwrap();
        memory.unmap(0x2000, PAGE_SIZE).unwrap();
        // An exported buffer can outlive its mapping without excluding an
        // unrelated hardware address space from execution.
        memory.prepare_hardware().unwrap();
        pin.write(0, b"retained").unwrap();
        assert_eq!(pin.read(0, 8).unwrap(), b"retained");
    }

    #[test]
    fn sparse_publication_survives_frame_reuse_and_repeated_worker_epochs() {
        let mut memory = Memory::default();
        memory
            .map(0x1000, PAGE_SIZE * 257, Permissions::RW)
            .unwrap();
        // Reuse a low root-frame index for a high virtual address; publication
        // must not confuse virtual table order with stable frame indices.
        memory.unmap(0x2000, PAGE_SIZE).unwrap();
        memory.map(0x400000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let addresses = [0x1000, 0x41000, 0x81000, 0x101000, 0x400000];
        for epoch in 1..=3u64 {
            let view = memory.parallel_view(&mut registry).unwrap();
            let mut threads = Vec::new();
            for address in addresses {
                let mut view = view.clone();
                threads.push(std::thread::spawn(move || {
                    view.write_array(address, epoch.to_le_bytes()).unwrap();
                }));
            }
            for thread in threads {
                thread.join().unwrap();
            }
            drop(view);
            memory.commit_parallel().unwrap();
            memory.commit_parallel().unwrap();
            for address in addresses {
                assert_eq!(memory.read_u64(address).unwrap(), epoch);
            }
            assert_eq!(memory.read_u64(0x5000).unwrap(), 0);
        }
    }

    #[test]
    fn retained_views_publish_after_an_unrelated_backing_epoch_refresh() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE * 2, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut earlier = memory.parallel_view(&mut registry).unwrap();
        backing_changed();
        let mut later = memory.parallel_view(&mut registry).unwrap();
        earlier.write_array(0x1000, 7u64.to_le_bytes()).unwrap();
        later.write_array(0x2000, 9u64.to_le_bytes()).unwrap();
        drop((earlier, later));
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_u64(0x1000).unwrap(), 7);
        assert_eq!(memory.read_u64(0x2000).unwrap(), 9);
    }

    #[test]
    fn commit_coalesces_dirty_runs_and_preserves_clean_backing_alias_holes() {
        struct Backing {
            bytes: RefCell<[u8; 4096]>,
            writes: RefCell<Vec<(usize, usize)>>,
            version: Cell<u64>,
            identity: u64,
            fail_once: Cell<bool>,
        }
        impl PageBacking for Backing {
            fn parallel_key(&self) -> Option<(u64, u64)> {
                Some((self.identity, 0))
            }
            fn check(&self, _: u64) -> Result<(), MemoryError> {
                Ok(())
            }
            fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
                out.copy_from_slice(&self.bytes.borrow()[offset..offset + out.len()]);
                Ok(())
            }
            fn write(&self, offset: usize, input: &[u8]) -> Result<(), MemoryError> {
                if self.fail_once.replace(false) {
                    return Err(MemoryError::BackingIo(5));
                }
                self.bytes.borrow_mut()[offset..offset + input.len()].copy_from_slice(input);
                self.writes.borrow_mut().push((offset, input.len()));
                self.version.set(self.version.get().wrapping_add(1));
                backing_changed();
                Ok(())
            }
            fn native_resident(&self) -> bool {
                true
            }
            fn sync(&self) -> Result<(), MemoryError> {
                Ok(())
            }
            fn version(&self) -> u64 {
                self.version.get()
            }
            fn writable(&self) -> bool {
                true
            }
            fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
                Err(MemoryError::InvalidRange)
            }
        }
        let object = Rc::new(Backing {
            bytes: RefCell::new([0; 4096]),
            writes: RefCell::new(Vec::new()),
            version: Cell::new(0),
            identity: new_backing_identity(),
            fail_once: Cell::new(false),
        });
        let mut memory = Memory::default();
        memory
            .map_backed(0x1000, vec![object.clone()], true, Permissions::RW, false)
            .unwrap();
        memory
            .map_backed(0x3000, vec![object.clone()], true, Permissions::RW, false)
            .unwrap();
        let mut registry = Registry::default();
        let mut hardware = memory.parallel_view(&mut registry).unwrap();
        hardware.enable_hardware();
        // SAFETY: this isolated legacy backing has no native aliases or actors.
        // It cannot export canonical shared bytes; no shadow may be published.
        assert!(matches!(
            unsafe {
                hardware.export_hardware_page(0x1000, Access::Write, |_| {
                    panic!("legacy shared shadow must not allocate")
                })
            },
            Err(MemoryError::BackingIo(95))
        ));
        drop(hardware);
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.fill_with(0x1000, 4096, |b| b.fill(1)).unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        assert_eq!(*object.writes.borrow(), [(0, 4096)]);
        object.writes.borrow_mut().clear();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.fill_with(0x3000, 64, |b| b.fill(7)).unwrap();
        view.fill_with(0x3080, 64, |b| b.fill(8)).unwrap();
        drop(view);
        // An independent backing alias can change a clean hole. Commit must
        // retain it instead of publishing the old snapshot's whole page.
        object.write(64, &[9; 64]).unwrap();
        object.writes.borrow_mut().clear();
        memory.commit_parallel().unwrap();
        assert_eq!(*object.writes.borrow(), [(0, 64), (128, 64)]);
        assert_eq!(memory.read_array::<64>(0x1000).unwrap(), [7; 64]);
        assert_eq!(memory.read_array::<64>(0x1040).unwrap(), [9; 64]);
        assert_eq!(memory.read_array::<64>(0x1080).unwrap(), [8; 64]);
        object.writes.borrow_mut().clear();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.fill_with(0x1000, 128, |b| b.fill(2)).unwrap();
        drop(view);
        memory.commit_parallel().unwrap();
        assert_eq!(*object.writes.borrow(), [(0, 128)]);
        // A transient persistence failure must keep uncommitted fragments.
        let mut view = memory.parallel_view(&mut registry).unwrap();
        view.write_array(0x3020, 42u64.to_le_bytes()).unwrap();
        drop(view);
        object.fail_once.set(true);
        assert_eq!(memory.commit_parallel(), Err(MemoryError::BackingIo(5)));
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_u64(0x1020).unwrap(), 42);
    }
    #[test]
    fn immutable_code_ignores_unrelated_live_code_epochs() {
        let mut immutable = Memory::default();
        immutable.map(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut mutable = Memory::default();
        mutable
            .map(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    execute: true,
                    ..Permissions::RW
                },
            )
            .unwrap();
        let mut registry = Registry::default();
        let a = immutable.parallel_view(&mut registry).unwrap();
        let mut b = mutable.parallel_view(&mut registry).unwrap();
        assert!(!a.snapshot.dynamic_code);
        assert!(b.snapshot.dynamic_code);
        let before = a.instruction_identity();
        let mutable_before = b.instruction_identity();
        b.write_array(0x1000, 0xd503201fu32.to_le_bytes()).unwrap();
        assert_eq!(a.instruction_identity(), before);
        assert_ne!(b.instruction_identity(), mutable_before);
    }
    #[test]
    fn racing_rmw_and_shared_vm_publish_every_increment() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut sibling = memory.share();
        let mut registry = Registry::default();
        let start = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let mut view = sibling.parallel_view(&mut registry).unwrap();
            let start = start.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..10000 {
                    view.atomic_update(0x1000, 8, |data| {
                        let n = u64::from_le_bytes(data.try_into().unwrap());
                        data.copy_from_slice(&(n + 1).to_le_bytes());
                        ((), true)
                    })
                    .unwrap();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_u64(0x1000).unwrap(), 40000);
        assert_eq!(sibling.read_u64(0x1000).unwrap(), 40000);
    }
    #[test]
    fn exclusives_detect_aba_but_allow_an_unrelated_granule() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut a = memory.parallel_view(&mut registry).unwrap();
        let mut b = memory.parallel_view(&mut registry).unwrap();
        let mut old = [0; 8];
        let token = a.exclusive_read(0x1000, &mut old).unwrap();
        b.write_array(0x1000, 1u64.to_le_bytes()).unwrap();
        b.write_array(0x1000, 0u64.to_le_bytes()).unwrap();
        assert!(!a
            .exclusive_write(0x1000, &2u64.to_le_bytes(), Some(token))
            .unwrap());
        let token = a.exclusive_read(0x1000, &mut old).unwrap();
        b.write_array(0x1020, 3u64.to_le_bytes()).unwrap();
        assert!(a
            .exclusive_write(0x1000, &2u64.to_le_bytes(), Some(token))
            .unwrap());
        memory.commit_parallel().unwrap();
        assert_eq!(memory.read_u64(0x1000).unwrap(), 2);
        assert_eq!(memory.read_u64(0x1020).unwrap(), 3);
    }
    #[test]
    fn coordinator_aba_and_native_stores_invalidate_a_worker_reservation() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut a = memory.parallel_view(&mut registry).unwrap();
        let mut old = [0; 8];
        let token = a.exclusive_read(0x1000, &mut old).unwrap();
        drop(a);
        memory.write_array(0x1000, 1u64.to_le_bytes()).unwrap();
        memory.write_array(0x1000, 0u64.to_le_bytes()).unwrap();
        let mut a = memory.parallel_view(&mut registry).unwrap();
        assert!(!a
            .exclusive_write(0x1000, &2u64.to_le_bytes(), Some(token))
            .unwrap());
        let token = a.exclusive_read(0x1000, &mut old).unwrap();
        drop(a);
        memory.fill_with(0x1000, 8, |bytes| bytes.fill(0)).unwrap();
        let mut a = memory.parallel_view(&mut registry).unwrap();
        assert!(!a
            .exclusive_write(0x1000, &2u64.to_le_bytes(), Some(token))
            .unwrap());
    }
    #[test]
    fn remapping_changes_reservation_identity_and_cross_page_faults_have_no_effect() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::R).unwrap();
        let mut registry = Registry::default();
        let mut a = memory.parallel_view(&mut registry).unwrap();
        let mut bytes = [0; 8];
        let token = a.exclusive_read(0x1000, &mut bytes).unwrap();
        assert!(matches!(
            a.write(0x1fff, &[1, 2]),
            Err(MemoryError::Permission { .. })
        ));
        assert_eq!(a.read_array::<1>(0x1fff).unwrap(), [0]);
        drop(a);
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut a = memory.parallel_view(&mut registry).unwrap();
        assert!(!a
            .exclusive_write(0x1000, &1u64.to_le_bytes(), Some(token))
            .unwrap());
    }
    #[test]
    fn shared_backing_aliases_are_one_transaction_domain_and_fork_cow_stays_private() {
        let mut parent = Memory::default();
        parent
            .map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
            .unwrap();
        parent.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut child = parent.clone();
        let mut registry = Registry::default();
        let p = parent.parallel_view(&mut registry).unwrap();
        let c = child.parallel_view(&mut registry).unwrap();
        // Only the concurrent views cross host-thread boundaries. The parent
        // and child retain coordinator-local COW pages until joined commit.
        std::thread::scope(|scope| {
            for (mut view, private_value) in [(p, 3u64), (c, 4u64)] {
                scope.spawn(move || {
                    view.atomic_update(0x1000, 8, |b| {
                        let v = u64::from_le_bytes(b.try_into().unwrap());
                        b.copy_from_slice(&(v + 1).to_le_bytes());
                        ((), true)
                    })
                    .unwrap();
                    view.write_array(0x2000, private_value.to_le_bytes())
                        .unwrap();
                });
            }
        });
        parent.commit_parallel().unwrap();
        child.commit_parallel().unwrap();
        assert_eq!(parent.read_u64(0x1000).unwrap(), 2);
        assert_eq!(child.read_u64(0x1000).unwrap(), 2);
        assert_eq!(parent.read_u64(0x2000).unwrap(), 3);
        assert_eq!(child.read_u64(0x2000).unwrap(), 4);
    }
    #[test]
    fn acquire_release_publication_and_page_code_tokens_reach_peers() {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    execute: true,
                    ..Permissions::RW
                },
            )
            .unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let mut writer = memory.parallel_view(&mut registry).unwrap();
        let reader = memory.parallel_view(&mut registry).unwrap();
        let before = reader.instruction_identity();
        let page_before = reader.instruction_page_identity(0x1000).unwrap();
        let started = Arc::new(Barrier::new(2));
        let gate = started.clone();
        let thread = std::thread::spawn(move || {
            gate.wait();
            writer
                .write_array(0x1000, 0xd503201fu32.to_le_bytes())
                .unwrap();
            writer.fence(Ordering::Release);
            writer.write_array(0x2000, 1u64.to_le_bytes()).unwrap();
        });
        started.wait();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while reader.read_u64(0x2000).unwrap() == 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        reader.fence(Ordering::Acquire);
        assert_eq!(reader.fetch_u32(0x1000).unwrap(), 0xd503201f);
        assert_ne!(reader.instruction_identity(), before);
        assert_ne!(
            reader.instruction_page_identity(0x1000).unwrap(),
            page_before
        );
        thread.join().unwrap();
        memory.commit_parallel().unwrap();
        assert_eq!(memory.fetch_u32(0x1000).unwrap(), 0xd503201f);
    }
}
