// SPDX-License-Identifier: GPL-3.0-or-later
//! Demand accounting for guest pages, independent of virtual mapping size.
//! Anonymous software zeros pay on write; file bytes and physical hardware
//! exports pay on access. Worker frames retain the same per-page charge.
use super::*;
use std::sync::{
    atomic::{AtomicU64, AtomicU8, AtomicUsize},
    Arc,
};

pub(super) struct Budget {
    used: AtomicUsize,
    limit: AtomicUsize,
}

impl Budget {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            limit: AtomicUsize::new(limit),
        })
    }
    fn take(&self, bytes: usize) -> Result<(), MemoryError> {
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes)
                    .filter(|&n| n <= self.limit.load(Ordering::Relaxed))
            })
            .map(|_| ())
            .map_err(|_| MemoryError::Limit)
    }
}
type NativeRanges = std::sync::Mutex<BTreeMap<usize, std::sync::Weak<dyn crate::HardwareRange>>>;
pub(super) struct Account {
    local: Arc<Budget>,
    peak: AtomicUsize,
    total: Option<Arc<Budget>>,
    native: std::sync::OnceLock<NativeRanges>,
    cow_epoch: AtomicU64,
}
impl Account {
    pub(super) fn cow_epoch(&self) -> u64 {
        self.cow_epoch.load(Ordering::Relaxed)
    }
    pub(super) fn publish_cow(&self) {
        self.cow_epoch
            .store(new_backing_identity(), Ordering::Relaxed);
    }
    pub(super) fn resident_bytes(&self) -> usize {
        self.local.used.load(Ordering::Relaxed) + self.native_resident()
    }
    pub(super) fn record_peak(&self, bytes: usize) -> usize {
        let peak = self.peak.load(Ordering::Relaxed);
        if bytes > peak {
            self.peak.fetch_max(bytes, Ordering::Relaxed).max(bytes)
        } else {
            peak
        }
    }
    pub(super) fn peak_bytes(&self) -> usize {
        self.record_peak(self.resident_bytes())
    }
    pub(super) fn native_allowed(&self) -> bool {
        !CgroupMemoryTarget::active()
            && self.local.limit.load(Ordering::Relaxed) >= ADDRESS_LIMIT as usize
            && self
                .total
                .as_ref()
                .is_none_or(|b| b.limit.load(Ordering::Relaxed) >= ADDRESS_LIMIT as usize)
    }
    pub(super) fn register_native(&self, range: &Arc<dyn crate::HardwareRange>) {
        let mut native = self.native.get_or_init(Default::default).lock().unwrap();
        native.insert(
            Arc::as_ptr(range) as *const () as usize,
            Arc::downgrade(range),
        );
    }
    fn has_native(&self) -> bool {
        self.native.get().is_some_and(|ranges| {
            ranges
                .lock()
                .unwrap()
                .values()
                .any(|r| r.strong_count() != 0)
        })
    }
    fn native_resident(&self) -> usize {
        let Some(native) = self.native.get() else {
            return 0;
        };
        let ranges: Vec<_> = {
            let mut ranges = native.lock().unwrap();
            ranges.retain(|_, r| r.strong_count() != 0);
            ranges
                .values()
                .filter_map(std::sync::Weak::upgrade)
                .collect()
        };
        ranges.iter().map(|r| r.resident_bytes()).sum()
    }
    fn available(&self) -> usize {
        let local = self
            .local
            .limit
            .load(Ordering::Relaxed)
            .saturating_sub(self.local.used.load(Ordering::Relaxed));
        self.total.as_ref().map_or(local, |total| {
            local.min(
                total
                    .limit
                    .load(Ordering::Relaxed)
                    .saturating_sub(total.used.load(Ordering::Relaxed)),
            )
        })
    }

    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            peak: AtomicUsize::new(0),
            local: Budget::new(limit),
            total: None,
            native: Default::default(),
            cow_epoch: AtomicU64::new(0),
        })
    }
    fn fork(&self) -> Arc<Self> {
        Arc::new(Self {
            peak: AtomicUsize::new(0),
            local: Budget::new(self.local.limit.load(Ordering::Relaxed)),
            total: self.total.clone(),
            native: Default::default(),
            cow_epoch: AtomicU64::new(0),
        })
    }
    fn take(&self, bytes: usize) -> Result<(), MemoryError> {
        self.local.take(bytes)?;
        if let Some(total) = &self.total {
            if let Err(error) = total.take(bytes) {
                self.local.used.fetch_sub(bytes, Ordering::Relaxed);
                return Err(error);
            }
        }
        Ok(())
    }
    fn release(&self, bytes: usize) {
        // The count immediately before a release captures the charged high-water
        // mark without changing first-touch or already-resident guest accesses.
        let before = self.local.used.fetch_sub(bytes, Ordering::Relaxed);
        self.record_peak(before);
        if let Some(total) = &self.total {
            total.used.fetch_sub(bytes, Ordering::Relaxed);
        }
    }
}
pub(super) struct Charge {
    account: Arc<Account>,
    // 0 = untouched, 2 = resident, 3 = native extent, 5 = resident private
    // mapping of the original cache page, 6 = fork-shared private page.
    // The last two states need COW admission on first write.
    // Cold transitions use the original page's object mutex. Ordinary accesses
    // consult only relaxed residency bits and the existing byte/region guards.
    state: AtomicU8,
    ownership: parking_lot::Mutex<Ownership>,
}
#[derive(Clone, Default)]
struct Ownership {
    physical: Option<Arc<crate::cgroup_memory::PhysicalCharge>>,
    cache: Option<(Arc<crate::cgroup_memory::SharedCharge>, bool)>,
}
impl Charge {
    pub(super) fn new(account: &Arc<Account>) -> Arc<Self> {
        Arc::new(Self {
            account: account.clone(),
            state: AtomicU8::new(0),
            ownership: Default::default(),
        })
    }
    /// A fresh fork charge has no concurrent consumers until task publication.
    /// Reserve against the actual shared budgets, then publish its final state;
    /// the first-touch state machine is only needed by already shared charges.
    pub(super) fn fork(
        account: &Arc<Account>,
        old: &Self,
        private: bool,
    ) -> Result<Arc<Self>, MemoryError> {
        let mut owner = old.ownership.lock();
        let state = old.state.load(Ordering::Relaxed);
        let resident = old.resident();
        if resident {
            account.take(PAGE_SIZE as usize)?;
        }
        let cow = private && matches!(state, 2 | 6) && owner.cache.is_none();
        if cow && owner.physical.is_none() {
            owner.physical = Some(crate::cgroup_memory::PhysicalCharge::root());
        }
        Ok(Arc::new(Self {
            account: account.clone(),
            state: AtomicU8::new(if cow {
                6
            } else if state == 5 {
                5
            } else if resident {
                2
            } else {
                0
            }),
            ownership: parking_lot::Mutex::new(owner.clone()),
        }))
    }
    pub(super) fn fork_pending(&self) -> bool {
        self.state.load(Ordering::Relaxed) == 6
    }
    /// Called only after all child RSS admissions and fork policies succeeded.
    pub(super) fn commit_fork(&self) {
        let owner = self.ownership.lock();
        if owner.cache.is_none()
            && owner.physical.is_some()
            && self.state.load(Ordering::Relaxed) == 2
        {
            self.state.store(6, Ordering::Relaxed);
        }
    }
    pub(super) fn native(account: &Arc<Account>) -> Arc<Self> {
        Arc::new(Self {
            account: account.clone(),
            state: AtomicU8::new(3),
            ownership: Default::default(),
        })
    }
    pub(super) fn promote_native(&self) -> Result<(), MemoryError> {
        if self.state.load(Ordering::Relaxed) != 3 {
            return self.ensure();
        }
        let mut owner = self.ownership.lock();
        if self.state.load(Ordering::Relaxed) == 3 {
            self.take(&mut owner, false)?;
        }
        Ok(())
    }
    pub(super) fn page_resident(&self, bytes: Option<&SharedPage>) -> Result<u8, MemoryError> {
        match self.state.load(Ordering::Relaxed) {
            3 => bytes.map_or(Ok(1), SharedPage::native_page_resident),
            2 | 5 | 6 => Ok(1),
            _ => Ok(0),
        }
    }
    pub(super) fn resident(&self) -> bool {
        // Only quota membership: bytes are initialized before view publication
        // and shared CPU/native accesses use their own region/ARM ordering.
        // Do not turn accounting into a second acquire on ordinary accesses.
        matches!(self.state.load(Ordering::Relaxed), 2 | 3 | 5 | 6)
    }
    pub(super) fn write_ready(&self) -> bool {
        matches!(self.state.load(Ordering::Relaxed), 2 | 3)
    }
    pub(super) fn attach_cache(
        &self,
        cache: Arc<crate::cgroup_memory::SharedCharge>,
        private: bool,
    ) {
        let mut owner = self.ownership.lock();
        if self.resident() {
            owner.physical = cache.existing();
        }
        owner.cache = Some((cache, private));
        if private && self.state.load(Ordering::Relaxed) == 2 {
            self.state.store(5, Ordering::Relaxed);
        }
    }
    /// Replacing an RSS budget is not a physical page allocation or cgroup
    /// migration. Preserve the original page/cache lease through that rebinding.
    fn reaccount(account: &Arc<Account>, old: &Self) -> Result<Arc<Self>, MemoryError> {
        let owner = old.ownership.lock();
        let state = old.state.load(Ordering::Relaxed);
        if old.resident() {
            account.take(PAGE_SIZE as usize)?;
        }
        Ok(Arc::new(Self {
            account: account.clone(),
            state: AtomicU8::new(if state == 3 { 2 } else { state }),
            ownership: parking_lot::Mutex::new(owner.clone()),
        }))
    }
    /// Cold I/O preflight only. The final atomic ensure remains authoritative;
    /// a peer already reserving this same page must not get a false quota error.
    pub(super) fn check_available(&self) -> Result<(), MemoryError> {
        if self.state.load(Ordering::Relaxed) != 0
            || self.account.available() >= PAGE_SIZE as usize
            || self.state.load(Ordering::Relaxed) != 0
        {
            Ok(())
        } else {
            Err(MemoryError::Limit)
        }
    }
    fn take(&self, owner: &mut Ownership, write: bool) -> Result<(), MemoryError> {
        self.account.take(PAGE_SIZE as usize)?;
        let private = owner.cache.as_ref().is_some_and(|(_, private)| *private);
        let physical = if private && write {
            // A private file fault first reaches the original cache page, then
            // creates its own page. Use the same leases for direct software,
            // native and worker/hardware paths, including a first-access write.
            owner
                .cache
                .as_ref()
                .unwrap()
                .0
                .get()
                .and_then(|_| crate::cgroup_memory::PhysicalCharge::new())
        } else if let Some((cache, _)) = &owner.cache {
            cache.get()
        } else {
            crate::cgroup_memory::PhysicalCharge::new()
        };
        match physical {
            Ok(charge) => {
                owner.physical = charge;
                if private && write {
                    owner.cache = None;
                }
                self.state
                    .store(if private && !write { 5 } else { 2 }, Ordering::Relaxed);
                Ok(())
            }
            Err(error) => {
                self.account.release(PAGE_SIZE as usize);
                Err(error)
            }
        }
    }
    pub(super) fn ensure(&self) -> Result<(), MemoryError> {
        if self.resident() {
            return Ok(());
        }
        let mut owner = self.ownership.lock();
        if self.resident() {
            return Ok(());
        }
        self.take(&mut owner, false)
    }
    pub(super) fn ensure_write(&self) -> Result<(), MemoryError> {
        if self.write_ready() {
            return Ok(());
        }
        let mut owner = self.ownership.lock();
        if self.write_ready() {
            return Ok(());
        }
        if self.state.load(Ordering::Relaxed) == 6 {
            // An exclusive surviving page keeps its original ownership after
            // task migration. Only an actual COW takes the writer's quota.
            if owner
                .physical
                .as_ref()
                .is_some_and(|page| Arc::strong_count(page) > 1)
            {
                owner.physical = crate::cgroup_memory::PhysicalCharge::new()?;
            }
            self.state.store(2, Ordering::Relaxed);
            Ok(())
        } else if self.state.load(Ordering::Relaxed) == 5 {
            // The original file/shmem cache page keeps its first owner. COW
            // allocates one new private physical lease against the actual writer.
            let physical = crate::cgroup_memory::PhysicalCharge::new()?;
            owner.physical = physical;
            owner.cache = None;
            self.state.store(2, Ordering::Relaxed);
            Ok(())
        } else {
            self.take(&mut owner, true)
        }
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        if matches!(self.state.load(Ordering::Relaxed), 2 | 5 | 6) {
            self.account.release(PAGE_SIZE as usize);
        }
    }
}
impl Memory {
    /// Preflight before VFS creates file/shared-page storage. A fixed mapping
    /// can reuse already charged destination slots; no byte owner changes here.
    pub fn check_backed_mapping(
        &self,
        address: u64,
        len: u64,
        fixed: bool,
    ) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow().check_backed_mapping(address, len, fixed);
        }
        let end = Self::mapping_end(address, len)?;
        let reused = if fixed {
            self.pages.range(address..end).count() * PAGE_SIZE as usize
        } else {
            0
        };
        if (self.pages.len() * PAGE_SIZE as usize - reused)
            .checked_add(len as usize)
            .is_none_or(|bytes| bytes > MAX_DESCRIBED_BYTES)
        {
            return Err(MemoryError::Limit);
        }
        // No resident charge until this mapping actually supplies CPU/native bytes.
        Ok(())
    }
    /// Anonymous zero mappings are not resident until their first write. File
    /// mappings are charged on access; fork still charges each VM.
    pub fn resident_bytes(&self) -> usize {
        if let Some(shared) = &self.shared {
            return shared.borrow().resident_bytes();
        }
        self.account.resident_bytes()
    }
    pub fn peak_resident_bytes(&self) -> usize {
        if let Some(shared) = &self.shared {
            return shared.borrow().peak_resident_bytes();
        }
        self.account.peak_bytes()
    }
    /// Bind a fresh runtime to one aggregate guest budget before workers start.
    pub fn set_total_limit(&mut self, limit: usize) -> Result<(), MemoryError> {
        self.bind_account(Arc::new(Account {
            peak: AtomicUsize::new(0),
            local: Budget::new(self.limit),
            total: Some(Budget::new(limit)),
            native: Default::default(),
            cow_epoch: AtomicU64::new(0),
        }))
    }
    /// An exec address space joins the old VM's aggregate accounting domain.
    pub fn inherit_total_limit(&mut self, old: &Memory) -> Result<(), MemoryError> {
        if let Some(shared) = &old.shared {
            return self.inherit_total_limit(&shared.borrow());
        }
        self.bind_account(Arc::new(Account {
            peak: AtomicUsize::new(0),
            local: Budget::new(self.limit),
            total: old.account.total.clone(),
            native: Default::default(),
            cow_epoch: AtomicU64::new(0),
        }))
    }
    fn bind_account(&mut self, account: Arc<Account>) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().bind_account(account);
        }
        let previous_peak = self.account.peak_bytes();
        self.adopt_anonymous();
        self.parallel_cache = None;
        let mut charges = Vec::new();
        for page in self.frames.iter().flatten() {
            let charge = Charge::reaccount(&account, &page.charge)?;
            charges.push(charge);
        }
        for (page, charge) in self.frames.iter_mut().flatten().zip(charges) {
            if let Some(b) = &page.backing {
                b.detach(&page.charge);
            }
            page.charge = charge;
            page.register_backing();
        }
        self.anonymous = self.anonymous.fork(&account);
        self.sparse_pages.get_mut().clear();
        self.invalidate_translations();
        account.record_peak(previous_peak);
        self.account = account;
        Ok(())
    }
    pub(super) fn replace_native_account(&mut self, limit: usize) -> Result<bool, MemoryError> {
        if !self.account.has_native() {
            return Ok(false);
        }
        if self.has_parallel_users() {
            return Err(MemoryError::InvalidRange);
        }
        self.bind_account(Arc::new(Account {
            peak: AtomicUsize::new(0),
            local: Budget::new(limit),
            total: self.account.total.clone(),
            native: Default::default(),
            cow_epoch: AtomicU64::new(0),
        }))?;
        Ok(true)
    }
    pub(super) fn update_resident_limit(&self, limit: usize) {
        self.account.local.limit.store(limit, Ordering::Relaxed);
    }
    pub(super) fn fork_account(&self) -> Arc<Account> {
        self.account.fork()
    }
    /// Advisory quota query only. Independent mms can allocate after this
    /// check; guest task creation must use try_fork's fallible accounting.
    pub fn can_fork(&self) -> bool {
        if let Some(shared) = &self.shared {
            return shared.borrow().can_fork();
        }
        self.account.total.as_ref().is_none_or(|total| {
            total
                .used
                .load(Ordering::Relaxed)
                .checked_add(self.resident_bytes())
                .is_some_and(|used| used <= total.limit.load(Ordering::Relaxed))
        })
    }
    pub(super) fn materialize_zero(
        &mut self,
        address: u64,
        len: usize,
    ) -> Result<bool, MemoryError> {
        if len <= (PAGE_SIZE - address % PAGE_SIZE) as usize {
            // The CPU/native caller has already reached this page. Reuse its
            // TLB entry; ordinary page-sized operations need no BTree walk.
            let base = address & !(PAGE_SIZE - 1);
            let frame = self.frame(base).expect("validated write page");
            let page = self.frames[frame].as_ref().expect("mapped page");
            if page.backing.is_some() {
                page.check_backing(address)?;
                page.prepare_source(address)?;
                page.charge.ensure_write()?;
                return Ok(false);
            }
            page.charge.ensure_write()?;
            if !page.bytes.is_zero() {
                return Ok(false);
            }
            let bytes = self
                .mmu
                .page(base)
                .unwrap_or_else(|| Arc::new(PageBytes::new([0; PAGE_SIZE as usize])));
            self.frames[frame].as_mut().expect("mapped page").bytes = bytes;
            return Ok(true);
        }
        let end = address + len as u64;
        // Reserve all reached pages before changing bytes, including native and
        // cross-page writes. Quota failure leaves guest data unchanged.
        for (&base, &frame) in self.pages.range(address & !(PAGE_SIZE - 1)..end) {
            let page = self.frames[frame].as_ref().expect("mapped page");
            page.check_backing(base.max(address))?;
            page.prepare_source(base.max(address))?;
            page.charge.ensure_write()?;
        }
        let mut changed = false;
        for (&base, &frame) in self.pages.range(address & !(PAGE_SIZE - 1)..end) {
            let page = self.frames[frame].as_mut().expect("mapped page");
            if page.backing.is_none() && page.bytes.is_zero() {
                page.bytes = self
                    .mmu
                    .page(base)
                    .unwrap_or_else(|| Arc::new(PageBytes::new([0; PAGE_SIZE as usize])));
                changed = true;
            }
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parallel::Registry, CpuMemory};
    const P: usize = PAGE_SIZE as usize;
    #[test]
    fn zero_mapping_native_write_discard_remap_and_quota_follow_reached_pages() {
        let mut m = Memory::new(16 << 20);
        m.set_total_limit(2 * P).unwrap();
        m.map(0x10000, 8 << 20, Permissions::RW).unwrap();
        assert_eq!(m.resident_bytes(), 0);
        assert_eq!(m.read_u64(0x10000), Ok(0));
        assert_eq!(m.read_u64(0x80fff8), Ok(0));
        assert_eq!(m.resident_bytes(), 0);
        m.with_write_chunk(0x10000, 8, |bytes| bytes.fill(17))
            .unwrap();
        m.write_array(0x11000, [42u8]).unwrap();
        assert_eq!(m.resident_bytes(), 2 * P);
        assert_eq!(m.check_backed_mapping(0x12000, PAGE_SIZE, false), Ok(()));
        assert_eq!(m.check_backed_mapping(0x10000, PAGE_SIZE, true), Ok(()));
        assert_eq!(m.write_array(0x12000, [99u8]), Err(MemoryError::Limit));
        assert_eq!(m.read_array::<1>(0x12000), Ok([0]));
        m.discard(0x10000, PAGE_SIZE).unwrap();
        assert_eq!(m.resident_bytes(), P);
        assert_eq!(m.read_u64(0x10000), Ok(0));
        m.write_array(0x12000, [99u8]).unwrap();
        m.remap(0x10000, 3 * PAGE_SIZE, 0x1000000, 3 * PAGE_SIZE, false)
            .unwrap();
        assert_eq!(m.resident_bytes(), 2 * P);
        assert_eq!(m.read_array::<1>(0x1002000), Ok([99]));
        m.unmap(0x1000000, 3 * PAGE_SIZE).unwrap();
        assert_eq!(m.resident_bytes(), 0);
    }
    #[test]
    fn fork_charges_written_pages_and_zero_cow_is_independent() {
        let mut parent = Memory::new(8 * P);
        parent.set_total_limit(2 * P).unwrap();
        parent.map(0x10000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
        parent.write_array(0x10000, [17u8]).unwrap();
        assert!(parent.can_fork());
        let mut child = parent.clone();
        assert!(!parent.can_fork());
        assert_eq!(child.resident_bytes(), P);
        assert_eq!(child.write_array(0x11000, [42u8]), Err(MemoryError::Limit));
        parent.discard(0x10000, PAGE_SIZE).unwrap();
        child.write_array(0x11000, [42u8]).unwrap();
        assert_eq!(parent.read_array::<1>(0x10000), Ok([0]));
        assert_eq!(child.read_array::<1>(0x10000), Ok([17]));
        assert_eq!(parent.read_array::<1>(0x11000), Ok([0]));
        assert_eq!(child.read_array::<1>(0x11000), Ok([42]));
        drop(child);
        parent.write_array(0x10000, [99u8]).unwrap();
    }
    #[test]
    fn fork_of_read_only_sparse_zeros_does_not_consume_the_resident_budget() {
        for retained in [false, true] {
            let mut parent = Memory::new(4 * P);
            parent.set_total_limit(P).unwrap();
            parent.map(0x10000, 1024 * 1024, Permissions::RW).unwrap();
            let mut registry = Registry::default();
            let view = parent.parallel_view(&mut registry).unwrap();
            for address in [0x10000, 0x90000] {
                assert_eq!(view.read_array::<8>(address), Ok([0; 8]));
            }
            let held = if retained {
                Some(view)
            } else {
                drop(view);
                None
            };
            assert_eq!(parent.resident_bytes(), 0);
            let mut child = parent.try_fork().unwrap();
            assert_eq!(child.resident_bytes(), 0);
            assert_eq!(
                parent
                    .account
                    .total
                    .as_ref()
                    .unwrap()
                    .used
                    .load(Ordering::Relaxed),
                0
            );
            child.write_array(0x10000, [41u8]).unwrap();
            assert_eq!(parent.read_array::<1>(0x10000), Ok([0]));
            assert_eq!(parent.write_array(0x10000, [43u8]), Err(MemoryError::Limit));
            drop(child);
            drop(held);
            parent.write_array(0x10000, [43u8]).unwrap();
            assert_eq!(parent.resident_bytes(), P);
        }
    }
    #[test]
    fn fork_quota_race_rolls_back_child_charges_and_preserves_parent_custody() {
        for sparse in [false, true] {
            for retained in [false, true] {
                let mut parent = Memory::new(8 * P);
                parent.set_total_limit(6 * P).unwrap();
                parent
                    .map(
                        0x10000,
                        if sparse { 32 } else { 4 } * PAGE_SIZE,
                        Permissions::RW,
                    )
                    .unwrap();
                let mut registry = Registry::default();
                if sparse {
                    let mut view = parent.parallel_view(&mut registry).unwrap();
                    view.write_array(0x10000, [17u8]).unwrap();
                    view.write_array(0x11000, [23u8]).unwrap();
                    drop(view);
                    parent.commit_parallel().unwrap();
                    assert!(parent.pages.is_empty(), "exercise sparse fork charging");
                } else {
                    parent.write_array(0x10000, [17u8]).unwrap();
                    parent.write_array(0x11000, [23u8]).unwrap();
                }
                let held = retained.then(|| parent.parallel_view(&mut registry).unwrap());
                let mut peer = parent.try_fork().unwrap();
                assert!(parent.can_fork());
                let mut worker = peer.parallel_view(&mut registry).unwrap();
                // Deterministically place another mm's first touch between
                // the formerly authoritative admission check and the fork.
                let mut worker = std::thread::spawn(move || {
                    worker.write_array(0x12000, [29u8]).unwrap();
                    worker
                })
                .join()
                .unwrap();
                let epoch = parent.fork_epoch.get();
                let identity = parent.instruction_identity();
                let total = parent.account.total.as_ref().unwrap();
                assert_eq!(total.used.load(Ordering::Relaxed), 5 * P);
                assert!(matches!(parent.try_fork(), Err(MemoryError::Limit)));
                assert_eq!(total.used.load(Ordering::Relaxed), 5 * P);
                assert_eq!(parent.fork_epoch.get(), epoch);
                assert_eq!(parent.instruction_identity(), identity);
                assert_eq!(parent.read_array::<1>(0x10000), Ok([17]));
                assert_eq!(parent.read_array::<1>(0x11000), Ok([23]));
                // The failed fork reserved one page before failing on its
                // second. This store can use it only if rollback released it.
                worker.write_array(0x13000, [31u8]).unwrap();
                assert_eq!(total.used.load(Ordering::Relaxed), 6 * P);
                drop(worker);
                drop(peer);
                assert_eq!(total.used.load(Ordering::Relaxed), 2 * P);
                let mut child = parent.try_fork().unwrap();
                child.write_array(0x10000, [41u8]).unwrap();
                assert_eq!(parent.read_array::<1>(0x10000), Ok([17]));
                assert_eq!(child.read_array::<1>(0x10000), Ok([41]));
                drop(child);
                drop(held);
                assert_eq!(total.used.load(Ordering::Relaxed), 2 * P);
            }
        }
    }
    #[test]
    fn concurrent_first_stores_share_charges_and_enforce_the_total_before_effects() {
        let mut m = Memory::new(8 * P);
        m.set_total_limit(2 * P).unwrap();
        m.map(0x10000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
        let mut registry = Registry::default();
        let view = m.parallel_view(&mut registry).unwrap();
        assert_eq!(
            m.resident_bytes(),
            0,
            "freezing zero pages does not commit guest bytes"
        );
        std::thread::scope(|scope| {
            for n in 0..8u64 {
                let mut worker = view.clone();
                scope.spawn(move || {
                    for i in 0..2u64 {
                        worker
                            .write_array(0x10000 + i * PAGE_SIZE + n * 64, [n as u8 + 1])
                            .unwrap();
                    }
                });
            }
        });
        assert_eq!(
            m.resident_bytes(),
            2 * P,
            "worker stores count before coordinator commit"
        );
        let mut worker = view.clone();
        assert_eq!(worker.write_array(0x12000, [99u8]), Err(MemoryError::Limit));
        assert_eq!(worker.read_array::<1>(0x12000), Ok([0]));
        drop(worker);
        drop(view);
        m.commit_parallel().unwrap();
        assert_eq!(m.resident_bytes(), 2 * P, "commit does not charge twice");
        for n in 0..8u64 {
            assert_eq!(m.read_array::<1>(0x11000 + n * 64), Ok([n as u8 + 1]));
        }
        m.unmap(0x10000, 4 * PAGE_SIZE).unwrap();
        drop(m.parallel_view(&mut registry).unwrap());
        assert_eq!(m.resident_bytes(), 0);
    }
    #[test]
    fn native_worker_and_independent_vm_compete_for_the_same_total() {
        use crate::NativeMemory;
        let mut parent = Memory::new(4 * P);
        parent.set_total_limit(P).unwrap();
        parent.map(0x10000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        let mut child = parent.clone();
        let mut registry = Registry::default();
        let mut a = parent.parallel_view(&mut registry).unwrap();
        let mut b = child.parallel_view(&mut registry).unwrap();
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|s| {
            let t = s.spawn(|| {
                barrier.wait();
                a.fill_with(0x10000, 8, |out| out.fill(17))
            });
            barrier.wait();
            let other = b.write_array(0x10000, [42u8]);
            (t.join().unwrap().is_ok(), other.is_ok())
        });
        assert_ne!(
            results.0, results.1,
            "exactly one VM can commit the only page"
        );
        assert_eq!(parent.resident_bytes() + child.resident_bytes(), P);
    }
}

#[cfg(test)]
mod overcommit_tests {
    use super::*;
    #[test]
    fn untouched_accessible_mappings_and_protection_do_not_spend_ram_quota() {
        let mut memory = Memory::new(2 * PAGE_SIZE as usize);
        memory
            .map(0x10000, 256 * PAGE_SIZE, Permissions::RW)
            .unwrap();
        memory
            .map(0x200000, 256 * PAGE_SIZE, Permissions::NONE)
            .unwrap();
        memory
            .protect(0x200000, 256 * PAGE_SIZE, Permissions::RW)
            .unwrap();
        assert_eq!(memory.resident_bytes(), 0);
        assert_eq!(memory.read_u64(0x10000).unwrap(), 0);
        assert_eq!(memory.read_u64(0x2ff000).unwrap(), 0);
        assert_eq!(memory.resident_bytes(), 0);
        memory.set_limit(PAGE_SIZE as usize).unwrap();
        memory.write_array(0x10000, [17]).unwrap();
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(memory.write_array(0x200000, [19]), Err(MemoryError::Limit));
        memory.unmap(0x10000, PAGE_SIZE).unwrap();
        memory.write_array(0x200000, [19]).unwrap();
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
    }
}
