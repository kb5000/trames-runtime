// SPDX-License-Identifier: GPL-3.0-or-later
//! First-write accounting for anonymous zero pages. Charges are shared with
//! worker frames, so concurrent first stores cannot bypass the guest budget.
use super::*;
use std::sync::{
    atomic::{AtomicU8, AtomicUsize},
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
pub(super) struct Account {
    local: Arc<Budget>,
    total: Option<Arc<Budget>>,
}
impl Account {
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
            local: Budget::new(limit),
            total: None,
        })
    }
    fn fork(&self) -> Arc<Self> {
        Arc::new(Self {
            local: Budget::new(self.local.limit.load(Ordering::Relaxed)),
            total: self.total.clone(),
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
        self.local.used.fetch_sub(bytes, Ordering::Relaxed);
        if let Some(total) = &self.total {
            total.used.fetch_sub(bytes, Ordering::Relaxed);
        }
    }
}
pub(super) struct Charge {
    account: Arc<Account>,
    // 0 = untouched, 1 = first writer reserving, 2 = charged. Region guards
    // may be disjoint; this state serializes only the page's first allocation.
    state: AtomicU8,
}
impl Charge {
    pub(super) fn new(account: &Arc<Account>) -> Arc<Self> {
        Arc::new(Self {
            account: account.clone(),
            state: AtomicU8::new(0),
        })
    }
    pub(super) fn resident(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2
    }
    pub(super) fn ensure(&self) -> Result<(), MemoryError> {
        if self.resident() {
            return Ok(());
        }
        loop {
            match self
                .state
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire)
            {
                Ok(_) => {
                    let result = self.account.take(PAGE_SIZE as usize);
                    self.state
                        .store(if result.is_ok() { 2 } else { 0 }, Ordering::Release);
                    return result;
                }
                Err(2) => return Ok(()),
                Err(_) => std::hint::spin_loop(),
            }
        }
    }
}
impl Drop for Charge {
    fn drop(&mut self) {
        if self.resident() {
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
            self.pages
                .range(address..end)
                .filter(|(_, frame)| self.frames[**frame].as_ref().unwrap().charge.resident())
                .count() as u64
                * PAGE_SIZE
        } else {
            0
        };
        if len - reused > self.account.available() as u64 {
            Err(MemoryError::Limit)
        } else {
            Ok(())
        }
    }
    /// Anonymous zero mappings are not resident until their first write. File
    /// mappings remain conservatively charged; fork still charges each VM.
    pub fn resident_bytes(&self) -> usize {
        if let Some(shared) = &self.shared {
            return shared.borrow().resident_bytes();
        }
        self.account.local.used.load(Ordering::Relaxed)
    }
    /// Bind a fresh runtime to one aggregate guest budget before workers start.
    pub fn set_total_limit(&mut self, limit: usize) -> Result<(), MemoryError> {
        self.bind_account(Arc::new(Account {
            local: Budget::new(self.limit),
            total: Some(Budget::new(limit)),
        }))
    }
    /// An exec address space joins the old VM's aggregate accounting domain.
    pub fn inherit_total_limit(&mut self, old: &Memory) -> Result<(), MemoryError> {
        if let Some(shared) = &old.shared {
            return self.inherit_total_limit(&shared.borrow());
        }
        self.bind_account(Arc::new(Account {
            local: Budget::new(self.limit),
            total: old.account.total.clone(),
        }))
    }
    fn bind_account(&mut self, account: Arc<Account>) -> Result<(), MemoryError> {
        if let Some(shared) = &self.shared {
            return shared.borrow_mut().bind_account(account);
        }
        self.parallel_cache = None;
        let mut charges = Vec::new();
        for page in self.frames.iter().flatten() {
            let charge = Charge::new(&account);
            if page.charge.resident() {
                charge.ensure()?;
            }
            charges.push(charge);
        }
        for (page, charge) in self.frames.iter_mut().flatten().zip(charges) {
            page.charge = charge;
        }
        self.account = account;
        Ok(())
    }
    pub(super) fn update_resident_limit(&self, limit: usize) {
        self.account.local.limit.store(limit, Ordering::Relaxed);
    }
    pub(super) fn fork_account(&self) -> Arc<Account> {
        self.account.fork()
    }
    /// Check quotas before cloning. Clone is non-fallible, so Kernel performs
    /// this admission while all workers are joined, immediately before fork.
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
            page.charge.ensure()?;
            if page.backing.is_some() || !page.bytes.is_zero() {
                return Ok(false);
            }
            let bytes = self
                .mmu
                .page(base)
                .unwrap_or_else(|| Rc::new(PageBytes::new([0; PAGE_SIZE as usize])));
            self.frames[frame].as_mut().expect("mapped page").bytes = bytes;
            return Ok(true);
        }
        let end = address + len as u64;
        // Reserve all reached pages before changing bytes, including native and
        // cross-page writes. Quota failure leaves guest data unchanged.
        for (_, &frame) in self.pages.range(address & !(PAGE_SIZE - 1)..end) {
            self.frames[frame]
                .as_ref()
                .expect("mapped page")
                .charge
                .ensure()?;
        }
        let mut changed = false;
        for (&base, &frame) in self.pages.range(address & !(PAGE_SIZE - 1)..end) {
            let page = self.frames[frame].as_mut().expect("mapped page");
            if page.backing.is_none() && page.bytes.is_zero() {
                page.bytes = self
                    .mmu
                    .page(base)
                    .unwrap_or_else(|| Rc::new(PageBytes::new([0; PAGE_SIZE as usize])));
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
        assert_eq!(
            m.check_backed_mapping(0x12000, PAGE_SIZE, false),
            Err(MemoryError::Limit)
        );
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
