// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest shmem ownership follows SharedFile's original resource, including
//! native mappings and transferred FDs. No resource/accounting thread exists.
use crate::Result;
use std::{
    collections::BTreeMap,
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Arc, Mutex,
    },
};
use trames_memory::{
    CgroupMemoryContext, CgroupMemoryKind, CgroupPageCharge, CgroupReservation, MappedResidents,
    PAGE_SIZE,
};
use trames_shared::{SharedFile, SharedFileAccess, SharedFileAccounting, SharedFileCharge};
struct Context(CgroupMemoryContext);
impl trames_shared::SharedFileContext for Context {
    fn enter(&self) -> Box<dyn std::any::Any> {
        match self.0.enter_if_absent() {
            Some(scope) => Box::new(scope),
            None => Box::new(()),
        }
    }
}

pub(super) struct Page {
    pub owners: Arc<MappedResidents>,
    pub dirty: Arc<AtomicBool>,
    pub generation: Arc<AtomicU64>,
    bytes: Mutex<(u64, std::sync::Weak<trames_memory::SharedPage>)>,
    observers: Mutex<Vec<std::sync::Weak<crate::mapped::MappingState>>>,
}
impl Default for Page {
    fn default() -> Self {
        Self {
            owners: Arc::new(MappedResidents::with_kind(CgroupMemoryKind::Shmem)),
            dirty: Arc::default(),
            generation: Arc::default(),
            bytes: Mutex::default(),
            observers: Mutex::default(),
        }
    }
}
impl Page {
    pub fn observe(&self, state: &Arc<crate::mapped::MappingState>) {
        let mut observers = self.observers.lock().unwrap();
        observers.retain(|observer| observer.strong_count() != 0);
        let state = Arc::downgrade(state);
        if !observers.iter().any(|observer| observer.ptr_eq(&state)) {
            observers.push(state);
        }
    }
    fn changed(&self) {
        let observers: Vec<_> = self
            .observers
            .lock()
            .unwrap()
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        for observer in observers {
            observer.changed(None);
        }
    }
    pub fn load(&self, file: &SharedFile, offset: u64) -> Result<Arc<trames_memory::SharedPage>> {
        let mut cached = self.bytes.lock().unwrap();
        let generation = self.generation.load(Relaxed);
        if cached.0 == generation {
            if let Some(bytes) = cached.1.upgrade() {
                return Ok(bytes);
            }
        }
        let mapping = file
            .map(offset as usize, PAGE_SIZE as usize)
            .map_err(crate::storage::host_errno)?;
        // SAFETY: original SharedFile geometry and lifetime are retained in the
        // mapping; CPU aliases all reuse this resource's weak canonical page.
        let bytes =
            unsafe { trames_memory::SharedMapping::from_shared_file(mapping) }.shared_page();
        self.owners.bind_cache(&bytes);
        self.owners
            .publish_cache(&bytes)
            .map_err(|_| crate::Errno(12))?;
        *cached = (generation, Arc::downgrade(&bytes));
        Ok(bytes)
    }
}
struct Extent {
    allocation: CgroupReservation,
}
struct Allocation {
    end: u64,
    resource: Arc<Extent>,
}
#[derive(Default)]
struct State {
    allocated: BTreeMap<u64, Allocation>,
    pages: BTreeMap<u64, Arc<Page>>,
}
#[derive(Default)]
struct Inner {
    state: Mutex<State>,
}
#[derive(Default)]
pub(super) struct Account {
    inner: Arc<Inner>,
}
struct Loan {
    inner: Arc<Inner>,
    inserted: Vec<(u64, Arc<Extent>)>,
    pins: Vec<(u64, CgroupPageCharge)>,
    offset: usize,
    length: usize,
    access: SharedFileAccess,
    committed: bool,
}
impl Account {
    pub fn cell(&self, offset: u64) -> Arc<Page> {
        let index = offset / PAGE_SIZE;
        let mut state = self.inner.state.lock().unwrap();
        // A metadata lookup does not admit memory. Actual SharedFile map/write
        // transactions install the slice before bytes can be published.
        if let Some(cell) = state.pages.get(&index) {
            return cell.clone();
        }
        let cell = Arc::new(Page::default());
        if let Some((&base, allocation)) = state.allocated.range(..=index).next_back() {
            if index < allocation.end {
                cell.owners.adopt_cache(
                    &allocation
                        .resource
                        .allocation
                        .page((index - base) as usize)
                        .expect("existing shmem slice"),
                );
            }
        }
        state.pages.insert(index, cell.clone());
        cell
    }
    pub fn has_allocated_after(&self, length: u64) -> bool {
        self.inner
            .state
            .lock()
            .unwrap()
            .allocated
            .last_key_value()
            .is_some_and(|(_, allocation)| allocation.end > length.div_ceil(PAGE_SIZE))
    }
    fn prepare(&self, offset: usize, length: usize, access: SharedFileAccess) -> io::Result<Loan> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let first = offset as u64 / PAGE_SIZE;
        let last = (end as u64).div_ceil(PAGE_SIZE);
        let mut state = self.inner.state.lock().unwrap();
        let mut cursor = first;
        if let Some((_, allocation)) = state.allocated.range(..=first).next_back() {
            cursor = cursor.max(allocation.end.min(last));
        }
        let mut gaps = Vec::new();
        for (&begin, allocation) in state.allocated.range(first..last) {
            if begin > cursor {
                gaps.push(cursor..begin);
            }
            cursor = cursor.max(allocation.end.min(last));
        }
        if cursor < last {
            gaps.push(cursor..last);
        }
        let mut proposed = Vec::with_capacity(gaps.len());
        for gap in gaps {
            let allocation =
                CgroupReservation::new((gap.end - gap.start) as usize, CgroupMemoryKind::Shmem)
                    .map_err(|error| match error {
                        trames_memory::MemoryError::Pending(fault) => {
                            trames_shared::ResourcePending::io_error(fault.wait)
                        }
                        trames_memory::MemoryError::BackingIo(code) => {
                            io::Error::from_raw_os_error(code as i32)
                        }
                        _ => io::Error::from(io::ErrorKind::OutOfMemory),
                    })?;
            proposed.push((gap, Arc::new(Extent { allocation })));
        }
        let mut inserted = Vec::with_capacity(proposed.len());
        for (gap, resource) in proposed {
            state.allocated.insert(
                gap.start,
                Allocation {
                    end: gap.end,
                    resource: resource.clone(),
                },
            );
            inserted.push((gap.start, resource));
        }
        let mut pins = Vec::new();
        // Map/IO pins inherit original allocation; merely preallocating a huge
        // zero extent never creates a per-page graph. Uncontrolled slices need
        // no per-page pin allocation either.
        let scan = state
            .allocated
            .range(..=first)
            .next_back()
            .map_or(first, |(&base, _)| base);
        for (&base, allocation) in state.allocated.range(scan..last) {
            let from = first.max(base);
            let to = last.min(allocation.end);
            if from >= to {
                continue;
            }
            if access != SharedFileAccess::Allocate && allocation.resource.allocation.controlled() {
                for index in from..to {
                    pins.push((
                        index,
                        allocation
                            .resource
                            .allocation
                            .page((index - base) as usize)
                            .expect("allocated shared IO slice"),
                    ));
                }
            }
            for (&index, cell) in state.pages.range(from..to) {
                // Cold source pages have not bound their bytes yet. Existing
                // cells already own their original physical lease.
                if inserted.iter().any(|(start, _)| *start == base) {
                    cell.owners.adopt_cache(
                        &allocation
                            .resource
                            .allocation
                            .page((index - base) as usize)
                            .expect("allocated shared mapping slice"),
                    );
                }
            }
        }
        Ok(Loan {
            inner: self.inner.clone(),
            inserted,
            pins,
            offset,
            length,
            access,
            committed: false,
        })
    }
}
impl SharedFileAccounting for Account {
    fn write_chunk(&self, offset: usize, length: usize) -> usize {
        let capacity = trames_memory::CgroupMemoryTarget::allocation_capacity();
        if capacity >= length.saturating_add(PAGE_SIZE as usize) {
            return length;
        }
        let first = offset as u64 / PAGE_SIZE;
        let last = ((offset + length) as u64).div_ceil(PAGE_SIZE);
        let mut pages = (capacity / PAGE_SIZE as usize) as u64;
        let state = self.inner.state.lock().unwrap();
        let scan = state
            .allocated
            .range(..=first)
            .next_back()
            .map_or(first, |(&base, _)| base);
        let mut cursor = first;
        let prefix = |end: u64| {
            let count = (end * PAGE_SIZE)
                .saturating_sub(offset as u64)
                .min(length as u64) as usize;
            if count == 0 {
                length.min(PAGE_SIZE as usize - offset % PAGE_SIZE as usize)
            } else {
                count
            }
        };
        for (&base, allocation) in state.allocated.range(scan..last) {
            if base > cursor {
                let gap = base - cursor;
                if gap > pages {
                    return prefix(cursor + pages);
                }
                pages -= gap;
            }
            cursor = cursor.max(allocation.end).min(last);
        }
        if last - cursor > pages {
            prefix(cursor + pages)
        } else {
            length
        }
    }
    fn context(&self) -> Option<Arc<dyn trames_shared::SharedFileContext>> {
        Some(Arc::new(Context(CgroupMemoryContext::capture())))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn reserve(
        &self,
        offset: usize,
        length: usize,
        access: SharedFileAccess,
    ) -> io::Result<Box<dyn SharedFileCharge>> {
        self.prepare(offset, length, access)
            .map(|loan| Box::new(loan) as Box<dyn SharedFileCharge>)
    }
    fn truncate(&self, length: usize) {
        let limit = (length as u64).div_ceil(PAGE_SIZE);
        let mut state = self.inner.state.lock().unwrap();
        let changed: Vec<_> = state
            .pages
            .range(limit..)
            .map(|(_, cell)| cell.clone())
            .collect();
        for cell in &changed {
            cell.owners.invalidate_cache();
            cell.dirty.store(false, Relaxed);
            cell.generation.fetch_add(1, Relaxed);
        }
        for (&base, allocation) in &mut state.allocated {
            let keep = limit.saturating_sub(base).min(allocation.end - base);
            allocation.resource.allocation.truncate(keep as usize);
            allocation.end = base + keep;
        }
        state
            .allocated
            .retain(|&base, allocation| base < allocation.end);
        state.pages.retain(|&index, cell| {
            index < limit || Arc::strong_count(cell) != 1 || Arc::strong_count(&cell.owners) != 1
        });
        drop(state);
        if !changed.is_empty() {
            trames_memory::backing_invalidated();
        }
        for cell in changed {
            cell.changed();
        }
    }
}
impl SharedFileCharge for Loan {
    fn changed(&self) -> bool {
        !self.inserted.is_empty()
    }
    fn commit(mut self: Box<Self>, used: usize) -> Arc<dyn Send + Sync> {
        debug_assert!(used <= self.length);
        if self.access == SharedFileAccess::Write && used < self.length {
            let last = if used == 0 {
                self.offset as u64 / PAGE_SIZE
            } else {
                ((self.offset + used) as u64).div_ceil(PAGE_SIZE)
            };
            self.pins.retain(|(index, _)| *index < last);
            self.discard_from(last);
        }
        self.committed = true;
        Arc::new(std::mem::take(&mut self.pins))
    }
}
impl Loan {
    fn discard_from(&self, last: u64) {
        let mut state = self.inner.state.lock().unwrap();
        let mut changed = Vec::new();
        for (base, resource) in &self.inserted {
            if let Some(allocation) = state
                .allocated
                .get(base)
                .filter(|allocation| Arc::ptr_eq(&allocation.resource, resource))
            {
                let end = allocation.end;
                let keep = last.max(*base).min(end);
                if keep == end {
                    continue;
                }
                for (_, cell) in state.pages.range(keep..end) {
                    cell.owners.invalidate_cache();
                    cell.generation.fetch_add(1, Relaxed);
                    changed.push(cell.clone());
                }
                resource.allocation.truncate((keep - *base) as usize);
                if keep == *base {
                    state.allocated.remove(base);
                } else {
                    state.allocated.get_mut(base).unwrap().end = keep;
                }
            }
        }
        drop(state);
        for cell in changed {
            cell.changed();
        }
    }
}
impl Drop for Loan {
    fn drop(&mut self) {
        if self.committed || self.inserted.is_empty() {
            return;
        }
        // The original SharedFile allocation transaction excludes another
        // reserve/truncate while provisional extents are visible here.
        self.discard_from(self.offset as u64 / PAGE_SIZE);
    }
}
pub(super) fn install(file: &SharedFile, imported: bool) -> Result<()> {
    if file.accounting::<Account>().is_some() {
        return Ok(());
    }
    let _native_root = imported.then(|| CgroupMemoryContext::default().enter());
    let account = Arc::new(Account::default());
    if imported && !file.is_empty() {
        // Unknown native input existed before guest import. Existing guest
        // identities recover their original accounting through SharedFile.
        let _root = CgroupMemoryContext::default().enter();
        let loan = account
            .prepare(0, file.len(), SharedFileAccess::Allocate)
            .map_err(crate::storage::host_errno)?;
        let _pins = Box::new(loan).commit(file.len());
    }
    if let Err(error) = file.set_accounting(account) {
        if file.accounting::<Account>().is_none() {
            return Err(crate::storage::host_errno(error));
        }
    }
    Ok(())
}
pub(super) fn cell(file: &SharedFile, offset: u64) -> Option<Arc<Page>> {
    file.accounting::<Account>()
        .map(|account| account.cell(offset))
}
pub(super) fn has_allocated_after(file: &SharedFile, length: u64) -> bool {
    file.accounting::<Account>()
        .is_some_and(|account| account.has_allocated_after(length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vfs;
    use trames_memory::{CgroupMemoryTarget, Memory, MemoryCgroup, MemoryError, Permissions};

    #[test]
    fn native_mappings_keep_first_owner_until_the_last_physical_pin() {
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        second.set_limit(0);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(first.clone()));
        let _scope = target.scope();
        let file = SharedFile::anonymous().unwrap();
        install(&file, false).unwrap();
        file.set_len(2 * PAGE_SIZE as usize).unwrap();
        assert_eq!(first.current(), 0);
        let original = file.map(PAGE_SIZE as usize, PAGE_SIZE as usize).unwrap();
        target.set(Some(second.clone()));
        let alias = file.map(PAGE_SIZE as usize, PAGE_SIZE as usize).unwrap();
        assert_eq!(first.current(), PAGE_SIZE as usize);
        assert_eq!(second.current(), 0);
        file.set_len(0).unwrap();
        assert_eq!(first.current(), PAGE_SIZE as usize);
        drop(original);
        assert_eq!(first.current(), PAGE_SIZE as usize);
        drop(alias);
        assert_eq!(first.current(), 0);
    }

    #[test]
    fn guest_mmap_is_lazy_and_ordinary_io_shares_its_physical_owner() {
        let first = MemoryCgroup::new(None);
        let second = MemoryCgroup::new(None);
        second.set_limit(PAGE_SIZE as usize);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(first.clone()));
        let _scope = target.scope();
        let mut v = Vfs::default();
        let fd = v.memfd_create(b"accounted", 0).unwrap();
        v.truncate_fd(fd, 2 * PAGE_SIZE).unwrap();
        let mut memory = Memory::default();
        for address in [0x10000, 0x20000] {
            memory
                .map_backed(
                    address,
                    v.mapping_pages(fd, 0, 2 * PAGE_SIZE, true, true).unwrap(),
                    true,
                    Permissions::RW,
                    false,
                )
                .unwrap();
        }
        assert_eq!(first.current(), 0, "mmap reserves address space only");
        target.set(Some(second.clone()));
        assert_eq!(memory.read_array::<1>(0x10000), Ok([0]));
        assert_eq!(memory.read_array::<1>(0x20000), Ok([0]));
        assert_eq!(second.current(), PAGE_SIZE as usize);
        assert_eq!(memory.read_array::<1>(0x11000), Err(MemoryError::Limit));
        target.set(Some(first.clone()));
        first.set_limit(0);
        assert_eq!(v.pwrite(fd, b"shared", 0), Ok(6));
        assert_eq!(memory.read_array::<6>(0x20000).unwrap(), *b"shared");
        assert_eq!(first.current(), 0);
        assert_eq!(second.current(), PAGE_SIZE as usize);
        let native = v
            .shared_file(fd)
            .unwrap()
            .map(0, PAGE_SIZE as usize)
            .unwrap();
        v.truncate_fd(fd, 0).unwrap();
        drop(memory);
        v.close(fd).unwrap();
        assert_eq!(second.current(), PAGE_SIZE as usize);
        drop(native);
        assert_eq!(second.current(), 0);
    }

    #[test]
    fn exported_actor_survives_native_delivery_and_explicit_root_stays_root() {
        let creator = MemoryCgroup::new(None);
        let sender = MemoryCgroup::new(None);
        let denied = MemoryCgroup::new(None);
        denied.set_limit(0);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(creator.clone()));
        let scope = target.scope();
        let file = SharedFile::anonymous().unwrap();
        install(&file, false).unwrap();
        file.set_len(4 * PAGE_SIZE as usize).unwrap();
        target.set(Some(sender.clone()));
        let (fd, transfer) = file.export().unwrap();
        let raw = file.duplicate_fd().unwrap();
        drop(scope);
        let native = std::thread::spawn(move || {
            let native = SharedFile::import(fd).unwrap();
            native.write_at(0, b"accepted actor").unwrap();
            let raw = SharedFile::import(raw).unwrap();
            raw.write_at(PAGE_SIZE, b"original resource actor").unwrap();
            native
        })
        .join()
        .unwrap();
        assert!(transfer.claimed());
        assert_eq!(sender.current(), PAGE_SIZE as usize);
        assert_eq!(creator.current(), PAGE_SIZE as usize);
        let _scope = target.scope();
        target.set(Some(denied.clone()));
        assert_eq!(
            native
                .write_at(3 * PAGE_SIZE, b"denied")
                .unwrap_err()
                .kind(),
            io::ErrorKind::OutOfMemory
        );
        target.set(None);
        native
            .write_at(2 * PAGE_SIZE, b"explicit root actor")
            .unwrap();
        assert_eq!(sender.current(), PAGE_SIZE as usize);
        assert_eq!(creator.current(), PAGE_SIZE as usize);
        assert_eq!(denied.current(), 0);
        native.set_len(0).unwrap();
        assert_eq!(sender.current(), 0);
        assert_eq!(creator.current(), 0);
    }

    #[test]
    fn bounded_shared_write_returns_completed_prefix_and_failure_refunds_extents() {
        let group = MemoryCgroup::new(None);
        group.set_limit(PAGE_SIZE as usize);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _scope = target.scope();
        let file = SharedFile::anonymous().unwrap();
        install(&file, false).unwrap();
        assert_eq!(
            file.write_at(100, &vec![7; 2 * PAGE_SIZE as usize])
                .unwrap(),
            PAGE_SIZE as usize - 100
        );
        assert_eq!(file.len(), PAGE_SIZE as usize);
        assert_eq!(group.current(), PAGE_SIZE as usize);
        file.set_len(0).unwrap();
        assert_eq!(group.current(), 0);
        let limited = SharedFile::anonymous_in(trames_shared::SharedBudget::new(0)).unwrap();
        install(&limited, false).unwrap();
        assert!(limited.reserve_range(0, PAGE_SIZE as usize).is_err());
        assert_eq!(
            group.current(),
            0,
            "native quota failure also refunds cgroup admission"
        );
    }
}
