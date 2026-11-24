// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{CpuMemory, MappedResidents, Memory, PageBacking, Permissions, SharedPage};

const BASE: u64 = 0x40000;
struct CachePage {
    owners: MappedResidents,
    bytes: Arc<SharedPage>,
    identity: u64,
}
impl CachePage {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            owners: Default::default(),
            bytes: Arc::new(SharedPage::new([9; PAGE_SIZE as usize])),
            identity: crate::new_backing_identity(),
        })
    }
}
impl PageBacking for CachePage {
    fn mapped_residents(&self) -> Option<&MappedResidents> {
        Some(&self.owners)
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.identity, 0))
    }
    fn shared_page(&self) -> Option<Arc<SharedPage>> {
        Some(self.bytes.clone())
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        self.bytes.copy_read(offset, out);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        self.bytes.copy_write(offset, bytes);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        0
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}
fn mapped(page: &Arc<CachePage>, shared: bool) -> Memory {
    let mut memory = Memory::default();
    memory
        .map_backed(BASE, vec![page.clone()], shared, Permissions::RW, false)
        .unwrap();
    memory
}

#[test]
fn shared_aliases_and_fork_keep_one_first_owner_until_the_original_cache_page_dies() {
    let a = MemoryCgroup::new(None);
    let b = MemoryCgroup::new(None);
    a.set_limit(PAGE_SIZE as usize);
    b.set_limit(0);
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    target.set(Some(a.clone()));
    let cache = CachePage::new();
    let mut first = mapped(&cache, true);
    first
        .map_backed(
            BASE + PAGE_SIZE,
            vec![cache.clone()],
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    assert_eq!(first.read_array::<1>(BASE).unwrap(), [9]);
    assert_eq!(first.read_array::<1>(BASE + PAGE_SIZE).unwrap(), [9]);
    assert_eq!(first.resident_bytes(), 2 * PAGE_SIZE as usize);
    assert_eq!(a.current(), PAGE_SIZE as usize);
    let mut fork = first.clone();
    drop(first);
    assert_eq!(a.current(), PAGE_SIZE as usize);
    target.set(Some(b.clone()));
    let other = mapped(&cache, true);
    assert_eq!(other.read_array::<1>(BASE).unwrap(), [9]);
    assert_eq!(b.current(), 0, "an alias is not a new physical page");
    fork.write_array(BASE, [7]).unwrap();
    assert_eq!(other.read_array::<1>(BASE).unwrap(), [7]);
    drop((fork, other));
    assert_eq!(
        a.current(),
        PAGE_SIZE as usize,
        "cached physical storage still exists"
    );
    drop(cache);
    assert_eq!(a.current(), 0);
}

#[test]
fn private_first_write_charges_the_actual_writer_in_all_shared_memory_access_paths() {
    for mechanism in 0..3 {
        let a = MemoryCgroup::new(None);
        let b = MemoryCgroup::new(None);
        a.set_limit(PAGE_SIZE as usize);
        b.set_limit(PAGE_SIZE as usize);
        let target = Arc::new(CgroupMemoryTarget::default());
        let _scope = target.scope();
        target.set(Some(a.clone()));
        let cache = CachePage::new();
        let mut memory = mapped(&cache, false);
        assert_eq!(memory.read_array::<1>(BASE).unwrap(), [9]);
        assert!(
            !memory.hardware_page_info(BASE).unwrap().writable,
            "a read-paid private cache page must fault before hardware writes"
        );
        assert_eq!(a.current(), PAGE_SIZE as usize);
        target.set(Some(b.clone()));
        match mechanism {
            0 => memory.write_array(BASE, [3]).unwrap(),
            1 => {
                memory
                    .with_write_chunk(BASE, 1, |bytes| bytes[0] = 3)
                    .unwrap();
            }
            _ => {
                let mut view = memory
                    .parallel_view(&mut crate::parallel::Registry::default())
                    .unwrap();
                view.write(BASE, &[3]).unwrap();
                drop(view);
                memory.commit_parallel().unwrap();
            }
        }
        assert_eq!(memory.read_array::<1>(BASE).unwrap(), [3]);
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        assert_eq!(a.current(), PAGE_SIZE as usize);
        assert_eq!(b.current(), PAGE_SIZE as usize);
        let mut original = [0];
        cache.bytes.copy_read(0, &mut original);
        assert_eq!(original, [9]);
        drop(memory);
        assert_eq!(b.current(), 0);
        drop(cache);
        assert_eq!(a.current(), 0);
    }
}

#[test]
fn failed_private_cow_preserves_the_cache_owner_and_can_retry_after_a_live_limit_change() {
    let a = MemoryCgroup::new(None);
    let b = MemoryCgroup::new(None);
    b.set_limit(0);
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    target.set(Some(a.clone()));
    let cache = CachePage::new();
    let mut memory = mapped(&cache, false);
    memory.read_array::<1>(BASE).unwrap();
    // Rebinding an RSS budget neither allocates a physical page nor migrates it.
    memory.set_total_limit(PAGE_SIZE as usize).unwrap();
    assert_eq!(a.current(), PAGE_SIZE as usize);
    target.set(Some(b.clone()));
    assert_eq!(memory.write_array(BASE, [1]), Err(MemoryError::Limit));
    assert_eq!(memory.read_array::<1>(BASE).unwrap(), [9]);
    assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
    assert_eq!(b.current(), 0);
    let (origin, limit) = target.take_oom().unwrap();
    assert!(Arc::ptr_eq(&origin, &b) && Arc::ptr_eq(&limit, &b));
    b.set_limit(PAGE_SIZE as usize);
    memory.write_array(BASE, [1]).unwrap();
    assert_eq!(memory.read_array::<1>(BASE).unwrap(), [1]);
    assert_eq!(b.current(), PAGE_SIZE as usize);
}

#[test]
fn an_existing_root_cache_page_is_not_recharged_to_a_migrated_reader() {
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    let cache = CachePage::new();
    let root = mapped(&cache, true);
    root.read_array::<1>(BASE).unwrap();
    let b = MemoryCgroup::new(None);
    b.set_limit(0);
    target.set(Some(b.clone()));
    let moved = mapped(&cache, true);
    moved.read_array::<1>(BASE).unwrap();
    assert_eq!(b.current(), 0);
}

#[test]
fn a_first_access_private_write_accounts_for_both_cache_and_cow_storage() {
    for worker in [false, true] {
        let group = MemoryCgroup::new(None);
        group.set_limit(2 * PAGE_SIZE as usize);
        let target = Arc::new(CgroupMemoryTarget::default());
        target.set(Some(group.clone()));
        let _scope = target.scope();
        let cache = CachePage::new();
        let mut memory = mapped(&cache, false);
        if worker {
            let mut view = memory
                .parallel_view(&mut crate::parallel::Registry::default())
                .unwrap();
            view.write(BASE, &[1]).unwrap();
            drop(view);
            memory.commit_parallel().unwrap();
        } else {
            memory.write_array(BASE, [1]).unwrap();
        }
        assert_eq!(group.current(), 2 * PAGE_SIZE as usize);
        assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
        drop(memory);
        assert_eq!(group.current(), PAGE_SIZE as usize);
        drop(cache);
        assert_eq!(group.current(), 0);
    }
}
