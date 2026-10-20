// SPDX-License-Identifier: GPL-3.0-or-later
//! Storage identity and mixed coordinator/CPU/native concurrency regressions.
use super::*;
use std::sync::Barrier;

#[test]
fn coordinator_and_four_workers_share_one_allocation_and_atomic_domain() {
    let mut memory = Memory::default();
    memory.map(0x40000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(0x40000, 0u64.to_le_bytes()).unwrap();
    let physical = memory.frames[memory.pages[&0x40000]]
        .as_ref()
        .unwrap()
        .bytes
        .physical()
        .map(|(owner, at)| (owner.kernel.as_ptr() as usize, at));
    let mut registry = Registry::default();
    let view = memory.parallel_view(&mut registry).unwrap();
    let source = memory.frames[memory.pages[&0x40000]]
        .as_ref()
        .unwrap()
        .bytes
        .shared()
        .unwrap()
        .clone();
    let frame = view.frame(0x40000, Access::Write).unwrap();
    assert!(frame.direct);
    assert!(Arc::ptr_eq(&source, frame.bytes.bytes.as_ref().unwrap()));
    assert_eq!(
        physical,
        source
            .physical()
            .map(|(owner, at)| (owner.kernel.as_ptr() as usize, at))
    );
    assert_eq!(registry.metrics.source_page_reads, 0);
    assert_eq!(registry.metrics.copied_publish_bytes, 0);
    assert_eq!(memory.resident_bytes(), PAGE_SIZE as usize);
    let start = Arc::new(Barrier::new(5));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let mut view = view.clone();
        let start = start.clone();
        workers.push(std::thread::spawn(move || {
            start.wait();
            for _ in 0..2000 {
                view.atomic_update(0x40000, 8, |bytes| {
                    let value = u64::from_le_bytes(bytes.try_into().unwrap());
                    bytes.copy_from_slice(&(value + 1).to_le_bytes());
                    ((), true)
                })
                .unwrap();
            }
        }));
    }
    start.wait();
    for _ in 0..2000 {
        memory
            .atomic_update(0x40000, 8, |bytes| {
                let value = u64::from_le_bytes(bytes.try_into().unwrap());
                bytes.copy_from_slice(&(value + 1).to_le_bytes());
                ((), true)
            })
            .unwrap();
    }
    for worker in workers {
        worker.join().unwrap();
    }
    // No commit/refresh is needed for byte visibility in either direction.
    assert_eq!(memory.read_u64(0x40000).unwrap(), 10000);
    assert_eq!(view.read_u64(0x40000).unwrap(), 10000);
    drop(view);
    memory.commit_parallel().unwrap();
    assert!(Arc::ptr_eq(
        &source,
        memory.frames[memory.pages[&0x40000]]
            .as_ref()
            .unwrap()
            .bytes
            .shared()
            .unwrap()
    ));
    for _ in 0..32 {
        memory
            .with_write_chunk(0x40040, 16, |bytes| bytes.fill(42))
            .unwrap();
        let view = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(view.read_array::<16>(0x40040).unwrap(), [42; 16]);
        drop(view);
        memory.commit_parallel().unwrap();
    }
    assert_eq!(registry.metrics.copied_publish_bytes, 0);
    assert_eq!(registry.metrics.cow_detach_bytes, 0);
}

#[test]
fn native_and_coordinator_exclusives_share_monitors_and_alias_pair_guards() {
    let mut memory = Memory::default();
    memory.map(0x40000, PAGE_SIZE, Permissions::RW).unwrap();
    let mut registry = Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    let mut bytes = [0; 8];
    let worker_token = view.exclusive_read(0x40000, &mut bytes).unwrap();
    memory
        .with_write_chunk(0x40000, 8, |bytes| bytes.fill(1))
        .unwrap();
    assert!(!view
        .exclusive_write(0x40000, &[2; 8], Some(worker_token))
        .unwrap());
    let local_token = memory.exclusive_read(0x40000, &mut bytes).unwrap();
    view.write_array(0x40000, [0; 8]).unwrap();
    assert!(!memory
        .exclusive_write(0x40000, &[2; 8], Some(local_token))
        .unwrap());
    let token = memory.exclusive_read(0x40000, &mut bytes).unwrap();
    view.write_array(0x40040, [42; 8]).unwrap();
    assert!(memory
        .exclusive_write(0x40000, &[3; 8], Some(token))
        .unwrap());
    let pair = NativeMemory::with_read_pair(&memory, 0x40000, 0x40040, 8, |a, b| {
        (a.to_vec(), b.to_vec())
    })
    .unwrap();
    assert_eq!(pair, ((vec![3; 8], vec![42; 8]), true, true));
    assert_eq!(view.read_array::<8>(0x40000).unwrap(), [3; 8]);
}

#[test]
fn cached_views_after_fork_detach_private_bytes_but_shared_vm_never_does() {
    let mut parent = Memory::default();
    parent.map(0x40000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
    parent.write_array(0x40000, [7; 8]).unwrap();
    let mut registry = Registry::default();
    drop(parent.parallel_view(&mut registry).unwrap());
    parent.commit_parallel().unwrap();
    let mut child = parent.clone();
    let mut parent_view = parent.parallel_view(&mut registry).unwrap();
    parent_view.write_array(0x40000, [8; 8]).unwrap();
    assert_eq!(child.read_array::<8>(0x40000).unwrap(), [7; 8]);
    drop(parent_view);
    parent.commit_parallel().unwrap();
    let mut child_view = child.parallel_view(&mut registry).unwrap();
    child_view.write_array(0x41000, [9; 8]).unwrap();
    assert_eq!(parent.read_array::<8>(0x41000).unwrap(), [0; 8]);
    assert_eq!(child.resident_bytes(), 2 * PAGE_SIZE as usize);
    drop(child_view);
    child.commit_parallel().unwrap();
    let before = registry.metrics.cow_detach_bytes;
    let mut sibling = parent.share();
    let mut a = sibling.parallel_view(&mut registry).unwrap();
    let b = parent.parallel_view(&mut registry).unwrap();
    a.write_array(0x40000, [10; 8]).unwrap();
    assert_eq!(b.read_array::<8>(0x40000).unwrap(), [10; 8]);
    assert_eq!(sibling.read_array::<8>(0x40000).unwrap(), [10; 8]);
    assert_eq!(registry.metrics.cow_detach_bytes, before);
}

#[test]
fn fork_with_a_retained_writer_cannot_mutate_the_child_snapshot() {
    let mut parent = Memory::default();
    parent.map(0x40000, PAGE_SIZE, Permissions::RW).unwrap();
    let mut registry = Registry::default();
    let mut writer = parent.parallel_view(&mut registry).unwrap();
    writer.write_array(0x40000, [11; 8]).unwrap();
    let child = parent.clone();
    writer.write_array(0x40000, [12; 8]).unwrap();
    assert_eq!(parent.read_array::<8>(0x40000).unwrap(), [12; 8]);
    assert_eq!(child.read_array::<8>(0x40000).unwrap(), [11; 8]);
}

#[test]
fn a_private_file_copy_rejoins_shared_storage_after_its_first_cow_write() {
    let mut memory = Memory::default();
    memory
        .map_shared_anonymous(0x1000, PAGE_SIZE, Permissions::RW, false)
        .unwrap();
    let backing = memory.frames[memory.pages[&0x1000]]
        .as_ref()
        .unwrap()
        .backing
        .as_ref()
        .unwrap()
        .object
        .clone();
    memory
        .map_backed(0x5000, vec![backing], false, Permissions::RW, false)
        .unwrap();
    let mut registry = Registry::default();
    let mut first = memory.parallel_view(&mut registry).unwrap();
    assert!(!first.frame(0x5000, Access::Write).unwrap().direct);
    first.write_array(0x5000, [42; 8]).unwrap();
    drop(first);
    memory.commit_parallel().unwrap();
    let published = registry.metrics.copied_publish_bytes;
    let mut next = memory.parallel_view(&mut registry).unwrap();
    assert!(next.frame(0x5000, Access::Write).unwrap().direct);
    next.write_array(0x5000, [43; 8]).unwrap();
    assert_eq!(memory.read_array::<8>(0x5000).unwrap(), [43; 8]);
    assert_eq!(memory.read_array::<8>(0x1000).unwrap(), [0; 8]);
    drop(next);
    memory.commit_parallel().unwrap();
    assert_eq!(registry.metrics.copied_publish_bytes, published);
}

#[test]
fn retired_views_keep_reused_slots_with_live_neighbors_and_snapshot_generations() {
    for refresh in [false, true] {
        let mut memory = Memory::default();
        memory.map(0x40000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x40000, [11; 8]).unwrap();
        memory.write_array(0x41000, [22; 8]).unwrap();
        let mut registry = Registry::default();
        let old = memory.parallel_view(&mut registry).unwrap();
        if refresh {
            backing::backing_changed();
            // Old View now belongs to a different Snapshot from the cache.
            drop(memory.parallel_view(&mut registry).unwrap());
        }
        memory.unmap(0x40000, PAGE_SIZE).unwrap();
        memory.map(0x40000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x40000, [33; 8]).unwrap();
        assert_eq!(old.read_array::<8>(0x40000).unwrap(), [11; 8]);
        assert_eq!(old.read_array::<8>(0x41000).unwrap(), [22; 8]);
        assert_eq!(memory.read_array::<8>(0x40000).unwrap(), [33; 8]);
        let next = memory.parallel_view(&mut registry).unwrap();
        assert_eq!(next.read_array::<8>(0x40000).unwrap(), [33; 8]);
        drop(old);
        drop(next);
        assert!(!memory.has_parallel_users());
    }
}
