// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{CpuMemory, Memory, Permissions};

const BASE: u64 = 0x40000;
const PAGE: usize = PAGE_SIZE as usize;

fn resident() -> Memory {
    let mut memory = Memory::default();
    memory.map(BASE, 2 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write_array(BASE, [7]).unwrap();
    memory
}

#[test]
fn fork_shares_physical_ownership_and_only_cow_charges_the_writer() {
    for mechanism in 0..3 {
        let a = MemoryCgroup::new(None);
        let b = MemoryCgroup::new(None);
        a.set_limit(PAGE);
        b.set_limit(0);
        let target = Arc::new(CgroupMemoryTarget::default());
        let _scope = target.scope();
        target.set(Some(a.clone()));
        let parent = resident();
        let mut child = parent.try_fork().unwrap();
        assert_eq!(a.current(), PAGE);
        assert_eq!(child.resident_bytes(), PAGE);
        target.set(Some(b.clone()));
        assert_eq!(child.read_array::<1>(BASE), Ok([7]));
        assert_eq!(child.write_array(BASE, [9]), Err(MemoryError::Limit));
        assert_eq!(parent.read_array::<1>(BASE), Ok([7]));
        assert_eq!(child.read_array::<1>(BASE), Ok([7]));
        assert_eq!(a.current(), PAGE);
        assert_eq!(b.current(), 0);
        b.set_limit(PAGE);
        match mechanism {
            0 => child.write_array(BASE, [9]).unwrap(),
            1 => {
                child
                    .with_write_chunk(BASE, 1, |bytes| bytes[0] = 9)
                    .unwrap();
            }
            _ => {
                let mut view = child
                    .parallel_view(&mut crate::parallel::Registry::default())
                    .unwrap();
                view.write_array(BASE, [9]).unwrap();
                drop(view);
                child.commit_parallel().unwrap();
            }
        }
        assert_eq!(child.read_array::<1>(BASE), Ok([9]));
        assert_eq!(parent.read_array::<1>(BASE), Ok([7]));
        assert_eq!(a.current(), PAGE);
        assert_eq!(b.current(), PAGE);
        drop(parent);
        assert_eq!(a.current(), 0);
        drop(child);
        assert_eq!(b.current(), 0);
    }
}

#[test]
fn an_exclusive_survivor_keeps_its_original_charge_after_migration() {
    let a = MemoryCgroup::new(None);
    let b = MemoryCgroup::new(None);
    b.set_limit(0);
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    target.set(Some(a.clone()));
    let parent = resident();
    let mut child = parent.try_fork().unwrap();
    drop(parent);
    target.set(Some(b.clone()));
    child.write_array(BASE, [9]).unwrap();
    assert_eq!(a.current(), PAGE);
    assert_eq!(b.current(), 0);
    drop(child);
    assert_eq!(a.current(), 0);
}

#[test]
fn a_root_owned_fork_page_still_charges_a_new_private_copy_after_migration() {
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    let parent = resident();
    let mut child = parent.try_fork().unwrap();
    let group = MemoryCgroup::new(None);
    group.set_limit(0);
    target.set(Some(group.clone()));
    assert_eq!(child.write_array(BASE, [9]), Err(MemoryError::Limit));
    assert_eq!(child.read_array::<1>(BASE), Ok([7]));
    group.set_limit(PAGE);
    child.write_array(BASE, [9]).unwrap();
    assert_eq!(group.current(), PAGE);
    assert_eq!(parent.read_array::<1>(BASE), Ok([7]));
}

#[test]
fn retained_paid_cpu_and_hardware_mappings_reenter_cow_admission() {
    let a = MemoryCgroup::new(None);
    a.set_limit(PAGE);
    let b = MemoryCgroup::new(None);
    b.set_limit(0);
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    target.set(Some(a.clone()));
    let mut parent = resident();
    let mut registry = crate::parallel::Registry::default();
    registry.use_hardware();
    let mut held = parent.parallel_view(&mut registry).unwrap();
    held.write_array(BASE, [7]).unwrap(); // prime the paid CPU translation
    held.enable_hardware();
    assert!(held.hardware_page_info(BASE).unwrap().writable);
    let before = held.hardware_view_version();
    let chunk = held.hardware_mapping_chunk_version(BASE).unwrap();
    let child = parent.try_fork().unwrap();
    assert_eq!(a.current(), PAGE);
    assert_ne!(held.hardware_view_version().0, before.0);
    assert_ne!(held.hardware_mapping_chunk_version(BASE), Some(chunk));
    assert!(held.hardware_mapping_ranges(before.0).is_none());
    assert!(!held.hardware_page_info(BASE).unwrap().writable);
    assert!(held.hardware_write_frame(BASE).is_err());
    target.set(Some(b.clone()));
    assert_eq!(held.write_array(BASE, [9]), Err(MemoryError::Limit));
    assert_eq!(child.read_array::<1>(BASE), Ok([7]));
    b.set_limit(PAGE);
    held.write_array(BASE, [9]).unwrap();
    assert_eq!(b.current(), PAGE);
    assert_eq!(held.read_array::<1>(BASE), Ok([9]));
    assert_eq!(child.read_array::<1>(BASE), Ok([7]));
    drop(held);
    parent.commit_parallel().unwrap();
    assert_eq!(parent.read_array::<1>(BASE), Ok([9]));
}

#[test]
fn failed_fork_does_not_revoke_retained_permissions_or_leak_tentative_leases() {
    let group = MemoryCgroup::new(None);
    group.set_limit(2 * PAGE);
    let target = Arc::new(CgroupMemoryTarget::default());
    let _scope = target.scope();
    target.set(Some(group.clone()));
    let mut parent = resident();
    parent.write_array(BASE + PAGE_SIZE, [8]).unwrap();
    parent.set_total_limit(3 * PAGE).unwrap();
    let mut registry = crate::parallel::Registry::default();
    registry.use_hardware();
    let mut held = parent.parallel_view(&mut registry).unwrap();
    held.enable_hardware();
    let before = held.hardware_view_version();
    assert!(matches!(parent.try_fork(), Err(MemoryError::Limit)));
    assert_eq!(held.hardware_view_version(), before);
    assert!(held.hardware_page_info(BASE).unwrap().writable);
    assert_eq!(parent.resident_bytes(), 2 * PAGE);
    assert_eq!(group.current(), 2 * PAGE);
    // The failed child's tentative physical lease must have gone away.
    held.write_array(BASE, [9]).unwrap();
    assert_eq!(group.current(), 2 * PAGE);
}
