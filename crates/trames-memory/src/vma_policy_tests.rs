// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
const BASE: u64 = 0x10000;
#[test]
fn fork_excludes_resident_anonymous_and_reserved_ranges_before_charging_child() {
    let mut memory = Memory::new(3 * PAGE_SIZE as usize);
    memory.map(BASE, 3 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(BASE, b"parent").unwrap();
    memory.write(BASE + PAGE_SIZE, b"child").unwrap();
    memory
        .reserve(BASE + 3 * PAGE_SIZE, PAGE_SIZE, false)
        .unwrap();
    memory.advise_fork(BASE, PAGE_SIZE, 10).unwrap();
    memory
        .advise_fork(BASE + 2 * PAGE_SIZE, 2 * PAGE_SIZE, 10)
        .unwrap();
    let mut child = memory.try_fork().unwrap();
    assert!(child.is_free(BASE, PAGE_SIZE));
    assert!(child.is_free(BASE + 2 * PAGE_SIZE, 2 * PAGE_SIZE));
    assert_eq!(child.read_array::<5>(BASE + PAGE_SIZE).unwrap(), *b"child");
    assert_eq!(memory.read_array::<6>(BASE).unwrap(), *b"parent");
    child.write(BASE + PAGE_SIZE, b"other").unwrap();
    assert_eq!(memory.read_array::<5>(BASE + PAGE_SIZE).unwrap(), *b"child");
}
#[test]
fn dofork_and_wipe_keep_parent_data_and_wipe_again_in_grandchildren() {
    let mut memory = Memory::default();
    memory.map(BASE, 3 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.write(BASE, b"secret").unwrap();
    memory.advise_fork(BASE, 2 * PAGE_SIZE, 10).unwrap();
    memory.advise_fork(BASE, PAGE_SIZE, 11).unwrap();
    memory.advise_fork(BASE, PAGE_SIZE, 18).unwrap();
    let mut child = memory.try_fork().unwrap();
    assert_eq!(child.read_array::<6>(BASE).unwrap(), [0; 6]);
    assert!(child.is_free(BASE + PAGE_SIZE, PAGE_SIZE));
    assert_eq!(memory.read_array::<6>(BASE).unwrap(), *b"secret");
    child.write(BASE, b"second").unwrap();
    assert_eq!(
        child.try_fork().unwrap().read_array::<6>(BASE).unwrap(),
        [0; 6]
    );
    child.advise_fork(BASE, PAGE_SIZE, 19).unwrap();
    assert_eq!(
        child.try_fork().unwrap().read_array::<6>(BASE).unwrap(),
        *b"second"
    );
}
#[test]
fn remap_moves_and_extends_policy_but_replacement_mapping_clears_it() {
    let mut memory = Memory::default();
    memory.map(BASE, 2 * PAGE_SIZE, Permissions::RW).unwrap();
    memory.advise_fork(BASE + PAGE_SIZE, PAGE_SIZE, 10).unwrap();
    memory
        .remap(BASE, 2 * PAGE_SIZE, BASE * 2, 3 * PAGE_SIZE, false)
        .unwrap();
    let child = memory.try_fork().unwrap();
    assert!(!child.is_free(BASE * 2, PAGE_SIZE));
    assert!(child.is_free(BASE * 2 + PAGE_SIZE, 2 * PAGE_SIZE));
    memory
        .map_fixed(BASE * 2 + PAGE_SIZE, PAGE_SIZE, Permissions::RW)
        .unwrap();
    let child = memory.try_fork().unwrap();
    assert!(!child.is_free(BASE * 2 + PAGE_SIZE, PAGE_SIZE));
    assert!(child.is_free(BASE * 2 + 2 * PAGE_SIZE, PAGE_SIZE));
}
#[test]
fn shared_mm_has_one_policy_and_worker_view_defers_mutation_before_effects() {
    let mut memory = Memory::default();
    memory.map(BASE, PAGE_SIZE, Permissions::RW).unwrap();
    let mut shared = memory.share();
    let mut view = memory
        .parallel_view(&mut parallel::Registry::default())
        .unwrap();
    assert!(CpuMemory::advise_fork(&mut view, BASE, PAGE_SIZE, 10).is_none());
    shared.advise_fork(BASE, PAGE_SIZE, 10).unwrap();
    assert!(memory.try_fork().unwrap().is_free(BASE, PAGE_SIZE));
    shared.advise_fork(BASE, PAGE_SIZE, 11).unwrap();
    assert!(!memory.try_fork().unwrap().is_free(BASE, PAGE_SIZE));
}

#[test]
fn numa_ranges_survive_fork_and_remap_and_exclude_replacement_pages() {
    let mut mm = Memory::default();
    let p = PAGE_SIZE;
    mm.map(BASE, 4 * p, Permissions::RW).unwrap();
    let old = mm.parallel_view(&mut Default::default()).unwrap();
    mm.bind_numa_policy(BASE, p * 4, 2).unwrap();
    mm.bind_numa_policy(BASE + p, p * 2, 3).unwrap();
    assert_eq!(old.numa_mode_at(BASE), 0);
    drop(old);
    let current = mm.parallel_view(&mut Default::default()).unwrap();
    assert_eq!(current.numa_mode_at(BASE + p), 3);
    drop(current);
    let mut child = mm.try_fork().unwrap();
    child.bind_numa_policy(BASE, p * 4, 0).unwrap();
    assert_eq!(child.numa_mode_at(BASE), 0);
    assert_eq!(mm.numa_mode_at(BASE), 2);
    let dst = BASE * 3;
    mm.remap(BASE, p * 4, dst, p * 5, false).unwrap();
    assert_eq!(mm.numa_mode_at(BASE), 0);
    assert_eq!(mm.numa_mode_at(dst + p), 3);
    assert_eq!(mm.numa_mode_at(dst + 4 * p), 2);
    mm.map_fixed(dst + 2 * p, p, Permissions::RW).unwrap();
    assert_eq!(mm.numa_mode_at(dst + 2 * p), 0);
    mm.unmap(dst + p, p).unwrap();
    assert!(mm.bind_numa_policy(dst, 4 * p, 1).is_err());
    assert_eq!(mm.numa_mode_at(dst), 2);
    mm.bind_numa_policy(dst, 4 * p, 0).unwrap();
    assert_eq!(mm.numa_mode_at(dst), 0);
    assert_eq!(mm.numa_mode_at(dst + 4 * p), 2);
}
