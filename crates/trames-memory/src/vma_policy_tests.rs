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
