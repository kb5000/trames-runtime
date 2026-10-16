// SPDX-License-Identifier: GPL-3.0-or-later
//! Exercise warmed translations across architectural permission and lifetime changes.
use std::{cell::Cell, rc::Rc};
use trames_memory::{
    parallel::Registry, Access, CpuMemory, Memory, MemoryError, PageBacking, Permissions,
    ADDRESS_LIMIT, PAGE_SIZE,
};

fn permission_matrix(memory: &mut impl CpuMemory, permissions: Permissions) {
    for _ in 0..3 {
        let read = memory.read_array::<4>(0x1034);
        let write = memory.write_array(0x1034, [0; 4]);
        let fetch = memory.fetch_u32(0x1034);
        for (allowed, access, result) in [
            (permissions.read, Access::Read, read.map(|_| ())),
            (permissions.write, Access::Write, write),
            (permissions.execute, Access::Execute, fetch.map(|_| ())),
        ] {
            assert_eq!(
                result,
                if allowed {
                    Ok(())
                } else {
                    Err(MemoryError::Permission {
                        address: 0x1034,
                        access,
                    })
                }
            );
        }
    }
}

#[test]
fn warming_one_access_does_not_grant_another_and_protect_revokes_permissions() {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let mut registry = Registry::default();
    for bits in [7, 0, 1, 2, 4, 3, 5, 6, 7, 0] {
        let permissions = Permissions {
            read: bits & 1 != 0,
            write: bits & 2 != 0,
            execute: bits & 4 != 0,
        };
        memory.protect(0x1000, PAGE_SIZE, permissions).unwrap();
        permission_matrix(&mut memory, permissions);
        let mut view = memory.parallel_view(&mut registry).unwrap();
        permission_matrix(&mut view, permissions);
    }
}

#[test]
fn resident_cow_discard_remap_and_frame_growth_revoke_old_translations() {
    let mut parent = Memory::default();
    parent.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    parent.write_array(0x1013, [7; 16]).unwrap();
    assert_eq!(parent.read_array::<16>(0x1013).unwrap(), [7; 16]);
    let mut child = parent.clone();
    parent.write_array(0x1013, [9; 16]).unwrap();
    assert_eq!(child.read_array::<16>(0x1013).unwrap(), [7; 16]);
    assert_eq!(parent.read_array::<16>(0x1013).unwrap(), [9; 16]);
    child.discard(0x1000, PAGE_SIZE).unwrap();
    assert_eq!(child.read_array::<16>(0x1013).unwrap(), [0; 16]);
    // Grow/reallocate the slab, then move the warmed mapping and recycle its slot.
    parent
        .map(0x100000, 512 * PAGE_SIZE, Permissions::RW)
        .unwrap();
    assert_eq!(parent.read_array::<16>(0x1013).unwrap(), [9; 16]);
    parent
        .remap(0x1000, PAGE_SIZE, 0x8000, PAGE_SIZE, false)
        .unwrap();
    assert_eq!(parent.read_array::<16>(0x8013).unwrap(), [9; 16]);
    assert_eq!(
        parent.read_array::<1>(0x1013),
        Err(MemoryError::Unmapped(0x1013))
    );
    parent.map_fixed(0x8000, PAGE_SIZE, Permissions::R).unwrap();
    assert_eq!(parent.read_array::<16>(0x8013).unwrap(), [0; 16]);
    assert!(parent.write_array(0x8013, [1]).is_err());
}

fn boundary_checks(memory: &mut impl CpuMemory) {
    memory.write_array(ADDRESS_LIMIT - 8, [7; 8]).unwrap();
    assert_eq!(
        memory
            .read_array::<8>(0xab00_0000_0000_0000 | (ADDRESS_LIMIT - 8))
            .unwrap(),
        [7; 8]
    );
    assert_eq!(
        memory.write_array(ADDRESS_LIMIT - 4, [9; 8]),
        Err(MemoryError::AddressRange(ADDRESS_LIMIT - 4))
    );
    assert_eq!(memory.read_array::<8>(ADDRESS_LIMIT - 8).unwrap(), [7; 8]);
    for address in [ADDRESS_LIMIT, u64::MAX - 3] {
        assert_eq!(
            memory.fetch_u32(address),
            Err(MemoryError::AddressRange(address))
        );
    }
    memory.write_array(0x1ff8, [3; 8]).unwrap();
    assert_eq!(
        memory.write_array(0x1ffc, [9; 8]),
        Err(MemoryError::Permission {
            address: 0x2000,
            access: Access::Write
        })
    );
    assert_eq!(memory.read_array::<8>(0x1ff8).unwrap(), [3; 8]);
}

#[test]
fn tags_empty_entries_address_limit_and_cross_page_faults_preserve_effects() {
    let mut memory = Memory::default();
    memory
        .map(ADDRESS_LIMIT - PAGE_SIZE, PAGE_SIZE, Permissions::RW)
        .unwrap();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.map(0x2000, PAGE_SIZE, Permissions::R).unwrap();
    boundary_checks(&mut memory);
    boundary_checks(&mut memory.parallel_view(&mut Registry::default()).unwrap());
}

struct LiveBacking {
    valid: Cell<bool>,
    checks: Cell<usize>,
}
impl PageBacking for LiveBacking {
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((12345, 0))
    }
    fn check(&self, address: u64) -> Result<(), MemoryError> {
        self.checks.set(self.checks.get() + 1);
        if self.valid.get() {
            Ok(())
        } else {
            Err(MemoryError::Bus(address))
        }
    }
    fn read(&self, _: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        out.fill(8);
        Ok(())
    }
    fn write(&self, _: usize, _: &[u8]) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn version(&self) -> u64 {
        u64::from(self.valid.get())
    }
    fn writable(&self) -> bool {
        true
    }
    fn next_page(&self, _: u64) -> Result<Rc<dyn PageBacking>, MemoryError> {
        Err(MemoryError::InvalidRange)
    }
}

#[test]
fn warmed_backing_and_private_copy_still_fault_after_truncation() {
    for shared in [false, true] {
        let mut memory = Memory::default();
        let backing = Rc::new(LiveBacking {
            valid: Cell::new(true),
            checks: Cell::new(0),
        });
        memory
            .map_backed(
                0x1000,
                vec![backing.clone()],
                shared,
                Permissions::RW,
                false,
            )
            .unwrap();
        memory.read_array::<8>(0x1020).unwrap();
        memory.write_array(0x1020, [9; 8]).unwrap();
        let checks = backing.checks.get();
        memory.read_array::<8>(0x1020).unwrap();
        assert!(backing.checks.get() > checks);
        let mut registry = Registry::default();
        let view = memory.parallel_view(&mut registry).unwrap();
        view.read_array::<8>(0x1020).unwrap();
        drop(view); // Kernel/backing mutation only at a joined checkpoint.
        backing.valid.set(false);
        trames_memory::backing_changed();
        for address in [0x1020, 0x1050] {
            assert_eq!(
                memory.read_array::<8>(address),
                Err(MemoryError::Bus(address))
            );
            assert_eq!(
                memory.write_array(address, [1; 8]),
                Err(MemoryError::Bus(address))
            );
        }
        let view = memory.parallel_view(&mut registry).unwrap();
        for address in [0x1020, 0x1050] {
            assert_eq!(
                view.read_array::<8>(address),
                Err(MemoryError::Bus(address))
            );
        }
    }
}
