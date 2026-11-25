// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
struct Fixture {
    aio: Aio,
    direct: DirectSyscalls,
    memory: Memory,
    context: Arc<Context>,
    id: u64,
    wake: Arc<dyn IoWake>,
}
impl Fixture {
    fn new(count: u64) -> Self {
        let aio = Aio::default();
        let vfs = trames_vfs::Vfs::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events());
        let mut memory = Memory::default();
        memory.map(0x1000, 4 * PAGE_SIZE, Permissions::RW).unwrap();
        aio.setup([count, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
        let id = memory.read_u64(0x1000).unwrap();
        let context = aio.context(id, &memory).unwrap();
        Self {
            aio,
            direct,
            memory,
            context,
            id,
            wake: Arc::new(Wake),
        }
    }
}
#[test]
fn moved_ring_uses_recorded_address_and_user_slot_without_backing_identity_checks() {
    let mut f = Fixture::new(8);
    f.memory
        .remap(f.id, PAGE_SIZE, 0x9000, PAGE_SIZE, false)
        .unwrap();
    assert_eq!(f.context.mapping.address(), 0x9000);
    assert!(f.aio.context(f.id, &f.memory).is_err());
    assert!(Arc::ptr_eq(
        &f.aio.context(0x9000, &f.memory).unwrap(),
        &f.context
    ));
    assert_eq!(
        f.memory
            .remap(0x9000, PAGE_SIZE, 0x9000, 2 * PAGE_SIZE, false),
        Err(MemoryError::BackingIo(14))
    );
    assert_eq!(
        f.memory.alias_shared_mapping(0x9000, 0xa000, PAGE_SIZE),
        Err(MemoryError::BackingIo(14))
    );
    assert!(f
        .memory
        .protect(0x9000, PAGE_SIZE, Permissions::RX)
        .is_err());
    f.memory
        .map_backed(
            0xb000,
            f.context.mappings.clone(),
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
    assert!(
        f.aio.context(0xb000, &f.memory).is_err(),
        "the same ring at another VA is not its accepted context handle"
    );
    f.memory
        .map_fixed(0x9000, PAGE_SIZE, Permissions::RW)
        .unwrap();
    f.memory
        .write_array(0x9000, (f.context.slot + 1).to_le_bytes())
        .unwrap();
    assert!(f.aio.context(0x9000, &f.memory).is_err());
    f.memory
        .write_array(0x9000, f.context.slot.to_le_bytes())
        .unwrap();
    assert!(Arc::ptr_eq(
        &f.aio.context(0x9000, &f.memory).unwrap(),
        &f.context
    ));
    assert!(matches!(
        f.direct
            .start(
                4,
                [0x9000, 0, 0, 0, 0, 0],
                &mut f.memory,
                1,
                &Arc::downgrade(&f.wake),
                None
            )
            .unwrap(),
        IoAttempt::Complete(Ok(0))
    ));
    assert!(matches!(
        f.direct
            .start(
                1,
                [0x9000, 0, 0, 0, 0, 0],
                &mut f.memory,
                1,
                &Arc::downgrade(&f.wake),
                None
            )
            .unwrap(),
        IoAttempt::Complete(Ok(0))
    ));
    assert!(f.memory.validate_mapped(0x9000, PAGE_SIZE).is_err());
    assert!(f.memory.validate_mapped(0xb000, PAGE_SIZE).is_ok());
}
#[test]
fn fork_inherits_ring_bytes_without_a_context_and_failed_file_move_restores_source_metadata() {
    let mut f = Fixture::new(8);
    let mut child = f.memory.try_fork().unwrap();
    assert_eq!(
        child.read_array::<32>(f.id).unwrap(),
        f.memory.read_array::<32>(f.id).unwrap()
    );
    child.write_array(f.id + 8, 7u32.to_le_bytes()).unwrap();
    assert_eq!(f.context.head(), 7);
    assert!(f.aio.fork().context(f.id, &child).is_err());
    child.map(0x9000, PAGE_SIZE, Permissions::RW).unwrap();
    child.write(0x9000, b"old destination").unwrap();
    child.set_range_lock(f.id, PAGE_SIZE, Some(true)).unwrap();
    assert_eq!(
        child.remap(f.id, PAGE_SIZE, 0x9000, PAGE_SIZE, true),
        Err(MemoryError::BackingIo(22))
    );
    assert!(child.validate_mapped(f.id, PAGE_SIZE).is_ok());
    assert!(
        child.validate_mapped(0x9000, PAGE_SIZE).is_err(),
        "fixed destination was removed before the file hook failed"
    );
    assert_eq!(child.lock_mode_at(f.id), Some(true));
    assert!(!child.mapping_expandable(f.id));
    assert_eq!(f.context.mapping.address(), f.id);
    assert!(f.aio.context(f.id, &f.memory).is_ok());
    assert!(matches!(
        f.direct
            .start(
                1,
                [f.id, 0, 0, 0, 0, 0],
                &mut f.memory,
                1,
                &Arc::downgrade(&f.wake),
                None
            )
            .unwrap(),
        IoAttempt::Complete(Ok(0))
    ));
    assert!(child.validate_mapped(f.id, PAGE_SIZE).is_ok());
    assert_eq!(
        child.remap(f.id, PAGE_SIZE, 0x9000, PAGE_SIZE, false),
        Err(MemoryError::BackingIo(22))
    );
}
#[test]
fn moving_a_partial_ring_records_that_vma_start_and_destroy_uses_the_original_mmap_size() {
    let mut f = Fixture::new(128);
    assert_eq!(f.context.mapping.length, 2 * PAGE_SIZE);
    f.memory
        .remap(f.id + PAGE_SIZE, PAGE_SIZE, 0x9000, PAGE_SIZE, false)
        .unwrap();
    assert_eq!(f.context.mapping.address(), 0x9000);
    assert!(f.aio.context(f.id, &f.memory).is_err());
    // This first context has slot zero, as does the untouched event page.
    assert_eq!(f.context.slot, 0);
    assert!(f.aio.context(0x9000, &f.memory).is_ok());
    f.memory.map(0xa000, PAGE_SIZE, Permissions::RW).unwrap();
    f.memory.write(0xa000, b"range member").unwrap();
    assert!(matches!(
        f.direct
            .start(
                1,
                [0x9000, 0, 0, 0, 0, 0],
                &mut f.memory,
                1,
                &Arc::downgrade(&f.wake),
                None
            )
            .unwrap(),
        IoAttempt::Complete(Ok(0))
    ));
    assert!(f.memory.validate_mapped(0x9000, PAGE_SIZE).is_err());
    assert!(f.memory.validate_mapped(0xa000, PAGE_SIZE).is_err());
    assert!(
        f.memory.validate_mapped(f.id, PAGE_SIZE).is_ok(),
        "native destroy does not search every surviving file alias"
    );
}
