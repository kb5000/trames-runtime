// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-ready output that faults only at the provider's actual store boundary.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use trames_memory::{
    Memory, MemoryError, PageBacking, PageSource, PageWait, Permissions, SharedPage, PAGE_SIZE,
};

struct Gate {
    bytes: Arc<SharedPage>,
    ready: AtomicBool,
    wait: Arc<PageWait>,
    identity: u64,
}
impl Gate {
    fn finish(&self) {
        self.ready.store(true, Ordering::Relaxed);
        self.wait.finish();
    }
}
struct Source(Arc<SharedPage>);
impl PageSource for Source {
    fn load(&self) -> Result<Arc<SharedPage>, MemoryError> {
        Ok(self.0.clone())
    }
}
impl PageBacking for Gate {
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.bytes.copy_read(offset, bytes);
        Ok(())
    }
    fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
        if !self.ready.load(Ordering::Relaxed) {
            return Err(self.wait.fault(0));
        }
        self.bytes.copy_write(offset, bytes);
        Ok(())
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.identity, 0))
    }
    fn page_source(&self) -> Option<Arc<dyn PageSource>> {
        Some(Arc::new(Source(self.bytes.clone())))
    }
    fn cpu_borrow_safe(&self) -> bool {
        true
    }
    fn sync(&self) -> Result<(), MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
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
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
struct Fixture {
    aio: Aio,
    direct: DirectSyscalls,
    memory: Memory,
    gate: Arc<Gate>,
    _target: Arc<dyn IoWake>,
    wait: PendingIo,
    id: u64,
    context: Arc<Context>,
}
impl Fixture {
    fn new() -> Self {
        let vfs = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events());
        let mut memory = Memory::default();
        memory.map(0x1000, 2 * PAGE_SIZE, Permissions::RW).unwrap();
        let gate = Arc::new(Gate {
            bytes: Arc::new(SharedPage::new([0; PAGE_SIZE as usize])),
            ready: false.into(),
            wait: Arc::default(),
            identity: trames_memory::new_backing_identity(),
        });
        memory
            .map_backed(0x3000, vec![gate.clone()], true, Permissions::RW, false)
            .unwrap();
        let id = memory.find_free(0x7fff_fc00_0000, PAGE_SIZE).unwrap();
        let target: Arc<dyn IoWake> = Arc::new(Wake);
        let IoAttempt::Blocked(wait) = direct
            .start(
                0,
                [8, 0x2ffc, 0, 0, 0, 0],
                &mut memory,
                1,
                &Arc::downgrade(&target),
                None,
            )
            .unwrap()
        else {
            panic!("store, rather than read/preflight, waits")
        };
        let context = aio
            .0
            .contexts
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        assert_eq!(
            memory.read_array::<4>(0x2ffc).unwrap(),
            id.to_le_bytes()[..4]
        );
        assert_eq!(context.state.lock().unwrap().users, 1);
        Self {
            aio,
            direct,
            memory,
            gate,
            _target: target,
            wait,
            id,
            context,
        }
    }
}
#[test]
fn setup_store_wait_keeps_the_original_context_handle_and_copied_prefix() {
    let mut f = Fixture::new();
    f.memory.write(0x2ffc, b"KEEP").unwrap();
    f.gate.finish();
    assert!(matches!(
        f.direct.resume(f.wait, &mut f.memory),
        IoAttempt::Complete(Ok(0))
    ));
    assert_eq!(f.memory.read_array::<4>(0x2ffc).unwrap(), *b"KEEP");
    assert_eq!(
        f.memory.read_array::<4>(0x3000).unwrap(),
        f.id.to_le_bytes()[4..]
    );
    assert!(Arc::ptr_eq(
        f.aio.0.contexts.lock().unwrap().values().next().unwrap(),
        &f.context
    ));
    assert_eq!(f.context.state.lock().unwrap().users, 0);
    assert!(!f.memory.mapping_cleanup_pending());
    assert!(f.memory.validate_mapped(f.id, PAGE_SIZE).is_ok());
}
#[test]
fn failed_setup_output_removes_its_original_allocation_before_returning_fault() {
    let mut f = Fixture::new();
    f.memory.unmap(0x3000, PAGE_SIZE).unwrap();
    assert!(matches!(
        f.direct.resume(f.wait, &mut f.memory),
        IoAttempt::Complete(Err(Errno(14)))
    ));
    assert!(f.aio.0.contexts.lock().unwrap().is_empty());
    assert!(f.context.state.lock().unwrap().dead);
    assert_eq!(f.context.state.lock().unwrap().users, 0);
    assert!(f.memory.validate_mapped(f.id, PAGE_SIZE).is_err());
    assert!(!f.memory.mapping_cleanup_pending());
}
#[test]
fn abandoned_setup_reaps_its_recorded_moved_range_and_preserves_the_old_address() {
    let mut f = Fixture::new();
    f.memory
        .remap(f.id, PAGE_SIZE, 0x9000, PAGE_SIZE, false)
        .unwrap();
    f.memory.map(f.id, PAGE_SIZE, Permissions::RW).unwrap();
    f.memory.write(f.id, b"replacement").unwrap();
    drop(f.wait);
    assert!(f.aio.0.contexts.lock().unwrap().is_empty());
    assert!(f.memory.mapping_cleanup_pending());
    assert!(f.memory.reap_mapping_cleanup().unwrap());
    assert!(f.memory.validate_mapped(0x9000, PAGE_SIZE).is_err());
    assert_eq!(f.memory.read_array::<11>(f.id).unwrap(), *b"replacement");
}
#[test]
fn abandoned_setup_unmaps_a_replacement_inside_the_recorded_context_range() {
    let mut f = Fixture::new();
    f.memory
        .map_fixed(f.id, PAGE_SIZE, Permissions::RW)
        .unwrap();
    f.memory.write(f.id, b"replacement").unwrap();
    drop(f.wait);
    assert!(f.memory.reap_mapping_cleanup().unwrap());
    assert!(f.memory.validate_mapped(f.id, PAGE_SIZE).is_err());
}
#[test]
fn a_setup_user_released_after_destroy_cannot_unmap_the_range_twice() {
    for finish in [false, true] {
        let mut f = Fixture::new();
        let target = Arc::downgrade(&f._target);
        let IoAttempt::Blocked(destroy) = f
            .direct
            .start(1, [f.id, 0, 0, 0, 0, 0], &mut f.memory, 2, &target, None)
            .unwrap()
        else {
            panic!("destroy waits for the setup user that is copying its handle")
        };
        f.memory.map(f.id, PAGE_SIZE, Permissions::RW).unwrap();
        f.memory.write(f.id, b"later").unwrap();
        if finish {
            f.gate.finish();
            assert!(matches!(
                f.direct.resume(f.wait, &mut f.memory),
                IoAttempt::Complete(Ok(0))
            ));
        } else {
            drop(f.wait);
        }
        assert!(matches!(
            f.direct.resume(destroy, &mut f.memory),
            IoAttempt::Complete(Ok(0))
        ));
        assert!(!f.memory.mapping_cleanup_pending());
        assert_eq!(f.memory.read_array::<5>(f.id).unwrap(), *b"later");
    }
}
#[test]
fn abandoned_setup_waits_for_existing_views_and_cannot_publish_a_new_view() {
    let mut f = Fixture::new();
    let view = f.memory.parallel_view(&mut Default::default()).unwrap();
    drop(f.wait);
    assert!(!f.memory.reap_mapping_cleanup().unwrap());
    assert!(f.memory.parallel_view(&mut Default::default()).is_none());
    assert!(f.memory.current_parallel_view().is_none());
    assert_eq!(view.read_array::<4>(f.id).unwrap(), [0; 4]);
    drop(view);
    assert!(f.memory.reap_mapping_cleanup().unwrap());
    assert!(f.memory.validate_mapped(f.id, PAGE_SIZE).is_err());
    assert!(f.memory.parallel_view(&mut Default::default()).is_some());
}
#[test]
fn context_allocation_failure_precedes_handle_output_permissions() {
    let vfs = trames_vfs::Vfs::default();
    let aio = Aio::default();
    let direct =
        DirectSyscalls::new(vfs.direct_descriptors()).with_aio(aio.clone(), vfs.native_events());
    let target: Arc<dyn IoWake> = Arc::new(Wake);
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    for _ in 0..128 {
        memory.write_array(0x1000, 0u64.to_le_bytes()).unwrap();
        aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
    }
    memory.write_array(0x1000, 0u64.to_le_bytes()).unwrap();
    memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
    assert!(matches!(
        direct
            .start(
                0,
                [8, 0x1000, 0, 0, 0, 0],
                &mut memory,
                1,
                &Arc::downgrade(&target),
                None
            )
            .unwrap(),
        IoAttempt::Complete(Err(Errno(11)))
    ));
}
