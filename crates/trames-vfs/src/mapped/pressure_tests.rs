// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::Mutex;
use trames_memory::{
    CgroupMemoryContext, CgroupMemoryKind, CgroupMemoryTarget, CgroupPageCharge, Memory,
    MemoryCgroup, MemoryError, Permissions, SyncCompletion, SyncExecutor, SyncResource,
};

type Writeback = (Arc<dyn SyncResource>, Box<dyn SyncCompletion>);
#[derive(Default)]
struct Executor(Mutex<Vec<Writeback>>);
impl SyncExecutor for Executor {
    fn submit(&self, resource: Arc<dyn SyncResource>, done: Box<dyn SyncCompletion>) {
        self.0.lock().unwrap().push((resource, done));
    }
}
impl Executor {
    fn step(&self) {
        let (resource, done) = self.0.lock().unwrap().pop().expect("original writeback");
        let admission = resource
            .layout()
            .map(|layout| layout.write().try_enter().ok().unwrap());
        let result = resource.sync();
        drop(admission);
        done.complete(result);
    }
}
fn pending(
    result: std::result::Result<CgroupPageCharge, MemoryError>,
) -> Arc<trames_memory::PageWait> {
    match result {
        Err(MemoryError::Pending(fault)) => fault.wait,
        _ => panic!("allocation must retain pressure"),
    }
}
#[test]
fn dirty_mapping_reclaims_only_after_original_mm_and_last_byte_pin_retire() {
    pressure(false);
}
#[test]
fn another_mm_can_reload_and_dirty_canonical_bytes_before_original_pins_retire() {
    pressure(true);
}
fn pressure(reload: bool) {
    let directory = std::env::temp_dir().join(format!(
        "trames-mapped-pressure-{}-{}",
        std::process::id(),
        trames_memory::new_backing_identity()
    ));
    let mut v = Vfs::open_disk(&directory, Default::default()).unwrap();
    v.import_file(b"/file", vec![7; PAGE_SIZE as usize])
        .unwrap();
    let fd = v.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
    let executor = Arc::new(Executor::default());
    let _actor = crate::FileActorScope::enter_with_sync(
        Arc::new(CredentialState::new(v.credentials.clone())),
        v.pid,
        Some(executor.clone()),
    );
    let original = MemoryCgroup::new(None);
    original.set_limit(PAGE_SIZE as usize);
    let other = MemoryCgroup::new(None);
    let task = Arc::new(CgroupMemoryTarget::default());
    task.set(Some(original.clone()));
    let _task = task.scope();
    let accepted = CgroupMemoryContext::capture();
    let mut memory = Memory::default();
    let pages = v.mapping_pages(fd, 0, PAGE_SIZE, true, true).unwrap();
    let backing = pages[0].clone();
    memory
        .map_backed(PAGE_SIZE, pages, true, Permissions::RW, false)
        .unwrap();
    memory.write(PAGE_SIZE, &[42]).unwrap();
    // Original file pages can predate the first proc/native source binding.
    let report = memory.memory_report();
    report.bind_read_waker(Arc::new(|_| {}));
    let pin = backing.shared_page().expect("original physical byte pin");
    task.set(Some(other.clone()));
    let live = CgroupMemoryContext::capture();
    let _accepted = accepted.enter();
    let writeback = pending(CgroupPageCharge::new(CgroupMemoryKind::Anonymous));
    assert!(task.take_oom().is_none());
    assert_eq!(executor.0.lock().unwrap().len(), 1);
    executor.step();
    assert!(writeback.ready());
    assert_eq!(original.current(), PAGE_SIZE as usize);
    assert_eq!(original.reclaimed_bytes(), 0);
    let mut peer = Memory::default();
    if reload {
        let _live = live.enter();
        peer.map_backed(
            PAGE_SIZE,
            vec![backing.clone()],
            true,
            Permissions::RW,
            false,
        )
        .unwrap();
        peer.write(PAGE_SIZE, &[43]).unwrap();
        assert_eq!(other.current(), PAGE_SIZE as usize);
    }
    let checkpoint = pending(CgroupPageCharge::new(CgroupMemoryKind::Anonymous));
    assert!(report.has_requested_reads());
    assert!(memory.activate_proc_reads());
    assert!(checkpoint.ready());
    assert_eq!(
        original.current(),
        PAGE_SIZE as usize,
        "external bytes still own the original lease"
    );
    // At most one follow-up observes the actual invalidation epoch change.
    if let Err(MemoryError::Pending(fault)) = CgroupPageCharge::new(CgroupMemoryKind::Anonymous) {
        assert!(memory.activate_proc_reads());
        assert!(fault.wait.ready());
    }
    assert!(matches!(
        CgroupPageCharge::new(CgroupMemoryKind::Anonymous),
        Err(MemoryError::Limit)
    ));
    assert!(task.take_oom().is_some());
    drop(pin);
    assert_eq!(original.current(), 0);
    assert_eq!(original.reclaimed_bytes(), PAGE_SIZE as usize);
    let allocation = CgroupPageCharge::new(CgroupMemoryKind::Anonymous).unwrap();
    assert_eq!(other.current(), if reload { PAGE_SIZE as usize } else { 0 });
    drop(allocation);
    drop(_accepted);
    assert_eq!(
        memory.read_array::<1>(PAGE_SIZE).unwrap(),
        [if reload { 43 } else { 42 }]
    );
    assert_eq!(
        other.current(),
        PAGE_SIZE as usize,
        "reloaded physical bytes get their current first owner"
    );
    drop((memory, peer, backing));
    drop(v);
    assert_eq!(other.current(), 0);
    assert_eq!(
        other.reclaimed_bytes(),
        0,
        "new dirty bytes were never pressure-evicted"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
