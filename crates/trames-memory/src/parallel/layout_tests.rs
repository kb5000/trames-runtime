// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::Mutex;

struct File {
    layout: Arc<layout::Layout>,
    bytes: Mutex<[u8; PAGE_SIZE as usize]>,
    reads: AtomicU64,
    syncs: AtomicU64,
}
impl File {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            layout: Arc::default(),
            bytes: Mutex::new([0; PAGE_SIZE as usize]),
            reads: AtomicU64::new(0),
            syncs: AtomicU64::new(0),
        })
    }
    fn map(self: &Arc<Self>, memory: &mut Memory, base: u64, shared: bool) {
        memory
            .map_backed(base, vec![self.clone()], shared, Permissions::RW, false)
            .unwrap();
    }
}
impl PageBacking for File {
    fn layout(&self) -> Option<Arc<layout::Layout>> {
        Some(self.layout.clone())
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        Some((self.layout.identity(), 0))
    }
    fn check(&self, _: u64) -> Result<(), MemoryError> {
        Ok(())
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        out.copy_from_slice(&self.bytes.lock().unwrap()[offset..offset + out.len()]);
        Ok(())
    }
    fn write(&self, offset: usize, input: &[u8]) -> Result<(), MemoryError> {
        self.bytes.lock().unwrap()[offset..offset + input.len()].copy_from_slice(input);
        Ok(())
    }
    fn sync(&self) -> Result<(), MemoryError> {
        self.syncs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn sync_key(&self) -> Option<u64> {
        Some(self.layout.identity())
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

#[test]
fn writeback_capture_retains_original_shared_backings_across_unmap_and_replacement() {
    let original = File::new();
    let replacement = File::new();
    let mut memory = Memory::default();
    original.map(&mut memory, 0x1000, true);
    original.map(&mut memory, 0x2000, true);
    original.map(&mut memory, 0x3000, false);
    let mut registry = Registry::default();
    let mut view = memory.parallel_view(&mut registry).unwrap();
    view.write(0x1000, &[42]).unwrap();
    let work = CpuMemory::prepare_sync(&view, 0x1000, 3 * PAGE_SIZE)
        .unwrap()
        .unwrap();
    assert_eq!(original.syncs.load(Ordering::Relaxed), 0);
    drop(view);
    memory.commit_parallel().unwrap();
    memory.unmap(0x1000, 3 * PAGE_SIZE).unwrap();
    replacement.map(&mut memory, 0x1000, true);
    work.run().unwrap();
    assert_eq!(original.syncs.load(Ordering::Relaxed), 1);
    assert_eq!(replacement.syncs.load(Ordering::Relaxed), 0);
    let view = memory.parallel_view(&mut registry).unwrap();
    CpuMemory::prepare_sync(&view, 0x1000, PAGE_SIZE)
        .unwrap()
        .unwrap()
        .run()
        .unwrap();
    assert_eq!(
        replacement.syncs.load(Ordering::Relaxed),
        1,
        "index follows mapping replacement"
    );
}

#[test]
fn writeback_selection_preflights_holes_and_never_materializes_anonymous_or_private_bytes() {
    let file = File::new();
    let mut memory = Memory::default();
    file.map(&mut memory, 0x1000, true);
    file.map(&mut memory, 0x2000, false);
    memory.map(0x100000000, 1 << 36, Permissions::RW).unwrap();
    let mut registry = Registry::default();
    let view = memory.parallel_view(&mut registry).unwrap();
    let reads = file.reads.load(Ordering::Relaxed);
    let used = memory.resident_bytes();
    assert!(matches!(
        CpuMemory::prepare_sync(&view, 0x1000, 3 * PAGE_SIZE),
        Some(Err(MemoryError::Unmapped(0x3000)))
    ));
    assert!(CpuMemory::prepare_sync(&view, 0x2000, PAGE_SIZE)
        .unwrap()
        .unwrap()
        .is_empty());
    assert!(CpuMemory::prepare_sync(&view, 0x100000000, 1 << 36)
        .unwrap()
        .unwrap()
        .is_empty());
    assert_eq!(file.reads.load(Ordering::Relaxed), reads);
    assert_eq!(memory.resident_bytes(), used);
    assert_eq!(file.syncs.load(Ordering::Relaxed), 0);
    assert!(view.snapshot.anonymous.cached(0x100000000).is_none());
}

#[test]
fn layout_waits_for_commit_and_every_retained_view_generation() {
    let file = File::new();
    let mut memory = Memory::default();
    file.map(&mut memory, 0x1000, true);
    let mut registry = Registry::default();
    let mut old = memory.parallel_view(&mut registry).unwrap();
    old.write_array(0x1000, [7]).unwrap();
    memory.commit_retired_parallel().unwrap();
    let mut newer = memory.parallel_view(&mut registry).unwrap();
    let retained = newer.clone();
    let writer = file.layout.write();
    assert!(memory.parallel_view(&mut registry).is_none());
    assert_eq!(
        memory.parallel_layout_waits()[0].identity(),
        file.layout.identity()
    );
    old.write_array(0x1001, [8]).unwrap();
    newer.write_array(0x1002, [9]).unwrap();
    drop((old, newer));
    memory.commit_retired_parallel().unwrap();
    assert!(
        !writer.ready(),
        "retained external generation still owns bytes"
    );
    drop(retained);
    assert!(
        !writer.ready(),
        "last View return does not replace final mm commit"
    );
    memory.commit_parallel().unwrap();
    let exclusive = writer.try_enter().ok().unwrap();
    assert_eq!(&file.bytes.lock().unwrap()[..3], &[7, 8, 9]);
    assert!(memory.parallel_view(&mut registry).is_none());
    drop(exclusive);
    assert!(memory.parallel_view(&mut registry).is_some());
}

#[test]
fn cold_aliases_forks_and_private_file_views_cannot_publish_during_mutation() {
    for shared in [false, true] {
        let file = File::new();
        let unrelated = File::new();
        let mut original = Memory::default();
        file.map(&mut original, 0x1000, shared);
        let mut registry = Registry::default();
        drop(original.parallel_view(&mut registry).unwrap());
        original.commit_parallel().unwrap();
        let mut child = original.try_fork().unwrap();
        let mut cold = Memory::default();
        file.map(&mut cold, 0x8000, shared);
        let mut foreign = Memory::default();
        unrelated.map(&mut foreign, 0x1000, true);
        let writer = file.layout.write();
        assert_eq!(file.layout.readers().len(), 1);
        assert!(file.layout.readers()[0].same_resource(&original.memory_report()));
        original.commit_parallel().unwrap();
        let exclusive = writer.try_enter().ok().unwrap();
        let reads = file.reads.load(Ordering::Relaxed);
        for memory in [&mut original, &mut child, &mut cold] {
            assert!(memory.parallel_view(&mut registry).is_none());
        }
        assert_eq!(
            file.reads.load(Ordering::Relaxed),
            reads,
            "admission must precede provider metadata/page-in"
        );
        assert!(foreign.parallel_view(&mut registry).is_some());
        drop(exclusive);
        for memory in [&mut original, &mut child, &mut cold] {
            drop(memory.parallel_view(&mut registry).unwrap());
        }
        assert_eq!(file.layout.readers().len(), 3);
    }
}

#[test]
fn incremental_unmap_and_replacement_update_backing_admission_membership() {
    let first = File::new();
    let second = File::new();
    let mut memory = Memory::default();
    first.map(&mut memory, 0x1000, true);
    first.map(&mut memory, 0x2000, true);
    let mut registry = Registry::default();
    drop(memory.parallel_view(&mut registry).unwrap());
    memory.commit_parallel().unwrap();
    memory.unmap(0x1000, PAGE_SIZE).unwrap();
    second.map(&mut memory, 0x1000, true);
    drop(memory.parallel_view(&mut registry).unwrap());
    memory.commit_parallel().unwrap();
    assert_eq!(first.layout.readers().len(), 1);
    assert_eq!(second.layout.readers().len(), 1);
    memory.unmap(0x2000, PAGE_SIZE).unwrap();
    drop(memory.parallel_view(&mut registry).unwrap());
    memory.commit_parallel().unwrap();
    assert!(first.layout.write().ready(), "last alias was unmapped");
    assert!(
        !second.layout.write().ready(),
        "replacement still published"
    );
}
