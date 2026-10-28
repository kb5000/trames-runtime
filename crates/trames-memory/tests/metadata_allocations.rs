// SPDX-License-Identifier: GPL-3.0-or-later
//! Mapping, fork and publication must not need a guest-sized host allocation.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
use trames_memory::{parallel::Registry, CpuMemory, Memory, NativeMemory, Permissions, PAGE_SIZE};

struct MeasuredAllocator;
thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}
fn record(size: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(previous) = largest.get() {
            largest.set(Some(previous.max(size)));
            TOTAL.with(|total| total.set(total.get() + size));
        }
    });
}
// SAFETY: every request is forwarded unchanged to System, with only a
// nonallocating, thread-local measurement of its requested size.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(pointer, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

fn small_allocations<T>(operation: impl FnOnce() -> T) -> T {
    LARGEST.set(Some(0));
    let result = operation();
    let largest = LARGEST.replace(None).unwrap();
    assert!(
        largest <= 128 * 1024,
        "contiguous metadata allocation: {largest}"
    );
    result
}

#[test]
fn large_sparse_vm_fork_and_worker_publication_use_small_allocations() {
    let mut memory = Memory::new(128 << 20);
    small_allocations(|| memory.map(0, 64 << 20, Permissions::RW).unwrap());
    // Cross a metadata block boundary, then publish, fork and reuse slots.
    let address = 255 * PAGE_SIZE;
    memory.write_array(address, [17u8]).unwrap();
    memory.write_array(address + PAGE_SIZE, [23u8]).unwrap();
    memory
        .copy_with(address + PAGE_SIZE, address, 1, |d, s| d.copy_from_slice(s))
        .unwrap();
    assert_eq!(memory.read_array::<1>(address + PAGE_SIZE).unwrap(), [17]);
    memory.write_array(address + PAGE_SIZE, [23u8]).unwrap();
    let mut registry = Registry::default();
    let view = small_allocations(|| memory.parallel_view(&mut registry).unwrap());
    assert_eq!(view.read_array::<1>(address).unwrap(), [17]);
    assert_eq!(view.read_array::<1>(address + PAGE_SIZE).unwrap(), [23]);
    drop(view);
    let mut child = small_allocations(|| memory.clone());
    child.write_array(address, [99u8]).unwrap();
    assert_eq!(memory.read_array::<1>(address).unwrap(), [17]);
    small_allocations(|| {
        memory.unmap(address, 2 * PAGE_SIZE).unwrap();
        memory.map(address, 2 * PAGE_SIZE, Permissions::R).unwrap();
    });
    let view = small_allocations(|| memory.parallel_view(&mut registry).unwrap());
    assert_eq!(view.read_array::<1>(address).unwrap(), [0]);
    assert!(!view.native_writable_range(address, 1).unwrap());
}

#[test]
fn untouched_gib_mapping_and_worker_snapshots_have_bounded_total_metadata() {
    let mut memory = Memory::default();
    let base = 1 << 32;
    let len = 1 << 30;
    let mut registry = Registry::default();
    registry.use_hardware();
    memory.prepare_hardware().unwrap();
    TOTAL.set(0);
    small_allocations(|| {
        memory.map(base, len, Permissions::RW).unwrap();
        drop(memory.parallel_view(&mut registry).unwrap());
        memory
            .protect(base + PAGE_SIZE, len - 2 * PAGE_SIZE, Permissions::R)
            .unwrap();
        drop(memory.parallel_view(&mut registry).unwrap());
    });
    assert!(
        TOTAL.get() < 128 * 1024,
        "untouched metadata allocated {} bytes",
        TOTAL.get()
    );
    assert_eq!(memory.resident_bytes(), 0);
}
