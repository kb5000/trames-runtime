// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::signal::frame_copy_tests::Faults;
use std::{sync::Arc, time::Duration};
fn fixture() -> (Arc<IoTask>, Children, IoRoutes, Faults) {
    let task = Arc::new(IoTask::default());
    let routes = IoRoutes::default();
    routes.directory.publish(&task, 42, 42, 42, 0, 0);
    task.bind_thread_addresses(&Arc::new(trames_execution::ThreadAddresses::default()));
    (task, Children::default(), routes, Faults::new(0x2000))
}
#[test]
fn rusage_retains_original_cpu_snapshot_and_completed_prefix_across_page_wait() {
    let (task, children, routes, mut memory) = fixture();
    task.proc_view.account(Duration::new(2, 250_000_000), 0);
    let mut call = Call::new(
        165,
        [0, 0x1ff8, 0, 0, 0, 0],
        Instant::now(),
        &task,
        &children,
        &routes,
    )
    .unwrap();
    assert_eq!(call.check(&mut memory), None);
    assert!(!call.ready());
    assert_eq!(memory.memory.read_u64(0x1ff8).unwrap(), 2);
    task.proc_view.account(Duration::new(9, 123), 1);
    memory
        .memory
        .write_array(0x1ff8, 99u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_u64(0x1ff8).unwrap(), 99);
    assert_eq!(memory.memory.read_u64(0x2000).unwrap(), 250_000);
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
}
#[test]
fn rusage_invalid_who_precedes_output_and_permanent_error_keeps_actual_prefix() {
    let (task, children, routes, mut memory) = fixture();
    assert_eq!(
        Call::new(
            165,
            [99, 0x2000, 0, 0, 0, 0],
            Instant::now(),
            &task,
            &children,
            &routes
        )
        .err(),
        Some(Errno(22))
    );
    task.proc_view.account(Duration::new(2, 250_000_000), 0);
    let mut call = Call::new(
        165,
        [1, 0x1ff8, 0, 0, 0, 0],
        Instant::now(),
        &task,
        &children,
        &routes,
    )
    .unwrap();
    assert_eq!(call.check(&mut memory), None);
    memory
        .memory
        .unmap(0x2000, trames_memory::PAGE_SIZE)
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Err(Errno(14))));
    assert_eq!(memory.memory.read_u64(0x1ff8).unwrap(), 2);
}
#[test]
fn times_keeps_struct_snapshot_but_samples_return_clock_after_copy_completion() {
    let (task, children, routes, mut memory) = fixture();
    task.proc_view.account(Duration::from_millis(2500), 0);
    let started = Instant::now() - Duration::from_secs(2);
    let before = usage::ticks(started.elapsed());
    let mut call = Call::new(
        153,
        [0x1ff8, 0, 0, 0, 0, 0],
        started,
        &task,
        &children,
        &routes,
    )
    .unwrap();
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(memory.memory.read_u64(0x1ff8).unwrap(), 250);
    task.proc_view.account(Duration::from_secs(9), 1);
    memory
        .memory
        .write_array(0x1ff8, 99u64.to_le_bytes())
        .unwrap();
    std::thread::sleep(Duration::from_millis(30));
    memory.wait.finish();
    let value = call.check(&mut memory).unwrap().unwrap();
    assert!(value >= before + 2);
    assert_eq!(call.check(&mut memory), Some(Ok(value)));
    assert_eq!(memory.memory.read_u64(0x1ff8).unwrap(), 99);
    assert_eq!(memory.memory.read_array::<24>(0x2000).unwrap(), [0; 24]);
    let mut count = Call::new(153, [0; 6], started, &task, &children, &routes).unwrap();
    assert!(count.check(&mut memory).unwrap().unwrap() >= value);
}
#[test]
fn robust_list_copies_length_first_and_retains_original_head_after_state_change() {
    let (task, children, routes, mut memory) = fixture();
    let addresses = task.thread_addresses().unwrap();
    addresses.set_robust(0x1234);
    let mut call = Call::new(
        100,
        [0, 0x2000, 0x1100, 0, 0, 0],
        Instant::now(),
        &task,
        &children,
        &routes,
    )
    .unwrap();
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 24);
    addresses.set_robust(0x9999);
    memory
        .memory
        .write_array(0x1100, 99u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 99);
    assert_eq!(memory.memory.read_u64(0x2000).unwrap(), 0x1234);
}
#[test]
fn robust_length_failure_does_not_write_head_and_aliasing_preserves_native_store_order() {
    let (task, children, routes, mut memory) = fixture();
    task.thread_addresses().unwrap().set_robust(0x1234);
    for direct in [false, true] {
        memory
            .memory
            .write_array(0x1100, 99u64.to_le_bytes())
            .unwrap();
        let args = [0, 0x1100, 0x90000, 0, 0, 0];
        let result = if direct {
            routes.robust_list(&task, 100, args, &mut memory.memory)
        } else {
            Call::new(100, args, Instant::now(), &task, &children, &routes)
                .unwrap()
                .check(&mut memory.memory)
                .unwrap()
        };
        assert_eq!(result, Err(Errno(14)));
        assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 99);
        let args = [0, 0x1100, 0x1100, 0, 0, 0];
        let result = if direct {
            routes.robust_list(&task, 100, args, &mut memory.memory)
        } else {
            Call::new(100, args, Instant::now(), &task, &children, &routes)
                .unwrap()
                .check(&mut memory.memory)
                .unwrap()
        };
        assert_eq!(result, Ok(0));
        assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 0x1234);
    }
}
#[test]
fn robust_scalar_store_crossing_a_page_is_not_split_into_independent_stores() {
    let (task, children, routes, mut memory) = fixture();
    task.thread_addresses().unwrap().set_robust(0x1234);
    memory.memory.write_array(0x1ffc, [0x77; 4]).unwrap();
    memory
        .memory
        .write_array(0x1100, 99u64.to_le_bytes())
        .unwrap();
    let mut call = Call::new(
        100,
        [0, 0x1100, 0x1ffc, 0, 0, 0],
        Instant::now(),
        &task,
        &children,
        &routes,
    )
    .unwrap();
    assert_eq!(call.check(&mut memory), None);
    assert_eq!(memory.memory.read_array::<4>(0x1ffc).unwrap(), [0x77; 4]);
    assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 99);
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_u64(0x1ffc).unwrap(), 24);
    assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 0x1234);
}
#[test]
fn cancellation_releases_snapshot_and_never_repeats_completed_query_stores() {
    let (task, children, routes, mut memory) = fixture();
    task.thread_addresses().unwrap().set_robust(0x1234);
    let mut call = Call::new(
        100,
        [0, 0x2000, 0x1100, 0, 0, 0],
        Instant::now(),
        &task,
        &children,
        &routes,
    )
    .unwrap();
    assert_eq!(call.check(&mut memory), None);
    call.cancel();
    memory.wait.finish();
    assert_eq!(call.check(&mut memory), Some(Err(Errno(4))));
    assert_eq!(memory.memory.read_u64(0x1100).unwrap(), 24);
    assert_eq!(memory.memory.read_u64(0x2000).unwrap(), 0);
}
