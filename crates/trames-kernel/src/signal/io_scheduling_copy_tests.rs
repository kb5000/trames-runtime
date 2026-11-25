// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::signal::frame_copy_tests::Faults;
use trames_memory::{Permissions, PAGE_SIZE};
fn task(routes: &IoRoutes, id: u32, uid: u32) -> Signals {
    let signals = Signals {
        io_directory: routes.directory.clone(),
        ..Default::default()
    };
    signals.publish_policy(&routes.namespace, uid == 0);
    signals
        .io
        .scheduling
        .publish_credentials(&trames_vfs::Credentials::user(uid, uid));
    signals.io.scheduling.set_affinity(15);
    routes.directory.publish(&signals.io, id, id, id, uid, uid);
    signals
}
fn fixture() -> (Signals, IoRoutes, Faults) {
    let routes = IoRoutes::default();
    (task(&routes, 1, 0), routes, Faults::new(0x2000))
}
fn call(source: &Signals, routes: &IoRoutes, number: u32, args: [u64; 6]) -> Call {
    Call::new(source.io.clone(), routes.clone(), 4, number, args)
}
fn attr(memory: &mut impl CpuMemory, address: u64, size: u32, policy: u32, nice: i32) {
    let mut bytes = [0; 64];
    bytes[..4].copy_from_slice(&size.to_le_bytes());
    bytes[4..8].copy_from_slice(&policy.to_le_bytes());
    bytes[16..20].copy_from_slice(&nice.to_le_bytes());
    memory
        .write(address, &bytes[..size.min(64) as usize])
        .unwrap();
}
#[test]
fn setattr_import_keeps_supported_body_before_waiting_for_unknown_zero_tail() {
    let (source, routes, mut memory) = fixture();
    attr(&mut memory.memory, 0x1fd0, 64, 3, 7);
    let mut request = call(&source, &routes, 274, [0, 0x1fd0, 0, 0, 0, 0]);
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(source.io.scheduling.cpu(), (0, 0));
    memory
        .memory
        .write_array(0x1fe0, 19i32.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x1fd4, 5u32.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(source.io.scheduling.cpu(), (3, 7));
    source.io.scheduling.set_nice(11);
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(source.io.scheduling.nice(), 11);
}
#[test]
fn affinity_import_retains_fragments_then_waits_for_original_running_departure_once() {
    let (source, routes, mut memory) = fixture();
    let lease = source.io.lifecycle().enter(&source.io, 1);
    memory
        .memory
        .write_array(0x1ffc, 2u64.to_le_bytes())
        .unwrap();
    let mut request = call(
        &source,
        &routes,
        122,
        [0, 8 | (1u64 << 32), 0x1ffc, 0, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(source.io.scheduling.affinity(), 15);
    memory
        .memory
        .write_array(0x1ffc, 4u32.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(source.io.scheduling.affinity(), 2);
    assert!(!request.ready());
    let completion = request.completion().unwrap();
    assert!(!completion.finished());
    memory
        .memory
        .write_array(0x1ffc, 8u64.to_le_bytes())
        .unwrap();
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(source.io.scheduling.affinity(), 2);
    drop(lease);
    assert!(completion.finished());
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(source.io.scheduling.affinity(), 2);
}
#[test]
fn getter_snapshot_survives_original_target_release_and_pid_reuse() {
    let (source, routes, mut memory) = fixture();
    let target = task(&routes, 2, 1000);
    attr(&mut memory.memory, 0x1100, 48, 3, 7);
    routes
        .scheduling(
            &source.io,
            4,
            274,
            [2, 0x1100, 0, 0, 0, 0],
            &mut memory.memory,
        )
        .unwrap();
    let mut request = call(&source, &routes, 275, [2, 0x1ff8, 48, 0, 0, 0]);
    assert_eq!(request.check(&mut memory), None);
    let weak = Arc::downgrade(&target.io);
    drop(target);
    assert!(weak.upgrade().is_none());
    let replacement = task(&routes, 2, 1000);
    memory.memory.write_array(0x1ff8, [0x77; 8]).unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_array::<8>(0x1ff8).unwrap(), [0x77; 8]);
    assert_eq!(
        i32::from_le_bytes(memory.memory.read_array::<4>(0x2008).unwrap()),
        7
    );
    assert_eq!(replacement.io.scheduling.cpu(), (0, 0));
}
#[test]
fn getaffinity_keeps_actual_output_prefix_and_original_mask_after_a_later_update() {
    let (source, routes, mut memory) = fixture();
    let mut request = call(&source, &routes, 123, [0, 8, 0x1ffc, 0, 0, 0]);
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(
        memory.memory.read_array::<4>(0x1ffc).unwrap(),
        15u32.to_le_bytes()
    );
    source.io.scheduling.set_affinity(2);
    memory.memory.write_array(0x1ffc, [0x77; 4]).unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(8)));
    assert_eq!(memory.memory.read_array::<4>(0x1ffc).unwrap(), [0x77; 4]);
    assert_eq!(memory.memory.read_array::<4>(0x2000).unwrap(), [0; 4]);
    assert_eq!(source.io.scheduling.affinity(), 2);
}
#[test]
fn input_and_scalar_validation_errors_precede_task_lookup_and_owner_checks() {
    let (source, routes, mut memory) = fixture();
    for (number, args, error) in [
        (118, [999, 0x90000, 0, 0, 0, 0], 14),
        (118, [u32::MAX as u64, 0x90000, 0, 0, 0, 0], 22),
        (119, [999, u32::MAX as u64, 0x90000, 0, 0, 0], 22),
        (122, [999, 8, 0x90000, 0, 0, 0], 14),
        (123, [999, 7, 0x90000, 0, 0, 0], 22),
        (121, [999, 0, 0, 0, 0, 0], 22),
        (274, [999, 0x90000, 1, 0, 0, 0], 22),
        (274, [999, 0x90000, 0, 0, 0, 0], 14),
        (275, [999, 0x90000, 47, 0, 0, 0], 22),
    ] {
        assert_eq!(
            call(&source, &routes, number, args).check(&mut memory),
            Some(Err(Errno(error)))
        );
    }
    let unprivileged = task(&routes, 3, 1000);
    let _foreign = task(&routes, 4, 2000);
    assert_eq!(
        call(&unprivileged, &routes, 122, [4, 8, 0x90000, 0, 0, 0]).check(&mut memory),
        Some(Err(Errno(14)))
    );
    memory
        .memory
        .write_array(0x1100, 2u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        call(&unprivileged, &routes, 122, [4, 8, 0x1100, 0, 0, 0]).check(&mut memory),
        Some(Err(Errno(1)))
    );
}
#[test]
fn size_negotiation_waits_for_original_input_and_keeps_e2big_after_failed_size_store() {
    let (source, routes, mut memory) = fixture();
    attr(&mut memory.memory, 0x1fd0, 64, 3, 7);
    memory
        .memory
        .write_array(0x2000, 1u32.to_le_bytes())
        .unwrap();
    let mut request = call(&source, &routes, 274, [0, 0x1fd0, 0, 0, 0, 0]);
    assert_eq!(request.check(&mut memory), None);
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Err(Errno(7))));
    assert_eq!(
        memory.memory.read_array::<4>(0x1fd0).unwrap(),
        48u32.to_le_bytes()
    );
    assert_eq!(source.io.scheduling.cpu(), (0, 0));
    memory
        .memory
        .write_array(0x1100, 8u32.to_le_bytes())
        .unwrap();
    memory
        .memory
        .protect(0x1000, PAGE_SIZE, Permissions::R)
        .unwrap();
    assert_eq!(
        call(&source, &routes, 274, [0, 0x1100, 0, 0, 0, 0]).check(&mut memory),
        Some(Err(Errno(7)))
    );
    assert_eq!(
        routes.scheduling(
            &source.io,
            4,
            274,
            [0, 0x1100, 0, 0, 0, 0],
            &mut memory.memory
        ),
        Err(Errno(7))
    );
    assert_eq!(
        memory.memory.read_array::<4>(0x1100).unwrap(),
        8u32.to_le_bytes()
    );
}
#[test]
fn cancel_before_import_and_after_affinity_publication_neither_executes_nor_rolls_back() {
    for published in [false, true] {
        let (source, routes, mut memory) = fixture();
        let lease = source.io.lifecycle().enter(&source.io, 1);
        memory
            .memory
            .write_array(0x1ffc, 2u64.to_le_bytes())
            .unwrap();
        let mut request = call(&source, &routes, 122, [0, 8, 0x1ffc, 0, 0, 0]);
        assert_eq!(request.check(&mut memory), None);
        if published {
            memory.wait.finish();
            assert_eq!(request.check(&mut memory), None);
            assert_eq!(source.io.scheduling.affinity(), 2);
        }
        request.cancel();
        memory.wait.finish();
        drop(lease);
        assert_eq!(request.check(&mut memory), Some(Err(Errno(4))));
        assert_eq!(
            source.io.scheduling.affinity(),
            if published { 2 } else { 15 }
        );
    }
}
#[test]
fn permanent_query_output_error_retains_actual_prefix_without_resampling_target() {
    let (source, routes, mut memory) = fixture();
    source.io.scheduling.set_affinity(15);
    let mut request = call(&source, &routes, 123, [0, 8, 0x1ffc, 0, 0, 0]);
    assert_eq!(request.check(&mut memory), None);
    memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
    memory.wait.finish();
    source.io.scheduling.set_affinity(2);
    assert_eq!(request.check(&mut memory), Some(Err(Errno(14))));
    assert_eq!(
        memory.memory.read_array::<4>(0x1ffc).unwrap(),
        15u32.to_le_bytes()
    );
}
