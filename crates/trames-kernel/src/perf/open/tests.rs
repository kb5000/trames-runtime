// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::signal::{frame_copy_tests::Faults, Signals};
use std::time::Duration;
use trames_memory::{Permissions, PAGE_SIZE};
fn task(routes: &IoRoutes, id: u32) -> Signals {
    let signals = Signals {
        io_directory: routes.directory.clone(),
        ..Default::default()
    };
    signals.publish_policy(&routes.namespace, true);
    routes.directory.publish(&signals.io, id, id, id, 0, 0);
    signals
}
fn fixture() -> (Signals, IoRoutes, trames_vfs::Vfs, Faults) {
    let routes = IoRoutes::default();
    let source = task(&routes, 1);
    let vfs = trames_vfs::Vfs::default();
    source.io.credentials().publish_pidfd_resources(
        &vfs.credentials,
        &vfs.shared_files(),
        vfs.dumpable_state(),
        vfs.pidfd_namespace_source(),
    );
    (source, routes, vfs, Faults::new(0x2000))
}
fn attr(memory: &mut impl CpuMemory, address: u64, size: u32, format: u64) {
    let mut bytes = [0; 144];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&size.to_le_bytes());
    bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&format.to_le_bytes());
    memory.write_array(address, bytes).unwrap();
}
fn call(source: &Signals, routes: &IoRoutes, vfs: &trames_vfs::Vfs, args: [u64; 6]) -> OpenCall {
    OpenCall::new(
        source.io.clone(),
        routes.clone(),
        vfs.fd_flags_snapshot(),
        vfs.descriptor_factory(),
        args,
        4,
    )
}
fn next_fd(vfs: &mut trames_vfs::Vfs) -> u32 {
    let fd = vfs.open_at(-100, b"/probe", 0x42, 0o600).unwrap();
    vfs.close(fd).unwrap();
    fd
}
fn counter(vfs: &mut trames_vfs::Vfs, fd: u32) -> u64 {
    u64::from_le_bytes(vfs.read(fd, 8).unwrap().try_into().unwrap())
}
#[test]
fn negative_task_pid_and_cgroup_fd_follow_their_original_resource_lookups() {
    let (source, routes, vfs, mut memory) = fixture();
    attr(&mut memory.memory, 0x1100, 136, 0);
    for (pid, cpu, flags, error) in [(-2i32, -1i32, 0, 3), (-1, 0, 4, 22), (-2, 0, 4, 9)] {
        let mut request = call(
            &source,
            &routes,
            &vfs,
            [0x1100, pid as u64, cpu as u64, u64::MAX, flags, 0],
        );
        assert_eq!(request.check(&mut memory), Some(Err(Errno(error))));
    }
}
#[test]
fn attr_body_retains_copied_prefix_and_creates_one_event_only_after_input_completes() {
    let (source, routes, mut vfs, mut memory) = fixture();
    let expected = next_fd(&mut vfs);
    attr(&mut memory.memory, 0x1ff0, 136, 0);
    let mut request = call(
        &source,
        &routes,
        &vfs,
        [0x1ff0, 0, u64::MAX, u64::MAX, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(next_fd(&mut vfs), expected);
    memory
        .memory
        .write_array(0x1ff8, 9u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    let fd = request.check(&mut memory).unwrap().unwrap() as u32;
    assert_eq!(fd, expected);
    source.io.proc_view.account(Duration::from_nanos(100), 0);
    assert_eq!(counter(&mut vfs, fd), 100);
    vfs.close(fd).unwrap();
    assert_eq!(next_fd(&mut vfs), fd);
    assert_eq!(request.check(&mut memory), Some(Ok(fd as u64)));
    assert_eq!(next_fd(&mut vfs), fd);
}
#[test]
fn supported_attr_body_is_kept_before_waiting_for_future_tail() {
    let (source, routes, mut vfs, mut memory) = fixture();
    attr(&mut memory.memory, 0x1f78, 144, 0);
    let mut request = call(
        &source,
        &routes,
        &vfs,
        [0x1f78, 0, u64::MAX, u64::MAX, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    memory
        .memory
        .write_array(0x1f80, 9u64.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    let fd = request.check(&mut memory).unwrap().unwrap() as u32;
    source.io.proc_view.account(Duration::from_nanos(73), 0);
    assert_eq!(counter(&mut vfs, fd), 73);
}
#[test]
fn size_hint_uses_only_size_word_and_e2big_survives_failed_hint_store() {
    let (source, routes, mut vfs, mut memory) = fixture();
    let expected = next_fd(&mut vfs);
    memory
        .memory
        .write_array(0x3000, 8u32.to_le_bytes())
        .unwrap();
    let mut request = call(
        &source,
        &routes,
        &vfs,
        [0x2ffc, 0, u64::MAX, u64::MAX, 0, 0],
    );
    assert_eq!(request.check(&mut memory), Some(Err(Errno(7))));
    assert!(!memory.wait.ready());
    assert_eq!(
        memory.memory.read_array::<4>(0x3000).unwrap(),
        136u32.to_le_bytes()
    );
    assert_eq!(next_fd(&mut vfs), expected);
    attr(&mut memory.memory, 0x1100, 8, 0);
    memory
        .memory
        .protect(0x1000, PAGE_SIZE, Permissions::R)
        .unwrap();
    assert_eq!(
        call(
            &source,
            &routes,
            &vfs,
            [0x1100, 0, u64::MAX, u64::MAX, 0, 0]
        )
        .check(&mut memory),
        Some(Err(Errno(7)))
    );
    assert_eq!(Attr::read(&mut memory.memory, 0x1100).err(), Some(Errno(7)));
    assert_eq!(
        memory.memory.read_array::<4>(0x1104).unwrap(),
        8u32.to_le_bytes()
    );
}
#[test]
fn cancellation_and_permanent_input_failure_leave_no_event_or_descriptor_reservation() {
    for cancelled in [false, true] {
        let (source, routes, mut vfs, mut memory) = fixture();
        let expected = next_fd(&mut vfs);
        attr(&mut memory.memory, 0x1ff0, 136, 0);
        let mut request = call(
            &source,
            &routes,
            &vfs,
            [0x1ff0, 0, u64::MAX, u64::MAX, 0, 0],
        );
        assert_eq!(request.check(&mut memory), None);
        if cancelled {
            request.cancel();
        } else {
            memory.memory.unmap(0x2000, PAGE_SIZE).unwrap();
        }
        memory.wait.finish();
        assert_eq!(
            request.check(&mut memory),
            Some(Err(Errno(if cancelled { 4 } else { 14 })))
        );
        assert_eq!(next_fd(&mut vfs), expected);
    }
}
#[test]
fn group_fd_is_looked_up_after_attr_copy_and_joins_replacement_original_event() {
    let (source, routes, mut vfs, mut memory) = fixture();
    attr(&mut memory.memory, 0x1100, 64, 8);
    let leader_attr = Attr::read(&mut memory.memory, 0x1100).unwrap();
    let fd = vfs
        .descriptor_factory()
        .perf_event(
            leader_attr.clone(),
            source.io.proc_view.perf_clock(),
            None,
            false,
        )
        .unwrap();
    attr(&mut memory.memory, 0x1ff0, 136, 0);
    let mut request = call(
        &source,
        &routes,
        &vfs,
        [0x1ff0, 0, u64::MAX, fd as u64, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    vfs.close(fd).unwrap();
    assert_eq!(
        vfs.descriptor_factory()
            .perf_event(leader_attr, source.io.proc_view.perf_clock(), None, false)
            .unwrap(),
        fd
    );
    memory.wait.finish();
    let child = request.check(&mut memory).unwrap().unwrap() as u32;
    assert_ne!(child, fd);
    let bytes = vfs.read(fd, 32).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()), 2);
}
#[test]
fn target_pid_is_resolved_after_attr_import_and_event_keeps_that_original_clock() {
    let (source, routes, mut vfs, mut memory) = fixture();
    let target = task(&routes, 2);
    attr(&mut memory.memory, 0x1ff0, 136, 0);
    let mut request = call(
        &source,
        &routes,
        &vfs,
        [0x1ff0, 2, u64::MAX, u64::MAX, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    let weak = Arc::downgrade(&target.io);
    drop(target);
    assert!(weak.upgrade().is_none());
    let replacement = task(&routes, 2);
    memory.wait.finish();
    let fd = request.check(&mut memory).unwrap().unwrap() as u32;
    source.io.proc_view.account(Duration::from_nanos(100), 0);
    assert_eq!(counter(&mut vfs, fd), 0);
    replacement.io.proc_view.account(Duration::from_nanos(7), 1);
    assert_eq!(counter(&mut vfs, fd), 7);
}
#[test]
fn descriptor_limit_precedes_group_lookup_and_failed_lookup_releases_its_slot() {
    let (source, routes, mut vfs, mut memory) = fixture();
    let expected = next_fd(&mut vfs);
    attr(&mut memory.memory, 0x1100, 136, 0);
    vfs.set_descriptor_limit(0);
    let args = [0x1100, 0, u64::MAX, 999, 0, 0];
    assert_eq!(
        call(&source, &routes, &vfs, args).check(&mut memory),
        Some(Err(Errno(24)))
    );
    vfs.set_descriptor_limit(expected + 1);
    assert_eq!(
        call(&source, &routes, &vfs, args).check(&mut memory),
        Some(Err(Errno(9)))
    );
    let mut request = call(
        &source,
        &routes,
        &vfs,
        [0x1100, 0, u64::MAX, u64::MAX, 0, 0],
    );
    assert_eq!(request.check(&mut memory), Some(Ok(expected as u64)));
}
