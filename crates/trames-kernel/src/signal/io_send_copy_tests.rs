// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::signal::frame_copy_tests::Faults;
struct Task {
    signals: Signals,
    _child: Arc<crate::children::Child>,
}
fn task(routes: &IoRoutes, id: u32) -> Task {
    let mut signals = Signals {
        io_directory: routes.directory.clone(),
        ..Default::default()
    };
    signals.publish_policy(&routes.namespace, true);
    routes.directory.publish(&signals.io, id, id, id, 0, 0);
    signals.set_mask(1 << 34);
    let child = Arc::new(crate::children::Child::default());
    signals.io.lifecycle().bind(&child, None, id, 0);
    Task {
        signals,
        _child: child,
    }
}
fn fixture() -> (Task, Task, IoRoutes, trames_vfs::Vfs, Faults) {
    let routes = IoRoutes::default();
    let source = task(&routes, 1);
    let target = task(&routes, 2);
    (
        source,
        target,
        routes,
        trames_vfs::Vfs::default(),
        Faults::new(0x2000),
    )
}
fn info(memory: &mut impl CpuMemory, address: u64, signo: u32, code: i32, value: u64) {
    let mut bytes = [0; 128];
    bytes[..4].copy_from_slice(&signo.to_le_bytes());
    bytes[8..12].copy_from_slice(&code.to_le_bytes());
    bytes[16..20].copy_from_slice(&123u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&456u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&value.to_le_bytes());
    memory.write_array(address, bytes).unwrap();
}
#[test]
fn queued_siginfo_keeps_accepted_header_and_enqueues_once_after_complete_input() {
    for number in [138, 240] {
        let (source, target, routes, vfs, mut memory) = fixture();
        info(&mut memory.memory, 0x1ff0, 54, -1, 0x1234);
        let args = if number == 138 {
            [2, 35, 0x1ff0, 0, 0, 0]
        } else {
            [2 | (1u64 << 32), 2 | (1u64 << 32), 35, 0x1ff0, 0, 0]
        };
        let mut request = Call::new(
            source.signals.io.clone(),
            routes,
            vfs.fd_flags_snapshot(),
            number,
            args,
        );
        assert_eq!(request.check(&mut memory), None);
        assert_eq!(target.signals.pending_bits(), 0);
        memory
            .memory
            .write_array(0x1ff8, (-6i32).to_le_bytes())
            .unwrap();
        memory.wait.finish();
        assert_eq!(request.check(&mut memory), Some(Ok(0)));
        let (_, received) = target.signals.io.dequeue(1 << 34).unwrap();
        let user = received.user.unwrap();
        assert_eq!(i32::from_le_bytes(user[8..12].try_into().unwrap()), -1);
        assert_eq!(u64::from_le_bytes(user[24..32].try_into().unwrap()), 0x1234);
        assert_eq!(u32::from_le_bytes(user[..4].try_into().unwrap()), 35);
        assert_eq!(request.check(&mut memory), Some(Ok(0)));
        assert!(target.signals.io.dequeue(1 << 34).is_none());
    }
}
#[test]
fn unknown_layout_keeps_original_body_while_copying_expansion_before_send_validation() {
    let (source, _target, routes, vfs, mut memory) = fixture();
    info(&mut memory.memory, 0x1fd0, 35, 1000, 0x1234);
    let mut request = Call::new(
        source.signals.io.clone(),
        routes,
        vfs.fd_flags_snapshot(),
        138,
        [1, 35, 0x1fd0, 0, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(source.signals.pending_bits(), 0);
    memory
        .memory
        .write_array(0x1fd8, (-1i32).to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    let (_, received) = source.signals.io.dequeue(1 << 34).unwrap();
    assert_eq!(received.code, 1000);
    assert_eq!(
        i32::from_le_bytes(received.user.unwrap()[8..12].try_into().unwrap()),
        1000
    );
}
#[test]
fn cancellation_drops_original_input_and_never_enqueues_on_late_page_completion() {
    let (source, target, routes, vfs, mut memory) = fixture();
    info(&mut memory.memory, 0x1ff0, 35, -1, 0x1234);
    let mut request = Call::new(
        source.signals.io.clone(),
        routes,
        vfs.fd_flags_snapshot(),
        138,
        [2, 35, 0x1ff0, 0, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    request.cancel();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Err(Errno(4))));
    assert_eq!(target.signals.pending_bits(), 0);
}
#[test]
fn pidfd_keeps_original_ofd_target_across_numeric_fd_close_and_reuse() {
    let (source, target, routes, mut vfs, mut memory) = fixture();
    let other = task(&routes, 3);
    let fd = routes.pidfd_open(&vfs.descriptor_factory(), 2, 0).unwrap() as u32;
    info(&mut memory.memory, 0x1ff0, 35, -1, 0x1234);
    let mut request = Call::new(
        source.signals.io.clone(),
        routes.clone(),
        vfs.fd_flags_snapshot(),
        424,
        [fd as u64, 35, 0x1ff0, 0, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    vfs.close(fd).unwrap();
    assert_eq!(
        routes.pidfd_open(&vfs.descriptor_factory(), 3, 0).unwrap(),
        fd as u64
    );
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert!(target.signals.io.dequeue(1 << 34).is_some());
    assert_eq!(other.signals.pending_bits(), 0);
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert!(target.signals.io.dequeue(1 << 34).is_none());
}
#[test]
fn pidfd_input_errors_precede_missing_live_target_after_original_fd_acceptance() {
    let (source, target, routes, vfs, mut memory) = fixture();
    let fd = routes.pidfd_open(&vfs.descriptor_factory(), 2, 0).unwrap();
    drop(target);
    for (address, error) in [(0x90000, 14), (0, 3)] {
        let mut request = Call::new(
            source.signals.io.clone(),
            routes.clone(),
            vfs.fd_flags_snapshot(),
            424,
            [fd, 35, address, 0, 0, 0],
        );
        assert_eq!(request.check(&mut memory), Some(Err(Errno(error))));
    }
    for (number, args, error) in [
        (138, [999, 35, 0x90000, 0, 0, 0], 14),
        (240, [0, 0, 35, 0x90000, 0, 0], 14),
        (424, [999, 35, 0x90000, 6, 0, 0], 22),
        (424, [999, 35, 0x90000, 0, 0, 0], 9),
    ] {
        assert_eq!(
            Call::new(
                source.signals.io.clone(),
                routes.clone(),
                vfs.fd_flags_snapshot(),
                number,
                args
            )
            .check(&mut memory),
            Some(Err(Errno(error)))
        );
    }
}
#[test]
fn pidfd_unknown_expansion_error_precedes_signo_mismatch_and_target_permission() {
    let (source, _target, routes, vfs, mut memory) = fixture();
    let fd = routes.pidfd_open(&vfs.descriptor_factory(), 2, 0).unwrap();
    info(&mut memory.memory, 0x1fd0, 34, 1000, 0);
    memory.memory.write_array(0x2000, [1]).unwrap();
    let mut request = Call::new(
        source.signals.io.clone(),
        routes,
        vfs.fd_flags_snapshot(),
        424,
        [fd, 35, 0x1fd0, 0, 0, 0],
    );
    assert_eq!(request.check(&mut memory), None);
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Err(Errno(7))));
}
#[test]
fn numeric_queue_targets_resolve_after_input_but_retained_pidfd_cannot_retarget_pid_reuse() {
    for pidfd in [false, true] {
        let (source, target, routes, vfs, mut memory) = fixture();
        let fd = routes.pidfd_open(&vfs.descriptor_factory(), 2, 0).unwrap();
        info(&mut memory.memory, 0x1ff0, 35, -1, 0x1234);
        let (number, args) = if pidfd {
            (424, [fd, 35, 0x1ff0, 0, 0, 0])
        } else {
            (138, [2, 35, 0x1ff0, 0, 0, 0])
        };
        let mut request = Call::new(
            source.signals.io.clone(),
            routes.clone(),
            vfs.fd_flags_snapshot(),
            number,
            args,
        );
        assert_eq!(request.check(&mut memory), None);
        let weak = Arc::downgrade(&target.signals.io);
        drop(target);
        assert!(weak.upgrade().is_none());
        let replacement = task(&routes, 2);
        memory.wait.finish();
        assert_eq!(
            request.check(&mut memory),
            Some(if pidfd { Err(Errno(3)) } else { Ok(0) })
        );
        assert_eq!(replacement.signals.io.dequeue(1 << 34).is_some(), !pidfd);
    }
}
