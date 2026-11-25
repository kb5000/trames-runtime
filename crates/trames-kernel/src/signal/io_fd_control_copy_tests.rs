// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::signal::frame_copy_tests::Faults;
use trames_memory::PAGE_SIZE;
fn task(routes: &IoRoutes, id: u32) -> Signals {
    let mut signals = Signals {
        io_directory: routes.directory.clone(),
        ..Default::default()
    };
    signals.publish_policy(&routes.namespace, true);
    routes.directory.publish(&signals.io, id, id, id, 0, 0);
    signals.set_mask(1 << 34);
    signals
}
fn fixture() -> (Signals, Signals, Signals, IoRoutes, trames_vfs::Vfs, Faults) {
    let routes = IoRoutes::default();
    let source = task(&routes, 1);
    let first = task(&routes, 2);
    let second = task(&routes, 3);
    (
        source,
        first,
        second,
        routes,
        trames_vfs::Vfs::default(),
        Faults::new(0x2000),
    )
}
fn call(
    source: &Signals,
    routes: &IoRoutes,
    vfs: &trames_vfs::Vfs,
    number: u32,
    fd: u32,
    command: u32,
    address: u64,
) -> FdControlCall {
    FdControlCall::new(
        &source.io,
        routes.clone(),
        &vfs.fd_flags_snapshot(),
        number,
        [fd as u64, command as u64, address, 0, 0, 0],
    )
}
fn owner(routes: &IoRoutes, vfs: &trames_vfs::Vfs, fd: u32, pid: u32, memory: &mut impl CpuMemory) {
    vfs.fd_flags_snapshot()
        .async_control(
            fd,
            8,
            pid as u64,
            memory,
            &routes.async_owners(&Default::default()),
        )
        .unwrap();
}
fn get_owner(
    routes: &IoRoutes,
    vfs: &trames_vfs::Vfs,
    fd: u32,
    memory: &mut impl CpuMemory,
) -> u64 {
    vfs.fd_flags_snapshot()
        .async_control(fd, 9, 0, memory, &routes.async_owners(&Default::default()))
        .unwrap()
}
#[test]
fn setown_ex_retains_original_header_and_ofd_until_complete_input_then_sets_once() {
    let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
    let [fd, _writer] = vfs.pipe(0).unwrap();
    let alias = vfs.dup(fd, 0, false).unwrap();
    memory
        .memory
        .write_array(0x1ffc, 1u32.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x2000, 2u32.to_le_bytes())
        .unwrap();
    let mut request = call(&source, &routes, &vfs, 25, fd, 15, 0x1ffc);
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(get_owner(&routes, &vfs, alias, &mut memory.memory), 0);
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory
        .memory
        .write_array(0x1ffc, 2u32.to_le_bytes())
        .unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    vfs.fd_flags_snapshot()
        .async_control(
            alias,
            16,
            0x1100,
            &mut memory.memory,
            &routes.async_owners(&Default::default()),
        )
        .unwrap();
    assert_eq!(
        memory.memory.read_array::<8>(0x1100).unwrap(),
        [1, 0, 0, 0, 2, 0, 0, 0]
    );
    assert_eq!(get_owner(&routes, &vfs, fd, &mut memory.memory), 0);
    owner(&routes, &vfs, alias, 3, &mut memory.memory);
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(get_owner(&routes, &vfs, alias, &mut memory.memory), 3);
}
#[test]
fn getown_ex_snapshots_owner_before_copy_and_keeps_prefix_after_owner_change() {
    let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
    let fd = vfs.eventfd(0, 0).unwrap();
    let alias = vfs.dup(fd, 0, false).unwrap();
    owner(&routes, &vfs, fd, 2, &mut memory.memory);
    let mut request = call(&source, &routes, &vfs, 25, fd, 16, 0x1ffc);
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(
        memory.memory.read_array::<4>(0x1ffc).unwrap(),
        1u32.to_le_bytes()
    );
    owner(&routes, &vfs, alias, 3, &mut memory.memory);
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory.memory.write_array(0x1ffc, [0x77; 4]).unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(memory.memory.read_array::<4>(0x1ffc).unwrap(), [0x77; 4]);
    assert_eq!(
        memory.memory.read_array::<4>(0x2000).unwrap(),
        2u32.to_le_bytes()
    );
    assert_eq!(get_owner(&routes, &vfs, alias, &mut memory.memory), 3);
}
#[test]
fn fionbio_input_does_not_change_flags_until_complete_or_retarget_a_reused_fd() {
    let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
    let [fd, _writer] = vfs.pipe(0).unwrap();
    let alias = vfs.dup(fd, 0, false).unwrap();
    memory
        .memory
        .write_array(0x1ffe, 1u32.to_le_bytes())
        .unwrap();
    let mut request = call(&source, &routes, &vfs, 29, fd, 0x5421, 0x1ffe);
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(vfs.flags(alias).unwrap() & trames_vfs::O_NONBLOCK, 0);
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory.memory.write_array(0x1ffe, [0; 2]).unwrap();
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_ne!(vfs.flags(alias).unwrap() & trames_vfs::O_NONBLOCK, 0);
    assert_eq!(vfs.flags(fd).unwrap() & trames_vfs::O_NONBLOCK, 0);
    vfs.descriptor_control(alias)
        .unwrap()
        .short(alias, 4, 0, &vfs.credentials)
        .unwrap();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(vfs.flags(alias).unwrap() & trames_vfs::O_NONBLOCK, 0);
}
#[test]
fn fioasync_installs_original_endpoint_and_signal_owner_only_after_input() {
    let (source, first, second, routes, mut vfs, mut memory) = fixture();
    let [fd, writer] = vfs.pipe(0).unwrap();
    let alias = vfs.dup(fd, 0, false).unwrap();
    owner(&routes, &vfs, fd, 2, &mut memory.memory);
    vfs.fd_flags_snapshot()
        .async_control(
            fd,
            10,
            35,
            &mut memory.memory,
            &routes.async_owners(&Default::default()),
        )
        .unwrap();
    memory
        .memory
        .write_array(0x1ffe, 1u32.to_le_bytes())
        .unwrap();
    let mut request = call(&source, &routes, &vfs, 29, fd, 0x5452, 0x1ffe);
    assert_eq!(request.check(&mut memory), None);
    vfs.write(writer, b"x").unwrap();
    assert!(first.io.dequeue(1 << 34).is_none());
    assert_eq!(vfs.read(alias, 1).unwrap(), b"x");
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    vfs.write(writer, b"y").unwrap();
    let (_, received) = first.io.dequeue(1 << 34).unwrap();
    assert_eq!(received.poll, Some((0x41, fd)));
    assert!(second.io.dequeue(1 << 34).is_none());
    assert_eq!(vfs.flags(fd).unwrap() & 0x2000, 0);
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert!(first.io.dequeue(1 << 34).is_none());
}
#[test]
fn socket_owner_get_uses_one_scalar_store_and_original_snapshot_after_fd_reuse() {
    let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
    let fd = vfs.socket(1, 1, 0).unwrap();
    let alias = vfs.dup(fd, 0, false).unwrap();
    owner(&routes, &vfs, fd, 2, &mut memory.memory);
    memory.memory.write_array(0x1ffe, [0x55; 4]).unwrap();
    let mut request = call(&source, &routes, &vfs, 29, fd, 0x8903, 0x1ffe);
    assert_eq!(request.check(&mut memory), None);
    assert_eq!(memory.memory.read_array::<2>(0x1ffe).unwrap(), [0x55; 2]);
    owner(&routes, &vfs, alias, 3, &mut memory.memory);
    vfs.close(fd).unwrap();
    assert_eq!(vfs.eventfd(0, 0).unwrap(), fd);
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Ok(0)));
    assert_eq!(
        memory.memory.read_array::<4>(0x1ffe).unwrap(),
        2u32.to_le_bytes()
    );
    assert_eq!(get_owner(&routes, &vfs, alias, &mut memory.memory), 3);
}
#[test]
fn descriptor_and_ioctl_type_errors_precede_pointer_import_but_owner_errors_follow_it() {
    let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
    let fd = vfs.eventfd(0, 0).unwrap();
    let path = vfs.open_at(-100, b"/", trames_vfs::O_PATH, 0).unwrap();
    for (number, target, command, error) in [
        (25, 999, 15, 9),
        (29, 999, 0x5421, 9),
        (25, path, 15, 9),
        (29, path, 0x5421, 9),
        (29, fd, 0x8901, 25),
        (25, fd, 15, 14),
    ] {
        assert_eq!(
            call(&source, &routes, &vfs, number, target, command, 0x90000).check(&mut memory),
            Some(Err(Errno(error)))
        );
    }
    memory
        .memory
        .write_array(0x1ffc, 9u32.to_le_bytes())
        .unwrap();
    memory
        .memory
        .write_array(0x2000, 999u32.to_le_bytes())
        .unwrap();
    let mut request = call(&source, &routes, &vfs, 25, fd, 15, 0x1ffc);
    assert_eq!(request.check(&mut memory), None);
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Err(Errno(22))));
    assert_eq!(get_owner(&routes, &vfs, fd, &mut memory.memory), 0);
}
#[test]
fn cancellation_and_permanent_input_error_do_not_publish_owner_or_async_flags() {
    for cancelled in [false, true] {
        let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
        let [fd, _writer] = vfs.pipe(0).unwrap();
        memory
            .memory
            .write_array(0x1ffc, 1u32.to_le_bytes())
            .unwrap();
        memory
            .memory
            .write_array(0x2000, 2u32.to_le_bytes())
            .unwrap();
        let mut request = call(&source, &routes, &vfs, 25, fd, 15, 0x1ffc);
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
        assert_eq!(get_owner(&routes, &vfs, fd, &mut memory.memory), 0);
        assert_eq!(vfs.flags(fd).unwrap() & 0x2000, 0);
    }
}
#[test]
fn accepted_control_keeps_entire_original_pipe_ofd_and_releases_it_on_cancel() {
    let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
    let [fd, writer] = vfs.pipe(0).unwrap();
    memory
        .memory
        .write_array(0x1ffe, 1u32.to_le_bytes())
        .unwrap();
    let mut request = call(&source, &routes, &vfs, 29, fd, 0x5421, 0x1ffe);
    assert_eq!(request.check(&mut memory), None);
    vfs.close(fd).unwrap();
    assert_eq!(vfs.write(writer, b"x"), Ok(1));
    request.cancel();
    assert_eq!(vfs.write(writer, b"y"), Err(Errno(32)));
    memory.wait.finish();
    assert_eq!(request.check(&mut memory), Some(Err(Errno(4))));
}
#[test]
fn owner_type_survives_zero_owner_and_signal_argument_uses_native_low_word() {
    let (source, _first, _second, routes, mut vfs, mut memory) = fixture();
    let fd = vfs.eventfd(0, 0).unwrap();
    assert_eq!(
        call(&source, &routes, &vfs, 25, fd, 16, 0x1100).check(&mut memory),
        Some(Ok(0))
    );
    assert_eq!(memory.memory.read_array::<8>(0x1100).unwrap(), [0; 8]);
    owner(&routes, &vfs, fd, 0, &mut memory.memory);
    assert_eq!(
        call(&source, &routes, &vfs, 25, fd, 16, 0x1100).check(&mut memory),
        Some(Ok(0))
    );
    assert_eq!(
        memory.memory.read_array::<8>(0x1100).unwrap(),
        [1, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        call(&source, &routes, &vfs, 25, fd, 10, 35 | (1u64 << 32)).check(&mut memory),
        Some(Ok(0))
    );
    assert_eq!(
        call(&source, &routes, &vfs, 25, fd, 11, 0).check(&mut memory),
        Some(Ok(35))
    );
}
