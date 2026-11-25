// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn fixture() -> (
    trames_vfs::Vfs,
    u32,
    DirectSyscalls,
    Memory,
    Arc<file::copyout_tests::Deferred>,
    Arc<dyn IoWake>,
) {
    let mut vfs = trames_vfs::Vfs::default();
    let fd = vfs.timerfd(1, 0).unwrap();
    let source = DirectSyscalls::new(vfs.direct_descriptors())
        .with_resources(vfs.descriptor_factory())
        .with_clock(Instant::now());
    let mut memory = Memory::default();
    memory.map(0x1000, 0x4000, Permissions::RW).unwrap();
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    (vfs, fd, source, memory, page, Arc::new(Wake))
}
fn spec(memory: &mut Memory, address: u64, interval: u64, value: u64) {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&interval.to_le_bytes());
    bytes[16..24].copy_from_slice(&value.to_le_bytes());
    memory.write(address, &bytes).unwrap();
}
fn parked(
    source: &DirectSyscalls,
    number: u32,
    args: [u64; 6],
    memory: &mut Memory,
    wake: &Arc<dyn IoWake>,
) -> PendingIo {
    let Some(IoAttempt::Blocked(wait)) =
        source.start(number, args, memory, 1, &Arc::downgrade(wake), None)
    else {
        panic!("timer copy must keep its original receipt");
    };
    wait
}
fn value(attempt: IoAttempt) -> Result<u64, Errno> {
    let IoAttempt::Complete(value) = attempt else {
        panic!("timer must finish");
    };
    value
}
#[test]
fn input_precedes_validation_and_fdget_and_keeps_fragments_across_fd_reuse() {
    let (mut vfs, fd, source, mut memory, page, wake) = fixture();
    let old = vfs.timerfd_resource(fd).unwrap();
    memory.write(0x2ff0, &7u64.to_le_bytes()).unwrap();
    let args = [fd as u64, 0, 0x2ff0, 0, 0, 0];
    assert_eq!(source.invoke(86, args, &mut memory), None);
    assert_eq!(old.update(None), (Duration::ZERO, Duration::ZERO));
    let wait = parked(&source, 86, args, &mut memory, &wake);
    memory.write(0x2ff0, &99u64.to_le_bytes()).unwrap();
    vfs.close(fd).unwrap();
    assert_eq!(vfs.timerfd(1, 0).unwrap(), fd);
    page.finish();
    memory.write(0x3000, &3600u64.to_le_bytes()).unwrap();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(old.update(None), (Duration::ZERO, Duration::ZERO));
    let (interval, remaining) = vfs.timerfd_get(fd).unwrap();
    assert_eq!(interval, Duration::from_secs(7));
    assert!(remaining.as_secs() >= 3599);
    assert_eq!(source.timer_completed(), 1);
}
#[test]
fn set_effect_and_old_snapshot_are_not_replayed_by_output_fault_or_fd_reuse() {
    let (mut vfs, fd, source, mut memory, page, wake) = fixture();
    let original = vfs.timerfd_resource(fd).unwrap();
    vfs.timerfd_set(
        fd,
        Duration::from_secs(7),
        Some(Instant::now() + Duration::from_secs(3600)),
    )
    .unwrap();
    spec(&mut memory, 0x1100, 11, 7200);
    let args = [fd as u64, 0, 0x1100, 0x2ff0, 0, 0];
    assert_eq!(source.invoke(86, args, &mut memory), None);
    assert_eq!(original.update(None).0, Duration::from_secs(11));
    assert_eq!(memory.read_u64(0x2ff0).unwrap(), 7);
    let wait = parked(&source, 86, args, &mut memory, &wake);
    let old = wait.file_pending().unwrap();
    memory.write(0x2ff0, &99u64.to_le_bytes()).unwrap();
    spec(&mut memory, 0x1100, 88, 1);
    vfs.timerfd_set(fd, Duration::from_secs(23), None).unwrap();
    vfs.close(fd).unwrap();
    assert_eq!(vfs.timerfd(1, 0).unwrap(), fd);
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.read_u64(0x2ff0).unwrap(), 99);
    assert!(memory.read_u64(0x3000).unwrap() >= 3599);
    assert_eq!(original.update(None).0, Duration::from_secs(23));
    assert_eq!(
        vfs.timerfd_get(fd).unwrap(),
        (Duration::ZERO, Duration::ZERO)
    );
    assert_eq!(
        value(source.start_retained_file(old, 86, args, &mut memory, 1, &Arc::downgrade(&wake))),
        Err(Errno(4))
    );
    assert_eq!(source.timer_completed(), 1);
}
#[test]
fn get_snapshot_survives_rearm_and_original_source_release() {
    let (vfs, fd, source, mut memory, page, wake) = fixture();
    vfs.timerfd_set(
        fd,
        Duration::from_secs(9),
        Some(Instant::now() + Duration::from_secs(3600)),
    )
    .unwrap();
    let args = [fd as u64, 0x2ff0, 0, 0, 0, 0];
    assert_eq!(source.invoke(87, args, &mut memory), None);
    let wait = parked(&source, 87, args, &mut memory, &wake);
    drop(source);
    vfs.timerfd_set(fd, Duration::from_secs(17), None).unwrap();
    page.finish();
    assert_eq!(
        value(DirectSyscalls::default().resume(wait, &mut memory)),
        Ok(0)
    );
    assert_eq!(memory.read_u64(0x2ff0).unwrap(), 9);
    assert!(memory.read_u64(0x3000).unwrap() >= 3599);
    assert_eq!(vfs.timerfd_get(fd).unwrap().0, Duration::from_secs(17));
}
#[test]
fn permanent_output_error_does_not_undo_update_and_native_error_order_is_retained() {
    let (mut vfs, fd, source, mut memory, _page, _wake) = fixture();
    spec(&mut memory, 0x1100, 13, 3600);
    assert_eq!(
        source.invoke(86, [fd as u64, 0, 0x1100, 0, 0, 0], &mut memory),
        Some(Ok(0))
    );
    spec(&mut memory, 0x1100, 31, 7200);
    assert_eq!(
        source.invoke(86, [fd as u64, 0, 0x1100, 0x9000, 0, 0], &mut memory),
        Some(Err(Errno(14)))
    );
    assert_eq!(vfs.timerfd_get(fd).unwrap().0, Duration::from_secs(31));
    assert_eq!(
        source.invoke(86, [999, 4, 0x9000, 0, 0, 0], &mut memory),
        Some(Err(Errno(14)))
    );
    assert_eq!(
        source.invoke(86, [999, 4, 0x1100, 0, 0, 0], &mut memory),
        Some(Err(Errno(22)))
    );
    assert_eq!(
        source.invoke(86, [999, 0, 0x1100, 0, 0, 0], &mut memory),
        Some(Err(Errno(9)))
    );
    assert_eq!(
        source.invoke(87, [999, 0x9000, 0, 0, 0, 0], &mut memory),
        Some(Err(Errno(9)))
    );
    let ordinary = vfs.open_at(-100, b"/ordinary", 0x42, 0o600).unwrap();
    assert_eq!(
        source.invoke(87, [ordinary as u64, 0x9000, 0, 0, 0, 0], &mut memory),
        Some(Err(Errno(22)))
    );
}
#[test]
fn cancellation_retires_original_input_and_output_without_reexecuting_timer_update() {
    for output in [false, true] {
        let (vfs, fd, source, mut memory, page, wake) = fixture();
        let args = if output {
            spec(&mut memory, 0x1100, 17, 3600);
            [fd as u64, 0, 0x1100, 0x2ff0, 0, 0]
        } else {
            [fd as u64, 0, 0x2ff0, 0, 0, 0]
        };
        assert_eq!(source.invoke(86, args, &mut memory), None);
        let wait = parked(&source, 86, args, &mut memory, &wake);
        let old = wait.file_pending().unwrap();
        wait.cancel_copies();
        page.finish();
        assert_eq!(value(source.resume(wait, &mut memory)), Err(Errno(4)));
        assert_eq!(
            value(source.start_retained_file(
                old,
                86,
                args,
                &mut memory,
                1,
                &Arc::downgrade(&wake)
            )),
            Err(Errno(4))
        );
        assert_eq!(
            vfs.timerfd_get(fd).unwrap().0,
            Duration::from_secs(if output { 17 } else { 0 })
        );
    }
}
#[test]
fn missing_alarm_authority_hands_off_original_import_and_ofd_before_any_effect() {
    let mut vfs = trames_vfs::Vfs::default();
    let fd = vfs.timerfd(8, 0).unwrap();
    let original = vfs.timerfd_resource(fd).unwrap();
    let source = DirectSyscalls::new(vfs.direct_descriptors());
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    spec(&mut memory, 0x1100, 19, 3600);
    let args = [fd as u64, 0, 0x1100, 0, 0, 0];
    assert_eq!(source.invoke(86, args, &mut memory), None);
    assert_eq!(original.update(None), (Duration::ZERO, Duration::ZERO));
    let Some(IoAttempt::FileCheckpoint(checkpoint)) =
        source.start(86, args, &mut memory, 1, &Arc::downgrade(&wake), None)
    else {
        panic!("original timer capability must hand off");
    };
    let old = checkpoint.clone();
    let file::FileBoundary::TimerFd(call) = checkpoint.take() else {
        panic!("original timer");
    };
    vfs.close(fd).unwrap();
    assert_eq!(vfs.timerfd(1, 0).unwrap(), fd);
    spec(&mut memory, 0x1100, 77, 1);
    let joined =
        DirectSyscalls::new(vfs.direct_descriptors()).with_resources(vfs.descriptor_factory());
    assert_eq!(
        value(call.resume(&joined, &mut memory, 1, &Arc::downgrade(&wake))),
        Ok(0)
    );
    assert_eq!(original.update(None).0, Duration::from_secs(19));
    assert_eq!(
        vfs.timerfd_get(fd).unwrap(),
        (Duration::ZERO, Duration::ZERO)
    );
    assert!(matches!(
        old.take(),
        file::FileBoundary::Signal {
            value: Err(Errno(4))
        }
    ));
}
#[test]
fn alarm_permission_follows_input_validation_and_does_not_update_original_timer() {
    let mut vfs = trames_vfs::Vfs::default();
    let fd = vfs.timerfd(8, 0).unwrap();
    let original = vfs.timerfd_resource(fd).unwrap();
    vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
    let source =
        DirectSyscalls::new(vfs.direct_descriptors()).with_resources(vfs.descriptor_factory());
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    spec(&mut memory, 0x1100, 19, 3600);
    assert_eq!(
        source.invoke(86, [fd as u64, 0, 0x1100, 0x9000, 0, 0], &mut memory),
        Some(Err(Errno(1)))
    );
    memory
        .write(0x1108, &1_000_000_000u64.to_le_bytes())
        .unwrap();
    assert_eq!(
        source.invoke(86, [fd as u64, 0, 0x1100, 0x9000, 0, 0], &mut memory),
        Some(Err(Errno(22)))
    );
    assert_eq!(original.update(None), (Duration::ZERO, Duration::ZERO));
}
#[test]
fn native_integer_flags_and_large_timespecs_saturate_at_ktime_conversion() {
    let (vfs, fd, source, mut memory, _page, _wake) = fixture();
    spec(&mut memory, 0x1100, i64::MAX as u64, i64::MAX as u64);
    assert_eq!(
        source.invoke(86, [fd as u64, 1u64 << 32, 0x1100, 0, 0, 0], &mut memory),
        Some(Ok(0))
    );
    let (interval, remaining) = vfs.timerfd_get(fd).unwrap();
    assert_eq!(interval, Duration::from_nanos(i64::MAX as u64));
    assert!(remaining > Duration::from_secs(3600));
}
