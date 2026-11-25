// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
struct Wake;
impl IoWake for Wake {
    fn wake_io(&self, _: &Arc<IoSignal>) {}
}
fn fixture() -> (Memory, Arc<file::copyout_tests::Deferred>, Arc<dyn IoWake>) {
    let mut memory = Memory::default();
    memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    let page = file::copyout_tests::install(&mut memory, 0x3000);
    (memory, page, Arc::new(Wake))
}
fn value(attempt: IoAttempt) -> Result<u64, Errno> {
    let IoAttempt::Complete(result) = attempt else {
        panic!("metadata call must complete");
    };
    result
}
fn parked(
    source: &DirectSyscalls,
    number: u32,
    args: [u64; 6],
    memory: &mut Memory,
    wake: &Arc<dyn IoWake>,
) -> PendingIo {
    let Some(IoAttempt::Blocked(wait)) =
        source.start_metadata_copy(number, args, memory, 1, &Arc::downgrade(wake))
    else {
        panic!("original metadata cursor must park");
    };
    wait
}
#[test]
fn cpu_clock_keeps_original_observation_and_copied_prefix_through_page_wait() {
    let (mut memory, page, wake) = fixture();
    let source = DirectSyscalls::default();
    let task = trames_vfs::ProcessView::default();
    task.account(Duration::new(2, 123), 0);
    let args = [3, 0x2ff8, 0, 0, 0, 0];
    assert_eq!(
        source.invoke_time(113, args, &mut memory, Instant::now(), None, Some(&task)),
        None
    );
    assert_eq!(memory.read_u64(0x2ff8).unwrap(), 2);
    let wait = parked(&source, 113, args, &mut memory, &wake);
    let old = wait.file_pending().unwrap();
    task.account(Duration::new(11, 77), 1);
    memory.write(0x2ff8, &99u64.to_le_bytes()).unwrap();
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.read_u64(0x2ff8).unwrap(), 99);
    assert_eq!(memory.read_u64(0x3000).unwrap(), 123);
    assert_eq!(
        value(source.start_retained_file(old, 113, args, &mut memory, 1, &Arc::downgrade(&wake))),
        Err(Errno(4))
    );
}
#[test]
fn clock_validation_resolution_and_original_group_clock_precede_output_faults() {
    let (mut memory, page, wake) = fixture();
    let source = DirectSyscalls::default();
    let started = Instant::now();
    assert_eq!(
        source.invoke_time(
            113,
            [u64::MAX, 0x3000, 0, 0, 0, 0],
            &mut memory,
            started,
            None,
            None
        ),
        Some(Err(Errno(22)))
    );
    assert_eq!(
        source.invoke_time(
            113,
            [2, 0x3000, 0, 0, 0, 0],
            &mut memory,
            started,
            Some(Err(Errno(22))),
            None
        ),
        Some(Err(Errno(22)))
    );
    assert_eq!(
        source.invoke_time(114, [1, 0, 0, 0, 0, 0], &mut memory, started, None, None),
        Some(Ok(0))
    );
    let args = [2, 0x2ff8, 0, 0, 0, 0];
    assert_eq!(
        source.invoke_time(
            113,
            args,
            &mut memory,
            started,
            Some(Ok(Duration::new(9, 456))),
            None
        ),
        None
    );
    let wait = parked(&source, 113, args, &mut memory, &wake);
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.read_u64(0x2ff8).unwrap(), 9);
    assert_eq!(memory.read_u64(0x3000).unwrap(), 456);
}
#[test]
fn timeval_finishes_original_scalar_then_timezone_without_replaying_earlier_store() {
    let (mut memory, page, wake) = fixture();
    let source = DirectSyscalls::default();
    let args = [0x2ff8, 0x1100, 0, 0, 0, 0];
    memory.write(0x1100, &[0x77; 8]).unwrap();
    assert_eq!(
        source.invoke_time(169, args, &mut memory, Instant::now(), None, None),
        None
    );
    assert_eq!(memory.read_array::<8>(0x1100).unwrap(), [0x77; 8]);
    let wait = parked(&source, 169, args, &mut memory, &wake);
    memory.write(0x2ff8, &99u64.to_le_bytes()).unwrap();
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.read_u64(0x2ff8).unwrap(), 99);
    assert!(memory.read_u64(0x3000).unwrap() < 1_000_000);
    assert_eq!(memory.read_array::<8>(0x1100).unwrap(), [0; 8]);
}
#[test]
fn later_timezone_failure_keeps_the_already_copied_timeval() {
    let (mut memory, _page, _wake) = fixture();
    let source = DirectSyscalls::default();
    memory.write(0x1100, &[0x77; 16]).unwrap();
    assert_eq!(
        source.invoke_time(
            169,
            [0x1100, 0x9000, 0, 0, 0, 0],
            &mut memory,
            Instant::now(),
            None,
            None
        ),
        Some(Err(Errno(14)))
    );
    assert_ne!(memory.read_array::<8>(0x1100).unwrap(), [0x77; 8]);
    assert!(memory.read_u64(0x1108).unwrap() < 1_000_000);
}
#[test]
fn getcpu_retains_prior_error_while_later_destination_waits_and_still_attempts_both() {
    let (mut memory, page, wake) = fixture();
    let source = DirectSyscalls::default();
    let args = [0x9000, 0x3000, 0, 0, 0, 0];
    assert_eq!(source.invoke_getcpu(args, 7, &mut memory), None);
    let wait = parked(&source, 168, args, &mut memory, &wake);
    page.finish();
    memory.write(0x3000, &[0x77; 4]).unwrap();
    assert_eq!(value(source.resume(wait, &mut memory)), Err(Errno(14)));
    assert_eq!(memory.read_array::<4>(0x3000).unwrap(), [0; 4]);
    assert_eq!(
        source.invoke_getcpu([0x1100, 0x9000, 0, 0, 0, 0], 7, &mut memory),
        Some(Err(Errno(14)))
    );
    assert_eq!(
        u32::from_le_bytes(memory.read_array::<4>(0x1100).unwrap()),
        7
    );
}
#[test]
fn getcpu_uses_original_scalar_store_and_processor_across_cross_page_wait() {
    let (mut memory, page, wake) = fixture();
    let source = DirectSyscalls::default();
    let args = [0x2fff, 0x1100, 0, 0, 0, 0];
    memory.write(0x2fff, &[0x77]).unwrap();
    memory.write(0x1100, &[0x77; 4]).unwrap();
    assert_eq!(source.invoke_getcpu(args, 7, &mut memory), None);
    assert_eq!(memory.read_array::<1>(0x2fff).unwrap(), [0x77]);
    assert_eq!(memory.read_array::<4>(0x1100).unwrap(), [0x77; 4]);
    let wait = parked(&source, 168, args, &mut memory, &wake);
    drop(source);
    page.finish();
    assert_eq!(
        value(DirectSyscalls::default().resume(wait, &mut memory)),
        Ok(0)
    );
    assert_eq!(
        u32::from_le_bytes(memory.read_array::<4>(0x2fff).unwrap()),
        7
    );
    assert_eq!(
        u32::from_le_bytes(memory.read_array::<4>(0x1100).unwrap()),
        0
    );
}
#[test]
fn uname_keeps_snapshot_and_defers_compatibility_override_until_whole_output_is_copied() {
    let (mut memory, page, wake) = fixture();
    let source = DirectSyscalls::default();
    let uts = trames_vfs::Vfs::default().uts_capability();
    uts.set(false, b"original").unwrap();
    uts.set(true, b"old-domain").unwrap();
    let personality = crate::TaskPersonality::default();
    personality.call(0x20000).unwrap();
    let args = [0x2f00, 0, 0, 0, 0, 0];
    assert_eq!(
        source.invoke_uts(&uts, &personality, 160, args, &mut memory),
        None
    );
    assert_eq!(memory.read_array::<13>(0x2f82).unwrap(), *b"6.0.0-trames\0");
    let wait = parked(&source, 160, args, &mut memory, &wake);
    memory.write(0x2f00, b"other").unwrap();
    uts.set(true, b"new-domain").unwrap();
    personality.call(0).unwrap();
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(memory.read_array::<5>(0x2f00).unwrap(), *b"other");
    assert_eq!(
        memory.read_array::<14>(0x2f82).unwrap(),
        *b"2.6.60-trames\0"
    );
    assert_eq!(
        memory.read_array::<11>(0x2f00 + 325).unwrap(),
        *b"old-domain\0"
    );
}
#[test]
fn uts_input_keeps_original_namespace_fragments_and_scalar_width_across_copy_wait() {
    for number in [161, 162] {
        let (mut memory, page, wake) = fixture();
        let source = DirectSyscalls::default();
        let uts = trames_vfs::Vfs::default().uts_capability();
        let personality = crate::TaskPersonality::default();
        let args = [0x2ffe, 6 | (1u64 << 32), 0, 0, 0, 0];
        memory.write(0x2ffe, b"ab").unwrap();
        let old = uts.names();
        assert_eq!(
            source.invoke_uts(&uts, &personality, number, args, &mut memory),
            None
        );
        assert_eq!(uts.names(), old);
        let wait = parked(&source, number, args, &mut memory, &wake);
        let retired = wait.file_pending().unwrap();
        memory.write(0x2ffe, b"zz").unwrap();
        page.finish();
        memory.write(0x3000, b"cdef").unwrap();
        assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
        assert_eq!(uts.names()[usize::from(number == 162)], b"abcdef");
        uts.set(number == 162, b"later").unwrap();
        assert_eq!(
            value(source.start_retained_file(
                retired,
                number,
                args,
                &mut memory,
                1,
                &Arc::downgrade(&wake)
            )),
            Err(Errno(4))
        );
        assert_eq!(uts.names()[usize::from(number == 162)], b"later");
    }
}
#[test]
fn uts_permission_and_length_errors_precede_any_lazy_input() {
    let (mut memory, _page, _wake) = fixture();
    let source = DirectSyscalls::default();
    let mut vfs = trames_vfs::Vfs::default();
    let allowed = vfs.uts_capability();
    vfs.credentials = trames_vfs::Credentials::user(1000, 1000);
    let denied = vfs.uts_capability();
    let personality = crate::TaskPersonality::default();
    for number in [161, 162] {
        assert_eq!(
            source.invoke_uts(
                &denied,
                &personality,
                number,
                [0x3000, u64::MAX, 0, 0, 0, 0],
                &mut memory
            ),
            Some(Err(Errno(1)))
        );
        assert_eq!(
            source.invoke_uts(
                &allowed,
                &personality,
                number,
                [0x3000, u64::MAX, 0, 0, 0, 0],
                &mut memory
            ),
            Some(Err(Errno(22)))
        );
        assert!(!source.file_prepared(number, [0x3000, u64::MAX, 0, 0, 0, 0]));
    }
}
#[test]
fn sysinfo_samples_once_and_keeps_output_prefix_and_original_statistics_across_wait() {
    struct Statistics(std::sync::atomic::AtomicUsize);
    impl crate::SystemStatistics for Statistics {
        fn observe(&self) -> Option<crate::SystemInfo> {
            let value = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            Some(crate::SystemInfo {
                tasks: 17 * value,
                ..Default::default()
            })
        }
    }
    let (mut memory, page, wake) = fixture();
    let provider = Arc::new(Statistics(0.into()));
    let source = DirectSyscalls::default().with_statistics(Some(provider.clone()));
    let args = [0x2ffe, 0, 0, 0, 0, 0];
    assert_eq!(source.invoke_system(179, args, &mut memory), None);
    let wait = parked(&source, 179, args, &mut memory, &wake);
    memory.write(0x2ffe, b"zz").unwrap();
    page.finish();
    assert_eq!(value(source.resume(wait, &mut memory)), Ok(0));
    assert_eq!(provider.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(memory.read_array::<2>(0x2ffe).unwrap(), *b"zz");
    assert_eq!(
        u16::from_le_bytes(memory.read_array(0x2ffe + 80).unwrap()),
        17
    );
}
#[test]
fn entropy_retains_accepted_bytes_handles_partial_faults_and_cancels_old_snapshots() {
    for cancel in [false, true] {
        let (mut memory, page, wake) = fixture();
        let source = DirectSyscalls::default();
        let args = [0x2ffe, 8, 4, 0, 0, 0];
        assert_eq!(source.invoke_entropy(args, &mut memory), None);
        let wait = parked(&source, 278, args, &mut memory, &wake);
        let retired = wait.file_pending().unwrap();
        if cancel {
            wait.cancel_copies();
        }
        memory.write(0x2ffe, b"zz").unwrap();
        page.finish();
        assert_eq!(
            value(source.resume(wait, &mut memory)),
            if cancel { Err(Errno(4)) } else { Ok(8) }
        );
        assert_eq!(memory.read_array::<2>(0x2ffe).unwrap(), *b"zz");
        if cancel {
            assert_eq!(memory.read_array::<6>(0x3000).unwrap(), [0; 6]);
        }
        let before = memory.read_array::<6>(0x3000).unwrap();
        let _ =
            source.start_retained_file(retired, 278, args, &mut memory, 1, &Arc::downgrade(&wake));
        assert_eq!(memory.read_array::<6>(0x3000).unwrap(), before);
    }
    let (mut memory, _page, _wake) = fixture();
    let source = DirectSyscalls::default();
    assert_eq!(
        source.invoke_entropy([0x3000, 8, 6, 0, 0, 0], &mut memory),
        Some(Err(Errno(22)))
    );
    memory.unmap(0x3000, PAGE_SIZE).unwrap();
    // Retain another asynchronous source so the permanent destination failure
    // uses the same production cursor as a backed output.
    memory.unmap(0x4000, PAGE_SIZE).unwrap();
    let _unused = file::copyout_tests::install(&mut memory, 0x4000);
    assert_eq!(
        source.invoke_entropy([0x2ffe, 8, 0, 0, 0, 0], &mut memory),
        Some(Ok(2))
    );
}
