// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{CapturedOutput, DirectSyscalls, IoAttempt, Linux};
use std::sync::Arc;
use trames_memory::{Memory, PAGE_SIZE};

#[test]
fn source_and_solo_file_advice_share_fd_type_range_and_unused_operand_precedence() {
    let mut linux = Linux::new(0);
    linux
        .vfs
        .import_file(b"/file", b"unchanged".to_vec())
        .unwrap();
    let file = linux.vfs.open_at(-100, b"/file", 2, 0).unwrap();
    let path = linux
        .vfs
        .open_at(-100, b"/file", trames_vfs::O_PATH, 0)
        .unwrap();
    let directory = linux.vfs.open_at(-100, b"/", 0, 0).unwrap();
    let [pipe, _] = linux.vfs.pipe(0).unwrap();
    linux.vfs.seek(file, 3, 0).unwrap();
    let source = DirectSyscalls::default().with_paths(linux.vfs.path_queries());
    let mut memory = Memory::default();
    let stat = linux.vfs.stat_fd(file).unwrap();
    let mut calls = Vec::new();
    for advice in 0..=5 {
        calls.push((
            223,
            [file as u64, 1, i64::MAX as u64, advice, u64::MAX, u64::MAX],
            Ok(0),
        ));
    }
    calls.extend([
        (
            213,
            [
                file as u64,
                i64::MAX as u64,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            ],
            Ok(0),
        ),
        (213, [path as u64, 0, 0, 0, 0, 0], Ok(0)),
        (223, [path as u64, 0, 0, 5, 0, 0], Ok(0)),
        (223, [file as u64, 0, 0, 6, 0, 0], Err(Errno(22))),
        (223, [file as u64, 0, 0, 0x100000000, 0, 0], Err(Errno(22))),
        (223, [file as u64, 0, u64::MAX, 0, 0, 0], Err(Errno(22))),
        (213, [file as u64, u64::MAX, 0, 0, 0, 0], Err(Errno(22))),
        (223, [directory as u64, 0, 0, 0, 0, 0], Err(Errno(22))),
        (213, [pipe as u64, 0, 0, 0, 0, 0], Err(Errno(22))),
        (
            223,
            [u32::MAX as u64, u64::MAX, u64::MAX, u64::MAX, 0, 0],
            Err(Errno(9)),
        ),
        (213, [(1u64 << 32) | file as u64, 0, 0, 0, 0, 0], Ok(0)),
    ]);
    for (number, args, expected) in calls {
        assert!(DirectSyscalls::file_entry(number, args));
        assert!(source.supports_call(number, args));
        assert_eq!(
            source.invoke_file(number, args, &mut memory),
            Some(expected),
            "source {number} {args:?}"
        );
        assert_eq!(
            linux.syscall(
                number as u64,
                args,
                &mut memory,
                &mut CapturedOutput::default()
            ),
            expected,
            "solo {number} {args:?}"
        );
    }
    assert_eq!(linux.vfs.seek(file, 0, 1), Ok(3));
    assert_eq!(
        linux.vfs.stat_fd(file).unwrap(),
        stat,
        "hints change neither metadata nor file contents"
    );
    assert_eq!(linux.vfs.pread(file, 9, 0).unwrap(), b"unchanged");
    assert_eq!(
        memory.resident_bytes(),
        0,
        "no guest pointer, page-in or resident charge"
    );
}

#[test]
fn source_file_advice_observes_original_live_files_and_detached_membership() {
    let mut original = Linux::new(0);
    original.vfs.import_file(b"/file", vec![7]).unwrap();
    let fd = original.vfs.open_at(-100, b"/file", 0, 0).unwrap();
    let source = DirectSyscalls::default().with_paths(original.vfs.path_queries());
    let detached = original.clone_with_files(false);
    let detached_source = DirectSyscalls::default().with_paths(detached.vfs.path_queries());
    let mut shared = original.clone_with_files(true);
    let mut unrelated = Linux::new(0);
    assert_eq!(unrelated.vfs.open_at(-100, b"/", 0, 0).unwrap(), fd);
    let mut memory = Memory::default();
    let args = [fd as u64, 0, PAGE_SIZE, 3, 0, 0];
    assert_eq!(source.invoke_file(223, args, &mut memory), Some(Ok(0)));
    shared.vfs.close(fd).unwrap();
    assert_eq!(shared.vfs.open_at(-100, b"/", 0, 0).unwrap(), fd);
    assert_eq!(
        source.invoke_file(223, args, &mut memory),
        Some(Err(Errno(22)))
    );
    assert_eq!(
        detached_source.invoke_file(223, args, &mut memory),
        Some(Ok(0))
    );
    shared.vfs.close(fd).unwrap();
    assert_eq!(
        source.invoke_file(213, args, &mut memory),
        Some(Err(Errno(9)))
    );
    assert_eq!(
        detached_source.invoke_file(213, args, &mut memory),
        Some(Ok(0))
    );
}

#[test]
fn owned_and_direct_file_advice_need_no_memory_or_native_executor() {
    let mut vfs = trames_vfs::Vfs::default();
    vfs.import_file(b"/file", vec![7]).unwrap();
    let fd = vfs.open_at(-100, b"/file", 0, 0).unwrap();
    let mut memory = Memory::default();
    let no_source = DirectSyscalls::default();
    let args = [fd as u64, 0, 0, 0, u64::MAX, u64::MAX];
    assert!(!no_source.supports_call(213, args));
    assert_eq!(no_source.invoke_file(213, args, &mut memory), None);
    struct Target;
    impl trames_vfs::IoWake for Target {
        fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {}
    }
    let wake: Arc<dyn trames_vfs::IoWake> = Arc::new(Target);
    let target = Arc::downgrade(&wake);
    assert!(matches!(
        no_source.start_owned_file(&mut vfs, 213, args, &mut memory, 1, &target),
        Some(IoAttempt::Complete(Ok(0)))
    ));
    let source = DirectSyscalls::default().with_paths(vfs.path_queries());
    assert!(matches!(
        source.start(223, args, &mut memory, 1, &target, None),
        Some(IoAttempt::Complete(Ok(0)))
    ));
    assert!(matches!(
        source.start_file_call(213, args, &mut memory, 1, &target),
        Some(IoAttempt::Complete(Ok(0)))
    ));
    assert_eq!(memory.resident_bytes(), 0);
}
