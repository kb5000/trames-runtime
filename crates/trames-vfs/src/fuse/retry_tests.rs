// SPDX-License-Identifier: GPL-3.0-or-later
//! Revalidate only on a bounded ESTALE boundary, never on an ordinary wait.
use super::*;

fn stale(c: &Connection, request: &[u8]) {
    c.write(&reply(id(request), -116, &[])).unwrap();
}

#[test]
fn pathname_lookup_stale_is_bounded_and_an_open_keeps_its_original_reserved_slot() {
    for opening in [false, true] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        let slot = v.shared_files().reserve().unwrap();
        let expected = slot.number();
        drop(slot);
        let work = if opening {
            assert!(paths
                .open_at_resolve(AT_FDCWD, b"/mnt/missing", O_PATH, 0, 0, &files)
                .is_none());
            paths.take_open_work().unwrap()
        } else {
            assert!(paths.statx_at(AT_FDCWD, b"/mnt/missing", false).is_none());
            paths.take_fuse_stat().unwrap()
        };
        stale(c, &receive(c, 1, 1));
        let work = waiting(work);
        assert!(!work.ready());
        let request = receive(c, 1, 1);
        assert_eq!(&request[40..], b"missing\0");
        let work = waiting(work);
        assert_eq!(c.read(8192), Err(Errno(11)));
        // The second request has been sent, with the same reserved FD still
        // unavailable to another open. An ordinary waiter does not replay it.
        let spare = v.shared_files().reserve().unwrap();
        assert_eq!(spare.number(), expected + u32::from(opening));
        drop(spare);
        // Abort ends the accepted request and releases the reservation.
        c.abort();
        assert!(finish(work).is_err());
        assert_eq!(v.shared_files().reserve().unwrap().number(), expected);
    }
}

#[test]
fn repeated_lookup_stale_returns_the_second_error_without_another_request() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/file", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    stale(c, &receive(c, 1, 1));
    let work = waiting(work);
    stale(c, &receive(c, 1, 1));
    assert!(matches!(finish(work), Err(Errno(116))));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn nested_stale_rewalks_the_original_full_name_and_forgets_the_failed_parent() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/a/b", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 1, 1), &entry(22, 122, 0o40755));
    let work = waiting(work);
    stale(c, &receive(c, 1, 22));
    let work = waiting(work);
    receive(c, 2, 22);
    let a = receive(c, 1, 1);
    assert_eq!(&a[40..], b"a\0");
    answer(c, &a, &entry(32, 132, 0o40755));
    let work = waiting(work);
    let b = receive(c, 1, 32);
    assert_eq!(&b[40..], b"b\0");
    answer(c, &b, &entry(33, 133, 0o100644));
    let FileValue::FuseStat(stat, _) = finish(work).unwrap() else {
        panic!("stat")
    };
    assert_eq!(u64::from_le_bytes(stat[8..16].try_into().unwrap()), 133);
    forget_each(c, &[32, 33]);
}

#[test]
fn stat_getattr_stale_has_one_outer_retry_but_descriptor_stat_does_not_rewalk() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/file", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let mut found = entry(22, 122, 0o100644);
    found[24..32].fill(0);
    answer(c, &receive(c, 1, 1), &found);
    let work = waiting(work);
    stale(c, &receive(c, 3, 22));
    let work = waiting(work);
    receive(c, 2, 22);
    answer(c, &receive(c, 1, 1), &found);
    let work = waiting(work);
    stale(c, &receive(c, 3, 22));
    assert!(matches!(finish(work), Err(Errno(116))));
    receive(c, 2, 22);
    assert_eq!(c.read(8192), Err(Errno(11)));

    let (_opened, fd) = open_file(&v, c, 0);
    assert!(paths.statx_fd(fd).is_none());
    let work = paths.take_fuse_stat().unwrap();
    stale(c, &receive(c, 3, 10));
    assert!(matches!(finish(work), Err(Errno(116))));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn numeric_dirfd_is_read_again_only_at_explicit_stale_revalidation() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/fallback", 0o755).unwrap();
    v.import_file(b"/fallback/child", b"replacement".to_vec())
        .unwrap();
    let expected = v.stat_at(AT_FDCWD, b"/fallback/child").unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(
            AT_FDCWD,
            b"/mnt/directory",
            O_PATH | O_DIRECTORY,
            0,
            0,
            &files
        )
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!("directory FD")
    };
    assert!(paths.statx_at(fd as i32, b"child", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let request = receive(c, 1, 70);
    v.shared_files()
        .close_range(fd as u32, fd as u32, 0, 1)
        .unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/fallback", O_DIRECTORY, 0).unwrap(),
        fd as u32
    );
    assert!(!work.ready());
    assert_eq!(c.read(8192), Err(Errno(11)));
    stale(c, &request);
    let FileValue::FuseStat(stat, _) = finish(work).unwrap() else {
        panic!("revalidated stat")
    };
    assert_eq!(&stat[8..16], &expected[8..16]);
    for _ in 0..4 {
        match c.read(8192) {
            Ok(message) => assert_eq!(op(&message), 2),
            Err(Errno(11)) => return,
            other => panic!("unexpected daemon request: {other:?}"),
        }
    }
    panic!("bounded original lookup references")
}

#[test]
fn a_fixed_file_alias_remains_the_original_capability_during_stale_revalidation() {
    for pair in [false, true] {
        let (mut v, dev) = mounted();
        v.mkdir_at(AT_FDCWD, b"/fallback", 0o755).unwrap();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        assert!(paths
            .open_at_resolve(
                AT_FDCWD,
                b"/mnt/directory",
                O_PATH | O_DIRECTORY,
                0,
                0,
                &files
            )
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
        let FileValue::Count(fd) = finish(work).unwrap() else {
            panic!("directory FD")
        };
        let original = v.shared_files().lookup(fd as u32).unwrap().unwrap();
        if pair {
            assert!(paths
                .fd_pair([Some(Ok(original)), None], |view, aliases| {
                    view.statx_at(aliases[0] as i32, b"child", false)
                })
                .is_none());
        } else {
            assert!(matches!(
                paths.retained_control(original, |view, alias| {
                    view.statx_at(alias as i32, b"child", false)
                }),
                Err(Errno(95))
            ));
        }
        let work = paths.take_fuse_stat().unwrap();
        let request = receive(c, 1, 70);
        v.shared_files()
            .close_range(fd as u32, fd as u32, 0, 1)
            .unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/fallback", O_DIRECTORY, 0).unwrap(),
            fd as u32
        );
        stale(c, &request);
        let work = waiting(work);
        let request = receive(c, 1, 70);
        assert_eq!(&request[40..], b"child\0");
        answer(c, &request, &entry(71, 171, 0o100644));
        let FileValue::FuseStat(stat, _) = finish(work).unwrap() else {
            panic!("original fixed file")
        };
        assert_eq!(u64::from_le_bytes(stat[8..16].try_into().unwrap()), 171);
    }
}

#[test]
fn a_revalidated_symlink_still_enforces_the_original_openat2_boundary() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"mnt/link", O_PATH, 0, 8, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(22, 122, 0o120777));
    let work = waiting(work);
    stale(c, &receive(c, 5, 22));
    let work = waiting(work);
    receive(c, 2, 22);
    answer(c, &receive(c, 1, 1), &entry(23, 123, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 23), b"/outside");
    assert!(matches!(finish(work), Err(Errno(18))));
    receive(c, 2, 23);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn mkdir_callback_stale_rewalks_parent_once_and_does_not_retry_failed_filename_create() {
    for lookup_failure in [false, true] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
            fd: AT_FDCWD,
            path: b"/mnt/a/new".to_vec(),
            mode: 0o755,
        }));
        answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
        let work = waiting(work);
        let leaf = receive(c, 1, 70);
        if lookup_failure {
            stale(c, &leaf);
            assert!(matches!(finish(work), Err(Errno(116))));
        } else {
            c.write(&reply(id(&leaf), -2, &[])).unwrap();
            let work = waiting(work);
            stale(c, &receive(c, 9, 70));
            let work = waiting(work);
            receive(c, 2, 70);
            answer(c, &receive(c, 1, 1), &entry(71, 171, 0o40755));
            let work = waiting(work);
            c.write(&reply(id(&receive(c, 1, 71)), -2, &[])).unwrap();
            let work = waiting(work);
            stale(c, &receive(c, 9, 71));
            assert!(matches!(finish(work), Err(Errno(116))));
            receive(c, 2, 71);
        }
        if lookup_failure {
            receive(c, 2, 70);
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn empty_path_metadata_revalidates_once_but_descriptor_only_chmod_and_times_do_not() {
    for times in [false, true] {
        for empty in [false, true] {
            let (v, dev) = mounted();
            let c = dev.connection().unwrap();
            let (paths, fd) = open_file(&v, c, 0);
            let call = if times {
                NamespaceCall::Times {
                    fd: fd as i32,
                    path: empty.then(Vec::new),
                    times: None,
                    flags: if empty { 0x1000 } else { 0 },
                }
            } else {
                NamespaceCall::Chmod {
                    fd: fd as i32,
                    path: None,
                    mode: 0o640,
                    nofollow: false,
                    empty,
                }
            };
            let work = waiting(paths.namespace_work(call));
            stale(c, &receive(c, 4, 10));
            let work = if empty {
                let work = waiting(work);
                stale(c, &receive(c, 4, 10));
                work
            } else {
                work
            };
            assert!(matches!(finish(work), Err(Errno(116))));
            assert_eq!(c.read(8192), Err(Errno(11)));
        }
    }
}
