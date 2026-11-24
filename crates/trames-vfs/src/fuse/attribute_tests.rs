// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn chmod(path: &[u8], mode: u32) -> NamespaceCall {
    NamespaceCall::Chmod {
        fd: AT_FDCWD,
        path: Some(path.to_vec()),
        mode,
        nofollow: false,
        empty: false,
    }
}
fn attr(mode: u32) -> [u8; 104] {
    let mut out = [0; 104];
    out[16..].copy_from_slice(&entry(70, 230, mode)[40..]);
    out
}
fn original_fd(v: &Vfs, c: &Connection, flags: u32) -> u32 {
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", flags, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o106755));
    let work = if flags & O_PATH == 0 {
        let work = waiting(work);
        answer(
            c,
            &receive(c, 14, 70),
            &123u64
                .to_le_bytes()
                .into_iter()
                .chain([0; 8])
                .collect::<Vec<_>>(),
        );
        work
    } else {
        work
    };
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    fd as u32
}
#[test]
fn chmod_uses_the_accepted_node_and_only_publishes_daemon_attributes() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let work = waiting(v.path_queries().namespace_work(chmod(b"/mnt/file", 0o671)));
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100644));
    let work = waiting(work);
    let request = receive(c, 4, 70);
    assert_eq!(request.len(), 128);
    assert_eq!(&request[40..44], &1u32.to_le_bytes());
    assert_eq!(&request[108..112], &0o100671u32.to_le_bytes());
    answer(c, &request, &attr(0o100640));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn chown_getattr_and_setattr_keep_the_original_empty_fd_and_writer() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = original_fd(&v, c, O_PATH);
    let work = waiting(v.path_queries().namespace_work(NamespaceCall::Chown {
        fd: fd as i32,
        path: None,
        uid: 12,
        gid: 13,
        nofollow: false,
        empty: true,
    }));
    let capabilities = receive(c, 22, 70);
    c.write(&reply(id(&capabilities), -61, &[])).unwrap();
    let work = waiting(work);
    let refresh = receive(c, 3, 70);
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd
    );
    assert_eq!(
        v.mount(None, b"/mnt", None, 4096 | 32 | 1, None),
        Err(Errno(16))
    );
    answer(c, &refresh, &attr(0o106755));
    let work = waiting(work);
    let request = receive(c, 4, 70);
    assert_eq!(&request[40..44], &7u32.to_le_bytes());
    assert_eq!(&request[108..112], &0o100755u32.to_le_bytes());
    assert_eq!(&request[116..120], &12u32.to_le_bytes());
    assert_eq!(&request[120..124], &13u32.to_le_bytes());
    answer(c, &request, &attr(0o100755));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    v.mount(None, b"/mnt", None, 4096 | 32 | 1, None).unwrap();
    receive(c, 2, 70);
}
#[test]
fn cancelling_setattr_releases_its_writer_and_interrupts_only_the_sent_request() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let work = waiting(v.path_queries().namespace_work(chmod(b"/mnt/file", 0o600)));
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100644));
    let work = waiting(work);
    let request = receive(c, 4, 70);
    assert_eq!(
        v.mount(None, b"/mnt", None, 4096 | 32 | 1, None),
        Err(Errno(16))
    );
    drop(work);
    let interrupt = receive(c, 36, 0);
    assert_eq!(&interrupt[40..48], &request[8..16]);
    receive(c, 2, 70);
    v.mount(None, b"/mnt", None, 4096 | 32 | 1, None).unwrap();
    answer(c, &request, &attr(0o100600));
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn malformed_and_rejected_setattr_replies_do_not_publish_requested_permissions() {
    for reply_kind in 0..3 {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let fd = original_fd(&v, c, O_PATH);
        let descriptor = v.descriptor(fd).unwrap();
        let node = {
            let open = descriptor.open.borrow();
            let Some(events::SharedControl::FuseFile(file)) = &open.control else {
                panic!()
            };
            file.inode().unwrap()
        };
        let work = waiting(v.path_queries().namespace_work(NamespaceCall::Chmod {
            fd: fd as i32,
            path: None,
            mode: 0o777,
            nofollow: false,
            empty: true,
        }));
        let request = receive(c, 4, 70);
        match reply_kind {
            0 => {
                c.write(&reply(id(&request), -1, &[])).unwrap();
            }
            1 => assert_eq!(c.write(&reply(id(&request), 0, &[0; 103])), Err(Errno(22))),
            _ => answer(c, &request, &attr(0o040755)),
        }
        assert!(
            matches!(finish(work), Err(Errno(error)) if error == if reply_kind == 0 { 1 } else { 5 })
        );
        assert_eq!(node.borrow().mode, 0o106755);
    }
}
#[test]
fn timestamp_now_and_omit_have_distinct_wire_bits_and_omit_both_needs_no_lookup() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Times {
        fd: AT_FDCWD,
        path: Some(b"/mnt/file".to_vec()),
        times: Some([[0, UTIME_NOW], [0, UTIME_OMIT]]),
        flags: 0,
    }));
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100644));
    let work = waiting(work);
    let request = receive(c, 4, 70);
    assert_eq!(&request[40..44], &0x90u32.to_le_bytes());
    answer(c, &request, &attr(0o100644));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    assert!(matches!(
        finish(paths.namespace_work(NamespaceCall::Times {
            fd: -123,
            path: Some(b"/absent".to_vec()),
            times: Some([[0, UTIME_OMIT]; 2]),
            flags: 0
        })),
        Ok(FileValue::Count(0))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
}
#[test]
fn data_fd_setattr_retains_the_original_open_until_completion_without_wire_fh() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = original_fd(&v, c, 0);
    let work = waiting(v.path_queries().namespace_work(NamespaceCall::Chmod {
        fd: fd as i32,
        path: None,
        mode: 0o600,
        nofollow: false,
        empty: false,
    }));
    let request = receive(c, 4, 70);
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    answer(c, &receive(c, 25, 70), &[]);
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert_eq!(&request[40..44], &1u32.to_le_bytes());
    assert_eq!(&request[48..56], &[0; 8]);
    answer(c, &request, &attr(0o100600));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 18, 70);
    receive(c, 2, 70);
}

#[test]
fn directory_attributes_are_shared_by_all_open_descriptions_after_setattr_and_getattr() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    let mut fds = Vec::new();
    for _ in 0..2 {
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
        answer(c, &receive(c, 1, 1), &entry(70, 230, 0o040755));
        let FileValue::Count(fd) = finish(work).unwrap() else {
            panic!()
        };
        fds.push(fd as u32);
    }
    let work = waiting(paths.namespace_work(chmod(b"/mnt/directory", 0o700)));
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o040755));
    let work = waiting(work);
    receive(c, 2, 70);
    answer(c, &receive(c, 4, 70), &attr(0o040700));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    for &fd in &fds {
        let (stat, _) = paths.statx_fd_cached(fd).unwrap().unwrap();
        assert_eq!(&stat[16..20], &0o040700u32.to_le_bytes());
    }
    assert!(paths.statx_fd(fds[0]).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 3, 70), &attr(0o040711));
    finish(work).unwrap();
    let (stat, _) = paths.statx_fd_cached(fds[1]).unwrap().unwrap();
    assert_eq!(&stat[16..20], &0o040711u32.to_le_bytes());
}

#[test]
fn an_older_getattr_returns_its_own_reply_without_replacing_setattr_cache() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = original_fd(&v, c, 0);
    let paths = v.path_queries();
    assert!(paths.statx_fd(fd).is_none());
    let old = paths.take_fuse_stat().unwrap();
    let request = receive(c, 3, 70);
    let set = waiting(paths.namespace_work(NamespaceCall::Chmod {
        fd: fd as i32,
        path: None,
        mode: 0o600,
        nofollow: false,
        empty: false,
    }));
    let mut reply = attr(0o100600);
    reply[..8].copy_from_slice(&3600u64.to_le_bytes());
    answer(c, &receive(c, 4, 70), &reply);
    assert!(matches!(finish(set), Ok(FileValue::Count(0))));
    answer(c, &request, &attr(0o100755));
    assert!(
        matches!(finish(old),Ok(FileValue::FuseStat(bytes,_))if bytes[16..20]==0o100755u32.to_le_bytes())
    );
    assert_eq!(
        paths.statx_fd_cached(fd).unwrap().unwrap().0[16..20],
        0o100600u32.to_le_bytes()
    );
}

#[test]
fn setattr_applies_but_expires_when_a_newer_read_finished_during_its_wait() {
    let (mut v, dev) = mount_vfs_options(Vfs::default(), 0, ",default_permissions,allow_other");
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", O_PATH, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(
        c,
        &receive(c, 3, 1),
        &permission_tests::attributes(1, 0o040755, 0),
    );
    let work = waiting(work);
    answer(
        c,
        &receive(c, 1, 1),
        &permission_tests::lookup_entry(70, 0o100755),
    );
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let fd = fd as u32;
    let set = waiting(paths.namespace_work(NamespaceCall::Chmod {
        fd: fd as i32,
        path: None,
        mode: 0o604,
        nofollow: false,
        empty: true,
    }));
    let request = receive(c, 4, 70);
    assert!(paths.statx_fd(fd).is_none());
    let get = paths.take_fuse_stat().unwrap();
    let mut reply = attr(0o100640);
    reply[..8].copy_from_slice(&3600u64.to_le_bytes());
    answer(c, &receive(c, 3, 70), &reply);
    finish(get).unwrap();
    reply[76..80].copy_from_slice(&0o100604u32.to_le_bytes());
    answer(c, &request, &reply);
    finish(set).unwrap();
    assert_eq!(
        paths.statx_fd_cached(fd).unwrap().unwrap().0[16..20],
        0o100604u32.to_le_bytes()
    );
    v.credentials = Credentials::user(1000, 1000);
    let paths = v.path_queries();
    assert!(paths
        .access_at_empty(fd as i32, b"", 4, true, false, true)
        .is_none());
    let work = paths.take_fuse_stat().unwrap();
    reply[76..80].copy_from_slice(&0o100600u32.to_le_bytes());
    answer(c, &receive(c, 3, 70), &reply);
    assert!(matches!(finish(work), Err(Errno(13))));
}

#[test]
fn failed_path_operations_still_publish_lookup_attributes_and_retire_old_identities() {
    for (suffix, flags, kind, generation, error) in [
        (b"".as_slice(), O_CREAT | 0x80 | 2, 0o100600, 0u64, 17),
        (b"", O_CREAT | 0x80 | 2, 0o040755, 0, 17),
        (b"", O_CREAT | 0x80 | 2, 0o120777, 0, 17),
        (b"/child", O_PATH, 0o100600, 0, 20),
        (b"/child", O_PATH, 0o100600, 1, 20),
        (b"/", O_PATH, 0o100600, 0, 20),
        (b"", O_NOFOLLOW, 0o120777, 0, 40),
    ] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let fd = original_fd(&v, c, O_PATH);
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        let mut path = b"/mnt/alias".to_vec();
        path.extend_from_slice(suffix);
        assert!(paths
            .open_at_resolve(AT_FDCWD, &path, flags, 0o600, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        let mut entry = entry(70, 230, kind);
        entry[8..16].copy_from_slice(&generation.to_le_bytes());
        answer(c, &receive(c, 1, 1), &entry);
        assert!(matches!(finish(work), Err(Errno(actual)) if actual == error));
        let cached = paths.statx_fd_cached(fd).unwrap();
        if kind & 0o170000 != 0o100000 || generation != 0 {
            assert!(matches!(cached, Err(Errno(5))));
        } else {
            assert_eq!(cached.unwrap().0[16..20], 0o100600u32.to_le_bytes());
        }
    }
}

#[test]
fn bad_identity_lookup_preserves_exclusive_create_and_path_only_open_precedence() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let fd = original_fd(&v, c, O_PATH);
    let paths = v.path_queries();
    assert!(paths.statx_fd(fd).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 3, 70), &attr(0o040755));
    assert!(matches!(finish(work), Err(Errno(5))));
    let files = FileEpoch::default().capture(&v, true);
    for (flags, expected) in [(O_CREAT | 0x80 | 2, Some(17)), (0, Some(5)), (O_PATH, None)] {
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/alias", flags, 0o600, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100600));
        match (finish(work), expected) {
            (Err(Errno(error)), Some(expected)) => assert_eq!(error, expected),
            (Ok(FileValue::Count(alias)), None) => {
                assert!(matches!(
                    paths.statx_fd_cached(alias as u32),
                    Some(Err(Errno(5)))
                ));
            }
            _ => panic!("incorrect bad-inode open precedence"),
        }
        while let Ok(message) = c.read(8192) {
            assert_eq!(op(&message), 2);
        }
    }
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/alias", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o100600));
    assert!(matches!(finish(work), Err(Errno(5))));
}

#[test]
fn a_followed_link_retires_the_old_type_before_readlink_completes() {
    let (mut v, dev) = mounted();
    v.import_file(b"/target", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let fd = original_fd(&v, c, O_PATH);
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/alias", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o120777));
    let work = waiting(work);
    let request = receive(c, 5, 70);
    assert!(matches!(paths.statx_fd_cached(fd), Some(Err(Errno(5)))));
    answer(c, &request, b"/target");
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(_, _))));
}
