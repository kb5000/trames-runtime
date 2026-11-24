// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn publish(v: &mut Vfs) {
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                fds: v.fd_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
}
fn follow(c: &Connection, work: FileWork, target: &[u8]) -> FileWork {
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), target);
    let work = waiting(work);
    receive(c, 2, 71);
    work
}
fn join(work: FileWork, v: &mut Vfs) -> FileWork {
    let FileOutcome::Owner(work) = work.run() else {
        panic!("expected original proc metadata")
    };
    let FileOutcome::Waiting(work) = work.resume_owner(v) else {
        panic!()
    };
    work
}
fn count(work: FileWork) {
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
}

#[test]
fn proc_directory_access_uses_the_retained_node_after_source_fd_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, fd) = open_directory(&v, c, false);
    publish(&mut v);
    let paths = v.path_queries();
    assert!(paths
        .access_at(AT_FDCWD, b"/mnt/link", 1, false, false)
        .is_none());
    let work = follow(
        c,
        paths.take_fuse_stat().unwrap(),
        format!("/proc/self/fd/{fd}").as_bytes(),
    );
    let work = waiting(join(work, &mut v));
    let access = receive(c, 34, 70);
    assert_eq!(&access[40..44], &1u32.to_le_bytes());
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd
    );
    receive(c, 29, 70);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "the inode survives until ACCESS finishes"
    );
    answer(c, &access, &[]);
    count(work);
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn proc_regular_fuse_file_access_keeps_its_inode_until_reply_or_cancel() {
    for cancel in [false, true] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (_, fd) = open_file(&v, c, 2);
        publish(&mut v);
        let paths = v.path_queries();
        assert!(paths
            .access_at(AT_FDCWD, b"/mnt/link", 6, false, false)
            .is_none());
        let work = follow(
            c,
            paths.take_fuse_stat().unwrap(),
            format!("/proc/self/fd/{fd}").as_bytes(),
        );
        let work = waiting(join(work, &mut v));
        let access = receive(c, 34, 10);
        v.shared_files().close_range(fd, fd, 0, 1).unwrap();
        answer(c, &receive(c, 25, 10), &[]);
        answer(c, &receive(c, 18, 10), &[]);
        assert_eq!(c.read(8192), Err(Errno(11)));
        if cancel {
            drop(work);
            answer(c, &access, &[]);
        } else {
            answer(c, &access, &[]);
            count(work);
        }
        receive(c, 2, 10);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn access_enosys_is_cached_after_the_actual_inode_request() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, fd) = open_file(&v, c, 0);
    publish(&mut v);
    let paths = v.path_queries();
    for first in [true, false] {
        assert!(paths
            .access_at(AT_FDCWD, b"/mnt/link", 4, false, false)
            .is_none());
        let work = follow(
            c,
            paths.take_fuse_stat().unwrap(),
            format!("/proc/self/fd/{fd}").as_bytes(),
        );
        let work = join(work, &mut v);
        if first {
            let work = waiting(work);
            let access = receive(c, 34, 10);
            c.write(&reply(id(&access), -38, &[])).unwrap();
            count(work);
        } else {
            count(work);
        }
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn proc_fuse_file_access_checks_live_mount_flags_at_the_linux_stages() {
    for (flags, mask, error) in [(1, 2, 30), (8, 1, 13)] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (_, fd) = open_file(&v, c, 0);
        publish(&mut v);
        let paths = v.path_queries();
        assert!(paths
            .access_at(AT_FDCWD, b"/mnt/link", mask, false, false)
            .is_none());
        let work = follow(
            c,
            paths.take_fuse_stat().unwrap(),
            format!("/proc/self/fd/{fd}").as_bytes(),
        );
        let work = join(work, &mut v);
        v.mount(None, b"/mnt", None, 32 | 4096 | flags, None)
            .unwrap();
        let work = if mask == 2 {
            let work = waiting(work);
            answer(c, &receive(c, 34, 10), &[]);
            work
        } else {
            work
        };
        assert!(matches!(finish(work), Err(Errno(value)) if value == error));
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn access_daemon_errors_precede_readonly_and_success_samples_the_reply_time_flags() {
    for (initial, changed, daemon_error, expected) in [
        (1, 1, 13, 13),
        (1, 1, 1, 1),
        (0, 1, 0, 30),
        (1, 0, 0, 0),
        (0, 1, 38, 30),
    ] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        v.mount(None, b"/mnt", None, 32 | 4096 | initial, None)
            .unwrap();
        let paths = v.path_queries();
        assert!(paths
            .access_at(AT_FDCWD, b"/mnt/file", 2, false, false)
            .is_none());
        let work = paths.take_fuse_stat().unwrap();
        answer(c, &receive(c, 1, 1), &entry(72, 172, 0o100600));
        let work = waiting(work);
        let request = receive(c, 34, 72);
        v.mount(None, b"/mnt", None, 32 | 4096 | changed, None)
            .unwrap();
        c.write(&reply(id(&request), -daemon_error, &[])).unwrap();
        let result = finish(work);
        if expected == 0 {
            assert!(matches!(result, Ok(FileValue::Count(0))));
        } else {
            assert!(matches!(result, Err(Errno(error)) if error == expected));
        }
        receive(c, 2, 72);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    v.mount(None, b"/mnt", None, 32 | 4096 | 1 | 8, None)
        .unwrap();
    let paths = v.path_queries();
    assert!(paths
        .access_at(AT_FDCWD, b"/mnt/file", 3, false, false)
        .is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 1, 1), &entry(72, 172, 0o100777));
    assert!(matches!(finish(work), Err(Errno(13))));
    receive(c, 2, 72);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "noexec is checked before ACCESS"
    );
}

#[test]
fn access_to_proc_memfd_and_anonymous_inode_uses_real_inode_permissions() {
    for anonymous in [false, true] {
        let (mut v, dev) = mounted();
        let fd = if anonymous {
            v.eventfd(0, 0).unwrap()
        } else {
            v.memfd_create(b"original", 0).unwrap()
        };
        if !anonymous {
            v.chmod_fd(fd, 0o600).unwrap();
        }
        publish(&mut v);
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        for (mask, expected) in [(0, 0), (6, 0), (1, 13)] {
            assert!(paths
                .access_at(AT_FDCWD, b"/mnt/link", mask, false, false)
                .is_none());
            let work = follow(
                c,
                paths.take_fuse_stat().unwrap(),
                format!("/proc/self/fd/{fd}").as_bytes(),
            );
            let result = finish(join(work, &mut v));
            if expected == 0 {
                assert!(matches!(result, Ok(FileValue::Count(0))));
            } else {
                assert!(matches!(result, Err(Errno(value)) if value == expected));
            }
            assert_eq!(c.read(8192), Err(Errno(11)));
        }
    }
}

#[test]
fn proc_fuse_access_uses_real_or_effective_ids_after_the_owner_wait() {
    let (mut v, _unused) = mounted();
    v.mkdir_at(AT_FDCWD, b"/world", 0o755).unwrap();
    let device_fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
    let dev = v.fuse_device(device_fd).unwrap().unwrap();
    let options = format!("fd={device_fd},rootmode=40755,user_id=0,group_id=0,allow_other");
    v.mount(None, b"/world", Some(b"fuse"), 0, Some(options.as_bytes()))
        .unwrap();
    let c = dev.connection().unwrap();
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    answer(c, &receive(c, 26, 0), &version);
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/world/data", 0, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &entry(10, 210, 0o100600));
    let work = waiting(work);
    answer(c, &receive(c, 14, 10), &[0; 16]);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    // A target process owned by the caller's real UID lets both authority
    // choices traverse /proc, without a root-owned fd directory masking the
    // final FUSE ACCESS request under real-ID access(2).
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 2,
                tgid: 2,
                credentials: Credentials::user(1000, 1000),
                fds: v.fd_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    v.credentials.uid = 1000;
    v.credentials.gid = 1000;
    let paths = v.path_queries();
    for effective in [false, true] {
        assert!(paths
            .access_at(AT_FDCWD, b"/world/link", 4, effective, false)
            .is_none());
        let work = follow(
            c,
            paths.take_fuse_stat().unwrap(),
            format!("/proc/2/fd/{fd}").as_bytes(),
        );
        let work = waiting(join(work, &mut v));
        let access = receive(c, 34, 10);
        assert_eq!(
            &access[24..28],
            &(if effective { 0u32 } else { 1000 }).to_le_bytes()
        );
        answer(c, &access, &[]);
        count(work);
        assert_eq!(paths.view.borrow().credentials.fsuid, 0);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn readonly_special_fuse_inode_delegates_write_and_f_ok_to_the_daemon() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    v.mount(None, b"/mnt", None, 32 | 4096 | 1, None).unwrap();
    let paths = v.path_queries();
    for mask in [0, 2] {
        assert!(paths
            .access_at(AT_FDCWD, b"/mnt/device", mask, false, false)
            .is_none());
        let work = paths.take_fuse_stat().unwrap();
        answer(c, &receive(c, 1, 1), &entry(72, 172, 0o020666));
        let work = waiting(work);
        let access = receive(c, 34, 72);
        assert_eq!(&access[40..44], &mask.to_le_bytes());
        answer(c, &access, &[]);
        count(work);
        receive(c, 2, 72);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn removed_bind_root_checks_allow_other_before_climbing_to_an_ordinary_parent() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, fd) = open_directory(&v, c, false);
    v.mkdir_at(AT_FDCWD, b"/alias", 0o755).unwrap();
    v.import_file(b"/outside", b"ordinary".to_vec()).unwrap();
    let tree = MountFdCall::Tree {
        fd: fd as i32,
        path: Vec::new(),
        flags: 0x1000 | 1,
    }
    .run(&mut v)
    .unwrap() as u32;
    MountFdCall::Move {
        from: tree as i32,
        source: Vec::new(),
        to: AT_FDCWD,
        target: b"/alias".to_vec(),
        flags: 4,
    }
    .run(&mut v)
    .unwrap();
    v.shared_files().close_range(tree, tree, 0, 1).unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/alias".to_vec())));
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry(70, 170, 0o40755)[40..]);
    answer(c, &receive(c, 3, 70), &attr);
    let work = waiting(work);
    answer(c, &receive(c, 34, 70), &[]);
    count(work);
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Unlink {
        fd: AT_FDCWD,
        path: b"/mnt/directory".to_vec(),
        directory: true,
    }));
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry(1, 1, 0o40755)[40..]);
    answer(c, &receive(c, 3, 1), &attr);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    let work = waiting(work);
    answer(c, &receive(c, 11, 1), &[]);
    count(work);
    v.credentials = Credentials::user(1000, 1000);
    assert!(matches!(
        v.path_queries().statx_at(AT_FDCWD, b"../outside", false),
        Some(Err(Errno(13)))
    ));
}
