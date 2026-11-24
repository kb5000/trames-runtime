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
fn followed(c: &Connection, work: FileWork, target: &[u8]) -> FileWork {
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), target);
    let work = waiting(work);
    receive(c, 2, 71);
    assert!(work.ready() && !work.waits_for_fuse());
    assert!(!work.host_work() && work.fuse_signal_request().is_none());
    work
}
fn joined(work: FileWork, v: &mut Vfs) -> FileWork {
    let FileOutcome::Owner(work) = work.run() else {
        panic!("missing proc publication must join owner")
    };
    let FileOutcome::Waiting(work) = work.resume_owner(v) else {
        panic!("owner must retain a resumable operation")
    };
    assert!(work.ready());
    work
}

#[test]
fn proc_private_volume_directory_components_keep_the_original_inode_during_native_wait() {
    let store = std::env::temp_dir().join(format!(
        "trames-fuse-indexed-{}-{}",
        std::process::id(),
        trames_memory::new_backing_identity()
    ));
    let base = Vfs::open_disk(&store, DiskOptions::default()).unwrap();
    let (mut v, dev) = mount_vfs(base, 0);
    for path in [
        b"/parent".as_slice(),
        b"/parent/dir",
        b"/parent/dir/leaf",
        b"/parent/peer",
        b"/moved",
        b"/moved/peer",
    ] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    let fd = v
        .open_at(AT_FDCWD, b"/parent/dir", O_PATH | O_DIRECTORY, 0)
        .unwrap();
    let expected = v.stat_at(AT_FDCWD, b"/parent/dir/leaf").unwrap();
    publish(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/link/leaf", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(
        c,
        &receive(c, 5, 71),
        format!("/proc/self/fd/{fd}").as_bytes(),
    );
    let work = waiting(work);
    receive(c, 2, 71);
    // The persistent root needs its native stage before the proc owner join.
    assert!(work.host_work() && work.ready());
    let work = waiting(work);
    let work = waiting(joined(work, &mut v));
    assert!(work.host_work() && work.ready() && !work.waits_for_fuse());
    // This native stage has not looked up the proc fd yet. Keep that fd live;
    // closing it here legitimately returns ENOENT before any target is accepted.
    v.rename_at(AT_FDCWD, b"/parent/dir", AT_FDCWD, b"/moved/dir", 0)
        .unwrap();
    v.mkdir_at(AT_FDCWD, b"/parent/dir", 0o755).unwrap();
    v.mkdir_at(AT_FDCWD, b"/parent/dir/leaf", 0o755).unwrap();
    let FileValue::FuseStat(actual, _) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(&actual[..16], &expected[..16]);
    v.close(fd).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    drop(paths);
    drop(dev);
    drop(v);
    std::fs::remove_dir_all(store).unwrap();
}

#[test]
fn proc_fuse_chdir_keeps_the_original_directory_through_rename_and_fd_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, fd) = open_directory(&v, c, false);
    publish(&mut v);
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/link".to_vec())));
    let work = followed(c, work, format!("/proc/self/fd/{fd}").as_bytes());
    let work = waiting(joined(work, &mut v));
    let getattr = receive(c, 3, 70);
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd
    );
    receive(c, 29, 70);
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry(70, 170, 0o40755)[40..]);
    answer(c, &getattr, &attr);
    let work = waiting(work);
    let access = receive(c, 34, 70);
    let rename = waiting(paths.namespace_work(NamespaceCall::Rename {
        oldfd: AT_FDCWD,
        old: b"/mnt/directory".to_vec(),
        newfd: AT_FDCWD,
        new: b"/mnt/moved".to_vec(),
        flags: 0,
    }));
    let mut root = [0; 104];
    root[16..].copy_from_slice(&entry(1, 1, 0o40755)[40..]);
    answer(c, &receive(c, 3, 1), &root);
    let rename = waiting(rename);
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    let rename = waiting(rename);
    answer(c, &receive(c, 3, 1), &root);
    let rename = waiting(rename);
    let missing = receive(c, 1, 1);
    c.write(&reply(id(&missing), -2, &[])).unwrap();
    let rename = waiting(rename);
    answer(c, &receive(c, 12, 1), &[]);
    assert!(matches!(finish(rename), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    assert_eq!(v.cwd().unwrap(), b"/");
    answer(c, &access, &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_eq!(v.cwd().unwrap(), b"/mnt/moved");
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "cwd retains the original lookup"
    );
    v.chdir(b"/").unwrap();
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn proc_fuse_chdir_denial_or_cancellation_does_not_publish_a_cwd() {
    for cancel in [false, true] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (_, fd) = open_directory(&v, c, false);
        publish(&mut v);
        let paths = v.path_queries();
        let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/link".to_vec())));
        let work = followed(c, work, format!("/proc/self/fd/{fd}").as_bytes());
        let work = waiting(joined(work, &mut v));
        let mut attr = [0; 104];
        attr[16..].copy_from_slice(&entry(70, 170, 0o40755)[40..]);
        answer(c, &receive(c, 3, 70), &attr);
        let work = waiting(work);
        let access = receive(c, 34, 70);
        v.shared_files().close_range(fd, fd, 0, 1).unwrap();
        receive(c, 29, 70);
        if cancel {
            drop(work);
            answer(c, &access, &[]);
        } else {
            c.write(&reply(id(&access), -13, &[])).unwrap();
            assert!(matches!(finish(work), Err(Errno(13))));
        }
        assert_eq!(v.cwd().unwrap(), b"/");
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn proc_chdir_rejects_fuse_regular_files_and_anonymous_inodes_as_not_directories() {
    for anonymous in [false, true] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let fd = if anonymous {
            v.eventfd(0, 0).unwrap()
        } else {
            open_file(&v, c, 0).1
        };
        publish(&mut v);
        let paths = v.path_queries();
        let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/link".to_vec())));
        let work = followed(c, work, format!("/proc/self/fd/{fd}").as_bytes());
        assert!(matches!(finish(joined(work, &mut v)), Err(Errno(20))));
        assert_eq!(v.cwd().unwrap(), b"/");
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
}

#[test]
fn owner_join_resumes_stat_without_replaying_the_fuse_link() {
    for unavailable in [false, true] {
        struct Unavailable;
        impl ProcSource for Unavailable {
            fn available(&self, _: ProcRefresh) -> bool {
                false
            }
            fn observe(&self, _: ProcQuery<'_>) -> RuntimeInfo {
                panic!("unavailable provider")
            }
        }
        let (mut v, dev) = mounted();
        publish(&mut v);
        if unavailable {
            v.set_proc_source(Arc::new(Unavailable));
        }
        let expected = v.stat_at(AT_FDCWD, b"/proc/self/status").unwrap();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        assert!(paths.statx_at(AT_FDCWD, b"/mnt/link", false).is_none());
        let work = followed(c, paths.take_fuse_stat().unwrap(), b"/proc/self/status");
        let work = joined(work, &mut v);
        let FileValue::FuseStat(stat, _) = finish(work).unwrap() else {
            panic!()
        };
        assert_eq!(stat, expected);
        assert_eq!(
            c.read(8192),
            Err(Errno(11)),
            "no second FUSE pathname traversal"
        );
    }
}

#[test]
fn proc_fd_open_keeps_the_original_reservation_and_original_memfd_inode() {
    let (mut v, dev) = mounted();
    let original = v.memfd_create(b"original", 0).unwrap();
    v.write(original, b"retained bytes").unwrap();
    publish(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/link", 0, 0, 0, &files)
        .is_none());
    let work = followed(
        c,
        paths.take_open_work().unwrap(),
        format!("/proc/self/fd/{original}").as_bytes(),
    );
    let occupied = v
        .open_at(AT_FDCWD, b"/occupied", O_CREAT | 2, 0o600)
        .unwrap();
    let work = joined(work, &mut v);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    assert!((fd as u32) < occupied);
    v.close(original).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        original
    );
    assert_eq!(v.read(fd as u32, 32).unwrap(), b"retained bytes");
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn joined_proc_directory_can_return_to_a_daemon_and_survive_fd_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, fd) = open_directory(&v, c, false);
    publish(&mut v);
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/link/leaf", false).is_none());
    let work = followed(
        c,
        paths.take_fuse_stat().unwrap(),
        format!("/proc/self/fd/{fd}").as_bytes(),
    );
    let work = joined(work, &mut v);
    let work = waiting(work);
    assert!(work.waits_for_fuse());
    let leaf = receive(c, 1, 70);
    assert_eq!(&leaf[40..], b"leaf\0");
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd
    );
    receive(c, 29, 70);
    answer(c, &leaf, &entry(72, 172, 0o100600));
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
    let mut forgotten = Vec::new();
    while let Ok(request) = c.read(8192) {
        assert_eq!(op(&request), 2);
        forgotten.push(u64::from_le_bytes(request[16..24].try_into().unwrap()));
    }
    forgotten.sort_unstable();
    assert_eq!(forgotten, [70, 72]);
}

#[test]
fn proc_fd_reopen_retains_the_fuse_inode_and_gets_a_fresh_handle() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, original) = open_file(&v, c, 2);
    publish(&mut v);
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/link", 0, 0, 0, &files)
        .is_none());
    let work = followed(
        c,
        paths.take_open_work().unwrap(),
        format!("/proc/self/fd/{original}").as_bytes(),
    );
    let work = waiting(joined(work, &mut v));
    let getattr = receive(c, 3, 10);
    assert_eq!(&getattr[48..56], &9876u64.to_le_bytes());
    v.shared_files()
        .close_range(original, original, 0, 1)
        .unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        original
    );
    answer(c, &receive(c, 25, 10), &[]);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "GETATTR retains the original handle until its reply"
    );
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&entry(10, 210, 0o100600)[40..]);
    answer(c, &getattr, &attr);
    let work = waiting(work);
    let open = receive(c, 14, 10);
    let release = receive(c, 18, 10);
    assert_eq!(&release[40..48], &9876u64.to_le_bytes());
    answer(c, &release, &[]);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&2222u64.to_le_bytes());
    answer(c, &open, &handle);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let target = v
        .shared_files()
        .lookup(fd as u32)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let work = waiting(FileWork::new(
        &paths,
        target,
        FileCommand::Read {
            count: 8,
            offset: None,
        },
    ));
    let read = receive(c, 15, 10);
    assert_eq!(&read[40..48], &2222u64.to_le_bytes());
    assert_eq!(&read[48..56], &0u64.to_le_bytes());
    answer(c, &read, b"fresh");
    assert_eq!(finish(work).unwrap().into_bytes().unwrap(), b"fresh");
    v.shared_files()
        .close_range(fd as u32, fd as u32, 0, 1)
        .unwrap();
    answer(c, &receive(c, 25, 10), &[]);
    let release = receive(c, 18, 10);
    assert_eq!(&release[40..48], &2222u64.to_le_bytes());
    answer(c, &release, &[]);
    receive(c, 2, 10);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn owner_checkpoint_can_resume_an_original_legacy_pty_open() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/link", 2, 0, 0, &files)
        .is_none());
    let work = followed(c, paths.take_open_work().unwrap(), b"/dev/ptmx");
    let FileValue::Count(fd) = finish(joined(work, &mut v)).unwrap() else {
        panic!()
    };
    v.pty(fd as u32)
        .unwrap()
        .unwrap()
        .pair
        .locked
        .store(false, Ordering::Relaxed);
    let peer = v.open_pty_peer(fd as u32, 2 | 0x100).unwrap();
    assert!(v.pty(peer).unwrap().is_some());
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn cancelled_owner_continuation_releases_its_original_open_slot() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/link", 0, 0, 0, &files)
        .is_none());
    let work = followed(c, paths.take_open_work().unwrap(), b"/proc/self/status");
    let FileOutcome::Owner(work) = work.run() else {
        panic!()
    };
    let occupied = v
        .open_at(AT_FDCWD, b"/occupied", O_CREAT | 2, 0o600)
        .unwrap();
    drop(work);
    let released = v
        .open_at(AT_FDCWD, b"/released", O_CREAT | 2, 0o600)
        .unwrap();
    assert!(released < occupied);
    v.umount(b"/mnt", 0).unwrap();
}

#[test]
fn namespace_parent_resumes_through_the_original_proc_directory() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/outside", 0o755).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/outside", O_DIRECTORY, 0).unwrap();
    publish(&mut v);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
        fd: AT_FDCWD,
        path: b"/mnt/link/new".to_vec(),
        mode: 0o700,
    }));
    let work = followed(c, work, format!("/proc/self/fd/{fd}").as_bytes());
    assert!(matches!(
        finish(joined(work, &mut v)),
        Ok(FileValue::Count(0))
    ));
    assert!(v.is_directory(b"/outside/new"));
    assert_eq!(c.read(8192), Err(Errno(11)));
}
