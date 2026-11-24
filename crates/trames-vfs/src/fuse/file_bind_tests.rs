// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn linked_entry(node: u64, ino: u64, mode: u32) -> [u8; 128] {
    let mut out = entry(node, ino, mode);
    out[104..108].copy_from_slice(
        &(if mode & 0o170000 == 0o040000 {
            2u32
        } else {
            1u32
        })
        .to_le_bytes(),
    );
    out
}

#[test]
fn a_bound_regular_inode_uses_getattr_and_open_on_its_original_daemon_node() {
    let (mut v, dev) = mounted();
    v.import_file(b"/bound", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/file".to_vec()),
        target: b"/bound".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    answer(c, &receive(c, 1, 1), &linked_entry(10, 210, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "bind retains the lookup without opening the file"
    );
    assert!(paths.statx_at(AT_FDCWD, b"/bound", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&linked_entry(10, 210, 0o100644)[40..]);
    answer(c, &receive(c, 3, 10), &attr);
    let FileValue::FuseStat(stat, mount) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(u64::from_le_bytes(stat[8..16].try_into().unwrap()), 210);
    assert!(mount.is_root);
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/bound", 2, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 3, 10), &attr);
    let work = waiting(work);
    answer(c, &receive(c, 14, 10), &[0; 16]);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    assert!(paths.statx_fd_cached(fd as u32).unwrap().unwrap().1.is_root);
    let target = v
        .shared_files()
        .lookup(fd as u32)
        .unwrap()
        .unwrap()
        .file_target()
        .unwrap();
    let write = waiting(FileWork::new(
        &paths,
        target.clone(),
        FileCommand::Write {
            bytes: b"hi".to_vec(),
            offset: Some(0),
        },
    ));
    let write = no_capabilities(c, write);
    answer(c, &receive(c, 16, 10), &2u64.to_le_bytes());
    assert!(matches!(finish(write), Ok(FileValue::Count(2))));
    let read = waiting(FileWork::new(
        &paths,
        target.clone(),
        FileCommand::Read {
            count: 2,
            offset: Some(0),
        },
    ));
    answer(c, &receive(c, 15, 10), b"hi");
    assert!(matches!(finish(read), Ok(FileValue::Bytes(bytes)) if bytes == b"hi"));
    drop(target);
    v.close(fd as u32).unwrap();
    answer(c, &receive(c, 25, 10), &[]);
    answer(c, &receive(c, 18, 10), &[]);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "mount retains its inode after closing the OFD"
    );
    v.umount(b"/bound", 0).unwrap();
    receive(c, 2, 10);
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/mnt", 0).unwrap();
    assert_eq!(c.read(8192), Err(Errno(19)));
}

#[test]
fn a_fuse_file_can_be_the_covered_target_of_an_ordinary_file_bind() {
    let (mut v, dev) = mounted();
    v.import_file(b"/source", b"original".to_vec()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/source".to_vec()),
        target: b"/mnt/file".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    answer(c, &receive(c, 1, 1), &linked_entry(10, 210, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    let fd = v.open_at(AT_FDCWD, b"/mnt/file", 0, 0).unwrap();
    assert_eq!(v.read(fd, 8).unwrap(), b"original");
    v.close(fd).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/mnt/file", 0).unwrap();
    receive(c, 2, 10);
    v.umount(b"/mnt", 0).unwrap();
    assert_eq!(c.read(8192), Err(Errno(19)));
}

#[test]
fn bound_files_canonicalize_nodeid_generation_without_merging_reported_inode_numbers() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let mut roots = Vec::new();
    for (index, node) in [10, 11, 10].into_iter().enumerate() {
        let target = format!("/bound{index}");
        v.import_file(target.as_bytes(), Vec::new()).unwrap();
        let work = waiting(paths.namespace_work(NamespaceCall::Mount {
            source: Some(format!("/mnt/file{index}").into_bytes()),
            target: target.into_bytes(),
            kind: None,
            flags: 4096,
            data: None,
        }));
        answer(c, &receive(c, 1, 1), &linked_entry(node, 210, 0o100644));
        assert!(matches!(finish(work), Ok(FileValue::Count(0))));
        roots.push(
            v.mounts
                .as_ref()
                .unwrap()
                .0
                .borrow()
                .mounts
                .last()
                .unwrap()
                .root
                .clone(),
        );
    }
    assert!(Arc::ptr_eq(&roots[0], &roots[2]));
    assert!(!Arc::ptr_eq(&roots[0], &roots[1]));
    receive(c, 2, 10); // The additional alias granted its own lookup reference.
    drop(roots);
    v.umount(b"/bound0", 0).unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/bound2", 0).unwrap();
    receive(c, 2, 10);
    v.umount(b"/bound1", 0).unwrap();
    receive(c, 2, 11);
}

#[test]
fn bound_file_open_samples_live_readonly_after_getattr_and_path_only_uses_the_inode() {
    let (mut v, dev) = mounted();
    v.import_file(b"/bound", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/file".to_vec()),
        target: b"/bound".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    answer(c, &receive(c, 1, 1), &linked_entry(10, 210, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/bound", 2, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    let request = receive(c, 3, 10);
    v.mount(None, b"/bound", None, 32 | 4096 | 1, None).unwrap();
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&linked_entry(10, 210, 0o100644)[40..]);
    answer(c, &request, &attr);
    assert!(matches!(finish(work), Err(Errno(30))));
    assert_eq!(c.read(8192), Err(Errno(11)));
    let fd = v.open_at(AT_FDCWD, b"/bound", O_PATH, 0).unwrap();
    assert_eq!(v.read(fd, 1), Err(Errno(9)));
    let target = v
        .shared_files()
        .lookup(fd)
        .unwrap()
        .unwrap()
        .filesystem_target();
    let stat = waiting(FileWork::new(&paths, target, FileCommand::Stat));
    answer(c, &receive(c, 3, 10), &attr);
    assert!(matches!(finish(stat), Ok(FileValue::FuseStat(_, m)) if m.is_root));
    v.close(fd).unwrap();
    v.umount(b"/bound", 0).unwrap();
    receive(c, 2, 10);
}

#[test]
fn a_bound_proc_file_fd_outlives_source_close_and_reuse_without_retaining_its_handle() {
    let (mut v, dev) = mounted();
    v.import_file(b"/bound", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_file(&v, c, 0);
    let first = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/file".to_vec()),
        target: b"/bound".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    answer(c, &receive(c, 1, 1), &linked_entry(10, 210, 0o100644));
    assert!(matches!(finish(first), Ok(FileValue::Count(0))));
    receive(c, 2, 10);
    v.umount(b"/bound", 0).unwrap();
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
    let mut work = paths.namespace_work(NamespaceCall::Mount {
        source: Some(format!("/proc/self/fd/{fd}").into_bytes()),
        target: b"/bound".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    });
    let mut complete = false;
    let mut joined = false;
    for _ in 0..8 {
        match work.run() {
            FileOutcome::Complete(reply) => {
                assert!(matches!(reply.result, Ok(FileValue::Count(0))));
                complete = true;
                break;
            }
            FileOutcome::Waiting(next) => {
                assert!(next.ready() && !next.waits_for_fuse());
                work = next;
            }
            FileOutcome::Owner(next) => {
                assert!(!joined);
                v.rename_at(AT_FDCWD, b"/bound", AT_FDCWD, b"/moved", 0)
                    .unwrap();
                v.import_file(b"/bound", b"replacement".to_vec()).unwrap();
                let FileOutcome::Waiting(next) = next.resume_owner(&mut v) else {
                    panic!("typed continuation must preserve the first operand")
                };
                work = next;
                joined = true;
            }
            FileOutcome::Layout(_) => panic!("a mount operand does not modify file layout"),
        }
    }
    assert!(complete && joined);
    assert!(!v.statx_at(AT_FDCWD, b"/bound", false).unwrap().1.is_root);
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.close(fd).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd
    );
    answer(c, &receive(c, 25, 10), &[]);
    answer(c, &receive(c, 18, 10), &[]);
    assert!(paths.statx_at(AT_FDCWD, b"/moved", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let request = receive(c, 3, 10);
    assert_eq!(
        &request[40..56],
        &[0; 16],
        "bind retains an inode, not the closed fh"
    );
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&linked_entry(10, 210, 0o100644)[40..]);
    answer(c, &request, &attr);
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(_, m)) if m.is_root));
    v.umount(b"/moved", 0).unwrap();
    receive(c, 2, 10);
}

#[test]
fn create_type_reuse_retires_the_bound_directory_and_keeps_the_new_handle() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/bound-dir", 0o755).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let bind = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/directory".to_vec()),
        target: b"/bound-dir".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    answer(c, &receive(c, 1, 1), &linked_entry(70, 170, 0o40755));
    assert!(matches!(finish(bind), Ok(FileValue::Count(0))));
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", O_CREAT | 2, 0o600, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    let missing = receive(c, 1, 1);
    c.write(&reply(id(&missing), -2, &[])).unwrap();
    let work = waiting(work);
    let create = receive(c, 35, 1);
    let mut payload = linked_entry(70, 170, 0o100600).to_vec();
    payload.extend_from_slice(&[0; 16]);
    answer(c, &create, &payload);
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    assert!(matches!(
        paths.statx_at(AT_FDCWD, b"/bound-dir", false),
        Some(Err(Errno(5)))
    ));
    v.shared_files()
        .close_range(fd as u32, fd as u32, 0, 1)
        .unwrap();
    answer(c, &receive(c, 25, 70), &[]);
    answer(c, &receive(c, 18, 70), &[]);
    receive(c, 2, 70);
    v.umount(b"/bound-dir", 0).unwrap();
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn a_type_changing_getattr_permanently_marks_the_original_bind_bad() {
    let (mut v, dev) = mounted();
    v.import_file(b"/bound", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let bind = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/file".to_vec()),
        target: b"/bound".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    answer(c, &receive(c, 1, 1), &linked_entry(10, 210, 0o100644));
    assert!(matches!(finish(bind), Ok(FileValue::Count(0))));
    assert!(paths.statx_at(AT_FDCWD, b"/bound", false).is_none());
    let bad = paths.take_fuse_stat().unwrap();
    let mut wrong = [0; 104];
    wrong[16..].copy_from_slice(&linked_entry(10, 210, 0o040755)[40..]);
    answer(c, &receive(c, 3, 10), &wrong);
    assert!(matches!(finish(bad), Err(Errno(5))));
    assert!(matches!(
        paths.statx_at(AT_FDCWD, b"/bound", false),
        Some(Err(Errno(5)))
    ));
    let files = FileEpoch::default().capture(&v, true);
    assert!(matches!(
        paths.open_at_resolve(AT_FDCWD, b"/bound", 0, 0, 0, &files),
        Some(Err(Errno(5)))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/bound", 0).unwrap();
    receive(c, 2, 10);
}
