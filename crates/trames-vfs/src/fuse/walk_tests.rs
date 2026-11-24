// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn next(c: &Connection, opcode: u32, node: u64, forgotten: &mut Vec<u64>) -> Vec<u8> {
    loop {
        let request = c.read(8192).unwrap();
        let target = u64::from_le_bytes(request[16..24].try_into().unwrap());
        if op(&request) == 2 {
            forgotten.push(target);
            continue;
        }
        assert_eq!((op(&request), target), (opcode, node));
        return request;
    }
}
fn balanced(c: &Connection, mut forgotten: Vec<u64>, expected: &[u64]) {
    while let Ok(request) = c.read(8192) {
        assert_eq!(op(&request), 2);
        forgotten.push(u64::from_le_bytes(request[16..24].try_into().unwrap()));
    }
    forgotten.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(forgotten, expected);
}

#[test]
fn followed_relative_link_resumes_the_vfs_walk_through_dotdot() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let mut forgotten = Vec::new();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/dir/link", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &next(c, 1, 1, &mut forgotten), &entry(70, 170, 0o40755));
    let work = waiting(work);
    answer(
        c,
        &next(c, 1, 70, &mut forgotten),
        &entry(71, 171, 0o120777),
    );
    let work = waiting(work);
    answer(c, &next(c, 5, 71, &mut forgotten), b"../data");
    let work = waiting(work);
    let lookup = next(c, 1, 1, &mut forgotten);
    assert_eq!(&lookup[40..], b"data\0");
    answer(c, &lookup, &entry(10, 210, 0o100644));
    let FileValue::FuseStat(stat, _) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(u64::from_le_bytes(stat[8..16].try_into().unwrap()), 210);
    balanced(c, forgotten, &[70, 71, 10]);
}

#[test]
fn a_link_wait_keeps_the_original_directory_after_fd_reuse_and_cwd_change() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let mut forgotten = Vec::new();
    assert!(paths.statx_at(fd as i32, b"link/leaf", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(
        c,
        &next(c, 1, 70, &mut forgotten),
        &entry(71, 171, 0o120777),
    );
    let work = waiting(work);
    let link = next(c, 5, 71, &mut forgotten);
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd
    );
    next(c, 29, 70, &mut forgotten);
    v.mkdir_at(AT_FDCWD, b"/elsewhere", 0o755).unwrap();
    v.chdir(b"/elsewhere").unwrap();
    answer(c, &link, b"target");
    let work = waiting(work);
    let target = next(c, 1, 70, &mut forgotten);
    assert_eq!(&target[40..], b"target\0");
    answer(c, &target, &entry(72, 172, 0o40755));
    let work = waiting(work);
    let leaf = next(c, 1, 72, &mut forgotten);
    assert_eq!(&leaf[40..], b"leaf\0");
    answer(c, &leaf, &entry(73, 173, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
    balanced(c, forgotten, &[70, 71, 72, 73]);
}

#[test]
fn followed_link_can_open_an_ordinary_file_with_the_original_reserved_slot() {
    for truncate in [false, true] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        v.import_file(b"/outside", b"ordinary".to_vec()).unwrap();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        let flags = if truncate { 2 | O_TRUNC } else { 0 };
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/link", flags, 0, 0, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        let other = v
            .open_at(AT_FDCWD, b"/occupied", O_CREAT | 2, 0o600)
            .unwrap();
        answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
        let work = waiting(work);
        answer(c, &receive(c, 5, 71), b"/outside");
        let value = match work.run() {
            FileOutcome::Complete(reply) => reply.result,
            FileOutcome::Layout(work) => finish(work.exclusive()),
            _ => panic!("ordinary target has no remaining daemon request"),
        };
        let FileValue::Count(fd) = value.unwrap() else {
            panic!()
        };
        assert!((fd as u32) < other, "pending open kept its reservation");
        assert_eq!(
            v.read(fd as u32, 32).unwrap(),
            if truncate {
                b"".as_slice()
            } else {
                b"ordinary".as_slice()
            }
        );
        balanced(c, Vec::new(), &[71]);
    }
}

#[test]
fn link_loop_is_bounded_and_every_lookup_is_forgotten() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let mut forgotten = Vec::new();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/loop", false).is_none());
    let mut work = paths.take_fuse_stat().unwrap();
    for index in 0..41 {
        answer(c, &next(c, 1, 1, &mut forgotten), &entry(71, 171, 0o120777));
        if index == 40 {
            assert!(matches!(finish(work), Err(Errno(40))));
            balanced(c, forgotten, &[71; 41]);
            return;
        }
        work = waiting(work);
        answer(c, &next(c, 5, 71, &mut forgotten), b"loop");
        work = waiting(work);
    }
    unreachable!()
}

#[test]
fn access_uses_live_mount_flags_after_the_lookup_wait() {
    for (initial, changed, mask, denied) in [(0, 8, 1, 13), (0, 1, 2, 30)] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        v.mount(None, b"/mnt", None, 32 | 4096 | initial, None)
            .unwrap();
        let paths = v.path_queries();
        assert!(paths
            .access_at(AT_FDCWD, b"/mnt/file", mask, false, false)
            .is_none());
        let work = paths.take_fuse_stat().unwrap();
        let lookup = receive(c, 1, 1);
        v.mount(None, b"/mnt", None, 32 | 4096 | changed, None)
            .unwrap();
        answer(c, &lookup, &entry(80, 180, 0o100777));
        let work = if mask == 2 {
            let work = waiting(work);
            answer(c, &receive(c, 34, 80), &[]);
            work
        } else {
            work
        };
        assert!(matches!(finish(work), Err(Errno(error)) if error == denied));
        balanced(c, Vec::new(), &[80]);
    }
}

#[test]
fn no_symlinks_rejects_before_readlink_and_nofollow_can_open_the_link_itself() {
    for (flags, policy, error) in [
        (0, 4, Some(40)),
        (O_NOFOLLOW, 0, Some(40)),
        (O_PATH | O_NOFOLLOW, 0, None),
    ] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let files = FileEpoch::default().capture(&v, true);
        assert!(paths
            .open_at_resolve(AT_FDCWD, b"/mnt/link", flags, 0, policy, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
        let result = finish(work);
        if let Some(error) = error {
            assert!(matches!(result, Err(Errno(actual)) if actual == error));
        } else {
            let FileValue::Count(fd) = result.unwrap() else {
                panic!()
            };
            v.shared_files()
                .close_range(fd as u32, fd as u32, 0, 1)
                .unwrap();
        }
        balanced(c, Vec::new(), &[71]);
    }
}

#[test]
fn a_link_crosses_fuse_connections_and_interrupts_only_the_current_request() {
    let (mut v, dev) = mounted();
    let first = dev.connection().unwrap();
    v.mkdir_at(AT_FDCWD, b"/other", 0o755).unwrap();
    let device_fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
    let other = v.fuse_device(device_fd).unwrap().unwrap();
    let options = format!("fd={device_fd},rootmode=40755,user_id=0,group_id=0");
    v.mount(None, b"/other", Some(b"fuse"), 0, Some(options.as_bytes()))
        .unwrap();
    let second = other.connection().unwrap();
    let init = receive(second, 26, 0);
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    answer(second, &init, &version);
    let paths = v.path_queries();
    let mut forgotten = Vec::new();
    assert!(paths.statx_at(AT_FDCWD, b"/mnt/link/leaf", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(first, &receive(first, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(first, &receive(first, 5, 71), b"/other/target");
    let work = waiting(work);
    let target = receive(second, 1, 1);
    balanced(first, Vec::new(), &[71]);
    assert_eq!(
        v.umount(b"/other", 0),
        Err(Errno(16)),
        "current pathname use pins the second mount"
    );
    v.umount(b"/mnt", 0).unwrap();
    work.fuse_signal_request().unwrap().interrupt();
    let interrupt = next(second, 36, 0, &mut forgotten);
    assert_eq!(&interrupt[40..], &id(&target).to_le_bytes());
    assert_eq!(
        first.read(8192),
        Err(Errno(19)),
        "completed source mount can abort independently"
    );
    drop(work);
    answer(second, &target, &entry(72, 172, 0o40755));
    balanced(second, forgotten, &[72]);
    v.umount(b"/other", 0).unwrap();
}

#[test]
fn scoped_link_resolution_keeps_the_original_directory_boundary() {
    for (policy, target, error) in [
        (8, b"../outside".as_slice(), Some(18)),
        (16, b"/target".as_slice(), None),
    ] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let (paths, directory) = open_directory(&v, c, false);
        let files = FileEpoch::default().capture(&v, true);
        let mut forgotten = Vec::new();
        assert!(paths
            .open_at_resolve(directory as i32, b"link", O_PATH, 0, policy, &files)
            .is_none());
        let work = paths.take_open_work().unwrap();
        answer(c, &receive(c, 1, 70), &entry(71, 171, 0o120777));
        let work = waiting(work);
        answer(c, &receive(c, 5, 71), target);
        if let Some(error) = error {
            assert!(matches!(finish(work), Err(Errno(actual)) if actual == error));
            balanced(c, forgotten, &[71]);
        } else {
            let work = waiting(work);
            let target = next(c, 1, 70, &mut forgotten);
            assert_eq!(&target[40..], b"target\0");
            answer(c, &target, &entry(73, 173, 0o100644));
            let FileValue::Count(fd) = finish(work).unwrap() else {
                panic!()
            };
            v.shared_files()
                .close_range(fd as u32, fd as u32, 0, 1)
                .unwrap();
            balanced(c, forgotten, &[71, 73]);
        }
    }
}

#[test]
fn access_keeps_real_ids_when_a_daemon_link_returns_to_an_ordinary_inode() {
    let (mut v, _dev) = mounted();
    v.import_file(b"/private", b"root-owned".to_vec()).unwrap();
    v.node(b"/private").unwrap().borrow_mut().mode = 0o100600;
    v.mkdir_at(AT_FDCWD, b"/world", 0o755).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
    let dev = v.fuse_device(fd).unwrap().unwrap();
    let options = format!("fd={fd},rootmode=40755,user_id=0,group_id=0,allow_other");
    v.mount(None, b"/world", Some(b"fuse"), 0, Some(options.as_bytes()))
        .unwrap();
    let c = dev.connection().unwrap();
    let init = receive(c, 26, 0);
    let mut version = [0; 64];
    version[..4].copy_from_slice(&7u32.to_le_bytes());
    version[4..8].copy_from_slice(&31u32.to_le_bytes());
    answer(c, &init, &version);
    v.credentials.uid = 1000;
    let paths = v.path_queries();
    for effective in [false, true] {
        assert!(paths
            .access_at(AT_FDCWD, b"/world/link", 4, effective, false)
            .is_none());
        let work = paths.take_fuse_stat().unwrap();
        let lookup = receive(c, 1, 1);
        assert_eq!(
            u32::from_le_bytes(lookup[24..28].try_into().unwrap()),
            if effective { 0 } else { 1000 }
        );
        answer(c, &lookup, &entry(71, 171, 0o120777));
        let work = waiting(work);
        answer(c, &receive(c, 5, 71), b"/private");
        let result = finish(work);
        if effective {
            assert!(matches!(result, Ok(FileValue::Count(0))));
        } else {
            assert!(matches!(result, Err(Errno(13))));
        }
        assert_eq!(
            paths.view.borrow().credentials.fsuid,
            0,
            "accepted authority does not replace the reusable control view"
        );
        balanced(c, Vec::new(), &[71]);
    }
}

#[test]
fn bind_root_uses_its_retained_fuse_directory_and_dotdot_leaves_the_mount() {
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
    let mut forgotten = Vec::new();
    assert!(paths.statx_at(AT_FDCWD, b"/alias", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let request = receive(c, 3, 70);
    let mut attributes = [0; 104];
    attributes[16..].copy_from_slice(&entry(70, 170, 0o40755)[40..]);
    answer(c, &request, &attributes);
    let FileValue::FuseStat(_, mount) = finish(work).unwrap() else {
        panic!()
    };
    assert!(mount.is_root);
    assert!(paths.statx_at(AT_FDCWD, b"/alias/file", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let lookup = next(c, 1, 70, &mut forgotten);
    assert_eq!(&lookup[40..], b"file\0");
    answer(c, &lookup, &entry(73, 173, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
    balanced(c, forgotten, &[73]);
    assert!(matches!(
        paths.statx_at(AT_FDCWD, b"/alias/../outside", false),
        Some(Ok(..))
    ));
    v.umount(b"/alias", 0).unwrap();
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    receive(c, 29, 70);
    balanced(c, Vec::new(), &[70]);
}
