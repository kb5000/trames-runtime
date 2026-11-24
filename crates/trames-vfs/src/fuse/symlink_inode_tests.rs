// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn link_entry() -> [u8; 128] {
    let mut bytes = entry(71, 171, 0o120777);
    bytes[104..108].copy_from_slice(&1u32.to_le_bytes());
    bytes
}
fn link_tree(paths: &PathQueries, c: &Connection, clone: bool) -> u32 {
    let work = waiting(
        paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Tree {
            fd: AT_FDCWD,
            path: b"/mnt/link".to_vec(),
            flags: 0x100 | u32::from(clone),
        })),
    );
    answer(c, &receive(c, 1, 1), &link_entry());
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    fd as u32
}
fn bind_link(v: &mut Vfs, paths: &PathQueries, c: &Connection, target: &[u8]) {
    let fd = link_tree(paths, c, true);
    assert!(matches!(
        finish(
            paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Move {
                from: fd as i32,
                source: Vec::new(),
                to: AT_FDCWD,
                target: target.to_vec(),
                flags: 4,
            }))
        ),
        Ok(FileValue::Count(0))
    ));
    v.close(fd).unwrap();
}

#[test]
fn nofollow_tree_retains_daemon_link_for_fstat_and_empty_path_readlink() {
    for clone in [false, true] {
        let (mut v, dev) = mounted();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let fd = link_tree(&paths, c, clone);
        assert_eq!(
            c.read(8192),
            Err(Errno(11)),
            "NOFOLLOW does not fetch link text"
        );
        assert!(paths.statx_fd(fd).is_none());
        let work = paths.take_fuse_stat().unwrap();
        let mut attrs = [0; 104];
        attrs[16..].copy_from_slice(&link_entry()[40..]);
        answer(c, &receive(c, 3, 71), &attrs);
        assert!(
            matches!(finish(work), Ok(FileValue::FuseStat(s, _)) if u32::from_le_bytes(s[16..20].try_into().unwrap()) == 0o120777)
        );
        assert!(paths.readlink_at(fd as i32, b"").is_none());
        let work = paths.take_fuse_stat().unwrap();
        let request = receive(c, 5, 71);
        v.close(fd).unwrap();
        assert_eq!(
            v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
                .unwrap(),
            fd
        );
        answer(c, &request, b"original-target");
        assert!(matches!(finish(work), Ok(FileValue::Bytes(s)) if s == b"original-target"));
        receive(c, 2, 71);
        assert_eq!(c.read(8192), Err(Errno(11)));
        v.close(fd).unwrap();
    }
}

#[test]
fn bound_daemon_link_follows_its_target_from_the_mountpoints_parent() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/other", 0o755).unwrap();
    v.import_file(b"/other/target", b"original".to_vec())
        .unwrap();
    v.import_file(b"/other/alias", Vec::new()).unwrap();
    let expected = v.stat_at(AT_FDCWD, b"/other/target").unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    bind_link(&mut v, &paths, c, b"/other/alias");
    assert!(paths.statx_at(AT_FDCWD, b"/other/alias", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 5, 71), b"target");
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(s, _)) if s[..16] == expected[..16]));
    v.umount(b"/other/alias", 8).unwrap();
    receive(c, 2, 71);
}

#[test]
fn path_only_nofollow_open_keeps_a_link_after_close_and_fd_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/link", O_PATH | O_NOFOLLOW, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &link_entry());
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    assert!(paths.readlink_at(fd as i32, b"").is_none());
    let work = paths.take_fuse_stat().unwrap();
    let request = receive(c, 5, 71);
    v.close(fd as u32).unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd as u32
    );
    answer(c, &request, b"old-link-target");
    assert!(matches!(finish(work), Ok(FileValue::Bytes(s)) if s == b"old-link-target"));
    receive(c, 2, 71);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "O_PATH acquired no fh to flush or release"
    );
    v.close(fd as u32).unwrap();
}

#[test]
fn bound_link_parent_mutation_retains_the_link_after_lazy_unmount_and_replacement() {
    let (mut v, dev) = mounted();
    for path in [
        b"/other".as_slice(),
        b"/other/target",
        b"/other/replacement",
    ] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    v.import_file(b"/other/alias", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    bind_link(&mut v, &paths, c, b"/other/alias");
    let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
        fd: AT_FDCWD,
        path: b"/other/alias/new".to_vec(),
        mode: 0o700,
    }));
    let request = receive(c, 5, 71);
    v.umount(b"/other/alias", 2 | 8).unwrap();
    v.unlink_at(AT_FDCWD, b"/other/alias", false).unwrap();
    v.symlink_at(b"replacement", AT_FDCWD, b"/other/alias")
        .unwrap();
    answer(c, &request, b"target");
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert!(v.stat_at(AT_FDCWD, b"/other/target/new").is_ok());
    assert_eq!(
        v.stat_at(AT_FDCWD, b"/other/replacement/new"),
        Err(Errno(2))
    );
    v.reap_detached_mounts();
    receive(c, 2, 71);
}

#[test]
fn bound_link_loop_and_no_symlinks_policy_do_not_replay_lookup() {
    let (mut v, dev) = mounted();
    v.import_file(b"/alias", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    bind_link(&mut v, &paths, c, b"/alias");
    let files = FileEpoch::default().capture(&v, true);
    assert!(matches!(
        paths.open_at_resolve(AT_FDCWD, b"/alias", 0, 0, 4, &files),
        Some(Err(Errno(40)))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert!(paths.statx_at(AT_FDCWD, b"/alias", false).is_none());
    let mut work = paths.take_fuse_stat().unwrap();
    for step in 0..40 {
        answer(c, &receive(c, 5, 71), b"/alias");
        if step == 39 {
            assert!(matches!(finish(work), Err(Errno(40))));
            break;
        }
        work = waiting(work);
    }
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/alias", 8).unwrap();
    receive(c, 2, 71);
}

#[test]
fn cancelling_readlink_releases_the_last_lookup_and_ignores_a_late_reply() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let fd = link_tree(&paths, c, false);
    assert!(paths.readlink_at(fd as i32, b"").is_none());
    let work = paths.take_fuse_stat().unwrap();
    let request = receive(c, 5, 71);
    v.close(fd).unwrap();
    drop(work);
    let interrupt = receive(c, 36, 0);
    assert_eq!(&interrupt[40..48], &request[8..16]);
    receive(c, 2, 71);
    answer(c, &request, b"late-target");
    assert_eq!(c.read(8192), Err(Errno(11)));
    assert!(matches!(
        paths.readlink_at(fd as i32, b""),
        Some(Err(Errno(9)))
    ));
}

#[test]
fn a_bound_relative_link_retains_its_original_parent_across_rename_and_replacement() {
    let (mut v, dev) = mounted();
    for p in [b"/parent".as_slice(), b"/parent/target"] {
        v.mkdir_at(AT_FDCWD, p, 0o755).unwrap();
    }
    v.import_file(b"/parent/alias", Vec::new()).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    bind_link(&mut v, &paths, c, b"/parent/alias");
    let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
        fd: AT_FDCWD,
        path: b"/parent/alias/new".to_vec(),
        mode: 0o700,
    }));
    let request = receive(c, 5, 71);
    v.rename_at(AT_FDCWD, b"/parent", AT_FDCWD, b"/moved", 0)
        .unwrap();
    for p in [b"/parent".as_slice(), b"/parent/target"] {
        v.mkdir_at(AT_FDCWD, p, 0o755).unwrap();
    }
    answer(c, &request, b"target");
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert!(v.stat_at(AT_FDCWD, b"/moved/target/new").is_ok());
    assert_eq!(v.stat_at(AT_FDCWD, b"/parent/target/new"), Err(Errno(2)));
    v.umount(b"/moved/alias", 8).unwrap();
    receive(c, 2, 71);
}
