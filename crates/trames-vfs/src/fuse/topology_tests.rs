// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn mount_call(target: &[u8]) -> NamespaceCall {
    NamespaceCall::Mount {
        source: None,
        target: target.to_vec(),
        kind: Some(b"tmpfs".to_vec()),
        flags: 0,
        data: None,
    }
}
fn follow(c: &Connection, work: FileWork, target: &[u8]) -> FileWork {
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), target);
    work
}

#[test]
fn mounting_through_a_fuse_symlink_uses_the_resolved_target() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/target", 0o755).unwrap();
    let before = v.statx_at(AT_FDCWD, b"/target", false).unwrap().1.id;
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(mount_call(b"/mnt/link")));
    let work = follow(c, work, b"/target");
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 71);
    assert_ne!(
        v.statx_at(AT_FDCWD, b"/target", false).unwrap().1.id,
        before
    );
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/target", 0).unwrap();
}

#[test]
fn identical_source_and_target_spellings_remain_separate_accepted_operands() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/directory".to_vec()),
        target: b"/mnt/directory".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    let work = waiting(work);
    // Equal bytes do not merge Linux's target and source lookups. The name
    // may select a different inode when the second operand is reached.
    answer(c, &receive(c, 1, 1), &entry(72, 172, 0o40755));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    let table = v.mounts.as_ref().unwrap().0.borrow();
    let mount = table.mounts.last().unwrap();
    assert_eq!(mount.root.borrow().inode, 172);
    assert_eq!(
        mount.parent.borrow().as_ref().unwrap().node.borrow().inode,
        170
    );
}

#[test]
fn topology_wait_releases_admin_and_retains_the_first_operand_for_bind_and_move() {
    for flags in [4096, 8192] {
        let (mut v, dev) = mounted();
        for path in [b"/source".as_slice(), b"/target", b"/other"] {
            v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        if flags == 8192 {
            v.mount(None, b"/source", Some(b"tmpfs"), 0, None).unwrap();
        }
        v.mkdir_at(AT_FDCWD, b"/source/inside", 0o755).unwrap();
        let expected = v.stat_at(AT_FDCWD, b"/source/inside").unwrap();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let work = waiting(paths.namespace_work(NamespaceCall::Mount {
            source: Some(b"/mnt/link".to_vec()),
            target: b"/target".to_vec(),
            kind: None,
            flags,
            data: None,
        }));
        // A daemon callback can perform a topology operation while LOOKUP waits.
        v.mount(None, b"/other", Some(b"tmpfs"), 0, None).unwrap();
        v.umount(b"/other", 0).unwrap();
        v.rename_at(AT_FDCWD, b"/target", AT_FDCWD, b"/moved", 0)
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/target", 0o755).unwrap();
        let work = follow(c, work, b"/source");
        assert!(matches!(finish(work), Ok(FileValue::Count(0))));
        receive(c, 2, 71);
        assert_eq!(
            &v.stat_at(AT_FDCWD, b"/moved/inside").unwrap()[..16],
            &expected[..16]
        );
        assert_eq!(v.stat_at(AT_FDCWD, b"/target/inside"), Err(Errno(2)));
        assert_eq!(c.read(8192), Err(Errno(11)));
        v.umount(b"/moved", 0).unwrap();
    }
}

#[test]
fn a_fuse_directory_can_be_covered_and_unmounted_without_its_own_lookup_becoming_busy() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(mount_call(b"/mnt/directory")));
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert!(
        v.statx_at(AT_FDCWD, b"/mnt/directory", false)
            .unwrap()
            .1
            .is_root
    );
    assert!(matches!(
        finish(paths.namespace_work(NamespaceCall::Umount {
            target: b"/mnt/directory".to_vec(),
            flags: 0
        })),
        Ok(FileValue::Count(0))
    ));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn umount_nofollow_rejects_a_fuse_symlink_without_readlink() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Umount {
        target: b"/mnt/link".to_vec(),
        flags: 8,
    }));
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    assert!(matches!(finish(work), Err(Errno(22))));
    receive(c, 2, 71);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn mount_capability_denial_precedes_any_fuse_request() {
    let (mut v, dev) = mounted();
    v.credentials.caps.effective = 0;
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(matches!(
        finish(paths.namespace_work(mount_call(b"/mnt/link"))),
        Err(Errno(1))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn a_cancelled_mount_forgets_a_late_lookup_without_publishing_topology() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let before = v.mounts.as_ref().unwrap().0.borrow().mounts.len();
    let work = waiting(paths.namespace_work(mount_call(b"/mnt/directory")));
    let request = receive(c, 1, 1);
    drop(work);
    answer(c, &request, &entry(70, 170, 0o40755));
    receive(c, 2, 70);
    assert_eq!(v.mounts.as_ref().unwrap().0.borrow().mounts.len(), before);
    v.umount(b"/mnt", 0).unwrap();
}

#[test]
fn bind_through_a_fuse_link_can_still_select_an_ordinary_file() {
    let (mut v, dev) = mounted();
    v.import_file(b"/source", b"original".to_vec()).unwrap();
    v.import_file(b"/target", b"replacement".to_vec()).unwrap();
    let expected = v.stat_at(AT_FDCWD, b"/source").unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mount {
        source: Some(b"/mnt/link".to_vec()),
        target: b"/target".to_vec(),
        kind: None,
        flags: 4096,
        data: None,
    }));
    assert!(matches!(
        finish(follow(c, work, b"/source")),
        Ok(FileValue::Count(0))
    ));
    receive(c, 2, 71);
    assert_eq!(
        &v.stat_at(AT_FDCWD, b"/target").unwrap()[..16],
        &expected[..16]
    );
    v.umount(b"/target", 0).unwrap();
}

#[test]
fn pivot_root_resumes_the_new_root_operand_through_a_fuse_symlink() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/new", 0o755).unwrap();
    v.mount(None, b"/new", Some(b"tmpfs"), 0, None).unwrap();
    v.mkdir_at(AT_FDCWD, b"/new/old", 0o755).unwrap();
    v.mkdir_at(AT_FDCWD, b"/old-marker", 0o755).unwrap();
    let old_marker = v.stat_at(AT_FDCWD, b"/old-marker").unwrap();
    let expected = v.stat_at(AT_FDCWD, b"/new").unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::PivotRoot {
        new_root: b"/mnt/link".to_vec(),
        put_old: b"/new/old".to_vec(),
    }));
    assert!(matches!(
        finish(follow(c, work, b"/new")),
        Ok(FileValue::Count(0))
    ));
    receive(c, 2, 71);
    v.chdir(b"/").unwrap();
    assert_eq!(&v.stat_at(AT_FDCWD, b"/").unwrap()[..16], &expected[..16]);
    assert_eq!(
        &v.stat_at(AT_FDCWD, b"/old/old-marker").unwrap()[..16],
        &old_marker[..16]
    );
    assert_eq!(c.read(8192), Err(Errno(11)));
}
