// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn source_entry(node: u64, mode: u32, links: u32) -> [u8; 128] {
    let mut bytes = entry(node, 230, mode);
    bytes[104..108].copy_from_slice(&links.to_le_bytes());
    bytes
}
fn link_call(old: &[u8], new: &[u8]) -> NamespaceCall {
    NamespaceCall::Link {
        follow: false,
        empty_path: false,
        oldfd: AT_FDCWD,
        old: old.to_vec(),
        newfd: AT_FDCWD,
        new: new.to_vec(),
    }
}
fn destination(c: &Connection, work: FileWork) -> FileWork {
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&source_entry(1, 0o40755, 2)[40..]);
    answer(c, &receive(c, 3, 1), &attr);
    let work = waiting(work);
    let lookup = receive(c, 1, 1);
    assert_eq!(&lookup[40..], b"alias\0");
    c.write(&reply(id(&lookup), -2, &[])).unwrap();
    waiting(work)
}
#[test]
fn hardlink_uses_the_original_source_node_and_balances_both_lookup_grants() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/mnt/alias")));
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    let work = waiting(work);
    let work = destination(c, work);
    let request = receive(c, 13, 1);
    assert_eq!(&request[40..48], &70u64.to_le_bytes());
    assert_eq!(&request[48..], b"alias\0");
    answer(c, &request, &source_entry(70, 0o100644, 2));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn link_existing_destination_and_cross_mount_errors_do_not_send_link() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/mnt/alias")));
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    let work = waiting(work);
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&source_entry(1, 0o40755, 2)[40..]);
    answer(c, &receive(c, 3, 1), &attr);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &source_entry(80, 0o100644, 1));
    assert!(matches!(finish(work), Err(Errno(17))));
    receive(c, 2, 80);
    receive(c, 2, 70);
    let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/ordinary")));
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    assert!(matches!(finish(work), Err(Errno(18))));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn cancelling_link_forgets_the_original_and_late_success_grant_once_each() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/mnt/alias")));
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    let work = waiting(work);
    let work = destination(c, work);
    let request = receive(c, 13, 1);
    drop(work);
    let interrupt = receive(c, 36, 0);
    assert_eq!(&interrupt[40..48], &request[8..16]);
    receive(c, 2, 70);
    answer(c, &request, &source_entry(70, 0o100644, 2));
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn alternate_nodeid_link_reply_matches_linux_and_releases_both_grants() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/mnt/alias")));
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    let work = waiting(work);
    let work = destination(c, work);
    answer(c, &receive(c, 13, 1), &source_entry(71, 0o100644, 2));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 71);
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn nofollow_link_uses_the_symlink_inode_without_readlink() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/mnt/alias")));
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o120777, 1));
    let work = waiting(work);
    let work = destination(c, work);
    let request = receive(c, 13, 1);
    assert_eq!(&request[40..48], &70u64.to_le_bytes());
    answer(c, &request, &source_entry(70, 0o120777, 2));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
}

#[test]
fn empty_path_link_keeps_the_original_path_only_fd_after_close_and_reuse() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", O_PATH, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let mut call = link_call(b"", b"/mnt/alias");
    if let NamespaceCall::Link {
        oldfd, empty_path, ..
    } = &mut call
    {
        *oldfd = fd as i32;
        *empty_path = true;
    }
    let work = waiting(paths.namespace_work(call));
    v.shared_files()
        .close_range(fd as u32, fd as u32, 0, 1)
        .unwrap();
    assert_eq!(
        v.open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        fd as u32
    );
    let work = destination(c, work);
    let request = receive(c, 13, 1);
    assert_eq!(&request[40..48], &70u64.to_le_bytes());
    answer(c, &request, &source_entry(70, 0o100644, 2));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
}

#[test]
fn link_enosys_becomes_eperm_and_disables_future_link_callbacks() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    v.open_at(AT_FDCWD, b"/ordinary", O_CREAT | 2, 0o600)
        .unwrap();
    let paths = v.path_queries();
    for first in [true, false] {
        let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/mnt/alias")));
        answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
        let work = waiting(work);
        let mut attr = [0; 104];
        attr[16..].copy_from_slice(&source_entry(1, 0o40755, 2)[40..]);
        answer(c, &receive(c, 3, 1), &attr);
        let work = waiting(work);
        let lookup = receive(c, 1, 1);
        c.write(&reply(id(&lookup), -2, &[])).unwrap();
        let work = if first {
            let work = waiting(work);
            let request = receive(c, 13, 1);
            c.write(&reply(id(&request), -38, &[])).unwrap();
            work
        } else {
            work
        };
        assert!(matches!(finish(work), Err(Errno(1))));
        receive(c, 2, 70);
        assert_eq!(c.read(8192), Err(Errno(11)));
    }
    // Cached daemon capability errors do not replace the VFS mount check.
    let work = waiting(paths.namespace_work(link_call(b"/ordinary", b"/mnt/alias")));
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&source_entry(1, 0o40755, 2)[40..]);
    answer(c, &receive(c, 3, 1), &attr);
    let work = waiting(work);
    c.write(&reply(id(&receive(c, 1, 1)), -2, &[])).unwrap();
    match finish(work) {
        Err(error) => assert_eq!(error, Errno(18)),
        Ok(_) => panic!("cross-mount link succeeded"),
    }
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn empty_path_cannot_resurrect_the_last_unlinked_fuse_inode() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", O_PATH, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    let work = waiting(paths.namespace_work(NamespaceCall::Unlink {
        fd: AT_FDCWD,
        path: b"/mnt/file".to_vec(),
        directory: false,
    }));
    let mut attr = [0; 104];
    attr[16..].copy_from_slice(&source_entry(1, 0o40755, 2)[40..]);
    answer(c, &receive(c, 3, 1), &attr);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100644, 1));
    let work = waiting(work);
    answer(c, &receive(c, 10, 1), &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    let mut call = link_call(b"", b"/mnt/alias");
    if let NamespaceCall::Link {
        oldfd, empty_path, ..
    } = &mut call
    {
        *oldfd = fd as i32;
        *empty_path = true;
    }
    let work = waiting(paths.namespace_work(call));
    answer(c, &receive(c, 3, 1), &attr);
    let work = waiting(work);
    let lookup = receive(c, 1, 1);
    c.write(&reply(id(&lookup), -2, &[])).unwrap();
    assert!(matches!(finish(work), Err(Errno(2))));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn empty_path_cannot_resurrect_a_last_unlinked_ordinary_source() {
    let mut v = Vfs::default();
    v.import_file(b"/source", b"payload".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/source", O_PATH, 0).unwrap();
    v.unlink_at(AT_FDCWD, b"/source", false).unwrap();
    let mut call = link_call(b"", b"/alias");
    if let NamespaceCall::Link {
        oldfd, empty_path, ..
    } = &mut call
    {
        *oldfd = fd as i32;
        *empty_path = true;
    }
    assert!(matches!(
        finish(v.path_queries().namespace_work(call)),
        Err(Errno(2))
    ));
}

fn mounted_allow_other() -> (Vfs, Arc<Device>) {
    let mut v = Vfs::default();
    v.set_runtime_info(1, RuntimeInfo::default());
    v.mkdir_at(AT_FDCWD, b"/mnt", 0o755).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/dev/fuse", 2, 0).unwrap();
    let device = v.fuse_device(fd).unwrap().unwrap();
    let options = format!("fd={fd},rootmode=40755,user_id=0,group_id=0,allow_other");
    v.mount(None, b"/mnt", Some(b"fuse"), 0, Some(options.as_bytes()))
        .unwrap();
    let c = device.connection().unwrap();
    let init = c.read(8192).unwrap();
    let mut info = [0; 64];
    info[..4].copy_from_slice(&7u32.to_le_bytes());
    info[4..8].copy_from_slice(&31u32.to_le_bytes());
    answer(c, &init, &info);
    v.credentials = Credentials::user(1000, 1000);
    (v, device)
}

#[test]
fn protected_hardlinks_uses_fuse_permission_semantics_and_rejects_unsafe_modes() {
    for mode in [0o100600, 0o104600, 0o102610, 0o120777] {
        let (v, dev) = mounted_allow_other();
        let c = dev.connection().unwrap();
        let paths = v.path_queries();
        let work = waiting(paths.namespace_work(link_call(b"/mnt/file", b"/mnt/alias")));
        let mut entry = source_entry(70, mode, 1);
        entry[108..112].copy_from_slice(&2000u32.to_le_bytes());
        answer(c, &receive(c, 1, 1), &entry);
        let work = waiting(work);
        let mut attr = [0; 104];
        attr[16..].copy_from_slice(&source_entry(1, 0o40755, 2)[40..]);
        answer(c, &receive(c, 3, 1), &attr);
        let work = waiting(work);
        let lookup = receive(c, 1, 1);
        c.write(&reply(id(&lookup), -2, &[])).unwrap();
        if mode == 0o100600 {
            let work = waiting(work);
            let request = receive(c, 13, 1);
            assert_eq!(&request[24..28], &1000u32.to_le_bytes());
            answer(c, &request, &source_entry(70, mode, 2));
            assert!(matches!(finish(work), Ok(FileValue::Count(0))));
        } else {
            assert!(matches!(finish(work), Err(Errno(1))));
        }
    }
}

#[test]
fn a_changed_opener_identity_requires_capability_for_empty_path_fuse_link() {
    let (mut v, dev) = mounted_allow_other();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b"/mnt/file", O_PATH, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    answer(c, &receive(c, 1, 1), &source_entry(70, 0o100600, 1));
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    v.credentials = Credentials::user(1000, 1000);
    let mut call = link_call(b"", b"/mnt/alias");
    if let NamespaceCall::Link {
        oldfd, empty_path, ..
    } = &mut call
    {
        *oldfd = fd as i32;
        *empty_path = true;
    }
    assert!(matches!(
        finish(v.path_queries().namespace_work(call)),
        Err(Errno(2))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
}
