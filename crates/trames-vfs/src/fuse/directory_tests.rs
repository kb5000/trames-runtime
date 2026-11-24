// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn retained_directory_cursor_commits_only_complete_entries_and_cancel_keeps_the_last_cookie() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let work = readdir(&paths, fd, 96);
    let request = receive(c, 28, 70);
    let mut bytes = dirent(40, 19, b"first", 8);
    bytes.extend(dirent(41, 71, b"second", 8));
    answer(c, &request, &bytes);
    let mut reply = directory_reply(work);
    let first = reply.next_entry().unwrap().unwrap();
    assert_eq!(
        reply.next_entry().unwrap(),
        Some(first.clone()),
        "a page wait cannot advance the directory"
    );
    assert_eq!(reply.copied(), 0);
    let seek = waiting(
        paths
            .fuse_file_work(
                fd,
                FileCommand::Seek {
                    offset: 0,
                    whence: 1,
                },
            )
            .unwrap()
            .unwrap(),
    );
    assert!(
        !seek.ready(),
        "the accepted output still owns the original OFD transaction"
    );
    reply.commit_entry();
    assert_eq!(reply.copied(), first.len());
    let second = reply.next_entry().unwrap().unwrap();
    assert_eq!(&second[8..16], &71u64.to_le_bytes());
    drop(reply);
    assert!(seek.ready());
    assert!(matches!(finish(seek), Ok(FileValue::Count(19))));
}

fn attr(c: &Connection, node: u64) {
    let mut bytes = [0; 104];
    bytes[16..].copy_from_slice(&entry(node, 230, 0o40755)[40..]);
    answer(c, &receive(c, 3, node), &bytes);
}

#[test]
fn directory_identity_supports_fchdir_dot_parent_and_original_relative_lookup() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let work = waiting(paths.namespace_work(NamespaceCall::Fchdir(fd)));
    attr(c, 70);
    let work = waiting(work);
    let access = receive(c, 34, 70);
    assert_eq!(&access[40..44], &1u32.to_le_bytes());
    answer(c, &access, &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_eq!(v.cwd().unwrap(), b"/mnt/directory");

    // A relative lookup keeps the accepted inode even if the descriptor slot
    // is closed/reused and another thread changes the shared cwd while waiting.
    assert!(paths.statx_at(fd as i32, b"leaf", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    let request = receive(c, 1, 70);
    assert_eq!(&request[40..], b"leaf\0");
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    let replacement = v
        .open_at(AT_FDCWD, b"/replacement", O_CREAT | 2, 0o600)
        .unwrap();
    assert_eq!(replacement, fd);
    v.chdir(b"/").unwrap();
    // The file handle closes; the accepted path operation still owns nlookup.
    receive(c, 29, 70);
    answer(c, &request, &entry(80, 280, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
    let mut forgotten = [0; 2];
    for node in &mut forgotten {
        let request = c.read(8192).unwrap();
        assert_eq!(op(&request), 2);
        *node = u64::from_le_bytes(request[16..24].try_into().unwrap());
    }
    forgotten.sort_unstable();
    assert_eq!(forgotten, [70, 80]);

    let (paths, fd) = open_directory(&v, c, false);
    assert!(paths.statx_at(fd as i32, b".", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    attr(c, 70);
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
    assert!(paths.statx_at(fd as i32, b"..", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    attr(c, 1);
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
}

#[test]
fn opening_dot_from_fuse_cwd_uses_original_directory_and_balances_lookup() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let work = waiting(paths.namespace_work(NamespaceCall::Fchdir(fd)));
    attr(c, 70);
    let work = waiting(work);
    let access = receive(c, 34, 70);
    assert_eq!(&access[40..44], &1u32.to_le_bytes());
    answer(c, &access, &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    receive(c, 29, 70);
    assert_eq!(c.read(8192), Err(Errno(11)), "cwd still owns lookup");

    let files = FileEpoch::default().capture(&v, true);
    assert!(paths
        .open_at_resolve(AT_FDCWD, b".", O_DIRECTORY, 0, 0, &files)
        .is_none());
    let work = paths.take_open_work().unwrap();
    attr(c, 70);
    let work = waiting(work);
    let request = receive(c, 27, 70);
    let mut handle = [0; 16];
    handle[..8].copy_from_slice(&852u64.to_le_bytes());
    answer(c, &request, &handle);
    let FileValue::Count(new_fd) = finish(work).unwrap() else {
        panic!()
    };
    v.chdir(b"/").unwrap();
    assert_eq!(c.read(8192), Err(Errno(11)), "new OFD still owns lookup");
    v.shared_files()
        .close_range(new_fd as u32, new_fd as u32, 0, 1)
        .unwrap();
    receive(c, 29, 70);
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)), "one LOOKUP, one final FORGET");
}

#[test]
fn fresh_directory_lookup_keeps_identity_without_caching_the_path_result() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (_, a) = open_directory(&v, c, false);
    let (_, b) = open_directory(&v, c, false);
    let node = |fd| {
        v.shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .open
            .node
            .clone()
            .unwrap()
    };
    let first = node(a);
    let second = node(b);
    assert!(Arc::ptr_eq(&first, &second));
    let weak = Arc::downgrade(&first);
    drop(first);
    drop(second);
    v.shared_files().close_range(a, a, 0, 1).unwrap();
    receive(c, 29, 70);
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "second OFD retains the first inode lease"
    );
    v.shared_files().close_range(b, b, 0, 1).unwrap();
    receive(c, 29, 70);
    receive(c, 2, 70);
    receive(c, 2, 70);
    assert!(weak.upgrade().is_none());
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn chdir_waits_for_daemon_search_permission_and_does_not_change_cwd_on_error() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let original = v.cwd().unwrap();
    for error in [-13, 0] {
        let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"/mnt/directory".to_vec())));
        answer(c, &receive(c, 1, 1), &entry(70, 230, 0o40755));
        let work = waiting(work);
        let access = receive(c, 34, 70);
        assert_eq!(
            v.cwd().unwrap(),
            original,
            "pending chdir has not published cwd"
        );
        c.write(&reply(id(&access), error, &[])).unwrap();
        if error != 0 {
            assert!(matches!(finish(work), Err(Errno(13))));
            assert_eq!(v.cwd().unwrap(), original);
            receive(c, 2, 70);
        } else {
            assert!(matches!(finish(work), Ok(FileValue::Count(0))));
            assert_eq!(v.cwd().unwrap(), b"/mnt/directory");
            assert_eq!(
                c.read(8192),
                Err(Errno(11)),
                "cwd retains looked-up directory"
            );
        }
    }
}

#[test]
fn renamed_cwd_keeps_directory_identity_and_removed_cwd_can_climb_to_parent() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let work = waiting(paths.namespace_work(NamespaceCall::Fchdir(fd)));
    attr(c, 70);
    let work = waiting(work);
    answer(c, &receive(c, 34, 70), &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));

    let work = waiting(paths.namespace_work(NamespaceCall::Rename {
        oldfd: AT_FDCWD,
        old: b"/mnt/directory".to_vec(),
        newfd: AT_FDCWD,
        new: b"/mnt/moved".to_vec(),
        flags: 0,
    }));
    attr(c, 1);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o40755));
    let work = waiting(work);
    attr(c, 1);
    let work = waiting(work);
    let missing = receive(c, 1, 1);
    c.write(&reply(id(&missing), -2, &[])).unwrap();
    let work = waiting(work);
    let rename = receive(c, 12, 1);
    assert_eq!(v.cwd().unwrap(), b"/mnt/directory");
    answer(c, &rename, &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    assert_eq!(v.cwd().unwrap(), b"/mnt/moved");

    let work = waiting(paths.namespace_work(NamespaceCall::Unlink {
        fd: AT_FDCWD,
        path: b"/mnt/moved".to_vec(),
        directory: true,
    }));
    attr(c, 1);
    let work = waiting(work);
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o40755));
    let work = waiting(work);
    answer(c, &receive(c, 11, 1), &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    receive(c, 2, 70);
    assert_eq!(v.cwd(), Err(Errno(2)));

    let work = waiting(paths.namespace_work(NamespaceCall::Chdir(b"..".to_vec())));
    attr(c, 1);
    let work = waiting(work);
    answer(c, &receive(c, 34, 1), &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_eq!(v.cwd().unwrap(), b"/mnt");
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    receive(c, 29, 70);
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn cold_cwd_projection_does_not_keep_unmounted_daemon_alive() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let work = waiting(paths.namespace_work(NamespaceCall::Fchdir(fd)));
    attr(c, 70);
    let work = waiting(work);
    answer(c, &receive(c, 34, 70), &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    let cold = v.path_queries();
    assert_eq!(cold.view.borrow().cwd().unwrap(), b"/mnt/directory");
    v.chdir(b"/").unwrap();
    v.shared_files().close_range(fd, fd, 0, 1).unwrap();
    receive(c, 29, 70);
    receive(c, 2, 70);
    v.umount(b"/mnt", 0).unwrap();
    assert_eq!(
        c.read(8192),
        Err(Errno(19)),
        "unmount wakes daemon despite a cold observer"
    );
    drop(cold);
}

#[test]
fn chroot_waits_for_access_and_keeps_original_root_inode_and_cwd() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let original_cwd = v.context.paths.borrow().cwd_node.clone().unwrap();
    let work = waiting(paths.namespace_work(NamespaceCall::Chroot(b"/mnt/jail".to_vec())));
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o40755));
    let work = waiting(work);
    let access = receive(c, 34, 70);
    assert_ne!(v.root_location().unwrap().key, b"/jail");
    v.mount(Some(b"tmpfs"), b"/mnt", Some(b"tmpfs"), 0, None)
        .unwrap();
    answer(c, &access, &[]);
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    let state = v.context.paths.borrow();
    assert!(Arc::ptr_eq(state.cwd_node.as_ref().unwrap(), &original_cwd));
    assert_eq!(
        state
            .root_node
            .as_ref()
            .unwrap()
            .fuse_directory
            .get()
            .unwrap()
            .id(),
        70
    );
    drop(state);
    let paths = v.path_queries();
    assert!(paths.statx_at(AT_FDCWD, b"/inside", false).is_none());
    let work = paths.take_fuse_stat().unwrap();
    answer(c, &receive(c, 1, 70), &entry(80, 280, 0o100644));
    assert!(matches!(finish(work), Ok(FileValue::FuseStat(..))));
}

#[test]
fn chroot_capability_type_access_denial_and_cancellation_never_publish_root() {
    let (mut denied, dev) = mounted();
    denied.credentials = Credentials::user(1000, 1000);
    assert!(matches!(
        finish(
            denied
                .path_queries()
                .namespace_work(NamespaceCall::Chroot(b"/mnt/no-lookup".to_vec()))
        ),
        Err(Errno(1))
    ));
    assert_eq!(dev.connection().unwrap().read(8192), Err(Errno(11)));
    for error in [20, 13, 4] {
        let (v, dev) = mounted();
        let c = dev.connection().unwrap();
        let before = v.root_location().unwrap();
        let paths = v.path_queries();
        let work = waiting(paths.namespace_work(NamespaceCall::Chroot(b"/mnt/jail".to_vec())));
        answer(
            c,
            &receive(c, 1, 1),
            &entry(70, 230, if error == 20 { 0o100644 } else { 0o40755 }),
        );
        if error == 20 {
            assert!(matches!(finish(work), Err(Errno(20))));
        } else {
            let work = waiting(work);
            let access = receive(c, 34, 70);
            if error == 4 {
                drop(work);
                let interrupt = receive(c, 36, 0);
                assert_eq!(&interrupt[40..48], &access[8..16]);
                answer(c, &access, &[]);
            } else {
                c.write(&reply(id(&access), -13, &[])).unwrap();
                assert!(matches!(finish(work), Err(Errno(13))));
            }
        }
        assert_eq!(v.root_location().unwrap(), before);
        receive(c, 2, 70);
    }
}

#[test]
fn chroot_enosys_publishes_only_the_original_shared_fs_context() {
    let (mut v, dev) = mounted();
    let peer = v.clone_with_resources(true, true);
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Chroot(b"/mnt/jail".to_vec())));
    answer(c, &receive(c, 1, 1), &entry(70, 230, 0o40755));
    let work = waiting(work);
    let access = receive(c, 34, 70);
    v.unshare_context();
    c.write(&reply(id(&access), -38, &[])).unwrap();
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    assert_ne!(v.root_location().unwrap(), peer.root_location().unwrap());
    assert_eq!(
        peer.context
            .paths
            .borrow()
            .root_node
            .as_ref()
            .unwrap()
            .fuse_directory
            .get()
            .unwrap()
            .id(),
        70
    );
    assert_eq!(v.cwd().unwrap(), b"/");
}
