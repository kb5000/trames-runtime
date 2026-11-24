// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn tree(path: &[u8], flags: u32) -> NamespaceCall {
    NamespaceCall::MountFd(MountFdCall::Tree {
        fd: AT_FDCWD,
        path: path.to_vec(),
        flags,
    })
}

#[test]
fn open_tree_resumes_a_fuse_directory_lookup_and_attaches_the_original_inode() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/target", 0o755).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(tree(b"/mnt/directory", 1 | O_CLOEXEC)));
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    assert!(v.fds.get(&(fd as u32)).unwrap().cloexec.get());
    assert!(matches!(
        finish(
            paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Move {
                from: fd as i32,
                source: Vec::new(),
                to: AT_FDCWD,
                target: b"/target".to_vec(),
                flags: 4,
            }))
        ),
        Ok(FileValue::Count(0))
    ));
    v.close(fd as u32).unwrap();
    assert_eq!(
        v.mounts
            .as_ref()
            .unwrap()
            .0
            .borrow()
            .mounts
            .last()
            .unwrap()
            .root
            .borrow()
            .inode,
        170
    );
    v.umount(b"/target", 0).unwrap();
    receive(c, 2, 70);
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn move_mount_retains_the_accepted_source_while_its_fuse_target_waits() {
    let (mut v, dev) = mounted();
    for path in [b"/source".as_slice(), b"/relocated", b"/other"] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    v.mount(None, b"/source", Some(b"tmpfs"), 0, None).unwrap();
    let source = v.mount_location(b"/source", true).unwrap().mount.unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(
        paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Move {
            from: AT_FDCWD,
            source: b"/source".to_vec(),
            to: AT_FDCWD,
            target: b"/mnt/target".to_vec(),
            flags: 0,
        })),
    );
    // The original admin transaction is not held across the daemon callback.
    v.mount(None, b"/other", Some(b"tmpfs"), 0, None).unwrap();
    v.umount(b"/other", 0).unwrap();
    v.mount(Some(b"/source"), b"/relocated", None, 8192, None)
        .unwrap();
    v.mount(None, b"/source", Some(b"tmpfs"), 0, None).unwrap();
    let replacement = v.mount_location(b"/source", true).unwrap().mount.unwrap();
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    let parent = source.parent.borrow();
    assert_eq!(parent.as_ref().unwrap().node.borrow().inode, 170);
    assert!(!Arc::ptr_eq(&source, &replacement));
    drop(parent);
    assert!(replacement.parent.borrow().is_some());
    v.umount(b"/mnt/target", 0).unwrap();
    receive(c, 2, 70);
    v.umount(b"/source", 0).unwrap();
}

#[test]
fn set_attr_through_a_fuse_link_changes_only_the_resolved_mount() {
    let (mut v, dev) = mounted();
    v.mkdir_at(AT_FDCWD, b"/target", 0o755).unwrap();
    v.mount(None, b"/target", Some(b"tmpfs"), 0, None).unwrap();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    for readonly in [true, false] {
        let work = waiting(
            paths.namespace_work(NamespaceCall::MountFd(MountFdCall::SetAttr {
                fd: AT_FDCWD,
                path: b"/mnt/link".to_vec(),
                flags: 0,
                attrs: MountAttributes::new(u64::from(readonly), u64::from(!readonly), 0).unwrap(),
            })),
        );
        answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
        let work = waiting(work);
        answer(c, &receive(c, 5, 71), b"/target");
        assert!(matches!(finish(work), Ok(FileValue::Count(0))));
        receive(c, 2, 71);
        assert_eq!(
            v.mount_location(b"/target", true)
                .unwrap()
                .mount
                .unwrap()
                .flags
                .get()
                & 1
                != 0,
            readonly
        );
        assert_eq!(
            v.mount_location(b"/mnt", true)
                .unwrap()
                .mount
                .unwrap()
                .flags
                .get()
                & 1,
            0
        );
    }
    v.umount(b"/target", 0).unwrap();
}

#[test]
fn mount_fd_empty_path_retains_the_original_daemon_file_and_tree_fd() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, original) = open_file(&v, c, 0);
    let FileValue::Count(tree_fd) = finish(paths.namespace_work(NamespaceCall::MountFd(
        MountFdCall::Tree {
            fd: original as i32,
            path: Vec::new(),
            flags: 1 | 0x1000,
        },
    )))
    .unwrap() else {
        panic!()
    };
    assert_eq!(
        c.read(8192),
        Err(Errno(11)),
        "cloning an accepted inode does not reopen its fh"
    );
    v.close(original).unwrap();
    answer(c, &receive(c, 25, 10), &[]);
    answer(c, &receive(c, 18, 10), &[]);
    assert_eq!(
        v.open_at(AT_FDCWD, b"/first-replacement", O_CREAT | 2, 0o600)
            .unwrap(),
        original
    );
    let work = waiting(
        paths.namespace_work(NamespaceCall::MountFd(MountFdCall::Move {
            from: tree_fd as i32,
            source: Vec::new(),
            to: AT_FDCWD,
            target: b"/mnt/target".to_vec(),
            flags: 4,
        })),
    );
    v.close(tree_fd as u32).unwrap();
    let replacement = v
        .open_at(AT_FDCWD, b"/second-replacement", O_CREAT | 2, 0o600)
        .unwrap();
    assert_eq!(replacement, tree_fd as u32);
    answer(c, &receive(c, 1, 1), &entry(20, 220, 0o100600));
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
    {
        let table = v.mounts.as_ref().unwrap().0.borrow();
        let bound = table.mounts.last().unwrap();
        assert_eq!(bound.root.borrow().inode, 210);
        assert_eq!(
            bound.parent.borrow().as_ref().unwrap().node.borrow().inode,
            220
        );
    }
    assert_eq!(c.read(8192), Err(Errno(11)));
    v.umount(b"/mnt/target", 0).unwrap();
    let mut forgotten = [c.read(8192).unwrap(), c.read(8192).unwrap()];
    assert!(forgotten.iter().all(|m| op(m) == 2));
    forgotten.sort_by_key(|m| u64::from_le_bytes(m[16..24].try_into().unwrap()));
    assert_eq!(
        u64::from_le_bytes(forgotten[0][16..24].try_into().unwrap()),
        10
    );
    assert_eq!(
        u64::from_le_bytes(forgotten[1][16..24].try_into().unwrap()),
        20
    );
    v.close(original).unwrap();
    v.close(replacement).unwrap();
}

#[test]
fn non_cloning_open_tree_needs_no_mount_capability_and_no_daemon_open() {
    let (mut v, dev) = mounted();
    v.credentials.caps.effective = 0;
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(tree(b"/mnt/directory", O_CLOEXEC)));
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    let FileValue::Count(fd) = finish(work).unwrap() else {
        panic!()
    };
    assert_eq!(c.read(8192), Err(Errno(11)));
    let d = v.fds.get(&(fd as u32)).unwrap();
    assert!(d.cloexec.get());
    assert_eq!(d.open.borrow().flags.get() & O_PATH, O_PATH);
    drop(d);
    v.close(fd as u32).unwrap();
    receive(c, 2, 70);
}

#[test]
fn modern_mount_validation_and_noop_attributes_do_not_send_daemon_requests() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    assert!(matches!(
        finish(paths.namespace_work(tree(b"/mnt/directory", 0x80))),
        Err(Errno(22))
    ));
    assert!(matches!(
        finish(
            paths.namespace_work(NamespaceCall::MountFd(MountFdCall::SetAttr {
                fd: -1,
                path: b"/mnt/missing".to_vec(),
                flags: 0,
                attrs: MountAttributes::new(0, 0, 0).unwrap(),
            }))
        ),
        Ok(FileValue::Count(0))
    ));
    v.credentials.caps.effective = 0;
    let unprivileged = v.path_queries();
    assert!(matches!(
        finish(unprivileged.namespace_work(tree(b"/mnt/directory", 1))),
        Err(Errno(1))
    ));
    assert_eq!(c.read(8192), Err(Errno(11)));
}

#[test]
fn cancelling_open_tree_releases_a_late_lookup_without_publishing_an_fd() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let count = v.fds.entries().len();
    let work = waiting(paths.namespace_work(tree(b"/mnt/directory", 1)));
    let request = receive(c, 1, 1);
    drop(work);
    answer(c, &request, &entry(70, 170, 0o40755));
    receive(c, 2, 70);
    assert_eq!(v.fds.entries().len(), count);
    assert_eq!(c.read(8192), Err(Errno(11)));
}
