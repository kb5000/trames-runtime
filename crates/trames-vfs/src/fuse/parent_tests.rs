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
fn balanced(c: &Connection, mut forgotten: Vec<u64>, expected: &[u64], release: bool) {
    let mut released = 0;
    while let Ok(request) = c.read(8192) {
        if op(&request) == 29 {
            released += 1;
        } else {
            assert_eq!(op(&request), 2);
            forgotten.push(u64::from_le_bytes(request[16..24].try_into().unwrap()));
        }
    }
    forgotten.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(forgotten, expected);
    assert_eq!(released, usize::from(release));
}
fn complete(work: FileWork) {
    assert!(matches!(finish(work), Ok(FileValue::Count(0))));
}

#[test]
fn a_parent_link_can_leave_a_readonly_fuse_mount_before_mutation_admission() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    v.mkdir_at(AT_FDCWD, b"/outside", 0o755).unwrap();
    v.mount(None, b"/mnt", None, 32 | 4096 | 1, None).unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
        fd: AT_FDCWD,
        path: b"/mnt/link/new".to_vec(),
        mode: 0o755,
    }));
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), b"/outside");
    complete(work);
    assert!(v.is_directory(b"/outside/new"));
    balanced(c, Vec::new(), &[71], false);
}

#[test]
fn mkdir_parent_keeps_original_fd_and_relative_link_base_across_waits() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    let (paths, fd) = open_directory(&v, c, false);
    let mut forgotten = Vec::new();
    let work = waiting(paths.namespace_work(NamespaceCall::Mkdir {
        fd: fd as i32,
        path: b"link/new".to_vec(),
        mode: 0o755,
    }));
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
    v.mkdir_at(AT_FDCWD, b"/elsewhere", 0o755).unwrap();
    v.chdir(b"/elsewhere").unwrap();
    answer(c, &link, b"target");
    let work = waiting(work);
    let target = next(c, 1, 70, &mut forgotten);
    assert_eq!(&target[40..], b"target\0");
    answer(c, &target, &entry(72, 172, 0o40755));
    let work = waiting(work);
    let missing = next(c, 1, 72, &mut forgotten);
    assert_eq!(&missing[40..], b"new\0");
    c.write(&reply(id(&missing), -2, &[])).unwrap();
    let work = waiting(work);
    let mkdir = next(c, 9, 72, &mut forgotten);
    answer(c, &mkdir, &entry(73, 173, 0o40755));
    complete(work);
    balanced(c, forgotten, &[70, 71, 72, 73], true);
}

#[test]
fn ordinary_rename_parent_is_retained_while_the_other_parent_waits_on_a_daemon() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    for path in [b"/source".as_slice(), b"/dest"] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    v.import_file(b"/source/old", b"original".to_vec()).unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Rename {
        oldfd: AT_FDCWD,
        old: b"/source/old".to_vec(),
        newfd: AT_FDCWD,
        new: b"/mnt/link/new".to_vec(),
        flags: 0,
    }));
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    let link = receive(c, 5, 71);
    v.rename_at(AT_FDCWD, b"/source", AT_FDCWD, b"/moved", 0)
        .unwrap();
    v.mkdir_at(AT_FDCWD, b"/source", 0o755).unwrap();
    v.import_file(b"/source/old", b"replacement".to_vec())
        .unwrap();
    answer(c, &link, b"/dest");
    complete(work);
    assert!(matches!(v.node(b"/moved/old"), Err(Errno(2))));
    for (path, bytes) in [
        (b"/dest/new".as_slice(), b"original".as_slice()),
        (b"/source/old", b"replacement"),
    ] {
        let fd = v.open_at(AT_FDCWD, path, 0, 0).unwrap();
        assert_eq!(v.read(fd, 32).unwrap(), bytes);
    }
    balanced(c, Vec::new(), &[71], false);
}

#[test]
fn rename_classifies_mounts_after_following_the_source_parent_link() {
    let (mut v, dev) = mounted();
    let c = dev.connection().unwrap();
    v.mkdir_at(AT_FDCWD, b"/outside", 0o755).unwrap();
    v.import_file(b"/outside/old", b"original".to_vec())
        .unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Rename {
        oldfd: AT_FDCWD,
        old: b"/mnt/link/old".to_vec(),
        newfd: AT_FDCWD,
        new: b"/outside/new".to_vec(),
        flags: 0,
    }));
    answer(c, &receive(c, 1, 1), &entry(71, 171, 0o120777));
    let work = waiting(work);
    answer(c, &receive(c, 5, 71), b"/outside");
    complete(work);
    assert!(v.node(b"/outside/new").is_ok());
    assert!(matches!(v.node(b"/outside/old"), Err(Errno(2))));
    balanced(c, Vec::new(), &[71], false);
}

#[test]
fn destination_parent_lookup_failure_precedes_cross_mount_rename_rejection() {
    let (v, dev) = mounted();
    let c = dev.connection().unwrap();
    let paths = v.path_queries();
    let work = waiting(paths.namespace_work(NamespaceCall::Rename {
        oldfd: AT_FDCWD,
        old: b"/mnt/parent/old".to_vec(),
        newfd: AT_FDCWD,
        new: b"/missing/new".to_vec(),
        flags: 0,
    }));
    answer(c, &receive(c, 1, 1), &entry(70, 170, 0o40755));
    assert!(matches!(finish(work), Err(Errno(2))));
    balanced(c, Vec::new(), &[70], false);
}
