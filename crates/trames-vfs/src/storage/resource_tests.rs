// SPDX-License-Identifier: GPL-3.0-or-later
//! Native metadata admission retains original targets and published phases.
use super::*;

struct Store(PathBuf);
impl Store {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "trames-metadata-origin-{}-{}",
            std::process::id(),
            trames_memory::new_backing_identity(),
        )))
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn write(v: &mut Vfs, path: &[u8], bytes: &[u8]) {
    let fd = v.open_at(AT_FDCWD, path, 2, 0).unwrap();
    assert_eq!(v.write(fd, bytes).unwrap(), bytes.len());
    v.close(fd).unwrap();
}
fn stat(v: &mut Vfs, group: &str, field: &str) -> u64 {
    let path = format!("/sys/fs/cgroup/{group}/io.stat");
    let fd = v.open_at(AT_FDCWD, path.as_bytes(), 0, 0).unwrap();
    let bytes = v.pread(fd, 4096, 0).unwrap();
    v.close(fd).unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .split_whitespace()
        .find_map(|part| part.strip_prefix(field).map(|value| value.parse().unwrap()))
        .unwrap_or(0)
}
fn fixture(store: &Store) -> (Vfs, u32, NodeRef) {
    let mut v = Vfs::open_disk(&store.0, Default::default()).unwrap();
    v.set_runtime_info(1, Default::default());
    v.import_file(b"/file", b"original".to_vec()).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/file", 2, 0).unwrap();
    let node = v
        .descriptor(fd)
        .unwrap()
        .open
        .borrow()
        .node
        .clone()
        .unwrap();
    write(&mut v, b"/sys/fs/cgroup/cgroup.subtree_control", b"+io");
    for path in [b"/sys/fs/cgroup/a".as_slice(), b"/sys/fs/cgroup/b"] {
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
    }
    write(&mut v, b"/sys/fs/cgroup/a/cgroup.procs", b"1");
    (v, fd, node)
}
fn xattr(fd: u32, name: &[u8], value: Vec<u8>, flags: u32) -> NamespaceCall {
    NamespaceCall::Xattr {
        fd: fd as i32,
        path: None,
        follow: true,
        name: name.to_vec(),
        value: Some(value),
        flags,
    }
}
fn waiting(work: FileWork) -> FileWork {
    let FileOutcome::Waiting(work) = work.run() else {
        panic!("metadata resource wait")
    };
    assert!(!work.ready());
    work
}
fn finish(work: FileWork) -> Result<u64> {
    let FileOutcome::Complete(reply) = work.run() else {
        panic!("original metadata completion")
    };
    match reply.result? {
        FileValue::Count(count) => Ok(count),
        _ => panic!("metadata result"),
    }
}
fn caps(bit: u32) -> Vec<u8> {
    let mut record = vec![0; 20];
    record[..4].copy_from_slice(&0x0200_0001u32.to_le_bytes());
    record[4..8].copy_from_slice(&(1u32 << bit).to_le_bytes());
    record
}

#[test]
fn an_xattr_manifest_wait_rolls_back_until_the_original_inode_can_commit() {
    for cancel in [false, true] {
        let store = Store::new();
        let (mut v, fd, node) = fixture(&store);
        let original_time = node.borrow().times;
        let original_manifest = crate::storage::test_image(&store.0);
        write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wbps=1");
        let task = v.cgroup_task(1).unwrap();
        let scope = task.resource_scope();
        let work =
            waiting(
                v.path_queries()
                    .namespace_work(xattr(fd, b"user.test", b"value".to_vec(), 1)),
            );
        assert!(!node.borrow().xattrs.contains_key(b"user.test".as_slice()));
        assert_eq!(node.borrow().times, original_time);
        assert_eq!(crate::storage::test_image(&store.0), original_manifest);
        assert!(!store.0.join("manifest.new").exists());
        assert_eq!(stat(&mut v, "a", "wios="), 0);
        drop(scope);
        // Both metadata and namespace locks are free during the budget wait.
        v.rename_at(AT_FDCWD, b"/file", AT_FDCWD, b"/original", 0)
            .unwrap();
        v.close(fd).unwrap();
        let reused = v.open_at(AT_FDCWD, b"/file", 0x42, 0o600).unwrap();
        assert_eq!(reused, fd);
        write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
        let _other = task.resource_scope();
        if cancel {
            drop(work);
            assert!(!node.borrow().xattrs.contains_key(b"user.test".as_slice()));
            assert_eq!(stat(&mut v, "a", "wios="), 0);
        } else {
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wbps=max");
            assert!(work.ready());
            assert_eq!(finish(work), Ok(0));
            assert_eq!(
                node.borrow().xattrs.get(b"user.test".as_slice()),
                Some(&b"value".to_vec())
            );
            assert_eq!(
                v.get_xattr(fd as i32, None, true, b"user.test"),
                Err(Errno(61))
            );
            assert_eq!(stat(&mut v, "a", "wios="), 1);
            assert_eq!(
                stat(&mut v, "a", "wbytes="),
                crate::storage::test_record_bytes(&store.0)
            );
        }
        assert_eq!(stat(&mut v, "b", "wios="), 0);
    }
}

#[test]
fn a_manifest_open_failure_refunds_unissued_credit_and_preserves_the_existing_temporary_file() {
    let store = Store::new();
    let (mut v, fd, node) = fixture(&store);
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    crate::storage::block_publication(&store.0).unwrap();
    let task = v.cgroup_task(1).unwrap();
    let _scope = task.resource_scope();
    assert_eq!(
        finish(
            v.path_queries()
                .namespace_work(xattr(fd, b"user.test", b"first".to_vec(), 1))
        ),
        Err(Errno(22))
    );
    assert!(!node.borrow().xattrs.contains_key(b"user.test".as_slice()));
    assert!(store.0.join("manifest.wal").is_dir());
    assert_eq!(stat(&mut v, "a", "wios="), 0);
    crate::storage::unblock_publication(&store.0).unwrap();
    // No timer advance or quota reset: the first request issued no write.
    assert_eq!(
        finish(
            v.path_queries()
                .namespace_work(xattr(fd, b"user.test", b"second".to_vec(), 1))
        ),
        Ok(0)
    );
    assert_eq!(stat(&mut v, "a", "wios="), 1);
}

#[test]
fn capability_creation_keeps_its_published_sidecar_while_the_manifest_waits() {
    for cancel in [false, true] {
        let store = Store::new();
        let expected = caps(capabilities::SETUID);
        {
            let (mut v, fd, node) = fixture(&store);
            let notify = v.inotify_init(O_NONBLOCK).unwrap();
            v.inotify_add(notify, b"/file", inotify::ATTRIB).unwrap();
            write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
            let task = v.cgroup_task(1).unwrap();
            let scope = task.resource_scope();
            let work = waiting(v.path_queries().namespace_work(xattr(
                fd,
                file_caps::NAME,
                expected.clone(),
                1,
            )));
            let time = node.borrow().times[2];
            let inode = node.borrow().inode;
            let sidecar = store.0.join("objects").join(format!("{inode:016x}.cap"));
            let original_sidecar = std::fs::read(&sidecar).unwrap();
            assert_eq!(
                v.get_xattr(fd as i32, None, true, file_caps::NAME).unwrap(),
                expected
            );
            assert_eq!(stat(&mut v, "a", "wios="), 1);
            assert_eq!(stat(&mut v, "a", "wbytes="), original_sidecar.len() as u64);
            assert_eq!(v.read(notify, 4096), Err(Errno(11)));
            assert!(!store.0.join("manifest.new").exists());
            assert!(!sidecar.with_extension("new").exists());
            drop(scope);
            write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
            let _other = task.resource_scope();
            if cancel {
                drop(work);
                // Cancellation after a real namespace publication preserves
                // that effect; it does not perform destructor-side disk IO.
                assert_eq!(v.read(notify, 4096), Err(Errno(11)));
            } else {
                write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
                assert_eq!(finish(work), Ok(0));
                assert_eq!(node.borrow().times[2], time);
                assert_eq!(stat(&mut v, "a", "wios="), 2);
                let event = v.read(notify, 4096).unwrap();
                assert_eq!(event.len(), 16);
                assert_eq!(v.read(notify, 4096), Err(Errno(11)));
            }
            assert_eq!(std::fs::read(&sidecar).unwrap(), original_sidecar);
            assert_eq!(stat(&mut v, "b", "wios="), 0);
            let mut n = node.borrow_mut();
            let Content::File(data) = &mut n.content else {
                panic!("original file")
            };
            assert!(data.begin_transaction().unwrap().is_ok());
        }
        let reopened = Vfs::open_disk(&store.0, Default::default()).unwrap();
        assert_eq!(
            reopened
                .get_xattr(AT_FDCWD, Some(b"/file"), true, file_caps::NAME)
                .unwrap(),
            expected
        );
    }
}

#[test]
fn cancelling_before_sidecar_admission_changes_no_capability_or_timestamp() {
    let store = Store::new();
    let (mut v, fd, node) = fixture(&store);
    let time = node.borrow().times;
    let inode = node.borrow().inode;
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wbps=1");
    let task = v.cgroup_task(1).unwrap();
    let _scope = task.resource_scope();
    let work = waiting(v.path_queries().namespace_work(xattr(
        fd,
        file_caps::NAME,
        caps(capabilities::SETUID),
        1,
    )));
    assert_eq!(node.borrow().file_caps(), None);
    let sidecar = store.0.join("objects").join(format!("{inode:016x}.cap"));
    assert!(!sidecar.exists());
    assert!(!sidecar.with_extension("new").exists());
    assert!(!store.0.join("manifest.new").exists());
    drop(work);
    assert_eq!(node.borrow().times, time);
    assert_eq!(stat(&mut v, "a", "wios="), 0);
    let mut n = node.borrow_mut();
    let Content::File(data) = &mut n.content else {
        panic!("original file")
    };
    assert!(data.begin_transaction().unwrap().is_ok());
}

#[test]
fn a_capability_rollback_wait_retains_the_original_error_and_does_not_republish_the_new_grant() {
    let store = Store::new();
    let (mut v, fd, node) = fixture(&store);
    let old = caps(capabilities::SETGID);
    v.set_xattr(fd as i32, None, true, file_caps::NAME, Some(&old), 0)
        .unwrap();
    let old_time = node.borrow().times[2];
    let inode = node.borrow().inode;
    let sidecar = store.0.join("objects").join(format!("{inode:016x}.cap"));
    let old_sidecar = std::fs::read(&sidecar).unwrap();
    crate::storage::force_checkpoint_for_test(&v, &store.0);
    let manifest = store.0.join("manifest");
    let saved = store.0.join("manifest.saved");
    // A real native rename error occurs after the replacement manifest was
    // written and synchronized. It consumes IO and leaves rollback to resume.
    std::fs::rename(&manifest, &saved).unwrap();
    std::fs::create_dir(&manifest).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let task = v.cgroup_task(1).unwrap();
    let scope = task.resource_scope();
    let work = waiting(v.path_queries().namespace_work(xattr(
        fd,
        file_caps::NAME,
        caps(capabilities::SETUID),
        2,
    )));
    assert_eq!(stat(&mut v, "a", "wios="), 1);
    drop(scope);
    write(&mut v, b"/sys/fs/cgroup/b/cgroup.procs", b"1");
    let _other = task.resource_scope();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    let work = waiting(work);
    assert_eq!(stat(&mut v, "a", "wios="), 2);
    assert!(!store.0.join("manifest.new").exists());
    assert_ne!(std::fs::read(&sidecar).unwrap(), old_sidecar);
    std::fs::remove_dir(&manifest).unwrap();
    std::fs::rename(saved, &manifest).unwrap();
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=max");
    write(&mut v, b"/sys/fs/cgroup/a/io.max", b"253:1 wiops=1");
    assert_eq!(finish(work), Err(Errno(5)));
    assert_eq!(
        v.get_xattr(fd as i32, None, true, file_caps::NAME).unwrap(),
        old
    );
    assert_eq!(node.borrow().times[2], old_time);
    assert_eq!(std::fs::read(&sidecar).unwrap(), old_sidecar);
    assert_eq!(stat(&mut v, "a", "wios="), 3);
    assert_eq!(stat(&mut v, "b", "wios="), 0);
}
