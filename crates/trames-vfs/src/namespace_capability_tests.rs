// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained metadata uses its accepted inode across contention and name/FD reuse.
use super::*;

fn record(bit: u32) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[..4].copy_from_slice(&0x0200_0001u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&(1u32 << bit).to_le_bytes());
    bytes
}
fn fixture() -> (Vfs, u32, NodeRef, trames_shared::FileTransactionLease) {
    let mut v = Vfs::default();
    v.mkdir_at(AT_FDCWD, b"/caps", 0o755).unwrap();
    v.mount(None, b"/caps", Some(b"tmpfs"), 0, None).unwrap();
    let fd = v.open_at(AT_FDCWD, b"/caps/file", 0x42, 0o700).unwrap();
    v.write(fd, b"original").unwrap();
    let node = v
        .descriptor(fd)
        .unwrap()
        .open
        .borrow()
        .node
        .clone()
        .unwrap();
    let lease = {
        let mut n = node.borrow_mut();
        let Content::File(data) = &mut n.content else {
            panic!("file")
        };
        data.begin_transaction().unwrap().unwrap().unwrap()
    };
    (v, fd, node, lease)
}
fn command(fd: u32, path: bool, flags: u32) -> NamespaceCall {
    NamespaceCall::Xattr {
        fd: if path { AT_FDCWD } else { fd as i32 },
        path: path.then(|| b"/caps/file".to_vec()),
        follow: true,
        name: file_caps::NAME.to_vec(),
        value: Some(record(capabilities::SETUID)),
        flags,
    }
}
fn waiting(work: FileWork) -> FileWork {
    let FileOutcome::Waiting(work) = work.run() else {
        panic!("original metadata should wait")
    };
    assert!(work.waiting());
    assert!(!work.ready());
    assert!(!work.interruptible_wait());
    work
}
fn complete(work: FileWork) -> Result<u64> {
    let FileOutcome::Complete(reply) = work.run() else {
        panic!("ready original metadata")
    };
    match reply.result? {
        FileValue::Count(count) => Ok(count),
        _ => panic!("metadata count"),
    }
}

#[test]
fn capability_admission_retains_the_original_inode_across_fd_reuse_and_path_replacement() {
    struct Wake;
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    for path in [false, true] {
        let (mut v, fd, node, lease) = fixture();
        let old_times = node.borrow().times;
        let notify = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(notify, b"/caps/file", inotify::ATTRIB)
            .unwrap();
        let work = waiting(v.path_queries().namespace_work(command(fd, path, 1)));
        let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
        let signal = IoSignal::new(7, Arc::downgrade(&target));
        let sources = work.wait_sources(&signal).unwrap();
        assert!(!sources.subscriptions.is_empty());
        assert!(sources.native.is_empty());
        assert!(sources.deadline.is_none());
        assert_eq!(node.borrow().file_caps(), None);
        assert_eq!(node.borrow().times, old_times);
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        // Neither the filesystem namespace mutex nor inode metadata mutex is
        // retained over the resource wait. Concurrent rename/creation works.
        v.rename_at(AT_FDCWD, b"/caps/file", AT_FDCWD, b"/caps/moved", 0)
            .unwrap();
        v.close(fd).unwrap();
        let replacement = v.open_at(AT_FDCWD, b"/caps/file", 0x42, 0o600).unwrap();
        assert_eq!(replacement, fd);
        assert!(v.get_xattr(fd as i32, None, true, file_caps::NAME).is_err());
        assert!(!signal.ready());
        drop(lease);
        assert!(signal.ready());
        assert!(work.ready());
        assert_eq!(complete(work), Ok(0));
        assert_eq!(
            v.get_xattr(AT_FDCWD, Some(b"/caps/moved"), true, file_caps::NAME)
                .unwrap(),
            record(capabilities::SETUID)
        );
        assert_eq!(
            v.get_xattr(fd as i32, None, true, file_caps::NAME),
            Err(Errno(61))
        );
        let event = v.read(notify, 4096).unwrap();
        assert_eq!(event.len(), 16, "one completed attribute update");
        assert_eq!(
            u32::from_le_bytes(event[4..8].try_into().unwrap()),
            inotify::ATTRIB
        );
        assert_eq!(v.read(notify, 4096), Err(Errno(11)));
        drop(sources);
    }
}

#[test]
fn cancelling_a_capability_wait_publishes_no_attribute_or_timestamp() {
    let (mut v, fd, node, lease) = fixture();
    let old_times = node.borrow().times;
    let notify = v.inotify_init(O_NONBLOCK).unwrap();
    v.inotify_add(notify, b"/caps/file", inotify::ATTRIB)
        .unwrap();
    let work = waiting(v.path_queries().namespace_work(command(fd, false, 1)));
    drop(work);
    assert_eq!(node.borrow().file_caps(), None);
    assert_eq!(node.borrow().times, old_times);
    assert_eq!(v.read(notify, 4096), Err(Errno(11)));
    drop(lease);
    v.pwrite(fd, b"after", 0).unwrap();
    assert_eq!(v.pread(fd, 8, 0).unwrap(), b"afternal");
    let mut n = node.borrow_mut();
    let Content::File(data) = &mut n.content else {
        panic!("file")
    };
    assert!(data.begin_transaction().unwrap().is_ok());
}

#[test]
fn exclusive_capability_creation_rechecks_the_original_inode_at_transaction_admission() {
    let (mut v, fd, node, lease) = fixture();
    let work = waiting(v.path_queries().namespace_work(command(fd, false, 1)));
    let winning = record(capabilities::SETGID);
    {
        let _owner = lease.enter();
        v.set_xattr(fd as i32, None, true, file_caps::NAME, Some(&winning), 0)
            .unwrap();
    }
    let times = node.borrow().times;
    drop(lease);
    assert_eq!(complete(work), Err(Errno(17)));
    assert_eq!(node.borrow().times, times);
    assert_eq!(
        v.get_xattr(fd as i32, None, true, file_caps::NAME).unwrap(),
        winning
    );
}

#[test]
fn ownership_revocation_wait_preserves_its_accepted_path_without_poisoning_later_calls() {
    for cancel in [false, true] {
        let (mut v, fd, node, lease) = fixture();
        {
            let _owner = lease.enter();
            v.set_xattr(
                fd as i32,
                None,
                true,
                file_caps::NAME,
                Some(&record(capabilities::SETUID)),
                0,
            )
            .unwrap();
        }
        let paths = v.path_queries();
        let NamespaceAttempt::Retained(work) = paths.namespace_attempt(NamespaceCall::Chown {
            fd: AT_FDCWD,
            path: Some(b"/caps/file".to_vec()),
            uid: 1000,
            gid: u32::MAX,
            nofollow: false,
            empty: false,
        }) else {
            panic!("ownership must retain its original resource wait")
        };
        assert!(work.waiting());
        assert!(!work.ready());
        assert_eq!(node.borrow().uid, 0);
        assert!(node.borrow().file_caps().is_some());
        v.rename_at(AT_FDCWD, b"/caps/file", AT_FDCWD, b"/caps/moved", 0)
            .unwrap();
        let new_fd = v.open_at(AT_FDCWD, b"/caps/file", 0x42, 0o600).unwrap();
        if cancel {
            drop(work);
        } else {
            drop(lease);
            assert!(work.ready());
            assert_eq!(complete(work), Ok(0));
            assert_eq!(node.borrow().uid, 1000);
            assert!(node.borrow().file_caps().is_none());
        }
        // Reuse the original PathQueries after a suspended inline attempt.
        // Its next call must resolve the new file instead of retaining a stale
        // metadata slot from the completed or cancelled ownership change.
        assert_eq!(
            complete(paths.namespace_work(NamespaceCall::Chmod {
                fd: AT_FDCWD,
                path: Some(b"/caps/file".to_vec()),
                mode: 0o640,
                nofollow: false,
                empty: false,
            })),
            Ok(0)
        );
        let replacement = v.stat_fd(new_fd).unwrap();
        assert_eq!(
            u32::from_le_bytes(replacement[24..28].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(replacement[16..20].try_into().unwrap()) & 0o7777,
            0o640
        );
        if cancel {
            assert_eq!(node.borrow().uid, 0);
            assert_eq!(node.borrow().file_metadata().mode & 0o7777, 0o700);
            assert!(node.borrow().file_caps().is_some());
        }
    }
}
