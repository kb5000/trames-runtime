// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
fn finish(work: FileWork) -> Result<u32> {
    match work.run() {
        FileOutcome::Complete(reply) => reply.result.map(|value| match value {
            FileValue::Count(fd) => fd as u32,
            _ => panic!("memfd count"),
        }),
        _ => panic!("memfd retains native work, not an owner or mapping checkpoint"),
    }
}
#[test]
fn native_memfd_creation_reserves_original_inode_and_fd_without_holding_fs_lock() {
    for panic in [false, true] {
        let mut v = Vfs::default();
        let fs = v.fs.clone();
        let files = v.shared_files();
        let factory = v.descriptor_factory();
        let nodes = v.capacity().nodes_used;
        let first = v.available(0).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            v.memfd_publish_with(b"failed", 2, |_| {
                assert!(
                    fs.shared.try_borrow().is_some(),
                    "host backing must run outside the original filesystem lock"
                );
                assert_eq!(Vfs::filesystem_capacity(&fs.borrow()).nodes_used, nodes + 1);
                assert_eq!(files.observation_descriptor(first).err(), Some(Errno(9)));
                let next = factory.eventfd(0, 0).unwrap();
                assert_ne!(next, first);
                assert_eq!(files.close(next, 0), Some(Ok(())));
                if panic {
                    panic!("native allocation unwind");
                }
                Err(std::io::Error::from_raw_os_error(13))
            })
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), Err(Errno(13)));
        }
        assert_eq!(v.capacity().nodes_used, nodes);
        assert_eq!(v.memfd_create(b"after", 2), Ok(first));
    }
}
#[test]
fn concurrent_original_memfd_workers_obey_live_inode_and_fd_limits() {
    for inode_limit in [false, true] {
        let mut v = Vfs::default();
        let original = v.capacity();
        let first = v.available(0).unwrap();
        if inode_limit {
            let mut limits = v.fs.borrow().limits;
            limits.nodes = original.nodes_used + 3;
            v.set_storage_limits(limits).unwrap();
        } else {
            v.set_descriptor_limit(first + 3);
        }
        let works: Vec<_> = (0..12)
            .map(|_| {
                v.path_queries().namespace_work(NamespaceCall::Memfd(
                    MemfdParameters::new(b"parallel".to_vec(), 2).unwrap(),
                ))
            })
            .collect();
        let gate = std::sync::Arc::new(std::sync::Barrier::new(works.len()));
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            for work in works {
                let (gate, send) = (gate.clone(), send.clone());
                scope.spawn(move || {
                    gate.wait();
                    send.send(finish(work)).unwrap();
                });
            }
        });
        let results: Vec<_> = (0..12).map(|_| receive.recv().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
        assert!(results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| e.0 == if inode_limit { 28 } else { 24 }));
        for fd in results.into_iter().filter_map(Result::ok) {
            v.close(fd).unwrap();
        }
        assert_eq!(v.capacity().nodes_used, original.nodes_used);
    }
}
#[test]
fn retained_memfd_uses_original_files_credentials_budget_flags_and_last_close_lifetime() {
    let mut v = Vfs {
        credentials: Credentials::user(1000, 1001),
        ..Vfs::default()
    };
    let paths = v.path_queries();
    let budget = v.memfd_available();
    let work = paths.namespace_work(NamespaceCall::Memfd(
        MemfdParameters::new(b"accepted".to_vec(), 3).unwrap(),
    ));
    assert!(work.host_work());
    v.credentials = Credentials::default();
    let mut other = Vfs::default();
    other.memfd_create(b"unrelated", 0).unwrap();
    let fd = finish(work).unwrap();
    assert_eq!(
        v.fd_kind(fd).unwrap(),
        FdKind::Node(b"/memfd:accepted".to_vec())
    );
    assert_eq!(v.flags(fd).unwrap(), 2 | O_CLOEXEC);
    assert_eq!(v.seals(fd, None), Ok(0));
    assert_eq!(v.memfd_available(), budget);
    let descriptor = v.descriptor(fd).unwrap();
    let original = descriptor.open.borrow().shared.clone();
    let node = Arc::downgrade(original.node.as_ref().unwrap());
    assert_eq!(
        (
            original.node.as_ref().unwrap().borrow().uid,
            original.node.as_ref().unwrap().borrow().gid
        ),
        (1000, 1001)
    );
    drop(descriptor);
    v.truncate_fd(fd, 1 << 30).unwrap();
    assert_eq!(
        v.memfd_available(),
        budget,
        "sparse size is not physical allocation"
    );
    v.pwrite(fd, b"payload", 4096).unwrap();
    assert!(v.memfd_available() < budget);
    v.close(fd).unwrap();
    assert_eq!(v.memfd_create(b"replacement", 2), Ok(fd));
    assert!(node.upgrade().is_some());
    drop(original);
    assert!(node.upgrade().is_none());
    assert_eq!(v.memfd_available(), budget);
    assert_eq!(
        other.fd_kind(fd).unwrap(),
        FdKind::Node(b"/memfd:unrelated".to_vec())
    );
}
