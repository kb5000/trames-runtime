// SPDX-License-Identifier: GPL-3.0-or-later
//! Complete task ownership, including cold controls and local memoization.
use super::*;

#[test]
fn full_vfs_handoff_retains_queued_controls_namespaces_and_original_files() {
    let mut parent = Vfs::default();
    parent.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                namespaces: parent.namespace_snapshot(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let namespace = parent
        .open_at(AT_FDCWD, b"/proc/self/ns/net", 0, 0)
        .unwrap();
    let ns_identity = parent.stat_fd(namespace).unwrap();
    let epoll = parent.epoll_create(O_CLOEXEC).unwrap();
    let control = match parent.descriptor(epoll).unwrap().open {
        OpenHandle::Owner(control) => Arc::downgrade(&control),
        _ => panic!("original epoll control"),
    };
    let [reader, writer] = parent.pipe(O_NONBLOCK).unwrap();
    parent.epoll_ctl(epoll, 1, reader, 1, 91).unwrap();
    let [sender, receiver] = parent.socketpair(1, 1, 0).unwrap();
    let mut child = parent.clone();
    parent
        .local_socket(sender)
        .unwrap()
        .unwrap()
        .send_rights(b"c", 0, parent.send_rights(&[epoll]).unwrap())
        .unwrap();
    parent.close(epoll).unwrap();
    child.close(epoll).unwrap();
    let (ready, start) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        start.recv().unwrap();
        assert_eq!(child.stat_fd(namespace).unwrap(), ns_identity);
        assert_eq!(child.namespace_type(namespace), Ok(Some(CLONE_NEWNET)));
        let message = child
            .local_socket(receiver)
            .unwrap()
            .unwrap()
            .recv(1, 0)
            .unwrap();
        assert_eq!(message.data, b"c");
        let (fds, truncated) = child.receive_rights(message.rights, 1, true);
        assert!(!truncated);
        child.write(writer, b"x").unwrap();
        assert_eq!(
            child.epoll_wait(fds[0], 8, |_, _| Ok(None)).unwrap(),
            vec![(1, 91)]
        );
        assert_eq!(child.read(reader, 1).unwrap(), b"x");
        child.close(fds[0]).unwrap();
        child.reap_local_rights();
    });
    drop(parent);
    assert!(
        control.upgrade().is_some(),
        "the queued right owns the original control"
    );
    ready.send(()).unwrap();
    worker.join().unwrap();
    assert!(control.upgrade().is_none());
}

#[test]
fn concurrent_shared_files_keep_private_caches_and_fork_the_actual_membership() {
    let mut parent = Vfs::default();
    parent.mkdir_at(AT_FDCWD, b"/moved", 0o755).unwrap();
    let [reader, writer] = parent.pipe(O_NONBLOCK).unwrap();
    parent.stream_descriptors();
    parent.fd_flags_snapshot();
    let mut peer = parent.clone_with_resources(true, true);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let gate = barrier.clone();
    let worker = std::thread::spawn(move || {
        peer.chdir(b"/moved").unwrap();
        gate.wait();
        for _ in 0..2000 {
            peer.dup3(writer, 64, O_CLOEXEC).unwrap();
            peer.stream_descriptors();
            peer.fd_flags_snapshot();
            peer.close(64).unwrap();
        }
        peer.close(writer).unwrap();
    });
    barrier.wait();
    assert_eq!(parent.cwd().unwrap(), b"/moved");
    for _ in 0..2000 {
        let child = parent.clone();
        let mask = child.stream_descriptors();
        let copied_alias = child.fd_kind(64).is_ok();
        assert_eq!(mask[1] & 1 != 0, copied_alias);
        if copied_alias {
            assert_ne!(child.flags(64).unwrap() & O_CLOEXEC, 0);
        }
        child.fd_flags_snapshot();
    }
    worker.join().unwrap();
    assert_eq!(parent.flags(writer), Err(Errno(9)));
    assert_eq!(parent.read(reader, 1).unwrap(), b"");
}
