// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::atomic::AtomicUsize;

#[test]
fn concurrent_socket_creation_uses_the_original_complete_namespace_and_ofds() {
    fn shared<T: Send + Sync>() {}
    shared::<LocalResource>();
    shared::<linux_namespace::RootNetwork>();
    shared::<binding::PathBindings>();
    shared::<DescriptorFactory>();
    shared::<LocalOperation>();
    let mut v = Vfs {
        credentials: Credentials::user(501, 502),
        ..Vfs::default()
    };
    let factory = v.descriptor_factory().with_local_identity([42, 501, 502]);
    let original = Arc::downgrade(&v.root_network);
    v.credentials = Credentials::default();
    v.unshare_net().unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let factory = factory.clone();
            let original = original.clone();
            scope.spawn(move || {
                for i in 0..48 {
                    let kind = [1, 2, 5][i % 3];
                    let [a, b] = factory
                        .local_pair_with_output(1, kind | O_NONBLOCK | O_CLOEXEC, 0, |_| Ok(()))
                        .unwrap();
                    let socket = factory.local_operation(a).unwrap().unwrap();
                    assert!(Arc::ptr_eq(&socket.network, &original.upgrade().unwrap()));
                    assert_eq!(socket.peer_credentials(), [42, 501, 502]);
                    let alias = factory.files.duplicate(a, 0, false).unwrap().unwrap();
                    let tx = factory
                        .files
                        .lookup(alias)
                        .unwrap()
                        .unwrap()
                        .direct_byte()
                        .unwrap();
                    let rx = factory
                        .files
                        .lookup(b)
                        .unwrap()
                        .unwrap()
                        .direct_byte()
                        .unwrap();
                    assert!(tx.nonblocking());
                    assert_eq!(tx.write(b"x"), Ok(1));
                    assert_eq!(rx.read(1), Ok(b"x".to_vec()));
                    for fd in [a, alias, b] {
                        assert_eq!(factory.files.close(fd, 42), Some(Ok(())));
                    }
                    // This accepted call pins the full original OFD after all
                    // its numeric descriptors have closed on this worker.
                    assert_eq!(socket.kind(), kind);
                }
            });
        }
    });
    assert_eq!(v.fd_snapshot().len(), 3);
    drop(factory);
    assert!(original.upgrade().is_none());
}

#[test]
fn pair_copyout_errors_and_panics_leave_no_fds_or_endpoint_quota() {
    let v = Vfs::default();
    let factory = v.descriptor_factory();
    let live = || {
        v.root_network
            .local
            .borrow()
            .sockets
            .iter()
            .filter(|s| s.strong_count() != 0)
            .count()
    };
    assert_eq!(
        factory.local_pair_with_output(1, 1, 0, |_| Err(Errno(14))),
        Err(Errno(14))
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = factory.local_pair_with_output(1, 1, 0, |_| panic!("copyout panic"));
    }));
    assert!(result.is_err());
    assert_eq!(live(), 0);
    assert_eq!(v.fd_snapshot().len(), 3);
    let pair = factory.local_pair_with_output(1, 1, 0, |_| Ok(())).unwrap();
    assert_eq!(pair, [3, 4]);
    for fd in pair {
        factory.files.close(fd, 1).unwrap().unwrap();
    }
    assert_eq!(live(), 0);
}

#[test]
fn accepted_unix_ofd_pins_the_endpoint_but_passive_watches_do_not() {
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let snapshot = v.direct_descriptors();
    let factory = v.descriptor_factory();
    let accepted = factory.local_operation(a).unwrap().unwrap();
    let weak = Arc::downgrade(accepted.0.local.as_ref().unwrap());
    let ep = v.epoll_create(0).unwrap();
    v.epoll_ctl(ep, 1, a, 1, 9).unwrap();
    v.close(a).unwrap();
    assert!(snapshot.get(a).is_none());
    assert_eq!(v.poll(b, 1 | 16) & 16, 0);
    let replacement = v.local_create(2, 0).unwrap();
    assert_eq!(replacement, a);
    std::thread::spawn(move || {
        assert_eq!(accepted.send(b"original", 0), Ok(8));
        drop(accepted);
    })
    .join()
    .unwrap();
    assert!(weak.upgrade().is_none());
    assert_eq!(v.read(b, 8), Ok(b"original".to_vec()));
    assert_ne!(v.poll(b, 1 | 16) & 16, 0);
    assert!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap().is_empty());
    assert_eq!(v.local_socket(replacement).unwrap().unwrap().kind(), 2);
}

struct Target {
    socket: LocalOperation,
    calls: AtomicUsize,
}
impl IoWake for Target {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        // Reenter control state: notification must not retain transition locks.
        self.socket.set_reuse(2, 1).unwrap();
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}
#[test]
fn preconnect_subscriptions_and_options_survive_connection_publication() {
    let mut v = Vfs::default();
    let listener = v.local_create(1, 0).unwrap();
    let server = v.local_socket(listener).unwrap().unwrap();
    v.local_bind(&server, b"\x01\x00\0preconnect-events")
        .unwrap();
    v.local_listen(&server, 2).unwrap();
    let client = v.local_create(1, 0).unwrap();
    let factory = v.descriptor_factory();
    let accepted = factory.local_operation(client).unwrap().unwrap();
    accepted.set_reuse(7, 8192).unwrap();
    accepted.set_reuse(8, 4096).unwrap();
    accepted.set_reuse(16, 1).unwrap();
    accepted.set_reuse(35, 1).unwrap();
    let target = Arc::new(Target {
        socket: accepted,
        calls: AtomicUsize::new(0),
    });
    let erased: Arc<dyn IoWake> = target.clone();
    let signal = IoSignal::new(1, Arc::downgrade(&erased));
    let _subscription = target.socket.subscribe(&signal);
    let client_socket = v.local_socket(client).unwrap().unwrap();
    v.local_connect(&client_socket, b"\x01\x00\0preconnect-events")
        .unwrap();
    let (peer, _) = v.local_accept(&server, 0).unwrap();
    assert_eq!(target.socket.buffer_size(false), 16384);
    assert_eq!(target.socket.buffer_size(true), 8192);
    assert_eq!(target.socket.reuse(16), 1);
    assert_eq!(target.socket.reuse(35), 1);
    signal.reset();
    let count = target.calls.load(Ordering::Relaxed);
    v.write(peer, b"x").unwrap();
    assert!(signal.ready());
    assert!(target.calls.load(Ordering::Relaxed) > count);
    let received = client_socket.recv(1, 0).unwrap();
    assert_eq!(received.data, b"x");
    assert!(received.credentials.is_some());
    assert_eq!(received.timestamp.unwrap().0, 35);
}

#[test]
fn worker_final_close_defers_only_legacy_rights_destruction_to_the_owner() {
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let [queued, _peer] = v.socketpair(1, 1, 0).unwrap();
    let weak = Arc::downgrade(
        v.descriptor(queued)
            .unwrap()
            .open
            .borrow()
            .local
            .as_ref()
            .unwrap(),
    );
    let factory = v.descriptor_factory();
    assert!(factory.send_local_rights(&[queued]).is_none());
    let sender = v.local_socket(a).unwrap().unwrap();
    sender
        .send_rights(b"x", 0, v.send_rights(&[queued]).unwrap())
        .unwrap();
    v.close(queued).unwrap();
    assert!(weak.upgrade().is_some());
    assert!(!v.local_rights_need_owner());
    std::thread::spawn(move || factory.files.close(b, 1).unwrap().unwrap())
        .join()
        .unwrap();
    assert!(v.local_rights_need_owner());
    v.reap_local_rights();
    assert!(weak.upgrade().is_none());
    assert!(!v.local_rights_need_owner());
}
