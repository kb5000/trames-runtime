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

#[test]
fn concurrent_path_binders_publish_one_inode_without_overwriting_the_winner() {
    let mut v = Vfs::default();
    let fds: Vec<_> = (0..8).map(|_| v.local_create(1, 0).unwrap()).collect();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let jobs: Vec<_> = fds
        .iter()
        .map(|&fd| {
            let socket = v.descriptor_factory().local_operation(fd).unwrap().unwrap();
            let paths = v.path_queries();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                (
                    fd,
                    paths.local_bind(&socket, b"\x01\x00/bind-race\0").unwrap(),
                )
            })
        })
        .collect();
    let rows: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    let winners: Vec<_> = rows.iter().filter(|(_, result)| result.is_ok()).collect();
    assert_eq!(winners.len(), 1);
    for (fd, result) in &rows {
        if result.is_err() {
            assert_eq!(*result, Err(Errno(98)));
            assert_eq!(
                v.local_socket(*fd).unwrap().unwrap().name(false).unwrap(),
                [1, 0]
            );
        }
    }
    let winner = v.local_socket(winners[0].0).unwrap().unwrap();
    v.local_listen(&winner, 1).unwrap();
    let client = v.local_create(1, 0).unwrap();
    let client = v.local_socket(client).unwrap().unwrap();
    v.local_connect(&client, b"\x01\x00/bind-race\0").unwrap();
    assert!(winner.listening());
    assert_eq!(winner.accept_address_size(), Ok(2));
}

#[test]
fn waiting_connection_releases_the_listener_and_never_follows_a_rebound_address() {
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    let mut v = Vfs::default();
    let listener = v.local_create(1, 0).unwrap();
    let server = v.local_socket(listener).unwrap().unwrap();
    let address = b"\x01\x00\0weak-original-listener";
    v.local_bind(&server, address).unwrap();
    v.local_listen(&server, 0).unwrap();
    let first = v.local_create(1, 0).unwrap();
    v.local_connect(&v.local_socket(first).unwrap().unwrap(), address)
        .unwrap();
    let second = v.local_create(1, 0).unwrap();
    let socket = v
        .descriptor_factory()
        .local_operation(second)
        .unwrap()
        .unwrap();
    let connection = v
        .path_queries()
        .local_connection(&socket, address, [1, 0, 0])
        .unwrap()
        .unwrap();
    assert_eq!(connection.attempt(), Err(Errno(11)));
    let wake: Arc<dyn IoWake> = Arc::new(Wake);
    let signal = IoSignal::new(1, Arc::downgrade(&wake));
    let _subscription = connection.subscribe(&signal);
    drop(server);
    v.close(listener).unwrap();
    assert!(signal.ready());
    assert_eq!(connection.attempt(), Err(Errno(111)));
    let replacement = v.local_create(1, 0).unwrap();
    let server = v.local_socket(replacement).unwrap().unwrap();
    v.local_bind(&server, address).unwrap();
    v.local_listen(&server, 4).unwrap();
    assert_eq!(connection.attempt(), Err(Errno(111)));
    assert_eq!(server.accept_address_size(), Err(Errno(11)));
}

#[test]
fn accept_preflight_capacity_and_output_failure_preserve_reservations_and_queue_order() {
    let mut v = Vfs::default();
    let listener = v.local_create(1, 0).unwrap();
    let server = v.local_socket(listener).unwrap().unwrap();
    let address = b"\x01\x00\0accept-errors";
    v.local_bind(&server, address).unwrap();
    v.local_listen(&server, 4).unwrap();
    let client = v.local_create(1, 0).unwrap();
    v.local_connect(&v.local_socket(client).unwrap().unwrap(), address)
        .unwrap();
    let factory = v.descriptor_factory();
    assert_eq!(
        factory.accept_local_output(
            &server,
            0,
            &mut (),
            |_, _| Err::<(), _>(Errno(14)),
            |_, _, _| Ok(())
        ),
        Err(Errno(14))
    );
    assert_eq!(server.accept_address_size(), Ok(2));
    assert_eq!(
        factory.accept_local_output(&server, 1, &mut (), |_, _| Ok(()), |_, _, _| Ok(())),
        Err(Errno(22))
    );
    assert_eq!(server.accept_address_size(), Ok(2));
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = factory.accept_local_output(
            &server,
            0,
            &mut (),
            |_, _| Ok(()),
            |_, _, _| panic!("accept output panic"),
        );
    }));
    assert!(failed.is_err());
    assert_eq!(server.accept_address_size(), Err(Errno(11)));
    assert_ne!(v.poll(client, 16) & 16, 0);
    assert_eq!(v.local_create(1, 0), Ok(5));
}

#[test]
fn concurrent_acceptors_get_distinct_real_ofds_and_exact_peer_addresses() {
    let mut v = Vfs::default();
    let listener = v.local_create(1, 0).unwrap();
    let server = v.local_socket(listener).unwrap().unwrap();
    let address = b"\x01\x00\0many-acceptors";
    v.local_bind(&server, address).unwrap();
    v.local_listen(&server, 64).unwrap();
    for i in 0..32u8 {
        let client = v.local_create(1, 0).unwrap();
        let core = v.local_socket(client).unwrap().unwrap();
        let name = [b"\x01\x00\0client-".as_slice(), &[i]].concat();
        v.local_bind(&core, &name).unwrap();
        v.local_connect(&core, address).unwrap();
        core.send(&[i], 0).unwrap();
    }
    let jobs: Vec<_> = (0..8)
        .map(|_| {
            let factory = v.descriptor_factory();
            let listener = factory.local_operation(listener).unwrap().unwrap();
            std::thread::spawn(move || {
                let mut fds = Vec::new();
                for _ in 0..4 {
                    let (fd, name) = factory
                        .accept_local_output(
                            &listener,
                            O_NONBLOCK | O_CLOEXEC,
                            &mut (),
                            |_, size| Ok(size),
                            |_, size, name| {
                                assert_eq!(size, name.len());
                                Ok(())
                            },
                        )
                        .unwrap();
                    let bytes = factory
                        .files
                        .lookup(fd)
                        .unwrap()
                        .unwrap()
                        .direct_byte()
                        .unwrap()
                        .read(1)
                        .unwrap();
                    assert_eq!(name.last().copied(), bytes.first().copied());
                    fds.push(fd);
                }
                fds
            })
        })
        .collect();
    let mut fds: Vec<_> = jobs
        .into_iter()
        .flat_map(|job| job.join().unwrap())
        .collect();
    fds.sort_unstable();
    fds.dedup();
    assert_eq!(fds.len(), 32);
    assert_eq!(server.accept_address_size(), Err(Errno(11)));
    for fd in fds {
        assert_eq!(v.flags(fd).unwrap() & O_NONBLOCK, O_NONBLOCK);
        assert!(v.fds.get(&fd).unwrap().cloexec.get());
    }
}
