// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::atomic::AtomicUsize;

#[test]
fn owning_rights_include_unaccepted_listener_children_without_a_connect_graph_lock() {
    let mut v = Vfs::default();
    let listener = v.local_create(1, 0).unwrap();
    let server = v.local_socket(listener).unwrap().unwrap();
    let address = b"\x01\x00\0pending-rights-cycle";
    v.local_bind(&server, address).unwrap();
    v.local_listen(&server, 4).unwrap();
    let client = v.local_create(1, 0).unwrap();
    v.local_connect(&v.local_socket(client).unwrap().unwrap(), address)
        .unwrap();
    let pending = Arc::downgrade(
        server
            .listener
            .borrow()
            .as_ref()
            .unwrap()
            .pending
            .front()
            .unwrap(),
    );
    assert_eq!(
        v.local_socket(client).unwrap().unwrap().send_rights(
            b"cycle",
            0,
            v.send_rights(&[listener]).unwrap()
        ),
        Err(Errno(95))
    );
    drop(server);
    v.close(listener).unwrap();
    assert!(pending.upgrade().is_none());
    assert_eq!(v.read(client, 1).unwrap(), b"");
}

#[test]
fn queued_unix_final_close_can_reenter_the_same_ownership_graph_from_notification() {
    struct SendAgain {
        tx: DirectFd,
        rights: SharedRights,
        done: std::sync::mpsc::Sender<()>,
    }
    impl IoWake for SendAgain {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            assert_eq!(
                self.tx
                    .send_local_message(b"new", 0, &self.rights, [1, 0, 0]),
                Some(Ok(3))
            );
            self.done.send(()).unwrap();
        }
    }
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let [c, d] = v.socketpair(1, 1, 0).unwrap();
    let [out, _input] = v.socketpair(1, 1, 0).unwrap();
    let [carried, _peer] = v.socketpair(1, 1, 0).unwrap();
    let factory = v.descriptor_factory();
    let (done, wait) = std::sync::mpsc::channel();
    let target: Arc<dyn IoWake> = Arc::new(SendAgain {
        tx: v.direct_descriptors().get(out).unwrap(),
        rights: factory.send_local_rights(&[carried]).unwrap().unwrap(),
        done,
    });
    let signal = IoSignal::new(1, Arc::downgrade(&target));
    let _subscription = factory
        .local_operation(d)
        .unwrap()
        .unwrap()
        .subscribe(&signal);
    v.local_socket(a)
        .unwrap()
        .unwrap()
        .send_rights(b"old", 0, v.send_rights(&[c]).unwrap())
        .unwrap();
    v.close(c).unwrap();
    let worker = std::thread::spawn(move || factory.files.close(b, 1).unwrap().unwrap());
    wait.recv_timeout(std::time::Duration::from_secs(3))
        .expect("final close ran under an ownership/queue lock");
    worker.join().unwrap();
    drop(_subscription);
}

#[test]
fn concurrent_unix_rights_cannot_publish_a_reciprocal_owning_cycle() {
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let [c, d] = v.socketpair(1, 1, 0).unwrap();
    let factory = v.descriptor_factory();
    let weak =
        [b, c].map(|fd| Arc::downgrade(factory.local_operation(fd).unwrap().unwrap().core()));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let jobs: Vec<_> = [(a, c), (d, b)]
        .into_iter()
        .map(|(source, carried)| {
            let fd = v.direct_descriptors().get(source).unwrap();
            let rights = factory.send_local_rights(&[carried]).unwrap().unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                fd.send_local_message(b"x", 0, &rights, [1, 0, 0]).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|&&r| r == Ok(1)).count(), 1);
    assert_eq!(results.iter().filter(|&&r| r == Err(Errno(95))).count(), 1);
    for fd in [a, b, c, d] {
        v.close(fd).unwrap();
    }
    assert!(weak.iter().all(|p| p.upgrade().is_none()));
}

#[test]
fn shared_unix_rights_keep_original_ofd_across_reuse_peek_and_worker_import() {
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 5, 0).unwrap();
    let [c, d] = v.socketpair(1, 1, 0).unwrap();
    let factory = v.descriptor_factory();
    let rights = factory.send_local_rights(&[c]).unwrap().unwrap();
    v.close(c).unwrap();
    assert_eq!(v.eventfd(99, 0).unwrap(), c);
    let tx = v.direct_descriptors().get(a).unwrap();
    assert_eq!(
        std::thread::spawn(move || tx.send_local_message(b"fd", 0, &rights, [1, 0, 0]).unwrap())
            .join()
            .unwrap(),
        Ok(2)
    );
    let rx = v.direct_descriptors().get(b).unwrap();
    let peek = rx.recv_local_message(1, 2).unwrap().unwrap();
    assert_eq!(peek.data, b"f");
    assert!(peek.truncated);
    let (first, cut) = factory.receive_local_rights(peek.rights, 1, true);
    assert!(!cut);
    let received = std::thread::spawn(move || rx.recv_local_message(9, 0).unwrap().unwrap())
        .join()
        .unwrap();
    let (second, cut) = factory.receive_local_rights(received.rights, 1, false);
    assert!(!cut);
    assert_eq!(received.data, b"fd");
    assert_ne!(v.flags(first[0]).unwrap() & O_CLOEXEC, 0);
    assert_eq!(v.flags(second[0]).unwrap() & O_CLOEXEC, 0);
    v.write(first[0], b"one").unwrap();
    assert_eq!(v.read(d, 3).unwrap(), b"one");
    v.write(second[0], b"two").unwrap();
    assert_eq!(v.read(d, 3).unwrap(), b"two");
    assert_eq!(v.read(c, 8).unwrap(), 99u64.to_le_bytes());
}

#[test]
fn raw_worker_read_discards_unix_rights_and_releases_the_original_socket() {
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let [c, _d] = v.socketpair(1, 1, 0).unwrap();
    let factory = v.descriptor_factory();
    let weak = Arc::downgrade(factory.local_operation(c).unwrap().unwrap().core());
    v.local_socket(a)
        .unwrap()
        .unwrap()
        .send_rights(b"x", 0, v.send_rights(&[c]).unwrap())
        .unwrap();
    v.close(c).unwrap();
    assert_eq!(v.eventfd(73, 0).unwrap(), c);
    assert!(weak.upgrade().is_some());
    let rx = v.direct_descriptors().get(b).unwrap();
    assert_eq!(
        std::thread::spawn(move || rx.read(1)).join().unwrap(),
        Ok(b"x".to_vec())
    );
    assert!(weak.upgrade().is_none());
    assert_eq!(v.read(c, 8).unwrap(), 73u64.to_le_bytes());
}

#[test]
fn complete_epoll_and_shared_unix_rights_observe_one_cycle_graph() {
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let [c, d] = v.socketpair(1, 1, 0).unwrap();
    v.set_runtime_info(
        1,
        RuntimeInfo {
            processes: vec![ProcessInfo {
                pid: 1,
                tgid: 1,
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let legacy = v.epoll_create(0).unwrap();
    let factory = v.descriptor_factory();
    assert!(factory.send_local_rights(&[legacy]).unwrap().is_ok());
    v.local_socket(a)
        .unwrap()
        .unwrap()
        .send_rights(b"x", 0, v.send_rights(&[legacy, c]).unwrap())
        .unwrap();
    let tx = v.direct_descriptors().get(d).unwrap();
    let rights = factory.send_local_rights(&[b]).unwrap().unwrap();
    assert_eq!(
        tx.send_local_message(b"cycle", 0, &rights, [1, 0, 0]),
        Some(Err(Errno(95)))
    );
    let received = v.local_socket(b).unwrap().unwrap().recv(1, 0).unwrap();
    let (fds, cut) = v.receive_rights(received.rights, 2, false);
    assert!(!cut);
    assert_eq!(fds.len(), 2);
    assert_eq!(
        tx.send_local_message(b"allowed", 0, &rights, [1, 0, 0]),
        Some(Ok(7))
    );
}

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
fn worker_final_close_releases_shared_unix_rights_without_owner_reap() {
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
    assert!(factory.send_local_rights(&[queued]).unwrap().is_ok());
    let sender = v.local_socket(a).unwrap().unwrap();
    sender
        .send_rights(b"x", 0, v.send_rights(&[queued]).unwrap())
        .unwrap();
    v.close(queued).unwrap();
    assert!(weak.upgrade().is_some());

    std::thread::spawn(move || factory.files.close(b, 1).unwrap().unwrap())
        .join()
        .unwrap();

    assert!(weak.upgrade().is_none());
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

#[test]
fn ring_registration_and_queued_rights_observe_cycles_in_both_admission_orders() {
    for queued_first in [false, true] {
        let mut v = Vfs::default();
        let (fd, ring) = v.uring_create(4, 8).unwrap();
        let [a, b] = v.socketpair(1, 1, 0).unwrap();
        let factory = v.descriptor_factory();
        let tx = v.direct_descriptors().get(a).unwrap();
        let file = v.retain_uring_file(b).unwrap();
        let rights = factory.send_local_rights(&[fd]).unwrap().unwrap();
        if queued_first {
            assert_eq!(
                tx.send_local_message(b"r", 0, &rights, [1, 0, 0]),
                Some(Ok(1))
            );
            assert!(matches!(ring.bind_file(&file), Err(Errno(95))));
        } else {
            ring.state.lock().unwrap().files = Some(vec![Some(ring.bind_file(&file).unwrap())]);
            assert_eq!(
                tx.send_local_message(b"r", 0, &rights, [1, 0, 0]),
                Some(Err(Errno(95)))
            );
            let retired = ring.state.lock().unwrap().files.take();
            drop(retired);
            assert_eq!(
                tx.send_local_message(b"r", 0, &rights, [1, 0, 0]),
                Some(Ok(1))
            );
        }
        let weak = Arc::downgrade(&ring);
        drop(rights);
        drop(file);
        drop(ring);
        v.close(fd).unwrap();
        assert!(weak.upgrade().is_some()); // the real received FD still owns it
        v.close(b).unwrap();
        assert!(weak.upgrade().is_none());
    }
}

#[test]
fn concurrent_ring_registration_and_fd_transfer_cannot_publish_a_reciprocal_cycle() {
    let mut v = Vfs::default();
    let (fd, ring) = v.uring_create(4, 8).unwrap();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let tx = v.direct_descriptors().get(a).unwrap();
    let rights = v
        .descriptor_factory()
        .send_local_rights(&[fd])
        .unwrap()
        .unwrap();
    let file = v.retain_uring_file(b).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    let r = ring.clone();
    let registration = std::thread::spawn(move || {
        other.wait();
        r.bind_file(&file)
    });
    let send = std::thread::spawn(move || {
        barrier.wait();
        tx.send_local_message(b"r", 0, &rights, [1, 0, 0]).unwrap()
    });
    let registration = registration.join().unwrap();
    let send = send.join().unwrap();
    assert_eq!(
        usize::from(registration.is_ok()) + usize::from(send.is_ok()),
        1
    );
    assert!(registration.as_ref().err() == Some(&Errno(95)) || send == Err(Errno(95)));
    drop(registration);
    let weak = Arc::downgrade(&ring);
    drop(ring);
    for descriptor in [a, b, fd] {
        v.close(descriptor).unwrap();
    }
    assert!(weak.upgrade().is_none());
}

// A complete original projection can still be intentionally opaque to byte or
// control execution. Passing its lifetime must never require a Kernel ledger.
fn opaque(v: &mut Vfs, fd: u32) -> OpenWeak {
    let descriptor = v.descriptor(fd).unwrap();
    let metadata = descriptor.open.borrow().shared.clone();
    let open = OpenHandle::Owner(Arc::new(SharedCell::new(
        OpenDescription::shared_projection(metadata),
    )));
    let weak = open.downgrade();
    v.fds.insert(
        fd,
        Descriptor {
            open,
            cloexec: descriptor.cloexec,
        },
    );
    weak
}
#[test]
fn mixed_opaque_rights_retain_original_controls_and_import_on_source_after_close_reuse() {
    let mut v = Vfs::default();
    let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
    let event = v.eventfd(41, 0).unwrap();
    let ep = v.epoll_create(0).unwrap();
    v.epoll_ctl(ep, 1, event, 1, 77).unwrap();
    let original = opaque(&mut v, ep);
    let factory = v.descriptor_factory();
    let rights = std::thread::spawn({
        let factory = factory.clone();
        move || factory.send_local_rights(&[event, ep]).unwrap().unwrap()
    })
    .join()
    .unwrap();
    v.close(ep).unwrap();
    assert_eq!(v.eventfd(99, 0).unwrap(), ep);
    let sender = v.direct_descriptors().get(tx).unwrap();
    assert_eq!(
        std::thread::spawn(move || sender.send_local_message(b"x", 0, &rights, [1, 0, 0]))
            .join()
            .unwrap(),
        Some(Ok(1))
    );
    let receiver = v.direct_descriptors().get(rx).unwrap();
    let packet = std::thread::spawn(move || receiver.recv_local_message(1, 0).unwrap().unwrap())
        .join()
        .unwrap();
    let got = std::thread::spawn(move || factory.receive_local_rights(packet.rights, 2, true))
        .join()
        .unwrap();
    assert!(!got.1);
    assert_eq!(got.0.len(), 2);
    assert!(OpenHandle::ptr_eq(
        &v.descriptor(got.0[1]).unwrap().open,
        &original.upgrade().unwrap()
    ));
    assert_eq!(
        v.epoll_wait(got.0[1], 1, |_, _| Ok(None)).unwrap(),
        vec![(1, 77)]
    );
    assert_eq!(v.read(ep, 8).unwrap(), 99u64.to_le_bytes());
    for fd in got.0 {
        v.close(fd).unwrap();
    }
    assert!(original.upgrade().is_none());
}
#[test]
fn opaque_ring_ownership_rejects_cycles_and_final_close_needs_no_owner_reap() {
    let mut v = Vfs::default();
    let [a, b] = v.socketpair(1, 1, 0).unwrap();
    let (fd, ring) = v.uring_create(4, 8).unwrap();
    let carried = v.retain_uring_file(a).unwrap();
    ring.state.lock().unwrap().files = Some(vec![Some(ring.bind_file(&carried).unwrap())]);
    let original = opaque(&mut v, fd);
    let factory = v.descriptor_factory();
    let rights = factory.send_local_rights(&[fd]).unwrap().unwrap();
    let tx = v.direct_descriptors().get(b).unwrap();
    assert_eq!(
        tx.send_local_message(b"cycle", 0, &rights, [1, 0, 0]),
        Some(Err(Errno(95)))
    );
    drop(rights);
    v.close(fd).unwrap();
    assert!(original.upgrade().is_none());
    let fd = v.eventfd(7, 0).unwrap();
    let original = opaque(&mut v, fd);
    let file = v.retain_uring_file(fd).unwrap();
    v.close(fd).unwrap();
    assert!(original.upgrade().is_some());
    assert_eq!(v.eventfd(99, 0).unwrap(), fd);
    std::thread::spawn(move || drop(file)).join().unwrap();
    assert!(
        original.upgrade().is_none(),
        "last complete projection closes on the releasing worker"
    );
    assert_eq!(v.read(fd, 8).unwrap(), 99u64.to_le_bytes());
}
