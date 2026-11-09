// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn original_nested_graph_limits_cycles_aliases_and_close_reuse() {
    let mut v = Vfs::default();
    let event = v.eventfd(1, 0).unwrap();
    let nodes: Vec<_> = (0..6).map(|_| v.epoll_create(0).unwrap()).collect();
    v.epoll_ctl(nodes[4], 1, event, 1, 44).unwrap();
    for i in (0..4).rev() {
        v.epoll_ctl(nodes[i], 1, nodes[i + 1], 1, i as u64).unwrap();
    }
    let direct = v.direct_descriptors();
    assert_eq!(
        direct.epoll_control(nodes[4], 1, nodes[5], 1, 55),
        Some(Err(Errno(40)))
    );
    assert_eq!(
        direct.epoll_control(nodes[4], 1, nodes[0], 1, 55),
        Some(Err(Errno(40)))
    );
    assert_eq!(
        v.epoll_wait(nodes[0], 1, |_, _| Ok(None)).unwrap(),
        vec![(1, 0)]
    );
    let alias = v.dup(nodes[1], 0, false).unwrap();
    assert_eq!(
        direct.epoll_control(nodes[0], 1, alias, 1, 99),
        Some(Ok(()))
    );
    let mut ready = v.epoll_wait(nodes[0], 4, |_, _| Ok(None)).unwrap();
    ready.sort_unstable();
    assert_eq!(ready, vec![(1, 0), (1, 99)]);
    assert_eq!(direct.epoll_control(nodes[0], 2, alias, 0, 0), Some(Ok(())));
    let held = direct.epoll(nodes[0]).unwrap().unwrap();
    v.close(nodes[0]).unwrap();
    assert_eq!(v.eventfd(77, 0).unwrap(), nodes[0]);
    assert_eq!(held.epoll_wait(1).unwrap(), vec![(1, 0)]);
    assert_eq!(v.read(nodes[0], 8).unwrap(), 77u64.to_le_bytes());
    v.read(event, 8).unwrap();
    assert!(held.epoll_wait(1).unwrap().is_empty());
}

#[test]
fn opposite_nested_adds_join_foreign_original_graphs_without_a_cycle() {
    for foreign in [false, true] {
        let mut a = Vfs::default();
        let mut b = if foreign { Vfs::default() } else { a.clone() };
        let x = a.epoll_create(0).unwrap();
        let y = b.epoll_create(0).unwrap();
        // Install the original transferred OFDs, with independent descriptor
        // flags, just as a rights receiver does. No control-view copy is used.
        let original_y = b.fds.get(&y).unwrap().open;
        let original_x = a.fds.get(&x).unwrap().open;
        a.fds.insert(
            20,
            Descriptor {
                open: original_y,
                cloexec: false.into(),
            },
        );
        b.fds.insert(
            21,
            Descriptor {
                open: original_x,
                cloexec: false.into(),
            },
        );
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let (send, receive) = std::sync::mpsc::channel();
        let mut workers = Vec::new();
        for (files, fd, target) in [
            (a.direct_descriptors(), x, 20),
            (b.direct_descriptors(), y, 21),
        ] {
            let barrier = barrier.clone();
            let send = send.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                send.send(files.epoll_control(fd, 1, target, 1, 7)).unwrap();
            }));
        }
        let results: Vec<_> = (0..2)
            .map(|_| {
                receive
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap()
            })
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Some(Ok(())))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Some(Err(Errno(40))))
                .count(),
            1
        );
        for worker in workers {
            worker.join().unwrap();
        }
    }
}

#[test]
fn nested_graph_churn_and_flat_mod_do_not_lock_recursive_watch_state() {
    let mut v = Vfs::default();
    let a = v.epoll_create(0).unwrap();
    let b = v.epoll_create(0).unwrap();
    let event = v.eventfd(1, 0).unwrap();
    v.epoll_ctl(b, 1, event, 1, 1).unwrap();
    v.epoll_ctl(a, 1, b, 1, 2).unwrap();
    let direct = v.direct_descriptors();
    let original = direct.epoll(a).unwrap().unwrap();
    let (send, receive) = std::sync::mpsc::channel();
    let mut workers = Vec::new();
    for kind in 0..3 {
        let direct = direct.clone();
        let original = original.clone();
        let send = send.clone();
        workers.push(std::thread::spawn(move || {
            for i in 0..1500 {
                match kind {
                    0 => {
                        assert_eq!(direct.epoll_control(a, 2, b, 0, 0), Some(Ok(())));
                        assert_eq!(direct.epoll_control(b, 1, a, 1, 3), Some(Ok(())));
                        assert_eq!(direct.epoll_control(b, 2, a, 0, 0), Some(Ok(())));
                        assert_eq!(direct.epoll_control(a, 1, b, 1, 2), Some(Ok(())));
                    }
                    1 => {
                        assert_eq!(direct.epoll_control(b, 3, event, 1, i), Some(Ok(())));
                    }
                    _ => {
                        let _ = original.epoll_wait(2).unwrap();
                        let _ = original.next_deadline();
                    }
                }
            }
            send.send(()).unwrap();
        }));
    }
    for _ in 0..3 {
        receive
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
    }
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn original_interest_index_has_one_capacity_for_nested_and_flat_watches() {
    let mut v = Vfs::default();
    v.set_descriptor_limit(4096);
    let root = v.epoll_create(0).unwrap();
    let child = v.epoll_create(0).unwrap();
    v.epoll_ctl(root, 1, child, 1, 1).unwrap();
    let mut events = Vec::new();
    for i in 0..1023 {
        let event = v.eventfd(0, 0).unwrap();
        v.epoll_ctl(root, 1, event, 1, i).unwrap();
        events.push(event);
    }
    let extra = v.eventfd(0, 0).unwrap();
    assert_eq!(
        v.direct_descriptors().epoll_control(root, 1, extra, 1, 5),
        Some(Err(Errno(28)))
    );
    v.close(events.pop().unwrap()).unwrap();
    assert_eq!(
        v.direct_descriptors().epoll_control(root, 1, extra, 1, 5),
        Some(Ok(()))
    );
}

#[test]
fn nested_signalfd_uses_waiting_callers_signal_reader_without_a_frozen_owner_table() {
    struct Signals(bool);
    impl SignalReader for Signals {
        fn poll(&self, mask: u64) -> (u16, [u64; 2]) {
            (u16::from(self.0 && mask & 1 != 0), [0; 2])
        }
        fn take(&self, _: u64) -> Option<[u8; 128]> {
            None
        }
        fn subscribe(&self, _: &Arc<IoSignal>) -> Vec<IoSubscription> {
            Vec::new()
        }
    }
    let mut v = Vfs::default();
    let signal = v.signalfd(-1, 1, 0).unwrap();
    let child = v.epoll_create(0).unwrap();
    let root = v.epoll_create(0).unwrap();
    v.epoll_ctl(child, 1, signal, 1, 11).unwrap();
    v.epoll_ctl(root, 1, child, 1, 42).unwrap();
    let files = v.direct_descriptors();
    assert!(
        files.epoll(root).is_none(),
        "a genuinely absent caller provider remains explicit"
    );
    let a = files
        .clone()
        .with_signal_reader(Some(Arc::new(Signals(false))));
    let b = files.with_signal_reader(Some(Arc::new(Signals(true))));
    assert!(a
        .epoll(root)
        .unwrap()
        .unwrap()
        .epoll_wait(1)
        .unwrap()
        .is_empty());
    assert_eq!(
        b.epoll(root).unwrap().unwrap().epoll_wait(1).unwrap(),
        vec![(1, 42)]
    );
    assert!(a
        .epoll(root)
        .unwrap()
        .unwrap()
        .epoll_wait(1)
        .unwrap()
        .is_empty());
}
