// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::Barrier;

#[test]
fn complete_network_graph_is_shared_and_concurrent_creation_has_one_quota() {
    fn shared<T: Send + Sync>() {}
    shared::<Network>();
    shared::<Socket>();
    shared::<Fabric>();
    let fabric = Fabric::new().unwrap();
    let network = Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
    let ready = Barrier::new(9);
    let release = Barrier::new(9);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let (network, ready, release) = (&network, &ready, &release);
            scope.spawn(move || {
                let sockets: Vec<_> = (0..16)
                    .filter_map(|_| match network.socket(2, 2, 0) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            assert_eq!(e, NetError(24));
                            None
                        }
                    })
                    .collect();
                ready.wait();
                release.wait();
                drop(sockets);
            });
        }
        ready.wait();
        assert_eq!(network.live_sockets(), MAX_SOCKETS);
        assert!(matches!(network.socket(2, 2, 0), Err(NetError(24))));
        release.wait();
    });
    assert_eq!(network.live_sockets(), 0);
    drop(network);
    assert_eq!(fabric.stats().environments, 0);
}

#[test]
fn competing_virtual_binds_publish_one_port_and_close_on_the_worker() {
    let fabric = Fabric::new().unwrap();
    let network = Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
    let original_handles = fabric.stats().stack_sockets;
    let gate = Barrier::new(8);
    let address = "10.0.0.2:32123".parse().unwrap();
    let sockets: Vec<_> = (0..8).map(|_| network.socket(2, 2, 0).unwrap()).collect();
    let results: Vec<_> = std::thread::scope(|scope| {
        sockets
            .iter()
            .map(|s| {
                let gate = &gate;
                scope.spawn(move || {
                    gate.wait();
                    s.bind(address)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|j| j.join().unwrap())
            .collect()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results
        .iter()
        .all(|r| *r == Ok(()) || *r == Err(NetError(98))));
    std::thread::spawn(move || drop(sockets)).join().unwrap();
    assert_eq!(network.live_sockets(), 0);
    assert_eq!(fabric.stats().stack_sockets, original_handles);
}

#[test]
fn independent_virtual_udp_operations_progress_on_the_same_fabric() {
    let fabric = Fabric::new().unwrap();
    let a = Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
    let b = Network::virtual_network(&fabric, 3, NetworkMode::Outbound).unwrap();
    let pairs: Vec<_> = (0..4)
        .map(|i| {
            let tx = a.socket(2, 2, 0).unwrap();
            let rx = b.socket(2, 2, 0).unwrap();
            rx.bind(SocketAddr::new("10.0.0.3".parse().unwrap(), 33000 + i))
                .unwrap();
            (tx, rx)
        })
        .collect();
    std::thread::scope(|scope| {
        for (tx, rx) in &pairs {
            scope.spawn(move || {
                let peer = rx.local_addr().unwrap();
                for n in 0u32..100 {
                    tx.send(&n.to_le_bytes(), 0, Some(peer)).unwrap();
                    let end = std::time::Instant::now() + Duration::from_secs(3);
                    loop {
                        match rx.recv(4, 0) {
                            Ok(r) => {
                                assert_eq!(r.data, n.to_le_bytes());
                                break;
                            }
                            Err(NetError(11)) if std::time::Instant::now() < end => {
                                wait(&[(rx.clone(), 1)], Duration::from_millis(1)).unwrap();
                            }
                            Err(e) => panic!("UDP did not progress: {e:?}"),
                        }
                    }
                }
            });
        }
    });
}
