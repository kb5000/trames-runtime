// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::time::Duration;

#[test]
fn topology_readers_and_other_namespace_packets_progress_independently() {
    fn shared<T: Send + Sync>() {}
    shared::<Topology>();
    shared::<View>();
    let mut topology = Topology::default();
    topology.add_space(1, None, None);
    topology.add_space(2, None, None);
    let graph = Arc::new(RwLock::new(topology));
    let namespace_one = graph.read().unwrap().connections(1);
    let held_state = namespace_one.lock().unwrap();
    let held_topology = graph.read().unwrap();
    let worker = graph.clone();
    let (complete, result) = std::sync::mpsc::channel();
    let task = std::thread::spawn(move || {
        let mut packet = crate::conntrack::message(
            "127.0.0.1:40000".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            6,
            2,
            &[],
        );
        let graph = worker.read().unwrap();
        assert!(graph.native_policy(2, false, &mut packet, None).is_some());
        complete.send(()).unwrap();
    });
    result
        .recv_timeout(Duration::from_secs(2))
        .expect("unrelated namespace blocked behind a topology reader or conntrack lock");
    drop((held_state, held_topology));
    task.join().unwrap();
}

#[test]
fn packet_accounting_needs_no_topology_writer_and_survives_link_move() {
    let loopback = Arc::new(Loopback::new(true));
    let mut topology = Topology::default();
    topology.add_space(1, Some(loopback.clone()), None);
    topology.add_space(2, None, None);
    let (link, _) = topology.create_veth(1, b"one", 2, b"two").unwrap();
    topology.account(1, link, 17, true, false);
    let graph = Arc::new(RwLock::new(topology));
    let reader = graph.read().unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let graph = &graph;
            scope.spawn(move || {
                let graph = graph.read().unwrap();
                for _ in 0..1000 {
                    graph.account(1, 1, 64, true, false);
                    graph.account(1, 1, 32, false, true);
                }
            });
        }
    });
    let stats = reader.device(1, 1).unwrap().stats;
    assert_eq!(
        (stats.tx_packets, stats.tx_bytes, stats.tx_dropped),
        (8000, 512000, 0)
    );
    assert_eq!(
        (stats.rx_packets, stats.rx_bytes, stats.rx_dropped),
        (8000, 256000, 8000)
    );
    loopback.set(false);
    assert!(!reader.device(1, 1).unwrap().up);
    drop(reader);
    let worker = graph.clone();
    std::thread::spawn(move || {
        worker.read().unwrap().account(1, 1, 1, true, false);
    })
    .join()
    .unwrap();
    assert_eq!(
        graph.read().unwrap().device(1, 1).unwrap().stats.tx_packets,
        8001
    );
    let mut graph = graph.write().unwrap();
    graph
        .change_link(1, link, None, Some(2), None, None, None, None)
        .unwrap();
    assert_eq!(graph.device(2, link).unwrap().stats.tx_bytes, 17);
    graph.account(2, link, 3, true, false);
    assert_eq!(graph.device(2, link).unwrap().stats.tx_bytes, 20);
}

#[test]
fn unchanged_native_refresh_does_not_wait_for_topology_readers() {
    let info = NetworkInfo {
        id: 0,
        ipv4: "192.0.2.2".parse().unwrap(),
        ipv6: Ipv6Addr::UNSPECIFIED,
        gateway4: "192.0.2.1".parse().unwrap(),
        gateway6: Ipv6Addr::UNSPECIFIED,
        mtu: 1500,
        prefix4: 24,
        prefix6: 0,
    };
    let mut topology = Topology::default();
    topology.add_space(1, None, Some(info));
    topology.refresh_direct(1, true, Some(info));
    let graph = Arc::new(RwLock::new(topology));
    let held = graph.read().unwrap();
    let revision = held.revision();
    let worker = graph.clone();
    let (complete, result) = std::sync::mpsc::channel();
    let task = std::thread::spawn(move || {
        refresh_native(&worker, 1, true, Some(info));
        complete.send(()).unwrap();
    });
    result
        .recv_timeout(Duration::from_secs(2))
        .expect("unchanged refresh needs no writer");
    assert_eq!(held.revision(), revision);
    drop(held);
    task.join().unwrap();
    refresh_native(&graph, 1, true, Some(NetworkInfo { mtu: 1400, ..info }));
    assert_eq!(graph.read().unwrap().device(1, 2).unwrap().mtu, 1400);
    assert_ne!(graph.read().unwrap().revision(), revision);
}
