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

#[test]
fn separate_fabrics_exchange_packets_and_isolate_named_links() {
    let directory = std::path::PathBuf::from(format!("/tmp/trames-link-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let a = Fabric::new().unwrap();
    let b = Fabric::new().unwrap();
    a.attach(&directory, 2, false).unwrap();
    b.attach(&directory, 3, false).unwrap();
    assert!(Fabric::new().unwrap().attach(&directory, 2, false).is_err());
    let na = Network::virtual_network(&a, 2, NetworkMode::Outbound).unwrap();
    let nb = Network::virtual_network(&b, 3, NetworkMode::Outbound).unwrap();
    let tx = na.socket(2, 2, 0).unwrap();
    let rx = nb.socket(2, 2, 0).unwrap();
    rx.bind("0.0.0.0:32001".parse().unwrap()).unwrap();
    tx.send(b"separate", 0, Some("10.0.0.3:32001".parse().unwrap()))
        .unwrap();
    wait(&[(rx.clone(), 1)], Duration::from_secs(1)).unwrap();
    assert_eq!(rx.recv(64, 0).unwrap().data, b"separate");
    let (sources, _) = rx.wait_interests();
    assert!(sources.iter().any(|s| matches!(s, WaitSource::Link(_))));
    // A different directory can reuse the same address and port without joining.
    let other = directory.join("other");
    std::fs::create_dir(&other).unwrap();
    let c = Fabric::new().unwrap();
    c.attach(&other, 3, false).unwrap();
    let nc = Network::virtual_network(&c, 3, NetworkMode::Outbound).unwrap();
    let isolated = nc.socket(2, 2, 0).unwrap();
    isolated.bind("0.0.0.0:32001".parse().unwrap()).unwrap();
    assert!(matches!(isolated.recv(64, 0), Err(NetError(11))));
    drop((sources, isolated, nc, c, rx, tx, nb, na, a, b));
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn published_tcp_and_udp_reuse_existing_gateway_and_waiters() {
    use std::io::{Read, Write};
    let fabric = Fabric::new().unwrap();
    let net = Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
    let listener = net.socket(2, 1, 0).unwrap();
    listener.bind("0.0.0.0:35000".parse().unwrap()).unwrap();
    listener.listen(4).unwrap();
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let host = reservation.local_addr().unwrap();
    drop(reservation);
    fabric
        .publish(host, "10.0.0.2:35000".parse().unwrap(), 1)
        .unwrap();
    let worker = std::thread::spawn(move || {
        let mut c = std::net::TcpStream::connect(host).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        c.write_all(b"tcp").unwrap();
        let mut b = [0; 3];
        c.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"ok!");
    });
    let end = std::time::Instant::now() + Duration::from_secs(3);
    let accepted = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(NetError(11)) if std::time::Instant::now() < end => {
                wait(&[(listener.clone(), 1)], Duration::from_millis(20)).unwrap()
            }
            other => panic!("accept: {}", other.err().unwrap()),
        }
    };
    loop {
        match accepted.recv(3, 0) {
            Ok(r) => {
                assert_eq!(r.data, b"tcp");
                break;
            }
            Err(NetError(11)) if std::time::Instant::now() < end => {
                wait(&[(accepted.clone(), 1)], Duration::from_millis(20)).unwrap()
            }
            other => panic!("recv: {}", other.err().unwrap()),
        }
    }
    accepted.send(b"ok!", 0, None).unwrap();
    // Drive the original stack while the host consumes its reply.
    while !worker.is_finished() && std::time::Instant::now() < end {
        wait(&[(accepted.clone(), 1)], Duration::from_millis(5)).unwrap();
    }
    worker.join().unwrap();
    let udp = net.socket(2, 2, 0).unwrap();
    udp.bind("0.0.0.0:35001".parse().unwrap()).unwrap();
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let host = reservation.local_addr().unwrap();
    drop(reservation);
    fabric
        .publish(host, "10.0.0.2:35001".parse().unwrap(), 2)
        .unwrap();
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.send_to(b"udp", host).unwrap();
    let received = loop {
        match udp.recv(3, 0) {
            Ok(r) => break r,
            Err(NetError(11)) if std::time::Instant::now() < end => {
                wait(&[(udp.clone(), 1)], Duration::from_millis(5)).unwrap()
            }
            other => panic!("udp recv: {}", other.err().unwrap()),
        }
    };
    assert_eq!(received.data, b"udp");
    udp.send(b"ok", 0, received.address).unwrap();
    for _ in 0..3 {
        wait(&[(udp.clone(), 1)], Duration::from_millis(1)).unwrap();
    }
    let mut bytes = [0; 2];
    assert_eq!(client.recv(&mut bytes).unwrap(), 2);
    assert_eq!(&bytes, b"ok");
}
