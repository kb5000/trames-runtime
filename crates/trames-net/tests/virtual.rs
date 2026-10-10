// SPDX-License-Identifier: GPL-3.0-or-later
use std::{
    net::{IpAddr, SocketAddr},
    rc::Rc,
    time::{Duration, Instant},
};
use trames_net::{wait, Fabric, NetError, Network, NetworkMode, Socket, MSG_PEEK, MSG_TRUNC};
fn net(f: &Fabric, id: u8) -> Network {
    Network::virtual_network(f, id, NetworkMode::Outbound).unwrap()
}
fn socket(n: &Network, v6: bool, tcp: bool) -> Rc<Socket> {
    n.socket(if v6 { 10 } else { 2 }, if tcp { 1 } else { 2 }, 0)
        .unwrap()
}
fn parse(s: &str) -> SocketAddr {
    s.parse().unwrap()
}
fn until<T>(s: &Rc<Socket>, mut f: impl FnMut() -> Result<T, NetError>) -> T {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        match f() {
            Ok(v) => return v,
            Err(NetError(11)) => {}
            Err(e) => panic!("{e}"),
        }
        assert!(Instant::now() < end, "network timeout");
        wait(&[(s.clone(), 1 | 4)], Duration::from_millis(2)).unwrap();
    }
}
fn connect(s: &Rc<Socket>, a: SocketAddr) {
    assert_eq!(s.connect(a), Err(NetError(115)));
    until(s, || {
        if s.connect_complete()? {
            Ok(())
        } else {
            Err(NetError(11))
        }
    });
}
#[test]
fn tcp_ipv4_ipv6_namespaces_eof_and_private_loopback() {
    let f = Fabric::new().unwrap();
    let a = net(&f, 2);
    let b = net(&f, 3);
    for v6 in [false, true] {
        let own = if v6 {
            "[fd00::2]:8080"
        } else {
            "10.0.0.2:8080"
        };
        let same = if v6 {
            "[fd00::3]:8080"
        } else {
            "10.0.0.3:8080"
        };
        let server = socket(&a, v6, true);
        server.bind(parse(own)).unwrap();
        server.listen(2).unwrap();
        let other = socket(&b, v6, true);
        other.bind(parse(same)).unwrap();
        other.listen(2).unwrap();
        let client = socket(&b, v6, true);
        connect(&client, parse(own));
        let (accepted, peer) = until(&server, || server.accept());
        assert_eq!(peer.ip(), parse(same).ip());
        client.send(b"hello", 0, None).unwrap();
        assert_eq!(
            until(&accepted, || accepted.recv(5, MSG_PEEK)).data,
            b"hello"
        );
        assert_eq!(accepted.recv(5, 0).unwrap().data, b"hello");
        client.shutdown(1).unwrap();
        assert!(until(&accepted, || accepted.recv(1, 0)).data.is_empty());
        accepted.send(b"reply", 0, None).unwrap();
        accepted.shutdown(1).unwrap();
        assert_eq!(until(&client, || client.recv(5, 0)).data, b"reply");
        assert!(until(&client, || client.recv(1, 0)).data.is_empty());
        let loopaddr = parse(if v6 { "[::1]:9000" } else { "127.0.0.1:9000" });
        let la = socket(&a, v6, true);
        let lb = socket(&b, v6, true);
        la.bind(loopaddr).unwrap();
        lb.bind(loopaddr).unwrap();
        la.listen(1).unwrap();
        lb.listen(1).unwrap();
        let lc = socket(&b, v6, true);
        connect(&lc, loopaddr);
        let _ = until(&lb, || lb.accept());
        assert_eq!(la.poll(1).unwrap(), 0);
    }
}
#[test]
fn udp_large_fragmentation_zero_truncation_and_connected_filter() {
    let f = Fabric::new().unwrap();
    let a = net(&f, 2);
    let b = net(&f, 3);
    for v6 in [false, true] {
        let server = socket(&a, v6, false);
        let address = parse(if v6 {
            "[fd00::2]:2345"
        } else {
            "10.0.0.2:2345"
        });
        server.bind(address).unwrap();
        let client = socket(&b, v6, false);
        client.connect(address).unwrap();
        let size = if v6 { 65527 } else { 65507 };
        let payload: Vec<_> = (0..size).map(|i| (i % 251) as u8).collect();
        assert_eq!(client.send(&payload, 0, None).unwrap(), size);
        let received = until(&server, || server.recv(size, 0));
        assert_eq!(received.data, payload);
        client.send(b"data", 0, None).unwrap();
        let r = until(&server, || server.recv(2, MSG_PEEK | MSG_TRUNC));
        assert_eq!(r.length, 4);
        assert_eq!(r.data, b"da");
        assert!(r.truncated);
        assert_eq!(server.recv(4, 0).unwrap().data, b"data");
        client.send(b"", 0, None).unwrap();
        assert_eq!(until(&server, || server.recv(0, 0)).length, 0);
        assert_eq!(server.recv(10, 0).err(), Some(NetError(11)));
    }
}
#[test]
fn policy_quota_teardown_and_reused_environment_id() {
    let f = Fabric::new().unwrap();
    let a = net(&f, 2);
    assert!(Network::virtual_network(&f, 2, NetworkMode::Full).is_err());
    let s = socket(&a, false, true);
    assert_eq!(s.bind(parse("10.0.0.3:80")), Err(NetError(99)));
    s.bind(parse("10.0.0.2:80")).unwrap();
    s.listen(1).unwrap();
    let b = Network::virtual_network(&f, 3, NetworkMode::Loopback).unwrap();
    assert_eq!(
        socket(&b, false, true).connect(parse("10.0.0.2:80")),
        Err(NetError(13))
    );
    let off = Network::virtual_network(&f, 4, NetworkMode::Off).unwrap();
    assert!(matches!(off.socket(2, 1, 0), Err(NetError(13))));
    let many: Vec<_> = (0..64).map(|_| socket(&b, false, false)).collect();
    assert!(matches!(b.socket(2, 2, 0), Err(NetError(24))));
    drop(many);
    assert_eq!(b.live_sockets(), 0);
    a.finish();
    assert_eq!(s.send(b"x", 0, None), Err(NetError(107)));
    let anew = net(&f, 2);
    assert_eq!(anew.live_sockets(), 0);
    assert!(f.stats().stack_sockets <= 256);
}
#[test]
fn native_gateway_tcp_and_udp_both_families() {
    for v6 in [false, true] {
        let localhost: IpAddr = if v6 {
            "::1".parse().unwrap()
        } else {
            "127.0.0.1".parse().unwrap()
        };
        let tcp = std::net::TcpListener::bind((localhost, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let thread = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = tcp.accept().unwrap();
            let mut data = Vec::new();
            s.read_to_end(&mut data).unwrap();
            s.write_all(&data).unwrap();
        });
        let f = Fabric::new().unwrap();
        let n = net(&f, 2);
        let vip: IpAddr = if v6 {
            "2001:db8::1".parse().unwrap()
        } else {
            "198.18.0.1".parse().unwrap()
        };
        f.map_host_ip(vip, localhost).unwrap();
        let c = socket(&n, v6, true);
        connect(&c, SocketAddr::new(vip, port));
        let payload = vec![0x5a; 60000];
        let mut offset = 0;
        while offset < payload.len() {
            offset += until(&c, || c.send(&payload[offset..], 0, None));
        }
        c.shutdown(1).unwrap();
        let mut data = Vec::new();
        loop {
            let r = until(&c, || c.recv(65536, 0));
            if r.data.is_empty() {
                break;
            }
            data.extend_from_slice(&r.data);
        }
        assert_eq!(data, payload);
        thread.join().unwrap();
        n.finish();
        assert_eq!(f.stats().native_flows, 0);
        let udp = std::net::UdpSocket::bind((localhost, 0)).unwrap();
        let port = udp.local_addr().unwrap().port();
        let thread = std::thread::spawn(move || {
            let mut data = vec![0; 65535];
            let (n, p) = udp.recv_from(&mut data).unwrap();
            udp.send_to(&data[..n], p).unwrap();
        });
        let n = net(&f, 3);
        let c = socket(&n, v6, false);
        c.connect(SocketAddr::new(vip, port)).unwrap();
        c.send(&payload, 0, None).unwrap();
        assert_eq!(until(&c, || c.recv(65536, 0)).data, payload);
        thread.join().unwrap();
        n.finish();
        assert_eq!(f.stats().native_flows, 0);
    }
}
#[test]
fn dns_internal_a_aaaa_and_refused_connect_error_consumption() {
    let f = Fabric::new().unwrap();
    let n = net(&f, 2);
    let _peer = net(&f, 3);
    let c = socket(&n, false, false);
    c.connect(parse("10.0.0.1:53")).unwrap();
    for (kind, expected) in [
        (1u16, vec![10, 0, 0, 3]),
        (
            28u16,
            "fd00::3"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ),
    ] {
        let mut q = vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'e', b'n', b'v', b'3', 6, b't', b'r',
            b'a', b'm', b'e', b's', 0,
        ];
        q.extend_from_slice(&kind.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        c.send(&q, 0, None).unwrap();
        let r = until(&c, || c.recv(512, 0));
        assert_eq!(&r.data[..2], &[0x12, 0x34]);
        assert_eq!(r.data[7], 1);
        assert!(r.data.ends_with(&expected));
    }
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    f.map_host_ip("198.18.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap())
        .unwrap();
    let c = socket(&n, false, true);
    assert_eq!(
        c.connect(SocketAddr::new("198.18.0.1".parse().unwrap(), port)),
        Err(NetError(115))
    );
    let end = Instant::now() + Duration::from_secs(5);
    while c.connect_complete() == Ok(false) {
        assert!(Instant::now() < end);
        wait(&[(c.clone(), 4)], Duration::from_millis(2)).unwrap();
    }
    assert_eq!(c.get_option(1, 4).unwrap(), 111);
    assert_eq!(c.get_option(1, 4).unwrap(), 0);
}
#[test]
fn tcp_survives_checksum_corruption_and_loss() {
    let f = Fabric::new().unwrap();
    let a = net(&f, 2);
    let b = net(&f, 3);
    let server = socket(&a, false, true);
    server.bind(parse("10.0.0.2:4567")).unwrap();
    server.listen(1).unwrap();
    let c = socket(&b, false, true);
    connect(&c, parse("10.0.0.2:4567"));
    let (s, _) = until(&server, || server.accept());
    f.set_link_faults(7, 11);
    let data: Vec<_> = (0..32000).map(|i| (i % 251) as u8).collect();
    c.send(&data, 0, None).unwrap();
    let mut received = Vec::new();
    while received.len() < data.len() {
        received.extend_from_slice(&until(&s, || s.recv(65536, 0)).data);
    }
    assert_eq!(received, data);
    assert!(f.stats().dropped > 0);
    assert!(f.stats().corrupted > 0);
}
#[test]
fn icmp_echo_both_families_and_dns_over_tcp() {
    let f = Fabric::new().unwrap();
    let n = net(&f, 2);
    let _peer = net(&f, 3);
    for v6 in [false, true] {
        let c = n
            .socket(if v6 { 10 } else { 2 }, 2, if v6 { 58 } else { 1 })
            .unwrap();
        let target = parse(if v6 { "[fd00::3]:0" } else { "10.0.0.3:0" });
        let mut data = vec![if v6 { 128 } else { 8 }, 0, 0, 0, 0, 0, 0, 1];
        data.extend_from_slice(b"echo-data");
        c.send(&data, 0, Some(target)).unwrap();
        let r = until(&c, || c.recv(1024, MSG_PEEK));
        assert_eq!(r.data[0], if v6 { 129 } else { 0 });
        assert_eq!(&r.data[8..], b"echo-data");
        assert_eq!(r.address, Some(target));
        assert_eq!(c.recv(1024, 0).unwrap().data, r.data);
    }
    let c = socket(&n, false, true);
    connect(&c, parse("10.0.0.1:53"));
    let q = vec![
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'e', b'n', b'v', b'3', 6, b't', b'r', b'a', b'm',
        b'e', b's', 0, 0, 1, 0, 1,
    ];
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    c.send(&framed, 0, None).unwrap();
    let reply = until(&c, || c.recv(512, 0));
    assert_eq!(
        u16::from_be_bytes(reply.data[..2].try_into().unwrap()) as usize,
        reply.data.len() - 2
    );
    assert!(reply.data.ends_with(&[10, 0, 0, 3]));
}
#[test]
fn dual_stack_wildcard_and_udp_connected_peer_filter() {
    let f = Fabric::new().unwrap();
    let a = net(&f, 2);
    let b = net(&f, 3);
    let listener = socket(&a, true, true);
    listener.set_option(41, 26, 0).unwrap();
    listener.bind(parse("[::]:4444")).unwrap();
    listener.listen(1).unwrap();
    let c = socket(&b, false, true);
    connect(&c, parse("10.0.0.2:4444"));
    let (_accepted, peer) = until(&listener, || listener.accept());
    assert_eq!(peer.ip(), "::ffff:10.0.0.3".parse::<IpAddr>().unwrap());
    let receiver = socket(&a, false, false);
    receiver.bind(parse("10.0.0.2:6666")).unwrap();
    receiver.connect(parse("10.0.0.3:7777")).unwrap();
    let wrong = socket(&b, false, false);
    wrong.bind(parse("10.0.0.3:7778")).unwrap();
    wrong
        .send(b"wrong", 0, Some(parse("10.0.0.2:6666")))
        .unwrap();
    assert_eq!(receiver.recv(10, 0).err(), Some(NetError(11)));
    let right = socket(&b, false, false);
    right.bind(parse("10.0.0.3:7777")).unwrap();
    right
        .send(b"right", 0, Some(parse("10.0.0.2:6666")))
        .unwrap();
    assert_eq!(receiver.recv(10, 0).unwrap().data, b"right");
}
#[test]
fn namespace_finish_resets_peer_and_preserves_other_namespace() {
    let f = Fabric::new().unwrap();
    let a = net(&f, 2);
    let b = net(&f, 3);
    let listener = socket(&a, false, true);
    listener.bind(parse("10.0.0.2:5555")).unwrap();
    listener.listen(1).unwrap();
    let c = socket(&b, false, true);
    connect(&c, parse("10.0.0.2:5555"));
    let (_s, _) = until(&listener, || listener.accept());
    a.finish();
    assert_eq!(c.recv(1, 0).err(), Some(NetError(104)));
    assert!(c.recv(1, 0).unwrap().data.is_empty());
    let replacement = net(&f, 2);
    let x = socket(&replacement, false, false);
    x.bind(parse("10.0.0.2:5555")).unwrap();
    let y = socket(&b, false, false);
    y.send(b"new namespace", 0, Some(parse("10.0.0.2:5555")))
        .unwrap();
    assert_eq!(x.recv(100, 0).unwrap().data, b"new namespace");
}
#[test]
fn aggregate_stack_quota_rejects_listener_before_partial_allocation() {
    let f = Fabric::new().unwrap();
    let n = net(&f, 2);
    let mut listeners = Vec::new();
    for port in 10000..10007 {
        let s = socket(&n, true, true);
        s.set_option(41, 26, 0).unwrap();
        s.bind(parse(&format!("[::]:{port}"))).unwrap();
        s.listen(8).unwrap();
        listeners.push(s);
    }
    let s = socket(&n, true, true);
    s.set_option(41, 26, 0).unwrap();
    s.bind(parse("[::]:10007")).unwrap();
    let before = f.stats().stack_sockets;
    assert_eq!(s.listen(8), Err(NetError(105)));
    assert_eq!(f.stats().stack_sockets, before);
    assert!(before <= 256);
    drop(listeners);
    s.listen(8).unwrap();
}

#[test]
fn system_resolver_worker_returns_bounded_dns_wire_answer() {
    let f = Fabric::new().unwrap();
    let n = net(&f, 2);
    let c = socket(&n, false, false);
    c.connect(parse("10.0.0.1:53")).unwrap();
    let q = vec![
        0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'1', b'2', b'7', 1, b'0', 1, b'0', 1, b'1',
        0, 0, 1, 0, 1,
    ];
    c.send(&q, 0, None).unwrap();
    let r = until(&c, || c.recv(512, 0));
    assert_eq!(&r.data[..2], &[0xab, 0xcd]);
    assert_eq!(r.data[7], 1);
    assert!(r.data.ends_with(&[127, 0, 0, 1]));
}
