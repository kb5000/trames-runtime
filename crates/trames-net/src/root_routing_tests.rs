// SPDX-License-Identifier: GPL-3.0-or-later
use super::routing_tests::{assign, bridge, pair};
use super::*;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
fn addr(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}
#[test]
fn root_wildcard_accepts_native_and_guest_and_guest_can_use_bridge_service() {
    let root = Network::new(NetworkMode::Full);
    let child = root.isolated().unwrap();
    let server = root.socket(2, 1, 0).unwrap();
    server.bind(addr("0.0.0.0", 0)).unwrap();
    server.listen(3).unwrap();
    let port = server.local_addr().unwrap().port();
    let br = bridge(&root, b"host-bridge");
    assign(&root, br, "172.29.0.1", 24);
    let ci = pair(&root, &child, b"host-peer", br);
    assign(&child, ci, "172.29.0.2", 24);
    let client = child.socket(2, 1, 0).unwrap();
    assert_eq!(client.connect(addr("172.29.0.1", port)), Err(NetError(115)));
    assert_eq!(client.connect_complete(), Ok(true));
    let (accepted, peer) = server.accept().unwrap();
    assert_eq!(peer.ip(), "172.29.0.2".parse::<std::net::IpAddr>().unwrap());
    client.send(b"guest to root", 0, None).unwrap();
    assert_eq!(accepted.recv(64, 0).unwrap().data, b"guest to root");
    accepted.send(b"bridge service", 0, None).unwrap();
    assert_eq!(client.recv(64, 0).unwrap().data, b"bridge service");
    let _host = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    let (_, host_peer) = server.accept().unwrap();
    assert!(host_peer.ip().is_loopback());
}
#[test]
fn root_reaches_private_tcp_udp_without_routing_regular_sockets_through_the_stack() {
    let root = Network::new(NetworkMode::Full);
    let child = root.isolated().unwrap();
    let br = bridge(&root, b"br-connect");
    assign(&root, br, "172.30.0.1", 24);
    let ci = pair(&root, &child, b"connect-peer", br);
    assign(&child, ci, "172.30.0.2", 24);
    let listener = child.socket(2, 1, 0).unwrap();
    listener.bind(addr("0.0.0.0", 18003)).unwrap();
    listener.listen(2).unwrap();
    let client = root.socket(2, 1, 0).unwrap();
    assert_eq!(
        client.connect(addr("172.30.0.2", 18003)),
        Err(NetError(115))
    );
    assert_eq!(client.connect_complete(), Ok(true));
    let (accepted, peer) = listener.accept().unwrap();
    assert_eq!(peer.ip(), "172.30.0.1".parse::<std::net::IpAddr>().unwrap());
    client.send(b"root to guest", 0, None).unwrap();
    assert_eq!(accepted.recv(64, 0).unwrap().data, b"root to guest");
    let recv = child.socket(2, 2, 0).unwrap();
    recv.bind(addr("0.0.0.0", 18004)).unwrap();
    let sender = root.socket(2, 2, 0).unwrap();
    sender
        .send(b"udp", 0, Some(addr("172.30.0.2", 18004)))
        .unwrap();
    let received = recv.recv(64, 0).unwrap();
    assert_eq!(received.data, b"udp");
    recv.send(b"reply", 0, received.address).unwrap();
    assert_eq!(sender.recv(64, 0).unwrap().data, b"reply");
    let ordinary = root.socket(2, 2, 0).unwrap();
    assert!(matches!(&ordinary.0,SocketBackend::Hybrid(s) if s.waiters(1).1.is_none()));
}
#[test]
fn root_bind_conflict_rolls_back_native_half_and_preserves_socket_quota() {
    let root = Network::new(NetworkMode::Full);
    let br = bridge(&root, b"br-bind");
    assign(&root, br, "172.31.0.1", 24);
    let private = root.socket(2, 1, 0).unwrap();
    private.bind(addr("172.31.0.1", 0)).unwrap();
    let port = private.local_addr().unwrap().port();
    let wildcard = root.socket(2, 1, 0).unwrap();
    assert_eq!(wildcard.bind(addr("0.0.0.0", port)), Err(NetError(98)));
    assert_eq!(wildcard.local_addr().unwrap().port(), 0);
    wildcard.bind(addr("127.0.0.1", 0)).unwrap();
    let baseline = root.live_sockets();
    let mut sockets = vec![];
    for _ in baseline..MAX_SOCKETS {
        sockets.push(root.socket(16, 3, 0).unwrap());
    }
    assert_eq!(root.live_sockets(), MAX_SOCKETS);
    assert!(matches!(root.socket(2, 2, 0), Err(NetError(24))));
    drop(sockets);
    assert_eq!(root.live_sockets(), baseline);
}
fn default_route(n: &Network, device: u32, gateway: &str) {
    let gateway: std::net::IpAddr = gateway.parse().unwrap();
    let r = netdev::Route {
        destination: netdev::Address {
            ip: if gateway.is_ipv4() {
                "0.0.0.0".parse().unwrap()
            } else {
                "::".parse().unwrap()
            },
            prefix: 0,
        },
        device,
        gateway: Some(gateway),
        metric: 0,
        protocol: 3,
    };
    n.1.graph
        .borrow_mut()
        .route(n.namespace_id(), r, true, false, false)
        .unwrap();
}
#[test]
fn l3_forwarding_is_per_family_and_hop_limit_and_routes_really_apply() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let ba = bridge(&root, b"route-a");
    let bb = bridge(&root, b"route-b");
    assign(&root, ba, "172.24.0.1", 24);
    assign(&root, bb, "172.25.0.1", 24);
    assign(&root, ba, "fd24::1", 64);
    assign(&root, bb, "fd25::1", 64);
    let ai = pair(&root, &a, b"route-pa", ba);
    let bi = pair(&root, &b, b"route-pb", bb);
    assign(&a, ai, "172.24.0.2", 24);
    assign(&b, bi, "172.25.0.2", 24);
    assign(&a, ai, "fd24::2", 64);
    assign(&b, bi, "fd25::2", 64);
    default_route(&a, ai, "172.24.0.1");
    default_route(&b, bi, "172.25.0.1");
    default_route(&a, ai, "fd24::1");
    default_route(&b, bi, "fd25::1");
    for (af, ip, level, option) in [(2, "172.25.0.2", 0, 2), (10, "fd25::2", 41, 16)] {
        let family6 = af == 10;
        let server = b.socket(af, 2, 0).unwrap();
        server
            .bind(addr(if family6 { "::" } else { "0.0.0.0" }, 18200))
            .unwrap();
        let client = a.socket(af, 2, 0).unwrap();
        client.send(b"disabled", 0, Some(addr(ip, 18200))).unwrap();
        assert!(matches!(server.recv(64, 0), Err(NetError(11))));
        root.set_forwarding(family6, true);
        assert!(!a.forwarding(family6));
        client.send(b"routed", 0, Some(addr(ip, 18200))).unwrap();
        let message = server.recv(64, 0).unwrap();
        assert_eq!(message.data, b"routed");
        server.send(b"response", 0, message.address).unwrap();
        assert_eq!(client.recv(64, 0).unwrap().data, b"response");
        client.set_option(level, option, 1).unwrap();
        client.send(b"ttl1", 0, Some(addr(ip, 18200))).unwrap();
        assert!(matches!(server.recv(64, 0), Err(NetError(11))));
        client.set_option(level, option, 2).unwrap();
        client.send(b"ttl2", 0, Some(addr(ip, 18200))).unwrap();
        assert_eq!(server.recv(64, 0).unwrap().data, b"ttl2");
        root.set_forwarding(family6, false);
        client
            .send(b"disabled again", 0, Some(addr(ip, 18200)))
            .unwrap();
        assert!(matches!(server.recv(64, 0), Err(NetError(11))));
        // Root selects the address of the correct bridge, not its first UDP
        // handle. Ordinary native sockets retain their separate path.
        let host = root.socket(af, 2, 0).unwrap();
        host.send(b"root", 0, Some(addr(ip, 18200))).unwrap();
        let message = server.recv(64, 0).unwrap();
        assert_eq!(
            message.address.unwrap().ip(),
            if family6 { "fd25::1" } else { "172.25.0.1" }
                .parse::<std::net::IpAddr>()
                .unwrap()
        );
    }
    root.set_forwarding(false, true);
    let listener = b.socket(2, 1, 0).unwrap();
    listener.bind(addr("0.0.0.0", 18201)).unwrap();
    listener.listen(2).unwrap();
    let client = a.socket(2, 1, 0).unwrap();
    assert_eq!(
        client.connect(addr("172.25.0.2", 18201)),
        Err(NetError(115))
    );
    assert_eq!(client.connect_complete(), Ok(true));
    let (accepted, _) = listener.accept().unwrap();
    client.send(b"routed TCP", 0, None).unwrap();
    assert_eq!(accepted.recv(64, 0).unwrap().data, b"routed TCP");
    let external = a.socket(2, 2, 0).unwrap();
    external
        .send(b"no implicit NAT", 0, Some(addr("198.51.100.9", 9)))
        .unwrap();
    assert!(a
        .1
        .graph
        .borrow()
        .target(a.namespace_id(), "198.51.100.9".parse().unwrap())
        .is_none());
}
#[test]
fn unconnected_root_udp_keeps_its_port_when_switching_between_native_and_guest_routes() {
    let root = Network::new(NetworkMode::Full);
    let child = root.isolated().unwrap();
    let br = bridge(&root, b"br-mixed");
    assign(&root, br, "172.28.0.1", 24);
    let ci = pair(&root, &child, b"mixed-peer", br);
    assign(&child, ci, "172.28.0.2", 24);
    let host = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let guest = child.socket(2, 2, 0).unwrap();
    guest.bind(addr("0.0.0.0", 18300)).unwrap();
    let sender = root.socket(2, 2, 0).unwrap();
    sender
        .send(b"native", 0, Some(host.local_addr().unwrap()))
        .unwrap();
    let mut bytes = [0; 32];
    let (_, native_peer) = host.recv_from(&mut bytes).unwrap();
    sender
        .send(b"guest", 0, Some(addr("172.28.0.2", 18300)))
        .unwrap();
    let received = guest.recv(32, 0).unwrap();
    assert_eq!(received.data, b"guest");
    assert_eq!(received.address.unwrap().port(), native_peer.port());
    guest.send(b"reply", 0, received.address).unwrap();
    assert_eq!(sender.recv(32, 0).unwrap().data, b"reply");
    sender
        .send(b"back", 0, Some(host.local_addr().unwrap()))
        .unwrap();
    let (n, peer) = host.recv_from(&mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"back");
    assert_eq!(peer.port(), native_peer.port());
}
#[test]
fn rtm_setlink_updates_guest_devices_and_cannot_change_native_eth0() {
    let root = Network::new(NetworkMode::Full);
    let br = bridge(&root, b"br-setlink");
    let nl = root.socket(16, 3, 0).unwrap();
    for (index, up, expected) in [(br, false, 0i32), (br, true, 0), (2, false, -95)] {
        let mut data = vec![0; 16];
        data[4..8].copy_from_slice(&index.to_le_bytes());
        data[8..12].copy_from_slice(&u32::from(up).to_le_bytes());
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        nl.send_bytes_authorized(&netlink::message(19, 5, 1, 0, &data), 0, None, true)
            .unwrap();
        let reply = nl.recv(65536, 0).unwrap();
        assert_eq!(
            i32::from_le_bytes(reply.data[16..20].try_into().unwrap()),
            expected
        );
        if index == br {
            assert_eq!(
                root.devices().iter().find(|d| d.index == index).unwrap().up,
                up
            );
        }
    }
}
