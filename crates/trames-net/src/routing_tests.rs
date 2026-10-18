// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::netdev::{Address, DeviceKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
fn addr(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}
pub(super) fn assign(n: &Network, index: u32, ip: &str, prefix: u8) {
    n.1.graph
        .borrow_mut()
        .address(
            n.namespace_id(),
            index,
            Address {
                ip: ip.parse().unwrap(),
                prefix,
            },
            true,
            false,
        )
        .unwrap();
    n.set_device_up(index, true).unwrap();
}
pub(super) fn pair(root: &Network, n: &Network, name: &[u8], bridge: u32) -> u32 {
    let (a, b) = root
        .1
        .graph
        .borrow_mut()
        .create_veth(root.namespace_id(), name, n.namespace_id(), b"eth0")
        .unwrap();
    root.1
        .graph
        .borrow_mut()
        .change_link(
            root.namespace_id(),
            a,
            None,
            None,
            Some(true),
            Some(bridge),
            None,
        )
        .unwrap();
    n.set_device_up(b, true).unwrap();
    b
}
pub(super) fn bridge(root: &Network, name: &[u8]) -> u32 {
    let i = root
        .1
        .graph
        .borrow_mut()
        .create_bridge(root.namespace_id(), name)
        .unwrap();
    root.set_device_up(i, true).unwrap();
    i
}
#[test]
fn bridge_controls_real_tcp_udp_and_live_link_isolation() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let c = root.isolated().unwrap();
    let ba = bridge(&root, b"br-a");
    let bc = bridge(&root, b"br-c");
    let ai = pair(&root, &a, b"va", ba);
    let bi = pair(&root, &b, b"vb", ba);
    let ci = pair(&root, &c, b"vc", bc);
    // Bind before address assignment; live configuration must update wildcard
    // listeners instead of leaving them restricted to the old loopback set.
    let server = b.socket(2, 1, 0).unwrap();
    server.bind(addr("0.0.0.0", 14001)).unwrap();
    server.listen(2).unwrap();
    let udp = b.socket(2, 2, 0).unwrap();
    udp.bind(addr("0.0.0.0", 14002)).unwrap();
    assign(&a, ai, "192.0.2.10", 24);
    assign(&b, bi, "192.0.2.20", 24);
    assign(&c, ci, "192.0.2.30", 24);
    let client = a.socket(2, 1, 0).unwrap();
    assert_eq!(
        client.connect(addr("192.0.2.20", 14001)),
        Err(NetError(115))
    );
    assert_eq!(client.connect_complete(), Ok(true));
    let (accepted, peer) = server.accept().unwrap();
    assert_eq!(peer.ip(), "192.0.2.10".parse::<IpAddr>().unwrap());
    assert_eq!(client.send(b"actual TCP", 0, None), Ok(10));
    assert_eq!(accepted.recv(30, 0).unwrap().data, b"actual TCP");
    let ping = a.socket(2, 2, 1).unwrap();
    ping.send(&[8, 0, 0, 0, 0, 0, 0, 1], 0, Some(addr("192.0.2.20", 0)))
        .unwrap();
    let pong = ping.recv(32, 0).unwrap();
    assert_eq!(pong.data[0], 0);
    assert_eq!(&pong.data[6..8], &[0, 1]);
    let tx = a.socket(2, 2, 0).unwrap();
    assert_eq!(
        tx.send(b"same bridge", 0, Some(addr("192.0.2.20", 14002))),
        Ok(11)
    );
    assert_eq!(udp.recv(30, 0).unwrap().data, b"same bridge");
    let other = c.socket(2, 2, 0).unwrap();
    assert_eq!(
        other.send(b"isolated", 0, Some(addr("192.0.2.20", 14002))),
        Ok(8)
    );
    assert!(matches!(udp.recv(30, 0), Err(NetError(11))));
    b.set_device_up(bi, false).unwrap();
    tx.send(b"down", 0, Some(addr("192.0.2.20", 14002)))
        .unwrap();
    assert!(matches!(udp.recv(30, 0), Err(NetError(11))));
    b.set_device_up(bi, true).unwrap();
    tx.send(b"up", 0, Some(addr("192.0.2.20", 14002))).unwrap();
    assert_eq!(udp.recv(30, 0).unwrap().data, b"up");
    let host_peer = root
        .1
        .graph
        .borrow()
        .peer_device(
            match b
                .1
                .graph
                .borrow()
                .device(b.namespace_id(), bi)
                .unwrap()
                .kind
            {
                DeviceKind::Veth { peer } => peer,
                _ => unreachable!(),
            },
        )
        .unwrap();
    root.1
        .graph
        .borrow_mut()
        .change_link(
            root.namespace_id(),
            host_peer.index,
            None,
            None,
            None,
            Some(0),
            None,
        )
        .unwrap();
    tx.send(b"detached", 0, Some(addr("192.0.2.20", 14002)))
        .unwrap();
    assert!(matches!(udp.recv(30, 0), Err(NetError(11))));
    assert!(
        a.devices()
            .iter()
            .find(|d| d.index == ai)
            .unwrap()
            .stats
            .tx_packets
            > 0
    );
}
#[test]
fn ipv6_duplicate_ports_and_address_removal_are_namespace_scoped() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"br6");
    let ai = pair(&root, &a, b"p6a", br);
    let bi = pair(&root, &b, b"p6b", br);
    assign(&a, ai, "fd42::a", 64);
    assign(&b, bi, "fd42::b", 64);
    let sa = a.socket(10, 2, 0).unwrap();
    let sb = b.socket(10, 2, 0).unwrap();
    sa.bind(addr("::", 15000)).unwrap();
    sb.bind(addr("::", 15000)).unwrap();
    sa.send(b"ipv6", 0, Some(addr("fd42::b", 15000))).unwrap();
    let p = sb.recv(30, 0).unwrap();
    assert_eq!(p.data, b"ipv6");
    assert_eq!(
        p.address.unwrap().ip(),
        "fd42::a".parse::<IpAddr>().unwrap()
    );
    b.1.graph
        .borrow_mut()
        .address(
            b.namespace_id(),
            bi,
            Address {
                ip: "fd42::b".parse().unwrap(),
                prefix: 64,
            },
            false,
            false,
        )
        .unwrap();
    sa.send(b"gone", 0, Some(addr("fd42::b", 15000))).unwrap();
    assert!(matches!(sb.recv(30, 0), Err(NetError(11))));
    assert_eq!(
        sb.send(b"no route", 0, Some(addr("fd42::a", 15000))),
        Err(NetError(101))
    );
    let unrelated = root.isolated().unwrap();
    assert_eq!(
        unrelated
            .socket(2, 2, 0)
            .unwrap()
            .send(b"x", 0, Some(addr("198.51.100.1", 1))),
        Err(NetError(101))
    );
    assert_eq!(
        unrelated.socket(2, 2, 0).unwrap().bind(addr("10.0.0.2", 1)),
        Err(NetError(99))
    );
}
fn attr(out: &mut Vec<u8>, k: u16, v: &[u8]) {
    netlink::attr(out, k, v)
}
fn wire(
    s: &Rc<Socket>,
    kind: u16,
    flags: u16,
    payload: &[u8],
    admin: bool,
    fd: Option<&Network>,
) -> i32 {
    s.send_bytes_with_namespace(
        &netlink::message(kind, flags | 5, 123, 0, payload),
        0,
        None,
        admin,
        &|n| {
            if n == 99 {
                fd.cloned().ok_or(NetError(9))
            } else {
                Err(NetError(9))
            }
        },
    )
    .unwrap();
    let r = s.recv(65536, 0).unwrap().data;
    assert_eq!(&r[4..6], &2u16.to_le_bytes());
    i32::from_le_bytes(r[16..20].try_into().unwrap())
}
#[test]
fn netlink_pair_move_and_rejection_are_atomic_and_notify_subscribers() {
    let root = Network::new(NetworkMode::Full);
    let n = root.isolated().unwrap();
    let s = root.socket(16, 3, 0).unwrap();
    let monitor = root.socket(16, 3, 0).unwrap();
    monitor
        .bind_bytes(&{
            let mut a = netlink::address(0);
            a[8..12].copy_from_slice(&1u32.to_le_bytes());
            a
        })
        .unwrap();
    let mut data = vec![0; 16];
    attr(&mut data, 3, b"edge0\0");
    let mut info = vec![];
    attr(&mut info, 1, b"veth\0");
    let mut peer = vec![0; 16];
    attr(&mut peer, 3, b"eth0\0");
    attr(&mut peer, 28, &99u32.to_le_bytes());
    let mut nested = vec![];
    attr(&mut nested, 1, &peer);
    attr(&mut info, 2, &nested);
    attr(&mut data, 18, &info);
    assert_eq!(wire(&s, 16, 0x600, &data, false, Some(&n)), -1);
    assert!(root.devices().iter().all(|d| d.name != b"edge0"));
    assert_eq!(wire(&s, 16, 0x600, &data, true, None), -9);
    assert!(root.devices().iter().all(|d| d.name != b"edge0"));
    assert_eq!(wire(&s, 16, 0x600, &data, true, Some(&n)), 0);
    let notification = monitor.recv(65536, 0).unwrap().data;
    assert_eq!(&notification[8..16], &[0; 8]);
    assert!(notification.windows(6).any(|v| v == b"edge0\0"));
    let edge = root
        .devices()
        .into_iter()
        .find(|d| d.name == b"edge0")
        .unwrap();
    let peer = n.devices().into_iter().find(|d| d.name == b"eth0").unwrap();
    let mut change = vec![0; 16];
    change[4..8].copy_from_slice(&edge.index.to_le_bytes());
    attr(&mut change, 3, b"moved0\0");
    attr(&mut change, 28, &99u32.to_le_bytes());
    assert_eq!(wire(&s, 16, 0, &change, true, Some(&n)), 0);
    assert!(root.devices().iter().all(|d| d.index != edge.index));
    assert!(n.devices().iter().any(|d| d.name == b"moved0"));
    assert_eq!(wire(&s, 16, 0x600, &data, true, Some(&n)), -17);
    assert!(root.devices().iter().all(|d| d.name != b"edge0"));
    let ns = n.namespace_id();
    let mut g = n.1.graph.borrow_mut();
    g.remove_link(ns, peer.index).unwrap();
    assert!(g.device(ns, edge.index).is_err());
}
#[test]
fn routes_require_configuration_and_namespace_teardown_removes_veth_peer() {
    let root = Network::new(NetworkMode::Full);
    let n = root.isolated().unwrap();
    let br = bridge(&root, b"br0");
    let i = pair(&root, &n, b"life0", br);
    assign(&n, i, "172.23.0.2", 24);
    assert_eq!(
        n.1.graph
            .borrow()
            .source(n.namespace_id(), "203.0.113.1".parse().unwrap()),
        Err(NetError(101))
    );
    let route = netdev::Route {
        destination: Address {
            ip: Ipv4Addr::UNSPECIFIED.into(),
            prefix: 0,
        },
        device: i,
        gateway: Some("172.23.0.1".parse().unwrap()),
        metric: 10,
        protocol: 3,
    };
    n.1.graph
        .borrow_mut()
        .route(n.namespace_id(), route, true, false, false)
        .unwrap();
    assert_eq!(
        n.1.graph
            .borrow()
            .source(n.namespace_id(), "203.0.113.1".parse().unwrap())
            .unwrap()
            .2,
        route.gateway
    );
    let peer = match n.devices().into_iter().find(|d| d.index == i).unwrap().kind {
        DeviceKind::Veth { peer } => peer,
        _ => unreachable!(),
    };
    let retained = n.socket(2, 2, 0).unwrap();
    drop(n);
    assert!(root.devices().iter().any(|d| d.index == peer));
    drop(retained);
    assert!(root.devices().iter().all(|d| d.index != peer));
}
#[test]
fn explicit_static_routes_work_and_teardown_notifies_without_enabling_host_egress() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"br-static");
    let ai = pair(&root, &a, b"sa", br);
    let bi = pair(&root, &b, b"sb", br);
    assign(&a, ai, "192.0.2.1", 32);
    assign(&b, bi, "198.51.100.2", 32);
    let client = a.socket(2, 2, 0).unwrap();
    let server = b.socket(2, 2, 0).unwrap();
    server.bind(addr("0.0.0.0", 18000)).unwrap();
    assert_eq!(
        client.send(b"x", 0, Some(addr("198.51.100.2", 18000))),
        Err(NetError(101))
    );
    let route = netdev::Route {
        destination: Address {
            ip: "198.51.100.2".parse().unwrap(),
            prefix: 32,
        },
        device: ai,
        gateway: None,
        metric: 10,
        protocol: 3,
    };
    a.1.graph
        .borrow_mut()
        .route(a.namespace_id(), route, true, false, false)
        .unwrap();
    client
        .send(b"static", 0, Some(addr("198.51.100.2", 18000)))
        .unwrap();
    assert_eq!(server.recv(30, 0).unwrap().data, b"static");
    a.1.graph
        .borrow_mut()
        .route(a.namespace_id(), route, false, false, false)
        .unwrap();
    assert_eq!(
        client.send(b"x", 0, Some(addr("198.51.100.2", 18000))),
        Err(NetError(101))
    );
    let monitor = root.socket(16, 3, 0).unwrap();
    let mut nl = netlink::address(0);
    nl[8..12].copy_from_slice(&1u32.to_le_bytes());
    monitor.bind_bytes(&nl).unwrap();
    let peer = match b.devices().iter().find(|d| d.index == bi).unwrap().kind {
        DeviceKind::Veth { peer } => peer,
        _ => unreachable!(),
    };
    drop(server);
    drop(b);
    let notification = monitor.recv(65536, 0).unwrap().data;
    assert_eq!(&notification[4..6], &17u16.to_le_bytes());
    assert_eq!(&notification[20..24], &peer.to_le_bytes());
    let disabled = Network::new(NetworkMode::Loopback);
    let private = disabled.isolated().unwrap();
    let br = bridge(&disabled, b"restricted");
    let i = pair(&disabled, &private, b"restricted-p", br);
    assign(&private, i, "192.0.2.99", 24);
    assert_eq!(
        private
            .socket(2, 2, 0)
            .unwrap()
            .send(b"x", 0, Some(addr("192.0.2.1", 18000))),
        Err(NetError(13))
    );
}
#[test]
fn an_old_netlink_fd_keeps_the_protocol_stack_alive_until_last_close() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"br-pin");
    let ai = pair(&root, &a, b"pin-a", br);
    let bi = pair(&root, &b, b"pin-b", br);
    assign(&a, ai, "192.0.2.41", 24);
    assign(&b, bi, "192.0.2.42", 24);
    let netlink_only = b.socket(16, 3, 0).unwrap();
    drop(b);
    let ping = a.socket(2, 2, 1).unwrap();
    ping.send(&[8, 0, 0, 0, 0, 0, 0, 1], 0, Some(addr("192.0.2.42", 0)))
        .unwrap();
    assert_eq!(ping.recv(32, 0).unwrap().data[0], 0);
    drop(netlink_only);
    assert!(root.devices().iter().all(|d| d.name != b"pin-b"));
}
