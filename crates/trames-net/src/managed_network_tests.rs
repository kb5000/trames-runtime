// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::netdev::{Address, PolicyRoute, Route, Rule};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}
fn configured() -> Network {
    let n = Network::managed_uplink(NetworkMode::Outbound).unwrap();
    n.set_device_ipv4(2, Some("10.0.0.2".parse().unwrap()), Some(24))
        .unwrap();
    let id = n.namespace_id();
    n.1.graph
        .write()
        .unwrap()
        .policy_route(
            id,
            1002,
            PolicyRoute {
                route: Route {
                    onlink: false,
                    destination: Address {
                        ip: ip("0.0.0.0"),
                        prefix: 0,
                    },
                    device: 2,
                    gateway: Some(ip("10.0.0.1")),
                    metric: 0,
                    protocol: 3,
                },
                kind: 1,
            },
            true,
            false,
            true,
        )
        .unwrap();
    rule(&n, 10000, 1, 1002, 0x10064, 0x1ffff, None);
    rule(&n, 29000, 1, 1002, 0, 0xffff, None);
    rule(&n, 32000, 7, 0, 0, 0, None);
    n
}
fn rule(
    n: &Network,
    priority: u32,
    action: u8,
    table: u32,
    mark: u32,
    mask: u32,
    uid: Option<[u32; 2]>,
) {
    n.1.graph
        .write()
        .unwrap()
        .policy_rule(
            n.namespace_id(),
            Rule {
                family: 2,
                priority,
                table,
                action,
                mark,
                mask,
                input: Some(b"lo".to_vec()),
                output: None,
                uid,
                invert: false,
            },
            true,
            true,
            true,
        )
        .unwrap();
}
#[test]
fn managed_policy_controls_real_udp_and_route_probe_without_host_changes() {
    let n = configured();
    let host = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    host.set_nonblocking(true).unwrap();
    let remote: SocketAddr =
        SocketAddr::new(ip("198.51.100.17"), host.local_addr().unwrap().port());
    n.map_host_ip(remote.ip(), ip("127.0.0.1")).unwrap();
    let s = n.socket(2, 2, 0).unwrap();
    s.set_owner_uid(10001);
    s.set_option(1, 36, 0x10064).unwrap();
    s.connect(SocketAddr::new(remote.ip(), 0)).unwrap();
    assert_eq!(s.local_addr().unwrap().ip(), ip("10.0.0.2"));
    assert_eq!(s.peer_addr(), Err(NetError(107)));
    s.connect(remote).unwrap();
    s.send(b"original-marked-socket", 0, None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut data = [0; 64];
    let (len, peer) = loop {
        match host.recv_from(&mut data) {
            Ok(v) => break v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "managed uplink did not deliver payload"
                );
                wait(&[(s.clone(), 1)], Duration::from_millis(1)).unwrap();
            }
            Err(e) => panic!("{e}"),
        }
    };
    assert_eq!(&data[..len], b"original-marked-socket");
    host.send_to(b"native-reply", peer).unwrap();
    let got = loop {
        match s.recv(64, 0) {
            Ok(v) => break v,
            Err(NetError(11)) => {
                assert!(Instant::now() < deadline);
                wait(&[(s.clone(), 1)], Duration::from_millis(1)).unwrap();
            }
            Err(e) => panic!("{e}"),
        }
    };
    assert_eq!(got.data, b"native-reply");
    s.set_option(1, 36, 77).unwrap();
    assert_eq!(s.send(b"blocked", 0, None), Err(NetError(101)));
    s.set_option(1, 36, 0x10064).unwrap();
    rule(&n, 9000, 8, 0, 0, 0, Some([10001, 10001]));
    assert_eq!(s.send(b"uid-prohibited", 0, None), Err(NetError(13)));
    assert!(matches!(host.recv_from(&mut data),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
    let native = Network::new(NetworkMode::Outbound);
    assert!(native.devices().iter().any(|d| d.index == 2));
    assert_eq!(
        native.set_device_ipv4(2, Some("10.0.0.9".parse().unwrap()), Some(24)),
        Err(NetError(95))
    );
}
#[test]
fn ipv6_disable_retires_addresses_and_tables_and_secret_is_namespace_owned() {
    let n = configured();
    let other = configured();
    let id = n.namespace_id();
    assert_eq!(n.stable_secret(2), Err(NetError(5)));
    let secret = "fdaa::1".parse().unwrap();
    n.set_stable_secret(2, secret).unwrap();
    assert_eq!(n.stable_secret(2), Ok(secret));
    assert_eq!(n.ipv6_knob(2, 3), Ok(2));
    assert_eq!(other.stable_secret(2), Err(NetError(5)));
    assert_eq!(n.set_stable_secret(0, secret), Err(NetError(5)));
    let a = Address {
        ip: ip("fd00::2"),
        prefix: 64,
    };
    {
        let mut g = n.1.graph.write().unwrap();
        g.address(id, 2, a, true, false).unwrap();
        g.policy_route(
            id,
            1002,
            PolicyRoute {
                route: Route {
                    onlink: false,
                    destination: Address {
                        ip: ip("::"),
                        prefix: 0,
                    },
                    device: 2,
                    gateway: None,
                    metric: 0,
                    protocol: 3,
                },
                kind: 1,
            },
            true,
            false,
            true,
        )
        .unwrap();
    }
    n.set_ipv6_knob(2, 2, 1).unwrap();
    let mut g = n.1.graph.write().unwrap();
    assert!(!g.device(id, 2).unwrap().addresses.contains(&a));
    assert!(!g
        .policy_routes(id)
        .iter()
        .any(|(_, r)| r.route.destination.ip.is_ipv6() && r.route.device == 2));
    assert_eq!(g.address(id, 2, a, true, false), Err(NetError(13)));
    drop(g);
    n.set_ipv6_knob(2, 2, 0).unwrap();
    n.1.graph
        .write()
        .unwrap()
        .address(id, 2, a, true, false)
        .unwrap();
    assert_eq!(n.set_ipv6_knob(2, 2, 4), Err(NetError(22)));
}
#[test]
fn link_down_obeys_namespace_and_interface_ipv6_retention() {
    for (all, iface, retained) in [(0, 0, false), (0, 1, true), (-1, 1, false), (1, -1, true)] {
        let n = configured();
        let id = n.namespace_id();
        n.set_device_up(2, true).unwrap();
        n.set_ipv6_knob(0, 4, all).unwrap();
        n.set_ipv6_knob(2, 4, iface).unwrap();
        let global = Address {
            ip: ip("fd00::27"),
            prefix: 64,
        };
        let local = Address {
            ip: ip("fe80::27"),
            prefix: 64,
        };
        for a in [global, local] {
            n.1.graph
                .write()
                .unwrap()
                .address(id, 2, a, true, false)
                .unwrap();
        }
        n.set_device_up(2, false).unwrap();
        let addresses = n
            .devices()
            .into_iter()
            .find(|d| d.index == 2)
            .unwrap()
            .addresses;
        assert!(addresses.iter().any(|a| a.ip == ip("10.0.0.2")));
        assert_eq!(addresses.contains(&global), retained);
        assert!(!addresses.contains(&local));
    }
}

#[test]
fn device_binding_filters_local_delivery_and_checks_rebinding_authority() {
    let fabric = Fabric::new().unwrap();
    let net = Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
    for kind in [1, 2] {
        let uplink = net.socket(2, kind, 0).unwrap();
        let local = net.socket(2, kind, 0).unwrap();
        assert!(uplink.bound_device_name().unwrap().is_empty());
        uplink.set_bound_device(b"eth0", false).unwrap();
        assert_eq!(uplink.set_bound_device(b"", false), Err(NetError(1)));
        assert_eq!(uplink.bound_device_name().unwrap(), b"eth0\0");
        local.set_bound_device(b"lo", false).unwrap();
        uplink.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = uplink.local_addr().unwrap();
        local.bind(address).unwrap();
        let sender = net.socket(2, kind, 0).unwrap();
        if kind == 1 {
            uplink.listen(1).unwrap();
            local.listen(1).unwrap();
            assert_eq!(sender.connect(address), Err(NetError(115)));
            assert!(sender.connect_complete().unwrap());
            let _peer = local.accept().unwrap();
            assert!(matches!(uplink.accept(), Err(NetError(11))));
        } else {
            sender.send(b"local", 0, Some(address)).unwrap();
            assert_eq!(local.recv(16, 0).unwrap().data, b"local");
            assert_eq!(uplink.poll(1).unwrap() & 1, 0);
        }
        uplink.set_bound_device(b"", true).unwrap();
        assert!(uplink.bound_device_name().unwrap().is_empty());
    }
}

#[test]
fn udp_destination_and_packet_info_switch_independently() {
    let fabric = Fabric::new().unwrap();
    for network in [
        Network::new(NetworkMode::Outbound),
        Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap(),
    ] {
        for (family, level, original, info, any, loopback) in [
            (2, 0, 20, 8, "0.0.0.0", "127.0.0.1"),
            (10, 41, 74, 49, "::", "::1"),
        ] {
            let receiver = network.socket(family, 2, 0).unwrap();
            receiver.bind(SocketAddr::new(ip(any), 0)).unwrap();
            let dest = SocketAddr::new(ip(loopback), receiver.local_addr().unwrap().port());
            let sender = network.socket(family, 2, 0).unwrap();
            for (want_original, want_info) in
                [(true, false), (true, true), (false, true), (false, false)]
            {
                receiver
                    .set_option(level, info, i32::from(want_info))
                    .unwrap();
                receiver
                    .set_option(level, original, i32::from(want_original))
                    .unwrap();
                sender.send(b"udp", 0, Some(dest)).unwrap();
                for flags in [2, 0] {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let packet = loop {
                        match receiver.recv(3, flags) {
                            Ok(packet) => break packet,
                            Err(NetError(11)) if Instant::now() < deadline => {
                                wait(&[(receiver.clone(), 1)], Duration::from_millis(5)).unwrap();
                            }
                            Err(e) => panic!("recv {dest}, flags={flags}, original={want_original}, info={want_info}: {e:?}"),
                        }
                    };
                    assert_eq!(packet.data, b"udp");
                    assert_eq!(
                        packet.ip.original_destination,
                        want_original.then_some(dest)
                    );
                    assert_eq!(
                        packet.packet_info.map(|p| p.address),
                        want_info.then_some(dest.ip())
                    );
                }
            }
        }
    }
}

#[test]
fn original_netd_zero_address_request_is_a_noop_and_dumps_accept_legacy_padding() {
    let n = Network::managed_uplink(NetworkMode::Outbound).unwrap();
    let nl = n.socket(16, 3, 0).unwrap();
    let mut data = vec![2, 0, 0, 0];
    data.extend_from_slice(&2u32.to_le_bytes());
    for kind in [2u16, 4] {
        data.extend_from_slice(&8u16.to_le_bytes());
        data.extend_from_slice(&kind.to_le_bytes());
        data.extend_from_slice(&[0; 4]);
    }
    nl.send_bytes_authorized(&netlink::message(20, 5, 1, 0, &data), 0, None, true)
        .unwrap();
    assert_eq!(
        i32::from_le_bytes(nl.recv(4096, 0).unwrap().data[16..20].try_into().unwrap()),
        0
    );
    assert!(n
        .devices()
        .iter()
        .find(|d| d.index == 2)
        .unwrap()
        .addresses
        .is_empty());
    for kind in [22, 26, 34] {
        let mut data = vec![0; 32];
        data[1] = 0xff; // historical non-strict callers leave unused request tail.
        nl.send_bytes(&netlink::message(kind, 0x301, 2, 0, &data), 0, None)
            .unwrap();
        let reply = nl.recv(65536, 0).unwrap();
        assert_ne!(
            u16::from_le_bytes(reply.data[4..6].try_into().unwrap()),
            2,
            "legacy dump rejected: {kind}"
        );
    }
    n.set_device_ipv4(2, Some("10.0.0.2".parse().unwrap()), None)
        .unwrap();
    assert!(n
        .devices()
        .iter()
        .find(|d| d.index == 2)
        .unwrap()
        .addresses
        .iter()
        .any(|a| a.prefix == 8));
    n.set_device_ipv4(2, None, Some(24)).unwrap();
    n.set_device_ipv4(2, Some("0.0.0.0".parse().unwrap()), None)
        .unwrap();
    assert!(n
        .devices()
        .iter()
        .find(|d| d.index == 2)
        .unwrap()
        .addresses
        .is_empty());
}

#[test]
fn managed_dns_uses_real_existing_gateway_resolver_and_return_route() {
    let n = configured();
    let s = n.socket(2, 2, 0).unwrap();
    s.set_option(1, 36, 0xf0064).unwrap();
    s.connect("10.0.0.1:53".parse().unwrap()).unwrap();
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(b"\x07gateway\x06trames\x00\x00\x01\x00\x01");
    s.send(&q, 0, None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let r = loop {
        match s.recv(512, 0) {
            Ok(v) => break v,
            Err(NetError(11)) => {
                assert!(Instant::now() < deadline);
                wait(&[(s.clone(), 1)], Duration::from_millis(1)).unwrap();
            }
            Err(e) => panic!("{e}"),
        }
    };
    assert_eq!(&r.data[..2], &[0x12, 0x34]);
    assert_eq!(r.data[3] & 15, 0);
    assert_eq!(r.data[7], 1);
    assert_eq!(&r.data[r.data.len() - 4..], &[10, 0, 0, 1]);
}

#[test]
fn native_linux_netd_request_reference_and_route_results_match() {
    let n = Network::managed_uplink(NetworkMode::Outbound).unwrap();
    let nl = n.socket(16, 3, 0).unwrap();
    for row in include_str!("../../../tests/fixtures/managed-network-linux-reference.txt").lines() {
        let mut parts = row.split_whitespace();
        let label = parts.next().unwrap();
        let hex = parts.next().unwrap();
        let status = parts.next().unwrap().parse::<i32>().unwrap();
        let wire = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        nl.send_bytes_authorized(&wire, 0, None, true).unwrap();
        let reply = nl.recv(4096, 0).unwrap();
        assert_eq!(
            i32::from_le_bytes(reply.data[16..20].try_into().unwrap()),
            status,
            "{label}"
        );
    }
    for (mark, expected) in [(0x10064, Ok(())), (0, Ok(())), (77, Err(NetError(101)))] {
        let s = n.socket(2, 2, 0).unwrap();
        s.set_owner_uid(10001);
        s.set_option(1, 36, mark).unwrap();
        assert_eq!(s.connect("198.51.100.17:0".parse().unwrap()), expected);
    }
    let s = n.socket(2, 2, 0).unwrap();
    s.set_owner_uid(10001);
    s.initialize_inode_owner(10001, 10001);
    s.chown(10005, u32::MAX, |_| Ok(())).unwrap();
    assert_eq!(
        s.connect("198.51.100.17:0".parse().unwrap()),
        Err(NetError(13))
    );
}
#[test]
fn managed_marked_tcp_delivers_original_stream_and_live_prohibit_blocks_writes() {
    use std::io::{Read, Write};
    let n = configured();
    let host = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    host.set_nonblocking(true).unwrap();
    let remote = SocketAddr::new(ip("198.51.100.18"), host.local_addr().unwrap().port());
    n.map_host_ip(remote.ip(), ip("127.0.0.1")).unwrap();
    let s = n.socket(2, 1, 0).unwrap();
    s.set_owner_uid(10001);
    s.set_option(1, 36, 0x10064).unwrap();
    assert_eq!(s.connect(remote), Err(NetError(115)));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut peer = loop {
        wait(&[(s.clone(), 5)], Duration::from_millis(1)).unwrap();
        match host.accept() {
            Ok((p, _)) => break p,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline)
            }
            Err(e) => panic!("{e}"),
        }
    };
    while !s.connect_complete().unwrap() {
        assert!(Instant::now() < deadline);
        wait(&[(s.clone(), 5)], Duration::from_millis(1)).unwrap();
    }
    peer.set_nonblocking(true).unwrap();
    s.send(b"tcp-payload", 0, None).unwrap();
    let mut bytes = [0; 32];
    let len = loop {
        wait(&[(s.clone(), 5)], Duration::from_millis(1)).unwrap();
        match peer.read(&mut bytes) {
            Ok(n) => break n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline)
            }
            Err(e) => panic!("{e}"),
        }
    };
    assert_eq!(&bytes[..len], b"tcp-payload");
    peer.write_all(b"tcp-reply").unwrap();
    let r = loop {
        match s.recv(32, 0) {
            Ok(v) => break v,
            Err(NetError(11)) => {
                assert!(Instant::now() < deadline);
                wait(&[(s.clone(), 1)], Duration::from_millis(1)).unwrap();
            }
            Err(e) => panic!("{e}"),
        }
    };
    assert_eq!(r.data, b"tcp-reply");
    rule(&n, 9000, 8, 0, 0, 0, Some([10001, 10001]));
    assert_eq!(s.send(b"prohibited", 0, None), Err(NetError(13)));
}

#[test]
fn loopback_aliases_share_a_prefix_route_and_leave_room_to_restore_ipv6() {
    let n = Network::virtual_network(&Fabric::new().unwrap(), 2, NetworkMode::Full).unwrap();
    let ns = n.namespace_id();
    let mut g = n.1.graph.write().unwrap();
    let address = |ip, prefix| Address { ip, prefix };
    let first = address(ip("192.0.2.1"), 24);
    let second = address(ip("192.0.2.2"), 24);
    g.address(ns, 1, first, true, false).unwrap();
    let before = g.device(ns, 1).unwrap();
    g.address(ns, 1, second, true, false).unwrap();
    let after = g.device(ns, 1).unwrap();
    let mut changes = Vec::new();
    crate::rtnetlink::address_changes(&before, &after, &mut changes);
    assert_eq!(changes.iter().map(|c| c.1).collect::<Vec<_>>(), [20]);
    assert_eq!(
        g.routes(ns)
            .iter()
            .filter(|r| r.destination == first.network())
            .count(),
        1
    );
    g.address(ns, 1, first, false, false).unwrap();
    assert_eq!(
        g.source(ns, ip("192.0.2.42")).unwrap(),
        (second.ip, 1, None)
    );

    let localhost = address(ip("::1"), 128);
    g.address(ns, 1, localhost, false, false).unwrap();
    for host in 1..=3 {
        g.address(ns, 1, address([198, 51, 100, host].into(), 32), true, false)
            .unwrap();
    }
    let extra = address(ip("203.0.113.1"), 32);
    assert_eq!(g.address(ns, 1, extra, true, false), Err(NetError(28)));
    g.address(ns, 1, localhost, true, false).unwrap();
    drop(g);
    n.set_loopback_up(false).unwrap();
    assert!(!n.loopback_up());
    n.set_loopback_up(true).unwrap();
    assert!(n
        .devices()
        .into_iter()
        .find(|d| d.index == 1)
        .unwrap()
        .addresses
        .contains(&localhost));
}
