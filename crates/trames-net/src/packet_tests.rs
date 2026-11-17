// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::routing_tests::{assign, bridge, pair};
use std::net::{IpAddr, SocketAddr};
fn addr(ip: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip.parse().unwrap(), port)
}
pub(crate) fn udp4(
    source: &str,
    destination: &str,
    sport: u16,
    dport: u16,
    data: &[u8],
) -> Vec<u8> {
    let mut p = vec![0; 28 + data.len()];
    let len = p.len() as u16;
    p[0] = 0x45;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    let IpAddr::V4(src) = source.parse().unwrap() else {
        unreachable!()
    };
    let IpAddr::V4(dst) = destination.parse().unwrap() else {
        unreachable!()
    };
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&sport.to_be_bytes());
    p[22..24].copy_from_slice(&dport.to_be_bytes());
    p[24..26].copy_from_slice(&(8 + data.len() as u16).to_be_bytes());
    p[28..].copy_from_slice(data);
    smoltcp::wire::Ipv4Packet::new_unchecked(&mut p).fill_checksum();
    p
}
fn filter(code: &[(u16, u8, u8, u32)]) -> Vec<u8> {
    code.iter()
        .flat_map(|(op, jt, jf, k)| {
            let mut b = op.to_le_bytes().to_vec();
            b.extend_from_slice(&[*jt, *jf]);
            b.extend_from_slice(&k.to_le_bytes());
            b
        })
        .collect()
}
#[test]
fn classic_filter_validates_control_flow_scratch_arithmetic_and_snaplen() {
    use crate::socket_filter::Program;
    for code in [
        vec![(0x05, 0, 0, 10), (0x06, 0, 0, 9)],
        vec![(0x60, 0, 0, 0), (0x06, 0, 0, 9)],
        vec![(0x34, 0, 0, 0), (0x16, 0, 0, 0)],
        vec![(0x15, 0, 9, 0), (0x06, 0, 0, 1)],
        vec![(0x20, 0, 0, 0xfffff000), (0x16, 0, 0, 0)],
    ] {
        assert!(Program::new(&filter(&code)).is_err());
    }
    let p = Program::new(&filter(&[
        (0x00, 0, 0, 12),
        (0x02, 0, 0, 0),
        (0x01, 0, 0, 4),
        (0x3c, 0, 0, 0),
        (0x61, 0, 0, 0),
        (0x0c, 0, 0, 0),
        (0x16, 0, 0, 0),
    ]))
    .unwrap();
    assert_eq!(p.run(&[]), 15);
    let p = Program::new(&filter(&[(0x20, 0, 0, 400), (0x06, 0, 0, 99)])).unwrap();
    assert_eq!(p.run(b"short"), 0);
    // Scratch initialized on one arm cannot be loaded after the paths join.
    assert!(Program::new(&filter(&[
        (0x15, 1, 0, 0),
        (0x02, 0, 0, 0),
        (0x60, 0, 0, 0),
        (0x16, 0, 0, 0)
    ]))
    .is_err());
}
#[test]
fn tun_real_udp_both_directions_pi_and_final_close() {
    for flags in [1, 0x1001] {
        let root = Network::new(NetworkMode::Full);
        let n = root.isolated().unwrap();
        let tun = n.open_tun();
        assert_eq!(tun.attach(b"tun%d", flags, false), Err(NetError(1)));
        assert_eq!(tun.attach(b"tun%d", flags, true).unwrap(), b"tun0");
        let index = n
            .devices()
            .into_iter()
            .find(|d| d.name == b"tun0")
            .unwrap()
            .index;
        assign(&n, index, "192.0.2.1", 24);
        let client = n.socket(2, 2, 0).unwrap();
        client.bind(addr("192.0.2.1", 7001)).unwrap();
        struct Wake;
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
        }
        let wake: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
        let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&wake));
        let _sub = tun.subscribe(&signal).unwrap();
        assert_eq!(
            client.send(b"through tun", 0, Some(addr("192.0.2.2", 7002))),
            Ok(11)
        );
        assert_eq!(tun.poll(1).0, 1);
        let p = tun.read(2048).unwrap();
        let offset = if flags & 0x1000 == 0 { 4 } else { 0 };
        assert_eq!(&p[offset + 28..], b"through tun");
        let mut reply = udp4("192.0.2.2", "192.0.2.1", 7002, 7001, b"response");
        if offset == 4 {
            let mut pi = vec![0, 0, 8, 0];
            pi.extend_from_slice(&reply);
            reply = pi;
        }
        assert_eq!(tun.write(&reply), Ok(reply.len()));
        assert_eq!(client.recv(100, 0).unwrap().data, b"response");
        assert_eq!(tun.read(100), Err(NetError(11)));
        drop(tun);
        assert!(n.devices().iter().all(|d| d.index != index));
    }
}
#[test]
fn packet_capture_filter_injection_and_namespace_isolation() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let c = root.isolated().unwrap();
    let br = bridge(&root, b"br-packet");
    let ai = pair(&root, &a, b"ap", br);
    let bi = pair(&root, &b, b"bp", br);
    assign(&a, ai, "192.0.2.10", 24);
    assign(&b, bi, "192.0.2.20", 24);
    let tap = b.socket(17, 3, 3u16.to_be() as u32).unwrap();
    tap.bind_bytes(&crate::packet_socket::address(bi, 3, 0, [0; 6]))
        .unwrap();
    let isolated = c.socket(17, 2, 3u16.to_be() as u32).unwrap();
    // tcpdump-style IPv4 UDP port filter, including MSH and indirect load.
    tap.attach_filter(&filter(&[
        (0x28, 0, 0, 12),
        (0x15, 0, 6, 0x800),
        (0x30, 0, 0, 23),
        (0x15, 0, 4, 17),
        (0xb1, 0, 0, 14),
        (0x48, 0, 0, 16),
        (0x15, 0, 1, 7002),
        (0x06, 0, 0, 64),
        (0x06, 0, 0, 0),
    ]))
    .unwrap();
    let server = b.socket(2, 2, 0).unwrap();
    server.bind(addr("192.0.2.20", 7002)).unwrap();
    let tx = a.socket(2, 2, 0).unwrap();
    tx.send(b"capture", 0, Some(addr("192.0.2.20", 7002)))
        .unwrap();
    assert_eq!(server.recv(20, 0).unwrap().data, b"capture");
    let capture = tap.recv(10, MSG_PEEK | MSG_TRUNC).unwrap();
    assert_eq!(capture.length, 49);
    assert!(capture.truncated);
    assert_eq!(capture.packet_address.unwrap()[10], 0);
    let frame = tap.recv(2048, 0).unwrap();
    assert_eq!(&frame.data[12..14], &[8, 0]);
    assert_eq!(&frame.data[42..], b"capture");
    assert_eq!(isolated.poll(1), Ok(0));
    tx.send(b"filtered", 0, Some(addr("192.0.2.20", 7003)))
        .unwrap();
    assert_eq!(tap.poll(1), Ok(0));
    let injector = a.socket(17, 2, 0x0800u16.to_be() as u32).unwrap();
    let mac = b.devices().into_iter().find(|d| d.index == bi).unwrap().mac;
    let raw = udp4("192.0.2.10", "192.0.2.20", 7001, 7002, b"injected");
    let target = crate::packet_socket::address(ai, 0x800, 0, mac);
    assert_eq!(injector.send_bytes(&raw, 0, Some(&target)), Ok(raw.len()));
    assert_eq!(server.recv(100, 0).unwrap().data, b"injected");
    tap.set_option(1, 44, 1).unwrap();
    assert_eq!(
        tap.attach_filter(&filter(&[(0x06, 0, 0, 1)])),
        Err(NetError(1))
    );
    assert_eq!(tap.set_option_bytes(1, 27, &[]), Err(NetError(1)));
}
#[test]
fn neighbors_netlink_override_real_delivery_and_dump() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"br-neigh");
    let ai = pair(&root, &a, b"an", br);
    let bi = pair(&root, &b, b"bn", br);
    assign(&a, ai, "192.0.2.10", 24);
    assign(&b, bi, "192.0.2.20", 24);
    let socket = a.socket(16, 3, 0).unwrap();
    let ip: IpAddr = "192.0.2.20".parse().unwrap();
    let mut data = vec![0; 12];
    data[0] = 2;
    data[4..8].copy_from_slice(&ai.to_le_bytes());
    data[8..10].copy_from_slice(&32u16.to_le_bytes());
    crate::netlink::attr(&mut data, 1, &[192, 0, 2, 20]);
    let request = crate::netlink::message(28, 1 | 4 | 0x400, 1, 0, &data);
    socket
        .send_bytes_authorized(&request, 0, None, true)
        .unwrap();
    assert_eq!(&socket.recv(100, 0).unwrap().data[16..20], &[0; 4]);
    let server = b.socket(2, 2, 0).unwrap();
    server.bind(addr("192.0.2.20", 7002)).unwrap();
    let client = a.socket(2, 2, 0).unwrap();
    client
        .send(b"blocked", 0, Some(addr("192.0.2.20", 7002)))
        .unwrap();
    assert_eq!(server.poll(1), Ok(0));
    let dump = crate::netlink::message(30, 1 | 0x300, 2, 0, &[2]);
    socket.send_bytes(&dump, 0, None).unwrap();
    let entry = socket.recv(1024, 0).unwrap().data;
    assert_eq!(&entry[4..6], &28u16.to_le_bytes());
    assert_eq!(&entry[24..26], &32u16.to_le_bytes());
    let _done = socket.recv(100, 0).unwrap();
    let request = crate::netlink::message(29, 1 | 4, 3, 0, &data);
    socket
        .send_bytes_authorized(&request, 0, None, true)
        .unwrap();
    let _ack = socket.recv(100, 0).unwrap();
    client
        .send(b"restored", 0, Some(addr("192.0.2.20", 7002)))
        .unwrap();
    assert_eq!(server.recv(100, 0).unwrap().data, b"restored");
    assert!(a
        .1
        .graph
        .read()
        .unwrap()
        .neighbors(a.namespace_id(), ai, 2)
        .iter()
        .any(|e| e.address == ip && e.state == 2));
}

#[test]
fn tun_ipv6_and_notification_reentry_hold_no_fabric_or_topology_lock() {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    struct Wake {
        network: Network,
        tun: std::sync::Weak<crate::tun::Connection>,
        count: AtomicUsize,
    }
    impl trames_shared::IoWake for Wake {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
            assert!(self.network.1.graph.try_write().is_ok());
            if let Some(tun) = self.tun.upgrade() {
                let _ = tun.poll(1);
            }
            self.count.fetch_add(1, Relaxed);
        }
    }
    let root = Network::new(NetworkMode::Full);
    let n = root.isolated().unwrap();
    let tun = n.open_tun();
    tun.attach(b"tun6", 0x1001, true).unwrap();
    let index = n
        .devices()
        .into_iter()
        .find(|d| d.name == b"tun6")
        .unwrap()
        .index;
    assign(&n, index, "fd00:55::1", 64);
    let wake = Arc::new(Wake {
        network: n.clone(),
        tun: Arc::downgrade(&tun),
        count: AtomicUsize::new(0),
    });
    let target: Arc<dyn trames_shared::IoWake> = wake.clone();
    let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&target));
    let _sub = tun.subscribe(&signal).unwrap();
    let client = n.socket(10, 2, 0).unwrap();
    client.bind(addr("fd00:55::1", 7001)).unwrap();
    client
        .send(b"IPv6", 0, Some(addr("fd00:55::2", 7002)))
        .unwrap();
    assert!(wake.count.load(Relaxed) > 0);
    let mut reply = tun.read(2048).unwrap();
    assert_eq!(&reply[48..], b"IPv6");
    for i in 0..16 {
        reply.swap(8 + i, 24 + i);
    }
    reply.swap(40, 42);
    reply.swap(41, 43);
    let source =
        smoltcp::wire::IpAddress::from("fd00:55::2".parse::<std::net::Ipv6Addr>().unwrap());
    let destination =
        smoltcp::wire::IpAddress::from("fd00:55::1".parse::<std::net::Ipv6Addr>().unwrap());
    smoltcp::wire::UdpPacket::new_unchecked(&mut reply[40..]).fill_checksum(&source, &destination);
    tun.write(&reply).unwrap();
    assert_eq!(client.recv(100, 0).unwrap().data, b"IPv6");
}
