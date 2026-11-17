// SPDX-License-Identifier: GPL-3.0-or-later
//! Whole internal Ethernet path: raw frames, bridge controls, TAP and L3 sockets.
use super::*;
use crate::{
    ethernet::{BridgeConfig, FdbEntry, Frame},
    routing_tests::{assign, bridge, pair},
};
fn mac(n: &Network, index: u32) -> [u8; 6] {
    n.devices()
        .into_iter()
        .find(|d| d.index == index)
        .unwrap()
        .mac
}
fn raw(n: &Network, index: u32) -> Arc<Socket> {
    let s = n.socket(17, 3, 3u16.to_be() as u32).unwrap();
    s.bind_bytes(&crate::packet_socket::address(index, 3, 0, [0; 6]))
        .unwrap();
    s
}
fn send(s: &Socket, index: u32, source: [u8; 6], destination: [u8; 6], payload: &[u8]) {
    let f = Frame::build(source, destination, 0x88b5, payload);
    assert_eq!(
        s.send_bytes(
            &f.0,
            0,
            Some(&crate::packet_socket::address(
                index,
                0x88b5,
                0,
                destination
            ))
        ),
        Ok(f.0.len())
    );
}
fn attach(root: &Network, index: u32, master: u32) {
    root.1
        .graph
        .write()
        .unwrap()
        .change_link(
            root.namespace_id(),
            index,
            None,
            None,
            Some(true),
            Some(master),
            None,
            None,
        )
        .unwrap();
}
fn tap(root: &Network, br: u32, name: &[u8]) -> (Arc<crate::tun::Connection>, u32) {
    let tap = root.open_tun();
    tap.attach(name, 0x1002, true).unwrap();
    let index = root
        .devices()
        .into_iter()
        .find(|d| d.name == name)
        .unwrap()
        .index;
    attach(root, index, br);
    (tap, index)
}
#[test]
fn arbitrary_frames_fdb_learning_flooding_and_tap_hairpin_are_real() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"l2-br");
    let ai = pair(&root, &a, b"l2-a", br);
    let bi = pair(&root, &b, b"l2-b", br);
    let (tap, ti) = tap(&root, br, b"tap0");
    let tx = raw(&a, ai);
    let rx = raw(&b, bi);
    let am = mac(&a, ai);
    let bm = mac(&b, bi);
    send(&tx, ai, am, bm, b"unknown unicast");
    let f = rx.recv(2048, 0).unwrap().data;
    assert_eq!(tap.read(2048).unwrap(), f);
    assert_eq!(&f[14..], b"unknown unicast");
    send(&rx, bi, bm, am, b"learn reply");
    let _ = tx.recv(2048, 0).unwrap(); // Includes the sender's outgoing copy first.
                                       // Drain own outgoing frames before testing the other direction.
    while tx.recv(2048, 0).is_ok() {}
    while rx.recv(2048, 0).is_ok() {}
    send(&tx, ai, am, bm, b"learned unicast");
    assert_eq!(tap.read(2048), Err(NetError(11)));
    assert_eq!(&rx.recv(2048, 0).unwrap().data[14..], b"learned unicast");
    let spoof = [2, 9, 8, 7, 6, 5];
    let broadcast = Frame::build(spoof, [255; 6], 0x88b5, b"tap broadcast");
    tap.write(&broadcast.0).unwrap();
    assert_eq!(tap.read(2048), Err(NetError(11)));
    let mut g = root.1.graph.write().unwrap();
    let mut cfg = g.port_config(root.namespace_id(), ti).unwrap().clone();
    cfg.hairpin = true;
    g.configure_port(root.namespace_id(), ti, cfg).unwrap();
    drop(g);
    tap.write(&broadcast.0).unwrap();
    assert_eq!(tap.read(2048).unwrap(), &*broadcast.0);
    assert!(root
        .1
        .graph
        .read()
        .unwrap()
        .fdb(root.namespace_id(), br)
        .iter()
        .any(|(_, e)| e.mac == spoof && e.port == ti));
}
#[test]
fn access_trunk_vlan_membership_tags_and_unknown_vlan_isolation() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"vlan-br");
    let ai = pair(&root, &a, b"vlan-a", br);
    let bi = pair(&root, &b, b"vlan-b", br);
    let (trunk, ti) = tap(&root, br, b"trunk");
    let pa = match a
        .devices()
        .into_iter()
        .find(|d| d.index == ai)
        .unwrap()
        .kind
    {
        DeviceKind::Veth { peer } => peer,
        _ => unreachable!(),
    };
    let pb = match b
        .devices()
        .into_iter()
        .find(|d| d.index == bi)
        .unwrap()
        .kind
    {
        DeviceKind::Veth { peer } => peer,
        _ => unreachable!(),
    };
    {
        let mut g = root.1.graph.write().unwrap();
        g.configure_bridge(
            root.namespace_id(),
            br,
            BridgeConfig {
                vlan_filtering: true,
                ageing: 30000,
            },
        )
        .unwrap();
        for (index, vid) in [(pa, 10), (pb, 20)] {
            let mut p = g.port_config(root.namespace_id(), index).unwrap().clone();
            p.vlans.clear();
            p.vlan(vid, 6, true).unwrap();
            g.configure_port(root.namespace_id(), index, p).unwrap();
        }
        let mut p = g.port_config(root.namespace_id(), ti).unwrap().clone();
        p.vlans.clear();
        p.vlan(10, 0, true).unwrap();
        p.vlan(20, 0, true).unwrap();
        g.configure_port(root.namespace_id(), ti, p).unwrap();
    }
    let tx = raw(&a, ai);
    let rx = raw(&b, bi);
    let am = mac(&a, ai);
    let bm = mac(&b, bi);
    send(&tx, ai, am, bm, b"VLAN10 only");
    let wire = trunk.read(2048).unwrap();
    let wire = Frame::new(&wire).unwrap();
    assert_eq!(wire.vlan(), Some(10));
    assert_eq!(rx.poll(1), Ok(0));
    let source = [2, 1, 2, 3, 4, 5];
    let f = Frame::build(source, am, 0x88b5, b"tagged10").tagged(Some(10));
    trunk.write(&f.0).unwrap();
    let mut saw = false;
    while let Ok(r) = tx.recv(2048, 0) {
        if &r.data[14..] == b"tagged10" {
            saw = true;
            assert_eq!(&r.data[12..14], &0x88b5u16.to_be_bytes());
            break;
        }
    }
    assert!(saw);
    let f = Frame::build(source, bm, 0x88b5, b"tagged20").tagged(Some(20));
    trunk.write(&f.0).unwrap();
    assert_eq!(&rx.recv(2048, 0).unwrap().data[14..], b"tagged20");
    let f = Frame::build(source, [255; 6], 0x88b5, b"forbidden30").tagged(Some(30));
    trunk.write(&f.0).unwrap();
    assert_eq!(rx.poll(1), Ok(0));
}
#[test]
fn static_fdb_redirects_normal_udp_instead_of_bypassing_switch_by_ip() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"fdb-br");
    let ai = pair(&root, &a, b"fdb-a", br);
    let bi = pair(&root, &b, b"fdb-b", br);
    let (tap, ti) = tap(&root, br, b"sink");
    assign(&a, ai, "192.0.2.10", 24);
    assign(&b, bi, "192.0.2.20", 24);
    let rx = b.socket(2, 2, 0).unwrap();
    rx.bind("192.0.2.20:7002".parse().unwrap()).unwrap();
    let tx = a.socket(2, 2, 0).unwrap();
    let bm = mac(&b, bi);
    let e = FdbEntry {
        mac: bm,
        vlan: 0,
        port: ti,
        permanent: true,
        local: false,
    };
    root.1
        .graph
        .write()
        .unwrap()
        .fdb_modify(root.namespace_id(), br, e, true, 0x400)
        .unwrap();
    tx.send(
        b"redirect to TAP",
        0,
        Some("192.0.2.20:7002".parse().unwrap()),
    )
    .unwrap();
    assert_eq!(rx.poll(1), Ok(0));
    let mut saw = false;
    while let Ok(f) = tap.read(2048) {
        let f = Frame::new(&f).unwrap();
        if f.protocol() == 0x800 {
            assert_eq!(&f.payload()[28..], b"redirect to TAP");
            saw = true;
        }
    }
    assert!(saw);
    root.1
        .graph
        .write()
        .unwrap()
        .fdb_modify(root.namespace_id(), br, e, false, 0)
        .unwrap();
    tx.send(b"restored", 0, Some("192.0.2.20:7002".parse().unwrap()))
        .unwrap();
    assert_eq!(rx.recv(100, 0).unwrap().data, b"restored");
}
#[test]
fn arp_and_ndp_packets_resolve_real_neighbors_and_opaque_frames_preserve_bytes() {
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"arp-br");
    let ai = pair(&root, &a, b"arp-a", br);
    let bi = pair(&root, &b, b"arp-b", br);
    assign(&a, ai, "192.0.2.10", 24);
    assign(&b, bi, "192.0.2.20", 24);
    assign(&a, ai, "fd00:ab::10", 64);
    assign(&b, bi, "fd00:ab::20", 64);
    let tap = raw(&a, ai);
    let rx = b.socket(10, 2, 0).unwrap();
    rx.bind("[fd00:ab::20]:7002".parse().unwrap()).unwrap();
    let tx = a.socket(10, 2, 0).unwrap();
    tx.send(b"NDP", 0, Some("[fd00:ab::20]:7002".parse().unwrap()))
        .unwrap();
    assert_eq!(rx.recv(100, 0).unwrap().data, b"NDP");
    let mut solicitation = false;
    let mut advertisement = false;
    while let Ok(p) = tap.recv(2048, 0) {
        let f = Frame::new(&p.data).unwrap();
        if f.protocol() == 0x86dd && f.payload().get(6) == Some(&58) {
            solicitation |= f.payload().get(40) == Some(&135);
            advertisement |= f.payload().get(40) == Some(&136);
        }
    }
    assert!(solicitation && advertisement);
    assert!(a
        .1
        .graph
        .read()
        .unwrap()
        .neighbors(a.namespace_id(), ai, 10)
        .iter()
        .any(|e| e.address == "fd00:ab::20".parse::<std::net::IpAddr>().unwrap() && e.state == 2));
}

#[test]
fn named_ethernet_ports_echo_both_ip_families() {
    let fabric = Fabric::new().unwrap();
    let a = Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
    let b = Network::virtual_network(&fabric, 3, NetworkMode::Outbound).unwrap();
    let trace_a = raw(&a, 2);
    let trace_b = raw(&b, 2);
    for (family, protocol, target, kind) in [(2, 1, "10.0.0.3:0", 8), (10, 58, "[fd00::3]:0", 128)]
    {
        let ping = a.socket(family, 2, protocol).unwrap();
        ping.send(
            &[kind, 0, 0, 0, 0, 0, 0, 1],
            0,
            Some(target.parse().unwrap()),
        )
        .unwrap();
        let received = ping.recv(100, 0);
        let mut trace = vec![];
        for socket in [&trace_a, &trace_b] {
            while let Ok(r) = socket.recv(2048, 0) {
                let f = Frame::new(&r.data).unwrap();
                trace.push((f.protocol(), f.payload().to_vec()));
            }
        }
        assert!(
            received.is_ok(),
            "family {family}: {:?}, frames: {:?}",
            received.err(),
            trace
        );
    }
}

#[test]
fn linux_bridge_netlink_controls_are_atomic_authorized_and_reported() {
    use crate::netlink::{attr, message};
    let root = Network::new(NetworkMode::Full);
    let br = bridge(&root, b"control-br");
    let (_tap, ti) = tap(&root, br, b"control-tap");
    let control = crate::netlink::Socket::new(root.1.clone(), None, 3, 0).unwrap();
    let monitor = crate::netlink::Socket::new(root.1.clone(), None, 3, 0).unwrap();
    let mut address = crate::netlink::address(12345);
    address[8..12].copy_from_slice(&5u32.to_le_bytes());
    monitor.bind_bytes(&address).unwrap();
    let call = |kind: u16, flags: u16, data: &[u8], admin, expected| {
        control
            .send_bytes_authorized(&message(kind, flags | 5, 99, 0, data), 0, None, admin)
            .unwrap();
        let reply = control.recv(65536, 0).unwrap().data;
        assert_eq!(&reply[4..6], &2u16.to_le_bytes());
        assert_eq!(
            i32::from_le_bytes(reply[16..20].try_into().unwrap()),
            expected
        );
    };
    let mut link = vec![0; 16];
    link[0] = 7;
    link[4..8].copy_from_slice(&ti.to_le_bytes());
    let mut port = vec![];
    attr(&mut port, 4, &[1]);
    attr(&mut port, 8, &[0]);
    attr(&mut link, 12 | 0x8000, &port);
    call(19, 0, &link, false, -1);
    assert!(
        !root
            .1
            .graph
            .read()
            .unwrap()
            .port_config(root.namespace_id(), ti)
            .unwrap()
            .hairpin
    );
    call(19, 0, &link, true, 0);
    assert_eq!(
        &monitor.recv(65536, 0).unwrap().data[4..6],
        &16u16.to_le_bytes()
    );
    {
        let g = root.1.graph.read().unwrap();
        let p = g.port_config(root.namespace_id(), ti).unwrap();
        assert!(p.hairpin && !p.learning);
    }
    let mut vlans = vec![];
    for (flags, vid) in [(8u16, 10u16), (16, 12)] {
        attr(
            &mut vlans,
            2,
            &[flags.to_le_bytes(), vid.to_le_bytes()].concat(),
        );
    }
    let mut link = link[..16].to_vec();
    attr(&mut link, 26 | 0x8000, &vlans);
    call(19, 0, &link, true, 0);
    monitor.recv(65536, 0).unwrap();
    assert!((10..=12).all(|v| root
        .1
        .graph
        .read()
        .unwrap()
        .port_config(root.namespace_id(), ti)
        .unwrap()
        .vlans
        .contains_key(&v)));
    // A later malformed VLAN rolls back earlier valid attributes in the same request.
    let mut invalid = vec![];
    for vid in [20u16, 4095] {
        attr(&mut invalid, 2, &[0, 0, vid as u8, (vid >> 8) as u8]);
    }
    let mut link = link[..16].to_vec();
    attr(&mut link, 26 | 0x8000, &invalid);
    call(19, 0, &link, true, -22);
    assert!(!root
        .1
        .graph
        .read()
        .unwrap()
        .port_config(root.namespace_id(), ti)
        .unwrap()
        .vlans
        .contains_key(&20));
    let mut neighbor = vec![0; 12];
    neighbor[0] = 7;
    neighbor[4..8].copy_from_slice(&ti.to_le_bytes());
    neighbor[8..10].copy_from_slice(&64u16.to_le_bytes());
    neighbor[10] = 4;
    attr(&mut neighbor, 2, &[2, 20, 30, 40, 50, 60]);
    call(28, 0x600, &neighbor, true, 0);
    assert_eq!(
        &monitor.recv(65536, 0).unwrap().data[4..6],
        &28u16.to_le_bytes()
    );
    call(28, 0x600, &neighbor, true, -17);
    neighbor[8..10].copy_from_slice(&128u16.to_le_bytes());
    call(28, 0x100, &neighbor, true, 0);
    monitor.recv(65536, 0).unwrap();
    let entries = root.1.graph.read().unwrap().fdb(root.namespace_id(), br);
    assert!(entries
        .iter()
        .any(|(_, e)| e.mac == [2, 20, 30, 40, 50, 60] && e.local));
    assert!(entries
        .iter()
        .any(|(_, e)| e.mac == mac(&root, br) && e.local));
    control
        .send_bytes_authorized(
            &message(30, 1 | 0x300, 100, 0, &[7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            None,
            false,
        )
        .unwrap();
    let dump = control.recv(65536, 0).unwrap().data;
    assert_eq!(&dump[4..6], &28u16.to_le_bytes());
    while control.recv(65536, 0).is_ok() {}
    call(29, 0, &neighbor, true, 0);
    assert_eq!(
        &monitor.recv(65536, 0).unwrap().data[4..6],
        &29u16.to_le_bytes()
    );
}

#[test]
fn fdb_ages_moves_and_link_deletion_removes_entries_and_neighbors() {
    use crate::ethernet::Switch;
    let switch = Switch::default();
    let m = [2, 10, 20, 30, 40, 50];
    switch.learn(1, m, 2, 1);
    assert_eq!(switch.lookup(1, m, 1), Some(2));
    std::thread::sleep(Duration::from_millis(25));
    assert_eq!(switch.lookup(1, m, 1), None);
    switch.learn(1, m, 3, 0);
    assert_eq!(switch.lookup(1, m, 0), Some(3));
    switch
        .modify(
            FdbEntry {
                mac: m,
                vlan: 1,
                port: 4,
                permanent: true,
                local: false,
            },
            true,
            0x400,
        )
        .unwrap();
    switch.learn(1, m, 5, 1);
    assert_eq!(switch.lookup(1, m, 1), Some(4));
    switch.forget(4);
    assert_eq!(switch.lookup(1, m, 0), None);
    let root = Network::new(NetworkMode::Full);
    let br = bridge(&root, b"cycle-br");
    let (p, q) = root
        .1
        .graph
        .write()
        .unwrap()
        .create_veth(
            root.namespace_id(),
            b"cycle-a",
            root.namespace_id(),
            b"cycle-b",
        )
        .unwrap();
    attach(&root, p, br);
    assert_eq!(
        root.1
            .graph
            .read()
            .unwrap()
            .check_bridge_loop(root.namespace_id(), q, br),
        Err(NetError(40))
    );
    let (tap, ti) = tap(&root, br, b"lifetime-tap");
    let f = Frame::build(m, [255; 6], 0x88b5, b"learn");
    tap.write(&f.0).unwrap();
    assert!(root
        .1
        .graph
        .read()
        .unwrap()
        .fdb(root.namespace_id(), br)
        .iter()
        .any(|(_, e)| e.mac == m));
    drop(tap);
    let g = root.1.graph.read().unwrap();
    assert!(g.device(root.namespace_id(), ti).is_err());
    assert!(g
        .fdb(root.namespace_id(), br)
        .iter()
        .all(|(_, e)| e.port != ti));
}

#[test]
fn packet_promiscuity_and_bpf_filter_real_opaque_ethernet_bytes() {
    let root = Network::new(NetworkMode::Full);
    let n = root.isolated().unwrap();
    let br = bridge(&root, b"filter-br");
    let ni = pair(&root, &n, b"filter-a", br);
    let (tap, _) = tap(&root, br, b"filter-tap");
    let capture = raw(&n, ni);
    let frame = Frame::build(
        [2, 11, 22, 33, 44, 55],
        [2, 55, 44, 33, 22, 11],
        0x88b5,
        b"opaque",
    );
    tap.write(&frame.0).unwrap();
    assert_eq!(capture.poll(1), Ok(0));
    let mut membership = ni.to_le_bytes().to_vec();
    membership.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    capture.set_option_bytes(263, 1, &membership).unwrap();
    // Read the real EtherType at byte 12 and accept only the experimental protocol.
    let code = [
        (0x28u16, 0u8, 0u8, 12u32),
        (0x15, 0, 1, 0x88b5),
        (0x06, 0, 0, 65535),
        (0x06, 0, 0, 0),
    ];
    let filter: Vec<u8> = code
        .into_iter()
        .flat_map(|(op, jt, jf, k)| {
            [op.to_le_bytes().as_slice(), &[jt, jf], &k.to_le_bytes()].concat()
        })
        .collect();
    capture.attach_filter(&filter).unwrap();
    tap.write(&frame.0).unwrap();
    assert_eq!(capture.recv(2048, 0).unwrap().data, &*frame.0);
    let other = Frame::build(frame.source(), frame.destination(), 0x88b6, b"reject");
    tap.write(&other.0).unwrap();
    assert_eq!(capture.poll(1), Ok(0));
    capture.set_option_bytes(263, 2, &membership).unwrap();
    tap.write(&frame.0).unwrap();
    assert_eq!(capture.poll(1), Ok(0));
}

#[test]
fn original_protocol_resources_progress_arp_while_sender_has_no_network_wait() {
    use trames_shared::{HostEvents, HostProtocols, IoSignal, IoWake};
    struct Wake(HostProtocols);
    impl IoWake for Wake {
        fn wake_io(&self, signal: &Arc<IoSignal>) {
            self.0.wake(signal);
        }
    }
    let dir = std::path::PathBuf::from(format!("/tmp/trames-l2-driver-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = Fabric::new().unwrap();
    let b = Fabric::new().unwrap();
    a.attach(&dir, 2, false).unwrap();
    b.attach(&dir, 3, false).unwrap();
    let na = Network::virtual_network(&a, 2, NetworkMode::Outbound).unwrap();
    let nb = Network::virtual_network(&b, 3, NetworkMode::Outbound).unwrap();
    let tx = na.socket(2, 2, 0).unwrap();
    let rx = nb.socket(2, 2, 0).unwrap();
    rx.bind("10.0.0.3:34567".parse().unwrap()).unwrap();
    let wake = Arc::new(Wake(HostProtocols::default()));
    let target: Arc<dyn IoWake> = wake.clone();
    for n in [&na, &nb] {
        wake.0.register(n.protocol(), Arc::downgrade(&target));
    }
    let events = HostEvents::new().unwrap();
    wake.0.progress(&|| Ok(events.clone())).unwrap();
    assert!(
        wake.0.deadline().is_none(),
        "idle Ethernet must not poll a timer"
    );
    tx.send(
        b"no sender wait",
        0,
        Some("10.0.0.3:34567".parse().unwrap()),
    )
    .unwrap();
    for _ in 0..6 {
        wake.0.progress(&|| Ok(events.clone())).unwrap();
        events
            .wait(Some(std::time::Instant::now() + Duration::from_millis(10)))
            .unwrap();
    }
    assert_eq!(rx.recv(64, 0).unwrap().data, b"no sender wait");
    drop((tx, rx, na, nb, a, b));
    wake.0.progress(&|| Ok(events.clone())).unwrap();
    assert!(!wake.0.external());
    assert!(wake.0.deadline().is_none());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn bridged_large_datagrams_survive_ip_firewall_defragmentation() {
    use crate::nftables::tests::{batch, chain, table};
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"frag-br");
    let ai = pair(&root, &a, b"frag-a", br);
    let bi = pair(&root, &b, b"frag-b", br);
    assign(&a, ai, "192.0.2.10", 24);
    assign(&b, bi, "192.0.2.20", 24);
    let result = batch(
        &root.1,
        &[table("frag"), chain("frag", "forward", Some(2), 0, 1)],
    );
    assert!(result
        .iter()
        .all(|r| r[4..6] != 2u16.to_le_bytes() || r[16..20] == [0; 4]));
    let tx = a.socket(2, 2, 0).unwrap();
    let rx = b.socket(2, 2, 0).unwrap();
    rx.bind("192.0.2.20:34002".parse().unwrap()).unwrap();
    let payload = vec![0x5a; 60000];
    tx.send(&payload, 0, Some("192.0.2.20:34002".parse().unwrap()))
        .unwrap();
    assert_eq!(rx.recv(65536, 0).unwrap().data, payload);
    batch(&root.1, &[chain("frag", "forward", Some(2), 0, 0)]);
    tx.send(b"blocked", 0, Some("192.0.2.20:34002".parse().unwrap()))
        .unwrap();
    assert_eq!(rx.poll(1), Ok(0));
}
