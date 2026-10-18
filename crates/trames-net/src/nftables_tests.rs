// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{Network, NetworkMode};
fn req(op: u16, family: u8, flags: u16, a: &[u8]) -> Vec<u8> {
    let mut d = data(family);
    d.extend_from_slice(a);
    message(SUBSYSTEM | op, 1 | flags, 10 + op as u32, 0, &d)
}
fn table(n: &str) -> Vec<u8> {
    let mut a = vec![];
    string(&mut a, 1, n);
    req(0, 2, 0x400, &a)
}
fn chain(t: &str, n: &str, hook: Option<u32>, priority: i32, policy: u32) -> Vec<u8> {
    let mut a = vec![];
    string(&mut a, 1, t);
    string(&mut a, 3, n);
    if let Some(h) = hook {
        let mut d = vec![];
        number(&mut d, 1, h);
        number(&mut d, 2, priority as u32);
        attr(&mut a, 4 | 0x8000, &d);
        number(&mut a, 5, policy);
        string(&mut a, 7, "filter");
    }
    req(3, 2, 0x400, &a)
}
fn expression(n: &str, d: &[u8]) -> Vec<u8> {
    let mut a = vec![];
    string(&mut a, 1, n);
    attr(&mut a, 2 | 0x8000, d);
    let mut b = vec![];
    attr(&mut b, 1 | 0x8000, &a);
    b
}
fn verdict(code: i32, chain: Option<&str>) -> Vec<u8> {
    let mut v = vec![];
    number(&mut v, 1, code as u32);
    if let Some(n) = chain {
        string(&mut v, 2, n);
    }
    let mut d = vec![];
    attr(&mut d, 2 | 0x8000, &v);
    let mut i = vec![];
    number(&mut i, 1, 0);
    attr(&mut i, 2 | 0x8000, &d);
    expression("immediate", &i)
}
fn rule(t: &str, c: &str, e: &[u8]) -> Vec<u8> {
    let mut a = vec![];
    string(&mut a, 1, t);
    string(&mut a, 2, c);
    attr(&mut a, 4 | 0x8000, e);
    req(6, 2, 0x400 | 0x800, &a)
}
fn batch(ns: &Namespace, r: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let start = message(16, 1, 1, 0, &[0, 0, 0, 10]);
    let end = message(17, 1, 100, 0, &[0, 0, 0, 10]);
    let mut rs = vec![start.as_slice()];
    rs.extend(r.iter().map(Vec::as_slice));
    rs.push(&end);
    request(ns, &rs, 1, true, 128, MAX_BYTES).unwrap()
}
fn errno(r: &[Vec<u8>]) -> i32 {
    if r.is_empty() {
        0
    } else {
        i32::from_le_bytes(r.last().unwrap()[16..20].try_into().unwrap())
    }
}
fn packet() -> Vec<u8> {
    let mut p = vec![0; 28];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[192, 0, 2, 3]);
    p[16..20].copy_from_slice(&[192, 0, 2, 4]);
    p[20..22].copy_from_slice(&18000u16.to_be_bytes());
    p[22..24].copy_from_slice(&19000u16.to_be_bytes());
    smoltcp::wire::Ipv4Packet::new_unchecked(&mut p).fill_checksum();
    p
}
fn allows(ns: &Namespace, hook: u32) -> bool {
    ns.graph
        .borrow()
        .firewall(ns.id())
        .borrow()
        .allows(&Context {
            packet: &packet(),
            hook,
            input: 3,
            output: 4,
            input_name: b"veth-in",
            output_name: b"br-out",
        })
}
#[test]
fn batch_rollback_generation_authority_capacity_and_namespace_are_real() {
    let n = Namespace::default();
    let other = Namespace::default();
    let before = n.graph.borrow().firewall(n.id());
    assert_eq!(
        errno(&batch(
            &n,
            &[table("filter"), chain("filter", "out", Some(3), 0, 0)]
        )),
        0
    );
    assert!(!allows(&n, 3));
    assert!(allows(&other, 3));
    assert_eq!(before.borrow().generation, 1);
    assert_eq!(
        errno(&batch(
            &n,
            &[
                table("rollback"),
                rule("filter", "out", &expression("masq", &[]))
            ]
        )),
        -95
    );
    assert_eq!(before.borrow().generation, 1);
    assert_eq!(before.borrow().tables.len(), 1);
    let mut gen = vec![];
    number(&mut gen, 1, 0);
    let mut begin = vec![0, 0, 0, 10];
    begin.extend(gen);
    let r = message(16, 1, 1, 0, &begin);
    let create = table("stale");
    let end = message(17, 1, 2, 0, &[0, 0, 0, 10]);
    assert_eq!(
        errno(&request(&n, &[&r, &create, &end], 1, true, 128, MAX_BYTES).unwrap()),
        -85
    );
    let r = req(16, 0, 0, &[]);
    assert_eq!(
        errno(&request(&n, &[&r], 1, false, 128, MAX_BYTES).unwrap()),
        -1
    );
    let begin = message(16, 1, 1, 0, &[0, 0, 0, 10]);
    let mut create = table("capacity");
    create[6..8].copy_from_slice(&0x405u16.to_le_bytes());
    assert_eq!(
        request(&n, &[&begin, &create, &end], 1, true, 0, 0),
        Err(NetError(105))
    );
    assert_eq!(before.borrow().generation, 1);
    assert_eq!(before.borrow().tables.len(), 1);
}
#[test]
fn jumps_priorities_live_counters_and_payload_match() {
    let n = Namespace::default();
    let mut payload = vec![];
    number(&mut payload, 1, 1);
    number(&mut payload, 2, 2);
    number(&mut payload, 3, 2);
    number(&mut payload, 4, 2);
    let mut v = vec![];
    attr(&mut v, 1, &19000u16.to_be_bytes());
    let mut cmp = vec![];
    number(&mut cmp, 1, 1);
    number(&mut cmp, 2, 0);
    attr(&mut cmp, 3 | 0x8000, &v);
    let mut e = expression("payload", &payload);
    e.extend(expression("cmp", &cmp));
    e.extend(expression("counter", &[]));
    e.extend(verdict(0, None));
    let setup = [
        table("filter"),
        chain("filter", "out", Some(3), 0, 1),
        chain("filter", "user", None, 0, 1),
        rule("filter", "user", &e),
        rule("filter", "out", &verdict(-3, Some("user"))),
    ];
    assert_eq!(errno(&batch(&n, &setup)), 0);
    assert!(!allows(&n, 3));
    assert!(allows(&n, 1));
    let state = n.graph.borrow().firewall(n.id());
    let state = state.borrow();
    let t = &state.tables[&(2, "filter".into())];
    let r = &t.chains["user"].rules[0];
    assert!(
        matches!(&r.expressions[2],Expr::Counter{packets,bytes} if packets.get()==1 && bytes.get()==28)
    );
    let wire = rule_data(2, "filter", "user", r);
    assert!(wire.windows(8).any(|v| v == 1u64.to_be_bytes()));
    drop(state);
    // ACCEPT in an earlier base chain cannot bypass a later DROP policy.
    let n = Namespace::default();
    assert_eq!(
        errno(&batch(
            &n,
            &[
                table("f"),
                chain("f", "accept", Some(3), -10, 1),
                rule("f", "accept", &verdict(1, None)),
                chain("f", "drop", Some(3), 10, 0)
            ]
        )),
        0
    );
    assert!(!allows(&n, 3));
}
#[test]
fn cycles_invalid_registers_and_native_hooks_are_rejected_atomically() {
    let n = Namespace::default();
    let setup = [
        table("f"),
        chain("f", "a", None, 0, 1),
        chain("f", "b", None, 0, 1),
        rule("f", "a", &verdict(-3, Some("b"))),
        rule("f", "b", &verdict(-4, Some("a"))),
    ];
    assert_eq!(errno(&batch(&n, &setup)), -40);
    assert!(n.graph.borrow().firewall(n.id()).borrow().tables.is_empty());
    let mut cmp = vec![];
    number(&mut cmp, 1, 23);
    number(&mut cmp, 2, 0);
    let mut v = vec![];
    attr(&mut v, 1, &[0; 8]);
    attr(&mut cmp, 3 | 0x8000, &v);
    assert!(matches!(
        expressions(&expression("cmp", &cmp)),
        Err(NetError(22))
    ));
    let native = Network::new(NetworkMode::Full);
    assert_eq!(
        errno(&batch(
            &native.1,
            &[table("f"), chain("f", "input", Some(1), 0, 0)]
        )),
        -95
    );
    assert_eq!(
        errno(&batch(
            &native.1,
            &[table("f"), chain("f", "forward", Some(2), 0, 0)]
        )),
        0
    );
    let fabric = crate::Fabric::new().unwrap();
    let legacy = Network::virtual_network(&fabric, 2, NetworkMode::Full).unwrap();
    assert_eq!(
        errno(&batch(
            &legacy.1,
            &[table("f"), chain("f", "out", Some(3), 0, 0)]
        )),
        -95
    );
}
#[test]
fn protocol_ports_multicast_and_transport_provenance_are_separate() {
    let n = Network::default();
    let route = n.socket(16, 3, 0).unwrap();
    let nft = n.socket(16, 3, 12).unwrap();
    let address = crate::netlink::address(42);
    route.bind_bytes(&address).unwrap();
    nft.bind_bytes(&address).unwrap();
    let duplicate = n.socket(16, 3, 12).unwrap();
    assert_eq!(duplicate.bind_bytes(&address), Err(NetError(98)));
    assert_eq!(nft.set_option(270, 1, 7), Err(NetError(95)));
    let r = req(16, 0, 0, &[]);
    nft.send_bytes_authorized(&r, 0, None, true).unwrap();
    let received = nft.recv(4096, 0).unwrap();
    assert_eq!(
        received.netlink_address,
        Some([16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    );
    assert_eq!(
        u16::from_le_bytes(received.data[4..6].try_into().unwrap()),
        SUBSYSTEM | 15
    );
    assert_eq!(route.poll(1), Ok(0));
}
#[test]
fn routed_filter_blocks_active_tcp_without_touching_native_path() {
    use crate::routing_tests::{assign, bridge, pair};
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let ba = bridge(&root, b"nf-a");
    let bb = bridge(&root, b"nf-b");
    assign(&root, ba, "172.24.0.1", 24);
    assign(&root, bb, "172.25.0.1", 24);
    let ai = pair(&root, &a, b"nf-pa", ba);
    let bi = pair(&root, &b, b"nf-pb", bb);
    assign(&a, ai, "172.24.0.2", 24);
    assign(&b, bi, "172.25.0.2", 24);
    for (n, dev, gw) in [(&a, ai, "172.24.0.1"), (&b, bi, "172.25.0.1")] {
        n.1.graph
            .borrow_mut()
            .route(
                n.namespace_id(),
                crate::netdev::Route {
                    destination: crate::netdev::Address {
                        ip: "0.0.0.0".parse().unwrap(),
                        prefix: 0,
                    },
                    device: dev,
                    gateway: Some(gw.parse().unwrap()),
                    metric: 0,
                    protocol: 3,
                },
                true,
                false,
                false,
            )
            .unwrap();
    }
    root.set_forwarding(false, true);
    let listener = b.socket(2, 1, 0).unwrap();
    listener.bind("0.0.0.0:19010".parse().unwrap()).unwrap();
    listener.listen(2).unwrap();
    let client = a.socket(2, 1, 0).unwrap();
    assert_eq!(
        client.connect("172.25.0.2:19010".parse().unwrap()),
        Err(NetError(115))
    );
    assert_eq!(client.connect_complete(), Ok(true));
    let (accepted, _) = listener.accept().unwrap();
    client.send(b"before", 0, None).unwrap();
    assert_eq!(accepted.recv(64, 0).unwrap().data, b"before");
    assert_eq!(
        errno(&batch(
            &root.1,
            &[table("f"), chain("f", "forward", Some(2), 0, 0)]
        )),
        0
    );
    client.send(b"blocked", 0, None).unwrap();
    assert!(matches!(accepted.recv(64, 0), Err(NetError(11))));
    // Local root-to-container traffic does not traverse FORWARD.
    let receiver = b.socket(2, 2, 0).unwrap();
    receiver.bind("0.0.0.0:19011".parse().unwrap()).unwrap();
    let sender = root.socket(2, 2, 0).unwrap();
    sender
        .send(b"local", 0, Some("172.25.0.2:19011".parse().unwrap()))
        .unwrap();
    assert_eq!(receiver.recv(64, 0).unwrap().data, b"local");
    let mut d = vec![];
    string(&mut d, 1, "f");
    assert_eq!(errno(&batch(&root.1, &[req(2, 2, 0, &d)])), 0);
    let sender = a.socket(2, 2, 0).unwrap();
    sender
        .send(b"restored", 0, Some("172.25.0.2:19011".parse().unwrap()))
        .unwrap();
    assert_eq!(receiver.recv(64, 0).unwrap().data, b"restored");
}
