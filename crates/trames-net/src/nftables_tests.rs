// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{Network, NetworkMode};
fn req(op: u16, family: u8, flags: u16, a: &[u8]) -> Vec<u8> {
    let mut d = data(family);
    d.extend_from_slice(a);
    message(SUBSYSTEM | op, 1 | flags, 10 + op as u32, 0, &d)
}
pub(crate) fn table(n: &str) -> Vec<u8> {
    let mut a = vec![];
    string(&mut a, 1, n);
    req(0, 2, 0x400, &a)
}
pub(crate) fn chain(t: &str, n: &str, hook: Option<u32>, priority: i32, policy: u32) -> Vec<u8> {
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
pub(crate) fn batch(ns: &Namespace, r: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let start = message(16, 1, 1, 0, &[0, 0, 0, 10]);
    let end = message(17, 1, 100, 0, &[0, 0, 0, 10]);
    let mut rs = vec![start.as_slice()];
    rs.extend(r.iter().map(Vec::as_slice));
    rs.push(&end);
    request(ns, &rs, 1, true, 128, MAX_BYTES).unwrap()
}
fn shared_batch(shared: &Firewall, r: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    let start = message(16, 1, 1, 0, &[0, 0, 0, 10]);
    let end = message(17, 1, 100, 0, &[0, 0, 0, 10]);
    let mut requests = vec![start.as_slice()];
    requests.extend(r.iter().map(Vec::as_slice));
    requests.push(&end);
    request_rules(shared, true, &requests, 1, true, 128, MAX_BYTES)
}
#[test]
fn dormant_and_socket_owned_tables_follow_hook_and_socket_lifetimes() {
    use crate::netlink::Socket;
    let ns = std::sync::Arc::new(Namespace::default());
    let owned_table = |flags| {
        let mut attrs = vec![];
        string(&mut attrs, 1, "owned");
        number(&mut attrs, 2, flags);
        req(0, 2, 0, &attrs)
    };
    let mut address = [0; 12];
    address[..2].copy_from_slice(&16u16.to_le_bytes());
    address[4..8].copy_from_slice(&1u32.to_le_bytes());
    let owner = Socket::new(ns.clone(), None, 3, 12).unwrap();
    owner.bind_bytes(&address, 1).unwrap();
    let shared = ns.graph.read().unwrap().firewall(ns.id());
    assert_eq!(
        errno(&batch(
            &ns,
            &[owned_table(3), chain("owned", "drop", Some(3), 0, 0)]
        )),
        0
    );
    assert!(!shared.has_rules());
    assert_eq!(
        errno(&batch(
            &ns,
            &[table("keep"), chain("keep", "accept", Some(3), 1, 1)]
        )),
        0
    );
    assert!(shared.has_rules() && allows(&ns, 3));
    assert_eq!(errno(&batch(&ns, &[owned_table(2)])), 0);
    let unrelated = Socket::new(ns.clone(), None, 3, 0).unwrap();
    unrelated.bind_bytes(&address, 1).unwrap();
    drop(unrelated);
    assert!(!allows(&ns, 3));
    drop(owner);
    let replacement = Socket::new(ns.clone(), None, 3, 12).unwrap();
    replacement.bind_bytes(&address, 1).unwrap();
    assert!(shared.has_rules() && allows(&ns, 3));
    let rules = shared.read().unwrap();
    assert_eq!(rules.tables.len(), 1);
    assert!(rules.tables.contains_key(&(2, "keep".into())));
}
#[test]
fn chain_rename_keeps_jump_target_and_dump_consistent_after_rollback() {
    let ns = Namespace::default();
    let shared = ns.graph.read().unwrap().firewall(ns.id());
    assert_eq!(
        errno(&batch(
            &ns,
            &[
                table("filter"),
                chain("filter", "out", Some(3), 0, 1),
                chain("filter", "old", None, 0, 1),
                rule("filter", "old", &verdict(0, None)),
                rule("filter", "out", &verdict(-3, Some("old"))),
            ]
        )),
        0
    );
    let handle = shared.read().unwrap().tables[&(2, "filter".into())].chains["old"].handle;
    let rename = |new| {
        let mut a = vec![];
        string(&mut a, 1, "filter");
        integer(&mut a, 2, handle);
        string(&mut a, 3, new);
        req(3, 2, 0, &a)
    };
    assert_eq!(errno(&batch(&ns, &[rename("new"), rename("out")])), -17);
    assert!(shared.read().unwrap().tables[&(2, "filter".into())]
        .chains
        .contains_key("old"));
    assert_eq!(errno(&batch(&ns, &[rename("new")])), 0);
    assert!(!allows(&ns, 3));
    let rules = shared.read().unwrap();
    let rule = &rules.tables[&(2, "filter".into())].chains["out"].rules[0];
    let dump = rule_data(2, "filter", "out", rule);
    let attrs = attrs(&dump[4..]).unwrap();
    let decoded = expressions_in(need(&attrs, 4).unwrap(), 2).unwrap();
    assert!(matches!(decoded.as_slice(), [Expr::Verdict(-3, Some(target))] if target == "new"));
}
#[test]
fn resource_id_and_unspecified_flush_use_one_original_rules_transaction() {
    let ns = Namespace::default();
    assert_eq!(errno(&batch(&ns, &[table("first"), table("second")])), 0);
    let mut flush = req(2, 0, 4, &[]);
    flush[18..20].copy_from_slice(&10u16.to_be_bytes());
    assert_eq!(errno(&batch(&ns, &[flush])), 0);
    let rules = ns.graph.read().unwrap().firewall(ns.id());
    assert!(rules.read().unwrap().tables.is_empty());
}
#[test]
fn concurrent_rule_batches_preserve_every_commit_and_generation() {
    let rules = std::sync::Arc::new(Firewall::default());
    let start = std::sync::Barrier::new(9);
    std::thread::scope(|scope| {
        for index in 0..8 {
            let (rules, start) = (&rules, &start);
            scope.spawn(move || {
                let name = format!("worker-{index}");
                start.wait();
                assert_eq!(errno(&shared_batch(rules, &[table(&name)]).unwrap()), 0);
            });
        }
        start.wait();
    });
    let current = rules.read().unwrap();
    assert_eq!(current.generation, 9);
    assert_eq!(current.tables.len(), 8);
    for index in 0..8 {
        assert!(current.tables.contains_key(&(2, format!("worker-{index}"))));
    }
    drop(current);
    assert_eq!(
        errno(
            &shared_batch(
                &rules,
                &[table("rollback"), chain("rollback", "bad", Some(5), 0, 1)]
            )
            .unwrap()
        ),
        -95
    );
    assert_eq!(rules.read().unwrap().generation, 9);
    assert!(!rules
        .read()
        .unwrap()
        .tables
        .contains_key(&(2, "rollback".into())));
}
#[test]
fn counters_keep_parallel_packets_across_live_rule_publication() {
    let rules = std::sync::Arc::new(Firewall::default());
    assert_eq!(
        errno(
            &shared_batch(
                &rules,
                &[
                    table("filter"),
                    chain("filter", "out", Some(3), 0, 1),
                    rule("filter", "out", &expression("counter", &[]))
                ]
            )
            .unwrap()
        ),
        0
    );
    let start = std::sync::Barrier::new(6);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let (rules, start) = (&rules, &start);
            scope.spawn(move || {
                let packet = packet();
                let ns = Namespace::default();
                let graph = ns.graph.read().unwrap();
                let ctx = Context {
                    packet: &packet,
                    hook: 3,
                    input: 0,
                    output: 1,
                    tuple: crate::conntrack::key(&packet).unwrap().tuple,
                    track: None,
                    graph: &graph,
                    namespace: ns.id(),
                };
                start.wait();
                for _ in 0..2000 {
                    assert!(rules.read().unwrap().allows(&ctx));
                }
            });
        }
        let (rules, start) = (&rules, &start);
        scope.spawn(move || {
            start.wait();
            for index in 0..4 {
                assert_eq!(
                    errno(&shared_batch(rules, &[table(&format!("aux-{index}"))]).unwrap()),
                    0
                );
            }
        });
        start.wait();
    });
    let current = rules.read().unwrap();
    let chain = &current.tables[&(2, "filter".into())].chains["out"];
    let Expr::Counter { packets, bytes } = &chain.rules[0].expressions[0] else {
        panic!("counter")
    };
    assert_eq!(packets.get(), 8000);
    assert_eq!(bytes.get(), 8000 * packet().len() as u64);
    assert_eq!(current.generation, 6);
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
    let graph = ns.graph.read().unwrap();
    let packet = packet();
    graph.firewall(ns.id()).read().unwrap().allows(&Context {
        packet: &packet,
        hook,
        input: 3,
        output: 4,
        tuple: crate::conntrack::key(&packet).unwrap().tuple,
        track: None,
        graph: &graph,
        namespace: ns.id(),
    })
}
#[test]
fn batch_rollback_generation_authority_capacity_and_namespace_are_real() {
    let n = Namespace::default();
    let other = Namespace::default();
    let before = n.graph.read().unwrap().firewall(n.id());
    assert_eq!(
        errno(&batch(
            &n,
            &[table("filter"), chain("filter", "out", Some(3), 0, 0)]
        )),
        0
    );
    assert!(!allows(&n, 3));
    assert!(allows(&other, 3));
    assert_eq!(before.read().unwrap().generation, 2);
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
    assert_eq!(before.read().unwrap().generation, 2);
    assert_eq!(before.read().unwrap().tables.len(), 1);
    let mut gen = vec![];
    number(&mut gen, 1, 1);
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
    assert_eq!(before.read().unwrap().generation, 2);
    assert_eq!(before.read().unwrap().tables.len(), 1);
    // Explicit zero admits the batch regardless of the current generation.
    let mut any = vec![0, 0, 0, 10];
    number(&mut any, 1, 0);
    let begin = message(16, 1, 1, 0, &any);
    assert_eq!(
        errno(&request(&n, &[&begin, &create, &end], 1, true, 128, MAX_BYTES).unwrap()),
        0
    );
    assert_eq!(before.read().unwrap().generation, 3);
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
    let state = n.graph.read().unwrap().firewall(n.id());
    let state = state.read().unwrap();
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
fn packet_rule_matches(exprs: Vec<Expr>, ctx: &Context<'_>) -> bool {
    let mut rule = Rule {
        handle: 1,
        userdata: vec![],
        expressions: exprs,
        wire: vec![],
        compatibility: None,
    };
    rule.expressions.push(Expr::Verdict(1, None));
    rule.verdict(ctx, &mut Effects::default()) == Some((1, None))
}

#[test]
fn shifts_propagate_carries_across_overlapping_registers() {
    let ns = Namespace::default();
    let graph = ns.graph.read().unwrap();
    let packet = packet();
    let ctx = Context {
        packet: &packet,
        tuple: crate::conntrack::key(&packet).unwrap().tuple,
        hook: 0,
        input: 1,
        output: 0,
        graph: &graph,
        namespace: ns.id(),
        track: None,
    };
    let initial = [0x8000_0001u32, 0xc000_0002];
    for (left, bits, dest, expected) in [
        (true, 1, 4, [3u32, 0x8000_0004]),
        (false, 1, 0, [0x4000_0000, 0xe000_0001]),
        (false, 1, 4, [0x4000_0000, 0xa000_0000]),
        (false, 0, 0, initial),
    ] {
        let bytes = |v: [u32; 2]| {
            v.into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<u8>>()
        };
        assert!(packet_rule_matches(
            vec![
                Expr::Immediate {
                    dest: 0,
                    value: bytes(initial)
                },
                Expr::Shift {
                    src: 0,
                    dest,
                    len: 8,
                    left,
                    bits
                },
                Expr::Compare {
                    src: dest,
                    op: 0,
                    value: bytes(expected)
                },
            ],
            &ctx
        ));
    }
}
#[test]
fn fib_and_addrtype_use_packet_address_and_selected_guest_interface() {
    use crate::routing_tests::{assign, bridge};
    let root = Network::new(NetworkMode::Full);
    let net = root.isolated().unwrap();
    let wan = bridge(&net, b"wan");
    let lan = bridge(&net, b"lan");
    assign(&net, wan, "192.0.2.3", 24);
    assign(&net, lan, "198.51.100.1", 24);
    let graph = net.1.graph.read().unwrap();
    let packet = packet();
    let mut ctx = Context {
        packet: &packet,
        tuple: crate::conntrack::key(&packet).unwrap().tuple,
        hook: 0,
        input: wan,
        output: 0,
        graph: &graph,
        namespace: net.namespace_id(),
        track: None,
    };
    let fib = |ctx: &Context<'_>, result, flags, value: Vec<u8>| {
        packet_rule_matches(
            vec![
                Expr::Fib {
                    dest: 0,
                    result,
                    flags,
                },
                Expr::Compare {
                    src: 0,
                    op: 0,
                    value,
                },
            ],
            ctx,
        )
    };
    assert!(fib(&ctx, 1, 2, wan.to_le_bytes().to_vec()));
    assert!(fib(&ctx, 1, 2 | 32, 1u32.to_le_bytes().to_vec()));
    let mut name = vec![0; 16];
    name[..3].copy_from_slice(b"wan");
    assert!(fib(&ctx, 2, 2 | 8, name));
    assert!(fib(&ctx, 3, 1 | 8, 2u32.to_le_bytes().to_vec()));
    let addrtype = |ctx: &Context<'_>| {
        packet_rule_matches(
            vec![Expr::AddrType {
                source: 1 << 2,
                destination: 1 << 1,
                flags: 4,
            }],
            ctx,
        )
    };
    assert!(addrtype(&ctx));
    ctx.input = lan;
    assert!(fib(&ctx, 2, 2 | 8, vec![0; 16]));
    assert!(fib(&ctx, 3, 1 | 8, 1u32.to_le_bytes().to_vec()));
    assert!(!addrtype(&ctx));
    ctx.tuple.destination = "203.0.113.8:1".parse().unwrap();
    assert!(fib(&ctx, 1, 2 | 32, 0u32.to_le_bytes().to_vec()));
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
    assert!(n
        .graph
        .read()
        .unwrap()
        .firewall(n.id())
        .read()
        .unwrap()
        .tables
        .is_empty());
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
            &[table("f"), chain("f", "invalid", Some(5), 0, 0)]
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
        0
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
            .write()
            .unwrap()
            .route(
                n.namespace_id(),
                crate::netdev::Route {
                    onlink: false,
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
#[test]
fn native_root_input_and_output_policy_enforces_real_socket_io() {
    let root = Network::new(NetworkMode::Loopback);
    let receiver = root.socket(2, 2, 0).unwrap();
    receiver.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = receiver.local_addr().unwrap();
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        errno(&batch(
            &root.1,
            &[table("f"), chain("f", "input", Some(1), 0, 0)]
        )),
        0
    );
    let ready = || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while receiver.poll(1).unwrap() & 1 == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "native UDP delivery timed out"
            );
            std::thread::yield_now();
        }
    };
    peer.send_to(b"denied", address).unwrap();
    ready();
    assert!(matches!(receiver.recv(100, 0), Err(NetError(11))));
    assert_eq!(
        errno(&batch(&root.1, &[rule("f", "input", &verdict(1, None))])),
        0
    );
    peer.send_to(b"allowed", address).unwrap();
    ready();
    assert_eq!(receiver.recv(100, 0).unwrap().data, b"allowed");
    assert_eq!(
        errno(&batch(&root.1, &[chain("f", "output", Some(3), 0, 0)])),
        0
    );
    assert_eq!(
        receiver.send_bytes(
            b"outbound",
            0,
            Some(&crate::encode_address(peer.local_addr().unwrap()))
        ),
        Err(NetError(13))
    );
    assert_eq!(
        peer.recv(&mut [0; 10]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn captured_tcp_uses_live_policy_and_retains_original_socket_after_close() {
    use std::io::{Read, Write};
    let root = Network::new(NetworkMode::Loopback);
    let listener = root.socket(2, 1, 0).unwrap();
    listener.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    listener.listen(1).unwrap();
    let mut host = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    host.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    crate::wait(&[(listener.clone(), 1)], std::time::Duration::from_secs(1)).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let direct = accepted.direct_tcp().unwrap();
    let control = accepted.direct_control().unwrap();
    let lease = direct.retain().unwrap();
    assert!(lease.shares_socket(&control.retain().unwrap()));
    assert_eq!(direct.send(b"a", 0), Ok(1));
    let mut byte = [0];
    host.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"a");
    assert_eq!(
        errno(&batch(
            &root.1,
            &[
                table("tcp-guard"),
                chain("tcp-guard", "output", Some(3), 0, 1),
                rule("tcp-guard", "output", &expression("counter", &[]))
            ]
        )),
        0
    );
    assert!(accepted.direct_tcp().is_some());
    drop(accepted);
    assert_eq!(direct.send(b"b", 0), Ok(1));
    host.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"b");
    let rules = root.1.graph.read().unwrap().firewall(root.1.id());
    assert!(rules.has_rules());
    {
        let current = rules.read().unwrap();
        let e = &current.tables[&(2, "tcp-guard".into())].chains["output"].rules[0].expressions[0];
        assert!(
            matches!(e, Expr::Counter { packets, bytes } if packets.get() == 1 && bytes.get() > 1)
        );
    }
    assert_eq!(
        errno(&batch(
            &root.1,
            &[chain("tcp-guard", "output", Some(3), 0, 0)]
        )),
        0
    );
    assert_eq!(direct.send(b"blocked", 0), Err(NetError(13)));
    let mut attrs = vec![];
    string(&mut attrs, 1, "tcp-guard");
    assert_eq!(errno(&batch(&root.1, &[req(2, 2, 0, &attrs)])), 0);
    assert!(!rules.has_rules());
    assert_eq!(direct.send(b"c", 0), Ok(1));
    host.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"c");
    // Re-enable input DROP on this same pre-publication capability. The original
    // receive consumes the denied packet and shuts down the actual TCP endpoint.
    assert_eq!(
        errno(&batch(
            &root.1,
            &[table("input"), chain("input", "in", Some(1), 0, 0)]
        )),
        0
    );
    host.write_all(b"denied").unwrap();
    let (ready, _lease) = direct.readiness_fd().unwrap();
    let mut fds = [nix::poll::PollFd::new(
        std::os::fd::AsFd::as_fd(&ready),
        nix::poll::PollFlags::POLLIN,
    )];
    assert_eq!(
        nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(2000u16)).unwrap(),
        1
    );
    assert_eq!(direct.recv(100, 0), Err(NetError(13)));
    assert_eq!(host.read(&mut byte).unwrap(), 0);
    drop(lease);
    drop(_lease);
    assert_eq!(direct.send(b"stale", 0), Err(NetError(9)));
    drop(listener);
    let namespace = std::sync::Arc::downgrade(&root.1);
    drop(root);
    assert!(
        namespace.upgrade().is_none(),
        "weak capabilities must not pin namespace lifetime"
    );
}

#[test]
fn tun_and_packet_injection_obey_ip_port_firewall_and_tap_precedes_input_drop() {
    use crate::routing_tests::{assign, bridge, pair};
    let root = Network::new(NetworkMode::Full);
    let a = root.isolated().unwrap();
    let b = root.isolated().unwrap();
    let br = bridge(&root, b"fw-packet");
    let ai = pair(&root, &a, b"fw-a", br);
    let bi = pair(&root, &b, b"fw-b", br);
    assign(&a, ai, "192.0.2.10", 24);
    assign(&b, bi, "192.0.2.20", 24);
    let tun = b.open_tun();
    tun.attach(b"tun0", 0x1001, true).unwrap();
    let ti = b
        .devices()
        .into_iter()
        .find(|d| d.name == b"tun0")
        .unwrap()
        .index;
    assign(&b, ti, "198.51.100.1", 24);
    let tap = b.socket(17, 2, 0x0800u16.to_be() as u32).unwrap();
    let rx = b.socket(2, 2, 0).unwrap();
    rx.bind("0.0.0.0:7002".parse().unwrap()).unwrap();
    let mut payload = vec![];
    number(&mut payload, 1, 1);
    number(&mut payload, 2, 2);
    number(&mut payload, 3, 2);
    number(&mut payload, 4, 2);
    let mut v = vec![];
    attr(&mut v, 1, &7002u16.to_be_bytes());
    let mut cmp = vec![];
    number(&mut cmp, 1, 1);
    number(&mut cmp, 2, 0);
    attr(&mut cmp, 3 | 0x8000, &v);
    let mut e = expression("payload", &payload);
    e.extend(expression("cmp", &cmp));
    e.extend(verdict(0, None));
    assert_eq!(
        errno(&batch(
            &b.1,
            &[
                table("packet-fw"),
                chain("packet-fw", "input", Some(1), 0, 1),
                rule("packet-fw", "input", &e)
            ]
        )),
        0
    );
    let dropped = crate::packet_tests::udp4("198.51.100.2", "198.51.100.1", 7001, 7002, b"drop");
    tun.write(&dropped).unwrap();
    assert_eq!(rx.poll(1), Ok(0));
    assert_eq!(tap.recv(100, 0).unwrap().data, dropped);
    let mut allowed =
        crate::packet_tests::udp4("198.51.100.2", "198.51.100.1", 7001, 7003, b"allow");
    let rx_allowed = b.socket(2, 2, 0).unwrap();
    rx_allowed.bind("0.0.0.0:7003".parse().unwrap()).unwrap();
    tun.write(&allowed).unwrap();
    assert_eq!(rx_allowed.recv(100, 0).unwrap().data, b"allow");
    let _ = tap.recv(100, 0).unwrap();
    let injector = a.socket(17, 2, 0x0800u16.to_be() as u32).unwrap();
    let mac = b.devices().into_iter().find(|d| d.index == bi).unwrap().mac;
    let destination = crate::packet_socket::address(ai, 0x800, 0, mac);
    allowed = crate::packet_tests::udp4("192.0.2.10", "192.0.2.20", 7001, 7002, b"drop raw");
    injector
        .send_bytes(&allowed, 0, Some(&destination))
        .unwrap();
    assert_eq!(rx.poll(1), Ok(0));
    assert_eq!(tap.recv(100, 0).unwrap().data, allowed);
}

#[test]
fn udp_group_traffic_uses_guest_links_memberships_and_namespace_hooks() {
    let fabric = crate::Fabric::new().unwrap();
    let sender_net = Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
    let peer = Network::virtual_network(&fabric, 3, NetworkMode::Outbound).unwrap();
    let sender = sender_net.socket(2, 2, 0).unwrap();
    let group = [239, 8, 1, 7];
    let dest = "239.8.1.7:18307".parse().unwrap();
    let bind = "0.0.0.0:18307".parse().unwrap();
    let join = |network: &Network, addr: [u8; 4]| {
        let rx = network.socket(2, 2, 0).unwrap();
        rx.set_option(1, 2, 1).unwrap();
        rx.bind(bind).unwrap();
        rx.set_option_bytes(0, 35, &[group, addr].concat()).unwrap();
        rx.set_option(0, 8, 1).unwrap();
        rx.set_option(0, 12, 1).unwrap();
        rx
    };
    let local = join(&sender_net, [10, 0, 0, 2]);
    let remote = join(&peer, [10, 0, 0, 3]);
    let wrong_link = join(&peer, [127, 0, 0, 1]);
    wrong_link.set_option(0, 49, 0).unwrap();
    sender.set_option_bytes(0, 32, &[10, 0, 0, 2]).unwrap();
    sender.set_option(0, 33, 7).unwrap();
    sender.set_option(0, 34, 0).unwrap();
    let data = vec![0x23; 6113];
    sender.send(&data, 0, Some(dest)).unwrap();
    let packet = remote.recv(data.len(), 0).unwrap();
    assert_eq!(packet.data, data);
    assert_eq!(packet.ip.fields.hop_limit, Some(7));
    let info = packet.packet_info.unwrap();
    assert_eq!(info.interface, 2);
    assert_eq!(info.address, dest.ip());
    assert_eq!(packet.ip.spec_destination, Some([10, 0, 0, 3].into()));
    assert!(matches!(local.recv(9, 0), Err(crate::NetError(11))));
    assert!(matches!(wrong_link.recv(9, 0), Err(crate::NetError(11))));

    sender.set_option(0, 34, 1).unwrap();
    sender.set_option(0, 33, 0).unwrap();
    sender.send(b"local", 0, Some(dest)).unwrap();
    assert_eq!(local.recv(9, 0).unwrap().data, b"local");
    assert!(matches!(remote.recv(9, 0), Err(crate::NetError(11))));

    sender.set_option(0, 33, 1).unwrap();
    assert_eq!(
        errno(&batch(
            &peer.1,
            &[table("filter"), chain("filter", "input", Some(1), 0, 0)]
        )),
        0
    );
    sender.send(b"input", 0, Some(dest)).unwrap();
    assert_eq!(local.recv(9, 0).unwrap().data, b"input");
    assert!(matches!(remote.recv(9, 0), Err(crate::NetError(11))));
    assert_eq!(
        errno(&batch(
            &sender_net.1,
            &[table("filter"), chain("filter", "out", Some(3), 0, 0)]
        )),
        0
    );
    sender.send(b"output", 0, Some(dest)).unwrap();
    assert!(matches!(local.recv(9, 0), Err(crate::NetError(11))));
}
