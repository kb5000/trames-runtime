// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[path = "icmp_gateway.rs"]
mod icmp_gateway;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, IpRepr, Ipv4Repr, Ipv6Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};
const FLOWS: usize = 64;
struct TcpFlow {
    node: u64,
    tuple: Tuple,
    native: Rc<native::Socket>,
    handle: Option<SocketHandle>,
    syn: Option<Vec<u8>>,
    owner: Weak<Socket>,
    native_eof: bool,
    write_shutdown: bool,
    last: Instant,
}

struct UdpFlow {
    node: u64,
    tuple: Tuple,
    native: Rc<native::Socket>,
    owner: Weak<Socket>,
    pending: Option<Vec<u8>>,
    last: Instant,
}
struct DnsTcp {
    handle: SocketHandle,
    input: Vec<u8>,
    output: Vec<u8>,
    token: Option<u64>,
    last: Instant,
}
#[derive(Clone)]
enum ReplyTo {
    Udp {
        node: u64,
        handle: SocketHandle,
        peer: IpEndpoint,
    },
    Tcp {
        handle: SocketHandle,
    },
}
struct PendingDns {
    token: u64,
    question: Vec<u8>,
    to: ReplyTo,
    expires: Instant,
}
#[derive(Clone)]
struct RoutedFlow {
    node: u64,
    original: crate::conntrack::Key,
    view: crate::netdev::View,
    input: u32,
    last: Instant,
}
pub(super) struct Gateway {
    pub node: Node,
    pub mappings: BTreeMap<IpAddr, IpAddr>,
    routed: BTreeMap<crate::conntrack::Key, RoutedFlow>,
    native: native::Network,
    tcp: Vec<TcpFlow>,
    udp: Vec<UdpFlow>,
    udp_handles: BTreeMap<SocketAddr, SocketHandle>,
    dns_udp: Vec<SocketHandle>,
    dns_tcp: Vec<DnsTcp>,
    resolver: dns::Resolver,
    pending_dns: Vec<PendingDns>,
    icmp: Vec<icmp_gateway::Flow>,
}
impl Gateway {
    pub fn new() -> Result<Self> {
        let mut node = make_node(1, smoltcp::time::Instant::ZERO)?;
        let mut dns_udp = Vec::new();
        let mut dns_tcp = Vec::new();
        for address in [
            SocketAddr::new(v4(1).into(), 53),
            SocketAddr::new(v6(1).into(), 53),
        ] {
            let mut u = udp_socket();
            u.bind(endpoint(address)).unwrap();
            dns_udp.push(node.sockets.add(u));
            for _ in 0..2 {
                let mut t = tcp_socket();
                t.listen(endpoint(address)).unwrap();
                dns_tcp.push(DnsTcp {
                    handle: node.sockets.add(t),
                    input: Vec::new(),
                    output: Vec::new(),
                    token: None,
                    last: Instant::now(),
                });
            }
        }
        Ok(Self {
            node,
            mappings: BTreeMap::new(),
            routed: BTreeMap::new(),
            native: native::Network::new(NetworkMode::Outbound),
            tcp: Vec::new(),
            udp: Vec::new(),
            udp_handles: BTreeMap::new(),
            dns_udp,
            dns_tcp,
            resolver: dns::Resolver::new(),
            pending_dns: Vec::new(),
            icmp: Vec::new(),
        })
    }
    pub fn route_flow(
        &mut self,
        wire: crate::conntrack::Key,
        original: crate::conntrack::Key,
        node: u64,
        view: crate::netdev::View,
        input: u32,
    ) -> bool {
        if self.routed.len() >= 128 && !self.routed.contains_key(&wire) {
            return false;
        }
        self.routed.insert(
            wire,
            RoutedFlow {
                node,
                original,
                view,
                input,
                last: Instant::now(),
            },
        );
        true
    }
    pub fn reply_route(&mut self, packet: &[u8]) -> Option<(crate::netdev::View, u32)> {
        let key = crate::conntrack::key(packet)?.reverse();
        let flow = self.routed.get_mut(&key)?;
        flow.last = Instant::now();
        Some((flow.view.clone(), flow.input))
    }
    pub fn pending_handles(&self) -> usize {
        self.tcp.iter().filter(|f| f.handle.is_none()).count()
    }
    pub fn flow_count(&self) -> usize {
        self.tcp.len() + self.udp.len() + self.icmp.len()
    }
    fn owner(
        &self,
        nodes: &BTreeMap<u64, Node>,
        key: u64,
        tuple: Tuple,
        kind: u32,
    ) -> Weak<Socket> {
        let protocol = if kind == 1 { 6 } else { 17 };
        let tuple = self
            .routed
            .get(&crate::conntrack::Key { protocol, tuple })
            .map_or(tuple, |r| r.original.tuple);
        nodes
            .get(&key)
            .and_then(|n| {
                n.registry.iter().filter_map(Weak::upgrade).find(|s| {
                    if s.kind != kind {
                        return false;
                    }
                    let state = s.state.borrow();
                    state.bound.is_some_and(|a| {
                        a.port() == tuple.source.port()
                            && (a.ip().is_unspecified() || a.ip() == tuple.source.ip())
                    }) && (kind == 2 || state.peer == Some(tuple.destination))
                })
            })
            .map(|s| Rc::downgrade(&s))
            .unwrap_or_default()
    }
    pub fn ingress(
        &mut self,
        key: u64,
        p: Vec<u8>,
        h: &packet::Header,
        nodes: &BTreeMap<u64, Node>,
        now: smoltcp::time::Instant,
        can_add: bool,
    ) -> bool {
        let Some(ns) = nodes.get(&key).and_then(|n| n.owner.upgrade()) else {
            return false;
        };
        if ns.finished.get() || !matches!(ns.mode, NetworkMode::Outbound | NetworkMode::Full) {
            return false;
        }
        let tuple = h.tuple;
        let dest = tuple.destination;

        if !crate::conntrack::key(&p).is_some_and(|k| self.routed.contains_key(&k))
            && (dest.ip() == IpAddr::V4(v4(1)) || dest.ip() == IpAddr::V6(v6(1)))
        {
            return self.node.port.receive_packet(p);
        }
        if h.protocol == 6 && h.first {
            let Ok(t) = TcpPacket::new_checked(&p[h.offset..]) else {
                return false;
            };
            if !t.verify_checksum(&ip(tuple.source.ip()), &ip(dest.ip())) {
                return false;
            }
            if !self.tcp.iter().any(|f| f.node == key && f.tuple == tuple) && t.syn() && !t.ack() {
                if !can_add || self.flow_count() >= FLOWS {
                    return false;
                }
                let owner = self.owner(nodes, key, tuple, 1);
                if owner.strong_count() == 0 {
                    return false;
                }
                let actual = SocketAddr::new(
                    self.mappings.get(&dest.ip()).copied().unwrap_or(dest.ip()),
                    dest.port(),
                );
                let family = if actual.is_ipv4() { 2 } else { 10 };
                let Ok(native) = self.native.socket(family, 1, 6) else {
                    return false;
                };
                match native.connect(actual) {
                    Ok(()) | Err(NetError(115)) => {}
                    Err(e) => {
                        if let Some(s) = owner.upgrade() {
                            let mut state = s.state.borrow_mut();
                            state.error = Some(e.0);
                            state.connection = Connection::Failed(e.0);
                        }
                        self.reset(&p, h);
                        return true;
                    }
                }
                self.tcp.push(TcpFlow {
                    node: key,
                    tuple,
                    native,
                    handle: None,
                    syn: Some(p),
                    owner,
                    native_eof: false,
                    write_shutdown: false,
                    last: Instant::now(),
                });
                return true;
            }
            if let Some(f) = self.tcp.iter().find(|f| f.node == key && f.tuple == tuple) {
                if f.handle.is_none() {
                    return true;
                }
            }
            self.node.port.receive_packet(p)
        } else if h.protocol == 17 {
            if h.first && !self.udp_handles.contains_key(&dest) {
                if !can_add || self.udp_handles.len() >= FLOWS {
                    return false;
                }
                let mut u = udp_socket();
                if u.bind(endpoint(dest)).is_err() {
                    return false;
                }
                self.udp_handles.insert(dest, self.node.sockets.add(u));
            }
            let accepted = self.node.port.receive_packet(p);
            self.node
                .iface
                .poll(now, &mut self.node.port, &mut self.node.sockets);
            accepted
        } else if matches!(h.protocol, 1 | 58) {
            self.icmp_ingress(key, &p, h, nodes)
        } else {
            false
        }
    }
    fn reset(&mut self, p: &[u8], h: &packet::Header) {
        let Ok(t) = TcpPacket::new_checked(&p[h.offset..]) else {
            return;
        };
        let tuple = h.tuple;
        let repr = TcpRepr {
            src_port: tuple.destination.port(),
            dst_port: tuple.source.port(),
            control: TcpControl::Rst,
            seq_number: TcpSeqNumber(0),
            ack_number: Some(t.seq_number() + 1),
            window_len: 0,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload: &[],
        };
        let iprepr = match (tuple.destination.ip(), tuple.source.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => IpRepr::Ipv4(Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Tcp,
                payload_len: repr.header_len(),
                hop_limit: 64,
            }),
            (IpAddr::V6(s), IpAddr::V6(d)) => IpRepr::Ipv6(Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Tcp,
                payload_len: repr.header_len(),
                hop_limit: 64,
            }),
            _ => return,
        };
        let mut bytes = vec![0; iprepr.buffer_len() + repr.header_len()];
        iprepr.emit(
            &mut bytes[..iprepr.buffer_len()],
            &ChecksumCapabilities::default(),
        );
        repr.emit(
            &mut TcpPacket::new_unchecked(&mut bytes[iprepr.buffer_len()..]),
            &ip(tuple.destination.ip()),
            &ip(tuple.source.ip()),
            &ChecksumCapabilities::default(),
        );
        self.node.port.tx.push_back(bytes);
    }
    pub fn service(&mut self, now: smoltcp::time::Instant, nodes: &BTreeMap<u64, Node>) {
        self.routed.retain(|_, r| {
            nodes.contains_key(&r.node) && r.last.elapsed() < Duration::from_secs(600)
        });
        self.icmp_service(nodes);
        let mut gone = Vec::new();
        let mut failures = Vec::new();
        for (index, flow) in self.tcp.iter_mut().enumerate() {
            // A live guest socket may be idle or hold a closed receive window
            // while unpacking a large response. Its lifetime belongs to the
            // socket/protocol, not a gateway activity timer. Bound only orphans.
            if !nodes.contains_key(&flow.node)
                || (flow.owner.strong_count() == 0 && flow.last.elapsed() > Duration::from_secs(30))
            {
                gone.push(index);
                continue;
            }
            if flow.handle.is_none() {
                match flow.native.connect_complete() {
                    Ok(false) => continue,
                    Err(e) => {
                        if let Some(s) = flow.owner.upgrade() {
                            let mut state = s.state.borrow_mut();
                            state.error = Some(e.0);
                            state.connection = Connection::Failed(e.0);
                        }
                        if let Some(p) = flow.syn.take() {
                            failures.push(p);
                        }
                        gone.push(index);
                        continue;
                    }
                    Ok(true) => {}
                }
                let mut t = tcp_socket();
                if t.listen(endpoint(flow.tuple.destination)).is_err() {
                    gone.push(index);
                    continue;
                }
                let handle = self.node.sockets.add(t);
                flow.handle = Some(handle);
                if let Some(p) = flow.syn.take() {
                    self.node.port.receive_packet(p);
                    self.node
                        .iface
                        .poll(now, &mut self.node.port, &mut self.node.sockets);
                }
            }
            let t = self
                .node
                .sockets
                .get_mut::<tcp::Socket>(flow.handle.unwrap());
            if matches!(t.state(), tcp::State::Listen | tcp::State::SynReceived) {
                continue;
            }
            t.set_timeout(None);
            if t.state() == tcp::State::Closed {
                gone.push(index);
                continue;
            }
            if t.can_recv() {
                let data = t.peek(t.recv_queue().min(BUFFER)).unwrap();
                match flow.native.send(data, 0, None) {
                    Ok(n) => {
                        let _ = t.recv(|_| (n, ()));
                        flow.last = Instant::now();
                    }
                    Err(NetError(11)) => {}
                    Err(_) => {
                        t.abort();
                        gone.push(index);
                        continue;
                    }
                }
            }
            if !t.may_recv() && !flow.write_shutdown {
                let _ = flow.native.shutdown(1);
                flow.write_shutdown = true;
            }
            let room = t.send_capacity() - t.send_queue();
            if !flow.native_eof && t.may_send() && room > 0 {
                match flow.native.recv(room.min(BUFFER), 0) {
                    Ok(r) => {
                        if r.data.is_empty() {
                            flow.native_eof = true;
                            t.close();
                        } else {
                            let n = t.send_slice(&r.data).unwrap_or(0);
                            debug_assert_eq!(n, r.data.len());
                            flow.last = Instant::now();
                        }
                    }
                    Err(NetError(11)) => {}
                    Err(_) => {
                        t.abort();
                        gone.push(index);
                    }
                }
            }
        }
        // Flush an abort's RST before freeing its state.
        self.node
            .iface
            .poll(now, &mut self.node.port, &mut self.node.sockets);
        for index in gone.into_iter().rev() {
            let f = self.tcp.remove(index);
            let _ = f.native.shutdown(2);
            if let Some(h) = f.handle {
                self.node.sockets.remove(h);
            }
        }
        for p in failures {
            if let Some(h) = packet::header(&p) {
                self.reset(&p, &h);
            }
        }
        let handles: Vec<_> = self.udp_handles.iter().map(|(a, h)| (*a, *h)).collect();
        for (destination, h) in handles {
            for _ in 0..16 {
                let packet = match self.node.sockets.get_mut::<udp::Socket>(h).recv() {
                    Ok((data, meta)) => Some((data.to_vec(), address(meta.endpoint))),
                    Err(_) => None,
                };
                let Some((data, source)) = packet else {
                    break;
                };
                let tuple = Tuple {
                    source,
                    destination,
                };
                let node = self
                    .routed
                    .get(&crate::conntrack::Key {
                        protocol: 17,
                        tuple,
                    })
                    .map(|r| r.node)
                    .or_else(|| {
                        nodes
                            .iter()
                            .find(|(_, n)| {
                                source.ip() == IpAddr::V4(v4(n.id))
                                    || source.ip() == IpAddr::V6(v6(n.id))
                            })
                            .map(|(&key, _)| key)
                    });
                let Some(node) = node else {
                    continue;
                };
                let position = if let Some(index) = self
                    .udp
                    .iter()
                    .position(|f| f.node == node && f.tuple == tuple)
                {
                    index
                } else {
                    if self.flow_count() >= FLOWS {
                        continue;
                    }
                    let owner = self.owner(nodes, node, tuple, 2);
                    if owner.strong_count() == 0 {
                        continue;
                    }
                    let actual = SocketAddr::new(
                        self.mappings
                            .get(&destination.ip())
                            .copied()
                            .unwrap_or(destination.ip()),
                        destination.port(),
                    );
                    let Ok(native) =
                        self.native
                            .socket(if actual.is_ipv4() { 2 } else { 10 }, 2, 17)
                    else {
                        continue;
                    };
                    if native.connect(actual).is_err() {
                        continue;
                    }
                    self.udp.push(UdpFlow {
                        node,
                        tuple,
                        native,
                        owner,
                        pending: None,
                        last: Instant::now(),
                    });
                    self.udp.len() - 1
                };
                let flow = &mut self.udp[position];
                if flow.pending.is_some() {
                    continue;
                }
                match flow.native.send(&data, 0, None) {
                    Ok(_) => flow.last = Instant::now(),
                    Err(NetError(11)) => flow.pending = Some(data),
                    Err(_) => {}
                }
            }
        }
        self.udp.retain_mut(|f| {
            if !nodes.contains_key(&f.node)
                || f.owner.strong_count() == 0
                || f.last.elapsed() > Duration::from_secs(60)
            {
                return false;
            }
            if let Some(data) = f.pending.take() {
                match f.native.send(&data, 0, None) {
                    Ok(_) => f.last = Instant::now(),
                    Err(NetError(11)) => f.pending = Some(data),
                    Err(_) => return false,
                }
            }
            let Some(&h) = self.udp_handles.get(&f.tuple.destination) else {
                return false;
            };
            let u = self.node.sockets.get_mut::<udp::Socket>(h);
            if u.can_send() {
                for _ in 0..4 {
                    match f.native.recv(65535, 0) {
                        Ok(r) => {
                            if u.send_slice(&r.data, endpoint(f.tuple.source)).is_err() {
                                break;
                            }
                            f.last = Instant::now();
                        }
                        Err(NetError(11)) => break,
                        Err(_) => return false,
                    }
                }
            }
            true
        });
        let unused: Vec<_> = self
            .udp_handles
            .keys()
            .filter(|a| {
                !self.udp.iter().any(|f| f.tuple.destination == **a)
                    && !self
                        .node
                        .sockets
                        .get::<udp::Socket>(self.udp_handles[*a])
                        .can_recv()
            })
            .copied()
            .collect();
        // Keep endpoints briefly for in-flight fragment reassembly; reclaim when near the cap.
        if self.udp_handles.len() > 32 {
            for a in unused {
                let h = self.udp_handles.remove(&a).unwrap();
                self.node.sockets.remove(h);
            }
        }
        self.dns_service(nodes);
    }
    pub fn waiters(&self) -> Vec<(Rc<native::Socket>, u16)> {
        let mut waiters = Vec::new();
        waiters.extend(
            self.icmp
                .iter()
                .map(|f| (f.native.clone(), if f.pending.is_some() { 5 } else { 1 })),
        );
        for f in &self.tcp {
            let events = if let Some(h) = f.handle {
                let t = self.node.sockets.get::<tcp::Socket>(h);
                u16::from(!f.native_eof && t.may_send() && t.send_queue() < t.send_capacity())
                    | if t.can_recv() { 4 } else { 0 }
            } else {
                4
            };
            if events != 0 {
                waiters.push((f.native.clone(), events));
            }
        }
        for f in &self.udp {
            let mut events = if f.pending.is_some() { 4 } else { 0 };
            if self
                .udp_handles
                .get(&f.tuple.destination)
                .is_some_and(|h| self.node.sockets.get::<udp::Socket>(*h).can_send())
            {
                events |= 1;
            }
            if events != 0 {
                waiters.push((f.native.clone(), events));
            }
        }
        waiters
    }
    pub fn close_node(&mut self, key: u64) {
        self.routed.retain(|_, r| r.node != key);
        self.tcp.retain(|f| {
            if f.node == key {
                let _ = f.native.shutdown(2);
                if let Some(h) = f.handle {
                    self.node.sockets.remove(h);
                }
                false
            } else {
                true
            }
        });
        self.udp.retain(|f| f.node != key);
        self.icmp.retain(|f| f.node != key);
        self.pending_dns
            .retain(|p| !matches!(p.to,ReplyTo::Udp{node,..} if node==key));
    }
    fn dns_reply(&mut self, to: &ReplyTo, data: Vec<u8>) {
        match *to {
            ReplyTo::Udp { handle, peer, .. } => {
                let _ = self
                    .node
                    .sockets
                    .get_mut::<udp::Socket>(handle)
                    .send_slice(&data, peer);
            }
            ReplyTo::Tcp { handle } => {
                if let Some(s) = self.dns_tcp.iter_mut().find(|s| s.handle == handle) {
                    s.token = None;
                    s.output = (data.len() as u16).to_be_bytes().to_vec();
                    s.output.extend_from_slice(&data);
                }
            }
        }
    }
    fn dns_query(&mut self, packet: Vec<u8>, to: ReplyTo, nodes: &BTreeMap<u64, Node>) {
        let limit = if matches!(to, ReplyTo::Udp { .. }) {
            512
        } else {
            4096
        };
        let q = match dns::parse(&packet) {
            Ok(q) => q,
            Err(code) => {
                self.dns_reply(&to, dns::answer(&packet, &[], code, limit));
                return;
            }
        };
        let local = if q.name == "gateway.trames" {
            Some(vec![v4(1).into(), v6(1).into()])
        } else if q.name == "localhost" {
            Some(vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()])
        } else if let Some(id) = q
            .name
            .strip_prefix("env")
            .and_then(|n| n.strip_suffix(".trames"))
            .and_then(|n| n.parse::<u8>().ok())
        {
            Some(if nodes.values().any(|n| n.id == id) {
                vec![v4(id).into(), v6(id).into()]
            } else {
                Vec::new()
            })
        } else if q.name.ends_with(".trames") {
            Some(Vec::new())
        } else {
            None
        };
        if let Some(ips) = local {
            self.dns_reply(
                &to,
                dns::answer(&packet, &ips, if ips.is_empty() { 3 } else { 0 }, limit),
            );
            return;
        }
        if self.pending_dns.len() >= 8 {
            self.dns_reply(&to, dns::answer(&packet, &[], 2, limit));
            return;
        }
        if let Some(token) = self.resolver.query(&q) {
            if let ReplyTo::Tcp { handle } = to {
                if let Some(s) = self.dns_tcp.iter_mut().find(|s| s.handle == handle) {
                    s.token = Some(token);
                }
            }
            self.pending_dns.push(PendingDns {
                token,
                question: packet,
                to,
                expires: Instant::now() + Duration::from_secs(10),
            });
        } else {
            self.dns_reply(&to, dns::answer(&packet, &[], 2, limit));
        }
    }
    fn dns_service(&mut self, nodes: &BTreeMap<u64, Node>) {
        let mut queries = Vec::new();
        for &h in &self.dns_udp {
            for _ in 0..16 {
                let u = self.node.sockets.get_mut::<udp::Socket>(h);
                let Ok((data, meta)) = u.recv() else {
                    break;
                };
                let source = address(meta.endpoint);
                if let Some((&node, _)) = nodes.iter().find(|(_, n)| {
                    source.ip() == IpAddr::V4(v4(n.id)) || source.ip() == IpAddr::V6(v6(n.id))
                }) {
                    queries.push((
                        data.to_vec(),
                        ReplyTo::Udp {
                            node,
                            handle: h,
                            peer: meta.endpoint,
                        },
                    ));
                }
            }
        }
        for session in &mut self.dns_tcp {
            let t = self.node.sockets.get_mut::<tcp::Socket>(session.handle);
            if t.state() == tcp::State::Closed || session.last.elapsed() > Duration::from_secs(30) {
                let local = t
                    .local_endpoint()
                    .map(address)
                    .unwrap_or(SocketAddr::new(v4(1).into(), 53));
                t.abort();
                let _ = t.listen(endpoint(local));
                session.input.clear();
                session.output.clear();
                session.token = None;
                session.last = Instant::now();
                continue;
            }
            if session.output.is_empty() && session.token.is_none() && t.can_recv() {
                let room = 4098 - session.input.len();
                if room == 0 {
                    t.abort();
                    continue;
                }
                let mut bytes = vec![0; room.min(t.recv_queue())];
                if let Ok(n) = t.recv_slice(&mut bytes) {
                    session.input.extend_from_slice(&bytes[..n]);
                    session.last = Instant::now();
                }
            }
            if session.input.len() >= 2 && session.token.is_none() && session.output.is_empty() {
                let size = u16::from_be_bytes([session.input[0], session.input[1]]) as usize;
                if !(12..=4096).contains(&size) {
                    t.abort();
                    continue;
                }
                if session.input.len() >= size + 2 {
                    let q = session.input[2..size + 2].to_vec();
                    session.input.drain(..size + 2);
                    queries.push((
                        q,
                        ReplyTo::Tcp {
                            handle: session.handle,
                        },
                    ));
                }
            }
            if !session.output.is_empty() && t.can_send() {
                if let Ok(n) = t.send_slice(&session.output) {
                    session.output.drain(..n);
                    session.last = Instant::now();
                }
            }
            if matches!(
                t.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
            ) && session.output.is_empty()
                && session.token.is_none()
                && !t.is_listening()
            {
                t.close();
            }
        }
        for (q, to) in queries {
            self.dns_query(q, to, nodes);
        }
        while let Some((token, response)) = self.resolver.result() {
            if let Some(index) = self.pending_dns.iter().position(|p| p.token == token) {
                let p = self.pending_dns.remove(index);
                if let ReplyTo::Tcp { handle } = p.to {
                    if !self
                        .dns_tcp
                        .iter()
                        .any(|s| s.handle == handle && s.token == Some(token))
                    {
                        continue;
                    }
                }
                let limit = if matches!(p.to, ReplyTo::Udp { .. }) {
                    512
                } else {
                    4096
                };
                self.dns_reply(&p.to, response.answer(&p.question, limit));
            }
        }
        let expired: Vec<_> = self
            .pending_dns
            .iter()
            .enumerate()
            .filter(|(_, p)| p.expires <= Instant::now())
            .map(|(i, _)| i)
            .collect();
        for i in expired.into_iter().rev() {
            let p = self.pending_dns.remove(i);
            if let ReplyTo::Tcp { handle } = p.to {
                if !self
                    .dns_tcp
                    .iter()
                    .any(|s| s.handle == handle && s.token == Some(p.token))
                {
                    continue;
                }
            }
            self.dns_reply(&p.to, dns::answer(&p.question, &[], 2, 512));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn until<T>(socket: &Rc<crate::Socket>, mut operation: impl FnMut() -> Result<T>) -> T {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            match operation() {
                Ok(value) => return value,
                Err(NetError(11)) => {}
                Err(error) => panic!("{error}"),
            }
            assert!(Instant::now() < end, "gateway test timed out");
            crate::wait(&[(socket.clone(), 1 | 4)], Duration::from_millis(2)).unwrap();
        }
    }

    #[test]
    fn live_tcp_backpressure_survives_idle_sweep_and_orphan_is_reaped() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let payload: Vec<_> = (0..3 * BUFFER + 17).map(|i| (i % 251) as u8).collect();
        let (release, released) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let bytes = &payload;
            scope.spawn(move || {
                let (mut peer, _) = listener.accept().unwrap();
                peer.set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                peer.write_all(bytes).unwrap();
                if released.recv_timeout(Duration::from_secs(5)).is_ok() {
                    peer.write_all(b"tail").unwrap();
                }
            });
            let fabric = Fabric::new().unwrap();
            fabric
                .map_host_ip("198.18.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap())
                .unwrap();
            let network =
                crate::Network::virtual_network(&fabric, 2, NetworkMode::Outbound).unwrap();
            let client = network.socket(2, 1, 0).unwrap();
            assert_eq!(
                client.connect(SocketAddr::new("198.18.0.1".parse().unwrap(), port)),
                Err(NetError(115))
            );
            until(&client, || {
                if client.connect_complete()? {
                    Ok(())
                } else {
                    Err(NetError(11))
                }
            });
            // Do not consume guest bytes until both receive and gateway send
            // buffers are full. This exercises real TCP zero-window pressure.
            until(&client, || {
                let mut inner = fabric.0.borrow_mut();
                inner.tick();
                let flow = &inner.gateway.tcp[0];
                let tcp = inner
                    .gateway
                    .node
                    .sockets
                    .get::<tcp::Socket>(flow.handle.unwrap());
                if tcp.send_queue() == tcp.send_capacity() {
                    Ok(())
                } else {
                    Err(NetError(11))
                }
            });
            {
                let mut inner = fabric.0.borrow_mut();
                assert_eq!(inner.gateway.tcp.len(), 1);
                assert!(inner.gateway.tcp[0].owner.strong_count() > 0);
                // Age only the sweep clock, without sleeping or changing the
                // protocol clock/sequence state of either real endpoint.
                inner.gateway.tcp[0].last -= Duration::from_secs(121);
                inner.tick();
                assert_eq!(
                    inner.gateway.tcp.len(),
                    1,
                    "live TCP flow expired under backpressure"
                );
            }
            release.send(()).unwrap();
            let mut received = Vec::new();
            loop {
                let chunk = until(&client, || client.recv(BUFFER, 0));
                if chunk.data.is_empty() {
                    break;
                }
                received.extend_from_slice(&chunk.data);
            }
            assert_eq!(&received[..payload.len()], &payload);
            assert_eq!(&received[payload.len()..], b"tail");
            drop(client);
            let mut inner = fabric.0.borrow_mut();
            for flow in &mut inner.gateway.tcp {
                flow.last -= Duration::from_secs(31);
            }
            inner.tick();
            assert!(inner.gateway.tcp.is_empty(), "orphaned TCP flow leaked");
        });
    }
}
