// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
impl Socket {
    pub fn info(&self) -> crate::SocketInfo {
        let state = self.state.borrow();
        let fabric = self.network.0.fabric.0.borrow();
        let mut code = if state.peer.is_some() { 1 } else { 7 };
        let (mut tx, mut rx) = (0, 0);
        if let Some(n) = fabric.nodes.get(&self.network.0.key) {
            for h in &state.handles {
                let (a, b) = match self.kind {
                    1 => {
                        let s = n.sockets.get::<tcp::Socket>(*h);
                        code = if state.connection == Connection::Listening {
                            10
                        } else {
                            match s.state() {
                                tcp::State::Established => 1,
                                tcp::State::SynSent => 2,
                                tcp::State::SynReceived => 3,
                                tcp::State::FinWait1 => 4,
                                tcp::State::FinWait2 => 5,
                                tcp::State::TimeWait => 6,
                                tcp::State::Closed => 7,
                                tcp::State::CloseWait => 8,
                                tcp::State::LastAck => 9,
                                tcp::State::Listen => 10,
                                tcp::State::Closing => 11,
                            }
                        };
                        (s.send_queue(), s.recv_queue())
                    }
                    2 => {
                        let s = n.sockets.get::<udp::Socket>(*h);
                        (s.send_queue(), s.recv_queue())
                    }
                    3 => {
                        let s = n.sockets.get::<icmp::Socket>(*h);
                        (s.send_queue(), s.recv_queue())
                    }
                    _ => {
                        let s = n.sockets.get::<raw::Socket>(*h);
                        (s.send_queue(), s.recv_queue())
                    }
                };
                tx += a;
                rx += b;
            }
        }
        rx += state.icmp_pending.as_ref().map_or(0, |p| p.0.len());
        crate::SocketInfo {
            namespace_id: 0, // Filled by the public socket wrapper.
            family: self.family,
            kind: if self.kind == 4 {
                3
            } else if self.kind == 3 {
                2
            } else {
                self.kind
            },
            protocol: if self.kind == 1 {
                6
            } else if self.kind == 2 {
                17
            } else if self.family == 2 {
                1
            } else {
                58
            },
            state: code,
            local: state.bound.map(|a| self.presented(a)),
            peer: state.peer.map(|a| self.presented(a)),
            tx_queue: Some(tx),
            rx_queue: Some(rx),
        }
    }
    pub fn fabric(&self) -> Fabric {
        self.network.0.fabric.clone()
    }
    pub fn address_size(&self) -> usize {
        if self.family == 2 {
            16
        } else {
            28
        }
    }
    fn normalize(&self, a: SocketAddr) -> Result<SocketAddr> {
        if a.is_ipv4() != (self.family == 2) {
            return Err(NetError(97));
        }
        if let SocketAddr::V6(v) = a {
            if v.scope_id() != 0 {
                return Err(NetError(95));
            }
            if let Some(v4) = v.ip().to_ipv4_mapped() {
                if self.state.borrow().v6_only {
                    return Err(NetError(101));
                }
                return Ok(SocketAddr::new(v4.into(), v.port()));
            }
        }
        Ok(a)
    }
    fn presented(&self, a: SocketAddr) -> SocketAddr {
        if self.family == 10 && a.is_ipv4() {
            SocketAddr::new(
                match a.ip() {
                    IpAddr::V4(a) => a.to_ipv6_mapped().into(),
                    _ => unreachable!(),
                },
                a.port(),
            )
        } else {
            a
        }
    }
    fn wildcard(&self) -> SocketAddr {
        SocketAddr::new(
            if self.family == 2 {
                Ipv4Addr::UNSPECIFIED.into()
            } else {
                Ipv6Addr::UNSPECIFIED.into()
            },
            0,
        )
    }
    fn own(&self, a: IpAddr) -> bool {
        if let Some(v) = &self.network.0.routing {
            return a.is_unspecified() || v.own(a);
        }
        a.is_unspecified()
            || (!self.network.is_isolated()
                && (a == IpAddr::V4(self.network.0.info.ipv4)
                    || a == IpAddr::V6(self.network.0.info.ipv6)))
            || (self.network.0.loopback_up.get()
                && (a == IpAddr::V4(Ipv4Addr::LOCALHOST) || a == IpAddr::V6(Ipv6Addr::LOCALHOST)))
    }
    fn destination(&self, a: SocketAddr) -> Result<()> {
        if a.port() == 0 && !matches!(self.kind, 3 | 4) {
            return Err(NetError(22));
        }
        let v = a.ip();
        if self.network.0.routing.is_none()
            && self.network.is_isolated()
            && (!v.is_loopback() || !self.network.0.loopback_up.get())
        {
            return Err(NetError(101));
        }
        if v.is_unspecified()
            || v.is_multicast()
            || matches!(v,IpAddr::V4(a) if a.is_broadcast() || a.octets()[0]>=240)
        {
            return Err(NetError(13));
        }
        if self.network.0.mode == NetworkMode::Loopback && !self.own(v) {
            return Err(NetError(13));
        }
        if v.is_loopback()
            && !matches!(v,IpAddr::V4(a) if a==Ipv4Addr::LOCALHOST)
            && v != IpAddr::V6(Ipv6Addr::LOCALHOST)
        {
            return Err(NetError(99));
        }
        if let Some(view) = &self.network.0.routing {
            view.source(v)?;
            return Ok(());
        }
        if private_ip(v) && v != IpAddr::V4(v4(1)) && v != IpAddr::V6(v6(1)) {
            let i = self.network.0.fabric.0.borrow();
            if !i
                .nodes
                .values()
                .any(|n| v == IpAddr::V4(v4(n.id)) || v == IpAddr::V6(v6(n.id)))
            {
                return Err(NetError(113));
            }
        }
        Ok(())
    }
    fn addresses(&self, bound: SocketAddr) -> Vec<SocketAddr> {
        let state = self.state.borrow();
        if !bound.ip().is_unspecified() {
            return vec![bound];
        }
        if let Some(view) = &self.network.0.routing {
            let ips = view.addresses(false);
            return ips
                .into_iter()
                .filter(|a| {
                    a.ip.is_ipv4() == (self.family == 2) || (self.family == 10 && !state.v6_only)
                })
                .map(|a| SocketAddr::new(a.ip, bound.port()))
                .collect();
        }
        let info = self.network.0.info;
        let mut ips = if self.family == 2 {
            vec![IpAddr::V4(info.ipv4), Ipv4Addr::LOCALHOST.into()]
        } else {
            vec![IpAddr::V6(info.ipv6), Ipv6Addr::LOCALHOST.into()]
        };
        if self.family == 10 && !state.v6_only {
            ips.extend([IpAddr::V4(info.ipv4), Ipv4Addr::LOCALHOST.into()]);
        }
        // Wildcard bindings belong to the namespace, even while lo is down.
        // Keep their loopback handles ready for a later LinkSetUp; packet
        // delivery is gated by the live interface state in the fabric.
        ips.retain(|a| !self.network.is_isolated() || a.is_loopback());
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, bound.port()))
            .collect()
    }
    fn port_free(&self, a: SocketAddr) -> bool {
        let i = self.network.0.fabric.0.borrow();
        let Some(n) = i.nodes.get(&self.network.0.key) else {
            return false;
        };
        n.registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|s| !std::ptr::eq(s.as_ref(), self) && s.kind == self.kind)
            .all(|s| {
                let state = s.state.borrow();
                let Some(b) = state.bound else {
                    return true;
                };
                if a.port() != b.port() {
                    return true;
                }
                let same_family = a.is_ipv4() == b.is_ipv4()
                    || (self.family == 10 && !self.state.borrow().v6_only)
                    || (s.family == 10 && !state.v6_only);
                !same_family
                    || (!a.ip().is_unspecified() && !b.ip().is_unspecified() && a.ip() != b.ip())
            })
    }
    fn choose_port(&self, ip: IpAddr) -> Result<u16> {
        let mut seed = [0; 2];
        getrandom::fill(&mut seed).map_err(|_| NetError(5))?;
        let first = u16::from_ne_bytes(seed) % 16384;
        for n in 0..16384u32 {
            let p = 49152 + ((first as u32 + n) % 16384) as u16;
            if self.port_free(SocketAddr::new(ip, p)) {
                return Ok(p);
            }
        }
        Err(NetError(98))
    }
    pub fn bind(&self, a: SocketAddr) -> Result<()> {
        self.fabric().tick();
        let mut a = self.normalize(a)?;
        if self.network.0.finished.get() {
            return Err(NetError(100));
        }
        if self.state.borrow().bound.is_some() {
            return Err(NetError(22));
        }
        if !self.own(a.ip()) {
            return Err(NetError(99));
        }
        if self.kind == 4 {
            a.set_port(0);
        } else if a.port() == 0 {
            a.set_port(self.choose_port(a.ip())?);
        } else if !self.port_free(a) {
            return Err(NetError(98));
        }
        if self.kind == 3 {
            let mut i = self.network.0.fabric.0.borrow_mut();
            i.reserve(1)?;
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            let mut s = icmp::Socket::new(
                icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 16], vec![0; BUFFER]),
                icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 16], vec![0; BUFFER]),
            );
            s.set_hop_limit(Some(self.state.borrow().hop_limit));
            s.bind(icmp::Endpoint::Ident(a.port()))
                .map_err(|_| NetError(22))?;
            self.state.borrow_mut().handles = vec![n.sockets.add(s)];
        }
        if self.kind == 4 {
            let mut i = self.network.0.fabric.0.borrow_mut();
            i.reserve(1)?;
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            let socket = raw::Socket::new(
                if self.family == 2 {
                    smoltcp::wire::IpVersion::Ipv4
                } else {
                    smoltcp::wire::IpVersion::Ipv6
                },
                if self.family == 2 {
                    smoltcp::wire::IpProtocol::Icmp
                } else {
                    smoltcp::wire::IpProtocol::Icmpv6
                },
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 16], vec![0; BUFFER]),
                raw::PacketBuffer::new(vec![raw::PacketMetadata::EMPTY; 16], vec![0; BUFFER]),
            );
            self.state.borrow_mut().handles = vec![n.sockets.add(socket)];
        }
        if self.kind == 2 {
            let addresses = self.addresses(a);
            let mut i = self.network.0.fabric.0.borrow_mut();
            i.reserve(addresses.len())?;
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            let mut handles = Vec::new();
            for address in addresses {
                let mut s = udp_socket();
                s.set_hop_limit(Some(self.state.borrow().hop_limit));
                s.bind(IpListenEndpoint {
                    addr: Some(ip(address.ip())),
                    port: address.port(),
                })
                .map_err(|_| NetError(22))?;
                handles.push(n.sockets.add(s));
            }
            self.state.borrow_mut().handles = handles;
        }
        self.state.borrow_mut().bound = Some(a);
        Ok(())
    }
    pub(crate) fn preflight_listen(&self, backlog: u32) -> Result<()> {
        if self.kind != 1 {
            return Err(NetError(95));
        }
        let state = self.state.borrow();
        if state.connection == Connection::Listening {
            return Ok(());
        }
        if state.connection != Connection::Idle {
            return Err(NetError(22));
        }
        let bound = state.bound.ok_or(NetError(22))?;
        drop(state);
        self.network
            .0
            .fabric
            .0
            .borrow()
            .reserve(self.addresses(bound).len() * backlog.clamp(1, 8) as usize)
    }
    pub fn listen(&self, backlog: u32) -> Result<()> {
        if self.kind != 1 {
            return Err(NetError(95));
        }
        let state = self.state.borrow();
        if !matches!(state.connection, Connection::Idle | Connection::Listening) {
            return Err(NetError(22));
        }
        let bound = state.bound.ok_or(NetError(22))?;
        drop(state);
        if self.state.borrow().connection == Connection::Listening {
            return Ok(());
        }
        let addresses = self.addresses(bound);
        let backlog = backlog.clamp(1, 8) as usize;
        let mut i = self.network.0.fabric.0.borrow_mut();
        i.reserve(addresses.len() * backlog)?;
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        for a in addresses {
            for _ in 0..backlog {
                let mut s = tcp_socket();
                s.set_hop_limit(Some(state.hop_limit));
                s.listen(endpoint(a)).map_err(|_| NetError(22))?;
                state.handles.push(n.sockets.add(s));
            }
        }
        state.connection = Connection::Listening;
        state.backlog = backlog;
        Ok(())
    }
    pub fn accept(&self) -> Result<(Rc<Socket>, SocketAddr)> {
        self.fabric().tick();
        self.network.reserve()?;
        let mut i = self.network.0.fabric.0.borrow_mut();
        i.reserve(1)?;
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        if state.connection != Connection::Listening {
            return Err(NetError(22));
        }
        let index = state
            .handles
            .iter()
            .position(|h| {
                matches!(
                    n.sockets.get::<tcp::Socket>(*h).state(),
                    tcp::State::Established | tcp::State::CloseWait
                )
            })
            .ok_or(NetError(11))?;
        let handle = state.handles.swap_remove(index);
        let s = n.sockets.get::<tcp::Socket>(handle);
        let local = address(s.local_endpoint().unwrap());
        let peer = address(s.remote_endpoint().unwrap());
        let mut replacement = tcp_socket();
        replacement.set_hop_limit(Some(state.hop_limit));
        replacement
            .listen(endpoint(local))
            .map_err(|_| NetError(22))?;
        state.handles.push(n.sockets.add(replacement));
        let accepted = State {
            handles: vec![handle],
            connection: Connection::Connected,
            bound: Some(local),
            peer: Some(peer),
            error: None,
            blocking_failed: false,
            read_closed: false,
            write_closed: false,
            v6_only: state.v6_only,
            reuse: state.reuse,
            nodelay: state.nodelay,
            keepalive: state.keepalive,
            keep_idle: state.keep_idle,
            keep_interval: state.keep_interval,
            keep_count: state.keep_count,
            backlog: 1,
            icmp_pending: None,
            hop_limit: state.hop_limit,
            receive_hops: state.receive_hops,
            last_hop: None,
            broadcast: state.broadcast,
            icmp6_filter: state.icmp6_filter,
            hop_message: state.hop_message,
            device: state.device,
            raw_identifiers: std::collections::BTreeSet::new(),
        };
        drop(state);
        drop(i);
        Ok((
            self.network.wrap(self.family, 1, accepted),
            self.presented(peer),
        ))
    }
    pub fn connect(&self, a: SocketAddr) -> Result<()> {
        let a = self.normalize(a)?;
        self.destination(a)?;
        let state = self.state.borrow();
        if self.kind == 1 {
            match state.connection {
                Connection::Connecting => return Err(NetError(114)),
                Connection::Connected => return Err(NetError(106)),
                Connection::Listening => return Err(NetError(22)),
                Connection::Failed(e) => return Err(NetError(e)),
                Connection::Idle => {}
            }
        }
        let bound = state.bound;
        drop(state);
        if bound.is_none() {
            self.bind(self.wildcard())?;
        }
        if self.kind != 1 {
            let mut s = self.state.borrow_mut();
            s.peer = Some(a);
            s.connection = Connection::Connected;
            return Ok(());
        }
        let mut bound = self.state.borrow().bound.unwrap();
        if bound.ip().is_unspecified() {
            bound.set_ip(if let Some(view) = &self.network.0.routing {
                view.source(a.ip())?
            } else if a.ip().is_loopback() {
                if a.is_ipv4() {
                    Ipv4Addr::LOCALHOST.into()
                } else {
                    Ipv6Addr::LOCALHOST.into()
                }
            } else if a.is_ipv4() {
                self.network.0.info.ipv4.into()
            } else {
                self.network.0.info.ipv6.into()
            });
        }
        if bound.is_ipv4() != a.is_ipv4() {
            return Err(NetError(97));
        }
        if bound.ip().is_loopback() != a.ip().is_loopback() {
            return Err(NetError(99));
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        i.reserve(1)?;
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut s = tcp_socket();
        s.connect(n.iface.context(), endpoint(a), endpoint(bound))
            .map_err(|_| NetError(22))?;
        let mut state = self.state.borrow_mut();
        s.set_hop_limit(Some(state.hop_limit));
        s.set_nagle_enabled(!state.nodelay);
        if state.keepalive {
            s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(
                state.keep_idle as u64,
            )));
        }
        state.handles.push(n.sockets.add(s));
        state.bound = Some(bound);
        state.peer = Some(a);
        state.connection = Connection::Connecting;
        drop(state);
        drop(i);
        self.fabric().tick();
        Err(NetError(115))
    }
    pub fn connect_complete(&self) -> Result<bool> {
        self.fabric().tick();
        match self.state.borrow().connection {
            Connection::Connecting => Ok(false),
            Connection::Connected => Ok(true),
            Connection::Failed(e) => Err(NetError(e)),
            _ => Err(NetError(107)),
        }
    }
    pub fn resume_connect(&self) -> Result<bool> {
        let r = self.connect_complete();
        let mut s = self.state.borrow_mut();
        if matches!(s.connection, Connection::Failed(_)) {
            s.error = None;
            s.blocking_failed = true;
        }
        r
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.presented(self.state.borrow().bound.unwrap_or(self.wildcard())))
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.state
            .borrow()
            .peer
            .map(|a| self.presented(a))
            .ok_or(NetError(107))
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if how > 2 {
            return Err(NetError(22));
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        if state.connection != Connection::Connected {
            return Err(NetError(107));
        }
        if how != 1 {
            state.read_closed = true;
        }
        if how != 0 {
            state.write_closed = true;
            if self.kind == 1 {
                n.sockets.get_mut::<tcp::Socket>(state.handles[0]).close();
            }
        }
        drop(state);
        drop(i);
        self.fabric().tick();
        Ok(())
    }
    fn before_io(&self) -> Result<()> {
        let _ = self.connect_complete();
        let mut s = self.state.borrow_mut();
        if s.connection == Connection::Connecting {
            return Err(NetError(11));
        }
        if let Some(e) = s.error.take() {
            return Err(NetError(e));
        }
        Ok(())
    }
    pub fn send(&self, bytes: &[u8], flags: u32, destination: Option<SocketAddr>) -> Result<usize> {
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > MAX_TRANSFER {
            return Err(NetError(90));
        }
        self.fabric().tick();
        if self.kind == 3 {
            return self.send_icmp(bytes, destination);
        }
        if self.kind == 4 {
            return self.send_raw(bytes, destination);
        }
        if self.kind == 2 {
            let a = if let Some(a) = destination {
                self.normalize(a)?
            } else {
                self.state.borrow().peer.ok_or(NetError(89))?
            };
            self.destination(a)?;
            if bytes.len() > if a.is_ipv4() { 65507 } else { 65527 } {
                return Err(NetError(90));
            }
            if self.state.borrow().bound.is_none() {
                self.bind(self.wildcard())?;
            }
            let state = self.state.borrow();
            if state.write_closed {
                return Err(NetError(32));
            }
            let selected = if state.bound.is_some_and(|b| b.ip().is_unspecified()) {
                self.network
                    .0
                    .routing
                    .as_ref()
                    .map(|view| view.source(a.ip()))
                    .transpose()?
            } else {
                None
            };
            let mut i = self.network.0.fabric.0.borrow_mut();
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            let h = state
                .handles
                .iter()
                .find(|h| {
                    let ep = n.sockets.get::<udp::Socket>(**h).endpoint();
                    ep.addr.is_some_and(|p| {
                        if let Some(source) = selected {
                            addr(p) == source
                        } else {
                            addr(p).is_ipv4() == a.is_ipv4()
                                && addr(p).is_loopback() == a.ip().is_loopback()
                        }
                    })
                })
                .copied()
                .ok_or(NetError(99))?;
            n.sockets
                .get_mut::<udp::Socket>(h)
                .send_slice(bytes, endpoint(a))
                .map_err(|e| match e {
                    udp::SendError::BufferFull => NetError(11),
                    _ => NetError(99),
                })?;
            drop(i);
            drop(state);
            self.fabric().tick();
            return Ok(bytes.len());
        }
        if destination.is_some() {
            return Err(NetError(106));
        }
        self.before_io()?;
        let state = self.state.borrow();
        if state.write_closed || matches!(state.connection, Connection::Failed(_)) {
            return Err(NetError(32));
        }
        if state.connection != Connection::Connected {
            return Err(NetError(107));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let s = n.sockets.get_mut::<tcp::Socket>(state.handles[0]);
        if !s.may_send() {
            return Err(NetError(32));
        }
        let count = s.send_slice(bytes).map_err(|_| NetError(32))?;
        if count == 0 {
            return Err(NetError(11));
        }
        drop(i);
        drop(state);
        self.fabric().tick();
        Ok(count)
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Received> {
        if flags & !(MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT) != 0 {
            return Err(NetError(95));
        }
        if count > MAX_TRANSFER {
            return Err(NetError(90));
        }
        self.fabric().tick();
        if self.kind == 3 {
            return self.recv_icmp(count, flags);
        }
        if self.kind == 4 {
            return self.recv_raw(count, flags);
        }
        if self.kind == 1 {
            self.before_io()?;
        }
        let state = self.state.borrow();
        if state.read_closed || self.kind == 1 && count == 0 {
            return Ok(Received {
                netlink_address: None,
                data: Vec::new(),
                address: None,
                length: 0,
                truncated: false,
            });
        }
        if self.kind == 1 && state.connection != Connection::Connected {
            if matches!(state.connection, Connection::Failed(_)) && !state.blocking_failed {
                return Ok(Received {
                    netlink_address: None,
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
            return Err(NetError(107));
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        if self.kind == 1 {
            let s = n.sockets.get_mut::<tcp::Socket>(state.handles[0]);
            if !s.can_recv() {
                if s.may_recv() {
                    return Err(NetError(11));
                }
                return Ok(Received {
                    netlink_address: None,
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
            let mut bytes = vec![0; count.min(s.recv_queue())];
            let size = if flags & MSG_PEEK != 0 {
                s.peek_slice(&mut bytes)
            } else {
                s.recv_slice(&mut bytes)
            }
            .map_err(|_| NetError(11))?;
            bytes.truncate(size);
            drop(i);
            drop(state);
            self.fabric().tick();
            Ok(Received {
                netlink_address: None,
                data: bytes,
                address: None,
                length: size,
                truncated: false,
            })
        } else {
            for h in &state.handles {
                let s = n.sockets.get_mut::<udp::Socket>(*h);
                for _ in 0..16 {
                    let Ok((data, meta)) = s.peek() else {
                        break;
                    };
                    let source = address(meta.endpoint);
                    if state.peer.is_some_and(|peer| peer != source) {
                        let _ = s.recv();
                        continue;
                    }
                    let size = data.len();
                    let bytes = data[..count.min(size)].to_vec();
                    if flags & MSG_PEEK == 0 {
                        let _ = s.recv();
                    }
                    return Ok(Received {
                        netlink_address: None,
                        data: bytes,
                        address: Some(self.presented(source)),
                        length: if flags & MSG_TRUNC != 0 {
                            size
                        } else {
                            count.min(size)
                        },
                        truncated: size > count,
                    });
                }
            }
            Err(NetError(11))
        }
    }
    pub fn poll(&self, events: u16) -> Result<u16> {
        self.fabric().tick();
        let state = self.state.borrow();
        if matches!(state.connection, Connection::Failed(_)) {
            return Ok(events & 4 | 16 | if state.error.is_some() { 8 } else { 0 });
        }
        let i = self.network.0.fabric.0.borrow();
        let n = i.nodes.get(&self.network.0.key).ok_or(NetError(100))?;
        let mut ready = if state.error.is_some() { 8 } else { 0 };
        for h in &state.handles {
            if self.kind == 1 {
                let s = n.sockets.get::<tcp::Socket>(*h);
                if state.connection == Connection::Listening {
                    if matches!(s.state(), tcp::State::Established | tcp::State::CloseWait) {
                        ready |= 1;
                    }
                } else if state.connection == Connection::Connected {
                    if s.can_recv() || !s.may_recv() || state.read_closed {
                        ready |= 1;
                    }
                    if s.can_send() || !s.may_send() {
                        ready |= 4;
                    }
                    if s.state() == tcp::State::Closed {
                        ready |= 16;
                    }
                }
            } else if self.kind == 4 {
                let s = n.sockets.get::<raw::Socket>(*h);
                if s.can_recv() || state.icmp_pending.is_some() {
                    ready |= 1;
                }
                if s.can_send() {
                    ready |= 4;
                }
            } else if self.kind == 3 {
                let s = n.sockets.get::<icmp::Socket>(*h);
                if s.can_recv() || state.icmp_pending.is_some() {
                    ready |= 1;
                }
                if s.can_send() {
                    ready |= 4;
                }
            } else {
                let s = n.sockets.get::<udp::Socket>(*h);
                if s.can_recv() {
                    ready |= 1;
                }
                if s.can_send() {
                    ready |= 4;
                }
            }
        }
        if self.kind != 1 && state.handles.is_empty() {
            ready |= 4;
        }
        Ok((ready & events) | (ready & 24))
    }
    pub fn set_option(&self, level: u32, name: u32, value: i32) -> Result<()> {
        let mut state = self.state.borrow_mut();
        match (level, name) {
            (1, 2) => state.reuse = value != 0,
            (1, 9) => state.keepalive = value != 0,
            (1, 6) => state.broadcast = value != 0,
            (0, 2) if self.family == 2 && (1..=255).contains(&value) => {
                state.hop_limit = value as u8
            }
            (41, 16) if self.family == 10 && (-1..=255).contains(&value) => {
                state.hop_limit = if value == -1 { 64 } else { value as u8 }
            }
            (0, 12) if self.family == 2 && self.kind == 4 => state.receive_hops = value != 0,
            (41, 51 | 8) if self.family == 10 && self.kind == 4 => {
                state.receive_hops = value != 0;
                state.hop_message = if name == 8 { 8 } else { 52 };
            }
            (255, 7) if self.family == 10 && self.kind == 4 && value == 2 => {}
            (1, 7 | 8) => {
                if value <= 0 || value as usize > MAX_BUFFER {
                    return Err(NetError(22));
                }
            }
            (6, 1) if self.kind == 1 => state.nodelay = value != 0,
            (6, 4..=6) if self.kind == 1 => {
                if !(1..=if name == 6 { 127 } else { 32767 }).contains(&value) {
                    return Err(NetError(22));
                }
                match name {
                    4 => state.keep_idle = value as u32,
                    // smoltcp uses a single idle/probe interval. These two
                    // Linux tuning values are retained for ABI compatibility;
                    // they do not replace its retransmission/expiry policy.
                    5 => state.keep_interval = value as u32,
                    _ => state.keep_count = value as u32,
                }
            }
            (41, 26) if self.family == 10 => {
                if matches!(self.kind, 3 | 4) && value == 0 {
                    return Err(NetError(95));
                }
                if state.bound.is_some() {
                    return Err(NetError(22));
                }
                state.v6_only = value != 0;
            }
            (1, 20 | 21) => return Err(NetError(95)),
            _ => return Err(NetError(92)),
        }
        if self.kind == 1 {
            let mut i = self.network.0.fabric.0.borrow_mut();
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            for h in &state.handles {
                let s = n.sockets.get_mut::<tcp::Socket>(*h);
                s.set_hop_limit(Some(state.hop_limit));
                s.set_nagle_enabled(!state.nodelay);
                s.set_keep_alive(
                    state
                        .keepalive
                        .then_some(smoltcp::time::Duration::from_secs(state.keep_idle as u64)),
                );
            }
        }
        if matches!(self.kind, 2 | 3) {
            let mut i = self.network.0.fabric.0.borrow_mut();
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            for h in &state.handles {
                if self.kind == 2 {
                    n.sockets
                        .get_mut::<udp::Socket>(*h)
                        .set_hop_limit(Some(state.hop_limit));
                } else {
                    n.sockets
                        .get_mut::<icmp::Socket>(*h)
                        .set_hop_limit(Some(state.hop_limit));
                }
            }
        }
        Ok(())
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        if (level, name) == (1, 4) {
            let _ = self.connect_complete();
            return Ok(self.state.borrow_mut().error.take().unwrap_or(0) as i32);
        }
        let state = self.state.borrow();
        match (level, name) {
            (1, 3) => Ok(if self.kind == 3 {
                2
            } else if self.kind == 4 {
                3
            } else {
                self.kind as i32
            }),
            (1, 39) => Ok(self.family as i32),
            (1, 38) => Ok(if self.kind == 1 {
                6
            } else if matches!(self.kind, 3 | 4) {
                if self.family == 2 {
                    1
                } else {
                    58
                }
            } else {
                17
            }),
            (1, 30) => Ok(i32::from(state.connection == Connection::Listening)),
            (1, 2) => Ok(i32::from(state.reuse)),
            (1, 9) => Ok(i32::from(state.keepalive)),
            (1, 6) => Ok(i32::from(state.broadcast)),
            (0, 2) if self.family == 2 => Ok(state.hop_limit as i32),
            (41, 16) if self.family == 10 => Ok(state.hop_limit as i32),
            (0, 12) | (41, 51 | 8) => Ok(i32::from(state.receive_hops)),
            (1, 7 | 8) => Ok(BUFFER as i32),
            (6, 1) if self.kind == 1 => Ok(i32::from(state.nodelay)),
            (6, 4) if self.kind == 1 => Ok(state.keep_idle as i32),
            (6, 5) if self.kind == 1 => Ok(state.keep_interval as i32),
            (6, 6) if self.kind == 1 => Ok(state.keep_count as i32),
            (41, 26) if self.family == 10 => Ok(i32::from(state.v6_only)),
            _ => Err(NetError(92)),
        }
    }
}

impl Socket {
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if (level, name) == (58, 1) && self.family == 10 && self.kind == 4 {
            if value.len() != 32 {
                return Err(NetError(22));
            }
            self.state.borrow_mut().icmp6_filter.copy_from_slice(value);
            return Ok(());
        }
        if (level, name) == (1, 25) {
            if value.len() > 16 {
                return Err(NetError(22));
            }
            let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
            let device = match &value[..end] {
                b"" => None,
                b"lo" => Some(1),
                b"eth0" if !self.network.is_isolated() => Some(2),
                _ => return Err(NetError(19)),
            };
            if self.kind != 4 {
                return Err(NetError(95));
            }
            self.state.borrow_mut().device = device;
            return Ok(());
        }
        if value.len() < 4 {
            return Err(NetError(22));
        }
        self.set_option(
            level,
            name,
            i32::from_le_bytes(value[..4].try_into().unwrap()),
        )
    }
    pub fn ancillary_hop(&self) -> Option<(u32, u32, u8)> {
        let state = self.state.borrow();
        if !state.receive_hops {
            return None;
        }
        state.last_hop.map(|hop| {
            if self.family == 2 {
                (0, 2, hop)
            } else {
                (41, state.hop_message, hop)
            }
        })
    }
    fn send_raw(&self, bytes: &[u8], destination: Option<SocketAddr>) -> Result<usize> {
        let a = destination
            .map(|a| self.normalize(a))
            .transpose()?
            .or(self.state.borrow().peer)
            .ok_or(NetError(89))?;
        self.destination(a)?;
        if bytes.len() < 8 || bytes.len() > 1400 {
            return Err(NetError(90));
        }
        if self.state.borrow().bound.is_none() {
            self.bind(self.wildcard())?;
        }
        if bytes[0] == if self.family == 2 { 8 } else { 128 } && bytes[1] == 0 {
            let mut state = self.state.borrow_mut();
            let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
            if state.raw_identifiers.len() >= 32 && !state.raw_identifiers.contains(&identifier) {
                return Err(NetError(105));
            }
            state.raw_identifiers.insert(identifier);
        }
        let state = self.state.borrow();
        if state.write_closed {
            return Err(NetError(32));
        }
        if state
            .device
            .is_some_and(|i| (i == 1) != a.ip().is_loopback())
        {
            return Err(NetError(101));
        }
        let bound = state.bound.unwrap().ip();
        let source = if !bound.is_unspecified() {
            bound
        } else if let Some(view) = &self.network.0.routing {
            view.source(a.ip())?
        } else if a.ip().is_loopback() {
            if self.family == 2 {
                Ipv4Addr::LOCALHOST.into()
            } else {
                Ipv6Addr::LOCALHOST.into()
            }
        } else if self.family == 2 {
            self.network.0.info.ipv4.into()
        } else {
            self.network.0.info.ipv6.into()
        };
        let mut data = if self.family == 2 {
            let (IpAddr::V4(source), IpAddr::V4(destination)) = (source, a.ip()) else {
                return Err(NetError(97));
            };
            let mut header = vec![0; 20];
            header[0] = 0x45;
            header[2..4].copy_from_slice(&((20 + bytes.len()) as u16).to_be_bytes());
            header[8] = state.hop_limit;
            header[9] = 1;
            header[12..16].copy_from_slice(&source.octets());
            header[16..20].copy_from_slice(&destination.octets());
            smoltcp::wire::Ipv4Packet::new_unchecked(&mut header).fill_checksum();
            header.extend_from_slice(bytes);
            header
        } else {
            let (IpAddr::V6(source), IpAddr::V6(destination)) = (source, a.ip()) else {
                return Err(NetError(97));
            };
            let mut header = vec![0; 40];
            header[0] = 0x60;
            header[4..6].copy_from_slice(&(bytes.len() as u16).to_be_bytes());
            header[6] = 58;
            header[7] = state.hop_limit;
            header[8..24].copy_from_slice(&source.octets());
            header[24..40].copy_from_slice(&destination.octets());
            header.extend_from_slice(bytes);
            smoltcp::wire::Icmpv6Packet::new_unchecked(&mut header[40..])
                .fill_checksum(&source, &destination);
            header
        };
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let n = fabric
            .nodes
            .get_mut(&self.network.0.key)
            .ok_or(NetError(100))?;
        n.sockets
            .get_mut::<raw::Socket>(state.handles[0])
            .send_slice(&data)
            .map_err(|_| NetError(11))?;
        data.clear();
        drop(fabric);
        drop(state);
        self.fabric().tick();
        if let Some(errno) = self.state.borrow_mut().error.take() {
            Err(NetError(errno))
        } else {
            Ok(bytes.len())
        }
    }
    fn recv_raw(&self, count: usize, flags: u32) -> Result<Received> {
        if self.state.borrow().bound.is_none() {
            self.bind(self.wildcard())?;
        }
        let mut state = self.state.borrow_mut();
        if let Some(errno) = state.error.take() {
            return Err(NetError(errno));
        }
        if state.read_closed {
            return Ok(Received {
                netlink_address: None,
                data: Vec::new(),
                address: None,
                length: 0,
                truncated: false,
            });
        }
        if state.icmp_pending.is_none() {
            let mut fabric = self.network.0.fabric.0.borrow_mut();
            let n = fabric
                .nodes
                .get_mut(&self.network.0.key)
                .ok_or(NetError(100))?;
            for _ in 0..16 {
                let data = n
                    .sockets
                    .get_mut::<raw::Socket>(state.handles[0])
                    .recv()
                    .map_err(|_| NetError(11))?;
                let Some(header) = packet::header(data) else {
                    continue;
                };
                let peer = header.tuple.source.ip();
                if state.peer.is_some_and(|a| a.ip() != peer)
                    || state.bound.is_some_and(|a| {
                        !a.ip().is_unspecified() && a.ip() != header.tuple.destination.ip()
                    })
                {
                    continue;
                }
                if state
                    .device
                    .is_some_and(|i| (i == 1) != header.tuple.destination.ip().is_loopback())
                {
                    continue;
                }
                if self.family == 10 {
                    let Some(&kind) = data.get(header.offset) else {
                        continue;
                    };
                    if state.icmp6_filter[kind as usize / 8] & (1 << (kind % 8)) != 0 {
                        continue;
                    }
                }
                state.last_hop = Some(if self.family == 2 { data[8] } else { data[7] });
                state.icmp_pending = Some((
                    if self.family == 2 {
                        data.to_vec()
                    } else {
                        data[header.offset..].to_vec()
                    },
                    peer,
                ));
                break;
            }
        }
        let (data, peer) = state.icmp_pending.as_ref().ok_or(NetError(11))?;
        let length = data.len();
        let received = Received {
            netlink_address: None,
            data: data[..count.min(length)].to_vec(),
            address: Some(SocketAddr::new(*peer, 0)),
            length,
            truncated: count < length,
        };
        if flags & MSG_PEEK == 0 {
            state.icmp_pending = None;
        }
        Ok(received)
    }
    fn send_icmp(&self, bytes: &[u8], destination: Option<SocketAddr>) -> Result<usize> {
        let a = if let Some(a) = destination {
            self.normalize(a)?
        } else {
            self.state.borrow().peer.ok_or(NetError(89))?
        };
        self.destination(a)?;
        if bytes.len() < 8
            || bytes.len() > 1400
            || bytes[0] != if a.is_ipv4() { 8 } else { 128 }
            || bytes[1] != 0
        {
            return Err(NetError(22));
        }
        if self.state.borrow().bound.is_none() {
            self.bind(self.wildcard())?;
        }
        let state = self.state.borrow();
        if state.write_closed {
            return Err(NetError(32));
        }
        let mut data = bytes.to_vec();
        data[4..6].copy_from_slice(&state.bound.unwrap().port().to_be_bytes());
        if a.is_ipv4() {
            smoltcp::wire::Icmpv4Packet::new_unchecked(&mut data).fill_checksum();
        } else {
            let source = if let Some(view) = &self.network.0.routing {
                let IpAddr::V6(source) = view.source(a.ip())? else {
                    return Err(NetError(97));
                };
                source
            } else if a.ip().is_loopback() {
                Ipv6Addr::LOCALHOST
            } else {
                self.network.0.info.ipv6
            };
            let IpAddr::V6(dest) = a.ip() else {
                return Err(NetError(97));
            };
            smoltcp::wire::Icmpv6Packet::new_unchecked(&mut data).fill_checksum(&source, &dest);
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        n.sockets
            .get_mut::<icmp::Socket>(state.handles[0])
            .send_slice(&data, ip(a.ip()))
            .map_err(|_| NetError(11))?;
        drop(i);
        drop(state);
        self.fabric().tick();
        if let Some(errno) = self.state.borrow_mut().error.take() {
            Err(NetError(errno))
        } else {
            Ok(bytes.len())
        }
    }
    fn recv_icmp(&self, count: usize, flags: u32) -> Result<Received> {
        let mut state = self.state.borrow_mut();
        if let Some(errno) = state.error.take() {
            return Err(NetError(errno));
        }
        if state.read_closed {
            return Ok(Received {
                netlink_address: None,
                data: Vec::new(),
                address: None,
                length: 0,
                truncated: false,
            });
        }
        if state.icmp_pending.is_none() {
            let mut i = self.network.0.fabric.0.borrow_mut();
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            let h = *state.handles.first().ok_or(NetError(11))?;
            for _ in 0..16 {
                let (data, peer) = n
                    .sockets
                    .get_mut::<icmp::Socket>(h)
                    .recv()
                    .map_err(|_| NetError(11))?;
                let peer = addr(peer);
                if data.first() != Some(&if self.family == 2 { 0 } else { 129 })
                    || state.peer.is_some_and(|a| a.ip() != peer)
                {
                    continue;
                }
                state.icmp_pending = Some((data.to_vec(), peer));
                break;
            }
            if state.icmp_pending.is_none() {
                return Err(NetError(11));
            }
        }
        let (data, peer) = state.icmp_pending.as_ref().unwrap();
        let length = data.len();
        let received = Received {
            netlink_address: None,
            data: data[..count.min(length)].to_vec(),
            address: Some(SocketAddr::new(*peer, 0)),
            length: if flags & MSG_TRUNC != 0 {
                length
            } else {
                count.min(length)
            },
            truncated: count < length,
        };
        if flags & MSG_PEEK == 0 {
            state.icmp_pending = None;
        }
        Ok(received)
    }
}
