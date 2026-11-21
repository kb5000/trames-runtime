// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
#[derive(Clone, Copy, PartialEq, Eq)]
enum PortUse {
    Ephemeral,
    Bind,
    Listen,
}

fn addresses_overlap(a: SocketAddr, a_dual: bool, b: SocketAddr, b_dual: bool) -> bool {
    a.port() == b.port()
        && if a.is_ipv4() == b.is_ipv4() {
            a.ip().is_unspecified() || b.ip().is_unspecified() || a.ip() == b.ip()
        } else if a.is_ipv6() {
            a_dual && a.ip().is_unspecified()
        } else {
            b_dual && b.ip().is_unspecified()
        }
}

impl Socket {
    pub fn subscribe_tcp_ready(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Option<trames_shared::IoSubscription> {
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let node = fabric.nodes.get_mut(&self.network.0.key)?;
        let state = self.state.borrow();
        if state.connection != Connection::Connected {
            return None;
        }
        let h = *state.handles.first()?;
        let source = node.tcp_waiters.entry(h).or_insert_with(|| {
            node.sockets.get_mut::<tcp::Socket>(h).observe_io(Some(h));
            Arc::default()
        });
        let source = source.clone();
        drop(state);
        drop(fabric);
        Some(source.subscribe(signal))
    }
    pub fn subscribe_udp_readable(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Option<trames_shared::IoSubscription> {
        if self.kind != 2 {
            return None;
        }
        if let Some(source) = self.state.borrow().udp_readable.clone() {
            return Some(source.subscribe(signal));
        }
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let node = fabric.nodes.get_mut(&self.network.0.key)?;
        let mut state = self.state.borrow_mut();
        let source = state
            .udp_readable
            .get_or_insert_with(Default::default)
            .clone();
        let token = state.udp_bind_order;
        if token != 0 {
            node.udp_readers.insert(token, source.clone());
            for &handle in &state.handles {
                node.sockets
                    .get_mut::<udp::Socket>(handle)
                    .observe_readable(token);
            }
        }
        drop(state);
        drop(fabric);
        Some(source.subscribe(signal))
    }

    pub fn set_owner_uid(&self, uid: u32) {
        self.uid.set(uid);
    }
    fn route_source(&self, view: &crate::netdev::View, ip: IpAddr) -> Result<IpAddr> {
        view.source_for(ip, self.route_context())
    }
    fn route_context(&self) -> crate::netdev::RouteContext {
        let device = self.route_device.get();
        crate::netdev::RouteContext {
            mark: self.mark.get(),
            uid: self.uid.get(),
            device: (device != 0).then_some(device),
        }
    }
    pub fn info(&self) -> crate::SocketInfo {
        let fabric = self.network.0.fabric.0.borrow();
        let state = self.state.borrow();
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
    pub fn poll_epoch(&self) -> [u64; 2] {
        let i = self.network.0.fabric.0.borrow();
        i.nodes.get(&self.network.0.key).map_or([0; 2], |n| {
            let rx = n
                .links
                .iter()
                .fold(0u64, |s, l| s.wrapping_add(l.rx_packets));
            let tx = n
                .links
                .iter()
                .fold(0u64, |s, l| s.wrapping_add(l.tx_packets));
            [rx, rx.wrapping_add(tx)]
        })
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
    fn udp_destination_address(&self, address: SocketAddr) -> Result<SocketAddr> {
        self.normalize(if self.family == 10 && address.is_ipv4() {
            self.presented(address)
        } else {
            address
        })
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
        if let Some(v) = self.network.0.routing.get() {
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
        self.destination_ip(a.ip())
    }
    fn destination_ip(&self, v: IpAddr) -> Result<()> {
        if self.network.0.routing.get().is_none()
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
        if self.network.0.routing.get().is_none()
            && v.is_loopback()
            && !matches!(v,IpAddr::V4(a) if a==Ipv4Addr::LOCALHOST)
            && v != IpAddr::V6(Ipv6Addr::LOCALHOST)
        {
            return Err(NetError(99));
        }
        if let Some(view) = self.network.0.routing.get() {
            self.route_source(view, v)?;
            return Ok(());
        }
        if private_ip(v) && v != IpAddr::V4(v4(1)) && v != IpAddr::V6(v6(1)) {
            let i = self.network.0.fabric.0.borrow();
            if i.external.is_none()
                && !i
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
        if let Some(view) = self.network.0.routing.get() {
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
    fn port_free(&self, address: SocketAddr, usage: PortUse) -> bool {
        let i = self.network.0.fabric.0.borrow();
        let Some(n) = i.nodes.get(&self.network.0.key) else {
            return false;
        };
        let own = self.state.borrow();
        let dual = self.family == 10 && !own.v6_only;
        let mut udp_owner = None;
        let free = n
            .registry
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|s| !std::ptr::eq(s.as_ref(), self.meta.as_ref()) && s.kind == self.kind)
            .all(|s| {
                let other = s.state.borrow();
                let Some(bound) = other.bound else {
                    return true;
                };
                if !addresses_overlap(address, dual, bound, s.family == 10 && !other.v6_only)
                    || own.device.zip(other.device).is_some_and(|(a, b)| a != b)
                {
                    return true;
                }
                if usage == PortUse::Listen && other.connection != Connection::Listening {
                    return true;
                }
                if usage == PortUse::Ephemeral {
                    return false;
                }
                let reusable_port =
                    own.reuse_port && other.reuse_port && self.uid.get() == s.uid.get();
                if usage == PortUse::Bind
                    && own.reuse
                    && other.reuse
                    && (self.kind == 2 || other.connection != Connection::Listening)
                {
                    return true;
                }
                if self.kind == 2 && own.reuse_port {
                    // Linux UDP walks the port chain newest binding first. The
                    // first overlap not admitted by REUSEADDR decides REUSEPORT.
                    if udp_owner.is_none_or(|(order, _)| other.udp_bind_order > order) {
                        udp_owner = Some((other.udp_bind_order, reusable_port));
                    }
                    return true;
                }
                reusable_port
            });
        if !free || self.kind != 1 || usage == PortUse::Listen {
            return free && udp_owner.is_none_or(|(_, reusable)| reusable);
        }
        // Closing TCP endpoints still own their local port after guest FD
        // retirement. Reusing it here can deliver a new SYN to old TIME_WAIT
        // state. The original protocol deadline, not FD lifetime, releases it.
        n.detached.iter().all(|entry| {
            if usage == PortUse::Bind && own.reuse && entry.reuse_addr
                || own.device.zip(entry.device).is_some_and(|(a, b)| a != b)
            {
                return true;
            }
            let socket = n.sockets.get::<tcp::Socket>(entry.handle);
            socket.state() == tcp::State::Closed
                || socket.local_endpoint().is_none_or(|endpoint| {
                    let b = super::address(endpoint);
                    !addresses_overlap(address, dual, b, false)
                })
        })
    }
    fn choose_port(&self, ip: IpAddr) -> Result<u16> {
        // Randomize once per original namespace, then visit the range before
        // reuse. A fresh random choice per connection collides with a remote
        // peer's TIME_WAIT even after our local endpoint has fully closed.
        // The namespace binding lock already serializes port selection.
        let cursor = self.network.0.ephemeral_port.get();
        let [low, high] = self.network.port_range();
        let span = u32::from(high) - u32::from(low) + 1;
        let first = if (low..=high).contains(&cursor) {
            u32::from(cursor - low)
        } else {
            let mut seed = [0; 2];
            getrandom::fill(&mut seed).map_err(|_| NetError(5))?;
            u32::from(u16::from_ne_bytes(seed)) % span
        };
        for n in 0..span {
            let p = low + ((first + n) % span) as u16;
            if self.port_free(SocketAddr::new(ip, p), PortUse::Ephemeral) {
                self.network
                    .0
                    .ephemeral_port
                    .set(if p == high { low } else { p + 1 });
                return Ok(p);
            }
        }
        Err(NetError(98))
    }
    pub fn bind(&self, a: SocketAddr) -> Result<()> {
        let _binding = self.network.0.binding.lock();
        self.bind_locked(a, true)
    }
    pub(super) fn ensure_bound(&self) -> Result<()> {
        let _binding = self.network.0.binding.lock();
        if self.state.borrow().bound.is_some() {
            return Ok(());
        }
        let requested = self
            .state
            .borrow()
            .requested_bind
            .unwrap_or_else(|| self.wildcard());
        self.bind_locked(self.presented(requested), false)
    }
    fn bind_locked(&self, a: SocketAddr, explicit: bool) -> Result<()> {
        self.fabric().tick();
        if self.family == 10 && a.is_ipv4() {
            return Err(NetError(22));
        }
        let requested = self.normalize(a)?;
        let mut a = requested;
        if self.network.0.finished.get() {
            return Err(NetError(100));
        }
        if self.state.borrow().bound.is_some() {
            return Err(NetError(22));
        }
        if !(self.own(a.ip()) || self.kind == 2 && multicast::group(a.ip())) {
            return Err(NetError(99));
        }
        if self.kind == 4 {
            a.set_port(0);
        } else if a.port() == 0 {
            a.set_port(self.choose_port(a.ip())?);
        } else if !self.port_free(a, PortUse::Bind) {
            return Err(NetError(98));
        }
        if self.kind == 3 {
            let mut i = self.network.0.fabric.0.borrow_mut();
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
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            n.udp_bind_order += 1;
            let mut state = self.state.borrow_mut();
            state.udp_bind_order = n.udp_bind_order;
            if let Some(source) = &state.udp_readable {
                n.udp_readers.insert(state.udp_bind_order, source.clone());
            }
            state.udp_shared = state.reuse || state.reuse_port;
            state.udp_group = state.reuse_port.then(|| self.reuse_port_group());
            let specific = !a.ip().is_unspecified();
            for (index, address) in addresses.into_iter().enumerate() {
                if let Some(handle) = state.handles.get(index) {
                    state.bind_udp_handle(
                        n.sockets.get_mut::<udp::Socket>(*handle),
                        address,
                        specific,
                    )?;
                } else {
                    let socket = state.bound_udp_handle(address, specific)?;
                    state.handles.push(n.sockets.add(socket));
                }
            }
        }
        let mut state = self.state.borrow_mut();
        if explicit {
            state.requested_bind = Some(requested);
        }
        state.bound = Some(a);
        Ok(())
    }
    pub(crate) fn preflight_listen(&self, _backlog: u32) -> Result<()> {
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
        if !self.state.borrow().shared_tcp_binding || self.port_free(bound, PortUse::Listen) {
            Ok(())
        } else {
            Err(NetError(98))
        }
    }
    pub fn listen(&self, backlog: u32) -> Result<()> {
        if self.kind != 1 {
            return Err(NetError(95));
        }
        let state = self.state.borrow();
        match state.connection {
            Connection::Listening => return Ok(()),
            Connection::Idle => {}
            _ => return Err(NetError(22)),
        }
        let bound = state.bound;
        drop(state);
        let bound = match bound {
            Some(address) => address,
            None => {
                // An unbound Linux TCP listener acquires an ephemeral port
                // in its own network namespace on the first listen.
                self.ensure_bound()?;
                self.state.borrow().bound.ok_or(NetError(22))?
            }
        };
        let shared = self.state.borrow().shared_tcp_binding;
        let _binding = shared.then(|| self.network.0.binding.lock());
        if shared && !self.port_free(bound, PortUse::Listen) {
            return Err(NetError(98));
        }
        let addresses = self.addresses(bound);
        let backlog = (backlog as usize)
            .saturating_add(1)
            .min(crate::socket_quota::GUEST_SOCKET_LIMIT);
        let mut i = self.network.0.fabric.0.borrow_mut();
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        if state.reuse_port {
            n.next_listener += 1;
            state.listener_rank = n.next_listener;
        }
        if backlog > 1 {
            n.growing_listeners.push(Arc::downgrade(&self.meta));
        }
        for a in addresses {
            let mut socket = state.new_tcp_socket();
            socket
                .listen_queued(endpoint(a), backlog)
                .map_err(|_| NetError(22))?;
            state.handles.push(n.sockets.add(socket));
        }
        state.connection = Connection::Listening;
        state.read_closed = false;
        state.write_closed = false;
        state.backlog = backlog;
        Ok(())
    }
    pub fn accept(&self) -> Result<(Arc<Socket>, SocketAddr)> {
        if self.kind != 1 {
            return Err(NetError(95));
        }
        self.fabric().tick();
        let reservation = self.network.reserve()?;
        let mut i = self.network.0.fabric.0.borrow_mut();
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        if state.connection != Connection::Listening {
            return Err(NetError(22));
        }
        let index = state
            .handles
            .iter()
            .position(|h| n.sockets.get::<tcp::Socket>(*h).accept_ready())
            .ok_or(NetError(11))?;
        let handle = state.handles.swap_remove(index);
        let s = n.sockets.get_mut::<tcp::Socket>(handle);
        s.leave_accept_queue();
        let local = address(s.local_endpoint().unwrap());
        let peer = address(s.remote_endpoint().unwrap());
        if !state.handles.iter().any(|&other| {
            let slot = n.sockets.get::<tcp::Socket>(other);
            slot.is_listening() && slot.listen_endpoint().addr == Some(ip(local.ip()))
        }) {
            let mut replacement = state.new_tcp_socket();
            replacement
                .listen_queued(endpoint(local), state.backlog)
                .map_err(|_| NetError(22))?;
            state.handles.push(n.sockets.add(replacement));
        }
        let accepted = State {
            handles: vec![handle],
            connection: Connection::Connected,
            bound: Some(local),
            peer: Some(peer),
            error: None,
            connect_result_pending: false,
            read_closed: false,
            write_closed: false,
            v6_only: state.v6_only,
            reuse: state.reuse,
            reuse_port: state.reuse_port,
            listener_rank: 0,
            shared_tcp_binding: state.shared_tcp_binding,
            udp_bind_order: 0,
            requested_bind: None,
            udp_shared: false,
            udp_readable: None,
            udp_errors: None,
            udp_group: None,
            nodelay: state.nodelay,
            cork: state.cork,
            max_segment: state.max_segment,
            quick_ack: state.quick_ack,
            congestion: state.congestion,
            fin_wait_seconds: state.fin_wait_seconds,
            syn_retries: state.syn_retries,
            defer_accept_secs: state.defer_accept_secs,
            user_timeout_ms: state.user_timeout_ms,
            window_clamp: state.window_clamp,
            linger_enabled: state.linger_enabled,
            linger_seconds: state.linger_seconds,
            linger_closing: false,
            receive_inq: state.receive_inq,
            receive_low_water: state.receive_low_water,
            no_check: state.no_check,
            timestamp_option: state.timestamp_option,
            last_packet_ns: None,
            keepalive: state.keepalive,
            keep_idle: state.keep_idle,
            keep_interval: state.keep_interval,
            keep_count: state.keep_count,
            backlog: 1,
            icmp_pending: None,
            hop_limit: state.hop_limit,
            receive_hops: state.receive_hops,
            udp_options: state.udp_options,
            last_hop: None,
            broadcast: state.broadcast,
            multicast: None,
            icmp6_filter: state.icmp6_filter,
            hop_message: state.hop_message,
            device: state.device,
            raw_identifiers: std::collections::BTreeSet::new(),
            receive_buffer: state.receive_buffer,
            send_buffer: state.send_buffer,
        };
        drop(state);
        drop(i);
        let socket = self.network.wrap(self.family, 1, accepted, reservation);
        socket.uid.set(self.uid.get());
        socket.mark.set(self.mark.get());
        socket.route_device.set(self.route_device.get());
        Ok((socket, self.presented(peer)))
    }
    pub fn disconnect_udp(&self) -> Result<()> {
        if self.kind != 2 {
            return Err(NetError(97));
        }
        let _binding = self.network.0.binding.lock();
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let node = fabric
            .nodes
            .get_mut(&self.network.0.key)
            .ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        state.peer = None;
        state.connection = Connection::Idle;
        state.device = None;
        self.route_device.set(0);
        let explicit = state.requested_bind.filter(|a| a.port() != 0);
        if explicit.is_none() {
            node.udp_readers.remove(&state.udp_bind_order);
            state.udp_bind_order = 0;
        }
        for &h in &state.handles {
            let s = node.sockets.get_mut::<udp::Socket>(h);
            if explicit.is_some() {
                s.set_receive_peer(None);
            } else {
                s.release_binding();
            }
        }
        state.bound = explicit;
        Ok(())
    }
    pub fn connect(&self, a: SocketAddr) -> Result<()> {
        // Dual-stack UDP accepts a sockaddr_in directly on connect (glibc
        // probes available address families this way).
        let mut a = if self.kind == 2 {
            self.udp_destination_address(a)?
        } else {
            self.normalize(a)?
        };
        // Linux treats a connect to an unspecified address as local loopback.
        if a.ip().is_unspecified() {
            a.set_ip(if a.is_ipv4() {
                Ipv4Addr::LOCALHOST.into()
            } else {
                Ipv6Addr::LOCALHOST.into()
            });
        }
        // UDP connect is also Linux's source-route probe: a zero destination
        // port selects the source without establishing a getpeername peer.
        let group_source = if self.kind == 2 && multicast::group(a.ip()) {
            Some(IpAddr::V4(self.group_source(a, None)?.1))
        } else {
            None
        };
        if group_source.is_none() {
            if self.kind == 2 || self.kind == 1 && a.port() == 0 {
                self.destination_ip(a.ip())?;
            } else {
                self.destination(a)?;
            }
        }
        let mut state = self.state.borrow_mut();
        if self.kind == 1 {
            match state.connection {
                Connection::Connecting => return Err(NetError(114)),
                Connection::Connected => {
                    return if std::mem::take(&mut state.connect_result_pending) {
                        Ok(())
                    } else {
                        Err(NetError(106))
                    };
                }
                Connection::Listening => return Err(NetError(22)),
                Connection::Failed(_) => {
                    state.connection = Connection::Idle;
                    state.connect_result_pending = false;
                    return Err(NetError(state.error.take().unwrap_or(103)));
                }
                Connection::Idle => {}
            }
        }
        if self.kind == 1 && a.port() == 0 && self.own(a.ip()) {
            state.fail_connect(111);
            return Err(NetError(115));
        }
        let bound = state.bound;
        drop(state);
        if bound.is_none() {
            self.ensure_bound()?;
        }
        if self.kind != 1 {
            let mut fabric = self.network.0.fabric.0.borrow_mut();
            let mut s = self.state.borrow_mut();
            if self.kind == 2 && s.requested_bind.is_none_or(|b| b.ip().is_unspecified()) {
                let source = if let Some(source) = group_source {
                    source
                } else if let Some(view) = self.network.0.routing.get() {
                    self.route_source(view, a.ip())?
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
                };
                s.bound.as_mut().unwrap().set_ip(source);
            }
            if self.kind == 2 {
                let node = fabric
                    .nodes
                    .get_mut(&self.network.0.key)
                    .ok_or(NetError(100))?;
                for handle in &s.handles {
                    node.sockets
                        .get_mut::<udp::Socket>(*handle)
                        .set_receive_peer((a.port() != 0).then(|| endpoint(a)));
                }
            }
            s.peer = Some(a);
            s.connection = Connection::Connected;
            return Ok(());
        }
        let mut bound = self.state.borrow().bound.unwrap();
        if bound.ip().is_unspecified() {
            bound.set_ip(if let Some(view) = self.network.0.routing.get() {
                self.route_source(view, a.ip())?
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
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        if state.shared_tcp_binding && state.requested_bind.is_some() {
            let local = Some(endpoint(bound));
            let remote = Some(endpoint(a));
            if n.sockets.iter().any(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(tcp)
                if tcp.state() != tcp::State::Closed && tcp.local_endpoint() == local && tcp.remote_endpoint() == remote
                    && tcp.accepts_device(state.device.unwrap_or(0)))) {
                return Err(NetError(99));
            }
        }
        let mut s = state.new_tcp_socket();
        s.connect(n.iface.context(), endpoint(a), endpoint(bound))
            .map_err(|_| NetError(22))?;
        state.handles.push(n.sockets.add(s));
        state.bound = Some(bound);
        state.peer = Some(a);
        state.connect_result_pending = true;
        state.connection = Connection::Connecting;
        self.connecting
            .store(true, std::sync::atomic::Ordering::Relaxed);
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
        if !matches!(r, Ok(false)) {
            s.connect_result_pending = false;
            if matches!(s.connection, Connection::Failed(_)) {
                s.connection = Connection::Idle;
                s.error = None;
            }
        }
        r
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        let state = self.state.borrow();
        Ok(self.presented(
            state
                .bound
                .or(state.requested_bind)
                .unwrap_or_else(|| self.wildcard()),
        ))
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.state
            .borrow()
            .peer
            .filter(|a| self.kind != 2 || a.port() != 0)
            .map(|a| self.presented(a))
            .ok_or(NetError(107))
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if how > 2 {
            return Err(NetError(22));
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        let now = i.now();
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        if self.kind == 1 {
            match state.connection {
                Connection::Listening | Connection::Connecting => {
                    if state.connection == Connection::Listening && how == 1 {
                        return Ok(());
                    }
                    if state.connection == Connection::Listening && state.backlog > 1 {
                        n.growing_listeners
                            .retain(|weak| weak.as_ptr() != Arc::as_ptr(&self.meta));
                    }
                    for &handle in &state.handles {
                        let socket = n.sockets.get_mut::<tcp::Socket>(handle);
                        socket.leave_accept_queue();
                        socket.abort_with_context(n.iface.context());
                    }
                    n.iface.poll(now, &mut n.port, &mut n.sockets);
                    for handle in state.handles.drain(..) {
                        n.sockets.remove(handle);
                    }
                    if state.connection == Connection::Connecting {
                        self.connecting
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        state.fail_connect(104);
                    } else {
                        state.connection = Connection::Idle;
                    }
                    n.dirty = true;
                    drop(state);
                    i.tick();
                    return Ok(());
                }
                Connection::Connected
                    if matches!(
                        n.sockets.get::<tcp::Socket>(state.handles[0]).state(),
                        tcp::State::Closed | tcp::State::TimeWait
                    ) =>
                {
                    return Err(NetError(107))
                }
                _ => {}
            }
        }
        let connected = state.connection == Connection::Connected;
        if !connected && self.kind != 2 {
            return Err(NetError(107));
        }
        if how != 1 {
            state.read_closed = true;
        }
        if how != 0 {
            state.write_closed = true;
            if self.kind == 1 {
                n.sockets.get_mut::<tcp::Socket>(state.handles[0]).close();
                n.dirty = true;
            }
        }
        if how != 1 {
            if let Some(source) = &state.udp_readable {
                i.notifications.push(source.clone());
            }
        }
        drop(state);
        drop(i);
        self.fabric().tick();
        if connected {
            Ok(())
        } else {
            Err(NetError(107))
        }
    }
    // The caller has already progressed the original fabric. Never reacquire
    // it here just to recheck the same connection/error state.
    fn before_io(&self) -> Result<()> {
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
        self.send_control(bytes, flags, destination, Default::default())
    }
    pub fn send_control(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<SocketAddr>,
        control: crate::DatagramControl,
    ) -> Result<usize> {
        let info = control.packet_info;
        if self.kind == 1 && self.network.0.managed_uplink {
            if let Some(peer) = self.state.borrow().peer {
                self.destination(peer)?;
            }
        }
        if control != Default::default() && self.kind != 2 {
            return Err(NetError(95));
        }
        if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
            return Err(NetError(95));
        }
        if bytes.len() > MAX_TRANSFER {
            return Err(NetError(90));
        }
        if !matches!(self.kind, 1 | 2) {
            self.fabric().tick();
        }
        if self.kind == 3 {
            return self.send_icmp(bytes, destination);
        }
        if self.kind == 4 {
            return self.send_raw(bytes, destination);
        }
        if self.kind == 2 {
            let initial = self.state.borrow();
            initial.udp_errors.as_ref().unwrap().check_pending()?;
            let a = if let Some(a) = destination {
                let mut a = self.udp_destination_address(a)?;
                if a.ip().is_unspecified() {
                    a.set_ip(if a.is_ipv4() {
                        Ipv4Addr::LOCALHOST.into()
                    } else {
                        Ipv6Addr::LOCALHOST.into()
                    });
                }
                a
            } else {
                initial.peer.ok_or(NetError(89))?
            };
            drop(initial);
            if multicast::group(a.ip()) {
                return self.send_group(a, bytes, control);
            }
            self.destination(a)?;
            if bytes.len() > if a.is_ipv4() { 65507 } else { 65527 } {
                if a.is_ipv6() {
                    let mtu = if let Some(view) = self.network.0.routing.get() {
                        let graph = view.graph.read().unwrap();
                        let (_, index, _) =
                            graph.source_for(view.namespace, a.ip(), self.route_context())?;
                        graph.device(view.namespace, index)?.mtu
                    } else if a.ip().is_loopback() {
                        65536
                    } else {
                        self.network.0.info.mtu
                    };
                    let mut fabric = self.network.0.fabric.0.borrow_mut();
                    let state = self.state.borrow();
                    if state.udp_errors.as_ref().unwrap().too_big(a, mtu) {
                        if let Some(source) = &state.udp_readable {
                            fabric.notifications.push(source.clone());
                        }
                    }
                }
                return Err(NetError(90));
            }
            if self.state.borrow().bound.is_none() {
                self.ensure_bound()?;
            }
            let mut i = self.network.0.fabric.0.borrow_mut();
            let state = self.state.borrow();
            if state.write_closed {
                return Err(NetError(32));
            }
            // A mapped local IPv4 address fixes the source family, even on
            // an AF_INET6 descriptor with spare wildcard receive handles.
            if a.is_ipv6() && state.bound.is_some_and(|b| b.is_ipv4()) {
                return Err(NetError(97));
            }
            let group_bound = state.bound.is_some_and(|b| multicast::group(b.ip()));
            let selected = if let Some(info) = info.filter(|i| !i.address.is_unspecified()) {
                Some(info.address)
            } else if group_bound || state.bound.is_some_and(|b| b.ip().is_unspecified()) {
                self.network
                    .0
                    .routing
                    .get()
                    .map(|view| self.route_source(view, a.ip()))
                    .transpose()?
            } else {
                None
            };
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            let h = state
                .handles
                .iter()
                .find(|h| {
                    let ep = n.sockets.get::<udp::Socket>(**h).endpoint();
                    ep.addr.is_some_and(|p| {
                        if let Some(source) = selected {
                            addr(p) == source || group_bound
                        } else {
                            addr(p).is_ipv4() == a.is_ipv4()
                                && addr(p).is_loopback() == a.ip().is_loopback()
                        }
                    })
                })
                .copied()
                .ok_or_else(|| {
                    if a.is_ipv4()
                        && state
                            .bound
                            .is_some_and(|b| b.is_ipv6() && !b.ip().is_unspecified())
                    {
                        NetError(101)
                    } else {
                        NetError(99)
                    }
                })?;
            n.dirty = true;
            let sent = n
                .sockets
                .get_mut::<udp::Socket>(h)
                .send_slice(
                    bytes,
                    smoltcp::socket::udp::UdpMetadata {
                        endpoint: endpoint(a),
                        received_ns: 0,
                        local_port: 0,
                        local_address: info
                            .filter(|i| !i.address.is_unspecified())
                            .map(|i| ip(i.address))
                            .or_else(|| selected.filter(|_| group_bound).map(ip)),
                        meta: {
                            let family = usize::from(a.is_ipv6());
                            let defaults = state.udp_options[family].fields;
                            let fields = control.fields[family];
                            let mut meta = smoltcp::phy::PacketMeta::default();
                            meta.traffic_class =
                                fields.traffic_class.or(defaults.traffic_class).unwrap_or(0);
                            meta.omit_udp_checksum = state.no_check && a.is_ipv4();
                            meta.hop_limit = fields.hop_limit.or(defaults.hop_limit);
                            meta
                        },
                    },
                )
                .map_err(|e| match e {
                    udp::SendError::BufferFull => NetError(11),
                    _ => NetError(99),
                });
            drop(state);
            // A full queue can still own pending IP fragments. Advance that
            // original resource before returning EAGAIN, as on successful IO.
            i.tick();
            sent?;
            return Ok(bytes.len());
        }
        // Connected TCP always uses its established peer, including sendto().
        let mut i = self.network.0.fabric.0.borrow_mut();
        let can_enqueue = {
            let state = self.state.borrow();
            state.connection == Connection::Connected
                && i.nodes.get(&self.network.0.key).is_some_and(|n| {
                    state
                        .handles
                        .first()
                        .is_some_and(|h| n.sockets.get::<tcp::Socket>(*h).can_send())
                })
        };
        if !can_enqueue {
            i.tick();
        }
        self.before_io()?;
        let state = self.state.borrow();
        if state.write_closed || matches!(state.connection, Connection::Failed(_)) {
            return Err(NetError(32));
        }
        if state.connection != Connection::Connected {
            return Err(NetError(if self.network.0.finished.get() {
                107
            } else {
                32
            }));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let s = n.sockets.get_mut::<tcp::Socket>(state.handles[0]);
        if !s.may_send() {
            return Err(NetError(s.take_failure().map_or(32, tcp_errno)));
        }
        let count = s.send_slice(bytes).map_err(|_| NetError(32))?;
        n.dirty |= count != 0;
        drop(state);
        i.tick();
        if count == 0 {
            return Err(NetError(11));
        }
        Ok(count)
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Received> {
        // One UDP receive always consumes at most one record. MSG_WAITALL
        // cannot extend it. MSG_CTRUNC is an output flag.
        let wait_all = flags & 0x100 != 0;
        let ignored = MSG_NOSIGNAL | 8 | if matches!(self.kind, 1 | 2) { 0x100 } else { 0 };
        let flags = flags & !ignored;
        if self.kind == 2 && flags & crate::MSG_ERRQUEUE != 0 {
            if flags & !(crate::MSG_ERRQUEUE | MSG_DONTWAIT | MSG_TRUNC | MSG_PEEK) != 0 {
                return Err(NetError(95));
            }
            self.fabric().tick();
            let mut result = self
                .state
                .borrow()
                .udp_errors
                .as_ref()
                .unwrap()
                .receive(count, self.family == 10)?;
            result.address = result.address.map(|a| self.presented(a));
            return Ok(result);
        }
        if flags & !(MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT) != 0 {
            return Err(NetError(95));
        }
        if count > MAX_TRANSFER {
            return Err(NetError(90));
        }
        if !matches!(self.kind, 1 | 2) {
            self.fabric().tick();
        }
        if self.kind == 3 {
            return self.recv_icmp(count, flags);
        }
        if self.kind == 4 {
            return self.recv_raw(count, flags);
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        // Buffered data belongs to this socket. Do not advance unrelated
        // protocol resources just to dequeue it; progress only on exhaustion.
        let buffered = {
            let state = self.state.borrow();
            i.nodes.get(&self.network.0.key).is_some_and(|n| {
                if self.kind == 1 {
                    state.connection == Connection::Connected
                        && state
                            .handles
                            .first()
                            .is_some_and(|h| n.sockets.get::<tcp::Socket>(*h).can_recv())
                } else {
                    state
                        .handles
                        .iter()
                        .any(|h| n.sockets.get::<udp::Socket>(*h).can_recv())
                }
            })
        };
        if !buffered {
            i.tick();
        }
        let mut state = self.state.borrow_mut();
        if let Some(errors) = &state.udp_errors {
            errors.check_pending()?;
        }
        if self.kind == 1 {
            if state.connection == Connection::Connecting {
                return Err(NetError(11));
            }
            if let Some(error) = state.error {
                // An established stream delivers buffered bytes before its
                // pending reset. SO_ERROR and writes can still consume it.
                let drain_first = error == 104
                    && (buffered
                        || state
                            .handles
                            .first()
                            .and_then(|h| {
                                i.nodes
                                    .get(&self.network.0.key)
                                    .map(|n| n.sockets.get::<tcp::Socket>(*h).can_recv())
                            })
                            .unwrap_or(false));
                if !drain_first && count != 0 {
                    state.error = None;
                    return Err(NetError(error));
                }
            }
        }
        if self.kind == 1 && state.connection != Connection::Connected {
            if matches!(state.connection, Connection::Failed(_)) {
                return Ok(Received {
                    stream_minimum: 0,
                    packet_address: None,
                    netlink_address: None,
                    credentials: None,
                    ip: Default::default(),
                    packet_info: None,
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
            return Err(NetError(107));
        }
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        if self.kind == 1 {
            let s = n.sockets.get_mut::<tcp::Socket>(state.handles[0]);
            if count == 0 || !s.can_recv() {
                if count != 0 {
                    if let Some(failure) = s.take_failure() {
                        return Err(NetError(tcp_errno(failure)));
                    }
                    if s.may_recv() && !state.read_closed {
                        return Err(NetError(11));
                    }
                }
                return Ok(Received {
                    stream_minimum: 0,
                    packet_address: None,
                    netlink_address: None,
                    credentials: None,
                    ip: crate::ReceivedIp {
                        tcp_inq: state.receive_inq.then(|| s.receive_queue_hint()),
                        ..Default::default()
                    },
                    packet_info: None,
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
            let available = count.min(s.recv_queue());
            let timestamp = if state.timestamp_option != 0 {
                s.receive_timestamp(available)
                    .map(|ns| (state.timestamp_option, ns))
            } else {
                None
            };
            let (bytes, size) = if flags & MSG_TRUNC != 0 {
                let size = if flags & MSG_PEEK == 0 {
                    s.discard_received(available).map_err(|_| NetError(11))?
                } else {
                    available
                };
                (Vec::new(), size)
            } else {
                let mut bytes = vec![0; available];
                let size = if flags & MSG_PEEK != 0 {
                    s.peek_slice(&mut bytes)
                } else {
                    s.recv_slice(&mut bytes)
                }
                .map_err(|_| NetError(11))?;
                bytes.truncate(size);
                (bytes, size)
            };
            let stream_minimum = if state.read_closed
                || !matches!(
                    s.state(),
                    tcp::State::Established | tcp::State::FinWait1 | tcp::State::FinWait2
                ) {
                0
            } else {
                state.receive_low_water as usize
            };
            if flags & (MSG_PEEK | MSG_DONTWAIT) == MSG_PEEK && stream_minimum != 0 {
                let target = if wait_all {
                    count
                } else {
                    count.min(stream_minimum)
                };
                if size < target {
                    s.wait_for_readable_bytes(target);
                }
            }
            // Dequeuing preserves the cumulative ACK number. Only a newly
            // advertisable window needs an extra fabric poll.
            let advertise = flags & MSG_PEEK == 0 && size != 0 && s.window_to_update();
            let tcp_inq = state.receive_inq.then(|| s.receive_queue_hint());
            n.dirty |= advertise;
            drop(state);
            if advertise {
                i.tick();
            }
            Ok(Received {
                stream_minimum,
                packet_address: None,
                netlink_address: None,
                credentials: None,
                ip: crate::ReceivedIp {
                    tcp_inq,
                    timestamp,
                    ..Default::default()
                },
                packet_info: None,
                data: bytes,
                address: None,
                length: size,
                truncated: false,
            })
        } else {
            for h in &state.handles {
                let s = n.sockets.get_mut::<udp::Socket>(*h);
                if let Ok((data, meta)) = s.peek() {
                    // Peer filtering occurs on ingress. Datagrams queued before
                    // connect retain their original source and delivery order.
                    let source = address(meta.endpoint);
                    let size = data.len();
                    let bytes = data[..count.min(size)].to_vec();
                    let ipv6 = source.is_ipv6();
                    let options = state.udp_options[usize::from(ipv6)];
                    let mapped = !ipv6 && self.family == 10 && state.udp_options[1].receive_info;
                    let stamp = meta.received_ns;
                    let mut headers = crate::ReceivedIp {
                        error: None,
                        tcp_inq: None,
                        timestamp: (state.timestamp_option != 0)
                            .then_some((state.timestamp_option, stamp)),
                        spec_destination: None,
                        fields: crate::IpFields {
                            hop_limit: meta.meta.hop_limit.filter(|_| options.receive_hops),
                            traffic_class: options.receive_class.then_some(meta.meta.traffic_class),
                        },
                        ipv6,
                        mapped_info: mapped && options.receive_info,
                        original_destination: if options.original_destination {
                            meta.local_address
                                .map(|ip| SocketAddr::new(addr(ip), meta.local_port))
                        } else {
                            None
                        },
                    };
                    let packet_info = if options.receive_info || mapped {
                        meta.local_address.map(|a| {
                            let address = addr(a);
                            let interface = if meta.meta.ingress_index != 0 {
                                let idx = meta.meta.ingress_index;
                                headers.spec_destination = self
                                    .network
                                    .0
                                    .routing
                                    .get()
                                    .and_then(|v| {
                                        v.graph.read().unwrap().device(v.namespace, idx).ok()
                                    })
                                    .and_then(|d| {
                                        d.addresses.iter().find_map(|a| match a.ip {
                                            IpAddr::V4(v) => Some(v),
                                            _ => None,
                                        })
                                    });
                                idx
                            } else {
                                self.network
                                    .0
                                    .routing
                                    .get()
                                    .and_then(|v| {
                                        v.graph
                                            .read()
                                            .unwrap()
                                            .devices(v.namespace)
                                            .into_iter()
                                            .find(|d| d.addresses.iter().any(|a| a.ip == address))
                                    })
                                    .map_or(if address.is_loopback() { 1 } else { 2 }, |d| d.index)
                            };
                            let address = if mapped && !options.receive_info {
                                self.presented(SocketAddr::new(address, 0)).ip()
                            } else {
                                address
                            };
                            crate::PacketInfo { address, interface }
                        })
                    } else {
                        None
                    };
                    if state.timestamp_option == 0 {
                        state.last_packet_ns = Some(stamp);
                    }
                    if flags & MSG_PEEK == 0 {
                        let _ = s.recv();
                        if source.is_ipv4() {
                            n.iface.record_udp_read_v4();
                        }
                    }
                    return Ok(Received {
                        stream_minimum: 0,
                        packet_address: None,
                        netlink_address: None,
                        credentials: None,
                        ip: headers,
                        packet_info,
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
            if state.read_closed && flags & MSG_DONTWAIT == 0 {
                return Ok(Received {
                    stream_minimum: 0,
                    packet_address: None,
                    netlink_address: None,
                    credentials: None,
                    ip: Default::default(),
                    packet_info: None,
                    data: Vec::new(),
                    address: None,
                    length: 0,
                    truncated: false,
                });
            }
            Err(NetError(11))
        }
    }
    pub fn poll(&self, events: u16) -> Result<u16> {
        self.fabric().tick();
        let mut i = self.network.0.fabric.0.borrow_mut();
        let state = self.state.borrow();
        if self.kind == 1 && state.connection == Connection::Idle {
            return Ok(16 | (events & (4 | 0x100)));
        }
        if matches!(state.connection, Connection::Failed(_)) {
            return Ok(events & (1 | 4 | 0x40 | 0x100 | 0x2000)
                | 16
                | if state.error.is_some() { 8 } else { 0 });
        }
        let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
        let mut ready =
            if state.error.is_some() || state.udp_errors.as_ref().is_some_and(|e| e.ready()) {
                8
            } else {
                0
            };
        for h in &state.handles {
            if self.kind == 1 {
                let s = n.sockets.get_mut::<tcp::Socket>(*h);
                if state.connection == Connection::Listening {
                    if s.accept_ready() {
                        ready |= 1 | 0x40;
                    }
                } else if state.connection == Connection::Connected {
                    let threshold = (state.receive_low_water as usize).min(state.receive_buffer);
                    if s.recv_queue() >= threshold
                        || !matches!(
                            s.state(),
                            tcp::State::Established | tcp::State::FinWait1 | tcp::State::FinWait2
                        )
                        || state.read_closed
                    {
                        ready |= 1 | 0x40;
                    } else if threshold > 1 && events & (1 | 0x40) != 0 {
                        s.wait_for_readable_bytes(threshold);
                    }
                    if matches!(
                        s.state(),
                        tcp::State::CloseWait
                            | tcp::State::LastAck
                            | tcp::State::Closing
                            | tcp::State::TimeWait
                            | tcp::State::Closed
                    ) || state.read_closed
                    {
                        ready |= 0x2000;
                    }
                    if s.can_send() || !s.may_send() {
                        ready |= 4 | 0x100;
                    }
                    if matches!(
                        s.state(),
                        tcp::State::LastAck
                            | tcp::State::Closing
                            | tcp::State::TimeWait
                            | tcp::State::Closed
                    ) || state.read_closed && state.write_closed
                    {
                        ready |= 16;
                        if s.failure().is_some() {
                            ready |= 8;
                        }
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
        if self.kind == 2 && state.read_closed {
            ready |= 1 | 0x2000;
            if state.write_closed {
                ready |= 16;
            }
        }
        if self.kind != 1 && state.handles.is_empty() {
            ready |= 4;
        }
        Ok((ready & events) | (ready & 24))
    }
    pub fn set_option(&self, level: u32, name: u32, value: i32) -> Result<()> {
        if (level, name) == (1, 36) {
            self.mark.set(value as u32);
            return Ok(());
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        let mut state = self.state.borrow_mut();
        match (level, name) {
            (0, 11) | (41, 25) if self.kind == 2 && (level == 0 || self.family == 10) => {
                state
                    .udp_errors
                    .as_ref()
                    .unwrap()
                    .enable(level == 41, value != 0);
                return Ok(());
            }
            (0, 8 | 12 | 13 | 20) | (41, 49 | 51 | 66 | 74)
                if self.kind == 2 && (level == 0 || self.family == 10) =>
            {
                let options = &mut state.udp_options[usize::from(level == 41)];
                match name {
                    8 | 49 => options.receive_info = value != 0,
                    20 | 74 => options.original_destination = value != 0,
                    12 | 51 => options.receive_hops = value != 0,
                    _ => options.receive_class = value != 0,
                }
                return Ok(());
            }
            (0, 1 | 2) | (41, 16 | 67) if self.kind == 2 && (level == 0 || self.family == 10) => {
                let fields = &mut state.udp_options[usize::from(level == 41)].fields;
                match (level, name) {
                    (0, 1) => fields.traffic_class = Some(value as u8),
                    (41, 67) if (-1..=255).contains(&value) => {
                        fields.traffic_class = u8::try_from(value).ok()
                    }
                    (_, 2 | 16)
                        if value == -1
                            || (1..=255).contains(&value)
                            || level == 41 && value == 0 =>
                    {
                        fields.hop_limit = u8::try_from(value).ok()
                    }
                    _ => return Err(NetError(22)),
                }
                return Ok(());
            }
            (0, 33 | 34 | 49) if self.kind == 2 => return state.multicast_scalar(name, value),
            (1, 2) => {
                state.reuse = value != 0;
                state.shared_tcp_binding |= self.kind == 1 && state.reuse;
                state.udp_shared |= value != 0 && state.udp_bind_order != 0;
            }
            (1, 15) if matches!(self.kind, 1 | 2) => {
                state.reuse_port = value != 0;
                state.shared_tcp_binding |= self.kind == 1 && state.reuse_port;
                if state.udp_bind_order != 0 {
                    state.udp_shared |= state.reuse_port;
                    state.udp_group = state.reuse_port.then(|| self.reuse_port_group());
                }
            }
            (1, 29 | 35 | 63 | 64) if matches!(self.kind, 1 | 2) => {
                state.timestamp_option = if value == 0 { 0 } else { name };
            }
            (1, 11) if matches!(self.kind, 1 | 2) => state.no_check = value != 0,
            (1, 16) => return Err(NetError(95)),
            (1, 18) if matches!(self.kind, 1 | 2) => {
                state.receive_low_water = if value < 0 { i32::MAX } else { value.max(1) };
            }
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
            (1, 32 | 33) if !matches!(self.kind, 1 | 2) => return Err(NetError(92)),
            (1, 7 | 8 | 32 | 33) => {
                if !matches!(self.kind, 1 | 2) && (value <= 0 || value as usize > MAX_BUFFER) {
                    return Err(NetError(22));
                }
                if matches!(self.kind, 1 | 2) {
                    let bytes = crate::socket_buffer_size(name, value);
                    let mut writable = None;
                    let receive = matches!(name, 8 | 33);
                    if receive {
                        state.receive_buffer = bytes;
                        if let Some(errors) = &state.udp_errors {
                            errors.set_budget(bytes);
                        }
                    } else {
                        state.send_buffer = bytes;
                    }
                    let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
                    for h in &state.handles {
                        if self.kind == 1 {
                            let socket = n.sockets.get_mut::<tcp::Socket>(*h);
                            let was_writable = socket.can_send();
                            configure_tcp_buffer(socket, receive, bytes);
                            if !receive && !was_writable && socket.can_send() {
                                writable = n.tcp_waiters.get(h).cloned();
                            }
                            if receive && state.window_clamp != 0 {
                                socket.set_receive_window_limit(
                                    bytes.min(state.window_clamp as usize),
                                );
                            }
                            continue;
                        }
                        let s = n.sockets.get_mut::<udp::Socket>(*h);
                        configure_udp_buffer(s, receive, bytes);
                    }
                    i.notifications.extend(writable);
                }
            }
            (0, 33 | 34) if self.kind == 1 => return Err(NetError(22)),
            (6, 7) if self.kind == 1 => {
                if !(1..=127).contains(&value) {
                    return Err(NetError(22));
                }
                state.syn_retries = Some(value as u8);
            }
            (6, 9) if self.kind == 1 => {
                // Linux rounds up to a whole SYN retransmission interval (1,
                // 2, 4, ... seconds, capped at 120) and stores an 8-bit count.
                let mut seconds = 0;
                let mut interval = 1;
                for _ in 0..255 {
                    if seconds >= value {
                        break;
                    }
                    seconds += interval;
                    interval = (interval * 2).min(120);
                }
                state.defer_accept_secs = seconds as u32;
            }
            (6, 10) if self.kind == 1 => {
                if value == 0
                    && !matches!(state.connection, Connection::Idle | Connection::Failed(_))
                {
                    return Err(NetError(22));
                }
                state.window_clamp = if value == 0 {
                    0
                } else {
                    value.max((crate::socket_buffer_size(8, 0) / 2) as i32) as u32
                };
            }
            (6, 36) if self.kind == 1 => {
                state.receive_inq = match value {
                    0 => false,
                    1 => true,
                    _ => return Err(NetError(22)),
                };
                return Ok(());
            }
            (6, 18) if self.kind == 1 => {
                state.user_timeout_ms = value.try_into().map_err(|_| NetError(22))?;
            }
            (6, 8) if self.kind == 1 => {
                state.fin_wait_seconds = if value == 0 { 60 } else { value.clamp(-1, 120) };
                return Ok(());
            }
            (6, 1) if self.kind == 1 => state.nodelay = value != 0,
            (6, 2) if self.kind == 1 => {
                state.max_segment = match value {
                    0 => None,
                    88..=32767 => Some(value as u16),
                    _ => return Err(NetError(22)),
                };
            }
            (6, 3) if self.kind == 1 => state.cork = value != 0,
            (6, 12) if self.kind == 1 => state.quick_ack = value != 0,
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
            let flush = ((level, name) == (6, 1) && state.nodelay && state.cork).then(|| i.now());
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            n.dirty = true;
            for h in &state.handles {
                let s = n.sockets.get_mut::<tcp::Socket>(*h);
                match (level, name) {
                    (0, 2) | (41, 16) => s.set_hop_limit(Some(state.hop_limit)),
                    (6, 1) => {
                        s.set_nagle_enabled(!state.nodelay);
                        if let Some(now) = flush {
                            s.push_corked(now);
                        }
                    }
                    (1, 29 | 35 | 63 | 64) => {
                        s.enable_receive_timestamps(state.timestamp_option != 0)
                    }
                    (6, 9) => s.set_defer_accept(state.defer_accept_secs),
                    (6, 7) => s.set_syn_retries(state.syn_retries.unwrap()),
                    (6, 10) => s.set_receive_window_limit(if state.window_clamp == 0 {
                        state.receive_buffer
                    } else {
                        state.receive_buffer.min(state.window_clamp as usize)
                    }),
                    (6, 18) => s.set_user_timeout((state.user_timeout_ms != 0).then(|| {
                        smoltcp::time::Duration::from_millis(state.user_timeout_ms.into())
                    })),
                    (6, 2) => s.set_max_segment(state.max_segment),
                    (6, 3) => s.set_cork(state.cork),
                    (6, 12) => s.set_quick_ack(state.quick_ack),
                    (1, 9) | (6, 4) => s.set_keep_alive(
                        state
                            .keepalive
                            .then_some(smoltcp::time::Duration::from_secs(state.keep_idle as u64)),
                    ),
                    _ => {}
                }
            }
        }
        if matches!(self.kind, 2 | 3) {
            let n = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
            for h in &state.handles {
                if self.kind == 2 {
                    let socket = n.sockets.get_mut::<udp::Socket>(*h);
                    if (level, name) == (1, 2) && value != 0 {
                        socket.allow_shared_delivery();
                    } else if (level, name) == (1, 15) {
                        socket.set_reuse_port_group(state.udp_group);
                    }
                    socket.set_hop_limit(Some(state.hop_limit));
                } else {
                    n.sockets
                        .get_mut::<icmp::Socket>(*h)
                        .set_hop_limit(Some(state.hop_limit));
                }
            }
        }
        drop(state);
        i.driver_dirty = true;
        Ok(())
    }
    pub fn next_datagram_len(&self, peer: Option<SocketAddr>) -> Result<Option<usize>> {
        if self.kind != 2 {
            return Err(NetError(25));
        }
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        fabric.tick();
        let node = fabric.nodes.get(&self.network.0.key).ok_or(NetError(100))?;
        let peer = peer.map(|p| endpoint(SocketAddr::new(p.ip().to_canonical(), p.port())));
        Ok(self
            .state
            .borrow()
            .handles
            .iter()
            .find_map(|h| node.sockets.get::<udp::Socket>(*h).next_datagram_len(peer)))
    }
    pub fn tcp_readable_bytes(&self) -> Result<usize> {
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        fabric.tick();
        let state = self.state.borrow();
        if state.connection == Connection::Listening {
            return Err(NetError(22));
        }
        let node = fabric.nodes.get(&self.network.0.key).ok_or(NetError(100))?;
        Ok(state
            .handles
            .first()
            .map_or(0, |h| node.sockets.get::<tcp::Socket>(*h).recv_queue()))
    }
    pub fn tcp_info(&self) -> Result<[u8; 104]> {
        if self.kind != 1 {
            return Err(NetError(95));
        }
        let state_code = self.info().state;
        let fabric = self.network.0.fabric.0.borrow();
        let state = self.state.borrow();
        let socket = state.handles.first().and_then(|handle| {
            fabric
                .nodes
                .get(&self.network.0.key)
                .map(|node| node.sockets.get::<tcp::Socket>(*handle))
        });
        let mut out = [0; 104];
        out[0] = state_code;
        if let Some(socket) = socket {
            out[5] = u8::from(socket.sack_negotiated()) << 1;
            let [rto, rtt, variance, mss, cwnd, window] = socket.transport_info();
            for (offset, value) in [
                (8, rto),
                (16, mss),
                (68, rtt),
                (72, variance),
                (80, cwnd / mss.max(1)),
                (96, window),
            ] {
                out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        Ok(out)
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        if self.family == 2 && self.kind == 2 && level == 41 {
            return Err(NetError(95));
        }
        if (level, name) == (1, 36) {
            return Ok(self.mark.get() as i32);
        }
        if (level, name) == (1, 4) {
            let mut i = self.network.0.fabric.0.borrow_mut();
            i.tick();
            let mut state = self.state.borrow_mut();
            if let Some(errors) = &state.udp_errors {
                return Ok(errors.take_pending() as i32);
            }
            if let Some(error) = state.error.take() {
                return Ok(error as i32);
            }
            if self.kind == 1 && state.connection == Connection::Connected {
                let node = i.nodes.get_mut(&self.network.0.key).ok_or(NetError(100))?;
                if let Some(failure) = node
                    .sockets
                    .get_mut::<tcp::Socket>(state.handles[0])
                    .take_failure()
                {
                    return Ok(tcp_errno(failure) as i32);
                }
            }
            return Ok(0);
        }
        if self.kind == 1 && level == 6 && matches!(name, 2 | 12) {
            let fabric = self.network.0.fabric.0.borrow();
            let state = self.state.borrow();
            if state.connection == Connection::Connected {
                let node = fabric.nodes.get(&self.network.0.key).ok_or(NetError(100))?;
                let socket = node.sockets.get::<tcp::Socket>(state.handles[0]);
                return Ok(if name == 2 {
                    socket.send_mss() as i32
                } else {
                    i32::from(socket.quick_ack())
                });
            }
            return Ok(if name == 2 {
                i32::from(state.max_segment.unwrap_or(536))
            } else {
                i32::from(state.quick_ack)
            });
        }
        let state = self.state.borrow();
        if self.kind == 2 && (level == 0 || level == 41 && self.family == 10) {
            let options = state.udp_options[usize::from(level == 41)];
            match (level, name) {
                (0, 1) | (41, 67) => {
                    return Ok(i32::from(options.fields.traffic_class.unwrap_or(0)))
                }
                (0, 2) | (41, 16) => return Ok(i32::from(options.fields.hop_limit.unwrap_or(64))),
                (0, 11) | (41, 25) => {
                    return Ok(i32::from(
                        state.udp_errors.as_ref().unwrap().enabled(level == 41),
                    ))
                }
                (0, 8) | (41, 49) => return Ok(i32::from(options.receive_info)),
                (0, 20) | (41, 74) => return Ok(i32::from(options.original_destination)),
                (0, 13) | (41, 66) => return Ok(i32::from(options.receive_class)),
                (0, 12) | (41, 51) => return Ok(i32::from(options.receive_hops)),
                _ => {}
            }
        }
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
            (0, 33 | 34) if self.kind == 1 => Ok(state.multicast_value(name)),
            (0, 32 | 33 | 34 | 49) if self.kind == 2 => Ok(state.multicast_value(name)),
            (1, 2) => Ok(i32::from(state.reuse)),
            (1, 15) if matches!(self.kind, 1 | 2) => Ok(i32::from(state.reuse_port)),
            (1, 29 | 35 | 63 | 64) if matches!(self.kind, 1 | 2) => {
                Ok(i32::from(state.timestamp_option == name))
            }
            (1, 11) if matches!(self.kind, 1 | 2) => Ok(i32::from(state.no_check)),
            (1, 16) => Err(NetError(95)),
            (1, 18) if matches!(self.kind, 1 | 2) => Ok(state.receive_low_water),
            (1, 9) => Ok(i32::from(state.keepalive)),
            (1, 6) => Ok(i32::from(state.broadcast)),
            (0, 2) if self.family == 2 => Ok(state.hop_limit as i32),
            (41, 16) if self.family == 10 => Ok(state.hop_limit as i32),
            (0, 12) | (41, 51 | 8) => Ok(i32::from(state.receive_hops)),
            (1, 7 | 8) => Ok(if matches!(self.kind, 1 | 2) {
                if name == 8 {
                    state.receive_buffer
                } else {
                    state.send_buffer
                }
            } else {
                BUFFER
            } as i32),
            (6, 3) if self.kind == 1 => Ok(i32::from(state.cork)),
            (6, 7) if self.kind == 1 => Ok(state.syn_retries.unwrap_or(6).into()),
            (6, 9) if self.kind == 1 => Ok(state.defer_accept_secs as i32),
            (6, 10) if self.kind == 1 => Ok(state.window_clamp as i32),
            (6, 36) if self.kind == 1 => Ok(i32::from(state.receive_inq)),
            (6, 18) if self.kind == 1 => Ok(state.user_timeout_ms as i32),
            (6, 8) if self.kind == 1 => Ok(state.fin_wait_seconds),
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
    pub fn last_packet_ns(&self) -> Result<u64> {
        if self.kind != 2 {
            return Err(NetError(25));
        }
        self.state.borrow().last_packet_ns.ok_or(NetError(2))
    }
    pub(crate) fn congestion_name(&self) -> Result<[u8; 16]> {
        if self.kind != 1 {
            return Err(NetError(95));
        }
        let name: &[u8] = match self.state.borrow().congestion {
            tcp::CongestionControl::Cubic => b"cubic",
            tcp::CongestionControl::Reno => b"reno",
            tcp::CongestionControl::None => b"none",
        };
        let mut out = [0; 16];
        out[..name.len()].copy_from_slice(name);
        Ok(out)
    }
    // Called only after close has removed the last file description and socket
    // lease. The caller can park while the original transport drains its FIN.
    pub(crate) fn start_linger(&self) -> Option<Duration> {
        let state = self.state.borrow_mut();
        if self.kind != 1
            || !state.linger_enabled
            || state.linger_seconds == 0
            || state.connection != Connection::Connected
        {
            return None;
        }
        let duration = Duration::from_secs(state.linger_seconds.into());
        let handle = state.handles[0];
        drop(state);
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let node = fabric.nodes.get_mut(&self.network.0.key)?;
        let tcp = node.sockets.get_mut::<tcp::Socket>(handle);
        if tcp.recv_queue() != 0 {
            return None;
        }
        tcp.close_final();
        if !matches!(
            tcp.state(),
            tcp::State::FinWait1 | tcp::State::Closing | tcp::State::LastAck
        ) {
            return None;
        }
        self.state.borrow_mut().linger_closing = true;
        node.dirty = true;
        Some(duration)
    }
    pub(crate) fn linger_done(&self) -> bool {
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        fabric.tick();
        let state = self.state.borrow();
        let Some(node) = fabric.nodes.get(&self.network.0.key) else {
            return true;
        };
        !matches!(
            node.sockets.get::<tcp::Socket>(state.handles[0]).state(),
            tcp::State::FinWait1 | tcp::State::Closing | tcp::State::LastAck
        )
    }
    pub(crate) fn bind_device(&self, value: &[u8], can_rebind: bool) -> Result<()> {
        if value.len() > 16 {
            return Err(NetError(22));
        }
        let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
        let device = if value[..end].is_empty() {
            None
        } else if let Some(view) = self.network.0.routing.get() {
            Some(view.device(&value[..end])?)
        } else {
            match &value[..end] {
                b"lo" => Some(1),
                b"eth0" if !self.network.is_isolated() => Some(2),
                _ => return Err(NetError(19)),
            }
        };
        if self.kind != 4 && self.network.0.routing.get().is_none() {
            return Err(NetError(95));
        }
        let _binding = self.network.0.binding.lock();
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let node = fabric
            .nodes
            .get_mut(&self.network.0.key)
            .ok_or(NetError(100))?;
        let mut state = self.state.borrow_mut();
        if state.device.is_some() && !can_rebind {
            return Err(NetError(1));
        }
        state.device = device;
        state.shared_tcp_binding |= self.kind == 1 && device.is_some();
        let index = device.unwrap_or(0);
        for handle in &state.handles {
            match self.kind {
                1 => node
                    .sockets
                    .get_mut::<tcp::Socket>(*handle)
                    .set_linux_binding(
                        index,
                        state.listener_rank,
                        state.bound.is_some_and(|a| !a.ip().is_unspecified()),
                    ),
                2 => node
                    .sockets
                    .get_mut::<udp::Socket>(*handle)
                    .set_ingress_device(index),
                _ => {}
            }
        }
        self.route_device.set(device.unwrap_or(0));
        Ok(())
    }
    pub(crate) fn bound_device_name(&self) -> Result<Vec<u8>> {
        let Some(index) = self.state.borrow().device else {
            return Ok(Vec::new());
        };
        let mut name = if let Some(view) = self.network.0.routing.get() {
            view.graph
                .read()
                .unwrap()
                .device(view.namespace, index)?
                .name
        } else {
            match index {
                1 => b"lo".to_vec(),
                2 => b"eth0".to_vec(),
                _ => return Err(NetError(19)),
            }
        };
        name.push(0);
        Ok(name)
    }
    pub fn linger(&self) -> Result<[u8; 8]> {
        let state = self.state.borrow();
        let mut value = [0; 8];
        value[..4].copy_from_slice(&i32::from(state.linger_enabled).to_le_bytes());
        value[4..].copy_from_slice(&state.linger_seconds.to_le_bytes());
        Ok(value)
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if (level, name) == (6, 13) && self.kind == 1 {
            let name = value.split(|b| *b == 0).next().unwrap_or_default();
            let selected = match name {
                b"reno" => tcp::CongestionControl::Reno,
                b"cubic" => tcp::CongestionControl::Cubic,
                _ => return Err(NetError(2)),
            };
            let mut fabric = self.network.0.fabric.0.borrow_mut();
            let mut state = self.state.borrow_mut();
            if state.congestion != selected {
                let node = fabric
                    .nodes
                    .get_mut(&self.network.0.key)
                    .ok_or(NetError(100))?;
                for &h in &state.handles {
                    node.sockets
                        .get_mut::<tcp::Socket>(h)
                        .set_congestion_control(selected);
                }
                state.congestion = selected;
                node.dirty = true;
            }
            return Ok(());
        }
        if level == 0 && self.kind == 2 && matches!(name, 32 | 35 | 36) {
            return self.membership(name, value);
        }
        if (level, name) == (1, 13) {
            let linger = crate::parse_linger(value)?;
            let mut state = self.state.borrow_mut();
            state.linger_enabled = linger.is_some();
            if let Some(duration) = linger {
                state.linger_seconds = duration.as_secs() as u32;
            }
            return Ok(());
        }
        if (level, name) == (58, 1) && self.family == 10 && self.kind == 4 {
            if value.len() != 32 {
                return Err(NetError(22));
            }
            self.state.borrow_mut().icmp6_filter.copy_from_slice(value);
            return Ok(());
        }
        if (level, name) == (1, 25) {
            return self.bind_device(value, true);
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
            self.ensure_bound()?;
        }
        if bytes[0] == if self.family == 2 { 8 } else { 128 } && bytes[1] == 0 {
            let mut state = self.state.borrow_mut();
            let identifier = u16::from_be_bytes([bytes[4], bytes[5]]);
            if state.raw_identifiers.len() >= 32 && !state.raw_identifiers.contains(&identifier) {
                return Err(NetError(105));
            }
            state.raw_identifiers.insert(identifier);
        }
        let mut fabric = self.network.0.fabric.0.borrow_mut();
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
        } else if let Some(view) = self.network.0.routing.get() {
            self.route_source(view, a.ip())?
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
            self.ensure_bound()?;
        }
        let mut fabric = self.network.0.fabric.0.borrow_mut();
        let mut state = self.state.borrow_mut();
        if let Some(errno) = state.error.take() {
            return Err(NetError(errno));
        }
        if state.read_closed {
            return Ok(Received {
                stream_minimum: 0,
                packet_address: None,
                netlink_address: None,
                credentials: None,
                ip: Default::default(),
                packet_info: None,
                data: Vec::new(),
                address: None,
                length: 0,
                truncated: false,
            });
        }
        if state.icmp_pending.is_none() {
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
            stream_minimum: 0,
            packet_address: None,
            netlink_address: None,
            credentials: None,
            ip: Default::default(),
            packet_info: None,
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
            self.ensure_bound()?;
        }
        let mut i = self.network.0.fabric.0.borrow_mut();
        let state = self.state.borrow();
        if state.write_closed {
            return Err(NetError(32));
        }
        let mut data = bytes.to_vec();
        data[4..6].copy_from_slice(&state.bound.unwrap().port().to_be_bytes());
        if a.is_ipv4() {
            smoltcp::wire::Icmpv4Packet::new_unchecked(&mut data).fill_checksum();
        } else {
            let source = if let Some(view) = self.network.0.routing.get() {
                let IpAddr::V6(source) = self.route_source(view, a.ip())? else {
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
        let mut i = self.network.0.fabric.0.borrow_mut();
        let mut state = self.state.borrow_mut();
        if let Some(errno) = state.error.take() {
            return Err(NetError(errno));
        }
        if state.read_closed {
            return Ok(Received {
                stream_minimum: 0,
                packet_address: None,
                netlink_address: None,
                credentials: None,
                ip: Default::default(),
                packet_info: None,
                data: Vec::new(),
                address: None,
                length: 0,
                truncated: false,
            });
        }
        if state.icmp_pending.is_none() {
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
            stream_minimum: 0,
            packet_address: None,
            netlink_address: None,
            credentials: None,
            ip: Default::default(),
            packet_info: None,
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
