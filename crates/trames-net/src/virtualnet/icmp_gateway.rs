// SPDX-License-Identifier: GPL-3.0-or-later
//! ICMP echo egress uses unprivileged native datagram sockets, never host raw sockets.
use super::*;
pub(super) struct Flow {
    pub node: u64,
    tuple: Tuple,
    identifier: u16,
    pub native: Rc<native::Socket>,
    owner: Weak<Socket>,
    pub pending: Option<Vec<u8>>,
    last: Instant,
}
impl Gateway {
    pub(super) fn icmp_ingress(
        &mut self,
        key: u64,
        p: &[u8],
        h: &packet::Header,
        nodes: &BTreeMap<u64, Node>,
    ) -> bool {
        let data = &p[h.offset..];
        let v4 = h.protocol == 1;
        if data.len() < 8
            || data.len() > 1400
            || data[0] != if v4 { 8 } else { 128 }
            || data[1] != 0
        {
            return false;
        }
        let checksum = if v4 {
            smoltcp::wire::Icmpv4Packet::new_unchecked(data).verify_checksum()
        } else {
            let (IpAddr::V6(source), IpAddr::V6(destination)) =
                (h.tuple.source.ip(), h.tuple.destination.ip())
            else {
                return false;
            };
            smoltcp::wire::Icmpv6Packet::new_unchecked(data).verify_checksum(&source, &destination)
        };
        if !checksum {
            return false;
        }
        let identifier = u16::from_be_bytes([data[4], data[5]]);
        let owner = nodes.get(&key).and_then(|n| {
            n.registry.iter().filter_map(Weak::upgrade).find(|s| {
                if s.family != if v4 { 2 } else { 10 } || !matches!(s.kind, 3 | 4) {
                    return false;
                }
                let state = s.state.borrow();
                state.bound.is_some_and(|a| {
                    (a.ip().is_unspecified() || a.ip() == h.tuple.source.ip())
                        && if s.kind == 3 {
                            a.port() == identifier
                        } else {
                            state.raw_identifiers.contains(&identifier)
                        }
                }) && state
                    .peer
                    .is_none_or(|a| a.ip() == h.tuple.destination.ip())
            })
        });
        let Some(owner) = owner else {
            return false;
        };
        let position = if let Some(i) = self
            .icmp
            .iter()
            .position(|f| f.node == key && f.identifier == identifier && f.tuple == h.tuple)
        {
            i
        } else {
            if self.icmp.len() >= 32 || self.flow_count() >= FLOWS {
                owner.state.borrow_mut().error = Some(105);
                return false;
            }
            let actual = self
                .mappings
                .get(&h.tuple.destination.ip())
                .copied()
                .unwrap_or(h.tuple.destination.ip());
            if actual.is_ipv4() != v4 {
                owner.state.borrow_mut().error = Some(97);
                return false;
            }
            let socket =
                match self
                    .native
                    .socket(if v4 { 2 } else { 10 }, 2, if v4 { 1 } else { 58 })
                {
                    Ok(s) => s,
                    Err(e) => {
                        owner.state.borrow_mut().error = Some(e.0);
                        return false;
                    }
                };
            if let Err(e) = socket.connect(SocketAddr::new(actual, 0)) {
                owner.state.borrow_mut().error = Some(e.0);
                return false;
            }
            self.icmp.push(Flow {
                node: key,
                tuple: h.tuple,
                identifier,
                native: socket,
                owner: Rc::downgrade(&owner),
                pending: None,
                last: Instant::now(),
            });
            self.icmp.len() - 1
        };
        let flow = &mut self.icmp[position];
        if flow.pending.is_some() {
            owner.state.borrow_mut().error = Some(11);
            return false;
        }
        match flow.native.send(data, 0, None) {
            Ok(_) => flow.last = Instant::now(),
            Err(NetError(11)) => flow.pending = Some(data.to_vec()),
            Err(e) => {
                owner.state.borrow_mut().error = Some(e.0);
                return false;
            }
        }
        true
    }
    pub(super) fn icmp_service(&mut self, nodes: &BTreeMap<u64, Node>) {
        let mut replies = Vec::new();
        self.icmp.retain_mut(|flow| {
            if !nodes.contains_key(&flow.node)
                || flow.owner.strong_count() == 0
                || flow.last.elapsed() > Duration::from_secs(60)
            {
                return false;
            }
            if let Some(data) = flow.pending.take() {
                match flow.native.send(&data, 0, None) {
                    Ok(_) => flow.last = Instant::now(),
                    Err(NetError(11)) => flow.pending = Some(data),
                    Err(e) => {
                        if let Some(s) = flow.owner.upgrade() {
                            s.state.borrow_mut().error = Some(e.0);
                        }
                        return false;
                    }
                }
            }
            for _ in 0..4 {
                let received = match flow.native.recv(65536, 0) {
                    Ok(r) => r,
                    Err(NetError(11)) => break,
                    Err(e) => {
                        if let Some(s) = flow.owner.upgrade() {
                            s.state.borrow_mut().error = Some(e.0);
                        }
                        return false;
                    }
                };
                let mut data = received.data;
                let mut hop = 64;
                // Darwin includes an IPv4 header; Linux ping sockets return just ICMP.
                if data.first().is_some_and(|b| b >> 4 == 4) {
                    let offset = ((data[0] & 15) as usize) * 4;
                    if offset < 20 || data.len() < offset + 8 {
                        continue;
                    }
                    hop = data[8];
                    data.drain(..offset);
                } else if data.first().is_some_and(|b| b >> 4 == 6) {
                    if data.len() < 48 {
                        continue;
                    }
                    hop = data[7];
                    data.drain(..40);
                }
                let v4 = flow.tuple.destination.is_ipv4();
                if data.len() < 8
                    || data.len() > 1400
                    || data[0] != if v4 { 0 } else { 129 }
                    || data[1] != 0
                {
                    continue;
                }
                if v4 && !smoltcp::wire::Icmpv4Packet::new_unchecked(&data).verify_checksum() {
                    continue;
                }
                data[4..6].copy_from_slice(&flow.identifier.to_be_bytes());
                let repr = match (flow.tuple.destination.ip(), flow.tuple.source.ip()) {
                    (IpAddr::V4(source), IpAddr::V4(destination)) => {
                        smoltcp::wire::Icmpv4Packet::new_unchecked(&mut data).fill_checksum();
                        IpRepr::Ipv4(Ipv4Repr {
                            src_addr: source,
                            dst_addr: destination,
                            next_header: IpProtocol::Icmp,
                            payload_len: data.len(),
                            hop_limit: hop,
                        })
                    }
                    (IpAddr::V6(source), IpAddr::V6(destination)) => {
                        smoltcp::wire::Icmpv6Packet::new_unchecked(&mut data)
                            .fill_checksum(&source, &destination);
                        IpRepr::Ipv6(Ipv6Repr {
                            src_addr: source,
                            dst_addr: destination,
                            next_header: IpProtocol::Icmpv6,
                            payload_len: data.len(),
                            hop_limit: hop,
                        })
                    }
                    _ => continue,
                };
                let mut packet = vec![0; repr.header_len()];
                repr.emit(&mut packet, &ChecksumCapabilities::default());
                packet.extend_from_slice(&data);
                if replies.len() < 96 {
                    replies.push(packet);
                }
                flow.last = Instant::now();
            }
            true
        });
        for packet in replies {
            if self.node.port.tx.len() < 96 {
                self.node.port.tx.push_back(packet);
            }
        }
    }
}
