use super::*;

#[cfg(feature = "socket-dns")]
use crate::socket::dns::Socket as DnsSocket;

#[cfg(feature = "socket-udp")]
use crate::socket::udp::Socket as UdpSocket;

impl InterfaceInner {
    #[cfg(all(feature = "std", feature = "socket-udp"))]
    pub(super) fn udp_unreachable(
        &mut self,
        sockets: &mut SocketSet,
        outer: IpRepr,
        quoted: IpRepr,
        code: u8,
        data: &[u8],
        interface: u32,
    ) {
        if quoted.src_addr() != outer.dst_addr() || data.len() < 8 { return; }
        #[cfg(feature = "socket-raw")]
        for (_, item) in sockets.iter_mut() {
            if let Some(raw) = crate::socket::raw::Socket::downcast_mut(item) {
                raw.unreachable(&outer, &quoted, code, &data[..data.len().min(quoted.payload_len())], interface);
            }
            #[cfg(feature = "socket-icmp")]
            if matches!(quoted.next_header(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                if let Some(icmp) = crate::socket::icmp::Socket::downcast_mut(item) {
                    icmp.unreachable(&outer, &quoted, code, &data[..data.len().min(quoted.payload_len())], interface);
                }
            }
        }
        if quoted.next_header() != IpProtocol::Udp { return; }
        let len = usize::from(u16::from_be_bytes([data[4], data[5]]));
        if len < 8 || quoted.payload_len() < 8 {
            return;
        }
        let local = IpEndpoint::new(quoted.src_addr(), u16::from_be_bytes([data[0], data[1]]));
        let peer = IpEndpoint::new(quoted.dst_addr(), u16::from_be_bytes([data[2], data[3]]));
        if local.port == 0 {
            return;
        }
        let owner = sockets
            .iter_mut()
            .filter_map(|(h, item)| {
                UdpSocket::downcast_mut(item)?
                    .error_rank(local, peer)
                    .map(|rank| (rank, h))
            })
            .max_by_key(|(rank, _)| *rank);
        if let Some(((connected, specific, _), mut h)) = owner {
            if let Some(group) = sockets.get::<UdpSocket>(h).reuse_port_group {
                // Use the same return-flow affinity as an ordinary UDP reply.
                let flow = socket_flow(peer, local);
                if let Some((_, chosen)) = sockets
                    .iter_mut()
                    .filter_map(|(candidate, item)| {
                        let socket = UdpSocket::downcast_mut(item)?;
                        let (c, s, order) = socket.error_rank(local, peer)?;
                        (socket.reuse_port_group == Some(group) && (c, s) == (connected, specific))
                            .then(|| (mix_flow(flow ^ mix_flow(order)), candidate))
                    })
                    .max_by_key(|(score, _)| *score)
                {
                    h = chosen;
                }
            }
            sockets.get::<UdpSocket>(h).unreachable(
                self,
                outer.src_addr(),
                peer,
                code,
                &data[8..data.len().min(len).min(quoted.payload_len())],
            );
        }
    }

    pub(super) fn process_udp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let parsed = UdpPacket::new_checked(ip_payload).and_then(|packet| {
            let repr = UdpRepr::parse(&packet, &src_addr, &dst_addr, &self.caps.checksum)?;
            Ok((packet, repr))
        });
        let Ok((udp_packet, udp_repr)) = parsed else {
            #[cfg(feature = "proto-ipv4")]
            if matches!(ip_repr, IpRepr::Ipv4(_)) {
                self.counters.udp_invalid += 1;
            }
            return None;
        };

        #[cfg(feature = "socket-udp")]
        {
            let mut shared = None;
            for (handle, item) in sockets.iter_mut() {
                let Some(socket) = UdpSocket::downcast_mut(item) else {
                    continue;
                };
                if (socket.ingress_device != 0 && socket.ingress_device != meta.ingress_index)
                    || !socket.accepts(self, &ip_repr, &udp_repr)
                {
                    continue;
                }
                let Some(rank) = socket.shared_priority() else {
                    socket.process_wire(self, meta, &ip_repr, &udp_repr, &udp_packet);
                    return None;
                };
                if shared.as_ref().is_none_or(|(best, _, _)| rank > *best) {
                    shared = Some((rank, handle, socket.reuse_port_group));
                }
            }
            if let Some(((priority, _), mut handle, group)) = shared {
                if let Some(group) = group {
                    let flow = socket_flow(
                        IpEndpoint::new(src_addr, udp_repr.src_port),
                        IpEndpoint::new(dst_addr, udp_repr.dst_port),
                    );
                    let mut best = None;
                    for (candidate, item) in sockets.iter_mut() {
                        let Some(socket) = UdpSocket::downcast_mut(item) else {
                            continue;
                        };
                        if socket.reuse_port_group != Some(group)
                            || (socket.ingress_device != 0
                                && socket.ingress_device != meta.ingress_index)
                            || !socket.accepts(self, &ip_repr, &udp_repr)
                        {
                            continue;
                        }
                        if let Some((candidate_priority, order)) = socket.shared_priority() {
                            let score = mix_flow(flow ^ mix_flow(order));
                            if candidate_priority == priority && best.is_none_or(|old| score > old)
                            {
                                best = Some(score);
                                handle = candidate;
                            }
                        }
                    }
                }
                let socket = sockets.get_mut::<UdpSocket>(handle);
                socket.process_wire(self, meta, &ip_repr, &udp_repr, &udp_packet);
                return None;
            }
        }

        #[cfg(feature = "socket-dns")]
        for dns_socket in sockets
            .items_mut()
            .filter_map(|i| DnsSocket::downcast_mut(&mut i.socket))
        {
            if dns_socket.accepts(&ip_repr, &udp_repr) {
                dns_socket.process(self, &ip_repr, &udp_repr, udp_packet.payload());
                return None;
            }
        }

        #[cfg(feature = "proto-ipv4")]
        if matches!(ip_repr, IpRepr::Ipv4(_))
            && !self.is_broadcast(&dst_addr)
            && !dst_addr.is_multicast()
        {
            self.counters.udp_no_ports += 1;
        }

        // The packet wasn't handled by a socket, send an ICMP port unreachable packet.
        match ip_repr {
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(_) if handled_by_raw_socket => None,
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(_) if handled_by_raw_socket => None,
            #[cfg(feature = "proto-ipv4")]
            IpRepr::Ipv4(ipv4_repr) => {
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, ipv4_repr.buffer_len());
                let icmpv4_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::PortUnreachable,
                    header: ipv4_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv4_reply(ipv4_repr, icmpv4_reply_repr)
            }
            #[cfg(feature = "proto-ipv6")]
            IpRepr::Ipv6(ipv6_repr) => {
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV6_MIN_MTU, ipv6_repr.buffer_len());
                let icmpv6_reply_repr = Icmpv6Repr::DstUnreachable {
                    reason: Icmpv6DstUnreachable::PortUnreachable,
                    header: ipv6_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv6_reply(ipv6_repr, icmpv6_reply_repr)
            }
        }
    }
}
