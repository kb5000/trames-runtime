use super::*;

use crate::socket::tcp::Socket;

impl InterfaceInner {
    pub(crate) fn process_tcp<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ingress: u32,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        self.counters.in_segs += 1;
        let mut listener = None;
        let mut full_priority = None;
        let initial_syn = tcp_repr.control == TcpControl::Syn && tcp_repr.ack_number.is_none();
        let mut flow = None;
        for (handle, item) in sockets.iter_mut() {
            let Some(socket) = Socket::downcast_mut(item) else {
                continue;
            };
            if socket.ingress_device != 0 && socket.ingress_device != ingress {
                continue;
            }
            if !socket.accepts(self, &ip_repr, &tcp_repr) {
                if initial_syn && socket.queues_syn_for(dst_addr, tcp_repr.dst_port) {
                    let priority = (socket.specific_bind, socket.ingress_device != 0);
                    full_priority = Some(full_priority.map_or(priority, |old| priority.max(old)));
                }
                continue;
            }
            if socket.is_listening()
                && socket.listener_rank != 0
                && tcp_repr.control == TcpControl::Syn
            {
                // A matching established tuple takes precedence over a new listener.
                // Rank logical listeners once per flow, independent of backlog size.
                let key = *flow.get_or_insert_with(|| {
                    socket_flow(
                        IpEndpoint::new(src_addr, tcp_repr.src_port),
                        IpEndpoint::new(dst_addr, tcp_repr.dst_port),
                    )
                });
                let score = (
                    (socket.specific_bind, socket.ingress_device != 0),
                    mix_flow(key ^ mix_flow(socket.listener_rank)),
                );
                if listener.is_none_or(|(best, _)| score > best) {
                    listener = Some((score, handle));
                }
                continue;
            }
            let mark = socket.mark;
            return socket
                .process_wire(self, &ip_repr, &tcp_repr, ip_payload)
                .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)).with_reply_mark(mark));
        }
        if let Some(((priority, _), handle)) = listener {
            // Backpressure belongs to the best matching listener group. A full
            // device-bound group must not spill connections to a wildcard one.
            if full_priority.is_some_and(|full| full > priority) {
                return None;
            }
            let socket = sockets.get_mut::<Socket>(handle);
            let mark = socket.mark;
            return socket
                .process_wire(self, &ip_repr, &tcp_repr, ip_payload)
                .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)).with_reply_mark(mark));
        }

        // A full accept queue drops new SYNs. An existing four-tuple has
        // already had a chance to handle the segment above.
        if full_priority.is_some() {
            return None;
        }
        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
        {
            // Never reply to a TCP RST packet with another TCP RST packet. We also never want to
            // send a TCP RST packet with unspecified addresses.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let (ip, tcp) = tcp::Socket::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}
