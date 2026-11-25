// SPDX-License-Identifier: GPL-3.0-or-later
//! Raw descriptors share the existing bounded Linux error queue. Wire errors
//! are matched to the original endpoint before applying any raw data filter.
use super::*;
use smoltcp::wire::IpRepr;
pub(super) struct Receiver(pub Weak<SocketMeta>);
impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawErrorReceiver")
    }
}
impl raw::ErrorReceiver for Receiver {
    fn unreachable(
        &self,
        outer: &IpRepr,
        quoted: &IpRepr,
        code: u8,
        data: &[u8],
        interface: u32,
    ) -> bool {
        let Some(owner) = self.0.upgrade() else {
            return false;
        };
        let state = owner.state.borrow();
        let source = addr(quoted.src_addr());
        let peer = addr(quoted.dst_addr());
        if state
            .bound
            .is_some_and(|a| !a.ip().is_unspecified() && a.ip() != source)
            || state.peer.is_some_and(|a| a.ip() != peer)
            || (owner.family == 2) != source.is_ipv4()
            || state.device.is_some_and(|device| device != interface)
            || matches!(owner.protocol, 1 | 58)
                && (data.len() < 8
                    || !{
                        let id = u16::from_be_bytes([data[4], data[5]]);
                        if owner.kind == 3 {
                            state.bound.is_some_and(|a| a.port() == id)
                        } else {
                            state.raw_identifiers.contains(&id)
                        }
                    })
        {
            return false;
        }
        udp::ErrorReceiver::unreachable(
            state.udp_errors.as_ref().unwrap().as_ref(),
            state.peer.is_some(),
            outer.src_addr(),
            IpEndpoint::new(quoted.dst_addr(), 0),
            code,
            data,
        )
    }
}
