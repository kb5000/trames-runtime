// SPDX-License-Identifier: GPL-3.0-or-later
//! Root guest sockets retain the BSD fast path. Only guest-owned routes and
//! bridge listeners use the shared packet stack; no host route is modified.
use super::*;
use std::{
    cell::{Cell, RefCell},
    net::IpAddr,
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Path {
    Idle,
    Native,
    Guest,
    Both,
}
pub(super) struct Socket {
    network: native::Network,
    namespace: Rc<netlink::Namespace>,
    family: u32,
    kind: u32,
    protocol: u32,
    native: RefCell<Option<Rc<native::Socket>>>,
    guest: RefCell<Option<Rc<virtualnet::Socket>>>,
    path: Cell<Path>,
    bound: Cell<Option<SocketAddr>>,
    peer: Cell<Option<SocketAddr>>,
    listening: Cell<bool>,
    options: RefCell<Vec<(u32, u32, Vec<u8>)>>,
}
impl Socket {
    pub fn new(
        network: native::Network,
        namespace: Rc<netlink::Namespace>,
        family: u32,
        kind: u32,
        protocol: u32,
    ) -> Result<Rc<Self>> {
        let native = network.socket(family, kind, protocol)?;
        native.attach_policy(namespace.clone());
        Ok(Rc::new(Self {
            network,
            namespace,
            family,
            kind,
            protocol,
            native: RefCell::new(Some(native)),
            guest: RefCell::new(None),
            path: Cell::new(Path::Idle),
            bound: Cell::new(None),
            peer: Cell::new(None),
            listening: Cell::new(false),
            options: RefCell::default(),
        }))
    }
    fn native(&self) -> Result<Rc<native::Socket>> {
        if let Some(s) = self.native.borrow().as_ref() {
            return Ok(s.clone());
        }
        let s = self.network.socket(self.family, self.kind, self.protocol)?;
        s.attach_policy(self.namespace.clone());
        for (level, name, value) in self.options.borrow().iter() {
            s.set_option_bytes(*level, *name, value)?;
        }
        *self.native.borrow_mut() = Some(s.clone());
        Ok(s)
    }
    fn guest(&self) -> Result<Rc<virtualnet::Socket>> {
        if let Some(s) = self.guest.borrow().as_ref() {
            return Ok(s.clone());
        }
        let stack = self.namespace.root_stack()?;
        let s = stack.socket(self.family, self.kind, self.protocol)?;
        for (level, name, value) in self.options.borrow().iter() {
            s.set_option_bytes(*level, *name, value)?;
        }
        if let Some(bound) = self.bound.get() {
            s.bind(bound)?;
        }
        *self.guest.borrow_mut() = Some(s.clone());
        Ok(s)
    }
    fn remember_native_binding(&self, native: &native::Socket) {
        if self.kind == 2 && self.bound.get().is_none() {
            if let Ok(a) = native.local_addr() {
                if a.port() != 0 {
                    self.bound.set(Some(SocketAddr::new(
                        if self.family == 2 {
                            std::net::Ipv4Addr::UNSPECIFIED.into()
                        } else {
                            std::net::Ipv6Addr::UNSPECIFIED.into()
                        },
                        a.port(),
                    )));
                }
            }
        }
    }
    fn redirect(&self, peer: SocketAddr) -> bool {
        if !matches!(self.kind, 1 | 2) {
            return false;
        }
        let graph = self.namespace.graph.borrow();
        if !graph.firewall(self.namespace.id()).borrow().active(3) {
            return false;
        }
        let peer = match peer.ip() {
            IpAddr::V6(v) => v
                .to_ipv4_mapped()
                .map_or(peer, |v| SocketAddr::new(v.into(), peer.port())),
            _ => peer,
        };
        let Ok((mut source, _, _)) = graph.source(self.namespace.id(), peer.ip()) else {
            return false;
        };
        let bound = self
            .bound
            .get()
            .or_else(|| {
                self.native
                    .borrow()
                    .as_ref()
                    .and_then(|s| s.local_addr().ok())
            })
            .filter(|a| a.port() != 0);
        if let Some(a) = bound.filter(|a| !a.ip().is_unspecified()) {
            source = a.ip();
        }
        let mut p = crate::conntrack::message(
            SocketAddr::new(source, bound.map_or(0, |a| a.port())),
            peer,
            if self.kind == 1 { 6 } else { 17 },
            2,
            &[],
        );
        graph.output_redirect(self.namespace.id(), &mut p, bound.is_some())
    }
    fn internal(&self, address: IpAddr) -> bool {
        let address = match address {
            IpAddr::V6(v) => v.to_ipv4_mapped().map_or(address, IpAddr::V4),
            _ => address,
        };
        if !address.is_loopback()
            && self
                .namespace
                .graph
                .borrow()
                .devices(self.namespace.id())
                .iter()
                .any(|d| {
                    matches!(d.kind, DeviceKind::Bridge | DeviceKind::Veth { .. })
                        && d.addresses.iter().any(|a| a.ip == address)
                })
        {
            return true;
        }
        !address.is_loopback()
            && self
                .namespace
                .graph
                .borrow()
                .source(self.namespace.id(), address)
                .ok()
                .and_then(|(_, index, _)| {
                    self.namespace
                        .graph
                        .borrow()
                        .device(self.namespace.id(), index)
                        .ok()
                })
                .is_some_and(|d| matches!(d.kind, DeviceKind::Bridge | DeviceKind::Veth { .. }))
    }
    pub fn poll_epoch(&self) -> Option<[u64; 2]> {
        let mut epoch = if self.path.get() != Path::Guest {
            self.native().ok()?.poll_epoch()?
        } else {
            [0; 2]
        };
        if let Some(g) = self.guest.borrow().as_ref() {
            let e = g.poll_epoch();
            for i in 0..2 {
                epoch[i] = epoch[i].wrapping_add(e[i]);
            }
        }
        Some(epoch)
    }
    pub fn info(&self) -> SocketInfo {
        if self.path.get() == Path::Guest {
            return self.guest.borrow().as_ref().unwrap().info();
        }
        let mut info = self
            .native
            .borrow()
            .as_ref()
            .map(|s| s.info())
            .unwrap_or(SocketInfo {
                namespace_id: 0,
                family: self.family,
                kind: self.kind,
                protocol: match (self.kind, self.protocol) {
                    (1, _) => 6,
                    (2, 0 | 17) => 17,
                    (_, protocol) => protocol,
                },
                state: 7,
                local: None,
                peer: None,
                tx_queue: None,
                rx_queue: None,
            });
        if self.path.get() == Path::Both {
            if let Some(s) = self.guest.borrow().as_ref() {
                let g = s.info();
                info.tx_queue = info.tx_queue.zip(g.tx_queue).map(|(a, b)| a + b);
                info.rx_queue = info.rx_queue.zip(g.rx_queue).map(|(a, b)| a + b);
            }
        }
        info
    }
    pub fn address_size(&self) -> usize {
        if self.family == 2 {
            16
        } else {
            28
        }
    }
    pub fn bind(&self, address: SocketAddr) -> Result<()> {
        if self.bound.get().is_some() {
            return Err(NetError(22));
        }
        if self.internal(address.ip()) {
            let guest = self.guest()?;
            guest.bind(address)?;
            self.bound.set(Some(guest.local_addr()?));
            self.path.set(Path::Guest);
            return Ok(());
        }
        let native = self.native()?;
        native.bind(address)?;
        let actual = native.local_addr()?;
        if address.ip().is_unspecified() && matches!(self.kind, 1 | 2) {
            if let Err(error) = self.guest().and_then(|guest| guest.bind(actual)) {
                // Failed bind must leave the socket unbound, including its BSD
                // half. No guest/native poll waiter survives this syscall.
                drop(native);
                self.native.borrow_mut().take();
                self.guest.borrow_mut().take();
                let _ = self.native();
                return Err(error);
            }
            self.path.set(Path::Both);
        } else {
            self.path.set(Path::Native);
        }
        self.bound.set(Some(actual));
        Ok(())
    }
    pub fn listen(&self, backlog: u32) -> Result<()> {
        match self.path.get() {
            Path::Guest => self.guest()?.listen(backlog)?,
            Path::Both => {
                let guest = self.guest()?;
                guest.preflight_listen(backlog)?;
                // No other guest operation can change the handle budget in
                // between; commit the BSD listener only after preflight.
                self.native()?.listen(backlog)?;
                guest.listen(backlog)?;
            }
            _ => self.native()?.listen(backlog)?,
        }
        self.listening.set(true);
        Ok(())
    }
    pub fn accept(&self) -> Result<(super::SocketBackend, SocketAddr)> {
        if !self.listening.get() {
            return Err(NetError(22));
        }
        if matches!(self.path.get(), Path::Guest | Path::Both) {
            match self.guest()?.accept() {
                Ok((s, p)) => return Ok((super::SocketBackend::Virtual(s), p)),
                Err(NetError(11)) if self.path.get() == Path::Both => {}
                Err(e) => return Err(e),
            }
        }
        let (s, p) = self.native()?.accept()?;
        Ok((super::SocketBackend::Native(s), p))
    }
    pub fn connect(&self, address: SocketAddr) -> Result<()> {
        if self.listening.get() {
            return Err(NetError(22));
        }
        let guest = if self.kind == 1 && self.peer.get().is_some() {
            self.path.get() == Path::Guest
        } else {
            self.internal(address.ip()) || self.redirect(address) || self.path.get() == Path::Guest
        };
        self.peer.set(Some(address));
        if guest {
            let s = self.guest()?;
            self.path.set(Path::Guest);
            s.connect(address)
        } else {
            self.path.set(Path::Native);
            let native = self.native()?;
            let result = native.connect(address);
            if result.is_ok() {
                self.remember_native_binding(&native);
            }
            result
        }
    }
    pub fn connect_complete(&self) -> Result<bool> {
        if self.path.get() == Path::Guest {
            self.guest()?.connect_complete()
        } else {
            self.native()?.connect_complete()
        }
    }
    pub fn resume_connect(&self) -> Result<bool> {
        if self.path.get() == Path::Guest {
            self.guest()?.resume_connect()
        } else {
            self.native()?.resume_connect()
        }
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        if self.path.get() == Path::Guest {
            self.guest()?.local_addr()
        } else {
            self.native()?.local_addr()
        }
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        if self.path.get() == Path::Guest {
            self.guest()?.peer_addr()
        } else {
            self.native()?.peer_addr()
        }
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        if self.path.get() == Path::Guest {
            self.guest()?.shutdown(how)
        } else {
            self.native()?.shutdown(how)
        }
    }
    pub fn send(&self, bytes: &[u8], flags: u32, address: Option<SocketAddr>) -> Result<usize> {
        self.send_control(bytes, flags, address, None)
    }
    pub fn send_control(
        &self,
        bytes: &[u8],
        flags: u32,
        address: Option<SocketAddr>,
        info: Option<crate::PacketInfo>,
    ) -> Result<usize> {
        if self.kind != 1
            && self.path.get() != Path::Guest
            && address
                .or(self.peer.get())
                .is_some_and(|a| self.internal(a.ip()) || self.redirect(a))
        {
            let s = self.guest()?;
            if self.kind == 3 {
                self.path.set(Path::Guest);
                return s.send_control(bytes, flags, address.or(self.peer.get()), info);
            }
            if self.bound.get().is_none() {
                let wildcard = SocketAddr::new(
                    if self.family == 2 {
                        std::net::Ipv4Addr::UNSPECIFIED.into()
                    } else {
                        std::net::Ipv6Addr::UNSPECIFIED.into()
                    },
                    0,
                );
                self.bind(wildcard)?;
            }
            self.path.set(Path::Both);
            return s.send_control(bytes, flags, address.or(self.peer.get()), info);
        }
        if self.path.get() == Path::Guest {
            self.guest()?.send_control(bytes, flags, address, info)
        } else {
            let native = self.native()?;
            let result = if let Some(info) = info {
                native.send_packet(bytes, flags, address, info)
            } else {
                native.send(bytes, flags, address)
            };
            if result.is_ok() {
                self.remember_native_binding(&native);
            }
            result
        }
    }
    pub fn recv(&self, count: usize, flags: u32) -> Result<Received> {
        if matches!(self.path.get(), Path::Guest | Path::Both) {
            let guest = self.guest()?;
            // A UDP sendto override does not change a connected socket's peer.
            for _ in 0..16 {
                match guest.recv(count, flags) {
                    Ok(r)
                        if self.kind == 2
                            && self.peer.get().is_some_and(|peer| r.address != Some(peer)) =>
                    {
                        if flags & MSG_PEEK != 0 {
                            let _ = guest.recv(count, flags & !MSG_PEEK);
                        }
                        continue;
                    }
                    Ok(r) => return Ok(r),
                    Err(NetError(11)) if self.path.get() == Path::Both => break,
                    Err(e) => return Err(e),
                }
            }
        }
        self.native()?.recv(count, flags)
    }
    pub fn poll(&self, events: u16) -> Result<u16> {
        let mut out = 0;
        if self.path.get() != Path::Guest {
            out |= self.native()?.poll(events)?;
        }
        if matches!(self.path.get(), Path::Guest | Path::Both) {
            out |= self.guest()?.poll(events)?;
        }
        Ok(out)
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        {
            let options = self.options.borrow();
            if options.len() >= 128 && !options.iter().any(|(l, n, _)| *l == level && *n == name) {
                return Err(NetError(105));
            }
        }
        if matches!(self.path.get(), Path::Guest | Path::Both) {
            self.guest()?.set_option_bytes(level, name, value)?;
        }
        if self.path.get() != Path::Guest {
            self.native()?.set_option_bytes(level, name, value)?;
        }
        let mut options = self.options.borrow_mut();
        options.retain(|(l, n, _)| *l != level || *n != name);
        options.push((level, name, value.to_vec()));
        Ok(())
    }
    pub fn set_option(&self, level: u32, name: u32, value: i32) -> Result<()> {
        self.set_option_bytes(level, name, &value.to_le_bytes())
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        if self.path.get() == Path::Guest {
            self.guest()?.get_option(level, name)
        } else {
            self.native()?.get_option(level, name)
        }
    }
    pub fn ancillary_hop(&self) -> Option<(u32, u32, u8)> {
        if self.path.get() == Path::Guest {
            self.guest.borrow().as_ref().and_then(|s| s.ancillary_hop())
        } else {
            self.native
                .borrow()
                .as_ref()
                .and_then(|s| s.ancillary_hop())
        }
    }
    pub fn waiters(&self, events: u16) -> (Option<(Rc<native::Socket>, u16)>, Option<Fabric>) {
        let native = (self.path.get() != Path::Guest)
            .then(|| self.native.borrow().as_ref().map(|s| (s.clone(), events)))
            .flatten();
        let fabric = matches!(self.path.get(), Path::Guest | Path::Both)
            .then(|| self.guest.borrow().as_ref().map(|s| s.fabric()))
            .flatten();
        (native, fabric)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_native_descriptor_cannot_bypass_guest_low_port_authorization() {
        let root = Network::new(NetworkMode::Full);
        let socket = root.socket(2, 1, 0).unwrap();
        let super::super::SocketBackend::Hybrid(hybrid) = &socket.0 else {
            unreachable!()
        };
        hybrid.native.borrow_mut().take();
        assert_eq!(socket.info().unwrap().protocol, 6);
        assert_eq!(
            socket.bind_authorized(&encode_address("127.0.0.1:80".parse().unwrap()), false),
            Err(NetError(13))
        );
    }
}
