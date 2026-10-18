// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked sockets with native and isolated userspace packet-stack backends.
mod conntrack;
mod direct_dns;
mod dns;
mod hybrid;
mod interfaces;
mod native;
mod netdev;
mod netlink;
mod nftables;
mod rtnetlink;
pub use netdev::{Address as DeviceAddress, Device, DeviceKind, Route as DeviceRoute};
mod virtualnet;
pub use native::{
    decode_address, encode_address, NetError, NetworkMode, Received, MAX_BUFFER, MAX_SOCKETS,
    MAX_TRANSFER, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC,
};
use std::{cell::Cell, net::SocketAddr, rc::Rc, time::Duration};
pub use virtualnet::{Fabric, LinkStats, NetworkInfo, NetworkStats};
type Result<T> = std::result::Result<T, NetError>;
#[derive(Clone)]
pub struct SocketInfo {
    /// Identity of the socket's creating network namespace, retained across setns.
    pub namespace_id: u64,
    pub family: u32,
    pub kind: u32,
    pub protocol: u32,
    pub state: u8,
    pub local: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub tx_queue: Option<usize>,
    pub rx_queue: Option<usize>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketInfo {
    pub address: std::net::IpAddr,
    pub interface: u32,
}
#[derive(Clone)]
pub struct Network(Backend, Rc<netlink::Namespace>);
#[derive(Clone)]
enum Backend {
    Native(native::Network),
    Virtual(virtualnet::Network),
}
impl Default for Network {
    fn default() -> Self {
        Self::new(NetworkMode::Off)
    }
}
impl Network {
    /// Trusted embedder test/service mapping; never reachable from a guest syscall.
    pub fn map_host_ip(
        &self,
        virtual_ip: std::net::IpAddr,
        host_ip: std::net::IpAddr,
    ) -> Result<()> {
        let fabric = {
            let mut shared = self.1.fabric.borrow_mut();
            if shared.is_none() {
                *shared = Some(Fabric::new()?);
            }
            shared.as_ref().unwrap().clone()
        };
        fabric.map_host_ip(virtual_ip, host_ip)
    }
    pub fn namespace_id(&self) -> u64 {
        self.1.id()
    }
    pub fn ping_range(&self) -> [u32; 2] {
        self.1.ping_range.get()
    }
    pub fn set_ping_range(&self, range: [u32; 2]) {
        self.1.ping_range.set(range);
    }
    pub fn unprivileged_port(&self) -> u16 {
        self.1.unprivileged_port.get()
    }
    pub fn set_unprivileged_port(&self, port: u16) {
        self.1.unprivileged_port.set(port);
    }
    /// A new Linux network namespace starts with an unconfigured, down lo and
    /// no external devices. Its stack never binds a host listener.
    pub fn isolated(&self) -> Result<Self> {
        let mode = match &self.0 {
            Backend::Native(n) => n.mode(),
            Backend::Virtual(n) => n.mode(),
        };
        let fabric = {
            let mut shared = self.1.fabric.borrow_mut();
            if shared.is_none() {
                *shared = Some(Fabric::new()?);
            }
            shared.as_ref().unwrap().clone()
        };
        let loopback = Rc::new(std::cell::Cell::new(false));
        let namespace = Rc::new(self.1.isolated(loopback.clone())?);
        let view = netdev::View {
            graph: namespace.graph.clone(),
            namespace: namespace.id(),
        };
        let stack = fabric.dynamic_environment(mode, view, loopback)?;
        namespace
            .stack
            .set(stack.clone())
            .ok()
            .expect("new namespace stack");
        Ok(Self(Backend::Virtual(stack), namespace))
    }
    pub fn devices(&self) -> Vec<Device> {
        self.1.refresh_native();
        self.1.graph.borrow().devices(self.namespace_id())
    }
    pub fn set_device_up(&self, index: u32, up: bool) -> Result<()> {
        if self.1.native.get().is_some() {
            self.1.root_stack()?;
        }
        self.1.graph.borrow_mut().change_link(
            self.namespace_id(),
            index,
            None,
            None,
            Some(up),
            None,
            None,
            None,
        )
    }
    pub fn loopback_up(&self) -> bool {
        self.1.loopback_up()
    }
    pub fn set_loopback_up(&self, up: bool) -> Result<()> {
        self.1.set_loopback_up(up)
    }
    pub fn new(mode: NetworkMode) -> Self {
        let native = native::Network::new(mode);
        let namespace = Rc::new(netlink::Namespace::default());
        namespace
            .graph
            .borrow_mut()
            .add_space(namespace.id(), None, native.info());
        namespace
            .native
            .set(native.clone())
            .ok()
            .expect("new native namespace");
        namespace.refresh_native();
        Self(Backend::Native(native), namespace)
    }
    pub fn virtual_network(fabric: &Fabric, id: u8, mode: NetworkMode) -> Result<Self> {
        let stack = fabric.environment(id, mode)?;
        let namespace = Rc::new(netlink::Namespace::default());
        namespace.nft_packet_hooks.set(false);
        namespace
            .graph
            .borrow_mut()
            .add_space(namespace.id(), None, Some(stack.info()));
        namespace
            .stack
            .set(stack.clone())
            .ok()
            .expect("new explicit fabric namespace stack");
        Ok(Self(Backend::Virtual(stack), namespace))
    }
    pub fn forwarding(&self, ipv6: bool) -> bool {
        self.1.graph.borrow().forwarding(self.namespace_id(), ipv6)
    }
    pub fn set_forwarding(&self, ipv6: bool, enabled: bool) {
        self.1
            .graph
            .borrow_mut()
            .set_forwarding(self.namespace_id(), ipv6, enabled);
    }
    pub fn bridge_filter(&self, ipv6: bool) -> bool {
        self.1
            .graph
            .borrow()
            .bridge_filter(self.namespace_id(), ipv6)
    }
    pub fn set_bridge_filter(&self, ipv6: bool, enabled: bool) {
        self.1
            .graph
            .borrow_mut()
            .set_bridge_filter(self.namespace_id(), ipv6, enabled);
    }
    pub fn routes(&self) -> Vec<DeviceRoute> {
        self.1.refresh_native();
        self.1.graph.borrow().routes(self.namespace_id())
    }
    pub fn device_carrier(&self, d: &Device) -> bool {
        self.1.graph.borrow().carrier(d)
    }
    pub fn live_sockets(&self) -> usize {
        self.1.socket_count.get()
    }
    pub fn info(&self) -> Option<NetworkInfo> {
        self.1.refresh_native();
        match &self.0 {
            Backend::Native(n) => n.info(),
            Backend::Virtual(n) => (!n.is_isolated()).then(|| n.info()),
        }
    }
    pub fn links(&self) -> Option<[LinkStats; 2]> {
        match &self.0 {
            Backend::Native(n) => Some(n.links()),
            Backend::Virtual(n) => Some(n.links()),
        }
    }
    pub fn finish(&self) {
        if let Some(stack) = self.1.stack.get() {
            stack.finish();
        } else if let Backend::Virtual(n) = &self.0 {
            n.finish();
        }
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Rc<Socket>> {
        if self.live_sockets() >= MAX_SOCKETS {
            return Err(NetError(24));
        }
        if family == 16 {
            return Ok(Socket::wrap(
                SocketBackend::Netlink(netlink::Socket::new(
                    self.1.clone(),
                    self.info(),
                    kind,
                    protocol,
                )?),
                self.1.clone(),
            ));
        }
        let backend = match &self.0 {
            Backend::Native(n) => SocketBackend::Hybrid(hybrid::Socket::new(
                n.clone(),
                self.1.clone(),
                family,
                kind,
                protocol,
            )?),
            Backend::Virtual(n) => SocketBackend::Virtual(n.socket(family, kind, protocol)?),
        };
        Ok(Socket::wrap(backend, self.1.clone()))
    }
}
pub struct Socket(
    SocketBackend,
    Rc<netlink::Namespace>,
    [Cell<Option<Duration>>; 2],
);
enum SocketBackend {
    Hybrid(Rc<hybrid::Socket>),
    Netlink(Rc<netlink::Socket>),
    Native(Rc<native::Socket>),
    Virtual(Rc<virtualnet::Socket>),
}
macro_rules! delegate {
    ($name:ident($($arg:ident:$ty:ty),*) -> $ret:ty) => {
        pub fn $name(&self,$($arg:$ty),*) -> $ret {
            match &self.0 {SocketBackend::Hybrid(s)=>s.$name($($arg),*), SocketBackend::Native(s)=>s.$name($($arg),*),SocketBackend::Virtual(s)=>s.$name($($arg),*), SocketBackend::Netlink(s)=>s.$name($($arg),*) }
        }
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.1.socket_count.set(self.1.socket_count.get() - 1);
    }
}
impl Socket {
    fn wrap(backend: SocketBackend, namespace: Rc<netlink::Namespace>) -> Rc<Self> {
        namespace.socket_count.set(namespace.socket_count.get() + 1);
        Rc::new(Self(backend, namespace, [Cell::new(None), Cell::new(None)]))
    }
    /// Guest socket timeouts are enforced by the virtual task scheduler; host
    /// sockets remain nonblocking. The shared socket owns them across dup/fork.
    pub fn set_io_timeout(&self, receive: bool, timeout: Option<Duration>) {
        self.2[usize::from(receive)].set(timeout);
    }
    pub fn io_timeout(&self, receive: bool) -> Option<Duration> {
        self.2[usize::from(receive)].get()
    }
    pub fn poll_epoch(&self) -> Option<[u64; 2]> {
        match &self.0 {
            SocketBackend::Netlink(s) => Some(s.poll_epoch()),
            SocketBackend::Native(s) => s.poll_epoch(),
            SocketBackend::Hybrid(s) => s.poll_epoch(),
            SocketBackend::Virtual(s) => Some(s.poll_epoch()),
        }
    }
    pub fn info(&self) -> Option<SocketInfo> {
        let mut info = match &self.0 {
            SocketBackend::Hybrid(s) => Some(s.info()),
            SocketBackend::Virtual(s) => Some(s.info()),
            SocketBackend::Native(s) => Some(s.info()),
            SocketBackend::Netlink(_) => None,
        }?;
        info.namespace_id = self.1.id();
        Some(info)
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if let SocketBackend::Hybrid(s) = &self.0 {
            return s.set_option_bytes(level, name, value);
        }
        if let SocketBackend::Native(s) = &self.0 {
            return s.set_option_bytes(level, name, value);
        }
        if let SocketBackend::Virtual(s) = &self.0 {
            return s.set_option_bytes(level, name, value);
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
    pub fn send_packet(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<SocketAddr>,
        mut info: PacketInfo,
    ) -> Result<usize> {
        self.1.refresh_native();
        let graph = self.1.graph.borrow();
        let owned_ip = match info.address {
            std::net::IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map_or(info.address, std::net::IpAddr::V4),
            ip => ip,
        };
        if info.interface != 0 {
            let device = graph.device(self.1.id(), info.interface)?;
            if info.address.is_unspecified() {
                info.address = device
                    .addresses
                    .iter()
                    .find(|a| a.ip.is_ipv4() == info.address.is_ipv4())
                    .ok_or(NetError(99))?
                    .ip;
            } else if !device.addresses.iter().any(|a| {
                a.ip == owned_ip
                    || device.kind == DeviceKind::Loopback
                        && owned_ip.is_loopback()
                        && a.contains(owned_ip)
            }) {
                return Err(NetError(99));
            }
        }
        if !owned_ip.is_unspecified() && !graph.own(self.1.id(), owned_ip) {
            return Err(NetError(99));
        }
        drop(graph);
        match &self.0 {
            SocketBackend::Native(s) => s.send_packet(bytes, flags, destination, info),
            SocketBackend::Virtual(s) => s.send_control(bytes, flags, destination, Some(info)),
            SocketBackend::Hybrid(s) => s.send_control(bytes, flags, destination, Some(info)),
            _ => Err(NetError(95)),
        }
    }
    pub fn ancillary_hop(&self) -> Option<(u32, u32, u8)> {
        if let SocketBackend::Hybrid(s) = &self.0 {
            return s.ancillary_hop();
        }
        if let SocketBackend::Virtual(s) = &self.0 {
            s.ancillary_hop()
        } else if let SocketBackend::Native(s) = &self.0 {
            s.ancillary_hop()
        } else {
            None
        }
    }
    pub fn bind_bytes(&self, bytes: &[u8]) -> Result<()> {
        if let SocketBackend::Netlink(s) = &self.0 {
            s.bind_bytes(bytes)
        } else {
            self.bind(decode_address(bytes)?)
        }
    }
    pub fn bind_authorized(&self, bytes: &[u8], can_bind_service: bool) -> Result<()> {
        if self.info().is_some_and(|s| matches!(s.protocol, 6 | 17)) {
            let address = decode_address(bytes)?;
            if address.port() != 0
                && address.port() < self.1.unprivileged_port.get()
                && !can_bind_service
            {
                return Err(NetError(13));
            }
        }
        self.bind_bytes(bytes)
    }
    pub fn connect_bytes(&self, bytes: &[u8]) -> Result<()> {
        if let SocketBackend::Netlink(s) = &self.0 {
            s.connect_bytes(bytes)
        } else {
            self.connect(decode_address(bytes)?)
        }
    }
    pub fn local_bytes(&self) -> Result<Vec<u8>> {
        if let SocketBackend::Netlink(s) = &self.0 {
            s.local_bytes()
        } else {
            self.local_addr().map(encode_address)
        }
    }
    pub fn peer_bytes(&self) -> Result<Vec<u8>> {
        if let SocketBackend::Netlink(s) = &self.0 {
            s.peer_bytes()
        } else {
            self.peer_addr().map(encode_address)
        }
    }
    pub fn received_address(&self, received: &Received) -> Vec<u8> {
        if matches!(self.0, SocketBackend::Netlink(_)) {
            received
                .netlink_address
                .map_or_else(|| netlink::address(0), Vec::from)
        } else {
            received.address.map_or_else(Vec::new, encode_address)
        }
    }
    pub fn send_bytes(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
    ) -> Result<usize> {
        self.send_bytes_authorized(bytes, flags, destination, false)
    }
    pub fn send_bytes_authorized(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
    ) -> Result<usize> {
        self.send_bytes_with_namespace(bytes, flags, destination, net_admin, &|_| Err(NetError(9)))
    }
    pub fn send_bytes_with_namespace(
        &self,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        net_admin: bool,
        resolve: &dyn Fn(u32) -> Result<Network>,
    ) -> Result<usize> {
        if let SocketBackend::Netlink(s) = &self.0 {
            s.send_with_namespace(bytes, flags, destination, net_admin, resolve)
        } else {
            self.send(bytes, flags, destination.map(decode_address).transpose()?)
        }
    }
    delegate!(address_size() -> usize);
    delegate!(bind(address: SocketAddr) -> Result<()>);
    delegate!(listen(backlog: u32) -> Result<()>);
    delegate!(connect(address: SocketAddr) -> Result<()>);
    delegate!(connect_complete() -> Result<bool>);
    delegate!(resume_connect() -> Result<bool>);
    delegate!(local_addr() -> Result<SocketAddr>);
    delegate!(peer_addr() -> Result<SocketAddr>);
    delegate!(shutdown(how: u32) -> Result<()>);
    delegate!(send(bytes: &[u8], flags: u32, address: Option<SocketAddr>) -> Result<usize>);
    delegate!(recv(count: usize, flags: u32) -> Result<Received>);
    delegate!(poll(events: u16) -> Result<u16>);
    delegate!(set_option(level: u32, name: u32, value: i32) -> Result<()>);
    delegate!(get_option(level: u32, name: u32) -> Result<i32>);
    pub fn accept(&self) -> Result<(Rc<Self>, SocketAddr)> {
        if self.1.socket_count.get() >= MAX_SOCKETS {
            return Err(NetError(24));
        }
        let (backend, peer) = match &self.0 {
            SocketBackend::Hybrid(s) => s.accept()?,
            SocketBackend::Netlink(_) => return Err(NetError(95)),
            SocketBackend::Native(s) => {
                let (s, peer) = s.accept()?;
                (SocketBackend::Native(s), peer)
            }
            SocketBackend::Virtual(s) => {
                let (s, peer) = s.accept()?;
                (SocketBackend::Virtual(s), peer)
            }
        };
        let accepted = Self::wrap(backend, self.1.clone());
        for receive in [false, true] {
            accepted.set_io_timeout(receive, self.io_timeout(receive));
        }
        Ok((accepted, peer))
    }
}
pub fn wait(sockets: &[(Rc<Socket>, u16)], timeout: Duration) -> Result<()> {
    let mut native = Vec::new();
    let mut fabrics: Vec<Fabric> = Vec::new();
    for (s, events) in sockets {
        match &s.0 {
            SocketBackend::Hybrid(s) => {
                let (n, f) = s.waiters(*events);
                if let Some(n) = n {
                    native.push(n);
                }
                if let Some(f) = f {
                    if !fabrics.iter().any(|other| other.same(&f)) {
                        fabrics.push(f);
                    }
                }
            }
            SocketBackend::Netlink(_) => {}
            SocketBackend::Native(s) => native.push((s.clone(), *events)),
            SocketBackend::Virtual(s) => {
                let f = s.fabric();
                if !fabrics.iter().any(|other| other.same(&f)) {
                    fabrics.push(f);
                }
            }
        }
    }
    let mut duration = timeout;
    for f in &fabrics {
        f.tick();
        duration = duration.min(f.next_wait());
        native.extend(f.native_waiters());
    }
    if native.is_empty() {
        std::thread::sleep(duration);
    } else {
        native::wait(&native, duration)?;
    }
    for f in &fabrics {
        f.tick();
    }
    Ok(())
}

#[cfg(test)]
mod routing_tests;

#[cfg(test)]
mod root_routing_tests;
