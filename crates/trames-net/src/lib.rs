// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked sockets with native and isolated userspace packet-stack backends.
mod direct_dns;
mod dns;
mod interfaces;
mod native;
mod netlink;
mod virtualnet;
pub use native::{
    decode_address, encode_address, NetError, NetworkMode, Received, MAX_BUFFER, MAX_SOCKETS,
    MAX_TRANSFER, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC,
};
use std::{net::SocketAddr, rc::Rc, time::Duration};
pub use virtualnet::{Fabric, LinkStats, NetworkInfo, NetworkStats};
type Result<T> = std::result::Result<T, NetError>;
#[derive(Clone)]
pub struct SocketInfo {
    pub family: u32,
    pub kind: u32,
    pub protocol: u32,
    pub state: u8,
    pub local: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub tx_queue: Option<usize>,
    pub rx_queue: Option<usize>,
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
    pub fn new(mode: NetworkMode) -> Self {
        Self(
            Backend::Native(native::Network::new(mode)),
            Rc::new(netlink::Namespace::default()),
        )
    }
    pub fn virtual_network(fabric: &Fabric, id: u8, mode: NetworkMode) -> Result<Self> {
        Ok(Self(
            Backend::Virtual(fabric.environment(id, mode)?),
            Rc::new(netlink::Namespace::default()),
        ))
    }
    pub fn live_sockets(&self) -> usize {
        self.1.live()
            + match &self.0 {
                Backend::Native(n) => n.live_sockets(),
                Backend::Virtual(n) => n.live_sockets(),
            }
    }
    pub fn info(&self) -> Option<NetworkInfo> {
        match &self.0 {
            Backend::Native(n) => n.info(),
            Backend::Virtual(n) => Some(n.info()),
        }
    }
    pub fn links(&self) -> Option<[LinkStats; 2]> {
        match &self.0 {
            Backend::Native(n) => Some(n.links()),
            Backend::Virtual(n) => Some(n.links()),
        }
    }
    pub fn finish(&self) {
        if let Backend::Virtual(n) = &self.0 {
            n.finish();
        }
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Rc<Socket>> {
        if self.live_sockets() >= MAX_SOCKETS {
            return Err(NetError(24));
        }
        if family == 16 {
            return Ok(Rc::new(Socket(SocketBackend::Netlink(
                netlink::Socket::new(self.1.clone(), self.info(), kind, protocol)?,
            ))));
        }
        let backend = match &self.0 {
            Backend::Native(n) => SocketBackend::Native(n.socket(family, kind, protocol)?),
            Backend::Virtual(n) => SocketBackend::Virtual(n.socket(family, kind, protocol)?),
        };
        Ok(Rc::new(Socket(backend)))
    }
}
pub struct Socket(SocketBackend);
enum SocketBackend {
    Netlink(Rc<netlink::Socket>),
    Native(Rc<native::Socket>),
    Virtual(Rc<virtualnet::Socket>),
}
macro_rules! delegate {
    ($name:ident($($arg:ident:$ty:ty),*) -> $ret:ty) => {
        pub fn $name(&self,$($arg:$ty),*) -> $ret {
            match &self.0 { SocketBackend::Native(s)=>s.$name($($arg),*),SocketBackend::Virtual(s)=>s.$name($($arg),*), SocketBackend::Netlink(s)=>s.$name($($arg),*) }
        }
    }
}
impl Socket {
    pub fn info(&self) -> Option<SocketInfo> {
        match &self.0 {
            SocketBackend::Virtual(s) => Some(s.info()),
            SocketBackend::Native(s) => Some(s.info()),
            SocketBackend::Netlink(_) => None,
        }
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
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
    pub fn ancillary_hop(&self) -> Option<(u32, u32, u8)> {
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
            netlink::address(0)
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
        if let SocketBackend::Netlink(s) = &self.0 {
            s.send_bytes(bytes, flags, destination)
        } else {
            self.send(bytes, flags, destination.map(decode_address).transpose()?)
        }
    }
    delegate!(address_size() -> usize);
    delegate!(bind(address:SocketAddr) -> Result<()>);
    delegate!(listen(backlog:u32) -> Result<()>);
    delegate!(connect(address:SocketAddr) -> Result<()>);
    delegate!(connect_complete() -> Result<bool>);
    delegate!(resume_connect() -> Result<bool>);
    delegate!(local_addr() -> Result<SocketAddr>);
    delegate!(peer_addr() -> Result<SocketAddr>);
    delegate!(shutdown(how:u32) -> Result<()>);
    delegate!(send(bytes:&[u8],flags:u32,address:Option<SocketAddr>) -> Result<usize>);
    delegate!(recv(count:usize,flags:u32) -> Result<Received>);
    delegate!(poll(events:u16) -> Result<u16>);
    delegate!(set_option(level:u32,name:u32,value:i32) -> Result<()>);
    delegate!(get_option(level:u32,name:u32) -> Result<i32>);
    pub fn accept(&self) -> Result<(Rc<Self>, SocketAddr)> {
        let (backend, peer) = match &self.0 {
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
        Ok((Rc::new(Self(backend)), peer))
    }
}
pub fn wait(sockets: &[(Rc<Socket>, u16)], timeout: Duration) -> Result<()> {
    let mut native = Vec::new();
    let mut fabrics: Vec<Fabric> = Vec::new();
    for (s, events) in sockets {
        match &s.0 {
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
