// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked sockets with native and isolated userspace packet-stack backends.
mod native;
mod virtualnet;
pub use native::{
    decode_address, encode_address, NetError, NetworkMode, Received, MAX_BUFFER, MAX_SOCKETS,
    MAX_TRANSFER, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_TRUNC,
};
use std::{net::SocketAddr, rc::Rc, time::Duration};
pub use virtualnet::{Fabric, NetworkInfo, NetworkStats};
type Result<T> = std::result::Result<T, NetError>;
#[derive(Clone)]
pub struct Network(Backend);
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
        Self(Backend::Native(native::Network::new(mode)))
    }
    pub fn virtual_network(fabric: &Fabric, id: u8, mode: NetworkMode) -> Result<Self> {
        Ok(Self(Backend::Virtual(fabric.environment(id, mode)?)))
    }
    pub fn live_sockets(&self) -> usize {
        match &self.0 {
            Backend::Native(n) => n.live_sockets(),
            Backend::Virtual(n) => n.live_sockets(),
        }
    }
    pub fn info(&self) -> Option<NetworkInfo> {
        match &self.0 {
            Backend::Native(_) => None,
            Backend::Virtual(n) => Some(n.info()),
        }
    }
    pub fn finish(&self) {
        if let Backend::Virtual(n) = &self.0 {
            n.finish();
        }
    }
    pub fn socket(&self, family: u32, kind: u32, protocol: u32) -> Result<Rc<Socket>> {
        let backend = match &self.0 {
            Backend::Native(n) => SocketBackend::Native(n.socket(family, kind, protocol)?),
            Backend::Virtual(n) => SocketBackend::Virtual(n.socket(family, kind, protocol)?),
        };
        Ok(Rc::new(Socket(backend)))
    }
}
pub struct Socket(SocketBackend);
enum SocketBackend {
    Native(Rc<native::Socket>),
    Virtual(Rc<virtualnet::Socket>),
}
macro_rules! delegate {
    ($name:ident($($arg:ident:$ty:ty),*) -> $ret:ty) => {
        pub fn $name(&self,$($arg:$ty),*) -> $ret {
            match &self.0 { SocketBackend::Native(s)=>s.$name($($arg),*),SocketBackend::Virtual(s)=>s.$name($($arg),*) }
        }
    }
}
impl Socket {
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
