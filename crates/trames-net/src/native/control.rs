// SPDX-License-Identifier: GPL-3.0-or-later
//! TCP controls over the existing host transport. No namespace/routing authority.
use super::*;
use std::sync::{Mutex, Weak};
pub(crate) type SavedOptions = Arc<Mutex<Vec<(u32, u32, Vec<u8>)>>>;
#[derive(Clone)]
pub struct DirectControl {
    socket: Weak<Endpoint>,
    family: u32,
    pub(crate) options: Option<SavedOptions>,
}
impl Socket {
    pub fn direct_control(&self) -> Option<DirectControl> {
        (self.kind == 1 && !self.dns_peer.get() && self.dns.borrow().is_empty()).then(|| {
            DirectControl {
                socket: Arc::downgrade(&self.native),
                family: self.family,
                options: None,
            }
        })
    }
}
impl DirectControl {
    pub fn retain(&self) -> Result<TcpLease> {
        self.socket.upgrade().map(TcpLease).ok_or(NetError(9))
    }
    pub fn address_size(&self) -> usize {
        if self.family == 2 {
            16
        } else {
            28
        }
    }
    pub fn address(&self, peer: bool) -> Result<SocketAddr> {
        let socket = self.socket.upgrade().ok_or(NetError(9))?;
        let address = if peer {
            socket.control().peer_addr()
        } else {
            socket.control().local_addr()
        };
        address.map_err(from_io)?.as_socket().ok_or(NetError(5))
    }
    pub fn get_option(&self, level: u32, name: u32) -> Result<i32> {
        let socket = self.socket.upgrade().ok_or(NetError(9))?;
        match (level, name) {
            (6, 1) => socket.nodelay(),
            (1, 3) => Ok(1),
            (1, 38) => Ok(6),
            (1, 39) => Ok(self.family as i32),
            _ => Err(NetError(92)),
        }
    }
    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        if (level, name) != (6, 1) {
            return Err(NetError(92));
        }
        if value.len() < 4 {
            return Err(NetError(22));
        }
        let socket = self.socket.upgrade().ok_or(NetError(9))?;
        let mut options = self.options.as_ref().map(|o| o.lock().unwrap());
        if options
            .as_ref()
            .is_some_and(|o| o.len() >= 128 && !o.iter().any(|(l, n, _)| (*l, *n) == (level, name)))
        {
            return Err(NetError(105));
        }
        socket.set_nodelay(i32::from_le_bytes(value[..4].try_into().unwrap()))?;
        if let Some(options) = options.as_mut() {
            options.retain(|(l, n, _)| (*l, *n) != (level, name));
            options.push((level, name, value.to_vec()));
        }
        Ok(())
    }
}
impl Endpoint {
    pub(super) fn set_nodelay(&self, value: i32) -> Result<()> {
        self.control().set_tcp_nodelay(value != 0).map_err(from_io)
    }
    pub(super) fn nodelay(&self) -> Result<i32> {
        self.control().tcp_nodelay().map(i32::from).map_err(from_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_is_shared_weak_and_uses_the_original_endpoint() {
        fn shared<T: Send + Sync>() {}
        shared::<DirectControl>();
        let network = Network::new(NetworkMode::Loopback);
        let socket = network.socket(2, 1, 0).unwrap();
        let control = socket.direct_control().unwrap();
        let worker = control.clone();
        std::thread::spawn(move || worker.set_option_bytes(6, 1, &1i32.to_le_bytes()).unwrap())
            .join()
            .unwrap();
        assert_eq!(socket.get_option(6, 1), Ok(1));
        assert_eq!(control.get_option(1, 39), Ok(2));
        let accepted = control.retain().unwrap();
        drop(socket);
        assert_eq!(network.live_sockets(), 1);
        assert_eq!(control.get_option(6, 1), Ok(1));
        drop(accepted);
        assert_eq!(network.live_sockets(), 0);
        assert_eq!(control.get_option(1, 3), Err(NetError(9)));
        assert!(network.socket(2, 2, 0).unwrap().direct_control().is_none());
        let dns = network.socket(2, 1, 0).unwrap();
        dns.dns_peer.set(true);
        assert!(dns.direct_control().is_none());
    }
}
