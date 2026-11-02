// SPDX-License-Identifier: GPL-3.0-or-later
//! TCP controls over the existing host transport. No namespace/routing authority.
use super::*;
use std::sync::{Mutex, Weak};
pub(crate) type SavedOptions = Arc<Mutex<Vec<(u32, u32, Vec<u8>)>>>;
#[derive(Clone)]
pub struct DirectControl {
    socket: Weak<Endpoint>,
    family: u32,
    unfiltered: bool,
    links: Arc<direct::Links>,
    pub(crate) timeouts: [Option<Duration>; 2],
    pub(crate) options: Option<SavedOptions>,
}
impl Socket {
    pub fn direct_control(&self) -> Option<DirectControl> {
        (self.kind == 1 && !self.dns_peer.get() && self.dns.borrow().is_empty()).then(|| {
            DirectControl {
                socket: Arc::downgrade(&self.native),
                family: self.family,
                unfiltered: !self.policy.borrow().as_ref().is_some_and(|ns| {
                    ns.graph
                        .read()
                        .unwrap()
                        .firewall(ns.id())
                        .read()
                        .unwrap()
                        .has_rules()
                }),
                links: self.network.0.links.clone(),
                timeouts: [None; 2],
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
            (1, 3) => Ok(1),
            (1, 38) => Ok(6),
            (1, 39) => Ok(self.family as i32),
            (1, 30) => Ok(i32::from(
                socket.state.connection() == Connection::Listening,
            )),
            (1, 4) if self.unfiltered => {
                if socket.state.connection() == Connection::Connecting {
                    // Admission excludes live namespace policy. The owner uses
                    // this same completion primitive with its policy callback.
                    let _ = socket.complete_connect(|_| Ok(()));
                }
                if let Some(error) = socket.state.take_error() {
                    return Ok(error as i32);
                }
                Ok(socket
                    .control()
                    .take_error()
                    .map_err(from_io)?
                    .map_or(0, |error| from_io(error).0 as i32))
            }
            _ => socket.get_option(self.family, 1, level, name),
        }
    }
    pub fn supports_operation(&self, number: u32, level: u32, name: u32) -> bool {
        match number {
            204 | 205 | 210 => true,
            208 => matches!(
                (level, name),
                (1, 2 | 6..=9) | (6, 1 | 4..=6) | (0, 2) | (41, 16 | 26)
            ),
            209 => {
                matches!((level, name), (1, 2..=4 | 7..=9 | 30 | 38 | 39) | (6, 1 | 4..=6) | (41, 26))
                    && ((level, name) != (1, 4) || self.unfiltered)
            }
            _ => false,
        }
    }
    pub fn io_timeout(&self, receive: bool) -> Option<Duration> {
        self.timeouts[usize::from(receive)]
    }
    /// Publish only original connected, policy-free native byte authority.
    /// A pending/failed connection never becomes a worker TCP capability.
    pub fn direct_tcp(&self) -> Option<DirectTcp> {
        let socket = self.socket.upgrade()?;
        if !self.unfiltered
            || socket.state.connection() != Connection::Connected
            || socket.state.pending_error().is_some()
        {
            return None;
        }
        Some(DirectTcp {
            socket: self.socket.clone(),
            links: self.links.clone(),
            peer: self.address(true).ok()?,
        })
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        let how = match how {
            0 => Shutdown::Read,
            1 => Shutdown::Write,
            2 => Shutdown::Both,
            _ => return Err(NetError(22)),
        };
        self.socket
            .upgrade()
            .ok_or(NetError(9))?
            .control()
            .shutdown(how)
            .map_err(from_io)
    }

    pub fn set_option_bytes(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
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
        socket.set_option(
            self.family,
            1,
            level,
            name,
            i32::from_le_bytes(value[..4].try_into().unwrap()),
        )?;
        if let Some(options) = options.as_mut() {
            options.retain(|(l, n, _)| (*l, *n) != (level, name));
            options.push((level, name, value.to_vec()));
        }
        Ok(())
    }
}
impl Endpoint {
    pub(super) fn set_option(
        &self,
        family: u32,
        kind: u32,
        level: u32,
        name: u32,
        value: i32,
    ) -> Result<()> {
        let result = match (level, name) {
            (1, 2) => self.control().set_reuse_address(value != 0),
            (1, 6) => self.control().set_broadcast(value != 0),
            (0, 2) if family == 2 && (1..=255).contains(&value) => {
                self.control().set_ttl_v4(value as u32)
            }
            (41, 16) if family == 10 && (1..=255).contains(&value) => {
                self.control().set_unicast_hops_v6(value as u32)
            }
            (1, 9) => {
                let _keepalive = self.keepalive.lock().unwrap();
                self.control().set_keepalive(value != 0)
            }
            (1, 7 | 8) => {
                if value <= 0 || value as usize > MAX_BUFFER {
                    return Err(NetError(22));
                }
                if name == 7 {
                    self.control().set_send_buffer_size(value as usize)
                } else {
                    self.control().set_recv_buffer_size(value as usize)
                }
            }
            (6, 1) if kind == 1 => return self.set_nodelay(value),
            (6, 4..=6) if kind == 1 => {
                // The host helper toggles SO_KEEPALIVE while Linux's parameter
                // setter preserves it. Exclude only setters of this same state.
                let _keepalive = self.keepalive.lock().unwrap();
                if !(1..=if name == 6 { 127 } else { 32767 }).contains(&value) {
                    return Err(NetError(22));
                }
                let parameters = match name {
                    4 => TcpKeepalive::new().with_time(Duration::from_secs(value as u64)),
                    5 => TcpKeepalive::new().with_interval(Duration::from_secs(value as u64)),
                    _ => TcpKeepalive::new().with_retries(value as u32),
                };
                let socket = self.control();
                let enabled = socket.keepalive().map_err(from_io)?;
                let changed = socket.set_tcp_keepalive(&parameters);
                // socket2 enables SO_KEEPALIVE; Linux's individual TCP options
                // preserve it, including when the parameter operation fails.
                let restored = if enabled {
                    Ok(())
                } else {
                    socket.set_keepalive(false)
                };
                changed.and(restored)
            }
            (41, 26) if family == 10 => self.control().set_only_v6(value != 0),
            (1, 20 | 21) => return Err(NetError(95)), // guest timeout state is not implemented
            _ => return Err(NetError(92)),
        };
        result.map_err(from_io)
    }
    pub(super) fn get_option(&self, family: u32, kind: u32, level: u32, name: u32) -> Result<i32> {
        match (level, name) {
            (1, 2) => Ok(i32::from(self.control().reuse_address().map_err(from_io)?)),
            (1, 9) => Ok(i32::from(self.control().keepalive().map_err(from_io)?)),
            (1, 7) => Ok(self.control().send_buffer_size().map_err(from_io)? as i32),
            (1, 8) => Ok(self.control().recv_buffer_size().map_err(from_io)? as i32),
            (6, 1) if kind == 1 => self.nodelay(),
            (6, 4) if kind == 1 => Ok(self
                .control()
                .tcp_keepalive_time()
                .map_err(from_io)?
                .as_secs() as i32),
            (6, 5) if kind == 1 => Ok(self
                .control()
                .tcp_keepalive_interval()
                .map_err(from_io)?
                .as_secs() as i32),
            (6, 6) if kind == 1 => {
                Ok(self.control().tcp_keepalive_retries().map_err(from_io)? as i32)
            }
            (41, 26) if family == 10 => Ok(i32::from(self.control().only_v6().map_err(from_io)?)),
            _ => Err(NetError(92)),
        }
    }

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
    fn original_connection_error_is_consumed_once_across_workers_and_owner() {
        let network = Network::new(NetworkMode::Loopback);
        let socket = network.socket(2, 1, 0).unwrap();
        socket.native.state.set_connection(Connection::Failed(111));
        let control = socket.direct_control().unwrap();
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    let control = &control;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        control.get_option(1, 4).unwrap()
                    })
                })
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|&&error| error == 111).count(), 1);
        assert_eq!(results.iter().filter(|&&error| error == 0).count(), 7);
        assert_eq!(socket.get_option(1, 4), Ok(0));
        assert_eq!(socket.connect_complete(), Err(NetError(111)));
        assert!(control.direct_tcp().is_none());
    }
    #[test]
    fn native_completion_options_and_shutdown_share_original_state() {
        use std::{
            io::Read,
            net::{Ipv4Addr, TcpListener},
        };
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let network = Network::new(NetworkMode::Loopback);
        let socket = network.socket(2, 1, 0).unwrap();
        let control = socket.direct_control().unwrap();
        let result = socket.connect(listener.local_addr().unwrap());
        assert!(matches!(result, Ok(()) | Err(NetError(115))));
        let (mut peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        std::thread::spawn(move || {
            assert_eq!(control.get_option(1, 4), Ok(0));
            assert!(control.direct_tcp().is_some());
            control.set_option_bytes(1, 9, &1i32.to_le_bytes()).unwrap();
            assert_eq!(control.get_option(1, 9), Ok(1));
            control
                .set_option_bytes(6, 4, &30i32.to_le_bytes())
                .unwrap();
            assert_eq!(control.get_option(6, 4), Ok(30));
            control
                .set_option_bytes(1, 8, &65536i32.to_le_bytes())
                .unwrap();
            assert!(control.get_option(1, 8).unwrap() >= 65536);
            assert_eq!(control.shutdown(3), Err(NetError(22)));
            control.shutdown(1).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        assert_eq!(socket.get_option(1, 9), Ok(1));
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }
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
        let mut restricted = control.clone();
        restricted.unfiltered = false;
        assert!(!restricted.supports_operation(209, 1, 4));
        assert_eq!(restricted.get_option(1, 4), Err(NetError(92)));
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
