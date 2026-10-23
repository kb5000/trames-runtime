// SPDX-License-Identifier: GPL-3.0-or-later
//! Rebuilt per cohort: connect and firewall changes need not change an FD table.
use super::*;
#[derive(Clone)]
pub struct DirectTcpFd {
    pub tcp: trames_net::DirectTcp,
    pub flags: u32,
    pub(super) status: StatusFlags,
    pub timeouts: [Option<std::time::Duration>; 2],
}
impl DirectTcpFd {
    pub fn nonblocking(&self) -> bool {
        self.status.get() & O_NONBLOCK != 0
    }
}
#[derive(Clone, Default)]
pub struct DirectNetwork(Arc<[Option<DirectTcpFd>]>);
impl DirectNetwork {
    pub fn get(&self, fd: u32) -> Option<&DirectTcpFd> {
        self.0.get(fd as usize)?.as_ref()
    }
    pub fn shares_resources(&self, other: &Self) -> bool {
        self.0.iter().flatten().any(|a| {
            other
                .0
                .iter()
                .flatten()
                .any(|b| a.tcp.shares_socket(&b.tcp))
        })
    }
}
impl Vfs {
    pub fn direct_network(&self) -> DirectNetwork {
        if self.network.live_sockets() == 0 {
            return DirectNetwork::default();
        }
        let mut entries = Vec::new();
        for (&fd, descriptor) in self.fds.entries().iter() {
            let open = descriptor.open.borrow();
            let Some(tcp) = open.socket.as_ref().and_then(|socket| socket.direct_tcp()) else {
                continue;
            };
            entries.resize_with(fd as usize + 1, || None);
            entries[fd as usize] = Some(DirectTcpFd {
                tcp,
                flags: open.flags.get(),
                status: open.flags.clone(),
                timeouts: [false, true]
                    .map(|receive| open.socket.as_ref().unwrap().io_timeout(receive)),
            });
        }
        DirectNetwork(entries.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        net::{Ipv4Addr, TcpListener},
        time::Duration,
    };
    #[test]
    fn tcp_capabilities_refresh_without_fd_mutation_and_do_not_delay_last_close() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        let flags = v.fd_flags_snapshot().get(fd).unwrap();
        assert!(v.direct_network().get(fd).is_none());
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        assert_eq!(v.fd_flags_snapshot().get(fd).unwrap(), flags);
        let capability = v.direct_network();
        assert!(capability.get(fd).is_some());
        drop(socket);
        v.close(fd).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(
            capability.get(fd).unwrap().tcp.send(b"closed", 0),
            Err(trames_net::NetError(9))
        );
        assert!(v.direct_network().get(fd).is_none());
    }
    #[test]
    fn accepted_tcp_lease_survives_alias_close_and_fd_reuse_until_worker_release() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        let fd = v.socket(2, 1, 0).unwrap();
        let socket = v.socket_fd(fd).unwrap();
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        drop(socket);
        let cap = v.direct_network().get(fd).unwrap().tcp.clone();
        let lease = v.retain_uring_fd(fd).unwrap().tcp_lease().unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let mut child = v.clone();
        v.close(fd).unwrap();
        v.close(alias).unwrap();
        child.close_all();
        let replacement = v.socket(2, 2, 0).unwrap();
        assert_eq!(replacement, fd);
        assert!(v
            .retain_uring_fd(replacement)
            .unwrap()
            .tcp_lease()
            .is_none());
        assert_eq!(cap.send(b"original", 0), Ok(8));
        let mut bytes = [0; 8];
        peer.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"original");
        drop((v, child));
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        std::thread::spawn(move || drop(lease)).join().unwrap();
        peer.set_nonblocking(false).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(cap.recv(1, 0), Err(trames_net::NetError(9)));
    }
}
