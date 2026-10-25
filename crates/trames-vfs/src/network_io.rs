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
/// Reuse TCP capabilities while preparing one stopped execution cohort.
/// Discard before running guests: connect, timeout and policy changes need not
/// change FD membership. Keeping the identity alive also prevents pointer reuse.
#[derive(Default)]
pub struct NetworkEpoch {
    captures: BTreeMap<usize, (Rc<fd_table::DescriptorVersion>, DirectNetwork)>,
}
impl NetworkEpoch {
    pub fn capture(&mut self, vfs: &Vfs) -> DirectNetwork {
        let identity = vfs.fds.identity();
        self.captures
            .entry(Rc::as_ptr(&identity) as usize)
            .or_insert_with(|| (identity, vfs.direct_network()))
            .1
            .clone()
    }
}
impl Vfs {
    /// Inspect only the requested FD when deciding whether byte I/O can run
    /// on a worker. Unrelated sockets do not affect this capability.
    pub fn direct_tcp_fd(&self, fd: u32) -> Option<DirectTcpFd> {
        let descriptor = self.fds.get(&fd)?;
        let result = Self::direct_tcp_open(&descriptor.open.borrow());
        result
    }
    fn direct_tcp_open(open: &OpenDescription) -> Option<DirectTcpFd> {
        let socket = open.socket.as_ref()?;
        Some(DirectTcpFd {
            tcp: socket.direct_tcp()?,
            flags: open.flags.get(),
            status: open.flags.clone(),
            timeouts: [false, true].map(|receive| socket.io_timeout(receive)),
        })
    }
    pub fn direct_network(&self) -> DirectNetwork {
        if self.network.live_sockets() == 0 {
            return DirectNetwork::default();
        }
        let mut entries = Vec::new();
        for (&fd, descriptor) in self.fds.entries().iter() {
            let Some(tcp) = Self::direct_tcp_open(&descriptor.open.borrow()) else {
                continue;
            };
            entries.resize_with(fd as usize + 1, || None);
            entries[fd as usize] = Some(tcp);
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
        let mut before_connect = NetworkEpoch::default();
        assert!(before_connect.capture(&v).get(fd).is_none());
        drop(before_connect);
        assert!(matches!(
            socket.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let (mut peer, _) = listener.accept().unwrap();
        assert_eq!(socket.connect_complete(), Ok(true));
        assert_eq!(v.fd_flags_snapshot().get(fd).unwrap(), flags);
        // Connection completion has not changed FD membership. A new cohort
        // must still discover it, then share that one capture across threads.
        let shared = v.clone_with_resources(true, true);
        let mut epoch = NetworkEpoch::default();
        let capability = epoch.capture(&v);
        let sibling = epoch.capture(&shared);
        assert!(Arc::ptr_eq(&capability.0, &sibling.0));
        assert!(capability.get(fd).is_some());
        assert!(v.direct_tcp_fd(fd).is_some());
        assert!(v.direct_tcp_fd(u32::MAX).is_none());
        drop(epoch);
        drop(shared);
        drop(socket);
        v.close(fd).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(
            capability.get(fd).unwrap().tcp.send(b"closed", 0),
            Err(trames_net::NetError(9))
        );
        assert!(v.direct_network().get(fd).is_none());
        assert!(NetworkEpoch::default().capture(&v).get(fd).is_none());
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
