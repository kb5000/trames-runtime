// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::net::SocketAddr;
impl Vfs {
    /// Selected by the embedding app, never by guest syscalls. Forks share the
    /// namespace quota and sockets through their open descriptions.
    pub fn configure_network(&mut self, mode: NetworkMode) -> Result<()> {
        if self.network.live_sockets() != 0 {
            return Err(Errno(16));
        }
        self.network = trames_net::Network::new(mode);
        Ok(())
    }
    pub fn configure_virtual_network(
        &mut self,
        fabric: &trames_net::Fabric,
        id: u8,
        mode: NetworkMode,
    ) -> Result<()> {
        if self.network.live_sockets() != 0 {
            return Err(Errno(16));
        }
        self.network =
            trames_net::Network::virtual_network(fabric, id, mode).map_err(|e| Errno(e.0))?;
        Ok(())
    }
    pub fn configure_local_fabric(&mut self, mode: NetworkMode) -> Result<()> {
        let fabric = trames_net::Fabric::new().map_err(|e| Errno(e.0))?;
        self.configure_virtual_network(&fabric, 2, mode)
    }
    pub fn network_info(&self) -> Option<trames_net::NetworkInfo> {
        self.network.info()
    }
    pub fn network_links(&self) -> Option<[trames_net::LinkStats; 2]> {
        self.network.links()
    }
    pub fn finish_network(&self) {
        self.network.finish();
    }
    pub fn socket(&mut self, family: u32, kind: u32, protocol: u32) -> Result<u32> {
        if matches!(family, 2 | 10) && kind & 0xf == 3 && self.credentials.euid != 0 {
            return Err(Errno(1));
        }
        if kind & !(O_CLOEXEC | O_NONBLOCK | 0xf) != 0 {
            return Err(Errno(22));
        }
        let fd = self.available(0)?;
        let socket = self
            .network
            .socket(family, kind & 0xf, protocol)
            .map_err(|e| Errno(e.0))?;
        self.socket_descriptor(fd, socket, kind);
        Ok(fd)
    }
    fn socket_descriptor(&mut self, fd: u32, socket: Rc<NetSocket>, flags: u32) {
        self.fds.insert(
            fd,
            Descriptor {
                open: Rc::new(RefCell::new(OpenDescription {
                    id: self.open_id(),
                    owner: (self.credentials.fsuid, self.credentials.fsgid),
                    kind: FdKind::Socket,
                    flags: 2 | (flags & O_NONBLOCK),
                    position: 0,
                    node: None,
                    pipe: None,
                    socket: Some(socket),
                    bridge: None,
                    kernel_log: None,
                    anonymous: None,
                    local: None,
                })),
                cloexec: flags & O_CLOEXEC != 0,
            },
        );
    }
    pub fn socket_fd(&self, fd: u32) -> Result<Rc<NetSocket>> {
        self.descriptor(fd)?
            .open
            .borrow()
            .socket
            .clone()
            .ok_or(Errno(88))
    }
    pub fn accept(&mut self, fd: u32, flags: u32) -> Result<(u32, SocketAddr)> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        let socket = self.socket_fd(fd)?;
        let new = self.available(0)?;
        let (socket, address) = socket.accept().map_err(|e| Errno(e.0))?;
        self.socket_descriptor(new, socket, flags);
        Ok((new, address))
    }
    pub fn live_sockets(&self) -> usize {
        self.network.live_sockets()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fork_dup_cloexec_and_quota_follow_socket_lifetime() {
        let mut parent = Vfs::default();
        parent.configure_network(NetworkMode::Loopback).unwrap();
        let socket = parent.socket(2, 1 | O_CLOEXEC | O_NONBLOCK, 0).unwrap();
        let mut child = parent.clone();
        let copy = child.dup(socket, 0, false).unwrap();
        parent.close(socket).unwrap();
        assert_eq!(parent.live_sockets(), 1);
        child.set_status_flags(copy, 2).unwrap();
        assert_eq!(child.flags(socket).unwrap() & O_NONBLOCK, 0);
        child.close_exec();
        assert_eq!(child.fd_kind(socket), Err(Errno(9)));
        assert_eq!(child.fd_kind(copy), Ok(FdKind::Socket));
        assert_eq!(
            child.stat_fd(copy).unwrap()[16..20],
            0o140600u32.to_le_bytes()
        );
        assert_eq!(parent.configure_network(NetworkMode::Off), Err(Errno(16)));
        child.close(copy).unwrap();
        assert_eq!(parent.live_sockets(), 0);
        let descriptors: Vec<_> = (0..trames_net::MAX_SOCKETS)
            .map(|_| parent.socket(2, 2, 0).unwrap())
            .collect();
        assert_eq!(child.socket(2, 1, 0), Err(Errno(24)));
        parent.close(descriptors[0]).unwrap();
        let new = child.socket(2, 1, 0).unwrap();
        assert_eq!(parent.live_sockets(), trames_net::MAX_SOCKETS);
        parent.close_all();
        assert_eq!(child.live_sockets(), 1);
        child.close(new).unwrap();
        assert_eq!(child.live_sockets(), 0);
    }
}
