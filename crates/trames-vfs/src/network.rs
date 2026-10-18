// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::net::SocketAddr;
#[derive(Clone, Copy)]
enum Sysctl {
    PingRange,
    UnprivilegedPort,
    Forwarding(bool),
}
impl Sysctl {
    fn path(path: &[u8]) -> Option<Self> {
        match path {
            b"/proc/sys/net/ipv4/ping_group_range" => Some(Self::PingRange),
            b"/proc/sys/net/ipv4/ip_unprivileged_port_start" => Some(Self::UnprivilegedPort),
            b"/proc/sys/net/ipv4/ip_forward" | b"/proc/sys/net/ipv4/conf/all/forwarding" => {
                Some(Self::Forwarding(false))
            }
            b"/proc/sys/net/ipv6/conf/all/forwarding" => Some(Self::Forwarding(true)),
            _ => None,
        }
    }
}
#[derive(Clone)]
pub(super) struct Control {
    namespace: Rc<linux_namespace::RootNetwork>,
    kind: Sysctl,
}
impl Control {
    pub fn read(&self, offset: u64, count: usize) -> Vec<u8> {
        let n = self.namespace.network.borrow();
        let data = match self.kind {
            Sysctl::PingRange => {
                let [a, b] = n.ping_range();
                format!("{a}\t{b}\n")
            }
            Sysctl::UnprivilegedPort => format!("{}\n", n.unprivileged_port()),
            Sysctl::Forwarding(ipv6) => format!("{}\n", u8::from(n.forwarding(ipv6))),
        }
        .into_bytes();
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        data[start..start + count.min(data.len() - start)].to_vec()
    }
    pub fn write(&self, bytes: &[u8], offset: u64, authorized: bool) -> Result<usize> {
        if !authorized {
            return Err(Errno(13));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if bytes.len() > 4096 || offset != 0 {
            return Err(Errno(22));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Errno(22))?;
        let values = text
            .split_ascii_whitespace()
            .map(|v| v.parse::<u32>().map_err(|_| Errno(22)))
            .collect::<Result<Vec<_>>>()?;
        let n = self.namespace.network.borrow();
        match (self.kind, values.as_slice()) {
            (Sysctl::PingRange, [a, b]) if *a != u32::MAX && *b != u32::MAX => {
                n.set_ping_range([*a, *b])
            }
            (Sysctl::UnprivilegedPort, [port]) if *port <= u16::MAX as u32 => {
                n.set_unprivileged_port(*port as u16)
            }
            (Sysctl::Forwarding(ipv6), [enabled]) if *enabled <= 1 => {
                n.set_forwarding(ipv6, *enabled != 0)
            }
            _ => return Err(Errno(22)),
        }
        Ok(bytes.len())
    }
}
impl Vfs {
    pub(super) fn network_control(&self, path: &ResolvedPath) -> Option<Control> {
        if !self.uses_pseudo(path) {
            return None;
        }
        Some(Control {
            namespace: self.root_network.clone(),
            kind: Sysctl::path(path)?,
        })
    }
    /// Selected by the embedding app, never by guest syscalls. Forks share the
    /// namespace quota and sockets through their open descriptions.
    pub fn configure_network(&mut self, mode: NetworkMode) -> Result<()> {
        if self.network.live_sockets() != 0 {
            return Err(Errno(16));
        }
        self.network = trames_net::Network::new(mode);
        *self.root_network.network.borrow_mut() = self.network.clone();
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
        *self.root_network.network.borrow_mut() = self.network.clone();
        Ok(())
    }
    pub fn configure_local_fabric(&mut self, mode: NetworkMode) -> Result<()> {
        let fabric = trames_net::Fabric::new().map_err(|e| Errno(e.0))?;
        self.configure_virtual_network(&fabric, 2, mode)
    }
    pub fn network_devices(&self) -> Vec<trames_net::Device> {
        let mut devices = self.network.devices();
        if let Some(links) = self.network.links() {
            for d in &mut devices {
                if d.kind == trames_net::DeviceKind::Loopback {
                    d.stats = links[0];
                } else if d.kind == trames_net::DeviceKind::Direct {
                    d.stats = links[1];
                }
            }
        }
        devices
    }
    pub fn network_routes(&self) -> Vec<trames_net::DeviceRoute> {
        self.network.routes()
    }
    pub fn network_carrier(&self, d: &trames_net::Device) -> bool {
        self.network.device_carrier(d)
    }
    pub fn set_network_device_up(&self, index: u32, up: bool) -> Result<()> {
        if !self.credentials.has_cap(capabilities::NET_ADMIN) {
            return Err(Errno(1));
        }
        self.network
            .set_device_up(index, up)
            .map_err(|e| Errno(e.0))
    }
    pub fn socket_send_bytes(
        &self,
        socket: &NetSocket,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
    ) -> Result<usize> {
        socket
            .send_bytes_with_namespace(
                bytes,
                flags,
                destination,
                self.credentials.has_cap(capabilities::NET_ADMIN),
                &|fd| {
                    let descriptor = self.descriptor(fd).map_err(|e| trames_net::NetError(e.0))?;
                    let open = descriptor.open.borrow();
                    match &open.namespace {
                        Some(linux_namespace::NamespaceHandle::Net(ns)) => {
                            Ok(ns.network.borrow().clone())
                        }
                        _ => Err(trames_net::NetError(22)),
                    }
                },
            )
            .map_err(|e| Errno(e.0))
    }
    pub fn network_info(&self) -> Option<trames_net::NetworkInfo> {
        self.network.info()
    }
    pub fn loopback_up(&self) -> bool {
        self.network.loopback_up()
    }
    pub fn set_loopback_up(&self, up: bool) -> Result<()> {
        if !self.credentials.has_cap(capabilities::NET_ADMIN) {
            return Err(Errno(1));
        }
        self.network.set_loopback_up(up).map_err(|e| Errno(e.0))
    }
    pub fn network_links(&self) -> Option<[trames_net::LinkStats; 2]> {
        self.network.links()
    }
    pub fn finish_network(&self) {
        self.network.finish();
    }
    pub fn socket(&mut self, family: u32, kind: u32, protocol: u32) -> Result<u32> {
        if family == 1 {
            return self.local_create(kind, protocol);
        }
        if matches!((family, kind & 0xf, protocol), (2, 2, 1) | (10, 2, 58)) {
            let [low, high] = self.network.ping_range();
            if !std::iter::once(self.credentials.egid)
                .chain(self.credentials.groups.iter().copied())
                .any(|gid| (low..=high).contains(&gid))
            {
                return Err(Errno(13));
            }
        }
        if matches!(family, 2 | 10)
            && kind & 0xf == 3
            && !self.credentials.has_cap(capabilities::NET_RAW)
        {
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
                    notification: None,
                    local: None,
                    pty: None,
                    namespace: None,
                    network_control: None,
                    oom: None,
                    mount: None,
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
    fn forwarding_controls_pin_namespace_recheck_authority_and_validate_values() {
        let mut v = Vfs::default();
        v.configure_network(NetworkMode::Loopback).unwrap();
        v.set_runtime_info(
            1,
            RuntimeInfo {
                processes: vec![ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    credentials: Credentials::default(),
                    namespaces: v.namespace_snapshot(),
                    ..ProcessInfo::default()
                }],
                ..RuntimeInfo::default()
            },
        );
        let f = v
            .open_at(AT_FDCWD, b"/proc/sys/net/ipv4/ip_forward", 2, 0)
            .unwrap();
        assert_eq!(v.read(f, 100).unwrap(), b"0\n");
        v.seek(f, 0, 0).unwrap();
        assert_eq!(v.write(f, b"2"), Err(Errno(22)));
        v.unshare_net().unwrap();
        assert!(!v.network.forwarding(false));
        v.write(f, b"1").unwrap();
        assert!(!v.network.forwarding(false));
        let alias = v
            .open_at(AT_FDCWD, b"/proc/sys/net/ipv6/conf/all/forwarding", 2, 0)
            .unwrap();
        v.write(alias, b"1").unwrap();
        assert!(v.network.forwarding(true));
        assert!(!v.network.forwarding(false));
        v.credentials = Credentials::user(1000, 1000);
        v.seek(f, 0, 0).unwrap();
        assert_eq!(v.write(f, b"0"), Err(Errno(13)));
    }
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
