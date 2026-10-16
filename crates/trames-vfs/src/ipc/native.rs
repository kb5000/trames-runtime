// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded coordinator-owned adapters between guest AF_UNIX and native services.
//! Native threads receive only bytes, owned host FDs and host resource leases.
use super::*;
use std::{io, os::fd::OwnedFd};
use trames_shared::{NativeSocket, SharedFile, MAX_BYTES_OUT, MAX_FDS_OUT};
use trames_wayland::Server;

struct Outgoing {
    bytes: Vec<u8>,
    fds: Vec<OwnedFd>,
    done: usize,
}
struct Incoming {
    bytes: Vec<u8>,
    rights: LocalRights,
    done: usize,
}
struct Connection {
    local: Rc<LocalSocket>,
    native: NativeSocket,
    token: u64,
    owner: (u32, u32),
    outgoing: Option<Outgoing>,
    incoming: Option<Incoming>,
}
pub(crate) struct Services {
    server: Server,
    bindings: Vec<(Vec<u8>, Rc<LocalSocket>)>,
    connections: Vec<Connection>,
}
fn io_errno(e: io::Error) -> Errno {
    match e.kind() {
        io::ErrorKind::WouldBlock => Errno(11),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => Errno(32),
        _ => storage::host_errno(e),
    }
}
impl Services {
    fn pump(&mut self, vfs: &Vfs) -> bool {
        let mut progress = false;
        for (_, listener) in &self.bindings {
            let mut pending = listener.listener.borrow_mut();
            let Some(pending) = pending.as_mut() else {
                continue;
            };
            while let Some(local) = pending.pending.pop_front() {
                if self.connections.len() >= 64 {
                    drop(local);
                    continue;
                }
                let [pid, uid, gid] = local.peer_credentials.get();
                match self.server.connect(pid, uid, gid) {
                    Ok((token, native)) => {
                        self.connections.push(Connection {
                            local,
                            native: native.into(),
                            token,
                            owner: (uid, gid),
                            outgoing: None,
                            incoming: None,
                        });
                        progress = true;
                    }
                    Err(_) => drop(local),
                }
            }
        }
        self.connections
            .retain_mut(|connection| match connection.pump(vfs) {
                Ok(changed) => {
                    progress |= changed;
                    true
                }
                Err(_) => false,
            });
        progress
    }
}
impl Connection {
    fn pump(&mut self, vfs: &Vfs) -> Result<bool> {
        let mut progress = false;
        for _ in 0..16 {
            if self.outgoing.is_none() {
                match self.local.recv(MAX_BYTES_OUT, 0x40) {
                    Ok(packet) if packet.data.is_empty() => return Err(Errno(32)),
                    Ok(packet) => {
                        if packet.rights.0.len() > MAX_FDS_OUT {
                            return Err(Errno(90));
                        }
                        let fds = packet
                            .rights
                            .0
                            .iter()
                            .map(|open| {
                                let open = open.borrow();
                                if open.flags & O_PATH != 0 || open.flags & 3 == 1 {
                                    return Err(Errno(9));
                                }
                                let node = open.node.as_ref().ok_or(Errno(95))?.borrow();
                                let Content::File(data) = &node.content else {
                                    return Err(Errno(95));
                                };
                                data.shared_file()
                                    .ok_or(Errno(95))?
                                    .duplicate_fd()
                                    .map_err(io_errno)
                            })
                            .collect::<Result<Vec<_>>>()?;
                        self.outgoing = Some(Outgoing {
                            bytes: packet.data,
                            fds,
                            done: 0,
                        });
                    }
                    Err(Errno(11)) => break,
                    Err(e) => return Err(e),
                }
            }
            let packet = self.outgoing.as_mut().unwrap();
            match self
                .native
                .send_msg(&packet.bytes[packet.done..], &packet.fds)
            {
                Ok(0) => return Err(Errno(32)),
                Ok(count) => {
                    packet.done += count;
                    packet.fds.clear();
                    progress = true;
                    if packet.done == packet.bytes.len() {
                        self.outgoing = None;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(io_errno(e)),
            }
        }
        for _ in 0..16 {
            if self.incoming.is_none() {
                let mut bytes = vec![0; MAX_BYTES_OUT];
                let mut fds = VecDeque::new();
                match self.native.rcv_msg(&mut bytes, &mut fds) {
                    Ok(0) => return Err(Errno(32)),
                    Ok(count) => {
                        bytes.truncate(count);
                        let rights = fds
                            .into_iter()
                            .map(|fd| vfs.native_file_description(fd, self.owner))
                            .collect::<Result<Vec<_>>>()?;
                        self.incoming = Some(Incoming {
                            bytes,
                            rights: LocalRights(rights),
                            done: 0,
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(io_errno(e)),
                }
            }
            let packet = self.incoming.as_mut().unwrap();
            match self
                .local
                .send_rights(&packet.bytes[packet.done..], 0x40, packet.rights.clone())
            {
                Ok(0) => break,
                Ok(count) => {
                    packet.done += count;
                    packet.rights = LocalRights::default();
                    progress = true;
                    if packet.done == packet.bytes.len() {
                        self.incoming = None;
                    }
                }
                Err(Errno(11)) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(progress)
    }
}
impl Vfs {
    pub fn enable_wayland(&mut self, directory: &[u8]) -> Result<Server> {
        if !directory.starts_with(b"/") || directory.contains(&0) {
            return Err(Errno(22));
        }
        let mut path = Vec::new();
        for part in directory.split(|c| *c == b'/').filter(|p| !p.is_empty()) {
            path.push(b'/');
            path.extend_from_slice(part);
            match self.mkdir_at(AT_FDCWD, &path, 0o700) {
                Ok(()) | Err(Errno(17)) => {}
                Err(e) => return Err(e),
            }
        }
        path.extend_from_slice(b"/wayland-0");
        let services = self.native_services.borrow().clone();
        let services = match services {
            Some(services) => services,
            None => {
                let server = Server::new().map_err(io_errno)?;
                let services = Rc::new(RefCell::new(Services {
                    server,
                    bindings: Vec::new(),
                    connections: Vec::new(),
                }));
                *self.native_services.borrow_mut() = Some(services.clone());
                services
            }
        };
        if services.borrow().bindings.iter().any(|(p, _)| p == &path) {
            return Ok(services.borrow().server.clone());
        }
        // Persisted socket inodes have no live endpoint after a cold restart.
        // Replace only such a stale socket; never replace an ordinary user file.
        if let Ok(resolved) = self.resolve_final(AT_FDCWD, &path, false) {
            if let Ok(node) = self.node(&resolved) {
                let stale =
                    matches!(&node.borrow().content,Content::Socket(peer)if peer.strong_count()==0);
                if stale {
                    self.unlink_at(AT_FDCWD, &path, false)?;
                }
            }
        }
        let listener = self.new_local(1)?;
        let mut name = vec![1, 0];
        name.extend_from_slice(&path);
        name.push(0);
        self.local_bind(&listener, &name)?;
        self.local_listen(&listener, 32)?;
        let mut services = services.borrow_mut();
        services.bindings.push((path, listener));
        Ok(services.server.clone())
    }
    pub fn pump_native_services(&self) -> bool {
        let services = self.native_services.borrow().clone();
        services.is_some_and(|services| services.borrow_mut().pump(self))
    }
    pub fn has_native_services(&self) -> bool {
        self.native_services.borrow().is_some()
    }
    /// Resolve an authenticated Wayland connection from a live guest descriptor.
    pub fn wayland_connection(&self, fd: u32) -> Result<(Server, u64)> {
        self.pump_native_services();
        let socket = self.local_socket(fd)?.ok_or(Errno(88))?;
        let services = self.native_services.borrow().clone().ok_or(Errno(95))?;
        let services = services.borrow();
        let token = services
            .connections
            .iter()
            .find(|c| Rc::ptr_eq(&c.local.channel.borrow(), &socket.channel.borrow()))
            .map(|c| c.token)
            .ok_or(Errno(9))?;
        Ok((services.server.clone(), token))
    }
    fn native_file_description(
        &self,
        fd: OwnedFd,
        owner: (u32, u32),
    ) -> Result<Rc<RefCell<OpenDescription>>> {
        let file = SharedFile::import(fd).map_err(io_errno)?;
        let mut fs = self.fs.borrow_mut();
        fs.inodes.retain(|n| n.strong_count() != 0);
        if fs.inodes.len() >= fs.limits.nodes {
            return Err(Errno(28));
        }
        let inode = fs.next_inode;
        fs.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
        let node = Rc::new(RefCell::new(Node {
            notifications: inotify::Marks::default(),
            device: 16,
            content: Content::File(storage::FileData::Shared(file)),
            mode: 0o100400,
            uid: owner.0,
            gid: owner.1,
            volatile: false,
            inode,
            links: 0,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: Some(15),
        }));
        fs.inodes.push(Rc::downgrade(&node));
        drop(fs);
        Ok(Rc::new(RefCell::new(OpenDescription {
            id: self.open_id(),
            owner,
            kind: FdKind::Node(b"/memfd:wayland-resource".to_vec()),
            flags: 0,
            position: 0,
            node: Some(node),
            pipe: None,
            socket: None,
            bridge: None,
            kernel_log: None,
            anonymous: None,
            notification: None,
            local: None,
            pty: None,
            namespace: None,
            oom: None,
            mount: None,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guest_unix_stream_reaches_the_native_wayland_server_with_standard_wire_messages() {
        let mut vfs = Vfs::default();
        let server = vfs.enable_wayland(b"/run/user/0").unwrap();
        let fd = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        let socket = vfs.local_socket(fd).unwrap().unwrap();
        let mut address = vec![1, 0];
        address.extend_from_slice(b"/run/user/0/wayland-0\0");
        vfs.local_connect(&socket, &address).unwrap();
        socket
            .send(
                &[
                    1u32.to_ne_bytes(),
                    (12u32 << 16).to_ne_bytes(),
                    2u32.to_ne_bytes(),
                ]
                .concat(),
                0,
            )
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let response = loop {
            vfs.pump_native_services();
            match socket.recv(4096, 0x40) {
                Ok(packet) => break packet,
                Err(Errno(11)) => assert!(std::time::Instant::now() < deadline),
                Err(e) => panic!("{e}"),
            };
            std::thread::yield_now();
        };
        assert_eq!(response.data.len(), 24);
        assert_eq!(&response.data[..4], &2u32.to_ne_bytes());
        assert!(vfs.wayland_connection(fd).unwrap().1 > 0);
        drop(server);
    }
}
