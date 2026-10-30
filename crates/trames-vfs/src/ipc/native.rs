// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded coordinator-owned adapters between guest AF_UNIX and native services.
//! Native threads receive only bytes, owned host FDs and host resource leases.
use super::*;
use std::{
    io::{self, Read, Write},
    os::fd::OwnedFd,
};
use trames_shared::{NativeSocket, SharedFile, MAX_BYTES_OUT, MAX_FDS_OUT};
use trames_wayland::Server;

enum Grant {
    Connection(u64),
    Shared(SharedFile),
}
struct Grants {
    server: Server,
    fds: BTreeMap<u32, Grant>,
}
/// Authenticated capabilities of a frozen FD table, never VFS Rc or raw FDs.
/// The caller must end this snapshot before mutating/reusing that table.
#[derive(Clone, Default)]
pub struct WaylandAuth(Option<Arc<Grants>>);
impl WaylandAuth {
    pub fn resolve(&self, fd: u32) -> Option<(Server, u64)> {
        let grants = self.0.as_ref()?;
        let token = match grants.fds.get(&fd)? {
            Grant::Connection(token) => *token,
            // Resolve compositor registration live, keeping its original
            // inode identity lease; copied bytes cannot manufacture a grant.
            Grant::Shared(file) => {
                grants
                    .server
                    .snapshot()
                    .wsi_connections
                    .get(&file.key())?
                    .connection
            }
        };
        Some((grants.server.clone(), token))
    }
}

struct Outgoing {
    bytes: Vec<u8>,
    fds: Vec<OwnedFd>,
    done: usize,
    leases: Vec<trames_shared::ExportLease>,
    registered: bool,
}
struct Incoming {
    bytes: Vec<u8>,
    rights: LocalRights,
    done: usize,
}
struct Connection {
    xwm: bool,
    local: Rc<LocalSocket>,
    native: NativeSocket,
    token: u64,
    owner: (u32, u32),
    outgoing: Option<Outgoing>,
    incoming: Option<Incoming>,
    exports: Vec<trames_shared::ExportLease>,
    relays: Vec<PipeRelay>,
}
// Endpoint ownership is shared; inode metadata remains an owner projection.
// Keeping that anchor preserves the original unlink/inotify/node lifetime.
struct PipeRelay {
    host: trames_shared::NativePipe,
    guest: Arc<PipeEndpoint>,
    _metadata: Option<NodeRef>,
    to_native: bool,
}
impl PipeRelay {
    fn new(
        host: trames_shared::NativePipe,
        pipe: Pipe,
        to_native: bool,
        metadata: Option<NodeRef>,
    ) -> Self {
        Self {
            host,
            guest: PipeEndpoint::anonymous(pipe.data, to_native, !to_native),
            _metadata: metadata,
            to_native,
        }
    }
    fn pump(&mut self) -> bool {
        let mut pipe = self.guest.data.lock().unwrap();
        if self.to_native {
            if pipe.bytes.is_empty() {
                return pipe.writers != 0;
            }
            let bytes = pipe.bytes.iter().take(16384).copied().collect::<Vec<_>>();
            match self.host.write(&bytes) {
                Ok(n) => {
                    pipe.bytes.drain(..n);
                    pipe.io_epoch[1] = pipe.io_epoch[1].wrapping_add(1);
                    true
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
                _ => false,
            }
        } else {
            if pipe.readers == 0 {
                return false;
            }
            let room = (PIPE_CAPACITY - pipe.bytes.len()).min(16384);
            if room == 0 {
                return true;
            }
            let mut bytes = vec![0; room];
            match self.host.read(&mut bytes) {
                Ok(0) => false,
                Ok(n) => {
                    pipe.bytes.extend(&bytes[..n]);
                    pipe.io_epoch[0] = pipe.io_epoch[0].wrapping_add(1);
                    true
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => true,
                _ => false,
            }
        }
    }
}
pub(crate) struct Services {
    identity: u64,
    server: Server,
    bindings: Vec<(Vec<u8>, Rc<LocalSocket>, bool)>,
    connections: Vec<Connection>,
    connection_revision: u64,
}
fn io_errno(e: io::Error) -> Errno {
    match e.kind() {
        io::ErrorKind::WouldBlock => Errno(11),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => Errno(32),
        _ => storage::host_errno(e),
    }
}
impl OpenDescription {
    fn pipe_description(id: u64, owner: (u32, u32), pipe: Pipe, write: bool) -> Self {
        Self {
            shared: Arc::new(SharedOpenDescription {
                native_image: None,
                mount_resource: std::sync::OnceLock::new(),
                control: None,
                read_node: None,
                id,
                owner,
                kind: if write {
                    FdKind::PipeWrite
                } else {
                    FdKind::PipeRead
                },
                flags: (if write { 1 } else { 0 }).into(),
                file_position: Arc::default(),
                flock: std::sync::OnceLock::new(),
                pipe: Some(PipeEnd::new(pipe, !write, write, None)),
                node: None,
                bridge: None,
                kernel_log: None,
                notification: None,
            }),
            position: 0,
            socket: None,
            anonymous: None,
            local: None,
            pty: None,
            namespace: None,
            oom: None,
            network_control: None,
            mount: None,
        }
    }
}
impl Services {
    fn pump(&mut self, vfs: &Vfs) -> bool {
        let mut progress = false;
        for (_, listener, xwm) in &self.bindings {
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
                let connected = if *xwm {
                    self.server
                        .connect_xwm(pid, uid, gid)
                        .map(|socket| (0, socket))
                } else {
                    self.server.connect(pid, uid, gid)
                };
                match connected {
                    Ok((token, native)) => {
                        self.connection_revision = self.connection_revision.wrapping_add(1);
                        self.connections.push(Connection {
                            xwm: *xwm,
                            local,
                            native: native.into(),
                            token,
                            owner: (uid, gid),
                            outgoing: None,
                            incoming: None,
                            exports: Vec::new(),
                            relays: Vec::new(),
                        });
                        progress = true;
                    }
                    Err(_) => drop(local),
                }
            }
        }
        let connections = self.connections.len();
        self.connections
            .retain_mut(|connection| match connection.pump(vfs, &self.server) {
                Ok(changed) => {
                    progress |= changed;
                    true
                }
                Err(e) => {
                    if e.0 != 32 {
                        vfs.log(
                            4,
                            &format!(
                                "wayland bridge connection={} errno={}",
                                connection.token, e.0
                            ),
                        );
                    }
                    false
                }
            });
        if self.connections.len() != connections {
            self.connection_revision = self.connection_revision.wrapping_add(1);
        }
        progress
    }
}
impl Connection {
    fn pump(&mut self, vfs: &Vfs, server: &Server) -> Result<bool> {
        let mut progress = false;
        self.relays.retain_mut(|relay| {
            let before = relay.guest.data.lock().unwrap().bytes.len();
            let alive = relay.pump();
            progress |= !alive || relay.guest.data.lock().unwrap().bytes.len() != before;
            alive
        });
        self.exports.retain(|lease| !lease.claimed());
        for _ in 0..16 {
            if self.outgoing.is_none() {
                if self.exports.len() >= 64 {
                    break;
                }
                match self.local.recv(MAX_BYTES_OUT, 0x40) {
                    Ok(packet) if packet.data.is_empty() => return Err(Errno(32)),
                    Ok(packet) => {
                        if packet.rights.0.len() > MAX_FDS_OUT {
                            return Err(Errno(90));
                        }
                        let exported = packet
                            .rights
                            .0
                            .iter()
                            .map(|open| {
                                let open = open.borrow();
                                if open.flags.get() & O_PATH != 0 {
                                    return Err(Errno(9));
                                }
                                if let Some(end) = &open.pipe {
                                    if self.relays.len() >= 64 {
                                        return Err(Errno(24));
                                    }
                                    if !end.write || end.read {
                                        return Err(Errno(95));
                                    }
                                    let (reader, writer) =
                                        trames_shared::NativePipe::pair().map_err(io_errno)?;
                                    self.relays.push(PipeRelay::new(
                                        reader,
                                        end.pipe.clone(),
                                        false,
                                        end.metadata.clone(),
                                    ));
                                    return Ok((writer.into_fd(), None));
                                }
                                if open.flags.get() & 3 == 1 {
                                    return Err(Errno(9));
                                }
                                let node = open.node.as_ref().ok_or(Errno(95))?.borrow();
                                let Content::File(data) = &node.content else {
                                    return Err(Errno(95));
                                };
                                data.shared_file()
                                    .ok_or(Errno(95))?
                                    .export()
                                    .map(|(fd, lease)| (fd, Some(lease)))
                                    .map_err(io_errno)
                            })
                            .collect::<Result<Vec<_>>>()?;
                        let (fds, leases): (Vec<_>, Vec<_>) = exported.into_iter().unzip();
                        let leases = leases.into_iter().flatten().collect();
                        self.outgoing = Some(Outgoing {
                            bytes: packet.data,
                            fds,
                            done: 0,
                            leases,
                            registered: false,
                        });
                    }
                    Err(Errno(11)) => break,
                    Err(e) => return Err(e),
                }
            }
            let packet = self.outgoing.as_mut().unwrap();
            if !packet.registered {
                if !packet.leases.is_empty() {
                    match server.retain_exports(self.token, packet.leases.clone()) {
                        Ok(()) => self.exports.append(&mut packet.leases),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(io_errno(e)),
                    }
                }
                packet.registered = true;
            }
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
                        let mut rights = Vec::new();
                        for fd in fds {
                            if trames_shared::NativePipe::is_pipe(&fd).map_err(io_errno)? {
                                if self.relays.len() >= 64 {
                                    return Err(Errno(24));
                                }
                                let host =
                                    trames_shared::NativePipe::import(fd).map_err(io_errno)?;
                                if !host.writable().map_err(io_errno)? {
                                    return Err(Errno(95));
                                }
                                let pipe = Pipe::new(vfs.open_id());
                                let open = OpenDescription::pipe_description(
                                    vfs.open_id(),
                                    self.owner,
                                    pipe.clone(),
                                    true,
                                );
                                rights.push(OpenHandle::new(open));
                                self.relays.push(PipeRelay::new(host, pipe, true, None));
                            } else {
                                rights.push(vfs.native_file_description(fd, self.owner)?);
                            }
                        }
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
    fn clear_stale_x11_endpoints(&mut self) {
        let Ok(directory) = self.resolve_final(AT_FDCWD, b"/tmp/.X11-unix", false) else {
            return;
        };
        let names =
            {
                let fs = directory.mount().map_or(&self.fs, |m| &m.fs).borrow();
                crate::directory::children(&fs.paths,directory.key()).filter(|(name,node)| {
                name.starts_with(b"X") && name.len()>1 && name[1..].iter().all(u8::is_ascii_digit)
                 && matches!(&node.borrow().content,Content::Socket(peer) if !peer.is_live())
            }).map(|(name,_)|name.to_vec()).collect::<Vec<_>>()
            };
        for name in names {
            let mut socket = b"/tmp/.X11-unix/".to_vec();
            socket.extend_from_slice(&name);
            if self.unlink_at(AT_FDCWD, &socket, false).is_err() {
                continue;
            }
            let mut lock = b"/tmp/.".to_vec();
            lock.extend_from_slice(&name);
            lock.extend_from_slice(b"-lock");
            if let Ok(path) = self.resolve_final(AT_FDCWD, &lock, false) {
                let regular = self
                    .node(&path)
                    .is_ok_and(|node| matches!(node.borrow().content, Content::File(_)));
                if regular {
                    let _ = self.unlink_at(AT_FDCWD, &lock, false);
                }
            }
        }
    }
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
        let services = self.native_services.borrow().clone();
        let services = match services {
            Some(services) => services,
            None => {
                // A persisted X11 socket without a live endpoint proves its
                // lock belongs to an earlier session. Linux PIDs restart at 1,
                // so kill(old_pid,0) alone can mistake a reused PID for Xwayland.
                self.clear_stale_x11_endpoints();
                let server = Server::new().map_err(io_errno)?;
                let services = Rc::new(RefCell::new(Services {
                    identity: trames_memory::new_backing_identity(),
                    server,
                    bindings: Vec::new(),
                    connections: Vec::new(),
                    connection_revision: 0,
                }));
                *self.native_services.borrow_mut() = Some(services.clone());
                services
            }
        };
        // Register the XWM endpoint before the Wayland display: a launcher
        // connects it first and then execs Xwayland without changing its PID.
        for (name, xwm) in [
            (b"/trames-xwm".as_slice(), true),
            (b"/wayland-0".as_slice(), false),
        ] {
            let mut path = path.clone();
            path.extend_from_slice(name);
            if services
                .borrow()
                .bindings
                .iter()
                .any(|(p, _, _)| p == &path)
            {
                continue;
            }
            // Persisted socket inodes have no live endpoint after a cold restart.
            // Replace only such a stale socket; never replace an ordinary user file.
            if let Ok(resolved) = self.resolve_final(AT_FDCWD, &path, false) {
                if let Ok(node) = self.node(&resolved) {
                    let stale =
                        matches!(&node.borrow().content,Content::Socket(peer)if !peer.is_live());
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
            services.bindings.push((path, listener, xwm));
        }
        let server = services.borrow().server.clone();
        Ok(server)
    }
    pub fn pump_native_services(&self) -> bool {
        let services = self.native_services.borrow().clone();
        services.is_some_and(|services| services.borrow_mut().pump(self))
    }
    pub fn wayland_server(&self) -> Option<Server> {
        self.native_services
            .borrow()
            .as_ref()
            .map(|s| s.borrow().server.clone())
    }
    pub fn has_native_services(&self) -> bool {
        self.native_services
            .borrow()
            .as_ref()
            .is_some_and(|services| !services.borrow().connections.is_empty())
    }
    /// Resolve an authenticated Wayland connection from a live guest descriptor.
    pub fn wayland_connection(&self, fd: u32) -> Result<(Server, u64)> {
        self.pump_native_services();
        let services = self.native_services.borrow().clone().ok_or(Errno(95))?;
        let services = services.borrow();
        let token = if let Some(socket) = self.local_socket(fd)? {
            services
                .connections
                .iter()
                .find(|c| !c.xwm && Rc::ptr_eq(&c.local.channel.borrow(), &socket.channel.borrow()))
                .map(|c| c.token)
                .ok_or(Errno(9))?
        } else {
            // The compositor registered this same retained shared inode from
            // SCM_RIGHTS on its actual connection. A socket pair, guessed
            // object ID or a file containing copied bytes cannot mint a grant.
            let file = self.shared_file(fd)?;
            services
                .server
                .snapshot()
                .wsi_connections
                .get(&file.key())
                .ok_or(Errno(11))?
                .connection
        };
        Ok((services.server.clone(), token))
    }
    pub fn wayland_auth_snapshot(&self) -> WaylandAuth {
        let services = self.native_services.borrow();
        let Some(services) = services.as_ref() else {
            return WaylandAuth::default();
        };
        let services = services.borrow();
        if services.connections.is_empty() {
            return WaylandAuth::default();
        }
        // The same object lock orders cache capture and every owner/worker FD
        // mutation. Cache before/after never owns a stale closed file's quota.
        let mut entries = self.fds.entries();
        // Resource identities cannot be reused while old grants remain.
        // Connection changes matter even without an FD-table mutation.
        if let Some(auth) = entries.cached_wayland(services.identity, services.connection_revision)
        {
            return auth;
        }
        let mut fds = BTreeMap::new();
        for (&fd, descriptor) in entries.iter() {
            let description = descriptor.open.borrow();
            let grant = if let Some(socket) = &description.local {
                services
                    .connections
                    .iter()
                    .find(|c| {
                        !c.xwm && Rc::ptr_eq(&c.local.channel.borrow(), &socket.channel.borrow())
                    })
                    .map(|c| Grant::Connection(c.token))
            } else {
                Self::shared_file_open(&description).ok().map(Grant::Shared)
            };
            if let Some(grant) = grant {
                fds.insert(fd, grant);
            }
        }
        let auth = WaylandAuth(Some(Arc::new(Grants {
            server: services.server.clone(),
            fds,
        })));
        entries.cache_wayland(
            services.identity,
            services.connection_revision,
            auth.clone(),
        );
        auth
    }
    fn native_file_description(&self, fd: OwnedFd, owner: (u32, u32)) -> Result<OpenHandle> {
        let file = SharedFile::import(fd).map_err(io_errno)?;
        let mut fs = self.fs.borrow_mut();
        fs.admit_inode()?;
        let inode = fs.next_inode;
        fs.next_inode = inode.checked_add(1).ok_or(Errno(28))?;
        let node = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
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
        fs.inodes.push(Arc::downgrade(&node));
        drop(fs);
        Ok(OpenHandle::new(OpenDescription {
            shared: Arc::new(SharedOpenDescription {
                native_image: None,
                mount_resource: std::sync::OnceLock::new(),
                control: None,
                read_node: None,
                id: self.open_id(),
                owner,
                kind: FdKind::Node(b"/memfd:wayland-resource".to_vec()),
                flags: (0).into(),
                file_position: Arc::default(),
                flock: std::sync::OnceLock::new(),
                node: Some(node),
                pipe: None,
                bridge: None,
                kernel_log: None,
                notification: None,
            }),
            position: 0,
            socket: None,
            anonymous: None,
            local: None,
            pty: None,
            namespace: None,
            network_control: None,
            oom: None,
            mount: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clipboard_pipe_relays_preserve_bytes_backpressure_and_eof() {
        let mut vfs = Vfs::default();
        let [read, write] = vfs.pipe(O_NONBLOCK).unwrap();
        let end = vfs
            .descriptor(write)
            .unwrap()
            .open
            .borrow()
            .pipe
            .clone()
            .unwrap();
        let (reader, mut writer) = trames_shared::NativePipe::pair().unwrap();
        let mut relay = PipeRelay::new(reader, end.pipe.clone(), false, end.metadata.clone());
        drop(end);
        vfs.close(write).unwrap();
        assert_eq!(vfs.read(read, 10), Err(Errno(11)));
        writer.write_all("host 中文".as_bytes()).unwrap();
        assert!(relay.pump());
        assert_eq!(vfs.read(read, 100).unwrap(), "host 中文".as_bytes());
        assert_eq!(vfs.read(read, 1), Err(Errno(11)));
        drop(writer);
        assert!(!relay.pump());
        drop(relay);
        assert!(vfs.read(read, 1).unwrap().is_empty());
        let (mut reader, writer) = trames_shared::NativePipe::pair().unwrap();
        let pipe = Pipe::new(vfs.open_id());
        let open = OpenHandle::new(OpenDescription::pipe_description(
            vfs.open_id(),
            (0, 0),
            pipe.clone(),
            true,
        ));
        let (fds, truncated) = vfs.receive_rights(LocalRights(vec![open]), 1, false);
        assert!(!truncated);
        let mut relay = PipeRelay::new(writer, pipe, true, None);
        vfs.write(fds[0], b"guest text").unwrap();
        vfs.close(fds[0]).unwrap();
        assert!(relay.pump());
        let mut bytes = [0; 32];
        let n = reader.read(&mut bytes).unwrap();
        assert_eq!(&bytes[..n], b"guest text");
        assert!(!relay.pump());
        drop(relay);
        assert_eq!(reader.read(&mut bytes).unwrap(), 0);
    }
    #[test]
    fn frozen_wayland_auth_carries_only_actual_connection_or_registered_inode_capabilities() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<WaylandAuth>();
        let mut vfs = Vfs::default();
        let _server = vfs.enable_wayland(b"/run/user/0").unwrap();
        let fd = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        assert!(vfs.wayland_auth_snapshot().resolve(fd).is_none());
        let socket = vfs.local_socket(fd).unwrap().unwrap();
        let mut address = vec![1, 0];
        address.extend_from_slice(b"/run/user/0/wayland-0\0");
        vfs.local_connect(&socket, &address).unwrap();
        let token = vfs.wayland_connection(fd).unwrap().1;
        let first = vfs.wayland_auth_snapshot();
        let repeated = vfs.wayland_auth_snapshot();
        assert!(Arc::ptr_eq(
            first.0.as_ref().unwrap(),
            repeated.0.as_ref().unwrap()
        ));
        let peer = vfs.clone_with_files(true);
        let shared = peer.wayland_auth_snapshot();
        assert!(Arc::ptr_eq(
            first.0.as_ref().unwrap(),
            shared.0.as_ref().unwrap()
        ));
        drop(peer);
        let alias = vfs.dup(fd, 0, false).unwrap();
        let pair = vfs.socketpair(1, 1, 0).unwrap();
        let copied = vfs.memfd_create(b"unregistered-wayland", 0).unwrap();
        vfs.write(copied, b"copied capability bytes").unwrap();
        let snapshot = vfs.wayland_auth_snapshot();
        assert!(snapshot.resolve(copied).is_none());
        assert!(snapshot.resolve(pair[0]).is_none());
        assert!(snapshot.resolve(u32::MAX).is_none());
        std::thread::spawn(move || {
            assert_eq!(snapshot.resolve(fd).unwrap().1, token);
            assert_eq!(snapshot.resolve(alias).unwrap().1, token);
        })
        .join()
        .unwrap();
        vfs.close(fd).unwrap();
        let replacement = vfs.local_create(1, 0).unwrap();
        assert_eq!(replacement, fd);
        assert!(vfs.wayland_auth_snapshot().resolve(fd).is_none());
        assert_eq!(vfs.wayland_auth_snapshot().resolve(alias).unwrap().1, token);
    }
    #[test]
    fn cached_auth_rechecks_connections_without_an_fd_membership_change() {
        let mut vfs = Vfs::default();
        let _server = vfs.enable_wayland(b"/run/user/0").unwrap();
        let first = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        let second = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        let mut address = vec![1, 0];
        address.extend_from_slice(b"/run/user/0/wayland-0\0");
        vfs.local_connect(&vfs.local_socket(first).unwrap().unwrap(), &address)
            .unwrap();
        let token = vfs.wayland_connection(first).unwrap().1;
        let before = vfs.wayland_auth_snapshot();
        assert!(before.resolve(second).is_none());
        let membership = vfs.shared_files().capture_identity();
        vfs.local_connect(&vfs.local_socket(second).unwrap().unwrap(), &address)
            .unwrap();
        let other = vfs.wayland_connection(second).unwrap().1;
        assert_eq!(vfs.shared_files().capture_identity(), membership);
        let after = vfs.wayland_auth_snapshot();
        assert_eq!(after.resolve(first).unwrap().1, token);
        assert_eq!(after.resolve(second).unwrap().1, other);
        assert!(!Arc::ptr_eq(
            before.0.as_ref().unwrap(),
            after.0.as_ref().unwrap()
        ));
    }
    #[test]
    fn retired_auth_cache_does_not_retain_closed_worker_file_quota() {
        let mut vfs = Vfs::default();
        let _server = vfs.enable_wayland(b"/run/user/0").unwrap();
        let socket = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        let mut address = vec![1, 0];
        address.extend_from_slice(b"/run/user/0/wayland-0\0");
        vfs.local_connect(&vfs.local_socket(socket).unwrap().unwrap(), &address)
            .unwrap();
        vfs.wayland_connection(socket).unwrap();
        let before = vfs.memfd_available();
        let fd = vfs.memfd_create(b"retire-auth", 0).unwrap();
        vfs.truncate_fd(fd, 16384).unwrap();
        vfs.write(fd, &[31; 16384]).unwrap();
        assert!(vfs.memfd_available() < before);
        let pipe = vfs.pipe(0).unwrap();
        let snapshot = vfs.wayland_auth_snapshot();
        let retired = Arc::downgrade(snapshot.0.as_ref().unwrap());
        drop(snapshot);
        let membership = vfs.shared_files();
        std::thread::spawn(move || assert_eq!(membership.close(pipe[0], 0), Some(Ok(()))))
            .join()
            .unwrap();
        assert!(
            retired.upgrade().is_none(),
            "worker membership changes must retire inactive auth grants"
        );
        drop(vfs.wayland_auth_snapshot());
        vfs.close(fd).unwrap();
        assert_eq!(
            vfs.memfd_available(),
            before,
            "inactive authorization caches cannot retain closed file allocations"
        );
    }
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
            if vfs.poll(fd, 1) & 1 != 0 {
                assert_eq!(vfs.readable_bytes(fd), Ok(Some(24)));
            }
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
    #[test]
    fn cold_wayland_start_removes_only_dead_x11_sockets_and_their_locks() {
        let mut v = Vfs::default();
        let _ = v.mkdir_at(AT_FDCWD, b"/tmp", 0o1777);
        v.mkdir_at(AT_FDCWD, b"/tmp/.X11-unix", 0o1777).unwrap();
        let address = |n| format!("\x01\x00/tmp/.X11-unix/X{n}\x00").into_bytes();
        let dead = v.new_local(1).unwrap();
        v.local_bind(&dead, &address(0)).unwrap();
        drop(dead);
        let live = v.new_local(1).unwrap();
        v.local_bind(&live, &address(1)).unwrap();
        v.import_file(b"/tmp/.X0-lock", b"4".to_vec()).unwrap();
        v.import_file(b"/tmp/.X1-lock", b"5".to_vec()).unwrap();
        v.import_file(b"/tmp/.X11-unix/X2", b"user file".to_vec())
            .unwrap();
        v.import_file(b"/tmp/.X2-lock", b"6".to_vec()).unwrap();
        let _server = v.enable_wayland(b"/run/user/0").unwrap();
        assert_eq!(v.stat_at(AT_FDCWD, b"/tmp/.X11-unix/X0"), Err(Errno(2)));
        assert_eq!(v.stat_at(AT_FDCWD, b"/tmp/.X0-lock"), Err(Errno(2)));
        for path in [
            b"/tmp/.X11-unix/X1".as_slice(),
            b"/tmp/.X1-lock",
            b"/tmp/.X11-unix/X2",
            b"/tmp/.X2-lock",
        ] {
            assert!(v.stat_at(AT_FDCWD, path).is_ok());
        }
    }
}
