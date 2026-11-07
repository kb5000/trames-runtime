// SPDX-License-Identifier: GPL-3.0-or-later
//! Event-driven shared adapters between guest AF_UNIX and native services.
//! Native threads receive only bytes, owned host FDs and host resource leases.
use super::*;
use std::{
    io::{self, Read, Write},
    os::fd::OwnedFd,
};
use trames_shared::{NativeSocket, SharedFile, MAX_BYTES_OUT, MAX_FDS_OUT};
use trames_wayland::Server;

/// A live descriptor authority, not an epoch's copied grants. Resolving accepts
/// one original OFD before native work; closed/reused slots cannot redirect it.
#[derive(Clone, Default)]
pub struct WaylandAuth {
    source: Option<(SharedFiles, std::sync::Weak<Services>)>,
}
pub struct WaylandGrant {
    server: Server,
    token: u64,
    _file: SharedFd,
}
impl WaylandGrant {
    pub fn connection(&self) -> (Server, u64) {
        (self.server.clone(), self.token)
    }
}
impl WaylandAuth {
    /// A namespace switch changes Files lookup, never the native service root.
    pub fn with_files(&self, files: SharedFiles) -> Self {
        Self {
            source: self
                .source
                .as_ref()
                .map(|(_, services)| (files, services.clone())),
        }
    }
    pub fn resolve(&self, fd: u32) -> Result<WaylandGrant> {
        let (files, services) = self.source.as_ref().ok_or(Errno(95))?;
        let services = services.upgrade().ok_or(Errno(95))?;
        let file = files.query_lookup(fd).unwrap_or(Err(Errno(95)))?;
        let token = if let Some(socket) = &file.open.local {
            services
                .registry
                .lock()
                .unwrap()
                .connections
                .iter()
                .find(|c| {
                    !c.xwm && Arc::ptr_eq(&c.local.channel.borrow(), &socket.channel.borrow())
                })
                .map(|c| c.token)
                .ok_or(Errno(9))?
        } else {
            let flags = file.open.flags.get();
            if flags & O_PATH != 0 || flags & 3 == 1 {
                return Err(Errno(9));
            }
            let node = file.open.node.as_ref().ok_or(Errno(19))?.borrow();
            let Content::File(data) = &node.content else {
                return Err(Errno(19));
            };
            let shared = data.shared_file().ok_or(Errno(95))?;
            let key = shared.key();
            drop(node);
            services
                .server
                .snapshot()
                .wsi_connections
                .get(&key)
                .ok_or(Errno(11))?
                .connection
        };
        Ok(WaylandGrant {
            server: services.server.clone(),
            token,
            _file: file,
        })
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
    rights: SharedRights,
    done: usize,
}
struct Connection {
    local: Arc<LocalResource>,
    native: NativeSocket,
    token: u64,
    owner: (u32, u32),
    outgoing: Option<Outgoing>,
    incoming: Option<Incoming>,
    command_wait: Option<IoSubscription>,
    exports: Vec<(trames_shared::ExportLease, IoSubscription)>,
    relays: Vec<PipeRelay>,
    read: Interest,
    write: Interest,
}
// Endpoint ownership is shared; inode metadata remains an owner projection.
// Keeping that anchor preserves the original unlink/inotify/node lifetime.
struct PipeRelay {
    host: trames_shared::NativePipe,
    guest: Arc<PipeEndpoint>,
    _metadata: Option<NodeRef>,
    to_native: bool,
    interest: Interest,
    subscription: Option<IoSubscription>,
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
            interest: Interest { subscription: None },
            subscription: None,
        }
    }
    fn pump(&mut self) -> bool {
        let mut pipe = self.guest.data.lock().unwrap();
        if self.to_native {
            if pipe.read_reserved {
                return true;
            }
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
            let room = pipe.write_room().min(16384);
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
struct Binding {
    path: Vec<u8>,
    local: Arc<LocalResource>,
    xwm: bool,
    _subscription: IoSubscription,
}
#[derive(Default)]
struct Registry {
    bindings: Vec<Binding>,
    connections: Vec<Arc<Bridge>>,
}
/// Only registry membership is shared across connections. Transport progress,
/// partial messages and resource destruction belong to the connection itself.
pub(crate) struct Services {
    me: std::sync::Weak<Services>,
    server: Server,
    importer: Importer,
    log: Arc<kernel_log::KernelLog>,
    events: Arc<HostEvents>,
    signal: Arc<IoSignal>,
    host_signal: Arc<IoSignal>,
    accepting: std::sync::Mutex<()>,
    registry: std::sync::Mutex<Registry>,
    executor: std::sync::Mutex<Option<(Arc<HostEvents>, HostSubscription)>>,
}
#[derive(Clone)]
struct Importer {
    fs: FsHandle,
    ids: Arc<AtomicU64>,
}
struct Bridge {
    local: Arc<LocalResource>,
    token: u64,
    xwm: bool,
    services: std::sync::Weak<Services>,
    signal: Arc<IoSignal>,
    _guest: IoSubscription,
    state: std::sync::Mutex<Option<Connection>>,
}
struct Interest {
    subscription: Option<HostSubscription>,
}
impl Interest {
    fn update(
        &mut self,
        needed: bool,
        fd: impl std::os::fd::AsFd,
        write: bool,
        events: &Arc<HostEvents>,
        signal: &Arc<IoSignal>,
    ) -> Result<()> {
        if !needed {
            self.subscription = None;
        } else if let Some(subscription) = &self.subscription {
            subscription.rearm().map_err(io_errno)?;
        } else {
            self.subscription = Some(
                events
                    .subscribe(
                        fd.as_fd().try_clone_to_owned().map_err(io_errno)?,
                        write,
                        signal,
                    )
                    .map_err(io_errno)?,
            );
        }
        Ok(())
    }
}
fn io_errno(e: io::Error) -> Errno {
    match e.kind() {
        io::ErrorKind::WouldBlock => Errno(11),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => Errno(32),
        _ => storage::host_errno(e),
    }
}
impl SharedOpenDescription {
    fn pipe_description(id: u64, owner: (u32, u32), pipe: Pipe, write: bool) -> Arc<Self> {
        Arc::new(Self {
            console: Default::default(),
            oom: None,
            network_control: None,
            mount_file: None,
            runtime_file: None,
            socket: None,
            _disk_file: None,
            #[cfg(all(feature = "hostfs", unix))]
            host_file: None,
            native_image: None,
            mount_resource: std::sync::OnceLock::new(),
            mount_use: Default::default(),
            directory_mount: Default::default(),
            namespace_resource: None,
            file_authority: Default::default(),
            tcp_publication: Default::default(),
            socket_control: None,
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
            ofd_records: Default::default(),
            pipe: Some(PipeEnd::new(pipe, !write, write, None)),
            pty: None,
            local: None,
            node: None,
            bridge: None,
            kernel_log: None,
            notification: None,
        })
    }
}
impl Services {
    fn new(vfs: &Vfs, server: Server) -> Result<Arc<Self>> {
        let events = HostEvents::new().map_err(io_errno)?;
        Ok(Arc::new_cyclic(|me: &std::sync::Weak<Self>| Self {
            me: me.clone(),
            server,
            importer: Importer {
                fs: vfs.fs.clone(),
                ids: vfs.next_open.clone(),
            },
            log: vfs.kernel_log.clone(),
            events,
            signal: IoSignal::new(0, me.clone()),
            host_signal: IoSignal::new(1, me.clone()),
            accepting: std::sync::Mutex::new(()),
            registry: std::sync::Mutex::default(),
            executor: std::sync::Mutex::default(),
        }))
    }
    fn accept(self: &Arc<Self>) {
        loop {
            let Ok(guard) = self.accepting.try_lock() else {
                return;
            };
            loop {
                self.signal.reset();
                let bindings: Vec<_> = self
                    .registry
                    .lock()
                    .unwrap()
                    .bindings
                    .iter()
                    .map(|b| (b.local.clone(), b.xwm))
                    .collect();
                for (listener, xwm) in bindings {
                    let pending: Vec<_> = listener
                        .listener
                        .borrow_mut()
                        .as_mut()
                        .map(|l| l.pending.drain(..).collect())
                        .unwrap_or_default();
                    if !pending.is_empty() {
                        listener.listen_epoch.fetch_add(1, Ordering::Relaxed);
                        listener.notify();
                    }
                    for local in pending {
                        if self.registry.lock().unwrap().connections.len() >= 64 {
                            continue;
                        }
                        let [pid, uid, gid] = local.peer_credentials.get();
                        let connected = if xwm {
                            self.server
                                .connect_xwm(pid, uid, gid)
                                .map(|socket| (0, socket))
                        } else {
                            self.server.connect(pid, uid, gid)
                        };
                        if let Ok((token, socket)) = connected {
                            let bridge =
                                Bridge::new(self, local, token, xwm, (uid, gid), socket.into());
                            {
                                let mut registry = self.registry.lock().unwrap();
                                registry.connections.push(bridge.clone());
                            }
                            bridge.drive();
                        }
                    }
                }
                if !self.signal.ready() {
                    break;
                }
            }
            drop(guard);
            // A notification may have failed try_lock just before unlock.
            if !self.signal.ready() {
                break;
            }
        }
    }
    fn remove(&self, bridge: &Bridge) {
        let retired = {
            let mut registry = self.registry.lock().unwrap();
            let Some(index) = registry
                .connections
                .iter()
                .position(|b| std::ptr::eq(b.as_ref(), bridge))
            else {
                return;
            };
            registry.connections.swap_remove(index)
        };
        drop(retired);
    }
    fn dispatch(&self) {
        let _ = self.events.wait(Some(std::time::Instant::now()));
    }
}
impl IoWake for Services {
    fn wake_io(&self, signal: &Arc<IoSignal>) {
        if Arc::ptr_eq(signal, &self.signal) {
            if let Some(me) = self.me.upgrade() {
                me.accept();
            }
        } else {
            self.host_signal.reset();
            self.dispatch();
            if let Some((_, subscription)) = self.executor.lock().unwrap().as_ref() {
                let _ = subscription.rearm();
            }
        }
    }
}
impl trames_shared::ReadinessDriver for Services {
    fn attach(&self, events: Arc<HostEvents>) -> io::Result<()> {
        let mut executor = self.executor.lock().unwrap();
        if executor
            .as_ref()
            .is_some_and(|(current, _)| Arc::ptr_eq(current, &events))
        {
            return Ok(());
        }
        let subscription = events.subscribe(self.events.event_fd()?, false, &self.host_signal)?;
        let previous = executor.replace((events, subscription));
        drop(executor);
        drop(previous);
        Ok(())
    }
}
impl Bridge {
    fn new(
        services: &Arc<Services>,
        local: Arc<LocalResource>,
        token: u64,
        xwm: bool,
        owner: (u32, u32),
        native: NativeSocket,
    ) -> Arc<Self> {
        let bridge = Arc::new_cyclic(|me: &std::sync::Weak<Self>| {
            let signal = IoSignal::new(0, me.clone());
            Self {
                _guest: local.subscribe(&signal),
                local: local.clone(),
                token,
                xwm,
                services: Arc::downgrade(services),
                signal,
                state: std::sync::Mutex::new(Some(Connection {
                    local: local.clone(),
                    native,
                    token,
                    owner,
                    outgoing: None,
                    incoming: None,
                    command_wait: None,
                    exports: Vec::new(),
                    relays: Vec::new(),
                    read: Interest { subscription: None },
                    write: Interest { subscription: None },
                })),
            }
        });
        let driver: Arc<dyn trames_shared::ReadinessDriver> = services.clone();
        local
            .channel
            .borrow()
            .resource
            .readiness
            .set_driver(Arc::downgrade(&driver));
        bridge
    }
    fn drive(&self) {
        loop {
            let Ok(mut state) = self.state.try_lock() else {
                return;
            };
            let Some(services) = self.services.upgrade() else {
                return;
            };
            let mut failed = None;
            loop {
                self.signal.reset();
                let Some(connection) = state.as_mut() else {
                    break;
                };
                if let Err(error) = connection.pump(&services, &self.signal) {
                    failed = Some(error);
                    break;
                }
                if !self.signal.ready() {
                    break;
                }
            }
            let retired = failed.and_then(|error| {
                if error.0 != 32 {
                    services.log.append(
                        4,
                        &format!("wayland bridge connection={} errno={}", self.token, error.0),
                    );
                }
                state.take()
            });
            drop(state);
            if retired.is_some() {
                services.remove(self);
                // Last endpoint/pipe/FD release can re-enter the same bridge.
                drop(retired);
                return;
            }
            if !self.signal.ready() {
                return;
            }
        }
    }
}
impl IoWake for Bridge {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.drive();
    }
}
impl Connection {
    fn pump(&mut self, services: &Arc<Services>, signal: &Arc<IoSignal>) -> Result<bool> {
        let server = &services.server;
        let importer = &services.importer;
        let mut progress = false;
        self.relays.retain_mut(|relay| {
            let before = relay.guest.data.lock().unwrap().bytes.len();
            let alive = relay.pump();
            progress |= !alive || relay.guest.data.lock().unwrap().bytes.len() != before;
            alive
        });
        self.exports.retain(|(lease, _)| !lease.claimed());
        for _ in 0..16 {
            if self.outgoing.is_none() {
                if self.exports.len() >= 64 {
                    break;
                }
                match self
                    .local
                    .channel
                    .borrow()
                    .resource
                    .recv_local(self.local.side(), MAX_BYTES_OUT, 0x40)
                    .unwrap_or(Err(Errno(95)))
                {
                    Ok(packet) if packet.data.is_empty() => return Err(Errno(32)),
                    Ok(packet) => {
                        if packet.rights.len() > MAX_FDS_OUT {
                            return Err(Errno(90));
                        }
                        let exported = packet
                            .rights
                            .iter()
                            .map(|open| {
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
                        Ok(()) => self.exports.extend(packet.leases.drain(..).map(|lease| {
                            let subscription = lease.subscribe(signal);
                            (lease, subscription)
                        })),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if self.command_wait.is_none() {
                                self.command_wait = Some(server.subscribe_commands(signal));
                                continue; // subscribe, then retry once before waiting
                            }
                            break;
                        }
                        Err(e) => return Err(io_errno(e)),
                    }
                }
                self.command_wait = None;
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
                                let pipe = Pipe::new(importer.open_id());
                                let open = SharedOpenDescription::pipe_description(
                                    importer.open_id(),
                                    self.owner,
                                    pipe.clone(),
                                    true,
                                );
                                rights.push(open);
                                self.relays.push(PipeRelay::new(host, pipe, true, None));
                            } else {
                                rights.push(importer.file_description(fd, self.owner)?);
                            }
                        }
                        self.incoming = Some(Incoming {
                            bytes,
                            rights: SharedRights::new(rights, false),
                            done: 0,
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(io_errno(e)),
                }
            }
            let packet = self.incoming.as_mut().unwrap();
            match self.local.channel.borrow().resource.send_shared(
                self.local.side(),
                &packet.bytes[packet.done..],
                0x40,
                packet.rights.clone(),
                Some(self.local.credentials.get()),
            ) {
                Ok(0) => break,
                Ok(count) => {
                    packet.done += count;
                    packet.rights = SharedRights::default();
                    progress = true;
                    if packet.done == packet.bytes.len() {
                        self.incoming = None;
                    }
                }
                Err(Errno(11)) => break,
                Err(e) => return Err(e),
            }
        }
        self.read.update(
            self.incoming.is_none(),
            &self.native,
            false,
            &services.events,
            signal,
        )?;
        self.write.update(
            self.outgoing.as_ref().is_some_and(|p| p.registered),
            &self.native,
            true,
            &services.events,
            signal,
        )?;
        for relay in &mut self.relays {
            if relay.subscription.is_none() {
                relay.subscription = Some(relay.guest.data.readiness.subscribe(signal));
                let driver: Arc<dyn trames_shared::ReadinessDriver> = services.clone();
                relay
                    .guest
                    .data
                    .readiness
                    .set_driver(Arc::downgrade(&driver));
            }
            let pipe = relay.guest.data.lock().unwrap();
            let needed = if relay.to_native {
                !pipe.bytes.is_empty()
            } else {
                pipe.write_room() != 0
            };
            drop(pipe);
            relay.interest.update(
                needed,
                &relay.host,
                relay.to_native,
                &services.events,
                signal,
            )?;
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
                let services = Services::new(self, server)?;
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
                .registry
                .lock()
                .unwrap()
                .bindings
                .iter()
                .any(|binding| binding.path == path)
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
            let subscription = listener.subscribe(&services.signal);
            services.registry.lock().unwrap().bindings.push(Binding {
                path,
                local: listener.core.clone(),
                xwm,
                _subscription: subscription,
            });
        }
        let server = services.server.clone();
        Ok(server)
    }
    pub fn dispatch_native_events(&self) {
        let services = self.native_services.borrow().clone();
        if let Some(services) = services {
            services.dispatch();
        }
    }
    pub fn wayland_server(&self) -> Option<Server> {
        self.native_services
            .borrow()
            .as_ref()
            .map(|s| s.server.clone())
    }
    pub fn has_native_services(&self) -> bool {
        self.native_services
            .borrow()
            .as_ref()
            .is_some_and(|services| !services.registry.lock().unwrap().connections.is_empty())
    }
    /// Only the resource identity and live Files domain cross to a worker.
    pub fn wayland_auth(&self) -> WaylandAuth {
        WaylandAuth {
            source: self
                .native_services
                .borrow()
                .as_ref()
                .map(|services| (self.shared_files(), Arc::downgrade(services))),
        }
    }
    pub fn wayland_connection(&self, fd: u32) -> Result<WaylandGrant> {
        self.wayland_auth().resolve(fd)
    }
    pub fn native_service_event_fd(&self) -> Option<HostFd> {
        self.native_services
            .borrow()
            .as_ref()?
            .events
            .event_fd()
            .ok()
    }
}
impl Importer {
    fn open_id(&self) -> u64 {
        descriptor_factory::next_id(&self.ids)
    }
    fn file_description(
        &self,
        fd: OwnedFd,
        owner: (u32, u32),
    ) -> Result<Arc<SharedOpenDescription>> {
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
        fs.track_inode(&node)?;
        drop(fs);
        Ok(Arc::new(SharedOpenDescription {
            console: Default::default(),
            oom: None,
            network_control: None,
            mount_file: None,
            runtime_file: None,
            socket: None,
            _disk_file: None,
            #[cfg(all(feature = "hostfs", unix))]
            host_file: None,
            native_image: None,
            mount_resource: std::sync::OnceLock::new(),
            mount_use: Default::default(),
            directory_mount: Default::default(),
            namespace_resource: None,
            file_authority: Default::default(),
            tcp_publication: Default::default(),
            socket_control: None,
            control: None,
            read_node: None,
            id: self.open_id(),
            owner,
            kind: FdKind::Node(b"/memfd:wayland-resource".to_vec()),
            flags: (0).into(),
            file_position: Arc::default(),
            flock: std::sync::OnceLock::new(),
            ofd_records: Default::default(),
            node: Some(node),
            pipe: None,
            pty: None,
            local: None,
            bridge: None,
            kernel_log: None,
            notification: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Executor {
        events: Arc<HostEvents>,
        wakes: AtomicU64,
    }
    impl IoWake for Executor {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
        fn host_events(&self) -> Option<Arc<HostEvents>> {
            Some(self.events.clone())
        }
    }
    fn test_bridge(vfs: &mut Vfs, services: &Arc<Services>) -> (u32, Arc<Bridge>, NativeSocket) {
        let [guest, adapter] = vfs.socketpair(1, 1 | O_NONBLOCK, 0).unwrap();
        let local = vfs.local_socket(adapter).unwrap().unwrap().core.clone();
        vfs.close(adapter).unwrap();
        let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let bridge = Bridge::new(services, local, 1, false, (0, 0), socket.into());
        services
            .registry
            .lock()
            .unwrap()
            .connections
            .push(bridge.clone());
        bridge.drive();
        (guest, bridge, peer.into())
    }
    fn executor() -> (Arc<Executor>, Arc<dyn IoWake>) {
        let executor = Arc::new(Executor {
            events: HostEvents::new().unwrap(),
            wakes: AtomicU64::new(0),
        });
        (executor.clone(), executor)
    }
    fn wait_executor(executor: &Executor) {
        executor
            .events
            .wait(Some(
                std::time::Instant::now() + std::time::Duration::from_secs(2),
            ))
            .unwrap();
    }
    #[test]
    fn native_bridges_run_on_calling_workers_and_existing_idle_executor_without_owner_pump() {
        fn shared<T: Send + Sync>() {}
        shared::<Services>();
        shared::<Bridge>();
        let mut vfs = Vfs::default();
        let services = Services::new(&vfs, Server::new().unwrap()).unwrap();
        let (executor, target) = executor();
        let mut connections = Vec::new();
        let mut signals = Vec::new();
        let mut subscriptions = Vec::new();
        for pid in 1..=4 {
            let (fd, bridge, native) = test_bridge(&mut vfs, &services);
            let io = vfs.direct_descriptors().get(fd).unwrap().clone();
            let signal = IoSignal::new(pid, Arc::downgrade(&target));
            let subscribed = io.subscribe(&signal);
            assert!(subscribed.iter().any(IoSubscription::external));
            subscriptions.extend(subscribed);
            signals.push(signal);
            connections.push((fd, io, bridge, native));
        }
        // A stalled connection cannot hold up an unrelated connection's send.
        let busy = connections[0].2.state.lock().unwrap();
        std::thread::scope(|scope| {
            for (i, (_, io, _, _)) in connections.iter().enumerate() {
                scope.spawn(move || assert_eq!(io.write(&[i as u8; 64]), Ok(64)));
            }
        });
        let mut bytes = [0; 128];
        let mut rights = VecDeque::new();
        for (i, (_, _, _, native)) in connections.iter().enumerate().skip(1) {
            assert_eq!(native.rcv_msg(&mut bytes, &mut rights).unwrap(), 64);
            assert_eq!(&bytes[..64], &[i as u8; 64]);
        }
        drop(busy);
        connections[0].2.drive();
        assert_eq!(
            connections[0].3.rcv_msg(&mut bytes, &mut rights).unwrap(),
            64
        );
        for (i, (_, _, _, native)) in connections.iter().enumerate() {
            signals[i].reset();
            native.send_msg(&[i as u8 + 10; 64], &[]).unwrap();
        }
        wait_executor(&executor);
        for (i, (_, io, _, _)) in connections.iter().enumerate() {
            assert!(signals[i].ready());
            assert_eq!(io.read(64).unwrap(), vec![i as u8 + 10; 64]);
        }
        assert_eq!(services.registry.lock().unwrap().connections.len(), 4);
        for (fd, io, bridge, native) in connections {
            drop(io);
            vfs.close(fd).unwrap();
            // The byte capability owns no endpoint; registry removal is direct.
            assert!(bridge.state.lock().unwrap().is_none());
            assert_eq!(native.rcv_msg(&mut bytes, &mut rights).unwrap(), 0);
        }
        assert!(services.registry.lock().unwrap().connections.is_empty());
    }
    #[test]
    fn native_rights_and_clipboard_pipes_progress_without_owner_projections() {
        let mut vfs = Vfs::default();
        let services = Services::new(&vfs, Server::new().unwrap()).unwrap();
        let (fd, bridge, native) = test_bridge(&mut vfs, &services);
        let io = vfs.direct_descriptors().get(fd).unwrap().clone();
        let factory = vfs.descriptor_factory();
        let (executor, target) = executor();
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let _subscriptions = io.subscribe(&signal);
        let file = SharedFile::anonymous().unwrap();
        file.write_at(0, b"native inode").unwrap();
        native
            .send_msg(b"f", &[file.duplicate_fd().unwrap()])
            .unwrap();
        wait_executor(&executor);
        let packet = io.recv_local_message(1, 0).unwrap().unwrap();
        assert_eq!(packet.data, b"f");
        let (fds, truncated) = factory.receive_local_rights(packet.rights, 1, true);
        assert!(!truncated);
        assert_eq!(vfs.shared_file(fds[0]).unwrap().key(), file.key());
        assert_eq!(vfs.read(fds[0], 32).unwrap(), b"native inode");
        vfs.close(fds[0]).unwrap();
        // Export the same complete inode through worker SCM_RIGHTS.
        let carried = vfs.memfd_create(b"worker-native", 0).unwrap();
        vfs.write(carried, b"worker inode").unwrap();
        let rights = factory.send_local_rights(&[carried]).unwrap().unwrap();
        io.send_local_message(b"g", 0, &rights, [1, 0, 0])
            .unwrap()
            .unwrap();
        vfs.close(carried).unwrap();
        drop(rights);
        let mut bytes = [0; 64];
        let mut fds = VecDeque::new();
        assert_eq!(native.rcv_msg(&mut bytes, &mut fds).unwrap(), 1);
        let imported = SharedFile::import(fds.pop_front().unwrap()).unwrap();
        assert_eq!(imported.read_at(0, 64).unwrap(), b"worker inode");
        // Native writer -> guest reader: EOF and readiness are real pipe events.
        let [read, write] = vfs.pipe(O_NONBLOCK).unwrap();
        let rights = factory.send_local_rights(&[write]).unwrap().unwrap();
        io.send_local_message(b"p", 0, &rights, [1, 0, 0])
            .unwrap()
            .unwrap();
        vfs.close(write).unwrap();
        drop(rights);
        assert_eq!(native.rcv_msg(&mut bytes, &mut fds).unwrap(), 1);
        let mut host = trames_shared::NativePipe::import(fds.pop_front().unwrap()).unwrap();
        host.write_all(b"clipboard host").unwrap();
        wait_executor(&executor);
        assert_eq!(vfs.read(read, 64).unwrap(), b"clipboard host");
        drop(host);
        wait_executor(&executor);
        assert!(vfs.read(read, 1).unwrap().is_empty());
        // Guest writer -> native reader, including close after buffered bytes.
        let (mut reader, writer) = trames_shared::NativePipe::pair().unwrap();
        native.send_msg(b"q", &[writer.into_fd()]).unwrap();
        wait_executor(&executor);
        let packet = io.recv_local_message(1, 0).unwrap().unwrap();
        let (fds, _) = factory.receive_local_rights(packet.rights, 1, false);
        let writer = vfs.direct_descriptors().get(fds[0]).unwrap().clone();
        std::thread::spawn(move || assert_eq!(writer.write(b"clipboard guest"), Ok(15)))
            .join()
            .unwrap();
        vfs.close(fds[0]).unwrap();
        let n = reader.read(&mut bytes).unwrap();
        assert_eq!(&bytes[..n], b"clipboard guest");
        assert_eq!(reader.read(&mut bytes).unwrap(), 0);
        drop(io);
        vfs.close(fd).unwrap();
        assert!(bridge.state.lock().unwrap().is_none());
        assert!(services.registry.lock().unwrap().connections.is_empty());
    }

    #[test]
    fn native_bridge_rearms_real_backpressure_in_both_directions() {
        use std::os::fd::AsRawFd;
        let mut vfs = Vfs::default();
        let services = Services::new(&vfs, Server::new().unwrap()).unwrap();
        let (fd, bridge, native) = test_bridge(&mut vfs, &services);
        let io = vfs.direct_descriptors().get(fd).unwrap().clone();
        let (executor, target) = executor();
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let _subscriptions = io.subscribe(&signal);
        let size = 4096i32;
        let state = bridge.state.lock().unwrap();
        // SAFETY: scoped integer socket option on the live retained socket.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    state.as_ref().unwrap().native.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&size as *const i32).cast(),
                    std::mem::size_of_val(&size) as _,
                )
            },
            0
        );
        drop(state);
        let payload: Vec<_> = (0..PIPE_CAPACITY).map(|i| i as u8).collect();
        assert_eq!(io.write(&payload), Ok(payload.len()));
        assert!(bridge
            .state
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .outgoing
            .is_some());
        let mut received = Vec::new();
        let mut bytes = [0; MAX_BYTES_OUT];
        let mut rights = VecDeque::new();
        while received.len() < payload.len() {
            loop {
                match native.rcv_msg(&mut bytes, &mut rights) {
                    Ok(n) => {
                        assert!(n > 0);
                        received.extend_from_slice(&bytes[..n]);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    other => panic!("{other:?}"),
                }
            }
            if received.len() < payload.len() {
                wait_executor(&executor);
            }
        }
        assert_eq!(received, payload);
        // A full guest queue suppresses native read interest. Draining it on a
        // guest worker resumes the retained original packet before reading more.
        let packet = [0x6d; MAX_BYTES_OUT];
        for _ in 0..(PIPE_CAPACITY / MAX_BYTES_OUT + 1) {
            assert_eq!(native.send_msg(&packet, &[]).unwrap(), packet.len());
            wait_executor(&executor);
        }
        let state = bridge.state.lock().unwrap();
        assert!(state.as_ref().unwrap().incoming.is_some());
        assert!(state.as_ref().unwrap().read.subscription.is_none());
        drop(state);
        let reader = io.clone();
        let received = std::thread::spawn(move || {
            let mut received = Vec::new();
            while received.len() < PIPE_CAPACITY + MAX_BYTES_OUT {
                received.extend(reader.read(16384).unwrap());
            }
            received
        })
        .join()
        .unwrap();
        assert_eq!(received, vec![0x6d; PIPE_CAPACITY + MAX_BYTES_OUT]);
        let state = bridge.state.lock().unwrap();
        assert!(state.as_ref().unwrap().incoming.is_none());
        assert!(state.as_ref().unwrap().read.subscription.is_some());
    }
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
        let open = OpenHandle::Shared(SharedOpenDescription::pipe_description(
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
    fn live_wayland_authority_resolves_new_connections_and_never_retargets_a_grant() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<WaylandAuth>();
        send_sync::<WaylandGrant>();
        let mut vfs = Vfs::default();
        vfs.enable_wayland(b"/run/user/0").unwrap();
        let auth = vfs.wayland_auth();
        vfs.import_file(b"/wrong-mode", b"bytes".to_vec()).unwrap();
        for flags in [1, O_PATH] {
            let file = vfs.open_at(AT_FDCWD, b"/wrong-mode", flags, 0).unwrap();
            assert!(matches!(auth.resolve(file), Err(Errno(9))));
            vfs.close(file).unwrap();
        }
        let fd = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        assert!(auth.resolve(fd).is_err());
        let socket = vfs.local_socket(fd).unwrap().unwrap();
        vfs.local_connect(&socket, b"\x01\x00/run/user/0/wayland-0\0")
            .unwrap();
        let grant = auth.resolve(fd).unwrap();
        let token = grant.connection().1;
        assert!(token > 0);
        let alias = vfs.dup(fd, 0, false).unwrap();
        let pair = vfs.socketpair(1, 1, 0).unwrap();
        let copied = vfs.memfd_create(b"unregistered-wayland", 0).unwrap();
        vfs.write(copied, b"copied capability bytes").unwrap();
        for invalid in [pair[0], copied, u32::MAX] {
            assert!(auth.resolve(invalid).is_err());
        }
        let shared = vfs.clone_with_files(true).wayland_auth();
        std::thread::spawn(move || {
            assert_eq!(shared.resolve(alias).unwrap().connection().1, token)
        })
        .join()
        .unwrap();
        vfs.close(fd).unwrap();
        let replacement = vfs.eventfd(71, 0).unwrap();
        assert_eq!(replacement, fd);
        assert!(auth.resolve(fd).is_err());
        assert_eq!(grant.connection().1, token);
        assert!(Arc::ptr_eq(
            grant._file.open.local.as_ref().unwrap(),
            &socket.core
        ));
        assert_eq!(auth.resolve(alias).unwrap().connection().1, token);
        assert_eq!(vfs.read(fd, 8).unwrap(), 71u64.to_le_bytes());
    }
    #[test]
    fn one_live_authority_observes_connect_without_any_membership_refresh() {
        let mut vfs = Vfs::default();
        vfs.enable_wayland(b"/run/user/0").unwrap();
        let first = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        let second = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        let auth = vfs.wayland_auth();
        let address = b"\x01\x00/run/user/0/wayland-0\0";
        vfs.local_connect(&vfs.local_socket(first).unwrap().unwrap(), address)
            .unwrap();
        let token = auth.resolve(first).unwrap().connection().1;
        assert!(auth.resolve(second).is_err());
        let membership = vfs.shared_files().capture_identity();
        vfs.local_connect(&vfs.local_socket(second).unwrap().unwrap(), address)
            .unwrap();
        assert_eq!(vfs.shared_files().capture_identity(), membership);
        assert_eq!(auth.resolve(first).unwrap().connection().1, token);
        assert_ne!(auth.resolve(second).unwrap().connection().1, token);
    }
    #[test]
    fn live_authority_does_not_pin_unqueried_files_and_grant_keeps_only_accepted_ofd() {
        let mut vfs = Vfs::default();
        vfs.enable_wayland(b"/run/user/0").unwrap();
        let auth = vfs.wayland_auth();
        let before = vfs.memfd_available();
        let file = vfs.memfd_create(b"not-cached", 0).unwrap();
        vfs.truncate_fd(file, 16384).unwrap();
        vfs.write(file, &[31; 16384]).unwrap();
        assert!(vfs.memfd_available() < before);
        assert!(auth.resolve(file).is_err());
        vfs.close(file).unwrap();
        assert_eq!(vfs.memfd_available(), before);
        let fd = vfs.local_create(1 | O_NONBLOCK, 0).unwrap();
        vfs.local_connect(
            &vfs.local_socket(fd).unwrap().unwrap(),
            b"\x01\x00/run/user/0/wayland-0\0",
        )
        .unwrap();
        let grant = auth.resolve(fd).unwrap();
        let original = Arc::downgrade(&grant._file.open);
        vfs.close(fd).unwrap();
        let replacement = vfs.eventfd(29, 0).unwrap();
        assert_eq!(replacement, fd);
        assert!(original.upgrade().is_some());
        drop(grant);
        assert!(original.upgrade().is_none());
        assert!(auth.resolve(fd).is_err());
        assert_eq!(vfs.read(fd, 8).unwrap(), 29u64.to_le_bytes());
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
            vfs.dispatch_native_events();
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
        assert!(vfs.wayland_connection(fd).unwrap().connection().1 > 0);
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
