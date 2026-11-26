// SPDX-License-Identifier: GPL-3.0-or-later
//! Original Unix namespace/control operations shared by owner and workers.
use super::*;

/// Resolved target identity, independent of path rebinding. A waiting connect
/// must not keep the listener open; its original notification source stays live.
#[derive(Clone)]
pub struct LocalConnection {
    client: Arc<LocalResource>,
    peer: std::sync::Weak<LocalResource>,
    readiness: Arc<Readiness>,
    identity: [u32; 3],
}
impl LocalConnection {
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.readiness.subscribe(signal)
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        let peer = self.peer.upgrade();
        fds.1.as_ref().is_some_and(|files| {
            files.byte_descriptions().iter().any(|file| {
                file.open.local.as_ref().is_some_and(|core| {
                    Arc::ptr_eq(core, &self.client)
                        || peer.as_ref().is_some_and(|peer| Arc::ptr_eq(core, peer))
                })
            })
        })
    }
    pub fn attempt(&self) -> Result<()> {
        let transition = self.client.transition.lock().unwrap();
        self.client.check_connect()?;
        let peer = self.peer.upgrade().ok_or(Errno(111))?;
        if self.client.kind == 2 {
            *self.client.datagram_peer.borrow_mut() = Arc::downgrade(&peer);
            *self.client.peer_name.borrow_mut() = Some(peer.name.clone());
            self.client
                .datagram_connected
                .store(true, Ordering::Release);
            return Ok(());
        }
        let mut listener = peer.listener.borrow_mut();
        let l = listener.as_mut().ok_or(Errno(111))?;
        if l.pending.len() > l.backlog {
            return Err(Errno(11));
        }
        let accepted = LocalResource::allocate(
            self.client.kind,
            peer.credentials.get(),
            peer.network.clone(),
            peer.ownership.clone(),
            peer.domain.clone(),
        )?;
        self.client.credentials.set(self.identity);
        *accepted.name.borrow_mut() = peer.name.borrow().clone();
        *accepted.timeouts.borrow_mut() = *peer.timeouts.borrow();
        accepted.linger.set(peer.linger.get());
        accepted.set_reuse(16, peer.reuse(16))?;
        let timestamp = peer.timestamp.load(Ordering::Relaxed);
        if timestamp != 0 {
            accepted.set_reuse(timestamp, 1)?;
        }
        LocalResource::pair(&self.client, &accepted);
        // This client was already published before connect.
        FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
        l.pending.push_back(accepted);
        peer.listen_epoch.fetch_add(1, Ordering::Relaxed);
        drop(listener);
        drop(transition);
        peer.notify();
        self.client.notify();
        Ok(())
    }
}
impl LocalResource {
    fn check_connect(&self) -> Result<()> {
        if self.connected() && !self.addressed_datagram() {
            return Err(Errno(106));
        }
        if self.listening() {
            return Err(Errno(22));
        }
        Ok(())
    }
}
impl LocalOperation {
    pub(crate) fn core(&self) -> &Arc<LocalResource> {
        self.0.local.as_ref().expect("Unix OFD")
    }
    pub fn flags(&self) -> u32 {
        self.0.flags.get()
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.core().subscribe(signal)
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        fds.1.as_ref().is_some_and(|files| {
            files
                .byte_descriptions()
                .iter()
                .any(|file| Arc::ptr_eq(&self.0, &file.open))
        })
    }
}
impl LocalNamespace {
    fn bind_abstract(&mut self, name: &[u8], socket: &Arc<LocalResource>) -> bool {
        let binding = self
            .abstract_names
            .entry((socket.kind, name.to_vec()))
            .or_default();
        if binding.strong_count() != 0 {
            return false;
        }
        *binding = Arc::downgrade(socket);
        true
    }
}
impl Vfs {
    pub(crate) fn local_bind_core(
        &mut self,
        socket: &Arc<LocalResource>,
        bytes: &[u8],
    ) -> Result<()> {
        let _binding = if let Some(query) = &self.query {
            match socket.bind_lock.try_enter() {
                Some(lease) => lease,
                None => return query.defer(),
            }
        } else {
            socket.bind_lock.enter()
        };
        self.local_bind_entered(socket, bytes)
    }
    pub(crate) fn local_bind_entered(
        &mut self,
        socket: &Arc<LocalResource>,
        bytes: &[u8],
    ) -> Result<()> {
        let _transition = socket.transition.lock().unwrap();
        if socket.name.borrow().len() != 2 {
            return Err(Errno(22));
        }
        let name = if bytes == [1, 0] {
            let mut ns = socket.namespace.borrow_mut();
            (0..1 << 20)
                .find_map(|_| {
                    let id = ns.next_autobind;
                    ns.next_autobind = (id + 1) & 0xfffff;
                    let mut name = vec![1, 0, 0];
                    name.extend_from_slice(format!("{id:05x}").as_bytes());
                    ns.bind_abstract(&name, socket).then_some(name)
                })
                .ok_or(Errno(28))?
        } else {
            let (name, abstract_) = Self::local_address(bytes)?;
            if abstract_ {
                if !socket.namespace.borrow_mut().bind_abstract(&name, socket) {
                    return Err(Errno(98));
                }
            } else {
                let (p, fuse) =
                    self.capture_fuse_path(AT_FDCWD, &name[2..name.len() - 1], false)?;
                if let Some(plan) = fuse {
                    return self.defer_fuse_namespace(
                        plan,
                        fuse::NamespaceAction::SocketBind {
                            socket: socket.clone(),
                            name,
                            bindings: self.path_bindings.clone(),
                        },
                        None,
                        landlock::MAKE_SOCK,
                    );
                }
                let trailing = name.last() == Some(&0) && name.get(name.len() - 2) == Some(&b'/');
                drop(_transition);
                return self.local_bind_resolved(socket, name, p, trailing);
            }
            name
        };
        socket.publish_bound_name(name);
        Ok(())
    }
    pub(crate) fn local_bind_resolved(
        &mut self,
        socket: &Arc<LocalResource>,
        name: Vec<u8>,
        path: ResolvedPath,
        trailing: bool,
    ) -> Result<()> {
        let _transition = socket.transition.lock().unwrap();
        if socket.name.borrow().len() != 2 {
            return Err(Errno(22));
        }
        match self.node(&path) {
            Ok(_) => return Err(Errno(98)),
            Err(Errno(2)) if trailing => return Err(Errno(2)),
            Err(Errno(2)) => {}
            Err(error) => return Err(error),
        }
        self.check_create_parent_write(&path)?;
        let mut binding = self.path_bindings.bind(socket);
        if let Some(mount) = &path.mount {
            binding.retain_mount(&mount.identity);
        }
        self.insert_entry(
            path,
            Content::Socket(binding.path()),
            0o140000 | (socket.inode_permissions.load(Ordering::Relaxed) & !self.umask()),
            true,
        )
        .map_err(|error| if error == Errno(17) { Errno(98) } else { error })?;
        let _ = socket.pathname_binding.set(binding);
        socket.publish_bound_name(name);
        Ok(())
    }
}
impl LocalResource {
    pub(crate) fn publish_fuse_binding(
        self: &Arc<Self>,
        bindings: &PathBindings,
        inode: NodeRef,
        name: Vec<u8>,
        mount: &Arc<mounts::MountIdentity>,
    ) {
        let mut binding = bindings.bind(self);
        inode.borrow_mut().content = Content::Socket(binding.path());
        binding.retain_inode(inode);
        binding.retain_mount(mount);
        let _ = self.pathname_binding.set(binding);
        self.publish_bound_name(name);
    }
    pub(crate) fn publish_bound_name(&self, name: Vec<u8>) {
        *self.name.borrow_mut() = name;
        // Packets queued before bind retain their original unbound address.
        // Future sends share a new immutable source snapshot.
        *self.datagram_source.borrow_mut() = None;
    }
}
impl Vfs {
    pub(crate) fn local_destination_core(
        &self,
        socket: &Arc<LocalResource>,
        bytes: &[u8],
    ) -> Result<Arc<LocalResource>> {
        let (name, abstract_) = Self::local_address(bytes)?;
        let peer = if abstract_ {
            socket
                .namespace
                .borrow()
                .abstract_names
                .get(&(socket.kind, name))
                .and_then(std::sync::Weak::upgrade)
                .ok_or(Errno(111))?
        } else {
            let p = self.resolve_final(-100, &name[2..name.len() - 1], true)?;
            let node = self.node(&p)?;
            let n = node.borrow();
            if !self.allowed_on(&n, 2, &p) {
                return Err(Errno(13));
            }
            let Content::Socket(peer) = &n.content else {
                return Err(Errno(111));
            };
            self.path_bindings.resolve(peer).ok_or(Errno(111))?
        };
        if peer.kind != socket.kind {
            return Err(Errno(91));
        }
        if abstract_
            && !self
                .credentials
                .landlock
                .allows_scope(&peer.domain, landlock::ABSTRACT_UNIX_SOCKET)
            && !(socket.kind == 2
                && std::sync::Weak::ptr_eq(&socket.datagram_peer.borrow(), &Arc::downgrade(&peer)))
        {
            return Err(Errno(1));
        }
        Ok(peer)
    }
    pub(crate) fn local_connection_core(
        &self,
        socket: &Arc<LocalResource>,
        bytes: &[u8],
        identity: [u32; 3],
    ) -> Result<LocalConnection> {
        let _transition = socket.transition.lock().unwrap();
        socket.check_connect()?;
        let peer = self.local_destination_core(socket, bytes)?;
        let readiness = peer.channel.borrow().resource.readiness.clone();
        Ok(LocalConnection {
            client: socket.clone(),
            peer: Arc::downgrade(&peer),
            readiness,
            identity,
        })
    }
    pub fn local_connection_operation(
        &self,
        socket: &LocalOperation,
        bytes: &[u8],
        identity: [u32; 3],
    ) -> Result<LocalConnection> {
        self.local_connection_core(socket.core(), bytes, identity)
    }
    pub fn local_bind_operation(&mut self, socket: &LocalOperation, bytes: &[u8]) -> Result<()> {
        self.local_bind_core(socket.core(), bytes)
    }
}
impl DescriptorFactory {
    pub fn local_peer_identity(&self) -> [u32; 3] {
        [
            self.local_sender_credentials()[0],
            self.local_credentials().euid,
            self.local_credentials().egid,
        ]
    }
    /// The selected peer address and its preflight belong to the same queue
    /// item. No output fault can publish an FD; notifications leave queue locks.
    pub fn accept_local_output<C, P>(
        &self,
        socket: &LocalResource,
        flags: u32,
        context: &mut C,
        prepare: impl FnOnce(&mut C, usize) -> Result<P>,
        output: impl FnOnce(&mut C, P, &[u8]) -> Result<()>,
    ) -> Result<(u32, Vec<u8>)> {
        let (descriptor, name, prepared) =
            self.prepare_accept_local(socket, flags, context, prepare)?;
        output(context, prepared, &name)?;
        Ok((descriptor.publish()?, name))
    }
    pub fn prepare_accept_local<C, P>(
        &self,
        socket: &LocalResource,
        flags: u32,
        context: &mut C,
        prepare: impl FnOnce(&mut C, usize) -> Result<P>,
    ) -> Result<(PreparedDescriptor, Vec<u8>, P)> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        if socket.kind == 2 {
            return Err(Errno(95));
        }
        let mut listener = socket.listener.borrow_mut();
        let pending = &mut listener.as_mut().ok_or(Errno(22))?.pending;
        let front = pending.front().ok_or(Errno(11))?;
        let name = front.peer_address();
        let prepared = prepare(context, name.len())?;
        let reserved = self.files.reserve()?;
        let accepted = pending.pop_front().expect("selected accepted endpoint");
        socket.listen_epoch.fetch_add(1, Ordering::Relaxed);
        drop(listener);
        socket.notify();
        let credentials = self.local_credentials();
        let descriptor = Vfs::local_description(
            self.open_id(),
            (credentials.fsuid, credentials.fsgid),
            accepted,
            flags,
        );
        Ok((
            PreparedDescriptor {
                reservation: reserved,
                descriptor,
            },
            name,
            prepared,
        ))
    }
}
