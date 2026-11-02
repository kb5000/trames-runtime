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
            *self.client.peer_name.borrow_mut() = peer.name.borrow().clone();
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
        )?;
        self.client.credentials.set(self.identity);
        *accepted.name.borrow_mut() = peer.name.borrow().clone();
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
        if self.connected() {
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
impl Vfs {
    pub(crate) fn local_bind_core(
        &mut self,
        socket: &Arc<LocalResource>,
        bytes: &[u8],
    ) -> Result<()> {
        let _transition = socket.transition.lock().unwrap();
        let (name, abstract_) = Self::local_address(bytes)?;
        if socket.name.borrow().len() != 2 {
            return Err(Errno(22));
        }
        if abstract_ {
            let mut ns = socket.namespace.borrow_mut();
            if ns
                .abstract_names
                .get(&name)
                .and_then(std::sync::Weak::upgrade)
                .is_some()
            {
                return Err(Errno(98));
            }
            ns.abstract_names
                .insert(name.clone(), Arc::downgrade(socket));
        } else {
            let p = self.resolve_final(-100, &name[2..name.len() - 1], false)?;
            match self.node(&p) {
                Ok(_) => return Err(Errno(98)),
                Err(Errno(2)) => {}
                Err(e) => return Err(e),
            }
            self.check_parent_write(&p)?;
            let binding = self.path_bindings.bind(socket);
            // Search/insert must not overwrite another concurrent binder.
            self.insert_entry(
                p,
                Content::Socket(binding.path()),
                0o140000 | (0o777 & !self.umask()),
                true,
            )
            .map_err(|error| if error == Errno(17) { Errno(98) } else { error })?;
            let _ = socket.pathname_binding.set(binding);
        }
        *socket.name.borrow_mut() = name;
        Ok(())
    }
    pub(super) fn local_destination_core(
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
                .get(&name)
                .and_then(std::sync::Weak::upgrade)
                .ok_or(Errno(111))?
        } else {
            let p = self.resolve_final(-100, &name[2..name.len() - 1], true)?;
            let node = self.node(&p)?;
            let n = node.borrow();
            if !self.allowed(&n, 2) {
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
        let mut listener = socket.listener.borrow_mut();
        let pending = &mut listener.as_mut().ok_or(Errno(22))?.pending;
        let front = pending.front().ok_or(Errno(11))?;
        let name = front.peer_name.borrow().clone();
        let prepared = prepare(context, name.len())?;
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        let reserved = self.files.reserve()?;
        let accepted = pending.pop_front().expect("selected accepted endpoint");
        socket.listen_epoch.fetch_add(1, Ordering::Relaxed);
        drop(listener);
        socket.notify();
        output(context, prepared, &name)?;
        let credentials = self.local_credentials();
        let descriptor = Vfs::local_description(
            self.open_id(),
            (credentials.fsuid, credentials.fsgid),
            accepted,
            flags,
        );
        Ok((reserved.publish(descriptor, None), name))
    }
}
