// SPDX-License-Identifier: GPL-3.0-or-later
//! Addressed AF_UNIX datagrams use the existing endpoint queue and wait epochs.
use super::*;

impl Vfs {
    pub fn local_sender_credentials(&self) -> [u32; 3] {
        [self.lock_owner, self.credentials.uid, self.credentials.gid]
    }

    pub fn local_send_to(
        &self,
        socket: &Rc<LocalSocket>,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: LocalRights,
    ) -> Result<usize> {
        self.local_send_credentials(
            socket,
            bytes,
            flags,
            destination,
            rights,
            self.local_sender_credentials(),
        )
    }
    pub fn local_send_credentials(
        &self,
        socket: &Rc<LocalSocket>,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: LocalRights,
        credentials: [u32; 3],
    ) -> Result<usize> {
        if socket.kind != 2 || socket.channel.borrow().ends()[0].strong_count() != 0 {
            if destination.is_some() {
                return Err(Errno(106));
            }
            return socket.send_rights_credentials(bytes, flags, rights, credentials);
        }
        socket.check_datagram_send(bytes.len(), flags)?;
        let target = self.local_datagram_core(&socket.core, destination)?;
        target.send_owner_checked(&self.local_rights, bytes, flags, rights, credentials)
    }
}

/// One accepted send's resolved target. The queue/source notification remains
/// available after target close; this capability does not keep its endpoint open.
#[derive(Clone)]
pub struct LocalDatagram {
    source: Arc<LocalResource>,
    peer: std::sync::Weak<LocalResource>,
    channel: Arc<Channel>,
}
impl LocalDatagram {
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.channel.resource.readiness.subscribe(signal)
    }
    pub fn shares_resources(&self, fds: &DirectFds) -> bool {
        let peer = self.peer.upgrade();
        fds.1.as_ref().is_some_and(|files| {
            files.byte_descriptions().iter().any(|file| {
                file.open.local.as_ref().is_some_and(|core| {
                    Arc::ptr_eq(core, &self.source)
                        || peer.as_ref().is_some_and(|peer| Arc::ptr_eq(core, peer))
                })
            })
        })
    }
    fn receiver(&self) -> Result<Arc<LocalResource>> {
        let peer = self.peer.upgrade().ok_or(Errno(111))?;
        peer.check_datagram_sender(&self.source)?;
        Ok(peer)
    }
    fn send_shared_checked(
        &self,
        bytes: &[u8],
        flags: u32,
        rights: SharedRights,
        identity: [u32; 3],
    ) -> Result<usize> {
        let receiver = self.receiver()?;
        let source = self.source.name.borrow().clone();
        self.channel.resource.send_addressed(
            bytes,
            flags,
            shared_rights::QueuedRights::for_receiver(&receiver, rights)?,
            identity,
            source,
        )
    }
    fn send_owner_checked(
        &self,
        owner: &OwnerLedger,
        bytes: &[u8],
        flags: u32,
        rights: LocalRights,
        credentials: [u32; 3],
    ) -> Result<usize> {
        let peer = self.receiver()?;
        if let Some(shared) = rights.shared() {
            let source = self.source.name.borrow().clone();
            return self.channel.resource.send_addressed(
                bytes,
                flags,
                shared_rights::QueuedRights::for_receiver(&peer, shared)?,
                credentials,
                source,
            );
        }
        let graph = ownership::Ownership::legacy(&peer, &rights)?;
        let channel = &self.channel;
        let id = channel
            .next_right
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Errno(75))?;
        owner.insert(channel, 0, id, Ancillary { rights });
        let source = self.source.name.borrow().clone();
        let result = channel.resource.send_addressed(
            bytes,
            flags,
            Some(shared_rights::QueuedRights::legacy(id, graph)),
            credentials,
            source,
        );
        if result.is_err() {
            let unused = owner.remove(channel, id);
            drop(unused);
        }
        result
    }
}

impl LocalSocket {
    pub(super) fn send_connected_rights(
        &self,
        bytes: &[u8],
        flags: u32,
        rights: LocalRights,
        identity: [u32; 3],
    ) -> Result<usize> {
        self.check_datagram_send(bytes.len(), flags)?;
        if !self.connected() {
            return Err(Errno(89));
        }
        let peer = self.datagram_peer.borrow().upgrade().ok_or(Errno(111))?;
        let channel = peer.channel.borrow().clone();
        let target = LocalDatagram {
            source: self.core.clone(),
            peer: Arc::downgrade(&peer),
            channel,
        };
        target.send_owner_checked(&self.owner, bytes, flags, rights, identity)
    }
}

impl LocalResource {
    fn check_datagram_sender(&self, source: &LocalResource) -> Result<()> {
        if self.connected() {
            let expected = self.datagram_peer.borrow().upgrade();
            if !expected
                .as_ref()
                .is_some_and(|expected| std::ptr::eq(&**expected, source))
            {
                return Err(Errno(1));
            }
        }
        Ok(())
    }
    pub(crate) fn send_connected_datagram(
        &self,
        bytes: &[u8],
        flags: u32,
        identity: Option<[u32; 3]>,
    ) -> Result<usize> {
        self.check_datagram_send(bytes.len(), flags)?;
        if !self.connected() {
            return Err(Errno(89));
        }
        let peer = self.datagram_peer.borrow().upgrade().ok_or(Errno(111))?;
        peer.check_datagram_sender(self)?;
        let source = self.name.borrow().clone();
        let channel = peer.channel.borrow().clone();
        channel.resource.send_addressed(
            bytes,
            flags,
            None,
            identity.unwrap_or_else(|| self.credentials.get()),
            source,
        )
    }
    pub(crate) fn addressed_datagram(&self) -> bool {
        self.kind == 2 && self.channel.paired.get().is_none()
    }
    fn check_datagram_send(&self, length: usize, flags: u32) -> Result<()> {
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if length > self.buffer_size(false) {
            return Err(Errno(90));
        }
        if self.channel.borrow().resource.send_check(0, flags).is_err() {
            return Err(Errno(32));
        }
        Ok(())
    }
    pub(crate) fn datagram_resource(&self) -> Arc<channel::Resource> {
        self.channel.borrow().resource.clone()
    }
}
impl LocalOperation {
    pub fn send_connected_datagram(
        &self,
        bytes: &[u8],
        flags: u32,
        identity: Option<[u32; 3]>,
    ) -> Result<usize> {
        self.core().send_connected_datagram(bytes, flags, identity)
    }
    fn datagram_admit<'a>(
        &self,
        target: &'a std::sync::OnceLock<LocalDatagram>,
        length: usize,
        flags: u32,
        resolve: impl FnOnce() -> Option<Result<LocalDatagram>>,
    ) -> Option<Result<&'a LocalDatagram>> {
        if let Err(error) = self.check_datagram_send(length, flags) {
            return Some(Err(error));
        }
        if target.get().is_none() {
            match resolve()? {
                Ok(prepared) => {
                    let _ = target.set(prepared);
                }
                Err(error) => return Some(Err(error)),
            }
        }
        Some(Ok(target.get().expect("accepted datagram target")))
    }
    pub fn send_datagram(
        &self,
        target: &std::sync::OnceLock<LocalDatagram>,
        bytes: &[u8],
        flags: u32,
        rights: SharedRights,
        identity: [u32; 3],
        resolve: impl FnOnce() -> Option<Result<LocalDatagram>>,
    ) -> Option<Result<usize>> {
        Some(
            self.datagram_admit(target, bytes.len(), flags, resolve)?
                .and_then(|target| target.send_shared_checked(bytes, flags, rights, identity)),
        )
    }
}
impl Vfs {
    pub(crate) fn local_datagram_core(
        &self,
        socket: &Arc<LocalResource>,
        destination: Option<&[u8]>,
    ) -> Result<LocalDatagram> {
        let peer = if let Some(name) = destination {
            self.local_destination_core(socket, name)?
        } else if socket.connected() {
            socket.datagram_peer.borrow().upgrade().ok_or(Errno(111))?
        } else {
            return Err(Errno(89));
        };
        let channel = peer.channel.borrow().clone();
        Ok(LocalDatagram {
            source: socket.clone(),
            peer: Arc::downgrade(&peer),
            channel,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn send_datagram_owned(
        &self,
        socket: &LocalOperation,
        target: &std::sync::OnceLock<LocalDatagram>,
        bytes: &[u8],
        flags: u32,
        destination: Option<&[u8]>,
        rights: LocalRights,
        identity: [u32; 3],
    ) -> Result<usize> {
        socket
            .datagram_admit(target, bytes.len(), flags, || {
                Some(self.local_datagram_core(socket.core(), destination))
            })
            .expect("owner resolves datagram target")?
            .send_owner_checked(&self.local_rights, bytes, flags, rights, identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addressed_metadata_and_portable_rights_live_in_the_real_queue_without_owner_entries() {
        let mut v = Vfs::default();
        v.set_lock_owner(42);
        let tx = v.local_create(2, 0).unwrap();
        let rx = v.local_create(2, 0).unwrap();
        let sender = v.local_socket(tx).unwrap().unwrap();
        let receiver = v.local_socket(rx).unwrap().unwrap();
        let name = b"\x01\x00\0datagram-source";
        let destination = b"\x01\x00\0datagram-target";
        v.local_bind(&sender, name).unwrap();
        v.local_bind(&receiver, destination).unwrap();
        receiver.set_reuse(35, 1).unwrap();
        let event = v.eventfd(73, 0).unwrap();
        v.local_send_to(
            &sender,
            b"abcd",
            0,
            Some(destination),
            v.send_rights(&[event]).unwrap(),
        )
        .unwrap();
        assert!(v.local_rights.entries.borrow().is_empty());
        // Datagram credentials were always captured at send, even if passcred
        // was enabled after enqueue. Keep that behavior outside the ledger.
        receiver.set_reuse(16, 1).unwrap();
        v.close(event).unwrap();
        let fd = v.direct_descriptors().get(rx).unwrap();
        let received =
            std::thread::spawn(move || fd.recv_local_message(2, 2 | 0x20).unwrap().unwrap())
                .join()
                .unwrap();
        assert_eq!(received.data, b"ab");
        assert_eq!(received.length, 4);
        assert!(received.truncated);
        assert_eq!(received.source, name);
        assert_eq!(received.credentials, Some([42, 0, 0]));
        assert_eq!(received.timestamp.unwrap().0, 35);
        let (aliases, truncated) =
            v.descriptor_factory()
                .receive_local_rights(received.rights, 1, true);
        assert!(!truncated);
        assert_eq!(v.read(aliases[0], 8).unwrap(), 73u64.to_le_bytes());
        assert_ne!(v.flags(aliases[0]).unwrap() & O_CLOEXEC, 0);
        assert_eq!(receiver.recv(9, 0).unwrap().data, b"abcd");
        assert!(v.local_rights.entries.borrow().is_empty());
        v.local_connect(&sender, destination).unwrap();
        sender.send(b"core", 0).unwrap();
        assert_eq!(receiver.recv(9, 0).unwrap().data, b"core");
        sender
            .send_rights(b"owner-api", 0, LocalRights::default())
            .unwrap();
        assert_eq!(receiver.recv(9, 0).unwrap().data, b"owner-api");
        assert_eq!(
            v.direct_descriptors().get(tx).unwrap().write(b"direct"),
            Ok(6)
        );
        assert_eq!(receiver.recv(9, 0).unwrap().data, b"direct");
    }
    #[test]
    fn concurrent_addressed_senders_keep_each_packets_source_identity_and_boundary() {
        let mut v = Vfs::default();
        let rx = v.local_create(2, 0).unwrap();
        let receiver = v.local_socket(rx).unwrap().unwrap();
        let destination = b"\x01\x00\0parallel-datagrams";
        v.local_bind(&receiver, destination).unwrap();
        receiver.set_reuse(16, 1).unwrap();
        let mut jobs = Vec::new();
        for n in 0..8u8 {
            let tx = v.local_create(2, 0).unwrap();
            let sender = v.local_socket(tx).unwrap().unwrap();
            let name = [b"\x01\x00\0source-".as_slice(), &[n]].concat();
            v.local_bind(&sender, &name).unwrap();
            let op = v.descriptor_factory().local_operation(tx).unwrap().unwrap();
            let paths = v.path_queries();
            jobs.push(std::thread::spawn(move || {
                for j in 0..8u8 {
                    let target = std::sync::OnceLock::new();
                    assert_eq!(
                        op.send_datagram(
                            &target,
                            &[n, j],
                            0,
                            SharedRights::default(),
                            [n as u32 + 1, 0, 0],
                            || paths.local_datagram(&op, Some(destination))
                        ),
                        Some(Ok(2))
                    );
                }
            }));
        }
        for job in jobs {
            job.join().unwrap();
        }
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let received = receiver.recv(2, 0).unwrap();
            let n = received.data[0];
            assert_eq!(received.source.last().copied(), Some(n));
            assert_eq!(received.credentials, Some([n as u32 + 1, 0, 0]));
            assert!(seen.insert(received.data));
        }
        assert!(v.local_rights.entries.borrow().is_empty());
    }
}
