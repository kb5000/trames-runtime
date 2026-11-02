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
        if socket.kind != 2 || socket.channel.borrow().ends[0].strong_count() != 0 {
            if destination.is_some() {
                return Err(Errno(106));
            }
            return socket.send_rights_credentials(bytes, flags, rights, credentials);
        }
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        if bytes.len() > socket.buffer_size(false) {
            return Err(Errno(90));
        }
        if socket
            .channel
            .borrow()
            .resource
            .send_check(0, flags)
            .is_err()
        {
            return Err(Errno(32));
        }
        let peer = if let Some(name) = destination {
            self.local_destination(socket, name)?
        } else if socket.connected() {
            LocalSocket::view(
                socket.datagram_peer.borrow().upgrade().ok_or(Errno(111))?,
                self.local_rights.clone(),
            )
        } else {
            return Err(Errno(89));
        };
        // A connected receiver accepts only its selected sender.
        if peer.connected()
            && !peer
                .datagram_peer
                .borrow()
                .upgrade()
                .is_some_and(|expected| Arc::ptr_eq(&expected, &socket.core))
        {
            return Err(Errno(1));
        }
        // The rights graph stays in the VFS owner domain. Queues hold opaque
        // IDs and the same bounded data/resource lock as paired Unix sockets.
        let mut pending: Vec<_> = rights
            .0
            .iter()
            .filter_map(|open| open.borrow().local.clone())
            .collect();
        let mut visited = std::collections::BTreeSet::new();
        while let Some(endpoint) = pending.pop() {
            if Arc::ptr_eq(&endpoint, &peer.core) {
                return Err(Errno(95));
            }
            if !visited.insert(Arc::as_ptr(&endpoint) as usize) {
                continue;
            }
            let channel = endpoint.channel.borrow();
            let ledger = self.local_rights.entries.borrow();
            for id in channel.resource.right_ids(endpoint.side()) {
                for open in &ledger
                    .get(&(Arc::as_ptr(&channel) as usize, id))
                    .expect("queued metadata")
                    .data
                    .rights
                    .0
                {
                    if let Some(local) = &open.borrow().local {
                        pending.push(local.clone());
                    }
                }
            }
        }
        let channel = peer.channel.borrow();
        let id = channel
            .next_right
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Errno(75))?;
        self.local_rights.insert(
            &channel,
            0,
            id,
            Ancillary {
                rights,
                credentials: Some(credentials),
                source: socket.name.borrow().clone(),
            },
        );
        let result =
            channel
                .resource
                .send_credentials(1, bytes, flags, Some(id), Some(credentials));
        if result.is_err() {
            let unused = self.local_rights.remove(&channel, id);
            drop(unused);
        }
        result
    }
}
