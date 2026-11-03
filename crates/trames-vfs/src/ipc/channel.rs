// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared AF_UNIX bytes/state. Rights are opaque tokens, resolved only by the
//! owning VFS thread; no Rc, guest pointer or descriptor table crosses here.
use super::super::*;
use super::shared_rights::{QueuedRights, SharedRights};
use crate::readiness::Readiness;
use std::sync::Mutex;

struct Packet {
    data: Vec<u8>,
    rights: Option<QueuedRights>,
    credentials: Option<[u32; 3]>,
    timestamp: Option<[u64; 2]>,
    source: Vec<u8>,
}
struct Data {
    queues: [VecDeque<Packet>; 2],
    used: [usize; 2],
    alive: [bool; 2],
    read_closed: [bool; 2],
    write_closed: [bool; 2],
    epochs: [[u64; 2]; 2],
    passcred: [bool; 2],
    timestamp: [u32; 2],
    send_limit: [usize; 2],
    receive_limit: [usize; 2],
}
pub(crate) struct Received {
    pub data: Vec<u8>,
    pub length: usize,
    pub truncated: bool,
    pub(super) rights: Option<QueuedRights>,
    pub credentials: Option<[u32; 3]>,
    pub timestamp: Option<[u64; 2]>,
    pub source: Vec<u8>,
    pub(super) options: [u32; 2],
}
pub(crate) struct Resource {
    pub(super) ends: [std::sync::Weak<super::LocalResource>; 2],
    kind: u32,
    data: Mutex<Data>,
    pub readiness: Arc<Readiness>,
}
impl Resource {
    pub(super) fn alive(&self, side: usize) -> bool {
        self.data.lock().unwrap().alive[side]
    }
    pub fn kind(&self) -> u32 {
        self.kind
    }
    pub fn new(kind: u32, connected: bool) -> Arc<Self> {
        Self::with_readiness(kind, connected, Arc::default())
    }
    pub(super) fn with_readiness(
        kind: u32,
        connected: bool,
        readiness: Arc<Readiness>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ends: Default::default(),
            kind,
            data: Mutex::new(Data {
                queues: [VecDeque::new(), VecDeque::new()],
                used: [0; 2],
                alive: [connected || kind == 2; 2],
                read_closed: [false; 2],
                write_closed: [false; 2],
                epochs: [[0; 2]; 2],
                passcred: [false; 2],
                timestamp: [0; 2],
                send_limit: [
                    PIPE_CAPACITY,
                    if kind == 2 && !connected {
                        usize::MAX
                    } else {
                        PIPE_CAPACITY
                    },
                ],
                receive_limit: [PIPE_CAPACITY; 2],
            }),
            readiness,
        })
    }
    // Notifications must leave the channel lock before entering the run queue.
    fn change<T>(&self, f: impl FnOnce(&mut Data) -> T) -> T {
        let mut data = self.data.lock().unwrap();
        let before = data.epochs;
        let result = f(&mut data);
        let changed = before != data.epochs;
        drop(data);
        if changed {
            self.readiness.notify_locked();
        }
        result
    }
    pub fn readable_bytes(&self, side: usize) -> usize {
        let data = self.data.lock().unwrap();
        if self.kind == 2 {
            data.queues[side].front().map_or(0, |p| p.data.len())
        } else {
            data.used[side]
        }
    }
    pub fn set_passcred(&self, side: usize, enabled: bool) {
        self.data.lock().unwrap().passcred[side] = enabled;
    }
    pub fn set_timestamp(&self, side: usize, mode: u32) {
        self.data.lock().unwrap().timestamp[side] = mode;
    }
    pub fn buffer_size(&self, side: usize, receive: bool) -> usize {
        let data = self.data.lock().unwrap();
        if receive {
            data.receive_limit[side]
        } else {
            data.send_limit[side]
        }
    }
    pub(super) fn inherit_options(&self, side: usize, original: &Resource, from: usize) {
        let values = {
            let data = original.data.lock().unwrap();
            (
                data.send_limit[from],
                data.receive_limit[from],
                data.passcred[from],
                data.timestamp[from],
            )
        };
        let mut data = self.data.lock().unwrap();
        data.send_limit[side] = values.0;
        data.receive_limit[side] = values.1;
        data.passcred[side] = values.2;
        data.timestamp[side] = values.3;
    }
    pub(super) fn set_buffer_unnotified(&self, side: usize, receive: bool, requested: u32) {
        let bytes = (u64::from(requested) * 2)
            .clamp(if receive { 256 } else { 2048 }, i32::MAX as u64) as usize;
        let mut data = self.data.lock().unwrap();
        if receive {
            data.receive_limit[side] = bytes;
        } else {
            data.send_limit[side] = bytes;
        }
        data.epochs[side][1] = data.epochs[side][1].wrapping_add(1);
        data.epochs[1 - side][1] = data.epochs[1 - side][1].wrapping_add(1);
    }
    pub fn shutdown(&self, side: usize, how: u32) -> Result<()> {
        if how > 2 {
            return Err(Errno(22));
        }
        self.change(|data| {
            if how != 1 {
                data.read_closed[side] = true;
            }
            if how != 0 {
                data.write_closed[side] = true;
            }
            for epoch in &mut data.epochs {
                for counter in epoch {
                    *counter = counter.wrapping_add(1);
                }
            }
        });
        Ok(())
    }
    pub fn close(&self, side: usize) -> Vec<u64> {
        let packets = self.change(|data| {
            data.alive[side] = false;
            data.used[side] = 0;
            for counter in &mut data.epochs[1 - side] {
                *counter = counter.wrapping_add(1);
            }
            std::mem::take(&mut data.queues[side])
        });
        // Rights can run final-close callbacks; never drop them under Data.
        packets
            .into_iter()
            .filter_map(|p| p.rights.as_ref().and_then(QueuedRights::owner))
            .collect()
    }
    pub fn send_check(&self, side: usize, flags: u32) -> Result<()> {
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        self.data.lock().unwrap().send_check(side, self.kind)
    }
    pub fn send_credentials(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: Option<u64>,
        identity: Option<[u32; 3]>,
    ) -> Result<usize> {
        self.send_ancillary(
            side,
            bytes,
            flags,
            rights.map(QueuedRights::Owner),
            identity,
            Vec::new(),
        )
    }
    pub(super) fn send_shared(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: SharedRights,
        identity: Option<[u32; 3]>,
    ) -> Result<usize> {
        let rights = if rights.owns_unix() {
            self.send_check(side, flags)?;
            let receiver = self.ends[1 - side]
                .upgrade()
                .ok_or(Errno(if self.kind == 2 { 111 } else { 32 }))?;
            QueuedRights::for_receiver(&receiver, rights)?
        } else {
            (!rights.is_empty()).then_some(QueuedRights::Shared(rights))
        };
        self.send_ancillary(side, bytes, flags, rights, identity, Vec::new())
    }
    pub(super) fn send_addressed(
        &self,
        bytes: &[u8],
        flags: u32,
        rights: Option<QueuedRights>,
        identity: [u32; 3],
        source: Vec<u8>,
    ) -> Result<usize> {
        self.send_ancillary(1, bytes, flags, rights, Some(identity), source)
    }
    pub(super) fn send_ancillary(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: Option<QueuedRights>,
        identity: Option<[u32; 3]>,
        source: Vec<u8>,
    ) -> Result<usize> {
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        self.change(|data| {
            data.send_check(side, self.kind)?;
            if self.kind == 1 && bytes.is_empty() {
                return Ok(0);
            }
            let peer = 1 - side;
            let credentials = if data.passcred[peer] || !source.is_empty() {
                Some(identity.ok_or(Errno(95))?)
            } else {
                None
            };
            let timestamp = (data.timestamp[peer] != 0).then(|| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                [now.as_secs(), u64::from(now.subsec_nanos())]
            });
            let queue = &mut data.queues[peer];
            if self.kind != 1 && bytes.len() > data.send_limit[side] {
                return Err(Errno(90));
            }
            let room = data.send_limit[side]
                .min(data.receive_limit[peer])
                .saturating_sub(data.used[peer]);
            if (self.kind != 1 && (room < bytes.len() || queue.len() >= 128))
                || (self.kind == 1 && room == 0 && !bytes.is_empty())
            {
                return Err(Errno(11));
            }
            let count = room.min(bytes.len());
            let merge = self.kind == 1
                && rights.is_none()
                && queue.back().is_some_and(|p| {
                    p.rights.is_none() && p.credentials == credentials && p.timestamp == timestamp
                });
            if !merge && queue.len() >= 128 {
                return Err(Errno(11));
            }
            if merge && count != 0 {
                queue
                    .back_mut()
                    .expect("stream queue")
                    .data
                    .extend_from_slice(&bytes[..count]);
            } else if count != 0 || self.kind != 1 {
                queue.push_back(Packet {
                    data: bytes[..count].to_vec(),
                    rights: rights.clone(),
                    credentials,
                    timestamp,
                    source,
                });
            }
            data.used[peer] += count;
            data.epochs[peer][0] = data.epochs[peer][0].wrapping_add(1);
            Ok(count)
        })
    }
    /// None is before effects for actual owner-only rights. Shared metadata is
    /// returned outside Data, including when a raw byte read discards rights.
    pub fn recv(
        &self,
        side: usize,
        count: usize,
        flags: u32,
        allow_rights: bool,
    ) -> Option<Result<Received>> {
        self.recv_mode(side, count, flags, if allow_rights { 2 } else { 0 })
    }
    pub(crate) fn recv_portable(
        &self,
        side: usize,
        count: usize,
        flags: u32,
    ) -> Option<Result<Received>> {
        self.recv_mode(side, count, flags, 1)
    }
    fn recv_mode(
        &self,
        side: usize,
        count: usize,
        flags: u32,
        mode: u8,
    ) -> Option<Result<Received>> {
        if flags & !(2 | 0x20 | 0x40 | 0x100 | 0x4000 | 0x40000000) != 0 {
            return Some(Err(Errno(95)));
        }
        if self.kind == 1 && flags & 0x100 != 0 && flags & 0x40 == 0 && count > PIPE_CAPACITY {
            return Some(Err(Errno(95)));
        }
        self.change(|data| {
            let options = [u32::from(data.passcred[side]), data.timestamp[side]];
            let peer = 1 - side;
            let eof = data.read_closed[side] || !data.alive[peer] || data.write_closed[peer];
            let queue = &mut data.queues[side];
            if (self.kind == 1 && count == 0) || (eof && queue.is_empty() && self.kind != 2) {
                return Some(Ok(Received {
                    data: Vec::new(),
                    length: 0,
                    truncated: false,
                    rights: None,
                    credentials: None,
                    timestamp: None,
                    source: Vec::new(),
                    options,
                }));
            }
            if queue.is_empty() {
                return Some(Err(Errno(11)));
            }
            if self.kind != 1 {
                let packet = queue.front().expect("packet");
                if mode == 1 && packet.rights.as_ref().is_some_and(|r| r.owner().is_some())
                    || mode == 0
                        && (packet.rights.is_some()
                            || packet.credentials.is_some()
                            || packet.timestamp.is_some())
                {
                    return None;
                }
                let length = packet.data.len();
                let out = Received {
                    data: packet.data[..count.min(length)].to_vec(),
                    length,
                    truncated: count < length,
                    rights: packet.rights.clone(),
                    credentials: packet.credentials,
                    timestamp: packet.timestamp,
                    source: packet.source.clone(),
                    options,
                };
                if flags & 2 == 0 {
                    queue.pop_front();
                    data.used[side] -= length;
                    data.epochs[peer][1] = data.epochs[peer][1].wrapping_add(1);
                }
                return Some(Ok(out));
            }
            let mut bytes = Vec::new();
            let mut rights = None;
            let credentials = queue.front().and_then(|p| p.credentials);
            let timestamp = queue.front().and_then(|p| p.timestamp);
            for packet in queue.iter() {
                if packet.credentials != credentials || packet.timestamp != timestamp {
                    break;
                }
                if mode == 0 && (packet.credentials.is_some() || packet.timestamp.is_some()) {
                    return None;
                }
                let n = (count - bytes.len()).min(packet.data.len());
                bytes.extend_from_slice(&packet.data[..n]);
                if packet.rights.is_some() {
                    // A plain prefix ending before the rights-bearing packet
                    // can complete locally. Crossing its boundary defers the
                    // entire call before any queue or guest-memory effects.
                    if mode == 0
                        || mode == 1 && packet.rights.as_ref().is_some_and(|r| r.owner().is_some())
                    {
                        return None;
                    }
                    rights = packet.rights.clone();
                    break;
                }
                if bytes.len() == count {
                    break;
                }
            }
            if flags & 2 == 0 {
                if flags & 0x100 != 0
                    && flags & 0x40 == 0
                    && !eof
                    && bytes.len() < count
                    && rights.is_none()
                {
                    return Some(Err(Errno(11)));
                }
                let mut remaining = bytes.len();
                while remaining != 0 {
                    let packet = queue.front_mut().expect("stream bytes");
                    let n = remaining.min(packet.data.len());
                    packet.data.drain(..n);
                    packet.rights = None;
                    remaining -= n;
                    if packet.data.is_empty() {
                        queue.pop_front();
                    }
                }
                data.used[side] -= bytes.len();
                if !bytes.is_empty() {
                    data.epochs[peer][1] = data.epochs[peer][1].wrapping_add(1);
                }
            }
            let length = bytes.len();
            Some(Ok(Received {
                data: bytes,
                length,
                truncated: false,
                rights,
                credentials,
                timestamp,
                source: Vec::new(),
                options,
            }))
        })
    }
    pub fn poll(&self, side: usize, events: u16) -> (u16, [u64; 2]) {
        let data = self.data.lock().unwrap();
        let peer = 1 - side;
        let eof = data.read_closed[side] || !data.alive[peer] || data.write_closed[peer];
        let queue = &data.queues[side];
        let send_queue = &data.queues[peer];
        let room = data.send_limit[side]
            .min(data.receive_limit[peer])
            .saturating_sub(data.used[peer]);
        let ready = (if !queue.is_empty() || (eof && self.kind != 2) {
            events & 1
        } else {
            0
        }) | (if room != 0
            && (send_queue.len() < 128
                || self.kind == 1 && send_queue.back().is_some_and(|p| p.rights.is_none()))
        {
            events & 4
        } else {
            0
        }) | (if eof && self.kind != 2 {
            events & 0x2000
        } else {
            0
        }) | (if !data.alive[peer] || (eof && data.write_closed[side]) {
            16
        } else {
            0
        });
        (ready, data.epochs[side])
    }
}
impl Data {
    fn send_check(&self, side: usize, kind: u32) -> Result<()> {
        if self.write_closed[side] {
            return Err(Errno(32));
        }
        if !self.alive[1 - side] {
            return Err(Errno(if kind == 2 { 111 } else { 32 }));
        }
        if self.read_closed[1 - side] {
            return Err(Errno(32));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_survive_partial_reads_and_cached_worker_capabilities() {
        let mut vfs = Vfs::default();
        let [a, b] = vfs.socketpair(1, 1, 0).unwrap();
        let direct = vfs.direct_descriptors();
        let tx = direct.get(a).unwrap();
        let rx = direct.get(b).unwrap();
        let receiver = vfs.local_socket(b).unwrap().unwrap();
        receiver.set_reuse(16, 1).unwrap();
        assert_eq!(
            tx.send_credentials(b"abc", 0, Some([42, 1000, 1001])),
            Ok(3)
        );
        assert_eq!(
            tx.send_credentials(b"def", 0, Some([43, 1002, 1003])),
            Ok(3)
        );
        assert_eq!(rx.recv_local_message(9, 2).unwrap().unwrap().data, b"abc");
        let first = receiver.recv(1, 0).unwrap();
        assert_eq!(first.data, b"a");
        assert_eq!(first.credentials, Some([42, 1000, 1001]));
        let rest = receiver.recv(9, 0).unwrap();
        assert_eq!(rest.data, b"bc");
        assert_eq!(rest.credentials, first.credentials);
        let next = receiver.recv(9, 0).unwrap();
        assert_eq!(next.data, b"def");
        assert_eq!(next.credentials, Some([43, 1002, 1003]));
        tx.send_credentials(b"raw", 0, Some([44, 1003, 1004]))
            .unwrap();
        assert_eq!(rx.read_attempt(9).unwrap().unwrap(), b"raw");
        assert_eq!(tx.send(b"missing-identity", 0), Err(Errno(95)));
        assert_eq!(vfs.readable_bytes(b), Ok(Some(0)));
    }
    #[test]
    fn worker_and_owner_share_bytes_offsets_and_shutdown_without_endpoint_leases() {
        let mut vfs = Vfs::default();
        let [a, b] = vfs.socketpair(1, 1, 0).unwrap();
        let snapshot = vfs.direct_descriptors();
        let tx = DirectFd::snapshot(&vfs.descriptor(a).unwrap().open.borrow()).unwrap();
        let rx = DirectFd::snapshot(&vfs.descriptor(b).unwrap().open.borrow()).unwrap();
        assert_eq!(tx.write(b"abc"), Ok(3));
        assert_eq!(vfs.readable_bytes(b), Ok(Some(3)));
        assert_eq!(vfs.read(b, 1).unwrap(), b"a");
        vfs.write(a, b"def").unwrap();
        assert_eq!(rx.recv_local_message(9, 2).unwrap().unwrap().data, b"bcdef");
        assert_eq!(rx.readable_bytes(), 5);
        assert_eq!(rx.read(2).unwrap(), b"bc");
        assert_eq!(vfs.read(b, 9).unwrap(), b"def");
        vfs.close(a).unwrap();
        // Retaining the capability is not another open socket endpoint.
        assert_eq!(rx.read(1), Ok(Vec::new()));
        assert_eq!(rx.send(b"x", 0x4000), Err(Errno(32)));
        assert_ne!(vfs.poll(b, 0x2001) & 16, 0);
        assert!(snapshot.get(a).is_none());
    }
    #[test]
    fn shared_rights_keep_original_peek_and_partial_delivery_on_workers() {
        let mut vfs = Vfs::default();
        let [a, b] = vfs.socketpair(1, 1, 0).unwrap();
        let [reader, writer] = vfs.pipe(0).unwrap();
        let snapshot = vfs.direct_descriptors();
        let sender = vfs.local_socket(a).unwrap().unwrap();
        sender.send(b"prefix", 0).unwrap();
        sender
            .send_rights(b"abc", 0, vfs.send_rights(&[writer]).unwrap())
            .unwrap();
        snapshot.get(a).unwrap().write(b"def").unwrap();
        let rx = snapshot.get(b).unwrap();
        assert_eq!(rx.read_attempt(3).unwrap().unwrap(), b"pre");
        assert_eq!(
            rx.recv_local_message(8, 2).unwrap().unwrap().data,
            b"fixabc"
        );
        assert_eq!(rx.read_attempt(3).unwrap().unwrap(), b"fix");
        assert_eq!(rx.recv_local_message(2, 2).unwrap().unwrap().data, b"ab");
        assert_eq!(vfs.readable_bytes(b), Ok(Some(6)));
        let receiver = vfs.local_socket(b).unwrap().unwrap();
        let peek = receiver.recv(2, 2).unwrap();
        assert_eq!(peek.data, b"ab");
        assert!(!peek.rights.is_empty());
        drop(peek);
        assert_eq!(rx.recv_local_message(2, 2).unwrap().unwrap().data, b"ab");
        let received = receiver.recv(1, 0).unwrap();
        assert_eq!(received.data, b"a");
        let (fds, truncated) = vfs.receive_rights(received.rights, 1, false);
        assert_eq!(fds.len(), 1);
        assert!(!truncated);
        assert_eq!(rx.read_attempt(9).unwrap().unwrap(), b"bcdef");
        vfs.close(writer).unwrap();
        vfs.write(fds[0], b"alive").unwrap();
        assert_eq!(vfs.read(reader, 9).unwrap(), b"alive");
    }
    #[test]
    fn concurrent_stream_writers_preserve_records_and_bounded_backpressure() {
        let mut vfs = Vfs::default();
        let [a, b] = vfs.socketpair(1, 1 | O_NONBLOCK, 0).unwrap();
        let snapshot = vfs.direct_descriptors();
        std::thread::scope(|scope| {
            for writer in 0..4u64 {
                let tx = snapshot.get(a).unwrap();
                scope.spawn(move || {
                    for i in 0..128u64 {
                        assert_eq!(tx.write(&((writer << 32) | i).to_le_bytes()), Ok(8));
                    }
                });
            }
        });
        let bytes = vfs.read(b, PIPE_CAPACITY).unwrap();
        let mut records: Vec<_> = bytes
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect();
        records.sort_unstable();
        assert_eq!(
            records,
            (0..4u64)
                .flat_map(|w| (0..128u64).map(move |i| w << 32 | i))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            snapshot.get(a).unwrap().write(&vec![7; PIPE_CAPACITY + 1]),
            Ok(PIPE_CAPACITY)
        );
        assert_eq!(snapshot.get(a).unwrap().write(b"x"), Err(Errno(11)));
        assert_eq!(vfs.read(b, 1).unwrap(), [7]);
        assert_eq!(snapshot.get(a).unwrap().write(b"xy"), Ok(1));
    }
    #[test]
    fn connect_and_last_close_refresh_shared_fd_and_epoll_snapshots() {
        let mut vfs = Vfs::default();
        let listener = vfs.local_create(1, 0).unwrap();
        let server = vfs.local_socket(listener).unwrap().unwrap();
        vfs.local_bind(&server, b"\x01\x00\0worker-local-connect")
            .unwrap();
        vfs.local_listen(&server, 1).unwrap();
        let client = vfs.local_create(1, 0).unwrap();
        let old = vfs.direct_descriptors();
        assert!(old.get(client).unwrap().is_poll_only());
        assert!(!old.get(client).unwrap().is_unix());
        let socket = vfs.local_socket(client).unwrap().unwrap();
        vfs.local_connect(&socket, b"\x01\x00\0worker-local-connect")
            .unwrap();
        let (accepted, _) = vfs.local_accept(&server, 0).unwrap();
        assert!(vfs.direct_descriptors().get(client).unwrap().is_unix());
        let ep = vfs.epoll_create(0).unwrap();
        vfs.epoll_ctl(ep, 1, accepted, 1, 55).unwrap();
        let mut child = vfs.clone();
        child.close(accepted).unwrap();
        let cached = child.direct_descriptors();
        vfs.write(client, b"x").unwrap();
        assert_eq!(cached.get(ep).unwrap().epoll_wait(1).unwrap(), [(1, 55)]);
        vfs.close(accepted).unwrap();
        assert!(child
            .direct_descriptors()
            .get(ep)
            .unwrap()
            .epoll_wait(1)
            .unwrap()
            .is_empty());
    }
}
