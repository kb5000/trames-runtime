// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared AF_UNIX bytes/state and original owning rights. No guest pointer or
//! mutable descriptor table crosses a queued message.
use super::super::*;
use super::shared_rights::{QueuedRights, SharedRights};
use crate::readiness::Readiness;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Mutex,
};

// Keep the queued record aligned for AArch64 vector loads/stores. Sender
// metadata replaces the old per-packet source Vec rather than enlarging it.
#[repr(align(16))]
struct Packet {
    data: Vec<u8>,
    rights: Option<QueuedRights>,
    credentials: Option<[u32; 3]>,
    timestamp: Option<[u64; 2]>,
    source: Option<DatagramCharge>,
}

// Only addressed datagrams need accounting shared across different receivers.
// A charge owns no endpoint or OFD: queued self-sends cannot create a cycle.
struct DatagramBudget {
    used: AtomicUsize,
    limit: AtomicUsize,
    epoch: AtomicU64,
    readiness: Arc<Readiness>,
}
pub(super) struct DatagramSource {
    budget: Arc<DatagramBudget>,
    name: Vec<u8>,
}
struct DatagramCharge {
    source: Arc<DatagramSource>,
    bytes: usize,
}
impl DatagramSource {
    fn charge(self: Arc<Self>, length: usize) -> Result<DatagramCharge> {
        // Even an empty packet consumes queue metadata. Ordinary paired queues
        // keep their existing single-lock accounting and need no atomic charge.
        let bytes = length + std::mem::size_of::<Packet>();
        self.budget
            .used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                (used < self.budget.limit.load(Ordering::Relaxed)).then_some(used + bytes)
            })
            .map_err(|_| Errno(11))?;
        Ok(DatagramCharge {
            source: self,
            bytes,
        })
    }
}
impl Drop for DatagramCharge {
    fn drop(&mut self) {
        self.source
            .budget
            .used
            .fetch_sub(self.bytes, Ordering::Relaxed);
        self.source.budget.epoch.fetch_add(1, Ordering::Relaxed);
        // The packet retires outside the receiving queue lock.
        self.source.budget.readiness.notify_locked();
    }
}
struct Data {
    queues: [VecDeque<Packet>; 2],
    used: [usize; 2],
    alive: [bool; 2],
    read_closed: [bool; 2],
    write_closed: [bool; 2],
    error: [u32; 2],
    epochs: [[u64; 2]; 2],
    passcred: [bool; 2],
    timestamp: [u32; 2],
    send_limit: [usize; 2],
    receive_limit: [usize; 2],
    receive_low_water: [usize; 2],
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
    datagram_budget: Option<Arc<DatagramBudget>>,
}
impl Resource {
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
            datagram_budget: (kind == 2 && !connected).then(|| {
                Arc::new(DatagramBudget {
                    used: AtomicUsize::new(0),
                    limit: AtomicUsize::new(PIPE_CAPACITY),
                    epoch: AtomicU64::new(0),
                    readiness: readiness.clone(),
                })
            }),
            ends: Default::default(),
            kind,
            data: Mutex::new(Data {
                queues: [VecDeque::new(), VecDeque::new()],
                used: [0; 2],
                alive: [connected || kind == 2; 2],
                read_closed: [false; 2],
                write_closed: [false; 2],
                error: [0; 2],
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
                receive_low_water: [1; 2],
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
    pub fn set_low_water(&self, side: usize, value: u32) {
        self.data.lock().unwrap().receive_low_water[side] = if (value as i32) < 0 {
            i32::MAX as usize
        } else {
            value.max(1) as usize
        };
    }
    pub fn low_water(&self, side: usize) -> u32 {
        self.data.lock().unwrap().receive_low_water[side] as u32
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
                data.receive_low_water[from],
            )
        };
        let mut data = self.data.lock().unwrap();
        data.send_limit[side] = values.0;
        data.receive_limit[side] = values.1;
        data.passcred[side] = values.2;
        data.timestamp[side] = values.3;
        data.receive_low_water[side] = values.4;
    }
    pub(super) fn set_buffer_unnotified(&self, side: usize, receive: bool, requested: u32) {
        // Linux clamps before doubling, including negative force requests.
        // No backing allocation is reserved by this observable socket hint.
        let bytes = (u64::from(requested) * 2)
            .clamp(if receive { 2304 } else { 2048 }, i32::MAX as u64) as usize;
        if !receive {
            if let Some(budget) = &self.datagram_budget {
                budget.limit.store(bytes, Ordering::Relaxed);
                budget.epoch.fetch_add(1, Ordering::Relaxed);
            }
        }
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
                if self.kind != 2 {
                    data.write_closed[1 - side] = true;
                }
            }
            if how != 0 {
                data.write_closed[side] = true;
                if self.kind != 2 {
                    data.read_closed[1 - side] = true;
                }
            }
            for epoch in &mut data.epochs {
                for counter in epoch {
                    *counter = counter.wrapping_add(1);
                }
            }
        });
        Ok(())
    }
    pub fn close(&self, side: usize) {
        self.close_mode(side, false);
    }
    pub(super) fn abort(&self, side: usize) {
        self.close_mode(side, true);
    }
    fn close_mode(&self, side: usize, reset: bool) {
        let packets = self.change(|data| {
            if self.kind != 2 && (reset || !data.queues[side].is_empty()) {
                data.error[1 - side] = 104;
            }
            data.alive[side] = false;
            data.read_closed[side] = true;
            data.write_closed[side] = true;
            if self.kind != 2 {
                // Shutdown/close publish the endpoint's own receive state.
                // Ordinary read/poll need not infer it again from the peer.
                data.read_closed[1 - side] = true;
                data.write_closed[1 - side] = true;
            }
            data.used[side] = 0;
            for counter in &mut data.epochs[1 - side] {
                *counter = counter.wrapping_add(1);
            }
            std::mem::take(&mut data.queues[side])
        });
        drop(packets); // Final close and owning-graph retirement run outside Data.
    }
    pub(super) fn take_error(&self, side: usize) -> u32 {
        std::mem::take(&mut self.data.lock().unwrap().error[side])
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
        identity: Option<[u32; 3]>,
    ) -> Result<usize> {
        self.send_ancillary(side, bytes, flags, None, identity, false)
    }
    pub(super) fn send_shared(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: SharedRights,
        identity: Option<[u32; 3]>,
    ) -> Result<usize> {
        self.send_shared_mode(side, bytes, flags, rights, identity, false)
    }
    pub(super) fn send_shared_mode(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: SharedRights,
        identity: Option<[u32; 3]>,
        explicit: bool,
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
        self.send_ancillary(side, bytes, flags, rights, identity, explicit)
    }
    pub(super) fn datagram_source(&self, name: Vec<u8>) -> Arc<DatagramSource> {
        Arc::new(DatagramSource {
            budget: self
                .datagram_budget
                .as_ref()
                .expect("addressed datagram")
                .clone(),
            name,
        })
    }
    pub fn outgoing_bytes(&self, side: usize) -> usize {
        self.datagram_budget.as_ref().map_or_else(
            || self.data.lock().unwrap().used[1 - side],
            |budget| budget.used.load(Ordering::Relaxed),
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_addressed(
        &self,
        bytes: &[u8],
        flags: u32,
        rights: Option<QueuedRights>,
        identity: [u32; 3],
        source: Arc<DatagramSource>,
        explicit: bool,
    ) -> Result<usize> {
        self.send_ancillary_charged::<true>(
            1,
            bytes,
            flags,
            rights,
            Some(identity),
            explicit,
            Some(source),
        )
    }
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_ancillary(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: Option<QueuedRights>,
        identity: Option<[u32; 3]>,
        explicit: bool,
    ) -> Result<usize> {
        if flags & !(0x40 | 0x4000 | 0x40000000) != 0 {
            return Err(Errno(95));
        }
        self.send_ancillary_charged::<false>(side, bytes, flags, rights, identity, explicit, None)
    }
    #[allow(clippy::too_many_arguments)]
    fn send_ancillary_charged<const ADDRESSED: bool>(
        &self,
        side: usize,
        bytes: &[u8],
        flags: u32,
        rights: Option<QueuedRights>,
        identity: Option<[u32; 3]>,
        explicit: bool,
        mut source: Option<Arc<DatagramSource>>,
    ) -> Result<usize> {
        debug_assert_eq!(flags & !(0x40 | 0x4000 | 0x40000000), 0);
        self.change(|data| {
            data.send_check(side, self.kind)?;
            if self.kind == 1 && bytes.is_empty() {
                return Ok(0);
            }
            let peer = 1 - side;
            let credentials = if explicit || data.passcred[side] || data.passcred[peer] {
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
            if self.kind != 1 && bytes.len() > data.send_limit[side].saturating_sub(32) {
                return Err(Errno(90));
            }
            // AF_UNIX flow control uses the sender's SO_SNDBUF. SO_RCVBUF is
            // observable but does not constrain the peer's write budget.
            let room = data.send_limit[side].saturating_sub(data.used[peer]);
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
                // Compile distinct paired/addressed entry points. Ordinary
                // streams and socketpairs never execute sender-budget code.
                let charge = if ADDRESSED {
                    Some(
                        source
                            .take()
                            .expect("addressed sender source")
                            .charge(count)?,
                    )
                } else {
                    None
                };
                queue.push_back(Packet {
                    data: bytes[..count].to_vec(),
                    rights: rights.clone(),
                    credentials,
                    timestamp,
                    source: charge,
                });
            }
            data.used[peer] += count;
            data.epochs[peer][0] = data.epochs[peer][0].wrapping_add(1);
            Ok(count)
        })
    }
    /// Ancillary data leaves Data before final-close callbacks. Plain byte
    /// projections may defer before consuming a packet requiring ancillary ABI.
    pub fn recv(
        &self,
        side: usize,
        count: usize,
        flags: u32,
        allow_rights: bool,
    ) -> Option<Result<Received>> {
        if self.datagram_budget.is_some() {
            self.recv_mode::<true>(side, count, flags, allow_rights, false)
        } else {
            self.recv_mode::<false>(side, count, flags, allow_rights, false)
        }
    }
    pub(crate) fn recv_portable(
        &self,
        side: usize,
        count: usize,
        flags: u32,
    ) -> Option<Result<Received>> {
        self.recv_mode::<true>(side, count, flags, true, false)
    }
    pub(crate) fn recv_paired_portable(
        &self,
        side: usize,
        count: usize,
        flags: u32,
    ) -> Option<Result<Received>> {
        self.recv_mode::<false>(side, count, flags, true, false)
    }
    pub(crate) fn recv_message(
        &self,
        side: usize,
        count: usize,
        flags: u32,
    ) -> Option<Result<Received>> {
        if self.datagram_budget.is_some() {
            self.recv_mode::<true>(side, count, flags, true, true)
        } else {
            self.recv_mode::<false>(side, count, flags, true, true)
        }
    }
    pub(crate) fn recv_message_bytes(
        &self,
        side: usize,
        count: usize,
        flags: u32,
    ) -> Option<Result<Received>> {
        self.recv_mode::<false>(side, count, flags, false, true)
    }
    fn recv_mode<const ADDRESSED: bool>(
        &self,
        side: usize,
        count: usize,
        flags: u32,
        ancillary: bool,
        message: bool,
    ) -> Option<Result<Received>> {
        // Linux accepts the output-only MSG_CTRUNC bit on input. Android's
        // ReceiveFileDescriptorVector passes it on every Zygote receive.
        if flags & !(2 | 8 | 0x20 | 0x40 | 0x100 | 0x4000 | 0x40000000) != 0 {
            return Some(Err(Errno(95)));
        }
        if self.kind == 1 && flags & 0x100 != 0 && flags & 0x40 == 0 && count > PIPE_CAPACITY {
            return Some(Err(Errno(95)));
        }
        let mut retired = None;
        let result = self.change(|data| {
            let options = [u32::from(data.passcred[side]), data.timestamp[side]];
            let peer = 1 - side;
            let eof = data.read_closed[side];
            let queue = &mut data.queues[side];
            // read(0) does not wait or consume a pending error. Socket receive
            // APIs instead inspect the queue, error and shutdown state.
            if self.kind == 1 && count == 0 && !message {
                return Some(Ok(Received::empty(options)));
            }
            if queue.is_empty() {
                let error = std::mem::take(&mut data.error[side]);
                return Some(if error != 0 {
                    Err(Errno(error))
                } else if eof {
                    Ok(Received::empty(options))
                } else {
                    Err(Errno(11))
                });
            }
            if self.kind == 1 && count == 0 && message {
                let mut rights = None;
                let mut credentials = None;
                let mut timestamp = None;
                if let Some(packet) = queue.front_mut() {
                    if !ancillary
                        && (packet.rights.is_some()
                            || packet.credentials.is_some()
                            || packet.timestamp.is_some())
                    {
                        return None;
                    }
                    // recvmsg(0) detaches SCM_RIGHTS without consuming payload.
                    // PEEK duplicates the same original OFDs and leaves metadata.
                    rights = if flags & 2 != 0 {
                        packet.rights.clone()
                    } else {
                        packet.rights.take()
                    };
                    credentials = packet.credentials;
                    timestamp = packet.timestamp;
                }
                return Some(Ok(Received {
                    data: Vec::new(),
                    length: 0,
                    truncated: false,
                    rights,
                    credentials,
                    timestamp,
                    source: Vec::new(),
                    options,
                }));
            }
            if self.kind != 1 {
                let packet = queue.front().expect("packet");
                if !ancillary
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
                    source: packet
                        .source
                        .as_ref()
                        .map_or_else(Vec::new, |charge| charge.source.name.clone()),
                    options,
                };
                if flags & 2 == 0 {
                    // The returned rights clone keeps every original OFD
                    // alive. Only the sender charge can notify on retirement;
                    // carry that small token out of Data, not a whole Packet.
                    if ADDRESSED {
                        retired = queue
                            .pop_front()
                            .and_then(|mut packet| packet.source.take());
                    } else {
                        queue.pop_front();
                    }
                    data.used[side] -= length;
                    data.epochs[peer][1] = data.epochs[peer][1].wrapping_add(1);
                }
                return Some(Ok(out));
            }
            let mut bytes = Vec::new();
            let mut rights = None;
            let credentials = queue.front().and_then(|p| p.credentials);
            let timestamp = queue.front().and_then(|p| p.timestamp);
            let mut boundary = false;
            for packet in queue.iter() {
                if data.passcred[side] && packet.credentials != credentials
                    || packet.timestamp != timestamp
                {
                    boundary = true;
                    break;
                }
                if !ancillary && (packet.credentials.is_some() || packet.timestamp.is_some()) {
                    return None;
                }
                let n = (count - bytes.len()).min(packet.data.len());
                bytes.extend_from_slice(&packet.data[..n]);
                if packet.rights.is_some() {
                    // A plain prefix ending before the rights-bearing packet
                    // can complete locally. Crossing its boundary defers the
                    // entire call before any queue or guest-memory effects.
                    if !ancillary {
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
                if (flags & 0x100 != 0 || data.receive_low_water[side] > 1)
                    && flags & 0x40 == 0
                    && !eof
                    && !boundary
                    && bytes.len()
                        < if flags & 0x100 != 0 {
                            count
                        } else {
                            count.min(data.receive_low_water[side])
                        }
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
        });
        drop(retired);
        result
    }
    pub fn poll(&self, side: usize, events: u16) -> (u16, [u64; 2]) {
        let data = self.data.lock().unwrap();
        let peer = 1 - side;
        let eof = data.read_closed[side];
        let queue = &data.queues[side];
        let send_queue = &data.queues[peer];
        let room = data.send_limit[side].saturating_sub(data.used[peer]);
        let writable = if let Some(budget) = &self.datagram_budget {
            budget.used.load(Ordering::Relaxed) <= budget.limit.load(Ordering::Relaxed) / 4
        } else {
            room != 0
                && (send_queue.len() < 128
                    || self.kind == 1 && send_queue.back().is_some_and(|p| p.rights.is_none()))
        };
        let ready = (if !queue.is_empty() || eof {
            events & 1
        } else {
            0
        }) | (if writable { events & 4 } else { 0 })
            | (if eof { events & 0x2000 } else { 0 })
            | (if !data.alive[peer] || (eof && data.write_closed[side]) {
                16
            } else {
                0
            })
            | if data.error[side] != 0 { 8 } else { 0 };
        let mut epochs = data.epochs[side];
        if let Some(budget) = &self.datagram_budget {
            epochs[1] = epochs[1].wrapping_add(budget.epoch.load(Ordering::Relaxed));
        }
        (ready, epochs)
    }
}
impl Received {
    fn empty(options: [u32; 2]) -> Self {
        Self {
            data: Vec::new(),
            length: 0,
            truncated: false,
            rights: None,
            credentials: None,
            timestamp: None,
            source: Vec::new(),
            options,
        }
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
    fn raw_unix_sockets_are_datagrams_before_publication_and_keep_fd_flags() {
        let mut v = Vfs::default();
        let flags = 3 | O_NONBLOCK | O_CLOEXEC;
        let fd = v.socket(1, flags, 0).unwrap();
        assert_eq!(v.local_socket(fd).unwrap().unwrap().kind(), 2);
        assert_ne!(v.flags(fd).unwrap() & O_NONBLOCK, 0);
        assert_eq!(v.fd_flags_snapshot().fcntl(fd, 1, 0), Ok(1));
        let [a, b] = v.socketpair(1, flags, 0).unwrap();
        assert_eq!(v.local_socket(a).unwrap().unwrap().kind(), 2);
        let direct = v.direct_descriptors();
        assert_eq!(direct.get(a).unwrap().write(b"packet"), Ok(6));
        assert_eq!(direct.get(b).unwrap().read(2), Ok(b"pa".to_vec()));
        assert_eq!(direct.get(b).unwrap().read(9), Err(Errno(11)));
        assert_eq!(v.socket(1, flags, 2), Err(Errno(93)));
        assert_eq!(v.socket(1, 4, 0), Err(Errno(94)));
    }
    #[test]
    fn addressed_datagrams_can_reconnect_to_the_same_or_a_new_peer_but_cannot_accept() {
        let mut v = Vfs::default();
        let a = v.socket(1, 2, 0).unwrap();
        let b = v.socket(1, 2, 0).unwrap();
        let c = v.socket(1, 3, 0).unwrap();
        let first = v.local_socket(a).unwrap().unwrap();
        let second = v.local_socket(b).unwrap().unwrap();
        let sender = v.local_socket(c).unwrap().unwrap();
        let address_a = b"\x01\x00\0reconnect-a";
        let address_b = b"\x01\x00\0reconnect-b";
        v.local_bind(&first, address_a).unwrap();
        v.local_bind(&second, address_b).unwrap();
        assert_eq!(v.local_accept(&first, 0), Err(Errno(95)));
        assert_eq!(v.local_accept(&first, 4), Err(Errno(22)));
        for address in [address_a, address_a, address_b] {
            v.local_connect(&sender, address).unwrap();
            assert_eq!(sender.name(true).unwrap(), address);
            assert_eq!(sender.send(b"x", 0), Ok(1));
            let receiver = if address == address_a {
                &first
            } else {
                &second
            };
            assert_eq!(receiver.recv(1, 0).unwrap().data, b"x");
        }
        assert_eq!(first.recv(1, 0).err(), Some(Errno(11)));
    }
    #[test]
    fn shutdown_notifies_existing_waiters_and_propagates_only_on_connected_transports() {
        struct Wake;
        impl IoWake for Wake {
            fn wake_io(&self, _: &Arc<IoSignal>) {}
        }
        let target: Arc<dyn IoWake> = Arc::new(Wake);
        for kind in [1, 2, 5] {
            let resource = Resource::new(kind, true);
            let signal = IoSignal::new(1, Arc::downgrade(&target));
            let _subscription = resource.readiness.subscribe(&signal);
            resource.shutdown(0, 0).unwrap();
            assert!(signal.ready());
            assert_eq!(resource.poll(0, 0x2005).0, 0x2005);
            assert_eq!(resource.poll(1, 0).0, 0);
            assert_eq!(resource.send_credentials(1, b"x", 0, None), Err(Errno(32)));
            resource.shutdown(0, 1).unwrap();
            assert_eq!(resource.poll(0, 0x2005).0, 0x2015);
            assert_eq!(resource.poll(1, 0).0, if kind == 2 { 0 } else { 16 });
            let received = resource.recv_message(1, 0, 0x40).unwrap();
            if kind == 2 {
                assert!(matches!(received, Err(Errno(11))));
            } else {
                assert!(received.unwrap().data.is_empty());
            }
        }
    }
    #[test]
    fn empty_zero_length_message_waits_but_plain_read_does_not_consume_pending_error() {
        let data = Resource::new(1, true);
        for flags in [0, 2, 0x20, 0x22] {
            assert!(matches!(
                data.recv_message(0, 0, flags),
                Some(Err(Errno(11)))
            ));
            assert!(matches!(
                data.recv_message_bytes(0, 0, flags),
                Some(Err(Errno(11)))
            ));
            assert!(data
                .recv(0, 0, flags, false)
                .unwrap()
                .unwrap()
                .data
                .is_empty());
        }
        data.send_credentials(0, b"unread", 0, None).unwrap();
        data.shutdown(1, 2).unwrap();
        assert!(data.recv_message(0, 1, 0).unwrap().unwrap().data.is_empty());
        data.close(1);
        assert_ne!(data.poll(0, 0).0 & 8, 0);
        assert!(data.recv(0, 0, 0, false).unwrap().unwrap().data.is_empty());
        assert!(matches!(data.recv(0, 1, 0, false), Some(Err(Errno(104)))));
        assert_eq!(data.take_error(0), 0);
        assert_eq!(data.poll(0, 0).0, 16);
        assert!(data.recv_message(0, 1, 0).unwrap().unwrap().data.is_empty());
    }
    #[test]
    fn closing_listener_resets_only_its_unaccepted_connections_and_error_is_consumed_once() {
        let mut v = Vfs::default();
        for accepted in [false, true] {
            let listener = v.socket(1, 1, 0).unwrap();
            let endpoint = v.local_socket(listener).unwrap().unwrap();
            v.local_bind(&endpoint, &[1, 0, 0, if accepted { b'a' } else { b'b' }])
                .unwrap();
            endpoint.listen(1).unwrap();
            let client = v.socket(1, 1, 0).unwrap();
            let peer = v.local_socket(client).unwrap().unwrap();
            v.local_connect(&peer, &endpoint.name(false).unwrap())
                .unwrap();
            let server = accepted.then(|| v.local_accept(&endpoint, 0).unwrap().0);
            drop(endpoint);
            v.close(listener).unwrap();
            if let Some(server) = server {
                assert_eq!(peer.take_error(), 0);
                assert_eq!(v.write(client, b"ok"), Ok(2));
                assert_eq!(v.read(server, 2), Ok(b"ok".to_vec()));
            } else {
                assert_ne!(v.poll(client, 0) & 8, 0);
                assert_eq!(peer.take_error(), 104);
                assert_eq!(peer.take_error(), 0);
                assert_eq!(v.read(client, 1), Ok(Vec::new()));
            }
        }
    }
    #[test]
    fn unix_sender_budget_ignores_receive_buffer_and_growing_it_unblocks_poll() {
        for kind in [1, 2, 5] {
            let data = Resource::new(kind, true);
            data.set_buffer_unnotified(1, true, 128);
            let bytes = vec![7; PIPE_CAPACITY / 4];
            for _ in 0..4 {
                assert_eq!(
                    data.send_credentials(0, &bytes, 0x40, None),
                    Ok(bytes.len())
                );
            }
            assert_eq!(data.poll(0, 4).0, 0);
            assert_eq!(data.send_credentials(0, &bytes, 0x40, None), Err(Errno(11)));
            data.set_buffer_unnotified(0, false, PIPE_CAPACITY as u32);
            assert_eq!(data.poll(0, 4).0, 4);
            assert_eq!(
                data.send_credentials(0, &bytes, 0x40, None),
                Ok(bytes.len())
            );
            let out = data.recv_message(1, bytes.len(), 0).unwrap().unwrap();
            assert_eq!(out.data, bytes);
        }
    }
    #[test]
    fn explicit_credentials_and_sender_passcred_are_distinct_from_late_receive_enable() {
        for kind in [1, 2, 5] {
            for mode in 0..3 {
                let mut vfs = Vfs::default();
                let [a, b] = vfs.socketpair(1, kind, 0).unwrap();
                let tx = vfs.direct_descriptors().get(a).unwrap();
                let receiver = vfs.local_socket(b).unwrap().unwrap();
                if mode == 1 {
                    vfs.local_socket(a)
                        .unwrap()
                        .unwrap()
                        .set_reuse(16, 1)
                        .unwrap();
                }
                let rights = SharedRights::default();
                let result = if mode == 2 {
                    tx.send_local_message_explicit(b"x", 0, &rights, [42, 1000, 1001])
                } else {
                    tx.send_local_message(b"x", 0, &rights, [42, 1000, 1001])
                };
                assert_eq!(result, Some(Ok(1)));
                receiver.set_reuse(16, 1).unwrap();
                assert_eq!(
                    receiver.recv(1, 0).unwrap().credentials,
                    Some(if mode == 0 {
                        [0, u32::MAX, u32::MAX]
                    } else {
                        [42, 1000, 1001]
                    })
                );
            }
        }
    }
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
    fn zero_length_peeks_alias_original_rights_and_consumption_detaches_only_metadata() {
        let mut v = Vfs::default();
        let [tx, rx] = v.socketpair(1, 1, 0).unwrap();
        let event = v.eventfd(42, 0).unwrap();
        let sender = v.local_socket(tx).unwrap().unwrap();
        sender
            .send_rights(b"xyz", 0, v.send_rights(&[event]).unwrap())
            .unwrap();
        let receiver = v.direct_descriptors().get(rx).unwrap();
        let factory = v.descriptor_factory();
        let mut aliases = Vec::new();
        for _ in 0..2 {
            let peek = receiver.recv_local_message(0, 2).unwrap().unwrap();
            assert!(peek.data.is_empty());
            let (fds, truncated) = factory.receive_local_rights(peek.rights, 1, true);
            assert!(!truncated);
            assert_eq!(fds.len(), 1);
            aliases.push(fds[0]);
            assert_eq!(v.readable_bytes(rx), Ok(Some(3)));
        }
        v.close(event).unwrap();
        let message = receiver.recv_local_message(0, 0).unwrap().unwrap();
        let (fds, truncated) = factory.receive_local_rights(message.rights, 1, false);
        assert!(!truncated);
        assert_eq!(fds.len(), 1);
        aliases.push(fds[0]);
        let payload = receiver.recv_local_message(3, 0).unwrap().unwrap();
        assert_eq!(payload.data, b"xyz");
        assert!(payload.rights.is_empty());
        assert_eq!(v.read(aliases[0], 8).unwrap(), 42u64.to_le_bytes());
        v.write(aliases[1], &5u64.to_le_bytes()).unwrap();
        assert_eq!(v.read(aliases[2], 8).unwrap(), 5u64.to_le_bytes());
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
