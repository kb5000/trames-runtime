// SPDX-License-Identifier: GPL-3.0-or-later
//! The FUSE device transports one complete message per read or write.
//! Requests stay attached to their original connection across descriptor clones.
use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
#[cfg(test)]
#[path = "receiver_tests.rs"]
mod receiver_tests;

const INIT: u32 = 26;
const INTERRUPT: u32 = 36;
const HEADER: usize = 40;
const MIN_BUFFER: usize = 8192;

#[derive(Clone, Copy, Default)]
pub struct Caller {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Init,
    Ready,
    Aborted,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Interrupt {
    None,
    Requested,
    Queued,
    Sent,
}
struct Entry {
    // Consumed when the daemon reads the request.
    message: Option<Vec<u8>>,
    interrupt: Interrupt,
    caller: Caller,
    reply: Option<Arc<Completion>>,
    one_way: bool,
    flushing: Option<Arc<File>>,
    output: ReplySize,
}
#[derive(Clone, Copy)]
enum ReplySize {
    Exact(usize),
    AtMost(usize),
    Any,
}
impl ReplySize {
    fn for_request(opcode: u32, body: &[u8]) -> Self {
        let size = |at| {
            body.get(at..at + 4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
        };
        match opcode {
            1 | 6 | 8 | 9 | 13 => Self::Exact(128),
            3 | 4 => Self::Exact(104),
            5 => Self::AtMost(MAX_PATH - 1),
            14 | 27 => Self::Exact(16),
            15 | 28 | 44 => size(16).map_or(Self::Any, Self::AtMost),
            16 | 37 | 40 | 46 | 47 => Self::Exact(8),
            17 => Self::Exact(80),
            22 | 23 => match size(0) {
                Some(0) => Self::Exact(8),
                Some(size) => Self::AtMost(size),
                None => Self::Any,
            },
            31 => Self::Exact(24),
            35 => Self::Exact(144),
            10..=12 | 18 | 20 | 21 | 24 | 25 | 29 | 30 | 32..=34 | 38 | 43 | 45 | 48..=50 => {
                Self::Exact(0)
            }
            _ => Self::Any,
        }
    }
    fn accepts(self, size: usize) -> bool {
        match self {
            Self::Exact(expected) => size == expected,
            Self::AtMost(max) => size <= max,
            Self::Any => true,
        }
    }
}
struct Queue {
    phase: Phase,
    next: u64,
    epoch: u64,
    interrupts_enabled: bool,
    pending: VecDeque<u64>,
    interrupts: VecDeque<u64>,
    requests: BTreeMap<u64, Entry>,
}
struct Completion {
    result: Mutex<Option<Result<Vec<u8>>>>,
    receiver: Option<std::sync::Weak<dyn ReplyReceiver>>,
    cleanup: Option<(std::sync::Weak<Connection>, Caller, ReplyResource)>,
    attributes: Option<AbandonedAttributes>,
    attr_version: u64,
    changed: Arc<Readiness>,
}
/// A retained byte resource completes on the actor writing the daemon reply.
/// Installed before enqueueing, weakly owned, and invoked without connection
/// or completion locks. It must not retain a guest pointer or execution slot.
pub(super) trait ReplyReceiver: Send + Sync {
    fn complete(&self, result: Result<Vec<u8>>);
}
struct AbandonedAttributes {
    fs: std::sync::Weak<Mounted>,
    inode: std::sync::Weak<Inode>,
    set: bool,
}
enum ReplyResource {
    Lookup {
        kind: Option<u32>,
    },
    Open {
        node: u64,
        flags: u32,
        directory: bool,
    },
    Create {
        flags: u32,
    },
}
// A successful reply can arrive after its guest waiter has gone.
impl Drop for Completion {
    fn drop(&mut self) {
        let Some(Ok(bytes)) = self.result.get_mut().unwrap().take() else {
            return;
        };
        if let Some(attributes) = &self.attributes {
            if let (Some(fs), Some(inode)) = (attributes.fs.upgrade(), attributes.inode.upgrade()) {
                fs.abandoned_attributes(&inode, &bytes, self.attr_version, attributes.set);
            }
        }
        let Some((connection, caller, resource)) = &self.cleanup else {
            return;
        };
        let Some(c) = connection.upgrade() else {
            return;
        };
        if let Some(fs) = c.mounted.get().and_then(std::sync::Weak::upgrade) {
            match resource {
                ReplyResource::Lookup { kind } => {
                    fs.abandoned_entry(&bytes, self.attr_version, *kind)
                }
                ReplyResource::Create { .. } if bytes.len() == 144 => {
                    fs.abandoned_entry(&bytes[..128], self.attr_version, Some(0o100000))
                }
                _ => {}
            }
        }
        match resource {
            ReplyResource::Create { flags } => {
                if let Some(node) = bytes
                    .get(..128)
                    .filter(|_| bytes.len() == 144)
                    .and_then(|entry| entry_id(entry, Some(0o100000)))
                {
                    if let Some(fh) = bytes.get(128..136) {
                        c.release(
                            node,
                            *caller,
                            u64::from_le_bytes(fh.try_into().unwrap()),
                            *flags,
                            false,
                        );
                    }
                    c.forget(node, *caller);
                }
            }
            ReplyResource::Lookup { kind } => {
                if let Some(node) = entry_id(&bytes, *kind) {
                    c.forget(node, *caller);
                }
            }
            ReplyResource::Open {
                node,
                flags,
                directory,
            } => {
                if let Some(fh) = bytes.get(..8) {
                    c.release(
                        *node,
                        *caller,
                        u64::from_le_bytes(fh.try_into().unwrap()),
                        *flags,
                        *directory,
                    );
                }
            }
        }
    }
}
pub(super) fn lookup_id(bytes: &[u8]) -> Option<u64> {
    let node = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    (node > 1).then_some(node)
}
pub(super) fn valid_attr(raw: &[u8]) -> bool {
    raw.len() == 88
        && matches!(
            u32::from_le_bytes(raw[60..64].try_into().unwrap()) & 0o170000,
            0o010000 | 0o020000 | 0o040000 | 0o060000 | 0o100000 | 0o120000 | 0o140000
        )
        && u64::from_le_bytes(raw[8..16].try_into().unwrap()) <= i64::MAX as u64
}
/// A reply grants an entry only after the callback's identity/type/size checks.
pub(super) fn entry_id(bytes: &[u8], kind: Option<u32>) -> Option<u64> {
    if bytes.len() != 128 || !valid_attr(&bytes[40..]) {
        return None;
    }
    let actual = u32::from_le_bytes(bytes[100..104].try_into().unwrap()) & 0o170000;
    if kind.is_some_and(|kind| kind != actual) {
        return None;
    }
    lookup_id(bytes)
}
impl Completion {
    fn finish(&self, result: Result<Vec<u8>>) {
        if let Some(receiver) = &self.receiver {
            if let Some(receiver) = receiver.upgrade() {
                receiver.complete(result);
            }
            return;
        }
        *self.result.lock().unwrap() = Some(result);
        self.changed.notify_atomic();
    }
}

pub struct Connection {
    queue: Mutex<Queue>,
    changed: Arc<Readiness>,
    max_write: std::sync::atomic::AtomicUsize,
    options: std::sync::atomic::AtomicU32,
    attr_version: std::sync::atomic::AtomicU64,
    pub(super) mounted: OnceLock<std::sync::Weak<Mounted>>,
}
/// An accepted operation. Dropping the last guest wait withdraws an unread
/// request. A delivered request keeps its ID until reply or disconnect.
pub struct Request {
    pub(super) attr_version: u64,
    id: u64,
    connection: Arc<Connection>,
    completion: Arc<Completion>,
}
impl Request {
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.completion.changed.subscribe(signal)
    }
    pub fn ready(&self) -> bool {
        self.completion.result.lock().unwrap().is_some()
    }
    pub fn take(&self) -> Option<Result<Vec<u8>>> {
        self.completion.result.lock().unwrap().take()
    }
    pub fn needs_interrupt(&self) -> bool {
        let q = self.connection.queue.lock().unwrap();
        q.interrupts_enabled
            && q.requests
                .get(&self.id)
                .is_some_and(|e| e.interrupt == Interrupt::None)
    }
    pub fn interrupt(&self) {
        let mut q = self.connection.queue.lock().unwrap();
        if !q.interrupts_enabled {
            return;
        }
        let Some(entry) = q.requests.get_mut(&self.id) else {
            return;
        };
        if entry.interrupt != Interrupt::None {
            return;
        }
        if entry.message.is_some() {
            entry.interrupt = Interrupt::Requested;
            return;
        }
        entry.interrupt = Interrupt::Queued;
        q.interrupts.push_back(self.id);
        q.epoch = q.epoch.wrapping_add(1);
        drop(q);
        self.connection.changed.notify_atomic();
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        let mut q = self.connection.queue.lock().unwrap();
        let enabled = q.interrupts_enabled;
        let Some(entry) = q.requests.get_mut(&self.id) else {
            return;
        };
        if entry.message.is_some() {
            q.pending.retain(|&id| id != self.id);
            q.requests.remove(&self.id);
        } else {
            // Keep the completion until the daemon replies so an abandoned
            // LOOKUP can return the reference granted by that reply.
            if self.completion.cleanup.is_none()
                && self.completion.attributes.is_none()
                && self.completion.receiver.is_none()
            {
                entry.reply = None;
            }
            if enabled && entry.interrupt == Interrupt::None {
                entry.interrupt = Interrupt::Queued;
                q.interrupts.push_back(self.id);
                q.epoch = q.epoch.wrapping_add(1);
                drop(q);
                self.connection.changed.notify_atomic();
            }
        }
    }
}

fn packet(id: u64, opcode: u32, node: u64, caller: Caller, body: &[u8]) -> Result<Vec<u8>> {
    let len =
        u32::try_from(body.len().checked_add(HEADER).ok_or(Errno(75))?).map_err(|_| Errno(75))?;
    let mut message = Vec::with_capacity(len as usize);
    message.extend(len.to_le_bytes());
    message.extend(opcode.to_le_bytes());
    message.extend(id.to_le_bytes());
    message.extend(node.to_le_bytes());
    message.extend(caller.uid.to_le_bytes());
    message.extend(caller.gid.to_le_bytes());
    message.extend(caller.pid.to_le_bytes());
    message.extend([0; 4]);
    message.extend_from_slice(body);
    Ok(message)
}
impl Connection {
    pub fn new(caller: Caller) -> Arc<Self> {
        let mut body = [0; 16];
        body[..4].copy_from_slice(&7u32.to_le_bytes());
        body[4..8].copy_from_slice(&31u32.to_le_bytes());
        body[12..16]
            .copy_from_slice(&((1u32 << 5) | (1 << 6) | (1 << 20) | (1 << 29)).to_le_bytes()); // BIG_WRITES, DONT_MASK, POSIX_ACL, SETXATTR_EXT
        let init = Entry {
            message: Some(packet(2, INIT, 0, caller, &body).expect("fixed init length")),
            interrupt: Interrupt::None,
            caller,
            reply: None,
            one_way: false,
            flushing: None,
            output: ReplySize::AtMost(64),
        };
        Arc::new(Self {
            queue: Mutex::new(Queue {
                phase: Phase::Init,
                next: 4,
                epoch: 1,
                interrupts_enabled: true,
                pending: [2].into(),
                interrupts: VecDeque::new(),
                requests: [(2, init)].into(),
            }),
            changed: Arc::default(),
            max_write: std::sync::atomic::AtomicUsize::new(4096),
            options: Default::default(),
            attr_version: std::sync::atomic::AtomicU64::new(1),
            mounted: OnceLock::new(),
        })
    }
    pub(crate) fn initialized(&self) -> bool {
        self.options.load(Ordering::Relaxed) & (1 << 31) != 0
    }
    pub(crate) fn option(&self, flag: u32) -> bool {
        self.options.load(Ordering::Relaxed) & flag != 0
    }
    pub(crate) fn init_result(&self) -> Result<()> {
        if self.queue.lock().unwrap().phase == Phase::Aborted {
            Err(Errno(107))
        } else {
            Ok(())
        }
    }
    pub fn request(
        self: &Arc<Self>,
        opcode: u32,
        node: u64,
        caller: Caller,
        body: &[u8],
    ) -> Result<Request> {
        self.request_with_entry_kind(opcode, node, caller, body, None, None)
    }
    pub(super) fn request_received(
        self: &Arc<Self>,
        opcode: u32,
        node: u64,
        caller: Caller,
        body: &[u8],
        receiver: std::sync::Weak<dyn ReplyReceiver>,
    ) -> Result<Request> {
        // Resource-granting replies need the ordinary abandoned-reply cleanup.
        // Page IO owns byte replies only and cannot bypass that lifecycle.
        assert!(matches!(opcode, 15 | 16));
        self.request_with_entry_kind(opcode, node, caller, body, None, Some(receiver))
    }
    pub(super) fn request_entry(
        self: &Arc<Self>,
        opcode: u32,
        node: u64,
        caller: Caller,
        body: &[u8],
        kind: u32,
    ) -> Result<Request> {
        self.request_with_entry_kind(opcode, node, caller, body, Some(kind), None)
    }
    fn request_with_entry_kind(
        self: &Arc<Self>,
        opcode: u32,
        node: u64,
        caller: Caller,
        body: &[u8],
        kind: Option<u32>,
        receiver: Option<std::sync::Weak<dyn ReplyReceiver>>,
    ) -> Result<Request> {
        let attr_version = if matches!(opcode, 1 | 3 | 4 | 6 | 8 | 9 | 13 | 35) {
            self.attr_version.load(Ordering::Relaxed)
        } else {
            0
        };
        let attributes = if matches!(opcode, 3 | 4) {
            self.mounted
                .get()
                .and_then(std::sync::Weak::upgrade)
                .and_then(|fs| {
                    Some(AbandonedAttributes {
                        inode: Arc::downgrade(&fs.attribute_target(node)?),
                        fs: Arc::downgrade(&fs),
                        set: opcode == 4,
                    })
                })
        } else {
            None
        };
        let mut q = self.queue.lock().unwrap();
        if q.phase == Phase::Aborted {
            return Err(Errno(107));
        }
        let id = q.next;
        q.next = id.checked_add(2).ok_or(Errno(75))?;
        let completion = Arc::new(Completion {
            result: Mutex::default(),
            receiver,
            attributes,
            attr_version,
            cleanup: match opcode {
                1 | 6 | 8 | 9 | 13 => Some(ReplyResource::Lookup {
                    kind: kind.or_else(|| match opcode {
                        6 => Some(0o120000),
                        8 => body
                            .get(..4)
                            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) & 0o170000),
                        9 => Some(0o040000),
                        _ => None,
                    }),
                }),
                35 if body.len() >= 4 => Some(ReplyResource::Create {
                    flags: (u32::from_le_bytes(body[..4].try_into().unwrap())
                        & !(O_CLOEXEC | OPEN_ONLY_FLAGS))
                        | O_LARGEFILE,
                }),
                14 | 27 if body.len() >= 4 => Some(ReplyResource::Open {
                    node,
                    flags: u32::from_le_bytes(body[..4].try_into().unwrap()),
                    directory: opcode == 27,
                }),
                _ => None,
            }
            .map(|resource| (Arc::downgrade(self), caller, resource)),
            changed: Arc::default(),
        });
        q.requests.insert(
            id,
            Entry {
                message: Some(packet(id, opcode, node, caller, body)?),
                interrupt: Interrupt::None,
                caller,
                reply: Some(completion.clone()),
                one_way: false,
                flushing: None,
                output: ReplySize::for_request(opcode, body),
            },
        );
        q.pending.push_back(id);
        q.epoch = q.epoch.wrapping_add(1);
        drop(q);
        self.changed.notify_atomic();
        Ok(Request {
            attr_version,
            id,
            connection: self.clone(),
            completion,
        })
    }
    pub(super) fn next_attr_version(&self) -> u64 {
        self.attr_version
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }
    pub(super) fn current_attr_version(&self) -> u64 {
        self.attr_version.load(Ordering::Relaxed)
    }
    pub(super) fn forget(&self, node: u64, caller: Caller) {
        self.background(2, node, caller, &1u64.to_le_bytes(), None);
    }
    pub(super) fn release(&self, node: u64, caller: Caller, fh: u64, flags: u32, directory: bool) {
        let mut body = [0; 24];
        body[..8].copy_from_slice(&fh.to_le_bytes());
        body[8..12].copy_from_slice(&flags.to_le_bytes());
        self.background(if directory { 29 } else { 18 }, node, caller, &body, None);
    }
    pub(super) fn data_limit(&self) -> usize {
        self.max_write.load(Ordering::Relaxed)
    }
    pub(super) fn background(
        &self,
        opcode: u32,
        node: u64,
        caller: Caller,
        body: &[u8],
        flushing: Option<Arc<File>>,
    ) {
        let mut q = self.queue.lock().unwrap();
        if q.phase == Phase::Aborted {
            return;
        }
        let id = q.next;
        let Some(next) = id.checked_add(2) else {
            return;
        };
        q.next = next;
        q.requests.insert(
            id,
            Entry {
                message: Some(
                    packet(id, opcode, node, caller, body).expect("fixed cleanup packet length"),
                ),
                interrupt: Interrupt::None,
                caller,
                reply: None,
                one_way: opcode == 2,
                flushing,
                output: ReplySize::Exact(0),
            },
        );
        q.pending.push_back(id);
        q.epoch = q.epoch.wrapping_add(1);
        drop(q);
        self.changed.notify_atomic();
    }
    pub fn poll(&self, mask: u16) -> (u16, [u64; 2]) {
        let q = self.queue.lock().unwrap();
        let available = q.phase == Phase::Aborted
            || !q.interrupts.is_empty()
            || q.pending
                .front()
                .is_some_and(|&id| id == 2 || q.phase == Phase::Ready);
        let bits = if q.phase == Phase::Aborted {
            8
        } else {
            mask & (poll_mask::WRITE_NORMAL | if available { poll_mask::READ_NORMAL } else { 0 })
        };
        (bits, [q.epoch, 0])
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
    fn notification(&self, code: i32, body: &[u8]) -> Result<()> {
        match code {
            2 if body.len() == 24 => {
                let fs = self
                    .mounted
                    .get()
                    .and_then(std::sync::Weak::upgrade)
                    .ok_or(Errno(2))?;
                fs.notify_inode(
                    u64::from_le_bytes(body[..8].try_into().unwrap()),
                    i64::from_le_bytes(body[8..16].try_into().unwrap()),
                    i64::from_le_bytes(body[16..24].try_into().unwrap()),
                )
            }
            _ => Err(Errno(22)),
        }
    }
    pub fn read(&self, size: usize) -> Result<Vec<u8>> {
        let mut q = self.queue.lock().unwrap();
        if q.phase == Phase::Aborted {
            return Err(Errno(19));
        }
        if size < MIN_BUFFER {
            return Err(Errno(22));
        }
        if let Some(id) = q.interrupts.pop_front() {
            let e = q
                .requests
                .get_mut(&id)
                .expect("interrupt has original request");
            e.interrupt = Interrupt::Sent;
            return packet(id | 1, INTERRUPT, 0, e.caller, &id.to_le_bytes());
        }
        let id = *q.pending.front().ok_or(Errno(11))?;
        if q.phase == Phase::Init && id != 2 {
            return Err(Errno(11));
        }
        let e = q.requests.get_mut(&id).unwrap();
        if e.message.as_ref().unwrap().len() > size {
            return Err(Errno(22));
        }
        let msg = e.message.take().unwrap();
        let interrupted = e.interrupt == Interrupt::Requested;
        if interrupted {
            e.interrupt = Interrupt::Queued;
        }
        let one_way = e.one_way;
        q.pending.pop_front();
        if one_way {
            q.requests.remove(&id);
        }
        if interrupted {
            q.interrupts.push_back(id);
            q.epoch = q.epoch.wrapping_add(1);
            drop(q);
            self.changed.notify_atomic();
        }
        Ok(msg)
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        if bytes.len() < 16
            || u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize != bytes.len()
        {
            return Err(Errno(22));
        }
        let err = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        if id != 0 && !(-4095..=0).contains(&err) {
            return Err(Errno(22));
        }
        let mut q = self.queue.lock().unwrap();
        if q.phase == Phase::Aborted {
            return Err(Errno(19));
        }
        if id == 0 {
            // Notifications carry their positive opcode in the error field.
            // Inode/cache operations run outside the transport queue lock.
            drop(q);
            self.notification(err, &bytes[16..])?;
            return Ok(bytes.len());
        }
        let e = q.requests.get_mut(&(id & !1)).ok_or(Errno(2))?;
        if e.message.is_some() {
            return Err(Errno(2));
        }
        if id & 1 != 0 {
            if e.interrupt != Interrupt::Sent || bytes.len() != 16 {
                return Err(Errno(22));
            }
            if err == -11 {
                e.interrupt = Interrupt::Queued;
                q.interrupts.push_back(id & !1);
                q.epoch = q.epoch.wrapping_add(1);
            } else if err == -38 {
                q.interrupts_enabled = false;
                q.interrupts.clear();
                for e in q.requests.values_mut() {
                    e.interrupt = Interrupt::None;
                }
            }
            drop(q);
            self.changed.notify_atomic();
        } else if id == 2 {
            let malformed = if err == 0 {
                !e.output.accepts(bytes.len() - 16)
            } else {
                bytes.len() != 16
            };
            if malformed {
                self.abort_locked(q);
                return Err(Errno(22));
            }
            let mut info = [0; 64];
            info[..bytes.len() - 16].copy_from_slice(&bytes[16..]);
            let valid = err == 0
                && info[..4] == 7u32.to_le_bytes()
                && u32::from_le_bytes(info[4..8].try_into().unwrap()) >= 9;
            if valid {
                let max_write = bytes.get(36..40).map_or(4096, |raw| {
                    u32::from_le_bytes(raw.try_into().unwrap()) as usize
                });
                // Match Linux's minimum transfer and default 32-page ceiling.
                // INIT does not advertise MAX_PAGES or larger request buffers.
                self.max_write
                    .store(max_write.clamp(4096, 32 * 4096), Ordering::Relaxed);
                let flags = bytes
                    .get(28..32)
                    .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()));
                self.options.store(
                    (1 << 31) | (flags & ((1 << 6) | (1 << 20) | (1 << 29))),
                    Ordering::Relaxed,
                );
                q.requests.remove(&id);
                q.phase = Phase::Ready;
                q.epoch = q.epoch.wrapping_add(1);
                drop(q);
                self.changed.notify_atomic();
            } else {
                self.abort_locked(q);
            }
        } else {
            let entry = q.requests.remove(&id).unwrap();
            if entry.interrupt == Interrupt::Queued {
                q.interrupts.retain(|&n| n != id);
            }
            drop(q);
            let malformed = if err == 0 {
                !entry.output.accepts(bytes.len() - 16)
            } else {
                bytes.len() != 16
            };
            if let Some(file) = entry.flushing {
                if !malformed && err == -38 {
                    file.disable_flush();
                }
            }
            if let Some(c) = entry.reply {
                c.finish(if malformed {
                    Err(Errno(5))
                } else if err == 0 {
                    Ok(bytes[16..].to_vec())
                } else {
                    Err(Errno((-err) as u32))
                });
            }
            if malformed {
                return Err(Errno(22));
            }
        }
        Ok(bytes.len())
    }
    pub fn abort(&self) {
        self.abort_locked(self.queue.lock().unwrap());
    }
    fn abort_locked(&self, mut q: std::sync::MutexGuard<'_, Queue>) {
        self.options.fetch_or(1 << 31, Ordering::Relaxed);
        if q.phase == Phase::Aborted {
            return;
        }
        q.phase = Phase::Aborted;
        q.epoch = q.epoch.wrapping_add(1);
        q.pending.clear();
        q.interrupts.clear();
        let requests = std::mem::take(&mut q.requests);
        drop(q);
        self.changed.notify_atomic();
        for e in requests.into_values() {
            if let Some(c) = e.reply {
                c.finish(Err(Errno(103)));
            }
        }
    }
}
