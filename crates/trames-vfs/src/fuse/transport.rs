// SPDX-License-Identifier: GPL-3.0-or-later
//! The FUSE device transports one complete message per read or write.
//! Requests stay attached to their original connection across descriptor clones.
use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

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
    cleanup: Option<(std::sync::Weak<Connection>, Caller, ReplyResource)>,
    changed: Arc<Readiness>,
}
enum ReplyResource {
    Lookup,
    Open { node: u64, flags: u32 },
}
// A successful reply can arrive after its guest waiter has gone.
impl Drop for Completion {
    fn drop(&mut self) {
        let Some((connection, caller, resource)) = &self.cleanup else {
            return;
        };
        let Some(Ok(bytes)) = self.result.get_mut().unwrap().take() else {
            return;
        };
        let Some(c) = connection.upgrade() else {
            return;
        };
        match resource {
            ReplyResource::Lookup => {
                if let Some(node) = lookup_id(&bytes) {
                    c.forget(node, *caller);
                }
            }
            ReplyResource::Open { node, flags } => {
                if let Some(fh) = bytes.get(..8) {
                    c.release(
                        *node,
                        *caller,
                        u64::from_le_bytes(fh.try_into().unwrap()),
                        *flags,
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
impl Completion {
    fn finish(&self, result: Result<Vec<u8>>) {
        *self.result.lock().unwrap() = Some(result);
        self.changed.notify_atomic();
    }
}

pub struct Connection {
    queue: Mutex<Queue>,
    changed: Arc<Readiness>,
}
/// An accepted operation. Dropping the last guest wait withdraws an unread
/// request. A delivered request keeps its ID until reply or disconnect.
pub struct Request {
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
            if self.completion.cleanup.is_none() {
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
        let init = Entry {
            message: Some(packet(2, INIT, 0, caller, &body).expect("fixed init length")),
            interrupt: Interrupt::None,
            caller,
            reply: None,
            one_way: false,
            flushing: None,
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
        })
    }
    pub fn request(
        self: &Arc<Self>,
        opcode: u32,
        node: u64,
        caller: Caller,
        body: &[u8],
    ) -> Result<Request> {
        let mut q = self.queue.lock().unwrap();
        if q.phase == Phase::Aborted {
            return Err(Errno(107));
        }
        let id = q.next;
        q.next = id.checked_add(2).ok_or(Errno(75))?;
        let completion = Arc::new(Completion {
            result: Mutex::default(),
            cleanup: match opcode {
                1 => Some(ReplyResource::Lookup),
                14 if body.len() >= 4 => Some(ReplyResource::Open {
                    node,
                    flags: u32::from_le_bytes(body[..4].try_into().unwrap()),
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
            },
        );
        q.pending.push_back(id);
        q.epoch = q.epoch.wrapping_add(1);
        drop(q);
        self.changed.notify_atomic();
        Ok(Request {
            id,
            connection: self.clone(),
            completion,
        })
    }
    pub(super) fn forget(&self, node: u64, caller: Caller) {
        self.background(2, node, caller, &1u64.to_le_bytes(), None);
    }
    pub(super) fn release(&self, node: u64, caller: Caller, fh: u64, flags: u32) {
        let mut body = [0; 24];
        body[..8].copy_from_slice(&fh.to_le_bytes());
        body[8..12].copy_from_slice(&flags.to_le_bytes());
        self.background(18, node, caller, &body, None);
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
        if !(-4095..=0).contains(&err) || err != 0 && bytes.len() != 16 {
            return Err(Errno(22));
        }
        let id = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let mut q = self.queue.lock().unwrap();
        if q.phase == Phase::Aborted {
            return Err(Errno(19));
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
            if err == 0 && bytes.len() < 24 {
                return Err(Errno(22));
            }
            let valid = err == 0
                && bytes[16..20] == 7u32.to_le_bytes()
                && u32::from_le_bytes(bytes[20..24].try_into().unwrap()) >= 9;
            if valid {
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
            if let Some(file) = entry.flushing {
                if err == -38 {
                    file.disable_flush();
                }
            }
            if let Some(c) = entry.reply {
                c.finish(if err == 0 {
                    Ok(bytes[16..].to_vec())
                } else {
                    Err(Errno((-err) as u32))
                });
            }
        }
        Ok(bytes.len())
    }
    pub fn abort(&self) {
        self.abort_locked(self.queue.lock().unwrap());
    }
    fn abort_locked(&self, mut q: std::sync::MutexGuard<'_, Queue>) {
        if q.phase == Phase::Aborted {
            return;
        }
        q.phase = Phase::Aborted;
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
