// SPDX-License-Identifier: GPL-3.0-or-later
//! System V message queues owned by the original IPC namespace. The directory
//! protects identity publication only; transfer and waits use one queue's lock.
use super::*;
use std::{collections::VecDeque, sync::Mutex};
#[cfg(test)]
#[path = "sysv_message_tests.rs"]
mod tests;

pub const MSGMAX: usize = 8192;
pub const MSGMNB: usize = 16384;
pub const MSGMNI: usize = 32000;
#[derive(Default)]
pub(super) struct Messages(Mutex<Directory>);
#[derive(Default)]
struct Directory {
    next: u32,
    queues: BTreeMap<u32, Arc<Queue>>,
    keys: BTreeMap<i32, u32>,
}
struct Queue {
    key: i32,
    owner: UserNamespace,
    state: Mutex<State>,
    ready: Arc<Readiness>,
}
struct State {
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    limit: usize,
    bytes: usize,
    messages: VecDeque<Message>,
    sent: u64,
    received: u64,
    changed: u64,
    sender: u32,
    receiver: u32,
    sender_reference: Option<PidReference>,
    receiver_reference: Option<PidReference>,
    dead: bool,
}
#[derive(Clone)]
struct Message {
    kind: i64,
    data: Vec<u8>,
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
impl State {
    fn allowed(&self, c: &Credentials, bits: u32, owner: &UserNamespace) -> bool {
        let shift = if c.euid == self.uid || c.euid == self.cuid {
            6
        } else if c.egid == self.gid
            || c.egid == self.cgid
            || c.groups.contains(&self.gid)
            || c.groups.contains(&self.cgid)
        {
            3
        } else {
            0
        };
        self.mode >> shift & bits == bits || c.has_ns_cap(owner, capabilities::IPC_OWNER)
    }
    fn controls(&self, c: &Credentials, owner: &UserNamespace) -> bool {
        c.euid == self.uid || c.euid == self.cuid || c.has_ns_cap(owner, capabilities::SYS_ADMIN)
    }
}

/// Accepted operation retains its original queue even if the ID is removed.
/// No directory lookup, guest pointer import or message copy is replayed.
pub struct Request {
    queue: Arc<Queue>,
    credentials: Credentials,
    pid: u32,
    reference: Option<PidReference>,
    operation: Operation,
}
enum Operation {
    Send(Message),
    Receive {
        kind: i64,
        length: usize,
        flags: u32,
    },
}
pub enum Reply {
    Sent,
    Received { kind: i64, data: Vec<u8> },
}
impl Request {
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.queue.ready.subscribe(signal)
    }
    pub fn attempt(&self) -> Result<Reply> {
        let mut state = self.queue.state.lock().unwrap();
        if state.dead {
            return Err(Errno(43));
        }
        let result = match &self.operation {
            Operation::Send(message) => {
                if !state.allowed(&self.credentials, 2, &self.queue.owner) {
                    return Err(Errno(13));
                }
                if message.data.len() > state.limit.saturating_sub(state.bytes)
                    || state.messages.len() >= state.limit
                {
                    return Err(Errno(11));
                }
                state.bytes += message.data.len();
                state.messages.push_back(message.clone());
                state.sent = now();
                state.sender = self.pid;
                state.sender_reference = self.reference.clone();
                Reply::Sent
            }
            Operation::Receive {
                kind,
                length,
                flags,
            } => {
                if !state.allowed(&self.credentials, 4, &self.queue.owner) {
                    return Err(Errno(13));
                }
                let index = if flags & 0x4000 != 0 {
                    usize::try_from(*kind)
                        .ok()
                        .filter(|i| *i < state.messages.len())
                } else if *kind < 0 {
                    state
                        .messages
                        .iter()
                        .enumerate()
                        .filter(|(_, m)| m.kind <= kind.saturating_neg())
                        .min_by_key(|(_, m)| m.kind)
                        .map(|(i, _)| i)
                } else {
                    state.messages.iter().position(|m| {
                        *kind == 0
                            || if flags & 0x2000 != 0 {
                                m.kind != *kind
                            } else {
                                m.kind == *kind
                            }
                    })
                };
                let Some(index) = index else {
                    return Err(Errno(42));
                };
                if state.messages[index].data.len() > *length && flags & 0x1000 == 0 {
                    return Err(Errno(7));
                }
                if state.messages[index].data.len() > *length && flags & 0x4000 != 0 {
                    // Linux's checkpoint copy cannot truncate its source.
                    return Err(Errno(22));
                }
                let mut message = if flags & 0x4000 != 0 {
                    state.messages[index].clone()
                } else {
                    let message = state.messages.remove(index).unwrap();
                    state.bytes -= message.data.len();
                    state.received = now();
                    state.receiver = self.pid;
                    state.receiver_reference = self.reference.clone();
                    message
                };
                message.data.truncate(*length);
                Reply::Received {
                    kind: message.kind,
                    data: message.data,
                }
            }
        };
        drop(state);
        if !matches!(self.operation, Operation::Receive { flags, .. } if flags & 0x4000 != 0) {
            self.queue.ready.notify_locked();
        }
        Ok(result)
    }
}
impl DescriptorFactory {
    pub fn message_get(&self, key: i32, flags: u32) -> Result<u32> {
        let mut directory = self.ipc_namespace.messages.0.lock().unwrap();
        if key != 0 {
            if let Some(id) = directory.keys.get(&key).copied() {
                if flags & 0x600 == 0x600 {
                    return Err(Errno(17));
                }
                let queue = &directory.queues[&id];
                let bits = ((flags >> 6) | (flags >> 3) | flags) & 7;
                if !queue
                    .state
                    .lock()
                    .unwrap()
                    .allowed(&self.credentials, bits, &queue.owner)
                {
                    return Err(Errno(13));
                }
                return Ok(id);
            }
            if flags & 0x200 == 0 {
                return Err(Errno(2));
            }
        }
        if directory.queues.len() >= MSGMNI || directory.next > i32::MAX as u32 {
            return Err(Errno(28));
        }
        let id = directory.next;
        directory.next += 1;
        let c = &self.credentials;
        let queue = Arc::new(Queue {
            key,
            owner: self.ipc_namespace.user_namespace.clone(),
            ready: Arc::default(),
            state: Mutex::new(State {
                uid: c.euid,
                gid: c.egid,
                cuid: c.euid,
                cgid: c.egid,
                mode: flags & 0o777,
                limit: MSGMNB,
                bytes: 0,
                messages: VecDeque::new(),
                sent: 0,
                received: 0,
                changed: now(),
                sender: 0,
                receiver: 0,
                sender_reference: None,
                receiver_reference: None,
                dead: false,
            }),
        });
        directory.queues.insert(id, queue);
        if key != 0 {
            directory.keys.insert(key, id);
        }
        Ok(id)
    }
    fn message_queue(&self, id: u32) -> Result<Arc<Queue>> {
        self.ipc_namespace
            .messages
            .0
            .lock()
            .unwrap()
            .queues
            .get(&id)
            .cloned()
            .ok_or(Errno(22))
    }
    pub fn message_send(&self, id: u32, kind: i64, data: Vec<u8>, pid: u32) -> Result<Request> {
        if data.len() > MSGMAX || kind <= 0 {
            return Err(Errno(22));
        }
        Ok(Request {
            queue: self.message_queue(id)?,
            credentials: self.credentials.clone(),
            pid,
            reference: self.pid_namespace.retain(pid),
            operation: Operation::Send(Message { kind, data }),
        })
    }
    pub fn message_receive(
        &self,
        id: u32,
        kind: i64,
        length: usize,
        flags: u32,
        pid: u32,
    ) -> Result<Request> {
        if length > isize::MAX as usize
            || flags & 0x4000 != 0 && (flags & 0x800 == 0 || flags & 0x2000 != 0)
        {
            return Err(Errno(22));
        }
        Ok(Request {
            queue: self.message_queue(id)?,
            credentials: self.credentials.clone(),
            pid,
            reference: self.pid_namespace.retain(pid),
            operation: Operation::Receive {
                kind,
                length,
                flags,
            },
        })
    }
    /// ABI bytes are imported/exported by Linux; this capability contains no
    /// guest memory or task table. IPC_SET commits all metadata together.
    pub fn message_control(
        &self,
        id: u32,
        command: u32,
        input: Option<&[u8; 120]>,
    ) -> Result<(u64, Vec<u8>)> {
        let command = command & !0x100;
        if matches!(command, 3 | 12) {
            let directory = self.ipc_namespace.messages.0.lock().unwrap();
            let mut fields = [
                512000i32,
                16384,
                MSGMAX as i32,
                MSGMNB as i32,
                MSGMNI as i32,
                16,
                16384,
                65535,
            ];
            if command == 12 {
                fields[0] = directory.queues.len() as i32;
                fields[1] = 0;
                fields[6] = 0;
                for queue in directory.queues.values() {
                    let state = queue.state.lock().unwrap();
                    fields[1] += state.messages.len() as i32;
                    fields[6] += state.bytes as i32;
                }
            }
            return Ok((
                directory.queues.keys().next_back().copied().unwrap_or(0) as u64,
                fields.into_iter().flat_map(i32::to_le_bytes).collect(),
            ));
        }
        let queue = self.message_queue(id)?;
        let mut state = queue.state.lock().unwrap();
        if state.dead {
            return Err(Errno(43));
        }
        let c = &self.credentials;
        if matches!(command, 0 | 1) && !state.controls(c, &queue.owner) {
            return Err(Errno(1));
        }
        match command {
            0 => {
                // Directory -> queue is the only nested order. Release the
                // object before removing its directory entry, then revalidate.
                drop(state);
                let mut directory = self.ipc_namespace.messages.0.lock().unwrap();
                let mut state = queue.state.lock().unwrap();
                if state.dead {
                    return Err(Errno(43));
                }
                if !state.controls(c, &queue.owner) {
                    return Err(Errno(1));
                }
                state.dead = true;
                state.messages.clear();
                state.bytes = 0;
                directory.queues.remove(&id);
                if queue.key != 0 {
                    directory.keys.remove(&queue.key);
                }
                drop(state);
                drop(directory);
                queue.ready.notify_locked();
                Ok((0, Vec::new()))
            }
            1 => {
                let bytes = input.ok_or(Errno(14))?;
                let word = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
                let limit = u64::from_le_bytes(bytes[88..96].try_into().unwrap());
                if limit > MSGMNB as u64 && !c.has_ns_cap(&queue.owner, capabilities::SYS_RESOURCE)
                {
                    return Err(Errno(1));
                }
                let uid = c.mapped_id(false, word(4))?;
                let gid = c.mapped_id(true, word(8))?;
                state.uid = uid;
                state.gid = gid;
                state.mode = word(20) & 0o777;
                state.limit = usize::try_from(limit).map_err(|_| Errno(22))?;
                state.changed = now();
                drop(state);
                queue.ready.notify_locked();
                Ok((0, Vec::new()))
            }
            2 | 11 | 13 => {
                if command != 13 && !state.allowed(c, 4, &queue.owner) {
                    return Err(Errno(13));
                }
                let mut bytes = vec![0; 120];
                for (i, value) in [
                    (0, queue.key as u32),
                    (4, c.local_id(false, state.uid)),
                    (8, c.local_id(true, state.gid)),
                    (12, c.local_id(false, state.cuid)),
                    (16, c.local_id(true, state.cgid)),
                    (20, state.mode),
                    (96, self.pid_namespace.local(state.sender)),
                    (100, self.pid_namespace.local(state.receiver)),
                ] {
                    bytes[i..i + 4].copy_from_slice(&value.to_le_bytes());
                }
                for (i, value) in [
                    (48, state.sent),
                    (56, state.received),
                    (64, state.changed),
                    (72, state.bytes as u64),
                    (80, state.messages.len() as u64),
                    (88, state.limit as u64),
                ] {
                    bytes[i..i + 8].copy_from_slice(&value.to_le_bytes());
                }
                Ok((if command == 2 { 0 } else { id as u64 }, bytes))
            }
            _ => Err(Errno(22)),
        }
    }
}
