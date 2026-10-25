// SPDX-License-Identifier: GPL-3.0-or-later
//! Worker io_uring capabilities. No owner Rc graph or namespace crosses threads.
//! A ring lock arbitrates kernel cursors, not unrelated rings or byte resources.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
    sync::Mutex,
};
use trames_memory::{PageBacking, SharedPage, PAGE_SIZE};
use trames_vfs::{
    DirectFd, DirectTcpFd, RetainedFd, Uring, UringRequest, UringSqe, Vfs, URING_CQES,
    URING_SQ_ARRAY,
};
type Result<T> = std::result::Result<T, Errno>;

#[derive(Clone)]
enum Object {
    Byte(DirectFd),
    Tcp(DirectTcpFd),
    File(trames_vfs::DirectFile),
}
#[derive(Clone)]
struct Resource {
    object: Object,
    identity: usize,
    datagram: bool,
}
type FixedFiles = Arc<[Result<Option<Resource>>]>;
impl Resource {
    fn capture(file: &RetainedFd) -> Option<Self> {
        let object = file
            .direct_byte()
            .map(Object::Byte)
            .or_else(|| file.direct_tcp().map(Object::Tcp))?;
        Some(Self {
            object,
            identity: file.identity(),
            datagram: file.datagram(),
        })
    }
    fn regular(file: &RetainedFd, cap: trames_vfs::DirectFile) -> Self {
        Self {
            object: Object::File(cap),
            identity: file.identity(),
            datagram: false,
        }
    }
    fn shared_file(&self) -> Option<trames_vfs::SharedFd> {
        match &self.object {
            Object::Byte(file) => file.shared_file(),
            Object::File(file) => file.shared_file(),
            Object::Tcp(_) => None,
        }
    }
    fn next_deadline(&self) -> Option<Instant> {
        match &self.object {
            Object::Byte(f) => f.next_deadline(),
            Object::Tcp(_) | Object::File(_) => None,
        }
    }
}

struct Request {
    owner: u64,
    task: u32,
    sequence: u64,
    sqe: UringSqe,
    resource: Option<Resource>,
    parts: Option<Vec<(u64, usize)>>,
    requested: u64,
    error: Option<Errno>,
    buffer: Option<Arc<trames_memory::PinnedBuffer>>,
    dependency: Option<(u64, bool)>,
    started: bool,
    deadline: Option<Instant>,
    timeout_count: Option<u64>,
    timeout_target: Option<u64>,
    timeout_duration: Option<Duration>,
    shots: u64,
    poll_ready: u16,
    poll_epoch: [u64; 2],
}
impl Request {
    fn supported(s: &UringSqe) -> bool {
        matches!(
            s.opcode(),
            0 | 1 | 2 | 4 | 5 | 6 | 7 | 11 | 12 | 14 | 15 | 22 | 23 | 26 | 27 | 31 | 32
        )
    }
    fn validate(s: &UringSqe) -> Result<()> {
        let ioprio_mask = if s.opcode() == 27 { 3 } else { 0 };
        let group = matches!(s.opcode(), 4 | 5 | 31 | 32) || s.flags() & 32 != 0;
        if s.flags() & !63 != 0
            || s.ioprio() & !ioprio_mask != 0
            || s.flags() & 32 != 0 && !matches!(s.opcode(), 22 | 27)
            || s.0[40..]
                .iter()
                .enumerate()
                .any(|(i, b)| *b != 0 && !(group && i < 2))
            || s.opcode() == 27
                && s.multishot()
                && (s.flags() & 32 == 0
                    || s.length() != 0
                    || s.op_flags() & (2 | 0x40 | 0x100) != 0)
            || matches!(s.opcode(), 26 | 27) && s.offset() != 0
        {
            return Err(Errno(22));
        }
        Ok(())
    }

    fn metadata(&self) -> usize {
        512 + self.parts.as_ref().map_or(0, |p| p.len() * 16)
    }
    fn events(&self) -> u16 {
        match self.sqe.opcode() {
            2 | 5 | 23 | 26 => 4,
            6 => self.sqe.op_flags() as u16,
            _ => 1,
        }
    }
    fn nowait(&self) -> bool {
        match self.sqe.opcode() {
            1 | 2 | 4 | 5 | 22 | 23 => self.sqe.op_flags() & 8 != 0,
            26 | 27 => self.sqe.op_flags() & 0x40 != 0,
            _ => false,
        }
    }
    fn run(
        &mut self,
        memory: &mut impl CpuMemory,
        scratch: &mut Vec<u8>,
        cache: &mut trames_vfs::DiskReadCache,
        selected: Option<trames_vfs::UringProvidedBuffer>,
    ) -> Option<Result<i32>> {
        if let Some(e) = self.error {
            return Some(Err(e));
        }
        let mut sqe = self.sqe.clone();
        if let Some(b) = selected {
            let count = if sqe.opcode() == 27 && sqe.length() == 0 {
                b.length
            } else {
                b.length.min(sqe.length())
            };
            sqe.0[16..24].copy_from_slice(&b.address.to_le_bytes());
            sqe.0[24..28].copy_from_slice(&count.to_le_bytes());
        }
        let s = &sqe;
        if s.opcode() == 0 {
            return Some(if s.op_flags() == 0 {
                Ok(0)
            } else {
                Err(Errno(22))
            });
        }
        let resource = self.resource.as_ref()?;
        if s.opcode() == 6 {
            return match &resource.object {
                Object::Byte(f) => Some(
                    if s.length() & !9 != 0
                        || s.length() & 8 != 0 && !s.multishot()
                        || s.op_flags() & !0x201f != 0
                    {
                        Err(Errno(22))
                    } else {
                        let (events, epoch) = f.poll_state(s.op_flags() as u16)?;
                        let fresh = !s.multishot()
                            || s.length() & 8 != 0
                            || events & !self.poll_ready != 0
                            || events & 3 != 0 && epoch[0] != self.poll_epoch[0]
                            || events & 4 != 0 && epoch[1] != self.poll_epoch[1];
                        if events == 0 || !fresh {
                            if events == 0 {
                                self.poll_ready = 0;
                                self.poll_epoch = epoch;
                            }
                            Err(Errno(11))
                        } else {
                            self.poll_ready = events;
                            self.poll_epoch = epoch;
                            Ok(events as i32)
                        }
                    },
                ),
                // Native TCP poll has no public zero-time readiness capability.
                Object::Tcp(_) | Object::File(_) => None,
            };
        }
        let network = matches!(s.opcode(), 26 | 27);
        let write = matches!(s.opcode(), 2 | 5 | 23 | 26);
        if !network
            && !matches!(&resource.object, Object::File(_))
            && !matches!(s.offset(), 0 | u64::MAX)
        {
            return Some(Err(Errno(29)));
        }
        if !network && s.op_flags() & !8 != 0 {
            return Some(Err(Errno(95)));
        }
        let scalar;
        let parts = match &self.parts {
            Some(p) => p.as_slice(),
            None => {
                scalar = [(s.address(), (s.length() as usize).min(crate::MAX_WRITE))];
                &scalar
            }
        };
        let count = parts.iter().map(|p| p.1).sum();
        let checked = parts
            .iter()
            .filter(|p| p.1 != 0 && self.buffer.is_none())
            .try_for_each(|&(a, n)| {
                Linux::check(
                    memory,
                    a,
                    n,
                    if write { Access::Read } else { Access::Write },
                )
            });
        if let Err(e) = checked {
            // Selected pools validate data only when an I/O can issue. The
            // original owner probes readiness before touching a selected VA;
            // keep its EAGAIN/no-consumption rule on this cold fault path.
            if selected.is_some() {
                let empty = match &resource.object {
                    Object::Byte(f) => f.poll_ready(1) == Some(0),
                    Object::Tcp(f) if f.flags & trames_vfs::O_PATH == 0 && f.flags & 3 != 1 => {
                        f.tcp.recv(1, 2 | 0x40).is_err_and(|e| e.0 == 11)
                    }
                    _ => false,
                };
                if empty {
                    return Some(Err(Errno(11)));
                }
            }
            return Some(Err(e));
        }
        let flags = if network { s.op_flags() } else { 0 };
        if write {
            let gathered = if let Some(buffer) = &self.buffer {
                scratch.resize(count, 0);
                buffer
                    .range(s.address(), count)
                    .and_then(|offset| buffer.read_into(offset, scratch))
                    .map_err(|_| Errno(14))
            } else {
                Linux::gather_parts(memory, parts, count, scratch)
            };
            if let Err(e) = gathered {
                return Some(Err(e));
            }
            Some(
                match &resource.object {
                    Object::Byte(f) if network => f.send(scratch, flags),
                    Object::Byte(f) => f.write(scratch),
                    Object::File(_) if network => Err(Errno(88)),
                    Object::File(f) => f.write(
                        scratch,
                        (s.offset() != u64::MAX).then_some(s.offset()),
                        cache,
                    )?,
                    Object::Tcp(f) => {
                        if f.flags & trames_vfs::O_PATH != 0 || f.flags & 3 == 0 {
                            Err(Errno(9))
                        } else {
                            f.tcp.send(scratch, flags).map_err(|e| Errno(e.0))
                        }
                    }
                }
                .map(|n| n as i32),
            )
        } else {
            if network {
                if let Object::Byte(f) = &resource.object {
                    return Some(f.recv_counted(count, flags)?.and_then(|(bytes, length)| {
                        Linux::scatter(memory, parts, &bytes)?;
                        Ok(length as i32)
                    }));
                }
            }
            let bytes = match &resource.object {
                Object::Byte(f) if network => f.recv(count, flags)?,
                Object::Byte(f) => f.read_attempt(count)?,
                Object::File(_) if network => Err(Errno(88)),
                Object::File(f) => {
                    f.read(count, (s.offset() != u64::MAX).then_some(s.offset()), cache)?
                }
                Object::Tcp(f) => {
                    if f.flags & trames_vfs::O_PATH != 0 || f.flags & 3 == 1 {
                        Err(Errno(9))
                    } else {
                        f.tcp.recv(count, flags).map_err(|e| Errno(e.0))
                    }
                }
            };
            Some(bytes.and_then(|b| {
                if let Some(buffer) = &self.buffer {
                    buffer
                        .range(s.address(), b.len())
                        .and_then(|offset| buffer.write(offset, &b))
                        .map_err(|_| Errno(14))?;
                } else {
                    Linux::scatter(memory, parts, &b)?;
                }
                Ok(b.len() as i32)
            }))
        }
    }
}

struct Queue {
    entries: u32,
    cq_entries: u32,
    ring_bytes: usize,
    pages: Vec<Arc<SharedPage>>,
}
impl Queue {
    fn read<const N: usize>(&self, offset: usize) -> [u8; N] {
        let mut bytes = [0; N];
        // All ABI cells/slots fit in a page. Kernel-private offsets bound them.
        self.pages[offset / PAGE_SIZE as usize]
            .with_read(offset % PAGE_SIZE as usize, N, |b| bytes.copy_from_slice(b));
        bytes
    }
    fn write(&self, offset: usize, bytes: &[u8]) {
        self.pages[offset / PAGE_SIZE as usize].with_write(
            offset % PAGE_SIZE as usize,
            bytes.len(),
            |b| b.copy_from_slice(bytes),
        );
    }
    fn load(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.read(offset))
    }
    fn store(&self, offset: usize, value: u32) {
        self.write(offset, &value.to_le_bytes());
    }
    fn sqe(&self, head: u32) -> Option<UringSqe> {
        let index = self.load(URING_SQ_ARRAY + (head & (self.entries - 1)) as usize * 4);
        (index < self.entries).then(|| UringSqe(self.read(self.ring_bytes + index as usize * 64)))
    }
    fn cq_head(&self, state: &State) -> Result<u32> {
        let head = self.load(64);
        if state.tail.wrapping_sub(head) > self.cq_entries {
            Err(Errno(22))
        } else {
            Ok(head)
        }
    }
    fn flush(&self, state: &mut State) -> Result<()> {
        let head = self.cq_head(state)?;
        let mut count = 0u64;
        while state.tail.wrapping_sub(head) < self.cq_entries {
            let Some((data, res, flags)) = state.overflow.pop_front() else {
                break;
            };
            let mut b = [0; 16];
            b[..8].copy_from_slice(&data.to_le_bytes());
            b[8..12].copy_from_slice(&res.to_le_bytes());
            b[12..].copy_from_slice(&flags.to_le_bytes());
            self.write(
                URING_CQES + (state.tail & (self.cq_entries - 1)) as usize * 16,
                &b,
            );
            state.tail = state.tail.wrapping_add(1);
            count += 1;
        }
        // SharedPage's existing range release/acquire publishes CQ bytes to
        // guest CPUs; do not layer a second fence or raw atomic alias over it.
        self.store(68, state.tail);
        self.store(16, if state.overflow.is_empty() { 0 } else { 2 });
        if count != 0 && self.load(84) & 1 == 0 {
            if let Some(f) = &state.eventfd {
                let _ = f.write(&count.to_le_bytes());
            }
        }
        Ok(())
    }
}
#[derive(Default)]
struct State {
    head: u32,
    tail: u32,
    dropped: u32,
    next: u64,
    completion_count: u64,
    overflow: VecDeque<(u64, i32, u32)>,
    completed: BTreeMap<u64, bool>,
    pending: VecDeque<Request>,
    active: BTreeSet<u64>,
    drains: BTreeSet<u64>,
    dependencies: BTreeMap<u64, usize>,
    inflight: usize,
    inflight_metadata: usize,
    waits: BTreeMap<u32, (u32, Option<Instant>)>,
    eventfd: Option<DirectFd>,
    disabled: bool,
    scratch: Vec<u8>,
    cache: trames_vfs::DiskReadCache,
    buffers: Option<Vec<Arc<trames_memory::PinnedBuffer>>>,
    provided: BTreeMap<u16, trames_vfs::UringBufferGroup>,
    busy_groups: BTreeSet<u16>,
    contended_groups: BTreeSet<u16>,
    multishot_cursor: u64,
    running: BTreeMap<u64, Running>,
    shot_reservations: usize,
}
struct Ring {
    identity: usize,
    queue: Queue,
    state: Mutex<State>,
    readiness: Arc<trames_vfs::Readiness>,
}
impl State {
    fn insert(&mut self, r: Request) {
        self.active.insert(r.sequence);
        if r.sqe.flags() & 2 != 0 {
            self.drains.insert(r.sequence);
        }
        if let Some((parent, _)) = r.dependency {
            *self.dependencies.entry(parent).or_default() += 1;
        }
        self.pending.push_back(r);
    }
    fn eligible(&self, r: &Request) -> bool {
        let linked = r.sqe.opcode() == 15;
        // Only a linked timer can bypass its own predecessor. At most one
        // sequence is excluded, so either lookup visits at most two entries.
        let earlier = |set: &BTreeSet<u64>| {
            set.iter()
                .copied()
                .find(|&id| !linked || r.timeout_target != Some(id))
                .is_some_and(|id| id < r.sequence)
        };
        !earlier(&self.drains)
            && !(r.sqe.flags() & 2 != 0 && earlier(&self.active))
            && (linked
                || r.dependency
                    .is_none_or(|(id, _)| self.completed.contains_key(&id)))
    }

    fn finish_request(
        &mut self,
        mut r: Request,
        result: Result<(i32, bool)>,
        flags: u32,
    ) -> (bool, Option<Request>) {
        let (value, success) = result.unwrap_or_else(|e| (-(e.0 as i32), false));
        r.shots = r.shots.saturating_add(1);
        let repeating = r.sqe.opcode() == 11
            && r.sqe.multishot()
            && matches!(value, 0 | -62)
            && r.error.is_none();
        let more = r.sqe.multishot()
            && r.error.is_none()
            && match r.sqe.opcode() {
                6 => value >= 0,
                27 => value > 0 || value == 0 && r.resource.as_ref().is_some_and(|f| f.datagram),
                11 => repeating && (r.sqe.offset() == 0 || r.shots < r.sqe.offset()),
                _ => false,
            };
        self.post(
            &r,
            Ok(value),
            flags | if more { 2 } else { 0 },
            (!more).then_some(success),
        );
        if more {
            self.multishot_cursor = r.sequence;
            if repeating {
                r.deadline = r
                    .timeout_duration
                    .and_then(|d| Instant::now().checked_add(d));
            }
            self.pending.push_back(r);
            (true, None)
        } else {
            // Actual OFD final-close callbacks run after the ring lock drops.
            (false, Some(r))
        }
    }

    fn terminal(&mut self, r: &Request, result: Result<i32>) {
        let success = result.as_ref().is_ok_and(|&n| {
            !matches!(r.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23 | 26 | 27) || n as u64 == r.requested
        });
        self.post(r, result, 0, Some(success));
    }
    fn post(&mut self, r: &Request, result: Result<i32>, flags: u32, terminal: Option<bool>) {
        if let Some(success) = terminal {
            self.active.remove(&r.sequence);
            self.drains.remove(&r.sequence);
            if self.dependencies.contains_key(&r.sequence) {
                self.completed.insert(r.sequence, success);
            }
            if let Some((parent, _)) = r.dependency {
                if let Some(count) = self.dependencies.get_mut(&parent) {
                    *count -= 1;
                    if *count == 0 {
                        self.dependencies.remove(&parent);
                        self.completed.remove(&parent);
                    }
                }
            }
        }
        if !matches!(r.sqe.opcode(), 11 | 15) {
            self.completion_count = self.completion_count.saturating_add(1);
        }
        self.overflow.push_back((
            r.sqe.user_data(),
            result.unwrap_or_else(|e| -(e.0 as i32)),
            flags,
        ));
    }
}
#[path = "uring/control.rs"]
mod control;
use control::Running;
#[path = "uring/poll.rs"]
mod poll;
mod wait;
pub(super) use poll::PollWait;

impl Ring {
    fn outstanding(&self, state: &State) -> usize {
        let unread = state
            .tail
            .wrapping_sub(self.queue.load(64))
            .min(self.queue.cq_entries) as usize;
        state.pending.len()
            + state.inflight
            + state.overflow.len()
            + unread
            + state.shot_reservations
    }
    fn backpressured(&self, state: &State, r: &Request) -> bool {
        r.sqe.multishot()
            && r.error.is_none()
            && self.outstanding(state) >= (self.queue.entries as usize * 8).min(8192)
    }
    fn progress(&self, memory: &mut impl CpuMemory, owner: u64, task: u32) -> bool {
        let (mut scratch, mut cache, mut cutoff) = {
            let mut state = self.state.lock().unwrap();
            (
                std::mem::take(&mut state.scratch),
                std::mem::take(&mut state.cache),
                state.multishot_cursor,
            )
        };
        let mut deferred = false;
        let mut attempted = BTreeSet::new();
        // Allocates only for cancellation/linked-timeout batches. Ordinary
        // completed requests return their one retired value without a Vec push.
        let mut cancelled = Vec::new();
        let mut budget = 64;
        loop {
            let mut state = self.state.lock().unwrap();
            let mut candidate = None;
            let mut contended = Vec::new();
            for (i, r) in state.pending.iter().enumerate() {
                if r.owner != owner
                    || r.task != task
                    || attempted.contains(&r.sequence)
                    || !state.eligible(r)
                {
                    continue;
                }
                if (r.selected() || matches!(r.sqe.opcode(), 31 | 32))
                    && state.busy_groups.contains(&r.sqe.buffer_group())
                {
                    contended.push(r.sqe.buffer_group());
                    continue;
                }
                if r.sqe.multishot()
                    && r.error.is_none()
                    && (budget == 0 || r.sequence <= cutoff || self.backpressured(&state, r))
                {
                    continue;
                }
                candidate = Some(i);
                break;
            }
            state.contended_groups.extend(contended);
            let Some(index) = candidate else {
                if cutoff != 0 && budget != 0 {
                    cutoff = 0;
                    state.multishot_cursor = 0;
                    continue;
                }
                state.scratch = scratch;
                state.cache = cache;
                break;
            };
            let mut r = state.pending.remove(index).unwrap();
            if r.sqe.opcode() != 15
                && r.dependency.is_some_and(|(parent, hard)| {
                    !hard && state.completed.get(&parent) == Some(&false)
                })
            {
                state.terminal(&r, Err(Errno(125)));
                drop(state);
                self.readiness.notify_locked();
                attempted.clear();
                continue;
            }
            if let Some(result) = state.control(&mut r, &mut cancelled) {
                if result == Err(Errno(11)) && r.error.is_none() && !r.nowait() {
                    attempted.insert(r.sequence);
                    state.pending.push_back(r);
                    continue;
                }
                let (more, retired) = state.finish_request(r, result, 0);
                if more {
                    budget -= 1;
                }
                attempted.clear();
                drop(state);
                drop(retired);
                cancelled.clear();
                self.readiness.notify_locked();
                continue;
            }
            let mut selected = None;
            let mut selected_error = None;
            if r.selected() {
                match crate::uring::buffers::peek(&r.sqe, r.owner, &state.provided) {
                    Ok(buffer) => {
                        selected = Some(buffer);
                        state.busy_groups.insert(r.sqe.buffer_group());
                    }
                    Err(e) => selected_error = Some(e),
                }
            }
            let reserved = r.sqe.multishot() && r.error.is_none();
            state.shot_reservations += usize::from(reserved);
            state.inflight += 1;
            state.inflight_metadata += r.metadata();
            state.running.insert(r.sequence, r.running());
            drop(state);
            // Only imported metadata/control runs under the object lock. Byte
            // transport and guest memory borrows remain on this worker outside it.
            let result = if let Some(e) = selected_error {
                Some(Err(e))
            } else {
                r.started = true;
                let requested = selected.map_or(r.requested, |b| {
                    if r.sqe.opcode() == 27 && r.sqe.length() == 0 {
                        b.length as u64
                    } else {
                        b.length.min(r.sqe.length()) as u64
                    }
                });
                r.run(memory, &mut scratch, &mut cache, selected)
                    .map(|result| {
                        result.map(|n| {
                            (
                                n,
                                !matches!(r.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23 | 26 | 27)
                                    || n as u64 == requested,
                            )
                        })
                    })
            };
            let mut state = self.state.lock().unwrap();
            state.running.remove(&r.sequence);
            state.inflight -= 1;
            state.inflight_metadata -= r.metadata();
            state.shot_reservations -= usize::from(reserved);
            let mut notify = false;
            let consumed =
                selected.filter(|_| result.is_some() && !matches!(result, Some(Err(Errno(11)))));
            let flags = if let Some(buffer) = consumed {
                let group = state
                    .provided
                    .get_mut(&r.sqe.buffer_group())
                    .expect("leased provided group");
                match &mut group.source {
                    trames_vfs::UringBufferSource::Classic(buffers) => {
                        buffers.pop_front();
                    }
                    trames_vfs::UringBufferSource::Ring { head, .. } => {
                        *head = head.wrapping_add(1)
                    }
                }
                1 | (buffer.id as u32) << 16
            } else {
                0
            };
            if selected.is_some() {
                state.busy_groups.remove(&r.sqe.buffer_group());
                notify |= state.contended_groups.remove(&r.sqe.buffer_group());
            }
            let mut retired = None;
            match result {
                None => {
                    deferred = true;
                    attempted.insert(r.sequence);
                    state.pending.push_back(r);
                }
                Some(Err(Errno(11))) if r.error.is_none() && !r.nowait() => {
                    attempted.insert(r.sequence);
                    state.pending.push_back(r);
                }
                Some(result) => {
                    let (more, completed) = state.finish_request(r, result, flags);
                    if more {
                        budget -= 1;
                    }
                    retired = completed;
                    attempted.clear();
                    notify = true;
                }
            }
            drop(state);
            drop(retired);
            if notify {
                self.readiness.notify_locked();
            }
        }
        deferred
    }
}

/// Send capability owned by one task's frozen syscall snapshot.
#[derive(Default)]
pub struct UringSnapshot {
    rings: BTreeMap<u32, Arc<Ring>>,
    // Only excluded owner controls are frozen. Shared slots resolve live at
    // SQE acceptance and the request owns the resulting original OFD.
    resources: BTreeMap<u32, Resource>,
    membership: Option<trames_vfs::SharedFiles>,
    files: trames_vfs::DirectFiles,
    valid_fds: BTreeSet<u32>,
    fixed: BTreeMap<u32, FixedFiles>,
    owner: u64,
    task: u32,
    completed: Cell<u64>,
    pub(super) clock: Option<Instant>,
    pub(super) descriptors: Option<trames_vfs::DirectFds>,
    poll_rings: BTreeMap<usize, Arc<Ring>>,
}
impl UringSnapshot {
    fn resource(&self, fd: u32) -> Result<Option<Resource>> {
        if let Some(file) = self.membership.as_ref().and_then(|files| files.lookup(fd)) {
            let file = file?;
            let identity = file.identity();
            let object = file
                .clone()
                .direct_byte()
                .map(Object::Byte)
                .or_else(|| self.files.accept(file).map(Object::File));
            return Ok(object.map(|object| Resource {
                object,
                identity,
                datagram: false,
            }));
        }
        if self.valid_fds.contains(&fd) {
            Ok(self.resources.get(&fd).cloned())
        } else {
            Err(Errno(9))
        }
    }
    pub fn contains(&self, fd: u32) -> bool {
        self.rings.contains_key(&fd)
    }
    pub fn completed(&self) -> u64 {
        self.completed.get()
    }
    pub(super) fn supports_register(&self, args: [u64; 6]) -> bool {
        self.contains(args[0] as u32) && matches!(args[1], 1 | 5 | 8 | 23 | 26)
    }
    pub(super) fn register(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
    ) -> Option<IoAttempt> {
        if !self.supports_register(args) {
            return None;
        }
        let ring = self.rings.get(&(args[0] as u32))?;
        if pid != self.task {
            return Some(IoAttempt::Checkpoint);
        }
        let mut state = ring.state.lock().unwrap();
        if state.disabled {
            return Some(IoAttempt::Checkpoint);
        }
        if args[1] == 23 && !state.busy_groups.is_empty() {
            // Unregister cannot invalidate a selected buffer's active lease.
            return Some(IoAttempt::Checkpoint);
        }
        let result = (|| match args[1] {
            1 | 5 => {
                if args[2] != 0 || args[3] != 0 {
                    return Err(Errno(22));
                }
                if args[1] == 1 {
                    state.buffers.take().ok_or(Errno(6))?;
                } else {
                    state.eventfd.take().ok_or(Errno(6))?;
                }
                Ok(0)
            }
            8 => crate::uring::probe(args, memory),
            23 | 26 => crate::uring::buffers::ring_control(&mut state.provided, args, memory),
            _ => unreachable!(),
        })();
        drop(state);
        ring.readiness.notify_locked();
        self.completed.set(self.completed.get() + 1);
        Some(IoAttempt::Complete(result))
    }
    pub(super) fn start(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let ring = self.rings.get(&(args[0] as u32))?.clone();
        if pid != self.task {
            return Some(IoAttempt::Checkpoint);
        }
        let mut state = ring.state.lock().unwrap();
        if state.disabled {
            return Some(IoAttempt::Checkpoint);
        }
        if args[2] > ring.queue.cq_entries as u64 {
            state.waits.remove(&pid);
            return Some(IoAttempt::Complete(Err(Errno(22))));
        }
        let head = match ring.queue.cq_head(&state) {
            Ok(h) => h,
            Err(e) => {
                state.waits.remove(&pid);
                return Some(IoAttempt::Complete(Err(e)));
            }
        };
        if !state.waits.contains_key(&pid) {
            let deadline = match crate::uring::time::enter_deadline(
                args,
                memory,
                self.clock.unwrap_or_else(Instant::now),
            ) {
                Ok(deadline) => deadline,
                Err(e) => return Some(IoAttempt::Complete(Err(e))),
            };
            let available = ring.queue.load(4).wrapping_sub(state.head);
            if available > ring.queue.entries {
                return Some(IoAttempt::Complete(Err(Errno(22))));
            }
            let count = available.min(args[1] as u32);
            let limit = (ring.queue.entries as usize * 8).min(8192);
            if state.pending.len()
                + state.inflight
                + state.overflow.len()
                + state.tail.wrapping_sub(head) as usize
                + count as usize
                > limit
            {
                return Some(IoAttempt::Complete(Err(Errno(16))));
            }
            // Import the complete accepted batch before the first effect. A
            // mixed/unsupported batch takes the owner path without consuming it.
            let mut prepared = Vec::new();
            let mut metadata = state.inflight_metadata
                + state.pending.iter().map(Request::metadata).sum::<usize>();
            let mut previous = None;
            let mut sequence = state.next;
            for i in 0..count {
                let Some(s) = ring.queue.sqe(state.head.wrapping_add(i)) else {
                    prepared.push(None);
                    previous = None;
                    continue;
                };
                if !Request::supported(&s) {
                    state.disabled = true;
                    return Some(IoAttempt::Checkpoint);
                }
                let mut error = Request::validate(&s).err();
                let takes_file = matches!(s.opcode(), 1 | 2 | 4 | 5 | 6 | 22 | 23 | 26 | 27)
                    || s.opcode() == 14 && s.op_flags() & 2 != 0;
                let resource = if error.is_some() {
                    None
                } else if !takes_file {
                    if s.flags() & 1 != 0 {
                        error = Some(Errno(22));
                    }
                    None
                } else if s.flags() & 1 != 0 || s.opcode() == 14 && s.op_flags() & 8 != 0 {
                    match self
                        .fixed
                        .get(&(args[0] as u32))
                        .and_then(|files| files.get(s.fd() as usize))
                    {
                        Some(Ok(Some(f))) => Some(f.clone()),
                        Some(Err(_)) => {
                            state.disabled = true;
                            return Some(IoAttempt::Checkpoint);
                        }
                        _ => {
                            error = Some(Errno(9));
                            None
                        }
                    }
                } else {
                    match self.resource(s.fd() as u32) {
                        Ok(Some(file)) => Some(file),
                        Err(e) => {
                            error = Some(e);
                            None
                        }
                        Ok(None) => {
                            state.disabled = true;
                            return Some(IoAttempt::Checkpoint);
                        }
                    }
                };
                if let Some(f) = &resource {
                    if s.opcode() == 6 && matches!(&f.object, Object::Tcp(_) | Object::File(_)) {
                        state.disabled = true;
                        return Some(IoAttempt::Checkpoint);
                    }
                    if matches!(&f.object, Object::Tcp(_))
                        && matches!(s.opcode(), 26 | 27)
                        && s.op_flags()
                            & !(if s.opcode() == 26 {
                                0x40 | 0x4000
                            } else {
                                2 | 0x40
                            })
                            != 0
                    {
                        state.disabled = true;
                        return Some(IoAttempt::Checkpoint);
                    }
                }
                let buffer = if matches!(s.opcode(), 4 | 5) {
                    match state
                        .buffers
                        .as_ref()
                        .and_then(|b| b.get(s.buffer_group() as usize))
                    {
                        Some(b) if b.range(s.address(), s.length() as usize).is_ok() => {
                            Some(b.clone())
                        }
                        _ => {
                            error = Some(Errno(14));
                            None
                        }
                    }
                } else {
                    None
                };
                let mut r = Request {
                    owner: self.owner,
                    task: pid,
                    sequence: sequence + 1,
                    requested: s.length() as u64,
                    sqe: s,
                    resource,
                    parts: None,
                    error,
                    buffer,
                    dependency: previous,
                    started: false,
                    deadline: None,
                    timeout_count: None,
                    timeout_target: None,
                    timeout_duration: None,
                    shots: 0,
                    poll_ready: 0,
                    poll_epoch: [0; 2],
                };
                r.import_timer(memory, self.clock.unwrap_or_else(Instant::now));
                if matches!(r.sqe.opcode(), 1 | 2) {
                    match Linux::positioned_vector_import(
                        memory,
                        [0, r.sqe.address(), r.sqe.length() as u64, 0, 0, 0],
                        r.sqe.opcode() == 2,
                    ) {
                        Ok(vector) => {
                            r.requested = vector.requested;
                            r.parts = Some(vector.parts);
                        }
                        Err(e) => r.error = Some(e),
                    }
                }
                metadata += r.metadata();
                if metadata > 1024 * 1024 {
                    break;
                }
                sequence = r.sequence;
                previous = if r.sqe.flags() & (4 | 8) != 0 {
                    Some((r.sequence, r.sqe.flags() & 8 != 0))
                } else {
                    None
                };
                prepared.push(Some(r));
            }
            if count != 0 && prepared.is_empty() {
                return Some(IoAttempt::Complete(Err(Errno(16))));
            }
            let submitted = prepared.len() as u32;
            for request in prepared {
                state.head = state.head.wrapping_add(1);
                if let Some(r) = request {
                    state.next = r.sequence;
                    state.insert(r);
                } else {
                    state.dropped = state.dropped.wrapping_add(1);
                }
            }
            ring.queue.store(0, state.head);
            ring.queue.store(20, state.dropped);
            state.waits.insert(pid, (submitted, deadline));
        }
        drop(state);
        let deferred = ring.progress(memory, self.owner, pid);
        let mut state = ring.state.lock().unwrap();
        let tail = state.tail;
        if ring.queue.flush(&mut state).is_err() {
            return Some(IoAttempt::Checkpoint);
        }
        let ready = args[3] & 1 == 0
            || args[2] == 0
            || state.tail.wrapping_sub(ring.queue.load(64)) >= args[2] as u32;
        let (submitted, deadline) = state.waits.get(&pid).copied().unwrap_or((0, None));
        let expired = deadline.is_some_and(|d| Instant::now() >= d);
        if ready || expired {
            state.waits.remove(&pid);
        }
        let changed = tail != state.tail;
        drop(state);
        if changed {
            ring.readiness.notify_locked();
        }
        if ready || expired {
            self.completed.set(self.completed.get() + 1);
            return Some(IoAttempt::Complete(if !ready && submitted == 0 {
                Err(Errno(62))
            } else {
                Ok(submitted as u64)
            }));
        }
        if deferred {
            return Some(IoAttempt::Checkpoint);
        }
        let signal = IoSignal::new(pid, target.clone());
        self.resume(
            PendingIo {
                number: 426,
                args,
                deadline,
                signal,
                resource_deadline: None,
                flock: None,
                retained_byte: None,
                retained_poll: None,
                _subscriptions: Vec::new(),
                host_subscription: None,
                poll_uring: None,
                target: target.clone(),
                uring: Some(Box::new(Wait {
                    ring,
                    owner: self.owner,
                    task: pid,
                    sources: wait::WaitSources::default(),
                    target: target.clone(),
                })),
            },
            memory,
        )
        .into()
    }
    pub(super) fn resume(&self, mut pending: PendingIo, memory: &mut impl CpuMemory) -> IoAttempt {
        pending.signal.reset();
        let wait = pending.uring.as_mut().unwrap();
        if !wait.sources.refresh(
            std::slice::from_ref(&wait.ring),
            wait.owner,
            wait.task,
            &pending.signal,
            &wait.target,
        ) {
            return IoAttempt::Checkpoint;
        }
        let deferred = wait.ring.progress(memory, wait.owner, wait.task);
        let mut state = wait.ring.state.lock().unwrap();
        let tail = state.tail;
        if wait.ring.queue.flush(&mut state).is_err() {
            return IoAttempt::Checkpoint;
        }
        let changed = tail != state.tail;
        let (submitted, deadline) = state
            .waits
            .get(&wait.task)
            .copied()
            .unwrap_or((0, pending.deadline));
        pending.deadline = deadline;
        let ready = pending.args[3] & 1 == 0
            || pending.args[2] == 0
            || state.tail.wrapping_sub(wait.ring.queue.load(64)) >= pending.args[2] as u32;
        let expired = deadline.is_some_and(|d| Instant::now() >= d);
        if ready || expired {
            state.waits.remove(&wait.task);
        }
        let checkpoint = deferred || state.disabled;
        drop(state);
        pending.resource_deadline = wait.ring.request_deadline(wait.owner, wait.task);
        if changed {
            wait.ring.readiness.notify_locked();
        }
        if ready || expired {
            self.completed.set(self.completed.get() + 1);
            return IoAttempt::Complete(if !ready && submitted == 0 {
                Err(Errno(62))
            } else {
                Ok(submitted as u64)
            });
        }
        if checkpoint {
            return IoAttempt::Checkpoint;
        }
        IoAttempt::Blocked(pending)
    }
}
pub(super) struct Wait {
    ring: Arc<Ring>,
    owner: u64,
    task: u32,
    sources: wait::WaitSources,
    target: Weak<dyn IoWake>,
}
impl Wait {
    pub fn external(&self) -> bool {
        self.sources.external()
    }
}

struct Owner {
    ring: Rc<Uring>,
    direct: Arc<Ring>,
    _pages: Vec<Rc<dyn PageBacking>>,
    // Strong original OFDs, including already-closed accepted descriptions.
    originals: BTreeMap<(u32, u64), RetainedFd>,
    descriptors: BTreeMap<(u32, u32), RetainedFd>,
    fixed: BTreeMap<(u32, u32), RetainedFd>,
    tasks: BTreeSet<u32>,
}
#[derive(Default)]
pub struct UringEpoch {
    owners: BTreeMap<usize, Owner>,
}
pub struct UringHandoff {
    pub task: u32,
    pub submitted: Option<u32>,
    pub ring: Rc<Uring>,
    pub deadline: Option<Instant>,
}
impl UringEpoch {
    pub fn has_native_wait(ring: &Rc<Uring>, owner: u64, task: u32) -> bool {
        ring.state.borrow().pending.iter().any(|r| {
            r.owner == owner
                && r.task == task
                && r.started
                && matches!(r.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23 | 26 | 27)
                && r.file.as_ref().is_some_and(|f| f.direct_tcp().is_some())
        })
    }
    pub fn has_event_wait(
        ring: &Rc<Uring>,
        owner: u64,
        task: u32,
        enter_deadline: Option<Instant>,
    ) -> bool {
        Self::has_native_wait(ring, owner, task)
            || enter_deadline.is_some()
            || ring.next_deadline().is_some()
                && ring.state.borrow().pending.iter().any(|r| {
                    r.owner == owner && r.task == task && r.started && r.deadline.is_some()
                })
    }
    pub fn poll_rings(
        vfs: &Vfs,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        task: u32,
    ) -> Option<Vec<Rc<Uring>>> {
        if !matches!(number, 22 | 73 | 441) || vfs.urings().is_empty() {
            return None;
        }
        let mut rings = Vec::new();
        if number == 73 {
            if args[1] > 256 || args[3] != 0 {
                return None;
            }
            for i in 0..args[1] {
                let fd = i32::from_le_bytes(memory.read_array(args[0].checked_add(i * 8)?).ok()?);
                if fd >= 0 {
                    rings.extend(vfs.uring_poll_rings(fd as u32)?);
                }
            }
        } else {
            if args[4] != 0 {
                return None;
            }
            rings = vfs.uring_poll_rings(args[0] as u32)?;
        }
        let owner = memory.instruction_identity().0;
        (!rings.is_empty()
            && rings.iter().all(|ring| {
                Self::can_adopt(ring)
                    && ring
                        .state
                        .borrow()
                        .pending
                        .iter()
                        .all(|r| r.owner == owner && r.task == task)
            }))
        .then_some(rings)
    }
    /// Admission hint for an already parked enter. Mapping/FD mutation still
    /// joins; the snapshot performs final capability admission before effects.
    pub fn can_adopt(ring: &Rc<Uring>) -> bool {
        let state = ring.state.borrow();
        state.pending.iter().all(|r| {
            Request::supported(&r.sqe)
                && r.path.is_none()
                && r.file
                    .as_ref()
                    .is_none_or(|f| Resource::capture(f).is_some())
        })
    }
    pub fn adopt_wait(
        &mut self,
        task: u32,
        ring: &Rc<Uring>,
        submitted: u32,
        deadline: Option<Instant>,
    ) -> bool {
        let Some(owner) = self.owners.get(&(Rc::as_ptr(ring) as usize)) else {
            return false;
        };
        owner
            .direct
            .state
            .lock()
            .unwrap()
            .waits
            .insert(task, (submitted, deadline));
        true
    }
    pub fn capture(&mut self, vfs: &Vfs, owner: u64, task: u32) -> UringSnapshot {
        self.capture_with_files(vfs, owner, task, &Default::default())
    }
    pub fn capture_with_files(
        &mut self,
        vfs: &Vfs,
        owner: u64,
        task: u32,
        files: &trames_vfs::DirectFiles,
    ) -> UringSnapshot {
        self.capture_all(vfs, owner, task, files, &BTreeMap::new())
    }
    pub fn capture_all(
        &mut self,
        vfs: &Vfs,
        owner: u64,
        task: u32,
        files: &trames_vfs::DirectFiles,
        retained_files: &BTreeMap<usize, trames_vfs::PreparedFile>,
    ) -> UringSnapshot {
        let descriptors = vfs.uring_descriptors();
        if descriptors.is_empty() {
            return UringSnapshot::default();
        }
        let mut snapshot = UringSnapshot {
            owner,
            task,
            membership: Some(vfs.shared_files()),
            files: files.clone(),
            ..Default::default()
        };
        let mut retained = BTreeMap::new();
        for fd in 0..trames_vfs::MAX_FDS {
            if vfs.flags(fd).is_ok() {
                snapshot.valid_fds.insert(fd);
            }
            if let Ok(file) = vfs.retain_uring_fd(fd) {
                if file.shared_file().is_some() {
                    continue;
                }
                if let Some(resource) = Resource::capture(&file)
                    .or_else(|| files.get(fd).map(|cap| Resource::regular(&file, cap)))
                {
                    snapshot.resources.insert(fd, resource);
                    retained.insert(fd, file);
                }
            }
        }
        let capture_pending = |file: &RetainedFd| {
            Resource::capture(file)
                .or_else(|| files.retain(file).map(|cap| Resource::regular(file, cap)))
                .or_else(|| {
                    retained_files
                        .get(&file.identity())
                        .and_then(|prepared| prepared.retain(file))
                        .map(|cap| Resource::regular(file, cap))
                })
                .or_else(|| {
                    retained.iter().find_map(|(fd, current)| {
                        file.same_file(current)
                            .then(|| snapshot.resources.get(fd).cloned())
                            .flatten()
                    })
                })
        };
        let mut fixed_cache: BTreeMap<usize, FixedFiles> = BTreeMap::new();
        for (fd, ring) in descriptors {
            let key = Rc::as_ptr(&ring) as usize;
            if let std::collections::btree_map::Entry::Vacant(slot) = self.owners.entry(key) {
                let mut state = ring.state.borrow_mut();
                if state.pending.iter().any(|r| {
                    !Request::supported(&r.sqe)
                        || r.path.is_some()
                        || r.file
                            .as_ref()
                            .is_some_and(|f| capture_pending(f).is_none())
                }) {
                    continue;
                }
                let eventfd = match &state.eventfd {
                    Some(f) => match f.direct_byte() {
                        Some(d) => Some(d),
                        None => continue,
                    },
                    None => None,
                };
                let Ok(pages) = vfs.uring_queue_pages(fd) else {
                    continue;
                };
                let shared: Option<Vec<_>> = pages.iter().map(|p| p.shared_page()).collect();
                let Some(shared) = shared else {
                    continue;
                };
                let mut originals = BTreeMap::new();
                let pending: VecDeque<_> = state
                    .pending
                    .drain(..)
                    .map(|r| {
                        if let Some(f) = &r.file {
                            if f.shared_file().is_none() {
                                originals.insert((r.task, r.sequence), f.clone());
                            }
                        }
                        Request {
                            owner: r.owner,
                            task: r.task,
                            sequence: r.sequence,
                            sqe: r.sqe,
                            resource: r.file.as_ref().and_then(capture_pending),
                            parts: r.parts,
                            requested: r.requested,
                            error: r.error,
                            buffer: r.buffer,
                            dependency: r.dependency,
                            started: r.started,
                            deadline: r.deadline,
                            timeout_count: r.timeout_count,
                            timeout_target: r.timeout_target,
                            timeout_duration: r.timeout_duration,
                            shots: r.shots,
                            poll_ready: r.poll_ready,
                            poll_epoch: r.poll_epoch,
                        }
                    })
                    .collect();
                let mut direct_state = State {
                    head: state.head,
                    tail: state.tail,
                    dropped: state.dropped,
                    next: state.next,
                    completion_count: state.completion_count,
                    completed: std::mem::take(&mut state.completed),
                    overflow: std::mem::take(&mut state.overflow),
                    eventfd,
                    buffers: std::mem::take(&mut state.buffers),
                    provided: std::mem::take(&mut state.provided),
                    multishot_cursor: state.multishot_cursor,
                    ..Default::default()
                };
                for r in pending {
                    direct_state.insert(r);
                }
                direct_state
                    .completed
                    .retain(|id, _| direct_state.dependencies.contains_key(id));
                let direct = Arc::new(Ring {
                    identity: key,
                    queue: Queue {
                        entries: ring.entries,
                        cq_entries: ring.cq_entries,
                        ring_bytes: ring.ring_bytes as usize,
                        pages: shared,
                    },
                    state: Mutex::new(direct_state),
                    readiness: Arc::default(),
                });
                drop(state);
                slot.insert(Owner {
                    ring: ring.clone(),
                    direct,
                    _pages: pages,
                    originals,
                    descriptors: BTreeMap::new(),
                    fixed: BTreeMap::new(),
                    tasks: BTreeSet::new(),
                });
            }
            let entry = self.owners.get_mut(&key).unwrap();
            if entry.tasks.insert(task) {
                for &fd in snapshot.resources.keys() {
                    if let Ok(file) = vfs.retain_uring_fd(fd) {
                        entry.descriptors.insert((task, fd), file);
                    }
                }
            }
            if let Some(files) = &ring.state.borrow().files {
                let fixed = fixed_cache.entry(key).or_insert_with(|| {
                    files
                        .iter()
                        .enumerate()
                        .map(|(index, file)| match file {
                            Some(file) => {
                                if file.shared_file().is_none() {
                                    entry.fixed.insert((task, index as u32), file.clone());
                                }
                                capture_pending(file).map(Some).ok_or(Errno(95))
                            }
                            None => Ok(None),
                        })
                        .collect::<Vec<_>>()
                        .into()
                });
                snapshot.fixed.insert(fd, fixed.clone());
            }
            snapshot.rings.insert(fd, entry.direct.clone());
            snapshot.poll_rings.insert(key, entry.direct.clone());
        }
        if !snapshot.poll_rings.is_empty() {
            let polls = snapshot
                .poll_rings
                .iter()
                .map(|(&key, ring)| (key, ring.clone() as Arc<dyn trames_vfs::DirectPoll>))
                .collect();
            snapshot.descriptors = Some(vfs.direct_descriptors_with_polls(&polls));
        }
        snapshot
    }
    /// Every worker/View has stopped before merging. No per-SQE owner RPC.
    pub fn finish(mut self) -> Vec<UringHandoff> {
        self.restore()
    }
    fn restore(&mut self) -> Vec<UringHandoff> {
        let mut waits = Vec::new();
        for (_, entry) in std::mem::take(&mut self.owners) {
            let mut direct = entry.direct.state.lock().unwrap_or_else(|e| e.into_inner());
            let mut state = entry.ring.state.borrow_mut();
            state.head = direct.head;
            state.tail = direct.tail;
            state.dropped = direct.dropped;
            state.next = direct.next;
            state.completion_count = direct.completion_count;
            state.completed = std::mem::take(&mut direct.completed);
            state.overflow = std::mem::take(&mut direct.overflow);
            state.provided = std::mem::take(&mut direct.provided);
            state.buffers = std::mem::take(&mut direct.buffers);
            if direct.eventfd.is_none() {
                state.eventfd = None;
            }
            state.multishot_cursor = direct.multishot_cursor;
            let mut pending = direct.pending.drain(..).collect::<Vec<_>>();
            pending.sort_unstable_by_key(|r| r.sequence);
            for r in pending {
                let file = r.resource.as_ref().and_then(|resource| {
                    resource
                        .shared_file()
                        .map(trames_vfs::SharedFd::retained)
                        .or_else(|| {
                            entry
                                .originals
                                .get(&(r.task, r.sequence))
                                .or_else(|| {
                                    if r.sqe.flags() & 1 != 0 {
                                        entry.fixed.get(&(r.task, r.sqe.fd() as u32))
                                    } else {
                                        entry.descriptors.get(&(r.task, r.sqe.fd() as u32))
                                    }
                                })
                                .cloned()
                        })
                });
                state.pending.push_back(UringRequest {
                    owner: r.owner,
                    task: r.task,
                    sequence: r.sequence,
                    sqe: r.sqe,
                    file,
                    buffer: r.buffer,
                    error: r.error,
                    dependency: r.dependency,
                    deadline: r.deadline,
                    parts: r.parts,
                    requested: r.requested,
                    path: None,
                    how: None,
                    started: r.started,
                    timeout_count: r.timeout_count,
                    timeout_target: r.timeout_target,
                    timeout_duration: r.timeout_duration,
                    shots: r.shots,
                    poll_ready: r.poll_ready,
                    poll_epoch: r.poll_epoch,
                });
            }
            let mut tasks = state
                .pending
                .iter()
                .map(|r| r.task)
                .collect::<std::collections::BTreeSet<_>>();
            tasks.extend(direct.waits.keys().copied());
            for task in tasks {
                let wait = direct.waits.remove(&task);
                waits.push(UringHandoff {
                    task,
                    submitted: wait.map(|w| w.0),
                    ring: entry.ring.clone(),
                    deadline: wait.and_then(|w| w.1),
                });
            }
        }
        waits
    }
}
impl Drop for UringEpoch {
    fn drop(&mut self) {
        self.restore();
    }
}

impl trames_vfs::DirectPoll for Ring {
    fn identity(&self) -> usize {
        self.identity
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let state = self.state.lock().unwrap();
        let ready = state
            .tail
            .wrapping_sub(self.queue.load(64))
            .min(self.queue.cq_entries);
        (
            if ready != 0 { events & 1 } else { 0 },
            [state.tail as u64, 0],
        )
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> trames_vfs::IoSubscription {
        self.readiness.subscribe(signal)
    }
}

#[cfg(test)]
#[path = "uring/owned_tests.rs"]
mod owned_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uring::tests::{add, cq, setup, sqe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Target(AtomicUsize);
    impl IoWake for Target {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn target() -> Arc<dyn IoWake> {
        Arc::new(Target(AtomicUsize::new(0)))
    }
    fn start(
        snapshot: &UringSnapshot,
        fd: u32,
        n: u32,
        min: u32,
        memory: &mut impl CpuMemory,
        t: &Arc<dyn IoWake>,
    ) -> IoAttempt {
        snapshot
            .start(
                [fd as u64, n as u64, min as u64, u64::from(min != 0), 0, 0],
                memory,
                snapshot.task,
                &Arc::downgrade(t),
            )
            .unwrap()
    }
    fn complete(a: IoAttempt, n: u64) {
        match a {
            IoAttempt::Complete(Ok(v)) => assert_eq!(v, n),
            _ => panic!("expected completion {n}"),
        }
    }
    fn read(fd: u32, data: u64) -> [u8; 64] {
        let mut s = sqe(22, fd, data);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        s[24..28].copy_from_slice(&1u32.to_le_bytes());
        s
    }
    #[test]
    fn local_uring_nop_overflow_wrap_and_bad_head_use_private_cursors() {
        fn send<T: Send>() {}
        send::<UringSnapshot>();
        send::<PendingIo>();
        let (l, mut m, fd, r) = setup(2);
        let t = target();
        let mut epoch = UringEpoch::default();
        r.state.borrow_mut().head = u32::MAX - 1;
        r.state.borrow_mut().tail = u32::MAX - 1;
        m.write_array(0x10000, (u32::MAX - 1).to_le_bytes())
            .unwrap();
        m.write_array(0x10004, (u32::MAX - 1).to_le_bytes())
            .unwrap();
        m.write_array(0x10040, (u32::MAX - 1).to_le_bytes())
            .unwrap();
        m.write_array(0x10044, (u32::MAX - 1).to_le_bytes())
            .unwrap();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        for i in 0..3 {
            add(&mut m, &r, sqe(0, 0, 2 * i));
            add(&mut m, &r, sqe(0, 0, 2 * i + 1));
            complete(start(&s, fd, 2, 0, &mut m, &t), 2);
        }
        assert_eq!(cq(&mut m, &r), (0, 0));
        assert_eq!(cq(&mut m, &r), (1, 0));
        complete(start(&s, fd, 0, 0, &mut m, &t), 0);
        for i in 2..6 {
            assert_eq!(cq(&mut m, &r), (i, 0));
        }
        m.write_array(0x10040, 100u32.to_le_bytes()).unwrap();
        assert!(matches!(
            start(&s, fd, 0, 0, &mut m, &t),
            IoAttempt::Complete(Err(Errno(22)))
        ));
        assert_eq!(s.completed(), 4);
        assert!(epoch.finish().is_empty());
        assert_eq!(r.state.borrow().head, 4);
        assert_eq!(r.state.borrow().tail, 4);
    }
    #[test]
    fn local_uring_mixed_batch_defers_before_any_effect() {
        let (mut l, mut m, fd, r) = setup(4);
        let t = target();
        add(&mut m, &r, sqe(0, 0, 1));
        add(&mut m, &r, sqe(255, 0, 2));
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        assert!(matches!(
            start(&s, fd, 2, 0, &mut m, &t),
            IoAttempt::Checkpoint
        ));
        assert_eq!(m.read_array::<4>(0x10000).unwrap(), 0u32.to_le_bytes());
        assert_eq!(r.cq_ready(), 0);
        assert!(epoch.finish().is_empty());
        assert_eq!(
            l.uring_enter([fd as u64, 2, 0, 0, 0, 0], &mut m, None, 7),
            Ok((2, true))
        );
        assert_eq!(cq(&mut m, &r), (1, 0));
        assert_eq!(cq(&mut m, &r), (2, -22));
    }
    #[test]
    fn local_uring_pipe_wait_keeps_submission_and_ignores_new_sqes_on_resume() {
        let (mut l, mut m, fd, r) = setup(8);
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        add(&mut m, &r, read(reader, 1));
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let t = target();
        let mut view = m.parallel_view(&mut Default::default()).unwrap();
        let IoAttempt::Blocked(wait) = start(&s, fd, 1, 1, &mut view, &t) else {
            panic!("expected park")
        };
        assert!(!wait.signal.ready());
        drop(view);
        add(&mut m, &r, sqe(0, 0, 2));
        l.vfs.write(writer, b"x").unwrap();
        assert!(wait.signal.ready());
        let mut view = m.parallel_view(&mut Default::default()).unwrap();
        complete(s.resume(wait, &mut view), 1);
        drop(view);
        assert_eq!(cq(&mut m, &r), (1, 1));
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"x");
        assert_eq!(m.read_array::<4>(0x10000).unwrap(), 1u32.to_le_bytes());
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (2, 0));
        assert!(epoch.finish().is_empty());
    }
    #[test]
    fn local_uring_inotify_wait_retains_watch_after_fd_reuse_and_wakes_from_file_worker() {
        let (mut l, mut m, fd, r) = setup(4);
        l.vfs.import_file(b"/data", vec![0; 8]).unwrap();
        let file = l.vfs.open_at(-100, b"/data", 2, 0).unwrap();
        let notify = l.vfs.inotify_init(0).unwrap();
        let wd = l.vfs.inotify_add(notify, b"/data", 2).unwrap();
        let mut request = read(notify, 41);
        request[24..28].copy_from_slice(&16u32.to_le_bytes());
        add(&mut m, &r, request);
        let mut files = trames_vfs::FileEpoch::default();
        let caps = files.capture(&l.vfs, true);
        let mut epoch = UringEpoch::default();
        let snapshot = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let t = target();
        let IoAttempt::Blocked(wait) = start(&snapshot, fd, 1, 1, &mut m, &t) else {
            panic!("expected inotify park")
        };
        l.vfs.close(notify).unwrap();
        let replacement = l.vfs.eventfd(7, 0).unwrap();
        assert_eq!(replacement, notify);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                assert_eq!(
                    caps.get(file)
                        .unwrap()
                        .write(b"x", Some(0), &mut Default::default()),
                    Some(Ok(1))
                );
            });
        });
        assert!(wait.signal.ready());
        complete(snapshot.resume(wait, &mut m), 1);
        assert_eq!(cq(&mut m, &r), (41, 16));
        assert_eq!(m.read_array::<4>(0x2000).unwrap(), wd.to_le_bytes());
        assert_eq!(m.read_array::<4>(0x2004).unwrap(), 2u32.to_le_bytes());
        assert_eq!(l.vfs.read(replacement, 8).unwrap(), 7u64.to_le_bytes());
        drop(snapshot);
        assert!(epoch.finish().is_empty());
        files.finish();
    }
    #[test]
    fn local_uring_handoff_retains_closed_ofd_and_never_resubmits_batch() {
        let (mut l, mut m, fd, r) = setup(4);
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        add(&mut m, &r, read(reader, 9));
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let t = target();
        let IoAttempt::Blocked(wait) = start(&s, fd, 1, 1, &mut m, &t) else {
            panic!("expected park")
        };
        drop(wait);
        drop(s);
        let handoff = epoch.finish();
        assert_eq!(handoff.len(), 1);
        assert_eq!(handoff[0].submitted, Some(1));
        l.vfs.close(reader).unwrap();
        let [other, _] = l.vfs.pipe(0).unwrap();
        assert_eq!(other, reader);
        l.vfs.write(writer, b"a").unwrap();
        assert_eq!(
            l.uring_enter_ring(r.clone(), [fd as u64, 1, 1, 1, 0, 0], &mut m, Some(1), 7),
            Ok((1, true))
        );
        assert_eq!(cq(&mut m, &r), (9, 1));
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"a");
        assert_eq!(r.cq_ready(), 0);
    }
    #[test]
    fn local_uring_vm_authority_and_drop_restore_accepted_request() {
        let (mut l, mut m, fd, r) = setup(4);
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        add(&mut m, &r, read(reader, 10));
        let owner = m.instruction_identity().0;
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, owner, 7);
        let t = target();
        complete(start(&s, fd, 1, 0, &mut m, &t), 1);
        drop(s);
        drop(epoch);
        assert_eq!(r.state.borrow().pending.len(), 1);
        let mut child = m.clone();
        l.vfs.write(writer, b"v").unwrap();
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, child.instruction_identity().0, 8);
        complete(start(&s, fd, 0, 0, &mut child, &t), 0);
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), [0]);
        let active = epoch.finish();
        assert_eq!(active[0].task, 7);
        assert_eq!(active[0].submitted, None);
        assert!(l.progress_uring(&mut m, 7));
        assert_eq!(cq(&mut m, &r), (10, 1));
    }
    #[test]
    fn local_uring_shared_ring_arbitrates_two_worker_consumers() {
        let (l, mut m, fd, r) = setup(8);
        for i in 0..8 {
            add(&mut m, &r, sqe(0, 0, i));
        }
        let mut epoch = UringEpoch::default();
        let owner = m.instruction_identity().0;
        let a = epoch.capture(&l.vfs, owner, 7);
        let b = epoch.capture(&l.vfs, owner, 8);
        let mut va = m.parallel_view(&mut Default::default()).unwrap();
        let mut vb = m.parallel_view(&mut Default::default()).unwrap();
        std::thread::scope(|scope| {
            let t = target();
            let u = t.clone();
            scope.spawn(move || complete(start(&a, fd, 4, 0, &mut va, &t), 4));
            scope.spawn(move || complete(start(&b, fd, 4, 0, &mut vb, &u), 4));
        });
        assert!(epoch.finish().is_empty());
        let mut data = (0..8).map(|_| cq(&mut m, &r).0).collect::<Vec<_>>();
        data.sort_unstable();
        assert_eq!(data, (0..8).collect::<Vec<_>>());
        assert_eq!(r.state.borrow().head, 8);
    }
    #[test]
    fn local_uring_vectors_faults_and_eventfd_count_actual_cq_publication() {
        let (mut l, mut m, fd, r) = setup(2);
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        let event = l.vfs.eventfd(0, 0).unwrap();
        l.uring_register([fd as u64, 4, 0x1000, 1, 0, 0], &mut m)
            .unwrap_err();
        m.write_array(0x1000, event.to_le_bytes()).unwrap();
        l.uring_register([fd as u64, 4, 0x1000, 1, 0, 0], &mut m)
            .unwrap();
        m.write(0x2100, b"abc").unwrap();
        m.write_array(0x2200, 0x2100u64.to_le_bytes()).unwrap();
        m.write_array(0x2208, 3u64.to_le_bytes()).unwrap();
        let mut write = read(writer, 30);
        write[0] = 2;
        write[16..24].copy_from_slice(&0x2200u64.to_le_bytes());
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let t = target();
        add(&mut m, &r, write);
        add(&mut m, &r, read(reader, 31));
        complete(start(&s, fd, 2, 2, &mut m, &t), 2);
        assert_eq!(cq(&mut m, &r), (30, 3));
        assert_eq!(cq(&mut m, &r), (31, 1));
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"a");
        assert_eq!(l.vfs.read(event, 8).unwrap(), 2u64.to_le_bytes());
        let mut bad = read(reader, 32);
        bad[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        add(&mut m, &r, bad);
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (32, -14));
        assert_eq!(l.vfs.read(reader, 2).unwrap(), b"bc");
        assert!(epoch.finish().is_empty());
    }
    #[test]
    fn local_uring_other_submitter_notifies_cq_only_waiter() {
        let (l, mut m, fd, r) = setup(4);
        let owner = m.instruction_identity().0;
        let t = target();
        let mut epoch = UringEpoch::default();
        let a = epoch.capture(&l.vfs, owner, 7);
        let b = epoch.capture(&l.vfs, owner, 8);
        let IoAttempt::Blocked(wait) = start(&a, fd, 0, 1, &mut m, &t) else {
            panic!("expected CQ wait")
        };
        add(&mut m, &r, sqe(0, 0, 44));
        complete(start(&b, fd, 1, 0, &mut m, &t), 1);
        assert!(wait.signal.ready());
        complete(a.resume(wait, &mut m), 0);
        assert_eq!(cq(&mut m, &r), (44, 0));
        assert!(epoch.finish().is_empty());
    }
    #[test]
    fn local_uring_parked_enter_is_adopted_without_resubmitting_on_next_epoch() {
        let (mut l, mut m, fd, r) = setup(4);
        let [reader, writer] = l.vfs.pipe(0).unwrap();
        let owner = m.instruction_identity().0;
        add(&mut m, &r, read(reader, 45));
        let t = target();
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, owner, 7);
        let IoAttempt::Blocked(wait) = start(&s, fd, 1, 1, &mut m, &t) else {
            panic!("expected wait")
        };
        drop(wait);
        drop(s);
        let handoff = epoch.finish();
        assert_eq!(handoff[0].submitted, Some(1));
        assert!(UringEpoch::can_adopt(&r));
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, owner, 7);
        assert!(epoch.adopt_wait(7, &r, 1, None));
        add(&mut m, &r, sqe(0, 0, 46));
        l.vfs.write(writer, b"r").unwrap();
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (45, 1));
        assert_eq!(m.read_array::<4>(0x10000).unwrap(), 1u32.to_le_bytes());
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (46, 0));
        assert!(epoch.finish().is_empty());
    }
    #[test]
    fn local_uring_regular_files_preserve_offsets_and_defer_growth_once() {
        let (mut l, mut m, fd, r) = setup(8);
        l.vfs.import_file(b"/data", b"abcdefgh".to_vec()).unwrap();
        let file = l.vfs.open_at(trames_vfs::AT_FDCWD, b"/data", 2, 0).unwrap();
        let mut files = trames_vfs::FileEpoch::default();
        let caps = files.capture(&l.vfs, true);
        let mut epoch = UringEpoch::default();
        let s = epoch.capture_with_files(&l.vfs, m.instruction_identity().0, 7, &caps);
        let t = target();
        let mut request = read(file, 50);
        request[8..16].copy_from_slice(&3u64.to_le_bytes());
        add(&mut m, &r, request);
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (50, 1));
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"d");
        request = read(file, 51);
        request[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        add(&mut m, &r, request);
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (51, 1));
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"a");
        request = read(file, 52);
        request[0] = 23;
        request[8..16].copy_from_slice(&8u64.to_le_bytes());
        add(&mut m, &r, request);
        assert!(matches!(
            start(&s, fd, 1, 1, &mut m, &t),
            IoAttempt::Checkpoint
        ));
        drop(s);
        let handoff = epoch.finish();
        assert_eq!(handoff[0].submitted, Some(1));
        files.finish();
        assert_eq!(l.vfs.seek(file, 0, 1), Ok(1));
        assert_eq!(l.vfs.pread(file, 100, 0).unwrap(), b"abcdefgh");
        assert_eq!(
            l.uring_enter_ring(r.clone(), [fd as u64, 1, 1, 1, 0, 0], &mut m, Some(1), 7),
            Ok((1, true))
        );
        assert_eq!(cq(&mut m, &r), (52, 1));
        assert_eq!(l.vfs.pread(file, 10, 0).unwrap(), b"abcdefgha");
    }
    #[test]
    fn local_uring_boundary_poll_flags_and_timerfd_deadline_rearm() {
        let (mut l, mut m, fd, r) = setup(4);
        let timer = l.vfs.timerfd(1, 0).unwrap();
        let resource = l.vfs.timerfd_resource(timer).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3600);
        resource.update(Some((Duration::ZERO, Some(deadline))));
        let mut bad = sqe(6, timer, 60);
        bad[28..32].copy_from_slice(&128u32.to_le_bytes());
        add(&mut m, &r, bad);
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let t = target();
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (60, -22));
        let mut request = read(timer, 61);
        request[24..28].copy_from_slice(&8u32.to_le_bytes());
        add(&mut m, &r, request);
        let IoAttempt::Blocked(wait) = start(&s, fd, 1, 1, &mut m, &t) else {
            panic!("expected timer wait")
        };
        assert_eq!(wait.wake_deadline(), Some(deadline));
        assert!(!wait.signal.ready());
        resource.update(Some((Duration::ZERO, Some(Instant::now()))));
        assert!(wait.signal.ready());
        complete(s.resume(wait, &mut m), 1);
        assert_eq!(cq(&mut m, &r), (61, 8));
        assert_eq!(m.read_array::<8>(0x2000).unwrap(), 1u64.to_le_bytes());
        assert!(epoch.finish().is_empty());
    }
    #[test]
    fn local_uring_boundary_invalid_adopted_cq_head_clears_saved_wait() {
        let (l, mut m, fd, r) = setup(4);
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let t = target();
        assert!(epoch.adopt_wait(7, &r, 1, Some(Instant::now())));
        assert!(epoch.adopt_wait(7, &r, 1, None));
        m.write_array(0x10040, 100u32.to_le_bytes()).unwrap();
        assert!(matches!(
            start(&s, fd, 1, 1, &mut m, &t),
            IoAttempt::Complete(Err(Errno(22)))
        ));
        assert!(epoch.finish().is_empty());
    }
    #[test]
    fn local_uring_boundary_native_tcp_extended_flags_defer_before_consuming() {
        use std::net::{Ipv4Addr, TcpListener};
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let (mut l, mut m, fd, r) = setup(4);
        l.vfs
            .configure_network(trames_vfs::NetworkMode::Loopback)
            .unwrap();
        let socket = l.vfs.socket(2, 1, 0).unwrap();
        let original = l.vfs.socket_fd(socket).unwrap();
        assert!(matches!(
            original.connect(listener.local_addr().unwrap()),
            Ok(()) | Err(trames_net::NetError(115))
        ));
        let _peer = listener.accept().unwrap().0;
        assert_eq!(original.connect_complete(), Ok(true));
        let mut request = read(socket, 62);
        request[0] = 27;
        request[28..32].copy_from_slice(&256u32.to_le_bytes());
        add(&mut m, &r, request);
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        let t = target();
        assert!(matches!(
            start(&s, fd, 1, 1, &mut m, &t),
            IoAttempt::Checkpoint
        ));
        assert_eq!(m.read_array::<4>(0x10000).unwrap(), 0u32.to_le_bytes());
        assert!(epoch.finish().is_empty());
        assert_eq!(r.cq_ready(), 0);
    }
}
