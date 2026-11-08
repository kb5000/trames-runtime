// SPDX-License-Identifier: GPL-3.0-or-later
//! Worker io_uring capabilities. No owner Rc graph or namespace crosses threads.
//! A ring lock arbitrates kernel cursors, not unrelated rings or byte resources.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

use trames_vfs::{
    Uring, UringFile, UringObject as Object, UringRequest as Request, UringResource as Resource,
    UringRunning as Running, UringSqe, UringState as State, Vfs,
};
type Result<T> = std::result::Result<T, Errno>;
pub(crate) mod actor;
mod background;
pub use actor::{UringActor, UringFileLayout};
pub use background::UringBackground;

trait ResourceOps: Sized {
    fn capture(file: &UringFile) -> Option<Self>;
    fn regular(file: &UringFile, cap: trames_vfs::DirectFile) -> Self;
    fn next_deadline(&self) -> Option<Instant>;
}
impl ResourceOps for Resource {
    fn capture(file: &UringFile) -> Option<Self> {
        let object = file
            .direct_byte()
            .map(Object::Byte)
            .or_else(|| file.direct_tcp().map(Object::Tcp))?;
        Some(Self {
            object,
            identity: file.identity(),
        })
    }
    fn regular(file: &UringFile, cap: trames_vfs::DirectFile) -> Self {
        Self {
            object: Object::File(cap),
            identity: file.identity(),
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        match &self.object {
            Object::Byte(f) => f.next_deadline(),
            Object::Tcp(_) | Object::File(_) => None,
        }
    }
}

trait RequestOps: Sized {
    fn supported(s: &UringSqe) -> bool;
    fn metadata(&self) -> usize;
    fn events(&self) -> u16;
    fn nowait(&self) -> bool;
    fn run(
        &mut self,
        memory: &mut impl CpuMemory,
        scratch: &mut Vec<u8>,
        cache: &mut trames_vfs::DiskReadCache,
        selected: Option<trames_vfs::UringProvidedBuffer>,
    ) -> Option<Result<i32>>;
}
impl RequestOps for Request {
    fn supported(s: &UringSqe) -> bool {
        trames_vfs::URING_OPS.contains(&s.opcode())
    }

    fn metadata(&self) -> usize {
        512 + self.parts.as_ref().map_or(0, |p| p.len() * 16)
            + self.path.as_ref().map_or(0, Vec::len)
    }
    fn events(&self) -> u16 {
        match self.sqe.opcode() {
            2 | 5 | 16 | 23 | 26 => 4,
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
        // An accepted file actor owns its imported input through native waits.
        // Never retry a second byte operation through the stateless fast helper.
        if self.execution.is_some()
            && self
                .file
                .as_ref()
                .and_then(|f| f.shared_file())
                .and_then(|f| f.file_target())
                .is_some()
            && matches!(s.opcode(), 1 | 2 | 4 | 5 | 22 | 23)
        {
            return None;
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
        if !matches!(s.opcode(), 1 | 2 | 4 | 5 | 22 | 23 | 26 | 27) {
            return None;
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
        if let Object::Byte(fd) = &resource.object {
            if fd.is_signalfd() {
                return Some(if network {
                    Err(Errno(88))
                } else if write {
                    Err(Errno(22))
                } else {
                    signal_read::SignalRead::uring(
                        fd,
                        parts,
                        memory,
                        s.opcode() == 1,
                        self.buffer.as_deref(),
                    )
                    .map(|n| n as i32)
                });
            }
        }
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
        if matches!(resource.object, Object::Tcp(_))
            && matches!(s.opcode(), 26 | 27)
            && s.op_flags()
                & !(if s.opcode() == 26 {
                    0x40 | 0x4000
                } else {
                    2 | 0x40
                })
                != 0
        {
            return None;
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

type Ring = Uring;

pub(crate) trait StateOps: Sized {
    fn insert(&mut self, r: Request);
    fn eligible(&self, r: &Request) -> bool;
    fn finish_request(
        &mut self,
        r: Request,
        result: Result<(i32, bool)>,
        flags: u32,
    ) -> (bool, Option<Request>);
    fn terminal(&mut self, r: &Request, result: Result<i32>);
    fn post(&mut self, r: &Request, result: Result<i32>, flags: u32, terminal: Option<bool>);
}
impl StateOps for State {
    fn insert(&mut self, r: Request) {
        let fresh = self.active.insert(r.sequence);
        if fresh && r.sqe.flags() & 2 != 0 {
            self.drains.insert(r.sequence);
        }
        if let Some((parent, _)) = r.dependency.filter(|_| fresh) {
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
                6 | 13 => value >= 0,
                27 => value > 0 || value == 0 && r.file.as_ref().is_some_and(|f| f.datagram()),
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
use control::{ControlStateOps, TimerRequestOps};
#[path = "uring/poll.rs"]
mod poll;
mod wait;
pub(super) use poll::PollWait;
use wait::RingWaitOps;

pub(crate) trait RingOps {
    fn outstanding(&self, state: &State) -> usize;
    fn backpressured(&self, state: &State, r: &Request) -> bool;
    fn progress_with<M: CpuMemory>(
        &self,
        memory: &mut M,
        owner: u64,
        task: u32,
        execute: &mut impl FnMut(
            &mut Request,
            &mut M,
            Option<trames_vfs::UringProvidedBuffer>,
        ) -> Option<Result<(i32, bool)>>,
    ) -> bool;
}
impl RingOps for Ring {
    fn outstanding(&self, state: &State) -> usize {
        let unread = state
            .tail
            .wrapping_sub(self.load_queue(64))
            .min(self.cq_entries) as usize;
        state.pending.len()
            + state.inflight
            + state.overflow.len()
            + unread
            + state.shot_reservations
    }
    fn backpressured(&self, state: &State, r: &Request) -> bool {
        r.sqe.multishot()
            && r.error.is_none()
            && self.outstanding(state) >= (self.entries as usize * 8).min(8192)
    }
    fn progress_with<M: CpuMemory>(
        &self,
        memory: &mut M,
        owner: u64,
        task: u32,
        execute: &mut impl FnMut(
            &mut Request,
            &mut M,
            Option<trames_vfs::UringProvidedBuffer>,
        ) -> Option<Result<(i32, bool)>>,
    ) -> bool {
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
                if r.selection.is_none()
                    && (r.selected() || matches!(r.sqe.opcode(), 31 | 32))
                    && state
                        .provided
                        .get(&r.sqe.buffer_group())
                        .is_some_and(|g| state.busy_groups.contains(&g.identity))
                {
                    contended.push(state.provided[&r.sqe.buffer_group()].identity);
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
                std::mem::swap(&mut state.scratch, &mut scratch);
                std::mem::swap(&mut state.cache, &mut cache);
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
            let mut group_lease = None;
            let mut selected_error = None;
            if let Some(lease) = &r.selection {
                selected = Some(lease.buffer);
                group_lease = Some((lease.group, lease.identity));
            } else if r.selected() {
                match crate::uring::buffers::peek(&r.sqe, r.owner, &state.provided) {
                    Ok(buffer) => {
                        selected = Some(buffer);
                        let key = state.provided[&r.sqe.buffer_group()].identity;
                        state.busy_groups.insert(key);
                        r.selected_identity = Some(key);
                        group_lease = Some((r.sqe.buffer_group(), key));
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
                    .or_else(|| execute(&mut r, memory, selected))
            };
            if let (Some(selection), Some(buffer)) = (&mut r.selection, selected) {
                selection.buffer = buffer;
            }
            if result.is_some() {
                r.started = true;
            }
            let mut state = self.state.lock().unwrap();
            state.running.remove(&r.sequence);
            state.inflight -= 1;
            state.inflight_metadata -= r.metadata();
            state.shot_reservations -= usize::from(reserved);
            let mut notify = false;
            let consumed =
                selected.filter(|_| result.is_some() && !matches!(result, Some(Err(Errno(11)))));
            let flags = if let Some(buffer) = consumed {
                let (id, key) = group_lease.expect("selected group lease");
                let group = if state.provided.get(&id).is_some_and(|g| g.identity == key) {
                    state.provided.get_mut(&id).unwrap()
                } else {
                    state
                        .retired_groups
                        .get_mut(&key)
                        .expect("retained unregistered group")
                };
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
            let keep_group = r.selection.is_some() && matches!(result, Some(Err(Errno(11))));
            let retired_group = if let Some((_, key)) = group_lease.filter(|_| !keep_group) {
                state.busy_groups.remove(&key);
                notify |= state.contended_groups.remove(&key);
                state.retired_groups.remove(&key)
            } else {
                None
            };
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
            drop(retired_group);
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
    #[cfg(test)]
    rings: BTreeMap<u32, Arc<Ring>>,
    // Only excluded owner controls are frozen. Shared slots resolve live at
    // SQE acceptance and the request owns the resulting original OFD.
    membership: Option<trames_vfs::SharedFiles>,
    files: trames_vfs::DirectFiles,
    retained_files: BTreeMap<usize, trames_vfs::PreparedFile>,
    owner: u64,
    task: u32,
    completed: Cell<u64>,
    pub(super) clock: Option<Instant>,
    pub(super) descriptors: Option<trames_vfs::DirectFds>,
    actor: Option<Arc<std::sync::OnceLock<Arc<UringActor>>>>,
    local_actor: std::sync::OnceLock<Arc<UringActor>>,
    context: std::sync::OnceLock<Arc<actor::Execution>>,
}
impl UringSnapshot {
    pub(super) fn refresh_namespaces(
        &mut self,
        membership: trames_vfs::SharedFiles,
        files: &trames_vfs::DirectFiles,
        descriptors: trames_vfs::DirectFds,
        retained: BTreeMap<usize, trames_vfs::PreparedFile>,
    ) {
        self.membership = Some(membership);
        self.files = files.clone();
        self.descriptors = Some(descriptors);
        // Old ring roots and their already accepted OFDs stay alive even when
        // absent from the new Files table. Only new acceptance gets new paths.
        self.retained_files.extend(retained);
        self.context.take();
        #[cfg(test)]
        {
            self.rings.clear();
        }
    }
    pub(super) fn cancel_task(&self, owner: u64, task: u32) {
        let actor = self
            .actor
            .as_ref()
            .and_then(|root| root.get())
            .or_else(|| self.local_actor.get());
        if let Some(actor) = actor {
            actor.cancel_task(owner, task);
        }
    }
    pub(super) fn ensure_context(
        &self,
        paths: Option<&trames_vfs::PathQueries>,
        factory: Option<&trames_vfs::DescriptorFactory>,
        files: &trames_vfs::DirectFiles,
        disk: Option<&Arc<dyn FileExecutor>>,
        layouts: Option<&Arc<crate::FileLayouts>>,
        signal: Option<&Arc<dyn trames_vfs::TaskSignal>>,
    ) {
        if self.context.get().is_none() {
            if let (Some(paths), Some(factory)) = (paths, factory) {
                let _ = self.context.set(Arc::new(actor::Execution::new(
                    paths,
                    factory,
                    files,
                    disk.cloned(),
                    layouts.cloned(),
                    signal.cloned(),
                )));
            }
        }
    }
    fn progress(&self, ring: &Arc<Ring>, memory: &mut impl CpuMemory, task: u32) -> bool {
        ring.progress_with(memory, self.owner, task, &mut |r, memory, selected| {
            self.actor().execute(ring, r, memory, selected)
        })
    }
    pub fn with_actor(mut self, actor: Arc<std::sync::OnceLock<Arc<UringActor>>>) -> Self {
        if let Some(actor) = actor.get() {
            self.prepare_rings(actor.rings());
        }
        self.actor = Some(actor);
        self
    }
    fn actor(&self) -> &Arc<UringActor> {
        self.actor
            .as_ref()
            .map_or(&self.local_actor, |actor| &**actor)
            .get_or_init(Arc::default)
    }
    fn prepare_rings(&self, rings: impl IntoIterator<Item = Arc<Uring>>) {
        for ring in rings {
            let mut state = ring.state.lock().unwrap();
            for r in &mut state.pending {
                if r.resource.is_none() {
                    r.resource = r
                        .file
                        .as_ref()
                        .and_then(|file| self.accepted_resource(file));
                }
            }
        }
    }

    fn ring(&self, fd: u32) -> Option<Arc<Ring>> {
        if let Some(files) = &self.membership {
            return files.uring(fd).ok();
        }
        #[cfg(test)]
        {
            self.rings.get(&fd).cloned()
        }
        #[cfg(not(test))]
        {
            None
        }
    }
    fn accepted_resource(&self, file: &UringFile) -> Option<Resource> {
        file.shared_file()
            .and_then(|shared| self.descriptors.as_ref()?.byte_file(shared))
            .map(|f| Resource {
                object: Object::Byte(f),
                identity: file.identity(),
            })
            .or_else(|| Resource::capture(file))
            .or_else(|| {
                self.files
                    .retain(&file.retained())
                    .map(|cap| Resource::regular(file, cap))
            })
            .or_else(|| {
                self.retained_files
                    .get(&file.identity())
                    .and_then(|p| p.retain(&file.retained()))
                    .map(|cap| Resource::regular(file, cap))
            })
    }

    pub fn contains(&self, fd: u32) -> bool {
        self.ring(fd).is_some()
    }
    pub(super) fn record_completed(&self) {
        self.completed.set(self.completed.get() + 1);
    }
    pub fn completed(&self) -> u64 {
        self.completed.get()
    }
    pub(super) fn available(&self) -> bool {
        #[cfg(test)]
        {
            self.membership.is_some() || !self.rings.is_empty()
        }
        #[cfg(not(test))]
        {
            self.membership.is_some()
        }
    }
    pub(super) fn supports_register(&self, _args: [u64; 6]) -> bool {
        self.available()
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
        if pid != self.task {
            return Some(IoAttempt::Checkpoint);
        }
        let Some(ring) = self.ring(args[0] as u32) else {
            self.record_completed();
            return Some(IoAttempt::Complete(Err(Errno(9))));
        };
        let result = crate::uring::register(&ring, args, memory, |fd| {
            Some(self.membership.as_ref()?.uring_file(fd))
        });
        ring.readiness.notify_locked();
        match result {
            None => Some(IoAttempt::Checkpoint),
            Some(result) => {
                self.record_completed();
                Some(IoAttempt::Complete(result))
            }
        }
    }
    pub(super) fn start(
        &self,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        if !self.available() {
            return None;
        }
        if pid != self.task {
            return Some(IoAttempt::Checkpoint);
        }
        let Some(ring) = self.ring(args[0] as u32) else {
            self.record_completed();
            return Some(IoAttempt::Complete(Err(Errno(9))));
        };
        self.start_ring(ring, args, memory, pid, target)
    }
    fn start_ring(
        &self,
        ring: Arc<Ring>,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> Option<IoAttempt> {
        let mut rejected_files = Vec::new();
        let mut prepared = Vec::new();
        let mut retired_graph = Vec::new();
        let mut rejected_requests = Vec::new();
        let mut state = ring.state.lock().unwrap();
        if args[2] > ring.cq_entries as u64 {
            state.waits.remove(&pid);
            return Some(IoAttempt::Complete(Err(Errno(22))));
        }
        let head = match ring.cq_head(&state) {
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
            let available = ring.load_queue(4).wrapping_sub(state.head);
            if available > ring.entries {
                return Some(IoAttempt::Complete(Err(Errno(22))));
            }
            let count = available.min(args[1] as u32);
            let limit = (ring.entries as usize * 8).min(8192);
            if state.pending.len()
                + state.inflight
                + state.overflow.len()
                + state.tail.wrapping_sub(head) as usize
                + count as usize
                > limit
            {
                return Some(IoAttempt::Complete(Err(Errno(16))));
            }
            // Import the complete accepted batch before the first effect.
            // Original opaque OFDs are retained just like ordinary resources.
            let mut metadata = state.inflight_metadata
                + state.pending.iter().map(Request::metadata).sum::<usize>();
            let mut previous = None;
            let mut sequence = state.next;
            for i in 0..count {
                let Some(s) = ring.sqe(state.head.wrapping_add(i)) else {
                    prepared.push(None);
                    previous = None;
                    continue;
                };
                let Some(mut r) = crate::uring::import_request(
                    s,
                    sequence + 1,
                    &state,
                    memory,
                    pid,
                    previous,
                    self.clock.unwrap_or_else(Instant::now),
                    |fd| Some(self.membership.as_ref()?.uring_file(fd)),
                ) else {
                    return Some(IoAttempt::Checkpoint);
                };
                // No malformed request needs to retain an unused source OFD.
                if r.error.is_some() {
                    if let Some(file) = r.file.take() {
                        rejected_files.push(file);
                    }
                } else if let Some(file) = r.file.take() {
                    let (bound, retired) = ring.bind_file_deferred(&file);
                    if !retired.is_empty() {
                        retired_graph.push(retired);
                    }
                    match bound {
                        Ok(bound) => {
                            r.resource = self.accepted_resource(&bound);
                            r.file = Some(bound);
                        }
                        Err(error) => {
                            r.error = Some(error);
                            rejected_files.push(file);
                        }
                    }
                }
                if r.error.is_none() && matches!(r.sqe.opcode(), 26 | 27) && r.sqe.offset() != 0 {
                    r.error = Some(Errno(22));
                }
                metadata += r.metadata();
                if metadata > 1024 * 1024 {
                    rejected_requests.push(r);
                    break;
                }
                let context = matches!(r.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23)
                    && (self.context.get().is_some() || r.resource.is_none())
                    && r.file.is_some()
                    || matches!(
                        r.sqe.opcode(),
                        3 | 13 | 16 | 17 | 18 | 19 | 21 | 28 | 34 | 45 | 55 | 56 | 57
                    )
                    || r.sqe.opcode() == 6
                        && !matches!(
                            r.resource.as_ref().map(|f| &f.object),
                            Some(Object::Byte(_))
                        )
                    || matches!(r.sqe.opcode(), 26 | 27)
                        && (r.resource.is_none()
                            || matches!(
                                r.resource.as_ref().map(|f| &f.object),
                                Some(Object::Tcp(_))
                            ) && r.sqe.op_flags()
                                & !(if r.sqe.opcode() == 26 {
                                    0x40 | 0x4000
                                } else {
                                    2 | 0x40
                                })
                                != 0);
                if r.error.is_none() && context {
                    if let Some(context) = self.context.get() {
                        self.actor().accept(&ring, &mut r, context.clone());
                    } else if r.resource.is_none() || r.sqe.opcode() != 6 {
                        prepared.push(Some(r));
                        return Some(IoAttempt::Checkpoint);
                    }
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
                    let mut r = r;
                    r.source = Some(Arc::downgrade(
                        &(self.actor().clone() as Arc<dyn trames_vfs::UringSource>),
                    ));
                    state.insert(r);
                } else {
                    state.dropped = state.dropped.wrapping_add(1);
                }
            }
            ring.store_queue(0, state.head);
            ring.store_queue(20, state.dropped);
            state.waits.insert(pid, (submitted, deadline));
        }
        drop(state);
        let deferred = self.progress(&ring, memory, pid);
        let mut state = ring.state.lock().unwrap();
        if state
            .pending
            .iter()
            .any(|r| r.owner == self.owner && r.task == pid)
        {
            self.actor().track(&ring);
        }
        let tail = state.tail;
        let count = match ring.flush(&mut state) {
            Ok(count) => count,
            Err(error) => {
                state.waits.remove(&pid);
                return Some(IoAttempt::Complete(Err(error)));
            }
        };
        let completion_event = ring.completion_event(&state, count);
        let ready = args[3] & 1 == 0
            || args[2] == 0
            || state.tail.wrapping_sub(ring.load_queue(64)) >= args[2] as u32;
        let (submitted, deadline) = state.waits.get(&pid).copied().unwrap_or((0, None));
        let expired = deadline.is_some_and(|d| Instant::now() >= d);
        if ready || expired {
            state.waits.remove(&pid);
        }
        let changed = tail != state.tail;
        drop(state);
        if changed {
            ring.notify_completion(completion_event);
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
                aio: None,
                number: 426,
                args,
                deadline,
                signal,
                resource_deadline: None,
                flock: None,
                retained_byte: None,
                retained_socket: None,
                native_tcp: None,
                epoll_revision: None,
                retained_poll: None,
                _subscriptions: Vec::new(),
                socket_subscriptions: Vec::new(),
                host_subscription: None,
                poll_uring: None,
                file: None,
                target: target.clone(),
                uring: Some(Box::new(Wait {
                    ring,
                    actor: self.actor().clone(),
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
        if !wait.sources.prepare(
            std::slice::from_ref(&wait.ring),
            wait.owner,
            wait.task,
            &pending.signal,
            &wait.target,
            &wait.actor,
            memory,
        ) {
            return IoAttempt::Checkpoint;
        }
        let deferred = self.progress(&wait.ring, memory, wait.task);
        let mut state = wait.ring.state.lock().unwrap();
        let tail = state.tail;
        let count = match wait.ring.flush(&mut state) {
            Ok(count) => count,
            Err(error) => {
                state.waits.remove(&wait.task);
                return IoAttempt::Complete(Err(error));
            }
        };
        let completion_event = wait.ring.completion_event(&state, count);
        let changed = tail != state.tail;
        let (submitted, deadline) = state
            .waits
            .get(&wait.task)
            .copied()
            .unwrap_or((0, pending.deadline));
        pending.deadline = deadline;
        let ready = pending.args[3] & 1 == 0
            || pending.args[2] == 0
            || state.tail.wrapping_sub(wait.ring.load_queue(64)) >= pending.args[2] as u32;
        let expired = deadline.is_some_and(|d| Instant::now() >= d);
        if ready || expired {
            state.waits.remove(&wait.task);
        }
        let checkpoint = deferred;
        drop(state);
        pending.resource_deadline = [
            wait.ring.request_deadline(wait.owner, wait.task),
            wait.sources.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
        if changed {
            wait.ring.notify_completion(completion_event);
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
/// Accepted enter metadata, retaining the original ring across task handoff.
/// Queue cursors, requests and registration authority stay in the shared ring.
#[derive(Clone)]
pub struct UringEnter {
    pub ring: Arc<Uring>,
    pub submitted: u32,
    pub deadline: Option<Instant>,
}
impl PendingIo {
    pub fn uring_enter(&self) -> Option<UringEnter> {
        let wait = self.uring.as_ref()?;
        let (submitted, deadline) = wait
            .ring
            .state
            .lock()
            .unwrap()
            .waits
            .get(&wait.task)
            .copied()?;
        Some(UringEnter {
            ring: wait.ring.clone(),
            submitted,
            deadline,
        })
    }
}
impl DirectSyscalls {
    pub fn start_retained_uring(
        &self,
        call: UringEnter,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if pid != self.urings.task {
            return IoAttempt::Checkpoint;
        }
        self.urings.ensure_context(
            self.paths.as_ref(),
            self.resources.as_ref(),
            &self.files,
            self.file_executor.as_ref(),
            self.file_layouts.as_ref(),
            self.task_signal.as_ref(),
        );
        call.ring
            .state
            .lock()
            .unwrap()
            .waits
            .entry(pid)
            .or_insert((call.submitted, call.deadline));
        self.urings
            .start_ring(call.ring, args, memory, pid, target)
            .expect("retained original ring")
    }
}
pub(super) struct Wait {
    ring: Arc<Ring>,
    actor: Arc<UringActor>,
    owner: u64,
    task: u32,
    sources: wait::WaitSources,
    target: Weak<dyn IoWake>,
}
impl Wait {
    pub fn external(&self) -> bool {
        self.sources.external() || self.actor.pending_disk()
    }
}

#[derive(Default)]
pub struct UringEpoch {
    _marker: std::marker::PhantomData<()>,
}
pub struct UringHandoff {
    pub task: u32,
    pub submitted: Option<u32>,
    pub ring: Arc<Uring>,
    pub deadline: Option<Instant>,
}
impl UringEpoch {
    pub fn has_native_wait(ring: &Arc<Uring>, owner: u64, task: u32) -> bool {
        ring.state.lock().unwrap().pending.iter().any(|r| {
            r.owner == owner
                && r.task == task
                && r.started
                && matches!(r.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23 | 26 | 27)
                && r.file.as_ref().is_some_and(|f| f.direct_tcp().is_some())
        })
    }
    pub fn has_event_wait(
        ring: &Arc<Uring>,
        owner: u64,
        task: u32,
        enter_deadline: Option<Instant>,
    ) -> bool {
        Self::has_native_wait(ring, owner, task)
            || enter_deadline.is_some()
            || ring.next_deadline().is_some()
                && ring.state.lock().unwrap().pending.iter().any(|r| {
                    r.owner == owner && r.task == task && r.started && r.deadline.is_some()
                })
    }
    pub fn poll_rings(
        vfs: &Vfs,
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
        task: u32,
    ) -> Option<Vec<Arc<Uring>>> {
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
                        .lock()
                        .unwrap()
                        .pending
                        .iter()
                        .all(|r| r.owner == owner && r.task == task)
            }))
        .then_some(rings)
    }
    /// Admission hint for an already parked enter. Mapping/FD mutation still
    /// joins; the snapshot performs final capability admission before effects.
    pub fn can_adopt(ring: &Arc<Uring>) -> bool {
        let state = ring.state.lock().unwrap();
        state.pending.iter().all(|r| {
            r.error.is_some()
                || r.execution.is_some()
                || Request::supported(&r.sqe)
                    && r.path.is_none()
                    && (r.resource.is_some()
                        || r.file
                            .as_ref()
                            .is_none_or(|f| f.is_signalfd() || Resource::capture(f).is_some()))
        })
    }
    pub fn adopt_wait(
        &mut self,
        task: u32,
        ring: &Arc<Uring>,
        submitted: u32,
        deadline: Option<Instant>,
    ) -> bool {
        ring.state
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
        let mut snapshot = UringSnapshot {
            owner,
            task,
            membership: Some(vfs.shared_files()),
            files: files.clone(),
            retained_files: retained_files.clone(),
            ..Default::default()
        };
        snapshot.prepare_rings(vfs.urings());
        #[cfg(test)]
        for (fd, ring) in vfs.uring_descriptors() {
            snapshot.rings.insert(fd, ring);
        }
        snapshot.descriptors = Some(vfs.direct_descriptors());
        snapshot
    }
    /// The original shared state and waits remain in place across cohorts.
    pub fn finish(self) -> Vec<UringHandoff> {
        Vec::new()
    }
}

#[cfg(test)]
#[path = "uring/subsystem_tests.rs"]
mod subsystem_tests;

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
        r.state.lock().unwrap().head = u32::MAX - 1;
        r.state.lock().unwrap().tail = u32::MAX - 1;
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
        assert_eq!(r.state.lock().unwrap().head, 4);
        assert_eq!(r.state.lock().unwrap().tail, 4);
    }
    #[test]
    fn local_uring_mixed_batch_reports_unknown_opcode_without_owner_dispatch() {
        let (l, mut m, fd, r) = setup(4);
        let t = target();
        add(&mut m, &r, sqe(0, 0, 1));
        add(&mut m, &r, sqe(255, 0, 2));
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, m.instruction_identity().0, 7);
        complete(start(&s, fd, 2, 0, &mut m, &t), 2);
        assert_eq!(m.read_array::<4>(0x10000).unwrap(), 2u32.to_le_bytes());
        assert_eq!(r.cq_ready(), 2);
        assert!(epoch.finish().is_empty());
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
        assert!(handoff.is_empty());
        assert_eq!(r.state.lock().unwrap().waits[&7].0, 1);
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
        let _ = epoch.finish();
        assert_eq!(r.state.lock().unwrap().pending.len(), 1);
        let mut child = m.clone();
        l.vfs.write(writer, b"v").unwrap();
        let mut epoch = UringEpoch::default();
        let s = epoch.capture(&l.vfs, child.instruction_identity().0, 8);
        complete(start(&s, fd, 0, 0, &mut child, &t), 0);
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), [0]);
        let active = epoch.finish();
        assert!(active.is_empty());
        assert_eq!(r.state.lock().unwrap().pending[0].task, 7);
        assert!(!r.state.lock().unwrap().waits.contains_key(&7));
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
        assert_eq!(r.state.lock().unwrap().head, 8);
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
        assert!(epoch.finish().is_empty());
        assert_eq!(r.state.lock().unwrap().waits[&7].0, 1);
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
    fn local_uring_regular_files_preserve_offsets_and_grow_without_handoff() {
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
        complete(start(&s, fd, 1, 1, &mut m, &t), 1);
        assert_eq!(cq(&mut m, &r), (52, 1));
        assert_eq!(l.vfs.seek(file, 0, 1), Ok(1));
        drop(s);
        assert!(epoch.finish().is_empty());
        files.finish();
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
