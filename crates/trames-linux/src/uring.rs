// SPDX-License-Identifier: GPL-3.0-or-later
//! A bounded guest io_uring engine. Requests use the original VFS byte/offset
//! operations; readiness, timeouts and CQ overflow survive the submitting call.
use crate::direct::uring::StateOps;
use crate::{Linux, MAX_WRITE};
use std::{
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use trames_memory::{Access, Memory};
use trames_vfs::{
    Errno, Uring, UringFileView, UringRequest, UringSqe, UringState, URING_CQES, URING_MAX_ENTRIES,
    URING_OPS, URING_SQ_ARRAY,
};
pub(crate) mod buffers;
pub(crate) mod execute;
pub(crate) mod time;
type Result<T> = std::result::Result<T, Errno>;
fn u32_at(bytes: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap())
}
fn put(bytes: &mut [u8], i: usize, v: u32) {
    bytes[i..i + 4].copy_from_slice(&v.to_le_bytes());
}
impl Linux {
    pub fn worker_uring_event(&self, memory: &Memory, task: u32) -> bool {
        self.uring_actor.get().is_some_and(|actor| {
            actor.active()
                && !actor.owner_required()
                && (actor.event_wait(memory.instruction_identity().0, task)
                    || self.vfs.has_native_event_sources())
        })
    }
    pub fn uring_requires_owner(&self) -> bool {
        self.uring_actor
            .get()
            .is_some_and(|actor| actor.owner_required())
    }
    pub fn worker_uring_pending(&self) -> bool {
        self.uring_actor
            .get()
            .is_some_and(|actor| actor.active() && !actor.owner_required())
    }
    pub fn uring_actor_root(&self) -> std::sync::Arc<std::sync::OnceLock<Arc<crate::UringActor>>> {
        self.uring_actor.clone()
    }
    pub fn track_uring(&mut self, ring: &Arc<Uring>) {
        self.uring_actor.get_or_init(Arc::default).track(ring);
    }

    pub fn set_uring_clock(&mut self, started: Instant) {
        self.uring_clock = started;
    }

    pub(crate) fn uring_setup(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        let (entries, cq_entries, output) = setup_parameters(a, memory)?;
        self.vfs
            .uring_create_with_output(entries, cq_entries, || {
                memory.write(a[1], &output).map_err(|_| Errno(14))
            })
            .map(|(fd, _)| fd as u64)
    }
    pub(crate) fn uring_register(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        let ring = self.vfs.uring(a[0] as u32)?;
        let result = register(&ring, a, memory, true, |fd| {
            Some(self.vfs.retain_uring_file(fd))
        })
        .expect("owner has original Files and pin authority");
        self.vfs.reap_uring_files();
        result
    }

    fn uring_request(
        &self,
        sqe: UringSqe,
        state: &mut UringState,
        memory: &Memory,
        task: u32,
        dependency: Option<(u64, bool)>,
    ) -> UringRequest {
        state.next += 1;
        import_request(
            sqe,
            state.next,
            state,
            memory,
            task,
            dependency,
            self.uring_clock,
            |fd| Some(self.vfs.retain_uring_file(fd)),
        )
        .expect("joined file authority")
    }

    pub fn uring_enter_deadline(&self, a: [u64; 6], memory: &Memory) -> Result<Option<Instant>> {
        time::enter_deadline(a, memory, self.uring_clock)
    }

    pub fn uring_enter(
        &mut self,
        a: [u64; 6],
        memory: &mut Memory,
        saved: Option<u32>,
        task: u32,
    ) -> Result<(u32, bool)> {
        let ring = self.vfs.uring(a[0] as u32)?;
        self.uring_enter_ring(ring, a, memory, saved, task)
    }
    pub fn uring_enter_ring(
        &mut self,
        ring: Arc<Uring>,
        a: [u64; 6],
        memory: &mut Memory,
        saved: Option<u32>,
        task: u32,
    ) -> Result<(u32, bool)> {
        if saved.is_none() {
            self.uring_enter_deadline(a, memory)?;
        }
        if a[2] > ring.cq_entries as u64 {
            return Err(Errno(22));
        }
        let submitted = if let Some(n) = saved {
            n
        } else {
            let mut retired_files = Vec::new();
            let mut retired_graph = Vec::new();
            let mut retired_requests = Vec::new();
            let mut state = ring.state.lock().unwrap();
            let head = ring.cq_head(&state)?;
            let available = ring.sq_tail().wrapping_sub(state.head);
            if available > ring.entries {
                return Err(Errno(22));
            }
            let count = available.min(a[1] as u32);
            let outstanding = state.pending.len()
                + state.inflight
                + state.shot_reservations
                + state.overflow.len()
                + state.tail.wrapping_sub(head) as usize;
            if outstanding + count as usize > ring.outstanding_limit() {
                return Err(Errno(16));
            }
            let mut previous = None;
            let mut consumed = 0;
            let mut metadata: usize = state.inflight_metadata
                + state
                    .pending
                    .iter()
                    .map(|r| {
                        512 + r.parts.as_ref().map_or(0, |p| p.len() * 16)
                            + r.path.as_ref().map_or(0, Vec::len)
                    })
                    .sum::<usize>();
            for _ in 0..count {
                let sqe = ring.sqe(state.head);
                let Some(sqe) = sqe else {
                    state.head = state.head.wrapping_add(1);
                    consumed += 1;
                    state.dropped = state.dropped.wrapping_add(1);
                    previous = None;
                    continue;
                };
                let mut request = self.uring_request(sqe, &mut state, memory, task, previous);
                if let Some(file) = request.file.take() {
                    if request.error.is_some() {
                        retired_files.push(file);
                    } else {
                        let (bound, retired) = ring.bind_file_deferred(&file);
                        if !retired.is_empty() {
                            retired_graph.push(retired);
                        }
                        match bound {
                            Ok(bound) => request.file = Some(bound),
                            Err(error) => {
                                request.error = Some(error);
                                retired_files.push(file);
                            }
                        }
                    }
                }
                let bytes = 512
                    + request.parts.as_ref().map_or(0, |p| p.len() * 16)
                    + request.path.as_ref().map_or(0, Vec::len);
                if metadata + bytes > 1024 * 1024 {
                    retired_requests.push(request);
                    break;
                }
                metadata += bytes;
                state.head = state.head.wrapping_add(1);
                consumed += 1;
                previous = if request.sqe.flags() & (4 | 8) != 0 {
                    Some((request.sequence, request.sqe.flags() & 8 != 0))
                } else {
                    None
                };
                let actor = self.uring_actor.get_or_init(Arc::default).clone();
                request.source = Some(Arc::downgrade(&(actor as Arc<dyn trames_vfs::UringSource>)));
                state.insert(request);
            }
            if consumed == 0 && count != 0 {
                return Err(Errno(16));
            }
            ring.publish_head(&state);
            consumed
        };
        self.progress_ring(&ring, memory, task);
        if ring
            .state
            .lock()
            .unwrap()
            .pending
            .iter()
            .any(|r| r.owner == memory.instruction_identity().0 && r.task == task)
        {
            self.track_uring(&ring);
        }
        Ok((
            submitted,
            a[3] & 1 == 0 || a[2] == 0 || ring.cq_ready() >= a[2] as u32,
        ))
    }
    fn complete_request(
        state: &mut UringState,
        request: &UringRequest,
        result: i32,
        success: bool,
    ) {
        Self::post_uring_completion(state, request, result, 0, Some(success));
    }
    fn post_uring_completion(
        state: &mut UringState,
        request: &UringRequest,
        result: i32,
        flags: u32,
        terminal: Option<bool>,
    ) {
        state.post(request, Ok(result), flags, terminal);
    }

    fn progress_ring(&mut self, ring: &Arc<Uring>, memory: &mut Memory, task: u32) -> bool {
        use crate::direct::uring::RingOps;
        let before = {
            let state = ring.state.lock().unwrap();
            (state.tail, state.overflow.len())
        };
        let actor = self.uring_actor.get();
        ring.progress_with(
            memory,
            memory.instruction_identity().0,
            task,
            &mut |request, memory, selected| {
                actor
                    .and_then(|actor| actor.execute(ring, request, memory, selected))
                    .or_else(|| Some(execute::owner(&mut self.vfs, request, memory, selected)))
            },
        );
        let mut state = ring.state.lock().unwrap();
        let changed = before != (state.tail, state.overflow.len());
        let count = ring.flush(&mut state).unwrap_or(0);
        let event = ring.completion_event(&state, count);
        drop(state);
        if changed || count != 0 {
            ring.notify_completion(event);
        }
        self.vfs.reap_uring_files();
        changed || count != 0
    }
    /// Existing joined scheduling checkpoints drive only rings with accepted
    /// requests. No SQPOLL, new thread, timer bus or per-operation RPC is added.
    pub fn progress_uring(&mut self, memory: &mut Memory, task: u32) -> bool {
        let mut changed = false;
        let rings = self.uring_rings();
        for ring in &rings {
            changed |= self.progress_ring(ring, memory, task);
        }
        if let Some(actor) = self.uring_actor.get() {
            if changed {
                actor.owner_progressed();
            }
            actor.reset_active(rings.iter().any(|ring| {
                ring.state
                    .lock()
                    .unwrap()
                    .pending
                    .iter()
                    .any(|r| r.owner == memory.instruction_identity().0 && r.task == task)
            }));
        }
        changed
    }
    pub fn cancel_uring(&mut self, memory: &mut Memory, task: u32) {
        let owner = memory.instruction_identity().0;
        for ring in self.uring_rings() {
            let mut retired = Vec::new();
            let mut state = ring.state.lock().unwrap();
            let mut pending = std::mem::take(&mut state.pending);
            while let Some(request) = pending.pop_front() {
                if request.owner == owner && request.task == task {
                    Self::complete_request(&mut state, &request, -125, false);
                    retired.push(request);
                } else {
                    state.pending.push_back(request);
                }
            }
            state.waits.remove(&task);
            let count = ring.flush(&mut state).unwrap_or(0);
            let event = ring.completion_event(&state, count);
            drop(state);
            drop(retired);
            ring.notify_completion(event);
        }
        self.vfs.reap_uring_files();
    }
    pub fn uring_deadline(&self) -> Option<Instant> {
        self.uring_rings()
            .iter()
            .filter_map(|r| r.next_deadline())
            .min()
    }
    pub fn uring_pending(&self) -> bool {
        self.uring_rings()
            .iter()
            .any(|r| !r.state.lock().unwrap().pending.is_empty())
    }
    pub fn uring_native_wait_fds(&self) -> Vec<trames_vfs::HostFd> {
        self.uring_rings()
            .iter()
            .flat_map(|ring| ring.native_wait_fds())
            .collect()
    }
    pub fn uring_sockets(&self) -> Vec<(std::sync::Arc<trames_net::Socket>, u16)> {
        self.uring_rings()
            .iter()
            .flat_map(|r| r.sockets())
            .collect()
    }
    pub fn uring_rings(&self) -> Vec<Arc<Uring>> {
        let mut rings = self.vfs.urings();
        if let Some(actor) = self.uring_actor.get() {
            for ring in actor.rings() {
                if !rings.iter().any(|r| Arc::ptr_eq(r, &ring)) {
                    rings.push(ring);
                }
            }
        }
        rings
    }
}

pub(crate) fn probe(a: [u64; 6], memory: &mut impl trames_memory::CpuMemory) -> Result<u64> {
    if a[3] > 256 {
        return Err(Errno(22));
    }
    let size = 16 + a[3] as usize * 8;
    Linux::check(memory, a[2], size, Access::Write)?;
    let mut output = vec![0; size];
    output[0] = *URING_OPS.last().unwrap();
    output[1] = a[3].min(output[0] as u64 + 1) as u8;
    for i in 0..output[1] as usize {
        output[16 + i * 8] = i as u8;
        if URING_OPS.contains(&(i as u8)) {
            output[18 + i * 8] = 1;
        }
    }
    memory.write(a[2], &output).map_err(|_| Errno(14))?;
    Ok(0)
}

pub(crate) fn setup_parameters(
    a: [u64; 6],
    memory: &impl trames_memory::CpuMemory,
) -> Result<(u32, u32, [u8; 120])> {
    Linux::check(memory, a[1], 120, Access::Write)?;
    let input = memory.read_array::<120>(a[1]).map_err(|_| Errno(14))?;
    let flags = u32_at(&input, 8);
    if flags & !(8 | 16) != 0 {
        return Err(Errno(22));
    }
    if input[12..40].iter().any(|b| *b != 0) {
        return Err(Errno(22));
    }
    let requested = a[0] as u32;
    if requested == 0 || requested > URING_MAX_ENTRIES && flags & 16 == 0 {
        return Err(Errno(22));
    }
    let entries = requested.min(URING_MAX_ENTRIES).next_power_of_two();
    let cq_entries = if flags & 8 != 0 {
        let requested = u32_at(&input, 4);
        if requested < entries || requested > URING_MAX_ENTRIES * 2 && flags & 16 == 0 {
            return Err(Errno(22));
        }
        requested.min(URING_MAX_ENTRIES * 2).next_power_of_two()
    } else {
        entries * 2
    };
    let mut output = [0; 120];
    for (i, v) in [
        (0, entries),
        (4, cq_entries),
        (8, flags),
        (20, 1 | 2 | (1 << 8)),
        (40, 0),
        (44, 4),
        (48, 8),
        (52, 12),
        (56, 16),
        (60, 20),
        (64, URING_SQ_ARRAY as u32),
        (80, 64),
        (84, 68),
        (88, 72),
        (92, 76),
        (96, 80),
        (100, URING_CQES as u32),
        (104, 84),
    ] {
        put(&mut output, i, v);
    }
    Ok((entries, cq_entries, output))
}

/// One registration algorithm over the original ring. Excluded owner controls
/// and structural pinning defer before publishing any registration change.
pub(crate) fn register(
    ring: &Arc<Uring>,
    a: [u64; 6],
    memory: &mut impl trames_memory::CpuMemory,
    owner: bool,
    mut accept: impl FnMut(u32) -> Option<Result<trames_vfs::UringFile>>,
) -> Option<Result<u64>> {
    let deferred = std::cell::Cell::new(false);
    let mut accepted_originals = Vec::new();
    let mut retired_graph = Vec::new();
    let mut capture = |fd| {
        let file = accept(fd).unwrap_or_else(|| {
            deferred.set(true);
            Err(Errno(95))
        })?;
        let (bound, retired) = ring.bind_file_deferred(&file);
        if !retired.is_empty() {
            retired_graph.push(retired);
        }
        accepted_originals.push(file);
        bound
    };
    let mut imports = Vec::new();
    let mut updates = Vec::new();
    let mut retired_updates = Vec::new();
    let mut retired_files = None;
    let mut retired_buffers = None;
    let mut retired_event = None;
    let mut state = ring.state.lock().unwrap();
    let value = (|| match a[1] as u32 {
        22 | 23 | 26 => buffers::register_ring(&mut state, a, memory, &deferred),
        0 => {
            if state.buffers.is_some() {
                return Err(Errno(16));
            }
            if a[3] == 0 || a[3] > 1024 {
                return Err(Errno(22));
            }
            Linux::check(memory, a[2], a[3] as usize * 16, Access::Read)?;
            let mut total = 0u64;
            let mut vectors = Vec::new();
            for i in 0..a[3] {
                let address = memory.read_u64(a[2] + i * 16).map_err(|_| Errno(14))?;
                let length = memory.read_u64(a[2] + i * 16 + 8).map_err(|_| Errno(14))?;
                total = total
                    .checked_add(length)
                    .filter(|n| *n <= 64 * 1024 * 1024)
                    .ok_or(Errno(12))?;
                if length == 0 {
                    return Err(Errno(14));
                }
                vectors.push((address, length as usize));
            }
            let buffers = vectors
                .into_iter()
                .map(|(address, length)| {
                    memory
                        .pin_buffer_rw(address, length)
                        .unwrap_or_else(|| {
                            deferred.set(true);
                            Err(trames_memory::MemoryError::BackingIo(95))
                        })
                        .map(std::sync::Arc::new)
                        .map_err(|e| match e {
                            trames_memory::MemoryError::BackingIo(95) => Errno(95),
                            trames_memory::MemoryError::Limit => Errno(12),
                            _ => Errno(14),
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            state.buffers = Some(buffers);
            Ok(0)
        }
        1 => {
            if a[2] != 0 || a[3] != 0 {
                return Err(Errno(22));
            }
            retired_buffers = Some(state.buffers.take().ok_or(Errno(6))?);
            Ok(0)
        }
        2 => {
            if state.files.is_some() {
                return Err(Errno(16));
            }
            if a[3] == 0 || a[3] > URING_MAX_ENTRIES as u64 {
                return Err(Errno(22));
            }
            Linux::check(memory, a[2], a[3] as usize * 4, Access::Read)?;
            for i in 0..a[3] {
                let accepted = (|| {
                    let fd = memory
                        .read_array::<4>(a[2] + i * 4)
                        .map_err(|_| Errno(14))?;
                    let fd = i32::from_le_bytes(fd);
                    if fd == -1 {
                        Ok(None)
                    } else {
                        capture(fd as u32).map(Some)
                    }
                })()?;
                imports.push(accepted);
            }
            state.files = Some(std::mem::take(&mut imports));
            Ok(0)
        }
        3 => {
            if a[2] != 0 || a[3] != 0 {
                return Err(Errno(22));
            }
            if !owner
                && state.files.as_ref().is_some_and(|files| {
                    files
                        .iter()
                        .flatten()
                        .any(|file| file.shared_file().is_none())
                })
            {
                deferred.set(true);
                return Err(Errno(95));
            }
            retired_files = Some(state.files.take().ok_or(Errno(6))?);
            Ok(0)
        }
        4 => {
            if a[3] != 1 {
                return Err(Errno(22));
            }
            if state.eventfd.is_some() {
                return Err(Errno(16));
            }
            let fd = u32::from_le_bytes(memory.read_array(a[2]).map_err(|_| Errno(14))?);
            state.eventfd = Some({
                let file = capture(fd)?;
                if !file.is_eventfd() {
                    return Err(Errno(22));
                }
                file
            });
            Ok(0)
        }
        5 => {
            if a[2] != 0 || a[3] != 0 {
                return Err(Errno(22));
            }
            retired_event = Some(state.eventfd.take().ok_or(Errno(6))?);
            Ok(0)
        }
        6 => {
            let input = memory.read_array::<16>(a[2]).map_err(|_| Errno(14))?;
            if u32_at(&input, 4) != 0 || a[3] == 0 || a[3] > URING_MAX_ENTRIES as u64 {
                return Err(Errno(22));
            }
            let offset = u32_at(&input, 0) as usize;
            let address = u64_at(&input, 8);
            let files = state.files.as_mut().ok_or(Errno(6))?;
            if offset
                .checked_add(a[3] as usize)
                .is_none_or(|end| end > files.len())
            {
                return Err(Errno(22));
            }
            Linux::check(memory, address, a[3] as usize * 4, Access::Read)?;
            let mut changed = 0;
            let mut first_error = None;
            for i in 0..a[3] as usize {
                let fd = i32::from_le_bytes(
                    memory
                        .read_array(address + i as u64 * 4)
                        .map_err(|_| Errno(14))?,
                );
                let file = match fd {
                    -2 => {
                        changed += 1;
                        continue;
                    }
                    -1 => Ok(None),
                    _ => capture(fd as u32).map(Some),
                };
                match file {
                    Ok(file) => {
                        updates.push((offset + i, file));
                        changed += 1;
                    }
                    Err(e) if changed == 0 => {
                        first_error = Some(e);
                        break;
                    }
                    Err(_) => break,
                }
            }
            if !owner
                && updates.iter().any(|(index, _)| {
                    files[*index]
                        .as_ref()
                        .is_some_and(|file| file.shared_file().is_none())
                })
            {
                deferred.set(true);
            }
            if deferred.get() {
                return Err(Errno(95));
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            for (index, file) in updates.drain(..) {
                if let Some(old) = std::mem::replace(&mut files[index], file) {
                    retired_updates.push(old);
                }
            }
            Ok(changed)
        }
        8 => probe(a, memory),
        // Async-only eventfd needs an execution-context distinction.
        _ => Err(Errno(22)),
    })();
    drop(state);
    if deferred.get() {
        None
    } else {
        Some(value)
    }
}

/// Shared one-time SQE metadata import. Ordinary data bytes remain execution-time
/// accesses; no guest pointer, vector table or sockaddr is re-read after parking.
#[allow(clippy::too_many_arguments)] // One accepted SQE plus original source/import context.
pub(crate) fn import_request(
    sqe: UringSqe,
    sequence: u64,
    state: &UringState,
    memory: &impl trames_memory::CpuMemory,
    task: u32,
    dependency: Option<(u64, bool)>,
    clock: Instant,
    mut accept: impl FnMut(u32) -> Option<Result<trames_vfs::UringFile>>,
) -> Option<UringRequest> {
    let timeout_deadline =
        |address, flags| time::deadline(memory, address, flags, clock).map(|d| d.0);

    let mut request = UringRequest {
        owner: memory.instruction_identity().0,
        task,
        sequence,
        sqe,
        resource: None,
        execution: None,
        source: None,
        file: None,
        buffer: None,
        error: None,
        dependency,
        deadline: None,
        parts: None,
        requested: 0,
        path: None,
        how: None,
        started: false,
        timeout_count: None,
        timeout_target: None,
        timeout_duration: None,
        shots: 0,
        poll_ready: 0,
        poll_epoch: [0; 2],
    };
    let s = &request.sqe;
    request.requested = s.length() as u64;
    let ioprio_mask = match s.opcode() {
        13 => 1,
        27 => 3,
        _ => 0,
    };
    let group_field = matches!(s.opcode(), 4 | 5 | 31 | 32) || s.flags() & 32 != 0;
    if s.flags() & !63 != 0
        || s.ioprio() & !ioprio_mask != 0
        || s.flags() & 32 != 0 && !matches!(s.opcode(), 22 | 27)
        || s.0[40..64]
            .iter()
            .enumerate()
            .any(|(i, b)| *b != 0 && !(group_field && i < 2))
        || s.opcode() == 27
            && s.multishot()
            && (s.flags() & 32 == 0 || s.length() != 0 || s.op_flags() & (2 | 0x40 | 0x100) != 0)
    {
        request.error = Some(Errno(22));
    }
    if !URING_OPS.contains(&s.opcode()) {
        request.error = Some(Errno(22));
    }
    if request.error.is_some() {
        return Some(request);
    }
    let path_op = matches!(s.opcode(), 18 | 21 | 28);
    if path_op {
        let path = if s.opcode() == 21 && s.address() == 0 && s.op_flags() & 0x1000 != 0 {
            Ok(Vec::new())
        } else {
            Linux::path(memory, s.address())
        };
        match path {
            Ok(path) => request.path = Some(path),
            Err(e) => {
                request.error = Some(e);
                return Some(request);
            }
        }
    }
    let absolute = request.path.as_ref().is_some_and(|p| p.starts_with(b"/"));
    let takes_file = matches!(
        s.opcode(),
        1 | 2 | 3 | 4 | 5 | 6 | 13 | 16 | 17 | 22 | 23 | 26 | 27 | 34 | 55 | 56 | 57
    ) || s.opcode() == 14 && s.op_flags() & 2 != 0;
    if takes_file || path_op && s.fd() != -100 && !absolute {
        let file = if s.flags() & 1 != 0 || s.opcode() == 14 && s.op_flags() & 8 != 0 {
            state
                .files
                .as_ref()
                .and_then(|files| files.get(s.fd() as usize))
                .and_then(Clone::clone)
                .ok_or(Errno(9))
        } else {
            accept(s.fd() as u32)?
        };
        match file {
            Ok(file) => request.file = Some(file),
            Err(e) => request.error = Some(e),
        }
    } else if s.flags() & 1 != 0 {
        request.error = Some(Errno(22));
    }
    if matches!(s.opcode(), 4 | 5) {
        let index = u16::from_le_bytes(s.0[40..42].try_into().unwrap()) as usize;
        match state
            .buffers
            .as_ref()
            .and_then(|buffers| buffers.get(index))
        {
            Some(buffer) if buffer.range(s.address(), s.length() as usize).is_ok() => {
                request.buffer = Some(buffer.clone())
            }
            _ => request.error = Some(Errno(14)),
        }
    }
    if matches!(s.opcode(), 1 | 2) {
        match Linux::positioned_vector_import(
            memory,
            [0, s.address(), s.length() as u64, 0, 0, 0],
            s.opcode() == 2,
        ) {
            Ok(vector) => {
                request.requested = vector.requested;
                request.parts = Some(vector.parts);
            }
            Err(e) => request.error = Some(e),
        }
    }
    if matches!(s.opcode(), 16 | 56) {
        let address = (|| {
            if !(2..=128).contains(&s.offset()) {
                return Err(Errno(22));
            }
            let mut bytes = vec![0; s.offset() as usize];
            memory
                .read(s.address(), &mut bytes)
                .map_err(|_| Errno(14))?;
            Ok(bytes)
        })();
        match address {
            Ok(bytes) => request.path = Some(bytes),
            Err(e) => request.error = Some(e),
        }
    }
    if s.opcode() == 28 {
        let how = Linux::decode_open_how(memory, s.offset(), s.length() as u64);
        match how {
            Ok(how) => request.how = Some(how),
            Err(e) => request.error = Some(e),
        }
    }
    if s.opcode() == 11 && request.error.is_none() {
        let timeout = if s.length() != 1 {
            Err(Errno(22))
        } else {
            if s.multishot() && s.op_flags() & 1 != 0 {
                Err(Errno(22))
            } else {
                timeout_deadline(s.address(), s.op_flags() & !64)
            }
        };
        request.timeout_duration = crate::timer::duration(memory, s.address()).ok();
        match timeout {
            Ok(deadline) => {
                if s.op_flags() & 1 != 0 {
                    request.deadline = Some(deadline);
                }
            }
            Err(e) => request.error = Some(e),
        }
    }

    if s.opcode() == 15 {
        request.timeout_target = dependency.map(|d| d.0);
        if dependency.is_none() || s.length() != 1 || s.offset() != 0 {
            request.error = Some(Errno(22));
        } else {
            match timeout_deadline(s.address(), s.op_flags()) {
                Ok(deadline) => {
                    request.deadline = Some(deadline);
                    request.timeout_duration = crate::timer::duration(memory, s.address()).ok();
                }
                Err(e) => request.error = Some(e),
            }
        }
    }
    if s.opcode() == 12 && s.op_flags() & (2 | 16) != 0 {
        if s.op_flags() & 18 == 18 || s.op_flags() & !31 != 0 {
            request.error = Some(Errno(22));
        } else {
            match timeout_deadline(s.offset(), s.op_flags() & !18) {
                Ok(deadline) => {
                    request.deadline = Some(deadline);
                    request.timeout_duration = crate::timer::duration(memory, s.offset()).ok();
                }
                Err(e) => request.error = Some(e),
            }
        }
    }

    Some(request)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    const QUEUE: u64 = 0x10000;
    const SQES: u64 = 0x20000;
    fn memory() -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE * 4, Permissions::RW).unwrap();
        m
    }
    pub(crate) fn setup(entries: u32) -> (Linux, Memory, u32, Arc<Uring>) {
        let mut l = Linux::new(0x100000);
        let mut m = memory();
        let fd = l
            .uring_setup([entries as u64, 0x1000, 0, 0, 0, 0], &mut m)
            .unwrap() as u32;
        let r = l.vfs.uring(fd).unwrap();
        for (address, offset, len) in [(QUEUE, 0, r.ring_bytes), (SQES, 0x10000000, r.sqe_bytes)] {
            let pages = l.vfs.mapping_pages(fd, offset, len, true, true).unwrap();
            m.map_backed(address, pages, true, Permissions::RW, false)
                .unwrap();
        }
        (l, m, fd, r)
    }
    pub(crate) fn add(m: &mut Memory, r: &Uring, sqe: [u8; 64]) {
        let tail = u32::from_le_bytes(m.read_array(QUEUE + 4).unwrap());
        let slot = tail & (r.entries - 1);
        m.write(SQES + slot as u64 * 64, &sqe).unwrap();
        m.write_array(
            QUEUE + URING_SQ_ARRAY as u64 + slot as u64 * 4,
            slot.to_le_bytes(),
        )
        .unwrap();
        m.write_array(QUEUE + 4, tail.wrapping_add(1).to_le_bytes())
            .unwrap();
    }
    pub(crate) fn sqe(op: u8, fd: u32, data: u64) -> [u8; 64] {
        let mut s = [0; 64];
        s[0] = op;
        put(&mut s, 4, fd);
        s[32..40].copy_from_slice(&data.to_le_bytes());
        s
    }
    pub(crate) fn enter(l: &mut Linux, m: &mut Memory, fd: u32, count: u32) {
        assert_eq!(
            l.uring_enter([fd as u64, count as u64, 0, 0, 0, 0], m, None, 7),
            Ok((count, true))
        );
    }
    pub(crate) fn cq(m: &mut Memory, r: &Uring) -> (u64, i32) {
        let head = u32::from_le_bytes(m.read_array(QUEUE + 64).unwrap());
        let bytes = m
            .read_array::<16>(QUEUE + URING_CQES as u64 + (head & (r.cq_entries - 1)) as u64 * 16)
            .unwrap();
        m.write_array(QUEUE + 64, head.wrapping_add(1).to_le_bytes())
            .unwrap();
        (u64_at(&bytes, 0), u32_at(&bytes, 8) as i32)
    }
    #[test]
    fn setup_validates_before_allocating_and_rejects_unimplemented_modes() {
        let mut l = Linux::new(0x100000);
        let mut m = memory();
        for entries in [0, 4097, u32::MAX] {
            assert_eq!(
                l.uring_setup([entries as u64, 0x1000, 0, 0, 0, 0], &mut m),
                Err(Errno(22))
            );
        }
        assert_eq!(
            l.uring_setup([8, 0x4ff0, 0, 0, 0, 0], &mut m),
            Err(Errno(14))
        );
        for flags in [1u32, 2, 4, 32, 64, 128, 256] {
            m.write_array(0x1008, flags.to_le_bytes()).unwrap();
            assert_eq!(
                l.uring_setup([8, 0x1000, 0, 0, 0, 0], &mut m),
                Err(Errno(22))
            );
        }
        assert!(l.vfs.urings().is_empty());
    }
    #[test]
    fn corrupt_user_indices_are_bounded_and_bad_sqe_indices_are_dropped() {
        let (mut l, mut m, fd, r) = setup(2);
        m.write_array(QUEUE + 4, 3u32.to_le_bytes()).unwrap();
        assert_eq!(
            l.uring_enter([fd as u64, 3, 0, 0, 0, 0], &mut m, None, 7),
            Err(Errno(22))
        );
        assert_eq!(r.state.lock().unwrap().head, 0);
        m.write_array(QUEUE + 4, 1u32.to_le_bytes()).unwrap();
        m.write_array(QUEUE + URING_SQ_ARRAY as u64, 99u32.to_le_bytes())
            .unwrap();
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(r.state.lock().unwrap().dropped, 1);
        assert_eq!(r.cq_ready(), 0);
        m.write_array(QUEUE + 64, (r.cq_entries + 1).to_le_bytes())
            .unwrap();
        assert_eq!(
            l.uring_enter([fd as u64, 0, 0, 0, 0, 0], &mut m, None, 7),
            Err(Errno(22))
        );
    }
    #[test]
    fn queue_indices_wrap_without_losing_or_overwriting_completions() {
        let (mut l, mut m, fd, r) = setup(2);
        {
            let mut s = r.state.lock().unwrap();
            s.head = u32::MAX;
            s.tail = u32::MAX;
            r.publish_head(&s);
        }
        m.write_array(QUEUE + 4, u32::MAX.to_le_bytes()).unwrap();
        m.write_array(QUEUE + 64, u32::MAX.to_le_bytes()).unwrap();
        add(&mut m, &r, sqe(0, 0, 1));
        add(&mut m, &r, sqe(0, 0, 2));
        enter(&mut l, &mut m, fd, 2);
        assert_eq!(r.cq_ready(), 2);
        assert_eq!(cq(&mut m, &r), (1, 0));
        assert_eq!(cq(&mut m, &r), (2, 0));
        assert_eq!(r.cq_ready(), 0);
    }
    #[test]
    fn accepted_cq_overflow_applies_backpressure_without_dropping_requests() {
        let (mut l, mut m, fd, r) = setup(2);
        for i in (0..16).step_by(2) {
            add(&mut m, &r, sqe(0, 0, i));
            add(&mut m, &r, sqe(0, 0, i + 1));
            enter(&mut l, &mut m, fd, 2);
        }
        add(&mut m, &r, sqe(0, 0, 16));
        assert_eq!(
            l.uring_enter([fd as u64, 1, 0, 0, 0, 0], &mut m, None, 7),
            Err(Errno(16))
        );
        assert_eq!(r.state.lock().unwrap().head, 16);
        for i in 0..16 {
            if r.cq_ready() == 0 {
                assert!(l.progress_uring(&mut m, 7));
            }
            assert_eq!(cq(&mut m, &r), (i, 0));
        }
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (16, 0));
    }
    #[test]
    fn short_linked_read_cancels_following_request_and_preserves_file_position() {
        let (mut l, mut m, fd, r) = setup(2);
        let file = l.vfs.open_at(-100, b"/empty", 0x42, 0o600).unwrap();
        let mut read = sqe(22, file, 1);
        read[1] = 4;
        read[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut read, 24, 4);
        add(&mut m, &r, read);
        add(&mut m, &r, sqe(0, 0, 2));
        enter(&mut l, &mut m, fd, 2);
        assert_eq!(cq(&mut m, &r), (1, 0));
        assert_eq!(cq(&mut m, &r), (2, -125));
        assert_eq!(l.vfs.seek(file, 0, 1), Ok(0));
    }
    #[test]
    fn submission_is_not_replayed_while_getevents_waits_and_exit_cancels_it() {
        let (mut l, mut m, fd, r) = setup(2);
        let [read, _write] = l.vfs.pipe(0).unwrap();
        let mut s = sqe(22, read, 1);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        assert_eq!(
            l.uring_enter([fd as u64, 1, 1, 1, 0, 0], &mut m, None, 7),
            Ok((1, false))
        );
        add(&mut m, &r, sqe(0, 0, 2));
        assert_eq!(
            l.uring_enter([fd as u64, 1, 1, 1, 0, 0], &mut m, Some(1), 7),
            Ok((1, false))
        );
        assert_eq!(r.state.lock().unwrap().head, 1);
        l.cancel_uring(&mut m, 7);
        assert_eq!(cq(&mut m, &r), (1, -125));
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (2, 0));
    }
    #[test]
    fn pending_buffers_are_never_used_in_another_task_or_address_space() {
        let (mut l, mut m, fd, r) = setup(2);
        let [read, write] = l.vfs.pipe(0).unwrap();
        let mut s = sqe(22, read, 1);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        let mut other = m.clone();
        l.vfs.write(write, b"x").unwrap();
        assert!(!l.progress_uring(&mut other, 7));
        assert!(!l.progress_uring(&mut m, 8));
        assert!(l.progress_uring(&mut m, 7));
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"x");
        assert_eq!(other.read_array::<1>(0x2000).unwrap(), [0]);
    }
    #[test]
    fn fixed_file_registration_is_transactional_and_private_fd_views_restore_on_panic() {
        let (mut l, mut m, fd, r) = setup(2);
        let file = l.vfs.open_at(-100, b"/file", 0x42, 0o600).unwrap();
        m.write_array(0x2000, file.to_le_bytes()).unwrap();
        m.write_array(0x2004, 999u32.to_le_bytes()).unwrap();
        assert_eq!(
            l.uring_register([fd as u64, 2, 0x2000, 2, 0, 0], &mut m),
            Err(Errno(9))
        );
        assert!(r.state.lock().unwrap().files.is_none());
        let handle = l.vfs.retain_uring_fd(file).unwrap();
        let before = l.vfs.clone_with_files(true);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| l
            .vfs
            .with_uring_fd(&handle, |_, _| panic!("injected operation panic"))))
        .is_err());
        assert!(l.vfs.fd_kind(file).is_ok());
        assert!(l.vfs.shares_descriptors_with(&before));
    }
    #[test]
    fn cached_ring_discovery_is_weak_and_mappings_retain_the_original_registered_files() {
        let (mut l, mut m, fd, r) = setup(2);
        let (ring_bytes, sqe_bytes) = (r.ring_bytes, r.sqe_bytes);
        let file = l
            .vfs
            .open_at(-100, b"/registered-mmap", 0x42, 0o600)
            .unwrap();
        let contender = l.vfs.open_at(-100, b"/registered-mmap", 2, 0).unwrap();
        l.vfs.flock(file, 6).unwrap();
        m.write_array(0x2000, file.to_le_bytes()).unwrap();
        l.uring_register([fd as u64, 2, 0x2000, 1, 0, 0], &mut m)
            .unwrap();
        l.vfs.close(file).unwrap();
        let weak = Arc::downgrade(&r);
        assert_eq!(l.vfs.urings().len(), 1);
        drop(r);
        l.vfs.close(fd).unwrap();
        assert!(l.vfs.urings().is_empty());
        assert!(weak.upgrade().is_some());
        assert_eq!(m.read_array::<4>(QUEUE + 12).unwrap(), 2u32.to_le_bytes());
        assert_eq!(l.vfs.flock(contender, 6), Err(Errno(11)));
        m.unmap(SQES, sqe_bytes).unwrap();
        assert!(weak.upgrade().is_some());
        m.unmap(QUEUE, ring_bytes).unwrap();
        assert!(weak.upgrade().is_none());
        l.vfs.flock(contender, 6).unwrap();
    }
    #[test]
    fn imported_vector_metadata_is_bounded_and_partial_submissions_are_not_lost() {
        let (mut l, mut m, fd, r) = setup(128);
        let [read, _write] = l.vfs.pipe(0).unwrap();
        m.write(0x1000, &[0; 16384]).unwrap();
        m.write_array(0x1000, 0x4fffu64.to_le_bytes()).unwrap();
        m.write_array(0x1008, 1u64.to_le_bytes()).unwrap();
        for i in 0..128 {
            let mut s = sqe(1, read, i);
            s[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
            put(&mut s, 24, 1024);
            add(&mut m, &r, s);
        }
        let mut consumed = 0;
        while consumed < 128 {
            let (n, ready) = l
                .uring_enter([fd as u64, 128, 0, 0, 0, 0], &mut m, None, 7)
                .unwrap();
            assert!(ready && n > 0 && n < 128);
            assert!(r.state.lock().unwrap().pending.len() < 64);
            l.cancel_uring(&mut m, 7);
            consumed += n;
        }
        assert_eq!(consumed, 128);
        for i in 0..128 {
            assert_eq!(cq(&mut m, &r), (i, -125));
        }
    }
    #[test]
    fn fsync_uses_the_retained_file_and_invalid_enter_does_not_consume_sqes() {
        let (mut l, mut m, fd, r) = setup(2);
        let file = l.vfs.open_at(-100, b"/sync", 0x42, 0o600).unwrap();
        l.vfs.write(file, b"data").unwrap();
        add(&mut m, &r, sqe(3, file, 1));
        assert_eq!(
            l.uring_enter([fd as u64, 1, 0, 4, 0, 0], &mut m, None, 7),
            Err(Errno(22))
        );
        assert_eq!(r.state.lock().unwrap().head, 0);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (1, 0));
        let [read, _write] = l.vfs.pipe(0).unwrap();
        add(&mut m, &r, sqe(3, read, 2));
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (2, -22));
    }
    #[test]
    fn submitted_requests_keep_progressing_after_submitter_closes_its_ring_fd() {
        let (mut l, mut m, fd, r) = setup(2);
        let other = l.clone();
        let [read, write] = l.vfs.pipe(0).unwrap();
        let mut s = sqe(22, read, 1);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        l.vfs.close(fd).unwrap();
        assert!(l.vfs.urings().is_empty());
        assert!(other.vfs.uring(fd).is_ok());
        l.vfs.write(write, b"x").unwrap();
        assert!(l.progress_uring(&mut m, 7));
        assert_eq!(cq(&mut m, &r), (1, 1));
        assert_eq!(m.read_array::<1>(0x2000).unwrap(), *b"x");
    }
    #[test]
    fn malformed_absolute_open_cannot_clear_invalid_flags_or_allocate_a_file() {
        let (mut l, mut m, fd, r) = setup(2);
        m.write(0x2000, b"/should-not-exist\0").unwrap();
        let mut s = sqe(18, 999, 1);
        s[1] = 0x80;
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 28, 0x42);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (1, -22));
        assert!(l.vfs.stat_at(-100, b"/should-not-exist").is_err());
    }
    #[test]
    fn linked_timeout_can_expire_a_drain_predecessor_and_cancel_the_rest() {
        let (mut l, mut m, fd, r) = setup(4);
        let [read, _write] = l.vfs.pipe(0).unwrap();
        m.write(0x2100, &[0; 16]).unwrap();
        let mut s = sqe(22, read, 1);
        s[1] = 2 | 4;
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        let mut s = sqe(15, 0, 2);
        s[1] = 4;
        s[16..24].copy_from_slice(&0x2100u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        add(&mut m, &r, sqe(0, 0, 3));
        enter(&mut l, &mut m, fd, 3);
        assert_eq!(cq(&mut m, &r), (1, -125));
        assert_eq!(cq(&mut m, &r), (2, -62));
        assert_eq!(cq(&mut m, &r), (3, -125));
    }
    #[test]
    fn invalid_timeout_update_preserves_the_original_deadline() {
        let (mut l, mut m, fd, r) = setup(2);
        m.write_array(0x2000, 3600u64.to_le_bytes()).unwrap();
        m.write_array(0x2008, 0u64.to_le_bytes()).unwrap();
        let mut s = sqe(11, 0, 1);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        let before = r.state.lock().unwrap().pending[0].deadline;
        let mut s = sqe(12, 0, 2);
        s[16..24].copy_from_slice(&1u64.to_le_bytes());
        s[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 28, 2 | 16);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (2, -22));
        assert_eq!(r.state.lock().unwrap().pending[0].deadline, before);
    }
    #[test]
    fn cancel_fixed_file_uses_original_ofd_after_numeric_fd_reuse() {
        let (mut l, mut m, fd, r) = setup(4);
        let [read, _write] = l.vfs.pipe(0).unwrap();
        m.write_array(0x2000, read.to_le_bytes()).unwrap();
        l.uring_register([fd as u64, 2, 0x2000, 1, 0, 0], &mut m)
            .unwrap();
        let mut s = sqe(22, read, 1);
        s[16..24].copy_from_slice(&0x2100u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        l.vfs.close(read).unwrap();
        let [new, _] = l.vfs.pipe(0).unwrap();
        assert_eq!(new, read);
        let mut s = sqe(14, 0, 2);
        put(&mut s, 28, 1 | 2 | 8);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (1, -125));
        assert_eq!(cq(&mut m, &r), (2, 1));
    }
    #[test]
    fn buffer_registration_is_transactional_and_shared_backings_are_not_fake_pinned() {
        let (mut l, mut m, fd, r) = setup(2);
        m.write_array(0x2000, 0x3000u64.to_le_bytes()).unwrap();
        m.write_array(0x2008, 8u64.to_le_bytes()).unwrap();
        m.write_array(0x2010, 0x9000u64.to_le_bytes()).unwrap();
        m.write_array(0x2018, 8u64.to_le_bytes()).unwrap();
        assert_eq!(
            l.uring_register([fd as u64, 0, 0x2000, 2, 0, 0], &mut m),
            Err(Errno(14))
        );
        assert!(r.state.lock().unwrap().buffers.is_none());
        m.write_array(0x2000, QUEUE.to_le_bytes()).unwrap();
        assert_eq!(
            l.uring_register([fd as u64, 0, 0x2000, 1, 0, 0], &mut m),
            Err(Errno(95))
        );
        assert!(r.state.lock().unwrap().buffers.is_none());
    }
    fn cq_flags(m: &mut Memory, r: &Uring) -> (u64, i32, u32) {
        let head = u32::from_le_bytes(m.read_array(QUEUE + 64).unwrap());
        let bytes = m
            .read_array::<16>(QUEUE + URING_CQES as u64 + (head & (r.cq_entries - 1)) as u64 * 16)
            .unwrap();
        m.write_array(QUEUE + 64, head.wrapping_add(1).to_le_bytes())
            .unwrap();
        (
            u64_at(&bytes, 0),
            u32_at(&bytes, 8) as i32,
            u32_at(&bytes, 12),
        )
    }
    fn poll_multi(m: &mut Memory, r: &Uring, file: u32, data: u64, level: bool) {
        let mut s = sqe(6, file, data);
        put(&mut s, 24, if level { 9 } else { 1 });
        put(&mut s, 28, 1);
        add(m, r, s);
    }
    #[test]
    fn multishot_cq_pressure_preserves_more_flags_and_leaves_room_for_terminal_results() {
        let (mut l, mut m, fd, r) = setup(2);
        let event = l.vfs.eventfd(1, 0).unwrap();
        poll_multi(&mut m, &r, event, 1, true);
        enter(&mut l, &mut m, fd, 1);
        {
            let ready = r.cq_ready();
            let s = r.state.lock().unwrap();
            assert_eq!(s.pending.len(), 1);
            assert_eq!(
                s.pending.len() + s.overflow.len() + ready as usize,
                r.outstanding_limit()
            );
        }
        let before = r.state.lock().unwrap().completion_count;
        l.progress_uring(&mut m, 7);
        assert_eq!(r.state.lock().unwrap().completion_count, before);
        for _ in 0..4 {
            assert_eq!(cq_flags(&mut m, &r), (1, 1, 2));
        }
        let mut cancel = sqe(14, 0, 2);
        cancel[16..24].copy_from_slice(&1u64.to_le_bytes());
        add(&mut m, &r, cancel);
        enter(&mut l, &mut m, fd, 1);
        let mut final_count = 0;
        for _ in 0..32 {
            if r.cq_ready() == 0 {
                l.progress_uring(&mut m, 7);
            }
            if r.cq_ready() == 0 {
                break;
            }
            let c = cq_flags(&mut m, &r);
            match c {
                (1, 1, 2) => {}
                (1, -125, 0) | (2, 0, 0) => final_count += 1,
                _ => panic!("unexpected CQE {c:?}"),
            }
        }
        assert_eq!(final_count, 2);
        assert!(r.state.lock().unwrap().pending.is_empty());
    }
    #[test]
    fn multishot_budget_rotates_past_64_requests_and_idle_high_sequences_do_not_starve_peers() {
        let (mut l, mut m, fd, r) = setup(128);
        let event = l.vfs.eventfd(1, 0).unwrap();
        for id in 1..=128 {
            poll_multi(&mut m, &r, event, id, false);
        }
        enter(&mut l, &mut m, fd, 128);
        assert_eq!(r.cq_ready(), 64);
        for id in 1..=64 {
            assert_eq!(cq_flags(&mut m, &r), (id, 1, 2));
        }
        l.progress_uring(&mut m, 7);
        for id in 65..=128 {
            assert_eq!(cq_flags(&mut m, &r), (id, 1, 2));
        }
        // Every lower poll sees a new event epoch; append a higher idle watcher.
        let idle = l.vfs.eventfd(0, 0).unwrap();
        poll_multi(&mut m, &r, idle, 129, false);
        enter(&mut l, &mut m, fd, 1);
        l.vfs.write(event, &1u64.to_le_bytes()).unwrap();
        l.progress_uring(&mut m, 7);
        assert!(r.cq_ready() > 0);
    }
    #[test]
    fn provided_pools_do_not_translate_another_vms_addresses_or_pin_invalid_data() {
        let (mut l, mut m, fd, r) = setup(4);
        let [read, write] = l.vfs.pipe(0).unwrap();
        let mut s = sqe(31, 1, 1);
        s[16..24].copy_from_slice(&0x3000u64.to_le_bytes());
        put(&mut s, 24, 4);
        s[40..42].copy_from_slice(&9u16.to_le_bytes());
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (1, 0, 0));
        l.vfs.write(write, b"keep").unwrap();
        let mut other = m.clone();
        let mut s = sqe(22, read, 2);
        s[1] = 32;
        put(&mut s, 24, 4);
        s[40..42].copy_from_slice(&9u16.to_le_bytes());
        add(&mut other, &r, s);
        enter(&mut l, &mut other, fd, 1);
        assert_eq!(cq_flags(&mut other, &r), (2, -14, 0));
        assert_eq!(r.state.lock().unwrap().provided[&9].slots(), 1);
        assert_eq!(l.vfs.read(read, 4).unwrap(), b"keep");
    }
    #[test]
    fn provided_ring_tail_wrap_is_bounded_and_status_does_not_advance_it() {
        use trames_vfs::{UringBufferGroup, UringBufferSource};
        let (mut l, mut m, fd, r) = setup(4);
        let [read, write] = l.vfs.pipe(0).unwrap();
        let pin = std::sync::Arc::new(m.pin_rw(0x3000, 32).unwrap());
        let mut descriptor = [0u8; 16];
        descriptor[..8].copy_from_slice(&0x4000u64.to_le_bytes());
        put(&mut descriptor, 8, 1);
        descriptor[12..14].copy_from_slice(&65535u16.to_le_bytes());
        pin.write(16, &descriptor).unwrap();
        pin.write(14, &0u16.to_le_bytes()).unwrap();
        r.state.lock().unwrap().provided.insert(
            7,
            UringBufferGroup::new(
                m.instruction_identity().0,
                UringBufferSource::Ring {
                    memory: pin.clone(),
                    head: u16::MAX,
                    entries: 2,
                },
            ),
        );
        l.vfs.write(write, b"ab").unwrap();
        let mut s = sqe(22, read, 1);
        s[1] = 32;
        put(&mut s, 24, 1);
        s[40..42].copy_from_slice(&7u16.to_le_bytes());
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (1, 1, 1 | (65535u32 << 16)));
        assert_eq!(m.read_array::<1>(0x4000).unwrap(), *b"a");
        pin.write(14, &3u16.to_le_bytes()).unwrap();
        s[32..40].copy_from_slice(&2u64.to_le_bytes());
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (2, -22, 0));
        assert_eq!(l.vfs.read(read, 1).unwrap(), b"b");
        m.write(0x2100, &[0; 40]).unwrap();
        m.write_array(0x2100, 7u32.to_le_bytes()).unwrap();
        l.uring_register([fd as u64, 26, 0x2100, 1, 0, 0], &mut m)
            .unwrap();
        assert_eq!(m.read_u64(0x2100).unwrap(), 7);
    }
    #[test]
    fn buffer_ring_registration_validates_before_pin_and_classic_pools_have_metadata_limits() {
        let (mut l, mut m, fd, r) = setup(4);
        m.write(0x2000, &[0; 40]).unwrap();
        m.write_array(0x2000, 0x3000u64.to_le_bytes()).unwrap();
        m.write_array(0x2008, 3u32.to_le_bytes()).unwrap();
        assert_eq!(
            l.uring_register([fd as u64, 22, 0x2000, 1, 0, 0], &mut m),
            Err(Errno(22))
        );
        assert!(r.state.lock().unwrap().provided.is_empty());
        let mut s = sqe(31, 65536, 1);
        s[16..24].copy_from_slice(&0x4000u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (1, 0, 0));
        s[40..42].copy_from_slice(&1u16.to_le_bytes());
        put(&mut s, 4, 1);
        s[32..40].copy_from_slice(&2u64.to_le_bytes());
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (2, -12, 0));
        assert_eq!(r.state.lock().unwrap().provided[&0].slots(), 65536);
    }
    #[test]
    fn multishot_notifications_include_more_and_cancellation_has_no_stale_flags() {
        let (mut l, mut m, fd, r) = setup(4);
        let notify = l.vfs.eventfd(0, 0).unwrap();
        let ready = l.vfs.eventfd(1, 0).unwrap();
        m.write_array(0x2000, notify.to_le_bytes()).unwrap();
        l.uring_register([fd as u64, 4, 0x2000, 1, 0, 0], &mut m)
            .unwrap();
        poll_multi(&mut m, &r, ready, 1, false);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (1, 1, 2));
        assert_eq!(l.vfs.read(notify, 8).unwrap(), 1u64.to_le_bytes());
        let mut s = sqe(14, 0, 2);
        s[16..24].copy_from_slice(&1u64.to_le_bytes());
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (1, -125, 0));
        assert_eq!(cq_flags(&mut m, &r), (2, 0, 0));
        assert_eq!(l.vfs.read(notify, 8).unwrap(), 2u64.to_le_bytes());
    }
    #[test]
    fn repeating_timeout_update_copies_the_new_interval_and_absolute_multishot_is_rejected() {
        let (mut l, mut m, fd, r) = setup(4);
        m.write_array(0x2000, 3600u64.to_le_bytes()).unwrap();
        m.write_array(0x2008, 0u64.to_le_bytes()).unwrap();
        let mut s = sqe(11, 0, 1);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        s[8..16].copy_from_slice(&2u64.to_le_bytes());
        put(&mut s, 24, 1);
        put(&mut s, 28, 64);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        m.write(0x2100, &[0; 16]).unwrap();
        let mut s = sqe(12, 0, 2);
        s[16..24].copy_from_slice(&1u64.to_le_bytes());
        s[8..16].copy_from_slice(&0x2100u64.to_le_bytes());
        put(&mut s, 28, 2);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (2, 0, 0));
        assert_eq!(cq_flags(&mut m, &r), (1, -62, 2));
        assert_eq!(cq_flags(&mut m, &r), (1, -62, 0));
        let mut s = sqe(11, 0, 3);
        s[16..24].copy_from_slice(&0x2100u64.to_le_bytes());
        put(&mut s, 24, 1);
        put(&mut s, 28, 64 | 1);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (3, -22, 0));
    }
    #[test]
    fn ordinary_timeout_arms_after_its_dependency_and_count_starts_at_issue() {
        let (mut l, mut m, fd, r) = setup(4);
        let [read, write] = l.vfs.pipe(0).unwrap();
        m.write_array(0x2000, 3600u64.to_le_bytes()).unwrap();
        m.write_array(0x2008, 0u64.to_le_bytes()).unwrap();
        let mut s = sqe(22, read, 1);
        s[1] = 4;
        s[16..24].copy_from_slice(&0x3000u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        let mut s = sqe(11, 0, 2);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        s[8..16].copy_from_slice(&1u64.to_le_bytes());
        put(&mut s, 24, 1);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 2);
        assert_eq!(l.uring_deadline(), None);
        l.vfs.write(write, b"x").unwrap();
        l.progress_uring(&mut m, 7);
        assert_eq!(cq_flags(&mut m, &r), (1, 1, 0));
        assert_eq!(r.cq_ready(), 0);
        assert!(l.uring_deadline().is_some());
        add(&mut m, &r, sqe(0, 0, 3));
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq_flags(&mut m, &r), (3, 0, 0));
        assert_eq!(cq_flags(&mut m, &r), (2, 0, 0));
    }
    #[test]
    fn backpressured_multishot_timer_does_not_force_expired_scheduler_wakeups() {
        let (mut l, mut m, fd, r) = setup(2);
        m.write(0x2000, &[0; 16]).unwrap();
        let mut s = sqe(11, 0, 1);
        s[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 24, 1);
        put(&mut s, 28, 64);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(r.state.lock().unwrap().pending.len(), 1);
        assert_eq!(l.uring_deadline(), None);
        for _ in 0..4 {
            assert_eq!(cq_flags(&mut m, &r), (1, -62, 2));
        }
        assert!(l.uring_deadline().is_some());
    }
}
