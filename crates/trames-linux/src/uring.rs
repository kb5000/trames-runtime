// SPDX-License-Identifier: GPL-3.0-or-later
//! A bounded guest io_uring engine. Requests use the original VFS byte/offset
//! operations; readiness, timeouts and CQ overflow survive the submitting call.
use crate::{Linux, MAX_WRITE};
use std::{
    collections::VecDeque,
    rc::Rc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use trames_memory::{Access, Memory};
use trames_vfs::{
    Errno, Uring, UringRequest, UringSqe, UringState, URING_CQES, URING_MAX_ENTRIES, URING_OPS,
    URING_SQ_ARRAY,
};
pub(crate) mod buffers;
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
    pub fn track_uring(&mut self, ring: &Rc<Uring>) {
        if !self
            .uring_active
            .iter()
            .any(|r| r.ptr_eq(&Rc::downgrade(ring)))
        {
            self.uring_active.push(Rc::downgrade(ring));
        }
    }
    pub fn set_uring_clock(&mut self, started: Instant) {
        self.uring_clock = started;
    }
    fn uring_timeout_deadline(&self, memory: &Memory, address: u64, flags: u32) -> Result<Instant> {
        time::deadline(memory, address, flags, self.uring_clock).map(|d| d.0)
    }

    pub(crate) fn uring_setup(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        Self::check(memory, a[1], 120, Access::Write)?;
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
        let (fd, _ring) = self.vfs.uring_create(entries, cq_entries)?;
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
        memory.write(a[1], &output).map_err(|_| Errno(14))?;
        Ok(fd as u64)
    }
    pub(crate) fn uring_register(&mut self, a: [u64; 6], memory: &mut Memory) -> Result<u64> {
        let ring = self.vfs.uring(a[0] as u32)?;
        let mut state = ring.state.borrow_mut();
        match a[1] as u32 {
            22 | 23 | 26 => self.uring_buffer_register(&mut state, a, memory),
            0 => {
                if state.buffers.is_some() {
                    return Err(Errno(16));
                }
                if a[3] == 0 || a[3] > 1024 {
                    return Err(Errno(22));
                }
                Self::check(memory, a[2], a[3] as usize * 16, Access::Read)?;
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
                            .pin_rw(address, length)
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
                state.buffers.take().ok_or(Errno(6))?;
                Ok(0)
            }
            2 => {
                if state.files.is_some() {
                    return Err(Errno(16));
                }
                if a[3] == 0 || a[3] > URING_MAX_ENTRIES as u64 {
                    return Err(Errno(22));
                }
                Self::check(memory, a[2], a[3] as usize * 4, Access::Read)?;
                let files = (0..a[3])
                    .map(|i| {
                        let fd = memory
                            .read_array::<4>(a[2] + i * 4)
                            .map_err(|_| Errno(14))?;
                        let fd = i32::from_le_bytes(fd);
                        if fd == -1 {
                            Ok(None)
                        } else {
                            self.vfs.retain_uring_fd(fd as u32).map(Some)
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                state.files = Some(files);
                Ok(0)
            }
            3 => {
                if a[2] != 0 || a[3] != 0 {
                    return Err(Errno(22));
                }
                state.files.take().ok_or(Errno(6))?;
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
                state.eventfd = Some(self.vfs.uring_eventfd(fd)?);
                Ok(0)
            }
            5 => {
                if a[2] != 0 || a[3] != 0 {
                    return Err(Errno(22));
                }
                state.eventfd.take().ok_or(Errno(6))?;
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
                Self::check(memory, address, a[3] as usize * 4, Access::Read)?;
                let mut changed = 0;
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
                        _ => self.vfs.retain_uring_fd(fd as u32).map(Some),
                    };
                    match file {
                        Ok(file) => {
                            files[offset + i] = file;
                            changed += 1;
                        }
                        Err(e) if changed == 0 => return Err(e),
                        Err(_) => break,
                    }
                }
                Ok(changed)
            }
            8 => probe(a, memory),
            // Async-only eventfd needs an execution-context distinction.
            _ => Err(Errno(22)),
        }
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
        let mut request = UringRequest {
            owner: memory.instruction_identity().0,
            task,
            sequence: state.next,
            sqe,
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
                && (s.flags() & 32 == 0
                    || s.length() != 0
                    || s.op_flags() & (2 | 0x40 | 0x100) != 0)
        {
            request.error = Some(Errno(22));
        }
        if !URING_OPS.contains(&s.opcode()) {
            request.error = Some(Errno(22));
        }
        if request.error.is_some() {
            return request;
        }
        let path_op = matches!(s.opcode(), 18 | 21 | 28);
        if path_op {
            let path = if s.opcode() == 21 && s.address() == 0 && s.op_flags() & 0x1000 != 0 {
                Ok(Vec::new())
            } else {
                Self::path(memory, s.address())
            };
            match path {
                Ok(path) => request.path = Some(path),
                Err(e) => {
                    request.error = Some(e);
                    return request;
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
                self.vfs.retain_uring_fd(s.fd() as u32)
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
            match Self::positioned_vector_import(
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
            let how = Self::decode_open_how(memory, s.offset(), s.length() as u64);
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
                    self.uring_timeout_deadline(memory, s.address(), s.op_flags() & !64)
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
                match self.uring_timeout_deadline(memory, s.address(), s.op_flags()) {
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
                match self.uring_timeout_deadline(memory, s.offset(), s.op_flags() & !18) {
                    Ok(deadline) => {
                        request.deadline = Some(deadline);
                        request.timeout_duration = crate::timer::duration(memory, s.offset()).ok();
                    }
                    Err(e) => request.error = Some(e),
                }
            }
        }

        request
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
        ring: Rc<Uring>,
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
            let mut state = ring.state.borrow_mut();
            let head = ring.cq_head(&state)?;
            let available = ring.sq_tail().wrapping_sub(state.head);
            if available > ring.entries {
                return Err(Errno(22));
            }
            let count = available.min(a[1] as u32);
            let outstanding =
                state.pending.len() + state.overflow.len() + state.tail.wrapping_sub(head) as usize;
            if outstanding + count as usize > ring.outstanding_limit() {
                return Err(Errno(16));
            }
            let mut previous = None;
            let mut consumed = 0;
            let mut metadata: usize = state
                .pending
                .iter()
                .map(|r| {
                    512 + r.parts.as_ref().map_or(0, |p| p.len() * 16)
                        + r.path.as_ref().map_or(0, Vec::len)
                })
                .sum();
            for _ in 0..count {
                let sqe = ring.sqe(state.head);
                let Some(sqe) = sqe else {
                    state.head = state.head.wrapping_add(1);
                    consumed += 1;
                    state.dropped = state.dropped.wrapping_add(1);
                    previous = None;
                    continue;
                };
                let request = self.uring_request(sqe, &mut state, memory, task, previous);
                let bytes = 512
                    + request.parts.as_ref().map_or(0, |p| p.len() * 16)
                    + request.path.as_ref().map_or(0, Vec::len);
                if metadata + bytes > 1024 * 1024 {
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
                state.pending.push_back(request);
            }
            if consumed == 0 && count != 0 {
                return Err(Errno(16));
            }
            ring.publish_head(&state);
            consumed
        };
        if !self
            .uring_active
            .iter()
            .any(|r| r.ptr_eq(&Rc::downgrade(&ring)))
        {
            self.uring_active.push(Rc::downgrade(&ring));
        }
        self.progress_ring(&ring, memory, task);
        Ok((
            submitted,
            a[3] & 1 == 0 || a[2] == 0 || ring.cq_ready() >= a[2] as u32,
        ))
    }
    fn uring_rw(&mut self, request: &UringRequest, memory: &mut Memory) -> Result<(i32, bool)> {
        let s = &request.sqe;
        let write = matches!(s.opcode(), 2 | 5 | 23);
        if s.op_flags() & !8 != 0 {
            return Err(Errno(95));
        } // RWF_NOWAIT only
        let parts = if let Some(parts) = &request.parts {
            parts.clone()
        } else {
            vec![(s.address(), (s.length() as usize).min(MAX_WRITE))]
        };
        let count: usize = parts.iter().map(|p| p.1).sum();
        for &(address, len) in &parts {
            if len != 0 && request.buffer.is_none() {
                Self::check(
                    memory,
                    address,
                    len,
                    if write { Access::Read } else { Access::Write },
                )?;
            }
        }
        let file = request.file.as_ref().ok_or(Errno(9))?;
        let stream = file.stream();
        if stream && !matches!(s.offset(), 0 | u64::MAX) {
            return Err(Errno(29));
        }
        let mut bytes = Vec::new();
        let result = if write {
            if let Some(buffer) = &request.buffer {
                bytes = buffer
                    .read(
                        buffer.range(s.address(), count).map_err(|_| Errno(14))?,
                        count,
                    )
                    .map_err(|_| Errno(14))?;
            } else {
                Self::gather_parts(memory, &parts, count, &mut bytes)?;
            }
            self.vfs.with_uring_fd(file, |v, fd| {
                if stream || s.offset() == u64::MAX {
                    v.write(fd, &bytes)
                } else {
                    v.pwrite(fd, &bytes, s.offset())
                }
            })?
        } else {
            bytes = self.vfs.with_uring_fd(file, |v, fd| {
                if stream || s.offset() == u64::MAX {
                    v.read(fd, count)
                } else {
                    v.pread(fd, count, s.offset())
                }
            })?;
            if let Some(buffer) = &request.buffer {
                buffer
                    .write(
                        buffer
                            .range(s.address(), bytes.len())
                            .map_err(|_| Errno(14))?,
                        &bytes,
                    )
                    .map_err(|_| Errno(14))?;
            } else {
                Self::scatter(memory, &parts, &bytes)?;
            }
            bytes.len()
        };
        Ok((result as i32, result as u64 == request.requested))
    }
    fn uring_network(
        &mut self,
        request: &UringRequest,
        memory: &mut Memory,
    ) -> Result<(i32, bool)> {
        let s = &request.sqe;
        let file = request.file.as_ref().ok_or(Errno(9))?;
        if matches!(s.opcode(), 16 | 56) {
            if s.op_flags() != 0 || s.length() != 0 {
                return Err(Errno(22));
            }
            return self.vfs.with_uring_fd(file, |v, fd| {
                if let Some(socket) = v.local_socket(fd)? {
                    if s.opcode() == 16 {
                        v.local_connect(&socket, request.path.as_deref().unwrap())?;
                    } else {
                        v.local_bind(&socket, request.path.as_deref().unwrap())?;
                    }
                } else {
                    let socket = v.socket_fd(fd)?;
                    let result = if s.opcode() == 56 {
                        socket.bind_authorized(
                            request.path.as_deref().unwrap(),
                            v.credentials
                                .has_cap(trames_vfs::capabilities::NET_BIND_SERVICE),
                        )
                    } else if request.started {
                        socket.resume_connect().and_then(|ready| {
                            if ready {
                                Ok(())
                            } else {
                                Err(trames_net::NetError(11))
                            }
                        })
                    } else {
                        socket.connect_bytes(request.path.as_deref().unwrap())
                    };
                    result.map_err(|e| Errno(if e.0 == 115 { 11 } else { e.0 }))?;
                }
                Ok((0, true))
            });
        }
        if s.opcode() == 13 {
            if s.length() != 0 {
                return Err(Errno(22));
            }
            return self
                .vfs
                .with_uring_install(file, |v, fd| {
                    Self::network_vfs(
                        v,
                        242,
                        [
                            fd as u64,
                            s.address(),
                            s.offset(),
                            s.op_flags() as u64,
                            0,
                            0,
                        ],
                        memory,
                    )
                    .map(|fd| fd as u32)
                })
                .map(|fd| (fd as i32, true));
        }
        let (number, args) = match s.opcode() {
            26 | 27 if s.offset() == 0 => (
                if s.opcode() == 26 { 206 } else { 207 },
                [0, s.address(), s.length() as u64, s.op_flags() as u64, 0, 0],
            ),
            34 if s.op_flags() == 0 => (210, [0, s.length() as u64, 0, 0, 0, 0]),
            57 if s.op_flags() == 0 => (201, [0, s.length() as u64, 0, 0, 0, 0]),
            _ => return Err(Errno(22)),
        };
        self.vfs.with_uring_fd(file, |v, fd| {
            let mut args = args;
            args[0] = fd as u64;
            Self::network_vfs(v, number, args, memory).map(|n| {
                (
                    n as i32,
                    !matches!(s.opcode(), 26 | 27) || n == request.requested,
                )
            })
        })
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
        if let Some(success) = terminal {
            state.completed.insert(request.sequence, success);
        }
        if !matches!(request.sqe.opcode(), 11 | 15) {
            state.completion_count = state.completion_count.saturating_add(1);
        }
        state
            .overflow
            .push_back((request.sqe.user_data(), result, flags));
    }
    fn progress_ring(&mut self, ring: &Rc<Uring>, memory: &mut Memory, task: u32) -> bool {
        let mut state = ring.state.borrow_mut();
        if state.pending.is_empty() && state.overflow.is_empty() {
            return false;
        }
        let owner = memory.instruction_identity().0;
        let Ok(cq_head) = ring.cq_head(&state) else {
            return false;
        };
        // Bounded draining, then return to the existing scheduler. A sequence
        // cursor gives later multishot requests a turn across checkpoints.
        if !state
            .pending
            .iter()
            .any(|r| r.sqe.multishot() && r.sequence > state.multishot_cursor)
        {
            state.multishot_cursor = 0;
        }
        let mut cutoff = state.multishot_cursor;
        let mut shot_budget = 64usize;
        let mut any_changed = false;
        loop {
            let mut pending = std::mem::take(&mut state.pending);
            let mut waiting = VecDeque::new();
            let mut changed = false;
            while let Some(mut request) = pending.pop_front() {
                if request.owner != owner || request.task != task {
                    waiting.push_back(request);
                    continue;
                }
                if waiting.iter().any(|r: &UringRequest| {
                    r.sequence < request.sequence
                        && (request.sqe.flags() & 2 != 0 || r.sqe.flags() & 2 != 0)
                        && !(request.sqe.opcode() == 15
                            && request.timeout_target == Some(r.sequence))
                }) {
                    waiting.push_back(request);
                    continue;
                }
                if let Some((dependency, hard)) =
                    request.dependency.filter(|_| request.sqe.opcode() != 15)
                {
                    match state.completed.get(&dependency) {
                        None => {
                            waiting.push_back(request);
                            continue;
                        }
                        Some(false) if !hard => {
                            Self::complete_request(&mut state, &request, -125, false);
                            changed = true;
                            continue;
                        }
                        _ => {}
                    }
                }
                if request.error.is_none() && request.sqe.multishot() {
                    let outstanding = waiting.len()
                        + pending.len()
                        + 1
                        + state.overflow.len()
                        + state.tail.wrapping_sub(cq_head) as usize;
                    if shot_budget == 0
                        || request.sequence <= cutoff
                        || outstanding >= ring.outstanding_limit()
                    {
                        waiting.push_back(request);
                        continue;
                    }
                }
                // Relative/count timeouts arm when they issue, not while a
                // predecessor or IO_DRAIN is still holding them in the queue.
                if request.sqe.opcode() == 11 && !request.started && request.error.is_none() {
                    if request.sqe.op_flags() & 1 == 0 {
                        request.deadline = request
                            .timeout_duration
                            .and_then(|d| Instant::now().checked_add(d));
                    }
                    if !request.sqe.multishot() && request.sqe.offset() != 0 {
                        request.timeout_count =
                            Some(state.completion_count.saturating_add(request.sqe.offset()));
                    }
                    request.started = true;
                }
                // A linked timer runs beside its predecessor rather than waiting
                // for it. Relative timers arm when that predecessor first issues.
                if request.sqe.opcode() == 15 && !request.started {
                    if let Some(target) = request.timeout_target {
                        let running = waiting
                            .iter()
                            .chain(pending.iter())
                            .any(|r| r.sequence == target && r.started);
                        if running {
                            if request.sqe.op_flags() & 1 == 0 {
                                request.deadline = request
                                    .timeout_duration
                                    .and_then(|d| Instant::now().checked_add(d));
                            }
                            request.started = true;
                        }
                    }
                }
                let mut cqe_flags = 0;
                let s = &request.sqe;
                let result = if let Some(e) = request.error {
                    Err(e)
                } else {
                    match s.opcode() {
                        0 => {
                            if s.op_flags() != 0 {
                                Err(Errno(22))
                            } else {
                                Ok((0, true))
                            }
                        }
                        22 | 27 if s.flags() & 32 != 0 => {
                            let (result, flags) =
                                self.uring_selected_io(&request, &mut state, memory);
                            cqe_flags = flags;
                            result
                        }
                        1 | 2 | 4 | 5 | 22 | 23 => self.uring_rw(&request, memory),
                        3 => {
                            if s.op_flags() & !1 != 0 {
                                Err(Errno(22))
                            } else {
                                self.vfs
                                    .with_uring_fd(request.file.as_ref().unwrap(), |v, fd| {
                                        v.sync_fd(fd, s.op_flags() & 1 != 0)
                                    })
                                    .map(|()| (0, true))
                            }
                        }
                        6 => {
                            if s.length() & !9 != 0
                                || s.length() & 8 != 0 && !s.multishot()
                                || s.op_flags() & !0x201f != 0
                            {
                                Err(Errno(22))
                            } else {
                                let file = request.file.as_ref().unwrap();
                                let (events, epoch) = if s.multishot() {
                                    file.readiness(s.op_flags() as u16)
                                } else {
                                    (file.poll(s.op_flags() as u16), [0; 2])
                                };
                                let fresh = !s.multishot()
                                    || s.length() & 8 != 0
                                    || events & !request.poll_ready != 0
                                    || events & 3 != 0 && epoch[0] != request.poll_epoch[0]
                                    || events & 4 != 0 && epoch[1] != request.poll_epoch[1];
                                if events == 0 || !fresh {
                                    if events == 0 {
                                        request.poll_ready = 0;
                                        request.poll_epoch = epoch;
                                    }
                                    Err(Errno(11))
                                } else {
                                    request.poll_ready = events;
                                    request.poll_epoch = epoch;
                                    Ok((events as i32, true))
                                }
                            }
                        }
                        11 => {
                            if request
                                .timeout_count
                                .is_some_and(|n| state.completion_count >= n)
                            {
                                Ok((0, true))
                            } else if request.deadline.is_some_and(|d| Instant::now() >= d) {
                                if s.op_flags() & 32 != 0 {
                                    Ok((0, true))
                                } else {
                                    Err(Errno(62))
                                }
                            } else {
                                Err(Errno(11))
                            }
                        }
                        13 | 16 | 26 | 27 | 34 | 56 | 57 => self.uring_network(&request, memory),
                        17 => self
                            .vfs
                            .with_uring_fd(request.file.as_ref().unwrap(), |v, fd| {
                                v.allocate_fd(fd, s.length() as u64, s.offset(), s.address())
                                    .map(|()| (0, true))
                            }),
                        18 | 28 => {
                            let path = request.path.as_deref().unwrap();
                            let (flags, mode, resolve) =
                                request.how.unwrap_or((s.op_flags(), s.length(), 0));
                            if s.opcode() == 28 && s.op_flags() != 0 {
                                Err(Errno(22))
                            } else if let Some(file) = &request.file {
                                self.vfs
                                    .with_uring_install(file, |v, fd| {
                                        v.open_at_resolve(fd as i32, path, flags, mode, resolve)
                                    })
                                    .map(|fd| (fd as i32, true))
                            } else {
                                self.vfs
                                    .open_at_resolve(s.fd(), path, flags, mode, resolve)
                                    .map(|fd| (fd as i32, true))
                            }
                        }
                        19 => {
                            if s.op_flags() != 0 || s.length() != 0 {
                                Err(Errno(22))
                            } else if self.vfs.uring(s.fd() as u32).is_ok() {
                                Err(Errno(9))
                            } else {
                                self.vfs.close(s.fd() as u32).map(|()| (0, true))
                            }
                        }
                        21 => {
                            let a = [
                                s.fd() as u64,
                                0,
                                s.op_flags() as u64,
                                s.length() as u64,
                                s.offset(),
                                0,
                            ];
                            let path = request.path.as_deref().unwrap();
                            if let Some(file) = &request.file {
                                self.vfs
                                    .with_uring_path_fd(file, |v, fd| {
                                        let mut a = a;
                                        a[0] = fd as u64;
                                        Self::statx_path(v, a, path, memory)
                                    })
                                    .map(|n| (n as i32, true))
                            } else {
                                Self::statx_path(&self.vfs, a, path, memory)
                                    .map(|n| (n as i32, true))
                            }
                        }
                        45 => {
                            if s.op_flags() & !(trames_vfs::O_CLOEXEC | trames_vfs::O_NONBLOCK) != 0
                                || s.address() != 0
                                || s.offset() > u32::MAX as u64
                            {
                                Err(Errno(22))
                            } else {
                                self.vfs
                                    .socket(
                                        s.fd() as u32,
                                        s.offset() as u32 | s.op_flags(),
                                        s.length(),
                                    )
                                    .map(|fd| (fd as i32, true))
                            }
                        }
                        31 | 32 => self.uring_provide(&request, &mut state),
                        55 => self
                            .vfs
                            .with_uring_fd(request.file.as_ref().unwrap(), |v, fd| {
                                v.truncate_fd(fd, s.offset()).map(|()| (0, true))
                            }),
                        15 => {
                            if let Some(success) = request
                                .timeout_target
                                .and_then(|t| state.completed.get(&t))
                                .copied()
                            {
                                Ok((-125, success))
                            } else if request.started
                                && request.deadline.is_some_and(|d| Instant::now() >= d)
                            {
                                for queue in [&mut waiting, &mut pending] {
                                    if let Some(i) = queue
                                        .iter()
                                        .position(|r| Some(r.sequence) == request.timeout_target)
                                    {
                                        let target = queue.remove(i).unwrap();
                                        Self::complete_request(&mut state, &target, -125, false);
                                        break;
                                    }
                                }
                                if s.op_flags() & 32 != 0 {
                                    Ok((0, true))
                                } else {
                                    Err(Errno(62))
                                }
                            } else {
                                Err(Errno(11))
                            }
                        }
                        7 | 12 | 14 => {
                            let flags = s.op_flags();
                            if s.opcode() == 7 && s.length() != 0 {
                                if s.length() & !6 != 0
                                    || s.length() & 2 == 0 && flags != 0
                                    || s.length() & 2 != 0 && flags & !0x201f != 0
                                {
                                    Err(Errno(22))
                                } else {
                                    let target =
                                        waiting.iter_mut().chain(pending.iter_mut()).find(|r| {
                                            r.owner == owner
                                                && r.sqe.opcode() == 6
                                                && r.sqe.user_data() == s.address()
                                        });
                                    if let Some(target) = target {
                                        if s.length() & 2 != 0 {
                                            target.sqe.0[28..32]
                                                .copy_from_slice(&flags.to_le_bytes());
                                        }
                                        if s.length() & 4 != 0 {
                                            target.sqe.0[32..40]
                                                .copy_from_slice(&s.offset().to_le_bytes());
                                        }
                                        target.poll_ready = 0;
                                        target.poll_epoch = [0; 2];
                                        Ok((0, true))
                                    } else {
                                        Err(Errno(2))
                                    }
                                }
                            } else if s.opcode() == 12 && flags & 18 != 0 {
                                let link = flags & 16 != 0;
                                let target =
                                    waiting.iter_mut().chain(pending.iter_mut()).find(|r| {
                                        r.owner == owner
                                            && r.sqe.user_data() == s.address()
                                            && r.sqe.opcode() == if link { 15 } else { 11 }
                                    });
                                if let Some(target) = target {
                                    target.deadline = request.deadline;
                                    target.timeout_count = None;
                                    let timeout_flags =
                                        (target.sqe.op_flags() & (64 | 32)) | (flags & (1 | 4 | 8));
                                    target.sqe.0[28..32]
                                        .copy_from_slice(&timeout_flags.to_le_bytes());
                                    if target.sqe.opcode() == 11 && !target.sqe.multishot() {
                                        target.sqe.0[8..16].copy_from_slice(&0u64.to_le_bytes());
                                    }
                                    if target.sqe.multishot() {
                                        target.timeout_duration = request.timeout_duration;
                                    }
                                    if link {
                                        target.started = true;
                                    }
                                    Ok((0, true))
                                } else {
                                    Err(Errno(2))
                                }
                            } else if s.opcode() != 14 && flags != 0
                                || s.opcode() == 14
                                    && (flags & !15 != 0
                                        || flags & 8 != 0 && flags & 2 == 0
                                        || flags & 6 == 6)
                            {
                                Err(Errno(22))
                            } else {
                                let all = s.opcode() == 14 && flags & 5 != 0;
                                let mut cancelled = 0;
                                for queue in [&mut waiting, &mut pending] {
                                    let mut i = 0;
                                    while i < queue.len() {
                                        let target = &queue[i];
                                        let matches_key = if flags & 4 != 0 {
                                            true
                                        } else if flags & 2 != 0 {
                                            target
                                                .file
                                                .as_ref()
                                                .zip(request.file.as_ref())
                                                .is_some_and(|(a, b)| a.same_file(b))
                                        } else {
                                            target.sqe.user_data() == s.address()
                                        };
                                        if target.owner == owner
                                            && matches_key
                                            && (s.opcode() == 14
                                                || s.opcode() == 7 && target.sqe.opcode() == 6
                                                || s.opcode() == 12 && target.sqe.opcode() == 11)
                                            && (all || cancelled == 0)
                                        {
                                            let target = queue.remove(i).unwrap();
                                            Self::complete_request(
                                                &mut state, &target, -125, false,
                                            );
                                            cancelled += 1;
                                        } else {
                                            i += 1;
                                        }
                                    }
                                }
                                if cancelled != 0 {
                                    Ok((if all { cancelled } else { 0 }, true))
                                } else {
                                    Err(Errno(2))
                                }
                            }
                        }
                        _ => Err(Errno(22)),
                    }
                };
                match result {
                    Err(Errno(11))
                        if request.error.is_none()
                            && (matches!(s.opcode(), 6 | 11 | 13 | 15 | 16 | 26 | 27)
                                || matches!(s.opcode(), 1 | 2 | 4 | 5 | 22 | 23)
                                    && s.op_flags() & 8 == 0)
                            && !(matches!(s.opcode(), 26 | 27) && s.op_flags() & 0x40 != 0) =>
                    {
                        if s.opcode() != 15 {
                            request.started = true;
                        }
                        waiting.push_back(request)
                    }
                    value => {
                        let (value, success) = value.unwrap_or_else(|e| (-(e.0 as i32), false));
                        let repeating_timeout = s.opcode() == 11
                            && s.multishot()
                            && matches!(value, 0 | -62)
                            && request.error.is_none();
                        request.shots = request.shots.saturating_add(1);
                        let more = s.multishot()
                            && request.error.is_none()
                            && (match s.opcode() {
                                6 | 13 => value >= 0,
                                27 => {
                                    value > 0
                                        || value == 0
                                            && request.file.as_ref().is_some_and(|f| f.datagram())
                                }
                                11 => {
                                    repeating_timeout
                                        && (s.offset() == 0 || request.shots < s.offset())
                                }
                                _ => false,
                            });
                        if more {
                            request.started = true;
                            Self::post_uring_completion(
                                &mut state,
                                &request,
                                value,
                                cqe_flags | 2,
                                None,
                            );
                            shot_budget -= 1;
                            state.multishot_cursor = request.sequence;
                            if repeating_timeout {
                                request.deadline = request
                                    .timeout_duration
                                    .and_then(|d| Instant::now().checked_add(d));
                            }
                            waiting.push_back(request);
                        } else {
                            Self::post_uring_completion(
                                &mut state,
                                &request,
                                value,
                                cqe_flags,
                                Some(success),
                            );
                        }
                        changed = true;
                    }
                }
            }
            state.pending = waiting;
            let dependencies: std::collections::BTreeSet<_> = state
                .pending
                .iter()
                .filter_map(|r| r.dependency.map(|d| d.0))
                .collect();
            state.completed.retain(|id, _| dependencies.contains(id));
            let count = ring.flush(&mut state).unwrap_or(0);
            if count != 0 && ring.eventfd_enabled() {
                if let Some(event) = &state.eventfd {
                    let _ = self
                        .vfs
                        .with_uring_fd(event, |v, fd| v.write(fd, &count.to_le_bytes()));
                }
            }
            any_changed |= changed || count != 0;
            if !changed || state.pending.is_empty() {
                // An idle higher sequence must not indefinitely suppress a
                // newly ready lower one. Wrap at most once without progress.
                if !changed && cutoff != 0 && shot_budget != 0 && !state.pending.is_empty() {
                    cutoff = 0;
                    state.multishot_cursor = 0;
                    continue;
                }
                break;
            }
        }
        any_changed
    }
    /// Existing joined scheduling checkpoints drive only rings with accepted
    /// requests. No SQPOLL, new thread, timer bus or per-operation RPC is added.
    pub fn progress_uring(&mut self, memory: &mut Memory, task: u32) -> bool {
        let mut changed = false;
        self.uring_active.retain(|r| r.strong_count() != 0);
        for ring in self.uring_rings() {
            changed |= self.progress_ring(&ring, memory, task);
        }
        changed
    }
    pub fn cancel_uring(&mut self, memory: &mut Memory, task: u32) {
        let owner = memory.instruction_identity().0;
        for ring in self.uring_rings() {
            let mut state = ring.state.borrow_mut();
            let mut pending = std::mem::take(&mut state.pending);
            while let Some(request) = pending.pop_front() {
                if request.owner == owner && request.task == task {
                    Self::complete_request(&mut state, &request, -125, false);
                } else {
                    state.pending.push_back(request);
                }
            }
            let count = ring.flush(&mut state).unwrap_or(0);
            if count != 0 && ring.eventfd_enabled() {
                if let Some(event) = &state.eventfd {
                    let _ = self
                        .vfs
                        .with_uring_fd(event, |v, fd| v.write(fd, &count.to_le_bytes()));
                }
            }
        }
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
            .any(|r| !r.state.borrow().pending.is_empty())
    }
    pub fn uring_native_wait_fds(&self) -> Vec<trames_vfs::HostFd> {
        self.uring_rings()
            .iter()
            .flat_map(|ring| ring.native_wait_fds())
            .collect()
    }
    pub fn uring_sockets(&self) -> Vec<(Rc<trames_net::Socket>, u16)> {
        self.uring_rings()
            .iter()
            .flat_map(|r| r.sockets())
            .collect()
    }
    fn uring_rings(&self) -> Vec<Rc<Uring>> {
        let mut rings = self.vfs.urings();
        for ring in self.uring_active.iter().filter_map(std::rc::Weak::upgrade) {
            if !rings.iter().any(|r| Rc::ptr_eq(r, &ring)) {
                rings.push(ring);
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
    pub(crate) fn setup(entries: u32) -> (Linux, Memory, u32, Rc<Uring>) {
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
    fn enter(l: &mut Linux, m: &mut Memory, fd: u32, count: u32) {
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
        assert_eq!(r.state.borrow().head, 0);
        m.write_array(QUEUE + 4, 1u32.to_le_bytes()).unwrap();
        m.write_array(QUEUE + URING_SQ_ARRAY as u64, 99u32.to_le_bytes())
            .unwrap();
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(r.state.borrow().dropped, 1);
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
            let mut s = r.state.borrow_mut();
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
        assert_eq!(r.state.borrow().head, 16);
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
        assert_eq!(r.state.borrow().head, 1);
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
        assert!(r.state.borrow().files.is_none());
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
        let weak = Rc::downgrade(&r);
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
            assert!(r.state.borrow().pending.len() < 64);
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
        assert_eq!(r.state.borrow().head, 0);
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
        let before = r.state.borrow().pending[0].deadline;
        let mut s = sqe(12, 0, 2);
        s[16..24].copy_from_slice(&1u64.to_le_bytes());
        s[8..16].copy_from_slice(&0x2000u64.to_le_bytes());
        put(&mut s, 28, 2 | 16);
        add(&mut m, &r, s);
        enter(&mut l, &mut m, fd, 1);
        assert_eq!(cq(&mut m, &r), (2, -22));
        assert_eq!(r.state.borrow().pending[0].deadline, before);
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
        assert!(r.state.borrow().buffers.is_none());
        m.write_array(0x2000, QUEUE.to_le_bytes()).unwrap();
        assert_eq!(
            l.uring_register([fd as u64, 0, 0x2000, 1, 0, 0], &mut m),
            Err(Errno(95))
        );
        assert!(r.state.borrow().buffers.is_none());
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
            let s = r.state.borrow();
            assert_eq!(s.pending.len(), 1);
            assert_eq!(
                s.pending.len() + s.overflow.len() + r.cq_ready() as usize,
                r.outstanding_limit()
            );
        }
        let before = r.state.borrow().completion_count;
        l.progress_uring(&mut m, 7);
        assert_eq!(r.state.borrow().completion_count, before);
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
        assert!(r.state.borrow().pending.is_empty());
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
        assert_eq!(r.state.borrow().provided[&9].slots(), 1);
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
        r.state.borrow_mut().provided.insert(
            7,
            UringBufferGroup {
                owner: m.instruction_identity().0,
                source: UringBufferSource::Ring {
                    memory: pin.clone(),
                    head: u16::MAX,
                    entries: 2,
                },
            },
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
        assert!(r.state.borrow().provided.is_empty());
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
        assert_eq!(r.state.borrow().provided[&0].slots(), 65536);
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
        assert_eq!(r.state.borrow().pending.len(), 1);
        assert_eq!(l.uring_deadline(), None);
        for _ in 0..4 {
            assert_eq!(cq_flags(&mut m, &r), (1, -62, 2));
        }
        assert!(l.uring_deadline().is_some());
    }
}
