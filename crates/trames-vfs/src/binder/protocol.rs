// SPDX-License-Identifier: GPL-3.0-or-later
//! Original-thread ioctl admission and retained read half of WRITE_READ.
use super::*;
use trames_memory::{Access, CpuMemory};

// Ready ioctls stay on the caller's stack; only a parked read needs a box.
#[allow(clippy::large_enum_variant)]
pub enum Started {
    Complete(u64),
    Read(Ioctl),
}
pub struct Ioctl {
    file: SharedFd,
    process: Arc<Connection>,
    factory: DescriptorFactory,
    tid: u32,
    address: u64,
    header: [u8; 48],
}
fn read(memory: &impl CpuMemory, address: u64, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut bytes = vec![0; len];
    memory.read(address, &mut bytes).map_err(|_| Errno(14))?;
    Ok(bytes)
}
fn checked_len(value: u64, limit: usize) -> Result<usize> {
    usize::try_from(value)
        .ok()
        .filter(|v| *v <= limit)
        .ok_or(Errno(22))
}
impl Ioctl {
    pub fn start(
        file: SharedFd,
        factory: DescriptorFactory,
        tid: u32,
        cmd: u32,
        address: u64,
        memory: &mut impl CpuMemory,
    ) -> Result<Started> {
        let Some(events::SharedControl::Binder(process)) = &file.open.control else {
            return Err(Errno(25));
        };
        let process = process.clone();
        if file.open.flags.get() & O_PATH != 0 {
            return Err(Errno(9));
        }
        process.check_owner(factory.local_sender_credentials()[0])?;
        match cmd {
            VERSION => {
                memory
                    .write_array(address, 8u32.to_le_bytes())
                    .map_err(|_| Errno(14))?;
            }
            SET_MAX_THREADS => {
                let value = memory.read_array::<4>(address).map_err(|_| Errno(14))?;
                process.state.lock().unwrap().max_threads = u32::from_le_bytes(value);
            }
            SET_CONTEXT_MGR | SET_CONTEXT_MGR_EXT => {
                let (pointer, cookie, flags) = if cmd == SET_CONTEXT_MGR_EXT {
                    let bytes = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
                    (word(&bytes, 8), word(&bytes, 16), dword(&bytes, 4))
                } else {
                    let _ = memory.read_array::<4>(address).map_err(|_| Errno(14))?;
                    (0, 0, 0x100)
                };
                process.set_manager(
                    pointer,
                    cookie,
                    flags,
                    factory.local_credentials().euid,
                    tid,
                )?;
            }
            THREAD_EXIT => process.thread_exit(tid),
            GET_NODE_DEBUG => {
                let input = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
                let node = process
                    .state
                    .lock()
                    .unwrap()
                    .nodes
                    .range((
                        std::ops::Bound::Excluded(word(&input, 0)),
                        std::ops::Bound::Unbounded,
                    ))
                    .next()
                    .map(|(_, node)| node.clone());
                let mut out = [0; 24];
                if let Some(node) = node {
                    put(&mut out, 0, node.pointer);
                    put(&mut out, 8, node.cookie);
                    let state = node.state.lock().unwrap();
                    put32(&mut out, 16, u32::from(state.strong != 0));
                    put32(&mut out, 20, u32::from(state.weak != 0));
                }
                memory.write_array(address, out).map_err(|_| Errno(14))?;
            }
            GET_NODE_INFO => {
                let mut out = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
                if out[4..].iter().any(|b| *b != 0) {
                    return Err(Errno(22));
                }
                let manager = process
                    .context
                    .manager
                    .lock()
                    .unwrap()
                    .node
                    .as_ref()
                    .and_then(Weak::upgrade);
                if !manager.is_some_and(|node| node.owner.ptr_eq(&process.myself)) {
                    return Err(Errno(1));
                }
                let node = process.strong_target(dword(&out, 0))?;
                let state = node.state.lock().unwrap();
                put32(&mut out, 4, state.strong as u32);
                put32(&mut out, 8, state.local_weak as u32);
                drop(state);
                memory.write_array(address, out).map_err(|_| Errno(14))?;
            }
            GET_EXTENDED_ERROR => {
                let error = process.state.lock().unwrap().last_error;
                let mut out = [0; 12];
                put32(&mut out, 0, error.0);
                put32(&mut out, 4, error.1);
                put32(&mut out, 8, error.2 as u32);
                memory.write_array(address, out).map_err(|_| Errno(14))?;
            }
            WRITE_READ => {
                let header = memory.read_array::<48>(address).map_err(|_| Errno(14))?;
                memory
                    .check(address, 48, Access::Write)
                    .map_err(|_| Errno(14))?;
                let mut request = Self {
                    file,
                    process,
                    factory,
                    tid,
                    address,
                    header,
                };
                let result = request.write(memory);
                request.publish(memory)?;
                result?;
                return Ok(Started::Read(request));
            }
            _ => return Err(Errno(22)), // Binder driver uses EINVAL, not success stubs.
        }
        Ok(Started::Complete(0))
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.process.subscribe(signal)
    }
    fn publish(&self, memory: &mut impl CpuMemory) -> Result<()> {
        memory
            .write_array(self.address, self.header)
            .map_err(|_| Errno(14))
    }
    fn write(&mut self, memory: &impl CpuMemory) -> Result<()> {
        let size = usize::try_from(word(&self.header, 0)).map_err(|_| Errno(22))?;
        let mut consumed = checked_len(word(&self.header, 8), size)?;
        let base = word(&self.header, 16);
        while consumed < size {
            let address = base.checked_add(consumed as u64).ok_or(Errno(14))?;
            if size - consumed < 4 {
                return Err(Errno(22));
            }
            let command_bytes = memory.read_array::<4>(address).map_err(|_| Errno(14))?;
            let cmd = dword(&command_bytes, 0);
            let len = ((cmd >> 16) & 0x3fff) as usize;
            if len > size - consumed - 4 {
                return Err(Errno(22));
            }
            let argument = read(memory, address.checked_add(4).ok_or(Errno(14))?, len)?;
            // Linux consumes the command word even when command execution
            // fails. Previously accepted commands are never replayed on wake.
            consumed += 4;
            put(&mut self.header, 8, consumed as u64);
            match cmd {
                TRANSACTION | REPLY | TRANSACTION_SG | REPLY_SG => {
                    let packet = self.import(&argument, memory);
                    let reply = matches!(cmd, REPLY | REPLY_SG);
                    let identity = [self.process.owner, self.factory.local_credentials().euid];
                    let result = packet
                        .and_then(|packet| self.process.submit(self.tid, packet, reply, identity));
                    if let Err(error) = result {
                        let response = if matches!(error.0, 3 | 111) {
                            BR_DEAD_REPLY
                        } else {
                            BR_FAILED_REPLY
                        };
                        self.process.state.lock().unwrap().last_error =
                            (0, response, -(error.0 as i32));
                        self.process.bytes(self.tid, response);
                    }
                }
                FREE_BUFFER => self.process.free_buffer(word(&argument, 0))?,
                INCREFS | ACQUIRE | RELEASE | DECREFS => {
                    self.process.ref_command(cmd, dword(&argument, 0))?
                }
                INCREFS_DONE | ACQUIRE_DONE => {
                    let state = self.process.state.lock().unwrap();
                    let node = state.nodes.get(&word(&argument, 0)).ok_or(Errno(22))?;
                    if node.cookie != word(&argument, 8) {
                        return Err(Errno(22));
                    }
                }
                REGISTER_LOOPER | ENTER_LOOPER | EXIT_LOOPER => {
                    let mut state = self.process.state.lock().unwrap();
                    if cmd == REGISTER_LOOPER {
                        if state.requested_threads == 0 {
                            return Err(Errno(22));
                        }
                        state.requested_threads -= 1;
                    }
                    let thread = state.threads.entry(self.tid).or_default();
                    thread.looper = cmd != EXIT_LOOPER;
                    thread.registered = cmd == REGISTER_LOOPER;
                }
                REQUEST_DEATH => self
                    .process
                    .request_death(dword(&argument, 0), word(&argument, 4))?,
                CLEAR_DEATH => self
                    .process
                    .clear_death(dword(&argument, 0), word(&argument, 4))?,
                DEAD_DONE => self.process.death_done(word(&argument, 0))?,
                _ => return Err(Errno(22)),
            }
            consumed += len;
            put(&mut self.header, 8, consumed as u64);
        }
        Ok(())
    }
    fn import(&self, bytes: &[u8], memory: &impl CpuMemory) -> Result<Packet> {
        let header: [u8; 64] = bytes[..64].try_into().unwrap();
        let size = checked_len(word(&header, 32), 4 * 1024 * 1024)?;
        let offset_size = checked_len(word(&header, 40), 4 * 1024 * 1024)?;
        if offset_size % 8 != 0 {
            return Err(Errno(22));
        }
        let data = read(memory, word(&header, 48), size)?;
        let raw_offsets = read(memory, word(&header, 56), offset_size)?;
        let offsets = raw_offsets
            .chunks_exact(8)
            .map(|v| checked_len(word(v, 0), size))
            .collect::<Result<Vec<_>>>()?;
        let extra_limit = if bytes.len() == 72 {
            checked_len(word(bytes, 64), 4 * 1024 * 1024)?
        } else {
            0
        };
        let mut packet = Packet {
            header,
            data,
            offsets,
            extra: Vec::new(),
            objects: Vec::new(),
            relocations: Vec::new(),
        };
        let mut previous_end = 0;
        // SG parent entries index the original offsets array, not a separate
        // list of buffer objects. Validate bounds and backwards-only ancestry.
        let mut parents: BTreeMap<usize, (usize, usize, usize, usize)> = BTreeMap::new();
        let mut last_fixup: Option<(usize, usize)> = None;
        for (index, &offset) in packet.offsets.iter().enumerate() {
            if offset % 4 != 0 || offset < previous_end {
                return Err(Errno(22));
            }
            let raw = packet
                .data
                .get(offset..offset.checked_add(4).ok_or(Errno(22))?)
                .ok_or(Errno(22))?;
            let kind = dword(raw, 0);
            let object_size = match kind {
                TYPE_BINDER | TYPE_WEAK_BINDER | TYPE_HANDLE | TYPE_WEAK_HANDLE | TYPE_FD => 24,
                TYPE_PTR => 40,
                TYPE_FDA => 32,
                _ => return Err(Errno(22)),
            };
            let object = packet
                .data
                .get(offset..offset + object_size)
                .ok_or(Errno(22))?;
            previous_end = offset + object_size;
            match kind {
                TYPE_BINDER | TYPE_WEAK_BINDER | TYPE_HANDLE | TYPE_WEAK_HANDLE => {
                    let node = if matches!(kind, TYPE_BINDER | TYPE_WEAK_BINDER) {
                        self.process.owned_node(
                            word(object, 8),
                            word(object, 16),
                            dword(object, 4),
                            self.tid,
                        )?
                    } else if kind == TYPE_HANDLE {
                        self.process.strong_target(dword(object, 8))?
                    } else {
                        self.process.target(dword(object, 8))?
                    };
                    packet.objects.push(Object::Node {
                        offset,
                        node,
                        strong: matches!(kind, TYPE_BINDER | TYPE_HANDLE),
                    });
                }
                TYPE_FD => {
                    let file = self.capture_fd(dword(object, 8))?;
                    packet.objects.push(Object::Fd {
                        extra: false,
                        offset: offset + 8,
                        file,
                        array: false,
                    });
                }
                TYPE_PTR => {
                    let length = checked_len(word(object, 16), extra_limit)?;
                    let at = align(packet.extra.len())?;
                    let end = at
                        .checked_add(length)
                        .filter(|end| *end <= extra_limit)
                        .ok_or(Errno(22))?;
                    packet.extra.resize(at, 0);
                    packet
                        .extra
                        .extend_from_slice(&read(memory, word(object, 8), length)?);
                    let parent = checked_len(word(object, 24), index)?;
                    let parent_offset = usize::try_from(word(object, 32)).map_err(|_| Errno(22))?;
                    if dword(object, 4) & !1 != 0 {
                        return Err(Errno(22));
                    }
                    if dword(object, 4) & 1 != 0 {
                        let (start, len, _, _) = *parents.get(&parent).ok_or(Errno(22))?;
                        if parent_offset % 8 != 0
                            || parent_offset.checked_add(8).is_none_or(|v| v > len)
                        {
                            return Err(Errno(22));
                        }
                        validate_parent(&parents, last_fixup, parent, parent_offset)?;
                        packet.relocations.push((start + parent_offset, at));
                    }
                    parents.insert(
                        index,
                        (
                            at,
                            length,
                            if dword(object, 4) & 1 != 0 {
                                parent
                            } else {
                                usize::MAX
                            },
                            parent_offset,
                        ),
                    );
                    packet.objects.push(Object::Buffer { offset, extra: at });
                    debug_assert_eq!(packet.extra.len(), end);
                    last_fixup = Some((index, 0));
                }
                TYPE_FDA => {
                    let count = checked_len(word(object, 8), extra_limit / 4)?;
                    let parent = checked_len(word(object, 16), index)?;
                    let parent_offset = usize::try_from(word(object, 24)).map_err(|_| Errno(22))?;
                    let (start, len, _, _) = *parents.get(&parent).ok_or(Errno(22))?;
                    if parent_offset % 4 != 0
                        || parent_offset.checked_add(count * 4).is_none_or(|n| n > len)
                    {
                        return Err(Errno(22));
                    }
                    validate_parent(&parents, last_fixup, parent, parent_offset)?;
                    for i in 0..count {
                        let at = start + parent_offset + i * 4;
                        let file = self.capture_fd(dword(&packet.extra, at))?;
                        packet.objects.push(Object::Fd {
                            extra: true,
                            offset: at,
                            file,
                            array: true,
                        });
                    }
                    last_fixup = Some((parent, parent_offset + count * 4));
                }
                _ => unreachable!(),
            }
        }
        if align(packet.extra.len())? > extra_limit {
            return Err(Errno(22));
        }
        Ok(packet)
    }
    fn capture_fd(&self, fd: u32) -> Result<SharedFd> {
        let file = self.factory.files.query_lookup(fd).ok_or(Errno(95))??;
        // A Binder device is not an Android data-buffer transport. Avoid
        // creating an OFD -> queued transfer -> same OFD lifetime cycle.
        if file.open.flags.get() & O_PATH != 0
            || matches!(file.open.control, Some(events::SharedControl::Binder(_)))
        {
            return Err(Errno(1));
        }
        Ok(file)
    }
    pub fn finish(&mut self, memory: &mut impl CpuMemory) -> Result<Option<u64>> {
        let capacity = usize::try_from(word(&self.header, 24)).map_err(|_| Errno(22))?;
        let mut consumed = checked_len(word(&self.header, 32), capacity)?;
        if capacity == 0 {
            return Ok(Some(0));
        }
        let read_base = word(&self.header, 40);
        let mut written = false;
        while capacity - consumed >= 4 {
            let work = {
                let mut state = self.process.state.lock().unwrap();
                if state.closed {
                    return Err(Errno(111));
                }
                let thread = state.threads.entry(self.tid).or_default();
                thread.waiting = false;
                // Like Linux, an idle non-looper can drain process/death work.
                // Looper registration governs thread-pool growth, not this
                // eligibility check (otherwise a plain caller can wait forever).
                let process_work = thread.stack.is_empty() && thread.queue.is_empty();
                let candidate = if let Some(work) = thread.queue.front() {
                    Some(work)
                } else if process_work {
                    state.queue.front()
                } else {
                    None
                };
                let Some(candidate) = candidate else { break };
                let prefix = if consumed == 0 { 4 } else { 0 };
                if candidate.size() + prefix > capacity - consumed {
                    break;
                }
                let address = read_base.checked_add(consumed as u64).ok_or(Errno(14))?;
                memory
                    .check(address, candidate.size() + prefix, Access::Write)
                    .map_err(|_| Errno(14))?;
                if process_work {
                    state.queue.pop_front().unwrap()
                } else {
                    state
                        .threads
                        .get_mut(&self.tid)
                        .unwrap()
                        .queue
                        .pop_front()
                        .unwrap()
                }
            };
            if consumed == 0 {
                memory
                    .write_array(read_base, BR_NOOP.to_le_bytes())
                    .map_err(|_| Errno(14))?;
                consumed += 4;
            }
            if let Work::Reply(_, call) = &work {
                self.pop_call(call);
            }
            let (out, stop) = match work {
                Work::Bytes(out) | Work::Node(out) => (out, false),
                Work::Death(cookie) => (command(BR_DEAD_BINDER, &cookie.to_le_bytes()), true),
                Work::ClearDeath(cookie) => (command(BR_CLEAR_DEATH, &cookie.to_le_bytes()), false),
                Work::Dead(call) => {
                    self.pop_call(&call);
                    (command(BR_DEAD_REPLY, &[]), true)
                }
                Work::Transaction(buffer) | Work::Reply(buffer, _) => {
                    let reply = buffer.node.is_none();
                    if let Err(error) = buffer.install(&self.factory) {
                        if let Some(call) = &buffer.call {
                            call.fail();
                        }
                        return Err(error);
                    }
                    let address = buffer.pool.base + buffer.offset as u64;
                    let mut state = self.process.state.lock().unwrap();
                    if state.closed {
                        return Err(Errno(111));
                    }
                    if let Some(call) = &buffer.call {
                        call.to_tid.store(self.tid as u64, Ordering::Relaxed);
                        state
                            .threads
                            .entry(self.tid)
                            .or_default()
                            .stack
                            .push(call.clone());
                    }
                    // Reply work owns the call only until the outgoing frame
                    // is popped; use a separate match before moving work below.
                    state.buffers.insert(address, buffer.clone());
                    let mut header = buffer.header;
                    let sender = if dword(&header, 20) & ONE_WAY != 0 {
                        0
                    } else {
                        self.factory.local_pid(dword(&header, 24))
                    };
                    put32(&mut header, 24, sender);
                    (
                        command(if reply { BR_REPLY } else { BR_TRANSACTION }, &header),
                        true,
                    )
                }
            };
            memory
                .write(read_base + consumed as u64, &out)
                .map_err(|_| Errno(14))?;
            consumed += out.len();
            written = true;
            if stop {
                break;
            }
        }
        put(&mut self.header, 32, consumed as u64);
        self.publish(memory)?;
        if written || consumed != 0 {
            let spawn = {
                let mut state = self.process.state.lock().unwrap();
                let looper = state.threads.get(&self.tid).is_some_and(|t| t.looper);
                let registered = state.threads.values().filter(|t| t.registered).count() as u32;
                let waiting = state.threads.values().any(|t| t.waiting);
                let spawn = looper
                    && !waiting
                    && state.requested_threads == 0
                    && registered < state.max_threads;
                if spawn {
                    state.requested_threads += 1;
                }
                spawn
            };
            if spawn {
                memory
                    .write_array(read_base, BR_SPAWN.to_le_bytes())
                    .map_err(|_| Errno(14))?;
            }
            return Ok(Some(0));
        }
        if self.file.open.flags.get() & O_NONBLOCK != 0 {
            return Err(Errno(11));
        }
        self.process
            .state
            .lock()
            .unwrap()
            .threads
            .entry(self.tid)
            .or_default()
            .waiting = true;
        Ok(None)
    }
    fn pop_call(&self, call: &Arc<Call>) {
        let mut state = self.process.state.lock().unwrap();
        let thread = state.threads.entry(self.tid).or_default();
        if thread.stack.last().is_some_and(|c| Arc::ptr_eq(c, call)) {
            thread.stack.pop();
        }
    }
}
fn validate_parent(
    parents: &BTreeMap<usize, (usize, usize, usize, usize)>,
    last: Option<(usize, usize)>,
    parent: usize,
    offset: usize,
) -> Result<()> {
    let Some((mut current, end)) = last else {
        return Err(Errno(22));
    };
    if current == parent {
        return if offset >= end {
            Ok(())
        } else {
            Err(Errno(22))
        };
    }
    while let Some((_, _, ancestor, parent_offset)) = parents.get(&current) {
        if *ancestor == parent {
            return if offset >= parent_offset + 8 {
                Ok(())
            } else {
                Err(Errno(22))
            };
        }
        if *ancestor == usize::MAX {
            break;
        }
        current = *ancestor;
    }
    Err(Errno(22))
}

impl Vfs {
    pub fn task_pid(&self) -> u32 {
        self.pid
    }
    pub fn binder_file(&self, fd: u32) -> Result<Option<SharedFd>> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        Ok(
            matches!(open.control, Some(events::SharedControl::Binder(_)))
                .then(|| SharedFd::new(open.shared.clone())),
        )
    }
    pub fn binder_exit(&self, tid: u32, last: bool) {
        self.binder.exit(self.lock_owner, tid, last);
    }
}
impl Drop for Ioctl {
    fn drop(&mut self) {
        if let Some(thread) = self
            .process
            .state
            .lock()
            .unwrap()
            .threads
            .get_mut(&self.tid)
        {
            thread.waiting = false;
        }
    }
}
impl DescriptorFactory {
    pub fn binder_file(&self, fd: u32) -> Option<Result<SharedFd>> {
        let file = match self.files.query_lookup(fd)? {
            Ok(file) => file,
            Err(_) => return None,
        };
        matches!(file.open.control, Some(events::SharedControl::Binder(_))).then_some(Ok(file))
    }
    pub fn binder_exit(&self, tid: u32, last: bool) {
        self.binder
            .exit(self.local_sender_credentials()[0], tid, last);
    }
}
