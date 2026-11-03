// SPDX-License-Identifier: GPL-3.0-or-later
//! Legacy buffered Linux AIO. Accepted batches use the existing disk executor;
//! the source task performs copyout and publishes CQ/eventfd in that order.
//! io_submit may block for buffered I/O, as on Linux. It releases its CPU slot
//! while waiting, and returns only after this batch's buffers are no longer in
//! use. There are no detached guest pointers, memory-owner RPCs or new threads.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Mutex,
};

#[derive(Clone, Default)]
pub struct Aio(Arc<Registry>);
#[derive(Default)]
struct Registry {
    base: std::sync::atomic::AtomicU64,
    contexts: Mutex<BTreeMap<u64, Arc<Context>>>,
}
#[derive(Clone)]
pub struct RetainedAio {
    context: Arc<Context>,
    batch: Option<Arc<Mutex<Batch>>>,
    number: u32,
    args: [u64; 6],
    deadline: Option<Instant>,
}
struct Context {
    state: Mutex<State>,
    readiness: Arc<trames_vfs::Readiness>,
}
struct State {
    capacity: usize,
    dead: bool,
    active: BTreeSet<u64>,
    events: VecDeque<[u8; 32]>,
}
struct Request {
    object: u64,
    data: u64,
    result: Arc<FileResult>,
    output: FileOutput,
    event: Option<trames_vfs::NativeEvent>,
}
struct Batch {
    context: Arc<Context>,
    requests: VecDeque<Request>,
    submitted: u64,
}
impl Drop for Batch {
    fn drop(&mut self) {
        // Task exit can abandon a source copyout. Host work still owns only its
        // OFD and owned bytes; release these credits without touching guest RAM.
        if !self.requests.is_empty() {
            let mut state = self.context.state.lock().unwrap();
            for request in &self.requests {
                state.active.remove(&request.object);
            }
            drop(state);
            self.context.readiness.notify_locked();
        }
    }
}
impl Aio {
    pub fn fork(&self) -> Self {
        let result = Self::default();
        result.0.base.store(
            self.0.base.load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );
        result
    }
    pub fn install(
        &self,
        memory: &mut trames_memory::Memory,
    ) -> Result<(), trames_memory::MemoryError> {
        let address = memory
            .find_free(0x7fff_fc00_0000, 4096)
            .ok_or(trames_memory::MemoryError::Limit)?;
        memory.map(address, 4096, trames_memory::Permissions::R)?;
        self.0
            .base
            .store(address, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    fn context(&self, id: u64) -> Result<Arc<Context>, Errno> {
        self.0
            .contexts
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(Errno(22))
    }
    fn setup(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        let count = a[0] as u32;
        if count == 0 {
            return Err(Errno(22));
        }
        if count > 65536 {
            return Err(Errno(11));
        }
        if u64::from_le_bytes(memory.read_array(a[1]).map_err(|_| Errno(14))?) != 0 {
            return Err(Errno(22));
        }
        Linux::check(memory, a[1], 8, Access::Write)?;
        let base = self.0.base.load(std::sync::atomic::Ordering::Relaxed);
        if base == 0 {
            return Err(Errno(12));
        }
        let mut contexts = self.0.contexts.lock().unwrap();
        let id = (0..128)
            .map(|n| base + n * 32)
            .find(|id| !contexts.contains_key(id))
            .ok_or(Errno(11))?;
        // libaio checks the ring magic before its optional userspace fast path.
        // These mapped zero headers select its syscall fallback. They reserve
        // only one demand-zero page per mm, not an mmap on every io_setup.
        Linux::check(memory, id, 32, Access::Read)?;
        memory
            .write_array(a[1], id.to_le_bytes())
            .map_err(|_| Errno(14))?;
        contexts.insert(
            id,
            Arc::new(Context {
                state: Mutex::new(State {
                    capacity: count as usize,
                    dead: false,
                    active: BTreeSet::new(),
                    events: VecDeque::new(),
                }),
                readiness: Arc::default(),
            }),
        );
        Ok(0)
    }
}
impl DirectSyscalls {
    pub fn with_aio(mut self, aio: Aio, events: trames_vfs::NativeEvents) -> Self {
        self.aio = Some((aio, events));
        self
    }
    pub fn aio_call(number: u32) -> bool {
        matches!(number, 0..=4 | 292)
    }
    fn import_aio(
        &self,
        address: u64,
        memory: &mut impl CpuMemory,
    ) -> Result<(Request, trames_vfs::FileWork), Errno> {
        let b = memory.read_array::<64>(address).map_err(|_| Errno(14))?;
        let u32_at = |n| u32::from_le_bytes(b[n..n + 4].try_into().unwrap());
        let u64_at = |n| u64::from_le_bytes(b[n..n + 8].try_into().unwrap());
        let op = u16::from_le_bytes(b[16..18].try_into().unwrap());
        if u64_at(48) != 0 || u32_at(56) & !1 != 0 || b[18..20] != [0, 0] {
            return Err(Errno(22));
        }
        if u32_at(12) != 0 {
            return Err(Errno(95));
        }
        if !matches!(op, 0..=3 | 7 | 8) {
            return Err(Errno(22));
        }
        if matches!(op, 0 | 1 | 7 | 8) && u64_at(40) > i64::MAX as u64 {
            return Err(Errno(22));
        }
        let fd = u32_at(20);
        let file = self
            .membership
            .as_ref()
            .and_then(|f| f.lookup(fd))
            .unwrap_or(Err(Errno(9)))?;
        let target = file.file_target().ok_or(Errno(22))?;
        let flags = target.status_flags();
        if flags & trames_vfs::O_PATH != 0
            || matches!(op, 0 | 7) && flags & 3 == 1
            || matches!(op, 1 | 8) && flags & 3 == 0
        {
            return Err(Errno(9));
        }
        if flags & 0x4000 != 0 {
            return Err(Errno(95));
        }
        let number = match op {
            0 => 67,
            1 => 68,
            2 => 82,
            3 => 83,
            7 => 69,
            8 => 70,
            _ => unreachable!(),
        };
        let (command, output) = file::import(
            number,
            [fd as u64, u64_at(24), u64_at(32), u64_at(40), 0, 0],
            memory,
            &mut Vec::new(),
        )?;
        let event = if u32_at(56) & 1 != 0 {
            Some(self.aio.as_ref().unwrap().1.event(u32_at(60))?)
        } else {
            None
        };
        memory
            .write_array(address + 8, 0u32.to_le_bytes())
            .map_err(|_| Errno(14))?;
        Ok((
            Request {
                object: address,
                data: u64_at(0),
                result: Arc::default(),
                output,
                event,
            },
            trames_vfs::FileWork::new(self.paths.as_ref().ok_or(Errno(9))?, target, command),
        ))
    }
    fn submit_aio(
        &self,
        context: Arc<Context>,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<Option<Arc<Mutex<Batch>>>, Errno> {
        if a[1] > i64::MAX as u64 {
            return Err(Errno(22));
        }
        if a[1] == 0 {
            return Ok(None);
        }
        let mut requests = VecDeque::new();
        let mut error = Errno(11);
        for i in 0..a[1] {
            let address = match a[2]
                .checked_add(i * 8)
                .and_then(|p| memory.read_array(p).ok())
                .map(u64::from_le_bytes)
            {
                Some(a) => a,
                None => {
                    error = Errno(14);
                    break;
                }
            };
            {
                let mut state = context.state.lock().unwrap();
                if state.dead {
                    error = Errno(22);
                    break;
                }
                if state.active.len() + state.events.len() >= state.capacity {
                    break;
                }
                if !state.active.insert(address) {
                    error = Errno(22);
                    break;
                }
            }
            match self.import_aio(address, memory) {
                Ok((request, work)) => {
                    if let Some(executor) = &self.file_executor {
                        executor.submit_file(work, request.result.clone());
                    } else {
                        request.result.complete(work.run());
                    }
                    requests.push_back(request);
                }
                Err(e) => {
                    context.state.lock().unwrap().active.remove(&address);
                    error = e;
                    break;
                }
            }
        }
        if requests.is_empty() {
            return Err(error);
        }
        let submitted = requests.len() as u64;
        let batch = Arc::new(Mutex::new(Batch {
            context,
            requests,
            submitted,
        }));
        Ok(Some(batch))
    }
    pub(super) fn start_aio(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        deadline: Option<Instant>,
    ) -> Option<IoAttempt> {
        if !Self::aio_call(number) {
            return None;
        }
        self.aio.as_ref()?;
        Some(self.aio_attempt(number, a, memory, pid, target, deadline, None))
    }
    pub fn start_retained_aio(
        &self,
        call: RetainedAio,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        self.aio_attempt(
            call.number,
            call.args,
            memory,
            pid,
            target,
            call.deadline,
            Some(call),
        )
    }
    #[allow(clippy::too_many_arguments)] // Original accepted syscall and source wake authority.
    fn aio_attempt(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
        deadline: Option<Instant>,
        retained: Option<RetainedAio>,
    ) -> IoAttempt {
        let (aio, _) = self.aio.as_ref().expect("accepted AIO domain");
        let result = (|| {
            if number == 0 {
                return Ok(IoAttempt::Complete(aio.setup(a, memory)));
            }
            let context = match &retained {
                Some(call) => call.context.clone(),
                None => aio.context(a[0])?,
            };
            let mut batch_state = retained.and_then(|call| call.batch);
            let signal = IoSignal::new(pid, target.clone());
            let mut subscriptions = vec![context.readiness.subscribe(&signal)];
            let deadline = if matches!(number, 4 | 292) {
                if a[1] > a[2] || a[2] > i64::MAX as u64 {
                    return Err(Errno(22));
                }
                Linux::check(memory, a[3], (a[2].min(65536) as usize) * 32, Access::Write)?;
                if number == 292 && a[5] != 0 {
                    let mask = memory.read_array::<16>(a[5]).map_err(|_| Errno(14))?;
                    if u64::from_le_bytes(mask[..8].try_into().unwrap()) != 0 {
                        return Err(Errno(95));
                    }
                }
                if deadline.is_some() || a[4] == 0 {
                    deadline
                } else {
                    let b = memory.read_array::<16>(a[4]).map_err(|_| Errno(14))?;
                    let sec = u64::from_le_bytes(b[..8].try_into().unwrap());
                    let ns = u64::from_le_bytes(b[8..].try_into().unwrap());
                    if sec > i64::MAX as u64 || ns >= 1_000_000_000 {
                        return Err(Errno(22));
                    }
                    Some(
                        Instant::now()
                            .checked_add(Duration::new(sec, ns as u32))
                            .ok_or(Errno(22))?,
                    )
                }
            } else {
                None
            };
            if number == 2 {
                let batch = match batch_state.take() {
                    Some(batch) => Some(batch),
                    None => self.submit_aio(context.clone(), a, memory)?,
                };
                let Some(batch) = batch else {
                    return Ok(IoAttempt::Complete(Ok(0)));
                };
                batch_state = Some(batch.clone());
                let mut batch = batch.lock().unwrap();
                let mut remaining = batch.requests.len();
                while remaining != 0 {
                    remaining -= 1;
                    let request = batch.requests.pop_front().unwrap();
                    let Some(outcome) = request.result.take() else {
                        subscriptions.push(request.result.subscribe(&signal));
                        if request.result.ready() {
                            remaining += 1;
                        }
                        batch.requests.push_back(request);
                        continue;
                    };
                    let result = match outcome {
                        trames_vfs::FileOutcome::Complete(reply) => {
                            if reply.file_size_signal {
                                if let Some(task) = &self.task_signal {
                                    task.raise(25);
                                }
                            }
                            request.output.apply(reply.result, memory)
                        }
                        // An unsupported live mapped-file transition has made no
                        // effects. Report it, rather than invoke an mm owner.
                        trames_vfs::FileOutcome::Layout(_) | trames_vfs::FileOutcome::Owner(_) => {
                            Err(Errno(95))
                        }
                    };
                    let mut event = [0; 32];
                    event[..8].copy_from_slice(&request.data.to_le_bytes());
                    event[8..16].copy_from_slice(&request.object.to_le_bytes());
                    event[16..24].copy_from_slice(
                        &result
                            .unwrap_or_else(|e| 0u64.wrapping_sub(e.0 as u64))
                            .to_le_bytes(),
                    );
                    let mut state = context.state.lock().unwrap();
                    state.active.remove(&request.object);
                    state.events.push_back(event);
                    drop(state);
                    context.readiness.notify_locked();
                    if let Some(event) = request.event {
                        event.notify();
                    }
                }
                if batch.requests.is_empty() {
                    let submitted = batch.submitted;
                    drop(batch);
                    return Ok(IoAttempt::Complete(Ok(submitted)));
                }
            } else if number == 1 {
                let mut state = context.state.lock().unwrap();
                let first = !state.dead;
                state.dead = true;
                if state.active.is_empty() {
                    drop(state);
                    let mut contexts = aio.0.contexts.lock().unwrap();
                    if !contexts
                        .get(&a[0])
                        .is_some_and(|old| Arc::ptr_eq(old, &context))
                    {
                        return Err(Errno(22));
                    }
                    contexts.remove(&a[0]);
                    return Ok(IoAttempt::Complete(Ok(0)));
                }
                drop(state);
                if first {
                    context.readiness.notify_locked();
                }
            } else if number == 3 {
                let state = context.state.lock().unwrap();
                return Err(if state.active.contains(&a[1]) {
                    Errno(11)
                } else {
                    Errno(22)
                });
            } else {
                let mut state = context.state.lock().unwrap();
                if state.dead {
                    return Err(Errno(22));
                }
                if state.events.len() >= a[1] as usize
                    || deadline.is_some_and(|d| Instant::now() >= d)
                {
                    let n = state.events.len().min(a[2] as usize);
                    for i in 0..n {
                        memory
                            .write_array(a[3] + i as u64 * 32, *state.events.front().unwrap())
                            .map_err(|_| Errno(14))?;
                        state.events.pop_front();
                    }
                    return Ok(IoAttempt::Complete(Ok(n as u64)));
                }
            }
            Ok(IoAttempt::Blocked(PendingIo {
                aio: Some(RetainedAio {
                    context,
                    batch: batch_state,
                    number,
                    args: a,
                    deadline,
                }),
                number,
                args: a,
                deadline,
                signal,
                flock: None,
                retained_byte: None,
                retained_socket: None,
                native_tcp: None,
                resource_deadline: None,
                retained_poll: None,
                epoll_revision: None,
                _subscriptions: subscriptions,
                host_subscription: None,
                socket_subscriptions: Vec::new(),
                uring: None,
                poll_uring: None,
                file: None,
                target: target.clone(),
            }))
        })();
        result.unwrap_or_else(|e| IoAttempt::Complete(Err(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions};
    #[derive(Default)]
    struct Disk(Mutex<Vec<(trames_vfs::FileWork, Arc<FileResult>)>>);
    impl FileExecutor for Disk {
        fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<FileResult>) {
            self.0.lock().unwrap().push((work, result));
        }
    }
    impl Disk {
        fn complete(&self) {
            for (work, result) in self.0.lock().unwrap().drain(..) {
                result.complete(work.run());
            }
        }
    }
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    fn value(attempt: IoAttempt) -> Result<u64, Errno> {
        match attempt {
            IoAttempt::Complete(value) => value,
            _ => panic!("expected completion"),
        }
    }
    #[test]
    fn buffered_submit_yields_slot_then_copies_bytes_before_cq_and_eventfd() {
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/data", b"payload".to_vec()).unwrap();
        let fd = v.open_at(trames_vfs::AT_FDCWD, b"/data", 0, 0).unwrap();
        let event = v.eventfd(0, 0).unwrap();
        let aio = Aio::default();
        let mut memory = Memory::new(1024 * 1024);
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        aio.install(&mut memory).unwrap();
        let disk = Arc::new(Disk::default());
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_aio(aio.clone(), v.native_events())
            .with_paths(v.path_queries())
            .with_file_executor(disk.clone());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        assert_eq!(
            value(
                direct
                    .start(0, [8, 0x1000, 0, 0, 0, 0], &mut memory, 1, &target, None)
                    .unwrap()
            ),
            Ok(0)
        );
        let context = u64::from_le_bytes(memory.read_array(0x1000).unwrap());
        let mut cb = [0; 64];
        cb[..8].copy_from_slice(&123u64.to_le_bytes());
        cb[20..24].copy_from_slice(&fd.to_le_bytes());
        cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
        cb[32..40].copy_from_slice(&7u64.to_le_bytes());
        cb[56..60].copy_from_slice(&1u32.to_le_bytes());
        cb[60..64].copy_from_slice(&event.to_le_bytes());
        memory.write_array(0x2000, cb).unwrap();
        memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
        let pending = match direct
            .start(
                2,
                [context, 1, 0x1800, 0, 0, 0],
                &mut memory,
                1,
                &target,
                None,
            )
            .unwrap()
        {
            IoAttempt::Blocked(p) => p,
            _ => panic!("must release execution slot"),
        };
        assert!(pending.external_wait());
        assert!(!pending.signal.ready());
        assert_eq!(v.read(event, 8), Err(Errno(11)));
        disk.complete();
        assert!(pending.signal.ready());
        assert_eq!(value(direct.resume(pending, &mut memory)), Ok(1));
        assert_eq!(memory.read_array::<7>(0x3000).unwrap(), *b"payload");
        assert_eq!(v.read(event, 8).unwrap(), 1u64.to_le_bytes());
        assert_eq!(
            value(
                direct
                    .start(
                        4,
                        [context, 1, 1, 0x4000, 0, 0],
                        &mut memory,
                        2,
                        &target,
                        None
                    )
                    .unwrap()
            ),
            Ok(1)
        );
        let event = memory.read_array::<32>(0x4000).unwrap();
        assert_eq!(u64::from_le_bytes(event[..8].try_into().unwrap()), 123);
        assert_eq!(u64::from_le_bytes(event[16..24].try_into().unwrap()), 7);
        assert!(aio.fork().context(context).is_err());
        assert!(aio.clone().context(context).is_ok());
        cb[16..18].copy_from_slice(&1u16.to_le_bytes());
        memory.write_array(0x2000, cb).unwrap();
        assert_eq!(
            value(
                direct
                    .start(
                        2,
                        [context, 1, 0x1800, 0, 0, 0],
                        &mut memory,
                        1,
                        &target,
                        None
                    )
                    .unwrap()
            ),
            Err(Errno(9)),
            "write-only operation must reject a read-only OFD before accepting it"
        );
        assert_eq!(
            value(
                direct
                    .start(1, [context, 0, 0, 0, 0, 0], &mut memory, 2, &target, None)
                    .unwrap()
            ),
            Ok(0)
        );
        assert!(aio.context(context).is_err());
    }
    #[test]
    fn parked_getevents_retains_destroyed_context_across_numeric_reuse() {
        let v = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let mut memory = Memory::default();
        memory.map(0x1000, 0x3000, Permissions::RW).unwrap();
        aio.install(&mut memory).unwrap();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_aio(aio.clone(), v.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        assert_eq!(
            value(
                direct
                    .start(0, [8, 0x1000, 0, 0, 0, 0], &mut memory, 1, &target, None)
                    .unwrap()
            ),
            Ok(0)
        );
        let id = u64::from_le_bytes(memory.read_array(0x1000).unwrap());
        let wait = match direct
            .start(4, [id, 1, 1, 0x2000, 0, 0], &mut memory, 1, &target, None)
            .unwrap()
        {
            IoAttempt::Blocked(p) => p,
            _ => panic!("empty CQ must park"),
        };
        assert_eq!(
            value(
                direct
                    .start(1, [id, 0, 0, 0, 0, 0], &mut memory, 2, &target, None)
                    .unwrap()
            ),
            Ok(0)
        );
        memory.write_array(0x1000, 0u64.to_le_bytes()).unwrap();
        assert_eq!(
            value(
                direct
                    .start(0, [8, 0x1000, 0, 0, 0, 0], &mut memory, 2, &target, None)
                    .unwrap()
            ),
            Ok(0)
        );
        assert_eq!(u64::from_le_bytes(memory.read_array(0x1000).unwrap()), id);
        assert_eq!(value(direct.resume(wait, &mut memory)), Err(Errno(22)));
        assert!(aio.context(id).is_ok());
    }
}
