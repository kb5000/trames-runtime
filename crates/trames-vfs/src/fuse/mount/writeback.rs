// SPDX-License-Identifier: GPL-3.0-or-later
//! Daemon writeback driven by original file tasks and reply readiness.
use super::*;
use std::collections::VecDeque;
use std::sync::{Mutex, Weak};
use trames_memory::{MemoryError, PageWait, SyncCompletion, SyncExecutor, SyncResource, PAGE_SIZE};

#[derive(Default)]
pub(super) struct Queue {
    active: Option<Arc<Wave>>,
    pending: VecDeque<Arc<Wave>>,
    background: Weak<Accepted>,
}
pub(super) struct OpenWriter {
    file: Arc<File>,
    original: SharedFd,
    _lease: Arc<mapped::MountWrite>,
    executor: Arc<dyn SyncExecutor>,
}
impl OpenWriter {
    pub(super) fn original(&self) -> &SharedFd {
        &self.original
    }
    pub(super) fn executor(&self) -> Arc<dyn SyncExecutor> {
        self.executor.clone()
    }
    pub(super) fn new(
        file: Arc<File>,
        original: SharedFd,
        executor: Arc<dyn SyncExecutor>,
    ) -> Result<Arc<Self>> {
        let lease = match &file._writer {
            Some(lease) => lease.clone(),
            None => Arc::new(mapped::MountWrite::new(&file.mount.identity)?),
        };
        Ok(Self::with_lease(file, original, executor, lease))
    }
    fn with_lease(
        file: Arc<File>,
        original: SharedFd,
        executor: Arc<dyn SyncExecutor>,
        lease: Arc<mapped::MountWrite>,
    ) -> Arc<Self> {
        let writer = Arc::new(Self {
            file,
            original,
            _lease: lease,
            executor,
        });
        writer.file.attr.cache.remember_writer(&writer.original);
        {
            let mut writers = writer.file.attr.cache.writers.lock().unwrap();
            writers.retain(|writer| writer.strong_count() != 0);
            writers.push(Arc::downgrade(&writer));
        }
        writer
    }
    pub(super) fn flush(self: &Arc<Self>, caller: Caller) -> Pending {
        let outcome = Arc::new(Outcome::default());
        self.flush_with(caller, Box::new(OutcomeCompletion(outcome.clone())));
        Pending(outcome)
    }
    pub(super) fn flush_with(
        self: &Arc<Self>,
        caller: Caller,
        completion: Box<dyn SyncCompletion>,
    ) {
        let resource = Sync::with_options(
            self.file.clone(),
            self.original.clone(),
            caller,
            false,
            false,
            Some(self.clone()),
            Some(self.executor.clone()),
        );
        self.executor.submit(Arc::new(resource), completion);
    }
    fn range_resource(
        self: &Arc<Self>,
        caller: Caller,
        offset: u64,
        length: u64,
        write: bool,
    ) -> Arc<dyn SyncResource> {
        let mut resource = Sync::with_options(
            self.file.clone(),
            self.original.clone(),
            caller,
            false,
            false,
            Some(self.clone()),
            Some(self.executor.clone()),
        );
        let accepted = Arc::get_mut(&mut resource.0).unwrap();
        accepted.range = Some((
            offset,
            if length == 0 {
                u64::MAX
            } else {
                offset + length
            },
        ));
        accepted.write = write;
        // sync_file_range does not write inode metadata. Explicit close,
        // fsync, syncfs and mapping close resources retain their full barrier.
        accepted.times.store(false, Ordering::Relaxed);
        Arc::new(resource)
    }
    pub(super) fn range(
        self: &Arc<Self>,
        caller: Caller,
        offset: u64,
        length: u64,
        flags: u32,
    ) -> Pending {
        if flags & 4 != 0 || flags & 2 == 0 {
            return submit(
                self.range_resource(caller, offset, length, flags & 2 != 0),
                &self.executor,
            );
        }
        let resource = self.range_resource(caller, offset, length, true);
        if flags & 1 == 0 {
            self.executor.submit(resource, Box::new(Discard));
            return Pending::completed(Ok(()));
        }
        let outcome = Arc::new(Outcome::default());
        self.executor.submit(
            self.range_resource(caller, offset, length, false),
            Box::new(BeginRange {
                executor: self.executor.clone(),
                resource,
                outcome: outcome.clone(),
            }),
        );
        Pending(outcome)
    }
}
struct BeginRange {
    executor: Arc<dyn SyncExecutor>,
    resource: Arc<dyn SyncResource>,
    outcome: Arc<Outcome>,
}
impl SyncCompletion for BeginRange {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        if result.is_ok() {
            self.executor.submit(self.resource, Box::new(Discard));
        }
        Box::new(OutcomeCompletion(self.outcome)).complete(result);
    }
}
pub(crate) struct Pending(Arc<Outcome>);
pub(super) fn submit(resource: Arc<dyn SyncResource>, executor: &Arc<dyn SyncExecutor>) -> Pending {
    let outcome = Arc::new(Outcome::default());
    executor.submit(resource, Box::new(OutcomeCompletion(outcome.clone())));
    Pending(outcome)
}
impl Pending {
    pub(super) fn completed(result: Result<()>) -> Self {
        let outcome = Arc::new(Outcome::default());
        *outcome.result.lock().unwrap() = Some(result);
        outcome.wait.finish();
        Self(outcome)
    }
    pub(crate) fn ready(&self) -> bool {
        self.0.wait.ready()
    }
    pub(crate) fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.0.wait.subscribe(signal)
    }
    pub(crate) fn result(&self) -> Option<Result<()>> {
        *self.0.result.lock().unwrap()
    }
}
#[derive(Clone)]
pub(super) struct Sync(Arc<Accepted>);
struct Accepted {
    file: Arc<File>,
    original: SharedFd,
    caller: Caller,
    fsync: bool,
    data_only: bool,
    range: Option<(u64, u64)>,
    write: bool,
    times: std::sync::atomic::AtomicBool,
    _writer: Option<Arc<OpenWriter>>,
    executor: Option<Arc<dyn SyncExecutor>>,
    wave: Mutex<Option<Arc<Wave>>>,
    outcome: OnceLock<Arc<Outcome>>,
}
#[derive(Default)]
struct Outcome {
    result: Mutex<Option<Result<()>>>,
    wait: Arc<PageWait>,
}
struct OutcomeCompletion(Arc<Outcome>);
impl SyncCompletion for OutcomeCompletion {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        let result = result.map_err(|error| match error {
            MemoryError::BackingIo(code) => Errno(code),
            _ => Errno(5),
        });
        *self.0.result.lock().unwrap() = Some(result);
        self.0.wait.finish();
    }
}
struct Discard;
impl SyncCompletion for Discard {
    fn complete(self: Box<Self>, _: std::result::Result<(), MemoryError>) {}
}
impl Sync {
    pub(super) fn new(
        file: Arc<File>,
        original: SharedFd,
        caller: Caller,
        writer: Option<Arc<OpenWriter>>,
    ) -> Self {
        Self::with_options(
            file,
            original,
            caller,
            true,
            false,
            writer,
            crate::file_actor::sync_executor(),
        )
    }
    pub(super) fn with_options(
        file: Arc<File>,
        original: SharedFd,
        caller: Caller,
        fsync: bool,
        data_only: bool,
        writer: Option<Arc<OpenWriter>>,
        executor: Option<Arc<dyn SyncExecutor>>,
    ) -> Self {
        Self(Arc::new(Accepted {
            file,
            original,
            caller,
            fsync,
            data_only,
            range: None,
            write: true,
            times: std::sync::atomic::AtomicBool::new(true),
            _writer: writer,
            executor,
            wave: Mutex::default(),
            outcome: OnceLock::new(),
        }))
    }
}
impl Drop for Accepted {
    fn drop(&mut self) {
        if let Some(wave) = self.wave.get_mut().unwrap().take() {
            // A failed executor can retire the accepted task while it is queued
            // for layout admission. No pending callback remains to close it.
            let cancelled = {
                let state = wave.state.lock().unwrap();
                state.result.is_none() && state.completion.is_none()
            };
            if cancelled {
                wave.finish(Err(Errno(5)));
            }
        }
    }
}
impl SyncResource for Sync {
    fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        Some(self.0.file.attr.layout.clone())
    }
    fn failed(&self, error: MemoryError) {
        let error = Errno(match error {
            MemoryError::BackingIo(code) => code,
            _ => 5,
        });
        let wave = self.0.wave.lock().unwrap().clone();
        if let Some(wave) = wave {
            let record = {
                let mut state = wave.state.lock().unwrap();
                if state.result.is_some() {
                    false
                } else {
                    state.error = Some(error);
                    true
                }
            };
            if record {
                self.0.file.attr.cache.record_error(error);
            }
            wave.finish(Err(error));
        } else {
            self.0.file.attr.cache.record_error(error);
        }
    }
    fn sync(&self) -> std::result::Result<(), MemoryError> {
        let outcome = self.0.outcome.get_or_init(|| {
            let outcome = Arc::new(Outcome::default());
            if let Some(executor) = &self.0.executor {
                executor.submit(
                    Arc::new(self.clone()),
                    Box::new(OutcomeCompletion(outcome.clone())),
                );
            } else {
                *outcome.result.lock().unwrap() = Some(Err(Errno(95)));
                outcome.wait.finish();
            }
            outcome
        });
        match *outcome.result.lock().unwrap() {
            Some(result) => result.map_err(|e| MemoryError::BackingIo(e.0)),
            None => Err(outcome.wait.fault(0)),
        }
    }
    fn sync_async(
        &self,
        completion: Box<dyn SyncCompletion>,
    ) -> std::result::Result<(), Box<dyn SyncCompletion>> {
        let (wave, new) = {
            let mut slot = self.0.wave.lock().unwrap();
            if let Some(wave) = &*slot {
                (wave.clone(), false)
            } else {
                let wave = Arc::new(Wave {
                    file: self.0.file.clone(),
                    _original: self.0.original.clone(),
                    caller: self.0.caller,
                    fsync: self.0.fsync,
                    data_only: self.0.data_only,
                    range: self.0.range,
                    write: self.0.write,
                    accepted: Arc::downgrade(&self.0),
                    state: Mutex::default(),
                    signal: OnceLock::new(),
                });
                *slot = Some(wave.clone());
                (wave, true)
            }
        };
        if new {
            wave.enqueue(completion);
        } else {
            wave.accept(completion);
        }
        Ok(())
    }
}
pub(super) fn background(writer: &Arc<OpenWriter>) {
    background_with_times(writer, true);
}
pub(super) fn background_data(writer: &Arc<OpenWriter>) {
    background_with_times(writer, false);
}
fn background_with_times(writer: &Arc<OpenWriter>, times: bool) {
    // Coalesce using the original accepted resource, under the existing inode
    // queue lock. A mapping-close request can upgrade a queued data-only wave.
    // Keep upgraded resources alive until the queue guard is released.
    let (resource, new) = {
        let mut queue = writer.file.attr.cache.writeback.lock().unwrap();
        if let Some(accepted) = queue.background.upgrade() {
            if times {
                accepted.times.store(true, Ordering::Relaxed);
            }
            (Sync(accepted), false)
        } else {
            let resource = Sync::with_options(
                writer.file.clone(),
                writer.original.clone(),
                Caller::default(),
                false,
                false,
                Some(writer.clone()),
                Some(writer.executor.clone()),
            );
            resource.0.times.store(times, Ordering::Relaxed);
            queue.background = Arc::downgrade(&resource.0);
            (resource, true)
        }
    };
    if !new {
        return;
    }
    let accepted = Arc::downgrade(&resource.0);
    writer.executor.submit(
        Arc::new(resource),
        Box::new(Background {
            writer: writer.clone(),
            accepted,
        }),
    );
}
struct Background {
    writer: Arc<OpenWriter>,
    accepted: Weak<Accepted>,
}
impl SyncCompletion for Background {
    fn complete(self: Box<Self>, result: std::result::Result<(), MemoryError>) {
        let cache = &self.writer.file.attr.cache;
        let accepted = self.accepted.upgrade();
        let times = {
            let mut queue = cache.writeback.lock().unwrap();
            if queue.background.ptr_eq(&self.accepted) {
                queue.background = Weak::new();
            }
            // Sample the upgrade in the same critical section that retires
            // its original queue membership, including a late close request.
            accepted
                .as_ref()
                .is_some_and(|a| a.times.load(Ordering::Relaxed))
        };
        // A different VMA can retire while this inode's snapshot is in flight.
        // Its later dirty generation must get a fresh, coalesced wave.
        if result.is_ok()
            && (cache.dirty()
                || times && self.writer.file.attr.dirty_times.load(Ordering::Relaxed) != 0)
        {
            background_with_times(&self.writer, times);
        }
    }
}

struct Wave {
    file: Arc<File>,
    _original: SharedFd,
    caller: Caller,
    fsync: bool,
    data_only: bool,
    range: Option<(u64, u64)>,
    write: bool,
    accepted: Weak<Accepted>,
    state: Mutex<State>,
    signal: OnceLock<Arc<IoSignal>>,
}
#[derive(Default)]
struct State {
    completion: Option<Box<dyn SyncCompletion>>,
    transaction: Option<inode::Write>,
    subscriptions: Vec<IoSubscription>,
    pages: Option<VecDeque<(u64, Arc<cache::Page>)>>,
    current: Option<Snapshot>,
    serial: u64,
    pending: bool,
    reply: Option<(u64, Kind, Result<Vec<u8>>)>,
    request: Option<Request>,
    receiver: Option<Arc<dyn transport::ReplyReceiver>>,
    synced: bool,
    result: Option<Result<()>>,
    error: Option<Errno>,
}
struct Snapshot {
    pages: Vec<(Arc<cache::Page>, u64)>,
    offset: u64,
    bytes: Vec<u8>,
    cursor: usize,
}
impl Snapshot {
    fn failed(self, count: usize, pending: &mut VecDeque<(u64, Arc<cache::Page>)>) {
        let attempted = self.cursor + count;
        for (index, (page, generation)) in self.pages.into_iter().enumerate().rev() {
            if index * (PAGE_SIZE as usize) < attempted {
                // Retire only pages reached by an actual request, including
                // earlier successful slices. Preserve a newer store generation.
                page.wrote_back(generation);
            } else {
                // Captured but never submitted bytes still belong to the dirty
                // cache. Later work reacquires them under the original layout.
                pending.push_front((self.offset / PAGE_SIZE + index as u64, page));
            }
        }
    }
}
#[derive(Clone, Copy)]
enum Kind {
    Write(usize),
    Times(u64),
    Sync,
}
struct Receiver {
    wave: Weak<Wave>,
    serial: u64,
    kind: Kind,
}
impl transport::ReplyReceiver for Receiver {
    fn complete(&self, result: Result<Vec<u8>>) {
        if let Some(wave) = self.wave.upgrade() {
            wave.received(self.serial, self.kind, result);
        }
    }
}
impl IoWake for Wave {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        let completion = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_none() && state.transaction.is_none() && !state.pending {
                state.completion.take()
            } else {
                None
            }
        };
        if let Some(completion) = completion {
            completion.retry();
        }
    }
}
enum Action {
    Wait,
    Retry(Box<dyn SyncCompletion>),
    Send(u64, u32, Caller, Vec<u8>, Arc<dyn transport::ReplyReceiver>),
    Finish(Result<()>),
}
impl Wave {
    fn enqueue(self: &Arc<Self>, completion: Box<dyn SyncCompletion>) {
        self.state.lock().unwrap().completion = Some(completion);
        let first = {
            let mut queue = self.file.attr.cache.writeback.lock().unwrap();
            if queue.active.is_none() {
                queue.active = Some(self.clone());
                true
            } else {
                queue.pending.push_back(self.clone());
                false
            }
        };
        if first {
            self.advance(true);
        }
    }
    fn accept(self: &Arc<Self>, completion: Box<dyn SyncCompletion>) {
        let mut state = self.state.lock().unwrap();
        if let Some(result) = state.result {
            drop(state);
            completion.complete(result.map_err(|e| MemoryError::BackingIo(e.0)));
        } else {
            assert!(
                state.completion.replace(completion).is_none(),
                "one accepted writeback task"
            );
            let reply = state.reply.take();
            drop(state);
            if let Some((serial, kind, result)) = reply {
                self.apply_received(serial, kind, result);
            } else {
                self.advance(true);
            }
        }
    }
    fn retry(&self) {
        let completion = self.state.lock().unwrap().completion.take();
        if let Some(completion) = completion {
            completion.retry();
        }
    }
    // Only capture=true runs under original layout admission. Reply callbacks
    // send owned remaining bytes or return the same task to that admission.
    fn action(self: &Arc<Self>, capture: bool) -> Action {
        let mut state = self.state.lock().unwrap();
        if state.result.is_some() || state.pending {
            return Action::Wait;
        }
        if state.transaction.is_none() {
            if !capture {
                return Action::Retry(state.completion.take().expect("accepted writeback"));
            }
            if let Err(error) = self
                .file
                .attr
                .check()
                .and_then(|_| self.file.reference.fs.connection.init_result())
            {
                return Action::Finish(Err(error));
            }
            let signal = self.signal.get_or_init(|| {
                let target: Arc<dyn IoWake> = self.clone();
                IoSignal::new(0, Arc::downgrade(&target))
            });
            signal.reset();
            state.subscriptions = vec![self.file.attr.subscribe_write(signal)];
            let Some(transaction) = self.file.attr.try_write() else {
                return Action::Wait;
            };
            state.transaction = Some(transaction);
            state.subscriptions.clear();
        }
        if state.pages.is_none() {
            if self.write && self.range.is_none() {
                self.file
                    .attr
                    .cache
                    .buffered_pressure
                    .store(0, Ordering::Relaxed);
            }
            state.pages = Some(if self.write {
                self.file
                    .attr
                    .cache
                    .dirty_pages()
                    .into_iter()
                    .filter(|(index, _)| {
                        self.range.is_none_or(|(start, end)| {
                            index * PAGE_SIZE < end && (index + 1) * PAGE_SIZE > start
                        })
                    })
                    .collect()
            } else {
                VecDeque::new()
            });
        }
        while state.current.is_none() {
            if state.pages.as_ref().unwrap().is_empty() {
                break;
            }
            if !capture {
                return Action::Retry(state.completion.take().expect("accepted writeback"));
            }
            let (index, page) = state.pages.as_mut().unwrap().pop_front().unwrap();
            let generation = page.dirty.load(Ordering::Relaxed);
            if generation == 0 {
                continue;
            }
            let offset = index * PAGE_SIZE;
            let size =
                u64::from_le_bytes(self.file.attr.lock().unwrap()[8..16].try_into().unwrap());
            let count = size.saturating_sub(offset).min(PAGE_SIZE) as usize;
            if count == 0 {
                page.wrote_back(generation);
                continue;
            }
            let mut length = count;
            let mut pages = vec![(page, generation)];
            // Snapshot ownership is independent of the wire message ceiling.
            // Only this bounded copy needs original layout admission; middle
            // replies can continue sending its already-owned bytes.
            let limit = 1024 * 1024;
            while let Some((next, page)) = state.pages.as_ref().unwrap().front() {
                let start = next * PAGE_SIZE;
                let count = size.saturating_sub(start).min(PAGE_SIZE) as usize;
                if start != offset + length as u64 || count == 0 || count > limit - length {
                    break;
                }
                let stamp = page.dirty.load(Ordering::Relaxed);
                if stamp == 0 {
                    break;
                }
                let (_, page) = state.pages.as_mut().unwrap().pop_front().unwrap();
                length += count;
                pages.push((page, stamp));
            }
            // Fix the bounded extent before allocating its output. Every byte
            // is copied once, under the same original layout admission; small
            // writes do not reserve the full 1 MiB snapshot ceiling.
            let mut bytes = vec![0; length];
            for (index, (page, _)) in pages.iter().enumerate() {
                let at = index * PAGE_SIZE as usize;
                let end = (at + PAGE_SIZE as usize).min(length);
                page.bytes().copy_read(0, &mut bytes[at..end]);
            }
            state.current = Some(Snapshot {
                pages,
                offset,
                bytes,
                cursor: 0,
            });
        }
        let (opcode, caller, body, kind) = if let Some(current) = &state.current {
            let count = (current.bytes.len() - current.cursor)
                .min(self.file.reference.fs.connection.data_limit());
            let mut body = Vec::with_capacity(40 + count);
            body.resize(40, 0);
            body[..8].copy_from_slice(&self.file.fh.unwrap_or(0).to_le_bytes());
            body[8..16].copy_from_slice(&(current.offset + current.cursor as u64).to_le_bytes());
            body[16..20].copy_from_slice(&(count as u32).to_le_bytes());
            body[20..24].copy_from_slice(&1u32.to_le_bytes()); // FUSE_WRITE_CACHE; no task credentials
            body[32..36].copy_from_slice(&self.file.current_flags().to_le_bytes());
            body.extend_from_slice(&current.bytes[current.cursor..current.cursor + count]);
            (16, Caller::default(), body, Kind::Write(count))
        } else if self.write
            && self
                .accepted
                .upgrade()
                .is_some_and(|a| a.times.load(Ordering::Relaxed))
            && self.file.attr.dirty_times.load(Ordering::Relaxed) != 0
        {
            let attr = self.file.attr.lock().unwrap();
            let stamp = self.file.attr.dirty_times.load(Ordering::Relaxed);
            let mut body = vec![0; 88];
            body[..4].copy_from_slice(&(32u32 | 64 | 1024).to_le_bytes()); // MTIME | FH | CTIME
            body[8..16].copy_from_slice(&self.file.fh.unwrap_or(0).to_le_bytes());
            body[40..56].copy_from_slice(&attr[32..48]);
            body[60..68].copy_from_slice(&attr[52..60]);
            (4, self.caller, body, Kind::Times(stamp))
        } else if let Some(error) = state.error {
            return Action::Finish(Err(error));
        } else if self.fsync
            && !state.synced
            && self
                .file
                .reference
                .fs
                .sync_unsupported
                .load(Ordering::Relaxed)
                & 1
                == 0
        {
            let mut body = vec![0; 16];
            body[..8].copy_from_slice(&self.file.fh.unwrap_or(0).to_le_bytes());
            body[8] = u8::from(self.data_only);
            state.synced = true;
            (20, self.caller, body, Kind::Sync)
        } else {
            return Action::Finish(Ok(()));
        };
        state.serial = state.serial.wrapping_add(1);
        let serial = state.serial;
        let receiver: Arc<dyn transport::ReplyReceiver> = Arc::new(Receiver {
            wave: Arc::downgrade(self),
            serial,
            kind,
        });
        state.receiver = Some(receiver.clone());
        state.pending = true;
        Action::Send(serial, opcode, caller, body, receiver)
    }
    fn advance(self: &Arc<Self>, capture: bool) {
        self.dispatch(self.action(capture));
    }
    fn dispatch(self: &Arc<Self>, action: Action) {
        match action {
            Action::Wait => {}
            Action::Retry(completion) => completion.retry(),
            Action::Finish(result) => self.finish(result),
            Action::Send(serial, opcode, caller, body, receiver) => {
                let result = self.file.reference.fs.connection.request_received(
                    opcode,
                    self.file.reference.node,
                    caller,
                    &body,
                    Arc::downgrade(&receiver),
                );
                match result {
                    Ok(request) => {
                        let mut state = self.state.lock().unwrap();
                        if state.serial == serial && state.pending {
                            state.request = Some(request);
                        } else {
                            drop(state);
                            drop(request);
                        }
                    }
                    Err(error) => receiver.complete(Err(error)),
                }
            }
        }
    }
    fn received(self: &Arc<Self>, serial: u64, kind: Kind, result: Result<Vec<u8>>) {
        let failed = result.is_err();
        let forward = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_some()
                || state.serial != serial
                || !state.pending
                || state.reply.is_some()
            {
                return;
            }
            let intermediate = match (kind, &result, state.current.as_ref()) {
                (Kind::Write(count), Ok(bytes), Some(current)) => {
                    bytes.len() == 8
                        && u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize == count
                        && current.cursor + count < current.bytes.len()
                }
                _ => false,
            };
            if intermediate {
                let Kind::Write(count) = kind else {
                    unreachable!()
                };
                state.current.as_mut().unwrap().cursor += count;
                state.pending = false;
                Some((state.request.take(), state.receiver.take()))
            } else {
                state.reply = Some((serial, kind, result));
                None
            }
        };
        if let Some((request, receiver)) = forward {
            drop(request);
            drop(receiver);
            // This changes only a private snapshot cursor and sends owned
            // bytes. No cache stamp, page, inode or mapping is modified here.
            self.advance(false);
        } else if failed {
            // A disconnected transport can reject the next request in this
            // same stack. Keep failures on the original task so a large dirty
            // remainder cannot recursively dispatch until the stack overflows.
            self.defer_reply();
        } else {
            self.resume_reply();
        }
    }
    fn resume_reply(self: &Arc<Self>) {
        // This is the same original publication exclusion used by the pool,
        // never a mapped() observation. All work below is bounded memory and
        // owned-message work; actual waits return to the existing executor.
        match self.file.attr.layout.write().try_enter() {
            Ok(admission) => {
                let reply = {
                    let mut state = self.state.lock().unwrap();
                    if state.result.is_none() && state.completion.is_some() {
                        state.reply.take()
                    } else {
                        None
                    }
                };
                if let Some((serial, kind, result)) = reply {
                    let action = self.reply_action(serial, kind, result);
                    // Completion and subsequent dispatch cannot resume a
                    // consumer while this inline publication lease is held.
                    drop(admission);
                    self.dispatch(action);
                }
            }
            Err(ticket) => {
                drop(ticket);
                self.defer_reply();
            }
        }
    }
    fn defer_reply(&self) {
        let completion = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_none() && state.reply.is_some() {
                state.completion.take()
            } else {
                None
            }
        };
        if let Some(completion) = completion {
            completion.retry();
        }
    }
    fn apply_received(self: &Arc<Self>, serial: u64, kind: Kind, result: Result<Vec<u8>>) {
        self.dispatch(self.reply_action(serial, kind, result));
    }
    fn reply_action(self: &Arc<Self>, serial: u64, kind: Kind, result: Result<Vec<u8>>) -> Action {
        let (request, receiver, result) = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_some() || state.serial != serial || !state.pending {
                return Action::Wait;
            }
            state.pending = false;
            let request = state.request.take();
            let receiver = state.receiver.take();
            let mut result = match (kind, result) {
                (Kind::Write(count), Ok(bytes))
                    if bytes.len() == 8
                        && u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize == count =>
                {
                    let current = state.current.as_mut().expect("accepted dirty page");
                    current.cursor += count;
                    if current.cursor == current.bytes.len() {
                        for (page, generation) in &current.pages {
                            page.wrote_back(*generation);
                        }
                        state.current = None;
                    }
                    Ok(())
                }
                (Kind::Sync, Ok(bytes)) if bytes.is_empty() => Ok(()),
                (Kind::Times(stamp), Ok(bytes)) if bytes.len() == 104 => {
                    inode::validate(&bytes[16..]).map(|()| {
                        let _ = self.file.attr.dirty_times.compare_exchange(
                            stamp,
                            0,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    })
                }
                (Kind::Sync, Err(Errno(38))) => {
                    self.file
                        .reference
                        .fs
                        .sync_unsupported
                        .fetch_or(1, Ordering::Relaxed);
                    Ok(())
                }
                (_, Err(error)) => Err(error),
                _ => Err(Errno(5)),
            };
            if matches!(kind, Kind::Write(_) | Kind::Times(_)) {
                if let Err(error) = result {
                    // Submitted pages leave the dirty set even on server
                    // failure. New mmap stores retain a distinct generation.
                    if let (Kind::Write(count), Some(current)) = (kind, state.current.take()) {
                        current.failed(count, state.pages.as_mut().unwrap());
                    }
                    if let Kind::Times(stamp) = kind {
                        let _ = self.file.attr.dirty_times.compare_exchange(
                            stamp,
                            0,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        );
                    }
                    self.file.attr.cache.record_error(error);
                    state.error.get_or_insert(error);
                    result = Ok(());
                }
            }
            (request, receiver, result)
        };
        drop(request);
        drop(receiver);
        if let Err(error) = result {
            Action::Finish(Err(error))
        } else {
            self.action(true)
        }
    }
    fn finish(self: &Arc<Self>, result: Result<()>) {
        let (completion, transaction, request, receiver, subscriptions) = {
            let mut state = self.state.lock().unwrap();
            if state.result.is_some() {
                return;
            }
            if !self.fsync && state.error.is_none() {
                if let Err(error) = result {
                    self.file.attr.cache.record_error(error);
                }
            }
            state.result = Some(result);
            // Publication may still be returning the original Request. A
            // retired wave cannot install that handle after this terminal.
            state.pending = false;
            (
                state.completion.take(),
                state.transaction.take(),
                state.request.take(),
                state.receiver.take(),
                std::mem::take(&mut state.subscriptions),
            )
        };
        let (retired, next) = {
            let mut queue = self.file.attr.cache.writeback.lock().unwrap();
            let retired = if queue
                .active
                .as_ref()
                .is_some_and(|wave| Arc::ptr_eq(wave, self))
            {
                queue.active.take()
            } else {
                queue.pending.retain(|wave| !Arc::ptr_eq(wave, self));
                None
            };
            let next = if queue.active.is_none() {
                queue.pending.pop_front()
            } else {
                None
            };
            if let Some(next) = &next {
                queue.active = Some(next.clone());
            }
            (retired, next)
        };
        drop(request);
        drop(receiver);
        drop(subscriptions);
        drop(transaction);
        drop(retired);
        self.file.attr.validity.set(0, 0);
        self.file.attr.cache.changed(true);
        let result = if self.fsync {
            let recorded = self.file.attr.cache.check_error(&self.file.writeback_seen);
            result.and(recorded)
        } else {
            result
        };
        if let Some(completion) = completion {
            completion.complete(result.map_err(|e| MemoryError::BackingIo(e.0)));
        }
        if let Some(next) = next {
            next.retry();
        }
    }
}
