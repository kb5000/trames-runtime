// SPDX-License-Identifier: GPL-3.0-or-later
//! Legacy buffered Linux AIO. Accepted batches use the existing disk executor;
//! the source task performs copyout and publishes CQ/eventfd in that order.
//! io_submit may block for buffered I/O, as on Linux. It releases its CPU slot
//! while waiting, and returns only after this batch's buffers are no longer in
//! use. There are no detached guest pointers, memory-owner RPCs or new threads.
use super::file::FileCopyout;
use super::*;
#[path = "aio/events.rs"]
mod events;
#[path = "aio/input.rs"]
mod input;
#[path = "aio/lookup.rs"]
pub(in crate::direct) mod lookup;
#[path = "aio/setup.rs"]
mod setup;
pub use setup::SetupInput;
#[cfg(test)]
#[path = "aio/exit_tests.rs"]
mod exit_tests;
#[path = "aio/mapping.rs"]
mod mapping;
#[cfg(test)]
#[path = "aio/mask_tests.rs"]
mod mask_tests;
#[path = "aio/owned.rs"]
mod owned;
#[cfg(test)]
#[path = "aio/resource_tests.rs"]
mod resource_tests;
#[path = "aio/retire.rs"]
mod retire;
#[cfg(test)]
#[path = "aio/submit_tests.rs"]
mod submit_tests;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};

#[derive(Clone, Default)]
pub struct Aio(Arc<Registry>);
struct Registry {
    contexts: Mutex<BTreeMap<u32, Arc<Context>>>,
    retiring: Mutex<Vec<Weak<Context>>>,
    closed: std::sync::atomic::AtomicBool,
    close_key: u64,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            contexts: Mutex::default(),
            retiring: Mutex::default(),
            closed: false.into(),
            close_key: trames_memory::new_backing_identity(),
        }
    }
}
#[derive(Clone)]
pub struct RetainedAio {
    context: Arc<Context>,
    user: Option<Arc<lookup::User>>,
    destroyed: bool,
    batch: Option<Arc<Mutex<Batch>>>,
    import: Option<Arc<Mutex<input::Submit>>>,
    header: Option<Arc<Mutex<input::Header>>>,
    events: Option<Arc<Mutex<events::Events>>>,
    reaped: u64,
    number: u32,
    args: [u64; 6],
    deadline: Option<Instant>,
}
impl RetainedAio {
    pub fn entry(&self) -> (u32, [u64; 6]) {
        (self.number, self.args)
    }
    pub fn must_finish_on_exit(&self) -> bool {
        self.user.as_ref().is_some_and(|user| user.active())
            && (self.number == 1 && self.destroyed
                || self.number == 2
                    && (self.import.is_some()
                        || self
                            .batch
                            .as_ref()
                            .is_some_and(|batch| !batch.lock().unwrap().requests.is_empty())))
    }
    pub fn exit_waiting(&self) -> bool {
        matches!(self.number, 1 | 2)
            && self
                .user
                .as_ref()
                .is_some_and(|user| user.exiting() && user.active())
    }
    pub fn native_mask(&self) -> bool {
        self.header
            .as_ref()
            .is_some_and(|header| header.lock().unwrap().native_mask())
    }
    pub fn cancel(&self) {
        if let Some(header) = &self.header {
            header.lock().unwrap().finish(false);
        }
        if let Some(events) = &self.events {
            events.lock().unwrap().cancel();
        }
        if let Some(import) = &self.import {
            import.lock().unwrap().cancel();
        }
        if let Some(batch) = &self.batch {
            let (requests, pending) = {
                let mut batch = batch.lock().unwrap();
                (std::mem::take(&mut batch.requests), batch.pending.take())
            };
            Batch::discard_pending(&self.context, pending);
            Batch::abandon(&self.context, requests);
        }
        if let Some(user) = &self.user {
            user.release();
        }
    }
    pub fn interruptible(&self) -> bool {
        matches!(self.number, 4 | 292)
            && self.events.is_none()
            && !self.context.state.lock().unwrap().reaping
    }
    pub fn interrupted(&self) -> Result<u64, Errno> {
        if let Some(header) = &self.header {
            header.lock().unwrap().finish(true);
        }
        if let Some(user) = &self.user {
            user.release();
        }
        if self.reaped != 0 {
            Ok(self.reaped)
        } else {
            Err(Errno(4))
        }
    }
}
struct Context {
    slot: u32,
    mapping: Arc<mapping::Mapping>,
    ring: Vec<Arc<trames_memory::SharedPage>>,
    mappings: Vec<Arc<dyn trames_memory::PageBacking>>,
    slots: u32,
    state: Mutex<State>,
    readiness: Arc<trames_vfs::Readiness>,
    mapping_close: std::sync::OnceLock<Arc<FileResult>>,
}
struct State {
    capacity: usize,
    dead: bool,
    active: Active,
    tail: u32,
    reaping: bool,
    users: usize,
    destroyers: usize,
    closing: Vec<Arc<retire::CloseWait>>,
    owned: BTreeMap<usize, Arc<owned::Fsync>>,
}
#[derive(Default)]
struct Active {
    objects: BTreeMap<u64, usize>,
    count: usize,
}
impl Active {
    fn len(&self) -> usize {
        self.count
    }
    fn is_empty(&self) -> bool {
        self.count == 0
    }
    fn contains(&self, object: &u64) -> bool {
        self.objects.contains_key(object)
    }
    fn insert(&mut self, object: u64) {
        *self.objects.entry(object).or_default() += 1;
        self.count += 1;
    }
    fn remove(&mut self, object: &u64) -> bool {
        let Some(count) = self.objects.get_mut(object) else {
            return false;
        };
        *count -= 1;
        self.count -= 1;
        if *count == 0 {
            self.objects.remove(object);
        }
        true
    }
}
#[allow(clippy::large_enum_variant)] // Transient dispatch is consumed immediately; boxing adds an allocation to every AIO file request.
enum Work {
    Disk(trames_vfs::FileWork),
    Pipe(trames_vfs::DirectFd, trames_vfs::FileCommand),
}
struct Request {
    _file: trames_vfs::SharedFd,
    resources: trames_vfs::CgroupResourceContext,
    actor: Option<Arc<trames_vfs::FileActorSnapshot>>,
    asynchronous: bool,
    waiting: Option<trames_vfs::FileWork>,
    layout: Option<Box<LayoutWait>>,
    pipe: Option<(trames_vfs::DirectFd, trames_vfs::FileCommand)>,
    object: u64,
    data: u64,
    result: Arc<FileResult>,
    output: FileOutput,
    copyout: Option<FileCopyout>,
    event: Option<trames_vfs::NativeEvent>,
}
struct Iocb {
    address: u64,
    bytes: [u8; 64],
    file: trames_vfs::SharedFd,
    resources: trames_vfs::CgroupResourceContext,
    actor: Option<Arc<trames_vfs::FileActorSnapshot>>,
    event: Option<trames_vfs::NativeEvent>,
}
struct LayoutWait {
    work: trames_vfs::FileWork,
    ticket: Option<trames_memory::layout::LayoutWrite>,
}
struct Batch {
    context: Arc<Context>,
    requests: VecDeque<Request>,
    pending: Option<(Request, Work)>,
}
struct AbandonedRequest {
    context: Arc<Context>,
    object: u64,
    file: Option<trames_vfs::SharedFd>,
    event: Option<trames_vfs::NativeEvent>,
}
impl Drop for AbandonedRequest {
    fn drop(&mut self) {
        drop(self.file.take());
        drop(self.event.take());
        self.context
            .state
            .lock()
            .unwrap()
            .active
            .remove(&self.object);
        self.context.notify();
    }
}
impl Batch {
    fn discard_pending(context: &Context, pending: Option<(Request, Work)>) {
        if let Some((request, work)) = pending {
            let object = request.object;
            drop(work);
            drop(request);
            context.state.lock().unwrap().active.remove(&object);
            context.notify();
        }
    }
    fn abandon(context: &Arc<Context>, requests: VecDeque<Request>) {
        for request in requests {
            let native_pending = request.waiting.is_none()
                && request.layout.is_none()
                && request.pipe.is_none()
                && request.copyout.is_none();
            let result = request.result.clone();
            let release: Box<dyn Send> = Box::new(AbandonedRequest {
                context: context.clone(),
                object: request.object,
                file: Some(request._file.clone()),
                event: request.event.clone(),
            });
            let release = match request
                .waiting
                .as_ref()
                .and_then(trames_vfs::FileWork::fuse_signal_request)
            {
                Some(pending) => pending.retain_cancellation(release),
                None => Some(release),
            };
            // Release local copy/position/layout resources before making this
            // request inactive. In-flight owned host work keeps its credit
            // until its original FileResult is completed by the existing pool.
            drop(request);
            result.abandon(release, native_pending);
        }
    }
}
impl Drop for Batch {
    fn drop(&mut self) {
        Self::discard_pending(&self.context, self.pending.take());
        Self::abandon(&self.context, std::mem::take(&mut self.requests));
    }
}
impl Context {
    fn complete(
        &self,
        request: Request,
        result: Result<u64, Errno>,
        resources: trames_vfs::FileResources,
    ) {
        let mut event = [0; 32];
        event[..8].copy_from_slice(&request.data.to_le_bytes());
        event[8..16].copy_from_slice(&request.object.to_le_bytes());
        event[16..24].copy_from_slice(
            &result
                .unwrap_or_else(|error| 0u64.wrapping_sub(error.0 as u64))
                .to_le_bytes(),
        );
        self.publish(&mut self.state.lock().unwrap(), event);
        if let Some(event) = &request.event {
            event.notify();
        }
        let object = request.object;
        drop(resources);
        drop(request);
        self.state.lock().unwrap().active.remove(&object);
        self.notify();
    }
    fn head(&self) -> u32 {
        // SAFETY: naturally aligned u32 cells in the first mapped guest page.
        (unsafe { self.ring[0].load_acquire_u32(8) }) % self.slots
    }
    fn pending(&self, head: u32, tail: u32) -> usize {
        ((tail + self.slots - head) % self.slots) as usize
    }
    fn event(&self, index: u32) -> (&trames_memory::SharedPage, usize) {
        let offset = 32 + index as usize * 32;
        (&self.ring[offset / 4096], offset % 4096)
    }
    fn publish(&self, state: &mut State, bytes: [u8; 32]) {
        let (page, offset) = self.event(state.tail);
        page.copy_write(offset, &bytes);
        state.tail = (state.tail + 1) % self.slots;
        // SAFETY: the tail cell is aligned and the event is complete.
        unsafe {
            self.ring[0].store_release_u32(12, state.tail);
        }
    }
}
impl Aio {
    pub fn fork(&self) -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn context(&self, id: u64, memory: &impl CpuMemory) -> Result<Arc<Context>, Errno> {
        let slot = u32::from_le_bytes(memory.read_array(id).map_err(|_| Errno(22))?);
        self.context_slot(id, slot)
    }
    fn context_slot(&self, id: u64, slot: u32) -> Result<Arc<Context>, Errno> {
        if id >= trames_memory::ADDRESS_LIMIT || !id.is_multiple_of(trames_memory::PAGE_SIZE) {
            return Err(Errno(22));
        }
        let context = self
            .0
            .contexts
            .lock()
            .unwrap()
            .get(&slot)
            .cloned()
            .ok_or(Errno(22))?;
        if context.mapping.address() != id {
            return Err(Errno(22));
        }
        Ok(context)
    }
    fn setup_count(count: u32) -> Result<(), Errno> {
        if count == 0 {
            return Err(Errno(22));
        }
        if count > 65536 {
            return Err(Errno(11));
        }
        Ok(())
    }
    #[cfg(test)]
    fn setup(&self, a: [u64; 6], memory: &mut trames_memory::Memory) -> Result<u64, Errno> {
        if u64::from_le_bytes(memory.read_array(a[1]).map_err(|_| Errno(14))?) != 0 {
            return Err(Errno(22));
        }
        Self::setup_count(a[0] as u32)?;
        let mut allocation = self.allocate(a[0] as u32, a[1], memory)?;
        if allocation.copy.progress(memory).is_err() {
            allocation.cancel(memory)?;
            return Err(Errno(14));
        }
        allocation.commit();
        Ok(0)
    }
    fn allocate(
        &self,
        count: u32,
        output: u64,
        memory: &mut trames_memory::Memory,
    ) -> Result<setup::Allocation, Errno> {
        let mut contexts = self.0.contexts.lock().unwrap();
        if self.0.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Errno(22));
        }
        let slot = (0..128)
            .find(|id| !contexts.contains_key(id))
            .ok_or(Errno(11))?;
        // The header occupies one event; a spare slot distinguishes full and empty.
        let pages = ((count as usize + 2) * 32).div_ceil(4096);
        let length = (pages * 4096) as u64;
        let id = memory
            .find_free(0x7fff_fc00_0000, length)
            .ok_or(Errno(12))?;
        let backing = trames_memory::SharedAnonymousPages::fixed_mapping(pages);
        let ring: Vec<_> = backing.iter().map(|b| b.shared_page().unwrap()).collect();
        let slots = (length / 32 - 1) as u32;
        for (i, word) in [slot, slots, 0, 0, 0xa10a10a1, 1, 0, 32]
            .into_iter()
            .enumerate()
        {
            ring[0].copy_write(i * 4, &word.to_le_bytes());
        }
        let context = Arc::new_cyclic(|context| {
            let mapping = mapping::Mapping::new(
                memory.proc_address_space().unwrap(),
                id,
                length,
                context.clone(),
            );
            Context {
                slot,
                mappings: mapping.pages(&backing),
                mapping,
                ring,
                slots,
                state: Mutex::new(State {
                    capacity: count as usize,
                    dead: false,
                    active: Active::default(),
                    tail: 0,
                    reaping: false,
                    users: 0,
                    destroyers: 0,
                    closing: Vec::new(),
                    owned: BTreeMap::new(),
                }),
                readiness: Arc::default(),
                mapping_close: Default::default(),
            }
        });
        memory
            .map_backed(
                id,
                context.mappings.clone(),
                true,
                trames_memory::Permissions::RW,
                false,
            )
            .map_err(Linux::memory_errno)?;
        let mapping = memory.mapping_cleanup_lease(context.mapping.clone());
        let allocation = setup::Allocation::new(self.clone(), context.clone(), mapping, output, id);
        contexts.insert(slot, context);
        memory.retain_mm_close_resource(
            self.0.close_key,
            Arc::new(retire::FinalClose::new(self.clone())),
        );
        Ok(allocation)
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
    fn iocb_bytes(address: u64, memory: &impl CpuMemory) -> Result<[u8; 64], Errno> {
        let b = memory.read_array::<64>(address).map_err(|_| Errno(14))?;
        let u64_at = |n| u64::from_le_bytes(b[n..n + 8].try_into().unwrap());
        if u64_at(48) != 0 || u64_at(32) > i64::MAX as u64 {
            return Err(Errno(22));
        }
        Ok(b)
    }
    fn bind_iocb(&self, address: u64, b: [u8; 64], pid: u32) -> Result<Iocb, Errno> {
        let u32_at = |n| u32::from_le_bytes(b[n..n + 4].try_into().unwrap());
        let file = self
            .membership
            .as_ref()
            .and_then(|files| files.lookup(u32_at(20)))
            .unwrap_or(Err(Errno(9)))?;
        if file.filesystem_target().status_flags() & trames_vfs::O_PATH != 0 {
            return Err(Errno(9));
        }
        let event = if u32_at(56) & 1 != 0 {
            Some(self.aio.as_ref().unwrap().1.event(u32_at(60))?)
        } else {
            None
        };
        let resources = self.resource_context(pid);
        let op = u16::from_le_bytes(b[16..18].try_into().unwrap());
        let actor = if matches!(op, 2 | 3) {
            let _resources = resources.enter();
            trames_vfs::FileActorScope::frozen()
                .or_else(|| {
                    self.resources.as_ref().map(|factory| {
                        trames_vfs::FileActorScope::frozen_for(factory.local_credentials(), pid)
                    })
                })
                .map(Arc::new)
        } else {
            None
        };
        Ok(Iocb {
            address,
            bytes: b,
            file,
            resources,
            actor,
            event,
        })
    }
    fn import_aio(
        &self,
        accepted: &Iocb,
        memory: &impl CpuMemory,
    ) -> Result<(Request, Work), Errno> {
        let address = accepted.address;
        let b = &accepted.bytes;
        let u32_at = |n| u32::from_le_bytes(b[n..n + 4].try_into().unwrap());
        let u64_at = |n| u64::from_le_bytes(b[n..n + 8].try_into().unwrap());
        let op = u16::from_le_bytes(b[16..18].try_into().unwrap());
        if matches!(op, 2 | 3)
            && (u64_at(24) != 0 || u64_at(32) != 0 || u64_at(40) != 0 || u32_at(12) != 0)
        {
            return Err(Errno(22));
        }
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
        let file = &accepted.file;
        let file_target = file.filesystem_target();
        let flags = file_target.status_flags();
        if matches!(op, 0 | 7) && !trames_vfs::fd_can_read(flags)
            || matches!(op, 1 | 8) && !trames_vfs::fd_can_write(flags)
        {
            return Err(Errno(9));
        }
        if matches!(op, 0 | 1 | 7 | 8) && flags & trames_vfs::O_DIRECT != 0 {
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
            false,
            file_target.unsigned_offsets(),
        )?;
        let work = if matches!(op, 2 | 3) {
            Work::Disk(trames_vfs::FileWork::new(
                self.paths.as_ref().ok_or(Errno(9))?,
                file.filesystem_target(),
                command,
            ))
        } else if let Some(target) = file.file_target() {
            Work::Disk(trames_vfs::FileWork::new(
                self.paths.as_ref().ok_or(Errno(9))?,
                target,
                command,
            ))
        } else if let Some(pipe) = file
            .clone()
            .direct_byte()
            .filter(|fd| fd.is_pipe() && matches!(op, 0 | 1 | 7 | 8))
        {
            Work::Pipe(pipe, command)
        } else {
            return Err(Errno(22));
        };
        Ok((
            Request {
                _file: accepted.file.clone(),
                resources: accepted.resources.clone(),
                actor: accepted.actor.clone(),
                asynchronous: matches!(op, 2 | 3),
                pipe: None,
                waiting: None,
                layout: None,
                object: address,
                data: u64_at(0),
                result: Arc::default(),
                output,
                copyout: None,
                event: accepted.event.clone(),
            },
            work,
        ))
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
        let (aio, _) = self.aio.as_ref()?;
        let resources = self.resource_context(pid);
        if number == 0 {
            return Some(
                Box::new(SetupInput::new(aio.clone(), a, resources))
                    .resume(self, memory, pid, target),
            );
        }
        Some(
            Box::new(lookup::Lookup::new(
                aio.clone(),
                number,
                a,
                deadline,
                resources,
            ))
            .resume(self, memory, pid, target),
        )
    }
    pub fn start_retained_aio(
        &self,
        call: RetainedAio,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if call.user.as_ref().is_some_and(|user| !user.active()) {
            let error = if matches!(call.number, 4 | 292) && call.context.state.lock().unwrap().dead
            {
                Errno(22)
            } else {
                Errno(4)
            };
            return IoAttempt::Complete(Err(error));
        }
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
    /// Fatal task exit completes accepted requests on the original task/mm.
    /// It can interrupt a pipe or an unread FUSE request, but does not invent
    /// a cancellation result for already executing native/daemon operations.
    pub fn drain_aio_exit(
        &self,
        call: RetainedAio,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        if let Some(user) = &call.user {
            user.begin_exit();
        }
        self.start_retained_aio(call, memory, pid, target)
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
        let reaped = retained.as_ref().map_or(0, |call| call.reaped);
        let user = retained.as_ref().and_then(|call| call.user.clone());
        // A context user represents one accepted syscall across all snapshots.
        // IOCBs override this control/input scope with their own accepted origin.
        let _resources = user.as_ref().and_then(|user| user.resource_scope());
        let mask_header = retained.as_ref().and_then(|call| call.header.clone());
        let result = (|| {
            let mut call = retained.expect("context lookup precedes AIO execution");
            let context = call.context.clone();
            let exiting = call.user.as_ref().is_some_and(|user| user.exiting());
            if number == 1 && !call.destroyed {
                let Some(mm) = memory.mapping_owner() else {
                    return Ok(IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                        file::FileBoundary::Aio(call),
                    )));
                };
                {
                    let mut state = context.state.lock().unwrap();
                    if state.dead {
                        return Err(Errno(22));
                    }
                    state.dead = true;
                }
                let mut contexts = aio.0.contexts.lock().unwrap();
                if contexts
                    .get(&context.slot)
                    .is_some_and(|current| Arc::ptr_eq(current, &context))
                {
                    aio.0
                        .retiring
                        .lock()
                        .unwrap()
                        .push(Arc::downgrade(&context));
                    contexts.remove(&context.slot);
                }
                drop(contexts);
                context.notify();
                let _ = mm.unmap(context.mapping.address(), context.mapping.length);
                call.destroyed = true;
            }
            let user = call.user;
            let destroyed = call.destroyed;
            let mut import_state = call.import;
            let mut header_state = call.header;
            let events_state = call.events;
            let mut batch_state = call.batch;
            let signal = IoSignal::new(pid, target.clone());
            let mut subscriptions = vec![context.readiness.subscribe(&signal)];
            if number == 1 {
                if let Some(close) = context.mapping_close.get() {
                    subscriptions.push(close.subscribe(&signal));
                }
            }
            let deadline = if matches!(number, 4 | 292) {
                if a[1] > a[2] || a[2] > i64::MAX as u64 {
                    return Err(Errno(22));
                }
                let header = header_state
                    .get_or_insert_with(|| Arc::new(Mutex::new(input::Header::default())))
                    .clone();
                let imported = header
                    .lock()
                    .unwrap()
                    .progress(self, number, a, memory, deadline);
                match imported {
                    Ok(Ok(input::Parameters::Ready(deadline))) => deadline,
                    Ok(Ok(input::Parameters::NeedsTask)) => {
                        return Ok(IoAttempt::FileCheckpoint(file::FileCheckpoint::new(
                            file::FileBoundary::Aio(RetainedAio {
                                context,
                                user,
                                destroyed,
                                batch: batch_state,
                                import: import_state,
                                header: header_state,
                                events: events_state,
                                reaped,
                                number,
                                args: a,
                                deadline,
                            }),
                        )))
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(fault) => {
                        subscriptions.extend(fault.wait.subscribe(&signal));
                        return Ok(self.park_aio(
                            RetainedAio {
                                context,
                                user,
                                destroyed,
                                batch: batch_state,
                                import: import_state,
                                header: header_state,
                                events: events_state,
                                reaped,
                                number,
                                args: a,
                                deadline,
                            },
                            signal,
                            subscriptions,
                            target,
                        ));
                    }
                }
            } else {
                None
            };
            if let Some(events) = events_state {
                return Ok(self.aio_events(
                    RetainedAio {
                        context,
                        user,
                        destroyed,
                        batch: batch_state,
                        import: import_state,
                        header: header_state,
                        events: Some(events),
                        reaped,
                        number,
                        args: a,
                        deadline,
                    },
                    memory,
                    signal,
                    subscriptions,
                    target,
                ));
            }
            if number == 2 {
                let import = import_state
                    .get_or_insert_with(|| {
                        Arc::new(Mutex::new(input::Submit::new(context.clone())))
                    })
                    .clone();
                let batch_root = batch_state
                    .get_or_insert_with(|| {
                        Arc::new(Mutex::new(Batch {
                            context: context.clone(),
                            requests: VecDeque::new(),
                            pending: None,
                        }))
                    })
                    .clone();
                'submit: loop {
                    let mut batch = batch_root.lock().unwrap();
                    if batch.requests.is_empty() {
                        if batch.pending.is_none() {
                            let next = import.lock().unwrap().next(self, a, memory, pid, exiting);
                            match next {
                                input::Next::Done(result) => {
                                    drop(batch);
                                    return Ok(IoAttempt::Complete(result));
                                }
                                input::Next::Wait(wait) => {
                                    subscriptions.extend(wait.subscribe(&signal));
                                    drop(batch);
                                    return Ok(self.park_aio(
                                        RetainedAio {
                                            context,
                                            user,
                                            destroyed,
                                            batch: batch_state,
                                            import: import_state,
                                            header: header_state,
                                            events: None,
                                            reaped,
                                            number,
                                            args: a,
                                            deadline,
                                        },
                                        signal,
                                        subscriptions,
                                        target,
                                    ));
                                }
                                input::Next::Ready(request, work) => {
                                    batch.pending = Some((request, work))
                                }
                            }
                        }
                        let (mut request, work) = batch.pending.take().unwrap();
                        if request.asynchronous {
                            match owned::start(self, context.clone(), request, work) {
                                Ok(()) => {
                                    import.lock().unwrap().accepted();
                                    continue 'submit;
                                }
                                Err(original) => {
                                    batch.pending = Some(original);
                                    drop(batch);
                                    return Ok(IoAttempt::FileCheckpoint(
                                        file::FileCheckpoint::new(file::FileBoundary::Aio(
                                            RetainedAio {
                                                context,
                                                user,
                                                destroyed,
                                                batch: batch_state,
                                                import: import_state,
                                                header: header_state,
                                                events: None,
                                                reaped,
                                                number,
                                                args: a,
                                                deadline,
                                            },
                                        )),
                                    ));
                                }
                            }
                        }
                        match work {
                            Work::Disk(work) => {
                                if let Some(executor) = &self.file_executor {
                                    request.result.begin();
                                    executor.submit_file(work, request.result.clone());
                                } else {
                                    request.result.complete(work.run());
                                }
                            }
                            Work::Pipe(fd, command) => request.pipe = Some((fd, command)),
                        }
                        batch.requests.push_back(request);
                    }
                    let mut remaining = batch.requests.len();
                    while remaining != 0 {
                        remaining -= 1;
                        let mut request = batch.requests.pop_front().unwrap();
                        let _resources = request.resources.enter();
                        let completed = if request.copyout.is_some() {
                            None
                        } else if request.layout.is_some() && exiting {
                            // Fatal exit has not started this provider operation.
                            request.layout = None;
                            Some(Err(Errno(4)))
                        } else {
                            let outcome = if let Some(mut layout) = request.layout.take() {
                                let subscription =
                                    layout.ticket.as_ref().unwrap().layout().subscribe(&signal);
                                let exclusive = match layout.ticket.take().unwrap().try_enter() {
                                    Ok(exclusive) => exclusive,
                                    Err(ticket) => {
                                        layout.ticket = Some(ticket);
                                        request.layout = Some(layout);
                                        subscriptions.push(subscription);
                                        batch.requests.push_back(request);
                                        continue;
                                    }
                                };
                                let work = layout.work.enter_layout(exclusive);
                                if let Some(executor) =
                                    self.file_executor.as_ref().filter(|_| work.host_work())
                                {
                                    request.result.begin();
                                    executor.submit_file(work, request.result.clone());
                                    request.result.take()
                                } else {
                                    Some(work.run())
                                }
                            } else if let Some(work) = request.waiting.take() {
                                if exiting {
                                    if let Some(request) = work.fuse_signal_request() {
                                        request.interrupt_fatal();
                                    }
                                }
                                if work.ready() {
                                    if let Some(executor) =
                                        self.file_executor.as_ref().filter(|_| work.host_work())
                                    {
                                        request.result.begin();
                                        executor.submit_file(work, request.result.clone());
                                        request.result.take()
                                    } else {
                                        Some(work.run())
                                    }
                                } else {
                                    subscriptions.extend(
                                        work.wait_sources(&signal)
                                            .map_err(|_| Errno(5))?
                                            .subscriptions,
                                    );
                                    if work.ready() {
                                        remaining += 1;
                                    }
                                    request.waiting = Some(work);
                                    batch.requests.push_back(request);
                                    continue;
                                }
                            } else if let Some((pipe, command)) = &request.pipe {
                                // Subscribe before checking the original pipe. A blocking
                                // endpoint returns the slot while readers/writers progress.
                                subscriptions.extend(pipe.subscribe(&signal));
                                let mut result = {
                                    match command {
                                        trames_vfs::FileCommand::Read { count, .. } => {
                                            pipe.read(*count).map(trames_vfs::FileValue::Bytes)
                                        }
                                        trames_vfs::FileCommand::Write { bytes, .. } => pipe
                                            .write(bytes)
                                            .map(|n| trames_vfs::FileValue::Count(n as u64)),
                                        _ => unreachable!("pipe read/write"),
                                    }
                                };
                                if matches!(result, Err(Errno(11))) && !pipe.nonblocking() {
                                    if exiting {
                                        result = Err(Errno(4));
                                    } else {
                                        batch.requests.push_back(request);
                                        continue;
                                    }
                                }
                                Some(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
                                    resources: Default::default(),
                                    result,
                                    file_size_signal: false,
                                    scratch: None,
                                }))
                            } else {
                                request.result.take()
                            };
                            let Some(outcome) = outcome else {
                                subscriptions.push(request.result.subscribe(&signal));
                                if request.result.ready() {
                                    remaining += 1;
                                }
                                batch.requests.push_back(request);
                                continue;
                            };
                            match outcome {
                                trames_vfs::FileOutcome::Waiting(work) => {
                                    subscriptions.extend(
                                        work.wait_sources(&signal)
                                            .map_err(|_| Errno(5))?
                                            .subscriptions,
                                    );
                                    if work.ready() {
                                        remaining += 1;
                                    }
                                    request.waiting = Some(work);
                                    batch.requests.push_back(request);
                                    continue;
                                }
                                trames_vfs::FileOutcome::Complete(reply) => {
                                    if reply.file_size_signal {
                                        if let Some(task) = &self.task_signal {
                                            task.raise(25);
                                        }
                                    }
                                    request.copyout = Some(
                                        FileCopyout::new(&request.output, reply.result)
                                            .retain(reply.resources),
                                    );
                                    None
                                }
                                trames_vfs::FileOutcome::Layout(work) => {
                                    let fallback = match &self.file_layouts {
                                        Some(layouts) => {
                                            layouts.submit(work, request.result.clone())
                                        }
                                        None => Err(work),
                                    };
                                    if let Err(work) = fallback {
                                        let Some(ticket) = work.begin_layout() else {
                                            request.result.fail(95);
                                            remaining += 1;
                                            batch.requests.push_back(request);
                                            continue;
                                        };
                                        subscriptions.push(ticket.layout().subscribe(&signal));
                                        request.layout = Some(Box::new(LayoutWait {
                                            work,
                                            ticket: Some(ticket),
                                        }));
                                        remaining += 1;
                                    } else {
                                        subscriptions.push(request.result.subscribe(&signal));
                                        if request.result.ready() {
                                            remaining += 1;
                                        }
                                    }
                                    batch.requests.push_back(request);
                                    continue;
                                }
                                trames_vfs::FileOutcome::Owner(_) => Some(Err(Errno(95))),
                            }
                        };
                        let result = if let Some(result) = completed {
                            result
                        } else {
                            match request.copyout.as_mut().unwrap().progress(memory) {
                                Ok(value) => value,
                                Err(fault) => {
                                    if exiting {
                                        request.copyout.as_mut().unwrap().faulted()
                                    } else {
                                        subscriptions.extend(fault.wait.subscribe(&signal));
                                        if fault.wait.ready() {
                                            remaining += 1;
                                        }
                                        batch.requests.push_back(request);
                                        continue;
                                    }
                                }
                            }
                        };
                        context.complete(request, result, Default::default());
                        import.lock().unwrap().accepted();
                    }
                    if batch.requests.is_empty() {
                        drop(batch);
                        continue 'submit;
                    }
                    drop(batch);
                    break 'submit;
                }
            } else if number == 1 {
                let state = context.state.lock().unwrap();
                if state.active.is_empty()
                    && !state.reaping
                    && state.users == 0
                    && context
                        .mapping_close
                        .get()
                        .is_none_or(|close| close.ready())
                {
                    return Ok(IoAttempt::Complete(Ok(0)));
                }
            } else if number == 3 {
                let state = context.state.lock().unwrap();
                return Err(if state.active.contains(&a[1]) {
                    Errno(11)
                } else {
                    Errno(22)
                });
            } else {
                if let Some(events) = events::Events::begin(
                    context.clone(),
                    a[1].saturating_sub(reaped),
                    a[2].saturating_sub(reaped),
                    deadline.is_some_and(|d| Instant::now() >= d),
                )? {
                    return Ok(self.aio_events(
                        RetainedAio {
                            context,
                            user,
                            destroyed,
                            batch: batch_state,
                            import: import_state,
                            header: header_state,
                            events: Some(Arc::new(Mutex::new(events))),
                            reaped,
                            number,
                            args: a,
                            deadline,
                        },
                        memory,
                        signal,
                        subscriptions,
                        target,
                    ));
                }
            }
            Ok(self.park_aio(
                RetainedAio {
                    context,
                    user,
                    destroyed,
                    batch: batch_state,
                    import: import_state,
                    header: header_state,
                    events: None,
                    reaped,
                    number,
                    args: a,
                    deadline,
                },
                signal,
                subscriptions,
                target,
            ))
        })();
        let mut result = result.unwrap_or_else(|e| {
            IoAttempt::Complete(if matches!(number, 4 | 292) && reaped != 0 {
                Ok(reaped)
            } else {
                Err(e)
            })
        });
        if matches!(result, IoAttempt::Complete(_)) {
            if let Some(header) = mask_header {
                let interrupted = header.lock().unwrap().finish(false);
                if interrupted && matches!(result, IoAttempt::Complete(Ok(0))) {
                    result = IoAttempt::Complete(Err(Errno(4)));
                }
            }
            if let Some(user) = user {
                user.release();
            }
        }
        result
    }
    fn park_aio(
        &self,
        call: RetainedAio,
        signal: Arc<IoSignal>,
        subscriptions: Vec<IoSubscription>,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let number = call.number;
        let a = call.args;
        let deadline = if call.events.is_some()
            || matches!(call.number, 4 | 292) && call.context.state.lock().unwrap().reaping
        {
            None
        } else {
            call.deadline
        };
        IoAttempt::Blocked(PendingIo {
            message: None,
            process_vm: None,
            binder: None,
            aio: Some(call),
            number,
            args: a,
            deadline,
            signal,
            flock: None,
            record: None,
            retained_byte: None,
            retained_socket: None,
            native_tcp: None,
            resource_deadline: None,
            retained_poll: None,
            epoll_revision: None,
            terminal_job: false,
            _subscriptions: subscriptions,
            host_subscription: None,
            socket_subscriptions: Vec::new(),
            uring: None,
            poll_uring: None,
            file: None,
            fifo_open: None,
            target: target.clone(),
        })
    }
    fn aio_events(
        &self,
        mut call: RetainedAio,
        memory: &mut impl CpuMemory,
        signal: Arc<IoSignal>,
        mut subscriptions: Vec<IoSubscription>,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let Some(address) = call
            .reaped
            .checked_mul(32)
            .and_then(|offset| call.args[3].checked_add(offset))
        else {
            return IoAttempt::Complete(if call.reaped != 0 {
                Ok(call.reaped)
            } else {
                Err(Errno(14))
            });
        };
        let result = call
            .events
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .progress(memory, address);
        match result {
            Ok(Err(error)) => IoAttempt::Complete(if call.reaped != 0 {
                Ok(call.reaped)
            } else {
                Err(error)
            }),
            Ok(Ok(count)) => {
                call.reaped += count;
                call.events = None;
                if call.context.state.lock().unwrap().dead {
                    return IoAttempt::Complete(if call.reaped != 0 {
                        Ok(call.reaped)
                    } else {
                        Err(Errno(22))
                    });
                }
                if call.reaped >= call.args[1] || call.deadline.is_some_and(|d| Instant::now() >= d)
                {
                    IoAttempt::Complete(Ok(call.reaped))
                } else {
                    self.park_aio(call, signal, subscriptions, target)
                }
            }
            Err(fault) => {
                subscriptions.extend(fault.wait.subscribe(&signal));
                self.park_aio(call, signal, subscriptions, target)
            }
        }
    }
}

impl PendingIo {
    /// The original AIO destroy detached its recorded range before waiting
    /// for users. Retain any resulting VMA close writeback on that same call.
    pub fn retain_aio_mapping_close(&mut self, close: Arc<FileResult>) {
        let context = &self
            .aio
            .as_ref()
            .expect("original AIO mapping destruction")
            .context;
        assert!(
            context.mapping_close.set(close.clone()).is_ok(),
            "one original range unmap"
        );
        let original = context.clone();
        close.on_finished(Box::new(move || original.notify()));
        self._subscriptions.push(close.subscribe(&self.signal));
        if close.ready() {
            self.signal.notify();
        }
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
    fn cancelled_submit_keeps_native_credit_until_completion_without_retired_snapshot_copyout() {
        let mut vfs = trames_vfs::Vfs::default();
        vfs.import_file(b"/original", b"data".to_vec()).unwrap();
        let fd = vfs.open_at(-100, b"/original", 0, 0).unwrap();
        let aio = Aio::default();
        let disk = Arc::new(Disk::default());
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events())
            .with_paths(vfs.path_queries())
            .with_file_executor(disk.clone());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
        let id = memory.read_u64(0x1000).unwrap();
        let context = aio.context(id, &memory).unwrap();
        let mut cb = [0; 64];
        cb[20..24].copy_from_slice(&fd.to_le_bytes());
        cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
        cb[32..40].copy_from_slice(&4u64.to_le_bytes());
        memory.write_array(0x2000, cb).unwrap();
        memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
        let IoAttempt::Blocked(submit) = direct
            .start(2, [id, 1, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
            .unwrap()
        else {
            panic!("native work must park");
        };
        let retired = submit.aio.as_ref().unwrap().clone();
        submit.cancel_copies();
        assert!(context.state.lock().unwrap().active.contains(&0x2000));
        assert_eq!(context.state.lock().unwrap().users, 0);
        let IoAttempt::Blocked(destroy) = direct
            .start(1, [id, 0, 0, 0, 0, 0], &mut memory, 2, &target, None)
            .unwrap()
        else {
            panic!("destroy waits for the original provider");
        };
        disk.complete();
        assert!(context.state.lock().unwrap().active.is_empty());
        assert!(destroy.signal.ready());
        assert_eq!(value(direct.resume(destroy, &mut memory)), Ok(0));
        assert_eq!(
            value(direct.start_retained_aio(retired, &mut memory, 1, &target)),
            Err(Errno(4))
        );
        assert_eq!(memory.read_array::<4>(0x3000).unwrap(), [0; 4]);
        assert_eq!(value(direct.resume(submit, &mut memory)), Err(Errno(4)));
    }

    #[test]
    fn setup_input_fault_preserves_its_read_prefix_and_allocates_only_after_import() {
        let vfs = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x4000, Permissions::RW).unwrap();
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        let IoAttempt::Blocked(wait) = direct
            .start(0, [8, 0x2ffc, 0, 0, 0, 0], &mut memory, 1, &target, None)
            .unwrap()
        else {
            panic!("setup input waits without a context or VMA allocation")
        };
        assert!(aio.0.contexts.lock().unwrap().is_empty());
        memory.write_array(0x2ffc, 7u32.to_le_bytes()).unwrap();
        page.finish();
        assert_eq!(value(direct.resume(wait, &mut memory)), Ok(0));
        assert_eq!(aio.0.contexts.lock().unwrap().len(), 1);
        assert!(aio
            .context(memory.read_u64(0x2ffc).unwrap(), &memory)
            .is_ok());
    }
    #[test]
    fn setup_structural_checkpoint_keeps_the_original_zero_input() {
        let vfs = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x4000, Permissions::RW).unwrap();
        let mut view = memory.parallel_view(&mut Default::default()).unwrap();
        let IoAttempt::FileCheckpoint(checkpoint) = direct
            .start(0, [8, 0x1000, 0, 0, 0, 0], &mut view, 1, &target, None)
            .unwrap()
        else {
            panic!("structural ownership follows pure input import")
        };
        drop(view);
        memory.write_array(0x1000, 7u64.to_le_bytes()).unwrap();
        let file::FileBoundary::AioSetup(call) = checkpoint.take() else {
            panic!("original setup capability")
        };
        assert_eq!(value(call.resume(&direct, &mut memory, 1, &target)), Ok(0));
        assert!(aio
            .context(memory.read_u64(0x1000).unwrap(), &memory)
            .is_ok());
    }
    #[test]
    fn cancel_import_reads_key_before_waiting_for_an_unaccepted_context() {
        let vfs = trames_vfs::Vfs::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(Aio::default(), vfs.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x4000, Permissions::RW).unwrap();
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        memory.write_array(0x2008, 7u32.to_le_bytes()).unwrap();
        assert_eq!(
            value(
                direct
                    .start(
                        3,
                        [0x3000, 0x2000, 0, 0, 0, 0],
                        &mut memory,
                        1,
                        &target,
                        None
                    )
                    .unwrap()
            ),
            Err(Errno(22))
        );
        memory.write_array(0x2008, 0u32.to_le_bytes()).unwrap();
        let IoAttempt::Blocked(wait) = direct
            .start(
                3,
                [0x3000, 0x2000, 0, 0, 0, 0],
                &mut memory,
                1,
                &target,
                None,
            )
            .unwrap()
        else {
            panic!("context get_user waits before EINVAL")
        };
        assert!(wait.aio.is_none(), "lookup has not acquired a context user");
        memory.write_array(0x2008, 7u32.to_le_bytes()).unwrap();
        page.finish();
        assert_eq!(value(direct.resume(wait, &mut memory)), Err(Errno(22)));
    }
    #[test]
    fn destroy_waits_for_the_original_getevents_copy_and_its_context_user() {
        let vfs = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
        let id = memory.read_u64(0x1000).unwrap();
        let context = aio.context(id, &memory).unwrap();
        context.publish(&mut context.state.lock().unwrap(), [9; 32]);
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        let IoAttempt::Blocked(getter) = direct
            .start(4, [id, 1, 1, 0x3000, 0, 0], &mut memory, 1, &target, None)
            .unwrap()
        else {
            panic!("original completion copy waits")
        };
        let retired_snapshot = getter.aio.clone().unwrap();
        assert_eq!(context.state.lock().unwrap().users, 1);
        assert!(!getter.aio.as_ref().unwrap().interruptible());
        let IoAttempt::Blocked(mut destroy) = direct
            .start(1, [id, 0, 0, 0, 0, 0], &mut memory, 2, &target, None)
            .unwrap()
        else {
            panic!("destroy waits after removing its original mapping")
        };
        let close = Arc::new(FileResult::default());
        destroy.retain_aio_mapping_close(close.clone());
        assert!(aio.context(id, &memory).is_err());
        assert!(!destroy.aio.as_ref().unwrap().interruptible());
        page.finish();
        assert_eq!(value(direct.resume(getter, &mut memory)), Ok(1));
        assert_eq!(context.state.lock().unwrap().users, 0);
        let IoAttempt::Blocked(destroy) = direct.resume(destroy, &mut memory) else {
            panic!("destroy retains its detached VMA writeback after the last AIO user")
        };
        close.complete(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
            result: Ok(trames_vfs::FileValue::Count(0)),
            resources: Default::default(),
            file_size_signal: false,
            scratch: None,
        }));
        assert_eq!(value(direct.resume(destroy, &mut memory)), Ok(0));
        drop(retired_snapshot);
        assert_eq!(memory.read_array::<32>(0x3000).unwrap(), [9; 32]);
    }
    #[test]
    fn getevents_interrupt_preserves_its_previously_reaped_count_and_releases_user() {
        let vfs = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x4000, Permissions::RW).unwrap();
        aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
        let id = memory.read_u64(0x1000).unwrap();
        let context = aio.context(id, &memory).unwrap();
        context.publish(&mut context.state.lock().unwrap(), [4; 32]);
        let IoAttempt::Blocked(wait) = direct
            .start(4, [id, 2, 2, 0x2000, 0, 0], &mut memory, 1, &target, None)
            .unwrap()
        else {
            panic!("a partial batch waits for its remaining minimum")
        };
        assert!(wait.aio.as_ref().unwrap().interruptible());
        assert_eq!(wait.aio.as_ref().unwrap().interrupted(), Ok(1));
        assert_eq!(context.head(), 1);
        drop(wait);
        assert_eq!(context.state.lock().unwrap().users, 0);
    }
    #[test]
    fn cq_copy_failure_keeps_the_whole_batch_and_releases_the_original_reader() {
        let aio = Aio::default();
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
        let context = aio
            .context(memory.read_u64(0x1000).unwrap(), &memory)
            .unwrap();
        {
            let mut state = context.state.lock().unwrap();
            context.publish(&mut state, [1; 32]);
            context.publish(&mut state, [2; 32]);
        }
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let _page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        let mut accepted = events::Events::begin(context.clone(), 2, 2, false)
            .unwrap()
            .unwrap();
        assert!(accepted.progress(&mut memory, 0x2fe0).is_err());
        assert_eq!(memory.read_array::<32>(0x2fe0).unwrap(), [1; 32]);
        assert!(events::Events::begin(context.clone(), 0, 2, true)
            .unwrap()
            .is_none());
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        assert_eq!(accepted.progress(&mut memory, 0x2fe0), Ok(Err(Errno(14))));
        assert_eq!(context.head(), 0);
        let mut next = events::Events::begin(context.clone(), 1, 2, false)
            .unwrap()
            .unwrap();
        assert_eq!(next.progress(&mut memory, 0x4000), Ok(Ok(2)));
        assert_eq!(memory.read_array::<32>(0x4000).unwrap(), [1; 32]);
        assert_eq!(memory.read_array::<32>(0x4020).unwrap(), [2; 32]);
        drop(accepted);
        assert_eq!(
            context.head(),
            2,
            "old completion cannot roll back a later consumer"
        );
    }
    #[test]
    fn cq_copy_wait_preserves_its_already_copied_record_prefix() {
        let aio = Aio::default();
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
        let context = aio
            .context(memory.read_u64(0x1000).unwrap(), &memory)
            .unwrap();
        context.publish(&mut context.state.lock().unwrap(), [42; 32]);
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        let mut events = events::Events::begin(context.clone(), 1, 1, false)
            .unwrap()
            .unwrap();
        assert!(events.progress(&mut memory, 0x2ff8).is_err());
        assert_eq!(context.head(), 0);
        memory.write(0x2ff8, b"KEEPKEEP").unwrap();
        page.finish();
        assert_eq!(events.progress(&mut memory, 0x2ff8), Ok(Ok(1)));
        assert_eq!(memory.read_array::<8>(0x2ff8).unwrap(), *b"KEEPKEEP");
        assert_eq!(memory.read_array::<24>(0x3000).unwrap(), [42; 24]);
        assert_eq!(context.head(), 1);
    }
    #[test]
    fn getevents_keeps_an_earlier_successful_batch_when_a_later_batch_copy_fails() {
        let vfs = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        aio.setup([8, 0x1000, 0, 0, 0, 0], &mut memory).unwrap();
        let id = memory.read_u64(0x1000).unwrap();
        let context = aio.context(id, &memory).unwrap();
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let _page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        context.publish(&mut context.state.lock().unwrap(), [1; 32]);
        let IoAttempt::Blocked(wait) = direct
            .start(4, [id, 2, 2, 0x2fe0, 0, 0], &mut memory, 1, &target, None)
            .unwrap()
        else {
            panic!("one successful batch remains below min_nr")
        };
        assert_eq!(context.head(), 1);
        context.publish(&mut context.state.lock().unwrap(), [2; 32]);
        let IoAttempt::Blocked(wait) = direct.resume(wait, &mut memory) else {
            panic!("second batch copy waits")
        };
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        assert_eq!(value(direct.resume(wait, &mut memory)), Ok(1));
        assert_eq!(context.head(), 1);
        assert_eq!(
            context.pending(context.head(), context.state.lock().unwrap().tail),
            1
        );
        assert_eq!(memory.read_array::<32>(0x2fe0).unwrap(), [1; 32]);
    }
    #[test]
    fn submit_input_fault_retains_original_iocb_file_and_payload_before_dispatch() {
        let mut vfs = trames_vfs::Vfs::default();
        vfs.import_file(b"/old", Vec::new()).unwrap();
        vfs.import_file(b"/new", Vec::new()).unwrap();
        let file = vfs.open_at(-100, b"/old", 2, 0).unwrap();
        let aio = Aio::default();
        let disk = Arc::new(Disk::default());
        let direct = DirectSyscalls::new(vfs.direct_descriptors())
            .with_aio(aio.clone(), vfs.native_events())
            .with_paths(vfs.path_queries())
            .with_resources(vfs.descriptor_factory())
            .with_file_executor(disk.clone());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
        assert_eq!(
            value(
                direct
                    .start(0, [8, 0x1000, 0, 0, 0, 0], &mut memory, 1, &target, None)
                    .unwrap()
            ),
            Ok(0)
        );
        let context = memory.read_u64(0x1000).unwrap();
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        let mut cb = [0; 64];
        cb[..8].copy_from_slice(&123u64.to_le_bytes());
        cb[8..12].copy_from_slice(&0xaabbccddu32.to_le_bytes());
        cb[16..18].copy_from_slice(&1u16.to_le_bytes());
        cb[20..24].copy_from_slice(&file.to_le_bytes());
        cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
        cb[32..40].copy_from_slice(&7u64.to_le_bytes());
        memory.write_array(0x2000, cb).unwrap();
        memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
        let IoAttempt::Blocked(wait) = direct
            .start(
                2,
                [context, 1, 0x1800, 0, 0, 0],
                &mut memory,
                1,
                &target,
                None,
            )
            .unwrap()
        else {
            panic!("payload import returns the source slot")
        };
        assert!(
            disk.0.lock().unwrap().is_empty(),
            "no provider has seen an incomplete import"
        );
        assert_eq!(
            memory.read_array::<4>(0x2008).unwrap(),
            [0; 4],
            "Linux writes aio_key before importing payload bytes"
        );
        vfs.close(file).unwrap();
        assert_eq!(vfs.open_at(-100, b"/new", 2, 0).unwrap(), file);
        memory.write_array(0x2018, 0x4000u64.to_le_bytes()).unwrap();
        memory.write(0x4000, b"mutated").unwrap();
        page.finish();
        memory.write(0x3000, b"written").unwrap();
        let IoAttempt::Blocked(wait) = direct.resume(wait, &mut memory) else {
            panic!("original native work")
        };
        assert_eq!(disk.0.lock().unwrap().len(), 1);
        disk.complete();
        assert_eq!(value(direct.resume(wait, &mut memory)), Ok(1));
        assert_eq!(memory.read_array::<4>(0x2008).unwrap(), [0; 4]);
        let original = vfs.open_at(-100, b"/old", 0, 0).unwrap();
        assert_eq!(vfs.read(original, 7).unwrap(), b"written");
        assert_eq!(vfs.pread(file, 7, 0).unwrap(), b"");
        let context = aio.context(context, &memory).unwrap();
        assert!(context.state.lock().unwrap().active.is_empty());
        assert_eq!(context.state.lock().unwrap().tail, 1);
    }
    #[test]
    fn accepted_aio_bytes_wait_for_the_destination_before_cq_and_eventfd_publication() {
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/data", b"payload".to_vec()).unwrap();
        let fd = v.open_at(-100, b"/data", 0, 0).unwrap();
        let event = v.eventfd(0, 0).unwrap();
        let aio = Aio::default();
        let disk = Arc::new(Disk::default());
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_aio(aio.clone(), v.native_events())
            .with_paths(v.path_queries())
            .with_file_executor(disk.clone());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x5000, Permissions::RW).unwrap();
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
        let IoAttempt::Blocked(pending) = direct
            .start(
                2,
                [context, 1, 0x1800, 0, 0, 0],
                &mut memory,
                1,
                &target,
                None,
            )
            .unwrap()
        else {
            panic!("accepted disk request")
        };
        // The IO was accepted against the original buffer. Its later copyout
        // must fault in the new destination without resubmitting that read.
        memory.unmap(0x3000, trames_memory::PAGE_SIZE).unwrap();
        let page = crate::direct::file::copyout_tests::install(&mut memory, 0x3000);
        disk.complete();
        let IoAttempt::Blocked(pending) = direct.resume(pending, &mut memory) else {
            panic!("original bytes await destination")
        };
        assert_eq!(v.read(event, 8), Err(Errno(11)));
        assert_eq!(
            aio.context(context, &memory)
                .unwrap()
                .state
                .lock()
                .unwrap()
                .tail,
            0
        );
        assert!(disk.0.lock().unwrap().is_empty(), "no second disk job");
        page.finish();
        assert!(pending.signal.ready());
        assert_eq!(value(direct.resume(pending, &mut memory)), Ok(1));
        assert_eq!(memory.read_array::<7>(0x3000).unwrap(), *b"payload");
        assert_eq!(v.read(event, 8).unwrap(), 1u64.to_le_bytes());
        assert_eq!(
            aio.context(context, &memory)
                .unwrap()
                .state
                .lock()
                .unwrap()
                .tail,
            1
        );
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
        assert!(aio.fork().context(context, &memory).is_err());
        assert!(aio.clone().context(context, &memory).is_ok());
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
        assert!(aio.context(context, &memory).is_err());
    }
    #[test]
    fn large_submit_keeps_only_one_buffered_request_live_without_an_artificial_batch_prefix() {
        let mut v = trames_vfs::Vfs::default();
        v.import_file(b"/data", vec![0; 512 * 1024]).unwrap();
        let fd = v.open_at(trames_vfs::AT_FDCWD, b"/data", 0, 0).unwrap();
        let aio = Aio::default();
        let mut memory = Memory::default();
        memory.map(0x1000, 0x83000, Permissions::RW).unwrap();
        let disk = Arc::new(Disk::default());
        let direct = DirectSyscalls::new(v.direct_descriptors())
            .with_aio(aio, v.native_events())
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
        for i in 0..3 {
            let mut cb = [0; 64];
            cb[20..24].copy_from_slice(&fd.to_le_bytes());
            cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
            cb[32..40].copy_from_slice(&(512u64 * 1024).to_le_bytes());
            memory.write_array(0x1800 + i * 64, cb).unwrap();
            memory
                .write_array(0x1400 + i * 8, (0x1800 + i * 64).to_le_bytes())
                .unwrap();
        }
        let mut wait = match direct
            .start(
                2,
                [context, 3, 0x1400, 0, 0, 0],
                &mut memory,
                1,
                &target,
                None,
            )
            .unwrap()
        {
            IoAttempt::Blocked(p) => p,
            _ => panic!("disk batch must park"),
        };
        for index in 0..3 {
            assert_eq!(
                disk.0.lock().unwrap().len(),
                1,
                "only the current buffered request owns staging"
            );
            disk.complete();
            let attempt = direct.resume(wait, &mut memory);
            if index == 2 {
                assert_eq!(value(attempt), Ok(3));
                break;
            }
            let IoAttempt::Blocked(next) = attempt else {
                panic!("next original buffered request");
            };
            wait = next;
        }
        assert_eq!(
            value(
                direct
                    .start(
                        4,
                        [context, 3, 3, 0x2000, 0, 0],
                        &mut memory,
                        1,
                        &target,
                        None
                    )
                    .unwrap()
            ),
            Ok(3)
        );
    }

    #[test]
    fn destroy_waits_for_blocked_pipe_and_unmaps_replaced_pages_in_its_recorded_range() {
        let mut v = trames_vfs::Vfs::default();
        let [reader, writer] = v.pipe(0).unwrap();
        let aio = Aio::default();
        let direct =
            DirectSyscalls::new(v.direct_descriptors()).with_aio(aio.clone(), v.native_events());
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let target = Arc::downgrade(&wake);
        let mut memory = Memory::default();
        memory.map(0x1000, 0x4000, Permissions::RW).unwrap();
        let setup = [128, 0x1000, 0, 0, 0, 0];
        aio.setup(setup, &mut memory).unwrap();
        let id = u64::from_le_bytes(memory.read_array(0x1000).unwrap());
        memory.map_fixed(id + 4096, 4096, Permissions::RW).unwrap();
        memory.write_array(id + 4096, *b"keep").unwrap();

        let mut cb = [0; 64];
        cb[20..24].copy_from_slice(&reader.to_le_bytes());
        cb[24..32].copy_from_slice(&0x3000u64.to_le_bytes());
        cb[32..40].copy_from_slice(&1u64.to_le_bytes());
        memory.write_array(0x2000, cb).unwrap();
        memory.write_array(0x1800, 0x2000u64.to_le_bytes()).unwrap();
        let IoAttempt::Blocked(submit) = direct
            .start(2, [id, 1, 0x1800, 0, 0, 0], &mut memory, 1, &target, None)
            .unwrap()
        else {
            panic!("empty pipe must park");
        };
        let IoAttempt::Blocked(destroy) = direct
            .start(1, [id, 0, 0, 0, 0, 0], &mut memory, 2, &target, None)
            .unwrap()
        else {
            panic!("destroy must wait for accepted copyout");
        };
        assert!(submit.signal.ready());
        assert!(aio.context(id, &memory).is_err());
        assert!(memory.read_array::<4>(id + 4096).is_err());
        let IoAttempt::Blocked(submit) = direct.resume(submit, &mut memory) else {
            panic!("detaching the context does not cancel an accepted blocking read");
        };
        assert_eq!(v.write(writer, b"X"), Ok(1));
        assert_eq!(value(direct.resume(submit, &mut memory)), Ok(1));
        assert_eq!(memory.read_array::<1>(0x3000).unwrap(), *b"X");
        assert!(destroy.signal.ready());
        assert_eq!(value(direct.resume(destroy, &mut memory)), Ok(0));
    }

    #[test]
    fn parked_getevents_retains_destroyed_context_across_numeric_reuse() {
        let v = trames_vfs::Vfs::default();
        let aio = Aio::default();
        let mut memory = Memory::default();
        memory.map(0x1000, 0x3000, Permissions::RW).unwrap();
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
        let stale = wait.aio.clone().unwrap();
        let IoAttempt::Blocked(destroy) = direct
            .start(1, [id, 0, 0, 0, 0, 0], &mut memory, 2, &target, None)
            .unwrap()
        else {
            panic!("the original getevents user must return before destroy")
        };
        assert_eq!(value(direct.resume(wait, &mut memory)), Err(Errno(22)));
        assert_eq!(value(direct.resume(destroy, &mut memory)), Ok(0));
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
        assert_eq!(
            value(direct.start_retained_aio(stale, &mut memory, 1, &target)),
            Err(Errno(22))
        );
        assert!(aio.context(id, &memory).is_ok());
    }
}
