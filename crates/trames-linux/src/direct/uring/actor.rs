// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-task execution ownership. Rings contain weak cleanup tokens, never
//! a task, Files root or path island. No resource service thread is involved.
use super::*;
#[path = "actor_byte.rs"]
mod byte;
#[path = "actor_file.rs"]
mod file;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
#[path = "scope.rs"]
mod scope;
pub(crate) use scope::Scope;
type Key = (usize, u64);
fn retained(request: &Request) -> bool {
    request.file.as_ref().is_some_and(|file| {
        if matches!(request.sqe.opcode(), 1 | 2 | 3 | 4 | 5 | 17 | 22 | 23 | 55) {
            file.file_target().is_none()
        } else {
            file.shared_file().is_none()
        }
    })
}
pub(crate) struct Execution {
    paths: Mutex<trames_vfs::PathQueries>,
    factory: trames_vfs::DescriptorFactory,
    files: trames_vfs::DirectFiles,
    descriptors: trames_vfs::DirectFds,
    disk: Option<Arc<dyn FileExecutor>>,
    layouts: Option<Arc<crate::FileLayouts>>,
    signal: Option<Arc<dyn trames_vfs::TaskSignal>>,
}
struct Accepted {
    import: Option<crate::uring::input::Pending>,
    page: Option<Arc<trames_memory::PageWait>>,
    input: Option<Box<file_input::Bytes>>,
    fifo_open: Option<trames_vfs::FifoOpen>,
    context: Arc<Execution>,
    owner: u64,
    task: u32,
    retained: bool,
    socket: Option<socket_wait::RetainedSocket>,
    file: Option<file::FileIo>,
    byte: Option<byte::ByteIo>,
}
#[derive(Default)]
pub struct UringActor {
    rings: Mutex<BTreeMap<usize, Weak<Uring>>>,
    scopes: scope::Scopes,
    accepted: Mutex<BTreeMap<Key, Accepted>>,
    file_size_signal: AtomicBool,
}
impl trames_vfs::UringSource for UringActor {}
struct Lease {
    actor: Weak<UringActor>,
    key: Key,
}
impl trames_vfs::UringExecutionLease for Lease {}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(actor) = self.actor.upgrade() {
            let retired = actor.accepted.lock().unwrap().remove(&self.key);
            drop(retired); // Native close/namespace callbacks run unlocked.
        }
    }
}
impl Execution {
    pub(crate) fn new(
        paths: &trames_vfs::PathQueries,
        factory: &trames_vfs::DescriptorFactory,
        files: &trames_vfs::DirectFiles,
        descriptors: trames_vfs::DirectFds,
        disk: Option<Arc<dyn FileExecutor>>,
        layouts: Option<Arc<crate::FileLayouts>>,
        signal: Option<Arc<dyn trames_vfs::TaskSignal>>,
    ) -> Self {
        Self {
            paths: Mutex::new(paths.retain_context()),
            factory: factory.clone(),
            files: files.clone(),
            descriptors,
            disk,
            layouts,
            signal,
        }
    }
    fn run(
        &self,
        call: &mut Accepted,
        request: &mut Request,
        memory: &mut impl CpuMemory,
        actor: &UringActor,
        ring: &Uring,
    ) -> Option<Result<(i32, bool)>> {
        if call.import.is_some() {
            return self.import(call, request, memory, actor, ring);
        }
        if call.page.as_ref().is_some_and(|page| !page.ready()) {
            return Some(Err(Errno(11)));
        }
        call.page = None;
        let mut signal = false;
        let byte_copy = memory.async_faults_possible()
            && request.buffer.is_none()
            && matches!(request.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23 | 26 | 27);
        let result = if call.retained
            && !byte_copy
            && !matches!(request.sqe.opcode(), 18 | 19 | 21 | 28 | 45)
        {
            if matches!(request.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23)
                && request.file.as_ref().is_some_and(|file| file.is_signalfd())
            {
                byte::signal(request, memory)
            } else {
                self.paths.lock().unwrap().uring_query(|vfs| {
                    let result = crate::uring::execute::retained(vfs, request, memory, None);
                    signal = vfs.take_file_size_signal();
                    result
                })
            }
        } else {
            self.run_shared(call, request, memory, actor, ring)
        };
        if signal {
            self.raise_file_size(actor);
        }
        if result.is_some() {
            return result;
        }
        // A shared body's None is a before-effect admission miss. Native file
        // jobs/layouts always retain FileIo and return their original wait.
        // The sealed original context is independent of the current observer.
        let (result, signal) = self
            .paths
            .lock()
            .unwrap()
            .uring_original(Some(&self.descriptors), |vfs| {
                crate::uring::execute::retained(vfs, request, memory, None)
            });
        if signal {
            self.raise_file_size(actor);
        }
        result
    }
    fn raise_file_size(&self, actor: &UringActor) {
        if let Some(task) = &self.signal {
            task.raise(25);
        } else {
            actor.file_size_signal.store(true, Ordering::Relaxed);
        }
    }
    fn import(
        &self,
        call: &mut Accepted,
        request: &mut Request,
        memory: &impl CpuMemory,
        actor: &UringActor,
        ring: &Uring,
    ) -> Option<Result<(i32, bool)>> {
        let mut import = call.import.take().unwrap();
        if !import.wait.ready() {
            call.page = Some(import.wait.clone());
            call.import = Some(import);
            return Some(Err(Errno(11)));
        }
        let parsed = import
            .replay(request, ring, memory, |fd| {
                Some(self.factory.files().uring_file(fd))
            })
            .expect("original source Files authority");
        let Some(mut parsed) = parsed else {
            call.page = Some(import.wait.clone());
            call.import = Some(import);
            return Some(Err(Errno(11)));
        };
        if let Some(original) = &request.file {
            parsed.file = Some(original.clone());
            parsed.resource = request.resource.take();
        } else if let Some(file) = parsed.file.take() {
            let original = actor
                .rings
                .lock()
                .unwrap()
                .get(&(ring as *const Uring as usize))
                .and_then(Weak::upgrade);
            let Some(original) = original else {
                return Some(Err(Errno(9)));
            };
            let (bound, retired) = original.bind_file_deferred(&file);
            drop(retired);
            match bound {
                Ok(file) => {
                    parsed.resource = file
                        .shared_file()
                        .and_then(|file| self.descriptors.byte_file(file))
                        .map(|fd| Resource {
                            object: Object::Byte(fd),
                            identity: file.identity(),
                        })
                        .or_else(|| Resource::capture(&file));
                    parsed.file = Some(file);
                }
                Err(error) => parsed.error = Some(error),
            }
        }
        parsed.owner = request.owner;
        parsed.execution = request.execution.take();
        parsed.source = request.source.take();
        call.retained = retained(&parsed);
        call.page = None;
        let result = parsed.error.unwrap_or(Errno(11));
        *request = parsed;
        // Re-enter the ordinary metadata/operation dispatcher once, after this
        // pure import. No ready page subscription is retained as a polling loop.
        Some(Err(result))
    }
    fn run_shared(
        &self,
        call: &mut Accepted,
        request: &mut Request,
        memory: &mut impl CpuMemory,
        actor: &UringActor,
        ring: &Uring,
    ) -> Option<Result<(i32, bool)>> {
        let s = &request.sqe;
        Some(match s.opcode() {
            1 | 2 | 3 | 4 | 5 | 17 | 22 | 23 | 55 => {
                if memory.async_faults_possible()
                    && request.buffer.is_none()
                    && matches!(s.opcode(), 1 | 2 | 4 | 5 | 22 | 23)
                    && request.file.as_ref()?.file_target().is_none()
                {
                    return byte::execute(self, call, request, memory);
                }
                return file::execute(self, call, request, memory, actor, ring);
            }
            6 => {
                if s.length() & !9 != 0
                    || s.length() & 8 != 0 && !s.multishot()
                    || s.op_flags() & !trames_vfs::poll_mask::SUPPORTED != 0
                {
                    return Some(Err(Errno(22)));
                }
                let file = request.file.as_ref()?;
                let (events, epoch) = if file.is_signalfd() {
                    let Object::Byte(fd) = &request.resource.as_ref()?.object else {
                        return None;
                    };
                    fd.poll_state(s.op_flags() as u16)?
                } else {
                    file.readiness(s.op_flags() as u16)
                };
                let fresh = !s.multishot()
                    || s.length() & 8 != 0
                    || trames_vfs::poll_mask::new_edges(
                        events,
                        request.poll_ready,
                        epoch,
                        request.poll_epoch,
                    ) != 0;
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
            18 | 28 => {
                let (flags, mode, policy) = request.how.unwrap_or((s.op_flags(), s.length(), 0));
                if s.opcode() == 28 && s.op_flags() != 0 {
                    return Some(Err(Errno(22)));
                }
                return file::open(self, call, request, memory, actor, flags, mode, policy);
            }
            19 => {
                if s.op_flags() != 0 || s.length() != 0 {
                    Err(Errno(22))
                } else if self.factory.files().uring(s.fd() as u32).is_ok() {
                    Err(Errno(9))
                } else {
                    self.factory
                        .files()
                        .close(s.fd() as u32, self.factory.local_peer_identity()[0])?
                        .map(|()| (0, true))
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
                if s.op_flags() & !0x7900 != 0
                    || s.op_flags() & 0x6000 == 0x6000
                    || s.length() & 0x8000_0000 != 0
                {
                    return Some(Err(Errno(22)));
                }
                if let Err(e) = Linux::check(memory, s.offset(), 256, Access::Write) {
                    return Some(Err(e));
                }
                self.paths
                    .lock()
                    .unwrap()
                    .uring_statx(
                        request.file.as_ref(),
                        s.fd(),
                        request.path.as_deref()?,
                        s.op_flags(),
                    )?
                    .and_then(|(stat, mount)| Linux::finish_statx(a, memory, stat, mount))
                    .map(|n| (n as i32, true))
            }
            45 => {
                if s.op_flags() & !(trames_vfs::O_CLOEXEC | trames_vfs::O_NONBLOCK) != 0
                    || s.address() != 0
                    || s.offset() > u32::MAX as u64
                {
                    Err(Errno(22))
                } else {
                    self.factory
                        .socket(s.fd() as u32, s.offset() as u32 | s.op_flags(), s.length())
                        .map(|fd| (fd as i32, true))
                }
            }
            13 | 16 | 26 | 27 | 34 | 56 | 57 => {
                if call.socket.is_none() {
                    match socket_wait::RetainedSocket::uring(&self.factory, request, memory)? {
                        Ok(socket) => call.socket = Some(socket),
                        Err(e) => return Some(Err(e)),
                    }
                }
                let socket = call.socket.as_mut().unwrap();
                let result =
                    if matches!(s.opcode(), 16 | 56) && request.file.as_ref()?.socket().is_none() {
                        socket.uring_attempt(memory, Some(&*self.paths.lock().unwrap()))
                    } else {
                        socket.uring_attempt(memory, None)
                    };
                let result = match result {
                    Some(result) => result,
                    None if memory.async_faults_possible() && matches!(s.opcode(), 26 | 27) => {
                        return byte::network(self, call, request, memory)
                    }
                    None => return None,
                };
                if let Some(fault) = socket.take_fault() {
                    call.page = Some(fault.wait);
                    return Some(Err(Errno(11)));
                }
                result.map(|n| {
                    (
                        n as i32,
                        !matches!(s.opcode(), 26 | 27) || n == request.requested,
                    )
                })
            }
            _ => return None,
        })
    }
}
impl UringActor {
    /// Cancel the original submitter's requests without a VFS/Memory owner.
    /// Accepted native jobs retain their own staging; CQ and endpoint callbacks
    /// run only after the original ring lock has been released.
    pub fn cancel_task(&self, owner: u64, task: u32) {
        let scope = self.scope(owner, task).map(|scope| {
            let revision = scope.revision();
            (scope, revision)
        });
        Self::cancel_task_rings(self.rings(), owner, task);
        if let Some((scope, revision)) = scope {
            self.finish_scope(&scope, revision);
        }
    }
    pub(crate) fn cancel_task_rings(rings: Vec<Arc<Uring>>, owner: u64, task: u32) {
        for ring in rings {
            let mut retired = Vec::new();
            let mut state = ring.state.lock().unwrap();
            let mut pending = std::mem::take(&mut state.pending);
            while let Some(request) = pending.pop_front() {
                if request.owner == owner && request.task == task {
                    Linux::complete_request(&mut state, &request, -125, false);
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
    }
    pub(crate) fn take_file_size_signal(&self) -> bool {
        self.file_size_signal.load(Ordering::Relaxed)
            && self.file_size_signal.swap(false, Ordering::Relaxed)
    }
    pub(crate) fn pending_disk(&self, owner: u64, task: u32) -> bool {
        self.accepted.lock().unwrap().values().any(|call| {
            call.owner == owner
                && call.task == task
                && (call.page.is_some()
                    || call.file.as_ref().is_some_and(file::FileIo::pending_native))
        })
    }

    pub(crate) fn event_wait(&self, owner: u64, task: u32) -> bool {
        if self.pending_disk(owner, task) {
            return true;
        }
        self.rings().iter().any(|ring| {
            if ring.request_deadline(owner, task).is_some() {
                return true;
            }
            let files: Vec<_> = {
                let state = ring.state.lock().unwrap();
                state
                    .pending
                    .iter()
                    .filter(|r| {
                        r.owner == owner && r.task == task && r.started && ring.waitable(&state, r)
                    })
                    .filter_map(|r| r.file.clone())
                    .collect()
            };
            files.iter().any(|file| !file.native_wait_fds().is_empty())
        })
    }
    pub(crate) fn track(self: &Arc<Self>, ring: &Arc<Uring>, owner: u64, task: u32) {
        self.rings
            .lock()
            .unwrap()
            .insert(Arc::as_ptr(ring) as usize, Arc::downgrade(ring));
        self.activate(owner, task);
    }
    pub(crate) fn accept(
        self: &Arc<Self>,
        ring: &Arc<Uring>,
        request: &mut Request,
        context: Arc<Execution>,
    ) {
        self.accept_import(ring, request, context, None);
    }
    pub(crate) fn accept_import(
        self: &Arc<Self>,
        ring: &Arc<Uring>,
        request: &mut Request,
        context: Arc<Execution>,
        mut import: Option<crate::uring::input::Pending>,
    ) {
        self.bind_source(request);
        if let Some(import) = &mut import {
            import.bind(request);
        }
        if request.resource.is_none() {
            // Reader/task-sensitive byte resources belong to the submitter,
            // including requests imported before its first worker capture.
            // A later CQ observer cannot supply its own reader or re-resolve FD.
            request.resource = request.file.as_ref().and_then(|file| {
                file.shared_file()
                    .and_then(|file| context.descriptors.byte_file(file))
                    .map(|fd| Resource {
                        object: Object::Byte(fd),
                        identity: file.identity(),
                    })
                    .or_else(|| Resource::capture(file))
            });
        }
        let key = (Arc::as_ptr(ring) as usize, request.sequence);
        self.rings
            .lock()
            .unwrap()
            .insert(key.0, Arc::downgrade(ring));
        // Decide original body admission once, not on every retry/byte copy.
        let retained = retained(request);
        self.accepted.lock().unwrap().insert(
            key,
            Accepted {
                page: import.as_ref().map(|import| import.wait.clone()),
                import,
                input: None,
                context,
                owner: request.owner,
                task: request.task,
                retained,
                socket: None,
                file: None,
                byte: None,
                fifo_open: None,
            },
        );
        request.execution = Some(Arc::new(Lease {
            actor: Arc::downgrade(self),
            key,
        }));
    }
    pub(crate) fn execute(
        &self,
        ring: &Uring,
        request: &mut Request,
        memory: &mut impl CpuMemory,
        selected: Option<trames_vfs::UringProvidedBuffer>,
    ) -> Option<Result<(i32, bool)>> {
        if request.execution.is_some() {
            if let Some(source) = &request.source {
                if !std::ptr::addr_eq(source.as_ptr(), self as *const Self) {
                    let Some(source) = source.upgrade() else {
                        return Some(Err(Errno(125)));
                    };
                    let source: Arc<dyn std::any::Any + Send + Sync> = source;
                    let source = Arc::downcast::<Self>(source).ok()?;
                    return source.execute_original(ring, request, memory, selected);
                }
            }
        }
        self.execute_original(ring, request, memory, selected)
    }
    pub(super) fn bind_source(self: &Arc<Self>, request: &mut Request) {
        request.source = Some(Arc::downgrade(
            &(self.clone() as Arc<dyn trames_vfs::UringSource>),
        ));
    }
    fn execute_original(
        &self,
        ring: &Uring,
        request: &mut Request,
        memory: &mut impl CpuMemory,
        selected: Option<trames_vfs::UringProvidedBuffer>,
    ) -> Option<Result<(i32, bool)>> {
        let key = (ring as *const Uring as usize, request.sequence);
        let mut call = self.accepted.lock().unwrap().remove(&key)?;
        let before = (
            call.import.is_some(),
            call.page.as_ref().map(|page| Arc::as_ptr(page) as usize),
            call.socket.as_ref().map(|s| s.uring_wait_kind()),
            call.file.as_ref().map(|f| f.wait_revision),
        );
        let original = request;
        let mut selected_view;
        let request = if let Some(buffer) = selected {
            selected_view = original.clone();
            let length = if original.sqe.opcode() == 27 && original.sqe.length() == 0 {
                buffer.length
            } else {
                buffer.length.min(original.sqe.length())
            };
            selected_view.sqe.0[16..24].copy_from_slice(&buffer.address.to_le_bytes());
            selected_view.sqe.0[24..28].copy_from_slice(&length.to_le_bytes());
            selected_view.requested = length as u64;
            &mut selected_view
        } else {
            &mut *original
        };
        let was_importing = request.import_pending;
        let result = call
            .context
            .clone()
            .run(&mut call, request, memory, self, ring);
        let copy_pending = call.page.is_some()
            || call.file.as_ref().is_some_and(file::FileIo::pending_copy)
            || was_importing && !request.import_pending;
        if copy_pending && request.selection.is_none() {
            if let Some(buffer) = selected {
                file::retain_selection(self, ring, request, buffer);
            }
        }
        let selection = request.selection.clone();
        if request.sqe.multishot()
            && matches!(request.sqe.opcode(), 26 | 27)
            && matches!(result, Some(Ok(_)))
        {
            call.socket = None;
            call.byte = None;
        }
        let changed = before
            != (
                call.import.is_some(),
                call.page.as_ref().map(|page| Arc::as_ptr(page) as usize),
                call.socket.as_ref().map(|s| s.uring_wait_kind()),
                call.file.as_ref().map(|f| f.wait_revision),
            );
        original.selection = selection;
        original.copy_pending = copy_pending;
        self.accepted.lock().unwrap().insert(key, call);
        if changed {
            ring.readiness.notify_locked();
        }
        result
    }
    pub(super) fn subscribe(
        &self,
        ring: &Uring,
        sequence: u64,
        signal: &Arc<IoSignal>,
    ) -> Option<Vec<trames_vfs::IoSubscription>> {
        let socket = {
            let accepted = self.accepted.lock().unwrap();
            let call = accepted.get(&(ring as *const Uring as usize, sequence))?;
            if let Some(page) = &call.page {
                return Some(vec![page.subscribe(signal)]);
            }
            if let Some(open) = &call.fifo_open {
                return Some(vec![open.subscribe(signal)]);
            }
            if let Some(file) = &call.file {
                return Some(file.subscribe(signal));
            }
            call.socket.clone()
        };
        socket?.uring_subscribe(signal).map(|s| vec![s])
    }
    pub(crate) fn rings(&self) -> Vec<Arc<Uring>> {
        let mut rings = self.rings.lock().unwrap();
        let mut live = Vec::new();
        rings.retain(|_, ring| {
            if let Some(ring) = ring.upgrade() {
                live.push(ring);
                true
            } else {
                false
            }
        });
        live
    }
}
