// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-task execution ownership. Rings contain weak cleanup tokens, never
//! a task, Files root or path island. No resource service thread is involved.
use super::*;
#[path = "actor_file.rs"]
mod file;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};
type Key = (usize, u64);
pub(crate) struct Execution {
    paths: Mutex<trames_vfs::PathQueries>,
    factory: trames_vfs::DescriptorFactory,
    files: trames_vfs::DirectFiles,
    disk: Option<Arc<dyn FileExecutor>>,
    layouts: Option<Arc<crate::FileLayouts>>,
    signal: Option<Arc<dyn trames_vfs::TaskSignal>>,
}
struct Accepted {
    context: Arc<Execution>,
    retained: bool,
    socket: Option<socket_wait::RetainedSocket>,
    file: Option<file::FileIo>,
}
#[derive(Default)]
pub struct UringActor {
    rings: Mutex<BTreeMap<usize, Weak<Uring>>>,
    active: AtomicBool,
    owner_required: AtomicBool,
    revision: AtomicU64,
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
        disk: Option<Arc<dyn FileExecutor>>,
        layouts: Option<Arc<crate::FileLayouts>>,
        signal: Option<Arc<dyn trames_vfs::TaskSignal>>,
    ) -> Self {
        Self {
            paths: Mutex::new(paths.retain_context()),
            factory: factory.clone(),
            files: files.clone(),
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
        if call.retained {
            return self
                .paths
                .lock()
                .unwrap()
                .uring_query(|vfs| crate::uring::execute::retained(vfs, request, memory, None));
        }
        let s = &request.sqe;
        Some(match s.opcode() {
            1 | 2 | 3 | 4 | 5 | 17 | 22 | 23 | 55 => {
                return file::execute(self, call, request, memory, actor, ring);
            }
            6 => {
                if s.length() & !9 != 0
                    || s.length() & 8 != 0 && !s.multishot()
                    || s.op_flags() & !0x201f != 0
                {
                    return Some(Err(Errno(22)));
                }
                let (events, epoch) = request.file.as_ref()?.readiness(s.op_flags() as u16);
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
                    .uring_stat(
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
                        socket.uring_attempt(memory, Some(&*self.paths.lock().unwrap()))?
                    } else {
                        socket.uring_attempt(memory, None)?
                    };
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
        Self::cancel_task_rings(self.rings(), owner, task);
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
    pub(crate) fn require_owner(&self) {
        self.owner_required.store(true, Ordering::Relaxed);
    }
    pub(crate) fn owner_required(&self) -> bool {
        self.owner_required.load(Ordering::Relaxed)
    }
    pub(crate) fn owner_progressed(&self) {
        self.owner_required.store(false, Ordering::Relaxed);
    }
    pub(crate) fn reset_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
    }
    pub(crate) fn pending_disk(&self) -> bool {
        self.accepted
            .lock()
            .unwrap()
            .values()
            .any(|call| call.file.as_ref().is_some_and(file::FileIo::pending_native))
    }

    pub(crate) fn event_wait(&self, owner: u64, task: u32) -> bool {
        if self.pending_disk() {
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
    pub(crate) fn active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }
    pub(crate) fn track(&self, ring: &Arc<Uring>) {
        self.revision.fetch_add(1, Ordering::Relaxed);
        self.active.store(true, Ordering::Relaxed);
        self.rings
            .lock()
            .unwrap()
            .insert(Arc::as_ptr(ring) as usize, Arc::downgrade(ring));
    }
    pub(crate) fn accept(
        self: &Arc<Self>,
        ring: &Arc<Uring>,
        request: &mut Request,
        context: Arc<Execution>,
    ) {
        if request.resource.is_none() {
            request.resource = request.file.as_ref().and_then(Resource::capture);
        }
        let key = (Arc::as_ptr(ring) as usize, request.sequence);
        self.rings
            .lock()
            .unwrap()
            .insert(key.0, Arc::downgrade(ring));
        // Decide original body admission once, not on every retry/byte copy.
        let retained = request.file.as_ref().is_some_and(|file| {
            let shared = file.shared_file();
            shared.is_none()
                || matches!(request.sqe.opcode(), 1 | 2 | 3 | 4 | 5 | 17 | 22 | 23 | 55)
                    && shared.and_then(|f| f.file_target()).is_none()
        });
        self.accepted.lock().unwrap().insert(
            key,
            Accepted {
                context,
                retained,
                socket: None,
                file: None,
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
        let key = (ring as *const Uring as usize, request.sequence);
        let mut call = self.accepted.lock().unwrap().remove(&key)?;
        let before = (
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
        let result = call
            .context
            .clone()
            .run(&mut call, request, memory, self, ring);
        let selection = request.selection.clone();
        if request.sqe.multishot()
            && matches!(request.sqe.opcode(), 26 | 27)
            && matches!(result, Some(Ok(_)))
        {
            call.socket = None;
        }
        let changed = before
            != (
                call.socket.as_ref().map(|s| s.uring_wait_kind()),
                call.file.as_ref().map(|f| f.wait_revision),
            );
        original.selection = selection;
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
