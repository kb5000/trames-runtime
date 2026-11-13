// SPDX-License-Identifier: GPL-3.0-or-later
//! Android Binder resources shared by every execution backend.
//!
//! Each device context, process, node and receive pool owns its own state. No
//! coordinator, service thread, guest Memory borrow or numeric target PID is
//! retained. Notifications run after unlocking; a waiting ioctl yields its CPU
//! slot through the same resource subscriptions as pipes/futexes.
use super::*;
use std::sync::{atomic::AtomicBool, Mutex, Weak};
pub mod abi;
mod pool;
mod protocol;
#[cfg(test)]
mod tests;
use abi::*;
use pool::{align, Pool};
pub use protocol::{Ioctl, Started};

#[derive(Default)]
pub(crate) struct Contexts {
    contexts: [Arc<Context>; 3],
    processes: Mutex<Vec<Weak<Connection>>>,
}
#[derive(Default)]
struct Context {
    manager: Mutex<Manager>,
}
#[derive(Default)]
struct Manager {
    node: Option<Weak<Node>>,
    uid: Option<u32>,
}
impl Contexts {
    pub fn open(&self, device: usize, owner: u32, _uid: u32) -> Arc<Connection> {
        let connection = Arc::new_cyclic(|weak| Connection {
            identity: trames_memory::new_backing_identity(),
            myself: weak.clone(),
            context: self.contexts[device].clone(),
            owner,
            state: Mutex::default(),
            readiness: Arc::default(),
            epoch: AtomicU64::new(0),
        });
        let mut processes = self.processes.lock().unwrap();
        processes.retain(|p| p.strong_count() != 0);
        processes.push(Arc::downgrade(&connection));
        connection
    }
    pub fn exit(&self, owner: u32, tid: u32, last: bool) {
        let processes: Vec<_> = self
            .processes
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|p| p.owner == owner)
            .collect();
        for process in processes {
            if last {
                process.close();
            } else {
                process.thread_exit(tid);
            }
        }
    }
}

pub struct Connection {
    identity: u64,
    myself: Weak<Self>,
    context: Arc<Context>,
    owner: u32,
    state: Mutex<State>,
    readiness: Arc<Readiness>,
    epoch: AtomicU64,
}
#[derive(Default)]
struct State {
    closed: bool,
    threads: BTreeMap<u32, Thread>,
    queue: VecDeque<Work>,
    queue_epoch: u64,
    nodes: BTreeMap<u64, Arc<Node>>,
    handles: BTreeMap<u32, Arc<Reference>>,
    next_handle: u32,
    pool: Weak<Pool>,
    buffers: BTreeMap<u64, Arc<Buffer>>,
    deaths: BTreeMap<u64, Death>,
    max_threads: u32,
    requested_threads: u32,
    last_error: (u32, u32, i32),
}
struct Thread {
    identity: u64,
    epoch: u64,
    poll: Weak<PollConnection>,
    queue: VecDeque<Work>,
    stack: Vec<Arc<Call>>,
    looper: bool,
    registered: bool,
    waiting: bool,
}
impl Default for Thread {
    fn default() -> Self {
        Self {
            identity: trames_memory::new_backing_identity(),
            epoch: 0,
            poll: Weak::new(),
            queue: VecDeque::new(),
            stack: Vec::new(),
            looper: false,
            registered: false,
            waiting: false,
        }
    }
}
enum Work {
    Bytes(Vec<u8>),
    Node(Arc<Node>),
    Transaction(Arc<Buffer>),
    Reply(Arc<Buffer>, Arc<Call>),
    Dead(Arc<Call>, u32),
    Death(u64),
    ClearDeath(u64),
}
impl Work {
    fn size(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Node(..) => 40,
            Self::Transaction(_) | Self::Reply(..) => 68,
            Self::Dead(..) => 4,
            Self::Death(_) | Self::ClearDeath(_) => 12,
        }
    }
}
struct Call {
    from: Weak<Connection>,
    from_tid: u32,
    to: Weak<Connection>,
    to_tid: AtomicU64,
    finished: AtomicBool,
    accept_fds: bool,
    parent: Option<Arc<Call>>,
}
impl Call {
    fn fail(self: &Arc<Self>) {
        self.fail_with(BR_DEAD_REPLY);
    }
    fn fail_with(self: &Arc<Self>, command: u32) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            if let Some(from) = self.from.upgrade() {
                let _ = from.enqueue(Some(self.from_tid), Work::Dead(self.clone(), command));
            }
        }
    }
}
struct Node {
    owner: Weak<Connection>,
    owner_tid: AtomicU64,
    pointer: u64,
    cookie: u64,
    flags: u32,
    dead: AtomicBool,
    is_manager: AtomicBool,
    state: Mutex<NodeState>,
}
#[derive(Default)]
struct NodeState {
    strong: u64,
    weak: u64,
    local_weak: u64,
    inflight: u64,
    queued: u64,
    pending_weak: u64,
    pending_strong: u64,
    async_active: bool,
    async_queue: VecDeque<Arc<Buffer>>,
    watchers: Vec<(Weak<Connection>, u64)>,
    has_weak: bool,
    has_strong: bool,
}
impl NodeState {
    fn idle(&self) -> bool {
        self.strong == 0
            && self.weak == 0
            && self.local_weak == 0
            && self.inflight == 0
            && self.queued == 0
            && self.pending_weak == 0
            && self.pending_strong == 0
            && !self.async_active
            && self.async_queue.is_empty()
            && !self.has_weak
            && !self.has_strong
    }
}
impl Node {
    fn change(&self, strong: bool, add: bool, amount: u64) -> Option<u32> {
        if amount == 0 {
            return None;
        }
        {
            let mut state = self.state.lock().unwrap();
            let count = if strong {
                &mut state.strong
            } else {
                &mut state.weak
            };
            let before = *count;
            *count = if add {
                before + amount
            } else {
                before.saturating_sub(amount)
            };
            let notice = if before == 0 && add {
                Some(if strong { BR_ACQUIRE } else { BR_INCREFS })
            } else if *count == 0 && !add && before != 0 {
                Some(if strong { BR_RELEASE } else { BR_DECREFS })
            } else {
                None
            };
            notice.filter(|_| !self.is_manager.load(Ordering::Relaxed))
        }
    }
    fn publish(self: &Arc<Self>, _: u32) {
        // One coalesced node work item, as in Linux Binder. Replaying every
        // transient zero would release a guest object before a concurrent new
        // reference could acquire it. Reconcile actual references at delivery.
        if self.is_manager.load(Ordering::Relaxed) {
            return;
        }
        {
            let mut state = self.state.lock().unwrap();
            let strong = state.strong != 0 || state.inflight != 0 || state.pending_strong != 0;
            let weak =
                state.weak != 0 || state.local_weak != 0 || state.pending_weak != 0 || strong;
            if state.queued != 0 || strong == state.has_strong && weak == state.has_weak {
                return;
            }
            state.queued = 1;
        }
        if let Some(owner) = self.owner.upgrade() {
            owner.enqueue_node(
                self.owner_tid.load(Ordering::Relaxed) as u32,
                Work::Node(self.clone()),
            );
        }
    }
    fn notices(&self) -> Vec<u8> {
        let mut state = self.state.lock().unwrap();
        state.queued = 0;
        let strong = state.strong != 0 || state.inflight != 0 || state.pending_strong != 0;
        let weak = state.weak != 0 || state.local_weak != 0 || state.pending_weak != 0 || strong;
        let mut out = Vec::new();
        let mut payload = self.pointer.to_le_bytes().to_vec();
        payload.extend_from_slice(&self.cookie.to_le_bytes());
        for (changed, cmd) in [
            (weak && !state.has_weak, BR_INCREFS),
            (strong && !state.has_strong, BR_ACQUIRE),
            (!strong && state.has_strong, BR_RELEASE),
            (!weak && state.has_weak, BR_DECREFS),
        ] {
            if changed {
                out.extend_from_slice(&command(cmd, &payload));
                match cmd {
                    BR_INCREFS => state.pending_weak = 1,
                    BR_ACQUIRE => state.pending_strong = 1,
                    _ => {}
                }
            }
        }
        state.has_weak = weak;
        state.has_strong = strong;
        out
    }
    fn acknowledge(self: &Arc<Self>, command: u32) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            let pending = if command == INCREFS_DONE {
                &mut state.pending_weak
            } else {
                &mut state.pending_strong
            };
            if *pending == 0 {
                return Err(Errno(22));
            }
            *pending -= 1;
        }
        self.publish(0);
        self.retire();
        Ok(())
    }
    fn notice_delivered(self: &Arc<Self>) {
        self.retire();
    }
    fn retire(self: &Arc<Self>) {
        if let Some(owner) = self.owner.upgrade() {
            let mut state = owner.state.lock().unwrap();
            if !self.is_manager.load(Ordering::Relaxed)
                && self.state.lock().unwrap().idle()
                && state
                    .nodes
                    .get(&self.pointer)
                    .is_some_and(|node| Arc::ptr_eq(node, self))
            {
                state.nodes.remove(&self.pointer);
            }
        }
    }
    fn die(&self) {
        if self.dead.swap(true, Ordering::AcqRel) {
            return;
        }
        let (watchers, queued) = {
            let mut state = self.state.lock().unwrap();
            (
                std::mem::take(&mut state.watchers),
                std::mem::take(&mut state.async_queue),
            )
        };
        for (process, cookie) in watchers {
            if let Some(process) = process.upgrade() {
                process.death(cookie);
            }
        }
        drop(queued);
    }
    fn queue_async(&self, buffer: Arc<Buffer>) -> Result<()> {
        let deliver = {
            let mut state = self.state.lock().unwrap();
            if self.dead.load(Ordering::Relaxed) {
                return Err(Errno(3));
            }
            if state.async_active {
                state.async_queue.push_back(buffer);
                None
            } else {
                state.async_active = true;
                buffer.async_active.store(true, Ordering::Relaxed);
                Some(buffer)
            }
        };
        if let Some(buffer) = deliver {
            self.owner
                .upgrade()
                .ok_or(Errno(3))?
                .enqueue(None, Work::Transaction(buffer))?;
        }
        Ok(())
    }
    fn finish_async(&self) {
        let next = {
            let mut state = self.state.lock().unwrap();
            let next = state.async_queue.pop_front();
            state.async_active = next.is_some();
            if let Some(buffer) = &next {
                buffer.async_active.store(true, Ordering::Relaxed);
            }
            next
        };
        if let Some(buffer) = next {
            if let Some(owner) = self.owner.upgrade() {
                let _ = owner.enqueue(None, Work::Transaction(buffer));
            }
        }
    }
}
// A Linux local strong reference holds the actual guest object, not merely
// the host Arc, while constructing/queuing transactions or translating handles.
struct NodeLease(Arc<Node>);
impl NodeLease {
    fn new(node: Arc<Node>) -> Self {
        node.state.lock().unwrap().inflight += 1;
        Self(node)
    }
}
impl std::ops::Deref for NodeLease {
    type Target = Node;
    fn deref(&self) -> &Node {
        &self.0
    }
}
impl Drop for NodeLease {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().inflight -= 1;
        self.0.publish(0);
        self.0.retire();
    }
}
struct Reference {
    node: Arc<Node>,
    receiver: Weak<Connection>,
    handle: u32,
    counts: Mutex<[u64; 4]>, // user weak/strong, buffer weak/strong
}
impl Reference {
    // The caller holds the original receiving process's handle index. Update
    // membership/counts together; notifications are returned for AFTER unlock.
    fn change(&self, index: usize, add: bool) -> Result<Vec<u32>> {
        let mut counts = self.counts.lock().unwrap();
        if !add && counts[index] == 0 {
            return Err(Errno(22));
        }
        let weak_before = counts.iter().any(|n| *n != 0);
        let strong_before = counts[1] != 0 || counts[3] != 0;
        counts[index] = if add {
            counts[index] + 1
        } else {
            counts[index] - 1
        };
        let weak_after = counts.iter().any(|n| *n != 0);
        let strong_after = counts[1] != 0 || counts[3] != 0;
        // A strong reference also owns a weak reference to the remote node.
        let mut notices = Vec::new();
        if !weak_before && weak_after {
            if let Some(cmd) = self.node.change(false, true, 1) {
                notices.push(cmd);
            }
        }
        if strong_before != strong_after {
            if let Some(cmd) = self.node.change(true, strong_after, 1) {
                notices.push(cmd);
            }
        }
        if weak_before && !weak_after {
            if let Some(cmd) = self.node.change(false, false, 1) {
                notices.push(cmd);
            }
        }
        Ok(notices)
    }
    fn empty(&self) -> bool {
        self.counts.lock().unwrap().iter().all(|n| *n == 0)
    }
}
impl Drop for Reference {
    fn drop(&mut self) {
        let counts = *self.counts.get_mut().unwrap();
        if let Some(cmd) =
            self.node
                .change(true, false, u64::from(counts[1] != 0 || counts[3] != 0))
        {
            self.node.publish(cmd);
        }
        if let Some(cmd) = self
            .node
            .change(false, false, u64::from(counts.iter().any(|n| *n != 0)))
        {
            self.node.publish(cmd);
        }
    }
}
struct BufferReference(Arc<Reference>, bool);
struct LocalReference(Arc<Node>, bool);
impl LocalReference {
    fn new(node: Arc<Node>, strong: bool) -> Self {
        if !strong {
            node.state.lock().unwrap().local_weak += 1;
        }
        if let Some(cmd) = node.change(false, true, 1) {
            node.publish(cmd);
        }
        if strong {
            if let Some(cmd) = node.change(true, true, 1) {
                node.publish(cmd);
            }
        }
        Self(node, strong)
    }
}
impl Drop for LocalReference {
    fn drop(&mut self) {
        if !self.1 {
            self.0.state.lock().unwrap().local_weak -= 1;
        }
        if self.1 {
            if let Some(cmd) = self.0.change(true, false, 1) {
                self.0.publish(cmd);
            }
        }
        if let Some(cmd) = self.0.change(false, false, 1) {
            self.0.publish(cmd);
        }
    }
}
impl Drop for BufferReference {
    fn drop(&mut self) {
        if let Some(receiver) = self.0.receiver.upgrade() {
            let _ = receiver.release_ref(&self.0, 2 + usize::from(self.1));
        } else if let Ok(notices) = self.0.change(2 + usize::from(self.1), false) {
            for cmd in notices {
                self.0.node.publish(cmd);
            }
        }
    }
}
struct Death {
    node: Weak<Node>,
    delivered: bool,
    acknowledged: bool,
    clear: bool,
}
pub(super) struct Packet {
    header: [u8; 64],
    data: Vec<u8>,
    offsets: Vec<usize>,
    extra: Vec<u8>,
    objects: Vec<Object>,
    relocations: Vec<(usize, usize)>,
}
enum Object {
    Node {
        offset: usize,
        node: Arc<Node>,
        strong: bool,
        _lease: Option<NodeLease>,
    },
    Buffer {
        offset: usize,
        extra: usize,
    },
    Fd {
        extra: bool,
        offset: usize,
        file: SharedFd,
        array: bool,
    },
}
struct Buffer {
    pool: Arc<Pool>,
    offset: usize,
    header: [u8; 64],
    _references: Vec<BufferReference>,
    _local_references: Vec<LocalReference>,
    fds: Mutex<Vec<FdFixup>>,
    auto_fds: Mutex<Vec<(SharedFiles, u32, CloseOnExec, u32)>>,
    node: Option<Arc<Node>>,
    call: Option<Arc<Call>>,
    async_active: AtomicBool,
}
struct FdFixup {
    offset: usize,
    file: SharedFd,
    array: bool,
}
impl Buffer {
    fn install(&self, factory: &DescriptorFactory) -> Result<()> {
        let mut fixes = self.fds.lock().unwrap();
        // Reserve the entire transfer before publishing the first destination
        // slot. EMFILE cannot publish half an Android native_handle_t.
        let reservations = fixes
            .iter()
            .map(|_| factory.files.reserve())
            .collect::<Result<Vec<_>>>()?;
        let mut installed = Vec::new();
        for (fix, reservation) in fixes.iter().zip(reservations) {
            let identity: CloseOnExec = true.into();
            let result = reservation.publish(
                Descriptor {
                    open: OpenHandle::Shared(fix.file.open.clone()),
                    cloexec: identity.clone(),
                },
                None,
            );
            let fd = match result {
                Ok(fd) => fd,
                Err(error) => {
                    for (fd, identity, _) in installed {
                        factory.files.close_if_slot(
                            fd,
                            &identity,
                            factory.local_sender_credentials()[0],
                        );
                    }
                    return Err(error);
                }
            };
            installed.push((fd, identity, fix.array));
            self.pool.write(self.offset + fix.offset, &fd.to_le_bytes());
        }
        let mut automatic = self.auto_fds.lock().unwrap();
        for (fd, identity, array) in installed {
            if array {
                automatic.push((
                    factory.files.clone(),
                    fd,
                    identity,
                    factory.local_sender_credentials()[0],
                ));
            }
        }
        fixes.clear();
        Ok(())
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        // FDA descriptors belong to the received buffer, flat FD objects to
        // userspace. Never close a reused destination number on buffer free.
        for (files, fd, identity, owner) in self.auto_fds.get_mut().unwrap().drain(..) {
            files.close_if_slot(fd, &identity, owner);
        }
        self.pool
            .free(self.offset, dword(&self.header, 20) & CLEAR_BUF != 0);
        if self.async_active.swap(false, Ordering::Relaxed) {
            if let Some(node) = &self.node {
                node.finish_async();
            }
        }
        if let Some(node) = &self.node {
            node.state.lock().unwrap().inflight -= 1;
            node.publish(0);
            node.retire();
        }
    }
}
impl Connection {
    pub(super) fn owner(&self) -> u32 {
        self.owner
    }
    pub(super) fn poll_handle(self: &Arc<Self>) -> Arc<dyn DirectPoll> {
        // The shared OFD cache has no caller. Do not create a retired leader's
        // Binder thread while preparing another task's original poll context.
        Arc::new(PollConnection {
            process: Arc::downgrade(self),
            tid: self.owner,
            identity: self.identity as usize,
            bound: false,
            readiness: self.readiness.clone(),
        })
    }
    fn poll_handle_for(self: &Arc<Self>, tid: u32) -> Arc<dyn DirectPoll> {
        let mut state = self.state.lock().unwrap();
        let thread = state.threads.entry(tid).or_default();
        if let Some(poll) = thread.poll.upgrade() {
            return poll;
        }
        let poll = Arc::new(PollConnection {
            process: Arc::downgrade(self),
            tid,
            identity: thread.identity as usize,
            bound: true,
            readiness: self.readiness.clone(),
        });
        thread.poll = Arc::downgrade(&poll);
        poll
    }
    pub(super) fn poll_for(&self, tid: u32, events: u16) -> (u16, [u64; 2]) {
        self.poll_thread(tid, None, events)
    }
    fn poll_thread(&self, tid: u32, identity: Option<usize>, events: u16) -> (u16, [u64; 2]) {
        let state = self.state.lock().unwrap();
        let thread = state.threads.get(&tid);
        if state.closed
            || identity.is_some_and(|id| thread.is_none_or(|t| t.identity as usize != id))
        {
            return (0x18, [u64::MAX, 0]);
        }
        let local = thread.is_some_and(|t| !t.queue.is_empty());
        let process = thread.is_none_or(|t| t.stack.is_empty() && t.queue.is_empty());
        let ready = local || process && !state.queue.is_empty();
        (
            (if ready { events & 1 } else { 0 }),
            [
                thread.map_or(0, |t| t.epoch),
                if process { state.queue_epoch } else { 0 },
            ],
        )
    }
    pub fn check_owner(&self, owner: u32) -> Result<()> {
        if owner != self.owner {
            return Err(Errno(22));
        }
        if self.state.lock().unwrap().closed {
            return Err(Errno(111));
        }
        Ok(())
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.readiness.subscribe(signal)
    }
    fn notify(&self) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
        self.readiness.notify_atomic();
    }
    fn enqueue(&self, tid: Option<u32>, work: Work) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(Errno(111));
            }
            if let Some(tid) = tid {
                let thread = state.threads.entry(tid).or_default();
                thread.queue.push_back(work);
                thread.epoch = thread.epoch.wrapping_add(1);
            } else {
                state.queue.push_back(work);
                state.queue_epoch = state.queue_epoch.wrapping_add(1);
            }
        }
        self.notify();
        Ok(())
    }
    fn bytes(&self, tid: u32, cmd: u32) {
        let _ = self.enqueue(Some(tid), Work::Bytes(command(cmd, &[])));
    }
    fn enqueue_node(&self, tid: u32, work: Work) {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return;
            }
            if let Some(thread) = state.threads.get_mut(&tid) {
                thread.queue.push_back(work);
                thread.epoch = thread.epoch.wrapping_add(1);
            } else {
                state.queue.push_back(work);
                state.queue_epoch = state.queue_epoch.wrapping_add(1);
            }
        }
        self.notify();
    }
    fn owned_node(&self, pointer: u64, cookie: u64, flags: u32, tid: u32) -> Result<Arc<Node>> {
        if flags & 0x1000 != 0 {
            return Err(Errno(95));
        }
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Errno(111));
        }
        if let Some(node) = state.nodes.get(&pointer) {
            if node.cookie == cookie {
                node.owner_tid.store(tid as u64, Ordering::Relaxed);
                return Ok(node.clone());
            }
            // Failed packet imports can leave an unpublished empty node. Only
            // a fully retired generation may be replaced at a reused address.
            if node.is_manager.load(Ordering::Relaxed) || !node.state.lock().unwrap().idle() {
                return Err(Errno(22));
            }
            state.nodes.remove(&pointer);
        }
        state.threads.entry(tid).or_default();
        let node = Arc::new(Node {
            owner: self.myself.clone(),
            owner_tid: AtomicU64::new(tid as u64),
            pointer,
            cookie,
            flags,
            dead: AtomicBool::new(false),
            is_manager: AtomicBool::new(false),
            state: Mutex::default(),
        });
        state.nodes.insert(pointer, node.clone());
        Ok(node)
    }
    fn target(&self, handle: u32) -> Result<Arc<Node>> {
        if handle == 0 {
            return self
                .context
                .manager
                .lock()
                .unwrap()
                .node
                .as_ref()
                .and_then(Weak::upgrade)
                .filter(|n| !n.dead.load(Ordering::Relaxed))
                .ok_or(Errno(3));
        }
        let state = self.state.lock().unwrap();
        let reference = state.handles.get(&handle).ok_or(Errno(22))?;
        if reference.node.dead.load(Ordering::Relaxed) {
            return Err(Errno(3));
        }
        Ok(reference.node.clone())
    }
    fn strong_target(&self, handle: u32) -> Result<NodeLease> {
        if handle == 0 {
            return self.target(0).map(NodeLease::new);
        }
        let state = self.state.lock().unwrap();
        let reference = state.handles.get(&handle).ok_or(Errno(22))?;
        let counts = reference.counts.lock().unwrap();
        if counts[1] == 0 && counts[3] == 0 {
            return Err(Errno(22));
        }
        if reference.node.dead.load(Ordering::Relaxed) {
            return Err(Errno(3));
        }
        // Pin under the sender's handle index, before another thread can
        // release its final handle. Target buffers extend this pin until free.
        Ok(NodeLease::new(reference.node.clone()))
    }
    fn reference(&self, node: Arc<Node>, index: usize) -> Result<Arc<Reference>> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Errno(111));
        }
        if let Some(reference) = state.handles.values().find(|r| Arc::ptr_eq(&r.node, &node)) {
            let reference = reference.clone();
            let notices = reference.change(index, true)?;
            drop(state);
            for cmd in notices {
                reference.node.publish(cmd);
            }
            return Ok(reference);
        }
        let manager = self
            .context
            .manager
            .lock()
            .unwrap()
            .node
            .as_ref()
            .and_then(Weak::upgrade);
        let handle = if manager.as_ref().is_some_and(|n| Arc::ptr_eq(n, &node)) {
            0
        } else {
            state.next_handle = state.next_handle.checked_add(1).ok_or(Errno(28))?;
            state.next_handle
        };
        let reference = Arc::new(Reference {
            node,
            receiver: self.myself.clone(),
            handle,
            counts: Mutex::default(),
        });
        state.handles.insert(handle, reference.clone());
        let notices = reference.change(index, true)?;
        drop(state);
        for cmd in notices {
            reference.node.publish(cmd);
        }
        Ok(reference)
    }
    fn release_ref(&self, reference: &Arc<Reference>, index: usize) -> Result<()> {
        let (retired, notices) = {
            let mut state = self.state.lock().unwrap();
            let notices = reference.change(index, false)?;
            if reference.empty()
                && state
                    .handles
                    .get(&reference.handle)
                    .is_some_and(|r| Arc::ptr_eq(r, reference))
            {
                (state.handles.remove(&reference.handle), notices)
            } else {
                (None, notices)
            }
        };
        for cmd in notices {
            reference.node.publish(cmd);
        }
        drop(retired);
        Ok(())
    }
    fn ref_command(&self, cmd: u32, handle: u32) -> Result<()> {
        let index = usize::from(matches!(cmd, ACQUIRE | RELEASE));
        if matches!(cmd, INCREFS | ACQUIRE) {
            let target = if handle == 0 {
                let Ok(node) = self.target(0) else {
                    return Ok(());
                };
                node
            } else {
                let state = self.state.lock().unwrap();
                let Some(reference) = state.handles.get(&handle) else {
                    return Ok(());
                };
                // References survive their remote process. libbinder can still
                // acquire/release one while consuming death and queued parcels.
                reference.node.clone()
            };
            if target.owner.ptr_eq(&self.myself) {
                return Err(Errno(22));
            }
            self.reference(target, index).map(|_| ())
        } else {
            let reference = self.state.lock().unwrap().handles.get(&handle).cloned();
            let Some(reference) = reference else {
                return Ok(());
            };
            match self.release_ref(&reference, index) {
                Err(Errno(22)) => Ok(()), // Linux ignores invalid refcount commands.
                result => result,
            }
        }
    }
    fn set_manager(&self, pointer: u64, cookie: u64, flags: u32, uid: u32, tid: u32) -> Result<()> {
        let node = self.owned_node(pointer, cookie, flags, tid)?;
        let mut manager = self.context.manager.lock().unwrap();
        if manager
            .node
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|n| !n.dead.load(Ordering::Relaxed))
        {
            return Err(Errno(16));
        }
        if manager.uid.is_some_and(|owner| owner != uid) {
            return Err(Errno(1));
        }
        manager.node = Some(Arc::downgrade(&node));
        manager.uid = Some(uid);
        // The context object is pinned by the manager. Linux marks both user
        // references present at registration; it never emits INCREFS/ACQUIRE
        // for the legacy null ptr/cookie pair (libbinder would dereference it).
        node.is_manager.store(true, Ordering::Relaxed);
        Ok(())
    }
    pub fn mapping(
        self: &Arc<Self>,
        address: u64,
        offset: u64,
        length: u64,
        writable: bool,
    ) -> Result<Vec<Arc<dyn trames_memory::PageBacking>>> {
        if offset != 0 || writable {
            return Err(Errno(1));
        }
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Errno(111));
        }
        if state.pool.upgrade().is_some() {
            return Err(Errno(16));
        }
        let pool = Pool::new(address, length)?;
        state.pool = Arc::downgrade(&pool);
        let mapping = Arc::new(Mapping {
            process: Mutex::new(Some(self.clone())),
            pool: pool.clone(),
        });
        // Backings retain the OFD's process resource, exactly like a file mmap;
        // the process retains only a weak pool, so close/unmap cannot form a cycle.
        Ok(pool
            .backings()
            .into_iter()
            .map(|page| {
                Arc::new(MappedPage {
                    page,
                    mapping: mapping.clone(),
                }) as Arc<dyn trames_memory::PageBacking>
            })
            .collect())
    }
    fn make_buffer(
        &self,
        mut packet: Packet,
        node: Option<Arc<Node>>,
        call: Option<Arc<Call>>,
        sender: [u32; 2],
    ) -> Result<Arc<Buffer>> {
        let pool = self.state.lock().unwrap().pool.upgrade().ok_or(Errno(3))?;
        let data_length = packet.data.len();
        let offsets_at = align(data_length)?;
        let extra_at = offsets_at
            .checked_add(packet.offsets.len() * 8)
            .ok_or(Errno(22))?;
        let length = extra_at.checked_add(packet.extra.len()).ok_or(Errno(22))?;
        let offset = pool.allocate(length)?;
        let mut references = Vec::new();
        let mut local_references = Vec::new();
        let mut fixes = Vec::new();
        let translated = (|| {
            for object in packet.objects {
                match object {
                    Object::Node {
                        offset: at,
                        node,
                        strong,
                        _lease,
                    } => {
                        if node.owner.ptr_eq(&self.myself) {
                            put32(
                                &mut packet.data,
                                at,
                                if strong {
                                    TYPE_BINDER
                                } else {
                                    TYPE_WEAK_BINDER
                                },
                            );
                            put(&mut packet.data, at + 8, node.pointer);
                            put(&mut packet.data, at + 16, node.cookie);
                            local_references.push(LocalReference::new(node, strong));
                        } else {
                            let reference = self.reference(node, 2 + usize::from(strong))?;
                            put32(
                                &mut packet.data,
                                at,
                                if strong {
                                    TYPE_HANDLE
                                } else {
                                    TYPE_WEAK_HANDLE
                                },
                            );
                            put(&mut packet.data, at + 8, reference.handle as u64);
                            put(&mut packet.data, at + 16, 0);
                            references.push(BufferReference(reference, strong));
                        }
                    }
                    Object::Buffer { offset: at, extra } => {
                        put(
                            &mut packet.data,
                            at + 8,
                            pool.base + (offset + extra_at + extra) as u64,
                        );
                    }
                    Object::Fd {
                        extra,
                        offset: at,
                        file,
                        array,
                    } => {
                        fixes.push(FdFixup {
                            offset: if extra { extra_at + at } else { at },
                            file,
                            array,
                        });
                    }
                }
            }
            // Parent pointers in SG buffers were recorded as offsets into the
            // copied extra region. Relocate once after the actual pool allocation.
            for fix in &packet.relocations {
                put(
                    &mut packet.extra,
                    fix.0,
                    pool.base + (offset + extra_at + fix.1) as u64,
                );
            }
            Ok(())
        })();
        if let Err(error) = translated {
            pool.free(offset, false);
            return Err(error);
        }
        pool.write(offset, &packet.data);
        let offsets: Vec<_> = packet
            .offsets
            .iter()
            .flat_map(|v| (*v as u64).to_le_bytes())
            .collect();
        pool.write(offset + offsets_at, &offsets);
        pool.write(offset + extra_at, &packet.extra);
        if let Some(node) = &node {
            put(&mut packet.header, 0, node.pointer);
            put(&mut packet.header, 8, node.cookie);
        } else {
            put(&mut packet.header, 0, 0);
            put(&mut packet.header, 8, 0);
        }
        put32(&mut packet.header, 24, sender[0]);
        put32(&mut packet.header, 28, sender[1]);
        put(&mut packet.header, 48, pool.base + offset as u64);
        put(
            &mut packet.header,
            56,
            pool.base + (offset + offsets_at) as u64,
        );
        if let Some(node) = &node {
            node.state.lock().unwrap().inflight += 1;
        }
        Ok(Arc::new(Buffer {
            pool,
            offset,
            header: packet.header,
            _references: references,
            _local_references: local_references,
            fds: Mutex::new(fixes),
            auto_fds: Mutex::default(),
            node,
            call,
            async_active: AtomicBool::new(false),
        }))
    }
    fn take_reply(&self, tid: u32) -> Result<Arc<Call>> {
        let mut state = self.state.lock().unwrap();
        let thread = state.threads.entry(tid).or_default();
        let call = thread.stack.last().ok_or(Errno(71))?;
        if !call.to.ptr_eq(&self.myself) || call.to_tid.load(Ordering::Relaxed) != tid as u64 {
            return Err(Errno(71));
        }
        Ok(thread.stack.pop().unwrap())
    }
    fn reject_reply(&self, tid: u32, command: u32) -> Result<()> {
        let call = self.take_reply(tid)?;
        call.fail_with(command);
        // Linux completes the replier's write while the original caller gets
        // the failed reply. Neither thread retains the finished stack frame.
        self.bytes(tid, BR_COMPLETE);
        Ok(())
    }
    fn submit(&self, tid: u32, packet: Packet, reply: bool, identity: [u32; 2]) -> Result<()> {
        if reply {
            let call = self.take_reply(tid)?;
            let prepared = (|| {
                if !call.accept_fds
                    && packet
                        .objects
                        .iter()
                        .any(|o| matches!(o, Object::Fd { .. }))
                {
                    return Err(Errno(1));
                }
                let receiver = call.from.upgrade().ok_or(Errno(3))?;
                let buffer = receiver.make_buffer(packet, None, None, identity)?;
                Ok((receiver, buffer))
            })();
            // Buffer translation queues the owner's ACQUIRE before COMPLETE,
            // keeping returned temporary guest objects alive. COMPLETE must in
            // turn precede any immediate nested call provoked by the reply.
            self.bytes(tid, BR_COMPLETE);
            let result = prepared.and_then(|(receiver, buffer): (Arc<Connection>, Arc<Buffer>)| {
                if call.finished.swap(true, Ordering::AcqRel) {
                    return Err(Errno(3));
                }
                receiver.enqueue(Some(call.from_tid), Work::Reply(buffer, call.clone()))
            });
            if let Err(error) = result {
                call.fail_with(if matches!(error.0, 3 | 111) {
                    BR_DEAD_REPLY
                } else {
                    BR_FAILED_REPLY
                });
            }
            return Ok(());
        }
        let target = self.strong_target(dword(&packet.header, 0))?;
        let node = target.0.clone();
        if node.owner.ptr_eq(&self.myself) {
            return Err(Errno(22));
        }
        if node.flags & 0x100 == 0
            && packet
                .objects
                .iter()
                .any(|o| matches!(o, Object::Fd { .. }))
        {
            return Err(Errno(1));
        }
        let receiver = node.owner.upgrade().ok_or(Errno(3))?;
        let oneway = dword(&packet.header, 20) & ONE_WAY != 0;
        let parent = self
            .state
            .lock()
            .unwrap()
            .threads
            .entry(tid)
            .or_default()
            .stack
            .last()
            .cloned();
        let call = (!oneway).then(|| {
            Arc::new(Call {
                from: self.myself.clone(),
                from_tid: tid,
                to: Arc::downgrade(&receiver),
                to_tid: AtomicU64::new(0),
                finished: AtomicBool::new(false),
                accept_fds: dword(&packet.header, 20) & ACCEPT_FDS != 0,
                parent: parent.clone(),
            })
        });
        let buffer = receiver.make_buffer(packet, Some(node.clone()), call.clone(), identity)?;
        if let Some(call) = &call {
            self.state
                .lock()
                .unwrap()
                .threads
                .entry(tid)
                .or_default()
                .stack
                .push(call.clone());
        }
        let mut destination = None;
        let mut ancestor = parent;
        while let Some(call) = ancestor {
            if !call.finished.load(Ordering::Relaxed) && call.from.ptr_eq(&node.owner) {
                destination = Some(call.from_tid);
                break;
            }
            ancestor = call.parent.clone();
        }
        // Completion must precede any immediate nested callback from the
        // receiver. Otherwise its sendReply consumes the older completion and
        // leaves its own BR_COMPLETE in the idle server command stream.
        self.bytes(tid, BR_COMPLETE);
        let result = if oneway {
            node.queue_async(buffer)
        } else {
            receiver.enqueue(destination, Work::Transaction(buffer))
        };
        if result.is_err() {
            if let Some(call) = call {
                call.fail();
            }
            // Publication was admitted before a concurrent destination exit.
            // A synchronous caller receives DEAD_REPLY; an admitted oneway has
            // no reply, like an async transaction whose target then exits.
        }
        Ok(())
    }
    fn free_buffer(&self, address: u64) -> Result<()> {
        let buffer = self
            .state
            .lock()
            .unwrap()
            .buffers
            .remove(&address)
            .ok_or(Errno(22))?;
        drop(buffer);
        Ok(())
    }
    fn thread_exit(&self, tid: u32) {
        let thread = self.state.lock().unwrap().threads.remove(&tid);
        if let Some(thread) = thread {
            for call in &thread.stack {
                call.fail();
            }
            for work in thread.queue {
                if matches!(work, Work::Node(..)) {
                    let _ = self.enqueue(None, work);
                } else if let Work::Transaction(buffer) = work {
                    if let Some(call) = &buffer.call {
                        call.fail();
                    }
                }
            }
        }
        self.notify();
    }
    fn close(&self) {
        let retired = {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return;
            }
            let mut retired = std::mem::take(&mut *state);
            state.closed = true;
            retired.closed = true;
            retired
        };
        for node in retired.nodes.values() {
            node.die();
        }
        for thread in retired.threads.values() {
            for call in &thread.stack {
                call.fail();
            }
        }
        for work in retired
            .queue
            .iter()
            .chain(retired.threads.values().flat_map(|t| &t.queue))
        {
            if let Work::Transaction(buffer) = work {
                if let Some(call) = &buffer.call {
                    call.fail();
                }
            }
        }
        drop(retired);
        self.notify();
    }
    fn death(&self, cookie: u64) {
        let queue = {
            let mut state = self.state.lock().unwrap();
            let Some(death) = state.deaths.get_mut(&cookie) else {
                return;
            };
            if death.delivered {
                false
            } else {
                death.delivered = true;
                true
            }
        };
        if queue {
            let _ = self.enqueue(None, Work::Death(cookie));
        }
    }
    fn request_death(&self, handle: u32, cookie: u64) -> Result<()> {
        let node = self.target(handle).or_else(|_| {
            self.state
                .lock()
                .unwrap()
                .handles
                .get(&handle)
                .map(|r| r.node.clone())
                .ok_or(Errno(22))
        })?;
        {
            let mut state = self.state.lock().unwrap();
            if state.deaths.contains_key(&cookie) {
                return Err(Errno(22));
            }
            state.deaths.insert(
                cookie,
                Death {
                    node: Arc::downgrade(&node),
                    delivered: false,
                    acknowledged: false,
                    clear: false,
                },
            );
        }
        let dead = {
            let mut state = node.state.lock().unwrap();
            state.watchers.push((self.myself.clone(), cookie));
            node.dead.load(Ordering::Relaxed)
        };
        if dead {
            self.death(cookie);
        }
        Ok(())
    }
    fn clear_death(&self, handle: u32, cookie: u64) -> Result<()> {
        let (node, complete) = {
            let mut state = self.state.lock().unwrap();
            let reference = state.handles.get(&handle).ok_or(Errno(22))?.node.clone();
            let death = state.deaths.get_mut(&cookie).ok_or(Errno(22))?;
            if !death.node.ptr_eq(&Arc::downgrade(&reference)) {
                return Err(Errno(22));
            }
            death.clear = true;
            let complete = !death.delivered || death.acknowledged;
            let node = death.node.clone();
            if complete {
                state.deaths.remove(&cookie);
            }
            (node, complete)
        };
        if let Some(node) = node.upgrade() {
            node.state
                .lock()
                .unwrap()
                .watchers
                .retain(|(p, c)| !p.ptr_eq(&self.myself) || *c != cookie);
        }
        if complete {
            self.enqueue(None, Work::ClearDeath(cookie))?;
        }
        Ok(())
    }
    fn death_done(&self, cookie: u64) -> Result<()> {
        let complete = {
            let mut state = self.state.lock().unwrap();
            let death = state.deaths.get_mut(&cookie).ok_or(Errno(22))?;
            if !death.delivered {
                return Err(Errno(22));
            }
            death.acknowledged = true;
            let complete = death.clear;
            if complete {
                state.deaths.remove(&cookie);
            }
            complete
        };
        if complete {
            self.enqueue(None, Work::ClearDeath(cookie))?;
        }
        Ok(())
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}
impl DirectPoll for Connection {
    fn identity(&self) -> usize {
        self.identity as usize
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.poll_for(self.owner, events)
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.subscribe(signal)
    }
}
struct PollConnection {
    process: Weak<Connection>,
    tid: u32,
    identity: usize,
    bound: bool,
    readiness: Arc<Readiness>,
}
impl DirectPoll for PollConnection {
    fn bind_task(&self, tid: u32) -> Option<Arc<dyn DirectPoll>> {
        if self.bound && tid == self.tid {
            return None;
        }
        Some(self.process.upgrade()?.poll_handle_for(tid))
    }
    fn identity(&self) -> usize {
        self.identity
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.process
            .upgrade()
            .map_or((0x18, [u64::MAX, 0]), |process| {
                process.poll_thread(self.tid, self.bound.then_some(self.identity), events)
            })
    }
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.readiness.subscribe(signal)
    }
}
// Only a mapping retains process lifetime. Its bytes still use the exact same
// canonical SharedPage providers; this wrapper adds no per-byte policy.
struct Mapping {
    process: Mutex<Option<Arc<Connection>>>,
    pool: Arc<Pool>,
}
impl Mapping {
    fn close(&self) {
        self.pool.live.store(false, Ordering::Relaxed);
        // Physical byte snapshots may outlive the VMA. They must not postpone
        // filp release/death notifications until a whole CPU cohort finishes.
        let process = self.process.lock().unwrap().take();
        drop(process);
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        self.close();
    }
}
struct MappedPage {
    page: Arc<dyn trames_memory::PageBacking>,
    mapping: Arc<Mapping>,
}
impl trames_memory::PageBacking for MappedPage {
    fn inherit_on_fork(&self) -> bool {
        false
    }
    fn cpu_borrow_safe(&self) -> bool {
        self.page.cpu_borrow_safe()
    }
    fn parallel_key(&self) -> Option<(u64, u64)> {
        self.page.parallel_key()
    }
    fn shared_page(&self) -> Option<Arc<trames_memory::SharedPage>> {
        self.page.shared_page()
    }
    fn parallel_versioned(&self) -> bool {
        true
    }
    fn parallel_metadata_domain(&self) -> Option<(u64, u64)> {
        self.page.parallel_metadata_domain()
    }
    fn parallel_domain_offset(&self) -> Option<u64> {
        self.page.parallel_domain_offset()
    }
    fn parallel_commit_isolated(&self) -> bool {
        true
    }
    fn check(&self, a: u64) -> std::result::Result<(), trames_memory::MemoryError> {
        self.page.check(a)
    }
    fn read(&self, o: usize, b: &mut [u8]) -> std::result::Result<(), trames_memory::MemoryError> {
        self.page.read(o, b)
    }
    fn write(&self, o: usize, b: &[u8]) -> std::result::Result<(), trames_memory::MemoryError> {
        self.page.write(o, b)
    }
    fn native_resident(&self) -> bool {
        true
    }
    fn with_read(
        &self,
        o: usize,
        l: usize,
        f: &mut dyn FnMut(&[u8]),
    ) -> std::result::Result<bool, trames_memory::MemoryError> {
        self.page.with_read(o, l, f)
    }
    fn sync(&self) -> std::result::Result<(), trames_memory::MemoryError> {
        Ok(())
    }
    fn sync_required(&self) -> bool {
        false
    }
    fn version(&self) -> u64 {
        self.page.version()
    }
    fn writable(&self) -> bool {
        false
    }
    fn private_writable(&self) -> bool {
        false
    }
    fn unmapped(&self) {
        self.mapping.close();
    }
    fn executable(&self) -> bool {
        false
    }
    fn next_page(
        &self,
        _: u64,
    ) -> std::result::Result<Arc<dyn trames_memory::PageBacking>, trames_memory::MemoryError> {
        Err(trames_memory::MemoryError::InvalidRange)
    }
}
