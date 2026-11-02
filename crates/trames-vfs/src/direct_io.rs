// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared byte resources. No namespace, descriptor-table Rc or guest memory lives
//! behind these handles. Admitted mutations use actual shared Files/OFD ownership.
use super::*;
use crate::readiness::Readiness;
use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};

/// A retained event object for native asynchronous completions. It carries no
/// guest descriptor-table borrow or guest pointer, and does not resolve a reused FD.
#[derive(Clone)]
pub struct NativeEvent(Arc<NativeWriter>);
struct NativeWriter {
    counter: Arc<EventCounter>,
    owner: std::thread::Thread,
}
impl Drop for NativeWriter {
    fn drop(&mut self) {
        self.counter.native_writers.fetch_sub(1, Ordering::Relaxed);
    }
}
impl NativeEvent {
    pub fn notify(&self) {
        // Saturation already leaves the level-triggered descriptor readable.
        let _ = self.0.counter.write(&1u64.to_le_bytes());
        // Workers use ordinary resource subscriptions. The joined owner may
        // instead be parked with every guest task blocked; retain its wake
        // token even if completion wins the race with park_timeout().
        self.0.owner.unpark();
    }
}

pub(super) struct EventCounter {
    count: AtomicU64,
    native_writers: AtomicU64,
    semaphore: bool,
    readiness: Arc<Readiness>,
    epoch: [AtomicU64; 2],
}
impl EventCounter {
    pub(super) fn new(count: u64, semaphore: bool) -> Self {
        Self {
            count: AtomicU64::new(count),
            native_writers: AtomicU64::new(0),
            semaphore,
            readiness: Arc::default(),
            epoch: [AtomicU64::new(0), AtomicU64::new(0)],
        }
    }
    pub(super) fn read(&self, count: usize) -> Result<Vec<u8>> {
        if count < 8 {
            return Err(Errno(22));
        }
        // Eventfd is an actual synchronization operation: acquiring the counter
        // observes data published before a successful writer's release RMW.
        let old = self
            .count
            .try_update(Ordering::Acquire, Ordering::Relaxed, |n| {
                (n != 0).then(|| if self.semaphore { n - 1 } else { 0 })
            })
            .map_err(|_| Errno(11))?;
        self.epoch[1].fetch_add(1, Ordering::Relaxed);
        self.readiness.notify_atomic();
        Ok((if self.semaphore { 1 } else { old })
            .to_le_bytes()
            .to_vec())
    }
    pub(super) fn write(&self, bytes: &[u8]) -> Result<usize> {
        if bytes.len() < 8 {
            return Err(Errno(22));
        }
        let value = u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes"));
        if value == u64::MAX {
            return Err(Errno(22));
        }
        self.count
            .try_update(Ordering::Release, Ordering::Relaxed, |n| {
                n.checked_add(value).filter(|n| *n < u64::MAX)
            })
            .map_err(|_| Errno(11))?;
        self.epoch[0].fetch_add(1, Ordering::Relaxed);
        self.readiness.notify_atomic();
        Ok(8)
    }
    pub(super) fn poll(&self, events: u16) -> u16 {
        let count = self.count.load(Ordering::Relaxed);
        (if count > 0 { events & 1 } else { 0 })
            | (if count < u64::MAX - 1 { events & 4 } else { 0 })
    }
    pub(super) fn epoch(&self) -> [u64; 2] {
        self.epoch.each_ref().map(|n| n.load(Ordering::Relaxed))
    }
}

pub(super) struct PipeData {
    pub bytes: VecDeque<u8>,
    pub readers: u32,
    pub writers: u32,
    pub read_epoch: u64,
    pub write_epoch: u64,
    pub io_epoch: [u64; 2],
}
impl PipeData {
    pub(super) fn new() -> Self {
        Self {
            bytes: VecDeque::new(),
            readers: 0,
            writers: 0,
            read_epoch: 0,
            write_epoch: 0,
            io_epoch: [0; 2],
        }
    }
    // The original pipe algorithms, shared by VFS and worker-local calls.
    pub(super) fn read(&mut self, count: usize) -> Result<Vec<u8>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.bytes.is_empty() && self.writers != 0 {
            return Err(Errno(11));
        }
        let n = count.min(self.bytes.len());
        if n != 0 {
            self.io_epoch[1] = self.io_epoch[1].wrapping_add(1);
        }
        Ok(self.bytes.drain(..n).collect())
    }
    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        if self.readers == 0 {
            return Err(Errno(32));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let room = PIPE_CAPACITY - self.bytes.len();
        if room == 0 || bytes.len() <= 4096 && room < bytes.len() {
            return Err(Errno(11));
        }
        let n = room.min(bytes.len());
        self.bytes.extend(&bytes[..n]);
        self.io_epoch[0] = self.io_epoch[0].wrapping_add(1);
        Ok(n)
    }
}

// Every legacy, splice and native-relay path also uses this guard. Notifications
// happen after unlock, so a wake callback can safely retry the same pipe.
pub(super) struct PipeResource {
    data: Mutex<PipeData>,
    readiness: Arc<Readiness>,
}
pub(super) struct PipeGuard<'a> {
    guard: Option<MutexGuard<'a, PipeData>>,
    source: &'a PipeResource,
    before: [u64; 2],
}
impl PipeResource {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(PipeData::new()),
            readiness: Arc::default(),
        }
    }
    pub fn lock<'a>(&'a self) -> LockResult<PipeGuard<'a>> {
        let wrap = |guard: MutexGuard<'a, PipeData>| {
            let before = guard.io_epoch;
            PipeGuard {
                guard: Some(guard),
                source: self,
                before,
            }
        };
        match self.data.lock() {
            Ok(guard) => Ok(wrap(guard)),
            Err(error) => Err(PoisonError::new(wrap(error.into_inner()))),
        }
    }
}
impl std::ops::Deref for PipeGuard<'_> {
    type Target = PipeData;
    fn deref(&self) -> &PipeData {
        self.guard.as_ref().unwrap()
    }
}
impl std::ops::DerefMut for PipeGuard<'_> {
    fn deref_mut(&mut self) -> &mut PipeData {
        self.guard.as_mut().unwrap()
    }
}
impl Drop for PipeGuard<'_> {
    fn drop(&mut self) {
        let changed = self.guard.as_ref().unwrap().io_epoch != self.before;
        drop(self.guard.take());
        if changed {
            self.source.readiness.notify_locked();
        }
    }
}

/// A frozen poll-only capability; no FD table, Rc or guest memory is retained.
pub trait DirectPoll: Send + Sync {
    fn identity(&self) -> usize;
    fn poll(&self, events: u16) -> (u16, [u64; 2]);
    fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription;
}
#[derive(Clone)]
enum ByteResource {
    TcpPoll(trames_net::TcpPoll),
    Mounts(Arc<mounts::watch::MountWatch>),
    Regular,
    Kmsg(Arc<kernel_log::Kmsg>),
    PollOnly(Arc<dyn DirectPoll>),
    Event(Arc<EventCounter>),
    Timer(Arc<TimerFd>),
    Inotify(inotify::Capability),
    Epoll(DirectEpoll),
    Unix {
        data: Arc<ipc::channel::Resource>,
        side: usize,
    },
    Pty {
        data: Arc<pty::PtyIo>,
        master: bool,
    },
    Pipe {
        data: Arc<PipeResource>,
        read: bool,
        write: bool,
        initial_write_epoch: u64,
    },
}
#[derive(Clone)]
pub(super) enum WatchResource {
    Shared(std::sync::Weak<SharedOpenDescription>),
    Owner(DirectFd),
}
impl WatchResource {
    pub(super) fn live(&self) -> bool {
        match self {
            Self::Shared(open) => open.strong_count() != 0,
            Self::Owner(fd) => fd.origin.as_ref().is_none_or(OfdIdentity::is_live),
        }
    }
    fn accepted(fd: &DirectFd) -> Self {
        if let Some(file) = &fd._file {
            Self::Shared(Arc::downgrade(&file.open))
        } else {
            Self::Owner(fd.clone())
        }
    }
    pub(super) fn capture(
        open: &OpenWeak,
        polls: Option<&BTreeMap<usize, Arc<dyn DirectPoll>>>,
    ) -> Option<Self> {
        match open {
            OpenWeak::Shared(open) => Some(Self::Shared(open.clone())),
            OpenWeak::Owner(_) => {
                let open = open.upgrade()?;
                let open = open.borrow();
                let fd = match polls {
                    Some(polls) => DirectFd::snapshot_poll(&open, polls),
                    None => {
                        DirectFd::snapshot(&open).or_else(|| DirectFd::snapshot_tcp_poll(&open))
                    }
                }?;
                Some(Self::Owner(fd))
            }
        }
    }
    pub(super) fn resolve(&self) -> Option<DirectFd> {
        match self {
            Self::Shared(open) => SharedFd::new(open.upgrade()?).direct_byte(),
            Self::Owner(fd) => fd
                .origin
                .as_ref()
                .is_none_or(OfdIdentity::is_live)
                .then(|| fd.clone()),
        }
    }
}
pub(super) type DirectWatch = ((u32, u64), Arc<Mutex<events::WatchState>>, WatchResource);
#[derive(Clone)]
struct DirectEpoll {
    watches: Option<Arc<Vec<DirectWatch>>>,
    live: Arc<epoll::LiveEpoll>,
}
struct WatchSnapshot<'a> {
    live: Arc<Vec<DirectWatch>>,
    frozen: &'a [DirectWatch],
}
impl WatchSnapshot<'_> {
    fn iter(&self) -> impl Iterator<Item = &DirectWatch> {
        epoll::ordered(&self.live, self.frozen, None)
    }
}
impl DirectEpoll {
    fn snapshot(&self) -> WatchSnapshot<'_> {
        WatchSnapshot {
            live: self.live.snapshot(),
            frozen: self.watches.as_deref().map_or(&[], |w| w.as_slice()),
        }
    }
}
/// Retained byte authority with immutable access bits and live OFD status.
/// It is Send + Sync by composition; no unsafe Rc/RefCell conversion is used.
#[derive(Clone)]
pub struct DirectFd {
    resource: ByteResource,
    flags: u32,
    status: StatusFlags,
    _file: Option<SharedFd>,
    origin: Option<OfdIdentity>,
}
impl DirectFd {
    pub(super) fn tcp_poll(open: &Arc<SharedOpenDescription>, tcp: trames_net::TcpPoll) -> Self {
        Self {
            resource: ByteResource::TcpPoll(tcp),
            flags: open.flags.get(),
            status: open.flags.clone(),
            _file: None,
            origin: Some(OfdIdentity::new(open)),
        }
    }
    pub(super) fn snapshot_tcp_poll(open: &OpenDescription) -> Option<Self> {
        Some(Self::tcp_poll(
            &open.shared,
            open.socket.as_ref()?.direct_tcp()?.poll_only(),
        ))
    }
    pub fn ofd_identity(&self) -> OfdIdentity {
        self._file.as_ref().map_or_else(
            || self.origin.as_ref().expect("prepared OFD identity").clone(),
            SharedFd::ofd_identity,
        )
    }
    pub fn shared_file(&self) -> Option<SharedFd> {
        self._file.clone()
    }
    pub fn retains_ofd(&self) -> bool {
        self._file.is_some()
    }
    pub(super) fn regular_poll(open: &SharedOpenDescription) -> Self {
        Self {
            resource: ByteResource::Regular,
            flags: open.flags.get(),
            status: open.flags.clone(),
            _file: None,
            origin: None,
        }
    }
    pub(super) fn shared_byte(open: &SharedOpenDescription) -> Option<Self> {
        let resource = match &open.control {
            Some(events::SharedControl::Event(counter)) => ByteResource::Event(counter.clone()),
            Some(events::SharedControl::Timer(timer)) => ByteResource::Timer(timer.clone()),
            Some(events::SharedControl::Inotify(instance)) => {
                ByteResource::Inotify(instance.capability())
            }
            Some(events::SharedControl::Epoll(live)) => {
                if live.owner_count() != 0 {
                    return None;
                }
                ByteResource::Epoll(DirectEpoll {
                    watches: None,
                    live: live.clone(),
                })
            }
            None => {
                let end = open.pipe.as_ref()?;
                ByteResource::Pipe {
                    data: end.data.clone(),
                    read: end.read,
                    write: end.write,
                    initial_write_epoch: end.initial_write_epoch,
                }
            }
        };
        Some(Self {
            resource,
            flags: open.flags.get(),
            status: open.flags.clone(),
            _file: None,
            origin: None,
        })
    }
    pub(super) fn with_ofd(mut self, file: SharedFd) -> Self {
        self._file = Some(file);
        self
    }
    // A conservative scheduling hint, never an access/FD authority check.
    // Live interests exclude nested epoll; frozen owner captures follow the
    // validated acyclic owner graph, so this traversal cannot cycle.
    fn shares_resource(&self, other: &Self) -> bool {
        match (&self.resource, &other.resource) {
            (ByteResource::TcpPoll(a), ByteResource::TcpPoll(b)) => a.shares_socket(b),
            (ByteResource::Kmsg(a), ByteResource::Kmsg(b)) => a.same_log(b),
            (ByteResource::Epoll(a), _) => a
                .snapshot()
                .iter()
                .any(|(_, _, fd)| fd.resolve().is_some_and(|fd| fd.shares_resource(other))),
            (_, ByteResource::Epoll(b)) => b
                .snapshot()
                .iter()
                .any(|(_, _, fd)| fd.resolve().is_some_and(|fd| self.shares_resource(&fd))),
            (ByteResource::Event(a), ByteResource::Event(b)) => Arc::ptr_eq(a, b),
            (ByteResource::Timer(a), ByteResource::Timer(b)) => Arc::ptr_eq(a, b),
            (ByteResource::Inotify(a), ByteResource::Inotify(b)) => Arc::ptr_eq(&a.queue, &b.queue),
            (ByteResource::Pipe { data: a, .. }, ByteResource::Pipe { data: b, .. }) => {
                Arc::ptr_eq(a, b)
            }
            (ByteResource::Unix { data: a, .. }, ByteResource::Unix { data: b, .. }) => {
                Arc::ptr_eq(a, b)
            }
            (ByteResource::Pty { data: a, .. }, ByteResource::Pty { data: b, .. }) => {
                Arc::ptr_eq(a, b)
            }
            _ => false,
        }
    }
    /// Native interests of this accepted resource, not every open watch.
    pub fn native_wait_fds(&self) -> Vec<HostFd> {
        match &self.resource {
            ByteResource::TcpPoll(tcp) => tcp.poll_event_fd().map(Into::into).into_iter().collect(),
            ByteResource::Timer(timer) => timer.native_fd().into_iter().collect(),
            #[cfg(all(feature = "hostfs", unix))]
            ByteResource::Inotify(queue) => queue.native_fd().map(Into::into).into_iter().collect(),
            ByteResource::Epoll(epoll) => epoll
                .snapshot()
                .iter()
                .filter(|(_, state, _)| state.lock().unwrap().armed)
                .filter_map(|(_, _, fd)| fd.resolve())
                .flat_map(|fd| fd.native_wait_fds())
                .collect(),
            _ => Vec::new(),
        }
    }
    pub fn subscribe(&self, signal: &Arc<crate::IoSignal>) -> Vec<crate::IoSubscription> {
        match &self.resource {
            ByteResource::TcpPoll(tcp) => vec![IoSubscription::native(
                tcp.poll_event_fd().map(Into::into),
                signal,
            )],
            ByteResource::Mounts(watch) => vec![watch.subscribe(signal)],
            ByteResource::Regular => Vec::new(),
            ByteResource::Kmsg(log) => vec![log.subscribe(signal)],
            ByteResource::PollOnly(poll) => vec![poll.subscribe(signal)],
            ByteResource::Event(counter) => vec![counter.readiness.subscribe(signal)],
            ByteResource::Timer(timer) => vec![timer.subscribe(signal)],
            ByteResource::Inotify(queue) => vec![queue.queue.subscribe(signal)],
            ByteResource::Pipe { data, .. } => vec![data.readiness.subscribe(signal)],
            ByteResource::Unix { data, .. } => vec![data.readiness.subscribe(signal)],
            ByteResource::Pty { data, .. } => vec![data.subscribe(signal)],
            ByteResource::Epoll(epoll) => {
                let mut subscriptions = vec![epoll.live.changed.subscribe(signal)];
                subscriptions.extend(
                    epoll
                        .snapshot()
                        .iter()
                        .filter(|(_, state, _)| state.lock().unwrap().armed)
                        .flat_map(|(_, _, fd)| {
                            fd.resolve()
                                .map(|fd| fd.subscribe(signal))
                                .unwrap_or_default()
                        }),
                );
                subscriptions
            }
        }
    }
    pub(super) fn snapshot(open: &OpenDescription) -> Option<Self> {
        let resource = if let Some(file) = &open.mount_file {
            ByteResource::Mounts(file.watch.clone())
        } else if let Some(log) = &open.kernel_log {
            ByteResource::Kmsg(log.clone())
        } else if let Some(events::Anonymous::Event(counter)) = &open.anonymous {
            ByteResource::Event(counter.clone())
        } else if let Some(events::Anonymous::Timer(timer)) = &open.anonymous {
            ByteResource::Timer(timer.clone())
        } else if let Some(events::Anonymous::Inotify(instance)) = &open.anonymous {
            ByteResource::Inotify(instance.capability())
        } else if let Some(events::Anonymous::Epoll {
            watches, shared, ..
        }) = &open.anonymous
        {
            let mut direct = Vec::new();
            for (&key, watch) in watches {
                if watch.open.strong_count() != 0 {
                    direct.push((
                        key,
                        watch.state.clone(),
                        WatchResource::capture(&watch.open, None)?,
                    ));
                }
            }
            ByteResource::Epoll(DirectEpoll {
                watches: (!direct.is_empty()).then(|| Arc::new(direct)),
                live: shared.clone(),
            })
        } else if matches!(open.kind, FdKind::PipeRead | FdKind::PipeWrite) {
            let end = open.pipe.as_ref()?;
            ByteResource::Pipe {
                data: end.data.clone(),
                read: end.read,
                write: end.write,
                initial_write_epoch: end.initial_write_epoch,
            }
        } else if let Some((data, side)) = open.local.as_ref().and_then(|s| s.direct()) {
            ByteResource::Unix { data, side }
        } else if let Some(end) = &open.pty {
            ByteResource::Pty {
                data: end.pair.io.clone(),
                master: end.master,
            }
        } else {
            return None;
        };
        Some(Self {
            resource,
            flags: open.flags.get(),
            status: open.flags.clone(),
            _file: None,
            origin: Some(OfdIdentity::new(&open.shared)),
        })
    }
    /// Ring RECV has an explicit copied/reported length ABI. Keep the general
    /// scalar syscall snapshot's existing admission unchanged.
    pub(super) fn snapshot_uring(open: &OpenDescription) -> Option<Self> {
        Self::snapshot(open).or_else(|| {
            let (data, side) = open.local.as_ref()?.direct_message()?;
            Some(Self {
                resource: ByteResource::Unix { data, side },
                flags: open.flags.get(),
                status: open.flags.clone(),
                _file: None,
                origin: Some(OfdIdentity::new(&open.shared)),
            })
        })
    }
    fn snapshot_poll(
        open: &OpenDescription,
        polls: &BTreeMap<usize, Arc<dyn DirectPoll>>,
    ) -> Option<Self> {
        if let Some(fd) = Self::snapshot_tcp_poll(open) {
            return Some(fd);
        }
        if let Some(file) = &open.mount_file {
            return Some(Self {
                resource: ByteResource::Mounts(file.watch.clone()),
                flags: open.flags.get(),
                status: open.flags.clone(),
                _file: None,
                origin: Some(OfdIdentity::new(&open.shared)),
            });
        }
        let resource = match &open.anonymous {
            Some(events::Anonymous::Uring(ring)) => {
                ByteResource::PollOnly(polls.get(&(Rc::as_ptr(ring) as usize))?.clone())
            }
            Some(events::Anonymous::Epoll {
                watches, shared, ..
            }) => {
                let mut direct = Vec::new();
                for (&key, watch) in watches {
                    if watch.open.strong_count() != 0 {
                        direct.push((
                            key,
                            watch.state.clone(),
                            WatchResource::capture(&watch.open, Some(polls))?,
                        ));
                    }
                }
                ByteResource::Epoll(DirectEpoll {
                    watches: (!direct.is_empty()).then(|| Arc::new(direct)),
                    live: shared.clone(),
                })
            }
            _ => return Self::snapshot(open),
        };
        Some(Self {
            resource,
            flags: open.flags.get(),
            status: open.flags.clone(),
            _file: None,
            origin: Some(OfdIdentity::new(&open.shared)),
        })
    }
    pub fn is_poll_only(&self) -> bool {
        matches!(
            self.resource,
            ByteResource::TcpPoll(_)
                | ByteResource::PollOnly(_)
                | ByteResource::Regular
                | ByteResource::Mounts(_)
        )
    }
    pub fn poll_identities(&self) -> Vec<usize> {
        match &self.resource {
            ByteResource::PollOnly(poll) => vec![poll.identity()],
            ByteResource::Epoll(epoll) => epoll
                .snapshot()
                .iter()
                .filter(|(_, state, _)| state.lock().unwrap().armed)
                .flat_map(|(_, _, fd)| {
                    fd.resolve()
                        .map(|fd| fd.poll_identities())
                        .unwrap_or_default()
                })
                .collect(),
            _ => Vec::new(),
        }
    }
    pub fn is_epoll(&self) -> bool {
        matches!(self.resource, ByteResource::Epoll(_))
    }
    pub fn is_unix(&self) -> bool {
        matches!(self.resource, ByteResource::Unix { .. })
    }
    pub fn is_pty(&self) -> bool {
        matches!(self.resource, ByteResource::Pty { .. })
    }
    pub fn is_inotify(&self) -> bool {
        matches!(self.resource, ByteResource::Inotify(_))
    }
    pub fn inotify_remove(&self, wd: i32) -> Result<u64> {
        let ByteResource::Inotify(queue) = &self.resource else {
            return Err(Errno(22));
        };
        if self.flags & O_PATH != 0 {
            return Err(Errno(22));
        }
        queue.remove_watch(wd).map(|()| 0)
    }
    pub fn terminal_query(&self, request: u32) -> Option<Vec<u8>> {
        if self.flags & O_PATH != 0 {
            return None;
        }
        match &self.resource {
            ByteResource::Pty { data, .. } => data.query(request),
            _ => None,
        }
    }
    pub fn terminal_read(
        &self,
        count: usize,
        access: Option<pty::TerminalAccess>,
    ) -> Option<Result<Vec<u8>>> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 1 {
            return Some(Err(Errno(9)));
        }
        match &self.resource {
            ByteResource::Pty { data, master } => data.read(*master, count, access),
            _ => None,
        }
    }
    pub fn terminal_write(
        &self,
        bytes: &[u8],
        access: Option<pty::TerminalAccess>,
    ) -> Option<Result<usize>> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 0 {
            return Some(Err(Errno(9)));
        }
        match &self.resource {
            ByteResource::Pty { data, master } => data.write(*master, bytes, access),
            _ => None,
        }
    }
    pub fn timer(&self) -> Option<&TimerFd> {
        if let ByteResource::Timer(timer) = &self.resource {
            Some(timer)
        } else {
            None
        }
    }
    pub fn poll_ready(&self, events: u16) -> Option<u16> {
        (!self.is_epoll()).then(|| self.poll(events).0)
    }
    /// Preserve the original poll epoch for worker multishot edge detection.
    pub fn poll_state(&self, events: u16) -> Option<(u16, [u64; 2])> {
        (!self.is_epoll()).then(|| self.poll(events))
    }
    pub fn next_deadline(&self) -> Option<std::time::Instant> {
        match &self.resource {
            ByteResource::Timer(timer) => timer.deadline(),
            ByteResource::Epoll(epoll) => epoll
                .snapshot()
                .iter()
                .filter_map(|(_, state, fd)| {
                    let fd = fd.resolve()?;
                    let state = state.lock().unwrap();
                    (state.armed && state.events & 1 != 0)
                        .then(|| fd.next_deadline())
                        .flatten()
                })
                .min(),
            _ => None,
        }
    }
    pub fn has_readable_bytes(&self) -> bool {
        matches!(
            self.resource,
            ByteResource::Unix { .. }
                | ByteResource::Pipe { .. }
                | ByteResource::Pty { .. }
                | ByteResource::Inotify(_)
        )
    }
    pub fn readable_bytes(&self) -> usize {
        match &self.resource {
            ByteResource::Unix { data, side } => data.readable_bytes(*side),
            ByteResource::Pipe { data, .. } => data.lock().unwrap().bytes.len(),
            ByteResource::Pty { data, master } => data.readable_bytes(*master),
            ByteResource::Inotify(queue) => queue.available(),
            _ => unreachable!("readable byte resource"),
        }
    }
    pub fn shutdown(&self, how: u32) -> Result<()> {
        match &self.resource {
            ByteResource::Unix { data, side } => data.shutdown(*side, how),
            _ => Err(Errno(88)),
        }
    }
    fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let ready = self.peek_poll(events);
        if let ByteResource::Mounts(watch) = &self.resource {
            if events != 0 {
                watch.acknowledge(ready.1[0]);
            }
        }
        ready
    }
    pub(super) fn peek_poll(&self, events: u16) -> (u16, [u64; 2]) {
        match &self.resource {
            ByteResource::TcpPoll(tcp) => tcp.poll(events).unwrap_or((32, [0; 2])),
            ByteResource::Mounts(watch) => watch.peek(events),
            ByteResource::Regular => (events & 5, [0; 2]),
            ByteResource::Kmsg(log) => log.poll(events),
            ByteResource::PollOnly(poll) => poll.poll(events),
            ByteResource::Event(counter) => (counter.poll(events), counter.epoch()),
            ByteResource::Timer(timer) => timer.poll(events),
            ByteResource::Inotify(queue) => queue.poll(events),
            ByteResource::Unix { data, side } => data.poll(*side, events),
            ByteResource::Pty { data, master } => data.poll_state(*master, events),
            ByteResource::Pipe {
                data,
                read,
                initial_write_epoch,
                ..
            } => {
                let data = data.lock().unwrap();
                let ready = if *read {
                    (if data.bytes.is_empty() { 0 } else { events & 1 })
                        | (if data.writers == 0 && data.write_epoch != *initial_write_epoch {
                            16
                        } else {
                            0
                        })
                } else if data.readers == 0 {
                    8
                } else if PIPE_CAPACITY - data.bytes.len() >= 4096 {
                    events & 4
                } else {
                    0
                };
                (ready, data.io_epoch)
            }
            ByteResource::Epoll(epoll) => {
                let mut ready = false;
                let mut generation = 0u64;
                for (_, state, resource) in epoll.snapshot().iter() {
                    let state = state.lock().unwrap();
                    if state.armed {
                        if let Some(fd) = resource.resolve() {
                            let (events, epoch) = fd.peek_poll(state.events as u16);
                            generation = generation.wrapping_add(epoch[0]).wrapping_add(epoch[1]);
                            ready |= events != 0 && state.ready(events, epoch);
                        }
                    }
                }
                (if ready { events & 1 } else { 0 }, [generation, 0])
            }
        }
    }
    pub fn epoll_wait(&self, max: usize) -> Result<Vec<(u32, u64)>> {
        let ByteResource::Epoll(epoll) = &self.resource else {
            return Err(Errno(22));
        };
        epoll
            .live
            .wait(max, epoll.watches.as_deref().map_or(&[], |w| w.as_slice()))
    }
    pub fn epoll_revision(&self) -> Option<u64> {
        if let ByteResource::Epoll(epoll) = &self.resource {
            Some(epoll.live.revision())
        } else {
            None
        }
    }
    pub(super) fn acknowledge(&self, epoch: [u64; 2]) {
        if let ByteResource::Mounts(watch) = &self.resource {
            watch.acknowledge(epoch[0]);
        }
    }

    pub fn is_eventfd(&self) -> bool {
        matches!(self.resource, ByteResource::Event(_))
    }
    pub fn is_kmsg(&self) -> bool {
        matches!(self.resource, ByteResource::Kmsg(_))
    }
    pub fn kmsg_seek(&self, offset: i64, whence: u32) -> Result<u64> {
        if self.flags & O_PATH != 0 {
            return Err(Errno(9));
        }
        let ByteResource::Kmsg(log) = &self.resource else {
            return Err(Errno(29));
        };
        log.seek(offset, whence)
    }
    pub fn readv_records(&self) -> bool {
        matches!(
            self.resource,
            ByteResource::Event(_) | ByteResource::Inotify(_)
        )
    }
    pub fn nonblocking(&self) -> bool {
        self.status.get() & O_NONBLOCK != 0
    }
    pub fn read(&self, count: usize) -> Result<Vec<u8>> {
        self.read_attempt(count).unwrap_or(Err(Errno(95)))
    }
    /// None requests the original owner before consuming any bytes or rights.
    pub fn read_attempt(&self, count: usize) -> Option<Result<Vec<u8>>> {
        if self.is_unix() {
            return self.recv(count, 0);
        }
        if self.flags & O_PATH != 0 || self.flags & 3 == 1 {
            return Some(Err(Errno(9)));
        }
        Some(match &self.resource {
            ByteResource::Kmsg(log) => log.read(count),
            ByteResource::Event(counter) => counter.read(count),
            ByteResource::Timer(timer) => timer.read(count),
            ByteResource::Inotify(queue) => queue.read(count),
            ByteResource::Epoll(_)
            | ByteResource::TcpPoll(_)
            | ByteResource::PollOnly(_)
            | ByteResource::Regular
            | ByteResource::Mounts(_) => Err(Errno(22)),
            ByteResource::Pipe { data, read, .. } => {
                if !read {
                    return Some(Err(Errno(9)));
                }
                data.lock().unwrap().read(count)
            }
            ByteResource::Unix { .. } => unreachable!("handled Unix receive"),
            ByteResource::Pty { .. } => return self.terminal_read(count, None),
        })
    }
    pub fn recv(&self, count: usize, flags: u32) -> Option<Result<Vec<u8>>> {
        self.recv_counted(count, flags)
            .map(|r| r.map(|(bytes, _)| bytes))
    }
    /// MSG_TRUNC reports the original packet length without extending the
    /// copied data. Both paths use the original Unix byte/rights algorithm.
    pub fn recv_counted(&self, count: usize, flags: u32) -> Option<Result<(Vec<u8>, usize)>> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 1 {
            return Some(Err(Errno(9)));
        }
        let ByteResource::Unix { data, side } = &self.resource else {
            return None;
        };
        data.recv(*side, count, flags, false).map(|r| {
            r.map(|r| {
                let length = if flags & 0x20 != 0 {
                    r.length
                } else {
                    r.data.len()
                };
                (r.data, length)
            })
        })
    }
    pub fn send(&self, bytes: &[u8], flags: u32) -> Result<usize> {
        self.send_credentials(bytes, flags, None)
    }
    pub fn send_credentials(
        &self,
        bytes: &[u8],
        flags: u32,
        credentials: Option<[u32; 3]>,
    ) -> Result<usize> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 0 {
            return Err(Errno(9));
        }
        match &self.resource {
            ByteResource::Unix { data, side } => {
                data.send_credentials(*side, bytes, flags, None, credentials)
            }
            _ => Err(Errno(88)),
        }
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 0 {
            return Err(Errno(9));
        }
        match &self.resource {
            ByteResource::Kmsg(log) => log.write(bytes),
            ByteResource::Mounts(_) => Err(Errno(22)),
            ByteResource::Event(counter) => counter.write(bytes),
            ByteResource::Epoll(_)
            | ByteResource::TcpPoll(_)
            | ByteResource::PollOnly(_)
            | ByteResource::Regular
            | ByteResource::Timer(_)
            | ByteResource::Inotify(_) => Err(Errno(22)),
            ByteResource::Unix { .. } => self.send(bytes, 0),
            ByteResource::Pty { .. } => self.terminal_write(bytes, None).unwrap_or(Err(Errno(95))),
            ByteResource::Pipe { data, write, .. } => {
                if !write {
                    return Err(Errno(9));
                }
                data.lock().unwrap().write(bytes)
            }
        }
    }
}

#[derive(Clone, Default)]
pub struct DirectFds(
    pub(super) Arc<[Option<DirectFd>]>,
    pub(super) Option<SharedFiles>,
);
impl DirectFds {
    pub fn shared_files(&self) -> Option<SharedFiles> {
        self.1.clone()
    }
    pub fn get(&self, fd: u32) -> Option<DirectFd> {
        if let Some(result) = self.1.as_ref().and_then(|files| files.poll_lookup(fd)) {
            return match result.ok()? {
                fd_table::PollOpen::Shared(file) => file.direct_poll(),
                fd_table::PollOpen::Tcp(open, tcp) => Some(DirectFd::tcp_poll(&open, tcp)),
                fd_table::PollOpen::Epoll(open) => {
                    let mut fd = DirectFd::shared_byte(&open)?;
                    fd.origin = Some(OfdIdentity::new(&open));
                    Some(fd)
                }
            };
        }
        if let Some(open) = self.1.as_ref().and_then(|files| files.control_open(fd)) {
            if let Some(events::SharedControl::Epoll(live)) = &open.control {
                if live.owner_count() == 0 {
                    let mut result = DirectFd::shared_byte(&open)?;
                    result.origin = Some(OfdIdentity::new(&open));
                    return Some(result);
                }
                let cached = self.0.get(fd as usize)?.as_ref()?;
                if let ByteResource::Epoll(epoll) = &cached.resource {
                    return Arc::ptr_eq(live, &epoll.live).then(|| cached.clone());
                }
            }
            return None;
        }
        let cached = self.0.get(fd as usize)?.clone()?;
        (!cached.is_epoll()).then_some(cached)
    }
    pub fn epoll_control(
        &self,
        fd: u32,
        op: u32,
        target: u32,
        events: u32,
        data: u64,
    ) -> Option<Result<()>> {
        let open = self.1.as_ref()?.control_open(fd)?;
        let Some(events::SharedControl::Epoll(live)) = &open.control else {
            return None;
        };
        let target_fd = self.get(target)?;
        let identity = target_fd.ofd_identity();
        let target_open = identity.open()?;
        if Arc::ptr_eq(&open, &target_open) {
            return Some(Err(Errno(22)));
        }
        if target_fd.is_epoll() {
            return None;
        }
        if matches!(target_fd.resource, ByteResource::Regular) {
            return Some(Err(Errno(1)));
        }
        let key = (target, target_open.id);
        if live.owner_count() != 0 && !live.contains(key) {
            return None;
        }
        Some(live.update(key, op, events, data, WatchResource::accepted(&target_fd)))
    }
    fn candidates(&self) -> Vec<DirectFd> {
        self.0
            .iter()
            .flatten()
            .cloned()
            .chain(
                self.1
                    .iter()
                    .flat_map(SharedFiles::byte_descriptions)
                    .filter_map(SharedFd::direct_byte),
            )
            .collect()
    }
    pub fn shares_with<'a>(&self, resources: impl Iterator<Item = &'a DirectFd>) -> bool {
        let candidates = self.candidates();
        resources.into_iter().any(|fd| {
            candidates
                .iter()
                .any(|candidate| candidate.shares_resource(fd))
        })
    }
    /// Related retained resources can justify admitting a blocked I/O peer
    /// alongside one runnable task. Unrelated idle terminals/control pipes
    /// alone must not force a CPU-only process off the serial MMU path.
    pub fn shares_resources(&self, other: &Self) -> bool {
        let ours = self.candidates();
        let theirs = other.candidates();
        ours.iter()
            .any(|a| theirs.iter().any(|b| a.shares_resource(b)))
    }
}
impl Vfs {
    pub fn native_event(&self, fd: u32) -> Result<NativeEvent> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        match &open.control {
            Some(events::SharedControl::Event(counter)) if open.flags.get() & O_PATH == 0 => {
                counter.native_writers.fetch_add(1, Ordering::Relaxed);
                Ok(NativeEvent(Arc::new(NativeWriter {
                    counter: counter.clone(),
                    owner: std::thread::current(),
                })))
            }
            _ => Err(Errno(22)),
        }
    }
    /// Live eventfds with retained native producers are external event sources,
    /// just like open native sockets. A plain guest eventfd is not one.
    pub fn native_wait_fds_for(&self, fd: u32) -> Vec<HostFd> {
        self.descriptor(fd)
            .map_or_else(|_| Vec::new(), |d| native_wait_open(&d.open.borrow()))
    }
    pub fn native_wait_fds(&self) -> Vec<HostFd> {
        #[cfg(all(feature = "hostfs", unix))]
        return self
            .fds
            .entries()
            .values()
            .filter_map(|descriptor| {
                let open = descriptor.open.borrow();
                match &open.control {
                    Some(events::SharedControl::Inotify(instance)) => {
                        instance.queue.native_fd().map(Into::into)
                    }
                    _ => None,
                }
            })
            .collect();
        #[cfg(not(all(feature = "hostfs", unix)))]
        Vec::new()
    }
    pub fn has_native_event_sources(&self) -> bool {
        self.fds.entries().values().any(|descriptor| {
            let open = descriptor.open.borrow();
            match &open.control {
                Some(events::SharedControl::Event(counter)) => {
                    counter.native_writers.load(Ordering::Relaxed) != 0
                }
                Some(events::SharedControl::Inotify(instance)) => instance.queue.has_native(),
                _ => false,
            }
        })
    }
    /// Legacy record readers consume each nonempty iovec independently.
    /// A single inotify event cannot be split across two short destinations.
    pub fn readv_records(&self, fd: u32) -> Result<bool> {
        Ok(matches!(
            self.descriptor(fd)?.open.borrow().anonymous,
            Some(events::Anonymous::Event(_) | events::Anonymous::Inotify(_))
        ))
    }
    pub fn is_eventfd(&self, fd: u32) -> Result<bool> {
        Ok(matches!(
            self.descriptor(fd)?.open.borrow().anonymous,
            Some(events::Anonymous::Event(_))
        ))
    }
    pub fn direct_descriptors_with_polls(
        &self,
        polls: &BTreeMap<usize, Arc<dyn DirectPoll>>,
    ) -> DirectFds {
        self.promote_tcp_epoll_watches();
        let descriptors = self.fds.entries();
        let mut entries = vec![
            None;
            descriptors
                .last_key_value()
                .map_or(0, |(&fd, _)| fd as usize + 1)
        ];
        for (&fd, descriptor) in descriptors.iter() {
            if matches!(descriptor.open, open_handle::OpenView::Owner(_)) {
                entries[fd as usize] = DirectFd::snapshot_poll(&descriptor.open.borrow(), polls);
            }
        }
        DirectFds(entries.into(), Some(self.shared_files()))
    }
    pub fn direct_descriptors(&self) -> DirectFds {
        self.promote_tcp_epoll_watches();
        self.descriptor_snapshots().1
    }
}

fn native_wait_open(open: &OpenDescription) -> Vec<HostFd> {
    match &open.anonymous {
        Some(events::Anonymous::Timer(timer)) => timer.native_fd().into_iter().collect(),
        #[cfg(all(feature = "hostfs", unix))]
        Some(events::Anonymous::Inotify(instance)) => instance
            .queue
            .native_fd()
            .map(Into::into)
            .into_iter()
            .collect(),
        Some(events::Anonymous::Epoll {
            watches, shared, ..
        }) => shared
            .snapshot()
            .iter()
            .filter(|w| w.1.lock().unwrap().armed)
            .filter_map(|w| w.2.resolve())
            .flat_map(|fd| fd.native_wait_fds())
            .chain(
                watches
                    .values()
                    .filter(|watch| watch.state.lock().unwrap().armed)
                    .filter_map(|watch| watch.open.upgrade())
                    .flat_map(|open| native_wait_open(&open.borrow())),
            )
            .collect(),
        _ => Vec::new(),
    }
}
impl RetainedFd {
    pub fn native_wait_fds(&self) -> Vec<HostFd> {
        native_wait_open(&self.0.open.borrow())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};
    #[test]
    fn live_epoll_controls_reach_old_views_and_never_retarget_reused_numbers() {
        let mut v = Vfs::default();
        let direct = v.direct_descriptors(); // before either resource exists
        let ep = v.epoll_create(0).unwrap();
        let event = v.eventfd(1, 0).unwrap();
        let alias = v.dup(event, 0, false).unwrap();
        let wait = direct.get(ep).unwrap();
        assert_eq!(
            direct.epoll_control(ep, 1, event, 0xc0000001, 42),
            Some(Ok(()))
        );
        assert_eq!(
            direct.epoll_control(ep, 1, event, 1, 99),
            Some(Err(Errno(17)))
        );
        assert_eq!(wait.epoll_wait(1).unwrap(), vec![(1, 42)]);
        assert!(wait.epoll_wait(1).unwrap().is_empty());
        assert_eq!(
            direct.epoll_control(ep, 3, event, 0xc0000001, 43),
            Some(Ok(()))
        );
        assert_eq!(wait.epoll_wait(1).unwrap(), vec![(1, 43)]);
        assert_eq!(direct.epoll_control(ep, 3, event, 1, 44), Some(Ok(())));
        v.close(event).unwrap();
        let replacement = v.eventfd(0, 0).unwrap();
        assert_eq!(replacement, event);
        assert_eq!(
            direct.epoll_control(ep, 2, replacement, 0, 0),
            Some(Err(Errno(2)))
        );
        assert_eq!(wait.epoll_wait(1).unwrap(), vec![(1, 44)]); // real alias remains
        v.close(alias).unwrap();
        assert!(wait.epoll_wait(1).unwrap().is_empty());
        assert_eq!(
            direct.epoll_control(ep, 1, replacement, 1, 45),
            Some(Ok(()))
        );
        assert!(wait.epoll_wait(1).unwrap().is_empty());
        v.write(replacement, &1u64.to_le_bytes()).unwrap();
        assert_eq!(wait.epoll_wait(1).unwrap(), vec![(1, 45)]);
        assert_eq!(direct.epoll_control(ep, 2, replacement, 0, 0), Some(Ok(())));
        assert!(wait.epoll_wait(1).unwrap().is_empty());
    }
    #[test]
    fn live_shared_and_owner_interests_share_the_original_limit_and_cursor() {
        let mut v = Vfs::default();
        let ep = v.epoll_create(0).unwrap();
        let signal = v.signalfd(-1, 1 << 10, 0).unwrap();
        v.epoll_ctl(ep, 1, signal, 1, 100).unwrap();
        let mut events = Vec::new();
        for i in 0..1023 {
            let fd = v.eventfd(u32::from(i == 0), 0).unwrap();
            v.epoll_ctl(ep, 1, fd, 1, i).unwrap();
            events.push(fd);
        }
        let extra = v.eventfd(0, 0).unwrap();
        assert_eq!(v.epoll_ctl(ep, 1, extra, 1, 2000), Err(Errno(28)));
        v.close(*events.last().unwrap()).unwrap();
        assert_eq!(v.epoll_ctl(ep, 1, extra, 1, 2000), Ok(()));
        let a = v
            .epoll_wait_signals(ep, 1, 1 << 10, |_, _| Ok(None))
            .unwrap();
        let b = v
            .epoll_wait_signals(ep, 1, 1 << 10, |_, _| Ok(None))
            .unwrap();
        assert_eq!(a, vec![(1, 100)]);
        assert_eq!(b, vec![(1, 0)]);
        // A signal-dependent interest still uses its original owner authority.
        assert!(v.direct_descriptors().get(ep).is_none());
    }
    #[test]
    fn concurrent_live_epoll_registration_has_one_winner_and_one_oneshot() {
        let mut v = Vfs::default();
        let ep = v.epoll_create(0).unwrap();
        let event = v.eventfd(1, 0).unwrap();
        let direct = v.direct_descriptors();
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        direct.epoll_control(ep, 1, event, 0x40000001, 1).unwrap()
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| **r == Err(Errno(17))).count(), 7);
        let deliveries: usize = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| direct.get(ep).unwrap().epoll_wait(1).unwrap().len()))
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).sum()
        });
        assert_eq!(deliveries, 1);
    }
    #[test]
    fn live_byte_lookup_follows_reuse_and_new_aliases_while_accepted_calls_keep_original_ofds() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let bytes = v.direct_descriptors();
        let old_reader = bytes.get(reader).unwrap();
        let old_writer = bytes.get(writer).unwrap();
        let (old_ofd, old_data) = {
            let d = v.descriptor(writer).unwrap();
            let o = d.open.borrow();
            (
                Arc::downgrade(&o.shared),
                Arc::downgrade(&o.pipe.as_ref().unwrap().data),
            )
        };
        v.close(reader).unwrap();
        v.close(writer).unwrap();
        assert!(bytes.get(reader).is_none());
        let [replacement, new_writer] = v.pipe(O_NONBLOCK).unwrap();
        assert_eq!(replacement, reader);
        let alias = v
            .shared_files()
            .duplicate(new_writer, 200, false)
            .unwrap()
            .unwrap();
        assert_eq!(alias, 200);
        assert_eq!(bytes.get(alias).unwrap().write(b"new"), Ok(3));
        assert_eq!(old_writer.write(b"old"), Ok(3));
        assert_eq!(old_reader.read(3).unwrap(), b"old");
        assert_eq!(bytes.get(replacement).unwrap().read(3).unwrap(), b"new");
        drop(old_writer);
        assert!(old_ofd.upgrade().is_none());
        assert!(old_reader.read(1).unwrap().is_empty());
        drop(old_reader);
        assert!(old_data.upgrade().is_none());
        drop(v);
        assert!(bytes.get(replacement).is_none());
        assert!(bytes.get(alias).is_none());
    }

    #[test]
    fn cached_epoll_watch_is_weak_and_never_retargets_a_reused_shared_fd() {
        let mut v = Vfs::default();
        let [reader, writer] = v.pipe(O_NONBLOCK).unwrap();
        let epoll = v.epoll_create(0).unwrap();
        v.epoll_ctl(epoll, 1, reader, 1, 42).unwrap();
        let bytes = v.direct_descriptors();
        let watch = bytes.get(epoll).unwrap();
        let data = {
            let d = v.descriptor(reader).unwrap();
            let o = d.open.borrow();
            Arc::downgrade(&o.pipe.as_ref().unwrap().data)
        };
        v.write(writer, b"queued").unwrap();
        assert_eq!(watch.epoll_wait(1).unwrap(), vec![(1, 42)]);
        let files = v.shared_files();
        thread::scope(|scope| {
            scope
                .spawn(|| files.close(reader, 0).unwrap().unwrap())
                .join()
                .unwrap();
        });
        assert_eq!(v.write(writer, b"x"), Err(Errno(32)));
        assert!(watch.epoll_wait(1).unwrap().is_empty());
        v.close(writer).unwrap();
        assert!(data.upgrade().is_none());
        let [replacement, writer] = v.pipe(O_NONBLOCK).unwrap();
        assert_eq!(replacement, reader);
        v.write(writer, b"new").unwrap();
        assert!(watch.epoll_wait(1).unwrap().is_empty());
        assert_eq!(bytes.get(replacement).unwrap().read(3).unwrap(), b"new");
    }

    #[test]
    fn cohort_resource_hint_follows_aliases_peer_ends_and_epoll_watches() {
        let mut sender = Vfs::default();
        let [read, write] = sender.pipe(0).unwrap();
        let mut receiver = sender.clone();
        sender.close(read).unwrap();
        receiver.close(write).unwrap();
        let epoll = receiver.epoll_create(0).unwrap();
        receiver.epoll_ctl(epoll, 1, read, 1, 42).unwrap();
        assert!(sender
            .direct_descriptors()
            .shares_resources(&receiver.direct_descriptors()));
        let mut other = Vfs::default();
        other.pipe(0).unwrap();
        assert!(!sender
            .direct_descriptors()
            .shares_resources(&other.direct_descriptors()));
        let [a, b] = sender.socketpair(1, 1, 0).unwrap();
        let mut peer = sender.clone();
        sender.close(b).unwrap();
        peer.close(a).unwrap();
        peer.close(write).unwrap();
        assert!(sender
            .direct_descriptors()
            .shares_resources(&peer.direct_descriptors()));
        assert!(
            DirectFd::snapshot(&receiver.descriptor(epoll).unwrap().open.borrow())
                .unwrap()
                .shares_resource(&sender.direct_descriptors().get(write).unwrap())
        );
        // A snapshot comparison may retain bytes but cannot keep the endpoint
        // open or authorize an I/O operation through an epoll watch.
        sender.close(write).unwrap();
        assert!(!sender
            .direct_descriptors()
            .shares_resources(&receiver.direct_descriptors()));
    }

    #[test]
    fn last_close_in_a_different_fd_table_invalidates_epoll_resource_snapshot() {
        let mut parent = Vfs::default();
        let event = parent.eventfd(1, 0).unwrap();
        let ep = parent.epoll_create(0).unwrap();
        parent.epoll_ctl(ep, 1, event, 1, 42).unwrap();
        let mut child = parent.clone();
        child.close(event).unwrap();
        let snapshot = child.direct_descriptors();
        assert_eq!(
            snapshot.get(ep).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 42)]
        );
        // Only the parent's FD table changes. The child's cached epoll cannot
        // count its retained EventCounter as a still-open guest description.
        parent.close(event).unwrap();
        let refreshed = child.direct_descriptors();
        assert!(refreshed.get(ep).unwrap().epoll_wait(1).unwrap().is_empty());
        assert!(child.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap().is_empty());
    }
    #[test]
    fn epoll_delivery_is_shared_with_joined_waiters_and_refreshes_after_ctl() {
        let mut vfs = Vfs::default();
        let event = vfs.eventfd(1, 0).unwrap();
        let ep = vfs.epoll_create(0).unwrap();
        vfs.epoll_ctl(ep, 1, event, 0xc0000001, 123).unwrap();
        let cached = vfs.direct_descriptors();
        let fd = cached.get(ep).unwrap();
        assert_eq!(fd.epoll_wait(1).unwrap(), vec![(1, 123)]);
        assert!(vfs.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap().is_empty());
        vfs.epoll_ctl(ep, 3, event, 0x80000001, 456).unwrap();
        let fresh = vfs.direct_descriptors();
        assert_eq!(
            fresh.get(ep).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 456)]
        );
        assert!(vfs.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap().is_empty());
        vfs.write(event, &1u64.to_le_bytes()).unwrap();
        assert_eq!(
            vfs.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(),
            vec![(1, 456)]
        );
        assert!(fresh.get(ep).unwrap().epoll_wait(1).unwrap().is_empty());
        vfs.epoll_ctl(ep, 3, event, 1, 789).unwrap();
        let fresh = vfs.direct_descriptors();
        assert_eq!(
            fresh.get(ep).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 789)]
        );
        assert_eq!(
            vfs.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(),
            vec![(1, 789)]
        );
        let timer = vfs.timerfd(1, 0).unwrap();
        vfs.epoll_ctl(ep, 1, timer, 1, 321).unwrap();
        assert!(vfs.direct_descriptors().get(ep).is_some());
        let signal = vfs.signalfd(-1, 1, 0).unwrap();
        vfs.epoll_ctl(ep, 1, signal, 1, 322).unwrap();
        assert!(vfs.direct_descriptors().get(ep).is_none());
    }
    #[test]
    fn concurrent_epoll_oneshot_has_only_one_delivery_and_rotates_duplicate_watches() {
        let mut vfs = Vfs::default();
        let a = vfs.eventfd(1, 0).unwrap();
        let b = vfs.eventfd(1, 0).unwrap();
        let ep = vfs.epoll_create(0).unwrap();
        vfs.epoll_ctl(ep, 1, a, 0x40000001, 123).unwrap();
        let direct = vfs.direct_descriptors();
        let deliveries = std::sync::atomic::AtomicUsize::new(0);
        thread::scope(|scope| {
            for _ in 0..8 {
                let deliveries = &deliveries;
                let fd = direct.get(ep).unwrap();
                scope.spawn(move || {
                    deliveries.fetch_add(fd.epoll_wait(1).unwrap().len(), Ordering::Relaxed);
                });
            }
        });
        assert_eq!(deliveries.load(Ordering::Relaxed), 1);
        vfs.epoll_ctl(ep, 3, a, 1, 123).unwrap();
        vfs.epoll_ctl(ep, 1, b, 1, 456).unwrap();
        let direct = vfs.direct_descriptors();
        assert_eq!(
            direct.get(ep).unwrap().epoll_wait(1).unwrap(),
            vec![(1, 456)]
        );
        assert_eq!(
            vfs.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(),
            vec![(1, 123)]
        );
    }
    #[test]
    fn native_producer_liveness_follows_the_retained_event_and_its_live_descriptors() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(0, O_NONBLOCK).unwrap();
        assert!(!vfs.has_native_event_sources());
        let event = vfs.native_event(fd).unwrap();
        let alias = vfs.dup(fd, 0, false).unwrap();
        assert!(vfs.has_native_event_sources());
        let copy = event.clone();
        drop(event);
        assert!(vfs.has_native_event_sources());
        vfs.close(fd).unwrap();
        assert!(vfs.has_native_event_sources());
        vfs.close(alias).unwrap();
        let reused = vfs.eventfd(0, O_NONBLOCK).unwrap();
        assert_eq!(fd, reused);
        assert!(!vfs.has_native_event_sources());
        drop(copy);
        let event = vfs.native_event(reused).unwrap();
        assert!(vfs.has_native_event_sources());
        drop(event);
        assert!(!vfs.has_native_event_sources());
    }
    #[test]
    fn native_completion_preserves_a_joined_owner_wake_before_park() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(0, O_NONBLOCK).unwrap();
        let event = vfs.native_event(fd).unwrap();
        // Consume any pre-existing park token; completion then wins the race
        // with the owner's idle park, with no subscription/CPU worker running.
        std::thread::park_timeout(std::time::Duration::ZERO);
        std::thread::spawn(move || event.notify()).join().unwrap();
        let began = std::time::Instant::now();
        std::thread::park_timeout(std::time::Duration::from_secs(2));
        assert!(began.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(vfs.read(fd, 8).unwrap(), 1u64.to_le_bytes());
    }
    #[test]
    fn native_completion_retains_the_original_event_after_close_and_fd_reuse() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(0, O_NONBLOCK).unwrap();
        let event = vfs.native_event(fd).unwrap();
        let old = vfs.direct_descriptors().get(fd).unwrap();
        vfs.close(fd).unwrap();
        let reused = vfs.eventfd(0, O_NONBLOCK).unwrap();
        assert_eq!(fd, reused);
        std::thread::spawn(move || event.notify()).join().unwrap();
        assert_eq!(old.read(8).unwrap(), 1u64.to_le_bytes());
        assert_eq!(vfs.read(reused, 8), Err(Errno(11)));
    }
    #[test]
    fn atomic_eventfd_and_semaphore_preserve_concurrent_counts() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(0, O_NONBLOCK).unwrap();
        let direct = vfs.direct_descriptors();
        thread::scope(|scope| {
            for _ in 0..4 {
                let counter = direct.get(fd).unwrap();
                scope.spawn(move || {
                    for _ in 0..1024 {
                        assert_eq!(counter.write(&1u64.to_le_bytes()), Ok(8));
                    }
                });
            }
        });
        assert_eq!(vfs.read(fd, 8).unwrap(), 4096u64.to_le_bytes());
        assert_eq!(direct.get(fd).unwrap().read(8), Err(Errno(11)));
        assert_eq!(
            direct.get(fd).unwrap().write(&u64::MAX.to_le_bytes()),
            Err(Errno(22))
        );
        assert_eq!(
            direct.get(fd).unwrap().write(&(u64::MAX - 1).to_le_bytes()),
            Ok(8)
        );
        assert_eq!(vfs.write(fd, &1u64.to_le_bytes()), Err(Errno(11)));
        assert_eq!(vfs.read(fd, 8).unwrap(), (u64::MAX - 1).to_le_bytes());
        let sem = vfs.eventfd(4096, 1 | O_NONBLOCK).unwrap();
        let direct = vfs.direct_descriptors();
        let total: usize = thread::scope(|scope| {
            let mut threads = Vec::new();
            for _ in 0..4 {
                let sem = direct.get(sem).unwrap();
                threads.push(scope.spawn(move || {
                    let mut total = 0;
                    loop {
                        match sem.read(8) {
                            Ok(bytes) => {
                                assert_eq!(bytes, 1u64.to_le_bytes());
                                total += 1;
                            }
                            Err(Errno(11)) => return total,
                            result => panic!("unexpected semaphore result {result:?}"),
                        }
                    }
                }));
            }
            threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .sum()
        });
        assert_eq!(total, 4096);
        assert_eq!(vfs.poll(sem, 1), 0);
    }

    #[test]
    fn direct_pipe_writers_share_vfs_bytes_and_keep_records_atomic() {
        let mut vfs = Vfs::default();
        let [read, write] = vfs.pipe(0).unwrap();
        let direct = vfs.direct_descriptors();
        thread::scope(|scope| {
            for writer in 0..4u64 {
                let end = direct.get(write).unwrap();
                scope.spawn(move || {
                    for index in 0..1024u64 {
                        assert_eq!(end.write(&((writer << 32) | index).to_le_bytes()), Ok(8));
                    }
                });
            }
        });
        let bytes = vfs.read(read, PIPE_CAPACITY).unwrap();
        assert_eq!(bytes.len(), 4 * 1024 * 8);
        let records: std::collections::BTreeSet<_> = bytes
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(records.len(), 4096);
        for writer in 0..4u64 {
            for index in 0..1024u64 {
                assert!(records.contains(&((writer << 32) | index)));
            }
        }
        vfs.close(write).unwrap();
        assert_eq!(direct.get(read).unwrap().read(8), Ok(Vec::new()));
        assert_eq!(vfs.poll(read, 1), 16);
    }

    #[test]
    fn resource_locks_are_independent_and_pipe_buf_rules_match() {
        let mut vfs = Vfs::default();
        let [_, first] = vfs.pipe(O_NONBLOCK).unwrap();
        let [read, write] = vfs.pipe(O_NONBLOCK).unwrap();
        let direct = vfs.direct_descriptors();
        let ByteResource::Pipe { data, .. } = &direct.get(first).unwrap().resource else {
            unreachable!()
        };
        let held = data.lock().unwrap();
        thread::scope(|scope| {
            let (tx, rx) = std::sync::mpsc::channel();
            let end = direct.get(write).unwrap();
            scope.spawn(move || tx.send(end.write(b"xy")).unwrap());
            let result = rx.recv_timeout(Duration::from_secs(2));
            drop(held);
            assert_eq!(result.unwrap(), Ok(2));
        });
        assert_eq!(vfs.read(read, 8).unwrap(), b"xy");
        assert_eq!(vfs.write(write, &vec![1; PIPE_CAPACITY]), Ok(PIPE_CAPACITY));
        assert_eq!(direct.get(read).unwrap().read(1).unwrap(), [1]);
        assert_eq!(direct.get(write).unwrap().write(b"ab"), Err(Errno(11)));
        assert_eq!(
            vfs.read(read, PIPE_CAPACITY).unwrap().len(),
            PIPE_CAPACITY - 1
        );
    }

    #[test]
    fn fd_reuse_keeps_handles_distinct_and_fork_status_is_live() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(1, 0).unwrap();
        let old = vfs.direct_descriptors();
        let alias = vfs.dup(fd, 0, false).unwrap();
        let mut child = vfs.clone();
        child.set_status_flags(fd, O_NONBLOCK).unwrap();
        assert!(vfs.direct_descriptors().get(alias).unwrap().nonblocking());
        assert!(old.get(fd).unwrap().nonblocking());
        let accepted = old.get(fd).unwrap();
        vfs.close(fd).unwrap();
        let new_fd = vfs.eventfd(7, 0).unwrap();
        assert_eq!(fd, new_fd);
        assert_eq!(old.get(fd).unwrap().read(8).unwrap(), 7u64.to_le_bytes());
        assert_eq!(old.get(fd).unwrap().read(8), Err(Errno(11)));
        assert_eq!(accepted.read(8).unwrap(), 1u64.to_le_bytes());
    }
}
