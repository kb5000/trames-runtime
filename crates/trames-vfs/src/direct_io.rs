// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared byte resources. No namespace, descriptor-table Rc or guest memory lives
//! behind these handles. Descriptor mutation still requires its owner boundary.
use super::*;
use crate::readiness::Readiness;
use std::sync::{LockResult, Mutex, MutexGuard, PoisonError};

pub(super) struct EventCounter {
    count: AtomicU64,
    semaphore: bool,
    readiness: Arc<Readiness>,
    epoch: [AtomicU64; 2],
}
impl EventCounter {
    pub(super) fn new(count: u64, semaphore: bool) -> Self {
        Self {
            count: AtomicU64::new(count),
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

#[derive(Clone)]
enum ByteResource {
    Event(Arc<EventCounter>),
    Timer(Arc<TimerFd>),
    Epoll(Arc<DirectEpoll>),
    Unix {
        data: Arc<ipc::channel::Resource>,
        side: usize,
    },
    Pipe {
        data: Arc<PipeResource>,
        read: bool,
        write: bool,
        initial_write_epoch: u64,
    },
}
type DirectWatch = ((u32, u64), Arc<Mutex<events::WatchState>>, DirectFd);
struct DirectEpoll {
    watches: Vec<DirectWatch>,
    cursor: Arc<Mutex<Option<(u32, u64)>>>,
}
/// A retained resource with flags frozen by the current FD mutation boundary.
/// It is Send + Sync by composition; no unsafe Rc/RefCell conversion is used.
#[derive(Clone)]
pub struct DirectFd {
    resource: ByteResource,
    flags: u32,
}
impl DirectFd {
    pub fn subscribe(&self, signal: &Arc<crate::IoSignal>) -> Vec<crate::IoSubscription> {
        match &self.resource {
            ByteResource::Event(counter) => vec![counter.readiness.subscribe(signal)],
            ByteResource::Timer(timer) => vec![timer.readiness.subscribe(signal)],
            ByteResource::Pipe { data, .. } => vec![data.readiness.subscribe(signal)],
            ByteResource::Unix { data, .. } => vec![data.readiness.subscribe(signal)],
            ByteResource::Epoll(epoll) => epoll
                .watches
                .iter()
                .filter(|(_, state, _)| state.lock().unwrap().armed)
                .flat_map(|(_, _, fd)| fd.subscribe(signal))
                .collect(),
        }
    }
    pub(super) fn snapshot(open: &OpenDescription) -> Option<Self> {
        let resource = if let Some(events::Anonymous::Event(counter)) = &open.anonymous {
            ByteResource::Event(counter.clone())
        } else if let Some(events::Anonymous::Timer(timer)) = &open.anonymous {
            ByteResource::Timer(timer.clone())
        } else if let Some(events::Anonymous::Epoll { watches, cursor }) = &open.anonymous {
            let mut direct = Vec::new();
            for (&key, watch) in watches {
                if let Some(target) = watch.open.upgrade() {
                    let fd = Self::snapshot(&target.borrow())?;
                    direct.push((key, watch.state.clone(), fd));
                }
            }
            ByteResource::Epoll(Arc::new(DirectEpoll {
                watches: direct,
                cursor: cursor.clone(),
            }))
        } else if matches!(open.kind, FdKind::PipeRead | FdKind::PipeWrite) {
            let end = open.pipe.as_ref()?;
            ByteResource::Pipe {
                data: end.pipe.borrow().data.clone(),
                read: end.read,
                write: end.write,
                initial_write_epoch: end.initial_write_epoch,
            }
        } else if let Some((data, side)) = open.local.as_ref().and_then(|s| s.direct()) {
            ByteResource::Unix { data, side }
        } else {
            return None;
        };
        Some(Self {
            resource,
            flags: open.flags,
        })
    }
    pub fn is_epoll(&self) -> bool {
        matches!(self.resource, ByteResource::Epoll(_))
    }
    pub fn is_unix(&self) -> bool {
        matches!(self.resource, ByteResource::Unix { .. })
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
    pub fn next_deadline(&self) -> Option<std::time::Instant> {
        match &self.resource {
            ByteResource::Timer(timer) => timer.deadline(),
            ByteResource::Epoll(epoll) => epoll
                .watches
                .iter()
                .filter_map(|(_, state, fd)| {
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
            ByteResource::Unix { .. } | ByteResource::Pipe { .. }
        )
    }
    pub fn readable_bytes(&self) -> usize {
        match &self.resource {
            ByteResource::Unix { data, side } => data.readable_bytes(*side),
            ByteResource::Pipe { data, .. } => data.lock().unwrap().bytes.len(),
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
        match &self.resource {
            ByteResource::Event(counter) => (counter.poll(events), counter.epoch()),
            ByteResource::Timer(timer) => timer.poll(events),
            ByteResource::Unix { data, side } => data.poll(*side, events),
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
            ByteResource::Epoll(_) => unreachable!("nested epoll is rejected at registration"),
        }
    }
    pub fn epoll_wait(&self, max: usize) -> Result<Vec<(u32, u64)>> {
        let ByteResource::Epoll(epoll) = &self.resource else {
            return Err(Errno(22));
        };
        // One delivery cursor per epoll object, shared with the joined path.
        // This also arbitrates ET and ONESHOT between concurrent waiters.
        let mut cursor = epoll.cursor.lock().unwrap();
        let start = cursor.map_or(0, |c| {
            epoll.watches.partition_point(|(key, _, _)| *key <= c)
        });
        let mut result = Vec::new();
        for (key, state, fd) in epoll.watches[start..].iter().chain(&epoll.watches[..start]) {
            let mut state = state.lock().unwrap();
            if !state.armed {
                continue;
            }
            let (ready, epoch) = fd.poll(state.events as u16);
            if let Some(event) = state.observe(ready, epoch) {
                *cursor = Some(*key);
                result.push(event);
                if result.len() == max {
                    break;
                }
            }
        }
        Ok(result)
    }
    pub fn is_eventfd(&self) -> bool {
        matches!(self.resource, ByteResource::Event(_))
    }
    pub fn nonblocking(&self) -> bool {
        self.flags & O_NONBLOCK != 0
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
            ByteResource::Event(counter) => counter.read(count),
            ByteResource::Timer(timer) => timer.read(count),
            ByteResource::Epoll(_) => Err(Errno(22)),
            ByteResource::Pipe { data, read, .. } => {
                if !read {
                    return Some(Err(Errno(9)));
                }
                data.lock().unwrap().read(count)
            }
            ByteResource::Unix { .. } => unreachable!("handled Unix receive"),
        })
    }
    pub fn recv(&self, count: usize, flags: u32) -> Option<Result<Vec<u8>>> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 1 {
            return Some(Err(Errno(9)));
        }
        let ByteResource::Unix { data, side } = &self.resource else {
            return None;
        };
        data.recv(*side, count, flags, false)
            .map(|r| r.map(|r| r.data))
    }
    pub fn send(&self, bytes: &[u8], flags: u32) -> Result<usize> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 0 {
            return Err(Errno(9));
        }
        match &self.resource {
            ByteResource::Unix { data, side } => data.send(*side, bytes, flags, None),
            _ => Err(Errno(88)),
        }
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        if self.flags & O_PATH != 0 || self.flags & 3 == 0 {
            return Err(Errno(9));
        }
        match &self.resource {
            ByteResource::Event(counter) => counter.write(bytes),
            ByteResource::Epoll(_) | ByteResource::Timer(_) => Err(Errno(22)),
            ByteResource::Unix { .. } => self.send(bytes, 0),
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
pub struct DirectFds(pub(super) Arc<[Option<DirectFd>]>);
impl DirectFds {
    pub fn get(&self, fd: u32) -> Option<&DirectFd> {
        self.0.get(fd as usize)?.as_ref()
    }
}
impl Vfs {
    pub fn is_eventfd(&self, fd: u32) -> Result<bool> {
        Ok(matches!(
            self.descriptor(fd)?.open.borrow().anonymous,
            Some(events::Anonymous::Event(_))
        ))
    }
    pub fn direct_descriptors(&self) -> DirectFds {
        let revision = FD_FLAGS_REVISION.load(Ordering::Relaxed);
        if let Some((old, snapshot)) = &*self.fds.identity.direct.borrow() {
            if *old == revision {
                return snapshot.clone();
            }
        }
        // Flags and resources are built together with ONE descriptor scan.
        self.fd_flags_snapshot();
        self.fds
            .identity
            .direct
            .borrow()
            .as_ref()
            .expect("FD snapshot pair")
            .1
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread, time::Duration};

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
    fn fd_reuse_and_fork_status_changes_rebuild_shared_handles() {
        let mut vfs = Vfs::default();
        let fd = vfs.eventfd(1, 0).unwrap();
        let old = vfs.direct_descriptors();
        let alias = vfs.dup(fd, 0, false).unwrap();
        let mut child = vfs.clone();
        child.set_status_flags(fd, O_NONBLOCK).unwrap();
        assert!(vfs.direct_descriptors().get(alias).unwrap().nonblocking());
        assert!(!old.get(fd).unwrap().nonblocking());
        vfs.close(fd).unwrap();
        let new_fd = vfs.eventfd(7, 0).unwrap();
        assert_eq!(fd, new_fd);
        assert_eq!(
            vfs.direct_descriptors().get(fd).unwrap().read(8).unwrap(),
            7u64.to_le_bytes()
        );
        assert_eq!(old.get(fd).unwrap().read(8).unwrap(), 1u64.to_le_bytes());
    }
}
