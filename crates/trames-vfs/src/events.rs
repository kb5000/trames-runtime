// SPDX-License-Identifier: GPL-3.0-or-later
//! In-process event descriptors. No guest descriptor is a host descriptor.
use super::*;
use std::time::{Duration, Instant};

pub(super) enum Anonymous {
    Uring(Arc<Uring>),
    Bpf(Arc<bpf::Program>),
    Inotify(Arc<inotify::InotifyInstance>),
    Signal(Arc<SignalMask>),
    Event(Arc<direct_io::EventCounter>),
    Timer(Arc<TimerFd>),
    Epoll(Arc<epoll::LiveEpoll>),
}

/// Shared control portions of the original anonymous resources, including
/// epoll's one original interest index.
pub(super) struct SignalMask {
    mask: AtomicU64,
    pub(super) revision: AtomicU64,
    pub(super) changed: Arc<Readiness>,
}
impl SignalMask {
    pub(super) fn new(mask: u64) -> Self {
        Self {
            mask: AtomicU64::new(mask & !((1 << 8) | (1 << 18))),
            revision: AtomicU64::new(0),
            changed: Arc::default(),
        }
    }
    pub(super) fn get(&self) -> u64 {
        self.mask.load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, mask: u64) {
        self.mask
            .store(mask & !((1 << 8) | (1 << 18)), Ordering::Relaxed);
        self.revision.fetch_add(1, Ordering::Relaxed);
        self.changed.notify_atomic();
    }
}
pub(super) enum SharedControl {
    Binder(Arc<binder::Connection>),
    Cgroup(Arc<cgroup::CgroupFile>),
    Uring(Arc<Uring>),
    Signal(Arc<SignalMask>),
    Bpf(Arc<bpf::Program>),
    Event(Arc<direct_io::EventCounter>),
    Timer(Arc<TimerFd>),
    Inotify(Arc<inotify::InotifyInstance>),
    Epoll(Arc<epoll::LiveEpoll>),
}
impl SharedControl {
    fn capture(control: &Anonymous) -> Option<Self> {
        Some(match control {
            Anonymous::Uring(ring) => Self::Uring(ring.clone()),
            Anonymous::Signal(mask) => Self::Signal(mask.clone()),
            Anonymous::Bpf(program) => Self::Bpf(program.clone()),
            Anonymous::Event(counter) => Self::Event(counter.clone()),
            Anonymous::Timer(timer) => Self::Timer(timer.clone()),
            Anonymous::Inotify(instance) => Self::Inotify(instance.clone()),
            Anonymous::Epoll(shared) => Self::Epoll(shared.clone()),
        })
    }
    pub(super) fn owner_projection(&self) -> Option<Anonymous> {
        Some(match self {
            Self::Cgroup(_) | Self::Binder(_) => return None,
            Self::Uring(ring) => Anonymous::Uring(ring.clone()),
            Self::Signal(mask) => Anonymous::Signal(mask.clone()),
            Self::Bpf(program) => Anonymous::Bpf(program.clone()),
            Self::Event(counter) => Anonymous::Event(counter.clone()),
            Self::Timer(timer) => Anonymous::Timer(timer.clone()),
            Self::Inotify(instance) => Anonymous::Inotify(instance.clone()),
            Self::Epoll(shared) => Anonymous::Epoll(shared.clone()),
        })
    }
}

pub(super) struct WatchState {
    pub events: u32,
    pub data: u64,
    pub armed: bool,
    last_ready: u16,
    last_epoch: [u64; 2],
}
impl WatchState {
    pub(super) fn new(events: u32, data: u64) -> Self {
        Self {
            events,
            data,
            armed: true,
            last_ready: 0,
            last_epoch: [0; 2],
        }
    }
    pub fn ready(&self, ready: u16, epoch: [u64; 2]) -> bool {
        self.events & 0x80000000 == 0
            || ready & !self.last_ready != 0
            || ready & 3 != 0 && epoch[0] != self.last_epoch[0]
            || ready & 4 != 0 && epoch[1] != self.last_epoch[1]
    }
    pub fn observe(&mut self, ready: u16, epoch: [u64; 2]) -> Option<(u32, u64)> {
        if !self.armed {
            return None;
        }
        let deliver = ready != 0 && self.ready(ready, epoch);
        if deliver || ready == 0 {
            self.last_ready = ready;
            self.last_epoch = epoch;
        }
        if !deliver {
            return None;
        }
        if self.events & 0x40000000 != 0 {
            self.armed = false;
        }
        Some((ready as u32, self.data))
    }
}
impl Anonymous {
    pub(super) fn name(&self) -> &'static [u8] {
        match self {
            Self::Uring(_) => b"anon_inode:[io_uring]",
            Self::Bpf(_) => b"anon_inode:bpf-prog",
            Self::Inotify(_) => b"anon_inode:inotify",
            Self::Signal(_) => b"anon_inode:[signalfd]",
            Self::Event(_) => b"anon_inode:[eventfd]",
            Self::Timer(_) => b"anon_inode:[timerfd]",
            Self::Epoll(_) => b"anon_inode:[eventpoll]",
        }
    }
    pub(super) fn poll(
        &self,
        events: u16,
        pending: u64,
        reader: Option<&Arc<dyn SignalReader>>,
    ) -> u16 {
        match self {
            Self::Uring(ring) => {
                if ring.cq_ready() != 0 {
                    events & 1
                } else {
                    0
                }
            }
            Self::Bpf(_) => 0,
            Self::Inotify(i) => {
                if i.queue.available() != 0 {
                    events & 1
                } else {
                    0
                }
            }
            Self::Signal(mask) => {
                if mask.get() & pending != 0 {
                    events & 1
                } else {
                    0
                }
            }
            Self::Event(counter) => counter.poll(events),
            Self::Timer(timer) => timer.poll(events).0,
            Self::Epoll(live) => {
                let Some(_traversal) = epoll::Traversal::enter(live) else {
                    return 0;
                };
                if live.snapshot().iter().any(|(_, state, target)| {
                    epoll::inspect::<false>(state, target.is_nested(), |requested| {
                        let Some(open) = target.original_open() else {
                            return Ok(None);
                        };
                        let open = open.borrow();
                        Ok(Some((
                            Vfs::peek_poll_open(&open, requested, pending, reader),
                            Vfs::poll_epoch_with(&open, reader),
                        )))
                    })
                    .is_ok_and(|ready| ready.is_some())
                }) {
                    events & 1
                } else {
                    0
                }
            }
        }
    }
    pub(super) fn read(&mut self, count: usize) -> Result<Vec<u8>> {
        if let Self::Inotify(i) = self {
            return i.queue.read(count);
        }
        if count < 8 {
            return Err(Errno(22));
        }
        match self {
            Self::Event(counter) => counter.read(count),
            Self::Timer(timer) => timer.read(count),
            Self::Bpf(_) | Self::Signal(_) | Self::Epoll(_) | Self::Inotify(_) | Self::Uring(_) => {
                Err(Errno(22))
            }
        }
    }
    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        let Self::Event(counter) = self else {
            return Err(Errno(22));
        };
        counter.write(bytes)
    }
}

impl Vfs {
    /// The descriptor holds only its mask. Signals belong to the reading task,
    /// never to the descriptor's creator or the host process.
    pub fn signalfd(&mut self, fd: i32, mask: u64, flags: u32) -> Result<u32> {
        self.descriptor_factory()
            .signalfd(fd, mask, flags)
            .unwrap_or_else(|| {
                // An existing owner-only FD cannot be a shared signalfd. Preserve
                // owner type errors without admitting that resource to workers.
                self.descriptor(fd as u32).and(Err(Errno(22)))
            })
    }
    pub fn signalfd_mask(&self, fd: u32) -> Result<Option<u64>> {
        Ok(match &self.descriptor(fd)?.open.borrow().anonymous {
            Some(Anonymous::Signal(mask)) => Some(mask.get()),
            _ => None,
        })
    }
    pub(super) fn anonymous(&mut self, flags: u32, anonymous: Anonymous) -> Result<u32> {
        let reservation = self.shared_files().reserve()?;
        let descriptor = anonymous_descriptor(self.open_id(), flags, anonymous);
        reservation.publish(descriptor, Some(&self.fds))
    }
    pub fn eventfd(&mut self, initial: u32, flags: u32) -> Result<u32> {
        self.descriptor_factory().eventfd(initial, flags)
    }
    pub fn timerfd(&mut self, clock: u32, flags: u32) -> Result<u32> {
        self.descriptor_factory().timerfd(clock, flags)
    }
    pub fn timerfd_resource(&self, fd: u32) -> Result<Arc<TimerFd>> {
        match &self.descriptor(fd)?.open.borrow().anonymous {
            Some(Anonymous::Timer(timer)) => Ok(timer.clone()),
            _ => Err(Errno(22)),
        }
    }
    pub fn timerfd_clock(&self, fd: u32) -> Result<u32> {
        Ok(self.timerfd_resource(fd)?.clock)
    }
    pub fn timerfd_get(&self, fd: u32) -> Result<(Duration, Duration)> {
        Ok(self.timerfd_resource(fd)?.update(None))
    }
    pub fn timerfd_set(
        &self,
        fd: u32,
        interval: Duration,
        deadline: Option<Instant>,
    ) -> Result<()> {
        self.timerfd_resource(fd)?
            .update(Some((interval, deadline)));
        Ok(())
    }
    pub fn next_timerfd_deadline(&self) -> Option<Instant> {
        // Membership changes invalidate this object index. Rearm/disarm/read
        // stay on the original shared timer, so no FD snapshot or stale copied
        // deadline is needed on the scheduler's ordinary polling path.
        let cache = self.fds.cache();
        cache
            .timers
            .get_or_init(|| {
                let mut timers = BTreeMap::new();
                for descriptor in self.fds.entries().values() {
                    if let Some(Anonymous::Timer(timer)) = &descriptor.open.borrow().anonymous {
                        timers
                            .entry(Arc::as_ptr(timer) as usize)
                            .or_insert_with(|| Arc::downgrade(timer));
                    }
                }
                timers.into_values().collect::<Vec<_>>().into()
            })
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .filter_map(|timer| timer.deadline())
            .min()
    }
    pub fn epoll_create(&mut self, flags: u32) -> Result<u32> {
        if flags & !O_CLOEXEC != 0 {
            return Err(Errno(22));
        }
        let shared = epoll::LiveEpoll::new(self.next_open.epolls.clone());
        self.anonymous(flags, Anonymous::Epoll(shared))
    }
    pub fn epoll_ctl(&self, fd: u32, op: u32, target: u32, events: u32, data: u64) -> Result<()> {
        let epoll = self.descriptor(fd)?.open.clone();
        let target_open = self.descriptor(target)?.open.clone();
        epoll::control(epoll, target_open, target, op, events, data)
    }
    pub fn epoll_wait(
        &self,
        fd: u32,
        max: usize,
        mut special: impl FnMut(&FdKind, u16) -> Result<Option<u16>>,
    ) -> Result<Vec<(u32, u64)>> {
        self.epoll_wait_signals(fd, max, 0, |kind, events| {
            special(kind, events).map(|r| r.map(|r| (r, [0; 2])))
        })
    }
    pub(super) fn poll_epoch(o: &OpenDescription) -> [u64; 2] {
        Self::poll_epoch_with(o, None)
    }
    fn poll_epoch_with(o: &OpenDescription, reader: Option<&Arc<dyn SignalReader>>) -> [u64; 2] {
        if let Some(SharedControl::Binder(process)) = &o.control {
            return process.poll(0).1;
        }
        if let Some(SharedControl::Cgroup(file)) = &o.control {
            return file.poll(0).1;
        }
        if let Some(file) = &o.mount_file {
            return file.watch.poll(0).1;
        }
        if let Some(log) = &o.kernel_log {
            return log.poll(0).1;
        }
        if let Some(bridge) = &o.bridge {
            return bridge.peek(0).1;
        }
        if let Some(Anonymous::Uring(ring)) = &o.anonymous {
            return ring.cq_epoch();
        }
        if let Some(epoch) = o.socket.as_ref().and_then(|s| s.poll_epoch()) {
            return epoch;
        }
        if let Some(end) = &o.pipe {
            return end.data.lock().unwrap().io_epoch;
        }
        if let Some(local) = &o.local {
            return local.poll_epoch();
        }
        if let Some(Anonymous::Inotify(i)) = &o.anonymous {
            return i.queue.poll(0).1;
        }
        if let Some(Anonymous::Event(counter)) = &o.anonymous {
            return counter.epoch();
        }
        if let Some(Anonymous::Timer(timer)) = &o.anonymous {
            return timer.epoch();
        }
        if let Some(Anonymous::Signal(mask)) = &o.anonymous {
            let mut epoch = reader.map_or([0; 2], |reader| reader.poll(mask.get()).1);
            epoch[0] = epoch[0].wrapping_add(mask.revision.load(Ordering::Relaxed));
            return epoch;
        }
        if let Some(Anonymous::Epoll(live)) = &o.anonymous {
            let Some(_traversal) = epoll::Traversal::enter(live) else {
                return [live.revision(), 0];
            };
            let generation = live
                .snapshot()
                .iter()
                .filter_map(|watch| watch.2.original_open())
                .map(|open| Self::poll_epoch_with(&open.borrow(), reader))
                .fold(live.revision(), |sum, epoch| {
                    sum.wrapping_add(epoch[0]).wrapping_add(epoch[1])
                });
            return [generation, 0];
        }

        o.pty
            .as_ref()
            .map_or([0; 2], |end| end.pair.poll_epoch(end.master))
    }
    /// Armed host input retains the original endpoint, including nested sets.
    pub fn epoll_waits_for_stdin(&self, fd: u32) -> Result<bool> {
        let live = match &self.descriptor(fd)?.open.borrow().anonymous {
            Some(Anonymous::Epoll(live)) => live.clone(),
            _ => return Err(Errno(22)),
        };
        fn stdin(live: &Arc<epoll::LiveEpoll>) -> bool {
            let Some(_traversal) = epoll::Traversal::enter(live) else {
                return false;
            };
            live.snapshot().iter().any(|(_, state, target)| {
                if !state.lock().unwrap().armed {
                    return false;
                }
                let Some(open) = target.original_open() else {
                    return false;
                };
                let open = open.borrow();
                open.kind == FdKind::Stdin
                    || matches!(&open.anonymous, Some(Anonymous::Epoll(child)) if stdin(child))
            })
        }
        Ok(stdin(&live))
    }
    fn epoll_target_poll(
        &self,
        target: &direct_io::WatchResource,
        events: u16,
        pending: u64,
        special: &mut impl FnMut(&FdKind, u16) -> Result<Option<(u16, [u64; 2])>>,
    ) -> Result<Option<(u16, [u64; 2])>> {
        let Some(open) = target.original_open() else {
            return Ok(None);
        };
        let open = open.borrow();
        if open.pty.is_none() {
            if let Some(ready) = special(&open.kind, events)? {
                return Ok(Some(ready));
            }
        }
        let reader = self.signal_reader.borrow();
        Ok(Some((
            Self::peek_poll_open(&open, events, pending, reader.as_ref()),
            Self::poll_epoch_with(&open, reader.as_ref()),
        )))
    }
    pub fn epoll_ready_signals(
        &self,
        fd: u32,
        pending: u64,
        mut special: impl FnMut(&FdKind, u16) -> Result<Option<(u16, [u64; 2])>>,
    ) -> Result<bool> {
        let live = match &self.descriptor(fd)?.open.borrow().anonymous {
            Some(Anonymous::Epoll(live)) => live.clone(),
            _ => return Err(Errno(22)),
        };
        let Some(_traversal) = epoll::Traversal::enter(&live) else {
            return Ok(false);
        };
        for (_, state, target) in live.snapshot().iter() {
            if epoll::inspect::<false>(state, target.is_nested(), |events| {
                self.epoll_target_poll(target, events, pending, &mut special)
            })?
            .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    pub fn epoll_wait_signals(
        &self,
        fd: u32,
        max: usize,
        pending: u64,
        mut special: impl FnMut(&FdKind, u16) -> Result<Option<(u16, [u64; 2])>>,
    ) -> Result<Vec<(u32, u64)>> {
        let live = match &self.descriptor(fd)?.open.borrow().anonymous {
            Some(Anonymous::Epoll(live)) => live.clone(),
            _ => return Err(Errno(22)),
        };
        let Some(_traversal) = epoll::Traversal::enter(&live) else {
            return Ok(Vec::new());
        };
        let mut cursor = live.cursor.lock().unwrap();
        let watches = live.snapshot();
        let mut result = Vec::new();
        for (key, state, target) in epoll::ordered(&watches, *cursor) {
            if let Some((event, epoch)) =
                epoll::inspect::<true>(state, target.is_nested(), |events| {
                    self.epoll_target_poll(target, events, pending, &mut special)
                })?
            {
                if let Some(open) = target.original_open() {
                    if let Some(file) = &open.borrow().mount_file {
                        file.watch.acknowledge(epoch[0]);
                    }
                }
                result.push(event);
                *cursor = Some(*key);
                if result.len() == max {
                    break;
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timer_expirations_accumulate_and_disarm_clears_pending() {
        let mut v = Vfs::default();
        let fd = v.timerfd(1, O_NONBLOCK).unwrap();
        v.timerfd_set(
            fd,
            Duration::from_millis(1),
            Some(Instant::now() - Duration::from_millis(4)),
        )
        .unwrap();
        assert_eq!(v.poll(fd, 1), 1);
        let bytes = v.read(fd, 8).unwrap();
        assert!(u64::from_le_bytes(bytes.try_into().unwrap()) >= 5);
        v.timerfd_set(fd, Duration::ZERO, None).unwrap();
        assert_eq!(v.poll(fd, 1), 0);
        assert_eq!(v.read(fd, 8), Err(Errno(11)));
    }
    #[test]
    fn unsupported_epoll_modes_leave_registrations_unchanged() {
        let mut v = Vfs::default();
        let fd = v.eventfd(1, 0).unwrap();
        let ep = v.epoll_create(O_CLOEXEC).unwrap();
        assert_eq!(v.epoll_ctl(ep, 1, fd, 0x08000001, 42), Err(Errno(95)));
        assert_eq!(v.epoll_ctl(ep, 1, ep, 1, 42), Err(Errno(22)));
        assert_eq!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap(), vec![]);
        v.epoll_ctl(ep, 1, fd, 1, 42).unwrap();
        assert_eq!(v.poll(ep, 1), 1);
        let mut child = v.clone();
        let alias = child.dup(ep, 0, false).unwrap();
        child.close_exec();
        assert_eq!(child.fd_kind(ep), Err(Errno(9)));
        assert_eq!(
            child.epoll_wait(alias, 1, |_, _| Ok(None)).unwrap(),
            vec![(1, 42)]
        );
        v.read(fd, 8).unwrap();
        assert_eq!(child.poll(alias, 1), 0);
    }
    #[test]
    fn anonymous_and_socket_owners_survive_identity_changes() {
        let mut v = Vfs {
            credentials: Credentials::user(1000, 1001),
            ..Vfs::default()
        };
        let event = v.eventfd(0, 0).unwrap();
        let pair = v.socketpair(1, 1, 0).unwrap();
        v.credentials = Credentials::user(2000, 2001);
        for fd in [pair[0], pair[1]] {
            let stat = v.stat_fd(fd).unwrap();
            assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 1000);
            assert_eq!(u32::from_le_bytes(stat[28..32].try_into().unwrap()), 1001);
        }
        assert_eq!(
            u32::from_le_bytes(v.stat_fd(event).unwrap()[24..28].try_into().unwrap()),
            0
        );
        assert_eq!(
            u32::from_le_bytes(v.stat_fd(event).unwrap()[16..20].try_into().unwrap()),
            0o600
        );
    }
}

#[cfg(test)]
mod timer_index_tests {
    use super::*;
    #[test]
    fn timer_index_reads_live_state_and_tracks_fork_shared_close_and_fd_reuse() {
        let mut parent = Vfs::default();
        for _ in 0..128 {
            parent.eventfd(0, 0).unwrap();
        }
        let timer = parent.timerfd(1, 0).unwrap();
        let resource = parent.timerfd_resource(timer).unwrap();
        let weak = Arc::downgrade(&resource);
        let first = Instant::now() + Duration::from_secs(60);
        parent
            .timerfd_set(timer, Duration::ZERO, Some(first))
            .unwrap();
        assert_eq!(parent.next_timerfd_deadline(), Some(first));
        let cached = parent.fds.identity();
        assert_eq!(parent.fds.cache().timers.get().unwrap().len(), 1);
        let mut child = parent.clone();
        let mut shared = parent.clone_with_files(true);
        let second = first + Duration::from_secs(10);
        resource.update(Some((Duration::ZERO, Some(second))));
        assert_eq!(parent.next_timerfd_deadline(), Some(second));
        assert!(
            Arc::ptr_eq(&cached, &parent.fds.identity()),
            "timer updates cannot rebuild the FD index"
        );
        child.close(timer).unwrap();
        assert_eq!(child.next_timerfd_deadline(), None);
        assert_eq!(parent.next_timerfd_deadline(), Some(second));
        shared.close(timer).unwrap();
        let reused = parent.eventfd(0, 0).unwrap();
        assert_eq!(reused, timer);
        assert_eq!(parent.next_timerfd_deadline(), None);
        assert_eq!(shared.next_timerfd_deadline(), None);
        drop(resource);
        assert!(
            weak.upgrade().is_none(),
            "cached timer index cannot prolong timer lifetime"
        );
    }
    #[test]
    fn empty_timer_index_remains_empty_until_actual_membership_changes() {
        let mut v = Vfs::default();
        for _ in 0..128 {
            v.eventfd(0, 0).unwrap();
        }
        assert_eq!(v.next_timerfd_deadline(), None);
        let version = v.fds.identity();
        assert!(v.fds.cache().timers.get().unwrap().is_empty());
        for _ in 0..128 {
            assert_eq!(v.next_timerfd_deadline(), None);
        }
        assert!(Arc::ptr_eq(&version, &v.fds.identity()));
        let timer = v.timerfd(1, 0).unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        v.timerfd_set(timer, Duration::ZERO, Some(deadline))
            .unwrap();
        assert_eq!(v.next_timerfd_deadline(), Some(deadline));
        v.timerfd_set(timer, Duration::ZERO, None).unwrap();
        assert_eq!(v.next_timerfd_deadline(), None);
    }
}

pub(super) fn anonymous_descriptor(id: u64, flags: u32, anonymous: Anonymous) -> Descriptor {
    let access = if matches!(anonymous, Anonymous::Inotify(_)) {
        0
    } else {
        2
    };
    let descriptor = Descriptor {
        open: OpenHandle::new(OpenDescription {
            shared: Arc::new(SharedOpenDescription {
                console: Default::default(),
                oom: None,
                network_control: None,
                mount_file: None,
                runtime_file: None,
                socket: None,
                _disk_file: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_file: None,
                native_image: None,
                mount_resource: std::sync::OnceLock::new(),
                mount_use: Default::default(),
                directory_mount: Default::default(),
                namespace_resource: None,
                file_authority: Default::default(),
                tcp_publication: Default::default(),
                socket_control: None,
                control: SharedControl::capture(&anonymous),
                read_node: None,
                id,
                owner: (0, 0),
                kind: FdKind::Anonymous,
                flags: (access | (flags & O_NONBLOCK)).into(),
                file_position: Arc::default(),
                flock: std::sync::OnceLock::new(),
                ofd_records: Default::default(),
                node: None,
                pipe: None,
                pty: None,
                local: None,
                bridge: None,
                kernel_log: None,
                notification: None,
            }),
            anonymous: Some(anonymous),

            namespace: None,
            mount: None,
        }),
        cloexec: (flags & O_CLOEXEC != 0).into(),
    };
    if let Some(SharedControl::Epoll(live)) = &descriptor.open.borrow().control {
        live.bind(&descriptor.open.borrow().shared);
    }
    descriptor
}
