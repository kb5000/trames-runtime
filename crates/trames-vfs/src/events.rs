// SPDX-License-Identifier: GPL-3.0-or-later
//! In-process event descriptors. No guest descriptor is a host descriptor.
use super::*;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) enum Anonymous {
    Uring(Rc<Uring>),
    Bpf(Arc<bpf::Program>),
    Inotify(Arc<inotify::InotifyInstance>),
    Signal(Arc<SignalMask>),
    Event(Arc<direct_io::EventCounter>),
    Timer(Arc<TimerFd>),
    Epoll {
        watches: BTreeMap<(u32, u64), Watch>,
        cursor: Arc<Mutex<Option<(u32, u64)>>>,
        shared: Arc<epoll::LiveEpoll>,
    },
}

/// Shared control portions of the original anonymous resources. Epoll keeps
/// owner-only targets in Anonymous; its admitted live index contains no Rc.
pub(super) struct SignalMask(AtomicU64);
impl SignalMask {
    pub(super) fn new(mask: u64) -> Self {
        Self(AtomicU64::new(mask & !((1 << 8) | (1 << 18))))
    }
    pub(super) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    pub(super) fn set(&self, mask: u64) {
        self.0
            .store(mask & !((1 << 8) | (1 << 18)), Ordering::Relaxed);
    }
}
pub(super) enum SharedControl {
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
            Anonymous::Signal(mask) => Self::Signal(mask.clone()),
            Anonymous::Bpf(program) => Self::Bpf(program.clone()),
            Anonymous::Event(counter) => Self::Event(counter.clone()),
            Anonymous::Timer(timer) => Self::Timer(timer.clone()),
            Anonymous::Inotify(instance) => Self::Inotify(instance.clone()),
            Anonymous::Epoll { shared, .. } => Self::Epoll(shared.clone()),
            _ => return None,
        })
    }
    pub(super) fn owner_projection(&self) -> Anonymous {
        match self {
            Self::Signal(mask) => Anonymous::Signal(mask.clone()),
            Self::Bpf(program) => Anonymous::Bpf(program.clone()),
            Self::Event(counter) => Anonymous::Event(counter.clone()),
            Self::Timer(timer) => Anonymous::Timer(timer.clone()),
            Self::Inotify(instance) => Anonymous::Inotify(instance.clone()),
            Self::Epoll(shared) => Anonymous::Epoll {
                watches: BTreeMap::new(),
                cursor: shared.cursor.clone(),
                shared: shared.clone(),
            },
        }
    }
}

pub(super) struct Watch {
    pub(super) open: OpenWeak,
    pub(super) state: Arc<Mutex<WatchState>>,
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
            Self::Epoll { .. } => b"anon_inode:[eventpoll]",
        }
    }
    pub(super) fn poll(&self, events: u16, pending: u64) -> u16 {
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
            Self::Epoll {
                watches, shared, ..
            } => {
                if shared.ready()
                    || watches.values().any(|w| {
                        let state = w.state.lock().unwrap();
                        state.armed
                            && w.open.upgrade().is_some_and(|o| {
                                let o = o.borrow();
                                let ready = Vfs::peek_poll_open(&o, state.events as u16, pending);
                                ready != 0 && state.ready(ready, Vfs::poll_epoch(&o))
                            })
                    })
                {
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
            Self::Bpf(_)
            | Self::Signal(_)
            | Self::Epoll { .. }
            | Self::Inotify(_)
            | Self::Uring(_) => Err(Errno(22)),
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
    /// Prepare original owner interests at an execution capture boundary.
    /// TCP may have been registered before connect completed. Once connected,
    /// its native transport cannot change routes or become a DNS endpoint;
    /// later namespace filtering affects bytes, never this poll-only authority.
    pub(super) fn promote_tcp_epoll_watches(&self) {
        let descriptors = self.fds.entries();
        for descriptor in descriptors.values() {
            let open_handle::OpenView::Owner(owner) = &descriptor.open else {
                continue;
            };
            if !matches!(owner.borrow().control, Some(SharedControl::Epoll(_))) {
                continue;
            }
            let mut open = owner.borrow_mut();
            let Some(Anonymous::Epoll {
                watches, shared, ..
            }) = open.anonymous.as_mut()
            else {
                continue;
            };
            let promoted: Vec<_> = watches
                .iter()
                .filter_map(|(&key, watch)| {
                    let target = watch.open.upgrade()?;
                    let poll = direct_io::DirectFd::snapshot_tcp_poll(&target.borrow())?;
                    Some((
                        key,
                        watch.state.clone(),
                        direct_io::WatchResource::Owner(poll),
                    ))
                })
                .collect();
            if promoted.is_empty() {
                continue;
            }
            for (key, _, _) in &promoted {
                watches.remove(key);
            }
            shared.promote(promoted, watches.len());
            FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
        }
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
        Ok(reservation.publish(descriptor, Some(&self.fds)))
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
        let version = self.fds.identity();
        version
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
                timers.into_values().collect()
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
        let shared = Arc::new(epoll::LiveEpoll::default());
        self.anonymous(
            flags,
            Anonymous::Epoll {
                watches: BTreeMap::new(),
                cursor: shared.cursor.clone(),
                shared,
            },
        )
    }
    pub fn epoll_ctl(&self, fd: u32, op: u32, target: u32, events: u32, data: u64) -> Result<()> {
        let epoll = self.descriptor(fd)?.open.clone();
        let target_number = target;
        let target = self.descriptor(target)?.open.clone();
        if OpenHandle::ptr_eq(&epoll, &target) {
            return Err(Errno(22));
        }
        let t = target.borrow();
        if t.namespace.is_some()
            || matches!(t.kind, FdKind::Node(_))
                && t.bridge.is_none()
                && t.pipe.is_none()
                && t.kernel_log.is_none()
                && t.mount_file.is_none()
        {
            return Err(Errno(1));
        }
        // Accept ET only for sources with explicit wakeup generations.
        if op != 2
            && events & 0x80000000 != 0
            && !matches!(t.kind, FdKind::Terminal)
            && t.local.is_none()
            && t.pipe.is_none()
            && t.kernel_log.is_none()
            && t.mount_file.is_none()
            && t.socket.as_ref().and_then(|s| s.poll_epoch()).is_none()
            && !matches!(
                t.anonymous,
                Some(
                    Anonymous::Event(_)
                        | Anonymous::Timer(_)
                        | Anonymous::Inotify(_)
                        | Anonymous::Uring(_)
                        | Anonymous::Epoll { .. }
                )
            )
        {
            return Err(Errno(95));
        }
        if matches!(t.anonymous, Some(Anonymous::Bpf(_))) {
            return Err(Errno(1));
        }
        let key = (target_number, t.id);
        let nested = matches!(t.anonymous, Some(Anonymous::Epoll { .. }));
        // The caller's descriptor number distinguishes separate dup registrations.
        drop(t);
        if op == 1 && nested {
            fn check(
                at: &OpenHandle,
                source: &OpenHandle,
                target: &OpenHandle,
                chain: &mut Vec<usize>,
            ) -> Result<()> {
                let open = at.borrow();
                if let Some(Anonymous::Epoll { watches, .. }) = &open.anonymous {
                    if chain.contains(&at.identity()) || chain.len() >= 5 {
                        return Err(Errno(40));
                    }
                    chain.push(at.identity());
                    for child in watches.values().filter_map(|w| w.open.upgrade()) {
                        check(&child, source, target, chain)?;
                    }
                    if OpenHandle::ptr_eq(at, source) {
                        check(target, source, target, chain)?;
                    }
                    chain.pop();
                }
                Ok(())
            }
            for descriptor in self.fds.entries().values() {
                check(&descriptor.open.owned(), &epoll, &target, &mut Vec::new())?;
            }
        }
        if self.epoll_ctl_key(epoll, target, key, op, events, data)? {
            // Only owner-only interests require rebuilding their captures.
            // Admitted interests publish on this object's live index instead.
            FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    fn epoll_ctl_key(
        &self,
        epoll: OpenHandle,
        target: OpenHandle,
        key: (u32, u64),
        op: u32,
        events: u32,
        data: u64,
    ) -> Result<bool> {
        let mut e = epoll.borrow_mut();
        let Some(Anonymous::Epoll {
            watches, shared, ..
        }) = e.anonymous.as_mut()
        else {
            return Err(Errno(22));
        };
        watches.retain(|_, w| w.open.strong_count() != 0);
        shared.set_owner_count(watches.len());
        // An admitted target has one live shared registration, not an owner
        // copy plus a worker snapshot. Nested and signal targets stay here.
        if !watches.contains_key(&key) {
            let t = target.borrow();
            let nested = matches!(t.anonymous, Some(Anonymous::Epoll { .. }));
            drop(t);
            if !nested {
                if let Some(resource) = direct_io::WatchResource::capture(&target.downgrade(), None)
                {
                    return shared
                        .update(key, op, events, data, resource)
                        .map(|()| false);
                }
            }
        }
        if !matches!(op, 1..=3) {
            return Err(Errno(22));
        }
        if op != 2 && events & !0xc000201f != 0 {
            return Err(Errno(95));
        }
        let result = match op {
            1 if watches.contains_key(&key) => Err(Errno(17)),
            2 | 3 if !watches.contains_key(&key) => Err(Errno(2)),
            2 => {
                let watch = watches.remove(&key).unwrap();
                watch.state.lock().unwrap().armed = false;
                shared.set_owner_count(watches.len());
                Ok(())
            }
            _ => {
                if op == 1 && watches.len() + shared.len() >= 1024 {
                    return Err(Errno(28));
                }
                watches.insert(
                    key,
                    Watch {
                        open: target.downgrade(),
                        state: Arc::new(Mutex::new(WatchState {
                            events,
                            data,
                            armed: true,
                            last_ready: 0,
                            last_epoch: [0; 2],
                        })),
                    },
                );
                shared.set_owner_count(watches.len());
                Ok(())
            }
        };
        result.map(|()| true)
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
        if let Some(file) = &o.mount_file {
            return file.watch.poll(0).1;
        }
        if let Some(log) = &o.kernel_log {
            return log.poll(0).1;
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
        if let Some(Anonymous::Epoll {
            watches, shared, ..
        }) = &o.anonymous
        {
            let generation = watches
                .values()
                .filter_map(|watch| watch.open.upgrade())
                .map(|open| Self::poll_epoch(&open.borrow()))
                .fold(shared.epoch(), |sum, epoch| {
                    sum.wrapping_add(epoch[0]).wrapping_add(epoch[1])
                });
            return [generation, 0];
        }
        o.pty
            .as_ref()
            .map_or([0; 2], |end| end.pair.poll_epoch(end.master))
    }
    /// Armed host-input watches can wake externally without a socket or PTY.
    /// Inspect only existing watch metadata; do not consume readiness/one-shots.
    pub fn epoll_waits_for_stdin(&self, fd: u32) -> Result<bool> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        let Some(Anonymous::Epoll { watches, .. }) = &open.anonymous else {
            return Err(Errno(22));
        };
        Ok(watches.values().any(|watch| {
            watch.state.lock().unwrap().armed
                && watch
                    .open
                    .upgrade()
                    .is_some_and(|open| open.borrow().kind == FdKind::Stdin)
        }))
    }
    /// Observe readiness without consuming edges, disarming one-shot watches,
    /// acknowledging native notifications or advancing the delivery cursor.
    pub fn epoll_ready_signals(
        &self,
        fd: u32,
        pending: u64,
        mut special: impl FnMut(&FdKind, u16) -> Result<Option<(u16, [u64; 2])>>,
    ) -> Result<bool> {
        let descriptor = self.descriptor(fd)?;
        let open = descriptor.open.borrow();
        let Some(Anonymous::Epoll {
            watches, shared, ..
        }) = &open.anonymous
        else {
            return Err(Errno(22));
        };
        if shared.ready() {
            return Ok(true);
        }
        for watch in watches.values() {
            let state = watch.state.lock().unwrap();
            if !state.armed {
                continue;
            }
            let Some(target) = watch.open.upgrade() else {
                continue;
            };
            let target = target.borrow();
            let requested = state.events as u16;
            let special = if target.pty.is_none() {
                special(&target.kind, requested)?
            } else {
                None
            };
            let (ready, epoch) = special.unwrap_or_else(|| {
                (
                    Self::peek_poll_open(&target, requested, pending),
                    Self::poll_epoch(&target),
                )
            });
            if ready != 0 && state.ready(ready, epoch) {
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
        let e_descriptor = self.descriptor(fd)?;
        let mut e = e_descriptor.open.borrow_mut();
        let Some(Anonymous::Epoll {
            watches,
            cursor,
            shared,
        }) = e.anonymous.as_mut()
        else {
            return Err(Errno(22));
        };
        watches.retain(|_, w| w.open.strong_count() != 0);
        shared.set_owner_count(watches.len());
        if watches.is_empty() {
            return shared.wait(max, &[]);
        }
        let mut cursor = cursor.lock().unwrap();
        let live = shared.snapshot();
        let mut keys: Vec<_> = watches
            .keys()
            .copied()
            .chain(live.iter().map(|w| w.0))
            .collect();
        keys.sort_unstable();
        let start = cursor.map_or(0, |c| keys.partition_point(|k| *k <= c));
        let mut result = Vec::new();
        for &key in keys[start..].iter().chain(keys[..start].iter()) {
            let Some(watch) = watches.get(&key) else {
                let at = live.binary_search_by_key(&key, |w| w.0).unwrap();
                let (_, state, target) = &live[at];
                let Some(fd) = target.resolve() else {
                    continue;
                };
                let mut state = state.lock().unwrap();
                if !state.armed {
                    continue;
                }
                let (ready, epoch) = fd.peek_poll(state.events as u16);
                if let Some(event) = state.observe(ready, epoch) {
                    fd.acknowledge(epoch);
                    result.push(event);
                    *cursor = Some(key);
                    if result.len() == max {
                        break;
                    }
                }
                continue;
            };
            let mut state = watch.state.lock().unwrap();
            if !state.armed {
                continue;
            }
            let Some(open) = watch.open.upgrade() else {
                continue;
            };
            let o = open.borrow();
            let requested = (state.events & 0xffff) as u16;
            let override_ready = if o.pty.is_none() {
                special(&o.kind, requested)?
            } else {
                None
            };
            let (ready, epoch) = override_ready.unwrap_or_else(|| {
                (
                    Self::peek_poll_open(&o, requested, pending),
                    Self::poll_epoch(&o),
                )
            });
            if let Some(event) = state.observe(ready, epoch) {
                if let Some(file) = &o.mount_file {
                    file.watch.acknowledge(epoch[0]);
                }
                result.push(event);
                *cursor = Some(key);
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
        assert_eq!(v.epoll_ctl(ep, 1, fd, 0x10000001, 42), Err(Errno(95)));
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
        assert_eq!(cached.timers.get().unwrap().len(), 1);
        let mut child = parent.clone();
        let mut shared = parent.clone_with_files(true);
        let second = first + Duration::from_secs(10);
        resource.update(Some((Duration::ZERO, Some(second))));
        assert_eq!(parent.next_timerfd_deadline(), Some(second));
        assert!(
            Rc::ptr_eq(&cached, &parent.fds.identity()),
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
        assert!(version.timers.get().unwrap().is_empty());
        for _ in 0..128 {
            assert_eq!(v.next_timerfd_deadline(), None);
        }
        assert!(Rc::ptr_eq(&version, &v.fds.identity()));
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
    Descriptor {
        open: OpenHandle::new(OpenDescription {
            shared: Arc::new(SharedOpenDescription {
                socket: None,
                _disk_file: None,
                #[cfg(all(feature = "hostfs", unix))]
                host_file: None,
                native_image: None,
                mount_resource: std::sync::OnceLock::new(),
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
                bridge: None,
                kernel_log: None,
                notification: None,
            }),
            position: 0,
            anonymous: Some(anonymous),
            local: None,
            pty: None,
            namespace: None,
            network_control: None,
            mount_file: None,
            oom: None,
            mount: None,
        }),
        cloexec: (flags & O_CLOEXEC != 0).into(),
    }
}
