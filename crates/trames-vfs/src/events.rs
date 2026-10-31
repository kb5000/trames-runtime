// SPDX-License-Identifier: GPL-3.0-or-later
//! In-process event descriptors. No guest descriptor is a host descriptor.
use super::*;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) enum Anonymous {
    Uring(Rc<Uring>),
    Bpf(Arc<bpf::Program>),
    Inotify(Arc<inotify::InotifyInstance>),
    Signal {
        mask: u64,
    },
    Event(Arc<direct_io::EventCounter>),
    Timer(Arc<TimerFd>),
    Epoll {
        watches: BTreeMap<(u32, u64), Watch>,
        cursor: Arc<Mutex<Option<(u32, u64)>>>,
    },
}

/// Actual anonymous resources whose complete control lifetime is thread-safe.
/// Owner-only signal, epoll and ring controls stay in Anonymous above.
pub(super) enum SharedControl {
    Event(Arc<direct_io::EventCounter>),
    Timer(Arc<TimerFd>),
    Inotify(Arc<inotify::InotifyInstance>),
}
impl SharedControl {
    fn capture(control: &Anonymous) -> Option<Self> {
        Some(match control {
            Anonymous::Event(counter) => Self::Event(counter.clone()),
            Anonymous::Timer(timer) => Self::Timer(timer.clone()),
            Anonymous::Inotify(instance) => Self::Inotify(instance.clone()),
            _ => return None,
        })
    }
    pub(super) fn owner_projection(&self) -> Anonymous {
        match self {
            Self::Event(counter) => Anonymous::Event(counter.clone()),
            Self::Timer(timer) => Anonymous::Timer(timer.clone()),
            Self::Inotify(instance) => Anonymous::Inotify(instance.clone()),
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
            Self::Signal { .. } => b"anon_inode:[signalfd]",
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
            Self::Signal { mask } => {
                if mask & pending != 0 {
                    events & 1
                } else {
                    0
                }
            }
            Self::Event(counter) => counter.poll(events),
            Self::Timer(timer) => timer.poll(events).0,
            Self::Epoll { watches, .. } => {
                if watches.values().any(|w| {
                    let state = w.state.lock().unwrap();
                    state.armed
                        && w.open.upgrade().is_some_and(|o| {
                            let o = o.borrow();
                            let ready = Vfs::poll_open(&o, state.events as u16, pending);
                            ready != 0 && state.ready(ready, Vfs::poll_epoch(&o))
                        })
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
            Self::Bpf(_)
            | Self::Signal { .. }
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
    /// The descriptor holds only its mask. Signals belong to the reading task,
    /// never to the descriptor's creator or the host process.
    pub fn signalfd(&mut self, fd: i32, mask: u64, flags: u32) -> Result<u32> {
        if flags & !(O_NONBLOCK | O_CLOEXEC) != 0 {
            return Err(Errno(22));
        }
        let mask = mask & !((1 << 8) | (1 << 18));
        if fd == -1 {
            return self.anonymous(flags, Anonymous::Signal { mask });
        }
        let open_descriptor = self.descriptor(fd as u32)?;
        let mut open = open_descriptor.open.borrow_mut();
        let Some(Anonymous::Signal { mask: current }) = open.anonymous.as_mut() else {
            return Err(Errno(22));
        };
        *current = mask;
        Ok(fd as u32)
    }
    pub fn signalfd_mask(&self, fd: u32) -> Result<Option<u64>> {
        Ok(match self.descriptor(fd)?.open.borrow().anonymous {
            Some(Anonymous::Signal { mask }) => Some(mask),
            _ => None,
        })
    }
    pub(super) fn anonymous(&mut self, flags: u32, anonymous: Anonymous) -> Result<u32> {
        let fd = self.available(0)?;
        let access = if matches!(anonymous, Anonymous::Inotify(_)) {
            0
        } else {
            2
        };
        self.fds.insert(
            fd,
            Descriptor {
                open: OpenHandle::new(OpenDescription {
                    shared: Arc::new(SharedOpenDescription {
                        _disk_file: None,
                        #[cfg(all(feature = "hostfs", unix))]
                        host_file: None,
                        native_image: None,
                        mount_resource: std::sync::OnceLock::new(),
                        control: SharedControl::capture(&anonymous),
                        read_node: None,
                        id: self.open_id(),
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
                    socket: None,
                    anonymous: Some(anonymous),
                    local: None,
                    pty: None,
                    namespace: None,
                    network_control: None,
                    oom: None,
                    mount: None,
                }),
                cloexec: (flags & O_CLOEXEC != 0).into(),
            },
        );
        Ok(fd)
    }
    pub fn eventfd(&mut self, initial: u32, flags: u32) -> Result<u32> {
        if flags & !(O_CLOEXEC | O_NONBLOCK | 1) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(
            flags,
            Anonymous::Event(Arc::new(direct_io::EventCounter::new(
                initial as u64,
                flags & 1 != 0,
            ))),
        )
    }
    pub fn timerfd(&mut self, clock: u32, flags: u32) -> Result<u32> {
        if !matches!(clock, 0 | 1 | 7) || flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(flags, Anonymous::Timer(TimerFd::new(clock)))
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
        self.anonymous(
            flags,
            Anonymous::Epoll {
                watches: BTreeMap::new(),
                cursor: Arc::default(),
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
            && t.socket.as_ref().and_then(|s| s.poll_epoch()).is_none()
            && !matches!(
                t.anonymous,
                Some(
                    Anonymous::Event(_)
                        | Anonymous::Timer(_)
                        | Anonymous::Inotify(_)
                        | Anonymous::Uring(_)
                )
            )
        {
            return Err(Errno(95));
        }
        if matches!(t.anonymous, Some(Anonymous::Bpf(_))) {
            return Err(Errno(1));
        }
        if matches!(t.anonymous, Some(Anonymous::Epoll { .. })) {
            return Err(Errno(95));
        }
        let key = (target_number, t.id);
        // The caller's descriptor number distinguishes separate dup registrations.
        drop(t);
        self.epoll_ctl_key(epoll, target, key, op, events, data)?;
        // Cached worker snapshots include the complete frozen watch set.
        FD_FLAGS_REVISION.fetch_add(1, Ordering::Relaxed);
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
    ) -> Result<()> {
        let mut e = epoll.borrow_mut();
        let Some(Anonymous::Epoll { watches, .. }) = e.anonymous.as_mut() else {
            return Err(Errno(22));
        };
        watches.retain(|_, w| w.open.strong_count() != 0);
        if !matches!(op, 1..=3) {
            return Err(Errno(22));
        }
        if op != 2 && events & !0xc000201f != 0 {
            return Err(Errno(95));
        }
        match op {
            1 if watches.contains_key(&key) => Err(Errno(17)),
            2 | 3 if !watches.contains_key(&key) => Err(Errno(2)),
            2 => {
                watches.remove(&key);
                Ok(())
            }
            _ => {
                if op == 1 && watches.len() >= 1024 {
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
                Ok(())
            }
        }
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
    pub fn epoll_wait_signals(
        &self,
        fd: u32,
        max: usize,
        pending: u64,
        mut special: impl FnMut(&FdKind, u16) -> Result<Option<(u16, [u64; 2])>>,
    ) -> Result<Vec<(u32, u64)>> {
        let e_descriptor = self.descriptor(fd)?;
        let mut e = e_descriptor.open.borrow_mut();
        let Some(Anonymous::Epoll { watches, cursor }) = e.anonymous.as_mut() else {
            return Err(Errno(22));
        };
        watches.retain(|_, w| w.open.strong_count() != 0);
        let mut cursor = cursor.lock().unwrap();
        let keys: Vec<_> = watches.keys().copied().collect();
        let start = cursor.map_or(0, |c| keys.partition_point(|k| *k <= c));
        let mut result = Vec::new();
        for &key in keys[start..].iter().chain(keys[..start].iter()) {
            let watch = watches.get(&key).expect("watch");
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
                    Self::poll_open(&o, requested, pending),
                    Self::poll_epoch(&o),
                )
            });
            if let Some(event) = state.observe(ready, epoch) {
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
        for _ in 0..MAX_FDS / 2 {
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
        for _ in 0..MAX_FDS / 2 {
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
