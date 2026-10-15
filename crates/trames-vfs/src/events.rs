// SPDX-License-Identifier: GPL-3.0-or-later
//! In-process event descriptors. No guest descriptor is a host descriptor.
use super::*;
use std::time::{Duration, Instant};

pub(super) enum Anonymous {
    Signal {
        mask: u64,
    },
    Event {
        count: u64,
        semaphore: bool,
    },
    Timer {
        clock: u32,
        deadline: Option<Instant>,
        interval: Duration,
        pending: u64,
    },
    Epoll {
        watches: BTreeMap<(u32, u64), Watch>,
        cursor: Option<(u32, u64)>,
    },
}

pub(super) struct Watch {
    open: Weak<RefCell<OpenDescription>>,
    events: u32,
    data: u64,
    armed: bool,
}
impl Anonymous {
    pub(super) fn name(&self) -> &'static [u8] {
        match self {
            Self::Signal { .. } => b"anon_inode:[signalfd]",
            Self::Event { .. } => b"anon_inode:[eventfd]",
            Self::Timer { .. } => b"anon_inode:[timerfd]",
            Self::Epoll { .. } => b"anon_inode:[eventpoll]",
        }
    }
    fn tick(&mut self) {
        if let Self::Timer {
            deadline,
            interval,
            pending,
            ..
        } = self
        {
            let now = Instant::now();
            if let Some(d) = deadline.filter(|d| *d <= now) {
                let elapsed = now.saturating_duration_since(d);
                let extra = if interval.is_zero() {
                    0
                } else {
                    elapsed.as_nanos() / interval.as_nanos()
                };
                *pending =
                    pending.saturating_add(extra.saturating_add(1).min(u64::MAX as u128) as u64);
                *deadline = if interval.is_zero() {
                    None
                } else {
                    let left = interval.as_nanos() - elapsed.as_nanos() % interval.as_nanos();
                    now.checked_add(Duration::new(
                        (left / 1_000_000_000) as u64,
                        (left % 1_000_000_000) as u32,
                    ))
                };
            }
        }
    }
    pub(super) fn poll(&self, events: u16, pending: u64) -> u16 {
        match self {
            Self::Signal { mask } => {
                if mask & pending != 0 {
                    events & 1
                } else {
                    0
                }
            }
            Self::Event { count, .. } => {
                (if *count > 0 { events & 1 } else { 0 })
                    | (if *count < u64::MAX - 1 { events & 4 } else { 0 })
            }
            Self::Timer {
                pending, deadline, ..
            } => {
                if *pending != 0 || deadline.is_some_and(|d| d <= Instant::now()) {
                    events & 1
                } else {
                    0
                }
            }
            Self::Epoll { watches, .. } => {
                if watches.values().any(|w| {
                    w.armed
                        && w.open.upgrade().is_some_and(|o| {
                            Vfs::poll_open(&o.borrow(), w.events as u16, pending) != 0
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
        if count < 8 {
            return Err(Errno(22));
        }
        self.tick();
        let value = match self {
            Self::Event { count, semaphore } => {
                if *count == 0 {
                    return Err(Errno(11));
                }
                let value = if *semaphore { 1 } else { *count };
                *count -= value;
                value
            }
            Self::Timer { pending, .. } => {
                if *pending == 0 {
                    return Err(Errno(11));
                }
                std::mem::take(pending)
            }
            Self::Signal { .. } | Self::Epoll { .. } => return Err(Errno(22)),
        };
        Ok(value.to_le_bytes().to_vec())
    }
    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        let Self::Event { count, .. } = self else {
            return Err(Errno(22));
        };
        if bytes.len() < 8 {
            return Err(Errno(22));
        }
        let value = u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes"));
        if value == u64::MAX {
            return Err(Errno(22));
        }
        *count = count
            .checked_add(value)
            .filter(|n| *n < u64::MAX)
            .ok_or(Errno(11))?;
        Ok(8)
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
        let mut open = self.descriptor(fd as u32)?.open.borrow_mut();
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
    fn anonymous(&mut self, flags: u32, anonymous: Anonymous) -> Result<u32> {
        let fd = self.available(0)?;
        self.fds.insert(
            fd,
            Descriptor {
                open: Rc::new(RefCell::new(OpenDescription {
                    id: self.open_id(),
                    owner: (0, 0),
                    kind: FdKind::Anonymous,
                    flags: 2 | (flags & O_NONBLOCK),
                    position: 0,
                    node: None,
                    pipe: None,
                    socket: None,
                    bridge: None,
                    kernel_log: None,
                    anonymous: Some(anonymous),
                    local: None,
                    pty: None,
                    namespace: None,
                    mount: None,
                })),
                cloexec: flags & O_CLOEXEC != 0,
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
            Anonymous::Event {
                count: initial as u64,
                semaphore: flags & 1 != 0,
            },
        )
    }
    pub fn timerfd(&mut self, clock: u32, flags: u32) -> Result<u32> {
        if !matches!(clock, 0 | 1 | 7) || flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(Errno(22));
        }
        self.anonymous(
            flags,
            Anonymous::Timer {
                clock,
                deadline: None,
                interval: Duration::ZERO,
                pending: 0,
            },
        )
    }
    pub fn timerfd_clock(&self, fd: u32) -> Result<u32> {
        match self.descriptor(fd)?.open.borrow().anonymous {
            Some(Anonymous::Timer { clock, .. }) => Ok(clock),
            _ => Err(Errno(22)),
        }
    }
    pub fn timerfd_get(&self, fd: u32) -> Result<(Duration, Duration)> {
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        let a = o.anonymous.as_mut().ok_or(Errno(22))?;
        a.tick();
        match a {
            Anonymous::Timer {
                interval, deadline, ..
            } => Ok((
                *interval,
                deadline.map_or(Duration::ZERO, |d| {
                    d.saturating_duration_since(Instant::now())
                }),
            )),
            _ => Err(Errno(22)),
        }
    }
    pub fn timerfd_set(
        &self,
        fd: u32,
        interval: Duration,
        deadline: Option<Instant>,
    ) -> Result<()> {
        let mut o = self.descriptor(fd)?.open.borrow_mut();
        match o.anonymous.as_mut() {
            Some(Anonymous::Timer {
                interval: i,
                deadline: d,
                pending,
                ..
            }) => {
                *i = interval;
                *d = deadline;
                *pending = 0;
                Ok(())
            }
            _ => Err(Errno(22)),
        }
    }
    pub fn next_timerfd_deadline(&self) -> Option<Instant> {
        self.fds
            .values()
            .filter_map(|d| match d.open.borrow().anonymous {
                Some(Anonymous::Timer { deadline, .. }) => deadline,
                _ => None,
            })
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
                cursor: None,
            },
        )
    }
    pub fn epoll_ctl(&self, fd: u32, op: u32, target: u32, events: u32, data: u64) -> Result<()> {
        let epoll = self.descriptor(fd)?.open.clone();
        let target_number = target;
        let target = self.descriptor(target)?.open.clone();
        if Rc::ptr_eq(&epoll, &target) {
            return Err(Errno(22));
        }
        let t = target.borrow();
        if matches!(t.anonymous, Some(Anonymous::Epoll { .. })) {
            return Err(Errno(95));
        }
        if t.namespace.is_some() || matches!(t.kind, FdKind::Node(_)) && t.bridge.is_none() {
            return Err(Errno(1));
        }
        let key = (target_number, t.id);
        // The caller's descriptor number distinguishes separate dup registrations.
        drop(t);
        self.epoll_ctl_key(epoll, target, key, op, events, data)
    }
    fn epoll_ctl_key(
        &self,
        epoll: Rc<RefCell<OpenDescription>>,
        target: Rc<RefCell<OpenDescription>>,
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
        if op != 2 && events & !0x4000201f != 0 {
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
                        open: Rc::downgrade(&target),
                        events,
                        data,
                        armed: true,
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
        special: impl FnMut(&FdKind, u16) -> Result<Option<u16>>,
    ) -> Result<Vec<(u32, u64)>> {
        self.epoll_wait_signals(fd, max, 0, special)
    }
    pub fn epoll_wait_signals(
        &self,
        fd: u32,
        max: usize,
        pending: u64,
        mut special: impl FnMut(&FdKind, u16) -> Result<Option<u16>>,
    ) -> Result<Vec<(u32, u64)>> {
        let mut e = self.descriptor(fd)?.open.borrow_mut();
        let Some(Anonymous::Epoll { watches, cursor }) = e.anonymous.as_mut() else {
            return Err(Errno(22));
        };
        watches.retain(|_, w| w.open.strong_count() != 0);
        let keys: Vec<_> = watches.keys().copied().collect();
        let start = cursor.map_or(0, |c| keys.partition_point(|k| *k <= c));
        let mut result = Vec::new();
        let mut selected = Vec::new();
        for &key in keys[start..].iter().chain(keys[..start].iter()) {
            let watch = watches.get(&key).expect("watch");
            if !watch.armed {
                continue;
            }
            let Some(open) = watch.open.upgrade() else {
                continue;
            };
            let o = open.borrow();
            let requested = (watch.events & 0xffff) as u16;
            let ready = if let Some(ready) = special(&o.kind, requested)? {
                ready
            } else {
                Self::poll_open(&o, requested, pending)
            };
            if ready != 0 {
                result.push((ready as u32, watch.data));
                selected.push(key);
                if result.len() == max {
                    break;
                }
            }
        }
        for key in selected {
            *cursor = Some(key);
            let watch = watches.get_mut(&key).expect("selected watch");
            if watch.events & 0x40000000 != 0 {
                watch.armed = false;
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
        assert_eq!(v.epoll_ctl(ep, 1, fd, 0x80000001, 42), Err(Errno(95)));
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
