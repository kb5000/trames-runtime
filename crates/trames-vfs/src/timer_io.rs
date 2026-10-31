// SPDX-License-Identifier: GPL-3.0-or-later
//! One timerfd object, shared with workers; no host timer/service thread.
mod clock_watch;
use crate::readiness::Readiness;
use crate::{Errno, Result};
use clock_watch::ClockWatch;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct State {
    deadline: Option<Instant>,
    interval: Duration,
    pending: u64,
    epoch: u64,
    cancel: Option<ClockWatch>,
    cancelled: bool,
    absolute: Option<Duration>,
}
pub struct TimerFd {
    pub clock: u32,
    state: Mutex<State>,
    pub(crate) readiness: Arc<Readiness>,
}
impl TimerFd {
    pub(crate) fn new(clock: u32) -> Arc<Self> {
        Arc::new(Self {
            clock,
            state: Mutex::new(State {
                deadline: None,
                interval: Duration::ZERO,
                pending: 0,
                epoch: 0,
                cancel: None,
                cancelled: false,
                absolute: None,
            }),
            readiness: Arc::default(),
        })
    }
    fn change<T>(&self, f: impl FnOnce(&mut State, Instant) -> T) -> T {
        let mut state = self.state.lock().unwrap();
        let before = state.epoch;
        let result = f(&mut state, Instant::now());
        let changed = state.epoch != before;
        drop(state);
        if changed {
            self.readiness.notify_locked();
        }
        result
    }
    /// Snapshot old state and optionally replace it in the same transaction.
    /// Reset/disarm also notifies waiters so their cached deadline is rebuilt.
    pub fn update(&self, new: Option<(Duration, Option<Instant>)>) -> (Duration, Duration) {
        self.update_mode(new.map(|(i, d)| (i, d, None)))
            .expect("ordinary timers have no native setup")
    }
    pub fn update_mode(
        &self,
        new: Option<(Duration, Option<Instant>, Option<Duration>)>,
    ) -> Result<(Duration, Duration)> {
        // Native registration completes before changing any timer state.
        let watcher = if new.is_some_and(|(_, _, cancel)| cancel.is_some()) {
            Some(ClockWatch::new()?)
        } else {
            None
        };
        self.change(|state, now| {
            state.tick(now);
            let old = (
                state.interval,
                state
                    .deadline
                    .map_or(Duration::ZERO, |d| d.saturating_duration_since(now)),
            );
            let was_cancelled = state.cancelled;
            if let Some((interval, deadline, absolute)) = new {
                state.interval = interval;
                state.deadline = deadline;
                state.pending = 0;
                state.cancel = watcher;
                state.absolute = absolute;
                state.cancelled = false;
                state.epoch = state.epoch.wrapping_add(1);
            }
            if new.is_some() && was_cancelled {
                Err(Errno(125))
            } else {
                Ok(old)
            }
        })
    }
    pub(crate) fn native_fd(&self) -> Option<crate::HostFd> {
        self.state
            .lock()
            .unwrap()
            .cancel
            .as_ref()
            .and_then(ClockWatch::fd)
    }
    pub(crate) fn subscribe(&self, signal: &Arc<crate::IoSignal>) -> crate::IoSubscription {
        let subscription = self.readiness.subscribe(signal);
        match self.native_fd() {
            Some(fd) => subscription.with_host(fd, signal),
            None => subscription,
        }
    }
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.state.lock().unwrap().deadline
    }
    pub(crate) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.change(|state, now| {
            state.tick(now);
            (
                if state.pending != 0 || state.cancelled {
                    events & 1
                } else {
                    0
                },
                [state.epoch, 0],
            )
        })
    }
    pub(crate) fn epoch(&self) -> [u64; 2] {
        [self.state.lock().unwrap().epoch, 0]
    }
    pub(crate) fn read(&self, count: usize) -> Result<Vec<u8>> {
        if count < 8 {
            return Err(Errno(22));
        }
        self.change(|state, now| {
            state.tick(now);
            if state.cancelled {
                state.cancelled = false;
                state.pending = 0;
                return Err(Errno(125));
            }
            if state.pending == 0 {
                return Err(Errno(11));
            }
            Ok(std::mem::take(&mut state.pending).to_le_bytes().to_vec())
        })
    }
}
impl State {
    fn tick(&mut self, now: Instant) {
        if self.cancel.as_ref().is_some_and(ClockWatch::changed) {
            // The absolute target remains in realtime coordinates after a
            // clock step. Cancellation is reported once; an unrearmed timer
            // still expires at that target, rather than the stale host Instant.
            self.deadline = self.absolute.filter(|d| !d.is_zero()).and_then(|target| {
                let real = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?;
                now.checked_add(target.saturating_sub(real))
            });
            self.cancelled = true;
            self.pending = 0;
            self.epoch = self.epoch.wrapping_add(1);
        }
        if let Some(d) = self.deadline.filter(|d| *d <= now) {
            let elapsed = now.saturating_duration_since(d);
            let extra = if self.interval.is_zero() {
                0
            } else {
                elapsed.as_nanos() / self.interval.as_nanos()
            };
            let expirations = extra.saturating_add(1).min(u64::MAX as u128) as u64;
            self.pending = self.pending.saturating_add(expirations);
            self.epoch = self.epoch.wrapping_add(expirations);
            if let Some(target) = self.absolute {
                self.absolute = if self.interval.is_zero() {
                    None
                } else {
                    self.interval
                        .as_nanos()
                        .checked_mul(expirations as u128)
                        .and_then(|ns| {
                            let sec = u64::try_from(ns / 1_000_000_000).ok()?;
                            target.checked_add(Duration::new(sec, (ns % 1_000_000_000) as u32))
                        })
                };
            }
            self.deadline = if self.interval.is_zero() {
                None
            } else {
                let left = self.interval.as_nanos() - elapsed.as_nanos() % self.interval.as_nanos();
                now.checked_add(Duration::new(
                    (left / 1_000_000_000) as u64,
                    (left % 1_000_000_000) as u32,
                ))
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Vfs, O_NONBLOCK};
    #[test]
    fn periodic_expirations_keep_phase_accumulate_and_saturate() {
        let now = Instant::now();
        let mut state = State {
            deadline: Some(now - Duration::from_millis(9)),
            interval: Duration::from_millis(1),
            pending: 0,
            epoch: 0,
            cancel: None,
            cancelled: false,
            absolute: None,
        };
        state.tick(now);
        assert_eq!(state.pending, 10);
        assert_eq!(state.deadline, Some(now + Duration::from_millis(1)));
        state.pending = u64::MAX - 1;
        state.tick(now + Duration::from_millis(5));
        assert_eq!(state.pending, u64::MAX);
        assert_eq!(state.deadline, Some(now + Duration::from_millis(6)));
    }
    #[test]
    fn owner_worker_read_and_edge_oneshot_epoll_share_timer_state() {
        let mut v = Vfs::default();
        let fd = v.timerfd(1, O_NONBLOCK).unwrap();
        let ep = v.epoll_create(0).unwrap();
        v.epoll_ctl(ep, 1, fd, 0xc0000001, 42).unwrap();
        let files = v.direct_descriptors();
        v.timerfd_set(fd, Duration::from_secs(3600), Some(Instant::now()))
            .unwrap();
        assert_eq!(files.get(ep).unwrap().epoll_wait(1).unwrap(), [(1, 42)]);
        assert!(files.get(ep).unwrap().next_deadline().is_none());
        assert_eq!(v.read(fd, 8).unwrap(), 1u64.to_le_bytes());
        assert_eq!(files.get(fd).unwrap().read(8), Err(Errno(11)));
        v.epoll_ctl(ep, 3, fd, 0x80000001, 43).unwrap();
        let fresh = v.direct_descriptors();
        assert!(fresh.get(ep).unwrap().next_deadline().is_some());
        v.timerfd_set(fd, Duration::ZERO, Some(Instant::now()))
            .unwrap();
        assert_eq!(fresh.get(ep).unwrap().epoll_wait(1).unwrap(), [(1, 43)]);
        assert!(v.epoll_wait(ep, 1, |_, _| Ok(None)).unwrap().is_empty());
        assert_eq!(fresh.get(fd).unwrap().read(8).unwrap(), 1u64.to_le_bytes());
        assert_eq!(v.read(fd, 8), Err(Errno(11)));
        // A retained resource is not a retained open description/watch.
        let mut child = v.clone();
        child.close(fd).unwrap();
        child.direct_descriptors();
        v.close(fd).unwrap();
        assert!(child
            .direct_descriptors()
            .get(ep)
            .unwrap()
            .epoll_wait(1)
            .unwrap()
            .is_empty());
    }
}
