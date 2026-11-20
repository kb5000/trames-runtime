// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::task_control::Group;
use std::sync::OnceLock;

enum Owner {
    Process(Weak<Group>),
    Thread(Weak<IoTask>),
}

pub(super) struct CpuClock {
    owner: Owner,
    schedule: Option<Arc<CpuSchedule>>,
}

impl CpuClock {
    pub(super) fn new(
        clock: u32,
        notify: bool,
        caller: &IoTask,
        directory: &IoDirectory,
    ) -> Result<Self, Errno> {
        let schedule = |slot: &OnceLock<Arc<CpuSchedule>>| {
            notify.then(|| slot.get_or_init(Default::default).clone())
        };
        let (owner, schedule) = if clock == 2 {
            let group = caller.lifecycle();
            (
                Owner::Process(Arc::downgrade(group)),
                schedule(&group.posix_timers),
            )
        } else {
            let task = directory
                .proc_task(caller.tid())
                .filter(|t| std::ptr::eq(t.as_ref(), caller))
                .ok_or(Errno(3))?;
            (
                Owner::Thread(Arc::downgrade(&task)),
                schedule(&task.posix_timers),
            )
        };
        Ok(Self { owner, schedule })
    }

    fn now(&self) -> Option<Duration> {
        match &self.owner {
            Owner::Process(g) => Some(g.upgrade()?.cpu_time()),
            Owner::Thread(t) => Some(t.upgrade().filter(|t| t.live())?.proc_view.elapsed()),
        }
    }

    pub(super) fn remove(&self, id: i32, deadline: Option<Duration>) {
        if let (Some(schedule), Some(deadline)) = (&self.schedule, deadline) {
            schedule.update(id, Some(deadline), None);
        }
    }

    pub(super) fn update(
        &self,
        id: i32,
        timer: &Arc<Timer>,
        state: &mut State,
        new: Option<(Duration, Duration, bool)>,
        output: Option<u64>,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let now = self.now();
        let new = match new {
            Some((interval, value, absolute)) => {
                let now = now.ok_or(Errno(3))?;
                let deadline = if value.is_zero() {
                    None
                } else if absolute {
                    Some(value)
                } else {
                    Some(now.checked_add(value).ok_or(Errno(22))?)
                };
                Some((interval, deadline, now))
            }
            None => None,
        };
        if let Some(out) = output {
            let (interval, left) = match (state.cpu_deadline, now) {
                (Some(d), Some(now)) if now < d => (state.interval, d - now),
                (Some(d), Some(now)) if self.schedule.is_none() => (
                    state.interval,
                    period_remaining(now - d, state.interval).unwrap_or_default(),
                ),
                (Some(_), Some(_)) => (state.interval, Duration::from_nanos(1)),
                _ => (Duration::ZERO, Duration::ZERO),
            };
            write_times(memory, out, interval, left, false)?;
        }
        if let Some((interval, deadline, now)) = new {
            let old = state.cpu_deadline;
            state.cpu_deadline = deadline;
            state.interval = interval;
            state.overrun = 0;
            if let Some(schedule) = &self.schedule {
                if let Some(d) = deadline.filter(|d| *d <= now) {
                    schedule.expire_one(id, timer, state, old, d, now);
                } else {
                    schedule.update(id, old, deadline.map(|d| (d, Arc::downgrade(timer))));
                }
            }
        }
        Ok(0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CpuEventId {
    Timer(i32),
    Sleep(usize),
}
enum CpuEvent {
    Timer(Weak<Timer>),
    Sleep(Weak<CpuSleep>),
}
type Entries = BTreeMap<(Duration, CpuEventId), CpuEvent>;

/// One sleeper on its own process clock. The clock's existing accounting
/// schedule owns a weak entry, so cancellation needs no timer ID or signal.
pub struct CpuSleep {
    group: Weak<Group>,
    schedule: Arc<CpuSchedule>,
    deadline: Duration,
    expired: AtomicBool,
    wake: Mutex<Weak<trames_shared::IoSignal>>,
}
impl CpuSleep {
    pub fn new(task: &IoTask, value: Duration, absolute: bool) -> Result<Arc<Self>, Errno> {
        let group = task.lifecycle();
        let now = group.cpu_time();
        let deadline = if absolute {
            value
        } else {
            now.checked_add(value).ok_or(Errno(22))?
        };
        let schedule = group.posix_timers.get_or_init(Default::default).clone();
        let wait = Arc::new(Self {
            group: Arc::downgrade(group),
            schedule,
            deadline,
            expired: AtomicBool::new(deadline <= now),
            wake: Mutex::default(),
        });
        if deadline > now {
            let mut entries = wait.schedule.entries.lock().unwrap();
            entries.insert(wait.key(), CpuEvent::Sleep(Arc::downgrade(&wait)));
            wait.schedule.publish(&entries);
            drop(entries);
            wait.schedule.charge(|| group.cpu_time());
        }
        Ok(wait)
    }
    fn key(&self) -> (Duration, CpuEventId) {
        (
            self.deadline,
            CpuEventId::Sleep(self as *const Self as usize),
        )
    }
    pub fn ready(&self) -> bool {
        self.expired.load(Ordering::Relaxed)
    }
    pub fn remaining(&self) -> Duration {
        self.group.upgrade().map_or(Duration::ZERO, |g| {
            self.deadline.saturating_sub(g.cpu_time())
        })
    }
    pub fn bind(&self, signal: &Arc<trames_shared::IoSignal>) {
        *self.wake.lock().unwrap() = Arc::downgrade(signal);
    }
}
impl Drop for CpuSleep {
    fn drop(&mut self) {
        let mut entries = self.schedule.entries.lock().unwrap();
        entries.remove(&self.key());
        self.schedule.publish(&entries);
    }
}

/// Indexed by the clock being charged, irrespective of the signal recipient.
/// Queue entries never keep the original timer, process or thread alive.
pub(crate) struct CpuSchedule {
    next_ns: AtomicU64,
    entries: Mutex<Entries>,
}
impl Default for CpuSchedule {
    fn default() -> Self {
        Self {
            next_ns: AtomicU64::new(u64::MAX),
            entries: Default::default(),
        }
    }
}
impl CpuSchedule {
    fn publish(&self, entries: &Entries) {
        self.next_ns.store(
            entries.first_key_value().map_or(u64::MAX, |((d, _), _)| {
                d.as_nanos().min((u64::MAX - 1) as u128) as u64
            }),
            Ordering::Relaxed,
        );
    }

    fn update(&self, id: i32, old: Option<Duration>, new: Option<(Duration, Weak<Timer>)>) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(d) = old {
            entries.remove(&(d, CpuEventId::Timer(id)));
        }
        if let Some((d, timer)) = new {
            entries.insert((d, CpuEventId::Timer(id)), CpuEvent::Timer(timer));
        }
        self.publish(&entries);
    }

    pub(crate) fn charge(&self, now: impl FnOnce() -> Duration) {
        let next = self.next_ns.load(Ordering::Relaxed);
        if next == u64::MAX {
            return;
        }
        let now = now();
        if now < Duration::from_nanos(next) {
            return;
        }
        // Detach a finite batch before taking timer locks or delivering signals.
        let due = {
            let mut entries = self.entries.lock().unwrap();
            let mut due = Vec::new();
            while entries
                .first_key_value()
                .is_some_and(|((d, _), _)| *d <= now)
            {
                due.push(entries.pop_first().unwrap());
            }
            self.publish(&entries);
            due
        };
        for ((deadline, key), event) in due {
            let (id, timer) = match (key, event) {
                (CpuEventId::Timer(id), CpuEvent::Timer(timer)) => (id, timer),
                (CpuEventId::Sleep(_), CpuEvent::Sleep(wait)) => {
                    if let Some(wait) = wait.upgrade() {
                        wait.expired.store(true, Ordering::Relaxed);
                        let wake = wait.wake.lock().unwrap().upgrade();
                        if let Some(wake) = wake {
                            wake.notify();
                        }
                    }
                    continue;
                }
                _ => unreachable!("clock event key and resource disagree"),
            };
            let Some(timer) = timer.upgrade() else {
                continue;
            };
            let mut state = timer.state.lock().unwrap();
            if !state.deleted && state.cpu_deadline == Some(deadline) {
                self.expire_one(id, &timer, &mut state, Some(deadline), deadline, now);
            }
        }
    }

    fn expire_one(
        &self,
        id: i32,
        timer: &Arc<Timer>,
        state: &mut State,
        old: Option<Duration>,
        deadline: Duration,
        now: Duration,
    ) {
        let elapsed = now - deadline;
        state.cpu_deadline =
            period_remaining(elapsed, state.interval).and_then(|left| now.checked_add(left));
        self.update(
            id,
            old,
            state.cpu_deadline.map(|d| (d, Arc::downgrade(timer))),
        );
        timer.deliver(id, state, elapsed);
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{call, setup};
    use super::*;

    #[test]
    fn process_sleep_uses_group_execution_and_cancels_its_exact_entry() {
        let (_, directory, leader, _) = setup();
        let peer = Arc::new(IoTask::default());
        peer.share_process(&leader);
        directory.publish(&peer, 43, 42, 42, 0, 0);
        let group = leader.lifecycle();
        group.register(&leader, 42);
        group.register(&peer, 43);
        let ns = Duration::from_nanos;
        peer.proc_view.account(ns(7), 1);
        let relative = CpuSleep::new(&leader, ns(5), false).unwrap();
        let absolute = CpuSleep::new(&peer, ns(12), true).unwrap();
        let cancelled = CpuSleep::new(&leader, ns(12), true).unwrap();
        let schedule = &relative.schedule;
        assert_eq!(schedule.entries.lock().unwrap().len(), 3);
        drop(cancelled);
        assert_eq!(schedule.entries.lock().unwrap().len(), 2);
        for _ in 0..3 {
            leader.check_cpu_timers();
        }
        assert_eq!(relative.remaining(), ns(5));
        assert!(!relative.ready());
        peer.proc_view.account(ns(5), 1);
        peer.check_cpu_timers();
        assert!(relative.ready() && absolute.ready());
        assert!(schedule.entries.lock().unwrap().is_empty());
        assert_eq!(schedule.next_ns.load(Ordering::Relaxed), u64::MAX);
        assert!(CpuSleep::new(&peer, ns(1), true).unwrap().ready());
    }
    #[test]
    fn process_and_thread_alarms_follow_their_original_clocks() {
        let (timers, directory, leader, mut memory) = setup();
        let peer = Arc::new(IoTask::default());
        peer.share_process(&leader);
        directory.publish(&peer, 43, 42, 42, 0, 0);
        let group = leader.lifecycle();
        group.register(&leader, 42);
        group.register(&peer, 43);
        peer.proc_view.account(Duration::from_nanos(2), 1);
        let mut ids = Vec::new();
        for clock in [2, 3] {
            timers
                .call(
                    107,
                    [clock, 0, 0x1000, 0, 0, 0],
                    &mut memory,
                    Instant::now(),
                    &peer,
                    &directory,
                    &PidNamespace::default(),
                )
                .unwrap();
            let id = u32::from_le_bytes(memory.read_array(0x1000).unwrap()) as u64;
            ids.push(id);
            // A different thread arms the timer relative to the original clock.
            write_times(
                &mut memory,
                0x1100,
                Duration::from_nanos(4),
                Duration::from_nanos(10),
                false,
            )
            .unwrap();
            call(
                &timers,
                &directory,
                &mut memory,
                110,
                [id, 0, 0x1100, 0x1100, 0, 0],
            )
            .unwrap();
            assert_eq!(memory.read_array::<32>(0x1100).unwrap(), [0; 32]);
        }
        assert!(timers.next_deadline().is_none());
        leader.check_cpu_timers();
        assert_eq!(leader.process().bits(), 0);
        leader.proc_view.account(Duration::from_nanos(21), 0);
        leader.check_cpu_timers();
        assert_eq!(
            leader.process().take(14).unwrap().timer,
            Some((ids[0] as i32, 2, ids[0]))
        );
        call(
            &timers,
            &directory,
            &mut memory,
            111,
            [ids[0], 0, 0, 0, 0, 0],
        )
        .unwrap();
        call(
            &timers,
            &directory,
            &mut memory,
            108,
            [ids[1], 0x1200, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(memory.read_u64(0x1218).unwrap(), 10);
        peer.proc_view.account(Duration::from_nanos(10), 1);
        peer.check_cpu_timers();
        assert_eq!(
            leader.process().take(14).unwrap().timer,
            Some((ids[1] as i32, 0, ids[1]))
        );
        // An absolute expiration already in the past fires inside settime.
        write_times(
            &mut memory,
            0x1100,
            Duration::ZERO,
            Duration::from_nanos(1),
            false,
        )
        .unwrap();
        call(
            &timers,
            &directory,
            &mut memory,
            110,
            [ids[1], 1, 0x1100, 0, 0, 0],
        )
        .unwrap();
        assert!(leader.process().take(14).is_some());
        peer.exit();
        call(
            &timers,
            &directory,
            &mut memory,
            108,
            [ids[1], 0x1200, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(memory.read_array::<32>(0x1200).unwrap(), [0; 32]);
        assert_eq!(
            call(
                &timers,
                &directory,
                &mut memory,
                110,
                [ids[1], 0, 0x1100, 0, 0, 0]
            ),
            Err(Errno(3))
        );
        timers.clear_process(42, true);
        assert_eq!(
            call(
                &timers,
                &directory,
                &mut memory,
                109,
                [ids[1], 0, 0, 0, 0, 0]
            ),
            Err(Errno(22))
        );
    }

    #[test]
    fn silent_cpu_timer_keeps_phase_without_installing_accounting_work() {
        let (timers, directory, task, mut memory) = setup();
        memory.write_array(0x140c, 1u32.to_le_bytes()).unwrap();
        call(
            &timers,
            &directory,
            &mut memory,
            107,
            [3, 0x1400, 0x1000, 0, 0, 0],
        )
        .unwrap();
        let id = u32::from_le_bytes(memory.read_array(0x1000).unwrap()) as u64;
        write_times(
            &mut memory,
            0x1100,
            Duration::from_nanos(10),
            Duration::from_nanos(3),
            false,
        )
        .unwrap();
        call(
            &timers,
            &directory,
            &mut memory,
            110,
            [id, 1, 0x1100, 0, 0, 0],
        )
        .unwrap();
        task.proc_view.account(Duration::from_nanos(26), 0);
        task.check_cpu_timers();
        call(
            &timers,
            &directory,
            &mut memory,
            108,
            [id, 0x1200, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(memory.read_u64(0x1218).unwrap(), 7);
        assert!(task.posix_timers.get().is_none());
        assert_eq!(task.process().bits(), 0);
    }
}
