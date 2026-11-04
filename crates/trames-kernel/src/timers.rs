// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared POSIX/interval timers. Existing executors drive the original deadline
//! index; no timer thread, guest pointer retention or syscall RPC is required.
use crate::signal::{Info, IoDirectory, TimerTarget};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trames_memory::{Access, CpuMemory};
use trames_vfs::{Errno, PidNamespace};

pub fn timer_call(number: u32) -> bool {
    matches!(number, 102 | 103 | 107..=111)
}
pub trait TimerWake: Send + Sync {
    fn timers_changed(&self);
}
struct Timer {
    tgid: u32,
    clock: u64,
    signal: u32,
    value: u64,
    target: Option<TimerTarget>,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    deleted: bool,
    deadline: Option<Instant>,
    interval: Duration,
    overrun: i32,
}
struct Registry {
    next_id: i32,
    timers: BTreeMap<i32, Arc<Timer>>,
}
pub struct Timers {
    registry: RwLock<Registry>,
    schedule: Mutex<BTreeSet<(Instant, i32)>>,
    origin: Instant,
    next: AtomicU64,
    wake: Mutex<Option<Weak<dyn TimerWake>>>,
}
impl Default for Timers {
    fn default() -> Self {
        Self {
            registry: RwLock::new(Registry {
                next_id: 1,
                timers: BTreeMap::new(),
            }),
            schedule: Default::default(),
            origin: Instant::now(),
            next: AtomicU64::new(u64::MAX),
            wake: Default::default(),
        }
    }
}
fn duration(memory: &impl CpuMemory, address: u64, micros: bool) -> Result<Duration, Errno> {
    let b = memory.read_array::<16>(address).map_err(|_| Errno(14))?;
    let sec = u64::from_le_bytes(b[..8].try_into().unwrap());
    let sub = u64::from_le_bytes(b[8..].try_into().unwrap());
    let limit = if micros { 1_000_000 } else { 1_000_000_000 };
    if sec > i64::MAX as u64 || sub >= limit {
        return Err(Errno(22));
    }
    Ok(Duration::new(
        sec,
        sub as u32 * if micros { 1000 } else { 1 },
    ))
}
fn export(
    memory: &mut impl CpuMemory,
    address: u64,
    state: &State,
    micros: bool,
    lazy: bool,
) -> Result<(), Errno> {
    let mut bytes = [0; 32];
    let now = Instant::now();
    let left = state.deadline.map_or(Duration::ZERO, |deadline| {
        if lazy && deadline <= now && !state.interval.is_zero() {
            let ns = state.interval.as_nanos()
                - now.saturating_duration_since(deadline).as_nanos() % state.interval.as_nanos();
            Duration::new((ns / 1_000_000_000) as u64, (ns % 1_000_000_000) as u32)
        } else {
            deadline.saturating_duration_since(now)
        }
    });
    for (chunk, d) in bytes.chunks_exact_mut(16).zip([state.interval, left]) {
        chunk[..8].copy_from_slice(&d.as_secs().to_le_bytes());
        chunk[8..].copy_from_slice(
            &(if micros {
                d.subsec_micros() as u64
            } else {
                d.subsec_nanos() as u64
            })
            .to_le_bytes(),
        );
    }
    memory.write_array(address, bytes).map_err(|_| Errno(14))
}
impl Timers {
    pub fn bind(&self, wake: Weak<dyn TimerWake>) {
        *self.wake.lock().unwrap() = Some(wake);
    }
    fn ticks(&self, d: Instant) -> u64 {
        d.saturating_duration_since(self.origin)
            .as_nanos()
            .min((u64::MAX - 1) as u128) as u64
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        let ticks = self.next.load(Ordering::Relaxed);
        (ticks != u64::MAX).then(|| self.origin + Duration::from_nanos(ticks))
    }
    pub fn due(&self) -> bool {
        self.next_deadline().is_some_and(|d| d <= Instant::now())
    }
    fn publish(&self, schedule: &BTreeSet<(Instant, i32)>) {
        self.next.store(
            schedule.first().map_or(u64::MAX, |(d, _)| self.ticks(*d)),
            Ordering::Relaxed,
        );
    }
    fn reschedule(&self, id: i32, old: Option<Instant>, new: Option<Instant>) {
        if old == new {
            return;
        }
        let earlier = {
            let mut schedule = self.schedule.lock().unwrap();
            let previous = schedule.first().map(|(d, _)| *d);
            if let Some(d) = old {
                schedule.remove(&(d, id));
            }
            if let Some(d) = new {
                schedule.insert((d, id));
            }
            self.publish(&schedule);
            schedule
                .first()
                .is_some_and(|(d, _)| previous.is_none_or(|p| *d < p))
        };
        if earlier {
            let wake = self.wake.lock().unwrap().as_ref().and_then(Weak::upgrade);
            if let Some(wake) = wake {
                wake.timers_changed();
            }
        }
    }
    fn lookup(&self, tgid: u32, id: i32) -> Result<Arc<Timer>, Errno> {
        self.registry
            .read()
            .unwrap()
            .timers
            .get(&id)
            .filter(|t| t.tgid == tgid)
            .cloned()
            .ok_or(Errno(22))
    }
    fn retire(&self, id: i32, timer: &Timer) {
        let mut state = timer.state.lock().unwrap();
        state.deleted = true;
        let old = state.deadline.take();
        if timer.signal != 0 {
            self.reschedule(id, old, None);
        }
    }
    pub fn clear_process(&self, tgid: u32, exec: bool) {
        let removed = {
            let mut registry = self.registry.write().unwrap();
            let ids: Vec<_> = registry
                .timers
                .iter()
                .filter_map(|(&id, t)| (t.tgid == tgid && (!exec || id > 0)).then_some(id))
                .collect();
            ids.into_iter()
                .map(|id| (id, registry.timers.remove(&id).unwrap()))
                .collect::<Vec<_>>()
        };
        for (id, timer) in removed {
            self.retire(id, &timer);
        }
    }
    /// Called outside the execution-queue mutex. Timer state -> deadline index
    /// is the only nested order; the index is released before any signal wake.
    pub fn tick(&self) {
        if !self.due() {
            return;
        }
        let due = {
            let mut schedule = self.schedule.lock().unwrap();
            let until = Instant::now();
            let due: Vec<_> = schedule.range(..=(until, i32::MAX)).copied().collect();
            for entry in &due {
                schedule.remove(entry);
            }
            self.publish(&schedule);
            due
        };
        // Process each accepted expiration once. Sub-microsecond periodic
        // timers must yield execution rather than keep this maintenance loop hot.
        for (deadline, id) in due {
            let timer = self.registry.read().unwrap().timers.get(&id).cloned();
            let Some(timer) = timer else { continue };
            let mut state = timer.state.lock().unwrap();
            if state.deleted || state.deadline != Some(deadline) {
                continue;
            }
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(deadline).as_nanos();
            let extra = if state.interval.is_zero() {
                0
            } else {
                elapsed / state.interval.as_nanos()
            };
            state.deadline = if state.interval.is_zero() {
                None
            } else {
                let remaining = state.interval.as_nanos() - elapsed % state.interval.as_nanos();
                now.checked_add(Duration::new(
                    (remaining / 1_000_000_000) as u64,
                    (remaining % 1_000_000_000) as u32,
                ))
            };
            self.reschedule(id, Some(deadline), state.deadline);
            state.overrun = extra.min(i32::MAX as u128) as i32;
            if timer.signal != 0 {
                state.overrun = timer.target.as_ref().unwrap().signal(
                    timer.signal,
                    Info {
                        code: if id < 0 { 128 } else { -2 },
                        timer: if id < 0 {
                            None
                        } else {
                            Some((id, state.overrun, timer.value))
                        },
                        ..Info::default()
                    },
                );
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        started: Instant,
        tgid: u32,
        directory: &IoDirectory,
        namespace: &PidNamespace,
    ) -> Result<u64, Errno> {
        if matches!(number, 102 | 103) {
            if a[0] != 0 {
                return Err(Errno(if a[0] <= 2 { 95 } else { 22 }));
            }
            let id = -(tgid as i32);
            let output = if number == 102 { a[1] } else { a[2] };
            if number == 102 || output != 0 {
                memory
                    .check(output, 32, Access::Write)
                    .map_err(|_| Errno(14))?;
            }
            let new = if number == 103 {
                let interval = duration(memory, a[1], true)?;
                let value = duration(memory, a[1].checked_add(16).ok_or(Errno(14))?, true)?;
                let deadline = if value.is_zero() {
                    None
                } else {
                    Some(Instant::now().checked_add(value).ok_or(Errno(22))?)
                };
                Some((interval, deadline))
            } else {
                None
            };
            let timer = if number == 103 {
                let target = Some(directory.timer_target(tgid, None)?);
                let mut registry = self.registry.write().unwrap();
                registry
                    .timers
                    .entry(id)
                    .or_insert_with(|| {
                        Arc::new(Timer {
                            tgid,
                            clock: 1,
                            signal: 14,
                            value: 0,
                            target,
                            state: Default::default(),
                        })
                    })
                    .clone()
            } else {
                match self.lookup(tgid, id) {
                    Ok(t) => t,
                    Err(_) => {
                        export(memory, output, &State::default(), true, false)?;
                        return Ok(0);
                    }
                }
            };
            let mut state = timer.state.lock().unwrap();
            if state.deleted {
                return Err(Errno(22));
            }
            if number == 102 || output != 0 {
                export(memory, output, &state, true, false)?;
            }
            if let Some((interval, deadline)) = new {
                let old = state.deadline;
                state.interval = interval;
                state.deadline = deadline;
                state.overrun = 0;
                self.reschedule(id, old, deadline);
            }
            return Ok(0);
        }
        if number == 107 {
            if !matches!(a[0], 0 | 1) {
                return Err(Errno(22));
            }
            memory
                .check(a[2], 4, Access::Write)
                .map_err(|_| Errno(14))?;
            let mut registry = self.registry.write().unwrap();
            let id = registry.next_id;
            let (signal, value, thread) = if a[1] == 0 {
                (14, id as u64, None)
            } else {
                let b = memory.read_array::<16>(a[1]).map_err(|_| Errno(14))?;
                let value = u64::from_le_bytes(b[..8].try_into().unwrap());
                let signal = u32::from_le_bytes(b[8..12].try_into().unwrap());
                let notify = u32::from_le_bytes(b[12..16].try_into().unwrap());
                if notify != 1 && (signal == 0 || signal > 64) {
                    return Err(Errno(22));
                }
                let thread = match notify {
                    0 | 1 => None,
                    4 => {
                        let tid = u32::from_le_bytes(
                            memory
                                .read_array::<4>(a[1].checked_add(16).ok_or(Errno(14))?)
                                .map_err(|_| Errno(14))?,
                        );
                        Some(namespace.global(tid).ok_or(Errno(22))?)
                    }
                    _ => return Err(Errno(22)),
                };
                (if notify == 1 { 0 } else { signal }, value, thread)
            };
            let target = if signal == 0 {
                None
            } else {
                Some(directory.timer_target(tgid, thread)?)
            };
            if registry.timers.keys().filter(|id| **id > 0).count() >= 32 {
                return Err(Errno(11));
            }
            let next = id.checked_add(1).ok_or(Errno(11))?;
            memory
                .write_array(a[2], id.to_le_bytes())
                .map_err(|_| Errno(14))?;
            registry.next_id = next;
            registry.timers.insert(
                id,
                Arc::new(Timer {
                    tgid,
                    clock: a[0],
                    signal,
                    value,
                    target,
                    state: Default::default(),
                }),
            );
            return Ok(0);
        }
        let id = a[0] as i32;
        if id < 1 {
            return Err(Errno(22));
        }
        let timer = self.lookup(tgid, id)?;
        let mut state = timer.state.lock().unwrap();
        if state.deleted {
            return Err(Errno(22));
        }
        match number {
            109 => Ok(state.overrun as u64),
            111 => {
                state.deleted = true;
                let old = state.deadline.take();
                if timer.signal != 0 {
                    self.reschedule(id, old, None);
                }
                drop(state);
                self.registry.write().unwrap().timers.remove(&id);
                Ok(0)
            }
            108 | 110 => {
                let output = if number == 108 { a[1] } else { a[3] };
                if number == 108 || output != 0 {
                    memory
                        .check(output, 32, Access::Write)
                        .map_err(|_| Errno(14))?;
                }
                let new = if number == 110 {
                    let interval = duration(memory, a[2], false)?;
                    let value = duration(memory, a[2].checked_add(16).ok_or(Errno(14))?, false)?;
                    let deadline = if value.is_zero() {
                        None
                    } else {
                        let duration = if a[1] & 1 == 0 {
                            value
                        } else {
                            let now = if timer.clock == 0 {
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .map_err(|_| Errno(5))?
                            } else {
                                started.elapsed()
                            };
                            value.saturating_sub(now)
                        };
                        Some(Instant::now().checked_add(duration).ok_or(Errno(22))?)
                    };
                    Some((interval, deadline))
                } else {
                    None
                };
                if number == 108 || output != 0 {
                    export(memory, output, &state, false, timer.signal == 0)?;
                }
                if let Some((interval, deadline)) = new {
                    let old = state.deadline;
                    state.interval = interval;
                    state.deadline = deadline;
                    state.overrun = 0;
                    if timer.signal != 0 {
                        self.reschedule(id, old, deadline);
                    }
                }
                Ok(0)
            }
            _ => Err(Errno(38)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::IoTask;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    fn setup() -> (Timers, Arc<IoDirectory>, Arc<IoTask>, Memory) {
        let directory = Arc::new(IoDirectory::default());
        let task = Arc::new(IoTask::default());
        directory.publish(&task, 42, 42, 42, 0, 0);
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        (Timers::default(), directory, task, m)
    }
    fn call(
        t: &Timers,
        d: &IoDirectory,
        m: &mut Memory,
        n: u32,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        t.call(n, a, m, Instant::now(), 42, d, &PidNamespace::default())
    }
    fn create(t: &Timers, d: &IoDirectory, m: &mut Memory) -> i32 {
        call(t, d, m, 107, [1, 0, 0x1000, 0, 0, 0]).unwrap();
        m.read_u64(0x1000).unwrap() as i32
    }
    #[test]
    fn timer_abi_faults_aliases_and_retirement_preserve_original_state() {
        let (t, d, _task, mut m) = setup();
        let id = create(&t, &d, &mut m);
        for (at, value) in [(0x1100, 0u64), (0x1108, 0), (0x1110, 60), (0x1118, 0)] {
            m.write_array(at, value.to_le_bytes()).unwrap();
        }
        call(&t, &d, &mut m, 110, [id as u64, 0, 0x1100, 0x1100, 0, 0]).unwrap();
        assert_eq!(m.read_array::<32>(0x1100).unwrap(), [0; 32]);
        m.write_array(0x1118, 1_000_000_000u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            call(&t, &d, &mut m, 110, [id as u64, 0, 0x1100, 0, 0, 0]),
            Err(Errno(22))
        );
        m.write_array(0x1118, 0u64.to_le_bytes()).unwrap();
        assert_eq!(
            call(&t, &d, &mut m, 110, [id as u64, 0, 0x1100, 0x1ff8, 0, 0]),
            Err(Errno(14))
        );
        call(&t, &d, &mut m, 108, [id as u64, 0x1200, 0, 0, 0, 0]).unwrap();
        assert!(m.read_u64(0x1210).unwrap() >= 59);
        assert!(t.next_deadline().is_some());
        call(&t, &d, &mut m, 111, [id as u64, 0, 0, 0, 0, 0]).unwrap();
        assert!(t.next_deadline().is_none());
        assert_eq!(
            call(&t, &d, &mut m, 108, [id as u64, 0x1200, 0, 0, 0, 0]),
            Err(Errno(22))
        );
    }
    #[test]
    fn expiration_batches_do_not_spin_and_keep_pending_overrun_and_target_identity() {
        let (t, d, task, mut m) = setup();
        let id = create(&t, &d, &mut m);
        let timer = t.lookup(42, id).unwrap();
        let deadline = Instant::now() - Duration::from_millis(1);
        {
            let mut s = timer.state.lock().unwrap();
            s.deadline = Some(deadline);
            s.interval = Duration::from_nanos(1);
        }
        t.reschedule(id, None, Some(deadline));
        t.tick();
        assert!(task.process().bits() & (1 << 13) != 0);
        let first = task.process().take(14).unwrap();
        assert_eq!(first.timer.unwrap().0, id);
        assert!(first.timer.unwrap().1 > 0);
        // One tick handles each due timer once even when its period is shorter
        // than the maintenance work. It remains armed for the next dispatch.
        assert!(t.next_deadline().is_some());
        task.exit();
        let replacement = Arc::new(IoTask::default());
        d.publish(&replacement, 42, 42, 42, 0, 0);
        t.tick();
        assert!(!replacement.ready());
        t.clear_process(42, false);
        assert!(t.next_deadline().is_none());
    }
    #[test]
    fn exec_removes_posix_timers_but_keeps_process_real_interval_timer() {
        let (t, d, _task, mut m) = setup();
        let id = create(&t, &d, &mut m);
        m.write_array(0x1110, 60u64.to_le_bytes()).unwrap();
        call(&t, &d, &mut m, 103, [0, 0x1100, 0, 0, 0, 0]).unwrap();
        t.clear_process(42, true);
        assert_eq!(
            call(&t, &d, &mut m, 109, [id as u64, 0, 0, 0, 0, 0]),
            Err(Errno(22))
        );
        call(&t, &d, &mut m, 102, [0, 0x1200, 0, 0, 0, 0]).unwrap();
        assert!(m.read_u64(0x1210).unwrap() >= 59);
        t.clear_process(42, false);
        assert!(t.next_deadline().is_none());
    }
    #[test]
    fn notification_free_timers_keep_periodic_phase_without_a_deadline_or_signal() {
        let (t, d, task, mut m) = setup();
        m.write_array(0x140c, 1u32.to_le_bytes()).unwrap();
        call(&t, &d, &mut m, 107, [1, 0x1400, 0x1000, 0, 0, 0]).unwrap();
        let id = m.read_u64(0x1000).unwrap() as i32;
        m.write_array(0x1108, 1000u64.to_le_bytes()).unwrap();
        m.write_array(0x1118, 1u64.to_le_bytes()).unwrap();
        call(&t, &d, &mut m, 110, [id as u64, 0, 0x1100, 0, 0, 0]).unwrap();
        assert!(t.next_deadline().is_none());
        t.lookup(42, id).unwrap().state.lock().unwrap().deadline =
            Some(Instant::now() - Duration::from_millis(1));
        call(&t, &d, &mut m, 108, [id as u64, 0x1200, 0, 0, 0, 0]).unwrap();
        assert!(m.read_u64(0x1218).unwrap() > 0 && m.read_u64(0x1218).unwrap() <= 1000);
        assert_eq!(call(&t, &d, &mut m, 109, [id as u64, 0, 0, 0, 0, 0]), Ok(0));
        assert!(!task.ready());
        assert!(t.next_deadline().is_none());
    }
    #[test]
    fn concurrent_rearming_and_expiry_leave_exactly_the_live_deadline_index() {
        let (t, d, _task, mut m) = setup();
        let ids = [create(&t, &d, &mut m), create(&t, &d, &mut m)];
        std::thread::scope(|scope| {
            for id in ids {
                let t = &t;
                scope.spawn(move || {
                    let timer = t.lookup(42, id).unwrap();
                    for i in 0..1000 {
                        let mut s = timer.state.lock().unwrap();
                        let old = s.deadline;
                        s.deadline = Some(Instant::now() + Duration::from_secs(1 + i % 2));
                        t.reschedule(id, old, s.deadline);
                    }
                });
            }
            let t = &t;
            scope.spawn(move || {
                for _ in 0..1000 {
                    t.tick();
                }
            });
        });
        let expected: BTreeSet<_> = ids
            .into_iter()
            .map(|id| {
                (
                    t.lookup(42, id)
                        .unwrap()
                        .state
                        .lock()
                        .unwrap()
                        .deadline
                        .unwrap(),
                    id,
                )
            })
            .collect();
        assert_eq!(*t.schedule.lock().unwrap(), expected);
        assert_eq!(t.next_deadline(), expected.first().map(|(d, _)| *d));
    }
}
