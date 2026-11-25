// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared POSIX/interval timers. Existing executors drive the original deadline
//! index; no timer thread, guest pointer retention or syscall RPC is required.
mod call;
mod cpu;
use crate::signal::{Info, IoDirectory, IoTask, TimerTarget};
pub use call::Call;
use cpu::CpuClock;
pub(crate) use cpu::CpuSchedule;
pub use cpu::CpuSleep;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trames_memory::CpuMemory;
use trames_vfs::{Errno, PidNamespace};

pub fn timer_call(number: u32) -> bool {
    matches!(number, 102 | 103 | 107..=111)
}
pub trait TimerWake: Send + Sync {
    fn timers_changed(&self);
}
struct Timer {
    tgid: u32,
    clock: u32,
    cpu: Option<CpuClock>,
    signal: u32,
    value: u64,
    target: Option<TimerTarget>,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    deleted: bool,
    deadline: Option<Instant>,
    cpu_deadline: Option<Duration>,
    interval: Duration,
    overrun: i32,
}
fn period_remaining(elapsed: Duration, interval: Duration) -> Option<Duration> {
    let period = interval.as_nanos();
    if period == 0 {
        return None;
    }
    let ns = period - elapsed.as_nanos() % period;
    Some(Duration::new(
        (ns / 1_000_000_000) as u64,
        (ns % 1_000_000_000) as u32,
    ))
}

impl Timer {
    fn deliver(&self, id: i32, state: &mut State, elapsed: Duration) {
        let extra = elapsed
            .as_nanos()
            .checked_div(state.interval.as_nanos())
            .unwrap_or(0);
        state.overrun = extra.min(i32::MAX as u128) as i32;
        if self.signal != 0 {
            state.overrun = self.target.as_ref().unwrap().signal(
                self.signal,
                Info {
                    code: if id < 0 { 128 } else { -2 },
                    timer: if id < 0 {
                        None
                    } else {
                        Some((id, state.overrun, self.value))
                    },
                    ..Info::default()
                },
            );
        }
    }
}

struct Registry {
    next_id: i32,
    timers: BTreeMap<i32, Arc<Timer>>,
    reserved: BTreeSet<i32>,
}
pub struct Timers {
    registry: Arc<RwLock<Registry>>,
    schedule: Mutex<BTreeSet<(Instant, i32)>>,
    origin: Instant,
    next: AtomicU64,
    wake: Mutex<Option<Weak<dyn TimerWake>>>,
}
impl Default for Timers {
    fn default() -> Self {
        Self {
            registry: Arc::new(RwLock::new(Registry {
                next_id: 1,
                timers: BTreeMap::new(),
                reserved: Default::default(),
            })),
            schedule: Default::default(),
            origin: Instant::now(),
            next: AtomicU64::new(u64::MAX),
            wake: Default::default(),
        }
    }
}
fn export(
    memory: &mut impl CpuMemory,
    address: u64,
    state: &State,
    micros: bool,
    lazy: bool,
) -> Result<(), Errno> {
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
    write_times(memory, address, state.interval, left, micros)
}

fn write_times(
    memory: &mut impl CpuMemory,
    address: u64,
    interval: Duration,
    left: Duration,
    micros: bool,
) -> Result<(), Errno> {
    let mut bytes = [0; 32];
    for (chunk, d) in bytes.chunks_exact_mut(16).zip([interval, left]) {
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
#[derive(Default)]
struct CpuInterval {
    deadline: Option<Duration>,
    interval: Duration,
}

/// Process-owned ITIMER_VIRTUAL and ITIMER_PROF. Guest CPU accounting currently
/// attributes all charged execution to user time, so both use the group clock.
#[derive(Default)]
pub(crate) struct CpuIntervals {
    armed: AtomicBool,
    entries: Mutex<[CpuInterval; 2]>,
}
impl CpuIntervals {
    pub(crate) fn armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }
    fn publish(&self, entries: &[CpuInterval; 2]) {
        self.armed.store(
            entries.iter().any(|e| e.deadline.is_some()),
            Ordering::Relaxed,
        );
    }
    fn call(
        &self,
        index: usize,
        now: impl FnOnce() -> Duration,
        new: Option<(Duration, Duration)>,
        output: Option<u64>,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let mut entries = self.entries.lock().unwrap();
        let entry = &mut entries[index];
        let now = now();
        if let Some(address) = output {
            let left = entry.deadline.map_or(Duration::ZERO, |d| {
                d.saturating_sub(now).max(Duration::from_micros(1))
            });
            write_times(memory, address, entry.interval, left, true)?;
        }
        if let Some((interval, value)) = new {
            entry.interval = interval;
            entry.deadline = (!value.is_zero()).then(|| now.saturating_add(value));
            self.publish(&entries);
        }
        Ok(0)
    }
    pub(crate) fn expire(&self, now: Duration) -> [bool; 2] {
        let mut entries = self.entries.lock().unwrap();
        let mut expired = [false; 2];
        for (entry, due) in entries.iter_mut().zip(&mut expired) {
            let Some(deadline) = entry.deadline else {
                continue;
            };
            if now < deadline {
                continue;
            }
            *due = true;
            entry.deadline = if entry.interval.is_zero() {
                None
            } else {
                let period = entry.interval.as_nanos();
                let left = period - (now - deadline).as_nanos() % period;
                now.checked_add(Duration::new(
                    (left / 1_000_000_000) as u64,
                    (left % 1_000_000_000) as u32,
                ))
            };
        }
        if expired.contains(&true) {
            self.publish(&entries);
        }
        expired
    }
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
    fn retire(&self, id: i32, timer: &Timer, state: &mut State) {
        if let Some(cpu) = &timer.cpu {
            cpu.remove(id, state.cpu_deadline.take());
        }
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
            self.retire(id, &timer, &mut timer.state.lock().unwrap());
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
            let elapsed = now.saturating_duration_since(deadline);
            state.deadline =
                period_remaining(elapsed, state.interval).and_then(|left| now.checked_add(left));
            self.reschedule(id, Some(deadline), state.deadline);
            timer.deliver(id, &mut state, elapsed);
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self,
        number: u32,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
        started: Instant,
        caller: &IoTask,
        directory: &IoDirectory,
        namespace: &PidNamespace,
    ) -> Result<u64, Errno> {
        let input = call::Input::import(number, a, memory)?;
        let mut prepared = self.prepare(number, a, input, started, caller, directory, namespace)?;
        prepared.output.progress(memory).map_err(|_| Errno(14))?;
        if let Some(create) = prepared.create.take() {
            create.publish(caller, directory)?;
        }
        Ok(prepared.value)
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        &self,
        number: u32,
        a: [u64; 6],
        input: call::Input,
        started: Instant,
        caller: &IoTask,
        directory: &IoDirectory,
        namespace: &PidNamespace,
    ) -> Result<call::Prepared, Errno> {
        let tgid = caller.tgid();
        let mut output = crate::user_copy::Output::default();
        match input {
            call::Input::Interval(times) => {
                let which = a[0] as u32;
                if which > 2 {
                    return Err(Errno(22));
                }
                let address = if number == 102 {
                    Some(a[1])
                } else {
                    (a[2] != 0).then_some(a[2])
                };
                if which != 0 {
                    let group = caller.lifecycle();
                    group.cpu_intervals.call(
                        (which - 1) as usize,
                        || group.cpu_time(),
                        times,
                        address,
                        &mut output,
                    )?;
                } else {
                    let id = -(tgid as i32);
                    let new = times
                        .map(|(interval, value)| -> Result<_, Errno> {
                            let value = call::ktime(value);
                            let interval = call::ktime(interval);
                            Ok((
                                if value.is_zero() {
                                    Duration::ZERO
                                } else {
                                    interval
                                },
                                if value.is_zero() {
                                    None
                                } else {
                                    Some(Instant::now().checked_add(value).ok_or(Errno(22))?)
                                },
                            ))
                        })
                        .transpose()?;
                    let timer = if number == 103 {
                        let target = Some(directory.timer_target(tgid, None)?);
                        let mut registry = self.registry.write().unwrap();
                        Some(
                            registry
                                .timers
                                .entry(id)
                                .or_insert_with(|| {
                                    Arc::new(Timer {
                                        tgid,
                                        clock: 1,
                                        cpu: None,
                                        signal: 14,
                                        value: 0,
                                        target,
                                        state: Default::default(),
                                    })
                                })
                                .clone(),
                        )
                    } else {
                        self.lookup(tgid, id).ok()
                    };
                    if let Some(timer) = timer {
                        let mut state = timer.state.lock().unwrap();
                        if state.deleted {
                            return Err(Errno(22));
                        }
                        if let Some(address) = address {
                            export(&mut output, address, &state, true, false)?;
                        }
                        if let Some((interval, deadline)) = new {
                            let old = state.deadline;
                            state.interval = interval;
                            state.deadline = deadline;
                            state.overrun = 0;
                            self.reschedule(id, old, deadline);
                        }
                    } else if let Some(address) = address {
                        export(&mut output, address, &State::default(), true, false)?;
                    }
                }
            }
            call::Input::Create(event) => {
                let clock = a[0] as u32;
                if clock > 3 {
                    return Err(Errno(22));
                }
                let mut create = call::Create::reserve(self.registry.clone(), clock, tgid)?;
                let (signal, value, thread) = if let Some(event) = event {
                    let value = u64::from_le_bytes(event[..8].try_into().unwrap());
                    let signal = u32::from_le_bytes(event[8..12].try_into().unwrap());
                    let notify = u32::from_le_bytes(event[12..16].try_into().unwrap());
                    if notify != 1 && (signal == 0 || signal > 64) {
                        return Err(Errno(22));
                    }
                    let thread = match notify {
                        0..=2 => None,
                        4 => Some(
                            namespace
                                .global(u32::from_le_bytes(event[16..20].try_into().unwrap()))
                                .ok_or(Errno(22))?,
                        ),
                        _ => return Err(Errno(22)),
                    };
                    (if notify == 1 { 0 } else { signal }, value, thread)
                } else {
                    (14, create.id as u64, None)
                };
                create.signal = signal;
                create.value = value;
                create.target = if signal == 0 {
                    None
                } else {
                    Some(directory.timer_target(tgid, thread)?)
                };
                output
                    .write_array(a[2], create.id.to_le_bytes())
                    .map_err(|_| Errno(14))?;
                return Ok(call::Prepared {
                    output,
                    create: Some(create),
                    value: 0,
                });
            }
            call::Input::Posix(new) => {
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
                    109 => {
                        return Ok(call::Prepared {
                            output,
                            create: None,
                            value: state.overrun as u64,
                        })
                    }
                    111 => {
                        self.retire(id, &timer, &mut state);
                        drop(state);
                        self.registry.write().unwrap().timers.remove(&id);
                    }
                    108 | 110 => {
                        let address = if number == 108 {
                            Some(a[1])
                        } else {
                            (a[3] != 0).then_some(a[3])
                        };
                        let new = new
                            .map(|(interval, value)| (call::ktime(interval), call::ktime(value)));
                        if let Some(cpu) = &timer.cpu {
                            cpu.update(
                                id,
                                &timer,
                                &mut state,
                                new.map(|(i, v)| (i, v, a[1] as u32 & 1 != 0)),
                                address,
                                &mut output,
                            )?;
                        } else {
                            let new = new
                                .map(|(interval, value)| -> Result<_, Errno> {
                                    let deadline = if value.is_zero() {
                                        None
                                    } else {
                                        let delta = if a[1] as u32 & 1 == 0 {
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
                                        Some(Instant::now().checked_add(delta).ok_or(Errno(22))?)
                                    };
                                    Ok((interval, deadline))
                                })
                                .transpose()?;
                            if let Some(address) = address {
                                export(&mut output, address, &state, false, timer.signal == 0)?;
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
                        }
                    }
                    _ => return Err(Errno(38)),
                }
            }
        }
        Ok(call::Prepared {
            output,
            create: None,
            value: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::IoTask;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    pub(super) fn setup() -> (Timers, Arc<IoDirectory>, Arc<IoTask>, Memory) {
        let directory = Arc::new(IoDirectory::default());
        let task = Arc::new(IoTask::default());
        directory.publish(&task, 42, 42, 42, 0, 0);
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        (Timers::default(), directory, task, m)
    }
    pub(super) fn call(
        t: &Timers,
        d: &IoDirectory,
        m: &mut Memory,
        n: u32,
        a: [u64; 6],
    ) -> Result<u64, Errno> {
        t.call(
            n,
            a,
            m,
            Instant::now(),
            &d.proc_task(42).unwrap(),
            d,
            &PidNamespace::default(),
        )
    }
    fn create(t: &Timers, d: &IoDirectory, m: &mut Memory) -> i32 {
        call(t, d, m, 107, [1, 0, 0x1000, 0, 0, 0]).unwrap();
        m.read_u64(0x1000).unwrap() as i32
    }
    #[test]
    fn cpu_intervals_share_execution_across_threads_and_keep_independent_phase() {
        let (timers, directory, leader, mut memory) = setup();
        let peer = Arc::new(IoTask::default());
        peer.share_process(&leader);
        directory.publish(&peer, 43, 42, 42, 0, 0);
        let group = leader.lifecycle();
        group.register(&leader, 42);
        group.register(&peer, 43);
        // One-shot virtual alarm after 10us, profiling every 4us starting at 7us.
        for (which, period, value) in [(1, 0u64, 10u64), (2, 4, 7)] {
            memory.write_array(0x1108, period.to_le_bytes()).unwrap();
            memory.write_array(0x1118, value.to_le_bytes()).unwrap();
            call(
                &timers,
                &directory,
                &mut memory,
                103,
                [which, 0x1100, 0x1100, 0, 0, 0],
            )
            .unwrap();
            assert_eq!(memory.read_array::<32>(0x1100).unwrap(), [0; 32]);
        }
        assert!(timers.next_deadline().is_none());
        assert!(!IoTask::default().lifecycle().cpu_intervals.armed());
        timers.clear_process(42, true);
        leader.proc_view.account(Duration::from_micros(4), 0);
        peer.proc_view.account(Duration::from_micros(2), 1);
        peer.check_cpu_timers();
        assert_eq!(leader.process().bits(), 0);
        peer.proc_view.account(Duration::from_micros(11), 1);
        peer.check_cpu_timers();
        for sig in [26, 27] {
            assert_eq!(leader.process().take(sig).unwrap().code, 128);
        }
        leader.check_cpu_timers();
        assert_eq!(leader.process().bits(), 0);
        call(
            &timers,
            &directory,
            &mut memory,
            102,
            [1, 0x1200, 0, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(memory.read_array::<32>(0x1200).unwrap(), [0; 32]);
        call(
            &timers,
            &directory,
            &mut memory,
            103,
            [2, 0, 0x1200, 0, 0, 0],
        )
        .unwrap();
        assert_eq!(memory.read_u64(0x1208).unwrap(), 4);
        assert_eq!(memory.read_u64(0x1218).unwrap(), 2);
        assert!(!group.cpu_intervals.armed());
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
        m.write_array(0x1110, 120u64.to_le_bytes()).unwrap();
        assert_eq!(
            call(&t, &d, &mut m, 110, [id as u64, 0, 0x1100, 0x1ff8, 0, 0]),
            Err(Errno(14))
        );
        call(&t, &d, &mut m, 108, [id as u64, 0x1200, 0, 0, 0, 0]).unwrap();
        assert!(m.read_u64(0x1210).unwrap() >= 119);
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
