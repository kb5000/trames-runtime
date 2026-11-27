// SPDX-License-Identifier: GPL-3.0-or-later
//! Original session memory stalls, observed through existing resource deadlines.
//! No timer, polling bus or pressure-service thread belongs to this resource.
use crate::*;
use std::collections::VecDeque;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize},
    Mutex, Weak,
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Default)]
pub struct PressureMemory {
    pub total: usize,
    pub free: usize,
    pub available: usize,
}
pub type PressureSource = Arc<dyn Fn() -> PressureMemory + Send + Sync>;
pub struct MemoryPressure {
    tracking: AtomicBool,
    monitors: AtomicUsize,
    bounded: bool,
    active_stalls: Arc<AtomicBool>,
    changed: Arc<trames_shared::Readiness>,
    state: Mutex<State>,
    source: PressureSource,
    reports: Mutex<Vec<Weak<report::Report>>>,
    scans: AtomicU64,
    evicted: AtomicU64,
    refaults: AtomicU64,
}
#[derive(Default, Clone, Copy)]
struct CpuState {
    running: usize,
    stalled: usize,
    productive: usize,
}
struct TaskState {
    schedule: Arc<Schedule>,
    running: bool,
    depth: usize,
    admission: bool,
    cpu: usize,
}
struct State {
    active_stalls: Arc<AtomicBool>,
    last: Instant,
    tasks: BTreeMap<u64, TaskState>,
    cpus: [CpuState; 32],
    stalled: usize,
    total: [u64; 2], // nanoseconds, rendered as microseconds only at the ABI
    average: [[f64; 3]; 2],
    average_at: Instant,
    average_rate: [f64; 2],
    history: VecDeque<(Instant, Instant, [f64; 2])>,
    guards: BTreeMap<u64, (u64, Option<Instant>)>,
    deadlines: BTreeMap<(Instant, u64), u64>,
}
pub struct PressureTask {
    domain: Arc<MemoryPressure>,
    id: u64,
    schedule: Arc<Schedule>,
    admission: Mutex<Option<(Instant, u64, bool)>>,
    admitting: AtomicBool,
    waiters: AtomicUsize,
    protected: Mutex<Option<Arc<dyn Fn() -> bool + Send + Sync>>>,
}
struct Schedule {
    runnable: AtomicBool,
    cpu: AtomicUsize,
}
pub struct PressureStall {
    task: Arc<PressureTask>,
    id: u64,
}
pub struct PressureMonitor {
    domain: Arc<MemoryPressure>,
    state: Mutex<Monitor>,
}
struct Monitor {
    kind: usize,
    threshold: Duration,
    window: Duration,
    since: Instant,
    last_event: Option<Instant>,
    epoch: u64,
    pending: bool,
    next_poll: Option<Instant>,
}
impl State {
    fn active(&self) -> [f64; 2] {
        if self.stalled == 0 {
            return [0.0; 2];
        }
        let nonidle = self
            .cpus
            .iter()
            .filter(|c| c.running != 0 || c.stalled != 0)
            .count();
        if nonidle == 0 {
            return [0.0; 2];
        }
        let some = self.cpus.iter().filter(|c| c.stalled != 0).count();
        let full = self
            .cpus
            .iter()
            .filter(|c| c.stalled != 0 && c.productive == 0)
            .count();
        [some as f64 / nonidle as f64, full as f64 / nonidle as f64]
    }
    fn advance(&mut self, now: Instant) {
        while self
            .deadlines
            .first_key_value()
            .is_some_and(|((at, _), _)| *at <= now)
        {
            let ((at, id), task) = self.deadlines.pop_first().unwrap();
            self.advance_time(at);
            if self.guards.remove(&id).is_some() {
                self.transition(task, None, -1, None, None);
            }
        }
        self.advance_time(now);
        self.refresh_schedules();
    }
    fn refresh_schedules(&mut self) {
        // The hint only avoids idle bookkeeping; it is not a publication
        // barrier. Every stall/observation reconciles the live atomic metadata,
        // including a dispatch racing the first stall. Metadata owns no task
        // or retirement callback, so refreshing cannot retire under this lock.
        self.cpus = [CpuState::default(); 32];
        for task in self.tasks.values_mut() {
            task.running = task.schedule.runnable.load(Ordering::Relaxed);
            task.cpu = task.schedule.cpu.load(Ordering::Relaxed).min(31);
            let stalled = task.depth != 0 || task.admission;
            let cpu = &mut self.cpus[task.cpu];
            cpu.running += usize::from(task.running);
            cpu.stalled += usize::from(stalled);
            cpu.productive += usize::from(task.running && !stalled);
        }
    }
    fn advance_time(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last);
        if elapsed.is_zero() {
            return;
        }
        let active = self.active();
        // Consecutive scheduling transitions with the same PSI ratio compose
        // into one exact exponential interval. Flush only at ratio changes or
        // observation, rather than doing six exp calls per ordinary dispatch.
        if active != self.average_rate {
            self.advance_average(self.last);
            self.average_rate = active;
        }
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        for (kind, &ratio) in active.iter().enumerate() {
            self.total[kind] = self.total[kind].saturating_add((nanos as f64 * ratio) as u64);
        }
        if active[0] > 0.0 {
            if let Some((_, end, _)) = self
                .history
                .back_mut()
                .filter(|(_, end, old)| *end == self.last && *old == active)
            {
                *end = now;
            } else {
                self.history.push_back((self.last, now, active));
            }
        }
        self.last = now;
        while self.history.front().is_some_and(|(_, end, _)| {
            now.saturating_duration_since(*end) > Duration::from_secs(10)
        }) {
            self.history.pop_front();
        }
    }
    fn advance_average(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.average_at);
        for (kind, &ratio) in self.average_rate.iter().enumerate() {
            for (average, seconds) in self.average[kind].iter_mut().zip([10.0, 60.0, 300.0]) {
                if *average != 0.0 || ratio != 0.0 {
                    let decay = (-elapsed.as_secs_f64() / seconds).exp();
                    *average = *average * decay + 100.0 * ratio * (1.0 - decay);
                }
            }
        }
        self.average_at = now;
    }
    fn transition(
        &mut self,
        id: u64,
        runnable: Option<bool>,
        stall: i32,
        cpu: Option<usize>,
        admission: Option<bool>,
    ) {
        let Some(task) = self.tasks.get_mut(&id) else {
            return;
        };
        let stalled = task.depth != 0 || task.admission;
        self.stalled -= usize::from(stalled);
        let old = &mut self.cpus[task.cpu];
        old.running -= usize::from(task.running);
        old.stalled -= usize::from(stalled);
        old.productive -= usize::from(task.running && !stalled);
        if let Some(value) = runnable {
            task.running = value;
        }
        if let Some(cpu) = cpu {
            task.cpu = cpu.min(31);
        }
        task.depth = task.depth.saturating_add_signed(stall as isize);
        if let Some(admission) = admission {
            task.admission = admission;
        }
        let stalled = task.depth != 0 || task.admission;
        self.stalled += usize::from(stalled);
        let new = &mut self.cpus[task.cpu];
        new.running += usize::from(task.running);
        new.stalled += usize::from(stalled);
        new.productive += usize::from(task.running && !stalled);
        self.active_stalls
            .store(self.stalled != 0, Ordering::Relaxed);
    }
    fn in_window(&self, kind: usize, now: Instant, window: Duration) -> Duration {
        let start = now.checked_sub(window).unwrap_or(now);
        self.history.iter().filter(|(_, _, a)| a[kind] > 0.0).fold(
            Duration::ZERO,
            |sum, (a, b, active)| {
                sum + b
                    .min(&now)
                    .saturating_duration_since((*a).max(start))
                    .mul_f64(active[kind])
            },
        )
    }
}
impl MemoryPressure {
    pub fn new(source: PressureSource) -> Arc<Self> {
        Self::with_source(source, true)
    }
    /// Host availability remains a hint. Actual pager waits provide PSI, and
    /// the host's own allocator continues to decide physical admission.
    pub fn host(source: PressureSource) -> Arc<Self> {
        Self::with_source(source, false)
    }
    fn with_source(source: PressureSource, bounded: bool) -> Arc<Self> {
        let now = Instant::now();
        let active_stalls = Arc::new(AtomicBool::new(false));
        Arc::new(Self {
            tracking: AtomicBool::new(false),
            monitors: AtomicUsize::new(0),
            bounded,
            active_stalls: active_stalls.clone(),
            changed: Arc::default(),
            source,
            reports: Default::default(),
            scans: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            refaults: AtomicU64::new(0),
            state: Mutex::new(State {
                active_stalls,
                last: now,
                tasks: BTreeMap::new(),
                cpus: [CpuState::default(); 32],
                stalled: 0,
                total: [0; 2],
                average: [[0.0; 3]; 2],
                average_at: now,
                average_rate: [0.0; 2],
                history: VecDeque::new(),
                guards: BTreeMap::new(),
                deadlines: BTreeMap::new(),
            }),
        })
    }
    pub fn tracking(&self) -> bool {
        self.tracking.load(Ordering::Relaxed)
    }
    pub fn monitored(&self) -> bool {
        self.monitors.load(Ordering::Relaxed) != 0
    }
    pub(super) fn allocation_waits_possible(&self) -> bool {
        self.bounded && self.monitored()
    }
    pub fn memory(&self) -> PressureMemory {
        (self.source)()
    }
    pub fn watermarks(&self) -> [usize; 3] {
        Self::watermarks_for(self.memory().total)
    }
    fn watermarks_for(total: usize) -> [usize; 3] {
        let high = (total / 16).clamp(PAGE_SIZE as usize * 16, 64 * 1024 * 1024);
        [high / 4, high / 2, high]
    }
    pub fn task(self: &Arc<Self>) -> Arc<PressureTask> {
        let task = Arc::new(PressureTask {
            domain: self.clone(),
            id: new_backing_identity(),
            schedule: Arc::new(Schedule {
                runnable: AtomicBool::new(true),
                cpu: AtomicUsize::new(0),
            }),
            admission: Default::default(),
            admitting: AtomicBool::new(false),
            waiters: AtomicUsize::new(0),
            protected: Default::default(),
        });
        let mut state = self.state.lock().unwrap();
        state.advance(Instant::now());
        state.tasks.insert(
            task.id,
            TaskState {
                schedule: task.schedule.clone(),
                running: true,
                depth: 0,
                admission: false,
                cpu: 0,
            },
        );
        state.cpus[0].running += 1;
        state.cpus[0].productive += 1;
        task
    }
    fn track(&self) {
        let mut state = self.state.lock().unwrap();
        if self.tracking.swap(true, Ordering::Relaxed) {
            return;
        }
        state.last = Instant::now();
        state.refresh_schedules();
    }
    pub fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> trames_shared::IoSubscription {
        self.changed.subscribe(signal)
    }
    pub fn format(&self) -> Vec<u8> {
        self.track();
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        state.advance(now);
        state.advance_average(now);
        let mut text = String::new();
        for (kind, name) in ["some", "full"].iter().enumerate() {
            let a = state.average[kind];
            text.push_str(&format!(
                "{name} avg10={:.2} avg60={:.2} avg300={:.2} total={}\n",
                a[0],
                a[1],
                a[2],
                state.total[kind] / 1000
            ));
        }
        text.into_bytes()
    }
    pub fn scanned_pages(&self) -> u64 {
        self.scans.load(Ordering::Relaxed)
    }
    pub fn reclaimed(&self) -> u64 {
        self.evicted.load(Ordering::Relaxed)
    }
    pub fn anonymous_refaults(&self) -> u64 {
        self.refaults.load(Ordering::Relaxed)
    }
    pub fn source_changed(&self) {
        self.changed.notify_atomic();
    }
    pub fn reclaimed_pages(&self, pages: u64) {
        self.scans.fetch_add(pages, Ordering::Relaxed);
        self.evicted.fetch_add(pages, Ordering::Relaxed);
        self.changed.notify_atomic();
    }
    pub(super) fn register_report(&self, report: &MemoryReport) {
        let mut reports = self.reports.lock().unwrap();
        reports.retain(|r| r.strong_count() != 0);
        let weak = Arc::downgrade(&report.0);
        if !reports.iter().any(|r| r.ptr_eq(&weak)) {
            reports.push(weak);
        }
    }
    fn scans(&self) -> Vec<Arc<MmControl>> {
        let reports: Vec<_> = self
            .reports
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .map(MemoryReport)
            .collect();
        reports
            .into_iter()
            .filter_map(|report| {
                report
                    .submit_control(|memory| {
                        Ok(memory.scan_pressure_pages().to_le_bytes().to_vec())
                    })
                    .ok()
            })
            .collect()
    }
    pub fn monitor(
        self: &Arc<Self>,
        bytes: &[u8],
        privileged: bool,
    ) -> Result<Arc<PressureMonitor>, u32> {
        let text = std::str::from_utf8(bytes.split(|b| *b == 0).next().unwrap_or_default())
            .map_err(|_| 22u32)?;
        let mut parts = text.split_whitespace();
        let kind = match parts.next() {
            Some("some") => 0,
            Some("full") => 1,
            _ => return Err(22),
        };
        let threshold: u64 = parts.next().ok_or(22u32)?.parse().map_err(|_| 22u32)?;
        let window: u64 = parts.next().ok_or(22u32)?.parse().map_err(|_| 22u32)?;
        if threshold == 0
            || threshold > window
            || window > 10_000_000
            || (!privileged && !window.is_multiple_of(2_000_000))
        {
            return Err(22);
        }
        self.track();
        self.monitors.fetch_add(1, Ordering::Relaxed);
        self.changed.notify_atomic();
        Ok(Arc::new(PressureMonitor {
            domain: self.clone(),
            state: Mutex::new(Monitor {
                kind,
                threshold: Duration::from_micros(threshold),
                window: Duration::from_micros(window),
                since: Instant::now(),
                last_event: None,
                epoch: 0,
                pending: false,
                next_poll: None,
            }),
        }))
    }
    pub(super) fn allocation(self: &Arc<Self>, bytes: usize) -> Result<(), MemoryError> {
        if !self.bounded || !self.monitored() {
            if self.bounded {
                CgroupMemoryTarget::pressure_admitted();
            }
            return Ok(());
        }
        let memory = self.memory();
        if memory.available.saturating_sub(bytes) >= Self::watermarks_for(memory.total)[2] {
            CgroupMemoryTarget::pressure_admitted();
            return Ok(());
        }
        let Some(task) = CgroupMemoryTarget::pressure_task() else {
            return Ok(());
        };
        if task
            .protected
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|check| check())
        {
            task.admitted();
            return Ok(());
        }
        let now = Instant::now();
        let (deadline, generation) = task.begin_admission(now)?;
        let scans = self.scans();
        Err(PageWait::resource(Arc::new(AllocationWait {
            domain: self.clone(),
            bytes,
            deadline,
            scans,
            actor: task,
            generation,
            retrying: AtomicBool::new(false),
        }))
        .fault(0))
    }
    pub(super) fn released(&self) {
        // Only bounded allocation waits depend on released quota. HostManaged
        // availability is a hint; native pager completions have their own wake.
        if self.bounded && self.monitored() {
            self.changed.notify_atomic();
        }
    }
}
impl PressureTask {
    pub fn set_protected(&self, check: Arc<dyn Fn() -> bool + Send + Sync>) {
        *self.protected.lock().unwrap() = Some(check);
    }
    pub(crate) fn admitted(&self) {
        self.clear_admission(None, false);
    }
    pub(crate) fn execution_finished(&self) {
        self.clear_admission(None, true);
    }
    fn clear_admission(&self, generation: Option<u64>, only_idle: bool) {
        if !self.admitting.load(Ordering::Relaxed) {
            return;
        }
        let mut admission = self.admission.lock().unwrap();
        if generation.is_some_and(|id| {
            admission
                .as_ref()
                .is_none_or(|(_, current, _)| *current != id)
        }) || only_idle && self.waiters.load(Ordering::Relaxed) != 0
        {
            return;
        }
        self.finish_admission(&mut admission);
    }
    fn retry_admission(&self, generation: u64) {
        if let Some((_, current, retried)) = self.admission.lock().unwrap().as_mut() {
            if *current == generation {
                *retried = true;
            }
        }
    }
    fn cancel_admission(&self, generation: u64) {
        let mut admission = self.admission.lock().unwrap();
        if self.waiters.load(Ordering::Relaxed) == 0
            && admission
                .as_ref()
                .is_some_and(|(_, current, retried)| *current == generation && !retried)
        {
            self.finish_admission(&mut admission);
        }
    }
    fn finish_admission(&self, admission: &mut Option<(Instant, u64, bool)>) {
        *admission = None;
        self.admitting.store(false, Ordering::Relaxed);
        let mut state = self.domain.state.lock().unwrap();
        state.advance(Instant::now());
        state.transition(self.id, None, 0, None, Some(false));
    }
    fn begin_admission(&self, now: Instant) -> Result<(Instant, u64), MemoryError> {
        let mut admission = self.admission.lock().unwrap();
        let fresh = admission.is_none();
        let (since, generation, _) =
            *admission.get_or_insert_with(|| (now, new_backing_identity(), false));
        let deadline = since + Duration::from_secs(2);
        if now >= deadline {
            self.finish_admission(&mut admission);
            return Err(MemoryError::Limit);
        }
        self.waiters.fetch_add(1, Ordering::Relaxed);
        if fresh {
            self.admitting.store(true, Ordering::Relaxed);
            let mut state = self.domain.state.lock().unwrap();
            state.advance(now);
            state.transition(self.id, None, 0, None, Some(true));
        }
        drop(admission);
        if fresh {
            self.domain.changed.notify_atomic();
        }
        Ok((deadline, generation))
    }
    pub fn runnable(&self, value: bool) {
        if self.schedule.runnable.swap(value, Ordering::Relaxed) == value {
            return;
        }
        if self.domain.active_stalls.load(Ordering::Relaxed) {
            let mut state = self.domain.state.lock().unwrap();
            state.advance(Instant::now());
        }
    }
    pub fn dispatched(&self, cpu: usize) {
        let cpu = cpu.min(31);
        if self.schedule.cpu.swap(cpu, Ordering::Relaxed) == cpu {
            return;
        }
        if self.domain.active_stalls.load(Ordering::Relaxed) {
            let mut state = self.domain.state.lock().unwrap();
            state.advance(Instant::now());
        }
    }
    pub fn stall(self: &Arc<Self>) -> PressureStall {
        self.stall_until(None)
    }
    pub fn stall_until(self: &Arc<Self>, deadline: Option<Instant>) -> PressureStall {
        self.domain.track();
        let mut state = self.domain.state.lock().unwrap();
        state.advance(Instant::now());
        let id = new_backing_identity();
        state.transition(self.id, None, 1, None, None);
        state.guards.insert(id, (self.id, deadline));
        if let Some(at) = deadline {
            state.deadlines.insert((at, id), self.id);
        }
        drop(state);
        self.domain.changed.notify_atomic();
        PressureStall {
            task: self.clone(),
            id,
        }
    }
    pub fn memory_wait(
        self: &Arc<Self>,
        resource: Arc<dyn trames_shared::ResourceWait>,
    ) -> Arc<dyn trames_shared::ResourceWait> {
        if resource.ready() {
            return resource;
        }
        self.domain.refaults.fetch_add(1, Ordering::Relaxed);
        self.reclaim_wait(resource)
    }
    pub fn reclaim_wait(
        self: &Arc<Self>,
        resource: Arc<dyn trames_shared::ResourceWait>,
    ) -> Arc<dyn trames_shared::ResourceWait> {
        if resource.ready() {
            return resource;
        }
        Arc::new(MemoryWait {
            resource,
            stalled: self.stall(),
        })
    }
    pub fn hardware_wait(self: &Arc<Self>, resource: Arc<HardwareWait>) -> Arc<HardwareWait> {
        if resource.ready() {
            return resource;
        }
        self.domain.refaults.fetch_add(1, Ordering::Relaxed);
        resource.retaining(self.stall())
    }
    pub fn retire(&self) {
        self.admitted();
        let mut state = self.domain.state.lock().unwrap();
        state.advance(Instant::now());
        state.transition(self.id, Some(false), i32::MIN, None, Some(false));
        state.tasks.remove(&self.id);
        drop(state);
    }
}
impl Drop for PressureTask {
    fn drop(&mut self) {
        self.retire();
    }
}
impl PressureStall {
    pub fn finish(&self) {
        let mut state = self.task.domain.state.lock().unwrap();
        state.advance(Instant::now());
        if let Some((task, deadline)) = state.guards.remove(&self.id) {
            if let Some(at) = deadline {
                state.deadlines.remove(&(at, self.id));
            }
            state.transition(task, None, -1, None, None);
        }
    }
}
impl Drop for PressureStall {
    fn drop(&mut self) {
        self.finish();
    }
}
impl PressureMonitor {
    pub fn epoch(&self) -> [u64; 2] {
        [self.state.lock().unwrap().epoch, 0]
    }
    pub fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        self.observe(events, true)
    }
    pub fn peek(&self, events: u16) -> (u16, [u64; 2]) {
        self.observe(events, false)
    }
    pub fn acknowledge(&self, epoch: [u64; 2]) {
        let mut monitor = self.state.lock().unwrap();
        if monitor.epoch == epoch[0] {
            monitor.pending = false;
        }
    }
    fn observe(&self, events: u16, consume: bool) -> (u16, [u64; 2]) {
        let now = Instant::now();
        let mut state = self.domain.state.lock().unwrap();
        state.advance(now);
        let mut monitor = self.state.lock().unwrap();
        if monitor.next_poll.is_some_and(|at| at <= now) {
            monitor.next_poll = None;
        }
        let window = monitor
            .window
            .min(now.saturating_duration_since(monitor.since));
        let fire = monitor
            .last_event
            .is_none_or(|last| now.saturating_duration_since(last) >= monitor.window)
            && state.in_window(monitor.kind, now, window) >= monitor.threshold;
        let mut ready = events & 0x145;
        if fire {
            monitor.next_poll = None;
            monitor.last_event = Some(now);
            monitor.epoch = monitor.epoch.wrapping_add(1);
            monitor.pending = true;
        }
        if monitor.pending {
            ready |= events & 2;
            if consume {
                monitor.pending = false;
            }
        }
        (ready, [monitor.epoch, 0])
    }
    pub fn deadline(&self) -> Option<Instant> {
        let now = Instant::now();
        let mut state = self.domain.state.lock().unwrap();
        state.advance(now);
        let mut monitor = self.state.lock().unwrap();
        let window = monitor
            .window
            .min(now.saturating_duration_since(monitor.since));
        let accumulated = state.in_window(monitor.kind, now, window);
        if state.stalled == 0 && accumulated < monitor.threshold {
            monitor.next_poll = None;
            return None;
        }
        // Scheduling transitions and ready() may run under the original run
        // queue lock; they update clocks without invoking scheduler callbacks.
        // Use the earliest possible crossing at PSI's window/10 resolution so
        // CPU state changes cannot strand a monitor with a stale zero ratio.
        let missing = monitor
            .threshold
            .saturating_sub(accumulated)
            .max((monitor.window / 10).max(Duration::from_millis(1)));
        let at = monitor.last_event.map_or(now + missing, |last| {
            (last + monitor.window).max(now + missing)
        });
        // Re-evaluating other readiness sources must never slide this timer
        // into the future and starve an already accepted PSI observation.
        let at = monitor.next_poll.map_or(at, |old| old.min(at));
        monitor.next_poll = Some(at);
        Some(at)
    }
}
impl Drop for PressureMonitor {
    fn drop(&mut self) {
        self.domain.monitors.fetch_sub(1, Ordering::Relaxed);
        self.domain.changed.notify_atomic();
    }
}
struct AllocationWait {
    domain: Arc<MemoryPressure>,
    bytes: usize,
    deadline: Instant,
    scans: Vec<Arc<MmControl>>,
    actor: Arc<PressureTask>,
    generation: u64,
    retrying: AtomicBool,
}
impl trames_shared::ResourceWait for AllocationWait {
    fn ready(&self) -> bool {
        let m = self.domain.memory();
        let admitted = m.total == 0
            || !self.domain.monitored()
            || m.available.saturating_sub(self.bytes) >= MemoryPressure::watermarks_for(m.total)[2];
        if admitted {
            self.actor.clear_admission(Some(self.generation), false);
        }
        let retry = Instant::now() >= self.deadline || !self.scans.is_empty()
            // Retry only after a real original-mm scan completed. This is
            // bounded direct reclaim work, not a timer or readiness spin.
                && self.scans.iter().all(|scan| scan.result().is_some())
                && self.scans.iter().any(|scan| {
                    matches!(scan.result(), Some(Ok(bytes)) if bytes.as_slice().try_into().map(u64::from_le_bytes).unwrap_or(0) != 0)
                });
        if retry {
            self.actor.retry_admission(self.generation);
            self.retrying.store(true, Ordering::Relaxed);
        }
        admitted || retry
    }
    fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        let mut subscriptions = vec![self.domain.subscribe(signal)];
        for scan in &self.scans {
            subscriptions.extend(scan.subscribe(signal));
        }
        subscriptions
    }
    fn deadline(&self) -> Option<Instant> {
        Some(self.deadline)
    }
}
impl Drop for AllocationWait {
    fn drop(&mut self) {
        if self.actor.waiters.fetch_sub(1, Ordering::Relaxed) == 1
            && !self.retrying.load(Ordering::Relaxed)
        {
            self.actor.cancel_admission(self.generation);
        }
    }
}
struct MemoryWait {
    resource: Arc<dyn trames_shared::ResourceWait>,
    stalled: PressureStall,
}
impl trames_shared::ResourceWait for MemoryWait {
    fn ready(&self) -> bool {
        let ready = self.resource.ready();
        if ready {
            self.stalled.finish();
        }
        ready
    }
    fn subscribe(
        &self,
        signal: &Arc<trames_shared::IoSignal>,
    ) -> Vec<trames_shared::IoSubscription> {
        self.resource.subscribe(signal)
    }
    fn deadline(&self) -> Option<Instant> {
        self.resource.deadline()
    }
}
impl Memory {
    pub fn memory_pressure(&self, host: Option<PressureSource>) -> Arc<MemoryPressure> {
        if let Some(shared) = &self.shared {
            return shared.borrow().memory_pressure(host);
        }
        let total = self
            .account
            .total
            .as_ref()
            .expect("session aggregate memory budget");
        let pressure = total
            .pressure
            .get_or_init(|| {
                if let Some(host) = host {
                    return MemoryPressure::host(host);
                }
                let weak = Arc::downgrade(total);
                MemoryPressure::new(Arc::new(move || {
                    let Some(total) = weak.upgrade() else {
                        return PressureMemory::default();
                    };
                    let limit = total.limit.load(Ordering::Relaxed);
                    let free = limit.saturating_sub(total.used.load(Ordering::Relaxed));
                    PressureMemory {
                        total: limit,
                        free,
                        available: free,
                    }
                }))
            })
            .clone();
        pressure.register_report(&self.memory_report());
        pressure
    }
    pub(super) fn scan_pressure_pages(&self) -> u64 {
        let Some(pressure) = self
            .account
            .total
            .as_ref()
            .and_then(|total| total.pressure.get())
        else {
            return 0;
        };
        // An existing worker doing the original mm's reclaim scan is itself
        // reclaiming, rather than productive application work in PSI FULL.
        let _reclaim = CgroupMemoryTarget::pressure_task().map(|task| task.stall());
        let frames = self
            .frames
            .iter()
            .flatten()
            .filter(|page| page.charge.resident())
            .count();
        let anonymous = self
            .anonymous
            .populated()
            .into_iter()
            .filter(|&a| self.anonymous.page(a).is_some_and(|p| p.charge.resident()))
            .count();
        let inspected = (frames + anonymous) as u64;
        pressure.scans.fetch_add(inspected, Ordering::Relaxed);
        inspected
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn constant() -> PressureSource {
        Arc::new(|| PressureMemory {
            total: 128 << 20,
            free: 64 << 20,
            available: 64 << 20,
        })
    }
    #[test]
    fn repeated_readiness_checks_cannot_postpone_the_original_psi_deadline() {
        let domain = MemoryPressure::host(constant());
        let a = domain.task();
        let _productive = domain.task();
        let monitor = domain.monitor(b"full 300000 1000000", true).unwrap();
        let stall = a.stall(); // Productive peer on this CPU keeps FULL at zero.
        let first = monitor.deadline().unwrap();
        for _ in 0..32 {
            assert_eq!(monitor.peek(2).0, 0);
            assert_eq!(monitor.deadline(), Some(first));
        }
        monitor.state.lock().unwrap().next_poll = Some(Instant::now() - Duration::from_millis(1));
        assert_eq!(monitor.peek(2).0, 0);
        assert!(monitor.deadline().unwrap() > Instant::now());
        drop(stall);
        assert_eq!(monitor.deadline(), None);
    }
    #[test]
    fn ordinary_host_releases_do_not_wake_psi_but_bounded_quota_release_does() {
        struct Wake;
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {}
        }
        for bounded in [false, true] {
            let domain = if bounded {
                MemoryPressure::new(constant())
            } else {
                MemoryPressure::host(constant())
            };
            let _monitor = domain.monitor(b"some 1 2000000", true).unwrap();
            let target: Arc<dyn trames_shared::IoWake> = Arc::new(Wake);
            let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&target));
            let _subscription = domain.subscribe(&signal);
            domain.released();
            assert_eq!(signal.ready(), bounded);
            signal.reset();
            domain.source_changed();
            assert!(
                signal.ready(),
                "real native pressure events still wake the observer"
            );
        }
    }
    #[test]
    fn idle_scheduling_never_locks_psi_and_first_stall_uses_the_live_cpu_state() {
        let domain = MemoryPressure::host(constant());
        let monitor = domain.monitor(b"full 1 2000000", true).unwrap();
        let a = domain.task();
        let b = domain.task();
        {
            let _state = domain.state.lock().unwrap();
            a.dispatched(1);
            b.runnable(false);
        }
        let stall = a.stall();
        assert_eq!(domain.state.lock().unwrap().active(), [1.0, 1.0]);
        assert!(monitor.deadline().is_some());
        b.runnable(true);
        assert_eq!(domain.state.lock().unwrap().active(), [0.5, 0.5]);
        drop(stall);
        assert!(!domain.active_stalls.load(Ordering::Relaxed));
        let _state = domain.state.lock().unwrap();
        a.runnable(false);
        b.dispatched(1);
    }
    #[test]
    fn merged_average_intervals_match_per_transition_decay_and_flush_at_observation() {
        let domain = MemoryPressure::new(constant());
        let a = domain.task();
        let b = domain.task();
        let mut state = domain.state.lock().unwrap();
        let start = state.last;
        let mut reference = [[0.0; 3]; 2];
        for step in 1..=100 {
            let active = state.active();
            for (kind, ratio) in active.into_iter().enumerate() {
                for (average, seconds) in reference[kind].iter_mut().zip([10.0, 60.0, 300.0]) {
                    let decay = (-0.007f64 / seconds).exp();
                    *average = *average * decay + 100.0 * ratio * (1.0 - decay);
                }
            }
            let now = start + Duration::from_millis(step * 7);
            state.advance_time(now);
            if step % 11 == 0 {
                state.advance_average(now);
                for (actual, expected) in state
                    .average
                    .iter()
                    .flatten()
                    .zip(reference.iter().flatten())
                {
                    assert!((actual - expected).abs() < 1e-10);
                }
            }
            if step % 13 == 0 {
                state.transition(a.id, None, 0, None, Some(step % 26 == 0));
            }
            if step % 17 == 0 {
                state.transition(
                    b.id,
                    Some(step % 34 == 0),
                    0,
                    Some((step % 2) as usize),
                    None,
                );
            }
        }
        let last = state.last;
        state.advance_average(last);
        for (actual, expected) in state
            .average
            .iter()
            .flatten()
            .zip(reference.iter().flatten())
        {
            assert!((actual - expected).abs() < 1e-10);
        }
        let flushed = state.average_at;
        let now = state.last + Duration::from_millis(1);
        state.advance_time(now);
        let now = state.last + Duration::from_millis(1);
        state.advance_time(now);
        assert_eq!(
            state.average_at, flushed,
            "unchanged ratios need no decay work"
        );
    }
    #[test]
    fn host_monitor_keeps_ordinary_imports_direct_but_still_observes_native_stalls() {
        for bounded in [false, true] {
            let mut memory = Memory::default();
            memory.set_total_limit(128 << 20).unwrap();
            let domain = memory.memory_pressure((!bounded).then(constant));
            let monitor = domain.monitor(b"some 1 2000000", true).unwrap();
            assert_eq!(memory.async_faults_possible(), bounded);
            let mut registry = parallel::Registry::default();
            let view = memory.parallel_view(&mut registry).unwrap();
            assert_eq!(view.async_faults_possible(), bounded);
            drop(view);
            let task = domain.task();
            let original = Arc::new(PageWait::default());
            let wait = task.memory_wait(original.clone());
            assert_eq!(domain.state.lock().unwrap().stalled, 1);
            original.finish();
            assert!(wait.ready());
            assert_eq!(domain.state.lock().unwrap().stalled, 0);
            drop(monitor);
            assert!(!memory.async_faults_possible());
        }
    }
    #[test]
    fn scan_retry_preserves_the_stall_and_cancellation_clears_it_at_the_original_actor() {
        let mut memory = Memory::new(1 << 20);
        memory.set_total_limit(1 << 20).unwrap();
        memory.map(0x10000, 1 << 20, Permissions::RW).unwrap();
        memory.memory_report().bind_read_waker(Arc::new(|_| {}));
        let domain = memory.memory_pressure(None);
        let _monitor = domain.monitor(b"full 1 1000000", true).unwrap();
        let actor = Arc::new(CgroupMemoryTarget::default());
        let task = actor.bind_pressure(&domain);
        let scope = actor.scope();
        for page in 0..240 {
            memory.write(0x10000 + page * PAGE_SIZE, &[1]).unwrap();
        }
        let address = 0x10000 + 240 * PAGE_SIZE;
        let MemoryError::Pending(fault) = memory.write(address, &[1]).unwrap_err() else {
            panic!("pressure wait")
        };
        let generation = task.admission.lock().unwrap().unwrap().1;
        assert!(memory.activate_proc_reads());
        assert!(fault.wait.ready());
        drop(fault);
        assert_eq!(domain.state.lock().unwrap().stalled, 1);
        drop(actor.scope()); // Nested same-actor metadata work cannot end the fault.
        assert_eq!(domain.state.lock().unwrap().stalled, 1);
        let MemoryError::Pending(probe) = memory.write(address, &[1]).unwrap_err() else {
            panic!("retry preflight")
        };
        drop(probe); // A preflight rejection cannot restart an existing fault.
        assert_eq!(domain.state.lock().unwrap().stalled, 1);
        let MemoryError::Pending(retry) = memory.write(address, &[1]).unwrap_err() else {
            panic!("retry")
        };
        assert_eq!(task.admission.lock().unwrap().unwrap().1, generation);
        assert!(memory.activate_proc_reads());
        assert!(retry.wait.ready());
        drop(retry);
        assert_eq!(domain.state.lock().unwrap().stalled, 1);
        task.execution_finished(); // The interrupted turn made real guest progress.
        drop(scope);
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
        let scope = actor.scope();
        let MemoryError::Pending(cancelled) = memory.write(address, &[1]).unwrap_err() else {
            panic!("cancelled wait")
        };
        drop(cancelled);
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
        drop(scope);
    }
    #[test]
    fn a_scan_wakeup_does_not_restart_the_original_admission_deadline() {
        let domain = MemoryPressure::new(constant());
        let _monitor = domain.monitor(b"full 1 1000000", true).unwrap();
        let task = domain.task();
        let (deadline, generation) = task
            .begin_admission(Instant::now() - Duration::from_secs(3))
            .unwrap();
        let wait = AllocationWait {
            domain: domain.clone(),
            bytes: 128 << 20,
            deadline,
            generation,
            actor: task.clone(),
            scans: Vec::new(),
            retrying: AtomicBool::new(false),
        };
        assert!(trames_shared::ResourceWait::ready(&wait));
        assert!(task.admitting.load(Ordering::Relaxed));
        assert!(matches!(
            task.begin_admission(Instant::now()),
            Err(MemoryError::Limit)
        ));
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
    }
    #[test]
    fn an_empty_original_mm_scan_does_not_create_a_ready_retry_loop() {
        let mut memory = Memory::default();
        let report = memory.memory_report();
        report.bind_read_waker(Arc::new(|_| {}));
        let domain = MemoryPressure::new(Arc::new(|| PressureMemory {
            total: 1 << 20,
            free: 0,
            available: 0,
        }));
        domain.register_report(&report);
        let monitor = domain.monitor(b"some 1 1000000", true).unwrap();
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.bind_pressure(&domain);
        let _scope = actor.scope();
        let MemoryError::Pending(fault) = domain.allocation(PAGE_SIZE as usize).unwrap_err() else {
            panic!("expected retained pressure wait")
        };
        assert!(memory.activate_proc_reads());
        assert_eq!(domain.scanned_pages(), 0);
        assert!(!fault.wait.ready());
        drop(monitor);
        assert!(fault.wait.ready());
    }
    #[test]
    fn original_budget_stalls_without_charging_then_resumes_after_real_release() {
        let mut memory = Memory::new(1 << 20);
        memory.set_total_limit(1 << 20).unwrap();
        memory.map(0x10000, 1 << 20, Permissions::RW).unwrap();
        let domain = memory.memory_pressure(None);
        memory.memory_report().bind_read_waker(Arc::new(|_| {}));
        let monitor = domain.monitor(b"some 1000 1000000", true).unwrap();
        let target = Arc::new(CgroupMemoryTarget::default());
        let task = target.bind_pressure(&domain);
        let _scope = target.scope();
        for page in 0..240 {
            memory.write(0x10000 + page * PAGE_SIZE, &[42]).unwrap();
        }
        let before = memory.resident_bytes();
        let MemoryError::Pending(fault) =
            memory.write(0x10000 + 240 * PAGE_SIZE, &[17]).unwrap_err()
        else {
            panic!("bounded allocation must retain its wait")
        };
        assert_eq!(memory.resident_bytes(), before);
        assert!(!fault.wait.ready());
        assert!(monitor.deadline().is_some());
        assert!(memory.activate_proc_reads());
        assert!(domain.scanned_pages() >= 240);
        memory.unmap(0x10000, 16 * PAGE_SIZE).unwrap();
        assert!(fault.wait.ready());
        memory.write(0x10000 + 240 * PAGE_SIZE, &[17]).unwrap();
        assert_eq!(
            memory.read_array::<1>(0x10000 + 240 * PAGE_SIZE).unwrap(),
            [17]
        );
        for page in 241..256 {
            memory.write(0x10000 + page * PAGE_SIZE, &[42]).unwrap();
        }
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        let MemoryError::Pending(second) = memory.write(0x10000, &[1]).unwrap_err() else {
            panic!("reserve must stall a second allocation")
        };
        drop(monitor);
        assert!(second.wait.ready());
        memory.write(0x10000, &[1]).unwrap();
        task.retire();
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
    }
    #[test]
    fn native_waits_keep_per_cpu_some_full_time_and_cancel_without_retaining_tasks() {
        let domain = MemoryPressure::host(constant());
        let a = domain.task();
        let b = domain.task();
        b.dispatched(1);
        let monitor = domain.monitor(b"full 1 1000000", true).unwrap();
        let original = Arc::new(PageWait::default());
        let wait = a.memory_wait(original.clone());
        assert_eq!(domain.state.lock().unwrap().active(), [0.5, 0.5]);
        b.dispatched(0);
        assert_eq!(domain.state.lock().unwrap().active(), [1.0, 0.0]);
        b.runnable(false);
        assert_eq!(domain.state.lock().unwrap().active(), [1.0, 1.0]);
        assert!(monitor.deadline().is_some());
        let _text = domain.format();
        original.finish();
        assert!(wait.ready());
        assert_eq!(domain.state.lock().unwrap().active(), [0.0, 0.0]);
        assert_eq!(domain.anonymous_refaults(), 1);
        let weak = Arc::downgrade(&a);
        drop(a);
        assert!(weak.upgrade().is_some());
        drop(wait);
        assert!(weak.upgrade().is_none());
    }
    #[test]
    fn scheduling_and_ready_checks_never_reenter_scheduler_notification() {
        struct Wake {
            locked: AtomicBool,
            calls: AtomicUsize,
        }
        impl trames_shared::IoWake for Wake {
            fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
                assert!(
                    !self.locked.load(Ordering::Relaxed),
                    "reentered original run queue"
                );
                self.calls.fetch_add(1, Ordering::Relaxed);
            }
        }
        let domain = MemoryPressure::host(constant());
        let a = domain.task();
        let b = domain.task();
        let monitor = domain.monitor(b"full 1 1000000", true).unwrap();
        let wake = Arc::new(Wake {
            locked: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        });
        let target: Arc<dyn trames_shared::IoWake> = wake.clone();
        let signal = trames_shared::IoSignal::new(1, Arc::downgrade(&target));
        let _subscription = domain.subscribe(&signal);
        let source = Arc::new(PageWait::default());
        let resource = a.memory_wait(source.clone());
        assert_eq!(wake.calls.load(Ordering::Relaxed), 1);
        signal.reset();
        assert!(monitor.deadline().is_some()); // full is currently zero
        wake.locked.store(true, Ordering::Relaxed);
        b.runnable(false);
        b.dispatched(1);
        source.finish();
        assert!(resource.ready());
        b.retire();
        wake.locked.store(false, Ordering::Relaxed);
        assert_eq!(wake.calls.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn hardware_completion_and_cancellation_release_original_stall_leases() {
        let domain = MemoryPressure::host(constant());
        let task = domain.task();
        let original = Arc::new(HardwareWait::default());
        let wrapper = task.hardware_wait(original.clone());
        assert_eq!(domain.state.lock().unwrap().stalled, 1);
        original.fire();
        assert!(wrapper.ready());
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
        let pending = Arc::new(HardwareWait::default());
        let cancelled = task.hardware_wait(pending.clone());
        assert_eq!(domain.state.lock().unwrap().stalled, 1);
        drop(cancelled);
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
        let retried = task.hardware_wait(pending.clone());
        assert_eq!(domain.state.lock().unwrap().stalled, 1);
        pending.fire();
        assert!(retried.ready());
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
    }
    #[test]
    fn host_availability_is_not_a_quota() {
        let mut memory = Memory::new(ADDRESS_LIMIT as usize);
        memory.set_total_limit(ADDRESS_LIMIT as usize).unwrap();
        memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        let domain = memory.memory_pressure(Some(Arc::new(|| PressureMemory {
            total: 1 << 20,
            free: 0,
            available: 0,
        })));
        let monitor = domain.monitor(b"some 1 1000000", true).unwrap();
        let actor = Arc::new(CgroupMemoryTarget::default());
        actor.bind_pressure(&domain);
        let _scope = actor.scope();
        memory.write(0x10000, b"host still admits").unwrap();
        assert_eq!(
            memory.read_array::<17>(0x10000).unwrap(),
            *b"host still admits"
        );
        drop(monitor);
        assert!(!domain.monitored());
    }
    #[test]
    fn trigger_credentials_windows_rate_limit_and_timed_stalls_follow_original_resources() {
        let domain = MemoryPressure::new(constant());
        assert!(matches!(domain.monitor(b"some 1 1000000", false), Err(22)));
        assert!(domain.monitor(b"some 0 2000000", false).is_err());
        assert!(domain.monitor(b"full 3000000 2000000", true).is_err());
        let monitor = domain.monitor(b"full 1 2000000\0", false).unwrap();
        let task = domain.task();
        let guard = task.stall_until(Some(Instant::now() + Duration::from_millis(2)));
        std::thread::sleep(Duration::from_millis(4));
        let _stats = domain.format();
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
        assert_eq!(monitor.poll(2).0, 2);
        let epoch = monitor.epoch();
        assert_eq!(monitor.poll(2).0, 0);
        assert_eq!(monitor.epoch(), epoch);
        drop(guard);
        assert_eq!(domain.state.lock().unwrap().stalled, 0);
    }
}
