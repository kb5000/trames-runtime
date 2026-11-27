// SPDX-License-Identifier: GPL-3.0-or-later
//! Actual execution resources; CPU/cgroup observers retain no task or Files.
use super::*;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Scope(pub(crate) crate::cgroup::PerfGroup);
pub(super) struct CpuContext {
    pub(super) clock: Clock,
    pub(super) groups: Vec<(Scope, std::sync::Weak<ClockData>)>,
}
#[derive(Clone, Default)]
pub struct Domain {
    pub(super) active: Arc<std::sync::atomic::AtomicUsize>,
    used: Arc<std::sync::atomic::AtomicBool>,
    pub(super) cpus: Arc<parking_lot::Mutex<BTreeMap<u32, CpuContext>>>,
    quota: Arc<[Arc<quota::Quota>; 32]>,
    origin: Arc<std::sync::OnceLock<Instant>>,
}
impl Domain {
    /// A cold, monotonic hint. Before the first observer, a worker needs only
    /// this word; active resource/CPU checks remain authoritative afterwards.
    #[inline]
    pub fn observed(&self) -> bool {
        self.used.load(Ordering::Relaxed)
    }
    pub fn observe_events(&self) {
        self.used.store(true, Ordering::Relaxed);
    }
    /// An unused perf facility adds no timestamps, TLS scopes or allocations.
    pub fn observing(&self, task: &ProcessView, cpu: u32) -> bool {
        if task.perf_observing() {
            return true;
        }
        self.active.load(Ordering::Relaxed) != 0
            && self.cpus.lock().get(&cpu).is_some_and(|context| {
                context.clock.observing()
                    || context.groups.iter().any(|(_, clock)| {
                        clock
                            .upgrade()
                            .is_some_and(|clock| Clock(clock).observing())
                    })
            })
    }
    pub fn bind_origin(&self, origin: Instant) {
        self.origin.get_or_init(|| origin);
    }
    pub fn time(&self) -> u64 {
        self.origin
            .get_or_init(Instant::now)
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128) as u64
    }
    pub fn cpu(&self, cpu: u32, scope: Option<Scope>) -> Clock {
        self.observe_events();
        let mut cpus = self.cpus.lock();
        let entry = cpus.entry(cpu).or_insert_with(|| CpuContext {
            clock: Clock::execution(Some(cpu), true, Some(self.active.clone())),
            groups: Vec::new(),
        });
        if let Some(scope) = scope {
            entry.groups.retain(|(_, clock)| clock.strong_count() != 0);
            if let Some(clock) = entry
                .groups
                .iter()
                .find(|(old, _)| old.0.same(&scope.0))
                .and_then(|(_, clock)| clock.upgrade())
            {
                return Clock(clock);
            }
            let clock = Clock::execution(Some(cpu), false, Some(self.active.clone()));
            entry.groups.push((scope, Arc::downgrade(&clock.0)));
            clock
        } else {
            entry.clock.clone()
        }
    }
    pub fn enter(
        &self,
        task: &ProcessView,
        group: Option<&CgroupTask>,
        context: Sample,
    ) -> Option<Execution> {
        let existing = task.perf_existing();
        if !self.observing(task, context.cpu) {
            return None;
        }
        let base = existing.unwrap_or_else(|| task.perf_clock());
        let previous = base.0.cpu.swap(context.cpu, Ordering::Relaxed);
        let migrated = previous != u32::MAX && previous != context.cpu;
        let mut clocks = vec![(base.clone(), false)];
        if let Some(filtered) = base.0.filters.lock().get(&context.cpu) {
            clocks.push((filtered.clone(), true));
        }
        if self.active.load(Ordering::Relaxed) != 0 {
            let mut cpus = self.cpus.lock();
            if let Some(cpu) = cpus.get_mut(&context.cpu) {
                if cpu.clock.0.active.load(Ordering::Relaxed) {
                    clocks.push((cpu.clock.clone(), false));
                }
                cpu.groups.retain(|(_, clock)| clock.strong_count() != 0);
                for (scope, clock) in &cpu.groups {
                    if let Some(clock) = clock
                        .upgrade()
                        .filter(|clock| clock.active.load(Ordering::Relaxed))
                    {
                        if group.is_some_and(|task| scope.0.contains(task)) {
                            clocks.push((Clock(clock), true));
                        }
                    }
                }
            }
        }
        let began = Instant::now();
        for (clock, own_time) in &clocks {
            if *own_time && !clock.0.time.running() {
                clock.0.time.begin(began);
            }
            if migrated {
                clock.record(4, 1, &context, true, 0);
            }
        }
        let faults = clocks
            .iter()
            .any(|(clock, _)| clock.0.active.load(Ordering::Relaxed))
            .then(|| Arc::new(trames_memory::FaultCounts::default()));
        let fault_scope = trames_memory::FaultScope::enter(faults.clone());
        Some(Execution {
            clocks,
            began,
            faults,
            _fault_scope: fault_scope,
            context,
            domain: self.clone(),
            group: group.cloned(),
            _quota: quota::Guard::enter(self.quota[context.cpu as usize].clone()),
            image: task.perf_image_source(),
        })
    }
}
pub struct Execution {
    clocks: Vec<(Clock, bool)>,
    began: Instant,
    faults: Option<Arc<trames_memory::FaultCounts>>,
    domain: Domain,
    group: Option<CgroupTask>,
    _fault_scope: trames_memory::FaultScope,
    context: Sample,
    _quota: quota::Guard,
    image: metadata::ImageSource,
}
impl Execution {
    pub fn kernel(&self, kernel: bool) {
        if let Some(faults) = &self.faults {
            faults.kernel(kernel);
        }
    }
    fn refresh(&mut self) {
        let mut discovered = Vec::new();
        if let Some(clock) = self.clocks[0].0 .0.filters.lock().get(&self.context.cpu) {
            discovered.push((clock.clone(), true));
        }
        if self.domain.active.load(Ordering::Relaxed) != 0 {
            if let Some(cpu) = self.domain.cpus.lock().get_mut(&self.context.cpu) {
                if cpu.clock.0.active.load(Ordering::Relaxed) {
                    discovered.push((cpu.clock.clone(), false));
                }
                cpu.groups.retain(|(_, clock)| clock.strong_count() != 0);
                for (scope, clock) in &cpu.groups {
                    if self
                        .group
                        .as_ref()
                        .is_some_and(|group| scope.0.contains(group))
                    {
                        if let Some(clock) = clock
                            .upgrade()
                            .filter(|clock| clock.active.load(Ordering::Relaxed))
                        {
                            discovered.push((Clock(clock), true));
                        }
                    }
                }
            }
        }
        for (clock, own_time) in discovered {
            if !self.clocks.iter().any(|(old, _)| old.same(&clock)) {
                if own_time && !clock.0.time.running() {
                    clock.0.time.begin(Instant::now());
                }
                self.clocks.push((clock, own_time));
            }
        }
        if self.faults.is_none()
            && self
                .clocks
                .iter()
                .any(|(clock, _)| clock.0.active.load(Ordering::Relaxed))
        {
            let faults = Arc::new(trames_memory::FaultCounts::default());
            self._fault_scope.install(faults.clone());
            self.faults = Some(faults);
        }
    }
    pub fn boundary(&mut self, ip: u64, time: u64, kernel: bool) {
        self.refresh();
        let context = Sample {
            ip: if kernel { 0 } else { ip },
            time,
            ..self.context
        };
        let _sampling_work = self
            .clocks
            .iter()
            .any(|(clock, _)| {
                clock.0.sampling.load(Ordering::Relaxed) || clock.0.metadata.load(Ordering::Relaxed)
            })
            .then(quota::measure);
        let faults = self.faults.as_ref().map_or([0; 4], |faults| faults.take());
        let image = self
            .clocks
            .iter()
            .any(|(clock, _)| {
                clock.0.metadata.load(Ordering::Relaxed) && clock.0.active.load(Ordering::Relaxed)
            })
            .then(|| self.image.current())
            .flatten();
        for (clock, _) in &self.clocks {
            if let Some(image) = &image {
                clock.metadata(image, &context);
            }
            for (index, count) in faults.into_iter().enumerate().filter(|(_, n)| *n != 0) {
                let major = index & 1 != 0;
                let in_kernel = index >= 2;
                clock.record(2, count, &context, in_kernel, 0);
                clock.record(if major { 6 } else { 5 }, count, &context, in_kernel, 0);
            }
            clock.sample_mode(&context, kernel);
        }
    }
    pub fn budget(&mut self) -> Option<Duration> {
        let _sampling_work = self
            .clocks
            .iter()
            .any(|(clock, _)| clock.0.sampling.load(Ordering::Relaxed))
            .then(quota::measure);
        self.refresh();
        self.clocks
            .iter()
            .filter_map(|(clock, _)| clock.budget())
            .min()
    }
}
impl Drop for Execution {
    fn drop(&mut self) {
        let context = Sample {
            time: self
                .context
                .time
                .saturating_add(self.began.elapsed().as_nanos().min(u64::MAX as u128) as u64),
            ip: 0,
            ..self.context
        };
        self.boundary(0, context.time, true);
        for (clock, own_time) in &self.clocks {
            clock.record(3, 1, &context, true, 0);
            if *own_time {
                clock.0.time.finish(self.began, self.began.elapsed());
            }
        }
    }
}
impl Clock {
    pub(super) fn deactivate(&self) {
        if self.0.active.swap(false, Ordering::Relaxed) {
            if let Some(domain) = &self.0.wake_domain {
                domain.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    pub(crate) fn observing(&self) -> bool {
        self.0.active.load(Ordering::Relaxed)
            || self.0.filters.lock().values().any(Clock::observing)
    }
    fn execution(
        cpu: Option<u32>,
        wall: bool,
        wake_domain: Option<Arc<std::sync::atomic::AtomicUsize>>,
    ) -> Self {
        Self(Arc::new(ClockData {
            time: Arc::default(),
            terminal: Default::default(),
            enabled_time: None,
            groups: Default::default(),
            sampling: Default::default(),
            active: Default::default(),
            metadata: Default::default(),
            history: Default::default(),
            cpu: AtomicU32::new(u32::MAX),
            filters: Default::default(),
            wall: wall.then(Instant::now),
            filter: cpu,
            wake_domain,
        }))
    }
    pub fn for_cpu(&self, cpu: u32) -> Self {
        self.0
            .filters
            .lock()
            .entry(cpu)
            .or_insert_with(|| {
                let mut clock = Self::execution(Some(cpu), false, None);
                Arc::get_mut(&mut clock.0)
                    .expect("new execution clock")
                    .enabled_time = Some(self.0.time.clone());
                if let Some(terminal) = *self.0.terminal.lock() {
                    *clock.0.terminal.lock() = Some(Stamp {
                        cpu: 0,
                        enabled: terminal.enabled,
                    });
                }
                // The last observed CPU can be stale while collection is off.
                // Only that CPU's actual execution actor owns begin/finish.
                clock
            })
            .clone()
    }
    pub(super) fn output_compatible(&self, other: &Self) -> bool {
        self.same(other) || self.0.filter.is_some() && self.0.filter == other.0.filter
    }
    pub(super) fn groups(&self) -> Vec<Arc<parking_lot::Mutex<Group>>> {
        let mut registry = self.0.groups.lock();
        registry.groups.retain(|group| group.strong_count() != 0);
        registry
            .groups
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect()
    }
    pub(super) fn record(
        &self,
        config: u64,
        count: u64,
        context: &Sample,
        kernel: bool,
        address: u64,
    ) {
        if !self.0.active.load(Ordering::Relaxed) {
            return;
        }
        let context = Sample {
            ip: if kernel { 0 } else { context.ip },
            ..*context
        };
        let revision = self.0.groups.lock().revision;
        let source = self.read();
        let mut notifications = Vec::new();
        let mut active = false;
        for group in self.groups() {
            let mut group = group.lock();
            group.settle(source);
            for counter in group.members.values_mut() {
                if counter.running
                    && counter.config == config
                    && !(if kernel {
                        counter.attr.exclude_kernel
                    } else {
                        counter.attr.exclude_user
                    })
                {
                    counter.value = counter.value.wrapping_add(count);
                    if counter.attr.period != 0 {
                        counter.remaining = counter.remaining.saturating_sub(count);
                    }
                    counter.publish_branch();
                }
                active |= counter.running;
            }
            notifications.extend(group.sample_mode(source, &context, kernel, address));
        }
        if !active && self.0.groups.lock().revision == revision {
            self.deactivate();
        }
        for changed in notifications {
            changed.notify_atomic();
        }
    }
    fn sample_mode(&self, context: &Sample, kernel: bool) {
        if !self.0.sampling.load(Ordering::Relaxed) {
            return;
        }
        let revision = self.0.groups.lock().revision;
        let source = self.read();
        let mut notifications = Vec::new();
        let mut sampling = false;
        for group in self.groups() {
            let mut group = group.lock();
            notifications.extend(group.sample_mode(source, context, kernel, 0));
            sampling |= group
                .members
                .values()
                .any(|counter| counter.running && counter.attr.period != 0);
        }
        if self.0.groups.lock().revision == revision {
            self.0.sampling.store(sampling, Ordering::Relaxed);
        }
        for changed in notifications {
            changed.notify_atomic();
        }
    }
    fn budget(&self) -> Option<Duration> {
        if !self.0.sampling.load(Ordering::Relaxed) {
            return None;
        }
        let source = self.read();
        let mut remaining = None;
        for group in self.groups() {
            let mut group = group.lock();
            group.settle(source);
            for counter in group.members.values().filter(|counter| {
                counter.running && matches!(counter.config, 0 | 1) && counter.attr.period != 0
            }) {
                let duration = Duration::from_nanos(counter.remaining.max(1000));
                remaining = Some(remaining.map_or(duration, |old: Duration| old.min(duration)));
            }
        }
        remaining
    }
}
