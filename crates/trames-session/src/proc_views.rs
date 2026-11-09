// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only process directory over original task resources and live counters.
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};
use trames_vfs::{PidNamespace, ProcQuery, ProcRefresh, ProcSource, ProcTask, RuntimeInfo};

pub(super) struct Source {
    pub directory: Arc<trames_kernel::signal::IoDirectory>,
    pub counters: Arc<trames_vfs::ProcCounters>,
    pub created: AtomicU32,
    pub load: Arc<Mutex<Load>>,
    pub started: Instant,
    pub boot_time: u64,
    pub cpus: usize,
    pub features: &'static str,
    pub task_limit: usize,
    pub limits: crate::MemoryLimits,
    pub host: Option<Arc<dyn Fn() -> trames_linux::HostMemoryInfo + Send + Sync>>,
    pub reads: Mutex<Reads>,
    pub wake: Arc<dyn Fn() + Send + Sync>,
}
/// The existing five-second exponential sample, advanced by actual observers.
/// It is shared by source and legacy callers, never copied by the drive loop.
pub(super) struct Load {
    values: [f64; 3],
    sampled: Instant,
}
impl Default for Load {
    fn default() -> Self {
        Self {
            values: [0.0; 3],
            sampled: Instant::now(),
        }
    }
}
impl Load {
    pub fn sample(&mut self, at: Instant, running: usize) -> [f64; 3] {
        let elapsed = at.saturating_duration_since(self.sampled).as_secs_f64();
        if elapsed >= 5.0 {
            for (load, seconds) in self.values.iter_mut().zip([60.0, 300.0, 900.0]) {
                let decay = (-elapsed / seconds).exp();
                *load = *load * decay + running as f64 * (1.0 - decay);
            }
            self.sampled = at;
        }
        self.values
    }
}
#[derive(Default)]
pub(super) struct Reads {
    pending: Vec<trames_memory::MemoryReport>,
    waiting: Vec<ReadWait>,
    executor: Option<Weak<trames_vfs::IoSignal>>,
}
struct ReadWait {
    report: trames_memory::MemoryReport,
    signal: Arc<trames_vfs::IoSignal>,
    _subscriptions: Vec<trames_vfs::IoSubscription>,
}
pub(super) struct ReadDriver {
    source: Arc<Source>,
    pub signal: Arc<trames_vfs::IoSignal>,
}
impl Drop for ReadDriver {
    fn drop(&mut self) {
        let mut reads = self.source.reads.lock().unwrap();
        if reads
            .executor
            .as_ref()
            .is_some_and(|old| old.ptr_eq(&Arc::downgrade(&self.signal)))
        {
            reads.executor = None;
            let pending =
                !reads.pending.is_empty() || reads.waiting.iter().any(|wait| wait.signal.ready());
            drop(reads);
            if pending {
                (self.source.wake)();
            }
        }
    }
}
impl Source {
    fn running(tasks: &[Arc<trames_kernel::signal::IoTask>]) -> usize {
        tasks
            .iter()
            .filter(|task| {
                task.live()
                    && task.proc_view.runnable()
                    && !task.lifecycle().stopped()
                    && !task.cgroup().is_some_and(|group| group.frozen())
            })
            .count()
    }
    fn load(&self, at: Instant, sample: bool) -> [f64; 3] {
        if sample {
            let running = Self::running(&self.directory.proc_tasks());
            self.load.lock().unwrap().sample(at, running)
        } else {
            self.load.lock().unwrap().values
        }
    }
    fn idle(&self, at: Instant, times: &[Duration]) -> Duration {
        at.saturating_duration_since(self.started)
            .saturating_mul(self.cpus as u32)
            .saturating_sub(times.iter().copied().sum())
    }
    pub fn request_read(&self, report: trames_memory::MemoryReport) {
        let mut reads = self.reads.lock().unwrap();
        if reads.pending.iter().any(|old| old.same_resource(&report))
            || reads
                .waiting
                .iter()
                .any(|old| old.report.same_resource(&report))
        {
            return;
        }
        reads.pending.push(report);
        drop(reads);
        self.notify_reads();
    }
    pub fn bind_reads(self: &Arc<Self>, report: &trames_memory::MemoryReport) {
        let source = Arc::downgrade(self);
        report.bind_read_waker(Arc::new(move |report| {
            if let Some(source) = source.upgrade() {
                source.request_read(report);
            }
        }));
    }
    pub fn take_reads(&self) -> Vec<trames_memory::MemoryReport> {
        self.take_for(None)
    }
    pub fn bind_reader(self: &Arc<Self>, signal: Arc<trames_vfs::IoSignal>) -> ReadDriver {
        self.reads.lock().unwrap().executor = Some(Arc::downgrade(&signal));
        // Subscribe before the retry. Marking a ready request is harmless even
        // before the epoch begins; its first existing executor consumes it.
        signal.notify();
        ReadDriver {
            source: self.clone(),
            signal,
        }
    }
    pub fn take_worker_reads(
        &self,
        signal: &Arc<trames_vfs::IoSignal>,
    ) -> Vec<trames_memory::MemoryReport> {
        self.take_for(Some(signal))
    }
    fn take_for(
        &self,
        executor: Option<&Arc<trames_vfs::IoSignal>>,
    ) -> Vec<trames_memory::MemoryReport> {
        let mut reads = self.reads.lock().unwrap();
        let current = reads.executor.as_ref().and_then(Weak::upgrade);
        if match (executor, current.as_ref()) {
            (Some(requested), Some(current)) => !Arc::ptr_eq(requested, current),
            (None, None) => false,
            _ => true,
        } {
            return Vec::new();
        }
        let mut reports = std::mem::take(&mut reads.pending);
        let mut retired = Vec::new();
        let mut i = 0;
        while i < reads.waiting.len() {
            if reads.waiting[i].signal.ready() {
                let wait = reads.waiting.swap_remove(i);
                reports.push(wait.report.clone());
                retired.push(wait);
            } else {
                i += 1;
            }
        }
        drop(reads);
        drop(retired);
        reports
    }
    pub fn defer_read(
        &self,
        report: trames_memory::MemoryReport,
        signal: Arc<trames_vfs::IoSignal>,
        subscriptions: Vec<trames_vfs::IoSubscription>,
    ) {
        self.reads.lock().unwrap().waiting.push(ReadWait {
            report,
            signal: signal.clone(),
            _subscriptions: subscriptions,
        });
        if signal.ready() {
            self.notify_reads();
        }
    }
    fn notify_reads(&self) {
        let executor = self
            .reads
            .lock()
            .unwrap()
            .executor
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(signal) = executor {
            signal.notify();
        } else {
            (self.wake)();
        }
    }
    fn target(path: &[u8], namespace: &PidNamespace) -> Option<u32> {
        let parts: Vec<_> = path
            .strip_prefix(b"/proc/")?
            .split(|b| *b == b'/')
            .collect();
        let id = if parts.get(1) == Some(&b"task".as_slice()) {
            parts.get(2)?
        } else {
            parts.first()?
        };
        namespace.global(std::str::from_utf8(id).ok()?.parse().ok()?)
    }
}
impl trames_linux::SystemStatistics for Source {
    fn observe(&self) -> Option<trames_linux::SystemInfo> {
        if self.limits.is_host_managed() && self.host.is_none() {
            return None;
        }
        let tasks = self.directory.proc_tasks();
        let mut resident = BTreeMap::new();
        if !self.limits.is_host_managed() {
            for task in &tasks {
                if let Some(report) = task.memory_report() {
                    resident
                        .entry(report.identity())
                        .or_insert_with(|| report.resident_bytes());
                }
            }
        }
        let host = self
            .limits
            .is_host_managed()
            .then(|| self.host.as_ref().map(|host| host()))
            .flatten();
        let memory = self.limits.reported(resident.values().copied().sum(), host);
        let at = Instant::now();
        let running = Self::running(&tasks);
        Some(trames_linux::SystemInfo {
            uptime: at.saturating_duration_since(self.started),
            load: self.load.lock().unwrap().sample(at, running),
            total: memory.total,
            free: memory.free,
            tasks: tasks.len(),
        })
    }
}
impl trames_vfs::IoWake for Source {
    fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
        self.notify_reads();
    }
}
impl ProcSource for Source {
    fn available(&self, demand: ProcRefresh) -> bool {
        !demand.residency() || !self.limits.is_host_managed() || self.host.is_some()
    }
    fn task(&self, pid: u32) -> Option<Arc<dyn ProcTask>> {
        self.directory.proc_identity(pid)
    }
    fn observe(&self, query: ProcQuery<'_>) -> RuntimeInfo {
        let ProcQuery {
            path,
            demand,
            namespace,
            reader,
            enumerate,
            retained,
            content,
        } = query;
        let target = Self::target(path, namespace);
        let aggregate = (path == b"/proc" && enumerate)
            || matches!(path, b"/proc/stat" | b"/proc/loadavg")
            || target.is_none() && (demand.residency() || demand.descriptors());
        let mut tasks: Vec<Arc<dyn ProcTask>> = if aggregate {
            self.directory
                .proc_tasks()
                .into_iter()
                .map(|task| task as Arc<dyn ProcTask>)
                .collect()
        } else {
            Vec::new()
        };
        let mut add = |task: Arc<dyn ProcTask>| {
            if !tasks.iter().any(|old| old.identity() == task.identity()) {
                tasks.push(task);
            }
        };
        if let Some(task) = self.directory.proc_task(reader) {
            add(task);
        }
        if path.split(|b| *b == b'/').nth(3) == Some(b"task") {
            if let Some(group) = path
                .split(|b| *b == b'/')
                .nth(2)
                .and_then(|part| std::str::from_utf8(part).ok())
                .and_then(|part| part.parse::<u32>().ok())
                .and_then(|pid| namespace.global(pid))
                .and_then(|pid| self.directory.proc_task(pid))
            {
                add(group);
            }
        }
        let target_task = retained.cloned().or_else(|| {
            target
                .and_then(|pid| self.directory.proc_task(pid))
                .or_else(|| {
                    (path.starts_with(b"/proc/self") || path.starts_with(b"/proc/thread-self"))
                        .then(|| self.directory.proc_task(reader))
                        .flatten()
                })
                .map(|task| task as Arc<dyn ProcTask>)
        });
        if let Some(task) = target_task {
            if demand.residency() || enumerate && path.ends_with(b"/task") {
                for peer in task.threads() {
                    add(peer);
                }
            }
            add(task);
        }
        if let Some(task) = retained {
            tasks.retain(|candidate| {
                Some(candidate.pid()) != target || candidate.identity() == task.identity()
            });
        }
        let mut resident = BTreeMap::new();
        let mut processes = Vec::new();
        for task in tasks {
            let mut fields = if target.is_none_or(|pid| pid == ProcTask::pid(&*task)) {
                demand
            } else {
                ProcRefresh::Metadata
            };
            if content && target.is_some() {
                fields = fields.with_content();
            }
            let memory = task.memory_report();
            let bytes = if demand.residency() {
                memory.as_ref().map(|report| {
                    *resident
                        .entry(report.identity())
                        .or_insert_with(|| report.resident_bytes())
                })
            } else {
                None
            };
            if path == b"/proc/meminfo" {
                continue;
            }
            if let Some(info) = task.observe(fields, bytes) {
                processes.push(info);
            }
        }
        let used = resident.values().copied().sum();
        let host = if demand.residency() {
            self.host.as_ref().map(|host| host())
        } else {
            None
        };
        let memory = self.limits.reported(used, host);
        let at = Instant::now();
        let times = self.counters.times(self.cpus, at);
        let per_cpu_ticks: Vec<_> = times
            .iter()
            .map(|time| (time.as_nanos() / 10_000_000) as u64)
            .collect();
        RuntimeInfo {
            cpu_count: self.cpus,
            task_limit: self.task_limit,
            cpu_features: self.features,
            cpu_user_ticks: per_cpu_ticks.iter().sum(),
            per_cpu_ticks,
            processes,
            uptime: at.saturating_duration_since(self.started),
            boot_time: self.boot_time,
            context_switches: self.counters.switches.load(Ordering::Relaxed),
            idle: self.idle(at, &times),
            memory_limit: memory.total,
            available_memory: Some(memory.available),
            load: self.load(at, aggregate),
            processes_created: self.created.load(Ordering::Relaxed),
            used_memory: memory.total.saturating_sub(memory.free),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn load_sampling_advances_without_drive_loop_and_preserves_decay() {
        let origin = Instant::now();
        let mut load = Load {
            values: [0.0; 3],
            sampled: origin,
        };
        assert_eq!(load.sample(origin + Duration::from_secs(4), 12), [0.0; 3]);
        let active = load.sample(origin + Duration::from_secs(5), 4);
        for (value, seconds) in active.into_iter().zip([60.0_f64, 300.0, 900.0]) {
            assert!((value - 4.0 * (1.0 - (-5.0 / seconds).exp())).abs() < 1e-12);
        }
        let idle = load.sample(origin + Duration::from_secs(20), 0);
        for ((value, old), seconds) in idle.into_iter().zip(active).zip([60.0_f64, 300.0, 900.0]) {
            assert!((value - old * (-15.0 / seconds).exp()).abs() < 1e-12);
        }
        assert_eq!(load.sample(origin + Duration::from_secs(19), 100), idle);
    }
}
