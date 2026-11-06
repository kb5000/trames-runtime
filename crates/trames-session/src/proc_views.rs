// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only process directory over original task resources and live counters.
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};
use trames_vfs::{PidNamespace, ProcQuery, ProcRefresh, ProcSource, ProcTask, RuntimeInfo};

pub(super) struct Source {
    pub directory: Arc<trames_kernel::signal::IoDirectory>,
    pub counters: Arc<trames_vfs::ProcCounters>,
    pub created: AtomicU32,
    pub idle: AtomicU64,
    pub load: Mutex<[f64; 3]>,
    pub started: Instant,
    pub boot_time: u64,
    pub cpus: usize,
    pub features: &'static str,
    pub task_limit: usize,
    pub limits: crate::MemoryLimits,
    pub host: Option<Arc<dyn Fn() -> trames_linux::HostMemoryInfo + Send + Sync>>,
    pub reads: Mutex<Vec<trames_memory::MemoryReport>>,
    pub wake: Arc<dyn Fn() + Send + Sync>,
}
impl Source {
    pub fn request_read(&self, report: trames_memory::MemoryReport) {
        let mut reads = self.reads.lock().unwrap();
        if reads.iter().any(|old| old.same_resource(&report)) {
            return;
        }
        reads.push(report);
        drop(reads);
        (self.wake)();
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
        std::mem::take(&mut *self.reads.lock().unwrap())
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
impl trames_vfs::IoWake for Source {
    fn wake_io(&self, _: &Arc<trames_vfs::IoSignal>) {
        (self.wake)();
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
        let per_cpu_ticks = self.counters.ticks(self.cpus);
        RuntimeInfo {
            cpu_count: self.cpus,
            task_limit: self.task_limit,
            cpu_features: self.features,
            cpu_user_ticks: per_cpu_ticks.iter().sum(),
            per_cpu_ticks,
            processes,
            uptime: self.started.elapsed(),
            boot_time: self.boot_time,
            context_switches: self.counters.switches.load(Ordering::Relaxed),
            idle: std::time::Duration::from_nanos(self.idle.load(Ordering::Relaxed)),
            memory_limit: memory.total,
            available_memory: Some(memory.available),
            load: *self.load.lock().unwrap(),
            processes_created: self.created.load(Ordering::Relaxed),
            used_memory: memory.total.saturating_sub(memory.free),
        }
    }
}
