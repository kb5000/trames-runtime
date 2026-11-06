// SPDX-License-Identifier: GPL-3.0-or-later
//! Dynamic process facts from original task resources, not owner snapshots.
use super::*;
/// The original proc PID object contains only a weak task binding. Open proc
/// files may retain it without retaining Files through IoTask's image metadata.
/// Nonleader exec transfers the leader's PID object to its surviving task.
pub struct ProcPid {
    id: u32,
    identity: u64,
    current: RwLock<Weak<IoTask>>,
}
impl ProcPid {
    fn task(&self) -> Option<Arc<IoTask>> {
        let task = self.current.read().unwrap().upgrade()?;
        task.identifies(0, self.id).then_some(task)
    }
}
impl trames_vfs::ProcTask for ProcPid {
    fn present(&self) -> bool {
        self.task().is_some()
    }
    fn identity(&self) -> u64 {
        self.identity
    }
    fn pid(&self) -> u32 {
        self.id
    }
    fn observe(
        &self,
        demand: trames_vfs::ProcRefresh,
        residency: Option<usize>,
    ) -> Option<trames_vfs::ProcessInfo> {
        let task = self.task()?;
        let mut info = trames_vfs::ProcTask::observe(&*task, demand, residency)?;
        info.identity = self.identity;
        Some(info)
    }
    fn memory_report(&self) -> Option<trames_memory::MemoryReport> {
        trames_vfs::ProcTask::memory_report(&*self.task()?)
    }
    fn threads(&self) -> Vec<Arc<dyn trames_vfs::ProcTask>> {
        self.task()
            .map_or_else(Vec::new, |task| trames_vfs::ProcTask::threads(&*task))
    }
}
impl IoTask {
    pub(super) fn bind_proc_pid(self: &Arc<Self>, pid: u32) {
        let mut binding = self.proc_pid.write().unwrap();
        if binding.as_ref().is_none_or(|old| old.id != pid) {
            *binding = Some(Arc::new(ProcPid {
                id: pid,
                identity: self.proc_view.identity(),
                current: RwLock::new(Arc::downgrade(self)),
            }));
        } else {
            *binding.as_ref().unwrap().current.write().unwrap() = Arc::downgrade(self);
        }
    }
    pub fn inherit_proc_pid(self: &Arc<Self>, leader: &Arc<Self>) {
        let binding = leader.proc_pid.read().unwrap().clone();
        if let Some(binding) = &binding {
            *binding.current.write().unwrap() = Arc::downgrade(self);
        }
        *self.proc_pid.write().unwrap() = binding;
    }
    pub fn bind_proc_limits(&self, limits: &Arc<crate::limits::Limits>) {
        let original = self.proc_limits.get_or_init(|| limits.clone());
        debug_assert!(Arc::ptr_eq(original, limits));
    }
}
impl trames_vfs::ProcTask for IoTask {
    fn present(&self) -> bool {
        self.identifies(0, self.pid.load(Ordering::Relaxed))
    }
    fn identity(&self) -> u64 {
        self.proc_pid
            .read()
            .unwrap()
            .as_ref()
            .map_or_else(|| self.proc_view.identity(), |pid| pid.identity)
    }
    fn pid(&self) -> u32 {
        self.pid.load(Ordering::Relaxed)
    }
    fn threads(&self) -> Vec<Arc<dyn trames_vfs::ProcTask>> {
        self.proc_group.get().map_or_else(Vec::new, |group| {
            group
                .members
                .read()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|task| task.identifies(1, self.tgid()))
                .filter_map(|task| {
                    task.proc_pid
                        .read()
                        .unwrap()
                        .clone()
                        .map(|pid| pid as Arc<dyn trames_vfs::ProcTask>)
                })
                .collect()
        })
    }
    fn memory_report(&self) -> Option<trames_memory::MemoryReport> {
        self.live()
            .then(|| self.proc_view.memory_report())
            .flatten()
    }
    fn observe(
        &self,
        demand: trames_vfs::ProcRefresh,
        residency: Option<usize>,
    ) -> Option<trames_vfs::ProcessInfo> {
        let pid = self.pid.load(Ordering::Relaxed);
        if !self.identifies(0, pid) {
            return None;
        }
        // Observe credential publication before mm dumpability; a committed
        // identity drop cannot be paired with the former dumpable state.
        let credentials = self.credentials().read().clone();
        let mut info = self.proc_view.observe_with_residency(demand, residency)?;
        info.credentials = credentials;
        info.identity = trames_vfs::ProcTask::identity(self);
        if info.pid != pid {
            return None;
        }
        info.tgid = self.tgid();
        info.group = self.group();
        info.session = self.session();
        if let Some(family) = self.family() {
            info.parent = family.parent();
        }
        if demand.content() {
            info.affinity = self.scheduling.affinity();
            info.nice = self.scheduling.nice();
            info.scheduler = self.scheduling.policy();
            info.pending = self.inbox.bits();
            info.shared_pending = self.process().bits();
            info.blocked = self.mask();
            if let Some(policy) = self.policy.read().unwrap().as_ref() {
                (info.ignored, info.caught) = policy.actions.masks();
            }
        }
        if !self.live() {
            info.state = 'Z';
            info.mapped_bytes = 0;
            info.virtual_bytes = 0;
            info.maps.clear();
            info.arguments.clear();
            info.environment.clear();
            info.executable.clear();
            info.executable_file = None;
            info.cwd_directory = None;
            info.root_directory = None;
        } else if self.lifecycle().stopped() {
            info.state = 'T';
        }
        if demand.content() {
            if let Some(limits) = self.proc_limits.get() {
                info.file_size_limits = Some(limits.get(1));
                info.core_limits = Some(limits.get(4));
                info.nofile_limits = Some(limits.get(7));
            }
            if let Some(cgroup) = self.cgroup() {
                info.cgroup = cgroup.path();
            }
        }
        Some(info)
    }
}
impl IoDirectory {
    pub fn proc_identity(&self, pid: u32) -> Option<Arc<dyn trames_vfs::ProcTask>> {
        let task = self.proc_task(pid)?;
        let pid = task.proc_pid.read().unwrap().clone()?;
        Some(pid)
    }
    pub fn proc_task(&self, pid: u32) -> Option<Arc<IoTask>> {
        self.tasks(0, pid).into_iter().next()
    }
    pub fn proc_tasks(&self) -> Vec<Arc<IoTask>> {
        let groups: Vec<_> = self
            .groups
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(&(kind, pid), group)| (kind == 0).then_some((pid, group.clone())))
            .collect();
        groups
            .into_iter()
            .filter_map(|(pid, group)| {
                group
                    .members
                    .read()
                    .unwrap()
                    .iter()
                    .filter_map(Weak::upgrade)
                    .find(|task| task.identifies(0, pid))
            })
            .collect()
    }
}
