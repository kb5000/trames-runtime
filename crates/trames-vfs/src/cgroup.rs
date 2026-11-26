// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-wide cgroup v2 domains, freezer and hierarchical pids controller.
//! Original shared hierarchy and task membership, independent of CPU custody.
use super::*;
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicU32},
        Mutex, Weak,
    },
};

mod controllers;
mod io;
mod memory_control;
pub(super) use memory_control::MemoryWrite;
#[cfg(test)]
mod lifetime_tests;
#[cfg(test)]
mod memory_control_tests;
pub use controllers::CpuShare;
use controllers::{CONTROLLERS, PIDS};
pub(crate) use io::{
    admit as admit_io, complete as complete_io, limited as io_limited, Context as IoContext,
    Permit as IoPermit, Scope as IoScope,
};

const ROOT: u64 = 5 << 32;
const UNLIMITED: u32 = i32::MAX as u32;
const MAX_GROUPS: usize = 128;
const MAX_DEPTH: usize = 32;
const PIDS_FILES: &[(&str, u32)] = &[
    ("pids.current", 0o444),
    ("pids.max", 0o644),
    ("pids.peak", 0o444),
    ("pids.events", 0o444),
    ("pids.events.local", 0o444),
];
const FILES: &[(&str, u32)] = &[
    ("cgroup.procs", 0o644),
    ("cgroup.threads", 0o444),
    ("cgroup.controllers", 0o444),
    ("cgroup.subtree_control", 0o644),
    ("cgroup.type", 0o444),
    ("cgroup.events", 0o444),
    ("cgroup.max.depth", 0o644),
    ("cgroup.max.descendants", 0o644),
    ("cgroup.stat", 0o444),
    ("cpu.stat", 0o444),
    ("cgroup.freeze", 0o644),
    ("cgroup.kill", 0o200),
];
const ALLOW_OVERRIDE: u32 = 1;
const ALLOW_MULTI: u32 = 2;
const REPLACE: u32 = 4;
const MAX_DEVICE_PROGRAMS: usize = 64;

struct DeviceRules {
    programs: Vec<Arc<bpf::Program>>,
    flags: u32,
    revision: u64,
}
impl Default for DeviceRules {
    fn default() -> Self {
        Self {
            programs: Vec::new(),
            flags: 0,
            revision: 1,
        }
    }
}
/// A single snapshot serves device opens, mknod and effective queries.
/// Hierarchy edits rebuild affected snapshots under the cgroup topology lock.
pub(super) struct DeviceAccess {
    effective: SharedCell<Arc<[Arc<bpf::Program>]>>,
}
impl DeviceAccess {
    pub(super) fn check(&self, mode: u32, rdev: u64, access: u32) -> Result<()> {
        let kind = match mode & 0o170000 {
            0o20000 => 2,
            0o60000 => 1,
            _ => return Ok(()),
        };
        let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xfffff000);
        let minor = (rdev & 0xff) | ((rdev >> 12) & 0xffffff00);
        let context = [kind | (access << 16), major as u32, minor as u32];
        if self.effective.borrow().iter().any(|p| !p.allows(context)) {
            return Err(Errno(1));
        }
        Ok(())
    }
}
// Immutable original ancestry survives rmdir while an unreaped task still
// describes its last group. Inode numbers distinguish same-name replacements.
struct GroupLocation {
    path: Vec<u8>,
    ancestors: Vec<u64>,
}
struct Group {
    device_rules: DeviceRules,
    devices: Arc<DeviceAccess>,
    location: Arc<GroupLocation>,
    parent: Option<u64>,
    freeze: bool,
    subtree: u8,
    cpu: controllers::CpuSettings,
    cpu_usage: u64,
    cpus: Option<u64>,
    mems: Option<u64>,
    memory: Option<Arc<trames_memory::MemoryCgroup>>,
    io: Option<Arc<io::Group>>,
    retired: Resources,
    max_depth: u32,
    max_descendants: u32,
    descendants: u32,
    pids_max: Option<u64>,
    pids_peak: u64,
    pids_events: u64,
    pids_events_local: u64,
    current: u64,
    frozen_tasks: u64,
    events: Arc<ControlEvents>,
    pids_signal: Arc<ControlEvents>,
    pids_local_signal: Arc<ControlEvents>,
    files: BTreeMap<Vec<u8>, Arc<ControlEvents>>,
}
struct Dying {
    id: u64,
    nodes: Vec<std::sync::Weak<Inode>>,
    ancestors: Vec<u64>,
    resources: Resources,
}
#[derive(Default)]
struct Resources {
    memory: Vec<Weak<trames_memory::MemoryCgroup>>,
    io: Vec<io::Reference>,
}
impl Resources {
    fn memory(&mut self, group: &Arc<trames_memory::MemoryCgroup>) {
        self.memory.retain(|group| group.strong_count() != 0);
        self.memory.push(Arc::downgrade(group));
    }
    fn io(&mut self, group: &io::Group) {
        self.io.retain(io::Reference::live);
        self.io.push(group.reference());
    }
    fn live(&self) -> bool {
        self.memory.iter().any(|group| group.strong_count() != 0)
            || self.io.iter().any(io::Reference::live)
    }
}
impl Dying {
    fn live(&self) -> bool {
        self.nodes.iter().any(|node| node.strong_count() != 0) || self.resources.live()
    }
}
pub(super) struct Cgroups {
    pub bpf: bpf::Registry,
    pub fs: FsHandle,
    pub nsdelegate: Arc<AtomicBool>,
    groups: BTreeMap<u64, Group>,
    tasks: BTreeMap<u32, Arc<Member>>, // original global TID incarnation
    dying: Vec<Dying>,
    kill: BTreeSet<u32>,
    weighted: Arc<AtomicBool>,
}
struct Member {
    pid: AtomicU32,
    tgid: AtomicU32,
    group: AtomicU64,
    exited: std::sync::OnceLock<Arc<GroupLocation>>,
    exit_readiness: std::sync::OnceLock<Arc<Readiness>>,
    oom: std::sync::OnceLock<Weak<OomTask>>,
    cpu_base: AtomicU64,
    cpus: AtomicU64,
    cpu_limited: AtomicBool,
    bandwidth: SharedCell<Arc<[Arc<controllers::CpuBandwidth>]>>,
    memory: Arc<trames_memory::CgroupMemoryTarget>,
    io: Arc<io::Target>,
    share: SharedCell<Arc<CpuShare>>,
    weighted: Arc<AtomicBool>,
    frozen: AtomicBool,
    acknowledged: AtomicBool,
    kill_pending: AtomicBool,
    wake: Mutex<Option<Weak<dyn TaskSignal>>>,
}
impl Member {
    fn oom_protected(&self) -> bool {
        self.oom
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|oom| oom.protected())
    }
    fn new(pid: u32, tgid: u32, group: u64, frozen: bool, weighted: Arc<AtomicBool>) -> Self {
        Self {
            pid: AtomicU32::new(pid),
            tgid: AtomicU32::new(tgid),
            group: AtomicU64::new(group),
            exited: Default::default(),
            exit_readiness: Default::default(),
            oom: Default::default(),
            cpu_base: AtomicU64::new(0),
            cpus: AtomicU64::new(u64::MAX),
            cpu_limited: AtomicBool::new(false),
            bandwidth: Default::default(),
            memory: Arc::default(),
            io: Arc::default(),
            share: Default::default(),
            weighted,
            frozen: AtomicBool::new(frozen),
            acknowledged: AtomicBool::new(frozen),
            kill_pending: AtomicBool::new(false),
            wake: Mutex::default(),
        }
    }
    fn tgid(&self) -> u32 {
        self.tgid.load(Ordering::Relaxed)
    }
    fn group(&self) -> u64 {
        self.group.load(Ordering::Relaxed)
    }
    fn cpu_clock(&self) -> u64 {
        self.wake
            .lock()
            .unwrap()
            .as_ref()
            .and_then(Weak::upgrade)
            .map_or(0, |task| {
                task.cpu_elapsed().as_nanos().min(u64::MAX as u128) as u64
            })
    }
    fn cpu_delta(&self) -> u64 {
        self.cpu_clock()
            .saturating_sub(self.cpu_base.load(Ordering::Relaxed))
    }
    fn notify(&self) {
        let target = self.wake.lock().unwrap().as_ref().and_then(Weak::upgrade);
        if let Some(target) = target {
            target.scheduling_changed();
        }
    }
}
/// Deferred notifications from the actual cgroup task-birth transaction.
pub struct CgroupBirth {
    result: Result<()>,
    events: Vec<Arc<ControlEvents>>,
}
impl CgroupBirth {
    pub fn result(&self) -> Result<()> {
        self.result
    }
    pub fn notify(self) {
        notify_events(self.events);
    }
}
/// One actual task's cgroup membership. Retaining it neither retains a PID nor
/// allows a late exit to remove a replacement that reused the numeric TID.
#[derive(Clone)]
pub struct CgroupTask {
    groups: Arc<SharedCell<Cgroups>>,
    member: Arc<Member>,
}
/// Existing execution slots bind both resources of this actual task. Captured
/// file work replaces these live bindings with its original accepted owners.
pub struct CgroupResourceScope {
    _memory: trames_memory::CgroupMemoryScope,
    _io: io::Scope,
}
/// Owned allocation/IO origins for work accepted outside the CPU worker scope.
/// Explicit native/root absence is restored just like a concrete guest owner.
#[derive(Clone, Default)]
pub struct CgroupResourceContext {
    memory: trames_memory::CgroupMemoryContext,
    io: io::Context,
}
impl CgroupResourceContext {
    pub fn capture() -> Self {
        Self {
            memory: trames_memory::CgroupMemoryContext::capture(),
            io: io::Context::capture(),
        }
    }
    pub fn enter(&self) -> CgroupResourceScope {
        CgroupResourceScope {
            _memory: self.memory.enter(),
            _io: self.io.enter(),
        }
    }
}
impl CgroupTask {
    pub fn bind_oom(&self, oom: &Arc<OomTask>) {
        let _ = self.member.oom.set(Arc::downgrade(oom));
    }
    pub(super) fn context_for(
        groups: &Arc<SharedCell<Cgroups>>,
        tid: u32,
    ) -> Option<CgroupResourceContext> {
        let groups = groups.borrow();
        let member = groups.tasks.get(&tid)?;
        let _memory = member.memory.scope();
        let _io = member.io.scope();
        Some(CgroupResourceContext::capture())
    }
    pub fn memory_controlled(&self) -> bool {
        self.member.memory.controlled()
    }
    pub fn memory_scope(&self) -> trames_memory::CgroupMemoryScope {
        self.member.memory.scope()
    }
    pub fn resource_scope(&self) -> CgroupResourceScope {
        CgroupResourceScope {
            _memory: self.member.memory.scope(),
            _io: self.member.io.scope(),
        }
    }
    pub fn resource_context(&self) -> CgroupResourceContext {
        // Acceptance snapshots the same membership update for both resources.
        // Ordinary live CPU scopes keep their existing per-target access.
        let _groups = self.groups.borrow();
        let _scope = self.resource_scope();
        CgroupResourceContext::capture()
    }

    pub fn cpu_share(&self) -> Option<Arc<CpuShare>> {
        self.member
            .weighted
            .load(Ordering::Relaxed)
            .then(|| self.member.share.borrow().clone())
    }
    pub fn resource_limited(&self) -> bool {
        self.member.cpu_limited.load(Ordering::Relaxed) || self.member.memory.above_high()
    }
    pub fn resource_deadline(
        &self,
        now: std::time::Instant,
        elapsed: std::time::Duration,
    ) -> Option<std::time::Instant> {
        let high = self.member.memory.high_delay();
        let deadline = (!high.is_zero()).then(|| now + high);
        if !self.member.cpu_limited.load(Ordering::Relaxed) {
            return deadline;
        }
        self.member
            .bandwidth
            .borrow()
            .iter()
            .filter_map(|bandwidth| bandwidth.charge(now, elapsed))
            .chain(deadline)
            .max()
    }
    pub fn cpus(&self) -> u64 {
        self.member.cpus.load(Ordering::Relaxed)
    }
    pub fn memory_oom(&self) -> bool {
        let Some((_, limit)) = self.member.memory.take_oom() else {
            return false;
        };
        let (kill_group, victims) = {
            let cg = self.groups.borrow();
            let eligible = |task: &&Arc<Member>| {
                !task.oom_protected()
                    && cg
                        .memory_at(task.group())
                        .is_some_and(|memory| memory.is_within(&limit))
                    && task
                        .wake
                        .lock()
                        .unwrap()
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .is_some()
            };
            let primary = cg
                .tasks
                .values()
                .filter(eligible)
                .find(|task| task.tgid() == self.member.tgid())
                .or_else(|| cg.tasks.values().find(eligible));
            let Some(primary) = primary else { return false };
            let memory = cg.memory_at(primary.group()).unwrap();
            let kill_group = memory.oom_group_within(&limit);
            let mut seen = BTreeSet::new();
            let victims = cg
                .tasks
                .values()
                .filter_map(|task| {
                    let memory = cg.memory_at(task.group())?;
                    let selected = task.tgid() == primary.tgid()
                        || kill_group
                            .as_ref()
                            .is_some_and(|group| memory.is_within(group));
                    if !selected
                        || !memory.is_within(&limit)
                        || task.oom_protected()
                        || !seen.insert(task.tgid())
                    {
                        return None;
                    }
                    let victim = task.wake.lock().unwrap().as_ref().and_then(Weak::upgrade)?;
                    Some((victim, memory))
                })
                .collect::<Vec<_>>();
            (kill_group, victims)
        };
        if let Some(group) = kill_group {
            group.record_group_kill();
        }
        let killed = !victims.is_empty();
        for (task, group) in victims {
            group.record_oom_kill();
            task.terminate_process();
        }
        killed
    }
    pub fn path_status(&self) -> (Vec<u8>, bool) {
        let cg = self.groups.borrow();
        let id = self.member.group();
        if let Some(group) = cg.groups.get(&id) {
            return (group.location.path.clone(), false);
        }
        self.member
            .exited
            .get()
            .map_or_else(|| (b"/".to_vec(), false), |last| (last.path.clone(), true))
    }
    pub fn pid(&self) -> u32 {
        self.member.pid.load(Ordering::Relaxed)
    }
    pub fn frozen(&self) -> bool {
        self.member.frozen.load(Ordering::Relaxed)
    }
    pub fn bind(&self, target: &Arc<dyn TaskSignal>) {
        let next = Arc::downgrade(target);
        {
            let mut wake = self.member.wake.lock().unwrap();
            if wake.as_ref().is_some_and(|old| old.ptr_eq(&next)) {
                return;
            }
            *wake = Some(next);
        }
        let (events, pending, frozen) = {
            let mut cg = self.groups.borrow_mut();
            let original = cg
                .tasks
                .get(&self.pid())
                .is_some_and(|m| Arc::ptr_eq(m, &self.member));
            let pending = original && self.member.kill_pending.load(Ordering::Relaxed);
            if pending {
                cg.kill.remove(&self.pid());
            }
            let frozen = self.frozen() && original;
            let events = if frozen {
                let ack = target.quiescent();
                let old = self.member.acknowledged.swap(ack, Ordering::Relaxed);
                let id = self.member.group();
                let before = cg.event_states(cg.ancestors(id));
                cg.adjust(id, 0, i64::from(ack) - i64::from(old));
                cg.changed_events(before)
            } else {
                Vec::new()
            };
            (events, pending, frozen)
        };
        if frozen {
            self.member.notify();
        }
        notify_events(events);
        if pending {
            target.terminate_process();
        }
    }
    pub fn exit(&self) {
        let events = {
            let mut cg = self.groups.borrow_mut();
            let pid = self.pid();
            if !cg
                .tasks
                .get(&pid)
                .is_some_and(|task| Arc::ptr_eq(task, &self.member))
            {
                return;
            }
            let id = self.member.group();
            let before = cg.event_states(cg.ancestors(id));
            self.member
                .exited
                .get_or_init(|| cg.groups[&id].location.clone());
            cg.settle_cpu(&self.member);
            cg.tasks.remove(&pid);
            cg.kill.remove(&pid);
            cg.adjust(
                id,
                -1,
                -i64::from(self.member.acknowledged.load(Ordering::Relaxed)),
            );
            cg.changed_events(before)
        };
        if let Some(readiness) = self.member.exit_readiness.get() {
            readiness.notify_atomic();
        }
        notify_events(events);
    }
    /// Called once the original executor/accepted work has relinquished this
    /// task. Pure frozen maintenance never retracts an existing acknowledgement.
    pub fn acknowledge(&self) {
        if !self.frozen() || self.member.acknowledged.load(Ordering::Relaxed) {
            return;
        }
        let events = {
            let mut cg = self.groups.borrow_mut();
            if !self.frozen()
                || self.member.acknowledged.load(Ordering::Relaxed)
                || !cg
                    .tasks
                    .get(&self.pid())
                    .is_some_and(|m| Arc::ptr_eq(m, &self.member))
            {
                return;
            }
            let target = self
                .member
                .wake
                .lock()
                .unwrap()
                .as_ref()
                .and_then(Weak::upgrade);
            if target.is_some_and(|t| !t.quiescent()) {
                return;
            }
            let id = self.member.group();
            let before = cg.event_states(cg.ancestors(id));
            self.member.acknowledged.store(true, Ordering::Relaxed);
            cg.adjust(id, 0, 1);
            cg.changed_events(before)
        };
        notify_events(events);
    }
}
/// PID lookup and the runtime's administration check use the task doing I/O.
/// Migration additionally checks the opener's credentials and cgroup namespace.
#[derive(Clone)]
pub(super) struct CgroupAccess {
    owner: (u32, u32),
    namespace: PidNamespace,
    pid: u32,
    admin: bool,
    cpus: usize,
}
impl CgroupAccess {
    fn visible_pid(&self, pid: u32) -> u32 {
        self.namespace.local(pid)
    }
    fn global_pid(&self, pid: u32) -> Result<u32> {
        self.namespace.global(pid).ok_or(Errno(3))
    }
}
struct ControlEvents {
    generation: AtomicU64,
    readiness: Arc<Readiness>,
    node: Weak<Inode>,
    memory_notifications: Option<inotify::LiveNotifications>,
}
impl trames_memory::CgroupMemoryEvents for ControlEvents {
    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        if let Some(notifications) = &self.memory_notifications {
            notifications.send(inotify::MODIFY);
        }
        self.readiness.notify_atomic();
    }
}
impl ControlEvents {
    fn changed(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        if let Some(node) = self.node.upgrade() {
            let deleted = node.borrow().links == 0;
            if deleted {
                inotify::notify_removed(&node);
            } else {
                let notifications = inotify::capture_node(&node.borrow());
                notifications.send(inotify::MODIFY);
            }
        }
        self.readiness.notify_locked();
    }
}
fn notify_events(events: Vec<Arc<ControlEvents>>) {
    for event in events {
        event.changed();
    }
}
pub(super) struct CgroupFile {
    namespace: Arc<linux_namespace::CgroupNamespace>,
    migration_credentials: Option<Credentials>,
    task_source: Option<Weak<dyn ProcSource>>,
    groups: Arc<SharedCell<Cgroups>>,
    node: NodeRef,
    id: u64,
    name: Vec<u8>,
    events: Arc<ControlEvents>,
    observed: AtomicU64,
}
#[derive(Clone)]
pub(super) enum DeviceAuthority {
    Group(Arc<DeviceAccess>),
    Task(CgroupTask),
}
impl DeviceAuthority {
    pub(super) fn check(&self, mode: u32, rdev: u64, access: u32) -> Result<()> {
        match self {
            Self::Group(group) => group.check(mode, rdev, access),
            Self::Task(task) => {
                let group = task
                    .groups
                    .borrow()
                    .groups
                    .get(&task.member.group())
                    .ok_or(Errno(19))?
                    .devices
                    .clone();
                group.check(mode, rdev, access)
            }
        }
    }
}
fn below(path: &[u8], root: &[u8]) -> bool {
    path == root || root == b"/" || path.starts_with(root) && path.get(root.len()) == Some(&b'/')
}
fn child_path(path: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = path.to_vec();
    if out != b"/" {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}
impl Default for Cgroups {
    fn default() -> Self {
        let weighted = Arc::new(AtomicBool::new(false));
        let mut out = Self {
            bpf: bpf::Registry::default(),
            nsdelegate: Arc::default(),
            fs: FsHandle::new(Filesystem {
                shared_budget: trames_shared::SharedBudget::new(memfd::MEMFD_BYTES as usize),
                paths: BTreeMap::new(),
                inodes: Vec::new(),
                next_inode: ROOT,
                limits: StorageLimits::memory(),
                disk: None,
                volume: None,
            }),
            groups: BTreeMap::new(),
            tasks: BTreeMap::from([(
                1,
                Arc::new(Member::new(1, 1, ROOT, false, weighted.clone())),
            )]),
            dying: Vec::new(),
            kill: BTreeSet::new(),
            weighted,
        };
        out.add_group(b"/".to_vec(), None, 0o755, (0, 0));
        out.tasks[&1].io.set(out.io_at(ROOT));
        out.publish_bandwidth(&out.tasks[&1]);
        out
    }
}
/// The directory stays pinned across clone setup, including close/reuse of the guest FD.
pub struct CgroupDestination {
    namespace: Arc<linux_namespace::CgroupNamespace>,
    node: NodeRef,
    caller: Credentials,
}
impl Cgroups {
    fn member_group(&self, pid: u32) -> u64 {
        self.tasks.get(&pid).map_or(ROOT, |task| task.group())
    }
    fn destination(&self, target: &CgroupDestination, source: u64, threaded: bool) -> Result<u64> {
        let id = target.node.borrow().inode;
        let dest = self.groups.get(&id).ok_or(Errno(2))?;
        let fs = self.fs.borrow();
        if !fs
            .paths
            .get(&dest.location.path)
            .is_some_and(|n| Arc::ptr_eq(n, &target.node))
        {
            return Err(Errno(2));
        }
        drop(fs);
        self.check_procs_write(id, &target.caller)?;
        self.check_migration(source, id, &target.caller, &target.namespace)?;
        if id != ROOT && dest.subtree != 0 {
            return Err(Errno(16));
        }
        if threaded && id != source {
            return Err(Errno(95));
        }
        Ok(id)
    }
    fn check_procs_write(&self, id: u64, credentials: &Credentials) -> Result<()> {
        let control = &self.groups[&id].files[b"cgroup.procs".as_slice()];
        let node = control.node.upgrade().ok_or(Errno(2))?;
        if !credentials.allows_node(&node.borrow(), 2) {
            return Err(Errno(13));
        }
        Ok(())
    }
    fn check_migration(
        &self,
        source: u64,
        dest: u64,
        credentials: &Credentials,
        namespace: &linux_namespace::CgroupNamespace,
    ) -> Result<()> {
        let mut common = source;
        while !below(
            &self.groups[&dest].location.path,
            &self.groups[&common].location.path,
        ) {
            common = self.groups[&common]
                .parent
                .expect("root contains every cgroup");
        }
        self.check_procs_write(common, credentials)?;
        // Containing the common ancestor is equivalent to containing both tasks'
        // groups. A removed namespace root must never match a recreated pathname.
        if let Some(root) = &namespace.root {
            if self.nsdelegate.load(Ordering::Relaxed) {
                let boundary = self.groups.get(&root.borrow().inode).ok_or(Errno(2))?;
                if !below(&self.groups[&common].location.path, &boundary.location.path) {
                    return Err(Errno(2));
                }
            }
        }
        Ok(())
    }
    fn check_fork(&mut self, pid: u32, id: u64) -> (Result<()>, Vec<Arc<ControlEvents>>) {
        if self
            .tasks
            .get(&pid)
            .is_some_and(|task| task.kill_pending.load(Ordering::Relaxed))
        {
            return (Err(Errno(4)), Vec::new());
        }
        for group in self.ancestors(id) {
            if !self.pids_enabled(group) {
                continue;
            }
            let count = self.current(group) + 1;
            if self.groups[&group]
                .pids_max
                .is_some_and(|limit| count > limit)
            {
                self.groups
                    .get_mut(&group)
                    .expect("group")
                    .pids_events_local += 1;
                let mut events = vec![self.groups[&group].pids_local_signal.clone()];
                for ancestor in self.ancestors(group) {
                    if self.pids_enabled(ancestor) {
                        self.groups
                            .get_mut(&ancestor)
                            .expect("ancestor")
                            .pids_events += 1;
                        events.push(self.groups[&ancestor].pids_signal.clone());
                    }
                }
                return (Err(Errno(11)), events);
            }
            let entry = self.groups.get_mut(&group).expect("group");
            entry.pids_peak = entry.pids_peak.max(count);
        }
        (Ok(()), Vec::new())
    }
    fn fork_member(
        &mut self,
        parent: u32,
        child: u32,
        tgid: u32,
        id: u64,
    ) -> Vec<Arc<ControlEvents>> {
        let before = self.event_states(self.ancestors(id));
        let frozen = self.frozen(id);
        let pending = self
            .tasks
            .get(&parent)
            .is_some_and(|task| task.kill_pending.load(Ordering::Relaxed));
        let member = Arc::new(Member::new(child, tgid, id, frozen, self.weighted.clone()));
        member.memory.set(self.memory_at(id));
        member.io.set(self.io_at(id));
        self.publish_bandwidth(&member);
        member
            .cpus
            .store(self.effective_cpus(id, u64::MAX), Ordering::Relaxed);
        member.kill_pending.store(pending, Ordering::Relaxed);
        assert!(self.tasks.insert(child, member).is_none());
        self.adjust(id, 1, i64::from(frozen));
        self.update_peak(id);
        self.changed_events(before)
    }

    fn add_node(&self, path: Vec<u8>, directory: bool, mode: u32, owner: (u32, u32)) -> u64 {
        let mut fs = self.fs.borrow_mut();
        let inode = fs.next_inode;
        fs.next_inode += 1;
        let node = Arc::new(Inode::new(Node {
            identity: 0,
            record_locks: std::sync::OnceLock::new(),
            whole_locks: std::sync::OnceLock::new(),
            notifications: inotify::Marks::default(),
            path_hint: SharedCell::default(),
            device: 5,
            content: if directory {
                Content::Directory
            } else {
                Content::File(storage::FileData::memory(Vec::new()))
            },
            mode: mode | if directory { 0o40000 } else { 0o100000 },
            uid: owner.0,
            gid: owner.1,
            volatile: true,
            inode,
            links: 1,
            times: [storage::Timestamp::now(); 3],
            xattrs: BTreeMap::new(),
            seals: None,
        }));
        fs.track_inode(&node)
            .expect("non-file inode has no byte charge");
        fs.paths.insert(path, node);
        inode
    }
    fn add_group(&mut self, path: Vec<u8>, parent: Option<u64>, mode: u32, owner: (u32, u32)) {
        let id = self.add_node(path.clone(), true, mode, owner);
        let mut ancestors = vec![id];
        if let Some(parent) = parent {
            ancestors.extend_from_slice(&self.groups[&parent].location.ancestors);
        }
        let mut files = BTreeMap::new();
        for (name, mode) in FILES {
            // These controls apply only below the root cgroup.
            if parent.is_none()
                && matches!(
                    *name,
                    "cgroup.type" | "cgroup.events" | "cgroup.freeze" | "cgroup.kill"
                )
            {
                continue;
            }
            self.add_node(child_path(&path, name.as_bytes()), false, *mode, owner);
            files.insert(
                name.as_bytes().to_vec(),
                self.file_events(&path, name.as_bytes()),
            );
        }
        let events = files
            .get(b"cgroup.events".as_slice())
            .cloned()
            .unwrap_or_else(|| self.file_events(&path, b"cgroup.events"));
        self.groups.insert(
            id,
            Group {
                device_rules: DeviceRules::default(),
                devices: Arc::new(DeviceAccess {
                    effective: SharedCell::new(
                        parent
                            .map(|id| self.groups[&id].devices.effective.borrow().clone())
                            .unwrap_or_default(),
                    ),
                }),
                location: Arc::new(GroupLocation {
                    path: path.clone(),
                    ancestors,
                }),
                parent,
                freeze: false,
                subtree: 0,
                cpu: controllers::CpuSettings::default(),
                cpu_usage: 0,
                cpus: None,
                mems: None,
                memory: None,
                io: parent.is_none().then(|| io::Group::new(None)),
                retired: Resources::default(),
                max_depth: UNLIMITED,
                max_descendants: UNLIMITED,
                descendants: 0,
                pids_max: None,
                pids_peak: 0,
                pids_events: 0,
                pids_events_local: 0,
                current: if id == ROOT { 1 } else { 0 },
                frozen_tasks: 0,
                events,
                files,
                pids_signal: self.file_events(&path, b"pids.events"),
                pids_local_signal: self.file_events(&path, b"pids.events.local"),
            },
        );
        if parent.is_none() {
            // Root has accounting, while per-device limits are owned by the
            // parent and therefore exist only in non-root controller domains.
            let _ = self.install_files(id, &[("io.stat", 0o444)], true, owner);
        }
        if parent.is_some() {
            let available = self.available_controllers(id);
            for (_, bit) in CONTROLLERS {
                if available & bit != 0 {
                    let _ = self.install_controller(id, bit, true, owner);
                }
            }
        }
    }
    fn pids_enabled(&self, id: u64) -> bool {
        self.groups[&id]
            .parent
            .is_some_and(|parent| self.groups[&parent].subtree & PIDS != 0)
    }
    fn current(&self, id: u64) -> u64 {
        self.groups[&id].current
    }
    fn event_key(&self, id: u64) -> (bool, bool) {
        let group = &self.groups[&id];
        (
            group.current != 0,
            self.frozen(id) && group.current == group.frozen_tasks,
        )
    }
    fn event_states(&self, ids: impl IntoIterator<Item = u64>) -> BTreeMap<u64, (bool, bool)> {
        ids.into_iter().map(|id| (id, self.event_key(id))).collect()
    }
    fn changed_events(&self, before: BTreeMap<u64, (bool, bool)>) -> Vec<Arc<ControlEvents>> {
        before
            .into_iter()
            .filter_map(|(id, old)| {
                self.groups
                    .get(&id)
                    .and_then(|g| (self.event_key(id) != old).then(|| g.events.clone()))
            })
            .collect()
    }
    fn adjust(&mut self, id: u64, delta: i64, frozen: i64) {
        for id in self.ancestors(id) {
            let group = self.groups.get_mut(&id).unwrap();
            group.current = group.current.wrapping_add_signed(delta);
            group.frozen_tasks = group.frozen_tasks.wrapping_add_signed(frozen);
        }
    }
    fn file_events(&self, path: &[u8], name: &[u8]) -> Arc<ControlEvents> {
        let node = self.fs.borrow().paths.get(&child_path(path, name)).cloned();
        Arc::new(ControlEvents {
            generation: AtomicU64::new(1),
            readiness: Arc::default(),
            node: node.as_ref().map_or_else(Weak::new, Arc::downgrade),
            memory_notifications: matches!(name, b"memory.events" | b"memory.events.local")
                .then(|| {
                    node.as_ref()
                        .map(|node| inotify::LiveNotifications::capture(&node.borrow()))
                })
                .flatten(),
        })
    }
    fn update_peak(&mut self, id: u64) {
        for group in self.ancestors(id) {
            let count = self.current(group);
            if self.pids_enabled(group) {
                let entry = self.groups.get_mut(&group).expect("ancestor");
                entry.pids_peak = entry.pids_peak.max(count);
            }
        }
    }
    fn install_files(
        &mut self,
        id: u64,
        files: &[(&str, u32)],
        enable: bool,
        owner: (u32, u32),
    ) -> (Vec<Arc<ControlEvents>>, Vec<NodeRef>) {
        let mut events = Vec::new();
        let mut nodes = Vec::new();
        for (name, mode) in files {
            let path = child_path(&self.groups[&id].location.path, name.as_bytes());
            if enable {
                self.add_node(path, false, *mode, owner);
                let event = self.file_events(&self.groups[&id].location.path, name.as_bytes());
                self.groups
                    .get_mut(&id)
                    .unwrap()
                    .files
                    .insert(name.as_bytes().to_vec(), event);
            } else {
                if let Some(event) = self
                    .groups
                    .get_mut(&id)
                    .unwrap()
                    .files
                    .remove(name.as_bytes())
                {
                    events.push(event);
                }
                if let Some(node) = self.fs.borrow_mut().paths.remove(&path) {
                    node.borrow_mut().links = 0;
                    nodes.push(node);
                }
            }
        }
        (events, nodes)
    }
    fn install_pids(
        &mut self,
        id: u64,
        enable: bool,
        owner: (u32, u32),
    ) -> (Vec<Arc<ControlEvents>>, Vec<NodeRef>) {
        let (events, nodes) = self.install_files(id, PIDS_FILES, enable, owner);
        let path = self.groups[&id].location.path.clone();
        let signal = self.groups[&id]
            .files
            .get(b"pids.events".as_slice())
            .cloned()
            .unwrap_or_else(|| self.file_events(&path, b"pids.events"));
        let local = self.groups[&id]
            .files
            .get(b"pids.events.local".as_slice())
            .cloned()
            .unwrap_or_else(|| self.file_events(&path, b"pids.events.local"));
        let current = self.current(id);
        let group = self.groups.get_mut(&id).expect("group");
        group.pids_signal = signal;
        group.pids_local_signal = local;
        group.pids_max = None;
        group.pids_peak = current;
        group.pids_events = 0;
        group.pids_events_local = 0;
        (events, nodes)
    }
    fn frozen(&self, mut id: u64) -> bool {
        loop {
            let group = &self.groups[&id];
            if group.freeze {
                return true;
            }
            let Some(parent) = group.parent else {
                return false;
            };
            id = parent;
        }
    }
    fn ancestors(&self, id: u64) -> Vec<u64> {
        self.groups[&id].location.ancestors.clone()
    }
    fn refresh_device_filters(&self, changed: u64) {
        for group in self
            .groups
            .values()
            .filter(|g| g.location.ancestors.contains(&changed))
        {
            let mut effective = Vec::new();
            for id in &group.location.ancestors {
                let rules = &self.groups[id].device_rules;
                if effective.is_empty() || rules.flags == ALLOW_MULTI {
                    effective.extend(rules.programs.iter().cloned());
                }
            }
            *group.devices.effective.borrow_mut() = effective.into();
        }
    }
    fn retained_dying(&self) -> BTreeSet<u64> {
        // A removed descendant still pins its original parents, even after
        // those parents lose their own control-file and resource references.
        self.dying
            .iter()
            .filter(|group| group.live())
            .flat_map(|group| std::iter::once(group.id).chain(group.ancestors.iter().copied()))
            .collect()
    }
    fn prune(&mut self) {
        let retained = self.retained_dying();
        self.dying.retain(|group| retained.contains(&group.id));
        self.fs
            .borrow_mut()
            .inodes
            .retain(|n| n.strong_count() != 0);
    }
}
impl DescriptorFactory {
    fn bpf_group(&self, fd: u32) -> Result<u64> {
        let file = self.files.lookup(fd).ok_or(Errno(9))??;
        let open = &file.open;
        if !open
            .mount_resource
            .get()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
        {
            return Err(Errno(9));
        }
        let (id, linked) = {
            let node = open.node.as_ref().ok_or(Errno(9))?.borrow();
            if !matches!(node.content, Content::Directory) {
                return Err(Errno(9));
            }
            (node.inode, node.links != 0)
        };
        if !linked {
            return Err(Errno(19));
        }
        Ok(id)
    }
    pub fn bpf_attach_device(
        &self,
        target: u32,
        program: u32,
        flags: u32,
        replace: u32,
    ) -> Result<()> {
        self.bpf_attach_device_at_revision(target, program, flags, replace, 0)
    }
    pub fn bpf_attach_device_at_revision(
        &self,
        target: u32,
        program: u32,
        flags: u32,
        replace: u32,
        revision: u64,
    ) -> Result<()> {
        // Linux delegates attachment through the two original guest descriptors.
        // Creating a verified program or acquiring its descriptor by ID stays privileged.
        let mode = flags & !REPLACE;
        if !matches!(mode, 0 | ALLOW_OVERRIDE | ALLOW_MULTI)
            || flags & REPLACE != 0 && mode != ALLOW_MULTI
        {
            return Err(Errno(22));
        }
        let id = self.bpf_group(target)?;
        let program = self.bpf_program(program)?;
        if program.kind != 15 {
            return Err(Errno(22));
        }
        let replace = if flags & REPLACE != 0 {
            Some(self.bpf_program(replace)?)
        } else {
            None
        };
        let mut cg = self.cgroups.borrow_mut();
        let group = cg.groups.get(&id).ok_or(Errno(19))?;
        if revision != 0 && revision != group.device_rules.revision {
            return Err(Errno(116));
        }
        if group
            .location
            .ancestors
            .iter()
            .skip(1)
            .map(|a| &cg.groups[a].device_rules)
            .find(|r| !r.programs.is_empty())
            .is_some_and(|r| r.flags == 0)
        {
            return Err(Errno(1));
        }
        if mode == 0
            && cg.groups.iter().any(|(other, g)| {
                *other != id
                    && g.location.ancestors.contains(&id)
                    && !g.device_rules.programs.is_empty()
            })
        {
            return Err(Errno(1));
        }
        let rules = &mut cg.groups.get_mut(&id).unwrap().device_rules;
        if !rules.programs.is_empty() && rules.flags != mode {
            return Err(Errno(1));
        }
        if mode != ALLOW_MULTI {
            rules.programs.clear();
            rules.programs.push(program);
        } else {
            if rules.programs.iter().any(|p| p.id == program.id)
                && !replace.as_ref().is_some_and(|old| old.id == program.id)
            {
                return Err(Errno(22));
            }
            if let Some(old) = replace {
                let slot = rules
                    .programs
                    .iter_mut()
                    .find(|p| p.id == old.id)
                    .ok_or(Errno(2))?;
                *slot = program;
            } else {
                if rules.programs.len() >= MAX_DEVICE_PROGRAMS {
                    return Err(Errno(7));
                }
                rules.programs.push(program);
            }
        }
        rules.flags = mode;
        rules.revision = rules.revision.wrapping_add(1);
        cg.refresh_device_filters(id);
        Ok(())
    }
    pub fn bpf_detach_device(&self, target: u32, program: u32) -> Result<()> {
        self.bpf_detach_device_at_revision(target, program, 0)
    }
    pub fn bpf_detach_device_at_revision(
        &self,
        target: u32,
        program: u32,
        revision: u64,
    ) -> Result<()> {
        self.bpf_authorized()?;
        let id = self.bpf_group(target)?;
        let program = self.bpf_program(program)?;
        let mut cg = self.cgroups.borrow_mut();
        let rules = &mut cg.groups.get_mut(&id).ok_or(Errno(19))?.device_rules;
        if revision != 0 && revision != rules.revision {
            return Err(Errno(116));
        }
        let index = rules
            .programs
            .iter()
            .position(|p| p.id == program.id)
            .ok_or(Errno(2))?;
        rules.programs.remove(index);
        rules.revision = rules.revision.wrapping_add(1);
        if rules.programs.is_empty() {
            rules.flags = 0;
        }
        cg.refresh_device_filters(id);
        Ok(())
    }
    pub fn bpf_query_device(&self, target: u32, effective: bool) -> Result<(u32, Vec<u32>)> {
        self.bpf_query_cgroup(target, 6, effective)
            .map(|(flags, ids, _)| (flags, ids))
    }
    pub fn bpf_query_cgroup(
        &self,
        target: u32,
        hook: u32,
        effective: bool,
    ) -> Result<(u32, Vec<u32>, u64)> {
        self.bpf_authorized()?;
        let id = self.bpf_group(target)?;
        let cg = self.cgroups.borrow();
        let group = cg.groups.get(&id).ok_or(Errno(19))?;
        match hook {
            // The ingress/egress slots have no attached packet programs.
            0 | 1 => Ok((0, Vec::new(), u64::from(!effective))),
            6 if effective => Ok((
                0,
                group
                    .devices
                    .effective
                    .borrow()
                    .iter()
                    .map(|p| p.id)
                    .collect(),
                0,
            )),
            6 => Ok((
                group.device_rules.flags,
                group.device_rules.programs.iter().map(|p| p.id).collect(),
                group.device_rules.revision,
            )),
            _ => Err(Errno(22)),
        }
    }
}
impl Vfs {
    pub fn bpf_attach_device(
        &self,
        target: u32,
        program: u32,
        flags: u32,
        replace: u32,
    ) -> Result<()> {
        self.descriptor_factory()
            .bpf_attach_device(target, program, flags, replace)
    }
    pub fn bpf_detach_device(&self, target: u32, program: u32) -> Result<()> {
        self.descriptor_factory().bpf_detach_device(target, program)
    }
    pub fn bpf_query_device(&self, target: u32, effective: bool) -> Result<(u32, Vec<u32>)> {
        self.descriptor_factory()
            .bpf_query_device(target, effective)
    }
    pub(super) fn device_access(&self) -> DeviceAuthority {
        if let Some(query) = &self.query {
            return query.devices.clone();
        }
        if let Some(task) = self.cgroup_task(self.pid) {
            return DeviceAuthority::Task(task);
        }
        DeviceAuthority::Group(self.cgroups.borrow().groups[&ROOT].devices.clone())
    }
    pub(super) fn cgroup_device(&self, mode: u32, rdev: u64, access: u32) -> Result<()> {
        self.device_access().check(mode, rdev, access)
    }
    pub(super) fn check_device_open(&self, node: &Node, flags: u32) -> Result<()> {
        if flags & O_PATH != 0 {
            return Ok(());
        }
        let rdev = match node.content {
            Content::Null => 0x103,
            Content::Terminal => 0x500,
            Content::Device(d) => d.rdev(),
            _ => return Ok(()),
        };
        self.cgroup_device(
            node.mode,
            rdev,
            match flags & 3 {
                0 => 2,
                1 => 4,
                _ => 6,
            },
        )
    }
    /// Called before clone commits IDs/TID stores. All workers have joined;
    /// the following membership insertion cannot race another charge.
    pub fn cgroup_can_fork(&self, pid: u32) -> Result<()> {
        let (result, events) = {
            let mut cg = self.cgroups.borrow_mut();
            let id = cg.member_group(pid);
            cg.check_fork(pid, id)
        };
        notify_events(events);
        result
    }
    pub(super) fn cgroup_v1_conflicts(&self, data: &[u8]) -> bool {
        let active = self.cgroups.borrow().available_controllers(ROOT);
        data.split(|&item| item == b',').any(|option| {
            option == b"blkio" && active & controllers::IO != 0
                || CONTROLLERS
                    .iter()
                    .any(|(name, bit)| option == name.as_bytes() && active & bit != 0)
        })
    }

    pub(super) fn cgroup_subsystems(&self) -> Vec<u8> {
        format!(
            "#subsys_name\thierarchy\tnum_cgroups\tenabled\npids\t0\t{}\t1\n",
            self.cgroups.borrow().groups.len()
        )
        .into_bytes()
    }
    /// Evaluated only at joined scheduler boundaries, never on CPU workers.
    /// Freeze does not overwrite signal stops or the task's blocked syscall.
    pub fn cgroup_frozen(&self, pid: u32) -> bool {
        let cg = self.cgroups.borrow();
        cg.tasks
            .get(&pid)
            .is_some_and(|task| task.frozen.load(Ordering::Relaxed))
    }
    /// Unbound original tasks await binding; source-bound tasks receive the
    /// request directly. Pending state follows the original membership object.
    pub fn take_cgroup_kills(&self) -> BTreeSet<u32> {
        std::mem::take(&mut self.cgroups.borrow_mut().kill)
    }
    pub(super) fn cgroup_mount(path: &ResolvedPath) -> bool {
        path.mount
            .as_ref()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
    }
    pub(super) fn cgroup_mkdir(&self, path: &ResolvedPath, mode: u32) -> Result<()> {
        path.writable()?;
        let parent = self.node(&path.parent())?;
        if !self.allowed(&parent.borrow(), 3) {
            return Err(Errno(13));
        }
        let id = parent.borrow().inode;
        let mut cg = self.cgroups.borrow_mut();
        cg.prune();
        if cg.fs.borrow().paths.contains_key(&path.key) {
            return Err(Errno(17));
        }
        if !cg.groups.contains_key(&id) {
            return Err(Errno(19));
        }
        if path
            .key
            .rsplit(|&b| b == b'/')
            .next()
            .unwrap_or_default()
            .contains(&b'\n')
        {
            return Err(Errno(22));
        }
        let ancestors = cg.ancestors(id);
        if ancestors.iter().enumerate().any(|(depth, ancestor)| {
            let group = &cg.groups[ancestor];
            depth >= group.max_depth as usize || group.descendants >= group.max_descendants
        }) {
            return Err(Errno(11));
        }
        if cg.groups.len() + cg.dying.len() >= MAX_GROUPS || ancestors.len() > MAX_DEPTH {
            return Err(Errno(28));
        }
        cg.add_group(
            path.key.clone(),
            Some(id),
            mode & 0o777 & !self.umask(),
            (self.credentials.fsuid, self.credentials.fsgid),
        );
        for ancestor in ancestors {
            cg.groups.get_mut(&ancestor).unwrap().descendants += 1;
        }
        Ok(())
    }
    pub(super) fn cgroup_rmdir(&self, path: &ResolvedPath) -> Result<()> {
        path.writable()?;
        if !self.allowed(&self.node(&path.parent())?.borrow(), 3) {
            return Err(Errno(13));
        }
        let node = self.node(path)?;
        let id = node.borrow().inode;
        let mut cg = self.cgroups.borrow_mut();
        if !cg.groups.contains_key(&id) {
            return Err(Errno(1));
        }
        if id == ROOT {
            return Err(Errno(16));
        }
        if cg.groups[&id].descendants != 0 {
            return Err(Errno(16));
        }
        if cg.tasks.values().any(|task| task.group() == id) {
            return Err(Errno(16));
        }
        let ancestors = cg.ancestors(id)[1..].to_vec();
        // A leaf and its control files are the only directory entries to retire.
        // Start at the slash so similarly named siblings do not enter the range.
        let prefix = child_path(&path.key, b"");
        let mut removed = vec![path.key.clone()];
        removed.extend(
            cg.fs
                .borrow()
                .paths
                .range(prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&prefix))
                .map(|(key, _)| key.clone()),
        );
        let mut nodes = Vec::new();
        let events = cg.groups[&id].files.values().cloned().collect();
        let mut removed_nodes = Vec::new();
        for key in removed {
            let node = cg.fs.borrow_mut().paths.remove(&key).expect("cgroup inode");
            node.borrow_mut().links = 0;
            nodes.push(Arc::downgrade(&node));
            removed_nodes.push(node);
        }
        let mut group = cg.groups.remove(&id).expect("original cgroup");
        if let Some(memory) = group.memory.take() {
            group.retired.memory(&memory);
        }
        let io = group.io.take();
        if let Some(io) = &io {
            group.retired.io(io);
            io.retire_state();
        }
        for ancestor in &ancestors {
            cg.groups.get_mut(ancestor).unwrap().descendants -= 1;
        }
        cg.dying.push(Dying {
            id,
            nodes,
            ancestors,
            resources: group.retired,
        });
        cg.prune();
        drop(cg);
        if let Some(io) = io {
            io.notify();
        }
        notify_events(events);
        for node in removed_nodes {
            inotify::notify_removed(&node);
        }
        Ok(())
    }
    /// Compatibility setup for an already admitted task. Production birth
    /// validates limits and commits membership in cgroup_birth instead.
    pub fn cgroup_fork(&self, parent: u32, child: u32, tgid: u32) {
        let events = {
            let mut cg = self.cgroups.borrow_mut();
            let id = cg.member_group(parent);
            cg.fork_member(parent, child, tgid, id)
        };
        notify_events(events);
    }
    /// One original membership/limit transaction; notifications are published
    /// only after the caller releases its family publication lock.
    pub fn cgroup_birth(&self, parent: u32, child: u32, tgid: u32) -> CgroupBirth {
        let mut cg = self.cgroups.borrow_mut();
        let id = cg.member_group(parent);
        let (result, mut events) = cg.check_fork(parent, id);
        if result.is_ok() {
            events.extend(cg.fork_member(parent, child, tgid, id));
        }
        CgroupBirth { result, events }
    }
    pub(super) fn cgroup_root_for_namespace(
        &self,
        target: Option<&CgroupDestination>,
    ) -> Result<(Vec<u8>, NodeRef)> {
        let cg = self.cgroups.borrow();
        let id = target.map_or_else(
            || cg.member_group(self.pid),
            |target| target.node.borrow().inode,
        );
        let path = cg.groups.get(&id).ok_or(Errno(2))?.location.path.clone();
        let root = cg.fs.borrow().paths[&path].clone();
        if target.is_some_and(|t| !Arc::ptr_eq(&t.node, &root)) {
            return Err(Errno(2));
        }
        Ok((path, root))
    }
    pub fn clone_cgroup_destination(&self, fd: u32) -> Result<CgroupDestination> {
        let d = self.descriptor(fd)?;
        let open = d.open.borrow();
        if !open
            .mount
            .as_ref()
            .is_some_and(|m| m.kind == mounts::Kind::Cgroup)
        {
            return Err(Errno(9));
        }
        let node = open.node.as_ref().ok_or(Errno(9))?;
        if !matches!(node.borrow().content, Content::Directory) {
            return Err(Errno(9));
        }
        Ok(CgroupDestination {
            namespace: self.cgroup_namespace.clone(),
            node: node.clone(),
            caller: self.credentials.clone(),
        })
    }
    /// Task construction commits PID allocation and cgroup membership together.
    /// In particular, a rejected first child must leave namespace PID 1 free.
    /// Lock order is cgroup -> ancestor PID maps, matching cgroup PID queries;
    /// task/family publication and notifications happen after these guards drop.
    pub fn activate_child_birth(&mut self, parent: u32, child: u32, tgid: u32) -> CgroupBirth {
        self.activate_child_birth_into(parent, child, tgid, None)
    }
    pub fn activate_child_birth_into(
        &mut self,
        parent: u32,
        child: u32,
        tgid: u32,
        target: Option<&CgroupDestination>,
    ) -> CgroupBirth {
        let mut cg = self.cgroups.borrow_mut();
        let mut events = Vec::new();
        let identity = self.pid_children.allocate_with(child, || {
            let source = cg.member_group(parent);
            let id = match target {
                Some(target) => cg.destination(target, source, child != tgid)?,
                None => source,
            };
            let (result, changes) = cg.check_fork(parent, id);
            events.extend(changes);
            result?;
            events.extend(cg.fork_member(parent, child, tgid, id));
            Ok(())
        });
        drop(cg);
        let result = identity.map(|identity| {
            self.pid_identity = identity;
            self.pid_ns = self.pid_children.clone();
        });
        CgroupBirth { result, events }
    }
    pub fn cgroup_task(&self, pid: u32) -> Option<CgroupTask> {
        let member = self.cgroups.borrow().tasks.get(&pid)?.clone();
        Some(CgroupTask {
            groups: self.cgroups.clone(),
            member,
        })
    }
    pub fn cgroup_exit(&self, pid: u32) {
        if let Some(task) = self.cgroup_task(pid) {
            task.exit();
        }
    }
    pub fn cgroup_exec_rekey(&self, old: u32, new: u32) {
        let mut cg = self.cgroups.borrow_mut();
        if let Some(task) = cg.tasks.remove(&old) {
            task.pid.store(new, Ordering::Relaxed);
            task.tgid.store(new, Ordering::Relaxed);
            cg.tasks.insert(new, task);
        }
    }
    pub fn cgroup_path(&self, pid: u32) -> Vec<u8> {
        let cg = self.cgroups.borrow();
        let id = cg.tasks.get(&pid).map_or(ROOT, |task| task.group());
        cg.groups
            .get(&id)
            .map_or_else(|| b"/".to_vec(), |g| g.location.path.clone())
    }
    // Open descriptions retain inode identity: deletion/recreation at the same
    // path must never redirect an old control FD to a new group.
    pub(super) fn cgroup_access(&self) -> CgroupAccess {
        CgroupAccess {
            owner: (self.credentials.fsuid, self.credentials.fsgid),
            namespace: self.pid_ns.clone(),
            pid: self.pid,
            admin: self.credentials.has_cap(capabilities::SYS_ADMIN),
            cpus: self.pseudo.borrow().runtime.cpu_count,
        }
    }
    pub(super) fn cgroup_file(
        &self,
        path: &ResolvedPath,
        node: &NodeRef,
    ) -> Result<Option<Arc<CgroupFile>>> {
        if !Self::cgroup_mount(path) || matches!(node.borrow().content, Content::Directory) {
            return Ok(None);
        }
        let split = path.key.iter().rposition(|b| *b == b'/').ok_or(Errno(19))?;
        let cg = self.cgroups.borrow();
        let fs = cg.fs.borrow();
        let parent = fs.paths.get(&path.key[..split.max(1)]).ok_or(Errno(19))?;
        let id = parent.borrow().inode;
        if !cg.groups.contains_key(&id) {
            return Err(Errno(19));
        }
        Ok(Some(Arc::new(CgroupFile {
            namespace: self.cgroup_namespace.clone(),
            task_source: (path.key[split + 1..] == *b"cgroup.procs")
                .then(|| self.pseudo.borrow().source.as_ref().map(Arc::downgrade))
                .flatten(),
            migration_credentials: (path.key[split + 1..] == *b"cgroup.procs")
                .then(|| self.credentials.clone()),
            groups: self.cgroups.clone(),
            node: node.clone(),
            id,
            name: path.key[split + 1..].to_vec(),
            events: cg.groups[&id]
                .files
                .get(&path.key[split + 1..])
                .cloned()
                .ok_or(Errno(19))?,
            observed: AtomicU64::new(0),
        })))
    }
    pub(super) fn cgroup_read(
        &self,
        o: &OpenDescription,
        offset: u64,
        count: usize,
    ) -> Result<Option<Vec<u8>>> {
        match &o.control {
            Some(events::SharedControl::Cgroup(file)) => {
                file.cgroup_read(&self.cgroup_access(), offset, count)
            }
            _ => Ok(None),
        }
    }
}
impl CgroupFile {
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.events.readiness.subscribe(signal)
    }
    pub(super) fn poll(&self, events: u16) -> (u16, [u64; 2]) {
        let generation = self.events.generation.load(Ordering::Relaxed);
        let changed =
            generation != self.observed.load(Ordering::Relaxed) || self.node.borrow().links == 0;
        (
            (events & 0x145) | if changed { 8 | (events & 2) } else { 0 },
            [generation, 0],
        )
    }
    fn check_live(&self, cg: &Cgroups) -> Result<()> {
        if !cg.groups.contains_key(&self.id) || self.node.borrow().links == 0 {
            Err(Errno(19))
        } else {
            Ok(())
        }
    }
    pub(super) fn cgroup_read(
        &self,
        caller: &CgroupAccess,
        offset: u64,
        count: usize,
    ) -> Result<Option<Vec<u8>>> {
        let id = self.id;
        let name = &self.name;
        let cg = self.groups.borrow();
        self.check_live(&cg)?;
        if count != 0 {
            self.observed.store(
                self.events.generation.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
        let group = cg.groups.get(&id).ok_or(Errno(19))?;
        let text = match name.as_slice() {
            b"io.max" => group.io.as_ref().ok_or(Errno(19))?.format_max(),
            b"io.stat" => group.io.as_ref().ok_or(Errno(19))?.format_stat(),
            b"cgroup.procs" | b"cgroup.threads" => {
                let ids: BTreeSet<_> = cg
                    .tasks
                    .iter()
                    .filter(|(_, task)| task.group() == id)
                    .map(|(tid, task)| {
                        caller.visible_pid(if name == b"cgroup.procs" {
                            task.tgid()
                        } else {
                            *tid
                        })
                    })
                    .filter(|id| *id != 0)
                    .collect();
                ids.iter().map(|id| format!("{id}\n")).collect::<String>()
            }
            b"cgroup.controllers" => controllers::list(cg.available_controllers(id)),
            b"cgroup.subtree_control" => controllers::list(group.subtree),
            b"cpu.stat" => {
                let usage = cg.cpu_usage(id) / 1_000;
                format!("usage_usec {usage}\nuser_usec {usage}\nsystem_usec 0\n")
            }
            b"cpu.max" => format!(
                "{} {}\n",
                group
                    .cpu
                    .quota
                    .map_or_else(|| "max".to_owned(), |n| n.to_string()),
                group.cpu.period
            ),
            b"cpu.weight" => format!("{}\n", group.cpu.weight),
            b"cpuset.cpus" => controllers::format_mask(group.cpus.unwrap_or(0)),
            b"cpuset.cpus.effective" => controllers::format_mask(
                cg.effective_cpus(id, controllers::possible_cpus(caller.cpus)),
            ),
            b"cpuset.mems" => controllers::format_mask(group.mems.unwrap_or(0)),
            b"cpuset.mems.effective" => "0\n".to_owned(),
            b"memory.current" => format!("{}\n", group.memory.as_ref().ok_or(Errno(19))?.current()),
            b"memory.stat" => group.memory.as_ref().ok_or(Errno(19))?.format_stat(),
            b"memory.max" => {
                controllers::limit_text(group.memory.as_ref().ok_or(Errno(19))?.limit())
            }
            b"memory.high" => {
                controllers::limit_text(group.memory.as_ref().ok_or(Errno(19))?.high())
            }
            b"memory.oom.group" => format!(
                "{}\n",
                u8::from(group.memory.as_ref().ok_or(Errno(19))?.oom_group())
            ),
            b"memory.events" | b"memory.events.local" => group
                .memory
                .as_ref()
                .ok_or(Errno(19))?
                .format_events(name == b"memory.events.local"),
            b"cgroup.max.depth" | b"cgroup.max.descendants" => {
                let limit = if name == b"cgroup.max.depth" {
                    group.max_depth
                } else {
                    group.max_descendants
                };
                if limit == UNLIMITED {
                    "max\n".to_owned()
                } else {
                    format!("{limit}\n")
                }
            }
            b"pids.current" => format!("{}\n", cg.current(id)),
            b"pids.peak" => format!("{}\n", cg.groups.get(&id).ok_or(Errno(19))?.pids_peak),
            b"pids.max" => cg
                .groups
                .get(&id)
                .ok_or(Errno(19))?
                .pids_max
                .map_or_else(|| "max\n".to_owned(), |n| format!("{n}\n")),
            b"pids.events" => format!("max {}\n", cg.groups.get(&id).ok_or(Errno(19))?.pids_events),
            b"pids.events.local" => format!(
                "max {}\n",
                cg.groups.get(&id).ok_or(Errno(19))?.pids_events_local
            ),
            b"cgroup.type" => "domain\n".to_owned(),
            b"cgroup.events" => {
                let populated = cg.current(id) != 0;
                format!(
                    "populated {}\nfrozen {}\n",
                    u8::from(populated),
                    u8::from(cg.event_key(id).1)
                )
            }
            b"cgroup.freeze" => format!(
                "{}\n",
                u8::from(cg.groups.get(&id).ok_or(Errno(19))?.freeze)
            ),
            b"cgroup.stat" => {
                let descendants = group.descendants;
                let retained = cg.retained_dying();
                let dying = cg
                    .dying
                    .iter()
                    .filter(|g| g.ancestors.contains(&id) && retained.contains(&g.id))
                    .count();
                format!("nr_descendants {descendants}\nnr_dying_descendants {dying}\n")
            }
            _ => return Err(Errno(22)),
        };
        let from = (offset.min(text.len() as u64)) as usize;
        let to = from + count.min(text.len() - from);
        Ok(Some(text.as_bytes()[from..to].to_vec()))
    }
    fn check_write(&self, cg: &Cgroups, caller: &CgroupAccess, bytes: &[u8]) -> Result<()> {
        self.check_live(cg)?;
        if !caller.admin && self.name != b"cgroup.subtree_control" {
            return Err(Errno(1));
        }
        if self
            .namespace
            .root
            .as_ref()
            .is_some_and(|node| node.borrow().inode == self.id)
            && cg.nsdelegate.load(Ordering::Relaxed)
            && !matches!(
                self.name.as_slice(),
                b"cgroup.procs"
                    | b"cgroup.threads"
                    | b"cgroup.subtree_control"
                    | b"memory.oom.group"
                    | b"memory.reclaim"
            )
        {
            return Err(Errno(1));
        }
        if bytes.len() > 4096 {
            return Err(Errno(7));
        }
        Ok(())
    }
    pub(super) fn cgroup_write(
        &self,
        caller: &CgroupAccess,
        bytes: &[u8],
    ) -> Result<Option<usize>> {
        let id = self.id;
        let name = &self.name;
        // Validate the original control inode in the same hierarchy transaction
        // as its effect. Disabling/re-enabling a controller must not let an old
        // pids.max FD mutate the replacement control's state.
        let mut cg = self.groups.borrow_mut();
        self.check_write(&cg, caller, bytes)?;
        if bytes.is_empty() {
            return Ok(Some(0));
        }
        let text = std::str::from_utf8(bytes).map_err(|_| Errno(22))?.trim();
        match name.as_slice() {
            b"cgroup.controllers" => return Err(Errno(22)),
            b"cgroup.max.depth" | b"cgroup.max.descendants" => {
                let limit = if text == "max" {
                    UNLIMITED
                } else {
                    u32::try_from(sysctl::parse_kernel_i32(text)?).map_err(|_| Errno(34))?
                };
                let group = cg.groups.get_mut(&id).ok_or(Errno(19))?;
                if name == b"cgroup.max.depth" {
                    group.max_depth = limit;
                } else {
                    group.max_descendants = limit;
                }
            }
            b"io.max" => {
                let io = cg.groups[&id].io.as_ref().ok_or(Errno(19))?.clone();
                // Configuration and resource notifications run outside the
                // cgroup topology lock, using the original per-device policy.
                drop(cg);
                io.set_max(text)?;
            }
            b"cgroup.freeze" => {
                let freeze = match sysctl::parse_kernel_i32(text)? {
                    0 => false,
                    1 => true,
                    _ => return Err(Errno(34)),
                };
                let before = cg.event_states(cg.groups.keys().copied());
                cg.groups.get_mut(&id).ok_or(Errno(19))?.freeze = freeze;
                let tasks: Vec<_> = cg.tasks.values().cloned().collect();
                let mut changed = Vec::new();
                for task in tasks {
                    let group = task.group();
                    let frozen = cg.frozen(group);
                    if task.frozen.swap(frozen, Ordering::Relaxed) != frozen {
                        let target = task.wake.lock().unwrap().as_ref().and_then(Weak::upgrade);
                        let ack = frozen && target.is_none_or(|t| t.quiescent());
                        let old = task.acknowledged.swap(ack, Ordering::Relaxed);
                        cg.adjust(group, 0, i64::from(ack) - i64::from(old));
                        changed.push(task);
                    }
                }
                let events = cg.changed_events(before);
                drop(cg);
                for task in changed {
                    task.notify();
                }
                notify_events(events);
            }
            b"cgroup.kill" => {
                if sysctl::parse_kernel_i32(text)? != 1 {
                    return Err(Errno(34));
                }
                let path = &cg.groups.get(&id).ok_or(Errno(19))?.location.path;
                let targets: Vec<_> = cg
                    .tasks
                    .iter()
                    .filter(|(_, task)| below(&cg.groups[&task.group()].location.path, path))
                    .map(|(pid, task)| (*pid, task.clone()))
                    .collect();
                let groups: BTreeSet<_> = targets.iter().map(|(_, task)| task.tgid()).collect();
                for task in cg
                    .tasks
                    .values()
                    .filter(|task| groups.contains(&task.tgid()))
                {
                    task.kill_pending.store(true, Ordering::Relaxed);
                }
                let mut signals = Vec::new();
                for (pid, task) in targets {
                    let signal = task.wake.lock().unwrap().as_ref().and_then(Weak::upgrade);
                    if let Some(signal) = signal {
                        signals.push(signal);
                    } else {
                        cg.kill.insert(pid);
                    }
                }
                drop(cg);
                for signal in signals {
                    signal.terminate_process();
                }
            }
            b"cgroup.subtree_control" => {
                let change = cg.change_controllers(id, text, caller.owner)?;
                drop(cg);
                for io in change.io_retired {
                    io.notify();
                }
                for task in change.reschedule {
                    task.notify();
                }
                notify_events(change.events);
                for node in change.nodes {
                    inotify::notify_removed(&node);
                }
            }
            b"cpu.max" => {
                cg.groups.get_mut(&id).unwrap().cpu.set_limit(text)?;
                let tasks: Vec<_> = cg
                    .tasks
                    .values()
                    .filter(|task| cg.publish_bandwidth(task))
                    .cloned()
                    .collect();
                drop(cg);
                for task in tasks {
                    task.notify();
                }
            }
            b"cpu.weight" => {
                let cpu = &mut cg.groups.get_mut(&id).unwrap().cpu;
                cpu.set_weight(text)?;
                if cpu.weight != 100 {
                    cg.weighted.store(true, Ordering::Relaxed);
                } else if cg.weighted.load(Ordering::Relaxed) {
                    cg.weighted.store(
                        cg.groups.values().any(|group| group.cpu.weight != 100),
                        Ordering::Relaxed,
                    );
                }
            }
            b"cpuset.cpus" | b"cpuset.mems" => {
                let cpus = name == b"cpuset.cpus";
                let possible = if cpus {
                    controllers::possible_cpus(caller.cpus)
                } else {
                    1
                };
                let mask = if text.is_empty() {
                    None
                } else {
                    Some(controllers::parse_mask(text, possible)?)
                };
                let group = cg.groups.get_mut(&id).unwrap();
                if cpus {
                    group.cpus = mask;
                    let tasks = cg.publish_cpuset();
                    drop(cg);
                    for task in tasks {
                        task.notify();
                    }
                } else {
                    group.mems = mask;
                }
            }
            b"memory.max" | b"memory.high" | b"memory.reclaim" => return Err(Errno(95)),
            b"memory.oom.group" => {
                let enabled = match text {
                    "0" | "+0" => false,
                    "1" | "+1" => true,
                    _ => return Err(Errno(22)),
                };
                cg.groups[&id]
                    .memory
                    .as_ref()
                    .ok_or(Errno(19))?
                    .set_oom_group(enabled);
            }
            b"pids.max" => {
                let limit = if text == "max" {
                    None
                } else {
                    let value = text.strip_prefix('+').unwrap_or(text);
                    let (value, radix) = if let Some(value) = value
                        .strip_prefix("0x")
                        .or_else(|| value.strip_prefix("0X"))
                    {
                        (value, 16)
                    } else if value.len() > 1 && value.starts_with('0') {
                        (&value[1..], 8)
                    } else {
                        (value, 10)
                    };
                    Some(
                        u64::from_str_radix(value, radix)
                            .ok()
                            .filter(|n| *n <= 4194304)
                            .ok_or(Errno(22))?,
                    )
                };
                cg.groups.get_mut(&id).ok_or(Errno(19))?.pids_max = limit;
            }
            b"cgroup.procs" => {
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Errno(22));
                }
                let local = text.parse::<i32>().map_err(|_| Errno(22))? as u32;
                let target = if local == 0 {
                    caller.pid
                } else {
                    caller.global_pid(local)?
                };
                let Some(member) = cg.tasks.get(&target) else {
                    // The task directory owns wait/reap visibility. Query it only on a
                    // live-membership miss, outside the hierarchy lock.
                    drop(cg);
                    let retired = self
                        .task_source
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .and_then(|source| source.task(target))
                        .and_then(|task| task.exited_cgroup())
                        .ok_or(Errno(3))?;
                    let last = retired.member.exited.get().ok_or(Errno(3))?;
                    let cg = self.groups.borrow();
                    self.check_live(&cg)?;
                    if !Arc::ptr_eq(&self.groups, &retired.groups) || cg.tasks.contains_key(&target)
                    {
                        return Err(Errno(3));
                    }
                    let source = last
                        .ancestors
                        .iter()
                        .copied()
                        .find(|id| cg.groups.contains_key(id))
                        .ok_or(Errno(3))?;
                    cg.check_migration(
                        source,
                        id,
                        self.migration_credentials.as_ref().expect("procs opener"),
                        &self.namespace,
                    )?;
                    if id != ROOT && cg.groups[&id].subtree != 0 {
                        return Err(Errno(16));
                    }
                    return Ok(Some(bytes.len()));
                };
                let tgid = member.tgid();
                cg.check_migration(
                    member.group(),
                    id,
                    self.migration_credentials.as_ref().expect("procs opener"),
                    &self.namespace,
                )?;
                if id != ROOT && cg.groups[&id].subtree != 0 {
                    return Err(Errno(16));
                }
                let tasks: Vec<_> = cg
                    .tasks
                    .values()
                    .filter(|t| t.tgid() == tgid)
                    .cloned()
                    .collect();
                let before = cg.event_states(
                    tasks
                        .iter()
                        .flat_map(|t| cg.ancestors(t.group()))
                        .chain(cg.ancestors(id)),
                );
                let frozen = cg.frozen(id);
                let mut changed = Vec::new();
                for task in tasks {
                    let old_group = task.group();
                    cg.settle_cpu(&task);
                    let old_ack = task.acknowledged.load(Ordering::Relaxed);
                    cg.adjust(old_group, -1, -i64::from(old_ack));
                    task.group.store(id, Ordering::Relaxed);
                    let moved_memory = task.memory.set(cg.memory_at(id));
                    let moved_io = task.io.set(cg.io_at(id));
                    let cpus = cg.effective_cpus(id, u64::MAX);
                    let moved_cpu = task.cpus.swap(cpus, Ordering::Relaxed) != cpus;
                    let moved = task.frozen.swap(frozen, Ordering::Relaxed) != frozen;
                    let ack = if moved {
                        let target = task.wake.lock().unwrap().as_ref().and_then(Weak::upgrade);
                        frozen && target.is_none_or(|t| t.quiescent())
                    } else {
                        old_ack
                    };
                    task.acknowledged.store(ack, Ordering::Relaxed);
                    cg.adjust(id, 1, i64::from(ack));
                    if cg.publish_bandwidth(&task) || moved || moved_cpu || moved_memory || moved_io
                    {
                        changed.push(task);
                    }
                }
                cg.update_peak(id);
                let events = cg.changed_events(before);
                drop(cg);
                for task in changed {
                    task.notify();
                }
                notify_events(events);
            }
            b"cgroup.threads" | b"cgroup.type" => return Err(Errno(95)),
            _ => return Err(Errno(13)),
        }
        Ok(Some(bytes.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_cgroup_metadata_accepts_owners_modes_and_readonly_mount_rules() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/uid_1000", 0o755)
            .unwrap();
        v.chown_at(AT_FDCWD, b"/sys/fs/cgroup/uid_1000/.", 1000, 1000, true)
            .unwrap();
        v.chmod_at(AT_FDCWD, b"/sys/fs/cgroup/uid_1000", 0o770)
            .unwrap();
        v.chown_at(
            AT_FDCWD,
            b"/sys/fs/cgroup/uid_1000/cgroup.procs",
            1000,
            1000,
            false,
        )
        .unwrap();
        let stat = v.stat_at(AT_FDCWD, b"/sys/fs/cgroup/uid_1000").unwrap();
        assert_eq!(u32::from_le_bytes(stat[24..28].try_into().unwrap()), 1000);
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o7777,
            0o770
        );
        assert_eq!(
            v.chmod_at(AT_FDCWD, b"/proc/cmdline", 0o777),
            Err(Errno(30))
        );
        let fd = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/uid_1000/cgroup.procs", 2, 0)
            .unwrap();
        assert_eq!(v.truncate_fd(fd, 0), Err(Errno(30)));
        v.close(fd).unwrap();
        v.mount(None, b"/sys/fs/cgroup", None, 32 | 1, None)
            .unwrap();
        assert_eq!(
            v.chown_at(AT_FDCWD, b"/sys/fs/cgroup/uid_1000", 0, 0, false),
            Err(Errno(30))
        );
    }
    #[test]
    fn owner_and_source_control_io_use_one_original_file_position() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/x", 0o755).unwrap();
        v.cgroup_fork(1, 2, 2);
        let fd = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.procs", 2, 0)
            .unwrap();
        v.write(fd, b"2").unwrap();
        let alias = v.dup(fd, 0, false).unwrap();
        let direct = v.direct_descriptors().get(alias).unwrap();
        assert_eq!(v.seek(fd, 0, 1), Ok(1));
        v.seek(fd, 0, 0).unwrap();
        assert_eq!(v.read(fd, 1).unwrap(), b"2");
        assert_eq!(direct.read(1).unwrap(), b"\n");
        assert_eq!(v.read(alias, 1).unwrap(), b"");
        direct.byte_seek(0, 0).unwrap();
        assert_eq!(v.read(alias, 8).unwrap(), b"2\n");
        let freeze = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.freeze", 2, 0)
            .unwrap();
        v.write(freeze, b"1").unwrap();
        let source = v.direct_descriptors().get(freeze).unwrap();
        source.write(b"0").unwrap();
        assert_eq!(v.seek(freeze, 0, 1), Ok(2));
        assert_eq!(source.byte_seek(0, 1), Ok(2));
        source.byte_seek(0, 0).unwrap();
        assert_eq!(v.read(freeze, 8).unwrap(), b"0\n");
        assert_eq!(source.read(1).unwrap(), b"");
    }
    fn setup() -> Vfs {
        let mut v = Vfs::default();
        v.set_runtime_info(1, RuntimeInfo::default());
        v
    }
    #[test]
    fn shared_control_uses_callers_identity_and_permissions_and_retains_deleted_inode() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/x", 0o755).unwrap();
        v.cgroup_fork(1, 2, 2);
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.procs", 2, 0)
            .unwrap();
        let freeze = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.freeze", 2, 0)
            .unwrap();
        assert!(matches!(
            v.descriptor(procs).unwrap().open,
            OpenHandle::Shared(_)
        ));
        let original = v.shared_files().lookup(procs).unwrap().unwrap();
        let mut caller = v.clone_with_files(true);
        caller.set_process_context(2);
        let fd = caller
            .direct_descriptors()
            .byte_file(original.clone())
            .unwrap();
        assert_eq!(fd.write(b"0"), Ok(1));
        assert_eq!(v.cgroup_path(1), b"/");
        assert_eq!(v.cgroup_path(2), b"/x");
        caller.credentials = Credentials::user(1000, 1000);
        let fd = caller.direct_descriptors().byte_file(original).unwrap();
        assert_eq!(fd.write(b"1"), Err(Errno(1)));
        // The creator's root credentials do not accompany its OFD to the reader.
        fd.byte_seek(0, 0).unwrap();
        assert_eq!(fd.read(128).unwrap(), b"2\n");
        v.cgroup_exit(2);
        let old = v.direct_descriptors().get(freeze).unwrap();
        v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/x", true).unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/x", 0o755).unwrap();
        assert_eq!(old.write(b"1"), Err(Errno(19)));
        assert_eq!(old.read(8), Err(Errno(19)));
        let new = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.freeze", 0, 0)
            .unwrap();
        assert_eq!(v.read(new, 8).unwrap(), b"0\n");
    }
    struct TaskProbe {
        task: CgroupTask,
        idle: AtomicBool,
        wakes: AtomicU32,
        kills: AtomicU32,
    }
    impl TaskSignal for TaskProbe {
        fn raise(&self, sig: u32) {
            assert_eq!(sig, 9);
            self.kills.fetch_add(1, Ordering::Relaxed);
        }
        fn scheduling_changed(&self) {
            // A real callback may read the hierarchy. Writers must drop it first.
            assert!(self
                .task
                .groups
                .borrow()
                .tasks
                .contains_key(&self.task.pid()));
            self.wakes.fetch_add(1, Ordering::Relaxed);
        }
        fn quiescent(&self) -> bool {
            self.idle.load(Ordering::Relaxed)
        }
    }
    #[test]
    fn freezer_keeps_original_levels_and_waits_for_real_execution_acknowledgement() {
        let mut v = setup();
        for path in [b"/sys/fs/cgroup/x".as_slice(), b"/sys/fs/cgroup/x/y"] {
            v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        }
        v.cgroup_fork(1, 2, 2);
        v.cgroup_fork(1, 3, 3);
        let x = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.procs", 1, 0)
            .unwrap();
        let y = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/y/cgroup.procs", 1, 0)
            .unwrap();
        v.write(x, b"2").unwrap();
        v.write(y, b"3").unwrap();
        let a = Arc::new(TaskProbe {
            task: v.cgroup_task(2).unwrap(),
            idle: AtomicBool::new(false),
            wakes: AtomicU32::new(0),
            kills: AtomicU32::new(0),
        });
        let b = Arc::new(TaskProbe {
            task: v.cgroup_task(3).unwrap(),
            idle: AtomicBool::new(true),
            wakes: AtomicU32::new(0),
            kills: AtomicU32::new(0),
        });
        for task in [&a, &b] {
            let target: Arc<dyn TaskSignal> = task.clone();
            task.task.bind(&target);
        }
        let freeze = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.freeze", 1, 0)
            .unwrap();
        let inner = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/y/cgroup.freeze", 1, 0)
            .unwrap();
        let events = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.events", 0, 0)
            .unwrap();
        let direct = v.direct_descriptors();
        direct.get(freeze).unwrap().write(b"1").unwrap();
        assert!(a.task.frozen() && b.task.frozen());
        assert_eq!(v.pread(events, 128, 0).unwrap(), b"populated 1\nfrozen 0\n");
        a.idle.store(true, Ordering::Relaxed);
        a.task.acknowledge();
        assert_eq!(v.pread(events, 128, 0).unwrap(), b"populated 1\nfrozen 1\n");
        direct.get(inner).unwrap().write(b"1").unwrap();
        direct.get(freeze).unwrap().write(b"0").unwrap();
        assert!(!a.task.frozen() && b.task.frozen());
        assert_eq!(
            (
                a.wakes.load(Ordering::Relaxed),
                b.wakes.load(Ordering::Relaxed)
            ),
            (2, 1)
        );
        let kill = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.kill", 1, 0)
            .unwrap();
        v.direct_descriptors()
            .get(kill)
            .unwrap()
            .write(b"1")
            .unwrap();
        assert_eq!(
            (
                a.kills.load(Ordering::Relaxed),
                b.kills.load(Ordering::Relaxed)
            ),
            (1, 1)
        );
        assert!(
            v.take_cgroup_kills().is_empty(),
            "bound tasks are signalled directly"
        );
    }
    #[test]
    fn late_exit_cannot_retire_replacement_membership_and_runs_without_an_owner_view() {
        let v = setup();
        v.cgroup_fork(1, 2, 2);
        let old = v.cgroup_task(2).unwrap();
        v.cgroup_exit(2);
        v.cgroup_fork(1, 2, 2);
        let current = v.cgroup_task(2).unwrap();
        std::thread::spawn(move || old.exit()).join().unwrap();
        assert!(v.cgroup_task(2).is_some());
        std::thread::spawn(move || current.exit()).join().unwrap();
        assert!(v.cgroup_task(2).is_none());
    }
    #[test]
    fn removed_group_and_reused_pid_preserve_original_zombie_location() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/child", 0o755)
            .unwrap();
        v.cgroup_fork(1, 2, 2);
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/child/cgroup.procs", 1, 0)
            .unwrap();
        v.write(procs, b"2").unwrap();
        let original = v.cgroup_task(2).unwrap();
        original.exit();
        assert_eq!(original.path_status(), (b"/child".to_vec(), false));
        v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/child", true)
            .unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/child", 0o755)
            .unwrap();
        v.cgroup_fork(1, 2, 2);
        assert_eq!(original.path_status(), (b"/child".to_vec(), true));
        assert_eq!(
            v.cgroup_task(2).unwrap().path_status(),
            (b"/".to_vec(), false)
        );
    }
    struct Wake(AtomicU32);
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[test]
    fn population_and_pids_notifications_use_original_poll_and_inotify_resources() {
        let mut v = setup();
        let subtree = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/cgroup.subtree_control", 1, 0)
            .unwrap();
        v.write(subtree, b"+pids").unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/x", 0o755).unwrap();
        let events = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.events", 0, 0)
            .unwrap();
        let pids = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/pids.events", 0, 0)
            .unwrap();
        let max = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/pids.max", 1, 0)
            .unwrap();
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.procs", 1, 0)
            .unwrap();
        let watch = v.inotify_init(O_NONBLOCK).unwrap();
        v.inotify_add(watch, b"/sys/fs/cgroup/x/cgroup.events", inotify::MODIFY)
            .unwrap();
        let direct = v.direct_descriptors();
        let fd = direct.get(events).unwrap();
        let pidfd = direct.get(pids).unwrap();
        // kernfs starts with an unobserved generation. Polling does not consume it.
        assert_eq!(fd.peek_poll(2).0, 10);
        assert_eq!(v.poll(events, 2), 10);
        assert_eq!(fd.byte_seek(0, 2), Ok(0));
        assert_eq!(fd.byte_seek(-1, 2), Err(Errno(22)));
        assert_eq!(fd.device_pread(128, 0).unwrap(), b"populated 0\nfrozen 0\n");
        assert_eq!(fd.peek_poll(2).0, 0);
        assert_eq!(v.poll(events, 2), 0);
        let epoll = v.epoll_create(0).unwrap();
        v.epoll_ctl(epoll, 1, events, 0x80000002, 99).unwrap();
        let epoll_fd = v.direct_descriptors().get(epoll).unwrap();
        assert!(epoll_fd.epoll_wait(1).unwrap().is_empty());
        let target: Arc<dyn IoWake> = Arc::new(Wake(AtomicU32::new(0)));
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let _subscriptions = fd.subscribe(&signal);
        v.cgroup_fork(1, 2, 2);
        v.write(procs, b"2").unwrap();
        assert!(signal.ready());
        assert_eq!(fd.peek_poll(2).0, 10);
        assert_eq!(
            v.epoll_wait(epoll, 1, |_, _| Ok(None)).unwrap(),
            vec![(10, 99)]
        );
        assert!(epoll_fd.epoll_wait(1).unwrap().is_empty());
        assert_eq!(fd.device_pread(128, 0).unwrap(), b"populated 1\nfrozen 0\n");
        assert_eq!(fd.peek_poll(2).0, 0);
        assert!(!v.read(watch, 256).unwrap().is_empty());
        pidfd.device_pread(128, 0).unwrap();
        assert_eq!(pidfd.peek_poll(2).0, 0);
        v.write(max, b"1").unwrap();
        assert_eq!(v.cgroup_can_fork(2), Err(Errno(11)));
        assert_eq!(pidfd.peek_poll(2).0, 10);
        assert_eq!(pidfd.device_pread(128, 0).unwrap(), b"max 1\n");
        let gone = IoSignal::new(1, Arc::downgrade(&target));
        let _sub = pidfd.subscribe(&gone);
        v.write(subtree, b"-pids").unwrap();
        assert!(gone.ready());
        assert_eq!(pidfd.peek_poll(2).0, 10);
        assert_eq!(pidfd.device_pread(128, 0), Err(Errno(19)));
        let old_max = direct.get(max).unwrap();
        v.write(subtree, b"+pids").unwrap();
        assert_eq!(old_max.write(b"0"), Err(Errno(19)));
        let new_max = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/pids.max", 0, 0)
            .unwrap();
        assert_eq!(v.read(new_max, 128).unwrap(), b"max\n");
        v.cgroup_task(2).unwrap().exit();
        assert_eq!(fd.device_pread(128, 0).unwrap(), b"populated 0\nfrozen 0\n");
    }
    #[test]
    fn ancestor_limits_apply_across_siblings_and_release_on_unlink() {
        let mut v = setup();
        let create = |v: &mut Vfs, suffix: &str| {
            v.mkdir_at(
                AT_FDCWD,
                format!("/sys/fs/cgroup/{suffix}").as_bytes(),
                0o755,
            )
        };
        let limit = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/cgroup.max.descendants", 2, 0)
            .unwrap();
        v.write(limit, b"0x2").unwrap();
        create(&mut v, "a").unwrap();
        create(&mut v, "a/b").unwrap();
        let held = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/b/cgroup.procs", 0, 0)
            .unwrap();
        assert_eq!(create(&mut v, "sibling"), Err(Errno(11)));
        v.write(limit, b"0").unwrap();
        assert_eq!(
            v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a", true),
            Err(Errno(16))
        );
        v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/a/b", true).unwrap();
        assert_eq!(create(&mut v, "sibling"), Err(Errno(11)));
        v.write(limit, b"+02").unwrap();
        assert_eq!(v.write(limit, b"-1"), Err(Errno(34)));
        assert_eq!(v.write(limit, b"2147483648"), Err(Errno(34)));
        assert_eq!(v.write(limit, b"--1"), Err(Errno(22)));
        create(&mut v, "sibling").unwrap();
        assert_eq!(create(&mut v, "a/b"), Err(Errno(11)));
        v.close(held).unwrap();
        v.write(limit, b"2147483647").unwrap();
        let copy = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/cgroup.max.descendants", 0, 0)
            .unwrap();
        assert_eq!(v.read(copy, 32).unwrap(), b"max\n");
        let depth = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/a/cgroup.max.depth", 2, 0)
            .unwrap();
        v.write(depth, b"1").unwrap();
        create(&mut v, "a/b").unwrap();
        assert_eq!(create(&mut v, "a/b/c"), Err(Errno(11)));
        assert_eq!(create(&mut v, "sibling/bad\nname"), Err(Errno(22)));
        create(&mut v, "sibling/c").unwrap();
    }
    #[test]
    fn quotas_count_live_deleted_objects_and_release_them() {
        let mut v = setup();
        for i in 1..MAX_GROUPS {
            v.mkdir_at(AT_FDCWD, format!("/sys/fs/cgroup/g{i}").as_bytes(), 0o755)
                .unwrap();
        }
        let fd = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/g1/cgroup.procs", 2, 0)
            .unwrap();
        v.unlink_at(AT_FDCWD, b"/sys/fs/cgroup/g1", true).unwrap();
        assert_eq!(
            v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/new", 0o755),
            Err(Errno(28))
        );
        assert_eq!(v.write(fd, b"0"), Err(Errno(19)));
        v.close(fd).unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/new", 0o755).unwrap();
        assert_eq!(v.cgroups.borrow().groups.len(), MAX_GROUPS);
        assert!(v.cgroups.borrow().dying.is_empty());
    }
    #[test]
    fn namespace_delegation_changes_only_on_successful_superblock_configuration() {
        let mut v = setup();
        let mountpoint = b"/second";
        v.mkdir_at(AT_FDCWD, mountpoint, 0o755).unwrap();
        v.mount(None, mountpoint, Some(b"cgroup2"), 0, Some(b"nsdelegate"))
            .unwrap();
        assert!(v.cgroups.borrow().nsdelegate.load(Ordering::Relaxed));
        assert_eq!(
            v.mount(None, mountpoint, Some(b"cgroup2"), 0, None),
            Err(Errno(16))
        );
        assert_eq!(
            v.mount(None, mountpoint, None, 32, Some(b"unknown")),
            Err(Errno(95))
        );
        v.mount(None, mountpoint, None, 32 | 4096, None).unwrap();
        assert!(v.cgroups.borrow().nsdelegate.load(Ordering::Relaxed));
        let mut nested = v.clone();
        nested.unshare_cgroup().unwrap();
        nested.mount(None, mountpoint, None, 32, None).unwrap();
        assert!(v.cgroups.borrow().nsdelegate.load(Ordering::Relaxed));
        v.mount(None, mountpoint, None, 32, None).unwrap();
        assert!(!v.cgroups.borrow().nsdelegate.load(Ordering::Relaxed));
    }
    #[test]
    fn directed_birth_pins_the_inode_and_checks_both_procs_files() {
        let mut v = setup();
        let path = b"/sys/fs/cgroup/child";
        let procs = b"/sys/fs/cgroup/child/cgroup.procs";
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        let fd = v.open_at(AT_FDCWD, path, O_PATH | O_DIRECTORY, 0).unwrap();
        let stale = v.clone_cgroup_destination(fd).unwrap();
        v.close(fd).unwrap();
        v.unlink_at(AT_FDCWD, path, true).unwrap();
        v.mkdir_at(AT_FDCWD, path, 0o755).unwrap();
        assert_eq!(
            v.activate_child_birth_into(1, 2, 2, Some(&stale)).result(),
            Err(Errno(2))
        );
        assert!(v.cgroup_task(2).is_none());
        let fd = v.open_at(AT_FDCWD, path, O_PATH | O_DIRECTORY, 0).unwrap();
        let mut unprivileged = v.clone();
        unprivileged.credentials.set_id(false, 65534).unwrap();
        let target = unprivileged.clone_cgroup_destination(fd).unwrap();
        v.chmod_at(AT_FDCWD, procs, 0o666).unwrap();
        assert_eq!(
            v.activate_child_birth_into(1, 2, 2, Some(&target)).result(),
            Err(Errno(13))
        );
        assert!(v.cgroup_task(2).is_none());
        v.chmod_at(AT_FDCWD, b"/sys/fs/cgroup/cgroup.procs", 0o666)
            .unwrap();
        assert_eq!(
            v.activate_child_birth_into(1, 2, 1, Some(&target)).result(),
            Err(Errno(95))
        );
        let mut child = v.clone();
        child.unshare_cgroup_at(Some(&target)).unwrap();
        assert_eq!(
            child
                .activate_child_birth_into(1, 2, 2, Some(&target))
                .result(),
            Ok(())
        );
        assert_eq!(child.cgroup_view_path(&child.cgroup_path(2)), b"/");
        assert_eq!(v.cgroup_path(2), b"/child");
    }
    #[test]
    fn depth_limit_is_transactional_and_storage_budget_is_separate() {
        let mut v = setup();
        let before = v.capacity();
        let mut path = b"/sys/fs/cgroup".to_vec();
        for _ in 0..MAX_DEPTH {
            path.extend_from_slice(b"/x");
            v.mkdir_at(AT_FDCWD, &path, 0o755).unwrap();
        }
        path.extend_from_slice(b"/x");
        assert_eq!(v.mkdir_at(AT_FDCWD, &path, 0o755), Err(Errno(28)));
        assert_eq!(v.stat_at(AT_FDCWD, &path), Err(Errno(2)));
        assert_eq!(v.capacity().used_bytes, before.used_bytes);
        assert_eq!(v.capacity().nodes_used, before.nodes_used);
    }
    #[test]
    fn rejected_birth_preserves_first_namespace_init_and_ancestor_ids() {
        let mut v = setup();
        let controllers = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/cgroup.subtree_control", 1, 0)
            .unwrap();
        v.write(controllers, b"+pids").unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/x", 0o755).unwrap();
        v.cgroup_fork(1, 2, 2);
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.procs", 1, 0)
            .unwrap();
        v.write(procs, b"2").unwrap();
        let limit = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/pids.max", 1, 0)
            .unwrap();
        v.write(limit, b"1").unwrap();
        v.unshare_pid().unwrap();
        v.activate_child_pid(2).unwrap();
        let ancestor = v.pid_namespace().clone();
        v.unshare_pid().unwrap();
        let namespace = v.pid_children_namespace().clone();
        for id in 3..6 {
            let birth = v.activate_child_birth(2, id, id);
            assert_eq!(birth.result(), Err(Errno(11)));
            birth.notify();
            assert_eq!(namespace.global(1), None);
            assert_eq!(ancestor.local(id), 0);
            assert!(v.cgroup_task(id).is_none());
            assert_eq!(v.pid_namespace().id(), ancestor.id());
        }
        v.write(limit, b"2").unwrap();
        let birth = v.activate_child_birth(2, 6, 6);
        assert_eq!(birth.result(), Ok(()));
        birth.notify();
        assert_eq!(namespace.init(), 6);
        assert_eq!(namespace.local(6), 1);
        assert_eq!(ancestor.local(6), 2);
        assert!(v.cgroup_task(6).is_some());
        // Namespace validation precedes cgroup mutation, too.
        namespace.terminate();
        v.write(limit, b"3").unwrap();
        let birth = v.activate_child_birth(6, 7, 7);
        assert_eq!(birth.result(), Err(Errno(12)));
        birth.notify();
        assert!(v.cgroup_task(7).is_none());
    }
    #[test]
    fn birth_commits_the_current_group_limit_and_member_together() {
        let mut v = setup();
        let controllers = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/cgroup.subtree_control", 1, 0)
            .unwrap();
        v.write(controllers, b"+pids").unwrap();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/x", 0o755).unwrap();
        v.cgroup_fork(1, 2, 2);
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.procs", 1, 0)
            .unwrap();
        v.write(procs, b"2").unwrap();
        let limit = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/pids.max", 1, 0)
            .unwrap();
        v.write(limit, b"1").unwrap();
        let denied = v.cgroup_birth(2, 3, 3);
        assert_eq!(denied.result(), Err(Errno(11)));
        denied.notify();
        assert!(v.cgroup_task(3).is_none());
        v.write(limit, b"2").unwrap();
        let admitted = v.cgroup_birth(2, 3, 3);
        assert_eq!(admitted.result(), Ok(()));
        admitted.notify();
        assert!(v.cgroup_task(3).is_some());
        let denied = v.cgroup_birth(2, 4, 4);
        assert_eq!(denied.result(), Err(Errno(11)));
        denied.notify();
        assert!(v.cgroup_task(4).is_none());
        let current = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/pids.current", 0, 0)
            .unwrap();
        assert_eq!(v.read(current, 32).unwrap(), b"2\n");
    }
    #[test]
    fn accepted_kill_closes_unbound_birth_and_cannot_follow_reused_pid() {
        let mut v = setup();
        v.mkdir_at(AT_FDCWD, b"/sys/fs/cgroup/x", 0o755).unwrap();
        v.cgroup_fork(1, 2, 2);
        let procs = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.procs", 1, 0)
            .unwrap();
        v.write(procs, b"2").unwrap();
        let birth = v.cgroup_birth(2, 3, 3);
        assert_eq!(birth.result(), Ok(()));
        birth.notify();
        let old = v.cgroup_task(3).unwrap();
        let kill = v
            .open_at(AT_FDCWD, b"/sys/fs/cgroup/x/cgroup.kill", 1, 0)
            .unwrap();
        v.write(kill, b"1").unwrap();
        let denied = v.cgroup_birth(2, 4, 4);
        assert_eq!(denied.result(), Err(Errno(4)));
        denied.notify();
        let receiver = Arc::new(TaskProbe {
            task: old.clone(),
            idle: AtomicBool::new(true),
            wakes: AtomicU32::new(0),
            kills: AtomicU32::new(0),
        });
        let target: Arc<dyn TaskSignal> = receiver.clone();
        old.bind(&target);
        assert_eq!(receiver.kills.load(Ordering::Relaxed), 1);
        assert_eq!(receiver.wakes.load(Ordering::Relaxed), 0);
        assert_eq!(v.take_cgroup_kills(), [2].into());
        old.exit();
        let birth = v.cgroup_birth(1, 3, 3);
        assert_eq!(birth.result(), Ok(()));
        birth.notify();
        let current = v.cgroup_task(3).unwrap();
        let replacement = Arc::new(TaskProbe {
            task: current.clone(),
            idle: AtomicBool::new(true),
            wakes: AtomicU32::new(0),
            kills: AtomicU32::new(0),
        });
        let target: Arc<dyn TaskSignal> = replacement.clone();
        current.bind(&target);
        old.exit();
        assert!(Arc::ptr_eq(
            &v.cgroup_task(3).unwrap().member,
            &current.member
        ));
        assert_eq!(replacement.kills.load(Ordering::Relaxed), 0);
        assert!(v.take_cgroup_kills().is_empty());
    }
}
