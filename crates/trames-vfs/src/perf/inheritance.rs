// SPDX-License-Identifier: GPL-3.0-or-later
//! Original event families keep resource identities, never tasks or FD graphs.
use super::*;
use std::sync::{atomic::AtomicBool, Weak};

#[derive(Clone, Copy, Default)]
struct Totals {
    value: u64,
    time: u64,
    enabled: u64,
    lost: u64,
}
impl Totals {
    fn add(&mut self, other: Self) {
        self.value = self.value.wrapping_add(other.value);
        self.time = self.time.saturating_add(other.time);
        self.enabled = self.enabled.saturating_add(other.enabled);
        self.lost = self.lost.saturating_add(other.lost);
    }
}
pub(super) struct Family {
    id: u64,
    state: parking_lot::Mutex<FamilyState>,
}
#[derive(Default)]
struct FamilyState {
    closed: bool,
    retired: Totals,
    branches: Vec<Arc<Branch>>,
}
pub(super) struct Branch {
    clock: Weak<ClockData>,
    group: Weak<parking_lot::Mutex<Group>>,
    closed_at: Arc<parking_lot::Mutex<Option<Stamp>>>,
    connected: Arc<AtomicBool>,
    totals: parking_lot::Mutex<Totals>,
    pub(super) commands: parking_lot::Mutex<Vec<(Stamp, u32)>>,
}
impl Family {
    pub(super) fn new(id: u64) -> Self {
        Self {
            id,
            state: Default::default(),
        }
    }
    pub(super) fn live(&self) -> bool {
        !self.state.lock().branches.is_empty()
    }
    fn totals(&self) -> Totals {
        let state = self.state.lock();
        let mut totals = state.retired;
        for branch in &state.branches {
            totals.add(*branch.totals.lock());
        }
        totals
    }
    fn refresh(&self) {
        let branches = self.state.lock().branches.clone();
        for branch in branches {
            if let (Some(clock), Some(group)) = (branch.clock.upgrade(), branch.group.upgrade()) {
                // No parent/family lock is held while entering a child group.
                let clock = Clock(clock);
                let mut state = group.lock();
                state.settle(clock.read());
                drop(state);
            }
        }
    }
    pub(super) fn control(&self, request: u32) {
        let mut clocks = Vec::new();
        let state = self.state.lock();
        for branch in &state.branches {
            if branch.connected.load(Ordering::Relaxed) {
                if let Some(clock) = branch.clock.upgrade() {
                    clocks.push(Clock(clock));
                    branch
                        .commands
                        .lock()
                        .push((clocks.last().unwrap().read(), request));
                }
            }
        }
        drop(state);
        if request == 0x2400 {
            for clock in &clocks {
                clock.register_empty_sampling();
            }
        }
    }
    pub(super) fn close(&self) {
        let mut clocks = Vec::new();
        let mut state = self.state.lock();
        state.closed = true;
        for branch in &state.branches {
            if let Some(clock) = branch.clock.upgrade() {
                clocks.push(Clock(clock));
                *branch.closed_at.lock() = Some(clocks.last().unwrap().read());
            }
        }
        // A retained clock's final release can aggregate its children. Release
        // the family transaction first; destructors must not re-enter it.
        drop(state);
    }
    fn retire(&self, branch: &Arc<Branch>) {
        let mut state = self.state.lock();
        if let Some(index) = state
            .branches
            .iter()
            .position(|item| Arc::ptr_eq(item, branch))
        {
            state.retired.add(*branch.totals.lock());
            state.branches.swap_remove(index);
        }
    }
}
impl Counter {
    pub(super) fn primary_id(&self, id: u64) -> u64 {
        self.family.as_ref().map_or(id, |family| family.id)
    }
    pub(super) fn control(&mut self, request: u32) {
        match request {
            0x2400 => {
                self.enabled = true;
                self.exhausted = false;
                if self.refresh == Some(0) {
                    self.refresh = None;
                }
            }
            0x2401 => self.enabled = false,
            _ => self.value = 0,
        }
        self.publish_branch();
    }
    pub(super) fn totals(&self) -> (u64, u64, u64, u64) {
        let mut totals = Totals {
            value: self.value,
            time: self.time,
            enabled: self.enabled_time,
            lost: self.lost.load(Ordering::Relaxed),
        };
        if self.branch.is_none() {
            if let Some(family) = &self.family {
                totals.add(family.totals());
            }
        }
        (totals.value, totals.enabled, totals.time, totals.lost)
    }
    pub(super) fn publish_branch(&self) {
        if let Some(branch) = &self.branch {
            *branch.totals.lock() = Totals {
                value: self.value,
                time: self.time,
                enabled: self.enabled_time,
                lost: self.lost.load(Ordering::Relaxed),
            };
        }
    }
    pub(super) fn retire_branch(&self) {
        self.publish_branch();
        if let (Some(family), Some(branch)) = (&self.family, &self.branch) {
            family.retire(branch);
        }
    }
}
impl Event {
    pub(super) fn refresh_children(&self) {
        let families: Vec<_> = self
            .group
            .lock()
            .members
            .values()
            .filter(|counter| counter.branch.is_none())
            .filter_map(|counter| counter.family.clone())
            .collect();
        for family in families {
            family.refresh();
        }
    }
}
impl Group {
    pub(super) fn detach_all(&mut self) {
        for counter in self.members.values() {
            counter.connected.store(false, Ordering::Relaxed);
            counter.retire_branch();
        }
        self.sync();
    }
    fn detach(&mut self, id: u64) {
        if let Some(counter) = self.members.get(&id) {
            counter.connected.store(false, Ordering::Relaxed);
            counter.retire_branch();
        }
        for (&member, counter) in &mut self.members {
            if member == id || counter.leader == id {
                counter.leader = member;
            }
        }
        self.sync();
    }
}
impl Clock {
    pub(crate) fn revoke(&self) {
        let filters: Vec<_> = self.0.filters.lock().values().cloned().collect();
        for clock in filters {
            clock.revoke();
        }
        let source = self.read();
        let mut changes = Vec::new();
        let groups = self.groups();
        for group in groups {
            let mut group = group.lock();
            group.settle(source);
            group.detach_all();
            group.publish_userpages();
            changes.extend(
                group
                    .members
                    .values()
                    .map(|counter| counter.changed.clone()),
            );
        }
        self.0.sampling.store(false, Ordering::Relaxed);
        self.deactivate();
        for changed in changes {
            changed.notify_atomic();
        }
    }
    pub(crate) fn exec(&self) {
        let filters: Vec<_> = self.0.filters.lock().values().cloned().collect();
        for clock in filters {
            clock.exec();
        }
        let groups: Vec<_> = self
            .0
            .groups
            .lock()
            .groups
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        let source = self.read();
        let mut changes = Vec::new();
        let mut active = false;
        for group in groups {
            let mut group = group.lock();
            group.settle(source);
            let mut removed = Vec::new();
            for (&id, counter) in &mut group.members {
                if !counter.connected.load(Ordering::Relaxed) {
                    continue;
                }
                if counter.attr.enable_on_exec {
                    counter.attr.enable_on_exec = false;
                    if !counter.enabled {
                        counter.control(0x2400);
                    }
                }
                if counter.attr.remove_on_exec {
                    removed.push(id);
                    changes.push(counter.changed.clone());
                }
            }
            for id in removed {
                group.detach(id);
            }
            group.sync();
            group.publish_userpages();
            active |= group.members.values().any(|counter| counter.running);
        }
        if active {
            self.register_empty_sampling();
        }
        for changed in changes {
            changed.notify_atomic();
        }
    }
    fn register_empty_sampling(&self) {
        let mut registry = self.0.groups.lock();
        registry.revision = registry.revision.wrapping_add(1);
        if !self.0.active.swap(true, Ordering::Relaxed) {
            if let Some(domain) = &self.0.wake_domain {
                domain.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.0.sampling.store(true, Ordering::Relaxed);
    }
    pub(crate) fn inherit(&self, parent: &Self, threaded: bool) {
        let filters = parent.0.filters.lock().clone();
        for (cpu, clock) in filters {
            self.for_cpu(cpu).inherit(&clock, threaded);
        }
        let groups: Vec<_> = parent
            .0
            .groups
            .lock()
            .groups
            .iter()
            .filter_map(Weak::upgrade)
            .collect();
        for source in groups {
            let mut source = source.lock();
            source.settle(parent.read());
            let leaders: Vec<_> = source
                .members
                .iter()
                .filter_map(|(&id, counter)| {
                    (counter.leader == id
                        && counter.attr.inherit
                        && (!counter.attr.inherit_thread || threaded)
                        && counter.connected.load(Ordering::Relaxed))
                    .then_some(id)
                })
                .collect();
            for leader in leaders {
                let group = Arc::new(parking_lot::Mutex::new(Group {
                    source: self.read(),
                    members: BTreeMap::new(),
                }));
                let mut children = BTreeMap::new();
                let mut new_leader = None;
                let mut sampling = false;
                let mut metadata = false;
                let ids: Vec<_> = source
                    .members
                    .iter()
                    .filter_map(|(&id, counter)| {
                        (counter.leader == leader && counter.connected.load(Ordering::Relaxed))
                            .then_some(id)
                    })
                    .collect();
                for original in ids {
                    // All descendants join the original family. Serialize its
                    // admission with parent controls and final OFD release.
                    let Some(family) = source.members[&original].family.clone() else {
                        continue;
                    };
                    let mut state = family.state.lock();
                    if state.closed {
                        continue;
                    }
                    // A concurrent original-parent ioctl can queue a command
                    // while this intermediate task holds its group. Consume
                    // it before copying this task's actual enabled state.
                    let commands = source.members[&original]
                        .branch
                        .as_ref()
                        .map(|branch| std::mem::take(&mut *branch.commands.lock()))
                        .unwrap_or_default();
                    for (at, request) in commands {
                        source.advance(at);
                        source.members.get_mut(&original).unwrap().control(request);
                        source.sync();
                    }
                    let counter = &source.members[&original];
                    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                    let inherited_leader = if original == leader {
                        new_leader = Some(id);
                        id
                    } else {
                        new_leader.unwrap_or(id)
                    };
                    let closed_at = Arc::new(parking_lot::Mutex::new(None));
                    let connected = Arc::new(AtomicBool::new(true));
                    let branch = Arc::new(Branch {
                        clock: Arc::downgrade(&self.0),
                        group: Arc::downgrade(&group),
                        closed_at: closed_at.clone(),
                        connected: connected.clone(),
                        totals: Default::default(),
                        commands: Default::default(),
                    });
                    state.branches.push(branch.clone());
                    sampling |= counter.attr.period != 0 && counter.enabled;
                    metadata |= counter.attr.metadata != 0;
                    children.insert(
                        id,
                        Counter {
                            leader: inherited_leader,
                            config: counter.config,
                            enabled: counter.enabled,
                            running: false,
                            value: 0,
                            time: 0,
                            enabled_time: 0,
                            attr: counter.attr.clone(),
                            remaining: counter.attr.period.max(
                                if matches!(counter.config, 0 | 1) {
                                    counter.settings.minimum_period()
                                } else {
                                    1
                                },
                            ),
                            refresh: None,
                            exhausted: false,
                            throttled: false,
                            sample_at: 0,
                            sample_value: 0,
                            lost: Arc::new(AtomicU64::new(0)),
                            output: counter.output.clone(),
                            namespace: counter.namespace.clone(),
                            changed: counter.changed.clone(),
                            closed_at,
                            connected,
                            family: Some(family.clone()),
                            branch: Some(branch),
                            settings: counter.settings.clone(),
                        },
                    );
                }
                if children.is_empty() {
                    continue;
                }
                {
                    let mut destination = group.lock();
                    destination.members = children;
                    destination.sync();
                }
                // An unexposed child context owns inherited counters even
                // though it has no additional descriptor for them.
                let mut registry = self.0.groups.lock();
                registry.revision = registry.revision.wrapping_add(1);
                registry.groups.push(Arc::downgrade(&group));
                registry.inherited.push(group);
                self.0.active.store(true, Ordering::Relaxed);
                if metadata {
                    self.0.metadata.store(true, Ordering::Relaxed);
                }
                if sampling {
                    self.0.sampling.store(true, Ordering::Relaxed);
                }
            }
        }
    }
}
impl Drop for ClockData {
    fn drop(&mut self) {
        if self.active.load(Ordering::Relaxed) {
            if let Some(domain) = &self.wake_domain {
                domain.fetch_sub(1, Ordering::Relaxed);
            }
        }
        // Also covers a failed, never-published birth. No worker or task body
        // is retained merely to finish a child's accounting.
        let source = Stamp {
            cpu: self
                .wall
                .map_or_else(|| self.time.read(), |origin| origin.elapsed())
                .as_nanos()
                .min((u64::MAX - 1) as u128) as u64,
            enabled: self
                .enabled_time
                .as_ref()
                .map_or_else(
                    || {
                        self.wall
                            .map_or_else(|| self.time.read(), |origin| origin.elapsed())
                    },
                    |time| time.read(),
                )
                .as_nanos()
                .min((u64::MAX - 1) as u128) as u64,
        };
        for group in &self.groups.get_mut().inherited {
            let mut group = group.lock();
            group.settle(source);
            group.detach_all();
        }
        // Actual task exit notifies through Clock::retire. A weak observer can
        // be the last clock owner under another group's transaction; resource
        // destruction alone must not synchronously re-enter that caller.
    }
}
