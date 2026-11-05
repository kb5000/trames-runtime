// SPDX-License-Identifier: GPL-3.0-or-later
//! Original process-family relationships, shared by threads and both executors.
//! Scalar queries do not lock the structural graph. Notifications follow it.
use crate::{
    children::{Child, Children},
    signal::Info,
    task_control::Group,
    task_parent::Parents,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
};
use trames_vfs::PidNamespace;

pub struct Family {
    id: AtomicU32,
    parent: AtomicU32,
    subreaper: AtomicBool,
    live: AtomicBool,
    metadata: AtomicU64,
    presence: AtomicUsize,
    parent_changed: AtomicBool,
    registry: std::sync::OnceLock<Weak<Families>>,
    status: std::sync::OnceLock<i32>,
    host_status: std::sync::OnceLock<Arc<std::sync::atomic::AtomicI32>>,
}
impl Default for Family {
    fn default() -> Self {
        Self {
            id: AtomicU32::new(0),
            parent: AtomicU32::new(0),
            subreaper: AtomicBool::new(false),
            live: AtomicBool::new(true),
            metadata: AtomicU64::new(u64::MAX),
            presence: AtomicUsize::new(0),
            parent_changed: AtomicBool::new(false),
            registry: Default::default(),
            status: Default::default(),
            host_status: Default::default(),
        }
    }
}
impl Family {
    pub fn parent(&self) -> u32 {
        self.parent.load(Ordering::Relaxed)
    }
    /// Birth/bootstrap only; an existing relationship moves through Families.
    pub fn set_parent(&self, parent: u32) {
        self.parent.store(parent, Ordering::Relaxed);
        self.parent_changed.store(true, Ordering::Relaxed);
    }
    pub fn subreaper(&self) -> bool {
        self.subreaper.load(Ordering::Relaxed)
    }
    pub fn set_subreaper(&self, value: bool) {
        self.subreaper.store(value, Ordering::Relaxed);
    }
    pub fn live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }
    pub fn registry(&self) -> Option<Arc<Families>> {
        self.registry.get()?.upgrade()
    }
    pub fn status(&self) -> Option<i32> {
        self.status.get().copied()
    }
    pub fn bind_host_status(&self, status: Arc<std::sync::atomic::AtomicI32>) {
        self.host_status.get_or_init(|| status);
    }
}
pub struct Binding {
    pub id: u32,
    pub group: u32,
    pub uid: u32,
    pub namespace: PidNamespace,
    pub child: Arc<Child>,
    pub children: Arc<Children>,
    pub control: Arc<Group>,
    pub presence: crate::task::Visibility,
}
struct Entry {
    family: Arc<Family>,
    binding: Binding,
    parent: Weak<Family>,
    children: BTreeMap<u32, Weak<Family>>,
    pending: Option<i32>,
    waiting: usize,
    dependents: Vec<Weak<Family>>,
}
#[derive(Default)]
struct State {
    entries: BTreeMap<u32, Entry>,
}
impl State {
    fn publish(&mut self, family: &Arc<Family>, binding: Binding) -> Vec<crate::children::Notice> {
        let metadata = ((binding.group as u64) << 32) | binding.uid as u64;
        let id = binding.id;
        let presence = binding.presence.identity();
        family.id.store(id, Ordering::Relaxed);
        let parent = self.entries.get(&family.parent()).map(|e| e.family.clone());
        match self.entries.entry(id) {
            std::collections::btree_map::Entry::Occupied(mut e)
                if Arc::ptr_eq(&e.get().family, family) =>
            {
                e.get_mut().binding = binding;
            }
            std::collections::btree_map::Entry::Occupied(mut e) => {
                e.insert(Entry {
                    family: family.clone(),
                    binding,
                    parent: Weak::new(),
                    children: BTreeMap::new(),
                    pending: None,
                    waiting: 0,
                    dependents: Vec::new(),
                });
            }
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(Entry {
                    family: family.clone(),
                    binding,
                    parent: Weak::new(),
                    children: BTreeMap::new(),
                    pending: None,
                    waiting: 0,
                    dependents: Vec::new(),
                });
            }
        }
        let notices = self.attach(id, parent);
        family.metadata.store(metadata, Ordering::Relaxed);
        family.presence.store(presence, Ordering::Relaxed);
        notices
    }
    fn original(&self, family: &Arc<Family>) -> Option<&Entry> {
        self.entries
            .get(&family.id.load(Ordering::Relaxed))
            .filter(|e| Arc::ptr_eq(&e.family, family))
    }
    fn parent_of(&self, family: &Arc<Family>) -> Option<Arc<Family>> {
        self.original(family)?.parent.upgrade()
    }
    fn attach(&mut self, id: u32, parent: Option<Arc<Family>>) -> Vec<crate::children::Notice> {
        let family = self.entries[&id].family.clone();
        let previous = self.entries[&id].parent.upgrade();
        if let Some(old) = previous.and_then(|f| self.original(&f).map(|_| f)) {
            self.entries
                .get_mut(&old.id.load(Ordering::Relaxed))
                .unwrap()
                .children
                .remove(&id);
        }
        let resources = parent
            .as_ref()
            .and_then(|p| self.original(p))
            .map(|e| (e.binding.children.clone(), e.binding.control.clone()));
        if let Some(new) = parent.as_ref().filter(|p| self.original(p).is_some()) {
            self.entries
                .get_mut(&new.id.load(Ordering::Relaxed))
                .unwrap()
                .children
                .insert(id, Arc::downgrade(&family));
        }
        let entry = self.entries.get_mut(&id).unwrap();
        entry.parent = parent.as_ref().map_or_else(Weak::new, Arc::downgrade);
        family.parent.store(
            parent.as_ref().map_or(0, |p| p.id.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
        family.parent_changed.store(false, Ordering::Relaxed);
        entry
            .binding
            .control
            .bind_metadata(&entry.binding.child, id, entry.binding.uid);
        entry.binding.child.attach_quiet(
            resources.as_ref().map(|r| &r.0),
            resources.as_ref().map(|r| &r.1),
            id,
            entry.binding.group,
            entry.binding.uid,
        )
    }
}
#[derive(Default)]
pub struct Families(Mutex<State>);
pub struct Victim {
    pub id: u32,
    pub family: Arc<Family>,
    pub control: Arc<Group>,
}
#[derive(Default)]
pub struct Retirement {
    pub victims: Vec<Victim>,
}
impl Families {
    /// Structural birth publishes parents before children, before admission.
    /// Refresh also preserves this original family across nonleader exec.
    pub fn publish(self: &Arc<Self>, family: &Arc<Family>, binding: Binding) {
        family.registry.get_or_init(|| Arc::downgrade(self));
        let metadata = ((binding.group as u64) << 32) | binding.uid as u64;
        if family.id.load(Ordering::Relaxed) == binding.id
            && family.metadata.load(Ordering::Relaxed) == metadata
            && family.presence.load(Ordering::Relaxed) == binding.presence.identity()
            && !family.parent_changed.load(Ordering::Relaxed)
        {
            return;
        }
        let notices = self.0.lock().unwrap().publish(family, binding);
        for notice in notices {
            notice.notify();
        }
    }
    /// Commit original PID/group membership and family birth against namespace
    /// shutdown under their existing relationship lock. The closure performs
    /// no guest byte access, backing I/O or CPU/native execution.
    pub fn birth<R>(
        self: &Arc<Self>,
        family: &Arc<Family>,
        operation: impl FnOnce() -> Result<(Option<Binding>, R), trames_vfs::Errno>,
    ) -> Result<R, trames_vfs::Errno> {
        family.registry.get_or_init(|| Arc::downgrade(self));
        let (notices, value) = {
            let mut state = self.0.lock().unwrap();
            let (binding, value) = operation()?;
            let notices = binding.map_or_else(Vec::new, |binding| state.publish(family, binding));
            (notices, value)
        };
        for notice in notices {
            notice.notify();
        }
        Ok(value)
    }
    pub fn prune(&self) {
        let removed = {
            let mut state = self.0.lock().unwrap();
            let ids: Vec<_> = state
                .entries
                .iter()
                .filter_map(|(&id, e)| {
                    (!e.family.live()
                        && e.family.status().is_some()
                        && !e.binding.presence.present())
                    .then_some(id)
                })
                .collect();
            let mut removed = Vec::new();
            for id in ids {
                if let Some(entry) = state.entries.remove(&id) {
                    if let Some(parent) = entry
                        .parent
                        .upgrade()
                        .filter(|f| state.original(f).is_some())
                    {
                        state
                            .entries
                            .get_mut(&parent.id.load(Ordering::Relaxed))
                            .unwrap()
                            .children
                            .remove(&id);
                    }
                    removed.push(entry);
                }
            }
            removed
        };
        drop(removed);
    }
    /// The actual graph decides adoption and namespace victims. CPU/mm/native
    /// teardown belongs to the caller's lifecycle custody, not this graph.
    pub fn retire(&self, family: &Arc<Family>, parents: &Parents) -> Retirement {
        let (retirement, notices, exits) = {
            let mut state = self.0.lock().unwrap();
            let Some(entry) = state.original(family) else {
                return Retirement::default();
            };
            if !family.live.swap(false, Ordering::Relaxed) {
                return Retirement::default();
            }
            let namespace = entry.binding.namespace.clone();
            let id = entry.binding.id;
            if namespace.is_nested() && namespace.init() == id {
                namespace.terminate();
                let victims: Vec<_> = state
                    .entries
                    .values()
                    .filter(|e| e.binding.id != id && namespace.contains(&e.binding.namespace))
                    .map(|e| Victim {
                        id: e.binding.id,
                        family: e.family.clone(),
                        control: e.binding.control.clone(),
                    })
                    .collect();
                let mut waiting = 0;
                for victim in &victims {
                    if victim.family.status().is_none() {
                        state
                            .entries
                            .get_mut(&victim.id)
                            .unwrap()
                            .dependents
                            .push(Arc::downgrade(family));
                        waiting += 1;
                    }
                }
                state.entries.get_mut(&id).unwrap().waiting = waiting;
                return Retirement { victims };
            }
            let mut reaper = state
                .entries
                .get(&namespace.init())
                .map(|e| e.family.clone());
            let mut ancestor = state.parent_of(family);
            while let Some(current) = ancestor {
                let Some(entry) = state.original(&current) else {
                    break;
                };
                if entry.binding.namespace.id() != namespace.id() {
                    break;
                }
                if current.subreaper() && current.live() {
                    reaper = Some(current);
                    break;
                }
                let next = entry.parent.upgrade();
                if next.as_ref().is_some_and(|p| Arc::ptr_eq(p, &current)) {
                    break;
                }
                ancestor = next;
            }
            let children = std::mem::take(&mut state.entries.get_mut(&id).unwrap().children);
            let mut notices = Vec::new();
            let mut exits = Vec::new();
            let reaper_task = reaper
                .as_ref()
                .and_then(|f| state.original(f))
                .and_then(|e| e.binding.control.survivor());
            for (child_id, child) in children {
                let Some(_) = child.upgrade().filter(|c| state.original(c).is_some()) else {
                    continue;
                };
                notices.extend(state.attach(child_id, reaper.clone()));
                let child_entry = &state.entries[&child_id];
                for task in child_entry.binding.control.tasks() {
                    parents.reparent(&task, reaper_task.as_ref().map_or(0, |r| r.0));
                }
                if let Some((notice, status)) = child_entry.binding.child.finish_quiet(
                    None,
                    reaper
                        .as_ref()
                        .and_then(|f| state.original(f))
                        .is_some_and(|e| e.binding.control.auto_reap_children()),
                ) {
                    exits.push((notice, exit_info(child_id, child_entry.binding.uid, status)));
                }
            }
            (Retirement::default(), notices, exits)
        };
        for notice in notices {
            notice.notify();
        }
        for (notice, info) in exits {
            notice.signal(info);
        }
        retirement
    }
    /// Complete the original group, deferring namespace init notification until
    /// its actual shutdown victims complete. Dependencies are original family
    /// references, not a Process scan or a retry on an owner thread.
    pub fn complete(&self, family: &Arc<Family>, status: i32) -> bool {
        let (exits, reaped) = {
            let mut state = self.0.lock().unwrap();
            let Some(_) = state.original(family) else {
                return false;
            };
            let id = family.id.load(Ordering::Relaxed);
            state
                .entries
                .get_mut(&id)
                .unwrap()
                .pending
                .get_or_insert(status);
            let mut ready = vec![family.clone()];
            let mut exits = Vec::new();
            while let Some(current) = ready.pop() {
                let Some(entry) = state.original(&current) else {
                    continue;
                };
                if entry.waiting != 0 || current.status().is_some() {
                    continue;
                }
                let Some(status) = entry.pending else {
                    continue;
                };
                let auto = state
                    .parent_of(&current)
                    .and_then(|f| state.original(&f))
                    .is_some_and(|e| e.binding.control.auto_reap_children());
                current
                    .status
                    .set(status)
                    .expect("one original family completion");
                if let Some(host) = current.host_status.get() {
                    host.store(status, Ordering::Relaxed);
                }
                if let Some((notice, status)) = entry.binding.child.finish_quiet(Some(status), auto)
                {
                    exits.push((
                        notice,
                        exit_info(entry.binding.id, entry.binding.uid, status),
                    ));
                }
                let id = current.id.load(Ordering::Relaxed);
                let dependents =
                    std::mem::take(&mut state.entries.get_mut(&id).unwrap().dependents);
                for dependent in dependents {
                    let Some(dependent) =
                        dependent.upgrade().filter(|f| state.original(f).is_some())
                    else {
                        continue;
                    };
                    let entry = state
                        .entries
                        .get_mut(&dependent.id.load(Ordering::Relaxed))
                        .unwrap();
                    entry.waiting -= 1;
                    if entry.waiting == 0 && entry.pending.is_some() {
                        ready.push(dependent);
                    }
                }
            }
            (exits, state.entries[&id].binding.child.reaped())
        };
        for (notice, info) in exits {
            notice.signal(info);
        }
        reaped
    }
}

fn exit_info(id: u32, uid: u32, status: i32) -> Info {
    Info {
        sender: id,
        uid,
        status: if status & 127 == 0 {
            status >> 8
        } else {
            status & 127
        },
        code: if status & 127 == 0 { 1 } else { 2 },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        children::Wait,
        signal::{Action, Signals},
        task_parent::Parentage,
    };
    use trames_vfs::{Errno, Vfs};
    struct Process {
        family: Arc<Family>,
        signals: Signals,
        child: Arc<Child>,
        children: Arc<Children>,
        parentage: Arc<Parentage>,
    }
    impl Process {
        fn new(
            families: &Arc<Families>,
            parents: &Parents,
            ns: &PidNamespace,
            id: u32,
            parent: u32,
        ) -> Self {
            let p = Self {
                family: Arc::default(),
                signals: Signals::default(),
                child: Arc::default(),
                children: Arc::default(),
                parentage: Arc::default(),
            };
            p.family.set_parent(parent);
            p.signals.publish_policy(ns, true);
            p.signals.io.lifecycle().register(&p.signals.io, id);
            p.signals.io.bind_family(&p.family);
            p.parentage.set_parent_thread(parent);
            parents.publish(&p.signals.io, id, &p.parentage);
            p.child.bind_presence(&p.signals.presence);
            families.publish(
                &p.family,
                Binding {
                    id,
                    group: id,
                    uid: 1000,
                    namespace: ns.clone(),
                    child: p.child.clone(),
                    children: p.children.clone(),
                    control: p.signals.io.lifecycle().clone(),
                    presence: p.signals.presence.visibility(),
                },
            );
            p
        }
        fn wait(&self, ns: &PidNamespace) -> Result<Option<u64>, Errno> {
            self.children.wait(
                Wait::prepare(260, [u32::MAX as u64, 0, 1, 0, 0, 0]).unwrap(),
                ns,
                1,
                &mut trames_memory::Memory::default(),
            )
        }
    }
    #[test]
    fn adoption_moves_original_parent_scalar_threads_wait_and_later_job_notices_together() {
        let families = Arc::new(Families::default());
        let parents = Parents::default();
        let ns = PidNamespace::default();
        let init = Process::new(&families, &parents, &ns, 1, 0);
        let reaper = Process::new(&families, &parents, &ns, 10, 1);
        reaper.family.set_subreaper(true);
        let parent = Process::new(&families, &parents, &ns, 20, 10);
        let child = Process::new(&families, &parents, &ns, 30, 20);
        let saved = child.signals.io.family().unwrap().clone();
        families.retire(&parent.family, &parents);
        assert_eq!(saved.parent(), 10);
        assert_eq!(child.parentage.parent_thread(), 10);
        assert_eq!(parent.wait(&ns), Err(Errno(10)));
        assert_eq!(reaper.wait(&ns), Ok(Some(0)));
        child.signals.io.lifecycle().consume_stop(19, || true);
        let info = reaper.signals.io.process().take(17).unwrap();
        assert_eq!((info.sender, info.code, info.status), (30, 5, 19));
        assert!(parent.signals.io.process().take(17).is_none());
        child
            .signals
            .io
            .job_signal(18, true, Info::default(), false)
            .unwrap();
        assert_eq!(reaper.signals.io.process().take(17).unwrap().code, 6);
        assert!(!families.complete(&child.family, 23 << 8));
        assert_eq!(reaper.signals.io.process().take(17).unwrap().status, 23);
        assert!(!families.complete(&child.family, 99 << 8));
        assert!(reaper.signals.io.process().take(17).is_none());
        assert_eq!(child.child.pending(), Some(23 << 8));
        assert_eq!(reaper.wait(&ns), Ok(Some(30)));
        assert!(!child.signals.presence.present());
        assert_eq!(init.wait(&ns), Ok(Some(0)));
    }
    #[test]
    fn adopted_zombie_uses_actual_new_parent_disposition_and_retires_pid_before_owner_collection() {
        for action in [
            Action {
                handler: 1,
                ..Default::default()
            },
            Action {
                handler: 0x1234,
                flags: 2,
                ..Default::default()
            },
        ] {
            let families = Arc::new(Families::default());
            let parents = Parents::default();
            let ns = PidNamespace::default();
            let init = Process::new(&families, &parents, &ns, 1, 0);
            let parent = Process::new(&families, &parents, &ns, 20, 1);
            let child = Process::new(&families, &parents, &ns, 30, 20);
            assert!(!families.complete(&child.family, 7 << 8));
            assert!(child.signals.presence.present());
            init.signals.actions.set(17, action);
            families.retire(&parent.family, &parents);
            assert_eq!(child.family.parent(), 1);
            assert!(child.child.reaped());
            assert!(!child.signals.presence.present());
            assert_eq!(
                init.signals.io.process().take(17).is_some(),
                action.handler != 1
            );
            assert_eq!(parent.wait(&ns), Err(Errno(10)));
            assert_eq!(init.wait(&ns), Ok(Some(0))); // the live, original parent remains
            assert!(families.complete(&child.family, 88 << 8));
        }
    }
    #[test]
    fn live_parent_member_supplies_disposition_after_its_leader_exits() {
        let families = Arc::new(Families::default());
        let parents = Parents::default();
        let ns = PidNamespace::default();
        let parent = Process::new(&families, &parents, &ns, 1, 0);
        let child = Process::new(&families, &parents, &ns, 20, 1);
        let peer = parent.signals.fork(true);
        peer.io.share_process(&parent.signals.io);
        peer.publish_policy(&ns, true);
        peer.io.lifecycle().register(&peer.io, 2);
        parent.signals.io.exit();
        peer.actions.set(
            17,
            Action {
                flags: 2,
                handler: 0x1000,
                ..Default::default()
            },
        );
        assert!(families.complete(&child.family, 9));
        assert!(!child.signals.presence.present());
        assert_eq!(peer.io.process().take(17).unwrap().code, 2);
    }
    #[test]
    fn namespace_reaper_boundary_and_original_victim_plan_do_not_cross_into_host_family() {
        let families = Arc::new(Families::default());
        let parents = Parents::default();
        let mut vfs = Vfs::default();
        let root = vfs.pid_namespace().clone();
        let init = Process::new(&families, &parents, &root, 1, 0);
        init.family.set_subreaper(true);
        vfs.unshare_pid().unwrap();
        vfs.activate_child_pid(10).unwrap();
        let ns = vfs.pid_namespace().clone();
        let namespace_init = Process::new(&families, &parents, &ns, 10, 1);
        let parent = Process::new(&families, &parents, &ns, 20, 10);
        let child = Process::new(&families, &parents, &ns, 30, 20);
        families.retire(&parent.family, &parents);
        assert_eq!(child.family.parent(), 10);
        assert_eq!(child.parentage.parent_thread(), 10);
        let outside = Process::new(&families, &parents, &root, 40, 1);
        let victims = families.retire(&namespace_init.family, &parents).victims;
        assert!(ns.is_dead());
        assert_eq!(victims.iter().map(|v| v.id).collect::<Vec<_>>(), [20, 30]);
        assert!(victims
            .iter()
            .any(|v| Arc::ptr_eq(&v.family, &child.family)));
        assert_eq!(outside.family.parent(), 1);
        assert!(outside.family.live());
        assert!(!root.is_dead());
        assert!(families
            .retire(&namespace_init.family, &parents)
            .victims
            .is_empty());
    }
    #[test]
    fn delayed_original_exit_cannot_adopt_or_complete_a_reused_process_identity() {
        let families = Arc::new(Families::default());
        let parents = Parents::default();
        let ns = PidNamespace::default();
        let _init = Process::new(&families, &parents, &ns, 1, 0);
        let old = Process::new(&families, &parents, &ns, 10, 1);
        families.retire(&old.family, &parents);
        families.complete(&old.family, 0);
        let replacement = Process::new(&families, &parents, &ns, 10, 1);
        let child = Process::new(&families, &parents, &ns, 30, 10);
        assert!(families.retire(&old.family, &parents).victims.is_empty());
        assert!(!families.complete(&old.family, 9));
        assert_eq!(child.family.parent(), 10);
        assert_eq!(replacement.child.pending(), None);
        families.retire(&replacement.family, &parents);
        assert_eq!(child.family.parent(), 1);
        assert_eq!(child.parentage.parent_thread(), 1);
    }
    #[test]
    fn nested_namespace_completion_follows_original_victims_not_cleanup_order() {
        use std::sync::atomic::AtomicI32;
        let families = Arc::new(Families::default());
        let parents = Parents::default();
        let mut vfs = Vfs::default();
        let root = vfs.pid_namespace().clone();
        let outside = Process::new(&families, &parents, &root, 1, 0);
        vfs.unshare_pid().unwrap();
        vfs.activate_child_pid(10).unwrap();
        let outer_ns = vfs.pid_namespace().clone();
        let outer = Process::new(&families, &parents, &outer_ns, 10, 1);
        let peer = Process::new(&families, &parents, &outer_ns, 20, 10);
        vfs.unshare_pid().unwrap();
        vfs.activate_child_pid(30).unwrap();
        let inner_ns = vfs.pid_namespace().clone();
        let inner = Process::new(&families, &parents, &inner_ns, 30, 10);
        let leaf = Process::new(&families, &parents, &inner_ns, 40, 30);
        let host = Arc::new(AtomicI32::new(i32::MIN));
        outer.family.bind_host_status(host.clone());
        assert_eq!(families.retire(&outer.family, &parents).victims.len(), 3);
        assert_eq!(families.retire(&inner.family, &parents).victims.len(), 1);
        families.complete(&outer.family, 7 << 8);
        families.complete(&inner.family, 31 << 8);
        assert_eq!(outer.family.status(), None);
        assert_eq!(outer.child.pending(), None);
        assert_eq!(host.load(Ordering::Relaxed), i32::MIN);
        families.retire(&peer.family, &parents);
        families.complete(&peer.family, 9);
        assert_eq!(outer.family.status(), None);
        families.retire(&leaf.family, &parents);
        families.complete(&leaf.family, 9);
        assert_eq!(inner.family.status(), Some(31 << 8));
        assert_eq!(outer.family.status(), Some(7 << 8));
        assert_eq!(host.load(Ordering::Relaxed), 7 << 8);
        assert_eq!(outside.wait(&root), Ok(Some(10)));
        families.complete(&leaf.family, 0);
        assert_eq!(outside.wait(&root), Err(Errno(10)));
    }
    #[test]
    fn nonleader_exec_replaces_presence_without_losing_original_family_or_children() {
        let families = Arc::new(Families::default());
        let parents = Parents::default();
        let ns = PidNamespace::default();
        let init = Process::new(&families, &parents, &ns, 1, 0);
        let parent = Process::new(&families, &parents, &ns, 10, 1);
        let child = Process::new(&families, &parents, &ns, 30, 10);
        let survivor = parent.signals.fork(true);
        survivor.io.share_process(&parent.signals.io);
        survivor.publish_policy(&ns, true);
        survivor.io.lifecycle().register(&survivor.io, 11);
        parent.signals.io.exit();
        parent.signals.presence.visibility().reap();
        survivor.io.lifecycle().register(&survivor.io, 10);
        families.prune();
        parent.child.bind_presence(&survivor.presence);
        families.publish(
            &parent.family,
            Binding {
                id: 10,
                group: 10,
                uid: 1000,
                namespace: ns.clone(),
                child: parent.child.clone(),
                children: parent.children.clone(),
                control: survivor.io.lifecycle().clone(),
                presence: survivor.presence.visibility(),
            },
        );
        families.retire(&parent.family, &parents);
        assert_eq!(child.family.parent(), 1);
        assert!(!families.complete(&parent.family, 7 << 8));
        assert_eq!(parent.child.pending(), Some(7 << 8));
        assert_eq!(init.wait(&ns), Ok(Some(10)));
        assert!(!survivor.presence.present());
        assert_eq!(init.wait(&ns), Ok(Some(0))); // the adopted child remains live
    }
    #[test]
    fn birth_and_namespace_shutdown_share_one_original_publication_transaction() {
        use std::sync::mpsc;
        for dead_first in [false, true] {
            let families = Arc::new(Families::default());
            let parents = Arc::new(Parents::default());
            let mut vfs = Vfs::default();
            let root_ns = vfs.pid_namespace().clone();
            let _root = Process::new(&families, &parents, &root_ns, 1, 0);
            vfs.unshare_pid().unwrap();
            vfs.activate_child_pid(10).unwrap();
            let ns = vfs.pid_namespace().clone();
            let init = Process::new(&families, &parents, &ns, 10, 1);
            let child = Process {
                family: Arc::default(),
                signals: Signals::default(),
                child: Arc::default(),
                children: Arc::default(),
                parentage: Arc::default(),
            };
            child.family.set_parent(10);
            child.child.bind_presence(&child.signals.presence);
            let (start, go) = mpsc::channel();
            let (exited, exit) = mpsc::channel();
            let worker = {
                let families = families.clone();
                let parents = parents.clone();
                let init = init.family.clone();
                std::thread::spawn(move || {
                    go.recv().unwrap();
                    let plan = families.retire(&init, &parents);
                    exited.send(plan).unwrap();
                })
            };
            if dead_first {
                start.send(()).unwrap();
                assert!(exit
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap()
                    .victims
                    .is_empty());
            }
            let result = families.birth(&child.family, || {
                if ns.is_dead() {
                    return Err(Errno(12));
                }
                if !dead_first {
                    start.send(()).unwrap();
                }
                Ok((
                    Some(Binding {
                        id: 11,
                        group: 11,
                        uid: 1000,
                        namespace: ns.clone(),
                        child: child.child.clone(),
                        children: child.children.clone(),
                        control: child.signals.io.lifecycle().clone(),
                        presence: child.signals.presence.visibility(),
                    }),
                    (),
                ))
            });
            if dead_first {
                assert_eq!(result, Err(Errno(12)));
            } else {
                assert_eq!(result, Ok(()));
                let plan = exit
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
                assert_eq!(plan.victims.len(), 1);
                assert!(Arc::ptr_eq(&plan.victims[0].family, &child.family));
                families.complete(&init.family, 0);
                assert_eq!(init.family.status(), None);
                families.complete(&child.family, 9);
                assert_eq!(init.family.status(), Some(0));
            }
            worker.join().unwrap();
        }
    }
}
