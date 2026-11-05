// SPDX-License-Identifier: GPL-3.0-or-later
//! Original parent-thread relationships. Structural changes lock this graph;
//! PR_SET/GET_PDEATHSIG operate on the actual task's scalar state.
use crate::signal::{Info, IoTask};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, Weak,
    },
};

#[derive(Default)]
pub struct Parentage {
    tid: AtomicU32,
    thread: AtomicU32,
    signal: AtomicU32,
}
impl Parentage {
    pub fn parent_thread(&self) -> u32 {
        self.thread.load(Ordering::Relaxed)
    }
    pub fn set_parent_thread(&self, tid: u32) {
        self.thread.store(tid, Ordering::Relaxed);
    }
    pub fn death_signal(&self) -> u32 {
        self.signal.load(Ordering::Relaxed)
    }
    pub fn set_death_signal(&self, signal: u32) {
        self.signal.store(signal, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub struct Parents(Mutex<State>);
#[derive(Default)]
struct State {
    tasks: BTreeMap<usize, Task>,
    tids: BTreeMap<u32, usize>,
}
struct Task {
    original: Weak<IoTask>,
    parentage: Arc<Parentage>,
    tid: u32,
    parent: Option<usize>,
    children: BTreeSet<usize>,
}
fn key(task: &Arc<IoTask>) -> usize {
    Arc::as_ptr(task) as usize
}
impl State {
    fn reparent(&mut self, child: usize, parent: Option<usize>, tid: u32) {
        let previous = self.tasks.get(&child).and_then(|t| t.parent);
        if previous != parent {
            if let Some(old) = previous.and_then(|p| self.tasks.get_mut(&p)) {
                old.children.remove(&child);
            }
            if let Some(new) = parent.and_then(|p| self.tasks.get_mut(&p)) {
                new.children.insert(child);
            }
        }
        if let Some(task) = self.tasks.get_mut(&child) {
            task.parent = parent;
            task.parentage.set_parent_thread(tid);
        }
    }
}
impl Parents {
    pub fn publish(&self, task: &Arc<IoTask>, tid: u32, parentage: &Arc<Parentage>) {
        task.bind_parentage(parentage);
        // Birth and exec publish identity. Ordinary cohort capture does not
        // acquire the relationship lock; reparenting commits its own links.
        if parentage.tid.load(Ordering::Relaxed) == tid {
            return;
        }
        let mut state = self.0.lock().unwrap();
        let id = key(task);
        if let Some(old) = state
            .tasks
            .get(&id)
            .map(|t| t.tid)
            .filter(|&old| old != tid)
        {
            if state.tids.get(&old) == Some(&id) {
                state.tids.remove(&old);
            }
            let children = &state.tasks[&id].children;
            for child in children {
                state.tasks[child].parentage.set_parent_thread(tid);
            }
        }
        state.tids.insert(tid, id);
        state
            .tasks
            .entry(id)
            .or_insert_with(|| Task {
                original: Arc::downgrade(task),
                parentage: parentage.clone(),
                tid,
                parent: None,
                children: BTreeSet::new(),
            })
            .tid = tid;
        let parent_tid = parentage.parent_thread();
        let parent = state.tids.get(&parent_tid).copied().filter(|&p| p != id);
        state.reparent(id, parent, parent_tid);
        parentage.tid.store(tid, Ordering::Relaxed);
    }
    pub fn reparent(&self, child: &Arc<IoTask>, parent_tid: u32) {
        let mut state = self.0.lock().unwrap();
        let id = key(child);
        let parent = state.tids.get(&parent_tid).copied().filter(|&p| p != id);
        state.reparent(id, parent, parent_tid);
    }
    /// Successor retains the original thread, including exec's future TID.
    /// Notifications run after the relationship transaction has completed.
    pub fn retire(&self, task: &Arc<IoTask>, successor: Option<(u32, &Arc<IoTask>)>, info: Info) {
        self.retire_with(
            task,
            || successor.map(|(tid, task)| (tid, task.clone())),
            info,
        );
    }
    pub fn retire_with(
        &self,
        task: &Arc<IoTask>,
        choose: impl FnOnce() -> Option<(u32, Arc<IoTask>)>,
        info: Info,
    ) {
        let notifications = {
            let mut state = self.0.lock().unwrap();
            let id = key(task);
            let Some(removed) = state.tasks.remove(&id) else {
                return;
            };
            if state.tids.get(&removed.tid) == Some(&id) {
                state.tids.remove(&removed.tid);
            }
            if let Some(parent) = removed.parent.and_then(|p| state.tasks.get_mut(&p)) {
                parent.children.remove(&id);
            }
            if removed.children.is_empty() {
                return;
            }
            let (next_tid, next) = choose()
                .filter(|(_, task)| state.tasks.contains_key(&key(task)) && task.live())
                .map_or((0, None), |(tid, task)| (tid, Some(key(&task))));
            let mut notifications = Vec::new();
            for child in removed.children {
                state.reparent(child, next, next_tid);
                if let Some(child) = state.tasks.get(&child) {
                    let signal = child.parentage.death_signal();
                    if signal != 0 {
                        if let Some(target) = child.original.upgrade().filter(|t| t.live()) {
                            notifications.push((target, signal));
                        }
                    }
                }
            }
            notifications
        };
        for (target, signal) in notifications {
            target.parent_death(signal, info);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn task(parents: &Parents, tid: u32, parent: u32) -> (Arc<IoTask>, Arc<Parentage>) {
        let task = Arc::new(IoTask::default());
        let state = Arc::new(Parentage::default());
        state.set_parent_thread(parent);
        parents.publish(&task, tid, &state);
        (task, state)
    }
    fn info(sender: u32) -> Info {
        Info {
            sender,
            uid: 1000,
            ..Default::default()
        }
    }
    #[test]
    fn source_retirement_notifies_original_children_and_retargets_to_original_survivor() {
        let parents = Arc::new(Parents::default());
        let (first, _) = task(&parents, 10, 0);
        let (survivor, _) = task(&parents, 11, 0);
        let (child, child_state) = task(&parents, 30, 10);
        child_state.set_death_signal(35);
        let saved = child_state.clone();
        let source = parents.clone();
        let original = first.clone();
        let next = survivor.clone();
        std::thread::spawn(move || source.retire(&original, Some((11, &next)), info(10)))
            .join()
            .unwrap();
        assert_eq!(saved.parent_thread(), 11);
        assert_eq!(child.process().take(35).unwrap().sender, 10);
        parents.retire(&first, None, info(10));
        assert!(child.process().take(35).is_none());
        parents.retire(&survivor, None, info(11));
        assert_eq!(saved.parent_thread(), 0);
        assert_eq!(child.process().take(35).unwrap().sender, 11);
    }
    #[test]
    fn retired_identity_cannot_notify_children_of_a_reused_numeric_tid() {
        let parents = Parents::default();
        let (old, _) = task(&parents, 10, 0);
        parents.retire(&old, None, info(10));
        let (replacement, _) = task(&parents, 10, 0);
        let (child, state) = task(&parents, 30, 10);
        state.set_death_signal(35);
        parents.retire(&old, None, info(10));
        assert!(child.process().take(35).is_none());
        assert_eq!(state.parent_thread(), 10);
        parents.retire(&replacement, None, info(10));
        assert!(child.process().take(35).is_some());
    }
    #[test]
    fn nonleader_exec_survivor_keeps_original_children_through_future_tid_publication() {
        let parents = Parents::default();
        let (leader, _) = task(&parents, 10, 0);
        let (survivor, survivor_state) = task(&parents, 11, 0);
        let (child, state) = task(&parents, 30, 10);
        state.set_death_signal(35);
        parents.retire(&leader, Some((10, &survivor)), info(10));
        assert!(child.process().take(35).is_some());
        parents.publish(&survivor, 10, &survivor_state);
        assert_eq!(state.parent_thread(), 10);
        let (later, later_state) = task(&parents, 40, 10);
        later_state.set_death_signal(35);
        parents.retire(&survivor, None, info(10));
        assert!(child.process().take(35).is_some());
        assert!(later.process().take(35).is_some());
    }
    #[test]
    fn leader_thread_exit_keeps_the_original_live_process_signal_target() {
        let directory = Arc::new(crate::signal::IoDirectory::default());
        let namespace = trames_vfs::PidNamespace::default();
        let leader = crate::signal::Signals::default();
        let peer = crate::signal::Signals::default();
        peer.io.share_process(&leader.io);
        leader.publish_policy(&namespace, true);
        peer.publish_policy(&namespace, true);
        directory.publish(&leader.io, 10, 10, 10, 0, 0);
        directory.publish(&peer.io, 11, 10, 10, 0, 0);
        leader.io.exit();
        leader.io.reap_thread_presence();
        assert!(
            leader.presence.present(),
            "leader remains the waitable process identity"
        );
        let routes = crate::signal::IoRoutes {
            directory,
            namespace,
            uid: 0,
            euid: 0,
        };
        assert_eq!(
            routes.send(&peer.io, 129, [10, 35, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(peer.io.process().take(35).unwrap().sender, 10);
    }

    #[test]
    fn simultaneous_individual_exits_keep_one_actual_last_member() {
        let first = Arc::new(IoTask::default());
        let group = first.lifecycle().clone();
        let tasks: Vec<_> = (1..=16)
            .map(|pid| {
                let task = Arc::new(IoTask::default());
                task.share_process(&first);
                group.register(&task, pid);
                (pid, task)
            })
            .collect();
        let barrier = Arc::new(std::sync::Barrier::new(tasks.len()));
        let results = std::thread::scope(|scope| {
            let workers: Vec<_> = tasks
                .iter()
                .map(|(pid, task)| {
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        task.try_exit_nonlast(*pid, (*pid as i32) << 8)
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|w| w.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|&&exited| exited).count(), 15);
        assert_eq!(tasks.iter().filter(|(_, task)| task.live()).count(), 1);
        let (last, task) = group.survivor().unwrap();
        assert!(!task.try_exit_nonlast(last, 23 << 8));
        task.begin_exit(last, 23 << 8);
        assert_eq!(
            task.finish_exit(last),
            None,
            "earlier cleanup is still active"
        );
        assert_eq!(group.exit_status(), None);
        let mut completions = Vec::new();
        for (pid, task) in &tasks {
            completions.extend(task.finish_exit(*pid));
        }
        assert_eq!(completions, [23 << 8]);
        assert_eq!(group.exit_status(), Some(23 << 8));
    }

    #[test]
    fn explicit_reparenting_removes_original_link_before_old_parent_exit() {
        let parents = Parents::default();
        let (first, _) = task(&parents, 10, 0);
        let (second, _) = task(&parents, 11, 0);
        let (child, state) = task(&parents, 30, 10);
        state.set_death_signal(35);
        parents.reparent(&child, 11);
        parents.publish(&child, 30, &state);
        parents.retire(&first, None, info(10));
        assert!(child.process().take(35).is_none());
        parents.retire(&second, None, info(11));
        assert_eq!(child.process().take(35).unwrap().sender, 11);
    }
}
