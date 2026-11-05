// SPDX-License-Identifier: GPL-3.0-or-later
//! Process-wide job control over original tasks, independent of CPU custody.
//! No control lock covers guest execution, native work or a readiness callback.
use crate::{
    children::{Child, Notice},
    signal::{Info, IoTask},
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
};

#[derive(Default)]
pub struct Group {
    stopped: AtomicBool,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    members: BTreeMap<u32, Member>,
    child: Weak<Child>,
    tgid: u32,
    uid: u32,
    killed: bool,
    stop: Option<(u32, bool)>, // signo, fully acknowledged
}
struct Member {
    task: Weak<IoTask>,
    running: bool,
    held: bool,
    interrupt: Option<Arc<dyn trames_execution::ExecutionInterrupt>>,
}
// ExecutionInterrupt is supplied by the backend; no CPU itself crosses here.
pub struct Lease {
    group: Arc<Group>,
    pid: u32,
    task: Weak<IoTask>,
    held: Option<bool>,
}
struct Publication {
    event: Option<Notice>,
    info: Info,
}
impl Publication {
    fn publish(self) {
        if let Some(event) = self.event {
            event.signal(self.info);
        }
    }
}
impl State {
    fn tasks(&self) -> Vec<Arc<IoTask>> {
        self.members
            .values()
            .filter_map(|m| m.task.upgrade())
            .filter(|t| t.live())
            .collect()
    }
    fn acknowledge(&mut self) -> Option<Publication> {
        let (signal, announced) = self.stop?;
        if announced || self.killed {
            return None;
        }
        let mut live = false;
        for member in self.members.values() {
            if member.task.upgrade().is_some_and(|t| t.live()) {
                live = true;
                if member
                    .task
                    .upgrade()
                    .is_some_and(|t| t.pending_bits() & (1 << 8) != 0)
                {
                    return None;
                }
                if member.running || member.held {
                    return None;
                }
            }
        }
        if !live {
            return None;
        }
        self.stop = Some((signal, true));
        Some(Publication {
            event: self.child.upgrade().map(|c| c.stopped_quiet(signal)),
            info: Info {
                sender: self.tgid,
                uid: self.uid,
                status: signal as i32,
                code: 5,
                ..Default::default()
            },
        })
    }
}
impl Group {
    pub fn survivor(&self) -> Option<(u32, Arc<IoTask>)> {
        self.state
            .lock()
            .unwrap()
            .members
            .iter()
            .find_map(|(&pid, member)| {
                member
                    .task
                    .upgrade()
                    .filter(|task| task.live())
                    .map(|task| (pid, task))
            })
    }
    /// Claim an individual exit while another member remains alive. The last
    /// member keeps the actual process/group cleanup boundary before effects.
    pub(crate) fn try_retire_nonlast(
        &self,
        pid: u32,
        task: &Arc<IoTask>,
        mark: impl FnOnce(),
    ) -> bool {
        let notice = {
            let mut state = self.state.lock().unwrap();
            let original = Arc::downgrade(task);
            if !state
                .members
                .get(&pid)
                .is_some_and(|m| m.task.ptr_eq(&original))
                || !state
                    .members
                    .iter()
                    .any(|(&id, m)| id != pid && m.task.upgrade().is_some_and(|t| t.live()))
            {
                return false;
            }
            mark();
            state.members.remove(&pid);
            state.acknowledge()
        };
        if let Some(notice) = notice {
            notice.publish();
        }
        true
    }
    pub fn interrupt_member(&self, pid: u32) {
        let state = self.state.lock().unwrap();
        if let Some(interrupt) = state.members.get(&pid).and_then(|m| m.interrupt.as_ref()) {
            interrupt.request_exit();
        }
    }
    pub fn quiescent(&self, pid: u32) -> bool {
        self.state
            .lock()
            .unwrap()
            .members
            .get(&pid)
            .is_none_or(|m| !m.running && !m.held)
    }
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }
    pub fn bind(&self, child: &Arc<Child>, parent: Option<&Arc<Group>>, tgid: u32, uid: u32) {
        self.bind_metadata(child, tgid, uid);
        child.bind_parent_group(parent);
    }
    pub(crate) fn bind_metadata(&self, child: &Arc<Child>, tgid: u32, uid: u32) {
        let mut state = self.state.lock().unwrap();
        state.child = Arc::downgrade(child);
        state.tgid = tgid;
        state.uid = uid;
    }
    pub fn register(&self, task: &Arc<IoTask>, pid: u32) {
        let mut state = self.state.lock().unwrap();
        let identity = Arc::downgrade(task);
        if state
            .members
            .get(&pid)
            .is_some_and(|m| m.task.ptr_eq(&identity))
        {
            return;
        }
        let old = state
            .members
            .iter()
            .find_map(|(&id, m)| m.task.ptr_eq(&identity).then_some(id));
        let member = old
            .and_then(|id| state.members.remove(&id))
            .unwrap_or(Member {
                task: identity,
                running: false,
                held: false,
                interrupt: None,
            });
        // A non-leader exec replaces the old leader's PID with this original task.
        state.members.insert(pid, member);
    }
    pub fn enter(self: &Arc<Self>, task: &Arc<IoTask>, pid: u32) -> Lease {
        let mut state = self.state.lock().unwrap();
        let member = state.members.entry(pid).or_insert_with(|| Member {
            task: Arc::downgrade(task),
            running: false,
            held: false,
            interrupt: None,
        });
        assert!(!member.running, "one executor per task");
        member.running = true;
        Lease {
            group: self.clone(),
            pid,
            task: Arc::downgrade(task),
            held: None,
        }
    }
    pub fn hold(&self, pid: u32, held: bool) {
        let notice = {
            let mut s = self.state.lock().unwrap();
            if let Some(m) = s.members.get_mut(&pid) {
                m.held = held;
            }
            s.acknowledge()
        };
        if let Some(notice) = notice {
            notice.publish();
        }
    }
    pub fn retire(&self, pid: u32) {
        let notice = {
            let mut s = self.state.lock().unwrap();
            s.members.remove(&pid);
            s.acknowledge()
        };
        if let Some(notice) = notice {
            notice.publish();
        }
    }
    pub fn consume_stop(&self, signal: u32, take: impl FnOnce() -> bool) -> bool {
        let (tasks, notice) = {
            let mut state = self.state.lock().unwrap();
            if state.killed || !take() {
                return false;
            }
            if state.stop.is_none() {
                state.stop = Some((signal, false));
                self.stopped.store(true, Ordering::Relaxed);
            }
            for member in state.members.values() {
                if let Some(interrupt) = &member.interrupt {
                    interrupt.request_exit();
                }
            }
            let tasks = state.tasks();
            let notice = state.acknowledge();
            (tasks, notice)
        };
        if let Some(notice) = notice {
            notice.publish();
        }
        for task in tasks {
            task.wake_control();
        }
        true
    }
    /// Generation and enqueue share the group lock. CONT cannot discard a stop
    /// before a concurrent sender has actually put it in its original queue.
    pub fn generate<T>(&self, signal: u32, enqueue: impl FnOnce() -> T) -> T {
        let (value, tasks, notice) = {
            let mut state = self.state.lock().unwrap();
            let tasks = state.tasks();
            for task in &tasks {
                if signal == 18 {
                    for stop in 19..=22 {
                        task.inbox.discard(stop);
                        task.process().discard(stop);
                    }
                } else if matches!(signal, 19..=22) {
                    task.inbox.discard(18);
                    task.process().discard(18);
                }
            }
            let notice = if signal == 18 {
                self.stopped.store(false, Ordering::Relaxed);
                state.stop.take().map(|(sig, announced)| {
                    // An interrupted group stop reports STOPPED SIGCHLD, while
                    // its wait status records the subsequent continuation.
                    let event = state.child.upgrade().map(|child| {
                        if !announced {
                            let _ = child.stopped_quiet(sig);
                        }
                        child.continued_quiet()
                    });
                    Publication {
                        event,
                        info: Info {
                            sender: state.tgid,
                            uid: state.uid,
                            status: if announced { 18 } else { sig } as i32,
                            code: if announced { 6 } else { 5 },
                            ..Default::default()
                        },
                    }
                })
            } else {
                None
            };
            let value = enqueue();
            if signal == 9 {
                state.killed |= tasks.iter().any(|t| t.pending_bits() & (1 << 8) != 0);
            }
            (value, tasks, notice)
        };
        if let Some(notice) = notice {
            notice.publish();
        }
        if signal == 18 {
            for task in tasks {
                task.wake_control();
            }
        }
        value
    }
    pub(crate) fn auto_reap_children(&self) -> bool {
        self.live_task()
            .is_some_and(|task| task.auto_reap_children())
    }
    pub(crate) fn notify_child(&self, info: Info) {
        let tasks = self.state.lock().unwrap().tasks();
        if let Some(first) = tasks.first() {
            if first.child_signal(info) {
                if let Some(task) = tasks.iter().find(|t| t.ready()) {
                    task.wake_control();
                }
            }
        }
    }
    pub fn tasks(&self) -> Vec<Arc<IoTask>> {
        self.state.lock().unwrap().tasks()
    }
    pub fn parent(&self) -> Option<Arc<Group>> {
        let child = self.state.lock().unwrap().child.upgrade();
        child.and_then(|child| child.parent_group())
    }
    pub fn live_task(&self) -> Option<Arc<IoTask>> {
        self.state.lock().unwrap().tasks().into_iter().next()
    }
    fn finish(&self, pid: u32, task: &Weak<IoTask>, held: Option<bool>) {
        let notice = {
            let mut s = self.state.lock().unwrap();
            let member = match s.members.get_mut(&pid) {
                Some(member) => Some(member),
                None => s.members.values_mut().find(|m| m.task.ptr_eq(task)),
            };
            if let Some(m) = member {
                m.running = false;
                m.interrupt = None;
                if let Some(held) = held {
                    m.held = held;
                }
            }
            s.acknowledge()
        };
        if let Some(notice) = notice {
            notice.publish();
        }
    }
}
impl Lease {
    pub fn bind_interrupt(&self, interrupt: Arc<dyn trames_execution::ExecutionInterrupt>) -> bool {
        let mut state = self.group.state.lock().unwrap();
        state.members.get_mut(&self.pid).unwrap().interrupt = Some(interrupt);
        !self.group.stopped()
    }
    pub fn finish(mut self, held: Option<bool>) {
        self.held = held;
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.group.finish(self.pid, &self.task, self.held);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Signals;

    fn family() -> (Arc<IoTask>, Arc<IoTask>, Arc<Child>) {
        let a = Arc::new(IoTask::default());
        let b = Arc::new(IoTask::default());
        b.share_process(&a);
        let group = a.lifecycle();
        group.register(&a, 42);
        group.register(&b, 43);
        let child = Arc::new(Child::default());
        group.bind(&child, None, 42, 1000);
        (a, b, child)
    }
    #[test]
    fn stop_acknowledgement_waits_for_running_members_and_original_kernel_work() {
        let (a, b, child) = family();
        let group = a.lifecycle();
        let first = group.enter(&a, 42);
        let second = group.enter(&b, 43);
        assert!(group.consume_stop(19, || true));
        assert!(group.stopped());
        assert_eq!(child.pending(), None);
        first.finish(Some(false));
        assert_eq!(child.pending(), None);
        second.finish(Some(true)); // accepted disk work still owns this task
        assert_eq!(child.pending(), None);
        group.hold(43, false);
        assert_eq!(child.pending(), Some((19 << 8) | 0x7f));
        a.job_signal(18, true, Info::default(), false).unwrap();
        assert!(!group.stopped());
        assert_eq!(child.pending(), Some(0xffff));
    }
    struct Interrupt(AtomicBool);
    impl trames_execution::ExecutionInterrupt for Interrupt {
        fn request_exit(&self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    #[test]
    fn backend_interrupt_binding_closes_both_stop_entry_races_without_stopping_peers() {
        let (a, b, child) = family();
        let group = a.lifecycle();
        let first = group.enter(&a, 42);
        let second = group.enter(&b, 43);
        let interrupt = Arc::new(Interrupt(AtomicBool::new(false)));
        assert!(first.bind_interrupt(interrupt.clone()));
        let unrelated = Arc::new(IoTask::default());
        let peer = unrelated.lifecycle().enter(&unrelated, 80);
        assert!(group.consume_stop(19, || true));
        assert!(interrupt.0.load(Ordering::Relaxed));
        assert!(!second.bind_interrupt(Arc::new(Interrupt(AtomicBool::new(false)))));
        assert!(!unrelated.lifecycle().stopped());
        drop(first);
        drop(second);
        assert_eq!(child.pending(), Some((19 << 8) | 0x7f));
        drop(peer);
    }
    #[test]
    fn pending_kill_prevents_a_late_stop_acknowledgement() {
        let (a, _, child) = family();
        let lease = a.lifecycle().enter(&a, 42);
        a.lifecycle().consume_stop(19, || true);
        a.job_signal(9, true, Info::default(), true).unwrap();
        lease.finish(Some(false));
        assert_eq!(child.pending(), None);
    }
    #[test]
    fn continuation_during_group_stop_preserves_latest_wait_event_and_notification() {
        let (a, _, child) = family();
        let parent = Signals::default();
        parent.publish_policy(&Default::default(), false);
        parent.io.lifecycle().register(&parent.io, 7);
        a.lifecycle()
            .bind(&child, Some(parent.io.lifecycle()), 42, 1000);
        let lease = a.lifecycle().enter(&a, 42);
        a.lifecycle().consume_stop(19, || true);
        assert_eq!(child.pending(), None);
        a.job_signal(18, true, Info::default(), false).unwrap();
        let info = parent.io.process().take(17).unwrap();
        assert_eq!((info.sender, info.status, info.code), (42, 19, 5));
        assert_eq!(child.pending(), Some(0xffff));
        lease.finish(Some(false));
        assert_eq!(child.pending(), Some(0xffff));
        assert!(!a.lifecycle().stopped());
    }
    #[test]
    fn exec_rekeys_the_original_member_and_replaces_the_retired_leader() {
        let (a, b, child) = family();
        let lease = b.lifecycle().enter(&b, 43);
        a.lifecycle().register(&b, 42);
        assert_eq!(a.lifecycle().state.lock().unwrap().members.len(), 1);
        b.lifecycle().consume_stop(19, || true);
        assert_eq!(child.pending(), None);
        drop(lease);
        assert_eq!(child.pending(), Some((19 << 8) | 0x7f));
    }
    #[test]
    fn concurrent_stop_and_continue_generation_never_leave_opposing_pending_signals() {
        let (a, b, _) = family();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..500 {
                    a.job_signal(19, true, Info::default(), false).unwrap();
                }
            });
            scope.spawn(|| {
                for _ in 0..500 {
                    b.job_signal(18, false, Info::default(), false).unwrap();
                }
            });
        });
        let pending = a.pending_bits() | b.pending_bits();
        assert_ne!(pending & ((1 << 17) | (1 << 18)), (1 << 17) | (1 << 18));
    }
}
