// SPDX-License-Identifier: GPL-3.0-or-later
//! Resource-generated signals: shared mailboxes, task-local frames and weak PID
//! ownership. Resource callbacks never borrow a CPU or call a coordinator.
use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
};
use trames_vfs::{AsyncOwner, AsyncOwners, IoSignal, PidNamespace};
#[path = "io_guest.rs"]
mod guest;

#[derive(Default)]
pub struct Inbox {
    pending: Mutex<Pending>,
    bits: AtomicU64,
    epoch: AtomicU64,
    readiness: Arc<trames_vfs::Readiness>,
}
impl Inbox {
    fn timer_quiet(&self, sig: u32, info: Info) -> (i32, bool) {
        let mut pending = self.pending.lock().unwrap();
        let mut queued = false;
        let overrun = if let Some((id, extra, _)) = info.timer {
            if let Some(previous) = pending.timer_mut(sig, id) {
                let (_, overrun, _) = previous.timer.as_mut().unwrap();
                *overrun = overrun.saturating_add(extra).saturating_add(1);
                *overrun
            } else {
                let fresh = sig >= 32 || !pending.contains_key(&sig);
                queued = pending.enqueue(sig, info).is_ok() && fresh;
                extra
            }
        } else {
            let fresh = sig >= 32 || !pending.contains_key(&sig);
            queued = pending.enqueue(sig, info).is_ok() && fresh;
            0
        };
        self.bits.store(pending.bits(), Ordering::Relaxed);
        drop(pending);
        (overrun, queued)
    }
    fn timer(&self, sig: u32, info: Info) -> i32 {
        let (overrun, queued) = self.timer_quiet(sig, info);
        if queued {
            self.changed();
        }
        overrun
    }
    pub fn bits(&self) -> u64 {
        self.bits.load(Ordering::Relaxed)
    }
    pub fn enqueue(&self, sig: u32, info: Info) -> Result<(), Errno> {
        if self.enqueue_quiet(sig, info)? {
            self.changed();
        }
        Ok(())
    }
    fn enqueue_quiet(&self, sig: u32, info: Info) -> Result<bool, Errno> {
        let mut pending = self.pending.lock().unwrap();
        if sig < 32 && pending.contains_key(&sig) {
            return Ok(false);
        }
        pending.enqueue(sig, info)?;
        self.bits.store(pending.bits(), Ordering::Relaxed);
        drop(pending);
        Ok(true)
    }
    pub fn next(&self, mask: u64) -> Option<u32> {
        if self.bits() & mask == 0 {
            return None;
        }
        self.pending.lock().unwrap().next(mask)
    }
    pub fn take(&self, sig: u32) -> Option<Info> {
        let mut pending = self.pending.lock().unwrap();
        let result = pending.remove(&sig);
        self.bits.store(pending.bits(), Ordering::Relaxed);
        drop(pending);
        if result.is_some() {
            self.epoch.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
    pub fn discard(&self, sig: u32) {
        let mut pending = self.pending.lock().unwrap();
        if !pending.contains_key(&sig) {
            return;
        }
        pending.discard(sig);
        self.bits.store(pending.bits(), Ordering::Relaxed);
        drop(pending);
        self.epoch.fetch_add(1, Ordering::Relaxed);
    }
    fn changed(&self) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
        self.readiness.notify_atomic();
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> trames_vfs::IoSubscription {
        self.readiness.subscribe(signal)
    }
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Relaxed)
    }
    pub fn contains_key(&self, sig: &u32) -> bool {
        self.bits() & (1u64 << (*sig - 1)) != 0
    }
    pub fn is_empty(&self) -> bool {
        self.bits() == 0
    }
    pub fn peek(&self, sig: u32) -> Option<Info> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .find_map(|(&s, info)| (s == sig).then_some(*info))
    }
    pub fn first_fault(&self) -> Option<u32> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .find_map(|(&sig, info)| info.fault.is_some().then_some(sig))
    }
    pub fn senders(&self) -> Vec<u32> {
        self.pending
            .lock()
            .unwrap()
            .values()
            .map(|i| i.sender)
            .collect()
    }
    pub fn clear(&self) {
        let mut p = self.pending.lock().unwrap();
        if p.is_empty() {
            return;
        }
        p.clear();
        self.bits.store(0, Ordering::Relaxed);
        drop(p);
        self.epoch.fetch_add(1, Ordering::Relaxed);
    }
    pub fn dequeue(&self, mask: u64) -> Option<(u32, Info)> {
        if self.bits() & mask == 0 {
            return None;
        }
        let mut p = self.pending.lock().unwrap();
        let sig = p.next(mask)?;
        let info = p.remove(&sig).unwrap();
        self.bits.store(p.bits(), Ordering::Relaxed);
        drop(p);
        self.epoch.fetch_add(1, Ordering::Relaxed);
        Some((sig, info))
    }
}
#[derive(Clone, Copy, Default)]
pub struct IoContext {
    pub mask: u64,
    pub wait_mask: Option<u64>,
    pub frames: u32,
    pub alt_stack: AltStack,
}
pub struct IoTask {
    pub inbox: Inbox,
    process: std::sync::OnceLock<Arc<Inbox>>,
    lifecycle: std::sync::OnceLock<Arc<crate::task_control::Group>>,
    cgroup: std::sync::OnceLock<trames_vfs::CgroupTask>,
    thread_addresses: std::sync::OnceLock<Arc<trames_execution::ThreadAddresses>>,
    parentage: std::sync::OnceLock<Arc<crate::task_parent::Parentage>>,
    session: AtomicU32,
    pub context: Mutex<IoContext>,
    mask: AtomicU64,
    live: AtomicBool,
    presence: std::sync::OnceLock<crate::task::Visibility>,
    policy: RwLock<Option<Policy>>,
    pid: AtomicU32,
    tgid: AtomicU32,
    group: AtomicU32,
    uid: AtomicU32,
    suid: AtomicU32,
    wake: Mutex<Weak<IoSignal>>,
}
impl Default for IoTask {
    fn default() -> Self {
        Self {
            inbox: Default::default(),
            process: Default::default(),
            lifecycle: Default::default(),
            cgroup: Default::default(),
            thread_addresses: Default::default(),
            parentage: Default::default(),
            session: AtomicU32::new(0),
            context: Default::default(),
            mask: AtomicU64::new(0),
            live: AtomicBool::new(true),
            presence: Default::default(),
            policy: RwLock::default(),
            pid: AtomicU32::new(0),
            tgid: AtomicU32::new(0),
            group: AtomicU32::new(0),
            uid: AtomicU32::new(0),
            suid: AtomicU32::new(0),
            wake: Mutex::new(Weak::new()),
        }
    }
}
impl IoTask {
    fn identifies(&self, kind: u32, id: u32) -> bool {
        self.presence.get().map_or_else(
            || self.live.load(Ordering::Relaxed),
            crate::task::Visibility::present,
        ) && match kind {
            0 => self.pid.load(Ordering::Relaxed) == id,
            1 => self.tgid() == id,
            _ => self.group.load(Ordering::Relaxed) == id,
        }
    }
    pub fn tgid(&self) -> u32 {
        self.tgid.load(Ordering::Relaxed)
    }
    pub fn group(&self) -> u32 {
        self.group.load(Ordering::Relaxed)
    }
    fn belongs(&self, kind: u32, id: u32) -> bool {
        self.live.load(Ordering::Relaxed) && self.identifies(kind, id)
    }
    pub fn process(&self) -> &Arc<Inbox> {
        self.process.get_or_init(Arc::default)
    }
    pub fn share_process(&self, parent: &Self) {
        assert!(self.process.set(parent.process().clone()).is_ok());
        assert!(self.lifecycle.set(parent.lifecycle().clone()).is_ok());
    }
    pub fn lifecycle(&self) -> &Arc<crate::task_control::Group> {
        self.lifecycle.get_or_init(Arc::default)
    }
    pub fn cgroup(&self) -> Option<&trames_vfs::CgroupTask> {
        self.cgroup.get()
    }
    pub fn thread_addresses(&self) -> Option<&Arc<trames_execution::ThreadAddresses>> {
        self.thread_addresses.get()
    }
    pub fn bind_thread_addresses(&self, addresses: &Arc<trames_execution::ThreadAddresses>) {
        self.thread_addresses.get_or_init(|| addresses.clone());
    }
    pub fn parentage(&self) -> Option<&Arc<crate::task_parent::Parentage>> {
        self.parentage.get()
    }
    pub fn bind_parentage(&self, parentage: &Arc<crate::task_parent::Parentage>) {
        let original = self.parentage.get_or_init(|| parentage.clone());
        debug_assert!(Arc::ptr_eq(original, parentage));
    }
    pub fn bind_cgroup(self: &Arc<Self>, task: trames_vfs::CgroupTask) {
        if self.cgroup.set(task).is_ok() {
            let target: Arc<dyn trames_vfs::TaskSignal> = self.clone();
            self.cgroup.get().unwrap().bind(&target);
        }
    }
    pub fn session(&self) -> u32 {
        self.session.load(Ordering::Relaxed)
    }
    pub fn set_session(&self, session: u32) {
        self.session.store(session, Ordering::Relaxed);
    }
    pub fn live(&self) -> bool {
        self.live.load(Ordering::Relaxed) && self.presence.get().is_none_or(|p| p.present())
    }
    pub fn eligible_mask(&self, mask: u64) -> u64 {
        if self.lifecycle().stopped() {
            mask & ((1 << 8) | (1 << 17))
        } else {
            mask
        }
    }
    pub fn ready(&self) -> bool {
        (self.inbox.bits() | self.process().bits())
            & self.eligible_mask(!self.mask.load(Ordering::Relaxed))
            != 0
    }
    pub(crate) fn wake_control(&self) {
        if let Some(signal) = self.wake.lock().unwrap().upgrade() {
            signal.notify();
        }
    }
    fn job_enqueue<T>(
        &self,
        sig: u32,
        shared: bool,
        forced: bool,
        enqueue: impl FnOnce() -> T,
        ignored: impl FnOnce() -> T,
    ) -> T {
        let mask = if shared {
            self.lifecycle()
                .tasks()
                .iter()
                .fold(0, |mask, t| mask | t.mask())
        } else {
            self.mask()
        };
        self.lifecycle().generate(sig, || {
            let policy = self.policy.read().unwrap();
            let Some(policy) = policy.as_ref() else {
                return enqueue();
            };
            policy.actions.with_action(sig, |action| {
                let masked = mask & (1u64 << (sig - 1)) != 0;
                let init = policy.namespace.is_nested() && policy.namespace.local(self.tgid()) == 1;
                if init && action.handler <= 1 && !masked && !(matches!(sig, 9 | 19) && forced)
                    || action.handler == 1 && !masked
                {
                    ignored()
                } else {
                    enqueue()
                }
            })
        })
    }
    fn wake_job(&self, shared: bool) {
        if shared {
            for task in self.lifecycle().tasks() {
                if task.ready() {
                    task.wake();
                    break;
                }
            }
        } else {
            self.wake();
        }
    }
    pub fn job_signal(
        &self,
        sig: u32,
        shared: bool,
        info: Info,
        forced: bool,
    ) -> Result<(), Errno> {
        let queue = if shared {
            self.process().as_ref()
        } else {
            &self.inbox
        };
        if self.job_enqueue(
            sig,
            shared,
            forced,
            || queue.enqueue_quiet(sig, info),
            || Ok(false),
        )? {
            queue.changed();
        }
        self.wake_job(shared);
        Ok(())
    }
    fn job_timer(&self, sig: u32, shared: bool, info: Info) -> i32 {
        let queue = if shared {
            self.process().as_ref()
        } else {
            &self.inbox
        };
        let (overrun, queued) = self.job_enqueue(
            sig,
            shared,
            false,
            || queue.timer_quiet(sig, info),
            || (0, false),
        );
        if queued {
            queue.changed();
        }
        self.wake_job(shared);
        overrun
    }
    pub fn ancestor_sender(&self, sender: u32) -> bool {
        self.policy
            .read()
            .unwrap()
            .as_ref()
            .is_some_and(|p| p.namespace.local(sender) == 0)
    }
    pub(crate) fn child_signal(&self, info: Info) -> bool {
        let queued = {
            let policy = self.policy.read().unwrap();
            let Some(policy) = policy.as_ref() else {
                return false;
            };
            policy.actions.with_action(17, |action| {
                if action.handler == 1 || matches!(info.code, 5 | 6) && action.flags & 1 != 0 {
                    false
                } else {
                    self.process().enqueue_quiet(17, info).unwrap_or(false)
                }
            })
        };
        if queued {
            self.process().changed();
        }
        queued
    }
    pub fn set_wake(&self, signal: &Arc<IoSignal>) {
        *self.wake.lock().unwrap() = Arc::downgrade(signal);
    }
    fn wake(&self) {
        if self.ready() {
            if let Some(signal) = self.wake.lock().unwrap().upgrade() {
                signal.notify();
            }
        }
    }
    pub fn exit(&self) {
        self.live.store(false, Ordering::Relaxed);
        self.lifecycle().retire(self.pid.load(Ordering::Relaxed));
    }
    pub fn try_exit_nonlast(self: &Arc<Self>, pid: u32) -> bool {
        self.lifecycle()
            .try_retire_nonlast(pid, self, || self.live.store(false, Ordering::Relaxed))
    }
    pub fn reap_thread_presence(&self) {
        if self.pid.load(Ordering::Relaxed) != self.tgid() {
            if let Some(presence) = self.presence.get() {
                presence.reap();
            }
        }
    }
    pub fn publish_mask(&self, mask: u64) {
        let old = self.mask.load(Ordering::Relaxed);
        if old & !mask != 0 {
            // An unblock must observe prior enqueues, or a later producer must
            // observe this mask before selecting a wake target. Use the actual
            // task/process queue locks; ordinary reads and blocking-only mask
            // changes need no extra barrier or resource/global serialization.
            let _private = self.inbox.pending.lock().unwrap();
            let _process = self.process().pending.lock().unwrap();
            self.mask.store(mask, Ordering::Relaxed);
        } else {
            self.mask.store(mask, Ordering::Relaxed);
        }
    }
    pub fn mask(&self) -> u64 {
        self.mask.load(Ordering::Relaxed)
    }
    pub fn next(&self, mask: u64) -> Option<(u32, bool)> {
        let mask = self.eligible_mask(mask);
        self.inbox
            .next(mask)
            .map(|s| (s, false))
            .or_else(|| self.process().next(mask).map(|s| (s, true)))
    }
    pub fn take(&self, sig: u32, shared: bool) -> Option<Info> {
        if shared {
            self.process().take(sig)
        } else {
            self.inbox.take(sig)
        }
    }
}
struct Policy {
    actions: Actions,
    namespace: PidNamespace,
    can_kill: bool,
}
impl trames_vfs::TaskSignal for IoTask {
    fn scheduling_changed(&self) {
        self.lifecycle()
            .interrupt_member(self.pid.load(Ordering::Relaxed));
        self.wake_control();
    }
    fn quiescent(&self) -> bool {
        self.lifecycle().quiescent(self.pid.load(Ordering::Relaxed))
    }
    fn raise(&self, signal: u32) {
        if !self.live.load(Ordering::Relaxed) {
            return;
        }
        let info = if signal == 25 {
            // Linux FSIZE uses send_sig(..., current, 0): SI_USER, tgid/ruid.
            Info {
                code: 0,
                sender: self.tgid(),
                uid: self.uid.load(Ordering::Relaxed),
                ..Info::default()
            }
        } else {
            Info {
                code: 128,
                ..Info::default()
            }
        };
        if matches!(signal, 9 | 18..=22) {
            let _ = self.job_signal(signal, false, info, self.ancestor_sender(info.sender));
            return;
        }
        let enqueue = || self.inbox.enqueue_quiet(signal, info).unwrap_or(false);
        let policy = self.policy.read().unwrap();
        let changed = policy.as_ref().map_or_else(enqueue, |p| {
            p.actions
                .with_action(signal, |action| !ignored(signal, action) && enqueue())
        });
        drop(policy);
        if changed {
            self.inbox.changed();
            self.wake();
        }
    }
}
#[derive(Default)]
pub struct IoDirectory {
    pub parents: crate::task_parent::Parents,
    groups: Mutex<BTreeMap<(u32, u32), Arc<Group>>>,
    updates: AtomicU32,
}
struct Group {
    members: RwLock<Vec<Weak<IoTask>>>,
}
/// An accepted timer target retains its original process inbox/group incarnation,
/// or a weak reference to the original thread. PID reuse cannot redirect it.
pub struct TimerTarget {
    group: Arc<Group>,
    id: u32,
    thread: Option<Weak<IoTask>>,
    process: Arc<Inbox>,
}
impl TimerTarget {
    pub fn signal(&self, sig: u32, info: Info) -> i32 {
        if let Some(thread) = &self.thread {
            let Some(task) = thread.upgrade().filter(|t| t.belongs(0, self.id)) else {
                return 0;
            };
            if matches!(sig, 9 | 18..=22) {
                return task.job_timer(sig, false, info);
            }
            let overrun = task.inbox.timer(sig, info);
            task.wake();
            overrun
        } else {
            if matches!(sig, 9 | 18..=22) {
                let target = self
                    .group
                    .members
                    .read()
                    .unwrap()
                    .iter()
                    .filter_map(Weak::upgrade)
                    .find(|t| t.belongs(1, self.id));
                return target.map_or(0, |t| t.job_timer(sig, true, info));
            }
            let overrun = self.process.timer(sig, info);
            if let Some(task) = self
                .group
                .members
                .read()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .find(|t| t.belongs(1, self.id) && t.ready())
            {
                task.wake();
            }
            overrun
        }
    }
}
impl IoDirectory {
    fn tasks(&self, kind: u32, id: u32) -> Vec<Arc<IoTask>> {
        let group = self.groups.lock().unwrap().get(&(kind, id)).cloned();
        group.map_or_else(Vec::new, |g| {
            g.members
                .read()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|t| t.identifies(kind, id))
                .collect()
        })
    }
    pub fn orphaned(&self, task: &IoTask) -> bool {
        let pgrp = task.group();
        let session = task.session();
        !self
            .tasks(2, pgrp)
            .into_iter()
            .filter(|t| t.live())
            .any(|member| {
                member
                    .lifecycle()
                    .parent()
                    .and_then(|p| p.live_task())
                    .is_some_and(|parent| parent.session() == session && parent.group() != pgrp)
            })
    }
    pub fn discard_process(&self, tgid: u32, sig: u32) -> bool {
        let group = self.groups.lock().unwrap().get(&(1, tgid)).cloned();
        let Some(group) = group else { return false };
        let tasks: Vec<_> = group
            .members
            .read()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|t| t.belongs(1, tgid))
            .collect();
        for task in &tasks {
            task.inbox.discard(sig);
        }
        if let Some(task) = tasks.first() {
            task.process().discard(sig);
        }
        !tasks.is_empty()
    }
    pub fn timer_target(&self, tgid: u32, thread: Option<u32>) -> Result<TimerTarget, Errno> {
        let key = thread.map_or((1, tgid), |tid| (0, tid));
        let group = self
            .groups
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or(Errno(22))?;
        let task = group
            .members
            .read()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .find(|t| t.belongs(key.0, key.1) && t.tgid() == tgid)
            .ok_or(Errno(22))?;
        Ok(TimerTarget {
            group,
            id: key.1,
            thread: thread.map(|_| Arc::downgrade(&task)),
            process: task.process().clone(),
        })
    }
    pub fn publish(
        &self,
        task: &Arc<IoTask>,
        pid: u32,
        tgid: u32,
        group: u32,
        uid: u32,
        euid: u32,
    ) {
        task.lifecycle().register(task, pid);
        task.uid.store(uid, Ordering::Relaxed);
        task.suid.store(euid, Ordering::Relaxed);
        if task.pid.load(Ordering::Relaxed) == pid
            && task.tgid.load(Ordering::Relaxed) == tgid
            && task.group.load(Ordering::Relaxed) == group
        {
            return;
        }
        task.pid.store(pid, Ordering::Relaxed);
        task.tgid.store(tgid, Ordering::Relaxed);
        task.group.store(group, Ordering::Relaxed);
        let mut groups = self.groups.lock().unwrap();
        for key in [(0, pid), (1, tgid), (2, group)] {
            if groups.get(&key).is_some_and(|g| {
                g.members
                    .read()
                    .unwrap()
                    .iter()
                    .all(|t| t.upgrade().is_none_or(|t| !t.identifies(key.0, key.1)))
            }) {
                groups.remove(&key);
            }
            let group = groups.entry(key).or_insert_with(|| {
                Arc::new(Group {
                    members: RwLock::default(),
                })
            });
            let mut members = group.members.write().unwrap();
            members.retain(|t| t.upgrade().is_some_and(|t| t.identifies(key.0, key.1)));
            if !members.iter().any(|t| t.ptr_eq(&Arc::downgrade(task))) {
                members.push(Arc::downgrade(task));
            }
        }
        if self.updates.fetch_add(1, Ordering::Relaxed) % 256 == 255 {
            groups.retain(|key, g| {
                g.members
                    .read()
                    .unwrap()
                    .iter()
                    .any(|t| t.upgrade().is_some_and(|t| t.identifies(key.0, key.1)))
            });
        }
    }
}
#[derive(Default)]
pub struct IoRoutes {
    pub directory: Arc<IoDirectory>,
    pub namespace: PidNamespace,
    pub uid: u32,
    pub euid: u32,
}
struct Owner {
    group: Weak<Group>,
    kind: u32,
    id: u32,
    uid: u32,
    euid: u32,
}
impl AsyncOwners for IoRoutes {
    fn resolve(&self, kind: u32, pid: u32) -> Result<Arc<dyn AsyncOwner>, Errno> {
        let id = self.namespace.global(pid).ok_or(Errno(3))?;
        let group = self
            .directory
            .groups
            .lock()
            .unwrap()
            .get(&(kind, id))
            .cloned()
            .ok_or(Errno(3))?;
        Ok(Arc::new(Owner {
            group: Arc::downgrade(&group),
            kind,
            id,
            uid: self.uid,
            euid: self.euid,
        }))
    }
    fn visible(&self, pid: u32) -> u32 {
        self.namespace.local(pid)
    }
}
impl AsyncOwner for Owner {
    fn identity(&self) -> (u32, u32) {
        (
            self.kind,
            if self.group.upgrade().is_some_and(|g| {
                g.members
                    .read()
                    .unwrap()
                    .iter()
                    .any(|t| t.upgrade().is_some_and(|t| t.belongs(self.kind, self.id)))
            }) {
                self.id
            } else {
                0
            },
        )
    }
    fn signal(&self, signo: u32, fd: u32, band: u32) {
        let Some(group) = self.group.upgrade() else {
            return;
        };
        let sig = if signo == 0 { 29 } else { signo };
        let code = if band & 1 != 0 {
            1
        } else if band & 4 != 0 {
            2
        } else if band & 16 != 0 {
            6
        } else {
            4
        };
        let poll_band = match code {
            1 => 0x41,
            2 => 0x304,
            6 => 0x18,
            _ => 8,
        };
        let info = if signo == 0 {
            Info {
                code: 128,
                ..Info::default()
            }
        } else {
            Info {
                code: if matches!(sig, 4 | 5 | 7 | 8 | 11 | 17 | 31) {
                    -5
                } else {
                    code
                },
                poll: Some((poll_band, fd)),
                ..Info::default()
            }
        };
        let members: Vec<_> = group
            .members
            .read()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|t| t.belongs(self.kind, self.id))
            .filter(|t| {
                self.euid == 0
                    || self.uid == t.uid.load(Ordering::Relaxed)
                    || self.euid == t.uid.load(Ordering::Relaxed)
                    || self.uid == t.suid.load(Ordering::Relaxed)
                    || self.euid == t.suid.load(Ordering::Relaxed)
            })
            .collect();
        let mut delivered = BTreeSet::new();
        for task in &members {
            let process = task.tgid.load(Ordering::Relaxed);
            if self.kind != 0 && !delivered.insert(process) {
                continue;
            }
            let inbox = if self.kind == 0 {
                &task.inbox
            } else {
                task.process().as_ref()
            };
            let result = if matches!(sig, 9 | 18..=22) {
                task.job_signal(sig, self.kind != 0, info, task.ancestor_sender(info.sender))
            } else {
                inbox.enqueue(sig, info)
            };
            if result.is_err() {
                let _ = inbox.enqueue(
                    29,
                    Info {
                        code: 128,
                        ..Info::default()
                    },
                );
            }
            if self.kind == 0 {
                task.wake();
            } else if let Some(target) = members
                .iter()
                .find(|t| t.tgid.load(Ordering::Relaxed) == process && t.ready())
            {
                target.wake();
            }
        }
    }
}
impl Signals {
    pub fn begin_io(&self) {
        *self.io.context.lock().unwrap() = IoContext {
            mask: self.mask,
            wait_mask: self.wait_mask,
            frames: self.frames,
            alt_stack: self.alt_stack,
        };
        self.io.publish_mask(self.mask);
    }
    pub fn finish_io(&mut self) {
        let state = *self.io.context.lock().unwrap();
        self.mask = state.mask;
        self.wait_mask = state.wait_mask;
        self.frames = state.frames;
        self.alt_stack = state.alt_stack;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timer_job_control_clears_opposing_queues_and_resumes_ignored_or_masked_cont() {
        for thread in [false, true] {
            for ignored in [false, true] {
                let signals = Signals::default();
                signals.publish_policy(&Default::default(), false);
                signals
                    .io_directory
                    .publish(&signals.io, 42, 42, 42, 1000, 1000);
                signals.actions.set_handler(18, if ignored { 1 } else { 0 });
                if !ignored {
                    signals.io.publish_mask(1 << 17);
                }
                let target = signals
                    .io_directory
                    .timer_target(42, thread.then_some(42))
                    .unwrap();
                let info = Info {
                    timer: Some((7, 0, 99)),
                    ..Default::default()
                };
                target.signal(19, info);
                assert!(signals
                    .io
                    .lifecycle()
                    .consume_stop(19, || signals.io.take(19, !thread).is_some()));
                signals
                    .io
                    .job_signal(20, !thread, Info::default(), false)
                    .unwrap();
                assert_ne!(signals.io.pending_bits() & (1 << 19), 0);
                target.signal(18, info);
                assert!(!signals.io.lifecycle().stopped());
                assert_eq!(signals.io.pending_bits() & (0xf << 18), 0);
                if ignored {
                    assert_eq!(signals.io.pending_bits(), 0);
                } else {
                    assert_eq!(target.signal(18, info), 1);
                    assert_eq!(
                        signals.io.take(18, !thread).unwrap().timer,
                        Some((7, 1, 99))
                    );
                }
            }
        }
    }
    #[test]
    fn file_size_resource_signal_preserves_origin_ignores_discard_and_retired_targets() {
        let signals = Signals::default();
        let directory = IoDirectory::default();
        directory.publish(&signals.io, 42, 40, 40, 1000, 1000);
        signals.publish_policy(&PidNamespace::default(), false);
        signals.actions.set_handler(25, 0x4000);
        trames_vfs::TaskSignal::raise(&*signals.io, 25);
        let info = signals.io.inbox.take(25).unwrap();
        assert_eq!((info.code, info.sender, info.uid), (0, 40, 1000));
        signals.actions.set_handler(25, 1);
        trames_vfs::TaskSignal::raise(&*signals.io, 25);
        assert!(signals.io.inbox.is_empty());
        signals.actions.set_handler(25, 0x4000);
        signals.io.exit();
        trames_vfs::TaskSignal::raise(&*signals.io, 25);
        assert!(signals.io.inbox.is_empty());
    }

    #[test]
    fn pending_timer_overrun_does_not_create_another_signalfd_readiness_edge() {
        let inbox = Inbox::default();
        let info = Info {
            timer: Some((7, 0, 123)),
            ..Default::default()
        };
        assert_eq!(inbox.timer(35, info), 0);
        let epoch = inbox.epoch();
        assert_eq!(inbox.timer(35, info), 1);
        assert_eq!(inbox.epoch(), epoch);
        assert_eq!(inbox.take(35).unwrap().timer, Some((7, 1, 123)));
        assert_eq!(inbox.timer(35, info), 0);
        assert!(inbox.epoch() > epoch);
    }
    #[test]
    fn process_pending_is_shared_and_old_pid_owners_do_not_retarget_reused_ids() {
        let directory = Arc::new(IoDirectory::default());
        let namespace = PidNamespace::default();
        let leader = Arc::new(IoTask::default());
        let thread = Arc::new(IoTask::default());
        thread.share_process(&leader);
        leader.publish_mask(1 << 34);
        directory.publish(&leader, 42, 42, 42, 1000, 1000);
        directory.publish(&thread, 43, 42, 42, 1000, 1000);
        let routes = IoRoutes {
            directory: directory.clone(),
            namespace,
            uid: 1000,
            euid: 1000,
        };
        let owner = routes.resolve(1, 42).unwrap();
        owner.signal(35, 7, 1);
        assert!(!leader.ready());
        assert!(thread.ready());
        let info = thread.take(35, true).unwrap();
        assert_eq!(info.poll, Some((0x41, 7)));
        assert!(leader.process().next(u64::MAX).is_none());
        leader.exit();
        thread.exit();
        let replacement = Arc::new(IoTask::default());
        directory.publish(&replacement, 42, 42, 42, 1000, 1000);
        owner.signal(35, 7, 1);
        assert!(!replacement.ready());
        assert_eq!(owner.identity(), (1, 0));
        routes.resolve(1, 42).unwrap().signal(35, 9, 1);
        assert!(replacement.ready());
    }
    #[test]
    fn blocked_and_ignored_dispositions_keep_linux_sigio_default_termination() {
        assert_eq!(disposition(29, Action::default()), Disposition::Terminate);
        let mut signals = Signals::default();
        signals.io.inbox.enqueue(35, Info::default()).unwrap();
        signals.mask = 1 << 34;
        assert_eq!(signals.pending_bits(), 1 << 34);
        assert!(signals.select(false, false).is_none());
        signals.mask = 0;
        assert_eq!(signals.next_signal(u64::MAX), Some((35, false)));
        signals.take_signal(35, false);
        assert_eq!(signals.pending_bits(), 0);
    }
}
