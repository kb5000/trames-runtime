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

#[derive(Default)]
pub struct Inbox {
    pending: Mutex<Pending>,
    bits: AtomicU64,
}
impl Inbox {
    fn timer(&self, sig: u32, info: Info) -> i32 {
        let mut pending = self.pending.lock().unwrap();
        let overrun = if let Some((id, extra, _)) = info.timer {
            if let Some(previous) = pending.timer_mut(sig, id) {
                let (_, overrun, _) = previous.timer.as_mut().unwrap();
                *overrun = overrun.saturating_add(extra).saturating_add(1);
                *overrun
            } else {
                let _ = pending.enqueue(sig, info);
                extra
            }
        } else {
            let _ = pending.enqueue(sig, info);
            0
        };
        self.bits.store(pending.bits(), Ordering::Relaxed);
        overrun
    }
    pub fn bits(&self) -> u64 {
        self.bits.load(Ordering::Relaxed)
    }
    pub fn enqueue(&self, sig: u32, info: Info) -> Result<(), Errno> {
        let mut pending = self.pending.lock().unwrap();
        pending.enqueue(sig, info)?;
        self.bits.store(pending.bits(), Ordering::Relaxed);
        Ok(())
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
        result
    }
    pub fn discard(&self, sig: u32) {
        let mut pending = self.pending.lock().unwrap();
        pending.discard(sig);
        self.bits.store(pending.bits(), Ordering::Relaxed);
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
    pub context: Mutex<IoContext>,
    mask: AtomicU64,
    live: AtomicBool,
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
            context: Default::default(),
            mask: AtomicU64::new(0),
            live: AtomicBool::new(true),
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
    pub fn tgid(&self) -> u32 {
        self.tgid.load(Ordering::Relaxed)
    }
    fn belongs(&self, kind: u32, id: u32) -> bool {
        self.live.load(Ordering::Relaxed)
            && match kind {
                0 => self.pid.load(Ordering::Relaxed) == id,
                1 => self.tgid.load(Ordering::Relaxed) == id,
                _ => self.group.load(Ordering::Relaxed) == id,
            }
    }
    pub fn process(&self) -> &Arc<Inbox> {
        self.process.get_or_init(Arc::default)
    }
    pub fn share_process(&self, parent: &Self) {
        assert!(self.process.set(parent.process().clone()).is_ok());
    }
    pub fn ready(&self) -> bool {
        (self.inbox.bits() | self.process().bits()) & !self.mask.load(Ordering::Relaxed) != 0
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
impl trames_vfs::TaskSignal for IoTask {
    fn raise(&self, signal: u32) {
        let _ = self.inbox.enqueue(
            signal,
            Info {
                code: 128,
                ..Info::default()
            },
        );
        self.wake();
    }
}
#[derive(Default)]
pub struct IoDirectory {
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
            let overrun = task.inbox.timer(sig, info);
            task.wake();
            overrun
        } else {
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
                    .all(|t| t.upgrade().is_none_or(|t| !t.belongs(key.0, key.1)))
            }) {
                groups.remove(&key);
            }
            let group = groups.entry(key).or_insert_with(|| {
                Arc::new(Group {
                    members: RwLock::default(),
                })
            });
            let mut members = group.members.write().unwrap();
            members.retain(|t| t.upgrade().is_some_and(|t| t.belongs(key.0, key.1)));
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
                    .any(|t| t.upgrade().is_some_and(|t| t.belongs(key.0, key.1)))
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
            if inbox.enqueue(sig, info).is_err() {
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
