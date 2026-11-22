// SPDX-License-Identifier: GPL-3.0-or-later
//! Original parent/child wait relationships, independent of CPU custody.
//! Waiters serialize only against siblings and event consumers of this parent.
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
};
use trames_memory::CpuMemory;
use trames_shared::Readiness;
use trames_vfs::{Errno, IoSignal, IoSubscription, PidNamespace};

#[derive(Default)]
pub struct Children {
    entries: Mutex<BTreeMap<u32, Weak<Child>>>,
    changed: Arc<Readiness>,
    reaped: AtomicBool,
    collected: Mutex<crate::usage::Usage>,
}
#[derive(Default)]
pub struct Child(Mutex<State>);
type OnReap = Box<dyn FnOnce() + Send>;
pub(crate) struct Notice(
    Option<Arc<Children>>,
    Weak<crate::task_control::Group>,
    Vec<OnReap>,
);
impl Notice {
    pub fn notify(self) {
        for retire in self.2 {
            retire();
        }
        if let Some(parent) = self.0 {
            parent.changed.notify_locked();
        }
    }
    pub fn signal(self, signo: u32, info: crate::signal::Info) {
        for retire in self.2 {
            retire();
        }
        if let Some(parent) = self.0 {
            parent.changed.notify_locked();
        }
        if signo != 0 {
            if let Some(parent) = self.1.upgrade() {
                parent.notify_child(signo, info);
            }
        }
    }
}
/// The wait class follows the requested signal, even if the parent's later
/// exec makes Linux substitute SIGCHLD for the delivered notification.
#[derive(Clone, Copy)]
pub struct ExitSignal {
    signo: u32,
    parent_image: u64,
}
impl ExitSignal {
    pub fn new(signo: u32, parent_image: u64) -> Self {
        Self {
            signo,
            parent_image,
        }
    }
    fn delivered(self, parent_image: u64) -> u32 {
        if self.signo != 17 && self.parent_image != parent_image {
            17
        } else {
            self.signo
        }
    }
}
impl Default for ExitSignal {
    fn default() -> Self {
        Self::new(17, 0)
    }
}
#[derive(Default)]
struct State {
    owner: Option<Arc<crate::task_parent::Parentage>>,
    exit_signal: ExitSignal,
    id: u32,
    group: u32,
    credentials: Arc<trames_vfs::CredentialState>,
    parent: Weak<Children>,
    parent_group: Weak<crate::task_control::Group>,
    event: Option<i32>,
    trap: Option<i32>,
    traced_by_parent: bool,
    stopped: bool,
    exited: bool,
    reaped: bool,
    on_reap: Option<OnReap>,
    pidfd: Option<Arc<trames_vfs::PidFd>>,
    presence: crate::task::Visibility,
    group_usage: Weak<crate::task_control::Group>,
    children_usage: Weak<Children>,
    exit_usage: crate::usage::Usage,
}
impl Child {
    /// Allocated only when an application requests a process descriptor.
    pub fn pidfd(&self, id: u32) -> Arc<trames_vfs::PidFd> {
        let mut state = self.0.lock().unwrap();
        let (exited, reaped) = (state.exited, state.reaped);
        state
            .pidfd
            .get_or_insert_with(|| Arc::new(trames_vfs::PidFd::new(id, exited, reaped)))
            .clone()
    }

    /// Registration can race wait or automatic reaping. Destroy original resources
    /// outside family/child locks, exactly once in either ordering.
    pub fn on_reap(&self, retire: Box<dyn FnOnce() + Send>) {
        let mut state = self.0.lock().unwrap();
        if state.reaped {
            drop(state);
            retire();
        } else {
            // A nonleader exec may replace a retired leader and keep its wait event.
            state.on_reap = Some(match state.on_reap.take() {
                Some(previous) => Box::new(move || {
                    previous();
                    retire();
                }),
                None => retire,
            });
        }
    }

    pub fn bind_birth(
        &self,
        presence: &Arc<crate::task::Presence>,
        owner: &Arc<crate::task_parent::Parentage>,
        signal: ExitSignal,
    ) {
        let mut state = self.0.lock().unwrap();
        state.presence = presence.visibility();
        state.owner = Some(owner.clone());
        state.exit_signal = signal;
    }
    pub fn exit_signal(&self) -> ExitSignal {
        self.0.lock().unwrap().exit_signal
    }
    pub fn exec(&self) {
        let mut state = self.0.lock().unwrap();
        if state.exit_signal.signo != 17 {
            state.exit_signal = ExitSignal::default();
            let parent = state.parent.upgrade();
            drop(state);
            if let Some(parent) = parent {
                parent.changed.notify_locked();
            }
        }
    }
    pub(crate) fn bind_usage(
        &self,
        group: &Arc<crate::task_control::Group>,
        children: &Arc<Children>,
    ) {
        let mut state = self.0.lock().unwrap();
        state.group_usage = Arc::downgrade(group);
        state.children_usage = Arc::downgrade(children);
    }
    pub fn uid(&self) -> u32 {
        self.0.lock().unwrap().credentials.read().uid
    }
    pub fn bind_credentials(&self, credentials: Arc<trames_vfs::CredentialState>) {
        self.0.lock().unwrap().credentials = credentials;
    }
    pub(crate) fn parent_group(&self) -> Option<Arc<crate::task_control::Group>> {
        self.0.lock().unwrap().parent_group.upgrade()
    }
    pub(crate) fn bind_parent_group(&self, parent: Option<&Arc<crate::task_control::Group>>) {
        self.0.lock().unwrap().parent_group = parent.map_or_else(Weak::new, Arc::downgrade);
    }
    pub fn bind_presence(&self, presence: &Arc<crate::task::Presence>) {
        self.0.lock().unwrap().presence = presence.visibility();
    }
    /// Parentage changes are structural lifecycle operations. Never hold a
    /// child lock while acquiring a parent's membership lock or calling wakes.
    pub fn attach(self: &Arc<Self>, parent: Option<&Arc<Children>>, id: u32, group: u32, uid: u32) {
        let signal_parent = self.parent_group();
        let credentials = Arc::new(trames_vfs::CredentialState::new(
            trames_vfs::Credentials::user(uid, 0),
        ));
        for notice in self.attach_quiet(
            parent,
            signal_parent.as_ref(),
            id,
            group,
            &credentials,
            None,
        ) {
            notice.notify();
        }
    }
    pub(crate) fn attach_quiet(
        self: &Arc<Self>,
        parent: Option<&Arc<Children>>,
        signal_parent: Option<&Arc<crate::task_control::Group>>,
        id: u32,
        group: u32,
        credentials: &Arc<trames_vfs::CredentialState>,
        adopter: Option<u32>,
    ) -> Vec<Notice> {
        let mut notices = Vec::new();
        let (previous, previous_id) = {
            let mut state = self.0.lock().unwrap();
            if let Some(tid) = adopter {
                if let Some(owner) = &state.owner {
                    owner.set_parent_thread(tid);
                }
                state.exit_signal = Default::default();
            }
            let previous_id = state.id;
            let group_changed = state.group != group;
            state.id = id;
            state.group = group;
            state.credentials = credentials.clone();
            state.parent_group = signal_parent.map_or_else(Weak::new, Arc::downgrade);
            let next = parent.map_or_else(Weak::new, Arc::downgrade);
            if Weak::ptr_eq(&state.parent, &next) {
                drop(state);
                if group_changed {
                    if let Some(parent) = parent {
                        notices.push(Notice(Some(parent.clone()), Weak::new(), Vec::new()));
                    }
                }
                return notices;
            }
            state.traced_by_parent = false;
            state.trap = None;
            (std::mem::replace(&mut state.parent, next), previous_id)
        };
        if let Some(old) = previous.upgrade() {
            old.entries.lock().unwrap().remove(&previous_id);
            notices.push(Notice(Some(old), Weak::new(), Vec::new()));
        }
        if let Some(parent) = parent {
            if let Some(group) = signal_parent {
                group.bind_wait_children(parent);
            }
            parent
                .entries
                .lock()
                .unwrap()
                .insert(id, Arc::downgrade(self));
            notices.push(Notice(Some(parent.clone()), Weak::new(), Vec::new()));
        }
        notices
    }
    fn publish_quiet(&self, status: Option<i32>, exited: bool) -> Notice {
        let parent = {
            let mut state = self.0.lock().unwrap();
            // A consumed exit belongs to this original child, never a later
            // projection refresh or a process that happens to reuse its PID.
            if state.reaped || state.exited {
                return Notice(None, Weak::new(), Vec::new());
            }
            let stopped = !exited && status.is_some_and(|s| s != 0xffff);
            if status.is_some() && !exited && state.stopped == stopped {
                return Notice(None, Weak::new(), Vec::new());
            }
            if exited {
                state.trap = None;
            }
            state.stopped = stopped;
            state.event = status;
            state.exited = exited;
            (
                state.parent.upgrade(),
                state.parent_group.clone(),
                exited.then(|| state.pidfd.clone()).flatten(),
            )
        };
        let mut callbacks: Vec<OnReap> = Vec::new();
        if let Some(pid) = parent.2 {
            callbacks.push(Box::new(move || pid.publish(false)));
        }
        Notice(parent.0, parent.1, callbacks)
    }
    fn publish(&self, status: Option<i32>, exited: bool) {
        self.publish_quiet(status, exited).notify();
    }
    pub(crate) fn trace_by_parent(&self, parent: &Arc<Children>) -> Result<Notice, Errno> {
        let mut state = self.0.lock().unwrap();
        if state.reaped || state.exited || state.parent.as_ptr() != Arc::as_ptr(parent) {
            return Err(Errno(3));
        }
        state.traced_by_parent = true;
        Ok(Notice(Some(parent.clone()), Weak::new(), Vec::new()))
    }
    pub(crate) fn detach_trace(&self) -> Notice {
        let mut state = self.0.lock().unwrap();
        state.trap = None;
        state.traced_by_parent = false;
        Notice(state.parent.upgrade(), Weak::new(), Vec::new())
    }
    pub(crate) fn trace_event(&self, signal: Option<i32>) -> Notice {
        let mut state = self.0.lock().unwrap();
        if !state.traced_by_parent || state.exited || state.reaped {
            return Notice(None, Weak::new(), Vec::new());
        }
        state.trap = signal.map(|s| (s << 8) | 0x7f);
        Notice(
            state.parent.upgrade(),
            state.parent_group.clone(),
            Vec::new(),
        )
    }
    pub(crate) fn stopped_quiet(&self, signal: u32) -> Notice {
        self.publish_quiet(Some(((signal as i32) << 8) | 0x7f), false)
    }
    pub(crate) fn continued_quiet(&self) -> Notice {
        self.publish_quiet(Some(0xffff), false)
    }
    pub fn stopped(&self, signal: u32) {
        self.publish(Some(((signal as i32) << 8) | 0x7f), false);
    }
    pub fn continued(&self) {
        self.publish(Some(0xffff), false);
    }
    pub fn exited(&self, status: i32) {
        self.publish(Some(status), true);
    }
    /// Complete once, or re-notify an already exited child after adoption.
    /// Parent identity, status and automatic reaping form one child transaction.
    pub(crate) fn finish_quiet(
        &self,
        status: Option<i32>,
        parent: Option<(bool, u64)>,
        usage: Option<crate::usage::Usage>,
    ) -> Option<(Notice, u32, i32)> {
        let mut state = self.0.lock().unwrap();
        if state.reaped || status.is_some() == state.exited {
            return None;
        }
        if let Some(usage) = usage {
            state.exit_usage = usage;
        }
        let status = status.or(state.event)?;
        state.exited = true;
        state.stopped = false;
        state.event = Some(status);
        state.trap = None;
        let signo = parent.map_or(state.exit_signal.signo, |(_, image)| {
            state.exit_signal.delivered(image)
        });
        let auto_reap =
            !state.traced_by_parent && signo == 17 && parent.is_some_and(|(auto, _)| auto);
        let parent = state.parent.upgrade();
        if auto_reap {
            state.reaped = true;
            state.event = None;
            state.presence.reap();
            if let Some(parent) = &parent {
                parent.reaped.store(true, Ordering::Relaxed);
            }
        }
        let mut cleanup: Vec<OnReap> = if auto_reap {
            state.on_reap.take().into_iter().collect()
        } else {
            Vec::new()
        };
        if let Some(pid) = state.pidfd.clone() {
            cleanup.push(Box::new(move || pid.publish(auto_reap)));
        }
        Some((
            Notice(parent, state.parent_group.clone(), cleanup),
            signo,
            status,
        ))
    }
    pub fn clear(&self) {
        self.publish(None, false);
    }
    pub fn pending(&self) -> Option<i32> {
        self.0.lock().unwrap().event
    }
    pub fn reaped(&self) -> bool {
        self.0.lock().unwrap().reaped
    }
}

const WNOTHREAD: u64 = 0x2000_0000;
const WALL: u64 = 0x4000_0000;
const WCLONE: u64 = 0x8000_0000;

/// Accepted ABI, retained with the sleeping task rather than replayed by an owner.
#[derive(Clone, Copy, Debug)]
pub struct Wait {
    caller: u32,
    pidfd_target: u32,
    nonblocking_pidfd: bool,
    pub number: u32,
    pub args: [u64; 6],
}
impl Wait {
    pub fn prepare(caller: u32, number: u32, args: [u64; 6]) -> Result<Self, Errno> {
        Self::parse(caller, number, args, false)
    }
    fn parse(caller: u32, number: u32, args: [u64; 6], allow_pidfd: bool) -> Result<Self, Errno> {
        match number {
            260 => {
                if args[2] as u32 & !(11 | (WNOTHREAD | WALL | WCLONE) as u32) != 0 {
                    return Err(Errno(22));
                }
            }
            95 => {
                let which = args[0] as u32;
                let id = args[1] as i32;
                let options = args[3] as u32;
                if options & !(15 | 0x01000000 | (WNOTHREAD | WALL | WCLONE) as u32) != 0
                    || options & 14 == 0
                    || which > 3
                    || (which == 3 && !allow_pidfd)
                    || which != 0 && id < 0
                    || which == 1 && id == 0
                {
                    return Err(Errno(22));
                }
            }
            _ => return Err(Errno(38)),
        };
        Ok(Self {
            caller,
            pidfd_target: 0,
            nonblocking_pidfd: false,
            number,
            args,
        })
    }
    pub fn prepare_with_files(
        caller: u32,
        number: u32,
        args: [u64; 6],
        files: &trames_vfs::FdFlags,
        namespace: &PidNamespace,
    ) -> Result<Self, Errno> {
        if number != 95 || args[0] as u32 != 3 {
            return Self::prepare(caller, number, args);
        }
        let mut request = Self::parse(caller, number, args, true)?;
        let (target, nonblocking) = files.pidfd(args[1] as u32)?;
        if namespace.local(target.pid()) == 0 {
            return Err(Errno(10));
        }
        // Retain the session-global, never-reused child ID across a parked wait.
        request.pidfd_target = target.pid();
        request.nonblocking_pidfd = nonblocking;
        Ok(request)
    }
    fn options(&self) -> u64 {
        if self.number == 260 {
            self.args[2] as u32 as u64 | 4
        } else {
            self.args[3] as u32 as u64
        }
    }
    fn event_code(&self, state: &State) -> Option<i32> {
        if state.trap.is_some() && (self.number == 260 || self.options() & 2 != 0) {
            return Some(4); // CLD_TRAPPED
        }
        let status = state.event?;
        let options = self.options();
        if state.exited && options & 4 != 0 {
            Some(if status & 127 == 0 { 1 } else { 2 })
        } else if !state.exited && status == 0xffff && options & 8 != 0 {
            Some(6)
        } else if !state.exited && status != 0xffff && options & 2 != 0 {
            Some(5)
        } else {
            None
        }
    }
    fn matches(&self, child: &State, namespace: &PidNamespace, group: u32) -> bool {
        // An exited group can no longer generate stop or continue events.
        let options = self.options();
        if child.exited && options & 4 == 0
            || options & WNOTHREAD != 0
                && !child
                    .owner
                    .as_ref()
                    .is_some_and(|owner| owner.parent_thread() == self.caller)
            || !child.traced_by_parent
                && options & WALL == 0
                && (options & WCLONE != 0) != (child.exit_signal.signo != 17)
        {
            return false;
        }
        if self.number == 260 {
            let target = self.args[0] as i32;
            target == -1
                || target == 0 && child.group == group
                || target < -1 && namespace.local(child.group) == target.unsigned_abs()
                || target > 0 && namespace.local(child.id) == target as u32
        } else {
            match self.args[0] as u32 {
                0 => true,
                1 => namespace.local(child.id) == self.args[1] as u32,
                3 => child.id == self.pidfd_target,
                _ if self.args[1] == 0 => child.group == group,
                _ => namespace.local(child.group) == self.args[1] as u32,
            }
        }
    }
}
impl Children {
    pub(crate) fn thread_children(
        self: &Arc<Self>,
        tid: u32,
        namespace: &PidNamespace,
    ) -> Vec<u32> {
        let entries = self.entries.lock().unwrap();
        let mut ids = Vec::new();
        for child in entries.values().filter_map(Weak::upgrade) {
            let state = child.0.lock().unwrap();
            if !state.reaped
                && state.parent.as_ptr() == Arc::as_ptr(self)
                && state
                    .owner
                    .as_ref()
                    .is_some_and(|o| o.parent_thread() == tid)
            {
                let local = namespace.local(state.id);
                if local != 0 {
                    ids.push(local);
                }
            }
        }
        ids
    }

    /// Include zombies: their original task is already absent from the live
    /// parent-death-signal graph, but their parent thread can still change.
    pub(crate) fn transfer_owner(self: &Arc<Self>, old: u32, new: u32) -> Option<Notice> {
        let entries = self.entries.lock().unwrap();
        let mut moved = false;
        for child in entries.values().filter_map(Weak::upgrade) {
            let state = child.0.lock().unwrap();
            let Some(owner) = &state.owner else { continue };
            if owner.parent_thread() == old
                && !state.reaped
                && state.parent.as_ptr() == Arc::as_ptr(self)
            {
                owner.set_parent_thread(new);
                moved = true;
            }
        }
        moved.then(|| Notice(Some(self.clone()), Weak::new(), Vec::new()))
    }
    pub(crate) fn usage(&self) -> crate::usage::Usage {
        *self.collected.lock().unwrap()
    }
    pub fn take_reaped(&self) -> bool {
        self.reaped.load(Ordering::Relaxed) && self.reaped.swap(false, Ordering::Relaxed)
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.changed.subscribe(signal)
    }
    pub fn ready(self: &Arc<Self>, request: Wait, namespace: &PidNamespace, group: u32) -> bool {
        let entries = self.entries.lock().unwrap();
        let mut found = false;
        for child in entries.values().filter_map(Weak::upgrade) {
            let state = child.0.lock().unwrap();
            if !state.reaped
                && state.parent.as_ptr() == Arc::as_ptr(self)
                && request.matches(&state, namespace, group)
            {
                found = true;
                if request.event_code(&state).is_some() {
                    return true;
                }
            }
        }
        !found
    }
    /// A terminating PID-namespace init consumes its own exited children after
    /// all original namespace victims have completed. Outer parents' queues
    /// are separate and retain their real wait rights. No callback runs here.
    pub(crate) fn reap_exited(self: &Arc<Self>) -> Option<Notice> {
        let entries = self.entries.lock().unwrap();
        let mut changed = false;
        let mut cleanup = Vec::new();
        for child in entries.values().filter_map(Weak::upgrade) {
            let mut state = child.0.lock().unwrap();
            if !state.reaped && state.exited && state.parent.as_ptr() == Arc::as_ptr(self) {
                state.reaped = true;
                state.event = None;
                self.collected.lock().unwrap().include(state.exit_usage);
                state.presence.reap();
                cleanup.extend(state.on_reap.take());
                if let Some(pid) = state.pidfd.clone() {
                    cleanup.push(Box::new(move || pid.publish(true)));
                }
                changed = true;
            }
        }
        if changed {
            self.reaped.store(true, Ordering::Relaxed);
            Some(Notice(Some(self.clone()), Weak::new(), cleanup))
        } else {
            None
        }
    }
    pub fn wait(
        self: &Arc<Self>,
        request: Wait,
        namespace: &PidNamespace,
        group: u32,
        memory: &mut impl CpuMemory,
    ) -> Result<Option<u64>, Errno> {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, child| child.strong_count() != 0);
        let mut found = false;
        let options = request.options();
        for child in entries.values().filter_map(Weak::upgrade) {
            let mut state = child.0.lock().unwrap();
            if state.reaped
                || state.parent.as_ptr() != Arc::as_ptr(self)
                || !request.matches(&state, namespace, group)
            {
                continue;
            }
            found = true;
            let Some(code) = request.event_code(&state) else {
                continue;
            };
            let status =
                if code == 4 { state.trap } else { state.event }.expect("selected wait event");
            let local = namespace.local(state.id);
            // Only waitid with a siginfo destination observes the UID.
            let siginfo = (request.number == 95 && request.args[2] != 0)
                .then(|| (request.args[2], state.credentials.read().uid));
            let mut usage = state.exit_usage;
            let usage_pointer = if request.number == 260 {
                request.args[3]
            } else {
                request.args[4]
            };
            let live_usage = (!state.exited && usage_pointer != 0)
                .then(|| (state.group_usage.upgrade(), state.children_usage.upgrade()));
            let mut cleanup = None;
            if options & 0x01000000 == 0 {
                state.reaped = state.exited;
                if code == 4 {
                    state.trap = None;
                } else {
                    state.event = None;
                }
                if state.reaped {
                    self.collected.lock().unwrap().include(usage);
                    self.reaped.store(true, Ordering::Relaxed);
                    state.presence.reap();
                    cleanup = state.on_reap.take();
                }
            }
            // A second waiting thread must see the consumed event/ECHILD.
            // Callbacks can enter these objects, so release both locks first.
            let pidfd = state.reaped.then(|| state.pidfd.clone()).flatten();
            drop(state);
            drop(entries);
            if let Some(pid) = pidfd {
                pid.publish(true);
            }
            if let Some(retire) = cleanup {
                retire();
            }
            if options & 0x01000000 == 0 {
                self.changed.notify_locked();
            }
            if let Some((Some(group), children)) = live_usage {
                usage = group.usage();
                if let Some(task) = group.live_task() {
                    if let Some(mm) = task.proc_view.memory_report() {
                        usage.peak_bytes = usage.peak_bytes.max(mm.peak_resident_bytes());
                    }
                }
                if let Some(children) = children {
                    usage.include(children.usage());
                }
            }
            let a = request.args;
            if request.number == 260 {
                if a[1] != 0 {
                    memory
                        .write_array(a[1], status.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if a[3] != 0 {
                    usage.write(memory, a[3])?;
                }
            } else {
                // Linux waitid copies rusage before siginfo. A copyout error
                // does not undo an already consumed event (except WNOWAIT).
                if a[4] != 0 {
                    usage.write(memory, a[4])?;
                }
                if let Some((destination, uid)) = siginfo {
                    let mut bytes = [0; 128];
                    bytes[..4].copy_from_slice(&17u32.to_le_bytes());
                    bytes[8..12].copy_from_slice(&code.to_le_bytes());
                    bytes[16..20].copy_from_slice(&local.to_le_bytes());
                    bytes[20..24].copy_from_slice(&uid.to_le_bytes());
                    let value = match code {
                        1 | 4 | 5 => status >> 8,
                        6 => 18,
                        _ => status & 127,
                    };
                    bytes[24..28].copy_from_slice(&value.to_le_bytes());
                    memory
                        .write_array(destination, bytes)
                        .map_err(|_| Errno(14))?;
                }
            }
            return Ok(Some(if request.number == 260 {
                local as u64
            } else {
                0
            }));
        }
        drop(entries);
        if !found {
            return Err(Errno(10));
        }
        if request.nonblocking_pidfd && options & 1 == 0 {
            return Err(Errno(11));
        }
        if options & 1 != 0 {
            if request.number == 95 && request.args[2] != 0 {
                memory
                    .write_array(request.args[2], [0; 128])
                    .map_err(|_| Errno(14))?;
            }
            Ok(Some(0))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    fn memory() -> Memory {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory
    }
    fn child(family: &Arc<Children>, id: u32, group: u32) -> Arc<Child> {
        let child = Arc::new(Child::default());
        child.attach(Some(family), id, group, 1234);
        child
    }
    fn wait4(options: u64) -> Wait {
        Wait {
            caller: 1,
            pidfd_target: 0,
            nonblocking_pidfd: false,
            number: 260,
            args: [u32::MAX as u64, 0x1000, options, 0x1100, 0, 0],
        }
    }
    fn waitid(options: u64) -> Wait {
        Wait {
            caller: 1,
            pidfd_target: 0,
            nonblocking_pidfd: false,
            number: 95,
            args: [0, 0, 0x1000, options, 0x1100, 0],
        }
    }
    #[test]
    fn validation_no_children_and_nohang_outputs_preserve_the_abi() {
        let family = Arc::new(Children::default());
        let mut memory = memory();
        let ns = PidNamespace::default();
        for request in [
            wait4(4),
            waitid(0),
            Wait {
                args: [3, 0, 0, 4, 0, 0],
                ..waitid(4)
            },
        ] {
            assert_eq!(
                Wait::prepare(1, request.number, request.args).unwrap_err(),
                Errno(22)
            );
        }
        assert_eq!(family.wait(wait4(1), &ns, 1, &mut memory), Err(Errno(10)));
        let _child = child(&family, 42, 7);
        memory.write_array(0x1000, [0xff; 128]).unwrap();
        assert_eq!(family.wait(waitid(5), &ns, 1, &mut memory), Ok(Some(0)));
        assert_eq!(memory.read_array::<128>(0x1000).unwrap(), [0; 128]);
        assert_eq!(family.wait(wait4(0), &ns, 1, &mut memory), Ok(None));
    }
    #[test]
    fn parked_pidfd_wait_keeps_original_child_after_close_and_slot_reuse() {
        use trames_vfs::{DirectPoll, Vfs};
        let mut vfs = Vfs::default();
        let family = Arc::new(Children::default());
        let first = child(&family, 42, 1);
        let second = child(&family, 43, 1);
        let handle = first.pidfd(42);
        let files = vfs.descriptor_factory();
        let fd = files
            .reserve_pidfd(handle.clone(), 0)
            .unwrap()
            .publish()
            .unwrap();
        let args = [3, u64::from(fd), 0x1000, 4, 0, 0];
        let ns = PidNamespace::default();
        let wait = Wait::prepare_with_files(1, 95, args, &vfs.fd_flags_snapshot(), &ns).unwrap();
        assert_eq!(wait.args, args); // Original registers are required for SA_RESTART.
        let mut mem = memory();
        assert_eq!(family.wait(wait, &ns, 1, &mut mem), Ok(None));
        vfs.close(fd).unwrap();
        assert_eq!(
            files
                .reserve_pidfd(second.pidfd(43), 0)
                .unwrap()
                .publish()
                .unwrap(),
            fd
        );
        second.exited(0);
        assert_eq!(family.wait(wait, &ns, 1, &mut mem), Ok(None));
        first.exited(7 << 8);
        assert_eq!(handle.poll(1).0, 1);
        assert_eq!(family.wait(wait, &ns, 1, &mut mem), Ok(Some(0)));
        assert_eq!(handle.poll(1).0, 0x11);
        assert_eq!(
            &mem.read_array::<128>(0x1000).unwrap()[16..20],
            &42u32.to_le_bytes()
        );
        assert!(!second.reaped());
    }
    #[test]
    fn stop_continue_events_are_consumed_once_per_group_transition() {
        let family = Arc::new(Children::default());
        let child = child(&family, 42, 7);
        let mut memory = memory();
        let ns = PidNamespace::default();
        child.stopped(19);
        assert_eq!(family.wait(wait4(3), &ns, 1, &mut memory), Ok(Some(42)));
        assert_eq!(
            memory.read_array::<4>(0x1000).unwrap(),
            0x137fi32.to_le_bytes()
        );
        child.stopped(19); // another member acknowledges the same group stop
        assert_eq!(family.wait(wait4(3), &ns, 1, &mut memory), Ok(Some(0)));
        child.continued();
        assert_eq!(family.wait(waitid(9), &ns, 1, &mut memory), Ok(Some(0)));
        let info = memory.read_array::<128>(0x1000).unwrap();
        assert_eq!(&info[8..12], &6i32.to_le_bytes());
        assert_eq!(&info[24..28], &18i32.to_le_bytes());
        child.continued();
        assert_eq!(family.wait(wait4(9), &ns, 1, &mut memory), Ok(Some(0)));
        child.stopped(20);
        assert_eq!(family.wait(wait4(3), &ns, 1, &mut memory), Ok(Some(42)));
    }
    #[test]
    fn nowait_retains_exit_identity_until_one_actual_consumer() {
        let family = Arc::new(Children::default());
        let child = child(&family, 42, 7);
        child.exited(23 << 8);
        let mut memory = memory();
        let ns = PidNamespace::default();
        for _ in 0..2 {
            assert_eq!(
                family.wait(waitid(4 | 0x01000000), &ns, 1, &mut memory),
                Ok(Some(0))
            );
            let info = memory.read_array::<128>(0x1000).unwrap();
            assert_eq!(&info[16..20], &42u32.to_le_bytes());
            assert_eq!(&info[20..24], &1234u32.to_le_bytes());
            assert_eq!(&info[24..28], &23i32.to_le_bytes());
            assert!(!child.reaped());
        }
        assert_eq!(family.wait(wait4(0), &ns, 1, &mut memory), Ok(Some(42)));
        assert!(child.reaped());
        child.exited(99 << 8);
        child.attach(Some(&family), 42, 7, 0);
        assert_eq!(family.wait(wait4(1), &ns, 1, &mut memory), Err(Errno(10)));
        let replacement = child_for_reuse(&family);
        replacement.exited(11);
        assert_eq!(family.wait(wait4(0), &ns, 1, &mut memory), Ok(Some(42)));
        assert_eq!(memory.read_array::<4>(0x1000).unwrap(), 11i32.to_le_bytes());
    }
    fn child_for_reuse(family: &Arc<Children>) -> Arc<Child> {
        child(family, 42, 7)
    }
    #[test]
    fn reap_cleanup_runs_outside_child_locks_in_both_registration_orders() {
        for before in [true, false] {
            let family = Arc::new(Children::default());
            let child = child(&family, 42, 7);
            child.exited(0);
            let (signal, received) = std::sync::mpsc::channel();
            let original = Arc::downgrade(&child);
            let mut cleanup = Some(Box::new(move || {
                assert!(original.upgrade().unwrap().reaped());
                signal.send(()).unwrap();
            }) as OnReap);
            if before {
                child.on_reap(cleanup.take().unwrap());
            }
            let mut memory = memory();
            let ns = PidNamespace::default();
            assert_eq!(
                family.wait(waitid(4 | 0x01000000), &ns, 1, &mut memory),
                Ok(Some(0))
            );
            assert!(received.try_recv().is_err());
            assert_eq!(family.wait(wait4(0), &ns, 1, &mut memory), Ok(Some(42)));
            if let Some(cleanup) = cleanup {
                child.on_reap(cleanup);
            }
            assert_eq!(received.try_recv(), Ok(()));
        }
    }

    #[test]
    fn failed_copyout_still_consumes_the_exit_like_native_linux() {
        let family = Arc::new(Children::default());
        let child = child(&family, 42, 7);
        let mut memory = memory();
        let request = Wait::prepare(1, 260, wait4(0).args).unwrap();
        memory.unmap(0x1000, PAGE_SIZE).unwrap();
        child.exited(17 << 8);
        assert_eq!(
            family.wait(request, &Default::default(), 1, &mut memory),
            Err(Errno(14))
        );
        assert!(child.reaped());
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        assert_eq!(
            family.wait(request, &Default::default(), 1, &mut memory),
            Err(Errno(10))
        );
    }
    #[test]
    fn copyout_order_and_nowait_faults_match_native_linux() {
        for number in [95, 260] {
            let family = Arc::new(Children::default());
            let child = child(&family, 42, 1);
            child.exited(7 << 8);
            let mut memory = memory();
            memory.write_array(0x1000, [0x55; 128]).unwrap();
            let request = Wait {
                caller: 1,
                pidfd_target: 0,
                nonblocking_pidfd: false,
                number,
                args: if number == 260 {
                    [42, 0x1000, 0, 1, 0, 0]
                } else {
                    [1, 42, 0x1000, 4, 1, 0]
                },
            };
            assert_eq!(
                family.wait(request, &Default::default(), 1, &mut memory),
                Err(Errno(14))
            );
            assert!(child.reaped());
            assert_eq!(
                memory.read_array::<4>(0x1000).unwrap(),
                if number == 260 {
                    (7i32 << 8).to_le_bytes()
                } else {
                    [0x55; 4]
                }
            );
        }
        let family = Arc::new(Children::default());
        let child = child(&family, 42, 1);
        child.exited(0);
        let mut memory = memory();
        let bad = Wait {
            caller: 1,
            pidfd_target: 0,
            nonblocking_pidfd: false,
            number: 95,
            args: [0, 0, 1, 4 | 0x01000000, 0, 0],
        };
        assert_eq!(
            family.wait(bad, &Default::default(), 1, &mut memory),
            Err(Errno(14))
        );
        assert!(!child.reaped());
        assert_eq!(
            family.wait(wait4(0), &Default::default(), 1, &mut memory),
            Ok(Some(42))
        );
    }
    #[test]
    fn scalar_wait_arguments_use_linux_int_widths_without_output_preflight() {
        let family = Arc::new(Children::default());
        let _child = child(&family, 42, 1);
        let mut memory = memory();
        for (number, args) in [
            (260, [42, 1, (1u64 << 32) | 1, 1, 0, 0]),
            (
                95,
                [
                    (1u64 << 32) | 1,
                    (1u64 << 32) | 42,
                    0x1000,
                    (1u64 << 32) | 5,
                    1,
                    0,
                ],
            ),
        ] {
            let request = Wait::prepare(1, number, args).unwrap();
            assert_eq!(
                family.wait(request, &Default::default(), 1, &mut memory),
                Ok(Some(0))
            );
        }
    }
    #[test]
    fn concurrent_parent_threads_cannot_reap_the_same_child_twice() {
        let family = Arc::new(Children::default());
        let child = child(&family, 42, 7);
        child.exited(0);
        let barrier = std::sync::Barrier::new(16);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    scope.spawn(|| {
                        let mut memory = memory();
                        barrier.wait();
                        family.wait(wait4(1), &Default::default(), 1, &mut memory)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|r| **r == Ok(Some(42))).count(), 1);
        assert_eq!(results.iter().filter(|r| **r == Err(Errno(10))).count(), 15);
    }
    #[test]
    fn reparenting_notifies_both_families_and_moves_wait_authority() {
        let old = Arc::new(Children::default());
        let new = Arc::new(Children::default());
        let child = child(&old, 42, 7);
        let target: Arc<dyn trames_vfs::IoWake> = Arc::new(Wake);
        let signal = IoSignal::new(1, Arc::downgrade(&target));
        let _subscription = old.subscribe(&signal);
        child.attach(Some(&new), 42, 7, 1234);
        assert!(signal.ready());
        child.exited(0);
        let mut memory = memory();
        assert_eq!(
            old.wait(wait4(1), &Default::default(), 1, &mut memory),
            Err(Errno(10))
        );
        assert_eq!(
            new.wait(wait4(1), &Default::default(), 1, &mut memory),
            Ok(Some(42))
        );
    }
    struct Wake;
    impl trames_vfs::IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    #[test]
    fn subscription_and_exit_race_always_observes_a_result_or_notification() {
        let family = Arc::new(Children::default());
        let children: Vec<_> = (2..1026).map(|id| child(&family, id, 7)).collect();
        let barrier = std::sync::Barrier::new(2);
        let target: Arc<dyn trames_vfs::IoWake> = Arc::new(Wake);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for child in &children {
                    barrier.wait();
                    child.exited(0);
                    barrier.wait();
                    barrier.wait();
                }
            });
            let mut memory = memory();
            for id in 2..1026 {
                let signal = IoSignal::new(1, Arc::downgrade(&target));
                barrier.wait();
                let subscription = family.subscribe(&signal);
                let request = Wait {
                    args: [id, 0x1000, 0, 0, 0, 0],
                    ..wait4(0)
                };
                let result = family.wait(request, &Default::default(), 1, &mut memory);
                barrier.wait();
                assert!(result == Ok(Some(id)) || result == Ok(None) && signal.ready());
                if result == Ok(None) {
                    assert_eq!(
                        family.wait(request, &Default::default(), 1, &mut memory),
                        Ok(Some(id))
                    );
                }
                drop(subscription);
                barrier.wait();
            }
        });
    }
    #[test]
    fn worker_reaping_hides_pid_from_signals_and_limits_before_owner_drop() {
        use crate::{
            limits::{Authority, Directory, Fixed, Limits},
            signal::{IoDirectory, IoRoutes, Signals},
        };
        let family = Arc::new(Children::default());
        let child = child(&family, 42, 1);
        let source = Signals::default();
        let target = Signals::default();
        let namespace = PidNamespace::default();
        source.publish_policy(&namespace, true);
        target.publish_policy(&namespace, true);
        let directory = Arc::new(IoDirectory::default());
        directory.publish(&source.io, 1, 1, 1, 0, 0);
        directory.publish(&target.io, 42, 42, 1, 0, 0);
        target.io.exit();
        child.bind_presence(&target.presence);
        child.exited(0);
        let routes = IoRoutes {
            directory,
            ..Default::default()
        };
        let vfs = trames_vfs::Vfs::default();
        let limits = Limits::new(&vfs);
        let limit_directory = Arc::new(Directory::default());
        target.io.credentials().publish(&vfs.credentials);
        limit_directory.publish(42, &target.presence, &limits, target.io.credentials());
        let authority = Authority {
            directory: limit_directory,
            limits: Limits::new(&vfs),
            namespace: namespace.clone(),
            pid: 1,
            credentials: vfs.credentials.clone(),
            fixed: Fixed {
                address_space: 1 << 30,
                stack: 1 << 20,
                tasks: 1024,
            },
        };
        let mut memory = memory();
        assert_eq!(
            routes.send(&source.io, 129, [42, 0, 0, 0, 0, 0]),
            Some(Ok(0))
        );
        assert_eq!(
            authority.call(261, [42, 7, 0, 0x1000, 0, 0], &mut memory),
            Ok(0)
        );
        assert_eq!(
            family.wait(wait4(0), &namespace, 1, &mut memory),
            Ok(Some(42))
        );
        assert_eq!(
            routes.send(&source.io, 129, [42, 0, 0, 0, 0, 0]),
            Some(Err(Errno(3)))
        );
        assert_eq!(
            authority.call(261, [42, 7, 0, 0x1000, 0, 0], &mut memory),
            Err(Errno(3))
        );
        assert!(!target.presence.present());
        assert_eq!(
            Arc::strong_count(&target.presence),
            1,
            "owner projection is still alive"
        );
    }

    #[test]
    fn wait_selection_and_siginfo_use_the_callers_pid_namespace() {
        let mut vfs = trames_vfs::Vfs::default();
        vfs.unshare_pid().unwrap();
        vfs.activate_child_pid(100).unwrap();
        let mut nested_child = vfs.clone();
        nested_child.activate_child_pid(200).unwrap();
        let family = Arc::new(Children::default());
        let child = child(&family, 200, 100);
        child.exited(0);
        let mut memory = memory();
        let request = Wait {
            args: [2, 1, 0x1000, 4, 0, 0],
            ..waitid(4)
        };
        assert_eq!(
            family.wait(request, vfs.pid_namespace(), 100, &mut memory),
            Ok(Some(0))
        );
        assert_eq!(
            &memory.read_array::<128>(0x1000).unwrap()[16..20],
            &2u32.to_le_bytes()
        );
    }
}
