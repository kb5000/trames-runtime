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
}
#[derive(Default)]
pub struct Child(Mutex<State>);
#[derive(Default)]
struct State {
    id: u32,
    group: u32,
    uid: u32,
    parent: Weak<Children>,
    event: Option<i32>,
    stopped: bool,
    exited: bool,
    reaped: bool,
    presence: crate::task::Visibility,
}
impl Child {
    pub fn bind_presence(&self, presence: &Arc<crate::task::Presence>) {
        self.0.lock().unwrap().presence = presence.visibility();
    }
    /// Parentage changes are structural lifecycle operations. Never hold a
    /// child lock while acquiring a parent's membership lock or calling wakes.
    pub fn attach(self: &Arc<Self>, parent: Option<&Arc<Children>>, id: u32, group: u32, uid: u32) {
        let (previous, previous_id) = {
            let mut state = self.0.lock().unwrap();
            let previous_id = state.id;
            let group_changed = state.group != group;
            state.id = id;
            state.group = group;
            state.uid = uid;
            let next = parent.map_or_else(Weak::new, Arc::downgrade);
            if Weak::ptr_eq(&state.parent, &next) {
                drop(state);
                if group_changed {
                    if let Some(parent) = parent {
                        parent.changed.notify_locked();
                    }
                }
                return;
            }
            (std::mem::replace(&mut state.parent, next), previous_id)
        };
        if let Some(old) = previous.upgrade() {
            old.entries.lock().unwrap().remove(&previous_id);
            old.changed.notify_locked();
        }
        if let Some(parent) = parent {
            parent
                .entries
                .lock()
                .unwrap()
                .insert(id, Arc::downgrade(self));
            parent.changed.notify_locked();
        }
    }
    fn publish(&self, status: Option<i32>, exited: bool) {
        let parent = {
            let mut state = self.0.lock().unwrap();
            // A consumed exit belongs to this original child, never a later
            // projection refresh or a process that happens to reuse its PID.
            if state.reaped || state.exited {
                return;
            }
            let stopped = !exited && status.is_some_and(|s| s != 0xffff);
            if status.is_some() && !exited && state.stopped == stopped {
                return;
            }
            state.stopped = stopped;
            state.event = status;
            state.exited = exited;
            state.parent.upgrade()
        };
        if let Some(parent) = parent {
            parent.changed.notify_locked();
        }
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

/// Accepted ABI, retained with the sleeping task rather than replayed by an owner.
#[derive(Clone, Copy, Debug)]
pub struct Wait {
    pub number: u32,
    pub args: [u64; 6],
}
impl Wait {
    pub fn prepare(number: u32, args: [u64; 6]) -> Result<Self, Errno> {
        match number {
            260 => {
                if args[2] as u32 & !(11 | 0x40000000) != 0 {
                    return Err(Errno(22));
                }
            }
            95 => {
                let which = args[0] as u32;
                let id = args[1] as i32;
                let options = args[3] as u32;
                if options & !(15 | 0x01000000 | 0x40000000) != 0
                    || options & 14 == 0
                    || which > 2
                    || which != 0 && id < 0
                    || which == 1 && id == 0
                {
                    return Err(Errno(22));
                }
            }
            _ => return Err(Errno(38)),
        };
        Ok(Self { number, args })
    }
    fn options(&self) -> u64 {
        if self.number == 260 {
            self.args[2] as u32 as u64 | 4
        } else {
            self.args[3] as u32 as u64
        }
    }
    fn event_code(&self, state: &State) -> Option<i32> {
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
                _ if self.args[1] == 0 => child.group == group,
                _ => namespace.local(child.group) == self.args[1] as u32,
            }
        }
    }
}
impl Children {
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
                && Weak::ptr_eq(&state.parent, &Arc::downgrade(self))
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
                || !Weak::ptr_eq(&state.parent, &Arc::downgrade(self))
                || !request.matches(&state, namespace, group)
            {
                continue;
            }
            found = true;
            let Some(status) = state.event else { continue };
            let Some(code) = request.event_code(&state) else {
                continue;
            };
            let local = namespace.local(state.id);
            let uid = state.uid;
            if options & 0x01000000 == 0 {
                state.reaped = state.exited;
                state.event = None;
                if state.reaped {
                    self.reaped.store(true, Ordering::Relaxed);
                    state.presence.reap();
                }
            }
            // A second waiting thread must see the consumed event/ECHILD.
            // Callbacks can enter these objects, so release both locks first.
            drop(state);
            drop(entries);
            if options & 0x01000000 == 0 {
                self.changed.notify_locked();
            }
            let a = request.args;
            if request.number == 260 {
                if a[1] != 0 {
                    memory
                        .write_array(a[1], status.to_le_bytes())
                        .map_err(|_| Errno(14))?;
                }
                if a[3] != 0 {
                    memory.write_array(a[3], [0; 144]).map_err(|_| Errno(14))?;
                }
            } else {
                // Linux waitid copies rusage before siginfo. A copyout error
                // does not undo an already consumed event (except WNOWAIT).
                if a[4] != 0 {
                    memory.write_array(a[4], [0; 144]).map_err(|_| Errno(14))?;
                }
                if a[2] != 0 {
                    let mut bytes = [0; 128];
                    bytes[..4].copy_from_slice(&17u32.to_le_bytes());
                    bytes[8..12].copy_from_slice(&code.to_le_bytes());
                    bytes[16..20].copy_from_slice(&local.to_le_bytes());
                    bytes[20..24].copy_from_slice(&uid.to_le_bytes());
                    let value = match code {
                        1 | 5 => status >> 8,
                        6 => 18,
                        _ => status & 127,
                    };
                    bytes[24..28].copy_from_slice(&value.to_le_bytes());
                    memory.write_array(a[2], bytes).map_err(|_| Errno(14))?;
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
            number: 260,
            args: [u32::MAX as u64, 0x1000, options, 0x1100, 0, 0],
        }
    }
    fn waitid(options: u64) -> Wait {
        Wait {
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
                Wait::prepare(request.number, request.args).unwrap_err(),
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
    fn failed_copyout_still_consumes_the_exit_like_native_linux() {
        let family = Arc::new(Children::default());
        let child = child(&family, 42, 7);
        let mut memory = memory();
        let request = Wait::prepare(260, wait4(0).args).unwrap();
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
            let request = Wait::prepare(number, args).unwrap();
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
        limit_directory.publish(42, &target.presence, &limits, &vfs.credentials);
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
