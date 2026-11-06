// SPDX-License-Identifier: GPL-3.0-or-later
//! Original group termination readiness; no task body or executor is owned here.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use trames_kernel::task_control::Group;
use trames_shared::{IoSignal, IoSubscription, IoWake, Readiness};

#[derive(Default)]
pub(crate) struct ExitGroups {
    groups: Mutex<Groups>,
    ready: Arc<Readiness>,
}
#[derive(Default)]
struct Groups {
    watches: BTreeMap<usize, Watch>,
    pending: BTreeSet<usize>,
}
struct Watch {
    group: Weak<Group>,
    signal: Arc<IoSignal>,
    _subscription: IoSubscription,
    _target: Arc<dyn IoWake>,
}
struct GroupWake {
    key: usize,
    groups: Weak<ExitGroups>,
}
impl IoWake for GroupWake {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        if let Some(groups) = self.groups.upgrade() {
            groups.request(self.key);
        }
    }
}
impl IoWake for ExitGroups {
    fn wake_io(&self, _: &Arc<IoSignal>) {
        self.ready.notify_atomic();
    }
}
impl ExitGroups {
    fn request(&self, key: usize) {
        self.groups.lock().unwrap().pending.insert(key);
        self.ready.notify_atomic();
    }
    pub fn watch(self: &Arc<Self>, group: &Arc<Group>) {
        let key = Arc::as_ptr(group) as usize;
        if self.groups.lock().unwrap().watches.contains_key(&key) {
            return;
        }
        let target: Arc<dyn IoWake> = Arc::new(GroupWake {
            key,
            groups: Arc::downgrade(self),
        });
        let signal = IoSignal::new(0, Arc::downgrade(&target));
        let subscription = group.subscribe_exit(&signal);
        let watch = Watch {
            group: Arc::downgrade(group),
            signal: signal.clone(),
            _subscription: subscription,
            _target: target,
        };
        let mut groups = self.groups.lock().unwrap();
        let old = match groups.watches.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(watch);
                None
            }
            std::collections::btree_map::Entry::Occupied(_) => Some(watch),
        };
        drop(groups);
        drop(old);
        if signal.ready() {
            self.request(key);
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        let subscription = self.ready.subscribe(signal);
        // A new epoch retries terminal groups, including a previous executor's
        // cancelled custody/borrow wait. Actual task identities are revalidated.
        let groups: Vec<_> = self
            .groups
            .lock()
            .unwrap()
            .watches
            .values()
            .filter_map(|watch| watch.group.upgrade().map(|g| (g, watch.signal.clone())))
            .collect();
        for (group, wake) in groups {
            if group.termination().is_some() {
                wake.reset();
                wake.notify();
            }
        }
        subscription
    }
    pub fn take(&self) -> Vec<Arc<Group>> {
        let mut result = Vec::new();
        let mut groups = self.groups.lock().unwrap();
        let pending = std::mem::take(&mut groups.pending);
        let mut dead = Vec::new();
        for key in pending {
            let Some(watch) = groups.watches.get(&key) else {
                continue;
            };
            watch.signal.reset();
            if let Some(group) = watch.group.upgrade() {
                result.push(group);
            } else {
                dead.push(key);
            }
        }
        let removed: Vec<_> = dead
            .into_iter()
            .filter_map(|key| groups.watches.remove(&key))
            .collect();
        drop(groups);
        drop(removed);
        result
    }
    pub fn notify(&self) {
        self.ready.notify_atomic();
    }
    pub fn retire(&self, group: &Arc<Group>) {
        let key = Arc::as_ptr(group) as usize;
        let removed = {
            let mut groups = self.groups.lock().unwrap();
            groups.pending.remove(&key);
            groups.watches.remove(&key)
        };
        drop(removed);
    }
}
