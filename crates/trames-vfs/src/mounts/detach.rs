// SPDX-License-Identifier: GPL-3.0-or-later
//! Reverse dentry invalidation uses original mount resources and namespace
//! admission. A contended namespace returns its readiness to the existing caller.
use super::*;
use std::collections::{BTreeSet, VecDeque};

pub(crate) struct Invalidate {
    registry: registry::Snapshot,
    policy: Arc<MountPolicy>,
    detached: Arc<SharedCell<Vec<Vec<Arc<Mount>>>>>,
}
struct Plan {
    mounts: Vec<Arc<Mount>>,
    parents: BTreeMap<u64, Option<Attachment>>,
    children: BTreeMap<u64, Vec<u64>>,
    removed: BTreeSet<u64>,
    namespaces: Vec<MountNamespace>,
    admins: Vec<Arc<admin::Admin>>,
}
impl Invalidate {
    pub(crate) fn capture(v: &Vfs) -> Self {
        Self {
            registry: v.mount_registry.snapshot(),
            policy: v.pseudo.borrow().mount_policy.clone(),
            detached: v.detached_mounts.clone(),
        }
    }
    fn plan(&self, entry: &Arc<fuse::Entry>) -> Plan {
        // Read draft ownership before registry/namespace observation, retaining
        // this short index read through weak namespace upgrades. A publisher
        // registers its original admission before it can retire source trees.
        let publishing = self.registry.publishing();
        let mounts = self.registry.mounts();
        let parents: BTreeMap<_, _> = mounts
            .iter()
            .map(|mount| (mount.id, mount.parent.borrow().clone()))
            .collect();
        let mut children = BTreeMap::<u64, Vec<u64>>::new();
        let mut queue = VecDeque::new();
        for (&id, parent) in &parents {
            if let Some(parent) = parent {
                children.entry(parent.parent.id).or_default().push(id);
                if parent
                    .fuse_entry
                    .as_ref()
                    .is_some_and(|point| point.below(entry))
                {
                    queue.push_back(id);
                }
            }
        }
        let mut removed = BTreeSet::new();
        while let Some(id) = queue.pop_front() {
            if removed.insert(id) {
                queue.extend(children.get(&id).into_iter().flatten().copied());
            }
        }
        let private_namespaces: BTreeSet<_> = mounts
            .iter()
            .filter(|mount| removed.contains(&mount.id))
            .filter_map(|mount| fd::detached_namespace(mount, &parents))
            .collect();
        let weak_namespaces: Vec<_> = self.policy.namespaces.borrow().values().cloned().collect();
        let namespaces: Vec<_> = weak_namespaces
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .map(MountNamespace)
            .filter(|namespace| {
                private_namespaces.contains(&namespace.id())
                    || namespace
                        .0
                        .borrow()
                        .mounts
                        .iter()
                        .any(|mount| removed.contains(&mount.id))
            })
            .collect();
        let admins = namespaces
            .iter()
            .map(|namespace| namespace.0.borrow().admin.clone())
            .chain(publishing.iter().filter_map(|((mount, _), (owner, _))| {
                removed.contains(mount).then(|| owner.upgrade()).flatten()
            }))
            .map(|admin| (Arc::as_ptr(&admin) as usize, admin))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect();
        Plan {
            mounts,
            parents,
            children,
            removed,
            namespaces,
            admins,
        }
    }
    pub(crate) fn run(
        &self,
        entry: &Arc<fuse::Entry>,
    ) -> std::result::Result<(), Arc<admin::Admin>> {
        let initial = self.plan(entry);
        if initial.removed.is_empty() {
            return Ok(());
        }
        let mut leases = Vec::new();
        for admin in &initial.admins {
            let Some(lease) = admin.try_enter() else {
                return Err(admin.clone());
            };
            leases.push(lease);
        }
        // The name is already unhashed. New target attachments reject that
        // original entry; an intervening move/clone is re-observed under its
        // actual namespace admission before any topology is changed.
        let plan = self.plan(entry);
        if let Some(admin) = plan
            .admins
            .iter()
            .find(|admin| !initial.admins.iter().any(|old| Arc::ptr_eq(old, admin)))
        {
            return Err(admin.clone());
        }
        self.policy.path_changes.fetch_add(1, Ordering::AcqRel);
        let _change = PathChange(self.policy.clone());
        fd::remove_detached_members(&plan.mounts, &plan.removed);
        let mut events = Vec::new();
        for namespace in &plan.namespaces {
            let mut table = namespace.0.borrow_mut();
            let before = table.mounts.len();
            table
                .mounts
                .retain(|mount| !plan.removed.contains(&mount.id));
            if table.mounts.len() != before {
                events.push(table.events.clone());
            }
        }
        let mut detached = Vec::new();
        for mount in &plan.mounts {
            if !plan.removed.contains(&mount.id) {
                continue;
            }
            if plan.parents[&mount.id]
                .as_ref()
                .is_some_and(|parent| !plan.removed.contains(&parent.parent.id))
            {
                *mount.parent.borrow_mut() = None;
            }
            mount.set_propagation(propagation::State::default());
            detached.push(mount.clone());
        }
        for root in plan.mounts.iter().filter(|mount| {
            plan.removed.contains(&mount.id)
                && plan.parents[&mount.id]
                    .as_ref()
                    .is_some_and(|parent| !plan.removed.contains(&parent.parent.id))
        }) {
            let mut component = BTreeSet::new();
            let mut queue = VecDeque::from([root.id]);
            while let Some(id) = queue.pop_front() {
                if component.insert(id) {
                    queue.extend(plan.children.get(&id).into_iter().flatten().copied());
                }
            }
            fd::restore_detached_members(
                root,
                plan.mounts
                    .iter()
                    .filter(|mount| component.contains(&mount.id))
                    .cloned()
                    .collect(),
            );
        }
        if !detached.is_empty() {
            let mut retired = self.detached.borrow_mut();
            let known: BTreeSet<_> = retired.iter().flatten().map(|mount| mount.id).collect();
            // A lazy unmount can already own this exact forest. Two retirement
            // vectors retaining the same mount would pin each other forever.
            detached.retain(|mount| !known.contains(&mount.id));
            if !detached.is_empty() {
                retired.push(detached);
            }
        }
        let related: BTreeMap<_, _> = initial
            .admins
            .iter()
            .flat_map(|admin| admin.namespaces())
            .map(|namespace| (namespace.id(), namespace))
            .collect();
        let remaining = related
            .values()
            .flat_map(|namespace| namespace.0.borrow().mounts.clone())
            .collect::<Vec<_>>();
        propagation::normalize(&remaining);
        drop(leases);
        for event in events {
            event.changed();
        }
        Ok(())
    }
    pub(crate) fn reap(&self) {
        reap(&self.detached);
    }
}

pub(super) fn reap(detached: &SharedCell<Vec<Vec<Arc<Mount>>>>) {
    detached.borrow_mut().retain(|tree| {
        tree.iter().any(|mount| {
            let internal = 1 + tree
                .iter()
                .filter(|child| {
                    child
                        .parent
                        .borrow()
                        .as_ref()
                        .is_some_and(|parent| Arc::ptr_eq(&parent.parent, mount))
                })
                .count();
            Arc::strong_count(mount) > internal
                || mount.directory_users.load(Ordering::Relaxed) != 0
        })
    });
}
