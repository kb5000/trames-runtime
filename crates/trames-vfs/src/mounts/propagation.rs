// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared/slave topology updates execute under the original related-namespace
//! structural lease. Ordinary file IO never consults this state. No service
//! thread, guest-wide pause, host mount or polling bus participates.
use super::*;
use std::collections::BTreeSet;
use std::sync::Mutex;

static NEXT_GROUP: AtomicU64 = AtomicU64::new(1);
fn group() -> Result<u64> {
    NEXT_GROUP
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| Errno(28))
}
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(super) struct State {
    pub shared: u64,
    pub master: u64,
    lineage: Vec<u64>,
}
impl State {
    pub(super) fn resolved(mut self, alive: &BTreeSet<u64>) -> Self {
        while self.master != 0 && !alive.contains(&self.master) {
            self.master = if self.lineage.is_empty() {
                0
            } else {
                self.lineage.remove(0)
            };
        }
        self
    }
}
fn members(namespaces: &[MountNamespace]) -> Vec<Arc<Mount>> {
    namespaces
        .iter()
        .flat_map(|ns| ns.0.borrow().mounts.clone())
        .collect()
}
pub(super) fn live_groups(namespaces: &[MountNamespace]) -> BTreeSet<u64> {
    members(namespaces)
        .iter()
        .map(|m| m.propagation().shared)
        .filter(|g| *g != 0)
        .collect()
}
fn normalize(mounts: &[Arc<Mount>]) {
    let alive = mounts
        .iter()
        .map(|m| m.propagation().shared)
        .filter(|g| *g != 0)
        .collect();
    for mount in mounts {
        let old = mount.propagation();
        let next = old.clone().resolved(&alive);
        if old != next {
            mount.set_propagation(next);
        }
    }
}
impl Mount {
    pub(super) fn propagation(&self) -> State {
        self.propagation.lock().unwrap().clone()
    }
    pub(super) fn set_propagation(&self, state: State) {
        *self.propagation.lock().unwrap() = state;
    }
}
pub(super) type Metadata = Mutex<State>;

impl MountNamespace {
    pub(super) fn create(table: Table) -> Self {
        let table = Arc::new(SharedCell::new(table));
        table.borrow().admin.register(&table);
        Self(table)
    }
}

impl Vfs {
    pub(super) fn change_propagation(&self, target: &ResolvedPath, flags: u64) -> Result<()> {
        const REC: u64 = 16384;
        const PRIVATE: u64 = 1 << 18;
        const SLAVE: u64 = 1 << 19;
        const SHARED: u64 = 1 << 20;
        let operation = flags & !REC;
        if !matches!(operation, PRIVATE | SLAVE | SHARED) || !self.is_mount_root(target) {
            return Err(Errno(22));
        }
        let namespace = self.mounts.as_ref().ok_or(Errno(22))?;
        let namespaces = namespace.0.borrow().admin.namespaces();
        let mounts = members(&namespaces);
        normalize(&mounts);
        let selected = target.mount.as_ref().ok_or(Errno(22))?;
        let mut ids = BTreeSet::from([selected.id]);
        if flags & REC != 0 {
            loop {
                let before = ids.len();
                for mount in &namespace.0.borrow().mounts {
                    if mount
                        .parent
                        .borrow()
                        .as_ref()
                        .is_some_and(|a| ids.contains(&a.parent.id))
                    {
                        ids.insert(mount.id);
                    }
                }
                if before == ids.len() {
                    break;
                }
            }
        }
        for mount in mounts.iter().filter(|m| ids.contains(&m.id)) {
            let mut state = mount.propagation();
            match operation {
                PRIVATE => state = State::default(),
                SHARED => {
                    if state.shared == 0 {
                        state.shared = group()?;
                    }
                }
                SLAVE => {
                    if state.shared != 0
                        && mounts
                            .iter()
                            .any(|m| m.id != mount.id && m.propagation().shared == state.shared)
                    {
                        if state.master != 0 {
                            state.lineage.insert(0, state.master);
                        }
                        state.master = state.shared;
                    }
                    state.shared = 0;
                }
                _ => unreachable!(),
            }
            mount.set_propagation(state);
        }
        normalize(&mounts);
        for ns in namespaces {
            ns.0.borrow().events.changed();
        }
        Ok(())
    }

    // Follow peers and downstream slaves, never masters. Return each original
    // parent once, together with its immediate upstream parent peer group.
    fn propagation_parents(
        &self,
        parent: &Arc<Mount>,
    ) -> Result<Vec<(MountNamespace, Arc<Mount>, u64)>> {
        let namespace = self.mounts.as_ref().ok_or(Errno(22))?;
        let shared = parent.propagation().shared;
        let mut result = vec![(namespace.clone(), parent.clone(), 0)];
        if shared == 0 {
            return Ok(result);
        }
        let namespaces = namespace.0.borrow().admin.namespaces();
        normalize(&members(&namespaces));
        let mut pending = vec![(shared, 0)];
        let mut groups = BTreeSet::new();
        let mut seen = BTreeSet::from([parent.id]);
        while let Some((peer, upstream)) = pending.pop() {
            if !groups.insert(peer) {
                continue;
            }
            for ns in &namespaces {
                for mount in &ns.0.borrow().mounts {
                    let state = mount.propagation();
                    if state.shared == peer {
                        if seen.insert(mount.id) {
                            result.push((ns.clone(), mount.clone(), upstream));
                        }
                    } else if state.master == peer {
                        if state.shared != 0 {
                            pending.push((state.shared, peer));
                        } else if seen.insert(mount.id) {
                            result.push((ns.clone(), mount.clone(), peer));
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn publish_mounts(
        &self,
        namespace: &MountNamespace,
        added: Vec<Arc<Mount>>,
    ) -> Result<()> {
        let root = added.first().ok_or(Errno(22))?;
        let attachment = root.parent.borrow().clone().ok_or(Errno(22))?;
        let parents = self.propagation_parents(&attachment.parent)?;
        let parent_group = attachment.parent.propagation().shared;
        let mut state = root.propagation();
        if parent_group != 0 && state.shared == 0 {
            state.shared = group()?;
            root.set_propagation(state.clone());
        }
        let mut child_groups = BTreeMap::from([(parent_group, state.shared)]);
        // Allocate groups before constructing recipients: their order in the
        // namespace registry is unrelated to their master/slave ordering.
        for (_, parent, _) in &parents {
            let peer = parent.propagation().shared;
            if peer != 0 && !child_groups.contains_key(&peer) {
                child_groups.insert(peer, group()?);
            }
        }
        let parent_states: BTreeMap<_, _> = parents
            .iter()
            .map(|(_, m, _)| {
                let p = m.propagation();
                (p.shared, p)
            })
            .collect();
        let mut plans = vec![(namespace.clone(), added.clone())];
        for (ns, parent, upstream) in parents.into_iter().skip(1) {
            let Some(key) = parent.key_of(&attachment.node) else {
                continue;
            };
            let mut copies = BTreeMap::new();
            for mount in &added {
                copies.insert(mount.id, copy_mount(mount)?);
            }
            let copy = copies[&root.id].clone();
            *copy.parent.borrow_mut() = Some(Attachment {
                parent: parent.clone(),
                node: attachment.node.clone(),
                fallback: key,
            });
            let peer = parent.propagation().shared;
            copy.set_propagation(if upstream == 0 {
                state.clone()
            } else {
                let mut chain = vec![child_groups[&upstream]];
                let mut at = upstream;
                while at != parent_group {
                    at = parent_states[&at].master;
                    if at == 0 {
                        break;
                    }
                    chain.push(child_groups[&at]);
                }
                if state.master != 0 {
                    chain.push(state.master);
                    chain.extend_from_slice(&state.lineage);
                }
                State {
                    shared: if peer == 0 { 0 } else { child_groups[&peer] },
                    master: chain[0],
                    lineage: chain[1..].to_vec(),
                }
            });
            for mount in added.iter().skip(1) {
                let a = mount.parent.borrow().clone().ok_or(Errno(22))?;
                *copies[&mount.id].parent.borrow_mut() = Some(Attachment {
                    parent: copies[&a.parent.id].clone(),
                    node: a.node,
                    fallback: a.fallback,
                });
            }
            plans.push((ns, added.iter().map(|m| copies[&m.id].clone()).collect()));
        }
        let mut counts = BTreeMap::new();
        for (ns, mounts) in &plans {
            *counts.entry(ns.id()).or_insert(0) += mounts.len();
        }
        for (ns, mounts) in &plans {
            if mounts.iter().any(|mount| matches!(&mount.namespace, Some(linux_namespace::NamespaceHandle::Mount(target)) if ns.id() >= target.id())) { return Err(Errno(22)); }
            if ns.0.borrow().mounts.len() + counts[&ns.id()] > MAX_MOUNTS {
                return Err(Errno(28));
            }
        }
        for (_, mounts) in &plans {
            self.register_mounts(mounts)?;
        }
        for (ns, mounts) in plans {
            let mut table = ns.0.borrow_mut();
            table.mounts.extend(mounts);
            let events = table.events.clone();
            drop(table);
            events.changed();
        }
        Ok(())
    }

    pub(super) fn unmount_propagated(&self, mount: &Arc<Mount>, flags: u64) -> Result<()> {
        let ns = self.mounts.as_ref().ok_or(Errno(22))?;
        if !ns.0.borrow().mounts.iter().any(|m| Arc::ptr_eq(m, mount)) {
            return Err(Errno(22));
        }
        if Arc::ptr_eq(mount, &ns.0.borrow().root) {
            return Err(Errno(16));
        }
        let attachment = mount.parent.borrow().clone().ok_or(Errno(22))?;
        let mut targets = vec![(ns.clone(), mount.clone())];
        for (ns, parent, _) in self
            .propagation_parents(&attachment.parent)?
            .into_iter()
            .skip(1)
        {
            let peer =
                ns.0.borrow()
                    .mounts
                    .iter()
                    .rev()
                    .find(|m| {
                        m.parent.borrow().as_ref().is_some_and(|a| {
                            a.parent.id == parent.id && Arc::ptr_eq(&a.node, &attachment.node)
                        })
                    })
                    .cloned();
            if let Some(peer) = peer {
                targets.push((ns, peer));
            }
        }
        let mut plans = vec![];
        for (ns, mount) in targets {
            let table = ns.0.borrow();
            let mut ids = BTreeSet::from([mount.id]);
            loop {
                let before = ids.len();
                for m in &table.mounts {
                    if m.parent
                        .borrow()
                        .as_ref()
                        .is_some_and(|a| ids.contains(&a.parent.id))
                    {
                        ids.insert(m.id);
                    }
                }
                if ids.len() == before {
                    break;
                }
            }
            // Native Linux rejects the whole ordinary unmount when a peer
            // recipient is busy; no namespace is changed before this preflight.
            if flags & 2 == 0 && (ids.len() > 1 || mount.in_use() || mount.writers.active()) {
                return Err(Errno(16));
            }
            let detached: Vec<_> = table
                .mounts
                .iter()
                .filter(|m| ids.contains(&m.id))
                .cloned()
                .collect();
            drop(table);
            plans.push((ns, mount, ids, detached));
        }
        for (ns, mount, ids, detached) in plans {
            let mut table = ns.0.borrow_mut();
            table.mounts.retain(|m| !ids.contains(&m.id));
            let events = table.events.clone();
            drop(table);
            if flags & 2 != 0 {
                self.detached_mounts.borrow_mut().push(detached);
            }
            *mount.parent.borrow_mut() = None;
            events.changed();
        }
        normalize(&members(&ns.0.borrow().admin.namespaces()));
        Ok(())
    }
}
