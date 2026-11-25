// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared/slave topology updates execute under the original related-namespace
//! structural lease. Ordinary file IO never consults this state. No service
//! thread, guest-wide pause, host mount or polling bus participates.
use super::*;
use std::collections::BTreeSet;
use std::sync::Mutex;

// A detached tree and a slave's ancestry keep their IDs alive. Each guest
// recycles its own numbers after the last reference to a group disappears.
#[derive(Debug)]
pub(super) struct Group {
    pub(super) id: u64,
    pool: std::sync::Weak<Mutex<GroupIds>>,
}
impl PartialEq for Group {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.pool.ptr_eq(&other.pool)
    }
}
impl Eq for Group {}
impl Drop for Group {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            pool.lock().unwrap().unused.insert(self.id);
        }
    }
}
type Link = Option<Arc<Group>>;
#[derive(Default, Debug)]
struct GroupIds {
    last: u64,
    unused: BTreeSet<u64>,
}
#[derive(Default)]
pub(super) struct Groups(Arc<Mutex<GroupIds>>);
impl Groups {
    fn allocate(&self) -> Result<Arc<Group>> {
        let mut pool = self.0.lock().unwrap();
        let id = match pool.unused.pop_first() {
            Some(id) => id,
            None => {
                pool.last = pool.last.checked_add(1).ok_or(Errno(28))?;
                pool.last
            }
        };
        Ok(Arc::new(Group {
            id,
            pool: Arc::downgrade(&self.0),
        }))
    }
}
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub(super) struct State {
    pub shared: Link,
    pub master: Link,
    pub unbindable: bool,
    lineage: Vec<Arc<Group>>,
}
impl State {
    pub(super) fn has_relations(&self) -> bool {
        self.shared.is_some() || self.master.is_some()
    }
    pub(super) fn inherited_slave(mut self) -> Self {
        if let Some(shared) = self.shared.take() {
            if let Some(master) = self.master.replace(shared) {
                self.lineage.insert(0, master);
            }
        }
        self
    }
    pub(super) fn resolved(mut self, alive: &BTreeSet<u64>) -> Self {
        while self.master.as_ref().is_some_and(|g| !alive.contains(&g.id)) {
            self.master = if self.lineage.is_empty() {
                None
            } else {
                Some(self.lineage.remove(0))
            };
        }
        self
    }

    pub(super) fn dominating_group(&self, visible: &BTreeSet<u64>) -> u64 {
        self.master
            .iter()
            .chain(&self.lineage)
            .map(|g| g.id)
            .find(|id| visible.contains(id))
            .unwrap_or(0)
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
        .filter_map(|m| Some(m.propagation().shared?.id))
        .collect()
}
pub(super) fn normalize(mounts: &[Arc<Mount>]) {
    let alive = mounts
        .iter()
        .filter_map(|m| Some(m.propagation().shared?.id))
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
    pub(super) fn create(mut table: Table, policy: &Arc<MountPolicy>) -> Self {
        let id = table.id;
        table.registry = Some(Arc::downgrade(policy));
        let table = Arc::new(SharedCell::new(table));
        table.borrow().admin.register(&table);
        policy
            .namespaces
            .borrow_mut()
            .insert(id, Arc::downgrade(&table));
        Self(table)
    }
}

fn child_at(ns: &MountNamespace, parent: &Mount, node: &NodeRef) -> Option<Arc<Mount>> {
    ns.0.borrow()
        .mounts
        .iter()
        .rev()
        .find(|mount| {
            mount
                .parent
                .borrow()
                .as_ref()
                .is_some_and(|a| a.parent.id == parent.id && Arc::ptr_eq(&a.node, node))
        })
        .cloned()
}

impl Vfs {
    pub(super) fn plan_propagation(
        &self,
        selected: &[Arc<Mount>],
        operation: u64,
    ) -> Result<Vec<(Arc<Mount>, State)>> {
        const PRIVATE: u64 = 1 << 18;
        const SLAVE: u64 = 1 << 19;
        const SHARED: u64 = 1 << 20;
        const UNBINDABLE: u64 = 1 << 17;
        if !matches!(operation, PRIVATE | SLAVE | SHARED | UNBINDABLE) {
            return Err(Errno(22));
        }
        let namespace = self.mounts.as_ref().ok_or(Errno(22))?;
        let namespaces = namespace.0.borrow().admin.namespaces();
        let mounts = members(&namespaces);
        let alive = mounts
            .iter()
            .filter_map(|m| Some(m.propagation().shared?.id))
            .collect();
        let mut updates = Vec::with_capacity(selected.len());
        for mount in selected {
            let mut state = mount.propagation().resolved(&alive);
            match operation {
                PRIVATE => state = State::default(),
                UNBINDABLE => {
                    state = State {
                        unbindable: true,
                        ..State::default()
                    }
                }
                SHARED => {
                    state.unbindable = false;
                    if state.shared.is_none() {
                        state.shared = Some(self.pseudo.borrow().mount_policy.groups.allocate()?);
                    }
                }
                SLAVE => {
                    if state.shared.is_some()
                        && mounts
                            .iter()
                            .any(|m| m.id != mount.id && m.propagation().shared == state.shared)
                    {
                        if let Some(master) = state.master.take() {
                            state.lineage.insert(0, master);
                        }
                        state.master = state.shared.take();
                    }
                    state.shared = None;
                }
                _ => unreachable!(),
            }
            updates.push((mount.clone(), state));
        }
        Ok(updates)
    }
    pub(super) fn normalize_propagation(&self) {
        let Some(namespace) = self.mounts.as_ref() else {
            return;
        };
        let namespaces = namespace.0.borrow().admin.namespaces();
        normalize(&members(&namespaces));
        for ns in namespaces {
            ns.0.borrow().events.changed();
        }
    }
    pub(super) fn change_propagation(&self, target: &ResolvedPath, flags: u64) -> Result<()> {
        const REC: u64 = 16384;
        const PRIVATE: u64 = 1 << 18;
        const SLAVE: u64 = 1 << 19;
        const SHARED: u64 = 1 << 20;
        const UNBINDABLE: u64 = 1 << 17;
        let operation = flags & !REC;
        if !matches!(operation, PRIVATE | SLAVE | SHARED | UNBINDABLE)
            || !self.is_mount_root(target)
        {
            return Err(Errno(22));
        }
        let namespace = self.mounts.as_ref().ok_or(Errno(22))?;
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
        let selected: Vec<_> = namespace
            .0
            .borrow()
            .mounts
            .iter()
            .filter(|m| ids.contains(&m.id))
            .cloned()
            .collect();
        for (mount, state) in self.plan_propagation(&selected, operation)? {
            mount.set_propagation(state);
        }
        self.normalize_propagation();
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
        let Some(shared) = shared else {
            return Ok(result);
        };
        let namespaces = namespace.0.borrow().admin.namespaces();
        normalize(&members(&namespaces));
        let mut pending = vec![(shared.id, 0)];
        let mut groups = BTreeSet::new();
        let mut seen = BTreeSet::from([parent.id]);
        while let Some((peer, upstream)) = pending.pop() {
            if !groups.insert(peer) {
                continue;
            }
            for ns in &namespaces {
                for mount in &ns.0.borrow().mounts {
                    let state = mount.propagation();
                    if state.shared.as_ref().is_some_and(|g| g.id == peer) {
                        if seen.insert(mount.id) {
                            result.push((ns.clone(), mount.clone(), upstream));
                        }
                    } else if state.master.as_ref().is_some_and(|g| g.id == peer) {
                        if let Some(shared) = state.shared {
                            pending.push((shared.id, peer));
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
        apply_options: impl FnOnce(),
    ) -> Result<()> {
        let root = added.first().ok_or(Errno(22))?;
        let attachment = root.parent.borrow().clone().ok_or(Errno(22))?;
        self.publish_mounts_at(namespace, added, attachment, apply_options)
    }
    pub(super) fn publish_mounts_at(
        &self,
        namespace: &MountNamespace,
        added: Vec<Arc<Mount>>,
        attachment: Attachment,
        apply_options: impl FnOnce(),
    ) -> Result<()> {
        let root = added.first().ok_or(Errno(22))?;
        let parents = self.propagation_parents(&attachment.parent)?;
        let parent_group = attachment.parent.propagation().shared.map_or(0, |g| g.id);
        if parent_group != 0 && added.iter().any(|m| m.propagation().unbindable) {
            return Err(Errno(22));
        }
        let mut state = root.propagation();
        if parent_group != 0 && state.shared.is_none() {
            state.shared = Some(self.pseudo.borrow().mount_policy.groups.allocate()?);
        }
        let mut child_groups = BTreeMap::from([(parent_group, state.shared.clone())]);
        // Allocate groups before constructing recipients: their order in the
        // namespace registry is unrelated to their master/slave ordering.
        for (_, parent, _) in &parents {
            let peer = parent.propagation().shared.map_or(0, |g| g.id);
            if peer != 0 && !child_groups.contains_key(&peer) {
                child_groups.insert(
                    peer,
                    Some(self.pseudo.borrow().mount_policy.groups.allocate()?),
                );
            }
        }
        let parent_states: BTreeMap<_, _> = parents
            .iter()
            .map(|(_, m, _)| {
                let p = m.propagation();
                (p.shared.as_ref().map_or(0, |g| g.id), p)
            })
            .collect();
        // Charge every recipient table before cloning any trees. A shared
        // self-bind can double the topology in a single syscall.
        let recipients: Vec<_> = parents
            .into_iter()
            .skip(1)
            .filter_map(|(ns, parent, upstream)| {
                let key = parent.key_of(&attachment.node)?;
                Some((ns, parent, upstream, key))
            })
            .collect();
        let mut charges = BTreeMap::new();
        let limit = self.mount_limit();
        for ns in std::iter::once(namespace).chain(recipients.iter().map(|(ns, ..)| ns)) {
            let total = charges
                .entry(ns.id())
                .or_insert_with(|| ns.0.borrow().mounts.len());
            *total = total.checked_add(added.len()).ok_or(Errno(28))?;
            if *total > limit {
                return Err(Errno(28));
            }
            if added.iter().any(|m| matches!(&m.namespace, Some(linux_namespace::NamespaceHandle::Mount(target)) if ns.id() >= target.id())) {
                return Err(Errno(22));
            }
        }
        let mut plans = vec![(namespace.clone(), added.clone())];
        let mut covered = Vec::new();
        for (ns, parent, upstream, key) in recipients {
            let mut copies = BTreeMap::new();
            let less_privileged =
                namespace.0.borrow().user_namespace != ns.0.borrow().user_namespace;
            for mount in &added {
                let copy = copy_mount(mount)?;
                if less_privileged {
                    let attachment_lock = if Arc::ptr_eq(mount, root) {
                        0
                    } else {
                        LOCK_ATTACHMENT
                    };
                    copy.inherited.fetch_or(
                        attachment_lock | ATIME_FLAGS | (mount.flags.get() & 15),
                        Ordering::Relaxed,
                    );
                }
                copies.insert(mount.id, copy);
            }
            let copy = copies[&root.id].clone();
            if let Some(existing) = child_at(&ns, &parent, &attachment.node) {
                covered.push((existing, copy.clone()));
            }
            *copy.parent.borrow_mut() = Some(Attachment {
                parent: parent.clone(),
                node: attachment.node.clone(),
                fuse_entry: attachment.fuse_entry.clone(),
                fallback: key,
            });
            let peer = parent.propagation().shared.map_or(0, |g| g.id);
            copy.set_propagation(if upstream == 0 {
                state.clone()
            } else {
                let mut chain = vec![child_groups[&upstream].clone().unwrap()];
                let mut at = upstream;
                while at != parent_group {
                    at = parent_states[&at].master.as_ref().map_or(0, |g| g.id);
                    if at == 0 {
                        break;
                    }
                    chain.push(child_groups[&at].clone().unwrap());
                }
                if let Some(master) = &state.master {
                    chain.push(master.clone());
                    chain.extend_from_slice(&state.lineage);
                }
                State {
                    shared: child_groups.get(&peer).cloned().flatten(),
                    master: Some(chain[0].clone()),
                    lineage: chain[1..].to_vec(),
                    unbindable: false,
                }
            });
            for mount in added.iter().skip(1) {
                let a = mount.parent.borrow().clone().ok_or(Errno(22))?;
                *copies[&mount.id].parent.borrow_mut() = Some(Attachment {
                    parent: copies[&a.parent.id].clone(),
                    node: a.node,
                    fuse_entry: a.fuse_entry.clone(),
                    fallback: a.fallback,
                });
            }
            plans.push((ns, added.iter().map(|m| copies[&m.id].clone()).collect()));
        }
        let entry = attachment.fuse_entry.clone();
        let admin = namespace.0.borrow().admin.clone();
        let publishing: Vec<_> = plans
            .iter()
            .flat_map(|(_, mounts)| mounts.iter().cloned())
            .collect();
        let _publication = self.mount_registry.publishing(&admin, &publishing);
        self.reap_detached_mounts();
        let events = fuse::Entry::attach(entry.as_ref(), || {
            root.set_propagation(state);
            *root.parent.borrow_mut() = Some(attachment);
            for (_, mounts) in &plans {
                self.register_mounts_unreaped(mounts)?;
            }
            // Apply superblock options after all fallible validation and before mount watchers wake.
            apply_options();
            // A propagated mount goes beneath the mount already visible at
            // that dentry. Keeping a single parent edge per mountpoint also lets
            // unmount uncover the original tree without losing its descendants.
            for (previous, below) in covered {
                *previous.parent.borrow_mut() = Some(Attachment {
                    node: below.root.clone(),
                    fuse_entry: below
                        .root_entry
                        .clone()
                        .or_else(|| fuse::Entry::directory(&below.root)),
                    fallback: below.root_path(),
                    parent: below,
                });
            }
            let mut changed = Vec::new();
            for (ns, mounts) in plans {
                let mut table = ns.0.borrow_mut();
                table.mounts.extend(mounts);
                let events = table.events.clone();
                drop(table);
                changed.push(events);
            }
            Ok(changed)
        })?;
        for event in events {
            event.changed();
        }
        Ok(())
    }

    pub(super) fn unmount_propagated(&self, mount: &Arc<Mount>, flags: u64) -> Result<()> {
        let ns = self.mounts.as_ref().ok_or(Errno(22))?;
        if !ns.0.borrow().mounts.iter().any(|m| Arc::ptr_eq(m, mount)) {
            return Err(Errno(22));
        }
        if mount.inherited.load(Ordering::Relaxed) & LOCK_ATTACHMENT != 0 {
            return Err(Errno(22));
        }
        if Arc::ptr_eq(mount, &ns.0.borrow().root) {
            return Err(Errno(16));
        }
        let lazy = flags & 2 != 0;
        let mut removed = BTreeMap::from([(mount.id, (ns.clone(), mount.clone()))]);
        let mut subtree = vec![mount.clone()];
        let mut children: BTreeMap<u64, Vec<Arc<Mount>>> = BTreeMap::new();
        for child in &ns.0.borrow().mounts {
            if let Some(parent) = child.parent.borrow().as_ref() {
                children
                    .entry(parent.parent.id)
                    .or_default()
                    .push(child.clone());
            }
        }
        if !lazy && (children.contains_key(&mount.id) || mount.in_use() || mount.writers.active()) {
            return Err(Errno(16));
        }
        let mut i = 0;
        while i < subtree.len() {
            if let Some(nested) = children.get(&subtree[i].id) {
                for child in nested {
                    removed.insert(child.id, (ns.clone(), child.clone()));
                    subtree.push(child.clone());
                }
            }
            i += 1;
        }

        // Every attachment removed from the source subtree can propagate
        // independently, including events crossing a nested shared mount.
        let mut candidates = BTreeMap::new();
        for source in &subtree {
            let a = source.parent.borrow().clone().ok_or(Errno(22))?;
            for (peer_ns, parent, _) in self.propagation_parents(&a.parent)?.into_iter().skip(1) {
                if let Some(peer) = child_at(&peer_ns, &parent, &a.node) {
                    if !removed.contains_key(&peer.id) {
                        candidates.insert(peer.id, (peer_ns, peer));
                    }
                }
            }
        }

        // Postorder is determined by dependencies, independent of namespace
        // registry order. A peer with its own surviving submount stays put.
        loop {
            let before = candidates.len();
            for id in candidates.keys().copied().collect::<Vec<_>>() {
                let (ns, peer) = &candidates[&id];
                let retains_submount =
                    ns.0.borrow().mounts.iter().any(|child| {
                        !removed.contains_key(&child.id)
                            && child.parent.borrow().as_ref().is_some_and(|a| {
                                a.parent.id == id && !Arc::ptr_eq(&a.node, &peer.root)
                            })
                    });
                if retains_submount {
                    continue;
                }
                if !lazy && (peer.in_use() || peer.writers.active()) {
                    return Err(Errno(16));
                }
                removed.insert(id, candidates.remove(&id).unwrap());
            }
            if before == candidates.len() {
                break;
            }
        }
        let mut affected = BTreeMap::new();
        for (ns, m) in removed.values() {
            affected
                .entry(ns.id())
                .or_insert_with(|| (ns.clone(), Vec::new()))
                .1
                .push(m.clone());
        }
        for (ns, detached) in affected.into_values() {
            let mut table = ns.0.borrow_mut();
            for child in &table.mounts {
                if removed.contains_key(&child.id) {
                    continue;
                }
                let mut link = child.parent.borrow().clone();
                if !link
                    .as_ref()
                    .is_some_and(|a| removed.contains_key(&a.parent.id))
                {
                    continue;
                }
                // Restore the bottom of the surviving stack to the original
                // mountpoint before clearing the removed layers' parent edges.
                while let Some(a) = &link {
                    if !removed.contains_key(&a.parent.id) {
                        break;
                    }
                    let next = a.parent.parent.borrow().clone();
                    link = next;
                }
                *child.parent.borrow_mut() = link;
            }
            table.mounts.retain(|m| !removed.contains_key(&m.id));
            let events = table.events.clone();
            drop(table);
            for m in &detached {
                let boundary = m
                    .parent
                    .borrow()
                    .as_ref()
                    .is_some_and(|a| !removed.contains_key(&a.parent.id));
                if boundary {
                    *m.parent.borrow_mut() = None;
                }
                m.set_propagation(State::default());
            }
            if lazy {
                self.detached_mounts.borrow_mut().push(detached);
            }
            events.changed();
        }
        normalize(&members(&ns.0.borrow().admin.namespaces()));
        Ok(())
    }
}
