// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared PID identities. Root translations remain direct; only nested maps and
//! their lifecycle transactions synchronize. No CPU/guest-memory access locks.
use super::*;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, Weak,
};
pub const CLONE_NEWPID: u64 = 0x2000_0000;
static NEXT: AtomicU64 = AtomicU64::new(0xd000_0000);

pub(super) struct PidSpace {
    inode: u64,
    parent: Option<PidNamespace>,
    depth: usize,
    init: AtomicU64,
    dead: AtomicBool,
    maps: Mutex<Ids>,
    registry: Arc<Mutex<Vec<Weak<PidSpace>>>>,
}
struct Ids {
    next: u32,
    ids: BTreeMap<u32, u32>,
}
#[derive(Clone)]
pub struct PidNamespace(pub(super) Arc<PidSpace>);
impl Default for PidNamespace {
    fn default() -> Self {
        Self::new(None, Arc::default()).expect("initial PID namespace")
    }
}
impl PidNamespace {
    fn new(parent: Option<Self>, registry: Arc<Mutex<Vec<Weak<PidSpace>>>>) -> Result<Self> {
        let depth = parent.as_ref().map_or(0, |p| p.0.depth + 1);
        let mut all = registry.lock().unwrap();
        all.retain(|p| p.strong_count() != 0);
        if depth > 32 || all.len() >= 128 {
            return Err(Errno(28));
        }
        let inode = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        let n = Self(Arc::new(PidSpace {
            inode,
            parent,
            depth,
            init: AtomicU64::new(u64::MAX),
            dead: AtomicBool::new(false),
            maps: Mutex::new(Ids {
                next: 1,
                ids: BTreeMap::new(),
            }),
            registry: registry.clone(),
        }));
        all.push(Arc::downgrade(&n.0));
        Ok(n)
    }
    pub(super) fn local_in(&self, namespace: u64, global: u32) -> u32 {
        if namespace == 0 {
            return global;
        }
        let mut at = Some(self.clone());
        while let Some(n) = at {
            if n.id() == namespace {
                return n.local(global);
            }
            at = n.0.parent.clone();
        }
        0
    }
    pub(super) fn namespace_alive(&self, id: u64) -> bool {
        id == 0
            || self
                .0
                .registry
                .lock()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .any(|n| n.inode == id)
    }
    pub fn hierarchy(&self, global: u32) -> Vec<u32> {
        let mut ids = self
            .0
            .parent
            .as_ref()
            .map_or_else(Vec::new, |p| p.hierarchy(global));
        ids.push(self.local(global));
        ids
    }
    pub(super) fn lock_visibility(&self) -> Option<BTreeMap<u32, u32>> {
        self.is_nested()
            .then(|| self.0.maps.lock().unwrap().ids.clone())
    }
    pub fn id(&self) -> u64 {
        self.0.inode
    }
    pub fn local(&self, global: u32) -> u32 {
        if self.0.parent.is_none() {
            global
        } else {
            self.0
                .maps
                .lock()
                .unwrap()
                .ids
                .get(&global)
                .copied()
                .unwrap_or(0)
        }
    }
    pub fn global(&self, local: u32) -> Option<u32> {
        if local == 0 {
            return None;
        }
        if self.0.parent.is_none() {
            Some(local)
        } else {
            self.0
                .maps
                .lock()
                .unwrap()
                .ids
                .iter()
                .find(|(_, l)| **l == local)
                .map(|(g, _)| *g)
        }
    }
    pub fn contains(&self, other: &Self) -> bool {
        let mut at = Some(other.clone());
        while let Some(n) = at {
            if n.id() == self.id() {
                return true;
            }
            at = n.0.parent.clone();
        }
        false
    }
    pub fn init(&self) -> u32 {
        match self.0.init.load(Ordering::Relaxed) {
            u64::MAX => 1,
            init => init as u32,
        }
    }
    pub fn is_nested(&self) -> bool {
        self.0.parent.is_some()
    }
    pub fn is_dead(&self) -> bool {
        self.0.dead.load(Ordering::Relaxed) || self.0.parent.as_ref().is_some_and(Self::is_dead)
    }
    pub fn terminate(&self) {
        // Serialize death with any descendant allocation holding this ancestor.
        let _ids = self.0.maps.lock().unwrap();
        self.0.dead.store(true, Ordering::Relaxed);
    }
    pub fn parent(&self) -> Option<Self> {
        self.0.parent.clone()
    }
    /// Allocate in every ancestor before exposing a child. Allocation failure
    /// leaves all namespaces unchanged; IDs are not recycled during a session.
    fn allocate(&self, global: u32) -> Result<()> {
        if !self.is_nested() {
            return if self.is_dead() {
                Err(Errno(12))
            } else {
                Ok(())
            };
        }
        let mut chain = Vec::new();
        let mut at = Some(self);
        while let Some(n) = at {
            chain.push(n);
            at = n.0.parent.as_ref();
        }
        // Root -> leaf is the only multi-namespace lock order. Validate every
        // allocator before publishing any ID; failure consumes no ancestor ID.
        // Registry operations never run while these map locks are held.
        chain.reverse();
        let mut maps: Vec<_> = chain.iter().map(|n| n.0.maps.lock().unwrap()).collect();
        if chain.iter().any(|n| n.0.dead.load(Ordering::Relaxed)) {
            return Err(Errno(12));
        }
        if maps.iter().any(|m| m.next >= i32::MAX as u32) {
            return Err(Errno(11));
        }
        for (n, map) in chain.iter().zip(&mut maps).filter(|(n, _)| n.is_nested()) {
            let local = map.next;
            map.ids.insert(global, local);
            map.next = local + 1;
            if local == 1 {
                n.0.init.store(global as u64, Ordering::Relaxed);
            }
        }
        Ok(())
    }
    /// Only fork can grow the maps. Prune before it, retaining group/session
    /// leader IDs even after their original task was reaped.
    /// The caller still supplies `live` within the task lifecycle commit; a
    /// stale snapshot must not prune IDs allocated by an unrelated fork.
    pub fn retain_ids(&self, live: &std::collections::BTreeSet<u32>) {
        for n in self
            .0
            .registry
            .lock()
            .unwrap()
            .iter()
            .filter_map(Weak::upgrade)
        {
            n.maps
                .lock()
                .unwrap()
                .ids
                .retain(|id, _| live.contains(id) || n.init.load(Ordering::Relaxed) == *id as u64);
        }
    }
    pub(super) fn label(&self) -> Vec<u8> {
        format!("pid:[{}]", self.id()).into_bytes()
    }
}
impl Vfs {
    pub fn pid_namespace(&self) -> &PidNamespace {
        &self.pid_ns
    }
    pub fn pid_children_namespace(&self) -> &PidNamespace {
        &self.pid_children
    }
    pub fn unshare_pid(&mut self) -> Result<()> {
        if !self.credentials.has_cap(capabilities::SYS_ADMIN) {
            return Err(Errno(1));
        }
        if self.pid_children.id() != self.pid_ns.id() {
            return Err(Errno(22));
        }
        self.pid_children =
            PidNamespace::new(Some(self.pid_ns.clone()), self.pid_ns.0.registry.clone())?;
        Ok(())
    }
    pub fn activate_child_pid(&mut self, global: u32) -> Result<()> {
        self.pid_children.allocate(global)?;
        self.pid_ns = self.pid_children.clone();
        Ok(())
    }
    pub fn visible_pid(&self, global: u32) -> u32 {
        self.pid_ns.local(global)
    }
    pub fn global_pid(&self, local: u32) -> Result<u32> {
        self.pid_ns.global(local).ok_or(Errno(3))
    }
    pub(super) fn proc_namespace<'a, P: PathArg + ?Sized>(
        &'a self,
        path: &'a P,
    ) -> &'a PidNamespace {
        path.mount()
            .and_then(|m| m.pid_namespace.as_ref())
            .unwrap_or(&self.pid_ns)
    }
    pub(super) fn proc_runtime<'a, P: PathArg + ?Sized>(
        &self,
        path: &P,
        runtime: &'a RuntimeInfo,
    ) -> std::borrow::Cow<'a, RuntimeInfo> {
        let ns = self.proc_namespace(path);
        if !ns.is_nested() {
            return std::borrow::Cow::Borrowed(runtime);
        }
        let mut r = runtime.clone();
        r.processes.retain(|p| ns.local(p.pid) != 0);
        for p in &mut r.processes {
            for ids in &mut p.namespace_ids {
                *ids = ids.iter().skip(ns.0.depth).copied().collect();
            }
            p.pid = ns.local(p.pid);
            p.tgid = ns.local(p.tgid);
            p.parent = ns.local(p.parent);
            p.group = ns.local(p.group);
            p.session = ns.local(p.session);
        }
        std::borrow::Cow::Owned(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_translation_and_allocation_do_not_take_map_or_registry_locks() {
        let root = PidNamespace::default();
        let _maps = root.0.maps.lock().unwrap();
        let _registry = root.0.registry.lock().unwrap();
        let worker = root.clone();
        std::thread::spawn(move || {
            assert_eq!(worker.local(42), 42);
            assert_eq!(worker.global(42), Some(42));
            assert_eq!(worker.hierarchy(42), vec![42]);
            assert_eq!(worker.allocate(42), Ok(()));
            assert_eq!(worker.lock_visibility(), None);
            assert!(worker.namespace_alive(0));
        })
        .join()
        .unwrap();
    }
    #[test]
    fn concurrent_allocations_publish_unique_ancestor_ids_and_roll_back_limits() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<PidNamespace>();
        let root = PidNamespace::default();
        let parent = PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap();
        parent.allocate(2).unwrap();
        let a = PidNamespace::new(Some(parent.clone()), root.0.registry.clone()).unwrap();
        let b = PidNamespace::new(Some(parent.clone()), root.0.registry.clone()).unwrap();
        std::thread::scope(|scope| {
            for writer in 0..8 {
                let namespace = if writer % 2 == 0 {
                    a.clone()
                } else {
                    b.clone()
                };
                scope.spawn(move || {
                    for i in 0..12 {
                        namespace.allocate(1000 + writer * 12 + i).unwrap();
                    }
                });
            }
        });
        let mut ancestors = std::collections::BTreeSet::new();
        let mut children = [
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
        ];
        for writer in 0..8 {
            for i in 0..12 {
                let global = 1000 + writer * 12 + i;
                let (child, sibling) = if writer % 2 == 0 { (&a, &b) } else { (&b, &a) };
                let id = child.local(global);
                assert_ne!(id, 0);
                assert_eq!(child.global(id), Some(global));
                assert_eq!(sibling.local(global), 0);
                assert!(ancestors.insert(parent.local(global)));
                assert!(children[writer as usize % 2].insert(id));
            }
        }
        assert_eq!(ancestors, (2..98).collect());
        for child in children {
            assert_eq!(child, (1..49).collect());
        }
        let before = parent.0.maps.lock().unwrap().next;
        a.0.maps.lock().unwrap().next = i32::MAX as u32;
        assert_eq!(a.allocate(9000), Err(Errno(11)));
        assert_eq!(parent.0.maps.lock().unwrap().next, before);
        assert_eq!(parent.local(9000), 0);
    }
    #[test]
    fn termination_and_child_allocation_commit_without_partial_ancestor_ids() {
        for _ in 0..16 {
            let root = PidNamespace::default();
            let parent = PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap();
            parent.allocate(2).unwrap();
            let child = PidNamespace::new(Some(parent.clone()), root.0.registry.clone()).unwrap();
            let gate = Arc::new(std::sync::Barrier::new(2));
            let result = std::thread::scope(|scope| {
                let gate2 = gate.clone();
                let dead = &parent;
                scope.spawn(move || {
                    gate2.wait();
                    dead.terminate();
                });
                gate.wait();
                child.allocate(3)
            });
            match result {
                Ok(()) => {
                    assert_eq!(parent.local(3), 2);
                    assert_eq!(child.local(3), 1);
                }
                Err(Errno(12)) => {
                    assert_eq!(parent.local(3), 0);
                    assert_eq!(child.local(3), 0);
                }
                other => panic!("unexpected allocation: {other:?}"),
            }
            let before = parent.0.maps.lock().unwrap().next;
            assert!(child.is_dead());
            assert_eq!(child.allocate(4), Err(Errno(12)));
            assert_eq!(parent.0.maps.lock().unwrap().next, before);
        }
    }
    #[test]
    fn weak_namespace_identity_expires_after_last_worker_reference() {
        let root = PidNamespace::default();
        let child = PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap();
        child.allocate(42).unwrap();
        let weak = Arc::downgrade(&child.0);
        let id = child.id();
        std::thread::spawn(move || {
            assert_eq!(child.init(), 42);
            assert_eq!(child.local(42), 1);
            drop(child);
        })
        .join()
        .unwrap();
        assert!(weak.upgrade().is_none());
        assert!(!root.namespace_alive(id));
        assert!(root.namespace_alive(root.id()));
    }
    #[test]
    fn ancestor_ids_survive_group_leaders_but_siblings_are_invisible() {
        let root = PidNamespace::default();
        let a = PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap();
        a.allocate(8).unwrap();
        a.allocate(9).unwrap();
        let b = PidNamespace::new(Some(a.clone()), root.0.registry.clone()).unwrap();
        b.allocate(10).unwrap();
        let sibling = PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap();
        sibling.allocate(11).unwrap();
        assert_eq!(b.hierarchy(10), vec![10, 3, 1]);
        assert_eq!(b.local(8), 0);
        assert_eq!(a.local(11), 0);
        assert_eq!(sibling.global(2), None);
        // Retained group/session IDs are supplied by the coordinator even
        // after a task is gone; unreferenced IDs can be reclaimed.
        root.retain_ids(&[8, 9, 10, 11].into());
        assert_eq!(a.global(2), Some(9));
        root.retain_ids(&[8, 10, 11].into());
        assert_eq!(a.global(2), None);
        a.allocate(12).unwrap();
        assert_eq!(a.local(12), 4); // no ID reuse
    }
    #[test]
    fn dead_namespace_allocation_does_not_consume_ancestor_ids() {
        let root = PidNamespace::default();
        let a = PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap();
        a.allocate(2).unwrap();
        let b = PidNamespace::new(Some(a.clone()), root.0.registry.clone()).unwrap();
        b.allocate(3).unwrap();
        b.terminate();
        assert_eq!(b.allocate(4), Err(Errno(12)));
        assert_eq!(a.global(3), None);
        a.allocate(5).unwrap();
        assert_eq!(a.local(5), 3);
        a.terminate();
        assert!(b.is_dead());
    }
    #[test]
    fn depth_and_live_namespace_quotas_release_without_unbounded_registry_growth() {
        let root = PidNamespace::default();
        let mut at = root.clone();
        for _ in 0..32 {
            at = PidNamespace::new(Some(at), root.0.registry.clone()).unwrap();
        }
        assert!(matches!(
            PidNamespace::new(Some(at.clone()), root.0.registry.clone()),
            Err(Errno(28))
        ));
        drop(at);
        let mut held = Vec::new();
        for _ in 0..127 {
            held.push(PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap());
        }
        assert!(matches!(
            PidNamespace::new(Some(root.clone()), root.0.registry.clone()),
            Err(Errno(28))
        ));
        held.clear();
        for _ in 0..256 {
            let n = PidNamespace::new(Some(root.clone()), root.0.registry.clone()).unwrap();
            drop(n);
        }
        assert!(root.0.registry.lock().unwrap().len() <= 2);
    }
}
