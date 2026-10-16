// SPDX-License-Identifier: GPL-3.0-or-later
//! Coordinator-owned PID identities. No CPU or guest memory access takes a lock.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
pub const CLONE_NEWPID: u64 = 0x2000_0000;
static NEXT: AtomicU64 = AtomicU64::new(0xd000_0000);

pub(super) struct PidSpace {
    inode: u64,
    parent: Option<PidNamespace>,
    depth: usize,
    next: Cell<u32>,
    init: Cell<Option<u32>>,
    dead: Cell<bool>,
    ids: RefCell<BTreeMap<u32, u32>>,
    registry: Rc<RefCell<Vec<Weak<PidSpace>>>>,
}
#[derive(Clone)]
pub struct PidNamespace(pub(super) Rc<PidSpace>);
impl Default for PidNamespace {
    fn default() -> Self {
        Self::new(None, Rc::default()).expect("initial PID namespace")
    }
}
impl PidNamespace {
    fn new(parent: Option<Self>, registry: Rc<RefCell<Vec<Weak<PidSpace>>>>) -> Result<Self> {
        let depth = parent.as_ref().map_or(0, |p| p.0.depth + 1);
        let mut all = registry.borrow_mut();
        all.retain(|p| p.strong_count() != 0);
        if depth > 32 || all.len() >= 128 {
            return Err(Errno(28));
        }
        let inode = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Errno(28))?;
        let n = Self(Rc::new(PidSpace {
            inode,
            parent,
            depth,
            next: Cell::new(1),
            init: Cell::new(None),
            dead: Cell::new(false),
            ids: RefCell::default(),
            registry: registry.clone(),
        }));
        all.push(Rc::downgrade(&n.0));
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
                .borrow()
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
    pub fn id(&self) -> u64 {
        self.0.inode
    }
    pub fn local(&self, global: u32) -> u32 {
        if self.0.parent.is_none() {
            global
        } else {
            self.0.ids.borrow().get(&global).copied().unwrap_or(0)
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
                .ids
                .borrow()
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
        self.0.init.get().unwrap_or(1)
    }
    pub fn is_nested(&self) -> bool {
        self.0.parent.is_some()
    }
    pub fn is_dead(&self) -> bool {
        self.0.dead.get() || self.0.parent.as_ref().is_some_and(Self::is_dead)
    }
    pub fn terminate(&self) {
        self.0.dead.set(true);
    }
    pub fn parent(&self) -> Option<Self> {
        self.0.parent.clone()
    }
    /// Allocate in every ancestor before exposing a child. Allocation failure
    /// leaves all namespaces unchanged; IDs are not recycled during a session.
    fn allocate(&self, global: u32) -> Result<()> {
        let mut chain = Vec::new();
        let mut at = Some(self.clone());
        while let Some(n) = at {
            if n.is_dead() {
                return Err(Errno(12));
            }
            if n.0.next.get() >= i32::MAX as u32 {
                return Err(Errno(11));
            }
            at = n.0.parent.clone();
            if n.is_nested() {
                chain.push(n);
            }
        }
        for n in chain {
            let local = n.0.next.get();
            n.0.ids.borrow_mut().insert(global, local);
            n.0.next.set(local + 1);
            if local == 1 {
                n.0.init.set(Some(global));
            }
        }
        Ok(())
    }
    /// Only fork can grow the maps. Prune before it, retaining group/session
    /// leader IDs even after their original task was reaped.
    pub fn retain_ids(&self, live: &std::collections::BTreeSet<u32>) {
        for n in self.0.registry.borrow().iter().filter_map(Weak::upgrade) {
            n.ids
                .borrow_mut()
                .retain(|id, _| live.contains(id) || n.init.get() == Some(*id));
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
        assert!(root.0.registry.borrow().len() <= 2);
    }
}
