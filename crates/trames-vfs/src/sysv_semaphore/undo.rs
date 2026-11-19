// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(super) struct Adjustments {
    group: Weak<Group>,
    pub(super) values: BTreeMap<u16, i32>,
}
pub(super) struct Group {
    members: AtomicUsize,
    sets: Mutex<BTreeMap<usize, Weak<Set>>>,
}
impl Default for Group {
    fn default() -> Self {
        Self {
            members: AtomicUsize::new(1),
            sets: Default::default(),
        }
    }
}
impl Group {
    pub(super) fn commit(
        self: &Arc<Self>,
        set: &Arc<Set>,
        s: &mut State,
        updates: BTreeMap<u16, i32>,
    ) -> Result<()> {
        let key = Arc::as_ptr(self) as usize;
        let set_key = Arc::as_ptr(set) as usize;
        // The last departure drains this registry before taking any set lock.
        let mut sets = self.sets.lock().unwrap();
        if self.members.load(Ordering::Relaxed) == 0 {
            return Err(Errno(4));
        }
        let r = s.undo.entry(key).or_insert_with(|| Adjustments {
            group: Arc::downgrade(self),
            values: Default::default(),
        });
        for (index, adj) in updates {
            if adj == 0 {
                r.values.remove(&index);
            } else {
                r.values.insert(index, adj);
            }
        }
        if r.values.is_empty() {
            s.undo.remove(&key);
            sets.remove(&set_key);
        } else {
            sets.insert(set_key, Arc::downgrade(set));
        }
        Ok(())
    }
    fn leave(&self, actor: Actor) {
        if self.members.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let sets = std::mem::take(&mut *self.sets.lock().unwrap());
        for set in sets.into_values().filter_map(|s| s.upgrade()) {
            let mut s = set.state.lock().unwrap();
            if let Some(r) = s.undo.remove(&(self as *const Self as usize)) {
                if !r.values.is_empty() {
                    for (idx, adj) in r.values {
                        let sem = s.values.entry(idx).or_default();
                        sem.val = (sem.val + adj).clamp(0, MAX_VALUE);
                        sem.actor = actor.clone();
                    }
                    s.operated = crate::sysv_ipc::now();
                    drop(s);
                    set.ready.notify_locked();
                }
            }
        }
    }
}
pub(super) fn clear_all(set: &Set, s: &mut State) {
    for r in std::mem::take(&mut s.undo).into_values() {
        if let Some(g) = r.group.upgrade() {
            g.sets.lock().unwrap().remove(&(set as *const Set as usize));
        }
    }
}
/// Observer clones retain one task member. Only CLONE_SYSVSEM creates another
/// member of the group; an accepted request is never counted as a living task.
#[derive(Clone, Default)]
pub struct UndoMember(Arc<Member>);
#[derive(Default)]
struct Member {
    binding: std::sync::OnceLock<Mutex<Option<Arc<Group>>>>,
}
impl Drop for Member {
    fn drop(&mut self) {
        // A failed birth may drop its provisional member before publication.
        if let Some(group) = self
            .binding
            .get_mut()
            .and_then(|slot| slot.get_mut().unwrap().take())
        {
            group.leave(Actor::default());
        }
    }
}
impl UndoMember {
    pub(super) fn group(&self) -> Arc<Group> {
        self.0
            .binding
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .get_or_insert_with(Default::default)
            .clone()
    }
    pub(crate) fn fork_shared(&self) -> Self {
        let mut binding = self.0.binding.get_or_init(Default::default).lock().unwrap();
        let g = binding.get_or_insert_with(Default::default);
        g.members.fetch_add(1, Ordering::Relaxed);
        Self(Arc::new(Member {
            binding: std::sync::OnceLock::from(Mutex::new(Some(g.clone()))),
        }))
    }
    pub fn retire(&self, pid: u32, ns: &PidNamespace) {
        let g = self
            .0
            .binding
            .get()
            .and_then(|slot| slot.lock().unwrap().take());
        if let Some(group) = g {
            group.leave(Actor::new(pid, ns));
        }
    }
}
impl Vfs {
    pub fn share_sem_undo_from(&mut self, parent: &Vfs) {
        self.sem_undo = parent.sem_undo.fork_shared();
    }
    pub fn retire_sem_undo(&self, pid: u32) {
        self.sem_undo.retire(pid, self.pid_namespace());
    }
}
impl DescriptorFactory {
    pub fn retire_sem_undo(&self, pid: u32) {
        self.sem_undo.retire(pid, &self.pid_namespace);
    }
}
