// SPDX-License-Identifier: GPL-3.0-or-later
//! Namespace-owned System V sets. Arrays commit under their original set lock.
//! Sleepers retain the set and use normal source-executor readiness.
use super::*;
use std::sync::{atomic::AtomicUsize, Mutex, Weak};

mod undo;
use undo::Group;
pub use undo::UndoMember;

const MAX_SETS: u32 = 32000;
const MAX_SEMS: u32 = 32000;
const MAX_VALUE: i32 = 32767;
pub const MAX_OPS: usize = 500;
const INDEX_MASK: u32 = 32767;
#[derive(Default)]
pub(super) struct Semaphores(Mutex<Directory>);
#[derive(Default)]
struct Directory {
    next: u32,
    slots: BTreeMap<u32, Arc<Set>>,
    keys: BTreeMap<i32, u32>,
    count: u32,
}
pub struct Set {
    id: u32,
    key: i32,
    size: u32,
    namespace: UserNamespace,
    state: Mutex<State>,
    ready: Arc<Readiness>,
}
#[derive(Clone, Default)]
struct Actor {
    pid: u32,
    _reference: Option<PidReference>,
}
impl Actor {
    fn new(pid: u32, ns: &PidNamespace) -> Self {
        Self {
            pid,
            _reference: ns.retain(pid),
        }
    }
}
#[derive(Default)]
struct Value {
    val: i32,
    actor: Actor,
}
struct State {
    mode: crate::sysv_ipc::Permissions,
    changed: u64,
    operated: u64,
    dead: bool,
    // Large untouched sets have no per-semaphore allocation.
    values: BTreeMap<u16, Value>,
    waiters: BTreeMap<u64, (u16, bool)>,
    next_waiter: u64,
    undo: BTreeMap<usize, undo::Adjustments>,
}
#[derive(Clone, Copy)]
pub struct Operation {
    pub index: u16,
    pub change: i16,
    pub flags: u16,
}
pub struct Request {
    set: Arc<Set>,
    actor: Actor,
    credentials: Credentials,
    operations: Vec<Operation>,
    undo: Option<Arc<Group>>,
    // Only modified while holding the set lock. Zero denotes no wait registration.
    waiter: AtomicU64,
}
impl Request {
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        self.set.ready.subscribe(signal)
    }
    pub fn waiting(&self) -> bool {
        self.waiter.load(Ordering::Relaxed) != 0
    }
    fn clear_wait(&self, s: &mut State) {
        let id = self.waiter.swap(0, Ordering::Relaxed);
        if id != 0 {
            s.waiters.remove(&id);
        }
    }
    pub fn attempt(&self) -> Result<()> {
        let mut s = self.set.state.lock().unwrap();
        self.clear_wait(&mut s);
        if s.dead {
            return Err(Errno(43));
        }
        let write = self.operations.iter().any(|op| op.change != 0);
        if !s.mode.allowed(
            &self.credentials,
            if write { 2 } else { 4 },
            &self.set.namespace,
        ) {
            return Err(Errno(13));
        }
        let mut staged = BTreeMap::new();
        let mut undo = BTreeMap::new();
        for op in &self.operations {
            let val = staged
                .entry(op.index)
                .or_insert_with(|| s.values.get(&op.index).map_or(0, |v| v.val));
            let next = *val + i32::from(op.change);
            if next < 0 || (op.change == 0 && *val != 0) {
                if op.flags & 0x800 == 0 {
                    s.next_waiter += 1;
                    let id = s.next_waiter;
                    s.waiters.insert(id, (op.index, op.change == 0));
                    self.waiter.store(id, Ordering::Relaxed);
                }
                return Err(Errno(11));
            }
            if next > MAX_VALUE {
                return Err(Errno(34));
            }
            *val = next;
            if op.flags & 0x1000 != 0 && op.change != 0 {
                let key = Arc::as_ptr(self.undo.as_ref().unwrap()) as usize;
                let adjustment = undo.entry(op.index).or_insert_with(|| {
                    s.undo
                        .get(&key)
                        .and_then(|r| r.values.get(&op.index))
                        .copied()
                        .unwrap_or(0)
                });
                *adjustment -= i32::from(op.change);
                if !(-32768..=MAX_VALUE).contains(adjustment) {
                    return Err(Errno(34));
                }
            }
        }
        if let Some(group) = &self.undo {
            group.commit(&self.set, &mut s, undo)?;
        }
        for (idx, val) in staged {
            s.values.insert(
                idx,
                Value {
                    val,
                    actor: self.actor.clone(),
                },
            );
        }
        s.operated = crate::sysv_ipc::now();
        drop(s);
        if write {
            self.set.ready.notify_locked();
        }
        Ok(())
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        if self.waiting() {
            self.clear_wait(&mut self.set.state.lock().unwrap());
        }
    }
}
impl DescriptorFactory {
    pub fn semaphore_get(&self, key: i32, size: u32, flags: u32) -> Result<u32> {
        if size > MAX_SEMS {
            return Err(Errno(22));
        }
        let mut dir = self.ipc_namespace.semaphores.0.lock().unwrap();
        if key != 0 {
            if let Some(id) = dir.keys.get(&key) {
                if flags & 0x600 == 0x600 {
                    return Err(Errno(17));
                }
                let set = &dir.slots[&(id & INDEX_MASK)];
                if size > set.size {
                    return Err(Errno(22));
                }
                let bits = ((flags >> 6) | (flags >> 3) | flags) & 7;
                if !set
                    .state
                    .lock()
                    .unwrap()
                    .mode
                    .allowed(&self.credentials, bits, &set.namespace)
                {
                    return Err(Errno(13));
                }
                return Ok(*id);
            }
            if flags & 0x200 == 0 {
                return Err(Errno(2));
            }
        }
        if size == 0 {
            return Err(Errno(22));
        }
        if dir.slots.len() >= MAX_SETS as usize {
            return Err(Errno(28));
        }
        let id = loop {
            let id = dir.next;
            dir.next = (id + 1) & 0x7fffffff;
            if !dir.slots.contains_key(&(id & INDEX_MASK)) {
                break id;
            }
        };
        let set = Arc::new(Set {
            id,
            key,
            size,
            namespace: self.ipc_namespace.user_namespace.clone(),
            ready: Arc::default(),
            state: Mutex::new(State {
                mode: crate::sysv_ipc::Permissions::new(&self.credentials, flags),
                changed: crate::sysv_ipc::now(),
                operated: 0,
                dead: false,
                values: Default::default(),
                waiters: Default::default(),
                next_waiter: 0,
                undo: Default::default(),
            }),
        });
        dir.slots.insert(id & INDEX_MASK, set);
        if key != 0 {
            dir.keys.insert(key, id);
        }
        dir.count += size;
        Ok(id)
    }
    pub fn semaphore_set(&self, id: u32, by_index: bool) -> Result<Arc<Set>> {
        let d = self.ipc_namespace.semaphores.0.lock().unwrap();
        d.slots
            .get(&(id & INDEX_MASK))
            .filter(|s| {
                if by_index {
                    id <= INDEX_MASK
                } else {
                    s.id == id
                }
            })
            .cloned()
            .ok_or(Errno(22))
    }
    pub fn semaphore_request(&self, id: u32, ops: Vec<Operation>, pid: u32) -> Result<Request> {
        if ops.is_empty() {
            return Err(Errno(22));
        }
        if ops.len() > MAX_OPS {
            return Err(Errno(7));
        }
        let set = self.semaphore_set(id, false)?;
        if ops.iter().any(|o| u32::from(o.index) >= set.size) {
            return Err(Errno(27));
        }
        let undo = ops
            .iter()
            .any(|o| o.flags & 0x1000 != 0 && o.change != 0)
            .then(|| self.sem_undo.group());
        Ok(Request {
            set,
            actor: Actor::new(pid, &self.pid_namespace),
            credentials: self.credentials.clone(),
            operations: ops,
            undo,
            waiter: AtomicU64::new(0),
        })
    }
    pub fn semaphore_info(&self, dynamic: bool) -> (u64, Vec<u8>) {
        let dir = self.ipc_namespace.semaphores.0.lock().unwrap();
        let max = MAX_SEMS * MAX_SETS;
        let fields = [
            max,
            MAX_SETS,
            max,
            max,
            MAX_SEMS,
            MAX_OPS as u32,
            MAX_OPS as u32,
            if dynamic { dir.slots.len() as u32 } else { 20 },
            MAX_VALUE as u32,
            if dynamic { dir.count } else { MAX_VALUE as u32 },
        ];
        (
            u64::from(dir.slots.keys().next_back().copied().unwrap_or(0)),
            fields.into_iter().flat_map(u32::to_le_bytes).collect(),
        )
    }
    pub fn semaphore_remove(&self, id: u32) -> Result<()> {
        let mut d = self.ipc_namespace.semaphores.0.lock().unwrap();
        let set = d
            .slots
            .get(&(id & INDEX_MASK))
            .filter(|s| s.id == id)
            .cloned()
            .ok_or(Errno(22))?;
        let mut s = set.state.lock().unwrap();
        if !s.mode.controls(&self.credentials, &set.namespace) {
            return Err(Errno(1));
        }
        s.dead = true;
        undo::clear_all(&set, &mut s);
        d.slots.remove(&(id & INDEX_MASK));
        d.count -= set.size;
        if set.key != 0 {
            d.keys.remove(&set.key);
        }
        drop(s);
        drop(d);
        set.ready.notify_locked();
        Ok(())
    }
}
impl Set {
    pub fn size(&self) -> usize {
        self.size as usize
    }
    pub fn control(
        &self,
        f: &DescriptorFactory,
        index: u32,
        cmd: u32,
        arg: u64,
        bytes: &[u8],
        pid: u32,
    ) -> Result<(u64, Vec<u8>)> {
        let mut s = self.state.lock().unwrap();
        if s.dead {
            return Err(Errno(43));
        }
        let c = &f.credentials;
        let bits = match cmd {
            1 => {
                if !s.mode.controls(c, &self.namespace) {
                    return Err(Errno(1));
                }
                0
            }
            2 | 11..=15 | 18 => 4,
            16 | 17 => 2,
            20 => 0,
            _ => return Err(Errno(22)),
        };
        if !s.mode.allowed(c, bits, &self.namespace) {
            return Err(Errno(13));
        }
        if matches!(cmd, 11 | 12 | 14..=16) && index >= self.size {
            return Err(Errno(22));
        }
        let idx = index as u16;
        let mut out = Vec::new();
        let mut result = 0;
        match cmd {
            1 => {
                let word = |i| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
                if bytes.len() != 88 {
                    return Err(Errno(14));
                }
                let uid = c.mapped_id(false, word(4))?;
                let gid = c.mapped_id(true, word(8))?;
                s.mode.uid = uid;
                s.mode.gid = gid;
                s.mode.mode = word(20) & 0o777;
            }
            2 | 18 | 20 => {
                out.resize(88, 0);
                for (offset, v) in [
                    (0, self.key as u32),
                    (4, c.local_id(false, s.mode.uid)),
                    (8, c.local_id(true, s.mode.gid)),
                    (12, c.local_id(false, s.mode.cuid)),
                    (16, c.local_id(true, s.mode.cgid)),
                    (20, s.mode.mode),
                    (24, self.id >> 15),
                ] {
                    out[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
                }
                for (offset, v) in [(48, s.operated), (56, s.changed), (64, self.size as u64)] {
                    out[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
                }
                if cmd != 2 {
                    result = self.id as u64;
                }
            }
            11 => {
                result = s
                    .values
                    .get(&idx)
                    .map_or(0, |v| f.pid_namespace.local(v.actor.pid) as u64)
            }
            12 => result = s.values.get(&idx).map_or(0, |v| v.val as u64),
            13 => {
                out.resize(self.size() * 2, 0);
                for (index, v) in &s.values {
                    let i = usize::from(*index) * 2;
                    out[i..i + 2].copy_from_slice(&(v.val as u16).to_le_bytes());
                }
            }
            14 | 15 => {
                result = s
                    .waiters
                    .values()
                    .filter(|w| **w == (idx, cmd == 15))
                    .count() as u64
            }
            16 => {
                let val = arg as i32;
                if !(0..=MAX_VALUE).contains(&val) {
                    return Err(Errno(34));
                }
                s.values.insert(
                    idx,
                    Value {
                        val,
                        actor: Actor::new(pid, &f.pid_namespace),
                    },
                );
                for r in s.undo.values_mut() {
                    r.values.remove(&idx);
                }
            }
            17 => {
                if bytes.len() != self.size() * 2 {
                    return Err(Errno(14));
                }
                let vals = bytes
                    .chunks_exact(2)
                    .map(|b| i32::from(u16::from_le_bytes([b[0], b[1]])));
                if vals.clone().any(|v| v > MAX_VALUE) {
                    return Err(Errno(34));
                }
                let actor = Actor::new(pid, &f.pid_namespace);
                for (idx, val) in vals.enumerate() {
                    s.values.insert(
                        idx as u16,
                        Value {
                            val,
                            actor: actor.clone(),
                        },
                    );
                }
                undo::clear_all(self, &mut s);
            }
            _ => unreachable!(),
        }
        if matches!(cmd, 1 | 16 | 17) {
            s.changed = crate::sysv_ipc::now();
            drop(s);
            self.ready.notify_locked();
        }
        Ok((result, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn op(f: &DescriptorFactory, id: u32, index: u16, change: i16) -> Request {
        f.semaphore_request(
            id,
            vec![Operation {
                index,
                change,
                flags: 0x1000,
            }],
            9,
        )
        .unwrap()
    }
    #[test]
    fn undo_is_applied_at_last_member_exit_even_with_retained_observers() {
        let parent = Vfs::default();
        let f = parent.descriptor_factory();
        let id = f.semaphore_get(0, 2, 0o600).unwrap();
        let set = f.semaphore_set(id, false).unwrap();
        op(&f, id, 0, 5).attempt().unwrap();
        let mut child = parent.clone_with_resources(false, false);
        child.share_sem_undo_from(&parent);
        let c = child.descriptor_factory();
        op(&c, id, 1, 7).attempt().unwrap();
        set.control(&f, 0, 16, 20, &[], 9).unwrap();
        parent.retire_sem_undo(9);
        let value = |i| set.control(&f, i, 12, 0, &[], 9).unwrap().0;
        assert_eq!((value(0), value(1)), (20, 7));
        child.retire_sem_undo(10);
        assert_eq!((value(0), value(1)), (20, 0));
        assert_eq!(set.control(&f, 1, 11, 0, &[], 9).unwrap().0, 10);
    }
    #[test]
    fn cancelled_array_wait_retains_original_set_and_rolls_back_partial_changes() {
        let v = Vfs::default();
        let f = v.descriptor_factory();
        let id = f.semaphore_get(5, 2, 0o1600).unwrap();
        let set = f.semaphore_set(id, false).unwrap();
        let request = f
            .semaphore_request(
                id,
                vec![
                    Operation {
                        index: 0,
                        change: 2,
                        flags: 0x1000,
                    },
                    Operation {
                        index: 1,
                        change: -1,
                        flags: 0,
                    },
                ],
                1,
            )
            .unwrap();
        assert_eq!(request.attempt(), Err(Errno(11)));
        assert_eq!(set.control(&f, 0, 12, 0, &[], 1).unwrap().0, 0);
        assert_eq!(set.control(&f, 1, 14, 0, &[], 1).unwrap().0, 1);
        f.semaphore_remove(id).unwrap();
        let new = f.semaphore_get(5, 2, 0o1600).unwrap();
        assert_ne!(id, new);
        assert_eq!(request.attempt(), Err(Errno(43)));
        assert_eq!(
            f.semaphore_set(new, false)
                .unwrap()
                .control(&f, 1, 14, 0, &[], 1)
                .unwrap()
                .0,
            0
        );
    }
}
