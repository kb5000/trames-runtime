// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared keyed futex queues. Owned tasks retain synchronized registrations;
//! tickets cross workers without Process/Memory/Rc. No host thread waits here.
use std::{
    cell::Cell,
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};

pub(super) trait Wake: Send + Sync {
    fn wake(&self, ticket: &Arc<Ticket>) -> bool;
}
impl<C: trames_engine::Cpu> Wake for crate::run_queue::Epoch<C> {
    fn wake(&self, ticket: &Arc<Ticket>) -> bool {
        self.wake(ticket)
    }
}
pub(super) type Key = (u64, u64, u64);
const SHARDS: usize = 64;
const WAITING: u32 = 0;
const WOKEN: u32 = 1;
const CANCELLED: u32 = 2;
const TIMED_OUT: u32 = 3;
const VECTOR: u32 = 4;
type Queues = BTreeMap<Key, VecDeque<Arc<Ticket>>>;

pub(super) struct Ticket {
    pub pid: u32,
    pi_tid: u32,
    bits: u32,
    decision: Decision,
    index: Option<u32>,
    key: Mutex<Key>,
}
enum Decision {
    Single(Outcome),
    Vector(Arc<Outcome>),
}
struct Outcome {
    // A single winner includes the vector index; wake/cancel/timeout cannot
    // publish a result belonging to a different member of the same wait.
    state: AtomicU32,
    target: Mutex<Option<Weak<dyn Wake>>>,
    original: OnceLock<Weak<Ticket>>,
}
impl Outcome {
    fn new(target: Option<Weak<dyn Wake>>) -> Self {
        Self {
            state: AtomicU32::new(WAITING),
            target: Mutex::new(target),
            original: OnceLock::new(),
        }
    }
}
impl Decision {
    fn new(target: Option<Weak<dyn Wake>>) -> Self {
        Self::Single(Outcome::new(target))
    }
}
impl std::ops::Deref for Decision {
    type Target = Outcome;
    fn deref(&self) -> &Outcome {
        match self {
            Self::Single(outcome) => outcome,
            Self::Vector(outcome) => outcome,
        }
    }
}
impl Ticket {
    pub fn bind<C: trames_engine::Cpu>(&self, epoch: &Arc<crate::run_queue::Epoch<C>>) {
        let target = Arc::downgrade(epoch);
        let target: Weak<dyn Wake> = target;
        *self.decision.target.lock().unwrap() = Some(target);
    }
    fn state(&self) -> u32 {
        match self.decision.state.load(Ordering::Relaxed) {
            state if state >= VECTOR => WOKEN,
            state => state,
        }
    }
    pub fn value(&self) -> u64 {
        self.decision
            .state
            .load(Ordering::Relaxed)
            .saturating_sub(VECTOR) as u64
    }
    fn claim(&self, next: u32) -> bool {
        // Only arbitrates the winner of wake/cancel/timeout. Guest data keeps
        // the interpreter's memory model; queue publication uses the mutexes.
        let next = if next == WOKEN {
            self.index.map_or(WOKEN, |index| VECTOR + index)
        } else {
            next
        };
        self.decision
            .state
            .compare_exchange(WAITING, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

struct Inner {
    queues: [Mutex<Queues>; SHARDS],
    ready: Mutex<Ready>,
}
#[derive(Default)]
struct Ready {
    tickets: VecDeque<Arc<Ticket>>,
    waiting: Vec<ReadyWait>,
    source: Option<ReadySource>,
    #[cfg(all(test, trames_interpreter_conformance))]
    owner: Option<Arc<dyn Fn() + Send + Sync>>,
}
struct ReadyWait {
    ticket: Arc<Ticket>,
    signal: Arc<trames_shared::IoSignal>,
    _subscriptions: Vec<trames_shared::IoSubscription>,
}
struct ReadySource {
    signal: Weak<trames_shared::IoSignal>,
    control: Weak<crate::workers::Control>,
}
impl ReadySource {
    fn active(&self) -> Option<Arc<trames_shared::IoSignal>> {
        self.control.upgrade().filter(|c| !c.stopped())?;
        self.signal.upgrade()
    }
}
enum Notify {
    Source(Arc<trames_shared::IoSignal>),
    #[cfg(all(test, trames_interpreter_conformance))]
    Owner(Arc<dyn Fn() + Send + Sync>),
}
impl Ready {
    fn notifier(&self) -> Option<Notify> {
        let target = self
            .source
            .as_ref()
            .and_then(ReadySource::active)
            .map(Notify::Source);
        #[cfg(all(test, trames_interpreter_conformance))]
        let target = target.or_else(|| self.owner.clone().map(Notify::Owner));
        target
    }
}
fn notify(target: Option<Notify>) {
    match target {
        Some(Notify::Source(signal)) => signal.notify(),
        #[cfg(all(test, trames_interpreter_conformance))]
        Some(Notify::Owner(wake)) => wake(),
        None => {}
    }
}
impl trames_shared::IoWake for Inner {
    fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
        let target = self.ready.lock().unwrap().notifier();
        notify(target);
    }
}
pub(super) struct ReadyDriver {
    table: Futexes,
    pub signal: Arc<trames_shared::IoSignal>,
}
impl Drop for ReadyDriver {
    fn drop(&mut self) {
        let target = {
            let mut ready = self.table.0.ready.lock().unwrap();
            if !ready
                .source
                .as_ref()
                .is_some_and(|source| source.signal.ptr_eq(&Arc::downgrade(&self.signal)))
            {
                return;
            }
            ready.source = None;
            (!ready.tickets.is_empty() || ready.waiting.iter().any(|wait| wait.signal.ready()))
                .then(|| ready.notifier())
                .flatten()
        };
        notify(target);
    }
}
impl Default for Inner {
    fn default() -> Self {
        Self {
            queues: std::array::from_fn(|_| Mutex::default()),
            ready: Default::default(),
        }
    }
}
#[derive(Clone, Default)]
pub(super) struct Futexes(Arc<Inner>);

/// Cloned task states retain the same synchronized registration. Interruption
/// and exit cancel it explicitly; final-owner Drop is a cleanup backstop.
/// Queues retain Ticket, not Wait (no ownership cycle).
/// Wake notifies the scheduler only after releasing its futex bucket.
pub(super) struct Wait {
    pub ticket: Arc<Ticket>,
    members: Vec<Arc<Ticket>>,
    table: Futexes,
}
impl Wait {
    pub fn woken(&self) -> bool {
        self.ticket.state() == WOKEN
    }
    pub fn value(&self) -> u64 {
        self.ticket.value()
    }
    pub fn timeout(&self) -> bool {
        self.ticket.claim(TIMED_OUT)
    }
    /// Retire the logical wait even while an owner checkpoint retains a clone.
    /// Dropping just the executing worker's Arc must not leave a ticket that
    /// can consume a later wake intended for the task's new wait.
    pub fn cancel(&self) {
        self.ticket.claim(CANCELLED);
        if self.members.is_empty() && self.woken() {
            return;
        }
        for ticket in std::iter::once(&self.ticket).chain(&self.members) {
            self.unlink(ticket);
        }
    }
    fn unlink(&self, ticket: &Arc<Ticket>) {
        loop {
            let key = *ticket.key.lock().unwrap();
            let mut queues = self.table.0.queues[shard(key)].lock().unwrap();
            // Requeue owns the old/new buckets before updating this key. A
            // cancellation that raced that move retries the new bucket; it
            // cannot strand a cancelled ticket there or invert key/bucket locks.
            if *ticket.key.lock().unwrap() != key {
                continue;
            }
            if let Some(queue) = queues.get_mut(&key) {
                queue.retain(|queued| !Arc::ptr_eq(queued, ticket));
                if queue.is_empty() {
                    queues.remove(&key);
                }
            }
            break;
        }
    }
}
impl Drop for Wait {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn shard((a, b, c): Key) -> usize {
    // Word offset must participate (page-aligned addresses otherwise collide).
    ((a ^ b.rotate_left(17) ^ (c >> 2) ^ (c >> 12)) as usize) & (SHARDS - 1)
}
impl Futexes {
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn wait<E>(
        &self,
        key: Key,
        pid: u32,
        bits: u32,
        compare: impl FnOnce() -> Result<(), E>,
    ) -> Result<Arc<Wait>, E> {
        self.wait_target(key, pid, bits, None, compare)
    }
    pub fn wait_target<E>(
        &self,
        key: Key,
        pid: u32,
        bits: u32,
        target: Option<Weak<dyn Wake>>,
        compare: impl FnOnce() -> Result<(), E>,
    ) -> Result<Arc<Wait>, E> {
        let mut queues = self.0.queues[shard(key)].lock().unwrap();
        // Compare and registration share the wake lock, so a concurrent wake
        // cannot fall between them. Mapping edits still require joined views.
        compare()?;
        let ticket = Arc::new(Ticket {
            pid,
            pi_tid: 0,
            bits,
            decision: Decision::new(target),
            index: None,
            key: Mutex::new(key),
        });
        queues.entry(key).or_default().push_back(ticket.clone());
        Ok(Arc::new(Wait {
            ticket,
            members: Vec::new(),
            table: self.clone(),
        }))
    }
    pub fn wait_vector<E>(
        &self,
        keys: &[Key],
        pid: u32,
        target: Option<Weak<dyn Wake>>,
        compare: impl FnOnce() -> Result<(), E>,
    ) -> Result<Arc<Wait>, E> {
        assert!(!keys.is_empty() && keys.len() <= 128);
        let mut shards: Vec<_> = keys.iter().map(|&key| shard(key)).collect();
        shards.sort_unstable();
        shards.dedup();
        // Same ascending bucket order as requeue/wake-op. Only the actual
        // address buckets are held, and no callback runs while they are held.
        let mut queues: BTreeMap<_, _> = shards
            .into_iter()
            .map(|index| (index, self.0.queues[index].lock().unwrap()))
            .collect();
        compare()?;
        let decision = Arc::new(Outcome::new(target));
        let tickets: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(index, &key)| {
                Arc::new(Ticket {
                    pid,
                    pi_tid: 0,
                    bits: u32::MAX,
                    decision: Decision::Vector(decision.clone()),
                    index: Some(index as u32),
                    key: Mutex::new(key),
                })
            })
            .collect();
        let ticket = tickets[0].clone();
        decision
            .original
            .set(Arc::downgrade(&ticket))
            .expect("new vector wait");
        for (&key, ticket) in keys.iter().zip(&tickets) {
            queues
                .get_mut(&shard(key))
                .unwrap()
                .entry(key)
                .or_default()
                .push_back(ticket.clone());
        }
        Ok(Arc::new(Wait {
            ticket,
            members: tickets.into_iter().skip(1).collect(),
            table: self.clone(),
        }))
    }
    pub fn wake(&self, key: Key, count: u32, bits: u32) -> u64 {
        self.wake_local(key, count, bits).woken
    }
    pub fn wake_regular(
        &self,
        key: Key,
        count: u32,
        bits: u32,
    ) -> Result<Effect, trames_vfs::Errno> {
        self.wake_impl(key, count, bits, true)
    }
    pub fn wake_local(&self, key: Key, count: u32, bits: u32) -> Effect {
        self.wake_impl(key, count, bits, false)
            .expect("internal futex wake")
    }
    fn wake_impl(
        &self,
        key: Key,
        count: u32,
        bits: u32,
        ordinary: bool,
    ) -> Result<Effect, trames_vfs::Errno> {
        if count == 0 {
            return Ok(Effect::default());
        }
        let mut selected = Vec::new();
        {
            let mut queues = self.0.queues[shard(key)].lock().unwrap();
            let Some(queue) = queues.get_mut(&key) else {
                return Ok(Effect::default());
            };
            if ordinary && queue.iter().any(|t| t.pi_tid != 0 && t.state() == WAITING) {
                return Err(trames_vfs::Errno(22));
            }
            queue.retain(|ticket| {
                if selected.len() < count as usize && ticket.bits & bits != 0 && ticket.claim(WOKEN)
                {
                    selected.push(ticket.clone());
                    false
                } else {
                    true
                }
            });
            if queue.is_empty() {
                queues.remove(&key);
            }
        }
        Ok(self.publish(selected, 0))
    }
    /// PI lock admission and guest-word transition share the keyed wait lock.
    /// Contended tasks release their execution slot, using ordinary retained
    /// tickets; no host mutex is held while executing guest code.
    #[allow(clippy::too_many_arguments)]
    pub fn pi_lock(
        &self,
        key: Key,
        memory: &mut impl trames_memory::CpuMemory,
        address: u64,
        pid: u32,
        tid: u32,
        target: Option<Weak<dyn Wake>>,
        try_only: bool,
    ) -> Result<Option<Arc<Wait>>, trames_vfs::Errno> {
        use trames_vfs::Errno;
        let mut queues = self.0.queues[shard(key)].lock().unwrap();
        let queue = queues.entry(key).or_default();
        queue.retain(|t| t.state() == WAITING);
        if queue.iter().any(|t| t.pi_tid == 0) {
            return Err(Errno(22));
        }
        let mut result = Ok(false);
        memory
            .atomic_update(address, 4, |bytes| {
                let word = u32::from_le_bytes(bytes.try_into().unwrap());
                let owner = word & 0x3fff_ffff;
                let next = if owner == tid {
                    result = Err(Errno(35));
                    word
                } else if owner == 0 {
                    result = Ok(true);
                    tid | (word & 0x4000_0000)
                } else if try_only {
                    result = Err(Errno(11));
                    word
                } else {
                    word | 0x8000_0000
                };
                bytes.copy_from_slice(&next.to_le_bytes());
                ((), next != word)
            })
            .map_err(|_| Errno(14))?;
        match result {
            Ok(false) => {}
            result => {
                if queue.is_empty() {
                    queues.remove(&key);
                }
                return result.map(|_| None);
            }
        }
        let ticket = Arc::new(Ticket {
            pid,
            pi_tid: tid,
            bits: u32::MAX,
            decision: Decision::new(target),
            index: None,
            key: Mutex::new(key),
        });
        queue.push_back(ticket.clone());
        Ok(Some(Arc::new(Wait {
            ticket,
            members: Vec::new(),
            table: self.clone(),
        })))
    }
    pub fn pi_unlock(
        &self,
        key: Key,
        memory: &mut impl trames_memory::CpuMemory,
        address: u64,
        tid: u32,
    ) -> Result<Effect, trames_vfs::Errno> {
        use trames_vfs::Errno;
        let mut selected = Vec::new();
        {
            let mut queues = self.0.queues[shard(key)].lock().unwrap();
            let queue = queues.entry(key).or_default();
            queue.retain(|t| t.state() == WAITING);
            if queue.iter().any(|t| t.pi_tid == 0) {
                return Err(Errno(22));
            }
            let mut result = Ok(());
            memory
                .atomic_update(address, 4, |bytes| {
                    let word = u32::from_le_bytes(bytes.try_into().unwrap());
                    if word & 0x3fff_ffff != tid {
                        result = Err(Errno(1));
                        return ((), false);
                    }
                    while let Some(ticket) = queue.pop_front() {
                        if ticket.claim(WOKEN) {
                            selected.push(ticket);
                            break;
                        }
                    }
                    let next = selected.first().map_or(0, |t| t.pi_tid | 0x8000_0000);
                    bytes.copy_from_slice(&next.to_le_bytes());
                    ((), true)
                })
                .map_err(|_| Errno(14))?;
            result?;
            if queue.is_empty() {
                queues.remove(&key);
            }
        }
        Ok(self.publish(selected, 0))
    }
    fn publish(&self, selected: Vec<Arc<Ticket>>, moved: u64) -> Effect {
        // Scheduler callbacks run after unlocking all buckets and keys.
        let woken = selected.len() as u64;
        let mut unbound = Vec::new();
        for ticket in selected {
            let ticket = match ticket.decision.original.get() {
                Some(original) => match original.upgrade() {
                    Some(ticket) => ticket,
                    None => continue,
                },
                None => ticket,
            };
            let target = ticket
                .decision
                .target
                .lock()
                .unwrap()
                .as_ref()
                .and_then(Weak::upgrade);
            if !target.is_some_and(|epoch| epoch.wake(&ticket)) {
                unbound.push(ticket);
            }
        }
        if !unbound.is_empty() {
            let target = {
                let mut ready = self.0.ready.lock().unwrap();
                ready.tickets.extend(unbound);
                ready.notifier()
            };
            notify(target);
        }
        Effect { woken, moved }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn take_ready(&self, out: &mut Vec<Arc<Ticket>>) {
        out.extend(self.take_for(None));
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn bind_owner(&self, wake: Arc<dyn Fn() + Send + Sync>) {
        self.0.ready.lock().unwrap().owner = Some(wake);
    }
    pub fn bind_source(
        &self,
        signal: Arc<trames_shared::IoSignal>,
        control: &Arc<crate::workers::Control>,
    ) -> ReadyDriver {
        let pending = {
            let mut ready = self.0.ready.lock().unwrap();
            ready.source = Some(ReadySource {
                signal: Arc::downgrade(&signal),
                control: Arc::downgrade(control),
            });
            !ready.tickets.is_empty() || ready.waiting.iter().any(|wait| wait.signal.ready())
        };
        if pending {
            signal.notify();
        }
        ReadyDriver {
            table: self.clone(),
            signal,
        }
    }
    pub fn take_source_ready(&self, signal: &Arc<trames_shared::IoSignal>) -> Vec<Arc<Ticket>> {
        self.take_for(Some(signal))
    }
    pub fn source_pending(&self, signal: &Arc<trames_shared::IoSignal>) -> bool {
        let ready = self.0.ready.lock().unwrap();
        ready
            .source
            .as_ref()
            .and_then(ReadySource::active)
            .is_some_and(|current| Arc::ptr_eq(&current, signal))
            && (!ready.tickets.is_empty() || !ready.waiting.is_empty())
    }
    fn take_for(&self, source: Option<&Arc<trames_shared::IoSignal>>) -> Vec<Arc<Ticket>> {
        let mut ready = self.0.ready.lock().unwrap();
        let current = ready.source.as_ref().and_then(ReadySource::active);
        match (source, current.as_ref()) {
            (Some(requested), Some(current)) if Arc::ptr_eq(requested, current) => {}
            (None, None) => {}
            _ => return Vec::new(),
        }
        let mut tickets: Vec<_> = ready.tickets.drain(..).collect();
        let mut retired = Vec::new();
        let mut i = 0;
        while i < ready.waiting.len() {
            if ready.waiting[i].signal.ready() {
                let wait = ready.waiting.swap_remove(i);
                tickets.push(wait.ticket.clone());
                retired.push(wait);
            } else {
                i += 1;
            }
        }
        drop(ready);
        drop(retired);
        tickets
    }
    pub fn ready_target(&self) -> Weak<dyn trames_shared::IoWake> {
        Arc::downgrade(&(self.0.clone() as Arc<dyn trames_shared::IoWake>))
    }
    pub fn defer_ready(
        &self,
        ticket: Arc<Ticket>,
        signal: Arc<trames_shared::IoSignal>,
        subscriptions: Vec<trames_shared::IoSubscription>,
    ) {
        let target = {
            let mut ready = self.0.ready.lock().unwrap();
            ready.waiting.push(ReadyWait {
                ticket,
                signal: signal.clone(),
                _subscriptions: subscriptions,
            });
            signal.ready().then(|| ready.notifier()).flatten()
        };
        notify(target);
    }
    /// The atomic guest update and both wake selections share the ordered
    /// buckets with compare-and-enqueue/requeue. Callbacks run after unlocking.
    pub fn wake_op_regular(
        &self,
        first: Key,
        second: Key,
        counts: [u32; 2],
        update: impl FnOnce() -> Result<bool, trames_vfs::Errno>,
    ) -> Result<Effect, trames_vfs::Errno> {
        self.wake_op_impl(first, second, counts, update, Some(trames_vfs::Errno(22)))
    }
    fn wake_op_impl<E>(
        &self,
        first: Key,
        second: Key,
        counts: [u32; 2],
        update: impl FnOnce() -> Result<bool, E>,
        invalid: Option<E>,
    ) -> Result<Effect, E> {
        fn select(queues: &mut Queues, key: Key, count: u32, selected: &mut Vec<Arc<Ticket>>) {
            let mut remaining = count;
            if let Some(queue) = queues.get_mut(&key) {
                queue.retain(|ticket| {
                    if remaining != 0 && ticket.claim(WOKEN) {
                        remaining -= 1;
                        selected.push(ticket.clone());
                        false
                    } else {
                        true
                    }
                });
                if queue.is_empty() {
                    queues.remove(&key);
                }
            }
        }
        let mut selected = Vec::new();
        {
            let (a, b) = (shard(first), shard(second));
            let mut low = self.0.queues[a.min(b)].lock().unwrap();
            let mut high = (a != b).then(|| self.0.queues[a.max(b)].lock().unwrap());
            let comparison = update()?;
            if let Some(error) = invalid {
                let pi = |queues: &Queues, key| {
                    queues
                        .get(&key)
                        .is_some_and(|q| q.iter().any(|t| t.pi_tid != 0 && t.state() == WAITING))
                };
                if pi(&low, first)
                    || pi(&low, second)
                    || high.as_ref().is_some_and(|q| pi(q, first) || pi(q, second))
                {
                    return Err(error);
                }
            }
            if a == b {
                select(&mut low, first, counts[0], &mut selected);
                if comparison {
                    select(&mut low, second, counts[1], &mut selected);
                }
            } else {
                let high = high.as_mut().unwrap();
                let (one, two) = if a < b {
                    (&mut low, high)
                } else {
                    (high, &mut low)
                };
                select(one, first, counts[0], &mut selected);
                if comparison {
                    select(two, second, counts[1], &mut selected);
                }
            }
        }
        Ok(self.publish(selected, 0))
    }
    /// Compare, wake and move under the same ordered bucket locks. Tickets keep
    /// their original deadline/epoch target; no Process walk or callback is needed.
    #[cfg(all(test, trames_interpreter_conformance))]
    pub fn requeue<E>(
        &self,
        old: Key,
        new: Key,
        wake: u32,
        count: u32,
        compare: impl FnOnce() -> Result<(), E>,
    ) -> Result<Effect, E> {
        self.requeue_impl(old, new, wake, count, compare, None)
    }
    pub fn requeue_regular(
        &self,
        old: Key,
        new: Key,
        wake: u32,
        count: u32,
        compare: impl FnOnce() -> Result<(), trames_vfs::Errno>,
    ) -> Result<Effect, trames_vfs::Errno> {
        self.requeue_impl(old, new, wake, count, compare, Some(trames_vfs::Errno(22)))
    }
    #[allow(clippy::too_many_arguments)]
    fn requeue_impl<E>(
        &self,
        old: Key,
        new: Key,
        wake: u32,
        count: u32,
        compare: impl FnOnce() -> Result<(), E>,
        invalid: Option<E>,
    ) -> Result<Effect, E> {
        fn select(queue: &mut VecDeque<Arc<Ticket>>, count: u32, out: &mut Vec<Arc<Ticket>>) {
            queue.retain(|ticket| {
                if out.len() < count as usize && ticket.claim(WOKEN) {
                    out.push(ticket.clone());
                    false
                } else {
                    true
                }
            });
        }
        fn transfer(
            source: &mut VecDeque<Arc<Ticket>>,
            target: &mut VecDeque<Arc<Ticket>>,
            count: u32,
            new: Key,
        ) -> u64 {
            let mut n = 0;
            while n < count as u64 {
                let Some(ticket) = source.pop_front() else {
                    break;
                };
                if ticket.state() != WAITING {
                    continue;
                }
                *ticket.key.lock().unwrap() = new;
                target.push_back(ticket);
                n += 1;
            }
            n
        }
        let mut selected = Vec::new();
        let moved;
        {
            let (a, b) = (shard(old), shard(new));
            let (lo, hi) = (a.min(b), a.max(b));
            let mut first = self.0.queues[lo].lock().unwrap();
            let mut second = (a != b).then(|| self.0.queues[hi].lock().unwrap());
            if let Some(error) = invalid {
                let pi = |queues: &Queues, key| {
                    queues
                        .get(&key)
                        .is_some_and(|q| q.iter().any(|t| t.pi_tid != 0 && t.state() == WAITING))
                };
                if pi(&first, old)
                    || pi(&first, new)
                    || second.as_ref().is_some_and(|q| pi(q, old) || pi(q, new))
                {
                    return Err(error);
                }
            }
            // Even an empty queue must perform CMP_REQUEUE's comparison.
            compare()?;
            if old == new {
                moved = if let Some(queue) = first.get_mut(&old) {
                    select(queue, wake, &mut selected);
                    queue
                        .iter()
                        .filter(|t| t.state() == WAITING)
                        .take(count as usize)
                        .count() as u64
                } else {
                    0
                };
                if first.get(&old).is_some_and(VecDeque::is_empty) {
                    first.remove(&old);
                }
            } else if a == b {
                let mut source = first.remove(&old).unwrap_or_default();
                select(&mut source, wake, &mut selected);
                moved = if count == 0 {
                    0
                } else {
                    transfer(&mut source, first.entry(new).or_default(), count, new)
                };
                if first.get(&new).is_some_and(VecDeque::is_empty) {
                    first.remove(&new);
                }
                if !source.is_empty() {
                    first.insert(old, source);
                }
            } else {
                let second = second.as_mut().unwrap();
                let (from, to) = if a == lo {
                    (&mut first, second)
                } else {
                    (second, &mut first)
                };
                let mut source = from.remove(&old).unwrap_or_default();
                select(&mut source, wake, &mut selected);
                moved = if count == 0 {
                    0
                } else {
                    transfer(&mut source, to.entry(new).or_default(), count, new)
                };
                if to.get(&new).is_some_and(VecDeque::is_empty) {
                    to.remove(&new);
                }
                if !source.is_empty() {
                    from.insert(old, source);
                }
            }
        }
        Ok(self.publish(selected, moved))
    }
}

#[derive(Default, Debug)]
pub(super) struct Effect {
    pub woken: u64,
    pub moved: u64,
}
impl Effect {
    pub fn total(&self) -> u64 {
        self.woken + self.moved
    }
}

/// Per-dispatch authority only; the actual queues persist across epochs.
pub(super) struct Authority {
    pub table: Futexes,
    pub vm: u64,
    completed: Cell<u64>,
    requeues: Cell<u64>,
    woken: Cell<u64>,
}
impl Default for Authority {
    fn default() -> Self {
        Self::new(Futexes::default(), 0)
    }
}
impl Authority {
    pub fn new(table: Futexes, vm: u64) -> Self {
        Self {
            table,
            vm,
            completed: Cell::new(0),
            requeues: Cell::new(0),
            woken: Cell::new(0),
        }
    }
    pub fn record(&self, effect: &Effect, requeue: bool) {
        if requeue {
            self.requeues.set(self.requeues.get() + 1);
        } else {
            self.completed.set(self.completed.get() + 1);
        }
        self.woken.set(self.woken.get() + effect.woken);
    }
    pub fn requeues(&self) -> u64 {
        self.requeues.get()
    }
    pub fn woken(&self) -> u64 {
        self.woken.get()
    }
    pub fn completed(&self) -> u64 {
        self.completed.get()
    }
}

impl Authority {
    pub fn robust_exit(&self, memory: &mut impl trames_memory::CpuMemory, head: u64, tid: u32) {
        if head == 0 {
            return;
        }
        let Ok(header) = memory.read_array::<24>(head) else {
            return;
        };
        let first = u64::from_le_bytes(header[..8].try_into().unwrap());
        let offset = i64::from_le_bytes(header[8..16].try_into().unwrap());
        let pending = u64::from_le_bytes(header[16..].try_into().unwrap());
        fn release(
            authority: &Authority,
            memory: &mut impl trames_memory::CpuMemory,
            entry: u64,
            offset: i64,
            tid: u32,
        ) {
            // PI lists use bit zero as a tag. Ordinary robust pthread mutexes
            // use the same atomic word and shared-key wake as Linux do_exit.
            let address = (entry & !1).wrapping_add_signed(offset);
            if address & 3 != 0 {
                return;
            }
            let old = memory.atomic_update(address, 4, |bytes| {
                let word = u32::from_le_bytes(bytes.try_into().unwrap());
                let owned = word & 0x3fff_ffff == tid;
                if owned {
                    bytes.copy_from_slice(&((word & 0x8000_0000) | 0x4000_0000).to_le_bytes());
                }
                ((word, owned), owned)
            });
            if let Ok((word, true)) = old {
                if entry & 1 == 0 && word & 0x8000_0000 != 0 {
                    if let Ok(key) =
                        crate::worker_syscalls::futex_key(memory, authority.vm, address, false)
                    {
                        authority.record(&authority.table.wake_local(key, 1, u32::MAX), false);
                    }
                }
            }
        }
        let mut entry = first;
        for _ in 0..2048 {
            if entry & !1 == head || entry & !1 == 0 {
                break;
            }
            let Ok(next) = memory.read_array::<8>(entry & !1) else {
                break;
            };
            if entry & !1 != pending & !1 {
                release(self, memory, entry, offset, tid);
            }
            entry = u64::from_le_bytes(next);
        }
        if pending & !1 != 0 {
            release(self, memory, pending, offset, tid);
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    #[test]
    fn vector_wait_keeps_one_original_wake_and_cancels_all_members_after_requeue() {
        let table = Futexes::default();
        let keys = [(0, 7, 0x1000), (0, 7, 0x2004)];
        let destination = (0, 7, 0x3008);
        let wait = table
            .wait_vector(&keys, 11, None, || Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(
            table
                .requeue_regular(keys[0], destination, 0, 1, || Ok(()))
                .unwrap()
                .moved,
            1
        );
        assert_eq!(table.wake(keys[1], 1, u32::MAX), 1);
        assert!(wait.woken());
        assert_eq!(wait.value(), 1);
        // A second member cannot consume a wake or publish another task.
        assert_eq!(table.wake(destination, 1, u32::MAX), 0);
        let mut ready = Vec::new();
        table.take_ready(&mut ready);
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0], &wait.ticket));
        drop(wait);
        empty(&table);
    }
    #[test]
    fn vector_wake_race_reports_the_claimed_member_and_never_consumes_two_wakes() {
        let table = Futexes::default();
        let keys = [(0, 8, 0x1000), (0, 8, 0x2004)];
        let wait = table
            .wait_vector(&keys, 12, None, || Ok::<_, ()>(()))
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let peers: Vec<_> = keys
            .into_iter()
            .map(|key| {
                let (table, barrier) = (table.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    table.wake(key, 1, u32::MAX)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = peers.into_iter().map(|peer| peer.join().unwrap()).collect();
        assert_eq!(results.iter().sum::<u64>(), 1);
        assert_eq!(results[wait.value() as usize], 1);
        assert!(!wait.timeout());
        drop(wait);
        empty(&table);
    }
    #[test]
    fn vector_compare_failure_and_timeout_leave_no_member_that_can_consume_a_wake() {
        let table = Futexes::default();
        let keys = [(0, 9, 0x1000), (0, 9, 0x2004)];
        assert!(table.wait_vector(&keys, 13, None, || Err(())).is_err());
        empty(&table);
        let wait = table
            .wait_vector(&keys, 13, None, || Ok::<_, ()>(()))
            .unwrap();
        assert!(wait.timeout());
        wait.cancel();
        for key in keys {
            assert_eq!(table.wake(key, 1, u32::MAX), 0);
        }
        drop(wait);
        empty(&table);
    }
    use std::{
        sync::{mpsc, Barrier},
        thread,
    };

    fn register(table: &Futexes, key: Key, pid: u32, bits: u32) -> Arc<Wait> {
        table.wait(key, pid, bits, || Ok::<_, ()>(())).unwrap()
    }
    fn empty(table: &Futexes) {
        assert!(table.0.queues.iter().all(|q| q.lock().unwrap().is_empty()));
    }
    struct ReadyWake {
        table: Weak<Inner>,
        hits: std::sync::atomic::AtomicUsize,
    }
    impl trames_shared::IoWake for ReadyWake {
        fn wake_io(&self, _: &Arc<trames_shared::IoSignal>) {
            let table = self.table.upgrade().unwrap();
            // Both readiness and futex bucket locks must be released before
            // callbacks can enter the original executor queue.
            assert!(table.ready.try_lock().is_ok());
            assert!(table.queues.iter().all(|q| q.try_lock().is_ok()));
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn ready_signal(table: &Futexes) -> (Arc<ReadyWake>, Arc<trames_shared::IoSignal>) {
        let wake = Arc::new(ReadyWake {
            table: Arc::downgrade(&table.0),
            hits: Default::default(),
        });
        let target: Arc<dyn trames_shared::IoWake> = wake.clone();
        let signal = trames_shared::IoSignal::new(0, Arc::downgrade(&target));
        (wake, signal)
    }
    #[test]
    fn unbound_ready_delivery_follows_exact_driver_replacement_and_stopped_owner_handoff() {
        let table = Futexes::default();
        let (old_wake, old_signal) = ready_signal(&table);
        let (new_wake, new_signal) = ready_signal(&table);
        let old_control = Arc::new(crate::workers::Control::new(100));
        let new_control = Arc::new(crate::workers::Control::new(100));
        let old = table.bind_source(old_signal.clone(), &old_control);
        let wait = register(&table, (0, 7, 0x1000), 3, 1);
        assert_eq!(table.wake((0, 7, 0x1000), 1, 1), 1);
        assert_eq!(old_wake.hits.load(Ordering::Relaxed), 1);
        let new = table.bind_source(new_signal.clone(), &new_control);
        assert_eq!(new_wake.hits.load(Ordering::Relaxed), 1);
        drop(old);
        assert!(table.take_source_ready(&old_signal).is_empty());
        let mut owner = Vec::new();
        table.take_ready(&mut owner);
        assert!(owner.is_empty());
        let ready = table.take_source_ready(&new_signal);
        assert_eq!(ready.len(), 1);
        assert!(Arc::ptr_eq(&ready[0], &wait.ticket));
        assert!(!table.source_pending(&new_signal));
        let retry = trames_shared::IoSignal::new(3, table.ready_target());
        table.defer_ready(wait.ticket.clone(), retry.clone(), Vec::new());
        assert!(table.source_pending(&new_signal));
        assert!(table.take_source_ready(&new_signal).is_empty());
        let owner_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = owner_hits.clone();
        let original = Arc::downgrade(&table.0);
        table.bind_owner(Arc::new(move || {
            assert!(original.upgrade().unwrap().ready.try_lock().is_ok());
            hits.fetch_add(1, Ordering::Relaxed);
        }));
        new_control.stop();
        retry.notify();
        assert_eq!(owner_hits.load(Ordering::Relaxed), 1);
        assert!(table.take_source_ready(&new_signal).is_empty());
        table.take_ready(&mut owner);
        assert_eq!(owner.len(), 1);
        assert!(Arc::ptr_eq(&owner[0], &wait.ticket));
        drop(new);
        drop(wait);
        drop(owner);
        drop(ready);
        empty(&table);
        assert!(table.0.ready.lock().unwrap().waiting.is_empty());
    }
    #[test]
    fn deferred_futex_release_before_publication_and_final_driver_drop_cannot_lose_wakes() {
        let table = Futexes::default();
        let (wake, signal) = ready_signal(&table);
        let control = Arc::new(crate::workers::Control::new(100));
        let driver = table.bind_source(signal.clone(), &control);
        let wait = register(&table, (0, 7, 0x1000), 3, 1);
        table.wake((0, 7, 0x1000), 1, 1);
        let tickets = table.take_source_ready(&signal);
        assert_eq!(tickets.len(), 1);
        signal.reset();
        let retry = trames_shared::IoSignal::new(3, table.ready_target());
        retry.notify();
        table.defer_ready(tickets[0].clone(), retry, Vec::new());
        assert!(signal.ready());
        assert!(wake.hits.load(Ordering::Relaxed) >= 2);
        let owner_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits = owner_hits.clone();
        table.bind_owner(Arc::new(move || {
            hits.fetch_add(1, Ordering::Relaxed);
        }));
        drop(driver);
        assert_eq!(owner_hits.load(Ordering::Relaxed), 1);
        let mut owner = Vec::new();
        table.take_ready(&mut owner);
        assert_eq!(owner.len(), 1);
        assert!(Arc::ptr_eq(&owner[0], &wait.ticket));
    }
    #[test]
    fn compare_requeue_is_one_transaction_and_moves_original_keys_and_bitsets() {
        let table = Futexes::default();
        let old = (0, 7, 0x1000);
        let new = (0, 7, 0x1104);
        let waits: Vec<_> = (1..=3)
            .map(|pid| register(&table, old, pid, 1 << pid))
            .collect();
        assert_eq!(
            table
                .requeue(old, new, 1, 2, || Err::<(), _>(11))
                .unwrap_err(),
            11
        );
        assert!(waits
            .iter()
            .all(|w| !w.woken() && *w.ticket.key.lock().unwrap() == old));
        let effect = table.requeue(old, new, 1, 2, || Ok::<_, ()>(())).unwrap();
        assert_eq!((effect.woken, effect.moved), (1, 2));
        assert!(waits[0].woken());
        assert!(waits[1..]
            .iter()
            .all(|w| *w.ticket.key.lock().unwrap() == new));
        assert_eq!(table.wake(old, 3, u32::MAX), 0);
        assert_eq!(table.wake(new, 3, 1 << 2), 1);
        assert!(waits[1].woken() && !waits[2].woken());
        drop(waits);
        empty(&table);
        assert_eq!(
            table
                .requeue(old, new, 0, 0, || Err::<(), _>(11))
                .unwrap_err(),
            11
        );
        empty(&table);
    }
    #[test]
    fn concurrent_opposite_requeues_and_cancellation_leave_no_stale_tickets() {
        let table = Futexes::default();
        let keys = [(0, 7, 0x1000), (0, 7, 0x1104), (0, 7, 0x1100)];
        let waits: Vec<_> = (0..2048)
            .map(|i| register(&table, keys[i % 3], i as u32 + 1, 1))
            .collect();
        let barrier = Arc::new(Barrier::new(3));
        let movers: Vec<_> = [false, true]
            .into_iter()
            .map(|reverse| {
                let (table, barrier) = (table.clone(), barrier.clone());
                thread::spawn(move || {
                    barrier.wait();
                    for i in 0..2048 {
                        let a = i % 3;
                        let b = (i + 1) % 3;
                        let (a, b) = if reverse { (b, a) } else { (a, b) };
                        table
                            .requeue(keys[a], keys[b], 0, 64, || Ok::<_, ()>(()))
                            .unwrap();
                    }
                })
            })
            .collect();
        barrier.wait();
        drop(waits);
        for mover in movers {
            mover.join().unwrap();
        }
        empty(&table);
    }
    #[test]
    fn compare_and_enqueue_exclude_wake_and_mismatches_leave_no_registration() {
        let table = Futexes::default();
        let key = (0, 7, 0x1000);
        assert!(table.wait(key, 1, 1, || Err::<(), _>(11)).is_err());
        empty(&table);
        let (entered, entry) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let peer = table.clone();
        let waker = thread::spawn(move || {
            entry.recv().unwrap();
            release.send(()).unwrap();
            peer.wake(key, 1, 1)
        });
        let wait = table
            .wait(key, 1, 1, || {
                entered.send(()).unwrap();
                released.recv().unwrap();
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(waker.join().unwrap(), 1);
        assert!(wait.woken());
        assert!(!wait.timeout());
        empty(&table);
    }
    #[test]
    fn concurrent_wakes_claim_each_ticket_once_and_preserve_bitsets_and_keys() {
        let table = Futexes::default();
        let key = (0, 7, 0x1000);
        let waits: Vec<_> = (1..=257).map(|pid| register(&table, key, pid, 1)).collect();
        let filtered = register(&table, key, 258, 2);
        let private_vm = register(&table, (0, 8, 0x1000), 259, 1);
        let shared = register(&table, (1, 7, 0x1000), 260, 1);
        let barrier = Arc::new(Barrier::new(4));
        let peers: Vec<_> = (0..4)
            .map(|_| {
                let (table, barrier) = (table.clone(), barrier.clone());
                thread::spawn(move || {
                    barrier.wait();
                    (0..257).map(|_| table.wake(key, 1, 1)).sum::<u64>()
                })
            })
            .collect();
        assert_eq!(
            peers.into_iter().map(|p| p.join().unwrap()).sum::<u64>(),
            257
        );
        assert!(waits.iter().all(|w| w.woken()));
        assert!(!filtered.woken() && !private_vm.woken() && !shared.woken());
        let mut ready = Vec::new();
        table.take_ready(&mut ready);
        let ids: std::collections::BTreeSet<_> = ready.iter().map(|t| t.pid).collect();
        assert_eq!(ids.len(), 257);
        assert_eq!(ready.len(), 257);
        drop((waits, filtered, private_vm, shared));
        empty(&table);
    }
    #[test]
    fn timeout_and_wake_race_have_one_winner() {
        let table = Futexes::default();
        let key = (0, 7, 0x1000);
        let waits: Vec<_> = (1..=512).map(|pid| register(&table, key, pid, 1)).collect();
        let tickets: Vec<_> = waits.iter().map(|w| w.ticket.clone()).collect();
        let barrier = Arc::new(Barrier::new(2));
        let (peer, start) = (table.clone(), barrier.clone());
        let waker = thread::spawn(move || {
            start.wait();
            (0..512).map(|_| peer.wake(key, 1, 1)).sum::<u64>()
        });
        let timer = thread::spawn(move || {
            barrier.wait();
            tickets.iter().filter(|t| t.claim(TIMED_OUT)).count() as u64
        });
        let (woke, timed) = (waker.join().unwrap(), timer.join().unwrap());
        assert_eq!(woke + timed, 512);
        let mut ready = Vec::new();
        table.take_ready(&mut ready);
        assert_eq!(ready.len() as u64, woke);
        assert_eq!(waits.iter().filter(|w| w.woken()).count() as u64, woke);
        drop(waits);
        empty(&table);
    }
    #[test]
    fn interrupted_wait_cannot_steal_a_new_wake_while_owner_clone_is_retained() {
        let table = Futexes::default();
        let old = (0, 7, 0x1000);
        for new in [old, (0, 7, 0x1104)] {
            let interrupted = register(&table, old, 1, 1);
            let owner_checkpoint = interrupted.clone();
            if new != old {
                assert_eq!(
                    table
                        .requeue(old, new, 0, 1, || Ok::<_, ()>(()))
                        .unwrap()
                        .total(),
                    1
                );
            }
            interrupted.cancel();
            drop(interrupted);
            let next_wait = register(&table, new, 1, 1);
            assert_eq!(table.wake(new, 1, 1), 1);
            assert!(next_wait.woken());
            assert!(!owner_checkpoint.woken());
            assert_eq!(owner_checkpoint.ticket.state(), CANCELLED);
            drop(owner_checkpoint);
            assert_eq!(table.wake(new, 1, 1), 0);
            drop(next_wait);
            empty(&table);
        }
    }
    #[test]
    fn cancellation_unlinks_the_last_registration_owner_without_stale_keys() {
        let table = Futexes::default();
        let key = (0, 7, 0x1000);
        let wait = register(&table, key, 1, 1);
        let state_clone = wait.clone();
        drop(wait);
        assert_eq!(table.wake(key, 1, 1), 1);
        drop(state_clone);
        for i in 0..512 {
            let wait = register(&table, (0, i, 0x1000 + i * 4), 1, 1);
            let ticket = wait.ticket.clone();
            drop(wait);
            assert_eq!(ticket.state(), CANCELLED);
        }
        empty(&table);
        assert_eq!(table.wake(key, u32::MAX, u32::MAX), 0);
    }
    #[test]
    fn requeue_of_timed_out_tickets_does_not_leave_empty_destination_keys() {
        let table = Futexes::default();
        let old = (0, 7, 0x1000);
        for new in [(0, 7, 0x1100), (0, 7, 0x1104)] {
            let wait = register(&table, old, 1, 1);
            assert!(wait.timeout());
            assert_eq!(
                table
                    .requeue(old, new, 0, 1, || Ok::<_, ()>(()))
                    .unwrap()
                    .total(),
                0
            );
            empty(&table);
            drop(wait);
        }
    }
    #[test]
    fn requeue_preserves_tickets_and_cleans_both_same_and_different_shards() {
        let table = Futexes::default();
        let old = (0, 7, 0x1000);
        let same = (0, 7, 0x1100);
        let different = (0, 7, 0x1104);
        assert_eq!(shard(old), shard(same));
        assert_ne!(shard(old), shard(different));
        let waits: Vec<_> = (1..=4)
            .map(|pid| register(&table, old, pid, 1 << pid))
            .collect();
        assert_eq!(table.wake(old, 1, u32::MAX), 1);
        assert_eq!(
            table
                .requeue(old, old, 0, 2, || Ok::<_, ()>(()))
                .unwrap()
                .total(),
            2
        );
        for (target, count) in [(same, 2), (different, 8)] {
            let n = table
                .requeue(old, target, 0, count, || Ok::<_, ()>(()))
                .unwrap()
                .total();
            assert_eq!(n, if target == same { 2 } else { 1 });
        }
        assert_eq!(table.wake(old, 8, u32::MAX), 0);
        assert_eq!(table.wake(same, 8, 1 << 2), 1);
        assert!(waits[1].woken());
        assert!(!waits[2].woken());
        assert_eq!(table.wake(different, 8, u32::MAX), 1);
        drop(waits); // remaining moved registration unlinks its new key
        empty(&table);
    }
}
