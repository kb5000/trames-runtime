// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared keyed futex queues. Owned tasks retain synchronized registrations;
//! tickets cross workers without Process/Memory/Rc. No host thread waits here.
use std::{
    cell::Cell,
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex, Weak,
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
const WAITING: u8 = 0;
const WOKEN: u8 = 1;
const CANCELLED: u8 = 2;
const TIMED_OUT: u8 = 3;
type Queues = BTreeMap<Key, VecDeque<Arc<Ticket>>>;

pub(super) struct Ticket {
    pub pid: u32,
    bits: u32,
    state: AtomicU8,
    target: Mutex<Option<Weak<dyn Wake>>>,
    key: Mutex<Key>,
}
impl Ticket {
    pub fn bind<C: trames_engine::Cpu>(&self, epoch: &Arc<crate::run_queue::Epoch<C>>) {
        let target = Arc::downgrade(epoch);
        let target: Weak<dyn Wake> = target;
        *self.target.lock().unwrap() = Some(target);
    }

    fn claim(&self, next: u8) -> bool {
        // Only arbitrates the winner of wake/cancel/timeout. Guest data keeps
        // the interpreter's memory model; queue publication uses the mutexes.
        self.state
            .compare_exchange(WAITING, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

struct Inner {
    queues: [Mutex<Queues>; SHARDS],
    ready: Mutex<VecDeque<Arc<Ticket>>>,
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

/// Cloned task states retain the same synchronized registration; its final
/// owner cancels/unlinks it. Queues retain Ticket, not Wait (no ownership cycle).
/// Wake notifies the scheduler only after releasing its futex bucket.
pub(super) struct Wait {
    pub ticket: Arc<Ticket>,
    table: Futexes,
}
impl Wait {
    pub fn woken(&self) -> bool {
        self.ticket.state.load(Ordering::Relaxed) == WOKEN
    }
    pub fn timeout(&self) -> bool {
        self.ticket.claim(TIMED_OUT)
    }
}
impl Drop for Wait {
    fn drop(&mut self) {
        self.ticket.claim(CANCELLED);
        if self.woken() {
            return; // wake already unlinked it under the bucket lock
        }
        loop {
            let key = *self.ticket.key.lock().unwrap();
            let mut queues = self.table.0.queues[shard(key)].lock().unwrap();
            // Requeue owns the old/new buckets before updating this key. A
            // cancellation that raced that move retries the new bucket; it
            // cannot strand a cancelled ticket there or invert key/bucket locks.
            if *self.ticket.key.lock().unwrap() != key {
                continue;
            }
            if let Some(queue) = queues.get_mut(&key) {
                queue.retain(|ticket| !Arc::ptr_eq(ticket, &self.ticket));
                if queue.is_empty() {
                    queues.remove(&key);
                }
            }
            break;
        }
    }
}

fn shard((a, b, c): Key) -> usize {
    // Word offset must participate (page-aligned addresses otherwise collide).
    ((a ^ b.rotate_left(17) ^ (c >> 2) ^ (c >> 12)) as usize) & (SHARDS - 1)
}
impl Futexes {
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
            bits,
            state: AtomicU8::new(WAITING),
            target: Mutex::new(target),
            key: Mutex::new(key),
        });
        queues.entry(key).or_default().push_back(ticket.clone());
        Ok(Arc::new(Wait {
            ticket,
            table: self.clone(),
        }))
    }
    pub fn wake(&self, key: Key, count: u32, bits: u32) -> u64 {
        self.wake_local(key, count, bits).woken
    }
    pub fn wake_local(&self, key: Key, count: u32, bits: u32) -> Effect {
        if count == 0 {
            return Effect::default();
        }
        let mut selected = Vec::new();
        {
            let mut queues = self.0.queues[shard(key)].lock().unwrap();
            let Some(queue) = queues.get_mut(&key) else {
                return Effect::default();
            };
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
        self.publish(selected, 0)
    }
    fn publish(&self, selected: Vec<Arc<Ticket>>, moved: u64) -> Effect {
        // Scheduler callbacks run after unlocking all buckets and keys.
        let woken = selected.len() as u64;
        let mut legacy = false;
        for ticket in selected {
            let target = ticket
                .target
                .lock()
                .unwrap()
                .as_ref()
                .and_then(Weak::upgrade);
            if !target.is_some_and(|epoch| epoch.wake(&ticket)) {
                self.0.ready.lock().unwrap().push_back(ticket);
                legacy = true;
            }
        }
        Effect {
            woken,
            moved,
            legacy,
        }
    }
    pub fn take_ready(&self, out: &mut Vec<Arc<Ticket>>) {
        out.extend(self.0.ready.lock().unwrap().drain(..));
    }
    /// Compare, wake and move under the same ordered bucket locks. Tickets keep
    /// their original deadline/epoch target; no Process walk or callback is needed.
    pub fn requeue<E>(
        &self,
        old: Key,
        new: Key,
        wake: u32,
        count: u32,
        compare: impl FnOnce() -> Result<(), E>,
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
                if ticket.state.load(Ordering::Relaxed) != WAITING {
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
            // Even an empty queue must perform CMP_REQUEUE's comparison.
            compare()?;
            if old == new {
                moved = if let Some(queue) = first.get_mut(&old) {
                    select(queue, wake, &mut selected);
                    queue
                        .iter()
                        .filter(|t| t.state.load(Ordering::Relaxed) == WAITING)
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
    pub legacy: bool,
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
    readied: Cell<bool>,
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
            readied: Cell::new(false),
        }
    }
    pub fn record(&self, effect: &Effect, requeue: bool) {
        if requeue {
            self.requeues.set(self.requeues.get() + 1);
        } else {
            self.completed.set(self.completed.get() + 1);
        }
        self.woken.set(self.woken.get() + effect.woken);
        self.readied.set(self.readied.get() || effect.legacy);
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
    pub fn take_readied(&self) -> bool {
        self.readied.replace(false)
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
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
        assert_eq!((effect.woken, effect.moved, effect.legacy), (1, 2, true));
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
            assert_eq!(ticket.state.load(Ordering::Relaxed), CANCELLED);
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
