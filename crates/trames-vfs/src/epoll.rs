// SPDX-License-Identifier: GPL-3.0-or-later
//! Live admitted interests on the original epoll object. Owner-only targets
//! remain in its owner projection; no Rc graph enters this shared index.
use super::direct_io::{DirectWatch, WatchResource};
use super::*;
use std::sync::{atomic::AtomicUsize, Mutex, RwLock};

#[derive(Default)]
pub(super) struct LiveEpoll {
    watches: RwLock<Arc<Vec<DirectWatch>>>,
    pub(super) cursor: Arc<Mutex<Option<(u32, u64)>>>,
    owners: AtomicUsize,
    revision: AtomicU64,
    pub(super) changed: Arc<Readiness>,
}
impl LiveEpoll {
    /// Move already-registered interests when their original TCP connection
    /// becomes directly pollable. Preserve the same watch state and cursor;
    /// this is neither a new ADD nor an implicit ONESHOT rearm.
    pub(super) fn promote(&self, interests: Vec<DirectWatch>, owners: usize) {
        let mut index = self.watches.write().unwrap();
        let watches = Arc::make_mut(&mut index);
        watches.extend(interests);
        watches.sort_unstable_by_key(|w| w.0);
        // A reader seeing zero owner interests must wait for this index write
        // before inspecting the now-complete shared core.
        self.set_owner_count(owners);
        drop(index);
        self.revision.fetch_add(1, Ordering::Relaxed);
        self.changed.notify_atomic();
    }
    pub(super) fn snapshot(&self) -> Arc<Vec<DirectWatch>> {
        self.watches.read().unwrap().clone()
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }
    pub(super) fn owner_count(&self) -> usize {
        self.owners.load(Ordering::Relaxed)
    }
    pub(super) fn set_owner_count(&self, count: usize) {
        self.owners.store(count, Ordering::Relaxed);
    }
    pub(super) fn len(&self) -> usize {
        self.watches
            .read()
            .unwrap()
            .iter()
            .filter(|w| w.2.live())
            .count()
    }
    pub(super) fn contains(&self, key: (u32, u64)) -> bool {
        self.watches
            .read()
            .unwrap()
            .binary_search_by_key(&key, |w| w.0)
            .is_ok()
    }
    pub(super) fn update(
        &self,
        key: (u32, u64),
        op: u32,
        events: u32,
        data: u64,
        target: WatchResource,
    ) -> Result<()> {
        if !matches!(op, 1..=3) {
            return Err(Errno(22));
        }
        if op != 2 && events & !0xc000201f != 0 {
            return Err(Errno(95));
        }
        let mut removed = None;
        let mut retired = Vec::new();
        let mut index = self.watches.write().unwrap();
        let at = index.binary_search_by_key(&key, |w| w.0);
        match (op, at) {
            (1, Ok(_)) => return Err(Errno(17)),
            (2 | 3, Err(_)) => return Err(Errno(2)),
            (2, Ok(at)) => {
                index[at].1.lock().unwrap().armed = false;
                removed = Some(Arc::make_mut(&mut index).remove(at));
            }
            (3, Ok(at)) => *index[at].1.lock().unwrap() = events::WatchState::new(events, data),
            (1, Err(_)) => {
                // Last-close weak interests need not be scanned on every MOD.
                // Reclaim them before enforcing the original combined bound.
                if index.len() + self.owner_count() >= 1024 {
                    retired = Arc::make_mut(&mut index)
                        .extract_if(.., |w| !w.2.live())
                        .collect();
                }
                if index.len() + self.owner_count() >= 1024 {
                    return Err(Errno(28));
                }
                let at = index.binary_search_by_key(&key, |w| w.0).unwrap_err();
                Arc::make_mut(&mut index).insert(
                    at,
                    (
                        key,
                        Arc::new(std::sync::Mutex::new(events::WatchState::new(events, data))),
                        target,
                    ),
                );
            }
            _ => unreachable!(),
        }
        drop(index);
        drop(removed);
        drop(retired);
        self.revision.fetch_add(1, Ordering::Relaxed);
        // Callbacks may resubscribe immediately. Never notify under the index
        // or watch-state lock, and never create a resource-service thread.
        self.changed.notify_atomic();
        Ok(())
    }
    pub(super) fn ready(&self) -> bool {
        self.snapshot().iter().any(|(_, state, target)| {
            let Some(fd) = target.resolve() else {
                return false;
            };
            let state = state.lock().unwrap();
            let (ready, epoch) = fd.peek_poll(state.events as u16);
            state.armed && ready != 0 && state.ready(ready, epoch)
        })
    }
    pub(super) fn epoch(&self) -> u64 {
        self.snapshot()
            .iter()
            .filter_map(|w| w.2.resolve())
            .map(|fd| fd.peek_poll(0).1)
            .fold(self.revision(), |n, e| {
                n.wrapping_add(e[0]).wrapping_add(e[1])
            })
    }
    pub(super) fn wait(&self, max: usize, frozen: &[DirectWatch]) -> Result<Vec<(u32, u64)>> {
        let mut cursor = self.cursor.lock().unwrap();
        let shared = self.snapshot();
        let mut result = Vec::new();
        for (key, state, target) in ordered(&shared, frozen, *cursor) {
            let Some(fd) = target.resolve() else {
                continue;
            };
            let mut state = state.lock().unwrap();
            if !state.armed {
                continue;
            }
            let (ready, epoch) = fd.peek_poll(state.events as u16);
            if let Some(event) = state.observe(ready, epoch) {
                fd.acknowledge(epoch);
                *cursor = Some(*key);
                result.push(event);
                if result.len() == max {
                    break;
                }
            }
        }
        Ok(result)
    }
}
fn merge<'a>(a: &'a [DirectWatch], b: &'a [DirectWatch]) -> impl Iterator<Item = &'a DirectWatch> {
    let (mut a, mut b) = (a.iter().peekable(), b.iter().peekable());
    std::iter::from_fn(move || match (a.peek(), b.peek()) {
        (Some(x), Some(y)) if x.0 <= y.0 => a.next(),
        (_, Some(_)) => b.next(),
        _ => a.next(),
    })
}
pub(super) fn ordered<'a>(
    a: &'a [DirectWatch],
    b: &'a [DirectWatch],
    cursor: Option<(u32, u64)>,
) -> impl Iterator<Item = &'a DirectWatch> {
    let i = cursor.map_or(0, |c| a.partition_point(|w| w.0 <= c));
    let j = cursor.map_or(0, |c| b.partition_point(|w| w.0 <= c));
    merge(&a[i..], &b[j..]).chain(merge(&a[..i], &b[..j]))
}
