// SPDX-License-Identifier: GPL-3.0-or-later
//! One original interest index and topology for source and solo execution.
use super::direct_io::{DirectWatch, WatchResource};
use super::*;
use std::sync::{Mutex, RwLock};

type Observation = ((u32, u64), [u64; 2]);
type Parent = (std::sync::Weak<LiveEpoll>, (u32, u64));

pub(super) const EXCLUSIVE: u32 = 0x10000000;
pub(super) fn validate(op: u32, events: u32, old: Option<u32>, nested: bool) -> Result<()> {
    if !matches!(op, 1..=3) {
        return Err(Errno(22));
    }
    if op == 2 {
        return Ok(());
    }
    if events & EXCLUSIVE != 0 && (op != 1 || nested || events & !0xb000001d != 0)
        || op == 3 && old.is_some_and(|old| old & EXCLUSIVE != 0)
    {
        return Err(Errno(22));
    }
    if events & !0xf000201f != 0 {
        return Err(Errno(95));
    }
    Ok(())
}

thread_local! { static WALK: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) }; }
/// Concurrent DEL/reverse-ADD may overlap a retired immutable snapshot. Bound
/// that mixed-generation traversal without a global read lock or guest errno.
pub(super) struct Traversal;
impl Traversal {
    pub(super) fn enter(live: &Arc<LiveEpoll>) -> Option<Self> {
        let id = Arc::as_ptr(live) as usize;
        WALK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.len() >= 5 || stack.contains(&id) {
                return None;
            }
            stack.push(id);
            Some(Self)
        })
    }
}
impl Drop for Traversal {
    fn drop(&mut self) {
        WALK.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}
/// Nested inspection never holds a parent watch lock while traversing a child.
/// Flat inspection retains its original one-lock path. A concurrent MOD's mask
/// is applied again when recording the nested observation.
pub(super) fn inspect<const CONSUME: bool>(
    state: &Mutex<events::WatchState>,
    nested: bool,
    peek: impl FnOnce(u16) -> Result<Option<(u16, [u64; 2])>>,
) -> Result<Option<Observation>> {
    let finish = |state: &mut events::WatchState, ready: u16, epoch| {
        let ready = if nested {
            ready & (state.events as u16 | 8 | 16 | 32)
        } else {
            ready
        };
        let event = if CONSUME {
            state.observe(ready, epoch)
        } else {
            (state.armed && ready != 0 && state.ready(ready, epoch))
                .then_some((ready as u32, state.data))
        };
        event.map(|event| (event, epoch))
    };
    if nested {
        let requested = {
            let state = state.lock().unwrap();
            if !state.armed {
                return Ok(None);
            }
            state.events as u16
        };
        let Some((ready, epoch)) = peek(requested)? else {
            return Ok(None);
        };
        Ok(finish(&mut state.lock().unwrap(), ready, epoch))
    } else {
        let mut state = state.lock().unwrap();
        if !state.armed {
            return Ok(None);
        }
        let Some((ready, epoch)) = peek(state.events as u16)? else {
            return Ok(None);
        };
        Ok(finish(&mut state, ready, epoch))
    }
}
pub(super) struct LiveEpoll {
    pub(super) graph: Arc<epoll_graph::Graph>,
    open: std::sync::OnceLock<std::sync::Weak<SharedOpenDescription>>,
    watches: RwLock<Arc<Vec<DirectWatch>>>,
    pub(super) cursor: Arc<Mutex<Option<(u32, u64)>>>,
    parents: RwLock<Vec<Parent>>,
    revision: AtomicU64,
    pub(super) changed: Arc<Readiness>,
}
impl LiveEpoll {
    pub(super) fn new(graph: Arc<epoll_graph::Graph>) -> Arc<Self> {
        Arc::new(Self {
            graph,
            open: Default::default(),
            watches: Default::default(),
            cursor: Default::default(),
            parents: Default::default(),
            revision: AtomicU64::new(0),
            changed: Arc::default(),
        })
    }
    pub(super) fn bind(self: &Arc<Self>, open: &Arc<SharedOpenDescription>) {
        if self.open.set(Arc::downgrade(open)).is_ok() {
            epoll_graph::Graph::register(&self.graph, self);
        }
    }
    pub(super) fn live(&self) -> bool {
        self.open.get().is_some_and(|open| open.strong_count() != 0)
    }
    pub(super) fn children(&self) -> Vec<Arc<LiveEpoll>> {
        self.snapshot()
            .iter()
            .filter_map(|watch| watch.2.nested())
            .collect()
    }
    pub(super) fn snapshot(&self) -> Arc<Vec<DirectWatch>> {
        self.watches.read().unwrap().clone()
    }
    pub(super) fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }
    /// Only interest mutations propagate topology/subscription revisions. Data
    /// notifications still follow the original leaf readiness subscriptions.
    fn publish(&self) {
        self.revision.fetch_add(1, Ordering::Relaxed);
        let parents: Vec<_> = self
            .parents
            .read()
            .unwrap()
            .iter()
            .filter_map(|(parent, _)| parent.upgrade())
            .collect();
        self.changed.notify_atomic();
        if parents.is_empty() {
            return;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut pending = parents;
        while let Some(parent) = pending.pop() {
            if !seen.insert(Arc::as_ptr(&parent) as usize) {
                continue;
            }
            parent.revision.fetch_add(1, Ordering::Relaxed);
            pending.extend(
                parent
                    .parents
                    .read()
                    .unwrap()
                    .iter()
                    .filter_map(|(parent, _)| parent.upgrade()),
            );
            parent.changed.notify_atomic();
        }
    }
    pub(super) fn update(
        self: &Arc<Self>,
        key: (u32, u64),
        op: u32,
        events: u32,
        data: u64,
        target: WatchResource,
    ) -> Result<()> {
        let nested = target.nested();
        let change = || {
            self.update_index(key, op, events, data, target, nested.is_some())?;
            if let Some(child) = &nested {
                let mut parents = child.parents.write().unwrap();
                if op == 1 {
                    parents
                        .retain(|(parent, _)| parent.upgrade().is_some_and(|parent| parent.live()));
                    parents.push((Arc::downgrade(self), key));
                }
                if op == 2 {
                    parents.retain(|(parent, at)| {
                        *at != key || !std::ptr::eq(parent.as_ptr(), Arc::as_ptr(self))
                    });
                }
            }
            Ok(())
        };
        if let Some(child) = &nested {
            epoll_graph::Graph::change(self, child, op == 1, change)?;
        } else {
            change()?;
        }
        // No index, topology or watch-state lock spans a callback.
        self.publish();
        Ok(())
    }
    fn update_index(
        &self,
        key: (u32, u64),
        op: u32,
        events: u32,
        data: u64,
        target: WatchResource,
        nested: bool,
    ) -> Result<()> {
        let mut index = self.watches.write().unwrap();
        let at = index.binary_search_by_key(&key, |w| w.0);
        validate(
            op,
            events,
            at.ok().map(|i| index[i].1.lock().unwrap().events),
            nested,
        )?;
        match (op, at) {
            (1, Ok(_)) => return Err(Errno(17)),
            (2 | 3, Err(_)) => return Err(Errno(2)),
            (2, Ok(at)) => {
                index[at].1.lock().unwrap().armed = false;
                Arc::make_mut(&mut index).remove(at);
            }
            (3, Ok(at)) => *index[at].1.lock().unwrap() = events::WatchState::new(events, data),
            (1, Err(_)) => {
                if index.len() >= 1024 {
                    Arc::make_mut(&mut index).retain(|w| w.2.live());
                }
                if index.len() >= 1024 {
                    return Err(Errno(28));
                }
                let at = index.binary_search_by_key(&key, |w| w.0).unwrap_err();
                Arc::make_mut(&mut index).insert(
                    at,
                    (
                        key,
                        Arc::new(Mutex::new(events::WatchState::new(events, data))),
                        target,
                    ),
                );
            }
            _ => unreachable!(),
        }
        Ok(())
    }
    pub(super) fn wait_with(
        &self,
        max: usize,
        reader: Option<&Arc<dyn SignalReader>>,
    ) -> Result<Vec<(u32, u64)>> {
        let mut cursor = self.cursor.lock().unwrap();
        let shared = self.snapshot();
        let mut result = Vec::new();
        for (key, state, target) in ordered(&shared, *cursor) {
            let mut accepted = None;
            if let Some((event, epoch)) = inspect::<true>(state, target.is_nested(), |events| {
                let Some(fd) = target.resolve_with(reader) else {
                    return Ok(None);
                };
                let ready = fd.peek_poll(events);
                accepted = Some(fd);
                Ok(Some(ready))
            })? {
                if let Some(fd) = accepted {
                    fd.acknowledge(epoch);
                }
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
/// One source/solo control body over accepted original OFDs. FD validation
/// precedes this function; target type/ET checks retain their canonical order.
pub(super) fn control(
    epoll: OpenHandle,
    target: OpenHandle,
    number: u32,
    op: u32,
    events: u32,
    data: u64,
) -> Result<()> {
    if OpenHandle::ptr_eq(&epoll, &target) {
        return Err(Errno(22));
    }
    let t = target.borrow();
    let cgroup = matches!(t.control, Some(events::SharedControl::Cgroup(_)));
    if t.namespace.is_some()
        || matches!(t.kind, FdKind::Node(_))
            && t.bridge.is_none()
            && t.pipe.is_none()
            && t.kernel_log.is_none()
            && t.mount_file.is_none()
            && !cgroup
    {
        return Err(Errno(1));
    }
    if op != 2
        && events & 0x80000000 != 0
        && !matches!(t.kind, FdKind::Terminal)
        && t.local.is_none()
        && t.pipe.is_none()
        && t.kernel_log.is_none()
        && t.mount_file.is_none()
        && !cgroup
        && t.socket.as_ref().and_then(|s| s.poll_epoch()).is_none()
        && !matches!(
            t.anonymous,
            Some(
                events::Anonymous::Event(_)
                    | events::Anonymous::Timer(_)
                    | events::Anonymous::Inotify(_)
                    | events::Anonymous::Uring(_)
                    | events::Anonymous::Epoll(_)
            )
        )
    {
        return Err(Errno(95));
    }
    if matches!(t.anonymous, Some(events::Anonymous::Bpf(_))) {
        return Err(Errno(1));
    }
    // Weak OFD identity prevents a foreign descriptor with a colliding local
    // open-id from retargeting a registration after close/reuse or FD transfer.
    let key = (number, Arc::as_ptr(&t.shared) as u64);
    drop(t);
    let live = match &epoll.borrow().anonymous {
        Some(events::Anonymous::Epoll(live)) => live.clone(),
        _ => return Err(Errno(22)),
    };
    let nested = matches!(
        &target.borrow().anonymous,
        Some(events::Anonymous::Epoll(_))
    );
    let target = if nested {
        WatchResource::Nested(target.downgrade())
    } else {
        WatchResource::Original(target.downgrade())
    };
    live.update(key, op, events, data, target)
}
pub(super) fn ordered(
    watches: &[DirectWatch],
    cursor: Option<(u32, u64)>,
) -> impl Iterator<Item = &DirectWatch> {
    let at = cursor.map_or(0, |cursor| {
        watches.partition_point(|watch| watch.0 <= cursor)
    });
    watches[at..].iter().chain(watches[..at].iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Wake;
    impl IoWake for Wake {
        fn wake_io(&self, _: &Arc<IoSignal>) {}
    }
    #[test]
    fn exclusive_waiters_wake_one_eligible_interest_and_all_ordinary_interests() {
        let mut v = Vfs::default();
        let event = v.eventfd(0, 0).unwrap();
        let wake: Arc<dyn IoWake> = Arc::new(Wake);
        let mut waits = Vec::new();
        for (i, interest) in [EXCLUSIVE | 4, EXCLUSIVE | 1, EXCLUSIVE | 1, 1]
            .into_iter()
            .enumerate()
        {
            let epoll = v.epoll_create(0).unwrap();
            v.epoll_ctl(epoll, 1, event, interest, i as u64).unwrap();
            let fd = v.direct_descriptors().get(epoll).unwrap();
            let signal = IoSignal::new(i as u32 + 1, Arc::downgrade(&wake));
            let subscriptions = fd.subscribe(&signal);
            waits.push((signal, subscriptions));
        }
        // OUT was already ready; a counter increment must notify IN listeners,
        // not let the first, OUT-only exclusive interest consume their wakeup.
        v.write(event, &1u64.to_le_bytes()).unwrap();
        assert!(waits[3].0.ready());
        assert_eq!(waits[1..3].iter().filter(|w| w.0.ready()).count(), 1);
    }
    #[test]
    fn exclusive_registration_is_add_only_and_cannot_target_another_epoll() {
        let mut v = Vfs::default();
        let event = v.eventfd(0, 0).unwrap();
        let epoll = v.epoll_create(0).unwrap();
        let nested = v.epoll_create(0).unwrap();
        assert_eq!(
            v.epoll_ctl(epoll, 1, event, EXCLUSIVE | 0x40000001, 0),
            Err(Errno(22))
        );
        assert_eq!(
            v.epoll_ctl(epoll, 1, nested, EXCLUSIVE | 1, 0),
            Err(Errno(22))
        );
        v.epoll_ctl(epoll, 1, event, EXCLUSIVE | 1, 0).unwrap();
        assert_eq!(v.epoll_ctl(epoll, 3, event, 1, 0), Err(Errno(22)));
        v.epoll_ctl(epoll, 2, event, u32::MAX, 0).unwrap();
        v.epoll_ctl(epoll, 1, event, 1, 0).unwrap();
        assert_eq!(
            v.epoll_ctl(epoll, 3, event, EXCLUSIVE | 1, 0),
            Err(Errno(22))
        );
    }
}

#[cfg(test)]
#[path = "epoll_graph_tests.rs"]
mod graph_tests;
