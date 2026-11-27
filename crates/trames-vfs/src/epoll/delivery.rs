// SPDX-License-Identifier: GPL-3.0-or-later
//! Original epoll mutex custody across faultable event copies. These permits
//! belong to an operation, not an OS thread, and never keep a CPU slot blocked.
use super::*;

#[derive(Default)]
pub(crate) struct Gate {
    held: Mutex<bool>,
    available: std::sync::Condvar,
    changed: Arc<Readiness>,
}
pub(crate) struct Permit(Arc<Gate>);
impl Gate {
    pub(crate) fn enter(self: &Arc<Self>) -> Option<Permit> {
        let mut held = self.held.lock().unwrap();
        if *held {
            return None;
        }
        *held = true;
        Some(Permit(self.clone()))
    }
    /// Synchronous embedders have no executor to receive a parked call. Wait
    /// on this original object; source workers use enter/subscribe instead.
    pub(crate) fn enter_blocking(self: &Arc<Self>) -> Permit {
        let mut held = self
            .available
            .wait_while(self.held.lock().unwrap(), |held| *held)
            .unwrap();
        *held = true;
        Permit(self.clone())
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        *self.0.held.lock().unwrap() = false;
        self.0.available.notify_one();
        self.0.changed.notify_atomic();
    }
}
/// A mutex wait on an actual original epoll, including the original nested
/// file reference. Subscription precedes the executor's deciding retry.
#[derive(Clone)]
pub struct EpollBlocked {
    gate: Arc<Gate>,
    _file: Option<SharedFd>,
}
impl EpollBlocked {
    pub(super) fn new(gate: Arc<Gate>, file: Option<SharedFd>) -> Self {
        Self { gate, _file: file }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> IoSubscription {
        let subscription = self.gate.changed.subscribe(signal);
        if !*self.gate.held.lock().unwrap() {
            signal.notify();
        }
        subscription
    }
}
/// Scoped epoll observations for poll/select. All epoll mutexes are admitted
/// before providers can acknowledge proc watches; they end before user copyout.
#[derive(Default)]
pub struct EpollObservations {
    skip: Option<usize>,
    nodes: BTreeMap<usize, (Arc<LiveEpoll>, Option<SharedFd>, u64)>,
    permits: Vec<(Permit, Option<SharedFd>)>,
}
impl EpollObservations {
    pub(crate) fn collect(&mut self, live: &Arc<LiveEpoll>, file: Option<SharedFd>) {
        let id = Arc::as_ptr(live) as usize;
        if self.skip == Some(id) || self.nodes.contains_key(&id) {
            return;
        }
        self.nodes.insert(id, (live.clone(), file, live.revision()));
        self.children(live);
    }
    fn children(&mut self, live: &LiveEpoll) {
        for (_, _, resource) in live.snapshot().iter() {
            if let Some(child) = resource.nested() {
                let file = resource
                    .original_open()
                    .map(|open| SharedFd::new(open.borrow().shared.clone()));
                self.collect(&child, file);
            }
        }
    }
    pub fn admit(&mut self) -> std::result::Result<(), EpollBlocked> {
        // A poll can name the same independent epolls in opposite orders.
        // Admission order is stable; failed admission releases every permit.
        self.permits.clear();
        let mut permits = Vec::new();
        for (live, file, _) in self.nodes.values() {
            let permit = live
                .gate
                .enter()
                .ok_or_else(|| EpollBlocked::new(live.gate.clone(), file.clone()))?;
            permits.push((permit, file.clone()));
        }
        for (live, file, revision) in self.nodes.values() {
            if live.revision() != *revision {
                // Actual interest publication changed our captured subtree.
                // Yield once and recapture on its existing resource, never
                // traverse an unadmitted new child or spin under custody.
                return Err(EpollBlocked::new(live.gate.clone(), file.clone()));
            }
        }
        self.permits = permits;
        Ok(())
    }
}
impl Drop for EpollObservations {
    fn drop(&mut self) {
        self.permits.clear();
    }
}

struct Event {
    key: (u32, u64),
    state: Arc<Mutex<events::WatchState>>,
    epoch: [u64; 2],
    ready: u16,
    data: u64,
    target: Target,
}
enum Target {
    Direct(DirectFd),
    Original(SharedFd),
}
/// Absent caller authority is an executor handoff, never an empty ready set.
pub enum EpollPrepareError {
    Blocked(EpollBlocked),
    Owner,
    Error(Errno),
}
impl From<EpollBlocked> for EpollPrepareError {
    fn from(blocked: EpollBlocked) -> Self {
        Self::Blocked(blocked)
    }
}
/// An epoll_wait owns the original epoll file and mutex through its last event
/// copy. Uncopied events have never changed edge/oneshot or proc acknowledgement.
pub struct EpollDelivery {
    original: DirectFd,
    live: Arc<LiveEpoll>,
    permit: Option<Permit>,
    events: Option<Vec<Event>>,
    committed: usize,
}
impl EpollDelivery {
    pub(crate) fn new(original: DirectFd, live: Arc<LiveEpoll>) -> Self {
        Self {
            original,
            live,
            permit: None,
            events: None,
            committed: 0,
        }
    }
    pub fn prepare(&mut self, max: usize) -> std::result::Result<(), EpollPrepareError> {
        self.prepare_inner(max, None, 0, &mut |_, _| Ok(None))
    }
    pub fn prepare_owned(
        &mut self,
        max: usize,
        vfs: &Vfs,
        pending: u64,
        special: &mut impl FnMut(&FdKind, u16) -> Result<Option<(u16, [u64; 2])>>,
    ) -> std::result::Result<(), EpollPrepareError> {
        self.prepare_inner(max, Some(vfs), pending, special)
    }
    fn prepare_inner<F: FnMut(&FdKind, u16) -> Result<Option<(u16, [u64; 2])>>>(
        &mut self,
        max: usize,
        owner: Option<&Vfs>,
        pending: u64,
        special: &mut F,
    ) -> std::result::Result<(), EpollPrepareError> {
        if self.events.is_some() {
            return Ok(());
        }
        if self.permit.is_none() {
            self.permit = Some(self.live.gate.enter().ok_or_else(|| {
                EpollBlocked::new(self.live.gate.clone(), self.original.shared_file())
            })?);
        }
        let Some(_walk) = Traversal::enter(&self.live) else {
            self.events = Some(Vec::new());
            return Ok(());
        };
        let mut observations = EpollObservations::default();
        observations.skip = Some(Arc::as_ptr(&self.live) as usize);
        observations.children(&self.live);
        observations.admit()?;
        if owner.is_none() && !self.original.epoll_has_providers() {
            return Err(EpollPrepareError::Owner);
        }
        let cursor = *self.live.cursor.lock().unwrap();
        let snapshot = self.live.snapshot();
        let mut events = Vec::new();
        for (key, state, resource) in ordered(&snapshot, cursor) {
            let mut target = None;
            let mut empty = None;
            let mut missing_owner = false;
            let observed = inspect::<false>(state, resource.is_nested(), |requested| {
                let (accepted, ready) = if let Some(vfs) = owner {
                    if let Some(open) = resource.original_open() {
                        let file = SharedFd::new(open.borrow().shared.clone());
                        let ready =
                            vfs.peek_original(&open.borrow(), requested, pending, special)?;
                        (Target::Original(file), ready)
                    } else if let Some(fd) =
                        resource.resolve_with(self.original.epoll_signal_reader())
                    {
                        let ready = fd.peek_poll(requested);
                        (Target::Direct(fd), ready)
                    } else {
                        return Ok(None);
                    }
                } else if let Some(fd) = resource.resolve_with(self.original.epoll_signal_reader())
                {
                    let ready = fd.peek_poll(requested);
                    (Target::Direct(fd), ready)
                } else {
                    missing_owner = resource.live();
                    return if missing_owner {
                        Err(Errno(95))
                    } else {
                        Ok(None)
                    };
                };
                if ready.0 == 0 {
                    empty = Some(ready.1);
                }
                target = Some(accepted);
                Ok(Some(ready))
            })
            .map_err(|error| {
                if missing_owner || error == Errno(95) {
                    EpollPrepareError::Owner
                } else {
                    EpollPrepareError::Error(error)
                }
            })?;
            if let Some(((ready, data), epoch)) = observed {
                events.push(Event {
                    key: *key,
                    state: state.clone(),
                    ready: ready as u16,
                    data,
                    epoch,
                    target: target.expect("observed original file"),
                });
                if events.len() == max {
                    break;
                }
            } else if let Some(epoch) = empty {
                state.lock().unwrap().observe(0, epoch);
            }
        }
        self.events = Some(events);
        Ok(())
    }
    pub fn events(&self) -> impl Iterator<Item = (u32, u64)> + '_ {
        self.events
            .as_ref()
            .expect("admitted original epoll")
            .iter()
            .map(|event| (event.ready as u32, event.data))
    }
    pub fn len(&self) -> usize {
        self.events.as_ref().map_or(0, Vec::len)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn commit(&mut self, count: usize) {
        let events = self.events.as_ref().expect("admitted event copies");
        for event in &events[self.committed..count] {
            event
                .state
                .lock()
                .unwrap()
                .observe(event.ready, event.epoch);
            match &event.target {
                Target::Direct(fd) => fd.acknowledge(event.epoch),
                Target::Original(file) => {
                    if let Some(events::SharedControl::Pressure(pressure)) = &file.open.control { pressure.acknowledge(event.epoch); }
                    if let Some(watch) = file.open.proc_watch() {
                        watch.acknowledge(event.epoch[0]);
                    }
                }
            }
            *self.live.cursor.lock().unwrap() = Some(event.key);
        }
        self.committed = count;
    }
}
impl Drop for EpollDelivery {
    fn drop(&mut self) {
        drop(self.permit.take());
    }
}
