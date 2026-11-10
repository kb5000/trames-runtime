// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared, retained request interests for enter and CQ poll actors.
use super::poll::PollRingOps;
use super::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSource {
    Ring(usize),
    Byte(usize, u64),
    Socket(usize),
    Control(usize, u64),
}
struct Subscription<T> {
    value: T,
    used: bool,
}
/// A stopped actor keeps its subscriptions across retries. Keys are retained
/// OFD identities, not guest FD numbers; aliases cannot overwrite another wait.
/// Ring and byte identities occupy separate domains. Each actor has its own
/// signal and host one-shots, even when several actors share the same socket.
#[derive(Default)]
pub(super) struct WaitSources {
    local: BTreeMap<LocalSource, Subscription<Vec<trames_vfs::IoSubscription>>>,
    hosts: BTreeMap<(usize, bool, usize), Subscription<trames_vfs::IoSubscription>>,
    deadline: Option<Instant>,
    original: Option<trames_vfs::DirectFds>,
}
impl WaitSources {
    pub(super) fn bind_original(&mut self, fds: trames_vfs::DirectFds) {
        self.original = Some(fds);
    }
    fn local(
        &mut self,
        key: LocalSource,
        subscribe: impl FnOnce() -> Vec<trames_vfs::IoSubscription>,
    ) {
        self.local
            .entry(key)
            .or_insert_with(|| Subscription {
                value: subscribe(),
                used: true,
            })
            .used = true;
    }
    fn host(
        &mut self,
        key: (usize, bool),
        slot: usize,
        signal: &Arc<IoSignal>,
        fd: impl FnOnce() -> std::io::Result<trames_vfs::HostFd>,
    ) -> std::io::Result<bool> {
        use std::collections::btree_map::Entry;
        match self.hosts.entry((key.0, key.1, slot)) {
            Entry::Occupied(mut entry) => {
                let subscription = entry.get_mut();
                if !subscription.used {
                    subscription.value.rearm_host()?;
                    subscription.used = true;
                }
            }
            Entry::Vacant(entry) => {
                let value = trames_vfs::IoSubscription::native_direction(fd(), key.1, signal);
                value.rearm_host()?;
                entry.insert(Subscription { value, used: true });
            }
        }
        Ok(true)
    }
    pub(super) fn direct_wait_interests(&self) -> std::io::Result<Vec<(trames_vfs::HostFd, bool)>> {
        let mut fds = Vec::new();
        for subscription in self
            .hosts
            .values()
            .map(|entry| &entry.value)
            .chain(self.local.values().flat_map(|entry| entry.value.iter()))
        {
            if let Some(fd) = subscription.direct_wait_interest()? {
                fds.push(fd);
            }
        }
        Ok(fds)
    }
    fn byte(&mut self, identity: usize, fd: &trames_vfs::DirectFd, signal: &Arc<IoSignal>) -> bool {
        let revision = fd.epoll_revision().unwrap_or(0);
        let key = LocalSource::Byte(identity, revision);
        if !fd.dynamic_poll_sources() {
            if let Some(entry) = self.local.get_mut(&key) {
                entry.used = true;
                return true;
            }
        } else {
            // Native sets below an unchanged epoll can change independently of
            // its interests. Their own change notification schedules this retry.
            self.local.remove(&key);
        }
        let Some(fresh) = fd
            .refresh_epoll()
            .or_else(|| self.original.as_ref()?.bind_poll(fd))
        else {
            return false;
        };
        let revision = fresh.epoll_accepted_revision().unwrap_or(0);
        self.local(LocalSource::Byte(identity, revision), || {
            fresh.subscribe(signal)
        });
        // An interest mutation can precede first subscription. Capture proof
        // before subscribing, then close that gap without a graph-wide lock.
        if fresh.epoll_revision().is_some_and(|now| now != revision) {
            signal.notify();
        }
        true
    }
    fn socket(
        &mut self,
        identity: usize,
        socket: &trames_net::Socket,
        signal: &Arc<IoSignal>,
    ) -> std::io::Result<bool> {
        self.local(LocalSource::Socket(identity), || {
            vec![socket
                .subscribe(signal)
                .unwrap_or_else(|| socket.subscribe_changes(signal))]
        });
        if socket.is_netlink() {
            return Ok(true);
        }
        let (sources, delay) = socket.wait_interests();
        if let Some(deadline) = delay.and_then(|delay| Instant::now().checked_add(delay)) {
            self.deadline = [self.deadline, Some(deadline)].into_iter().flatten().min();
        }
        for source in sources {
            source.drain();
            self.host((identity, false), source.identity(), signal, || {
                source.open()
            })?;
        }
        Ok(true)
    }
    pub(super) fn external(&self) -> bool {
        !self.hosts.is_empty()
            || self
                .local
                .values()
                .any(|entry| entry.value.iter().any(|s| s.external()))
    }
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.deadline
    }
    /// Keep the normal subscribe-before-retry path. A failed stale interest
    /// gets one original-resource progress pass before capability escalation;
    /// a request that can finish needs no host subscription or owner pump.
    #[allow(clippy::too_many_arguments)] // Original source identity and wait resources.
    pub(super) fn prepare(
        &mut self,
        rings: &[Arc<Ring>],
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        actor: &UringActor,
        memory: &mut impl CpuMemory,
    ) -> std::io::Result<bool> {
        let first = self.refresh(rings, owner, task, signal, actor);
        if matches!(first, Ok(true)) {
            return first;
        }
        // A stale native interest can fail after its request became ready or
        // was cancelled. Retry original resources before reporting the error.
        if !rings
            .iter()
            .all(|ring| ring.poll_pump(owner, task, memory, actor))
        {
            return first.map(|_| false);
        }
        self.refresh(rings, owner, task, signal, actor)
    }
    pub(super) fn refresh(
        &mut self,
        rings: &[Arc<Ring>],
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        actor: &UringActor,
    ) -> std::io::Result<bool> {
        self.deadline = None;
        for subscription in self.local.values_mut() {
            subscription.used = false;
        }
        for subscription in self.hosts.values_mut() {
            subscription.used = false;
        }
        for ring in rings {
            if !ring.subscribe_requests(owner, task, signal, self, actor)? {
                return Ok(false);
            }
        }
        // Cancellation, completion, dependency changes and CQ backpressure can
        // remove interests. Do not retain their duplicate FDs or stale wakes.
        self.local.retain(|_, s| s.used);
        self.hosts.retain(|_, s| s.used);
        for entry in self.local.values() {
            for subscription in &entry.value {
                subscription.rearm_host()?;
            }
        }
        Ok(true)
    }
}

pub(super) trait RingWaitOps {
    fn waitable(&self, state: &State, r: &Request) -> bool;
    fn subscribe_requests(
        &self,
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        sources: &mut WaitSources,
        actor: &UringActor,
    ) -> std::io::Result<bool>;
    fn request_deadline(&self, owner: u64, task: u32) -> Option<Instant>;
}
impl RingWaitOps for Ring {
    fn waitable(&self, state: &State, r: &Request) -> bool {
        state.eligible(r)
            && !self.backpressured(state, r)
            && !(r.selection.is_none()
                && r.selected()
                && state
                    .provided
                    .get(&r.sqe.buffer_group())
                    .is_some_and(|g| state.busy_groups.contains(&g.identity)))
    }
    fn subscribe_requests(
        &self,
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        sources: &mut WaitSources,
        actor: &UringActor,
    ) -> std::io::Result<bool> {
        sources.local(LocalSource::Ring(self as *const Self as usize), || {
            vec![self.readiness.subscribe(signal)]
        });
        let interests: Vec<_> = {
            let state = self.state.lock().unwrap();
            state
                .pending
                .iter()
                .filter(|r| r.owner == owner && r.task == task && self.waitable(&state, r))
                .map(|r| (r.sequence, r.resource.clone(), r.file.clone(), r.events()))
                .collect()
        };
        // Resource subscriptions may enter their actual native socket or host
        // event object. Never retain the ring's metadata lock across them.
        for (sequence, resource, file, events) in interests {
            if let Some(subscriptions) = actor.subscribe(self, sequence, signal) {
                let key = LocalSource::Control(self as *const Uring as usize, sequence);
                sources.local.remove(&key);
                sources.local(key, || subscriptions);
                continue;
            }
            if let Some(resource) = &resource {
                match &resource.object {
                    Object::Byte(f) => {
                        if let Some(socket) = file.as_ref().and_then(|file| file.socket()) {
                            if !sources.socket(resource.identity, &socket, signal)? {
                                return Ok(false);
                            }
                        } else if !sources.byte(resource.identity, f, signal) {
                            return Ok(false);
                        }
                        continue;
                    }
                    Object::Tcp(f) => {
                        if !sources.host((resource.identity, events & 4 != 0), 0, signal, || {
                            tcp_wait_fd(&f.tcp)
                        })? {
                            return Ok(false);
                        }
                        continue;
                    }
                    Object::File(_) => continue,
                }
            }
            let Some(file) = file else {
                continue;
            };
            if let Some(socket) = file.socket() {
                if !sources.socket(file.identity(), &socket, signal)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
    fn request_deadline(&self, owner: u64, task: u32) -> Option<Instant> {
        let state = self.state.lock().unwrap();
        state
            .pending
            .iter()
            .filter(|r| r.owner == owner && r.task == task && self.waitable(&state, r))
            .filter_map(|r| {
                [
                    r.started.then_some(r.deadline).flatten(),
                    r.resource.as_ref().and_then(|f| f.next_deadline()),
                ]
                .into_iter()
                .flatten()
                .min()
            })
            .min()
    }
}

#[cfg(test)]
#[path = "wait_tests.rs"]
mod tests;
