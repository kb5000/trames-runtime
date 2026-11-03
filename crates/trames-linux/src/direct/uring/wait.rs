// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared, retained request interests for enter and CQ poll actors.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSource {
    Ring(usize),
    Byte(usize),
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
    hosts: BTreeMap<(usize, bool, usize), Subscription<trames_vfs::HostSubscription>>,
    deadline: Option<Instant>,
}
impl WaitSources {
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
        target: &Weak<dyn IoWake>,
        fd: impl FnOnce() -> std::io::Result<trames_vfs::HostFd>,
    ) -> Option<()> {
        use std::collections::btree_map::Entry;
        match self.hosts.entry((key.0, key.1, slot)) {
            Entry::Occupied(mut entry) => {
                let subscription = entry.get_mut();
                if !subscription.used {
                    subscription.value.rearm().ok()?;
                    subscription.used = true;
                }
            }
            Entry::Vacant(entry) => {
                let events = target.upgrade()?.host_events()?;
                entry.insert(Subscription {
                    value: events.subscribe(fd().ok()?, key.1, signal).ok()?,
                    used: true,
                });
            }
        }
        Some(())
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
    pub(super) fn refresh(
        &mut self,
        rings: &[Arc<Ring>],
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        target: &Weak<dyn IoWake>,
        actor: &UringActor,
    ) -> bool {
        self.deadline = None;
        for subscription in self.local.values_mut() {
            subscription.used = false;
        }
        for subscription in self.hosts.values_mut() {
            subscription.used = false;
        }
        for ring in rings {
            if !ring.subscribe_requests(owner, task, signal, target, self, actor) {
                return false;
            }
        }
        // Cancellation, completion, dependency changes and CQ backpressure can
        // remove interests. Do not retain their duplicate FDs or stale wakes.
        self.local.retain(|_, s| s.used);
        self.hosts.retain(|_, s| s.used);
        !self
            .local
            .values()
            .any(|entry| entry.value.iter().any(|s| s.rearm_host().is_err()))
    }
}

pub(super) trait RingWaitOps {
    fn waitable(&self, state: &State, r: &Request) -> bool;
    fn subscribe_requests(
        &self,
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        target: &Weak<dyn IoWake>,
        sources: &mut WaitSources,
        actor: &UringActor,
    ) -> bool;
    fn request_deadline(&self, owner: u64, task: u32) -> Option<Instant>;
}
impl RingWaitOps for Ring {
    fn waitable(&self, state: &State, r: &Request) -> bool {
        state.eligible(r)
            && !self.backpressured(state, r)
            && !(r.selected()
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
        target: &Weak<dyn IoWake>,
        sources: &mut WaitSources,
        actor: &UringActor,
    ) -> bool {
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
            if let Some(subscription) = actor.subscribe(self, sequence, signal) {
                let key = LocalSource::Control(self as *const Uring as usize, sequence);
                sources.local.remove(&key);
                sources.local(key, || vec![subscription]);
                continue;
            }
            if let Some(resource) = &resource {
                match &resource.object {
                    Object::Byte(f) => {
                        sources.local(LocalSource::Byte(resource.identity), || f.subscribe(signal));
                        continue;
                    }
                    Object::Tcp(f) => {
                        if sources
                            .host(
                                (resource.identity, events & 4 != 0),
                                0,
                                signal,
                                target,
                                || tcp_wait_fd(&f.tcp),
                            )
                            .is_none()
                        {
                            return false;
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
                let Ok((fds, delay)) = socket.wait_sources() else {
                    return false;
                };
                if let Some(deadline) = delay.and_then(|d| Instant::now().checked_add(d)) {
                    sources.deadline = [sources.deadline, Some(deadline)]
                        .into_iter()
                        .flatten()
                        .min();
                }
                for (i, fd) in fds.into_iter().enumerate() {
                    if sources
                        .host(
                            (file.identity(), events & 4 != 0),
                            i,
                            signal,
                            target,
                            || Ok(fd.into()),
                        )
                        .is_none()
                    {
                        return false;
                    }
                }
            }
        }
        true
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
