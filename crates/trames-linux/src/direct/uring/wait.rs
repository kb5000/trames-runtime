// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared, retained request interests for enter and CQ poll actors.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LocalSource {
    Ring(usize),
    Byte(usize),
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
    hosts: BTreeMap<(usize, bool), Subscription<trames_vfs::HostSubscription>>,
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
        signal: &Arc<IoSignal>,
        target: &Weak<dyn IoWake>,
        fd: impl FnOnce() -> std::io::Result<trames_vfs::HostFd>,
    ) -> Option<()> {
        use std::collections::btree_map::Entry;
        match self.hosts.entry(key) {
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
    pub(super) fn refresh(
        &mut self,
        rings: &[Arc<Ring>],
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        target: &Weak<dyn IoWake>,
    ) -> bool {
        for subscription in self.local.values_mut() {
            subscription.used = false;
        }
        for subscription in self.hosts.values_mut() {
            subscription.used = false;
        }
        for ring in rings {
            if !ring.subscribe_requests(owner, task, signal, target, self) {
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

impl Ring {
    pub(super) fn waitable(&self, state: &State, r: &Request) -> bool {
        state.eligible(r)
            && !self.backpressured(state, r)
            && !(r.selected() && state.busy_groups.contains(&r.sqe.buffer_group()))
    }
    pub(super) fn subscribe_requests(
        &self,
        owner: u64,
        task: u32,
        signal: &Arc<IoSignal>,
        target: &Weak<dyn IoWake>,
        sources: &mut WaitSources,
    ) -> bool {
        let state = self.state.lock().unwrap();
        sources.local(LocalSource::Ring(self.identity), || {
            vec![self.readiness.subscribe(signal)]
        });
        for r in state
            .pending
            .iter()
            .filter(|r| r.owner == owner && r.task == task && self.waitable(&state, r))
        {
            let Some(resource) = &r.resource else {
                continue;
            };
            match &resource.object {
                Object::Byte(f) => {
                    sources.local(LocalSource::Byte(resource.identity), || f.subscribe(signal))
                }
                Object::Tcp(f) => {
                    if sources
                        .host(
                            (resource.identity, r.events() & 4 != 0),
                            signal,
                            target,
                            || tcp_wait_fd(&f.tcp),
                        )
                        .is_none()
                    {
                        return false;
                    }
                }
                Object::File(_) => {}
            }
        }
        true
    }
    pub(super) fn request_deadline(&self, owner: u64, task: u32) -> Option<Instant> {
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
