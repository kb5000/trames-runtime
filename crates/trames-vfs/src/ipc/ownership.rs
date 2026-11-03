// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared owning Unix rights. Queue links never own this graph or an OFD.
use super::*;
use std::sync::{Mutex, Weak};

#[derive(Default)]
pub(crate) struct Ownership(Mutex<State>);
#[derive(Default)]
struct State {
    next: u64,
    receivers: BTreeMap<usize, BTreeMap<u64, Entry>>,
}
struct Entry {
    // Retain the allocation identity without keeping its endpoint open.
    _receiver: Weak<LocalResource>,
    targets: Vec<Weak<LocalResource>>,
    rights: Option<SharedRights>,
}
pub(super) struct Link {
    graph: Weak<Ownership>,
    receiver: usize,
    id: u64,
}
thread_local! {
    static DROP: RefCell<Option<Vec<SharedRights>>> = const { RefCell::new(None) };
}
fn release(rights: SharedRights) {
    // Closing one carried socket may retire another queue's link. Drain only
    // actual removed rights, outside the graph and queue locks, without recursion.
    DROP.with(|pending| {
        let mut state = pending.borrow_mut();
        if let Some(queue) = state.as_mut() {
            queue.push(rights);
            return;
        }
        *state = Some(vec![rights]);
        drop(state);
        loop {
            let next = pending.borrow_mut().as_mut().expect("rights drain").pop();
            if let Some(rights) = next {
                drop(rights);
            } else {
                *pending.borrow_mut() = None;
                break;
            }
        }
    });
}
impl Ownership {
    fn insert(
        self: &Arc<Self>,
        receiver: &Arc<LocalResource>,
        targets: Vec<Weak<LocalResource>>,
        rights: Option<SharedRights>,
    ) -> Result<Arc<Link>> {
        let destination = Arc::as_ptr(receiver) as usize;
        // Strong upgrades can become the final endpoint owner during a racing
        // close. Release them only after the graph guard, including error exits.
        let mut retained = Vec::new();
        let mut state = self.0.lock().unwrap();
        let mut pending = targets.clone();
        let mut visited = std::collections::BTreeSet::new();
        while let Some(weak) = pending.pop() {
            let node = weak.as_ptr() as usize;
            if node == destination {
                return Err(Errno(95));
            }
            if !visited.insert(node) {
                continue;
            }
            if let Some(entries) = state.receivers.get(&node) {
                for entry in entries.values() {
                    pending.extend(entry.targets.iter().cloned());
                }
            }
            if let Some(socket) = weak.upgrade() {
                // An unaccepted server is owned by its listener. A fresh
                // connection cannot add an owning cycle by itself; its listener
                // guard spans endpoint publication and pending insertion, so a
                // subsequent rights send observes this real edge here.
                if socket.kind != 2 && !socket.connected() {
                    let listener = socket.listener.borrow();
                    if let Some(listener) = listener.as_ref() {
                        pending.extend(listener.pending.iter().map(Arc::downgrade));
                    }
                }
                retained.push(socket);
            }
        }
        let id = state.next.checked_add(1).ok_or(Errno(75))?;
        state.next = id;
        state.receivers.entry(destination).or_default().insert(
            id,
            Entry {
                _receiver: Arc::downgrade(receiver),
                targets,
                rights,
            },
        );
        // Reservation and graph validation are one object transaction. It also
        // covers a concurrent send that has not yet published its queue packet.
        Ok(Arc::new(Link {
            graph: Arc::downgrade(self),
            receiver: destination,
            id,
        }))
    }
    pub(super) fn shared(receiver: &Arc<LocalResource>, rights: SharedRights) -> Result<Arc<Link>> {
        let graph = receiver.ownership.upgrade().ok_or(Errno(9))?;
        let targets = rights
            .iter()
            .filter_map(|o| o.local.as_ref())
            .map(Arc::downgrade)
            .collect();
        graph.insert(receiver, targets, Some(rights))
    }
    pub(super) fn legacy(
        receiver: &Arc<LocalResource>,
        rights: &LocalRights,
    ) -> Result<Option<Arc<Link>>> {
        let targets: Vec<_> = rights
            .0
            .iter()
            .filter_map(|o| o.borrow().local.as_ref().map(Arc::downgrade))
            .collect();
        if targets.is_empty() {
            return Ok(None);
        }
        let graph = receiver.ownership.upgrade().ok_or(Errno(9))?;
        graph.insert(receiver, targets, None).map(Some)
    }
}
impl Link {
    pub fn rights(&self) -> SharedRights {
        let Some(graph) = self.graph.upgrade() else {
            return SharedRights::default();
        };
        let state = graph.0.lock().unwrap();
        state.receivers[&self.receiver][&self.id]
            .rights
            .as_ref()
            .expect("shared rights link")
            .clone()
    }
}
impl Drop for Link {
    fn drop(&mut self) {
        let Some(graph) = self.graph.upgrade() else {
            return;
        };
        let removed = {
            let mut state = graph.0.lock().unwrap();
            let entries = state
                .receivers
                .get_mut(&self.receiver)
                .expect("live receiver graph");
            let removed = entries.remove(&self.id).expect("live rights link");
            if entries.is_empty() {
                state.receivers.remove(&self.receiver);
            }
            removed
        };
        if let Some(rights) = removed.rights {
            release(rights);
        }
    }
}
