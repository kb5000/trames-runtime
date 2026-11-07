// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared owning Unix rights. Queue links never own this graph or an OFD.
use super::*;
use std::sync::{Mutex, Weak};

type NodeKey = (u8, usize);
#[derive(Clone)]
enum Node {
    Socket(Weak<LocalResource>),
    Ring(Weak<Uring>),
}
impl Node {
    fn key(&self) -> NodeKey {
        match self {
            Self::Socket(weak) => (0, weak.as_ptr() as usize),
            Self::Ring(weak) => (1, weak.as_ptr() as usize),
        }
    }
    fn open(open: &SharedOpenDescription) -> Option<Self> {
        if let Some(socket) = &open.local {
            return Some(Self::Socket(Arc::downgrade(socket)));
        }
        match &open.control {
            Some(events::SharedControl::Uring(ring)) => Some(Self::Ring(Arc::downgrade(ring))),
            _ => None,
        }
    }
}
struct Retained {
    _socket: Option<Arc<LocalResource>>,
    _ring: Option<Arc<Uring>>,
}
/// Traversal upgrades may become final OFD owners during a concurrent close.
/// Their caller stages this value until its own resource lock is released.
#[derive(Default)]
pub(crate) struct Retirement(Vec<Retained>);
impl Retirement {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
#[derive(Default)]
pub(crate) struct Ownership(Mutex<State>);
#[derive(Default)]
struct State {
    next: u64,
    receivers: BTreeMap<NodeKey, BTreeMap<u64, Entry>>,
}
struct Entry {
    // Retain the allocation identity without keeping its endpoint open.
    _receiver: Node,
    targets: Vec<Node>,
    rights: Option<SharedRights>,
}
pub(crate) struct Link {
    graph: Weak<Ownership>,
    receiver: NodeKey,
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
        receiver: Node,
        targets: Vec<Node>,
        rights: Option<SharedRights>,
    ) -> Result<Arc<Link>> {
        let (result, retired) = self.insert_deferred(receiver, targets, rights);
        drop(retired);
        result
    }
    fn insert_deferred(
        self: &Arc<Self>,
        receiver: Node,
        targets: Vec<Node>,
        rights: Option<SharedRights>,
    ) -> (Result<Arc<Link>>, Retirement) {
        let destination = receiver.key();
        // Strong upgrades can become the final endpoint owner during a racing
        // close. Release them only after the graph guard, including error exits.
        let mut retained = Vec::new();
        let result = (|| {
            let mut state = self.0.lock().unwrap();
            let mut pending = targets.clone();
            let mut visited = std::collections::BTreeSet::new();
            while let Some(weak) = pending.pop() {
                let node = weak.key();
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
                match weak {
                    Node::Socket(weak) => {
                        if let Some(socket) = weak.upgrade() {
                            if socket.kind != 2 && !socket.connected() {
                                let listener = socket.listener.borrow();
                                if let Some(listener) = listener.as_ref() {
                                    pending.extend(
                                        listener
                                            .pending
                                            .iter()
                                            .map(|s| Node::Socket(Arc::downgrade(s))),
                                    );
                                }
                            }
                            retained.push(Retained {
                                _socket: Some(socket),
                                _ring: None,
                            });
                        }
                    }
                    Node::Ring(weak) => {
                        if let Some(ring) = weak.upgrade() {
                            retained.push(Retained {
                                _socket: None,
                                _ring: Some(ring),
                            });
                        }
                    }
                }
            }

            let id = state.next.checked_add(1).ok_or(Errno(75))?;
            state.next = id;
            state.receivers.entry(destination).or_default().insert(
                id,
                Entry {
                    _receiver: receiver,
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
        })();
        (result, Retirement(retained))
    }
    pub(super) fn shared(receiver: &Arc<LocalResource>, rights: SharedRights) -> Result<Arc<Link>> {
        let graph = receiver.ownership.upgrade().ok_or(Errno(9))?;
        let targets = rights.iter().filter_map(|o| Node::open(o)).collect();
        graph.insert(
            Node::Socket(Arc::downgrade(receiver)),
            targets,
            Some(rights),
        )
    }
    pub(crate) fn ring(
        receiver: &Arc<Uring>,
        file: &SharedOpenDescription,
    ) -> (Result<Option<Arc<Link>>>, Retirement) {
        let Some(target) = Node::open(file) else {
            return (Ok(None), Retirement::default());
        };
        let Some(graph) = receiver.ownership.upgrade() else {
            return (Err(Errno(9)), Retirement::default());
        };
        let (result, retired) =
            graph.insert_deferred(Node::Ring(Arc::downgrade(receiver)), vec![target], None);
        (result.map(Some), retired)
    }
}
impl Link {
    pub(crate) fn belongs_to_ring(&self, ring: &Uring) -> bool {
        self.receiver == (1, ring as *const Uring as usize)
    }
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
