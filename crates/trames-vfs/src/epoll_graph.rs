// SPDX-License-Identifier: GPL-3.0-or-later
//! Original nested-interest topology. Only nested-edge transactions take this
//! gate; flat controls, readiness, data I/O and CPU execution do not.
use super::*;
use std::sync::{Mutex, Weak};

#[derive(Default)]
pub(super) struct Graph(Mutex<State>);
#[derive(Default)]
struct State {
    parent: Option<Arc<Graph>>,
    nodes: Vec<Weak<epoll::LiveEpoll>>,
}
impl Graph {
    fn root(graph: &Arc<Self>) -> Arc<Self> {
        let mut graph = graph.clone();
        loop {
            let parent = graph.0.lock().unwrap().parent.clone();
            match parent {
                Some(parent) => graph = parent,
                None => return graph,
            }
        }
    }
    /// Foreign original descriptor graphs can meet through real FD transfers.
    /// Join those topology resources, with ordered root locks and weak nodes;
    /// no host-global registry, synthetic exclusion or lifetime cycle is added.
    fn joined<T>(
        a: &Arc<Self>,
        b: &Arc<Self>,
        operation: impl FnOnce(&mut Vec<Weak<epoll::LiveEpoll>>) -> T,
    ) -> T {
        loop {
            let mut a = Self::root(a);
            let mut b = Self::root(b);
            if Arc::ptr_eq(&a, &b) {
                let mut state = a.0.lock().unwrap();
                if state.parent.is_some() {
                    continue;
                }
                return operation(&mut state.nodes);
            }
            if Arc::as_ptr(&a) > Arc::as_ptr(&b) {
                std::mem::swap(&mut a, &mut b);
            }
            let mut first = a.0.lock().unwrap();
            let mut second = b.0.lock().unwrap();
            if first.parent.is_some() || second.parent.is_some() {
                continue;
            }
            first.nodes.append(&mut second.nodes);
            second.parent = Some(a.clone());
            return operation(&mut first.nodes);
        }
    }
    pub(super) fn register(graph: &Arc<Self>, node: &Arc<epoll::LiveEpoll>) {
        Self::joined(graph, graph, |nodes| {
            nodes.retain(|node| node.strong_count() != 0);
            nodes.push(Arc::downgrade(node));
        });
    }
    pub(super) fn change<T>(
        source: &Arc<epoll::LiveEpoll>,
        target: &Arc<epoll::LiveEpoll>,
        add: bool,
        operation: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        Self::joined(&source.graph, &target.graph, |nodes| {
            if add {
                fn height(
                    node: &Arc<epoll::LiveEpoll>,
                    source: &Arc<epoll::LiveEpoll>,
                    target: &Arc<epoll::LiveEpoll>,
                    active: &mut std::collections::BTreeSet<usize>,
                    memo: &mut BTreeMap<usize, usize>,
                ) -> Result<usize> {
                    let id = Arc::as_ptr(node) as usize;
                    if let Some(height) = memo.get(&id) {
                        return Ok(*height);
                    }
                    if !active.insert(id) {
                        return Err(Errno(40));
                    }
                    let mut depth = 1;
                    for child in node
                        .children()
                        .into_iter()
                        .chain(Arc::ptr_eq(node, source).then(|| target.clone()))
                    {
                        depth = depth.max(1 + height(&child, source, target, active, memo)?);
                        if depth > 5 {
                            return Err(Errno(40));
                        }
                    }
                    active.remove(&id);
                    memo.insert(id, depth);
                    Ok(depth)
                }
                let mut memo = BTreeMap::new();
                let mut active = std::collections::BTreeSet::new();
                for node in nodes
                    .iter()
                    .filter_map(Weak::upgrade)
                    .filter(|node| node.live())
                {
                    height(&node, source, target, &mut active, &mut memo)?;
                }
            }
            operation()
        })
    }
}
