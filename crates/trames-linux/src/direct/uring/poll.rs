// SPDX-License-Identifier: GPL-3.0-or-later
//! CQ poll/epoll waiters drive their own VM's accepted requests directly.
use super::*;

pub(crate) struct PollWait {
    rings: Vec<Arc<Ring>>,
    owner: u64,
    task: u32,
    target: Weak<dyn IoWake>,
    sources: wait::WaitSources,
    pub(crate) deadline: Option<Instant>,
}
impl Ring {
    fn poll_pump(&self, owner: u64, task: u32, memory: &mut impl CpuMemory) -> bool {
        {
            let state = self.state.lock().unwrap();
            // A CQ observer does not acquire another task's execution context.
            // A foreign request is observed only if its submitting task kept an
            // enter actor. Otherwise the lifecycle checkpoint must recover it.
            if state.disabled
                || state.pending.iter().any(|r| {
                    (r.owner != owner || r.task != task) && !state.waits.contains_key(&r.task)
                })
            {
                return false;
            }
        }
        if self.progress(memory, owner, task) {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        let tail = state.tail;
        if self.queue.flush(&mut state).is_err() {
            return false;
        }
        let changed = tail != state.tail;
        drop(state);
        if changed {
            self.readiness.notify_locked();
        }
        true
    }
}
impl UringSnapshot {
    pub(crate) fn poll_pump(&self, ids: &[usize], memory: &mut impl CpuMemory) -> bool {
        let mut pump = |id: &usize| {
            self.poll_rings
                .get(id)
                .is_some_and(|ring| ring.poll_pump(self.owner, self.task, memory))
        };
        if let [id] = ids {
            return pump(id);
        }
        // FD aliases must not multiply one ring's progress/fairness budget.
        ids.iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .iter()
            .all(pump)
    }
    pub(crate) fn poll_wait(&self, ids: Vec<usize>, target: Weak<dyn IoWake>) -> Option<PollWait> {
        let ids: BTreeSet<_> = ids.into_iter().collect();
        if ids.is_empty() {
            return None;
        }
        Some(PollWait {
            rings: ids
                .into_iter()
                .map(|id| self.poll_rings[&id].clone())
                .collect(),
            owner: self.owner,
            task: self.task,
            target,
            sources: wait::WaitSources::default(),
            deadline: None,
        })
    }
}
impl PollWait {
    pub(crate) fn external(&self) -> bool {
        self.sources.external()
    }
    pub(crate) fn refresh(&mut self, signal: &Arc<IoSignal>, memory: &mut impl CpuMemory) -> bool {
        self.deadline = None;
        if !self
            .sources
            .refresh(&self.rings, self.owner, self.task, signal, &self.target)
        {
            return false;
        }
        for ring in &self.rings {
            if !ring.poll_pump(self.owner, self.task, memory) {
                return false;
            }
            self.deadline = [self.deadline, ring.request_deadline(self.owner, self.task)]
                .into_iter()
                .flatten()
                .min();
        }
        true
    }
}
