// SPDX-License-Identifier: GPL-3.0-or-later
//! CQ poll/epoll waiters drive their own VM's accepted requests directly.
use super::*;

pub(crate) struct PollWait {
    rings: Vec<Arc<Ring>>,
    actor: Arc<UringActor>,
    owner: u64,
    task: u32,
    target: Weak<dyn IoWake>,
    sources: wait::WaitSources,
    pub(crate) deadline: Option<Instant>,
}
pub(super) trait PollRingOps {
    fn poll_pump(
        &self,
        owner: u64,
        task: u32,
        memory: &mut impl CpuMemory,
        actor: &UringActor,
    ) -> bool;
}
impl PollRingOps for Ring {
    fn poll_pump(
        &self,
        owner: u64,
        task: u32,
        memory: &mut impl CpuMemory,
        actor: &UringActor,
    ) -> bool {
        // Observe foreign CQ work only. Its original source actor owns guest
        // memory and execution; an observer never needs to recover that task.
        if self.progress_with(memory, owner, task, &mut |r, memory, selected| {
            actor.execute(self, r, memory, selected)
        }) {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        let tail = state.tail;
        // A corrupt guest CQ head prevents publication, not source execution.
        // Enter reports EINVAL; observers retain overflow until the head is fixed.
        let count = self.flush(&mut state).unwrap_or(0);
        let event = self.completion_event(&state, count);
        let changed = tail != state.tail;
        drop(state);
        if changed {
            self.notify_completion(event);
        }
        !actor.has_file_layouts()
    }
}
impl UringSnapshot {
    pub(crate) fn poll_pump(
        &self,
        resources: &[Arc<dyn trames_vfs::DirectPoll>],
        memory: &mut impl CpuMemory,
    ) -> bool {
        let mut pump = |resource: &Arc<dyn trames_vfs::DirectPoll>| {
            resource
                .clone()
                .into_uring()
                .is_some_and(|ring| ring.poll_pump(self.owner, self.task, memory, self.actor()))
        };
        if let [resource] = resources {
            return pump(resource);
        }
        let mut seen = BTreeSet::new();
        resources
            .iter()
            .all(|resource| !seen.insert(resource.identity()) || pump(resource))
    }
    pub(crate) fn poll_wait(
        &self,
        resources: Vec<Arc<dyn trames_vfs::DirectPoll>>,
        target: Weak<dyn IoWake>,
    ) -> Option<PollWait> {
        if resources.is_empty() {
            return None;
        }
        let mut rings = BTreeMap::new();
        for resource in resources {
            let ring = resource.into_uring()?;
            rings.entry(Arc::as_ptr(&ring) as usize).or_insert(ring);
        }
        Some(PollWait {
            actor: self.actor().clone(),
            rings: rings.into_values().collect(),
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
        self.sources.external() || self.actor.pending_disk()
    }
    pub(crate) fn refresh(&mut self, signal: &Arc<IoSignal>, memory: &mut impl CpuMemory) -> bool {
        self.deadline = None;
        if !self.sources.prepare(
            &self.rings,
            self.owner,
            self.task,
            signal,
            &self.target,
            &self.actor,
            memory,
        ) {
            return false;
        }
        self.deadline = self.sources.next_deadline();
        for ring in &self.rings {
            if !ring.poll_pump(self.owner, self.task, memory, &self.actor) {
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
