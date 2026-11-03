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
        {
            let state = self.state.lock().unwrap();
            // A CQ observer does not acquire another task's execution context.
            // A foreign request is observed only if its submitting task kept an
            // enter actor. Otherwise the lifecycle checkpoint must recover it.
            if state.pending.iter().any(|r| {
                (r.owner != owner || r.task != task)
                    && r.source.as_ref().and_then(Weak::upgrade).is_none()
                    && !state.waits.contains_key(&r.task)
            }) {
                return false;
            }
        }
        if self.progress_with(memory, owner, task, &mut |r, memory, selected| {
            actor.execute(self, r, memory, selected)
        }) {
            return false;
        }
        let mut state = self.state.lock().unwrap();
        let tail = state.tail;
        let count = match self.flush(&mut state) {
            Ok(count) => count,
            Err(_) => return false,
        };
        let event = self.completion_event(&state, count);
        let changed = tail != state.tail;
        drop(state);
        if changed {
            self.notify_completion(event);
        }
        true
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
        if !self.sources.refresh(
            &self.rings,
            self.owner,
            self.task,
            signal,
            &self.target,
            &self.actor,
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
