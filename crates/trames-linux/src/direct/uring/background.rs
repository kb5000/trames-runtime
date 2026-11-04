// SPDX-License-Identifier: GPL-3.0-or-later
//! Event-driven maintenance on the source task's existing execution View.
use super::poll::PollRingOps;
use super::*;
pub struct UringBackground {
    actor: Arc<UringActor>,
    owner: u64,
    task: u32,
    target: Weak<dyn IoWake>,
    pub signal: Arc<IoSignal>,
    sources: wait::WaitSources,
    deadline: Option<Instant>,
    armed: bool,
    revision: u64,
}
impl UringBackground {
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn external(&self) -> bool {
        self.sources.external() || self.actor.pending_disk()
    }
    pub fn needs_progress(&self) -> bool {
        !self.armed
            || self.signal.ready()
            || self.revision != self.actor.revision()
            || self.deadline.is_some_and(|d| d <= Instant::now())
    }
    pub fn progress(&mut self, memory: &mut impl CpuMemory) -> bool {
        if !self.needs_progress() {
            return true;
        }
        self.signal.reset();
        self.armed = true;
        self.revision = self.actor.revision();
        let rings = self.actor.rings();
        if !self.sources.refresh(
            &rings,
            self.owner,
            self.task,
            &self.signal,
            &self.target,
            &self.actor,
        ) {
            self.actor.require_owner();
            return false;
        }
        let mut active = false;
        self.deadline = self.sources.next_deadline();
        for ring in &rings {
            if !ring.poll_pump(self.owner, self.task, memory, &self.actor) {
                self.actor.require_owner();
                return false;
            }
            active |= ring
                .state
                .lock()
                .unwrap()
                .pending
                .iter()
                .any(|r| r.owner == self.owner && r.task == self.task);
            self.deadline = [self.deadline, ring.request_deadline(self.owner, self.task)]
                .into_iter()
                .flatten()
                .min();
        }
        self.actor.reset_active(active);
        true
    }
    pub fn active(&self) -> bool {
        self.actor.active()
    }
}
impl DirectSyscalls {
    pub fn uring_background(&self, pid: u32, target: &Weak<dyn IoWake>) -> Option<UringBackground> {
        let actor = self
            .urings
            .actor
            .as_ref()
            .map_or(&self.urings.local_actor, |actor| &**actor)
            .get()?;
        if !actor.active() {
            return None;
        }
        // Owner-accepted SQEs retain the same source context as caller-accepted
        // ones before their first worker pump. No SQE metadata is imported again.
        self.urings.ensure_context(
            self.paths.as_ref(),
            self.resources.as_ref(),
            &self.files,
            self.file_executor.as_ref(),
            self.task_signal.as_ref(),
        );
        if let Some(context) = self.urings.context.get() {
            for ring in actor.rings() {
                let mut state = ring.state.lock().unwrap();
                for request in &mut state.pending {
                    if request.owner == self.urings.owner
                        && request.task == pid
                        && request.execution.is_none()
                    {
                        actor.accept(&ring, request, context.clone());
                    }
                }
            }
        }
        Some(UringBackground {
            actor: actor.clone(),
            owner: self.urings.owner,
            task: pid,
            target: target.clone(),
            signal: IoSignal::new(pid, target.clone()),
            sources: Default::default(),
            deadline: None,
            armed: false,
            revision: 0,
        })
    }
}
