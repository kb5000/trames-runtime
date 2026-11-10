// SPDX-License-Identifier: GPL-3.0-or-later
//! Event-driven maintenance on the source task's existing execution View.
use super::poll::PollRingOps;
use super::*;
use trames_memory::Memory;
pub struct UringBackground {
    actor: Arc<UringActor>,
    scope: Arc<actor::Scope>,
    owner: u64,
    task: u32,
    pub signal: Arc<IoSignal>,
    sources: wait::WaitSources,
    deadline: Option<Instant>,
    armed: bool,
    revision: u64,
    original: bool,
}
impl UringBackground {
    /// Direct native sources when the caller supplies its own wait loop.
    pub fn native_wait_interests(&self) -> std::io::Result<Vec<(trames_vfs::HostFd, bool)>> {
        self.sources.direct_wait_interests()
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn external(&self) -> bool {
        self.sources.external() || self.actor.pending_disk(self.owner, self.task)
    }
    pub fn needs_progress(&self) -> bool {
        !self.armed
            || self.signal.ready()
            || self.revision != self.scope.revision()
            || self.deadline.is_some_and(|d| d <= Instant::now())
    }
    pub fn progress(&mut self, memory: &mut impl CpuMemory) -> std::io::Result<bool> {
        if !self.needs_progress() {
            return Ok(true);
        }
        if self.original {
            return Ok(!self.active());
        }
        self.signal.reset();
        self.armed = true;
        self.revision = self.scope.revision();
        let rings = self.actor.rings();
        // Retain a deadline that becomes due during the original body pump.
        let before = rings
            .iter()
            .filter_map(|ring| ring.request_deadline(self.owner, self.task))
            .min();
        let prepared = self.sources.prepare(
            &rings,
            self.owner,
            self.task,
            &self.signal,
            &self.actor,
            memory,
        );
        match prepared {
            Ok(true) => {}
            Ok(false) => {
                return Ok(false);
            }
            Err(error) => {
                self.armed = false;
                return Err(error);
            }
        }
        let mut active = false;
        self.deadline = [before, self.sources.next_deadline()]
            .into_iter()
            .flatten()
            .min();
        for ring in &rings {
            if !ring.poll_pump(self.owner, self.task, memory, &self.actor) {
                return Ok(false);
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
        if !active {
            self.actor.finish_scope(&self.scope, self.revision);
            self.sources = Default::default();
            self.deadline = None;
        }
        Ok(true)
    }
    /// A cold original body still runs on its submitting task's executor.
    /// Subscribe before the deciding full-resource pass, retaining request/CQ
    /// state and native errors. No caller/coordinator authority is involved.
    pub fn progress_original(
        &mut self,
        linux: &mut Linux,
        memory: &mut Memory,
    ) -> std::io::Result<()> {
        self.original = true;
        self.signal.reset();
        self.armed = true;
        let rings = self.actor.rings();
        let before = rings
            .iter()
            .filter_map(|ring| ring.request_deadline(self.owner, self.task))
            .min();
        linux.progress_uring(memory, self.task);
        self.revision = self.scope.revision();
        self.sources.bind_original(linux.vfs.direct_descriptors());
        if !self.sources.prepare(
            &rings,
            self.owner,
            self.task,
            &self.signal,
            &self.actor,
            memory,
        )? {
            return Err(std::io::Error::other(
                "original io_uring wait graph is incomplete",
            ));
        }
        linux.progress_uring(memory, self.task);
        self.deadline = [before, self.sources.next_deadline()]
            .into_iter()
            .flatten()
            .min();
        let mut active = false;
        for ring in &rings {
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
        if !active {
            self.actor.finish_scope(&self.scope, self.revision);
            self.sources = Default::default();
            self.deadline = None;
        }
        Ok(())
    }
    pub fn active(&self) -> bool {
        self.scope.active()
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
        let scope = actor.scope(self.urings.owner, pid)?;
        if !scope.active() {
            return None;
        }
        // Owner-accepted SQEs retain the same source context as caller-accepted
        // ones before their first worker pump. No SQE metadata is imported again.
        self.urings.ensure_context(
            self.paths.as_ref(),
            self.resources.as_ref(),
            &self.files,
            self.file_executor.as_ref(),
            self.file_layouts.as_ref(),
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
            scope,
            owner: self.urings.owner,
            task: pid,
            signal: IoSignal::new(pid, target.clone()),
            sources: Default::default(),
            deadline: None,
            armed: false,
            revision: 0,
            original: false,
        })
    }
}
