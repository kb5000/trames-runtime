// SPDX-License-Identifier: GPL-3.0-or-later
//! Terminal session publication on an existing executor, after CPU quiescence.
//! The waiting host cannot receive an unfinished guest call from this protocol.
use super::*;
impl<C: Cpu> Lifecycle<C> {
    pub(crate) fn finish_closed(
        &self,
        epoch: &Epoch<C>,
        cancel_io: bool,
    ) -> Result<(), RuntimeError> {
        let completed = epoch.drain_closed();
        let mut panic = false;
        for done in completed {
            panic |= done.outcome.is_none();
            if done.thread_exit.is_some() {
                self.retain_final_exit(done);
                continue;
            }
            let task = done
                .task
                .as_ref()
                .expect("source session original task")
                .clone();
            let mut custody = task.write();
            let published = super::super::returns::publish(&mut custody, done, 0);
            custody.pending_cpu = published
                .outcome
                .filter(|outcome| !matches!(outcome, SliceOutcome::Yield { .. }));
            drop(custody);
            for group in published.groups {
                self.exit_groups.watch(&group);
            }
            self.report.lock().unwrap().workers.merge(published.stats);
        }
        for group in std::mem::take(&mut self.report.lock().unwrap().exit_groups) {
            self.exit_groups.watch(&group);
        }
        self.retain_final_survivors();
        self.finish_retirements(epoch)?;
        let mut committed = std::collections::BTreeSet::new();
        for (id, task) in self.tasks.all() {
            let mut custody = task.write();
            let p = &mut *custody;
            if cancel_io {
                if let Some(actor) = p.linux.uring_actor_root().get() {
                    actor.cancel_task(p.memory.instruction_identity().0, id);
                }
            }
            if p.tgid != 1 {
                p.linux.vfs.set_lock_owner(p.tgid);
                p.linux.vfs.release_process_locks();
            }
            if p.signals.io.live() {
                // Runtime retains root CPU/Memory/VFS on an error, but native
                // invocation authority ends here, rather than in host-side Drop.
                p.space.retire();
                if committed.insert(p.memory.coordinator_ownership().0) {
                    p.memory.commit_parallel()?;
                }
            }
        }
        if epoch.control.end() == Some(crate::execution_control::End::Exited) {
            if let Some(root) = self.tasks.handle(&1) {
                root.read().linux.vfs.finish_network();
            }
        }
        if panic {
            return Err(RuntimeError::Arguments("CPU worker panicked"));
        }
        Ok(())
    }
}
