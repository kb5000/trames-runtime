// SPDX-License-Identifier: GPL-3.0-or-later
//! Mapping/lifecycle scopes share original custody and the existing CPU engine.
use super::*;

/// Pure additive anonymous mmap publishes through the original live mm while
/// peer Views continue. No queue checkpoint or owner service is involved.
pub(crate) fn additive<C: Cpu>(
    task: &tasks::Handle<C>,
    pid: u32,
    args: [u64; 6],
    target: &std::sync::Weak<dyn trames_shared::IoWake>,
) -> Result<u64, tasks::AdmissionWait> {
    let _permit = tasks::admit_one(task, pid, target)?.expect("original additive task");
    let p = &mut *task.write();
    p.linux.vfs.sync_task_namespaces();
    p.linux.vfs.set_process_context(pid);
    p.linux.vfs.set_lock_owner(p.tgid);
    let result = p
        .linux
        .mmap_additive(args, &mut p.memory)
        .expect("accepted additive mapping");
    p.memory.memory_report();
    Ok(result.unwrap_or_else(super::super::error))
}

impl<C: Cpu> Lifecycle<C> {
    pub(super) fn wait_mapping_borrowers(
        &self,
        checkpoint: &Checkpoint<C>,
        target: &std::sync::Weak<dyn trames_shared::IoWake>,
    ) -> Option<tasks::AdmissionWait> {
        let mut ids = std::collections::BTreeSet::new();
        let mut wait: Option<tasks::AdmissionWait> = None;
        let mut pending = false;
        for job in &checkpoint.jobs {
            let task = job
                .work
                .task
                .as_ref()
                .expect("original mapping task")
                .read();
            if !ids.insert(task.memory.coordinator_ownership().0)
                || task.memory.parallel_views_quiescent()
            {
                continue;
            }
            let wait = wait.get_or_insert_with(|| tasks::AdmissionWait {
                signal: trames_shared::IoSignal::new(0, target.clone()),
                subscriptions: Vec::new(),
            });
            wait.subscriptions
                .push(task.memory.subscribe_parallel_idle(&wait.signal));
            pending |= !task.memory.parallel_views_quiescent();
        }
        pending.then_some(wait).flatten()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn edit_mappings(
        &self,
        epoch: &Epoch<C>,
        checkpoint: &mut Checkpoint<C>,
        registry: &mut trames_memory::parallel::Registry,
        report: &mut Report,
        slot: usize,
        engine: &mut C::Engine,
    ) -> Option<tasks::AdmissionWait> {
        // Retain the existing bounded batching rule: this CPU can execute
        // quiesced guest instructions only when there is no unrelated job to
        // claim. It reuses this worker's engine and adds no execution slot.
        let batch = !C::EXACT_INSTRUCTIONS && epoch.checkpoint_owns_all_jobs(checkpoint);
        let deadline = Instant::now() + Duration::from_micros(250);
        for job in &mut checkpoint.jobs {
            if job.checkpoint.is_none() || !crate::worker_syscalls::vm_entry(&job.work.cpu) {
                continue;
            }
            let original = job
                .work
                .task
                .as_ref()
                .expect("original mapping task")
                .clone();
            let p = &mut *original.write();
            if p.signals.io.lifecycle().termination().is_some() {
                job.checkpoint = None;
                continue;
            }
            if job.work.cpu.x(8) == 222 {
                let args = args(&job.work.cpu);
                if let Err(layout) = p.linux.admit_mmap(args, &p.memory) {
                    let signal =
                        trames_shared::IoSignal::new(job.work.pid, epoch.io_target.clone());
                    let subscription = layout.subscribe(&signal);
                    if p.linux.admit_mmap(args, &p.memory).is_err() {
                        return Some(tasks::AdmissionWait {
                            signal,
                            subscriptions: vec![subscription],
                        });
                    }
                }
            }
            job.checkpoint = None;
            job.seccomp_entry.take();
            let pid = job.work.pid;
            p.linux.vfs.sync_task_namespaces();
            p.linux.vfs.set_process_context(pid);
            p.linux.vfs.set_lock_owner(p.tgid);
            p.cpu = std::mem::take(&mut job.work.cpu);
            p.state = State::Ready;
            let control = p.signals.io.lifecycle().enter(&p.signals.io, pid);
            let mut extra = false;
            let mut used_window = false;
            loop {
                let number = p.cpu.x(8) as u32;
                let kind = match number {
                    214 => 0,
                    215 => 1,
                    216 => 2,
                    222 => 3,
                    226 => 4,
                    232 => 5,
                    233 if p.cpu.x(2) as u32 == 4 => 6,
                    233 => 7,
                    427 => 8,
                    _ => unreachable!("accepted mapping operation"),
                };
                let began = Instant::now();
                // The selected mapping ABI has no host terminal/output effects.
                // Use the same Linux implementation as the joined caller.
                p.linux.dispatch(
                    &mut p.cpu,
                    &mut p.memory,
                    &mut trames_linux::CapturedOutput::default(),
                );
                p.memory.memory_report();
                let elapsed = began.elapsed();
                if job.work.syscalls.as_ref().is_some_and(|s| s.profile) {
                    job.stats.syscall_time += elapsed;
                }
                job.stats.syscalls += 1;
                report.mapping_calls[kind] += 1;
                report.mapping_syscalls += 1;
                report.mapping_batch[2] += u64::from(extra);
                report.time[3] += elapsed;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !batch
                    || p.stopped()
                    || p.frozen(pid)
                    || p.seccomp.mode() != 0
                    || remaining.is_zero()
                    || epoch.control.stopped()
                {
                    break;
                }
                let began = Instant::now();
                let Some(outcome) = p
                    .cpu
                    .run_quiesced(engine, &mut p.memory, registry, remaining)
                else {
                    break;
                };
                let elapsed = began.elapsed();
                p.cpu_time += elapsed;
                p.signals.io.proc_view.account(elapsed, slot);
                report.batch_cpu[slot] += elapsed;
                report.time[6] += elapsed;
                report.mapping_batch[0] += u64::from(!used_window);
                report.mapping_batch[1] += 1;
                used_window = true;
                if matches!(outcome, SliceOutcome::Syscall { .. })
                    && crate::worker_syscalls::vm_entry(&p.cpu)
                    && p.cpu.x(8) != 222
                {
                    p.cpu.clear_exclusive();
                    extra = true;
                    continue;
                }
                if !matches!(outcome, SliceOutcome::Yield { .. }) {
                    job.pending_cpu = Some(outcome);
                }
                break;
            }
            p.publish_stop_hold(pid);
            job.work.cpu = std::mem::take(&mut p.cpu);
            control.finish(job.stop_hold());
            if let Some(cgroup) = p.signals.io.cgroup() {
                cgroup.acknowledge();
            }
        }
        None
    }
}
