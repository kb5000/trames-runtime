// SPDX-License-Identifier: GPL-3.0-or-later
//! Image replacement uses exact original group members, not a Kernel scan.
use super::*;

impl<C: Cpu> Lifecycle<C> {
    /// Image I/O retains accepted arguments and filesystem objects on the
    /// original task. The whole checkpoint waits without task/mm permits or a
    /// CPU slot, so cancellation can still return the original CPUs unchanged.
    pub(super) fn prepare_images(
        &self,
        epoch: &Epoch<C>,
        checkpoint: &Checkpoint<C>,
    ) -> Option<tasks::AdmissionWait> {
        let mut wait: Option<tasks::AdmissionWait> = None;
        let mut pending = false;
        for job in checkpoint
            .jobs
            .iter()
            .filter(|job| job.structural_call().is_some_and(|call| call.exec()))
        {
            let original = job.work.task.as_ref().expect("original exec task");
            let p = &mut *original.write();
            if p.signals.io.lifecycle().termination().is_some() {
                continue;
            }
            if p.exec_pending.is_none() && p.linux.vfs.namespace_host_work() {
                p.linux.vfs.sync_task_namespaces();
                p.linux.vfs.set_process_context(job.work.pid);
                p.linux.vfs.set_lock_owner(p.tgid);
                let request = exec::Request::capture(
                    p,
                    job.structural_call().expect("accepted exec").number(),
                    args(&job.work.cpu),
                    self.birth.memory_limits.per_process,
                    self.birth.started,
                );
                match request {
                    Ok(request) => {
                        let result = Arc::new(exec::Pending::new(self.owner.clone()));
                        p.exec_pending = Some(exec::Preparation::Disk(result.clone()));
                        self.images.submit_image(request, result);
                    }
                    // A resident lookup error neither queues work nor wakes an
                    // owner. Keep its accepted errno inline until source commit.
                    Err(error) => p.exec_pending = Some(exec::Preparation::Error(error)),
                }
            }
            let Some(result) = p.exec_pending.as_ref().filter(|result| !result.ready()) else {
                continue;
            };
            let wait = wait.get_or_insert_with(|| tasks::AdmissionWait {
                signal: trames_shared::IoSignal::new(0, epoch.io_target.clone()),
                subscriptions: Vec::new(),
            });
            wait.subscriptions.push(result.subscribe(&wait.signal));
            pending |= !result.ready();
        }
        pending.then_some(wait).flatten()
    }
    pub(super) fn admit_groups(
        &self,
        checkpoint: &Checkpoint<C>,
        custody: &mut tasks::Cohort<C>,
        target: &std::sync::Weak<dyn trames_shared::IoWake>,
    ) -> Result<Groups<C>, tasks::AdmissionWait> {
        let mut groups = Groups::new();
        for job in checkpoint
            .jobs
            .iter()
            .filter(|job| job.structural_call().is_some_and(|call| call.exec()))
        {
            let group = job
                .work
                .task
                .as_ref()
                .unwrap()
                .read()
                .signals
                .io
                .lifecycle()
                .clone();
            let key = Arc::as_ptr(&group) as usize;
            if groups.contains_key(&key) {
                continue;
            }
            let mut members = Vec::new();
            for (id, task) in self.tasks.group(&group) {
                if !checkpoint.jobs.iter().any(|job| job.work.pid == id)
                    && !custody.include(&task, target)?
                {
                    continue;
                }
                if self.tasks.contains_original(id, &task) {
                    members.push((id, task));
                }
            }
            groups.insert(key, members);
        }
        Ok(groups)
    }
    pub(super) fn replace_images(
        &self,
        epoch: &Epoch<C>,
        checkpoint: &mut Checkpoint<C>,
        groups: &Groups<C>,
        report: &mut Report,
    ) -> Result<Vec<(u32, usize)>, RuntimeError> {
        let mut replaced = Vec::new();
        while let Some(index) = checkpoint
            .jobs
            .iter()
            .position(|job| job.structural_call().is_some_and(|call| call.exec()))
        {
            let mut job = checkpoint.jobs.remove(index);
            let pid = job.work.pid;
            let task = job.work.task.as_ref().expect("original exec task").clone();
            let mut custody = task.write();
            let p = &mut *custody;
            if p.signals.io.lifecycle().termination().is_some() {
                job.checkpoint = None;
                checkpoint.jobs.push(job);
                continue;
            }
            let began = Instant::now();
            let number = job.structural_call().expect("accepted exec").number();
            let a = args(&job.work.cpu);
            let group = p.signals.io.lifecycle().clone();
            let members = &groups[&(Arc::as_ptr(&group) as usize)];
            p.cpu = std::mem::take(&mut job.work.cpu);
            p.state = State::Ready;
            p.linux.vfs.sync_task_namespaces();
            p.linux.vfs.set_process_context(pid);
            p.linux.vfs.set_lock_owner(p.tgid);
            p.signals.finish_io();
            job.checkpoint = None;
            job.seccomp_entry.take();
            let control = group.enter(&p.signals.io, pid);
            let image = Kernel::prepare_exec_request(
                p,
                number,
                a,
                self.birth.memory_limits.per_process,
                self.birth.started,
            );
            job.stats.syscalls += 1;
            let image = match image {
                Ok(Some(image)) => image,
                Ok(None) => unreachable!("image admission waits before effects"),
                Err(error) => {
                    p.cpu.set_x(0, super::super::error(error));
                    job.work.trace.record(p.cpu.x(0));
                    p.signals.begin_io();
                    job.work.cpu = std::mem::take(&mut p.cpu);
                    control.finish(job.stop_hold());
                    let elapsed = began.elapsed();
                    if job.work.syscalls.as_ref().is_some_and(|s| s.profile) {
                        job.stats.syscall_time += elapsed;
                    }
                    report.time[3] += elapsed;
                    checkpoint.jobs.push(job);
                    continue;
                }
            };
            let actual = p.tgid;
            let old_presence = members
                .iter()
                .find(|(id, _)| *id == actual && *id != pid)
                .map(|(_, task)| {
                    let leader = task.read();
                    p.started = leader.started;
                    p.signals.io.inherit_proc_pid(&leader.signals.io);
                    leader.signals.presence.clone()
                });
            // Source proc counters already account every execution slice, even
            // if an exited peer's Done is awaiting asynchronous collection.
            p.cpu_time = p.cpu_time.max(p.signals.io.proc_view.elapsed());
            let identity = |p: &Process<C>| {
                let c = &p.linux.vfs.credentials;
                [c.euid, c.egid, c.fsuid, c.fsgid]
            };
            let old_ids = identity(p);
            let old_memory = Kernel::install_exec(p, image, self.birth.started);
            job.work.trace.replaced();
            p.trace = std::mem::take(&mut job.work.trace);
            if identity(p) != old_ids {
                p.parentage.set_death_signal(0);
            }
            for (peer, original) in members.iter().filter(|(id, _)| *id != pid) {
                if let Some(index) = checkpoint.jobs.iter().position(|job| job.work.pid == *peer) {
                    let mut peer_job = checkpoint.jobs.remove(index);
                    epoch.forget_checkpoint_member(*peer);
                    report.workers.merge(std::mem::take(&mut peer_job.stats));
                    // Drop original background waits/Views before clearing tid.
                    drop(peer_job);
                }
                if let Some(mut done) = epoch.take_replaced_return(*peer, original) {
                    report.exit_groups.append(&mut done.exit_groups);
                    report.workers.merge(done.take_stats());
                }
                let t = &mut *original.write();
                p.cpu_time += t.cpu_time.max(t.signals.io.proc_view.elapsed());
                if t.signals.io.live() {
                    t.linux.vfs.sync_task_namespaces();
                    t.signals.io.exit();
                    Kernel::cancel_native_task(t);
                    t.linux.cancel_uring(&mut t.memory, *peer);
                    Kernel::parent_thread_exited(t, Some((actual, p.signals.io.clone())));
                    t.linux.vfs.cgroup_exit(*peer);
                    let address = t.linux.clear_tid_address();
                    t.linux.exit_tid(&mut t.memory);
                    if address != 0 {
                        if let Ok(key) =
                            crate::worker_syscalls::futex_key(&t.memory, t.vm_id, address, false)
                        {
                            self.futexes.wake(key, 1, u32::MAX);
                        }
                    }
                    t.linux.vfs.release_descriptors();
                    t.linux.vfs.retire_context();
                    t.space.retire();
                    Kernel::release_vfork(t);
                }
                t.state = State::Zombie(0);
                Kernel::clear_exit_resources(t);
                self.memory.retire(std::mem::take(&mut t.memory))?;
                self.tasks.retire(*peer, original);
            }
            self.timers.clear_process(actual, true);
            Kernel::release_vfork(p);
            if pid != actual {
                p.linux.vfs.cgroup_exec_rekey(pid, actual);
            }
            p.vm_id = self.birth.resource_id();
            p.linux.vfs.set_process_context(actual);
            self.birth.publish_task_core(actual, p);
            self.birth.publish_family(actual, p);
            self.birth.bind_task_cgroup(actual, p);
            p.publish_stop_hold(actual);
            control.finish(Some(p.stop_held()));
            self.tasks.restore(pid, actual, &custody);
            drop(old_presence);
            self.memory.retire(old_memory)?;
            epoch.forget_checkpoint_member(pid);
            let elapsed = began.elapsed();
            if job.work.syscalls.as_ref().is_some_and(|s| s.profile) {
                job.stats.syscall_time += elapsed;
            }
            report.time[3] += elapsed;
            let slot = job.stats.worker;
            report.workers.merge(std::mem::take(&mut job.stats));
            replaced.push((actual, slot));
            drop(job);
        }
        Ok(replaced)
    }
}
