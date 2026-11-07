// SPDX-License-Identifier: GPL-3.0-or-later
//! Structural task work on an existing executor, with original task/mm custody.
//! This authority has no Kernel, process-table projection or resource thread.
use super::*;
use crate::run_queue::{Checkpoint, Epoch, Job};
use std::sync::Mutex;
#[path = "process_lifecycle_exec.rs"]
mod image;
#[path = "process_lifecycle_layouts.rs"]
pub(super) mod layouts;
#[path = "process_lifecycle_memory.rs"]
mod maintenance;
#[path = "process_lifecycle_mapping.rs"]
pub(crate) mod mapping;
#[path = "process_lifecycle_retirement.rs"]
mod retirement;
type Groups<C> = BTreeMap<usize, Vec<(u32, tasks::Handle<C>)>>;

pub(crate) struct Lifecycle<C: Cpu> {
    birth: birth::Birth,
    dispatch: dispatch::Dispatch,
    tasks: tasks::Directory<C>,
    registry: trames_memory::parallel::Registry,
    report: Mutex<Report>,
    memory: Arc<crate::retired_memory::RetiredMemory>,
    memory_wake: std::sync::OnceLock<crate::retired_memory::Driver>,
    layouts: Arc<trames_linux::FileLayouts>,
    layout_driver: std::sync::OnceLock<trames_linux::FileLayoutDriver>,
    proc_source: Option<Arc<crate::proc_views::Source>>,
    proc_driver: std::sync::OnceLock<crate::proc_views::ReadDriver>,
    exit_groups: Arc<crate::exit_groups::ExitGroups>,
    exit_wake: std::sync::OnceLock<MemoryWake>,
    retiring: Mutex<Vec<retirement::Retiring<C>>>,
    timers: Arc<trames_kernel::timers::Timers>,
    futexes: crate::futex::Futexes,
    images: Arc<dyn exec::Executor<C>>,
    owner: std::thread::Thread,
}
struct MemoryWake {
    signal: Arc<trames_shared::IoSignal>,
    _subscription: trames_shared::IoSubscription,
}
#[derive(Default)]
struct Report {
    groups: u64,
    spaces: u64,
    time: [Duration; 7],
    waits: [u64; 8],
    memory: trames_memory::parallel::Metrics,
    error: Option<RuntimeError>,
    backend_error: Option<String>,
    workers: crate::run_queue::Stats,
    exit_groups: Vec<Arc<trames_kernel::task_control::Group>>,
    mapping_calls: [u64; 9],
    mapping_batch: [u64; 3],
    mapping_syscalls: u64,
    batch_cpu: [Duration; 32],
}
/// Selection inspects already-accepted job metadata, never task-body locks.
/// Mixed mapping/lifecycle requests use the same original affected resources.
pub(crate) fn eligible<'a, C: Cpu>(
    jobs: impl Iterator<Item = &'a Job<C>>,
    proc_reads: bool,
    mm_only: bool,
    continuation: bool,
    layout_only: bool,
) -> bool {
    if layout_only {
        return jobs.into_iter().all(|job| job.work.task.is_some());
    }
    let mut requested = proc_reads || mm_only || continuation;
    for job in jobs {
        if job.work.task.is_none() {
            return false;
        }
        if job.checkpoint.is_some() {
            requested = true;
            if !crate::worker_syscalls::custody_entry(&job.work.cpu)
                || job.work.syscalls.as_ref().is_none_or(|s| s.owner_syscalls)
                || job
                    .seccomp_entry
                    .as_ref()
                    .is_some_and(|entry| !entry.allowed())
            {
                return false;
            }
        }
    }
    requested
}
impl<C: Cpu> Lifecycle<C> {
    pub(super) fn capture(kernel: &Kernel<C>) -> Self {
        Self {
            birth: birth::Birth::capture(kernel),
            dispatch: dispatch::Dispatch::capture(kernel),
            tasks: kernel.processes.directory(),
            registry: kernel.parallel_memory.share(),
            report: Mutex::default(),
            memory: kernel.memory_retirements(),
            memory_wake: Default::default(),
            layouts: kernel.file_layout_work(),
            layout_driver: Default::default(),
            proc_source: kernel.proc_source.clone(),
            proc_driver: Default::default(),
            exit_groups: kernel.processes.directory().exits(),
            exit_wake: Default::default(),
            retiring: Default::default(),
            timers: kernel.timers.clone(),
            futexes: kernel.futexes.clone(),
            images: kernel.workers.image_executor(),
            owner: std::thread::current(),
        }
    }
    pub(crate) fn bind_memory(&self, target: std::sync::Weak<dyn trames_shared::IoWake>) {
        let signal = trames_shared::IoSignal::new(0, target.clone());
        assert!(self
            .layout_driver
            .set(self.layouts.bind_reader(signal))
            .is_ok());
        let signal = trames_shared::IoSignal::new(0, target.clone());
        let subscription = self.exit_groups.subscribe(&signal);
        assert!(self
            .exit_wake
            .set(MemoryWake {
                signal,
                _subscription: subscription
            })
            .is_ok());
        if let Some(source) = &self.proc_source {
            let signal = trames_shared::IoSignal::new(0, target.clone());
            assert!(self.proc_driver.set(source.bind_reader(signal)).is_ok());
        }
        let signal = trames_shared::IoSignal::new(0, target);
        assert!(self
            .memory_wake
            .set(self.memory.bind_reader(signal))
            .is_ok());
    }
    pub(crate) fn memory_ready(&self) -> bool {
        self.memory_wake
            .get()
            .is_some_and(|wake| wake.signal.ready())
    }
    pub(crate) fn memory_signal(&self, signal: &Arc<trames_shared::IoSignal>) -> bool {
        self.memory_wake
            .get()
            .is_some_and(|wake| Arc::ptr_eq(signal, &wake.signal))
            || self
                .layout_driver
                .get()
                .is_some_and(|driver| Arc::ptr_eq(signal, &driver.signal))
            || self
                .proc_driver
                .get()
                .is_some_and(|driver| Arc::ptr_eq(signal, &driver.signal))
            || self
                .exit_wake
                .get()
                .is_some_and(|wake| Arc::ptr_eq(signal, &wake.signal))
    }
    pub(crate) fn reclaim(&self, epoch: &Epoch<C>) {
        self.memory_wake
            .get()
            .expect("bound retirement resource")
            .signal
            .reset();
        if let Err(error) = self.memory.pump() {
            self.report.lock().unwrap().error = Some(error.into());
            epoch.stop();
        }
    }
    pub(crate) fn collect(&self, kernel: &mut Kernel<C>) -> Option<RuntimeError> {
        self.collect_retirements(kernel);
        let report = std::mem::take(&mut *self.report.lock().unwrap());
        kernel.account_worker_stats(report.workers);
        for group in report.exit_groups {
            kernel.queue_exit_group(group);
        }
        kernel.vm_checkpoint_groups += report.groups;
        kernel.vm_checkpoint_spaces += report.spaces;
        for (target, value) in kernel.vm_checkpoint_time.iter_mut().zip(report.time) {
            *target += value;
        }
        for (target, value) in kernel.vm_checkpoint_wait_bins.iter_mut().zip(report.waits) {
            *target += value;
        }
        kernel.parallel_memory_time += report.time[2] + report.time[4];
        kernel.vm_local_syscalls += report.mapping_syscalls;
        kernel.context_switches += report.mapping_batch[1];
        for (target, value) in kernel
            .vm_checkpoint_calls
            .iter_mut()
            .zip(report.mapping_calls)
        {
            *target += value;
        }
        for (target, value) in kernel
            .vm_checkpoint_batch
            .iter_mut()
            .zip(report.mapping_batch)
        {
            *target += value;
        }
        for (target, value) in kernel.per_cpu.iter_mut().zip(report.batch_cpu) {
            *target += value;
            kernel.cpu_total += value;
        }
        kernel.parallel_memory.metrics.merge(report.memory);
        if report.backend_error.is_some() {
            kernel.backend_error = report.backend_error;
        }
        report.error
    }
    pub(crate) fn run(
        &self,
        epoch: &Epoch<C>,
        mut checkpoint: Checkpoint<C>,
        slot: usize,
        engine: &mut C::Engine,
    ) {
        let mut custody = match tasks::admit(&checkpoint.jobs, &epoch.io_target) {
            Ok(custody) => custody,
            Err(wait) => {
                epoch.defer_checkpoint(checkpoint, wait.signal, wait.subscriptions);
                return;
            }
        };
        if checkpoint.layout_only {
            self.release_layout_bytes(epoch, checkpoint);
            return;
        }
        let groups = match self.admit_groups(&checkpoint, &mut custody, &epoch.io_target) {
            Ok(groups) => groups,
            Err(wait) => {
                epoch.defer_checkpoint(checkpoint, wait.signal, wait.subscriptions);
                return;
            }
        };
        let lifecycle_only = checkpoint.jobs.iter().any(|job| job.checkpoint.is_some())
            && checkpoint
                .jobs
                .iter()
                .filter(|j| j.checkpoint.is_some())
                .all(|j| matches!(j.work.cpu.x(8) as u32, 220 | 221 | 281));
        for job in &mut checkpoint.jobs {
            drop(job.work.memory.take());
            job.work.cpu.clear_exclusive();
        }
        if let Some(wait) = self.retire_checkpoint(epoch, &checkpoint.ids) {
            epoch.defer_checkpoint(checkpoint, wait.signal, wait.subscriptions);
            return;
        }
        let metadata = checkpoint.proc_reads
            || checkpoint.layouts
            || !checkpoint.mm_only
            || checkpoint.jobs.iter().any(|job| job.checkpoint.is_some());
        if metadata && !lifecycle_only {
            if let Some(wait) = self.wait_mapping_borrowers(&checkpoint, &epoch.io_target) {
                epoch.defer_checkpoint(checkpoint, wait.signal, wait.subscriptions);
                return;
            }
        }
        let mut report = Report::default();
        let mut registry = self.registry.share();
        let wait = checkpoint
            .quiescent
            .saturating_duration_since(checkpoint.requested);
        report.time[0] = wait;
        report.time[1] = checkpoint
            .taken
            .saturating_duration_since(checkpoint.quiescent);
        let bucket = [5, 20, 100, 500, 1000, 2000, 5000]
            .iter()
            .position(|&limit| wait.as_micros() < limit)
            .unwrap_or(7);
        report.waits[bucket] = 1;
        // Keep the original checkpoint available for drain even if a host
        // implementation panics; the CPU pool must still acknowledge stop.
        let mut pending_image = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.execute(
                epoch,
                &mut checkpoint,
                &mut registry,
                &mut report,
                &groups,
                slot,
                engine,
                lifecycle_only,
                &mut pending_image,
            )
        }))
        .unwrap_or(Err(RuntimeError::Arguments("lifecycle worker panicked")));
        let began = Instant::now();
        if let Some(wait) = pending_image {
            epoch.defer_checkpoint(checkpoint, wait.signal, wait.subscriptions);
        } else {
            epoch.restore_checkpoint(checkpoint, matches!(result, Ok(true)));
        }
        report.time[5] += began.elapsed();
        report.memory = registry.metrics;
        if !matches!(result, Ok(true)) {
            report.error = result.err();
            epoch.stop();
        }
        // Accounting is collected independently, after work has completed.
        // No task operation or queue notification runs under this mutex.
        let mut total = self.report.lock().unwrap();
        total.workers.merge(report.workers);
        total.exit_groups.extend(report.exit_groups);
        total.groups += report.groups;
        total.spaces += report.spaces;
        total.mapping_syscalls += report.mapping_syscalls;
        for (target, value) in total.mapping_calls.iter_mut().zip(report.mapping_calls) {
            *target += value;
        }
        for (target, value) in total.mapping_batch.iter_mut().zip(report.mapping_batch) {
            *target += value;
        }
        for (target, value) in total.batch_cpu.iter_mut().zip(report.batch_cpu) {
            *target += value;
        }
        for (target, value) in total.time.iter_mut().zip(report.time) {
            *target += value;
        }
        for (target, value) in total.waits.iter_mut().zip(report.waits) {
            *target += value;
        }
        total.memory.merge(report.memory);
        if report.error.is_some() {
            total.error = report.error;
        }
        if report.backend_error.is_some() {
            total.backend_error = report.backend_error;
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        epoch: &Epoch<C>,
        checkpoint: &mut Checkpoint<C>,
        registry: &mut trames_memory::parallel::Registry,
        report: &mut Report,
        groups: &Groups<C>,
        slot: usize,
        engine: &mut C::Engine,
        lifecycle_only: bool,
        pending_image: &mut Option<tasks::AdmissionWait>,
    ) -> Result<bool, RuntimeError> {
        // Birth and exec credential publication share policy group admission.
        // Resource contention parks before any structural effects. Image I/O
        // drops these permits while pending and reacquires them before commit.
        let mut policy_permits = Vec::new();
        for job in checkpoint
            .jobs
            .iter()
            .filter(|job| job.checkpoint.is_some() && matches!(job.work.cpu.x(8), 220 | 221 | 281))
        {
            let task = job
                .work
                .task
                .as_ref()
                .expect("original lifecycle policy")
                .read();
            match task.seccomp.admit_birth(&epoch.io_target, job.work.pid) {
                Ok(permit) => policy_permits.push(permit),
                Err(wait) => {
                    *pending_image = Some(wait);
                    checkpoint.source_retry = true;
                    return Ok(true);
                }
            }
        }
        let began = Instant::now();
        let mut committed = std::collections::BTreeSet::new();
        let metadata = checkpoint.proc_reads
            || checkpoint.layouts
            || !checkpoint.mm_only
            || checkpoint.jobs.iter().any(|job| job.checkpoint.is_some());
        for job in checkpoint.jobs.iter().filter(|_| metadata) {
            let task = job.work.task.as_ref().expect("original lifecycle task");
            let p = &mut *task.write();
            if committed.insert(p.memory.coordinator_ownership().0) {
                if p.memory.parallel_views_quiescent() {
                    p.memory.commit_parallel()?;
                    if checkpoint.proc_reads {
                        assert!(p.memory.activate_proc_reads());
                    }
                } else {
                    p.memory.commit_retired_parallel()?;
                    if checkpoint.proc_reads {
                        self.birth.request_read(&p.memory);
                    }
                }
            }
        }
        report.time[2] += began.elapsed();
        *pending_image = self.prepare_images(epoch, checkpoint);
        if pending_image.is_some() {
            report.time[0] = Duration::ZERO;
            report.time[1] = Duration::ZERO;
            report.waits = [0; 8];
            return Ok(true);
        }
        *pending_image = self.admit_layouts(checkpoint, &epoch.io_target)?;
        if pending_image.is_some() {
            checkpoint.source_retry = true;
            return Ok(true);
        }
        report.groups = 1;
        report.spaces = if checkpoint.mm_only {
            checkpoint.ids.len()
        } else {
            committed.len()
        } as u64;
        let replaced = self.replace_images(epoch, checkpoint, groups, report)?;
        self.capture_created(epoch, checkpoint, replaced);
        *pending_image = self.edit_mappings(epoch, checkpoint, registry, report, slot, engine);
        if let Some(wait) = pending_image {
            self.commit_layout_roots(checkpoint, &wait.signal, &mut wait.subscriptions)?;
            checkpoint.source_retry = true;
            return Ok(true);
        }
        let mut created = Vec::new();
        // New bodies are admitted before publication, so a concurrent observer
        // cannot make this executor block while preparing a child's first View.
        let mut child_custody = Vec::new();
        for job in &mut checkpoint.jobs {
            let Some(_outcome) = job.checkpoint.take() else {
                continue;
            };
            let task = job
                .work
                .task
                .as_ref()
                .expect("original lifecycle task")
                .clone();
            let p = &mut *task.write();
            if p.signals.io.lifecycle().termination().is_some() {
                continue;
            }
            assert_eq!(job.work.cpu.x(8), 220);
            let began = Instant::now();
            p.linux.vfs.sync_task_namespaces();
            p.linux.vfs.set_process_context(job.work.pid);
            p.linux.vfs.set_lock_owner(p.tgid);
            p.cpu = std::mem::take(&mut job.work.cpu);
            p.state = State::Ready;
            let control = p.signals.io.lifecycle().enter(&p.signals.io, job.work.pid);
            // The accepted BPF result already allowed this exact entry. Never
            // reevaluate it or replay a policy action during the custody handoff.
            job.seccomp_entry.take();
            p.signals.finish_io();
            match self.birth.clone_task(job.work.pid, p, args(&p.cpu)) {
                Ok(child) => {
                    let id = child.id;
                    let value = child.value;
                    let child: tasks::Handle<C> = child.process.into();
                    let permit = child.try_admit().expect("unpublished child");
                    self.tasks.publish(id, child);
                    child_custody.push(permit);
                    created.push((id, job.stats.worker));
                    if let Some(value) = value {
                        p.cpu.set_x(0, value);
                    }
                }
                Err(error) => p.cpu.set_x(0, super::error(error)),
            }
            if let State::Completion(release) = &p.state {
                let wait = crate::run_queue::CompletionWait::new(release.clone());
                let snapshot = job.work.syscalls.as_ref().expect("source clone snapshot");
                wait.bind(
                    &snapshot.io_signals,
                    snapshot.io_wake.as_ref().expect("bound parent"),
                );
                job.waiting = Some(crate::run_queue::WaitState::Completion(wait));
            }
            p.signals.begin_io();
            p.signals
                .io
                .proc_view
                .waiting(!matches!(p.state, State::Ready));
            p.memory.memory_report();
            job.work.cpu = std::mem::take(&mut p.cpu);
            control.finish(job.stop_hold());
            if let Some(cgroup) = p.signals.io.cgroup() {
                cgroup.acknowledge();
            }
            job.stats.syscalls += 1;
            let elapsed = began.elapsed();
            if job.work.syscalls.as_ref().is_some_and(|s| s.profile) {
                job.stats.syscall_time += elapsed;
            }
            report.time[3] += elapsed;
        }
        drop(policy_permits);
        let began = Instant::now();
        // Capture new CPUs before preparing any View. The owned checkpoint now
        // survives a backing-layout wait or cancellation with every child/image
        // already represented; no completed structural syscall can be replayed.
        self.capture_created(epoch, checkpoint, created);
        let members: Vec<_> = checkpoint
            .jobs
            .iter()
            .map(|j| (j.work.pid, j.stats.worker))
            .collect();
        let Some(mut views) = dispatch::prepare_views(
            &self.tasks,
            registry,
            &members,
            lifecycle_only || !metadata,
            &mut report.backend_error,
        ) else {
            *pending_image = self.wait_layout_publication(checkpoint, &epoch.io_target)?;
            if pending_image.is_some() {
                checkpoint.source_retry = true;
                return Ok(true);
            }
            return Ok(false);
        };
        self.admit_private_views(&mut views, registry);
        for (pid, _, view) in views {
            checkpoint
                .jobs
                .iter_mut()
                .find(|j| j.work.pid == pid)
                .expect("captured original CPU")
                .work
                .memory = Some(view);
        }
        report.time[4] += began.elapsed();
        Ok(true)
    }
    fn capture_created(
        &self,
        epoch: &Epoch<C>,
        checkpoint: &mut Checkpoint<C>,
        created: Vec<(u32, usize)>,
    ) {
        let mut files = trames_vfs::FileEpoch::default();
        let mut urings = trames_linux::UringEpoch::default();
        let mut network = trames_vfs::NetworkEpoch::default();
        let count = created.len();
        for (pid, slot) in created {
            let task = self.tasks.handle(&pid).expect("published child/image");
            let identity = task.read().memory.instruction_identity().0;
            let mut job = self.dispatch.job(
                (pid, task),
                None,
                &epoch.control,
                &mut files,
                &mut urings,
                &mut network,
            );
            job.stats.worker = slot;
            epoch.admit_waiting_checkpoint(checkpoint, job, identity);
        }
        // Child-first COW publication preserves the parent's existing physical
        // allocation. Keep that order in the retained scope on every retry.
        checkpoint.jobs.rotate_right(count);
    }
    fn admit_private_views(
        &self,
        views: &mut [(u32, usize, Box<trames_memory::parallel::View>)],
        registry: &mut trames_memory::parallel::Registry,
    ) {
        let mut groups = BTreeMap::<u64, (usize, Vec<&mut trames_memory::parallel::View>)>::new();
        for (id, _, view) in views {
            let task = self.tasks.handle(id).expect("admitted task");
            let (identity, owners) = task.read().memory.coordinator_ownership();
            let group = groups.entry(identity).or_default();
            group.0 = owners;
            group.1.push(view.as_mut());
        }
        for (_, (owners, mut views)) in groups {
            if owners != views.len() {
                continue;
            }
            // SAFETY: every actual root owner is in this admitted cohort. All
            // its CPU/service actors are paused and original task/mm permits
            // exclude metadata access. The View API rejects external borrows,
            // mismatched snapshots and unsafe mutable/shared frame admission.
            if unsafe { trames_memory::parallel::View::try_private_epoch(&mut views) } {
                if views.len() == 1 {
                    registry.metrics.exclusive_private_views += 1;
                } else {
                    registry.metrics.readonly_private_views += views.len() as u64;
                }
            }
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use crate::workers::{Control, Event};
    use trames_cpu::Cpu;
    use trames_memory::Permissions;

    #[test]
    fn disk_image_wait_retains_accepted_files_and_frees_the_only_slot() {
        struct Held(std::sync::mpsc::Sender<(exec::Request, Arc<exec::Pending<Cpu>>)>);
        impl exec::Executor<Cpu> for Held {
            fn submit_image(&self, request: exec::Request, result: Arc<exec::Pending<Cpu>>) {
                self.0.send((request, result)).unwrap();
            }
        }
        for mode in 0..3 {
            let cancel = mode != 0;
            let path = std::env::temp_dir().join(format!(
                "trames-image-wait-{}-{}-{cancel}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut k = super::super::tests::kernel();
            let mut root = super::super::tests::admitted_process(&k);
            root.linux.vfs = trames_vfs::Vfs::open_disk(&path, Default::default()).unwrap();
            root.linux
                .vfs
                .import_executable(b"/image", b"invalid ELF".to_vec())
                .unwrap();
            let fd = root
                .linux
                .vfs
                .open_at(AT_FDCWD, b"/image", trames_vfs::O_CLOEXEC, 0)
                .unwrap();
            root.memory.write(0x1000, b"\0accepted\0").unwrap();
            root.memory
                .write_array(0x1100, 0x1001u64.to_le_bytes())
                .unwrap();
            root.memory.write_array(0x1108, 0u64.to_le_bytes()).unwrap();
            k.processes.insert(1, root);
            k.processes
                .insert(4, super::super::tests::admitted_process(&k));
            k.publish_io_tasks(None);
            let original = k.processes.handle(&1).unwrap();
            let epoch = Epoch::with_events(
                Arc::new(Control::new(u64::MAX / 2)),
                k.workers.events(),
                true,
            );
            let (send, receive) = std::sync::mpsc::channel();
            let mut lifecycle = Lifecycle::capture(&k);
            lifecycle.images = Arc::new(Held(send));
            epoch.bind_lifecycle(lifecycle);
            for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (4, 0)]).unwrap() {
                epoch.add(k.capture_worker(
                    id,
                    view,
                    &epoch.control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
            }
            let mut caller = epoch.take(0).unwrap();
            caller.work.cpu.set_x(8, 281);
            let args = [fd as u64, 0x1000, 0x1100, 0, 0x1000, 0];
            put_args(&mut caller.work.cpu, args);
            epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 0 });
            let foreign = epoch.take(0).unwrap();
            assert_eq!(foreign.work.pid, 4, "disk wait releases the same executor");
            epoch.park(foreign, Some(crate::run_queue::WaitState::OwnerEvent));
            let (request, result) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
            // No task/mm custody is retained during disk I/O. A shared-FD close
            // and guest argument overwrite cannot replace the accepted request.
            {
                let p = &mut *original.write();
                p.linux.vfs.close(fd).unwrap();
                p.memory.write(0x1000, b"/gone\0changed\0").unwrap();
                assert!(p.exec_pending.as_ref().is_some_and(|r| !r.ready()));
            }
            assert!(epoch.take_checkpoint().is_none());
            if cancel {
                epoch.stop();
                let done = epoch.drain();
                assert_eq!(done.len(), 2);
                let caller = done.into_iter().find(|d| d.pid == 1).unwrap();
                assert_eq!(super::super::args(&caller.cpu), args);
                k.adopt_worker_return(caller, false);
                let mut task = k.processes.checkout(&1).unwrap();
                k.call(
                    1,
                    &mut task,
                    281,
                    args,
                    &mut trames_linux::CapturedOutput::default(),
                );
                assert!(
                    matches!(task.state, State::Blocked(281, accepted) if accepted == args),
                    "an unfinished exec image must never resume guest instructions"
                );
                assert_eq!(super::super::args(&task.cpu), args);
                k.processes.insert(1, task);
            }
            if mode == 2 {
                let mut task = k.processes.checkout(&1).unwrap();
                k.exit(1, &mut task, 9);
                k.processes.insert(1, task);
                assert!(original.read().exec_pending.is_none());
            }
            result.complete(request.load());
            if mode == 2 {
                assert!(matches!(original.read().state, State::Zombie(9)));
                assert!(
                    original.read().exec_pending.is_none(),
                    "late image completion cannot resurrect a killed task"
                );
            } else if cancel {
                let mut task = k.processes.checkout(&1).unwrap();
                k.call(
                    1,
                    &mut task,
                    281,
                    args,
                    &mut trames_linux::CapturedOutput::default(),
                );
                assert_eq!(task.cpu.x(0), super::super::error(Errno(8)));
                assert!(matches!(task.state, State::Ready));
                assert!(task.exec_pending.is_none());
                k.processes.insert(1, task);
            } else {
                let caller = epoch.take(0).unwrap();
                assert_eq!(caller.work.pid, 1);
                assert_eq!(caller.work.cpu.x(0), super::super::error(Errno(8)));
                assert_eq!(caller.stats.syscalls, 1);
                epoch.park(caller, None);
                epoch.stop();
                assert_eq!(epoch.drain().len(), 2);
            }
            assert!(receive.try_recv().is_err(), "accepted I/O executes once");
            assert!(epoch.collect_lifecycle(&mut k).is_none());
            assert_eq!(k.vm_checkpoint_groups, u64::from(!cancel));
            while let Some(event) = k.workers.event_timeout(Duration::ZERO).unwrap() {
                assert!(!matches!(event, Event::VmReady));
            }
            drop(result);
            drop(original);
            drop(epoch);
            drop(k);
            std::fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn clone_and_vfork_complete_on_existing_cpu_slots_without_owner_events() {
        for cpus in [1, 4] {
            for (flags, children) in [(17, 1), (17 | 0x4100, 1), (0, 0)] {
                let mut kernel = super::super::tests::kernel();
                kernel.cpu_count = cpus;
                kernel.per_cpu = vec![Duration::ZERO; cpus];
                kernel.workers = crate::workers::Pool::new(cpus);
                let mut root = super::super::tests::admitted_process(&kernel);
                for (i, word) in [0xd4000001u32, 0xd2800ba8, 0xd4000001]
                    .into_iter()
                    .enumerate()
                {
                    root.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                root.memory
                    .protect(0x4000, trames_memory::PAGE_SIZE, Permissions::RX)
                    .unwrap();
                if cpus == 4 {
                    root.linux.vfs.credentials.caps.no_new_privs.set();
                    root.memory
                        .write(0x1000, &[6, 0, 0, 0, 0, 0, 0xff, 0x7f])
                        .unwrap();
                    root.memory.write_array(0x1100, 1u16.to_le_bytes()).unwrap();
                    root.memory
                        .write_array(0x1108, 0x1000u64.to_le_bytes())
                        .unwrap();
                    assert_eq!(kernel.seccomp(&mut root, [1, 0, 0x1100, 0, 0, 0]), Ok(0));
                }
                let policy = root.seccomp.clone();
                root.cpu = Cpu::new(0x4000, 0);
                root.cpu.set_x(8, 220);
                root.cpu.set_x(0, flags);
                kernel.publish_task(1, &root);
                kernel.processes.insert(1, root);
                let control = Arc::new(Control::new(10000));
                let epoch = Epoch::with_events(control.clone(), kernel.workers.events(), false);
                epoch.bind_lifecycle(Lifecycle::capture(&kernel));
                let views = kernel.prepare_parallel_views(&[(1, 0)]).unwrap();
                for (id, _, view) in views {
                    epoch.add(kernel.capture_worker(
                        id,
                        view,
                        &control,
                        &mut Default::default(),
                        &mut Default::default(),
                        &mut Default::default(),
                    ));
                }
                kernel.workers.launch(0, epoch.clone()).unwrap();
                let mut stopped = 0;
                let mut owner_events = 0;
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let event = kernel
                        .workers
                        .event_timeout(deadline.saturating_duration_since(Instant::now()))
                        .unwrap();
                    match event {
                        Some(Event::EpochStopped(_)) => stopped += 1,
                        Some(Event::Retired) => {}
                        Some(Event::VmReady | Event::Idle) => owner_events += 1,
                        _ => panic!("source fork did not finish"),
                    }
                    if stopped == epoch.active_slots().count_ones() {
                        break;
                    }
                }
                assert_eq!(owner_events, 0, "cpus={cpus} flags={flags:#x}");
                assert!(epoch.collect_lifecycle(&mut kernel).is_none());
                assert_eq!(kernel.vm_checkpoint_groups, 1);
                let done = epoch.drain();
                assert_eq!(kernel.processes.len(), children + 1);
                assert_eq!(
                    kernel.worker_syscalls + done.iter().map(|d| d.syscalls).sum::<u64>(),
                    children as u64 + 2
                );
                assert!(done.iter().all(|done| done.thread_exit.is_some()));
                assert!(kernel.processes.values().all(|p| !p.signals.io.live()));
                if cpus == 4 {
                    assert_eq!(
                        policy.evaluations(),
                        children as u64 + 2,
                        "accepted clone policy must not be evaluated again after custody"
                    );
                }
            }
        }
    }

    #[test]
    fn additive_custody_wait_keeps_arguments_and_frees_the_only_cpu_slot() {
        for hold_memory in [false, true] {
            for cancel in [false, true] {
                let mut k = super::super::tests::kernel();
                let mut root = super::super::tests::admitted_process(&k);
                let external = root.memory.share();
                for (i, word) in [
                    0xd4000001u32,
                    0xd2820001,
                    0xf9000020,
                    0xd2800540,
                    0xd2800ba8,
                    0xd4000001,
                ]
                .into_iter()
                .enumerate()
                {
                    root.memory
                        .write_array(0x4000 + i as u64 * 4, word.to_le_bytes())
                        .unwrap();
                }
                root.memory
                    .protect(0x4000, trames_memory::PAGE_SIZE, Permissions::RX)
                    .unwrap();
                root.cpu = Cpu::new(0x4000, 0);
                root.cpu.set_x(8, 222);
                let args = [0, trames_memory::PAGE_SIZE, 3, 0x22, u64::MAX, 0];
                put_args(&mut root.cpu, args);
                let mut foreign = super::super::tests::admitted_process(&k);
                foreign
                    .memory
                    .write_array(0x4000, 0xd4000001u32.to_le_bytes())
                    .unwrap();
                foreign
                    .memory
                    .protect(0x4000, trames_memory::PAGE_SIZE, Permissions::RX)
                    .unwrap();
                foreign.cpu = Cpu::new(0x4000, 0);
                foreign.cpu.set_x(8, 93);
                foreign.cpu.set_x(0, 7);
                foreign.tgid = 4;
                foreign.group = 4;
                let foreign_family = foreign.family.clone();
                k.processes.insert(1, root);
                k.processes.insert(4, foreign);
                k.publish_io_tasks(None);
                let original = k.processes.handle(&1).unwrap();
                let epoch = Epoch::with_events(
                    Arc::new(Control::new(u64::MAX / 2)),
                    k.workers.events(),
                    true,
                );
                epoch.bind_lifecycle(Lifecycle::capture(&k));
                for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (4, 0)]).unwrap() {
                    epoch.add(k.capture_worker(
                        id,
                        view,
                        &epoch.control,
                        &mut Default::default(),
                        &mut Default::default(),
                        &mut Default::default(),
                    ));
                }
                let (release, released) = std::sync::mpsc::channel();
                let (ready, held) = std::sync::mpsc::channel();
                let holder = std::thread::spawn(move || {
                    let _task = (!hold_memory).then(|| original.write());
                    let _memory = hold_memory.then(|| external.try_admit().unwrap());
                    ready.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(5)).unwrap();
                });
                held.recv_timeout(Duration::from_secs(2)).unwrap();
                k.workers.launch(0, epoch.clone()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(3);
                while foreign_family.status().is_none() {
                    match k
                        .workers
                        .event_timeout(deadline.saturating_duration_since(Instant::now()))
                        .unwrap()
                    {
                        Some(Event::Idle) => {}
                        _ => panic!("busy original custody occupied the only CPU slot"),
                    }
                }
                assert_eq!(foreign_family.status(), Some(7 << 8));
                if cancel {
                    epoch.stop();
                }
                release.send(()).unwrap();
                holder.join().unwrap();
                loop {
                    match k
                        .workers
                        .event_timeout(deadline.saturating_duration_since(Instant::now()))
                        .unwrap()
                    {
                        Some(Event::Idle) => {}
                        Some(Event::EpochStopped(_)) => break,
                        _ => panic!("additive mapping required owner processing"),
                    }
                }
                let mut returned = epoch.drain();
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                assert_eq!(k.vm_local_syscalls, u64::from(!cancel));
                assert_eq!(k.serviced_syscalls, 0);
                if cancel {
                    assert_eq!(returned.len(), 1);
                    let result = returned.pop().unwrap();
                    assert!(matches!(result.outcome, Some(SliceOutcome::Syscall { .. })));
                    assert_eq!(result.cpu.x(8), 222);
                    for (i, a) in args.into_iter().enumerate() {
                        assert_eq!(result.cpu.x(i), a);
                    }
                } else {
                    assert!(returned.is_empty());
                    let root = k.processes.read(&1);
                    assert!(matches!(root.state, State::Zombie(status) if status == 42 << 8));
                    let address = root.memory.read_u64(0x1000).unwrap();
                    assert!(address > 0 && address < u64::MAX - 4095);
                    assert!(root
                        .memory
                        .check(
                            address,
                            trames_memory::PAGE_SIZE as usize,
                            trames_memory::Access::Write
                        )
                        .is_ok());
                }
                assert_eq!(k.vm_checkpoint_groups, 0);
            }
        }
    }
    #[test]
    fn mixed_mapping_and_fork_wait_for_original_borrowers_without_owner_or_slot_loss() {
        for cancel in [false, true] {
            let mut k = super::super::tests::kernel();
            let mut root = super::super::tests::admitted_process(&k);
            k.publish_task(1, &root);
            k.syscall(
                1,
                &mut root,
                220,
                [0x111, 0, 0, 0, 0, 0],
                &mut trames_linux::CapturedOutput::default(),
            )
            .unwrap();
            let mut borrower = root.memory.parallel_view(&mut k.parallel_memory).unwrap();
            k.processes.insert(1, root);
            k.processes
                .insert(9, super::super::tests::admitted_process(&k));
            k.task_ids = Arc::new(trames_kernel::task::Ids::from_next(10));
            k.publish_io_tasks(None);
            let epoch = Epoch::with_events(
                Arc::new(Control::new(u64::MAX / 2)),
                k.workers.events(),
                true,
            );
            epoch.bind_lifecycle(Lifecycle::capture(&k));
            for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (2, 0), (9, 0)]).unwrap() {
                epoch.add(k.capture_worker(
                    id,
                    view,
                    &epoch.control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
            }
            // Hold both original execution actors before publishing either
            // request, so this is one real mixed affected-mm scope.
            let mut fork = epoch.take(0).unwrap();
            let mut mapper = epoch.take(0).unwrap();
            assert_eq!((fork.work.pid, mapper.work.pid), (1, 2));
            fork.work.cpu.set_x(8, 220);
            put_args(&mut fork.work.cpu, [17, 0, 0, 0, 0, 0]);
            mapper.work.cpu.set_x(8, 226);
            put_args(
                &mut mapper.work.cpu,
                [0x6000, trames_memory::PAGE_SIZE, 1, 0, 0, 0],
            );
            epoch.checkpoint(fork, SliceOutcome::Syscall { instructions: 0 });
            epoch.checkpoint(mapper, SliceOutcome::Syscall { instructions: 0 });
            assert!(epoch.take_checkpoint().is_none());
            let foreign = epoch.take(0).unwrap();
            assert_eq!(
                foreign.work.pid, 9,
                "borrowed mm cannot occupy this executor"
            );
            epoch.park(foreign, Some(crate::run_queue::WaitState::OwnerEvent));
            assert_eq!(epoch.member_ids(), vec![1, 2, 9]);
            use trames_memory::CpuMemory;
            borrower.write_array(0x6000, 19u64.to_le_bytes()).unwrap();
            if cancel {
                epoch.stop();
            }
            drop(borrower);
            assert!(
                epoch.take_checkpoint().is_none(),
                "owner cannot steal an idle retry"
            );
            if !cancel {
                let mut resumed = Vec::new();
                for _ in 0..3 {
                    resumed.push(epoch.take(0).unwrap());
                }
                assert_eq!(epoch.member_ids(), vec![1, 2, 9, 10]);
                let child = k.processes.read(&10);
                assert_eq!(child.memory.read_u64(0x6000).unwrap(), 19);
                assert!(child
                    .memory
                    .check(0x6000, 8, trames_memory::Access::Write)
                    .is_err());
                drop(child);
                for job in resumed {
                    epoch.park(job, Some(crate::run_queue::WaitState::OwnerEvent));
                }
                epoch.stop();
            }
            assert!(epoch.collect_lifecycle(&mut k).is_none());
            assert_eq!(k.vm_checkpoint_groups, u64::from(!cancel));
            assert_eq!(k.vm_checkpoint_calls[4], u64::from(!cancel));
            assert_eq!(epoch.drain().len(), if cancel { 3 } else { 4 });
            while let Some(event) = k.workers.event_timeout(Duration::ZERO).unwrap() {
                assert!(
                    !matches!(event, Event::VmReady),
                    "source scope requested owner work"
                );
            }
        }
    }
    #[test]
    fn source_claim_cannot_be_stolen_and_busy_custody_releases_the_slot() {
        for memory in [false, true] {
            for cancel in [false, true] {
                let mut kernel = super::super::tests::kernel();
                let mut parent = super::super::tests::admitted_process(&kernel);
                let external = parent.memory.share();
                kernel.publish_task(1, &parent);
                kernel.processes.insert(1, parent);
                let foreign = super::super::tests::admitted_process(&kernel);
                kernel.processes.insert(4, foreign);
                kernel.task_ids = Arc::new(trames_kernel::task::Ids::from_next(5));
                kernel.publish_io_tasks(None);
                let epoch = Epoch::with_events(
                    Arc::new(Control::new(10000)),
                    kernel.workers.events(),
                    true,
                );
                epoch.bind_lifecycle(Lifecycle::capture(&kernel));
                for (id, _, view) in kernel.prepare_parallel_views(&[(1, 0), (4, 0)]).unwrap() {
                    epoch.add(kernel.capture_worker(
                        id,
                        view,
                        &epoch.control,
                        &mut Default::default(),
                        &mut Default::default(),
                        &mut Default::default(),
                    ));
                }
                let mut caller = epoch.take(0).unwrap();
                assert_eq!(caller.work.pid, 1);
                caller.work.cpu.set_x(8, 220);
                put_args(&mut caller.work.cpu, [17, 0, 0, 0, 0, 0]);
                let original = caller.work.task.as_ref().unwrap().clone();
                let (release, released) = std::sync::mpsc::channel();
                let (ready, held) = std::sync::mpsc::channel();
                let holder = std::thread::spawn(move || {
                    let _task = (!memory).then(|| original.write());
                    let _memory = memory.then(|| external.try_admit().unwrap());
                    ready.send(()).unwrap();
                    released.recv_timeout(Duration::from_secs(5)).unwrap();
                });
                held.recv_timeout(Duration::from_secs(5)).unwrap();
                epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 0 });
                assert!(
                    epoch.take_checkpoint().is_none(),
                    "owner cannot steal source work"
                );
                let foreign = epoch.take(0).unwrap();
                assert_eq!(foreign.work.pid, 4, "busy admission releases the same slot");
                epoch.park(foreign, Some(crate::run_queue::WaitState::OwnerEvent));
                assert!(epoch.take_checkpoint().is_none());
                if cancel {
                    epoch.stop();
                }
                release.send(()).unwrap();
                holder.join().unwrap();
                assert!(
                    epoch.take_checkpoint().is_none(),
                    "owner cannot steal a custody retry"
                );
                if !cancel {
                    let job = epoch.take(0).unwrap();
                    assert_eq!(epoch.member_ids().len(), 3);
                    epoch.park(job, None);
                    epoch.stop();
                }
                let done = epoch.drain();
                assert_eq!(done.len(), if cancel { 2 } else { 3 });
                assert!(epoch.collect_lifecycle(&mut kernel).is_none());
                assert_eq!(kernel.vm_checkpoint_groups, u64::from(!cancel));
            }
        }
    }
}
