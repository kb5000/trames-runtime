// SPDX-License-Identifier: GPL-3.0-or-later
//! Original mapped-file layout admission on existing execution slots.
use super::*;

/// A failed View publication can mean either a live byte borrower or an
/// exclusive backing mutation. Subscribe to the actual resource before
/// checking readiness; quiescent bytes alone cannot wake a layout waiter.
pub(in crate::process) fn wait_view(
    memory: &Memory,
    signal: &Arc<trames_shared::IoSignal>,
) -> Vec<trames_shared::IoSubscription> {
    let layouts = memory.parallel_layout_waits();
    if layouts.is_empty() {
        let subscription = memory.subscribe_parallel_idle(signal);
        if memory.parallel_views_quiescent() {
            signal.notify();
        }
        vec![subscription]
    } else {
        layouts
            .into_iter()
            .map(|layout| {
                let subscription = layout.subscribe(signal);
                if !layout.pending() {
                    signal.notify();
                }
                subscription
            })
            .collect()
    }
}

impl<C: Cpu> Lifecycle<C> {
    pub(super) fn release_layout_bytes(&self, epoch: &Epoch<C>, mut checkpoint: Checkpoint<C>) {
        let began = Instant::now();
        for job in &mut checkpoint.jobs {
            drop(job.work.memory.take());
            job.work.cpu.clear_exclusive();
        }
        let mut wait: Option<tasks::AdmissionWait> = None;
        let mut seen = std::collections::BTreeSet::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut pending = false;
            for job in &checkpoint.jobs {
                let p = &mut *job.work.task.as_ref().unwrap().write();
                if !seen.insert(p.memory.coordinator_ownership().0) {
                    continue;
                }
                if p.memory.parallel_views_quiescent() {
                    p.memory.commit_parallel()?;
                } else {
                    let wait = wait.get_or_insert_with(|| tasks::AdmissionWait {
                        signal: trames_shared::IoSignal::new(0, epoch.io_target.clone()),
                        subscriptions: Vec::new(),
                    });
                    wait.subscriptions
                        .push(p.memory.subscribe_parallel_idle(&wait.signal));
                    p.memory.commit_retired_parallel()?;
                    pending |= !p.memory.parallel_views_quiescent();
                }
            }
            Ok::<_, RuntimeError>(pending)
        }))
        .unwrap_or(Err(RuntimeError::Arguments(
            "layout byte completion panicked",
        )));
        let mut report = self.report.lock().unwrap();
        report.time[2] += began.elapsed();
        let pending = match result {
            Ok(pending) => pending,
            Err(error) => {
                report.error = Some(error);
                epoch.fail();
                false
            }
        };
        drop(report);
        if pending && !epoch.control.stopped() {
            let wait = wait.expect("original byte borrower");
            epoch.defer_checkpoint(checkpoint, wait.signal, wait.subscriptions);
        } else {
            // Keep every accepted syscall untouched. Its original closure is
            // still required before structural mutation; only bytes returned.
            epoch.restore_checkpoint(checkpoint, false);
        }
    }
    pub(super) fn admit_layouts(
        &self,
        checkpoint: &Checkpoint<C>,
        target: &std::sync::Weak<dyn trames_shared::IoWake>,
    ) -> Result<Option<tasks::AdmissionWait>, RuntimeError> {
        let mut ready = true;
        for job in &checkpoint.jobs {
            let p = &mut *job
                .work
                .task
                .as_ref()
                .expect("original layout task")
                .write();
            ready &= p.memory.admit_parallel_layouts();
        }
        if ready {
            Ok(None)
        } else {
            self.wait_layout_publication(checkpoint, target)
        }
    }
    pub(crate) fn layouts_ready(&self) -> bool {
        self.layout_driver
            .get()
            .is_some_and(|driver| driver.signal.ready())
    }
    pub(crate) fn layouts_pending(&self) -> bool {
        self.layouts.pending()
    }
    pub(crate) fn pump_layouts(&self, epoch: &Epoch<C>) {
        let requests = self
            .layout_driver
            .get()
            .expect("bound file layouts")
            .take_ready();
        for mut request in requests {
            if let Err(error) = join_layout(&self.tasks, Some(epoch), &mut request) {
                self.layouts.fail(request, 5);
                self.report.lock().unwrap().error = Some(error.into());
                epoch.fail();
                continue;
            }
            if let Err(request) = self.layouts.try_submit(request) {
                self.layouts.restore(request);
            }
        }
    }
    pub(super) fn wait_layout_publication(
        &self,
        checkpoint: &Checkpoint<C>,
        target: &std::sync::Weak<dyn trames_shared::IoWake>,
    ) -> Result<Option<tasks::AdmissionWait>, RuntimeError> {
        let mut layouts = BTreeMap::new();
        for job in &checkpoint.jobs {
            let task = job.work.task.as_ref().expect("original layout task").read();
            for layout in task.memory.parallel_layout_waits() {
                layouts.entry(layout.identity()).or_insert(layout);
            }
        }
        if layouts.is_empty() {
            return Ok(None);
        }
        let signal = trames_shared::IoSignal::new(0, target.clone());
        let mut subscriptions = Vec::new();
        self.commit_layout_roots(checkpoint, &signal, &mut subscriptions)?;
        for layout in layouts.into_values() {
            subscriptions.push(layout.subscribe(&signal));
            if !layout.pending() {
                signal.notify();
            }
        }
        Ok(Some(tasks::AdmissionWait {
            signal,
            subscriptions,
        }))
    }
    pub(super) fn commit_layout_roots(
        &self,
        checkpoint: &Checkpoint<C>,
        signal: &Arc<trames_shared::IoSignal>,
        subscriptions: &mut Vec<trames_shared::IoSubscription>,
    ) -> Result<(), RuntimeError> {
        let mut committed = std::collections::BTreeSet::new();
        // Failed preparation dropped every tentative View. A writer can have
        // arrived after the initial commit, so release those new root leases
        // too before waiting; otherwise two independent layout waits can cycle.
        for job in &checkpoint.jobs {
            let task = job.work.task.as_ref().unwrap();
            let p = &mut *task.write();
            if committed.insert(p.memory.coordinator_ownership().0) {
                if p.memory.parallel_views_quiescent() {
                    p.memory.commit_parallel()?;
                } else {
                    subscriptions.push(p.memory.subscribe_parallel_idle(signal));
                    p.memory.commit_retired_parallel()?;
                    if p.memory.parallel_views_quiescent() {
                        signal.notify();
                    }
                }
            }
        }
        Ok(())
    }
}

/// Only original backing readers are visited. Independent files/mms do not
/// acquire task custody, and no queue/directory mutex spans a memory commit.
pub(in crate::process) fn join_layout<C: Cpu>(
    tasks: &tasks::Directory<C>,
    epoch: Option<&Epoch<C>>,
    request: &mut trames_linux::FileLayoutRequest,
) -> Result<(), trames_memory::MemoryError> {
    for report in request.layout().readers() {
        let mut candidates = tasks.memory(&report);
        candidates.sort_by_key(|(pid, _)| !epoch.is_some_and(|e| e.contains(*pid)));
        for (pid, task) in candidates {
            let _custody = match tasks::admit_on(&task, &request.signal) {
                Ok(Some(permit)) => permit,
                Ok(None) => continue,
                Err(subscriptions) => {
                    for subscription in subscriptions {
                        request.retain_wait(subscription);
                    }
                    break;
                }
            };
            let p = &mut *task.write();
            if !p.memory.has_memory_report(&report) {
                continue;
            }
            if p.memory.parallel_views_quiescent()
                && epoch.is_some_and(|e| e.suspended_memory(p.memory.instruction_identity().0))
            {
                // An owned scope can be parked on an independent image/layout
                // wait. Original task/mm custody proves it is not executing;
                // do not wait for that unrelated operation to release bytes.
                p.cpu.clear_exclusive();
                p.memory.commit_parallel()?;
                break;
            }
            if epoch.is_some_and(|e| e.request_file_layouts(pid)) {
                break;
            }
            let subscription = p.memory.subscribe_parallel_idle(&request.signal);
            if !p.memory.parallel_views_quiescent() {
                request.retain_wait(subscription);
                break;
            }
            p.cpu.clear_exclusive();
            p.memory.commit_parallel()?;
            break;
        }
    }
    Ok(())
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use crate::workers::{Control, Event};
    use trames_memory::{CpuMemory, Permissions, PAGE_SIZE};
    struct Held(std::sync::mpsc::Sender<(trames_vfs::FileWork, Arc<trames_linux::FileResult>)>);
    impl trames_linux::FileExecutor for Held {
        fn submit_file(&self, work: trames_vfs::FileWork, result: Arc<trames_linux::FileResult>) {
            assert!(self.0.send((work.queued(), result)).is_ok());
        }
    }
    #[test]
    fn layout_scopes_free_the_only_slot_and_cover_external_and_late_publication() {
        for mode in 0..3 {
            let mut k = super::super::super::tests::kernel();
            let mut root = super::super::super::tests::admitted_process(&k);
            k.syscall(
                1,
                &mut root,
                220,
                [17, 0, 0, 0, 0, 0],
                &mut trames_linux::CapturedOutput::default(),
            )
            .unwrap();
            root.linux
                .vfs
                .import_file(b"/mapped", vec![7; PAGE_SIZE as usize])
                .unwrap();
            let fd = root.linux.vfs.open_at(-100, b"/mapped", 2, 0).unwrap();
            root.memory
                .map_backed(
                    0x10000,
                    root.linux
                        .vfs
                        .mapping_pages(fd, 0, PAGE_SIZE, true, true)
                        .unwrap(),
                    true,
                    Permissions::RW,
                    false,
                )
                .unwrap();
            let original = root
                .linux
                .vfs
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap();
            let work = trames_vfs::FileWork::new(
                &root.linux.vfs.path_queries(),
                original,
                trames_vfs::FileCommand::Truncate(1),
            );
            let trames_vfs::FileOutcome::Layout(work) = work.run() else {
                panic!("accepted layout");
            };
            k.publish_task(1, &root);
            k.processes.insert(1, root);
            let external = (mode == 1).then(|| {
                k.processes
                    .get_mut(&1)
                    .unwrap()
                    .memory
                    .parallel_view(&mut k.parallel_memory)
                    .unwrap()
            });
            let (send, receive) = std::sync::mpsc::channel();
            let layouts = trames_linux::FileLayouts::new(Arc::new(Held(send)));
            assert!(k.layout_work.set(layouts.clone()).is_ok());
            let result = Arc::new(trames_linux::FileResult::default());
            let control = Arc::new(Control::new(10000));
            let epoch = Epoch::with_events(control.clone(), k.workers.events(), false);
            epoch.bind_lifecycle(Lifecycle::capture(&k));
            let views = k.prepare_parallel_views(&[(1, 0), (2, 0)]).unwrap();
            let mut work = Some(work);
            if mode == 2 {
                assert!(layouts.submit(work.take().unwrap(), result.clone()).is_ok());
            }
            for (id, _, view) in views {
                epoch.add(k.capture_worker(
                    id,
                    view,
                    &control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
            }
            if let Some(work) = work {
                assert!(layouts.submit(work, result.clone()).is_ok());
            }
            let mut foreign = epoch.take(0).unwrap();
            assert_eq!(
                foreign.work.pid, 2,
                "unrelated work owns the available slot"
            );
            if let Some(external) = external {
                assert!(
                    receive.try_recv().is_err(),
                    "external byte owner still lives"
                );
                drop(external);
                epoch.park(foreign, None);
                foreign = epoch.take(0).unwrap();
                assert_eq!(foreign.work.pid, 2);
            }
            let (work, native) = receive.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(!result.finished());
            assert!(epoch.contains(1));
            assert!(!control.stopped());
            native.complete(work.run());
            epoch.park(foreign, None);
            let mut resumed = epoch.take(0).unwrap();
            if resumed.work.pid != 1 {
                epoch.park(resumed, None);
                resumed = epoch.take(0).unwrap();
            }
            assert_eq!(resumed.work.pid, 1);
            assert_eq!(
                resumed
                    .work
                    .memory
                    .as_ref()
                    .unwrap()
                    .read_array::<1>(0x10000)
                    .unwrap(),
                [7]
            );
            assert!(result.finished());
            assert!(!layouts.pending());
            epoch.park(resumed, None);
            epoch.stop();
            assert_eq!(epoch.drain().len(), 2);
            assert!(epoch.collect_lifecycle(&mut k).is_none());
            while let Some(event) = k.workers.event_timeout(Duration::ZERO).unwrap() {
                assert!(!matches!(event, Event::VmReady));
            }
        }
    }
    #[test]
    fn mmap_wait_retains_original_fd_across_epoch_cancellation() {
        use trames_cpu::SliceOutcome;
        for cancel in [false, true] {
            let mut k = super::super::super::tests::kernel();
            let mut root = super::super::super::tests::admitted_process(&k);
            k.syscall(
                1,
                &mut root,
                220,
                [17, 0, 0, 0, 0, 0],
                &mut trames_linux::CapturedOutput::default(),
            )
            .unwrap();
            root.linux
                .vfs
                .import_file(b"/original", vec![37; PAGE_SIZE as usize])
                .unwrap();
            root.linux
                .vfs
                .import_file(b"/replacement", vec![91; PAGE_SIZE as usize])
                .unwrap();
            let fd = root.linux.vfs.open_at(-100, b"/original", 2, 0).unwrap();
            let layout = root.linux.vfs.mapping_file(fd).unwrap().layout().unwrap();
            let exclusive = layout.write().try_enter().ok().unwrap();
            k.publish_task(1, &root);
            k.processes.insert(1, root);
            let epoch = Epoch::with_events(Arc::new(Control::new(10000)), k.workers.events(), true);
            epoch.bind_lifecycle(Lifecycle::capture(&k));
            for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (2, 0)]).unwrap() {
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
            assert_eq!(caller.work.pid, 1);
            let a = [0x10000, PAGE_SIZE, 3, 0x11, fd as u64, 0];
            caller.work.cpu.set_x(8, 222);
            put_args(&mut caller.work.cpu, a);
            epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 0 });
            let foreign = epoch.take(0).unwrap();
            assert_eq!(foreign.work.pid, 2, "mmap releases the only execution slot");
            epoch.park(foreign, Some(crate::run_queue::WaitState::OwnerEvent));
            {
                let mut p = k.processes.get_mut(&1).unwrap();
                assert!(p.linux.has_pending_mmap());
                p.linux.vfs.close(fd).unwrap();
                assert_eq!(
                    p.linux.vfs.open_at(-100, b"/replacement", 2, 0).unwrap(),
                    fd
                );
            }
            if cancel {
                epoch.stop();
                for done in epoch.drain() {
                    k.restore_worker_return(done);
                }
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                drop(epoch);
                drop(exclusive);
                let mut p = k.processes.remove(&1).unwrap();
                k.call(
                    1,
                    &mut p,
                    222,
                    a,
                    &mut trames_linux::CapturedOutput::default(),
                );
                assert_eq!(p.cpu.x(0), 0x10000);
                assert_eq!(p.memory.read_array::<1>(0x10000).unwrap(), [37]);
                assert!(!p.linux.has_pending_mmap());
                assert_eq!(k.vm_checkpoint_calls[3], 0);
            } else {
                drop(exclusive);
                let job = epoch.take(0).unwrap();
                assert_eq!(job.work.pid, 1);
                assert_eq!(job.work.cpu.x(0), 0x10000);
                assert_eq!(
                    job.work
                        .memory
                        .as_ref()
                        .unwrap()
                        .read_array::<1>(0x10000)
                        .unwrap(),
                    [37]
                );
                epoch.park(job, None);
                epoch.stop();
                assert_eq!(epoch.drain().len(), 2);
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                assert_eq!(k.vm_checkpoint_calls[3], 1);
            }
        }
    }

    struct LateFile {
        layout: Arc<trames_memory::layout::Layout>,
        armed: std::sync::atomic::AtomicBool,
        writer: Mutex<Option<trames_memory::layout::LayoutWrite>>,
    }
    impl trames_memory::PageBacking for LateFile {
        fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
            Some(self.layout.clone())
        }
        fn parallel_key(&self) -> Option<(u64, u64)> {
            if self.armed.swap(false, std::sync::atomic::Ordering::Relaxed) {
                *self.writer.lock().unwrap() = Some(self.layout.write());
            }
            Some((self.layout.identity(), 0))
        }
        fn check(&self, _: u64) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn read(&self, _: usize, out: &mut [u8]) -> Result<(), trames_memory::MemoryError> {
            out.fill(73);
            Ok(())
        }
        fn write(&self, _: usize, _: &[u8]) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn sync(&self) -> Result<(), trames_memory::MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            0
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(
            &self,
            _: u64,
        ) -> Result<Arc<dyn trames_memory::PageBacking>, trames_memory::MemoryError> {
            Err(trames_memory::MemoryError::InvalidRange)
        }
    }
    #[test]
    fn created_child_survives_late_layout_wait_and_cancellation_without_replay() {
        use trames_cpu::SliceOutcome;
        for cancel in [false, true] {
            let mut k = super::super::super::tests::kernel();
            let mut root = super::super::super::tests::admitted_process(&k);
            k.syscall(
                1,
                &mut root,
                220,
                [17, 0, 0, 0, 0, 0],
                &mut trames_linux::CapturedOutput::default(),
            )
            .unwrap();
            let file = Arc::new(LateFile {
                layout: Arc::default(),
                armed: false.into(),
                writer: Mutex::default(),
            });
            root.memory
                .map_backed(0x10000, vec![file.clone()], true, Permissions::RW, false)
                .unwrap();
            k.publish_task(1, &root);
            k.processes.insert(1, root);
            let epoch = Epoch::with_events(Arc::new(Control::new(10000)), k.workers.events(), true);
            epoch.bind_lifecycle(Lifecycle::capture(&k));
            for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (2, 0)]).unwrap() {
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
            assert_eq!(caller.work.pid, 1);
            caller.work.cpu.set_x(8, 220);
            put_args(&mut caller.work.cpu, [17, 0, 0, 0, 0, 0]);
            file.armed.store(true, std::sync::atomic::Ordering::Relaxed);
            epoch.checkpoint(caller, SliceOutcome::Syscall { instructions: 0 });
            let foreign = epoch.take(0).unwrap();
            assert_eq!(foreign.work.pid, 2);
            epoch.park(foreign, Some(crate::run_queue::WaitState::OwnerEvent));
            assert_eq!(epoch.member_ids(), vec![1, 2, 3]);
            let writer = file
                .writer
                .lock()
                .unwrap()
                .take()
                .expect("writer arrived after child creation");
            assert!(
                writer.ready(),
                "failed View publication released every mm root"
            );
            if cancel {
                epoch.stop();
            }
            drop(writer);
            if !cancel {
                let first = epoch.take(0).unwrap();
                let second = epoch.take(0).unwrap();
                assert_eq!(
                    std::collections::BTreeSet::from([first.work.pid, second.work.pid]),
                    std::collections::BTreeSet::from([1, 3])
                );
                for job in [first, second] {
                    assert_eq!(job.work.cpu.x(0), if job.work.pid == 1 { 3 } else { 0 });
                    assert_eq!(
                        job.work
                            .memory
                            .as_ref()
                            .unwrap()
                            .read_array::<1>(0x10000)
                            .unwrap(),
                        [73]
                    );
                    epoch.park(job, Some(crate::run_queue::WaitState::OwnerEvent));
                }
                epoch.stop();
            }
            let done = epoch.drain();
            assert_eq!(done.len(), 3);
            for done in done {
                k.restore_worker_return(done);
            }
            assert!(epoch.collect_lifecycle(&mut k).is_none());
            assert_eq!(k.processes.len(), 3);
            assert_eq!(k.processes.read(&1).cpu.x(0), 3);
            assert_eq!(k.processes.read(&3).cpu.x(0), 0);
        }
    }
    #[test]
    fn cold_exit_waits_for_layout_completion_without_retrying_idle_memory() {
        for cancel in [false, true] {
            let mut k = super::super::super::tests::kernel();
            let mut root = super::super::super::tests::admitted_process(&k);
            k.syscall(
                1,
                &mut root,
                220,
                [17, 0, 0, 0, 0, 0],
                &mut trames_linux::CapturedOutput::default(),
            )
            .unwrap();
            let exclusive;
            let family;
            let group;
            {
                let mut child = k.processes.get_mut(&2).unwrap();
                child
                    .linux
                    .vfs
                    .import_file(b"/cold", vec![7; PAGE_SIZE as usize])
                    .unwrap();
                let fd = child.linux.vfs.open_at(-100, b"/cold", 2, 0).unwrap();
                let file = child.linux.vfs.mapping_file(fd).unwrap();
                let pages = child
                    .linux
                    .vfs
                    .mapping_pages(fd, 0, PAGE_SIZE, true, true)
                    .unwrap();
                child
                    .memory
                    .map_backed(0x10000, pages, true, Permissions::RW, false)
                    .unwrap();
                exclusive = file.layout().unwrap().write().try_enter().ok().unwrap();
                child.state = State::Suspend(0);
                family = child.family.clone();
                group = child.signals.io.lifecycle().clone();
            }
            k.publish_task(1, &root);
            k.processes.insert(1, root);
            let epoch = Epoch::with_events(Arc::new(Control::new(10000)), k.workers.events(), true);
            epoch.bind_lifecycle(Lifecycle::capture(&k));
            for (id, _, view) in k.prepare_parallel_views(&[(1, 0)]).unwrap() {
                epoch.add(k.capture_worker(
                    id,
                    view,
                    &epoch.control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
            }
            group.request_exit(31 << 8);
            let root_job = epoch.take(0).unwrap();
            assert_eq!(root_job.work.pid, 1);
            assert_eq!(family.status(), None);
            epoch.park(root_job, None);
            if cancel {
                epoch.stop();
                for done in epoch.drain() {
                    k.restore_worker_return(done);
                }
                assert!(epoch.collect_lifecycle(&mut k).is_none());
                drop(epoch);
                k.process_exits(None).unwrap();
                assert!(k.exits.waiting(2));
                assert_eq!(family.status(), None);
                drop(exclusive);
                k.process_exits(None).unwrap();
            } else {
                drop(exclusive);
                let root_job = epoch.take(0).unwrap();
                epoch.park(root_job, None);
                epoch.stop();
                assert_eq!(epoch.drain().len(), 1);
                assert!(epoch.collect_lifecycle(&mut k).is_none());
            }
            assert_eq!(family.status(), Some(31 << 8));
            assert!(!k.processes.read(&2).signals.io.live());
        }
    }
    #[test]
    fn layout_bytes_return_even_when_mapping_closure_waits_for_an_owned_scope() {
        let mut k = super::super::super::tests::kernel();
        let mut root = super::super::super::tests::admitted_process(&k);
        let mut io = trames_linux::CapturedOutput::default();
        k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut io)
            .unwrap();
        root.linux
            .vfs
            .import_file(b"/cycle", vec![7; PAGE_SIZE as usize])
            .unwrap();
        let fd = root.linux.vfs.open_at(-100, b"/cycle", 2, 0).unwrap();
        let pages = root
            .linux
            .vfs
            .mapping_pages(fd, 0, PAGE_SIZE, true, true)
            .unwrap();
        root.memory
            .map_backed(0x10000, pages, true, Permissions::RW, false)
            .unwrap();
        k.syscall(1, &mut root, 220, [17, 0, 0, 0, 0, 0], &mut io)
            .unwrap();
        let target = root
            .linux
            .vfs
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let trames_vfs::FileOutcome::Layout(work) = trames_vfs::FileWork::new(
            &root.linux.vfs.path_queries(),
            target,
            trames_vfs::FileCommand::Truncate(1),
        )
        .run() else {
            panic!("accepted layout");
        };
        k.publish_task(1, &root);
        k.processes.insert(1, root);
        let (send, receive) = std::sync::mpsc::channel();
        let layouts = trames_linux::FileLayouts::new(Arc::new(Held(send)));
        assert!(k.layout_work.set(layouts.clone()).is_ok());
        let epoch = Epoch::with_events(Arc::new(Control::new(10000)), k.workers.events(), true);
        epoch.bind_lifecycle(Lifecycle::capture(&k));
        for (id, _, view) in k.prepare_parallel_views(&[(1, 0), (2, 0), (3, 0)]).unwrap() {
            epoch.add(k.capture_worker(
                id,
                view,
                &epoch.control,
                &mut Default::default(),
                &mut Default::default(),
                &mut Default::default(),
            ));
        }
        let root = epoch.take(0).unwrap();
        let foreign = epoch.take(0).unwrap();
        let mut mapper = epoch.take(0).unwrap();
        assert_eq!(
            (root.work.pid, foreign.work.pid, mapper.work.pid),
            (1, 2, 3)
        );
        epoch.park(root, None);
        epoch.park(foreign, None);
        let result = Arc::new(trames_linux::FileResult::default());
        assert!(layouts.submit(work, result.clone()).is_ok());
        let foreign = epoch.take(0).unwrap();
        assert_eq!(foreign.work.pid, 2);
        assert!(
            receive.try_recv().is_err(),
            "running mapper still owns bytes"
        );
        mapper.work.cpu.set_x(8, 222);
        put_args(
            &mut mapper.work.cpu,
            [0x20000, PAGE_SIZE, 3, 0x32, u64::MAX, 0],
        );
        epoch.checkpoint(mapper, SliceOutcome::Syscall { instructions: 0 });
        epoch.park(foreign, None);
        let foreign = epoch.take(0).unwrap();
        assert_eq!(foreign.work.pid, 2);
        let (work, native) = receive
            .try_recv()
            .expect("mapping closure must not retain byte owners");
        native.complete(work.run());
        let first = epoch.take(0).unwrap();
        let second = epoch.take(0).unwrap();
        for job in [first, second] {
            if job.work.pid == 3 {
                assert_eq!(job.work.cpu.x(0), 0x20000);
            }
            epoch.park(job, Some(crate::run_queue::WaitState::OwnerEvent));
        }
        epoch.park(foreign, None);
        epoch.stop();
        assert_eq!(epoch.drain().len(), 3);
        assert!(epoch.collect_lifecycle(&mut k).is_none());
        assert_eq!(k.vm_checkpoint_calls[3], 1);
        assert!(result.finished());
    }
}
