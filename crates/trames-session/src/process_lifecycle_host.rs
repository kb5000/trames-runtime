// SPDX-License-Identifier: GPL-3.0-or-later
//! Host image construction/admission on original resources and existing workers.
use super::super::host::{Launch, Phase};
use super::*;
impl<C: Cpu> Lifecycle<C> {
    pub(crate) fn host_error(&self, error: RuntimeError) {
        self.report.lock().unwrap().error = Some(error);
    }
    pub(crate) fn host_ready(&self) -> bool {
        self.host_driver
            .get()
            .is_some_and(|driver| driver.signal.ready())
    }
    pub(crate) fn host_pending(&self) -> bool {
        self.host_launches.pending()
    }
    pub(crate) fn submit_host(&self, request: trames_linux::HostSpawn) {
        self.host_launches.submit(request);
    }
    pub(crate) fn pump_host(&self, epoch: &Epoch<C>, slot: usize) -> Result<(), RuntimeError> {
        let signal = self.host_driver.get().map(|driver| &driver.signal);
        let mut pending = Vec::new();
        let mut ready = self.host_launches.take(signal).into_iter();
        while let Some(mut work) = ready.next() {
            // Subscription destruction and every handler run outside the
            // resource list/run-queue locks. No original body is loaned by RPC.
            work.wait.take();
            let result = self.host_step(&mut work, epoch, slot);
            match result {
                Ok(true) => self.host_launches.completed(),
                Ok(false) => pending.push(work),
                Err(error) => {
                    pending.push(work);
                    pending.extend(ready);
                    self.host_launches.retain(pending);
                    return Err(error);
                }
            }
        }
        self.host_launches.retain(pending);
        Ok(())
    }
    fn host_step(
        &self,
        work: &mut Launch<C>,
        epoch: &Epoch<C>,
        slot: usize,
    ) -> Result<bool, RuntimeError> {
        let target: Arc<dyn trames_shared::IoWake> = self.host_launches.clone();
        let target = Arc::downgrade(&target);
        loop {
            if work.process.cancelled() && !matches!(work.phase, Phase::Published(..)) {
                work.process.fail(125);
                return Ok(true);
            }
            match std::mem::replace(&mut work.phase, Phase::Taken) {
                Phase::Request(request) => {
                    let Some(root) = self.tasks.handle(&1) else {
                        work.process.fail(3);
                        return Ok(true);
                    };
                    let _custody = match tasks::admit_one(&root, 1, &target) {
                        Ok(Some(permit)) => permit,
                        Ok(None) => {
                            work.process.fail(3);
                            return Ok(true);
                        }
                        Err(wait) => {
                            work.phase = Phase::Request(request);
                            work.wait = Some(wait);
                            return Ok(false);
                        }
                    };
                    let prepared = {
                        let root = root.read();
                        self.birth.prepare_host(&root, *request)
                    };
                    let (child, request) = match prepared {
                        Ok(value) => value,
                        Err(error) => {
                            work.process.fail(error.0);
                            return Ok(true);
                        }
                    };
                    drop(_custody);
                    let result = Arc::new(exec::Pending::new(self.owner.clone()));
                    self.images.submit_image(request, result.clone());
                    work.phase = Phase::Image(child, exec::Preparation::Disk(result));
                }
                Phase::Image(child, result) => {
                    if !result.ready() {
                        work.signal.reset();
                        let subscription = result.subscribe(&work.signal);
                        if !result.ready() {
                            work.wait = Some(tasks::AdmissionWait {
                                signal: work.signal.clone(),
                                subscriptions: vec![subscription],
                            });
                            work.phase = Phase::Image(child, result);
                            return Ok(false);
                        }
                    }
                    let image = match result.take() {
                        Ok(image) => image,
                        Err(error) => {
                            work.process.fail(error.0);
                            return Ok(true);
                        }
                    };
                    let child = match self.birth.finish_host(child, image) {
                        Ok(child) => child,
                        Err(error) => {
                            work.process.fail(error.0);
                            return Ok(true);
                        }
                    };
                    let id = child.id;
                    let task: tasks::Handle<C> = child.process.into();
                    // Publish original family/task authority before exposing the
                    // external PID. Cancellation then either wins publication,
                    // or addresses an already discoverable original group.
                    let _admission = task.try_admit().expect("unpublished host child");
                    let admission = epoch.reserve_host(id);
                    self.tasks.publish(id, task.clone());
                    if !work.process.publish(id) {
                        task.read().signals.io.lifecycle().request_exit(1);
                        return Ok(true);
                    }
                    work.phase = Phase::Published(id, task, admission);
                }
                Phase::Published(id, task, admission) => {
                    if !self.tasks.contains_original(id, &task) {
                        return Ok(true);
                    }
                    let _custody = match tasks::admit_one(&task, id, &target) {
                        Ok(Some(permit)) => permit,
                        Ok(None) => return Ok(true),
                        Err(wait) => {
                            work.phase = Phase::Published(id, task, admission);
                            work.wait = Some(wait);
                            return Ok(false);
                        }
                    };
                    if !task.read().signals.io.live() {
                        return Ok(true);
                    }
                    if epoch.contains(id) {
                        return Ok(true);
                    }
                    if work.process.cancelled() {
                        task.read().signals.io.lifecycle().request_exit(1);
                        return Ok(true);
                    }
                    let mut registry = self.registry.share();
                    let mut error = None;
                    let mut views = dispatch::prepare_views(
                        &self.tasks,
                        &mut registry,
                        &[(id, slot)],
                        false,
                        &mut error,
                    );
                    if let Some(error) = error {
                        work.phase = Phase::Published(id, task, admission);
                        return Err(RuntimeError::Backend(error));
                    }
                    if views.is_none() {
                        work.signal.reset();
                        let subscriptions = layouts::wait_view(&task.read().memory, &work.signal);
                        if work.signal.ready() {
                            // A provider/borrow may have become available while
                            // subscribing. Retry once, never spin on an actually
                            // excluded legacy backing. Its original Ready task
                            // retains the existing solo/admission route.
                            views = dispatch::prepare_views(
                                &self.tasks,
                                &mut registry,
                                &[(id, slot)],
                                false,
                                &mut error,
                            );
                            if let Some(error) = error {
                                work.phase = Phase::Published(id, task, admission);
                                return Err(RuntimeError::Backend(error));
                            }
                            if views.is_none() {
                                return Ok(true);
                            }
                        } else {
                            work.wait = Some(tasks::AdmissionWait {
                                signal: work.signal.clone(),
                                subscriptions,
                            });
                            work.phase = Phase::Published(id, task, admission);
                            return Ok(false);
                        }
                    }
                    let mut views = views.expect("ready source host child");
                    self.admit_private_views(&mut views, &mut registry);
                    let (_, _, view) = views.pop().expect("host child View");
                    let job = self.dispatch.job(
                        (id, task),
                        view,
                        &epoch.control,
                        &mut Default::default(),
                        &mut Default::default(),
                        &mut Default::default(),
                    );
                    epoch.admit_live(job);
                    self.report.lock().unwrap().memory.merge(registry.metrics);
                    return Ok(true);
                }
                Phase::Taken => unreachable!("original host operation retained"),
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

    struct Output(Option<trames_linux::HostSpawn>);
    impl GuestOutput for Output {
        fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
            Arc::new(trames_vfs::CapturedConsole::default())
        }
        fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
            Ok(bytes.len())
        }

        fn poll_host(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<trames_linux::HostState> {
            Ok(trames_linux::HostState::Running)
        }

        fn host_spawn(&mut self) -> Option<trames_linux::HostSpawn> {
            self.0.take()
        }
    }
    struct Held(std::sync::mpsc::Sender<(exec::Request, Arc<exec::Pending<Cpu>>)>);
    impl exec::Executor<Cpu> for Held {
        fn submit_image(&self, request: exec::Request, result: Arc<exec::Pending<Cpu>>) {
            self.0.send((request, result)).unwrap();
        }
    }
    fn image(busy: bool) -> Vec<u8> {
        let mut image = vec![0u8; 140];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (at, value) in [(16, 2u16), (18, 183), (52, 64), (54, 56), (56, 1)] {
            image[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (at, value) in [(20, 1u32), (64, 1), (68, 5)] {
            image[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (at, value) in [
            (24, 0x400080u64),
            (32, 64),
            (80, 0x400000),
            (96, 140),
            (104, 140),
            (112, 4096),
        ] {
            image[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let words = if busy {
            [0xd2801588u32, 0xd4000001, 0x17fffffe]
        } else {
            [0xd2800540, 0xd2800ba8, 0xd4000001]
        };
        for (i, word) in words.into_iter().enumerate() {
            image[128 + i * 4..132 + i * 4].copy_from_slice(&word.to_le_bytes());
        }
        image
    }
    fn setup(busy: bool) -> (Kernel<Cpu>, Output, Arc<trames_linux::HostProcess>) {
        let mut k = super::super::super::tests::kernel();
        let mut root = super::super::super::tests::admitted_process(&k);
        for (i, word) in [0xd2801588u32, 0xd4000001, 0x17fffffe]
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
        root.linux
            .vfs
            .import_executable(b"/program", image(busy))
            .unwrap();
        let process = Arc::new(trames_linux::HostProcess::default());
        let output = Output(Some(trames_linux::HostSpawn {
            argv: vec![b"program".to_vec()],
            environment: vec![b"PATH=/".to_vec()],
            vfs: root.linux.vfs.clone(),
            process: process.clone(),
        }));
        k.publish_task(1, &root);
        k.processes.insert(1, root);
        (k, output, process)
    }
    #[test]
    fn cold_host_launch_runs_on_sources_when_no_guest_cpu_is_ready() {
        struct Host {
            output: Output,
            process: Arc<trames_linux::HostProcess>,
            deadline: Instant,
        }
        impl GuestOutput for Host {
            fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
                self.output.source_console()
            }
            fn write(&mut self, fd: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                self.output.write(fd, bytes)
            }
            fn host_spawn(&mut self) -> Option<trames_linux::HostSpawn> {
                self.output.host_spawn()
            }
            fn control_poll_interval(&self) -> Duration {
                Duration::from_millis(1)
            }
            fn poll_host(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<HostState> {
                assert!(
                    Instant::now() < self.deadline,
                    "cold source host launch did not complete"
                );
                Ok(HostState::from_cancelled(
                    self.process.status() != trames_linux::HOST_RUNNING,
                ))
            }
        }
        for cpus in [1, 4, 12] {
            let (mut k, output, process) = setup(false);
            k.cpu_count = cpus;
            k.per_cpu.resize(cpus, Duration::ZERO);
            k.processes.get_mut(&1).unwrap().state =
                State::Sleep(Instant::now() + Duration::from_secs(30), 0);
            let mut host = Host {
                output,
                process: process.clone(),
                deadline: Instant::now() + Duration::from_secs(5),
            };
            assert!(matches!(
                k.drive(&mut host, u64::MAX),
                Err(RuntimeError::Cancelled)
            ));
            assert_eq!(process.status(), 42 << 8);
            assert_eq!(k.parallel_rounds, 1);
            assert!(k.worker_slices > 0);
            assert!(k.cohort_return_syscalls.is_empty());
            assert_eq!(k.service_requests, 0);
        }
    }
    fn start(k: &mut Kernel<Cpu>, lifecycle: Lifecycle<Cpu>) -> Arc<Epoch<Cpu>> {
        let epoch = Epoch::with_events(
            Arc::new(Control::new(u64::MAX / 2)),
            k.workers.events(),
            true,
        );
        epoch.bind_lifecycle(lifecycle);
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
        k.workers.launch(0, epoch.clone()).unwrap();
        epoch
    }
    fn until(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready() {
            assert!(
                Instant::now() < deadline,
                "source host lifecycle did not progress"
            );
            std::thread::yield_now();
        }
    }
    fn stop(k: &mut Kernel<Cpu>, epoch: &Epoch<Cpu>) {
        epoch.stop();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stopped = 0;
        while stopped < epoch.active_slots().count_ones() {
            match k
                .workers
                .event_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
            {
                Some(Event::EpochStopped(_)) => stopped += 1,
                Some(Event::Retired) => {}
                event => panic!(
                    "unexpected owner handoff: {}",
                    match event {
                        Some(Event::VmReady) => "VmReady",
                        Some(Event::Idle) => "Idle",
                        _ => "other/timeout",
                    }
                ),
            }
        }
        assert!(epoch.collect_lifecycle(k).is_none());
        for done in epoch.drain() {
            k.adopt_worker_return(done, false);
        }
        assert_eq!(k.vm_checkpoint_groups, 0);
    }
    #[test]
    fn live_host_launch_and_completion_share_the_only_busy_executor_without_owner_handoff() {
        let (mut k, mut output, process) = setup(false);
        let lifecycle = Lifecycle::capture(&k);
        let epoch = start(&mut k, lifecycle);
        assert!(!k
            .cohort_live_control(&epoch, &[(1, 0)], &mut output)
            .unwrap());
        until(|| process.status() != trames_linux::HOST_RUNNING);
        assert_eq!(process.pid(), 2);
        assert_eq!(process.status(), 42 << 8);
        until(|| !k.host_launches.pending());
        assert!(!k
            .cohort_live_control(&epoch, &[(1, 0)], &mut output)
            .unwrap());
        stop(&mut k, &epoch);
    }
    #[test]
    fn accepted_host_image_releases_original_custody_and_survives_epoch_replacement_or_disconnect()
    {
        for cancel in [false, true] {
            let (mut k, mut output, process) = setup(false);
            let (send, receive) = std::sync::mpsc::channel();
            let mut lifecycle = Lifecycle::capture(&k);
            lifecycle.images = Arc::new(Held(send));
            let epoch = start(&mut k, lifecycle);
            assert!(!k
                .cohort_live_control(&epoch, &[(1, 0)], &mut output)
                .unwrap());
            let (request, result) = receive.recv_timeout(Duration::from_secs(5)).unwrap();
            let root = k.processes.handle(&1).unwrap();
            assert!(
                root.try_admit().is_some(),
                "disk image wait retained parent task"
            );
            assert!(
                root.read().memory.try_admit().is_some(),
                "disk image wait retained parent mm"
            );
            if cancel {
                process.cancel();
            }
            stop(&mut k, &epoch);
            let lifecycle = Lifecycle::capture(&k);
            let replacement = start(&mut k, lifecycle);
            // Keep the old driver alive: its eventual Drop must not unbind the replacement.
            drop(epoch);
            result.complete(request.load());
            until(|| process.status() != trames_linux::HOST_RUNNING);
            assert_eq!(process.status(), if cancel { -125 } else { 42 << 8 });
            assert_eq!(process.pid(), if cancel { 0 } else { 2 });
            until(|| !k.host_launches.pending());
            assert!(!k
                .cohort_live_control(&replacement, &[(1, 0)], &mut output)
                .unwrap());
            stop(&mut k, &replacement);
            if cancel {
                assert_eq!(
                    k.processes.len(),
                    1,
                    "late completion created a cancelled child"
                );
            }
        }
    }
    #[test]
    fn source_created_host_group_retirement_never_becomes_a_foreign_ready_owner_task() {
        let (mut k, mut output, process) = setup(true);
        let lifecycle = Lifecycle::capture(&k);
        let epoch = start(&mut k, lifecycle);
        assert!(!k
            .cohort_live_control(&epoch, &[(1, 0)], &mut output)
            .unwrap());
        until(|| process.pid() != 0 && epoch.contains(process.pid()));
        let child = k.processes.handle(&process.pid()).unwrap();
        let held = loop {
            if let Some(held) = child.try_admit() {
                break held;
            }
            std::thread::yield_now();
        };
        let original = child.read().signals.io.clone();
        assert!(!k
            .cohort_live_control(&epoch, &[(1, 0)], &mut output)
            .unwrap());
        process.signal(15);
        until(|| !original.live() && !epoch.contains(process.pid()));
        assert!(matches!(child.read().state, State::Ready));
        assert!(!k.cohort_live_control(&epoch, &[(1, 0)], &mut output).unwrap(),
            "already terminal original actor must not re-enter owner fallback during cold retirement");
        drop(held);
        until(|| process.status() != trames_linux::HOST_RUNNING);
        assert_eq!(process.status(), 15);
        stop(&mut k, &epoch);
    }
}
