// SPDX-License-Identifier: GPL-3.0-or-later
//! File layout work retains its original backing across source and serial
//! execution. Native I/O uses the existing disk pool; no process scan or pause.
use super::*;
impl<C: Cpu> Kernel<C> {
    /// Serial/traced execution uses the same backing publication as source
    /// CPUs. Waiting retains readiness on the task, never a process-wide pause.
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn admit_owner_layouts(
        &self,
        pid: u32,
        p: &mut Process<C>,
    ) -> Result<bool, RuntimeError> {
        if p.layout_wait
            .as_ref()
            .is_some_and(|wait| !wait.signal.ready())
        {
            return Ok(false);
        }
        p.layout_wait = None;
        if p.memory.admit_parallel_layouts() {
            return Ok(true);
        }
        let signal = trames_shared::IoSignal::new(pid, Arc::downgrade(&self.byte_target));
        let mut subscriptions = lifecycle::layouts::wait_view(&p.memory, &signal);
        // A writer may have arrived after this mm's last commit. Release the
        // root lease before parking; external generations retain their own.
        subscriptions.push(p.memory.subscribe_parallel_idle(&signal));
        p.cpu.clear_exclusive();
        p.memory.commit_retired_parallel()?;
        p.layout_wait = Some(tasks::AdmissionWait {
            signal,
            subscriptions,
        });
        Ok(false)
    }
    pub(super) fn file_layout_work(&self) -> Arc<trames_linux::FileLayouts> {
        self.layout_work
            .get_or_init(|| {
                let layouts = trames_linux::FileLayouts::new(self.workers.file_executor());
                #[cfg(all(test, trames_interpreter_conformance))]
                layouts.bind_owner(trames_shared::IoSignal::new(
                    0,
                    Arc::downgrade(&self.byte_target),
                ));
                layouts
            })
            .clone()
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn start_file_checkpoint(
        &mut self,
        _pid: u32,
        p: &mut Process<C>,
        _number: u32,
        _args: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        match p.file_checkpoint.take().unwrap().take() {
            trames_linux::FileBoundary::Owner { work, output } => {
                let reply = work.run_owner(&mut p.linux.vfs);
                p.file_entry = None;
                output.apply(reply.result, &mut p.memory).map(Some)
            }
            trames_linux::FileBoundary::Signal { value } => {
                trames_vfs::TaskSignal::raise(&*p.signals.io, 25);
                p.file_entry = None;
                value.map(Some)
            }
            trames_linux::FileBoundary::Layout { work, output } => {
                let target = work.target().cloned();
                let result = Arc::new(trames_linux::FileResult::wake_joined());
                let pending = trames_linux::FilePending::new(result.clone(), output, target);
                p.retained_file = Some(pending);
                if let Err(work) = self.file_layout_work().submit(work, result) {
                    // Layout outcomes always retain a regular-file target.
                    drop(work);
                    return Err(Errno(5));
                }
                Ok(None)
            }
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn poll_file_layouts(&mut self) {
        if let Some(layouts) = self.layout_work.get().cloned() {
            let tasks = self.processes.directory();
            for mut request in layouts.take_owner() {
                if lifecycle::layouts::join_layout(&tasks, None, &mut request).is_err() {
                    layouts.fail(request, 5);
                } else if let Err(request) = layouts.try_submit(request) {
                    layouts.restore(request);
                }
            }
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use trames_execution::Registers;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn host_export_uses_original_backing_on_four_and_twelve_cpu_sources() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Export {
            file: trames_vfs::HostExport,
            done: Arc<AtomicBool>,
        }
        impl trames_linux::HostFileTask for Export {
            fn layout(&self) -> Option<Arc<trames_linux::HostFileLayout>> {
                Some(self.file.layout())
            }
            fn run(self: Box<Self>, admission: Option<trames_linux::HostFileAdmission>) {
                assert!(admission.is_some());
                let mut bytes = Vec::new();
                self.file.write_to(&mut bytes).unwrap();
                assert_eq!(&bytes[..8], &17u64.to_le_bytes());
                self.done.store(true, Ordering::Release);
            }
            fn fail(self: Box<Self>) {
                panic!("host export failed")
            }
        }
        struct Host {
            work: Option<Box<Export>>,
            ready: trames_vfs::DirectFd,
            done: Arc<AtomicBool>,
            layouts: Option<Arc<trames_linux::FileLayouts>>,
            deadline: Instant,
            pause: bool,
            paused: bool,
        }
        impl GuestOutput for Host {
            fn bind_host_files(
                &mut self,
                _: Arc<dyn trames_linux::FileExecutor>,
                layouts: Arc<trames_linux::FileLayouts>,
            ) {
                self.layouts = Some(layouts);
            }
            fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
                Arc::new(trames_vfs::CapturedConsole::default())
            }
            fn paused(&self) -> bool {
                self.paused
            }
            fn poll_host(
                &mut self,
                _: &trames_vfs::Vfs,
            ) -> std::io::Result<trames_linux::HostState> {
                if self.work.is_some() {
                    match self.ready.read(1) {
                        Err(trames_vfs::Errno(11)) => {
                            return Ok(trames_linux::HostState::from_cancelled(
                                Instant::now() > self.deadline,
                            ))
                        }
                        value => assert_eq!(
                            value,
                            Ok(vec![17]),
                            "guest publishes its mapped write before export"
                        ),
                    }
                    self.paused = self.pause;
                }
                if let Some(work) = self.work.take() {
                    self.layouts.as_ref().unwrap().submit_host(work);
                }
                Ok(trames_linux::HostState::from_cancelled(
                    self.done.load(Ordering::Acquire) || Instant::now() > self.deadline,
                ))
            }

            fn host_interest(&mut self, wait: &mut trames_linux::HostWait) -> std::io::Result<()> {
                wait.until(std::time::Instant::now() + Duration::from_millis(1));
                Ok(())
            }
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
        }
        // Multi-CPU source admission; solo uses the same backing driver and is
        // separately covered by its existing file-layout conformance fixtures.
        for (cpus, pause) in [(4, false), (12, false), (4, true), (12, true)] {
            let mut k = super::super::tests::kernel();
            k.cpu_count = cpus;
            k.workers = crate::workers::Pool::new(cpus);
            k.per_cpu = vec![Duration::ZERO; cpus];
            let mut root = super::super::tests::process();
            root.linux
                .vfs
                .import_file(b"/mapped", vec![0; PAGE_SIZE as usize])
                .unwrap();
            let export = root.linux.vfs.host_export(b"/mapped").unwrap();
            let [reader, writer] = root.linux.vfs.pipe(trames_vfs::O_NONBLOCK).unwrap();
            let ready = root
                .linux
                .vfs
                .shared_files()
                .lookup(reader)
                .unwrap()
                .unwrap()
                .direct_byte()
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
            for id in 1..=cpus {
                let mut p = if id == 1 {
                    root
                } else {
                    super::super::tests::process()
                };
                p.tgid = id as u32;
                p.vm_id = id as u64;
                p.signals.io.scheduling.set_affinity(1 << (id - 1));
                let words: Vec<u32> = if id == 1 {
                    vec![
                        0xd2a00020,
                        0xd2800221,
                        0xf9000001,
                        0xd2800000 | writer << 5,
                        0xd2a00021,
                        0xd2800022,
                        0xd2800808,
                        0xd4000001,
                        0x14000000,
                    ]
                } else {
                    vec![0x14000000]
                };
                p.memory
                    .write(
                        0x4000,
                        &words
                            .iter()
                            .flat_map(|v| v.to_le_bytes())
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                p.memory
                    .protect(0x4000, PAGE_SIZE, Permissions::RX)
                    .unwrap();
                k.processes.insert(id as u32, p);
                root = super::super::tests::process();
            }
            let done = Arc::new(AtomicBool::new(false));
            let mut host = Host {
                ready,
                work: Some(Box::new(Export {
                    file: export,
                    done: done.clone(),
                })),
                done: done.clone(),
                layouts: None,
                deadline: Instant::now() + Duration::from_secs(5),
                pause,
                paused: false,
            };
            assert!(matches!(
                k.drive(&mut host, u64::MAX),
                Err(RuntimeError::Cancelled)
            ));
            assert!(
                done.load(Ordering::Acquire),
                "host export must complete before its timeout"
            );
            assert_eq!(k.parallel_rounds, 1, "host I/O must not split the cohort");
            assert!(k.cohort_return_syscalls.is_empty());
        }
    }
    #[test]
    fn file_layout_waits_for_original_views_and_retires_once_without_global_pauses() {
        let mut k = super::super::tests::kernel();
        let mut p = super::super::tests::process();
        p.linux
            .vfs
            .import_file(b"/mapped", vec![0xa5; PAGE_SIZE as usize])
            .unwrap();
        let fd = p.linux.vfs.open_at(-100, b"/mapped", 2, 0).unwrap();
        p.memory
            .map_backed(
                0x10000,
                p.linux
                    .vfs
                    .mapping_pages(fd, 0, PAGE_SIZE, true, true)
                    .unwrap(),
                true,
                Permissions::RW,
                false,
            )
            .unwrap();
        let peer = p.fork();
        k.processes.insert(2, peer);
        k.processes.insert(3, super::super::tests::process());
        let view = p.memory.parallel_view(&mut Default::default()).unwrap();
        let args = [fd as u64, 1, 0, 0, 0, 0];
        let mut io = trames_linux::CapturedOutput::default();
        let layouts = k.file_layout_work();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !layouts.pending() {
            k.call(1, &mut p, 46, args, &mut io);
            assert!(Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(p.file_checkpoint.is_none());
        let result = p.byte_wait.as_ref().unwrap().file_pending().unwrap().result;
        assert_eq!(p.linux.vfs.seek(fd, 0, 2).unwrap(), PAGE_SIZE);
        k.processes.insert(1, p);
        k.poll_file_layouts();
        assert!(
            !result.finished(),
            "original external View excludes mutation"
        );
        let mut peer = k.processes.remove(&2).unwrap();
        assert!(!k.admit_owner_layouts(2, &mut peer).unwrap());
        assert!(!peer.layout_wait.as_ref().unwrap().signal.ready());
        k.processes.insert(2, peer);
        let mut foreign = k.processes.remove(&3).unwrap();
        assert!(k.admit_owner_layouts(3, &mut foreign).unwrap());
        k.processes.insert(3, foreign);
        drop(view);
        while !result.finished() {
            k.poll_file_layouts();
            assert!(Instant::now() < deadline);
            std::thread::park_timeout(Duration::from_millis(1));
        }
        let mut p = k.processes.remove(&1).unwrap();
        assert!(k.admit_owner_layouts(1, &mut p).unwrap());
        k.call(1, &mut p, 46, args, &mut io);
        assert!(matches!(p.state, State::Ready));
        assert_eq!(p.cpu.x(0), 0);
        assert!(p.file_entry.is_none());
        assert_eq!(p.linux.vfs.seek(fd, 0, 2).unwrap(), 1);
        assert!(!layouts.pending());
        let mut peer = k.processes.remove(&2).unwrap();
        assert!(k.admit_owner_layouts(2, &mut peer).unwrap());
    }
    #[test]
    fn caught_signal_keeps_the_accepted_native_result_instead_of_restarting_input() {
        let mut k = super::super::tests::kernel();
        let mut p = super::super::tests::process();
        p.linux.vfs.import_file(b"/file", Vec::new()).unwrap();
        let fd = p.linux.vfs.open_at(-100, b"/file", 2, 0).unwrap();
        let target = p
            .linux
            .vfs
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let result = Arc::new(trames_linux::FileResult::default());
        let args = [fd as u64, 0x1000, 7, 0, 0, 0];
        p.retained_file = Some(trames_linux::FilePending::new(
            result.clone(),
            trames_linux::FileOutput::None,
            target,
        ));
        p.file_entry = Some((p.cpu.pc(), 64, args));
        p.state = State::Blocked(64, args);
        p.signals.actions.set_handler(10, 0x5000);
        Kernel::<trames_cpu::Cpu>::queue_one(1, &mut p, 10, 1);
        assert_eq!(k.deliver(1, &mut p), Ok(false));
        assert!(p.file_entry.is_some());
        result.complete(trames_vfs::FileOutcome::Complete(trames_vfs::FileReply {
            result: Ok(trames_vfs::FileValue::Count(7)),
            file_size_signal: false,
            scratch: None,
        }));
        k.call(
            1,
            &mut p,
            64,
            args,
            &mut trames_linux::CapturedOutput::default(),
        );
        assert_eq!(p.cpu.x(0), 7);
        assert!(p.file_entry.is_none());
        assert_eq!(k.deliver(1, &mut p), Ok(true));
        assert_eq!(p.cpu.pc(), 0x5000);
        assert_eq!(p.cpu.x(0), 10);
    }
}
