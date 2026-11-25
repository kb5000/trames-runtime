// SPDX-License-Identifier: GPL-3.0-or-later
//! File layout work retains its original backing across source and serial
//! execution. Native I/O uses the existing disk pool; no process scan or pause.
use super::*;
impl<C: Cpu> Kernel<C> {
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn metadata_call(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        number: u32,
        args: [u64; 6],
        info: Option<trames_linux::SystemInfo>,
    ) -> Result<Option<u64>, Errno> {
        let source = trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
            .with_resources(p.linux.vfs.descriptor_factory())
            .with_paths(p.linux.vfs.path_queries())
            .with_clock(self.started)
            .with_boot_clock(p.linux.boot_clock());
        let target = Arc::downgrade(&self.byte_target);
        let attempt = if let Some(wait) = p.byte_wait.take() {
            source.resume(wait, &mut p.memory)
        } else if let Some(file) = p.retained_file.take() {
            source.start_retained_file(file, number, args, &mut p.memory, pid, &target)
        } else {
            let result = match number {
                160..=162 => source.invoke_uts(
                    &p.linux.vfs.uts_capability(),
                    &p.linux.personality,
                    number,
                    args,
                    &mut p.memory,
                ),
                86 | 87 => source.invoke(number, args, &mut p.memory),
                113 | 114 => source.invoke_time(
                    number,
                    args,
                    &mut p.memory,
                    self.started,
                    (trames_kernel::signal::IoRoutes {
                        directory: p.signals.io_directory.clone(),
                        namespace: p.linux.vfs.pid_namespace().clone(),
                        uid: p.linux.vfs.credentials.uid,
                        euid: p.linux.vfs.credentials.euid,
                    })
                    .cpu_clock(&p.signals.io, args[0]),
                    Some(&p.signals.io.proc_view),
                ),
                168 => source.invoke_getcpu(args, p.last_cpu as u32, &mut p.memory),
                169 => source.invoke_time(number, args, &mut p.memory, self.started, None, None),
                179 => source.invoke_statistics(
                    info.expect("original statistics snapshot"),
                    args,
                    &mut p.memory,
                ),
                278 => source.invoke_entropy(args, &mut p.memory),
                _ => unreachable!("metadata entry"),
            };
            if let Some(result) = result {
                return result.map(Some);
            }
            source
                .start_metadata_copy(number, args, &mut p.memory, pid, &target)
                .expect("original metadata receipt")
        };
        match attempt {
            trames_linux::IoAttempt::Complete(result) => {
                p.retained_file = None;
                result.map(Some)
            }
            trames_linux::IoAttempt::Blocked(wait) => {
                p.retained_file = wait.file_pending();
                p.byte_wait = Some(wait);
                Ok(None)
            }
            trames_linux::IoAttempt::FileCheckpoint(file) => {
                p.file_checkpoint = Some(file);
                Ok(None)
            }
            trames_linux::IoAttempt::HostError(error) => {
                self.backend_error = Some(error.to_string());
                Err(Errno(5))
            }
            _ => unreachable!("metadata copies own no structural mutation"),
        }
    }
    #[cfg(all(test, trames_interpreter_conformance))]
    pub(super) fn uring_call(
        &mut self,
        pid: u32,
        p: &mut Process<C>,
        args: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        if p.byte_wait.is_some() || p.uring_wait.is_some() {
            p.signals.finish_io();
        } else {
            p.signals.begin_io();
        }
        let source = trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
            .with_paths(p.linux.vfs.path_queries())
            .with_resources(p.linux.vfs.descriptor_factory())
            .with_task_signal(p.signals.io.clone())
            .with_signal_reader(p.signals.reader(p.linux.vfs.pid_namespace()))
            .with_urings(
                trames_linux::UringEpoch::default()
                    .capture(&p.linux.vfs, p.memory.instruction_identity().0, pid)
                    .with_actor(p.linux.uring_actor_root()),
            )
            .with_file_executor(self.workers.file_executor())
            .with_file_layouts(self.file_layout_work())
            .with_clock(self.started);
        let _actor = trames_vfs::FileActorScope::enter_with_sync(
            p.signals.io.credentials().clone(),
            pid,
            source.sync_executor(),
        );
        let target = Arc::downgrade(&self.byte_target);
        let attempt = if let Some(wait) = p.byte_wait.take() {
            source.resume(wait, &mut p.memory)
        } else if let Some(call) = p.uring_wait.take() {
            source.start_retained_uring(call, args, &mut p.memory, pid, &target)
        } else {
            source
                .start(426, args, &mut p.memory, pid, &target, None)
                .expect("original ring authority")
        };
        p.signals.finish_io();
        match attempt {
            trames_linux::IoAttempt::Complete(result) => {
                p.uring_wait = None;
                result.map(Some)
            }
            trames_linux::IoAttempt::Blocked(wait) => {
                p.uring_wait = wait.uring_enter();
                p.retained_file = wait.file_pending();
                p.byte_wait = Some(wait);
                Ok(None)
            }
            trames_linux::IoAttempt::FileCheckpoint(call) => {
                p.file_checkpoint = Some(call);
                Ok(None)
            }
            trames_linux::IoAttempt::HostError(error) => {
                self.backend_error = Some(error.to_string());
                Err(Errno(5))
            }
            _ => unreachable!("original accepted enter stays with its caller"),
        }
    }
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
        pid: u32,
        p: &mut Process<C>,
        _number: u32,
        _args: [u64; 6],
    ) -> Result<Option<u64>, Errno> {
        match p.file_checkpoint.take().unwrap().take() {
            trames_linux::FileBoundary::WaitInput(call) => {
                if call.has_native_mask() {
                    p.signals.finish_io();
                } else {
                    p.signals.begin_io();
                }
                let source = trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                    .with_task_signal(p.signals.io.clone());
                let attempt = call.resume_joined(
                    &source,
                    &mut p.linux,
                    &mut p.memory,
                    pid,
                    &Arc::downgrade(&self.byte_target),
                );
                p.signals.finish_io();
                match attempt {
                    trames_linux::IoAttempt::Complete(result) => result.map(Some),
                    trames_linux::IoAttempt::Blocked(wait) => {
                        p.retained_file = wait.file_pending();
                        p.byte_wait = Some(wait);
                        Ok(None)
                    }
                    trames_linux::IoAttempt::WaitCheckpoint(wait) => {
                        p.file_entry = None;
                        p.poll_deadline = wait.deadline;
                        p.retained_poll = Some(wait);
                        Ok(None)
                    }
                    trames_linux::IoAttempt::FileCheckpoint(file) => {
                        p.file_checkpoint = Some(file);
                        Ok(None)
                    }
                    trames_linux::IoAttempt::HostError(error) => {
                        self.backend_error = Some(error.to_string());
                        Err(Errno(5))
                    }
                    _ => unreachable!("original wait input"),
                }
            }
            trames_linux::FileBoundary::EpollControl {
                fd,
                op,
                target,
                events,
                data,
            } => {
                let call = p
                    .linux
                    .vfs
                    .prepare_epoll_control(fd, op, target, events, data)?;
                match trames_linux::DirectSyscalls::default().start_retained_epoll_control(
                    Box::new(call),
                    _args,
                    pid,
                    &Arc::downgrade(&self.byte_target),
                ) {
                    trames_linux::IoAttempt::Complete(result) => result.map(Some),
                    trames_linux::IoAttempt::Blocked(wait) => {
                        p.retained_file = wait.file_pending();
                        p.byte_wait = Some(wait);
                        Ok(None)
                    }
                    _ => unreachable!("original epoll control"),
                }
            }
            boundary @ (trames_linux::FileBoundary::Registration(_)
            | trames_linux::FileBoundary::UringEnter(_)
            | trames_linux::FileBoundary::Aio(_)
            | trames_linux::FileBoundary::AioLookup(_)
            | trames_linux::FileBoundary::AioSetup(_)
            | trames_linux::FileBoundary::TimerFd(_)
            | trames_linux::FileBoundary::Ioctl(_)) => {
                p.signals.finish_io();
                let source = trames_linux::DirectSyscalls::new(p.linux.vfs.direct_descriptors())
                    .with_aio(p.linux.aio.clone(), p.linux.vfs.native_events())
                    .with_paths(p.linux.vfs.path_queries())
                    .with_resources(p.linux.vfs.descriptor_factory())
                    .with_task_signal(p.signals.io.clone())
                    .with_signal_reader(p.signals.reader(p.linux.vfs.pid_namespace()))
                    .with_urings(
                        trames_linux::UringEpoch::default()
                            .capture(&p.linux.vfs, p.memory.instruction_identity().0, pid)
                            .with_actor(p.linux.uring_actor_root()),
                    )
                    .with_file_executor(self.workers.file_executor())
                    .with_file_layouts(self.file_layout_work())
                    .with_clock(self.started);
                let _actor = trames_vfs::FileActorScope::enter_with_sync(
                    p.signals.io.credentials().clone(),
                    pid,
                    source.sync_executor(),
                );
                let target = Arc::downgrade(&self.byte_target);
                let attempt = match boundary {
                    trames_linux::FileBoundary::Registration(call) => {
                        call.resume(&source, &mut p.memory, pid, &target)
                    }
                    trames_linux::FileBoundary::UringEnter(call) => {
                        call.resume(&source, &mut p.memory, pid, &target)
                    }
                    trames_linux::FileBoundary::Aio(call) => {
                        source.start_retained_aio(call, &mut p.memory, pid, &target)
                    }
                    trames_linux::FileBoundary::AioLookup(call) => {
                        call.resume(&source, &mut p.memory, pid, &target)
                    }
                    trames_linux::FileBoundary::AioSetup(call) => {
                        call.resume(&source, &mut p.memory, pid, &target)
                    }
                    trames_linux::FileBoundary::TimerFd(call) => {
                        call.resume(&source, &mut p.memory, pid, &target)
                    }
                    trames_linux::FileBoundary::Ioctl(call) => {
                        call.resume_joined(&source, &p.linux.vfs, &mut p.memory, pid, &target)
                    }
                    _ => unreachable!("accepted control checkpoint"),
                };
                p.signals.finish_io();
                match attempt {
                    trames_linux::IoAttempt::Complete(value) => value.map(Some),
                    trames_linux::IoAttempt::Blocked(wait) => {
                        p.uring_wait = wait.uring_enter();
                        p.retained_file = wait.file_pending();
                        p.byte_wait = Some(wait);
                        Ok(None)
                    }
                    trames_linux::IoAttempt::FileCheckpoint(file) => {
                        p.file_checkpoint = Some(file);
                        Ok(None)
                    }
                    _ => Err(Errno(5)),
                }
            }
            trames_linux::FileBoundary::Owner { work, output } => {
                let target = work.target().cloned();
                let result = Arc::new(trames_linux::FileResult::wake_joined());
                result.complete(work.resume_owner(&mut p.linux.vfs));
                p.retained_file = Some(trames_linux::FilePending::new(result, output, target));
                Ok(None)
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
    fn owner_proc_continuation_returns_to_retained_file_scheduling() {
        fn answer(v: &mut trames_vfs::Vfs, fd: u32, request: &[u8], payload: &[u8]) {
            let mut bytes = Vec::new();
            bytes.extend(((16 + payload.len()) as u32).to_le_bytes());
            bytes.extend(0i32.to_le_bytes());
            bytes.extend(&request[8..16]);
            bytes.extend(payload);
            assert_eq!(v.write(fd, &bytes).unwrap(), bytes.len());
        }
        let mut k = super::super::tests::kernel();
        let mut p = super::super::tests::process();
        let v = &mut p.linux.vfs;
        v.set_runtime_info(1, Default::default());
        v.mkdir_at(-100, b"/mnt", 0o755).unwrap();
        let daemon = v.open_at(-100, b"/dev/fuse", 2, 0).unwrap();
        let options = format!("fd={daemon},rootmode=40755,user_id=0,group_id=0");
        v.mount(None, b"/mnt", Some(b"fuse"), 0, Some(options.as_bytes()))
            .unwrap();
        let init = v.read(daemon, 8192).unwrap();
        let mut version = [0; 64];
        version[..4].copy_from_slice(&7u32.to_le_bytes());
        version[4..8].copy_from_slice(&31u32.to_le_bytes());
        answer(v, daemon, &init, &version);
        let original = v.memfd_create(b"original", 0).unwrap();
        v.write(original, b"original bytes").unwrap();
        v.set_runtime_info(
            1,
            trames_vfs::RuntimeInfo {
                processes: vec![trames_vfs::ProcessInfo {
                    pid: 1,
                    tgid: 1,
                    fds: v.fd_snapshot(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        p.memory.map(0x10000, PAGE_SIZE, Permissions::RW).unwrap();
        p.memory.write(0x10000, b"/mnt/link\0").unwrap();
        let args = [(-100i64) as u64, 0x10000, 0, 0, 0, 0];
        let mut io = trames_linux::CapturedOutput::default();
        let mut lookup = false;
        let mut readlink = false;
        let mut resumed = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            k.call(1, &mut p, 56, args, &mut io);
            resumed |= p.retained_file.is_some();
            while let Ok(request) = p.linux.vfs.read(daemon, 8192) {
                let opcode = u32::from_le_bytes(request[4..8].try_into().unwrap());
                match opcode {
                    1 => {
                        assert!(
                            !lookup,
                            "owner continuation must not repeat the FUSE lookup"
                        );
                        lookup = true;
                        let mut entry = [0; 128];
                        entry[..8].copy_from_slice(&71u64.to_le_bytes());
                        entry[24..32].copy_from_slice(&1u64.to_le_bytes());
                        entry[40..48].copy_from_slice(&171u64.to_le_bytes());
                        entry[100..104].copy_from_slice(&0o120777u32.to_le_bytes());
                        answer(&mut p.linux.vfs, daemon, &request, &entry);
                    }
                    5 => {
                        assert!(!readlink);
                        readlink = true;
                        answer(
                            &mut p.linux.vfs,
                            daemon,
                            &request,
                            format!("/proc/self/fd/{original}").as_bytes(),
                        );
                    }
                    2 => (),
                    _ => panic!("unexpected FUSE opcode {opcode}"),
                }
            }
            if lookup && readlink && p.file_entry.is_none() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "retained owner continuation did not complete"
            );
            std::thread::park_timeout(Duration::from_millis(1));
        }
        assert!(
            resumed,
            "the owner checkpoint must return a retained continuation"
        );
        let fd = p.cpu.x(0) as u32;
        assert_ne!(fd, original);
        assert_eq!(p.linux.vfs.read(fd, 32).unwrap(), b"original bytes");
        assert!(p.retained_file.is_none());
    }

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
            resources: Default::default(),
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
