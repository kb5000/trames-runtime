// SPDX-License-Identifier: GPL-3.0-or-later
//! Structural process-view publication; live state stays on original resources.
use super::*;
pub(super) struct ProcReadWait<C: Cpu> {
    pub checkpoint: Option<crate::run_queue::Checkpoint<C>>,
    pub report: Option<trames_memory::MemoryReport>,
    pub signal: Arc<trames_vfs::IoSignal>,
    pub subscriptions: Vec<trames_vfs::IoSubscription>,
}
impl<C: Cpu> Kernel<C> {
    pub(super) fn proc_read_wait(&self) -> ProcReadWait<C> {
        let source: Arc<dyn trames_vfs::IoWake> = self.proc_source.as_ref().unwrap().clone();
        ProcReadWait {
            checkpoint: None,
            report: None,
            signal: trames_vfs::IoSignal::new(0, Arc::downgrade(&source)),
            subscriptions: Vec::new(),
        }
    }
    pub(super) fn activate_proc_reads(
        &mut self,
        epoch: Option<&crate::run_queue::Epoch<C>>,
        reports: Vec<trames_memory::MemoryReport>,
        waiting: &mut Vec<ProcReadWait<C>>,
    ) -> Result<(), RuntimeError> {
        for report in reports {
            if !report.alive() || !report.has_requested_reads() {
                continue;
            }
            let Some((pid, _)) = self
                .processes
                .iter()
                .filter(|(_, p)| p.memory.has_memory_report(&report))
                .min_by_key(|(pid, _)| epoch.is_none_or(|epoch| !epoch.contains(*pid)))
            else {
                continue;
            };
            if epoch.is_some_and(|epoch| epoch.request_proc_reads(pid)) {
                continue;
            }
            let mut wait = self.proc_read_wait();
            let p = &mut *self.processes.get_mut(&pid).unwrap();
            wait.subscriptions
                .push(p.memory.subscribe_parallel_idle(&wait.signal));
            if !p.memory.parallel_views_quiescent() {
                wait.report = Some(report);
                waiting.push(wait);
                continue;
            }
            p.cpu.clear_exclusive();
            p.memory.commit_parallel()?;
            assert!(p.memory.activate_proc_reads());
        }
        Ok(())
    }
    pub(super) fn progress_proc_reads(&mut self) -> Result<(), RuntimeError> {
        let mut reports = self
            .proc_source
            .as_ref()
            .map_or_else(Vec::new, |s| s.take_reads());
        let waits = std::mem::take(&mut self.proc_owner_waits);
        let mut pending = Vec::new();
        for wait in waits {
            if wait.signal.ready() {
                reports.extend(wait.report);
            } else {
                pending.push(wait);
            }
        }
        let result = self.activate_proc_reads(None, reports, &mut pending);
        self.proc_owner_waits = pending;
        result
    }
    pub(super) fn install_proc_source(
        &mut self,
        root: &Process<C>,
        host: Option<Arc<dyn Fn() -> trames_linux::HostMemoryInfo + Send + Sync>>,
    ) {
        root.memory.renew_memory_report();
        let events = self.workers.events();
        let owner = std::thread::current();
        let source = Arc::new(crate::proc_views::Source {
            directory: root.signals.io_directory.clone(),
            counters: Arc::default(),
            created: std::sync::atomic::AtomicU32::new(self.task_ids.created()),
            load: self.load.clone(),
            started: self.started,
            boot_time: self.boot_time,
            cpus: self.cpu_count,
            features: C::feature_names(),
            task_limit: self.task_capacity.limit(),
            limits: self.memory_limits,
            host,
            reads: Default::default(),
            wake: Arc::new(move || {
                let _ = events.send(crate::workers::Event::<C>::VmReady);
                owner.unpark();
            }),
        });
        root.linux.vfs.set_proc_source(source.clone());
        self.proc_source = Some(source);
    }
    pub(super) fn publish_proc_task(&self, pid: u32, p: &Process<C>) {
        super::birth::Birth::capture(self).publish_proc(pid, p);
    }
    pub(super) fn proc_after_call(&self, pid: u32, p: &Process<C>, number: u32, args: [u64; 6]) {
        if self.proc_source.is_none() {
            return;
        }
        p.signals
            .io
            .proc_view
            .waiting(!matches!(p.state, State::Ready));
        if crate::worker_syscalls::vm_call(number) || matches!(number, 196 | 197) {
            p.memory.memory_report();
        }
        if p.cpu.x(0) > u64::MAX - 4095 {
            return;
        }
        if matches!(number, 97 | 268 | 277)
            || number == 436 && args[2] & 2 != 0
            || number == 167 && args[0] == 22
        {
            self.publish_proc_task(p.rekey.unwrap_or(pid), p);
        }
    }
}

impl<C: Cpu> Process<C> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn info(
        &self,
        pid: u32,
        origin: Instant,
        limits: super::super::MemoryLimits,
        resident_bytes: usize,
        demand: trames_vfs::ProcRefresh,
        maps: Vec<u8>,
    ) -> trames_vfs::ProcessInfo {
        // Argument bytes are mutable guest memory, so read them live only for
        // an actual cmdline observation. Unrelated proc files never consume
        // this payload; their next cmdline lookup requests its own refresh.
        let image = (demand.arguments() || demand.environment())
            .then(|| self.memory.memory_report().image_ranges())
            .flatten()
            .map(trames_vfs::ProcImage);
        let zombie = matches!(self.state, State::Zombie(_));
        let arguments_bytes = if demand.arguments() && zombie {
            Some(Vec::new())
        } else {
            image
                .as_ref()
                .filter(|_| demand.arguments())
                .and_then(|image| {
                    image.command_line(0, usize::MAX, |a, out| {
                        trames_vfs::ProcImage::local_reader(&self.memory, a, out)
                    })
                })
        };
        let environment_bytes = if demand.environment() && zombie {
            Some(Vec::new())
        } else {
            image
                .as_ref()
                .filter(|_| demand.environment())
                .and_then(|image| {
                    image.environment(0, usize::MAX, |a, out| {
                        trames_vfs::ProcImage::local_reader(&self.memory, a, out)
                    })
                })
        };
        let arguments = if demand.arguments() && arguments_bytes.is_none() {
            self.linux
                .argument_pointers
                .iter()
                .enumerate()
                .map(|(i, pointer)| {
                    self.memory
                        .read_c_string(
                            *pointer,
                            self.linux.arguments.get(i).map_or(65536, |a| a.len() + 1),
                        )
                        .unwrap_or_else(|_| {
                            self.linux.arguments.get(i).cloned().unwrap_or_default()
                        })
                })
                .collect()
        } else {
            Vec::new()
        };
        let (ignored, caught) = self.signals.actions.masks();
        let (cwd_directory, root_directory) = if demand.directories() {
            self.linux.vfs.proc_directories()
        } else {
            (None, None)
        };
        trames_vfs::ProcessInfo {
            identity: trames_vfs::ProcTask::identity(&*self.signals.io),
            pid,
            tgid: self.tgid,
            parent: self.family.parent(),
            group: self.group(),
            session: self.session(),
            state: if self.stopped() && !matches!(self.state, State::Zombie(_)) {
                'T'
            } else {
                match self.state {
                    State::Ready => 'R',
                    State::Zombie(_) => 'Z',
                    _ => 'S',
                }
            },
            credentials: self.linux.vfs.credentials.clone(),
            namespaces: self.linux.vfs.namespace_snapshot(),
            namespace_projection: None,
            namespace_ids: [self.tgid, pid, self.group(), self.session()]
                .map(|id| self.linux.vfs.pid_namespace().hierarchy(id)),
            command: self.linux.command_name.get(),
            cgroup: self.linux.vfs.cgroup_path(pid),
            nondumpable: self.linux.vfs.dumpable() != 1,
            seccomp: self.seccomp.mode(),
            seccomp_filters: self.seccomp.count(),
            arguments,
            arguments_bytes,
            environment: if demand.environment() && environment_bytes.is_none() {
                self.linux.environment.clone()
            } else {
                Vec::new()
            },
            environment_bytes,
            executable: self.linux.executable_file.as_ref().map_or_else(
                || self.linux.executable_path.clone(),
                |file| self.linux.vfs.executable_display(file),
            ),
            executable_file: self.linux.executable_file.as_ref().map(Arc::downgrade),
            cwd: self.linux.vfs.cwd().unwrap_or_else(|_| b"/".to_vec()),
            cwd_directory,
            root_directory,
            mapped_bytes: resident_bytes,
            virtual_bytes: self.memory.virtual_bytes(),
            maps,
            affinity: self.signals.io.scheduling.affinity(),
            processor: self.last_cpu as u32,
            nice: self.signals.io.scheduling.nice(),
            scheduler: self.signals.io.scheduling.policy(),
            user_ticks: (self.cpu_time.as_millis() / 10) as u64,
            start_ticks: (self.started.saturating_duration_since(origin).as_millis() / 10) as u64,
            terminal: self.linux.vfs.controlling_terminal().is_some(),
            terminal_number: self.linux.vfs.controlling_terminal().unwrap_or(0),
            fds: if demand.descriptors() {
                self.linux.vfs.fd_snapshot()
            } else {
                Vec::new()
            },
            auxiliary: if demand.auxiliary() {
                self.linux.auxiliary.clone()
            } else {
                Vec::new()
            },
            file_size_limits: Some(self.limits.get(1)),
            core_limits: Some(self.limits.get(4)),
            nofile_limits: Some(self.limits.get(7)),
            address_space_limit: Some(if limits.is_host_managed() {
                u64::MAX
            } else {
                limits.per_process as u64
            }),
            oom: Arc::downgrade(&self.oom),
            pending: self.signals.io.inbox.bits(),
            shared_pending: self.signals.io.process().bits(),
            blocked: self.signals.mask,
            ignored,
            caught,
        }
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use trames_execution::Registers;
    use trames_memory::PAGE_SIZE;
    use trames_vfs::{ProcRefresh, ProcSource};

    fn image(memory: &mut trames_memory::Memory, bytes: &[u8]) {
        memory.write(0x5800, bytes).unwrap();
        memory.set_image_ranges(trames_memory::ImageRanges {
            arguments: (0x5800, 0x5804),
            environment: (0x5804, 0x5808),
        });
    }
    #[test]
    fn proc_image_payloads_keep_original_environment_but_follow_current_command_line() {
        use trames_vfs::{FileCommand, FileOutcome, FileTarget, FileValue, FileWork};
        let mut kernel = super::super::tests::kernel();
        let mut first = super::super::tests::process();
        image(&mut first.memory, b"old\0A=1\0");
        kernel.install_proc_source(&first, None);
        kernel.publish_task(1, &first);
        let paths = first.linux.vfs.path_queries();
        let files = trames_vfs::DirectFiles::default();
        let env = paths
            .open_at_resolve(AT_FDCWD, b"/proc/self/environ", 0, 0, 0, &files)
            .unwrap()
            .unwrap();
        let cmd = paths
            .open_at_resolve(AT_FDCWD, b"/proc/self/cmdline", 0, 0, 0, &files)
            .unwrap()
            .unwrap();
        let target = |fd| {
            first
                .linux
                .vfs
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap()
        };
        let env_target = target(env);
        let cmd_target = target(cmd);
        let command = || FileCommand::Read {
            count: 128,
            offset: Some(0),
        };
        let bytes = |value: FileValue| match value {
            FileValue::Bytes(bytes) => bytes,
            _ => panic!("proc bytes"),
        };
        assert_eq!(
            bytes(
                env_target
                    .proc_read_local(&command(), &first.memory)
                    .unwrap()
                    .unwrap()
            ),
            b"A=1\0"
        );
        assert!(
            kernel.proc_source.as_ref().unwrap().take_reads().is_empty(),
            "same-mm reads never request activation"
        );
        let read = |target: FileTarget| FileWork::from_vfs(&first.linux.vfs, target, command());
        let work = read(env_target.clone());
        let FileOutcome::Waiting(work) = std::thread::spawn(move || work.run()).join().unwrap()
        else {
            panic!("cross-mm reader must wait before effects")
        };
        assert_eq!(first.linux.vfs.seek(env, 0, 1).unwrap(), 0);
        assert!(first.memory.activate_proc_reads());
        let FileOutcome::Complete(reply) = work.run() else {
            panic!("activated read")
        };
        assert_eq!(bytes(reply.result.unwrap()), b"A=1\0");
        first.memory.write(0x5804, b"A=9\0").unwrap();
        let mut next = super::super::tests::process();
        image(&mut next.memory, b"new\0B=2\0");
        let old = std::mem::replace(&mut first.memory, next.memory);
        kernel.publish_proc_task(1, &first);
        let read = |target| FileWork::new(&paths, target, command()).run();
        let FileOutcome::Complete(reply) = read(env_target.clone()) else {
            panic!("opened environment retains old mm")
        };
        assert_eq!(bytes(reply.result.unwrap()), b"A=9\0");
        let FileOutcome::Waiting(work) = read(cmd_target.clone()) else {
            panic!("command line requests current image")
        };
        first.memory.activate_proc_reads();
        let FileOutcome::Complete(reply) = work.run() else {
            panic!("current cmdline")
        };
        assert_eq!(bytes(reply.result.unwrap()), b"new\0");
        first.signals.io.begin_exit(1, 0);
        drop(first);
        let FileOutcome::Complete(reply) = read(cmd_target) else {
            panic!("reaped command line")
        };
        assert!(matches!(reply.result, Err(trames_vfs::Errno(3))));
        let FileOutcome::Complete(reply) = read(env_target.clone()) else {
            panic!("old live environment after target reap")
        };
        assert_eq!(bytes(reply.result.unwrap()), b"A=9\0");
        drop(old);
        let FileOutcome::Complete(reply) = read(env_target) else {
            panic!("dead old mm is EOF")
        };
        assert!(bytes(reply.result.unwrap()).is_empty());
    }

    #[test]
    fn concurrent_positioned_proc_reads_wait_only_on_their_own_page_dependencies() {
        use trames_vfs::{FileCommand, FileOutcome, FileValue, FileWork};
        let mut kernel = super::super::tests::kernel();
        let mut process = super::super::tests::process();
        process.memory.write(0x5000, b"a").unwrap();
        process.memory.write(0x6000, b"b").unwrap();
        process.memory.set_image_ranges(trames_memory::ImageRanges {
            arguments: (0x4000, 0x4001),
            environment: (0x5000, 0x7000),
        });
        kernel.install_proc_source(&process, None);
        kernel.publish_task(1, &process);
        let paths = process.linux.vfs.path_queries();
        let fd = paths
            .open_at_resolve(
                AT_FDCWD,
                b"/proc/self/environ",
                0,
                0,
                0,
                &trames_vfs::DirectFiles::default(),
            )
            .unwrap()
            .unwrap();
        let target = process
            .linux
            .vfs
            .shared_files()
            .lookup(fd)
            .unwrap()
            .unwrap()
            .file_target()
            .unwrap();
        let read = |offset| {
            FileWork::new(
                &paths,
                target.clone(),
                FileCommand::Read {
                    count: 1,
                    offset: Some(offset),
                },
            )
            .run()
        };
        let FileOutcome::Waiting(first) = read(0) else {
            panic!("first page is cold");
        };
        let FileOutcome::Waiting(second) = read(PAGE_SIZE) else {
            panic!("second page is independently cold");
        };
        assert_eq!(kernel.proc_source.as_ref().unwrap().take_reads().len(), 1);
        assert!(process.memory.activate_proc_reads());
        assert!(first.ready() && second.ready());
        process
            .memory
            .protect(0x6000, PAGE_SIZE, trames_memory::Permissions::NONE)
            .unwrap();
        assert!(
            first.ready(),
            "another pread cannot replace this operation's wait set"
        );
        assert!(kernel.proc_source.as_ref().unwrap().take_reads().is_empty());
        assert!(!second.ready());
        assert_eq!(kernel.proc_source.as_ref().unwrap().take_reads().len(), 1);
        let FileOutcome::Complete(reply) = first.run() else {
            panic!("unaffected page completes");
        };
        assert!(matches!(reply.result, Ok(FileValue::Bytes(bytes)) if bytes == b"a"));
        assert!(process.memory.activate_proc_reads());
        let FileOutcome::Complete(reply) = second.run() else {
            panic!("unreadable page is EOF");
        };
        assert!(matches!(reply.result, Ok(FileValue::Bytes(bytes)) if bytes.is_empty()));
        assert_eq!(process.linux.vfs.seek(fd, 0, 1), Ok(0));
    }
    #[test]
    fn actual_live_proc_image_svcs_pause_only_the_target_mm_and_use_no_owner_service() {
        for cpus in [1, 2, 4, 12] {
            let mut kernel = super::super::tests::kernel();
            kernel.cpu_count = cpus;
            kernel.per_cpu = vec![Duration::ZERO; cpus];
            kernel.workers = crate::workers::Pool::new(cpus);
            kernel.task_ids = Arc::new(trames_kernel::task::Ids::from_next(3));
            let mut root = super::super::tests::process();
            root.signals.io.scheduling.set_affinity((1 << cpus) - 1);
            image(&mut root.memory, b"one\0R=1\0");
            let mut peer = root.fork();
            peer.tgid = 2;
            peer.linux.vfs.set_process_context(2);
            image(&mut peer.memory, b"two\0P=2\0");
            root.memory.write(0x5000, b"/proc/self/cmdline\0").unwrap();
            root.memory.write(0x5100, b"/proc/2/environ\0").unwrap();
            let mut code = Vec::<u32>::new();
            for (path, out, result) in [(0x5000, 0x6000, 0), (0x5100, 0x6100, 8)] {
                code.extend([
                    0x92800c60, // AT_FDCWD
                    0xd2800001 | (path << 5),
                    0xd2800002,
                    0xd2800003,
                    0xd2800708,
                    0xd4000001, // openat
                    0xaa0003f3, // x19 = fd
                    0xd2800001 | (out << 5),
                    0xd2800802,
                    0xd28007e8,
                    0xd4000001, // read
                    0xd28e0004,
                    0xf9000080 | ((result / 8) << 10), // save result
                    0xaa1303e0,
                    0xd2800728,
                    0xd4000001, // close
                ]);
            }
            code.extend([0xd2800000, 0xd2800ba8, 0xd4000001]);
            root.memory
                .write(
                    0x4000,
                    &code
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            // Keep the target running while the reader requests its original mm.
            peer.memory
                .write(0x4000, &0x14000000u32.to_le_bytes())
                .unwrap();
            for p in [&mut root, &mut peer] {
                p.memory
                    .protect(0x4000, PAGE_SIZE, trames_memory::Permissions::RX)
                    .unwrap();
            }
            let observed = root.memory.share();
            kernel.install_proc_source(&root, None);
            kernel.publish_task(1, &root);
            kernel.publish_task(2, &peer);
            for pid in 3..=cpus as u32 {
                let mut other = peer.fork();
                other.tgid = pid;
                other.linux.vfs.set_process_context(pid);
                kernel.publish_task(pid, &other);
                kernel.processes.insert(pid, other);
            }
            kernel.processes.insert(1, root);
            kernel.processes.insert(2, peer);
            let mut output = trames_linux::CapturedOutput::default();
            if cpus == 1 {
                assert_eq!(kernel.drive(&mut output, 100_000_000).unwrap().code, 0);
            } else {
                assert!(kernel
                    .parallel_epoch(&mut output, 100_000_000, true)
                    .unwrap());
            }
            assert!(
                matches!(kernel.processes.read(&1).state, State::Zombie(0)),
                "root must finish at {cpus} CPUs, not exhaust the instruction budget"
            );
            assert_eq!(observed.read_u64(0x7000).unwrap(), 4, "same-mm cmdline");
            assert_eq!(observed.read_u64(0x7008).unwrap(), 4, "cross-mm environ");
            assert_eq!(observed.read_array::<4>(0x6000).unwrap(), *b"one\0");
            assert_eq!(observed.read_array::<4>(0x6100).unwrap(), *b"P=2\0");
            assert_eq!(kernel.service_requests, 0);
            for number in [56, 57, 63] {
                assert!(!kernel.cohort_return_syscalls.contains_key(&number));
            }
            assert_eq!(
                kernel.vm_checkpoint_groups,
                u64::from(cpus != 1),
                "one on-demand target activation"
            );
            assert_eq!(
                kernel.vm_checkpoint_spaces,
                u64::from(cpus != 1),
                "caller remains runnable"
            );
        }
    }

    #[test]
    fn proc_activation_waits_for_original_external_view_without_stopping_other_mms() {
        for clone_at_boundary in [false, true] {
            let mut kernel = super::super::tests::kernel();
            kernel.task_ids = Arc::new(trames_kernel::task::Ids::from_next(3));
            let mut root = super::super::tests::process();
            image(&mut root.memory, b"one\0R=1\0");
            kernel.install_proc_source(&root, None);
            let mut other = root.fork();
            other.tgid = 2;
            other.linux.vfs.set_process_context(2);
            kernel.publish_task(1, &root);
            kernel.publish_task(2, &other);
            let report = root.memory.memory_report();
            let read = report.request_read_page(0x5800).unwrap();
            let external = root
                .memory
                .parallel_view(&mut kernel.parallel_memory)
                .unwrap();
            kernel.processes.insert(1, root);
            kernel.processes.insert(2, other);
            let control = Arc::new(crate::workers::Control::new(1000));
            let epoch = crate::run_queue::Epoch::with_events(
                control.clone(),
                kernel.workers.events(),
                true,
            );
            let mut files = trames_vfs::FileEpoch::default();
            let mut rings = trames_linux::UringEpoch::default();
            let mut network = trames_vfs::NetworkEpoch::default();
            for pid in [1, 2] {
                let view = kernel
                    .processes
                    .get_mut(&pid)
                    .unwrap()
                    .memory
                    .parallel_view(&mut kernel.parallel_memory)
                    .unwrap();
                let job = kernel.capture_worker(
                    pid,
                    Box::new(view),
                    &control,
                    &mut files,
                    &mut rings,
                    &mut network,
                );
                epoch.add(job);
            }
            let mut waits = Vec::new();
            kernel
                .activate_proc_reads(Some(&epoch), vec![report], &mut waits)
                .unwrap();
            let mut checkpoint = epoch.take_checkpoint().unwrap();
            if clone_at_boundary {
                let job = &mut checkpoint.jobs[0];
                job.work.cpu.set_x(8, 220);
                for (i, value) in [17, 0, 0, 0, 0, 0].into_iter().enumerate() {
                    job.work.cpu.set_x(i, value);
                }
                job.checkpoint = Some(SliceOutcome::Syscall { instructions: 0 });
            }
            assert_eq!(checkpoint.jobs.len(), 1);
            let mut output = trames_linux::CapturedOutput::default();
            assert!(kernel
                .vm_checkpoint(&epoch, checkpoint, &mut output, &mut waits)
                .unwrap());
            if clone_at_boundary {
                assert!(waits.is_empty(), "clone resumes before the read-only scope");
                let reads = kernel.proc_source.as_ref().unwrap().take_reads();
                assert_eq!(reads.len(), 1);
                kernel
                    .activate_proc_reads(Some(&epoch), reads, &mut waits)
                    .unwrap();
                let checkpoint = epoch.take_checkpoint().unwrap();
                assert!(kernel
                    .vm_checkpoint(&epoch, checkpoint, &mut output, &mut waits)
                    .unwrap());
            }
            assert_eq!(waits.len(), 1);
            assert!(!waits[0].signal.ready());
            assert!(!read.ready());
            let foreign = epoch.take(0).unwrap();
            assert_eq!(foreign.work.pid, 2, "unrelated mm keeps its execution slot");
            epoch.park(foreign, None);
            drop(external);
            assert!(
                waits[0].signal.ready(),
                "last retained View releases the real wait"
            );
            let checkpoint = waits.pop().unwrap().checkpoint.unwrap();
            assert!(kernel
                .vm_checkpoint(&epoch, checkpoint, &mut output, &mut waits)
                .unwrap());
            assert!(waits.is_empty());
            let mut bytes = [0; 4];
            assert_eq!(read.read_chunk(0x5804, &mut bytes), Some(Ok(4)));
            assert_eq!(&bytes, b"R=1\0");
            assert_eq!(
                kernel.vm_checkpoint_spaces,
                1 + u64::from(clone_at_boundary)
            );
            epoch.stop();
            drop(epoch.drain());
            files.finish();
        }
    }

    #[test]
    fn original_proc_resources_are_observable_while_the_owner_and_private_cpu_are_occupied() {
        let mut kernel = super::super::tests::kernel();
        let mut process = super::super::tests::process();
        kernel.install_proc_source(&process, None);
        kernel.publish_task(1, &process);
        let source = kernel.proc_source.as_ref().unwrap().clone();
        process.memory.write(0x1000, &[1]).unwrap();
        process
            .linux
            .vfs
            .import_file(b"/late", b"live".to_vec())
            .unwrap();
        let fd = process.linux.vfs.open_at(AT_FDCWD, b"/late", 0, 0).unwrap();
        process.linux.vfs.seek(fd, 2, 0).unwrap();
        process.signals.io.scheduling.set_nice(9);
        process.signals.set_mask(1 << 9);
        process.limits.set(7, (16, MAX_FDS as u64));
        let mut view = process
            .memory
            .parallel_view(&mut kernel.parallel_memory)
            .unwrap();
        // SAFETY: metadata observers retain no guest bytes or execution View.
        // This is the only byte actor and owner byte access stays stopped.
        assert!(unsafe { view.try_exclusive_private() });
        let _owner_maps = kernel.proc_maps.borrow_mut();
        std::thread::spawn(move || {
            let snapshot = source.observe(trames_vfs::ProcQuery::new(
                b"/proc/1/status",
                ProcRefresh::Residency,
                &Default::default(),
                1,
            ));
            let task = &snapshot.processes[0];
            assert_eq!(task.nice, 9);
            assert_eq!(task.blocked, 1 << 9);
            assert_eq!(task.nofile_limits, Some((16, MAX_FDS as u64)));
            assert_eq!(task.mapped_bytes, PAGE_SIZE as usize);
            let snapshot = source.observe(trames_vfs::ProcQuery::new(
                b"/proc/1/fd",
                ProcRefresh::Descriptors,
                &Default::default(),
                1,
            ));
            let file = snapshot.processes[0]
                .fds
                .iter()
                .find(|entry| entry.fd == fd)
                .unwrap();
            assert_eq!(file.target, b"/late");
            assert_eq!(file.position, 2);
        })
        .join()
        .unwrap();
        drop(view);
    }

    #[test]
    fn proc_directory_keeps_original_task_identity_after_exit_and_pid_reuse() {
        let mut kernel = super::super::tests::kernel();
        let first = super::super::tests::process();
        kernel.install_proc_source(&first, None);
        kernel.publish_task(1, &first);
        let source = kernel.proc_source.as_ref().unwrap().clone();
        let retained = source.task(1).unwrap();
        let original = retained.identity();
        drop(first);
        let mut replacement = super::super::tests::process();
        replacement.signals.io_directory = source.directory.clone();
        kernel.publish_task(1, &replacement);
        assert_ne!(source.task(1).unwrap().identity(), original);
        assert!(retained.observe(ProcRefresh::Metadata, None).is_none());
        assert_eq!(
            source
                .observe(trames_vfs::ProcQuery::new(
                    b"/proc",
                    ProcRefresh::Metadata,
                    &Default::default(),
                    1
                ))
                .processes
                .len(),
            1
        );
    }

    #[test]
    fn point_proc_content_does_not_observe_unrelated_task_resources() {
        let mut kernel = super::super::tests::kernel();
        let first = super::super::tests::process();
        kernel.install_proc_source(&first, None);
        kernel.publish_task(1, &first);
        let source = kernel.proc_source.as_ref().unwrap().clone();
        let mut unrelated = super::super::tests::process();
        unrelated.tgid = 2;
        unrelated.signals.io_directory = source.directory.clone();
        kernel.publish_task(2, &unrelated);
        let (tx, rx) = std::sync::mpsc::channel();
        let remote = source.clone();
        let (result, worker) = unrelated.signals.actions.shared().with_action(10, |_| {
            let worker = std::thread::spawn(move || {
                let snapshot = remote.observe(trames_vfs::ProcQuery::new(
                    b"/proc/1/status",
                    ProcRefresh::Residency,
                    &Default::default(),
                    1,
                ));
                tx.send(
                    snapshot
                        .processes
                        .iter()
                        .map(|task| task.pid)
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            });
            (rx.recv_timeout(Duration::from_secs(5)), worker)
        });
        worker.join().unwrap();
        assert_eq!(result.unwrap(), vec![1]);
        let namespace = Default::default();
        let mut enumerate =
            trames_vfs::ProcQuery::new(b"/proc", ProcRefresh::Metadata, &namespace, 1);
        enumerate.enumerate = true;
        assert_eq!(source.observe(enumerate).processes.len(), 2);
    }

    #[test]
    fn shared_mm_layout_publication_and_residency_are_original_resources() {
        let mut kernel = super::super::tests::kernel();
        let mut first = super::super::tests::process();
        kernel.install_proc_source(&first, None);
        kernel.publish_task(1, &first);
        first.memory.write(0x1000, &[1]).unwrap();
        let memory = first.memory.share();
        let mut peer = first.fork_with_memory(memory);
        peer.tgid = 2;
        kernel.publish_task(2, &peer);
        first
            .memory
            .protect(0x2000, PAGE_SIZE, trames_memory::Permissions::RX)
            .unwrap();
        // No peer task projection is refreshed after this structural write.
        first.memory.memory_report();
        let source = kernel.proc_source.as_ref().unwrap();
        let snapshot = source.observe(trames_vfs::ProcQuery::new(
            b"/proc/2/maps",
            ProcRefresh::Mappings,
            &Default::default(),
            1,
        ));
        let task = snapshot
            .processes
            .iter()
            .find(|task| task.pid == 2)
            .unwrap();
        assert!(String::from_utf8_lossy(&task.maps).contains("000000002000-000000003000 r-xp"));
        let snapshot = source.observe(trames_vfs::ProcQuery::new(
            b"/proc/meminfo",
            ProcRefresh::Residency,
            &Default::default(),
            1,
        ));
        assert_eq!(
            snapshot.used_memory, PAGE_SIZE as usize,
            "a shared mm is counted once"
        );
    }
    #[test]
    fn accepted_proc_bodies_do_not_retarget_reused_pids_or_retain_task_files_cycles() {
        use trames_vfs::{FileCommand, FileOutcome, FileValue, FileWork};
        let mut kernel = super::super::tests::kernel();
        let mut first = super::super::tests::process();
        first.linux.command_name.set(b"proc-before");
        first.linux.auxiliary = vec![23; 32];
        kernel.install_proc_source(&first, None);
        kernel.publish_task(1, &first);
        let source = kernel.proc_source.as_ref().unwrap().clone();
        let original = Arc::downgrade(&first.signals.io);
        let paths = first.linux.vfs.path_queries();
        let files = trames_vfs::DirectFiles::default();
        let mut reads = Vec::new();
        for path in [
            b"/proc/self/comm".as_slice(),
            b"/proc/self/maps",
            b"/proc/self/auxv",
            b"/proc/version",
        ] {
            let fd = paths
                .open_at_resolve(AT_FDCWD, path, 0, 0, 0, &files)
                .unwrap()
                .unwrap();
            let target = first
                .linux
                .vfs
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap();
            reads.push(FileWork::from_vfs(
                &first.linux.vfs,
                target,
                FileCommand::Read {
                    count: 65536,
                    offset: Some(0),
                },
            ));
        }
        let before = paths
            .stat_at(AT_FDCWD, b"/proc/self/comm", false)
            .unwrap()
            .unwrap();
        let directory = paths
            .open_at_resolve(
                AT_FDCWD,
                b"/proc/self",
                trames_vfs::O_DIRECTORY,
                0,
                0,
                &files,
            )
            .unwrap()
            .unwrap();
        let entries = paths
            .getdents(directory, 65536, || Ok(()))
            .unwrap()
            .unwrap();
        assert!(entries.windows(5).any(|part| part == b"comm\0"));
        let mut replacement = super::super::tests::process();
        let directory_stat = paths.stat_fd_with_mount(directory).unwrap().unwrap();
        let cwd_link = paths
            .open_at_resolve(
                AT_FDCWD,
                b"/proc/self/cwd",
                trames_vfs::O_PATH | trames_vfs::O_NOFOLLOW,
                0,
                0,
                &files,
            )
            .unwrap()
            .unwrap();
        let cwd_stat = paths
            .stat_at(AT_FDCWD, b"/proc/self/cwd", true)
            .unwrap()
            .unwrap();
        assert_eq!(&cwd_stat[48..56], &0u64.to_le_bytes());
        assert_eq!(
            paths.readlink_at(cwd_link as i32, b""),
            Some(Ok(b"/".to_vec()))
        );
        let mut observer = first.linux.vfs.clone();
        observer.bind_signal_reader(replacement.signals.reader(observer.pid_namespace()));
        observer.chdir_fd(directory).unwrap();
        let mut cpu = first
            .memory
            .parallel_view(&mut kernel.parallel_memory)
            .unwrap();
        // SAFETY: proc metadata/body observers own no byte actor or View.
        assert!(unsafe { cpu.try_exclusive_private() });
        let live_read = {
            let fd = paths
                .open_at_resolve(AT_FDCWD, b"/proc/self/status", 0, 0, 0, &files)
                .unwrap()
                .unwrap();
            let target = first
                .linux
                .vfs
                .shared_files()
                .lookup(fd)
                .unwrap()
                .unwrap()
                .file_target()
                .unwrap();
            FileWork::from_vfs(
                &first.linux.vfs,
                target,
                FileCommand::Read {
                    count: 65536,
                    offset: None,
                },
            )
        };
        let _owner_maps = kernel.proc_maps.borrow_mut();
        let FileOutcome::Complete(reply) =
            std::thread::spawn(move || live_read.run()).join().unwrap()
        else {
            panic!("live proc read returned to owner")
        };
        let FileValue::Bytes(status) = reply.result.unwrap() else {
            panic!("status bytes")
        };
        assert!(String::from_utf8_lossy(&status).contains("Name:\tproc-before\n"));
        drop(_owner_maps);
        drop(cpu);
        first.signals.io.begin_exit(1, 0);
        assert_eq!(
            paths.stat_at(AT_FDCWD, b"/proc/self/cwd", true),
            Some(Ok(cwd_stat))
        );
        assert_eq!(
            paths.readlink_at(AT_FDCWD, b"/proc/self/cwd"),
            Some(Err(trames_vfs::Errno(2)))
        );
        assert_eq!(
            paths.readlink_at(cwd_link as i32, b""),
            Some(Err(trames_vfs::Errno(2)))
        );
        drop(first);
        assert!(
            original.upgrade().is_none(),
            "opened proc files cannot keep IoTask -> Files cycles alive"
        );
        replacement.signals.io_directory = source.directory.clone();
        replacement.linux.command_name.set(b"proc-reused");
        kernel.publish_task(1, &replacement);
        let observed_paths = observer.path_queries();
        assert_eq!(
            observed_paths.readlink_at(cwd_link as i32, b""),
            Some(Err(trames_vfs::Errno(2))),
            "saved proc symlink does not retarget a reused PID"
        );
        assert_eq!(
            observed_paths.stat_at(directory as i32, b"comm", false),
            Some(Err(trames_vfs::Errno(3)))
        );
        assert_eq!(
            observed_paths.stat_at(AT_FDCWD, b"comm", false),
            Some(Err(trames_vfs::Errno(3)))
        );
        assert_eq!(
            observed_paths.stat_fd_with_mount(directory),
            Some(Ok(directory_stat))
        );
        assert_eq!(
            observed_paths.getdents(directory, 65536, || Ok(())),
            Some(Ok(Vec::new()))
        );
        let after = paths
            .stat_at(AT_FDCWD, b"/proc/self/comm", false)
            .unwrap()
            .unwrap();
        assert_ne!(
            before[8..16],
            after[8..16],
            "PID reuse gets another proc inode"
        );
        let results = std::thread::spawn(move || {
            reads
                .into_iter()
                .map(|read| {
                    let FileOutcome::Complete(reply) = read.run() else {
                        panic!("accepted proc read returned to owner")
                    };
                    reply.result
                })
                .collect::<Vec<_>>()
        })
        .join()
        .unwrap();
        assert!(matches!(results[0], Err(trames_vfs::Errno(3))));
        assert!(matches!(results[1], Err(trames_vfs::Errno(3))));
        assert!(matches!(&results[2], Ok(FileValue::Bytes(bytes)) if bytes == &[23; 32]));
        assert!(
            matches!(&results[3], Ok(FileValue::Bytes(bytes)) if bytes.starts_with(b"Linux version"))
        );
    }

    #[test]
    fn actual_proc_metadata_and_body_svcs_finish_on_workers_in_one_cohort() {
        struct Output;
        impl GuestOutput for Output {
            fn source_console(&mut self) -> std::sync::Arc<dyn trames_vfs::ConsoleIo> {
                std::sync::Arc::new(trames_vfs::CapturedConsole::default())
            }

            fn poll_control(&mut self, _: &trames_vfs::Vfs) -> std::io::Result<bool> {
                Ok(false)
            }
            fn write(&mut self, _: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
        }
        let mut kernel = super::super::tests::kernel();
        kernel.cpu_count = 2;
        kernel.per_cpu = vec![Duration::ZERO; 2];
        kernel.workers = crate::workers::Pool::new(2);
        kernel.task_ids = Arc::new(trames_kernel::task::Ids::from_next(3));
        let mut root = super::super::tests::process();
        root.signals.io.scheduling.set_affinity(3);
        root.linux
            .vfs
            .import_file(b"/fixture", b"original executable".to_vec())
            .unwrap();
        root.linux
            .vfs
            .chmod_at(AT_FDCWD, b"/fixture", 0o755)
            .unwrap();
        root.linux.executable_file = Some(
            root.linux
                .vfs
                .executable_file_at(AT_FDCWD, b"/fixture", 0)
                .unwrap(),
        );
        root.linux.executable_path = b"/fixture".to_vec();
        root.memory.write(0x5000, b"/proc/self/exe\0").unwrap();
        root.memory.write(0x5080, b"/proc/self/status\0").unwrap();
        root.memory.write(0x5100, b"/proc/self\0").unwrap();
        let mut code = Vec::<u32>::new();
        for index in 0..32 {
            let (number, size) = if index % 2 == 0 { (79, 0) } else { (78, 256) };
            code.extend([
                0x92800c60, // movn x0, #99: AT_FDCWD
                0xd28a0001, // mov x1, #0x5000: original path
                0xaa1403e2, // mov x2, x20: this task's output buffer
                0xd2800003 | (size << 5),
                0xd2800008 | (number << 5),
                0xd4000001,                 // svc #0
                0xf9000260 | (index << 10), // str x0, [x19, #index*8]
            ]);
        }
        for round in 0..8 {
            for (operation, number) in [56, 63, 57].into_iter().enumerate() {
                match operation {
                    0 => code.extend([0x92800c60, 0xd28a1001, 0xd2800002, 0xd2800003]),
                    1 => code.extend([0xaa1503e0, 0xaa1403e1, 0xd2804002]),
                    _ => code.push(0xaa1503e0),
                }
                code.extend([0xd2800008 | (number << 5), 0xd4000001]);
                if operation == 0 {
                    code.push(0xaa0003f5);
                } // mov x21, x0: retained fd
                let result = 32 + round * 3 + operation as u32;
                code.push(0xf9000260 | (result << 10));
            }
        }
        for round in 0..4 {
            for (operation, number) in [56, 61, 57].into_iter().enumerate() {
                match operation {
                    0 => code.extend([0x92800c60, 0xd28a2001, 0xd2880002, 0xd2800003]),
                    1 => code.extend([0xaa1503e0, 0xaa1403e1, 0xd2804002]),
                    _ => code.push(0xaa1503e0),
                }
                code.extend([0xd2800008 | (number << 5), 0xd4000001]);
                if operation == 0 {
                    code.push(0xaa0003f5);
                }
                let result = 56 + round * 3 + operation as u32;
                code.push(0xf9000260 | (result << 10));
            }
        }
        // PID 1 terminates the runtime when it exits. Both test tasks publish
        // all proc results before either can do so; use the real worker futex
        // path rather than depending on incidental host scheduling fairness.
        code.extend([
            0xd2800020, 0xf90002e0, // *x23 = 1
            0xaa1703e0, 0xd2801021, 0xd2800022, 0xd2800003, 0xd2800c48, 0xd4000001, 0xaa1603e0,
            0xd2801001, 0xd2800002, 0xd2800003, 0xd2800c48, 0xd4000001,
        ]);
        code.extend([0xd2800000, 0xd2800ba8, 0xd4000001]); // exit(0)
        root.memory
            .write(
                0x4000,
                &code
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        root.memory
            .protect(0x4000, PAGE_SIZE, trames_memory::Permissions::RX)
            .unwrap();
        root.memory.write(0x7000, &[0xff; 640]).unwrap();
        root.memory.write(0x7800, &[0xff; 640]).unwrap();
        root.cpu.set_x(19, 0x7000);
        root.cpu.set_x(20, 0x6000);
        root.cpu.set_x(22, 0x7b00);
        root.cpu.set_x(23, 0x7300);
        let observed = root.memory.share();
        let memory = root.memory.share();
        let mut peer = root.fork_with_memory(memory);
        peer.tgid = 2;
        peer.linux.vfs.set_process_context(2);
        peer.cpu.set_x(19, 0x7800);
        peer.cpu.set_x(20, 0x6400);
        peer.cpu.set_x(22, 0x7300);
        peer.cpu.set_x(23, 0x7b00);
        kernel.install_proc_source(&root, None);
        kernel.publish_task(1, &root);
        kernel.publish_task(2, &peer);
        kernel.processes.insert(1, root);
        kernel.processes.insert(2, peer);
        assert!(kernel.parallel_epoch(&mut Output, 1_000_000, true).unwrap());
        assert!(
            matches!(kernel.processes.read(&1).state, State::Zombie(0)),
            "states/PC/SVC/result: {:?}; cohort returns: {:?}",
            kernel
                .processes
                .iter()
                .map(|(pid, p)| (
                    pid,
                    matches!(p.state, State::Ready),
                    p.cpu.pc(),
                    p.cpu.x(8),
                    p.cpu.x(0)
                ))
                .collect::<Vec<_>>(),
            kernel.cohort_return_syscalls
        );
        for base in [0x7000, 0x7800] {
            for index in 0..32 {
                assert_eq!(
                    observed.read_u64(base + index * 8).unwrap(),
                    if index % 2 == 0 { 0 } else { 8 },
                    "task results at {base:x}/{index}"
                );
            }
            for index in 32..68 {
                let result = observed.read_u64(base + index * 8).unwrap();
                if index % 3 == 1 {
                    // close: 34, 37, ...
                    assert_eq!(result, 0);
                } else {
                    assert!(
                        (1..=512).contains(&result),
                        "open/read at {base:x}/{index}: {result:#x}"
                    );
                }
            }
        }
        for number in [56, 57, 61, 63, 78, 79] {
            assert!(
                !kernel.cohort_return_syscalls.contains_key(&number),
                "proc syscall {number} returned the cohort"
            );
        }
        assert_eq!(kernel.service_requests, 0);
        assert!(kernel.worker_syscalls >= 136);
    }
}
