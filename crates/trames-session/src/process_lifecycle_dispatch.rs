// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold accepted operations retain their original task, operands and resources.
//! Only their affected mm takes custody; the waiting host has no dispatch role.
use super::*;
use trames_linux::{FileBoundary, IoAttempt, OutputFd};

/// A specific embedding capability absent from the source resource graph.
/// This is not an unclassified syscall/native exit or a request to try an owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Missing {
    HostStatistics,
    WaitGraph,
    ByteProvider,
    UringWaitGraph,
}

impl<C: Cpu> Lifecycle<C> {
    pub(super) fn dispatch_calls(
        &self,
        epoch: &Epoch<C>,
        checkpoint: &mut Checkpoint<C>,
        report: &mut Report,
        slot: usize,
    ) -> Result<(), RuntimeError> {
        let mut index = 0;
        while index < checkpoint.jobs.len() {
            let job = &mut checkpoint.jobs[index];
            if !job.maintenance_scope
                && (job.checkpoint_syscall().is_none()
                    || job.structural_call().is_some()
                        && job
                            .seccomp_entry
                            .as_ref()
                            .is_none_or(|entry| entry.allowed()))
            {
                index += 1;
                continue;
            }
            let original = job
                .work
                .task
                .as_ref()
                .expect("original dispatch task")
                .clone();
            let p = &mut *original.write();
            if p.signals.io.lifecycle().termination().is_some() {
                job.checkpoint = None;
                job.maintenance_scope = false;
                index += 1;
                continue;
            }
            if job.maintenance_scope {
                p.linux.progress_uring(&mut p.memory, job.work.pid);
                job.maintenance_scope = false;
                if p.linux.uring_requires_owner_for(&p.memory, job.work.pid) {
                    let job = checkpoint.jobs.swap_remove(index);
                    epoch.missing_capability(*job, Missing::UringWaitGraph);
                    continue;
                }
                if !matches!(
                    job.checkpoint,
                    Some(SliceOutcome::Syscall { .. } | SliceOutcome::NativeCall { .. })
                ) {
                    job.checkpoint = None;
                }
                if job.checkpoint_syscall().is_none() || job.structural_call().is_some() {
                    index += 1;
                    continue;
                }
            }
            let began = Instant::now();
            p.linux.vfs.sync_task_namespaces();
            p.linux.vfs.set_process_context(job.work.pid);
            p.linux.vfs.set_lock_owner(p.tgid);
            let control = p.signals.io.lifecycle().enter(&p.signals.io, job.work.pid);
            let number = job.work.cpu.x(8) as u32;
            let args = std::array::from_fn(|i| job.work.cpu.x(i));
            let result = self.dispatch_call(epoch, job, p, number, args)?;
            let elapsed = began.elapsed();
            job.stats.elapsed += elapsed;
            job.stats.cpu_times[slot] += elapsed;
            if job.work.syscalls.as_ref().is_some_and(|s| s.profile) {
                job.stats.syscall_time += elapsed;
            }
            report.time[3] += elapsed;
            p.memory.memory_report();
            control.finish(job.stop_hold());
            if let Some(cgroup) = p.signals.io.cgroup() {
                cgroup.acknowledge();
            }
            match result {
                Ok(None) => {
                    index += 1;
                }
                Ok(Some(exit)) => {
                    let mut job = checkpoint.jobs.swap_remove(index);
                    let outcome = job.checkpoint.take();
                    let done = job.finish_retired(
                        outcome,
                        epoch.progress.load(std::sync::atomic::Ordering::Relaxed),
                        exit,
                    );
                    epoch.finish_checkpoint_retired(done);
                }
                Err(missing) => {
                    let job = checkpoint.jobs.swap_remove(index);
                    epoch.missing_capability(*job, missing);
                }
            }
        }
        Ok(())
    }

    fn dispatch_call(
        &self,
        epoch: &Epoch<C>,
        job: &mut Box<Job<C>>,
        p: &mut Process<C>,
        number: u32,
        args: [u64; 6],
    ) -> Result<Result<Option<crate::worker_syscalls::Exit>, Missing>, RuntimeError> {
        if job.retry.is_none() {
            let resumed = job.seccomp_entry.is_some();
            let step = crate::syscall_dispatch::execute(
                job,
                &mut p.memory,
                Some(epoch),
                job.stats.worker,
                resumed,
                SliceOutcome::Syscall { instructions: 0 },
            );
            job.stats.syscalls += step.syscalls;
            if let Some(exit) = step.thread_exit {
                return Ok(Ok(Some(exit)));
            }
            if step.outcome.is_none()
                || step.maintenance
                || step.yielded
                || step.parked.is_some()
                || step.io.is_some()
            {
                job.checkpoint = None;
                job.seccomp_entry = None;
                job.waiting = step.parked;
                job.io = step.io;
                return Ok(Ok(None));
            }
        }
        let snapshot = job
            .work
            .syscalls
            .as_ref()
            .expect("original source resources");
        // An imported retry owns its original ABI, deadline and OFD. Never
        // rediscover an accepted descriptor from a potentially reused number.
        let retry = job.retry.take();
        let source = retry.as_ref().and_then(|call| call.retained_byte.clone());
        let socket = retry.as_ref().and_then(|call| call.retained_socket.clone());
        let attempt = if let Some(call) = retry {
            if let Some(file) = call.file_checkpoint {
                Some(self.file_boundary(epoch, job, p, file, number, args))
            } else if let Some(file) = call.file {
                Some(snapshot.direct.start_retained_file(
                    file,
                    number,
                    args,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                ))
            } else if let Some(socket) = call.retained_socket {
                Some(snapshot.direct.retry_owned_socket_vfs(
                    socket,
                    &mut p.linux.vfs,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                ))
            } else if let Some(file) = call.retained_byte {
                if file.is_unix() {
                    snapshot.direct.start_local_transfer(
                        Some(file),
                        number,
                        args,
                        &p.linux.vfs,
                        &mut p.memory,
                        job.work.pid,
                        &epoch.io_target,
                    )
                } else {
                    Some(
                        snapshot
                            .direct
                            .start_owned_byte(
                                Some(file),
                                number,
                                args,
                                &mut p.memory,
                                job.work.pid,
                                &epoch.io_target,
                            )
                            .expect("accepted original byte body"),
                    )
                }
            } else if let Some(wait) = call.retained_poll {
                Some(snapshot.direct.start_retained_poll(
                    wait,
                    args,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                    call.deadline,
                ))
            } else if let Some(aio) = call.aio {
                Some(snapshot.direct.start_retained_aio(
                    aio,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                ))
            } else if let Some(uring) = call.uring {
                Some(snapshot.direct.start_retained_uring(
                    uring,
                    args,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                ))
            } else if let Some(flock) = call.flock {
                Some(snapshot.direct.start_flock(
                    flock,
                    args,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                ))
            } else if let Some(record) = call.record {
                Some(snapshot.direct.start_record_wait(
                    record,
                    args,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                ))
            } else {
                snapshot.direct.start(
                    number,
                    args,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                    call.deadline,
                )
            }
        } else {
            snapshot
                .direct
                .start_owned_file(
                    &mut p.linux.vfs,
                    number,
                    args,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                )
                .or_else(|| {
                    snapshot.direct.start(
                        number,
                        args,
                        &mut p.memory,
                        job.work.pid,
                        &epoch.io_target,
                        None,
                    )
                })
        };
        let mut attempt = attempt;
        // A prepared body owns its exact original storage even at this cold
        // boundary. Layout work continues on the existing file pool.
        attempt = match attempt {
            Some(IoAttempt::FileCheckpoint(file)) => {
                Some(self.file_boundary(epoch, job, p, file, number, args))
            }
            other => other,
        };
        attempt = match attempt {
            Some(IoAttempt::SocketCheckpoint(call)) => {
                Some(snapshot.direct.retry_owned_socket_vfs(
                    call,
                    &mut p.linux.vfs,
                    &mut p.memory,
                    job.work.pid,
                    &epoch.io_target,
                ))
            }
            other => other,
        };
        let value = match attempt {
            Some(IoAttempt::HostError(error)) => {
                return Err(RuntimeError::Backend(error.to_string()))
            }
            Some(IoAttempt::Complete(value)) => value,
            Some(IoAttempt::Blocked(wait)) => {
                if let Some(poll) = &wait.retained_poll {
                    snapshot.begin_wait_mask(poll);
                }
                job.io = Some(wait);
                job.checkpoint = None;
                job.seccomp_entry = None;
                return Ok(Ok(None));
            }
            Some(IoAttempt::WaitCheckpoint(wait)) => {
                job.retry = Some(crate::run_queue::IoCall::from_wait(wait));
                return Ok(Err(Missing::WaitGraph));
            }
            Some(IoAttempt::ByteCheckpoint(file)) => {
                job.retry = Some(crate::run_queue::IoCall::from_byte(file, number, args));
                return Ok(Err(Missing::ByteProvider));
            }
            Some(
                IoAttempt::FileCheckpoint(_)
                | IoAttempt::SocketCheckpoint(_)
                | IoAttempt::Checkpoint,
            ) => {
                return Err(RuntimeError::Arguments(
                    "original operation did not admit its body",
                ));
            }
            None => {
                if let Some(value) = snapshot.invoke(&job.work.cpu, &mut p.memory) {
                    Ok(value)
                } else if number == 179 {
                    return Ok(Err(Missing::HostStatistics));
                } else {
                    if super::super::Kernel::<C>::has_session_syscall(number, args) {
                        return Err(RuntimeError::Arguments(
                            "session operation escaped the shared source dispatcher",
                        ));
                    }
                    let mut output = Console(std::array::from_fn(|fd| {
                        p.linux.vfs.bound_console(fd as u32)
                    }));
                    p.linux
                        .dispatch_untraced(&mut job.work.cpu, &mut p.memory, &mut output);
                    Ok(job.work.cpu.x(0))
                }
            }
        };
        let raw = value.unwrap_or_else(super::super::error);
        if (raw == super::super::error(Errno(32))
            && matches!(number, 64 | 66 | 71 | 76 | 206 | 211 | 269)
            && match number {
                206 => args[3] & 0x4000 == 0,
                211 => args[2] & 0x4000 == 0,
                269 => args[3] & 0x4000 == 0,
                _ => true,
            })
            || source.as_ref().is_some_and(|file| file.batch_pipe_signal())
            || socket.as_ref().is_some_and(|call| call.pipe_signal())
            || p.linux.take_batch_pipe_signal()
        {
            trames_vfs::TaskSignal::raise(&*snapshot.io_signals, 13);
        }
        if p.linux.take_file_size_signal() {
            trames_vfs::TaskSignal::raise(&*snapshot.io_signals, 25);
        }
        snapshot.finish_wait_mask();
        job.work.trace.finish(&mut job.work.cpu, raw);
        job.stats.syscalls += 1;
        job.checkpoint = None;
        job.seccomp_entry = None;
        Ok(Ok(None))
    }

    fn file_boundary(
        &self,
        epoch: &Epoch<C>,
        job: &Job<C>,
        p: &mut Process<C>,
        file: trames_linux::FileCheckpoint,
        number: u32,
        args: [u64; 6],
    ) -> IoAttempt {
        match file.take() {
            FileBoundary::Owner { work, output } => IoAttempt::Complete(
                output.apply(work.run_owner(&mut p.linux.vfs).result, &mut p.memory),
            ),
            FileBoundary::Signal { value } => {
                trames_vfs::TaskSignal::raise(&*p.signals.io, 25);
                IoAttempt::Complete(value)
            }
            FileBoundary::Layout { work, output } => {
                let target = work.target().cloned();
                let result = Arc::new(trames_linux::FileResult::wake_joined());
                let pending = trames_linux::FilePending::new(result.clone(), output, target);
                if self.layouts.submit(work, result).is_err() {
                    return IoAttempt::Complete(Err(Errno(5)));
                }
                job.work
                    .syscalls
                    .as_ref()
                    .unwrap()
                    .direct
                    .start_retained_file(
                        pending,
                        number,
                        args,
                        &mut p.memory,
                        job.work.pid,
                        &epoch.io_target,
                    )
            }
        }
    }
}

struct Console([Option<Arc<dyn trames_vfs::ConsoleIo>>; 3]);
impl trames_linux::execution_io::Output for Console {
    fn source_console(&mut self) -> Arc<dyn trames_vfs::ConsoleIo> {
        self.0
            .iter()
            .flatten()
            .next()
            .expect("bound original console")
            .clone()
    }
    fn write(&mut self, fd: OutputFd, bytes: &[u8]) -> std::io::Result<usize> {
        let (index, stream) = match fd {
            OutputFd::Stdout => (1, trames_vfs::ConsoleStream::Output),
            OutputFd::Stderr => (2, trames_vfs::ConsoleStream::Error),
        };
        self.0[index]
            .as_ref()
            .ok_or_else(|| std::io::Error::from_raw_os_error(9))?
            .write(stream, bytes)
            .map_err(|e| std::io::Error::from_raw_os_error(e.0 as i32))
    }
    fn poll_stdin(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let input = self.0[0]
            .as_ref()
            .ok_or_else(|| std::io::Error::from_raw_os_error(9))?
            .read(bytes.len())
            .map_err(|e| std::io::Error::from_raw_os_error(e.0 as i32))?;
        bytes[..input.len()].copy_from_slice(&input);
        Ok(input.len())
    }
    fn stdin_ready(&mut self) -> std::io::Result<bool> {
        Ok(self.0[0]
            .as_ref()
            .is_some_and(|io| io.poll(trames_vfs::ConsoleStream::Input, 1).0 != 0))
    }
}

#[cfg(all(test, trames_interpreter_conformance))]
mod tests {
    use super::*;
    use crate::process::tests::{admitted_process, kernel};
    use crate::workers::Control;
    use trames_cpu::Cpu;

    fn fixture(number: u32, args: [u64; 6]) -> Kernel<Cpu> {
        let mut k = kernel();
        let mut p = admitted_process(&k);
        p.linux
            .vfs
            .import_file(b"/file", b"original".to_vec())
            .unwrap();
        assert_eq!(p.linux.vfs.open_at(-100, b"/file", 2, 0).unwrap(), 3);
        p.linux
            .vfs
            .bind_console(trames_linux::CapturedOutput::default().source_console());
        p.cpu.set_x(8, number as u64);
        for (i, value) in args.iter().enumerate() {
            p.cpu.set_x(i, *value);
        }
        k.install_proc_source(&p, None);
        k.publish_task(1, &p);
        k.processes.insert(1, p);
        k
    }

    #[test]
    fn cold_original_memory_matches_canonical_terminal_results_across_the_full_abi() {
        let mut compared = 0;
        for args in [[u64::MAX; 6], [0; 6], [3, 0x1000, 8, 0, 0, 0]] {
            for number in 0..=512 {
                if crate::structural::Call::decode(number, args).is_some() || number == 139 {
                    continue;
                }
                let mut canonical = fixture(number, args);
                let mut p = canonical.processes.checkout(&1).unwrap();
                canonical.call(
                    1,
                    &mut p,
                    number,
                    args,
                    &mut trames_linux::CapturedOutput::default(),
                );
                if !matches!(p.state, State::Ready) {
                    continue;
                }
                let expected = p.cpu.x(0);
                let mut k = fixture(number, args);
                let lifecycle = Lifecycle::capture(&k);
                let epoch =
                    Epoch::with_events(Arc::new(Control::new(10000)), k.workers.events(), true);
                epoch.bind_session(true);
                epoch.bind_lifecycle(Lifecycle::capture(&k));
                let view = k
                    .prepare_parallel_views(&[(1, 0)])
                    .unwrap()
                    .pop()
                    .unwrap()
                    .2;
                epoch.add(k.capture_worker(
                    1,
                    view,
                    &epoch.control,
                    &mut Default::default(),
                    &mut Default::default(),
                    &mut Default::default(),
                ));
                let mut job = epoch.take(0).unwrap();
                drop(job.work.memory.take());
                let original = k.processes.handle(&1).unwrap();
                let mut p = original.write();
                p.memory.commit_parallel().unwrap();
                job.checkpoint = Some(SliceOutcome::Syscall { instructions: 0 });
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match lifecycle
                        .dispatch_call(&epoch, &mut job, &mut p, number, args)
                        .unwrap_or_else(|error| panic!("syscall={number} args={args:?}: {error}"))
                    {
                        Ok(None) => {}
                        other => panic!(
                            "syscall={number} args={args:?}: unexpected nonterminal result: {}",
                            other.is_err()
                        ),
                    }
                    let Some(wait) = job.io.take() else {
                        break;
                    };
                    while !wait.signal.ready() {
                        assert!(
                            Instant::now() < deadline,
                            "syscall={number} did not complete"
                        );
                        std::thread::yield_now();
                    }
                    job.retry = Some(crate::run_queue::IoCall::from(&wait));
                }
                assert_eq!(
                    job.work.cpu.x(0),
                    expected,
                    "syscall={number} args={args:?}"
                );
                drop(p);
                epoch.park(job, None);
                epoch.stop();
                drop(epoch.drain());
                compared += 1;
            }
        }
        assert!(
            compared > 1200,
            "only {compared} terminal ABI cases compared"
        );
    }
}
