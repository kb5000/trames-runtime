// SPDX-License-Identifier: GPL-3.0-or-later
//! Original file operations, owned once from issue through source-side copyout.
use super::*;
use crate::direct::{file::FileCopyout, FileOutput};
use trames_vfs::{FileCommand, FileOutcome, FileTarget, FileValue, FileWork};

pub(super) struct FileIo {
    pub(super) result: Arc<crate::FileResult>,
    pub(super) wait_revision: u64,
    dependency: Option<Box<FileDependency>>,
    parts: Vec<(u64, usize)>,
    buffer: Option<Arc<trames_memory::PinnedBuffer>>,
    address: u64,
    copyout: Option<FileCopyout>,
}
enum FileDependency {
    Resource(FileWork),
    Layout {
        work: FileWork,
        ticket: Option<trames_memory::layout::LayoutWrite>,
    },
}
impl Drop for FileIo {
    fn drop(&mut self) {
        // A retired ring/task must not leave a late native reply (and its OFD
        // position) owned by snapshots of this completion. The pool finishes
        // only owned host work; cancelled replies never copy into guest RAM.
        self.result.abandon(None, false);
    }
}
struct SelectionLease {
    ring: Weak<Uring>,
    identity: u64,
}
pub(super) fn retain_selection(
    actor: &UringActor,
    ring: &Uring,
    request: &mut Request,
    buffer: trames_vfs::UringProvidedBuffer,
) {
    let identity = request
        .selected_identity
        .expect("original selected-buffer identity");
    let ring = actor
        .rings
        .lock()
        .unwrap()
        .get(&(ring as *const Uring as usize))
        .expect("original source ring")
        .clone();
    request.selection = Some(trames_vfs::UringSelection {
        buffer,
        group: request.sqe.buffer_group(),
        identity,
        lease: Arc::new(SelectionLease { ring, identity }),
    });
}
impl trames_vfs::UringExecutionLease for SelectionLease {}
impl Drop for SelectionLease {
    fn drop(&mut self) {
        if let Some(ring) = self.ring.upgrade() {
            let mut state = ring.state.lock().unwrap();
            state.busy_groups.remove(&self.identity);
            let retired = state.retired_groups.remove(&self.identity);
            state.contended_groups.remove(&self.identity);
            drop(state);
            drop(retired);
            ring.readiness.notify_locked();
        }
    }
}
impl FileIo {
    pub(super) fn pending_copy(&self) -> bool {
        self.copyout.is_some()
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<trames_vfs::IoSubscription> {
        if let Some(copy) = &self.copyout {
            return copy.subscribe(signal).into_iter().collect();
        }
        match self.dependency.as_deref() {
            Some(FileDependency::Resource(work)) => {
                work.wait_sources(signal)
                    .expect("data reads subscribe to original memory resources")
                    .subscriptions
            }
            Some(FileDependency::Layout { ticket, .. }) => vec![ticket
                .as_ref()
                .expect("accepted layout")
                .layout()
                .subscribe(signal)],
            None => vec![self.result.subscribe(signal)],
        }
    }
    pub(super) fn pending_native(&self) -> bool {
        self.copyout.is_some() || self.dependency.is_none() && !self.result.ready()
    }
    fn finish_copyout(
        &mut self,
        request: &Request,
        memory: &mut impl CpuMemory,
    ) -> Result<(i32, bool)> {
        match self.copyout.as_mut().unwrap().progress(memory) {
            Ok(value) => {
                let n = value?;
                self.copyout = None;
                Ok((
                    n as i32,
                    !matches!(request.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23)
                        || n == request.requested,
                ))
            }
            Err(_) => {
                self.wait_revision = self.wait_revision.wrapping_add(1);
                Err(Errno(11))
            }
        }
    }
    fn finish_read(
        &mut self,
        value: FileValue,
        resources: trames_vfs::FileResources,
        request: &Request,
        memory: &mut impl CpuMemory,
    ) -> Result<(i32, bool)> {
        if let Some(buffer) = &self.buffer {
            let (bytes, mut position) = match value {
                FileValue::Bytes(bytes) => (bytes, None),
                FileValue::Read(reply) => {
                    let (bytes, position) = reply.into_parts();
                    (bytes, Some(position))
                }
                _ => unreachable!("accepted read bytes"),
            };
            buffer
                .range(self.address, bytes.len())
                .and_then(|offset| buffer.write(offset, &bytes))
                .map_err(|_| Errno(14))?;
            if let Some(position) = &mut position {
                position.record(bytes.len());
            }
            let n = bytes.len() as u64;
            return Ok((
                n as i32,
                !matches!(request.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23) || n == request.requested,
            ));
        }
        self.copyout = Some(
            FileCopyout::new(
                &FileOutput::Vectors(std::mem::take(&mut self.parts)),
                Ok(value),
            )
            .retain(resources),
        );
        self.finish_copyout(request, memory)
    }
    fn take_outcome(&mut self, execution: &Execution) -> Option<FileOutcome> {
        match self.dependency.as_deref_mut() {
            Some(FileDependency::Resource(work)) => {
                if !work.ready() {
                    return None;
                }
                let FileDependency::Resource(work) = *self.dependency.take().unwrap() else {
                    unreachable!();
                };
                if let Some(executor) = execution.disk.as_ref().filter(|_| work.host_work()) {
                    self.result.begin();
                    executor.submit_file(work, self.result.clone());
                    return self.result.take();
                }
                Some(work.run())
            }
            Some(FileDependency::Layout { ticket, .. }) => {
                let exclusive = match ticket.take().expect("accepted layout").try_enter() {
                    Ok(exclusive) => exclusive,
                    Err(pending) => {
                        *ticket = Some(pending);
                        return None;
                    }
                };
                self.wait_revision = self.wait_revision.wrapping_add(1);
                let FileDependency::Layout { work, .. } = *self.dependency.take().unwrap() else {
                    unreachable!();
                };
                let work = work.enter_layout(exclusive);
                if let Some(executor) = execution.disk.as_ref().filter(|_| work.host_work()) {
                    self.result.begin();
                    executor.submit_file(work, self.result.clone());
                    return self.result.take();
                }
                Some(work.run())
            }
            None => self.result.take(),
        }
    }
    fn finish(
        &mut self,
        outcome: FileOutcome,
        request: &Request,
        memory: &mut impl CpuMemory,
        actor: &UringActor,
        execution: &Execution,
    ) -> Result<(i32, bool)> {
        match outcome {
            FileOutcome::Waiting(work) => {
                self.dependency = Some(Box::new(FileDependency::Resource(work)));
                self.wait_revision = self.wait_revision.wrapping_add(1);
                Err(Errno(11))
            }
            FileOutcome::Owner(_) => unreachable!("io_uring data work has no namespace command"),
            FileOutcome::Layout(work) => {
                let fallback = match &execution.layouts {
                    Some(layouts) => layouts.submit(work, self.result.clone()),
                    None => Err(work),
                };
                let Err(work) = fallback else {
                    return Err(Errno(11));
                };
                // An embedding without a FileLayouts driver still owns its
                // accepted mutation. Wait on the original backing publication;
                // never transfer work to an unconsumed owner queue.
                let ticket = work
                    .begin_layout()
                    .expect("io_uring layout retains its inode");
                self.dependency = Some(Box::new(FileDependency::Layout {
                    work,
                    ticket: Some(ticket),
                }));
                self.wait_revision = self.wait_revision.wrapping_add(1);
                Err(Errno(11))
            }
            FileOutcome::Complete(reply) => {
                if reply.file_size_signal {
                    if let Some(task) = &execution.signal {
                        task.raise(25);
                    } else {
                        actor.file_size_signal.store(true, Ordering::Relaxed);
                    }
                }
                let n = match reply.result? {
                    FileValue::Count(n) => n,
                    value @ (FileValue::Bytes(_) | FileValue::Read(_)) => {
                        return self.finish_read(value, reply.resources, request, memory)
                    }
                    FileValue::FuseStat(..)
                    | FileValue::LocalConnection(_)
                    | FileValue::LocalDatagram(_)
                    | FileValue::Stat(_)
                    | FileValue::Transfer { .. }
                    | FileValue::Directory(_) => {
                        unreachable!("uring file operation")
                    }
                };
                Ok((
                    n as i32,
                    !matches!(request.sqe.opcode(), 1 | 2 | 4 | 5 | 22 | 23)
                        || n == request.requested,
                ))
            }
        }
    }
}
/// Socket pathname operations use the same original FileWork, native pool and
/// readiness subscriptions as ordinary file requests. No ring polling bridge
/// or service task owns their daemon wait.
pub(super) enum NamespaceReply {
    Waiting,
    Complete(Result<FileValue>),
}
pub(super) fn namespace(
    execution: &Execution,
    slot: &mut Option<FileIo>,
    work: Option<FileWork>,
) -> Option<NamespaceReply> {
    if slot.is_none() {
        let work = work?;
        let io = FileIo {
            result: Arc::default(),
            wait_revision: 0,
            dependency: None,
            parts: Vec::new(),
            buffer: None,
            address: 0,
            copyout: None,
        };
        if let Some(executor) = execution.disk.as_ref().filter(|_| work.host_work()) {
            executor.submit_file(work, io.result.clone());
        } else {
            io.result.complete(work.run());
        }
        *slot = Some(io);
    }
    let mut outcome = slot.as_mut().unwrap().take_outcome(execution);
    loop {
        match outcome {
            None => return Some(NamespaceReply::Waiting),
            Some(FileOutcome::Complete(reply)) => {
                *slot = None;
                return Some(NamespaceReply::Complete(reply.result));
            }
            Some(FileOutcome::Waiting(work)) => {
                let io = slot.as_mut().unwrap();
                io.dependency = Some(Box::new(FileDependency::Resource(work)));
                io.wait_revision = io.wait_revision.wrapping_add(1);
                return Some(NamespaceReply::Waiting);
            }
            Some(FileOutcome::Owner(work)) => {
                let mut joined = None;
                execution
                    .paths
                    .lock()
                    .unwrap()
                    .uring_original(None, |view| {
                        joined = Some(work.resume_owner(view));
                        Ok(())
                    });
                outcome = joined;
            }
            Some(FileOutcome::Layout(work)) => {
                let io = slot.as_mut().unwrap();
                if let Some(layouts) = &execution.layouts {
                    match layouts.submit(work, io.result.clone()) {
                        Ok(()) => return Some(NamespaceReply::Waiting),
                        Err(work) => {
                            let ticket = work.begin_layout().expect("accepted socket path layout");
                            io.dependency = Some(Box::new(FileDependency::Layout {
                                work,
                                ticket: Some(ticket),
                            }));
                        }
                    }
                } else {
                    let ticket = work.begin_layout().expect("accepted socket path layout");
                    io.dependency = Some(Box::new(FileDependency::Layout {
                        work,
                        ticket: Some(ticket),
                    }));
                }
                io.wait_revision = io.wait_revision.wrapping_add(1);
                return Some(NamespaceReply::Waiting);
            }
        }
    }
}
pub(super) fn parameters(
    request: &Request,
    memory: &impl CpuMemory,
) -> Result<(FileCommand, Vec<(u64, usize)>)> {
    let s = &request.sqe;
    let command = match s.opcode() {
        3 => {
            if s.op_flags() & !1 != 0 {
                return Err(Errno(22));
            }
            FileCommand::Sync {
                data_only: s.op_flags() & 1 != 0,
            }
        }
        17 => FileCommand::Allocate {
            mode: s.length() as u64,
            offset: s.offset(),
            length: s.address(),
        },
        55 => FileCommand::Truncate(s.offset()),
        _ => {
            if s.op_flags() & !8 != 0 {
                return Err(Errno(95));
            }
            let write = matches!(s.opcode(), 2 | 5 | 23);
            let parts = request.parts.clone().unwrap_or_else(|| {
                vec![(s.address(), (s.length() as usize).min(crate::MAX_WRITE))]
            });
            let count = parts.iter().map(|p| p.1).sum();
            for &(address, len) in &parts {
                if len != 0 && request.buffer.is_none() {
                    Linux::check_io_buffer(
                        memory,
                        address,
                        len,
                        if write { Access::Read } else { Access::Write },
                    )?;
                }
            }
            let offset = (s.offset() != u64::MAX).then_some(s.offset());
            let command = if write {
                let bytes = if let Some(buffer) = &request.buffer {
                    buffer
                        .read(
                            buffer.range(s.address(), count).map_err(|_| Errno(14))?,
                            count,
                        )
                        .map_err(|_| Errno(14))?
                } else {
                    let mut bytes = Vec::new();
                    Linux::gather_parts(memory, &parts, count, &mut bytes)?;
                    bytes
                };
                FileCommand::Write { bytes, offset }
            } else {
                FileCommand::Read { count, offset }
            };
            return Ok((command, parts));
        }
    };
    Ok((command, Vec::new()))
}
pub(super) fn execute(
    execution: &Execution,
    call: &mut Accepted,
    request: &mut Request,
    memory: &mut impl CpuMemory,
    actor: &UringActor,
    ring: &Uring,
) -> Option<Result<(i32, bool)>> {
    if let Some(io) = &mut call.file {
        if io.copyout.is_some() {
            return Some(io.finish_copyout(request, memory));
        }
        return Some(match io.take_outcome(execution) {
            Some(outcome) => io.finish(outcome, request, memory, actor, execution),
            None => Err(Errno(11)),
        });
    }
    let file: FileTarget = request.file.as_ref()?.file_target()?;
    let imported = if memory.async_faults_possible() {
        let input = call.input.get_or_insert_with(Default::default);
        let reader = file_input::Reader::new(memory, input);
        let result = parameters(request, &reader);
        if let Some(fault) = reader.fault() {
            call.page = Some(fault.wait);
            return Some(Err(Errno(11)));
        }
        result
    } else {
        parameters(request, memory)
    };
    let (command, parts) = match imported {
        Ok(parameters) => parameters,
        Err(e) => return Some(Err(e)),
    };
    call.input = None;
    let mut io = FileIo {
        result: Arc::default(),
        wait_revision: 0,
        dependency: None,
        parts,
        buffer: request.buffer.clone(),
        address: request.sqe.address(),
        copyout: None,
    };
    if let Some(result) = file.proc_io_local(&command, memory) {
        let result = io.finish(
            FileOutcome::Complete(trames_vfs::FileReply {
                resources: trames_vfs::FileResources::file(&file),
                result,
                file_size_signal: false,
                scratch: None,
            }),
            request,
            memory,
            actor,
            execution,
        );
        if io.copyout.is_some() {
            call.file = Some(io);
        }
        return Some(result);
    }
    let native = file.host_work(&command);
    if request.nowait() && native {
        return Some(Err(Errno(11)));
    }
    let queued = native && execution.disk.is_some();
    if queued && request.sqe.flags() & 32 != 0 && request.selection.is_none() {
        let group = request.sqe.buffer_group();
        let identity = request
            .selected_identity
            .expect("accepted provided-buffer identity");
        let ring = actor
            .rings
            .lock()
            .unwrap()
            .get(&(ring as *const Uring as usize))
            .expect("accepted source ring")
            .clone();
        request.selection = Some(trames_vfs::UringSelection {
            buffer: trames_vfs::UringProvidedBuffer {
                address: request.sqe.address(),
                length: request.sqe.length(),
                id: 0,
            },
            group,
            identity,
            lease: Arc::new(SelectionLease { ring, identity }),
        });
    }
    let outcome = {
        let paths = execution.paths.lock().unwrap();
        if queued {
            let work = FileWork::new(&paths, file, command);
            execution
                .disk
                .as_ref()
                .unwrap()
                .submit_file(work, io.result.clone());
            None
        } else {
            Some(FileWork::run_inline(&paths, file, command))
        }
    };
    if request.nowait()
        && matches!(
            outcome,
            Some(FileOutcome::Layout(_) | FileOutcome::Waiting(_))
        )
    {
        return Some(Err(Errno(11)));
    }
    if queued
        || matches!(
            outcome,
            Some(FileOutcome::Layout(_) | FileOutcome::Waiting(_))
        )
    {
        let result = match outcome {
            Some(outcome) => io.finish(outcome, request, memory, actor, execution),
            None => Err(Errno(11)),
        };
        call.file = Some(io);
        Some(result)
    } else {
        let result = io.finish(outcome.unwrap(), request, memory, actor, execution);
        if io.copyout.is_some() {
            call.file = Some(io);
        }
        Some(result)
    }
}

#[allow(clippy::too_many_arguments)] // Imported openat operands and original source context.
pub(super) fn open(
    execution: &Execution,
    call: &mut Accepted,
    request: &mut Request,
    memory: &mut impl CpuMemory,
    actor: &UringActor,
    flags: u32,
    mode: u32,
    policy: u64,
) -> Option<Result<(i32, bool)>> {
    if let Some(open) = &mut call.fifo_open {
        return Some(
            open.finish()
                .map_or(Err(Errno(11)), |result| result.map(|fd| (fd as i32, true))),
        );
    }
    if let Some(io) = &mut call.file {
        let result = match io.take_outcome(execution) {
            Some(outcome) => io.finish(outcome, request, memory, actor, execution),
            None => Err(Errno(11)),
        };
        return Some(finish_open(execution, call, result));
    }
    let work = {
        let paths = execution.paths.lock().unwrap();
        match paths.uring_open(
            request.file.as_ref(),
            request.sqe.fd(),
            request.path.as_deref()?,
            flags,
            mode,
            policy,
            &execution.files,
        ) {
            Some(Ok(fd)) => {
                if let Some(mut open) = paths.pending_fifo_open(fd) {
                    if let Some(result) = open.finish() {
                        return Some(result.map(|fd| (fd as i32, true)));
                    }
                    call.fifo_open = Some(open);
                    return Some(Err(Errno(11)));
                }
                return Some(Ok((fd as i32, true)));
            }
            Some(Err(error)) => return Some(Err(error)),
            None => paths.take_open_work()?,
        }
    };
    let mut io = FileIo {
        result: Arc::default(),
        wait_revision: 0,
        dependency: None,
        parts: Vec::new(),
        buffer: None,
        address: 0,
        copyout: None,
    };
    if let Some(executor) = execution.disk.as_ref().filter(|_| work.host_work()) {
        executor.submit_file(work, io.result.clone());
        call.file = Some(io);
        return Some(Err(Errno(11)));
    }
    let outcome = work.run();
    let layout = matches!(outcome, FileOutcome::Layout(_));
    let result = io.finish(outcome, request, memory, actor, execution);
    if layout {
        call.file = Some(io);
    }
    Some(finish_open(execution, call, result))
}

fn finish_open(
    execution: &Execution,
    call: &mut Accepted,
    result: Result<(i32, bool)>,
) -> Result<(i32, bool)> {
    let (fd, complete) = result?;
    if let Some(mut open) = execution.paths.lock().unwrap().pending_fifo_open(fd as u32) {
        if let Some(result) = open.finish() {
            return result.map(|fd| (fd as i32, complete));
        }
        call.fifo_open = Some(open);
        return Err(Errno(11));
    }
    Ok((fd, complete))
}
