// SPDX-License-Identifier: GPL-3.0-or-later
//! Original file operations, owned once from issue through source-side copyout.
use super::*;
use trames_vfs::{FileCommand, FileOutcome, FileTarget, FileValue, FileWork};

pub(super) struct FileIo {
    pub(super) result: Arc<crate::FileResult>,
    pub(super) wait_revision: u64,
    dependency: Option<Box<FileDependency>>,
    parts: Vec<(u64, usize)>,
    buffer: Option<Arc<trames_memory::PinnedBuffer>>,
    address: u64,
}
enum FileDependency {
    Resource(FileWork),
    Layout {
        work: FileWork,
        ticket: Option<trames_memory::layout::LayoutWrite>,
    },
}
struct SelectionLease {
    ring: Weak<Uring>,
    identity: u64,
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
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<trames_vfs::IoSubscription> {
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
        self.dependency.is_none() && !self.result.ready()
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
                    FileValue::Bytes(bytes) => {
                        if let Some(buffer) = &self.buffer {
                            buffer
                                .range(self.address, bytes.len())
                                .and_then(|offset| buffer.write(offset, &bytes))
                                .map_err(|_| Errno(14))?;
                        } else {
                            Linux::scatter(memory, &self.parts, &bytes)?;
                        }
                        bytes.len() as u64
                    }
                    FileValue::Stat(_) | FileValue::Transfer { .. } => {
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
fn parameters(
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
                    Linux::check(
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
        return Some(match io.take_outcome(execution) {
            Some(outcome) => io.finish(outcome, request, memory, actor, execution),
            None => Err(Errno(11)),
        });
    }
    let file: FileTarget = request.file.as_ref()?.file_target()?;
    let (command, parts) = match parameters(request, memory) {
        Ok(parameters) => parameters,
        Err(e) => return Some(Err(e)),
    };
    let mut io = FileIo {
        result: Arc::default(),
        wait_revision: 0,
        dependency: None,
        parts,
        buffer: request.buffer.clone(),
        address: request.sqe.address(),
    };
    if let Some(result) = file.proc_read_local(&command, memory) {
        return Some(io.finish(
            FileOutcome::Complete(trames_vfs::FileReply {
                result,
                file_size_signal: false,
                scratch: None,
            }),
            request,
            memory,
            actor,
            execution,
        ));
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
        Some(io.finish(outcome.unwrap(), request, memory, actor, execution))
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
    if let Some(io) = &mut call.file {
        return Some(match io.take_outcome(execution) {
            Some(outcome) => io.finish(outcome, request, memory, actor, execution),
            None => Err(Errno(11)),
        });
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
            Some(result) => return Some(result.map(|fd| (fd as i32, true))),
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
    Some(result)
}
