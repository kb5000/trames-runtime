// SPDX-License-Identifier: GPL-3.0-or-later
//! Intermediate daemon replies belong to an accepted transfer, not its syscall
//! output. The enclosing FileWork owns request cancellation and layout admission.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    SourceStat,
    TargetStat,
    Read,
    Write,
}
#[derive(Default)]
pub(super) struct Io {
    pending: Option<Step>,
    reply: Option<Result<FileValue>>,
    blocked: Option<Blocked>,
    child: Option<Box<Child>>,
    offered: usize,
    write_offered: Option<Arc<std::sync::atomic::AtomicUsize>>,
    write_end: Option<Arc<std::sync::atomic::AtomicU64>>,
}
struct Child {
    step: Step,
    outcome: FileOutcome,
}
/// A transfer publishes its local offset without holding an OFD position lease.
pub(super) struct Position {
    file: SharedFd,
    pub offset: u64,
    end: std::cell::Cell<Option<u64>>,
}
impl Position {
    pub(super) fn capture(file: SharedFd, offset: Option<u64>) -> Self {
        let offset = offset.unwrap_or_else(|| file.open.file_position.snapshot());
        Self {
            file,
            offset,
            end: std::cell::Cell::new(None),
        }
    }
    pub(super) fn record(&self, end: u64) {
        if !self.try_record(end) {
            self.end.set(Some(end));
        }
    }
    pub(super) fn try_record(&self, end: u64) -> bool {
        let mut position = self.file.open.file_position.lock().unwrap();
        if position.pending != 0 {
            return false;
        }
        position.value = end;
        self.end.set(None);
        true
    }
    pub(super) fn position(&self) -> Arc<file_data::FilePosition> {
        self.file.open.file_position.clone()
    }
}
impl Drop for Position {
    fn drop(&mut self) {
        if let Some(end) = self.end.get() {
            self.file.open.file_position.lock().unwrap().value = end;
        }
    }
}
enum Blocked {
    Fuse(Arc<fuse::File>, FileCommand),
    Position(Arc<file_data::FilePosition>),
}
impl Io {
    pub(super) fn resource_pending(&self) -> bool {
        self.child
            .as_ref()
            .is_some_and(|child| match &child.outcome {
                FileOutcome::Waiting(work) => work.resource_pending(),
                _ => false,
            })
    }
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some() && self.reply.is_none()
    }
    pub(super) fn complete(&mut self, reply: Result<FileValue>) {
        assert!(self.pending() && self.reply.is_none());
        self.reply = Some(reply);
    }
    pub(super) fn blocked(&self) -> bool {
        self.blocked.is_some()
            || self
                .child
                .as_ref()
                .is_some_and(|child| matches!(child.outcome, FileOutcome::Waiting(_)))
    }
    pub(super) fn ready(&self) -> bool {
        if let Some(child) = &self.child {
            return match &child.outcome {
                FileOutcome::Waiting(work) => work.ready(),
                _ => true,
            };
        }
        self.blocked.as_ref().is_none_or(|blocked| match blocked {
            Blocked::Fuse(file, command) => !file.waiting_for(command),
            Blocked::Position(position) => position.lock().unwrap().pending == 0,
        })
    }
    pub(super) fn wait_sources(&self, signal: &Arc<IoSignal>) -> std::io::Result<TransferWait> {
        if let Some(child) = &self.child {
            return match &child.outcome {
                FileOutcome::Waiting(work) => work.wait_sources(signal),
                _ => Ok(TransferWait {
                    subscriptions: vec![],
                    native: vec![],
                    deadline: None,
                }),
            };
        }
        let subscriptions = self
            .blocked
            .as_ref()
            .map_or_else(Vec::new, |blocked| match blocked {
                Blocked::Fuse(file, command) => file.subscribe_operation(command, signal),
                Blocked::Position(position) => vec![position.subscribe_pending(signal)],
            });
        Ok(TransferWait {
            subscriptions,
            native: vec![],
            deadline: None,
        })
    }
    pub(super) fn retained(&self) -> bool {
        self.child.is_some()
    }
    pub(super) fn owner(&self) -> bool {
        self.child
            .as_ref()
            .is_some_and(|child| matches!(child.outcome, FileOutcome::Owner(_)))
    }
    pub(super) fn layout(&self) -> Option<Arc<trames_memory::layout::Layout>> {
        match &self.child.as_ref()?.outcome {
            FileOutcome::Layout(work) => work.admission_layout(),
            _ => None,
        }
    }
    pub(super) fn layout_domains(&self) -> Vec<u64> {
        self.child
            .as_ref()
            .map_or_else(Vec::new, |child| match &child.outcome {
                FileOutcome::Waiting(work)
                | FileOutcome::Layout(work)
                | FileOutcome::Owner(work) => work.layout_domains(),
                FileOutcome::Complete(_) => Vec::new(),
            })
    }
    pub(super) fn host_work(&self) -> bool {
        self.child
            .as_ref()
            .is_some_and(|child| match &child.outcome {
                FileOutcome::Waiting(work) => work.host_work(),
                _ => false,
            })
    }
    pub(super) fn fuse_signal_request(&self) -> Option<Arc<fuse::Request>> {
        match &self.child.as_ref()?.outcome {
            FileOutcome::Waiting(work) | FileOutcome::Layout(work) | FileOutcome::Owner(work) => {
                work.fuse_signal_request()
            }
            _ => None,
        }
    }
    pub(super) fn fuse_interrupt_needed(&self) -> bool {
        self.child
            .as_ref()
            .is_some_and(|child| match &child.outcome {
                FileOutcome::Waiting(work)
                | FileOutcome::Layout(work)
                | FileOutcome::Owner(work) => work.fuse_interrupt_needed(),
                _ => false,
            })
    }
    pub(super) fn cancelled_write_progress(&self) -> usize {
        self.child.as_ref().map_or(0, |child| {
            if child.step != Step::Write {
                return 0;
            }
            match &child.outcome {
                FileOutcome::Waiting(work)
                | FileOutcome::Layout(work)
                | FileOutcome::Owner(work) => work.cancelled_write_progress(),
                FileOutcome::Complete(reply) => match &reply.result {
                    Ok(FileValue::Count(count)) => *count as usize,
                    _ => 0,
                },
            }
        })
    }
    pub(super) fn resume_owner(&mut self, vfs: &mut Vfs) {
        if let Some(child) = self.child.take() {
            let Child { step, outcome } = *child;
            let outcome = match outcome {
                FileOutcome::Owner(work) => work.resume_owner(vfs),
                other => other,
            };
            self.child = Some(Box::new(Child { step, outcome }));
        }
    }
    fn run_child(
        &mut self,
        v: &mut Vfs,
        work: Option<FileWork>,
        step: Step,
        bytes: Option<&mut Vec<u8>>,
    ) -> Result<FileValue> {
        self.blocked = None;
        let outcome = if let Some(child) = self.child.take() {
            assert!(child.step == step, "original intermediate file operation");
            child.outcome
        } else {
            FileOutcome::Waiting(work.expect("accepted intermediate file work"))
        };
        let exclusive = v
            .query
            .as_ref()
            .is_none_or(|query| query.file_layout_exclusive);
        let outcome = match outcome {
            FileOutcome::Waiting(work) => {
                if exclusive {
                    work.exclusive().run()
                } else {
                    work.run()
                }
            }
            FileOutcome::Layout(work) if exclusive => work.exclusive().run(),
            other => other,
        };
        if let FileOutcome::Complete(mut reply) = outcome {
            if let (Some(bytes), Some(scratch)) = (bytes, reply.scratch.take()) {
                *bytes = scratch;
            }
            if reply.file_size_signal {
                v.file_size_signal.set(true);
            }
            return reply.result;
        }
        self.child = Some(Box::new(Child { step, outcome }));
        v.query.as_ref().ok_or(Errno(95))?.defer()
    }
    /// Transfer ownership once. The parent keeps an empty Vec while this
    /// request owns its original buffer, then receives the same scratch back.
    pub(super) fn write(
        &mut self,
        descriptor: &Descriptor,
        v: &mut Vfs,
        bytes: &mut Vec<u8>,
        offset: Option<u64>,
        tail: Option<(u64, usize)>,
    ) -> Result<usize> {
        let work = if self.child.is_none() {
            let original = FileTarget(SharedFd::new(descriptor.open.borrow().shared.clone()));
            self.offered = bytes.len();
            self.write_offered =
                tail.map(|_| Arc::new(std::sync::atomic::AtomicUsize::new(bytes.len())));
            let end = Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
            self.write_end = Some(end.clone());
            let mut work = FileWork::from_vfs(
                v,
                original,
                FileCommand::Write {
                    bytes: std::mem::take(bytes),
                    offset,
                },
            )
            .report_write_end(end);
            if let Some((from, count)) = tail {
                work = work.copy_tail(from, count, self.write_offered.as_ref().unwrap().clone());
            }
            Some(work)
        } else {
            None
        };
        let result = self
            .run_child(v, work, Step::Write, Some(bytes))
            .and_then(Self::count);
        if let Some(offered) = &self.write_offered {
            self.offered = offered.load(Ordering::Relaxed);
        }
        if let (Ok(count), Some(end)) = (&result, &self.write_end) {
            if end.load(Ordering::Relaxed) == u64::MAX {
                end.store(offset.unwrap_or(0) + *count as u64, Ordering::Relaxed);
            }
        }
        result
    }
    pub(super) fn offered(&self) -> usize {
        self.offered
    }
    pub(super) fn write_end(&self) -> Option<u64> {
        self.write_end
            .as_ref()
            .map(|end| end.load(Ordering::Relaxed))
            .filter(|end| *end != u64::MAX)
    }
    fn defer<T>(&mut self, v: &Vfs, pending: Option<fuse::Metadata>, step: Step) -> Result<T> {
        let query = v.query.as_ref().ok_or(Errno(95))?;
        if let Some(pending) = pending {
            self.pending = Some(step);
            query.prepared.borrow_mut().fuse = Some(Box::new(pending));
        }
        query.defer()
    }
    pub(super) fn call(
        &mut self,
        descriptor: &Descriptor,
        v: &mut Vfs,
        command: FileCommand,
        step: Step,
    ) -> Result<FileValue> {
        if self.child.is_some() {
            return self.run_child(v, None, step, None);
        }
        if let Some(reply) = self.reply.take() {
            assert!(self.pending.take() == Some(step), "original transfer step");
            return reply;
        }
        self.blocked = None;
        let open = descriptor.open.borrow().shared.clone();
        let original = SharedFd::new(open.clone());
        if let Some(events::SharedControl::FuseFile(file)) = &open.control {
            match file.operation(v, &command, &original)? {
                Some(pending) => return self.defer(v, Some(pending), step),
                None => {
                    self.blocked = Some(Blocked::Fuse(file.clone(), command));
                    return self.defer(v, None, step);
                }
            }
        }
        if let (Some(events::SharedControl::Fuse(device)), FileCommand::Write { bytes, .. }) =
            (&open.control, &command)
        {
            if !fd_can_write(open.flags.get()) {
                return Err(Errno(9));
            }
            if let Some(pending) = device.notification(v, bytes)? {
                return self.defer(v, Some(pending), step);
            }
        }
        let target = FileTarget(original);
        if target.regular_file()
            && !target.daemon_backed()
            && matches!(command, FileCommand::Read { .. })
        {
            return self.run_child(v, Some(FileWork::from_vfs(v, target, command)), step, None);
        }
        match command {
            FileCommand::Stat => v.stat_open(&descriptor.open.borrow()).map(FileValue::Stat),
            FileCommand::Read {
                count,
                offset: Some(offset),
            } => v
                .pread_description(descriptor, count, offset)
                .map(FileValue::Bytes),
            FileCommand::Read {
                count,
                offset: None,
            } => v.read_description(descriptor, count).map(FileValue::Bytes),
            FileCommand::Write {
                bytes,
                offset: Some(offset),
            } => v
                .file_write_description(descriptor, &bytes, Some(offset))
                .map(|n| FileValue::Count(n as u64)),
            FileCommand::Write {
                bytes,
                offset: None,
            } => v
                .write_description(descriptor, &bytes)
                .map(|n| FileValue::Count(n as u64)),
            _ => unreachable!("typed intermediate transfer operation"),
        }
    }
    pub(super) fn seek(
        &mut self,
        v: &Vfs,
        descriptor: &Descriptor,
        offset: i64,
        whence: u32,
    ) -> Result<u64> {
        let open = descriptor.open.borrow();
        if let Some(events::SharedControl::FuseFile(file)) = &open.control {
            match file.seek(&open.file_position, offset, whence)? {
                Some(value) => {
                    self.blocked = None;
                    Ok(value)
                }
                None => {
                    self.blocked = Some(Blocked::Fuse(
                        file.clone(),
                        FileCommand::Seek { offset, whence },
                    ));
                    self.defer(v, None, Step::Read)
                }
            }
        } else {
            match Vfs::seek_description(descriptor, offset, whence) {
                Err(Errno(11)) => self.wait_position(v, open.file_position.clone()),
                result => {
                    self.blocked = None;
                    result
                }
            }
        }
    }
    pub(super) fn wait_position<T>(
        &mut self,
        v: &Vfs,
        position: Arc<file_data::FilePosition>,
    ) -> Result<T> {
        self.blocked = Some(Blocked::Position(position));
        v.query.as_ref().ok_or(Errno(11))?.defer()
    }
    pub(super) fn regular(file: &SharedFd) -> bool {
        file.open.is_regular_file()
            || matches!(&file.open.control, Some(events::SharedControl::FuseFile(file)) if file.regular())
    }
    pub(super) fn stat(value: FileValue) -> Result<[u8; 128]> {
        match value {
            FileValue::Stat(stat) | FileValue::FuseStat(stat, _) => Ok(stat),
            _ => Err(Errno(5)),
        }
    }
    pub(super) fn bytes(value: FileValue) -> Result<Vec<u8>> {
        value.into_bytes().ok_or(Errno(5))
    }
    pub(super) fn count(value: FileValue) -> Result<usize> {
        match value {
            FileValue::Count(count) => usize::try_from(count).map_err(|_| Errno(5)),
            _ => Err(Errno(5)),
        }
    }
}
