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
}
enum Blocked {
    Fuse(Arc<fuse::File>, FileCommand),
    Position(Arc<file_data::FilePosition>),
}
impl Io {
    pub(super) fn pending(&self) -> bool {
        self.pending.is_some() && self.reply.is_none()
    }
    pub(super) fn complete(&mut self, reply: Result<FileValue>) {
        assert!(self.pending() && self.reply.is_none());
        self.reply = Some(reply);
    }
    pub(super) fn blocked(&self) -> bool {
        self.blocked.is_some()
    }
    pub(super) fn ready(&self) -> bool {
        self.blocked.as_ref().is_none_or(|blocked| match blocked {
            Blocked::Fuse(file, command) => !file.waiting_for(command),
            Blocked::Position(position) => position.lock().unwrap().pending == 0,
        })
    }
    pub(super) fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        self.blocked
            .as_ref()
            .map_or_else(Vec::new, |blocked| match blocked {
                Blocked::Fuse(file, command) => file.subscribe_operation(command, signal),
                Blocked::Position(position) => vec![position.subscribe_pending(signal)],
            })
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
        match value {
            FileValue::Bytes(bytes) => Ok(bytes),
            _ => Err(Errno(5)),
        }
    }
    pub(super) fn count(value: FileValue) -> Result<usize> {
        match value {
            FileValue::Count(count) => usize::try_from(count).map_err(|_| Errno(5)),
            _ => Err(Errno(5)),
        }
    }
}
