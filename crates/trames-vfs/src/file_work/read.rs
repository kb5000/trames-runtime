// SPDX-License-Identifier: GPL-3.0-or-later
//! An original read owns its output and OFD position through resource waits.
use super::*;
use crate::read_reply::FileRead;

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;

pub(super) struct Cursor {
    node: NodeRef,
    position: Option<FileRead>,
    offset: u64,
    requested: usize,
    bytes: Vec<u8>,
}
impl FileTarget {
    pub(super) fn cursor_read(&self, command: &FileCommand) -> bool {
        if !matches!(command, FileCommand::Read { count, offset }
            if *count != 0 && offset.is_none_or(|offset| offset <= i64::MAX as u64))
            || !fd_can_read(self.0.open.flags.get())
            || self.daemon_backed()
            || self.0.open.proc_control()
            || self.0.open.control.is_some()
        {
            return false;
        }
        let open = OpenHandle::Shared(self.0.open.clone());
        let ordinary = Vfs::ordinary_file(&open.borrow(), false).is_some();
        ordinary
    }
}
impl Cursor {
    fn begin(target: &FileTarget, command: &FileCommand) -> Result<Self> {
        let FileCommand::Read { count, offset } = command else {
            unreachable!("retained read");
        };
        let open = OpenHandle::Shared(target.0.open.clone());
        let node = Vfs::ordinary_file(&open.borrow(), false).ok_or(Errno(9))?;
        let position = if offset.is_none() {
            Some(FileRead::begin(target.0.clone())?)
        } else {
            None
        };
        let offset = offset.unwrap_or_else(|| position.as_ref().unwrap().offset);
        Vfs::check_io_range(offset, *count as u64)?;
        Ok(Self {
            node,
            position,
            offset,
            requested: *count,
            bytes: Vec::new(),
        })
    }
}
impl FileWork {
    pub(super) fn run_read(mut self) -> FileOutcome {
        if self.read.is_none() {
            match Cursor::begin(self.target.as_ref().unwrap(), &self.command) {
                Ok(cursor) => self.read = Some(Box::new(cursor)),
                Err(Errno(11)) => return FileOutcome::Waiting(self),
                Err(error) => {
                    return FileOutcome::Complete(Self::descriptor_result(
                        Err(error),
                        &mut self.command,
                    ))
                }
            }
        }
        let cursor = self.read.as_deref_mut().unwrap();
        let scope = resource_io::Scope::enter();
        let result = {
            let node = cursor.node.borrow();
            match &node.content {
                Content::File(data) => data.read_into(
                    cursor.offset + cursor.bytes.len() as u64,
                    cursor.requested - cursor.bytes.len(),
                    &mut cursor.bytes,
                ),
                _ => Err(Errno(5)),
            }
        };
        if let Some(pending) = scope.finish() {
            self.resource_wait = Some(pending.wait);
            return FileOutcome::Waiting(self);
        }
        let result = self.finish_read(result);
        FileOutcome::Complete(Self::descriptor_result(result, &mut self.command))
    }
    /// A real error or caught signal after a prefix returns that prefix. No
    /// position is published until its actual guest copyout is known. Dropping
    /// a parked read instead releases the original FileRead without advancing.
    pub(super) fn finish_read(&mut self, terminal: Result<()>) -> Result<FileValue> {
        let Cursor {
            node,
            position,
            requested,
            bytes,
            ..
        } = *self.read.take().expect("original read cursor");
        let result = match terminal {
            Ok(()) => Ok(bytes),
            Err(_) if !bytes.is_empty() => Ok(bytes),
            Err(error) => Err(error),
        };
        let open = OpenHandle::Shared(self.target.as_ref().unwrap().0.open.clone());
        Vfs::complete_file_read(&open.borrow(), &node, &result, requested != 0);
        result.map(|bytes| match position {
            Some(position) => FileValue::Read(ReadReply::new(bytes, position)),
            None => FileValue::Bytes(bytes),
        })
    }
}
