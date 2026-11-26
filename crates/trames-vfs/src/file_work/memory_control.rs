// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained controller writes own the original OFD position, never its mutex.
use super::*;
use crate::read_reply::CommitRead;

pub(super) struct Cursor {
    request: Option<cgroup::MemoryWrite>,
    position: Option<crate::read_reply::FileRead>,
    count: usize,
}
impl Cursor {
    pub(super) fn finish(self) -> FileValue {
        if let Some(position) = &self.position {
            position.commit(self.count);
        }
        FileValue::Count(self.count as u64)
    }
}
impl FileTarget {
    pub(crate) fn memory_control(&self, command: &FileCommand) -> bool {
        matches!(
            command,
            FileCommand::Write { .. } | FileCommand::WriteSync { .. }
        ) && matches!(&self.0.open.control, Some(events::SharedControl::Cgroup(file)) if file.memory_write())
    }
}
impl FileWork {
    pub(super) fn run_memory_control(mut self) -> FileOutcome {
        if self.memory_control.is_none() {
            let target = self.target.as_ref().unwrap();
            let (bytes, offset) = match &self.command {
                FileCommand::Write { bytes, offset }
                | FileCommand::WriteSync { bytes, offset, .. } => (bytes, offset),
                _ => unreachable!(),
            };
            let flags = target.status_flags();
            let start = (|| {
                if !fd_can_write(flags) {
                    return Err(Errno(9));
                }
                let position = if offset.is_none() {
                    Some(crate::read_reply::FileRead::begin(target.0.clone())?)
                } else {
                    None
                };
                let Some(events::SharedControl::Cgroup(file)) = &target.0.open.control else {
                    unreachable!()
                };
                let request = cgroup::MemoryWrite::begin(
                    file.clone(),
                    &self.paths.view.borrow().cgroup_access(),
                    bytes,
                    flags,
                )?;
                Ok(Cursor {
                    request,
                    position,
                    count: bytes.len(),
                })
            })();
            match start {
                Ok(cursor) => self.memory_control = Some(Box::new(cursor)),
                Err(Errno(11)) => return FileOutcome::Waiting(self),
                Err(error) => {
                    return FileOutcome::Complete(Self::descriptor_result(
                        Err(error),
                        &mut self.command,
                    ))
                }
            }
        }
        let cursor = self.memory_control.as_mut().unwrap();
        let result = cursor
            .request
            .as_mut()
            .map_or(Ok(None), cgroup::MemoryWrite::step);
        match result {
            Ok(Some(wait)) => {
                self.resource_wait = Some(wait);
                FileOutcome::Waiting(self)
            }
            result => {
                let cursor = self.memory_control.take().unwrap();
                let result = result.map(|_| cursor.finish());
                FileOutcome::Complete(Self::descriptor_result(result, &mut self.command))
            }
        }
    }
}
