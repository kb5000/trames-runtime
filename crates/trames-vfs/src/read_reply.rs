// SPDX-License-Identifier: GPL-3.0-or-later
//! Accepted read bytes and the original position transaction. Guest copyout
//! owns the committed prefix; numeric FD membership cannot redirect it.
use super::*;

pub(crate) trait CommitRead: Send + Sync {
    fn commit(&self, copied: usize);
}
pub(crate) struct FileRead {
    file: SharedFd,
    pub(crate) offset: u64,
}
impl FileRead {
    pub(crate) fn begin(file: SharedFd) -> Result<Self> {
        let mut position = file.open.file_position.lock().unwrap();
        Self::begin_locked(&file, &mut position)
    }
    pub(crate) fn begin_locked(
        file: &SharedFd,
        position: &mut file_data::PositionGuard<'_>,
    ) -> Result<Self> {
        if position.pending != 0 {
            return Err(Errno(11));
        }
        let offset = position.value;
        position.pending += 1;
        Ok(Self {
            file: file.clone(),
            offset,
        })
    }
}
impl CommitRead for FileRead {
    fn commit(&self, copied: usize) {
        self.file.open.file_position.lock().unwrap().value =
            self.offset.wrapping_add(copied as u64);
    }
}
impl Drop for FileRead {
    fn drop(&mut self) {
        self.file.open.file_position.lock().unwrap().pending -= 1;
        self.file.open.file_position.notify_pending();
    }
}
pub struct ReadPosition {
    resource: Box<dyn CommitRead>,
    copied: usize,
}
impl ReadPosition {
    /// Record successful copy fragments. The actual position remains protected
    /// by the original lease until this accepted result is finished or dropped.
    pub fn record(&mut self, count: usize) {
        self.copied += count;
    }
}
impl Drop for ReadPosition {
    fn drop(&mut self) {
        self.resource.commit(self.copied);
        // The original resource then releases its position gate and readiness.
    }
}
pub struct ReadReply {
    bytes: Vec<u8>,
    position: ReadPosition,
}
impl ReadReply {
    pub(crate) fn new(bytes: Vec<u8>, position: impl CommitRead + 'static) -> Self {
        Self {
            bytes,
            position: ReadPosition {
                resource: Box::new(position),
                copied: 0,
            },
        }
    }
    pub fn into_parts(self) -> (Vec<u8>, ReadPosition) {
        (self.bytes, self.position)
    }
    /// An owned-byte consumer has accepted the entire result without a guest
    /// copy that could fault. Commit once, while retaining its original lease.
    pub fn into_bytes(self) -> Vec<u8> {
        let (bytes, mut position) = self.into_parts();
        position.record(bytes.len());
        bytes
    }
}
impl FileValue {
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Self::Bytes(bytes) => Some(bytes),
            Self::Read(reply) => Some(reply.into_bytes()),
            _ => None,
        }
    }
}
