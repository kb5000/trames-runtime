// SPDX-License-Identifier: GPL-3.0-or-later
//! The accepted result and copy cursor survive guest page waits. Retrying a
//! copy never re-runs its file operation or revisits its numeric descriptor.
use super::*;
use std::{collections::VecDeque, ops::Range};
use trames_memory::{MemoryError, PageFault, PAGE_SIZE};

struct Part {
    address: u64,
    bytes: Bytes,
    range: Range<usize>,
    copied: usize,
    scalar: bool,
}
enum Bytes {
    Owned(Vec<u8>),
    Shared(Arc<[u8]>),
    Word([u8; 8]),
}
impl Bytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Shared(bytes) => bytes,
            Self::Word(bytes) => bytes,
        }
    }
}
/// Count results allocate nothing. A scalar/stat result owns its one segment
/// inline, and an owned read Vec moves here without another Arc allocation.
enum Parts {
    Data {
        first: Option<Part>,
        rest: VecDeque<Part>,
    },
    Stat {
        address: u64,
        bytes: [u8; 128],
        copied: usize,
    },
}
impl Default for Parts {
    fn default() -> Self {
        Self::Data {
            first: None,
            rest: VecDeque::new(),
        }
    }
}
impl Parts {
    fn is_empty(&self) -> bool {
        matches!(self, Self::Data { first: None, .. })
    }
    fn push_back(&mut self, part: Part) {
        let Self::Data { first, rest } = self else {
            unreachable!("a stat output has one inline body")
        };
        if first.is_none() {
            *first = Some(part);
        } else {
            rest.push_back(part);
        }
    }
    fn front_mut(&mut self) -> Option<&mut Part> {
        match self {
            Self::Data { first, .. } => first.as_mut(),
            Self::Stat { .. } => None,
        }
    }
    fn pop_front(&mut self) {
        let Self::Data { first, rest } = self else {
            unreachable!("inline stat cursor")
        };
        *first = rest.pop_front();
    }
    fn clear(&mut self) {
        *self = Self::default();
    }
}
pub(in crate::direct) struct FileCopyout {
    parts: Parts,
    directory: Option<(u64, trames_vfs::fuse::DirectoryReply)>,
    outcome: Result<u64, Errno>,
    finished: Option<Result<u64, Errno>>,
    pub signal_owner: bool,
    waiting: Option<Arc<trames_memory::PageWait>>,
    read_position: Option<trames_vfs::ReadPosition>,
    copied: usize,
    partial_read: bool,
    continue_errors: bool,
    resources: trames_vfs::FileResources,
}
impl FileCopyout {
    pub(in crate::direct) fn append(&mut self, address: u64, bytes: Vec<u8>) {
        self.push(address, bytes);
    }
    pub(in crate::direct) fn append_scalar(&mut self, address: u64, bytes: Vec<u8>) {
        let len = bytes.len();
        self.parts.push_back(Part {
            address,
            bytes: Bytes::Owned(bytes),
            range: 0..len,
            copied: 0,
            scalar: true,
        });
    }
    pub(in crate::direct) fn continue_errors(&mut self) {
        self.continue_errors = true;
    }
    pub fn new(output: &FileOutput, result: Result<trames_vfs::FileValue, Errno>) -> Self {
        let mut copy = Self {
            parts: Parts::default(),
            directory: None,
            outcome: Ok(0),
            finished: None,
            signal_owner: false,
            waiting: None,
            read_position: None,
            copied: 0,
            partial_read: false,
            continue_errors: false,
            resources: Default::default(),
        };
        let value = match result {
            Ok(value) => value,
            Err(error) => {
                copy.outcome = Err(error);
                return copy;
            }
        };
        use trames_vfs::FileValue as Value;
        match value {
            Value::LocalConnection(_) | Value::LocalDatagram(_) => {
                unreachable!("pathname transport result is resumed before copyout")
            }
            Value::Read(reply) => {
                let (bytes, position) = reply.into_parts();
                copy = Self::new(output, Ok(Value::Bytes(bytes)));
                copy.read_position = Some(position);
            }
            Value::Count(count) => copy.outcome = Ok(count),
            Value::Transfer { count, from, to } => {
                let FileOutput::CopyOffsets {
                    from: input,
                    to: output,
                } = output
                else {
                    unreachable!("accepted copy output")
                };
                if *input != 0 {
                    copy.push_bytes(*input, Bytes::Word(from.to_le_bytes()));
                }
                if let Some(to) = to.filter(|_| *output != 0) {
                    copy.push_bytes(*output, Bytes::Word(to.to_le_bytes()));
                }
                copy.outcome = Ok(count);
            }
            Value::Directory(reply) => {
                let FileOutput::Directory(address) = output else {
                    unreachable!("accepted directory output")
                };
                copy.directory = Some((*address, reply));
            }
            Value::Bytes(mut bytes) => {
                let count = bytes.len();
                copy.partial_read =
                    matches!(output, FileOutput::Scalar(_) | FileOutput::Vectors(_));
                copy.outcome = Ok(count as u64);
                match output {
                    FileOutput::Scalar(address) => copy.push(*address, bytes),
                    FileOutput::Readlink(address, capacity) => {
                        let count = count.min(*capacity as usize);
                        bytes.truncate(count);
                        copy.push(*address, bytes);
                        copy.outcome = Ok(count as u64);
                    }
                    FileOutput::MountQuery { address, list } => {
                        copy.push(*address, bytes);
                        copy.outcome = Ok(if *list { (count / 8) as u64 } else { 0 });
                    }
                    FileOutput::Vectors(parts) => {
                        if count == 0 {
                            return copy;
                        }
                        if let [(address, length)] = parts.as_slice() {
                            bytes.truncate(*length);
                            copy.push(*address, bytes);
                            return copy;
                        }
                        let bytes: Arc<[u8]> = bytes.into();
                        let mut offset = 0;
                        for &(address, length) in parts {
                            let take = length.min(count - offset);
                            if take != 0 {
                                copy.parts.push_back(Part {
                                    address,
                                    bytes: Bytes::Shared(bytes.clone()),
                                    range: offset..offset + take,
                                    copied: 0,
                                    scalar: false,
                                });
                            }
                            offset += take;
                            if offset == count {
                                break;
                            }
                        }
                    }
                    FileOutput::Buffer {
                        address,
                        capacity,
                        query_size,
                        zero,
                    } => {
                        if !(*query_size && *capacity == 0) {
                            if *capacity < count as u64 {
                                copy.outcome = Err(Errno(34));
                                return copy;
                            }
                            copy.push(*address, bytes);
                        }
                        copy.outcome = Ok(if *zero { 0 } else { count as u64 });
                    }
                    _ => unreachable!("accepted read output"),
                }
            }
            Value::Stat(stat) => {
                let FileOutput::Stat(address) = output else {
                    unreachable!("accepted stat output")
                };
                copy.push_stat(*address, stat);
            }
            Value::FuseStat(stat, mount) => match output {
                FileOutput::Stat(address) => copy.push_stat(*address, stat),
                FileOutput::FuseStat(number, args) if *number == 291 => {
                    copy.push(args[4], Linux::statx_bytes(*args, stat, mount).to_vec());
                }
                FileOutput::FuseStat(number, args) => {
                    copy.push_stat(if *number == 80 { args[1] } else { args[2] }, stat);
                }
                _ => unreachable!("FUSE metadata output"),
            },
        }
        copy
    }
    pub fn retain(mut self, resources: trames_vfs::FileResources) -> Self {
        self.resources = resources;
        self
    }
    fn push(&mut self, address: u64, bytes: Vec<u8>) {
        self.push_bytes(address, Bytes::Owned(bytes));
    }
    fn push_stat(&mut self, address: u64, bytes: [u8; 128]) {
        self.parts = Parts::Stat {
            address,
            bytes,
            copied: 0,
        };
    }
    fn push_bytes(&mut self, address: u64, bytes: Bytes) {
        let len = bytes.as_slice().len();
        if len != 0 {
            self.parts.push_back(Part {
                address,
                bytes,
                range: 0..len,
                copied: 0,
                scalar: false,
            });
        }
    }
    fn finish(&mut self, result: Result<u64, Errno>) -> Result<Result<u64, Errno>, PageFault> {
        self.parts.clear();
        self.directory = None;
        self.read_position = None;
        self.resources = Default::default();
        self.finished = Some(result);
        Ok(result)
    }
    fn failed(&mut self, error: Errno) -> Result<Result<u64, Errno>, PageFault> {
        self.finish(self.failed_result(error))
    }
    fn failed_result(&self, error: Errno) -> Result<u64, Errno> {
        let prefix = self.directory.as_ref().map_or_else(
            || if self.partial_read { self.copied } else { 0 },
            |(_, reply)| reply.copied(),
        );
        if prefix != 0 {
            Ok(prefix as u64)
        } else {
            Err(error)
        }
    }
    pub(in crate::direct) fn faulted(&mut self) -> Result<u64, Errno> {
        self.waiting = None;
        self.failed(Errno(14))
            .expect("finishing an accepted copy cannot fault")
    }
    /// Invalidate every snapshot's cursor while returning its old resources
    /// for release outside the caller's copy mutex. Successful fragments keep
    /// their original position commit; no further guest store can be replayed.
    pub fn cancel(&mut self) -> Self {
        let result = self
            .finished
            .unwrap_or_else(|| self.failed_result(Errno(4)));
        let mut finished = Self::new(&FileOutput::None, Err(Errno(4)));
        finished.finished = Some(result);
        std::mem::replace(self, finished)
    }
    pub fn progress(
        &mut self,
        memory: &mut impl CpuMemory,
    ) -> Result<Result<u64, Errno>, PageFault> {
        if let Some(result) = self.finished {
            return Ok(result);
        }
        self.waiting = None;
        while let Parts::Stat {
            address,
            bytes,
            copied,
        } = &mut self.parts
        {
            if *copied == bytes.len() {
                return self.finish(self.outcome);
            }
            let Some(at) = address.checked_add(*copied as u64) else {
                return self.failed(Errno(14));
            };
            let count = (bytes.len() - *copied).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
            match memory.write(at, &bytes[*copied..*copied + count]) {
                Ok(()) => *copied += count,
                Err(MemoryError::Pending(fault)) => {
                    self.waiting = Some(fault.wait.clone());
                    return Err(fault);
                }
                Err(_) => return self.failed(Errno(14)),
            }
        }
        loop {
            if self.parts.is_empty() {
                if let Some((address, reply)) = &self.directory {
                    match reply.next_entry() {
                        Ok(Some(bytes)) => {
                            let Some(at) = address.checked_add(reply.copied() as u64) else {
                                return self.failed(Errno(14));
                            };
                            self.push(at, bytes);
                        }
                        Ok(None) => {
                            let count = reply.copied() as u64;
                            return self.finish(Ok(count));
                        }
                        Err(error) => return self.failed(error),
                    }
                } else {
                    return self.finish(self.outcome);
                }
            }
            let part = self.parts.front_mut().unwrap();
            let Some(at) = part.address.checked_add(part.copied as u64) else {
                if self.continue_errors {
                    self.outcome = Err(Errno(14));
                    self.parts.pop_front();
                    continue;
                }
                return self.failed(Errno(14));
            };
            let count = if part.scalar {
                part.range.len() - part.copied
            } else {
                (part.range.len() - part.copied).min((PAGE_SIZE - at % PAGE_SIZE) as usize)
            };
            let offset = part.range.start + part.copied;
            match memory.write(at, &part.bytes.as_slice()[offset..offset + count]) {
                Ok(()) => {
                    part.copied += count;
                    self.copied += count;
                    if let Some(position) = &mut self.read_position {
                        position.record(count);
                    }
                    if part.copied == part.range.len() {
                        self.parts.pop_front();
                        if let Some((_, reply)) = &mut self.directory {
                            reply.commit_entry();
                        }
                    }
                }
                Err(MemoryError::Pending(fault)) => {
                    self.waiting = Some(fault.wait.clone());
                    return Err(fault);
                }
                Err(_) => {
                    if !self.continue_errors {
                        return self.failed(Errno(14));
                    }
                    self.outcome = Err(Errno(14));
                    self.parts.pop_front();
                }
            }
        }
    }
    pub fn subscribe(&self, signal: &Arc<IoSignal>) -> Vec<IoSubscription> {
        let Some(wait) = self.waiting.as_ref() else {
            return Vec::new();
        };
        let subscription = wait.subscribe(signal);
        if wait.ready() {
            signal.notify();
        }
        subscription
    }
}
