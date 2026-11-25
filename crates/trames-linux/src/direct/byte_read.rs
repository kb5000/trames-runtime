// SPDX-License-Identifier: GPL-3.0-or-later
//! Dequeued byte/record data survives asynchronous destination faults.
use super::*;
use file::{FileCopyout, FileOutput};
use trames_memory::PageFault;

pub(super) struct Read {
    pub(super) original: RetainedByte,
    input: file_input::Bytes,
    parts: Option<Vec<(u64, usize)>>,
    count: usize,
    index: usize,
    done: usize,
    current: Option<FileCopyout>,
    expected: usize,
    requested: usize,
    pub(super) fault: Option<PageFault>,
    pub(super) deadline: Option<Instant>,
    finished: Option<Result<u64, Errno>>,
}
impl Read {
    pub(super) fn cancel(&mut self) -> Option<FileCopyout> {
        self.finished = Some(Err(Errno(4)));
        self.fault = None;
        self.current.take()
    }
    pub(super) fn new(original: RetainedByte, number: u32) -> Self {
        let deadline = original.socket_deadline(number);
        Self {
            original,
            input: Default::default(),
            parts: None,
            count: 0,
            index: 0,
            done: 0,
            current: None,
            expected: 0,
            requested: 0,
            fault: None,
            finished: None,
            deadline,
        }
    }
    pub(super) fn with_parts(
        original: RetainedByte,
        parts: Vec<(u64, usize)>,
        vectors: bool,
    ) -> Result<Self, Errno> {
        original.fd.check_read_access()?;
        let count = parts.iter().map(|p| p.1).sum();
        if original.fd.is_signalfd() && count < 128 && !(vectors && count == 0) {
            return Err(Errno(22));
        }
        let mut read = Self::new(original, 63);
        read.parts = Some(parts);
        read.count = count;
        Ok(read)
    }
    fn remaining(&self, mut skip: usize, mut count: usize) -> Vec<(u64, usize)> {
        let mut parts = Vec::new();
        for &(address, length) in self.parts.as_ref().unwrap() {
            if skip >= length {
                skip -= length;
                continue;
            }
            let n = (length - skip).min(count);
            if n != 0 {
                parts.push((address + skip as u64, n));
            }
            skip = 0;
            count -= n;
            if count == 0 {
                break;
            }
        }
        parts
    }
    fn finish(&mut self, result: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.finished = Some(result);
        Some(result)
    }
    pub(super) fn attempt(
        &mut self,
        direct: &DirectSyscalls,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        self.attempt_with(number, args, memory, |file, count| {
            direct.read_byte_owned(file, count)
        })
    }
    pub(super) fn attempt_with(
        &mut self,
        number: u32,
        args: [u64; 6],
        memory: &mut impl CpuMemory,
        mut read: impl FnMut(&RetainedByte, usize) -> Option<Result<Vec<u8>, Errno>>,
    ) -> Option<Result<u64, Errno>> {
        if let Some(result) = self.finished {
            return Some(result);
        }
        let signal = self.original.fd.is_signalfd();
        let records = !signal && byte_number(number) == 65 && self.original.fd.readv_records();
        if self.parts.is_none() {
            if let Err(error) = self.original.fd.check_read_access() {
                return self.finish(Err(error));
            }
            let reader = file_input::Reader::new(memory, &self.input);
            let parts = if byte_number(number) == 65 {
                Linux::readv_parts(&reader, args)
            } else {
                Linux::read_parameters(args, &reader).map(|count| (vec![(args[1], count)], count))
            };
            if let Some(fault) = reader.fault() {
                self.fault = Some(fault);
                return Some(Err(Errno(14)));
            }
            let (parts, count) = match parts {
                Ok(parts) => parts,
                Err(error) => return self.finish(Err(error)),
            };
            if signal && count < 128 && !(byte_number(number) == 65 && count == 0) {
                return self.finish(Err(Errno(22)));
            }
            self.count = count;
            self.parts = Some(parts);
        }
        loop {
            if let Some(copy) = &mut self.current {
                let copied = match copy.progress(memory) {
                    Err(fault) => {
                        self.fault = Some(fault);
                        return Some(Err(Errno(14)));
                    }
                    Ok(result) => result,
                };
                self.current = None;
                let count = match copied {
                    Ok(count) => count as usize,
                    Err(error) => {
                        return self.finish(if self.done != 0 && signal {
                            Ok(self.done as u64)
                        } else {
                            Err(error)
                        })
                    }
                };
                if signal && count != 128 {
                    return self.finish(if self.done != 0 {
                        Ok(self.done as u64)
                    } else {
                        Err(Errno(14))
                    });
                }
                self.done += count;
                if !signal && (!records || count < self.requested || count != self.expected) {
                    return self.finish(Ok(self.done as u64));
                }
            }
            let (requested, output) = if signal {
                if self.done + 128 > self.count {
                    return self.finish(Ok(self.done as u64));
                }
                (128, FileOutput::Vectors(self.remaining(self.done, 128)))
            } else if records {
                let parts = self.parts.as_ref().unwrap();
                while self.index < parts.len() && parts[self.index].1 == 0 {
                    self.index += 1;
                }
                if self.index == parts.len() {
                    return self.finish(Ok(self.done as u64));
                }
                let (address, count) = parts[self.index];
                self.index += 1;
                (count, FileOutput::Scalar(address))
            } else {
                (
                    self.count,
                    FileOutput::Vectors(self.parts.as_ref().unwrap().clone()),
                )
            };
            let bytes = if signal {
                self.original
                    .fd
                    .take_signal_record()
                    .map(|record| Ok((record.len(), trames_vfs::FileValue::Bytes(record.to_vec()))))
                    .unwrap_or(Err(Errno(11)))
            } else if let Some(reply) = self.original.fd.read_reply(requested) {
                reply.map(|reply| (reply.len(), trames_vfs::FileValue::Read(reply)))
            } else {
                read(&self.original, requested)?
                    .map(|bytes| (bytes.len(), trames_vfs::FileValue::Bytes(bytes)))
            };
            let bytes = match bytes {
                Ok(bytes) => bytes,
                Err(Errno(11)) if self.done == 0 => {
                    if records {
                        self.index -= 1;
                    }
                    return Some(Err(Errno(11)));
                }
                Err(error) => {
                    return self.finish(if self.done != 0 {
                        Ok(self.done as u64)
                    } else {
                        Err(error)
                    })
                }
            };
            self.expected = bytes.0;
            self.requested = requested;
            self.current = Some(FileCopyout::new(&output, Ok(bytes.1)));
        }
    }
}
impl DirectSyscalls {
    pub(in crate::direct) fn read_byte_owned(
        &self,
        file: &RetainedByte,
        count: usize,
    ) -> Option<Result<Vec<u8>, Errno>> {
        if let ByteOperation::Tcp(tcp) = &file.operation {
            return Some(if trames_vfs::fd_can_read(tcp.flags) {
                tcp.tcp.recv(count, 0).map_err(|e| Errno(e.0))
            } else {
                Err(Errno(9))
            });
        }
        if file.fd.is_pty() {
            if let Some(task) = &self.terminal_task {
                if let Some(end) = file.fd.pty_endpoint() {
                    if !end.pair.has_signal_route() {
                        end.pair.bind_signal_route(task.clone());
                    }
                }
                return Some(match file.fd.terminal_read_live(count, task.as_ref()) {
                    trames_vfs::TerminalIo::Complete(result) => result,
                    trames_vfs::TerminalIo::Stopped => {
                        self.terminal_stop.set(true);
                        Err(Errno(11))
                    }
                });
            }
            return file.fd.terminal_read(count, self.terminal);
        }
        file.fd.read_attempt(count)
    }
}
