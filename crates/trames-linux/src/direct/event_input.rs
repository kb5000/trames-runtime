// SPDX-License-Identifier: GPL-3.0-or-later
//! Poll/select input fragments and the original timeout origin survive page
//! waits. Descriptor capture starts only after the complete input is copied.
use super::*;
use crate::event_wait::{mask_descriptor, mask_value};
use crate::RetainedWait;
#[cfg(test)]
#[path = "event_input_tests.rs"]
mod tests;

#[derive(Default)]
struct Parameters {
    descriptor: Option<(u64, u64)>,
    deadline: Option<(Option<Instant>, bool)>,
    mask: Option<Option<u64>>,
}
impl Parameters {
    fn import(
        &mut self,
        memory: &impl CpuMemory,
        number: u32,
        args: [u64; 6],
        saved: Option<Instant>,
    ) -> Result<(Option<Instant>, Option<u64>, u64, bool), Errno> {
        if self.descriptor.is_none() {
            self.descriptor = Some(mask_descriptor(memory, number, args)?);
        }
        if self.deadline.is_none() {
            self.deadline = Some(RetainedWait::timeout(memory, number, args, saved)?);
        }
        if self.mask.is_none() {
            let (pointer, length) = self.descriptor.unwrap();
            self.mask = Some(mask_value(memory, pointer, length)?);
        }
        let (deadline, timeout_write) = self.deadline.unwrap();
        Ok((
            deadline,
            self.mask.unwrap(),
            RetainedWait::remaining(number, args),
            timeout_write,
        ))
    }
}
pub struct WaitInput {
    number: u32,
    args: [u64; 6],
    saved: Option<Instant>,
    bytes: file_input::Bytes,
    parameters: Parameters,
    count: Option<u32>,
    mask_lease: Option<Arc<dyn trames_vfs::TemporaryMask>>,
}
impl WaitInput {
    pub fn masked(number: u32, args: [u64; 6]) -> bool {
        match number {
            72 => args[5] != 0,
            73 => args[3] != 0,
            22 | 441 => args[4] != 0,
            _ => false,
        }
    }
    pub fn new(number: u32, args: [u64; 6], saved: Option<Instant>) -> Self {
        Self {
            number,
            args,
            saved,
            bytes: Default::default(),
            parameters: Default::default(),
            count: None,
            mask_lease: None,
        }
    }
    pub fn mask(&self) -> Option<u64> {
        self.parameters.mask.flatten()
    }
    pub fn has_native_mask(&self) -> bool {
        self.mask_lease.is_some()
    }
    fn import(
        &mut self,
        source: &DirectSyscalls,
        memory: &impl CpuMemory,
        owner: Option<&trames_vfs::Vfs>,
    ) -> (
        Option<Result<RetainedWait, Errno>>,
        Option<trames_memory::PageFault>,
    ) {
        let reader = file_input::Reader::new(memory, &self.bytes);
        let parameters = match self
            .parameters
            .import(&reader, self.number, self.args, self.saved)
        {
            Ok(parameters) => parameters,
            Err(error) => return (Some(Err(error)), reader.fault()),
        };
        if self.mask_lease.is_none() {
            if let Some(mask) = parameters.1 {
                self.mask_lease = source
                    .task_signal
                    .clone()
                    .and_then(|task| task.temporary_mask(mask));
                if self.mask_lease.is_none() {
                    return (None, reader.fault());
                }
            }
        }
        let descriptors = if let Some(owner) = owner {
            Some(owner.direct_descriptors())
        } else if source.descriptors.shared_files().is_none() {
            source
                .membership
                .as_ref()
                .map(|files| source.descriptors.with_files(files.clone()))
        } else {
            None
        };
        let descriptors = descriptors.as_ref().unwrap_or(&source.descriptors);
        let prepared = if matches!(self.number, 22 | 441) {
            epoll_buffer(&reader, self.args)
        } else if self.count.is_none() {
            let requested = self.args[if self.number == 73 { 1 } else { 0 }] as u32;
            if self.number == 72 && (requested as i32) < 0 {
                Err(Errno(22))
            } else if requested != 0 && descriptors.shared_files().is_none() && owner.is_none() {
                return (None, reader.fault());
            } else if self.number == 73 && requested > descriptors.descriptor_limit() {
                Err(Errno(22))
            } else {
                self.count = Some(if self.number == 72 {
                    descriptors.select_count(requested)
                } else {
                    requested
                });
                Ok(())
            }
        } else {
            Ok(())
        };
        let mut prepared = match prepared {
            Ok(()) => RetainedWait::prepare_parameters(
                descriptors,
                &reader,
                self.number,
                self.args,
                parameters,
                owner,
                self.count,
            ),
            Err(error) => Some(Err(error)),
        };
        let fault = reader.fault();
        if fault.is_none() {
            if let Some(Err(error)) = prepared {
                prepared = Some(Ok(RetainedWait::final_error(
                    self.number,
                    self.args,
                    parameters,
                    error,
                )));
            }
            if let Some(Ok(wait)) = &prepared {
                wait.attach_mask(self.mask_lease.take());
            }
        }
        (prepared, fault)
    }
    pub fn resume(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        memory: &mut impl CpuMemory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let (prepared, fault) = self.import(source, memory, None);
        if let Some(fault) = fault {
            let (number, args) = (self.number, self.args);
            return source.park_input(
                file_input::Accepted::WaitInput(self),
                fault,
                number,
                args,
                pid,
                target,
            );
        }
        match prepared {
            Some(Ok(wait)) => source.start_event_wait(wait, memory, pid, target),
            Some(Err(error)) => source.complete(self.number, self.args, Err(error)),
            None => IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::WaitInput(self))),
        }
    }
    pub fn resume_joined(
        mut self: Box<Self>,
        source: &DirectSyscalls,
        linux: &mut Linux,
        memory: &mut trames_memory::Memory,
        pid: u32,
        target: &Weak<dyn IoWake>,
    ) -> IoAttempt {
        let (prepared, fault) = self.import(source, memory, Some(&linux.vfs));
        if let Some(fault) = fault {
            let (number, args) = (self.number, self.args);
            return source.park_input(
                file_input::Accepted::WaitInput(self),
                fault,
                number,
                args,
                pid,
                target,
            );
        }
        match prepared {
            Some(Ok(wait)) => {
                source.start_original_poll(Arc::new(wait), linux, memory, pid, target)
            }
            Some(Err(error)) => source.complete(self.number, self.args, Err(error)),
            None => IoAttempt::FileCheckpoint(FileCheckpoint::new(FileBoundary::WaitInput(self))),
        }
    }
}
