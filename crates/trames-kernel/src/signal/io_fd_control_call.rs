// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted OFD control, with input fragments and one output snapshot.
use super::*;
use crate::user_copy::{Copies, CopyError, Output};
use trames_memory::{MemoryError, PageFault};
#[cfg(test)]
#[path = "io_fd_control_copy_tests.rs"]
mod tests;

pub struct FdControlCall {
    control: Option<Result<trames_vfs::StatusControl, Errno>>,
    routes: Option<IoRoutes>,
    domain: Option<trames_vfs::landlock::Domain>,
    number: u32,
    args: [u64; 6],
    checked: bool,
    input: Copies,
    prepared: Option<(Output, Result<u64, Errno>)>,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl FdControlCall {
    pub fn entry(number: u32, args: [u64; 6]) -> bool {
        number == 25 && matches!(args[1] as u32, 8..=11 | 15 | 16)
            || number == 29 && trames_vfs::DescriptorControl::status_ioctl_request(args[1] as u32)
    }
    pub fn new(
        source: &IoTask,
        routes: IoRoutes,
        files: &trames_vfs::FdFlags,
        number: u32,
        args: [u64; 6],
    ) -> Self {
        Self {
            control: Some(files.status_control(args[0] as u32)),
            routes: Some(routes),
            domain: Some(source.credentials().read().landlock.clone()),
            number,
            args,
            checked: false,
            input: Default::default(),
            prepared: None,
            fault: None,
            result: None,
        }
    }
    pub fn fault(&self) -> Option<PageFault> {
        self.fault.clone()
    }
    pub fn ready(&self) -> bool {
        self.fault.as_ref().is_none_or(|fault| fault.wait.ready())
    }
    pub fn cancel(&mut self) {
        let _ = self.complete(Err(Errno(4)));
    }
    fn complete(&mut self, result: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.control = None;
        self.routes = None;
        self.domain = None;
        self.input = Default::default();
        self.prepared = None;
        self.fault = None;
        self.result = Some(result);
        Some(result)
    }
    pub fn check(&mut self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        if let Some(result) = self.result {
            return Some(result);
        }
        self.fault = None;
        match self.progress(memory) {
            Ok(value) => self.complete(Ok(value)),
            Err(CopyError::Error(error)) => self.complete(Err(error)),
            Err(CopyError::Page(fault)) => {
                self.fault = Some(fault);
                None
            }
        }
    }
    fn progress(&mut self, memory: &mut impl CpuMemory) -> Result<u64, CopyError> {
        let control = self
            .control
            .as_ref()
            .unwrap()
            .as_ref()
            .map_err(|error| CopyError::Error(*error))?;
        if self.number == 29 && !self.checked {
            control
                .check_ioctl(self.args[1] as u32)
                .map_err(CopyError::Error)?;
            self.checked = true;
        }
        let routes = self.routes.as_ref().unwrap();
        let owners = routes.async_owners(self.domain.as_ref().unwrap());
        let args = self.args;
        let number = self.number;
        let output = self.number == 25 && args[1] as u32 == 16
            || self.number == 29 && matches!(args[1] as u32, 0x8903 | 0x8904);
        if !output {
            return self
                .input
                .run(memory, |view| invoke(control, number, args, view, &owners));
        }
        if self.prepared.is_none() {
            let mut output = if self.number == 29 {
                Output::scalars()
            } else {
                Output::default()
            };
            let value = invoke(control, number, args, &mut output, &owners);
            self.prepared = Some((output, value));
        }
        let (output, value) = self.prepared.as_mut().unwrap();
        match output.progress(memory) {
            Ok(()) => (*value).map_err(CopyError::Error),
            Err(MemoryError::Pending(fault)) => Err(CopyError::Page(fault)),
            Err(_) => Err(CopyError::Error(Errno(14))),
        }
    }
}
fn invoke(
    control: &trames_vfs::StatusControl,
    number: u32,
    args: [u64; 6],
    memory: &mut impl CpuMemory,
    owners: &impl AsyncOwners,
) -> Result<u64, Errno> {
    if number == 25 {
        control.fcntl(args[1] as u32, args[2], memory, owners)
    } else {
        control.ioctl_accepted(args[0] as u32, args[1] as u32, args[2], memory, owners)
    }
}
