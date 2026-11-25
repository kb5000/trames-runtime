// SPDX-License-Identifier: GPL-3.0-or-later
//! One accepted signal send; partial user input never repeats an enqueue.
use super::*;
use crate::user_copy::{Copies, CopyError};
use trames_memory::PageFault;
#[cfg(test)]
#[path = "io_send_copy_tests.rs"]
mod tests;
struct Owner {
    source: Arc<IoTask>,
    routes: IoRoutes,
    files: trames_vfs::FdFlags,
}
pub struct Call {
    owner: Option<Owner>,
    number: u32,
    args: [u64; 6],
    pidfd: Option<PidSignal>,
    input: Copies,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl Call {
    pub fn new(
        source: Arc<IoTask>,
        routes: IoRoutes,
        files: trames_vfs::FdFlags,
        number: u32,
        args: [u64; 6],
    ) -> Self {
        Self {
            owner: Some(Owner {
                source,
                routes,
                files,
            }),
            number,
            args,
            pidfd: None,
            input: Default::default(),
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
        self.pidfd = None;
        self.owner = None;
        self.input = Default::default();
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
        let owner = self.owner.as_ref().unwrap();
        if self.number == 424 && self.pidfd.is_none() {
            self.pidfd = Some(
                owner
                    .routes
                    .accept_pid_signal(&owner.files, self.args)
                    .map_err(CopyError::Error)?,
            );
        }
        let (number, args) = (self.number, self.args);
        let user = self.input.run(memory, |view| {
            let address = args[if number == 240 { 3 } else { 2 }];
            if number == 424 && address == 0 {
                Ok(None)
            } else {
                let signo =
                    (number != 424).then_some(args[if number == 240 { 2 } else { 1 }] as u32);
                IoRoutes::copy_signal_info(view, address, signo).map(Some)
            }
        })?;
        if number == 424 {
            owner
                .routes
                .pid_signal_value(&owner.source, args, self.pidfd.take().unwrap(), user)
        } else {
            owner
                .routes
                .queued_value(&owner.source, number, args, user.unwrap())
        }
        .map_err(CopyError::Error)
    }
}
