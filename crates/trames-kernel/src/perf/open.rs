// SPDX-License-Identifier: GPL-3.0-or-later
//! An event is created only after the original attr and unknown tail finish.
use super::*;
use crate::user_copy::{Copies, CopyError};
use std::sync::Arc;
use trames_memory::{CopiedOutput, MemoryError, PageFault};
#[cfg(test)]
mod tests;
struct Owner {
    caller: Arc<IoTask>,
    routes: IoRoutes,
    files: FdFlags,
    factory: DescriptorFactory,
}
pub struct OpenCall {
    owner: Option<Owner>,
    args: [u64; 6],
    cpus: usize,
    input: Copies,
    output: CopiedOutput,
    size_error: bool,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl OpenCall {
    pub fn new(
        caller: Arc<IoTask>,
        routes: IoRoutes,
        files: FdFlags,
        factory: DescriptorFactory,
        args: [u64; 6],
        cpus: usize,
    ) -> Self {
        Self {
            owner: Some(Owner {
                caller,
                routes,
                files,
                factory,
            }),
            args,
            cpus,
            input: Default::default(),
            output: Default::default(),
            size_error: false,
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
        self.owner = None;
        self.input = Default::default();
        self.output = Default::default();
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
        if !self.size_error {
            if self.args[4] & !15 != 0 {
                return Err(CopyError::Error(Errno(22)));
            }
            let attr = self
                .input
                .run(memory, |view| Attr::import(view, self.args[0]))?;
            match attr {
                trames_vfs::perf::AttrInput::Value(attr) => {
                    let owner = self.owner.as_ref().unwrap();
                    return owner
                        .routes
                        .perf_open_attr(
                            &owner.caller,
                            &owner.files,
                            &owner.factory,
                            self.args,
                            self.cpus,
                            attr,
                        )
                        .map_err(CopyError::Error);
                }
                trames_vfs::perf::AttrInput::SizeError => {
                    let address = self.args[0]
                        .checked_add(4)
                        .ok_or(CopyError::Error(Errno(14)))?;
                    self.output.push_scalar(address, &136u32.to_le_bytes());
                    self.size_error = true;
                    self.input = Default::default();
                }
            }
        }
        // perf_copy_attr returns E2BIG even when its best-effort size store
        // fails. A genuine temporary page wait still resumes that one store.
        if let Err(MemoryError::Pending(fault)) = self.output.progress(memory) {
            return Err(CopyError::Page(fault));
        }
        Err(CopyError::Error(Errno(7)))
    }
}
