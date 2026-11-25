// SPDX-License-Identifier: GPL-3.0-or-later
//! Unregister resets the original TLS fields before clearing registration.
//! Its accepted scalar arguments and completed stores survive a page wait.
use super::*;
use trames_memory::{CopiedOutput, MemoryError};

pub struct Call {
    args: [u64; 6],
    accepted: bool,
    unregister: bool,
    output: CopiedOutput,
    done: bool,
}
impl Call {
    pub fn new(args: [u64; 6]) -> Self {
        Self {
            args,
            accepted: false,
            unregister: false,
            output: Default::default(),
            done: false,
        }
    }
    /// The caller retains the same original task across every progress call.
    pub fn progress(
        &mut self,
        task: &Rseq,
        memory: &mut impl CpuMemory,
    ) -> Result<(), ResumeError> {
        if self.done {
            return Ok(());
        }
        if !self.accepted {
            if let Some(registration) = task.prepare_call(self.args).map_err(ResumeError::Error)? {
                for (offset, value) in [(0, 0u32), (4, u32::MAX), (20, 0), (24, 0)] {
                    self.output
                        .push_slice(registration.address + offset, &value.to_le_bytes());
                }
                self.unregister = true;
            }
            self.accepted = true;
        }
        self.output.progress(memory).map_err(|error| match error {
            MemoryError::Pending(fault) => ResumeError::Page(fault),
            _ => ResumeError::Error(Errno(14)),
        })?;
        if self.unregister {
            task.clear();
        }
        self.done = true;
        Ok(())
    }
}
