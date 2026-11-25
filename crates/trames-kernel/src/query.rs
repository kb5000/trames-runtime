// SPDX-License-Identifier: GPL-3.0-or-later
//! Original metadata snapshots; only their user copies can wait or resume.
use crate::{
    children::Children,
    signal::{IoRoutes, IoTask},
    usage,
};
use std::time::Instant;
use trames_memory::{CopiedOutput, CpuMemory, MemoryError, PageFault};
use trames_vfs::Errno;
#[cfg(test)]
mod tests;
pub fn entry(number: u32) -> bool {
    matches!(number, 100 | 153 | 165)
}
pub struct Call {
    output: CopiedOutput,
    times: Option<Instant>,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl Call {
    pub fn new(
        number: u32,
        args: [u64; 6],
        started: Instant,
        task: &IoTask,
        children: &Children,
        routes: &IoRoutes,
    ) -> Result<Self, Errno> {
        let mut output = CopiedOutput::default();
        match number {
            100 => {
                let head = routes.robust_head(task, args[0] as u32)?;
                output.push_scalar(args[2], &24u64.to_le_bytes());
                output.push_scalar(args[1], &head.to_le_bytes());
            }
            153 => {
                if args[0] != 0 {
                    output.push_slice(args[0], &usage::times_bytes(task, children));
                }
            }
            165 => output.push_slice(
                args[1],
                &usage::observe(task, children, args[0] as u32 as i32)?.encode(),
            ),
            _ => return Err(Errno(38)),
        }
        Ok(Self {
            output,
            times: (number == 153).then_some(started),
            fault: None,
            result: None,
        })
    }
    pub fn ready(&self) -> bool {
        self.fault.as_ref().is_none_or(|fault| fault.wait.ready())
    }
    pub fn fault(&self) -> Option<PageFault> {
        self.fault.clone()
    }
    pub fn cancel(&mut self) {
        let _ = self.complete(Err(Errno(4)));
    }
    fn complete(&mut self, value: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.output = Default::default();
        self.times = None;
        self.fault = None;
        self.result = Some(value);
        Some(value)
    }
    pub fn check(&mut self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        if let Some(value) = self.result {
            return Some(value);
        }
        self.fault = None;
        match self.output.progress(memory) {
            Ok(()) => self.complete(Ok(self
                .times
                .map_or(0, |started| usage::ticks(started.elapsed())))),
            Err(MemoryError::Pending(fault)) => {
                self.fault = Some(fault);
                None
            }
            Err(_) => self.complete(Err(Errno(14))),
        }
    }
}
