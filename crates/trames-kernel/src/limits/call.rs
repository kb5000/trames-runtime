// SPDX-License-Identifier: GPL-3.0-or-later
//! User input precedes target lookup; the original limit exchange precedes
//! faultable copyout. No limit/directory lock survives either user copy.
use super::*;
use crate::user_copy::{Copies, CopyError};
use trames_memory::{CopiedOutput, MemoryError, PageFault};
#[cfg(test)]
mod tests;

pub(super) struct Parameters {
    pub resource: u64,
    input: Option<u64>,
    output: Option<u64>,
}
impl Parameters {
    pub(super) fn new(number: u32, args: [u64; 6]) -> Self {
        Self {
            resource: (if number == 261 { args[1] } else { args[0] }) as u32 as u64,
            input: match number {
                164 => Some(args[1]),
                261 => (args[2] != 0).then_some(args[2]),
                _ => None,
            },
            output: match number {
                163 => Some(args[1]),
                261 => (args[3] != 0).then_some(args[3]),
                _ => None,
            },
        }
    }
    pub(super) fn import(&self, memory: &impl CpuMemory) -> Result<Option<Pair>, Errno> {
        let Some(address) = self.input else {
            return Ok(None);
        };
        let bytes = memory.read_array::<16>(address).map_err(|_| Errno(14))?;
        Ok(Some((
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        )))
    }
    pub(super) fn export(&self, memory: &mut impl CpuMemory, previous: Pair) -> Result<(), Errno> {
        let Some(address) = self.output else {
            return Ok(());
        };
        let mut output = CopiedOutput::default();
        output.push_slice(address, &encode(previous));
        output.progress(memory).map_err(|_| Errno(14))
    }
}
fn encode(pair: Pair) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&pair.0.to_le_bytes());
    bytes[8..].copy_from_slice(&pair.1.to_le_bytes());
    bytes
}
pub struct Call {
    authority: Option<Authority>,
    number: u32,
    args: [u64; 6],
    parameters: Parameters,
    input: Copies,
    output: CopiedOutput,
    target: Option<Arc<Limits>>,
    accepted: bool,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl Call {
    pub fn new(authority: Authority, number: u32, args: [u64; 6]) -> Self {
        Self {
            authority: Some(authority),
            number,
            args,
            parameters: Parameters::new(number, args),
            input: Default::default(),
            output: Default::default(),
            target: None,
            accepted: false,
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
        let _ = self.finish(Err(Errno(4)));
    }
    fn finish(&mut self, result: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.authority = None;
        self.target = None;
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
            Ok(()) => self.finish(Ok(0)),
            Err(CopyError::Error(error)) => self.finish(Err(error)),
            Err(CopyError::Page(fault)) => {
                self.fault = Some(fault);
                None
            }
        }
    }
    fn progress(&mut self, memory: &mut impl CpuMemory) -> Result<(), CopyError> {
        if !self.accepted {
            let next = self
                .input
                .run(memory, |view| self.parameters.import(view))?;
            let authority = self.authority.as_ref().unwrap();
            let pid = authority
                .resolve_pid(self.number, self.args)
                .map_err(CopyError::Error)?;
            let target = authority.target(pid).map_err(CopyError::Error)?;
            let previous = target
                .exchange(
                    self.parameters.resource,
                    next,
                    authority.fixed,
                    authority.credentials.has_cap(capabilities::SYS_RESOURCE),
                )
                .map_err(CopyError::Error)?;
            if let Some(address) = self.parameters.output {
                self.output.push_slice(address, &encode(previous));
            }
            self.target = Some(target);
            self.accepted = true;
            self.input = Default::default();
        }
        self.output.progress(memory).map_err(|error| match error {
            MemoryError::Pending(fault) => CopyError::Page(fault),
            _ => CopyError::Error(Errno(14)),
        })
    }
}
