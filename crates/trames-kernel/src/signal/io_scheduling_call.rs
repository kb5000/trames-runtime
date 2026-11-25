// SPDX-License-Identifier: GPL-3.0-or-later
//! The accepted scheduling input precedes task lookup and one policy update.
//! Snapshot output and an original affinity departure have independent waits.
use super::*;
use crate::user_copy::{Copies, CopyError, Output};
use trames_memory::{MemoryError, PageFault};
#[cfg(test)]
#[path = "io_scheduling_copy_tests.rs"]
mod tests;

pub(super) enum Input {
    None,
    Priority(i32),
    Affinity([u8; 8]),
    Attribute(FairAttr),
    SizeError,
}
impl Input {
    pub(super) fn read(
        number: u32,
        args: [u64; 6],
        memory: &impl CpuMemory,
    ) -> Result<Self, Errno> {
        match number {
            118 | 119 => {
                let pointer = if number == 118 { args[1] } else { args[2] };
                if pointer == 0
                    || (args[0] as u32 as i32) < 0
                    || number == 119 && (args[1] as u32 as i32) < 0
                {
                    return Err(Errno(22));
                }
                Ok(Self::Priority(i32::from_le_bytes(
                    memory.read_array::<4>(pointer).map_err(|_| Errno(14))?,
                )))
            }
            121 if args[1] == 0 || (args[0] as u32 as i32) < 0 => Err(Errno(22)),
            122 => {
                let mut bytes = [0; 8];
                let count = (args[1] as u32 as usize).min(bytes.len());
                if count != 0 {
                    memory
                        .read(args[2], &mut bytes[..count])
                        .map_err(|_| Errno(14))?;
                }
                Ok(Self::Affinity(bytes))
            }
            123 if (args[1] as u32) < 8 || args[1] as u32 & 7 != 0 => Err(Errno(22)),
            274 => {
                if args[1] == 0 || (args[0] as u32 as i32) < 0 || args[2] as u32 != 0 {
                    return Err(Errno(22));
                }
                FairAttr::read(memory, args[1])
            }
            275 => {
                if args[1] == 0
                    || (args[0] as u32 as i32) < 0
                    || !(FairAttr::SIZE..=4096).contains(&(args[2] as u32))
                    || args[3] as u32 != 0
                {
                    return Err(Errno(22));
                }
                Ok(Self::None)
            }
            _ => Ok(Self::None),
        }
    }
}
pub(super) struct Prepared {
    pub output: Output,
    pub value: Result<u64, Errno>,
    pub migration: Option<Arc<crate::completion::Completion>>,
    pub size_error: bool,
}
struct Owner {
    source: Arc<IoTask>,
    routes: IoRoutes,
}
pub struct Call {
    owner: Option<Owner>,
    cpus: usize,
    number: u32,
    args: [u64; 6],
    input: Copies,
    prepared: Option<Prepared>,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl Call {
    pub fn new(
        source: Arc<IoTask>,
        routes: IoRoutes,
        cpus: usize,
        number: u32,
        args: [u64; 6],
    ) -> Self {
        Self {
            owner: Some(Owner { source, routes }),
            cpus,
            number,
            args,
            input: Default::default(),
            prepared: None,
            fault: None,
            result: None,
        }
    }
    pub fn fault(&self) -> Option<PageFault> {
        self.fault.clone()
    }
    pub fn completion(&self) -> Option<Arc<crate::completion::Completion>> {
        self.prepared.as_ref()?.migration.clone()
    }
    pub fn ready(&self) -> bool {
        self.fault.as_ref().is_none_or(|fault| fault.wait.ready())
            && self
                .prepared
                .as_ref()
                .and_then(|p| p.migration.as_ref())
                .is_none_or(|wait| wait.finished())
    }
    pub fn cancel(&mut self) {
        let _ = self.complete(Err(Errno(4)));
    }
    fn complete(&mut self, result: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.prepared = None;
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
            Ok(Some(value)) => self.complete(value),
            Ok(None) => None,
            Err(CopyError::Error(error)) => self.complete(Err(error)),
            Err(CopyError::Page(fault)) => {
                self.fault = Some(fault);
                None
            }
        }
    }
    fn progress(
        &mut self,
        memory: &mut impl CpuMemory,
    ) -> Result<Option<Result<u64, Errno>>, CopyError> {
        let owner = self.owner.as_ref().unwrap();
        if self.prepared.is_none() {
            let input = self
                .input
                .run(memory, |view| Input::read(self.number, self.args, view))?;
            self.prepared = Some(owner.routes.scheduling_prepared(
                &owner.source,
                self.cpus,
                self.number,
                self.args,
                input,
            ));
            self.input = Default::default();
        }
        let prepared = self.prepared.as_mut().unwrap();
        match prepared.output.progress(memory) {
            Ok(()) => {}
            Err(MemoryError::Pending(fault)) => return Err(CopyError::Page(fault)),
            Err(_) if !prepared.size_error => return Err(CopyError::Error(Errno(14))),
            Err(_) => {}
        }
        if prepared
            .migration
            .as_ref()
            .is_some_and(|wait| !wait.finished())
        {
            return Ok(None);
        }
        Ok(Some(prepared.value))
    }
}
