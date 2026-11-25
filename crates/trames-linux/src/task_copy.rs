// SPDX-License-Identifier: GPL-3.0-or-later
//! Original task metadata input and one accepted output, independent of CPU custody.
use crate::direct::file_input::{Bytes, Reader};
use std::sync::Arc;
use trames_memory::{CopiedOutput, CpuMemory, MemoryError, PageFault};
use trames_vfs::{Credentials, Errno, KeyLease, KeyRegistry, SessionKeys, TaskName};
#[cfg(test)]
#[path = "task_copy_tests.rs"]
mod tests;
enum Owner {
    Name(TaskName),
    Keys {
        keys: SessionKeys,
        registry: Arc<KeyRegistry>,
        credentials: Credentials,
    },
}
pub struct TaskCopyCall {
    owner: Option<Owner>,
    args: [u64; 6],
    input: Bytes,
    output: CopiedOutput,
    key: Option<KeyLease>,
    value: Option<u64>,
    fault: Option<PageFault>,
    result: Option<Result<u64, Errno>>,
}
impl TaskCopyCall {
    pub fn name(name: TaskName, args: [u64; 6]) -> Self {
        Self::new(Owner::Name(name), args)
    }
    pub fn keys(
        keys: SessionKeys,
        registry: Arc<KeyRegistry>,
        credentials: Credentials,
        args: [u64; 6],
    ) -> Self {
        Self::new(
            Owner::Keys {
                keys,
                registry,
                credentials,
            },
            args,
        )
    }
    fn new(owner: Owner, args: [u64; 6]) -> Self {
        Self {
            owner: Some(owner),
            args,
            input: Default::default(),
            output: Default::default(),
            key: None,
            value: None,
            fault: None,
            result: None,
        }
    }
    pub fn scalar(address: u64, value: u32) -> Self {
        let mut output = CopiedOutput::default();
        output.push_scalar(address, &value.to_le_bytes());
        Self {
            owner: None,
            args: [0; 6],
            input: Default::default(),
            output,
            key: None,
            value: Some(0),
            fault: None,
            result: None,
        }
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
    fn complete(&mut self, result: Result<u64, Errno>) -> Option<Result<u64, Errno>> {
        self.owner = None;
        self.input = Default::default();
        self.output = Default::default();
        self.key = None;
        self.fault = None;
        self.result = Some(result);
        Some(result)
    }
    pub fn check(&mut self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        if let Some(result) = self.result {
            return Some(result);
        }
        self.fault = None;
        if self.value.is_none() {
            let reader = Reader::new(memory, &self.input);
            let prepared = match self.owner.as_ref().unwrap() {
                Owner::Name(name) => {
                    crate::task_name::prepare(name, self.args, &reader, &mut self.output)
                        .map(|value| (value, None))
                }
                Owner::Keys {
                    keys,
                    registry,
                    credentials,
                } => crate::keyctl::prepare(
                    keys,
                    registry,
                    credentials,
                    self.args,
                    &reader,
                    &mut self.output,
                ),
            };
            if let Some(fault) = reader.fault() {
                self.fault = Some(fault);
                return None;
            }
            match prepared {
                Ok((value, key)) => {
                    self.value = Some(value);
                    self.key = key;
                    self.input = Default::default();
                }
                Err(error) => return self.complete(Err(error)),
            }
        }
        match self.output.progress(memory) {
            Ok(()) => self.complete(Ok(self.value.unwrap())),
            Err(MemoryError::Pending(fault)) => {
                self.fault = Some(fault);
                None
            }
            Err(_) => self.complete(Err(Errno(14))),
        }
    }
}
