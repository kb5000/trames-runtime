// SPDX-License-Identifier: GPL-3.0-or-later
//! The original selected/reaped child and captured ABI outputs are one wait.
use super::*;
use crate::user_copy::Output;
use trames_memory::{MemoryError, PageFault, ADDRESS_LIMIT};

pub struct WaitCall {
    pub number: u32,
    pub args: [u64; 6],
    request: Result<Wait, Errno>,
    result: Option<Result<u64, Errno>>,
    output: Output,
    fault: Option<PageFault>,
    done: bool,
    binding: Option<(Arc<Children>, PidNamespace, u32)>,
}
impl WaitCall {
    pub fn prepare(
        caller: u32,
        number: u32,
        args: [u64; 6],
        files: &trames_vfs::FdFlags,
        namespace: &PidNamespace,
    ) -> Self {
        Self::new(
            number,
            args,
            Wait::prepare_with_files(caller, number, args, files, namespace),
        )
    }
    pub fn accepted(request: Wait) -> Self {
        Self::new(request.number, request.args, Ok(request))
    }
    fn new(number: u32, args: [u64; 6], request: Result<Wait, Errno>) -> Self {
        Self {
            number,
            args,
            request,
            result: None,
            output: Default::default(),
            fault: None,
            done: false,
            binding: None,
        }
    }
    pub fn interruptible(&self) -> bool {
        self.result.is_none()
    }
    pub fn fault(&self) -> Option<PageFault> {
        self.fault.clone()
    }
    pub fn subscribe(&self, family: &Children, signal: &Arc<IoSignal>) -> IoSubscription {
        self.binding.as_ref().map_or_else(
            || family.subscribe(signal),
            |(original, _, _)| original.subscribe(signal),
        )
    }
    pub fn ready(&self, family: &Arc<Children>, namespace: &PidNamespace, group: u32) -> bool {
        if let Some(fault) = &self.fault {
            return fault.wait.ready();
        }
        let (family, namespace, group) = self
            .binding
            .as_ref()
            .map_or((family, namespace, group), |(family, namespace, group)| {
                (family, namespace, *group)
            });
        self.result.is_some()
            || self
                .request
                .map_or(true, |request| family.ready(request, namespace, group))
    }
    pub fn check(
        &mut self,
        family: &Arc<Children>,
        namespace: &PidNamespace,
        group: u32,
        memory: &mut impl CpuMemory,
    ) -> Option<Result<u64, Errno>> {
        if self.done {
            return self.result;
        }
        let (family, namespace, group) = self
            .binding
            .get_or_insert_with(|| (family.clone(), namespace.clone(), group));
        if self.result.is_none() {
            let result = match self.request {
                Ok(request) => family.wait(request, namespace, *group, &mut self.output),
                Err(error) => {
                    if self.number == 95 {
                        if let Err(error) = write_info(&mut self.output, self.args[2], [0; 6]) {
                            self.result = Some(Err(error));
                        }
                    }
                    Err(error)
                }
            };
            if self.result.is_none() {
                self.result = match result {
                    Ok(None) => return None,
                    Ok(Some(value)) => Some(Ok(value)),
                    Err(error) => Some(Err(error)),
                };
            }
        }
        self.copy(memory)
    }
    pub fn interrupt(&mut self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        if self.done {
            return self.result;
        }
        if self.result.is_none() {
            self.result = Some(Err(Errno(4)));
            if self.number == 95 {
                if let Err(error) = write_info(&mut self.output, self.args[2], [0; 6]) {
                    self.result = Some(Err(error));
                }
            }
        }
        self.copy(memory)
    }
    fn copy(&mut self, memory: &mut impl CpuMemory) -> Option<Result<u64, Errno>> {
        self.fault = None;
        match self.output.progress(memory) {
            Err(MemoryError::Pending(fault)) => {
                self.fault = Some(fault);
                return None;
            }
            Err(_) => self.result = Some(Err(Errno(14))),
            Ok(()) => {}
        }
        self.done = true;
        self.result
    }
}
/// waitid updates six AArch64 siginfo fields; padding and the remaining union
/// are untouched. Its range check does not fault in or preflight guest pages.
pub(super) fn write_info(
    memory: &mut impl CpuMemory,
    address: u64,
    words: [u32; 6],
) -> Result<(), Errno> {
    if address == 0 {
        return Ok(());
    }
    let untagged = address & 0x00ff_ffff_ffff_ffff;
    if untagged
        .checked_add(128)
        .is_none_or(|end| end > ADDRESS_LIMIT)
    {
        return Err(Errno(14));
    }
    for (offset, word) in [0u64, 4, 8, 16, 20, 24].into_iter().zip(words) {
        memory
            .write_array(
                address.checked_add(offset).ok_or(Errno(14))?,
                word.to_le_bytes(),
            )
            .map_err(|_| Errno(14))?;
    }
    Ok(())
}
