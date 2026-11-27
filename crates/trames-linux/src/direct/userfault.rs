// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained userfaultfd ABI import, original-mm operation and independent copyout.
use super::*;
use trames_memory::{userfault::UserfaultFile, CopiedOutput, MemoryError};
const API: u32 = 0xc018aa3f;
const REGISTER: u32 = 0xc020aa00;
const UNREGISTER: u32 = 0x8010aa01;
const WAKE: u32 = 0x8010aa02;
const COPY: u32 = 0xc028aa03;
const ZERO: u32 = 0xc020aa04;
const CONTINUE: u32 = 0xc020aa07;

/// Small embeddings with original Memory can complete their own checkpoint
/// synchronously. Foreign-mm/resource waits still require the retained runtime.
pub(crate) fn solo(
    file: Arc<UserfaultFile>,
    request: u32,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Result<u64, Errno> {
    let mut control = Control::new(file, request, address);
    let input = file_input::Bytes::default();
    let mut output = CopiedOutput::default();
    loop {
        match control.progress(memory, &input, &mut output) {
            Ok(value) => {
                output.progress(memory).map_err(|_| Errno(14))?;
                value?;
                return control.finish();
            }
            Err(MemoryError::Pending(_)) => {
                let owner = memory.mapping_owner().ok_or(Errno(11))?;
                if !owner.memory_report().has_requested_reads() || !owner.activate_proc_reads() {
                    return Err(Errno(11));
                }
            }
            Err(_) => return Err(Errno(14)),
        }
    }
}

pub(super) struct Control {
    file: Arc<UserfaultFile>,
    request: u32,
    address: u64,
    header: Option<Vec<u8>>,
    operation: Option<Arc<trames_memory::MmControl>>,
    deferred: Option<Arc<trames_memory::PageWait>>,
    page_bytes: Option<Vec<u8>>,
    done: u64,
    api: bool,
}
impl Control {
    pub(super) fn new(file: Arc<UserfaultFile>, request: u32, address: u64) -> Self {
        Self {
            file,
            request,
            address,
            header: None,
            operation: None,
            deferred: None,
            page_bytes: None,
            done: 0,
            api: false,
        }
    }
    pub(super) fn finish(&self) -> Result<u64, Errno> {
        if self.api {
            self.file.initialize().map_err(Errno)?;
        }
        Ok(0)
    }
    pub(super) fn progress(
        &mut self,
        memory: &impl CpuMemory,
        input: &file_input::Bytes,
        output: &mut CopiedOutput,
    ) -> Result<Result<u64, Errno>, MemoryError> {
        if self.header.is_none() {
            if self.request != API && !self.file.initialized() {
                return Ok(Err(Errno(22)));
            }
            let len = match self.request {
                UNREGISTER | WAKE => 16,
                API => 24,
                REGISTER | ZERO | CONTINUE => 24,
                COPY => 32,
                _ => return Ok(Err(Errno(22))),
            };
            let mut bytes = vec![0; len];
            if let Err(error) =
                file_input::Reader::new(memory, input).read(self.address, &mut bytes)
            {
                return match error {
                    MemoryError::Pending(_) => Err(error),
                    _ => Ok(Err(Errno(14))),
                };
            }
            self.header = Some(bytes);
        }
        let raw = self.header.as_ref().unwrap();
        let word = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        if self.request == API {
            if self.file.initialized() || word(0) != 0xaa || word(1) != 0 {
                output.push_slice(self.address, &[0; 24]);
                return Ok(Err(Errno(22)));
            }
            let mut api = Vec::new();
            for word in [0xaau64, 0, (1 << 63) | (1 << 0) | (1 << 1)] {
                api.extend_from_slice(&word.to_le_bytes());
            }
            output.push_slice(self.address, &api);
            self.api = true;
            return Ok(Ok(0));
        }
        if self.request == CONTINUE {
            return Ok(Err(Errno(22)));
        }
        let (start, len) = (word(0), word(if self.request == COPY { 2 } else { 1 }));
        if let Err(error) = UserfaultFile::range(start, len) {
            return Ok(Err(Errno(error)));
        }
        if self.request == WAKE {
            return Ok(self.file.wake(start, len).map(|_| 0).map_err(Errno));
        }
        if matches!(self.request, REGISTER | UNREGISTER) {
            if self.operation.is_none() {
                if self.request == REGISTER && word(2) != 1 {
                    return Ok(Err(Errno(22)));
                }
                self.operation = Some(
                    match if self.request == REGISTER {
                        self.file.register(start, len)
                    } else {
                        self.file.unregister(start, len)
                    } {
                        Ok(request) => request,
                        Err(error) => return Ok(Err(Errno(error))),
                    },
                );
            }
            let request = self.operation.as_ref().unwrap();
            let Some(result) = request.result() else {
                return Err(request.fault(self.address));
            };
            return Ok(result
                .map(|bytes| {
                    if self.request == REGISTER {
                        output.push_slice(self.address + 24, &bytes);
                    }
                    0
                })
                .map_err(Errno));
        }
        let mode = word(if self.request == COPY { 3 } else { 2 });
        if mode & !1 != 0
            || self.request == COPY
                && (word(1)
                    .checked_add(len)
                    .is_none_or(|end| end > trames_memory::ADDRESS_LIMIT))
        {
            return Ok(Err(Errno(22)));
        }
        loop {
            if let Some(request) = self.operation.as_ref() {
                let Some(result) = request.result() else {
                    return Err(request.fault(self.address));
                };
                if let Some(wait) = request.deferred_wait() {
                    self.deferred = Some(wait);
                    self.operation = None;
                    continue;
                }
                if let Err(error) = result {
                    return Ok(self.copy_result(output, Err(error)));
                }
                self.operation = None;
                self.page_bytes = None;
                self.done += trames_memory::PAGE_SIZE;
                input.clear();
            }
            if self.done == len {
                return Ok(self.copy_result(output, Ok(())));
            }
            if let Some(wait) = self.deferred.as_ref() {
                if !wait.ready() {
                    return Err(wait.fault(self.address));
                }
                self.deferred = None;
            }
            if self.request == COPY && self.page_bytes.is_none() {
                let mut bytes = vec![0; trames_memory::PAGE_SIZE as usize];
                if let Err(error) =
                    file_input::Reader::new(memory, input).read(word(1) + self.done, &mut bytes)
                {
                    return match error {
                        MemoryError::Pending(_) => Err(error),
                        _ => Ok(self.copy_result(output, Err(14))),
                    };
                }
                self.page_bytes = Some(bytes);
            }
            self.operation = Some(
                match self
                    .file
                    .fill(start + self.done, self.page_bytes.clone(), mode & 1 == 0)
                {
                    Ok(request) => request,
                    Err(error) => return Ok(self.copy_result(output, Err(error))),
                },
            );
        }
    }
    fn copy_result(
        &self,
        output: &mut CopiedOutput,
        result: Result<(), u32>,
    ) -> Result<u64, Errno> {
        let count = match &result {
            Err(error) if self.done == 0 => -i64::from(*error),
            _ => self.done as i64,
        };
        output.push_slice(
            self.address + if self.request == COPY { 32 } else { 24 },
            &count.to_le_bytes(),
        );
        result
            .map(|_| 0)
            .map_err(|error| Errno(if self.done != 0 { 11 } else { error }))
    }
}
