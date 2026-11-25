// SPDX-License-Identifier: GPL-3.0-or-later
//! The current command's copied fragments. Shared resources captured by import
//! live in its packet cursor; they are never looked up again on a page retry.
use std::cell::RefCell;
use trames_memory::{Access, CopiedInput, CpuMemory, MemoryError, PageFault};

pub(super) struct Reader<'a, M> {
    memory: &'a M,
    input: &'a CopiedInput,
    fault: RefCell<Option<PageFault>>,
}
impl<'a, M: CpuMemory> Reader<'a, M> {
    pub fn new(memory: &'a M, input: &'a CopiedInput) -> Self {
        Self {
            memory,
            input,
            fault: RefCell::default(),
        }
    }
    pub fn fault(&self) -> Option<PageFault> {
        self.fault.borrow_mut().take()
    }
    pub fn pending(&self) -> bool {
        self.fault.borrow().is_some()
    }
    pub fn accepted(&self) {
        self.input.clear();
    }
}
impl<M: CpuMemory> CpuMemory for Reader<'_, M> {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn async_faults_possible(&self) -> bool {
        self.memory.async_faults_possible()
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        let result = self.input.read(self.memory, address, output);
        if let Err(MemoryError::Pending(fault)) = &result {
            *self.fault.borrow_mut() = Some(fault.clone());
        }
        result
    }
    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), MemoryError> {
        unreachable!("Binder input")
    }
    fn check(&self, _: u64, _: usize, _: Access) -> Result<(), MemoryError> {
        unreachable!("Binder input uses actual copies")
    }
    fn check_translation(&self, _: u64) -> Result<(), MemoryError> {
        unreachable!("Binder input")
    }
    fn fetch_u32(&self, _: u64) -> Result<u32, MemoryError> {
        unreachable!("Binder input")
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(&self, address: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.memory.instruction_page_identity(address)
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("Binder input")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("Binder input")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("Binder input")
    }
}
