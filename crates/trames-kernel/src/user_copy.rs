// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold task-boundary copies. Successful fragments belong to one accepted
//! operation; providers are not invoked again after a backing-page wait.
use std::{cell::RefCell, collections::BTreeMap};
use trames_memory::{Access, CpuMemory, MemoryError, PageFault, PAGE_SIZE};
use trames_vfs::Errno;

pub enum CopyError {
    Page(PageFault),
    Error(Errno),
}
pub(crate) fn write_bytes(
    memory: &mut impl CpuMemory,
    mut address: u64,
    bytes: &[u8],
) -> Result<(), MemoryError> {
    address &= 0x00ff_ffff_ffff_ffff;
    let mut copied = 0;
    while copied < bytes.len() {
        let count = (bytes.len() - copied).min((PAGE_SIZE - address % PAGE_SIZE) as usize);
        memory.write(address, &bytes[copied..copied + count])?;
        copied += count;
        address = address
            .checked_add(count as u64)
            .ok_or(MemoryError::InvalidRange)?;
    }
    Ok(())
}
#[derive(Default)]
pub(crate) struct Copies {
    reads: RefCell<BTreeMap<(u64, usize), Vec<u8>>>,
    failed_reads: RefCell<BTreeMap<(u64, usize), MemoryError>>,
    writes: Vec<Write>,
    fault: RefCell<Option<PageFault>>,
}
struct Write {
    address: u64,
    bytes: Vec<u8>,
    copied: usize,
}
/// Capture a provider that only emits outputs, then copy its accepted result.
/// No guest read or effect may depend on a write in this recording view.
#[derive(Default)]
pub(crate) struct Output {
    output: trames_memory::CopiedOutput,
    scalars: bool,
}
impl Output {
    pub fn scalars() -> Self {
        Self {
            scalars: true,
            ..Default::default()
        }
    }
    pub fn scalar(&mut self, address: u64, bytes: &[u8]) {
        self.output.push_scalar(address, bytes);
    }
    pub fn progress(&mut self, memory: &mut impl CpuMemory) -> Result<(), MemoryError> {
        self.output.progress(memory)
    }
}
fn copy_write(memory: &mut impl CpuMemory, write: &mut Write) -> Result<(), MemoryError> {
    while write.copied < write.bytes.len() {
        let at = write
            .address
            .checked_add(write.copied as u64)
            .ok_or(MemoryError::InvalidRange)?;
        let count = (write.bytes.len() - write.copied).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
        memory.write(at, &write.bytes[write.copied..write.copied + count])?;
        write.copied += count;
    }
    Ok(())
}
impl CpuMemory for Output {
    fn mapped_at_or_after(&self, _: u64) -> bool {
        unreachable!("recorded provider only emits outputs")
    }
    fn read(&self, _: u64, _: &mut [u8]) -> Result<(), MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.scalars {
            self.output.push_scalar(address, bytes);
        } else {
            self.output.push_slice(address, bytes);
        }
        Ok(())
    }
    fn check(&self, _: u64, _: usize, _: Access) -> Result<(), MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
    fn check_translation(&self, _: u64) -> Result<(), MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
    fn fetch_u32(&self, _: u64) -> Result<u32, MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        unreachable!("recorded provider only emits outputs")
    }
    fn instruction_page_identity(&self, _: u64) -> Result<(u64, u64, u64), MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
    fn atomic_update<T>(
        &mut self,
        _: u64,
        _: usize,
        _: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("recorded provider only emits outputs")
    }
}
pub(crate) struct View<'a, M> {
    memory: &'a mut M,
    copies: &'a mut Copies,
    index: usize,
}
impl Copies {
    pub fn read_array<const N: usize>(
        &self,
        memory: &impl CpuMemory,
        address: u64,
    ) -> Result<[u8; N], MemoryError> {
        let mut bytes = [0; N];
        self.read(memory, address, &mut bytes)?;
        Ok(bytes)
    }
    fn read(
        &self,
        memory: &impl CpuMemory,
        address: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryError> {
        if !memory.async_faults_possible() {
            return memory.read(address, output);
        }
        let mut copied = 0;
        while copied < output.len() {
            let at = address
                .checked_add(copied as u64)
                .ok_or(MemoryError::InvalidRange)?;
            let count = (output.len() - copied).min((PAGE_SIZE - at % PAGE_SIZE) as usize);
            let key = (at, count);
            if let Some(error) = self.failed_reads.borrow().get(&key).cloned() {
                return Err(error);
            }
            let cached = self.reads.borrow().get(&key).cloned();
            if let Some(bytes) = cached {
                output[copied..copied + count].copy_from_slice(&bytes);
            } else {
                if let Err(error) = memory.read(at, &mut output[copied..copied + count]) {
                    if !matches!(error, MemoryError::Pending(_)) {
                        self.failed_reads.borrow_mut().insert(key, error.clone());
                    }
                    return Err(error);
                }
                self.reads
                    .borrow_mut()
                    .insert(key, output[copied..copied + count].to_vec());
            }
            copied += count;
        }
        Ok(())
    }
    pub fn run<M: CpuMemory, T>(
        &mut self,
        memory: &mut M,
        operation: impl FnOnce(&mut View<'_, M>) -> Result<T, Errno>,
    ) -> Result<T, CopyError> {
        self.fault.borrow_mut().take();
        let result = operation(&mut View {
            memory,
            copies: self,
            index: 0,
        });
        if let Some(fault) = self.fault.borrow_mut().take() {
            return Err(CopyError::Page(fault));
        }
        result.map_err(CopyError::Error)
    }
}
impl<M: CpuMemory> View<'_, M> {
    fn observe<T>(&self, result: Result<T, MemoryError>) -> Result<T, MemoryError> {
        if let Err(MemoryError::Pending(fault)) = &result {
            *self.copies.fault.borrow_mut() = Some(fault.clone());
        }
        result
    }
}
impl<M: CpuMemory> CpuMemory for View<'_, M> {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn async_faults_possible(&self) -> bool {
        self.memory.async_faults_possible()
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        self.observe(self.copies.read(self.memory, address, output))
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.index == self.copies.writes.len() {
            self.copies.writes.push(Write {
                address,
                bytes: bytes.to_vec(),
                copied: 0,
            });
        }
        let write = &mut self.copies.writes[self.index];
        debug_assert_eq!(write.address, address);
        debug_assert_eq!(write.bytes, bytes);
        if let Err(error) = copy_write(self.memory, write) {
            if let MemoryError::Pending(fault) = &error {
                *self.copies.fault.borrow_mut() = Some(fault.clone());
            }
            return Err(error);
        }
        self.index += 1;
        Ok(())
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        self.observe(self.memory.check(address, len, access))
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.observe(self.memory.check_translation(address))
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.observe(self.memory.fetch_u32(address))
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
        unreachable!("task boundary user copy")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("task boundary user copy")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("task boundary user copy")
    }
}
