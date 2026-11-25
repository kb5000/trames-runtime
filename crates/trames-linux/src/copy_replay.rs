// SPDX-License-Identifier: GPL-3.0-or-later
//! A cold output cursor for already accepted messages. Providers retain the
//! original received packet/rights; this only resumes its ordered user copies.
use trames_memory::{Access, CpuMemory, MemoryError, PageFault, PAGE_SIZE};
#[derive(Default)]
pub(crate) struct Replay {
    writes: Vec<Write>,
    pub(crate) fault: Option<PageFault>,
}
struct Write {
    address: u64,
    bytes: Vec<u8>,
    copied: usize,
}
impl Replay {
    pub(crate) fn capture(&mut self, address: u64, bytes: &[u8]) {
        self.writes.push(Write {
            address,
            bytes: bytes.to_vec(),
            copied: 0,
        });
    }
    pub(crate) fn completed_writes(&self) -> usize {
        self.writes
            .iter()
            .take_while(|write| write.copied == write.bytes.len())
            .count()
    }
    /// Flush already-owned control outputs without invoking the provider again.
    pub(crate) fn progress(&mut self, memory: &mut impl CpuMemory) -> Result<(), MemoryError> {
        self.fault = None;
        for write in &mut self.writes {
            if let Err(error) = copy(memory, write) {
                if let MemoryError::Pending(fault) = &error {
                    self.fault = Some(fault.clone());
                }
                return Err(error);
            }
        }
        Ok(())
    }
}
fn copy(memory: &mut impl CpuMemory, write: &mut Write) -> Result<(), MemoryError> {
    while write.copied < write.bytes.len() {
        let address = write
            .address
            .checked_add(write.copied as u64)
            .ok_or(MemoryError::InvalidRange)?;
        let count =
            (write.bytes.len() - write.copied).min((PAGE_SIZE - address % PAGE_SIZE) as usize);
        memory.write(address, &write.bytes[write.copied..write.copied + count])?;
        write.copied += count;
    }
    Ok(())
}
pub(crate) struct Writer<'a, M> {
    memory: &'a mut M,
    replay: &'a mut Replay,
    index: usize,
}
impl<'a, M: CpuMemory> Writer<'a, M> {
    pub(crate) fn new(memory: &'a mut M, replay: &'a mut Replay) -> Self {
        replay.fault = None;
        Self {
            memory,
            replay,
            index: 0,
        }
    }
}
impl<M: CpuMemory> CpuMemory for Writer<'_, M> {
    fn mapped_at_or_after(&self, address: u64) -> bool {
        self.memory.mapped_at_or_after(address)
    }
    fn async_faults_possible(&self) -> bool {
        self.memory.async_faults_possible()
    }
    fn read(&self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        self.memory.read(address, output)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if self.index == self.replay.writes.len() {
            self.replay.writes.push(Write {
                address,
                bytes: bytes.to_vec(),
                copied: 0,
            });
        }
        if let Err(error) = copy(self.memory, &mut self.replay.writes[self.index]) {
            if let MemoryError::Pending(fault) = &error {
                self.replay.fault = Some(fault.clone());
            }
            return Err(error);
        }
        self.index += 1;
        Ok(())
    }
    fn check(&self, address: u64, len: usize, access: Access) -> Result<(), MemoryError> {
        self.memory.check(address, len, access)
    }
    fn check_translation(&self, address: u64) -> Result<(), MemoryError> {
        self.memory.check_translation(address)
    }
    fn fetch_u32(&self, address: u64) -> Result<u32, MemoryError> {
        self.memory.fetch_u32(address)
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
        unreachable!("ordered message copyout")
    }
    fn exclusive_read(&mut self, _: u64, _: &mut [u8]) -> Result<u128, MemoryError> {
        unreachable!("ordered message copyout")
    }
    fn exclusive_write(&mut self, _: u64, _: &[u8], _: Option<u128>) -> Result<bool, MemoryError> {
        unreachable!("ordered message copyout")
    }
}
