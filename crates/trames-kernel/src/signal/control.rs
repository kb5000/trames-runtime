// SPDX-License-Identifier: GPL-3.0-or-later
//! Task-owned signal controls over the original shared execution context.
use super::*;
impl IoTask {
    pub fn pending_bits(&self) -> u64 {
        self.inbox.bits() | self.process().bits()
    }
    pub fn mask_call(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        let new = update_mask(self.mask(), a, memory)?;
        if let Some(mask) = new {
            self.context.lock().unwrap().mask = mask;
            self.publish_mask(mask);
        }
        Ok(0)
    }
    pub fn pending_call(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        self.pending_call_mask(self.mask(), a, memory)
    }
    pub fn pending_call_mask(
        &self,
        mask: u64,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        if a[1] != 8 {
            return Err(Errno(22));
        }
        memory
            .write_array(a[0], (self.pending_bits() & mask).to_le_bytes())
            .map_err(|_| Errno(14))?;
        Ok(0)
    }
    pub fn alt_stack_call(
        &self,
        sp: u64,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        self.context
            .lock()
            .unwrap()
            .alt_stack
            .call(sp, a[0], a[1], memory)
    }
    pub fn dequeue(&self, mask: u64) -> Option<(u32, RetainedInfo)> {
        self.inbox
            .dequeue(mask)
            .or_else(|| self.process().dequeue(mask))
    }
    pub fn subscribe(
        &self,
        signal: &std::sync::Arc<trames_vfs::IoSignal>,
    ) -> Vec<trames_vfs::IoSubscription> {
        vec![
            self.inbox.subscribe(signal),
            self.process().subscribe(signal),
        ]
    }
}

/// One transactional ABI, independent of which executor currently owns the task.
pub(super) fn update_mask(
    old: u64,
    a: [u64; 6],
    memory: &mut impl CpuMemory,
) -> Result<Option<u64>, Errno> {
    if a[3] != 8 {
        return Err(Errno(22));
    }
    if a[2] != 0 {
        memory
            .check(a[2], 8, trames_memory::Access::Write)
            .map_err(|_| Errno(14))?;
    }
    let new = if a[1] != 0 {
        let bits = u64::from_le_bytes(memory.read_array::<8>(a[1]).map_err(|_| Errno(14))?);
        Some(
            match a[0] {
                0 => old | bits,
                1 => old & !bits,
                2 => bits,
                _ => return Err(Errno(22)),
            } & !UNBLOCKABLE,
        )
    } else {
        None
    };
    if a[2] != 0 {
        memory
            .write_array(a[2], old.to_le_bytes())
            .map_err(|_| Errno(14))?;
    }
    Ok(new)
}
