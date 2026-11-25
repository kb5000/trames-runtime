// SPDX-License-Identifier: GPL-3.0-or-later
//! Task-owned signal controls over the original shared execution context.
use super::*;
impl IoTask {
    pub fn pending_bits(&self) -> u64 {
        self.inbox.bits() | self.process().bits()
    }
    pub fn mask_call(&self, a: [u64; 6], memory: &mut impl CpuMemory) -> Result<u64, Errno> {
        let old = self.mask();
        let input = MaskInput::import(a, memory)?;
        if let Some(mask) = input.apply(self.mask()) {
            self.context.lock().unwrap().mask = mask;
            self.publish_mask(mask);
        }
        export_mask(old, a[2], memory)?;
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
        if a[1] > 8 {
            return Err(Errno(22));
        }
        if a[1] != 0 {
            memory
                .write(
                    a[0],
                    &(self.pending_bits() & mask).to_le_bytes()[..a[1] as usize],
                )
                .map_err(|_| Errno(14))?;
        }
        Ok(0)
    }
    pub fn alt_stack_call(
        &self,
        sp: u64,
        a: [u64; 6],
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let next = AltStack::import(memory, a[0])?;
        let previous = self.context.lock().unwrap().alt_stack.exchange(sp, next)?;
        if a[1] != 0 {
            memory
                .write_array(a[1], previous.encode(sp))
                .map_err(|_| Errno(14))?;
        }
        Ok(0)
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

/// Parsed input contains no borrowed memory. Its actual owner chooses the
/// current mask at the single state mutation, retaining the entry predecessor.
pub(super) struct MaskInput {
    how: u32,
    bits: Option<u64>,
}
impl MaskInput {
    pub fn import(a: [u64; 6], memory: &impl CpuMemory) -> Result<Self, Errno> {
        if a[3] != 8 {
            return Err(Errno(22));
        }
        let bits = if a[1] == 0 {
            None
        } else {
            Some(u64::from_le_bytes(
                memory.read_array::<8>(a[1]).map_err(|_| Errno(14))?,
            ))
        };
        let how = a[0] as u32;
        if bits.is_some() && how > 2 {
            return Err(Errno(22));
        }
        Ok(Self { how, bits })
    }
    pub fn apply(&self, current: u64) -> Option<u64> {
        self.bits.map(|bits| {
            (match self.how {
                0 => current | bits,
                1 => current & !bits,
                2 => bits,
                _ => unreachable!(),
            }) & !UNBLOCKABLE
        })
    }
}
pub(super) fn export_mask(
    old: u64,
    address: u64,
    memory: &mut impl CpuMemory,
) -> Result<(), Errno> {
    if address != 0 {
        memory
            .write_array(address, old.to_le_bytes())
            .map_err(|_| Errno(14))?;
    }
    Ok(())
}
