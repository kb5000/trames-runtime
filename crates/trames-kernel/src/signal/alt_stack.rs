// SPDX-License-Identifier: GPL-3.0-or-later
use trames_memory::CpuMemory;
use trames_vfs::Errno;

pub const SS_DISABLE: u32 = 2;
pub const SS_AUTODISARM: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltStack {
    pub sp: u64,
    pub size: u64,
    pub flags: u32,
}
impl Default for AltStack {
    fn default() -> Self {
        Self {
            sp: 0,
            size: 0,
            flags: SS_DISABLE,
        }
    }
}
impl AltStack {
    pub fn contains(self, sp: u64) -> bool {
        self.flags & SS_DISABLE == 0 && sp > self.sp && sp.wrapping_sub(self.sp) <= self.size
    }
    pub fn on_stack(self, sp: u64) -> bool {
        self.flags & SS_AUTODISARM == 0 && self.contains(sp)
    }
    pub fn reported_flags(self, sp: u64) -> u32 {
        self.flags | u32::from(self.on_stack(sp))
    }
    pub(super) fn import(memory: &impl CpuMemory, address: u64) -> Result<Option<Self>, Errno> {
        if address == 0 {
            return Ok(None);
        }
        Self::read(memory, address).map(Some)
    }
    pub(super) fn read(memory: &impl CpuMemory, address: u64) -> Result<Self, Errno> {
        let bytes = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
        Ok(Self {
            sp: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            size: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        })
    }
    pub fn restore(memory: &impl CpuMemory, address: u64) -> Result<Self, Errno> {
        // Sigreturn's stack address is mandatory, unlike sigaltstack's input.
        let next = Self::read(memory, address)?;
        let mut stack = Self::default();
        stack.exchange(0, Some(next))?;
        Ok(stack)
    }
    pub(super) fn exchange(&mut self, sp: u64, next: Option<Self>) -> Result<Self, Errno> {
        let old = *self;
        if let Some(mut next) = next {
            if old.on_stack(sp) {
                return Err(Errno(1));
            }
            if !matches!(next.flags & !SS_AUTODISARM, 0 | 1 | SS_DISABLE) {
                return Err(Errno(22));
            }
            // SS_ONSTACK is reported from the actual SP. It is accepted on
            // input without inventing a persistent on-stack status.
            next.flags &= !1;
            if next.flags & SS_DISABLE != 0 {
                next.sp = 0;
                next.size = 0;
            } else if next.size < 5120 {
                return Err(Errno(12));
            }
            *self = next;
        }
        Ok(old)
    }
    pub(super) fn encode(self, sp: u64) -> [u8; 24] {
        let mut bytes = [0; 24];
        bytes[..8].copy_from_slice(&self.sp.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.reported_flags(sp).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.size.to_le_bytes());
        bytes
    }
    pub fn call(
        &mut self,
        sp: u64,
        new: u64,
        old: u64,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        let next = Self::import(memory, new)?;
        let previous = self.exchange(sp, next)?;
        if old != 0 {
            memory
                .write_array(old, previous.encode(sp))
                .map_err(|_| Errno(14))?;
        }
        Ok(0)
    }
}
