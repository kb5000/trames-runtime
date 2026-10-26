// SPDX-License-Identifier: GPL-3.0-or-later
use trames_memory::{Access, CpuMemory};
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
    pub fn restore(memory: &impl CpuMemory, address: u64) -> Result<Self, Errno> {
        let bytes = memory.read_array::<24>(address).map_err(|_| Errno(14))?;
        let flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if !matches!(flags & !SS_AUTODISARM, 0 | 1 | SS_DISABLE) {
            return Err(Errno(22));
        }
        let flags = flags & !1;
        if flags & SS_DISABLE != 0 {
            return Ok(Self {
                flags,
                ..Self::default()
            });
        }
        let size = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        if size < 2048 {
            return Err(Errno(12));
        }
        Ok(Self {
            sp: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            size,
            flags,
        })
    }
    pub fn call(
        &mut self,
        sp: u64,
        new: u64,
        old: u64,
        memory: &mut impl CpuMemory,
    ) -> Result<u64, Errno> {
        if old != 0 {
            memory
                .check(old, 24, Access::Write)
                .map_err(|_| Errno(14))?;
        }
        let next = if new != 0 {
            let next = Self::restore(memory, new)?;
            if self.on_stack(sp) {
                return Err(Errno(1));
            }
            Some(next)
        } else {
            None
        };
        if old != 0 {
            let mut bytes = [0; 24];
            bytes[..8].copy_from_slice(&self.sp.to_le_bytes());
            bytes[8..12].copy_from_slice(&self.reported_flags(sp).to_le_bytes());
            bytes[16..24].copy_from_slice(&self.size.to_le_bytes());
            memory.write_array(old, bytes).map_err(|_| Errno(14))?;
        }
        if let Some(next) = next {
            *self = next;
        }
        Ok(0)
    }
}
