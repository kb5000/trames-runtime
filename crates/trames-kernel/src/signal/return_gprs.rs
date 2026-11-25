// SPDX-License-Identifier: GPL-3.0-or-later
//! ARM64 restores the mask and individual scalar registers before validating
//! optional records. A failed get_user zeroes that scalar and keeps going.
use super::*;
use crate::user_copy::CopyError;
use trames_execution::{Aarch64State, Registers};
use trames_memory::MemoryError;

pub(super) struct Gprs {
    address: u64,
    next: u8,
    failed: bool,
}
impl Gprs {
    pub fn new(address: u64) -> Self {
        Self {
            address,
            next: 0,
            failed: false,
        }
    }
    pub fn progress(
        &mut self,
        frame: &mut FrameState,
        state: &mut Aarch64State,
        task: Option<&IoTask>,
        memory: &impl CpuMemory,
    ) -> Result<(), CopyError> {
        FrameState::validate_return_address(self.address).map_err(CopyError::Error)?;
        while self.next < 35 {
            let offset = match self.next {
                0 => 168,
                n @ 1..=31 => 312 + (n as u64 - 1) * 8,
                32 => 560,
                33 => 568,
                34 => 576,
                _ => unreachable!(),
            };
            let value = match memory.read_array::<8>(self.address + offset) {
                Ok(bytes) => Some(u64::from_le_bytes(bytes)),
                Err(MemoryError::Pending(fault)) => return Err(CopyError::Page(fault)),
                Err(_) => {
                    self.failed = true;
                    None
                }
            };
            match self.next {
                0 => {
                    if let Some(mask) = value {
                        frame.mask = mask & !UNBLOCKABLE;
                        if let Some(task) = task {
                            task.context.lock().unwrap().mask = frame.mask;
                            task.publish_mask(frame.mask);
                        }
                    }
                }
                n @ 1..=31 => state.set_x(n as usize - 1, value.unwrap_or(0)),
                32 => state.sp = value.unwrap_or(0),
                33 => state.pc = value.unwrap_or(0),
                34 => {
                    let pstate = value.unwrap_or(0);
                    state.nzcv = pstate as u32 & 0xf0000000;
                    // valid_native_regs clears RES0 bits, then requires EL0t
                    // with AArch32 and the D/A/I/F masks disabled. PC/SP values
                    // themselves are left for normal EL0 fetch/access faults.
                    self.failed |= pstate & 0x3df != 0;
                }
                _ => unreachable!(),
            }
            self.next += 1;
        }
        if self.failed {
            Err(CopyError::Error(Errno(14)))
        } else {
            Ok(())
        }
    }
}
