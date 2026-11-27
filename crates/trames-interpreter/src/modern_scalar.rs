// SPDX-License-Identifier: GPL-3.0-or-later
//! FEAT_CSSC, FlagM2, speculation barrier and architectural entropy reads.
use super::{sign_extend, width_mask, Cpu, Flags};

impl Cpu {
    pub(super) fn execute_modern_scalar(&mut self, ins: u32) -> bool {
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let wide = ins >> 31 != 0;
        let mask = width_mask(wide);
        match ins {
            0xd500405f => {
                let flags = self.flags();
                self.set_flags(Flags {
                    n: false,
                    z: flags.z || flags.v,
                    c: flags.c && !flags.v,
                    v: false,
                });
                return true;
            }
            0xd500403f => {
                let flags = self.flags();
                let (c, z) = (flags.c, flags.z);
                self.set_flags(Flags {
                    n: !c && !z,
                    z: c && z,
                    c: c || z,
                    v: !c && z,
                });
                return true;
            }
            // Guest execution has no speculative memory accesses; SB enforces
            // the already ordered architectural execution, without host code.
            0xd50330ff => return true,
            _ => {}
        }
        if matches!(ins & 0xffffffe0, 0xd53b2400 | 0xd53b2420) {
            let mut bytes = [0; 8];
            let ok = getrandom::fill(&mut bytes).is_ok();
            self.set_x(rd, if ok { u64::from_le_bytes(bytes) } else { 0 });
            self.set_nzcv(if ok { 0 } else { 4 });
            return true;
        }
        let unary = ins & 0x7ffffc00;
        if matches!(unary, 0x5ac01800 | 0x5ac01c00 | 0x5ac02000) {
            let value = self.x(rn) & mask;
            let value = match unary {
                0x5ac01800 => {
                    (if wide {
                        value.trailing_zeros()
                    } else {
                        (value as u32).trailing_zeros()
                    }) as u64
                }
                0x5ac01c00 => value.count_ones() as u64,
                _ => {
                    if value & (1 << if wide { 63 } else { 31 }) != 0 {
                        value.wrapping_neg()
                    } else {
                        value
                    }
                }
            };
            self.put(rd, value, wide, false);
            return true;
        }
        let register = ins & 0x7fe0f000 == 0x1ac06000;
        let immediate = ins & 0x7ff00000 == 0x11c00000;
        if !register && !immediate {
            return false;
        }
        // The immediate is signed only for SMAX/SMIN; every destination
        // writes ZR rather than SP.
        let kind = if register {
            (ins >> 10) & 3
        } else {
            (ins >> 18) & 3
        };
        let unsigned = kind & 1 != 0;
        let minimum = kind & 2 != 0;
        let left = self.x(rn) & mask;
        let right = if register {
            self.x(rm) & mask
        } else {
            let value = ((ins >> 10) & 255) as u64;
            if unsigned {
                value
            } else {
                sign_extend(value, 8) & mask
            }
        };
        let less = if unsigned {
            left < right
        } else if wide {
            (left as i64) < (right as i64)
        } else {
            (left as u32 as i32) < (right as u32 as i32)
        };
        self.put(rd, if less == minimum { left } else { right }, wide, false);
        true
    }
}
