// SPDX-License-Identifier: GPL-3.0-or-later
use super::{shifted, sign_extend, width_mask, Cpu, CpuFault, Flags};
use trames_memory::CpuMemory;

#[inline]
pub(super) fn ones(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}
#[inline]
pub(super) fn rotate(value: u64, amount: u32, bits: u32) -> u64 {
    if amount == 0 {
        value & ones(bits)
    } else {
        ((value >> amount) | value.wrapping_shl(bits - amount)) & ones(bits)
    }
}

pub(super) fn logical_mask(n: u32, imms: u32, immr: u32, wide: bool) -> Option<u64> {
    let encoded = (n << 6) | (!imms & 63);
    if encoded < 2 {
        return None;
    }
    let length = 31 - encoded.leading_zeros();
    if !wide && length > 5 {
        return None;
    }
    let levels = (1 << length) - 1;
    let s = imms & levels;
    if s == levels {
        return None;
    }
    let size = 1 << length;
    let element = rotate(ones(s + 1), immr & levels, size);
    let mut value = 0;
    for offset in (0..if wide { 64 } else { 32 }).step_by(size as usize) {
        value |= element << offset;
    }
    Some(value)
}

impl Cpu {
    pub(super) fn execute_extended(
        &mut self,
        ins: u32,
        memory: &mut impl CpuMemory,
    ) -> Result<Option<u64>, CpuFault> {
        let pc = self.pc;
        let mut next = pc.wrapping_add(4);
        if ins == 0xd50330ff {
            memory.fence(std::sync::atomic::Ordering::SeqCst);
        }
        if let Some(next) = self.execute_compatibility(ins, memory)? {
            return Ok(Some(next));
        }
        if let Some(next) = self.execute_modern_memory(ins, memory)? {
            return Ok(Some(next));
        }
        if self.execute_modern_scalar(ins) {
            return Ok(Some(next));
        }
        // A64 primary encoding groups 0111/1111 contain SIMD and FP.
        // Integer, load/store and system fallbacks need no vector decoding.
        if ins & 0x0e000000 == 0x0e000000
            && (self.execute_vector_extensions(ins)?
                || self.execute_modern_crypto(ins)
                || self.execute_crypto(ins)
                || self.execute_half_vector(ins)?
                || self.execute_vector_integer(ins)?
                || self.execute_floating(ins)?)
        {
            return Ok(Some(next));
        }
        let invalid = || CpuFault::Instruction {
            pc,
            instruction: ins,
        };
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let left = self.vectors[rn] as u64;
        let right = self.vectors[rm] as u64;
        if ins == 0xd500401f {
            self.set_nzcv(self.nzcv() ^ 2);
            return Ok(Some(next));
        }
        if ins & 0xffe07c10 == 0xba000400 {
            let mask = ins & 15;
            let bits = self.x(rn).rotate_right((ins >> 15) & 63) as u32;
            self.set_nzcv((self.nzcv() & !mask) | (bits & mask));
            return Ok(Some(next));
        }
        if ins & 0xffffbc1f == 0x3a00080d {
            let width = if ins & 0x4000 != 0 { 16 } else { 8 };
            let value = self.x(rn) as u32;
            let sign = value >> (width - 1) & 1;
            let c = self.condition_flags.carry();
            self.set_flags(Flags {
                n: sign != 0,
                z: value & ((1 << width) - 1) == 0,
                c,
                v: sign ^ ((value >> width) & 1) != 0,
            });
            return Ok(Some(next));
        }
        if ins & 0xffe0fc00 == 0x5e000400 {
            // DUP scalar from a vector lane (MOV alias), clearing upper bits.
            let imm5 = (ins >> 16) & 31;
            if imm5 == 0 || imm5.trailing_zeros() > 3 {
                return Err(invalid());
            }
            let power = imm5.trailing_zeros();
            let bits = 8 << power;
            let lane = imm5 >> (power + 1);
            self.vectors[rd] = (self.vectors[rn] >> (lane * bits)) & ones(bits) as u128;
            return Ok(Some(next));
        }
        let scalar = match ins & 0xffe0fc00 {
            0x5ee08400 => Some(left.wrapping_add(right)),
            0x7ee08400 => Some(left.wrapping_sub(right)),
            0x7ee08c00 => Some(if left == right { u64::MAX } else { 0 }),
            0x5ee03400 => Some(if (left as i64) > (right as i64) {
                u64::MAX
            } else {
                0
            }),
            0x5ee03c00 => Some(if (left as i64) >= (right as i64) {
                u64::MAX
            } else {
                0
            }),
            0x7ee03400 => Some(if left > right { u64::MAX } else { 0 }),
            0x7ee03c00 => Some(if left >= right { u64::MAX } else { 0 }),
            0x5ee08c00 => Some(if left & right != 0 { u64::MAX } else { 0 }),
            _ => match ins & 0xfffffc00 {
                0x5ee0b800 => Some((left as i64).wrapping_abs() as u64),
                0x7ee0b800 => Some(left.wrapping_neg()),
                0x5ef1b800 => Some(left.wrapping_add((self.vectors[rn] >> 64) as u64)),
                _ => None,
            },
        };
        if let Some(value) = scalar {
            self.vectors[rd] = value as u128;
            return Ok(Some(next));
        }
        let wide = ins >> 31 != 0;
        let bits = if wide { 64 } else { 32 };
        let mask = width_mask(wide);
        if ins & 0x1f800000 == 0x12000000 {
            // logical immediate
            let n = (ins >> 22) & 1;
            if !wide && n != 0 {
                return Err(invalid());
            }
            let immediate =
                logical_mask(n, (ins >> 10) & 63, (ins >> 16) & 63, wide).ok_or_else(invalid)?;
            let opc = (ins >> 29) & 3;
            let value = match opc {
                0 | 3 => self.x(rn) & immediate,
                1 => self.x(rn) | immediate,
                2 => self.x(rn) ^ immediate,
                _ => unreachable!(),
            } & mask;
            if opc == 3 {
                self.set_flags(Flags {
                    n: value >> (bits - 1) != 0,
                    z: value == 0,
                    c: false,
                    v: false,
                });
            }
            self.put(rd, value, wide, opc != 3);
        } else if ins & 0x1f800000 == 0x13000000 {
            // SBFM/BFM/UBFM
            let opc = (ins >> 29) & 3;
            let r = (ins >> 16) & 63;
            let s = (ins >> 10) & 63;
            if opc == 3 || ((ins >> 22) & 1) != wide as u32 || r >= bits || s >= bits {
                return Err(invalid());
            }
            let wmask = rotate(ones(s + 1), r, bits);
            let tmask = ones(((s.wrapping_sub(r)) & (bits - 1)) + 1);
            let rotated = rotate(self.x(rn) & mask, r, bits);
            let value = match opc {
                0 => {
                    let top = if self.x(rn) & (1 << s) != 0 { mask } else { 0 };
                    (top & !tmask) | (rotated & wmask & tmask)
                }
                1 => {
                    let bottom = (self.x(rd) & !wmask) | (rotated & wmask);
                    (self.x(rd) & !tmask) | (bottom & tmask)
                }
                2 => rotated & wmask & tmask,
                _ => unreachable!(),
            };
            self.put(rd, value, wide, false);
        } else if ins & 0x1f800000 == 0x13800000 {
            // EXTR
            let amount = (ins >> 10) & 63;
            if ins & 0x60000000 != 0
                || ins & (1 << 21) != 0
                || ((ins >> 22) & 1) != wide as u32
                || amount >= bits
            {
                return Err(invalid());
            }
            let value = if amount == 0 {
                self.x(rm)
            } else {
                ((self.x(rm) & mask) >> amount) | self.x(rn).wrapping_shl(bits - amount)
            };
            self.put(rd, value, wide, false);
        } else if ins & 0x1f200000 == 0x0b200000 {
            // ADD/SUB extended register
            let option = (ins >> 13) & 7;
            let amount = (ins >> 10) & 7;
            if amount > 4 || ins & (3 << 22) != 0 {
                return Err(invalid());
            }
            let size = 8 << (option & 3);
            let mut rhs = self.x(rm) & ones(size);
            if option & 4 != 0 {
                rhs = sign_extend(rhs, size);
            }
            let flags = ins & (1 << 29) != 0;
            let value = self.arithmetic(
                self.reg(rn, true),
                rhs.wrapping_shl(amount),
                ins & (1 << 30) != 0,
                flags,
                wide,
            );
            self.put(rd, value, wide, !flags);
        } else if ins & 0x1fe00800 == 0x1a800000 {
            // CSEL/CSINC/CSINV/CSNEG
            if ins & (1 << 29) != 0 {
                return Err(invalid());
            }
            let mut value = if self.condition((ins >> 12) & 15) {
                self.x(rn)
            } else {
                let mut other = self.x(rm);
                if ins & (1 << 30) != 0 {
                    other = !other;
                }
                if ins & (1 << 10) != 0 {
                    other = other.wrapping_add(1);
                }
                other
            };
            value &= mask;
            self.put(rd, value, wide, false);
        } else if ins & 0x1fe00410 == 0x1a400000 {
            // CCMP/CCMN, register or immediate
            if ins & (1 << 29) == 0 {
                return Err(invalid());
            }
            if self.condition((ins >> 12) & 15) {
                let rhs = if ins & (1 << 11) != 0 {
                    rm as u64
                } else {
                    self.x(rm)
                };
                self.arithmetic(self.x(rn), rhs, ins & (1 << 30) != 0, true, wide);
            } else {
                self.set_nzcv(ins & 15);
            }
        } else if ins & 0x7e000000 == 0x36000000 {
            // TBZ/TBNZ
            let bit = ((ins >> 31) << 5) | ((ins >> 19) & 31);
            if (self.x(rd) & (1 << bit) != 0) == (ins & (1 << 24) != 0) {
                next = pc.wrapping_add(sign_extend((((ins >> 5) & 0x3fff) as u64) << 2, 16));
            }
        } else if ins & 0x1f000000 == 0x1b000000 {
            // multiply/add, long multiply, high multiply
            if ins & 0x60000000 != 0 {
                return Err(invalid());
            }
            let opcode = (ins >> 21) & 7;
            let ra = ((ins >> 10) & 31) as usize;
            let sub = ins & (1 << 15) != 0;
            let product = match opcode {
                0 => self.x(rn).wrapping_mul(self.x(rm)),
                1 if wide => (self.x(rn) as u32 as i32 as i64)
                    .wrapping_mul(self.x(rm) as u32 as i32 as i64)
                    as u64,
                5 if wide => (self.x(rn) as u32 as u64) * (self.x(rm) as u32 as u64),
                2 if wide && !sub => {
                    ((self.x(rn) as i64 as i128 * self.x(rm) as i64 as i128) >> 64) as u64
                }
                6 if wide && !sub => ((self.x(rn) as u128 * self.x(rm) as u128) >> 64) as u64,
                _ => return Err(invalid()),
            };
            let value = if opcode == 2 || opcode == 6 {
                product
            } else if sub {
                self.x(ra).wrapping_sub(product)
            } else {
                self.x(ra).wrapping_add(product)
            };
            self.put(rd, value, wide, false);
        } else if ins & 0x5fe00000 == 0x1ac00000 {
            // division and variable shifts
            if ins & (1 << 29) != 0 {
                return Err(invalid());
            }
            let a = self.x(rn) & mask;
            let b = self.x(rm) & mask;
            let value = match (ins >> 10) & 63 {
                2 => {
                    if b == 0 {
                        0
                    } else {
                        a / b
                    }
                }
                3 if b == 0 => 0,
                3 if wide => (a as i64).wrapping_div(b as i64) as u64,
                3 => (a as u32 as i32).wrapping_div(b as u32 as i32) as u32 as u64,
                opcode @ 8..=11 => shifted(a, opcode - 8, (b & (bits as u64 - 1)) as u32, wide),
                _ => return Err(invalid()),
            };
            self.put(rd, value, wide, false);
        } else if ins & 0x7fe00000 == 0x5ac00000 {
            // RBIT/REV/CLZ/CLS
            if rm != 0 {
                return Err(invalid());
            }
            let value = self.x(rn) & mask;
            let result = match (ins >> 10) & 63 {
                0 if wide => value.reverse_bits(),
                0 => (value as u32).reverse_bits() as u64,
                1 => {
                    let bytes = value.to_le_bytes();
                    let mut out = [0; 8];
                    for i in (0..8).step_by(2) {
                        out[i] = bytes[i + 1];
                        out[i + 1] = bytes[i];
                    }
                    u64::from_le_bytes(out)
                }
                2 => {
                    (value as u32).swap_bytes() as u64
                        | (((value >> 32) as u32).swap_bytes() as u64) << 32
                }
                3 if wide => value.swap_bytes(),
                4 if wide => value.leading_zeros() as u64,
                4 => (value as u32).leading_zeros() as u64,
                5 if wide => {
                    (if value >> 63 != 0 { !value } else { value }).leading_zeros() as u64 - 1
                }
                5 => {
                    (if value & (1 << 31) != 0 {
                        !(value as u32)
                    } else {
                        value as u32
                    })
                    .leading_zeros() as u64
                        - 1
                }
                _ => return Err(invalid()),
            };
            self.put(rd, result, wide, false);
        } else if ins & 0x1fe0fc00 == 0x1a000000 {
            // ADC/SBC
            let a = self.x(rn) & mask;
            let rhs = self.x(rm) & mask;
            let b = if ins & (1 << 30) != 0 {
                !rhs & mask
            } else {
                rhs
            };
            let sum = a as u128 + b as u128 + self.condition_flags.carry() as u128;
            let value = sum as u64 & mask;
            if ins & (1 << 29) != 0 {
                let sign = 1 << (bits - 1);
                self.set_flags(Flags {
                    n: value & sign != 0,
                    z: value == 0,
                    c: sum > mask as u128,
                    v: !(a ^ b) & (a ^ value) & sign != 0,
                });
            }
            self.put(rd, value, wide, false);
        } else if ins & 0xffffffe0 == 0xd53bd040 {
            self.set_x(rd, self.tpidr_el0);
        } else if ins & 0xffffffe0 == 0xd51bd040 {
            self.tpidr_el0 = self.x(rd);
        } else if ins & 0xffffffe0 == 0xd53bd060 {
            self.set_x(rd, 0); // Linux virtual read-only TLS register.
        } else if ins & 0xffffffe0 == 0xd53b0020 {
            // Virtual 64-byte I/D lines, with automatic instruction coherence.
            self.set_x(rd, 0xb4448004);
        } else if ins & 0xffffffe0 == 0xd53be000 {
            self.set_x(rd, crate::counter::frequency());
        } else if matches!(
            ins & 0xffffffe0,
            0xd53be040 | 0xd53be020 | 0xd53be0c0 | 0xd53be0a0
        ) {
            self.set_x(rd, crate::counter::read());
        } else if ins & 0xffffffe0 == 0xd53bd0a0 {
            self.set_x(rd, self.tpidr2_el0);
        } else if ins & 0xffffffe0 == 0xd51bd0a0 {
            self.tpidr2_el0 = self.x(rd);
        } else if ins & 0xffffffe0 == 0xd53b4200 {
            self.set_x(rd, (self.nzcv() as u64) << 28);
        } else if ins & 0xffffffe0 == 0xd51b4200 {
            self.set_nzcv((self.x(rd) >> 28) as u32 & 15);
        } else if ins & 0xffffffe0 == 0xd53b4400 {
            self.set_x(rd, self.fpcr as u64);
        } else if ins & 0xffffffe0 == 0xd53b4420 {
            self.fpsr |= trames_compute::status();
            self.set_x(rd, self.fpsr as u64);
        } else if ins & 0xffffffe0 == 0xd51b4400 {
            // RMode, FZ, DN, AHP and FZ16; trap enables remain RAZ/WI.
            self.fpcr = self.x(rd) as u32 & 0x07c80000;
            trames_compute::set_control(self.fpcr);
        } else if ins & 0xffffffe0 == 0xd51b4420 {
            self.fpsr = self.x(rd) as u32 & 0x0800009f;
            trames_compute::set_status(self.fpsr);
        } else if ins & 0xffffffe0 == 0xd53b00e0 {
            self.set_x(rd, 4);
        }
        // DCZID_EL0: 64-byte guest blocks
        else if ins & 0xffffffe0 == 0xd50b7420 {
            let address = self.x(rd) & !63;
            memory
                .write(address, &[0; 64])
                .map_err(|error| CpuFault::Memory { pc, error })?;
        } else if matches!(
            ins & 0xffffffe0,
            0xd50b7b20 | 0xd50b7a20 | 0xd50b7e20 | 0xd50b7520
        ) {
            // CVAU/CVAC/CIVAC/IVAU: guest code writes are already coherent;
            // preserve address-translation faults without touching host caches.
            memory
                .check_translation(self.x(rd))
                .map_err(|error| CpuFault::Memory { pc, error })?;
        } else if matches!(ins & 0xfffff0ff, 0xd503309f | 0xd50330bf | 0xd50330df)
            || matches!(
                ins,
                0xd503203f
                    | 0xd503205f
                    | 0xd503209f
                    | 0xd50320bf
                    | 0xd503221f
                    | 0xd503229f
                    | 0xd503211f
                    | 0xd503215f
                    | 0xd503219f
                    | 0xd50321df
                    | 0xd503231f
                    | 0xd503235f
                    | 0xd503239f
                    | 0xd50323df
                    | 0xd503241f
                    | 0xd503245f
                    | 0xd503249f
                    | 0xd50324df
                    | 0xd503251f // CHKFEAT: GCS disabled, HINT preserves X16.
                    | 0xd503233f
                    | 0xd503237f
                    | 0xd50323bf
                    | 0xd50323ff
                    | 0xd50320ff
            )
        {
            // Conservatively use a full host fence for all architectural DMB/DSB
            // domains/types and ISB. Hints do not receive an invented barrier.
            if matches!(ins & 0xfffff0ff, 0xd503309f | 0xd50330bf | 0xd50330df) {
                memory.fence(std::sync::atomic::Ordering::SeqCst);
            }
        } else if ins & 0xbfe0fc00 == 0x0e000400 {
            // DUP vector from a selected vector lane, including source aliases.
            let imm5 = (ins >> 16) & 31;
            if imm5 == 0 || imm5.trailing_zeros() > 3 {
                return Err(invalid());
            }
            let power = imm5.trailing_zeros();
            let bits = 8 << power;
            let width = if ins & (1 << 30) != 0 { 128 } else { 64 };
            if bits == 64 && width == 64 {
                return Err(invalid());
            }
            let lane = imm5 >> (power + 1);
            let value = (self.vectors[rn] >> (lane * bits)) & ones(bits) as u128;
            let mut result = 0;
            for index in 0..width / bits {
                result |= value << (index * bits);
            }
            self.vectors[rd] = result;
        } else if ins & 0xbfe0fc00 == 0x0e000c00 {
            // DUP vector from GPR
            let imm5 = (ins >> 16) & 31;
            if imm5 == 0 {
                return Err(invalid());
            }
            let element_bits = 8u32 << imm5.trailing_zeros();
            let vector_bits = if ins & (1 << 30) != 0 { 128 } else { 64 };
            if element_bits > 64 || (element_bits == 64 && vector_bits == 64) {
                return Err(invalid());
            }
            let value = (self.x(rn) & ones(element_bits)) as u128;
            let mut result = 0;
            for offset in (0..vector_bits).step_by(element_bits as usize) {
                result |= value << offset;
            }
            self.vectors[rd] = result;
        } else if matches!(
            ins & 0xfffffc00,
            0x9e660000 | 0x1e260000 | 0x1ee60000 | 0x9ee60000
        ) {
            // FMOV GPR <- scalar bits
            let bits = self.vectors[rn] as u64
                & if ins & (1 << 23) != 0 {
                    0xffff
                } else {
                    u64::MAX
                };
            self.put(rd, bits, ins >> 31 != 0, false);
        } else if matches!(
            ins & 0xfffffc00,
            0x9e670000 | 0x1e270000 | 0x1ee70000 | 0x9ee70000
        ) {
            // FMOV scalar <- GPR bits
            self.vectors[rd] = (self.x(rn)
                & if ins & (1 << 23) != 0 {
                    0xffff
                } else {
                    width_mask(ins >> 31 != 0)
                }) as u128;
        } else if ins & 0xfffffc00 == 0x1e604000 {
            self.vectors[rd] = self.vectors[rn] & u64::MAX as u128;
        } else if matches!(
            ins & 0x9f80fc00,
            0x0f000400 | 0x0f001400 | 0x0f002400 | 0x0f003400 | 0x0f004400 | 0x0f005400
        ) && ins & 0x00780000 != 0
        {
            // Integer shift-immediate, rounded/accumulating and bit insertion.
            let immediate = (ins >> 16) & 127;
            let bits = 1 << (31 - immediate.leading_zeros());
            let width = if ins & (1 << 30) != 0 { 128 } else { 64 };
            let unsigned = ins & (1 << 29) != 0;
            let opcode = (ins >> 12) & 7;
            if bits == 64 && width == 64 || opcode == 4 && !unsigned {
                return Err(invalid());
            }
            let mask = ones(bits);
            let shift = if opcode == 5 {
                immediate - bits
            } else {
                2 * bits - immediate
            };
            let source = self.vectors[rn];
            let destination = self.vectors[rd];
            let mut result = 0;
            for lane in 0..width / bits {
                let offset = lane * bits;
                let a = (source >> offset) as u64 & mask;
                let old = (destination >> offset) as u64 & mask;
                let value = if opcode == 5 {
                    let value = a.wrapping_shl(shift);
                    if unsigned {
                        value | (old & ones(shift))
                    } else {
                        value
                    }
                } else if opcode == 4 {
                    let lower = if shift == bits { 0 } else { a >> shift };
                    lower | (old & !ones(bits - shift))
                } else {
                    let rounding = if opcode & 2 != 0 {
                        1i128 << (shift - 1)
                    } else {
                        0
                    };
                    let value = if unsigned {
                        a as i128
                    } else {
                        sign_extend(a, bits) as i64 as i128
                    };
                    let shifted = ((value + rounding) >> shift) as u64;
                    if opcode & 1 != 0 {
                        shifted.wrapping_add(old)
                    } else {
                        shifted
                    }
                } & mask;
                result |= (value as u128) << offset;
            }
            self.vectors[rd] = result;
        } else if ins & 0x9f80fc00 == 0x0f00a400 && ins & 0x00780000 != 0 {
            // SSHLL/USHLL, including SXTL/UXTL and the upper-half forms.
            let immh = (ins >> 19) & 15;
            if immh == 0 || immh & 8 != 0 {
                return Err(invalid());
            }
            let size = 8u32 << (31 - immh.leading_zeros());
            let shift = ((ins >> 16) & 127) - size;
            let source = self.vectors[rn] >> (if ins & (1 << 30) != 0 { 64 } else { 0 });
            let mut result = 0u128;
            for lane in 0..64 / size {
                let value = ((source >> (lane * size)) as u64) & ones(size);
                let value = if ins & (1 << 29) == 0 {
                    sign_extend(value, size)
                } else {
                    value
                };
                result |=
                    ((value.wrapping_shl(shift) & ones(size * 2)) as u128) << (lane * size * 2);
            }
            self.vectors[rd] = result;
        } else if ins & 0x9ff80c00 == 0x0f000400 {
            // AdvSIMD modified immediate (integer modes)
            let imm = ((((ins >> 16) & 7) << 5) | ((ins >> 5) & 31)) as u64;
            let mode = (ins >> 12) & 15;
            let op = ins & (1 << 29) != 0;
            let (element, size) = match mode {
                0..=7 => (imm << ((mode >> 1) * 8), 32),
                8..=11 => (imm << (((mode >> 1) & 1) * 8), 16),
                12 => ((imm << 8) | 255, 32),
                13 => ((imm << 16) | 65535, 32),
                14 if !op => (imm, 8),
                14 => {
                    let mut value = 0;
                    for i in 0..8 {
                        if imm & (1 << i) != 0 {
                            value |= 255 << (i * 8);
                        }
                    }
                    (value, 64)
                }
                _ => return Err(invalid()),
            };
            let mut value = 0u128;
            for offset in (0..128).step_by(size) {
                value |= (element as u128) << offset;
            }
            let merge = mode < 12 && mode & 1 != 0;
            if merge {
                value = if op {
                    self.vectors[rd] & !value
                } else {
                    self.vectors[rd] | value
                };
            } else if op && mode != 14 {
                value = !value;
            }
            self.vectors[rd] = if ins & (1 << 30) != 0 {
                value
            } else {
                value & u64::MAX as u128
            };
        } else if matches!(ins & 0xbfe0fc00, 0x0e003c00 | 0x0e002c00) {
            // UMOV/SMOV to GPR
            let imm5 = (ins >> 16) & 31;
            if imm5 == 0 {
                return Err(invalid());
            }
            let power = imm5.trailing_zeros();
            let size = 8 << power;
            let index = imm5 >> (power + 1);
            let x = ins & (1 << 30) != 0;
            let signed = ins & 0x1000 == 0;
            if size > 64
                || index * size >= 128
                || (signed && size >= if x { 64 } else { 32 })
                || (!signed && ((x && size != 64) || (!x && size > 32)))
            {
                return Err(invalid());
            }
            let mut value = (self.vectors[rn] >> (index * size)) as u64 & ones(size);
            if signed {
                value = sign_extend(value, size);
            }
            self.put(rd, value, x, false);
        } else if ins & 0xbfe08c00 == 0x0e000000 {
            // TBL/TBX, one to four 128-bit tables, with register-number wrap.
            let bytes = if ins & (1 << 30) != 0 { 16 } else { 8 };
            let tables = ((ins >> 13) & 3) + 1;
            let mut result = if ins & 0x1000 != 0 {
                self.vectors[rd]
            } else {
                0
            };
            if bytes == 8 {
                result &= u64::MAX as u128;
            }
            for lane in 0..bytes {
                let index = ((self.vectors[rm] >> (lane * 8)) & 255) as u32;
                if index < tables * 16 {
                    let source = (rn + (index / 16) as usize) & 31;
                    let value = (self.vectors[source] >> ((index % 16) * 8)) & 255;
                    result = (result & !(255u128 << (lane * 8))) | (value << (lane * 8));
                }
            }
            self.vectors[rd] = result;
        } else if matches!(
            ins & 0xbf20fc00,
            0x0e208400
                | 0x2e208400
                | 0x2e208c00
                | 0x0e203400
                | 0x0e203c00
                | 0x2e203400
                | 0x2e203c00
                | 0x0e208c00
                | 0x0e20bc00
        ) || matches!(ins & 0xbf3ffc00, 0x0e20b800 | 0x2e20b800)
        {
            let size = (ins >> 22) & 3;
            let width = if ins & (1 << 30) != 0 { 128 } else { 64 };
            if size == 3 && width == 64 {
                return Err(invalid());
            }
            let bits = 8 << size;
            let lanes = width / bits;
            let mask = ones(bits);
            let operation = ins & 0xbf20fc00;
            use trames_compute::IntegerOp as I;
            let native = match operation {
                0x0e208400 => I::Add,
                0x2e208400 => I::Sub,
                0x0e20bc00 => I::PairAdd,
                0x2e208c00 => I::Equal,
                0x0e208c00 => I::Test,
                0x0e203400 => I::SignedGreater,
                0x0e203c00 => I::SignedGreaterEqual,
                0x2e203400 => I::UnsignedGreater,
                0x2e203c00 => I::UnsignedGreaterEqual,
                0x0e20b800 => I::Abs,
                0x2e20b800 => I::Neg,
                _ => unreachable!(),
            };
            if let Some(value) = trames_compute::vector_integer(
                bits,
                width == 128,
                native,
                self.vectors[rn],
                self.vectors[rm],
                self.vectors[rd],
            ) {
                self.vectors[rd] = value;
                return Ok(Some(next));
            }
            let mut result = 0u128;
            for lane in 0..lanes {
                let (a, b) = if operation == 0x0e20bc00 {
                    let source = if lane < lanes / 2 {
                        self.vectors[rn]
                    } else {
                        self.vectors[rm]
                    };
                    let offset = (lane % (lanes / 2)) * 2 * bits;
                    (
                        (source >> offset) as u64 & mask,
                        (source >> (offset + bits)) as u64 & mask,
                    )
                } else {
                    (
                        (self.vectors[rn] >> (lane * bits)) as u64 & mask,
                        (self.vectors[rm] >> (lane * bits)) as u64 & mask,
                    )
                };
                let a_signed = sign_extend(a, bits) as i64;
                let b_signed = sign_extend(b, bits) as i64;
                let value = match operation {
                    0x0e208400 | 0x0e20bc00 => a.wrapping_add(b),
                    0x2e208400 => a.wrapping_sub(b),
                    0x2e208c00 => {
                        if a == b {
                            mask
                        } else {
                            0
                        }
                    }
                    0x0e203400 => {
                        if a_signed > b_signed {
                            mask
                        } else {
                            0
                        }
                    }
                    0x0e203c00 => {
                        if a_signed >= b_signed {
                            mask
                        } else {
                            0
                        }
                    }
                    0x2e203400 => {
                        if a > b {
                            mask
                        } else {
                            0
                        }
                    }
                    0x2e203c00 => {
                        if a >= b {
                            mask
                        } else {
                            0
                        }
                    }
                    0x0e208c00 => {
                        if a & b != 0 {
                            mask
                        } else {
                            0
                        }
                    }
                    0x0e20b800 => a_signed.wrapping_abs() as u64,
                    0x2e20b800 => a.wrapping_neg(),
                    _ => unreachable!(),
                } & mask;
                result |= (value as u128) << (lane * bits);
            }
            self.vectors[rd] = result;
        } else if ins & 0xbf3ffc00 == 0x0e212800 {
            // XTN/XTN2 truncates each wide lane; XTN2 retains the low half.
            let size = (ins >> 22) & 3;
            if size == 3 {
                return Err(invalid());
            }
            let bits = 8 << size;
            let mut result = 0u128;
            for lane in 0..64 / bits {
                result |=
                    ((self.vectors[rn] >> (lane * bits * 2)) & ones(bits) as u128) << (lane * bits);
            }
            self.vectors[rd] = if ins & (1 << 30) != 0 {
                (self.vectors[rd] & u64::MAX as u128) | (result << 64)
            } else {
                result
            };
        } else if matches!(
            ins & 0xbf20fc00,
            0x0e001800 | 0x0e005800 | 0x0e002800 | 0x0e006800 | 0x0e003800 | 0x0e007800
        ) {
            // UZP1/2, TRN1/2 and ZIP1/2, with alias-safe source snapshots.
            let size = (ins >> 22) & 3;
            let vector_bits = if ins & (1 << 30) != 0 { 128 } else { 64 };
            if size == 3 && vector_bits == 64 {
                return Err(invalid());
            }
            let element_bits = 8 << size;
            let lanes = vector_bits / element_bits;
            let part = (ins >> 14) & 1;
            let operation = (ins >> 12) & 3;
            let lane_mask = ones(element_bits) as u128;
            let mut result = 0;
            for lane in 0..lanes {
                let (source, index) = match operation {
                    1 => (
                        if lane < lanes / 2 { rn } else { rm },
                        (lane % (lanes / 2)) * 2 + part,
                    ),
                    2 => (if lane % 2 == 0 { rn } else { rm }, (lane / 2) * 2 + part),
                    3 => (
                        if lane % 2 == 0 { rn } else { rm },
                        lane / 2 + part * (lanes / 2),
                    ),
                    _ => unreachable!(),
                };
                result |= ((self.vectors[source] >> (index * element_bits)) & lane_mask)
                    << (lane * element_bits);
            }
            self.vectors[rd] = result;
        } else if matches!(ins & 0xbf20fc00, 0x0e204400 | 0x2e204400) {
            // SSHL/USHL: shift distance is the signed low byte of each lane.
            let size = (ins >> 22) & 3;
            let vector_bits = if ins & (1 << 30) != 0 { 128 } else { 64 };
            if size == 3 && vector_bits == 64 {
                return Err(invalid());
            }
            let element_bits = 8 << size;
            let signed = ins & (1 << 29) == 0;
            let lane_mask = ones(element_bits);
            let mut result = 0u128;
            for lane in 0..vector_bits / element_bits {
                let offset = lane * element_bits;
                let value = (self.vectors[rn] >> offset) as u64 & lane_mask;
                let shift = (self.vectors[rm] >> offset) as u8 as i8 as i32;
                let value = if shift >= element_bits as i32 {
                    0
                } else if shift >= 0 {
                    value.wrapping_shl(shift as u32) & lane_mask
                } else if signed {
                    (sign_extend(value, element_bits) as i64
                        >> ((-shift) as u32).min(element_bits - 1)) as u64
                        & lane_mask
                } else if -shift >= element_bits as i32 {
                    0
                } else {
                    value >> (-shift as u32)
                };
                result |= (value as u128) << offset;
            }
            self.vectors[rd] = result;
        } else if ins & 0xffe08400 == 0x6e000400 {
            // INS element from another vector; both operands are read before
            // modifying the destination, including overlapping source lanes.
            let imm5 = (ins >> 16) & 31;
            if imm5 == 0 {
                return Err(invalid());
            }
            let power = imm5.trailing_zeros();
            if power > 3 {
                return Err(invalid());
            }
            let element_bits = 8u32 << power;
            let destination = imm5 >> (power + 1);
            let imm4 = (ins >> 11) & 15;
            // Bits below the element-size selector are architecturally ignored.
            let source = imm4 >> power;
            let lane_mask = (1u128 << element_bits) - 1;
            let value = (self.vectors[rn] >> (source * element_bits)) & lane_mask;
            let shift = destination * element_bits;
            self.vectors[rd] = (self.vectors[rd] & !(lane_mask << shift)) | (value << shift);
        } else if ins & 0xffe0fc00 == 0x4e001c00 {
            // INS vector lane from GPR
            let imm5 = (ins >> 16) & 31;
            if imm5 == 0 {
                return Err(invalid());
            }
            let power = imm5.trailing_zeros();
            let size = 8 << power;
            let index = imm5 >> (power + 1);
            if size > 64 || index * size >= 128 {
                return Err(invalid());
            }
            let offset = index * size;
            let lane_mask = (ones(size) as u128) << offset;
            self.vectors[rd] =
                (self.vectors[rd] & !lane_mask) | (((self.x(rn) & ones(size)) as u128) << offset);
        } else if matches!(
            ins & 0xbf20fc00,
            0x0e20a400 | 0x0e20ac00 | 0x2e20a400 | 0x2e20ac00
        ) {
            // SMAXP/SMINP/UMAXP/UMINP, integer pairwise reductions.
            let size = (ins >> 22) & 3;
            if size == 3 {
                return Err(invalid());
            }
            let bits = 8 << size;
            let vector_bits = if ins & (1 << 30) != 0 { 128 } else { 64 };
            let lanes = vector_bits / bits;
            let signed = ins & (1 << 29) == 0;
            let maximum = ins & 0x800 == 0;
            let mut result = 0u128;
            for (source_index, source) in
                [self.vectors[rn], self.vectors[rm]].into_iter().enumerate()
            {
                for pair in 0..lanes / 2 {
                    let a = ((source >> (2 * pair * bits)) as u64) & ones(bits);
                    let b = ((source >> ((2 * pair + 1) * bits)) as u64) & ones(bits);
                    let less = if signed {
                        (sign_extend(a, bits) as i64) < (sign_extend(b, bits) as i64)
                    } else {
                        a < b
                    };
                    let value = if less == maximum { b } else { a };
                    result |= (value as u128) << ((source_index as u32 * lanes / 2 + pair) * bits);
                }
            }
            self.vectors[rd] = result;
        } else if matches!(ins & 0xbfe0fc00, 0x0e201c00 | 0x0ea01c00 | 0x2e201c00) {
            // vector AND/ORR/EOR
            let value = match ins & 0xbfe0fc00 {
                0x0e201c00 => self.vectors[rn] & self.vectors[rm],
                0x0ea01c00 => self.vectors[rn] | self.vectors[rm],
                _ => self.vectors[rn] ^ self.vectors[rm],
            };
            self.vectors[rd] = if ins & (1 << 30) != 0 {
                value
            } else {
                value & u64::MAX as u128
            };
        } else if ins & 0xfffff0ff == 0xd503305f {
            self.clear_exclusive();
        } else if self.execute_memory(ins, memory)? {
        } else {
            return Ok(None);
        }
        Ok(Some(next))
    }
}

#[cfg(test)]
use trames_memory::Memory;
#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn reserved_pairwise_integer_size_faults_without_changing_registers() {
        let mut cpu = Cpu::default();
        cpu.vectors[0] = 0x1234;
        cpu.vectors[1] = 0x5678;
        let before = cpu.vectors;
        assert!(matches!(
            cpu.execute_extended(0x6ee1a400, &mut Memory::default()),
            Err(CpuFault::Instruction { .. })
        ));
        assert_eq!(cpu.vectors, before);
    }
    fn execute(ins: u32, a: u64, b: u64) -> Cpu {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, &ins.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut c = Cpu::new(0x1000, 0);
        c.set_x(0, a);
        c.set_x(1, b);
        c.step(&mut m).unwrap();
        c
    }
    #[test]
    fn signed_division_overflow_and_zero_divisors_follow_aarch64() {
        assert_eq!(
            execute(0x9ac10c00, i64::MIN as u64, u64::MAX).x(0),
            i64::MIN as u64
        );
        assert_eq!(execute(0x1ac10c00, 0x80000000, 0xffffffff).x(0), 0x80000000);
        assert_eq!(execute(0x9ac10800, 123, 0).x(0), 0);
    }
    #[test]
    fn signed_bitfield_and_bit_reversal_preserve_width_semantics() {
        assert_eq!(execute(0x93401c20, 0, 0x85).x(0), 0xffffffffffffff85);
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        m.write(0x1000, &0x5ac00339u32.to_le_bytes()).unwrap();
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let mut c = Cpu::new(0x1000, 0);
        c.set_x(25, 1);
        c.step(&mut m).unwrap();
        assert_eq!(c.x(25), 0x80000000);
    }
}
