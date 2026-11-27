// SPDX-License-Identifier: GPL-3.0-or-later
use super::{Cpu, CpuFault};
use crate::soft_float::{Format, ALTERNATIVE_HALF, DOUBLE, HALF, INEXACT, SINGLE};

impl Cpu {
    pub fn vector(&self, index: usize) -> u128 {
        self.vectors[index]
    }
    pub fn set_vector(&mut self, index: usize, bits: u128) {
        self.vectors[index] = bits;
    }
    pub(crate) fn execute_floating(&mut self, ins: u32) -> Result<bool, CpuFault> {
        if self.execute_vector_extra_float(ins)? {
            return Ok(true);
        }
        if self.execute_vector_float(ins)? {
            return Ok(true);
        }
        let invalid = || CpuFault::Instruction {
            pc: self.pc,
            instruction: ins,
        };
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        if ins & 0xfffffc00 == 0x1e7e0000 {
            // JavaScript truncation wraps modulo 2^32, with exactness in NZCV.Z.
            let mut flags = 0;
            let x = DOUBLE.unpack(self.vectors[rn] as u64, self.fpcr, &mut flags);
            let mut value = 0u32;
            if x.nan || x.inf {
                flags |= crate::soft_float::INVALID;
            } else {
                let limit = if x.sign {
                    1u128 << 31
                } else {
                    (1u128 << 31) - 1
                };
                let overflow;
                if x.exp >= 0 {
                    value = if x.exp < 32 {
                        (x.sig as u32).wrapping_shl(x.exp as u32)
                    } else {
                        0
                    };
                    overflow = x.sig != 0 && (x.exp >= 32 || x.sig > (limit >> x.exp));
                } else {
                    let distance = (-x.exp) as u32;
                    let magnitude = x.sig.checked_shr(distance).unwrap_or(0);
                    let lost = if distance >= 128 {
                        x.sig != 0
                    } else {
                        x.sig & ((1u128 << distance) - 1) != 0
                    };
                    value = magnitude as u32;
                    overflow = magnitude > limit;
                    if lost {
                        flags |= INEXACT;
                    }
                }
                if overflow {
                    flags = (flags & !INEXACT) | crate::soft_float::INVALID;
                }
                if x.sign {
                    value = value.wrapping_neg();
                }
            }
            self.set_x(rd, value as u64);
            self.set_nzcv(if flags == 0 && x.raw != 0x8000000000000000 {
                4
            } else {
                0
            });
            self.fpsr |= flags;
            return Ok(true);
        }
        let scalar_conversion = ins & 0xffbffc00;
        if matches!(
            scalar_conversion,
            0x5e21d800 | 0x7e21d800 | 0x5ea1b800 | 0x7ea1b800
        ) {
            let width = if ins & (1 << 22) != 0 { 64 } else { 32 };
            let fmt = if width == 64 { DOUBLE } else { SINGLE };
            let mut flags = 0;
            let raw = self.vectors[rn] as u64;
            let unsigned = ins & (1 << 29) != 0;
            let value = if scalar_conversion & 0x00800000 != 0 {
                let input = fmt.unpack(raw, self.fpcr, &mut flags);
                fmt.to_integer(input, width, unsigned, 0, 3, &mut flags)
            } else {
                let integer = if width == 32 { raw as u32 as u64 } else { raw };
                let signed = if width == 32 {
                    integer as i32 as i64
                } else {
                    integer as i64
                };
                let sign = !unsigned && signed < 0;
                let magnitude = if unsigned {
                    integer as u128
                } else {
                    signed.unsigned_abs() as u128
                };
                fmt.pack(
                    sign,
                    magnitude,
                    0,
                    (self.fpcr >> 22) & 3,
                    self.fpcr,
                    &mut flags,
                )
            };
            self.vectors[rd] = (if width == 32 {
                value & u32::MAX as u64
            } else {
                value
            }) as u128;
            self.fpsr |= flags;
            return Ok(true);
        }
        if matches!(ins & 0xdf80fc00, 0x5f005400 | 0x5f000400) {
            let immediate = (ins >> 16) & 127;
            if immediate < 64 {
                return Err(invalid());
            }
            let v = self.vectors[rn] as u64;
            let value = if ins & 0xfc00 == 0x5400 {
                v << (immediate - 64)
            } else if ins & (1 << 29) != 0 {
                if immediate == 64 {
                    0
                } else {
                    v >> (128 - immediate)
                }
            } else {
                ((v as i64) >> (128 - immediate).min(63)) as u64
            };
            self.vectors[rd] = value as u128;
            return Ok(true);
        }
        if ins & 0xfffffc00 == 0x9eae0000 {
            self.set_x(rd, (self.vectors[rn] >> 64) as u64);
            return Ok(true);
        }
        if ins & 0xfffffc00 == 0x9eaf0000 {
            self.vectors[rd] = (self.vectors[rd] & u64::MAX as u128) | ((self.x(rn) as u128) << 64);
            return Ok(true);
        }
        let fmt: Format = match (ins >> 22) & 3 {
            0 => SINGLE,
            1 => DOUBLE,
            3 => HALF,
            _ => return Ok(false),
        };
        let fpcr = self.fpcr;
        let mode = (fpcr >> 22) & 3;
        let mut flags = 0;
        let a = fmt.unpack(self.vectors[rn] as u64, fpcr, &mut flags);
        let mut bflags = 0;
        let b = fmt.unpack(self.vectors[rm] as u64, fpcr, &mut bflags);
        let result;
        if ins & 0xff201fe0 == 0x1e201000 {
            let imm = (ins >> 13) & 255;
            let sign = (imm >> 7) as u64 * fmt.sign_bit();
            let e = (((imm >> 6) & 1) ^ 1) << fmt.ebits.saturating_sub(1)
                | if imm & 64 != 0 {
                    ((1 << (fmt.ebits - 3)) - 1) << 2
                } else {
                    0
                }
                | ((imm >> 4) & 3);
            result = sign | ((e as u64) << fmt.frac) | (((imm & 15) as u64) << (fmt.frac - 4));
            flags = 0;
        } else if ins & 0xff207c00 == 0x1e204000 {
            let op = (ins >> 15) & 63;
            result = match op {
                0 => {
                    flags = 0;
                    self.vectors[rn] as u64 & (fmt.sign_bit() | (fmt.sign_bit() - 1))
                }
                1 => {
                    flags = 0;
                    self.vectors[rn] as u64 & (fmt.sign_bit() - 1)
                }
                2 => {
                    flags = 0;
                    (self.vectors[rn] as u64 ^ fmt.sign_bit())
                        & (fmt.sign_bit() | (fmt.sign_bit() - 1))
                }
                3 => fmt.sqrt(a, mode, fpcr, &mut flags),
                4 | 5 | 7
                    if (op == 4 && fmt.frac != 23)
                        || (op == 5 && fmt.frac != 52)
                        || (op == 7 && fmt.frac != 10) =>
                {
                    let half = if fpcr & (1 << 26) != 0 {
                        ALTERNATIVE_HALF
                    } else {
                        HALF
                    };
                    let from = if fmt.frac == 10 { half } else { fmt };
                    let to = match op {
                        4 => SINGLE,
                        5 => DOUBLE,
                        _ => half,
                    };
                    // Conversions never flush half subnormals. AHP only affects
                    // format conversions; FP16 arithmetic always uses IEEE.
                    let control = fpcr & !(1 << 19);
                    flags = 0;
                    let input = from.unpack(self.vectors[rn] as u64, control, &mut flags);
                    to.convert(from, input, mode, control, &mut flags)
                }
                8..=12 | 14..=15 => {
                    let round = match op {
                        8 => 0,
                        9 => 1,
                        10 => 2,
                        11 => 3,
                        12 => 4,
                        _ => mode,
                    };
                    if let Some(n) = fmt.nan_result(&[a], fpcr, &mut flags) {
                        n
                    } else if a.inf || a.exp >= 0 {
                        a.raw
                    } else {
                        let (mag, lost) = fmt.rounded_integer(a, round);
                        if op == 14 && lost {
                            flags |= INEXACT;
                        }
                        fmt.pack(a.sign, mag, 0, 0, fpcr, &mut flags)
                    }
                }
                16..=19 if fmt.frac != 10 => fmt.round_integer_size(
                    a,
                    if op & 2 == 0 { 32 } else { 64 },
                    if op & 1 == 0 { 3 } else { mode },
                    fpcr,
                    &mut flags,
                ),
                _ => return Err(invalid()),
            };
        } else if ins & 0xff200c00 == 0x1e200800 {
            flags |= bflags;
            result = match (ins >> 12) & 15 {
                0 => fmt.mul(a, b, mode, fpcr, &mut flags),
                1 => fmt.div(a, b, mode, fpcr, &mut flags),
                2 => fmt.add(a, b, mode, fpcr, &mut flags),
                3 => fmt.sub(a, b, mode, fpcr, &mut flags),
                4..=7 => {
                    let op = (ins >> 12) & 15;
                    fmt.minmax(a, b, op & 1 != 0, op >= 6, fpcr, &mut flags)
                }
                8 => {
                    let r = fmt.mul(a, b, mode, fpcr, &mut flags);
                    r ^ fmt.sign_bit()
                }
                _ => return Err(invalid()),
            };
        } else if ins & 0xff000000 == 0x1f000000 {
            flags |= bflags;
            let c = fmt.unpack(
                self.vectors[((ins >> 10) & 31) as usize] as u64,
                fpcr,
                &mut flags,
            );
            let n1 = ins & (1 << 21) != 0;
            let n0 = ins & (1 << 15) != 0;
            result = fmt.fma(a, b, c, n1 ^ n0, n1, mode, fpcr, &mut flags);
        } else if ins & 0xff20fc07 == 0x1e202000 {
            let rhs = if ins & 8 != 0 {
                fmt.unpack(0, fpcr, &mut flags)
            } else {
                b
            };
            if ins & 8 != 0 && rm != 0 {
                return Err(invalid());
            }
            // Only operands selected by the instruction may contribute IDC.
            flags = 0;
            let lhs = fmt.unpack(self.vectors[rn] as u64, fpcr, &mut flags);
            let rhs = fmt.unpack(rhs.raw, fpcr, &mut flags);
            let nzcv = fmt.compare(lhs, rhs, ins & 16 != 0, &mut flags);
            self.set_nzcv(nzcv);
            self.fpsr |= flags;
            return Ok(true);
        } else if ins & 0xff200c00 == 0x1e200400 {
            flags |= bflags;
            let nzcv = if self.condition((ins >> 12) & 15) {
                fmt.compare(a, b, ins & 16 != 0, &mut flags)
            } else {
                flags = 0;
                ins & 15
            };
            self.set_nzcv(nzcv);
            self.fpsr |= flags;
            return Ok(true);
        } else if ins & 0xff200c00 == 0x1e200c00 {
            result = if self.condition((ins >> 12) & 15) {
                self.vectors[rn] as u64
            } else {
                self.vectors[rm] as u64
            } & (fmt.sign_bit() | (fmt.sign_bit() - 1));
            flags = 0;
        } else if ins & 0x7f200000 == 0x1e200000 && ins & 0xfc00 == 0 {
            let op = (ins >> 16) & 31;
            let width = if ins >> 31 != 0 { 64 } else { 32 };
            if op == 2 || op == 3 {
                let raw = self.x(rn)
                    & if width == 64 {
                        u64::MAX
                    } else {
                        u32::MAX as u64
                    };
                let sign = op == 2 && raw & (1u64 << (width - 1)) != 0;
                let mag = if sign {
                    if width == 64 {
                        raw.wrapping_neg()
                    } else {
                        (raw as u32).wrapping_neg() as u64
                    }
                } else {
                    raw
                };
                flags = 0;
                result = fmt.pack(sign, mag as u128, 0, mode, fpcr, &mut flags);
            } else if matches!(op, 0 | 1 | 4 | 5 | 8 | 9 | 16 | 17 | 24 | 25) {
                flags = 0;
                let a = fmt.unpack(self.vectors[rn] as u64, fpcr, &mut flags);
                let rounding = if op & 6 == 4 { 4 } else { (op >> 3) & 3 };
                let value = fmt.to_integer(a, width, op & 1 != 0, 0, rounding, &mut flags);
                self.put(rd, value, width == 64, false);
                self.fpsr |= flags;
                return Ok(true);
            } else {
                return Ok(false);
            }
        } else if ins & 0x7f200000 == 0x1e000000 {
            let op = (ins >> 16) & 31;
            let width = if ins >> 31 != 0 { 64 } else { 32 };
            let scale = 64 - ((ins >> 10) & 63);
            if scale > width {
                return Err(invalid());
            }
            flags = 0;
            if op == 2 || op == 3 {
                let raw = self.x(rn)
                    & if width == 64 {
                        u64::MAX
                    } else {
                        u32::MAX as u64
                    };
                let sign = op == 2 && raw & (1u64 << (width - 1)) != 0;
                let mag = if sign {
                    if width == 64 {
                        raw.wrapping_neg()
                    } else {
                        (raw as u32).wrapping_neg() as u64
                    }
                } else {
                    raw
                };
                result = fmt.pack(sign, mag as u128, -(scale as i32), mode, fpcr, &mut flags);
            } else if op == 24 || op == 25 {
                let a = fmt.unpack(self.vectors[rn] as u64, fpcr, &mut flags);
                let value = fmt.to_integer(a, width, op & 1 != 0, scale, 3, &mut flags);
                self.put(rd, value, width == 64, false);
                self.fpsr |= flags;
                return Ok(true);
            } else {
                return Err(invalid());
            }
        } else {
            return Ok(false);
        }
        self.vectors[rd] = result as u128;
        self.fpsr |= flags;
        Ok(true)
    }
}
