// SPDX-License-Identifier: GPL-3.0-or-later
use super::{Cpu, CpuFault};
use crate::soft_float::{Format, ALTERNATIVE_HALF, DOUBLE, HALF, SINGLE};
fn mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}
fn lane(value: u128, index: u32, bits: u32) -> u64 {
    (value >> (index * bits)) as u64 & mask(bits)
}
impl Cpu {
    pub(crate) fn execute_vector_extra_float(&mut self, ins: u32) -> Result<bool, CpuFault> {
        let scalar = ins & 0xdf000000 == 0x5e000000 || ins & 0xdf000000 == 0x5f000000;
        let normal = if scalar { ins & !(1 << 28) } else { ins };
        let invalid = || CpuFault::Instruction {
            pc: self.pc,
            instruction: ins,
        };
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let a = self.vectors[rn];
        let b = self.vectors[rm];
        let old = self.vectors[rd];
        let double = ins & (1 << 22) != 0;
        let bits = if double { 64 } else { 32 };
        let fmt = if double { DOUBLE } else { SINGLE };
        let fpcr = self.fpcr;
        let mode = (fpcr >> 22) & 3;
        let q = ins & (1 << 30) != 0;
        let width = if scalar {
            bits
        } else if q {
            128
        } else {
            64
        };
        let mut result = 0;
        let mut flags = 0;
        let unary = normal & 0xbfbffc00;
        let binary = normal & 0xbfa0fc00;
        if matches!(unary, 0x0ea1d800 | 0x2ea1d800) {
            if double && !q && !scalar {
                return Err(invalid());
            }
            for i in 0..width / bits {
                let x = fmt.unpack(lane(a, i, bits), fpcr, &mut flags);
                let value = estimate(fmt, x, unary == 0x2ea1d800, mode, fpcr, &mut flags);
                result |= (value as u128) << (i * bits);
            }
        } else if scalar && unary == 0x0ea1f800 {
            let x = fmt.unpack(a as u64, fpcr, &mut flags);
            result = if let Some(n) = fmt.nan_result(&[x], fpcr, &mut flags) {
                n as u128
            } else {
                let field = (x.raw >> fmt.frac) & ((1u64 << fmt.ebits) - 1);
                let exponent = if field == 0 {
                    (1u64 << fmt.ebits) - 2
                } else {
                    ((1u64 << fmt.ebits) - 1) ^ field
                };
                ((if x.sign { fmt.sign_bit() } else { 0 }) | (exponent << fmt.frac)) as u128
            };
        } else if !scalar && matches!(normal & 0xbffffc00, 0x0ea1c800 | 0x2ea1c800) {
            for i in 0..(if q { 4 } else { 2 }) {
                let raw = lane(a, i, 32) as u32;
                let v = if normal & 0xbffffc00 == 0x0ea1c800 {
                    if raw & (1 << 31) == 0 {
                        u32::MAX
                    } else {
                        reciprocal(raw >> 23) << 23
                    }
                } else if raw & 0xc0000000 == 0 {
                    u32::MAX
                } else {
                    reciprocal_sqrt(raw >> 23) << 23
                };
                result |= (v as u128) << (i * 32);
            }
        } else if matches!(binary, 0x0e20fc00 | 0x0ea0fc00) {
            if double && !q && !scalar {
                return Err(invalid());
            }
            if !scalar {
                let op = if binary == 0x0ea0fc00 {
                    trames_compute::VectorFloatOp::ReciprocalSqrtStep
                } else {
                    trames_compute::VectorFloatOp::ReciprocalStep
                };
                if let Some(value) = trames_compute::vector_float(bits, q, op, a, b, old) {
                    self.vectors[rd] = value;
                    return Ok(true);
                }
            }
            let square = binary == 0x0ea0fc00;
            for i in 0..width / bits {
                let left = lane(a, i, bits);
                let right = lane(b, i, bits);
                let op = if square {
                    trames_compute::FloatOp::ReciprocalSqrtStep
                } else {
                    trames_compute::FloatOp::ReciprocalStep
                };
                if let Some(value) = trames_compute::scalar(bits, op, left, right, 0) {
                    result |= (value as u128) << (i * bits);
                    continue;
                }
                let mut x = fmt.unpack(left, fpcr, &mut flags);
                let y = fmt.unpack(right, fpcr, &mut flags);
                let special = x.inf && !y.inf && !y.nan && y.sig == 0
                    || y.inf && !x.inf && !x.nan && x.sig == 0;
                let value = if special {
                    fmt.pack(
                        false,
                        if square { 3 } else { 2 },
                        if square { -1 } else { 0 },
                        mode,
                        fpcr,
                        &mut flags,
                    )
                } else {
                    let constant = fmt.pack(
                        false,
                        if square { 3 } else { 2 },
                        if square { -1 } else { 0 },
                        0,
                        fpcr,
                        &mut flags,
                    );
                    let c = fmt.unpack(constant, fpcr, &mut flags);
                    if square {
                        x.exp -= 1;
                    }
                    fmt.fma(x, y, c, true, false, mode, fpcr, &mut flags)
                };
                result |= (value as u128) << (i * bits);
            }
        } else if matches!(
            unary,
            0x0ea0c800 | 0x2ea0c800 | 0x0ea0d800 | 0x2ea0d800 | 0x0ea0e800
        ) {
            if double && !q && !scalar {
                return Err(invalid());
            }
            for i in 0..width / bits {
                let x = fmt.unpack(lane(a, i, bits), fpcr, &mut flags);
                let zero = fmt.unpack(0, fpcr, &mut flags);
                let cmp = fmt.compare(x, zero, unary != 0x0ea0d800, &mut flags);
                let yes = match unary {
                    0x0ea0c800 => cmp == 2,
                    0x2ea0c800 => cmp == 2 || cmp == 6,
                    0x0ea0d800 => cmp == 6,
                    0x2ea0d800 => cmp == 8 || cmp == 6,
                    _ => cmp == 8,
                };
                if yes {
                    result |= (mask(bits) as u128) << (i * bits);
                }
            }
        } else if matches!(
            unary,
            0x0e21a800
                | 0x2e21a800
                | 0x0ea1a800
                | 0x2ea1a800
                | 0x0e21b800
                | 0x2e21b800
                | 0x0e21c800
                | 0x2e21c800
        ) {
            if double && !q && !scalar {
                return Err(invalid());
            }
            if !scalar {
                use trames_compute::VectorFloatOp as V;
                let op = match unary {
                    0x0e21a800 => V::FloatToSignedNearest,
                    0x2e21a800 => V::FloatToUnsignedNearest,
                    0x0ea1a800 => V::FloatToSignedPositive,
                    0x2ea1a800 => V::FloatToUnsignedPositive,
                    0x0e21b800 => V::FloatToSignedNegative,
                    0x2e21b800 => V::FloatToUnsignedNegative,
                    0x0e21c800 => V::FloatToSignedAway,
                    _ => V::FloatToUnsignedAway,
                };
                if let Some(value) = trames_compute::vector_float(bits, q, op, a, b, old) {
                    self.vectors[rd] = value;
                    return Ok(true);
                }
            }
            let round = match unary & !(1 << 29) {
                0x0e21a800 => 0,
                0x0ea1a800 => 1,
                0x0e21b800 => 2,
                _ => 4,
            };
            for i in 0..width / bits {
                let x = fmt.unpack(lane(a, i, bits), fpcr, &mut flags);
                result |= ((fmt.to_integer(x, bits, ins & (1 << 29) != 0, 0, round, &mut flags)
                    & mask(bits)) as u128)
                    << (i * bits);
            }
        } else if matches!(
            normal & 0xbffffc00,
            0x0e617800 | 0x0e616800 | 0x2e616800 | 0x0e217800 | 0x0e216800
        ) && (!scalar || normal & 0xbffffc00 == 0x2e616800)
        {
            let widen = matches!(normal & 0xbffffc00, 0x0e617800 | 0x0e217800);
            let odd = ins & (1 << 29) != 0;
            let half = ins & (1 << 22) == 0;
            let half_fmt = if fpcr & (1 << 26) != 0 {
                ALTERNATIVE_HALF
            } else {
                HALF
            };
            let from = if widen {
                if half {
                    half_fmt
                } else {
                    SINGLE
                }
            } else if half {
                SINGLE
            } else {
                DOUBLE
            };
            let to = if widen {
                if half {
                    SINGLE
                } else {
                    DOUBLE
                }
            } else if half {
                half_fmt
            } else {
                SINGLE
            };
            let input_bits = if widen {
                if half {
                    16
                } else {
                    32
                }
            } else if half {
                32
            } else {
                64
            };
            let output_bits = if widen {
                input_bits * 2
            } else {
                input_bits / 2
            };
            let count = if scalar {
                1
            } else if half {
                4
            } else {
                2
            };
            let control = if half { fpcr & !(1 << 19) } else { fpcr };
            for i in 0..count {
                let x = from.unpack(
                    lane(a, i + if widen && q { count } else { 0 }, input_bits),
                    control,
                    &mut flags,
                );
                let mut local = 0;
                let value = if odd {
                    to.convert_odd(from, x, control, &mut local)
                } else {
                    to.convert(from, x, mode, control, &mut local)
                };
                flags |= local;
                result |= (value as u128) << (i * output_bits);
            }
            if !widen && q && !scalar {
                result = (old & u64::MAX as u128) | (result << 64);
            }
        } else if matches!(normal & 0x9f80fc00, 0x0f00e400 | 0x0f00fc00) && ins & 0x00780000 != 0 {
            let immediate = (ins >> 16) & 127;
            let width_bits = 1 << (31 - immediate.leading_zeros());
            if width_bits != 32 && width_bits != 64 || !scalar && width_bits == 64 && !q {
                return Err(invalid());
            }
            let from_integer = ins & 0xfc00 == 0xe400;
            let fmt = if width_bits == 64 { DOUBLE } else { SINGLE };
            let scale = 2 * width_bits - immediate;
            let active = if scalar {
                width_bits
            } else if q {
                128
            } else {
                64
            };
            let unsigned = ins & (1 << 29) != 0;
            for i in 0..active / width_bits {
                let raw = lane(a, i, width_bits);
                let value = if from_integer {
                    let negative = !unsigned && raw & (1u64 << (width_bits - 1)) != 0;
                    let magnitude = if negative {
                        raw.wrapping_neg() & mask(width_bits)
                    } else {
                        raw
                    };
                    fmt.pack(
                        negative,
                        magnitude as u128,
                        -(scale as i32),
                        mode,
                        fpcr,
                        &mut flags,
                    )
                } else {
                    let x = fmt.unpack(raw, fpcr, &mut flags);
                    fmt.to_integer(x, width_bits, unsigned, scale, 3, &mut flags) & mask(width_bits)
                };
                result |= (value as u128) << (i * width_bits);
            }
        } else if matches!(
            normal & 0xbf00f400,
            0x0f009000 | 0x0f001000 | 0x0f005000 | 0x2f009000
        ) {
            let size = (ins >> 22) & 3;
            if size != 2 && size != 3 || !scalar && size == 3 && !q {
                return Err(invalid());
            }
            let index = if size == 2 {
                (((ins >> 11) & 1) << 1) | ((ins >> 21) & 1)
            } else {
                if ins & (1 << 21) != 0 {
                    return Err(invalid());
                }
                (ins >> 11) & 1
            };
            let selected = fmt.unpack(lane(self.vectors[rm], index, bits), fpcr, &mut flags);
            for i in 0..width / bits {
                let x = fmt.unpack(lane(a, i, bits), fpcr, &mut flags);
                let op = normal & 0xbf00f400;
                let value = if op == 0x0f009000 {
                    fmt.mul(x, selected, mode, fpcr, &mut flags)
                } else if op == 0x2f009000 {
                    multiply_extended(fmt, x, selected, mode, fpcr, &mut flags)
                } else {
                    let acc = fmt.unpack(lane(old, i, bits), fpcr, &mut flags);
                    fmt.fma(
                        x,
                        selected,
                        acc,
                        op == 0x0f005000,
                        false,
                        mode,
                        fpcr,
                        &mut flags,
                    )
                };
                result |= (value as u128) << (i * bits);
            }
        } else if matches!(binary, 0x0e20dc00 | 0x2ea0d400) {
            if double && !q && !scalar {
                return Err(invalid());
            }
            for i in 0..width / bits {
                let x = fmt.unpack(lane(a, i, bits), fpcr, &mut flags);
                let y = fmt.unpack(lane(b, i, bits), fpcr, &mut flags);
                let value = if binary == 0x0e20dc00 {
                    multiply_extended(fmt, x, y, mode, fpcr, &mut flags)
                } else {
                    fmt.sub(x, y, mode, fpcr, &mut flags) & !fmt.sign_bit()
                };
                result |= (value as u128) << (i * bits);
            }
        } else if !scalar && matches!(binary, 0x2e20f400 | 0x2ea0f400 | 0x2e20c400 | 0x2ea0c400)
            || scalar && matches!(unary, 0x2e30f800 | 0x2eb0f800 | 0x2e30c800 | 0x2eb0c800)
        {
            if double && !q && !scalar {
                return Err(invalid());
            }
            let count = if scalar { 1 } else { width / bits };
            let source_lanes = if scalar { 2 } else { width / bits };
            for i in 0..count {
                let source = if scalar || i < source_lanes / 2 { a } else { b };
                let at = (i % (source_lanes / 2)) * 2;
                let x = fmt.unpack(lane(source, at, bits), fpcr, &mut flags);
                let y = fmt.unpack(lane(source, at + 1, bits), fpcr, &mut flags);
                let value = fmt.minmax(
                    x,
                    y,
                    ins & (1 << 23) != 0,
                    ins & 0x3000 == 0,
                    fpcr,
                    &mut flags,
                );
                result |= (value as u128) << (i * bits);
            }
        } else if !scalar && matches!(unary, 0x2e30f800 | 0x2eb0f800 | 0x2e30c800 | 0x2eb0c800) {
            if double || !q {
                return Err(invalid());
            }
            // ARM reduces (0,1) and (2,3) independently before the final pair;
            // this order matters for NaN payload selection and signed zero.
            let mut inputs = [fmt.unpack(0, fpcr, &mut flags); 4];
            for (i, x) in inputs.iter_mut().enumerate() {
                *x = fmt.unpack(lane(a, i as u32, 32), fpcr, &mut flags);
            }
            let min = ins & (1 << 23) != 0;
            let numeric = ins & 0x3000 == 0;
            let first = fmt.minmax(inputs[0], inputs[1], min, numeric, fpcr, &mut flags);
            let second = fmt.minmax(inputs[2], inputs[3], min, numeric, fpcr, &mut flags);
            let x = fmt.unpack(first, fpcr, &mut flags);
            let y = fmt.unpack(second, fpcr, &mut flags);
            result = fmt.minmax(x, y, min, numeric, fpcr, &mut flags) as u128;
        } else {
            return Ok(false);
        }
        self.vectors[rd] = result;
        self.fpsr |= flags;
        Ok(true)
    }
}
// ARM's fixed 8-bit estimate: integer arithmetic makes every result independent
// of native floating-point rounding modes and host vector extensions.
fn reciprocal(input: u32) -> u32 {
    (((1u32 << 19) / (2 * input + 1)) + 1) >> 1
}
fn reciprocal_sqrt(input: u32) -> u32 {
    let denominator = if input < 256 {
        2 * input + 1
    } else {
        2 * ((input & !1) + 1)
    };
    let mut low = 512u64;
    let mut high = 1024u64;
    while low < high {
        let middle = (low + high).div_ceil(2);
        if denominator as u64 * middle * middle < (1u64 << 28) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    low.div_ceil(2) as u32
}
pub(super) fn estimate(
    fmt: Format,
    x: crate::soft_float::Number,
    square: bool,
    mode: u32,
    fpcr: u32,
    flags: &mut u32,
) -> u64 {
    if let Some(n) = fmt.nan_result(&[x], fpcr, flags) {
        return n;
    }
    if !x.inf && x.sig == 0 {
        *flags |= crate::soft_float::DIVZERO;
        return fmt.infinity(x.sign);
    }
    if square && x.sign {
        *flags |= crate::soft_float::INVALID;
        return fmt.canonical();
    }
    if x.inf {
        return if x.sign { fmt.sign_bit() } else { 0 };
    }
    let top = 127 - x.sig.leading_zeros();
    let exponent = top as i32 + x.exp;
    let (magnitude, scale) = if square {
        let precision = if exponent & 1 == 0 { 7 } else { 8 };
        let input = if top >= precision {
            (x.sig >> (top - precision)) as u32
        } else {
            (x.sig << (precision - top)) as u32
        };
        (reciprocal_sqrt(input), -exponent.div_euclid(2) - 9)
    } else {
        let input = if top >= 8 {
            (x.sig >> (top - 8)) as u32
        } else {
            (x.sig << (8 - top)) as u32
        };
        (reciprocal(input), -exponent - 9)
    };
    fmt.pack(x.sign, magnitude as u128, scale, mode, fpcr, flags)
}
pub(super) fn multiply_extended(
    fmt: Format,
    a: crate::soft_float::Number,
    b: crate::soft_float::Number,
    mode: u32,
    fpcr: u32,
    flags: &mut u32,
) -> u64 {
    if let Some(value) = fmt.nan_result(&[a, b], fpcr, flags) {
        return value;
    }
    if a.inf && !b.inf && b.sig == 0 || b.inf && !a.inf && a.sig == 0 {
        return fmt.pack(a.sign ^ b.sign, 2, 0, mode, fpcr, flags);
    }
    fmt.mul(a, b, mode, fpcr, flags)
}
