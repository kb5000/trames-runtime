// SPDX-License-Identifier: GPL-3.0-or-later
//! FP16 AdvSIMD. Arithmetic ignores AHP; conversions live in the FP modules.
use super::{Cpu, CpuFault};
use crate::soft_float::{HALF, INEXACT};
use crate::vector_extra_float::{estimate, multiply_extended};

fn lane(value: u128, index: u32) -> u64 {
    (value >> (index * 16)) as u64 & 0xffff
}

impl Cpu {
    pub(super) fn execute_half_vector(&mut self, ins: u32) -> Result<bool, CpuFault> {
        let scalar = ins & 0xdf000000 == 0x5e000000 || ins & 0xdf000000 == 0x5f000000;
        let normal = if scalar { ins & !(1 << 28) } else { ins };
        let unary = normal & 0xbffffc00;
        let binary = normal & 0xbfe0fc00;
        let indexed = normal & 0xbfc0f400;
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let a = self.vectors[rn];
        let b = self.vectors[rm];
        let old = self.vectors[rd];
        let q = ins & (1 << 30) != 0;
        let count = if scalar {
            1
        } else if q {
            8
        } else {
            4
        };
        let fpcr = self.fpcr;
        let mode = (fpcr >> 22) & 3;
        let mut flags = 0;
        let mut result = 0u128;
        let invalid = || CpuFault::Instruction {
            pc: self.pc,
            instruction: ins,
        };

        if !scalar && normal & 0xbff8fc00 == 0x0f00fc00 {
            let immediate = (((ins >> 16) & 7) << 5) | ((ins >> 5) & 31);
            let exponent = ((((immediate >> 6) & 1) ^ 1) << 4)
                | if immediate & 64 != 0 { 12 } else { 0 }
                | ((immediate >> 4) & 3);
            let value =
                (((immediate >> 7) << 15) | (exponent << 10) | ((immediate & 15) << 6)) as u128;
            for i in 0..count {
                result |= value << (i * 16);
            }
        } else if matches!(indexed, 0x0f009000 | 0x2f009000 | 0x0f001000 | 0x0f005000) {
            let index = (((ins >> 11) & 1) << 2) | (((ins >> 21) & 1) << 1) | ((ins >> 20) & 1);
            let selected = HALF.unpack(lane(self.vectors[rm & 15], index), fpcr, &mut flags);
            for i in 0..count {
                let x = HALF.unpack(lane(a, i), fpcr, &mut flags);
                let value = match indexed {
                    0x0f009000 => HALF.mul(x, selected, mode, fpcr, &mut flags),
                    0x2f009000 => multiply_extended(HALF, x, selected, mode, fpcr, &mut flags),
                    _ => {
                        let acc = HALF.unpack(lane(old, i), fpcr, &mut flags);
                        HALF.fma(
                            x,
                            selected,
                            acc,
                            indexed == 0x0f005000,
                            false,
                            mode,
                            fpcr,
                            &mut flags,
                        )
                    }
                };
                result |= (value as u128) << (16 * i);
            }
        } else if matches!(binary, 0x0f00e400 | 0x2f00e400 | 0x0f00fc00 | 0x2f00fc00) {
            let immediate = (ins >> 16) & 127;
            if immediate < 16 && !scalar {
                // immh=0 belongs to the modified-immediate encoding class.
                return Ok(false);
            }
            if !(16..32).contains(&immediate) {
                return Err(invalid());
            }
            let scale = 32 - immediate;
            let unsigned = ins & (1 << 29) != 0;
            for i in 0..count {
                let raw = lane(a, i);
                let value = if ins & 0xfc00 == 0xe400 {
                    let signed = raw as i16;
                    HALF.pack(
                        !unsigned && signed < 0,
                        if unsigned {
                            raw as u128
                        } else {
                            signed.unsigned_abs() as u128
                        },
                        -(scale as i32),
                        mode,
                        fpcr,
                        &mut flags,
                    )
                } else {
                    let x = HALF.unpack(raw, fpcr, &mut flags);
                    HALF.to_integer(x, 16, unsigned, scale, 3, &mut flags) & 0xffff
                };
                result |= (value as u128) << (16 * i);
            }
        } else if matches!(
            unary,
            0x0e30c800 | 0x0eb0c800 | 0x0e30f800 | 0x0eb0f800 | 0x0e30d800
        ) {
            if unary == 0x0e30d800 && !scalar {
                return Err(invalid());
            }
            let mut values = [0u64; 8];
            let active = if scalar { 2 } else { count };
            for i in 0..active {
                values[i as usize] = lane(a, i);
            }
            let mut remaining = active;
            while remaining > 1 {
                for i in 0..remaining / 2 {
                    let x = HALF.unpack(values[(i * 2) as usize], fpcr, &mut flags);
                    let y = HALF.unpack(values[(i * 2 + 1) as usize], fpcr, &mut flags);
                    values[i as usize] = if unary == 0x0e30d800 {
                        HALF.add(x, y, mode, fpcr, &mut flags)
                    } else {
                        HALF.minmax(
                            x,
                            y,
                            ins & (1 << 23) != 0,
                            ins & 0x3000 == 0,
                            fpcr,
                            &mut flags,
                        )
                    };
                }
                remaining /= 2;
            }
            result = values[0] as u128;
        } else if matches!(
            unary,
            0x0ef8f800
                | 0x2ef8f800
                | 0x2ef9f800
                | 0x0e798800
                | 0x0ef98800
                | 0x0e799800
                | 0x0ef99800
                | 0x2e798800
                | 0x2e799800
                | 0x2ef99800
                | 0x0e79d800
                | 0x2e79d800
                | 0x0ef9b800
                | 0x2ef9b800
                | 0x0e79a800
                | 0x2e79a800
                | 0x0ef9a800
                | 0x2ef9a800
                | 0x0e79b800
                | 0x2e79b800
                | 0x0e79c800
                | 0x2e79c800
                | 0x0ef9d800
                | 0x2ef9d800
                | 0x0ef9f800
                | 0x0ef8c800
                | 0x2ef8c800
                | 0x0ef8d800
                | 0x2ef8d800
                | 0x0ef8e800
        ) {
            if scalar
                && matches!(
                    unary,
                    0x0ef8f800
                        | 0x2ef8f800
                        | 0x2ef9f800
                        | 0x0e798800
                        | 0x0ef98800
                        | 0x0e799800
                        | 0x0ef99800
                        | 0x2e798800
                        | 0x2e799800
                        | 0x2ef99800
                )
                || !scalar && unary == 0x0ef9f800
            {
                return Err(invalid());
            }
            if !scalar {
                use trames_compute::VectorFloatOp as V;
                let op = match unary {
                    0x0ef8f800 => Some(V::Abs),
                    0x2ef8f800 => Some(V::Neg),
                    0x2ef9f800 => Some(V::Sqrt),
                    0x0ef9d800 => Some(V::ReciprocalEstimate),
                    0x2ef9d800 => Some(V::ReciprocalSqrtEstimate),
                    0x0e798800 => Some(V::RoundNearest),
                    0x0ef98800 => Some(V::RoundPositive),
                    0x0e799800 => Some(V::RoundNegative),
                    0x0ef99800 => Some(V::RoundZero),
                    0x2e798800 => Some(V::RoundAway),
                    0x2e799800 => Some(V::RoundExact),
                    0x2ef99800 => Some(V::RoundCurrent),
                    0x0e79d800 => Some(V::SignedToFloat),
                    0x2e79d800 => Some(V::UnsignedToFloat),
                    0x0ef9b800 => Some(V::FloatToSignedZero),
                    0x2ef9b800 => Some(V::FloatToUnsignedZero),
                    0x0e79a800 => Some(V::FloatToSignedNearest),
                    0x2e79a800 => Some(V::FloatToUnsignedNearest),
                    0x0ef9a800 => Some(V::FloatToSignedPositive),
                    0x2ef9a800 => Some(V::FloatToUnsignedPositive),
                    0x0e79b800 => Some(V::FloatToSignedNegative),
                    0x2e79b800 => Some(V::FloatToUnsignedNegative),
                    0x0e79c800 => Some(V::FloatToSignedAway),
                    0x2e79c800 => Some(V::FloatToUnsignedAway),
                    _ => None,
                };
                if let Some(op) = op {
                    if cfg!(target_arch = "aarch64") || fpcr & (1 << 19) == 0 {
                        if let Some(value) = trames_compute::vector_float(16, q, op, a, b, old) {
                            self.vectors[rd] = value;
                            return Ok(true);
                        }
                    }
                }
            }
            for i in 0..count {
                let raw = lane(a, i);
                let x = HALF.unpack(raw, fpcr, &mut flags);
                let unsigned = ins & (1 << 29) != 0;
                let value = match unary {
                    0x0ef8f800 => raw & 0x7fff,
                    0x2ef8f800 => raw ^ 0x8000,
                    0x2ef9f800 => HALF.sqrt(x, mode, fpcr, &mut flags),
                    0x0ef9d800 | 0x2ef9d800 => estimate(HALF, x, unsigned, mode, fpcr, &mut flags),
                    0x0ef9f800 => {
                        if let Some(n) = HALF.nan_result(&[x], fpcr, &mut flags) {
                            n
                        } else {
                            (raw & 0x8000)
                                | ((if raw & 0x7c00 == 0 {
                                    30
                                } else {
                                    31 ^ ((raw >> 10) & 31)
                                }) << 10)
                        }
                    }
                    0x0e79d800 | 0x2e79d800 => {
                        let signed = raw as i16;
                        HALF.pack(
                            !unsigned && signed < 0,
                            if unsigned {
                                raw as u128
                            } else {
                                signed.unsigned_abs() as u128
                            },
                            0,
                            mode,
                            fpcr,
                            &mut flags,
                        )
                    }
                    0x0ef9b800 | 0x2ef9b800 | 0x0e79a800 | 0x2e79a800 | 0x0ef9a800 | 0x2ef9a800
                    | 0x0e79b800 | 0x2e79b800 | 0x0e79c800 | 0x2e79c800 => {
                        let round = match unary & !(1 << 29) {
                            0x0e79a800 => 0,
                            0x0ef9a800 => 1,
                            0x0e79b800 => 2,
                            0x0ef9b800 => 3,
                            _ => 4,
                        };
                        HALF.to_integer(x, 16, unsigned, 0, round, &mut flags) & 0xffff
                    }
                    0x0ef8c800 | 0x2ef8c800 | 0x0ef8d800 | 0x2ef8d800 | 0x0ef8e800 => {
                        let zero = HALF.unpack(0, fpcr, &mut flags);
                        let cmp = HALF.compare(x, zero, unary != 0x0ef8d800, &mut flags);
                        let yes = match unary {
                            0x0ef8c800 => cmp == 2,
                            0x2ef8c800 => cmp == 2 || cmp == 6,
                            0x0ef8d800 => cmp == 6,
                            0x2ef8d800 => cmp == 8 || cmp == 6,
                            _ => cmp == 8,
                        };
                        if yes {
                            0xffff
                        } else {
                            0
                        }
                    }
                    _ => {
                        let round = match unary {
                            0x0e798800 => 0,
                            0x0ef98800 => 1,
                            0x0e799800 => 2,
                            0x0ef99800 => 3,
                            0x2e798800 => 4,
                            _ => mode,
                        };
                        if let Some(n) = HALF.nan_result(&[x], fpcr, &mut flags) {
                            n
                        } else if x.inf || x.exp >= 0 {
                            raw
                        } else {
                            let (mag, lost) = HALF.rounded_integer(x, round);
                            if unary == 0x2e799800 && lost {
                                flags |= INEXACT;
                            }
                            HALF.pack(x.sign, mag, 0, 0, fpcr, &mut flags)
                        }
                    }
                };
                result |= (value as u128) << (16 * i);
            }
        } else if matches!(
            binary,
            0x0e401400
                | 0x0ec01400
                | 0x2e401c00
                | 0x2e403c00
                | 0x0e400c00
                | 0x0ec00c00
                | 0x0e403400
                | 0x0ec03400
                | 0x0e400400
                | 0x0ec00400
                | 0x0e402400
                | 0x2e402400
                | 0x2ec02400
                | 0x2e402c00
                | 0x2ec02c00
                | 0x2e401400
                | 0x0e401c00
                | 0x2ec01400
                | 0x2e403400
                | 0x2ec03400
                | 0x2e400400
                | 0x2ec00400
                | 0x0e403c00
                | 0x0ec03c00
        ) {
            if scalar
                && !matches!(
                    binary,
                    0x0e401c00
                        | 0x2ec01400
                        | 0x0e403c00
                        | 0x0ec03c00
                        | 0x0e402400
                        | 0x2e402400
                        | 0x2ec02400
                        | 0x2e402c00
                        | 0x2ec02c00
                )
            {
                return Err(invalid());
            }
            if !scalar {
                use trames_compute::VectorFloatOp as V;
                let op = match binary {
                    0x0e401400 => Some(V::Add),
                    0x0ec01400 => Some(V::Sub),
                    0x2e401c00 => Some(V::Mul),
                    0x2e403c00 => Some(V::Div),
                    0x0e400c00 => Some(V::MultiplyAdd),
                    0x0ec00c00 => Some(V::MultiplySub),
                    0x0e403c00 => Some(V::ReciprocalStep),
                    0x0ec03c00 => Some(V::ReciprocalSqrtStep),
                    0x0e401c00 => Some(V::MultiplyExtended),
                    0x2ec01400 => Some(V::AbsoluteDifference),
                    0x0e403400 => Some(V::Max),
                    0x0ec03400 => Some(V::Min),
                    0x0e400400 => Some(V::MaxNumber),
                    0x0ec00400 => Some(V::MinNumber),
                    0x2e401400 => Some(V::PairAdd),
                    0x2e403400 => Some(V::PairMax),
                    0x2ec03400 => Some(V::PairMin),
                    0x2e400400 => Some(V::PairMaxNumber),
                    0x2ec00400 => Some(V::PairMinNumber),
                    0x0e402400 => Some(V::Equal),
                    0x2e402400 => Some(V::GreaterEqual),
                    0x2ec02400 => Some(V::Greater),
                    0x2e402c00 => Some(V::AbsoluteGreaterEqual),
                    0x2ec02c00 => Some(V::AbsoluteGreater),
                    _ => None,
                };
                if let Some(op) = op {
                    if cfg!(target_arch = "aarch64") || fpcr & (1 << 19) == 0 {
                        if let Some(value) = trames_compute::vector_float(16, q, op, a, b, old) {
                            self.vectors[rd] = value;
                            return Ok(true);
                        }
                    }
                }
            }
            let paired = matches!(
                binary,
                0x2e401400 | 0x2e403400 | 0x2ec03400 | 0x2e400400 | 0x2ec00400
            );
            for i in 0..count {
                let (left, right) = if paired {
                    let source = if i < count / 2 { a } else { b };
                    (
                        lane(source, (i % (count / 2)) * 2),
                        lane(source, (i % (count / 2)) * 2 + 1),
                    )
                } else {
                    (lane(a, i), lane(b, i))
                };
                let mut x = HALF.unpack(left, fpcr, &mut flags);
                let mut y = HALF.unpack(right, fpcr, &mut flags);
                let value = match binary {
                    0x0e401400 | 0x2e401400 => HALF.add(x, y, mode, fpcr, &mut flags),
                    0x0ec01400 | 0x2ec01400 => {
                        let value = HALF.sub(x, y, mode, fpcr, &mut flags);
                        if binary == 0x2ec01400 {
                            value & 0x7fff
                        } else {
                            value
                        }
                    }
                    0x2e401c00 => HALF.mul(x, y, mode, fpcr, &mut flags),
                    0x0e401c00 => multiply_extended(HALF, x, y, mode, fpcr, &mut flags),
                    0x2e403c00 => HALF.div(x, y, mode, fpcr, &mut flags),
                    0x0e400c00 | 0x0ec00c00 => {
                        let acc = HALF.unpack(lane(old, i), fpcr, &mut flags);
                        HALF.fma(
                            x,
                            y,
                            acc,
                            binary == 0x0ec00c00,
                            false,
                            mode,
                            fpcr,
                            &mut flags,
                        )
                    }
                    0x0e403c00 | 0x0ec03c00 => {
                        let op = if binary == 0x0ec03c00 {
                            trames_compute::FloatOp::ReciprocalSqrtStep
                        } else {
                            trames_compute::FloatOp::ReciprocalStep
                        };
                        if let Some(value) = trames_compute::scalar(16, op, left, right, 0) {
                            result |= (value as u128) << (16 * i);
                            continue;
                        }
                        let square = binary == 0x0ec03c00;
                        if x.inf && !y.inf && !y.nan && y.sig == 0
                            || y.inf && !x.inf && !x.nan && x.sig == 0
                        {
                            HALF.pack(
                                false,
                                if square { 3 } else { 2 },
                                if square { -1 } else { 0 },
                                mode,
                                fpcr,
                                &mut flags,
                            )
                        } else {
                            if square {
                                x.exp -= 1;
                            }
                            let c =
                                HALF.unpack(if square { 0x3e00 } else { 0x4000 }, fpcr, &mut flags);
                            HALF.fma(x, y, c, true, false, mode, fpcr, &mut flags)
                        }
                    }
                    0x0e402400 | 0x2e402400 | 0x2ec02400 | 0x2e402c00 | 0x2ec02c00 => {
                        if ins & 0x0800 != 0 {
                            x.sign = false;
                            y.sign = false;
                        }
                        let cmp = HALF.compare(x, y, binary != 0x0e402400, &mut flags);
                        let yes = if binary == 0x0e402400 {
                            cmp == 6
                        } else if ins & (1 << 23) != 0 {
                            cmp == 2
                        } else {
                            cmp == 2 || cmp == 6
                        };
                        if yes {
                            0xffff
                        } else {
                            0
                        }
                    }
                    _ => HALF.minmax(
                        x,
                        y,
                        ins & (1 << 23) != 0,
                        ins & 0x3000 == 0,
                        fpcr,
                        &mut flags,
                    ),
                };
                result |= (value as u128) << (16 * i);
            }
        } else {
            return Ok(false);
        }
        self.vectors[rd] = result;
        self.fpsr |= flags;
        Ok(true)
    }
}
