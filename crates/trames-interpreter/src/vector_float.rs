// SPDX-License-Identifier: GPL-3.0-or-later
use super::{Cpu, CpuFault};
use crate::soft_float::{DOUBLE, INEXACT, SINGLE};

fn immediate(bits: u32, frac: u32, ebits: u32) -> u64 {
    let e = ((((bits >> 6) & 1) ^ 1) << (ebits - 1))
        | if bits & 64 != 0 {
            ((1 << (ebits - 3)) - 1) << 2
        } else {
            0
        }
        | ((bits >> 4) & 3);
    ((bits >> 7) as u64) << (frac + ebits) | (e as u64) << frac | ((bits & 15) as u64) << (frac - 4)
}
impl Cpu {
    pub(crate) fn execute_vector_float(&mut self, ins: u32) -> Result<bool, CpuFault> {
        let invalid = || CpuFault::Instruction {
            pc: self.pc,
            instruction: ins,
        };
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        if ins & 0x9ff80c00 == 0x0f000400 && (ins >> 12) & 15 == 15 {
            if ins & (1 << 11) != 0 {
                return Err(invalid());
            }
            let double = ins & (1 << 29) != 0;
            let q = ins & (1 << 30) != 0;
            if double && !q {
                return Err(invalid());
            }
            let fmt = if double { DOUBLE } else { SINGLE };
            let bits = (((ins >> 16) & 7) << 5) | ((ins >> 5) & 31);
            let value = immediate(bits, fmt.frac, fmt.ebits);
            let width = if double { 64 } else { 32 };
            let mut result = 0;
            for offset in (0..if q { 128 } else { 64 }).step_by(width) {
                result |= (value as u128) << offset;
            }
            self.vectors[rd] = result;
            return Ok(true);
        }
        let binary = ins & 0xbfa0fc00;
        let unary = ins & 0xbfbffc00;
        let scalar_pair = ins & 0xffbffc00 == 0x7e30d800;
        let binary_valid = matches!(
            binary,
            0x0e20d400
                | 0x0ea0d400
                | 0x2e20d400
                | 0x2e20dc00
                | 0x2e20fc00
                | 0x0e20cc00
                | 0x0ea0cc00
                | 0x0e20f400
                | 0x0ea0f400
                | 0x0e20c400
                | 0x0ea0c400
                | 0x0e20e400
                | 0x2e20e400
                | 0x2ea0e400
                | 0x2e20ec00
                | 0x2ea0ec00
        );
        let unary_valid = matches!(
            unary,
            0x0ea0f800
                | 0x2ea0f800
                | 0x2ea1f800
                | 0x0e218800
                | 0x0ea18800
                | 0x0e219800
                | 0x0ea19800
                | 0x2e218800
                | 0x2e219800
                | 0x2ea19800
                | 0x0e21d800
                | 0x2e21d800
                | 0x0ea1b800
                | 0x2ea1b800
                | 0x0e21e800
                | 0x2e21e800
                | 0x0e21f800
                | 0x2e21f800
        );
        if !binary_valid && !unary_valid && !scalar_pair {
            return Ok(false);
        }
        let double = ins & (1 << 22) != 0;
        let q = ins & (1 << 30) != 0;
        if double && !q {
            return Err(invalid());
        }
        if !scalar_pair {
            use trames_compute::VectorFloatOp as V;
            let native = match binary {
                0x0e20d400 => Some(V::Add),
                0x0ea0d400 => Some(V::Sub),
                0x2e20dc00 => Some(V::Mul),
                0x2e20fc00 => Some(V::Div),
                0x0e20cc00 => Some(V::MultiplyAdd),
                0x0ea0cc00 => Some(V::MultiplySub),
                0x2e20d400 => Some(V::PairAdd),
                0x0e20f400 => Some(V::Max),
                0x0ea0f400 => Some(V::Min),
                0x0e20c400 => Some(V::MaxNumber),
                0x0ea0c400 => Some(V::MinNumber),
                0x0e20e400 => Some(V::Equal),
                0x2e20e400 => Some(V::GreaterEqual),
                0x2ea0e400 => Some(V::Greater),
                0x2e20ec00 => Some(V::AbsoluteGreaterEqual),
                0x2ea0ec00 => Some(V::AbsoluteGreater),
                _ => match unary {
                    0x2ea1f800 => Some(V::Sqrt),
                    0x0ea0f800 => Some(V::Abs),
                    0x2ea0f800 => Some(V::Neg),
                    0x0e218800 => Some(V::RoundNearest),
                    0x0ea18800 => Some(V::RoundPositive),
                    0x0e219800 => Some(V::RoundNegative),
                    0x0ea19800 => Some(V::RoundZero),
                    0x2e218800 => Some(V::RoundAway),
                    0x2e219800 => Some(V::RoundExact),
                    0x2ea19800 => Some(V::RoundCurrent),
                    0x0e21d800 => Some(V::SignedToFloat),
                    0x2e21d800 => Some(V::UnsignedToFloat),
                    0x0ea1b800 => Some(V::FloatToSignedZero),
                    0x2ea1b800 => Some(V::FloatToUnsignedZero),
                    _ => None,
                },
            };
            if let Some(op) = native {
                if let Some(result) = trames_compute::vector_float(
                    if double { 64 } else { 32 },
                    q,
                    op,
                    self.vectors[rn],
                    self.vectors[rm],
                    self.vectors[rd],
                ) {
                    self.vectors[rd] = result;
                    return Ok(true);
                }
            }
        }
        let width = if double { 64 } else { 32 };
        let fmt = if double { DOUBLE } else { SINGLE };
        let lane_mask = if double { u64::MAX } else { u32::MAX as u64 };
        let lanes = if scalar_pair {
            1
        } else {
            (if q { 128 } else { 64 }) / width
        };
        let mut result = 0;
        let fpcr = self.fpcr;
        let mode = (fpcr >> 22) & 3;
        let mut flags = 0;
        for lane in 0..lanes {
            let (av, bv) = if scalar_pair {
                (
                    (self.vectors[rn] as u64) & lane_mask,
                    ((self.vectors[rn] >> width) as u64) & lane_mask,
                )
            } else if binary == 0x2e20d400 {
                let source = if lane < lanes / 2 {
                    self.vectors[rn]
                } else {
                    self.vectors[rm]
                };
                let offset = (lane % (lanes / 2)) * 2 * width;
                (
                    ((source >> offset) as u64) & lane_mask,
                    ((source >> (offset + width)) as u64) & lane_mask,
                )
            } else {
                (
                    ((self.vectors[rn] >> (lane * width)) as u64) & lane_mask,
                    ((self.vectors[rm] >> (lane * width)) as u64) & lane_mask,
                )
            };
            let mut af = 0;
            let mut bf = 0;
            let a = fmt.unpack(av, fpcr, &mut af);
            let b = fmt.unpack(bv, fpcr, &mut bf);
            let mut lane_flags = af;
            if binary_valid || scalar_pair {
                lane_flags |= bf;
            }
            let value = if scalar_pair {
                fmt.add(a, b, mode, fpcr, &mut lane_flags)
            } else if binary_valid {
                match binary {
                    0x0e20d400 | 0x2e20d400 => fmt.add(a, b, mode, fpcr, &mut lane_flags),
                    0x0ea0d400 => fmt.sub(a, b, mode, fpcr, &mut lane_flags),
                    0x2e20dc00 => fmt.mul(a, b, mode, fpcr, &mut lane_flags),
                    0x2e20fc00 => fmt.div(a, b, mode, fpcr, &mut lane_flags),
                    0x0e20cc00 | 0x0ea0cc00 => {
                        let c = fmt.unpack(
                            ((self.vectors[rd] >> (lane * width)) as u64) & lane_mask,
                            fpcr,
                            &mut lane_flags,
                        );
                        fmt.fma(
                            a,
                            b,
                            c,
                            binary == 0x0ea0cc00,
                            false,
                            mode,
                            fpcr,
                            &mut lane_flags,
                        )
                    }
                    0x0e20f400 | 0x0ea0f400 | 0x0e20c400 | 0x0ea0c400 => fmt.minmax(
                        a,
                        b,
                        ins & (1 << 23) != 0,
                        binary & 0x3000 == 0,
                        fpcr,
                        &mut lane_flags,
                    ),
                    _ => {
                        let absolute = matches!(binary, 0x2e20ec00 | 0x2ea0ec00);
                        let mut left = a;
                        let mut right = b;
                        if absolute {
                            left.sign = false;
                            right.sign = false;
                            left.raw &= !fmt.sign_bit();
                            right.raw &= !fmt.sign_bit();
                        }
                        let relation =
                            fmt.compare(left, right, binary != 0x0e20e400, &mut lane_flags);
                        let yes = match binary {
                            0x0e20e400 => relation == 6,
                            0x2e20e400 | 0x2e20ec00 => relation == 6 || relation == 2,
                            _ => relation == 2,
                        };
                        if yes {
                            lane_mask
                        } else {
                            0
                        }
                    }
                }
            } else {
                match unary {
                    0x0ea0f800 => {
                        lane_flags = 0;
                        av & !fmt.sign_bit()
                    }
                    0x2ea0f800 => {
                        lane_flags = 0;
                        av ^ fmt.sign_bit()
                    }
                    0x2ea1f800 => fmt.sqrt(a, mode, fpcr, &mut lane_flags),
                    0x0e21d800 | 0x2e21d800 => {
                        lane_flags = 0;
                        let unsigned = unary == 0x2e21d800;
                        let sign = !unsigned && av & fmt.sign_bit() != 0;
                        let mag = if sign {
                            if double {
                                av.wrapping_neg()
                            } else {
                                (av as u32).wrapping_neg() as u64
                            }
                        } else {
                            av
                        };
                        fmt.pack(sign, mag as u128, 0, mode, fpcr, &mut lane_flags)
                    }
                    0x0ea1b800 | 0x2ea1b800 => {
                        fmt.to_integer(a, width, unary == 0x2ea1b800, 0, 3, &mut lane_flags)
                            & lane_mask
                    }
                    0x0e21e800 | 0x2e21e800 | 0x0e21f800 | 0x2e21f800 => fmt.round_integer_size(
                        a,
                        if unary & 0x1000 == 0 { 32 } else { 64 },
                        if unary & (1 << 29) == 0 { 3 } else { mode },
                        fpcr,
                        &mut lane_flags,
                    ),
                    _ => {
                        let round = match unary {
                            0x0e218800 => 0,
                            0x0ea18800 => 1,
                            0x0e219800 => 2,
                            0x0ea19800 => 3,
                            0x2e218800 => 4,
                            _ => mode,
                        };
                        if let Some(n) = fmt.nan_result(&[a], fpcr, &mut lane_flags) {
                            n
                        } else if a.inf || a.exp >= 0 {
                            av
                        } else {
                            let (mag, lost) = fmt.rounded_integer(a, round);
                            if unary == 0x2e219800 && lost {
                                lane_flags |= INEXACT;
                            }
                            fmt.pack(a.sign, mag, 0, 0, fpcr, &mut lane_flags)
                        }
                    }
                }
            };
            result |= (value as u128) << (lane * width);
            flags |= lane_flags;
        }
        self.vectors[rd] = result;
        self.fpsr |= flags;
        Ok(true)
    }
}
