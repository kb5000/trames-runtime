// SPDX-License-Identifier: GPL-3.0-or-later
//! BF16, FP16 widening multiply-add, and complex floating-point operations.
use super::{Cpu, CpuFault};
use crate::soft_float::{Format, DOUBLE, HALF, SINGLE};
use trames_compute::{BFloatOp as B, FloatOp as F};
fn lane(v: u128, i: u32, bits: u32) -> u64 {
    (v >> (i * bits)) as u64
        & if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
}
fn repeat(v: u64, bits: u32, width: u32) -> u128 {
    (0..width / bits).fold(0, |out, i| out | ((v as u128) << (i * bits)))
}
fn widen_half(raw: u16, flush: bool) -> u32 {
    let sign = (raw as u32 & 0x8000) << 16;
    let e = (raw >> 10) & 31;
    let frac = raw as u32 & 1023;
    if e == 0 {
        if frac == 0 || flush {
            return sign;
        }
        let shift = frac.leading_zeros() - 21;
        sign | ((113 - shift) << 23) | (((frac << shift) & 1023) << 13)
    } else {
        sign | ((if e == 31 { 255 } else { e as u32 + 112 }) << 23) | (frac << 13)
    }
}
fn bf_round(raw: u32) -> u16 {
    if raw & 0x7f800000 == 0x7f800000 && raw & 0x007fffff != 0 {
        return ((raw >> 16) as u16) | 64;
    }
    (raw.wrapping_add(0x7fff + ((raw >> 16) & 1)) >> 16) as u16
}

impl Cpu {
    pub(super) fn execute_vector_extensions(&mut self, ins: u32) -> Result<bool, CpuFault> {
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let (a, b, c) = (self.vectors[rn], self.vectors[rm], self.vectors[rd]);
        let q = ins & (1 << 30) != 0;
        let count = if q { 4 } else { 2 };
        let fpcr = self.fpcr;
        let invalid = || CpuFault::Instruction {
            pc: self.pc,
            instruction: ins,
        };
        let mut flags = 0;
        let unary = ins & 0xbffffc00;
        let binary = ins & 0xbfe0fc00;
        let indexed = ins & 0xbfc0f400;
        if ins & 0xfffffc00 == 0x1e634000 || unary == 0x0ea16800 {
            let scalar = ins & 0xfffffc00 == 0x1e634000;
            if let Some(value) = trames_compute::bfloat(
                if scalar {
                    B::ConvertScalar
                } else {
                    B::ConvertVector
                },
                q,
                a,
                0,
                c,
            ) {
                self.vectors[rd] = value;
                return Ok(true);
            }
            let mut result = 0;
            for i in 0..if scalar { 1 } else { 4 } {
                result |= (bf_round(lane(a, i, 32) as u32) as u128) << (i * 16);
            }
            self.vectors[rd] = if !scalar && q {
                (c & u64::MAX as u128) | (result << 64)
            } else {
                result
            };
            return Ok(true);
        }
        if matches!(binary, 0x2e40fc00 | 0x2e40ec00 | 0x2ec0fc00)
            || matches!(indexed, 0x0f40f000 | 0x0fc0f000)
        {
            let indexed_form = matches!(indexed, 0x0f40f000 | 0x0fc0f000);
            let dot = binary == 0x2e40fc00 || indexed == 0x0f40f000;
            let matrix = binary == 0x2e40ec00;
            if matrix && !q {
                return Err(invalid());
            }
            let b = if indexed_form {
                if dot {
                    let index = (((ins >> 11) & 1) << 1) | ((ins >> 21) & 1);
                    repeat(lane(b, index, 32), 32, 128)
                } else {
                    let index =
                        (((ins >> 11) & 1) << 2) | (((ins >> 21) & 1) << 1) | ((ins >> 20) & 1);
                    repeat(lane(self.vectors[rm & 15], index, 16), 16, 128)
                }
            } else {
                b
            };
            let op = if dot {
                B::Dot
            } else if matrix {
                B::Matrix
            } else {
                B::MultiplyLong
            };
            if let Some(value) = trames_compute::bfloat(op, q, a, b, c) {
                self.vectors[rd] = value;
                return Ok(true);
            }
            // Optional-host fallback keeps arithmetic native. BF dot/matrix
            // discard FP exception flags, flush subnormals and use default NaNs.
            let _dot_scope =
                (dot || matrix).then(|| trames_compute::Scope::new((1 << 24) | (1 << 25), 0));
            let mut result = 0;
            for i in 0..if dot { count } else { 4 } {
                let mut sum = lane(c, i, 32);
                if dot || matrix {
                    let pairs = if matrix { 2 } else { 1 };
                    for k in 0..pairs {
                        let left = if matrix { (i / 2) * 4 + k * 2 } else { i * 2 };
                        let right = if matrix { (i % 2) * 4 + k * 2 } else { i * 2 };
                        let p0 = trames_compute::scalar(
                            32,
                            F::Mul,
                            lane(a, left, 16) << 16,
                            lane(b, right, 16) << 16,
                            0,
                        )
                        .unwrap();
                        let p1 = trames_compute::scalar(
                            32,
                            F::Mul,
                            lane(a, left + 1, 16) << 16,
                            lane(b, right + 1, 16) << 16,
                            0,
                        )
                        .unwrap();
                        let product = trames_compute::scalar(32, F::Add, p0, p1, 0).unwrap();
                        sum = trames_compute::scalar(32, F::Add, sum, product, 0).unwrap();
                    }
                } else {
                    let selector = u32::from(q);
                    let x = SINGLE.unpack(lane(a, i * 2 + selector, 16) << 16, fpcr, &mut flags);
                    let y = SINGLE.unpack(lane(b, i * 2 + selector, 16) << 16, fpcr, &mut flags);
                    let z = SINGLE.unpack(sum, fpcr, &mut flags);
                    sum = SINGLE.fma(x, y, z, false, false, (fpcr >> 22) & 3, fpcr, &mut flags);
                }
                result |= (sum as u128) << (i * 32);
            }
            self.vectors[rd] = result;
            self.fpsr |= flags;
            return Ok(true);
        }
        let half_vector = matches!(binary, 0x0e20ec00 | 0x0ea0ec00 | 0x2e20cc00 | 0x2ea0cc00);
        let half_index = matches!(indexed, 0x0f800000 | 0x0f804000 | 0x2f808000 | 0x2f80c000);
        if half_vector || half_index {
            let upper = ins & (1 << 29) != 0;
            let subtract = if half_index {
                ins & (1 << 14) != 0
            } else {
                ins & (1 << 23) != 0
            };
            let b = if half_index {
                let index = (((ins >> 11) & 1) << 2) | (((ins >> 21) & 1) << 1) | ((ins >> 20) & 1);
                repeat(lane(self.vectors[rm & 15], index, 16), 16, 128)
            } else {
                b
            };
            if let Some(value) = trames_compute::multiply_long(q, upper, subtract, a, b, c) {
                self.vectors[rd] = value;
                return Ok(true);
            }
            let offset = if upper { count } else { 0 };
            let mut result = 0;
            for i in 0..count {
                let left = widen_half(lane(a, i + offset, 16) as u16, fpcr & (1 << 19) != 0) as u64;
                let right =
                    widen_half(lane(b, i + offset, 16) as u16, fpcr & (1 << 19) != 0) as u64;
                let left = left ^ if subtract { 1 << 31 } else { 0 };
                let x = SINGLE.unpack(left, fpcr, &mut flags);
                let y = SINGLE.unpack(right, fpcr, &mut flags);
                let z = SINGLE.unpack(lane(c, i, 32), fpcr, &mut flags);
                result |= (SINGLE.fma(x, y, z, false, false, (fpcr >> 22) & 3, fpcr, &mut flags)
                    as u128)
                    << (i * 32);
            }
            self.vectors[rd] = result;
            self.fpsr |= flags;
            return Ok(true);
        }
        let complex_vector = ins & 0xbf20e400 == 0x2e00c400;
        let complex_add = ins & 0xbf20ec00 == 0x2e00e400;
        let complex_index = ins & 0xbf009400 == 0x2f001000;
        if complex_vector || complex_add || complex_index {
            let size = (ins >> 22) & 3;
            if size == 0
                || size == 3 && (!q || complex_index)
                || complex_index && size == 2 && (!q || ins & (1 << 21) != 0)
                || complex_index && size == 1 && !q && ins & (1 << 11) != 0
            {
                return Err(invalid());
            }
            let bits = 8 << size;
            let width = if q { 128 } else { 64 };
            let rotation = if complex_add {
                if ins & (1 << 12) != 0 {
                    3
                } else {
                    1
                }
            } else if complex_index {
                (ins >> 13) & 3
            } else {
                (ins >> 11) & 3
            };
            let b = if complex_index {
                let index = if size == 1 {
                    (((ins >> 11) & 1) << 1) | ((ins >> 21) & 1)
                } else {
                    (ins >> 11) & 1
                };
                repeat(lane(b, index, bits * 2), bits * 2, width)
            } else {
                b
            };
            if let Some(value) = trames_compute::complex(bits, q, !complex_add, rotation, a, b, c) {
                self.vectors[rd] = value;
                return Ok(true);
            }
            let fmt: Format = match bits {
                16 => HALF,
                32 => SINGLE,
                _ => DOUBLE,
            };
            let mut result = 0;
            for i in (0..width / bits).step_by(2) {
                let nr = lane(a, i, bits);
                let ni = lane(a, i + 1, bits);
                let mr = lane(b, i, bits);
                let mi = lane(b, i + 1, bits);
                if complex_add {
                    let (real, imag) = if rotation == 1 {
                        (mi ^ fmt.sign_bit(), mr)
                    } else {
                        (mi, mr ^ fmt.sign_bit())
                    };
                    let x = fmt.unpack(nr, fpcr, &mut flags);
                    let y = fmt.unpack(real, fpcr, &mut flags);
                    result |=
                        (fmt.add(x, y, (fpcr >> 22) & 3, fpcr, &mut flags) as u128) << (i * bits);
                    let x = fmt.unpack(ni, fpcr, &mut flags);
                    let y = fmt.unpack(imag, fpcr, &mut flags);
                    result |= (fmt.add(x, y, (fpcr >> 22) & 3, fpcr, &mut flags) as u128)
                        << ((i + 1) * bits);
                } else {
                    let (left, real, imag) = match rotation {
                        0 => (nr, mr, mi),
                        1 => (ni, mi ^ fmt.sign_bit(), mr),
                        2 => (nr, mr ^ fmt.sign_bit(), mi ^ fmt.sign_bit()),
                        _ => (ni, mi, mr ^ fmt.sign_bit()),
                    };
                    for (j, right) in [real, imag].into_iter().enumerate() {
                        let x = fmt.unpack(left, fpcr, &mut flags);
                        let y = fmt.unpack(right, fpcr, &mut flags);
                        let z = fmt.unpack(lane(c, i + j as u32, bits), fpcr, &mut flags);
                        result |=
                            (fmt.fma(x, y, z, false, false, (fpcr >> 22) & 3, fpcr, &mut flags)
                                as u128)
                                << ((i + j as u32) * bits);
                    }
                }
            }
            self.vectors[rd] = result;
            self.fpsr |= flags;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bfloat_dot_and_matrix_have_functional_optional_host_fallbacks() {
        let source = (1..=8).enumerate().fold(0, |v, (i, n)| {
            v | ((((n as f32).to_bits() >> 16) as u128) << (16 * i))
        });
        let accumulator = (1..=4).enumerate().fold(0, |v, (i, n)| {
            v | (((n as f32).to_bits() as u128) << (32 * i))
        });
        for (ins, expected) in [
            (0x6e42fc20, [6.0f32, 27.0, 64.0, 117.0]),
            (0x6e42ec20, [31.0, 72.0, 73.0, 178.0]),
        ] {
            let mut c = Cpu::new(0x1000, 0x2800);
            c.vectors[0] = accumulator;
            c.vectors[1] = source;
            c.vectors[2] = source;
            let _scope = trames_compute::Scope::new(0, 0);
            assert!(c.execute_vector_extensions(ins).unwrap());
            for (i, value) in expected.iter().enumerate() {
                assert_eq!(lane(c.vectors[0], i as u32, 32), value.to_bits() as u64);
            }
        }
    }
}
