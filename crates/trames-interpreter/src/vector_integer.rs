// SPDX-License-Identifier: GPL-3.0-or-later
//! Integer AdvSIMD semantics. Sources are snapshotted before aliasing writes.
use super::{sign_extend, Cpu, CpuFault};

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
fn number(value: u64, bits: u32, unsigned: bool) -> i128 {
    if unsigned {
        value as i128
    } else {
        sign_extend(value, bits) as i64 as i128
    }
}
fn saturate(value: i128, bits: u32, unsigned: bool, qc: &mut bool) -> u64 {
    let low = if unsigned { 0 } else { -(1i128 << (bits - 1)) };
    let high = if unsigned {
        (1i128 << bits) - 1
    } else {
        (1i128 << (bits - 1)) - 1
    };
    *qc |= value < low || value > high;
    value.clamp(low, high) as u64 & mask(bits)
}
fn polynomial(a: u64, b: u64, bits: u32) -> u128 {
    if let Some(result) = trames_compute::polynomial_product(bits, a, b) {
        return result;
    }
    let mut result = 0;
    for bit in 0..bits {
        if b & (1u64 << bit) != 0 {
            result ^= (a as u128) << bit;
        }
    }
    result
}
fn shift(
    value: i128,
    amount: i32,
    bits: u32,
    rounding: bool,
    saturated: bool,
    unsigned: bool,
    qc: &mut bool,
) -> u64 {
    if amount >= bits as i32 {
        if saturated && value != 0 {
            return saturate(
                if value < 0 {
                    -(1i128 << bits)
                } else {
                    1i128 << bits
                },
                bits,
                unsigned,
                qc,
            );
        }
        return 0;
    }
    let shifted = if amount >= 0 {
        value << amount
    } else {
        let distance = (-amount) as u32;
        if distance > bits || distance >= 128 {
            if value < 0 && !rounding {
                -1
            } else {
                0
            }
        } else {
            (value + if rounding { 1i128 << (distance - 1) } else { 0 }) >> distance
        }
    };
    if saturated {
        saturate(shifted, bits, unsigned, qc)
    } else {
        shifted as u64 & mask(bits)
    }
}

impl Cpu {
    pub(crate) fn execute_vector_integer(&mut self, ins: u32) -> Result<bool, CpuFault> {
        let scalar = ins & 0xdf000000 == 0x5e000000 || ins & 0xdf000000 == 0x5f000000;
        let vector = ins & 0x9f000000 == 0x0e000000 || ins & 0x9f000000 == 0x0f000000;
        if !scalar && !vector {
            return Ok(false);
        }
        let invalid = || CpuFault::Instruction {
            pc: self.pc,
            instruction: ins,
        };
        let normal = if scalar { ins & !(1 << 28) } else { ins };
        let rd = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let rm = ((ins >> 16) & 31) as usize;
        let a = self.vectors[rn];
        let b = self.vectors[rm];
        let old = self.vectors[rd];
        let size = (ins >> 22) & 3;
        let bits = 8 << size;
        let unsigned = ins & (1 << 29) != 0;
        let upper = ins & (1 << 30) != 0 && !scalar;
        let width = if scalar {
            bits
        } else if upper {
            128
        } else {
            64
        };
        let mut result = 0u128;
        let mut qc = false;

        if !scalar
            && (matches!(
                normal & 0xbf20fc00,
                0x0e009400 | 0x2e009400 | 0x0e009c00 | 0x0e00a400 | 0x2e00a400 | 0x0e00ac00
            ) || matches!(normal & 0xbf00f400, 0x0f00e000 | 0x2f00e000 | 0x0f00f000))
        {
            let key = normal & 0xbf20fc00;
            let indexed_key = normal & 0xbf00f400;
            let indexed = matches!(indexed_key, 0x0f00e000 | 0x2f00e000 | 0x0f00f000);
            let mixed_indexed = indexed && indexed_key == 0x0f00f000;
            if mixed_indexed && ins & (1 << 22) != 0 || !mixed_indexed && size != 2 {
                return Err(invalid());
            }
            let matrix = !indexed && matches!(key, 0x0e00a400 | 0x2e00a400 | 0x0e00ac00);
            if matrix && !upper {
                return Err(invalid());
            }
            let mixed = mixed_indexed || matches!(key, 0x0e009c00 | 0x0e00ac00);
            let first_unsigned = if mixed_indexed {
                ins & (1 << 23) != 0
            } else {
                unsigned || mixed
            };
            let second_unsigned = if mixed_indexed {
                !first_unsigned
            } else {
                unsigned && !mixed
            };
            let index = ((ins >> 21) & 1) | (((ins >> 11) & 1) << 1);
            for i in 0..width / 32 {
                let mut sum = lane(old, i, 32) as i128;
                for k in 0..if matrix { 8 } else { 4 } {
                    let left_index = if matrix { (i / 2) * 8 + k } else { i * 4 + k };
                    let right_index = if matrix {
                        (i % 2) * 8 + k
                    } else if indexed {
                        index * 4 + k
                    } else {
                        i * 4 + k
                    };
                    sum += number(lane(a, left_index, 8), 8, first_unsigned)
                        * number(lane(b, right_index, 8), 8, second_unsigned);
                }
                result |= (sum as u32 as u128) << (i * 32);
            }
        } else if matches!(normal & 0xbf20fc00, 0x2e008400 | 0x2e008c00)
            || matches!(normal & 0xbf00f400, 0x2f00d000 | 0x2f00f000)
        {
            if size != 1 && size != 2 {
                return Err(invalid());
            }
            let indexed = normal & 0xbf00f400 == 0x2f00d000 || normal & 0xbf00f400 == 0x2f00f000;
            let subtract = if indexed {
                ins & 0x2000 != 0
            } else {
                ins & 0x0800 != 0
            };
            let index = if size == 1 {
                (((ins >> 11) & 1) << 2) | (((ins >> 21) & 1) << 1) | ((ins >> 20) & 1)
            } else {
                (((ins >> 11) & 1) << 1) | ((ins >> 21) & 1)
            };
            let source = if indexed && size == 1 { rm & 15 } else { rm };
            for i in 0..width / bits {
                let left = number(lane(a, i, bits), bits, false);
                let right = number(
                    lane(self.vectors[source], if indexed { index } else { i }, bits),
                    bits,
                    false,
                );
                let accumulator = number(lane(old, i, bits), bits, false);
                let product = 2 * left * right;
                let value = ((accumulator << bits)
                    + if subtract { -product } else { product }
                    + (1i128 << (bits - 1)))
                    >> bits;
                result |= (saturate(value, bits, false, &mut qc) as u128) << (i * bits);
            }
        } else if !scalar && normal & 0xbfe08400 == 0x2e000000 {
            // EXT concatenates the active (64 or 128 bit) parts of both sources.
            let offset = (ins >> 11) & 15;
            if offset >= width / 8 {
                return Err(invalid());
            }
            for i in 0..width / 8 {
                let index = i + offset;
                let value = if index < width / 8 {
                    lane(a, index, 8)
                } else {
                    lane(b, index - width / 8, 8)
                };
                result |= (value as u128) << (i * 8);
            }
        } else if !scalar
            && matches!(
                normal & 0xbfe0fc00,
                0x0e601c00 | 0x0ee01c00 | 0x2e601c00 | 0x2ea01c00 | 0x2ee01c00
            )
        {
            result = match normal & 0xbfe0fc00 {
                0x0e601c00 => a & !b,
                0x0ee01c00 => a | !b,
                0x2e601c00 => (old & a) | (!old & b),
                0x2ea01c00 => (old & !b) | (a & b),
                _ => (old & b) | (a & !b),
            };
            if width == 64 {
                result &= u64::MAX as u128;
            }
        } else if matches!(
            normal & 0xbf3ffc00,
            0x0e201800
                | 0x2e200800
                | 0x0e200800
                | 0x0e205800
                | 0x2e205800
                | 0x0e204800
                | 0x2e204800
                | 0x0e208800
                | 0x2e208800
                | 0x0e209800
                | 0x2e209800
                | 0x0e20a800
                | 0x0e203800
                | 0x2e203800
                | 0x0e207800
                | 0x2e207800
        ) {
            let key = normal & 0xbf3ffc00;
            let byte_op = matches!(key, 0x0e205800 | 0x2e205800);
            if bits == 64 && !scalar && !upper && !byte_op {
                return Err(invalid());
            }
            if scalar
                && bits != 64
                && matches!(
                    key,
                    0x0e208800 | 0x2e208800 | 0x0e209800 | 0x2e209800 | 0x0e20a800
                )
            {
                return Err(invalid());
            }
            let element_bits = if byte_op { 8 } else { bits };
            if byte_op
                && (scalar || (key == 0x0e205800 && size != 0) || (key == 0x2e205800 && size > 1))
            {
                return Err(invalid());
            }
            if matches!(key, 0x0e204800 | 0x2e204800) && (scalar || size == 3) {
                return Err(invalid());
            }
            if !scalar {
                use trames_compute::IntegerOp as I;
                let op = match key {
                    0x0e205800 => Some(I::Popcount),
                    0x2e205800 if size == 1 => Some(I::ReverseBits),
                    0x2e205800 => Some(I::Not),
                    0x2e204800 => Some(I::LeadingZeros),
                    0x0e204800 => Some(I::LeadingSign),
                    0x0e207800 => Some(I::SaturatingAbs),
                    0x2e207800 => Some(I::SaturatingNeg),
                    _ => None,
                };
                if let Some(op) = op {
                    if let Some(value) =
                        trames_compute::vector_integer(element_bits, upper, op, a, b, old)
                    {
                        self.vectors[rd] = value;
                        return Ok(true);
                    }
                }
            }
            for i in 0..width / element_bits {
                let value = lane(a, i, element_bits);
                let signed = number(value, element_bits, false);
                let v = match key {
                    0x0e201800 | 0x2e200800 | 0x0e200800 => {
                        let block = match key {
                            0x0e201800 => 16,
                            0x2e200800 => 32,
                            _ => 64,
                        };
                        if scalar || bits >= block {
                            return Err(invalid());
                        }
                        lane(a, i ^ (block / bits - 1), bits)
                    }
                    0x0e205800 => value.count_ones() as u64,
                    0x2e205800 if size == 1 => (value as u8).reverse_bits() as u64,
                    0x2e205800 => !value,
                    0x2e204800 => value.leading_zeros() as u64 - (64 - bits) as u64,
                    0x0e204800 => {
                        (if signed < 0 {
                            !value & mask(bits)
                        } else {
                            value
                        })
                        .leading_zeros() as u64
                            - (64 - bits) as u64
                            - 1
                    }
                    0x0e208800 => {
                        if signed > 0 {
                            mask(bits)
                        } else {
                            0
                        }
                    }
                    0x2e208800 => {
                        if signed >= 0 {
                            mask(bits)
                        } else {
                            0
                        }
                    }
                    0x0e209800 => {
                        if value == 0 {
                            mask(bits)
                        } else {
                            0
                        }
                    }
                    0x2e209800 => {
                        if signed <= 0 {
                            mask(bits)
                        } else {
                            0
                        }
                    }
                    0x0e20a800 => {
                        if signed < 0 {
                            mask(bits)
                        } else {
                            0
                        }
                    }
                    0x0e203800 => saturate(
                        number(lane(old, i, bits), bits, false) + value as i128,
                        bits,
                        false,
                        &mut qc,
                    ),
                    0x2e203800 => {
                        saturate(lane(old, i, bits) as i128 + signed, bits, true, &mut qc)
                    }
                    0x0e207800 => saturate(signed.abs(), bits, false, &mut qc),
                    _ => saturate(-signed, bits, false, &mut qc),
                } & mask(element_bits);
                result |= (v as u128) << (i * element_bits);
            }
        } else if !scalar && normal & 0xbf3ffc00 == 0x2e213800 {
            // SHLL has a fixed shift of the source element width (unlike SSHLL).
            if size == 3 {
                return Err(invalid());
            }
            let offset = if upper { 64 / bits } else { 0 };
            for i in 0..64 / bits {
                result |= ((lane(a, i + offset, bits) as u128) << bits) << (i * bits * 2);
            }
        } else if matches!(
            normal & 0xbf00f400,
            0x0f008000
                | 0x2f000000
                | 0x2f004000
                | 0x0f00a000
                | 0x2f00a000
                | 0x0f002000
                | 0x2f002000
                | 0x0f006000
                | 0x2f006000
                | 0x0f00b000
                | 0x0f003000
                | 0x0f007000
                | 0x0f00c000
                | 0x0f00d000
        ) {
            // Indexed multiply: snapshot the lane and accumulator before any
            // aliased destination write. Long forms always produce 128 bits.
            if size != 1 && size != 2 {
                return Err(invalid());
            }
            let key = normal & 0xbf00f400;
            let plain = matches!(key, 0x0f008000 | 0x2f000000 | 0x2f004000);
            if scalar && plain {
                return Err(invalid());
            }
            let high = matches!(key, 0x0f00c000 | 0x0f00d000);
            let long = !plain && !high;
            let index = if size == 1 {
                (((ins >> 11) & 1) << 2) | (((ins >> 21) & 1) << 1) | ((ins >> 20) & 1)
            } else {
                (((ins >> 11) & 1) << 1) | ((ins >> 21) & 1)
            };
            let source = if size == 1 { rm & 15 } else { rm };
            let selected = lane(self.vectors[source], index, bits);
            let output_bits = if long { bits * 2 } else { bits };
            let count = if scalar {
                1
            } else if long {
                64 / bits
            } else {
                width / bits
            };
            let offset = if long && upper { 64 / bits } else { 0 };
            for i in 0..count {
                let raw = lane(a, i + offset, bits);
                let left = number(raw, bits, unsigned);
                let right = number(selected, bits, unsigned);
                let accumulator = number(lane(old, i, output_bits), output_bits, unsigned);
                let value = if plain {
                    let product = left * right;
                    (match key {
                        0x0f008000 => product,
                        0x2f000000 => accumulator + product,
                        _ => accumulator - product,
                    }) as u64
                } else if high {
                    saturate(
                        (2 * left * right
                            + if key == 0x0f00d000 {
                                1i128 << (bits - 1)
                            } else {
                                0
                            })
                            >> bits,
                        bits,
                        false,
                        &mut qc,
                    )
                } else if matches!(key, 0x0f00b000 | 0x0f003000 | 0x0f007000) {
                    let product = number(
                        saturate(2 * left * right, output_bits, false, &mut qc),
                        output_bits,
                        false,
                    );
                    saturate(
                        match key {
                            0x0f003000 => accumulator + product,
                            0x0f007000 => accumulator - product,
                            _ => product,
                        },
                        output_bits,
                        false,
                        &mut qc,
                    )
                } else {
                    let product = left * right;
                    (match key {
                        0x0f002000 | 0x2f002000 => accumulator + product,
                        0x0f006000 | 0x2f006000 => accumulator - product,
                        _ => product,
                    }) as u64
                } & mask(output_bits);
                result |= (value as u128) << (i * output_bits);
            }
        } else if !scalar
            && matches!(
                normal & 0xbf3ffc00,
                0x0e31b800
                    | 0x0e303800
                    | 0x2e303800
                    | 0x0e30a800
                    | 0x0e31a800
                    | 0x2e30a800
                    | 0x2e31a800
            )
        {
            if size == 3 || (size == 2 && !upper) {
                return Err(invalid());
            }
            let key = normal & 0xbf3ffc00;
            let mut value = number(lane(a, 0, bits), bits, unsigned);
            for i in 1..width / bits {
                let next = number(lane(a, i, bits), bits, unsigned);
                value = match key {
                    0x0e31b800 | 0x0e303800 | 0x2e303800 => value + next,
                    0x0e30a800 | 0x2e30a800 => value.max(next),
                    _ => value.min(next),
                };
            }
            let output_bits = if matches!(key, 0x0e303800 | 0x2e303800) {
                bits * 2
            } else {
                bits
            };
            result = (value as u64 & mask(output_bits)) as u128;
        } else if !scalar
            && matches!(
                normal & 0xbf3ffc00,
                0x0e202800 | 0x2e202800 | 0x0e206800 | 0x2e206800
            )
        {
            if size == 3 {
                return Err(invalid());
            }
            for i in 0..width / (bits * 2) {
                let value = number(lane(a, i * 2, bits), bits, unsigned)
                    + number(lane(a, i * 2 + 1, bits), bits, unsigned);
                let acc = if ins & 0x4000 != 0 {
                    lane(old, i, bits * 2) as i128
                } else {
                    0
                };
                result |= (((value + acc) as u64 & mask(bits * 2)) as u128) << (i * bits * 2);
            }
        } else if matches!(normal & 0xbf3ffc00, 0x0e214800 | 0x2e214800 | 0x2e212800) {
            if size == 3 {
                return Err(invalid());
            }
            let source_unsigned = normal & 0xbf3ffc00 == 0x2e214800;
            let count = if scalar { 1 } else { 64 / bits };
            for i in 0..count {
                let value = number(lane(a, i, bits * 2), bits * 2, source_unsigned);
                result |= (saturate(value, bits, unsigned, &mut qc) as u128) << (i * bits);
            }
            if upper {
                result = (old & u64::MAX as u128) | (result << 64);
            }
        } else if normal & 0x9f200c00 == 0x0e200000
            && (!scalar || matches!((ins >> 12) & 15, 9 | 11 | 13))
        {
            let op = (ins >> 12) & 15;
            if op == 15
                || (size == 3 && op != 14)
                || (op == 14 && size != 0 && size != 3)
                || (matches!(op, 9 | 11 | 13) && (unsigned || size == 0))
            {
                return Err(invalid());
            }
            let count = if scalar { 1 } else { 64 / bits };
            let offset = if upper { 64 / bits } else { 0 };
            for i in 0..count {
                if op == 14 {
                    result |=
                        polynomial(lane(a, i + offset, bits), lane(b, i + offset, bits), bits)
                            << (i * bits * 2);
                    continue;
                }
                if op == 4 || op == 6 {
                    let left = lane(a, i, bits * 2) as i128;
                    let right = lane(b, i, bits * 2) as i128;
                    let value = (if op == 4 { left + right } else { left - right })
                        + if unsigned { 1i128 << (bits - 1) } else { 0 };
                    result |= (((value >> bits) as u64 & mask(bits)) as u128) << (i * bits);
                    continue;
                }
                let left = if op == 1 || op == 3 {
                    number(lane(a, i, bits * 2), bits * 2, unsigned)
                } else {
                    number(lane(a, i + offset, bits), bits, unsigned)
                };
                let right = number(lane(b, i + offset, bits), bits, unsigned);
                let acc = number(lane(old, i, bits * 2), bits * 2, unsigned);
                let value = match op {
                    0 | 1 => left + right,
                    2 | 3 => left - right,
                    5 => acc + (left - right).abs(),
                    7 => (left - right).abs(),
                    8 => acc + left * right,
                    10 => acc - left * right,
                    12 => left * right,
                    9 | 11 | 13 => {
                        let product = number(
                            saturate(2 * left * right, bits * 2, false, &mut qc),
                            bits * 2,
                            false,
                        );
                        if op == 9 {
                            acc + product
                        } else if op == 11 {
                            acc - product
                        } else {
                            product
                        }
                    }
                    _ => return Err(invalid()),
                };
                let value = if matches!(op, 9 | 11 | 13) {
                    saturate(value, bits * 2, false, &mut qc)
                } else {
                    value as u64 & mask(bits * 2)
                };
                result |= (value as u128) << (i * bits * 2);
            }
            if (op == 4 || op == 6) && upper {
                result = (old & u64::MAX as u128) | (result << 64);
            }
        } else if matches!(
            normal & 0x9f20fc00,
            0x0e200400
                | 0x0e202400
                | 0x0e201400
                | 0x0e200c00
                | 0x0e202c00
                | 0x0e206400
                | 0x0e206c00
                | 0x0e207400
                | 0x0e207c00
                | 0x0e209c00
                | 0x0e209400
                | 0x0e20b400
                | 0x0e205400
                | 0x0e204c00
                | 0x0e205c00
                | 0x0e204400
        ) {
            let key = normal & 0x9f20fc00;
            if !scalar
                && size == 3
                && !matches!(
                    key,
                    0x0e200c00 | 0x0e202c00 | 0x0e205400 | 0x0e204c00 | 0x0e205c00 | 0x0e204400
                )
            {
                return Err(invalid());
            }
            if !scalar && size == 3 && !upper {
                return Err(invalid());
            }
            if scalar
                && !matches!(
                    key,
                    0x0e200c00
                        | 0x0e202c00
                        | 0x0e20b400
                        | 0x0e205400
                        | 0x0e204c00
                        | 0x0e205c00
                        | 0x0e204400
                )
            {
                return Ok(false);
            }
            if scalar && size != 3 && matches!(key, 0x0e205400 | 0x0e204400) {
                return Err(invalid());
            }
            if key == 0x0e20b400 && size != 1 && size != 2 {
                return Err(invalid());
            }
            if key == 0x0e209c00 && unsigned && size != 0 {
                return Err(invalid());
            }
            if !scalar {
                use trames_compute::IntegerOp as I;
                let op = match (key, unsigned) {
                    (0x0e200400, false) => Some(I::SignedHalvingAdd),
                    (0x0e200400, true) => Some(I::UnsignedHalvingAdd),
                    (0x0e202400, false) => Some(I::SignedHalvingSub),
                    (0x0e202400, true) => Some(I::UnsignedHalvingSub),
                    (0x0e201400, false) => Some(I::SignedRoundingHalvingAdd),
                    (0x0e201400, true) => Some(I::UnsignedRoundingHalvingAdd),
                    (0x0e200c00, false) => Some(I::SignedSaturatingAdd),
                    (0x0e200c00, true) => Some(I::UnsignedSaturatingAdd),
                    (0x0e202c00, false) => Some(I::SignedSaturatingSub),
                    (0x0e202c00, true) => Some(I::UnsignedSaturatingSub),
                    (0x0e206400, false) => Some(I::SignedMax),
                    (0x0e206400, true) => Some(I::UnsignedMax),
                    (0x0e206c00, false) => Some(I::SignedMin),
                    (0x0e206c00, true) => Some(I::UnsignedMin),
                    (0x0e207400, false) => Some(I::SignedAbsoluteDifference),
                    (0x0e207400, true) => Some(I::UnsignedAbsoluteDifference),
                    (0x0e207c00, false) => Some(I::SignedAbsoluteDifferenceAccumulate),
                    (0x0e207c00, true) => Some(I::UnsignedAbsoluteDifferenceAccumulate),
                    (0x0e209c00, false) => Some(I::Mul),
                    (0x0e209400, false) => Some(I::MultiplyAdd),
                    (0x0e209400, true) => Some(I::MultiplySub),
                    (0x0e20b400, false) => Some(I::SaturatingMultiplyHigh),
                    (0x0e20b400, true) => Some(I::RoundingSaturatingMultiplyHigh),
                    (0x0e204400, false) => Some(I::SignedShift),
                    (0x0e204400, true) => Some(I::UnsignedShift),
                    (0x0e205400, false) => Some(I::SignedRoundingShift),
                    (0x0e205400, true) => Some(I::UnsignedRoundingShift),
                    (0x0e204c00, false) => Some(I::SignedSaturatingShift),
                    (0x0e204c00, true) => Some(I::UnsignedSaturatingShift),
                    (0x0e205c00, false) => Some(I::SignedRoundingSaturatingShift),
                    (0x0e205c00, true) => Some(I::UnsignedRoundingSaturatingShift),
                    _ => None,
                };
                if let Some(op) = op {
                    if let Some(value) = trames_compute::vector_integer(bits, upper, op, a, b, old)
                    {
                        self.vectors[rd] = value;
                        return Ok(true);
                    }
                }
            }
            for i in 0..width / bits {
                let raw_a = lane(a, i, bits);
                let raw_b = lane(b, i, bits);
                let left = number(raw_a, bits, unsigned);
                let right = number(raw_b, bits, unsigned);
                let acc = lane(old, i, bits) as i128;
                let value = match key {
                    0x0e200400 => ((left + right) >> 1) as u64,
                    0x0e202400 => ((left - right) >> 1) as u64,
                    0x0e201400 => ((left + right + 1) >> 1) as u64,
                    0x0e200c00 => saturate(left + right, bits, unsigned, &mut qc),
                    0x0e202c00 => saturate(left - right, bits, unsigned, &mut qc),
                    0x0e206400 => left.max(right) as u64,
                    0x0e206c00 => left.min(right) as u64,
                    0x0e207400 => (left - right).unsigned_abs() as u64,
                    0x0e207c00 => (acc + (left - right).abs()) as u64,
                    0x0e209c00 if unsigned => polynomial(raw_a, raw_b, 8) as u64,
                    0x0e209c00 => (left * right) as u64,
                    0x0e209400 => {
                        (if unsigned {
                            acc - left * right
                        } else {
                            acc + left * right
                        }) as u64
                    }
                    0x0e20b400 => saturate(
                        (2 * number(raw_a, bits, false) * number(raw_b, bits, false)
                            + if unsigned { 1i128 << (bits - 1) } else { 0 })
                            >> bits,
                        bits,
                        false,
                        &mut qc,
                    ),
                    _ => shift(
                        left,
                        raw_b as u8 as i8 as i32,
                        bits,
                        matches!(key, 0x0e205400 | 0x0e205c00),
                        matches!(key, 0x0e204c00 | 0x0e205c00),
                        unsigned,
                        &mut qc,
                    ),
                } & mask(bits);
                result |= (value as u128) << (i * bits);
            }
        } else if normal & 0x9f800400 == 0x0f000400 {
            if ins & 0x00780000 == 0 {
                return Ok(false);
            } // Modified immediate, not a shift.
            let op = (ins >> 11) & 31;
            if !(matches!(op, 12 | 14 | 16..=19) || scalar && matches!(op, 2 | 4 | 6 | 8 | 10)) {
                return Ok(false);
            }
            let immediate = (ins >> 16) & 127;
            if immediate < 8 {
                return Err(invalid());
            }
            let element_bits = 1 << (31 - immediate.leading_zeros());
            let narrow = (16..=19).contains(&op);
            if scalar && !narrow && !matches!(op, 12 | 14) && element_bits != 64 {
                return Err(invalid());
            }
            if element_bits == 64 && (narrow || !scalar && !upper)
                || op == 12 && !unsigned
                || op == 8 && !unsigned
            {
                return Err(invalid());
            }
            let active = if scalar {
                element_bits
            } else if narrow {
                64
            } else if upper {
                128
            } else {
                64
            };
            let distance = if matches!(op, 10 | 12 | 14) {
                (immediate - element_bits) as i32
            } else {
                -((2 * element_bits - immediate) as i32)
            };
            for i in 0..active / element_bits {
                let input_bits = if narrow {
                    element_bits * 2
                } else {
                    element_bits
                };
                let input_unsigned = if narrow {
                    unsigned && op >= 18
                } else {
                    unsigned && op != 12
                };
                let input = number(lane(a, i, input_bits), input_bits, input_unsigned);
                let previous = lane(old, i, element_bits);
                let value = if narrow {
                    let value = (input
                        + if op & 1 != 0 {
                            1i128 << (-distance - 1)
                        } else {
                            0
                        })
                        >> (-distance);
                    if op >= 18 || unsigned {
                        saturate(value, element_bits, unsigned, &mut qc)
                    } else {
                        value as u64
                    }
                } else if op == 8 {
                    let amount = (-distance) as u32;
                    let low = if amount == element_bits {
                        0
                    } else {
                        input as u64 >> amount
                    };
                    low | (previous & !mask(element_bits - amount))
                } else if op == 10 && unsigned {
                    ((input << distance) as u64)
                        | (previous
                            & if distance == 0 {
                                0
                            } else {
                                mask(distance as u32)
                            })
                } else {
                    let value = shift(
                        input,
                        distance,
                        element_bits,
                        matches!(op, 4 | 6),
                        matches!(op, 12 | 14),
                        unsigned,
                        &mut qc,
                    );
                    if matches!(op, 2 | 6) {
                        value.wrapping_add(previous)
                    } else {
                        value
                    }
                } & mask(element_bits);
                result |= (value as u128) << (i * element_bits);
            }
            if narrow && upper {
                result = (old & u64::MAX as u128) | (result << 64);
            }
        } else {
            return Ok(false);
        }
        self.vectors[rd] = result;
        if qc {
            self.fpsr |= 1 << 27;
        }
        Ok(true)
    }
}
