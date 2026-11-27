// SPDX-License-Identifier: GPL-3.0-or-later
use super::{sign_extend, Cpu, CpuFault};
use std::sync::atomic::Ordering;
use trames_memory::{CpuMemory, MemoryError};

#[inline]
pub(super) fn read_operand(
    memory: &impl CpuMemory,
    address: u64,
    size: usize,
) -> Result<u128, MemoryError> {
    Ok(match size {
        1 => memory.read_array::<1>(address)?[0] as u128,
        2 => u16::from_le_bytes(memory.read_array(address)?) as u128,
        4 => u32::from_le_bytes(memory.read_array(address)?) as u128,
        8 => u64::from_le_bytes(memory.read_array(address)?) as u128,
        16 => u128::from_le_bytes(memory.read_array(address)?),
        _ => unreachable!("validated scalar size"),
    })
}
#[inline]
pub(super) fn write_operand(
    memory: &mut impl CpuMemory,
    address: u64,
    size: usize,
    value: u128,
) -> Result<(), MemoryError> {
    match size {
        1 => memory.write_array(address, [value as u8]),
        2 => memory.write_array(address, (value as u16).to_le_bytes()),
        4 => memory.write_array(address, (value as u32).to_le_bytes()),
        8 => memory.write_array(address, (value as u64).to_le_bytes()),
        16 => memory.write_array(address, value.to_le_bytes()),
        _ => unreachable!("validated scalar size"),
    }
}

impl Cpu {
    pub(super) fn execute_memory(
        &mut self,
        ins: u32,
        memory: &mut impl CpuMemory,
    ) -> Result<bool, CpuFault> {
        let pc = self.pc;
        let invalid = || CpuFault::Instruction {
            pc,
            instruction: ins,
        };
        let fault = |error| CpuFault::Memory { pc, error };
        let rt = (ins & 31) as usize;
        let rn = ((ins >> 5) & 31) as usize;
        let vector = ins & (1 << 26) != 0;
        if ins & 0xbf000000 == 0x0d000000 {
            // AdvSIMD single structures: lane LD/ST1..4 and LD1R..LD4R.
            let q = ((ins >> 30) & 1) as usize;
            let s = ((ins >> 12) & 1) as usize;
            let size = ((ins >> 10) & 3) as usize;
            let opcode = ((ins >> 13) & 7) as usize;
            let structures = (((opcode & 1) << 1) | ((ins >> 21) & 1) as usize) + 1;
            let load = ins & (1 << 22) != 0;
            let replicate = opcode >> 1 == 3;
            let (element, lane) = match opcode >> 1 {
                0 => (1, (q << 3) | (s << 2) | size),
                1 if size & 1 == 0 => (2, (q << 2) | (s << 1) | (size >> 1)),
                2 if size == 0 => (4, (q << 1) | s),
                2 if size == 1 && s == 0 => (8, q),
                3 if load && s == 0 => (1 << size, 0),
                _ => return Err(invalid()),
            };
            let post = ins & (1 << 23) != 0;
            let rm = ((ins >> 16) & 31) as usize;
            if !post && rm != 0 {
                return Err(invalid());
            }
            let length = element * structures;
            let address = self.reg(rn, true);
            let mut bytes = [0; 32];
            if load {
                memory.read(address, &mut bytes[..length]).map_err(fault)?;
            } else {
                memory
                    .check(address, length, trames_memory::Access::Write)
                    .map_err(fault)?;
            }
            for index in 0..structures {
                let register = (rt + index) & 31;
                let offset = index * element;
                if load {
                    let mut data = [0; 16];
                    data[..element].copy_from_slice(&bytes[offset..offset + element]);
                    let value = u128::from_le_bytes(data);
                    if replicate {
                        let mut vector = 0;
                        for lane in 0..(8 << q) / element {
                            vector |= value << (lane * element * 8);
                        }
                        self.vectors[register] = vector;
                    } else {
                        let bits = element * 8;
                        let mask = ((1u128 << bits) - 1) << (lane * bits);
                        self.vectors[register] =
                            (self.vectors[register] & !mask) | (value << (lane * bits));
                    }
                } else {
                    let value = self.vectors[register] >> (lane * element * 8);
                    bytes[offset..offset + element]
                        .copy_from_slice(&value.to_le_bytes()[..element]);
                }
            }
            if !load {
                memory.write(address, &bytes[..length]).map_err(fault)?;
            }
            if post {
                self.sp_or_x(
                    rn,
                    address.wrapping_add(if rm == 31 { length as u64 } else { self.x(rm) }),
                );
            }
            return Ok(true);
        }
        if ins & 0xbf200000 == 0x0c000000 {
            // AdvSIMD LD1/ST1 and interleaved LD2/3/4/ST2/3/4 multiple structures.
            let (repeat, structures) = match (ins >> 12) & 15 {
                0 => (1, 4),
                2 => (4, 1),
                4 => (1, 3),
                6 => (3, 1),
                7 => (1, 1),
                8 => (1, 2),
                10 => (2, 1),
                _ => return Err(invalid()),
            };
            let vector_bytes = if ins & (1 << 30) != 0 { 16 } else { 8 };
            let element = 1usize << ((ins >> 10) & 3);
            if vector_bytes == 8 && element == 8 && structures != 1 {
                return Err(invalid());
            }
            let post = ins & (1 << 23) != 0;
            let rm = ((ins >> 16) & 31) as usize;
            if !post && rm != 0 {
                return Err(invalid());
            }
            let size = vector_bytes * repeat * structures;
            let address = self.reg(rn, true);
            let load = ins & (1 << 22) != 0;
            let mut bytes = [0; 64];
            if load {
                memory.read(address, &mut bytes[..size]).map_err(fault)?;
            } else {
                memory
                    .check(address, size, trames_memory::Access::Write)
                    .map_err(fault)?;
            }
            let mut values = [0u128; 4];
            for r in 0..repeat {
                for lane in 0..vector_bytes / element {
                    for s in 0..structures {
                        let index = r * structures + s;
                        let offset =
                            (r * (vector_bytes / element) * structures + lane * structures + s)
                                * element;
                        if load {
                            let mut value = [0; 16];
                            value[..element].copy_from_slice(&bytes[offset..offset + element]);
                            values[index] |= u128::from_le_bytes(value) << (lane * element * 8);
                        } else {
                            let value = self.vectors[(rt + index) & 31] >> (lane * element * 8);
                            bytes[offset..offset + element]
                                .copy_from_slice(&value.to_le_bytes()[..element]);
                        }
                    }
                }
            }
            if load {
                for (i, &value) in values.iter().enumerate().take(repeat * structures) {
                    self.vectors[(rt + i) & 31] = value;
                }
            } else {
                memory.write(address, &bytes[..size]).map_err(fault)?;
            }
            if post {
                self.sp_or_x(
                    rn,
                    address.wrapping_add(if rm == 31 { size as u64 } else { self.x(rm) }),
                );
            }
            return Ok(true);
        }
        if ins & 0xbfa07c00 == 0x08207c00 || ins & 0x3fa07c00 == 0x08a07c00 {
            // LSE CAS/CASP: one checked transaction, including both 128-bit words.
            let pair = ins & 0x3fa07c00 == 0x08207c00;
            if pair && ins >> 31 != 0 {
                return Err(invalid());
            }
            let size = if pair {
                4usize << ((ins >> 30) & 1)
            } else {
                1usize << (ins >> 30)
            };
            let count = if pair { 2 } else { 1 };
            let compare = ((ins >> 16) & 31) as usize;
            if pair && (!compare.is_multiple_of(2) || !rt.is_multiple_of(2)) {
                return Err(invalid());
            }
            let address = self.reg(rn, true);
            if !address.is_multiple_of((size * count) as u64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            let mut expected = [0u8; 16];
            let mut replacement = [0u8; 16];
            for i in 0..count {
                expected[i * size..(i + 1) * size]
                    .copy_from_slice(&self.x(compare + i).to_le_bytes()[..size]);
                replacement[i * size..(i + 1) * size]
                    .copy_from_slice(&self.x(rt + i).to_le_bytes()[..size]);
            }
            if ins & (1 << 15) != 0 {
                memory.fence(Ordering::Release);
            }
            let bytes = memory
                .atomic_update(address, size * count, |data| {
                    let mut old = [0; 16];
                    old[..data.len()].copy_from_slice(data);
                    let matched = data == &expected[..data.len()];
                    if matched {
                        data.copy_from_slice(&replacement[..data.len()]);
                    }
                    (old, matched)
                })
                .map_err(fault)?;
            if ins & (1 << 22) != 0 {
                memory.fence(Ordering::Acquire);
            }
            for i in 0..count {
                let mut value = [0; 8];
                value[..size].copy_from_slice(&bytes[i * size..(i + 1) * size]);
                self.set_x(compare + i, u64::from_le_bytes(value));
            }
            return Ok(true);
        }
        if ins & 0x3f200c00 == 0x38200000 && ins & 0x3ffffc00 != 0x38bfc000 {
            // LSE read-modify-write and store aliases; no unchecked host pointer.
            let size = 1usize << (ins >> 30);
            let operation = (ins >> 12) & 15;
            if operation > 8 {
                return Err(invalid());
            }
            let address = self.reg(rn, true);
            if !address.is_multiple_of(size as u64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            if ins & (1 << 22) != 0 {
                memory.fence(Ordering::Release);
            }
            let old = memory
                .atomic_update(address, size, |data| {
                    let mut bytes = [0; 8];
                    bytes[..size].copy_from_slice(data);
                    let old = u64::from_le_bytes(bytes);
                    let operand = self.x(((ins >> 16) & 31) as usize)
                        & if size == 8 {
                            u64::MAX
                        } else {
                            (1u64 << (size * 8)) - 1
                        };
                    let old_signed = sign_extend(old, (size * 8) as u32) as i64;
                    let operand_signed = sign_extend(operand, (size * 8) as u32) as i64;
                    let new = match operation {
                        0 => old.wrapping_add(operand),
                        1 => old & !operand,
                        2 => old ^ operand,
                        3 => old | operand,
                        4 => {
                            if old_signed > operand_signed {
                                old
                            } else {
                                operand
                            }
                        }
                        5 => {
                            if old_signed < operand_signed {
                                old
                            } else {
                                operand
                            }
                        }
                        6 => old.max(operand),
                        7 => old.min(operand),
                        _ => operand,
                    };
                    data.copy_from_slice(&new.to_le_bytes()[..size]);
                    (old, true)
                })
                .map_err(fault)?;
            if ins & (1 << 23) != 0 && rt != 31 {
                memory.fence(Ordering::Acquire);
            }
            self.set_x(rt, old);
            return Ok(true);
        }
        if matches!(ins & 0x3f600000, 0x08600000 | 0x08200000) {
            // Pair exclusives use one reservation for the complete 64/128-bit pair.
            let load = ins & (1 << 22) != 0;
            let size = 4usize << ((ins >> 30) & 1);
            if ins >> 31 == 0 || ins & (1 << 23) != 0 {
                return Err(invalid());
            }
            let second = ((ins >> 10) & 31) as usize;
            let status = ((ins >> 16) & 31) as usize;
            if status != 31 && (load || status == rn || status == rt || status == second) {
                return Err(invalid());
            }
            let address = self.reg(rn, true);
            if !address.is_multiple_of((size * 2) as u64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            if load {
                if rt == second {
                    return Err(invalid());
                }
                let mut bytes = [0; 16];
                let token = memory
                    .exclusive_read(address, &mut bytes[..size * 2])
                    .map_err(fault)?;
                if ins & (1 << 15) != 0 {
                    memory.fence(Ordering::Acquire);
                }
                for (i, reg) in [rt, second].into_iter().enumerate() {
                    let mut value = [0; 8];
                    value[..size].copy_from_slice(&bytes[i * size..(i + 1) * size]);
                    self.set_x(reg, u64::from_le_bytes(value));
                }
                self.exclusive = Some((address, size * 2, token));
            } else {
                let token = self
                    .exclusive
                    .take()
                    .filter(|r| r.0 == address && r.1 == size * 2)
                    .map(|r| r.2);
                let mut bytes = [0; 16];
                for (i, reg) in [rt, second].into_iter().enumerate() {
                    bytes[i * size..(i + 1) * size]
                        .copy_from_slice(&self.x(reg).to_le_bytes()[..size]);
                }
                if ins & (1 << 15) != 0 {
                    memory.fence(Ordering::Release);
                }
                let succeeds = memory
                    .exclusive_write(address, &bytes[..size * 2], token)
                    .map_err(fault)?;
                self.set_x(status, (!succeeds) as u64);
            }
            return Ok(true);
        }
        if matches!(
            ins & 0x3ffffc00,
            0x085f7c00 | 0x085ffc00 | 0x08dffc00 | 0x08df7c00 | 0x38bfc000
        ) {
            // LDXR/LDAXR/LDAR/LDLAR
            let size = 1usize << (ins >> 30);
            let address = self.reg(rn, true);
            if !address.is_multiple_of(size as u64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            let mut bytes = [0; 8];
            if matches!(ins & 0x3ffffc00, 0x085f7c00 | 0x085ffc00) {
                let token = memory
                    .exclusive_read(address, &mut bytes[..size])
                    .map_err(fault)?;
                self.exclusive = Some((address, size, token));
            } else {
                memory.read(address, &mut bytes[..size]).map_err(fault)?;
            }
            if ins & 0x3ffffc00 != 0x085f7c00 {
                memory.fence(Ordering::Acquire);
            }
            self.set_x(rt, u64::from_le_bytes(bytes));
            return Ok(true);
        }
        if matches!(ins & 0x3fe0fc00, 0x08007c00 | 0x0800fc00) {
            // STXR/STLXR
            let size = 1usize << (ins >> 30);
            let address = self.reg(rn, true);
            let status = ((ins >> 16) & 31) as usize;
            if status != 31 && (status == rt || status == rn) {
                return Err(invalid());
            }
            if !address.is_multiple_of(size as u64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            let token = self
                .exclusive
                .take()
                .filter(|r| r.0 == address && r.1 == size)
                .map(|r| r.2);
            if ins & (1 << 15) != 0 {
                memory.fence(Ordering::Release);
            }
            let succeeds = memory
                .exclusive_write(address, &self.x(rt).to_le_bytes()[..size], token)
                .map_err(fault)?;
            self.set_x(status, (!succeeds) as u64);
            return Ok(true);
        }
        if matches!(ins & 0x3ffffc00, 0x089ffc00 | 0x089f7c00) {
            // STLR/STLLR
            let size = 1usize << (ins >> 30);
            let address = self.reg(rn, true);
            if !address.is_multiple_of(size as u64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            memory.fence(Ordering::Release);
            memory
                .write(address, &self.x(rt).to_le_bytes()[..size])
                .map_err(fault)?;
            return Ok(true);
        }
        if ins & 0x3f200c00 == 0x19000000 {
            // FEAT_LRCPC2: unscaled RCpc acquire loads and release stores.
            // RCpc is conservatively implemented with acquire/release; these loads
            // do not create or clear an exclusive reservation.
            let size = 1usize << (ins >> 30);
            let opc = (ins >> 22) & 3;
            if (opc == 2 && size == 8) || (opc == 3 && size >= 4) {
                return Err(invalid());
            }
            let offset = sign_extend(((ins >> 12) & 511) as u64, 9);
            let address = self.reg(rn, true).wrapping_add(offset);
            if !address.is_multiple_of(size as u64) {
                return Err(fault(MemoryError::Alignment(address)));
            }
            if opc == 0 {
                memory.fence(Ordering::Release);
                write_operand(memory, address, size, self.x(rt) as u128).map_err(fault)?;
            } else {
                let value = read_operand(memory, address, size).map_err(fault)? as u64;
                memory.fence(Ordering::Acquire);
                let value = if opc >= 2 {
                    sign_extend(value, size as u32 * 8)
                } else {
                    value
                };
                self.put(rt, value, opc != 3, false);
            }
            return Ok(true);
        }
        if ins & 0x3a000000 == 0x28000000 {
            // pair loads/stores, all address modes
            let opc = ins >> 30;
            let load = ins & (1 << 22) != 0;
            let size = if vector {
                if opc == 3 {
                    return Err(invalid());
                }
                4usize << opc
            } else {
                match opc {
                    0 => 4,
                    2 => 8,
                    1 if load => 4,
                    _ => return Err(invalid()),
                }
            };
            let rt2 = ((ins >> 10) & 31) as usize;
            let mode = (ins >> 23) & 3;
            let writeback = mode == 1 || mode == 3;
            if !vector
                && ((writeback && rn != 31 && (rn == rt || rn == rt2)) || (load && rt == rt2))
            {
                return Err(invalid());
            }
            let base = self.reg(rn, true);
            let offset = sign_extend(((ins >> 15) & 127) as u64, 7).wrapping_mul(size as u64);
            let address = if mode == 1 {
                base
            } else {
                base.wrapping_add(offset)
            };
            let mut bytes = [0; 32];
            if load {
                memory
                    .read(address, &mut bytes[..size * 2])
                    .map_err(fault)?;
                for (index, reg) in [rt, rt2].into_iter().enumerate() {
                    let mut value = [0; 16];
                    value[..size].copy_from_slice(&bytes[index * size..(index + 1) * size]);
                    if vector {
                        self.vectors[reg] = u128::from_le_bytes(value);
                    } else {
                        let raw = u64::from_le_bytes(value[..8].try_into().expect("integer pair"));
                        self.set_x(reg, if opc == 1 { sign_extend(raw, 32) } else { raw });
                    }
                }
            } else {
                for (index, reg) in [rt, rt2].into_iter().enumerate() {
                    let value = if vector {
                        self.vectors[reg]
                    } else {
                        self.x(reg) as u128
                    };
                    bytes[index * size..(index + 1) * size]
                        .copy_from_slice(&value.to_le_bytes()[..size]);
                }
                memory.write(address, &bytes[..size * 2]).map_err(fault)?;
            }
            if writeback {
                self.sp_or_x(rn, base.wrapping_add(offset));
            }
            return Ok(true);
        }
        let class = ins & 0x3b000000;
        if class == 0x39000000 || class == 0x38000000 {
            // integer/SIMD immediate or register offset
            let size_field = ins >> 30;
            let opc = (ins >> 22) & 3;
            let size = if vector && opc >= 2 {
                if size_field != 0 {
                    return Err(invalid());
                }
                16
            } else {
                1usize << size_field
            };
            let load = if vector { opc & 1 != 0 } else { opc != 0 };
            if !vector && (size == 8 || size == 4) && opc == 3 {
                return Err(invalid());
            }
            let base = self.reg(rn, true);
            let mut writeback = None;
            let address = if class == 0x39000000 {
                base.wrapping_add(((ins >> 10) & 4095) as u64 * size as u64)
            } else if ins & (1 << 21) != 0 {
                if (ins >> 10) & 3 != 2 {
                    return Err(invalid());
                }
                let option = (ins >> 13) & 7;
                let reg = ((ins >> 16) & 31) as usize;
                let index = match option {
                    2 => self.x(reg) as u32 as u64,
                    3 => self.x(reg),
                    6 => self.x(reg) as u32 as i32 as i64 as u64,
                    7 => self.x(reg),
                    _ => return Err(invalid()),
                };
                let shift = if ins & (1 << 12) != 0 {
                    size.trailing_zeros()
                } else {
                    0
                };
                base.wrapping_add(index.wrapping_shl(shift))
            } else {
                let offset = sign_extend(((ins >> 12) & 511) as u64, 9);
                let mode = (ins >> 10) & 3;
                if mode == 2 && vector {
                    return Err(invalid());
                }
                if mode != 0 && mode != 2 {
                    if !vector && rn != 31 && rn == rt {
                        return Err(invalid());
                    }
                    writeback = Some(base.wrapping_add(offset));
                }
                if mode == 1 {
                    base
                } else {
                    base.wrapping_add(offset)
                }
            };
            if !vector && size == 8 && opc == 2 {
                return Ok(true);
            } // PRFM hint, no architected memory read
            if load {
                let raw = read_operand(memory, address, size).map_err(fault)?;
                if vector {
                    self.vectors[rt] = raw;
                } else {
                    let mut value = raw as u64;
                    if opc >= 2 {
                        value = sign_extend(value, size as u32 * 8);
                    }
                    if opc == 3 {
                        value &= u32::MAX as u64;
                    }
                    self.set_x(rt, value);
                }
            } else {
                let value = if vector {
                    self.vectors[rt]
                } else {
                    self.x(rt) as u128
                };
                write_operand(memory, address, size, value).map_err(fault)?;
            }
            if let Some(value) = writeback {
                self.sp_or_x(rn, value);
            }
            return Ok(true);
        }
        if class == 0x18000000 {
            // literal integer/SIMD loads and prefetch
            let opc = ins >> 30;
            if !vector && opc == 3 {
                return Ok(true);
            }
            let size = if vector {
                if opc == 3 {
                    return Err(invalid());
                }
                4usize << opc
            } else if opc == 1 {
                8
            } else {
                4
            };
            let address = pc.wrapping_add(sign_extend((((ins >> 5) & 0x7ffff) as u64) << 2, 21));
            let value = read_operand(memory, address, size).map_err(fault)?;
            if vector {
                self.vectors[rt] = value;
            } else {
                let value = value as u64;
                self.set_x(
                    rt,
                    if opc == 2 {
                        sign_extend(value, 32)
                    } else {
                        value
                    },
                );
            }
            return Ok(true);
        }
        // Exclusive and acquire/release operations are not silently reduced to normal loads.
        Ok(false)
    }
    pub(super) fn sp_or_x(&mut self, reg: usize, value: u64) {
        if reg == 31 {
            self.sp = value;
        } else {
            self.set_x(reg, value);
        }
    }
}

#[cfg(test)]
use trames_memory::Memory;
#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    fn state(instructions: &[u32]) -> (Cpu, Memory) {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in instructions.iter().enumerate() {
            m.write(0x1000 + i as u64 * 4, &word.to_le_bytes()).unwrap();
        }
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        m.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        (Cpu::new(0x1000, 0x2ff8), m)
    }
    #[test]
    fn rcpc2_faults_and_reserved_encodings_preserve_state() {
        for word in [
            0xd9400020, 0xd9000020, 0x59400020, 0x59000020, 0x99800020, 0xd9c00020, 0x99c00020,
            0x19200020,
        ] {
            let (mut cpu, mut memory) = state(&[word]);
            cpu.set_x(0, 0x12345678);
            cpu.set_x(1, 0x2fff);
            cpu.exclusive = Some((0x2000, 8, memory.revision() as u128));
            let before = (cpu.registers, cpu.sp, cpu.exclusive, memory.revision());
            assert!(cpu.step(&mut memory).is_err(), "{word:08x}");
            assert_eq!(cpu.pc, 0x1000);
            assert_eq!(
                (cpu.registers, cpu.sp, cpu.exclusive, memory.revision()),
                before
            );
            assert_eq!(memory.read_u64(0x2000).unwrap(), 0);
        }
    }
    #[test]
    fn pair_access_faults_do_not_partially_change_memory_or_registers() {
        let (mut c, mut m) = state(&[0xa90007e0]); // stp x0,x1,[sp]
        c.set_x(0, 42);
        c.set_x(1, 17);
        m.write(0x2ff8, &9u64.to_le_bytes()).unwrap();
        assert!(c.step(&mut m).is_err());
        assert_eq!(m.read_u64(0x2ff8).unwrap(), 9);
        assert_eq!(c.pc, 0x1000);
        let (mut c, mut m) = state(&[0xa94007e0]); // ldp x0,x1,[sp]
        c.set_x(0, 42);
        c.set_x(1, 17);
        assert!(c.step(&mut m).is_err());
        assert_eq!((c.x(0), c.x(1)), (42, 17));
    }
    #[test]
    fn faulting_post_index_load_preserves_base_register() {
        let (mut c, mut m) = state(&[0xf8408420]); // ldr x0,[x1],#8
        c.set_x(1, 0x3000);
        assert!(c.step(&mut m).is_err());
        assert_eq!(c.x(1), 0x3000);
    }
    #[test]
    fn exclusive_stores_track_reservations_and_memory_mutations() {
        let (mut c, mut m) = state(&[0xc85f7c20, 0xc8027c20]); // ldxr x0,[x1]; stxr w2,x0,[x1]
        c.set_x(1, 0x2000);
        c.step(&mut m).unwrap();
        c.set_x(0, 99);
        c.step(&mut m).unwrap();
        assert_eq!(c.x(2), 0);
        assert_eq!(m.read_u64(0x2000).unwrap(), 99);
        c.pc = 0x1000;
        c.step(&mut m).unwrap();
        m.write(0x2000, &41u64.to_le_bytes()).unwrap();
        c.step(&mut m).unwrap();
        assert_eq!(c.x(2), 1);
        assert_eq!(m.read_u64(0x2000).unwrap(), 41);
        c.pc = 0x1000;
        c.set_x(1, 0x2001);
        assert!(c.step(&mut m).is_err());
    }
}

#[cfg(test)]
mod structure_tests {
    use super::*;
    use trames_memory::{Permissions, PAGE_SIZE};
    #[test]
    fn structure_fault_preserves_all_destination_registers_and_base() {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let mut cpu = Cpu::default();
        cpu.set_x(2, 0x1ff0);
        cpu.set_vector(30, 1);
        cpu.set_vector(31, 2);
        assert!(cpu.execute_memory(0x4cdfa05e, &mut memory).is_err());
        assert_eq!(cpu.vector(30), 1);
        assert_eq!(cpu.vector(31), 2);
        assert_eq!(cpu.x(2), 0x1ff0);
    }
}
