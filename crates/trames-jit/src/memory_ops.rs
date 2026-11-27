// SPDX-License-Identifier: GPL-3.0-or-later
//! Decoded scalar memory fragments. Native data access stays inside the existing
//! Memory/View borrow; no guest pointer, lease or translation survives the call.
use crate::native::Code;
use trames_engine::CpuFault;
use trames_interpreter::Cpu;
use trames_memory::{CpuMemory, PAGE_SIZE};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Address {
    Offset(u64),
    Pre(u64),
    Post(u64),
    Register { reg: usize, option: u32, shift: u32 },
    Literal(u64),
}
pub(super) struct Operation {
    pc: u64,
    pub(super) address: Address,
    pub(super) rn: usize,
    pub(super) rt: usize,
    pub(super) size: usize,
    pub(super) load: bool,
    pub(super) second: Option<usize>,
    pub(super) ordered: bool,
    pub(super) opcode: Option<u32>,
    code: Option<Code>, // PRFM is an architecturally optional hint, no read.
}
fn signed(value: u64, bits: u32) -> u64 {
    ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
}
impl Operation {
    pub fn compile(memory: &impl CpuMemory, pc: u64) -> Result<Option<Self>, CpuFault> {
        let word = memory
            .fetch_u32(pc)
            .map_err(|error| CpuFault::Memory { pc, error })?;
        if word & (1 << 26) != 0 {
            return Ok(None);
        } // SIMD requires a separate lowering.
        let rt = (word & 31) as usize;
        let rn = ((word >> 5) & 31) as usize;
        if matches!(word & 0x3ffffc00, 0x08dffc00 | 0x089ffc00) {
            if !memory.cpu_hardware_ordering() {
                return Ok(None);
            }
            let load = word & (1 << 22) != 0;
            return Self {
                pc,
                address: Address::Offset(0),
                rn,
                rt,
                size: 1usize << (word >> 30),
                load,
                second: None,
                ordered: true,
                opcode: Some((word & !0x3ff) | u32::from(!load)),
                code: None,
            }
            .publish()
            .map(Some);
        }
        if word & 0x3a000000 == 0x28000000 {
            let opc = word >> 30;
            let load = word & (1 << 22) != 0;
            let element = match opc {
                0 => 4,
                2 => 8,
                1 if load => 4,
                _ => return Ok(None),
            };
            let second = ((word >> 10) & 31) as usize;
            let mode = (word >> 23) & 3;
            if (matches!(mode, 1 | 3) && rn != 31 && (rn == rt || rn == second))
                || (load && rt == second)
                || (opc == 1 && mode == 0)
            {
                return Ok(None);
            }
            let offset = signed(((word >> 15) & 127) as u64, 7).wrapping_mul(element as u64);
            let address = match mode {
                1 => Address::Post(offset),
                3 => Address::Pre(offset),
                _ => Address::Offset(offset),
            };
            let mut opcode = match opc {
                0 => 0x29000000,
                1 => 0x69000000,
                _ => 0xa9000000,
            };
            if load {
                opcode |= 1 << 22;
            }
            if mode == 0 {
                opcode &= !(1 << 24);
            } // preserve non-temporal hint
            opcode |= if load { 1 << 10 } else { (2 << 10) | 1 };
            return Self {
                pc,
                address,
                rn,
                rt,
                size: element * 2,
                load,
                second: Some(second),
                ordered: false,
                opcode: Some(opcode),
                code: None,
            }
            .publish()
            .map(Some);
        }
        let class = word & 0x3b000000;
        let (address, size, opc) = if class == 0x18000000 {
            let opc = word >> 30;
            (
                Address::Literal(pc.wrapping_add(signed(((word >> 5) & 0x7ffff) as u64, 19) << 2)),
                if opc == 1 { 8 } else { 4 },
                if opc == 3 { 4 } else { [1, 1, 2][opc as usize] },
            )
        } else if matches!(class, 0x39000000 | 0x38000000) {
            let size = 1usize << (word >> 30);
            let opc = (word >> 22) & 3;
            if size >= 4 && opc == 3 {
                return Ok(None);
            }
            let address = if class == 0x39000000 {
                Address::Offset(((word >> 10) & 4095) as u64 * size as u64)
            } else if word & (1 << 21) != 0 {
                let option = (word >> 13) & 7;
                if (word >> 10) & 3 != 2 || !matches!(option, 2 | 3 | 6 | 7) {
                    return Ok(None);
                }
                Address::Register {
                    reg: ((word >> 16) & 31) as usize,
                    option,
                    shift: if word & (1 << 12) != 0 {
                        size.trailing_zeros()
                    } else {
                        0
                    },
                }
            } else {
                let offset = signed(((word >> 12) & 511) as u64, 9);
                match (word >> 10) & 3 {
                    1 | 3 if rn != 31 && rn == rt => return Ok(None),
                    1 => Address::Post(offset),
                    3 => Address::Pre(offset),
                    _ => Address::Offset(offset), // LDTR/STTR have the same EL0 data permissions.
                }
            };
            (address, size, if size == 8 && opc == 2 { 4 } else { opc })
        } else {
            return Ok(None);
        };
        let load = opc != 0;
        let opcode = match (size, opc) {
            (_, 4) => None,
            (1, 0) => Some(0x39000001),
            (2, 0) => Some(0x79000001),
            (4, 0) => Some(0xb9000001),
            (8, 0) => Some(0xf9000001),
            (1, 1) => Some(0x39400000),
            (2, 1) => Some(0x79400000),
            (4, 1) => Some(0xb9400000),
            (8, 1) => Some(0xf9400000),
            (1, 2) => Some(0x39800000),
            (2, 2) => Some(0x79800000),
            (4, 2) => Some(0xb9800000),
            (1, 3) => Some(0x39c00000),
            (2, 3) => Some(0x79c00000),
            _ => return Ok(None),
        };
        Self {
            pc,
            address,
            rn,
            rt,
            size,
            load,
            second: None,
            ordered: false,
            opcode,
            code: None,
        }
        .publish()
        .map(Some)
    }
    fn publish(mut self) -> Result<Self, CpuFault> {
        self.code = self
            .opcode
            .map(|word| Code::publish(&[0xd503245f, word, 0xd65f03c0]))
            .transpose()
            .map_err(|e| CpuFault::Host(format!("JIT memory publication: {e}")))?;
        Ok(self)
    }
    pub fn pc(&self) -> u64 {
        self.pc
    }
    pub fn host_words(&self) -> u64 {
        if self.code.is_some() {
            3
        } else {
            0
        }
    }
    pub(super) fn operand(&self, cpu: &Cpu) -> (u64, Option<u64>) {
        let base = if self.rn == 31 {
            cpu.sp
        } else {
            cpu.x(self.rn)
        };
        match self.address {
            Address::Offset(offset) => (base.wrapping_add(offset), None),
            Address::Pre(offset) => {
                let next = base.wrapping_add(offset);
                (next, Some(next))
            }
            Address::Post(offset) => (base, Some(base.wrapping_add(offset))),
            Address::Literal(address) => (address, None),
            Address::Register { reg, option, shift } => {
                let raw = cpu.x(reg);
                let index = match option {
                    2 => raw as u32 as u64,
                    6 => raw as u32 as i32 as i64 as u64,
                    _ => raw,
                };
                (base.wrapping_add(index.wrapping_shl(shift)), None)
            }
        }
    }
    pub fn execute(&self, cpu: &mut Cpu, memory: &mut impl CpuMemory) -> Result<bool, CpuFault> {
        let pc = cpu.pc;
        let Some(code) = &self.code else {
            cpu.pc = pc.wrapping_add(4);
            return Ok(true);
        };
        let (address, writeback) = self.operand(cpu);
        let fault = |error| CpuFault::Memory { pc, error };
        // Checked-access recovery retains the existing interpreter fault boundary.
        // Inline native accesses rely on hardware, without a software preflight.
        if self.ordered && !address.is_multiple_of(self.size as u64) {
            return Err(fault(trames_memory::MemoryError::Alignment(address)));
        }
        let crosses = self.size as u64 > PAGE_SIZE - (address & (PAGE_SIZE - 1));
        let direct = if let Some(second) = self.second {
            if self.load {
                let (values, direct) = if crosses {
                    let mut bytes = [0u8; 16];
                    memory
                        .read(address, &mut bytes[..self.size])
                        .map_err(fault)?;
                    (unsafe { code.call_pair(bytes.as_mut_ptr(), 0, 0) }, false)
                } else {
                    memory
                        .cpu_read_chunk(address, self.size, |bytes| unsafe {
                            code.call_pair(bytes.as_ptr().cast_mut(), 0, 0)
                        })
                        .map_err(fault)?
                };
                cpu.set_x(self.rt, values.first);
                cpu.set_x(second, values.second);
                direct
            } else {
                let first = cpu.x(self.rt);
                let second = cpu.x(second);
                if crosses {
                    let mut bytes = [0u8; 16];
                    unsafe { code.call_pair(bytes.as_mut_ptr(), first, second) };
                    memory.write(address, &bytes[..self.size]).map_err(fault)?;
                    false
                } else {
                    memory
                        .cpu_store_chunk(address, self.size, |bytes| unsafe {
                            code.call_pair(bytes.as_mut_ptr(), first, second);
                        })
                        .map_err(fault)?
                        .1
                }
            }
        } else if self.load {
            let (value, direct) = if crosses {
                let mut bytes = [0u8; 8];
                memory
                    .read(address, &mut bytes[..self.size])
                    .map_err(fault)?;
                (unsafe { code.call_memory(bytes.as_mut_ptr(), 0) }, false)
            } else {
                let operation =
                    |bytes: &[u8]| unsafe { code.call_memory(bytes.as_ptr().cast_mut(), 0) };
                if self.ordered {
                    memory.cpu_acquire_chunk(address, self.size, operation)
                } else {
                    memory.cpu_read_chunk(address, self.size, operation)
                }
                .map_err(fault)?
            };
            cpu.set_x(self.rt, value);
            direct
        } else {
            let value = cpu.x(self.rt);
            if crosses {
                let mut bytes = [0u8; 8];
                unsafe { code.call_memory(bytes.as_mut_ptr(), value) };
                memory.write(address, &bytes[..self.size]).map_err(fault)?;
                false
            } else {
                let operation = |bytes: &mut [u8]| unsafe {
                    code.call_memory(bytes.as_mut_ptr(), value);
                };
                if self.ordered {
                    memory.cpu_release_chunk(address, self.size, operation)
                } else {
                    memory.cpu_store_chunk(address, self.size, operation)
                }
                .map_err(fault)?
                .1
            }
        };
        if let Some(value) = writeback {
            if self.rn == 31 {
                cpu.sp = value;
            } else {
                cpu.set_x(self.rn, value);
            }
        }
        cpu.pc = pc.wrapping_add(4);
        Ok(direct)
    }
}
