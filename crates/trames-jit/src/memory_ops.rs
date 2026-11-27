// SPDX-License-Identifier: GPL-3.0-or-later
//! Decoded scalar memory fragments. Native data access stays inside the existing
//! Memory/View borrow; no guest pointer, lease or translation survives the call.
use crate::native::Code;
use trames_engine::CpuFault;
use trames_interpreter::Cpu;
use trames_memory::{CpuMemory, PAGE_SIZE};

#[derive(Clone, Copy)]
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
        let code = opcode
            .map(|word| Code::publish(&[0xd503245f, word, 0xd65f03c0]))
            .transpose()
            .map_err(|e| CpuFault::Host(format!("JIT memory publication: {e}")))?;
        Ok(Some(Self {
            pc,
            address,
            rn,
            rt,
            size,
            load,
            opcode,
            code,
        }))
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
        let crosses = self.size as u64 > PAGE_SIZE - (address & (PAGE_SIZE - 1));
        let direct = if self.load {
            let (value, direct) = if crosses {
                // Canonical read owns cross-page permission/fault ordering and
                // staging; never issue a native load across disjoint host pages.
                let mut bytes = [0u8; 8];
                memory
                    .read(address, &mut bytes[..self.size])
                    .map_err(fault)?;
                (unsafe { code.call_memory(bytes.as_mut_ptr(), 0) }, false)
            } else {
                memory
                    .cpu_read_chunk(address, self.size, |bytes| {
                        // SAFETY: decoder emitted only a load of this exact width.
                        // The borrowed bytes are live; generated code cannot store.
                        unsafe { code.call_memory(bytes.as_ptr().cast_mut(), 0) }
                    })
                    .map_err(fault)?
            };
            cpu.set_x(self.rt, value);
            direct
        } else {
            // Snapshot the source before base writeback, including SP/ZR aliases.
            let value = cpu.x(self.rt);
            if crosses {
                let mut bytes = [0u8; 8];
                unsafe { code.call_memory(bytes.as_mut_ptr(), value) };
                memory.write(address, &bytes[..self.size]).map_err(fault)?;
                false
            } else {
                memory
                    .cpu_store_chunk(address, self.size, |bytes| {
                        // SAFETY: exact-width store, wholly inside the existing
                        // write lease. Its owner handles dirty/code/monitor updates.
                        unsafe { code.call_memory(bytes.as_mut_ptr(), value) };
                    })
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
