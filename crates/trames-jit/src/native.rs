// SPDX-License-Identifier: GPL-3.0-or-later
//! AArch64 integer block translator. Only the explicit instruction whitelist
//! below can enter host executable memory. No guest address becomes a host PC.
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc};
use trames_engine::CpuFault;
use trames_interpreter::Cpu;
use trames_memory::{CpuMemory, PAGE_SIZE};

type Identity = (u64, u64, u64);
const BLOCK_LIMIT: u64 = 64;
const CACHE_LIMIT: usize = 128;

#[derive(Default)]
pub(super) struct Cache {
    entries: BTreeMap<(u64, u64), Entry>,
}
struct Entry {
    checked: Identity,
    page: Identity,
    block: Option<Block>,
}
struct Block {
    code: Code,
    instructions: u64,
    next_pc: u64,
}
impl Cache {
    pub(super) fn execute(
        &mut self,
        cpu: &mut Cpu,
        memory: &impl CpuMemory,
        budget: u64,
    ) -> Result<Option<u64>, CpuFault> {
        let pc = cpu.pc;
        let limit = budget
            .min(BLOCK_LIMIT)
            .min((PAGE_SIZE - (pc & (PAGE_SIZE - 1))) / 4);
        let key = (pc, limit);
        let checked = memory.instruction_identity();
        let valid = if let Some(entry) = self.entries.get_mut(&key) {
            if entry.checked == checked {
                true
            } else {
                let page = memory
                    .instruction_page_identity(pc)
                    .map_err(|error| CpuFault::Memory { pc, error })?;
                if page == entry.page {
                    entry.checked = checked;
                    true
                } else {
                    false
                }
            }
        } else {
            false
        };
        if !valid {
            let page = memory
                .instruction_page_identity(pc)
                .map_err(|error| CpuFault::Memory { pc, error })?;
            let block = compile(memory, pc, limit)
                .map_err(|error| CpuFault::Host(format!("JIT code publication: {error}")))?;
            if self.entries.len() >= CACHE_LIMIT {
                self.entries.pop_first();
            }
            self.entries.insert(
                key,
                Entry {
                    checked,
                    page,
                    block,
                },
            );
        }
        let Some(block) = self
            .entries
            .get(&key)
            .and_then(|entry| entry.block.as_ref())
        else {
            return Ok(None);
        };
        // SAFETY: code only reads/writes the supplied 31-register array, through
        // statically bounded offsets. No host state or guest memory is aliased.
        unsafe {
            block.code.call(cpu.general_registers_mut());
        }
        cpu.pc = block.next_pc;
        Ok(Some(block.instructions))
    }
}

fn load(code: &mut Vec<u32>, guest: u32, host: u32) {
    if guest == 31 {
        code.push(0xaa1f03e0 | host);
    } else {
        code.push(0xf9400000 | (guest << 10) | (12 << 5) | host);
    }
}
fn store(code: &mut Vec<u32>, guest: u32) {
    if guest != 31 {
        code.push(0xf9000000 | (guest << 10) | (12 << 5) | 11);
    }
}
fn constant(code: &mut Vec<u32>, value: u64) {
    code.push(0xd280000b | (((value & 0xffff) as u32) << 5));
    for half in 1..4 {
        code.push(0xf280000b | (half << 21) | ((((value >> (half * 16)) & 0xffff) as u32) << 5));
    }
}
fn signed(value: u64, bits: u32) -> u64 {
    ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
}

fn compile(memory: &impl CpuMemory, start: u64, limit: u64) -> std::io::Result<Option<Block>> {
    let mut code = vec![0xd503245f, 0xaa0003ec]; // BTI c; mov x12, x0
    let mut count = 0;
    let mut next = start;
    for _ in 0..limit {
        let pc = next;
        // Never report a lookahead fault: the interpreter faults at reached PC.
        let Ok(word) = memory.fetch_u32(pc) else {
            break;
        };
        let rd = word & 31;
        let rn = (word >> 5) & 31;
        let rm = (word >> 16) & 31;
        let sf = word >> 31;
        let mut terminal = false;
        if word == 0xd503201f { // NOP
        } else if word & 0x1f800000 == 0x12800000 {
            // MOVN/Z/K
            let opc = (word >> 29) & 3;
            if opc == 1 || (sf == 0 && (word >> 21) & 3 >= 2) {
                break;
            }
            if opc == 3 {
                load(&mut code, rd, 11);
            }
            code.push((word & !31) | 11);
            store(&mut code, rd);
        } else if word & 0x1f800000 == 0x11000000 && word & (1 << 29) == 0 {
            // ADD/SUB immediate, no flags/SP
            if rd == 31 || rn == 31 {
                break;
            }
            load(&mut code, rn, 9);
            code.push((word & !0x3ff) | (9 << 5) | 11);
            store(&mut code, rd);
        } else if word & 0x1f200000 == 0x0b000000 && word & (1 << 29) == 0 {
            // ADD/SUB shifted
            if (word >> 22) & 3 == 3 || (sf == 0 && (word >> 10) & 63 >= 32) {
                break;
            }
            load(&mut code, rn, 9);
            load(&mut code, rm, 10);
            code.push((word & !0x1f03ff) | (10 << 16) | (9 << 5) | 11);
            store(&mut code, rd);
        } else if word & 0x1f000000 == 0x0a000000 && (word >> 29) & 3 != 3 {
            // AND/ORR/EOR, including inverted operand
            if sf == 0 && (word >> 10) & 63 >= 32 {
                break;
            }
            load(&mut code, rn, 9);
            load(&mut code, rm, 10);
            code.push((word & !0x1f03ff) | (10 << 16) | (9 << 5) | 11);
            store(&mut code, rd);
        } else if word & 0x1f000000 == 0x10000000 {
            // ADR/ADRP uses original guest PC
            let imm = signed(
                (((word >> 5) & 0x7ffff) as u64) << 2 | ((word >> 29) & 3) as u64,
                21,
            );
            let value = if sf == 1 {
                (pc & !0xfff).wrapping_add(imm << 12)
            } else {
                pc.wrapping_add(imm)
            };
            constant(&mut code, value);
            store(&mut code, rd);
        } else if word & 0x7c000000 == 0x14000000 {
            // B/BL never host branch to a guest address
            if sf == 1 {
                constant(&mut code, pc.wrapping_add(4));
                store(&mut code, 30);
            }
            next = pc.wrapping_add(signed((word & 0x3ffffff) as u64, 26) << 2);
            terminal = true;
        } else {
            break;
        }
        count += 1;
        if terminal {
            break;
        }
        next = next.wrapping_add(4);
    }
    if count == 0 {
        return Ok(None);
    }
    code.push(0xd65f03c0); // ret; incoming LR, SP, x18 and FP state untouched
    Ok(Some(Block {
        code: Code::publish(&code)?,
        instructions: count,
        next_pc: next,
    }))
}

/// Thread-affine executable mapping. Never writable while callable; mappings
/// are released on eviction/worker drop. No Rust allocation becomes executable.
struct Code {
    pointer: *mut libc::c_void,
    length: usize,
    _thread: PhantomData<Rc<()>>,
}
impl Code {
    fn publish(words: &[u32]) -> std::io::Result<Self> {
        // SAFETY: sysconf has no memory arguments; host page size is cold-path.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        let length = (words.len() * 4).div_ceil(page as usize) * page as usize;
        // SAFETY: anonymous private pages, no caller-owned range or descriptor.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let mapping = Self {
            pointer,
            length,
            _thread: PhantomData,
        };
        // SAFETY: this fresh RW mapping has capacity for all words. No execution
        // is possible until cache maintenance and the RX transition complete.
        unsafe {
            std::ptr::copy_nonoverlapping(words.as_ptr(), pointer.cast(), words.len());
            flush(pointer as usize, words.len() * 4);
            if libc::mprotect(pointer, length, libc::PROT_READ | libc::PROT_EXEC) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(mapping)
    }
    unsafe fn call(&self, registers: &mut [u64; 31]) {
        // SAFETY: codegen emits an AAPCS64 function with this exact ABI. The
        // entry begins with BTI c and returns through untouched host x30.
        let function: unsafe extern "C" fn(*mut u64) = unsafe { std::mem::transmute(self.pointer) };
        unsafe {
            function(registers.as_mut_ptr());
        }
    }
}
impl Drop for Code {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.pointer, self.length);
        }
    }
}
unsafe fn flush(start: usize, length: usize) {
    let ctr: u64;
    // SAFETY: mandated AArch64 instruction publication sequence. These cache
    // barriers occur only when publishing code, never on ordinary guest data.
    unsafe {
        std::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nomem, nostack));
        let dline = 4usize << ((ctr >> 16) & 15);
        let iline = 4usize << (ctr & 15);
        let end = start + length;
        let mut address = start & !(dline - 1);
        while address < end {
            std::arch::asm!("dc cvau, {address}", address = in(reg) address, options(nostack));
            address += dline;
        }
        std::arch::asm!("dsb ish", options(nostack));
        address = start & !(iline - 1);
        while address < end {
            std::arch::asm!("ic ivau, {address}", address = in(reg) address, options(nostack));
            address += iline;
        }
        std::arch::asm!("dsb ish", "isb", options(nostack));
    }
}
