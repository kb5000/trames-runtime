// SPDX-License-Identifier: GPL-3.0-or-later
//! AArch64 integer blocks with local register allocation and explicit exits.
//! Only whitelisted instructions enter host executable memory. Guest SVC is
//! translated into a block exit; no guest address becomes a host PC/syscall.
use crate::CompilationStats;
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
    pub stats: CompilationStats,
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
    syscall: bool,
    traffic: CompilationStats,
}
pub(super) struct Executed {
    pub instructions: u64,
    pub syscall: bool,
}
impl Cache {
    pub(super) fn execute(
        &mut self,
        cpu: &mut Cpu,
        memory: &impl CpuMemory,
        budget: u64,
    ) -> Result<Option<Executed>, CpuFault> {
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
            if let Some(block) = &block {
                self.stats.blocks += 1;
                self.stats.host_words += block.traffic.host_words;
                self.stats.register_loads += block.traffic.register_loads;
                self.stats.register_stores += block.traffic.register_stores;
            }
            if self.entries.len() >= CACHE_LIMIT && !self.entries.contains_key(&key) {
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
        // SAFETY: code reads/writes only the supplied 31-register frame, through
        // statically bounded offsets. Dirty values flush before every block exit.
        unsafe {
            block.code.call(cpu.general_registers_mut());
        }
        cpu.pc = block.next_pc;
        Ok(Some(Executed {
            instructions: block.instructions,
            syscall: block.syscall,
        }))
    }
}

#[derive(Clone, Copy)]
struct Binding {
    guest: u32,
    dirty: bool,
    used: u32,
}
/// Compile-time allocation only. x0 retains the register-frame argument; x1-x17
/// are caller-saved. x18/TLS, x19-x30, host SP and FP/SIMD are never modified.
/// Bindings do not survive block exit, so worker/task migration needs no flush.
struct Assembler {
    words: Vec<u32>,
    bindings: [Option<Binding>; 17],
    hosts: [u8; 31],
    clock: u32,
    traffic: CompilationStats,
}
impl Assembler {
    fn new() -> Self {
        Self {
            words: vec![0xd503245f],
            bindings: [None; 17],
            hosts: [u8::MAX; 31],
            clock: 0,
            traffic: CompilationStats::default(),
        }
    }
    fn store(&mut self, slot: usize, binding: Binding) {
        if binding.dirty {
            self.words
                .push(0xf9000000 | (binding.guest << 10) | (slot as u32 + 1)); // str xH,[x0,#guest*8]
            self.traffic.register_stores += 1;
        }
    }
    fn bind(&mut self, guest: u32, avoid: u32, read: bool) -> u32 {
        if guest == 31 {
            return 31;
        } // architectural zero, never a frame slot
        self.clock += 1;
        let existing = self.hosts[guest as usize];
        let slot = if existing != u8::MAX {
            existing as usize
        } else {
            let slot = self
                .bindings
                .iter()
                .position(Option::is_none)
                .unwrap_or_else(|| {
                    self.bindings
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| avoid & (1 << (i + 1)) == 0)
                        .min_by_key(|(_, b)| b.expect("occupied register").used)
                        .expect("at most two pinned sources")
                        .0
                });
            if let Some(binding) = self.bindings[slot] {
                self.store(slot, binding);
                self.hosts[binding.guest as usize] = u8::MAX;
            }
            if read {
                self.words
                    .push(0xf9400000 | (guest << 10) | (slot as u32 + 1)); // ldr xH,[x0,#guest*8]
                self.traffic.register_loads += 1;
            }
            self.hosts[guest as usize] = slot as u8;
            self.bindings[slot] = Some(Binding {
                guest,
                dirty: false,
                used: self.clock,
            });
            slot
        };
        let binding = self.bindings[slot].as_mut().expect("bound register");
        binding.used = self.clock;
        binding.dirty |= !read;
        slot as u32 + 1
    }
    fn read(&mut self, guest: u32, avoid: u32) -> u32 {
        self.bind(guest, avoid, true)
    }
    fn output(&mut self, guest: u32, avoid: u32) -> u32 {
        self.bind(guest, avoid, false)
    }
    fn constant(&mut self, guest: u32, value: u64) {
        if guest == 31 {
            return;
        }
        let host = self.output(guest, 0);
        self.words
            .push(0xd2800000 | (((value & 0xffff) as u32) << 5) | host);
        for half in 1..4 {
            let part = ((value >> (half * 16)) & 0xffff) as u32;
            if part != 0 {
                self.words
                    .push(0xf2800000 | (half << 21) | (part << 5) | host);
            }
        }
    }
    fn finish(mut self) -> (Vec<u32>, CompilationStats) {
        for slot in 0..self.bindings.len() {
            if let Some(binding) = self.bindings[slot] {
                self.store(slot, binding);
            }
        }
        self.words.push(0xd65f03c0); // ret: untouched incoming host LR
        self.traffic.host_words = self.words.len() as u64;
        (self.words, self.traffic)
    }
}
fn signed(value: u64, bits: u32) -> u64 {
    ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
}

fn compile(memory: &impl CpuMemory, start: u64, limit: u64) -> std::io::Result<Option<Block>> {
    let mut code = Assembler::new();
    let mut count = 0;
    let mut next = start;
    let mut syscall = false;
    for _ in 0..limit {
        let pc = next;
        // Never report lookahead faults; fault only when the reached PC fails.
        let Ok(word) = memory.fetch_u32(pc) else {
            break;
        };
        let rd = word & 31;
        let rn = (word >> 5) & 31;
        let rm = (word >> 16) & 31;
        let sf = word >> 31;
        let mut terminal = false;
        if word & 0xffe0001f == 0xd4000001 {
            // Retire SVC exactly once, advance guest PC and return to Runtime.
            // Never put the guest SVC opcode in host executable memory.
            syscall = true;
            next = pc.wrapping_add(4);
            terminal = true;
        } else if word == 0xd503201f { // NOP
        } else if word & 0x1f800000 == 0x12800000 {
            let opc = (word >> 29) & 3;
            if opc == 1 || (sf == 0 && (word >> 21) & 3 >= 2) {
                break;
            }
            if opc == 3 {
                code.read(rd, 0);
            }
            let dest = code.output(rd, 0);
            code.words.push((word & !31) | dest);
        } else if word & 0x1f800000 == 0x11000000 && word & (1 << 29) == 0 {
            if rd == 31 || rn == 31 {
                break;
            } // SP forms still use interpreter
            let lhs = code.read(rn, 0);
            let dest = code.output(rd, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
        } else if word & 0x1f200000 == 0x0b000000 && word & (1 << 29) == 0 {
            if (word >> 22) & 3 == 3 || (sf == 0 && (word >> 10) & 63 >= 32) {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        } else if word & 0x1f000000 == 0x0a000000 && (word >> 29) & 3 != 3 {
            if sf == 0 && (word >> 10) & 63 >= 32 {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        } else if word & 0x1f000000 == 0x10000000 {
            let imm = signed(
                (((word >> 5) & 0x7ffff) as u64) << 2 | ((word >> 29) & 3) as u64,
                21,
            );
            let value = if sf == 1 {
                (pc & !0xfff).wrapping_add(imm << 12)
            } else {
                pc.wrapping_add(imm)
            };
            code.constant(rd, value);
        } else if word & 0x7c000000 == 0x14000000 {
            if sf == 1 {
                code.constant(30, pc.wrapping_add(4));
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
    let (words, traffic) = code.finish();
    Ok(Some(Block {
        code: Code::publish(&words)?,
        instructions: count,
        next_pc: next,
        syscall,
        traffic,
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn syscall_exit_emits_no_host_supervisor_call() {
        let mut memory = trames_memory::Memory::default();
        memory
            .map(0x1000, PAGE_SIZE, trames_memory::Permissions::RW)
            .unwrap();
        memory
            .write_array(0x1000, 0xd4000001u32.to_le_bytes())
            .unwrap();
        memory
            .protect(0x1000, PAGE_SIZE, trames_memory::Permissions::RX)
            .unwrap();
        let block = compile(&memory, 0x1000, 64).unwrap().unwrap();
        assert!(block.syscall);
        assert_eq!((block.instructions, block.next_pc), (1, 0x1004));
        // SAFETY: inspect exactly the initialized words of this live RX mapping.
        let words = unsafe {
            std::slice::from_raw_parts(
                block.code.pointer.cast::<u32>(),
                block.traffic.host_words as usize,
            )
        };
        assert_eq!(words, &[0xd503245f, 0xd65f03c0]); // BTI c; RET
    }
}
