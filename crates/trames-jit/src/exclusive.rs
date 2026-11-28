// SPDX-License-Identifier: GPL-3.0-or-later
//! Closed private LL/SC windows. Integer lowering and register allocation are
//! shared with ordinary blocks. No helper or register-frame traffic occurs
//! between the real LR and SC; open/shared sequences use the existing monitor.
use super::{Assembler, Block, Code, CompileContext, Compiled, Flow, Frame};
use crate::memory_ops::Operation;
use trames_engine::CpuFault;
use trames_interpreter::Cpu;
use trames_memory::CpuMemory;

pub(super) struct Plan {
    pub first: Operation,
    pub last: Operation,
    pub count: u64,
}
pub(super) struct Window {
    plan: Plan,
    block: Block,
}
pub(super) struct Run {
    pub instructions: u64,
    pub accesses: u64,
    pub direct: bool,
}
fn exclusive(word: u32) -> bool {
    matches!(word & 0x3f600000, 0x08600000 | 0x08200000)
        || matches!(word & 0x3ffffc00, 0x085f7c00 | 0x085ffc00)
        || matches!(word & 0x3fe0fc00, 0x08007c00 | 0x0800fc00)
}
/// Cold structural admission only. Encoding validity/semantics still belong to
/// the shared scalar lowerer. Branches, callbacks and other memory end a window.
pub(super) fn integer(word: u32) -> bool {
    word == 0xd503201f
        || matches!(
            word & 0x1f800000,
            0x12800000 | 0x11000000 | 0x12000000 | 0x13000000 | 0x13800000
        )
        || matches!(word & 0x1f200000, 0x0b000000 | 0x0b200000)
        || matches!(word & 0x1f000000, 0x0a000000 | 0x1b000000 | 0x10000000)
        || word & 0x1fe00800 == 0x1a800000
        || word & 0x1fe00410 == 0x1a400000
        || word & 0x1fe0fc00 == 0x1a000000
        || word & 0x5fe00000 == 0x1ac00000
        || word & 0x7fe00000 == 0x5ac00000
        || word & 0x7fe0e000 == 0x1ac04000
        || word & 0x7fe0f000 == 0x1ac06000
        || word & 0x7ff00000 == 0x11c00000
        || matches!(word, 0xd500401f | 0xd500403f | 0xd500405f)
        || word & 0xffe07c10 == 0xba000400
        || word & 0xffffbc1f == 0x3a00080d
        || matches!(word & !31, 0xd53b4200 | 0xd51b4200)
}
impl Window {
    pub fn compile(
        memory: &impl CpuMemory,
        pc: u64,
        limit: u64,
        mode: u8,
    ) -> Result<Option<Self>, CpuFault> {
        if mode & 16 == 0 || limit < 2 || !memory.fetch_u32(pc).is_ok_and(exclusive) {
            return Ok(None);
        }
        let Some(first) = Operation::compile(memory, pc)? else {
            return Ok(None);
        };
        if first.exclusive.is_none()
            || !first.load
            || first.rn != 31 && (first.rt == first.rn || first.second == Some(first.rn))
        {
            return Ok(None);
        }
        for count in 2..=limit.min(16) {
            let end = pc.wrapping_add((count - 1) * 4);
            let Ok(word) = memory.fetch_u32(end) else {
                break;
            };
            if exclusive(word) {
                let Some(last) = Operation::compile(memory, end)? else {
                    break;
                };
                if last.exclusive.is_none()
                    || last.load
                    || last.rn != first.rn
                    || last.size != first.size
                    || last.second.is_some() != first.second.is_some()
                {
                    break;
                }
                let plan = Plan { first, last, count };
                let compiled = super::compile_body(
                    memory,
                    pc,
                    count,
                    0,
                    mode,
                    crate::features::profile().allowed,
                    CompileContext {
                        window: Some(&plan),
                        ..Default::default()
                    },
                )?;
                return Ok(compiled.map(|compiled| Self {
                    plan,
                    block: compiled.block,
                }));
            }
            if !integer(word) {
                break;
            }
        }
        Ok(None)
    }
    pub fn instructions(&self) -> u64 {
        self.plan.count
    }
    pub fn host_words(&self) -> u64 {
        self.block.code.word_count() + self.plan.first.host_words() + self.plan.last.host_words()
    }
    pub fn execute(
        &self,
        cpu: &mut Cpu,
        memory: &mut impl CpuMemory,
        frame: &mut Frame,
    ) -> Result<Run, (u64, CpuFault)> {
        let (address, _) = self.plan.first.operand(cpu);
        // No outstanding alias exists at this entry. Admission changes no VMA,
        // COW, residency or permissions; a decline executes the native checked LR.
        let alias = unsafe { memory.cpu_exclusive_page(address, self.plan.first.size) }
            .filter(|page| page.read != 0 && page.write != 0);
        let Some(page) = alias else {
            let direct = self.plan.first.execute(cpu, memory).map_err(|e| (0, e))?;
            return Ok(Run {
                instructions: 1,
                accesses: 1,
                direct,
            });
        };
        let clean = address & 0x00ff_ffff_ffff_ffff;
        // Protected CPU alias, not a raw Rust byte pointer. LR/SC faults resume
        // at exact emitted fixups with the host ABI/frame still live.
        frame.link_pcs = (page.read + (clean - page.base) as usize) as *const u64;
        let status = unsafe {
            self.block
                .code
                .call_window(cpu.native_register_pointers().0, frame)
        };
        if status == 2 {
            // The LR did not retire and published no CPU state. An alias fault
            // is classified/repaired by the same original checked LR boundary.
            let direct = self.plan.first.execute(cpu, memory).map_err(|e| (0, e))?;
            return Ok(Run {
                instructions: 1,
                accesses: 1,
                direct,
            });
        }
        cpu.sp = frame.sp;
        cpu.set_nzcv((frame.nzcv >> 28) as u32);
        if status == 3 {
            // SC fault published the exact dirty LR/ALU prefix, without status
            // writeback. Rejoin the original reservation domain only on this
            // cold path; the private window has made no intervening store.
            let retired = self.plan.count - 1;
            cpu.pc = self.plan.last.pc();
            let mut bytes = [0; 16];
            let token = memory
                .exclusive_read(address, &mut bytes[..self.plan.first.size])
                .map_err(|e| {
                    (
                        retired,
                        CpuFault::Memory {
                            pc: cpu.pc,
                            error: e,
                        },
                    )
                })?;
            cpu.set_exclusive(address, self.plan.first.size, token);
            let direct = self
                .plan
                .last
                .execute(cpu, memory)
                .map_err(|e| (retired, e))?;
            return Ok(Run {
                instructions: self.plan.count,
                accesses: 2,
                direct,
            });
        }
        debug_assert!(status <= 1);
        cpu.clear_exclusive();
        cpu.pc = self.plan.last.pc().wrapping_add(4);
        Ok(Run {
            instructions: self.plan.count,
            accesses: 2,
            direct: true,
        })
    }
}

pub(super) fn load(code: &mut Assembler, op: &Operation) -> usize {
    let a = code.output(op.rt as u32, 0);
    let b = op.second.map_or(31, |reg| code.output(reg as u32, 1 << a));
    let word = op.exclusive.unwrap().word & !0x1f7fff;
    let at = code.words.len();
    code.words
        .push(word | (31 << 16) | (b << 10) | (19 << 5) | a);
    code.monitor = true;
    at
}
pub(super) fn store(code: &mut Assembler, op: &Operation) -> (usize, Assembler) {
    let a = code.read(op.rt as u32, 0);
    let b = op.second.map_or(31, |reg| code.read(reg as u32, 1 << a));
    let mut prefix = code.clone();
    prefix.words.clear();
    prefix.monitor = false;
    let at = code.words.len();
    let word = op.exclusive.unwrap().word & !0x1f7fff;
    code.words
        .push(word | (17 << 16) | (b << 10) | (19 << 5) | a);
    code.monitor = false;
    let dest = code.output(op.exclusive.unwrap().status as u32, 0);
    code.words.push(0x2a1103e0 | dest); // mov wStatus,w17 (architectural zero ignored)
    (at, prefix)
}
fn epilogue(words: &mut Vec<u32>) {
    words.extend_from_slice(&[0xa8c17bf3, 0xd65f03c0]); // ldp x19,x30,[sp],#16; ret
}
pub(super) fn finish(
    code: Assembler,
    lr: usize,
    (sc, mut prefix): (usize, Assembler),
    next: u64,
    count: u64,
) -> Result<Compiled, CpuFault> {
    let (body, mut traffic, context) = code.finish();
    let mut words = vec![0xd503245f, 0xa9bf7bf3, 0xaa0103f0]; // bti c; save x19/LR; ctx=x1
    super::load(&mut words, 19, 16, 96);
    let start = words.len();
    words.extend_from_slice(&body);
    words.push(0xaa1103e0); // mov x0,x17; SC status
    epilogue(&mut words);
    let load_fault = words.len();
    words.extend_from_slice(&[0xd5033f5f, 0xd2800040]); // clrex; return 2
    epilogue(&mut words);
    let store_fault = words.len();
    words.push(0xd5033f5f);
    prefix.flush();
    words.extend_from_slice(&prefix.words);
    words.push(0xd2800060); // SC did not retire: return 3
    epilogue(&mut words);
    traffic.host_words = words.len() as u64;
    let fixups = [
        ((start + lr) * 4, load_fault * 4),
        ((start + sc) * 4, store_fault * 4),
    ];
    Ok(Compiled {
        memory: None,
        block: Block {
            code: Code::publish_fixups(&words, &fixups)
                .map_err(|error| CpuFault::Host(format!("JIT exclusive publication: {error}")))?,
            has_memory: false,
            has_vector: false,
            has_hardware: false,
            read_only_memory: false,
            memory_width: 1,
            instructions: count,
            next_pc: next,
            syscall: false,
            traffic,
            fast_offset: 0,
            tail_offset: 0,
            context,
            flow: Flow::Fixed,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use trames_memory::{Memory, Permissions, PAGE_SIZE};
    fn setup(words: &[u32]) -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in words.iter().enumerate() {
            m.write_array(0x1000 + 4 * i as u64, word.to_le_bytes())
                .unwrap();
        }
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        m.map(0x10000, 16384, Permissions::RW).unwrap();
        m.write_array(0x10000, 123u64.to_le_bytes()).unwrap();
        m
    }
    fn frame() -> Frame {
        Frame {
            remaining: 64,
            blocks: 0,
            pc: 0x1000,
            syscall: 0,
            last_slot: 0,
            links: std::ptr::null(),
            epochs: [std::ptr::null(); 3],
            expected: [0; 3],
            link_pcs: std::ptr::null(),
            sp: 0x10000,
            nzcv: 0xb0000000,
        }
    }
    #[test]
    fn both_native_fault_fixups_preserve_the_exact_retired_prefix_and_host_frame() {
        let words = [0xc85ffc20, 0xba0800e6, 0xc803fc24]; // ldaxr; adcs; stlxr
        let mut m = setup(&words);
        let window = Window::compile(&m, 0x1000, 3, 24).unwrap().unwrap();
        for protection in [libc::PROT_NONE, libc::PROT_READ] {
            let mut c = Cpu::new(0x1000, 0x10000);
            c.set_x(1, 0x10000);
            c.set_x(3, 0xfeed);
            c.set_x(4, 99);
            c.set_x(7, u64::MAX);
            c.set_x(8, 0);
            c.set_nzcv(0xb);
            let before = c.architectural_state();
            let page = unsafe { m.cpu_exclusive_page(0x10000, 8) }.unwrap();
            assert_eq!(
                unsafe { libc::mprotect(page.read as *mut _, 4096, protection) },
                0
            );
            let mut f = frame();
            f.link_pcs = page.read as *const u64;
            let result = unsafe {
                window
                    .block
                    .code
                    .call_window(c.native_register_pointers().0, &mut f)
            };
            assert_eq!(
                unsafe {
                    libc::mprotect(
                        page.read as *mut _,
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                    )
                },
                0
            );
            if protection == libc::PROT_NONE {
                assert_eq!(result, 2);
                assert_eq!(c.architectural_state(), before);
                assert_eq!(f.nzcv, 0xb0000000);
            } else {
                assert_eq!(result, 3);
                assert_eq!(c.x(0), 123);
                assert_eq!(c.x(6), 0);
                assert_eq!(c.x(3), 0xfeed);
                assert_eq!(f.nzcv, 0x60000000);
                assert_eq!(m.read_u64(0x10000).unwrap(), 123);
            }
            assert_eq!(f.sp, 0x10000);
        }
    }
    #[test]
    fn window_allocator_hoists_every_frame_read_outside_the_hardware_monitor() {
        let m = setup(&[0xc85ffc20, 0x9a0800e6, 0xc803fc24]);
        let w = Window::compile(&m, 0x1000, 3, 24).unwrap().unwrap();
        let words = unsafe {
            std::slice::from_raw_parts(w.block.code.pointer.cast::<u32>(), w.block.code.words)
        };
        let lr = words
            .iter()
            .position(|v| v & 0xfffffc00 == 0xc85ffc00)
            .unwrap();
        let sc = words
            .iter()
            .position(|v| v & 0xffe0fc00 == 0xc800fc00)
            .unwrap();
        assert!(sc > lr);
        for word in &words[lr + 1..sc] {
            assert_ne!(
                word & 0x0a000000,
                0x08000000,
                "memory instruction inside monitor: {word:08x}"
            );
            assert_ne!(word & 0xfffffc1f, 0xd63f0000, "helper call inside monitor");
        }
    }
}
