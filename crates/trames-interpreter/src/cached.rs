// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, lazily decoded code pages. No executable memory or host guest pointers.
use super::{
    extended::{logical_mask, ones, rotate},
    flags::ConditionFlags,
    shifted, sign_extend, width_mask, Cpu, CpuFault, Event, SliceOutcome,
};
use trames_memory::{CpuMemory, PAGE_SIZE};

const SLOTS: usize = 128;
const WAYS: usize = 2;
const SETS: usize = SLOTS / WAYS;
const PAGE_WORDS: usize = PAGE_SIZE as usize / 4;

/// A decoded five-bit register field. Only `decode` constructs this type.
#[derive(Clone, Copy, Debug)]
struct Register(u8);
impl Register {
    const fn decode(word: u32) -> Self {
        Self((word & 31) as u8)
    }
    #[inline(always)]
    fn index(self) -> usize {
        debug_assert!(self.0 < 32);
        // SAFETY: the private constructor masks to five bits. Cached operands
        // are never populated from guest data except through that constructor.
        // This describes an already validated index; public Cpu register access
        // and guest memory permissions retain their normal checks.
        unsafe { std::hint::assert_unchecked(self.0 < 32) };
        self.0 as usize
    }
}

#[derive(Clone, Copy, Debug)]
enum Addressing {
    Offset(u64),
    Pre(u64),
    Post(u64),
    Register { option: u8, shift: u8 },
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Nop,
    Svc,
    Move {
        opc: u8,
        shift: u8,
        value: u64,
    },
    Address {
        immediate: u64,
    },
    AddImmediate {
        value: u64,
    },
    FlagsImmediate {
        sub: bool,
        value: u64,
    },
    AddShift {
        sub: bool,
        flags: bool,
        kind: u8,
        amount: u8,
    },
    FlagsBranch {
        value: u64,
        offset: u64,
        condition: u8,
        sub: bool,
        immediate: bool,
        kind: u8,
        amount: u8,
    },
    LogicalShift {
        opc: u8,
        invert: bool,
        kind: u8,
        amount: u8,
    },
    LogicalImmediate {
        opc: u8,
        value: u64,
    },
    Bitfield {
        opc: u8,
        r: u8,
        s: u8,
        wmask: u64,
        tmask: u64,
    },
    Select {
        condition: u8,
        invert: bool,
        increment: bool,
    },
    AddExtended {
        sub: bool,
        flags: bool,
        signed: bool,
        bits: u8,
        amount: u8,
    },
    Compare {
        condition: u8,
        immediate: bool,
        sub: bool,
        nzcv: u8,
    },
    Multiply {
        kind: u8,
        ra: Register,
        sub: bool,
    },
    ShiftVariable {
        kind: u8,
    },
    Divide {
        signed: bool,
    },
    Branch {
        offset: u64,
        link: bool,
    },
    RegisterBranch {
        link: bool,
    },
    CompareBranch {
        offset: u64,
        nonzero: bool,
    },
    TestBranch {
        offset: u64,
        bit: u8,
        nonzero: bool,
    },
    ConditionalBranch {
        offset: u64,
        condition: u8,
    },
    // Size/kind validation and scaled offsets are done once. Other memory
    // encodings retain the complete checked reference implementation.
    MemoryImmediate {
        addressing: Addressing,
        size: u8,
        opc: u8,
        vector: bool,
    },
    Pair {
        offset: u64,
        size: u8,
        second: Register,
        load: bool,
        vector: bool,
        signed: bool,
        writeback: bool,
        post: bool,
    },
    Memory {
        writes: bool,
    },
    Fallback,
}

#[derive(Clone, Copy, Debug)]
struct Instruction {
    word: u32,
    rd: Register,
    rn: Register,
    rm: Register,
    wide: bool,
    op: Op,
}
impl Instruction {
    fn decode(word: u32) -> Self {
        let wide = word >> 31 != 0;
        let opc = ((word >> 29) & 3) as u8;
        let kind = ((word >> 22) & 3) as u8;
        let amount = ((word >> 10) & 63) as u8;
        let branch_offset = sign_extend((((word >> 5) & 0x7ffff) as u64) << 2, 21);
        let op = if word == 0xd503201f {
            Op::Nop
        } else if word & 0xffe0001f == 0xd4000001 {
            Op::Svc
        } else if word & 0x1f800000 == 0x12800000 {
            let shift = ((word >> 21) & 3) as u8 * 16;
            if opc == 1 || (!wide && shift >= 32) {
                Op::Fallback
            } else {
                Op::Move {
                    opc,
                    shift,
                    value: (((word >> 5) & 0xffff) as u64) << shift,
                }
            }
        } else if word & 0x1f000000 == 0x10000000 {
            Op::Address {
                immediate: sign_extend(
                    ((((word >> 5) & 0x7ffff) as u64) << 2) | ((word >> 29) & 3) as u64,
                    21,
                ),
            }
        } else if word & 0x1f800000 == 0x11000000 {
            let sub = word & (1 << 30) != 0;
            let value =
                (((word >> 10) & 0xfff) as u64) << if word & (1 << 22) != 0 { 12 } else { 0 };
            if word & (1 << 29) != 0 {
                Op::FlagsImmediate { sub, value }
            } else {
                // Non-S SUB immediate is addition of a decoded negative offset.
                // Width truncation is only needed at the destination write.
                Op::AddImmediate {
                    value: if sub { value.wrapping_neg() } else { value },
                }
            }
        } else if word & 0x1f200000 == 0x0b000000 {
            if kind == 3 || (!wide && amount >= 32) {
                Op::Fallback
            } else {
                Op::AddShift {
                    sub: word & (1 << 30) != 0,
                    flags: word & (1 << 29) != 0,
                    kind,
                    amount,
                }
            }
        } else if word & 0x1f000000 == 0x0a000000 {
            if !wide && amount >= 32 {
                Op::Fallback
            } else {
                Op::LogicalShift {
                    opc,
                    invert: word & (1 << 21) != 0,
                    kind,
                    amount,
                }
            }
        } else if word & 0x7c000000 == 0x14000000 {
            Op::Branch {
                offset: sign_extend(((word & 0x03ffffff) as u64) << 2, 28),
                link: wide,
            }
        } else if matches!(word & 0xfffffc1f, 0xd61f0000 | 0xd63f0000 | 0xd65f0000) {
            Op::RegisterBranch {
                link: word & 0xfffffc1f == 0xd63f0000,
            }
        } else if word & 0x7e000000 == 0x34000000 {
            Op::CompareBranch {
                offset: branch_offset,
                nonzero: word & (1 << 24) != 0,
            }
        } else if word & 0xff000010 == 0x54000000 {
            Op::ConditionalBranch {
                offset: branch_offset,
                condition: (word & 15) as u8,
            }
        } else if word & 0x1f800000 == 0x12000000 {
            let n = (word >> 22) & 1;
            match logical_mask(n, (word >> 10) & 63, (word >> 16) & 63, wide) {
                Some(value) if wide || n == 0 => Op::LogicalImmediate { opc, value },
                _ => Op::Fallback,
            }
        } else if word & 0x1f800000 == 0x13000000 {
            let r = ((word >> 16) & 63) as u8;
            let bits = if wide { 64 } else { 32 };
            if opc == 3 || ((word >> 22) & 1) != wide as u32 || r >= bits || amount >= bits {
                Op::Fallback
            } else {
                Op::Bitfield {
                    opc,
                    r,
                    s: amount,
                    wmask: rotate(ones(amount as u32 + 1), r as u32, bits as u32),
                    tmask: ones((((amount.wrapping_sub(r)) & (bits - 1)) + 1) as u32),
                }
            }
        } else if word & 0x1fe00800 == 0x1a800000 && word & (1 << 29) == 0 {
            Op::Select {
                condition: ((word >> 12) & 15) as u8,
                invert: word & (1 << 30) != 0,
                increment: word & (1 << 10) != 0,
            }
        } else if word & 0x7e000000 == 0x36000000 {
            Op::TestBranch {
                offset: sign_extend((((word >> 5) & 0x3fff) as u64) << 2, 16),
                bit: (((word >> 31) << 5) | ((word >> 19) & 31)) as u8,
                nonzero: word & (1 << 24) != 0,
            }
        } else if word & 0x1f200000 == 0x0b200000 && (word >> 10) & 7 <= 4 && word & (3 << 22) == 0
        {
            let option = ((word >> 13) & 7) as u8;
            Op::AddExtended {
                sub: word & (1 << 30) != 0,
                flags: word & (1 << 29) != 0,
                signed: option & 4 != 0,
                bits: 8 << (option & 3),
                amount: ((word >> 10) & 7) as u8,
            }
        } else if word & 0x1fe00410 == 0x1a400000 && word & (1 << 29) != 0 {
            Op::Compare {
                condition: ((word >> 12) & 15) as u8,
                immediate: word & (1 << 11) != 0,
                sub: word & (1 << 30) != 0,
                nzcv: (word & 15) as u8,
            }
        } else if word & 0x1f000000 == 0x1b000000 && word & 0x60000000 == 0 {
            let kind = ((word >> 21) & 7) as u8;
            let ra = ((word >> 10) & 31) as u8;
            let sub = word & (1 << 15) != 0;
            if kind == 0
                || (wide && matches!(kind, 1 | 5))
                || (wide && !sub && ra == 31 && matches!(kind, 2 | 6))
            {
                Op::Multiply {
                    kind,
                    ra: Register::decode(ra as u32),
                    sub,
                }
            } else {
                Op::Fallback
            }
        } else if word & 0x5fe00000 == 0x1ac00000 && word & (1 << 29) == 0 {
            match (word >> 10) & 63 {
                2 | 3 => Op::Divide {
                    signed: word & (1 << 10) != 0,
                },
                kind @ 8..=11 => Op::ShiftVariable {
                    kind: kind as u8 - 8,
                },
                _ => Op::Fallback,
            }
        } else if matches!(word & 0x3b000000, 0x39000000 | 0x38000000) {
            let vector = word & (1 << 26) != 0;
            let opc = ((word >> 22) & 3) as u8;
            let size_field = word >> 30;
            let size: u8 = if vector && opc >= 2 {
                16
            } else {
                1 << size_field
            };
            let addressing = if word & 0x3b000000 == 0x39000000 {
                Some(Addressing::Offset(
                    ((word >> 10) & 4095) as u64 * size as u64,
                ))
            } else if word & (1 << 21) != 0 {
                let option = ((word >> 13) & 7) as u8;
                if (word >> 10) & 3 != 2 || !matches!(option, 2 | 3 | 6 | 7) {
                    None
                } else {
                    Some(Addressing::Register {
                        option,
                        shift: if word & (1 << 12) != 0 {
                            size.trailing_zeros() as u8
                        } else {
                            0
                        },
                    })
                }
            } else {
                let mode = (word >> 10) & 3;
                let offset = sign_extend(((word >> 12) & 511) as u64, 9);
                if (mode == 2 && vector)
                    || (matches!(mode, 1 | 3)
                        && !vector
                        && (word >> 5) & 31 != 31
                        && (word >> 5) & 31 == word & 31)
                {
                    None
                } else {
                    Some(match mode {
                        1 => Addressing::Post(offset),
                        3 => Addressing::Pre(offset),
                        _ => Addressing::Offset(offset),
                    })
                }
            };
            if (vector && opc >= 2 && size_field != 0) || (!vector && size >= 4 && opc == 3) {
                Op::Fallback
            } else if let Some(addressing) = addressing {
                Op::MemoryImmediate {
                    addressing,
                    size,
                    opc,
                    vector,
                }
            } else {
                Op::Fallback
            }
        } else if word & 0x3a000000 == 0x28000000 {
            let vector = word & (1 << 26) != 0;
            let load = word & (1 << 22) != 0;
            let opc = word >> 30;
            let size = if vector {
                (opc != 3).then_some(4u8 << opc)
            } else {
                match opc {
                    0 => Some(4),
                    2 => Some(8),
                    1 if load => Some(4),
                    _ => None,
                }
            };
            let second = ((word >> 10) & 31) as u8;
            let mode = (word >> 23) & 3;
            let writeback = matches!(mode, 1 | 3);
            let rn = ((word >> 5) & 31) as u8;
            let rt = (word & 31) as u8;
            if !vector
                && ((writeback && rn != 31 && (rn == rt || rn == second)) || (load && rt == second))
            {
                Op::Fallback
            } else if let Some(size) = size {
                Op::Pair {
                    offset: sign_extend(((word >> 15) & 127) as u64, 7).wrapping_mul(size as u64),
                    size,
                    second: Register::decode(second as u32),
                    load,
                    vector,
                    signed: opc == 1,
                    writeback,
                    post: mode == 1,
                }
            } else {
                Op::Fallback
            }
        } else if word & 0x3b000000 == 0x18000000 {
            Op::Memory { writes: false }
        } else {
            Op::Fallback
        };
        Self {
            word,
            rd: Register::decode(word),
            rn: Register::decode(word >> 5),
            rm: Register::decode(word >> 16),
            wide,
            op,
        }
    }
    #[inline]
    fn may_write_code(&self) -> bool {
        matches!(
            self.op,
            Op::Memory { writes: true }
                | Op::MemoryImmediate { opc: 0, .. }
                | Op::MemoryImmediate {
                    opc: 2,
                    vector: true,
                    ..
                }
                | Op::Pair { load: false, .. }
                // Atomics, DC ZVA and other reference fallbacks can also write.
                | Op::Fallback
        )
    }
    fn followed_by(mut self, branch: Self) -> Self {
        let Op::ConditionalBranch { offset, condition } = branch.op else {
            return self;
        };
        self.op = match self.op {
            Op::FlagsImmediate { sub, value } => Op::FlagsBranch {
                value,
                offset,
                condition,
                sub,
                immediate: true,
                kind: 0,
                amount: 0,
            },
            Op::AddShift {
                sub,
                flags: true,
                kind,
                amount,
            } => Op::FlagsBranch {
                value: 0,
                offset,
                condition,
                sub,
                immediate: false,
                kind,
                amount,
            },
            op => op,
        };
        self
    }
}

#[derive(Debug)]
struct Entry {
    generation: u64,
    instruction: Instruction,
}
impl Clone for Entry {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            instruction: self.instruction,
        }
    }
}
impl Default for Entry {
    fn default() -> Self {
        Self {
            generation: 0,
            instruction: Instruction {
                word: 0,
                rd: Register::decode(0),
                rn: Register::decode(0),
                rm: Register::decode(0),
                wide: false,
                op: Op::Fallback,
            },
        }
    }
}
#[derive(Debug)]
struct CodePage {
    base: u64,
    identity: (u64, u64, u64),
    checked: (u64, u64, u64),
    generation: u64,
    instructions: Box<[Entry; PAGE_WORDS]>,
}
impl CodePage {
    #[cold]
    #[inline(never)]
    fn decode_slot(
        &mut self,
        memory: &impl CpuMemory,
        slot: usize,
        pc: u64,
        stats: &mut super::DecodeStats,
    ) -> Result<(), trames_memory::MemoryError> {
        // Decode only the reached PC: no speculative page reads,
        // early faults, or decoding of never-executed page contents.
        let word = memory.fetch_u32(pc)?;
        let instruction = Instruction::decode(word);
        self.instructions[slot].instruction = instruction;
        self.instructions[slot].generation = self.generation;
        stats.instructions += 1;
        // Form pairs only from words that have actually executed.
        // No lookahead fetch can move a fault before its reached PC.
        if slot != 0 && self.instructions[slot - 1].generation == self.generation {
            let previous = &mut self.instructions[slot - 1];
            previous.instruction = previous.instruction.followed_by(instruction);
        }
        if slot + 1 < PAGE_WORDS && self.instructions[slot + 1].generation == self.generation {
            let instruction = instruction.followed_by(self.instructions[slot + 1].instruction);
            self.instructions[slot].instruction = instruction;
        }
        Ok(())
    }
}
#[derive(Debug)]
pub(super) struct Cache {
    slots: Vec<Option<Box<CodePage>>>,
    recent: [u8; SETS],
    pub(super) stats: super::DecodeStats,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            // Dispatch placeholders and fork state need no decoded pages yet.
            slots: Vec::new(),
            recent: [0; SETS],
            stats: super::DecodeStats::default(),
        }
    }
}
impl Clone for Cache {
    fn clone(&self) -> Self {
        Self::default()
    } // fork copies state, not derived code
}
impl Cache {
    fn page(
        &mut self,
        memory: &impl CpuMemory,
        pc: u64,
    ) -> Result<(&mut CodePage, &mut super::DecodeStats), trames_memory::MemoryError> {
        let base = pc & !(PAGE_SIZE - 1);
        // Use every virtual address bit, including high library addresses.
        let set = (((base >> 12).wrapping_mul(0x9e3779b97f4a7c15)) >> (64 - SETS.ilog2())) as usize;
        let first = set * WAYS + self.recent[set] as usize;
        let second = set * WAYS + (self.recent[set] as usize ^ 1);
        // Probe the most recently used way first. Reuse the same virtual page
        // on an epoch change; otherwise replace the empty or least recent way.
        let slot = if self.slots[first].as_ref().is_some_and(|p| p.base == base) {
            first
        } else if self.slots[second].as_ref().is_some_and(|p| p.base == base) {
            second
        } else if self.slots[first].is_none() {
            first
        } else {
            second
        };
        self.recent[set] = (slot % WAYS) as u8;
        let checked = memory.instruction_identity();
        self.stats.lookups += 1;
        if self.slots[slot]
            .as_ref()
            .is_some_and(|p| p.base == base && p.checked == checked)
        {
            return Ok((
                self.slots[slot].as_deref_mut().expect("decoded code page"),
                &mut self.stats,
            ));
        }
        let identity = memory.instruction_page_identity(pc)?;
        if !self.slots[slot]
            .as_ref()
            .is_some_and(|p| p.base == base && p.identity == identity)
        {
            self.stats.misses += 1;
            if let Some(page) = &mut self.slots[slot] {
                page.base = base;
                page.identity = identity;
                page.generation = page.generation.wrapping_add(1);
                if page.generation == 0 {
                    // Epoch wrap must never expose a stale or empty entry.
                    for entry in page.instructions.iter_mut() {
                        entry.generation = 0;
                    }
                    page.generation = 1;
                }
            } else {
                self.slots[slot] = Some(Box::new(CodePage {
                    base,
                    identity,
                    checked,
                    generation: 1,
                    instructions: vec![Entry::default(); PAGE_WORDS]
                        .into_boxed_slice()
                        .try_into()
                        .expect("fixed code page"),
                }));
            }
        }
        let page = self.slots[slot].as_deref_mut().expect("decoded code page");
        page.checked = checked;
        Ok((page, &mut self.stats))
    }
}

impl Cpu {
    pub(super) fn run_worker_cached(
        &mut self,
        engine: &mut super::Engine,
        memory: &mut impl CpuMemory,
        budget: u64,
    ) -> SliceOutcome {
        // One cache per existing execution owner, not per Linux task. No TLS,
        // cross-worker lock, or new thread is needed. Memory identities include
        // the original mm and code generations; flags/registers remain per CPU.
        // A caller may have warmed the standalone API before handing this CPU
        // to a runtime. Release that old per-task working set on the transition.
        if !self.decoded.slots.is_empty() {
            self.decoded.slots = Vec::new();
        }
        engine.decoded.stats = self.decoded.stats;
        let result = self.execute_cached(memory, budget, &mut engine.decoded);
        self.decoded.stats = engine.decoded.stats;
        result
    }
    pub(super) fn run_cached(&mut self, memory: &mut impl CpuMemory, budget: u64) -> SliceOutcome {
        // Move the derived cache out once per slice; architectural state stays
        // directly accessible throughout execution, with no copy or FFI bounce.
        let mut cache = std::mem::replace(
            &mut self.decoded,
            Cache {
                slots: Vec::new(),
                recent: [0; SETS],
                stats: super::DecodeStats::default(),
            },
        );
        let result = self.execute_cached(memory, budget, &mut cache);
        self.decoded = cache;
        result
    }
    fn execute_cached(
        &mut self,
        memory: &mut impl CpuMemory,
        budget: u64,
        cache: &mut Cache,
    ) -> SliceOutcome {
        // Initialize once per execution slice, outside hot code-page lookups.
        if cache.slots.is_empty() && budget != 0 {
            cache.slots.resize_with(SLOTS, || None);
        }
        // Keep the small pending flag recipe separate from the register file.
        // Common handlers may retain it in host locals; fallback/exit boundaries
        // publish it before any architectural observer can see CPU state.
        let mut flags = self.condition_flags;
        let result = self.cached_slice(memory, budget, cache, &mut flags);
        self.condition_flags = flags;
        result
    }
    fn cached_slice(
        &mut self,
        memory: &mut impl CpuMemory,
        budget: u64,
        cache: &mut Cache,
        flags: &mut ConditionFlags,
    ) -> SliceOutcome {
        let mut executed = 0;
        while executed < budget {
            if self.pc & 3 != 0 {
                return self.slice_fault(
                    CpuFault::Memory {
                        pc: self.pc,
                        error: trames_memory::MemoryError::Alignment(self.pc),
                    },
                    executed,
                );
            }
            let (page, stats) = match cache.page(memory, self.pc) {
                Ok(page) => page,
                Err(error) => {
                    return self.slice_fault(CpuFault::Memory { pc: self.pc, error }, executed)
                }
            };
            let mut state = TailState {
                cpu: self,
                memory,
                flags,
                page,
                stats,
                budget,
            };
            match tail_enter(&mut state, 0, executed) {
                TailExit::Page(count) => executed = count,
                TailExit::Stop(outcome) => return outcome,
            }
        }
        SliceOutcome::Yield {
            instructions: executed,
        }
    }
    // Inline each operation into its tail handler. TAG comes only from the
    // exhaustive tail_next dispatcher, with no intervening cache mutation.
    // The specialization removes the redundant second operation dispatch.
    #[inline(always)]
    fn execute_decoded<M: CpuMemory, const TAG: usize>(
        &mut self,
        ins: &Instruction,
        memory: &mut M,
        remaining: u64,
        flags: &mut ConditionFlags,
    ) -> Result<(Event, u64), CpuFault> {
        let pc = self.pc;
        let mut next = pc.wrapping_add(4);
        let mut count = 1;
        let (rd, rn, rm) = (ins.rd.index(), ins.rn.index(), ins.rm.index());
        let wide = ins.wide;
        let mask = width_mask(wide);
        match ins.op {
            Op::Nop if TAG == 0 => {}
            Op::Svc if TAG == 1 => {
                self.pc = next;
                return Ok((Event::Syscall, 1));
            }
            Op::Move { opc, shift, value } if TAG == 2 => {
                let value = match opc {
                    0 => !value,
                    2 => value,
                    _ => (self.x(rd) & !(0xffffu64 << shift)) | value,
                };
                self.put(rd, value, wide, false);
            }
            Op::Address { immediate } if TAG == 3 => self.set_x(
                rd,
                if wide {
                    (pc & !4095).wrapping_add(immediate << 12)
                } else {
                    pc.wrapping_add(immediate)
                },
            ),
            Op::AddImmediate { value } if TAG == 4 => {
                self.put(rd, self.reg(rn, true).wrapping_add(value), wide, true);
            }
            Op::FlagsImmediate { sub, value } if TAG == 5 => {
                let value = flags.calculate(self.reg(rn, true), value, sub, true, wide);
                self.put(rd, value, wide, false);
            }
            Op::AddShift {
                sub,
                flags: set_flags,
                kind,
                amount,
            } if TAG == 6 => {
                let value = flags.calculate(
                    self.x(rn),
                    shifted(self.x(rm), kind as u32, amount as u32, wide),
                    sub,
                    set_flags,
                    wide,
                );
                self.put(rd, value, wide, false);
            }
            Op::FlagsBranch {
                value,
                offset,
                condition,
                sub,
                immediate,
                kind,
                amount,
            } if TAG == 7 => {
                let left = self.reg(rn, immediate);
                let right = if immediate {
                    value
                } else {
                    shifted(self.x(rm), kind as u32, amount as u32, wide)
                };
                let value = flags.calculate(left, right, sub, true, wide);
                self.put(rd, value, wide, false);
                if remaining >= 2 {
                    next = if flags.condition(condition as u32) {
                        next.wrapping_add(offset)
                    } else {
                        next.wrapping_add(4)
                    };
                    count = 2;
                }
            }
            Op::LogicalShift {
                opc,
                invert,
                kind,
                amount,
            } if TAG == 8 => {
                let rhs = shifted(self.x(rm), kind as u32, amount as u32, wide);
                self.decoded_logical(ins, if invert { !rhs } else { rhs }, opc, false, flags);
            }
            Op::LogicalImmediate { opc, value } if TAG == 9 => {
                self.decoded_logical(ins, value, opc, opc != 3, flags)
            }
            Op::Bitfield {
                opc,
                r,
                s,
                wmask,
                tmask,
            } if TAG == 10 => {
                let value = rotate(self.x(rn) & mask, r as u32, if wide { 64 } else { 32 });
                let value = match opc {
                    0 => {
                        let top = if self.x(rn) & (1 << s) != 0 { mask } else { 0 };
                        (top & !tmask) | (value & wmask & tmask)
                    }
                    1 => {
                        (self.x(rd) & !tmask) | (((self.x(rd) & !wmask) | (value & wmask)) & tmask)
                    }
                    _ => value & wmask & tmask,
                };
                self.put(rd, value, wide, false);
            }
            Op::Select {
                condition,
                invert,
                increment,
            } if TAG == 11 => {
                let value = if flags.condition(condition as u32) {
                    self.x(rn)
                } else {
                    let value = if invert { !self.x(rm) } else { self.x(rm) };
                    if increment {
                        value.wrapping_add(1)
                    } else {
                        value
                    }
                };
                self.put(rd, value, wide, false);
            }
            Op::AddExtended {
                sub,
                flags: set_flags,
                signed,
                bits,
                amount,
            } if TAG == 12 => {
                let rhs = self.x(rm) & ones(bits as u32);
                let rhs = if signed {
                    sign_extend(rhs, bits as u32)
                } else {
                    rhs
                };
                let value = flags.calculate(
                    self.reg(rn, true),
                    rhs.wrapping_shl(amount as u32),
                    sub,
                    set_flags,
                    wide,
                );
                self.put(rd, value, wide, !set_flags);
            }
            Op::Compare {
                condition,
                immediate,
                sub,
                nzcv,
            } if TAG == 13 => {
                if flags.condition(condition as u32) {
                    flags.calculate(
                        self.x(rn),
                        if immediate { rm as u64 } else { self.x(rm) },
                        sub,
                        true,
                        wide,
                    );
                } else {
                    flags.set(nzcv as u32);
                }
            }
            Op::Multiply { kind, ra, sub } if TAG == 14 => {
                let product = match kind {
                    0 => self.x(rn).wrapping_mul(self.x(rm)),
                    1 => (self.x(rn) as u32 as i32 as i64)
                        .wrapping_mul(self.x(rm) as u32 as i32 as i64)
                        as u64,
                    5 => (self.x(rn) as u32 as u64) * (self.x(rm) as u32 as u64),
                    2 => ((self.x(rn) as i64 as i128 * self.x(rm) as i64 as i128) >> 64) as u64,
                    _ => ((self.x(rn) as u128 * self.x(rm) as u128) >> 64) as u64,
                };
                let value = if matches!(kind, 2 | 6) {
                    product
                } else if sub {
                    self.x(ra.index()).wrapping_sub(product)
                } else {
                    self.x(ra.index()).wrapping_add(product)
                };
                self.put(rd, value, wide, false);
            }
            Op::ShiftVariable { kind } if TAG == 15 => {
                let amount = (self.x(rm) & if wide { 63 } else { 31 }) as u32;
                self.put(
                    rd,
                    shifted(self.x(rn), kind as u32, amount, wide),
                    wide,
                    false,
                );
            }
            Op::Divide { signed } if TAG == 16 => {
                let a = self.x(rn) & mask;
                let b = self.x(rm) & mask;
                let value = if b == 0 {
                    0
                } else if !signed {
                    a / b
                } else if wide {
                    (a as i64).wrapping_div(b as i64) as u64
                } else {
                    (a as u32 as i32).wrapping_div(b as u32 as i32) as u32 as u64
                };
                self.put(rd, value, wide, false);
            }
            Op::Branch { offset, link } if TAG == 17 => {
                if link {
                    self.set_x(30, next);
                }
                next = pc.wrapping_add(offset);
            }
            Op::RegisterBranch { link } if TAG == 18 => {
                let target = self.x(rn);
                if link {
                    self.set_x(30, next);
                }
                next = target;
            }
            Op::CompareBranch { offset, nonzero } if TAG == 19 => {
                if (self.x(rd) & mask != 0) == nonzero {
                    next = pc.wrapping_add(offset);
                }
            }
            Op::TestBranch {
                offset,
                bit,
                nonzero,
            } if TAG == 20 => {
                if (self.x(rd) & (1 << bit) != 0) == nonzero {
                    next = pc.wrapping_add(offset);
                }
            }
            Op::ConditionalBranch { offset, condition } if TAG == 21 => {
                if flags.condition(condition as u32) {
                    next = pc.wrapping_add(offset);
                }
            }
            Op::MemoryImmediate {
                addressing,
                size,
                opc,
                vector,
            } if TAG == 22 => {
                if !vector && size == 8 && opc == 2 {
                    self.pc = next;
                    return Ok((Event::Continue, 1));
                }
                let base = self.reg(rn, true);
                let (address, writeback) = match addressing {
                    Addressing::Offset(offset) => (base.wrapping_add(offset), None),
                    Addressing::Pre(offset) => {
                        let address = base.wrapping_add(offset);
                        (address, Some(address))
                    }
                    Addressing::Post(offset) => (base, Some(base.wrapping_add(offset))),
                    Addressing::Register { option, shift } => {
                        let index = match option {
                            2 => self.x(rm) as u32 as u64,
                            6 => self.x(rm) as u32 as i32 as i64 as u64,
                            _ => self.x(rm),
                        };
                        (base.wrapping_add(index.wrapping_shl(shift as u32)), None)
                    }
                };
                let size = size as usize;
                let fault = |error| CpuFault::Memory { pc, error };
                if if vector { opc & 1 != 0 } else { opc != 0 } {
                    let raw =
                        super::load_store::read_operand(memory, address, size).map_err(fault)?;
                    if vector {
                        self.vectors[rd] = raw;
                    } else {
                        let mut value = raw as u64;
                        if opc >= 2 {
                            value = sign_extend(value, size as u32 * 8);
                        }
                        if opc == 3 {
                            value &= u32::MAX as u64;
                        }
                        self.set_x(rd, value);
                    }
                } else {
                    let value = if vector {
                        self.vectors[rd]
                    } else {
                        self.x(rd) as u128
                    };
                    super::load_store::write_operand(memory, address, size, value)
                        .map_err(fault)?;
                }
                if let Some(value) = writeback {
                    self.put(rn, value, true, true);
                }
            }
            Op::Pair {
                offset,
                size,
                second,
                load,
                vector,
                signed,
                writeback,
                post,
            } if TAG == 23 => {
                let base = self.reg(rn, true);
                let address = if post {
                    base
                } else {
                    base.wrapping_add(offset)
                };
                let second = second.index();
                let fault = |error| CpuFault::Memory { pc, error };
                if load {
                    let (first, other) = match size {
                        4 => {
                            let pair =
                                u64::from_le_bytes(memory.read_array(address).map_err(fault)?);
                            (pair as u32 as u128, (pair >> 32) as u128)
                        }
                        8 => {
                            let pair =
                                u128::from_le_bytes(memory.read_array(address).map_err(fault)?);
                            (pair as u64 as u128, pair >> 64)
                        }
                        _ => {
                            let pair = memory.read_array::<32>(address).map_err(fault)?;
                            (
                                u128::from_le_bytes(pair[..16].try_into().expect("first vector")),
                                u128::from_le_bytes(pair[16..].try_into().expect("second vector")),
                            )
                        }
                    };
                    if vector {
                        self.vectors[rd] = first;
                        self.vectors[second] = other;
                    } else {
                        self.set_x(
                            rd,
                            if signed {
                                sign_extend(first as u64, 32)
                            } else {
                                first as u64
                            },
                        );
                        self.set_x(
                            second,
                            if signed {
                                sign_extend(other as u64, 32)
                            } else {
                                other as u64
                            },
                        );
                    }
                } else {
                    let first = if vector {
                        self.vectors[rd]
                    } else {
                        self.x(rd) as u128
                    };
                    let other = if vector {
                        self.vectors[second]
                    } else {
                        self.x(second) as u128
                    };
                    match size {
                        4 => memory
                            .write_array(
                                address,
                                ((first as u32 as u64) | ((other as u32 as u64) << 32))
                                    .to_le_bytes(),
                            )
                            .map_err(fault)?,
                        8 => memory
                            .write_array(
                                address,
                                ((first as u64 as u128) | ((other as u64 as u128) << 64))
                                    .to_le_bytes(),
                            )
                            .map_err(fault)?,
                        _ => {
                            let mut bytes = [0; 32];
                            bytes[..16].copy_from_slice(&first.to_le_bytes());
                            bytes[16..].copy_from_slice(&other.to_le_bytes());
                            memory.write_array(address, bytes).map_err(fault)?;
                        }
                    }
                }
                if writeback {
                    self.put(rn, base.wrapping_add(offset), true, true);
                }
            }
            Op::Memory { .. } if TAG == 24 => {
                if !self.execute_memory(ins.word, memory)? {
                    return Err(CpuFault::Instruction {
                        pc,
                        instruction: ins.word,
                    });
                }
            }
            Op::Fallback if TAG == 25 => {
                self.condition_flags = *flags;
                let result = self.execute_instruction(ins.word, memory);
                *flags = self.condition_flags;
                return result.map(|event| (event, 1));
            }
            // SAFETY: tail_next selects this specialization from this exact
            // entry's Op. No code-cache mutation occurs before executing it.
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
        self.pc = next;
        Ok((Event::Continue, count))
    }
    #[inline]
    fn decoded_logical(
        &mut self,
        ins: &Instruction,
        rhs: u64,
        opc: u8,
        sp: bool,
        flags: &mut ConditionFlags,
    ) {
        let (rd, rn, wide) = (ins.rd.index(), ins.rn.index(), ins.wide);
        let value = match opc {
            0 | 3 => self.x(rn) & rhs,
            1 => self.x(rn) | rhs,
            _ => self.x(rn) ^ rhs,
        } & width_mask(wide);
        if opc == 3 {
            flags.set(
                ((value & (if wide { 1 << 63 } else { 1 << 31 }) != 0) as u32) << 3
                    | ((value == 0) as u32) << 2,
            );
        }
        self.put(rd, value, wide, sp);
    }
}

struct TailState<'a, M: CpuMemory> {
    cpu: &'a mut Cpu,
    memory: &'a mut M,
    flags: &'a mut ConditionFlags,
    page: &'a mut CodePage,
    stats: &'a mut super::DecodeStats,
    budget: u64,
}
enum TailExit {
    Page(u64),
    Stop(SliceOutcome),
}
macro_rules! tail_next {
    ($state:ident, $executed:ident) => {{
        let pc = $state.cpu.pc;
        if $executed >= $state.budget {
            return TailExit::Stop(SliceOutcome::Yield {
                instructions: $executed,
            });
        }
        if pc & !(PAGE_SIZE - 1) != $state.page.base {
            return TailExit::Page($executed);
        }
        if pc & 3 != 0 {
            return TailExit::Stop($state.cpu.slice_fault(
                CpuFault::Memory {
                    pc,
                    error: trames_memory::MemoryError::Alignment(pc),
                },
                $executed,
            ));
        }
        let slot = (pc as usize & (PAGE_SIZE as usize - 1)) / 4;
        if $state.page.instructions[slot].generation != $state.page.generation {
            become tail_decode($state, slot, $executed);
        }
        match $state.page.instructions[slot].instruction.op {
            Op::Nop => become tail_op::<M, 0>($state, slot, $executed),
            Op::Svc => become tail_op::<M, 1>($state, slot, $executed),
            Op::Move { .. } => become tail_op::<M, 2>($state, slot, $executed),
            Op::Address { .. } => become tail_op::<M, 3>($state, slot, $executed),
            Op::AddImmediate { .. } => become tail_op::<M, 4>($state, slot, $executed),
            Op::FlagsImmediate { .. } => become tail_op::<M, 5>($state, slot, $executed),
            Op::AddShift { .. } => become tail_op::<M, 6>($state, slot, $executed),
            Op::FlagsBranch { .. } => become tail_op::<M, 7>($state, slot, $executed),
            Op::LogicalShift { .. } => become tail_op::<M, 8>($state, slot, $executed),
            Op::LogicalImmediate { .. } => become tail_op::<M, 9>($state, slot, $executed),
            Op::Bitfield { .. } => become tail_op::<M, 10>($state, slot, $executed),
            Op::Select { .. } => become tail_op::<M, 11>($state, slot, $executed),
            Op::AddExtended { .. } => become tail_op::<M, 12>($state, slot, $executed),
            Op::Compare { .. } => become tail_op::<M, 13>($state, slot, $executed),
            Op::Multiply { .. } => become tail_op::<M, 14>($state, slot, $executed),
            Op::ShiftVariable { .. } => become tail_op::<M, 15>($state, slot, $executed),
            Op::Divide { .. } => become tail_op::<M, 16>($state, slot, $executed),
            Op::Branch { .. } => become tail_op::<M, 17>($state, slot, $executed),
            Op::RegisterBranch { .. } => become tail_op::<M, 18>($state, slot, $executed),
            Op::CompareBranch { .. } => become tail_op::<M, 19>($state, slot, $executed),
            Op::TestBranch { .. } => become tail_op::<M, 20>($state, slot, $executed),
            Op::ConditionalBranch { .. } => become tail_op::<M, 21>($state, slot, $executed),
            Op::MemoryImmediate { .. } => become tail_op::<M, 22>($state, slot, $executed),
            Op::Pair { .. } => become tail_op::<M, 23>($state, slot, $executed),
            Op::Memory { .. } => become tail_op::<M, 24>($state, slot, $executed),
            Op::Fallback => become tail_op::<M, 25>($state, slot, $executed),
        }
    }};
}
#[cold]
#[inline(never)]
extern "rust-preserve-none" fn tail_decode<M: CpuMemory>(
    state: &mut TailState<'_, M>,
    slot: usize,
    executed: u64,
) -> TailExit {
    let pc = state.cpu.pc;
    if let Err(error) = state.page.decode_slot(state.memory, slot, pc, state.stats) {
        return TailExit::Stop(
            state
                .cpu
                .slice_fault(CpuFault::Memory { pc, error }, executed),
        );
    }
    tail_next!(state, executed)
}
#[inline(never)]
extern "rust-preserve-none" fn tail_enter<M: CpuMemory>(
    state: &mut TailState<'_, M>,
    _slot: usize,
    executed: u64,
) -> TailExit {
    tail_next!(state, executed)
}
#[inline(never)]
extern "rust-preserve-none" fn tail_op<M: CpuMemory, const TAG: usize>(
    state: &mut TailState<'_, M>,
    slot: usize,
    executed: u64,
) -> TailExit {
    debug_assert!(slot < PAGE_WORDS && executed < state.budget);
    // SAFETY: every entry is reached via tail_next, which checks the budget
    // and derives the slot from the low twelve PC bits, divided by four.
    unsafe { std::hint::assert_unchecked(slot < PAGE_WORDS && executed < state.budget) };
    let instruction = &state.page.instructions[slot].instruction;
    let count = match state.cpu.execute_decoded::<M, TAG>(
        instruction,
        state.memory,
        state.budget - executed,
        state.flags,
    ) {
        Ok((Event::Continue, count)) => count,
        Ok((Event::Yield, _)) => {
            return TailExit::Stop(SliceOutcome::Yield {
                instructions: executed,
            })
        }
        Ok((Event::Syscall, _)) => {
            return TailExit::Stop(SliceOutcome::Syscall {
                instructions: executed + 1,
            })
        }
        Ok((
            Event::NativeCall {
                pc,
                module,
                function,
            },
            _,
        )) => {
            return TailExit::Stop(SliceOutcome::NativeCall {
                instructions: executed,
                pc,
                module,
                function,
            })
        }
        Err(error) => return TailExit::Stop(state.cpu.slice_fault(error, executed)),
    };
    debug_assert!(count <= state.budget - executed);
    let executed = executed.wrapping_add(count);
    if matches!(TAG, 22..=25)
        && instruction.may_write_code()
        && state.memory.instruction_identity() != state.page.checked
    {
        return TailExit::Page(executed);
    }
    tail_next!(state, executed)
}

#[cfg(test)]
use trames_memory::Memory;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Flags;
    use trames_memory::Permissions;

    fn memory(words: &[u32]) -> Memory {
        let mut memory = Memory::default();
        memory
            .map(
                0x1000,
                PAGE_SIZE,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, word) in words.iter().enumerate() {
            memory
                .write(0x1000 + i as u64 * 4, &word.to_le_bytes())
                .unwrap();
        }
        memory
    }
    fn equal(a: &Cpu, b: &Cpu) {
        assert_eq!(a.registers, b.registers);
        assert_eq!(
            (
                a.pc,
                a.sp,
                a.flags(),
                a.fpcr,
                a.fpsr,
                a.tpidr_el0,
                a.exclusive
            ),
            (
                b.pc,
                b.sp,
                b.flags(),
                b.fpcr,
                b.fpsr,
                b.tpidr_el0,
                b.exclusive
            )
        );
        assert_eq!(a.vectors, b.vectors);
    }
    #[test]
    fn decoded_forms_keep_width_and_register_roles() {
        for base in [
            0x11001400, 0x0b000000, 0x4b000000, 0x0a000000, 0x2a000000, 0x4a000000, 0x52824680,
            0x12824680,
        ] {
            for wide in [0, 1 << 31] {
                for rd in [0, 3, 4, 30, 31] {
                    for rn in [0, 2, 31] {
                        for rm in [1, 3, 31] {
                            let word = base | wide | rd | (rn << 5) | (rm << 16);
                            let mut mem = memory(&[word, 0xd4000001]);
                            let mut cpu = Cpu::new(0x1000, u64::MAX);
                            for reg in 0..31 {
                                cpu.set_x(reg, (0x8000_0001_ffff_ffffu64).rotate_left(reg as u32));
                            }
                            cpu.set_nzcv(11);
                            // Repeat with the already decoded entry, observing
                            // each exact one-instruction state publication.
                            for _ in 0..2 {
                                cpu.pc = 0x1000;
                                let mut oracle = cpu.clone();
                                let mut other = mem.clone();
                                assert_eq!(
                                    format!("{:?}", cpu.run_slice(&mut mem, 1)),
                                    format!("{:?}", oracle.run_reference(&mut other, 1)),
                                    "{word:08x}"
                                );
                                equal(&cpu, &oracle);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn transient_values_publish_on_memory_fallback_and_stop_boundaries() {
        for ending in [0xd4000001, 0xd503203f, 0xf9400120, 0x00000000] {
            let words = [
                0x91000400, // add x0,x0,#1
                0x8b000021, // add x1,x1,x0
                0xca010042, // eor x2,x2,x1
                0x91000463, // add x3,x3,#1
                0xf9000100, // str x0,[x8]
                0xf9400101, // ldr x1,[x8]
                0xa9000d02, // stp x2,x3,[x8]
                0xa9400500, // ldp x0,x1,[x8]
                0xdac00002, // rbit x2,x0: reference fallback
                0x8b020063, // add x3,x3,x2
                ending,
            ];
            for budget in 0..=words.len() as u64 + 1 {
                let mut mem = memory(&words);
                let mut cpu = Cpu::new(0x1000, 0x2ff0);
                cpu.set_x(8, 0x2000);
                cpu.set_x(9, 0x9000); // unmapped load must preserve prior results
                for iteration in 0..2 {
                    cpu.pc = 0x1000;
                    for reg in 0..4 {
                        cpu.set_x(reg, u64::MAX - reg as u64 - iteration);
                    }
                    let mut oracle = cpu.clone();
                    let mut other = mem.clone();
                    assert_eq!(
                        format!("{:?}", cpu.run_slice(&mut mem, budget)),
                        format!("{:?}", oracle.run_reference(&mut other, budget))
                    );
                    equal(&cpu, &oracle);
                    assert_eq!(
                        mem.read_array::<16>(0x2000).unwrap(),
                        other.read_array::<16>(0x2000).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn fused_flags_branches_preserve_budgets_conditions_and_invalidations() {
        for arithmetic in [
            0xf100041f, 0xf10007ff, 0xb1000420, 0x31000420, 0xeb01001f, 0x6b817c1f,
        ] {
            for condition in 0..16 {
                let branch = 0x54000000u32 | (3 << 5) | condition;
                for budget in [1, 2, 3, 4, 4096] {
                    let mut memory =
                        memory(&[arithmetic, branch, 0xd4000001, 0xd503201f, 0xd4000001]);
                    let mut cpu = Cpu::new(0x1004, 1);
                    cpu.run_slice(&mut memory, 1); // warm branch independently
                    cpu.pc = 0x1000;
                    cpu.set_x(0, u64::MAX);
                    cpu.set_x(1, 0x8000000000000001);
                    let mut oracle = cpu.clone();

                    let mut other = memory.clone();
                    assert_eq!(
                        format!("{:?}", cpu.run_slice(&mut memory, budget)),
                        format!("{:?}", oracle.run_reference(&mut other, budget))
                    );
                    equal(&cpu, &oracle);
                    assert!(matches!(
                        cpu.decoded
                            .slots
                            .iter()
                            .flatten()
                            .find(|p| p.base == 0x1000)
                            .unwrap()
                            .instructions[0]
                            .instruction
                            .op,
                        Op::FlagsBranch { .. }
                    ));
                    // Replace the branch via another thread. A warmed pair must
                    // not skip the newly reached SVC or use the old target.
                    let mut thread = memory.share();
                    thread
                        .write_array(0x1004, 0xd4000001u32.to_le_bytes())
                        .unwrap();
                    other
                        .write_array(0x1004, 0xd4000001u32.to_le_bytes())
                        .unwrap();
                    cpu.pc = 0x1000;
                    oracle.pc = 0x1000;
                    assert_eq!(
                        format!("{:?}", cpu.run_slice(&mut memory, 3)),
                        format!("{:?}", oracle.run_reference(&mut other, 3))
                    );
                    equal(&cpu, &oracle);
                }
            }
        }
        // No pair spans a page: the branch's execute fault follows the compare.
        let mut memory = memory(&[]);
        memory
            .write_array(0x1ffc, 0xf100041fu32.to_le_bytes())
            .unwrap();
        memory.unmap(0x2000, PAGE_SIZE).unwrap();
        let mut cpu = Cpu::new(0x1ffc, 0);
        let mut oracle = cpu.clone();

        let mut other = memory.clone();
        assert_eq!(
            format!("{:?}", cpu.run_slice(&mut memory, 2)),
            format!("{:?}", oracle.run_reference(&mut other, 2))
        );
        equal(&cpu, &oracle);
    }
    #[test]
    fn unrelated_epochs_keep_decodes_but_exec_remapping_and_collisions_do_not() {
        let mut memory = memory(&[0xd2800020]);
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.run_slice(&mut memory, 1);
        let decoded = cpu.decode_stats().instructions;
        memory.map(0x9000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.protect(0x9000, PAGE_SIZE, Permissions::RX).unwrap();
        cpu.pc = 0x1000;
        cpu.run_slice(&mut memory, 1);
        assert_eq!(cpu.decode_stats().instructions, decoded);
        memory
            .map_fixed(0x1000, PAGE_SIZE, Permissions::RW)
            .unwrap();
        memory
            .write_array(0x1000, 0xd28000e0u32.to_le_bytes())
            .unwrap();
        cpu.pc = 0x1000;
        assert!(matches!(
            cpu.run_slice(&mut memory, 1),
            SliceOutcome::Fault(CpuFault::Memory { .. })
        ));
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        cpu.run_slice(&mut memory, 1);
        assert_eq!(cpu.x(0), 7);
        assert_eq!(cpu.decode_stats().instructions, decoded + 1);
        // Find two conflicting pages and exercise both ways, including eviction.
        let set = |base: u64| {
            ((base >> 12).wrapping_mul(0x9e3779b97f4a7c15) >> (64 - SETS.ilog2())) as usize
        };
        let aliases: Vec<_> = (3..1024u64)
            .map(|n| n * PAGE_SIZE)
            .filter(|&base| set(base) == set(0x1000))
            .take(2)
            .collect();
        for (i, &base) in aliases.iter().enumerate() {
            memory.map(base, PAGE_SIZE, Permissions::RW).unwrap();
            memory
                .write_array(base, (0xd2800000u32 | ((i as u32 + 10) << 5)).to_le_bytes())
                .unwrap();
            memory.protect(base, PAGE_SIZE, Permissions::RX).unwrap();
        }
        for (base, value) in [
            (0x1000, 7),
            (aliases[0], 10),
            (0x1000, 7),
            (aliases[0], 10),
            (aliases[1], 11),
            (0x1000, 7),
        ] {
            cpu.pc = base;
            cpu.run_slice(&mut memory, 1);
            assert_eq!(cpu.x(0), value);
        }
    }
    #[test]
    fn runtime_worker_cache_is_shared_by_tasks_without_retaining_task_working_sets() {
        use trames_engine::Cpu as Backend;
        let mut memory = memory(&[0xd28000a0]); // mov x0, #5
        let mut engine = super::super::Engine::default();
        let mut tasks: Vec<_> = (0..128).map(|_| Cpu::new(0x1000, 0)).collect();
        for task in &mut tasks {
            assert!(matches!(
                Backend::run(task, &mut engine, &mut memory, 1),
                SliceOutcome::Yield { instructions: 1 }
            ));
            assert_eq!(task.x(0), 5);
            assert_eq!(task.decode_stats().lookups, 1);
            assert!(
                task.decoded.slots.is_empty(),
                "Sleeping guest tasks own no decoded pages"
            );
        }
        assert_eq!(engine.decoded.slots.iter().flatten().count(), 1);
        assert_eq!(
            tasks
                .iter()
                .map(|t| t.decode_stats().instructions)
                .sum::<u64>(),
            1,
            "Same-mm tasks reuse decoded instructions"
        );
        let pointer = engine
            .decoded
            .slots
            .iter()
            .flatten()
            .next()
            .unwrap()
            .instructions
            .as_ptr();
        tasks[0].pc = 0x1000;
        Backend::run(&mut tasks[0], &mut engine, &mut memory, 1);
        assert_eq!(tasks[0].decode_stats().lookups, 2);
        assert_eq!(tasks[1].decode_stats().lookups, 1);
        assert_eq!(
            engine
                .decoded
                .slots
                .iter()
                .flatten()
                .next()
                .unwrap()
                .instructions
                .as_ptr(),
            pointer
        );
        // Identical VA/epochs in another mm must never execute the old word.
        let mut other = super::tests::memory(&[0xd28000e0]); // mov x0, #7
        tasks[1].pc = 0x1000;
        Backend::run(&mut tasks[1], &mut engine, &mut other, 1);
        assert_eq!(tasks[1].x(0), 7);
        tasks[0].pc = 0x1000;
        Backend::run(&mut tasks[0], &mut engine, &mut memory, 1);
        assert_eq!(tasks[0].x(0), 5);
    }
    #[test]
    fn runtime_engine_migration_preserves_fault_accounting_and_rechecks_execute_access() {
        use trames_engine::Cpu as Backend;
        let mut memory = memory(&[0xd28000a0, 0]); // mov; invalid instruction
        let mut task = Cpu::new(0x1000, 0);
        // Switching from standalone execution must release the task cache too.
        task.run_slice(&mut memory, 1);
        assert!(!task.decoded.slots.is_empty());
        let mut first = super::super::Engine::default();
        task.pc = 0x1000;
        assert!(matches!(
            Backend::run(&mut task, &mut first, &mut memory, 2),
            SliceOutcome::Fault(_)
        ));
        assert_eq!(task.fault_retired(), 1);
        assert!(task.decoded.slots.is_empty());
        let mut second = super::super::Engine::default();
        task.pc = 0x1000;
        assert!(matches!(
            Backend::run(&mut task, &mut second, &mut memory, 1),
            SliceOutcome::Yield { instructions: 1 }
        ));
        assert_eq!(task.fault_retired(), 0);
        memory.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        task.pc = 0x1000;
        assert!(matches!(
            Backend::run(&mut task, &mut first, &mut memory, 1),
            SliceOutcome::Fault(CpuFault::Memory {
                error: trames_memory::MemoryError::Permission { .. },
                ..
            })
        ));
    }
    #[test]
    fn page_cache_is_bounded_and_warm_words_do_not_hide_branch_alignment_faults() {
        let mut memory = memory(&[0xd61f0000, 0xd503201f]); // br x0; nop
        let mut cpu = Cpu::new(0x1004, 0);
        cpu.run_slice(&mut memory, 1);
        cpu.pc = 0x1000;
        cpu.set_x(0, 0x1005);
        assert!(matches!(
            cpu.run_slice(&mut memory, 2),
            SliceOutcome::Fault(CpuFault::Memory {
                pc: 0x1005,
                error: trames_memory::MemoryError::Alignment(0x1005)
            })
        ));
        memory
            .map(
                0x100000,
                PAGE_SIZE * 256,
                Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            )
            .unwrap();
        for page in 0..256u64 {
            let word = 0xd2800000u32 | ((page as u32) << 5);
            memory
                .write(0x100000 + page * PAGE_SIZE, &word.to_le_bytes())
                .unwrap();
        }
        for page in (0..256u64).chain(0..256) {
            cpu.pc = 0x100000 + page * PAGE_SIZE;
            assert!(matches!(
                cpu.run_slice(&mut memory, 1),
                SliceOutcome::Yield { instructions: 1 }
            ));
            assert_eq!(cpu.x(0), page);
        }
        assert_eq!(cpu.decoded.slots.len(), SLOTS);
        assert!(cpu.decoded.slots.iter().filter(|p| p.is_some()).count() <= SLOTS);
        assert!(cpu
            .decoded
            .slots
            .iter()
            .flatten()
            .all(|p| p.instructions.len() == PAGE_WORDS));
    }
    #[test]
    fn page_epoch_wrap_invalidates_stale_words_without_reallocating() {
        let mut memory = memory(&[0xd2800020]);
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.run_slice(&mut memory, 1);
        let page = cpu
            .decoded
            .slots
            .iter_mut()
            .flatten()
            .find(|p| p.base == 0x1000)
            .unwrap();
        let address = page.instructions.as_ptr();
        page.generation = u64::MAX;
        page.instructions[0].generation = u64::MAX;
        memory.write(0x1000, &0xd28000e0u32.to_le_bytes()).unwrap();
        cpu.pc = 0x1000;
        cpu.run_slice(&mut memory, 1);
        assert_eq!(cpu.x(0), 7);
        let page = cpu
            .decoded
            .slots
            .iter()
            .flatten()
            .find(|p| p.base == 0x1000)
            .unwrap();
        assert_eq!(page.generation, 1);
        assert_eq!(page.instructions.as_ptr(), address);
    }
    #[test]
    fn cached_random_operands_and_reserved_words_match_single_step_oracle() {
        let families = [
            (0x12800000, 0x1f800000),
            (0x10000000, 0x1f000000),
            (0x11000000, 0x1f800000),
            (0x0b000000, 0x1f200000),
            (0x0a000000, 0x1f000000),
            (0x12000000, 0x1f800000),
            (0x13000000, 0x1f800000),
            (0x1a800000, 0x1fe00800),
            (0x39000000, 0x3b000000),
            (0x38000000, 0x3b000000),
            (0x28000000, 0x3a000000),
            (0x18000000, 0x3b000000),
            (0x0b200000, 0x1f200000),
            (0x1a400000, 0x1fe00410),
            (0x1b000000, 0x1f000000),
            (0x1ac00000, 0x5fe00000),
            (0x34000000, 0x7e000000),
            (0x36000000, 0x7e000000),
            (0x54000000, 0xff000010),
            (0x14000000, 0x7c000000),
        ];
        let mut seed = 0x71b7a32c9d11u64;
        for &(base, mask) in &families {
            for _ in 0..256 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let word = base | (seed as u32 & !mask);
                let mut memory = memory(&[word]);
                let mut cpu = Cpu::new(0x1000, 0x2ff8);
                for reg in 0..31 {
                    cpu.set_x(
                        reg,
                        if reg % 3 == 0 {
                            0x2000 + (seed & 63)
                        } else {
                            seed.rotate_left(reg as u32)
                        },
                    );
                    cpu.vectors[reg] = (seed as u128) << 64 | (!seed as u128);
                }
                cpu.set_flags(Flags {
                    n: seed & 1 != 0,
                    z: seed & 2 != 0,
                    c: seed & 4 != 0,
                    v: seed & 8 != 0,
                });
                let mut oracle = cpu.clone();
                let mut expected_memory = memory.clone();

                let actual = cpu.run_slice(&mut memory, 1);
                let expected = oracle.run_reference(&mut expected_memory, 1);
                assert_eq!(format!("{actual:?}"), format!("{expected:?}"), "{word:08x}");
                equal(&cpu, &oracle);
                let mut actual = [0; 4096];
                let mut expected = [0; 4096];
                for address in [0x1000, 0x2000] {
                    memory.read(address, &mut actual).unwrap();
                    expected_memory.read(address, &mut expected).unwrap();
                    assert_eq!(actual, expected, "memory {word:08x}");
                }
                assert_eq!(memory.revision(), expected_memory.revision());
            }
        }
    }
    #[test]
    fn budgets_syscalls_and_page_boundary_faults_match_reference() {
        let words = [
            0xd2800060, 0x91000400, 0xf100041f, 0x54ffffc1, 0xd503201f, 0xd4000001,
        ];
        for budget in [0, 1, 2, 3, 17, 4096, 9000] {
            let mut memory = memory(&words);
            let mut other = memory.clone();
            let mut cpu = Cpu::new(0x1000, 0x9000);
            let mut oracle = cpu.clone();

            assert_eq!(
                format!("{:?}", cpu.run_slice(&mut memory, budget)),
                format!("{:?}", oracle.run_reference(&mut other, budget))
            );
            equal(&cpu, &oracle);
        }
        let mut memory = memory(&[]);
        memory.write(0x1ffc, &0xd503201fu32.to_le_bytes()).unwrap();
        memory.unmap(0x2000, PAGE_SIZE).unwrap();
        let mut cpu = Cpu::new(0x1ffc, 0);
        assert!(matches!(
            cpu.run_slice(&mut memory, 1),
            SliceOutcome::Yield { instructions: 1 }
        ));
        assert_eq!(cpu.pc, 0x2000);
        assert!(matches!(
            cpu.run_slice(&mut memory, 1),
            SliceOutcome::Fault(CpuFault::Memory { pc: 0x2000, .. })
        ));
    }
    #[test]
    fn self_modification_invalidates_the_next_instruction_inside_a_cached_page() {
        let mut memory = memory(&[0xb9000041, 0xd2800020, 0xd4000001]); // str w1,[x2]; mov x0,1; svc
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.pc = 0x1004;
        cpu.run_slice(&mut memory, 1); // warm the word about to be overwritten
        cpu.pc = 0x1000;
        cpu.set_x(1, 0xd2800120);
        cpu.set_x(2, 0x1004); // replace next word by mov x0,9
        assert!(matches!(
            cpu.run_slice(&mut memory, 2),
            SliceOutcome::Yield { instructions: 2 }
        ));
        assert_eq!(cpu.x(0), 9);
        let mut thread = memory.share();
        thread.write(0x1004, &0xd28000e0u32.to_le_bytes()).unwrap();
        cpu.pc = 0x1004;
        cpu.run_slice(&mut memory, 1);
        assert_eq!(cpu.x(0), 7);
        thread.protect(0x1000, PAGE_SIZE, Permissions::R).unwrap();
        cpu.pc = 0x1004;
        assert!(matches!(
            cpu.run_slice(&mut memory, 1),
            SliceOutcome::Fault(CpuFault::Memory { .. })
        ));
    }
    #[test]
    fn reference_fallback_code_stores_invalidate_a_warmed_next_word() {
        for words in [
            vec![0xb821805f, 0xd2800020],
            vec![0x885ffc44, 0x8803fc41, 0xd2800020],
        ] {
            let target = 0x1000 + (words.len() as u64 - 1) * 4;
            let mut memory = memory(&words);
            let mut cpu = Cpu::new(target, 0);
            cpu.run_slice(&mut memory, 1);
            assert_eq!(cpu.x(0), 1);
            cpu.pc = 0x1000;
            cpu.set_x(1, 0xd2800120);
            cpu.set_x(2, target);
            assert!(matches!(
                cpu.run_slice(&mut memory, words.len() as u64),
                SliceOutcome::Yield { .. }
            ));
            assert_eq!(cpu.x(0), 9);
        }
        let mut memory = memory(&[0xd50b7422, 0xd503201f]); // dc zva,x2; nop
        let mut cpu = Cpu::new(0x1004, 0);
        cpu.run_slice(&mut memory, 1);
        cpu.pc = 0x1000;
        cpu.set_x(2, 0x1000);
        assert!(matches!(
            cpu.run_slice(&mut memory, 2),
            SliceOutcome::Fault(CpuFault::Instruction {
                pc: 0x1004,
                instruction: 0
            })
        ));
    }
    #[test]
    fn independent_spaces_with_equal_epochs_do_not_reuse_decoded_code() {
        let mut a = memory(&[0xd2800020]);
        let mut b = memory(&[0xd28000e0]);
        assert_eq!(a.instruction_revision(), b.instruction_revision());
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.run_slice(&mut a, 1);
        assert_eq!(cpu.x(0), 1);
        cpu.pc = 0x1000;
        cpu.run_slice(&mut b, 1);
        assert_eq!(cpu.x(0), 7);
        b.unmap(0x1000, PAGE_SIZE).unwrap();
        b.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        b.write(0x1000, &0xd28000a0u32.to_le_bytes()).unwrap();
        b.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        cpu.pc = 0x1000;
        cpu.run_slice(&mut b, 1);
        assert_eq!(cpu.x(0), 5);
    }
}
