// SPDX-License-Identifier: GPL-3.0-or-later
//! Worker-private RX blocks and stable RW links. No guest code is patched.
use crate::{CompilationStats, LinkStats};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc, sync::atomic::Ordering};
use trames_engine::CpuFault;
use trames_interpreter::Cpu;
use trames_memory::{CpuMemory, PAGE_SIZE};

type Identity = (u64, u64, u64);
type Key = (u64, u64, u8);
const BLOCK_LIMIT: u64 = 64;
const CACHE_LIMIT: usize = 128;
const NO_SLOT: u64 = CACHE_LIMIT as u64;
const CHAIN_ENTRY: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handle {
    slot: usize,
    generation: u64,
}
struct Node {
    key: Key,
    checked: Identity,
    page: Identity,
    generation: u64,
    block: Option<Block>,
    next: Option<Handle>,
}
struct Block {
    code: Code,
    instructions: u64,
    next_pc: u64,
    syscall: bool,
    traffic: CompilationStats,
    fast_offset: usize,
    tail_offset: usize,
}
impl Block {
    fn entry(&self) -> usize {
        self.code.pointer as usize + CHAIN_ENTRY
    }
    fn scalar_entry(&self) -> usize {
        self.code.pointer as usize + self.fast_offset
    }
}
pub(super) struct Executed {
    pub instructions: u64,
    pub blocks: u64,
    pub syscall: bool,
}

/// One native entry owns this stack frame and its borrowed epoch pointers.
/// Generated code keeps counters in caller-saved x14/x15 until an actual exit.
#[repr(C)]
struct Frame {
    remaining: u64,
    blocks: u64,
    pc: u64,
    syscall: u64,
    last_slot: u64,
    links: *const usize,
    epochs: [*const std::sync::atomic::AtomicU64; 3],
    expected: [u64; 3],
}
const _: () = {
    assert!(std::mem::size_of::<Frame>() == 96);
    assert!(std::mem::offset_of!(Frame, remaining) == 0);
    assert!(std::mem::offset_of!(Frame, blocks) == 8);
    assert!(std::mem::offset_of!(Frame, pc) == 16);
    assert!(std::mem::offset_of!(Frame, syscall) == 24);
    assert!(std::mem::offset_of!(Frame, last_slot) == 32);
    assert!(std::mem::offset_of!(Frame, links) == 40);
    assert!(std::mem::offset_of!(Frame, epochs) == 48);
    assert!(std::mem::offset_of!(Frame, expected) == 72);
};

pub(super) struct Cache {
    index: BTreeMap<Key, usize>,
    nodes: Box<[Option<Node>; CACHE_LIMIT]>,
    // Addresses never move; only this worker writes cells, between native calls.
    links: Box<[usize; CACHE_LIMIT]>,
    tails: Box<[usize; CACHE_LIMIT]>,
    active: Option<(Identity, u8)>,
    hot: Option<Handle>,
    last: Option<Handle>,
    serial: u64,
    victim: usize,
    pub stats: CompilationStats,
    pub links_stats: LinkStats,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            index: BTreeMap::new(),
            nodes: Box::new(std::array::from_fn(|_| None)),
            links: Box::new([0; CACHE_LIMIT]),
            tails: Box::new([0; CACHE_LIMIT]),
            active: None,
            hot: None,
            last: None,
            serial: 0,
            victim: 0,
            stats: CompilationStats::default(),
            links_stats: LinkStats::default(),
        }
    }
}
impl Cache {
    fn node(&self, handle: Handle) -> Option<&Node> {
        self.nodes[handle.slot]
            .as_ref()
            .filter(|node| node.generation == handle.generation)
    }
    fn handle(&self, slot: usize) -> Handle {
        Handle {
            slot,
            generation: self.nodes[slot]
                .as_ref()
                .expect("occupied code slot")
                .generation,
        }
    }
    fn unlink_all(&mut self) {
        self.links.fill(0);
        self.tails.fill(0);
        for node in self.nodes.iter_mut().flatten() {
            node.next = None;
        }
        self.last = None;
    }
    fn remove(&mut self, slot: usize) {
        if let Some(node) = self.nodes[slot].take() {
            self.index.remove(&node.key);
            if let Some(block) = &node.block {
                let entry = block.entry();
                let scalar = block.scalar_entry();
                for link in self.tails.iter_mut() {
                    if *link == scalar {
                        *link = 0;
                    }
                }

                // Revoke every incoming native edge before unmapping RX code.
                for link in self.links.iter_mut() {
                    if *link == entry {
                        *link = 0;
                    }
                }
            }
            self.links[slot] = 0;
            self.tails[slot] = 0;
            // node.next handles carry generations, so stale continuations cannot
            // resurrect an evicted slot even if mmap reuses the same host VA.
            drop(node);
        }
    }
    fn lookup(
        &mut self,
        memory: &impl CpuMemory,
        pc: u64,
        limit: u64,
        mode: u8,
        checked: Identity,
    ) -> Result<Handle, CpuFault> {
        // Natural short blocks share a canonical cache entry even when callers
        // arrive with different remaining budgets. Only a genuinely too-large
        // block needs an exact-budget prefix (e.g. single stepping).
        if mode & 8 == 0 {
            return self.lookup_exact(memory, pc, limit, mode, checked);
        }
        let full = BLOCK_LIMIT.min((PAGE_SIZE - (pc & (PAGE_SIZE - 1))) / 4);
        let handle = self.lookup_exact(memory, pc, full, mode, checked)?;
        if self
            .node(handle)
            .and_then(|node| node.block.as_ref())
            .is_none_or(|block| block.instructions <= limit)
        {
            return Ok(handle);
        }
        self.lookup_exact(memory, pc, limit, mode, checked)
    }
    fn lookup_exact(
        &mut self,
        memory: &impl CpuMemory,
        pc: u64,
        limit: u64,
        mode: u8,
        checked: Identity,
    ) -> Result<Handle, CpuFault> {
        let key = (pc, limit, mode);
        let candidate = self
            .hot
            .and_then(|h| self.node(h).filter(|n| n.key == key).map(|_| h));
        let slot = if let Some(handle) = candidate {
            Some(handle.slot)
        } else {
            self.links_stats.lookups += 1;
            self.index.get(&key).copied()
        };
        if let Some(slot) = slot {
            let node = self.nodes[slot].as_ref().expect("indexed code slot");
            if node.checked == checked {
                return Ok(self.handle(slot));
            }
            let page = memory
                .instruction_page_identity(pc)
                .map_err(|error| CpuFault::Memory { pc, error })?;
            if node.page == page {
                self.nodes[slot].as_mut().unwrap().checked = checked;
                return Ok(self.handle(slot));
            }
            self.remove(slot);
        }
        let page = memory
            .instruction_page_identity(pc)
            .map_err(|error| CpuFault::Memory { pc, error })?;
        let slot = slot.unwrap_or_else(|| {
            self.nodes
                .iter()
                .position(Option::is_none)
                .unwrap_or_else(|| {
                    let slot = self.victim;
                    self.victim = (self.victim + 1) % CACHE_LIMIT;
                    slot
                })
        });
        self.remove(slot);
        let block = compile(memory, pc, limit, slot, mode)
            .map_err(|error| CpuFault::Host(format!("JIT code publication: {error}")))?;
        if let Some(block) = &block {
            self.stats.blocks += 1;
            self.stats.host_words += block.traffic.host_words;
            self.stats.register_loads += block.traffic.register_loads;
            self.stats.register_stores += block.traffic.register_stores;
        }
        self.serial = self
            .serial
            .checked_add(1)
            .expect("worker code generation exhausted");
        self.nodes[slot] = Some(Node {
            key,
            checked,
            page,
            generation: self.serial,
            block,
            next: None,
        });
        self.index.insert(key, slot);
        Ok(self.handle(slot))
    }
    fn connect(&mut self, source: Handle, target: Handle, checked: Identity) {
        if self
            .node(source)
            .is_some_and(|node| node.next == Some(target))
            && self.links[source.slot] != 0
        {
            return;
        }

        let Some(a) = self.node(source) else {
            return;
        };
        let Some(b) = self.node(target) else {
            return;
        };
        let (Some(from), Some(to)) = (&a.block, &b.block) else {
            return;
        };
        if a.key.2 & 8 == 0
            || a.checked != checked
            || b.checked != checked
            || a.key.2 != b.key.2
            || a.page != b.page
            || from.next_pc != b.key.0
            || a.key.0 / PAGE_SIZE != b.key.0 / PAGE_SIZE
            // Budget-cut prefixes remain usable for exact stepping, but must
            // never replace a full-block hot edge with a shorter fragment.
            || b.key.1 != BLOCK_LIMIT.min((PAGE_SIZE - (b.key.0 & (PAGE_SIZE - 1))) / 4)
        {
            return;
        }
        let entry = to.entry();
        let tail = if a.key.2 == 8 && !from.syscall && to.syscall {
            to.scalar_entry()
        } else {
            0
        };
        self.nodes[source.slot].as_mut().unwrap().next = Some(target);
        self.links[source.slot] = entry;
        self.tails[source.slot] = tail;
    }
    pub(super) fn execute(
        &mut self,
        cpu: &mut Cpu,
        memory: &impl CpuMemory,
        budget: u64,
    ) -> Result<Option<Executed>, CpuFault> {
        let pc = cpu.pc;
        // A terminal syscall block needs neither a native chain frame nor an
        // epoch guard beyond the existing one-block identity check. Keep its
        // steady-state entry as small as the original scalar JIT path.
        if let Some(handle) = self.hot {
            if let Some(node) = self.node(handle) {
                if node.key.0 == pc
                    && node
                        .block
                        .as_ref()
                        .is_some_and(|block| block.syscall && block.instructions <= budget)
                    && node.checked == memory.instruction_identity()
                {
                    let block = node.block.as_ref().unwrap();
                    unsafe {
                        block
                            .code
                            .call_scalar(block.fast_offset, cpu.general_registers_mut());
                    }
                    cpu.pc = block.next_pc;
                    let instructions = block.instructions;
                    self.last = Some(handle);
                    self.links_stats.entries += 1;
                    return Ok(Some(Executed {
                        instructions,
                        blocks: 1,
                        syscall: true,
                    }));
                }
            }
        }
        if let Some(handle) = self.hot {
            if let Some(node) = self.node(handle) {
                if node.key.0 == pc && node.key.2 == 8 && self.tails[handle.slot] != 0 {
                    if let (Some(block), Some(target)) = (&node.block, node.next) {
                        if let Some(to) = self.node(target).and_then(|n| n.block.as_ref()) {
                            let instructions = block.instructions + to.instructions;
                            if instructions <= budget
                                && memory
                                    .instruction_epochs()
                                    .is_some_and(|epochs| epochs.0.iter().all(Option::is_none))
                                && node.checked == memory.instruction_identity()
                            {
                                // Both blocks are fixed, same-page, stable for
                                // this borrow, and end in SVC. One native tail
                                // jump needs no variable-budget chain frame.
                                let resumed =
                                    self.last.and_then(|h| self.node(h)).is_some_and(|n| {
                                        n.checked == node.checked
                                            && n.next == Some(handle)
                                            && n.block
                                                .as_ref()
                                                .is_some_and(|b| b.syscall && b.next_pc == pc)
                                    });
                                unsafe {
                                    block.code.call_tail(
                                        block.tail_offset,
                                        cpu.general_registers_mut(),
                                        self.tails.as_ptr(),
                                    );
                                }
                                cpu.pc = to.next_pc;
                                self.last = Some(target);
                                self.links_stats.entries += 1;
                                self.links_stats.linked_blocks += 1;
                                self.links_stats.syscall_resumes += u64::from(resumed);
                                return Ok(Some(Executed {
                                    instructions,
                                    blocks: 2,
                                    syscall: true,
                                }));
                            }
                        }
                    }
                }
            }
        }
        let limit = budget
            .min(BLOCK_LIMIT)
            .min((PAGE_SIZE - (pc & (PAGE_SIZE - 1))) / 4);
        let epochs = memory.instruction_epochs();
        let mut frame = Frame {
            remaining: budget,
            blocks: 0,
            pc,
            syscall: 0,
            last_slot: NO_SLOT,
            links: self.links.as_ptr(),
            epochs: [std::ptr::null(); 3],
            expected: [0; 3],
        };
        let mut mode = if epochs.is_some() { 8 } else { 0 };
        if let Some(epochs) = &epochs {
            for (i, counter) in epochs.0.iter().enumerate() {
                if let Some(counter) = counter {
                    frame.epochs[i] = *counter;
                    // Sample before the identity check: a concurrent change can
                    // cause a conservative exit, never bless stale code as new.
                    frame.expected[i] = counter.load(if i == 0 {
                        Ordering::Acquire
                    } else {
                        Ordering::Relaxed
                    });
                    mode |= 1 << i;
                }
            }
        }
        let checked = memory.instruction_identity();
        if self.active != Some((checked, mode)) {
            self.unlink_all();
            self.active = Some((checked, mode));
        }
        let source = self.last.take().filter(|handle| {
            self.node(*handle).is_some_and(|node| {
                node.checked == checked
                    && node.block.as_ref().is_some_and(|block| block.next_pc == pc)
            })
        });
        let resume = source
            .and_then(|h| self.node(h))
            .filter(|n| n.checked == checked)
            .and_then(|n| n.block.as_ref().filter(|b| b.next_pc == pc).and(n.next))
            .filter(|h| {
                self.node(*h).is_some_and(|n| {
                    n.checked == checked
                        && n.key.0 == pc
                        && n.key.2 == mode
                        && n.block.as_ref().is_some_and(|b| b.instructions <= budget)
                })
            });
        let handle = if let Some(target) = resume {
            if source
                .and_then(|h| self.node(h))
                .and_then(|n| n.block.as_ref())
                .is_some_and(|b| b.syscall)
            {
                self.links_stats.syscall_resumes += 1;
            }
            target
        } else if let Some(hot) = self.hot.filter(|handle| {
            self.node(*handle).is_some_and(|node| {
                node.checked == checked
                    && node.key
                        == (
                            pc,
                            BLOCK_LIMIT.min((PAGE_SIZE - (pc & (PAGE_SIZE - 1))) / 4),
                            mode,
                        )
                    && node
                        .block
                        .as_ref()
                        .is_none_or(|block| block.instructions <= budget)
            })
        }) {
            hot
        } else {
            self.lookup(memory, pc, limit, mode, checked)?
        };
        if let Some(source) = source {
            self.connect(source, handle, checked);
        }
        self.hot = Some(handle);
        let Some(block) = self.node(handle).and_then(|n| n.block.as_ref()) else {
            return Ok(None);
        };
        // SAFETY: slots/code remain owned and unchanged until this call returns.
        // Epoch references are borrowed from this live Memory/View. Native jumps
        // use only installed same-page entries, never a guest-provided pointer.
        if block.syscall || self.links[handle.slot] == 0 {
            // Never pay chain-frame stores for an entry that cannot chain.
            unsafe {
                block
                    .code
                    .call_scalar(block.fast_offset, cpu.general_registers_mut());
            }
            frame.remaining = budget - block.instructions;
            frame.blocks = 1;
            frame.pc = block.next_pc;
            frame.syscall = u64::from(block.syscall);
            frame.last_slot = handle.slot as u64;
        } else {
            unsafe {
                block.code.call(cpu.general_registers_mut(), &mut frame);
            }
        }
        self.links_stats.entries += 1;
        self.links_stats.linked_blocks += frame.blocks.saturating_sub(1);
        cpu.pc = frame.pc;
        if frame.last_slot < NO_SLOT {
            self.last = Some(self.handle(frame.last_slot as usize));
        }
        if frame.blocks == 0 {
            return Ok(None);
        } // changed epoch: use existing single-step fallback
        Ok(Some(Executed {
            instructions: budget - frame.remaining,
            blocks: frame.blocks,
            syscall: frame.syscall != 0,
        }))
    }
}

#[derive(Clone, Copy)]
struct Binding {
    guest: u32,
    dirty: bool,
    used: u32,
}
/// Compile-time allocation only. x0 retains the register-frame argument; x1-x13
/// are caller-saved; x14/x15/x16 hold block count, budget and entry context.
/// x18/TLS, x19-x30, host SP and FP/SIMD are never modified.
/// Bindings do not survive block exit, so worker/task migration needs no flush.
struct Assembler {
    words: Vec<u32>,
    bindings: [Option<Binding>; 13],
    hosts: [u8; 31],
    clock: u32,
    traffic: CompilationStats,
}
impl Assembler {
    fn new() -> Self {
        Self {
            words: Vec::new(),
            bindings: [None; 13],
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
        self.traffic.host_words = self.words.len() as u64;
        (self.words, self.traffic)
    }
}

fn load(words: &mut Vec<u32>, rt: u32, rn: u32, offset: u32) {
    words.push(0xf9400000 | ((offset / 8) << 10) | (rn << 5) | rt);
}
fn store(words: &mut Vec<u32>, rt: u32, offset: u32) {
    words.push(0xf9000000 | ((offset / 8) << 10) | (16 << 5) | rt);
}
fn constant(words: &mut Vec<u32>, rt: u32, value: u64) {
    words.push(0xd2800000 | (((value & 0xffff) as u32) << 5) | rt);
    for half in 1..4 {
        let part = ((value >> (half * 16)) & 0xffff) as u32;
        if part != 0 {
            words.push(0xf2800000 | (half << 21) | (part << 5) | rt);
        }
    }
}
fn branch(words: &mut [u32], at: usize, target: usize) {
    words[at] |= (((target as i64 - at as i64) as u32) & 0x7ffff) << 5;
}
fn exit(words: &mut Vec<u32>, pc: u64, slot: u64, syscall: bool) {
    constant(words, 17, pc);
    store(words, 17, 16);
    constant(words, 17, slot);
    store(words, 17, 32);
    if syscall {
        constant(words, 17, 1);
        store(words, 17, 24);
    }
    store(words, 15, 0);
    store(words, 14, 8);
    words.push(0xd65f03c0);
}
fn render(
    body: &[u32],
    start: u64,
    next: u64,
    slot: usize,
    count: u64,
    mask: u8,
    syscall: bool,
) -> Vec<u32> {
    let mut words = vec![0xd503245f, 0xaa0103f0, 0xf940020f, 0xaa1f03ee, 0xd50324df]; // BTI c; ctx=x1; budget; blocks=0; BTI jc
    let mut guards = Vec::new();
    for i in 0..3 {
        if mask & (1 << i) == 0 {
            continue;
        }
        load(&mut words, 11, 16, 48 + i * 8);
        if i == 0 {
            words.push(0xc8dffc00 | (11 << 5) | 12);
        } else {
            load(&mut words, 12, 11, 0);
        }
        load(&mut words, 13, 16, 72 + i * 8);
        words.push(0xeb00001f | (13 << 16) | (12 << 5)); // cmp epochs
        guards.push(words.len());
        words.push(0x54000001); // b.ne slow exit
    }
    words.push(0xf100001f | ((count as u32) << 10) | (15 << 5));
    guards.push(words.len());
    words.push(0x54000003); // b.lo: no over-retirement
    words.push(0xd1000000 | ((count as u32) << 10) | (15 << 5) | 15);
    words.extend_from_slice(body);
    words.push(0x91000000 | (1 << 10) | (14 << 5) | 14);
    let mut done = Vec::new();
    if !syscall {
        done.push(words.len());
        words.push(0xb400000f); // cbz budget
        load(&mut words, 17, 16, 40);
        load(&mut words, 17, 17, slot as u32 * 8);
        done.push(words.len());
        words.push(0xb4000011); // cbz link
        words.push(0xd61f0220); // br x17 (link entry has BTI jc)
    }
    let success = words.len();
    exit(&mut words, next, slot as u64, syscall);
    let failed = words.len();
    exit(&mut words, start, NO_SLOT, false);
    for at in done {
        branch(&mut words, at, success);
    }
    for at in guards {
        branch(&mut words, at, failed);
    }
    words
}

fn signed(value: u64, bits: u32) -> u64 {
    ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
}

fn compile(
    memory: &impl CpuMemory,
    start: u64,
    limit: u64,
    slot: usize,
    mode: u8,
) -> std::io::Result<Option<Block>> {
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
    let (body, mut traffic) = code.finish();
    let mut words = render(&body, start, next, slot, count, mode & 7, syscall);
    let fast_offset = words.len() * 4;
    words.push(0xd50324df); // callable and tail-jump entry
    words.extend_from_slice(&body);
    words.push(0xd65f03c0);
    let tail_offset = words.len() * 4;
    words.extend_from_slice(&[0xd503245f, 0xaa0103f0]);
    words.extend_from_slice(&body);
    load(&mut words, 17, 16, slot as u32 * 8);
    words.push(0xd61f0220);
    traffic.host_words = words.len() as u64;
    Ok(Some(Block {
        code: Code::publish(&words)?,
        instructions: count,
        next_pc: next,
        syscall,
        traffic,
        fast_offset,
        tail_offset,
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
    unsafe fn call_tail(&self, offset: usize, registers: &mut [u64; 31], links: *const usize) {
        // SAFETY: the caller validated the bounded two-block edge and owns both
        // live RX entries. Only this worker can mutate/revoke the RW jump cell.
        let function: unsafe extern "C" fn(*mut u64, *const usize) =
            unsafe { std::mem::transmute(self.pointer.cast::<u8>().add(offset)) };
        unsafe {
            function(registers.as_mut_ptr(), links);
        }
    }
    unsafe fn call_scalar(&self, offset: usize, registers: &mut [u64; 31]) {
        // SAFETY: the secondary BTI-c entry contains the same bounded register
        // body and returns without modifying host callee-saved state or TLS.
        let function: unsafe extern "C" fn(*mut u64) =
            unsafe { std::mem::transmute(self.pointer.cast::<u8>().add(offset)) };
        unsafe {
            function(registers.as_mut_ptr());
        }
    }
    unsafe fn call(&self, registers: &mut [u64; 31], frame: &mut Frame) {
        // SAFETY: codegen emits an AAPCS64 function with this exact ABI. The
        // entry begins with BTI c and returns through untouched host x30.
        let function: unsafe extern "C" fn(*mut u64, *mut Frame) =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe {
            function(registers.as_mut_ptr(), frame);
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
    use std::sync::atomic::AtomicU64;
    use trames_memory::{Memory, Permissions};
    fn memory(words: &[u32]) -> Memory {
        let mut m = Memory::default();
        m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, w) in words.iter().enumerate() {
            m.write_array(0x1000 + i as u64 * 4, w.to_le_bytes())
                .unwrap();
        }
        m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        m
    }
    fn frame(links: &[usize; CACHE_LIMIT]) -> Frame {
        Frame {
            remaining: 64,
            blocks: 0,
            pc: 0x1000,
            syscall: 0,
            last_slot: NO_SLOT,
            links: links.as_ptr(),
            epochs: [std::ptr::null(); 3],
            expected: [0; 3],
        }
    }
    #[test]
    fn guarded_entries_reject_changed_epochs_without_retirement_or_host_svc() {
        let m = memory(&[0x91000400, 0xd4000001]);
        let links = [0usize; CACHE_LIMIT];
        for index in 0..3 {
            let block = compile(&m, 0x1000, 64, 0, 8 | (1 << index))
                .unwrap()
                .unwrap();
            let counter = AtomicU64::new(1);
            let mut f = frame(&links);
            f.epochs[index] = &counter;
            let mut regs = [0u64; 31];
            regs[0] = 123;
            unsafe {
                block.code.call(&mut regs, &mut f);
            }
            assert_eq!((f.blocks, f.remaining, f.pc, regs[0]), (0, 64, 0x1000, 123));
            f.expected[index] = 1;
            unsafe {
                block.code.call(&mut regs, &mut f);
            }
            assert_eq!(
                (f.blocks, f.remaining, f.pc, f.syscall, regs[0]),
                (1, 62, 0x1008, 1, 124)
            );
            let words = unsafe {
                std::slice::from_raw_parts(
                    block.code.pointer.cast::<u32>(),
                    block.traffic.host_words as usize,
                )
            };
            assert!(!words.iter().any(|word| word & 0xffe0001f == 0xd4000001));
        }
    }
    #[test]
    fn eviction_revokes_native_edges_before_rx_unmap_and_generations_reject_reuse() {
        let m = memory(&[0x14000004, 0, 0, 0, 0xd4000001]);
        let mut cpu = Cpu::new(0x1000, 0);
        let mut cache = Cache::default();
        cache.execute(&mut cpu, &m, 64).unwrap().unwrap();
        let source = cache.hot.unwrap();
        assert!(cache.execute(&mut cpu, &m, 64).unwrap().unwrap().syscall);
        let target = cache.hot.unwrap();
        cpu.pc = 0x1000;
        let hit = cache.execute(&mut cpu, &m, 64).unwrap().unwrap();
        assert_eq!((hit.blocks, hit.instructions, hit.syscall), (2, 2, true));
        assert_ne!(cache.links[source.slot], 0);
        cache.remove(target.slot);
        assert_eq!(cache.links[source.slot], 0);
        assert!(cache.node(target).is_none());
        cpu.pc = 0x1000;
        let miss = cache.execute(&mut cpu, &m, 64).unwrap().unwrap();
        assert_eq!((miss.blocks, miss.syscall, cpu.pc), (1, false, 0x1010));
        assert!(cache.execute(&mut cpu, &m, 64).unwrap().unwrap().syscall);
        let replacement = cache.hot.unwrap();
        assert_eq!(target.slot, replacement.slot);
        assert_ne!(target.generation, replacement.generation);
        cpu.pc = 0x1000;
        assert_eq!(cache.execute(&mut cpu, &m, 64).unwrap().unwrap().blocks, 2);
    }
}
