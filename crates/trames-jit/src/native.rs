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
    memory: Option<Box<MemoryOps>>,
    next: Option<Handle>,
}
impl Node {
    fn accepts(&self, pc: u64) -> bool {
        self.block.as_ref().is_some_and(|b| b.accepts(pc))
            || (self.block.is_none() && self.memory.is_some() && self.key.0.wrapping_add(4) == pc)
    }
}
struct Block {
    code: Code,
    has_memory: bool,
    instructions: u64,
    next_pc: u64,
    syscall: bool,
    traffic: CompilationStats,
    fast_offset: usize,
    tail_offset: usize,
    context: bool,
    flow: Flow,
}
// Keep decoded memory ownership out of the hot Block/Node layout. The existing
// optional pointer also owns legacy single-access embeddings without epochs.
enum MemoryOps {
    Single(crate::memory_ops::Operation),
    // Generated literals require stable operation addresses across Vec growth.
    #[allow(clippy::vec_box)]
    Fused(Vec<Box<crate::memory_ops::Operation>>),
}
impl MemoryOps {
    fn single(&self) -> Option<&crate::memory_ops::Operation> {
        match self {
            Self::Single(op) => Some(op),
            Self::Fused(_) => None,
        }
    }
    fn host_words(&self) -> u64 {
        match self {
            Self::Single(op) => op.host_words(),
            Self::Fused(ops) => ops.iter().map(|op| op.host_words()).sum(),
        }
    }
}
struct Compiled {
    block: Block,
    memory: Option<Box<MemoryOps>>,
}
impl std::ops::Deref for Compiled {
    type Target = Block;
    fn deref(&self) -> &Block {
        &self.block
    }
}

#[derive(Clone, Copy)]
enum Flow {
    Fixed,
    Syscall,
    Choice(u64),
    Register,
}
impl Block {
    fn accepts(&self, pc: u64) -> bool {
        match self.flow {
            Flow::Fixed | Flow::Syscall => pc == self.next_pc,
            Flow::Choice(taken) => pc == self.next_pc || pc == taken,
            Flow::Register => true,
        }
    }
    fn dynamic(&self) -> bool {
        matches!(self.flow, Flow::Choice(_) | Flow::Register)
    }
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
    link_pcs: *const u64,
    sp: u64,
    nzcv: u64,
}
const _: () = {
    assert!(std::mem::size_of::<Frame>() == 120);
    assert!(std::mem::offset_of!(Frame, remaining) == 0);
    assert!(std::mem::offset_of!(Frame, blocks) == 8);
    assert!(std::mem::offset_of!(Frame, pc) == 16);
    assert!(std::mem::offset_of!(Frame, syscall) == 24);
    assert!(std::mem::offset_of!(Frame, last_slot) == 32);
    assert!(std::mem::offset_of!(Frame, links) == 40);
    assert!(std::mem::offset_of!(Frame, epochs) == 48);
    assert!(std::mem::offset_of!(Frame, expected) == 72);
    assert!(std::mem::offset_of!(Frame, link_pcs) == 96);
    assert!(std::mem::offset_of!(Frame, sp) == 104);
    assert!(std::mem::offset_of!(Frame, nzcv) == 112);
};

/// Extra state exists only for helper-bearing blocks. The original scalar/SVC
/// frame, ABI and hot path stay unchanged. All pointers are entry-scoped; no data
/// address or Memory/View borrow is retained in the compiled cache.
#[repr(C)]
struct MemoryFrame<M> {
    frame: Frame,
    helper: usize,
    cpu: *mut Cpu,
    memory: *mut M,
    registers: *mut u64,
    checked: Identity,
    fault: Option<CpuFault>,
    stats: crate::MemoryStats,
}
const _: () = {
    assert!(std::mem::offset_of!(MemoryFrame<()>, helper) == 120);
    assert!(std::mem::offset_of!(MemoryFrame<()>, registers) == 144);
};
struct MemorySite {
    adjust: usize,
    stop: usize,
    before: u64,
}
unsafe extern "C" fn memory_access<M: CpuMemory>(
    pointer: *mut MemoryFrame<M>,
    operation: *const crate::memory_ops::Operation,
    remaining: u64,
    blocks: u64,
) -> u64 {
    // SAFETY: generated entry receives this exact monomorphized frame/helper.
    // CPU bindings have been flushed; both typed mutable borrows are exclusive
    // until return, and the immutable boxed operation outlives native execution.
    let (frame, op) = unsafe { (&mut *pointer, &*operation) };
    let (cpu, memory) = unsafe { (&mut *frame.cpu, &mut *frame.memory) };
    cpu.pc = op.pc();
    cpu.sp = frame.frame.sp;
    let result = op.execute(cpu, memory);
    frame.frame.sp = cpu.sp;
    let next = match result {
        Ok(direct) => {
            frame.stats.instructions += 1;
            frame.stats.staged += u64::from(!direct);
            if memory.instruction_identity() == frame.checked {
                1
            } else {
                frame.frame.remaining = remaining - 1;
                frame.frame.blocks = blocks + 1;
                0
            }
        }
        Err(error) => {
            frame.fault = Some(error);
            frame.frame.remaining = remaining;
            frame.frame.blocks = blocks;
            0
        }
    };
    if next == 0 {
        frame.frame.pc = cpu.pc;
        frame.frame.last_slot = NO_SLOT;
    }
    // This mutable CPU reborrow can invalidate an older register sub-borrow.
    // Re-derive it after the helper's last CPU observation; generated code reloads
    // this pointer before touching any guest registers, including after a loop.
    frame.registers = cpu.general_registers_mut().as_mut_ptr();
    next
}

#[derive(Default)]
struct Cold {
    index: BTreeMap<Key, usize>,
    serial: u64,
    victim: usize,
    fault_progress: (u64, u64),
    memory: crate::MemoryStats,
    compilation: CompilationStats,
}
pub(super) struct Cache {
    cold: Box<Cold>,
    nodes: Box<[Option<Node>; CACHE_LIMIT]>,
    // Addresses never move; only this worker writes cells, between native calls.
    links: Box<[usize; CACHE_LIMIT]>,
    tails: Box<[usize; CACHE_LIMIT]>,
    link_pcs: Box<[u64; CACHE_LIMIT]>,
    active: Option<(Identity, u8)>,
    hot: Option<Handle>,
    last: Option<Handle>,
    pub links_stats: LinkStats,
}
impl Default for Cache {
    fn default() -> Self {
        Self {
            cold: Box::default(),
            nodes: Box::new(std::array::from_fn(|_| None)),
            links: Box::new([0; CACHE_LIMIT]),
            tails: Box::new([0; CACHE_LIMIT]),
            link_pcs: Box::new([0; CACHE_LIMIT]),
            active: None,
            hot: None,
            last: None,
            links_stats: LinkStats::default(),
        }
    }
}
impl Cache {
    pub(super) fn memory_stats(&self) -> crate::MemoryStats {
        self.cold.memory
    }
    pub(super) fn compilation_stats(&self) -> CompilationStats {
        self.cold.compilation
    }
    pub(super) fn take_fault_progress(&mut self) -> (u64, u64) {
        std::mem::take(&mut self.cold.fault_progress)
    }
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
            self.cold.index.remove(&node.key);
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
            self.cold.index.get(&key).copied()
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
                    let slot = self.cold.victim;
                    self.cold.victim = (self.cold.victim + 1) % CACHE_LIMIT;
                    slot
                })
        });
        self.remove(slot);
        let (block, memory_op) = if let Some(compiled) = compile(memory, pc, limit, slot, mode)? {
            (Some(compiled.block), compiled.memory)
        } else {
            (
                None,
                crate::memory_ops::Operation::compile(memory, pc)?
                    .map(|op| Box::new(MemoryOps::Single(op))),
            )
        };
        if let Some(op) = &memory_op {
            self.cold.compilation.blocks += u64::from(block.is_none());
            self.cold.compilation.host_words += op.host_words();
        }
        if let Some(block) = &block {
            self.cold.compilation.blocks += 1;
            self.cold.compilation.host_words += block.traffic.host_words;
            self.cold.compilation.register_loads += block.traffic.register_loads;
            self.cold.compilation.register_stores += block.traffic.register_stores;
        }
        self.cold.serial = self
            .cold
            .serial
            .checked_add(1)
            .expect("worker code generation exhausted");
        self.nodes[slot] = Some(Node {
            key,
            checked,
            page,
            generation: self.cold.serial,
            block,
            memory: memory_op,
            next: None,
        });
        self.cold.index.insert(key, slot);
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
        if a.key.2 & 8 == 0
            || a.checked != checked
            || b.checked != checked
            || a.key.2 != b.key.2
            || a.page != b.page
            || !a.accepts(b.key.0)
            || a.key.0 / PAGE_SIZE != b.key.0 / PAGE_SIZE
            // Budget-cut prefixes remain usable for exact stepping, but must
            // never replace a full-block hot edge with a shorter fragment.
            || b.key.1 != BLOCK_LIMIT.min((PAGE_SIZE - (b.key.0 & (PAGE_SIZE - 1))) / 4)
        {
            return;
        }
        let (Some(from), Some(to)) = (&a.block, &b.block) else {
            self.nodes[source.slot].as_mut().unwrap().next = Some(target);
            self.links[source.slot] = 0;
            self.tails[source.slot] = 0;
            return;
        };
        if from.has_memory || to.has_memory {
            // Helper-bearing entries need a larger, typed frame. Their edges
            // remain generation-checked metadata, never ordinary native jumps.
            self.nodes[source.slot].as_mut().unwrap().next = Some(target);
            self.links[source.slot] = 0;
            self.tails[source.slot] = 0;
            return;
        }
        let entry = to.entry();
        let tail = if a.key.2 == 8
            && !from.syscall
            && to.syscall
            && !from.context
            && !to.context
            && !from.dynamic()
        {
            to.scalar_entry()
        } else {
            0
        };
        self.nodes[source.slot].as_mut().unwrap().next = Some(target);
        self.links[source.slot] = entry;
        self.link_pcs[source.slot] = self.nodes[target.slot].as_ref().unwrap().key.0;
        self.tails[source.slot] = tail;
    }
    #[inline(always)]
    pub(super) fn syscall<M: CpuMemory>(
        &mut self,
        cpu: &mut Cpu,
        memory: &M,
        budget: u64,
    ) -> Option<u64> {
        let pc = cpu.pc;
        // A terminal syscall block needs neither a native chain frame nor an
        // epoch guard beyond the existing one-block identity check. Keep its
        // steady-state entry as small as the original scalar JIT path.
        if let Some(handle) = self.hot {
            if let Some(node) = self.node(handle) {
                if node.key.0 == pc
                    && node.block.as_ref().is_some_and(|block| {
                        block.syscall && !block.context && block.instructions <= budget
                    })
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
                    return Some(instructions);
                }
            }
        }
        None
    }
    #[inline(always)]
    pub(super) fn execute<M: CpuMemory>(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut M,
        budget: u64,
    ) -> Result<Option<Executed>, CpuFault> {
        let pc = cpu.pc;
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
        self.execute_blocks(cpu, memory, budget)
    }
    // General lookup/compilation and the 120-byte chain frame are unnecessary
    // for steady-state short syscall entries. Keep them beyond the fast entry.
    #[inline(never)]
    fn execute_blocks<M: CpuMemory>(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut M,
        budget: u64,
    ) -> Result<Option<Executed>, CpuFault> {
        let pc = cpu.pc;
        if let Some(target) = self
            .last
            .and_then(|h| self.node(h))
            .and_then(|n| n.next)
            .filter(|h| {
                self.node(*h).is_some_and(|n| {
                    n.key.0 == pc
                        && n.memory
                            .as_deref()
                            .is_some_and(|ops| ops.single().is_some())
                        && n.checked == memory.instruction_identity()
                })
            })
        {
            self.hot = Some(target);
        }
        if let Some(op) = self
            .hot
            .and_then(|h| self.node(h))
            .filter(|n| {
                n.key.0 == pc
                    && n.memory
                        .as_deref()
                        .is_some_and(|ops| ops.single().is_some())
            })
            .filter(|n| n.checked == memory.instruction_identity())
            .and_then(|n| n.memory.as_deref().and_then(MemoryOps::single))
        {
            let direct = op.execute(cpu, memory)?;
            self.cold.memory.instructions += 1;
            self.cold.memory.staged += u64::from(!direct);
            self.last = self.hot;
            self.links_stats.entries += 1;
            return Ok(Some(Executed {
                instructions: 1,
                blocks: 1,
                syscall: false,
            }));
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
            link_pcs: self.link_pcs.as_ptr(),
            sp: cpu.sp,
            nzcv: (cpu.nzcv() as u64) << 28,
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
            self.node(*handle)
                .is_some_and(|node| node.checked == checked && node.accepts(pc))
        });
        let resume = source
            .and_then(|h| self.node(h))
            .filter(|n| n.checked == checked)
            .and_then(|n| n.accepts(pc).then_some(n.next).flatten())
            .filter(|h| {
                self.node(*h).is_some_and(|n| {
                    n.checked == checked
                        && n.key.0 == pc
                        && n.key.2 == mode
                        && n.block.as_ref().is_none_or(|b| b.instructions <= budget)
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
            if let Some(op) = self
                .node(handle)
                .and_then(|n| n.memory.as_deref().and_then(MemoryOps::single))
            {
                // Native epoch references are not used by this single checked
                // access. The mutable borrow may invalidate executable bytes;
                // return to the ordinary identity boundary before any next op.
                let direct = op.execute(cpu, memory)?;
                self.cold.memory.instructions += 1;
                self.cold.memory.staged += u64::from(!direct);
                self.last = Some(handle);
                self.links_stats.entries += 1;
                return Ok(Some(Executed {
                    instructions: 1,
                    blocks: 1,
                    syscall: false,
                }));
            }
            return Ok(None);
        };
        // SAFETY: slots/code remain owned and unchanged until this call returns.
        // Epoch references are borrowed from this live Memory/View. Native jumps
        // use only installed same-page entries, never a guest-provided pointer.
        if block.has_memory {
            return self.execute_memory_block(cpu, memory, budget, handle, frame);
        }
        if block.syscall || self.links[handle.slot] == 0 {
            // Never pay chain-frame stores for an entry that cannot chain.
            unsafe {
                if block.context {
                    block.code.call_context(
                        block.fast_offset,
                        cpu.general_registers_mut(),
                        &mut frame,
                    );
                } else {
                    block
                        .code
                        .call_scalar(block.fast_offset, cpu.general_registers_mut());
                }
            }
            frame.remaining = budget - block.instructions;
            frame.blocks = 1;
            if !block.dynamic() {
                frame.pc = block.next_pc;
            }
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
        cpu.sp = frame.sp;
        cpu.set_nzcv((frame.nzcv >> 28) as u32);
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
    // Keep the larger typed helper frame out of scalar/SVC native entries.
    #[inline(never)]
    fn execute_memory_block<M: CpuMemory>(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut M,
        budget: u64,
        handle: Handle,
        frame: Frame,
    ) -> Result<Option<Executed>, CpuFault> {
        let checked = self.node(handle).unwrap().checked;
        let block = self.node(handle).unwrap().block.as_ref().unwrap();
        let cpu_pointer = cpu as *mut Cpu;
        // Derive both reborrows from one raw parent, then suspend Rust CPU access
        // until native return. Every helper publishes a fresh register sub-borrow.
        let registers = unsafe { (*cpu_pointer).general_registers_mut().as_mut_ptr() };
        let block_length = block.instructions;
        let mut fused = MemoryFrame {
            frame,
            helper: memory_access::<M> as *const () as usize,
            cpu: cpu_pointer,
            memory: memory as *mut _,
            registers,
            checked,
            fault: None,
            stats: crate::MemoryStats::default(),
        };
        // All Rust register references end before entry. The helper temporarily
        // reborrows this same CPU/mm; no guest lease survives the callback.
        unsafe { block.code.call_memory_block(registers, &mut fused) };
        self.cold.memory.instructions += fused.stats.instructions;
        self.cold.memory.staged += fused.stats.staged;
        self.cold.memory.fused_entries += 1;
        self.cold.memory.fused_blocks += fused.frame.blocks;
        self.links_stats.entries += 1;
        self.links_stats.linked_blocks += fused.frame.blocks.saturating_sub(1);
        cpu.pc = fused.frame.pc;
        cpu.sp = fused.frame.sp;
        cpu.set_nzcv((fused.frame.nzcv >> 28) as u32);
        if let Some(error) = fused.fault {
            // Consumed only on the wrapper's fault path. The established scalar
            // return ABI and hot counters acquire no memory-specific result tag.
            let instructions = budget - fused.frame.remaining;
            let blocks =
                fused.frame.blocks + u64::from(instructions > fused.frame.blocks * block_length);
            self.cold.fault_progress = (instructions, blocks);
            return Err(error);
        }
        if fused.frame.last_slot < NO_SLOT {
            self.last = Some(self.handle(fused.frame.last_slot as usize));
        }
        if fused.frame.blocks == 0 {
            return Ok(None);
        }
        Ok(Some(Executed {
            instructions: budget - fused.frame.remaining,
            blocks: fused.frame.blocks,
            syscall: fused.frame.syscall != 0,
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
    hosts: [u8; 33],
    context: bool,
    flags_live: bool,
    flags_dirty: bool,
    clock: u32,
    traffic: CompilationStats,
}
impl Assembler {
    fn new() -> Self {
        Self {
            words: Vec::new(),
            bindings: [None; 13],
            hosts: [u8::MAX; 33],
            context: false,
            flags_live: false,
            flags_dirty: false,
            clock: 0,
            traffic: CompilationStats::default(),
        }
    }
    fn store(&mut self, slot: usize, binding: Binding) {
        if binding.dirty {
            if binding.guest == 32 {
                store(&mut self.words, slot as u32 + 1, 104);
            } else {
                self.words
                    .push(0xf9000000 | (binding.guest << 10) | (slot as u32 + 1));
            }
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
                if guest == 32 {
                    load(&mut self.words, slot as u32 + 1, 16, 104);
                    self.context = true;
                } else {
                    self.words
                        .push(0xf9400000 | (guest << 10) | (slot as u32 + 1));
                }
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
        self.context |= guest == 32;
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
    fn flags_read(&mut self) {
        self.context = true;
        if !self.flags_live {
            load(&mut self.words, 17, 16, 112);
            self.words.push(0xd51b4211); // msr nzcv,x17; never host TLS
            self.flags_live = true;
        }
    }
    fn flags_written(&mut self) {
        self.context = true;
        self.flags_live = true;
        self.flags_dirty = true;
    }
    fn flush(&mut self) {
        for slot in 0..self.bindings.len() {
            if let Some(binding) = self.bindings[slot] {
                self.store(slot, binding);
            }
        }
        if self.flags_dirty {
            // Bindings have all been flushed. x11 is now scratch, while x17
            // may hold a dynamic guest PC computed before an aliased LR write.
            self.words.push(0xd53b420b); // mrs x11,nzcv
            store(&mut self.words, 11, 112);
        }
        self.bindings.fill(None);
        self.hosts.fill(u8::MAX);
        self.flags_live = false;
        self.flags_dirty = false;
    }
    fn memory(&mut self, op: &crate::memory_ops::Operation, before: u64) -> MemorySite {
        self.flush();
        self.context = true;
        // One AAPCS64 helper boundary. Caller-saved guest bindings were flushed;
        // preserve only native entry context, budget/block counters and host LR.
        self.words
            .extend_from_slice(&[0xa9bd43e0, 0xa9013fee, 0xf90013fe]);
        self.words.push(0xaa1003e0); // x0 = extended frame
        constant(&mut self.words, 1, op as *const _ as usize as u64);
        let adjust = self.words.len();
        self.words.push(0x910001e2); // x2 = remaining budget at this instruction
        self.words.push(0xaa0e03e3); // x3 = completed blocks
        load(&mut self.words, 17, 16, 120);
        self.words.push(0xd63f0220); // blr helper
        self.words.extend_from_slice(&[
            0xaa0003f1, // keep continuation decision across context restore
            0xa9413fee, 0xf94013fe, 0xa8c343e0,
        ]);
        load(&mut self.words, 0, 16, 144); // refreshed CPU register reborrow
        let stop = self.words.len();
        self.words.push(0xb4000011); // cbz x17: precise fault/code-change exit
        MemorySite {
            adjust,
            stop,
            before,
        }
    }
    fn finish(mut self) -> (Vec<u32>, CompilationStats, bool) {
        self.flush();
        self.traffic.host_words = self.words.len() as u64;
        (self.words, self.traffic, self.context)
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
    (start, next): (u64, u64),
    slot: usize,
    count: u64,
    mask: u8,
    flow: Flow,
    memory: &[MemorySite],
) -> Vec<u32> {
    let syscall = matches!(flow, Flow::Syscall);
    let dynamic = matches!(flow, Flow::Choice(_) | Flow::Register);
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
    let body_start = words.len();
    words.extend_from_slice(body);
    if dynamic {
        store(&mut words, 17, 16);
    }
    words.push(0x91000000 | (1 << 10) | (14 << 5) | 14);
    let mut done = Vec::new();
    if !syscall {
        done.push(words.len());
        words.push(0xb400000f); // cbz budget
        if !memory.is_empty() {
            // Loop back through the existing budget/epoch guards. This keeps a
            // general same-block loop inside one native entry; each memory
            // instruction still takes its own scoped borrow and code check.
            match flow {
                Flow::Choice(taken) if taken == start => {
                    constant(&mut words, 11, start);
                    words.push(0xeb0b023f); // cmp selected PC, loop start
                    let at = words.len();
                    words.push(0x54000000); // b.eq guarded chain entry
                    branch(&mut words, at, CHAIN_ENTRY / 4);
                }
                Flow::Fixed if next == start => {
                    let offset = (CHAIN_ENTRY as i64 / 4 - words.len() as i64) as u32;
                    words.push(0x14000000 | (offset & 0x3ffffff));
                }
                _ => {}
            }
        }
        if dynamic {
            load(&mut words, 11, 16, 96);
            load(&mut words, 11, 11, slot as u32 * 8);
            words.push(0xeb0b023f); // cmp selected guest PC (x17), cached edge PC (x11)
            done.push(words.len());
            words.push(0x54000001); // b.ne actual-PC exit
        }
        load(&mut words, 17, 16, 40);
        load(&mut words, 17, 17, slot as u32 * 8);
        done.push(words.len());
        words.push(0xb4000011); // cbz link
        words.push(0xd61f0220); // br x17 (link entry has BTI jc)
    }
    let success = words.len();
    if dynamic {
        // The selected PC was published before link lookup could clobber x17.
        constant(&mut words, 17, slot as u64);
        store(&mut words, 17, 32);
        store(&mut words, 15, 0);
        store(&mut words, 14, 8);
        words.push(0xd65f03c0);
    } else {
        exit(&mut words, next, slot as u64, syscall);
    }
    let failed = words.len();
    exit(&mut words, start, NO_SLOT, false);
    for at in done {
        branch(&mut words, at, success);
    }
    for at in guards {
        branch(&mut words, at, failed);
    }
    if !memory.is_empty() {
        let stopped = words.len();
        words.push(0xd65f03c0); // helper already published precise exit state
        for site in memory {
            branch(&mut words, body_start + site.stop, stopped);
        }
    }
    words
}

fn signed(value: u64, bits: u32) -> u64 {
    ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
}

fn sp_register(reg: u32) -> u32 {
    if reg == 31 {
        32
    } else {
        reg
    }
}

// Translation-time validation, identical to the canonical logical-immediate
// mask decoder. No mask decoding executes inside a generated block.
fn logical_mask(n: u32, s: u32, _r: u32, wide: bool) -> bool {
    let value = (n << 6) | (!s & 63);
    if value == 0 || (!wide && n != 0) {
        return false;
    }
    let len = 31 - value.leading_zeros();
    len >= 1 && s & ((1 << len) - 1) != (1 << len) - 1
}

fn select_pc(code: &mut Assembler, test: u32, fall: u64, taken: u64) {
    code.context = true;
    let yes = code.words.len();
    code.words.push(test);
    constant(&mut code.words, 17, fall);
    let done = code.words.len();
    code.words.push(0x14000000);
    let target = code.words.len();
    constant(&mut code.words, 17, taken);
    let end = code.words.len();
    branch(&mut code.words, yes, target);
    code.words[done] |= (end - done) as u32;
}

fn compile(
    memory: &impl CpuMemory,
    start: u64,
    limit: u64,
    slot: usize,
    mode: u8,
) -> Result<Option<Compiled>, CpuFault> {
    compile_with_features(
        memory,
        start,
        limit,
        slot,
        mode,
        crate::features::profile().allowed,
    )
}
fn compile_with_features(
    memory: &impl CpuMemory,
    start: u64,
    limit: u64,
    slot: usize,
    mode: u8,
    host: trames_execution::Features,
) -> Result<Option<Compiled>, CpuFault> {
    let mut code = Assembler::new();
    let mut memory_ops = Vec::new();
    let mut memory_sites = Vec::new();
    let mut count = 0;
    let mut next = start;
    let mut syscall = false;
    let mut flow = Flow::Fixed;
    for _ in 0..limit {
        let pc = next;
        // Never report lookahead faults; fault only when the reached PC fails.
        let Ok(word) = memory.fetch_u32(pc) else {
            break;
        };
        if !crate::features::permits(host, word) {
            if count == 0 {
                return Err(CpuFault::Instruction {
                    pc,
                    instruction: word,
                });
            }
            break; // A preceding prefix must retire before the reached fault.
        }
        let rd = word & 31;
        let rn = (word >> 5) & 31;
        let rm = (word >> 16) & 31;
        let sf = word >> 31;
        let flags = word & (1 << 29) != 0;
        let mut terminal = false;
        if word & 0xffe0001f == 0xd4000001 {
            syscall = true;
            flow = Flow::Syscall;
            next = pc.wrapping_add(4);
            terminal = true;
        } else if word == 0xd503201f { // NOP
        } else if word & 0x7fe0e000 == 0x1ac04000 {
            let bytes = 1 << ((word >> 10) & 3);
            if (sf != 0) != (bytes == 8) {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
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
        } else if word & 0x1f800000 == 0x11000000 {
            let lhs = code.read(sp_register(rn), 0);
            let dest = code.output(if flags { rd } else { sp_register(rd) }, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        } else if word & 0x1f200000 == 0x0b000000 {
            if (word >> 22) & 3 == 3 || (sf == 0 && (word >> 10) & 63 >= 32) {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        } else if word & 0x1f200000 == 0x0b200000 {
            if (word >> 10) & 7 > 4 || word & (3 << 22) != 0 {
                break;
            }
            let lhs = code.read(sp_register(rn), 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(
                if flags { rd } else { sp_register(rd) },
                (1 << lhs) | (1 << rhs),
            );
            // The reference accepts UXTX/SXTX in a W operation. Its low 32
            // bits are identical to UXTW/SXTW; use the valid host W encoding.
            let word = if sf == 0 && (word >> 13) & 3 == 3 {
                word & !(1 << 13)
            } else {
                word
            };
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        } else if word & 0x1f000000 == 0x0a000000 {
            if sf == 0 && (word >> 10) & 63 >= 32 {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if (word >> 29) & 3 == 3 {
                code.flags_written();
            }
        } else if word & 0x1f800000 == 0x12000000 {
            if !logical_mask(
                (word >> 22) & 1,
                (word >> 10) & 63,
                (word >> 16) & 63,
                sf != 0,
            ) {
                break;
            }
            let lhs = code.read(rn, 0);
            let writes_flags = (word >> 29) & 3 == 3;
            let dest = code.output(if writes_flags { rd } else { sp_register(rd) }, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
            if writes_flags {
                code.flags_written();
            }
        } else if word & 0x1f800000 == 0x13000000 {
            let opc = (word >> 29) & 3;
            let bits = if sf == 0 { 32 } else { 64 };
            if opc == 3
                || (word >> 22) & 1 != sf
                || (word >> 16) & 63 >= bits
                || (word >> 10) & 63 >= bits
            {
                break;
            }
            let lhs = code.read(rn, 0);
            if opc == 1 {
                code.read(rd, 1 << lhs);
            }
            let dest = code.output(rd, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
        } else if word & 0x1f800000 == 0x13800000 {
            if word & 0x60200000 != 0
                || (word >> 22) & 1 != sf
                || (sf == 0 && (word >> 10) & 63 >= 32)
            {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        } else if word & 0x1fe00800 == 0x1a800000 {
            if flags {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.flags_read();
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        } else if word & 0x1fe00410 == 0x1a400000 {
            if !flags {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = if word & (1 << 11) == 0 {
                code.read(rm, 1 << lhs)
            } else {
                rm
            };
            code.flags_read();
            code.words
                .push((word & !0x1f03e0) | (rhs << 16) | (lhs << 5));
            code.flags_written();
        } else if word & 0x1fe0fc00 == 0x1a000000 {
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.flags_read();
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
            if flags {
                code.flags_written();
            }
        } else if word & 0x1f000000 == 0x1b000000 {
            let kind = (word >> 21) & 7;
            let ra = (word >> 10) & 31;
            if word & 0x60000000 != 0
                || !(kind == 0
                    || (sf != 0 && matches!(kind, 1 | 5))
                    || (sf != 0 && word & (1 << 15) == 0 && ra == 31 && matches!(kind, 2 | 6)))
            {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let addend = code.read(ra, (1 << lhs) | (1 << rhs));
            let dest = code.output(rd, (1 << lhs) | (1 << rhs) | (1 << addend));
            code.words
                .push((word & !0x1f7fff) | (rhs << 16) | (addend << 10) | (lhs << 5) | dest);
        } else if word & 0x7fe0f000 == 0x1ac06000 || word & 0x7ff00000 == 0x11c00000 {
            let immediate = word & 0x7ff00000 == 0x11c00000;
            let lhs = code.read(rn, 0);
            let rhs = if immediate {
                0
            } else {
                code.read(rm, 1 << lhs)
            };
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            let mask = if immediate { 0x3ff } else { 0x1f03ff };
            code.words
                .push((word & !mask) | (if immediate { 0 } else { rhs << 16 }) | (lhs << 5) | dest);
        } else if word & 0x5fe00000 == 0x1ac00000 {
            if flags || !matches!((word >> 10) & 63, 2 | 3 | 8..=11) {
                break;
            }
            let lhs = code.read(rn, 0);
            let rhs = code.read(rm, 1 << lhs);
            let dest = code.output(rd, (1 << lhs) | (1 << rhs));
            code.words
                .push((word & !0x1f03ff) | (rhs << 16) | (lhs << 5) | dest);
        } else if word & 0x7fe00000 == 0x5ac00000 {
            let kind = (word >> 10) & 63;
            if rm != 0 || kind > 8 || (sf == 0 && kind == 3) {
                break;
            }
            let lhs = code.read(rn, 0);
            let dest = code.output(rd, 1 << lhs);
            code.words.push((word & !0x3ff) | (lhs << 5) | dest);
        } else if matches!(word, 0xd500401f | 0xd500403f | 0xd500405f) {
            code.flags_read();
            code.words.push(word);
            code.flags_written();
        } else if word & 0xffe07c10 == 0xba000400 || word & 0xffffbc1f == 0x3a00080d {
            let source = code.read(rn, 0);
            code.flags_read();
            code.words.push((word & !0x3e0) | (source << 5));
            code.flags_written();
        } else if word & 0xffffffe0 == 0xd53b4200 {
            let dest = code.output(rd, 0);
            code.flags_read();
            code.words.push(0xd53b4200 | dest);
        } else if word & 0xffffffe0 == 0xd51b4200 {
            let value = code.read(rd, 0);
            code.words.push(0xd51b4200 | value);
            code.flags_written();
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
        } else if matches!(word & 0xfffffc1f, 0xd61f0000 | 0xd63f0000 | 0xd65f0000) {
            let source = code.read(rn, 0);
            code.words.push(0xaa0003f1 | (source << 16)); // mov x17,target before BLR aliases LR
            if word & 0xfffffc1f == 0xd63f0000 {
                code.constant(30, pc.wrapping_add(4));
            }
            code.context = true;
            flow = Flow::Register;
            next = pc.wrapping_add(4);
            terminal = true;
        } else if word & 0x7e000000 == 0x34000000 || word & 0x7e000000 == 0x36000000 {
            let source = code.read(rd, 0);
            let test_bit = word & 0x7e000000 == 0x36000000;
            let taken = pc.wrapping_add(if test_bit {
                signed(((word >> 5) & 0x3fff) as u64, 14) << 2
            } else {
                signed(((word >> 5) & 0x7ffff) as u64, 19) << 2
            });
            next = pc.wrapping_add(4);
            let mask = if test_bit { 0x7ffff } else { 0xffffff };
            select_pc(&mut code, (word & !mask) | source, next, taken);
            flow = Flow::Choice(taken);
            terminal = true;
        } else if word & 0xff000010 == 0x54000000 {
            next = pc.wrapping_add(4);
            let taken = pc.wrapping_add(signed(((word >> 5) & 0x7ffff) as u64, 19) << 2);
            code.flags_read();
            select_pc(&mut code, word & !0xffffe0, next, taken);
            flow = Flow::Choice(taken);
            terminal = true;
        } else if mode & 8 != 0 {
            let Some(op) = crate::memory_ops::Operation::compile(memory, pc)? else {
                break;
            };
            let op = Box::new(op);
            memory_sites.push(code.memory(&op, count));
            memory_ops.push(op);
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
    let dynamic = matches!(flow, Flow::Choice(_) | Flow::Register);
    for site in &memory_sites {
        code.words[site.adjust] |= ((count - site.before) as u32) << 10;
    }
    let (body, mut traffic, context) = code.finish();
    let mut words = render(
        &body,
        (start, next),
        slot,
        count,
        mode & 7,
        flow,
        &memory_sites,
    );
    let fast_offset = words.len() * 4;
    let tail_offset;
    if memory_sites.is_empty() {
        words.push(0xd50324df);
        if context {
            words.push(0xaa0103f0);
        } // ctx=x1; ordinary C scalar entry
        words.extend_from_slice(&body);
        if dynamic {
            store(&mut words, 17, 16);
        }
        words.push(0xd65f03c0);
        tail_offset = words.len() * 4;
        words.extend_from_slice(&[0xd503245f, 0xaa0103f0]);
        words.extend_from_slice(&body);
        load(&mut words, 17, 16, slot as u32 * 8);
        words.push(0xd61f0220);
    } else {
        tail_offset = 0;
    }
    traffic.host_words = words.len() as u64;
    Ok(Some(Compiled {
        memory: (!memory_ops.is_empty()).then(|| Box::new(MemoryOps::Fused(memory_ops))),
        block: Block {
            code: Code::publish(&words)
                .map_err(|error| CpuFault::Host(format!("JIT code publication: {error}")))?,
            has_memory: !memory_sites.is_empty(),
            instructions: count,
            next_pc: next,
            syscall,
            traffic,
            fast_offset,
            tail_offset,
            context,
            flow,
        },
    }))
}

/// Thread-affine executable mapping. Never writable while callable; mappings
/// are released on eviction/worker drop. No Rust allocation becomes executable.
pub(super) struct Code {
    pointer: *mut libc::c_void,
    length: usize,
    _thread: PhantomData<Rc<()>>,
}
impl Code {
    pub(super) fn publish(words: &[u32]) -> std::io::Result<Self> {
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
    unsafe fn call_memory_block<M: CpuMemory>(
        &self,
        registers: *mut u64,
        frame: *mut MemoryFrame<M>,
    ) {
        let function: unsafe extern "C" fn(*mut u64, *mut MemoryFrame<M>) =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(registers, frame) };
    }
    pub(super) unsafe fn call_memory(&self, pointer: *mut u8, value: u64) -> u64 {
        // SAFETY: the decoder selects a single baseline LDR/STR with exactly
        // the checked width. Pointer and lease live only through this call.
        let function: unsafe extern "C" fn(*mut u8, u64) -> u64 =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(pointer, value) }
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
    unsafe fn call_context(&self, offset: usize, registers: &mut [u64; 31], frame: &mut Frame) {
        // SAFETY: published AAPCS64 entry, live frame and worker-owned mapping.
        let function: unsafe extern "C" fn(*mut u64, *mut Frame) =
            unsafe { std::mem::transmute(self.pointer.cast::<u8>().add(offset)) };
        unsafe {
            function(registers.as_mut_ptr(), frame);
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
            link_pcs: std::ptr::null(),
            sp: 0,
            nzcv: 0,
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
        let mut m = memory(&[0x14000004, 0, 0, 0, 0xd4000001]);
        let mut cpu = Cpu::new(0x1000, 0);
        let mut cache = Cache::default();
        cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        let source = cache.hot.unwrap();
        assert!(
            cache
                .execute(&mut cpu, &mut m, 64)
                .unwrap()
                .unwrap()
                .syscall
        );
        let target = cache.hot.unwrap();
        cpu.pc = 0x1000;
        let hit = cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        assert_eq!((hit.blocks, hit.instructions, hit.syscall), (2, 2, true));
        assert_ne!(cache.links[source.slot], 0);
        cache.remove(target.slot);
        assert_eq!(cache.links[source.slot], 0);
        assert!(cache.node(target).is_none());
        cpu.pc = 0x1000;
        let miss = cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        assert_eq!((miss.blocks, miss.syscall, cpu.pc), (1, false, 0x1010));
        assert!(
            cache
                .execute(&mut cpu, &mut m, 64)
                .unwrap()
                .unwrap()
                .syscall
        );
        let replacement = cache.hot.unwrap();
        assert_eq!(target.slot, replacement.slot);
        assert_ne!(target.generation, replacement.generation);
        cpu.pc = 0x1000;
        assert_eq!(
            cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap().blocks,
            2
        );
    }
    #[test]
    fn memory_edges_remain_metadata_only_and_reject_evicted_generations() {
        let mut m = memory(&[0x14000004, 0, 0, 0, 0xf9400020]);
        m.map(0x2000, PAGE_SIZE, trames_memory::Permissions::RW)
            .unwrap();
        m.write_array(0x2000, 99u64.to_le_bytes()).unwrap();
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(1, 0x2000);
        let mut cache = Cache::default();
        cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        let source = cache.hot.unwrap();
        cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        let target = cache.hot.unwrap();
        assert!(
            cache
                .node(target)
                .unwrap()
                .block
                .as_ref()
                .unwrap()
                .has_memory
        );
        assert_eq!(cache.node(source).unwrap().next, Some(target));
        assert_eq!(cache.links[source.slot], 0); // The fragment uses a different ABI.
        cache.remove(target.slot);
        assert!(cache.node(target).is_none());
        cpu.pc = 0x1000;
        let branch = cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        assert_eq!((branch.instructions, branch.blocks, cpu.pc), (1, 1, 0x1010));
        cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        let replacement = cache.hot.unwrap();
        assert_eq!(replacement.slot, target.slot);
        assert_ne!(replacement.generation, target.generation);
        assert_eq!((cpu.x(0), cpu.pc), (99, 0x1014));
        assert_eq!(cache.links[source.slot], 0);
    }
}
