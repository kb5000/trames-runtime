// SPDX-License-Identifier: GPL-3.0-or-later
//! Worker-private RX blocks and stable RW links. No guest code is patched.
use crate::{CompilationStats, LinkStats};
use std::{collections::BTreeMap, marker::PhantomData, rc::Rc, sync::atomic::Ordering};
use trames_engine::CpuFault;
use trames_interpreter::Cpu;
#[path = "compatibility.rs"]
mod compatibility;
use trames_memory::{CpuMemory, PAGE_SIZE};

#[path = "exclusive.rs"]
mod exclusive;
#[path = "mops.rs"]
mod mops;

type Identity = (u64, u64, u64);
type Key = (u64, u64, u8);
const BLOCK_LIMIT: u64 = 64;
const CACHE_LIMIT: usize = 128;
const NO_SLOT: u64 = CACHE_LIMIT as u64;
const CHAIN_ENTRY: usize = 16;
// Hardware-only entry preserves x19..x23 and initializes affine operands before
// its backedge marker. Scalar/SVC entry layout stays unchanged.
const DIRECT_CHAIN_ENTRY: usize = 44;

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
    fn instructions(&self) -> u64 {
        self.block.as_ref().map_or_else(
            || self.memory.as_deref().map_or(1, MemoryOps::instructions),
            |block| block.instructions,
        )
    }
    fn accepts(&self, pc: u64) -> bool {
        self.block.as_ref().is_some_and(|b| b.accepts(pc))
            || (self.block.is_none()
                && self.memory.is_some()
                && self.key.0.wrapping_add(self.instructions() * 4) == pc)
    }
}
struct Block {
    code: Code,
    has_memory: bool,
    has_vector: bool,
    has_hardware: bool,
    read_only_memory: bool,
    memory_width: usize,
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
    Boundary(crate::system_ops::Boundary),
    Window(Box<exclusive::Window>),
    Mops(mops::Plan),
}
impl MemoryOps {
    fn single(&self) -> Option<&crate::memory_ops::Operation> {
        match self {
            Self::Single(op) => Some(op),
            Self::Fused(_) | Self::Boundary(_) | Self::Window(_) | Self::Mops(_) => None,
        }
    }
    fn instructions(&self) -> u64 {
        match self {
            Self::Window(window) => window.instructions(),
            Self::Mops(plan) => plan.instructions(),
            _ => 1,
        }
    }
    fn host_words(&self) -> u64 {
        match self {
            Self::Single(op) => op.host_words(),
            Self::Fused(ops) => ops.iter().map(|op| op.host_words()).sum(),
            Self::Boundary(_) => 0,
            Self::Window(window) => window.host_words(),
            Self::Mops(plan) => plan.host_words(),
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
        self.code.pointer as usize
            + if self.has_hardware {
                DIRECT_CHAIN_ENTRY
            } else {
                CHAIN_ENTRY
            }
    }
    fn scalar_entry(&self) -> usize {
        self.code.pointer as usize + self.fast_offset
    }
}
pub(super) struct Executed {
    pub instructions: u64,
    pub blocks: u64,
    pub exit: Exit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Exit {
    Continue,
    Syscall,
    NativeCall,
    Yield,
    /// Existing entry guard observed changed code before any guest instruction.
    Retry,
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
    hits: u64,
    direct: DirectRegion,
    direct_hits: u64,
    pages: [OperandPage; 64],
    stable: bool,
    read_only: bool,
    width: usize,
    checked: Identity,
    fault: Option<CpuFault>,
    stats: crate::MemoryStats,
}
/// Only FP/SIMD entries carry this pointer; the 120-byte scalar/SVC frame and
/// existing memory-frame offsets remain unchanged.
#[repr(C)]
struct VectorFrame {
    frame: Frame,
}
const _: () = {
    assert!(std::mem::size_of::<VectorFrame>() == 120);
};
#[repr(C)]
struct Floating {
    guest_control: u64,
    guest_status: u64,
    host_control: u64,
    host_status: u64,
}
#[repr(C)]
struct MixedFrame<M> {
    memory: MemoryFrame<M>,
    floating: Floating,
}
const FLOATING: u32 = std::mem::offset_of!(MixedFrame<()>, floating) as u32;
/// A connected union of already exported pages, never an assertion about holes.
/// `last` is the final legal start offset for the block's widest memory operand.
#[repr(C)]
#[derive(Clone, Copy)]
struct DirectRegion {
    base: u64,
    last: u64,
    bias: usize,
}
impl DirectRegion {
    // Guest TBI-clean addresses are <2^56, so wrapping_sub(MAX) is always >0.
    const EMPTY: Self = Self {
        base: u64::MAX,
        last: 0,
        bias: 0,
    };
    fn admit(&mut self, page: &trames_memory::NativePage, read_only: bool, width: usize) {
        let pointer = if read_only {
            page.read
        } else if page.read == page.write {
            page.write
        } else {
            0
        };
        if pointer == 0 {
            return;
        }
        let bias = pointer.wrapping_sub(page.base as usize);
        let mut base = page.base;
        let mut end = base + PAGE_SIZE;
        if self.base != u64::MAX && self.bias == bias {
            let old_end = self.base + self.last + width as u64;
            if base <= old_end && self.base <= end {
                base = base.min(self.base);
                end = end.max(old_end);
                if end - base > 1024 * 1024 {
                    base = page.base;
                    end = base + PAGE_SIZE;
                }
            }
        }
        *self = Self {
            base,
            last: end - base - width as u64,
            bias,
        };
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
struct OperandPage {
    tag: u64,
    read: usize,
    write: usize,
    reserved: usize,
}
impl OperandPage {
    const EMPTY: Self = Self {
        tag: u64::MAX,
        read: 0,
        write: 0,
        reserved: 0,
    };
}
const _: () = {
    assert!(std::mem::offset_of!(MemoryFrame<()>, helper) == 120);
    assert!(std::mem::offset_of!(MemoryFrame<()>, registers) == 144);
    assert!(std::mem::offset_of!(MemoryFrame<()>, hits) == 152);
    assert!(std::mem::offset_of!(MemoryFrame<()>, direct) == 160);
    assert!(std::mem::offset_of!(MemoryFrame<()>, direct_hits) == 184);
    assert!(std::mem::offset_of!(MemoryFrame<()>, pages) == 192);
    assert!(std::mem::size_of::<DirectRegion>() == 24);
    assert!(std::mem::size_of::<OperandPage>() == 32);
};
struct MemorySite {
    adjust: usize,
    stop: usize,
    before: u64,
    fixups: Vec<(usize, usize)>,
}
unsafe extern "C" fn memory_access<M: CpuMemory, const HARDWARE: bool, const FP: bool>(
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
    if FP {
        // The emitted bridge restored host control/status before Rust entry.
        let floating =
            unsafe { &mut *std::ptr::addr_of_mut!((*pointer.cast::<MixedFrame<M>>()).floating) };
        cpu.fpsr |= floating.guest_status as u32;
    }
    cpu.pc = op.pc();
    cpu.sp = frame.frame.sp;
    // Any checked call can prepare COW/storage or replace CPU aliases. Discard
    // all earlier loans before reborrowing Memory; only this call's final export
    // survives. Stores also populate the read slot after actual write admission.
    if HARDWARE && (!frame.stable || op.exclusive.is_some()) {
        frame.pages.fill(OperandPage::EMPTY);
        frame.direct = DirectRegion::EMPTY;
    }
    let address = if HARDWARE {
        op.operand(cpu).0 & 0x00ff_ffff_ffff_ffff
    } else {
        0
    };
    let result = op.execute(cpu, memory);
    frame.frame.sp = cpu.sp;
    let next = match result {
        Ok(direct) => {
            frame.stats.instructions += 1;
            frame.stats.staged += u64::from(!direct);
            if memory.instruction_identity() == frame.checked {
                if HARDWARE
                    && op.opcode.is_some()
                    && op.size as u64 <= PAGE_SIZE - address % PAGE_SIZE
                {
                    // SAFETY: prior loans are gone; native execution performs
                    // only bounded scalar accesses until the next helper/return.
                    if let Some(page) = unsafe { memory.cpu_native_page(address, !op.load) } {
                        frame.direct.admit(&page, frame.read_only, frame.width);
                        frame.pages[(page.base / PAGE_SIZE) as usize & 63] = OperandPage {
                            tag: page.base,
                            read: page.read,
                            write: page.write,
                            reserved: 0,
                        };
                    }
                }
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
    if FP {
        let floating =
            unsafe { &mut *std::ptr::addr_of_mut!((*pointer.cast::<MixedFrame<M>>()).floating) };
        floating.guest_status = cpu.fpsr as u64;
        let (registers, vectors) = cpu.native_register_pointers();
        frame.registers = registers;
        frame.frame.link_pcs = vectors.cast();
    } else {
        frame.registers = cpu.native_register_pointers().0;
    }
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
            .is_none_or(|node| node.instructions() <= limit)
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
        let (block, memory_op) = if let Some(plan) = mops::Plan::compile(memory, pc, limit)? {
            (None, Some(Box::new(MemoryOps::Mops(plan))))
        } else if let Some(window) = exclusive::Window::compile(memory, pc, limit, mode)? {
            (None, Some(Box::new(MemoryOps::Window(Box::new(window)))))
        } else if let Some(compiled) = compile(memory, pc, limit, slot, mode)? {
            (Some(compiled.block), compiled.memory)
        } else {
            (
                None,
                if let Some(boundary) = crate::system_ops::Boundary::decode(
                    memory
                        .fetch_u32(pc)
                        .map_err(|error| CpuFault::Memory { pc, error })?,
                ) {
                    Some(Box::new(MemoryOps::Boundary(boundary)))
                } else {
                    crate::memory_ops::Operation::compile(memory, pc)?
                        .map(|op| Box::new(MemoryOps::Single(op)))
                },
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
            self.cold.compilation.address_reuses += block.traffic.address_reuses;
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
        let tail = if a.key.2 & !16 == 8
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
                            .call_scalar(block.fast_offset, cpu.native_register_pointers().0);
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
                if node.key.0 == pc && node.key.2 & !16 == 8 && self.tails[handle.slot] != 0 {
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
                                        cpu.native_register_pointers().0,
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
                                    exit: Exit::Syscall,
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
                exit: Exit::Continue,
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
        if epochs.is_some() && memory.cpu_native_available() {
            mode |= 16;
        }
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
                        && n.instructions() <= budget
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
                    && node.instructions() <= budget
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
                    exit: Exit::Continue,
                }));
            }
            if let Some(MemoryOps::Window(window)) =
                self.node(handle).and_then(|n| n.memory.as_deref())
            {
                let result = window.execute(cpu, memory, &mut frame);
                match result {
                    Ok(run) => {
                        self.cold.memory.instructions += run.accesses;
                        self.cold.memory.staged += u64::from(!run.direct);
                        self.cold.memory.exclusive_windows += u64::from(run.instructions > 1);
                        self.last = Some(handle);
                        self.links_stats.entries += 1;
                        return Ok(Some(Executed {
                            instructions: run.instructions,
                            blocks: 1,
                            exit: Exit::Continue,
                        }));
                    }
                    Err((retired, error)) => {
                        self.cold.fault_progress = (retired, u64::from(retired != 0));
                        return Err(error);
                    }
                }
            }
            if let Some(MemoryOps::Mops(plan)) = self.node(handle).and_then(|n| n.memory.as_deref())
            {
                match plan.execute(cpu, memory) {
                    Ok(run) => {
                        self.cold.memory.instructions += run.instructions;
                        self.cold.memory.staged += u64::from(!run.direct);
                        self.last = Some(handle);
                        self.links_stats.entries += 1;
                        return Ok(Some(Executed {
                            instructions: run.instructions,
                            blocks: 1,
                            exit: if run.yielding {
                                Exit::Yield
                            } else {
                                Exit::Continue
                            },
                        }));
                    }
                    Err((retired, error)) => {
                        self.cold.fault_progress = (retired, u64::from(retired != 0));
                        return Err(error);
                    }
                }
            }
            if let Some(MemoryOps::Boundary(boundary)) =
                self.node(handle).and_then(|n| n.memory.as_deref())
            {
                let boundary = *boundary;
                if boundary.native_call(cpu) {
                    self.last = Some(handle);
                    return Ok(Some(Executed {
                        instructions: 0,
                        blocks: 0,
                        exit: Exit::NativeCall,
                    }));
                }
                self.cold.fault_progress = (0, 0);
                return Err(boundary.fault(pc));
            }
            return Ok(None);
        };
        // SAFETY: slots/code remain owned and unchanged until this call returns.
        // Epoch references are borrowed from this live Memory/View. Native jumps
        // use only installed same-page entries, never a guest-provided pointer.
        if block.has_memory {
            if block.has_vector {
                if self.node(handle).unwrap().memory.is_some() {
                    return self.execute_mixed_block(cpu, memory, budget, handle, frame);
                }
                return self.execute_vector_block(cpu, budget, handle, frame);
            }
            return self.execute_memory_block(cpu, memory, budget, handle, frame);
        }
        if block.syscall || self.links[handle.slot] == 0 {
            // Never pay chain-frame stores for an entry that cannot chain.
            unsafe {
                if block.context {
                    block.code.call_context(
                        block.fast_offset,
                        cpu.native_register_pointers().0,
                        &mut frame,
                    );
                } else {
                    block
                        .code
                        .call_scalar(block.fast_offset, cpu.native_register_pointers().0);
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
                block
                    .code
                    .call(cpu.native_register_pointers().0, &mut frame);
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
            return Ok(Some(Executed {
                instructions: 0,
                blocks: 0,
                exit: Exit::Retry,
            }));
        }
        Ok(Some(Executed {
            instructions: budget - frame.remaining,
            blocks: frame.blocks,
            exit: if frame.syscall != 0 {
                Exit::Syscall
            } else {
                Exit::Continue
            },
        }))
    }
    #[inline(never)]
    fn execute_vector_block(
        &mut self,
        cpu: &mut Cpu,
        budget: u64,
        handle: Handle,
        frame: Frame,
    ) -> Result<Option<Executed>, CpuFault> {
        let block = self.node(handle).unwrap().block.as_ref().unwrap();
        // Existing host control/status scope, once per native entry, never per
        // instruction. No Rust/provider callback runs in this native FP block.
        let scope = trames_host_compute::Scope::new(cpu.fpcr, cpu.fpsr);
        let (registers, vectors) = cpu.native_register_pointers();
        let mut vector_frame = VectorFrame { frame };
        vector_frame.frame.link_pcs = vectors.cast();
        unsafe {
            block.code.call_vectors(registers, &mut vector_frame);
        }
        cpu.fpsr |= trames_host_compute::status();
        drop(scope);
        self.links_stats.entries += 1;
        self.links_stats.linked_blocks += vector_frame.frame.blocks.saturating_sub(1);
        cpu.pc = vector_frame.frame.pc;
        cpu.sp = vector_frame.frame.sp;
        cpu.set_nzcv((vector_frame.frame.nzcv >> 28) as u32);
        if vector_frame.frame.last_slot < NO_SLOT {
            self.last = Some(self.handle(vector_frame.frame.last_slot as usize));
        }
        if vector_frame.frame.blocks == 0 {
            return Ok(Some(Executed {
                instructions: 0,
                blocks: 0,
                exit: Exit::Retry,
            }));
        }
        Ok(Some(Executed {
            instructions: budget - vector_frame.frame.remaining,
            blocks: vector_frame.frame.blocks,
            exit: if vector_frame.frame.syscall != 0 {
                Exit::Syscall
            } else {
                Exit::Continue
            },
        }))
    }
    #[inline]
    fn memory_frame<M: CpuMemory, const FP: bool>(
        &self,
        cpu: &mut Cpu,
        memory: &mut M,
        handle: Handle,
        mut frame: Frame,
    ) -> MemoryFrame<M> {
        let checked = self.node(handle).unwrap().checked;
        let block = self.node(handle).unwrap().block.as_ref().unwrap();
        let cpu_pointer = cpu as *mut Cpu;
        // Derive both reborrows from one raw parent, then suspend Rust CPU access
        // until native return. Every helper publishes a fresh register sub-borrow.
        let registers = if FP {
            let (registers, vectors) = unsafe { (*cpu_pointer).native_register_pointers() };
            frame.link_pcs = vectors.cast();
            registers
        } else {
            unsafe { (*cpu_pointer).native_register_pointers().0 }
        };
        MemoryFrame {
            frame,
            helper: if block.has_hardware {
                memory_access::<M, true, FP> as *const () as usize
            } else {
                memory_access::<M, false, FP> as *const () as usize
            },
            cpu: cpu_pointer,
            memory: memory as *mut _,
            registers,
            hits: 0,
            direct: DirectRegion::EMPTY,
            direct_hits: 0,
            pages: [OperandPage::EMPTY; 64],
            stable: memory.cpu_native_stable(),
            read_only: block.read_only_memory,
            width: block.memory_width,
            checked,
            fault: None,
            stats: crate::MemoryStats::default(),
        }
    }
    // Keep extra frame/control state out of ordinary scalar and memory entries.
    #[inline(never)]
    fn execute_memory_block<M: CpuMemory>(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut M,
        budget: u64,
        handle: Handle,
        frame: Frame,
    ) -> Result<Option<Executed>, CpuFault> {
        let mut fused = self.memory_frame::<M, false>(cpu, memory, handle, frame);
        self.run_memory_frame::<M>(budget, handle, &mut fused as *mut _)
    }
    #[inline(never)]
    fn execute_mixed_block<M: CpuMemory>(
        &mut self,
        cpu: &mut Cpu,
        memory: &mut M,
        budget: u64,
        handle: Handle,
        frame: Frame,
    ) -> Result<Option<Executed>, CpuFault> {
        let scope = trames_host_compute::Scope::new(cpu.fpcr, cpu.fpsr);
        let (host_control, host_status) = scope.saved_environment();
        let mut mixed = MixedFrame {
            memory: self.memory_frame::<M, true>(cpu, memory, handle, frame),
            floating: Floating {
                guest_control: 0,
                guest_status: 0,
                host_control,
                host_status,
            },
        };
        let result =
            self.run_memory_frame::<M>(budget, handle, (&mut mixed as *mut MixedFrame<M>).cast());
        cpu.fpsr |= trames_host_compute::status();
        drop(scope);
        result
    }
    #[inline]
    fn run_memory_frame<M: CpuMemory>(
        &mut self,
        budget: u64,
        handle: Handle,
        pointer: *mut MemoryFrame<M>,
    ) -> Result<Option<Executed>, CpuFault> {
        let block_length = self
            .node(handle)
            .unwrap()
            .block
            .as_ref()
            .unwrap()
            .instructions;
        // The mixed pointer derives from the whole allocation, before any
        // prefix reference. Its tail remains reachable by the typed FP helper.
        unsafe {
            self.node(handle)
                .unwrap()
                .block
                .as_ref()
                .unwrap()
                .code
                .call_memory_block((*pointer).registers, pointer)
        };
        let fused = unsafe { &mut *pointer };
        // Reborrow the CPU only after native return. Passing a fresh &mut Cpu
        // into this runner would invalidate the previously derived bank loans.
        let cpu = unsafe { &mut *fused.cpu };
        self.cold.memory.instructions += fused.stats.instructions + fused.hits + fused.direct_hits;
        self.cold.memory.hardware += fused.hits + fused.direct_hits;
        self.cold.memory.direct += fused.direct_hits;
        self.cold.memory.staged += fused.stats.staged;
        self.cold.memory.fused_entries += 1;
        self.cold.memory.fused_blocks += fused.frame.blocks;
        self.links_stats.entries += 1;
        self.links_stats.linked_blocks += fused.frame.blocks.saturating_sub(1);
        cpu.pc = fused.frame.pc;
        cpu.sp = fused.frame.sp;
        cpu.set_nzcv((fused.frame.nzcv >> 28) as u32);
        if let Some(error) = fused.fault.take() {
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
            return Ok(Some(Executed {
                instructions: 0,
                blocks: 0,
                exit: Exit::Retry,
            }));
        }
        Ok(Some(Executed {
            instructions: budget - fused.frame.remaining,
            blocks: fused.frame.blocks,
            exit: if fused.frame.syscall != 0 {
                Exit::Syscall
            } else {
                Exit::Continue
            },
        }))
    }
}

#[derive(Clone, Copy)]
struct Binding {
    guest: u32,
    dirty: bool,
    used: u32,
}

#[derive(Clone)]
struct Vectors {
    bindings: [Option<Binding>; 24],
    hosts: [u8; 32],
    clock: u32,
    used: bool,
}
impl Vectors {
    fn new() -> Self {
        Self {
            bindings: [None; 24],
            hosts: [u8::MAX; 32],
            clock: 0,
            used: false,
        }
    }
    const fn host(slot: usize) -> u32 {
        if slot < 16 {
            slot as u32 + 16
        } else {
            slot as u32 - 16
        }
    }
    const fn slot(host: u32) -> usize {
        if host >= 16 {
            host as usize - 16
        } else {
            host as usize + 16
        }
    }
    fn bind(
        &mut self,
        words: &mut Vec<u32>,
        traffic: &mut CompilationStats,
        guest: u32,
        avoid: u32,
        read: bool,
    ) -> u32 {
        self.bind_in(words, traffic, guest, avoid, read, false)
    }
    fn bind_in(
        &mut self,
        words: &mut Vec<u32>,
        traffic: &mut CompilationStats,
        guest: u32,
        avoid: u32,
        read: bool,
        low: bool,
    ) -> u32 {
        self.used = true;
        self.clock += 1;
        let old = self.hosts[guest as usize];
        let relocate = old != u8::MAX && low && Self::host(old as usize) >= 16;
        let previous = if relocate {
            self.bindings[old as usize].take()
        } else {
            None
        };
        let slot = if old != u8::MAX && !relocate {
            old as usize
        } else {
            let eligible =
                |i: usize| (!low || Self::host(i) < 16) && avoid & (1 << Self::host(i)) == 0;
            let slot = self
                .bindings
                .iter()
                .enumerate()
                .find_map(|(i, b)| (b.is_none() && eligible(i)).then_some(i))
                .unwrap_or_else(|| {
                    self.bindings
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| eligible(*i))
                        .min_by_key(|(_, b)| b.unwrap().used)
                        .unwrap()
                        .0
                });
            if let Some(binding) = self.bindings[slot] {
                if binding.dirty {
                    load(words, 17, 16, 96);
                    words.push(0x3d800000 | (binding.guest << 10) | (17 << 5) | Self::host(slot));
                    traffic.register_stores += 1;
                }
                self.hosts[binding.guest as usize] = u8::MAX;
            }
            if read {
                if previous.is_some() {
                    let src = Self::host(old as usize);
                    let dest = Self::host(slot);
                    words.push(0x4ea01c00 | (src << 16) | (src << 5) | dest);
                } else {
                    load(words, 17, 16, 96);
                    words.push(0x3dc00000 | (guest << 10) | (17 << 5) | Self::host(slot));
                    traffic.register_loads += 1;
                }
            }
            self.hosts[guest as usize] = slot as u8;
            self.bindings[slot] = Some(Binding {
                guest,
                dirty: previous.is_some_and(|b| b.dirty),
                used: self.clock,
            });
            slot
        };
        let b = self.bindings[slot].as_mut().unwrap();
        b.dirty |= !read;
        b.used = self.clock;
        Self::host(slot)
    }
    fn reserve(
        &mut self,
        words: &mut Vec<u32>,
        traffic: &mut CompilationStats,
        guest: u32,
        avoid: u32,
    ) -> u32 {
        let old = self.hosts[guest as usize];
        let dirty = old != u8::MAX && self.bindings[old as usize].unwrap().dirty;
        let host = self.bind(words, traffic, guest, avoid, false);
        self.bindings[self.hosts[guest as usize] as usize]
            .as_mut()
            .unwrap()
            .dirty = dirty;
        host
    }
    fn group(
        &mut self,
        words: &mut Vec<u32>,
        traffic: &mut CompilationStats,
        guest: usize,
        count: usize,
        read: bool,
    ) -> u32 {
        self.used = true;
        self.clock += 1;
        let aligned = self.hosts[guest];
        let start = if aligned != u8::MAX
            && aligned as usize + count <= 24
            && Self::host(aligned as usize + count - 1)
                == Self::host(aligned as usize) + count as u32 - 1
            && (0..count).all(|i| self.hosts[(guest + i) & 31] as usize == aligned as usize + i)
        {
            aligned as usize
        } else {
            (0..=24 - count)
                .filter(|start| {
                    Self::host(*start + count - 1) == Self::host(*start) + count as u32 - 1
                })
                .min_by_key(|start| {
                    let mut cost = 0;
                    let mut age = 0u64;
                    for i in 0..count {
                        if let Some(b) = self.bindings[start + i] {
                            if b.guest as usize != (guest + i) & 31 {
                                cost += 1 + 2 * u32::from(b.dirty);
                            }
                            age += b.used as u64;
                        } else {
                            cost += 1;
                        }
                    }
                    (cost, age)
                })
                .unwrap()
        };
        // Spill every displaced dirty value before loading any relocated member,
        // including cycles and guest lists wrapping V31 -> V0. An already packed
        // group emits no moves, loads or stores here on subsequent instructions.
        let mut pointer = false;
        for slot in 0..24 {
            let Some(b) = self.bindings[slot] else {
                continue;
            };
            let member = (b.guest as usize + 32 - guest) & 31;
            let displaced = (slot >= start
                && slot < start + count
                && b.guest as usize != (guest + slot - start) & 31)
                || (member < count && slot != start + member);
            if displaced {
                if b.dirty {
                    if !pointer {
                        load(words, 17, 16, 96);
                        pointer = true;
                    }
                    words.push(0x3d800000 | (b.guest << 10) | (17 << 5) | Self::host(slot));
                    traffic.register_stores += 1;
                }
                self.hosts[b.guest as usize] = u8::MAX;
                self.bindings[slot] = None;
            }
        }
        for i in 0..count {
            let slot = start + i;
            let reg = (guest + i) & 31;
            if self.bindings[slot].is_none() {
                if read {
                    if !pointer {
                        load(words, 17, 16, 96);
                        pointer = true;
                    }
                    words.push(0x3dc00000 | ((reg as u32) << 10) | (17 << 5) | Self::host(slot));
                    traffic.register_loads += 1;
                }
                self.bindings[slot] = Some(Binding {
                    guest: reg as u32,
                    dirty: false,
                    used: self.clock,
                });
                self.hosts[reg] = slot as u8;
            }
            self.bindings[slot].as_mut().unwrap().used = self.clock;
        }
        Self::host(start)
    }
    fn reload(&self, words: &mut Vec<u32>, traffic: &mut CompilationStats) {
        if self.bindings.iter().any(Option::is_some) {
            load(words, 17, 16, 96);
        }
        for (slot, b) in self.bindings.iter().enumerate() {
            if let Some(b) = b {
                words.push(0x3dc00000 | (b.guest << 10) | (17 << 5) | Self::host(slot));
                traffic.register_loads += 1;
            }
        }
    }
    fn flush(&mut self, words: &mut Vec<u32>, traffic: &mut CompilationStats) {
        if self.bindings.iter().flatten().any(|b| b.dirty) {
            load(words, 11, 16, 96);
        }
        for (slot, b) in self.bindings.iter().enumerate() {
            if let Some(b) = b.filter(|b| b.dirty) {
                words.push(0x3d800000 | (b.guest << 10) | (11 << 5) | Self::host(slot));
                traffic.register_stores += 1;
            }
        }
        self.bindings.fill(None);
        self.hosts.fill(u8::MAX);
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct OperandKey {
    address: crate::memory_ops::Address,
    base: usize,
    version: u32,
    index_version: u32,
}
impl OperandKey {
    fn loop_invariant(self, versions: &[u32; 33]) -> bool {
        if matches!(self.address, crate::memory_ops::Address::Literal(_)) {
            return true;
        }
        self.version == 0
            && self.index_version == 0
            && versions[sp_register(self.base as u32) as usize] == 0
            && match self.address {
                crate::memory_ops::Address::Register { reg, .. } => versions[reg] == 0,
                _ => true,
            }
    }
}
#[derive(Clone, Copy)]
struct LoopOperand {
    key: OperandKey,
    width: usize,
    branch: usize,
    normal: usize,
}
/// Compile-time allocation only. Between helpers, x0 holds the register-frame
/// argument; x1-x13 are caller-saved and x14/x15/x16 hold count/budget/context.
/// Scalar bodies use no host stack or FP/SIMD state. Memory calls balance the
/// host stack/LR and obey AAPCS64; no live guest vector binding crosses a helper.
/// Host x18/TLS and callee-saved state remain preserved on return.
/// Bindings do not survive block exit, so worker/task migration needs no flush.
#[derive(Clone)]
struct Assembler {
    words: Vec<u32>,
    bindings: [Option<Binding>; 13],
    hosts: [u8; 33],
    context: bool,
    flags_live: bool,
    flags_dirty: bool,
    clock: u32,
    traffic: CompilationStats,
    direct: bool,
    versions: [u32; 33],
    operand: Option<(OperandKey, usize)>,
    first_operand: Option<LoopOperand>,
    vectors: Vectors,
    floating: bool,
    monitor: bool,
    window_spill: bool,
    preloads: u64,
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
            direct: false,
            versions: [0; 33],
            operand: None,
            first_operand: None,
            vectors: Vectors::new(),
            floating: false,
            monitor: false,
            window_spill: false,
            preloads: 0,
        }
    }
    fn store(&mut self, slot: usize, binding: Binding) {
        if binding.dirty {
            self.window_spill |= self.monitor;
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
                .enumerate()
                .find_map(|(i, b)| (b.is_none() && avoid & (1 << (i + 1)) == 0).then_some(i))
                .unwrap_or_else(|| {
                    self.bindings
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| avoid & (1 << (i + 1)) == 0)
                        .min_by_key(|(_, b)| b.expect("occupied register").used)
                        .expect("native operand bindings fit the caller-saved bank")
                        .0
                });
            if let Some(binding) = self.bindings[slot] {
                self.store(slot, binding);
                self.hosts[binding.guest as usize] = u8::MAX;
            }
            if read {
                if self.monitor {
                    self.preloads |= 1 << guest;
                    self.window_spill = true;
                }
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
    fn scratch(&mut self, avoid: u32) -> u32 {
        let slot = (0..13)
            .filter(|slot| avoid & (1 << (slot + 1)) == 0)
            .min_by_key(|&slot| self.bindings[slot].map_or(0, |b| b.used + 1))
            .expect("caller-saved scratch register");
        if let Some(binding) = self.bindings[slot].take() {
            self.store(slot, binding);
            self.hosts[binding.guest as usize] = u8::MAX;
        }
        slot as u32 + 1
    }
    fn output(&mut self, guest: u32, avoid: u32) -> u32 {
        if guest != 31 {
            self.versions[guest as usize] += 1;
        }
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
            if self.monitor {
                self.preloads |= 1 << 63;
                self.window_spill = true;
            }
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
        // x17 may already contain a selected dynamic guest PC. Vector stores
        // use x11 only after integer bindings/NZCV have been published.
        self.vectors.flush(&mut self.words, &mut self.traffic);
        self.bindings.fill(None);
        self.hosts.fill(u8::MAX);
        self.flags_live = false;
        self.flags_dirty = false;
        self.operand = None;
    }
    fn vector(&mut self, word: u32, op: crate::vector_ops::Operation) {
        use crate::vector_ops::Form;
        self.context = true;
        let rd = word & 31;
        let rn = (word >> 5) & 31;
        let rm = (word >> 16) & 31;
        let ra = (word >> 10) & 31;
        let indexed_m = if let Form::Indexed { low, .. } = op.form {
            let guest = if low { rm & 15 } else { rm };
            Some(
                self.vectors
                    .bind_in(&mut self.words, &mut self.traffic, guest, 0, true, low),
            )
        } else {
            None
        };
        let n = match op.form {
            Form::Immediate | Form::ModifiedImmediate { .. } => 31,
            Form::Table { registers, .. } => self.vectors.group(
                &mut self.words,
                &mut self.traffic,
                rn as usize,
                registers,
                true,
            ),
            Form::FromGpr { .. } => self.read(rn, 0),
            _ => self.vectors.bind(
                &mut self.words,
                &mut self.traffic,
                rn,
                indexed_m.map_or(0, |m| 1 << m),
                true,
            ),
        };
        let n_mask = if matches!(
            op.form,
            Form::Immediate | Form::ModifiedImmediate { .. } | Form::FromGpr { .. }
        ) {
            0
        } else {
            1 << n
        };
        let table_mask = if let Form::Table { registers, .. } = op.form {
            ((1u32 << registers) - 1) << n
        } else {
            0
        };
        let m = match op.form {
            Form::Indexed { .. } => indexed_m.unwrap(),
            Form::Binary { .. }
            | Form::Table { .. }
            | Form::Ternary
            | Form::Select
            | Form::Compare { zero: false, .. } => self.vectors.bind(
                &mut self.words,
                &mut self.traffic,
                rm,
                (1 << n) | table_mask,
                true,
            ),
            _ => 31,
        };
        let m_mask = if matches!(
            op.form,
            Form::Binary { .. }
                | Form::Indexed { .. }
                | Form::Table { .. }
                | Form::Ternary
                | Form::Select
                | Form::Compare { zero: false, .. }
        ) {
            1 << m
        } else {
            0
        };
        let a = if matches!(op.form, Form::Ternary) {
            self.vectors.bind(
                &mut self.words,
                &mut self.traffic,
                ra,
                n_mask | m_mask,
                true,
            )
        } else {
            31
        };
        let a_mask = if matches!(op.form, Form::Ternary) {
            1 << a
        } else {
            0
        };
        if matches!(
            op.form,
            Form::Indexed {
                accumulate: true,
                ..
            } | Form::Binary { accumulate: true }
                | Form::FromGpr { merge: true }
                | Form::MergeUnary
                | Form::ModifiedImmediate { merge: true }
                | Form::Table { merge: true, .. }
        ) {
            self.vectors.bind(
                &mut self.words,
                &mut self.traffic,
                rd,
                n_mask | m_mask | a_mask | table_mask,
                true,
            );
        }
        if matches!(
            op.form,
            Form::Select
                | Form::Compare {
                    conditional: true,
                    ..
                }
        ) {
            self.flags_read();
        }
        let dest = match op.form {
            Form::Compare { .. } => rd,
            Form::ToGpr | Form::ToGprFlags => self.output(rd, 0),
            _ => self.vectors.bind(
                &mut self.words,
                &mut self.traffic,
                rd,
                n_mask | m_mask | a_mask | table_mask,
                false,
            ),
        };
        let emitted = match op.form {
            Form::Immediate | Form::ModifiedImmediate { .. } => (word & !31) | dest,
            Form::Unary
            | Form::MergeUnary
            | Form::ToGpr
            | Form::ToGprFlags
            | Form::FromGpr { .. } => (word & !0x3ff) | (n << 5) | dest,
            Form::Binary { .. } | Form::Table { .. } | Form::Select => {
                (word & !0x1f03ff) | (m << 16) | (n << 5) | dest
            }
            Form::Indexed { low, .. } => {
                (word & !(if low { 0x0f03ff } else { 0x1f03ff })) | (m << 16) | (n << 5) | dest
            }
            Form::Ternary => (word & !0x1f7fff) | (m << 16) | (a << 10) | (n << 5) | dest,
            Form::Compare { zero, .. } => {
                (word & !0x1f03e0) | (if zero { 0 } else { m << 16 }) | (n << 5)
            }
        };
        self.words.push(emitted);
        if matches!(op.form, Form::Compare { .. } | Form::ToGprFlags) {
            self.flags_written();
        }
    }
    fn cpu_field(
        &mut self,
        rt: u32,
        register: trames_interpreter::NativeSystemRegister,
        write: bool,
        wide: bool,
    ) {
        self.cpu_field_at(rt, Cpu::native_system_offset(register), write, wide);
    }
    fn cpu_field_at(&mut self, rt: u32, offset: i64, write: bool, wide: bool) {
        let scale = if wide { 8 } else { 4 };
        let op = match (wide, write) {
            (true, false) => 0xf9400000,
            (true, true) => 0xf9000000,
            (false, false) => 0xb9400000,
            (false, true) => 0xb9000000,
        };
        if offset >= 0 && offset % scale == 0 && offset / scale < 4096 {
            self.words.push(op | (((offset / scale) as u32) << 10) | rt);
        } else if (-256..256).contains(&offset) {
            self.words
                .push((op & !0x01000000) | (((offset as u32) & 511) << 12) | rt);
        } else {
            constant(&mut self.words, 17, offset as u64);
            self.words.push(0x8b110011); // add x17,x0,x17, from whole-CPU provenance
            self.words.push(op | (17 << 5) | rt);
        }
    }
    fn system(&mut self, word: u32, op: crate::system_ops::Register) {
        use crate::system_ops::Register::*;
        use trames_interpreter::NativeSystemRegister as R;
        let rd = word & 31;
        match op {
            ClearExclusive => {
                self.cpu_field_at(31, Cpu::native_exclusive_size_offset(), true, true);
                self.words.push(word);
            }
            Constant(value) => self.constant(rd, value),
            Counter { synchronized } => {
                let dest = self.output(rd, 0);
                if synchronized {
                    self.words.push(0xd5033fdf);
                }
                self.words.push(0xd53be040 | dest);
            }
            Random => {
                let dest = self.output(rd, 0);
                self.words.push((word & !31) | dest);
                self.flags_written();
            }
            Read(R::Tls | R::Tls2) => {
                if let Read(reg) = op {
                    let dest = self.output(rd, 0);
                    self.cpu_field(dest, reg, false, true);
                }
            }
            Write(R::Tls | R::Tls2) => {
                if let Write(reg) = op {
                    let src = self.read(rd, 0);
                    self.cpu_field(src, reg, true, true);
                }
            }
            Read(R::Fpcr) => {
                let dest = self.output(rd, 0);
                self.cpu_field(dest, R::Fpcr, false, false);
            }
            Read(R::Fpsr) | Write(R::Fpcr | R::Fpsr) => {
                // These are actual operands of the virtual system instruction,
                // not a hot capability probe. Scratch reservation is cold.
                for slot in [9, 10] {
                    if let Some(binding) = self.bindings[slot].take() {
                        self.store(slot, binding);
                        self.hosts[binding.guest as usize] = u8::MAX;
                    }
                }
                if matches!(op, Read(R::Fpsr)) {
                    let dest = self.output(rd, (1 << 10) | (1 << 11));
                    self.cpu_field(10, R::Fpsr, false, false);
                    self.words.push(0xd53b442b);
                    constant(&mut self.words, 17, 0x0800009f);
                    self.words.extend_from_slice(&[0x0a11016b, 0x2a0b014a]);
                    self.cpu_field(10, R::Fpsr, true, false);
                    if dest != 31 {
                        self.words.push(0x2a0a03e0 | dest);
                    }
                } else {
                    let Write(reg) = op else { unreachable!() };
                    let src = self.read(rd, (1 << 10) | (1 << 11));
                    constant(
                        &mut self.words,
                        10,
                        if matches!(reg, R::Fpcr) {
                            0x07c80000
                        } else {
                            0x0800009f
                        },
                    );
                    self.words.push(0x0a0a000b | (src << 5)); // and w11,wSrc,w10
                    self.cpu_field(11, reg, true, false);
                    self.words.push(if matches!(reg, R::Fpcr) {
                        0xd51b440b
                    } else {
                        0xd51b442b
                    });
                }
            }
        }
    }
    fn memory(&mut self, op: &crate::memory_ops::Operation, before: u64) -> MemorySite {
        self.flush();
        self.context = true;
        if self.floating {
            self.words.extend_from_slice(&[0xd53b440a, 0xd53b442b]);
            store(&mut self.words, 10, FLOATING);
            store(&mut self.words, 11, FLOATING + 8);
            load(&mut self.words, 10, 16, FLOATING + 16);
            load(&mut self.words, 11, 16, FLOATING + 24);
            self.words.extend_from_slice(&[0xd51b440a, 0xd51b442b]);
        }
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
        if self.floating {
            load(&mut self.words, 10, 16, FLOATING);
            load(&mut self.words, 11, 16, FLOATING + 8);
            self.words.extend_from_slice(&[0xd51b440a, 0xd51b442b]);
        }
        if self.direct {
            load(&mut self.words, 19, 16, 160);
            load(&mut self.words, 20, 16, 168);
            load(&mut self.words, 21, 16, 176);
            self.words.push(0xaa1f03f7); // x23=0: a helper ends address reuse
        }
        let stop = self.words.len();
        self.words.push(0xb4000011); // cbz x17: precise fault/code-change exit
        MemorySite {
            adjust,
            stop,
            before,
            fixups: Vec::new(),
        }
    }
    fn hardware_memory(&mut self, op: &crate::memory_ops::Operation, before: u64) -> MemorySite {
        use crate::memory_ops::{Address, Atomic};
        let cas_pair = matches!(op.atomic, Some(Atomic::Cas { pair: true, .. }));
        let scratch: u32 = (1 << 10)
            | (1 << 11)
            | (1 << 12)
            | (1 << 13)
            | if cas_pair { (1 << 6) | (1 << 7) } else { 0 };
        for slot in (0..13).filter(|slot| scratch & (1 << (slot + 1)) != 0) {
            if let Some(binding) = self.bindings[slot].take() {
                self.store(slot, binding);
                self.hosts[binding.guest as usize] = u8::MAX;
            }
        }
        self.context = true;
        let address_key = match op.address {
            Address::Pre(offset) => Address::Offset(offset),
            Address::Post(_) | Address::PostRegister(_) => Address::Offset(0),
            other => other,
        };
        let key = match address_key {
            Address::Literal(_) => Some(OperandKey {
                address: address_key,
                base: 0,
                version: 0,
                index_version: 0,
            }),
            _ => Some(OperandKey {
                address: address_key,
                base: op.rn,
                version: self.versions[op.base_register() as usize],
                index_version: if let Address::Register { reg, .. } = address_key {
                    self.versions[reg]
                } else {
                    0
                },
            }),
        };
        let reuse = key.is_some_and(|key| {
            self.operand
                .is_some_and(|(old, size)| old == key && size >= op.size)
        });
        let base = if matches!(op.address, Address::Literal(_)) {
            31
        } else {
            self.read(op.base_register(), scratch)
        };
        let vector_target = if op.vector {
            Some(if let Some(group) = op.structure {
                self.vectors.group(
                    &mut self.words,
                    &mut self.traffic,
                    op.rt,
                    group.registers,
                    !op.load || group.preserve,
                )
            } else if op.load {
                self.vectors
                    .reserve(&mut self.words, &mut self.traffic, op.rt as u32, 0)
            } else {
                self.vectors
                    .bind(&mut self.words, &mut self.traffic, op.rt as u32, 0, true)
            })
        } else {
            None
        };
        let vector_second = if op.vector {
            op.second.map(|reg| {
                if op.load {
                    self.vectors.reserve(
                        &mut self.words,
                        &mut self.traffic,
                        reg as u32,
                        1 << vector_target.unwrap(),
                    )
                } else {
                    self.vectors.bind(
                        &mut self.words,
                        &mut self.traffic,
                        reg as u32,
                        1 << vector_target.unwrap(),
                        true,
                    )
                }
            })
        } else {
            None
        };
        let source = if op.load || op.vector {
            31
        } else {
            self.read(
                match op.atomic {
                    Some(Atomic::Rmw { source }) => source as u32,
                    _ => op.rt as u32,
                },
                scratch | (1 << base),
            )
        };
        let source2 = if !op.load && !op.vector {
            op.second
                .or(cas_pair.then_some(op.rt + 1))
                .map(|reg| self.read(reg as u32, scratch | (1 << base) | (1 << source)))
        } else {
            None
        };
        let index = if let Address::Register { reg, .. } | Address::PostRegister(reg) = op.address {
            self.read(reg as u32, scratch | (1 << base) | (1 << source))
        } else {
            31
        };
        let compare = if let Some(Atomic::Cas { compare, .. }) = op.atomic {
            Some(self.read(
                compare as u32,
                scratch | (1 << base) | (1 << source) | source2.map_or(0, |r| 1 << r),
            ))
        } else {
            None
        };
        let compare2 = if let Some(Atomic::Cas {
            compare: reg,
            pair: true,
        }) = op.atomic
        {
            Some(self.read(
                (reg + 1) as u32,
                scratch
                    | (1 << base)
                    | (1 << source)
                    | source2.map_or(0, |r| 1 << r)
                    | compare.map_or(0, |r| 1 << r),
            ))
        } else {
            None
        };
        let prior = self.clone();
        let prior_stores = self.traffic.register_stores;
        // All routes, including a reused address, publish the same precise NZCV
        // recovery state before any comparison or possibly faulting instruction.
        if self.flags_live {
            self.words.push(0xd53b420c);
        }
        let mut reused_jump = None;
        let mut normal = None;
        let loop_candidate = before == 0 && self.first_operand.is_none();
        if reuse || loop_candidate {
            self.traffic.address_reuses += u64::from(reuse);
            normal = Some(self.words.len());
            // The first site's proof is enabled only after cold whole-block
            // dataflow and the actual same-block backedge have been verified.
            self.words.push(if reuse { 0xb4000017 } else { 0xb400001f });
            self.words.push(0xaa1603f1); // x17 = retained protected address
            self.words.push(0x9102e20b); // x11 = &direct_hits (frame+184)
            reused_jump = Some(self.words.len());
            self.words.push(0x14000000);
        }
        let normal_start = self.words.len();
        if let Some(at) = normal {
            branch(&mut self.words, at, normal_start);
            if loop_candidate {
                self.first_operand = key.map(|key| LoopOperand {
                    key,
                    width: op.size,
                    branch: at,
                    normal: normal_start,
                });
            }
        }
        self.words.push(0xaa1f03f7); // no proof survives a non-reused access
        match op.address {
            Address::CacheLine => self.words.push(0x927ae400 | (base << 5) | 17),
            Address::Literal(address) => constant(&mut self.words, 17, address),
            Address::Register { option, shift, .. } => self.words.push(
                0x8b200000 | (index << 16) | (option << 13) | (shift << 10) | (base << 5) | 17,
            ),
            Address::Offset(offset) | Address::Pre(offset) => {
                constant(&mut self.words, 10, offset);
                self.words.push(0x8b0a0000 | (base << 5) | 17);
            }
            Address::Post(_) | Address::PostRegister(_) => {
                self.words.push(0xaa0003f1 | (base << 16))
            }
            Address::Pointer { offset, mode } => {
                self.words.push(0xd340bc00 | (base << 5) | 17);
                if mode != 1 && offset != 0 {
                    constant(&mut self.words, 10, offset);
                    self.words.push(0x8b0a0231);
                }
            }
        }
        // Shared guest TBI, followed by the existing one-page custody bound.
        self.words.push(0xd3400000 | (55 << 10) | (17 << 5) | 17);
        // The native LDAR/STLR itself enforces the host's alignment rules; no
        // software preflight or stricter guest-bug emulation on the hot path.
        self.words.push(0xd3400000 | (11 << 10) | (17 << 5) | 10);
        self.words
            .push(0xf100001f | (((4096 - op.size) as u32) << 10) | (10 << 5));
        let mut misses = vec![self.words.len()];
        self.words.push(0x54000008);
        self.words.push(0xcb13022a); // x10 = guest address - direct base
        self.words.push(0xeb14015f); // cmp offset,last legal start
        let page_jump = self.words.len();
        self.words.push(0x54000008);
        self.words.push(0x8b150231); // x17 = guest address + direct bias
        self.words.push(0xaa1103f6); // retained address x22
        self.words.push(0xd2800037); // proof x23=1 (mixed blocks require RW admission)
        self.words.push(0x9102e20b); // &direct_hits
        let direct_jump = self.words.len();
        self.words.push(0x14000000);
        let page_start = self.words.len();
        branch(&mut self.words, page_jump, page_start);
        self.words.push(0xd3400000 | (11 << 10) | (17 << 5) | 10);
        self.words.push(0xcb0a022a);
        self.words
            .push(0xd3400000 | (12 << 16) | (17 << 10) | (17 << 5) | 11);
        self.words.push(0x8b0b160b);
        self.words.push(0x9103016b); // page cache now begins at frame+192
        load(&mut self.words, 13, 11, 0);
        self.words.push(0xeb0a01bf);
        misses.push(self.words.len());
        self.words.push(0x54000001);
        load(&mut self.words, 13, 11, if op.load { 8 } else { 16 });
        misses.push(self.words.len());
        self.words.push(0xb400000d);
        self.words.push(0xcb0a0231);
        self.words.push(0x8b1101b1);
        self.words.push(0x9102620b); // &page-cache hits (frame+152)
        let common = self.words.len();
        self.words[direct_jump] |= (common - direct_jump) as u32;
        if let Some(at) = reused_jump {
            self.words[at] |= (common - at) as u32;
        }
        if op.maintenance == Some(crate::memory_ops::Maintenance::TagZero) {
            // Only the existing tag-zero profile requires a 16-byte alignment
            // fault. Plain STP does not enforce MTE granule alignment itself.
            // Protected aliases preserve the guest's low granule bits.
            self.words.push(0xf2400e3f); // tst x17,#15
            misses.push(self.words.len());
            self.words.push(0x54000001);
        }
        if self.flags_live {
            self.words.push(0xd51b420c);
        }
        let output = match op.atomic {
            Some(Atomic::Cas { compare, .. }) => Some(compare),
            Some(Atomic::Rmw { .. } | Atomic::RmwPair) => Some(op.rt),
            None if op.load => Some(op.rt),
            _ => None,
        };
        let target = if op.vector {
            if op.load {
                if let Some(group) = op.structure {
                    for i in 0..group.registers {
                        self.vectors.bindings[Vectors::slot(vector_target.unwrap()) + i]
                            .as_mut()
                            .unwrap()
                            .dirty = true;
                    }
                } else {
                    self.vectors
                        .bind(&mut self.words, &mut self.traffic, op.rt as u32, 0, false);
                }
            }
            vector_target.unwrap()
        } else if let Some(reg) = output {
            self.output(reg as u32, scratch | (1 << base) | (1 << source))
        } else {
            source
        };
        let target2 = if op.vector {
            if op.load {
                if let Some(reg) = op.second {
                    self.vectors.bind(
                        &mut self.words,
                        &mut self.traffic,
                        reg as u32,
                        1 << target,
                        false,
                    );
                }
            }
            vector_second
        } else if matches!(op.atomic, Some(Atomic::RmwPair)) {
            Some(self.output(
                op.second.unwrap() as u32,
                scratch | (1 << base) | (1 << target) | (1 << source),
            ))
        } else if cas_pair {
            Some(self.output(
                (output.unwrap() + 1) as u32,
                scratch
                    | (1 << base)
                    | (1 << target)
                    | (1 << source)
                    | source2.map_or(0, |r| 1 << r),
            ))
        } else if op.load {
            op.second
                .map(|reg| self.output(reg as u32, scratch | (1 << base) | (1 << target)))
        } else {
            source2
        };
        if cas_pair {
            // Keep NZCV recovery in x12. CASP requires even consecutive register
            // pairs, so reserve x6/x7 and x10/x11 only for this cold-chosen form.
            self.words.push(0xaa0b03ed); // x13 keeps the selected hit counter
            for (dest, src) in [
                (10, compare.unwrap()),
                (11, compare2.unwrap()),
                (6, source),
                (7, source2.unwrap()),
            ] {
                self.words.push(0xaa0003e0 | (src << 16) | dest);
            }
        }
        let fault = self.words.len();
        if matches!(
            op.maintenance,
            Some(crate::memory_ops::Maintenance::Zero | crate::memory_ops::Maintenance::TagZero)
        ) {
            self.words
                .extend((0..op.size / 16).map(|i| 0xa9007e3f | ((i as u32 * 2) << 15)));
        } else {
            self.words.push(match op.atomic {
                Some(Atomic::RmwPair) => {
                    op.opcode.unwrap() | (target2.unwrap() << 16) | (17 << 5) | target
                }
                Some(Atomic::Rmw { .. }) => {
                    op.opcode.unwrap() | (source << 16) | (17 << 5) | target
                }
                Some(Atomic::Cas { pair: false, .. }) => {
                    op.opcode.unwrap() | (target << 16) | (17 << 5) | source
                }
                Some(Atomic::Cas { pair: true, .. }) => {
                    op.opcode.unwrap() | (10 << 16) | (17 << 5) | 6
                }
                None if target2.is_some() => {
                    (op.opcode.unwrap() & !0x7fff) | (target2.unwrap() << 10) | (17 << 5) | target
                }
                None => (op.opcode.expect("scalar operand") & !0x3ff) | (17 << 5) | target,
            });
        }
        if cas_pair {
            self.words.extend_from_slice(&[
                0xaa0a03e0 | target,
                0xaa0b03e0 | target2.unwrap(),
                0xaa0d03eb,
            ]);
        }
        if let Address::Pre(offset) | Address::Post(offset) = op.address {
            constant(&mut self.words, 10, offset);
            let target = self.output(sp_register(op.rn as u32), scratch | (1 << base));
            self.words.push(0x8b0a0000 | (base << 5) | target);
        }
        if let Address::PostRegister(_) = op.address {
            let target = self.output(
                sp_register(op.rn as u32),
                scratch | (1 << base) | (1 << index),
            );
            self.words
                .push(0x8b000000 | (index << 16) | (base << 5) | target);
        }
        if let Address::Pointer {
            offset,
            mode: 1 | 3,
        } = op.address
        {
            self.words.push(0xd340bc00 | (base << 5) | 13);
            constant(&mut self.words, 10, offset);
            let target = self.output(sp_register(op.rn as u32), scratch | (1 << base));
            self.words.push(0x8b0a01a0 | target);
        }
        load(&mut self.words, 10, 11, 0);
        self.words.push(0x9100054a);
        self.words.push(0xf900016a); // increment the selected non-atomic diagnostic
        let done = self.words.len();
        self.words.push(0x14000000);
        let slow_start = self.words.len();
        let mut slow = prior;
        slow.words.clear();
        if slow.flags_live {
            slow.words.push(0xd51b420c);
        }
        let mut site = slow.memory(op, before);
        site.adjust += slow_start;
        site.stop += slow_start;
        site.fixups = (0..if matches!(
            op.maintenance,
            Some(crate::memory_ops::Maintenance::Zero | crate::memory_ops::Maintenance::TagZero)
        ) {
            op.size / 16
        } else {
            1
        })
            .map(|i| (fault + i, slow_start))
            .collect();
        self.words.extend(slow.words);
        self.traffic.register_stores += slow.traffic.register_stores - prior_stores;
        for (slot, binding) in self.bindings.iter().enumerate() {
            if let Some(binding) = binding {
                if binding.guest == 32 {
                    load(&mut self.words, slot as u32 + 1, 16, 104);
                } else {
                    load(&mut self.words, slot as u32 + 1, 0, binding.guest * 8);
                }
            }
        }
        self.vectors.reload(&mut self.words, &mut self.traffic);
        if self.flags_live {
            load(&mut self.words, 12, 16, 112);
            self.words.push(0xd51b420c);
        }
        let end = self.words.len();
        self.words[done] |= (end - done) as u32;
        for at in misses {
            branch(&mut self.words, at, slow_start);
        }
        self.operand = key.map(|key| (key, op.size));
        site
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
fn native_return(words: &mut Vec<u32>, direct: bool) {
    if direct {
        words.extend_from_slice(&[0xf94013f7, 0xa9415bf5, 0xa8c353f3]);
    }
    words.push(0xd65f03c0);
}
fn exit(words: &mut Vec<u32>, pc: u64, slot: u64, syscall: bool, direct: bool) {
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
    native_return(words, direct);
}
fn render(
    body: &[u32],
    (start, next): (u64, u64),
    slot: usize,
    count: u64,
    mask: u8,
    flow: Flow,
    (memory, direct, vector_loop, vector_context): (&[MemorySite], bool, bool, bool),
) -> (Vec<u32>, usize) {
    let syscall = matches!(flow, Flow::Syscall);
    let dynamic = matches!(flow, Flow::Choice(_) | Flow::Register);
    let mut words = vec![0xd503245f];
    if direct {
        // One 48-byte AAPCS64 frame owns the affine-region/proof registers.
        words.extend_from_slice(&[0xa9bd53f3, 0xa9015bf5, 0xf90013f7]);
    }
    words.extend_from_slice(&[0xaa0103f0, 0xf940020f, 0xaa1f03ee]);
    if direct {
        load(&mut words, 19, 16, 160);
        load(&mut words, 20, 16, 168);
        load(&mut words, 21, 16, 176);
        words.push(0xaa1f03f7);
    }
    let chain = words.len();
    debug_assert_eq!(
        chain * 4,
        if direct {
            DIRECT_CHAIN_ENTRY
        } else {
            CHAIN_ENTRY
        }
    );
    words.push(0xd50324df);
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
        if !memory.is_empty() || vector_loop {
            // Loop back through the existing budget/epoch guards. This keeps a
            // general same-block loop inside one native entry; each memory
            // instruction still takes its own scoped borrow and code check.
            match flow {
                Flow::Choice(taken) if taken == start => {
                    constant(&mut words, 11, start);
                    words.push(0xeb0b023f); // cmp selected PC, loop start
                    let at = words.len();
                    words.push(0x54000000); // b.eq guarded chain entry
                    branch(&mut words, at, chain);
                }
                Flow::Fixed if next == start => {
                    let offset = (chain as i64 - words.len() as i64) as u32;
                    words.push(0x14000000 | (offset & 0x3ffffff));
                }
                _ => {}
            }
        }
        if dynamic && !vector_context {
            load(&mut words, 11, 16, 96);
            load(&mut words, 11, 11, slot as u32 * 8);
            words.push(0xeb0b023f); // cmp selected guest PC (x17), cached edge PC (x11)
            done.push(words.len());
            words.push(0x54000001); // b.ne actual-PC exit
        }
        if !vector_context {
            load(&mut words, 17, 16, 40);
            load(&mut words, 17, 17, slot as u32 * 8);
            done.push(words.len());
            words.push(0xb4000011);
            words.push(0xd61f0220);
        }
    }
    let success = words.len();
    if dynamic {
        // The selected PC was published before link lookup could clobber x17.
        constant(&mut words, 17, slot as u64);
        store(&mut words, 17, 32);
        store(&mut words, 15, 0);
        store(&mut words, 14, 8);
        native_return(&mut words, direct);
    } else {
        exit(&mut words, next, slot as u64, syscall, direct);
    }
    let failed = words.len();
    exit(&mut words, start, NO_SLOT, false, direct);
    for at in done {
        branch(&mut words, at, success);
    }
    for at in guards {
        branch(&mut words, at, failed);
    }
    if !memory.is_empty() {
        let stopped = words.len();
        native_return(&mut words, direct); // helper published precise exit state
        for site in memory {
            branch(&mut words, body_start + site.stop, stopped);
        }
    }
    (words, body_start)
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
    compile_body(
        memory,
        start,
        limit,
        slot,
        mode,
        host,
        CompileContext::default(),
    )
}
#[derive(Clone, Copy, Default)]
struct CompileContext<'a> {
    floating: bool,
    window: Option<&'a exclusive::Plan>,
    preloads: Option<u64>,
}
fn compile_body(
    memory: &impl CpuMemory,
    start: u64,
    limit: u64,
    slot: usize,
    mode: u8,
    host: trames_execution::Features,
    context: CompileContext<'_>,
) -> Result<Option<Compiled>, CpuFault> {
    let mut code = Assembler::new();
    code.direct = mode & 16 != 0;
    code.floating = context.floating;
    if let Some(preloads) = context.preloads {
        for reg in 0..33 {
            if reg != 31 && preloads & (1 << reg) != 0 {
                code.read(reg, 0);
            }
        }
        if preloads >> 63 != 0 {
            code.flags_read();
        }
    }
    let mut window_load = None;
    let mut window_store = None;
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
        if let Some(plan) = context.window {
            if count == 0 {
                window_load = Some(exclusive::load(&mut code, &plan.first));
                count += 1;
                next = next.wrapping_add(4);
                continue;
            }
            if count + 1 == plan.count {
                if code.versions[sp_register(plan.first.rn as u32) as usize] != 0 {
                    return Ok(None);
                }
                window_store = Some(exclusive::store(&mut code, &plan.last));
                count += 1;
                next = next.wrapping_add(4);
                break;
            }
            if !exclusive::integer(word) {
                return Ok(None);
            }
        }
        if let Some(branch) = compatibility::register(&mut code, word, pc) {
            if branch {
                flow = Flow::Register;
                next = pc.wrapping_add(4);
                terminal = true;
            }
        } else if let Some(op) = crate::vector_ops::decode(word) {
            if !code.floating && !memory_ops.is_empty() {
                return compile_body(
                    memory,
                    start,
                    limit,
                    slot,
                    mode,
                    host,
                    CompileContext {
                        floating: true,
                        ..context
                    },
                );
            }
            code.floating = true;
            code.vector(word, op);
        } else if let Some(op) = crate::system_ops::register(word) {
            if crate::system_ops::floating(op) {
                if !code.floating && !memory_ops.is_empty() {
                    return compile_body(
                        memory,
                        start,
                        limit,
                        slot,
                        mode,
                        host,
                        CompileContext {
                            floating: true,
                            ..context
                        },
                    );
                }
                code.floating = true;
            }
            code.system(word, op);
        } else if crate::system_ops::barrier(word) && memory.cpu_hardware_ordering() {
            code.words.push(word);
        } else if crate::system_ops::hint(word) {
            // Virtual WFx may wake spuriously. PAC/BTI hints keep the current
            // unadvertised guest profile; never act on host LR/TLS/control regs.
        } else if crate::system_ops::Boundary::decode(word).is_some() {
            break;
        } else if word & 0xffe0001f == 0xd4000001 {
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
            if op.vector && !code.floating && !memory_ops.is_empty() {
                return compile_body(
                    memory,
                    start,
                    limit,
                    slot,
                    mode,
                    host,
                    CompileContext {
                        floating: true,
                        ..context
                    },
                );
            }
            code.floating |= op.vector;
            let op = Box::new(op);
            memory_sites.push(if mode & 16 != 0 && op.opcode.is_some() {
                code.hardware_memory(&op, count)
            } else {
                code.memory(&op, count)
            });
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
    if let Some(plan) = context.window {
        let (Some(load), Some(store)) = (window_load, window_store) else {
            return Ok(None);
        };
        if context.preloads.is_none() && code.preloads != 0 {
            return compile_body(
                memory,
                start,
                limit,
                slot,
                mode,
                host,
                CompileContext {
                    preloads: Some(code.preloads),
                    ..context
                },
            );
        }
        if code.window_spill || count != plan.count {
            return Ok(None);
        }
        return exclusive::finish(code, load, store, next, count).map(Some);
    }
    let dynamic = matches!(flow, Flow::Choice(_) | Flow::Register);
    if let Some(first) = code.first_operand {
        let backedge = matches!(flow, Flow::Choice(taken) if taken == start)
            || matches!(flow, Flow::Fixed if next == start);
        if backedge
            && first.key.loop_invariant(&code.versions)
            && code
                .operand
                .is_some_and(|(key, size)| key == first.key && size >= first.width)
        {
            code.words[first.branch] = (code.words[first.branch] & !31) | 23;
            code.traffic.address_reuses += 1;
        } else {
            code.words[first.branch] = 0x14000000 | (first.normal - first.branch) as u32;
        }
    }
    for site in &memory_sites {
        code.words[site.adjust] |= ((count - site.before) as u32) << 10;
    }
    let has_vector = code.floating;
    let (body, mut traffic, context) = code.finish();
    let has_hardware = !memory_sites.is_empty() && mode & 16 != 0;
    let read_only_memory = memory_ops.iter().all(|op| op.load || op.opcode.is_none());
    let memory_width = memory_ops
        .iter()
        .filter(|op| op.opcode.is_some())
        .map(|op| op.size)
        .max()
        .unwrap_or(1);
    let (mut words, body_start) = render(
        &body,
        (start, next),
        slot,
        count,
        mode & 7,
        flow,
        (
            &memory_sites,
            has_hardware,
            has_vector && mode & 8 != 0,
            has_vector,
        ),
    );
    let fast_offset = words.len() * 4;
    let tail_offset;
    if memory_sites.is_empty() && !has_vector {
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
    let fixups: Vec<_> = memory_sites
        .iter()
        .flat_map(|site| site.fixups.iter().copied())
        .map(|(pc, recovery)| ((body_start + pc) * 4, (body_start + recovery) * 4))
        .collect();
    Ok(Some(Compiled {
        memory: (!memory_ops.is_empty()).then(|| Box::new(MemoryOps::Fused(memory_ops))),
        block: Block {
            code: Code::publish_fixups(&words, &fixups)
                .map_err(|error| CpuFault::Host(format!("JIT code publication: {error}")))?,
            has_memory: !memory_sites.is_empty() || has_vector,
            has_vector,
            has_hardware,
            read_only_memory,
            memory_width,
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
    words: usize,
    fixups: Option<trames_memory::NativeCodeFixups>,
    _thread: PhantomData<Rc<()>>,
}
#[repr(C)]
pub(super) struct PairValues {
    pub first: u64,
    pub second: u64,
}
impl Code {
    pub(super) fn publish(words: &[u32]) -> std::io::Result<Self> {
        Self::publish_fixups(words, &[])
    }
    fn publish_fixups(words: &[u32], fixups: &[(usize, usize)]) -> std::io::Result<Self> {
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
        let mut mapping = Self {
            pointer,
            length,
            words: words.len(),
            fixups: None,
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
        if !fixups.is_empty() {
            let pairs: Vec<_> = fixups
                .iter()
                .map(|&(pc, recovery)| (pointer as usize + pc, pointer as usize + recovery))
                .collect();
            // SAFETY: exact emitted scalar sites and local slow continuations;
            // mapping is thread-affine and token retires before its RX storage.
            mapping.fixups = Some(unsafe { trames_memory::NativeCodeFixups::register(&pairs) }?);
        }
        Ok(mapping)
    }
    unsafe fn call_window(&self, registers: *mut u64, frame: &mut Frame) -> u64 {
        let function: unsafe extern "C" fn(*mut u64, *mut Frame) -> u64 =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(registers, frame) }
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
    unsafe fn call_vectors(&self, registers: *mut u64, frame: *mut VectorFrame) {
        let function: unsafe extern "C" fn(*mut u64, *mut VectorFrame) =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe {
            function(registers, frame);
        }
    }
    pub(super) unsafe fn call_memory(&self, pointer: *mut u8, value: u64) -> u64 {
        // SAFETY: the decoder selects a single baseline LDR/STR with exactly
        // the checked width. Pointer and lease live only through this call.
        let function: unsafe extern "C" fn(*mut u8, u64) -> u64 =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(pointer, value) }
    }
    pub(super) unsafe fn call_vector_memory(&self, pointer: *mut u8, values: *mut u128) {
        // The exact-width original load/store acts inside the existing borrow.
        // Only caller-saved v0..v3 marshal the existing CPU vector values.
        let function: unsafe extern "C" fn(*mut u8, *mut u128) =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe {
            function(pointer, values);
        }
    }
    pub(super) unsafe fn call_pair(&self, pointer: *mut u8, first: u64, second: u64) -> PairValues {
        // SAFETY: AAPCS64 passes three scalar arguments in x0/x1/x2 and the
        // two-u64 aggregate result in x0/x1. The exact-width LDP/STP owns only
        // the complete borrowed operand; SP and host callee-saved state stay live.
        let function: unsafe extern "C" fn(*mut u8, u64, u64) -> PairValues =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(pointer, first, second) }
    }
    #[cfg(test)]
    pub(super) fn published_words(&self) -> &[u32] {
        unsafe {
            std::slice::from_raw_parts(self.pointer.cast::<u32>(), self.word_count() as usize)
        }
    }
    pub(super) fn word_count(&self) -> u64 {
        self.words as u64
    }
    pub(super) unsafe fn call_exclusive_read(&self, pointer: *const u8) -> PairValues {
        let function: unsafe extern "C" fn(*const u8) -> PairValues =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(pointer) }
    }
    pub(super) unsafe fn call_exclusive_write(&self, pointer: *mut u8, inputs: &[u64; 4]) -> u64 {
        let function: unsafe extern "C" fn(*mut u8, *const u64) -> u64 =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(pointer, inputs.as_ptr()) }
    }
    pub(super) unsafe fn call_atomic(&self, pointer: *mut u8, inputs: &[u64; 4]) -> PairValues {
        // One native LSE instruction, fixed even pairs for CASP. Canonical
        // storage or the original provider transaction retains all byte custody.
        let function: unsafe extern "C" fn(*mut u8, *const u64) -> PairValues =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe { function(pointer, inputs.as_ptr()) }
    }
    unsafe fn call_tail(&self, offset: usize, registers: *mut u64, links: *const usize) {
        // SAFETY: the caller validated the bounded two-block edge and owns both
        // live RX entries. Only this worker can mutate/revoke the RW jump cell.
        let function: unsafe extern "C" fn(*mut u64, *const usize) =
            unsafe { std::mem::transmute(self.pointer.cast::<u8>().add(offset)) };
        unsafe {
            function(registers, links);
        }
    }
    unsafe fn call_context(&self, offset: usize, registers: *mut u64, frame: &mut Frame) {
        // SAFETY: published AAPCS64 entry, live frame and worker-owned mapping.
        let function: unsafe extern "C" fn(*mut u64, *mut Frame) =
            unsafe { std::mem::transmute(self.pointer.cast::<u8>().add(offset)) };
        unsafe {
            function(registers, frame);
        }
    }
    unsafe fn call_scalar(&self, offset: usize, registers: *mut u64) {
        // SAFETY: the secondary BTI-c entry contains the same bounded register
        // body and returns without modifying host callee-saved state or TLS.
        let function: unsafe extern "C" fn(*mut u64) =
            unsafe { std::mem::transmute(self.pointer.cast::<u8>().add(offset)) };
        unsafe {
            function(registers);
        }
    }
    unsafe fn call(&self, registers: *mut u64, frame: &mut Frame) {
        // SAFETY: codegen emits an AAPCS64 function with this exact ABI. The
        // entry begins with BTI c and returns through untouched host x30.
        let function: unsafe extern "C" fn(*mut u64, *mut Frame) =
            unsafe { std::mem::transmute(self.pointer) };
        unsafe {
            function(registers, frame);
        }
    }
}
impl Drop for Code {
    fn drop(&mut self) {
        drop(self.fixups.take());
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
    fn structure_register_groups_reuse_packed_bindings_without_emitted_traffic() {
        let mut v = Vectors::new();
        let mut words = Vec::new();
        let mut traffic = CompilationStats::default();
        let host = v.group(&mut words, &mut traffic, 31, 4, false);
        assert!((16..=28).contains(&host));
        assert!(words.is_empty()); // Full loads do not read old destinations.
        for i in 0..4 {
            v.bindings[Vectors::slot(host) + i].as_mut().unwrap().dirty = true;
        }
        assert_eq!(v.group(&mut words, &mut traffic, 31, 4, true), host);
        assert!(words.is_empty()); // A following store/lane read uses live values.
        assert_eq!((traffic.register_loads, traffic.register_stores), (0, 0));
        for i in 0..4 {
            assert_eq!(
                Vectors::host(v.hosts[(31 + i) & 31] as usize),
                host + i as u32
            );
        }
    }

    #[test]
    fn fp_blocks_preserve_aapcs64_callee_vector_registers() {
        let mut words: Vec<_> = (0..32)
            .map(|r| 0x4ea01c00 | (r << 16) | (r << 5) | r)
            .collect();
        words.extend_from_slice(&[0x1e622820, 0xd4000001]);
        let m = memory(&words);
        let b = compile(&m, 0x1000, 64, 0, 8).unwrap().unwrap();
        assert!(b.block.has_vector);
        let links = [0usize; CACHE_LIMIT];
        let mut vectors = [0u128; 32];
        vectors[1] = 2f64.to_bits() as u128;
        vectors[2] = 3f64.to_bits() as u128;
        let mut f = VectorFrame {
            frame: frame(&links),
        };
        f.frame.link_pcs = vectors.as_mut_ptr().cast();
        let mut registers = [0u64; 31];
        let before = [0x8123456789abcdefu64; 8];
        let mut after = [0u64; 8];
        let _scope = trames_host_compute::Scope::new(0, 0);
        // Explicit callee-register inputs survive the generated C call. LLVM
        // owns saving the host's original d8..d15 around this test's asm.
        unsafe {
            std::arch::asm!(
                "ldp d8,d9,[x23]","ldp d10,d11,[x23,#16]","ldp d12,d13,[x23,#32]","ldp d14,d15,[x23,#48]",
                "mov x0,x21","mov x1,x22","blr x20",
                "stp d8,d9,[x24]","stp d10,d11,[x24,#16]","stp d12,d13,[x24,#32]","stp d14,d15,[x24,#48]",
                in("x20") b.block.code.pointer,in("x21") registers.as_mut_ptr(),in("x22") &mut f,
                in("x23") before.as_ptr(),in("x24") after.as_mut_ptr(),
                out("v8") _,out("v9") _,out("v10") _,out("v11") _,out("v12") _,out("v13") _,out("v14") _,out("v15") _,
                clobber_abi("C"),
            );
        }
        assert_eq!(after, before);
        assert_eq!(vectors[0], 5f64.to_bits() as u128);
        assert_eq!((f.frame.remaining, f.frame.syscall), (30, 1));
    }

    #[test]
    fn vector_register_bindings_are_reused_inside_the_compiled_block() {
        let mut words = vec![0x1e612800; 31];
        words.push(0xd4000001);
        let m = memory(&words);
        let c = compile(&m, 0x1000, 64, 0, 8).unwrap().unwrap();
        assert!(c.block.has_vector);
        assert!(!c.block.has_hardware);
        assert_eq!(c.block.traffic.register_loads, 2);
        assert_eq!(c.block.traffic.register_stores, 1);
        assert!(c.block.traffic.host_words < 100);
    }

    #[test]
    fn lse_and_rcpc_lower_to_one_original_hardware_instruction() {
        let host = crate::features::profile().allowed;
        for word in [
            0xf8240020, 0xf824803f, 0xc8a27c24, 0x48227c24, 0xf8bfc020, 0xd9400020, 0x99800020,
            0xd9000020,
        ] {
            if !crate::features::permits(host, word) {
                continue;
            }
            let m = memory(&[word, 0xd4000001]);
            let op = crate::memory_ops::Operation::compile(&m, 0x1000)
                .unwrap()
                .unwrap();
            let compiled = compile(&m, 0x1000, 64, 0, 8 | 16 | 1).unwrap().unwrap();
            assert_eq!(compiled.block.instructions, 2);
            let words = unsafe {
                std::slice::from_raw_parts(
                    compiled.block.code.pointer.cast::<u32>(),
                    compiled.block.traffic.host_words as usize,
                )
            };
            let mask = if op.atomic.is_some() {
                !0x1f03ff
            } else {
                !0x3ff
            };
            let sites: Vec<_> = words
                .iter()
                .filter(|&&w| w & mask == op.opcode.unwrap() & mask)
                .collect();
            assert_eq!(sites.len(), 1, "{word:08x}");
            if matches!(
                op.atomic,
                Some(crate::memory_ops::Atomic::Cas { pair: true, .. })
            ) {
                assert_eq!((sites[0] >> 16) & 1, 0);
                assert_eq!(sites[0] & 1, 0);
            }
        }
    }

    #[test]
    fn pair_ordered_and_barrier_lowerings_preserve_hardware_opcodes() {
        for word in [
            0xa9400820, 0xa9000820, 0x69400820, 0x28400820, 0xa8000820, 0x08dffc20, 0x489ffc20,
            0x88dffc20, 0xc89ffc20,
        ] {
            let m = memory(&[word, 0xd4000001]);
            let op = crate::memory_ops::Operation::compile(&m, 0x1000)
                .unwrap()
                .unwrap();
            let compiled = compile(&m, 0x1000, 64, 0, 8 | 16 | 1).unwrap().unwrap();
            assert_eq!(compiled.block.instructions, 2);
            let words = unsafe {
                std::slice::from_raw_parts(
                    compiled.block.code.pointer.cast::<u32>(),
                    compiled.block.traffic.host_words as usize,
                )
            };
            let mask = if op.second.is_some() { !0x7fff } else { !0x3ff };
            assert_eq!(
                words
                    .iter()
                    .filter(|&&w| w & mask == op.opcode.unwrap() & mask)
                    .count(),
                1,
                "{word:08x}"
            );
        }
        for base in [0xd50330bf, 0xd503309f] {
            for option in [1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15] {
                let barrier = base | (option << 8);
                let m = memory(&[barrier, 0xd5033fdf, 0xd4000001]);
                let compiled = compile(&m, 0x1000, 64, 0, 8 | 1).unwrap().unwrap();
                assert_eq!(compiled.block.instructions, 3);
                let words = unsafe {
                    std::slice::from_raw_parts(
                        compiled.block.code.pointer.cast::<u32>(),
                        compiled.block.traffic.host_words as usize,
                    )
                };
                assert!(words.contains(&barrier));
                assert_eq!(
                    words.iter().filter(|&&w| w == barrier).count(),
                    words.iter().filter(|&&w| w == 0xd5033fdf).count()
                );
            }
        }
    }

    #[test]
    fn relaxed_counter_reads_do_not_acquire_implicit_instruction_barriers() {
        for word in [0xd53be020, 0xd53be040, 0xd53be0a0, 0xd53be0c0] {
            let m = memory(&[word, 0xd4000001]);
            let compiled = compile(&m, 0x1000, 64, 0, 8 | 1).unwrap().unwrap();
            let words = unsafe {
                std::slice::from_raw_parts(
                    compiled.block.code.pointer.cast::<u32>(),
                    compiled.block.traffic.host_words as usize,
                )
            };
            assert!(words.iter().any(|w| w & !31 == 0xd53be040));
            assert_eq!(
                words.contains(&0xd5033fdf),
                matches!(word, 0xd53be0a0 | 0xd53be0c0)
            );
        }
    }

    #[test]
    fn direct_entries_preserve_native_callee_registers_on_every_return() {
        for path in 0..3 {
            let mut m = memory(&[0xf9400020, 0x91000400, 0xd4000001]);
            m.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
            m.write_array(0x2000, 42u64.to_le_bytes()).unwrap();
            let compiled = compile(&m, 0x1000, 64, 0, 8 | 16 | 1).unwrap().unwrap();
            let counter = AtomicU64::new(1);
            let links = [0usize; CACHE_LIMIT];
            let mut cpu = Cpu::new(0x1000, 0);
            cpu.set_x(1, 0x2000);
            let checked = m.instruction_identity();
            let cpu_pointer = &mut cpu as *mut Cpu;
            let registers = unsafe { (*cpu_pointer).native_register_pointers().0 };
            let mut f = frame(&links);
            f.epochs[0] = &counter;
            f.expected[0] = u64::from(path != 0);
            if path == 1 {
                f.remaining = 0;
            }
            let mut fused = MemoryFrame {
                frame: f,
                helper: memory_access::<Memory, true, false> as *const () as usize,
                cpu: cpu_pointer,
                memory: &mut m,
                registers,
                hits: 0,
                direct: DirectRegion::EMPTY,
                direct_hits: 0,
                pages: [OperandPage::EMPTY; 64],
                stable: false,
                read_only: true,
                width: 8,
                checked,
                fault: None,
                stats: crate::MemoryStats::default(),
            };
            let mut observed = [19u64, 20, 21, 22, 23];
            // SAFETY: exact generated entry/frame ABI, original code and all
            // epoch/data owners remain live. Explicit canaries verify all new
            // callee-saved registers, including epoch/budget early exits and a
            // normal helper-bearing return. The asm balances the host stack.
            unsafe {
                std::arch::asm!(
                "stp x19,x30,[sp,#-16]!", "mov x19,#19", "blr x9",
                "str x19,[x24]", "ldp x19,x30,[sp],#16",
                in("x9") compiled.code.pointer, in("x0") registers, in("x1") &mut fused,
                in("x24") observed.as_mut_ptr(), inlateout("x20") observed[1],
                inlateout("x21") observed[2], inlateout("x22") observed[3],
                inlateout("x23") observed[4], clobber_abi("C"));
            }
            assert_eq!(observed, [19, 20, 21, 22, 23]);
            assert!(fused.fault.is_none());
            assert_eq!(fused.frame.blocks, u64::from(path == 2));
            assert_eq!(fused.frame.pc, if path == 2 { 0x100c } else { 0x1000 });
            if path == 2 {
                assert_eq!(cpu.x(0), 43);
            }
        }
    }

    #[test]
    fn hardware_admission_preserves_scalar_syscall_tail_cells() {
        let mut m = memory(&[0x91000400, 0xd4000001, 0x17fffffe]);
        assert!(m.cpu_native_available());
        let mut cpu = Cpu::new(0x1008, 0);
        let mut cache = Cache::default();
        for _ in 0..8 {
            let mut retired = 0;
            loop {
                let result = cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
                retired += result.instructions;
                if result.exit == Exit::Syscall {
                    break;
                }
            }
            assert_eq!(retired, 3);
        }
        assert!(cache.tails.iter().any(|&entry| entry != 0));
        assert!(cache.active.is_some_and(|(_, mode)| mode & 16 != 0));
    }
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
                block.code.call(regs.as_mut_ptr(), &mut f);
            }
            assert_eq!((f.blocks, f.remaining, f.pc, regs[0]), (0, 64, 0x1000, 123));
            f.expected[index] = 1;
            unsafe {
                block.code.call(regs.as_mut_ptr(), &mut f);
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
        assert!(cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap().exit == Exit::Syscall);
        let target = cache.hot.unwrap();
        cpu.pc = 0x1000;
        let hit = cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        assert_eq!(
            (hit.blocks, hit.instructions, hit.exit == Exit::Syscall),
            (2, 2, true)
        );
        assert_ne!(cache.links[source.slot], 0);
        cache.remove(target.slot);
        assert_eq!(cache.links[source.slot], 0);
        assert!(cache.node(target).is_none());
        cpu.pc = 0x1000;
        let miss = cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap();
        assert_eq!(
            (miss.blocks, miss.exit == Exit::Syscall, cpu.pc),
            (1, false, 0x1010)
        );
        assert!(cache.execute(&mut cpu, &mut m, 64).unwrap().unwrap().exit == Exit::Syscall);
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
