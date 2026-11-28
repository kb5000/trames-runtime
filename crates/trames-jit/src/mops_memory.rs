// SPDX-License-Identifier: GPL-3.0-or-later
//! Protected MOPS operands. Only address translation and existing checked byte
//! transport live here; the CPU chooses the algorithm, progress and NZCV.
use super::{Interval, Plan, Ranges, State, ADDRESS, WORK_LIMIT};
use trames_memory::{Access, CpuMemory, MemoryError, NativeOperand, PAGE_SIZE};

pub(super) struct Translation {
    destination: u64,
    source: u64,
}
impl Translation {
    pub fn new(state: State, destination: u64, source: u64, set: bool, empty: bool) -> Self {
        Self {
            destination: if empty {
                0
            } else {
                (state.destination & ADDRESS)
                    .wrapping_add(destination)
                    .wrapping_sub(state.destination)
            },
            source: if empty || set {
                0
            } else {
                (state.source & ADDRESS)
                    .wrapping_add(source)
                    .wrapping_sub(state.source)
            },
        }
    }
    pub fn apply(&self, state: &mut State) {
        state.destination = state.destination.wrapping_add(self.destination);
        state.source = state.source.wrapping_add(self.source);
    }
    pub fn restore(&self, state: &mut State) {
        state.destination = state.destination.wrapping_sub(self.destination);
        state.source = state.source.wrapping_sub(self.source);
    }
}

struct Arena {
    mapping: NativeOperand,
    bias: u64,
    mapped: Vec<(usize, usize)>,
    granule: usize,
}
impl Arena {
    fn new(range: Interval, granule: usize) -> Result<Self, MemoryError> {
        let len = usize::try_from(range.len())
            .ok()
            .and_then(|len| len.checked_add(4 * granule))
            .ok_or(MemoryError::Limit)?;
        Ok(Self {
            mapping: NativeOperand::new(len).map_err(|_| MemoryError::Limit)?,
            bias: 0,
            mapped: Vec::with_capacity(2),
            granule,
        })
    }
    fn layout(&mut self, range: Interval, anchor: u64) {
        debug_assert!(self.mapped.is_empty());
        let padding = range.start.wrapping_sub(anchor) & (self.granule as u64 - 1);
        let base = (self.mapping.address() + self.granule - 1) & !(self.granule - 1);
        self.bias = (base as u64 + self.granule as u64 + padding).wrapping_sub(range.start);
    }
    fn address(&self, guest: u64) -> usize {
        guest.wrapping_add(self.bias) as usize
    }
    fn block(&self, range: Interval) -> (usize, usize) {
        let start = self.address(range.start) & !(self.granule - 1);
        let end = (self.address(range.end) + self.granule - 1) & !(self.granule - 1);
        (start - self.mapping.address(), end - start)
    }
    fn stage(&mut self, first: Interval, second: Option<Interval>) -> Result<(), MemoryError> {
        let mut blocks = [
            Some(self.block(first)),
            second.map(|range| self.block(range)),
        ];
        if blocks[1].is_some_and(|second| second.0 < blocks[0].unwrap().0) {
            blocks.swap(0, 1);
        }
        for (offset, len) in blocks.into_iter().flatten() {
            if let Some((previous, previous_len)) = self.mapped.last_mut() {
                if offset <= *previous + *previous_len {
                    let old_end = *previous + *previous_len;
                    let new_end = (offset + len).max(old_end);
                    if new_end > old_end && !self.mapping.stage(old_end, new_end - old_end) {
                        return Err(MemoryError::Limit);
                    }
                    *previous_len = new_end - *previous;
                    continue;
                }
            }
            if !self.mapping.stage(offset, len) {
                return Err(MemoryError::Limit);
            }
            self.mapped.push((offset, len));
        }
        Ok(())
    }
    unsafe fn alias(&mut self, range: Interval, source: usize) -> Result<(), MemoryError> {
        let (offset, len) = self.block(range);
        if !unsafe { self.mapping.alias(offset, source, len) } {
            return Err(MemoryError::Limit);
        }
        // Overlapping aliases have the same retained physical bytes. Keep both
        // intervals for reset; repeated reset is harmless and releases storage.
        if let Some((previous, previous_len)) = self.mapped.last_mut() {
            if offset <= *previous + *previous_len && *previous <= offset + len {
                let start = (*previous).min(offset);
                *previous_len = (*previous + *previous_len).max(offset + len) - start;
                *previous = start;
                return Ok(());
            }
        }
        self.mapped.push((offset, len));
        Ok(())
    }
    fn reset(&mut self) -> Result<(), MemoryError> {
        for &(offset, len) in &self.mapped {
            if !self.mapping.reset(offset, len) {
                return Err(MemoryError::Limit);
            }
        }
        self.mapped.clear();
        Ok(())
    }
    fn contains_mapped(&self, address: u64) -> bool {
        self.mapped.iter().any(|&(offset, len)| {
            address.wrapping_sub((self.mapping.address() + offset) as u64) < len as u64
        })
    }
}
struct Operands {
    destination: Arena,
    source: Option<Arena>,
    shared: bool,
}
impl Operands {
    fn new(plan: &Plan, ranges: Ranges, granule: usize) -> Result<Self, MemoryError> {
        // CPYF with destination after an overlapping source is unsuitable for
        // memmove. Opaque checked storage keeps its original page-snapshot byte
        // transport; valid overlap directions and CPY retain one common bias.
        let shared = ranges.source.is_some_and(|source| {
            source.overlaps(ranges.destination)
                && (plan.op.moving() || source.start >= ranges.destination.start)
        });
        let destination = if shared {
            union(ranges.destination, ranges.source.unwrap())
        } else {
            ranges.destination
        };
        Ok(Self {
            destination: Arena::new(destination, granule)?,
            source: if shared {
                None
            } else {
                ranges
                    .source
                    .map(|source| Arena::new(source, granule))
                    .transpose()?
            },
            shared,
        })
    }
    fn layout(&mut self, ranges: Ranges, chunk: Chunk, aliases: bool) {
        let anchor = if aliases { 0 } else { chunk.anchor };
        self.destination.layout(
            if self.shared {
                union(ranges.destination, ranges.source.unwrap())
            } else {
                ranges.destination
            },
            anchor,
        );
        if let Some(source) = self.source.as_mut() {
            source.layout(
                ranges.source.unwrap(),
                if aliases { 0 } else { chunk.source_anchor },
            );
        }
    }
    fn source(&self) -> &Arena {
        self.source.as_ref().unwrap_or(&self.destination)
    }
    fn translation(&self, plan: &Plan, state: State) -> Translation {
        Translation::new(
            state,
            self.destination.bias,
            self.source().bias,
            plan.op.set,
            false,
        )
    }
    fn reset(&mut self) -> Result<(), MemoryError> {
        self.destination.reset()?;
        if let Some(source) = self.source.as_mut() {
            source.reset()?;
        }
        Ok(())
    }
    fn contains_mapped(&self, address: u64) -> bool {
        self.destination.contains_mapped(address)
            || self
                .source
                .as_ref()
                .is_some_and(|source| source.contains_mapped(address))
    }
    fn stage(&mut self, chunk: Chunk, input: &[u8]) -> Result<(), MemoryError> {
        if self.shared {
            self.destination.stage(chunk.destination, chunk.source)?;
        } else {
            self.destination.stage(chunk.destination, None)?;
            if let Some(source) = self.source.as_mut() {
                source.stage(chunk.source.unwrap(), None)?;
            }
        }
        if let Some(source) = chunk.source {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    input.as_ptr(),
                    self.source().address(source.start) as *mut u8,
                    input.len(),
                )
            };
        }
        if self.shared {
            let source = chunk.source.unwrap();
            let arena = &mut self.destination;
            let (start, end) = if chunk.backwards {
                let start = arena.address(source.start) & !(arena.granule - 1);
                (start, arena.address(chunk.destination.start))
            } else {
                let end = (arena.address(source.end) + arena.granule - 1) & !(arena.granule - 1);
                (arena.address(chunk.destination.end), end)
            };
            // The first logical destination boundary is host-aligned if it is
            // the limiting role. Source-only granules remain readable there.
            if start < end
                && start.is_multiple_of(arena.granule)
                && end.is_multiple_of(arena.granule)
                && !arena
                    .mapping
                    .read_only(start - arena.mapping.address(), end - start)
            {
                return Err(MemoryError::Limit);
            }
        }
        Ok(())
    }
}
fn union(a: Interval, b: Interval) -> Interval {
    Interval {
        start: a.start.min(b.start),
        end: a.end.max(b.end),
    }
}
#[derive(Clone, Copy)]
struct Chunk {
    destination: Interval,
    source: Option<Interval>,
    anchor: u64,
    source_anchor: u64,
    backwards: bool,
}
impl Chunk {
    fn new(ranges: Ranges, backwards: bool) -> Self {
        let boundary = |range: Interval| {
            if backwards {
                ((range.end - 1) & (PAGE_SIZE - 1)) + 1
            } else {
                PAGE_SIZE - (range.start & (PAGE_SIZE - 1))
            }
        };
        let len = ranges
            .len()
            .min(boundary(ranges.destination))
            .min(ranges.source.map_or(u64::MAX, boundary));
        let slice = |range: Interval| {
            if backwards {
                Interval {
                    start: range.end - len,
                    end: range.end,
                }
            } else {
                Interval {
                    start: range.start,
                    end: range.start + len,
                }
            }
        };
        let destination = slice(ranges.destination);
        let source = ranges.source.map(slice);
        let anchor = source.map_or(destination, |source| {
            if boundary(ranges.source.unwrap()) < boundary(ranges.destination) {
                source
            } else {
                destination
            }
        });
        Self {
            destination,
            source,
            anchor: if backwards { anchor.start } else { anchor.end },
            source_anchor: source.map_or(
                0,
                |source| if backwards { source.start } else { source.end },
            ),
            backwards,
        }
    }
}

// Returns only original Memory errors. The frame is transient; no helper owns a
// software MOPS algorithm/option or any persistent extension register state.
pub(super) fn execute(
    plan: &Plan,
    memory: &mut impl CpuMemory,
    state: &mut State,
    stage: &mut usize,
) -> Result<(bool, bool), MemoryError> {
    execute_at_granule(
        plan,
        memory,
        state,
        stage,
        trames_memory::host_mapping_granule(),
    )
}
pub(super) fn execute_at_granule(
    plan: &Plan,
    memory: &mut impl CpuMemory,
    state: &mut State,
    stage: &mut usize,
    granule: usize,
) -> Result<(bool, bool), MemoryError> {
    let initial = Ranges::new(plan.op, *state, *stage)?;
    let mut operands = Operands::new(plan, initial, granule)?;
    let mut demanded = false;
    let mut reverse_hint = initial.backwards;
    let mut direct = true;
    let mut work = 0;
    let mut allow_alias = true;
    loop {
        let ranges = Ranges::new(plan.op, *state, *stage)?;
        if ranges.len() == 0 {
            let result = unsafe { plan.code.call_mops_at(state, *stage) };
            if result == 0 {
                return Ok((direct, false));
            }
            *stage = result as usize - 1;
            continue;
        }
        let backwards = ranges.backwards || *stage == 0 && plan.op.moving() && reverse_hint;
        let chunk = Chunk::new(ranges, backwards);
        let mut aliases = false;
        if demanded {
            // Admit resident private aliases before taking any Rust byte
            // snapshot. Declined exports are discarded before checked transport.
            let g = operands.destination.granule as u64;
            if allow_alias {
                for amount in [ranges.len().min(WORK_LIMIT - work), ranges.len().min(g)] {
                    let granules = |range: Interval| {
                        let (start, end) = if backwards {
                            (range.end - amount, range.end)
                        } else {
                            (range.start, range.start + amount)
                        };
                        Interval {
                            start: start & !(g - 1),
                            end: (end + g - 1) & !(g - 1),
                        }
                    };
                    let d = granules(ranges.destination);
                    let s = ranges.source.map(granules);
                    let destination =
                        unsafe { memory.cpu_native_span(d.start, d.len() as usize, true) };
                    let source = if let Some(source) = s {
                        unsafe {
                            memory.cpu_native_span(source.start, source.len() as usize, false)
                        }
                    } else {
                        Some(0)
                    };
                    if let (Some(destination), Some(source)) = (destination, source) {
                        operands.layout(ranges, chunk, true);
                        unsafe {
                            operands.destination.alias(d, destination)?;
                        }
                        if let Some(s) = s {
                            if operands.shared {
                                unsafe {
                                    operands.destination.alias(s, source)?;
                                }
                            } else {
                                unsafe {
                                    operands.source.as_mut().unwrap().alias(s, source)?;
                                }
                            }
                        }
                        aliases = true;
                        break;
                    }
                }
            }
            if !aliases {
                let mut input = [0u8; PAGE_SIZE as usize];
                if state.fault_access == 1 {
                    memory.check(
                        chunk.destination.start,
                        chunk.destination.len() as usize,
                        Access::Write,
                    )?;
                    if let Some(source) = chunk.source {
                        memory.read(source.start, &mut input[..source.len() as usize])?;
                    }
                } else {
                    if let Some(source) = chunk.source {
                        memory.read(source.start, &mut input[..source.len() as usize])?;
                    }
                    memory.check(
                        chunk.destination.start,
                        chunk.destination.len() as usize,
                        Access::Write,
                    )?;
                }
                operands.layout(ranges, chunk, false);
                operands.stage(
                    chunk,
                    if plan.op.set {
                        &[]
                    } else {
                        &input[..chunk.destination.len() as usize]
                    },
                )?;
            }
        } else {
            operands.layout(ranges, chunk, false);
        }
        let before = *state;
        let before_stage = *stage;
        let translation = operands.translation(plan, *state);
        translation.apply(state);
        let result = unsafe { plan.code.call_mops_at(state, *stage) };
        translation.restore(state);
        let after_stage = if result == 0 {
            plan.end + 1
        } else {
            result as usize - 1
        };
        let after = Ranges::new(plan.op, *state, after_stage)?;
        let done = ranges.len().saturating_sub(after.len());
        // Only the initialized progress prefix becomes a byte slice after all
        // aliases are reset. Private aliases do not zero/copy a stack page.
        let mut output = std::mem::MaybeUninit::<[u8; PAGE_SIZE as usize]>::uninit();
        if demanded && !aliases && done != 0 {
            if done > chunk.destination.len() {
                return Err(MemoryError::InvalidRange);
            }
            let start = if backwards {
                ranges.destination.end - done
            } else {
                ranges.destination.start
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    operands.destination.address(start) as *const u8,
                    output.as_mut_ptr().cast::<u8>(),
                    done as usize,
                )
            };
        }
        let mapped_fault = result != 0 && operands.contains_mapped(state.fault_address);
        if result != 0 && *stage == 0 && plan.op.moving() && !operands.shared {
            let address = state.fault_address;
            let d = address.wrapping_sub(operands.destination.bias);
            let s = address.wrapping_sub(operands.source().bias);
            reverse_hint = d >= ranges.destination.start + ranges.len() / 2
                && d < ranges.destination.end
                || ranges
                    .source
                    .is_some_and(|range| s >= range.start + range.len() / 2 && s < range.end);
        }
        // All cloned loans are gone before the next Memory/provider operation.
        operands.reset()?;
        if demanded && !aliases && done != 0 {
            let start = if backwards {
                ranges.destination.end - done
            } else {
                ranges.destination.start
            };
            // Native progress initialized exactly this bounded prefix above;
            // neither padding nor any uninitialized byte enters Rust's slice.
            let bytes =
                unsafe { std::slice::from_raw_parts(output.as_ptr().cast::<u8>(), done as usize) };
            if let Err(error) = memory.write(start, bytes) {
                *state = before;
                *stage = before_stage;
                return Err(error);
            }
        }
        if demanded && done != 0 {
            direct &= aliases;
        }
        work += done;
        *stage = after_stage;
        if result == 0 {
            return Ok((direct, false));
        }
        if aliases && mapped_fault {
            allow_alias = false;
        }
        if work >= WORK_LIMIT {
            return Ok((direct, true));
        }
        demanded = true;
    }
}
