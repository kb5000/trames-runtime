// SPDX-License-Identifier: GPL-3.0-or-later
//! Real MOPS stages and exact hardware progress. Temporary operands are not task
//! extension state; GPR/NZCV results belong to the existing shared CPU banks.
use super::Code;
use trames_engine::CpuFault;
use trames_interpreter::Cpu;
use trames_memory::{CpuMemory, MemoryError};
#[path = "mops_memory.rs"]
mod memory;

const WORK_LIMIT: u64 = 64 * 1024;
const ENTRY_WORDS: usize = 6;
const ADDRESS: u64 = 0x00ff_ffff_ffff_ffff;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct State {
    pub destination: u64,
    pub source: u64,
    pub count: u64,
    pub nzcv: u64,
    pub fault_address: u64,
    pub fault_access: u64,
}
// Fixed native load/store offsets are checked by the compiler, with no runtime
// validation or per-instruction frame-layout branch.
const _: () = {
    assert!(std::mem::size_of::<State>() == 48);
    assert!(std::mem::offset_of!(State, destination) == 0);
    assert!(std::mem::offset_of!(State, source) == 8);
    assert!(std::mem::offset_of!(State, count) == 16);
    assert!(std::mem::offset_of!(State, nzcv) == 24);
    assert!(std::mem::offset_of!(State, fault_address) == 32);
    assert!(std::mem::offset_of!(State, fault_access) == 40);
};
#[derive(Clone, Copy, Debug)]
pub(super) struct Operation {
    pub word: u32,
    pub set: bool,
    pub stage: usize,
    pub destination: usize,
    pub source: usize,
    pub count: usize,
}
impl Operation {
    fn moving(self) -> bool {
        !self.set && self.word & (1 << 26) != 0
    }
    pub fn decode(word: u32) -> Option<Self> {
        if !matches!(word & 0xff200c00, 0x19000400 | 0x1d000400) {
            return None;
        }
        let set = word & 0x00c00000 == 0x00c00000;
        // SETG requires allocation-tag ownership, which this CPU ABI does not
        // advertise. Never turn it into an untagged SET compatibility operation.
        if set && word & (1 << 26) != 0 {
            return None;
        }
        let stage = ((word >> if set { 14 } else { 22 }) & 3) as usize;
        let destination = (word & 31) as usize;
        let source = ((word >> 16) & 31) as usize;
        let count = ((word >> 5) & 31) as usize;
        if stage == 3
            || destination == 31
            || count == 31
            || destination == count
            || source == count
            || source == destination
            || !set && source == 31
        {
            return None;
        }
        Some(Self {
            word,
            set,
            stage,
            destination,
            source,
            count,
        })
    }
    pub fn opcode(self, stage: usize) -> u32 {
        let shift = if self.set { 14 } else { 22 };
        (self.word & !(0x1f03ff | (3 << shift))) | ((stage as u32) << shift) | (1 << 16) | (2 << 5)
    }
}

#[derive(Clone, Copy, Debug)]
struct Interval {
    start: u64,
    end: u64,
}
impl Interval {
    fn new(start: u64, length: u64) -> Result<Self, MemoryError> {
        Ok(Self {
            start,
            end: start
                .checked_add(length)
                .ok_or(MemoryError::AddressRange(start))?,
        })
    }
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
    fn len(self) -> u64 {
        self.end - self.start
    }
}
#[derive(Clone, Copy, Debug)]
struct Ranges {
    destination: Interval,
    source: Option<Interval>,
    backwards: bool,
}
impl Ranges {
    fn new(op: Operation, state: State, stage: usize) -> Result<Self, MemoryError> {
        let option_b = state.nzcv & (1 << 29) != 0;
        let count = if stage == 0 {
            state.count.min(if op.moving() {
                0x007f_ffff_ffff_ffff
            } else {
                i64::MAX as u64
            })
        } else if option_b || op.moving() && state.count as i64 > 0 {
            state.count
        } else {
            state.count.wrapping_neg()
        };
        let destination = state.destination & ADDRESS;
        let source = state.source & ADDRESS;
        let backwards = op.moving()
            && if stage == 0 {
                source < destination
                    && source
                        .checked_add(count)
                        .is_some_and(|end| end > destination)
            } else if option_b {
                state.nzcv & (1 << 31) != 0
            } else {
                state.count as i64 > 0
            };
        let range = |pointer: u64| {
            let start = if stage == 0 {
                pointer
            } else if option_b && backwards || !option_b && !backwards {
                pointer
                    .checked_sub(count)
                    .ok_or(MemoryError::AddressRange(pointer))?
            } else {
                pointer
            };
            Interval::new(start, count)
        };
        Ok(Self {
            destination: range(destination)?,
            source: (!op.set).then(|| range(source)).transpose()?,
            backwards,
        })
    }
    fn len(self) -> u64 {
        self.destination.len()
    }
}

pub(super) struct Plan {
    op: Operation,
    base: u64,
    end: usize,
    code: Code,
}
pub(super) struct Run {
    pub instructions: u64,
    pub direct: bool,
    pub yielding: bool,
}
impl Plan {
    pub fn compile(memory: &impl CpuMemory, pc: u64, limit: u64) -> Result<Option<Self>, CpuFault> {
        let word = memory
            .fetch_u32(pc)
            .map_err(|error| CpuFault::Memory { pc, error })?;
        let Some(op) = Operation::decode(word) else {
            return Ok(None);
        };
        if !crate::features::permits(crate::features::profile().allowed, word) {
            return Err(CpuFault::Instruction {
                pc,
                instruction: word,
            });
        }
        let shift = if op.set { 14 } else { 22 };
        let mut end = op.stage;
        for step in 1..limit.min((3 - op.stage) as u64) {
            let expected = (word & !(3 << shift)) | (((op.stage + step as usize) as u32) << shift);
            if memory.fetch_u32(pc.wrapping_add(step * 4)).ok() != Some(expected) {
                break;
            }
            end += 1;
        }
        Ok(Some(Self {
            op,
            base: pc.wrapping_sub(op.stage as u64 * 4),
            end,
            code: publish(op, end)?,
        }))
    }
    pub fn instructions(&self) -> u64 {
        (self.end + 1 - self.op.stage) as u64
    }
    pub fn host_words(&self) -> u64 {
        self.code.word_count()
    }
    fn save(&self, cpu: &mut Cpu, state: State, stage: usize) {
        cpu.set_x(self.op.destination, state.destination);
        if !self.op.set {
            cpu.set_x(self.op.source, state.source);
        }
        cpu.set_x(self.op.count, state.count);
        cpu.set_nzcv((state.nzcv >> 28) as u32);
        cpu.pc = self.base.wrapping_add(stage as u64 * 4);
    }
    fn progress(&self, stage: usize) -> u64 {
        stage.saturating_sub(self.op.stage) as u64
    }
    pub fn execute(
        &self,
        cpu: &mut Cpu,
        memory: &mut impl CpuMemory,
    ) -> Result<Run, (u64, CpuFault)> {
        let mut state = State {
            destination: cpu.x(self.op.destination),
            source: cpu.x(self.op.source),
            count: cpu.x(self.op.count),
            nzcv: u64::from(cpu.nzcv()) << 28,
            fault_address: 0,
            fault_access: 2,
        };
        let mut stage = self.op.stage;
        let ranges = Ranges::new(self.op, state, stage)
            .map_err(|error| (0, CpuFault::Memory { pc: cpu.pc, error }))?;
        // Complete small resident private ranges stay on their original protected
        // CPU aliases: no mmap, staging, provider callback or extra task state.
        let direct = if ranges.len() == 0 {
            Some((0, 0))
        } else if ranges.len() <= WORK_LIMIT {
            let destination = unsafe {
                memory.cpu_native_span(ranges.destination.start, ranges.len() as usize, true)
            };
            let source = if let Some(range) = ranges.source {
                unsafe { memory.cpu_native_span(range.start, range.len() as usize, false) }
            } else {
                Some(0)
            };
            match (destination, source) {
                (Some(destination), Some(source)) => {
                    let d = (destination as u64).wrapping_sub(ranges.destination.start);
                    let s = ranges
                        .source
                        .map_or(0, |range| (source as u64).wrapping_sub(range.start));
                    if ranges
                        .source
                        .is_none_or(|range| !range.overlaps(ranges.destination) || d == s)
                    {
                        Some((d, s))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            None
        };
        if let Some((destination, source)) = direct {
            let translation = memory::Translation::new(
                state,
                destination,
                source,
                self.op.set,
                ranges.len() == 0,
            );
            translation.apply(&mut state);
            let result = unsafe { self.code.call_mops_at(&mut state, stage) };
            translation.restore(&mut state);
            if result == 0 {
                self.save(cpu, state, self.end + 1);
                return Ok(Run {
                    instructions: self.instructions(),
                    direct: true,
                    yielding: false,
                });
            }
            stage = result as usize - 1;
        }
        let result = memory::execute(self, memory, &mut state, &mut stage);
        match result {
            Ok((direct, yielding)) => {
                self.save(cpu, state, if yielding { stage } else { self.end + 1 });
                Ok(Run {
                    instructions: if yielding {
                        self.progress(stage)
                    } else {
                        self.instructions()
                    },
                    direct,
                    yielding,
                })
            }
            Err(error) => {
                self.save(cpu, state, stage);
                Err((self.progress(stage), CpuFault::Memory { pc: cpu.pc, error }))
            }
        }
    }
}

/// A standalone M/E has the original P(/M) immediately before its reached PC,
/// permitting Linux's MOPS-mismatch handler to restart the real host sequence.
/// Its preceding opcodes are normally skipped. P-only needs no continuation.
pub(super) fn publish(op: Operation, end: usize) -> Result<Code, CpuFault> {
    // Every reached entry has its own caller ABI prefix, then branches into the
    // same consecutive P/M/E sequence. A recovered M/E resumes without replaying
    // an already completed P. Kernel mismatch restarts still see real adjacent P.
    let mut words = Vec::new();
    let prologue = (end + 1) * ENTRY_WORDS;
    for stage in 0..=end {
        words.extend_from_slice(&[0xd503245f, 0xaa0003e3, 0xa9400460, 0xa9411062, 0xd51b4204]);
        let branch = words.len();
        words.push(0x14000000 | (prologue + stage - branch) as u32);
    }
    for stage in 0..=end {
        words.push(op.opcode(stage));
    }
    words.extend_from_slice(&[0xd53b4204, 0xa9000460, 0xa9011062, 0xd2800000, 0xd65f03c0]);
    let mut offsets = Vec::new();
    for stage in 0..=end {
        offsets.push(((prologue + stage) * 4, words.len() * 4));
        words.extend_from_slice(&[
            0xd53b4204,
            0xa9000460,
            0xa9011062,
            0xa9021865,
            0xd2800000 | (((stage + 1) as u32) << 5),
            0xd65f03c0,
        ]);
    }
    let mut code =
        Code::publish(&words).map_err(|e| CpuFault::Host(format!("JIT MOPS publication: {e}")))?;
    let pairs: Vec<_> = offsets
        .into_iter()
        .map(|(pc, recovery)| (code.pointer as usize + pc, code.pointer as usize + recovery))
        .collect();
    code.fixups = Some(
        unsafe { trames_memory::NativeCodeFixups::register_with_memory(&pairs, 5, 6) }
            .map_err(|e| CpuFault::Host(format!("JIT MOPS recovery publication: {e}")))?,
    );
    Ok(code)
}
impl Code {
    pub(super) unsafe fn call_mops_at(&self, state: &mut State, stage: usize) -> u64 {
        let function: unsafe extern "C" fn(*mut State) -> u64 =
            unsafe { std::mem::transmute(self.pointer.add(stage * ENTRY_WORDS * 4)) };
        unsafe { function(state) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn llvm_mops_fixture_and_resume_entries_keep_consecutive_real_stages() {
        let fixture =
            include_str!("../../../docs/validation/jit-special-memory-20261128/category.words");
        for word in fixture
            .lines()
            .take(432)
            .map(|line| u32::from_str_radix(line, 16).unwrap())
        {
            let op = Operation::decode(word).unwrap();
            let code = publish(op, op.stage).unwrap();
            let words = code.published_words();
            let prologue = (op.stage + 1) * 6;
            for stage in 0..=op.stage {
                assert_eq!(words[stage * 6], 0xd503245f);
                let branch = stage * 6 + 5;
                assert_eq!(
                    branch + (words[branch] & 0x3ffffff) as usize,
                    prologue + stage
                );
                assert_eq!(words[prologue + stage], op.opcode(stage));
            }
            let shift = if op.set { 14 } else { 22 };
            let invalid = (word & !(3 << shift)) | (3 << shift);
            if op.set {
                assert!(Operation::decode(invalid).is_none());
            }
            // COPY's op1=11 space is SET/SETG, not a reserved COPY stage.
            else {
                assert!(Operation::decode(invalid).is_none_or(|next| next.set));
            }
        }
    }
    #[test]
    fn memory_translation_reads_both_real_architectural_progress_formats() {
        let op = Operation::decode(0x1d010440).unwrap();
        for (d, s, n, nzcv, backwards, start_d, start_s) in [
            (
                0x12000,
                0x22000,
                0u64.wrapping_sub(4097),
                0,
                false,
                0x10fff,
                0x20fff,
            ),
            (0x10000, 0x20000, 4097, 0, true, 0x10000, 0x20000),
            (0x10000, 0x20000, 4097, 0x20000000, false, 0x10000, 0x20000),
            (0x12000, 0x22000, 4097, 0xa0000000, true, 0x10fff, 0x20fff),
        ] {
            let state = State {
                destination: d,
                source: s,
                count: n,
                nzcv,
                ..Default::default()
            };
            let ranges = Ranges::new(op, state, 1).unwrap();
            assert_eq!((ranges.len(), ranges.backwards), (4097, backwards));
            assert_eq!(ranges.destination.start, start_d);
            assert_eq!(ranges.source.unwrap().start, start_s);
        }
    }
    #[test]
    fn native_mops_stage_fragments_preserve_real_register_and_nzcv_progress() {
        if crate::features::profile().allowed.hwcap2 & (1 << 43) == 0 {
            return;
        }
        for base in [0x19010440, 0x1d010440, 0x19c10440] {
            let op = Operation::decode(base).unwrap();
            let mut a = vec![0x41u8; 16384];
            let mut b = vec![0u8; 16384];
            let mut state = State {
                destination: b.as_mut_ptr() as u64,
                source: if op.set { 0x83 } else { a.as_mut_ptr() as u64 },
                count: 16381,
                nzcv: 0xb0000000,
                fault_address: 0,
                fault_access: 2,
            };
            for stage in 0..3 {
                let mut stage_op = op;
                stage_op.stage = stage;
                let code = publish(stage_op, stage).unwrap();
                assert_eq!(unsafe { code.call_mops_at(&mut state, stage) }, 0);
            }
            assert_eq!(state.count, 0);
            assert_eq!(&b[..16381], vec![if op.set { 0x83 } else { 0x41 }; 16381]);
            assert_eq!(&b[16381..], &[0; 3]);
        }
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn recovery_consumes_real_data_abort_address_and_access_without_tls_or_cpu_copies() {
        let operand = trames_memory::NativeOperand::new(16384).unwrap();
        for (instruction, expected) in [(0xf9400020, 0), (0xf9000020, 1)] {
            let words = [
                0xd503245f,
                0xaa0003e3,
                instruction,
                0xd2800000,
                0xd65f03c0,
                0xa9001865,
                0xd2800020,
                0xd65f03c0,
            ];
            let mut code = Code::publish(&words).unwrap();
            code.fixups = Some(
                unsafe {
                    trames_memory::NativeCodeFixups::register_with_memory(
                        &[(code.pointer as usize + 8, code.pointer as usize + 20)],
                        5,
                        6,
                    )
                }
                .unwrap(),
            );
            let mut result = [0u64; 2];
            let address = operand.address() + 4101;
            let function: unsafe extern "C" fn(*mut u64, usize) -> u64 =
                unsafe { std::mem::transmute(code.pointer) };
            assert_eq!(unsafe { function(result.as_mut_ptr(), address) }, 1);
            assert_eq!(result[0], address as u64);
            // Native Linux supplies ESR; QEMU user 8.x can omit this record.
            assert!(result[1] == expected || result[1] == 2, "{result:?}");
        }
    }
}

#[cfg(test)]
mod protected_tests {
    use super::*;
    use trames_memory::{Access, Memory, Permissions, PAGE_SIZE};
    struct Checked {
        memory: Memory,
        fail_write: bool,
    }
    impl CpuMemory for Checked {
        fn mapped_at_or_after(&self, a: u64) -> bool {
            CpuMemory::mapped_at_or_after(&self.memory, a)
        }
        fn read(&self, a: u64, out: &mut [u8]) -> Result<(), MemoryError> {
            self.memory.read(a, out)
        }
        fn write(&mut self, a: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            if self.fail_write {
                return Err(MemoryError::Permission {
                    address: a,
                    access: Access::Write,
                });
            }
            self.memory.write(a, bytes)
        }
        fn check(&self, a: u64, n: usize, access: Access) -> Result<(), MemoryError> {
            self.memory.check(a, n, access)
        }
        fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
            self.memory.check_translation(a)
        }
        fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
            self.memory.fetch_u32(a)
        }
        fn instruction_identity(&self) -> (u64, u64, u64) {
            self.memory.instruction_identity()
        }
        fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
            self.memory.instruction_page_identity(a)
        }
        fn atomic_update<T>(
            &mut self,
            a: u64,
            n: usize,
            f: impl FnOnce(&mut [u8]) -> (T, bool),
        ) -> Result<T, MemoryError> {
            self.memory.atomic_update(a, n, f)
        }
        fn exclusive_read(&mut self, a: u64, out: &mut [u8]) -> Result<u128, MemoryError> {
            self.memory.exclusive_read(a, out)
        }
        fn exclusive_write(
            &mut self,
            a: u64,
            bytes: &[u8],
            token: Option<u128>,
        ) -> Result<bool, MemoryError> {
            self.memory.exclusive_write(a, bytes, token)
        }
    }
    fn setup(word: u32) -> (Checked, Plan, Vec<u8>) {
        let mut memory = Memory::default();
        memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        let op = Operation::decode(word).unwrap();
        let shift = if op.set { 14 } else { 22 };
        for stage in 0..3 {
            memory
                .write_array(
                    0x1000 + stage * 4,
                    (word | (stage as u32) << shift).to_le_bytes(),
                )
                .unwrap();
        }
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        memory.map(0x10000, 0x40000, Permissions::RW).unwrap();
        let bytes: Vec<_> = (0..0x40000)
            .map(|i| (i as u8).wrapping_mul(19).wrapping_add((i >> 9) as u8))
            .collect();
        memory.write(0x10000, &bytes).unwrap();
        let checked = Checked {
            memory,
            fail_write: false,
        };
        let plan = Plan::compile(&checked, 0x1000, 3).unwrap().unwrap();
        (checked, plan, bytes)
    }
    #[test]
    fn protected_four_kib_fragments_keep_exact_bytes_on_four_sixteen_and_sixty_four_kib_guards() {
        if crate::features::profile().allowed.hwcap2 & (1 << 43) == 0 {
            return;
        }
        for granule in [4096, 16384, 65536] {
            for (word, destination, source) in [
                (0x19010440, 0x30003, 0x10005),
                (0x1d010440, 0x10013, 0x10005),
                (0x1d010440, 0x10005, 0x10013),
                (0x19010440, 0x10005, 0x11003),
                (0x1d010440, 0x11003, 0x10005),
                (0x1d010440, 0x10005, 0x11003),
                (0x19c10440, 0x20003, 0x87),
            ] {
                for count in [1, 4097, 8197, 32781] {
                    let (mut memory, plan, mut expected) = setup(word);
                    let mut state = State {
                        destination,
                        source,
                        count,
                        nzcv: 0xb0000000,
                        ..Default::default()
                    };
                    let start = (destination - 0x10000) as usize;
                    if plan.op.set {
                        expected[start..start + count as usize].fill(source as u8);
                    } else {
                        let from = (source - 0x10000) as usize;
                        expected.copy_within(from..from + count as usize, start);
                    }
                    let mut stage = 0;
                    assert_eq!(
                        memory::execute_at_granule(
                            &plan,
                            &mut memory,
                            &mut state,
                            &mut stage,
                            granule
                        )
                        .unwrap(),
                        (false, false)
                    );
                    assert_eq!(state.count, 0);
                    let mut actual = vec![0; expected.len()];
                    memory.memory.read(0x10000, &mut actual).unwrap();
                    assert_eq!(actual, expected, "word={word:x} G={granule} N={count}");
                }
            }
        }
    }
    #[test]
    fn failed_checked_publication_restores_the_first_unpublished_instruction_checkpoint() {
        if crate::features::profile().allowed.hwcap2 & (1 << 43) == 0 {
            return;
        }
        for word in [0x19010440, 0x1d010440, 0x19c10440] {
            let (mut memory, plan, expected) = setup(word);
            memory.fail_write = true;
            let mut state = State {
                destination: 0x30003,
                source: if plan.op.set { 0x87 } else { 0x10005 },
                count: 16381,
                nzcv: 0xb0000000,
                ..Default::default()
            };
            let old = state;
            let mut stage = 0;
            assert!(matches!(
                memory::execute_at_granule(&plan, &mut memory, &mut state, &mut stage, 16384),
                Err(MemoryError::Permission {
                    access: Access::Write,
                    ..
                })
            ));
            assert_eq!(
                (
                    state.destination,
                    state.source,
                    state.count,
                    state.nzcv,
                    stage
                ),
                (old.destination, old.source, old.count, old.nzcv, 0)
            );
            let mut actual = vec![0; expected.len()];
            memory.memory.read(0x10000, &mut actual).unwrap();
            assert_eq!(actual, expected);
        }
    }
}
