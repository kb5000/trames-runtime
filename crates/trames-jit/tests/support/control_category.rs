// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::cell::Cell;
use trames_memory::{Access, InstructionEpochs, MemoryError};
#[path = "../../../trames-interpreter/src/control_test_support.rs"]
mod oracle;
const WORDS: &str = include_str!("../../../../docs/validation/jit-control-20261128/category.words");
const ROWS: &str = include_str!("../../../../docs/validation/jit-control-20261128/category.cases");
const REJECTED: &str =
    include_str!("../../../../docs/validation/jit-control-20261128/rejected.words");
fn install(m: &mut Memory, words: &[u32]) {
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, w) in words.iter().enumerate() {
        m.write_array(0x1000 + 4 * i as u64, w.to_le_bytes())
            .unwrap();
    }
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
}
fn available(row: &str) -> bool {
    let host = <Cpu as Backend>::features();
    if row.starts_with("hbc ") {
        host.hwcap2 & (1 << 44) != 0
    } else if row.starts_with("cmp ") {
        host.hwcap & (1 << 33) != 0
    } else {
        true
    }
}
#[test]
fn every_control_encoding_matches_independent_whole_state_or_reached_host_rejection() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut m = memory(&[]);
    let mut engine = Engine::default();
    let mut count = [0u64; 2];
    for (i, (raw, row)) in WORDS.lines().zip(ROWS.lines()).enumerate() {
        let word = u32::from_str_radix(raw, 16).unwrap();
        install(&mut m, &[word]);
        let fields: Vec<_> = row.split_whitespace().collect();
        let left: usize = fields[3].parse().unwrap();
        let right: usize = fields[4].parse().unwrap();
        let trials = if matches!(fields[0], "cond" | "hbc") {
            16
        } else {
            6
        };
        for trial in 0..trials {
            let mut state = initial();
            state.nzcv = ((trial + i as u32) & 15) << 28;
            let values = [0, 1, u64::MAX, 0x8000000000000000, 0x80, 0x8000];
            if left != 31 {
                state.registers[left] = values[trial as usize % 6];
            }
            if fields[0] == "cmp" && fields[5] == "0" && right != 31 {
                state.registers[right] = values[(trial as usize + 2) % 6];
            }
            let mut c = Cpu::new(0, 0);
            c.restore_architectural_state(&state);
            let outcome = c.run_slice(&mut engine, &mut m, 1);
            if available(row) {
                assert!(
                    matches!(outcome, SliceOutcome::Yield { instructions: 1 }),
                    "{word:x}/{row}/{outcome:?}"
                );
                assert_eq!(
                    c.architectural_state(),
                    oracle::expected(row, &state),
                    "{word:x}/{row}"
                );
                count[0] += 1;
            } else {
                assert!(
                    matches!(outcome, SliceOutcome::Fault(trames_engine::CpuFault::Instruction { pc:0x1000, instruction }) if instruction == word),
                    "{word:x}/{row}"
                );
                assert_eq!(c.architectural_state(), state);
                assert_eq!(c.fault_retired(), 0);
                count[1] += 1;
            }
        }
        assert_eq!(m.fetch_u32(0x1000).unwrap(), word);
    }
    assert_eq!(engine.stats.fallback_instructions, 0);
    eprintln!(
        "Control whole-state matrix: {} native, {} reached host rejection",
        count[0], count[1]
    );
}
#[test]
fn control_targets_preserve_dirty_prefixes_memory_callbacks_budgets_and_link_aliases() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut count = 0;
    for (i, (raw, row)) in WORDS.lines().zip(ROWS.lines()).enumerate() {
        if i % 97 != 0 && !row.starts_with("blr ") && !row.starts_with("hbc ") {
            continue;
        }
        if !available(row) {
            continue;
        }
        let mut word = u32::from_str_radix(raw, 16).unwrap();
        // Give every immediate family the same independently known +8 target.
        word = match row.split_whitespace().next().unwrap() {
            "b" | "bl" => (word & !0x3ffffff) | 2,
            "cond" | "hbc" | "zero" => (word & !0xffffe0) | (2 << 5),
            "bit" => (word & !0x7ffe0) | (2 << 5),
            "cmp" => (word & !0x3fe0) | (2 << 5),
            _ => word,
        };
        let mut words: Vec<_> = (0..31).map(|r| 0x91000400 | (r << 5) | r).collect();
        words.extend_from_slice(&[0x1e622820, 0xf9400274, word, 0x91000c00, 0xd4000001]);
        let mut state = initial();
        state.registers[19] = 0x10000 - 1;
        state.nzcv = ((i as u32) & 15) << 28;
        if matches!(row.split_whitespace().next(), Some("br" | "blr" | "ret")) {
            let reg: usize = row.split_whitespace().nth(3).unwrap().parse().unwrap();
            if reg != 31 {
                state.registers[reg] = 0x1000 + 35 * 4 - 1;
            }
        }
        for budget in [1, 2, 64] {
            for mode in [0, 1, 2] {
                let e = compare_memory_sequence_mode(&words, &state, budget, mode);
                assert_eq!(e.stats.fallback_instructions, 0, "{word:x}/{row}");
                count += 1;
            }
        }
    }
    eprintln!("Control dirty-prefix/memory/budget programs: {count}");
}
#[test]
fn extension_reached_fault_retires_exact_prefix_without_changing_cpu_banks() {
    if !NATIVE_COMPILED {
        return;
    }
    for (raw, row) in WORDS
        .lines()
        .zip(ROWS.lines())
        .filter(|(_, row)| !available(row))
        .step_by(97)
    {
        let word = u32::from_str_radix(raw, 16).unwrap();
        let words = [0xb1000529, 0x1e622820, word];
        for budget in [1, 2, 64] {
            let mut a = memory(&words);
            let mut b = memory(&words);
            let state = initial();
            let mut c = Cpu::new(0, 0);
            let mut r = trames_interpreter::Cpu::new(0, 0);
            c.restore_architectural_state(&state);
            r.restore_architectural_state(&state);
            assert!(matches!(
                r.run_slice(&mut b, 2),
                SliceOutcome::Yield { instructions: 2 }
            ));
            let mut e = Engine::default();
            let mut prefix = 0;
            loop {
                let actual = c.run_slice(&mut e, &mut a, budget);
                if let SliceOutcome::Yield { instructions } = actual {
                    prefix += instructions;
                    continue;
                }
                assert!(
                    matches!(actual,SliceOutcome::Fault(trames_engine::CpuFault::Instruction{pc:0x1008,instruction}) if instruction==word),
                    "{row}"
                );
                assert_eq!(prefix + c.fault_retired(), 2);
                break;
            }
            assert_eq!(c.architectural_state(), r.architectural_state());
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
}

#[test]
fn native_extension_loops_keep_flags_exact_budgets_and_syscall_resumption() {
    if !NATIVE_COMPILED {
        return;
    }
    // SUBS + BC.NE; SUB + CBNE-immediate. CMPBR leaves original NZCV intact.
    for (branch, row, sub) in [
        (0x54fffff1u32, "hbc ", 0xf1000400u32),
        (0xf5e03fe0u32, "cmp ", 0xd1000400u32),
    ] {
        if !available(row) {
            continue;
        }
        let words = [sub, branch, 0xd4000001, 0x17fffffd];
        for flags in 0..16 {
            for budget in [1, 2, 3, 64] {
                let mut a = memory(&words);
                let mut b = memory(&words);
                let mut state = initial();
                state.nzcv = flags << 28;
                state.registers[0] = 17;
                let mut c = Cpu::new(0, 0);
                let mut r = trames_interpreter::Cpu::new(0, 0);
                c.restore_architectural_state(&state);
                r.restore_architectural_state(&state);
                let mut e = Engine::default();
                let mut syscalls = 0;
                for _ in 0..256 {
                    let x = c.run_slice(&mut e, &mut a, budget);
                    let y = r.run_slice(&mut b, budget);
                    assert_eq!(format!("{x:?}"), format!("{y:?}"));
                    assert_eq!(c.architectural_state(), r.architectural_state());
                    if matches!(x, SliceOutcome::Syscall { .. }) {
                        syscalls += 1;
                        if syscalls == 3 {
                            break;
                        }
                        c.set_x(0, 17);
                        r.set_x(0, 17);
                    } else {
                        assert!(matches!(x, SliceOutcome::Yield { .. }));
                    }
                }
                assert_eq!(syscalls, 3);
                assert_eq!(e.stats.fallback_instructions, 0);
                if budget == 64 {
                    assert!(e.link_stats().linked_blocks > 0);
                    assert!(e.link_stats().syscall_resumes > 0);
                }
            }
        }
    }
}

#[test]
fn extension_target_fault_and_code_permission_changes_rejoin_original_authority() {
    if !NATIVE_COMPILED {
        return;
    }
    for (word, row) in [(0x5400003eu32, "hbc "), (0xf4c00020u32, "cmp ")] {
        if !available(row) {
            continue;
        }
        for target_permission in [None, Some(Permissions::RW), Some(Permissions::RX)] {
            let mut a = memory(&[]);
            let mut b = memory(&[]);
            for m in [&mut a, &mut b] {
                m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
                m.write_array(0x1ffc, word.to_le_bytes()).unwrap();
                m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
                m.write_array(0x2000, 0xd4000001u32.to_le_bytes()).unwrap();
                if let Some(p) = target_permission {
                    m.protect(0x2000, PAGE_SIZE, p).unwrap();
                } else {
                    m.unmap(0x2000, PAGE_SIZE).unwrap();
                }
            }
            let mut state = initial();
            state.pc = 0x1ffc;
            let mut c = Cpu::new(0, 0);
            let mut r = trames_interpreter::Cpu::new(0, 0);
            c.restore_architectural_state(&state);
            r.restore_architectural_state(&state);
            let mut e = Engine::default();
            for attempt in 0..3 {
                c.restore_architectural_state(&state);
                r.restore_architectural_state(&state);
                let x = c.run_slice(&mut e, &mut a, 64);
                let y = r.run_slice(&mut b, 64);
                assert_eq!(format!("{x:?}"), format!("{y:?}"));
                assert_eq!(c.architectural_state(), r.architectural_state());
                assert_eq!(c.fault_retired(), r.fault_retired());
                if attempt == 1 {
                    for m in [&mut a, &mut b] {
                        m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
                    }
                }
            }
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
}

struct Traced {
    memory: Memory,
    pages: Cell<u64>,
    fetches: Cell<u64>,
    limit: Cell<u64>,
    epochs: bool,
}
impl CpuMemory for Traced {
    fn mapped_at_or_after(&self, a: u64) -> bool {
        self.memory.mapped_at_or_after(a)
    }
    fn read(&self, _a: u64, _out: &mut [u8]) -> Result<(), MemoryError> {
        panic!("invalid control data read")
    }
    fn write(&mut self, _a: u64, _bytes: &[u8]) -> Result<(), MemoryError> {
        panic!("invalid control data write")
    }
    fn check(&self, _a: u64, _len: usize, _access: Access) -> Result<(), MemoryError> {
        panic!("invalid control permission query")
    }
    fn check_translation(&self, _a: u64) -> Result<(), MemoryError> {
        panic!("invalid control data translation")
    }
    fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
        self.fetches.set(self.fetches.get() + 1);
        self.memory.fetch_u32(a)
    }
    fn instruction_identity(&self) -> (u64, u64, u64) {
        self.memory.instruction_identity()
    }
    fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
        self.pages.set(self.pages.get() + 1);
        assert!(
            self.pages.get() <= self.limit.get(),
            "extra decoder page query: interpreter fault entry"
        );
        self.memory.instruction_page_identity(a)
    }
    fn instruction_epochs(&self) -> Option<InstructionEpochs<'_>> {
        if self.epochs {
            self.memory.instruction_epochs()
        } else {
            None
        }
    }
    fn atomic_update<T>(
        &mut self,
        _a: u64,
        _len: usize,
        _f: impl FnOnce(&mut [u8]) -> (T, bool),
    ) -> Result<T, MemoryError> {
        panic!("invalid control transaction")
    }
    fn exclusive_read(&mut self, _a: u64, _out: &mut [u8]) -> Result<u128, MemoryError> {
        panic!("invalid control exclusive read")
    }
    fn exclusive_write(
        &mut self,
        _a: u64,
        _bytes: &[u8],
        _token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        panic!("invalid control exclusive write")
    }
}

#[test]
fn original_invalid_control_forms_fault_without_interpreter_or_warm_fetches_and_revalidate_code_changes(
) {
    if !NATIVE_COMPILED {
        return;
    }
    for (i, raw) in REJECTED.lines().enumerate() {
        let word = u32::from_str_radix(raw, 16).unwrap();
        let mut m = Traced {
            memory: memory(&[word, 0xd4000001]),
            pages: Cell::new(0),
            fetches: Cell::new(0),
            limit: Cell::new(1),
            epochs: i % 2 != 0,
        };
        let state = initial();
        let mut c = Cpu::new(0, 0);
        c.restore_architectural_state(&state);
        let mut e = Engine::default();
        for attempt in 0..3 {
            let before = (m.fetches.get(), e.compilation_stats().blocks);
            // An absent-feature gate can fault before installing a descriptor.
            if attempt != 0 && before.1 == 0 {
                break;
            }
            // Non-chaining embeddings intentionally retain exact-budget keys.
            let budget = [1, 2, 64][if m.epochs { attempt } else { i % 3 }];
            assert!(
                matches!(c.run_slice(&mut e,&mut m,budget),SliceOutcome::Fault(trames_engine::CpuFault::Instruction{pc:0x1000,instruction}) if instruction==word)
            );
            assert_eq!(c.architectural_state(), state);
            assert_eq!(c.fault_retired(), 0);
            assert_eq!(m.pages.get(), 1);
            if attempt != 0 {
                assert_eq!((m.fetches.get(), e.compilation_stats().blocks), before);
            }
        }
        if i % 97 == 0 {
            m.limit.set(u64::MAX);
            install(&mut m.memory, &[0x91000400, 0xd4000001]);
            assert!(matches!(
                c.run_slice(&mut e, &mut m, 64),
                SliceOutcome::Syscall { instructions: 2 }
            ));
            assert_eq!(c.x(0), state.registers[0].wrapping_add(1));
            c.set_pc(0x1000);
            m.memory
                .protect(0x1000, PAGE_SIZE, Permissions::RW)
                .unwrap();
            assert!(matches!(
                c.run_slice(&mut e, &mut m, 64),
                SliceOutcome::Fault(trames_engine::CpuFault::Memory { pc: 0x1000, .. })
            ));
        }
        assert_eq!(e.stats.fallback_instructions, 0);
    }
}
