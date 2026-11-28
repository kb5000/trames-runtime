// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::cell::Cell;
use trames_memory::{Access, InstructionEpochs, MemoryError};
const EXECUTION: &str =
    include_str!("../../../../docs/validation/jit-scalars-20261128/execution.words");
const REJECTED: &str =
    include_str!("../../../../docs/validation/jit-scalars-20261128/rejected.words");
fn available(word: u32, form: &str) -> bool {
    let host = <Cpu as Backend>::features();
    if form == "Crc" {
        host.hwcap & (1 << 7) != 0
    } else if form == "MinMax" || form == "Unary" && (word >> 10) & 63 >= 6 {
        host.hwcap2 & (1 << 34) != 0
    } else if matches!(word, 0xd500403f | 0xd500405f) {
        host.hwcap2 & (1 << 7) != 0
    } else if form == "Flags" || form == "FlagValue" {
        host.hwcap & (1 << 27) != 0
    } else {
        true
    }
}
fn install(m: &mut Memory, words: &[u32]) {
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, w) in words.iter().enumerate() {
        m.write_array(0x1000 + 4 * i as u64, w.to_le_bytes())
            .unwrap();
    }
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
}
fn compare(
    word: u32,
    form: &str,
    state: &Aarch64State,
    budget: u64,
    engine: &mut Engine,
    a: &mut Memory,
    b: &mut Memory,
) {
    let words = [0xb1000529, 0x1e622820, word, word, 0xd4000001];
    install(a, &words);
    install(b, &words);
    let mut c = Cpu::new(0, 0);
    let mut r = trames_interpreter::Cpu::new(0, 0);
    c.restore_architectural_state(state);
    r.restore_architectural_state(state);
    let absent = !available(word, form);
    if absent {
        assert!(matches!(
            r.run_slice(b, 2),
            SliceOutcome::Yield { instructions: 2 }
        ));
    }
    let before = engine.stats;
    let mut finished = false;
    for _ in 0..8 {
        let actual = c.run_slice(engine, a, budget);
        if absent {
            if !matches!(actual, SliceOutcome::Yield { .. }) {
                assert!(
                    matches!(actual,SliceOutcome::Fault(trames_engine::CpuFault::Instruction{pc:0x1008,instruction}) if instruction==word)
                );
                assert_eq!(c.architectural_state(), r.architectural_state(), "{word:x}");
                finished = true;
                break;
            }
        } else {
            let expected = r.run_slice(b, budget);
            assert_eq!(
                format!("{actual:?}"),
                format!("{expected:?}"),
                "{word:x}/{form}/{budget}"
            );
            assert_eq!(
                c.architectural_state(),
                r.architectural_state(),
                "{word:x}/{form}/{budget}"
            );
            assert_eq!(c.fault_retired(), r.fault_retired());
            if !matches!(actual, SliceOutcome::Yield { .. }) {
                assert!(
                    matches!(actual, SliceOutcome::Syscall { .. }),
                    "{word:x}/{form}"
                );
                assert_eq!(
                    engine.stats.native_instructions - before.native_instructions,
                    4,
                    "{word:x}/{form}"
                );
                finished = true;
                break;
            }
        }
    }
    assert!(finished, "{word:x}");
    assert_eq!(
        engine.stats.fallback_instructions - before.fallback_instructions,
        0,
        "{word:x}/{form}"
    );
    for (i, w) in words.iter().enumerate() {
        assert_eq!(a.fetch_u32(0x1000 + 4 * i as u64).unwrap(), *w);
    }
}

#[test]
fn every_llvm_scalar_selector_executes_or_rejects_absent_host_features_without_fallback() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut a = memory(&[]);
    let mut b = memory(&[]);
    let mut engine = Engine::default();
    let mut count = 0;
    for (i, line) in EXECUTION.lines().enumerate() {
        let (raw, form) = line.split_once(' ').unwrap();
        let word = u32::from_str_radix(raw, 16).unwrap();
        let mut state = initial();
        state.nzcv = ((i as u32) & 15) << 28;
        for r in &mut state.registers {
            *r ^= (i as u64).wrapping_mul(0x987654321);
        }
        for budget in [1, 64] {
            compare(word, form, &state, budget, &mut engine, &mut a, &mut b);
            count += 1;
        }
    }
    assert_eq!(count, 204944);
}

fn alias(word: u32, form: &str, d: u32, n: u32, m: u32, a: u32) -> u32 {
    let mut result = word;
    if !matches!(form, "Flags" | "FlagValue" | "Compare") {
        result = (result & !31) | d;
    }
    if !matches!(
        form,
        "Flags" | "Move" | "Address" | "ReadNzcv" | "WriteNzcv"
    ) {
        result = (result & !(31 << 5)) | (n << 5);
    }
    if matches!(
        form,
        "Crc"
            | "AddShift"
            | "AddExtended"
            | "LogicalShift"
            | "Extract"
            | "Select"
            | "Carry"
            | "Binary"
            | "Multiply"
    ) || form == "Compare" && word & (1 << 11) == 0
        || form == "MinMax" && word & 0x7ff00000 != 0x11c00000
    {
        result = (result & !(31 << 16)) | (m << 16);
    }
    if form == "Multiply" && !matches!((word >> 21) & 7, 2 | 6) {
        result = (result & !(31 << 10)) | (a << 10);
    }
    result
}

#[test]
fn scalar_aliases_and_dirty_register_pressure_survive_single_step_and_memory_callbacks() {
    if !NATIVE_COMPILED {
        return;
    }
    for (i, line) in EXECUTION.lines().enumerate().filter(|(i, _)| i % 97 == 0) {
        let (raw, form) = line.split_once(' ').unwrap();
        let word = u32::from_str_radix(raw, 16).unwrap();
        for (d, n, m, a) in [
            (0, 0, 0, 0),
            (30, 30, 29, 30),
            (31, 31, 31, 31),
            (1, 2, 1, 1),
        ] {
            let word = alias(word, form, d, n, m, a);
            if !available(word, form) {
                continue;
            }
            let mut words: Vec<_> = (0..31).map(|r| 0x91000400 | (r << 5) | r).collect();
            words.extend_from_slice(&[0x1e622820, word, 0xf9400274, word, 0xd4000001]); // LDR x20,[x19]
            let mut state = initial();
            state.nzcv = ((i as u32) & 15) << 28;
            state.registers[19] = 0x10000 - 1;
            for budget in [1, 64] {
                for mode in [0, 1, 2] {
                    let engine = compare_memory_sequence_mode(&words, &state, budget, mode);
                    assert_eq!(engine.stats.fallback_instructions, 0, "{word:x}/{form}");
                }
            }
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
        panic!("invalid scalar data read")
    }
    fn write(&mut self, _a: u64, _bytes: &[u8]) -> Result<(), MemoryError> {
        panic!("invalid scalar data write")
    }
    fn check(&self, _a: u64, _len: usize, _access: Access) -> Result<(), MemoryError> {
        panic!("invalid scalar permission query")
    }
    fn check_translation(&self, _a: u64) -> Result<(), MemoryError> {
        panic!("invalid scalar data translation")
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
        panic!("invalid scalar transaction")
    }
    fn exclusive_read(&mut self, _a: u64, _out: &mut [u8]) -> Result<u128, MemoryError> {
        panic!("invalid scalar exclusive read")
    }
    fn exclusive_write(
        &mut self,
        _a: u64,
        _bytes: &[u8],
        _token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        panic!("invalid scalar exclusive write")
    }
}

#[test]
fn original_invalid_scalar_forms_fault_without_interpreter_or_warm_fetches_and_revalidate_code_changes(
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
