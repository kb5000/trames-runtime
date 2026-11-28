// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn fixture() -> Vec<u32> {
    include_str!("../../../../docs/validation/jit-special-memory-20261128/category.words")
        .lines()
        .map(|line| u32::from_str_radix(line, 16).unwrap())
        .collect()
}
#[test]
fn host_lse128_forms_preserve_independent_inout_registers_sp_bases_and_atomic_bytes() {
    if NATIVE_COMPILED && trames_jit::host_features().unwrap().hwcap2 & (1 << 47) == 0 {
        return;
    }
    for word in fixture().into_iter().skip(432).take(72) {
        for budget in [1, 64] {
            for parallel in [false, true] {
                let mut state = initial();
                let base = ((word >> 5) & 31) as usize;
                if base == 31 {
                    state.sp = 0x10000;
                } else {
                    state.registers[base] = 0x10000;
                }
                let engine = compare_memory_sequence(&[word, 0xd4000001], &state, budget, parallel);
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0);
                }
            }
        }
    }
}
#[test]
fn unadvertised_lse128_ls64_and_unowned_tag_setting_mops_fault_before_emulation() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut words: Vec<_> = fixture().into_iter().skip(536).collect(); // LS64
    if trames_jit::host_features().unwrap().hwcap2 & (1 << 47) == 0 {
        words.extend(fixture().into_iter().skip(432).take(72));
    }
    for stage in 0..3 {
        for options in 0..4 {
            words.push(0x1dc10440 | stage << 14 | options << 12);
        }
    }
    for word in words {
        let mut memory = memory(&[0x91000529, word, 0xd4000001]);
        let mut cpu = Cpu::new(0x1000, 0x2800);
        let mut engine = Engine::default();
        assert!(
            matches!(cpu.run_slice(&mut engine, &mut memory, 64), SliceOutcome::Fault(trames_engine::CpuFault::Instruction { pc: 0x1004, instruction }) if instruction == word)
        );
        assert_eq!((cpu.pc(), cpu.x(9), cpu.fault_retired()), (0x1004, 1, 1));
        assert_eq!(engine.stats.fallback_instructions, 0);
    }
}
