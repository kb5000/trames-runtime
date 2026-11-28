// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

#[path = "control_test_support.rs"]
mod oracle;
use oracle::expected;

#[test]
fn complete_control_matrix_matches_independent_conditions_in_cached_and_step_paths() {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let mut cached = Cpu::new(0x1000, 0x2000);
    let mut stepped = cached.clone();
    let mut count = 0;
    let words = include_str!("../../../docs/validation/jit-control-20261128/category.words");
    let rows = include_str!("../../../docs/validation/jit-control-20261128/category.cases");
    for (i, (raw, row)) in words.lines().zip(rows.lines()).enumerate() {
        let word = u32::from_str_radix(raw, 16).unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
        memory.write_array(0x1000, word.to_le_bytes()).unwrap();
        memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        let fields: Vec<_> = row.split_whitespace().collect();
        let left: usize = fields[3].parse().unwrap();
        let right: usize = fields[4].parse().unwrap();
        let trials = if fields[0] == "cond" || fields[0] == "hbc" {
            16
        } else {
            6
        };
        for trial in 0..trials {
            let mut state = Aarch64State {
                pc: 0x1000,
                sp: 0x2000,
                nzcv: ((trial + i as u32) & 15) << 28,
                fpsr: 0x10,
                tpidr_el0: 123,
                tpidr2_el0: 456,
                vectors: [u128::MAX / 3; 32],
                ..Default::default()
            };
            state.registers = std::array::from_fn(|r| (r as u64).wrapping_mul(0x8123456789abcdef));
            let values = [0, 1, u64::MAX, 0x8000000000000000, 0x80, 0x8000];
            if left != 31 {
                state.registers[left] = values[trial as usize % 6];
            }
            if fields[5] == "0" && fields[0] == "cmp" && right != 31 {
                state.registers[right] = values[(trial as usize + 2) % 6];
            }
            let want = expected(row, &state);
            cached.restore_architectural_state(&state);
            stepped.restore_architectural_state(&state);
            assert!(
                matches!(
                    cached.run_slice(&mut memory, 1),
                    SliceOutcome::Yield { instructions: 1 }
                ),
                "{word:x}/{row}"
            );
            assert!(
                matches!(stepped.step(&mut memory), Ok(Event::Continue)),
                "{word:x}/{row}"
            );
            assert_eq!(cached.architectural_state(), want, "cached {word:x}/{row}");
            assert_eq!(stepped.architectural_state(), want, "step {word:x}/{row}");
            count += 1;
        }
    }
    eprintln!("Independent complete control matrix: {count} programs in each interpreter path");
}

#[test]
fn compare_branch_selector_admission_matches_all_llvm_words() {
    let fixture =
        include_str!("../../../docs/validation/jit-control-20261128/compare-selectors.words");
    let mut valid = 0;
    for row in fixture.lines() {
        let (word, yes) = row.split_once(' ').unwrap();
        let word = u32::from_str_radix(word, 16).unwrap();
        assert_eq!(
            control::CompareBranch::decode(word).is_some(),
            yes == "1",
            "{word:x}"
        );
        valid += usize::from(yes == "1");
    }
    assert_eq!(valid, 1536);
}
