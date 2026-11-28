// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use trames_memory::{Memory, Permissions, PAGE_SIZE};

#[test]
fn all_high_multiply_ignored_fields_match_independent_wide_products_in_both_engines() {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let values = [
        0u64,
        1,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        u64::MAX,
        0xfedc_ba98_7654_3210,
    ];
    let mut cached = Cpu::new(0x1000, 0x2000);
    let mut stepped = cached.clone();
    for signed in [false, true] {
        for ignored in 0..32 {
            for (rd, rn, rm) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (30, 31, 30), (31, 0, 0)] {
                let word: u32 = if signed { 0x9b400000 } else { 0x9bc00000 }
                    | (ignored << 10)
                    | (rm << 16)
                    | (rn << 5)
                    | rd;
                memory.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
                memory.write_array(0x1000, word.to_le_bytes()).unwrap();
                memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
                for a in values {
                    for b in values {
                        let mut state = Aarch64State {
                            pc: 0x1000,
                            sp: 0x2000,
                            nzcv: 0xb0000000,
                            fpsr: 0x10,
                            tpidr_el0: 123,
                            tpidr2_el0: 456,
                            vectors: [u128::MAX / 3; 32],
                            ..Default::default()
                        };
                        state.registers =
                            std::array::from_fn(|i| u64::MAX.wrapping_sub(i as u64 * 17));
                        if rn != 31 {
                            state.registers[rn as usize] = a;
                        }
                        if rm != 31 {
                            state.registers[rm as usize] = b;
                        }
                        let read = |r: u32| {
                            if r == 31 {
                                0
                            } else {
                                state.registers[r as usize]
                            }
                        };
                        let expected = if signed {
                            ((read(rn) as i64 as i128 * read(rm) as i64 as i128) >> 64) as u64
                        } else {
                            ((read(rn) as u128 * read(rm) as u128) >> 64) as u64
                        };
                        cached.restore_architectural_state(&state);
                        stepped.restore_architectural_state(&state);
                        assert!(matches!(
                            cached.run_slice(&mut memory, 1),
                            SliceOutcome::Yield { instructions: 1 }
                        ));
                        assert!(matches!(stepped.step(&mut memory), Ok(Event::Continue)));
                        state.pc += 4;
                        if rd != 31 {
                            state.registers[rd as usize] = expected;
                        }
                        assert_eq!(cached.architectural_state(), state, "{word:x}");
                        assert_eq!(stepped.architectural_state(), state, "{word:x}");
                    }
                }
            }
        }
    }
}
