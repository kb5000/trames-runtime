// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn corpus() -> impl Iterator<Item = (u32, u64, u64)> {
    include_str!("../data/arithmetic-encodings.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split_whitespace();
            (
                u32::from_str_radix(fields.next().unwrap(), 16).unwrap(),
                u64::from_str_radix(fields.next().unwrap(), 16).unwrap(),
                u64::from_str_radix(fields.next().unwrap(), 16).unwrap(),
            )
        })
}
fn admitted(hwcap: u64, hwcap2: u64) -> bool {
    !NATIVE_COMPILED
        || trames_jit::host_features()
            .is_some_and(|h| h.hwcap & hwcap == hwcap && h.hwcap2 & hwcap2 == hwcap2)
}
#[test]
fn complete_arithmetic_encoding_category_matches_reference_without_fallback() {
    for (word, h, h2) in corpus() {
        if !admitted(h, h2) {
            continue;
        }
        compare_fp_word(word, &initial());
    }
}

#[test]
fn complete_native_arithmetic_forms_have_a_reference_oracle() {
    let mut m = memory(&[0]);
    m.protect(
        0x1000,
        PAGE_SIZE,
        Permissions {
            read: true,
            write: true,
            execute: true,
        },
    )
    .unwrap();
    let state = initial();
    let mut r = trames_interpreter::Cpu::new(0x1000, 0);
    let mut missing = Vec::new();
    for (word, h, h2) in corpus() {
        if !admitted(h, h2) {
            continue;
        }
        m.write_array(0x1000, word.to_le_bytes()).unwrap();
        r.restore_architectural_state(&state);
        let out = r.run_slice(&mut m, 1);
        if !matches!(out, SliceOutcome::Yield { instructions: 1 }) {
            missing.push(format!("{word:08x}: {out:?}"));
        }
    }
    assert!(
        missing.is_empty(),
        "missing reference forms ({}):\n{}",
        missing.len(),
        missing.join("\n")
    );
}

#[test]
fn complete_arithmetic_aliases_survive_low_register_relocation_helpers_and_faults() {
    for line in include_str!("../data/arithmetic-aliases.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let mut fields = line.split_whitespace();
        let word = u32::from_str_radix(fields.next().unwrap(), 16).unwrap();
        let h = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
        let h2 = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
        if !admitted(h, h2) {
            continue;
        }
        let mut words: Vec<_> = (0..32)
            .map(|r| 0x4ea01c00 | (r << 16) | (r << 5) | r)
            .collect();
        words.extend_from_slice(&[
            word, 0x3dc0034c, 0x3d80074c, 0xd53b441b, 0xd53b443c, 0xd61f0320, 0xd4000001,
        ]);
        for variant in 0..5 {
            let mut state = initial();
            state.registers[25] = 0x1000 + 4 * (words.len() as u64 - 1);
            state.registers[26] = 0x10ff8;
            state.fpcr = match variant {
                1 => 1 << 22,
                2 => 2 << 22,
                3 => (3 << 22) | (1 << 25) | (1 << 24) | (1 << 19),
                4 => (1 << 26) | (1 << 19),
                _ => 0,
            };
            for (r, v) in state.vectors.iter_mut().enumerate() {
                *v = match variant {
                    1 => u128::MAX,
                    2 => (u128::MAX / 255) * (if r % 2 == 0 { 128 } else { 127 }),
                    3 => 0x80000000000000017f8000017fc01234,
                    4 => 0,
                    _ => *v,
                };
            }
            let e = compare_memory_sequence(
                &words,
                &state,
                if variant == 4 { 8 } else { 64 },
                variant % 2 == 0,
            );
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
            }
        }
    }
}

#[test]
fn arithmetic_dirty_banks_and_status_publish_precisely_before_memory_faults() {
    for line in include_str!("../data/arithmetic-aliases.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .step_by(17)
    {
        let mut f = line.split_whitespace();
        let word = u32::from_str_radix(f.next().unwrap(), 16).unwrap();
        let h = u64::from_str_radix(f.next().unwrap(), 16).unwrap();
        let h2 = u64::from_str_radix(f.next().unwrap(), 16).unwrap();
        if !admitted(h, h2) {
            continue;
        }
        let mut words: Vec<_> = (0..32)
            .map(|r| 0x4ea01c00 | (r << 16) | (r << 5) | r)
            .collect();
        words.extend_from_slice(&[word, 0x3dc0034c, 0xd4000001]);
        let mut state = initial();
        state.fpcr = (3 << 22) | (1 << 19);
        state.registers[26] = 0x10000 + hardware_span();
        for budget in [1, 64] {
            let e = compare_memory_sequence(&words, &state, budget, budget == 64);
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
            }
        }
    }
}
