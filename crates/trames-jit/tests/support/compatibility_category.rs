// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn fixture() -> impl Iterator<Item = (&'static str, u32)> {
    include_str!("../../../../docs/validation/jit-compatibility-20261128/category.cases")
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            (
                fields.next().unwrap(),
                u32::from_str_radix(fields.next().unwrap(), 16).unwrap(),
            )
        })
}
fn assign(state: &mut Aarch64State, reg: usize, value: u64) {
    if reg == 31 {
        state.sp = value;
    } else {
        state.registers[reg] = value;
    }
}

#[test]
fn whole_llvm_compatibility_category_matches_state_memory_and_retirement_in_all_modes() {
    assert_eq!(fixture().count(), 836);
    for (kind, word) in fixture() {
        for budget in [1, 2, 64] {
            for mode in 0..3 {
                let mut state = initial();
                if matches!(kind, "load" | "tag" | "stgp") {
                    assign(
                        &mut state,
                        ((word >> 5) & 31) as usize,
                        0xa5aa_0000_0001_2000,
                    );
                } else if kind == "branch" {
                    let reg = if matches!(word, 0xd65f0bff | 0xd65f0fff) {
                        30
                    } else {
                        ((word >> 5) & 31) as usize
                    };
                    if reg != 31 {
                        state.registers[reg] = 0xa5aa_0000_0000_1008;
                    }
                }
                let words = if kind == "branch" {
                    vec![0xb1000529, word, 0xd4000001]
                } else {
                    vec![0xb1000529, word, word, 0xd4000001]
                };
                let engine = compare_memory_sequence_mode(&words, &state, budget, mode);
                if NATIVE_COMPILED {
                    assert_eq!(
                        engine.stats.fallback_instructions, 0,
                        "kind={kind}; word={word:x}; budget={budget}; mode={mode}"
                    );
                    assert!(engine.stats.native_instructions >= 2);
                }
            }
        }
    }
}

#[test]
fn compatibility_pointer_arithmetic_covers_sign_boundaries_flags_aliases_and_sp() {
    let values = [
        0,
        1,
        (1 << 55) - 1,
        1 << 55,
        0x00ff_ffff_ffff_ffff,
        u64::MAX,
        0xa50f_1234_5678_9abc,
    ];
    for (kind, word) in fixture().filter(|(kind, _)| matches!(*kind, "subp" | "gmi" | "irg")) {
        for a in values {
            for b in values {
                let mut state = initial();
                assign(&mut state, ((word >> 5) & 31) as usize, a);
                let rm = ((word >> 16) & 31) as usize;
                if kind == "subp" || rm != 31 {
                    assign(&mut state, rm, b);
                }
                let engine =
                    compare_memory_sequence(&[word, 0x9a9f27e8, 0xd4000001], &state, 64, false);
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0, "{word:x}");
                }
            }
        }
    }
}

#[test]
fn compatibility_register_lowering_survives_full_caller_saved_pressure_and_fp_memory_mixing() {
    let words: Vec<_> = (0..31).map(|r| 0x91000400 | (r << 5) | r).collect();
    for (_, word) in fixture()
        .filter(|(kind, _)| matches!(*kind, "strip" | "code" | "irg" | "gmi" | "subp" | "addg"))
    {
        let mut program = words.clone();
        program.extend_from_slice(&[0x4e228420, word, 0x3d800020, 0xd4000001]); // vector add + Q store
        let mut state = initial();
        state.registers[1] = 0x11fff; // prefix increments x1 before memory
        let engine = compare_memory_sequence(&program, &state, 64, true);
        if NATIVE_COMPILED {
            assert_eq!(engine.stats.fallback_instructions, 0);
        }
    }
}

#[test]
fn compatibility_memory_faults_keep_dirty_prefixes_destinations_writeback_and_partial_bytes() {
    // Both keys, zero/tag-only stores, LDG, and all STGP writeback modes.
    let forms = [
        0xf8201c20, 0xf8a01c20, 0xd9601c20, 0xd9e01c20, 0xd9201c20, 0xd9a01c20, 0xd9600020,
        0x69008820, 0x69808820, 0x68808820, 0xd9e00820, 0xd9600820,
    ];
    for word in forms {
        for base in [0x2001, 0x2ff0, 0x3000, 0xffff_ffff_ffff_fff0] {
            for second in [None, Some(Permissions::R), Some(Permissions::NONE)] {
                for budget in [1, 64] {
                    let words = [0xb1000529, word, 0xd4000001];
                    let mut a = memory(&words);
                    let mut b = memory(&words);
                    for m in [&mut a, &mut b] {
                        m.write(0x2000, &[0x7b; PAGE_SIZE as usize]).unwrap();
                        if let Some(permissions) = second {
                            m.map(0x3000, PAGE_SIZE, permissions).unwrap();
                        }
                    }
                    let mut state = initial();
                    state.registers[1] = base;
                    let mut expected = trames_interpreter::Cpu::new(0, 0);
                    let mut actual = Cpu::new(0, 0);
                    expected.restore_architectural_state(&state);
                    actual.restore_architectural_state(&state);
                    let mut engine = Engine::default();
                    for _ in 0..4 {
                        let x = expected.run_slice(&mut a, budget);
                        let y = actual.run_slice(&mut engine, &mut b, budget);
                        assert_eq!(
                            format!("{x:?}"),
                            format!("{y:?}"),
                            "{word:x}; base={base:x}; second={second:?}"
                        );
                        assert_eq!(actual.architectural_state(), expected.architectural_state());
                        assert_eq!(actual.fault_retired(), expected.fault_retired());
                        assert_eq!(
                            a.read_array::<4096>(0x2000).unwrap(),
                            b.read_array::<4096>(0x2000).unwrap()
                        );
                        for (i, original) in words.into_iter().enumerate() {
                            assert_eq!(b.fetch_u32(0x1000 + i as u64 * 4).unwrap(), original);
                        }
                        if !matches!(x, SliceOutcome::Yield { .. }) {
                            break;
                        }
                    }
                    if NATIVE_COMPILED {
                        assert_eq!(engine.stats.fallback_instructions, 0);
                    }
                }
            }
        }
    }
}

#[test]
fn zero_tag_permission_checks_do_not_publish_data_writes_but_zeroing_and_stgp_do() {
    for word in [
        0xd9200820, 0xd9a00820, 0xd9600020, 0xd9600820, 0xd9e00820, 0x69000820,
    ] {
        let mut state = initial();
        state.registers[1] = 0x12000;
        for mode in 0..3 {
            let engine = compare_memory_sequence_mode(
                &[0xc85f7c23, word, 0xc8047c23, 0xd4000001],
                &state,
                64,
                mode,
            );
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn masked_pointer_and_zeroing_memory_reuse_native_aliases_after_warmup() {
    if !NATIVE_COMPILED {
        return;
    }
    for word in [0xf8200420, 0xf8a00420, 0xd9600820, 0xd9e00820, 0x69000820] {
        let mut words = vec![word; 8];
        words.push(0xd4000001);
        let mut m = memory(&words);
        m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
        m.write(0x10000, &vec![0; hardware_span() as usize])
            .unwrap();
        let mut cpu = Cpu::new(0x1000, 0x2800);
        let mut engine = Engine::default();
        for _ in 0..8 {
            cpu.set_pc(0x1000);
            cpu.set_x(1, 0xa5aa_0000_0001_0000);
            assert!(matches!(
                cpu.run_slice(&mut engine, &mut m, 64),
                SliceOutcome::Syscall { instructions: 9 }
            ));
        }
        assert_eq!(engine.stats.fallback_instructions, 0);
        assert!(
            engine.memory_stats().hardware >= 56,
            "{word:x}: {:?}",
            engine.memory_stats()
        );
        assert_eq!(engine.memory_stats().staged, 0);
    }
}

#[test]
fn tag_alignment_faults_after_a_reused_unaligned_data_alias_preserve_the_first_store() {
    let mut state = initial();
    state.registers[1] = 0xa5aa_0000_0001_2001;
    for mode in [0, 2] {
        for zero in [0xd9600820, 0xd9e00820] {
            let engine =
                compare_memory_sequence_mode(&[0x69000820, zero, 0xd4000001], &state, 64, mode);
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
            }
        }
    }
}
