// SPDX-License-Identifier: GPL-3.0-or-later
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::{Aarch64State, Registers};
use trames_jit::{Cpu, Engine, NATIVE_COMPILED};
use trames_memory::{CpuMemory, Memory, Permissions, PAGE_SIZE};

#[path = "support/scalar_category.rs"]
mod scalar_category;

#[path = "support/abstract_memory_category.rs"]
mod abstract_memory_category;

fn memory(words: &[u32]) -> Memory {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    memory.map(0x2000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, word) in words.iter().enumerate() {
        memory
            .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    memory
}
fn initial() -> Aarch64State {
    let mut state = Aarch64State {
        pc: 0x1000,
        sp: 0x2ff0,
        tpidr_el0: 0x12345678,
        tpidr2_el0: 0x9876,
        nzcv: 0xb0000000,
        fpcr: 0,
        fpsr: 0x10,
        ..Default::default()
    };
    let mut seed = 0x81a5f332168beccd_u64;
    for reg in &mut state.registers {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *reg = seed;
    }
    for (i, vector) in state.vectors.iter_mut().enumerate() {
        *vector = (u128::MAX / 33).wrapping_mul(i as u128 + 1);
    }
    state
}

fn hardware_span() -> u64 {
    (4 * PAGE_SIZE).max(trames_memory::host_mapping_granule() as u64)
}

// Compare whole architectural state, canonical bytes and precise retirement on
// both sides of every slice, including faults after a dirty native prefix.
fn compare_memory_sequence(
    words: &[u32],
    state: &Aarch64State,
    budget: u64,
    parallel: bool,
) -> Engine {
    compare_memory_sequence_mode(words, state, budget, if parallel { 2 } else { 0 })
}
fn compare_memory_sequence_mode(
    words: &[u32],
    state: &Aarch64State,
    budget: u64,
    mode: u8,
) -> Engine {
    let parallel = mode != 0;
    let mut a = memory(words);
    let mut b = memory(words);
    for m in [&mut a, &mut b] {
        m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
        let bytes: Vec<_> = (0..hardware_span())
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(0x85))
            .collect();
        m.write(0x10000, &bytes).unwrap();
    }
    let mut expected = trames_interpreter::Cpu::new(0, 0);
    let mut actual = Cpu::new(0, 0);
    expected.restore_architectural_state(state);
    actual.restore_architectural_state(state);
    let mut engine = Engine::default();
    let mut ra = trames_memory::parallel::Registry::default();
    let mut rb = trames_memory::parallel::Registry::default();
    let mut va = parallel.then(|| a.parallel_view(&mut ra).unwrap());
    let mut vb = parallel.then(|| b.parallel_view(&mut rb).unwrap());
    if mode == 2 {
        assert!(unsafe {
            trames_memory::parallel::View::try_private_epoch(&mut [va.as_mut().unwrap()])
        });
        assert!(unsafe {
            trames_memory::parallel::View::try_private_epoch(&mut [vb.as_mut().unwrap()])
        });
    }
    let mut reference_engine = trames_interpreter::Engine::default();
    for _ in 0..64 {
        let x = if parallel {
            expected.run_parallel(&mut reference_engine, va.as_mut().unwrap(), budget)
        } else {
            expected.run_slice(&mut a, budget)
        };
        let y = if parallel {
            actual.run_parallel(&mut engine, vb.as_mut().unwrap(), budget)
        } else {
            actual.run_slice(&mut engine, &mut b, budget)
        };
        assert_eq!(format!("{x:?}"), format!("{y:?}"), "words={words:x?}");
        let actual_state = actual.architectural_state();
        let expected_state = expected.architectural_state();
        if actual_state != expected_state {
            eprintln!("register differences {:?}; nzcv={:x}/{:x}; words={words:x?}; budget={budget}; parallel={parallel}",
                actual_state.registers.iter().zip(expected_state.registers.iter()).enumerate().filter(|(_, (a,b))| a!=b).collect::<Vec<_>>(),actual_state.nzcv,expected_state.nzcv);
        }
        assert_eq!(actual_state, expected_state, "words={words:x?}");
        assert_eq!(actual.fault_retired(), expected.fault_retired());
        let mut left = vec![0; hardware_span() as usize];
        let mut right = left.clone();
        if parallel {
            va.as_ref().unwrap().read(0x10000, &mut left).unwrap();
            vb.as_ref().unwrap().read(0x10000, &mut right).unwrap();
        } else {
            a.read(0x10000, &mut left).unwrap();
            b.read(0x10000, &mut right).unwrap();
        }
        assert_eq!(left, right, "words={words:x?}");
        if !matches!(x, SliceOutcome::Yield { .. }) {
            return engine;
        }
    }
    panic!("sequence did not terminate");
}

fn host_capability(bit: u32) -> bool {
    !NATIVE_COMPILED || trames_jit::host_features().unwrap().hwcap & (1 << bit) != 0
}

fn structure_word(base: u32, rt: u32, rn: u32, post: u32) -> u32 {
    base | (rn << 5)
        | rt
        | if post == 0 {
            0
        } else {
            (1 << 23) | (post << 16)
        }
}

#[test]
fn multiple_structures_keep_arrangements_interleaving_wrapped_lists_and_writeback() {
    if !host_capability(1) {
        return;
    }
    for q in 0..2 {
        for size in 0..4 {
            for opcode in [0, 2, 4, 6, 7, 8, 10] {
                if q == 0 && size == 3 && matches!(opcode, 0 | 4 | 8) {
                    continue;
                }
                for load in 0..2 {
                    for rt in [0, 15, 31] {
                        let rn = if rt == 15 { 31 } else { 1 };
                        for post in [0, 31, 3, rn] {
                            let word = structure_word(
                                0x0c000000
                                    | (q << 30)
                                    | (size << 10)
                                    | (opcode << 12)
                                    | (load << 22),
                                rt,
                                rn,
                                post,
                            );
                            let mut state = initial();
                            state.registers[1] = 0xab00_0000_0001_0040;
                            state.sp = 0x10080;
                            state.registers[3] = 17;
                            let words = [0x4ea1843f, word, 0xd4000001];
                            for budget in [1, 64] {
                                let e =
                                    compare_memory_sequence(&words, &state, budget, budget == 64);
                                if NATIVE_COMPILED {
                                    assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                                    assert_eq!(e.memory_stats().instructions, 1, "{word:08x}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn lane_structures_preserve_untouched_bits_and_replicates_clear_upper_halves() {
    if !host_capability(1) {
        return;
    }
    for count in 1..=4 {
        for power in 0..4 {
            for lane in 0..(16 >> power) {
                let (q, s, size, scale) = match power {
                    0 => (lane >> 3, (lane >> 2) & 1, lane & 3, 0),
                    1 => (lane >> 2, (lane >> 1) & 1, (lane & 1) << 1, 1),
                    2 => (lane >> 1, lane & 1, 0, 2),
                    _ => (lane, 0, 1, 2),
                };
                for load in 0..2 {
                    for rt in [7, 31] {
                        for post in [0, 31, 3] {
                            let opcode = (scale << 1) | ((count - 1) >> 1);
                            let word = structure_word(
                                0x0d000000
                                    | (q << 30)
                                    | (load << 22)
                                    | (((count - 1) & 1) << 21)
                                    | (opcode << 13)
                                    | (s << 12)
                                    | (size << 10),
                                rt,
                                1,
                                post,
                            );
                            let mut state = initial();
                            state.registers[1] = 0x10040;
                            state.registers[3] = 19;
                            for budget in [1, 64] {
                                let e = compare_memory_sequence(
                                    &[0x4ea1843f, word, 0xd4000001],
                                    &state,
                                    budget,
                                    budget == 64,
                                );
                                if NATIVE_COMPILED {
                                    assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                                    assert_eq!(e.memory_stats().instructions, 1, "{word:08x}");
                                }
                            }
                        }
                    }
                }
            }
            for q in 0..2 {
                for post in [0, 31, 3] {
                    let opcode = 6 | ((count - 1) >> 1);
                    let word = structure_word(
                        0x0d400000
                            | (q << 30)
                            | (((count - 1) & 1) << 21)
                            | (opcode << 13)
                            | (power << 10),
                        31,
                        1,
                        post,
                    );
                    let mut state = initial();
                    state.registers[1] = 0x10ff5;
                    state.registers[3] = u64::MAX - 3;
                    for budget in [1, 64] {
                        let e = compare_memory_sequence(
                            &[word, 0xd4000001],
                            &state,
                            budget,
                            budget == 64,
                        );
                        if NATIVE_COMPILED {
                            assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                            assert_eq!(e.memory_stats().instructions, 1, "{word:08x}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn structure_groups_survive_dirty_repacking_cross_pages_and_precise_faults() {
    if !host_capability(1) {
        return;
    }
    for rt in [0, 7, 15, 30, 31] {
        for load in 0..2 {
            for class in [0x4c002000, 0x4c004000, 0x4d20b000, 0x4d60ec00] {
                if class == 0x4d60ec00 && load == 0 {
                    continue;
                }
                let word = structure_word(class | (load << 22), rt, 1, 3);
                let mut words = Vec::new();
                // Deliberately scramble the existing bindings so wrapped groups
                // require relocation, cycles, dirty evictions and helper reloads.
                for reg in (0..23).map(|r| (r * 13) & 31) {
                    words.push(0x4ea08400 | (reg << 16) | (reg << 5) | reg);
                }
                words.extend_from_slice(&[word, 0x4ea08400, 0xf9400085, 0x4ea08400, 0xd4000001]);
                for address in [0x10000, 0x10ff7, 0x10000 + hardware_span() - 7] {
                    let mut state = initial();
                    state.registers[1] = address;
                    state.registers[3] = 9;
                    state.registers[4] = 0x11000;
                    for budget in [1, 8, 64] {
                        for parallel in [false, true] {
                            let e = compare_memory_sequence(&words, &state, budget, parallel);
                            if NATIVE_COMPILED {
                                assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn reserved_structure_encodings_keep_reached_pc_faults() {
    let mut state = initial();
    state.registers[1] = 0x10000;
    for word in [
        0x4c417020,
        0x4c607020,
        0x4c401020,
        0x0c400c20,
        0x4d414020,
        0x4d404420,
        0x4d409420,
        0x4d40c020 | (1 << 12),
        0x4d00c020,
    ] {
        for budget in [1, 64] {
            let e = compare_memory_sequence(
                &[0x91000400, word, 0xd4000001],
                &state,
                budget,
                budget == 64,
            );
            if NATIVE_COMPILED {
                assert_eq!(e.memory_stats().instructions, 0, "{word:08x}");
            }
        }
    }
}

#[test]
fn structure_neon_loops_reuse_aliases_without_fallback_or_staging() {
    if !NATIVE_COMPILED || !host_capability(1) {
        return;
    }
    for (load, store) in [
        (0x4c40a03f, 0x4c00a03f), // LD1/ST1 {v31,v0}
        (0x4c40803f, 0x4c00803f), // LD2/ST2
        (0x4d60c03f, 0x4d20003f),
    ] {
        // LD2R / ST2 lane
        let words = [load, 0x4ea38400, store, 0xf1000442, 0x54ffff81, 0xd4000001];
        let mut state = initial();
        state.registers[1] = 0x10000;
        state.registers[2] = 32;
        for parallel in [false, true] {
            let e = compare_memory_sequence(&words, &state, 256, parallel);
            assert_eq!(e.stats.fallback_instructions, 0);
            assert_eq!(e.memory_stats().instructions, 64);
            assert_eq!(e.memory_stats().staged, 0);
            assert!(e.memory_stats().hardware >= 60);
            assert!(e.memory_stats().direct >= 60);
            assert_eq!(e.memory_stats().fused_entries, 1);
            assert!(e.compilation_stats().address_reuses > 0);
        }
    }
}

fn compare_fp_word(word: u32, state: &Aarch64State) {
    for budget in [1, 64] {
        let e = compare_memory_sequence(&[word, 0xd4000001], state, budget, budget == 64);
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
            assert_eq!(e.memory_stats().instructions, 0);
        }
    }
}

#[test]
fn simd_copy_permute_and_immediate_category_matches_reference() {
    if !host_capability(1) {
        return;
    }
    let mut words = Vec::new();
    for q in 0..2u32 {
        for imm in 1..32u32 {
            let power = imm.trailing_zeros();
            if power > 3 {
                continue;
            }
            for base in [0x0e000400, 0x0e000c00] {
                if power != 3 || q != 0 {
                    words.push(base | (q << 30) | (imm << 16));
                }
            }
            if (q != 0) == (power == 3) {
                words.push(0x0e003c00 | (q << 30) | (imm << 16));
            }
            if power < if q != 0 { 3 } else { 2 } {
                words.push(0x0e002c00 | (q << 30) | (imm << 16));
            }
            words.push(0x5e000400 | (imm << 16));
            words.push(0x4e001c00 | (imm << 16));
            for src in 0..16 {
                words.push(0x6e000400 | (imm << 16) | (src << 11));
            }
        }
        for op in [
            0x0e001800, 0x0e005800, 0x0e002800, 0x0e006800, 0x0e003800, 0x0e007800,
        ] {
            for size in 0..4 {
                if size < 3 || q != 0 {
                    words.push(op | (q << 30) | (size << 22));
                }
            }
        }
        for (op, max_size) in [(0x0e201800, 0), (0x2e200800, 1), (0x0e200800, 2)] {
            for size in 0..=max_size {
                words.push(op | (q << 30) | (size << 22));
            }
        }
        for byte in 0..(8 << q) {
            words.push(0x2e000000 | (q << 30) | (byte << 11));
        }
        for mode in 0..16 {
            for invert in 0..2 {
                if mode == 15 && invert != 0 && q == 0 {
                    continue;
                }
                for imm in [0, 1, 0x55, 0x80, 0xff] {
                    words.push(
                        0x0f000400
                            | (q << 30)
                            | (invert << 29)
                            | (mode << 12)
                            | ((imm >> 5) << 16)
                            | ((imm & 31) << 5),
                    );
                }
            }
        }
        if host_capability(10) {
            for imm in [0, 1, 0x55, 0x80, 0xff] {
                words.push(0x0f00fc00 | (q << 30) | ((imm >> 5) << 16) | ((imm & 31) << 5));
            }
        }
    }
    for word in words {
        // Immediate and lane selectors share fields with ordinary register
        // encodings: change only the actual Rn/Rd fields for this family.
        let immediate = word & 0x9ff80400 == 0x0f000400;
        for (rd, rn, rm) in [(0, 1, 2), (31, 31, 31), (1, 1, 1), (0, 31, 0)] {
            let word = if immediate {
                (word & !31) | rd
            } else {
                (word & !0x3ff) | (rn << 5) | rd
            };
            let word = if matches!(word & 0xbfe08400, 0x2e000000)
                || matches!(
                    word & 0xbf20fc00,
                    0x0e001800 | 0x0e005800 | 0x0e002800 | 0x0e006800 | 0x0e003800 | 0x0e007800
                ) {
                (word & !0x1f0000) | (rm << 16)
            } else {
                word
            };
            compare_fp_word(word, &initial());
        }
    }
}

#[test]
fn table_lookup_category_keeps_all_table_registers_and_aliases_live() {
    if !host_capability(1) {
        return;
    }
    for q in 0..2 {
        for count in 1..=4 {
            for merge in 0..2 {
                for rn in [0, 14, 29, 30, 31] {
                    for (rd, rm) in [(0, 7), (31, 31), (rn, rn), ((rn + 1) & 31, (rn + 2) & 31)] {
                        let word = 0x0e000000
                            | (q << 30)
                            | ((count - 1) << 13)
                            | (merge << 12)
                            | (rm << 16)
                            | (rn << 5)
                            | rd;
                        for pattern in [0u128, u128::MAX, 0x3f302f201f100f000102030405060708] {
                            let mut state = initial();
                            state.vectors[rm as usize] = pattern;
                            for budget in [1, 64] {
                                let e = compare_memory_sequence(
                                    &[word, 0xd4000001],
                                    &state,
                                    budget,
                                    budget == 64,
                                );
                                if NATIVE_COMPILED {
                                    assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn complete_crypto_category_preserves_accumulators_aliases_and_exact_boundaries() {
    let mut cases = vec![
        (0x4e284800, 3, false),
        (0x4e285800, 3, false),
        (0x4e286800, 3, false),
        (0x4e287800, 3, false),
        (0x5e280800, 5, false),
        (0x5e281800, 5, false),
        (0x5e282800, 6, false),
        (0x5e000000, 5, true),
        (0x5e001000, 5, true),
        (0x5e002000, 5, true),
        (0x5e003000, 5, true),
        (0x5e004000, 6, true),
        (0x5e005000, 6, true),
        (0x5e006000, 6, true),
        (0x0e20e000, 1, true),
        (0x4e20e000, 1, true),
        (0x0ee0e000, 4, true),
        (0x4ee0e000, 4, true),
        (0xcec08000, 21, false),
        (0xcec08400, 19, false),
        (0xce608000, 21, true),
        (0xce608400, 21, true),
        (0xce608800, 21, true),
        (0xce608c00, 17, true),
        (0xce60c000, 18, true),
        (0xce60c400, 18, true),
        (0xce60c800, 19, true),
        (0xce000000, 17, true),
        (0xce200000, 17, true),
        (0xce400000, 18, true),
    ];
    for opcode in [0xce408000, 0xce408400, 0xce408800, 0xce408c00] {
        for imm in 0..4 {
            cases.push((opcode | (imm << 12), 18, true));
        }
    }
    for imm in 0..64 {
        cases.push((0xce800000 | (imm << 10), 17, true));
    }
    for (word, cap, binary) in cases {
        if !host_capability(cap) {
            continue;
        }
        for (rd, rn, rm, ra) in [
            (0, 1, 2, 3),
            (31, 31, 31, 31),
            (1, 1, 2, 1),
            (2, 1, 2, 2),
            (3, 2, 1, 3),
        ] {
            let mut word = word | (rn << 5) | rd;
            if binary {
                word |= rm << 16;
            }
            if matches!(word & 0xffe08000, 0xce000000 | 0xce200000 | 0xce400000) {
                word |= ra << 10;
            }
            for pattern in [0, u128::MAX, 0x000102030405060708090a0b0c0d0e0f] {
                let mut state = initial();
                state.vectors[rd as usize] = pattern;
                compare_fp_word(word, &state);
            }
        }
    }
}

#[test]
fn complete_move_and_crypto_blocks_preserve_pressure_helpers_and_dynamic_pc() {
    if !host_capability(1) {
        return;
    }
    for (rn, rm, rd) in [(31, 0, 31), (29, 31, 0), (0, 0, 2)] {
        let mut words = Vec::new();
        for reg in (0..23).map(|r| (r * 13) & 31) {
            words.push(0x4ea08400 | (reg << 16) | (reg << 5) | reg);
        }
        words.extend_from_slice(&[
            0x4e006000 | (rn << 5) | (rm << 16) | rd, // TBL four registers
            0x4e007000 | (rn << 5) | (rm << 16) | rd, // TBX with destination dependency
            0x6e180400 | (rd << 5) | 31,              // INS v31.d[1],vd.d[0]
            0x4e183c00 | (31 << 5) | 4,               // UMOV x4,v31.d[1]
            0x4e083c00 | (rd << 5) | 5,               // UMOV x5,vd.d[0]
            0x3dc00026, // LDR q6,[x1]: Rust callback can clobber all caller vectors
        ]);
        if host_capability(3) {
            words.extend_from_slice(&[0x4e284820, 0x4e286800]);
        }
        words.extend_from_slice(&[0x4e0073e0, 0xd61f00a0]); // TBX + BR x5
        let mut state = initial();
        state.registers[1] = 0x10ff7;
        // Table/index/destination overlap. Both engines must publish the same
        // computed branch target, including an unmapped target after the helper.
        state.vectors.fill(0x00000000000010100000000000001010);
        state.vectors[rm as usize] = u128::MAX;
        for budget in [1, 8, 64] {
            let e = compare_memory_sequence(&words, &state, budget, budget == 64);
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn unavailable_crypto_extensions_fault_before_any_interpreter_implementation() {
    if !NATIVE_COMPILED {
        return;
    }
    for (word, cap) in [
        (0x4e284820, 3),
        (0x0ee2e020, 4),
        (0x5e020020, 5),
        (0x5e024020, 6),
        (0xce020c20, 17),
        (0xce42ac20, 18),
        (0xcec08420, 19),
        (0xce628020, 21),
    ] {
        if host_capability(cap) {
            continue;
        }
        let mut m = memory(&[0x91000400, word, 0xd4000001]);
        let mut c = Cpu::new(0x1000, 0);
        let before = c.architectural_state().vectors;
        let mut e = Engine::default();
        let out = c.run_slice(&mut e, &mut m, 64);
        assert!(
            matches!(
                out,
                SliceOutcome::Fault(trames_engine::CpuFault::Instruction { pc: 0x1004, .. })
            ),
            "{word:08x}: {out:?}"
        );
        assert_eq!((c.pc(), c.x(0), c.fault_retired()), (0x1004, 1, 1));
        assert_eq!(c.architectural_state().vectors, before);
        assert_eq!(e.stats.fallback_instructions, 0);
    }
}

#[test]
fn system_register_category_uses_existing_guest_fields_and_preserves_live_banks() {
    for (read, write) in [
        (0xd53bd040, 0xd51bd040),
        (0xd53bd0a0, 0xd51bd0a0),
        (0xd53b4400, 0xd51b4400),
        (0xd53b4420, 0xd51b4420),
    ] {
        for (source, dest) in [(0, 1), (31, 31), (1, 1), (30, 0)] {
            for value in [0, u64::MAX, 0x07c80000, 0x0800009f, 0x1234567890abcdef] {
                let mut state = initial();
                state.registers[source.min(30) as usize] = value;
                state.fpcr = 0xffff_ffff;
                state.fpsr = 0xffff_ffff;
                let words = [read | dest, write | source, read | dest, 0xd4000001];
                for budget in [1, 64] {
                    for parallel in [false, true] {
                        let e = compare_memory_sequence(&words, &state, budget, parallel);
                        if NATIVE_COMPILED {
                            assert_eq!(e.stats.fallback_instructions, 0, "{words:x?}");
                        }
                    }
                }
            }
        }
    }
    for read in [0xd53bd060, 0xd53b0020, 0xd53b00e0] {
        for rd in [0, 1, 31] {
            compare_fp_word(read | rd, &initial());
        }
    }
    let mut words = Vec::new();
    for r in 0..24 {
        words.push(0x91000400 | (r << 5) | r);
    }
    words.extend_from_slice(&[
        0xd51bd040, 0xd53bd05f, 0xd51bd0a1, 0xd53bd0a2, 0x1e221820, 0xd53b4423, 0xd51b4424,
        0xd53b4425, 0xd51b4406, 0x1e292907, 0xd53b440a, 0x3dc0003f, 0xd53bd04b, 0xd53b442c,
        0xd4000001,
    ]);
    let mut state = initial();
    state.registers[1] = 0x10ff7 - 1;
    state.registers[4] = 0;
    state.registers[6] = 2 << 22;
    state.vectors[1] = 1f32.to_bits() as u128;
    state.vectors[2] = 0;
    for budget in [1, 8, 64] {
        for parallel in [false, true] {
            let e = compare_memory_sequence(&words, &state, budget, parallel);
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn cache_maintenance_barrier_and_hint_category_keeps_precise_memory_semantics() {
    for word in [0xd50b7420, 0xd50b7b20, 0xd50b7a20, 0xd50b7e20, 0xd50b7520] {
        for reg in [0, 1, 30, 31] {
            for address in [
                0x10000,
                0x10037,
                0x10fff,
                0x10000 + hardware_span() - 1,
                0x10000 + hardware_span(),
            ] {
                let mut state = initial();
                state.registers[reg.min(30) as usize] = address;
                for budget in [1, 64] {
                    for parallel in [false, true] {
                        let e = compare_memory_sequence(
                            &[0x910004a5, word | reg, 0xd4000001],
                            &state,
                            budget,
                            parallel,
                        );
                        if NATIVE_COMPILED {
                            assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                        }
                    }
                }
            }
        }
    }
    let mut state = initial();
    state.registers[1] = 0x10037;
    let e = compare_memory_sequence(
        &[0xf9400020, 0xd50b7421, 0xf9400022, 0xd4000001],
        &state,
        64,
        false,
    );
    if NATIVE_COMPILED {
        assert_eq!(e.stats.fallback_instructions, 0);
        assert_eq!(e.memory_stats().instructions, 3);
    }
    for base in [0xd503309f, 0xd50330bf, 0xd50330df] {
        for option in 0..16 {
            compare_fp_word(base | (option << 8), &initial());
        }
    }
    for word in [
        0xd503201f, 0xd503203f, 0xd503205f, 0xd503207f, 0xd503209f, 0xd50320bf, 0xd50320df,
        0xd50320ff, 0xd503221f, 0xd503229f, 0xd503211f, 0xd503215f, 0xd503219f, 0xd50321df,
        0xd503231f, 0xd503235f, 0xd503239f, 0xd50323df, 0xd503241f, 0xd503245f, 0xd503249f,
        0xd50324df, 0xd503251f, 0xd503233f, 0xd503237f, 0xd50323bf, 0xd50323ff, 0xd50322df,
        0xd503225f, 0xd503227f, 0xd5031000, 0xd503103f,
    ] {
        compare_fp_word(word, &initial());
    }
    if host_capability(29) {
        compare_fp_word(0xd50330ff, &initial());
    }
}

#[test]
fn trap_and_native_call_category_caches_boundaries_without_interpreter_entry() {
    for instruction in [
        0xd4200000, 0xd4200020, 0xd43fffe0, 0xd4400000, 0xd44a8a40, 0xd45fffe0,
    ] {
        let e = compare_memory_sequence(
            &[0x91000400, instruction, 0xd4000001],
            &initial(),
            64,
            false,
        );
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
    for mode in 0..5 {
        for module in [0x10005, 0x10006, 0x10007, 0x10008] {
            let mut a = memory(&[0x91000400, 0xd44a8a40, 0xd4000001]);
            let mut b = a.clone();
            let mut r = trames_interpreter::Cpu::new(0x1000, 0);
            let mut c = Cpu::new(0x1000, 0);
            match mode {
                0 => {}
                1 => {
                    c.set_native_calls(true);
                    r.set_native_calls(true);
                }
                2 => {
                    c.set_vulkan_calls(true);
                    r.set_vulkan_calls(true);
                }
                3 => {
                    c.set_video_calls(true);
                    r.set_video_calls(true);
                }
                _ => {
                    c.set_audio_calls(true);
                    r.set_audio_calls(true);
                }
            }
            c.set_x(16, module);
            r.set_x(16, module);
            c.set_x(17, 7);
            r.set_x(17, 7);
            let mut e = Engine::default();
            for budget in [1, 64, 64] {
                let x = r.run_slice(&mut a, budget);
                let y = c.run_slice(&mut e, &mut b, budget);
                assert_eq!(format!("{x:?}"), format!("{y:?}"));
                assert_eq!(c.architectural_state(), r.architectural_state());
                assert_eq!(c.fault_retired(), r.fault_retired());
                if matches!(x, SliceOutcome::Syscall { .. }) {
                    break;
                }
            }
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn architectural_counter_category_and_clock_samples_share_the_host_domain() {
    let frequency = <Cpu as Backend>::counter_frequency();
    assert!(frequency > 0);
    for word in [0xd53be000, 0xd53be020, 0xd53be040, 0xd53be0a0, 0xd53be0c0] {
        for rd in [0, 5, 31] {
            // Explicit guest ordering makes the enclosing host bracket valid
            // even for the architecturally relaxed counter aliases.
            let mut m = memory(&[0xd5033fdf, word | rd, 0xd4000001]);
            let mut c = Cpu::new(0x1000, 0);
            let mut e = Engine::default();
            let before = trames_interpreter::counter::read();
            assert!(matches!(
                c.run_slice(&mut e, &mut m, 64),
                SliceOutcome::Syscall { instructions: 3 }
            ));
            let after = trames_interpreter::counter::read();
            if rd != 31 {
                if word == 0xd53be000 {
                    assert_eq!(c.x(rd as usize), frequency);
                } else {
                    assert!((before..=after).contains(&c.x(rd as usize)));
                }
            }
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0);
            }
        }
    }
    if let Some(sample) = <Cpu as Backend>::clock_sample() {
        assert_eq!(sample.frequency, frequency);
        assert!(trames_interpreter::counter::read() >= sample.ticks);
    }
}

#[test]
fn maintenance_only_checks_translation_and_zeroes_one_guest_cache_line() {
    for permission in [
        Permissions {
            read: false,
            write: false,
            execute: false,
        },
        Permissions::RX,
    ] {
        let words = [0xd50b7b21, 0xd50b7a21, 0xd50b7e21, 0xd50b7521, 0xd4000001];
        let mut m = memory(&words);
        m.protect(0x2000, PAGE_SIZE, permission).unwrap();
        let mut c = Cpu::new(0x1000, 0);
        c.set_x(1, 0x2fff);
        let mut e = Engine::default();
        assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 5));
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
    let mut m = memory(&[0xd50b7421, 0xd4000001]);
    m.write(0x2000, &[0xa5; 192]).unwrap();
    m.protect(
        0x2000,
        PAGE_SIZE,
        Permissions {
            read: false,
            write: true,
            execute: false,
        },
    )
    .unwrap();
    let mut c = Cpu::new(0x1000, 0);
    c.set_x(1, 0x207f);
    let mut e = Engine::default();
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 2));
    m.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
    assert_eq!(m.read_array::<64>(0x2000).unwrap(), [0xa5; 64]);
    assert_eq!(m.read_array::<64>(0x2040).unwrap(), [0; 64]);
    assert_eq!(m.read_array::<64>(0x2080).unwrap(), [0xa5; 64]);
    if NATIVE_COMPILED {
        assert_eq!(e.stats.fallback_instructions, 0);
    }
}

#[test]
fn cached_native_call_rechecks_current_opt_ins_and_instruction_identity() {
    let mut m = memory(&[0xd44a8a40]);
    let mut c = Cpu::new(0x1000, 0);
    c.set_x(16, 0x10006);
    c.set_x(17, 17);
    c.set_vulkan_calls(true);
    let mut e = Engine::default();
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 1),
        SliceOutcome::NativeCall {
            instructions: 0,
            module: 0x10006,
            function: 17,
            ..
        }
    ));
    c.set_vulkan_calls(false);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 1),
        SliceOutcome::Fault(_)
    ));
    assert_eq!(c.fault_retired(), 0);
    c.set_audio_calls(true);
    c.set_x(16, 0x10008);
    c.set_x(17, 18);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 1),
        SliceOutcome::NativeCall {
            instructions: 0,
            module: 0x10008,
            function: 18,
            ..
        }
    ));
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write_array(0x1000, 0xd4000001u32.to_le_bytes()).unwrap();
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 1)), ("syscall", 1));
    if NATIVE_COMPILED {
        assert_eq!(e.stats.fallback_instructions, 0);
    }
}

#[test]
fn random_register_category_publishes_architectural_success_flags() {
    if !NATIVE_COMPILED || trames_jit::host_features().unwrap().hwcap2 & (1 << 16) == 0 {
        return;
    }
    for base in [0xd53b2400, 0xd53b2420] {
        for rd in [0, 30, 31] {
            let mut m = memory(&[base | rd, 0xd4000001]);
            let mut c = Cpu::new(0x1000, 0);
            let mut e = Engine::default();
            let mut state = initial();
            state.nzcv = 0xf0000000;
            c.restore_architectural_state(&state);
            assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 2));
            let flags = c.architectural_state().nzcv;
            assert!(flags == 0 || flags == 0x40000000);
            if flags == 0x40000000 && rd != 31 {
                assert_eq!(c.x(rd as usize), 0);
            }
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
}

#[test]
fn counter_frequency_tracks_elapsed_time_across_worker_threads() {
    let start = std::time::Instant::now();
    let first = trames_interpreter::counter::read();
    let frequency = <Cpu as Backend>::counter_frequency();
    let threads: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                let a = trames_interpreter::counter::read();
                std::thread::sleep(std::time::Duration::from_millis(10));
                let b = trames_interpreter::counter::read();
                assert!(b >= a);
                (a, b, <Cpu as Backend>::counter_frequency())
            })
        })
        .collect();
    for t in threads {
        let (a, b, f) = t.join().unwrap();
        assert!(a >= first && b >= a);
        assert_eq!(f, frequency);
    }
    let last = trames_interpreter::counter::read();
    let elapsed = start.elapsed().as_nanos();
    let ns = (last - first) as u128 * 1_000_000_000 / frequency as u128;
    // The outer bracket includes scheduling and the two clock-read costs.
    assert!(
        ns <= elapsed + 1_000_000 && ns + 1_000_000 >= elapsed,
        "counter={ns}, instant={elapsed}"
    );
}

#[test]
fn vector_memory_widths_address_modes_and_register_namespaces_match_reference() {
    for (size, opc) in [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (2, 0),
        (2, 1),
        (3, 0),
        (3, 1),
        (0, 2),
        (0, 3),
    ] {
        for (rn, rt) in [(1, 0), (1, 1), (31, 31)] {
            let mut cases =
                vec![(size << 30) | 0x3d000000 | (opc << 22) | (2 << 10) | (rn << 5) | rt];
            for mode in [0, 1, 3] {
                for off in [-16i32, 0, 16] {
                    cases.push(
                        (size << 30)
                            | 0x3c000000
                            | (opc << 22)
                            | (((off as u32) & 511) << 12)
                            | (mode << 10)
                            | (rn << 5)
                            | rt,
                    );
                }
            }
            for option in [2, 3, 6, 7] {
                for scaled in [0, 1] {
                    cases.push(
                        (size << 30)
                            | 0x3c200800
                            | (opc << 22)
                            | (2 << 16)
                            | (option << 13)
                            | (scaled << 12)
                            | (rn << 5)
                            | rt,
                    );
                }
            }
            for word in cases {
                for address in [0xab00_0000_0001_0100, 0xab00_0000_0001_0ff9] {
                    let mut state = initial();
                    state.registers[1] = address;
                    state.registers[2] = 1;
                    state.sp = address;
                    for budget in [1, 64] {
                        let e = compare_memory_sequence(
                            &[
                                0x1e6728de, word, 0xb1000463, word, 0x1e612800, word, 0xd4000001,
                            ],
                            &state,
                            budget,
                            budget == 64,
                        );
                        if NATIVE_COMPILED {
                            assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                        }
                    }
                }
            }
        }
    }
    for opc in 0..3 {
        let pc = 0x1004;
        let displacement = (0x10000 - pc) / 4;
        let word = (opc << 30) | 0x1c000000 | (displacement << 5) | 31;
        let e =
            compare_memory_sequence(&[0x1e6728de, word, word, 0xd4000001], &initial(), 64, true);
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
            assert!(e.memory_stats().hardware > 0);
        }
    }
}

#[test]
fn paired_vector_transfers_keep_one_operand_and_precise_writeback() {
    for opc in 0..3 {
        for load in [false, true] {
            for mode in 0..4 {
                for (rn, rt, rt2) in [(1, 0, 1), (31, 31, 0), (1, 30, 31)] {
                    for off in [-2i32, 0, 2] {
                        let word = (opc << 30)
                            | 0x2c000000
                            | (u32::from(load) << 22)
                            | (mode << 23)
                            | (((off as u32) & 127) << 15)
                            | (rt2 << 10)
                            | (rn << 5)
                            | rt;
                        for address in [0xab00_0000_0001_0100, 0xab00_0000_0001_0ff9] {
                            let mut state = initial();
                            state.registers[1] = address;
                            state.sp = address;
                            for budget in [1, 64] {
                                let e = compare_memory_sequence(
                                    &[0xb1000463, 0x1e6728de, word, word, word, 0xd4000001],
                                    &state,
                                    budget,
                                    budget == 64,
                                );
                                if NATIVE_COMPILED {
                                    assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn mixed_vector_memory_evictions_and_helper_reloads_preserve_every_live_bank() {
    let mut words = Vec::new();
    // More than sixteen dirty guest vectors force allocation/eviction before
    // loads, including a destination's old value at a potential slow exit.
    for reg in (0..23).chain(std::iter::once(31)) {
        words.push(0x4ea08400 | (reg << 16) | (reg << 5) | reg);
    }
    words.extend_from_slice(&[
        0xad40143f,                  // ldp q31,q5,[x1]
        0x4ea58400 | (31 << 5) | 31, // add v31.4s,v31.4s,v5.4s
        0xad00143f,                  // stp q31,q5,[x1]
        0xf9400064,                  // ldr x4,[x3]: ends an address proof and uses a helper
    ]);
    for reg in (0..23).chain(std::iter::once(31)).rev() {
        words.push(0x4ea08400 | (reg << 16) | (reg << 5) | reg);
    }
    words.push(0xd4000001);
    for address in [0x10000, 0x10ff0] {
        // same-page and staged pair
        let mut state = initial();
        state.registers[1] = address;
        state.registers[3] = 0x12000;
        for parallel in [false, true] {
            for budget in [1, 8, 128] {
                let engine = compare_memory_sequence(&words, &state, budget, parallel);
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0);
                }
            }
        }
    }
}

#[test]
fn mixed_vector_loops_reuse_hardware_addresses_without_interpreter_or_bridge_hits() {
    if !NATIVE_COMPILED {
        return;
    }
    for pair in [false, true] {
        let words = if pair {
            vec![
                0xad401020, 0x4ea38400, 0xad001020, 0xf1000442, 0x54ffff81, 0xd4000001,
            ]
        } else {
            vec![
                0x3dc00020, 0x4ea38400, 0x3d800020, 0xf1000442, 0x54ffff81, 0xd4000001,
            ]
        };
        let mut state = initial();
        state.registers[1] = 0x10000;
        state.registers[2] = 32;
        state.vectors[3] = 0x00000001000000010000000100000001;
        for parallel in [false, true] {
            let e = compare_memory_sequence(&words, &state, 256, parallel);
            assert_eq!(e.stats.fallback_instructions, 0);
            assert_eq!(e.memory_stats().instructions, 64);
            assert_eq!(e.memory_stats().staged, 0);
            assert!(e.memory_stats().hardware >= 60, "{:?}", e.memory_stats());
            assert!(e.memory_stats().direct >= 60);
            assert_eq!(e.memory_stats().fused_entries, 1);
            assert!(e.compilation_stats().address_reuses > 0);
        }
    }
}

#[test]
fn mixed_vector_loads_do_not_publish_a_new_destination_before_a_guest_fault() {
    let mut state = initial();
    state.registers[1] = 0x10ff0;
    let words = [0x4e221c1f, 0x1e221820, 0xad40043f, 0xd4000001];
    state.registers[1] = 0x10000 + hardware_span() - 16;
    for budget in [1, 64] {
        let e = compare_memory_sequence(&words, &state, budget, budget == 64);
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
}

#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
#[test]
fn backing_callbacks_see_host_fp_environment_and_cannot_pollute_guest_status() {
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    };
    use trames_memory::{MemoryError, PageBacking};
    fn environment() -> (u64, u64) {
        let (c, s);
        unsafe {
            std::arch::asm!("mrs {c},fpcr","mrs {s},fpsr",c=out(reg)c,s=out(reg)s,options(nostack,preserves_flags));
        }
        (c, s)
    }
    fn host_noise() {
        unsafe {
            std::arch::asm!("fmov s0,#1.0","movi v1.16b,#0","fdiv s0,s0,s1",out("v0") _,out("v1") _,options(nostack,preserves_flags));
        }
    }
    struct Backing {
        bytes: Mutex<Vec<u8>>,
        version: AtomicU64,
        fail: bool,
    }
    impl PageBacking for Backing {
        fn check(&self, _: u64) -> Result<(), MemoryError> {
            Ok(())
        }
        fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), MemoryError> {
            assert_eq!(environment(), (1 << 22, 0x10));
            host_noise();
            if self.fail {
                return Err(MemoryError::BackingIo(5));
            }
            out.copy_from_slice(&self.bytes.lock().unwrap()[offset..offset + out.len()]);
            Ok(())
        }
        fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
            assert_eq!(environment(), (1 << 22, 0x10));
            host_noise();
            self.bytes.lock().unwrap()[offset..offset + bytes.len()].copy_from_slice(bytes);
            self.version.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn sync(&self) -> Result<(), MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            self.version.load(Ordering::Relaxed)
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
            Err(MemoryError::BackingIo(5))
        }
    }
    for (fail, clear) in [(false, false), (true, false), (false, true), (true, true)] {
        let _host = trames_host_compute::Scope::new(1 << 22, 0x10);
        let mut bytes = vec![0; PAGE_SIZE as usize];
        for lane in bytes[..16].chunks_exact_mut(4) {
            lane.copy_from_slice(&1f32.to_le_bytes());
        }
        let backing = Arc::new(Backing {
            bytes: Mutex::new(bytes),
            version: AtomicU64::new(0),
            fail,
        });
        let prefix = 0x1e201800 | (22 << 16) | (21 << 5) | 20;
        let mut words = vec![prefix];
        if clear {
            words.extend_from_slice(&[0xd51b443f, 0xd53b4425, 0xd51b4408, 0xd51bd049]);
        }
        let completed = words.len() as u64;
        words.extend_from_slice(&[0x3dc00020, 0x4e21d400, 0x3d800020, 0xd4000001]);
        let mut m = memory(&words);
        m.map_backed(0x10000, vec![backing.clone()], true, Permissions::RW, false)
            .unwrap();
        let mut c = Cpu::new(0x1000, 0);
        let mut s = initial();
        s.registers[1] = 0x10000;
        s.registers[8] = 0;
        s.registers[9] = 0xabcddcba;
        s.fpcr = 2 << 22;
        s.fpsr = 4;
        s.vectors[21] = 1f32.to_bits() as u128;
        s.vectors[22] = 0;
        s.vectors[1] = (1f32.to_bits() as u128) * 0x00000001000000010000000100000001;
        c.restore_architectural_state(&s);
        let mut e = Engine::default();
        let before_tls: u64;
        unsafe {
            std::arch::asm!("mrs {v},tpidr_el0",v=out(reg)before_tls,options(nomem,nostack,preserves_flags));
        }
        let result = c.run_slice(&mut e, &mut m, 64);
        let after_tls: u64;
        unsafe {
            std::arch::asm!("mrs {v},tpidr_el0",v=out(reg)after_tls,options(nomem,nostack,preserves_flags));
        }
        assert_eq!(after_tls, before_tls);
        assert_eq!(environment(), (1 << 22, 0x10));
        assert_eq!(c.architectural_state().fpsr, if clear { 0 } else { 6 });
        if clear {
            assert_eq!(c.x(5), 0);
            assert_eq!(c.architectural_state().fpcr, 0);
            assert_eq!(c.architectural_state().tpidr_el0, 0xabcddcba);
        }
        assert_eq!(e.stats.fallback_instructions, 0);
        if fail {
            assert!(matches!(result, SliceOutcome::Fault(_)));
            assert_eq!(c.fault_retired(), completed);
            assert_eq!(c.pc(), 0x1000 + completed * 4);
            assert_eq!(c.architectural_state().vectors[0], s.vectors[0]);
        } else {
            assert_eq!(outcome(&result), ("syscall", completed + 4));
            assert_eq!(
                c.architectural_state().vectors[0],
                (2f32.to_bits() as u128) * 0x00000001000000010000000100000001
            );
            assert_eq!(&backing.bytes.lock().unwrap()[..4], &2f32.to_le_bytes());
            assert_eq!(e.memory_stats().staged, 2);
        }
    }
}

#[test]
fn native_scalar_fp_arithmetic_flags_conversions_and_aliases_match_reference() {
    for kind in [0, 1, 3] {
        if kind == 3 && !host_capability(9) {
            continue;
        }
        for (rd, rn, rm) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
            for control in [0, 1 << 22, (2 << 22) | (1 << 24) | (1 << 25)] {
                let mut state = initial();
                state.fpcr = control;
                for op in 0..=8 {
                    compare_fp_word(
                        0x1e200800 | (kind << 22) | (op << 12) | (rm << 16) | (rn << 5) | rd,
                        &state,
                    );
                }
                for op in [0, 1, 2, 3, 8, 9, 10, 11, 12, 14, 15] {
                    compare_fp_word(
                        0x1e204000 | (kind << 22) | (op << 15) | (rn << 5) | rd,
                        &state,
                    );
                }
                for sign in 0..4 {
                    compare_fp_word(
                        0x1f000000
                            | (kind << 22)
                            | ((sign >> 1) << 21)
                            | ((sign & 1) << 15)
                            | (rm << 16)
                            | (3 << 10)
                            | (rn << 5)
                            | rd,
                        &state,
                    );
                }
                for condition in [0, 1, 6, 14, 15] {
                    compare_fp_word(
                        0x1e200c00 | (kind << 22) | (rm << 16) | (condition << 12) | (rn << 5) | rd,
                        &state,
                    );
                    compare_fp_word(
                        0x1e200400
                            | (kind << 22)
                            | (rm << 16)
                            | (condition << 12)
                            | (rn << 5)
                            | 0xb,
                        &state,
                    );
                }
                for zero in [false, true] {
                    for signal in [false, true] {
                        compare_fp_word(
                            0x1e202000
                                | (kind << 22)
                                | (if zero { 8 } else { rm << 16 })
                                | ((signal as u32) << 4)
                                | (rn << 5),
                            &state,
                        );
                    }
                }
                compare_fp_word(0x1e201000 | (kind << 22) | (0x70 << 13) | rd, &state);
            }
        }
        for sf in 0..2 {
            for op in [0, 1, 2, 3, 4, 5, 8, 9, 16, 17, 24, 25] {
                compare_fp_word(
                    (sf << 31) | 0x1e200000 | (kind << 22) | (op << 16) | (1 << 5),
                    &initial(),
                );
            }
        }
    }
    for word in [
        0x1e260020, 0x1e270020, 0x9e660020, 0x9e670020, 0x9eae0020, 0x9eaf0020,
    ] {
        compare_fp_word(word, &initial());
    }
}

#[test]
fn native_neon_integer_float_accumulators_and_qc_match_reference() {
    let logical = [
        0x0e201c00, 0x0ea01c00, 0x2e201c00, 0x0e601c00, 0x0ee01c00, 0x2e601c00, 0x2ea01c00,
        0x2ee01c00,
    ];
    let integer = [
        0x0e208400, 0x2e208400, 0x0e20bc00, 0x0e208c00, 0x2e208c00, 0x0e203400, 0x2e203400,
        0x0e203c00, 0x2e203c00, 0x0e200c00, 0x2e200c00, 0x0e202c00, 0x2e202c00, 0x0e204400,
        0x2e204400, 0x0e204c00, 0x2e204c00, 0x0e205400, 0x2e205400, 0x0e205c00, 0x2e205c00,
    ];
    let small = [
        0x0e209c00, 0x0e209400, 0x2e209400, 0x0e206400, 0x2e206400, 0x0e206c00, 0x2e206c00,
    ];
    let float = [
        0x0e20d400, 0x0ea0d400, 0x2e20d400, 0x2e20dc00, 0x2e20fc00, 0x0e20cc00, 0x0ea0cc00,
        0x0e20f400, 0x0ea0f400, 0x0e20c400, 0x0ea0c400, 0x0e20e400, 0x2e20e400, 0x2ea0e400,
        0x2e20ec00, 0x2ea0ec00,
    ];
    for q in 0..2 {
        for (rd, rn, rm) in [(0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 31, 31)] {
            for op in logical {
                compare_fp_word(op | (q << 30) | (rm << 16) | (rn << 5) | rd, &initial());
            }
            for size in 0..4 {
                if size == 3 && q == 0 {
                    continue;
                }
                for op in integer
                    .into_iter()
                    .chain(small.into_iter().filter(|_| size < 3))
                {
                    compare_fp_word(
                        op | (q << 30) | (size << 22) | (rm << 16) | (rn << 5) | rd,
                        &initial(),
                    );
                }
            }
            for size in 0..2 {
                if size == 1 && q == 0 {
                    continue;
                }
                for op in float {
                    compare_fp_word(
                        op | (q << 30) | (size << 22) | (rm << 16) | (rn << 5) | rd,
                        &initial(),
                    );
                }
            }
        }
    }
}

#[test]
fn native_vectors_evict_dirty_registers_and_preserve_v31_and_dynamic_pc() {
    let mut words: Vec<_> = (0..32).map(|rd| 0x4e221c00 | (1 << 5) | rd).collect();
    words.extend((0..24).map(|rd| 0x4e228400 | (rd << 5) | rd));
    words.extend_from_slice(&[0x9e6603e0, 0xd61f00c0]); // FMOV x0,d31; BR x6
    let mut state = initial();
    state.registers[6] = 0x1000 + 4 * words.len() as u64;
    words.push(0xd4000001);
    for budget in [1, 3, 64] {
        let e = compare_memory_sequence(&words, &state, budget, false);
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
}

#[test]
fn fp_vector_blocks_return_cleanly_to_existing_memory_and_system_boundaries() {
    let mut state = initial();
    state.registers[1] = 0x10000;
    let words = [
        0x3dc00020, 0x4e20d400, 0x3d800020, 0xd53b4423, 0x1e622804, 0xf9400020, 0x4e221c9f,
        0xd4000001,
    ];
    for budget in [1, 64] {
        let e = compare_memory_sequence(&words, &state, budget, budget == 64);
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
        }
    }
}

#[test]
fn native_fp_special_values_rounding_and_sticky_status_match_reference() {
    for (kind, values) in [
        (
            0,
            vec![
                0u64, 0x80000000, 1, 0x00800000, 0x3f800000, 0x7f7fffff, 0x7f800000, 0xff800000,
                0x7fc12345, 0x7f812345,
            ],
        ),
        (
            1,
            vec![
                0,
                0x8000000000000000,
                1,
                0x0010000000000000,
                0x3ff0000000000000,
                0x7fefffffffffffff,
                0x7ff0000000000000,
                0xfff0000000000000,
                0x7ff8123456789abc,
                0x7ff0123456789abc,
            ],
        ),
        (
            3,
            vec![
                0, 0x8000, 1, 0x400, 0x3c00, 0x7bff, 0x7c00, 0xfc00, 0x7e01, 0x7c01,
            ],
        ),
    ] {
        if kind == 3 && !host_capability(9) {
            continue;
        }
        for (i, &value) in values.iter().enumerate() {
            for control in [
                0,
                1 << 22,
                2 << 22,
                3 << 22,
                (1 << 24) | (1 << 25) | (1 << 19),
            ] {
                let mut state = initial();
                state.fpcr = control;
                state.fpsr = 0x08000010;
                state.vectors[1] = value as u128;
                state.vectors[2] = values[(i + 3) % values.len()] as u128;
                state.vectors[3] = values[(i + 7) % values.len()] as u128;
                for op in [0, 1, 2, 3, 4, 5, 6, 7, 8] {
                    compare_fp_word(
                        0x1e200800 | (kind << 22) | (2 << 16) | (op << 12) | (1 << 5),
                        &state,
                    );
                }
                compare_fp_word(0x1f020c20 | (kind << 22), &state);
                compare_fp_word(0x1e222020 | (kind << 22), &state);
            }
        }
    }
}

#[test]
fn baseline_precision_conversions_preserve_alternative_half_and_flush_rules() {
    for word in [
        0x1e23c020, 0x1e63c020, 0x1ee24020, 0x1ee2c020, 0x1e22c020, 0x1e624020,
    ] {
        for control in [0, 1 << 26, 1 << 19, (1 << 26) | (1 << 19) | (1 << 25)] {
            for value in [
                1u64,
                0x7c01,
                0x7e01,
                0x3ff0000000000000,
                0x3f800000,
                u64::MAX,
            ] {
                let mut state = initial();
                state.fpcr = control;
                state.vectors[1] = value as u128;
                compare_fp_word(word, &state);
            }
        }
    }
}

#[test]
fn fp_neon_hot_loops_keep_exact_budgets_without_per_instruction_entry() {
    for word in [0x1e612800, 0x4e21d400, 0x4ea18400] {
        let mut state = initial();
        state.registers[2] = 32;
        state.vectors[0] = 0;
        state.vectors[1] = match word {
            0x1e612800 => 1f64.to_bits() as u128,
            0x4e21d400 => (1f32.to_bits() as u128) * 0x00000001000000010000000100000001,
            _ => 0x00000001000000010000000100000001,
        };
        let words = [word, word, 0xf1000442, 0x54ffffa1, 0x9e660000, 0xd4000001];
        for budget in [3, 17, 256] {
            let e = compare_memory_sequence(&words, &state, budget, false);
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0);
                if budget == 256 {
                    assert!(e.link_stats().entries <= 2);
                }
                assert_eq!(e.memory_stats().fused_entries, 0);
            }
        }
    }
}

#[test]
fn fp_cached_code_and_status_are_revalidated_after_instruction_replacement() {
    let mut m = memory(&[0x1e622820, 0xd4000001]);
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    let mut state = initial();
    state.vectors[1] = 2f64.to_bits() as u128;
    state.vectors[2] = 3f64.to_bits() as u128;
    c.restore_architectural_state(&state);
    c.run_slice(&mut e, &mut m, 64);
    assert_eq!(c.architectural_state().vectors[0], 5f64.to_bits() as u128);
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write_array(0x1000, 0x1e620820u32.to_le_bytes()).unwrap();
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    c.restore_architectural_state(&state);
    c.run_slice(&mut e, &mut m, 64);
    assert_eq!(c.architectural_state().vectors[0], 6f64.to_bits() as u128);
}

#[test]
fn a_running_fp_loop_observes_parallel_code_publication_at_its_block_guard() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut m = memory(&[0x1e612800, 0x91000400, 0x17fffffe]);
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
    let mut registry = trames_memory::parallel::Registry::default();
    let mut reader = m.parallel_view(&mut registry).unwrap();
    let mut writer = reader.clone();
    let mut c = Cpu::new(0x1000, 0);
    let mut s = initial();
    s.vectors[0] = 0;
    s.vectors[1] = 1f64.to_bits() as u128;
    s.registers[0] = 0;
    c.restore_architectural_state(&s);
    let mut e = Engine::default();
    c.run_parallel(&mut e, &mut reader, 96);
    c.restore_architectural_state(&s);
    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let peer = start.clone();
    let task = std::thread::spawn(move || {
        peer.wait();
        std::thread::sleep(std::time::Duration::from_millis(1));
        writer
            .write_array(0x1000, 0xd4000001u32.to_le_bytes())
            .unwrap();
    });
    start.wait();
    let result = c.run_parallel(&mut e, &mut reader, 100_000_000);
    task.join().unwrap();
    let SliceOutcome::Syscall { instructions } = result else {
        panic!("{result:?}");
    };
    assert_eq!(instructions, c.x(0) * 3 + 1);
    assert_eq!(c.pc(), 0x1004);
    assert_eq!(
        c.architectural_state().vectors[0],
        (c.x(0) as f64).to_bits() as u128
    );
    assert_eq!(e.stats.fallback_instructions, 0);
}

#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
#[test]
fn fp_entries_preserve_host_environment_on_yield_syscall_and_guest_fault() {
    fn environment() -> (u64, u64) {
        let (c, s);
        unsafe {
            std::arch::asm!("mrs {c},fpcr","mrs {s},fpsr",c=out(reg)c,s=out(reg)s,options(nostack,preserves_flags));
        }
        (c, s)
    }
    let before = environment();
    for word in [0xd4000001, 0, 0xf9400020] {
        let mut m = memory(&[0x1e221820, word]); // FDIV s0,s1,s2
        for budget in [1, 64] {
            let mut c = Cpu::new(0x1000, 0);
            let mut state = initial();
            state.fpcr = 1 << 22;
            state.fpsr = 0;
            state.vectors[1] = 1f32.to_bits() as u128;
            state.vectors[2] = 0;
            state.registers[1] = 0xdead0000;
            c.restore_architectural_state(&state);
            let mut e = Engine::default();
            let _ = c.run_slice(&mut e, &mut m, budget);
            assert_eq!(environment(), before);
            assert_ne!(c.architectural_state().fpsr & 2, 0);
        }
    }
}

#[test]
fn lse_rmw_widths_ordering_and_register_aliases_match_reference() {
    if !host_capability(8) {
        return;
    }
    for size in 0..4 {
        for operation in 0..=8 {
            for ordering in 0..4 {
                for (rn, rs, rt) in [
                    (1, 2, 0),
                    (1, 2, 2),
                    (1, 31, 0),
                    (1, 2, 31),
                    (31, 2, 0),
                    (1, 2, 1),
                    (1, 1, 0),
                ] {
                    let word = (size << 30)
                        | 0x38200000
                        | (ordering << 22)
                        | (rs << 16)
                        | (operation << 12)
                        | (rn << 5)
                        | rt;
                    let mut state = initial();
                    state.registers[1] = 0xab00_0000_0001_0080;
                    state.sp = state.registers[1];
                    for budget in [1, 64] {
                        let e = compare_memory_sequence(
                            &[0xb1000463, word, word, word, 0x9a9f37e5, 0xd4000001],
                            &state,
                            budget,
                            budget == 64,
                        );
                        if NATIVE_COMPILED {
                            assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn native_cas_and_casp_match_success_failure_pairs_and_alias_pressure() {
    if !host_capability(8) {
        return;
    }
    for pair in [false, true] {
        for size in 0..if pair { 2 } else { 4 } {
            let element = if pair { 4usize << size } else { 1usize << size };
            for ordering in 0..4 {
                for (rs, rt) in [(2, 4), (4, 2), (0, 0), (30, 30), (30, 0), (0, 30), (2, 2)] {
                    let word = (size << 30)
                        | if pair { 0x08207c00 } else { 0x08a07c00 }
                        | ((ordering & 1) << 15)
                        | ((ordering >> 1) << 22)
                        | (rs << 16)
                        | (1 << 5)
                        | rt;
                    for matched in [false, true] {
                        let mut state = initial();
                        state.registers[1] = 0xab00_0000_0001_0000;
                        for index in 0..if pair { 2 } else { 1 } {
                            let mut bytes = [0u8; 8];
                            for (i, b) in bytes[..element].iter_mut().enumerate() {
                                *b = ((index * element + i) as u8)
                                    .wrapping_mul(17)
                                    .wrapping_add(0x85);
                            }
                            if let Some(r) = state.registers.get_mut(rs as usize + index) {
                                *r = u64::from_le_bytes(bytes) ^ u64::from(!matched);
                            }
                        }
                        let mut words: Vec<_> =
                            (10..29).map(|rd| 0x91000400 | (rd << 5) | rd).collect();
                        words.extend_from_slice(&[0xb1000463, word, word, 0x9a9f37e5, 0xd4000001]);
                        for budget in [1, 64] {
                            let e = compare_memory_sequence(&words, &state, budget, budget == 64);
                            if NATIVE_COMPILED {
                                assert_eq!(e.stats.fallback_instructions, 0, "{word:08x}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn rcpc_loads_signed_unscaled_and_release_stores_match_reference() {
    if !host_capability(15) || !host_capability(26) {
        return;
    }
    for size in 0..4 {
        for opc in 0..4 {
            if opc == 2 && size == 3 || opc == 3 && size >= 2 {
                continue;
            }
            for offset in [-256i32, -16, 0, 8, 255] {
                let word = (size << 30)
                    | 0x19000000
                    | (opc << 22)
                    | (((offset as u32) & 511) << 12)
                    | (1 << 5);
                let mut state = initial();
                state.registers[1] = 0xab00_0000_0001_0100;
                for budget in [1, 64] {
                    let e = compare_memory_sequence(
                        &[word, word, word, 0xd4000001],
                        &state,
                        budget,
                        budget == 64,
                    );
                    if NATIVE_COMPILED {
                        assert_eq!(e.stats.fallback_instructions, 0);
                    }
                }
            }
        }
        for rt in [0, 1, 31] {
            let word = (size << 30) | 0x38bfc020 | rt;
            let mut state = initial();
            state.registers[1] = 0x10000;
            let e = compare_memory_sequence(&[word, word, 0xd4000001], &state, 64, true);
            if NATIVE_COMPILED {
                assert_eq!(e.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn shared_native_ldadd_is_atomic_without_a_new_synchronization_path() {
    if !NATIVE_COMPILED || !host_capability(8) {
        return;
    }
    let mut m = memory(&[0xf8240020, 0x8b0000a5, 0xf1000442, 0x54ffffa1, 0xd4000001]);
    m.write(0x2000, &vec![0; PAGE_SIZE as usize]).unwrap();
    let mut registry = trames_memory::parallel::Registry::default();
    let writer = m.parallel_view(&mut registry).unwrap();
    let peer = writer.clone();
    let run = |mut view: trames_memory::parallel::View| {
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(1, 0x2000);
        cpu.set_x(2, 4096);
        cpu.set_x(4, 1);
        let mut e = Engine::default();
        assert_eq!(
            outcome(&cpu.run_parallel(&mut e, &mut view, 32768)),
            ("syscall", 4096 * 4 + 1)
        );
        assert_eq!(e.stats.fallback_instructions, 0);
        assert_eq!(e.memory_stats().staged, 0);
        cpu.x(5)
    };
    let task = std::thread::spawn(move || run(writer));
    let sum = run(peer) + task.join().unwrap();
    m.commit_parallel().unwrap();
    assert_eq!(m.read_u64(0x2000).unwrap(), 8192);
    assert_eq!(sum, 8192 * 8191 / 2);
}

#[test]
fn lse_and_rcpc_alias_loops_stay_native_at_slice_boundaries() {
    if !NATIVE_COMPILED || !host_capability(8) || !host_capability(15) {
        return;
    }
    for words in [
        vec![0xf8240020, 0xf1000442, 0x54ffffc1, 0xd4000001],
        vec![
            0x91000404, 0xc8a07c24, 0x91000400, 0xf1000442, 0x54ffff81, 0xd4000001,
        ],
        vec![
            0xa9401424, 0x91000486, 0xaa0503e7, 0x48247c26, 0xf1000442, 0x54ffff61, 0xd4000001,
        ],
        vec![
            0xf8bfc020, 0x91000400, 0xc89ffc20, 0xf1000442, 0x54ffff81, 0xd4000001,
        ],
    ] {
        for parallel in [false, true] {
            let mut state = initial();
            state.registers[1] = 0x10000;
            state.registers[2] = 16;
            state.registers[4] = 1;
            let e = compare_memory_sequence(&words, &state, 128, parallel);
            assert_eq!(e.stats.fallback_instructions, 0);
            assert_eq!(e.memory_stats().staged, 0);
            assert!(e.memory_stats().hardware >= 14, "{:?}", e.memory_stats());
            assert!(e.memory_stats().direct >= 14);
        }
    }
}

#[test]
fn native_memory_reserves_scratch_registers_even_when_slots_are_free() {
    let mut state = initial();
    state.registers[1] = 0x10000;
    let mut words: Vec<_> = (10..29).map(|rd| 0x91000400 | (rd << 5) | rd).collect();
    words.extend_from_slice(&[
        0xb1000463, 0xf9400020, 0xf9400022, 0xa9401424, 0xa9001424, 0x9a9f37e5, 0xd4000001,
    ]);
    for parallel in [false, true] {
        let e = compare_memory_sequence(&words, &state, 64, parallel);
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
            assert!(e.memory_stats().hardware > 0);
        }
    }
}

#[test]
fn paired_integer_transfers_match_reference_including_aliases_and_writeback() {
    for (opc, load) in [(0, false), (0, true), (1, true), (2, false), (2, true)] {
        for mode in 0..4 {
            if opc == 1 && mode == 0 {
                continue;
            } // reserved LDNP sign-extending form
            for offset in [-4i32, 0, 3] {
                for (rn, rt, rt2) in [
                    (1, 0, 2),
                    (31, 0, 31),
                    (1, 31, 2),
                    (1, 2, 1),
                    (1, 1, 2),
                    (1, 0, 0),
                ] {
                    if ((mode == 1 || mode == 3) && rn != 31 && (rn == rt || rn == rt2))
                        || (load && rt == rt2)
                    {
                        continue;
                    }
                    let word = (opc << 30)
                        | 0x28000000
                        | (mode << 23)
                        | (u32::from(load) << 22)
                        | (((offset as u32) & 127) << 15)
                        | (rt2 << 10)
                        | (rn << 5)
                        | rt;
                    for cross in [false, true] {
                        let mut state = initial();
                        state.registers[1] = if cross {
                            0xab00_0000_0001_0ffd
                        } else {
                            0xab00_0000_0001_0100
                        };
                        state.sp = state.registers[1];
                        // Three copies warm the alias path; writeback and load/base
                        // overlap may intentionally leave the mapping and fault.
                        for budget in [1, 64] {
                            let engine = compare_memory_sequence(
                                &[0xb1000463, word, word, word, 0xd4000001],
                                &state,
                                budget,
                                budget == 64,
                            );
                            if NATIVE_COMPILED {
                                assert_eq!(engine.stats.fallback_instructions, 0, "{word:08x}");
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn ordered_transfers_barriers_and_checked_faults_match_reference() {
    for size in 0..4 {
        for load in [false, true] {
            for (rn, rt) in [(1, 0), (31, 31), (1, 1)] {
                let word =
                    (size << 30) | if load { 0x08dffc00 } else { 0x089ffc00 } | (rn << 5) | rt;
                for offset in [0, 1, 2, 4, 8] {
                    let mut state = initial();
                    state.registers[1] = 0xab00_0000_0001_0100 + offset;
                    state.sp = state.registers[1];
                    for budget in [1, 64] {
                        let engine = compare_memory_sequence(
                            &[0xb1000463, word, word, 0xd4000001],
                            &state,
                            budget,
                            budget == 64,
                        );
                        if NATIVE_COMPILED {
                            assert_eq!(engine.stats.fallback_instructions, 0);
                        }
                    }
                }
            }
        }
    }
    for base in [0xd50330bf, 0xd503309f] {
        for option in [1, 2, 3, 5, 6, 7, 9, 10, 11, 13, 14, 15] {
            let engine = compare_memory_sequence(
                &[
                    0xb1000463,
                    base | (option << 8),
                    0xd5033fdf,
                    0x9a9f37e4,
                    0xd4000001,
                ],
                &initial(),
                64,
                false,
            );
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn pairs_and_ordered_loops_use_hardware_aliases_with_exact_budgets() {
    if !NATIVE_COMPILED {
        return;
    }
    for words in [
        vec![
            0xa9400820, 0x91000400, 0xa9000820, 0xf1000463, 0x54ffff81, 0xd4000001,
        ],
        vec![
            0xc8dffc20, 0x91000400, 0xc89ffc20, 0xf1000463, 0x54ffff81, 0xd4000001,
        ],
    ] {
        for parallel in [false, true] {
            let mut state = initial();
            state.registers[1] = 0x10000;
            state.registers[3] = 16;
            let engine = compare_memory_sequence(&words, &state, 128, parallel);
            assert_eq!(engine.stats.fallback_instructions, 0);
            assert_eq!(engine.memory_stats().instructions, 32);
            assert!(
                engine.memory_stats().hardware >= 28,
                "{:?}",
                engine.memory_stats()
            );
            assert!(engine.memory_stats().direct >= 28);
            assert!(engine.compilation_stats().address_reuses > 0);
        }
    }
}

#[test]
fn guest_release_acquire_publishes_canonical_data_between_workers() {
    if !NATIVE_COMPILED {
        return;
    }
    // Guest handshakes deliberately use no Rust synchronization for guest data.
    // The ack prevents the producer from replacing data before it is consumed.
    let producer = [
        0xc8dffc65, 0xeb0000bf, 0x54ffffc1, 0x91000400, 0xf9000020, 0xc89ffc40, 0xf1000484,
        0x54ffff21, 0xd4000001,
    ];
    let consumer: [u32; 14] = [
        0xc8dffc45, 0x91000406, 0xeb0600bf, 0x54ffffa1, 0xf9400027, 0xeb0600ff, 0x540000c1,
        0xaa0603e0, 0xc89ffc60, 0xf1000484, 0x54fffec1, 0xd4000001, 0xd2800029, 0xd4000001,
    ];
    let mut m = memory(&producer);
    m.write(0x2000, &vec![0; PAGE_SIZE as usize]).unwrap();
    m.map(0x4000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, word) in consumer.into_iter().enumerate() {
        m.write_array(0x4000 + 4 * i as u64, word.to_le_bytes())
            .unwrap();
    }
    m.protect(0x4000, PAGE_SIZE, Permissions::RX).unwrap();
    let mut registry = trames_memory::parallel::Registry::default();
    let writer = m.parallel_view(&mut registry).unwrap();
    let reader = writer.clone();
    let run = |mut view: trames_memory::parallel::View, pc| {
        let mut cpu = Cpu::new(pc, 0);
        for (reg, value) in [(1, 0x2000), (2, 0x2008), (3, 0x2010), (4, 256)] {
            cpu.set_x(reg, value);
        }
        let mut engine = Engine::default();
        let start = std::time::Instant::now();
        loop {
            let exit = cpu.run_parallel(&mut engine, &mut view, 4096);
            if matches!(exit, SliceOutcome::Syscall { .. }) {
                break;
            }
            assert!(matches!(exit, SliceOutcome::Yield { .. }), "{exit:?}");
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "guest handshake timed out"
            );
            std::thread::yield_now();
        }
        assert_eq!((cpu.x(0), cpu.x(4), cpu.x(9)), (256, 0, 0));
        assert_eq!(engine.stats.fallback_instructions, 0);
        assert_eq!(engine.memory_stats().staged, 0);
    };
    let thread = std::thread::spawn(move || run(writer, 0x1000));
    run(reader, 0x4000);
    thread.join().unwrap();
}

#[test]
fn hardware_alias_loop_preserves_state_and_canonical_bytes() {
    if !NATIVE_COMPILED {
        return;
    }
    let words = [
        0xf9400020, 0x91000400, 0xf9000020, 0xf1000442, 0x54ffff81, 0xd4000001,
    ];
    for parallel in [false, true] {
        let mut a = memory(&words);
        let mut b = memory(&words);
        for m in [&mut a, &mut b] {
            m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
            m.write(0x10000, &vec![0; hardware_span() as usize])
                .unwrap();
        }
        let mut state = initial();
        state.registers[1] = 0xab00_0000_0001_0000;
        state.registers[2] = 64;
        let mut expected = trames_interpreter::Cpu::new(0, 0);
        let mut actual = Cpu::new(0, 0);
        expected.restore_architectural_state(&state);
        actual.restore_architectural_state(&state);
        let mut engine = Engine::default();
        let x = expected.run_slice(&mut a, 1000);
        let mut registry = trames_memory::parallel::Registry::default();
        let y = if parallel {
            let mut view = b.parallel_view(&mut registry).unwrap();
            // SAFETY: these are all execution actors; no other mm byte access
            // occurs until this sole view is dropped.
            assert!(unsafe { trames_memory::parallel::View::try_private_epoch(&mut [&mut view]) });
            let result = actual.run_parallel(&mut engine, &mut view, 1000);
            assert_eq!(view.read_u64(0x10000).unwrap(), 64);
            drop(view);
            b.commit_parallel().unwrap();
            result
        } else {
            actual.run_slice(&mut engine, &mut b, 1000)
        };
        assert_eq!(outcome(&x), outcome(&y));
        assert_eq!(actual.architectural_state(), expected.architectural_state());
        assert_eq!(b.read_u64(0x10000).unwrap(), 64);
        assert_eq!(engine.stats.fallback_instructions, 0);
        assert!(
            engine.memory_stats().hardware >= 120,
            "parallel={parallel}: {:?}",
            engine.memory_stats()
        );
        assert!(engine.memory_stats().direct >= 120);
        assert!(engine.compilation_stats().address_reuses > 0);
        assert_eq!(engine.memory_stats().instructions, 128);
    }
}
fn outcome(outcome: &SliceOutcome) -> (&'static str, u64) {
    match outcome {
        SliceOutcome::Yield { instructions } => ("yield", *instructions),
        SliceOutcome::Syscall { instructions } => ("syscall", *instructions),
        other => panic!("unexpected {other:?}"),
    }
}
#[test]
fn integer_blocks_preserve_exact_state_and_budgets() {
    let words = [
        0xd2800120, 0xf2b579a0, 0x12800041, 0x52800062, 0x91001c03, 0xcb030004, 0x8b041465,
        0xaa0100a6, 0x4a2210c7, 0x10000048, 0x90000009, 0xaa1f03ff, 0x91000be0, 0xeb01001f,
        0x9a81000a, 0xd4000001,
    ];
    for budget in [1, 2, 3, 7, 64] {
        let mut a = memory(&words);
        let mut b = memory(&words);
        let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
        let mut actual = Cpu::new(0x1000, 0);
        expected.restore_architectural_state(&initial());
        actual.restore_architectural_state(&initial());
        let mut engine = Engine::default();
        loop {
            let x = expected.run_slice(&mut a, budget);
            let y = actual.run_slice(&mut engine, &mut b, budget);
            assert_eq!(outcome(&x), outcome(&y));
            assert_eq!(actual.architectural_state(), expected.architectural_state());
            if matches!(x, SliceOutcome::Syscall { .. }) {
                break;
            }
        }
        assert_eq!(engine.stats.native_instructions > 0, NATIVE_COMPILED);
        assert_eq!(engine.stats.fallback_instructions == 0, NATIVE_COMPILED);
        // Code is still the original immutable guest image.
        assert_eq!(
            a.read_array::<64>(0x1000).unwrap(),
            b.read_array::<64>(0x1000).unwrap()
        );
    }
}
#[test]
fn whitelist_encoding_corpus_matches_interpreter() {
    let mut seed = 0x619f257b_u32;
    let mut translated = 0;
    for index in 0..2048 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let sf = (seed & 1) << 31;
        let rd = (seed >> 2) & 31;
        let rn = (seed >> 7) & 31;
        let rm = (seed >> 12) & 31;
        let shift = (seed >> 17) & if sf == 0 { 31 } else { 63 };
        let word = match index % 5 {
            0 => sf | 0x11000000 | ((seed & 0xfff) << 10) | (rn << 5) | rd,
            1 => {
                sf | 0x0b000000
                    | ((seed & 1) << 30)
                    | (((seed >> 1) % 3) << 22)
                    | (rm << 16)
                    | (shift << 10)
                    | (rn << 5)
                    | rd
            }
            2 => {
                sf | 0x0a000000
                    | (((seed >> 1) % 3) << 29)
                    | (((seed >> 4) & 3) << 22)
                    | ((seed & 1) << 21)
                    | (rm << 16)
                    | (shift << 10)
                    | (rn << 5)
                    | rd
            }
            3 => {
                sf | 0x12800000
                    | ([0, 2, 3][(seed as usize >> 1) % 3] << 29)
                    | (((seed >> 5) & if sf == 0 { 1 } else { 3 }) << 21)
                    | ((seed & 0xffff) << 5)
                    | rd
            }
            _ => sf | 0x10000000 | (((seed >> 5) & 3) << 29) | ((seed & 0x7ffff) << 5) | rd,
        };
        let mut a = memory(&[word]);
        let mut b = memory(&[word]);
        let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
        let mut actual = Cpu::new(0x1000, 0);
        expected.restore_architectural_state(&initial());
        actual.restore_architectural_state(&initial());
        let mut engine = Engine::default();
        assert_eq!(
            outcome(&expected.run_slice(&mut a, 1)),
            outcome(&actual.run_slice(&mut engine, &mut b, 1)),
            "{word:08x}"
        );
        assert_eq!(
            actual.architectural_state(),
            expected.architectural_state(),
            "{word:08x}"
        );
        translated += engine.stats.native_instructions;
    }
    if NATIVE_COMPILED {
        assert!(translated > 1900);
    } else {
        assert_eq!(translated, 0);
    }
}
#[test]
fn branch_link_fault_accounting_and_page_boundary() {
    let mut m = memory(&[0xd28000e0, 0x94000002, 0xd2800060, 0xd4000001]);
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 3));
    assert_eq!((c.x(0), c.x(30), c.pc()), (7, 0x1008, 0x1010));
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write_array(0x1ffc, 0xd2800120u32.to_le_bytes()).unwrap();
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    c.set_pc(0x1ffc);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 4),
        SliceOutcome::Fault(_)
    ));
    assert_eq!((c.x(0), c.pc(), c.fault_retired()), (9, 0x2000, 1));
    c.set_pc(0x1001);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 4),
        SliceOutcome::Fault(_)
    ));
    assert_eq!(c.fault_retired(), 0);
}
#[test]
fn invalidation_rechecks_code_permissions_replacements_and_spaces() {
    let mut m = memory(&[0xd2800020]);
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    for value in 1..=4 {
        if value != 1 {
            m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
            m.write_array(0x1000, (0xd2800000u32 | (value << 5)).to_le_bytes())
                .unwrap();
            m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
        }
        c.set_pc(0x1000);
        c.run_slice(&mut e, &mut m, 1);
        assert_eq!(c.x(0), value as u64);
    }
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    c.set_pc(0x1000);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 1),
        SliceOutcome::Fault(_)
    ));
    let mut other = memory(&[0xd28000e0]);
    c.set_pc(0x1000);
    c.run_slice(&mut e, &mut other, 1);
    assert_eq!(c.x(0), 7);
    other.unmap(0x1000, PAGE_SIZE).unwrap();
    c.set_pc(0x1000);
    assert!(matches!(
        c.run_slice(&mut e, &mut other, 1),
        SliceOutcome::Fault(_)
    ));
    other.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    other
        .write_array(0x1000, 0xd2800120u32.to_le_bytes())
        .unwrap();
    other.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    c.set_pc(0x1000);
    c.run_slice(&mut e, &mut other, 1);
    assert_eq!(c.x(0), 9);
}
#[test]
fn exclusive_reservation_survives_native_block_and_slice() {
    let mut m = memory(&[0xc85f7c20, 0x91000400, 0xc8027c20, 0xd4000001]);
    m.write_array(0x2000, 41u64.to_le_bytes()).unwrap();
    let mut c = Cpu::new(0x1000, 0);
    c.set_x(1, 0x2000);
    let mut e = Engine::default();
    c.run_slice(&mut e, &mut m, 2);
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 2)), ("syscall", 2));
    assert_eq!(c.x(2), 0);
    assert_eq!(m.read_u64(0x2000).unwrap(), 42);
}

#[test]
fn pending_native_exit_and_parallel_view_keep_dispatch_boundaries() {
    let mut m = memory(&[0xd28000e0, 0xd44a8a40, 0xd4000001]);
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    c.set_native_calls(true);
    c.set_x(16, 0x10001);
    c.set_x(17, 2);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 4),
        SliceOutcome::NativeCall {
            instructions: 1,
            pc: 0x1004,
            module: 0x10001,
            function: 2
        }
    ));
    assert_eq!(c.pc(), 0x1004);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 4),
        SliceOutcome::NativeCall {
            instructions: 0,
            ..
        }
    ));
    c.set_pc(0x1008);
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 4)), ("syscall", 1));
    let mut registry = trames_memory::parallel::Registry::default();
    let mut view = m.parallel_view(&mut registry).unwrap();
    c.set_pc(0x1000);
    assert_eq!(outcome(&c.run_parallel(&mut e, &mut view, 1)), ("yield", 1));
    assert_eq!(c.x(0), 7);
}

#[test]
fn compiled_syscalls_publish_arguments_once_and_resume_without_replay() {
    let words = [
        0xd2800ba8, 0xd2800140, 0xd2800161, 0xd2800182, 0xd28001a3, 0xd28001c4, 0xd28001e5,
        0xd41fffe1, 0x91001400, 0xd4000001,
    ];
    for budget in [1, 2, 7, 8, 64] {
        let mut m = memory(&words);
        let mut c = Cpu::new(0x1000, 0);
        let mut e = Engine::default();
        let mut count = 0;
        loop {
            match c.run_slice(&mut e, &mut m, budget) {
                SliceOutcome::Yield { instructions } => count += instructions,
                SliceOutcome::Syscall { instructions } => {
                    count += instructions;
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(count, 8);
        assert_eq!(c.pc(), 0x1020);
        assert_eq!(c.x(8), 93);
        assert_eq!(
            (0..6).map(|i| c.x(i)).collect::<Vec<_>>(),
            vec![10, 11, 12, 13, 14, 15]
        );
        // Commit a simulated Runtime return, then run the next entry. SVC must
        // neither invoke host exit(10), nor be replayed on the following slice.
        c.set_x(0, 1234);
        loop {
            match c.run_slice(&mut e, &mut m, budget) {
                SliceOutcome::Yield { .. } => {}
                SliceOutcome::Syscall { .. } => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!((c.x(0), c.pc()), (1239, 0x1028));
        assert_eq!(
            e.stats.direct_syscall_exits,
            if NATIVE_COMPILED { 2 } else { 0 }
        );
        if NATIVE_COMPILED {
            assert_eq!(e.stats.fallback_instructions, 0);
        }
        for (i, word) in words.iter().enumerate() {
            assert_eq!(m.fetch_u32(0x1000 + i as u64 * 4).unwrap(), *word);
        }
    }
}

#[test]
fn syscall_at_page_end_and_reserved_exception_encodings_keep_precise_faults() {
    let mut m = memory(&[]);
    let mut c = Cpu::new(0x1ffc, 0);
    let mut e = Engine::default();
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write_array(0x1ffc, 0xd4000001u32.to_le_bytes()).unwrap();
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 0)), ("yield", 0));
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 1));
    assert_eq!(c.pc(), 0x2000);
    assert!(matches!(
        c.run_slice(&mut e, &mut m, 64),
        SliceOutcome::Fault(_)
    ));
    assert_eq!(c.fault_retired(), 0);
    for word in [0xd4000002, 0xd4000003, 0xd4200000, 0xd4400000] {
        let mut m = memory(&[0xd2800020, word]);
        let mut c = Cpu::new(0x1000, 0);
        let mut e = Engine::default();
        assert!(
            matches!(c.run_slice(&mut e, &mut m, 64), SliceOutcome::Fault(_)),
            "{word:08x}"
        );
        assert_eq!((c.pc(), c.fault_retired()), (0x1004, 1));
        assert_eq!(e.stats.direct_syscall_exits, 0);
    }
}

#[test]
fn register_cache_uses_one_load_and_writeback_for_a_chain() {
    let mut words = vec![0x91000400; 16];
    words.push(0xd4000001);
    let mut m = memory(&words);
    let mut c = Cpu::new(0x1000, 0);
    c.set_x(0, 9);
    let mut e = Engine::default();
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 17));
    assert_eq!(c.x(0), 25);
    let cold = e.compilation_stats();
    if NATIVE_COMPILED {
        assert_eq!(
            (cold.blocks, cold.register_loads, cold.register_stores),
            (1, 1, 1)
        );
        assert_eq!(
            (
                e.stats.native_blocks,
                e.stats.native_instructions,
                e.stats.fallback_instructions,
                e.stats.direct_syscall_exits
            ),
            (1, 16, 0, 1)
        );
    }
    c.set_pc(0x1000);
    c.run_slice(&mut e, &mut m, 64);
    assert_eq!(c.x(0), 41);
    assert_eq!(e.compilation_stats().blocks, cold.blocks);
}

#[test]
fn dirty_eviction_source_aliases_and_deferred_flags_match_interpreter() {
    for seed in 0..32u32 {
        // First set deferred flags from old x0/x1, then overwrite both operands
        // while exceeding all 13 allocatable value registers.
        let mut words = vec![0xeb01001f];
        for reg in 0..31 {
            words.push(0xd2800000 | ((reg + 1 + seed) << 5) | reg);
        }
        for index in 0..30 {
            let rd = (index * 7 + seed) % 31;
            let rn = (index * 11 + 3 + seed) % 31;
            let rm = (index * 13 + 19 + seed) % 31;
            let sf = (index & 1) << 31;
            let sub = ((index >> 1) & 1) << 30;
            words.push(
                sf | sub | 0x0b000000 | (rm << 16) | (((index + seed) % 16) << 10) | (rn << 5) | rd,
            );
        }
        words.push(0xd4000001);
        for budget in [1, 7, 17, 64] {
            let mut a = memory(&words);
            let mut b = memory(&words);
            let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
            let mut actual = Cpu::new(0x1000, 0);
            let mut engine = Engine::default();
            expected.restore_architectural_state(&initial());
            actual.restore_architectural_state(&initial());
            loop {
                let x = expected.run_slice(&mut a, budget);
                let y = actual.run_slice(&mut engine, &mut b, budget);
                assert_eq!(outcome(&x), outcome(&y));
                assert_eq!(
                    actual.architectural_state(),
                    expected.architectural_state(),
                    "seed {seed} budget {budget}"
                );
                if matches!(x, SliceOutcome::Syscall { .. }) {
                    break;
                }
            }
        }
    }
}

#[test]
fn linked_loop_keeps_exact_budgets_and_avoids_native_reentry() {
    let words = [0x91000400, 0x17ffffff];
    let mut memory_a = memory(&words);
    let mut memory_b = memory(&words);
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    c.run_slice(&mut e, &mut memory_a, 128);
    for budget in [0, 1, 2, 3, 63, 64, 65, 4097, 10000] {
        let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
        c.restore_architectural_state(&expected.architectural_state());
        let x = expected.run_slice(&mut memory_b, budget);
        let y = c.run_slice(&mut e, &mut memory_a, budget);
        assert_eq!(outcome(&x), outcome(&y));
        assert_eq!(expected.architectural_state(), c.architectural_state());
    }
    if NATIVE_COMPILED {
        c.set_pc(0x1000);
        c.run_slice(&mut e, &mut memory_a, 128);
        let before = e.link_stats();
        c.run_slice(&mut e, &mut memory_a, 10000);
        let after = e.link_stats();
        assert_eq!(after.entries - before.entries, 1);
        assert_eq!(after.linked_blocks - before.linked_blocks, 4999);
    }
}

#[test]
fn syscall_continuations_use_current_arguments_and_revalidate_code_changes() {
    let mut m = memory(&[0x91000400, 0xd4000001, 0x17fffffe]);
    let mut c = Cpu::new(0x1008, 0);
    let mut e = Engine::default();
    for i in 0..16 {
        c.set_x(0, 1000 + i);
        c.set_x(8, if i & 1 == 0 { 93 } else { 172 });
        assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 3));
        assert_eq!((c.x(0), c.pc()), (1001 + i, 0x1008));
    }
    if NATIVE_COMPILED {
        assert!(e.link_stats().syscall_resumes > 0);
        assert!(e.link_stats().linked_blocks > 0);
        let lookups = e.link_stats().lookups;
        c.run_slice(&mut e, &mut m, 64);
        assert_eq!(e.link_stats().lookups, lookups);
    }
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    m.write_array(0x1000, 0x91000800u32.to_le_bytes()).unwrap();
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    c.set_x(0, 40);
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 3));
    assert_eq!(c.x(0), 42);
    c.set_pc(0x1004);
    c.set_x(0, 77);
    assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 1));
    assert_eq!(c.x(0), 77);
}

#[test]
fn cross_page_targets_remain_unlinked() {
    let mut m = memory(&[0x14000400]);
    m.write_array(0x2000, 0xd4000001u32.to_le_bytes()).unwrap();
    m.protect(0x2000, PAGE_SIZE, Permissions::RX).unwrap();
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    for _ in 0..8 {
        c.set_pc(0x1000);
        assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 2));
    }
    assert_eq!(e.link_stats().linked_blocks, 0);
}

#[test]
fn parallel_code_write_breaks_a_running_native_chain_at_its_epoch_guard() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut m = memory(&[0x91000400, 0x17ffffff]);
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
    let mut registry = trames_memory::parallel::Registry::default();
    let mut reader = m.parallel_view(&mut registry).unwrap();
    let mut writer = reader.clone();
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    c.run_parallel(&mut e, &mut reader, 128);
    c.set_x(0, 0);
    c.set_pc(0x1000);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    let thread = std::thread::spawn(move || {
        other.wait();
        std::thread::sleep(std::time::Duration::from_millis(1));
        writer.write(0x1000, &0xd4000001u32.to_le_bytes()).unwrap();
    });
    barrier.wait();
    let result = c.run_parallel(&mut e, &mut reader, 100_000_000);
    thread.join().unwrap();
    let SliceOutcome::Syscall { instructions } = result else {
        panic!("running chain missed changed code: {result:?}");
    };
    assert_eq!(instructions, c.x(0) * 2 + 1);
    assert_eq!(c.pc(), 0x1004);
    assert!(e.link_stats().linked_blocks > 0);
    assert_eq!(e.stats.fallback_instructions, 0);
}

#[test]
fn adjacent_syscalls_always_return_to_runtime_between_entries() {
    let mut m = memory(&[0xd4000001, 0xd4000001]);
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    for _ in 0..8 {
        c.set_pc(0x1000);
        assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 1));
        assert_eq!(c.pc(), 0x1004);
        c.set_x(0, 123);
        assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 1));
        assert_eq!((c.x(0), c.pc()), (123, 0x1008));
    }
}

#[test]
fn memory_embeddings_without_epoch_capability_never_follow_native_links() {
    use trames_memory::{Access, MemoryError};
    struct Plain(Memory);
    impl CpuMemory for Plain {
        fn mapped_at_or_after(&self, a: u64) -> bool {
            CpuMemory::mapped_at_or_after(&self.0, a)
        }
        fn read(&self, a: u64, out: &mut [u8]) -> Result<(), MemoryError> {
            self.0.read(a, out)
        }
        fn write(&mut self, a: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.0.write(a, bytes)
        }
        fn check(&self, a: u64, len: usize, access: Access) -> Result<(), MemoryError> {
            self.0.check(a, len, access)
        }
        fn check_translation(&self, a: u64) -> Result<(), MemoryError> {
            self.0.check_translation(a)
        }
        fn fetch_u32(&self, a: u64) -> Result<u32, MemoryError> {
            self.0.fetch_u32(a)
        }
        fn instruction_identity(&self) -> (u64, u64, u64) {
            self.0.instruction_identity()
        }
        fn instruction_page_identity(&self, a: u64) -> Result<(u64, u64, u64), MemoryError> {
            self.0.instruction_page_identity(a)
        }
        fn atomic_update<T>(
            &mut self,
            a: u64,
            len: usize,
            f: impl FnOnce(&mut [u8]) -> (T, bool),
        ) -> Result<T, MemoryError> {
            CpuMemory::atomic_update(&mut self.0, a, len, f)
        }
        fn exclusive_read(&mut self, a: u64, out: &mut [u8]) -> Result<u128, MemoryError> {
            CpuMemory::exclusive_read(&mut self.0, a, out)
        }
        fn exclusive_write(
            &mut self,
            a: u64,
            bytes: &[u8],
            token: Option<u128>,
        ) -> Result<bool, MemoryError> {
            CpuMemory::exclusive_write(&mut self.0, a, bytes, token)
        }
    }
    let mut m = memory(&[0x91000400, 0x17ffffff]);
    let mut c = Cpu::new(0x1000, 0);
    let mut e = Engine::default();
    c.run_slice(&mut e, &mut m, 128);
    let before = e.link_stats();
    let mut plain = Plain(m);
    c.set_pc(0x1000);
    c.set_x(0, 0);
    assert_eq!(
        outcome(&c.run_slice(&mut e, &mut plain, 128)),
        ("yield", 128)
    );
    assert_eq!(c.x(0), 64);
    let after = e.link_stats();
    assert_eq!(after.linked_blocks, before.linked_blocks);
    if NATIVE_COMPILED {
        assert_eq!(after.entries - before.entries, 64);
    }
    // The default full-overwrite borrow must not request read permission.
    plain.0.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    plain
        .0
        .write_array(0x1000, 0xf9000020u32.to_le_bytes())
        .unwrap();
    plain.0.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    plain
        .0
        .protect(
            0x2000,
            PAGE_SIZE,
            Permissions {
                read: false,
                write: true,
                execute: false,
            },
        )
        .unwrap();
    c.set_pc(0x1000);
    c.set_x(1, 0x2000);
    c.set_x(0, 123);
    assert_eq!(outcome(&c.run_slice(&mut e, &mut plain, 1)), ("yield", 1));
    plain.0.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
    assert_eq!(plain.0.read_u64(0x2000).unwrap(), 123);
    if NATIVE_COMPILED {
        assert_eq!(
            (e.memory_stats().instructions, e.memory_stats().staged),
            (1, 1)
        );
    }
}

#[test]
fn scalar_flags_sp_and_bit_operations_are_native_and_match_reference() {
    let cases: &[u32] = &[
        0x1100041f, 0x7100041f, 0x31000400, 0x510007e1, // SP / CMP / flags immediates
        0x0b020020, 0x6b82003f, 0x0b226020, 0x2b22e03f, // shifted/extended ADD(S)/SUB(S)
        0x6a021020, 0x0a621020, 0x12001c20, 0x72001c3f, // ANDS/BIC/logical immediate
        0x13017c20, 0x330c1c20, 0x53042020, 0x13821c20, // SBFM/BFM/UBFM/EXTR
        0x1a820020, 0x5a821420, 0x3a42002a, 0x7a42082a, // CSEL/CSNEG/CCMN/CCMP
        0x1a020020, 0x3a020020, 0x5a020020, 0x7a020020, // ADC/ADCS/SBC/SBCS
        0x1b020c20, 0x1b028c20, 0x1ac20820, 0x1ac20c20, // MADD/MSUB/UDIV/SDIV
        0x1ac22020, 0x1ac22420, 0x1ac22820, 0x1ac22c20, // variable shifts/rotate
        0x5ac00020, 0x5ac00420, 0x5ac00820, 0x5ac01020, 0x5ac01420, 0xd53b4200,
        0xd51b4200, // virtual NZCV
    ];
    for &base in cases {
        for wide in [false, true] {
            // EXTR and bitfield encodings require N == sf.
            let word = if matches!(base & 0x1f800000, 0x13000000 | 0x13800000) {
                base | if wide { 0x80400000 } else { 0 }
            } else if base & 0xff000000 == 0xd5000000 {
                base
            } else {
                base | if wide { 0x80000000 } else { 0 }
            };
            for nzcv in 0..16 {
                let mut state = initial();
                state.nzcv = nzcv << 28;
                state.registers[0] = 0x80000000ffffffff;
                state.registers[1] = 0x8000000000000000;
                state.registers[2] = if nzcv % 2 == 0 { 0 } else { u64::MAX };
                state.registers[3] = u64::MAX;
                let mut a = memory(&[word]);
                let mut b = memory(&[word]);
                let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
                let mut actual = Cpu::new(0x1000, 0);
                expected.restore_architectural_state(&state);
                actual.restore_architectural_state(&state);
                let mut engine = Engine::default();
                let reference = expected.run_slice(&mut a, 1);
                let compiled = actual.run_slice(&mut engine, &mut b, 1);
                assert_eq!(
                    format!("{compiled:?}"),
                    format!("{reference:?}"),
                    "{word:08x}"
                );
                assert_eq!(
                    actual.architectural_state(),
                    expected.architectural_state(),
                    "{word:08x} NZCV={nzcv}"
                );
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0, "{word:08x}");
                    assert_eq!(engine.stats.native_instructions, 1, "{word:08x}");
                }
            }
        }
    }
}

#[test]
fn conditional_countdown_links_and_retires_exactly_without_fallback() {
    for flags in [false, true] {
        let words = if flags {
            [0x91000400, 0xf1000421, 0x54ffffc1, 0xd4000001] // ADD; SUBS; B.NE; SVC
        } else {
            [0x91000400, 0xd1000421, 0xb5ffffc1, 0xd4000001] // ADD; SUB; CBNZ; SVC
        };
        for budget in [1, 2, 3, 4, 31, 32, 33, 64, 10_000] {
            let mut a = memory(&words);
            let mut b = memory(&words);
            let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
            let mut actual = Cpu::new(0x1000, 0);
            expected.set_x(1, 127);
            actual.set_x(1, 127);
            let mut engine = Engine::default();
            loop {
                let x = expected.run_slice(&mut a, budget);
                let y = actual.run_slice(&mut engine, &mut b, budget);
                assert_eq!(outcome(&x), outcome(&y));
                assert_eq!(actual.architectural_state(), expected.architectural_state());
                if matches!(x, SliceOutcome::Syscall { .. }) {
                    break;
                }
            }
            assert_eq!((actual.x(0), actual.x(1), actual.pc()), (127, 0, 0x1010));
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
                if budget >= 64 {
                    assert!(engine.link_stats().linked_blocks > 0);
                }
            }
        }
    }
}

#[test]
fn conditional_and_register_branches_preserve_flags_links_and_aliases() {
    for word in [
        0x34000040, 0x35000040, 0xb4000040, 0xb5000040, 0x36000040, 0x37000040, 0xb6f80040,
        0xb7f80040, 0xd61f0020, 0xd63f03c0, 0xd65f03c0,
    ] {
        for value in [0, 1, 1 << 31, 1 << 63, u64::MAX] {
            let mut state = initial();
            state.nzcv = 0xd0000000;
            state.registers[0] = value;
            state.registers[1] = 0x1010;
            state.registers[30] = 0x1014;
            let mut a = memory(&[word]);
            let mut b = memory(&[word]);
            let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
            let mut actual = Cpu::new(0x1000, 0);
            expected.restore_architectural_state(&state);
            actual.restore_architectural_state(&state);
            let mut engine = Engine::default();
            assert_eq!(
                outcome(&expected.run_slice(&mut a, 1)),
                outcome(&actual.run_slice(&mut engine, &mut b, 1))
            );
            assert_eq!(
                actual.architectural_state(),
                expected.architectural_state(),
                "{word:08x} {value:x}"
            );
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
            }
        }
    }
    for condition in 0..16 {
        for nzcv in 0..16 {
            let word = 0x54000040 | condition;
            let mut state = initial();
            state.nzcv = nzcv << 28;
            let mut a = memory(&[word]);
            let mut b = memory(&[word]);
            let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
            let mut actual = Cpu::new(0x1000, 0);
            expected.restore_architectural_state(&state);
            actual.restore_architectural_state(&state);
            let mut engine = Engine::default();
            expected.run_slice(&mut a, 1);
            actual.run_slice(&mut engine, &mut b, 1);
            assert_eq!(
                actual.architectural_state(),
                expected.architectural_state(),
                "cond={condition} NZCV={nzcv}"
            );
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
            }
        }
    }
}

#[test]
fn crc_and_flag_extensions_use_native_lowerings_with_exact_nzcv() {
    for word in [
        0x1ac24020, 0x1ac24420, 0x1ac24820, 0x9ac24c20, 0x1ac25020, 0x1ac25420, 0x1ac25820,
        0x9ac25c20, 0xd500401f, 0xba00842f, 0xba1f8425, 0x3a00082d, 0x3a00482d, 0xd500403f,
        0xd500405f,
    ] {
        for nzcv in 0..16 {
            for value in [
                0,
                0x7f,
                0x80,
                0xff,
                0x100,
                0x7fff,
                0x8000,
                0xffff,
                0x10000,
                u64::MAX,
            ] {
                let mut state = initial();
                state.nzcv = nzcv << 28;
                state.registers[1] = value;
                state.registers[2] = 0x9876543210fedcba;
                let mut a = memory(&[word]);
                let mut b = memory(&[word]);
                let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
                let mut actual = Cpu::new(0x1000, 0);
                expected.restore_architectural_state(&state);
                actual.restore_architectural_state(&state);
                let mut engine = Engine::default();
                if NATIVE_COMPILED {
                    let host = <Cpu as Backend>::features();
                    let present = if word & 0x7fe0e000 == 0x1ac04000 {
                        host.hwcap & (1 << 7) != 0
                    } else if matches!(word, 0xd500403f | 0xd500405f) {
                        host.hwcap2 & (1 << 7) != 0
                    } else {
                        host.hwcap & (1 << 27) != 0
                    };
                    if !present {
                        assert!(matches!(
                            actual.run_slice(&mut engine, &mut b, 1),
                            SliceOutcome::Fault(trames_engine::CpuFault::Instruction { .. })
                        ));
                        assert_eq!(engine.stats.fallback_instructions, 0);
                        continue;
                    }
                }
                assert_eq!(
                    format!("{:?}", expected.run_slice(&mut a, 1)),
                    format!("{:?}", actual.run_slice(&mut engine, &mut b, 1)),
                    "{word:08x}"
                );
                assert_eq!(
                    actual.architectural_state(),
                    expected.architectural_state(),
                    "{word:08x} {value:x} NZCV={nzcv}"
                );
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0, "{word:08x}");
                }
            }
        }
    }
}

#[test]
fn scalar_alias_pressure_long_products_and_sink_registers_match_reference() {
    let bases = [
        0xab000000, 0xcb000000, 0x9a000000, 0xfa000000, 0xaa000000, 0xea000000, 0x9a800000,
        0xda800400, 0x9b000000, 0x9b200000, 0x9ba00000, 0x9b407c00, 0x9bc07c00, 0x9ac00800,
        0x9ac00c00, 0x9ac02400, 0x93403c00, 0xb3483c00, 0xd3483c00, 0x93c01c00,
    ];
    let mut seed = 0x82a5ed401ccb7f39u64;
    for index in 0..4096 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let base = bases[index % bases.len()];
        let rd = (seed & 31) as u32;
        let rn = ((seed >> 5) & 31) as u32;
        let rm = ((seed >> 10) & 31) as u32;
        let mut word = base | (rn << 5) | rd;
        if base & 0x1f000000 == 0x1b000000 {
            word |= rm << 16;
            if base & 0x00600000 == 0 || base & 0x00600000 == 0x00200000 {
                word |= (((seed >> 15) & 31) as u32) << 10;
            }
        } else if !matches!(base & 0x1f800000, 0x13000000) {
            word |= rm << 16;
        }
        let mut state = initial();
        state.nzcv = ((seed >> 20) as u32 & 15) << 28;
        for reg in &mut state.registers {
            *reg ^= seed;
        }
        let mut a = memory(&[word]);
        let mut b = memory(&[word]);
        let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
        let mut actual = Cpu::new(0x1000, 0);
        expected.restore_architectural_state(&state);
        actual.restore_architectural_state(&state);
        let mut engine = Engine::default();
        assert_eq!(
            format!("{:?}", expected.run_slice(&mut a, 1)),
            format!("{:?}", actual.run_slice(&mut engine, &mut b, 1)),
            "{word:08x}"
        );
        assert_eq!(
            actual.architectural_state(),
            expected.architectural_state(),
            "{word:08x}"
        );
        if NATIVE_COMPILED {
            assert_eq!(engine.stats.fallback_instructions, 0, "{word:08x}");
        }
    }
}

#[test]
fn host_extensions_are_direct_when_present_and_sigill_when_absent() {
    for (base, feature_word, bit) in [
        (0x5ac01820, 1, 34),
        (0xdac01c20, 1, 34),
        (0xdac02020, 1, 34),
        (0x1ac26020, 1, 34),
        (0x9ac26420, 1, 34),
        (0x1ac26820, 1, 34),
        (0x9ac26c20, 1, 34),
        (0x11c3fc20, 1, 34),
        (0x91c7fc20, 1, 34),
        (0x11cbfc20, 1, 34),
        (0x91cffc20, 1, 34),
    ] {
        let mut a = memory(&[base]);
        let mut b = memory(&[base]);
        let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
        let mut actual = Cpu::new(0x1000, 0);
        expected.set_x(1, u64::MAX);
        actual.set_x(1, u64::MAX);
        expected.set_x(2, 1 << 63);
        actual.set_x(2, 1 << 63);
        let mut engine = Engine::default();
        let features = <Cpu as Backend>::features();
        let present = [features.hwcap, features.hwcap2][feature_word] & (1 << bit) != 0;
        let outcome = actual.run_slice(&mut engine, &mut b, 1);
        if NATIVE_COMPILED && !present {
            assert!(
                matches!(outcome,SliceOutcome::Fault(trames_engine::CpuFault::Instruction{pc:0x1000,instruction}) if instruction==base)
            );
            assert_eq!(actual.pc(), 0x1000);
            assert_eq!(actual.fault_retired(), 0);
        } else {
            expected.run_slice(&mut a, 1);
            assert_eq!(
                actual.architectural_state(),
                expected.architectural_state(),
                "{base:08x}"
            );
        }
        if NATIVE_COMPILED {
            assert_eq!(engine.stats.fallback_instructions, 0);
        }
    }
    if NATIVE_COMPILED && <Cpu as Backend>::features().hwcap2 & (1 << 34) == 0 {
        let mut m = memory(&[0x91000400, 0xdac01c20]);
        let mut c = Cpu::new(0x1000, 0);
        let mut e = Engine::default();
        assert!(matches!(
            c.run_slice(&mut e, &mut m, 64),
            SliceOutcome::Fault(trames_engine::CpuFault::Instruction { pc: 0x1004, .. })
        ));
        assert_eq!(
            (
                c.x(0),
                c.pc(),
                c.fault_retired(),
                e.stats.fallback_instructions
            ),
            (1, 0x1004, 1, 0)
        );
    }
}

fn data_memory(word: u32) -> Memory {
    let mut m = memory(&[word]);
    m.map(0x3000, PAGE_SIZE, Permissions::RW).unwrap();
    let data: Vec<u8> = (0..8192)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(0x80))
        .collect();
    m.write(0x2000, &data).unwrap();
    m
}

#[test]
fn scalar_memory_address_modes_widths_signs_and_register_aliases_match_reference() {
    for size in 0..4u32 {
        for opc in 0..4u32 {
            if size >= 2 && opc == 3 {
                continue;
            }
            for rt in [0, 31] {
                for rn in [1, 31] {
                    let base = (size << 30) | (opc << 22) | (rn << 5) | rt;
                    let mut forms = vec![
                        0x39000000 | base | (3 << 10),
                        0x38000000 | base | (0x1f9 << 12),
                        0x38000400 | base | (7 << 12),
                        0x38000c00 | base | (0x1f9 << 12),
                        0x38000800 | base,
                    ];
                    for option in [2, 3, 6, 7] {
                        for scaled in [0, 1] {
                            forms.push(
                                0x38200800 | base | (2 << 16) | (option << 13) | (scaled << 12),
                            );
                        }
                    }
                    for word in forms {
                        for index in [3, u64::MAX - 2] {
                            let mut state = initial();
                            state.sp = 0x2800;
                            state.registers[0] = 0xfedcba9876543280;
                            state.registers[1] = 0x2800;
                            state.registers[2] = index;
                            state.nzcv = 0xd0000000;
                            let mut a = data_memory(word);
                            let mut b = data_memory(word);
                            let mut expected = trames_interpreter::Cpu::default();
                            let mut actual = Cpu::default();
                            expected.restore_architectural_state(&state);
                            actual.restore_architectural_state(&state);
                            let mut engine = Engine::default();
                            let reference = expected.run_slice(&mut a, 1);
                            let compiled = actual.run_slice(&mut engine, &mut b, 1);
                            let retired = u64::from(matches!(
                                compiled,
                                SliceOutcome::Yield { instructions: 1 }
                            ));
                            assert_eq!(
                                format!("{reference:?}"),
                                format!("{compiled:?}"),
                                "{word:08x} index={index:x}"
                            );
                            assert_eq!(
                                actual.architectural_state(),
                                expected.architectural_state(),
                                "{word:08x}"
                            );
                            let mut x = vec![0; 8192];
                            let mut y = vec![0; 8192];
                            a.read(0x2000, &mut x).unwrap();
                            b.read(0x2000, &mut y).unwrap();
                            assert_eq!(x, y, "{word:08x}");
                            if NATIVE_COMPILED {
                                assert_eq!(engine.stats.fallback_instructions, 0, "{word:08x}");
                                assert_eq!(
                                    engine.memory_stats().instructions,
                                    retired,
                                    "{word:08x}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    for word in [0x18008000, 0x58008000, 0x98008000, 0xd8008000] {
        let mut a = data_memory(word);
        let mut b = data_memory(word);
        let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
        let mut actual = Cpu::new(0x1000, 0);
        let mut engine = Engine::default();
        expected.run_slice(&mut a, 1);
        actual.run_slice(&mut engine, &mut b, 1);
        assert_eq!(
            actual.architectural_state(),
            expected.architectural_state(),
            "{word:08x}"
        );
        if NATIVE_COMPILED {
            assert_eq!(
                (
                    engine.stats.fallback_instructions,
                    engine.memory_stats().instructions
                ),
                (0, 1)
            );
        }
    }
}

#[test]
fn memory_faults_cross_page_and_writeback_are_precise() {
    for word in [
        0xf8408420, 0xf8008420, 0xf8408c20, 0xf8008c20, 0xb9800020, 0xf9400020, 0xf9000020,
        0xa8c10820, 0xa8810820, 0xa9c10820, 0xa9810820, 0x69400820, 0xc8dffc20, 0xc89ffc20,
        0x3dc00020, 0x3d800020, 0xad400420, 0xad000420, 0xad810420, 0xadc10420, 0xf8240020,
        0xc8a27c24, 0x48227c24, 0xf8bfc020, 0xd9400020,
    ] {
        if ((word == 0xf8240020 || word == 0xc8a27c24 || word == 0x48227c24) && !host_capability(8))
            || (word == 0xf8bfc020 && !host_capability(15))
            || (word == 0xd9400020 && !host_capability(26))
        {
            continue;
        }
        for address in [0x2800, 0x2ffd, 0xab00000000002ffd, 0x3ffd] {
            for access in [
                Permissions::RW,
                Permissions::R,
                Permissions {
                    read: false,
                    write: true,
                    execute: false,
                },
                Permissions::NONE,
            ] {
                let mut a = data_memory(word);
                let mut b = data_memory(word);
                for m in [&mut a, &mut b] {
                    m.protect(0x2000, PAGE_SIZE, access).unwrap();
                    m.unmap(0x3000, PAGE_SIZE).unwrap();
                }
                let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
                let mut actual = Cpu::new(0x1000, 0);
                expected.set_x(1, address);
                actual.set_x(1, address);
                expected.set_x(0, 0xfedcba9876543210);
                actual.set_x(0, 0xfedcba9876543210);
                let mut engine = Engine::default();
                let x = expected.run_slice(&mut a, 1);
                let y = actual.run_slice(&mut engine, &mut b, 1);
                assert_eq!(
                    format!("{x:?}"),
                    format!("{y:?}"),
                    "{word:08x} {address:x} {access:?}"
                );
                assert_eq!(actual.architectural_state(), expected.architectural_state());
                assert_eq!(actual.fault_retired(), expected.fault_retired());
                a.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
                b.protect(0x2000, PAGE_SIZE, Permissions::R).unwrap();
                let mut x = vec![0; 4096];
                let mut y = vec![0; 4096];
                a.read(0x2000, &mut x).unwrap();
                b.read(0x2000, &mut y).unwrap();
                assert_eq!(x, y);
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0);
                }
            }
        }
    }
    // Successful cross-page transfers remain native, with explicit staging.
    for word in [0xf9400020, 0xf9000020, 0xa9400820, 0xa9000820, 0x69400820] {
        let mut m = data_memory(word);
        let mut c = Cpu::new(0x1000, 0);
        let mut e = Engine::default();
        c.set_x(1, 0x2ffd);
        c.set_x(0, 0x1234567812345678);
        assert!(matches!(
            c.run_slice(&mut e, &mut m, 1),
            SliceOutcome::Yield { instructions: 1 }
        ));
        if NATIVE_COMPILED {
            assert_eq!(
                (
                    e.memory_stats().instructions,
                    e.memory_stats().staged,
                    e.stats.fallback_instructions
                ),
                (1, 1, 0)
            );
        }
    }
}

#[test]
fn native_store_invalidates_exclusives_and_cached_code_in_memory_and_views() {
    for (parallel, store) in [
        (false, 0xf9000022),
        (true, 0xf9000022),
        (false, 0xf8220024),
        (true, 0xf8220024),
        (false, 0xc8a07c22),
        (true, 0xc8a07c22),
    ] {
        if store != 0xf9000022 && !host_capability(8) {
            continue;
        }
        let words = [0xc85f7c20, store, 0xc8037c20, 0xd4000001];
        let mut m = memory(&words);
        m.write_array(0x2000, 5u64.to_le_bytes()).unwrap();
        let mut c = Cpu::new(0x1000, 0);
        c.set_x(1, 0x2000);
        c.set_x(2, 99);
        let mut e = Engine::default();
        if parallel {
            let mut registry = trames_memory::parallel::Registry::default();
            let mut v = m.parallel_view(&mut registry).unwrap();
            assert_eq!(outcome(&c.run_parallel(&mut e, &mut v, 64)), ("syscall", 4));
            drop(v);
            m.commit_parallel().unwrap();
        } else {
            assert_eq!(outcome(&c.run_slice(&mut e, &mut m, 64)), ("syscall", 4));
        }
        assert_eq!(
            (c.x(3), m.read_u64(0x2000).unwrap()),
            (1, if store == 0xf8220024 { 104 } else { 99 })
        );
        if NATIVE_COMPILED {
            assert_eq!(e.memory_stats().instructions, 3);
            assert_eq!(e.stats.fallback_instructions, 0);
        }
        let mut code = memory(&[0xb9000022, 0xd2800020, 0xd4000001]);
        code.protect(
            0x1000,
            PAGE_SIZE,
            Permissions {
                read: true,
                write: true,
                execute: true,
            },
        )
        .unwrap();
        let mut cpu = Cpu::new(0x1004, 0);
        let mut engine = Engine::default();
        if parallel {
            let mut registry = trames_memory::parallel::Registry::default();
            let mut v = code.parallel_view(&mut registry).unwrap();
            cpu.run_parallel(&mut engine, &mut v, 1);
            cpu.set_pc(0x1000);
            cpu.set_x(1, 0x1004);
            cpu.set_x(2, 0xd28000e0);
            assert_eq!(
                outcome(&cpu.run_parallel(&mut engine, &mut v, 64)),
                ("syscall", 3)
            );
        } else {
            cpu.run_slice(&mut engine, &mut code, 1);
            cpu.set_pc(0x1000);
            cpu.set_x(1, 0x1004);
            cpu.set_x(2, 0xd28000e0);
            assert_eq!(
                outcome(&cpu.run_slice(&mut engine, &mut code, 64)),
                ("syscall", 3)
            );
        }
        assert_eq!(cpu.x(0), 7);
        if NATIVE_COMPILED {
            assert_eq!(
                (
                    engine.stats.fallback_instructions,
                    engine.memory_stats().instructions
                ),
                (0, 1)
            );
        }
    }
}

#[test]
fn scalar_view_borrows_match_reference_and_preserve_fork_cow() {
    for word in [
        0x39400020, 0x39c00020, 0x39800020, 0x79400020, 0x79c00020, 0x79800020, 0xb9400020,
        0xb9800020, 0xf9400020, 0x39000020, 0x79000020, 0xb9000020, 0xf9000020,
    ] {
        for address in [0x2800, 0x283f, 0x2ffd] {
            let mut a = data_memory(word);
            let mut b = data_memory(word);
            let child = b.try_fork().unwrap();
            let mut expected = trames_interpreter::Cpu::new(0x1000, 0);
            let mut actual = Cpu::new(0x1000, 0);
            expected.set_x(1, address);
            actual.set_x(1, address);
            expected.set_x(0, 0x8877665544332280);
            actual.set_x(0, 0x8877665544332280);
            let mut ra = trames_memory::parallel::Registry::default();
            let mut rb = trames_memory::parallel::Registry::default();
            let mut va = a.parallel_view(&mut ra).unwrap();
            let mut vb = b.parallel_view(&mut rb).unwrap();
            let mut ea = trames_interpreter::Engine::default();
            let mut eb = Engine::default();
            assert_eq!(
                outcome(&expected.run_parallel(&mut ea, &mut va, 1)),
                outcome(&actual.run_parallel(&mut eb, &mut vb, 1))
            );
            assert_eq!(
                actual.architectural_state(),
                expected.architectural_state(),
                "{word:08x}"
            );
            let mut x = vec![0; 8192];
            let mut y = vec![0; 8192];
            va.read(0x2000, &mut x).unwrap();
            vb.read(0x2000, &mut y).unwrap();
            assert_eq!(x, y);
            drop(va);
            drop(vb);
            a.commit_parallel().unwrap();
            b.commit_parallel().unwrap();
            let mut original = vec![0; 8192];
            child.read(0x2000, &mut original).unwrap();
            let pattern: Vec<u8> = (0..8192)
                .map(|i| (i as u8).wrapping_mul(17).wrapping_add(0x80))
                .collect();
            assert_eq!(original, pattern);
            if NATIVE_COMPILED {
                assert_eq!(
                    (
                        eb.stats.fallback_instructions,
                        eb.memory_stats().instructions
                    ),
                    (0, 1)
                );
            }
        }
    }
}

#[test]
fn native_full_store_does_not_read_a_staging_only_backing() {
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    };
    use trames_memory::{MemoryError, PageBacking};
    #[derive(Default)]
    struct Output {
        bytes: Mutex<Vec<u8>>,
        reads: AtomicU64,
        version: AtomicU64,
    }
    impl PageBacking for Output {
        fn check(&self, _: u64) -> Result<(), MemoryError> {
            Ok(())
        }
        fn read(&self, _: usize, _: &mut [u8]) -> Result<(), MemoryError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Err(MemoryError::BackingIo(5))
        }
        fn write(&self, offset: usize, bytes: &[u8]) -> Result<(), MemoryError> {
            let mut out = self.bytes.lock().unwrap();
            out.resize(4096, 0);
            out[offset..offset + bytes.len()].copy_from_slice(bytes);
            self.version.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn sync(&self) -> Result<(), MemoryError> {
            Ok(())
        }
        fn version(&self) -> u64 {
            self.version.load(Ordering::Relaxed)
        }
        fn writable(&self) -> bool {
            true
        }
        fn next_page(&self, _: u64) -> Result<Arc<dyn PageBacking>, MemoryError> {
            Err(MemoryError::BackingIo(5))
        }
    }
    for word in [
        0xf9000020, 0xa9000820, 0xc89ffc20, 0x3d800020, 0xad000420, 0x4c002020, 0xd50b7421,
    ] {
        let output = Arc::new(Output::default());
        let mut m = memory(&[word]);
        m.unmap(0x2000, PAGE_SIZE).unwrap();
        m.map_backed(
            0x2000,
            vec![output.clone()],
            true,
            Permissions {
                read: false,
                write: true,
                execute: false,
            },
            false,
        )
        .unwrap();
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(0, 0x8877665544332211);
        cpu.set_x(1, 0x2000);
        let mut state = cpu.architectural_state();
        state.vectors[0] = 0x8877665544332211;
        cpu.restore_architectural_state(&state);
        let mut engine = Engine::default();
        assert_eq!(
            outcome(&cpu.run_slice(&mut engine, &mut m, 1)),
            ("yield", 1)
        );
        assert_eq!(output.reads.load(Ordering::Relaxed), 0);
        if word == 0xd50b7421 {
            assert_eq!(&output.bytes.lock().unwrap()[..64], &[0; 64]);
        } else {
            assert_eq!(
                &output.bytes.lock().unwrap()[..8],
                &0x8877665544332211u64.to_le_bytes()
            );
        }
        if NATIVE_COMPILED {
            assert_eq!(
                (
                    engine.memory_stats().instructions,
                    engine.memory_stats().staged,
                    engine.stats.fallback_instructions
                ),
                (1, 1, 0)
            );
        }
    }
}

#[test]
fn separate_native_load_and_store_do_not_make_guest_rmw_atomic() {
    let mut m = memory(&[0xf9400020, 0x91000400, 0xf9000020, 0xd4000001]);
    let mut registry = trames_memory::parallel::Registry::default();
    let mut a = m.parallel_view(&mut registry).unwrap();
    let mut b = m.parallel_view(&mut registry).unwrap();
    let mut c1 = Cpu::new(0x1000, 0);
    let mut c2 = Cpu::new(0x1000, 0);
    c1.set_x(1, 0x2000);
    c2.set_x(1, 0x2000);
    let mut e1 = Engine::default();
    let mut e2 = Engine::default();
    assert_eq!(outcome(&c1.run_parallel(&mut e1, &mut a, 1)), ("yield", 1));
    assert_eq!(outcome(&c2.run_parallel(&mut e2, &mut b, 1)), ("yield", 1));
    assert_eq!((c1.x(0), c2.x(0)), (0, 0));
    assert_eq!(
        outcome(&c1.run_parallel(&mut e1, &mut a, 3)),
        ("syscall", 3)
    );
    assert_eq!(
        outcome(&c2.run_parallel(&mut e2, &mut b, 3)),
        ("syscall", 3)
    );
    assert_eq!(a.read_u64(0x2000).unwrap(), 1); // Allowed lost update, no algorithm lock.
    if NATIVE_COMPILED {
        assert_eq!(
            (
                e1.stats.fallback_instructions,
                e2.stats.fallback_instructions
            ),
            (0, 0)
        );
        assert_eq!(
            (
                e1.memory_stats().instructions,
                e2.memory_stats().instructions
            ),
            (2, 2)
        );
    }
}

#[test]
fn fused_memory_loops_keep_state_and_retirement_at_every_budget() {
    let words = [
        0x910003e1, // add x1,sp,#0
        0xf9400020, // ldr x0,[x1]
        0xb1000400, // adds x0,x0,#1
        0xf9000020, // str x0,[x1]
        0x9a1f0003, // adc x3,x0,xzr (flags survive the memory helper)
        0xf1000442, // subs x2,x2,#1
        0x54ffff61, // b.ne 0x1004
        0xd4000001,
    ];
    for parallel in [false, true] {
        for budget in [0, 1, 2, 3, 4, 5, 6, 7, 8, 31, 32, 33, 63, 64, 65, 1024] {
            let mut a = memory(&words);
            let mut b = memory(&words);
            a.write_array(0x2fe0, (u64::MAX - 3).to_le_bytes()).unwrap();
            b.write_array(0x2fe0, (u64::MAX - 3).to_le_bytes()).unwrap();
            let mut state = initial();
            state.sp = 0x2fe0;
            state.registers[2] = 17;
            let mut expected = trames_interpreter::Cpu::new(0, 0);
            let mut actual = Cpu::new(0, 0);
            expected.restore_architectural_state(&state);
            actual.restore_architectural_state(&state);
            let mut engine = Engine::default();
            let mut registry = trames_memory::parallel::Registry::default();
            let mut view = parallel.then(|| b.parallel_view(&mut registry).unwrap());
            for _ in 0..256 {
                let x = expected.run_slice(&mut a, budget);
                let y = if let Some(view) = &mut view {
                    actual.run_parallel(&mut engine, view, budget)
                } else {
                    actual.run_slice(&mut engine, &mut b, budget)
                };
                assert_eq!(outcome(&x), outcome(&y), "budget={budget} view={parallel}");
                assert_eq!(actual.architectural_state(), expected.architectural_state());
                let bytes = if let Some(view) = &view {
                    view.read_u64(0x2fe0).unwrap()
                } else {
                    b.read_u64(0x2fe0).unwrap()
                };
                assert_eq!(bytes, a.read_u64(0x2fe0).unwrap());
                if matches!(x, SliceOutcome::Syscall { .. }) || budget == 0 {
                    break;
                }
            }
            if budget != 0 {
                assert_eq!(actual.pc(), 0x1020);
            }
            if NATIVE_COMPILED {
                assert_eq!(engine.stats.fallback_instructions, 0);
                if budget == 1024 {
                    assert!(engine.memory_stats().fused_entries < 8);
                    assert!(engine.memory_stats().fused_blocks >= 17);
                }
            }
        }
    }
}

#[test]
fn fused_memory_faults_publish_the_exact_dirty_prefix_and_do_not_replay() {
    let prefix = [0x91000400, 0xd10043ff, 0xb1000463, 0xf9000020, 0x910004c6];
    for cut in 0..=prefix.len() {
        let mut words = prefix[..cut].to_vec();
        words.extend_from_slice(&[0xf94000a4, 0x910004e7, 0xd4000001]); // ldr x4,[x5]
        for parallel in [false, true] {
            for budget in [1, 2, 3, 4, 64] {
                let mut a = memory(&words);
                let mut b = memory(&words);
                let mut state = initial();
                state.registers[1] = 0x2000;
                state.registers[3] = u64::MAX;
                state.registers[5] = 0x4000;
                let mut expected = trames_interpreter::Cpu::new(0, 0);
                let mut actual = Cpu::new(0, 0);
                expected.restore_architectural_state(&state);
                actual.restore_architectural_state(&state);
                let mut engine = Engine::default();
                let mut registry = trames_memory::parallel::Registry::default();
                let mut view = parallel.then(|| b.parallel_view(&mut registry).unwrap());
                for _ in 0..8 {
                    let x = expected.run_slice(&mut a, budget);
                    let y = if let Some(view) = &mut view {
                        actual.run_parallel(&mut engine, view, budget)
                    } else {
                        actual.run_slice(&mut engine, &mut b, budget)
                    };
                    assert_eq!(format!("{x:?}"), format!("{y:?}"));
                    assert_eq!(actual.architectural_state(), expected.architectural_state());
                    if matches!(x, SliceOutcome::Fault(_)) {
                        assert_eq!(actual.fault_retired(), expected.fault_retired());
                        // A second attempt faults at its first instruction; no
                        // retired prefix or successful store is replayed.
                        let x = expected.run_slice(&mut a, budget);
                        let y = if let Some(view) = &mut view {
                            actual.run_parallel(&mut engine, view, budget)
                        } else {
                            actual.run_slice(&mut engine, &mut b, budget)
                        };
                        assert_eq!(format!("{x:?}"), format!("{y:?}"));
                        assert_eq!(actual.fault_retired(), 0);
                        assert_eq!(actual.architectural_state(), expected.architectural_state());
                        break;
                    }
                }
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.native_instructions, cut as u64);
                }
                assert_eq!(actual.pc(), 0x1000 + cut as u64 * 4);
                let bytes = if let Some(view) = &view {
                    view.read_u64(0x2000).unwrap()
                } else {
                    b.read_u64(0x2000).unwrap()
                };
                assert_eq!(bytes, a.read_u64(0x2000).unwrap());
            }
        }
    }
}

#[test]
fn parallel_code_write_interrupts_a_running_fused_memory_loop() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut m = memory(&[0xf9400020, 0x91000400, 0xf9000020, 0x17fffffd]);
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
    let mut registry = trames_memory::parallel::Registry::default();
    let mut reader = m.parallel_view(&mut registry).unwrap();
    let mut writer = reader.clone();
    let mut cpu = Cpu::new(0x1000, 0);
    cpu.set_x(1, 0x2000);
    let mut engine = Engine::default();
    cpu.run_parallel(&mut engine, &mut reader, 128);
    reader.write_array(0x2000, 0u64.to_le_bytes()).unwrap();
    cpu.set_x(0, 0);
    cpu.set_pc(0x1000);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let other = barrier.clone();
    let thread = std::thread::spawn(move || {
        other.wait();
        std::thread::sleep(std::time::Duration::from_millis(1));
        writer
            .write_array(0x1000, 0xd4000001u32.to_le_bytes())
            .unwrap();
    });
    barrier.wait();
    let result = cpu.run_parallel(&mut engine, &mut reader, 100_000_000);
    thread.join().unwrap();
    let SliceOutcome::Syscall { instructions } = result else {
        panic!("fused loop missed changed code: {result:?}");
    };
    assert_eq!(instructions, cpu.x(0) * 4 + 1);
    assert_eq!(cpu.pc(), 0x1004);
    assert!(engine.memory_stats().fused_blocks > engine.memory_stats().fused_entries);
}

#[test]
fn hardware_alias_scalar_forms_keep_live_bindings_flags_and_writeback() {
    if !NATIVE_COMPILED {
        return;
    }
    let mut cases = Vec::new();
    for size in 0..4u32 {
        for opc in 0..4u32 {
            if (size >= 2 && opc == 3) || (size == 3 && opc == 2) {
                continue;
            }
            for mode in 0..4u32 {
                // Unscaled, post/pre and unprivileged. Source/dest aliases and
                // tagged SP exercise the same emitter with warm page loans.
                for rt in [0, 1, 31] {
                    if matches!(mode, 1 | 3) && rt == 1 {
                        continue;
                    }
                    cases.push(
                        (size << 30)
                            | 0x38000000
                            | (opc << 22)
                            | (8 << 12)
                            | (mode << 10)
                            | (1 << 5)
                            | rt,
                    );
                }
            }
            for option in [2, 3, 6, 7] {
                for scaled in [0, 1] {
                    cases.push(
                        (size << 30)
                            | 0x38200820
                            | (opc << 22)
                            | (2 << 16)
                            | (option << 13)
                            | (scaled << 12),
                    );
                }
            }
        }
    }
    cases.extend([0xf84087e0, 0xf8008fe0, 0x394003ff, 0xf9400021]);
    for word in cases {
        let words = [
            0xf94003bc, 0xf90003bc, 0xb1000463, word, 0x9a9f37e4, 0xd4000001,
        ];
        let mut a = memory(&words);
        let mut b = memory(&words);
        for m in [&mut a, &mut b] {
            m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
            m.write(0x10000, &vec![0x85; hardware_span() as usize])
                .unwrap();
        }
        let mut state = initial();
        state.registers[1] = 0xab00_0000_0001_0080;
        state.registers[2] = 1;
        state.registers[3] = u64::MAX;
        state.registers[29] = 0x10000;
        state.sp = 0xcd00_0000_0001_0100;
        let mut expected = trames_interpreter::Cpu::new(0, 0);
        let mut actual = Cpu::new(0, 0);
        expected.restore_architectural_state(&state);
        actual.restore_architectural_state(&state);
        let mut engine = Engine::default();
        assert_eq!(
            outcome(&expected.run_slice(&mut a, 64)),
            outcome(&actual.run_slice(&mut engine, &mut b, 64)),
            "{word:08x}"
        );
        assert_eq!(
            actual.architectural_state(),
            expected.architectural_state(),
            "{word:08x}"
        );
        assert_eq!(
            a.read_array::<16384>(0x10000).unwrap(),
            b.read_array::<16384>(0x10000).unwrap(),
            "{word:08x}"
        );
        assert!(
            engine.memory_stats().hardware > 0,
            "{word:08x}: {:?}",
            engine.memory_stats()
        );
    }
}

#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
#[test]
fn hardware_faults_rejoin_checked_access_with_exact_cpu_state() {
    use trames_memory::{Access, InstructionEpochs, MemoryError, NativePage};
    struct Revoked {
        memory: Memory,
        alias: usize,
        exports: usize,
        store: bool,
    }
    impl CpuMemory for Revoked {
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
        fn cpu_hardware_ordering(&self) -> bool {
            true
        }
        fn cpu_native_available(&self) -> bool {
            self.memory.cpu_native_available()
        }
        unsafe fn cpu_native_page(&mut self, address: u64, write: bool) -> Option<NativePage> {
            self.exports += 1;
            if self.exports == 3 {
                // The fault recovery must have returned to checked canonical
                // access, without skipping a Rust frame or replaying the prefix.
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            self.alias as *mut _,
                            trames_memory::host_mapping_granule(),
                            libc::PROT_READ | libc::PROT_WRITE,
                        )
                    },
                    0
                );
                return None;
            }
            let page = unsafe { self.memory.cpu_native_page(address, write) }?;
            if self.exports == 2 {
                self.alias = page.read & !(trames_memory::host_mapping_granule() - 1);
                let protection = if self.store {
                    libc::PROT_READ
                } else {
                    libc::PROT_NONE
                };
                assert_eq!(
                    unsafe {
                        libc::mprotect(
                            self.alias as *mut _,
                            trames_memory::host_mapping_granule(),
                            protection,
                        )
                    },
                    0
                );
            }
            Some(page)
        }
        fn instruction_epochs(&self) -> Option<InstructionEpochs<'_>> {
            self.memory.instruction_epochs()
        }
        fn mapped_at_or_after(&self, a: u64) -> bool {
            self.memory.mapped_at_or_after(a)
        }
        fn read(&self, a: u64, out: &mut [u8]) -> Result<(), MemoryError> {
            self.memory.read(a, out)
        }
        fn write(&mut self, a: u64, bytes: &[u8]) -> Result<(), MemoryError> {
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
    }
    for (store, word) in [
        (false, 0xf8408420),
        (true, 0xf80087a0),
        (false, 0xa8c10820),
        (true, 0xa8810ba0),
        (false, 0xc8dffc20),
        (true, 0xc89fffa0),
        (true, 0xf82403a0),
        (true, 0x48287faa),
        (false, 0x3dc00024),
        (true, 0x3d8003a4),
        (false, 0xad401424),
        (true, 0xad0017a4),
        (false, 0x4c40203f),
        (true, 0x4c0023bf),
        (false, 0x4d60c03f),
        (true, 0x4d2023bf),
        (true, 0xd50b743d),
    ] {
        if (word == 0xf82403a0 || word == 0x48287faa) && !host_capability(8) {
            continue;
        }
        let words = if store {
            // The read succeeds with host PROT_READ, then the following store
            // reuses that exact translated address and faults. Its recovery
            // must also preserve newer flags and post-index writeback.
            [
                0xf94003bc, 0xf90003bc, 0xf94003a0, 0x910004a5, 0xb1000463, word, 0x9a9f37e4,
                0xd4000001,
            ]
        } else {
            [
                0xf94003bc, 0xf94003bc, 0xf90003bc, 0x910004a5, 0xb1000463, word, 0x9a9f37e4,
                0xd4000001,
            ]
        };
        let mut words = words.to_vec();
        words.insert(5, 0x1e6728c4); // FADD d4,d6,d7: a dirty vector prefix
        let mut a = memory(&words);
        let mut b = memory(&words);
        for m in [&mut a, &mut b] {
            m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
            m.write(0x10000, &vec![0x85; hardware_span() as usize])
                .unwrap();
        }
        let mut state = initial();
        state.registers[1] = 0xab00_0000_0001_0080;
        state.registers[3] = u64::MAX;
        state.registers[8] = 0x8585858585858585;
        state.registers[9] = 0x8585858585858585;
        state.registers[29] = 0x10000;
        let mut expected = trames_interpreter::Cpu::new(0, 0);
        let mut actual = Cpu::new(0, 0);
        expected.restore_architectural_state(&state);
        actual.restore_architectural_state(&state);
        let mut revoked = Revoked {
            memory: b,
            alias: 0,
            exports: 0,
            store,
        };
        let mut engine = Engine::default();
        assert_eq!(
            outcome(&expected.run_slice(&mut a, 64)),
            outcome(&actual.run_slice(&mut engine, &mut revoked, 64))
        );
        assert_eq!(actual.architectural_state(), expected.architectural_state());
        assert_eq!(revoked.exports, 3);
        assert_eq!(engine.memory_stats().hardware, 1);
        assert_eq!(
            a.read_array::<16384>(0x10000).unwrap(),
            revoked.memory.read_array::<16384>(0x10000).unwrap()
        );
    }
}

#[test]
fn hardware_alias_loans_end_at_permissions_replacement_fork_and_worker_boundaries() {
    if !NATIVE_COMPILED {
        return;
    }
    let words = [0xf9400020, 0xf9400022, 0x91000400, 0xf9000020, 0xd4000001];
    let mut m = memory(&words);
    m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
    m.write(0x10000, &vec![0; hardware_span() as usize])
        .unwrap();
    let mut cpu = Cpu::new(0x1000, 0);
    cpu.set_x(1, 0x10000);
    let mut engine = Engine::default();
    assert_eq!(
        outcome(&cpu.run_slice(&mut engine, &mut m, 64)),
        ("syscall", 5)
    );
    assert_eq!(engine.memory_stats().hardware, 1);
    m.protect(0x10000, hardware_span(), Permissions::R).unwrap();
    cpu.set_pc(0x1000);
    assert!(matches!(
        cpu.run_slice(&mut engine, &mut m, 64),
        SliceOutcome::Fault(_)
    ));
    assert_eq!(cpu.fault_retired(), 3);
    assert_eq!(cpu.pc(), 0x100c);
    assert_eq!(m.read_u64(0x10000).unwrap(), 1);
    m.map_fixed(0x10000, hardware_span(), Permissions::RW)
        .unwrap();
    m.write(0x10000, &vec![0; hardware_span() as usize])
        .unwrap();
    cpu.set_pc(0x1000);
    assert_eq!(
        outcome(&cpu.run_slice(&mut engine, &mut m, 64)),
        ("syscall", 5)
    );
    assert_eq!(m.read_u64(0x10000).unwrap(), 1);
    let fork = m.clone();
    cpu.set_pc(0x1000);
    assert_eq!(
        outcome(&cpu.run_slice(&mut engine, &mut m, 64)),
        ("syscall", 5)
    );
    assert_eq!(m.read_u64(0x10000).unwrap(), 2);
    assert_eq!(fork.read_u64(0x10000).unwrap(), 1);
    drop(fork);
    let mut registry = trames_memory::parallel::Registry::default();
    let mut view = m.parallel_view(&mut registry).unwrap();
    let other = view.clone(); // guard-required shared RW cannot borrow CPU aliases
    let before = engine.memory_stats().hardware;
    cpu.set_pc(0x1000);
    assert_eq!(
        outcome(&cpu.run_parallel(&mut engine, &mut view, 64)),
        ("syscall", 5)
    );
    assert_eq!(engine.memory_stats().hardware, before);
    assert_eq!(other.read_u64(0x10000).unwrap(), 3);
}

#[test]
fn hardware_alias_readonly_and_sparse_pages_share_the_frozen_memory_model() {
    if !NATIVE_COMPILED {
        return;
    }
    // Three distinct guest pages warm separate inline tags in one entry; all
    // loads are from immutable private bytes, including a sparse high address.
    let words = [
        0xf9400020, 0xf9400043, 0xf9400085, 0xf9400026, 0xf9400047, 0xf9400088, 0xd4000001,
    ];
    let mut m = memory(&words);
    for base in [0x10000, 0x20000, 0x1000030000] {
        m.map(base, hardware_span(), Permissions::RW).unwrap();
        m.write(base, &vec![0x85; hardware_span() as usize])
            .unwrap();
        m.protect(base, hardware_span(), Permissions::R).unwrap();
    }
    let mut registry = trames_memory::parallel::Registry::default();
    let mut a = m.parallel_view(&mut registry).unwrap();
    let mut b = a.clone();
    assert!(unsafe { trames_memory::parallel::View::try_private_epoch(&mut [&mut a, &mut b]) });
    for view in [&mut a, &mut b] {
        let mut cpu = Cpu::new(0x1000, 0);
        cpu.set_x(1, 0x10000);
        cpu.set_x(2, 0x20000);
        cpu.set_x(4, 0x1000030000);
        let mut engine = Engine::default();
        assert_eq!(
            outcome(&cpu.run_parallel(&mut engine, view, 64)),
            ("syscall", 7)
        );
        assert_eq!(engine.memory_stats().hardware, 3);
        for reg in [0, 3, 5, 6, 7, 8] {
            assert_eq!(cpu.x(reg), 0x8585858585858585);
        }
    }
}

#[test]
fn affine_address_reuse_rechecks_changed_bases_indices_sp_and_operand_width() {
    if !NATIVE_COMPILED {
        return;
    }
    let cases: &[(&[u32], u64)] = &[
        (&[0xf9400020, 0x91002021, 0xf9400023], 0x10000),
        (&[0xf8627820, 0x91000442, 0xf8627823], 0x10000),
        (&[0xf9400021, 0xf9400023], 0x10000),
        (&[0xf94003e0, 0x910023ff, 0xf94003e3], 0x10000),
        (&[0xf9400020, 0xf8008420, 0xf9400023], 0x10000),
        (&[0x39400020, 0xf9400023], 0x10fff),
    ];
    for &(body, address) in cases {
        let mut words = vec![0xf94003bc, 0xf90003bc]; // paid RW page admission
        words.extend_from_slice(body);
        words.push(0xd4000001);
        for parallel in [false, true] {
            let mut a = memory(&words);
            let mut b = memory(&words);
            for m in [&mut a, &mut b] {
                m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
                let mut data = vec![0; hardware_span() as usize];
                for (i, chunk) in data.chunks_exact_mut(8).enumerate() {
                    chunk.copy_from_slice(&(0x10008 + i as u64 * 17).to_le_bytes());
                }
                m.write(0x10000, &data).unwrap();
            }
            let mut state = initial();
            state.registers[1] = address;
            state.registers[2] = 0;
            state.registers[29] = 0x100f0;
            state.sp = 0x10000;
            let mut reference = trames_interpreter::Cpu::default();
            reference.restore_architectural_state(&state);
            let mut actual = Cpu::default();
            actual.restore_architectural_state(&state);
            let mut engine = Engine::default();
            let x = reference.run_slice(&mut a, 64);
            let y = if parallel {
                let mut registry = trames_memory::parallel::Registry::default();
                let mut view = b.parallel_view(&mut registry).unwrap();
                assert!(unsafe {
                    trames_memory::parallel::View::try_private_epoch(&mut [&mut view])
                });
                let result = actual.run_parallel(&mut engine, &mut view, 64);
                drop(view);
                b.commit_parallel().unwrap();
                result
            } else {
                actual.run_slice(&mut engine, &mut b, 64)
            };
            assert_eq!(
                format!("{x:?}"),
                format!("{y:?}"),
                "{body:x?} parallel={parallel}"
            );
            assert_eq!(
                actual.architectural_state(),
                reference.architectural_state(),
                "{body:x?}"
            );
            assert_eq!(actual.fault_retired(), reference.fault_retired());
            assert_eq!(
                a.read_array::<16384>(0x10000).unwrap(),
                b.read_array::<16384>(0x10000).unwrap()
            );
            assert_eq!(engine.stats.fallback_instructions, 0);
            if address == 0x10fff {
                assert_eq!(engine.memory_stats().staged, 1);
            }
        }
    }
}

#[test]
fn affine_runs_join_only_adjacent_admitted_pages_and_never_bridge_holes() {
    if !NATIVE_COMPILED {
        return;
    }
    // Read-only immutable exports may form a run across pages. Returning to the
    // first page must take the region path after the second export, not the TLB.
    let words = [0xf9400020, 0xf9400043, 0xf9400024, 0xf9400045, 0xd4000001];
    let mut m = memory(&words);
    m.map(0x10000, hardware_span(), Permissions::RW).unwrap();
    m.write(0x10000, &vec![0x85; hardware_span() as usize])
        .unwrap();
    m.protect(0x10000, hardware_span(), Permissions::R).unwrap();
    let mut registry = trames_memory::parallel::Registry::default();
    let mut view = m.parallel_view(&mut registry).unwrap();
    assert!(unsafe { trames_memory::parallel::View::try_private_epoch(&mut [&mut view]) });
    let mut cpu = Cpu::new(0x1000, 0);
    cpu.set_x(1, 0x10000);
    cpu.set_x(2, 0x11000);
    let mut engine = Engine::default();
    assert_eq!(
        outcome(&cpu.run_parallel(&mut engine, &mut view, 64)),
        ("syscall", 5)
    );
    assert_eq!(engine.memory_stats().direct, 2);
    drop(view);
    // A hole between two readable runs cannot inherit the common affine bias.
    m.unmap(0x11000, PAGE_SIZE).unwrap();
    m.protect(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    let words = [0xf9400020u32, 0xf9400043, 0xf9400085, 0xd4000001];
    for (i, word) in words.iter().enumerate() {
        m.write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    let mut view = m.parallel_view(&mut registry).unwrap();
    assert!(unsafe { trames_memory::parallel::View::try_private_epoch(&mut [&mut view]) });
    cpu.set_pc(0x1000);
    cpu.set_x(1, 0x10000);
    cpu.set_x(2, 0x12000);
    cpu.set_x(4, 0x11000);
    assert!(matches!(
        cpu.run_parallel(&mut engine, &mut view, 64),
        SliceOutcome::Fault(_)
    ));
    assert_eq!(cpu.fault_retired(), 2);
    assert_eq!(cpu.pc(), 0x1008);
}

#[path = "arithmetic/category.rs"]
mod arithmetic_category;

#[path = "support/exclusive_category.rs"]
mod exclusive_category;

#[path = "support/mops_category.rs"]
mod mops_category;

#[path = "support/special_memory_category.rs"]
mod special_memory_category;

#[path = "support/compatibility_category.rs"]
mod compatibility_category;

#[path = "support/execution_boundary_category.rs"]
mod execution_boundary_category;

#[path = "support/control_category.rs"]
mod control_category;
