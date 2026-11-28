// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

fn admitted() -> bool {
    !NATIVE_COMPILED || trames_jit::host_features().unwrap().hwcap2 & (1 << 43) != 0
}
fn triple(base: u32, d: u32, s: u32, n: u32) -> [u32; 3] {
    let shift = if base & 0x00c00000 == 0x00c00000 {
        14
    } else {
        22
    };
    std::array::from_fn(|stage| base | (stage as u32) << shift | d | s << 16 | n << 5)
}
fn finish(cpu: &mut Cpu, engine: &mut Engine, memory: &mut impl CpuMemory, budget: u64) -> u64 {
    let mut retired = 0;
    for _ in 0..128 {
        match cpu.run_slice(engine, memory, budget) {
            SliceOutcome::Yield { instructions } => retired += instructions,
            SliceOutcome::Syscall { instructions } => return retired + instructions,
            other => panic!("{other:?}; state={:?}", cpu.architectural_state()),
        }
    }
    panic!("MOPS did not finish at {:x}", cpu.pc());
}
fn exercise(words: &[u32], state: &Aarch64State, expected: &[u8], budget: u64, mode: usize) {
    let mut m = memory(words);
    m.map(0x10000, 0x20000, Permissions::RW).unwrap();
    let original: Vec<_> = (0..0x20000)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add((i >> 8) as u8))
        .collect();
    m.write(0x10000, &original).unwrap();
    let mut cpu = Cpu::new(0, 0);
    cpu.restore_architectural_state(state);
    let mut engine = Engine::default();
    let mut bytes = vec![0; 0x20000];
    if mode == 0 {
        assert_eq!(finish(&mut cpu, &mut engine, &mut m, budget), 4);
        m.read(0x10000, &mut bytes).unwrap();
    } else {
        let mut registry = trames_memory::parallel::Registry::default();
        let mut view = m.parallel_view(&mut registry).unwrap();
        if mode == 2 {
            assert!(unsafe { trames_memory::parallel::View::try_private_epoch(&mut [&mut view]) });
        }
        assert_eq!(finish(&mut cpu, &mut engine, &mut view, budget), 4);
        view.read(0x10000, &mut bytes).unwrap();
    }
    assert_eq!(
        bytes, expected,
        "words={words:x?}; budget={budget}; mode={mode}"
    );
    let actual = cpu.architectural_state();
    let d = (words[0] & 31) as usize;
    let s = ((words[0] >> 16) & 31) as usize;
    let n = ((words[0] >> 5) & 31) as usize;
    let set = words[0] & 0x00c00000 == 0x00c00000;
    let moving = !set && words[0] & (1 << 26) != 0;
    let count = state.registers[n];
    let destination = state.registers[d];
    let source = if s == 31 { 0 } else { state.registers[s] };
    let overlap = source < destination && source + count > destination;
    let forward = actual.registers[d] == destination.wrapping_add(count)
        && (set || actual.registers[s] == source.wrapping_add(count));
    let backwards = moving && actual.registers[d] == destination && actual.registers[s] == source;
    assert!(
        if !moving {
            forward
        } else if overlap {
            backwards
        } else {
            forward || backwards
        },
        "{actual:?}"
    );
    assert_eq!(actual.registers[n], 0);
    assert!(
        matches!(actual.nzcv, 0 | 2 | 10),
        "real algorithm NZCV={:x}",
        actual.nzcv
    );
    let mut expected_state = state.clone();
    expected_state.pc = 0x1010;
    expected_state.nzcv = actual.nzcv;
    expected_state.registers[d] = actual.registers[d];
    if !set {
        expected_state.registers[s] = actual.registers[s];
    }
    expected_state.registers[n] = 0;
    assert_eq!(actual, expected_state);
    for (i, &word) in words.iter().enumerate() {
        assert_eq!(m.fetch_u32(0x1000 + i as u64 * 4).unwrap(), word);
    }
    if NATIVE_COMPILED {
        assert_eq!(engine.stats.fallback_instructions, 0);
    }
}

#[test]
fn entire_mops_copy_move_set_options_preserve_banks_bytes_and_slice_budgets() {
    if !admitted() {
        return;
    }
    for base in [0x19000400u32, 0x1d000400, 0x19c00400] {
        let set = base == 0x19c00400;
        for options in 0..if set { 4 } else { 16 } {
            for count in [0, 1, 4097, 16381] {
                for budget in [1, 2, 64] {
                    for mode in 0..3 {
                        let (d, s, n) = if options & 1 == 0 {
                            (0, 1, 2)
                        } else {
                            (18, 30, 29)
                        };
                        let ops = triple(base | options << 12, d, s, n);
                        let words = [ops[0], ops[1], ops[2], 0xd4000001];
                        let mut state = initial();
                        state.registers[d as usize] = 0x20003;
                        state.registers[s as usize] = if set { 0x83 } else { 0x10005 };
                        state.registers[n as usize] = count;
                        let mut expected: Vec<_> = (0..0x20000)
                            .map(|i| (i as u8).wrapping_mul(17).wrapping_add((i >> 8) as u8))
                            .collect();
                        if set {
                            expected[0x10003..0x10003 + count as usize].fill(0x83);
                        } else {
                            expected.copy_within(5..5 + count as usize, 0x10003);
                        }
                        exercise(&words, &state, &expected, budget, mode);
                    }
                }
            }
        }
    }
}

#[test]
fn mops_overlap_zero_fill_and_long_cooperative_progress_use_real_stages() {
    if !admitted() {
        return;
    }
    for (base, destination, source) in [
        (0x1d000400, 0x10013, 0x10005),
        (0x1d000400, 0x10005, 0x10013),
        (0x1d000400, 0x10005, 0x10005),
        (0x19000400, 0x10005, 0x10013),
        (0x19c00400, 0x10005, 0),
    ] {
        for count in [15, 8197, 70013] {
            for budget in [1, 2, 64] {
                for mode in 0..3 {
                    let set = base == 0x19c00400;
                    let s = if set { 31 } else { 17 };
                    let ops = triple(base, 18, s, 29);
                    let words = [ops[0], ops[1], ops[2], 0xd4000001];
                    let mut state = initial();
                    state.registers[18] = destination;
                    if !set {
                        state.registers[17] = source;
                    }
                    state.registers[29] = count;
                    let mut expected: Vec<_> = (0..0x20000)
                        .map(|i| (i as u8).wrapping_mul(17).wrapping_add((i >> 8) as u8))
                        .collect();
                    let start = (destination - 0x10000) as usize;
                    if set {
                        expected[start..start + count as usize].fill(0);
                    } else {
                        let from = (source - 0x10000) as usize;
                        expected.copy_within(from..from + count as usize, start);
                    }
                    exercise(&words, &state, &expected, budget, mode);
                }
            }
        }
    }
}

#[test]
fn absent_mops_faults_at_reached_pc_without_interpreter_entry() {
    if !NATIVE_COMPILED || admitted() {
        return;
    }
    for base in [0x19000400, 0x1d000400, 0x19c00400] {
        for word in triple(base, 0, 1, 2) {
            let mut m = memory(&[0x91000529, word]);
            let mut cpu = Cpu::new(0x1000, 0x2800);
            let mut engine = Engine::default();
            assert!(matches!(
                cpu.run_slice(&mut engine, &mut m, 64),
                SliceOutcome::Fault(_)
            ));
            assert_eq!(cpu.pc(), 0x1004);
            assert_eq!(cpu.fault_retired(), 1);
            assert_eq!(cpu.x(9), 1);
            assert_eq!(engine.stats.fallback_instructions, 0);
        }
    }
}

#[test]
fn mops_memory_faults_publish_the_real_stage_dirty_prefix_and_original_error() {
    if !admitted() {
        return;
    }
    for base in [0x19000400, 0x1d000400, 0x19c00400] {
        for source_fault in [false, true] {
            if source_fault && base == 0x19c00400 {
                continue;
            }
            for protected in [false, true] {
                let ops = triple(base, 0, 1, 2);
                let mut m = memory(&[0x91000529, ops[0], ops[1], ops[2], 0xd4000001]);
                m.map(0x10000, 0x10000, Permissions::RW).unwrap();
                m.map(0x20000, 0x10000, Permissions::RW).unwrap();
                m.write(0x10000, &[0x83; 0x10000]).unwrap();
                m.write(0x20000, &[0; 0x10000]).unwrap();
                let address = if source_fault { 0x11000 } else { 0x21000 };
                let access = if source_fault {
                    trames_memory::Access::Read
                } else {
                    trames_memory::Access::Write
                };
                if protected {
                    m.protect(address, PAGE_SIZE, Permissions::NONE).unwrap();
                } else {
                    m.unmap(address, PAGE_SIZE).unwrap();
                }
                let mut cpu = Cpu::new(0x1000, 0x2800);
                cpu.set_x(0, 0x20000);
                cpu.set_x(1, if base == 0x19c00400 { 0x83 } else { 0x10000 });
                cpu.set_x(2, 12000);
                cpu.set_x(9, 10);
                let mut engine = Engine::default();
                let result = cpu.run_slice(&mut engine, &mut m, 64);
                let SliceOutcome::Fault(trames_engine::CpuFault::Memory { pc, error }) = result
                else {
                    panic!("{result:?}")
                };
                assert_eq!(pc, cpu.pc());
                assert!([0x1004, 0x1008, 0x100c].contains(&pc));
                assert_eq!(cpu.fault_retired(), (pc - 0x1000) / 4);
                assert_eq!(cpu.x(9), 11);
                if protected {
                    assert_eq!(
                        error,
                        trames_memory::MemoryError::Permission { address, access }
                    );
                } else {
                    assert_eq!(error, trames_memory::MemoryError::Unmapped(address));
                }
                assert_eq!(m.read_array::<4096>(0x20000).unwrap(), [0x83; 4096]);
                if NATIVE_COMPILED {
                    assert_eq!(engine.stats.fallback_instructions, 0);
                }
            }
        }
    }
}

#[test]
fn mops_writes_share_the_original_reservation_domain_without_clearing_read_only_tokens() {
    if !admitted() {
        return;
    }
    for base in [0x19000400, 0x1d000400, 0x19c00400] {
        let ops = triple(base, 0, 1, 2);
        let mut m = memory(&[ops[0], ops[1], ops[2], 0xd4000001]);
        m.map(0x10000, 0x20000, Permissions::RW).unwrap();
        m.write(0x10000, &[0x83; 0x10000]).unwrap();
        m.write(0x20000, &[0; 0x10000]).unwrap();
        let mut bytes = [0; 8];
        let source = m.exclusive_read(0x10000, &mut bytes).unwrap();
        let destination = m.exclusive_read(0x20000, &mut bytes).unwrap();
        let mut cpu = Cpu::new(0x1000, 0x2800);
        cpu.set_x(0, 0x20000);
        cpu.set_x(1, if base == 0x19c00400 { 0x83 } else { 0x10000 });
        cpu.set_x(2, 16381);
        let mut engine = Engine::default();
        assert_eq!(finish(&mut cpu, &mut engine, &mut m, 64), 4);
        assert_eq!(m.exclusive_read(0x10000, &mut bytes).unwrap(), source);
        assert_ne!(m.exclusive_read(0x20000, &mut bytes).unwrap(), destination);
        assert_eq!(m.read_array::<16>(0x20000).unwrap(), [0x83; 16]);
        if NATIVE_COMPILED {
            assert_eq!(engine.stats.fallback_instructions, 0);
        }
    }
}

#[test]
fn mops_preserves_independent_top_bytes_and_zero_length_ignores_unmapped_operands() {
    if !admitted() {
        return;
    }
    for (base, destination, source) in [
        (0x19000400, 0x20003, 0x10005),
        (0x1d000400, 0x10013, 0x10005),
        (0x1d000400, 0x10005, 0x10013),
        (0x19c00400, 0x20003, 0x83),
    ] {
        for budget in [1, 64] {
            for mode in 0..3 {
                let ops = triple(base, 18, 17, 29);
                let words = [ops[0], ops[1], ops[2], 0xd4000001];
                let mut state = initial();
                state.registers[18] = (0xab << 56) | destination;
                state.registers[17] = (0xcd << 56) | source;
                state.registers[29] = 4097;
                let mut expected: Vec<_> = (0..0x20000)
                    .map(|i| (i as u8).wrapping_mul(17).wrapping_add((i >> 8) as u8))
                    .collect();
                let start = (destination - 0x10000) as usize;
                if base == 0x19c00400 {
                    expected[start..start + 4097].fill(0x83);
                } else {
                    let from = (source - 0x10000) as usize;
                    expected.copy_within(from..from + 4097, start);
                }
                exercise(&words, &state, &expected, budget, mode);
            }
        }
        let ops = triple(base, 18, 17, 29);
        let mut memory = memory(&[ops[0], ops[1], ops[2], 0xd4000001]);
        let mut cpu = Cpu::new(0x1000, 0x2800);
        cpu.set_x(18, 0xabff_ffff_ffff_ffff);
        cpu.set_x(17, 0xcdff_ffff_ffff_ffff);
        cpu.set_x(29, 0);
        let mut engine = Engine::default();
        assert_eq!(finish(&mut cpu, &mut engine, &mut memory, 1), 4);
        assert_eq!(
            (cpu.x(18), cpu.x(17), cpu.x(29)),
            (0xabff_ffff_ffff_ffff, 0xcdff_ffff_ffff_ffff, 0)
        );
        if NATIVE_COMPILED {
            assert_eq!(engine.stats.fallback_instructions, 0);
        }
    }
}

#[cfg(all(
    feature = "native-aarch64",
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
#[test]
fn revoked_private_mops_aliases_rejoin_checked_transport_without_interpreter_entry() {
    if !admitted() {
        return;
    }
    for base in [0x19000400, 0x1d000400, 0x19c00400] {
        let ops = triple(base, 0, 1, 2);
        let mut memory = memory(&[ops[0], ops[1], ops[2], 0xd4000001]);
        memory.map(0x10000, 0x20000, Permissions::RW).unwrap();
        memory.write(0x10000, &[0x83; 16384]).unwrap();
        memory.write(0x20000, &[0x11; 16384]).unwrap();
        let pointer = {
            let page = unsafe { memory.cpu_native_page(0x20000, true) }.unwrap();
            page.write
        };
        let granule = trames_memory::host_mapping_granule();
        assert_eq!(
            unsafe { libc::mprotect(pointer as *mut _, granule, libc::PROT_NONE) },
            0
        );
        let mut cpu = Cpu::new(0x1000, 0x2800);
        cpu.set_x(0, 0x20000);
        cpu.set_x(1, if base == 0x19c00400 { 0x83 } else { 0x10000 });
        cpu.set_x(2, 8197);
        let mut engine = Engine::default();
        assert_eq!(finish(&mut cpu, &mut engine, &mut memory, 64), 4);
        assert_eq!(
            unsafe {
                libc::mprotect(
                    pointer as *mut _,
                    granule,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            0
        );
        let mut bytes = [0; 8197];
        memory.read(0x20000, &mut bytes).unwrap();
        assert_eq!(bytes, [0x83; 8197]);
        assert_eq!(engine.stats.fallback_instructions, 0);
    }
}
