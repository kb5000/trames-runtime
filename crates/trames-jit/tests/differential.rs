// SPDX-License-Identifier: GPL-3.0-or-later
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::{Aarch64State, Registers};
use trames_jit::{Cpu, Engine, NATIVE_COMPILED};
use trames_memory::{CpuMemory, Memory, Permissions, PAGE_SIZE};

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
        nzcv: 0xb,
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
    ] {
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
    for word in [0xf9400020, 0xf9000020] {
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
    for parallel in [false, true] {
        let words = [0xc85f7c20, 0xf9000022, 0xc8037c20, 0xd4000001];
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
        assert_eq!((c.x(3), m.read_u64(0x2000).unwrap()), (1, 99));
        if NATIVE_COMPILED {
            assert_eq!(e.memory_stats().instructions, 1);
            assert_eq!(e.stats.fallback_instructions, 2);
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
    let output = Arc::new(Output::default());
    let mut m = memory(&[0xf9000020]);
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
    let mut engine = Engine::default();
    assert_eq!(
        outcome(&cpu.run_slice(&mut engine, &mut m, 1)),
        ("yield", 1)
    );
    assert_eq!(output.reads.load(Ordering::Relaxed), 0);
    assert_eq!(
        &output.bytes.lock().unwrap()[..8],
        &0x8877665544332211u64.to_le_bytes()
    );
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
    for store in [false, true] {
        let word = if store { 0xf8008420 } else { 0xf8408420 }; // post-index #8
        let words = if store {
            // The read succeeds with host PROT_READ, then the following store
            // reuses that exact translated address and faults. Its recovery
            // must also preserve newer flags and post-index writeback.
            [
                0xf94003bc, 0xf90003bc, 0xf94003a0, 0x910004a5, 0xb1000463, 0xf80087a0, 0x9a9f37e4,
                0xd4000001,
            ]
        } else {
            [
                0xf94003bc, 0xf94003bc, 0xf90003bc, 0x910004a5, 0xb1000463, word, 0x9a9f37e4,
                0xd4000001,
            ]
        };
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
