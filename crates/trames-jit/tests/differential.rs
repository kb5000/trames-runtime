// SPDX-License-Identifier: GPL-3.0-or-later
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::{Aarch64State, Registers};
use trames_jit::{Cpu, Engine, NATIVE_COMPILED};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

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
        assert!(engine.stats.fallback_instructions > 0);
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
