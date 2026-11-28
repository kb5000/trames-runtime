// SPDX-License-Identifier: GPL-3.0-or-later
//! CPU-only cached syscall exits with a simulated return, not Linux handlers.
use std::{hint::black_box, time::Instant};
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::{Aarch64State, Registers};
use trames_memory::{Memory, Permissions, PAGE_SIZE};
const ROUNDS: u64 = 200_000;
fn measure(name: &str, words: &[u32], continuation: bool, increment: u64) {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, word) in words.iter().enumerate() {
        memory
            .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    let mut state = Aarch64State {
        pc: if continuation { 0x1008 } else { 0x1000 },
        sp: 0x2000,
        nzcv: 0xb0000000,
        fpsr: 0x10,
        tpidr_el0: 123,
        tpidr2_el0: 456,
        vectors: [u128::MAX / 3; 32],
        ..Default::default()
    };
    state.registers = std::array::from_fn(|i| (i as u64).wrapping_mul(0x123456789));
    state.registers[0] = 0;
    state.registers[8] = 172;
    let mut cpu = trames_jit::Cpu::new(0, 0);
    let mut engine = trames_jit::Engine::default();
    let samples = std::env::var("TRAMES_BENCH_SAMPLES").map_or(32, |n| n.parse().unwrap());
    let warmup = std::env::var("TRAMES_BENCH_WARMUP").map_or(8, |n| n.parse().unwrap());
    for sample in 0..samples {
        cpu.restore_architectural_state(&state);
        let before = engine.stats;
        let mut retired = 0;
        let start = Instant::now();
        for _ in 0..ROUNDS {
            if !continuation {
                cpu.set_pc(0x1000);
            }
            match black_box(cpu.run_slice(&mut engine, &mut memory, 64)) {
                SliceOutcome::Syscall { instructions } => retired += instructions,
                other => panic!("{other:?}"),
            }
            cpu.set_x(0, cpu.x(0).wrapping_add(1)); // original simulated return boundary
        }
        let ns = start.elapsed().as_nanos();
        let mut expected = state.clone();
        expected.pc = if continuation {
            0x1008
        } else {
            0x1000 + words.len() as u64 * 4
        };
        expected.registers[0] = increment * ROUNDS;
        assert_eq!(cpu.architectural_state(), expected);
        assert_eq!(retired, words.len() as u64 * ROUNDS);
        assert_eq!(
            engine.stats.fallback_instructions - before.fallback_instructions,
            0
        );
        assert_eq!(
            engine.stats.direct_syscall_exits - before.direct_syscall_exits,
            ROUNDS
        );
        for (i, word) in words.iter().enumerate() {
            assert_eq!(memory.fetch_u32(0x1000 + i as u64 * 4).unwrap(), *word);
        }
        println!("{{\"workload\":\"{name}\",\"sample\":{sample},\"warmup\":{},\"ns\":{ns},\"rounds\":{ROUNDS},\"retired\":{retired},\"fallback\":0}}", sample < warmup);
    }
}
fn main() {
    if !trames_jit::NATIVE_COMPILED {
        eprintln!("Requires native ARM64 Linux/Android JIT");
        std::process::exit(2);
    }
    let filter = std::env::var("TRAMES_BENCH_FILTER").ok();
    for (name, words, continuation, increment) in [
        ("svc-only", &[0xd4000001][..], false, 1),
        ("svc-round-trip", &[0x91000400, 0xd4000001][..], false, 2),
        (
            "svc-continuation",
            &[0x91000400, 0xd4000001, 0x17fffffe][..],
            true,
            2,
        ),
    ] {
        if filter.as_ref().is_none_or(|filter| name == filter) {
            measure(name, words, continuation, increment);
        }
    }
}
