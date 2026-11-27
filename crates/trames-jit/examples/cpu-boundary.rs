// SPDX-License-Identifier: GPL-3.0-or-later
//! CPU-only microbenchmarks. SVC measures backend exits and simulated returns,
//! not Linux syscall handlers, Android/JNI, end-to-end apps or device latency.
use std::{hint::black_box, time::Instant};
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_memory::{Memory, Permissions, PAGE_SIZE};

fn memory(words: &[u32]) -> Memory {
    let mut memory = Memory::default();
    memory.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, word) in words.iter().enumerate() {
        memory
            .write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    memory
}
fn measure<C: Backend>(words: &[u32], syscalls: bool) -> (u128, u64) {
    let mut memory = memory(words);
    let mut cpu = C::new(0x1000, 0);
    let mut engine = C::Engine::default();
    let rounds = if syscalls { 100_000 } else { 16 };
    let budget = if syscalls { 64 } else { 1_048_576 };
    let mut samples = Vec::new();
    let mut checksum = 0;
    for sample in 0..6 {
        let start = Instant::now();
        for _ in 0..rounds {
            if syscalls {
                cpu.set_pc(0x1000);
            }
            let outcome = cpu.run(&mut engine, &mut memory, budget);
            if syscalls {
                assert!(
                    matches!(outcome, SliceOutcome::Syscall { instructions } if instructions == words.len() as u64)
                );
                // Simulate the ordinary worker committing a return value. The
                // guest SVC has advanced PC exactly once; no instruction replay.
                cpu.set_x(0, cpu.x(0).wrapping_add(1));
            } else {
                assert!(
                    matches!(outcome, SliceOutcome::Yield { instructions } if instructions == budget)
                );
            }
            checksum ^= black_box(cpu.x(0));
        }
        if sample != 0 {
            samples.push(start.elapsed().as_nanos());
        }
    }
    samples.sort_unstable();
    (samples[samples.len() / 2], black_box(checksum))
}
fn main() {
    if !trames_jit::NATIVE_COMPILED {
        eprintln!("Requires native-aarch64 on an AArch64 Linux/Android host");
        std::process::exit(2);
    }
    let mut arithmetic = vec![0x91000400; 31];
    arithmetic.push(0x17ffffe1); // b -124, 32-instruction loop
    let mut syscall = vec![0x91000400; 16];
    syscall.push(0xd4000001);
    for (name, words, svc) in [
        ("integer-loop", arithmetic, false),
        ("svc-round-trip", syscall, true),
        ("svc-only", vec![0xd4000001], true),
    ] {
        let (interpreter, a) = measure::<trames_interpreter::Cpu>(&words, svc);
        let (jit, b) = measure::<trames_jit::Cpu>(&words, svc);
        assert_eq!(a, b);
        println!("{{\"workload\":\"{name}\",\"interpreter_ns\":{interpreter},\"jit_ns\":{jit},\"speedup\":{:.3}}}", interpreter as f64 / jit as f64);
    }
}
