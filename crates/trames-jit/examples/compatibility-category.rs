// SPDX-License-Identifier: GPL-3.0-or-later
//! Matched CPU-only compatibility loops; whole state/data checks stay outside timing.
use std::{hint::black_box, time::Instant};
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::Aarch64State;
use trames_memory::{Memory, Permissions, PAGE_SIZE};
const TRIPS: u64 = 65536;
const DATA: u64 = 0x10000;
fn memory(words: &[u32]) -> Memory {
    let mut m = Memory::default();
    m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, word) in words.iter().enumerate() {
        m.write_array(0x1000 + i as u64 * 4, word.to_le_bytes())
            .unwrap();
    }
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    m.map(DATA, 16384, Permissions::RW).unwrap();
    m.write(DATA, &[0; 16384]).unwrap();
    m
}
fn run<C: Backend>(cpu: &mut C, engine: &mut C::Engine, memory: &mut Memory) -> u64 {
    let mut retired = 0;
    loop {
        match cpu.run(engine, memory, 1_048_576) {
            SliceOutcome::Yield { instructions } => retired += instructions,
            SliceOutcome::Syscall { instructions } => return retired + instructions,
            other => panic!("{other:?}"),
        }
    }
}
fn measure(name: &str, words: &[u32], stride: u64, tail: u64) {
    let mut m = memory(words);
    let mut cpu = trames_jit::Cpu::new(0, 0);
    let mut engine = trames_jit::Engine::default();
    let mut state = Aarch64State {
        pc: 0x1000,
        sp: DATA,
        nzcv: 0xb0000000,
        tpidr_el0: 123,
        tpidr2_el0: 456,
        fpsr: 0x10,
        ..Default::default()
    };
    state.registers[1] = 0xa500_0000_0001_0000;
    state.registers[2] = TRIPS;
    state.registers[17] = 0xa5aa_0000_0000_1000;
    state.registers[18] = 0xa5ff_0000_0000_0000;
    state.registers[29] = 0x5cae;
    state.vectors = [u128::MAX / 3; 32];
    let samples = std::env::var("TRAMES_BENCH_SAMPLES").map_or(12, |n| n.parse().unwrap());
    let warmup = std::env::var("TRAMES_BENCH_WARMUP").map_or(2, |n| n.parse().unwrap());
    let require_native = std::env::var_os("TRAMES_BENCH_REQUIRE_NATIVE").is_some();
    let rounds = if name.starts_with("control-") { 64 } else { 8 };
    for sample in 0..samples {
        let before = engine.stats;
        let mut ns = 0;
        let mut retired = 0;
        for _ in 0..rounds {
            cpu.restore_architectural_state(&state);
            m.write(DATA, &[0; 4096]).unwrap();
            let start = Instant::now();
            retired += black_box(run(&mut cpu, &mut engine, &mut m));
            ns += start.elapsed().as_nanos();
        }
        let mut rm = memory(words);
        let mut reference = trames_interpreter::Cpu::new(0, 0);
        reference.restore_architectural_state(&state);
        let mut re = trames_interpreter::Engine::default();
        assert_eq!(run(&mut reference, &mut re, &mut rm), stride * TRIPS + tail);
        assert_eq!(retired, (stride * TRIPS + tail) * rounds);
        assert_eq!(cpu.architectural_state(), reference.architectural_state());
        assert_eq!(
            m.read_array::<4096>(DATA).unwrap(),
            rm.read_array::<4096>(DATA).unwrap()
        );
        for (i, word) in words.iter().enumerate() {
            assert_eq!(m.fetch_u32(0x1000 + i as u64 * 4).unwrap(), *word);
        }
        let fallback = engine.stats.fallback_instructions - before.fallback_instructions;
        if require_native || name.starts_with("control-") {
            assert_eq!(fallback, 0);
        }
        println!("{{\"workload\":\"{name}\",\"sample\":{sample},\"warmup\":{},\"ns\":{ns},\"rounds\":{rounds},\"retired\":{retired},\"fallback\":{fallback},\"native\":{}}}", sample < warmup, engine.stats.native_instructions-before.native_instructions);
    }
}
fn main() {
    if !trames_jit::NATIVE_COMPILED {
        eprintln!("Requires native-aarch64 on an AArch64 Linux/Android host");
        std::process::exit(2);
    }
    let filter = std::env::var("TRAMES_BENCH_FILTER").ok();
    for (name, words, stride, tail) in [
        (
            "pointer-arithmetic",
            &[
                0x9adf1032, 0x91813e52, 0x9add1651, 0xbac1025e, 0xf1000442, 0x54ffff61, 0xd4000001,
            ][..],
            6,
            1,
        ),
        (
            "authenticated-load-pair-store",
            &[
                0xf8200432, 0x91000652, 0x69007432, 0xf1000442, 0x54ffff81, 0xd4000001,
            ][..],
            5,
            1,
        ),
        (
            "tag-zero",
            &[0xd9e00820, 0x91000652, 0xf1000442, 0x54ffffa1, 0xd4000001][..],
            4,
            1,
        ),
        (
            "authentication-profile",
            &[
                0xdac10032, 0xdac143f2, 0x91000652, 0xf1000442, 0x54ffff81, 0xd4000001,
            ][..],
            5,
            1,
        ),
        (
            "authenticated-branch",
            &[0x91000652, 0xf1000442, 0x54000040, 0xd61f0a3f, 0xd4000001][..],
            4,
            0,
        ),
        (
            "control-integer",
            &[0x91000652, 0xf1000442, 0x54ffffc1, 0xd4000001][..],
            3,
            1,
        ),
        (
            "control-scalar-memory",
            &[
                0xf9400032, 0x91000652, 0xf9000032, 0xf1000442, 0x54ffff81, 0xd4000001,
            ][..],
            5,
            1,
        ),
    ] {
        if filter.as_ref().is_none_or(|filter| name.contains(filter)) {
            measure(name, words, stride, tail);
        }
    }
}
