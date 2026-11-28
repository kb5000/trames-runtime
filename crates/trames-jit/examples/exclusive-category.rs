// SPDX-License-Identifier: GPL-3.0-or-later
//! Matched CPU-only exclusive category benchmark. Validate complete state and
//! canonical bytes outside timing; real SC may fail spuriously and guest-retry.
use std::{hint::black_box, time::Instant};
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::Aarch64State;
use trames_memory::{CpuMemory, Memory, Permissions, PAGE_SIZE};
const TRIPS: u64 = 262144;
const DATA: u64 = 0x10000;
fn memory(words: &[u32]) -> Memory {
    let mut m = Memory::default();
    m.map(0x1000, PAGE_SIZE, Permissions::RW).unwrap();
    for (i, w) in words.iter().enumerate() {
        m.write_array(0x1000 + 4 * i as u64, w.to_le_bytes())
            .unwrap();
    }
    m.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    m.map(DATA, 16384, Permissions::RW).unwrap();
    m.write(DATA, &[0; 16384]).unwrap();
    m
}
trait BenchCpu: Backend {
    fn slice(
        &mut self,
        engine: &mut Self::Engine,
        memory: &mut impl CpuMemory,
        budget: u64,
    ) -> SliceOutcome;
}
impl BenchCpu for trames_jit::Cpu {
    fn slice(
        &mut self,
        engine: &mut Self::Engine,
        memory: &mut impl CpuMemory,
        budget: u64,
    ) -> SliceOutcome {
        self.run_slice(engine, memory, budget)
    }
}
impl BenchCpu for trames_interpreter::Cpu {
    fn slice(
        &mut self,
        engine: &mut Self::Engine,
        memory: &mut impl CpuMemory,
        budget: u64,
    ) -> SliceOutcome {
        self.run_with_engine(engine, memory, budget)
    }
}
fn run<C: BenchCpu>(c: &mut C, e: &mut C::Engine, m: &mut impl CpuMemory) -> u64 {
    let mut retired = 0;
    loop {
        match c.slice(e, m, 1_048_576) {
            SliceOutcome::Yield { instructions } => retired += instructions,
            SliceOutcome::Syscall { instructions } => return retired + instructions,
            other => panic!("{other:?}"),
        }
    }
}
fn measure(name: &str, words: &[u32], stride: u64, retry: u64, m: &mut impl CpuMemory) {
    let mut cpu = trames_jit::Cpu::new(0x1000, DATA);
    let mut engine = trames_jit::Engine::default();
    let mut state = Aarch64State {
        pc: 0x1000,
        sp: DATA,
        nzcv: 0xb0000000,
        ..Default::default()
    };
    state.registers[1] = DATA;
    state.registers[2] = TRIPS;
    let rounds = if name.starts_with("control-") { 64 } else { 1 };
    let samples = std::env::var("TRAMES_BENCH_SAMPLES").map_or(6, |n| n.parse().unwrap());
    let warmup = std::env::var("TRAMES_BENCH_WARMUP").map_or(1, |n| n.parse().unwrap());
    for sample in 0..samples {
        let before = engine.stats;
        let mut retired = 0;
        let mut ns = 0;
        for _ in 0..rounds {
            cpu.restore_architectural_state(&state);
            m.write(DATA, &[0; 4096]).unwrap();
            let start = Instant::now();
            retired += black_box(run(&mut cpu, &mut engine, m));
            ns += start.elapsed().as_nanos();
        }
        let mut rm = memory(words);
        let mut reference = trames_interpreter::Cpu::new(0, 0);
        reference.restore_architectural_state(&state);
        let mut re = trames_interpreter::Engine::default();
        assert_eq!(run(&mut reference, &mut re, &mut rm), stride * TRIPS + 1);
        assert_eq!(cpu.architectural_state(), reference.architectural_state());
        let mut actual = [0; 4096];
        m.read(DATA, &mut actual).unwrap();
        assert_eq!(actual, rm.read_array::<4096>(DATA).unwrap());
        assert!(retired > stride * TRIPS * rounds);
        let extra = retired - (stride * TRIPS + 1) * rounds;
        if retry == 0 {
            assert_eq!(extra, 0);
        } else {
            assert!(extra.is_multiple_of(retry));
        }
        for (i, word) in words.iter().enumerate() {
            assert_eq!(m.fetch_u32(0x1000 + i as u64 * 4).unwrap(), *word);
        }
        println!("{{\"workload\":\"{name}\",\"sample\":{sample},\"warmup\":{},\"ns\":{ns},\"rounds\":{rounds},\"retired\":{retired},\"extra_retry_instructions\":{extra},\"fallback\":{},\"native\":{}}}", sample < warmup, engine.stats.fallback_instructions-before.fallback_instructions,engine.stats.native_instructions-before.native_instructions);
    }
}
fn main() {
    if !trames_jit::NATIVE_COMPILED {
        eprintln!("Requires native-aarch64 on an AArch64 Linux/Android host");
        std::process::exit(2);
    }
    let filter = std::env::var("TRAMES_BENCH_FILTER").ok();
    let admits = |name: &str| filter.as_ref().is_none_or(|filter| name.contains(filter));
    let single = [
        0xc85ffc20, 0x91000400, 0xc803fc20, 0xb5ffffa3, 0xf1000442, 0x54ffff61, 0xd4000001,
    ];
    let pair = [
        0xc87f9020, 0x91000400, 0x91000884, 0xc8239020, 0xb5ffff83, 0xf1000442, 0x54ffff41,
        0xd4000001,
    ];
    let scalar = [
        0xf9400020, 0x91000400, 0xf9000020, 0xf1000442, 0x54ffff81, 0xd4000001,
    ];
    let integer = [0x91000400, 0xf1000442, 0x54ffffc1, 0xd4000001];
    for (name, words, stride, retry) in [
        ("private-ldaxr-stlxr", single.as_slice(), 6, 4),
        ("private-ldaxp-stlxp", pair.as_slice(), 7, 5),
        ("control-scalar-memory", scalar.as_slice(), 5, 0),
        ("control-integer", integer.as_slice(), 3, 0),
    ] {
        if admits(name) {
            measure(name, words, stride, retry, &mut memory(words));
        }
    }
    let mut m = memory(&single);
    let mut registry = trames_memory::parallel::Registry::default();
    let mut view = m.parallel_view(&mut registry).unwrap();
    if admits("guarded-ldaxr-stlxr") {
        measure("guarded-ldaxr-stlxr", &single, 6, 4, &mut view);
    }
}
