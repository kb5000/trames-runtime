// SPDX-License-Identifier: GPL-3.0-or-later
//! CPU-only native instructions through an opaque checked memory provider.
use std::{hint::black_box, sync::atomic::Ordering, time::Instant};
use trames_engine::{Cpu as Backend, SliceOutcome};
use trames_execution::Aarch64State;
use trames_memory::{Access, CpuMemory, Memory, MemoryError, Permissions, PAGE_SIZE};
const TRIPS: u64 = 65_536;
struct Abstract(Memory);
impl CpuMemory for Abstract {
    fn mapped_at_or_after(&self, a: u64) -> bool {
        self.0.mapped_at_or_after(a)
    }
    fn read(&self, a: u64, bytes: &mut [u8]) -> Result<(), MemoryError> {
        self.0.read(a, bytes)
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
    fn exclusive_read(&mut self, a: u64, bytes: &mut [u8]) -> Result<u128, MemoryError> {
        CpuMemory::exclusive_read(&mut self.0, a, bytes)
    }
    fn exclusive_write(
        &mut self,
        a: u64,
        bytes: &[u8],
        token: Option<u128>,
    ) -> Result<bool, MemoryError> {
        CpuMemory::exclusive_write(&mut self.0, a, bytes, token)
    }
    fn fence(&self, order: Ordering) {
        CpuMemory::fence(&self.0, order);
    }
}
fn measure(name: &str, words: &[u32], atomic: bool) {
    let mut memory = Memory::default();
    for a in [0x1000, 0x10000] {
        memory.map(a, PAGE_SIZE, Permissions::RW).unwrap();
    }
    for (i, word) in words.iter().enumerate() {
        memory
            .write_array(0x1000 + 4 * i as u64, word.to_le_bytes())
            .unwrap();
    }
    memory.protect(0x1000, PAGE_SIZE, Permissions::RX).unwrap();
    let mut memory = Abstract(memory);
    let mut state = Aarch64State {
        pc: 0x1000,
        sp: 0x2000,
        nzcv: 0xb0000000,
        fpsr: 0x10,
        tpidr_el0: 123,
        tpidr2_el0: 456,
        vectors: [u128::MAX / 3; 32],
        ..Default::default()
    };
    state.registers[1] = 0x10000;
    state.registers[2] = TRIPS;
    state.registers[4] = 1;
    let mut cpu = trames_jit::Cpu::new(0, 0);
    let mut engine = trames_jit::Engine::default();
    let samples = std::env::var("TRAMES_BENCH_SAMPLES").map_or(32, |n| n.parse().unwrap());
    let warmup = std::env::var("TRAMES_BENCH_WARMUP").map_or(8, |n| n.parse().unwrap());
    for sample in 0..samples {
        cpu.restore_architectural_state(&state);
        memory.0.write_array(0x10000, 7u64.to_le_bytes()).unwrap();
        let before = engine.stats;
        let start = Instant::now();
        let exit = black_box(cpu.run_slice(&mut engine, &mut memory, 1_048_576));
        let ns = start.elapsed().as_nanos();
        let retired = (if atomic { 3 } else { 5 }) * TRIPS + 1;
        assert!(matches!(exit, SliceOutcome::Syscall { instructions } if instructions == retired));
        let mut expected = state.clone();
        expected.pc = 0x1000 + 4 * words.len() as u64;
        expected.nzcv = 0x60000000;
        expected.registers[0] = 7 + TRIPS - u64::from(atomic);
        expected.registers[2] = 0;
        assert_eq!(cpu.architectural_state(), expected);
        assert_eq!(memory.0.read_u64(0x10000).unwrap(), 7 + TRIPS);
        for (i, word) in words.iter().enumerate() {
            assert_eq!(memory.0.fetch_u32(0x1000 + 4 * i as u64).unwrap(), *word);
        }
        let fallback = engine.stats.fallback_instructions - before.fallback_instructions;
        if std::env::var_os("TRAMES_BENCH_REQUIRE_NATIVE").is_some() {
            assert_eq!(fallback, 0);
        }
        println!("{{\"workload\":\"{name}\",\"sample\":{sample},\"warmup\":{},\"ns\":{ns},\"rounds\":1,\"trips\":{TRIPS},\"retired\":{retired},\"fallback\":{fallback}}}", sample < warmup);
    }
}
fn main() {
    if !trames_jit::NATIVE_COMPILED {
        std::process::exit(2);
    }
    let filter = std::env::var("TRAMES_BENCH_FILTER").ok();
    for (name, words, atomic) in [
        (
            "abstract-release-acquire",
            &[
                0xc8dffc20, 0x91000400, 0xc89ffc20, 0xf1000442, 0x54ffff81, 0xd4000001,
            ][..],
            false,
        ),
        (
            "abstract-atomic",
            &[0xf8e40020, 0xf1000442, 0x54ffffc1, 0xd4000001][..],
            true,
        ),
    ] {
        if atomic && <trames_jit::Cpu as Backend>::features().hwcap & (1 << 8) == 0 {
            continue;
        }
        if filter.as_ref().is_none_or(|filter| name == filter) {
            measure(name, words, atomic);
        }
    }
}
