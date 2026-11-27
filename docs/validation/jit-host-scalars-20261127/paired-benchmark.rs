// SPDX-License-Identifier: GPL-3.0-or-later
//! Matched, warmed CPU boundaries; no Linux syscall handler is executed.
use std::{hint::black_box, time::Instant};
use trames_engine::{Cpu, SliceOutcome};
use trames_memory::{parallel::{Registry, View}, Memory, Permissions, PAGE_SIZE};

const BASE: u64 = 0x1000;
const ENTRIES: u64 = 20_000;

struct Lane<C: Cpu> {
    cpu: C,
    engine: C::Engine,
    view: View,
    // Keep the owning address space and registry alive through every View.
    _registry: Registry,
    _memory: Memory,
}
impl<C: Cpu> Lane<C> {
    fn new(words: &[u32], pc: u64) -> Self {
        let mut memory = Memory::default();
        memory.map(BASE, PAGE_SIZE, Permissions::RW).unwrap();
        for (i, w) in words.iter().enumerate() {
            memory.write_array(BASE + i as u64 * 4, w.to_le_bytes()).unwrap();
        }
        memory.protect(BASE, PAGE_SIZE, Permissions::RX).unwrap();
        let mut registry = Registry::default();
        C::prepare_hardware_memory(&mut memory, &mut registry).unwrap();
        let mut view = memory.parallel_view(&mut registry).unwrap();
        C::prepare_hardware_view(&mut view);
        let mut cpu = C::new(pc, 0);
        cpu.set_x(8, 172);
        Self { cpu, engine: Default::default(), _memory: memory, _registry: registry, view }
    }

    fn sample(&mut self, workload: &str) -> (u128, u64, u64) {
        let initial = self.cpu.x(0);
        let start = Instant::now();
        let mut yields = 0;
        if workload == "integer-countdown" {
            for _ in 0..4 {
                self.cpu.set_pc(BASE);
                self.cpu.set_x(1, 262_144);
                let mut interrupt = C::begin_execution(&mut self.engine).unwrap();
                loop {
                    match self.cpu.run_parallel(&mut self.engine, &mut self.view, 1_048_576) {
                        SliceOutcome::Syscall { .. } => break,
                        SliceOutcome::Yield { .. } => {
                            yields += 1;
                            C::finish_execution(&mut self.engine);
                            interrupt = C::begin_execution(&mut self.engine).unwrap();
                        }
                        other => panic!("{other:?}, pc={:#x}", self.cpu.pc()),
                    }
                }
                C::finish_execution(&mut self.engine);
                drop(interrupt);
                assert_eq!(self.cpu.pc(), BASE + 136);
                assert_eq!(self.cpu.x(1), 0);
            }
        } else if workload == "integer-loop" {
            // Same 31 ADD + backward B bytes. KVM uses a wall-clock quantum;
            // JIT uses an exact instruction budget. Normalize by actual ADDs.
            for _ in 0..32 {
                let _interrupt = C::begin_execution(&mut self.engine).unwrap();
                let outcome = self.cpu.run_parallel(&mut self.engine, &mut self.view, 1_048_576);
                assert!(matches!(outcome, SliceOutcome::Yield { .. }), "{outcome:?}");
                C::finish_execution(&mut self.engine);
            }
            assert!((BASE..BASE + 128).contains(&self.cpu.pc()));
        } else {
            let mut interrupt = C::begin_execution(&mut self.engine).unwrap();
            for _ in 0..ENTRIES {
                if workload == "svc-only" { self.cpu.set_pc(BASE); }
                loop {
                    match self.cpu.run_parallel(&mut self.engine, &mut self.view, 64) {
                        SliceOutcome::Syscall { .. } => break,
                        SliceOutcome::Yield { .. } => {
                            yields += 1;
                            assert!(yields < ENTRIES, "no guest progress");
                            C::finish_execution(&mut self.engine);
                            interrupt = C::begin_execution(&mut self.engine).unwrap();
                        }
                        other => panic!("{other:?}, pc={:#x}", self.cpu.pc()),
                    }
                }
                assert_eq!(self.cpu.pc(), BASE + if workload == "svc-only" { 4 } else { 8 });
                self.cpu.set_x(0, self.cpu.x(0).wrapping_add(1));
            }
            C::finish_execution(&mut self.engine);
            drop(interrupt);
        }
        let elapsed = start.elapsed().as_nanos();
        let delta = black_box(self.cpu.x(0).wrapping_sub(initial));
        let units = if workload == "integer-countdown" {
            assert_eq!(delta, 31 * 262_144 * 4);
            delta
        } else if workload == "integer-loop" {
            assert!(delta > 0);
            delta
        } else {
            assert_eq!(delta, ENTRIES * if workload == "svc-only" { 1 } else { 2 });
            ENTRIES
        };
        (elapsed, units, yields)
    }
}

fn main() {
    assert!(trames_jit::NATIVE_COMPILED);
    let host = trames_kvm::Doctor::inspect();
    host.require_probe().unwrap();
    println!("{}", serde_json::json!({"host":host, "scope":"CPU backend + simulated syscall return; same Runtime, View, bytes and worker assignment hooks; excludes Linux handlers/JNI/startup; integer normalized by actual ADD count"}));
    let mut arithmetic = vec![0x91000400; 31];
    arithmetic.push(0x17ffffe1);
    let mut countdown = vec![0x91000400; 31];
    countdown.extend_from_slice(&[0xd1000421, 0xb5fffc01, 0xd4000001]); // SUB x1; CBNZ x1,loop; SVC
    let selected = std::env::args().nth(1);
    for (workload, words, pc) in [
        ("integer-loop", arithmetic, BASE),
        ("integer-countdown", countdown, BASE),
        ("svc-only", vec![0xd4000001], BASE),
        ("svc-continuation", vec![0x91000400, 0xd4000001, 0x17fffffe], BASE + 8),
    ] {
        if selected.as_ref().is_some_and(|name| name != workload) { continue; }
        let mut jit = Lane::<trames_jit::Cpu>::new(&words, pc);
        let mut kvm = Lane::<trames_kvm::kernel::Cpu>::new(&words, pc);
        for sample in 0..6 {
            for lane in if sample % 2 == 0 { ["jit", "kvm"] } else { ["kvm", "jit"] } {
                let (ns, units, yields) = if lane == "jit" { jit.sample(workload) } else { kvm.sample(workload) };
                println!("{}", serde_json::json!({"workload":workload,"sample":sample,"warmup":sample==0,"lane":lane,"ns":ns,"units":units,"ns_per_unit":ns as f64 / units as f64,"yields":yields}));
            }
        }
        if workload == "integer-countdown" {
            assert_eq!(jit.engine.stats.fallback_instructions, 0);
        } else {
            assert_eq!(jit.engine.stats.fallback_instructions, 0, "native-only fixtures must not fall back");
        }
        println!("{}", serde_json::json!({"workload":workload,"jit_stats":format!("{:?}",jit.engine.stats),"jit_links":format!("{:?}",jit.engine.link_stats())}));
    }
}
